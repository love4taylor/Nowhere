// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Multiplexed HTTP DNS with bounded messages and connection-scoped keepalive.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use hickory_net::proto::op::Message;
use rustls::pki_types::ServerName;
use tokio::task::JoinHandle;

use crate::common::network::connect_tcp_addr;

use super::config::{HttpOptions, UpstreamConfig};

pub(super) struct Driver {
    pub(super) task: JoinHandle<()>,
    pub(super) closed: Arc<AtomicBool>,
    pub(super) quic: Option<(quinn::Endpoint, quinn::Connection)>,
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.task.abort();
        if let Some((endpoint, connection)) = &self.quic {
            connection.close(0u32.into(), b"DNS session dropped");
            endpoint.close(0u32.into(), b"DNS session dropped");
        }
    }
}

#[derive(Clone)]
pub(super) struct HttpsSession {
    sender: h2::client::SendRequest<Bytes>,
    uri: http::Uri,
    driver: Arc<Driver>,
}

impl HttpsSession {
    pub(super) async fn connect(
        config: &UpstreamConfig,
        address: SocketAddr,
        source: Option<std::net::IpAddr>,
        tls: &rustls::ClientConfig,
        options: &HttpOptions,
    ) -> Result<Self> {
        let mut tls = tls.clone();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let tcp = connect_tcp_addr(source, address).await?;
        let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
            .connect(ServerName::try_from(config.host.clone())?, tcp)
            .await?;
        if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
            bail!("DoH requires HTTP/2 ALPN");
        }
        let uri = uri(config)?;
        let (sender, mut connection) = h2::client::Builder::new()
            .enable_push(false)
            .max_header_list_size(8192)
            .max_send_buffer_size(65536)
            .handshake(stream)
            .await?;
        let mut ping = connection
            .ping_pong()
            .context("missing HTTP/2 PING handle")?;
        let closed = Arc::new(AtomicBool::new(false));
        let done = closed.clone();
        let options = options.clone();
        let task = tokio::spawn(async move {
            let keepalive = async {
                loop {
                    tokio::time::sleep(options.keepalive).await;
                    // Keep polling the connection while awaiting the PING ACK.
                    if !matches!(
                        tokio::time::timeout(options.ping_timeout, ping.ping(h2::Ping::opaque()))
                            .await,
                        Ok(Ok(_))
                    ) {
                        break;
                    }
                }
            };
            tokio::select! {
                _ = &mut connection => {},
                _ = keepalive => {},
            }
            done.store(true, Ordering::Release);
        });
        Ok(Self {
            sender,
            uri,
            driver: Arc::new(Driver {
                task,
                closed,
                quic: None,
            }),
        })
    }

    pub(super) fn is_usable(&self) -> bool {
        !self.driver.closed.load(Ordering::Acquire)
    }

    pub(super) async fn query(&self, request: &Message) -> Result<Message> {
        let wire = request_wire(request)?;
        let headers = request_headers(self.uri.clone(), wire.len())?;
        let mut sender = self.sender.clone().ready().await?;
        let (response, mut body) = sender.send_request(headers, false)?;
        body.send_data(Bytes::from(wire), true)?;
        let response = response.await?;
        let (length, age) = response_metadata(response.status(), response.headers())?;
        let mut body = response.into_body();
        let mut wire = Vec::with_capacity(512);
        while let Some(chunk) = body.data().await {
            let chunk = chunk?;
            check_body_size(wire.len(), chunk.len())?;
            body.flow_control().release_capacity(chunk.len())?;
            wire.extend_from_slice(&chunk);
        }
        decode_response(&wire, length, age)
    }
}

/// Only connection-scoped failures invalidate a multiplexed HTTP session.
pub(super) fn connection_error(error: &anyhow::Error) -> bool {
    if let Some(error) = error.downcast_ref::<h2::Error>() {
        return !error.is_reset();
    }
    if let Some(error) = error.downcast_ref::<h3::error::StreamError>() {
        return !matches!(
            error,
            h3::error::StreamError::StreamError { .. }
                | h3::error::StreamError::RemoteTerminate { .. }
                | h3::error::StreamError::HeaderTooBig { .. }
        );
    }
    false
}

pub(super) fn uri(config: &UpstreamConfig) -> Result<http::Uri> {
    let host = if config.host.contains(':') {
        format!("[{}]", config.host)
    } else {
        config.host.clone()
    };
    // HTTP/3 also uses https on the wire (RFC 9114 section 4.3.1).
    Ok(format!("https://{host}:{}{}", config.port, config.path).parse()?)
}

pub(super) fn request_wire(request: &Message) -> Result<Vec<u8>> {
    let mut request = request.clone();
    request.metadata.id = 0;
    let wire = request.to_vec()?;
    check_body_size(0, wire.len())?;
    Ok(wire)
}

pub(super) fn request_headers(uri: http::Uri, length: usize) -> Result<http::Request<()>> {
    Ok(http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .header("content-length", length)
        .body(())?)
}

pub(super) fn response_metadata(
    status: http::StatusCode,
    headers: &http::HeaderMap,
) -> Result<(Option<u64>, u32)> {
    if !status.is_success() {
        bail!("DoH HTTP status {status}");
    }
    let content_type = headers
        .get("content-type")
        .context("missing DoH content-type")?
        .to_str()?;
    if !content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/dns-message")
    {
        bail!("invalid DoH content-type");
    }
    let number = |name: &str| -> Result<Option<u64>> {
        headers
            .get(name)
            .map(|value| Ok(value.to_str()?.parse()?))
            .transpose()
    };
    let length = number("content-length")?;
    if length.is_some_and(|length| length > u16::MAX as u64) {
        bail!("DoH body exceeds DNS message limit");
    }
    Ok((
        length,
        number("age")?.unwrap_or(0).min(u32::MAX as u64) as u32,
    ))
}

pub(super) fn check_body_size(current: usize, additional: usize) -> Result<()> {
    if additional > (u16::MAX as usize).saturating_sub(current) {
        bail!("DoH body exceeds DNS message limit");
    }
    Ok(())
}

pub(super) fn decode_response(wire: &[u8], length: Option<u64>, age: u32) -> Result<Message> {
    if length.is_some_and(|length| length != wire.len() as u64) {
        bail!("DoH content-length mismatch");
    }
    let mut response = Message::from_vec(wire)?;
    for record in response
        .answers
        .iter_mut()
        .chain(&mut response.authorities)
        .chain(&mut response.additionals)
    {
        record.ttl = record.ttl.saturating_sub(age);
    }
    Ok(response)
}
