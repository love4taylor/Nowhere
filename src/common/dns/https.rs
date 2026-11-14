// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Pooled HTTP/2 DNS with bounded bodies, explicit authority and HTTP Age handling.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use hickory_net::proto::op::Message;
use rustls::pki_types::ServerName;
use tokio::task::JoinHandle;

use crate::common::network::connect_tcp_addr;

use super::config::UpstreamConfig;

struct Driver(JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Clone)]
pub(super) struct HttpsSession {
    sender: h2::client::SendRequest<Bytes>,
    uri: http::Uri,
    _driver: Arc<Driver>,
}

impl HttpsSession {
    pub(super) async fn connect(
        config: &UpstreamConfig,
        address: SocketAddr,
        source: Option<std::net::IpAddr>,
        tls: &rustls::ClientConfig,
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
        let host = if config.host.contains(':') {
            format!("[{}]", config.host)
        } else {
            config.host.clone()
        };
        let uri = format!("https://{host}:{}{}", config.port, config.path).parse()?;
        let (sender, connection) = h2::client::Builder::new()
            .enable_push(false)
            .max_header_list_size(8192)
            .max_send_buffer_size(65536)
            .handshake(stream)
            .await?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self {
            sender,
            uri,
            _driver: Arc::new(Driver(driver)),
        })
    }

    pub(super) async fn query(&self, request: &Message) -> Result<Message> {
        let mut request = request.clone();
        request.metadata.id = 0;
        let wire = request.to_vec()?;
        let headers = http::Request::builder()
            .method("POST")
            .uri(self.uri.clone())
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .header("content-length", wire.len())
            .body(())?;
        let mut sender = self.sender.clone().ready().await?;
        let (response, mut body) = sender.send_request(headers, false)?;
        body.send_data(Bytes::from(wire), true)?;
        let response = response.await?;
        if !response.status().is_success() {
            bail!("DoH HTTP status {}", response.status());
        }
        let content_type = response
            .headers()
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
            response
                .headers()
                .get(name)
                .map(|value| Ok(value.to_str()?.parse()?))
                .transpose()
        };
        let length = number("content-length")?;
        if length.is_some_and(|length| length > u16::MAX as u64) {
            bail!("DoH body exceeds DNS message limit");
        }
        let age = number("age")?.unwrap_or(0).min(u32::MAX as u64) as u32;
        let mut body = response.into_body();
        let mut wire = Vec::with_capacity(512);
        while let Some(chunk) = body.data().await {
            let chunk = chunk?;
            if wire.len() + chunk.len() > u16::MAX as usize {
                bail!("DoH body exceeds DNS message limit");
            }
            body.flow_control().release_capacity(chunk.len())?;
            wire.extend_from_slice(&chunk);
        }
        if length.is_some_and(|length| length != wire.len() as u64) {
            bail!("DoH content-length mismatch");
        }
        let mut response = Message::from_vec(&wire)?;
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
}
