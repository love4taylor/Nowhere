// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Certificate-verified HTTP/3 DoH over multiplexed QUIC streams.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use bytes::{Buf, Bytes};
use hickory_net::proto::op::Message;

use super::config::{HttpOptions, UpstreamConfig};
use super::https::{self, Driver};

#[derive(Clone)]
pub(super) struct Http3Session {
    sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    uri: http::Uri,
    driver: Arc<Driver>,
}

struct RequestStream {
    stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    complete: bool,
}

impl Drop for RequestStream {
    fn drop(&mut self) {
        if !self.complete {
            // h3-quinn 0.0.10 moves RecvStream into its pending read future:
            // stop_sending() there would panic after a cancelled recv_data().
            // Dropping that future safely drops Quinn's RecvStream, which
            // implicitly sends STOP_SENDING. Reset the send half explicitly.
            self.stream
                .stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        }
    }
}

impl Http3Session {
    pub(super) async fn connect(
        config: &UpstreamConfig,
        address: SocketAddr,
        source: Option<IpAddr>,
        tls: &rustls::ClientConfig,
        options: &HttpOptions,
    ) -> Result<Self> {
        let uri = https::uri(config)?;
        let mut tls = tls.clone();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(options.keepalive));
        transport.max_idle_timeout(Some(
            (options.keepalive + options.ping_timeout + Duration::from_secs(1)).try_into()?,
        ));
        // HTTP/3 servers do not initiate request streams.
        transport.max_concurrent_bidi_streams(0u32.into());
        transport.max_concurrent_uni_streams(16u32.into());
        transport.stream_receive_window(65536u32.into());
        transport.receive_window((1024u32 * 1024).into());
        transport.send_window(1024 * 1024);
        client.transport_config(Arc::new(transport));
        let bind = SocketAddr::new(
            source.unwrap_or(if address.is_ipv4() {
                IpAddr::from([0, 0, 0, 0])
            } else {
                IpAddr::from([0u16; 8])
            }),
            0,
        );
        let mut endpoint = quinn::Endpoint::client(bind)?;
        endpoint.set_default_client_config(client);
        let quic = endpoint.connect(address, &config.host)?.await?;
        let (mut connection, sender) = h3::client::builder()
            .max_field_section_size(8192)
            .build(h3_quinn::Connection::new(quic.clone()))
            .await?;
        let closed = Arc::new(AtomicBool::new(false));
        let done = closed.clone();
        let task = tokio::spawn(async move {
            let _ = connection.wait_idle().await;
            done.store(true, Ordering::Release);
        });
        Ok(Self {
            sender,
            uri,
            driver: Arc::new(Driver {
                task,
                closed,
                quic: Some((endpoint, quic)),
            }),
        })
    }

    pub(super) fn is_usable(&self) -> bool {
        !self.driver.closed.load(Ordering::Acquire)
            && self
                .driver
                .quic
                .as_ref()
                .is_some_and(|(_, connection)| connection.close_reason().is_none())
    }

    pub(super) async fn query(&self, request: &Message) -> Result<Message> {
        let wire = https::request_wire(request)?;
        let mut sender = self.sender.clone();
        let stream = sender
            .send_request(https::request_headers(self.uri.clone(), wire.len())?)
            .await?;
        // The guard also cancels when a timeout/fallback drops the query future.
        let mut guard = RequestStream {
            stream,
            complete: false,
        };
        let stream = &mut guard.stream;
        let result = async {
            stream.send_data(Bytes::from(wire)).await?;
            stream.finish().await?;
            let response = stream.recv_response().await?;
            let (length, age) = https::response_metadata(response.status(), response.headers())?;
            let mut wire = Vec::with_capacity(512);
            while let Some(mut chunk) = stream.recv_data().await? {
                https::check_body_size(wire.len(), chunk.remaining())?;
                while chunk.has_remaining() {
                    let data = chunk.chunk();
                    wire.extend_from_slice(data);
                    let length = data.len();
                    chunk.advance(length);
                }
            }
            https::decode_response(&wire, length, age)
        }
        .await;
        guard.complete = result.is_ok();
        result
    }
}
