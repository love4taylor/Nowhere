// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Explicit plaintext DNS, with randomized UDP requests and pooled TCP fallback.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Result, anyhow};
use futures_util::StreamExt;
use hickory_net::DnsHandle;
use hickory_net::proto::op::{DnsRequest, DnsRequestOptions, Message};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
use hickory_net::xfer::DnsExchange;
use tokio::sync::Mutex;

type Exchange = DnsExchange<TokioRuntimeProvider>;

pub(super) async fn query_exchange(exchange: &Exchange, request: &Message) -> Result<Message> {
    Ok(exchange
        .send(DnsRequest::new(
            request.clone(),
            DnsRequestOptions::default(),
        ))
        .next()
        .await
        .ok_or_else(|| anyhow!("DNS upstream closed"))??
        .into_message())
}

pub(super) async fn connect_tcp(
    address: SocketAddr,
    bind: Option<SocketAddr>,
    timeout: Duration,
    provider: TokioRuntimeProvider,
) -> Result<Exchange> {
    // Hickory's Tokio provider enables TCP_NODELAY and honors the source bind.
    Ok(TcpClientStream::exchange(address, bind, timeout, Some(128), provider).await?)
}

#[derive(Default)]
struct TcpFallback {
    generation: u64,
    exchange: Option<Exchange>,
}

pub(super) struct UdpSession {
    exchange: Exchange,
    address: SocketAddr,
    bind: Option<SocketAddr>,
    timeout: Duration,
    provider: TokioRuntimeProvider,
    tcp: Mutex<TcpFallback>,
}

impl UdpSession {
    pub(super) fn new(
        address: SocketAddr,
        bind: Option<SocketAddr>,
        timeout: Duration,
        provider: TokioRuntimeProvider,
    ) -> Self {
        let exchange = UdpClientStream::builder(address, provider.clone())
            .with_bind_addr(bind)
            .with_timeout(Some(timeout))
            // One attempt: upstream hedging and deadlines already govern retry.
            .with_max_retries(1)
            .exchange();
        Self {
            exchange,
            address,
            bind,
            timeout,
            provider,
            tcp: Mutex::new(TcpFallback::default()),
        }
    }

    pub(super) async fn query(&self, request: &Message) -> Result<Message> {
        let mut randomized = request.clone();
        let mut id = [0; 2];
        getrandom::fill(&mut id)
            .map_err(|error| anyhow!("DNS transaction ID entropy unavailable: {error}"))?;
        randomized.metadata.id = u16::from_ne_bytes(id);
        // Hickory uses a fresh random source port per request and ignores replies
        // with the wrong source, transaction ID or question.
        let response = query_exchange(&self.exchange, &randomized).await?;
        super::upstream::validate_response(request, &response)?;
        if !response.metadata.truncation {
            return Ok(response);
        }
        // TC requires a full answer from the same peer over TCP. The caller's
        // original timeout encompasses UDP, connection setup and TCP exchange.
        self.query_tcp(request).await
    }

    async fn query_tcp(&self, request: &Message) -> Result<Message> {
        let mut retry = true;
        loop {
            let (exchange, generation, reused) = {
                let mut tcp = self.tcp.lock().await;
                let reused = tcp.exchange.is_some();
                if !reused {
                    tcp.exchange = Some(
                        connect_tcp(self.address, self.bind, self.timeout, self.provider.clone())
                            .await?,
                    );
                    tcp.generation = tcp.generation.wrapping_add(1);
                }
                (
                    tcp.exchange.as_ref().unwrap().clone(),
                    tcp.generation,
                    reused,
                )
            };
            match query_exchange(&exchange, request).await {
                Ok(response) => return Ok(response),
                Err(error) => {
                    let mut tcp = self.tcp.lock().await;
                    if tcp.generation == generation {
                        tcp.exchange = None;
                    }
                    drop(tcp);
                    if reused && retry {
                        retry = false;
                        continue;
                    }
                    return Err(error);
                }
            }
        }
    }
}
