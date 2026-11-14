// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! In-memory port-53 endpoints. Never expose an unauthenticated DNS listener.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use super::DnsResolver;

pub(crate) struct DnsSocket {
    resolver: Arc<DnsResolver>,
    sender: mpsc::Sender<Vec<u8>>,
    receiver: Mutex<mpsc::Receiver<Vec<u8>>>,
    cancel: CancellationToken,
}

impl DnsSocket {
    pub(crate) async fn send(&self, packet: &[u8]) -> Result<usize> {
        let permit = self
            .resolver
            .connections
            .clone()
            .try_acquire_owned()
            .context("DNS ingress concurrency exhausted")?;
        let packet_len = packet.len();
        let packet = packet.to_vec();
        let resolver = self.resolver.clone();
        let sender = self.sender.clone();
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            let _permit = permit;
            tokio::select! {
                _ = cancel.cancelled() => {},
                result = resolver.answer(&packet, true) => {
                    // A slow client must not retain arbitrary completed DNS answers.
                    if let Ok(response) = result { let _ = sender.try_send(response); }
                }
            }
        });
        Ok(packet_len)
    }

    pub(crate) async fn recv(&self) -> Result<Vec<u8>> {
        self.receiver
            .lock()
            .await
            .recv()
            .await
            .context("DNS socket closed")
    }
}

impl Drop for DnsSocket {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl DnsResolver {
    pub(crate) fn open_udp(self: &Arc<Self>) -> DnsSocket {
        let (sender, receiver) = mpsc::channel(16);
        DnsSocket {
            resolver: self.clone(),
            sender,
            receiver: Mutex::new(receiver),
            cancel: CancellationToken::new(),
        }
    }

    pub(crate) fn open_tcp(self: &Arc<Self>) -> Result<DuplexStream> {
        let permit = self
            .connections
            .clone()
            .try_acquire_owned()
            .context("DNS ingress concurrency exhausted")?;
        let (client, mut server) = tokio::io::duplex(8192);
        let resolver = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // Bound idle and slow-reader/writer resource retention, reset by each complete exchange.
            let _ = serve_tcp_with_idle(&mut server, &resolver).await;
        });
        Ok(client)
    }
}

async fn serve_tcp_with_idle(server: &mut DuplexStream, resolver: &Arc<DnsResolver>) -> Result<()> {
    loop {
        tokio::time::timeout(Duration::from_secs(30), async {
            let size = server.read_u16().await? as usize;
            if size < 12 {
                anyhow::bail!("short TCP DNS frame");
            }
            let mut packet = vec![0; size];
            server.read_exact(&mut packet).await?;
            let response = resolver.answer(&packet, false).await?;
            server.write_u16(u16::try_from(response.len())?).await?;
            server.write_all(&response).await?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("DNS TCP idle timeout")??;
    }
}
