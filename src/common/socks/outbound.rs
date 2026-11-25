// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Direct-or-SOCKS5 TCP/UDP connection establishment and proxy address retry.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::{Instant, timeout_at};

use crate::common::dns::DnsResolver;
use crate::common::network::{
    connect_tcp_addr, connect_tcp_candidates, connect_udp_addr, connect_udp_candidates,
    dial_tcp_candidates, filter_addrs_for_family,
};
use crate::common::{AddressFamily, DialPolicy, dial_udp_with_policy};
use crate::protocol::Target;

use super::config::SocksConfig;
use super::protocol::{
    COMMAND_CONNECT, COMMAND_UDP_ASSOCIATE, SocksAddress, negotiate, send_command, udp_header,
};
use super::udp::{OutboundUdpSocket, SocksUdpAssociation};

#[derive(Clone, Debug)]
pub(crate) struct OutboundDialer {
    dial_policy: DialPolicy,
    socks: Option<SocksConfig>,
    dns: Option<Arc<DnsResolver>>,
}

impl OutboundDialer {
    pub(crate) fn new(dial_policy: DialPolicy, socks: Option<SocksConfig>) -> Self {
        Self {
            dial_policy,
            socks,
            dns: None,
        }
    }

    pub(crate) fn with_dns(mut self, dns: Option<Arc<DnsResolver>>) -> Self {
        self.dns = dns;
        self
    }

    pub(crate) async fn dial_tcp_target(
        &self,
        target: &Target,
        timeout: Duration,
    ) -> Result<TcpStream> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("TCP dial timeout exceeds timer implementation limit")?;
        let connect = async {
            if let Some(config) = &self.socks {
                return self
                    .dial_socks_tcp(config, &SocksAddress::from_target(target), deadline)
                    .await;
            }
            match target {
                Target::Ip(address) => {
                    connect_tcp_addr(self.dial_policy.local_ip(address.ip())?, *address).await
                }
                Target::Domain { host, port } => {
                    let addresses = resolve_host(host, *port, self.dns.as_ref())
                        .await
                        .context("failed to resolve TCP target")?;
                    let addresses = filter_addrs_for_family(
                        addresses.into_iter(),
                        &self.dial_policy,
                        AddressFamily::Any,
                    );
                    connect_tcp_candidates(&self.dial_policy, addresses, deadline).await
                }
            }
        };
        timeout_at(deadline, connect)
            .await
            .context("common::socks::OutboundDialer::dial_tcp: dial timeout")?
    }

    pub(crate) async fn dial_udp_target(
        &self,
        target: &Target,
        timeout: Duration,
    ) -> Result<OutboundUdpSocket> {
        let Some(config) = &self.socks else {
            return match target {
                Target::Ip(address) => tokio::time::timeout(
                    timeout,
                    connect_udp_addr(self.dial_policy.local_ip(address.ip())?, *address),
                )
                .await
                .context("common::socks::OutboundDialer::dial_udp: dial timeout")?
                .map(OutboundUdpSocket::Direct),
                Target::Domain { host, port } if self.dns.is_some() => {
                    tokio::time::timeout(timeout, async {
                        let addresses = resolve_host(host, *port, self.dns.as_ref()).await?;
                        connect_udp_candidates(
                            &self.dial_policy,
                            filter_addrs_for_family(
                                addresses.into_iter(),
                                &self.dial_policy,
                                AddressFamily::Any,
                            ),
                        )
                        .await
                        .map(OutboundUdpSocket::Direct)
                    })
                    .await
                    .context("DNS UDP dial timeout")?
                }
                Target::Domain { .. } => {
                    dial_udp_with_policy(&self.dial_policy, &target.to_string(), timeout)
                        .await
                        .map(OutboundUdpSocket::Direct)
                }
            };
        };
        let target = SocksAddress::from_target(target);
        tokio::time::timeout(timeout, self.dial_socks_udp(config, target))
            .await
            .context("common::socks::OutboundDialer::dial_udp: dial timeout")?
    }

    async fn dial_socks_tcp(
        &self,
        config: &SocksConfig,
        target: &SocksAddress,
        deadline: Instant,
    ) -> Result<TcpStream> {
        let addrs = resolve_proxy(config, &self.dial_policy, self.dns.as_ref()).await?;
        let connect = |addr: SocketAddr| async move {
            let mut stream = connect_tcp_addr(self.dial_policy.local_ip(addr.ip())?, addr).await?;
            negotiate(&mut stream, config.credentials()).await?;
            send_command(&mut stream, COMMAND_CONNECT, target).await?;
            Ok(stream)
        };
        dial_tcp_candidates(&self.dial_policy, addrs, deadline, connect).await
    }

    async fn dial_socks_udp(
        &self,
        config: &SocksConfig,
        target: SocksAddress,
    ) -> Result<OutboundUdpSocket> {
        let addrs = resolve_proxy(config, &self.dial_policy, self.dns.as_ref()).await?;
        let mut last_err = None;
        for addr in addrs {
            match self
                .open_socks_udp_candidate(config, target.clone(), addr)
                .await
            {
                Ok(association) => return Ok(OutboundUdpSocket::Socks(association)),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            anyhow!("common::socks::OutboundDialer::dial_udp: no proxy address")
        }))
    }

    async fn open_socks_udp_candidate(
        &self,
        config: &SocksConfig,
        target: SocksAddress,
        proxy_addr: SocketAddr,
    ) -> Result<SocksUdpAssociation> {
        let mut control =
            connect_tcp_addr(self.dial_policy.local_ip(proxy_addr.ip())?, proxy_addr).await?;
        negotiate(&mut control, config.credentials()).await?;
        let unspecified = if proxy_addr.is_ipv4() {
            SocksAddress::Ip(SocketAddr::from(([0, 0, 0, 0], 0)))
        } else {
            SocksAddress::Ip(SocketAddr::from(([0u16; 8], 0)))
        };
        let mut relay = send_command(&mut control, COMMAND_UDP_ASSOCIATE, &unspecified).await?;
        relay.replace_unspecified_ip(proxy_addr.ip());
        let relay_addr = resolve_relay(&relay, &self.dial_policy, self.dns.as_ref()).await?;
        let socket =
            connect_udp_addr(self.dial_policy.local_ip(relay_addr.ip())?, relay_addr).await?;
        let target_header = udp_header(&target)?;
        Ok(SocksUdpAssociation {
            control,
            socket,
            target_header,
        })
    }
}

async fn resolve_proxy(
    config: &SocksConfig,
    policy: &DialPolicy,
    dns: Option<&Arc<DnsResolver>>,
) -> Result<Vec<SocketAddr>> {
    let endpoint = config.endpoint();
    let (host, port) = super::config::parse_host_port(&endpoint, "SOCKS5 proxy", false)?;
    let addrs = resolve_host(&host, port, dns)
        .await
        .context("common::socks::resolve_proxy: failed to resolve proxy endpoint")?;
    let addrs = filter_addrs_for_family(addrs.into_iter(), policy, AddressFamily::Any);
    if addrs.is_empty() {
        bail!("common::socks::resolve_proxy: no proxy address matches dial address family");
    }
    Ok(addrs)
}

async fn resolve_relay(
    relay: &SocksAddress,
    policy: &DialPolicy,
    dns: Option<&Arc<DnsResolver>>,
) -> Result<SocketAddr> {
    match relay {
        SocksAddress::Ip(addr) => {
            if addr.port() == 0 {
                bail!("common::socks::resolve_relay: proxy returned zero relay port");
            }
            if !policy.accepts(addr.ip()) {
                bail!("common::socks::resolve_relay: relay address family conflicts with dial");
            }
            Ok(*addr)
        }
        SocksAddress::Domain(host, port) => {
            if *port == 0 {
                bail!("common::socks::resolve_relay: proxy returned zero relay port");
            }
            let addrs = resolve_host(host, *port, dns)
                .await
                .context("common::socks::resolve_relay: failed to resolve relay endpoint")?;
            filter_addrs_for_family(addrs.into_iter(), policy, AddressFamily::Any)
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("common::socks::resolve_relay: no matching relay address"))
        }
    }
}

async fn resolve_host(
    host: &str,
    port: u16,
    dns: Option<&Arc<DnsResolver>>,
) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    match dns {
        Some(dns) => dns.lookup_ip(host, port).await,
        None => Ok(lookup_host((host, port)).await?.collect()),
    }
}

#[cfg(test)]
#[path = "../../tests/common/socks/outbound/mod.rs"]
mod tests;
