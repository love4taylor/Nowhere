// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Startup-validated encrypted DNS configuration. No implicit plaintext fallback.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rustls::pki_types::ServerName;
use url::Url;

use crate::common::query_first;

pub(crate) const PARAMETERS: &[&str] = &[
    "dns",
    "dns-fallback",
    "dns-hijack",
    "dns-cache-size",
    "dns-cache-bytes",
    "dns-stale",
    "dns-timeout",
    "dns-fallback-delay",
    "dns-probe-interval",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Transport {
    Https,
    Tls,
    Quic,
}

#[derive(Clone, Debug)]
pub(super) struct UpstreamConfig {
    pub(super) transport: Transport,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) path: String,
    pub(super) bootstrap: Option<IpAddr>,
}

impl UpstreamConfig {
    fn parse(raw: &str) -> Result<Self> {
        let url = Url::parse(raw).context("invalid DNS upstream URL")?;
        let (transport, default_port) = match url.scheme() {
            "https" => (Transport::Https, 443),
            "tls" => (Transport::Tls, 853),
            "quic" => (Transport::Quic, 853),
            _ => bail!("DNS upstream requires https:// (DoH), tls:// (DoT) or quic:// (DoQ)"),
        };
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            bail!("DNS upstream must not contain credentials or a fragment");
        }
        let host = url
            .host_str()
            .context("DNS upstream requires a host")?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        ServerName::try_from(host.clone()).context("invalid DNS TLS server name")?;
        let port = url.port().unwrap_or(default_port);
        if port == 0 {
            bail!("DNS upstream port must be nonzero");
        }
        if transport != Transport::Https && !matches!(url.path(), "" | "/") {
            bail!("DoT/DoQ upstream must not contain a path");
        }
        let mut bootstrap = None;
        for (key, value) in url.query_pairs() {
            if key != "bootstrap" || bootstrap.is_some() {
                bail!("DNS upstream accepts only one bootstrap=IP parameter");
            }
            bootstrap = Some(
                value
                    .parse()
                    .context("DNS bootstrap must be an IP literal")?,
            );
        }
        let path = if transport == Transport::Https && matches!(url.path(), "" | "/") {
            "/dns-query".to_owned()
        } else {
            url.path().to_owned()
        };
        Ok(Self {
            transport,
            host,
            port,
            path,
            bootstrap,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DnsConfig {
    pub(super) primary: Vec<UpstreamConfig>,
    pub(super) fallback: Vec<UpstreamConfig>,
    pub(super) hijack: bool,
    pub(super) cache_size: usize,
    pub(super) cache_bytes: usize,
    pub(super) stale: Duration,
    pub(super) timeout: Duration,
    pub(super) fallback_delay: Duration,
    pub(super) probe_interval: Duration,
}

impl DnsConfig {
    pub(crate) fn from_url(url: &Url) -> Result<Option<Self>> {
        let query = query_first(url, PARAMETERS)?;
        let Some(raw) = query.get("dns") else {
            if !query.is_empty() {
                bail!("dns is required with DNS options");
            }
            return Ok(None);
        };
        let list = |raw: &str| -> Result<Vec<UpstreamConfig>> {
            if raw.is_empty() {
                bail!("DNS upstream list must not be empty");
            }
            raw.split(',').map(UpstreamConfig::parse).collect()
        };
        let primary = list(raw)?;
        let fallback = query
            .get("dns-fallback")
            .map(|s| list(s))
            .transpose()?
            .unwrap_or_default();
        if primary.len() + fallback.len() > 8 {
            bail!("at most 8 DNS upstreams are allowed");
        }
        let number = |name: &str, default: usize, max: usize| -> Result<usize> {
            let Some(raw) = query.get(name) else {
                return Ok(default);
            };
            let value: usize = raw.parse().with_context(|| format!("invalid {name}"))?;
            if value == 0 || value > max {
                bail!("{name} must be in 1..={max}");
            }
            Ok(value)
        };
        let duration =
            |name: &str, default: Duration, min: Duration, max: Duration| -> Result<Duration> {
                let value = query
                    .get(name)
                    .map(|raw| humantime::parse_duration(raw))
                    .transpose()
                    .with_context(|| format!("invalid {name}"))?
                    .unwrap_or(default);
                if !(min..=max).contains(&value) {
                    bail!("{name} must be in {min:?}..={max:?}");
                }
                Ok(value)
            };
        let hijack = match query.get("dns-hijack").map(String::as_str) {
            None | Some("1") => true,
            Some("0") => false,
            _ => bail!("dns-hijack must be 0 or 1"),
        };
        let timeout = duration(
            "dns-timeout",
            Duration::from_secs(2),
            Duration::from_millis(10),
            Duration::from_secs(30),
        )?;
        let fallback_delay = duration(
            "dns-fallback-delay",
            Duration::from_millis(50),
            Duration::from_millis(1),
            Duration::from_secs(2),
        )?;
        if fallback_delay >= timeout {
            bail!("dns-fallback-delay must be less than dns-timeout");
        }
        Ok(Some(Self {
            primary,
            fallback,
            hijack,
            cache_size: number("dns-cache-size", 4096, 65536)?,
            cache_bytes: number("dns-cache-bytes", 8 * 1024 * 1024, 64 * 1024 * 1024)?,
            stale: duration(
                "dns-stale",
                Duration::from_secs(3600),
                Duration::ZERO,
                Duration::from_secs(86400),
            )?,
            timeout,
            fallback_delay,
            probe_interval: duration(
                "dns-probe-interval",
                Duration::from_millis(250),
                Duration::from_millis(10),
                Duration::from_secs(60),
            )?,
        }))
    }

    /// The effective service URL deliberately omits upstream names and bootstrap details.
    pub(crate) fn effective(&self) -> String {
        format!("&dns=encrypted&dns-hijack={}", u8::from(self.hijack))
    }
}
