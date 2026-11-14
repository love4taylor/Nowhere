// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Outbound address-family policy and source address selection.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Result, bail};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum AddressPreference {
    #[default]
    Default,
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DialPolicy {
    SingleSource {
        source: Option<IpAddr>,
        preference: AddressPreference,
        tcp_concurrent: bool,
    },
    DualStack {
        v4: Option<Ipv4Addr>,
        v6: Option<Ipv6Addr>,
        preference: AddressPreference,
        tcp_concurrent: bool,
    },
}

impl Default for DialPolicy {
    fn default() -> Self {
        Self::SingleSource {
            source: None,
            preference: AddressPreference::Default,
            tcp_concurrent: false,
        }
    }
}

impl DialPolicy {
    pub(crate) fn from_query(query: &HashMap<String, String>) -> Result<Self> {
        let tcp_concurrent = match query.get("tcp-concurrent").map(String::as_str) {
            None | Some("0") => false,
            Some("1") => true,
            Some(_) => bail!("tcp-concurrent must be 0 or 1"),
        };
        let preference = match query.get("prefer").map(String::as_str) {
            None | Some("default") => AddressPreference::Default,
            Some("ipv4") => AddressPreference::Ipv4,
            Some("ipv6") => AddressPreference::Ipv6,
            Some(_) => bail!("prefer must be ipv4, ipv6 or default"),
        };
        let dial = query.get("dial");
        let has_families = query.contains_key("dial4") || query.contains_key("dial6");
        if dial.is_some() && has_families {
            bail!("dial and dial4/dial6 are mutually exclusive");
        }
        if has_families {
            let v4 = match query.get("dial4").map(String::as_str) {
                None | Some("auto") => None,
                Some(value) => Some(
                    value
                        .parse::<Ipv4Addr>()
                        .map_err(|_| anyhow::anyhow!("dial4 must be auto or an IPv4 literal"))?,
                ),
            };
            let v6 = match query.get("dial6").map(String::as_str) {
                None | Some("auto") => None,
                Some(value) => {
                    let ip = value
                        .parse::<Ipv6Addr>()
                        .map_err(|_| anyhow::anyhow!("dial6 must be auto or an IPv6 literal"))?;
                    if ip.to_ipv4_mapped().is_some() {
                        bail!("dial6 must not be an IPv4-mapped IPv6 address");
                    }
                    Some(ip)
                }
            };
            Ok(Self::DualStack {
                v4,
                v6,
                preference,
                tcp_concurrent,
            })
        } else {
            match dial.map(String::as_str) {
                None | Some("auto") => Ok(Self::SingleSource {
                    source: None,
                    preference,
                    tcp_concurrent,
                }),
                Some(value) => Ok(Self::SingleSource {
                    source: Some(
                        value
                            .parse::<IpAddr>()
                            .map_err(|_| anyhow::anyhow!("dial must be auto or an IP literal"))?,
                    ),
                    preference,
                    tcp_concurrent,
                }),
            }
        }
    }

    pub(crate) fn accepts(&self, target: IpAddr) -> bool {
        match self {
            Self::SingleSource {
                source: Some(source),
                ..
            } => source.is_ipv4() == target.is_ipv4(),
            _ => true,
        }
    }

    pub(crate) fn local_ip(&self, target: IpAddr) -> Result<Option<IpAddr>> {
        if !self.accepts(target) {
            bail!("target address family conflicts with dial");
        }
        Ok(match self {
            Self::SingleSource { source, .. } => *source,
            Self::DualStack { v4, .. } if target.is_ipv4() => v4.map(IpAddr::V4),
            Self::DualStack { v6, .. } => v6.map(IpAddr::V6),
        })
    }

    pub(crate) fn preference(&self) -> AddressPreference {
        match self {
            Self::SingleSource { preference, .. } | Self::DualStack { preference, .. } => {
                *preference
            }
        }
    }

    pub(crate) fn tcp_concurrent(&self) -> bool {
        match self {
            Self::SingleSource { tcp_concurrent, .. } | Self::DualStack { tcp_concurrent, .. } => {
                *tcp_concurrent
            }
        }
    }
}

impl fmt::Display for DialPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SingleSource { source, .. } => write!(
                formatter,
                "dial={}",
                source.map_or_else(|| "auto".to_owned(), |ip| ip.to_string())
            ),
            Self::DualStack { v4, v6, .. } => write!(
                formatter,
                "dial4={} dial6={}",
                v4.map_or_else(|| "auto".to_owned(), |ip| ip.to_string()),
                v6.map_or_else(|| "auto".to_owned(), |ip| ip.to_string())
            ),
        }
    }
}

#[cfg(test)]
#[path = "../tests/common/dial.rs"]
mod tests;
