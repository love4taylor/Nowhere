// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Safe endpoints and random instance identifiers.

use anyhow::Result;

pub(crate) fn endpoint(value: &str) -> String {
    let address = if value.starts_with(':') {
        format!("0.0.0.0{value}")
    } else {
        value.to_owned()
    };
    if value.len() <= 512
        && !value.contains(['@', '?', '#', '%', '\\'])
        && !value.chars().any(|c| c.is_control() || c.is_whitespace())
        && crate::common::validate_endpoint_url_input(&format!("portal://{address}"), "telemetry")
            .is_ok()
        && url::Url::parse(&format!("portal://{address}"))
            .ok()
            .and_then(|url| crate::common::ServiceEndpoint::parse(&url, true, "telemetry").ok())
            .is_some()
    {
        value.to_owned()
    } else {
        "<redacted>".to_owned()
    }
}

pub(crate) fn dns_endpoint(value: &str) -> String {
    let valid = || -> Option<String> {
        if value.len() > 512 || value.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return None;
        }
        let url = url::Url::parse(value).ok()?;
        if !matches!(url.scheme(), "https" | "tls" | "quic")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
        {
            return None;
        }
        let host = url.host_str()?;
        let port = url
            .port()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 853 });
        if port == 0 || endpoint(&format!("{host}:{port}")) == "<redacted>" {
            return None;
        }
        Some(format!("{}://{host}:{port}", url.scheme()))
    };
    valid().unwrap_or_else(|| "<redacted>".to_owned())
}

pub(super) fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| anyhow::anyhow!("telemetry entropy unavailable: {e}"))?;
    Ok(hex(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
#[path = "../tests/telemetry/privacy.rs"]
mod tests;
