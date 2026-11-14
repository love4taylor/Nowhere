// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Bounded local IPC snapshot collection and deterministic one-shot status output.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::telemetry::{
    DnsSnapshot, Hello, InstanceRole, ServerMessage, TelemetryClient, TelemetrySnapshot,
    discover_instances,
};

use super::diagnostic::connection_failure_reason;
use super::format::{bytes, panel};

const STATUS_TIMEOUT: Duration = Duration::from_secs(2);
const STATUS_CONCURRENCY: usize = 8;

pub async fn status() -> Result<()> {
    let discovered = discover_instances().context("failed to discover local instances")?;
    if discovered.is_empty() {
        println!(
            "{}",
            panel("NOWHERE STATUS", &[("Status", "IDLE".to_owned())])
        );
        return Ok(());
    }
    let semaphore = Arc::new(Semaphore::new(STATUS_CONCURRENCY));
    let mut tasks = JoinSet::new();
    for instance in discovered {
        let semaphore = semaphore.clone();
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await.expect("status semaphore");
            (instance.pid, read_status(instance).await)
        });
    }
    let mut items = Vec::new();
    let mut failures = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((_, Ok(item))) => items.push(item),
            Ok((pid, Err(error))) => {
                failures.push(format!("PID {pid}: {}", connection_failure_reason(&error)))
            }
            Err(_) => failures.push("status task failed".to_owned()),
        }
    }
    items.sort_by_key(|item| (item.role, item.pid, item.id.clone()));
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            println!();
        }
        println!("{}", status_panel(item));
    }
    if !failures.is_empty() {
        failures.sort();
        bail!(
            "{} local instance(s) could not be read: {}",
            failures.len(),
            failures.join("; ")
        );
    }
    Ok(())
}

struct StatusItem {
    role: &'static str,
    pid: u32,
    id: String,
    endpoint: String,
    snapshot: TelemetrySnapshot,
}

async fn read_status(instance: crate::telemetry::DiscoveredInstance) -> Result<StatusItem> {
    tokio::time::timeout(STATUS_TIMEOUT, async {
        let client = TelemetryClient::connect(&instance).await?;
        let (hello, mut reader) = client.into_parts();
        let ServerMessage::Snapshot(snapshot) = reader.next_message().await? else {
            bail!("telemetry: service did not send initial snapshot");
        };
        Ok(status_item(hello, snapshot))
    })
    .await
    .context("telemetry snapshot timed out")?
}

fn status_item(hello: Hello, snapshot: TelemetrySnapshot) -> StatusItem {
    let role = match hello.instance.role {
        InstanceRole::Portal => "PORTAL",
        InstanceRole::Vector => "VECTOR",
        InstanceRole::Egress => "EGRESS",
    };
    StatusItem {
        role,
        pid: hello.instance.pid,
        id: hello.instance.id,
        endpoint: crate::telemetry::display_endpoint(&hello.instance.endpoint),
        snapshot,
    }
}

fn status_panel(item: &StatusItem) -> String {
    let mut rows = vec![
        ("Instance", item.id.clone()),
        ("Endpoint", item.endpoint.clone()),
        ("TCP upload", bytes(item.snapshot.tcp_upload_bytes)),
        ("TCP download", bytes(item.snapshot.tcp_download_bytes)),
        ("UDP upload", bytes(item.snapshot.udp_upload_bytes)),
        ("UDP download", bytes(item.snapshot.udp_download_bytes)),
        ("TCP flows", item.snapshot.tcp_active.to_string()),
        ("UDP flows", item.snapshot.udp_active.to_string()),
    ];
    let dns = item.snapshot.dns.as_ref().map(dns_rows).unwrap_or_default();
    rows.extend(
        dns.iter()
            .map(|(label, value)| (label.as_str(), value.clone())),
    );
    panel(&format!("{} · PID {}", item.role, item.pid), &rows)
}

fn dns_upstream(dns: &DnsSnapshot, index: Option<usize>) -> String {
    let Some((index, upstream)) =
        index.and_then(|index| dns.upstreams.get(index).map(|upstream| (index, upstream)))
    else {
        return "none yet".to_owned();
    };
    format!(
        "#{} {} {}",
        index + 1,
        if upstream.fallback {
            "fallback"
        } else {
            "primary"
        },
        crate::telemetry::display_dns_endpoint(&upstream.endpoint)
    )
}

fn dns_rows(dns: &DnsSnapshot) -> Vec<(String, String)> {
    let hits = dns.cache_hits.saturating_add(dns.stale_hits);
    let hit_rate = if dns.queries == 0 {
        0.0
    } else {
        (hits as f64 / dns.queries as f64 * 100.0).min(100.0)
    };
    let current = if dns.preferred_upstream.is_some() {
        dns_upstream(dns, dns.preferred_upstream)
    } else {
        "all degraded; retrying".to_owned()
    };
    let mut rows: Vec<_> = [
        (
            "DNS hijack",
            if dns.hijack { "on (TCP/UDP 53)" } else { "off" }.to_owned(),
        ),
        ("DNS current", current),
        ("DNS last used", dns_upstream(dns, dns.last_upstream)),
        (
            "DNS queries",
            format!("{} (failed {})", dns.queries, dns.failures),
        ),
        (
            "DNS hijacked",
            format!("TCP {} / UDP {}", dns.tcp_queries, dns.udp_queries),
        ),
        (
            "DNS cache hits",
            format!(
                "fresh {} / stale {} ({hit_rate:.1}%)",
                dns.cache_hits, dns.stale_hits
            ),
        ),
        ("DNS cache misses", dns.cache_misses.to_string()),
        (
            "DNS cache size",
            format!(
                "{} entries / {}",
                dns.cache_entries,
                bytes(dns.cache_bytes as u64)
            ),
        ),
        (
            "DNS refreshes",
            format!("{} (shared queries {})", dns.refreshes, dns.deduplicated),
        ),
        (
            "DNS fallbacks",
            format!(
                "{} replies / {} upstream switches",
                dns.fallback_replies, dns.upstream_switches
            ),
        ),
        ("DNS in flight", dns.in_flight.to_string()),
    ]
    .into_iter()
    .map(|(label, value)| (label.to_owned(), value))
    .collect();
    for (index, upstream) in dns.upstreams.iter().enumerate() {
        let latency = upstream.last_latency_us.map_or_else(
            || "n/a".to_owned(),
            |us| super::format::format_duration(Duration::from_micros(us)),
        );
        rows.push((
            format!("DNS upstream #{}", index + 1),
            format!(
                "{} · {} · {} · queries {} / failed {} / probes {} / last {}",
                crate::telemetry::display_dns_endpoint(&upstream.endpoint),
                if upstream.fallback {
                    "fallback"
                } else {
                    "primary"
                },
                if upstream.healthy {
                    "healthy"
                } else {
                    "degraded"
                },
                upstream.queries,
                upstream.failures,
                upstream.probes,
                latency
            ),
        ));
    }
    rows
}

#[cfg(test)]
#[path = "../tests/toolbox/status.rs"]
mod tests;
