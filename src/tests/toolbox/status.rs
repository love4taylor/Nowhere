// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Local status reads expose only identity and logical statistics.

use super::*;

#[tokio::test]
async fn status_reads_local_statistics_and_redacts_endpoint_credentials() {
    let server = crate::telemetry::TelemetryServer::bind(
        InstanceRole::Portal,
        "secret@localhost:2000",
        Arc::new(crate::transport::Stats::default()),
    )
    .unwrap();
    let discovered = server.discovered();
    let stop = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(server.run(stop.clone()));
    let item = read_status(discovered).await.unwrap();
    assert_eq!(item.endpoint, "<redacted>");
    let output = status_panel(&item);
    assert!(!output.contains("secret"));
    assert!(!output.contains("DNS current"));
    stop.cancel();
    task.await.unwrap();
}

#[tokio::test]
async fn dns_statistics_round_trip_through_ipc_without_extra_queries() {
    let upstream = crate::common::dns::tests::TestServer::new("https").await;
    let resolver = upstream.resolver(&[]);
    for role in [InstanceRole::Portal, InstanceRole::Egress] {
        let initial = resolver.snapshot();
        let server = crate::telemetry::TelemetryServer::bind(
            role,
            "127.0.0.1:2000",
            Arc::new(crate::transport::Stats::default()),
        )
        .unwrap()
        .with_dns(Some(resolver.clone()));
        let discovered = server.discovered();
        let stop = tokio_util::sync::CancellationToken::new();
        let task = tokio::spawn(server.run(stop.clone()));
        let item = read_status(discovered.clone()).await.unwrap();
        assert_eq!(item.snapshot.dns.as_ref().unwrap(), &initial);
        if initial.last_upstream.is_none() {
            assert!(status_panel(&item).contains("DNS last used  none yet"));
        }
        resolver.lookup_ip("status.test", 443).await.unwrap();
        let before = resolver.snapshot();
        let item = read_status(discovered).await.unwrap();
        assert_eq!(item.snapshot.dns.as_ref().unwrap(), &before);
        let output = status_panel(&item);
        assert!(
            output.contains("DNS current  #1 primary https://localhost:"),
            "{output}"
        );
        assert!(output.contains("DNS hijack  on (TCP/UDP 53)"));
        assert!(output.contains("DNS cache size  2 entries"));
        assert_eq!(resolver.snapshot(), before, "status reads must be passive");
        stop.cancel();
        task.await.unwrap();
    }
}

#[test]
fn dns_output_handles_degraded_upstreams_missing_indices_and_sensitive_metadata() {
    use crate::telemetry::DnsUpstreamSnapshot;
    let mut dns = DnsSnapshot {
        queries: 10,
        cache_hits: 6,
        stale_hits: 2,
        cache_misses: 2,
        last_upstream: Some(0),
        upstreams: vec![DnsUpstreamSnapshot {
            endpoint: "https://user:private-secret@dns.example/private-path?token=private-token"
                .to_owned(),
            fallback: true,
            ..Default::default()
        }],
        ..Default::default()
    };
    let output = dns_rows(&dns)
        .into_iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(output.contains("all degraded; retrying"));
    assert!(output.contains("fresh 6 / stale 2 (80.0%)"));
    assert!(output.contains("#1 fallback <redacted>"));
    assert!(!output.contains("private-"));
    dns.preferred_upstream = Some(999);
    dns.last_upstream = Some(999);
    assert_eq!(dns_upstream(&dns, dns.last_upstream), "none yet");
}
