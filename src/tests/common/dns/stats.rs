// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Passive snapshots, cache accounting and actual fallback/recovery ownership.

use super::*;

#[tokio::test]
async fn snapshots_are_passive_and_expose_only_upstream_transport_host_and_port() {
    for transport in ["https", "h3"] {
        let mut server = TestServer::new(transport).await;
        let mut url = url::Url::parse(&server.url).unwrap();
        url.set_path("/private-account-id");
        server.url = url.to_string();
        let resolver = server.resolver(&[]);
        for _ in 0..10 {
            let snapshot = resolver.snapshot();
            assert_eq!(snapshot.preferred_upstream, Some(0));
            assert_eq!(snapshot.last_upstream, None);
            assert_eq!(snapshot.queries, 0);
            assert_eq!(snapshot.cache_entries, 0);
            assert_eq!(snapshot.in_flight, 0);
            let wire = serde_json::to_string(&snapshot).unwrap();
            assert!(wire.contains(&format!("{transport}://localhost:")));
            assert!(!wire.contains("private-account-id"));
            assert!(!wire.contains("bootstrap"));
        }
        assert_eq!(server.count.load(Ordering::Relaxed), 0);
        assert_eq!(server.connections.load(Ordering::Relaxed), 0);
        assert!(resolver.probes.get().is_none());
    }
}

#[tokio::test]
async fn telemetry_distinguishes_current_health_last_winner_cache_and_recovery_probes() {
    let primary = TestServer::new("tls").await;
    let fallback = TestServer::new("https").await;
    primary.mode.store(4, Ordering::Relaxed);
    let resolver =
        primary.resolver_with_fallback(Some(&fallback), &[("dns-probe-interval", "20ms")]);
    assert_eq!(
        ask(&resolver, "failover-stats.test.", 1)
            .await
            .answers
            .len(),
        1
    );
    assert_eq!(
        ask(&resolver, "failover-stats.test.", 2)
            .await
            .answers
            .len(),
        1
    );
    tokio::time::timeout(Duration::from_millis(250), async {
        while !resolver.upstreams[0].unhealthy.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    let snapshot = resolver.snapshot();
    assert_eq!(snapshot.queries, 2);
    assert_eq!(snapshot.cache_hits, 1);
    assert_eq!(snapshot.cache_misses, 1);
    assert_eq!(snapshot.tcp_queries, 2);
    assert_eq!(snapshot.udp_queries, 0);
    assert_eq!(snapshot.preferred_upstream, Some(1));
    assert_eq!(snapshot.last_upstream, Some(1));
    assert_eq!(snapshot.fallback_replies, 1);
    assert_eq!(snapshot.upstream_switches, 0);
    assert_eq!(snapshot.upstreams[0].queries, 1);
    assert_eq!(snapshot.upstreams[0].failures, 1);
    assert!(!snapshot.upstreams[0].healthy);
    assert!(snapshot.upstreams[1].fallback);
    assert!(snapshot.upstreams[1].last_latency_us.is_some());
    assert_eq!(snapshot.cache_entries, 1);
    assert!(snapshot.cache_bytes > 0);
    primary.mode.store(0, Ordering::Relaxed);
    resolver.upstreams[0]
        .probe(&request(".", 0), Duration::from_millis(200))
        .await
        .unwrap();
    let recovered = resolver.snapshot();
    assert_eq!(recovered.preferred_upstream, Some(0));
    assert_eq!(
        recovered.last_upstream,
        Some(1),
        "probe must not become the last real answer"
    );
    assert_eq!(
        recovered.queries, 2,
        "probes are separate from logical queries"
    );
    assert_eq!(recovered.upstreams[0].queries, 1);
    assert!(recovered.upstreams[0].probes >= 3);
    assert!(recovered.upstreams[0].last_latency_us.is_none());
    assert_eq!(
        ask(&resolver, "recovered-stats.test.", 3)
            .await
            .answers
            .len(),
        1
    );
    let snapshot = resolver.snapshot();
    assert_eq!(snapshot.last_upstream, Some(0));
    assert_eq!(snapshot.upstream_switches, 1);
    assert_eq!(snapshot.fallback_replies, 1);
}

#[tokio::test]
async fn failed_resolution_and_malformed_hijacked_packets_have_distinct_counts() {
    let server = TestServer::new("tls").await;
    server.mode.store(1, Ordering::Relaxed);
    let resolver = server.resolver(&[("dns-timeout", "100ms"), ("dns-fallback-delay", "20ms")]);
    assert_eq!(
        ask(&resolver, "failed-stats.test.", 1)
            .await
            .metadata
            .response_code,
        ResponseCode::ServFail
    );
    let malformed =
        Message::from_vec(&resolver.answer(&[0x12, 0x34], true).await.unwrap()).unwrap();
    assert_eq!(malformed.metadata.response_code, ResponseCode::FormErr);
    tokio::time::timeout(Duration::from_millis(750), async {
        while !resolver.upstreams[0].unhealthy.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    let snapshot = resolver.snapshot();
    assert_eq!(snapshot.queries, 1);
    assert_eq!(snapshot.failures, 1);
    assert_eq!(snapshot.tcp_queries, 1);
    assert_eq!(snapshot.udp_queries, 1);
    assert_eq!(snapshot.preferred_upstream, None);
    assert_eq!(snapshot.last_upstream, None);
    assert_eq!(snapshot.upstreams[0].failures, 1);
}
