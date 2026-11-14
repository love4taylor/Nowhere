// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! HTTP stream isolation, bounded pools, prewarming and keepalive recovery.

use super::*;

#[tokio::test]
async fn request_errors_and_stream_resets_preserve_http_connections() {
    for transport in ["https", "h3"] {
        let server = TestServer::new(transport).await;
        let resolver = server.resolver(&[("dns-http-pool-size", "1")]);
        let upstream = &resolver.upstreams[0];
        assert!(upstream.query(&request("warm.test.", 1)).await.is_ok());
        // Bad MIME/status, CANCEL/REFUSED_STREAM, malformed DNS, excessive
        // declared/actual bodies all fail only this request, without reconnect.
        for mode in [5, 6, 16, 17, 18, 19, 20, 21] {
            server.mode.store(mode, Ordering::Relaxed);
            let count = server.count.load(Ordering::Relaxed);
            assert!(
                upstream
                    .query(&request("bad.test.", mode.into()))
                    .await
                    .is_err(),
                "{transport} mode={mode}"
            );
            assert_eq!(
                server.count.load(Ordering::Relaxed),
                count + 1,
                "must not retry request errors: {transport} mode={mode}"
            );
            server.mode.store(0, Ordering::Relaxed);
            assert_eq!(
                upstream
                    .query(&request("after.test.", 100))
                    .await
                    .unwrap()
                    .answers
                    .len(),
                1,
                "{transport} mode={mode}"
            );
            assert_eq!(
                server.connections.load(Ordering::Relaxed),
                1,
                "{transport} mode={mode} must preserve session"
            );
        }
    }
}

#[tokio::test]
async fn failing_http_stream_does_not_cancel_parallel_successes() {
    for transport in ["https", "h3"] {
        let server = TestServer::new(transport).await;
        let resolver = server.resolver(&[("dns-http-pool-size", "1")]);
        resolver.upstreams[0].prewarm().await;
        server.mode.store(16, Ordering::Relaxed);
        server.delay.store(30, Ordering::Relaxed);
        let mut tasks = JoinSet::new();
        for id in 0..32 {
            let resolver = resolver.clone();
            tasks.spawn(async move {
                let bad = id % 4 == 0;
                let name = if bad {
                    format!("bad.{id}.test.")
                } else {
                    format!("good.{id}.test.")
                };
                let result = resolver.upstreams[0].query(&request(&name, id)).await;
                assert_eq!(result.is_err(), bad, "id={id}: {result:?}");
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert_eq!(server.count.load(Ordering::Relaxed), 32);
        assert_eq!(server.connections.load(Ordering::Relaxed), 1, "{transport}");
    }
}

#[tokio::test]
async fn http_pools_bound_connections_and_multiplex_parallel_queries() {
    for (transport, size) in [("https", "1"), ("https", "2"), ("https", "4"), ("h3", "4")] {
        let server = TestServer::new(transport).await;
        let resolver = server.resolver(&[("dns-http-pool-size", size)]);
        server.delay.store(40, Ordering::Relaxed);
        let start = Instant::now();
        let mut tasks = JoinSet::new();
        for id in 0..48 {
            let resolver = resolver.clone();
            tasks.spawn(async move {
                assert_eq!(
                    resolver.upstreams[0]
                        .query(&request(&format!("parallel-{id}.test."), id))
                        .await
                        .unwrap()
                        .answers
                        .len(),
                    1
                );
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "requests must multiplex instead of serializing: {:?}",
            start.elapsed()
        );
        let expected = if transport == "h3" {
            1
        } else {
            size.parse::<usize>().unwrap()
        };
        assert_eq!(server.connections.load(Ordering::Relaxed), expected);
        assert_eq!(server.count.load(Ordering::Relaxed), 48);
        // Cancelling an in-flight request must release its pool load guard.
        assert!(
            tokio::time::timeout(
                Duration::from_millis(5),
                resolver.upstreams[0].query(&request("cancel.test.", 60))
            )
            .await
            .is_err()
        );
        server.delay.store(0, Ordering::Relaxed);
        for id in 70..78 {
            assert!(
                resolver.upstreams[0]
                    .query(&request("reuse.test.", id))
                    .await
                    .is_ok()
            );
        }
        assert_eq!(server.connections.load(Ordering::Relaxed), expected);
    }
}

#[tokio::test]
async fn prewarming_establishes_connections_without_dns_queries_or_health_changes() {
    for (transport, expected) in [("https", 3), ("h3", 1), ("tls", 0), ("quic", 0)] {
        let server = TestServer::new(transport).await;
        let resolver = server.resolver(&[("dns-http-pool-size", "3")]);
        resolver.upstreams[0].prewarm().await;
        // Allow the peer to observe completed TLS handshakes.
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            server.connections.load(Ordering::Relaxed),
            expected,
            "{transport}"
        );
        assert_eq!(server.count.load(Ordering::Relaxed), 0);
        let stats = resolver.upstreams[0].snapshot(false);
        assert_eq!((stats.queries, stats.probes, stats.failures), (0, 0, 0));
        assert!(stats.healthy);
        assert!(resolver.probes.get().is_none());
        resolver.upstreams[0].prewarm().await;
        assert_eq!(server.connections.load(Ordering::Relaxed), expected);
        let disabled = server.resolver(&[("dns-http-prewarm", "0")]);
        disabled.upstreams[0].prewarm().await;
        assert_eq!(server.connections.load(Ordering::Relaxed), expected);
    }
}

#[tokio::test]
async fn h2_ping_keeps_idle_sessions_and_replaces_unresponsive_peers() {
    let server = TestServer::new("https").await;
    let resolver = server.resolver(&[
        ("dns-http-pool-size", "1"),
        ("dns-http-keepalive", "20ms"),
        ("dns-http-ping-timeout", "30ms"),
    ]);
    resolver.upstreams[0].prewarm().await;
    tokio::time::sleep(Duration::from_millis(140)).await;
    assert_eq!(
        server.count.load(Ordering::Relaxed),
        0,
        "PING is not a DNS query"
    );
    assert!(
        resolver.upstreams[0]
            .query(&request("after-pings.test.", 1))
            .await
            .is_ok()
    );
    assert_eq!(server.connections.load(Ordering::Relaxed), 1);
    server.mode.store(15, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(150)).await;
    server.mode.store(0, Ordering::Relaxed);
    assert!(
        resolver.upstreams[0]
            .query(&request("after-blackhole.test.", 2))
            .await
            .is_ok()
    );
    assert_eq!(
        server.connections.load(Ordering::Relaxed),
        2,
        "missing PING ACK must expire only this connection"
    );
    assert_eq!(
        resolver.upstreams[0].snapshot(false).failures,
        0,
        "background keepalive must not fabricate DNS failures"
    );
}

#[tokio::test]
async fn h2_goaway_reconnects_without_poisoning_the_pool() {
    let server = TestServer::new("https").await;
    let resolver = server.resolver(&[("dns-http-pool-size", "1")]);
    assert!(
        resolver.upstreams[0]
            .query(&request("before-goaway.test.", 1))
            .await
            .is_ok()
    );
    server.mode.store(22, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(30)).await;
    server.mode.store(0, Ordering::Relaxed);
    assert!(
        resolver.upstreams[0]
            .query(&request("after-goaway.test.", 2))
            .await
            .is_ok()
    );
    assert_eq!(server.connections.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn http3_falls_back_to_h2_and_accounts_for_http_age() {
    let primary = TestServer::new("h3").await;
    let fallback = TestServer::new("https").await;
    let resolver =
        primary.resolver_with_fallback(Some(&fallback), &[("dns-fallback-delay", "100ms")]);
    primary.mode.store(6, Ordering::Relaxed);
    assert_eq!(
        ask(&resolver, "fallback-http3.test.", 123)
            .await
            .answers
            .len(),
        1
    );
    assert_eq!(fallback.count.load(Ordering::Relaxed), 1);
    primary.mode.store(7, Ordering::Relaxed);
    let response = resolver.upstreams[0]
        .query(&request("aged-http3.test.", 124))
        .await
        .unwrap();
    assert_eq!(response.answers[0].ttl, 30);
    assert_eq!(
        resolver.upstreams[0]
            .snapshot(false)
            .endpoint
            .split(':')
            .next(),
        Some("h3")
    );
}

#[tokio::test]
async fn h2_ping_failure_replaces_only_the_failed_pool_slot() {
    let server = TestServer::new("https").await;
    let resolver = server.resolver(&[
        ("dns-http-pool-size", "3"),
        ("dns-http-keepalive", "20ms"),
        ("dns-http-ping-timeout", "30ms"),
    ]);
    resolver.upstreams[0].prewarm().await;
    // First connection stalls while the other two keep ACKing PING.
    server.mode.store(23, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(150)).await;
    server.mode.store(0, Ordering::Relaxed);
    for id in 0..6 {
        assert!(
            resolver.upstreams[0]
                .query(&request("replace-one.test.", id))
                .await
                .is_ok()
        );
    }
    assert_eq!(server.connections.load(Ordering::Relaxed), 4);
}
