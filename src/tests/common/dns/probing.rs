// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Configured health targets distinguish per-question refusals from bad upstreams.

use super::*;

#[tokio::test]
async fn client_dns_errors_fall_back_without_poisoning_a_working_health_target() {
    for transport in ["tls", "https", "quic"] {
        for mode in 9..=12 {
            let primary = TestServer::new(transport).await;
            let fallback = TestServer::new("tls").await;
            primary.mode.store(mode, Ordering::Relaxed);
            let resolver = primary.resolver_with_fallback(
                Some(&fallback),
                &[
                    ("dns-probe-target", "probe-target.test"),
                    ("dns-probe-interval", "20ms"),
                    ("dns-fallback-delay", "200ms"),
                ],
            );
            assert_eq!(
                ask(&resolver, "business-error.test.", 1)
                    .await
                    .answers
                    .len(),
                1
            );
            tokio::time::timeout(Duration::from_millis(250), async {
                while resolver.snapshot().upstreams[0].probes == 0 {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await
            .unwrap();
            let snapshot = resolver.snapshot();
            assert_eq!(
                snapshot.preferred_upstream,
                Some(0),
                "mode={mode} transport={transport}"
            );
            assert_eq!(snapshot.last_upstream, Some(1));
            assert_eq!(snapshot.fallback_replies, 1);
            assert_eq!(snapshot.failures, 0);
            assert_eq!(snapshot.upstreams[0].failures, 1);
            assert!(snapshot.upstreams[0].healthy);
            assert_eq!(
                ask(&resolver, "normal-after-error.test.", 2)
                    .await
                    .answers
                    .len(),
                1
            );
            assert_eq!(resolver.snapshot().last_upstream, Some(0));
        }
    }
}

#[tokio::test]
async fn bad_target_answers_do_not_degrade_a_working_upstream_or_recover_a_bad_one() {
    for mode in [2, 3, 13, 14] {
        let primary = TestServer::new("tls").await;
        primary.mode.store(mode, Ordering::Relaxed);
        let resolver = primary.resolver(&[
            ("dns-probe-target", "probe-target.test"),
            ("dns-probe-interval", "20ms"),
        ]);
        let upstream = &resolver.upstreams[0];
        let probe = request("probe-target.test.", 0);
        for _ in 0..4 {
            assert!(
                upstream
                    .probe(&probe, Duration::from_millis(200))
                    .await
                    .is_err()
            );
        }
        assert!(upstream.snapshot(false).healthy);
        primary.mode.store(4, Ordering::Relaxed);
        for _ in 0..3 {
            assert!(upstream.query(&request("bad.test.", 1)).await.is_err());
        }
        assert!(!upstream.snapshot(false).healthy);
        primary.mode.store(mode, Ordering::Relaxed);
        assert!(
            upstream
                .probe(&probe, Duration::from_millis(200))
                .await
                .is_err()
        );
        assert!(!upstream.snapshot(false).healthy);
        primary.mode.store(0, Ordering::Relaxed);
        upstream
            .probe(&probe, Duration::from_millis(200))
            .await
            .unwrap();
        assert!(upstream.snapshot(false).healthy);
    }
}

#[tokio::test]
async fn real_success_recovers_without_waiting_for_a_probe_or_a_working_target() {
    for transport in ["tls", "https", "quic"] {
        let primary = TestServer::new(transport).await;
        let resolver = primary.resolver(&[("dns-probe-target", "probe-target.test")]);
        let upstream = &resolver.upstreams[0];
        primary.mode.store(4, Ordering::Relaxed);
        for n in 0..3 {
            assert!(upstream.query(&request("broken.test.", n)).await.is_err());
            assert_eq!(upstream.snapshot(false).healthy, n < 2);
        }
        for mode in [0, 3, 14] {
            primary.mode.store(mode, Ordering::Relaxed);
            let name = if mode == 14 {
                "probe-target.test."
            } else {
                "business.test."
            };
            assert!(upstream.query(&request(name, 99)).await.is_ok());
            assert!(upstream.snapshot(false).healthy);
            assert_eq!(upstream.snapshot(false).probes, 0);
            primary.mode.store(4, Ordering::Relaxed);
            for _ in 0..3 {
                assert!(upstream.query(&request("broken.test.", 10)).await.is_err());
            }
            assert!(!upstream.snapshot(false).healthy);
        }
    }
}

#[tokio::test]
async fn repeated_dns_error_codes_do_not_count_as_transport_failures() {
    for transport in ["tls", "https", "quic"] {
        for mode in 9..=12 {
            let server = TestServer::new(transport).await;
            server.mode.store(mode, Ordering::Relaxed);
            let resolver = server.resolver(&[]);
            let upstream = &resolver.upstreams[0];
            for _ in 0..5 {
                assert!(
                    upstream
                        .query(&request("business-error.test.", 1))
                        .await
                        .is_err()
                );
                assert!(upstream.snapshot(false).healthy, "{transport}: {mode}");
                assert!(
                    !upstream.needs_probe(),
                    "DNS errors are not transport failures"
                );
            }
        }
    }
}

#[tokio::test]
async fn in_flight_probe_cannot_override_newer_real_success_or_failures() {
    let server = TestServer::new("https").await;
    let resolver = server.resolver(&[]);
    let upstream = resolver.upstreams[0].clone();
    upstream.query(&request("warm.test.", 1)).await.unwrap();
    for stale_success in [false, true] {
        let count = server.count.load(Ordering::Relaxed);
        server.delay.store(120, Ordering::Relaxed);
        let probe_upstream = upstream.clone();
        let task = tokio::spawn(async move {
            let budget = if stale_success { 300 } else { 80 };
            probe_upstream
                .probe(
                    &request("probe-target.test.", 0),
                    Duration::from_millis(budget),
                )
                .await
        });
        tokio::time::timeout(Duration::from_millis(100), async {
            while server.count.load(Ordering::Relaxed) == count {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        server.delay.store(0, Ordering::Relaxed);
        if stale_success {
            server.mode.store(4, Ordering::Relaxed);
            for _ in 0..3 {
                assert!(upstream.query(&request("failed.test.", 2)).await.is_err());
            }
            assert!(!upstream.snapshot(false).healthy);
            server.mode.store(0, Ordering::Relaxed);
            assert!(task.await.unwrap().is_ok());
            assert!(!upstream.snapshot(false).healthy);
        } else {
            upstream
                .query(&request("new-success.test.", 2))
                .await
                .unwrap();
            assert!(task.await.unwrap().is_err());
            assert!(upstream.snapshot(false).healthy);
            assert!(!upstream.needs_probe());
        }
    }
}
