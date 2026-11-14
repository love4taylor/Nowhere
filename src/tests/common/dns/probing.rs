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
async fn configured_target_must_have_a_positive_answer_and_recovery_uses_the_same_target() {
    for mode in [13, 14] {
        let primary = TestServer::new("tls").await;
        primary.mode.store(mode, Ordering::Relaxed);
        let resolver = primary.resolver(&[
            ("dns-probe-target", "probe-target.test"),
            ("dns-probe-interval", "20ms"),
        ]);
        assert_eq!(ask(&resolver, "normal.test.", 1).await.answers.len(), 1);
        assert!(resolver.snapshot().upstreams[0].healthy);
        resolver.upstreams[0].request_probe();
        tokio::time::timeout(Duration::from_millis(250), async {
            while resolver.snapshot().upstreams[0].healthy {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(resolver.snapshot().preferred_upstream, None);
        assert_eq!(resolver.snapshot().last_upstream, Some(0));
        primary.mode.store(0, Ordering::Relaxed);
        tokio::time::timeout(Duration::from_millis(250), async {
            while !resolver.snapshot().upstreams[0].healthy {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(resolver.snapshot().preferred_upstream, Some(0));
        assert_eq!(resolver.snapshot().last_upstream, Some(0));
        assert_eq!(resolver.snapshot().queries, 1);
    }
}
