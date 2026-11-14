// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Verified transports, fallback recovery, ingress framing and resolver dialing.

use super::*;

#[tokio::test]
async fn doh_dot_doq_validate_certificates_reuse_sessions_and_resolve_both_families() {
    for transport in ["https", "tls", "quic"] {
        let server = TestServer::new(transport).await;
        let resolver = server.resolver(&[]);
        for id in [101, 102] {
            let response = ask(&resolver, &format!("unique{id}.test."), id).await;
            assert_eq!(response.metadata.id, id, "{transport}");
            assert_eq!(
                response.metadata.response_code,
                ResponseCode::NoError,
                "{transport}: {response:?}"
            );
            assert_eq!(response.answers.len(), 1);
        }
        let addresses = resolver.lookup_ip("addresses.test.", 443).await.unwrap();
        assert_eq!(
            addresses,
            vec![
                "127.0.0.1:443".parse::<SocketAddr>().unwrap(),
                "[::1]:443".parse().unwrap()
            ]
        );
        assert_eq!(
            server.connections.load(Ordering::Relaxed),
            1,
            "{transport} must reuse connections"
        );
        let empty_roots = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
        );
        let invalid =
            DnsResolver::with_tls(resolver.config.clone(), DialPolicy::default(), empty_roots)
                .unwrap();
        assert_eq!(
            ask(&invalid, "untrusted.test.", 103)
                .await
                .metadata
                .response_code,
            ResponseCode::ServFail,
            "{transport} must reject untrusted certificates"
        );
    }
}

#[tokio::test]
async fn hanging_primary_falls_back_in_milliseconds_skips_failed_primary_and_recovers() {
    let primary = TestServer::new("tls").await;
    let fallback = TestServer::new("https").await;
    primary.mode.store(1, Ordering::Relaxed);
    let resolver = primary.resolver_with_fallback(
        Some(&fallback),
        &[
            ("dns-fallback-delay", "30ms"),
            ("dns-probe-interval", "40ms"),
            ("dns-timeout", "500ms"),
        ],
    );
    let start = Instant::now();
    let response = ask(&resolver, "failover.test.", 1).await;
    let failover = start.elapsed();
    assert_eq!(response.answers.len(), 1);
    assert!(
        failover >= Duration::from_millis(30) && failover < Duration::from_millis(250),
        "{failover:?}"
    );
    tokio::time::timeout(Duration::from_millis(250), async {
        while !resolver.upstreams[0].unhealthy.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    let start = Instant::now();
    assert_eq!(
        ask(&resolver, "skip-primary.test.", 2).await.answers.len(),
        1
    );
    let subsequent = start.elapsed();
    assert!(subsequent < Duration::from_millis(30), "{subsequent:?}");
    primary.mode.store(0, Ordering::Relaxed);
    let start = Instant::now();
    tokio::time::timeout(Duration::from_millis(350), async {
        while resolver.upstreams[0].unhealthy.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    let recovery = start.elapsed();
    let old_fallback = fallback.count.load(Ordering::Relaxed);
    assert_eq!(ask(&resolver, "recovered.test.", 3).await.answers.len(), 1);
    assert_eq!(fallback.count.load(Ordering::Relaxed), old_fallback);
    eprintln!("DNS failover={failover:?}, subsequent={subsequent:?}, recovery={recovery:?}");
}

#[tokio::test]
async fn servfail_or_unrelated_answer_triggers_immediate_fallback_not_negative_caching() {
    for mode in [2, 4] {
        let primary = TestServer::new("quic").await;
        let fallback = TestServer::new("tls").await;
        primary.mode.store(mode, Ordering::Relaxed);
        let resolver =
            primary.resolver_with_fallback(Some(&fallback), &[("dns-fallback-delay", "200ms")]);
        let start = Instant::now();
        assert_eq!(ask(&resolver, "immediate.test.", 1).await.answers.len(), 1);
        assert!(start.elapsed() < Duration::from_millis(190));
        assert_eq!(fallback.count.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn all_upstreams_down_share_one_deadline_and_return_servfail_with_client_id() {
    let primary = TestServer::new("tls").await;
    let fallback = TestServer::new("https").await;
    primary.mode.store(1, Ordering::Relaxed);
    fallback.mode.store(1, Ordering::Relaxed);
    let resolver = primary.resolver_with_fallback(
        Some(&fallback),
        &[("dns-timeout", "120ms"), ("dns-fallback-delay", "20ms")],
    );
    let start = Instant::now();
    let response = ask(&resolver, "all-down.test.", 0x1234).await;
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(response.metadata.id, 0x1234);
    assert!(start.elapsed() < Duration::from_millis(230));
}

#[tokio::test]
async fn udp_truncation_obeys_edns_and_tcp_returns_the_full_message() {
    let server = TestServer::new("tls").await;
    let resolver = server.resolver(&[]);
    let mut request = request("large.test.", 17);
    let response = Message::from_vec(
        &resolver
            .answer(&request.to_vec().unwrap(), true)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(response.metadata.truncation);
    assert!(response.answers.is_empty());
    request.edns = Some(Edns::new());
    request.edns.as_mut().unwrap().set_max_payload(4096);
    let wire = resolver
        .answer(&request.to_vec().unwrap(), true)
        .await
        .unwrap();
    let response = Message::from_vec(&wire).unwrap();
    assert!(!response.metadata.truncation);
    assert!(wire.len() > 512 && wire.len() < 4096);
    let full = Message::from_vec(
        &resolver
            .answer(&request.to_vec().unwrap(), false)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(full.answers.len(), 12);
}

#[tokio::test]
async fn oversized_edns_options_and_multiple_questions_cannot_bypass_udp_limits() {
    use hickory_net::proto::rr::rdata::opt::{EdnsCode, EdnsOption};
    let server = TestServer::new("tls").await;
    let resolver = server.resolver(&[]);
    let mut query = request("options-size.test.", 78);
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    edns.options_mut().options.push((
        EdnsCode::Unknown(65000),
        EdnsOption::Unknown(65000, vec![1; 5000]),
    ));
    query.edns = Some(edns);
    let wire = query.to_vec().unwrap();
    let udp = resolver.answer(&wire, true).await.unwrap();
    assert!(udp.len() <= 4096);
    let response = Message::from_vec(&udp).unwrap();
    assert!(response.metadata.truncation);
    assert!(response.edns.unwrap().options().as_ref().is_empty());
    assert!(resolver.answer(&wire, false).await.unwrap().len() > 4096);
    query.queries = vec![query.queries[0].clone(); 128];
    let response = resolver
        .answer(&query.to_vec().unwrap(), true)
        .await
        .unwrap();
    assert!(response.len() <= 4096);
    let response = Message::from_vec(&response).unwrap();
    assert_eq!(response.metadata.response_code, ResponseCode::FormErr);
    assert!(response.queries.is_empty());
    assert_eq!(server.count.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn tcp_handles_fragmented_and_pipelined_queries_udp_restores_ids_and_releases_resources() {
    let server = TestServer::new("quic").await;
    let resolver = server.resolver(&[]);
    let mut tcp = resolver.open_tcp().unwrap();
    for id in [11, 12] {
        let wire = request("tcp.test.", id).to_vec().unwrap();
        tcp.write_u16(wire.len() as u16).await.unwrap();
        tcp.write_all(&wire[..5]).await.unwrap();
        tcp.write_all(&wire[5..]).await.unwrap();
    }
    for id in [11, 12] {
        let size = tcp.read_u16().await.unwrap();
        let mut wire = vec![0; size as usize];
        tcp.read_exact(&mut wire).await.unwrap();
        assert_eq!(Message::from_vec(&wire).unwrap().metadata.id, id);
    }
    drop(tcp);
    let udp = resolver.open_udp();
    for id in 20..28 {
        udp.send(&request("udp.test.", id).to_vec().unwrap())
            .await
            .unwrap();
    }
    let mut ids = Vec::new();
    for _ in 20..28 {
        ids.push(
            Message::from_vec(&udp.recv().await.unwrap())
                .unwrap()
                .metadata
                .id,
        );
    }
    ids.sort();
    assert_eq!(ids, (20..28).collect::<Vec<_>>());
    drop(udp);
    tokio::time::timeout(Duration::from_secs(1), async {
        while resolver.connections.available_permits() != 64 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn malformed_and_zone_transfer_queries_are_rejected_without_upstream_use() {
    let server = TestServer::new("tls").await;
    let resolver = server.resolver(&[]);
    for wire in [vec![], vec![0x12, 0x34], vec![0; 12]] {
        let response = Message::from_vec(&resolver.answer(&wire, true).await.unwrap()).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::FormErr);
    }
    let mut query = request("zone.test.", 4);
    query.queries[0].set_query_type(RecordType::AXFR);
    let response = Message::from_vec(
        &resolver
            .answer(&query.to_vec().unwrap(), false)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(response.metadata.response_code, ResponseCode::NotImp);
    assert_eq!(server.count.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn edns_options_bypass_cache_and_bad_versions_never_reach_upstream() {
    use hickory_net::proto::rr::rdata::opt::{EdnsCode, EdnsOption};
    let server = TestServer::new("tls").await;
    let resolver = server.resolver(&[]);
    let mut query = request("options.test.", 77);
    let mut edns = Edns::new();
    edns.options_mut().options.push((
        EdnsCode::Unknown(65000),
        EdnsOption::Unknown(65000, vec![1, 2]),
    ));
    query.edns = Some(edns);
    for _ in 0..2 {
        let response = Message::from_vec(
            &resolver
                .answer(&query.to_vec().unwrap(), false)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response.answers.len(), 1);
    }
    assert_eq!(server.count.load(Ordering::Relaxed), 2);
    query.edns.as_mut().unwrap().set_version(1);
    let response = Message::from_vec(
        &resolver
            .answer(&query.to_vec().unwrap(), false)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(u16::from(response.metadata.response_code), 16);
    assert_eq!(response.edns.unwrap().version(), 0);
    assert_eq!(server.count.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn direct_domain_dials_use_builtin_dns_and_keep_preference_concurrency_and_source_binding() {
    use crate::common::{AddressPreference, OutboundDialer};
    let server = TestServer::new("tls").await;
    let resolver = server.resolver(&[]);
    let policy = DialPolicy::DualStack {
        v4: Some("127.0.0.1".parse().unwrap()),
        v6: None,
        preference: AddressPreference::Ipv4,
        tcp_concurrent: true,
    };
    let dialer = OutboundDialer::new(policy, None).with_dns(Some(resolver));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Target::domain(
        "resolved-only-by-fixture.invalid",
        listener.local_addr().unwrap().port(),
    )
    .unwrap();
    let connection = dialer
        .dial_tcp_target(&target, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(connection.peer_addr().unwrap().is_ipv4());
    assert_eq!(
        connection.local_addr().unwrap().ip().to_string(),
        "127.0.0.1"
    );
    assert!(connection.nodelay().unwrap());
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = Target::domain(
        "resolved-only-by-fixture.invalid",
        socket.local_addr().unwrap().port(),
    )
    .unwrap();
    let outbound = dialer
        .dial_udp_target(&target, Duration::from_secs(1))
        .await
        .unwrap();
    outbound.send(b"dns dial", &mut Vec::new()).await.unwrap();
    let mut packet = [0; 32];
    let (size, peer) = tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&packet[..size], b"dns dial");
    assert_eq!(peer.ip().to_string(), "127.0.0.1");
    assert_eq!(
        server.count.load(Ordering::Relaxed),
        2,
        "A/AAAA cache shared by TCP and UDP"
    );
}

#[tokio::test]
async fn doh_rejects_http_errors_and_wrong_mime_and_subtracts_http_age_from_ttls() {
    for mode in [5, 6, 7] {
        let server = TestServer::new("https").await;
        server.mode.store(mode, Ordering::Relaxed);
        let resolver = server.resolver(&[]);
        let response = ask(&resolver, "http.test.", 2).await;
        if mode == 7 {
            assert_eq!(response.answers[0].ttl, 30);
            assert!(ask(&resolver, "http.test.", 3).await.answers[0].ttl <= 30);
            assert_eq!(server.count.load(Ordering::Relaxed), 1);
        } else {
            assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        }
    }
}

#[tokio::test]
async fn doh_ip_url_and_nonstandard_port_keep_correct_tls_identity_and_authority() {
    let mut server = TestServer::new("https").await;
    let mut url = url::Url::parse(&server.url).unwrap();
    url.set_host(Some("127.0.0.1")).unwrap();
    server.url = url.to_string();
    assert_eq!(
        ask(&server.resolver(&[]), "ip-url.test.", 1)
            .await
            .answers
            .len(),
        1
    );
}

#[tokio::test]
async fn closed_pooled_dot_session_reconnects_without_failing_the_next_question() {
    let server = TestServer::new("tls").await;
    server.mode.store(8, Ordering::Relaxed);
    let resolver = server.resolver(&[]);
    assert_eq!(ask(&resolver, "first.test.", 1).await.answers.len(), 1);
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(ask(&resolver, "second.test.", 2).await.answers.len(), 1);
    assert_eq!(server.connections.load(Ordering::Relaxed), 2);
}
