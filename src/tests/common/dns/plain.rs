// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Plaintext transport framing, spoof filtering, TCP retry and deadlines.

use super::*;
use std::sync::Mutex;
use tokio::net::UdpSocket;

struct PlainServer {
    address: SocketAddr,
    answers: Answers,
    udp_count: Arc<AtomicUsize>,
    tcp_count: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    udp_seen: Arc<Mutex<Vec<(SocketAddr, u16)>>>,
    tcp_peers: Arc<Mutex<Vec<SocketAddr>>>,
    task: JoinHandle<()>,
}

impl Drop for PlainServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl PlainServer {
    async fn new(ip: &str) -> Self {
        let listener = TcpListener::bind(format!("{ip}:0")).await.unwrap();
        let address = listener.local_addr().unwrap();
        let udp = Arc::new(UdpSocket::bind(address).await.unwrap());
        let answers = Answers {
            mode: Arc::new(AtomicU8::new(0)),
            count: Arc::new(AtomicUsize::new(0)),
            ttl: Arc::new(AtomicU32::new(60)),
            delay: Arc::new(AtomicU64::new(0)),
        };
        let udp_count = Arc::new(AtomicUsize::new(0));
        let tcp_count = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let udp_seen = Arc::new(Mutex::new(Vec::new()));
        let tcp_peers = Arc::new(Mutex::new(Vec::new()));
        let (a, uc, tc, cc, us, tp) = (
            answers.clone(),
            udp_count.clone(),
            tcp_count.clone(),
            connections.clone(),
            udp_seen.clone(),
            tcp_peers.clone(),
        );
        let task = tokio::spawn(async move {
            let mut jobs = JoinSet::new();
            let mut buffer = vec![0; 65535];
            loop {
                tokio::select! {
                    received = udp.recv_from(&mut buffer) => {
                        let Ok((size, peer)) = received else { break };
                        let wire = buffer[..size].to_vec();
                        us.lock().unwrap().push((peer, u16::from_be_bytes([wire[0], wire[1]])));
                        uc.fetch_add(1, Ordering::Relaxed);
                        let udp = udp.clone();
                        let a = a.clone();
                        jobs.spawn(async move {
                            let Some(wire) = a.answer(&wire).await else { return };
                            let mut response = Message::from_vec(&wire).unwrap();
                            let mode = a.mode.load(Ordering::Relaxed);
                            match mode {
                                // Truncate every UDP response, leaving TCP full.
                                24 | 26 | 27 => {
                                    response.metadata.truncation = true;
                                    response.answers.clear();
                                }
                                // Send forged packets before the legitimate answer.
                                25 => {
                                    let forged = UdpSocket::bind(SocketAddr::new(peer.ip(), 0)).await.unwrap();
                                    let _ = forged.send_to(&wire, peer).await;
                                    response.metadata.id = response.metadata.id.wrapping_add(1);
                                    let _ = udp.send_to(&response.to_vec().unwrap(), peer).await;
                                    response.metadata.id = response.metadata.id.wrapping_sub(1);
                                    response.queries[0].set_name(Name::from_ascii("forged.test.").unwrap());
                                    let _ = udp.send_to(&response.to_vec().unwrap(), peer).await;
                                    let _ = udp.send_to(&wire, peer).await;
                                    return;
                                }
                                _ => {},
                            }
                            let _ = udp.send_to(&response.to_vec().unwrap(), peer).await;
                        });
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, peer)) = accepted else { break };
                        stream.set_nodelay(true).unwrap();
                        cc.fetch_add(1, Ordering::Relaxed);
                        tp.lock().unwrap().push(peer);
                        let a = a.clone();
                        let tc = tc.clone();
                        jobs.spawn(async move {
                            let (mut read, write) = stream.into_split();
                            let write = Arc::new(tokio::sync::Mutex::new(write));
                            let mut requests = JoinSet::new();
                            while let Ok(size) = read.read_u16().await {
                                let mut wire = vec![0; size as usize];
                                if read.read_exact(&mut wire).await.is_err() { break; }
                                tc.fetch_add(1, Ordering::Relaxed);
                                let a = a.clone();
                                let write = write.clone();
                                requests.spawn(async move {
                                    let Some(response) = a.answer(&wire).await else { return };
                                    if a.mode.load(Ordering::Relaxed) == 26 { return; }
                                    let mut write = write.lock().await;
                                    // Fragment the length prefix and body deliberately.
                                    let size = (response.len() as u16).to_be_bytes();
                                    let _ = write.write_all(&size[..1]).await;
                                    let _ = write.write_all(&size[1..]).await;
                                    let _ = write.write_all(&response[..5]).await;
                                    let _ = write.write_all(&response[5..]).await;
                                    if matches!(a.mode.load(Ordering::Relaxed), 8 | 27) {
                                        let _ = write.shutdown().await;
                                    }
                                });
                                while requests.try_join_next().is_some() {}
                            }
                        });
                    }
                }
                while jobs.try_join_next().is_some() {}
            }
        });
        Self {
            address,
            answers,
            udp_count,
            tcp_count,
            connections,
            udp_seen,
            tcp_peers,
            task,
        }
    }

    fn resolver(
        &self,
        transport: &str,
        options: &[(&str, &str)],
        policy: DialPolicy,
    ) -> Arc<DnsResolver> {
        let mut url = url::Url::parse("portal://key@localhost:2000").unwrap();
        url.query_pairs_mut()
            .append_pair("dns", &format!("{transport}://{}", self.address));
        url.query_pairs_mut().extend_pairs(options.iter().copied());
        let config = DnsConfig::from_url(&url).unwrap().unwrap();
        DnsResolver::new(config, policy).unwrap()
    }
}

#[tokio::test]
async fn tcp_udp_resolve_families_restore_ids_cache_and_report_transport() {
    for transport in ["udp", "tcp"] {
        for ip in ["127.0.0.1", "[::1]"] {
            let server = PlainServer::new(ip).await;
            let resolver = server.resolver(transport, &[], DialPolicy::default());
            for id in [0, 65535] {
                let response = ask(&resolver, "plain.test.", id).await;
                assert_eq!(response.metadata.id, id);
                assert_eq!(response.answers.len(), 1, "{transport} {ip}: {response:?}");
            }
            let addresses = resolver.lookup_ip("dual.test.", 443).await.unwrap();
            assert_eq!(addresses.len(), 2);
            let snapshot = resolver.snapshot();
            assert_eq!(snapshot.cache_hits, 1);
            assert_eq!(snapshot.upstreams[0].queries, 3);
            assert_eq!(
                snapshot.upstreams[0].endpoint,
                format!("{transport}://{}", server.address)
            );
            assert_eq!(
                crate::telemetry::display_dns_endpoint(&snapshot.upstreams[0].endpoint),
                snapshot.upstreams[0].endpoint
            );
            assert_eq!(
                server.tcp_count.load(Ordering::Relaxed),
                if transport == "tcp" { 3 } else { 0 }
            );
            assert_eq!(
                server.connections.load(Ordering::Relaxed),
                usize::from(transport == "tcp")
            );
        }
    }
}

#[tokio::test]
async fn plaintext_concurrency_uses_pipelined_tcp_and_independent_udp_ids_ports() {
    for transport in ["udp", "tcp"] {
        let server = PlainServer::new("127.0.0.1").await;
        server.answers.delay.store(30, Ordering::Relaxed);
        let resolver = server.resolver(transport, &[], DialPolicy::default());
        let mut tasks = JoinSet::new();
        let started = Instant::now();
        for id in 0..32 {
            let resolver = resolver.clone();
            tasks.spawn(async move {
                let response = ask(&resolver, &format!("parallel-{id}.test."), id).await;
                assert_eq!(response.metadata.id, id);
                assert_eq!(response.answers.len(), 1);
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert!(
            started.elapsed() < Duration::from_millis(700),
            "{transport}: {:?}",
            started.elapsed()
        );
        if transport == "udp" {
            let seen = server.udp_seen.lock().unwrap();
            let ports: std::collections::HashSet<_> = seen.iter().map(|(p, _)| p.port()).collect();
            let ids: std::collections::HashSet<_> = seen.iter().map(|(_, id)| id).collect();
            assert_eq!(seen.len(), 32);
            assert!(ports.len() > 1 && ids.len() > 1);
            assert_eq!(server.connections.load(Ordering::Relaxed), 0);
        } else {
            assert_eq!(server.connections.load(Ordering::Relaxed), 1);
        }
    }
}

#[tokio::test]
async fn udp_ignores_spoofed_source_id_and_question() {
    let server = PlainServer::new("127.0.0.1").await;
    server.answers.mode.store(25, Ordering::Relaxed);
    let resolver = server.resolver("udp", &[], DialPolicy::default());
    assert_eq!(ask(&resolver, "verified.test.", 789).await.answers.len(), 1);
    assert_eq!(server.udp_count.load(Ordering::Relaxed), 1);
    assert_eq!(server.tcp_count.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn udp_truncation_retries_tcp_same_peer_reuses_and_reconnects() {
    let server = PlainServer::new("127.0.0.1").await;
    server.answers.mode.store(24, Ordering::Relaxed);
    let resolver = server.resolver("udp", &[], DialPolicy::default());
    for id in 0..3 {
        let response = resolver.upstreams[0]
            .query(&request("truncated.test.", id))
            .await
            .unwrap();
        assert!(!response.metadata.truncation);
        assert_eq!(response.answers.len(), 1);
    }
    assert_eq!(server.udp_count.load(Ordering::Relaxed), 3);
    assert_eq!(server.tcp_count.load(Ordering::Relaxed), 3);
    assert_eq!(server.connections.load(Ordering::Relaxed), 1);
    // The existing fallback closes after this answer; the next TC answer
    // must reconnect that same fallback, without replacing the UDP session.
    server.answers.mode.store(27, Ordering::Relaxed);
    for id in 0..2 {
        assert_eq!(
            ask(&resolver, &format!("reconnect-{id}.test."), id)
                .await
                .answers
                .len(),
            1
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.connections.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn udp_tcp_retry_keeps_one_deadline_and_allows_later_queries() {
    let server = PlainServer::new("127.0.0.1").await;
    server.answers.mode.store(26, Ordering::Relaxed);
    server.answers.delay.store(45, Ordering::Relaxed);
    let resolver = server.resolver("udp", &[("dns-timeout", "100ms")], DialPolicy::default());
    let started = Instant::now();
    assert!(
        resolver.upstreams[0]
            .query(&request("deadline.test.", 1))
            .await
            .is_err()
    );
    assert!(
        started.elapsed() < Duration::from_millis(150),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(server.tcp_count.load(Ordering::Relaxed), 1);
    server.answers.mode.store(24, Ordering::Relaxed);
    server.answers.delay.store(0, Ordering::Relaxed);
    assert!(
        resolver.upstreams[0]
            .query(&request("after-timeout.test.", 2))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn plaintext_source_binding_applies_to_udp_and_tcp_retry() {
    let server = PlainServer::new("127.0.0.1").await;
    server.answers.mode.store(24, Ordering::Relaxed);
    let mut policy = std::collections::HashMap::new();
    policy.insert("dial".to_owned(), "127.0.0.2".to_owned());
    let resolver = server.resolver("udp", &[], DialPolicy::from_query(&policy).unwrap());
    assert_eq!(ask(&resolver, "bound.test.", 1).await.answers.len(), 1);
    assert_eq!(
        server.udp_seen.lock().unwrap()[0].0.ip().to_string(),
        "127.0.0.2"
    );
    assert_eq!(
        server.tcp_peers.lock().unwrap()[0].ip().to_string(),
        "127.0.0.2"
    );
}

#[tokio::test]
async fn udp_failure_falls_back_to_tls_and_business_success_recovers() {
    let server = PlainServer::new("127.0.0.1").await;
    let fallback = TestServer::new("tls").await;
    server.answers.mode.store(1, Ordering::Relaxed);
    let resolver = server.resolver(
        "udp",
        &[
            ("dns-fallback", &fallback.url),
            ("dns-fallback-delay", "20ms"),
            ("dns-timeout", "300ms"),
        ],
        DialPolicy::default(),
    );
    // Use the local trust root for the encrypted fallback.
    let resolver = DnsResolver::with_tls(
        resolver.config.clone(),
        DialPolicy::default(),
        fallback.tls.clone(),
    )
    .unwrap();
    let started = Instant::now();
    assert_eq!(ask(&resolver, "fallback.test.", 1).await.answers.len(), 1);
    assert!(started.elapsed() < Duration::from_millis(250));
    assert_eq!(resolver.snapshot().last_upstream, Some(1));
    server.answers.mode.store(0, Ordering::Relaxed);
    assert_eq!(ask(&resolver, "recovered.test.", 2).await.answers.len(), 1);
    assert_eq!(resolver.snapshot().last_upstream, Some(0));
}

#[tokio::test]
async fn traditional_tcp_reconnects_after_the_server_closes_a_reused_connection() {
    let server = PlainServer::new("127.0.0.1").await;
    server.answers.mode.store(8, Ordering::Relaxed);
    let resolver = server.resolver("tcp", &[], DialPolicy::default());
    for id in 0..2 {
        assert_eq!(
            ask(&resolver, &format!("tcp-reconnect-{id}.test."), id)
                .await
                .answers
                .len(),
            1
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.connections.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn udp_truncation_tcp_failure_uses_the_configured_plaintext_fallback() {
    let primary = PlainServer::new("127.0.0.1").await;
    let fallback = PlainServer::new("127.0.0.1").await;
    primary.answers.mode.store(26, Ordering::Relaxed);
    let resolver = primary.resolver(
        "udp",
        &[
            ("dns-fallback", &format!("tcp://{}", fallback.address)),
            ("dns-fallback-delay", "20ms"),
            ("dns-timeout", "150ms"),
        ],
        DialPolicy::default(),
    );
    assert_eq!(
        ask(&resolver, "tcp-failure-fallback.test.", 1)
            .await
            .answers
            .len(),
        1
    );
    let snapshot = resolver.snapshot();
    assert_eq!(snapshot.last_upstream, Some(1));
    assert_eq!(snapshot.upstreams[0].queries, 1);
    // A slow primary also triggers a health probe, which uses the same transport.
    assert!(primary.udp_count.load(Ordering::Relaxed) >= 1);
    assert!(primary.tcp_count.load(Ordering::Relaxed) >= 1);
    assert_eq!(fallback.tcp_count.load(Ordering::Relaxed), 1);
}
