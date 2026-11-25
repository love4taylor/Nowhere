// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Network helper tests.

use super::*;

struct AttemptGuard(std::rc::Rc<std::cell::Cell<usize>>);

impl Drop for AttemptGuard {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

fn tcp_dial_policy(preference: Option<&str>, concurrent: bool) -> DialPolicy {
    let mut query = std::collections::HashMap::from([(
        "tcp-concurrent".to_owned(),
        u8::from(concurrent).to_string(),
    )]);
    if let Some(preference) = preference {
        query.insert("prefer".to_owned(), preference.to_owned());
    }
    DialPolicy::from_query(&query).unwrap()
}

#[tokio::test(start_paused = true)]
async fn concurrent_tcp_dials_all_addresses_in_the_first_group_and_picks_the_fastest() {
    let [v6, v4a, v4b, v4c] = ["[::1]:10", "127.0.0.1:100", "127.0.0.1:25", "127.0.0.1:50"]
        .map(|address| address.parse::<SocketAddr>().unwrap());
    for (preference, expected, count) in [(Some("ipv4"), v4b, 3), (None, v6, 1)] {
        let policy = tcp_dial_policy(preference, true);
        let start = Instant::now();
        let started = std::cell::Cell::new(0);
        let dropped = std::rc::Rc::new(std::cell::Cell::new(0));
        let result = dial_tcp_candidates(
            &policy,
            vec![v6, v4a, v4b, v4c],
            start + Duration::from_secs(15),
            |address| {
                let started = &started;
                let dropped = dropped.clone();
                async move {
                    let _guard = AttemptGuard(dropped);
                    assert_eq!(start.elapsed(), Duration::ZERO);
                    started.set(started.get() + 1);
                    tokio::time::sleep(Duration::from_millis(address.port().into())).await;
                    Ok(address)
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(result, expected);
        assert_eq!(started.get(), count);
        assert_eq!(dropped.get(), count);
    }
}

#[tokio::test(start_paused = true)]
async fn stalled_preferred_tcp_group_starts_the_other_family_and_is_cancelled_on_success() {
    let addresses = ["127.0.0.1:1", "127.0.0.1:2", "[::1]:1", "[::1]:2"]
        .map(|address| address.parse::<SocketAddr>().unwrap());
    for (preference, primary_ipv4, concurrent) in [
        (None, true, false),
        (None, true, true),
        (Some("ipv6"), false, false),
        (Some("ipv6"), false, true),
    ] {
        let policy = tcp_dial_policy(preference, concurrent);
        let dropped = std::rc::Rc::new(std::cell::Cell::new(0));
        let start = Instant::now();
        let result = dial_tcp_candidates(
            &policy,
            addresses.to_vec(),
            start + Duration::from_secs(15),
            |address| {
                let dropped = dropped.clone();
                async move {
                    let _guard = AttemptGuard(dropped);
                    if address.is_ipv4() == primary_ipv4 {
                        assert_eq!(start.elapsed(), Duration::ZERO);
                        return std::future::pending().await;
                    }
                    assert_eq!(start.elapsed(), TCP_FAMILY_FALLBACK_DELAY);
                    let duration = Duration::from_millis(address.port().into());
                    tokio::time::sleep(duration).await;
                    Ok(address)
                }
            },
        )
        .await
        .unwrap();
        assert_ne!(result.is_ipv4(), primary_ipv4);
        assert_eq!(result.port(), 1);
        assert_eq!(dropped.get(), if concurrent { 4 } else { 2 });
    }
}

#[tokio::test(start_paused = true)]
async fn failing_preferred_tcp_group_starts_the_other_family_immediately() {
    let policy = tcp_dial_policy(Some("ipv4"), true);
    let addresses = ["127.0.0.1:1", "[::1]:2", "127.0.0.1:3"]
        .map(|address| address.parse::<SocketAddr>().unwrap());
    let started = std::cell::Cell::new(0);
    let start = Instant::now();
    let result = dial_tcp_candidates(
        &policy,
        addresses.to_vec(),
        start + Duration::from_secs(15),
        |address| {
            started.set(started.get() + 1);
            std::future::ready(if address.is_ipv4() {
                Err(anyhow!("refused"))
            } else {
                Ok(address)
            })
        },
    )
    .await
    .unwrap();
    assert_eq!(result, addresses[1]);
    assert_eq!(start.elapsed(), Duration::ZERO);
    assert_eq!(started.get(), 3);
}

#[tokio::test(start_paused = true)]
async fn serial_tcp_reserves_deadline_for_the_next_address() {
    let policy = tcp_dial_policy(Some("ipv4"), false);
    let addresses = ["127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3"]
        .map(|address| address.parse::<SocketAddr>().unwrap());
    for (timeout, expected) in [
        (Duration::from_millis(650), Duration::from_millis(325)),
        (Duration::from_secs(15), TCP_ATTEMPT_BUDGET),
    ] {
        let dropped = std::rc::Rc::new(std::cell::Cell::new(0));
        let start = Instant::now();
        let result = dial_tcp_candidates(&policy, addresses.to_vec(), start + timeout, |address| {
            let dropped = dropped.clone();
            async move {
                let _guard = AttemptGuard(dropped.clone());
                if address == addresses[0] {
                    return std::future::pending().await;
                }
                assert_eq!(address, addresses[1]);
                assert_eq!(start.elapsed(), expected);
                assert_eq!(dropped.get(), 1);
                Ok(address)
            }
        })
        .await
        .unwrap();
        assert_eq!(result, addresses[1]);
        assert_eq!(dropped.get(), 2);
    }
}

#[tokio::test(start_paused = true)]
async fn last_active_tcp_attempts_can_use_the_remaining_dial_deadline() {
    let policy = tcp_dial_policy(None, true);
    let addresses = ["127.0.0.1:1", "[::1]:2"].map(|address| address.parse().unwrap());
    let start = Instant::now();
    let deadline = start + Duration::from_secs(4);
    let result = dial_tcp_candidates(
        &policy,
        addresses.to_vec(),
        deadline,
        |address| async move {
            if address == addresses[1] {
                return std::future::pending().await;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            Ok(address)
        },
    )
    .await
    .unwrap();
    assert_eq!(result, addresses[0]);

    let dropped = std::rc::Rc::new(std::cell::Cell::new(0));
    let dial = dial_tcp_candidates(&policy, addresses.to_vec(), deadline, |_| {
        let guard = AttemptGuard(dropped.clone());
        async move {
            let _guard = guard;
            std::future::pending::<Result<()>>().await
        }
    });
    assert!(tokio::time::timeout_at(deadline, dial).await.is_err());
    assert_eq!(start.elapsed(), Duration::from_secs(4));
    assert_eq!(dropped.get(), 2);
}

#[tokio::test]
async fn tcp_dial_reports_empty_and_all_failed_candidates() {
    let policy = tcp_dial_policy(Some("ipv4"), true);
    let addresses = ["127.0.0.1:1", "[::1]:2"].map(|address| address.parse().unwrap());
    for candidates in [vec![], addresses.to_vec()] {
        let result = dial_tcp_candidates(
            &policy,
            candidates,
            Instant::now() + Duration::from_secs(15),
            |address| std::future::ready(Err::<(), _>(anyhow!("refused {address}"))),
        )
        .await;
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn concurrent_tcp_uses_family_specific_sources_and_skips_bind_failures() {
    let policy = DialPolicy::from_query(&std::collections::HashMap::from([
        ("tcp-concurrent".to_owned(), "1".to_owned()),
        ("prefer".to_owned(), "ipv6".to_owned()),
        ("dial4".to_owned(), "127.0.0.1".to_owned()),
        ("dial6".to_owned(), "2001:db8::dead".to_owned()),
    ]))
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stream = tokio::time::timeout(
        Duration::from_secs(2),
        connect_tcp_candidates(
            &policy,
            vec![
                SocketAddr::new("::1".parse().unwrap(), address.port()),
                address,
            ],
            Instant::now() + Duration::from_secs(2),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(stream.peer_addr().unwrap(), address);
    assert_eq!(stream.local_addr().unwrap().ip(), address.ip());
    drop(stream);
    let stream = dial_tcp_with_policy(
        &policy,
        &format!("localhost:{}", address.port()),
        Duration::from_secs(2),
        AddressFamily::Any,
    )
    .await
    .unwrap();
    assert_eq!(stream.peer_addr().unwrap(), address);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket = dial_udp_with_policy(
        &policy,
        &format!("localhost:{}", udp.local_addr().unwrap().port()),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(socket.peer_addr().unwrap(), udp.local_addr().unwrap());
    assert_eq!(socket.local_addr().unwrap().ip(), address.ip());
}

#[test]
fn bind_udp_addrs_handles_wildcard_and_ip_literals() {
    assert_eq!(
        bind_udp_addrs("", 8080).unwrap(),
        vec![
            SocketAddr::from(([0, 0, 0, 0], 8080)),
            SocketAddr::from(([0u16; 8], 8080)),
        ]
    );
    assert_eq!(
        bind_udp_addrs("0.0.0.0", 8080).unwrap(),
        vec![SocketAddr::from(([0, 0, 0, 0], 8080))]
    );
    assert_eq!(
        bind_udp_addrs("::", 8080).unwrap(),
        vec![SocketAddr::from(([0u16; 8], 8080))]
    );
    assert_eq!(
        bind_udp_addrs("[::]", 8080).unwrap(),
        vec![SocketAddr::from(([0u16; 8], 8080))]
    );
    assert_eq!(
        bind_udp_addrs("127.0.0.1", 8080).unwrap(),
        vec![SocketAddr::from(([127, 0, 0, 1], 8080))]
    );
    assert_eq!(
        bind_udp_addrs("::1", 8080).unwrap(),
        vec![SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8080))]
    );
    assert_eq!(
        bind_udp_addrs("[::1]", 8080).unwrap(),
        vec![SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8080))]
    );
}

#[test]
fn preferred_family_orders_candidates_without_reordering_each_family() {
    let addresses = [
        "192.0.2.1:80".parse().unwrap(),
        "[2001:db8::1]:80".parse().unwrap(),
        "192.0.2.2:80".parse().unwrap(),
        "[2001:db8::2]:80".parse().unwrap(),
    ];
    for (value, indices) in [
        (None, [0, 1, 2, 3]),
        (Some("ipv4"), [0, 2, 1, 3]),
        (Some("ipv6"), [1, 3, 0, 2]),
    ] {
        let policy = tcp_dial_policy(value, false);
        let ordered =
            filter_addrs_for_family(addresses.iter().copied(), &policy, AddressFamily::Any);
        assert_eq!(ordered, indices.map(|index| addresses[index]));
        let filtered =
            filter_addrs_for_family(addresses.iter().copied(), &policy, AddressFamily::V4);
        assert_eq!(filtered, [addresses[0], addresses[2]]);
    }
}

#[test]
fn filter_addrs_matches_local_ip_family() {
    let addrs = [
        SocketAddr::from(([127, 0, 0, 1], 443)),
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 443)),
    ];

    assert_eq!(
        filter_addrs_for_family(
            addrs.into_iter(),
            &DialPolicy::default(),
            AddressFamily::Any
        ),
        addrs
    );
    assert_eq!(
        filter_addrs_for_family(addrs.into_iter(), &"127.0.0.1".into(), AddressFamily::Any),
        [addrs[0]]
    );
    assert_eq!(
        filter_addrs_for_family(addrs.into_iter(), &"::1".into(), AddressFamily::Any),
        [addrs[1]]
    );
}

#[test]
fn carrier_bind_resolution_expands_wildcards_and_filters_dns() {
    let v4 = CarrierEndpoint {
        port: 8080,
        family: AddressFamily::V4,
    };
    let v6 = CarrierEndpoint {
        port: 9090,
        family: AddressFamily::V6,
    };
    assert_eq!(
        resolve_bind_addrs("*", v4).unwrap(),
        [SocketAddr::from(([0, 0, 0, 0], 8080))]
    );
    assert_eq!(
        resolve_bind_addrs("*", v6).unwrap(),
        [SocketAddr::from(([0u16; 8], 9090))]
    );
    assert!(resolve_bind_addrs("127.0.0.1", v6).is_err());

    let localhost = resolve_bind_addrs("localhost", v4).unwrap();
    assert!(!localhost.is_empty());
    assert!(localhost.iter().all(SocketAddr::is_ipv4));
    assert!(localhost.windows(2).all(|pair| pair[0] != pair[1]));
}

#[test]
fn carrier_and_local_bind_family_filters_are_both_enforced() {
    let addrs = [
        SocketAddr::from(([127, 0, 0, 1], 443)),
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 443)),
    ];
    assert_eq!(
        filter_addrs_for_family(addrs.into_iter(), &DialPolicy::default(), AddressFamily::V6),
        [addrs[1]]
    );
    assert!(
        filter_addrs_for_family(addrs.into_iter(), &"127.0.0.1".into(), AddressFamily::V6,)
            .is_empty()
    );
}

#[tokio::test]
async fn dual_stack_binds_tcp_and_udp_sources_for_domain_and_ip_targets() {
    let policy = DialPolicy::DualStack {
        v4: Some("127.0.0.1".parse().unwrap()),
        v6: Some("::1".parse().unwrap()),
        preference: crate::common::AddressPreference::Default,
        tcp_concurrent: false,
    };
    let listener4 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener6 = match tokio::net::TcpListener::bind("[::1]:0").await {
        Ok(listener) => Some(listener),
        Err(error) => {
            eprintln!("SKIP IPv6 source binding: IPv6 loopback unavailable: {error}");
            None
        }
    };
    for listener in std::iter::once(&listener4).chain(listener6.as_ref()) {
        let target = listener.local_addr().unwrap();
        for host in [target.to_string(), format!("localhost:{}", target.port())] {
            let stream = dial_tcp_with_policy(
                &policy,
                &host,
                Duration::from_secs(2),
                if target.is_ipv4() {
                    AddressFamily::V4
                } else {
                    AddressFamily::V6
                },
            )
            .await
            .unwrap();
            let (_, peer) = listener.accept().await.unwrap();
            assert_eq!(stream.local_addr().unwrap().ip(), target.ip());
            assert_eq!(peer.ip(), target.ip());
        }
        let udp = UdpSocket::bind(SocketAddr::new(target.ip(), 0))
            .await
            .unwrap();
        let target = udp.local_addr().unwrap();
        let socket = dial_udp_with_policy(&policy, &target.to_string(), Duration::from_secs(2))
            .await
            .unwrap();
        socket.send(b"source").await.unwrap();
        let mut data = [0; 16];
        let (size, peer) = udp.recv_from(&mut data).await.unwrap();
        assert_eq!(&data[..size], b"source");
        assert_eq!(peer.ip(), target.ip());
    }
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket = dial_udp_with_policy(
        &"127.0.0.1".into(),
        &format!("localhost:{}", udp.local_addr().unwrap().port()),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert!(socket.peer_addr().unwrap().is_ipv4());
}

#[tokio::test]
async fn failed_explicit_source_tries_the_other_family_without_auto_fallback() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_target = udp.local_addr().unwrap();
    let policy = DialPolicy::DualStack {
        v4: Some("127.0.0.1".parse().unwrap()),
        v6: Some("2001:db8::dead".parse().unwrap()),
        preference: crate::common::AddressPreference::Default,
        tcp_concurrent: false,
    };
    let failed = SocketAddr::new("::1".parse().unwrap(), target.port());
    let stream = connect_tcp_candidates(
        &policy,
        vec![failed, target],
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(stream.peer_addr().unwrap(), target);
    let socket = connect_udp_candidates(&policy, vec![failed, udp_target])
        .await
        .unwrap();
    assert_eq!(socket.peer_addr().unwrap(), udp_target);
    let policy = DialPolicy::DualStack {
        v4: Some("192.0.2.254".parse().unwrap()),
        v6: None,
        preference: crate::common::AddressPreference::Default,
        tcp_concurrent: false,
    };
    assert!(
        connect_tcp_candidates(
            &policy,
            vec![target],
            Instant::now() + Duration::from_secs(2)
        )
        .await
        .is_err()
    );
    assert!(
        connect_udp_candidates(&policy, vec![udp_target])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn dual_stack_udp_domain_binds_source_for_the_resolved_family() {
    let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = v4.local_addr().unwrap().port();
    let v6 = match UdpSocket::bind(SocketAddr::new("::1".parse().unwrap(), port)).await {
        Ok(socket) => Some(socket),
        Err(error) => {
            eprintln!("SKIP IPv6 UDP domain source: IPv6 loopback unavailable: {error}");
            None
        }
    };
    let policy = DialPolicy::DualStack {
        v4: Some("127.0.0.1".parse().unwrap()),
        v6: v6.as_ref().map(|_| "::1".parse().unwrap()),
        preference: crate::common::AddressPreference::Default,
        tcp_concurrent: false,
    };
    let socket = dial_udp_with_policy(
        &policy,
        &format!("localhost:{port}"),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let peer = socket.peer_addr().unwrap();
    if peer.is_ipv6() && v6.is_none() {
        eprintln!("SKIP IPv6 UDP domain exchange: resolver selected unavailable IPv6 loopback");
        return;
    }
    socket.send(b"domain").await.unwrap();
    let receiver = if peer.is_ipv4() {
        &v4
    } else {
        v6.as_ref().unwrap()
    };
    let mut bytes = [0; 16];
    let (_, source) = tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source.ip(), peer.ip());
}
