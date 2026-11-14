// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! SOCKS outbound tcp regression tests.

use super::*;

#[tokio::test]
async fn concurrent_proxy_connections_bypass_stalled_handshakes_and_close_losers() {
    let listener4 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener4.local_addr().unwrap().port();
    let listener6 = match TcpListener::bind(SocketAddr::new("::1".parse().unwrap(), port)).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("SKIP concurrent dual-stack proxy: IPv6 loopback unavailable: {error}");
            return;
        }
    };
    let config = parse(&format!(
        "portal://secret@127.0.0.1:2000?out=localhost:{port}"
    ))
    .unwrap();
    let policy = DialPolicy::from_query(&std::collections::HashMap::from([
        ("tcp-concurrent".to_owned(), "1".to_owned()),
        ("prefer".to_owned(), "ipv6".to_owned()),
        ("dial4".to_owned(), "127.0.0.1".to_owned()),
        ("dial6".to_owned(), "::1".to_owned()),
    ]))
    .unwrap();
    let dialer = OutboundDialer::new(policy, config);
    let (started, waiting) = tokio::sync::oneshot::channel();
    let stalled = async {
        let (mut stream, _) = listener6.accept().await.unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        started.send(()).unwrap();
        assert_eq!(stream.read(&mut greeting).await.unwrap(), 0);
    };
    let working = async {
        let (mut stream, peer) = listener4.accept().await.unwrap();
        assert!(peer.is_ipv4());
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        waiting.await.unwrap();
        stream.write_all(&[SOCKS_VERSION, AUTH_NONE]).await.unwrap();
        let request = read_test_command(&mut stream).await;
        assert_eq!(request, (COMMAND_CONNECT, "target.test".to_owned(), 443));
        write_test_reply(&mut stream, SocketAddr::from(([127, 0, 0, 1], 50000))).await;
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    };
    let client = async {
        let target = Target::domain("target.test", 443).unwrap();
        let mut stream = dialer
            .dial_tcp_target(&target, Duration::from_secs(2))
            .await
            .unwrap();
        stream.write_all(b"race").await.unwrap();
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"race");
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(stalled, working, client);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tcp_connect_uses_only_no_auth_and_preserves_domain() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut methods = [0u8; 3];
        stream.read_exact(&mut methods).await.unwrap();
        assert_eq!(methods, [SOCKS_VERSION, 1, AUTH_NONE]);
        stream.write_all(&[SOCKS_VERSION, AUTH_NONE]).await.unwrap();
        let request = read_test_command(&mut stream).await;
        assert_eq!(request, (COMMAND_CONNECT, "target.test".to_string(), 443));
        write_test_reply(&mut stream, SocketAddr::from(([127, 0, 0, 1], 50000))).await;
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    });

    let config = parse(&format!("portal://secret@127.0.0.1:2000?out={endpoint}")).unwrap();
    let dialer = OutboundDialer::new("auto".into(), config);
    let target = Target::domain("target.test", 443).unwrap();
    let mut stream = dialer
        .dial_tcp_target(&target, Duration::from_secs(2))
        .await
        .unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"ping");
    drop(stream);
    server.await.unwrap();
}

#[tokio::test]
async fn authenticated_connect_cannot_downgrade_to_no_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut methods = [0u8; 3];
        stream.read_exact(&mut methods).await.unwrap();
        assert_eq!(methods, [SOCKS_VERSION, 1, AUTH_PASSWORD]);
        stream.write_all(&[SOCKS_VERSION, AUTH_NONE]).await.unwrap();
    });

    let config = parse(&format!(
        "portal://secret@127.0.0.1:2000?out=user:pass@{endpoint}"
    ))
    .unwrap();
    let dialer = OutboundDialer::new("auto".into(), config);
    let target = Target::domain("target.test", 443).unwrap();
    assert!(
        dialer
            .dial_tcp_target(&target, Duration::from_secs(2))
            .await
            .is_err()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn proxy_failure_never_falls_back_to_direct_target() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        let mut methods = [0u8; 3];
        stream.read_exact(&mut methods).await.unwrap();
        stream.write_all(&[SOCKS_VERSION, AUTH_NONE]).await.unwrap();
        let _ = read_test_command(&mut stream).await;
        stream
            .write_all(&[SOCKS_VERSION, 5, 0, ADDRESS_IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    });

    let config = parse(&format!("portal://secret@127.0.0.1:2000?out={proxy_addr}")).unwrap();
    let dialer = OutboundDialer::new("auto".into(), config);
    let protocol_target = Target::ip(target_addr).unwrap();
    assert!(
        dialer
            .dial_tcp_target(&protocol_target, Duration::from_secs(2))
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
    server.await.unwrap();
}
