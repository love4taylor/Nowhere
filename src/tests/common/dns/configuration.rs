// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! DNS upstream URL validation and resource-budget configuration.

use super::*;

#[test]
fn validates_upstreams_bounds_and_explicit_enablement() {
    let parse = |pairs: &[(&str, &str)]| {
        let mut url = url::Url::parse("portal://key@localhost:2000").unwrap();
        url.query_pairs_mut().extend_pairs(pairs.iter().copied());
        DnsConfig::from_url(&url)
    };
    assert!(parse(&[]).unwrap().is_none());
    let config = parse(&[("dns", "https://1.1.1.1/dns-query,tls://[2606:4700:4700::1111],quic://dns.adguard-dns.com?bootstrap=94.140.14.14")]).unwrap().unwrap();
    assert!(config.hijack);
    assert_eq!(config.primary.len(), 3);
    assert_eq!(config.fallback_delay, Duration::from_millis(50));
    assert_eq!(config.probe_interval, Duration::from_millis(250));
    assert!(config.probe_target.name().is_root());
    assert_eq!(config.probe_target.query_type(), RecordType::NS);
    assert_eq!(config.http.pool_size, 2);
    assert_eq!(config.http.keepalive, Duration::from_secs(30));
    assert_eq!(config.http.ping_timeout, Duration::from_secs(5));
    assert!(config.http.prewarm);
    let http3 = parse(&[
        ("dns", "h3://[::1]:4443/custom?bootstrap=::1"),
        ("dns-http-prewarm", "0"),
        ("dns-http-pool-size", "4"),
    ])
    .unwrap()
    .unwrap();
    assert_eq!(http3.primary[0].transport, config::Transport::Http3);
    assert_eq!(http3.primary[0].path, "/custom");
    assert_eq!(http3.primary[0].port, 4443);
    assert!(!http3.http.prewarm);
    let configured = parse(&[
        ("dns", "tls://1.1.1.1"),
        ("dns-probe-target", "example.com"),
    ])
    .unwrap()
    .unwrap();
    assert_eq!(configured.probe_target.name().to_ascii(), "example.com.");
    assert_eq!(configured.probe_target.query_type(), RecordType::A);
    for bad in [
        "",
        "udp://1.1.1.1/path",
        "tcp://1.1.1.1/path",
        "udp://1.1.1.1:0",
        "http://dns.test",
        "tls://dns.test/path",
        "https://user:password@dns.test/dns-query",
        "quic://dns.test#no",
        "tls://dns.test:0",
        "tls://dns.test?bootstrap=hostname.test",
        "tls://dns.test?insecure=1",
        "tls://dns.test?bootstrap=1.1.1.1&bootstrap=8.8.8.8",
    ] {
        assert!(parse(&[("dns", bad)]).is_err(), "accepted {bad}");
    }
    for pair in [
        ("dns-hijack", "true"),
        ("dns-cache-size", "0"),
        ("dns-cache-bytes", "67108865"),
        ("dns-stale", "2days"),
        ("dns-probe-interval", "1ms"),
        ("dns-probe-target", ""),
        ("dns-probe-target", "bad..name"),
        ("dns-timeout", "999days"),
        ("dns-fallback-delay", "2s"),
        ("dns-fallback", ""),
        ("dns-http-pool-size", "0"),
        ("dns-http-pool-size", "5"),
        ("dns-http-keepalive", "1ms"),
        ("dns-http-keepalive", "601s"),
        ("dns-http-ping-timeout", "1ms"),
        ("dns-http-ping-timeout", "61s"),
        ("dns-http-prewarm", "true"),
    ] {
        assert!(
            parse(&[("dns", "tls://1.1.1.1"), pair]).is_err(),
            "accepted {pair:?}"
        );
        assert!(
            parse(&[pair]).is_err(),
            "option without dns accepted: {pair:?}"
        );
    }
    let too_many = ["tls://1.1.1.1"; 9].join(",");
    assert!(parse(&[("dns", &too_many)]).is_err());
    let config = parse(&[
        ("dns", "tls://1.1.1.1"),
        ("dns-hijack", "0"),
        ("dns-stale", "0s"),
    ])
    .unwrap()
    .unwrap();
    assert!(!config.hijack);
    assert!(config.stale.is_zero());
}

#[tokio::test]
async fn port_53_matches_domain_ipv4_ipv6_only_when_enabled() {
    let server = TestServer::new("tls").await;
    for enabled in [true, false] {
        let resolver = server.resolver(&[("dns-hijack", if enabled { "1" } else { "0" })]);
        for target in [
            "192.0.2.1:53",
            "[2001:db8::1]:53",
            "unresolvable.invalid:53",
        ] {
            assert_eq!(resolver.hijacks(&target.parse().unwrap()), enabled);
        }
        assert!(!resolver.hijacks(&"192.0.2.1:5353".parse().unwrap()));
        assert!(!resolver.hijacks(&"example.test:443".parse().unwrap()));
    }
}

#[test]
fn plaintext_urls_defaults_bootstrap_and_effective_modes() {
    let parse = |upstreams: &str, fallback: Option<&str>| {
        let mut url = url::Url::parse("portal://key@localhost:2000").unwrap();
        url.query_pairs_mut().append_pair("dns", upstreams);
        if let Some(fallback) = fallback {
            url.query_pairs_mut().append_pair("dns-fallback", fallback);
        }
        DnsConfig::from_url(&url).unwrap().unwrap()
    };
    let config = parse(
        "udp://1.1.1.1,tcp://[::1]:5353,udp://dns.example?bootstrap=127.0.0.1",
        None,
    );
    assert_eq!(config.primary[0].transport, config::Transport::Udp);
    assert_eq!(config.primary[0].port, 53);
    assert_eq!(config.primary[1].transport, config::Transport::Tcp);
    assert_eq!(config.primary[1].host, "::1");
    assert_eq!(config.primary[1].port, 5353);
    assert_eq!(
        config.primary[2].bootstrap,
        Some("127.0.0.1".parse().unwrap())
    );
    assert_eq!(config.effective(), "&dns=plaintext&dns-hijack=1");
    assert_eq!(
        parse("tcp://1.1.1.1", Some("https://1.1.1.1")).effective(),
        "&dns=mixed&dns-hijack=1"
    );
    assert_eq!(
        parse("https://1.1.1.1", None).effective(),
        "&dns=encrypted&dns-hijack=1"
    );
    assert!(upstream::client_config(false).is_ok());
}
