// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Encrypted upstream URL validation and resource-budget configuration.

use super::*;

#[test]
fn validates_encrypted_upstreams_bounds_and_explicit_enablement() {
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
        "udp://1.1.1.1",
        "tcp://1.1.1.1",
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
