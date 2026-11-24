// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Portal effective configuration, outlet selection, defaults, and credential redaction tests.

use super::*;

#[test]
fn dns_settings_are_validated_at_startup_and_shared_with_direct_outbound() {
    for out in ["direct", "egress", "127.0.0.1:1080"] {
        for (upstreams, mode) in [
            ("https://1.1.1.1/dns-query", "encrypted"),
            ("udp://1.1.1.1,tcp://1.1.1.1", "plaintext"),
            ("https://1.1.1.1/dns-query,udp://1.1.1.1", "mixed"),
        ] {
            let portal = Portal::new(Url::parse(&format!(
                "portal://0123456789abcdef0123456789abcdef@127.0.0.1:2000?out={out}&dns={upstreams}"
            )).unwrap(), Logger).unwrap();
            assert!(portal.inner.forward.dns.is_some());
            assert!(
                portal
                    .inner
                    .effective
                    .contains(&format!("dns={mode}&dns-hijack=1"))
            );
            assert!(!portal.inner.effective.contains("1.1.1.1"));
        }
    }
    for query in [
        "dns=udp://1.1.1.1/path",
        "dns-hijack=1",
        "dns=tls://1.1.1.1&dns-cache-size=0",
    ] {
        assert!(
            Portal::new(
                Url::parse(&format!(
                    "portal://0123456789abcdef0123456789abcdef@127.0.0.1:2000?{query}"
                ))
                .unwrap(),
                Logger
            )
            .is_err()
        );
    }
}

#[test]
fn startup_url_preserves_effective_values_and_omits_credentials() {
    for (query, expected) in [
        (
            "?net=%ZZ&socks=%FF&unknown=%ZZ",
            "portal://127.0.0.1:2000?out=direct&tls=1&dial=auto&morph=1&grade=full&cipher=chacha&rate=0&etar=0",
        ),
        (
            "?etar=20&rate=10&dial4=127.0.0.1&morph=1&out=a%3Ab:p%40ss@localhost:1080",
            "portal://127.0.0.1:2000?out=localhost:1080&tls=1&dial4=127.0.0.1&dial6=auto&morph=1&grade=full&cipher=chacha&rate=10&etar=20",
        ),
        (
            "?out=egress&unknown=secret",
            "portal://127.0.0.1:2000?out=egress&tls=1&morph=1&grade=full&cipher=chacha&rate=0&etar=0",
        ),
        (
            "?morph=0&grade=core&cipher=aes",
            "portal://127.0.0.1:2000?out=direct&tls=1&dial=auto&morph=0&rate=0&etar=0",
        ),
        (
            "?prefer=ipv6",
            "portal://127.0.0.1:2000?out=direct&tls=1&dial=auto&prefer=ipv6&morph=1&grade=full&cipher=chacha&rate=0&etar=0",
        ),
        (
            "?prefer=ipv4",
            "portal://127.0.0.1:2000?out=direct&tls=1&dial=auto&prefer=ipv4&morph=1&grade=full&cipher=chacha&rate=0&etar=0",
        ),
        (
            "?prefer=default",
            "portal://127.0.0.1:2000?out=direct&tls=1&dial=auto&morph=1&grade=full&cipher=chacha&rate=0&etar=0",
        ),
        (
            "?prefer=ipv4&tcp-concurrent=1",
            "portal://127.0.0.1:2000?out=direct&tls=1&dial=auto&prefer=ipv4&tcp-concurrent=1&morph=1&grade=full&cipher=chacha&rate=0&etar=0",
        ),
        (
            "?prefer=ipv4&tcp-concurrent=1&grade=core&cipher=aes&dns=udp://1.1.1.1&dns-hijack=1",
            "portal://127.0.0.1:2000?out=direct&tls=1&dial=auto&prefer=ipv4&tcp-concurrent=1&morph=1&grade=core&cipher=aes&rate=0&etar=0&dns=plaintext&dns-hijack=1",
        ),
        (
            "?tcp-concurrent=0",
            "portal://127.0.0.1:2000?out=direct&tls=1&dial=auto&morph=1&grade=full&cipher=chacha&rate=0&etar=0",
        ),
        (
            "?out=localhost:1080&tcp-concurrent=1",
            "portal://127.0.0.1:2000?out=localhost:1080&tls=1&dial=auto&tcp-concurrent=1&morph=1&grade=full&cipher=chacha&rate=0&etar=0",
        ),
        (
            "?grade=core&cipher=aes",
            "portal://127.0.0.1:2000?out=direct&tls=1&dial=auto&morph=1&grade=core&cipher=aes&rate=0&etar=0",
        ),
    ] {
        let portal = Portal::new(
            Url::parse(&format!(
                "portal://0123456789abcdef0123456789abcdef@127.0.0.1:2000{query}"
            ))
            .unwrap(),
            Logger,
        )
        .unwrap();
        assert_eq!(portal.inner.effective, expected);
    }
}

#[test]
fn egress_output_rejects_portal_address_preference() {
    for value in ["default", "ipv4", "ipv6"] {
        let url = Url::parse(&format!(
            "portal://0123456789abcdef0123456789abcdef@127.0.0.1:2000?out=egress&prefer={value}"
        ))
        .unwrap();
        assert!(Portal::new(url, Logger).is_err());
    }
}

#[test]
fn portal_rejects_invalid_or_egress_tcp_concurrent_settings() {
    for query in [
        "tcp-concurrent=",
        "tcp-concurrent=true",
        "tcp-concurrent=2",
        "tcp-concurrent=%GG",
        "out=egress&tcp-concurrent=0",
        "out=egress&tcp-concurrent=1",
    ] {
        let url = Url::parse(&format!(
            "portal://0123456789abcdef0123456789abcdef@127.0.0.1:2000?{query}"
        ))
        .unwrap();
        assert!(Portal::new(url, Logger).is_err(), "accepted {query}");
    }
}

#[test]
fn egress_output_accepts_tcp_only_udp_only_and_dual_listeners() {
    for endpoint in [
        "127.0.0.1/tcp:2000",
        "127.0.0.1/udp:2000",
        "127.0.0.1/tcp:2000/udp:2001",
    ] {
        let url = Url::parse(&format!(
            "portal://0123456789abcdef0123456789abcdef@{endpoint}?out=egress"
        ))
        .unwrap();
        let portal = Portal::new(url, Logger).unwrap();
        assert!(portal.inner.egress_registry.is_some());
        assert_eq!(
            !portal.inner.tcp_bind_addrs.is_empty(),
            endpoint.contains("/tcp:")
        );
        assert_eq!(
            !portal.inner.udp_bind_addrs.is_empty(),
            endpoint.contains("/udp:")
        );
    }
}

#[test]
fn handshake_timeout_is_saved_per_portal_key_across_carriers_and_morph() {
    let mut instances = Vec::new();
    for (key, milliseconds) in [
        ("0123456789abcdef0123456789abcdef", 9100),
        ("fedcba9876543210fedcba9876543210", 24700),
    ] {
        for carrier in ["tcp", "udp"] {
            for morph in [0, 1] {
                let portal = Portal::new(
                    Url::parse(&format!(
                        "portal://{key}@127.0.0.1/{carrier}:2000?morph={morph}"
                    ))
                    .unwrap(),
                    Logger,
                )
                .unwrap();
                let expected = if std::env::var_os("NOW_TEST_HANDSHAKE_OVERRIDE").is_some() {
                    std::time::Duration::from_secs(45)
                } else {
                    std::time::Duration::from_millis(milliseconds)
                };
                instances.push((portal, expected));
            }
        }
    }
    for (portal, expected) in instances {
        assert_eq!(portal.inner.runtime.handshake_timeout, expected);
        assert_eq!(portal.inner.forward.runtime.handshake_timeout, expected);
    }
}
