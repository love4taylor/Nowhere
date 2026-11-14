// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Endpoint/target validation and random instance identity regressions.

use super::*;

#[test]
fn instance_ids_are_random_lowercase_hex() {
    let first = random_id().unwrap();
    let second = random_id().unwrap();
    assert_eq!(first.len(), 32);
    assert!(
        first
            .bytes()
            .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
    );
    assert_ne!(first, second);
}

#[test]
fn dns_endpoints_preserve_identity_without_paths_queries_credentials_or_terminal_controls() {
    for (input, expected) in [
        ("https://dns.example:443", "https://dns.example:443"),
        ("tls://1.1.1.1:853", "tls://1.1.1.1:853"),
        ("quic://[::1]:8853", "quic://[::1]:8853"),
    ] {
        assert_eq!(dns_endpoint(input), expected);
    }
    for input in [
        "https://user:password@dns.example/",
        "https://dns.example/private-id",
        "https://dns.example?bootstrap=192.0.2.1",
        "https://dns.example#private-id",
        "http://dns.example",
        "https://dns.example:0",
        "https://dns.example\nforged",
        "https://dns.example/\u{1b}[31m",
    ] {
        assert_eq!(dns_endpoint(input), "<redacted>", "{input:?}");
    }
}
