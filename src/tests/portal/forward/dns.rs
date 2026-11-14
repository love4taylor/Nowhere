// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Authenticated TLS/QUIC port-53 interception across every fixed outlet.

use hickory_net::proto::op::{Message, Query};
use hickory_net::proto::rr::{Name, RecordType};
use tokio::time::Instant;

use super::*;

#[tokio::test]
async fn hijacks_tcp_udp_ipv4_ipv6_domain_53_over_tls_quic_even_with_socks_or_offline_egress() {
    let server = crate::common::dns::tests::TestServer::new("https").await;
    for out in ["direct", "127.0.0.1:1", "egress"] {
        for morph in [false, true] {
            let resolver = server.resolver(&[]);
            let h = Harness::configured_inner(out, morph, "127.0.0.1", |inner| {
                Arc::get_mut(&mut inner.forward).unwrap().dns = Some(resolver);
            })
            .await;
            for net in ["tcp", "udp"] {
                let client = h.client(net, morph);
                for target in [
                    "192.0.2.53:53",
                    "[2001:db8::53]:53",
                    "must-not-resolve.invalid:53",
                ] {
                    let target: Target = target.parse().unwrap();
                    let mut query = Message::query();
                    query.metadata.id = 0xabcd;
                    query.metadata.recursion_desired = true;
                    query.queries.push(Query::query(
                        Name::from_ascii("hijack.test.").unwrap(),
                        RecordType::A,
                    ));
                    let wire = query.to_vec().unwrap();
                    let mut tcp = client.open_tcp(&target).await.unwrap();
                    tcp.write_u16(wire.len() as u16).await.unwrap();
                    tcp.write_all(&wire).await.unwrap();
                    let size = tokio::time::timeout(Duration::from_secs(2), tcp.read_u16())
                        .await
                        .unwrap()
                        .unwrap();
                    let mut response = vec![0; size as usize];
                    tcp.read_exact(&mut response).await.unwrap();
                    let response = Message::from_vec(&response).unwrap();
                    assert_eq!(response.metadata.id, 0xabcd);
                    assert_eq!(
                        response.answers.len(),
                        1,
                        "out={out} net={net} target={target}"
                    );
                    drop(tcp);
                    let mut udp = crate::vector::udp_flow::open_udp(client.clone(), &target)
                        .await
                        .unwrap();
                    assert!(udp.send(&wire).await.unwrap());
                    let mut buffer = Vec::new();
                    let response =
                        tokio::time::timeout(Duration::from_secs(2), udp.recv_into(&mut buffer))
                            .await
                            .unwrap()
                            .unwrap()
                            .unwrap();
                    let response = Message::from_vec(response.payload(&buffer)).unwrap();
                    assert_eq!(response.metadata.id, 0xabcd);
                    assert_eq!(response.answers.len(), 1);
                    udp.close().await;
                }
                client.close(Instant::now() + Duration::from_secs(2)).await;
            }
            h.close().await;
        }
    }
}
