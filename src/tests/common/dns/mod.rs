// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Local encrypted upstreams, cache semantics, failover and DNS ingress tests.

mod caching;
mod configuration;
mod probing;
mod stats;
mod transport;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use hickory_net::proto::op::{Edns, Message, OpCode, Query, ResponseCode};
use hickory_net::proto::rr::{
    Name, RData, Record, RecordType,
    rdata::{A, AAAA, NS, SOA, TXT},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

use super::*;

pub(crate) struct TestServer {
    pub(crate) url: String,
    tls: Arc<rustls::ClientConfig>,
    certificate: CertificateDer<'static>,
    mode: Arc<AtomicU8>,
    count: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    ttl: Arc<AtomicU32>,
    delay: Arc<AtomicU64>,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone)]
struct Answers {
    mode: Arc<AtomicU8>,
    count: Arc<AtomicUsize>,
    ttl: Arc<AtomicU32>,
    delay: Arc<AtomicU64>,
}

impl Answers {
    async fn answer(&self, wire: &[u8]) -> Option<Vec<u8>> {
        self.count.fetch_add(1, Ordering::Relaxed);
        let delay = self.delay.load(Ordering::Relaxed);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        let request = Message::from_vec(wire).unwrap();
        let mode = self.mode.load(Ordering::Relaxed);
        if mode == 1 {
            return None;
        }
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.metadata.recursion_available = true;
        response.metadata.authentic_data = true;
        response.queries.clone_from(&request.queries);
        response.edns.clone_from(&request.edns);
        let query = request.queries.first().unwrap();
        let name = query.name().clone();
        let ttl = self.ttl.load(Ordering::Relaxed);
        if (9..=12).contains(&mode) && name.to_ascii().starts_with("business-error.") {
            response.metadata.response_code = match mode {
                9 => ResponseCode::Refused,
                10 => ResponseCode::FormErr,
                11 => ResponseCode::NotImp,
                _ => ResponseCode::ServFail,
            };
        } else if mode == 13 && name.to_ascii().starts_with("probe-target.") {
            response.metadata.response_code = ResponseCode::NXDomain;
        } else if mode == 14 && name.to_ascii().starts_with("probe-target.") {
            // NOERROR without the requested records is not a successful target test.
        } else if mode == 2 {
            response.metadata.response_code = ResponseCode::ServFail;
        } else if mode == 3 {
            response.metadata.response_code = ResponseCode::NXDomain;
            response.authorities.push(Record::from_rdata(
                name.clone(),
                ttl,
                RData::SOA(SOA::new(Name::root(), Name::root(), 1, 60, 60, 3600, 2)),
            ));
        } else if query.name().to_ascii().starts_with("large.") {
            for _ in 0..12 {
                response.answers.push(Record::from_rdata(
                    name.clone(),
                    ttl,
                    RData::TXT(TXT::new(vec!["x".repeat(100)])),
                ));
            }
        } else {
            let data = match query.query_type() {
                RecordType::AAAA => RData::AAAA(AAAA("::1".parse().unwrap())),
                RecordType::NS => RData::NS(NS(Name::from_ascii("ns.test.").unwrap())),
                _ => RData::A(A("127.0.0.1".parse().unwrap())),
            };
            response.answers.push(Record::from_rdata(name, ttl, data));
        }
        if mode == 4 {
            response.queries[0].set_name(Name::from_ascii("unrelated.test.").unwrap());
        }
        Some(response.to_vec().unwrap())
    }
}

impl TestServer {
    pub(crate) async fn new(transport: &str) -> Self {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let cert = certified.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        server_tls.alpn_protocols = vec![match transport {
            "https" => b"h2".to_vec(),
            "tls" => b"dot".to_vec(),
            _ => b"doq".to_vec(),
        }];
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let tls = Arc::new(
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let answers = Answers {
            mode: Arc::new(AtomicU8::new(0)),
            count: Arc::new(AtomicUsize::new(0)),
            ttl: Arc::new(AtomicU32::new(60)),
            delay: Arc::new(AtomicU64::new(0)),
        };
        let connections = Arc::new(AtomicUsize::new(0));
        let (address, task) = if transport == "quic" {
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap();
            let endpoint = quinn::Endpoint::server(
                quinn::ServerConfig::with_crypto(Arc::new(crypto)),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let address = endpoint.local_addr().unwrap();
            let answers = answers.clone();
            let connections = connections.clone();
            let task = tokio::spawn(async move {
                let mut tasks = JoinSet::new();
                while let Some(incoming) = endpoint.accept().await {
                    let answers = answers.clone();
                    let connections = connections.clone();
                    tasks.spawn(async move {
                        let Ok(connection) = incoming.await else {
                            return;
                        };
                        connections.fetch_add(1, Ordering::Relaxed);
                        let mut queries = JoinSet::new();
                        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                            let answers = answers.clone();
                            queries.spawn(async move {
                                let Ok(wire) = recv.read_to_end(65537).await else {
                                    return;
                                };
                                assert_eq!(
                                    u16::from_be_bytes([wire[0], wire[1]]) as usize,
                                    wire.len() - 2
                                );
                                assert_eq!(&wire[2..4], &[0, 0], "DoQ IDs must be zero");
                                if let Some(response) = answers.answer(&wire[2..]).await {
                                    let mut framed = (response.len() as u16).to_be_bytes().to_vec();
                                    framed.extend(response);
                                    let _ = send.write_all(&framed).await;
                                    let _ = send.finish();
                                } else {
                                    std::future::pending::<()>().await;
                                }
                            });
                            while queries.try_join_next().is_some() {}
                        }
                    });
                    while tasks.try_join_next().is_some() {}
                }
            });
            (address, task)
        } else {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
            let answers = answers.clone();
            let connections = connections.clone();
            let https = transport == "https";
            let task = tokio::spawn(async move {
                let mut tasks = JoinSet::new();
                while let Ok((stream, _)) = listener.accept().await {
                    stream.set_nodelay(true).unwrap();
                    let acceptor = acceptor.clone();
                    let answers = answers.clone();
                    let connections = connections.clone();
                    tasks.spawn(async move {
                        let Ok(mut stream) = acceptor.accept(stream).await else {
                            return;
                        };
                        connections.fetch_add(1, Ordering::Relaxed);
                        if https {
                            let Ok(mut connection) = h2::server::handshake(stream).await else {
                                return;
                            };
                            let mut queries = JoinSet::new();
                            while let Some(Ok((request, mut respond))) = connection.accept().await {
                                assert_eq!(request.uri().path(), "/dns-query");
                                assert_eq!(request.uri().port_u16(), Some(address.port()));
                                assert_eq!(request.method(), http::Method::POST);
                                let answers = answers.clone();
                                queries.spawn(async move {
                                    let mut body = request.into_body();
                                    let mut wire = Vec::new();
                                    while let Some(Ok(chunk)) = body.data().await {
                                        let _ = body.flow_control().release_capacity(chunk.len());
                                        wire.extend_from_slice(&chunk);
                                    }
                                    if let Some(response) = answers.answer(&wire).await {
                                        let mode = answers.mode.load(Ordering::Relaxed);
                                        let headers = http::Response::builder()
                                            .status(if mode == 6 { 503 } else { 200 })
                                            .header(
                                                "content-type",
                                                if mode == 5 {
                                                    "text/plain"
                                                } else {
                                                    "application/dns-message"
                                                },
                                            )
                                            .header("age", if mode == 7 { "30" } else { "0" })
                                            .body(())
                                            .unwrap();
                                        if let Ok(mut stream) =
                                            respond.send_response(headers, false)
                                        {
                                            let _ = stream
                                                .send_data(bytes::Bytes::from(response), true);
                                        }
                                    } else {
                                        std::future::pending::<()>().await;
                                    }
                                });
                                while queries.try_join_next().is_some() {}
                            }
                        } else {
                            while let Ok(size) = stream.read_u16().await {
                                let mut wire = vec![0; size as usize];
                                if stream.read_exact(&mut wire).await.is_err() {
                                    break;
                                }
                                if let Some(response) = answers.answer(&wire).await
                                    && (stream.write_u16(response.len() as u16).await.is_err()
                                        || stream.write_all(&response).await.is_err())
                                {
                                    break;
                                }
                                if answers.mode.load(Ordering::Relaxed) == 8 {
                                    let _ = stream.flush().await;
                                    break;
                                }
                            }
                        }
                    });
                    while tasks.try_join_next().is_some() {}
                }
            });
            (address, task)
        };
        Self {
            url: format!(
                "{transport}://localhost:{}{}?bootstrap=127.0.0.1",
                address.port(),
                if transport == "https" {
                    "/dns-query"
                } else {
                    ""
                }
            ),
            tls,
            certificate: cert,
            mode: answers.mode,
            count: answers.count,
            ttl: answers.ttl,
            delay: answers.delay,
            connections,
            task,
        }
    }

    pub(crate) fn resolver(&self, options: &[(&str, &str)]) -> Arc<DnsResolver> {
        self.resolver_with_fallback(None, options)
    }

    fn resolver_with_fallback(
        &self,
        fallback: Option<&Self>,
        options: &[(&str, &str)],
    ) -> Arc<DnsResolver> {
        let mut url =
            url::Url::parse("portal://0123456789abcdef0123456789abcdef@127.0.0.1:2000").unwrap();
        url.query_pairs_mut().append_pair("dns", &self.url);
        if let Some(fallback) = fallback {
            url.query_pairs_mut()
                .append_pair("dns-fallback", &fallback.url);
        }
        for (name, value) in options {
            url.query_pairs_mut().append_pair(name, value);
        }
        let config = DnsConfig::from_url(&url).unwrap().unwrap();
        let tls = if let Some(fallback) = fallback {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(self.certificate.clone()).unwrap();
            roots.add(fallback.certificate.clone()).unwrap();
            Arc::new(
                rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
            )
        } else {
            self.tls.clone()
        };
        DnsResolver::with_tls(config, DialPolicy::default(), tls).unwrap()
    }
}

fn request(name: &str, id: u16) -> Message {
    let mut request = Message::query();
    request.metadata.id = id;
    request.metadata.recursion_desired = true;
    request
        .queries
        .push(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    request
}

async fn ask(resolver: &Arc<DnsResolver>, name: &str, id: u16) -> Message {
    Message::from_vec(
        &resolver
            .answer(&request(name, id).to_vec().unwrap(), false)
            .await
            .unwrap(),
    )
    .unwrap()
}
