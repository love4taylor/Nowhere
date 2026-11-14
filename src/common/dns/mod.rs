// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Encrypted forwarding resolver, bounded optimistic cache and hedged failover.

mod cache;
mod config;
mod health;
mod hijack;
mod https;
mod stats;
mod upstream;

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use hickory_net::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_net::proto::rr::{Name, RData, RecordType};
use tokio::sync::{Semaphore, watch};
use tokio::time::Instant;

use crate::common::DialPolicy;
use crate::protocol::Target;

use cache::Cache;
pub(crate) use config::DnsConfig;
pub(crate) use hijack::DnsSocket;
use upstream::Upstream;

type Outcome = Option<Result<Arc<Vec<u8>>, Arc<str>>>;
type Flight = watch::Receiver<Outcome>;
type Attempt = BoxFuture<'static, (usize, Result<Message>)>;

pub(crate) struct DnsResolver {
    config: DnsConfig,
    upstreams: Vec<Arc<Upstream>>,
    cache: Mutex<Cache>,
    flights: Mutex<HashMap<Vec<u8>, Flight>>,
    queries: Arc<Semaphore>,
    pub(super) connections: Arc<Semaphore>,
    probes: OnceLock<()>,
    counters: stats::Counters,
}

impl fmt::Debug for DnsResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsResolver")
            .field("upstreams", &self.upstreams.len())
            .field("hijack", &self.config.hijack)
            .finish_non_exhaustive()
    }
}

impl DnsResolver {
    pub(crate) fn new(config: DnsConfig, policy: DialPolicy) -> Result<Arc<Self>> {
        Self::with_tls(config, policy, upstream::client_config()?)
    }

    fn with_tls(
        config: DnsConfig,
        policy: DialPolicy,
        tls: Arc<rustls::ClientConfig>,
    ) -> Result<Arc<Self>> {
        let upstreams = config
            .primary
            .iter()
            .chain(&config.fallback)
            .cloned()
            .enumerate()
            .map(|(index, upstream)| {
                Arc::new(Upstream::new(
                    index,
                    upstream,
                    policy.clone(),
                    tls.clone(),
                    config.timeout,
                ))
            })
            .collect();
        Ok(Arc::new(Self {
            config,
            upstreams,
            cache: Mutex::new(Cache::default()),
            flights: Mutex::new(HashMap::new()),
            queries: Arc::new(Semaphore::new(128)),
            connections: Arc::new(Semaphore::new(64)),
            probes: OnceLock::new(),
            counters: stats::Counters::default(),
        }))
    }

    pub(crate) fn hijacks(&self, target: &Target) -> bool {
        self.config.hijack
            && match target {
                Target::Ip(address) => address.port() == 53,
                Target::Domain { port, .. } => *port == 53,
            }
    }

    /// Always produces a DNS response to a syntactically valid query, including SERVFAIL.
    pub(crate) async fn answer(self: &Arc<Self>, packet: &[u8], udp: bool) -> Result<Vec<u8>> {
        let counter = if udp {
            &self.counters.udp_queries
        } else {
            &self.counters.tcp_queries
        };
        counter.fetch_add(1, Ordering::Relaxed);
        let request = match Message::from_vec(packet) {
            Ok(request) => request,
            Err(_) => {
                let id = packet
                    .get(..2)
                    .map(|id| u16::from_be_bytes([id[0], id[1]]))
                    .unwrap_or(0);
                return Ok(Message::error_msg(id, OpCode::Query, ResponseCode::FormErr).to_vec()?);
            }
        };
        let mut response =
            if request.metadata.message_type != MessageType::Query || request.queries.len() != 1 {
                error_response(&request, ResponseCode::FormErr)
            } else if request
                .edns
                .as_ref()
                .is_some_and(|edns| edns.version() != 0)
            {
                let mut response = error_response(&request, ResponseCode::BADVERS);
                response.edns = Some(hickory_net::proto::op::Edns::new());
                response
            } else if request.metadata.op_code != OpCode::Query
                || request.signature.is_some()
                || matches!(
                    request.queries[0].query_type(),
                    RecordType::AXFR | RecordType::IXFR
                )
            {
                error_response(&request, ResponseCode::NotImp)
            } else {
                self.resolve(&request)
                    .await
                    .unwrap_or_else(|_| error_response(&request, ResponseCode::ServFail))
            };
        response.metadata.id = request.metadata.id;
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        response.metadata.checking_disabled = request.metadata.checking_disabled;
        if request.queries.len() == 1 {
            response.queries.clone_from(&request.queries);
        } else {
            response.queries.clear();
        }
        // An OPT response is meaningful only when the requester sent OPT.
        if request.edns.is_none() {
            response.edns = None;
        } else {
            response
                .edns
                .get_or_insert_with(Default::default)
                .set_max_payload(4096);
        }
        let wire = response.to_vec()?;
        if udp
            && wire.len()
                > request
                    .edns
                    .as_ref()
                    .map_or(512, |e| e.max_payload().max(512) as usize)
                    .min(4096)
        {
            let mut truncated = response.truncate();
            // Even a header-only truncation can exceed the UDP limit if a large
            // EDNS option is echoed by the upstream. Keep OPT, drop its payload.
            if let Some(edns) = &mut truncated.edns {
                edns.options_mut().options.clear();
            }
            return Ok(truncated.to_vec()?);
        }
        Ok(wire)
    }

    async fn resolve(self: &Arc<Self>, request: &Message) -> Result<Message> {
        self.counters.queries.fetch_add(1, Ordering::Relaxed);
        let result = self.resolve_inner(request).await;
        if result.is_err() {
            self.counters.failures.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    async fn resolve_inner(self: &Arc<Self>, request: &Message) -> Result<Message> {
        self.start_probes();
        let mut normalized = request.clone();
        normalized.metadata.id = 0;
        normalized.queries[0].set_name(request.queries[0].name().to_lowercase());
        let key = normalized.to_vec()?;
        // Cookies, ECS, padding and other stateful options are forwarded but never cached.
        let cacheable = request.answers.is_empty()
            && request.authorities.is_empty()
            && request.additionals.is_empty()
            && request
                .edns
                .as_ref()
                .is_none_or(|e| e.options().as_ref().is_empty());
        let hit = if cacheable {
            self.cache
                .lock()
                .unwrap()
                .get(&key, self.config.probe_interval)
        } else {
            None
        };
        if let Some(hit) = hit {
            let counter = if hit.stale {
                &self.counters.stale_hits
            } else {
                &self.counters.cache_hits
            };
            counter.fetch_add(1, Ordering::Relaxed);
            if hit.refresh {
                let _ = self.start_query(key, normalized, cacheable, true);
            }
            return Ok(hit.response);
        }
        self.counters.cache_misses.fetch_add(1, Ordering::Relaxed);
        let mut flight = self.start_query(key, normalized, cacheable, false)?;
        loop {
            if let Some(result) = flight.borrow().clone() {
                return match result {
                    Ok(wire) => Ok(Message::from_vec(&wire)?),
                    Err(error) => Err(anyhow!("DNS resolution failed: {error}")),
                };
            }
            flight.changed().await.context("DNS query task stopped")?;
        }
    }

    fn start_query(
        self: &Arc<Self>,
        key: Vec<u8>,
        request: Message,
        cacheable: bool,
        refresh: bool,
    ) -> Result<Flight> {
        let mut flights = self.flights.lock().unwrap();
        if let Some(flight) = flights.get(&key) {
            self.counters.deduplicated.fetch_add(1, Ordering::Relaxed);
            return Ok(flight.clone());
        }
        let permit = self
            .queries
            .clone()
            .try_acquire_owned()
            .context("DNS query concurrency exhausted")?;
        let (sender, receiver) = watch::channel(None);
        flights.insert(key.clone(), receiver.clone());
        if refresh {
            self.counters.refreshes.fetch_add(1, Ordering::Relaxed);
        }
        let resolver = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let response = resolver.exchange(request).await;
            let result = match response {
                Ok(response) => {
                    if cacheable {
                        resolver.cache.lock().unwrap().insert(
                            key.clone(),
                            &response,
                            &resolver.config,
                        );
                    }
                    response
                        .to_vec()
                        .map(Arc::new)
                        .map_err(|error| Arc::<str>::from(error.to_string()))
                }
                Err(error) => Err(Arc::<str>::from(error.to_string())),
            };
            sender.send_replace(Some(result));
            resolver.flights.lock().unwrap().remove(&key);
        });
        Ok(receiver)
    }

    async fn exchange(&self, request: Message) -> Result<Message> {
        let mut pending = vec![None; self.upstreams.len()];
        let work = async {
            let (mut candidates, degraded): (Vec<_>, Vec<_>) = (0..self.upstreams.len())
                .partition(|index| !self.upstreams[*index].unhealthy.load(Ordering::Relaxed));
            // Working alternatives precede degraded candidates. A degraded candidate
            // can still answer if alternatives fail; a real success also restores health.
            candidates.extend(degraded);
            let mut candidates = candidates.into_iter();
            let mut attempts = FuturesUnordered::<Attempt>::new();
            let request = Arc::new(request);
            let launch = |index: usize, attempts: &mut FuturesUnordered<Attempt>| {
                let upstream = self.upstreams[index].clone();
                let request = request.clone();
                attempts.push(async move { (index, upstream.query(&request).await) }.boxed());
            };
            let first = candidates.next().context("no DNS upstream")?;
            launch(first, &mut attempts);
            pending[first] = Some(Instant::now());
            let timer = tokio::time::sleep(self.config.fallback_delay);
            tokio::pin!(timer);
            let mut last_error = anyhow!("all DNS upstreams failed");
            let mut next = candidates.next();
            while !attempts.is_empty() {
                tokio::select! {
                    result = attempts.next() => {
                        let Some((index, result)) = result else { break; };
                        pending[index] = None;
                        match result {
                            Ok(response) => {
                                self.record_winner(index);
                                return Ok(response);
                            },
                            Err(error) => last_error = error,
                        }
                        // Transport failures/SERVFAIL trigger fallback immediately.
                        if let Some(index) = next.take() {
                            launch(index, &mut attempts); pending[index] = Some(Instant::now());
                            next = candidates.next();
                            timer.as_mut().reset(Instant::now() + self.config.fallback_delay);
                        }
                    }
                    _ = &mut timer, if next.is_some() => {
                        for (index, pending) in pending.iter().enumerate() {
                            if pending.is_some() { self.upstreams[index].request_probe(); }
                        }
                        let index = next.take().unwrap();
                        launch(index, &mut attempts); pending[index] = Some(Instant::now());
                        next = candidates.next();
                        timer.as_mut().reset(Instant::now() + self.config.fallback_delay);
                    }
                }
            }
            Err(last_error)
        };
        match tokio::time::timeout(self.config.timeout, work).await {
            Ok(result) => result,
            Err(error) => {
                // The shared deadline may fire before an individual attempt's timeout.
                for (index, pending) in pending.iter().enumerate() {
                    if let Some(started) = pending {
                        self.upstreams[index].mark_timed_out(*started);
                    }
                }
                Err(error).context("DNS total query timeout")
            }
        }
    }

    fn start_probes(self: &Arc<Self>) {
        self.probes.get_or_init(|| {
            let weak = Arc::downgrade(self);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(health::POLL_INTERVAL).await;
                    let Some(resolver) = weak.upgrade() else {
                        break;
                    };
                    for upstream in &resolver.upstreams {
                        upstream.report_health();
                    }
                }
            });
            for index in 0..self.upstreams.len() {
                let weak = Arc::downgrade(self);
                let weak_upstream = Arc::downgrade(&self.upstreams[index]);
                let interval = self.config.probe_interval;
                tokio::spawn(async move {
                    loop {
                        let Some(upstream) = weak_upstream.upgrade() else {
                            break;
                        };
                        if !upstream.needs_probe() && !upstream.probe_needed.load(Ordering::Relaxed)
                        {
                            tokio::select! {
                                _ = tokio::time::sleep(interval) => {},
                                _ = upstream.probe_wakeup.notified() => {},
                            }
                        }
                        let Some(resolver) = weak.upgrade() else {
                            break;
                        };
                        let requested = upstream.probe_needed.swap(false, Ordering::Relaxed);
                        if !requested && !upstream.needs_probe() {
                            continue;
                        }
                        let mut probe = Message::query();
                        probe.metadata.recursion_desired = true;
                        probe.queries.push(resolver.config.probe_target.clone());
                        let budget = resolver
                            .config
                            .fallback_delay
                            .max(interval)
                            .min(resolver.config.timeout);
                        let _ = upstream.probe(&probe, budget).await;
                        // Bound target traffic even when many client queries keep failing.
                        drop(resolver);
                        drop(upstream);
                        tokio::time::sleep(interval).await;
                    }
                });
            }
        });
    }

    pub(crate) async fn lookup_ip(
        self: &Arc<Self>,
        host: &str,
        port: u16,
    ) -> Result<Vec<SocketAddr>> {
        let mut name = Name::from_ascii(host).context("invalid DNS target name")?;
        // Wire questions are always absolute; match the parsed upstream reply even when
        // a Flow's domain target omitted the presentation-format trailing dot.
        name.set_fqdn(true);
        let query = |record_type| {
            let mut request = Message::query();
            request.metadata.recursion_desired = true;
            request
                .queries
                .push(Query::query(name.clone(), record_type));
            async move { self.resolve(&request).await }
        };
        let (v4, v6) = tokio::join!(query(RecordType::A), query(RecordType::AAAA));
        let mut addresses = Vec::new();
        for response in [v4, v6].into_iter().flatten() {
            for record in response.answers {
                let ip = match record.data {
                    RData::A(a) => IpAddr::V4(a.0),
                    RData::AAAA(a) => IpAddr::V6(a.0),
                    _ => continue,
                };
                let address = SocketAddr::new(ip, port);
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
        }
        if addresses.is_empty() {
            bail!("encrypted DNS returned no target IP address");
        }
        Ok(addresses)
    }
}

fn error_response(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::error_msg(request.metadata.id, request.metadata.op_code, code);
    response.queries.clone_from(&request.queries);
    response.metadata.recursion_available = true;
    response
}

#[cfg(test)]
#[path = "../../tests/common/dns/mod.rs"]
pub(crate) mod tests;
