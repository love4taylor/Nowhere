// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Reusable, certificate-verified DoH/DoT/DoQ sessions and source binding.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use hickory_net::DnsHandle;
use hickory_net::proto::op::{DnsRequest, DnsRequestOptions, Message, MessageType, ResponseCode};
use hickory_net::quic::QuicClientStream;
use hickory_net::runtime::{RuntimeProvider, Spawn, TokioRuntimeProvider};
use hickory_net::xfer::{DnsExchange, DnsMultiplexer};
use rustls::pki_types::ServerName;
use tokio::net::lookup_host;
use tokio::sync::{Mutex, Notify};
use tokio::time::Instant;

use crate::common::{AddressFamily, DialPolicy, filter_addrs_for_family};

use super::config::{HttpOptions, Transport, UpstreamConfig};
use super::health::{HealthState, ProbeOutcome};
use super::http3::Http3Session;
use super::https::HttpsSession;

#[derive(Default)]
struct Counters {
    queries: AtomicU64,
    failures: AtomicU64,
    probes: AtomicU64,
    last_latency_us: AtomicU64,
}

type Exchange = DnsExchange<TokioRuntimeProvider>;

#[derive(Clone)]
enum EncryptedSession {
    Dns(Exchange),
    Https(HttpsSession),
    Http3(Http3Session),
}

impl EncryptedSession {
    fn is_usable(&self) -> bool {
        match self {
            Self::Dns(_) => true,
            Self::Https(session) => session.is_usable(),
            Self::Http3(session) => session.is_usable(),
        }
    }

    fn invalidated_by(&self, error: &anyhow::Error) -> bool {
        matches!(self, Self::Dns(_)) || !self.is_usable() || super::https::connection_error(error)
    }
}

#[derive(Default)]
struct Session {
    generation: u64,
    exchange: Option<EncryptedSession>,
}

#[derive(Default)]
struct Slot {
    session: Mutex<Session>,
    active: AtomicUsize,
}

struct Busy<'a>(&'a AtomicUsize);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(super) struct Upstream {
    pub(super) unhealthy: AtomicBool,
    index: usize,
    config: UpstreamConfig,
    policy: DialPolicy,
    tls: Arc<rustls::ClientConfig>,
    timeout: Duration,
    slots: Vec<Slot>,
    next_slot: AtomicUsize,
    http: HttpOptions,
    // Keep the provider alive: it owns the encrypted sessions' background tasks.
    provider: TokioRuntimeProvider,
    counters: Counters,
    health: std::sync::Mutex<HealthState>,
    pub(super) probe_needed: AtomicBool,
    pub(super) probe_wakeup: Notify,
}

impl Upstream {
    pub(super) fn new(
        index: usize,
        config: UpstreamConfig,
        policy: DialPolicy,
        tls: Arc<rustls::ClientConfig>,
        timeout: Duration,
        http: HttpOptions,
    ) -> Self {
        // QUIC streams avoid TCP head-of-line blocking. RFC 9114 section 3.3
        // recommends a single H3 connection per peer; the TCP pool is for H2.
        let pool_size = if config.transport == Transport::Https {
            http.pool_size
        } else {
            1
        };
        Self {
            index,
            config,
            policy,
            tls,
            timeout,
            slots: (0..pool_size).map(|_| Slot::default()).collect(),
            next_slot: AtomicUsize::new(0),
            http,
            provider: TokioRuntimeProvider::new(),
            unhealthy: AtomicBool::new(false),
            counters: Counters::default(),
            health: std::sync::Mutex::new(HealthState::default()),
            probe_needed: AtomicBool::new(false),
            probe_wakeup: Notify::new(),
        }
    }

    pub(super) async fn prewarm(&self) {
        if !self.http.prewarm
            || !matches!(self.config.transport, Transport::Https | Transport::Http3)
        {
            return;
        }
        // At most four concurrent handshakes per H2 upstream, one for H3.
        let mut futures = futures_util::stream::FuturesUnordered::new();
        for slot in &self.slots {
            futures.push(async {
                slot.active.fetch_add(1, Ordering::Relaxed);
                let _busy = Busy(&slot.active);
                let _ = tokio::time::timeout(self.timeout, async {
                    let mut session = slot.session.lock().await;
                    if session.exchange.as_ref().is_none_or(|s| !s.is_usable()) {
                        session.exchange = Some(self.connect().await?);
                        session.generation = session.generation.wrapping_add(1);
                    }
                    anyhow::Ok(())
                })
                .await;
            });
        }
        while futures.next().await.is_some() {}
    }

    pub(super) fn needs_probe(&self) -> bool {
        self.health.lock().unwrap().needs_probe()
    }

    pub(super) fn report_health(&self) {
        let mut health = self.health.lock().unwrap();
        if let Some(notice) = health.log.poll(Instant::now()) {
            notice.log(self.index);
        }
    }

    pub(super) fn mark_timed_out(&self, started: Instant) {
        self.counters.failures.fetch_add(1, Ordering::Relaxed);
        self.business_failure(started);
        self.request_probe();
    }

    fn business_failure(&self, started: Instant) {
        let mut health = self.health.lock().unwrap();
        health.business_failure(started, Instant::now());
        self.unhealthy.store(health.unhealthy, Ordering::Relaxed);
    }

    pub(super) fn request_probe(&self) {
        // Deduplicate overlapping slow/failed queries into one pending health test.
        if !self.probe_needed.swap(true, Ordering::Relaxed) {
            self.probe_wakeup.notify_one();
        }
    }

    pub(super) async fn query(&self, request: &Message) -> Result<Message> {
        self.execute(request, None, self.timeout).await
    }

    pub(super) async fn probe(&self, request: &Message, budget: Duration) -> Result<Message> {
        let version = self.health.lock().unwrap().probe_version();
        self.execute(request, Some(version), budget.min(self.timeout))
            .await
    }

    async fn execute(
        &self,
        request: &Message,
        probe: Option<u64>,
        budget: Duration,
    ) -> Result<Message> {
        let started = Instant::now();
        let counter = if probe.is_some() {
            &self.counters.probes
        } else {
            &self.counters.queries
        };
        counter.fetch_add(1, Ordering::Relaxed);
        let mut result = tokio::time::timeout(budget, self.query_inner(request))
            .await
            .context("DNS upstream timeout")
            .and_then(|result| result);
        if let Some(version) = probe {
            let outcome = match &result {
                Err(_) => ProbeOutcome::Failure,
                Ok(response)
                    if response.metadata.response_code == ResponseCode::NoError
                        && response.answers.iter().any(|record| {
                            record.data.record_type() == request.queries[0].query_type()
                        }) =>
                {
                    ProbeOutcome::Success
                }
                Ok(_) => ProbeOutcome::TargetError,
            };
            let mut health = self.health.lock().unwrap();
            let notice = health.probe_result(version, outcome, Instant::now());
            self.unhealthy.store(health.unhealthy, Ordering::Relaxed);
            if let Some(notice) = notice {
                notice.log(self.index);
            }
            if matches!(outcome, ProbeOutcome::TargetError) {
                result = Err(anyhow!("DNS health target returned no requested records"));
            }
        } else {
            if result.is_err() {
                self.business_failure(started);
            } else if let Ok(response) = &result {
                if matches!(
                    response.metadata.response_code,
                    ResponseCode::NoError | ResponseCode::NXDomain
                ) {
                    let mut health = self.health.lock().unwrap();
                    let notice = health.business_success(Instant::now());
                    self.unhealthy.store(health.unhealthy, Ordering::Relaxed);
                    if let Some(notice) = notice {
                        notice.log(self.index);
                    }
                } else {
                    result = Err(anyhow!(
                        "DNS upstream rejected query: {:?}",
                        response.metadata.response_code
                    ));
                }
            }
            if result.is_err() {
                self.counters.failures.fetch_add(1, Ordering::Relaxed);
                self.request_probe();
            } else {
                self.counters.last_latency_us.store(
                    (started.elapsed().as_micros().min(u64::MAX as u128) as u64).saturating_add(1),
                    Ordering::Relaxed,
                );
            }
        }
        result
    }

    pub(super) fn snapshot(&self, fallback: bool) -> crate::telemetry::DnsUpstreamSnapshot {
        let scheme = match self.config.transport {
            Transport::Https => "https",
            Transport::Http3 => "h3",
            Transport::Tls => "tls",
            Transport::Quic => "quic",
        };
        let host = if self.config.host.contains(':') {
            format!("[{}]", self.config.host)
        } else {
            self.config.host.clone()
        };
        let latency = self.counters.last_latency_us.load(Ordering::Relaxed);
        crate::telemetry::DnsUpstreamSnapshot {
            endpoint: format!("{scheme}://{host}:{}", self.config.port),
            fallback,
            healthy: !self.unhealthy.load(Ordering::Relaxed),
            queries: self.counters.queries.load(Ordering::Relaxed),
            failures: self.counters.failures.load(Ordering::Relaxed),
            probes: self.counters.probes.load(Ordering::Relaxed),
            last_latency_us: (latency != 0).then(|| latency - 1),
        }
    }

    async fn query_inner(&self, request: &Message) -> Result<Message> {
        let start = self.next_slot.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        let slot = (0..self.slots.len())
            .map(|offset| &self.slots[(start + offset) % self.slots.len()])
            .min_by_key(|slot| slot.active.load(Ordering::Relaxed))
            .unwrap();
        slot.active.fetch_add(1, Ordering::Relaxed);
        let _busy = Busy(&slot.active);
        let mut retry = true;
        loop {
            let (exchange, generation, reused) = {
                let mut session = slot.session.lock().await;
                if session.exchange.as_ref().is_some_and(|s| !s.is_usable()) {
                    session.exchange = None;
                }
                let reused = session.exchange.is_some();
                if !reused {
                    session.exchange = Some(self.connect().await?);
                    session.generation = session.generation.wrapping_add(1);
                }
                (
                    session.exchange.as_ref().unwrap().clone(),
                    session.generation,
                    reused,
                )
            };
            let result = async {
                match &exchange {
                    EncryptedSession::Https(exchange) => exchange.query(request).await,
                    EncryptedSession::Http3(exchange) => exchange.query(request).await,
                    EncryptedSession::Dns(exchange) => Ok(exchange
                        .send(DnsRequest::new(
                            request.clone(),
                            DnsRequestOptions::default(),
                        ))
                        .next()
                        .await
                        .ok_or_else(|| anyhow!("DNS upstream closed"))??
                        .into_message()),
                }
            }
            .await;
            let response = match result {
                Ok(response) => response,
                Err(error) => {
                    if !exchange.invalidated_by(&error) {
                        return Err(error);
                    }
                    let mut session = slot.session.lock().await;
                    if session.generation == generation {
                        session.exchange = None;
                    }
                    drop(session);
                    // Idle upstreams may close pooled sessions. Reconnect once without
                    // giving this attempt or the overall fallback race a new deadline.
                    if reused && retry {
                        retry = false;
                        continue;
                    }
                    return Err(error);
                }
            };
            if response.metadata.message_type != MessageType::Response
                || response.metadata.op_code != request.metadata.op_code
                || response.queries != request.queries
            {
                bail!("DNS upstream returned an unrelated response");
            }
            if response.metadata.truncation {
                bail!("encrypted DNS upstream returned a truncated response");
            }
            return Ok(response);
        }
    }

    async fn connect(&self) -> Result<EncryptedSession> {
        let config = &self.config;
        let addrs = match config
            .bootstrap
            .or_else(|| config.host.parse::<IpAddr>().ok())
        {
            Some(ip) => vec![SocketAddr::new(ip, config.port)],
            None => lookup_host((config.host.as_str(), config.port))
                .await
                .context("failed to bootstrap DNS upstream; use bootstrap=IP to avoid system DNS")?
                .take(16)
                .collect(),
        };
        let addresses =
            filter_addrs_for_family(addrs.into_iter(), &self.policy, AddressFamily::Any);
        let mut last_error = anyhow!("no DNS upstream address matches dial policy");
        for address in addresses {
            // Each bootstrap address gets a bounded slice, allowing alternate families to run.
            let attempt = self.connect_address(address);
            match tokio::time::timeout(self.timeout.min(Duration::from_millis(500)), attempt).await
            {
                Ok(Ok(exchange)) => return Ok(exchange),
                Ok(Err(error)) => last_error = error,
                Err(_) => last_error = anyhow!("DNS upstream handshake timeout"),
            }
        }
        Err(last_error)
    }

    async fn connect_address(&self, address: SocketAddr) -> Result<EncryptedSession> {
        let bind = self
            .policy
            .local_ip(address.ip())?
            .map(|ip| SocketAddr::new(ip, 0));
        let config = &self.config;
        let name = Arc::<str>::from(config.host.as_str());
        match config.transport {
            Transport::Https => Ok(EncryptedSession::Https(
                HttpsSession::connect(
                    config,
                    address,
                    self.policy.local_ip(address.ip())?,
                    &self.tls,
                    &self.http,
                )
                .await?,
            )),
            Transport::Http3 => Ok(EncryptedSession::Http3(
                Http3Session::connect(
                    config,
                    address,
                    self.policy.local_ip(address.ip())?,
                    &self.tls,
                    &self.http,
                )
                .await?,
            )),
            Transport::Tls => {
                // Unlike tls_exchange(), this lower-level helper retains SNI.
                let (stream, sender) = hickory_net::tls::tls_client_connect_with_bind_addr(
                    address,
                    bind,
                    ServerName::try_from(config.host.clone())?,
                    self.tls.clone(),
                    self.provider.clone(),
                );
                let stream = DnsMultiplexer::new(stream.await?, sender)
                    .with_timeout(self.timeout)
                    .with_max_active_requests(128);
                let (exchange, background) = DnsExchange::from_stream(stream);
                self.provider.create_handle().spawn_bg(background);
                Ok(EncryptedSession::Dns(exchange))
            }
            Transport::Quic => {
                let mut builder = QuicClientStream::builder()
                    .crypto_config((*self.tls).clone())
                    .request_timeout(self.timeout);
                if let Some(bind) = bind {
                    builder = builder.bind_addr(bind);
                }
                let stream = builder.build(address, name).await?;
                let (exchange, background) = DnsExchange::from_stream(stream);
                self.provider.create_handle().spawn_bg(background);
                Ok(EncryptedSession::Dns(exchange))
            }
        }
    }
}

pub(super) fn client_config() -> Result<Arc<rustls::ClientConfig>> {
    let native = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    for certificate in native.certs {
        roots.add(certificate).context("invalid DNS trust root")?;
    }
    if roots.is_empty() {
        bail!("no DNS system trust roots available: {:?}", native.errors);
    }
    Ok(Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth(),
    ))
}
