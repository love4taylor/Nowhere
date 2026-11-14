// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Passive DNS counters and health snapshots; no lookup or probe on observation.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::telemetry::DnsSnapshot;

use super::DnsResolver;

const NONE: usize = usize::MAX;

pub(super) struct Counters {
    pub(super) queries: AtomicU64,
    pub(super) cache_hits: AtomicU64,
    pub(super) stale_hits: AtomicU64,
    pub(super) cache_misses: AtomicU64,
    pub(super) deduplicated: AtomicU64,
    pub(super) refreshes: AtomicU64,
    pub(super) failures: AtomicU64,
    pub(super) fallback_replies: AtomicU64,
    pub(super) upstream_switches: AtomicU64,
    pub(super) tcp_queries: AtomicU64,
    pub(super) udp_queries: AtomicU64,
    last_upstream: AtomicUsize,
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            stale_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            deduplicated: AtomicU64::new(0),
            refreshes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            fallback_replies: AtomicU64::new(0),
            upstream_switches: AtomicU64::new(0),
            tcp_queries: AtomicU64::new(0),
            udp_queries: AtomicU64::new(0),
            last_upstream: AtomicUsize::new(NONE),
        }
    }
}

impl DnsResolver {
    pub(super) fn record_winner(&self, index: usize) {
        let previous = self.counters.last_upstream.swap(index, Ordering::Relaxed);
        if previous != NONE && previous != index {
            self.counters
                .upstream_switches
                .fetch_add(1, Ordering::Relaxed);
        }
        if index >= self.config.primary.len() {
            self.counters
                .fallback_replies
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn snapshot(&self) -> DnsSnapshot {
        let (cache_entries, cache_bytes) = self.cache.lock().unwrap().usage();
        let upstreams: Vec<_> = self
            .upstreams
            .iter()
            .enumerate()
            .map(|(index, upstream)| upstream.snapshot(index >= self.config.primary.len()))
            .collect();
        let last = self.counters.last_upstream.load(Ordering::Relaxed);
        DnsSnapshot {
            hijack: self.config.hijack,
            queries: self.counters.queries.load(Ordering::Relaxed),
            cache_hits: self.counters.cache_hits.load(Ordering::Relaxed),
            stale_hits: self.counters.stale_hits.load(Ordering::Relaxed),
            cache_misses: self.counters.cache_misses.load(Ordering::Relaxed),
            deduplicated: self.counters.deduplicated.load(Ordering::Relaxed),
            refreshes: self.counters.refreshes.load(Ordering::Relaxed),
            failures: self.counters.failures.load(Ordering::Relaxed),
            fallback_replies: self.counters.fallback_replies.load(Ordering::Relaxed),
            upstream_switches: self.counters.upstream_switches.load(Ordering::Relaxed),
            tcp_queries: self.counters.tcp_queries.load(Ordering::Relaxed),
            udp_queries: self.counters.udp_queries.load(Ordering::Relaxed),
            cache_entries,
            cache_bytes,
            in_flight: 128 - self.queries.available_permits(),
            preferred_upstream: upstreams.iter().position(|upstream| upstream.healthy),
            last_upstream: (last != NONE).then_some(last),
            upstreams,
        }
    }
}
