// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Wire-format cache bounded by both entry count and charged bytes.

use std::collections::HashMap;
use std::time::Duration;

use hickory_net::proto::op::{Message, ResponseCode};
use hickory_net::proto::rr::RData;
use tokio::time::Instant;

use super::config::DnsConfig;

struct Entry {
    wire: Vec<u8>,
    inserted: Instant,
    expires: Instant,
    stale_until: Instant,
    refresh_after: Instant,
    touched: u64,
}

#[derive(Default)]
pub(super) struct Cache {
    entries: HashMap<Vec<u8>, Entry>,
    bytes: usize,
    clock: u64,
}

pub(super) struct Hit {
    pub(super) response: Message,
    pub(super) refresh: bool,
    pub(super) stale: bool,
}

impl Cache {
    pub(super) fn usage(&self) -> (usize, usize) {
        (self.entries.len(), self.bytes)
    }

    pub(super) fn get(&mut self, key: &[u8], retry: Duration) -> Option<Hit> {
        let now = Instant::now();
        if self.entries.get(key).is_some_and(|e| now >= e.stale_until) {
            self.remove(key);
        }
        let entry = self.entries.get_mut(key)?;
        self.clock = self.clock.wrapping_add(1);
        entry.touched = self.clock;
        let mut response = Message::from_vec(&entry.wire).ok()?;
        let stale = now >= entry.expires;
        let age = now
            .duration_since(entry.inserted)
            .as_secs()
            .min(u32::MAX as u64) as u32;
        let remaining =
            (entry.expires.duration_since(entry.inserted).as_secs() as u32).saturating_sub(age);
        for record in response
            .answers
            .iter_mut()
            .chain(&mut response.authorities)
            .chain(&mut response.additionals)
        {
            record.ttl = if stale {
                1
            } else {
                record.ttl.saturating_sub(age).min(remaining)
            };
        }
        if stale {
            // This forwarder does not validate DNSSEC, and old signatures may have expired.
            response.metadata.authentic_data = false;
        }
        let refresh = stale && now >= entry.refresh_after;
        if refresh {
            entry.refresh_after = now + retry;
        }
        Some(Hit {
            response,
            refresh,
            stale,
        })
    }

    pub(super) fn insert(&mut self, key: Vec<u8>, response: &Message, config: &DnsConfig) {
        // A fresh negative or TTL=0 answer must revoke a formerly positive stale answer.
        self.remove(&key);
        if response.metadata.truncation
            || response.signature.is_some()
            || !matches!(
                response.metadata.response_code,
                ResponseCode::NoError | ResponseCode::NXDomain
            )
        {
            return;
        }
        let negative = response.metadata.response_code == ResponseCode::NXDomain
            || response.answers.is_empty();
        let records = || {
            response
                .answers
                .iter()
                .chain(&response.authorities)
                .chain(&response.additionals)
        };
        let ttl = if negative {
            response
                .authorities
                .iter()
                .filter_map(|r| match &r.data {
                    RData::SOA(soa) => Some(r.ttl.min(soa.minimum)),
                    _ => None,
                })
                .min()
        } else {
            records().map(|r| r.ttl).min()
        };
        let Some(ttl) = ttl.filter(|ttl| *ttl > 0) else {
            return;
        };
        let Ok(wire) = response.to_vec() else {
            return;
        };
        let charge = charge(&key, &wire);
        if wire.len() > 16384 || charge > config.cache_bytes {
            return;
        }
        while self.entries.len() >= config.cache_size || self.bytes + charge > config.cache_bytes {
            // Bounded scan on eviction only; hits never allocate or grow an eviction queue.
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.touched)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.remove(&oldest);
        }
        self.clock = self.clock.wrapping_add(1);
        let now = Instant::now();
        let expires = now + Duration::from_secs(ttl.min(86400).into());
        self.entries.insert(
            key,
            Entry {
                wire,
                inserted: now,
                expires,
                stale_until: expires
                    + if negative {
                        Duration::ZERO
                    } else {
                        config.stale
                    },
                refresh_after: expires,
                touched: self.clock,
            },
        );
        self.bytes += charge;
    }

    fn remove(&mut self, key: &[u8]) {
        if let Some(entry) = self.entries.remove(key) {
            self.bytes -= charge(key, &entry.wire);
        }
    }
}

fn charge(key: &[u8], wire: &[u8]) -> usize {
    key.len() + wire.len() + 256
}
