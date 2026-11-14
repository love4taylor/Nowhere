// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Debounced health notices, independent of immediate DNS routing decisions.

use std::time::Duration;

use tokio::time::Instant;

use crate::common::Logger;

const ALERT_AFTER: Duration = Duration::from_secs(1);
const REPEAT_AFTER: Duration = Duration::from_secs(60);
pub(super) const POLL_INTERVAL: Duration = Duration::from_millis(250);
const FAILURE_THRESHOLD: u8 = 3;

#[derive(Clone, Copy)]
pub(super) enum ProbeOutcome {
    Success,
    Failure,
    TargetError,
}

/// Real answers take precedence over auxiliary tests, including tests in flight.
#[derive(Default)]
pub(super) struct HealthState {
    pub(super) log: HealthLog,
    pub(super) unhealthy: bool,
    failures: u8,
    business_version: u64,
    last_business_success: Option<Instant>,
}

impl HealthState {
    pub(super) fn needs_probe(&self) -> bool {
        self.unhealthy || self.failures != 0
    }

    pub(super) fn probe_version(&self) -> u64 {
        self.business_version
    }

    pub(super) fn business_success(&mut self, now: Instant) -> Option<Notice> {
        self.business_version = self.business_version.wrapping_add(1);
        self.last_business_success = Some(now);
        self.success(now)
    }

    pub(super) fn business_failure(&mut self, started: Instant, now: Instant) {
        // A late failure from an older concurrent request cannot undo a real success.
        if self
            .last_business_success
            .is_some_and(|last| last >= started)
        {
            return;
        }
        self.business_version = self.business_version.wrapping_add(1);
        self.failure(now);
    }

    pub(super) fn probe_result(
        &mut self,
        version: u64,
        outcome: ProbeOutcome,
        now: Instant,
    ) -> Option<Notice> {
        if version != self.business_version {
            return None;
        }
        match outcome {
            ProbeOutcome::Success => return self.success(now),
            ProbeOutcome::Failure => self.failure(now),
            ProbeOutcome::TargetError => {
                // A valid DNS error/negative answer proves reachability, not a broken
                // upstream. It cannot recover an already degraded upstream either.
                self.failures = 0;
            }
        }
        None
    }

    fn failure(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1).min(FAILURE_THRESHOLD);
        if self.failures >= FAILURE_THRESHOLD {
            self.unhealthy = true;
            self.log.degrade(now);
        }
    }

    fn success(&mut self, now: Instant) -> Option<Notice> {
        self.failures = 0;
        self.unhealthy = false;
        self.log.recover(now)
    }
}

#[derive(Default)]
pub(super) struct HealthLog {
    since: Option<Instant>,
    last_notice: Option<Instant>,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Notice {
    Degraded(Duration),
    StillDegraded(Duration),
    Recovered(Duration),
}

impl HealthLog {
    pub(super) fn degrade(&mut self, now: Instant) {
        self.since.get_or_insert(now);
    }

    pub(super) fn poll(&mut self, now: Instant) -> Option<Notice> {
        let elapsed = now.duration_since(self.since?);
        match self.last_notice {
            None if elapsed >= ALERT_AFTER => {
                self.last_notice = Some(now);
                Some(Notice::Degraded(elapsed))
            }
            Some(last) if now.duration_since(last) >= REPEAT_AFTER => {
                self.last_notice = Some(now);
                Some(Notice::StillDegraded(elapsed))
            }
            _ => None,
        }
    }

    pub(super) fn recover(&mut self, now: Instant) -> Option<Notice> {
        let elapsed = now.duration_since(self.since.take()?);
        self.last_notice.take().map(|_| Notice::Recovered(elapsed))
    }
}

impl Notice {
    pub(super) fn log(self, index: usize) {
        match self {
            Self::Degraded(elapsed) => Logger.info(format_args!(
                "dns upstream {index} degraded for {}ms; fallback/probes active",
                elapsed.as_millis()
            )),
            Self::StillDegraded(elapsed) => Logger.info(format_args!(
                "dns upstream {index} still degraded after {}ms; fallback/probes active",
                elapsed.as_millis()
            )),
            Self::Recovered(elapsed) => Logger.info(format_args!(
                "dns upstream {index} recovered after {}ms",
                elapsed.as_millis()
            )),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/common/dns/health.rs"]
mod tests;
