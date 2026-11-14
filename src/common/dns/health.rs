// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Debounced health notices, independent of immediate DNS routing decisions.

use std::time::Duration;

use tokio::time::Instant;

use crate::common::Logger;

const ALERT_AFTER: Duration = Duration::from_secs(1);
const REPEAT_AFTER: Duration = Duration::from_secs(60);
pub(super) const POLL_INTERVAL: Duration = Duration::from_millis(250);

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
