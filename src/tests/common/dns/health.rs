// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Deterministic debounce and paired recovery notices under repeated health flaps.

use super::*;

#[test]
fn rapid_flaps_remain_silent_and_do_not_accumulate() {
    let mut log = HealthLog::default();
    let start = Instant::now();
    for step in 0..1000 {
        let now = start + Duration::from_millis(step * 200);
        log.degrade(now);
        assert_eq!(log.poll(now + Duration::from_millis(99)), None);
        assert_eq!(log.recover(now + Duration::from_millis(100)), None);
    }
    assert_eq!(log.poll(start + Duration::from_secs(300)), None);
}

#[test]
fn persistent_failure_warns_once_then_every_minute_and_has_one_paired_recovery() {
    let mut log = HealthLog::default();
    let start = Instant::now();
    log.degrade(start);
    log.degrade(start + Duration::from_millis(900));
    assert_eq!(log.poll(start + Duration::from_millis(999)), None);
    assert_eq!(
        log.poll(start + Duration::from_secs(1)),
        Some(Notice::Degraded(Duration::from_secs(1)))
    );
    for seconds in 2..61 {
        log.degrade(start + Duration::from_secs(seconds));
        assert_eq!(log.poll(start + Duration::from_secs(seconds)), None);
    }
    assert_eq!(
        log.poll(start + Duration::from_secs(61)),
        Some(Notice::StillDegraded(Duration::from_secs(61)))
    );
    assert_eq!(
        log.recover(start + Duration::from_secs(62)),
        Some(Notice::Recovered(Duration::from_secs(62)))
    );
    assert_eq!(log.recover(start + Duration::from_secs(63)), None);
    log.degrade(start + Duration::from_secs(64));
    assert_eq!(log.recover(start + Duration::from_millis(64100)), None);
}
