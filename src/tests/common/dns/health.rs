// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Deterministic debounce and paired recovery notices under repeated health flaps.

use super::*;

#[test]
fn three_failures_degrade_and_real_success_restores_immediately() {
    let mut health = HealthState::default();
    let start = Instant::now();
    for n in 0..3 {
        let now = start + Duration::from_millis(n);
        health.business_failure(now, now);
        assert_eq!(health.unhealthy, n == 2);
    }
    assert!(health.needs_probe());
    health.business_success(start + Duration::from_millis(3));
    assert!(!health.unhealthy);
    assert!(!health.needs_probe());
    let now = start + Duration::from_millis(4);
    health.business_failure(now, now);
    assert!(!health.unhealthy, "success resets the failure streak");
}

#[test]
fn stale_probes_and_old_request_failures_cannot_override_new_business_evidence() {
    let mut health = HealthState::default();
    let start = Instant::now();
    let version = health.probe_version();
    health.business_success(start + Duration::from_millis(1));
    for _ in 0..3 {
        health.probe_result(
            version,
            ProbeOutcome::Failure,
            start + Duration::from_millis(2),
        );
        health.business_failure(start, start + Duration::from_millis(2));
    }
    assert!(!health.needs_probe());
    let version = health.probe_version();
    for n in 3..6 {
        let now = start + Duration::from_millis(n);
        health.business_failure(now, now);
    }
    assert!(health.unhealthy);
    health.probe_result(
        version,
        ProbeOutcome::Success,
        start + Duration::from_millis(6),
    );
    assert!(
        health.unhealthy,
        "old probe success cannot erase newer failures"
    );
}

#[test]
fn target_errors_neither_degrade_healthy_upstreams_nor_recover_bad_ones() {
    let mut health = HealthState::default();
    let now = Instant::now();
    for _ in 0..100 {
        health.probe_result(health.probe_version(), ProbeOutcome::TargetError, now);
    }
    assert!(!health.needs_probe());
    for _ in 0..3 {
        health.probe_result(health.probe_version(), ProbeOutcome::Failure, now);
    }
    assert!(health.unhealthy);
    health.probe_result(health.probe_version(), ProbeOutcome::TargetError, now);
    assert!(health.unhealthy);
    health.probe_result(health.probe_version(), ProbeOutcome::Success, now);
    assert!(!health.needs_probe());
}

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
