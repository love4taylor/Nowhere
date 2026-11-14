// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Cache aging, bounded storage, negative answers and optimistic refresh.

use super::*;

fn config() -> DnsConfig {
    DnsConfig::from_url(
        &url::Url::parse("portal://key@localhost:2000?dns=tls://1.1.1.1&dns-stale=5s").unwrap(),
    )
    .unwrap()
    .unwrap()
}

fn answer(ttl: u32) -> Message {
    let mut response = request("cache.test.", 0).into_response();
    response.metadata.authentic_data = true;
    response.answers.push(Record::from_rdata(
        Name::from_ascii("cache.test.").unwrap(),
        ttl,
        RData::A(A("192.0.2.1".parse().unwrap())),
    ));
    response
}

#[tokio::test(start_paused = true)]
async fn ttl_ages_stale_is_immediate_bounded_and_never_extends_on_hit() {
    let mut cache = Cache::default();
    cache.insert(b"key".to_vec(), &answer(2), &config());
    tokio::time::advance(Duration::from_secs(1)).await;
    let fresh = cache.get(b"key", Duration::from_millis(250)).unwrap();
    assert_eq!(fresh.response.answers[0].ttl, 1);
    assert!(!fresh.refresh);
    assert!(fresh.response.metadata.authentic_data);
    tokio::time::advance(Duration::from_secs(1)).await;
    let stale = cache.get(b"key", Duration::from_millis(250)).unwrap();
    assert!(stale.refresh);
    assert_eq!(stale.response.answers[0].ttl, 1);
    assert!(!stale.response.metadata.authentic_data);
    assert!(
        !cache
            .get(b"key", Duration::from_millis(250))
            .unwrap()
            .refresh
    );
    tokio::time::advance(Duration::from_secs(5)).await;
    assert!(cache.get(b"key", Duration::from_secs(1)).is_none());
}

#[tokio::test(start_paused = true)]
async fn negative_soa_minimum_expires_without_stale_and_zero_ttl_revokes_old_data() {
    let mut cache = Cache::default();
    let mut negative = request("cache.test.", 0).into_response();
    negative.metadata.response_code = ResponseCode::NXDomain;
    negative.authorities.push(Record::from_rdata(
        Name::root(),
        60,
        RData::SOA(SOA::new(Name::root(), Name::root(), 1, 60, 60, 3600, 2)),
    ));
    cache.insert(b"negative".to_vec(), &negative, &config());
    assert!(cache.get(b"negative", Duration::from_secs(1)).is_some());
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(cache.get(b"negative", Duration::from_secs(1)).is_none());
    cache.insert(b"zero".to_vec(), &answer(10), &config());
    cache.insert(b"zero".to_vec(), &answer(0), &config());
    assert!(cache.get(b"zero", Duration::from_secs(1)).is_none());
    negative.authorities.clear();
    cache.insert(b"no-soa".to_vec(), &negative, &config());
    assert!(cache.get(b"no-soa", Duration::from_secs(1)).is_none());
}

#[tokio::test]
async fn cache_evicts_by_count_and_bytes_and_never_caches_servfail() {
    let mut config = config();
    config.cache_size = 2;
    let mut cache = Cache::default();
    for key in [b"a", b"b", b"c"] {
        cache.insert(key.to_vec(), &answer(30), &config);
    }
    assert!(cache.get(b"a", Duration::from_secs(1)).is_none());
    assert!(cache.get(b"c", Duration::from_secs(1)).is_some());
    let mut bytes_config = config.clone();
    bytes_config.cache_size = 100;
    bytes_config.cache_bytes = 600;
    let mut bytes_cache = Cache::default();
    for key in [b"a", b"b", b"c"] {
        bytes_cache.insert(key.to_vec(), &answer(30), &bytes_config);
    }
    assert!(bytes_cache.get(b"a", Duration::from_secs(1)).is_none());
    assert!(bytes_cache.get(b"c", Duration::from_secs(1)).is_some());
    config.cache_bytes = 1;
    cache.insert(b"oversize".to_vec(), &answer(30), &config);
    assert!(cache.get(b"oversize", Duration::from_secs(1)).is_none());
    let mut failure = answer(30);
    failure.metadata.response_code = ResponseCode::ServFail;
    cache.insert(b"failed".to_vec(), &failure, &config);
    assert!(cache.get(b"failed", Duration::from_secs(1)).is_none());
}

#[tokio::test]
async fn encrypted_nxdomain_is_cached_without_using_fallback() {
    let primary = TestServer::new("https").await;
    let fallback = TestServer::new("quic").await;
    primary.mode.store(3, Ordering::Relaxed);
    let resolver = primary.resolver_with_fallback(Some(&fallback), &[]);
    for id in 1..=2 {
        let response = ask(&resolver, "negative.test.", id).await;
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(response.metadata.id, id);
        assert_eq!(response.authorities.len(), 1);
    }
    assert_eq!(primary.count.load(Ordering::Relaxed), 1);
    assert_eq!(fallback.count.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn concurrent_cache_misses_share_work_and_restore_each_clients_id_and_question() {
    let server = TestServer::new("https").await;
    server.delay.store(40, Ordering::Relaxed);
    let resolver = server.resolver(&[]);
    let mut tasks = JoinSet::new();
    for id in 1..=64 {
        let resolver = resolver.clone();
        tasks.spawn(async move {
            let name = if id % 2 == 0 {
                "CaChE.test."
            } else {
                "cache.test."
            };
            let response = ask(&resolver, name, id).await;
            assert_eq!(response.metadata.id, id);
            assert_eq!(response.queries[0].name().to_ascii(), name);
            assert_eq!(response.answers.len(), 1);
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    assert_eq!(server.count.load(Ordering::Relaxed), 1);
    assert!(resolver.flights.lock().unwrap().is_empty());
    assert_eq!(resolver.queries.available_permits(), 128);
}

#[tokio::test]
async fn optimistic_answer_does_not_wait_for_a_broken_upstream_and_refresh_is_deduplicated() {
    let server = TestServer::new("tls").await;
    server.ttl.store(1, Ordering::Relaxed);
    let resolver = server.resolver(&[("dns-timeout", "100ms"), ("dns-fallback-delay", "20ms")]);
    assert_eq!(ask(&resolver, "stale.test.", 1).await.answers.len(), 1);
    server.mode.store(1, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(1050)).await;
    let start = Instant::now();
    for id in 2..=30 {
        let response = ask(&resolver, "stale.test.", id).await;
        assert_eq!(response.metadata.id, id);
        assert_eq!(response.answers[0].ttl, 1);
        assert!(!response.metadata.authentic_data);
    }
    assert!(start.elapsed() < Duration::from_millis(50));
    assert!(resolver.flights.lock().unwrap().len() <= 1);
}
