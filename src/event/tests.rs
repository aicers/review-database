use std::collections::HashMap;

use jiff::Timestamp;
use review_protocol::types::EndpointRole::{Destination, Source};
use review_protocol::types::{
    Detail, DetectionEvent, DetectionModel, LabelDbMatchDetail, PrimarySubject, RawEventKind,
    Target, ThreatRole, UnusualDestinationPatternDetail,
};

use super::{
    DetectionEventStamp, Direction, EVENT_DELETION_BATCH_SIZE, EventDb, InvalidEvent,
    MAX_RAW_EVENT_KEYS, PutOutcome, RawEventKey, StoredDetectionEvent,
    fixture::{
        FakeCountryLookup, SENSOR, at, conn_body, conn_event, dns_body, host, http_body, ip,
        netflow5_body, netflow9_body, network_connect_body, raw_event_event, related, setup_store,
        setup_store_with_lookup, stamp, subject_event, time,
    },
};
use crate::{
    ModelInstance,
    test::acquire_db_permit,
    util::{COUNTRY_CODE_UNKNOWN, COUNTRY_CODE_UNRESOLVED},
};

fn event_at_nanos(nanos: i64) -> DetectionEvent {
    raw_event_event(
        at(nanos),
        SENSOR,
        conn_body(ip("192.0.2.1"), ip("198.51.100.1")),
    )
}

fn event_with_sensor(sensor: Option<&str>, time: Timestamp) -> DetectionEvent {
    let mut event = raw_event_event(time, SENSOR, conn_body(ip("192.0.2.1"), ip("198.51.100.1")));
    event.sensor = sensor.map(str::to_string);
    event
}

fn key_timestamp(key: i128) -> i64 {
    (key >> 64)
        .try_into()
        .expect("the upper half of an event key is an i64 timestamp")
}

fn records(db: &EventDb) -> Vec<(i128, StoredDetectionEvent)> {
    db.iter_forward().map(|item| item.unwrap()).collect()
}

fn codes(record: &StoredDetectionEvent) -> Vec<(std::net::IpAddr, [u8; 2])> {
    record.country_codes().collect()
}

#[test]
fn put_round_trips_a_raw_event_record_and_its_stamp() {
    let (_permit, store) = setup_store();
    let db = store.events();
    assert!(db.iter_forward().next().is_none());

    let event = conn_event("192.0.2.1", "198.51.100.1");
    let key = db.put(&event, &stamp()).unwrap();

    let stored = records(&db);
    assert_eq!(stored.len(), 1);
    let (stored_key, record) = &stored[0];
    assert_eq!(*stored_key, key);
    assert_eq!(record.event(), &event);
    assert_eq!(record.stamp(), &stamp());
    assert_eq!(
        codes(record),
        [
            (ip("192.0.2.1"), COUNTRY_CODE_UNRESOLVED),
            (ip("198.51.100.1"), COUNTRY_CODE_UNRESOLVED),
        ]
    );
    let (event_back, stamp_back) = record.clone().into_parts();
    assert_eq!(event_back, event);
    assert_eq!(stamp_back, stamp());
}

#[test]
fn put_round_trips_every_subject_shape() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let related_ips = vec![
        related("203.0.113.1", Source),
        related("2001:db8::2", Destination),
    ];
    let shapes = [
        host("192.0.2.9"),
        PrimarySubject::Cluster {
            clustering_model: 4,
            cluster_id: 17,
        },
        PrimarySubject::Sensor,
        PrimarySubject::Network {
            customer: 2,
            name: "office".to_string(),
            role: ThreatRole::Target,
        },
    ];
    let mut expected = Vec::new();
    for (offset, primary) in shapes.into_iter().enumerate() {
        let mut event = subject_event(primary, related_ips.clone());
        event.time = at(i64::try_from(offset).unwrap() + 1);
        let mut stamp = stamp();
        stamp.clustering_model_id = Some(u32::try_from(offset).unwrap());
        stamp.trained_at = None;
        stamp.installed_commit = None;
        db.put(&event, &stamp).unwrap();
        expected.push((event, stamp));
    }

    let stored = records(&db);
    assert_eq!(stored.len(), expected.len());
    for ((_, record), (event, stamp)) in stored.iter().zip(&expected) {
        assert_eq!(record.event(), event);
        assert_eq!(record.stamp(), stamp);
    }
    // A host subject's IP comes before the related IPs; the other shapes
    // have the related IPs only.
    assert_eq!(
        codes(&stored[0].1)
            .into_iter()
            .map(|(addr, _)| addr)
            .collect::<Vec<_>>(),
        [ip("192.0.2.9"), ip("203.0.113.1"), ip("2001:db8::2")]
    );
    for (_, record) in &stored[1..] {
        assert_eq!(
            codes(record)
                .into_iter()
                .map(|(addr, _)| addr)
                .collect::<Vec<_>>(),
            [ip("203.0.113.1"), ip("2001:db8::2")]
        );
    }
}

#[test]
fn put_attaches_country_codes_to_exactly_the_endpoint_addresses() {
    let lookup = FakeCountryLookup {
        codes: HashMap::from([
            (ip("192.0.2.1"), *b"US"),
            (ip("198.51.100.1"), *b"KR"),
            (ip("192.0.2.9"), *b"JP"),
            (ip("203.0.113.1"), *b"DE"),
        ]),
    };
    let (_permit, store) = setup_store_with_lookup(lookup);
    let db = store.events();

    // Body addresses.
    db.put(&conn_event("192.0.2.1", "198.51.100.1"), &stamp())
        .unwrap();
    // A host subject and its related IPs; an unknown address is `ZZ`.
    let mut subject = subject_event(
        host("192.0.2.9"),
        vec![
            related("203.0.113.1", Source),
            related("203.0.113.99", Destination),
        ],
    );
    subject.time = subject
        .time
        .checked_add(jiff::SignedDuration::from_secs(1))
        .unwrap();
    db.put(&subject, &stamp()).unwrap();
    // A Sysmon body names its addresses `source_ip` and `destination_ip`,
    // and a Netflow v5 body `src_addr` and `dst_addr`: neither has one.
    for (offset, body) in [
        network_connect_body(ip("192.0.2.1"), ip("198.51.100.1")),
        netflow5_body(ip("192.0.2.1"), ip("198.51.100.1")),
    ]
    .into_iter()
    .enumerate()
    {
        let time = time()
            .checked_add(jiff::SignedDuration::from_secs(
                i64::try_from(offset).unwrap() + 2,
            ))
            .unwrap();
        db.put(&raw_event_event(time, SENSOR, body), &stamp())
            .unwrap();
    }

    let stored = records(&db);
    assert_eq!(
        codes(&stored[0].1),
        [(ip("192.0.2.1"), *b"US"), (ip("198.51.100.1"), *b"KR")]
    );
    assert_eq!(
        codes(&stored[1].1),
        [
            (ip("192.0.2.9"), *b"JP"),
            (ip("203.0.113.1"), *b"DE"),
            (ip("203.0.113.99"), COUNTRY_CODE_UNKNOWN),
        ]
    );
    assert_eq!(codes(&stored[2].1), Vec::new());
    assert_eq!(codes(&stored[3].1), Vec::new());
}

#[test]
fn put_stores_every_call() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let event = conn_event("192.0.2.1", "198.51.100.1");

    let first = db.put(&event, &stamp()).unwrap();
    let second = db.put(&event, &stamp()).unwrap();

    assert_ne!(first, second);
    assert_eq!(db.raw_count(), 2);
    assert_eq!(first >> 32, second >> 32, "same time and model");
}

#[test]
fn put_does_not_validate_the_event() {
    let (_permit, store) = setup_store();
    let db = store.events();
    // The detail belongs to another model, and a raw event target has no
    // sensor: `validate` rejects both, storage takes both.
    let mut event = conn_event("192.0.2.1", "198.51.100.1");
    event.detail = Detail::LockyRansomware;
    event.sensor = None;
    assert!(event.validate().is_err());

    db.put(&event, &stamp()).unwrap();
    assert!(matches!(
        db.put_unless_stored(&event, &stamp()).unwrap(),
        PutOutcome::AlreadyStored
    ));
    assert_eq!(records(&db)[0].1.event(), &event);
}

/// The same event is stored once; another event of the same time and model,
/// or the same event at another time, is stored beside it.
#[test]
fn put_unless_stored_stores_an_event_once() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let event = conn_event("192.0.2.1", "198.51.100.1");

    let PutOutcome::Stored(key) = db.put_unless_stored(&event, &stamp()).unwrap() else {
        panic!("the first put stores the event");
    };
    assert_eq!(
        db.put_unless_stored(&event, &stamp()).unwrap(),
        PutOutcome::AlreadyStored
    );
    assert_eq!(db.raw_count(), 1);
    assert_eq!(records(&db)[0].0, key);

    let other = conn_event("192.0.2.2", "198.51.100.1");
    let PutOutcome::Stored(other_key) = db.put_unless_stored(&other, &stamp()).unwrap() else {
        panic!("an event with another body is stored");
    };
    assert_ne!(other_key, key);
    assert_eq!(
        db.put_unless_stored(&other, &stamp()).unwrap(),
        PutOutcome::AlreadyStored
    );

    let mut later = event.clone();
    later.time = later
        .time
        .checked_add(jiff::SignedDuration::from_secs(1))
        .unwrap();
    assert!(matches!(
        db.put_unless_stored(&later, &stamp()).unwrap(),
        PutOutcome::Stored(_)
    ));
    assert_eq!(db.raw_count(), 3);

    // An event `put` stored is recognized as well.
    let put_only = conn_event("192.0.2.3", "198.51.100.1");
    db.put(&put_only, &stamp()).unwrap();
    assert_eq!(
        db.put_unless_stored(&put_only, &stamp()).unwrap(),
        PutOutcome::AlreadyStored
    );
    assert_eq!(db.raw_count(), 4);
}

#[test]
fn put_unless_stored_ignores_the_receive_time_stamp_fields() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let event = conn_event("192.0.2.1", "198.51.100.1");
    assert!(matches!(
        db.put_unless_stored(&event, &stamp()).unwrap(),
        PutOutcome::Stored(_)
    ));

    let mut revision = stamp();
    revision.config_revision = Some(8);
    let mut version = stamp();
    version.installed_version = Some("2.0.0".to_string());
    version.installed_commit = None;
    let mut trained = stamp();
    trained.trained_at = None;
    for stamp in [revision, version, trained] {
        assert_eq!(
            db.put_unless_stored(&event, &stamp).unwrap(),
            PutOutcome::AlreadyStored
        );
    }
    assert_eq!(db.raw_count(), 1);
}

#[test]
fn put_unless_stored_ignores_country_codes() {
    let (_permit, store) = setup_store();
    store
        .events()
        .put(&conn_event("192.0.2.1", "198.51.100.1"), &stamp())
        .unwrap();
    let db = store
        .states
        .events(Some(std::sync::Arc::new(FakeCountryLookup {
            codes: HashMap::from([(ip("192.0.2.1"), *b"US")]),
        })));
    assert_eq!(
        db.put_unless_stored(&conn_event("192.0.2.1", "198.51.100.1"), &stamp())
            .unwrap(),
        PutOutcome::AlreadyStored
    );
    assert_eq!(db.raw_count(), 1);
}

#[test]
fn put_unless_stored_tells_apart_engine_instances_and_clustering_models() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let event = conn_event("192.0.2.1", "198.51.100.1");
    db.put_unless_stored(&event, &stamp()).unwrap();

    let mut instance = stamp();
    instance.engine_instance = ModelInstance {
        node_id: 2,
        agent_key: "semi-supervised".to_string(),
    };
    assert!(matches!(
        db.put_unless_stored(&event, &instance).unwrap(),
        PutOutcome::Stored(_)
    ));
    assert_eq!(db.raw_count(), 2);

    let mut clustering = stamp();
    clustering.clustering_model_id = Some(3);
    assert!(matches!(
        db.put_unless_stored(&event, &clustering).unwrap(),
        PutOutcome::Stored(_)
    ));
    assert_eq!(db.raw_count(), 3);

    for stamp in [stamp(), instance, clustering] {
        assert_eq!(
            db.put_unless_stored(&event, &stamp).unwrap(),
            PutOutcome::AlreadyStored
        );
    }
    assert_eq!(db.raw_count(), 3);
}

/// `-0.0` and `0.0` are equal scores, so the events holding them are the
/// same event.
#[test]
fn put_unless_stored_treats_negative_zero_as_zero() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let mut event = subject_event(host("192.0.2.9"), Vec::new());
    event.detection_model = DetectionModel::UnusualDestinationPattern;
    event.detail = Detail::UnusualDestinationPattern(UnusualDestinationPatternDetail {
        count: 3,
        expected_mean: -0.0,
        std_deviation: 0.0,
        z_score: -0.0,
        truncated_related_ips: 0,
    });
    event.score = -0.0;
    let mut positive = event.clone();
    positive.score = 0.0;
    positive.detail = Detail::UnusualDestinationPattern(UnusualDestinationPatternDetail {
        count: 3,
        expected_mean: 0.0,
        std_deviation: 0.0,
        z_score: 0.0,
        truncated_related_ips: 0,
    });
    assert_eq!(event, positive);

    assert!(matches!(
        db.put_unless_stored(&event, &stamp()).unwrap(),
        PutOutcome::Stored(_)
    ));
    assert_eq!(
        db.put_unless_stored(&positive, &stamp()).unwrap(),
        PutOutcome::AlreadyStored
    );
    assert_eq!(records(&db)[0].1.event(), &positive);
}

fn label_db_match_event(match_score: f32, rule_confidence: Option<f32>) -> DetectionEvent {
    let mut event = raw_event_event(
        time(),
        SENSOR,
        http_body(ip("192.0.2.1"), ip("198.51.100.1")),
    );
    event.detection_model = DetectionModel::LabelDbMatch;
    event.detail = Detail::LabelDbMatch(LabelDbMatchDetail {
        label_db: "synthetic-db".to_owned(),
        rule_id: 7,
        rule_name: "synthetic rule".to_owned(),
        matched_to: "/synthetic/path".to_owned(),
        cluster_id: 3,
        rule_confidence,
        match_score,
    });
    event
}

/// `-0.0` and `0.0` are equal `f32` values in a `LabelDbMatch` detail, so
/// the events holding them encode to the same bytes.
#[test]
fn label_db_match_negative_zeros_encode_as_zeros() {
    let negative = label_db_match_event(-0.0, None);
    let positive = label_db_match_event(0.0, None);
    assert_eq!(negative, positive);
    assert_eq!(
        super::record::encode_event(&negative).unwrap(),
        super::record::encode_event(&positive).unwrap()
    );

    let negative = label_db_match_event(0.5, Some(-0.0));
    let positive = label_db_match_event(0.5, Some(0.0));
    assert_eq!(negative, positive);
    assert_eq!(
        super::record::encode_event(&negative).unwrap(),
        super::record::encode_event(&positive).unwrap()
    );

    // A value other than a zero is kept as is.
    assert_ne!(
        super::record::encode_event(&label_db_match_event(0.5, Some(0.25))).unwrap(),
        super::record::encode_event(&label_db_match_event(0.5, Some(0.0))).unwrap()
    );

    let (_permit, store) = setup_store();
    let db = store.events();
    let negative = label_db_match_event(-0.0, Some(-0.0));
    let positive = label_db_match_event(0.0, Some(0.0));
    assert!(matches!(
        db.put_unless_stored(&negative, &stamp()).unwrap(),
        PutOutcome::Stored(_)
    ));
    assert_eq!(
        db.put_unless_stored(&positive, &stamp()).unwrap(),
        PutOutcome::AlreadyStored
    );
}

/// Concurrent calls for one event store it at most once, also when another
/// event already holds the first key of its time and model.
#[test]
fn put_unless_stored_stores_an_event_once_under_concurrency() {
    const CALLERS: usize = 8;

    let (_permit, store) = setup_store();
    store
        .events()
        .put(&conn_event("192.0.2.1", "198.51.100.1"), &stamp())
        .unwrap();
    let first_key = records(&store.events())[0].0;

    // Each round races on an event not stored yet, so that every round, not
    // only the first, exercises the race.
    for round in 0..10_u8 {
        let event = conn_event(&format!("192.0.2.{}", round + 2), "198.51.100.1");
        assert_eq!(
            super::event_key_base(&event),
            first_key,
            "the other event holds the first key of the time and model"
        );
        let barrier = std::sync::Barrier::new(CALLERS);
        let outcomes: Vec<PutOutcome> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..CALLERS)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        store.events().put_unless_stored(&event, &stamp()).unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PutOutcome::Stored(_)))
                .count(),
            1,
            "{outcomes:?}"
        );
        assert!(
            outcomes.iter().all(|outcome| matches!(
                outcome,
                PutOutcome::Stored(_) | PutOutcome::AlreadyStored
            )),
            "{outcomes:?}"
        );
        assert_eq!(store.events().raw_count(), usize::from(round) + 2);
    }
}

/// Concurrent calls for one event store it exactly once when no record holds
/// any key of its time and model yet.
#[test]
fn put_unless_stored_stores_an_event_once_under_concurrency_in_an_empty_bucket() {
    const CALLERS: usize = 8;

    let (_permit, store) = setup_store();

    // Each round races on its own time, so that every round starts with the
    // time-and-model bucket empty.
    for round in 0..10_u8 {
        let event = event_at_nanos(i64::from(round));
        let bucket = super::event_key_base(&event) >> 32;
        assert!(
            records(&store.events())
                .iter()
                .all(|(key, _)| key >> 32 != bucket),
            "the time and model of the round hold no record"
        );
        let barrier = std::sync::Barrier::new(CALLERS);
        let outcomes: Vec<PutOutcome> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..CALLERS)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        store.events().put_unless_stored(&event, &stamp()).unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let stored_keys: Vec<i128> = outcomes
            .iter()
            .filter_map(|outcome| match outcome {
                PutOutcome::Stored(key) => Some(*key),
                _ => None,
            })
            .collect();
        let [stored_key] = stored_keys[..] else {
            panic!("exactly one call stores the event: {outcomes:?}");
        };
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PutOutcome::AlreadyStored))
                .count(),
            CALLERS - 1,
            "{outcomes:?}"
        );

        let in_bucket: Vec<(i128, StoredDetectionEvent)> = records(&store.events())
            .into_iter()
            .filter(|(key, _)| key >> 32 == bucket)
            .collect();
        let [(key, record)] = &in_bucket[..] else {
            panic!("exactly one record in the bucket: {in_bucket:?}");
        };
        assert_eq!(*key, stored_key);
        assert_eq!(record.event(), &event);
        assert_eq!(record.stamp(), &stamp());
        assert_eq!(store.events().raw_count(), usize::from(round) + 1);
    }
}

#[test]
fn iteration_stops_on_corrupt_sst() {
    let _permit = acquire_db_permit();
    let dir = tempfile::tempdir().unwrap();
    let mut options = rocksdb::Options::default();
    options.create_if_missing(true);
    {
        let raw = rocksdb::OptimisticTransactionDB::open(&options, dir.path()).unwrap();
        let db = EventDb::new(&raw);
        for nanos in -3..0 {
            db.put(&event_at_nanos(nanos), &stamp()).unwrap();
        }
        for nanos in 0..20_000 {
            db.put(&event_at_nanos(nanos), &stamp()).unwrap();
        }
        let before = crate::test::sst_files(dir.path());
        raw.flush().unwrap();
        drop(raw);
        crate::test::corrupt_new_sst(dir.path(), &before);
    }
    let raw = rocksdb::OptimisticTransactionDB::open(&options, dir.path()).unwrap();
    let db = EventDb::new(&raw);
    let mut forward = db.iter_forward();
    for nanos in -3..0 {
        assert_eq!(key_timestamp(forward.next().unwrap().unwrap().0), nanos);
    }
    let error = loop {
        match forward.next().expect("corrupt block must be reached") {
            Ok((key, _)) => assert!(key_timestamp(key) >= 0),
            Err(error) => break error,
        }
    };
    assert!(
        matches!(error, InvalidEvent::Iteration(ref e) if e.kind() == rocksdb::ErrorKind::Corruption)
    );
    assert!(forward.next().is_none());

    let mut reverse = db.iter_reverse();
    let error = loop {
        match reverse.next().expect("corrupt block must be reached") {
            Ok((key, _)) => assert!(key_timestamp(key) >= 0),
            Err(error) => break error,
        }
    };
    assert!(
        matches!(error, InvalidEvent::Iteration(ref e) if e.kind() == rocksdb::ErrorKind::Corruption)
    );
    assert!(reverse.next().is_none());
}

#[test]
fn event_iterators_use_signed_chronological_order() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let timestamps = [i64::MIN, -1, 0, 1, i64::MAX];

    for nanos in [0, i64::MAX, -1, i64::MIN, 1] {
        db.put(&event_at_nanos(nanos), &stamp()).unwrap();
    }

    let forward: Vec<_> = db
        .iter_forward()
        .map(|item| key_timestamp(item.unwrap().0))
        .collect();
    assert_eq!(forward, timestamps);

    let reverse: Vec<_> = db
        .iter_reverse()
        .map(|item| key_timestamp(item.unwrap().0))
        .collect();
    assert_eq!(reverse, timestamps.into_iter().rev().collect::<Vec<_>>());
}

#[test]
fn iter_from_is_inclusive_and_crosses_only_the_later_sign_region() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let mut keys = HashMap::new();
    for nanos in [-5, -1, 0, 4] {
        keys.insert(nanos, db.put(&event_at_nanos(nanos), &stamp()).unwrap());
    }
    let from = |nanos: i64, direction| -> Vec<i64> {
        db.iter_from(keys[&nanos], direction)
            .map(|item| key_timestamp(item.unwrap().0))
            .collect()
    };

    assert_eq!(from(-5, Direction::Forward), [-5, -1, 0, 4]);
    assert_eq!(from(4, Direction::Reverse), [4, 0, -1, -5]);
    assert_eq!(from(0, Direction::Forward), [0, 4]);
    assert_eq!(from(-1, Direction::Reverse), [-1, -5]);

    let missing_negative = i128::from(-3_i64) << 64;
    let forward: Vec<_> = db
        .iter_from(missing_negative, Direction::Forward)
        .map(|item| key_timestamp(item.unwrap().0))
        .collect();
    assert_eq!(forward, [-1, 0, 4]);

    let missing_positive = i128::from(2_i64) << 64;
    let reverse: Vec<_> = db
        .iter_from(missing_positive, Direction::Reverse)
        .map(|item| key_timestamp(item.unwrap().0))
        .collect();
    assert_eq!(reverse, [0, -1, -5]);
}

#[test]
fn iterator_preserves_key_order_with_equal_timestamps() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let event = event_at_nanos(-1);
    let mut other_model = event.clone();
    other_model.detection_model = DetectionModel::LockyRansomware;
    other_model.detail = Detail::LockyRansomware;
    let mut inserted = Vec::new();

    for event in [&other_model, &event, &event] {
        inserted.push(db.put(event, &stamp()).unwrap());
    }
    inserted.sort_unstable();

    let forward: Vec<_> = db.iter_forward().map(|item| item.unwrap().0).collect();
    assert_eq!(forward, inserted);
    let reverse: Vec<_> = db.iter_reverse().map(|item| item.unwrap().0).collect();
    assert_eq!(reverse, inserted.into_iter().rev().collect::<Vec<_>>());
    assert!(forward.iter().all(|key| key_timestamp(*key) == -1));
}

#[test]
fn event_iterator_uses_one_snapshot_across_sign_regions() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let negative_key = db.put(&event_at_nanos(-1), &stamp()).unwrap();
    let non_negative_key = db.put(&event_at_nanos(1), &stamp()).unwrap();
    let mut iter = db.iter_forward();

    assert_eq!(iter.next().unwrap().unwrap().0, negative_key);

    let added_key = db.put(&event_at_nanos(2), &stamp()).unwrap();
    db.inner.delete(non_negative_key.to_be_bytes()).unwrap();

    assert_eq!(
        iter.map(|item| item.unwrap().0).collect::<Vec<_>>(),
        [non_negative_key]
    );
    assert_eq!(
        db.iter_forward()
            .map(|item| item.unwrap().0)
            .collect::<Vec<_>>(),
        [negative_key, added_key]
    );
}

#[test]
fn iterator_skips_unknown_detection_models() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let valid = db.put(&event_at_nanos(2_000_000_000), &stamp()).unwrap();
    let value = db.inner.get(valid.to_be_bytes()).unwrap().unwrap();

    // Model 20 is the first number review-protocol has not assigned.
    for model in [20_i128, 9999, i128::from(u32::MAX)] {
        let key = (1_000_000_000_i128 << 64) | (model << 32);
        db.put_raw(&key.to_be_bytes(), &value);
    }

    let keys: Vec<_> = db.iter_forward().map(|item| item.unwrap().0).collect();
    assert_eq!(keys, [valid]);
    let keys: Vec<_> = db.iter_reverse().map(|item| item.unwrap().0).collect();
    assert_eq!(keys, [valid]);
}

#[test]
fn iterator_returns_none_when_only_unknown_detection_models() {
    let (_permit, store) = setup_store();
    let db = store.events();
    for model in [9999_i128, 10000, 10001] {
        let key = (1_000_000_000_i128 << 64) | (model << 32);
        db.put_raw(&key.to_be_bytes(), b"dummy");
    }
    assert!(db.iter_forward().next().is_none());
}

#[test]
fn iterator_errors_on_malformed_key_and_value() {
    let (_permit, store) = setup_store();
    let db = store.events();
    db.put_raw(&[0xAB; 8], b"dummy");
    assert!(matches!(
        db.iter_forward().next(),
        Some(Err(InvalidEvent::Key(_)))
    ));

    let (_permit, store) = setup_store();
    let db = store.events();
    let key = (1_000_000_000_i128 << 64) | (i128::from(u32::from(DetectionModel::PortScan)) << 32);
    db.put_raw(&key.to_be_bytes(), b"dummy");
    assert!(matches!(
        db.iter_forward().next(),
        Some(Err(InvalidEvent::Value(_)))
    ));
}

#[test]
fn remove_before_deletes_old_events() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let old = event_with_sensor(Some(SENSOR), crate::test::utc(2020, 1, 1, 0, 0, 0));
    let recent = event_with_sensor(Some(SENSOR), crate::test::utc(2025, 6, 1, 0, 0, 0));
    db.put(&old, &stamp()).unwrap();
    db.put(&recent, &stamp()).unwrap();
    assert_eq!(db.iter_forward().count(), 2);

    let deleted = db
        .remove_before(crate::test::utc(2024, 1, 1, 0, 0, 0))
        .unwrap();
    assert_eq!(deleted, 1);
    let remaining = records(&db);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].1.event(), &recent);
}

#[test]
fn remove_before_empty_db_and_past_cutoff_delete_nothing() {
    let (_permit, store) = setup_store();
    let db = store.events();
    assert_eq!(db.remove_before(Timestamp::now()).unwrap(), 0);

    db.put(&event_at_nanos(1), &stamp()).unwrap();
    assert_eq!(db.remove_before(at(0)).unwrap(), 0);
    assert_eq!(db.iter_forward().count(), 1);
}

#[test]
fn remove_before_obeys_strict_signed_timestamp_boundaries() {
    let cases = [
        (i64::MIN, Vec::new()),
        (-1, vec![i64::MIN]),
        (0, vec![i64::MIN, -1]),
        (1, vec![i64::MIN, -1, 0]),
        (i64::MAX, vec![i64::MIN, -1, 0, 1]),
    ];

    for (cutoff, expected_deleted) in cases {
        let (_permit, store) = setup_store();
        let db = store.events();
        for nanos in [i64::MAX, 0, i64::MIN, 1, -1] {
            db.put(&event_at_nanos(nanos), &stamp()).unwrap();
        }

        assert_eq!(
            db.remove_before(at(cutoff)).unwrap(),
            u64::try_from(expected_deleted.len()).unwrap()
        );
        let remaining: Vec<_> = db
            .iter_forward()
            .map(|item| key_timestamp(item.unwrap().0))
            .collect();
        let expected_remaining: Vec<_> = [i64::MIN, -1, 0, 1, i64::MAX]
            .into_iter()
            .filter(|nanos| !expected_deleted.contains(nanos))
            .collect();
        assert_eq!(remaining, expected_remaining);
    }
}

#[test]
fn remove_before_out_of_range_cutoffs_delete_none_or_all() {
    let (_permit, store) = setup_store();
    let db = store.events();
    db.put(&event_at_nanos(0), &stamp()).unwrap();
    db.put(&event_at_nanos(i64::MAX), &stamp()).unwrap();

    let far_past =
        Timestamp::from_nanosecond(i128::from(i64::MIN) - 1).expect("valid jiff timestamp");
    assert_eq!(db.remove_before(far_past).unwrap(), 0);
    assert_eq!(db.iter_forward().count(), 2);

    let far_future =
        Timestamp::from_nanosecond(i128::from(i64::MAX) + 1).expect("valid jiff timestamp");
    assert_eq!(db.remove_before(far_future).unwrap(), 2);
    assert_eq!(db.iter_forward().count(), 0);
}

#[test]
fn remove_before_multiple_batches() {
    let (_permit, store) = setup_store();
    let db = store.events();

    // More than one batch in both physical regions, so each region has a
    // full-batch flush and a remainder batch.
    let events_per_region = EVENT_DELETION_BATCH_SIZE + 1;
    for i in 0..events_per_region {
        let offset = i64::try_from(i).expect("small value");
        for nanos in [-offset - 1, offset] {
            db.put(&event_at_nanos(nanos), &stamp()).unwrap();
        }
    }

    let total = events_per_region * 2;
    assert_eq!(db.iter_forward().count(), total);

    let cutoff = at(i64::try_from(events_per_region).expect("small value"));
    let deleted = db.remove_before(cutoff).unwrap();
    assert_eq!(deleted, u64::try_from(total).unwrap());
    assert_eq!(db.iter_forward().count(), 0);
}

fn sensors_of(db: &EventDb) -> Vec<Option<String>> {
    records(db)
        .into_iter()
        .map(|(_, record)| record.event().sensor.clone())
        .collect()
}

#[test]
fn remove_by_sensors_deletes_listed_sensors_and_keeps_no_sensor() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let base = crate::test::utc(2025, 1, 1, 0, 0, 0);
    let after = |secs| {
        base.checked_add(jiff::SignedDuration::from_secs(secs))
            .unwrap()
    };

    db.put(&event_with_sensor(Some("target.example"), base), &stamp())
        .unwrap();
    db.put(
        &event_with_sensor(Some("other-target.example"), after(1)),
        &stamp(),
    )
    .unwrap();
    db.put(&event_with_sensor(Some("keep.example"), after(2)), &stamp())
        .unwrap();
    db.put(&event_with_sensor(None, after(3)), &stamp())
        .unwrap();
    let mut subject = subject_event(host("192.0.2.9"), Vec::new());
    subject.sensor = Some("target.example".to_string());
    subject.time = after(4);
    db.put(&subject, &stamp()).unwrap();

    db.remove_by_sensors(&[
        "target.example".to_string(),
        "target.example".to_string(),
        "other-target.example".to_string(),
    ])
    .unwrap();
    assert_eq!(sensors_of(&db), [Some("keep.example".to_string()), None]);

    db.remove_by_sensors(&[]).unwrap();
    assert_eq!(db.iter_forward().count(), 2);
}

#[test]
fn remove_by_sensors_requires_exact_sensor_match() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let base = crate::test::utc(2025, 1, 1, 0, 0, 0);

    db.put(&event_with_sensor(Some("target.example"), base), &stamp())
        .unwrap();
    db.put(
        &event_with_sensor(
            Some("target.example.extra"),
            base.checked_add(jiff::SignedDuration::from_secs(1))
                .unwrap(),
        ),
        &stamp(),
    )
    .unwrap();

    db.remove_by_sensors(&["target.example".to_string()])
        .unwrap();
    assert_eq!(sensors_of(&db), [Some("target.example.extra".to_string())]);
}

#[test]
fn remove_by_sensors_writes_all_batches() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let base = crate::test::utc(2025, 1, 1, 0, 0, 0);
    let total = 1_001;

    for offset in 0..total {
        db.put(
            &event_with_sensor(
                Some("target.example"),
                base.checked_add(jiff::SignedDuration::from_secs(offset))
                    .unwrap(),
            ),
            &stamp(),
        )
        .unwrap();
    }
    db.put(
        &event_with_sensor(
            Some("keep.example"),
            base.checked_add(jiff::SignedDuration::from_secs(total))
                .unwrap(),
        ),
        &stamp(),
    )
    .unwrap();

    db.remove_by_sensors(&["target.example".to_string()])
        .unwrap();
    assert_eq!(sensors_of(&db), [Some("keep.example".to_string())]);
}

#[test]
fn remove_by_sensors_rejects_invalid_keys_and_values() {
    let sensors = ["target.example".to_string()];

    let (_permit, store) = setup_store();
    let db = store.events();
    db.put_raw(&[0xAB; 8], b"invalid");
    assert!(db.remove_by_sensors(&sensors).is_err());

    let (_permit, store) = setup_store();
    let db = store.events();
    let key = i128::from(1_000_000_000) << 64;
    db.put_raw(&key.to_be_bytes(), b"invalid");
    assert!(db.remove_by_sensors(&sensors).is_err());
}

fn raw_key(kind: RawEventKind, sensor: &str, time: Timestamp) -> RawEventKey {
    RawEventKey {
        raw_event_kind: kind,
        sensor: sensor.to_string(),
        time,
    }
}

/// Returns what a full scan selects for `key`, the oracle of the lookup.
fn scan_for(db: &EventDb, key: &RawEventKey) -> Vec<(i128, StoredDetectionEvent)> {
    records(db)
        .into_iter()
        .filter(|(_, record)| {
            let event = record.event();
            event.time == key.time
                && event.raw_event_kind == key.raw_event_kind
                && event.sensor.as_deref() == Some(key.sensor.as_str())
                && matches!(&event.target, Target::RawEvent { time, .. } if *time == key.time)
        })
        .collect()
}

fn with_model(mut event: DetectionEvent, model: DetectionModel) -> DetectionEvent {
    event.detection_model = model;
    event.detail = match model {
        DetectionModel::LockyRansomware => Detail::LockyRansomware,
        DetectionModel::TorExitNode => Detail::TorExitNode,
        DetectionModel::SuspiciousTlsTraffic => Detail::SuspiciousTlsTraffic,
        _ => Detail::NonBrowser,
    };
    event
}

/// Stores, around one conn raw event, the records the lookup must tell
/// apart, and returns the keys of the records about that raw event.
fn put_lookup_neighbors(db: &EventDb, time: Timestamp) -> Vec<i128> {
    let body = conn_body(ip("192.0.2.1"), ip("198.51.100.1"));
    let mut about = Vec::new();
    for model in [
        DetectionModel::NonBrowser,
        DetectionModel::TorExitNode,
        DetectionModel::LockyRansomware,
    ] {
        let event = with_model(raw_event_event(time, SENSOR, body.clone()), model);
        about.push(db.put(&event, &stamp()).unwrap());
    }
    // Same time, another kind.
    db.put(
        &raw_event_event(time, SENSOR, dns_body(ip("192.0.2.1"), ip("198.51.100.1"))),
        &stamp(),
    )
    .unwrap();
    // Same time and kind, another sensor, and no sensor.
    db.put(&raw_event_event(time, "sensor-2", body.clone()), &stamp())
        .unwrap();
    let mut no_sensor = raw_event_event(time, SENSOR, body.clone());
    no_sensor.sensor = None;
    db.put(&no_sensor, &stamp()).unwrap();
    // A subject record of the same time, kind and sensor.
    let mut subject = subject_event(host("192.0.2.1"), Vec::new());
    subject.time = time;
    db.put(&subject, &stamp()).unwrap();
    // The neighboring nanoseconds.
    for nanos in [-1, 1] {
        let near = time
            .checked_add(jiff::SignedDuration::from_nanos(nanos))
            .unwrap();
        db.put(&raw_event_event(near, SENSOR, body.clone()), &stamp())
            .unwrap();
    }
    about.sort_unstable();
    about
}

#[test]
fn lookup_returns_every_model_for_one_raw_event_and_nothing_else() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let about = put_lookup_neighbors(&db, time());

    let key = raw_key(RawEventKind::Conn, SENSOR, time());
    let found = db
        .find_by_raw_event_keys(std::slice::from_ref(&key))
        .unwrap();
    assert_eq!(found.len(), 1);
    let keys: Vec<_> = found[0].iter().map(|(key, _)| *key).collect();
    assert_eq!(keys, about);
    let models: Vec<_> = found[0]
        .iter()
        .map(|(_, record)| record.event().detection_model)
        .collect();
    assert!(models.contains(&DetectionModel::NonBrowser));
    assert!(models.contains(&DetectionModel::TorExitNode));
    assert!(models.contains(&DetectionModel::LockyRansomware));
    assert_eq!(found[0], scan_for(&db, &key));
}

#[test]
fn lookup_gives_each_key_its_own_list_in_input_order() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let first_time = time();
    let second_time = first_time
        .checked_add(jiff::SignedDuration::from_secs(10))
        .unwrap();
    put_lookup_neighbors(&db, first_time);
    put_lookup_neighbors(&db, second_time);

    let keys = [
        raw_key(RawEventKind::Conn, SENSOR, second_time),
        raw_key(RawEventKind::Dns, SENSOR, first_time),
        raw_key(RawEventKind::Conn, "sensor-2", first_time),
        raw_key(RawEventKind::Http, SENSOR, first_time),
        raw_key(RawEventKind::Conn, SENSOR, first_time),
        raw_key(RawEventKind::Conn, SENSOR, second_time),
    ];
    let found = db.find_by_raw_event_keys(&keys).unwrap();
    assert_eq!(found.len(), keys.len());
    let lengths: Vec<_> = found.iter().map(Vec::len).collect();
    assert_eq!(lengths, [3, 1, 1, 0, 3, 3]);
    for (list, key) in found.iter().zip(&keys) {
        assert_eq!(*list, scan_for(&db, key));
    }
    assert_eq!(found[0], found[5]);
}

#[test]
fn lookup_reads_pre_epoch_nanoseconds() {
    // The last nanosecond before the epoch has an all-`0xff` time prefix:
    // its keys are the last ones, and the next nanosecond's sort first.
    for nanos in [-1_i64, -132_924_303_876_543_211, i64::MIN, 0, i64::MAX] {
        let (_permit, store) = setup_store();
        let db = store.events();
        let time = at(nanos);
        let about = put_lookup_neighbors_in_range(&db, time);

        let key = raw_key(RawEventKind::Conn, SENSOR, time);
        let found = db
            .find_by_raw_event_keys(std::slice::from_ref(&key))
            .unwrap();
        let keys: Vec<_> = found[0].iter().map(|(key, _)| *key).collect();
        assert_eq!(keys, about, "{nanos}");
        assert_eq!(found[0], scan_for(&db, &key), "{nanos}");
    }
}

/// [`put_lookup_neighbors`], without the neighbors outside the `i64`
/// nanosecond range.
fn put_lookup_neighbors_in_range(db: &EventDb, time: Timestamp) -> Vec<i128> {
    let body = conn_body(ip("192.0.2.1"), ip("198.51.100.1"));
    let mut about = Vec::new();
    for model in [DetectionModel::NonBrowser, DetectionModel::TorExitNode] {
        let event = with_model(raw_event_event(time, SENSOR, body.clone()), model);
        about.push(db.put(&event, &stamp()).unwrap());
    }
    db.put(&raw_event_event(time, "sensor-2", body.clone()), &stamp())
        .unwrap();
    for nanos in [-1, 1] {
        let Some(near) = time
            .checked_add(jiff::SignedDuration::from_nanos(nanos))
            .ok()
            .filter(|near| crate::timestamp::to_i64_nanos(*near).is_ok())
        else {
            continue;
        };
        db.put(&raw_event_event(near, SENSOR, body.clone()), &stamp())
            .unwrap();
    }
    about.sort_unstable();
    about
}

#[test]
fn lookup_accepts_up_to_the_maximum_number_of_keys() {
    let (_permit, store) = setup_store();
    let db = store.events();
    db.put(&conn_event("192.0.2.1", "198.51.100.1"), &stamp())
        .unwrap();

    assert_eq!(db.find_by_raw_event_keys(&[]).unwrap().len(), 0);

    let key = raw_key(RawEventKind::Conn, SENSOR, time());
    let keys = vec![key; MAX_RAW_EVENT_KEYS];
    let found = db.find_by_raw_event_keys(&keys).unwrap();
    assert_eq!(found.len(), MAX_RAW_EVENT_KEYS);
    assert!(found.iter().all(|list| list.len() == 1));

    let keys = vec![raw_key(RawEventKind::Conn, SENSOR, time()); MAX_RAW_EVENT_KEYS + 1];
    assert_eq!(MAX_RAW_EVENT_KEYS + 1, 1001);
    assert!(db.find_by_raw_event_keys(&keys).is_err());
}

#[test]
fn lookup_skips_unknown_detection_models() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let event = conn_event("192.0.2.1", "198.51.100.1");
    let valid = db.put(&event, &stamp()).unwrap();
    let value = db.inner.get(valid.to_be_bytes()).unwrap().unwrap();
    let unknown = (valid & !(0xffff_ffff_i128 << 32)) | (9999_i128 << 32);
    db.put_raw(&unknown.to_be_bytes(), &value);

    let found = db
        .find_by_raw_event_keys(&[raw_key(RawEventKind::Conn, SENSOR, time())])
        .unwrap();
    assert_eq!(
        found[0].iter().map(|(key, _)| *key).collect::<Vec<_>>(),
        [valid]
    );
}

#[test]
fn lookup_matches_other_bodies_with_and_without_endpoints() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let time = time();
    for body in [
        http_body(ip("192.0.2.1"), ip("198.51.100.1")),
        netflow9_body(ip("192.0.2.1"), ip("198.51.100.1")),
        network_connect_body(ip("192.0.2.1"), ip("198.51.100.1")),
    ] {
        db.put(&raw_event_event(time, SENSOR, body), &stamp())
            .unwrap();
    }
    let keys = [
        raw_key(RawEventKind::Http, SENSOR, time),
        raw_key(RawEventKind::Netflow9, SENSOR, time),
        raw_key(RawEventKind::NetworkConnect, SENSOR, time),
    ];
    let found = db.find_by_raw_event_keys(&keys).unwrap();
    for (list, key) in found.iter().zip(&keys) {
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].1.event().raw_event_kind, key.raw_event_kind);
    }
}

/// The stamp is stored verbatim, including a `trained_at` outside the `i64`
/// nanosecond range and empty optional fields.
#[test]
fn put_stores_the_stamp_verbatim() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let far = Timestamp::from_nanosecond(i128::from(i64::MAX) + 1).expect("valid jiff timestamp");
    let stamps = [
        DetectionEventStamp {
            trained_at: Some(far),
            ..stamp()
        },
        DetectionEventStamp {
            engine_instance: ModelInstance {
                node_id: u32::MAX,
                agent_key: String::new(),
            },
            clustering_model_id: Some(u32::MAX),
            trained_at: None,
            installed_version: None,
            installed_commit: None,
            config_revision: None,
        },
    ];
    for (offset, stamp) in stamps.iter().enumerate() {
        db.put(&event_at_nanos(i64::try_from(offset).unwrap()), stamp)
            .unwrap();
    }
    let stored: Vec<_> = records(&db)
        .into_iter()
        .map(|(_, record)| record.stamp().clone())
        .collect();
    assert_eq!(stored, stamps);
}
