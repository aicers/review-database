use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicI64, AtomicUsize, Ordering},
        mpsc,
    },
};

use jiff::{SignedDuration, Timestamp};
use review_protocol::types::WindowOutlierDetail;
use review_protocol::types::{Detail, DetectionEvent, DetectionModel, RawEventKind};

use super::{ArrivalHookPoint, ArrivalKey, ArrivalKeyLengthError, ArrivalPage, next_arrival};
use crate::{
    Store,
    event::{
        EventDb, EventFilter, NO_FREE_KEY, PutOutcome, StoredDetectionEvent,
        TimeSeriesPolicySensors,
        fixture::{
            SENSOR, conn_body, host, ip, raw_event_event, setup_store, stamp, subject_event, time,
        },
    },
    tables::DETECTION_EVENT_ARRIVAL,
    test::{acquire_db_permit, capture_warnings},
};

/// 2027-01-15T08:00:00Z, in epoch nanoseconds: the time the tests' clock
/// starts at.
const T0: i64 = 1_800_000_000_000_000_000;
const SECOND: i64 = 1_000_000_000;
/// A scan cap no test reaches.
const NO_CAP: usize = 1_000;

/// Makes the writes of `store` read the time from the returned value, which
/// the test moves by hand, starting at `start`.
fn manual_clock(store: &Store, start: i64) -> Arc<AtomicI64> {
    let now = Arc::new(AtomicI64::new(start));
    let clock = Arc::clone(&now);
    store
        .states
        .arrival()
        .set_clock(Arc::new(move || -> anyhow::Result<i64> {
            Ok(clock.load(Ordering::SeqCst))
        }));
    now
}

/// Returns the rows of the arrival index, in key order.
fn index_rows(db: &EventDb) -> Vec<ArrivalKey> {
    let cf = db.inner.cf_handle(DETECTION_EVENT_ARRIVAL).unwrap();
    db.inner
        .iterator_cf(cf, rocksdb::IteratorMode::Start)
        .map(|row| ArrivalKey::try_from(&*row.unwrap().0).unwrap())
        .collect()
}

fn index_event_keys(db: &EventDb) -> Vec<i128> {
    index_rows(db).iter().map(ArrivalKey::event_key).collect()
}

fn record_keys(db: &EventDb) -> Vec<i128> {
    db.iter_forward().map(|item| item.unwrap().0).collect()
}

/// A filter with no condition.
fn all() -> EventFilter {
    EventFilter::new(
        None, None, None, None, None, None, None, None, None, None, None, None, None,
    )
}

/// A filter selecting the events of `sensors`, header-less time-series events
/// through `policies`.
fn of_sensors(sensors: &[&str], policies: TimeSeriesPolicySensors) -> EventFilter {
    EventFilter::new(
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some((sensors.iter().map(ToString::to_string).collect(), policies)),
        None,
        None,
        None,
    )
}

fn event_keys(page: &ArrivalPage) -> Vec<i128> {
    page.events.iter().map(|(key, _)| *key).collect()
}

/// A `Conn` event of `sensor` at `time`, one second apart for each
/// `offset`.
fn sensor_event(sensor: &str, offset: i64) -> DetectionEvent {
    raw_event_event(
        after(time(), offset),
        sensor,
        conn_body(ip("192.0.2.1"), ip("198.51.100.1")),
    )
}

fn after(time: Timestamp, seconds: i64) -> Timestamp {
    time.checked_add(SignedDuration::from_secs(seconds))
        .unwrap()
}

/// A `WindowOutlier` event of the time series `time_series_id` with no
/// header sensor.
fn sensorless_series_event(time_series_id: &str) -> DetectionEvent {
    let mut event = subject_event(host("192.0.2.1"), Vec::new());
    event.sensor = None;
    event.detection_model = DetectionModel::WindowOutlier;
    event.raw_event_kind = RawEventKind::Tls;
    event.detail = Detail::WindowOutlier(WindowOutlierDetail {
        time_series_id: time_series_id.to_string(),
        window_start: time(),
        nearest_cluster_id: 1,
        distance: 2.0,
        top_slots: Vec::new(),
        truncated: 0,
        pcap_truncated: None,
    });
    event
}

#[test]
fn an_arrival_key_round_trips_its_24_bytes() {
    let key = ArrivalKey::new(T0, -(7_i128 << 64) | 3);
    let bytes = key.to_bytes();
    assert_eq!(&bytes[..8], &T0.to_be_bytes());
    assert_eq!(&bytes[8..], &(-(7_i128 << 64) | 3).to_be_bytes());
    assert_eq!(ArrivalKey::from(bytes), key);
    assert_eq!(ArrivalKey::try_from(&bytes[..]), Ok(key));
    assert_eq!(<[u8; 24]>::from(key), bytes);
    assert_eq!(
        ArrivalKey::try_from(&bytes[..23]),
        Err(ArrivalKeyLengthError(23))
    );
}

#[test]
fn arrival_times_increase_and_stay_non_negative() {
    assert_eq!(next_arrival(T0, None).unwrap(), T0);
    assert_eq!(next_arrival(-5, None).unwrap(), 0);
    assert_eq!(next_arrival(T0, Some(T0 - 1)).unwrap(), T0);
    assert_eq!(next_arrival(T0, Some(T0)).unwrap(), T0 + 1);
    assert_eq!(next_arrival(T0 - SECOND, Some(T0)).unwrap(), T0 + 1);
    assert!(next_arrival(T0, Some(i64::MAX)).is_err());
}

#[test]
fn put_writes_one_index_row_per_record() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let event = sensor_event(SENSOR, 0);
    let first = db.put(&event, &stamp()).unwrap();
    let second = store.events().put(&event, &stamp()).unwrap();
    assert_ne!(first, second);

    let rows = index_rows(&db);
    assert_eq!(index_event_keys(&db), [first, second]);
    assert!(rows[0].arrival() < rows[1].arrival());
}

#[test]
fn put_unless_stored_writes_a_row_only_when_it_stores() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let event = sensor_event(SENSOR, 0);
    let PutOutcome::Stored(first) = db.put_unless_stored(&event, &stamp()).unwrap() else {
        panic!("the event is not stored yet");
    };
    assert_eq!(
        db.put_unless_stored(&event, &stamp()).unwrap(),
        PutOutcome::AlreadyStored
    );
    assert_eq!(index_event_keys(&db), [first]);

    // The same event bytes from another clustering model are another event.
    let mut other_model = stamp();
    other_model.clustering_model_id = Some(3);
    let PutOutcome::Stored(second) = db.put_unless_stored(&event, &other_model).unwrap() else {
        panic!("another clustering model's event is not stored yet");
    };
    assert_ne!(first, second);
    assert_eq!(record_keys(&db).len(), 2);
    assert_eq!(index_event_keys(&db), [first, second]);

    // A rejected event, and an event `put` cannot store, write no row.
    NO_FREE_KEY.set(true);
    let rejected = db.put_unless_stored(&sensor_event(SENSOR, 1), &stamp());
    let failed = db.put(&sensor_event(SENSOR, 2), &stamp());
    NO_FREE_KEY.set(false);
    assert!(matches!(rejected.unwrap(), PutOutcome::Rejected(_)));
    assert!(failed.is_err());
    assert_eq!(record_keys(&db).len(), 2);
    assert_eq!(index_event_keys(&db), [first, second]);
}

/// An event stored late, with a time two days before the others, is read
/// after the events that arrived before it, and a read from the cursor
/// returned reads only what arrived after it.
#[test]
fn the_read_follows_arrival_order_and_goes_on_from_its_cursor() {
    let (_permit, store) = setup_store();
    let now = manual_clock(&store, T0);
    let db = store.events();
    let early = db.put(&sensor_event(SENSOR, 0), &stamp()).unwrap();
    now.fetch_add(SECOND, Ordering::SeqCst);
    let next = db.put(&sensor_event(SENSOR, 1), &stamp()).unwrap();
    now.fetch_add(SECOND, Ordering::SeqCst);
    let late = db
        .put(&sensor_event(SENSOR, -2 * 24 * 3600), &stamp())
        .unwrap();
    // In key order the late event comes first.
    assert_eq!(record_keys(&db), [late, early, next]);

    let page = db.read_by_arrival(&all(), None, 10, NO_CAP).unwrap();
    assert_eq!(event_keys(&page), [early, next, late]);
    assert_eq!(
        page.last_scanned,
        Some(ArrivalKey::new(T0 + 2 * SECOND, late))
    );
    assert!(!page.has_more);

    now.fetch_add(SECOND, Ordering::SeqCst);
    let newer = db.put(&sensor_event(SENSOR, 2), &stamp()).unwrap();
    let page = db
        .read_by_arrival(&all(), page.last_scanned, 10, NO_CAP)
        .unwrap();
    assert_eq!(event_keys(&page), [newer]);
    assert!(!page.has_more);
    let records: Vec<(i128, StoredDetectionEvent)> =
        db.iter_forward().map(Result::unwrap).collect();
    assert_eq!(
        page.events,
        records
            .into_iter()
            .filter(|(key, _)| *key == newer)
            .collect::<Vec<_>>()
    );

    let page = db
        .read_by_arrival(&all(), page.last_scanned, 10, NO_CAP)
        .unwrap();
    assert_eq!(page.events, Vec::new());
    assert_eq!(page.last_scanned, None);
    assert!(!page.has_more);
}

#[test]
fn the_read_returns_at_most_first_events() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let keys: Vec<i128> = (0..3)
        .map(|offset| db.put(&sensor_event(SENSOR, offset), &stamp()).unwrap())
        .collect();
    let rows = index_rows(&db);

    let page = db.read_by_arrival(&all(), None, 2, NO_CAP).unwrap();
    assert_eq!(event_keys(&page), keys[..2]);
    assert_eq!(page.last_scanned, Some(rows[1]));
    assert!(page.has_more);

    let page = db
        .read_by_arrival(&all(), page.last_scanned, 2, NO_CAP)
        .unwrap();
    assert_eq!(event_keys(&page), keys[2..]);
    assert!(!page.has_more);

    let page = db.read_by_arrival(&all(), None, 0, NO_CAP).unwrap();
    assert_eq!(page.events, Vec::new());
    assert_eq!(page.last_scanned, None);
    assert!(page.has_more);
}

/// On a stretch of another customer's events the read scans no more rows
/// than its cap, returns nothing, and moves its cursor along.
#[test]
fn the_read_scans_at_most_the_cap() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let mine_first = db.put(&sensor_event("mine", 0), &stamp()).unwrap();
    for offset in 1..=5 {
        db.put(&sensor_event("theirs", offset), &stamp()).unwrap();
    }
    let mine_last = db.put(&sensor_event("mine", 6), &stamp()).unwrap();
    let rows = index_rows(&db);
    let mine = || of_sensors(&["mine"], TimeSeriesPolicySensors::new(HashMap::new()));

    let page = db.read_by_arrival(&mine(), None, 10, 3).unwrap();
    assert_eq!(event_keys(&page), [mine_first]);
    assert_eq!(page.last_scanned, Some(rows[2]));
    assert!(page.has_more);

    let page = db
        .read_by_arrival(&mine(), page.last_scanned, 10, 3)
        .unwrap();
    assert_eq!(page.events, Vec::new());
    assert_eq!(page.last_scanned, Some(rows[5]));
    assert!(page.has_more);

    let page = db
        .read_by_arrival(&mine(), page.last_scanned, 10, 3)
        .unwrap();
    assert_eq!(event_keys(&page), [mine_last]);
    assert_eq!(page.last_scanned, Some(rows[6]));
    assert!(!page.has_more);

    // A cap reached exactly at the end of the index leaves nothing more.
    let page = db.read_by_arrival(&mine(), Some(rows[3]), 10, 3).unwrap();
    assert_eq!(event_keys(&page), [mine_last]);
    assert!(!page.has_more);
}

/// The read selects by sensor, and a header-less time-series event by the
/// sensors of its policy, exactly as the reads in key order do.
#[test]
fn the_read_applies_the_filter_as_the_key_order_reads_do() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let own = db.put(&sensor_event("s1", 0), &stamp()).unwrap();
    let other = db.put(&sensor_event("o1", 1), &stamp()).unwrap();
    let own_series = db
        .put(&sensorless_series_event("7/192.0.2.1"), &stamp())
        .unwrap();
    let other_series = db
        .put(&sensorless_series_event("8/192.0.2.1"), &stamp())
        .unwrap();
    assert_eq!(
        index_event_keys(&db),
        [own, other, own_series, other_series]
    );

    let policies = || {
        TimeSeriesPolicySensors::new(HashMap::from([
            (7, vec!["s1".to_string()]),
            (8, vec!["o1".to_string()]),
        ]))
    };
    let key_order = |filter: &EventFilter| -> Vec<i128> {
        let mut keys: Vec<i128> = db
            .iter_forward()
            .map(Result::unwrap)
            .filter(|(_, record)| record.matches(filter).unwrap().0)
            .map(|(key, _)| key)
            .collect();
        keys.sort_unstable_by_key(|key| index_event_keys(&db).iter().position(|k| k == key));
        keys
    };

    let filter = of_sensors(&["s1"], policies());
    let page = db.read_by_arrival(&filter, None, 10, NO_CAP).unwrap();
    assert_eq!(event_keys(&page), [own, own_series]);
    assert_eq!(event_keys(&page), key_order(&filter));

    let filter = of_sensors(&["o1"], policies());
    let page = db.read_by_arrival(&filter, None, 10, NO_CAP).unwrap();
    assert_eq!(event_keys(&page), [other, other_series]);
    assert_eq!(event_keys(&page), key_order(&filter));

    // A policy with none of the customer's sensors selects none of its
    // header-less events.
    let filter = of_sensors(
        &["s1"],
        TimeSeriesPolicySensors::new(HashMap::from([(7, Vec::new())])),
    );
    let page = db.read_by_arrival(&filter, None, 10, NO_CAP).unwrap();
    assert_eq!(event_keys(&page), [own]);
    assert_eq!(event_keys(&page), key_order(&filter));
}

#[test]
fn a_row_whose_record_is_gone_is_skipped_and_counted() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let gone = db.put(&sensor_event(SENSOR, 0), &stamp()).unwrap();
    let kept = db.put(&sensor_event(SENSOR, 1), &stamp()).unwrap();
    let rows = index_rows(&db);
    db.inner.delete(gone.to_be_bytes()).unwrap();

    let page = db.read_by_arrival(&all(), None, 10, 1).unwrap();
    assert_eq!(page.events, Vec::new());
    assert_eq!(page.last_scanned, Some(rows[0]));
    assert!(page.has_more);

    let page = db
        .read_by_arrival(&all(), page.last_scanned, 10, 1)
        .unwrap();
    assert_eq!(event_keys(&page), [kept]);
    assert!(!page.has_more);
}

/// A row whose record cannot be decoded, or has an unknown detection model,
/// is skipped with a warning and counted as scanned.
#[test]
fn a_row_whose_record_is_unreadable_is_skipped_with_a_warning() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let first = db.put(&sensor_event(SENSOR, 0), &stamp()).unwrap();
    let broken = db.put(&sensor_event(SENSOR, 1), &stamp()).unwrap();
    let last = db.put(&sensor_event(SENSOR, 2), &stamp()).unwrap();
    db.put_raw(&broken.to_be_bytes(), b"dummy");
    let rows = index_rows(&db);

    let (page, warnings) = capture_warnings(|| db.read_by_arrival(&all(), None, 10, 2).unwrap());
    assert_eq!(event_keys(&page), [first]);
    assert_eq!(page.last_scanned, Some(rows[1]));
    assert!(page.has_more);
    assert_eq!(warnings.len(), 1, "{warnings:?}");

    // Model 21 is the first number review-protocol has not assigned.
    let unknown = (i128::from(T0) << 64) | (21 << 32);
    let value = db.inner.get(last.to_be_bytes()).unwrap().unwrap();
    db.put_raw(&unknown.to_be_bytes(), &value);
    let cf = db.inner.cf_handle(DETECTION_EVENT_ARRIVAL).unwrap();
    let unknown_row = ArrivalKey::new(rows[2].arrival() + 1, unknown);
    db.inner.put_cf(cf, unknown_row.to_bytes(), []).unwrap();

    let (page, warnings) = capture_warnings(|| {
        db.read_by_arrival(&all(), page.last_scanned, 10, NO_CAP)
            .unwrap()
    });
    assert_eq!(event_keys(&page), [last]);
    assert_eq!(page.last_scanned, Some(unknown_row));
    assert!(!page.has_more);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
}

/// While write A is stalled for 61 seconds after stamping its arrival time, a
/// write B started meanwhile waits for it and commits after it, and a reader
/// polling throughout reads A before B and both.
#[test]
fn a_stalled_write_keeps_a_later_one_behind_it() {
    const STALL: i64 = 61 * SECOND;

    let (_permit, store) = setup_store();
    let now = manual_clock(&store, T0);
    let event_a = sensor_event(SENSOR, 0);
    let event_b = sensor_event(SENSOR, 1);

    let (stamped_tx, stamped_rx) = mpsc::channel::<i64>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = Mutex::new(release_rx);
    let (waiting_tx, waiting_rx) = mpsc::channel::<()>();
    let (b_stamped_tx, b_stamped_rx) = mpsc::channel::<(i64, usize)>();
    let locks = AtomicUsize::new(0);
    let stamps = AtomicUsize::new(0);
    let weak: Weak<Store> = Arc::downgrade(&store);
    store
        .states
        .arrival()
        .set_hook(Some(Arc::new(move |point| match point {
            ArrivalHookPoint::BeforeLock => {
                if locks.fetch_add(1, Ordering::SeqCst) == 1 {
                    waiting_tx.send(()).unwrap();
                }
            }
            ArrivalHookPoint::Stamped(arrival) => {
                if stamps.fetch_add(1, Ordering::SeqCst) == 0 {
                    stamped_tx.send(arrival).unwrap();
                    release_rx.lock().unwrap().recv().unwrap();
                } else {
                    // The records committed by the time B stamps.
                    let store = weak.upgrade().unwrap();
                    let committed = store.events().iter_forward().count();
                    b_stamped_tx.send((arrival, committed)).unwrap();
                }
            }
        })));

    let (key_a, key_b, seen) = std::thread::scope(|scope| {
        let store: &Store = &store;
        let a = scope.spawn(|| store.events().put(&event_a, &stamp()).unwrap());
        assert_eq!(stamped_rx.recv().unwrap(), T0);

        now.fetch_add(STALL, Ordering::SeqCst);
        let b = scope.spawn(|| store.events().put(&event_b, &stamp()).unwrap());
        waiting_rx.recv().unwrap();

        let (polled_tx, polled_rx) = mpsc::channel::<()>();
        let reader = scope.spawn(move || {
            let mut seen = Vec::new();
            let mut cursor = None;
            let mut polls = 0_usize;
            while seen.len() < 2 {
                let page = store
                    .events()
                    .read_by_arrival(&all(), cursor, 10, NO_CAP)
                    .unwrap();
                seen.extend(event_keys(&page));
                cursor = page.last_scanned.or(cursor);
                polls += 1;
                if polls == 1 {
                    polled_tx.send(()).unwrap();
                }
                std::thread::yield_now();
            }
            seen
        });
        polled_rx.recv().unwrap();
        // Neither write has committed while A is stalled.
        assert_eq!(store.events().iter_forward().count(), 0);
        release_tx.send(()).unwrap();

        let key_a = a.join().unwrap();
        let key_b = b.join().unwrap();
        (key_a, key_b, reader.join().unwrap())
    });

    let (b_arrival, committed_before_b) = b_stamped_rx.recv().unwrap();
    assert_eq!(b_arrival, T0 + STALL);
    assert_eq!(committed_before_b, 1, "A committed before B stamped");
    assert_eq!(seen, [key_a, key_b]);
    let db = store.events();
    assert_eq!(
        index_rows(&db),
        [
            ArrivalKey::new(T0, key_a),
            ArrivalKey::new(T0 + STALL, key_b)
        ]
    );
    let mut written = record_keys(&db);
    written.sort_unstable();
    let mut read = seen.clone();
    read.sort_unstable();
    assert_eq!(read, written);
    store.states.arrival().set_hook(None);
}

#[test]
fn arrival_times_increase_when_the_clock_goes_backwards() {
    let (_permit, store) = setup_store();
    let now = manual_clock(&store, T0);
    let db = store.events();
    let first = db.put(&sensor_event(SENSOR, 0), &stamp()).unwrap();
    now.store(T0 - 3600 * SECOND, Ordering::SeqCst);
    let second = db.put(&sensor_event(SENSOR, 1), &stamp()).unwrap();
    now.store(T0 - 7200 * SECOND, Ordering::SeqCst);
    let PutOutcome::Stored(third) = db
        .put_unless_stored(&sensor_event(SENSOR, 2), &stamp())
        .unwrap()
    else {
        panic!("the event is not stored yet");
    };
    assert_eq!(
        index_rows(&db),
        [
            ArrivalKey::new(T0, first),
            ArrivalKey::new(T0 + 1, second),
            ArrivalKey::new(T0 + 2, third),
        ]
    );
    let page = db.read_by_arrival(&all(), None, 10, NO_CAP).unwrap();
    assert_eq!(event_keys(&page), [first, second, third]);
}

/// Arrival times go on from the last one stamped after the store is
/// reopened, also when the largest index row was deleted before.
#[test]
fn arrival_times_continue_after_reopening() {
    let _permit = acquire_db_permit();
    let data_dir = tempfile::tempdir().unwrap();
    let backup_dir = tempfile::tempdir().unwrap();
    let open = || Store::new(data_dir.path(), backup_dir.path(), None).unwrap();

    let last = {
        let store = open();
        let now = manual_clock(&store, T0);
        let db = store.events();
        db.put(&sensor_event(SENSOR, 0), &stamp()).unwrap();
        now.fetch_add(SECOND, Ordering::SeqCst);
        db.put(&sensor_event(SENSOR, 1), &stamp()).unwrap();
        index_rows(&db).last().unwrap().arrival()
    };
    assert_eq!(last, T0 + SECOND);

    let deleted = {
        let store = open();
        manual_clock(&store, T0 - 24 * 3600 * SECOND);
        let db = store.events();
        let key = db.put(&sensor_event(SENSOR, 2), &stamp()).unwrap();
        let row = *index_rows(&db).last().unwrap();
        assert_eq!(row, ArrivalKey::new(last + 1, key));
        let cf = db.inner.cf_handle(DETECTION_EVENT_ARRIVAL).unwrap();
        db.inner.delete_cf(cf, row.to_bytes()).unwrap();
        row.arrival()
    };

    let store = open();
    manual_clock(&store, T0 - 24 * 3600 * SECOND);
    let db = store.events();
    let key = db.put(&sensor_event(SENSOR, 3), &stamp()).unwrap();
    let row = *index_rows(&db).last().unwrap();
    assert_eq!(row, ArrivalKey::new(deleted + 1, key));
}

/// After an online restore the last arrival time is the one the restored
/// `meta` holds, not the one stamped since the backup.
#[test]
fn an_online_restore_reloads_the_last_arrival_time() {
    let _permit = acquire_db_permit();
    let data_dir = tempfile::tempdir().unwrap();
    let backup_dir = tempfile::tempdir().unwrap();
    let mut store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
    let now = manual_clock(&store, T0);
    let backed_up = store
        .events()
        .put(&sensor_event(SENSOR, 0), &stamp())
        .unwrap();
    store.backup(true, 1).unwrap();
    now.store(T0 + 3600 * SECOND, Ordering::SeqCst);
    store
        .events()
        .put(&sensor_event(SENSOR, 1), &stamp())
        .unwrap();

    now.store(T0 - 3600 * SECOND, Ordering::SeqCst);
    store.restore_from_backup(1).unwrap();
    let db = store.events();
    assert_eq!(index_rows(&db), [ArrivalKey::new(T0, backed_up)]);
    let key = db.put(&sensor_event(SENSOR, 2), &stamp()).unwrap();
    assert_eq!(
        index_rows(&db),
        [ArrivalKey::new(T0, backed_up), ArrivalKey::new(T0 + 1, key)]
    );
}

#[test]
fn remove_before_removes_the_rows_of_the_records_it_removes() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let old: Vec<i128> = (0..3)
        .map(|offset| db.put(&sensor_event(SENSOR, offset), &stamp()).unwrap())
        .collect();
    let recent: Vec<i128> = (10..13)
        .map(|offset| db.put(&sensor_event(SENSOR, offset), &stamp()).unwrap())
        .collect();
    // A late old event, and a pre-epoch one.
    let late = db.put(&sensor_event(SENSOR, 1), &stamp()).unwrap();
    let pre_epoch = db
        .put(
            &raw_event_event(
                crate::event::fixture::at(-SECOND),
                SENSOR,
                conn_body(ip("192.0.2.1"), ip("198.51.100.1")),
            ),
            &stamp(),
        )
        .unwrap();
    assert_eq!(index_rows(&db).len(), 8);

    assert_eq!(db.remove_before(after(time(), 10)).unwrap(), 5);
    assert_eq!(record_keys(&db), recent);
    assert_eq!(index_event_keys(&db), recent);
    assert!(
        !index_event_keys(&db)
            .iter()
            .any(|key| old.contains(key) || [late, pre_epoch].contains(key))
    );

    let far_future = Timestamp::from_nanosecond(i128::from(i64::MAX) + 1).unwrap();
    assert_eq!(db.remove_before(far_future).unwrap(), 3);
    assert_eq!(index_rows(&db), Vec::new());
}

#[test]
fn remove_by_sensors_removes_the_rows_of_the_records_it_removes() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let mut kept = Vec::new();
    for offset in 0..4 {
        db.put(&sensor_event("a1", offset * 3), &stamp()).unwrap();
        db.put(&sensor_event("a2", offset * 3 + 1), &stamp())
            .unwrap();
        kept.push(
            db.put(&sensor_event("b1", offset * 3 + 2), &stamp())
                .unwrap(),
        );
    }
    kept.push(
        db.put(&sensorless_series_event("7/192.0.2.1"), &stamp())
            .unwrap(),
    );
    assert_eq!(index_rows(&db).len(), 13);

    db.remove_by_sensors(&["a1".to_string(), "a2".to_string()])
        .unwrap();
    let mut records = record_keys(&db);
    records.sort_unstable();
    let mut rows = index_event_keys(&db);
    rows.sort_unstable();
    kept.sort_unstable();
    assert_eq!(records, kept);
    assert_eq!(rows, kept);
}
