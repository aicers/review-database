//! Stored-format baseline of detection events from before the endpoint
//! subject was added.
//!
//! The fixtures under `tests/fixtures/detection_event_v0_63/` were generated
//! once at commit 266599f ("feat!: index detection events by arrival order
//! and read them in that order"), on review-protocol 0.32.0, before the
//! dependency moved to review-protocol 0.33.0, by the ignored test
//! [`generate_detection_event_fixtures`]:
//!
//! ```sh
//! cargo test --all-features --lib generate_detection_event_fixtures -- --ignored
//! ```
//!
//! - `<name>.bin` holds the `encode_event` (bincode 1) bytes of the
//!   track-1-shaped event [`baseline_events`] names `<name>`;
//! - `data/` and `backup/` are a data directory and its backup directory,
//!   initialized by `migrate_data_dir` (format marker "0.63.0") and holding
//!   every one of those events, stored with [`EventDb::put`] and the stamp
//!   [`stamp`], one second apart, in [`baseline_events`] order. RocksDB's
//!   informational `LOG` file was deleted from `data/states.db/` before the
//!   commit; nothing reads it.
//!
//! The tests compare against the committed files and never regenerate them;
//! the generator stays only to document how they were made.
//!
//! review-protocol 0.35.0 appended six fields to `raw_event::Http`, so the
//! `body_http` fixture holds an `Http` body in a layout this crate no longer
//! reads. No reader of it was added: the format is deployed by a fresh
//! install, so no stored event has that layout. The tests check that the
//! fixture's record is the only one that cannot be read, and compare every
//! other one as before.

use std::path::{Path, PathBuf};

use jiff::SignedDuration;
use review_protocol::types::{DetectionEvent, EndpointRole, PrimarySubject, ThreatRole};

use super::{
    EventDb, EventFilter,
    fixture::{
        conn_body, dns_body, host, http_body, ip, netflow5_body, netflow9_body, raw_event_event,
        related, stamp, subject_event, time,
    },
    record,
};
use crate::Store;

/// The fixture directory, relative to the crate root.
const FIXTURE_DIR: &str = "tests/fixtures/detection_event_v0_63";

/// The format marker the data directory was written with.
const FORMAT_MARKER: &str = "0.63.0";

/// The fixture whose `Http` body has the review-protocol 0.34.0 layout,
/// which is no longer read.
const OLD_HTTP_LAYOUT: &str = "body_http";

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_DIR)
}

/// The track-1-shaped events of the baseline, each with its fixture name:
/// the four subjects that existed before the endpoint subject, network
/// bodies, and the `Netflow5` and `Netflow9` bodies.
fn baseline_events() -> Vec<(&'static str, DetectionEvent)> {
    let host_ip = ip("10.0.0.1");
    let peer = ip("198.51.100.7");
    vec![
        (
            "subject_host",
            subject_event(
                host("10.0.0.1"),
                vec![
                    related("198.51.100.7", EndpointRole::Destination),
                    related("203.0.113.9", EndpointRole::Source),
                ],
            ),
        ),
        (
            "subject_cluster",
            subject_event(
                PrimarySubject::Cluster {
                    clustering_model: 12,
                    cluster_id: 34,
                },
                vec![related("192.0.2.44", EndpointRole::Source)],
            ),
        ),
        (
            "subject_sensor",
            subject_event(PrimarySubject::Sensor, Vec::new()),
        ),
        (
            "subject_network",
            subject_event(
                PrimarySubject::Network {
                    customer: 3,
                    name: "office".to_string(),
                    role: ThreatRole::Target,
                },
                vec![related("2001:db8::5", EndpointRole::Destination)],
            ),
        ),
        (
            "body_conn",
            raw_event_event(time(), "sensor-1", conn_body(host_ip, peer)),
        ),
        (
            "body_dns",
            raw_event_event(time(), "sensor-1", dns_body(host_ip, ip("192.0.2.53"))),
        ),
        (
            "body_http",
            raw_event_event(time(), "sensor-2", http_body(ip("2001:db8::1"), peer)),
        ),
        (
            "body_netflow5",
            raw_event_event(time(), "sensor-1", netflow5_body(host_ip, peer)),
        ),
        (
            "body_netflow9",
            raw_event_event(time(), "sensor-1", netflow9_body(host_ip, peer)),
        ),
    ]
}

/// Returns the baseline events as stored in the data directory: the
/// `index`-th one at [`time`] plus `index` seconds, in its time and in the
/// time of its raw event or window.
fn stored_baseline_events() -> Vec<(&'static str, DetectionEvent)> {
    baseline_events()
        .into_iter()
        .zip(0_i64..)
        .map(|((name, mut event), index)| {
            let shift = SignedDuration::from_secs(index);
            event.time = event.time.checked_add(shift).expect("in range");
            match &mut event.target {
                review_protocol::types::Target::RawEvent { time, .. } => {
                    *time = time.checked_add(shift).expect("in range");
                }
                review_protocol::types::Target::Subject { window, .. } => {
                    window.start = window.start.checked_add(shift).expect("in range");
                    window.end = window.end.checked_add(shift).expect("in range");
                }
            }
            (name, event)
        })
        .collect()
}

/// Returns the stored baseline events this crate still reads: every one but
/// [`OLD_HTTP_LAYOUT`].
fn readable_stored_baseline_events() -> Vec<DetectionEvent> {
    stored_baseline_events()
        .into_iter()
        .filter(|(name, _)| *name != OLD_HTTP_LAYOUT)
        .map(|(_, event)| event)
        .collect()
}

#[test]
#[ignore = "run once at the base commit to generate tests/fixtures/detection_event_v0_63"]
fn generate_detection_event_fixtures() {
    let dir = fixture_dir();
    assert!(!dir.exists(), "remove {} first", dir.display());
    std::fs::create_dir_all(&dir).unwrap();
    for (name, event) in baseline_events() {
        let bytes = record::encode_event(&event).unwrap();
        std::fs::write(dir.join(format!("{name}.bin")), bytes).unwrap();
    }
    let data = dir.join("data");
    let backup = dir.join("backup");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&backup).unwrap();
    crate::migrate_data_dir(&data, &backup, None).unwrap();
    {
        let store = Store::new(&data, &backup, None).unwrap();
        let events = store.events();
        for (_, event) in stored_baseline_events() {
            events.put(&event, &stamp()).unwrap();
        }
    }
}

#[test]
fn encode_event_matches_pre_endpoint_bytes() {
    let dir = fixture_dir();
    for (name, event) in baseline_events() {
        let expected = std::fs::read(dir.join(format!("{name}.bin")))
            .unwrap_or_else(|e| panic!("reading fixture {name}: {e}"));
        if name == OLD_HTTP_LAYOUT {
            assert_ne!(record::encode_event(&event).unwrap(), expected);
            continue;
        }
        assert_eq!(
            record::encode_event(&event).unwrap(),
            expected,
            "encode_event bytes of {name}"
        );
        let decoded: DetectionEvent = bincode::deserialize(&expected).unwrap();
        assert_eq!(decoded, event, "decoded fixture {name}");
    }
}

/// Copies the directory `from` into `to`, recursively.
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A stored record as read: its event, stamp and country codes.
type ReadRecord = (DetectionEvent, super::DetectionEventStamp, Vec<[u8; 2]>);

/// Reads every record of `events` in key order, and returns the ones that
/// could be read with the number of those that could not.
fn read_all(events: &EventDb<'_>) -> (Vec<ReadRecord>, usize) {
    let mut unreadable = 0;
    let mut read = Vec::new();
    for item in events.iter_forward() {
        let Ok((_, record)) = item else {
            unreadable += 1;
            continue;
        };
        let codes = record.stored_country_codes().to_vec();
        let (event, stamp) = record.into_parts();
        read.push((event, stamp, codes));
    }
    (read, unreadable)
}

/// Drops the `hosts` family from the states database in `data`.
///
/// The fixture was written while the format still had that family, and the
/// store opens only a database whose families are the current ones. Nothing
/// was stored in it, so the events this test reads are as the fixture left
/// them.
fn drop_hosts_family(data: &Path) {
    let states = data.join(crate::DEFAULT_STATES);
    let families = rocksdb::DB::list_cf(&rocksdb::Options::default(), &states).unwrap();
    let mut db = rocksdb::DB::open_cf(&rocksdb::Options::default(), &states, &families).unwrap();
    let hosts = db.cf_handle("hosts").unwrap();
    assert_eq!(
        db.iterator_cf(hosts, rocksdb::IteratorMode::Start).count(),
        0
    );
    db.drop_cf("hosts").unwrap();
}

#[test]
fn pre_endpoint_data_directory_reads_unchanged() {
    let _permit = crate::test::acquire_db_permit();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let backup = dir.path().join("backup");
    copy_dir(&fixture_dir().join("data"), &data);
    copy_dir(&fixture_dir().join("backup"), &backup);
    drop_hosts_family(&data);

    crate::migrate_data_dir(&data, &backup, None).unwrap();
    for marker_dir in [&data, &backup] {
        assert_eq!(
            std::fs::read_to_string(marker_dir.join("VERSION"))
                .unwrap()
                .trim(),
            FORMAT_MARKER
        );
    }

    let store = Store::new(&data, &backup, None).unwrap();
    let events = store.events();
    let expected: Vec<_> = readable_stored_baseline_events()
        .into_iter()
        .map(|event| {
            let codes = record::country_codes(&event, None);
            (event, stamp(), codes)
        })
        .collect();
    assert_eq!(read_all(&events), (expected, 1));

    let arrival: Vec<DetectionEvent> = events
        .read_by_arrival(
            &EventFilter::new(
                None, None, None, None, None, None, None, None, None, None, None, None, None,
            ),
            None,
            usize::MAX,
            usize::MAX,
        )
        .unwrap()
        .events
        .into_iter()
        .map(|(_, record)| record.into_parts().0)
        .collect();
    assert_eq!(arrival, readable_stored_baseline_events());
}
