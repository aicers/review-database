//! Tests of the signature rule source storage.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use jiff::civil::date;
use review_protocol::types::{LoadedSignatureSet, RawEventKind, TruncatedCount};

use super::*;
use crate::{
    Agent, AgentStatus, CustomerDataDeletionJob, Node, NodeProfile,
    test::{DbGuard, acquire_db_permit},
};

thread_local! {
    /// A hook run on this thread right after an operation reads a source
    /// row, so that a test can pause the operation between its reads.
    pub(super) static AFTER_SOURCE_READ: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

const ET: SignatureSource = SignatureSource::EtOpen;
const SIGMA: SignatureSource = SignatureSource::SigmaHq;
const EMERGING: SignatureSource = SignatureSource::SigmaHqEmerging;
const ALL_SOURCES: [SignatureSource; 3] = [ET, SIGMA, EMERGING];

const HOG: &str = "hog";
const OTHER_HOG: &str = "hog-2";
const ENGINE: &str = "reconverge";

/// Every family this crate keeps signature records in.
const FAMILIES: [&str; 8] = [
    tables::SIGNATURE_SOURCES,
    tables::SIGNATURE_SOURCE_VERSIONS,
    tables::SIGNATURE_SOURCE_ARCHIVES,
    tables::SIGNATURE_RULE_SETS,
    tables::SIGNATURE_RULE_OVERRIDES,
    tables::SIGNATURE_PUSH_REVISION,
    tables::SIGNATURE_STATUS,
    tables::SIGNATURE_TRUNCATION_DAILY,
];

struct TestStore {
    _permit: DbGuard<'static>,
    store: Store,
    _db_dir: tempfile::TempDir,
    _backup_dir: tempfile::TempDir,
}

fn setup_store() -> TestStore {
    let permit = acquire_db_permit();
    let db_dir = tempfile::tempdir().unwrap();
    let backup_dir = tempfile::tempdir().unwrap();
    let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
    TestStore {
        _permit: permit,
        store,
        _db_dir: db_dir,
        _backup_dir: backup_dir,
    }
}

fn at(secs: i64) -> Timestamp {
    crate::test::from_second(secs, 0)
}

fn key(year: i16, month: i8, day: i8, number: Option<u64>) -> SignatureOrderKey {
    SignatureOrderKey {
        date: date(year, month, day),
        number,
    }
}

/// The archive of a version whose content digest is `digest`.
fn archive_of(digest: &str) -> Vec<u8> {
    format!("archive of {digest}").into_bytes()
}

/// The rule set a conversion of version `id` produces.
fn rules_of(id: u64) -> Vec<u8> {
    format!("rules of {id}").into_bytes()
}

/// Ingests a version of `source` with content `digest`.
fn ingest_as(
    store: &Store,
    source: SignatureSource,
    source_version: &str,
    digest: &str,
    order_key: SignatureOrderKey,
    origin: SignatureOrigin,
) -> Result<u64> {
    let archive = archive_of(digest);
    store.ingest_signature_version(&NewSignatureVersion {
        source,
        source_version,
        order_key,
        fetch_label: (origin == SignatureOrigin::Fetch).then_some("nightly"),
        origin,
        fetched_url: (origin == SignatureOrigin::Fetch).then_some("https://rules.example/a.tar"),
        archive_sha256: [7; 32],
        content_digest: digest.as_bytes(),
        received_at: at(100),
        archive: &archive,
    })
}

fn ingest(
    store: &Store,
    source: SignatureSource,
    digest: &str,
    order_key: SignatureOrderKey,
) -> Result<u64> {
    ingest_as(
        store,
        source,
        digest,
        digest,
        order_key,
        SignatureOrigin::Fetch,
    )
}

fn convert(store: &Store, id: u64) -> Result<()> {
    store.complete_signature_conversion(id, "conv-1", &rules_of(id), &format!("summary {id}"))
}

/// Ingests and converts a version, returning its id.
fn stage(store: &Store, source: SignatureSource, digest: &str, day: i8) -> u64 {
    let id = ingest(store, source, digest, key(2026, 3, day, None)).unwrap();
    convert(store, id).unwrap();
    id
}

/// Ingests, converts and applies a version, returning its id.
fn apply_new(store: &Store, source: SignatureSource, digest: &str, day: i8) -> u64 {
    let id = stage(store, source, digest, day);
    store.apply_signature_version(id).unwrap();
    id
}

fn refusal(error: &anyhow::Error) -> &SignatureError {
    error
        .downcast_ref::<SignatureError>()
        .unwrap_or_else(|| panic!("not a signature error: {error:#}"))
}

fn state_of(store: &Store, id: u64) -> Option<SignatureVersionState> {
    store.signature_version(id).unwrap().map(|v| v.state)
}

/// The rows of each signature family, by family name.
type Snapshot = BTreeMap<&'static str, Vec<(Vec<u8>, Vec<u8>)>>;

/// Returns every row of the signature families and the version id
/// counter, to compare what an operation changed.
fn snapshot(store: &Store) -> Snapshot {
    let db = store.states.db();
    let mut rows: BTreeMap<_, _> = FAMILIES
        .into_iter()
        .map(|name| {
            let cf = db.cf_handle(name).unwrap();
            let rows = db
                .iterator_cf(cf, IteratorMode::Start)
                .map(|entry| {
                    let (k, v) = entry.unwrap();
                    (k.to_vec(), v.to_vec())
                })
                .collect::<Vec<_>>();
            (name, rows)
        })
        .collect();
    let meta = db.cf_handle(tables::META).unwrap();
    let counter = db
        .get_cf(meta, tables::SIGNATURE_VERSION_ID_COUNTER)
        .unwrap()
        .map(|v| (tables::SIGNATURE_VERSION_ID_COUNTER.to_vec(), v))
        .into_iter()
        .collect();
    rows.insert("version id counter", counter);
    rows
}

/// Asserts that the slots of `source` name versions in the matching
/// states, that no other version of the source is in those states, and
/// that `Failed` and `Discarded` retention holds.
fn assert_consistent(store: &Store, source: SignatureSource) {
    use SignatureVersionState::{Applied, Converting, Discarded, Failed, Kept, Staged};

    let state = store.signature_source(source).unwrap();
    let versions = store.signature_versions_of_source(source).unwrap();
    let in_state = |s| -> Vec<u64> {
        versions
            .iter()
            .filter(|v| v.state == s)
            .map(|v| v.id)
            .collect()
    };
    assert_eq!(
        in_state(Applied),
        state.applied.into_iter().collect::<Vec<_>>()
    );
    assert_eq!(
        in_state(Staged),
        state.staged.into_iter().collect::<Vec<_>>()
    );
    assert!(state.kept.len() <= 2, "{state:?}");
    let mut kept = state.kept.clone();
    kept.sort_unstable();
    assert_eq!(in_state(Kept), kept);
    assert!(in_state(Failed).len() <= 1);
    assert!(in_state(Discarded).len() <= 1);
    for version in &versions {
        let archive = store.signature_archive(version.id).unwrap();
        let rules = store.signature_rule_set(version.id).unwrap();
        match version.state {
            Converting => {
                assert!(archive.is_some());
                assert!(rules.is_none());
            }
            Staged | Applied | Kept => {
                assert!(archive.is_some());
                assert!(rules.is_some());
                assert!(version.converter_version.is_some());
            }
            Failed | Discarded => {
                assert!(archive.is_none(), "{version:?}");
                assert!(rules.is_none(), "{version:?}");
            }
        }
    }
}

#[test]
fn order_keys() {
    let cases = [
        (key(2026, 3, 1, None), key(2026, 3, 2, None), true),
        (key(2026, 3, 2, None), key(2026, 3, 1, None), false),
        (key(2026, 3, 1, Some(9)), key(2026, 3, 2, Some(1)), true),
        (key(2026, 3, 2, Some(1)), key(2026, 3, 1, Some(9)), false),
        (key(2026, 3, 1, Some(1)), key(2026, 3, 1, Some(2)), true),
        (key(2026, 3, 1, Some(2)), key(2026, 3, 1, Some(1)), false),
        (key(2026, 3, 1, Some(2)), key(2026, 3, 1, Some(2)), false),
        (key(2026, 3, 1, None), key(2026, 3, 1, None), false),
        // A number on only one side: neither is earlier.
        (key(2026, 3, 1, Some(2)), key(2026, 3, 1, None), false),
        (key(2026, 3, 1, None), key(2026, 3, 1, Some(2)), false),
        (key(2026, 3, 1, None), key(2026, 3, 2, Some(0)), true),
        (key(2026, 3, 1, Some(u64::MAX)), key(2026, 3, 2, None), true),
    ];
    for (a, b, earlier) in cases {
        assert_eq!(a.is_earlier_than(&b), earlier, "{a:?} {b:?}");
    }
}

#[test]
fn a_source_without_a_row_reads_as_disabled_with_no_versions() {
    let t = setup_store();
    for source in ALL_SOURCES {
        assert_eq!(
            t.store.signature_source(source).unwrap(),
            SignatureSourceState {
                source,
                enabled: false,
                applied: None,
                kept: Vec::new(),
                staged: None,
                last_reconversion: None,
            }
        );
        assert_eq!(
            t.store.signature_versions_of_source(source).unwrap(),
            Vec::new()
        );
    }
    assert_eq!(t.store.signature_push_revision().unwrap(), 0);
    assert_eq!(t.store.signature_rule_overrides().unwrap(), Vec::new());
    assert!(t.store.signature_version(1).unwrap().is_none());
    assert!(t.store.signature_archive(1).unwrap().is_none());
    assert!(t.store.signature_rule_set(1).unwrap().is_none());
}

#[test]
fn ingest_stores_a_converting_version_with_its_archive() {
    let t = setup_store();
    let store = &t.store;
    let first = ingest_as(
        store,
        ET,
        "7000",
        "digest-a",
        key(2026, 3, 10, Some(7000)),
        SignatureOrigin::Fetch,
    )
    .unwrap();
    let second = ingest_as(
        store,
        ET,
        "upload",
        "digest-b",
        key(2026, 3, 10, None),
        SignatureOrigin::Upload,
    )
    .unwrap();
    let other = ingest(store, SIGMA, "digest-a", key(2026, 1, 1, None)).unwrap();
    assert!(first < second && second < other);

    assert_eq!(
        store.signature_version(first).unwrap(),
        Some(SignatureVersion {
            id: first,
            source: ET,
            source_version: "7000".to_owned(),
            order_key: key(2026, 3, 10, Some(7000)),
            fetch_label: Some("nightly".to_owned()),
            converter_version: None,
            origin: SignatureOrigin::Fetch,
            fetched_url: Some("https://rules.example/a.tar".to_owned()),
            archive_sha256: [7; 32],
            content_digest: b"digest-a".to_vec(),
            received_at: at(100),
            state: SignatureVersionState::Converting,
            failure_reason: None,
            summary: None,
        })
    );
    let uploaded = store.signature_version(second).unwrap().unwrap();
    assert_eq!(uploaded.origin, SignatureOrigin::Upload);
    assert_eq!(uploaded.fetch_label, None);
    assert_eq!(uploaded.fetched_url, None);
    assert_eq!(
        store.signature_archive(first).unwrap(),
        Some(archive_of("digest-a"))
    );
    assert_eq!(store.signature_rule_set(first).unwrap(), None);
    assert_eq!(
        store
            .signature_versions_in_state(SignatureVersionState::Converting)
            .unwrap()
            .into_iter()
            .map(|v| v.id)
            .collect::<Vec<_>>(),
        [first, second, other]
    );
    assert_eq!(
        store
            .signature_versions_of_source(ET)
            .unwrap()
            .into_iter()
            .map(|v| v.id)
            .collect::<Vec<_>>(),
        [first, second]
    );
    // Ingest leaves the source's slots, flag and the revision as they are.
    assert_eq!(store.signature_source(ET).unwrap().staged, None);
    assert!(!store.signature_source(ET).unwrap().enabled);
    assert_eq!(store.signature_push_revision().unwrap(), 0);
    assert_consistent(store, ET);
}

#[test]
fn ingest_refuses_the_content_of_the_applied_or_staged_version() {
    let t = setup_store();
    let store = &t.store;
    let applied = apply_new(store, ET, "applied", 10);
    let staged = stage(store, ET, "staged", 11);
    let before = snapshot(store);

    for (digest, expected) in [("applied", applied), ("staged", staged)] {
        // Even under another source version and a later order key.
        let error = ingest_as(
            store,
            ET,
            "another source version",
            digest,
            key(2026, 4, 1, None),
            SignatureOrigin::Upload,
        )
        .unwrap_err();
        assert_eq!(
            refusal(&error),
            &SignatureError::AlreadyPresent {
                version_id: expected
            }
        );
        assert_eq!(snapshot(store), before);
    }

    // The check comes before the order-key check.
    let error = ingest(store, ET, "applied", key(2020, 1, 1, None)).unwrap_err();
    assert_eq!(
        refusal(&error),
        &SignatureError::AlreadyPresent {
            version_id: applied
        }
    );
    assert_eq!(snapshot(store), before);

    // The same content of another source is not present.
    ingest(store, SIGMA, "applied", key(2026, 1, 1, None)).unwrap();
}

#[test]
fn ingest_refuses_an_order_key_earlier_than_the_applied_one() {
    let t = setup_store();
    let store = &t.store;

    // No applied version: any key is accepted, also one earlier than the
    // staged version's.
    stage(store, ET, "staged", 20);
    ingest(store, ET, "early", key(2026, 3, 1, None)).unwrap();

    let applied = apply_new(store, SIGMA, "applied", 10);
    let before = snapshot(store);
    let error = ingest(store, SIGMA, "older", key(2026, 3, 9, None)).unwrap_err();
    assert_eq!(
        refusal(&error),
        &SignatureError::OlderThanApplied {
            applied_version_id: applied
        }
    );
    assert_eq!(snapshot(store), before);

    ingest(store, SIGMA, "same day", key(2026, 3, 10, None)).unwrap();
    ingest(store, SIGMA, "later", key(2026, 3, 11, None)).unwrap();
}

/// Feeds `(origin, source version, digest, order key)` inputs to ingest,
/// converting and applying each accepted one, and returns each outcome:
/// the version id, or the refusal.
fn run_sequence(
    store: &Store,
    source: SignatureSource,
    inputs: &[(SignatureOrigin, &str, &str, SignatureOrderKey)],
) -> Vec<Result<u64, SignatureError>> {
    inputs
        .iter()
        .map(|(origin, version, digest, order_key)| {
            match ingest_as(store, source, version, digest, *order_key, *origin) {
                Ok(id) => {
                    convert(store, id).unwrap();
                    store.apply_signature_version(id).unwrap();
                    Ok(id)
                }
                Err(e) => Err(refusal(&e).clone()),
            }
        })
        .collect()
}

#[test]
fn rollback_guard_and_presence_across_fetches_and_uploads() {
    use SignatureOrigin::{Fetch, Upload};

    let t = setup_store();
    let store = &t.store;

    // The emerging-threats directory, ordered by its commit date.
    let outcomes = run_sequence(
        store,
        EMERGING,
        &[
            (Fetch, "commit-aaa", "et-dir-1", key(2026, 3, 10, None)),
            (Upload, "upload-1", "et-dir-1", key(2026, 3, 10, None)),
            (Upload, "upload-2", "et-dir-2", key(2026, 3, 12, None)),
            (Fetch, "commit-bbb", "et-dir-3", key(2026, 3, 11, None)),
        ],
    );
    let first = *outcomes[0].as_ref().unwrap();
    let second = *outcomes[2].as_ref().unwrap();
    assert_eq!(
        outcomes[1],
        Err(SignatureError::AlreadyPresent { version_id: first })
    );
    assert_eq!(
        outcomes[3],
        Err(SignatureError::OlderThanApplied {
            applied_version_id: second
        })
    );

    // SigmaHQ releases, ordered by their release date.
    let outcomes = run_sequence(
        store,
        SIGMA,
        &[
            (Fetch, "r2026-03-01", "sigma-1", key(2026, 3, 1, None)),
            (Upload, "r2026-03-01", "sigma-1", key(2026, 3, 1, None)),
            (Upload, "r2026-02-01", "sigma-0", key(2026, 2, 1, None)),
            (Fetch, "r2026-04-01", "sigma-2", key(2026, 4, 1, None)),
        ],
    );
    let first = *outcomes[0].as_ref().unwrap();
    assert_eq!(
        outcomes[1],
        Err(SignatureError::AlreadyPresent { version_id: first })
    );
    assert_eq!(
        outcomes[2],
        Err(SignatureError::OlderThanApplied {
            applied_version_id: first
        })
    );
    assert!(outcomes[3].is_ok());

    // ET: a fetched key carries the day's number, an uploaded one has none.
    let outcomes = run_sequence(
        store,
        ET,
        &[
            (Fetch, "7000", "et-1", key(2026, 3, 10, Some(7000))),
            (Upload, "upload", "et-2", key(2026, 3, 10, None)),
            (Fetch, "7001", "et-3", key(2026, 3, 10, Some(7001))),
            (Fetch, "6999", "et-4", key(2026, 3, 10, Some(6999))),
            (Upload, "upload-old", "et-5", key(2026, 3, 9, None)),
            (Fetch, "7100", "et-6", key(2026, 3, 11, Some(7100))),
        ],
    );
    let third = *outcomes[2].as_ref().unwrap();
    assert!(outcomes[0].is_ok() && outcomes[1].is_ok() && outcomes[5].is_ok());
    assert_eq!(
        outcomes[3],
        Err(SignatureError::OlderThanApplied {
            applied_version_id: third
        })
    );
    assert_eq!(
        outcomes[4],
        Err(SignatureError::OlderThanApplied {
            applied_version_id: third
        })
    );
    for source in ALL_SOURCES {
        assert_consistent(store, source);
    }
}

#[test]
fn a_conversion_stages_the_version_and_discards_the_staged_one() {
    let t = setup_store();
    let store = &t.store;
    let first = ingest(store, ET, "a", key(2026, 3, 1, None)).unwrap();
    let second = ingest(store, ET, "b", key(2026, 3, 2, None)).unwrap();
    store
        .complete_signature_conversion(first, "conv-1", b"rules", "1 rule")
        .unwrap();
    let staged = store.signature_version(first).unwrap().unwrap();
    assert_eq!(staged.state, SignatureVersionState::Staged);
    assert_eq!(staged.converter_version.as_deref(), Some("conv-1"));
    assert_eq!(staged.summary.as_deref(), Some("1 rule"));
    assert_eq!(
        store.signature_rule_set(first).unwrap().as_deref(),
        Some(&b"rules"[..])
    );
    assert_eq!(store.signature_source(ET).unwrap().staged, Some(first));

    convert(store, second).unwrap();
    assert_eq!(store.signature_source(ET).unwrap().staged, Some(second));
    assert_eq!(
        state_of(store, first),
        Some(SignatureVersionState::Discarded)
    );
    assert_eq!(store.signature_archive(first).unwrap(), None);
    assert_eq!(store.signature_rule_set(first).unwrap(), None);
    assert_eq!(store.signature_push_revision().unwrap(), 0);
    assert_consistent(store, ET);
}

#[test]
fn a_failed_conversion_keeps_the_reason_and_drops_the_archive() {
    let t = setup_store();
    let store = &t.store;
    let id = ingest(store, ET, "a", key(2026, 3, 1, None)).unwrap();
    store.fail_signature_conversion(id, "bad archive").unwrap();
    let failed = store.signature_version(id).unwrap().unwrap();
    assert_eq!(failed.state, SignatureVersionState::Failed);
    assert_eq!(failed.failure_reason.as_deref(), Some("bad archive"));
    assert_eq!(store.signature_archive(id).unwrap(), None);
    assert_eq!(store.signature_source(ET).unwrap().staged, None);
    assert_consistent(store, ET);
}

#[test]
fn discarding_empties_the_staged_slot() {
    let t = setup_store();
    let store = &t.store;
    let applied = apply_new(store, ET, "a", 1);
    let id = stage(store, ET, "b", 2);
    let revision = store.signature_push_revision().unwrap();
    store.discard_signature_version(id).unwrap();
    assert_eq!(state_of(store, id), Some(SignatureVersionState::Discarded));
    let source = store.signature_source(ET).unwrap();
    assert_eq!(source.staged, None);
    assert_eq!(source.applied, Some(applied));
    assert_eq!(store.signature_archive(id).unwrap(), None);
    assert_eq!(store.signature_rule_set(id).unwrap(), None);
    assert_eq!(store.signature_push_revision().unwrap(), revision);
    assert_consistent(store, ET);
}

#[test]
fn applying_moves_the_applied_version_to_the_front_of_the_kept_list() {
    let t = setup_store();
    let store = &t.store;

    // No kept version.
    let v1 = stage(store, ET, "a", 1);
    assert_eq!(store.apply_signature_version(v1).unwrap(), 1);
    let source = store.signature_source(ET).unwrap();
    assert_eq!((source.applied, source.staged), (Some(v1), None));
    assert_eq!(source.kept, Vec::<u64>::new());

    // One kept version.
    let v2 = stage(store, ET, "b", 2);
    assert_eq!(store.apply_signature_version(v2).unwrap(), 2);
    let source = store.signature_source(ET).unwrap();
    assert_eq!(source.applied, Some(v2));
    assert_eq!(source.kept, [v1]);
    assert_eq!(state_of(store, v1), Some(SignatureVersionState::Kept));

    // Two kept versions.
    let v3 = apply_new(store, ET, "c", 3);
    let source = store.signature_source(ET).unwrap();
    assert_eq!(source.applied, Some(v3));
    assert_eq!(source.kept, [v2, v1]);

    // The oldest kept version is cut off and deleted with its bytes.
    let v4 = apply_new(store, ET, "d", 4);
    let source = store.signature_source(ET).unwrap();
    assert_eq!(source.applied, Some(v4));
    assert_eq!(source.kept, [v3, v2]);
    assert_eq!(store.signature_version(v1).unwrap(), None);
    assert_eq!(store.signature_archive(v1).unwrap(), None);
    assert_eq!(store.signature_rule_set(v1).unwrap(), None);
    assert_eq!(
        store.signature_rule_set(v2).unwrap(),
        Some(rules_of(v2)),
        "a kept version keeps its rule set"
    );
    assert_eq!(store.signature_archive(v2).unwrap(), Some(archive_of("b")));
    assert_eq!(store.signature_push_revision().unwrap(), 4);
    assert_consistent(store, ET);
}

#[test]
fn rollback_to_either_kept_version() {
    for chosen in [0, 1] {
        let t = setup_store();
        let store = &t.store;
        // Later order keys first, so the rollback goes back in order.
        let a = apply_new(store, ET, "a", 1);
        let b = apply_new(store, ET, "b", 2);
        let c = apply_new(store, ET, "c", 3);
        assert_eq!(store.signature_source(ET).unwrap().kept, [b, a]);
        let (target, other) = if chosen == 0 { (b, a) } else { (a, b) };
        let revision = store.signature_push_revision().unwrap();

        assert_eq!(store.apply_signature_version(target).unwrap(), revision + 1);
        let source = store.signature_source(ET).unwrap();
        assert_eq!(source.applied, Some(target));
        assert_eq!(source.kept, [c, other]);
        assert_eq!(state_of(store, c), Some(SignatureVersionState::Kept));
        assert_eq!(
            store.signature_rule_set(target).unwrap(),
            Some(rules_of(target))
        );
        assert_consistent(store, ET);

        // An ingest is now checked against the rolled-back version.
        ingest(store, ET, "after rollback", key(2026, 3, 2, None)).unwrap();
    }
}

#[test]
fn only_the_most_recent_failed_and_discarded_versions_are_kept() {
    let t = setup_store();
    let store = &t.store;
    let failed: Vec<u64> = (0..3)
        .map(|i| {
            let id = ingest(store, ET, &format!("f{i}"), key(2026, 3, 1, None)).unwrap();
            store
                .fail_signature_conversion(id, &format!("reason {i}"))
                .unwrap();
            id
        })
        .collect();
    let discarded: Vec<u64> = (0..3)
        .map(|i| {
            let id = stage(store, ET, &format!("d{i}"), 1);
            if i % 2 == 0 {
                store.discard_signature_version(id).unwrap();
            }
            id
        })
        .collect();
    // d1 is staged; replacing it by another conversion discards it.
    let last = stage(store, ET, "d3", 1);

    let ids = |state| -> Vec<u64> {
        store
            .signature_versions_in_state(state)
            .unwrap()
            .into_iter()
            .map(|v| v.id)
            .collect()
    };
    assert_eq!(ids(SignatureVersionState::Failed), [failed[2]]);
    assert_eq!(ids(SignatureVersionState::Discarded), [discarded[2]]);
    assert_eq!(ids(SignatureVersionState::Staged), [last]);
    for id in [failed[0], failed[1], discarded[0], discarded[1]] {
        assert_eq!(store.signature_version(id).unwrap(), None, "{id}");
        assert_eq!(store.signature_archive(id).unwrap(), None);
        assert_eq!(store.signature_rule_set(id).unwrap(), None);
    }
    let kept_failed = store.signature_version(failed[2]).unwrap().unwrap();
    assert_eq!(kept_failed.failure_reason.as_deref(), Some("reason 2"));

    // Retention is per source.
    let other = ingest(store, SIGMA, "f", key(2026, 3, 1, None)).unwrap();
    store.fail_signature_conversion(other, "x").unwrap();
    assert_eq!(ids(SignatureVersionState::Failed), [failed[2], other]);
    assert_consistent(store, ET);
    assert_consistent(store, SIGMA);
}

#[test]
fn version_ids_are_never_reused() {
    let t = setup_store();
    let store = &t.store;
    let mut seen = BTreeSet::new();
    let mut last = 0;
    for i in 0..6 {
        let id = ingest(store, ET, &format!("f{i}"), key(2026, 3, 1, None)).unwrap();
        store.fail_signature_conversion(id, "x").unwrap();
        let other = ingest(store, SIGMA, &format!("s{i}"), key(2026, 3, 1, None)).unwrap();
        for id in [id, other] {
            assert!(id > last);
            assert!(seen.insert(id));
            last = id;
        }
    }
    // The earlier failed versions were deleted; their ids are not taken
    // again.
    assert_eq!(
        store
            .signature_versions_in_state(SignatureVersionState::Failed)
            .unwrap()
            .len(),
        1
    );
    let next = ingest(store, ET, "next", key(2026, 3, 1, None)).unwrap();
    assert!(next > last);
}

/// An operation on a version: its name, the states it takes and the call.
type Op<'a> = (
    &'a str,
    &'a [SignatureVersionState],
    Box<dyn Fn(u64) -> Result<()> + 'a>,
);

#[test]
#[allow(clippy::too_many_lines)]
fn operations_on_a_version_in_another_state_are_refused() {
    use SignatureVersionState::{Applied, Converting, Discarded, Failed, Kept, Staged};

    let t = setup_store();
    let store = &t.store;
    let kept = apply_new(store, ET, "kept", 1);
    let applied = apply_new(store, ET, "applied", 2);
    let staged = stage(store, ET, "staged", 3);
    let converting = ingest(store, ET, "converting", key(2026, 3, 4, None)).unwrap();
    let failed = ingest(store, ET, "failed", key(2026, 3, 4, None)).unwrap();
    store.fail_signature_conversion(failed, "x").unwrap();
    let discarded = stage(store, SIGMA, "discarded", 1);
    store.discard_signature_version(discarded).unwrap();
    let unknown = 999;
    let versions = [
        (converting, Converting),
        (staged, Staged),
        (applied, Applied),
        (kept, Kept),
        (failed, Failed),
        (discarded, Discarded),
    ];

    let ops: Vec<Op<'_>> = vec![
        (
            "conversion succeeded",
            &[Converting],
            Box::new(|id| convert(store, id)),
        ),
        (
            "conversion failed",
            &[Converting],
            Box::new(|id| store.fail_signature_conversion(id, "y")),
        ),
        (
            "discard",
            &[Staged],
            Box::new(|id| store.discard_signature_version(id)),
        ),
        (
            "apply",
            &[Staged, Kept],
            Box::new(|id| store.apply_signature_version(id).map(drop)),
        ),
        (
            "reconversion succeeded",
            &[Applied, Kept, Staged],
            Box::new(|id| {
                store
                    .complete_signature_reconversion(
                        id,
                        &SignatureReconversionSuccess {
                            converter_version: "conv-2",
                            rule_set: b"new",
                            summary: "new",
                            previous_rule_count: None,
                            rule_count: 1,
                            time: at(5),
                        },
                    )
                    .map(drop)
            }),
        ),
        (
            "reconversion failed",
            &[Applied, Kept, Staged],
            Box::new(|id| {
                store
                    .fail_signature_reconversion(id, "conv-2", "z", at(5))
                    .map(drop)
            }),
        ),
    ];

    for (name, allowed, op) in &ops {
        for (id, state) in versions {
            if allowed.contains(&state) {
                continue;
            }
            let before = snapshot(store);
            let error = op(id).unwrap_err();
            assert_eq!(
                refusal(&error),
                &SignatureError::InvalidState {
                    version_id: id,
                    state
                },
                "{name} on {state:?}"
            );
            assert_eq!(snapshot(store), before, "{name} on {state:?}");
        }
        let before = snapshot(store);
        let error = op(unknown).unwrap_err();
        assert_eq!(
            refusal(&error),
            &SignatureError::UnknownVersion {
                version_id: unknown
            },
            "{name}"
        );
        assert_eq!(snapshot(store), before, "{name}");
    }
    assert_consistent(store, ET);
    assert_consistent(store, SIGMA);
}

#[test]
fn a_successful_reconversion_replaces_the_rule_set_and_keeps_the_state() {
    let t = setup_store();
    let store = &t.store;
    let kept = apply_new(store, ET, "kept", 1);
    let applied = apply_new(store, ET, "applied", 2);
    let staged = stage(store, ET, "staged", 3);
    let slots = store.signature_source(ET).unwrap();

    for (id, state, raises) in [
        (applied, SignatureVersionState::Applied, true),
        (kept, SignatureVersionState::Kept, false),
        (staged, SignatureVersionState::Staged, false),
    ] {
        let revision = store.signature_push_revision().unwrap();
        let rules = format!("reconverted {id}").into_bytes();
        let summary = format!("summary of reconverted {id}");
        let raised = store
            .complete_signature_reconversion(
                id,
                &SignatureReconversionSuccess {
                    converter_version: "conv-2",
                    rule_set: &rules,
                    summary: &summary,
                    previous_rule_count: (id == kept).then_some(0),
                    rule_count: 42,
                    time: at(500),
                },
            )
            .unwrap();
        assert_eq!(raised, raises.then_some(revision + 1), "{state:?}");
        assert_eq!(
            store.signature_push_revision().unwrap(),
            revision + u64::from(raises)
        );
        let version = store.signature_version(id).unwrap().unwrap();
        assert_eq!(version.state, state);
        assert_eq!(version.converter_version.as_deref(), Some("conv-2"));
        assert_eq!(version.summary.as_deref(), Some(summary.as_str()));
        assert_eq!(store.signature_rule_set(id).unwrap(), Some(rules));
        let source = store.signature_source(ET).unwrap();
        assert_eq!(
            source.last_reconversion,
            Some(SignatureReconversion {
                time: at(500),
                version_id: id,
                previous_converter_version: Some("conv-1".to_owned()),
                attempted_converter_version: "conv-2".to_owned(),
                outcome: SignatureReconversionOutcome::Succeeded {
                    previous_rule_count: (id == kept).then_some(0),
                    rule_count: 42,
                },
            })
        );
        assert_eq!(
            (source.applied, source.kept, source.staged),
            (slots.applied, slots.kept.clone(), slots.staged)
        );
        assert_eq!(source.enabled, slots.enabled);
    }
    assert_consistent(store, ET);
}

#[test]
fn a_failed_reconversion_disables_the_source() {
    let t = setup_store();
    let store = &t.store;
    let applied = apply_new(store, ET, "applied", 1);
    let staged = stage(store, ET, "staged", 2);
    store.set_signature_source_enabled(ET, true).unwrap();
    let revision = store.signature_push_revision().unwrap();
    let before = store.signature_versions_of_source(ET).unwrap();

    assert_eq!(
        store
            .fail_signature_reconversion(staged, "conv-9", "unsupported keyword", at(700))
            .unwrap(),
        Some(revision + 1)
    );
    let source = store.signature_source(ET).unwrap();
    assert!(!source.enabled);
    assert_eq!(source.applied, Some(applied));
    assert_eq!(source.staged, Some(staged));
    assert_eq!(
        source.last_reconversion,
        Some(SignatureReconversion {
            time: at(700),
            version_id: staged,
            previous_converter_version: Some("conv-1".to_owned()),
            attempted_converter_version: "conv-9".to_owned(),
            outcome: SignatureReconversionOutcome::Failed {
                reason: "unsupported keyword".to_owned(),
            },
        })
    );
    assert_eq!(store.signature_versions_of_source(ET).unwrap(), before);
    assert_eq!(
        store.signature_rule_set(staged).unwrap(),
        Some(rules_of(staged))
    );

    // On a source already disabled it raises nothing, and records it.
    assert_eq!(
        store
            .fail_signature_reconversion(applied, "conv-9", "again", at(800))
            .unwrap(),
        None
    );
    assert_eq!(store.signature_push_revision().unwrap(), revision + 1);
    let record = store
        .signature_source(ET)
        .unwrap()
        .last_reconversion
        .unwrap();
    assert_eq!((record.version_id, record.time), (applied, at(800)));
}

#[test]
fn enabling_and_disabling_a_source_leaves_its_versions() {
    let t = setup_store();
    let store = &t.store;
    // Enabling needs no applied version.
    assert_eq!(
        store.set_signature_source_enabled(SIGMA, true).unwrap(),
        Some(1)
    );
    assert!(store.signature_source(SIGMA).unwrap().enabled);
    let staged = stage(store, SIGMA, "a", 1);
    assert_eq!(
        store.set_signature_source_enabled(SIGMA, false).unwrap(),
        Some(2)
    );
    let source = store.signature_source(SIGMA).unwrap();
    assert!(!source.enabled);
    assert_eq!(source.staged, Some(staged));
    // Operations do not depend on the flag.
    store.apply_signature_version(staged).unwrap();
    assert!(!store.signature_source(SIGMA).unwrap().enabled);
}

#[test]
fn rule_overrides_are_kept_across_versions() {
    let t = setup_store();
    let store = &t.store;
    let a = apply_new(store, ET, "a", 1);
    assert_eq!(
        store
            .disable_signature_rule(ET, "2013028", "alice", at(10))
            .unwrap(),
        Some(2)
    );
    store
        .disable_signature_rule(SIGMA, "5f1abf38-3f42-4e6b-9c4a-ff0c1d1d3ad2", "bob", at(11))
        .unwrap();
    store
        .disable_signature_rule(ET, "2000001", "bob", at(12))
        .unwrap();

    // Turning off a rule already off keeps the first account and time.
    let before = snapshot(store);
    assert_eq!(
        store
            .disable_signature_rule(ET, "2013028", "carol", at(99))
            .unwrap(),
        None
    );
    assert_eq!(snapshot(store), before);
    // Turning on a rule that is not off changes nothing.
    assert_eq!(store.enable_signature_rule(ET, "1").unwrap(), None);
    assert_eq!(store.enable_signature_rule(SIGMA, "2013028").unwrap(), None);
    assert_eq!(snapshot(store), before);

    let expected_rules = vec![
        (ET, "2000001".to_owned()),
        (ET, "2013028".to_owned()),
        (SIGMA, "5f1abf38-3f42-4e6b-9c4a-ff0c1d1d3ad2".to_owned()),
    ];
    let check = |store: &Store| {
        assert_eq!(store.signature_disabled_rules().unwrap(), expected_rules);
        let overrides = store.signature_rule_overrides().unwrap();
        assert_eq!(
            overrides.get(1),
            Some(&SignatureRuleOverride {
                source: ET,
                rule_id: "2013028".to_owned(),
                account: "alice".to_owned(),
                time: at(10),
            })
        );
    };
    check(store);

    // A new version whose rules differ, its apply and a rollback.
    let b = apply_new(store, ET, "b with another rule revision", 2);
    check(store);
    store.apply_signature_version(a).unwrap();
    check(store);
    store
        .complete_signature_reconversion(
            a,
            &SignatureReconversionSuccess {
                converter_version: "conv-2",
                rule_set: b"other",
                summary: "",
                previous_rule_count: Some(3),
                rule_count: 3,
                time: at(20),
            },
        )
        .unwrap();
    check(store);
    assert_eq!(store.signature_source(ET).unwrap().kept, [b]);

    let revision = store.signature_push_revision().unwrap();
    assert_eq!(
        store.enable_signature_rule(ET, "2013028").unwrap(),
        Some(revision + 1)
    );
    assert_eq!(
        store.signature_disabled_rules().unwrap(),
        [
            (ET, "2000001".to_owned()),
            (SIGMA, "5f1abf38-3f42-4e6b-9c4a-ff0c1d1d3ad2".to_owned()),
        ]
    );
    // Turned off again, it takes the new account and time.
    store
        .disable_signature_rule(ET, "2013028", "carol", at(30))
        .unwrap();
    let overrides = store.signature_rule_overrides().unwrap();
    assert_eq!(
        overrides
            .iter()
            .find(|o| o.rule_id == "2013028")
            .map(|o| (o.account.as_str(), o.time)),
        Some(("carol", at(30)))
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn the_push_revision_rises_once_per_change_and_never_on_a_no_op() {
    let t = setup_store();
    let store = &t.store;
    let mut expected = 0;
    let mut raised = |value: Option<u64>, raises: bool, what: &str| {
        if raises {
            expected += 1;
            assert_eq!(value, Some(expected), "{what}");
        } else {
            assert_eq!(value, None, "{what}");
        }
        assert_eq!(store.signature_push_revision().unwrap(), expected, "{what}");
    };

    // Ingest, conversion results and discards raise nothing.
    let first = ingest(store, ET, "a", key(2026, 3, 1, None)).unwrap();
    raised(None, false, "ingest");
    convert(store, first).unwrap();
    raised(None, false, "conversion");
    let failed = ingest(store, ET, "f", key(2026, 3, 1, None)).unwrap();
    store.fail_signature_conversion(failed, "x").unwrap();
    raised(None, false, "failed conversion");

    raised(store.apply_signature_version(first).ok(), true, "apply");
    let second = stage(store, ET, "b", 2);
    raised(
        store.apply_signature_version(second).ok(),
        true,
        "apply another",
    );
    raised(store.apply_signature_version(first).ok(), true, "rollback");
    let dropped = stage(store, ET, "d", 3);
    store.discard_signature_version(dropped).unwrap();
    raised(None, false, "discard");

    raised(
        store.set_signature_source_enabled(ET, true).unwrap(),
        true,
        "enable",
    );
    raised(
        store.set_signature_source_enabled(ET, true).unwrap(),
        false,
        "enable again",
    );
    raised(
        store.set_signature_source_enabled(SIGMA, false).unwrap(),
        false,
        "disable a source without a row",
    );
    raised(
        store
            .disable_signature_rule(ET, "1", "alice", at(1))
            .unwrap(),
        true,
        "rule off",
    );
    raised(
        store.disable_signature_rule(ET, "1", "bob", at(2)).unwrap(),
        false,
        "rule already off",
    );
    raised(
        store.enable_signature_rule(ET, "1").unwrap(),
        true,
        "rule on",
    );
    raised(
        store.enable_signature_rule(ET, "1").unwrap(),
        false,
        "rule not off",
    );

    let success = |id| {
        store
            .complete_signature_reconversion(
                id,
                &SignatureReconversionSuccess {
                    converter_version: "conv-2",
                    rule_set: b"r",
                    summary: "s",
                    previous_rule_count: None,
                    rule_count: 1,
                    time: at(3),
                },
            )
            .unwrap()
    };
    raised(success(first), true, "reconversion of the applied version");
    raised(success(second), false, "reconversion of a kept version");
    let staged = stage(store, ET, "s", 4);
    raised(success(staged), false, "reconversion of the staged version");

    raised(
        store
            .fail_signature_reconversion(staged, "conv-3", "x", at(4))
            .unwrap(),
        true,
        "failed reconversion disabling the source",
    );
    raised(
        store
            .fail_signature_reconversion(first, "conv-3", "x", at(5))
            .unwrap(),
        false,
        "failed reconversion on a disabled source",
    );
}

#[test]
fn concurrent_ingests_get_distinct_ids() {
    const THREADS: usize = 8;
    let t = setup_store();
    let store = &t.store;
    let barrier = std::sync::Barrier::new(THREADS);
    let ids: Vec<u64> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..THREADS)
            .map(|i| {
                let barrier = &barrier;
                s.spawn(move || {
                    barrier.wait();
                    ingest(store, ET, &format!("c{i}"), key(2026, 3, 1, None)).unwrap()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let distinct: BTreeSet<_> = ids.iter().copied().collect();
    assert_eq!(distinct.len(), THREADS);
    assert_eq!(
        store
            .signature_versions_in_state(SignatureVersionState::Converting)
            .unwrap()
            .into_iter()
            .map(|v| v.id)
            .collect::<BTreeSet<_>>(),
        distinct
    );
    for id in ids {
        assert!(store.signature_archive(id).unwrap().is_some());
    }
}

#[test]
fn concurrent_version_operations_keep_the_slots_consistent() {
    const ROUNDS: usize = 6;
    let t = setup_store();
    let store = &t.store;
    let base = apply_new(store, ET, "base", 1);
    let mut previous = base;
    for i in 0..ROUNDS {
        let converting: Vec<u64> = (0..4)
            .map(|j| ingest(store, ET, &format!("r{i}-{j}"), key(2026, 3, 1, None)).unwrap())
            .collect();
        let staged = stage(store, ET, &format!("r{i}-staged"), 1);
        let revision = store.signature_push_revision().unwrap();
        let barrier = std::sync::Barrier::new(7);
        let results: Vec<Result<Option<u64>>> = std::thread::scope(|s| {
            let barrier = &barrier;
            let mut handles = Vec::new();
            for id in converting.iter().copied().take(2) {
                handles.push(s.spawn(move || {
                    barrier.wait();
                    convert(store, id).map(|()| None)
                }));
            }
            for id in converting.iter().copied().skip(2) {
                handles.push(s.spawn(move || {
                    barrier.wait();
                    store.fail_signature_conversion(id, "x").map(|()| None)
                }));
            }
            for _ in 0..2 {
                handles.push(s.spawn(move || {
                    barrier.wait();
                    store.apply_signature_version(staged).map(Some)
                }));
            }
            handles.push(s.spawn(move || {
                barrier.wait();
                store.discard_signature_version(staged).map(|()| None)
            }));
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        // Every conversion result succeeds.
        for result in &results[..4] {
            assert!(result.is_ok(), "{result:?}");
        }
        // Of the two applies and the discard of one staged version, exactly
        // one succeeds, or none if a conversion replaced it first.
        let succeeded = results[4..].iter().filter(|r| r.is_ok()).count();
        assert!(succeeded <= 1, "{results:?}");
        let applied = results[4..6].iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            store.signature_push_revision().unwrap(),
            revision + u64::try_from(applied).unwrap()
        );
        let source = store.signature_source(ET).unwrap();
        if applied == 1 {
            assert_eq!(source.applied, Some(staged));
            assert_eq!(source.kept.first(), Some(&previous));
        } else {
            assert_eq!(source.applied, Some(previous));
        }
        assert_consistent(store, ET);
        // The two conversions both succeeded, so one of them is staged and
        // the other, or the staged version, is discarded.
        assert!(converting[..2].contains(&source.staged.unwrap()));
        let failed = store
            .signature_versions_in_state(SignatureVersionState::Failed)
            .unwrap();
        assert_eq!(failed.len(), 1);
        assert!(converting[2..].contains(&failed[0].id));
        if let Some(staged) = source.staged {
            store.apply_signature_version(staged).unwrap();
            previous = staged;
        }
        assert_consistent(store, ET);
    }
}

/// A conversion that has read its source's row, naming staged version `S`,
/// while two other conversions commit — the first discarding `S`, the
/// second deleting it as the older discarded version — still succeeds, as
/// it does when it runs after both.
#[test]
fn a_conversion_survives_its_staged_version_retiring_after_it_read_the_source() {
    let t = setup_store();
    let store = &t.store;
    let staged = stage(store, ET, "s", 1);
    let [paused, first, second] =
        ["a", "b", "c"].map(|d| ingest(store, ET, d, key(2026, 3, 2, None)).unwrap());

    let (read_tx, read_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel::<()>();
    let result = std::thread::scope(|scope| {
        let paused_thread = scope.spawn(move || {
            let mut pause = Some((read_tx, resume_rx));
            AFTER_SOURCE_READ.with_borrow_mut(|hook| {
                *hook = Some(Box::new(move || {
                    if let Some((read, resume)) = pause.take() {
                        read.send(()).unwrap();
                        resume.recv().unwrap();
                    }
                }));
            });
            convert(store, paused)
        });
        read_rx.recv().unwrap();
        convert(store, first).unwrap();
        convert(store, second).unwrap();
        assert_eq!(state_of(store, staged), None);
        resume_tx.send(()).unwrap();
        paused_thread.join().unwrap()
    });

    result.unwrap();
    let source = store.signature_source(ET).unwrap();
    assert_eq!(source.staged, Some(paused));
    assert_eq!(state_of(store, paused), Some(SignatureVersionState::Staged));
    assert_eq!(
        state_of(store, second),
        Some(SignatureVersionState::Discarded)
    );
    assert_eq!(state_of(store, first), None);
    assert_consistent(store, ET);
}

#[test]
fn concurrent_revision_raising_operations_yield_distinct_values() {
    const RULES: u64 = 8;
    let t = setup_store();
    let store = &t.store;
    let staged = stage(store, SIGMA, "a", 1);
    // Two threads per rule, two applies of one staged version and two
    // enables of one source.
    let threads = usize::try_from(RULES).unwrap() * 2 + 4;
    let barrier = std::sync::Barrier::new(threads);
    let values: Vec<Option<u64>> = std::thread::scope(|s| {
        let barrier = &barrier;
        let mut handles = Vec::new();
        for i in 0..RULES {
            handles.push(s.spawn(move || {
                barrier.wait();
                store
                    .disable_signature_rule(ET, &i.to_string(), "a", at(1))
                    .unwrap()
            }));
            // Half of these repeat a rule another thread turns off.
            handles.push(s.spawn(move || {
                barrier.wait();
                store
                    .disable_signature_rule(ET, &(i / 2).to_string(), "b", at(2))
                    .unwrap()
            }));
        }
        for _ in 0..2 {
            // Only one apply finds the version staged.
            handles.push(s.spawn(move || {
                barrier.wait();
                store.apply_signature_version(staged).ok()
            }));
            // Only one enable changes the flag.
            handles.push(s.spawn(move || {
                barrier.wait();
                store.set_signature_source_enabled(EMERGING, true).unwrap()
            }));
        }
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let changes = RULES + 2;
    let raised: Vec<u64> = values.into_iter().flatten().collect();
    let distinct: BTreeSet<_> = raised.iter().copied().collect();
    assert_eq!(distinct.len(), raised.len());
    assert_eq!(u64::try_from(raised.len()).unwrap(), changes);
    assert_eq!(distinct, (1..=changes).collect());
    assert_eq!(store.signature_push_revision().unwrap(), changes);
    assert_eq!(
        store.signature_disabled_rules().unwrap().len(),
        usize::try_from(RULES).unwrap()
    );
    assert_eq!(store.signature_source(SIGMA).unwrap().applied, Some(staged));
    assert!(store.signature_source(EMERGING).unwrap().enabled);
    assert_consistent(store, SIGMA);
}

fn agent(key: &str, kind: AgentKind) -> Agent {
    Agent::new(0, key.to_string(), kind, AgentStatus::Enabled, None, None).unwrap()
}

fn insert_node(store: &Store, name: &str) -> Node {
    let mut node = Node {
        id: 0,
        name: name.to_string(),
        name_draft: None,
        profile: Some(NodeProfile {
            customer_id: 1,
            description: String::new(),
            hostname: format!("{name}.example"),
        }),
        profile_draft: None,
        agents: vec![
            agent(HOG, AgentKind::SemiSupervised),
            agent(OTHER_HOG, AgentKind::SemiSupervised),
            agent(ENGINE, AgentKind::Unsupervised),
            agent("piglet", AgentKind::Sensor),
        ],
        external_services: Vec::new(),
        creation_time: at(0),
    };
    node.id = store.node_map().put(&node).unwrap();
    for agent in &mut node.agents {
        agent.node_id = node.id;
    }
    node
}

fn instance(node_id: u32, agent_key: &str) -> ModelInstance {
    ModelInstance {
        node_id,
        agent_key: agent_key.to_string(),
    }
}

fn truncated(
    model: DetectionModel,
    source: SignatureSource,
    rule_id: &str,
    window_start: Timestamp,
    count: u64,
) -> TruncatedCount {
    TruncatedCount {
        detection_model: model,
        source,
        rule_id: rule_id.to_owned(),
        orig_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        window_start: i64::try_from(window_start.as_nanosecond()).unwrap(),
        count,
    }
}

fn report(truncated: Vec<TruncatedCount>) -> SignatureStatusReport {
    SignatureStatusReport {
        loaded: vec![LoadedSignatureSet {
            source: ET,
            source_version: "7000".to_owned(),
            converter_version: "conv-1".to_owned(),
            rules: 10,
            failed_compile: 1,
            load_error: None,
        }],
        truncated,
        truncated_overflow: 3,
        os_gated_skipped: vec![(RawEventKind::Http, 2)],
        home_net_fallback: true,
    }
}

fn status_rows(store: &Store) -> usize {
    let db = store.states.db();
    let cf = db.cf_handle(tables::SIGNATURE_STATUS).unwrap();
    db.iterator_cf(cf, IteratorMode::Start).count()
}

#[test]
fn a_status_report_is_stored_and_replaced_per_instance() {
    let t = setup_store();
    let store = &t.store;
    let node = insert_node(store, "node");
    let hog = instance(node.id, HOG);
    let other = instance(node.id, OTHER_HOG);
    assert_eq!(store.signature_status(&hog).unwrap(), None);

    let first = report(Vec::new());
    store
        .set_signature_status_report(&hog, &first, at(10))
        .unwrap();
    assert_eq!(
        store.signature_status(&hog).unwrap(),
        Some(SignatureStatus {
            report: first.clone(),
            received_at: at(10),
        })
    );
    assert_eq!(store.signature_status(&other).unwrap(), None);

    let mut second = report(Vec::new());
    second.loaded.clear();
    second.home_net_fallback = false;
    store
        .set_signature_status_report(&hog, &second, at(20))
        .unwrap();
    store
        .set_signature_status_report(&other, &first, at(30))
        .unwrap();
    assert_eq!(
        store.signature_statuses().unwrap(),
        [
            (
                hog.clone(),
                SignatureStatus {
                    report: second,
                    received_at: at(20),
                }
            ),
            (
                other,
                SignatureStatus {
                    report: first,
                    received_at: at(30),
                }
            ),
        ]
    );
}

#[test]
fn a_status_report_of_another_agent_is_refused() {
    let t = setup_store();
    let store = &t.store;
    let node = insert_node(store, "node");
    let counted = report(vec![truncated(
        DetectionModel::EtSignature,
        ET,
        "1",
        at(0),
        5,
    )]);
    store
        .set_signature_status_report(&instance(node.id, HOG), &report(Vec::new()), at(1))
        .unwrap();
    let before = snapshot(store);
    for refused in [
        instance(node.id, ENGINE),
        instance(node.id, "piglet"),
        instance(node.id, "missing"),
        instance(node.id + 1, HOG),
    ] {
        let error = store
            .set_signature_status_report(&refused, &counted, at(2))
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<EngineDocumentError>(),
            Some(&EngineDocumentError::NotSemiSupervisedAgent {
                node_id: refused.node_id,
                agent_key: refused.agent_key.clone(),
            }),
            "{refused:?}"
        );
        assert_eq!(snapshot(store), before);
    }
}

#[test]
fn removing_the_agent_or_its_node_removes_its_status() {
    let t = setup_store();
    let store = &t.store;
    let node = insert_node(store, "node");
    let kept = insert_node(store, "kept");
    for n in [&node, &kept] {
        for key in [HOG, OTHER_HOG] {
            store
                .set_signature_status_report(&instance(n.id, key), &report(Vec::new()), at(1))
                .unwrap();
        }
    }
    assert_eq!(status_rows(store), 4);

    let mut removed = node.clone();
    removed.agents.retain(|a| a.key != HOG);
    store
        .node_map()
        .update(node.id, &node.clone().into(), &removed.clone().into())
        .unwrap();
    assert_eq!(
        store.signature_status(&instance(node.id, HOG)).unwrap(),
        None
    );
    assert!(
        store
            .signature_status(&instance(node.id, OTHER_HOG))
            .unwrap()
            .is_some()
    );
    assert_eq!(status_rows(store), 3);

    store.node_map().remove(node.id).unwrap();
    assert_eq!(
        store
            .signature_status(&instance(node.id, OTHER_HOG))
            .unwrap(),
        None
    );
    assert_eq!(status_rows(store), 2);
    for key in [HOG, OTHER_HOG] {
        assert!(
            store
                .signature_status(&instance(kept.id, key))
                .unwrap()
                .is_some()
        );
    }
}

fn daily(
    day: Date,
    model: DetectionModel,
    source: SignatureSource,
    rule_id: &str,
    count: u64,
) -> SignatureTruncationDaily {
    SignatureTruncationDaily {
        date: day,
        detection_model: model,
        source,
        rule_id: rule_id.to_owned(),
        count,
    }
}

#[test]
fn truncated_counts_add_into_daily_sums() {
    let t = setup_store();
    let store = &t.store;
    let node = insert_node(store, "node");
    let hog = instance(node.id, HOG);
    let other = instance(node.id, OTHER_HOG);
    let et = DetectionModel::EtSignature;
    let sigma = DetectionModel::SigmaSignature;
    let day1 = crate::test::utc_nano(2026, 3, 14, 0, 0, 0, 0);
    let late1 = crate::test::utc_nano(2026, 3, 14, 23, 59, 59, 999_999_999);
    let day2 = crate::test::utc_nano(2026, 3, 15, 0, 0, 0, 0);

    store
        .set_signature_status_report(
            &hog,
            &report(vec![
                truncated(et, ET, "2013028", day1, 5),
                truncated(et, ET, "2013028", late1, 7),
                truncated(sigma, SIGMA, "abc", day1, 1),
                truncated(et, ET, "2013028", day2, 2),
            ]),
            at(1),
        )
        .unwrap();
    store
        .set_signature_status_report(
            &other,
            &report(vec![
                truncated(et, ET, "2013028", day1, 10),
                truncated(sigma, EMERGING, "abc", day1, u64::MAX - 1),
            ]),
            at(2),
        )
        .unwrap();
    // A later report of the same instance adds again, saturating.
    store
        .set_signature_status_report(
            &other,
            &report(vec![truncated(sigma, EMERGING, "abc", late1, 5)]),
            at(3),
        )
        .unwrap();

    assert_eq!(
        store.signature_truncation_daily(date(2026, 3, 14)).unwrap(),
        [
            daily(date(2026, 3, 14), et, ET, "2013028", 22),
            daily(date(2026, 3, 14), sigma, SIGMA, "abc", 1),
            daily(date(2026, 3, 14), sigma, EMERGING, "abc", u64::MAX),
        ]
    );
    assert_eq!(
        store.signature_truncation_daily(date(2026, 3, 15)).unwrap(),
        [daily(date(2026, 3, 15), et, ET, "2013028", 2)]
    );
    assert_eq!(
        store.signature_truncation_daily(date(2026, 3, 13)).unwrap(),
        Vec::new()
    );

    // Saturation within a single report, before any row exists.
    store
        .set_signature_status_report(
            &hog,
            &report(vec![
                truncated(et, ET, "9", day2, u64::MAX),
                truncated(et, ET, "9", day2, 1),
            ]),
            at(4),
        )
        .unwrap();
    assert_eq!(
        store.signature_truncation_daily(date(2026, 3, 15)).unwrap(),
        [
            daily(date(2026, 3, 15), et, ET, "2013028", 2),
            daily(date(2026, 3, 15), et, ET, "9", u64::MAX),
        ]
    );

    // A window before the epoch falls on its UTC date.
    let before_epoch = crate::test::utc_nano(1969, 12, 31, 12, 0, 0, 0);
    store
        .set_signature_status_report(
            &hog,
            &report(vec![truncated(et, ET, "1", before_epoch, 1)]),
            at(5),
        )
        .unwrap();
    assert_eq!(
        store
            .signature_truncation_daily(date(1969, 12, 31))
            .unwrap(),
        [daily(date(1969, 12, 31), et, ET, "1", 1)]
    );
}

#[test]
fn pruning_deletes_the_daily_sums_before_the_date() {
    let t = setup_store();
    let store = &t.store;
    let node = insert_node(store, "node");
    let hog = instance(node.id, HOG);
    let et = DetectionModel::EtPolicySignature;
    let counts = [12, 13, 14, 15]
        .into_iter()
        .map(|day| {
            truncated(
                et,
                ET,
                "1",
                crate::test::utc_nano(2026, 3, day, 12, 0, 0, 0),
                1,
            )
        })
        .collect();
    store
        .set_signature_status_report(&hog, &report(counts), at(1))
        .unwrap();

    assert_eq!(
        store
            .prune_signature_truncation_daily(date(2026, 3, 14))
            .unwrap(),
        2
    );
    for (day, rows) in [(12, 0), (13, 0), (14, 1), (15, 1)] {
        assert_eq!(
            store
                .signature_truncation_daily(date(2026, 3, day))
                .unwrap()
                .len(),
            rows,
            "{day}"
        );
    }
    assert_eq!(
        store
            .prune_signature_truncation_daily(date(2026, 3, 14))
            .unwrap(),
        0
    );
    // The stored status report is left as it is.
    assert!(store.signature_status(&hog).unwrap().is_some());
}

#[test]
fn customer_data_deletion_leaves_the_signature_records() {
    let t = setup_store();
    let store = &t.store;
    let node = insert_node(store, "node");
    let applied = apply_new(store, ET, "a", 1);
    apply_new(store, ET, "b", 2);
    stage(store, ET, "c", 3);
    ingest(store, SIGMA, "d", key(2026, 3, 1, None)).unwrap();
    store.set_signature_source_enabled(ET, true).unwrap();
    store
        .fail_signature_reconversion(applied, "conv-2", "x", at(1))
        .unwrap();
    store
        .disable_signature_rule(ET, "1", "alice", at(1))
        .unwrap();
    store
        .set_signature_status_report(
            &instance(node.id, HOG),
            &report(vec![truncated(
                DetectionModel::EtSignature,
                ET,
                "1",
                at(0),
                3,
            )]),
            at(2),
        )
        .unwrap();
    let before = snapshot(store);
    assert!(before.values().all(|rows| !rows.is_empty()), "{before:?}");

    let customer_id = 1;
    store
        .create_customer_data_deletion_job(&CustomerDataDeletionJob::new(customer_id, Vec::new()))
        .unwrap();
    store
        .delete_dai_customer(customer_id, &["piglet.node.example".to_owned()])
        .unwrap();
    store
        .remove_customer_unsupervised_records(customer_id)
        .unwrap();
    store
        .time_series_generation_policy_map()
        .remove_customer_policies(customer_id)
        .unwrap();
    store.network_lists_map().remove(customer_id).unwrap();
    store.customer_networks_map().remove(customer_id).unwrap();
    store
        .events()
        .remove_by_sensors(&["piglet.node.example".to_owned()])
        .unwrap();

    assert_eq!(snapshot(store), before);
}
