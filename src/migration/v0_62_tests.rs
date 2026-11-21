//! Tests of the 0.62.0 step, [`super::migrate_0_61_to_0_62`], and of the
//! rules [`super::migrate_data_dir`] follows for a chain that stopped inside
//! it or between its two `VERSION` writes.

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
};

use bincode::Options;
use jiff::Timestamp;
use semver::Version;

use super::migration_structures::{
    ClusterValue, EngineInstanceRowValue, ModelRunValue, ModelValue, NetworkListSetValue,
    NetworkValue, NodeValue, OperationAttemptValue, OwnedNetworkSetValue, SamplingPolicyValue,
    SystemLogCollectorValue, TimestampConverter, TrafficFilterValue, TrainingDefinitionValue,
    TriageResponseValue,
};
use super::tests::{run_steps_to_v0_61, write_version};
use super::{
    DATABASE_FORMAT_VERSION, INDEXED_FAMILIES_V0_62, OPERATION_ATTEMPT_EXPIRES_AT_V0_62,
    OPERATION_ATTEMPT_RESERVED_V0_49, OldTimestampText, TIMESTAMP_FAMILIES_V0_62,
    V0_62_STARTED_KEY, VERSION_FILE_NAME, migrate_0_61_to_0_62, migrate_0_61_to_0_62_inner,
    migrate_data_dir, old_timestamp_nanos_v0_62, read_version_file, rewrite_value_v0_62,
    v0_62_completed_key,
};
use crate::tables::{
    CLUSTER, CUSTOMER_NETWORKS, ENGINE_INSTANCES, FORMAT_0_62, META, MODEL_RUNS, MODELS,
    NETWORK_LISTS, NETWORKS, NODES, OPERATION_ATTEMPTS, PREVIOUS_CLUSTER, SAMPLING_POLICY,
    SYSTEM_LOG_COLLECTORS, TOR_EXIT_NODES, TRAFFIC_FILTER_RULES, TRAINING_DEFINITIONS,
    TRIAGE_RESPONSE, TRUSTED_USER_AGENTS,
};
use crate::test::{
    acquire_db_permit, v0_61_display_string, v0_61_naive_string, v0_61_serde_string,
};
use crate::{
    Indexable, Network, OperationAction, OperationAttempt, OperationOutcome, OperationPhase,
    OperationRetryPolicy, Store, TorExitNode, TriageResponse, TrustedUserAgent, UniqueKey,
};

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// Every row of a store, by column family name, `default` included.
type Snapshot = BTreeMap<String, Rows>;

const NANOS_PER_SECOND: i64 = 1_000_000_000;

/// Opens the states database at `db_path` with every family it has.
fn open_db(db_path: &Path) -> rocksdb::OptimisticTransactionDB {
    let opts = rocksdb::Options::default();
    let families = super::existing_map_names(&opts, db_path).unwrap();
    rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, families).unwrap()
}

/// Returns every row of the states database at `db_path`.
fn snapshot(db_path: &Path) -> Snapshot {
    let db = open_db(db_path);
    let mut rows = Snapshot::new();
    rows.insert(
        "default".to_string(),
        db.iterator(rocksdb::IteratorMode::Start)
            .map(|entry| {
                let (key, value) = entry.unwrap();
                (key.to_vec(), value.to_vec())
            })
            .collect(),
    );
    for name in super::existing_map_names(&rocksdb::Options::default(), db_path).unwrap() {
        let cf = db.cf_handle(&name).unwrap();
        let entries = db
            .iterator_cf(&cf, rocksdb::IteratorMode::Start)
            .map(|entry| {
                let (key, value) = entry.unwrap();
                (key.to_vec(), value.to_vec())
            })
            .collect();
        rows.insert(name, entries);
    }
    rows
}

/// Returns `snapshot` with the markers the 0.62.0 step writes to `meta` left
/// out.
fn without_markers(mut snapshot: Snapshot) -> Snapshot {
    if let Some(meta) = snapshot.get_mut(META) {
        meta.retain(|(key, _)| !key.starts_with(b"migration/0.62.0/"));
    }
    snapshot
}

/// Returns whether `key` of family `cf_name` is a record the 0.62.0 step
/// rewrites rather than an index row it leaves alone.
fn is_record(cf_name: &str, key: &[u8]) -> bool {
    if cf_name == OPERATION_ATTEMPTS {
        key.first() < Some(&OPERATION_ATTEMPT_RESERVED_V0_49)
    } else {
        !(INDEXED_FAMILIES_V0_62.contains(&cf_name) && key.is_empty())
    }
}

fn decode<T: serde::de::DeserializeOwned>(value: &[u8]) -> T {
    bincode::DefaultOptions::new().deserialize(value).unwrap()
}

fn encode<T: serde::Serialize>(value: &T) -> Vec<u8> {
    bincode::DefaultOptions::new().serialize(value).unwrap()
}

/// Decodes the 0.62 record `value` of `cf_name`, converts every timestamp
/// with `ts`, and encodes the result.
fn remap_v0_62_record<U: serde::Serialize>(
    cf_name: &str,
    value: &[u8],
    ts: &mut TimestampConverter<'_, i64, U>,
) -> Vec<u8> {
    match cf_name {
        TRIAGE_RESPONSE => encode(
            &decode::<TriageResponseValue<i64>>(value)
                .map_timestamps(ts)
                .unwrap(),
        ),
        OPERATION_ATTEMPTS => encode(
            &decode::<OperationAttemptValue<i64>>(value)
                .map_timestamps(ts)
                .unwrap(),
        ),
        TOR_EXIT_NODES | TRUSTED_USER_AGENTS => encode(&ts(decode::<i64>(value)).unwrap()),
        CLUSTER | PREVIOUS_CLUSTER => encode(
            &decode::<ClusterValue<i64>>(value)
                .map_timestamps(ts)
                .unwrap(),
        ),
        NODES => encode(&decode::<NodeValue<i64>>(value).map_timestamps(ts).unwrap()),
        NETWORKS => encode(
            &decode::<NetworkValue<i64>>(value)
                .map_timestamps(ts)
                .unwrap(),
        ),
        NETWORK_LISTS => encode(
            &decode::<NetworkListSetValue<i64>>(value)
                .map_timestamps(ts)
                .unwrap(),
        ),
        CUSTOMER_NETWORKS => encode(
            &decode::<OwnedNetworkSetValue<i64>>(value)
                .map_timestamps(ts)
                .unwrap(),
        ),
        SAMPLING_POLICY => encode(
            &decode::<SamplingPolicyValue<i64>>(value)
                .map_timestamps(ts)
                .unwrap(),
        ),
        TRAFFIC_FILTER_RULES => encode(
            &decode::<TrafficFilterValue<i64>>(value)
                .map_timestamps(ts)
                .unwrap(),
        ),
        TRAINING_DEFINITIONS => encode(
            &decode::<TrainingDefinitionValue<i64>>(value)
                .map_timestamps(ts)
                .unwrap(),
        ),
        MODEL_RUNS => encode(
            &decode::<ModelRunValue<i64>>(value)
                .map_timestamps(ts)
                .unwrap(),
        ),
        MODELS => encode(&decode::<ModelValue<i64>>(value).map_timestamps(ts).unwrap()),
        ENGINE_INSTANCES => encode(
            &decode::<EngineInstanceRowValue<i64>>(value)
                .map_timestamps(ts)
                .unwrap(),
        ),
        SYSTEM_LOG_COLLECTORS => encode(
            &decode::<SystemLogCollectorValue<i64>>(value)
                .map_timestamps(ts)
                .unwrap(),
        ),
        _ => panic!("{cf_name} is not a family the 0.62.0 step rewrites"),
    }
}

/// Returns every timestamp the 0.62 record `value` of `cf_name` stores.
fn timestamps_of(cf_name: &str, value: &[u8]) -> Vec<i64> {
    let mut found = Vec::new();
    remap_v0_62_record(cf_name, value, &mut |nanos| {
        found.push(nanos);
        Ok(nanos)
    });
    found
}

/// Returns the 0.61 text of `nanos` in `form`.
fn v0_61_text(nanos: i64, form: OldTimestampText) -> String {
    let time = crate::timestamp::from_i64_nanos(nanos).unwrap();
    match form {
        OldTimestampText::Serde => v0_61_serde_string(time),
        OldTimestampText::Naive => v0_61_naive_string(time),
        OldTimestampText::Display => v0_61_display_string(time),
    }
}

/// Returns the 0.61 bytes of the 0.62 record `value` of `cf_name`: every
/// timestamp as the text 0.61 stored it.
fn v0_61_record(cf_name: &str, value: &[u8]) -> Vec<u8> {
    v0_61_record_with(cf_name, value, &mut v0_61_text)
}

/// Returns the 0.61 bytes of the 0.62 record `value` of `cf_name`, every
/// timestamp written as `text` gives it for the stored nanoseconds and the
/// form 0.61 stored that field in.
fn v0_61_record_with(
    cf_name: &str,
    value: &[u8],
    text: &mut dyn FnMut(i64, OldTimestampText) -> String,
) -> Vec<u8> {
    match cf_name {
        TOR_EXIT_NODES | TRUSTED_USER_AGENTS => {
            text(decode::<i64>(value), OldTimestampText::Display).into_bytes()
        }
        CLUSTER | PREVIOUS_CLUSTER => remap_v0_62_record(cf_name, value, &mut |nanos| {
            Ok(text(nanos, OldTimestampText::Naive))
        }),
        _ => remap_v0_62_record(cf_name, value, &mut |nanos| {
            Ok(text(nanos, OldTimestampText::Serde))
        }),
    }
}

/// Builds a 0.61 store in `data_dir` holding the rows of `live`, a snapshot
/// of a store this build wrote: every family but `format 0.62`, every record
/// of [`TIMESTAMP_FAMILIES_V0_62`] in its 0.61 bytes and every other row as
/// it is. Both directories read `0.61.0`.
fn build_v0_61_store(data_dir: &Path, backup_dir: &Path, live: &Snapshot) {
    build_v0_61_store_with(data_dir, backup_dir, live, &mut v0_61_text);
}

/// Builds a 0.61 store as [`build_v0_61_store`] does, every timestamp of a
/// record written as `text` gives it.
fn build_v0_61_store_with(
    data_dir: &Path,
    backup_dir: &Path,
    live: &Snapshot,
    text: &mut dyn FnMut(i64, OldTimestampText) -> String,
) {
    let db_path = data_dir.join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    let families: Vec<&str> = live
        .keys()
        .map(String::as_str)
        .filter(|name| *name != "default" && *name != FORMAT_0_62)
        .collect();
    let db: rocksdb::OptimisticTransactionDB =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, &families).unwrap();
    for (name, rows) in live {
        if name == FORMAT_0_62 {
            continue;
        }
        for (key, value) in rows {
            let value = if TIMESTAMP_FAMILIES_V0_62.contains(&name.as_str()) && is_record(name, key)
            {
                v0_61_record_with(name, value, text)
            } else {
                value.clone()
            };
            if name == "default" {
                db.put(key, value).unwrap();
            } else {
                db.put_cf(&db.cf_handle(name).unwrap(), key, value).unwrap();
            }
        }
    }
    drop(db);
    write_version(data_dir, "0.61.0");
    write_version(backup_dir, "0.61.0");
}

/// An operation attempt deadline-ordered by `expires_at`, terminal when
/// `finalized_at` is given.
fn attempt(
    idempotency_key: &str,
    started_at: Timestamp,
    expires_at: Timestamp,
    finalized_at: Option<Timestamp>,
) -> OperationAttempt {
    OperationAttempt {
        idempotency_key: idempotency_key.to_string(),
        host: "host-a.example".to_string(),
        target: "sensor".to_string(),
        instance: Some(1),
        action: OperationAction::Update,
        install_intent: None,
        config_template: None,
        package_digest: "sha256:aaa".to_string(),
        resolved_version: "1.2.3".to_string(),
        resolved_commit: "c0ffee".to_string(),
        phase: if finalized_at.is_some() {
            OperationPhase::Completed
        } else {
            OperationPhase::Dispatched
        },
        cleanup_state: None,
        started_at,
        retry_policy: OperationRetryPolicy {
            max_attempts: 5,
            attempts_made: 1,
            backoff_seconds: 30,
        },
        outcome: finalized_at.map(|_| OperationOutcome::Succeeded),
        failure_kind: None,
        finalized_at,
        expires_at,
        backup_id: None,
        pre_update_version: None,
        privilege_profile: None,
    }
}

/// The instants [`populate`] stores, with every precision the 0.61 strings
/// carry and a pre-1970 one.
fn in_range_times() -> [Timestamp; 4] {
    [
        "2000-02-29T12:34:56.123456789Z".parse().unwrap(),
        "1969-12-31T23:59:59.5Z".parse().unwrap(),
        "2024-06-15T12:30:45.1Z".parse().unwrap(),
        "1950-01-01T00:00:00.000123Z".parse().unwrap(),
    ]
}

/// Writes a record into every family of [`TIMESTAMP_FAMILIES_V0_62`] of a
/// fresh store in `data_dir`, each carrying the instants `t`: through the
/// public API where one takes the instant, and otherwise as the live type the
/// family stores, encoded as its table encodes it. The `IndexedMap`
/// families written without the API get an index row of their own.
fn populate(data_dir: &Path, backup_dir: &Path, t: [Timestamp; 4]) {
    {
        let store = Store::new(data_dir, backup_dir, None).unwrap();
        store
            .triage_response_map()
            .put(TriageResponse::new(
                "sensor-a".to_string(),
                t[0],
                vec![2, 1],
                "remarks".to_string(),
            ))
            .unwrap();
        let attempts = store.operation_attempt_map();
        attempts
            .upsert(&attempt("op-live", t[0], t[1], None))
            .unwrap();
        let mut done = attempt("op-done", t[2], t[3], Some(t[1]));
        done.instance = Some(2);
        attempts.upsert(&done).unwrap();
        store
            .tor_exit_node_map()
            .replace_all(
                [
                    TorExitNode {
                        ip_address: "10.0.0.1".to_string(),
                        updated_at: t[0],
                    },
                    TorExitNode {
                        ip_address: "10.0.0.2".to_string(),
                        updated_at: t[1],
                    },
                ]
                .into_iter(),
            )
            .unwrap();
        store
            .trusted_user_agent_map()
            .put(&TrustedUserAgent {
                user_agent: "agent/1.0".to_string(),
                updated_at: t[2],
            })
            .unwrap();
        let mut network = Network::new(
            "network-a".to_string(),
            "description".to_string(),
            crate::HostNetworkGroup::default(),
        );
        network.creation_time = t[3];
        store.network_map().insert(network).unwrap();
        store
            .network_lists_map()
            .replace(1, 0, Vec::new(), Vec::new())
            .unwrap();
        store
            .customer_networks_map()
            .replace(1, 0, Vec::new())
            .unwrap();
        store
            .sampling_policy_map()
            .insert(crate::NewSamplingPolicy {
                name: "policy-a".to_string(),
                kind: crate::SamplingKind::Conn,
                interval: crate::SamplingInterval::FiveMinutes,
                period: crate::SamplingPeriod::OneDay,
                offset: 0,
                src_ip: None,
                dst_ip: None,
                node: None,
                column: None,
                customer_id: 1,
            })
            .unwrap();
        store
            .traffic_filter_map()
            .add_rules(
                "host-a.example",
                "10.0.0.0/8".parse().unwrap(),
                Some(vec![80]),
                None,
                None,
            )
            .unwrap();
    }

    let db = open_db(&data_dir.join("states.db"));
    let put = |cf_name: &str, key: &[u8], value: Vec<u8>| {
        db.put_cf(&db.cf_handle(cf_name).unwrap(), key, value)
            .unwrap();
    };

    // The policy's creation time is the clock's; it is set here.
    let cf = db.cf_handle(SAMPLING_POLICY).unwrap();
    let mut policy: crate::SamplingPolicy = decode(&db.get_cf(&cf, b"policy-a").unwrap().unwrap());
    policy.creation_time = t[1];
    put(SAMPLING_POLICY, b"policy-a", policy.value());

    let cf = db.cf_handle(TRAFFIC_FILTER_RULES).unwrap();
    let mut filter: crate::TrafficFilter =
        decode(&db.get_cf(&cf, b"host-a.example").unwrap().unwrap());
    filter.last_modification_time = t[0];
    filter.update_time = Some(t[3]);
    put(TRAFFIC_FILTER_RULES, b"host-a.example", encode(&filter));

    for (cf_name, id, last_modification_time) in [
        (CLUSTER, 2, Some(t[1])),
        (CLUSTER, 3, None),
        (PREVIOUS_CLUSTER, 2, Some(t[2])),
    ] {
        let cluster = crate::tables::Cluster {
            model_id: 1,
            id,
            category_id: 3,
            detector_id: 4,
            event_ids: vec![5, 6],
            sensors: vec!["s5".to_string(), "s6".to_string()],
            labels: Some(vec!["label".to_string()]),
            qualifier_id: 7,
            status_id: 8,
            signature: "signature".to_string(),
            size: 9,
            score: Some(0.5),
            last_modification_time,
        };
        put(
            cf_name,
            cluster.unique_key().as_ref(),
            crate::tables::Value::value(&cluster),
        );
    }

    put(
        NODES,
        b"node-a",
        encode(&crate::tables::InnerNode {
            id: 0,
            name: "node-a".to_string(),
            name_draft: None,
            profile: Some(crate::NodeProfile {
                customer_id: 1,
                description: "node".to_string(),
                hostname: "node-a.example".to_string(),
            }),
            profile_draft: None,
            creation_time: t[2],
            agents: vec!["sensor".to_string()],
            external_services: Vec::new(),
        }),
    );
    put(NODES, b"", b"node index row".to_vec());

    put(
        TRAINING_DEFINITIONS,
        b"model-a",
        encode(&training_definition_record(t)),
    );
    put(
        MODEL_RUNS,
        &1_u32.to_be_bytes(),
        encode(&model_run_record(t)),
    );
    put(MODELS, b"model-a", encode(&model_record(t)));
    put(MODELS, b"", b"model index row".to_vec());
    put(
        ENGINE_INSTANCES,
        &crate::tables::engine_instance_key(0, "unsupervised"),
        encode(&engine_instance_record(t)),
    );
    put(
        SYSTEM_LOG_COLLECTORS,
        b"host-a.example",
        encode(&system_log_collector_record(t)),
    );
}

/// The model instance the model records of [`populate`] belong to.
fn model_instance() -> crate::ModelInstance {
    crate::ModelInstance {
        node_id: 0,
        agent_key: "unsupervised".to_string(),
    }
}

/// The `training definitions` record [`populate`] writes.
fn training_definition_record(t: [Timestamp; 4]) -> crate::TrainingDefinition {
    crate::TrainingDefinition {
        name: "model-a".to_string(),
        customer_id: 1,
        instance: Some(model_instance()),
        method: crate::ModelMethod::Multidimension,
        event_kind: "conn".to_string(),
        sources: vec!["s".to_string()],
        indicator: None,
        definition: "eps = 1".to_string(),
        cloning: false,
        last_run: Some(1),
        created_at: t[0],
        updated_at: t[1],
    }
}

/// The `model runs` record [`populate`] writes.
fn model_run_record(t: [Timestamp; 4]) -> crate::ModelRun {
    crate::ModelRun {
        id: 1,
        kind: crate::RunKind::Train,
        model: "model-a".to_string(),
        instance: model_instance(),
        state: crate::RunState::Succeeded,
        reason: None,
        requested_at: t[2],
        updated_at: t[3],
    }
}

/// The `models` record [`populate`] writes.
fn model_record(t: [Timestamp; 4]) -> crate::tables::Model {
    crate::tables::Model {
        id: 0,
        name: "model-a".to_string(),
        version: 2,
        kind: "multidimension".to_string(),
        max_event_id_num: 10,
        classification_id: Some(1),
        event_kind: "conn".to_string(),
        customer_id: 1,
        instance: Some(model_instance()),
        trained_at: t[0],
        classifier_generation: 2,
        trained_run_id: 1,
        trained_definition: "eps = 1".to_string(),
        previous: Some(crate::PreviousTraining {
            trained_at: t[1],
            version: 1,
            classifier_generation: 1,
            trained_run_id: 0,
            trained_definition: "eps = 2".to_string(),
        }),
        clusters_applied: None,
        trained_sources: Vec::new(),
    }
}

/// The `engine instances` record [`populate`] writes.
fn engine_instance_record(t: [Timestamp; 4]) -> crate::tables::EngineInstanceRow {
    let status = |finished_at: Option<Timestamp>, reported_at: Timestamp| crate::DetectorStatus {
        state: crate::DetectorState::Running,
        finished_at,
        outcome: Some(crate::RoundOutcome::Succeeded),
        reason: None,
        events: 3,
        sources: Vec::new(),
        reported_at,
    };
    crate::tables::EngineInstanceRow {
        stopped: false,
        applied: crate::EngineDocumentRefs::default(),
        pending: crate::EngineDocumentRefs::default(),
        statuses: [(1, status(Some(t[0]), t[1])), (2, status(None, t[2]))]
            .into_iter()
            .collect(),
    }
}

/// The `system log collectors` record [`populate`] writes.
fn system_log_collector_record(t: [Timestamp; 4]) -> crate::SystemLogCollector {
    crate::SystemLogCollector {
        host: "host-a.example".to_string(),
        instance: Some(1),
        install_keys: vec!["key-1".to_string()],
        installed_version: Some("1.0.0".to_string()),
        installed_commit: Some("c0ffee".to_string()),
        data_store: None,
        config: None,
        last_refusal: Some(crate::SystemLogCollectorRefusal {
            at: t[3],
            message: "refused".to_string(),
        }),
    }
}

/// Asserts that `snapshot` holds a record in every family of
/// [`TIMESTAMP_FAMILIES_V0_62`], and an index row in each `IndexedMap` one.
fn assert_every_family_populated(snapshot: &Snapshot) {
    for name in TIMESTAMP_FAMILIES_V0_62 {
        let rows = &snapshot[name];
        assert!(
            rows.iter().any(|(key, _)| is_record(name, key)),
            "{name} has no record"
        );
        if INDEXED_FAMILIES_V0_62.contains(&name) || name == OPERATION_ATTEMPTS {
            assert!(
                rows.iter().any(|(key, _)| !is_record(name, key)),
                "{name} has no index row"
            );
        }
    }
}

/// A store this build writes, its 0.61 counterpart, and the snapshot of the
/// former.
struct Stores {
    live: tempfile::TempDir,
    live_backup: tempfile::TempDir,
    old: tempfile::TempDir,
    old_backup: tempfile::TempDir,
    expected: Snapshot,
}

impl Stores {
    fn new(t: [Timestamp; 4]) -> Self {
        let live = tempfile::tempdir().unwrap();
        let live_backup = tempfile::tempdir().unwrap();
        populate(live.path(), live_backup.path(), t);
        let expected = snapshot(&live.path().join("states.db"));
        let old = tempfile::tempdir().unwrap();
        let old_backup = tempfile::tempdir().unwrap();
        build_v0_61_store(old.path(), old_backup.path(), &expected);
        Self {
            live,
            live_backup,
            old,
            old_backup,
            expected,
        }
    }

    fn old_db_path(&self) -> std::path::PathBuf {
        self.old.path().join("states.db")
    }
}

fn read_versions(data_dir: &Path, backup_dir: &Path) -> (Version, Version) {
    (
        read_version_file(&data_dir.join(VERSION_FILE_NAME)).unwrap(),
        read_version_file(&backup_dir.join(VERSION_FILE_NAME)).unwrap(),
    )
}

fn current_version() -> Version {
    Version::parse(DATABASE_FORMAT_VERSION).unwrap()
}

/// Asserts that `meta` of `snapshot` holds the start marker and the
/// completion key of every family.
fn assert_markers_complete(snapshot: &Snapshot) {
    let meta: Vec<&[u8]> = snapshot[META]
        .iter()
        .map(|(key, _)| key.as_slice())
        .collect();
    assert!(meta.contains(&V0_62_STARTED_KEY));
    for name in TIMESTAMP_FAMILIES_V0_62 {
        assert!(
            meta.contains(&v0_62_completed_key(name).as_slice()),
            "{name} not completed"
        );
    }
}

/// The events of level `WARN` and above recorded while running `f`.
fn warnings_while<R>(f: impl FnOnce() -> R) -> (R, Vec<String>) {
    let recorder = WarningRecorder::default();
    let events = Arc::clone(&recorder.events);
    let result = tracing::subscriber::with_default(recorder, f);
    let events = events.lock().unwrap().clone();
    (result, events)
}

/// A subscriber that records the message of every event of level `WARN` and
/// above, for the thread it is the default of.
#[derive(Default)]
struct WarningRecorder {
    events: Arc<Mutex<Vec<String>>>,
}

impl tracing::Subscriber for WarningRecorder {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::WARN
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Message(String);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let mut message = Message(String::new());
        event.record(&mut message);
        self.events.lock().unwrap().push(message.0);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

#[test]
fn old_timestamp_text_keeps_values_within_the_i64_range() {
    let cases: [(&str, OldTimestampText, i64); 9] = [
        (
            "2026-03-15T15:00:04.100Z",
            OldTimestampText::Serde,
            1_773_586_804_100_000_000,
        ),
        (
            "2000-02-29T12:34:56.123456789Z",
            OldTimestampText::Serde,
            951_827_696_123_456_789,
        ),
        (
            "1969-12-31T23:59:59.500Z",
            OldTimestampText::Serde,
            -500_000_000,
        ),
        (
            "2000-02-29T12:34:56.123456789",
            OldTimestampText::Naive,
            951_827_696_123_456_789,
        ),
        (
            "1950-01-01T00:00:00.000123",
            OldTimestampText::Naive,
            -631_151_999_999_877_000,
        ),
        (
            "2000-02-29 12:34:56 UTC",
            OldTimestampText::Display,
            951_827_696_000_000_000,
        ),
        (
            "2000-02-29 12:34:56.123456789 UTC",
            OldTimestampText::Display,
            951_827_696_123_456_789,
        ),
        // A leap second reads as the second before it.
        (
            "2016-12-31T23:59:60.500Z",
            OldTimestampText::Serde,
            1_483_228_799_500_000_000,
        ),
        (
            "2016-12-31 23:59:60.5 UTC",
            OldTimestampText::Display,
            1_483_228_799_500_000_000,
        ),
    ];
    for (text, form, expected) in cases {
        let (nanos, warnings) =
            warnings_while(|| old_timestamp_nanos_v0_62(text, form, "family", b"key").unwrap());
        assert_eq!(nanos, expected, "{text}");
        assert_eq!(warnings, Vec::<String>::new(), "{text}");
    }
}

#[test]
fn old_timestamp_text_outside_the_i64_range_saturates_with_a_warning() {
    let cases: [(&str, OldTimestampText, i64); 13] = [
        // Does not read: the sign of a year of five or more digits decides.
        ("+11476-08-15T05:20:00Z", OldTimestampText::Serde, i64::MAX),
        ("-11476-08-15T05:20:00Z", OldTimestampText::Serde, i64::MIN),
        ("+11476-08-15T05:20:00", OldTimestampText::Naive, i64::MAX),
        (
            "+11476-08-15 05:20:00 UTC",
            OldTimestampText::Display,
            i64::MAX,
        ),
        (
            "-11476-08-15 05:20:00 UTC",
            OldTimestampText::Display,
            i64::MIN,
        ),
        // Reads, but lies outside the range: the year decides.
        ("2300-01-01T00:00:00Z", OldTimestampText::Serde, i64::MAX),
        ("1600-01-01T00:00:00Z", OldTimestampText::Serde, i64::MIN),
        ("2300-01-01T00:00:00", OldTimestampText::Naive, i64::MAX),
        (
            "1600-01-01 00:00:00 UTC",
            OldTimestampText::Display,
            i64::MIN,
        ),
        (
            "2262-04-11T23:47:16.854775808Z",
            OldTimestampText::Serde,
            i64::MAX,
        ),
        (
            "1677-09-21T00:12:43.145224191Z",
            OldTimestampText::Serde,
            i64::MIN,
        ),
        // Reads, but lies past the end of a `jiff::Timestamp`.
        (
            "9999-12-31T23:59:59.999999999Z",
            OldTimestampText::Serde,
            i64::MAX,
        ),
        (
            "9999-12-31 23:59:59.999999999 UTC",
            OldTimestampText::Display,
            i64::MAX,
        ),
    ];
    for (text, form, expected) in cases {
        let (nanos, warnings) = warnings_while(|| {
            old_timestamp_nanos_v0_62(text, form, "the family", b"\x01\x02").unwrap()
        });
        assert_eq!(nanos, expected, "{text}");
        assert_eq!(warnings.len(), 1, "{text}");
        assert!(warnings[0].contains("the family"), "{}", warnings[0]);
        assert!(warnings[0].contains("0102"), "{}", warnings[0]);
    }
    // The ends of the range themselves keep their value.
    for (text, expected) in [
        ("2262-04-11T23:47:16.854775807Z", i64::MAX),
        ("1677-09-21T00:12:43.145224192Z", i64::MIN),
    ] {
        let (nanos, warnings) = warnings_while(|| {
            old_timestamp_nanos_v0_62(text, OldTimestampText::Serde, "family", b"key").unwrap()
        });
        assert_eq!(nanos, expected, "{text}");
        assert!(warnings.is_empty(), "{text}");
    }
}

#[test]
fn unreadable_old_timestamp_text_fails_naming_the_family_and_the_key() {
    for (text, form) in [
        ("garbage", OldTimestampText::Serde),
        ("2026-03-15T15:00:04", OldTimestampText::Serde),
        ("2026-13-15T15:00:04Z", OldTimestampText::Serde),
        ("2026-03-15 15:00:04 +00:00", OldTimestampText::Display),
        ("", OldTimestampText::Naive),
    ] {
        let error = old_timestamp_nanos_v0_62(text, form, "the family", b"\xab\xcd").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("the family"), "{message}");
        assert!(message.contains("abcd"), "{message}");
    }
}

/// The fixtures that pin the 0.61 bytes of a table value, the family and key
/// they are stored under, and the fixtures that pin the 0.62 bytes the live
/// table writes for the same record.
const FIXTURES: [(&str, &[u8], &str, &str); 5] = [
    (
        TRIAGE_RESPONSE,
        b"fixture-key",
        "triage_response_literal_v0_61.bin",
        "triage_response_literal_v0_62.bin",
    ),
    (
        TRAFFIC_FILTER_RULES,
        b"fixture.example.com",
        "traffic_filter_literal_bytes_v0_61.bin",
        "traffic_filter_literal_bytes_v0_62.bin",
    ),
    (
        SAMPLING_POLICY,
        b"fixture-policy",
        "sampling_policy_literal_bytes_v0_61.bin",
        "sampling_policy_literal_bytes_v0_62.bin",
    ),
    (
        NODES,
        b"fixture-node",
        "node_inner_literal_v0_61.bin",
        "node_inner_literal_v0_62.bin",
    ),
    (
        NETWORKS,
        b"fixture-network",
        "network_projected_private_value_v0_61.bin",
        "network_projected_private_value_v0_62.bin",
    ),
];

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

/// The 0.62.0 step rewrites each 0.61 fixture into the bytes the live table
/// writes for the same record, which the table's own tests pin to the 0.62
/// fixture.
#[test]
fn v0_61_fixtures_migrate_to_the_v0_62_fixtures() {
    for (cf_name, key, v0_61, v0_62) in FIXTURES {
        assert_eq!(
            rewrite_value_v0_62(cf_name, key, &fixture(v0_61)).unwrap(),
            fixture(v0_62),
            "{v0_61}"
        );
    }
}

#[test]
#[ignore = "run manually to regenerate the 0.62 fixtures from the 0.61 ones"]
fn dump_v0_62_fixtures() {
    for (cf_name, key, v0_61, v0_62) in FIXTURES {
        let bytes = rewrite_value_v0_62(cf_name, key, &fixture(v0_61)).unwrap();
        std::fs::write(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(v0_62),
            bytes,
        )
        .unwrap();
    }
}

/// A 0.61 store without a row migrates to an empty 0.62 store with every
/// current family and its markers.
#[test]
fn empty_v0_61_store_migrates() {
    let _permit = acquire_db_permit();
    let data_dir = tempfile::tempdir().unwrap();
    let backup_dir = tempfile::tempdir().unwrap();
    let families: Vec<&str> = crate::tables::MAP_NAMES
        .into_iter()
        .filter(|name| *name != FORMAT_0_62)
        .collect();
    let db_path = data_dir.path().join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    drop(
        rocksdb::OptimisticTransactionDB::<rocksdb::SingleThreaded>::open_cf(
            &opts, &db_path, families,
        )
        .unwrap(),
    );
    write_version(data_dir.path(), "0.61.0");
    write_version(backup_dir.path(), "0.61.0");

    migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

    assert_eq!(
        read_versions(data_dir.path(), backup_dir.path()),
        (current_version(), current_version())
    );
    let migrated = snapshot(&db_path);
    let mut families: Vec<&str> = migrated
        .keys()
        .map(String::as_str)
        .filter(|name| *name != "default")
        .collect();
    families.sort_unstable();
    let mut expected = crate::tables::MAP_NAMES.to_vec();
    expected.sort_unstable();
    assert_eq!(families, expected);
    assert_markers_complete(&migrated);
    for (name, rows) in without_markers(migrated) {
        assert_eq!(rows, Rows::new(), "{name}");
    }
    drop(Store::new(data_dir.path(), backup_dir.path(), None).unwrap());
}

/// Migrating a 0.61 store gives the rows this build writes for the same
/// records: every record in its 0.62 bytes, the `expires_at` index rebuilt
/// with the same keys, and every other row, the index rows included, byte for
/// byte. The store then opens and reads them, and neither a rerun of the step
/// nor a second start changes anything.
#[test]
fn v0_61_store_migrates_to_the_rows_this_build_writes() {
    let _permit = acquire_db_permit();
    let stores = Stores::new(in_range_times());
    assert_every_family_populated(&stores.expected);
    let old = snapshot(&stores.old_db_path());
    for name in TIMESTAMP_FAMILIES_V0_62 {
        assert_ne!(old[name], stores.expected[name], "{name}");
    }

    let (result, warnings) =
        warnings_while(|| migrate_data_dir(stores.old.path(), stores.old_backup.path(), None));
    result.unwrap();
    assert_eq!(warnings, Vec::<String>::new());

    assert_eq!(
        read_versions(stores.old.path(), stores.old_backup.path()),
        (current_version(), current_version())
    );
    let migrated = snapshot(&stores.old_db_path());
    assert_markers_complete(&migrated);
    assert_eq!(without_markers(migrated.clone()), stores.expected);

    migrate_0_61_to_0_62(stores.old.path()).unwrap();
    assert_eq!(snapshot(&stores.old_db_path()), migrated);
    migrate_data_dir(stores.old.path(), stores.old_backup.path(), None).unwrap();
    assert_eq!(snapshot(&stores.old_db_path()), migrated);

    let store = Store::new(stores.old.path(), stores.old_backup.path(), None).unwrap();
    let t = in_range_times();
    let attempts = store.operation_attempt_map();
    let live = attempts.get("op-live").unwrap().unwrap();
    assert_eq!((live.started_at, live.expires_at), (t[0], t[1]));
    let done = attempts.get("op-done").unwrap().unwrap();
    assert_eq!(done.finalized_at, Some(t[1]));
    assert_eq!(
        attempts.expired_attempts(t[1]).unwrap(),
        vec![done.clone(), live]
    );
    let response = store
        .triage_response_map()
        .get("sensor-a", &t[0])
        .unwrap()
        .unwrap();
    assert_eq!(response.remarks, "remarks");
    let network = store.network_map().get_by_id(0).unwrap().unwrap();
    assert_eq!(network.creation_time, t[3]);
    let mut nodes: Vec<(String, Timestamp)> = crate::Iterable::iter(
        &store.tor_exit_node_map(),
        rocksdb::Direction::Forward,
        None,
    )
    .map(|node| {
        let node = node.unwrap();
        (node.ip_address, node.updated_at)
    })
    .collect();
    nodes.sort_unstable();
    assert_eq!(
        nodes,
        [
            ("10.0.0.1".to_string(), t[0]),
            ("10.0.0.2".to_string(), t[1])
        ]
    );
    let policy = store.sampling_policy_map().get_by_id(0).unwrap().unwrap();
    assert_eq!(policy.creation_time, t[1]);
    let filter = store
        .traffic_filter_map()
        .get("host-a.example")
        .unwrap()
        .unwrap();
    assert_eq!(filter.update_time, Some(t[3]));
    let collector = store
        .system_log_collector_map()
        .get("host-a.example")
        .unwrap()
        .unwrap();
    assert_eq!(collector.last_refusal.unwrap().at, t[3]);

    drop(stores.live_backup);
}

/// A run that stopped after some families completed resumes from the first
/// family without a completion key, reading every row of it as 0.61, and
/// ends with the rows a run that never stopped writes.
#[test]
fn interrupted_step_resumes_from_the_first_family_not_completed() {
    let _permit = acquire_db_permit();
    let stores = Stores::new(in_range_times());

    assert!(!migrate_0_61_to_0_62_inner(stores.old.path(), Some(3)).unwrap());
    let partial = snapshot(&stores.old_db_path());
    let meta: Vec<&[u8]> = partial[META]
        .iter()
        .map(|(key, _)| key.as_slice())
        .collect();
    assert!(meta.contains(&V0_62_STARTED_KEY));
    for (index, name) in TIMESTAMP_FAMILIES_V0_62.into_iter().enumerate() {
        assert_eq!(
            meta.contains(&v0_62_completed_key(name).as_slice()),
            index < 3,
            "{name}"
        );
        if index < 3 {
            assert_eq!(partial[name], stores.expected[name], "{name}");
        } else {
            assert_ne!(partial[name], stores.expected[name], "{name}");
        }
    }

    migrate_data_dir(stores.old.path(), stores.old_backup.path(), None).unwrap();
    let migrated = snapshot(&stores.old_db_path());
    assert_markers_complete(&migrated);
    assert_eq!(without_markers(migrated), stores.expected);
    drop(stores.live);
}

/// The 0.61 texts of a timestamp outside the `i64` nanosecond range, by the
/// end it saturates to and the form it is stored in: a year of five or more
/// digits, which does not read; a year past either end of the range or a
/// nanosecond past it; and an instant past the end of a `jiff::Timestamp`.
/// [`populate`] stores few timestamps in the naive and `Display` forms, so
/// those lists are shorter; the test checks that every text is written.
const OUT_OF_RANGE_V0_61_TEXTS: [(i64, OldTimestampText, &[&str]); 6] = [
    (
        i64::MAX,
        OldTimestampText::Serde,
        &[
            "+11476-08-15T05:20:00Z",
            "2300-01-01T00:00:00Z",
            "9999-12-31T23:59:59.999999999Z",
            "2262-04-11T23:47:16.854775808Z",
        ],
    ),
    (
        i64::MIN,
        OldTimestampText::Serde,
        &[
            "-11476-08-15T05:20:00Z",
            "1600-01-01T00:00:00Z",
            "1677-09-21T00:12:43.145224191Z",
        ],
    ),
    (
        i64::MAX,
        OldTimestampText::Naive,
        &["+11476-08-15T05:20:00"],
    ),
    (i64::MIN, OldTimestampText::Naive, &["1600-01-01T00:00:00"]),
    (
        i64::MAX,
        OldTimestampText::Display,
        &[
            "+11476-08-15 05:20:00 UTC",
            "9999-12-31 23:59:59.999999999 UTC",
        ],
    ),
    (
        i64::MIN,
        OldTimestampText::Display,
        &["-11476-08-15 05:20:00 UTC"],
    ),
];

/// A record whose timestamps lie outside the `i64` nanosecond range is stored
/// saturated by every table that stores it, with no error and no panic. The
/// 0.62.0 step reads such a record from its 0.61 form, every saturated
/// timestamp written as a text outside the range, to the same bytes, with a
/// warning for each of those timestamps.
#[test]
fn out_of_range_timestamps_are_stored_saturated() {
    let _permit = acquire_db_permit();
    let far_future: Timestamp = "2300-01-01T00:00:00Z".parse().unwrap();
    let far_past: Timestamp = "1600-01-01T00:00:00Z".parse().unwrap();
    let data_dir = tempfile::tempdir().unwrap();
    let backup_dir = tempfile::tempdir().unwrap();
    populate(
        data_dir.path(),
        backup_dir.path(),
        [far_future, far_past, Timestamp::MAX, Timestamp::MIN],
    );
    let stored = snapshot(&data_dir.path().join("states.db"));
    for name in TIMESTAMP_FAMILIES_V0_62 {
        if [NETWORK_LISTS, CUSTOMER_NETWORKS].contains(&name) {
            // Their tables stamp the clock themselves.
            continue;
        }
        let saturated = stored[name]
            .iter()
            .filter(|(key, _)| is_record(name, key))
            .flat_map(|(_, value)| timestamps_of(name, value))
            .filter(|nanos| *nanos == i64::MAX || *nanos == i64::MIN)
            .count();
        assert_ne!(saturated, 0, "{name}");
    }
    // The key suffix of a triage response outside the range stays 0.
    let (key, _) = stored[TRIAGE_RESPONSE]
        .iter()
        .find(|(key, _)| !key.is_empty())
        .unwrap();
    assert_eq!(key.as_slice(), b"sensor-a\0\0\0\0\0\0\0\0");

    // Each saturated timestamp goes into the 0.61 store as the next text of
    // its end and form, in turn; every other one as its own 0.61 text.
    let mut written = [0_usize; OUT_OF_RANGE_V0_61_TEXTS.len()];
    let mut text = |nanos: i64, form: OldTimestampText| -> String {
        let Some((i, (_, _, texts))) =
            OUT_OF_RANGE_V0_61_TEXTS
                .iter()
                .enumerate()
                .find(|(_, (end, end_form, _))| {
                    *end == nanos
                        && std::mem::discriminant(end_form) == std::mem::discriminant(&form)
                })
        else {
            return v0_61_text(nanos, form);
        };
        let text = texts[written[i] % texts.len()];
        written[i] += 1;
        text.to_string()
    };
    let old = tempfile::tempdir().unwrap();
    let old_backup = tempfile::tempdir().unwrap();
    build_v0_61_store_with(old.path(), old_backup.path(), &stored, &mut text);
    let saturated: usize = TIMESTAMP_FAMILIES_V0_62
        .into_iter()
        .flat_map(|name| {
            stored[name]
                .iter()
                .filter(move |(key, _)| is_record(name, key))
                .flat_map(move |(_, value)| timestamps_of(name, value))
        })
        .filter(|nanos| *nanos == i64::MAX || *nanos == i64::MIN)
        .count();
    assert_eq!(written.iter().sum::<usize>(), saturated);
    for ((_, form, texts), written) in OUT_OF_RANGE_V0_61_TEXTS.iter().zip(written) {
        assert!(written >= texts.len(), "{form:?}: {written} of {texts:?}");
    }

    let (result, warnings) =
        warnings_while(|| migrate_data_dir(old.path(), old_backup.path(), None));
    result.unwrap();
    assert_eq!(warnings.len(), saturated, "{warnings:?}");
    assert_eq!(
        without_markers(snapshot(&old.path().join("states.db"))),
        stored
    );
}

/// Returns the 0.61 `expires_at` index key of `idempotency_key` for a
/// deadline `seconds` after the epoch, as the 0.61 table wrote it from
/// chrono's seconds.
fn v0_61_expires_at_key(seconds: i64, idempotency_key: &[u8]) -> Vec<u8> {
    let mut key = vec![OPERATION_ATTEMPT_EXPIRES_AT_V0_62];
    let mut seconds = seconds.to_be_bytes();
    seconds[0] ^= 0x80;
    key.extend_from_slice(&seconds);
    key.extend_from_slice(&0_u32.to_be_bytes());
    key.extend_from_slice(&u32::try_from(idempotency_key.len()).unwrap().to_be_bytes());
    key.extend_from_slice(idempotency_key);
    key
}

/// The `expires_at` index rows of `rows`, the operation attempts family.
fn expiry_rows(rows: &Rows) -> Rows {
    rows.iter()
        .filter(|(key, _)| key.first() == Some(&OPERATION_ATTEMPT_EXPIRES_AT_V0_62))
        .cloned()
        .collect()
}

/// A 0.61 attempt whose deadline, `2300-01-01`, lies past the `i64`
/// nanosecond range is stored at the end of the range, and its `expires_at`
/// index row is rebuilt from that stored value. The sweep at the end of the
/// range finds it, and a deletion, which recomputes the key from the record,
/// leaves no index row behind.
#[test]
fn v0_61_attempt_with_a_far_future_deadline_is_indexed_as_stored() {
    let _permit = acquire_db_permit();
    let t = in_range_times();
    let data_dir = tempfile::tempdir().unwrap();
    let backup_dir = tempfile::tempdir().unwrap();
    {
        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        store
            .operation_attempt_map()
            .upsert(&attempt("op-far", t[0], t[0], None))
            .unwrap();
    }
    let live = snapshot(&data_dir.path().join("states.db"));
    let old = tempfile::tempdir().unwrap();
    let old_backup = tempfile::tempdir().unwrap();
    build_v0_61_store(old.path(), old_backup.path(), &live);
    let db_path = old.path().join("states.db");
    {
        // The 0.61 record names 2300-01-01, and its index row the seconds
        // chrono kept for it.
        let db = open_db(&db_path);
        let cf = db.cf_handle(OPERATION_ATTEMPTS).unwrap();
        let mut record: OperationAttemptValue<String> =
            decode(&db.get_cf(&cf, b"op-far").unwrap().unwrap());
        record.expires_at = "2300-01-01T00:00:00Z".to_string();
        db.put_cf(&cf, b"op-far", encode(&record)).unwrap();
        let expiry = expiry_rows(&snapshot_of(&db, OPERATION_ATTEMPTS));
        assert_eq!(expiry.len(), 1);
        db.delete_cf(&cf, &expiry[0].0).unwrap();
        db.put_cf(
            &cf,
            v0_61_expires_at_key(10_413_792_000, b"op-far"),
            b"op-far",
        )
        .unwrap();
    }

    migrate_data_dir(old.path(), old_backup.path(), None).unwrap();

    let end_of_range = crate::timestamp::from_i64_nanos(i64::MAX).unwrap();
    let mut expected_key = vec![OPERATION_ATTEMPT_EXPIRES_AT_V0_62];
    let mut seconds = i64::MAX.div_euclid(NANOS_PER_SECOND).to_be_bytes();
    seconds[0] ^= 0x80;
    expected_key.extend_from_slice(&seconds);
    expected_key.extend_from_slice(
        &u32::try_from(i64::MAX.rem_euclid(NANOS_PER_SECOND))
            .unwrap()
            .to_be_bytes(),
    );
    expected_key.extend_from_slice(&6_u32.to_be_bytes());
    expected_key.extend_from_slice(b"op-far");
    assert_eq!(
        expiry_rows(&snapshot(&db_path)[OPERATION_ATTEMPTS]),
        [(expected_key, b"op-far".to_vec())]
    );

    let store = Store::new(old.path(), old_backup.path(), None).unwrap();
    let table = store.operation_attempt_map();
    assert_eq!(
        table.get("op-far").unwrap().unwrap().expires_at,
        end_of_range
    );
    let before_end = crate::timestamp::from_i64_nanos(i64::MAX - 1).unwrap();
    assert_eq!(table.expired_attempts(before_end).unwrap(), Vec::new());
    assert_eq!(table.sweep_expired(end_of_range).unwrap(), 1);
    let swept = table.get("op-far").unwrap().unwrap();
    assert_eq!(swept.outcome, Some(OperationOutcome::Failed));

    table.delete("op-far").unwrap();
    drop(store);
    let rows = &snapshot(&db_path)[OPERATION_ATTEMPTS];
    assert!(
        rows.iter().all(|(_, value)| value.as_slice() != b"op-far"),
        "{rows:?}"
    );
    assert_eq!(expiry_rows(rows), Rows::new());
}

fn snapshot_of(db: &rocksdb::OptimisticTransactionDB, cf_name: &str) -> Rows {
    let cf = db.cf_handle(cf_name).unwrap();
    db.iterator_cf(&cf, rocksdb::IteratorMode::Start)
        .map(|entry| {
            let (key, value) = entry.unwrap();
            (key.to_vec(), value.to_vec())
        })
        .collect()
}

/// A 0.61 row that does not decode in the 0.61 layout, and one whose
/// timestamp text does not read, each stop the migration with an error naming
/// the family and the key, and `VERSION` stays where it was.
#[test]
fn unreadable_v0_61_rows_stop_the_migration() {
    let _permit = acquire_db_permit();
    let stores = Stores::new(in_range_times());
    let cf_name = TRAINING_DEFINITIONS;
    let (key, value) = stores.expected[cf_name][0].clone();
    let mut old: TrainingDefinitionValue<String> = decode(&v0_61_record(cf_name, &value));
    old.updated_at = "garbage".to_string();

    for (bytes, expected) in [
        (vec![0xff], "does not decode in the 0.61 layout"),
        (encode(&old), "unreadable timestamp"),
    ] {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        build_v0_61_store(data_dir.path(), backup_dir.path(), &stores.expected);
        {
            let db = open_db(&data_dir.path().join("states.db"));
            db.put_cf(&db.cf_handle(cf_name).unwrap(), &key, bytes)
                .unwrap();
        }
        let error = migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(expected), "{message}");
        assert!(message.contains(cf_name), "{message}");
        assert!(
            message.contains(&data_encoding::HEXLOWER.encode(&key)),
            "{message}"
        );
        let version = Version::parse("0.61.0").unwrap();
        assert_eq!(
            read_versions(data_dir.path(), backup_dir.path()),
            (version.clone(), version)
        );
    }
}

/// Creates the column families of `families` that `db_path` lacks and drops
/// the ones it has outside them.
fn reshape_families(db_path: &Path, families: &[&str]) {
    let mut db = open_db(db_path);
    let present = super::existing_map_names(&rocksdb::Options::default(), db_path).unwrap();
    for name in &present {
        if !families.contains(&name.as_str()) {
            db.drop_cf(name).unwrap();
        }
    }
    for name in families {
        if !present.iter().any(|present| present == name) {
            db.create_cf(name, &rocksdb::Options::default()).unwrap();
        }
    }
}

/// Copies the directory tree at `from` to `to`.
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

/// A store of format 0.55, holding one operation attempt in the 0.49 layout
/// and a Tor exit node, and one of format 0.46, holding a Tor exit node.
fn old_store(version: &str, data_dir: &Path, backup_dir: &Path) {
    let t = in_range_times();
    {
        let store = Store::new(data_dir, backup_dir, None).unwrap();
        store
            .tor_exit_node_map()
            .replace_all(
                [TorExitNode {
                    ip_address: "10.0.0.1".to_string(),
                    updated_at: t[0],
                }]
                .into_iter(),
            )
            .unwrap();
        if version == "0.55.0" {
            store
                .operation_attempt_map()
                .upsert(&attempt("op-live", t[0], t[1], None))
                .unwrap();
        }
    }
    let db_path = data_dir.join("states.db");
    let live = snapshot(&db_path);
    {
        let db = open_db(&db_path);
        for name in [TOR_EXIT_NODES, OPERATION_ATTEMPTS] {
            let cf = db.cf_handle(name).unwrap();
            for (key, value) in &live[name] {
                if !is_record(name, key) {
                    continue;
                }
                let mut old = v0_61_record(name, value);
                if name == OPERATION_ATTEMPTS {
                    // The 0.49 layout is the 0.61 one without the final
                    // `privilege_profile`, which is `None` here.
                    assert_eq!(old.pop(), Some(0));
                }
                db.put_cf(&cf, key, old).unwrap();
            }
        }
    }
    let families: &[&str] = if version == "0.55.0" {
        &super::MAP_NAMES_V0_55
    } else {
        &super::MAP_NAMES_V0_43_TO_V0_46
    };
    reshape_families(&db_path, families);
    write_version(data_dir, version);
    write_version(backup_dir, version);
}

/// A chain from 0.55 or 0.46 that stopped inside the 0.62.0 step, with
/// exactly one family completed, still records the version it started from.
/// The retry resumes from the 0.62.0 step rather than running the earlier
/// steps over rows already rewritten, and ends with the store a chain that
/// never stopped leaves, with every current family.
#[test]
fn chain_stopped_inside_the_v0_62_step_resumes_from_it() {
    let _permit = acquire_db_permit();
    for version in ["0.55.0", "0.46.0"] {
        let reference = tempfile::tempdir().unwrap();
        let reference_backup = tempfile::tempdir().unwrap();
        old_store(version, reference.path(), reference_backup.path());
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        copy_dir(reference.path(), data_dir.path());
        copy_dir(reference_backup.path(), backup_dir.path());

        migrate_data_dir(reference.path(), reference_backup.path(), None).unwrap();

        run_steps_to_v0_61(data_dir.path());
        assert!(!migrate_0_61_to_0_62_inner(data_dir.path(), Some(1)).unwrap());
        let db_path = data_dir.path().join("states.db");
        let partial = snapshot(&db_path);
        let completed = TIMESTAMP_FAMILIES_V0_62
            .into_iter()
            .filter(|name| {
                partial[META]
                    .iter()
                    .any(|(key, _)| *key == v0_62_completed_key(name))
            })
            .collect::<Vec<_>>();
        assert_eq!(completed, [OPERATION_ATTEMPTS], "{version}");
        let original = Version::parse(version).unwrap();
        assert_eq!(
            read_versions(data_dir.path(), backup_dir.path()),
            (original.clone(), original)
        );

        migrate_data_dir(data_dir.path(), backup_dir.path(), None)
            .unwrap_or_else(|error| panic!("retry from {version}: {error:#}"));

        assert_eq!(
            read_versions(data_dir.path(), backup_dir.path()),
            (current_version(), current_version())
        );
        let migrated = snapshot(&db_path);
        assert_eq!(
            migrated,
            snapshot(&reference.path().join("states.db")),
            "{version}"
        );
        let mut families: Vec<&str> = migrated
            .keys()
            .map(String::as_str)
            .filter(|name| *name != "default")
            .collect();
        families.sort_unstable();
        let mut expected = crate::tables::MAP_NAMES.to_vec();
        expected.sort_unstable();
        assert_eq!(families, expected, "{version}");
        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        let node = crate::Iterable::iter(
            &store.tor_exit_node_map(),
            rocksdb::Direction::Forward,
            None,
        )
        .next()
        .unwrap()
        .unwrap();
        assert_eq!(node.updated_at, in_range_times()[0]);
    }
}

/// Runs a chain from `version` to the end and then puts the data marker back
/// at `version`: the state a crash between the backup `VERSION` write and
/// the data one leaves.
fn interrupted_version_write(version: &str) -> (tempfile::TempDir, tempfile::TempDir) {
    let data_dir = tempfile::tempdir().unwrap();
    let backup_dir = tempfile::tempdir().unwrap();
    if version == "0.61.0" {
        let stores = Stores::new(in_range_times());
        copy_dir(stores.old.path(), data_dir.path());
        copy_dir(stores.old_backup.path(), backup_dir.path());
    } else {
        old_store(version, data_dir.path(), backup_dir.path());
    }
    migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();
    write_version(data_dir.path(), version);
    (data_dir, backup_dir)
}

/// (a) A crash between the two `VERSION` writes leaves the backup marker
/// current and the data marker at the start of the chain. With every 0.62.0
/// marker present, the retry runs no step, leaves the store as it is and
/// writes the data marker.
#[test]
fn interrupted_version_write_completes_without_running_a_step() {
    let _permit = acquire_db_permit();
    for version in ["0.61.0", "0.55.0"] {
        let (data_dir, backup_dir) = interrupted_version_write(version);
        let db_path = data_dir.path().join("states.db");
        let before = snapshot(&db_path);
        assert_eq!(
            read_versions(data_dir.path(), backup_dir.path()),
            (Version::parse(version).unwrap(), current_version())
        );

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_versions(data_dir.path(), backup_dir.path()),
            (current_version(), current_version())
        );
        assert_eq!(snapshot(&db_path), before, "{version}");
    }
}

/// (b) The same state with one family's completion key missing is the
/// mismatch it always was.
#[test]
fn interrupted_version_write_without_every_completion_key_is_a_mismatch() {
    let _permit = acquire_db_permit();
    let (data_dir, backup_dir) = interrupted_version_write("0.61.0");
    {
        let db = open_db(&data_dir.path().join("states.db"));
        db.delete_cf(
            &db.cf_handle(META).unwrap(),
            v0_62_completed_key(SYSTEM_LOG_COLLECTORS),
        )
        .unwrap();
    }
    let error = migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("mismatched database version 0.61.0 and backup version 0.62.0"),
        "{error:#}"
    );
    assert_eq!(
        read_versions(data_dir.path(), backup_dir.path()),
        (Version::parse("0.61.0").unwrap(), current_version())
    );
}

/// (c) A mismatch without the start marker is an error, as it always was.
#[test]
fn version_mismatch_without_the_start_marker_is_an_error() {
    let _permit = acquire_db_permit();
    let (data_dir, backup_dir) = interrupted_version_write("0.61.0");
    {
        let db = open_db(&data_dir.path().join("states.db"));
        db.delete_cf(&db.cf_handle(META).unwrap(), V0_62_STARTED_KEY)
            .unwrap();
    }
    assert!(migrate_data_dir(data_dir.path(), backup_dir.path(), None).is_err());

    // Nor does a marker make any other mismatch acceptable: the backup
    // marker must be the current one, and the data marker older.
    for (data, backup) in [("0.62.0", "0.61.0"), ("0.61.0", "0.60.0")] {
        let (data_dir, backup_dir) = interrupted_version_write("0.61.0");
        write_version(data_dir.path(), data);
        write_version(backup_dir.path(), backup);
        assert!(
            migrate_data_dir(data_dir.path(), backup_dir.path(), None).is_err(),
            "{data} {backup}"
        );
    }
}

/// (d) A migrated store, its markers still in `meta`, opens again with no
/// step run and neither the store nor a marker changed.
#[test]
fn migrated_store_with_its_markers_reopens_unchanged() {
    let _permit = acquire_db_permit();
    let stores = Stores::new(in_range_times());
    migrate_data_dir(stores.old.path(), stores.old_backup.path(), None).unwrap();
    let before = snapshot(&stores.old_db_path());
    assert_markers_complete(&before);
    let versions = |stores: &Stores| {
        (
            std::fs::read(stores.old.path().join(VERSION_FILE_NAME)).unwrap(),
            std::fs::read(stores.old_backup.path().join(VERSION_FILE_NAME)).unwrap(),
        )
    };
    let markers = versions(&stores);

    migrate_data_dir(stores.old.path(), stores.old_backup.path(), None).unwrap();
    drop(Store::new(stores.old.path(), stores.old_backup.path(), None).unwrap());

    assert_eq!(snapshot(&stores.old_db_path()), before);
    assert_eq!(versions(&stores), markers);
}

/// The 0.62 bytes of a record in each family the fixtures above do not cover,
/// with the instants of [`in_range_times`], pinned independently of the
/// writer. Each timestamp is a zigzag varint `i64` of nanoseconds:
/// `fd 2a 5a a2 45 7e 24 6b 1a` is 2000-02-29T12:34:56.123456789Z,
/// `fc ff c9 9a 3b` is 1969-12-31T23:59:59.5Z,
/// `fd 00 66 9c 37 ca 5a b2 2f` is 2024-06-15T12:30:45.1Z and
/// `fd 0f 3f 8a ce cc 9a 84 11` is 1950-01-01T00:00:00.000123Z.
///
/// The live types encode to them, and the 0.62.0 step rewrites the 0.61 form
/// of each into them.
#[test]
fn v0_62_layouts_of_the_remaining_families_are_pinned() {
    #[rustfmt::skip]
    const NETWORK_LISTS_V0_62: &[u8] = &[
        0x03, 0x00, 0x00,
        0xfd, 0x2a, 0x5a, 0xa2, 0x45, 0x7e, 0x24, 0x6b, 0x1a,
    ];
    #[rustfmt::skip]
    const CUSTOMER_NETWORKS_V0_62: &[u8] = &[
        0x03, 0x00,
        0xfc, 0xff, 0xc9, 0x9a, 0x3b,
    ];
    #[rustfmt::skip]
    const TRAINING_DEFINITIONS_V0_62: &[u8] = &[
        0x07, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2d, 0x61, 0x01, 0x01, 0x00, 0x0c,
        0x75, 0x6e, 0x73, 0x75, 0x70, 0x65, 0x72, 0x76, 0x69, 0x73, 0x65, 0x64,
        0x00, 0x04, 0x63, 0x6f, 0x6e, 0x6e, 0x01, 0x01, 0x73, 0x00, 0x07, 0x65,
        0x70, 0x73, 0x20, 0x3d, 0x20, 0x31, 0x00, 0x01, 0x01,
        // created_at
        0xfd, 0x2a, 0x5a, 0xa2, 0x45, 0x7e, 0x24, 0x6b, 0x1a,
        // updated_at
        0xfc, 0xff, 0xc9, 0x9a, 0x3b,
    ];
    #[rustfmt::skip]
    const MODEL_RUNS_V0_62: &[u8] = &[
        0x01, 0x00, 0x07, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2d, 0x61, 0x00, 0x0c,
        0x75, 0x6e, 0x73, 0x75, 0x70, 0x65, 0x72, 0x76, 0x69, 0x73, 0x65, 0x64,
        0x02, 0x00,
        // requested_at
        0xfd, 0x00, 0x66, 0x9c, 0x37, 0xca, 0x5a, 0xb2, 0x2f,
        // updated_at
        0xfd, 0x0f, 0x3f, 0x8a, 0xce, 0xcc, 0x9a, 0x84, 0x11,
    ];
    #[rustfmt::skip]
    const MODELS_V0_62: &[u8] = &[
        0x00, 0x07, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x2d, 0x61, 0x04, 0x0e, 0x6d,
        0x75, 0x6c, 0x74, 0x69, 0x64, 0x69, 0x6d, 0x65, 0x6e, 0x73, 0x69, 0x6f,
        0x6e, 0x14, 0x01, 0x02, 0x04, 0x63, 0x6f, 0x6e, 0x6e, 0x01, 0x01, 0x00,
        0x0c, 0x75, 0x6e, 0x73, 0x75, 0x70, 0x65, 0x72, 0x76, 0x69, 0x73, 0x65,
        0x64,
        // trained_at
        0xfd, 0x2a, 0x5a, 0xa2, 0x45, 0x7e, 0x24, 0x6b, 0x1a,
        0x02, 0x01, 0x07, 0x65, 0x70, 0x73, 0x20, 0x3d, 0x20, 0x31, 0x01,
        // previous.trained_at
        0xfc, 0xff, 0xc9, 0x9a, 0x3b,
        0x02, 0x01, 0x00, 0x07, 0x65, 0x70, 0x73, 0x20, 0x3d, 0x20, 0x32, 0x00,
        0x00,
    ];
    #[rustfmt::skip]
    const ENGINE_INSTANCES_V0_62: &[u8] = &[
        0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x01,
        // statuses[1].finished_at
        0xfd, 0x2a, 0x5a, 0xa2, 0x45, 0x7e, 0x24, 0x6b, 0x1a,
        0x01, 0x00, 0x00, 0x03, 0x00,
        // statuses[1].reported_at
        0xfc, 0xff, 0xc9, 0x9a, 0x3b,
        0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00,
        // statuses[2].reported_at
        0xfd, 0x00, 0x66, 0x9c, 0x37, 0xca, 0x5a, 0xb2, 0x2f,
    ];
    #[rustfmt::skip]
    const SYSTEM_LOG_COLLECTORS_V0_62: &[u8] = &[
        0x0e, 0x68, 0x6f, 0x73, 0x74, 0x2d, 0x61, 0x2e, 0x65, 0x78, 0x61, 0x6d,
        0x70, 0x6c, 0x65, 0x01, 0x01, 0x01, 0x05, 0x6b, 0x65, 0x79, 0x2d, 0x31,
        0x01, 0x05, 0x31, 0x2e, 0x30, 0x2e, 0x30, 0x01, 0x06, 0x63, 0x30, 0x66,
        0x66, 0x65, 0x65, 0x00, 0x00, 0x01,
        // last_refusal.at
        0xfd, 0x0f, 0x3f, 0x8a, 0xce, 0xcc, 0x9a, 0x84, 0x11,
        0x07, 0x72, 0x65, 0x66, 0x75, 0x73, 0x65, 0x64,
    ];

    // The family, the key, the live type's encoding and the pinned bytes.
    type Case<'a> = (&'a str, &'a [u8], Vec<u8>, &'a [u8]);

    let t = in_range_times();
    let cases: [Case; 7] = [
        (
            NETWORK_LISTS,
            &1_u32.to_be_bytes(),
            encode(&crate::NetworkListSet {
                revision: 3,
                allowlist: Vec::new(),
                blocklist: Vec::new(),
                updated_at: t[0],
            }),
            NETWORK_LISTS_V0_62,
        ),
        (
            CUSTOMER_NETWORKS,
            &1_u32.to_be_bytes(),
            encode(&crate::OwnedNetworkSet {
                revision: 3,
                networks: Vec::new(),
                updated_at: t[1],
            }),
            CUSTOMER_NETWORKS_V0_62,
        ),
        (
            TRAINING_DEFINITIONS,
            b"model-a",
            encode(&training_definition_record(t)),
            TRAINING_DEFINITIONS_V0_62,
        ),
        (
            MODEL_RUNS,
            &1_u32.to_be_bytes(),
            encode(&model_run_record(t)),
            MODEL_RUNS_V0_62,
        ),
        (MODELS, b"model-a", encode(&model_record(t)), MODELS_V0_62),
        (
            ENGINE_INSTANCES,
            &crate::tables::engine_instance_key(0, "unsupervised"),
            encode(&engine_instance_record(t)),
            ENGINE_INSTANCES_V0_62,
        ),
        (
            SYSTEM_LOG_COLLECTORS,
            b"host-a.example",
            encode(&system_log_collector_record(t)),
            SYSTEM_LOG_COLLECTORS_V0_62,
        ),
    ];
    for (cf_name, key, live, pinned) in cases {
        assert_eq!(live, pinned, "{cf_name}");
        let old = v0_61_record(cf_name, pinned);
        assert_ne!(old, pinned, "{cf_name}");
        assert_eq!(
            rewrite_value_v0_62(cf_name, key, &old).unwrap(),
            pinned,
            "{cf_name}"
        );
    }
}

/// The 0.62.0 step rewrites the 0.61 form of the operation attempt record
/// that `operation_attempt_v0_62_literal.bin` pins, to which the live table's
/// own test holds its writer, into those very bytes, and indexes it by its
/// deadline.
#[test]
fn v0_61_operation_attempt_migrates_to_the_v0_62_fixture() {
    const IDEMPOTENCY_KEY: &[u8] = b"9d5cb6e0-0a3f-41de-9f0a-6b0f4e5c1a27";

    let _permit = acquire_db_permit();
    let pinned = fixture("operation_attempt_v0_62_literal.bin");
    let data_dir = tempfile::tempdir().unwrap();
    let backup_dir = tempfile::tempdir().unwrap();
    drop(Store::new(data_dir.path(), backup_dir.path(), None).unwrap());
    let mut live = snapshot(&data_dir.path().join("states.db"));
    live.get_mut(OPERATION_ATTEMPTS)
        .unwrap()
        .push((IDEMPOTENCY_KEY.to_vec(), pinned.clone()));

    let old = tempfile::tempdir().unwrap();
    let old_backup = tempfile::tempdir().unwrap();
    build_v0_61_store(old.path(), old_backup.path(), &live);
    let db_path = old.path().join("states.db");
    let old_rows = snapshot(&db_path)[OPERATION_ATTEMPTS].clone();
    assert_eq!(old_rows.len(), 1);
    assert_ne!(old_rows[0].1, pinned);

    migrate_data_dir(old.path(), old_backup.path(), None).unwrap();

    let rows = &snapshot(&db_path)[OPERATION_ATTEMPTS];
    let records: Rows = rows
        .iter()
        .filter(|(key, _)| is_record(OPERATION_ATTEMPTS, key))
        .cloned()
        .collect();
    let expires_at = decode::<OperationAttemptValue<i64>>(&pinned).expires_at;
    assert_eq!(records, [(IDEMPOTENCY_KEY.to_vec(), pinned)]);
    assert_eq!(
        expiry_rows(rows),
        [(
            v0_61_expires_at_key(expires_at.div_euclid(NANOS_PER_SECOND), IDEMPOTENCY_KEY),
            IDEMPOTENCY_KEY.to_vec()
        )]
    );
}
