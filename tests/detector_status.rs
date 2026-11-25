//! A detector status built outside the crate, with the per-detection-model
//! statuses and exclusion-list counts of the engine's report, is stored and
//! read back verbatim and in order.

use jiff::{Timestamp, civil::date};
use review_database::{
    Agent, AgentKind, AgentStatus, ClusteringModelTypeRef, DetectorSourceStatus, DetectorState,
    DetectorStatus, EngineDetectorRef, EngineDocumentRefs, EngineDocumentWrite, Model,
    ModelInstance, ModelOwner, Node, RoundOutcome, SourceState, Store, TrainedWith, TrainingRead,
};
use review_protocol::types::{DetectionModel, DetectionModelStatus, ExcludedCount};

const ENGINE: &str = "reconverge";
const MODEL: &str = "m1";

/// Stores a node with an Unsupervised Engine agent, a model of that engine
/// and an engine document whose pending references name detector 1 on the
/// model, returning the engine instance.
fn engine_with_detector(store: &Store) -> ModelInstance {
    let agent = Agent::new(
        0,
        ENGINE.to_string(),
        AgentKind::Unsupervised,
        AgentStatus::Enabled,
        None,
        None,
    )
    .unwrap();
    let mut node = Node {
        id: 0,
        name: "node".to_string(),
        name_draft: None,
        profile: None,
        profile_draft: None,
        agents: vec![agent],
        external_services: Vec::new(),
        creation_time: Timestamp::UNIX_EPOCH,
    };
    node.id = store.node_map().put(&node).unwrap();
    for agent in &mut node.agents {
        agent.node_id = node.id;
    }
    let engine = ModelInstance {
        node_id: node.id,
        agent_key: ENGINE.to_string(),
    };

    store
        .replace_model(
            Model {
                id: 0,
                name: MODEL.to_string(),
                version: 1,
                kind: "Multifield".to_string(),
                serialized_classifier: b"classifier".to_vec(),
                max_event_id_num: 10,
                raw_event_kind: "http".to_string(),
                log_kind: None,
                classification_id: 1,
                batch_info: Vec::new(),
                scores: [(1, 0.5)].into_iter().collect(),
                clustering_model_type: ClusteringModelTypeRef::Custom,
                training_read: TrainingRead::default(),
                detection_model_states: Vec::new(),
                cluster_count_at_training: None,
            },
            ModelOwner {
                customer_id: 1,
                instance: engine.clone(),
            },
            Timestamp::UNIX_EPOCH,
            TrainedWith {
                run_id: 1,
                definition: "eps = 5.0".to_string(),
                sources: Vec::new(),
            },
        )
        .unwrap();

    let mut drafted = node.clone();
    drafted.agents[0].draft = Some("detectors = 1".to_string().try_into().unwrap());
    store
        .node_map()
        .update_with_engine_documents(
            node.id,
            &node.into(),
            &drafted.into(),
            &[EngineDocumentWrite {
                agent_key: ENGINE.to_string(),
                applied: None,
                pending: Some(EngineDocumentRefs {
                    detectors: vec![EngineDetectorRef {
                        id: 1,
                        model: MODEL.to_string(),
                        sources: vec!["sensor-a".to_string()],
                        indicator: None,
                    }],
                }),
            }],
        )
        .unwrap();
    engine
}

#[test]
fn detection_models_and_excluded_round_trip_in_order() {
    let db_dir = tempfile::tempdir().unwrap();
    let backup_dir = tempfile::tempdir().unwrap();
    let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
    let engine = engine_with_detector(&store);

    let status = DetectorStatus {
        state: DetectorState::Running,
        finished_at: Some(Timestamp::from_second(1_700_000_000).unwrap()),
        outcome: Some(RoundOutcome::Succeeded),
        reason: None,
        events: 7,
        sources: vec![DetectorSourceStatus {
            source: "sensor-a".to_string(),
            state: SourceState::Served,
            reason: None,
        }],
        detection_models: vec![
            DetectionModelStatus {
                detection_model: DetectionModel::FarOutlier,
                skipped: Some("no clusters to compare".to_string()),
                truncated: 0,
            },
            DetectionModelStatus {
                detection_model: DetectionModel::LabelDbMatch,
                skipped: None,
                truncated: 5,
            },
        ],
        excluded: vec![
            ExcludedCount {
                entry: (1_u64 << 53) + 1,
                day: date(2026, 11, 22),
                count: 3,
            },
            ExcludedCount {
                entry: 2,
                day: date(2026, 11, 21),
                count: 1,
            },
        ],
        reported_at: Timestamp::from_second(1_700_000_100).unwrap(),
    };
    store.set_detector_status(&engine, 1, &status).unwrap();

    assert_eq!(store.detector_statuses(&engine).unwrap(), vec![(1, status)]);
}
