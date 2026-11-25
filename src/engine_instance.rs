//! The records the Central Manager keeps for each Unsupervised Engine
//! instance: the references of its applied and pending documents, its
//! detectors' last statuses and whether it is stopped.
//!
//! The references are written only together with the documents they
//! describe, by
//! [`NodeTable::update_with_engine_documents`](crate::NodeTable::update_with_engine_documents),
//! and every record of an agent is removed by the `NodeTable` writer that
//! removes the agent. What is here reads them, and writes the statuses and
//! the stopped state, each in a transaction that reads the instance's agent
//! row, so a write racing an uninstall conflicts with it.
//!
//! The highest detector id an instance's documents have named is kept apart,
//! under the instance's agent lookup key, and is never removed: a detector id
//! is never reused on an instance, also after the engine is removed and
//! installed again on the same host.
//!
//! Also the last exclusion report of each Semi-supervised Engine instance,
//! written in a transaction that reads the instance's agent row and removed
//! with the agent, and each customer's exclusion count totals, read from
//! those reports and from the Unsupervised Engine detectors' statuses.

use std::collections::{BTreeMap, HashSet};

use anyhow::{Context, Result};
use review_protocol::types::{EngineExclusionReport, ExcludedCount};
use rocksdb::{Direction, OptimisticTransactionDB, Transaction};

use crate::{
    Agent, AgentKind, DetectorStatus, EXCLUSIVE, EngineDocumentError, EngineExclusionTotal,
    EngineInstanceState, ModelInstance, ModelUse, Store,
    tables::{self, EngineInstanceRow as Row},
    training::INSTANCE_STOPPED,
    types::FromKeyValue,
};

impl Store {
    /// Returns the stored state of an engine instance; an instance with no
    /// record is not stopped and references nothing. Its `last_detector_id`
    /// is the detector id mark of its agent lookup key, which outlives the
    /// record.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn engine_instance_state(&self, instance: &ModelInstance) -> Result<EngineInstanceState> {
        let last_detector_id = self.states.nodes().last_detector_id(instance)?;
        Ok(self
            .states
            .engine_instances()
            .get(instance)?
            .unwrap_or_default()
            .into_state(instance.clone(), last_detector_id))
    }

    /// Returns the state of every engine instance with a stored record,
    /// ordered by node id, then agent key.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn engine_instance_states(&self) -> Result<Vec<EngineInstanceState>> {
        let nodes = self.states.nodes();
        self.states
            .engine_instances()
            .all()?
            .into_iter()
            .map(|(instance, row)| {
                let last_detector_id = nodes.last_detector_id(&instance)?;
                Ok(row.into_state(instance, last_detector_id))
            })
            .collect()
    }

    /// Returns the detectors whose applied or pending document names the
    /// model `name`, one entry per instance and detector id, ordered by node
    /// id, agent key, then detector id.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn model_users(&self, name: &str) -> Result<Vec<ModelUse>> {
        let mut users = Vec::new();
        for (instance, row) in self.states.engine_instances().all()? {
            let mut detectors: BTreeMap<i32, (bool, bool)> = BTreeMap::new();
            for detector in row.applied.detectors.iter().filter(|d| d.model == name) {
                detectors.entry(detector.id).or_default().0 = true;
            }
            for detector in row.pending.detectors.iter().filter(|d| d.model == name) {
                detectors.entry(detector.id).or_default().1 = true;
            }
            users.extend(
                detectors
                    .into_iter()
                    .map(|(detector_id, (applied, pending))| ModelUse {
                        instance: instance.clone(),
                        detector_id,
                        applied,
                        pending,
                    }),
            );
        }
        Ok(users)
    }

    /// Stores the status a detector of an engine instance reported,
    /// replacing the one stored before.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if the database operation
    /// fails. Returns an [`EngineDocumentError`] inside the error, and changes
    /// nothing, if the instance is not an [`AgentKind::Unsupervised`] agent
    /// row, or if `detector_id` appears in neither its applied nor its
    /// pending references.
    pub fn set_detector_status(
        &self,
        instance: &ModelInstance,
        detector_id: i32,
        status: &DetectorStatus,
    ) -> Result<()> {
        self.write_engine_instance(instance, |_, row| {
            if !row.names_detector(detector_id) {
                return Err(EngineDocumentError::UnknownDetector {
                    node_id: instance.node_id,
                    agent_key: instance.agent_key.clone(),
                    detector_id,
                }
                .into());
            }
            row.statuses.insert(detector_id, status.clone());
            Ok(())
        })
    }

    /// Returns the last status of each detector of an engine instance,
    /// ordered by detector id.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn detector_statuses(
        &self,
        instance: &ModelInstance,
    ) -> Result<Vec<(i32, DetectorStatus)>> {
        Ok(self
            .states
            .engine_instances()
            .get(instance)?
            .map_or_default(|row| row.statuses.into_iter().collect()))
    }

    /// Records whether an engine instance is stopped.
    ///
    /// Stopping an instance also fails, in the same transaction, every
    /// active run the instance performs, with the reason "instance stopped";
    /// a clone run among them removes the target definition it reserved.
    /// Recording that an instance is not stopped changes no run.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if the database operation
    /// fails. Returns an [`EngineDocumentError`] inside the error, and changes
    /// nothing, if the instance is not an [`AgentKind::Unsupervised`] agent
    /// row.
    pub fn set_engine_instance_stopped(
        &self,
        instance: &ModelInstance,
        stopped: bool,
    ) -> Result<()> {
        self.write_engine_instance(instance, |txn, row| {
            row.stopped = stopped;
            if stopped {
                self.fail_active_runs_of_instance(txn, instance, INSTANCE_STOPPED)?;
                #[cfg(test)]
                self.run_training_hook()?;
            }
            Ok(())
        })
    }

    /// Stores the exclusion report a Semi-supervised Engine instance sent,
    /// replacing the one stored before entirely: a count the earlier report
    /// had and `report` lacks is gone.
    ///
    /// The write is one transaction that reads the instance's agent row for
    /// update, so a write racing the agent's removal conflicts with it.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if the database operation
    /// fails. Returns an [`EngineDocumentError`] inside the error, and changes
    /// nothing, if the instance's agent row is missing or is not an
    /// [`AgentKind::SemiSupervised`] agent.
    pub fn set_engine_exclusion_report(
        &self,
        instance: &ModelInstance,
        report: &EngineExclusionReport,
    ) -> Result<()> {
        let db = self.states.db();
        let agents = self.states.agents();
        let counts = self.states.engine_exclusion_counts();
        let key = tables::engine_instance_key(instance.node_id, &instance.agent_key);
        loop {
            let txn = db.transaction();
            if agent_for_update(&txn, agents.raw().cf, &key)?
                .is_none_or(|agent| agent.kind != AgentKind::SemiSupervised)
            {
                return Err(EngineDocumentError::NotSemiSupervisedAgent {
                    node_id: instance.node_id,
                    agent_key: instance.agent_key.clone(),
                }
                .into());
            }
            counts.put(&txn, &key, report)?;
            match txn.commit() {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to write engine exclusion counts");
                    }
                }
            }
        }
    }

    /// Returns the last exclusion report a Semi-supervised Engine instance
    /// sent, or `None` if none is stored.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored report
    /// cannot be decoded.
    pub fn engine_exclusion_report(
        &self,
        instance: &ModelInstance,
    ) -> Result<Option<EngineExclusionReport>> {
        self.states
            .engine_exclusion_counts()
            .get(&tables::engine_instance_key(
                instance.node_id,
                &instance.agent_key,
            ))
    }

    /// Returns the exclusion counts of the engine instances of customer
    /// `customer_id`, summed per engine kind, exclusion-list entry and UTC
    /// day, ordered by engine kind, then entry, then day.
    ///
    /// An instance belongs to the customer when its node's applied profile
    /// has the customer's id; a node with no applied profile belongs to no
    /// customer. For each [`AgentKind::SemiSupervised`] agent the counts of
    /// its stored exclusion report are added, and for each
    /// [`AgentKind::Unsupervised`] agent the `excluded` counts of every stored
    /// detector status. An agent a node lists more than once counts once.
    /// The two kinds are summed apart, so an entry and day
    /// can have one total of each; no other kind has totals. Sums saturate
    /// at `u64::MAX`. A customer with no counts gets an empty vector.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored record
    /// cannot be decoded.
    pub fn engine_exclusion_totals(&self, customer_id: u32) -> Result<Vec<EngineExclusionTotal>> {
        let engine_instances = self.states.engine_instances();
        let exclusion_counts = self.states.engine_exclusion_counts();
        let mut totals: BTreeMap<(AgentKind, u64, jiff::civil::Date), u64> = BTreeMap::new();
        let mut add = |engine: AgentKind, counts: &[ExcludedCount]| {
            for count in counts {
                let total = totals.entry((engine, count.entry, count.day)).or_default();
                *total = total.saturating_add(count.count);
            }
        };
        for node in self.node_map().iter(Direction::Forward, None) {
            let node = node?;
            if node
                .profile
                .as_ref()
                .is_none_or(|profile| profile.customer_id != customer_id)
            {
                continue;
            }
            // A node may list the same agent more than once, and every
            // listing reads the same stored row, so each key counts once.
            let mut seen = HashSet::new();
            for agent in &node.agents {
                if !seen.insert(agent.key.as_str()) {
                    continue;
                }
                match agent.kind {
                    AgentKind::SemiSupervised => {
                        let key = tables::engine_instance_key(node.id, &agent.key);
                        if let Some(report) = exclusion_counts.get(&key)? {
                            add(agent.kind, &report.counts);
                        }
                    }
                    AgentKind::Unsupervised => {
                        let instance = ModelInstance {
                            node_id: node.id,
                            agent_key: agent.key.clone(),
                        };
                        if let Some(row) = engine_instances.get(&instance)? {
                            for status in row.statuses.values() {
                                add(agent.kind, &status.excluded);
                            }
                        }
                    }
                    AgentKind::Sensor
                    | AgentKind::TimeSeriesGenerator
                    | AgentKind::LogCollector => {}
                }
            }
        }
        Ok(totals
            .into_iter()
            .map(|((engine, entry, day), count)| EngineExclusionTotal {
                engine,
                entry,
                day,
                count,
            })
            .collect())
    }

    /// Changes the record of `instance` with `change`, in a transaction that
    /// reads the instance's agent row and record for update and refuses an
    /// instance that is not an Unsupervised Engine agent row.
    fn write_engine_instance(
        &self,
        instance: &ModelInstance,
        change: impl Fn(&Transaction<OptimisticTransactionDB>, &mut Row) -> Result<()>,
    ) -> Result<()> {
        let db = self.states.db();
        let agents = self.states.agents();
        let engine_instances = self.states.engine_instances();
        let key = tables::engine_instance_key(instance.node_id, &instance.agent_key);
        loop {
            let txn = db.transaction();
            if !is_unsupervised_agent(&txn, agents.raw().cf, &key)? {
                return Err(EngineDocumentError::NotUnsupervisedAgent {
                    node_id: instance.node_id,
                    agent_key: instance.agent_key.clone(),
                }
                .into());
            }
            let mut row = engine_instances
                .get_for_update(&txn, &key)?
                .unwrap_or_default();
            change(&txn, &mut row)?;
            engine_instances.put(&txn, &key, &row)?;
            match txn.commit() {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to write engine instance");
                    }
                }
            }
        }
    }
}

/// Returns whether the agent row at `key`, read for update within `txn`, is
/// an Unsupervised Engine agent.
fn is_unsupervised_agent(
    txn: &Transaction<OptimisticTransactionDB>,
    agents: &rocksdb::ColumnFamily,
    key: &[u8],
) -> Result<bool> {
    Ok(agent_for_update(txn, agents, key)?
        .is_some_and(|agent| agent.kind == AgentKind::Unsupervised))
}

/// Returns the agent row at `key`, read for update within `txn`.
pub(crate) fn agent_for_update(
    txn: &Transaction<OptimisticTransactionDB>,
    agents: &rocksdb::ColumnFamily,
    key: &[u8],
) -> Result<Option<Agent>> {
    txn.get_for_update_cf(agents, key, EXCLUSIVE)
        .context("cannot read agent")?
        .map(|value| Agent::from_key_value(key, &value))
        .transpose()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::{
        AgentStatus, DetectorSourceStatus, DetectorState, EngineDetectorRef, EngineDocumentRefs,
        EngineDocumentWrite, ModelIndicator, ModelOwner, Node, NodeProfile, RoundOutcome,
        SourceState, TrainedWith,
        test::{DbGuard, acquire_db_permit},
    };

    const ENGINE: &str = "reconverge";
    const OTHER_ENGINE: &str = "reconverge-2";
    const SENSOR: &str = "piglet";

    struct TestStore {
        _permit: DbGuard<'static>,
        store: Store,
        db_dir: tempfile::TempDir,
        backup_dir: tempfile::TempDir,
    }

    fn setup_store() -> TestStore {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
        TestStore {
            _permit: permit,
            store,
            db_dir,
            backup_dir,
        }
    }

    fn at(secs: i64) -> jiff::Timestamp {
        crate::test::from_second(secs, 0)
    }

    fn agent(key: &str, kind: AgentKind, config: Option<&str>, draft: Option<&str>) -> Agent {
        Agent::new(
            0,
            key.to_string(),
            kind,
            AgentStatus::Enabled,
            config.map(ToString::to_string),
            draft.map(ToString::to_string),
        )
        .unwrap()
    }

    /// The agents of the test node: two engine instances and a sensor.
    fn agents() -> Vec<Agent> {
        vec![
            agent(ENGINE, AgentKind::Unsupervised, None, None),
            agent(OTHER_ENGINE, AgentKind::Unsupervised, None, None),
            agent(SENSOR, AgentKind::Sensor, None, None),
        ]
    }

    /// Inserts a node named `name` with `agents`, returning it as stored.
    fn insert_node(store: &Store, name: &str, agents: Vec<Agent>) -> Node {
        insert_node_with_profiles(store, name, None, None, agents)
    }

    /// Inserts a node named `name` whose applied profile has `hostname`.
    fn insert_node_at(store: &Store, name: &str, hostname: &str, agents: Vec<Agent>) -> Node {
        insert_node_with_profiles(store, name, Some(profile(hostname)), None, agents)
    }

    fn insert_node_with_profiles(
        store: &Store,
        name: &str,
        profile: Option<NodeProfile>,
        profile_draft: Option<NodeProfile>,
        agents: Vec<Agent>,
    ) -> Node {
        let mut node = Node {
            id: 0,
            name: name.to_string(),
            name_draft: None,
            profile,
            profile_draft,
            agents,
            external_services: Vec::new(),
            creation_time: at(0),
        };
        node.id = store.node_map().put(&node).unwrap();
        for agent in &mut node.agents {
            agent.node_id = node.id;
        }
        node
    }

    fn profile(hostname: &str) -> NodeProfile {
        NodeProfile {
            customer_id: 1,
            description: String::new(),
            hostname: hostname.to_string(),
        }
    }

    fn stored_node(store: &Store, id: u32) -> Node {
        store.node_map().get_by_id(id).unwrap().unwrap().0
    }

    fn instance(node_id: u32, agent_key: &str) -> ModelInstance {
        ModelInstance {
            node_id,
            agent_key: agent_key.to_string(),
        }
    }

    /// Stores a model named `name` that belongs to `instance`.
    fn add_model(store: &Store, name: &str, instance: ModelInstance) {
        let body = crate::model::Model {
            id: 0,
            name: name.to_string(),
            version: 1,
            kind: "Multifield".to_string(),
            serialized_classifier: b"classifier".to_vec(),
            max_event_id_num: 10,
            raw_event_kind: "http".to_string(),
            classification_id: 1,
            batch_info: Vec::new(),
            scores: [(1, 0.5)].into_iter().collect(),
            log_kind: None,
            clustering_model_type: crate::ClusteringModelTypeRef::Custom,
            training_read: crate::TrainingRead::default(),
            detection_model_states: Vec::new(),
            cluster_count_at_training: None,
        };
        store
            .replace_model(
                body,
                ModelOwner {
                    customer_id: 1,
                    instance,
                },
                at(100),
                TrainedWith {
                    run_id: 1,
                    definition: "eps = 5.0".to_string(),
                    sources: Vec::new(),
                },
            )
            .unwrap();
    }

    fn add_indicator(store: &Store, name: &str) {
        store
            .model_indicator_map()
            .insert(ModelIndicator {
                name: name.to_string(),
                ..ModelIndicator::default()
            })
            .unwrap();
    }

    fn detector(id: i32, model: &str, indicator: Option<&str>) -> EngineDetectorRef {
        EngineDetectorRef {
            id,
            model: model.to_string(),
            sources: vec!["sensor-a".to_string()],
            indicator: indicator.map(ToString::to_string),
        }
    }

    fn refs(detectors: Vec<EngineDetectorRef>) -> EngineDocumentRefs {
        EngineDocumentRefs { detectors }
    }

    fn write(
        agent_key: &str,
        applied: Option<EngineDocumentRefs>,
        pending: Option<EngineDocumentRefs>,
    ) -> EngineDocumentWrite {
        EngineDocumentWrite {
            agent_key: agent_key.to_string(),
            applied,
            pending,
        }
    }

    /// Returns `node` with the agent `key` changed by `change`.
    fn with_agent(node: &Node, key: &str, change: impl FnOnce(&mut Agent)) -> Node {
        let mut node = node.clone();
        change(node.agents.iter_mut().find(|a| a.key == key).unwrap());
        node
    }

    fn with_draft(node: &Node, key: &str, draft: &str) -> Node {
        with_agent(node, key, |a| {
            a.draft = Some(draft.to_string().try_into().unwrap());
        })
    }

    fn with_config(node: &Node, key: &str, config: &str) -> Node {
        with_agent(node, key, |a| {
            a.config = Some(config.to_string().try_into().unwrap());
        })
    }

    fn without_agent(node: &Node, key: &str) -> Node {
        let mut node = node.clone();
        node.agents.retain(|a| a.key != key);
        node
    }

    fn update_with_documents(
        store: &Store,
        old: &Node,
        new: &Node,
        documents: &[EngineDocumentWrite],
    ) -> Result<Node> {
        store.node_map().update_with_engine_documents(
            old.id,
            &old.clone().into(),
            &new.clone().into(),
            documents,
        )
    }

    fn update(store: &Store, old: &Node, new: &Node) -> Result<Node> {
        store
            .node_map()
            .update(old.id, &old.clone().into(), &new.clone().into())
    }

    fn engine_error(error: &anyhow::Error) -> &EngineDocumentError {
        error
            .downcast_ref::<EngineDocumentError>()
            .unwrap_or_else(|| panic!("not an engine document error: {error:#}"))
    }

    fn status(events: u64) -> DetectorStatus {
        DetectorStatus {
            state: DetectorState::Running,
            finished_at: Some(at(10)),
            outcome: Some(RoundOutcome::Succeeded),
            reason: None,
            events,
            sources: vec![DetectorSourceStatus {
                source: "sensor-a".to_string(),
                state: SourceState::Served,
                reason: None,
            }],
            detection_models: Vec::new(),
            excluded: Vec::new(),
            reported_at: at(20),
        }
    }

    /// The state an instance with no record reads as.
    fn empty_state(instance: ModelInstance) -> EngineInstanceState {
        EngineInstanceState {
            instance,
            stopped: false,
            applied: EngineDocumentRefs::default(),
            pending: EngineDocumentRefs::default(),
            last_detector_id: 0,
        }
    }

    /// A store with a node holding [`agents`], and models `m1` and `m2` of
    /// its engine `ENGINE` and `other` of `OTHER_ENGINE`.
    fn setup_node() -> (TestStore, Node) {
        let t = setup_store();
        let node = insert_node(&t.store, "node", agents());
        add_model(&t.store, "m1", instance(node.id, ENGINE));
        add_model(&t.store, "m2", instance(node.id, ENGINE));
        add_model(&t.store, "other", instance(node.id, OTHER_ENGINE));
        (t, node)
    }

    #[test]
    fn references_are_stored_with_the_document() {
        let (t, node) = setup_node();
        let store = &t.store;
        add_indicator(store, "tokens");

        let pending = refs(vec![
            detector(1, "m1", Some("tokens")),
            detector(-2, "m2", None),
        ]);
        let drafted = with_draft(&node, ENGINE, "revision = 2");
        let returned = update_with_documents(
            store,
            &node,
            &drafted,
            &[write(ENGINE, None, Some(pending.clone()))],
        )
        .unwrap();
        assert_eq!(returned, drafted);
        assert_eq!(stored_node(store, node.id), drafted);
        let state = store
            .engine_instance_state(&instance(node.id, ENGINE))
            .unwrap();
        assert_eq!(
            state,
            EngineInstanceState {
                pending: pending.clone(),
                ..empty_state(instance(node.id, ENGINE))
            }
        );

        let applied = refs(vec![detector(1, "m1", Some("tokens"))]);
        let applied_node = with_config(&drafted, ENGINE, "revision = 2");
        update_with_documents(
            store,
            &drafted,
            &applied_node,
            &[write(ENGINE, Some(applied.clone()), None)],
        )
        .unwrap();
        assert_eq!(stored_node(store, node.id), applied_node);
        let expected = EngineInstanceState {
            applied,
            pending,
            ..empty_state(instance(node.id, ENGINE))
        };
        assert_eq!(
            store
                .engine_instance_state(&instance(node.id, ENGINE))
                .unwrap(),
            expected
        );
        assert_eq!(store.engine_instance_states().unwrap(), vec![expected]);

        assert_eq!(
            store.model_users("m1").unwrap(),
            vec![ModelUse {
                instance: instance(node.id, ENGINE),
                detector_id: 1,
                applied: true,
                pending: true,
            }]
        );
        assert_eq!(
            store.model_users("m2").unwrap(),
            vec![ModelUse {
                instance: instance(node.id, ENGINE),
                detector_id: -2,
                applied: false,
                pending: true,
            }]
        );
        assert_eq!(store.model_users("other").unwrap(), Vec::<ModelUse>::new());

        // An instance with no record reads as empty.
        assert_eq!(
            store
                .engine_instance_state(&instance(node.id, OTHER_ENGINE))
                .unwrap(),
            empty_state(instance(node.id, OTHER_ENGINE))
        );
    }

    /// Asserts that `documents` are refused with `expected` when updating
    /// the test node to `new`, and that neither the node nor any reference
    /// changed.
    fn assert_refused(
        store: &Store,
        node: &Node,
        new: &Node,
        documents: &[EngineDocumentWrite],
        expected: &EngineDocumentError,
    ) {
        let states = store.engine_instance_states().unwrap();
        let error = update_with_documents(store, node, new, documents).unwrap_err();
        assert_eq!(engine_error(&error), expected);
        assert!(error.to_string().contains(match expected {
            EngineDocumentError::ModelNotFound { model, .. }
            | EngineDocumentError::ModelOfAnotherInstance { model, .. }
            | EngineDocumentError::DuplicateModel { model, .. } => model.as_str(),
            EngineDocumentError::IndicatorNotFound { indicator, .. } => indicator.as_str(),
            EngineDocumentError::NotUnsupervisedAgent { agent_key, .. }
            | EngineDocumentError::NotSemiSupervisedAgent { agent_key, .. }
            | EngineDocumentError::DuplicateAgentKey { agent_key }
            | EngineDocumentError::KindChanged { agent_key }
            | EngineDocumentError::DraftWithoutReferences { agent_key }
            | EngineDocumentError::ConfigWithoutReferences { agent_key }
            | EngineDocumentError::StaleDocument { agent_key }
            | EngineDocumentError::RequiresEngineDocuments { agent_key }
            | EngineDocumentError::DuplicateDetectorId { agent_key, .. }
            | EngineDocumentError::UnknownDetector { agent_key, .. }
            | EngineDocumentError::DetectorIdRetired { agent_key, .. } => agent_key.as_str(),
        }));
        assert_eq!(stored_node(store, node.id), *node);
        assert_eq!(store.engine_instance_states().unwrap(), states);
    }

    #[test]
    fn invalid_references_are_refused() {
        let (t, node) = setup_node();
        let store = &t.store;
        add_indicator(store, "tokens");
        let drafted = with_draft(&node, ENGINE, "revision = 1");
        let pending = |detectors| [write(ENGINE, None, Some(refs(detectors)))];
        let key = || ENGINE.to_string();

        assert_refused(
            store,
            &node,
            &drafted,
            &pending(vec![detector(1, "missing", None)]),
            &EngineDocumentError::ModelNotFound {
                agent_key: key(),
                model: "missing".to_string(),
            },
        );
        assert_refused(
            store,
            &node,
            &drafted,
            &pending(vec![detector(1, "other", None)]),
            &EngineDocumentError::ModelOfAnotherInstance {
                agent_key: key(),
                model: "other".to_string(),
            },
        );
        assert_refused(
            store,
            &node,
            &drafted,
            &pending(vec![detector(1, "m1", None), detector(2, "m1", None)]),
            &EngineDocumentError::DuplicateModel {
                agent_key: key(),
                model: "m1".to_string(),
            },
        );
        assert_refused(
            store,
            &node,
            &drafted,
            &pending(vec![detector(7, "m1", None), detector(7, "m2", None)]),
            &EngineDocumentError::DuplicateDetectorId {
                agent_key: key(),
                detector_id: 7,
            },
        );
        assert_refused(
            store,
            &node,
            &drafted,
            &pending(vec![detector(1, "m1", Some("absent"))]),
            &EngineDocumentError::IndicatorNotFound {
                agent_key: key(),
                indicator: "absent".to_string(),
            },
        );
        // The applied slot is checked as well as the pending one.
        assert_refused(
            store,
            &node,
            &with_config(&drafted, ENGINE, "revision = 1"),
            &[write(
                ENGINE,
                Some(refs(vec![detector(1, "missing", None)])),
                Some(refs(vec![detector(1, "m1", None)])),
            )],
            &EngineDocumentError::ModelNotFound {
                agent_key: key(),
                model: "missing".to_string(),
            },
        );
    }

    #[test]
    fn invalid_agents_are_refused() {
        let (t, node) = setup_node();
        let store = &t.store;
        let empty = || Some(EngineDocumentRefs::default());

        assert_refused(
            store,
            &node,
            &node,
            &[write(SENSOR, None, empty())],
            &EngineDocumentError::NotUnsupervisedAgent {
                node_id: node.id,
                agent_key: SENSOR.to_string(),
            },
        );
        assert_refused(
            store,
            &node,
            &node,
            &[write("absent", None, empty())],
            &EngineDocumentError::NotUnsupervisedAgent {
                node_id: node.id,
                agent_key: "absent".to_string(),
            },
        );
        // An agent the update removes is not an agent of the node.
        assert_refused(
            store,
            &node,
            &without_agent(&node, ENGINE),
            &[write(ENGINE, None, empty())],
            &EngineDocumentError::NotUnsupervisedAgent {
                node_id: node.id,
                agent_key: ENGINE.to_string(),
            },
        );
        assert_refused(
            store,
            &node,
            &node,
            &[write(ENGINE, None, empty()), write(ENGINE, empty(), None)],
            &EngineDocumentError::DuplicateAgentKey {
                agent_key: ENGINE.to_string(),
            },
        );
        assert_refused(
            store,
            &node,
            &with_agent(&node, ENGINE, |a| a.kind = AgentKind::SemiSupervised),
            &[],
            &EngineDocumentError::KindChanged {
                agent_key: ENGINE.to_string(),
            },
        );
        assert_refused(
            store,
            &node,
            &with_agent(&node, SENSOR, |a| a.kind = AgentKind::Unsupervised),
            &[write(SENSOR, None, empty())],
            &EngineDocumentError::KindChanged {
                agent_key: SENSOR.to_string(),
            },
        );
        assert_refused(
            store,
            &node,
            &with_draft(&node, ENGINE, "revision = 1"),
            &[write(ENGINE, empty(), None)],
            &EngineDocumentError::DraftWithoutReferences {
                agent_key: ENGINE.to_string(),
            },
        );
        assert_refused(
            store,
            &node,
            &with_config(&node, ENGINE, "revision = 1"),
            &[],
            &EngineDocumentError::ConfigWithoutReferences {
                agent_key: ENGINE.to_string(),
            },
        );

        // A stored row that is no longer an Unsupervised agent is refused,
        // whatever `old` says.
        let stored = store.agents_map().get(node.id, ENGINE).unwrap().unwrap();
        let mut sensor = stored.clone();
        sensor.kind = AgentKind::Sensor;
        store.agents_map().update(&stored, &sensor).unwrap();
        let error = update_with_documents(store, &node, &node, &[write(ENGINE, None, empty())])
            .unwrap_err();
        assert_eq!(
            engine_error(&error),
            &EngineDocumentError::NotUnsupervisedAgent {
                node_id: node.id,
                agent_key: ENGINE.to_string(),
            }
        );
        assert_eq!(
            store.engine_instance_states().unwrap(),
            Vec::<EngineInstanceState>::new()
        );
    }

    /// A model deleted after the update read it and before the update
    /// commits makes the update conflict, retry, and refuse the reference.
    #[test]
    fn a_model_deleted_before_the_commit_refuses_the_update() {
        let (t, node) = setup_node();
        let store = &t.store;
        let drafted = with_draft(&node, ENGINE, "revision = 1");
        let fired = Cell::new(0);
        let mut nodes = store.node_map();
        nodes.set_before_commit_hook(Some(Box::new(|| {
            fired.set(fired.get() + 1);
            if fired.get() == 1 {
                store.delete_model("m1")?;
            }
            Ok(())
        })));

        let error = nodes
            .update_with_engine_documents(
                node.id,
                &node.clone().into(),
                &drafted.clone().into(),
                &[write(
                    ENGINE,
                    None,
                    Some(refs(vec![detector(1, "m1", None)])),
                )],
            )
            .unwrap_err();
        drop(nodes);

        assert_eq!(fired.get(), 1, "the retry refuses before the hook");
        assert_eq!(
            engine_error(&error),
            &EngineDocumentError::ModelNotFound {
                agent_key: ENGINE.to_string(),
                model: "m1".to_string(),
            }
        );
        assert_eq!(stored_node(store, node.id), node);
        assert_eq!(
            store.engine_instance_states().unwrap(),
            Vec::<EngineInstanceState>::new()
        );
        assert_eq!(store.model_users("m1").unwrap(), Vec::<ModelUse>::new());
    }

    /// Saves a draft naming `m1` and then one naming `m2`, returning the
    /// node as each left it.
    fn save_two_drafts(store: &Store, node: &Node) -> (Node, Node) {
        let first = with_draft(node, ENGINE, "model = \"m1\"");
        update_with_documents(
            store,
            node,
            &first,
            &[write(
                ENGINE,
                None,
                Some(refs(vec![detector(1, "m1", None)])),
            )],
        )
        .unwrap();
        let second = with_draft(&first, ENGINE, "model = \"m2\"");
        update_with_documents(
            store,
            &first,
            &second,
            &[write(
                ENGINE,
                None,
                Some(refs(vec![detector(1, "m2", None)])),
            )],
        )
        .unwrap();
        (first, second)
    }

    /// Asserts that the stored node is `node` and that `ENGINE` still
    /// references `m2` alone.
    fn assert_second_draft_kept(store: &Store, node: &Node) {
        assert_eq!(stored_node(store, node.id), *node);
        assert_eq!(store.model_users("m1").unwrap(), Vec::<ModelUse>::new());
        assert_eq!(
            store.model_users("m2").unwrap(),
            vec![ModelUse {
                instance: instance(node.id, ENGINE),
                detector_id: 1,
                applied: false,
                pending: true,
            }]
        );
    }

    /// A document the update keeps unchanged is checked against the stored
    /// one, so references read from a stale node do not replace those of
    /// the document stored since.
    #[test]
    fn references_of_a_stale_unchanged_document_are_refused() {
        let (t, node) = setup_node();
        let store = &t.store;
        let (first, second) = save_two_drafts(store, &node);

        let stale = [write(
            ENGINE,
            None,
            Some(refs(vec![detector(1, "m1", None)])),
        )];
        let error = update_with_documents(store, &first, &first, &stale).unwrap_err();
        assert_eq!(
            engine_error(&error),
            &EngineDocumentError::StaleDocument {
                agent_key: ENGINE.to_string(),
            }
        );
        assert!(error.to_string().contains(ENGINE));
        assert_second_draft_kept(store, &second);

        // The applied slot is checked against the stored `config`.
        let applied = with_config(&second, ENGINE, "model = \"m2\"");
        update_with_documents(
            store,
            &second,
            &applied,
            &[write(
                ENGINE,
                Some(refs(vec![detector(1, "m2", None)])),
                None,
            )],
        )
        .unwrap();
        let error = update_with_documents(
            store,
            &second,
            &second,
            &[write(
                ENGINE,
                Some(refs(vec![detector(1, "m1", None)])),
                None,
            )],
        )
        .unwrap_err();
        assert_eq!(
            engine_error(&error),
            &EngineDocumentError::StaleDocument {
                agent_key: ENGINE.to_string(),
            }
        );
        assert_eq!(stored_node(store, node.id), applied);
        assert_eq!(store.model_users("m1").unwrap(), Vec::<ModelUse>::new());

        // Writing the stored document's references again is accepted.
        update_with_documents(
            store,
            &applied,
            &applied,
            &[write(
                ENGINE,
                None,
                Some(refs(vec![detector(1, "m2", None)])),
            )],
        )
        .unwrap();
    }

    /// A document stored after the update read the agent and before the
    /// update commits makes the update conflict, retry, and refuse the
    /// references of the document it read.
    #[test]
    fn a_document_stored_before_the_commit_refuses_the_update() {
        let (t, node) = setup_node();
        let store = &t.store;
        let first = with_draft(&node, ENGINE, "model = \"m1\"");
        update_with_documents(
            store,
            &node,
            &first,
            &[write(
                ENGINE,
                None,
                Some(refs(vec![detector(1, "m1", None)])),
            )],
        )
        .unwrap();
        let second = with_draft(&first, ENGINE, "model = \"m2\"");

        let fired = Cell::new(0);
        let mut nodes = store.node_map();
        nodes.set_before_commit_hook(Some(Box::new(|| {
            fired.set(fired.get() + 1);
            if fired.get() == 1 {
                update_with_documents(
                    store,
                    &first,
                    &second,
                    &[write(
                        ENGINE,
                        None,
                        Some(refs(vec![detector(1, "m2", None)])),
                    )],
                )?;
            }
            Ok(())
        })));

        let error = nodes
            .update_with_engine_documents(
                node.id,
                &first.clone().into(),
                &first.clone().into(),
                &[write(
                    ENGINE,
                    None,
                    Some(refs(vec![detector(1, "m1", None)])),
                )],
            )
            .unwrap_err();
        drop(nodes);

        assert_eq!(fired.get(), 1, "the retry refuses before the hook");
        assert_eq!(
            engine_error(&error),
            &EngineDocumentError::StaleDocument {
                agent_key: ENGINE.to_string(),
            }
        );
        assert_second_draft_kept(store, &second);
    }

    /// Gives `ENGINE` of `node` a pending reference, a status and the
    /// stopped state, returning the node as updated.
    fn populate_engine(store: &Store, node: &Node) -> Node {
        let drafted = with_draft(node, ENGINE, "revision = 1");
        update_with_documents(
            store,
            node,
            &drafted,
            &[write(
                ENGINE,
                None,
                Some(refs(vec![detector(1, "m1", None)])),
            )],
        )
        .unwrap();
        let engine = instance(node.id, ENGINE);
        store.set_detector_status(&engine, 1, &status(3)).unwrap();
        store.set_engine_instance_stopped(&engine, true).unwrap();
        assert!(store.engine_instance_state(&engine).unwrap().stopped);
        assert_eq!(store.detector_statuses(&engine).unwrap().len(), 1);
        drafted
    }

    /// Asserts that `ENGINE` of node `id` has no record, and, when the node
    /// is inserted again, that it is given another id and the removed
    /// instance still has none.
    fn assert_engine_records_removed(store: &Store, id: u32, reinsert: bool) {
        let engine = instance(id, ENGINE);
        assert_eq!(
            store.engine_instance_state(&engine).unwrap(),
            empty_state(engine.clone())
        );
        assert_eq!(
            store.detector_statuses(&engine).unwrap(),
            Vec::<(i32, DetectorStatus)>::new()
        );
        assert_eq!(store.model_users("m1").unwrap(), Vec::<ModelUse>::new());
        assert!(
            store
                .engine_instance_states()
                .unwrap()
                .iter()
                .all(|state| state.instance != engine)
        );
        if reinsert {
            let node = insert_node(store, "reinserted", agents());
            assert_ne!(node.id, id, "the node id is not reused");
            assert_eq!(
                store.engine_instance_state(&engine).unwrap(),
                empty_state(engine.clone())
            );
            assert_eq!(
                store.detector_statuses(&engine).unwrap(),
                Vec::<(i32, DetectorStatus)>::new()
            );
        }
    }

    #[test]
    fn removing_the_agent_through_update_with_engine_documents_removes_its_records() {
        let (t, node) = setup_node();
        let store = &t.store;
        let node = populate_engine(store, &node);
        update_with_documents(store, &node, &without_agent(&node, ENGINE), &[]).unwrap();
        assert_engine_records_removed(store, node.id, false);
    }

    #[test]
    fn removing_the_agent_through_update_removes_its_records() {
        let (t, node) = setup_node();
        let store = &t.store;
        let node = populate_engine(store, &node);
        let removed = without_agent(&node, ENGINE);
        update(store, &node, &removed).unwrap();
        assert_engine_records_removed(store, node.id, false);

        // The agent is installed again under the same key.
        update(store, &removed, &node).unwrap();
        let engine = instance(node.id, ENGINE);
        assert_eq!(
            store.engine_instance_state(&engine).unwrap(),
            empty_state(engine.clone())
        );
        assert_eq!(
            store.detector_statuses(&engine).unwrap(),
            Vec::<(i32, DetectorStatus)>::new()
        );
    }

    #[test]
    fn removing_the_node_removes_the_records_of_its_agents() {
        let (t, node) = setup_node();
        let store = &t.store;
        populate_engine(store, &node);
        assert_eq!(
            store.node_map().remove(node.id).unwrap().1,
            Vec::<String>::new()
        );
        assert!(store.node_map().get_by_id(node.id).unwrap().is_none());
        assert!(store.agents_map().get(node.id, ENGINE).unwrap().is_none());
        assert_engine_records_removed(store, node.id, true);
        assert_eq!(
            store.engine_instance_states().unwrap(),
            Vec::<EngineInstanceState>::new()
        );
    }

    /// The references of the detectors `ids`, each serving the model
    /// `<prefix><id>`.
    fn detectors(prefix: &str, ids: &[i32]) -> EngineDocumentRefs {
        refs(
            ids.iter()
                .map(|id| detector(*id, &format!("{prefix}{id}"), None))
                .collect(),
        )
    }

    /// Returns `node` with `ENGINE` applying, and drafting, the detectors
    /// `ids`, each serving the model `<prefix><id>`.
    fn apply_detectors(store: &Store, node: &Node, prefix: &str, ids: &[i32]) -> Result<Node> {
        let detectors = detectors(prefix, ids);
        let doc = format!("ids = {ids:?}");
        let new = with_draft(&with_config(node, ENGINE, &doc), ENGINE, &doc);
        update_with_documents(
            store,
            node,
            &new,
            &[write(ENGINE, Some(detectors.clone()), Some(detectors))],
        )
    }

    /// Stores the models `<prefix><id>` of `ENGINE` of node `node_id`.
    fn add_detector_models(store: &Store, node_id: u32, prefix: &str, ids: &[i32]) {
        for id in ids {
            add_model(store, &format!("{prefix}{id}"), instance(node_id, ENGINE));
        }
    }

    fn last_detector_id(store: &Store, node_id: u32) -> i32 {
        store
            .engine_instance_state(&instance(node_id, ENGINE))
            .unwrap()
            .last_detector_id
    }

    /// An engine removed and installed again on the same host under the same
    /// key, through a new node, continues from the detector id mark its
    /// removed agent left, while the same key on another host has its own.
    #[test]
    fn a_reinstalled_engine_keeps_its_detector_id_mark() {
        const HOST: &str = "node1.example.com";
        let t = setup_store();
        let store = &t.store;
        let node = insert_node_at(store, "node", HOST, agents());
        add_detector_models(store, node.id, "m", &[1, 2, 3, 4]);
        let node = apply_detectors(store, &node, "m", &[1, 2, 3, 4]).unwrap();
        assert_eq!(last_detector_id(store, node.id), 4);

        // The removal finalizer's path: the agent row goes, with its record,
        // then the node.
        let removed = without_agent(&node, ENGINE);
        update(store, &node, &removed).unwrap();
        let engine = instance(node.id, ENGINE);
        assert_eq!(
            store.engine_instance_state(&engine).unwrap(),
            EngineInstanceState {
                last_detector_id: 4,
                ..empty_state(engine.clone())
            }
        );
        assert!(
            store
                .engine_instance_states()
                .unwrap()
                .iter()
                .all(|state| state.instance != engine)
        );
        store.node_map().remove(node.id).unwrap();
        assert_eq!(last_detector_id(store, node.id), 0, "the node is gone");

        let other = insert_node_at(store, "other", "node2.example.com", agents());
        let reinstalled = insert_node_at(store, "reinstalled", HOST, agents());
        let engine = instance(reinstalled.id, ENGINE);
        assert_eq!(
            store.engine_instance_state(&engine).unwrap(),
            EngineInstanceState {
                last_detector_id: 4,
                ..empty_state(engine.clone())
            }
        );
        add_detector_models(store, reinstalled.id, "n", &[1, 5]);
        assert_refused(
            store,
            &reinstalled,
            &with_config(&reinstalled, ENGINE, "ids = [1]"),
            &[write(ENGINE, Some(detectors("n", &[1])), None)],
            &EngineDocumentError::DetectorIdRetired {
                agent_key: ENGINE.to_string(),
                detector_id: 1,
            },
        );
        apply_detectors(store, &reinstalled, "n", &[5]).unwrap();
        assert_eq!(last_detector_id(store, reinstalled.id), 5);

        // The same key on another host has its own mark.
        assert_eq!(last_detector_id(store, other.id), 0);
        add_detector_models(store, other.id, "o", &[1]);
        apply_detectors(store, &other, "o", &[1]).unwrap();
        assert_eq!(last_detector_id(store, other.id), 1);
        assert_eq!(last_detector_id(store, reinstalled.id), 5);
    }

    /// An agent added again under the same key on the same node continues
    /// from its mark, kept under the draft hostname of a node with no applied
    /// profile, and a node with no hostname keeps no mark.
    #[test]
    fn a_detector_id_mark_survives_reinstalling_the_agent() {
        let t = setup_store();
        let store = &t.store;
        let node = insert_node_with_profiles(
            store,
            "node",
            None,
            Some(profile("draft.example.com")),
            agents(),
        );
        add_detector_models(store, node.id, "m", &[1, 2]);
        let node = apply_detectors(store, &node, "m", &[1, 2]).unwrap();
        assert_eq!(last_detector_id(store, node.id), 2);

        let removed = without_agent(&node, ENGINE);
        update(store, &node, &removed).unwrap();
        let mut readded = removed.clone();
        readded
            .agents
            .push(agent(ENGINE, AgentKind::Unsupervised, None, None));
        update(store, &removed, &readded).unwrap();
        let readded = stored_node(store, node.id);
        assert_eq!(last_detector_id(store, node.id), 2);
        add_detector_models(store, node.id, "n", &[1, 3]);
        let error = apply_detectors(store, &readded, "n", &[1, 3]).unwrap_err();
        assert_eq!(
            engine_error(&error),
            &EngineDocumentError::DetectorIdRetired {
                agent_key: ENGINE.to_string(),
                detector_id: 1,
            }
        );
        apply_detectors(store, &readded, "n", &[3]).unwrap();
        assert_eq!(last_detector_id(store, node.id), 3);

        let hostless = insert_node(store, "hostless", agents());
        add_detector_models(store, hostless.id, "h", &[1, 2]);
        let hostless = apply_detectors(store, &hostless, "h", &[2]).unwrap();
        apply_detectors(store, &hostless, "h", &[1]).unwrap();
        assert_eq!(last_detector_id(store, hostless.id), 0);
    }

    /// An uninstall whose cleanup deleted the record, and a stop recorded
    /// for the instance before the uninstall commits, conflict: the
    /// uninstall retries and no record is left.
    #[test]
    fn a_stop_racing_an_uninstall_leaves_no_record() {
        for remove_node in [false, true] {
            let (t, node) = setup_node();
            let store = &t.store;
            let engine = instance(node.id, ENGINE);
            let fired = Cell::new(0);
            let mut nodes = store.node_map();
            nodes.set_before_commit_hook(Some(Box::new(|| {
                fired.set(fired.get() + 1);
                if fired.get() == 1 {
                    store.set_engine_instance_stopped(&engine, true)?;
                }
                Ok(())
            })));
            if remove_node {
                nodes.remove(node.id).unwrap();
            } else {
                nodes
                    .update(
                        node.id,
                        &node.clone().into(),
                        &without_agent(&node, ENGINE).into(),
                    )
                    .unwrap();
            }
            drop(nodes);

            assert_eq!(fired.get(), 2, "the uninstall retried");
            assert_eq!(
                store.engine_instance_states().unwrap(),
                Vec::<EngineInstanceState>::new()
            );
            assert!(!store.engine_instance_state(&engine).unwrap().stopped);
        }
    }

    #[test]
    fn plain_update_refuses_engine_document_changes() {
        let (t, node) = setup_node();
        let store = &t.store;
        let refused = [
            with_draft(&node, ENGINE, "revision = 1"),
            with_config(&node, ENGINE, "revision = 1"),
            with_agent(&node, ENGINE, |a| a.kind = AgentKind::Sensor),
            with_agent(&node, SENSOR, |a| a.kind = AgentKind::Unsupervised),
        ];
        for new in refused {
            let error = update(store, &node, &new).unwrap_err();
            let EngineDocumentError::RequiresEngineDocuments { agent_key } = engine_error(&error)
            else {
                panic!("unexpected refusal: {error}");
            };
            assert!(agent_key == ENGINE || agent_key == SENSOR);
            assert!(error.to_string().contains("update_with_engine_documents"));
            assert_eq!(stored_node(store, node.id), node);
        }

        // Install state changes, and adding and removing an engine agent,
        // are accepted.
        let installed = with_agent(&node, ENGINE, |a| {
            a.installed_version = Some("1.0.0".to_string());
            a.lifecycle = crate::Lifecycle::Running;
        });
        update(store, &node, &installed).unwrap();
        assert_eq!(stored_node(store, node.id), installed);
        let mut added = installed.clone();
        added.agents.push(Agent {
            node_id: node.id,
            ..agent(
                "reconverge-3",
                AgentKind::Unsupervised,
                Some("revision = 0"),
                None,
            )
        });
        update(store, &installed, &added).unwrap();
        assert_eq!(stored_node(store, node.id), added);
        let removed = without_agent(&added, OTHER_ENGINE);
        update(store, &added, &removed).unwrap();
        assert_eq!(stored_node(store, node.id), removed);
    }

    #[test]
    fn writing_references_drops_statuses_of_detectors_no_longer_named() {
        let (t, node) = setup_node();
        let store = &t.store;
        let engine = instance(node.id, ENGINE);
        let drafted = with_draft(&node, ENGINE, "revision = 2");
        update_with_documents(
            store,
            &node,
            &drafted,
            &[write(
                ENGINE,
                None,
                Some(refs(vec![detector(1, "m1", None), detector(2, "m2", None)])),
            )],
        )
        .unwrap();
        let applied = with_config(&drafted, ENGINE, "revision = 2");
        update_with_documents(
            store,
            &drafted,
            &applied,
            &[write(
                ENGINE,
                Some(refs(vec![detector(1, "m1", None)])),
                None,
            )],
        )
        .unwrap();
        store.set_detector_status(&engine, 1, &status(1)).unwrap();
        store.set_detector_status(&engine, 2, &status(2)).unwrap();

        // Detector 2 leaves the draft; detector 1 stays in the config.
        let redrafted = with_draft(&applied, ENGINE, "revision = 1");
        update_with_documents(
            store,
            &applied,
            &redrafted,
            &[write(
                ENGINE,
                None,
                Some(refs(vec![detector(1, "m1", None)])),
            )],
        )
        .unwrap();
        assert_eq!(
            store.detector_statuses(&engine).unwrap(),
            vec![(1, status(1))]
        );
        assert_eq!(
            store.engine_instance_state(&engine).unwrap().pending,
            refs(vec![detector(1, "m1", None)])
        );
    }

    #[test]
    fn a_detector_id_is_never_reused() {
        let t = setup_store();
        let store = &t.store;
        let node = insert_node_at(store, "node", "node1.example.com", agents());
        add_detector_models(store, node.id, "m", &[1, 2, 3, 4, 5]);
        let engine = instance(node.id, ENGINE);
        let applied = |ids: &[i32]| detectors("m", ids);

        let node = apply_detectors(store, &node, "m", &[1, 2, 3]).unwrap();
        let node = apply_detectors(store, &node, "m", &[1, 2]).unwrap();
        assert_eq!(last_detector_id(store, node.id), 3);

        // A new detector 3 is refused, in either slot.
        let retired = EngineDocumentError::DetectorIdRetired {
            agent_key: ENGINE.to_string(),
            detector_id: 3,
        };
        let configured = with_config(&node, ENGINE, "ids = [1, 2, 3]");
        assert_refused(
            store,
            &node,
            &configured,
            &[write(ENGINE, Some(applied(&[1, 2, 3])), None)],
            &retired,
        );
        let drafted = with_draft(&node, ENGINE, "ids = [3]");
        assert_refused(
            store,
            &node,
            &drafted,
            &[write(ENGINE, None, Some(applied(&[3])))],
            &retired,
        );
        let error = update_with_documents(
            store,
            &node,
            &drafted,
            &[write(ENGINE, None, Some(applied(&[3])))],
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "detector id 3 of agent {ENGINE:?} was used by a removed detector; a detector \
                 id is never reused"
            )
        );

        let node = apply_detectors(store, &node, "m", &[1, 2, 4]).unwrap();
        assert_eq!(last_detector_id(store, node.id), 4);
        let state = store.engine_instance_state(&engine).unwrap();
        assert_eq!(state.applied, applied(&[1, 2, 4]));
        assert_eq!(
            store
                .engine_instance_states()
                .unwrap()
                .iter()
                .find(|state| state.instance == engine)
                .unwrap()
                .last_detector_id,
            4
        );

        // The mark counts drafts too.
        let draft = |node: &Node, ids: &[i32]| {
            let new = with_draft(node, ENGINE, &format!("ids = {ids:?}"));
            update_with_documents(
                store,
                node,
                &new,
                &[write(ENGINE, None, Some(applied(ids)))],
            )
        };
        let node = draft(&node, &[1, 2, 4, 5]).unwrap();
        assert_eq!(last_detector_id(store, node.id), 5);
        let node = draft(&node, &[1, 2, 4]).unwrap();
        assert_eq!(last_detector_id(store, node.id), 5);
        let error = draft(&node, &[1, 2, 4, 5]).unwrap_err();
        assert_eq!(
            engine_error(&error),
            &EngineDocumentError::DetectorIdRetired {
                agent_key: ENGINE.to_string(),
                detector_id: 5,
            }
        );

        // Detector 2 leaves the draft but stays in the config: it is the same
        // detector, and the draft can name it again.
        let node = draft(&node, &[1, 4]).unwrap();
        let node = draft(&node, &[1, 2, 4]).unwrap();
        assert_eq!(
            store.engine_instance_state(&engine).unwrap().pending,
            applied(&[1, 2, 4])
        );
        assert_eq!(last_detector_id(store, node.id), 5);
    }

    #[test]
    fn the_last_status_of_each_detector_is_kept() {
        let t = setup_store();
        let store = &t.store;
        // One agent key is a prefix of the other.
        let node = insert_node(
            store,
            "node",
            vec![
                agent("a", AgentKind::Unsupervised, None, None),
                agent("ab", AgentKind::Unsupervised, None, None),
            ],
        );
        add_model(store, "ma", instance(node.id, "a"));
        add_model(store, "ma2", instance(node.id, "a"));
        add_model(store, "mb", instance(node.id, "ab"));
        let drafted = with_draft(&with_draft(&node, "a", "x = 1"), "ab", "x = 1");
        update_with_documents(
            store,
            &node,
            &drafted,
            &[
                write(
                    "a",
                    None,
                    Some(refs(vec![
                        detector(5, "ma", None),
                        detector(-3, "ma2", None),
                    ])),
                ),
                write("ab", None, Some(refs(vec![detector(5, "mb", None)]))),
            ],
        )
        .unwrap();

        let a = instance(node.id, "a");
        let ab = instance(node.id, "ab");
        store.set_detector_status(&a, 5, &status(1)).unwrap();
        store.set_detector_status(&a, -3, &status(2)).unwrap();
        store.set_detector_status(&ab, 5, &status(3)).unwrap();
        store.set_detector_status(&a, 5, &status(4)).unwrap();

        assert_eq!(
            store.detector_statuses(&a).unwrap(),
            vec![(-3, status(2)), (5, status(4))]
        );
        assert_eq!(store.detector_statuses(&ab).unwrap(), vec![(5, status(3))]);
    }

    #[test]
    fn statuses_and_stops_of_non_engine_instances_are_refused() {
        let (t, node) = setup_node();
        let store = &t.store;
        populate_engine(store, &node);

        for agent_key in ["absent", SENSOR] {
            let target = instance(node.id, agent_key);
            let error = store
                .set_detector_status(&target, 1, &status(1))
                .unwrap_err();
            assert_eq!(
                engine_error(&error),
                &EngineDocumentError::NotUnsupervisedAgent {
                    node_id: node.id,
                    agent_key: agent_key.to_string(),
                }
            );
            let error = store
                .set_engine_instance_stopped(&target, true)
                .unwrap_err();
            assert_eq!(
                engine_error(&error),
                &EngineDocumentError::NotUnsupervisedAgent {
                    node_id: node.id,
                    agent_key: agent_key.to_string(),
                }
            );
        }
        let error = store
            .set_detector_status(&instance(node.id + 1, ENGINE), 1, &status(1))
            .unwrap_err();
        assert!(matches!(
            engine_error(&error),
            EngineDocumentError::NotUnsupervisedAgent { .. }
        ));

        let engine = instance(node.id, ENGINE);
        let error = store
            .set_detector_status(&engine, 2, &status(1))
            .unwrap_err();
        assert_eq!(
            engine_error(&error),
            &EngineDocumentError::UnknownDetector {
                node_id: node.id,
                agent_key: ENGINE.to_string(),
                detector_id: 2,
            }
        );
        assert_eq!(
            store.detector_statuses(&engine).unwrap(),
            vec![(1, status(3))]
        );
        assert_eq!(store.engine_instance_states().unwrap().len(), 1);
    }

    #[test]
    fn the_stopped_state_persists_across_reopening() {
        let t = setup_store();
        let node = insert_node(&t.store, "node", agents());
        let engine = instance(node.id, ENGINE);
        t.store.set_engine_instance_stopped(&engine, true).unwrap();
        let TestStore {
            _permit,
            store,
            db_dir,
            backup_dir,
        } = t;
        drop(store);

        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
        assert!(store.engine_instance_state(&engine).unwrap().stopped);
        store.set_engine_instance_stopped(&engine, false).unwrap();
        drop(store);

        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
        assert!(!store.engine_instance_state(&engine).unwrap().stopped);
    }

    // =========================================================================
    // Engine exclusion counts
    // =========================================================================

    const HOG: &str = "hog";
    const OTHER_HOG: &str = "hog-2";

    fn excluded(entry: u64, day: i8, count: u64) -> ExcludedCount {
        ExcludedCount {
            entry,
            day: jiff::civil::date(2026, 3, day),
            count,
        }
    }

    fn report(counts: Vec<ExcludedCount>) -> EngineExclusionReport {
        EngineExclusionReport { counts }
    }

    /// The agents of a node with two Semi-supervised Engine instances besides
    /// [`agents`].
    fn hog_agents() -> Vec<Agent> {
        let mut agents = agents();
        agents.push(agent(HOG, AgentKind::SemiSupervised, None, None));
        agents.push(agent(OTHER_HOG, AgentKind::SemiSupervised, None, None));
        agents
    }

    /// Returns the number of rows in the `engine exclusion counts` family.
    fn exclusion_count_rows(store: &Store) -> usize {
        let db = store.states.db();
        let cf = db.cf_handle(tables::ENGINE_EXCLUSION_COUNTS).unwrap();
        db.iterator_cf(cf, rocksdb::IteratorMode::Start).count()
    }

    #[test]
    fn an_exclusion_report_is_stored_and_replaced_completely() {
        let t = setup_store();
        let store = &t.store;
        let node = insert_node(store, "node", hog_agents());
        let hog = instance(node.id, HOG);
        let other_hog = instance(node.id, OTHER_HOG);
        assert_eq!(store.engine_exclusion_report(&hog).unwrap(), None);

        let first = report(vec![
            excluded((1 << 53) + 3, 14, 5),
            excluded(2, 14, 3),
            excluded(2, 15, u64::MAX),
        ]);
        store.set_engine_exclusion_report(&hog, &first).unwrap();
        assert_eq!(
            store.engine_exclusion_report(&hog).unwrap(),
            Some(first.clone())
        );
        assert_eq!(store.engine_exclusion_report(&other_hog).unwrap(), None);

        // The second report replaces the first: entry 2 is gone.
        let second = report(vec![excluded(1, 16, 9)]);
        store.set_engine_exclusion_report(&hog, &second).unwrap();
        assert_eq!(
            store.engine_exclusion_report(&hog).unwrap(),
            Some(second.clone())
        );

        // An empty report is stored as such.
        store
            .set_engine_exclusion_report(&other_hog, &report(Vec::new()))
            .unwrap();
        assert_eq!(
            store.engine_exclusion_report(&other_hog).unwrap(),
            Some(report(Vec::new()))
        );
        assert_eq!(store.engine_exclusion_report(&hog).unwrap(), Some(second));
        assert_eq!(exclusion_count_rows(store), 2);

        // No engine instance record is written for it.
        assert_eq!(
            store.engine_instance_states().unwrap(),
            Vec::<EngineInstanceState>::new()
        );
    }

    #[test]
    fn exclusion_reports_of_other_agents_are_refused() {
        let t = setup_store();
        let store = &t.store;
        let mut agents = hog_agents();
        agents.push(agent("tsg", AgentKind::TimeSeriesGenerator, None, None));
        agents.push(agent("logs", AgentKind::LogCollector, None, None));
        let node = insert_node(store, "node", agents);
        let counts = report(vec![excluded(1, 14, 5)]);

        for refused in [
            instance(node.id, ENGINE),
            instance(node.id, SENSOR),
            instance(node.id, "tsg"),
            instance(node.id, "logs"),
            instance(node.id, "missing"),
            instance(node.id + 1, HOG),
        ] {
            let error = store
                .set_engine_exclusion_report(&refused, &counts)
                .unwrap_err();
            assert_eq!(
                engine_error(&error),
                &EngineDocumentError::NotSemiSupervisedAgent {
                    node_id: refused.node_id,
                    agent_key: refused.agent_key.clone(),
                },
                "{refused:?}"
            );
            assert!(error.to_string().contains(&refused.agent_key));
            assert_eq!(store.engine_exclusion_report(&refused).unwrap(), None);
        }
        assert_eq!(exclusion_count_rows(store), 0);
        assert_eq!(
            store.engine_instance_states().unwrap(),
            Vec::<EngineInstanceState>::new()
        );

        // A refused write leaves a stored report as it is.
        let hog = instance(node.id, HOG);
        store.set_engine_exclusion_report(&hog, &counts).unwrap();
        let other = report(vec![excluded(2, 15, 1)]);
        assert!(
            store
                .set_engine_exclusion_report(&instance(node.id, ENGINE), &other)
                .is_err()
        );
        assert_eq!(store.engine_exclusion_report(&hog).unwrap(), Some(counts));
        assert_eq!(exclusion_count_rows(store), 1);
    }

    /// Stores a report for both Semi-supervised Engine agents of `node`.
    fn populate_hogs(store: &Store, node: &Node) {
        for key in [HOG, OTHER_HOG] {
            store
                .set_engine_exclusion_report(
                    &instance(node.id, key),
                    &report(vec![excluded(1, 14, 5)]),
                )
                .unwrap();
        }
    }

    #[test]
    fn removing_the_agent_through_update_removes_its_exclusion_report() {
        let t = setup_store();
        let store = &t.store;
        let node = insert_node(store, "node", hog_agents());
        populate_hogs(store, &node);

        let removed = without_agent(&node, HOG);
        update(store, &node, &removed).unwrap();
        assert_eq!(
            store
                .engine_exclusion_report(&instance(node.id, HOG))
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .engine_exclusion_report(&instance(node.id, OTHER_HOG))
                .unwrap(),
            Some(report(vec![excluded(1, 14, 5)]))
        );
        assert_eq!(exclusion_count_rows(store), 1);

        // The agent is installed again under the same key with no report.
        update(store, &removed, &node).unwrap();
        assert_eq!(
            store
                .engine_exclusion_report(&instance(node.id, HOG))
                .unwrap(),
            None
        );
    }

    #[test]
    fn removing_the_agent_through_update_with_engine_documents_removes_its_exclusion_report() {
        let t = setup_store();
        let store = &t.store;
        let node = insert_node(store, "node", hog_agents());
        populate_hogs(store, &node);

        update_with_documents(store, &node, &without_agent(&node, OTHER_HOG), &[]).unwrap();
        assert_eq!(
            store
                .engine_exclusion_report(&instance(node.id, OTHER_HOG))
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .engine_exclusion_report(&instance(node.id, HOG))
                .unwrap(),
            Some(report(vec![excluded(1, 14, 5)]))
        );
        assert_eq!(exclusion_count_rows(store), 1);
    }

    #[test]
    fn removing_the_node_removes_the_exclusion_reports_of_its_agents() {
        let t = setup_store();
        let store = &t.store;
        let node = insert_node(store, "node", hog_agents());
        let kept = insert_node(store, "kept", hog_agents());
        populate_hogs(store, &node);
        populate_hogs(store, &kept);
        assert_eq!(exclusion_count_rows(store), 4);

        store.node_map().remove(node.id).unwrap();
        for key in [HOG, OTHER_HOG] {
            assert_eq!(
                store
                    .engine_exclusion_report(&instance(node.id, key))
                    .unwrap(),
                None
            );
            assert_eq!(
                store
                    .engine_exclusion_report(&instance(kept.id, key))
                    .unwrap(),
                Some(report(vec![excluded(1, 14, 5)]))
            );
        }
        assert_eq!(exclusion_count_rows(store), 2);
    }

    fn total(engine: AgentKind, entry: u64, day: i8, count: u64) -> EngineExclusionTotal {
        EngineExclusionTotal {
            engine,
            entry,
            day: jiff::civil::date(2026, 3, day),
            count,
        }
    }

    /// Gives `ENGINE` of `node` detectors 1 and 2, serving `<prefix>1` and
    /// `<prefix>2`, and a status of each with the `excluded` counts given,
    /// returning the node as updated.
    fn set_engine_excluded(
        store: &Store,
        node: &Node,
        prefix: &str,
        excluded: [Vec<ExcludedCount>; 2],
    ) -> Node {
        let engine = instance(node.id, ENGINE);
        let ids = [1, 2];
        add_detector_models(store, node.id, prefix, &ids);
        let node = apply_detectors(store, node, prefix, &ids).unwrap();
        for (id, excluded) in ids.into_iter().zip(excluded) {
            let mut status = status(1);
            status.excluded = excluded;
            store.set_detector_status(&engine, id, &status).unwrap();
        }
        node
    }

    #[test]
    fn exclusion_totals_sum_each_engine_kind_apart_per_customer() {
        let t = setup_store();
        let store = &t.store;
        let customer_2 = NodeProfile {
            customer_id: 2,
            description: String::new(),
            hostname: "c2".to_string(),
        };
        let node_a = insert_node_at(store, "a", "a", hog_agents());
        let node_b = insert_node_at(store, "b", "b", hog_agents());
        let node_c = insert_node_with_profiles(store, "c", Some(customer_2), None, hog_agents());
        // A node with only a draft profile belongs to no customer.
        let node_d = insert_node_with_profiles(store, "d", None, Some(profile("d")), hog_agents());
        // A node with no profile at all belongs to no customer either.
        let node_e = insert_node(store, "e", hog_agents());

        // Customer 1: two REconverge detectors share (10, 14), and three Hog
        // instances share (10, 14). (11, 14) is REconverge's only, and
        // (12, 15) and (13, 16) are Hog's only; (13, 16) saturates.
        let node_a = set_engine_excluded(
            store,
            &node_a,
            "a",
            [
                vec![excluded(10, 14, 4), excluded(11, 14, 1)],
                vec![excluded(10, 14, 6)],
            ],
        );
        let set = |node: &Node, key: &str, counts| {
            store
                .set_engine_exclusion_report(&instance(node.id, key), &report(counts))
                .unwrap();
        };
        set(
            &node_a,
            HOG,
            vec![excluded(10, 14, 100), excluded(12, 15, 7)],
        );
        set(
            &node_a,
            OTHER_HOG,
            vec![excluded(10, 14, 200), excluded(13, 16, 1)],
        );
        set(
            &node_b,
            HOG,
            vec![excluded(13, 16, u64::MAX), excluded(10, 14, 3)],
        );

        // Customer 2 has the same pair from both kinds.
        set_engine_excluded(
            store,
            &node_c,
            "c",
            [vec![excluded(10, 14, 77)], Vec::new()],
        );
        set(&node_c, HOG, vec![excluded(10, 14, 1000)]);

        // Nodes of no customer.
        set(&node_d, HOG, vec![excluded(10, 14, 5000)]);
        set(&node_e, OTHER_HOG, vec![excluded(10, 14, 9000)]);

        assert_eq!(
            store.engine_exclusion_totals(1).unwrap(),
            vec![
                total(AgentKind::Unsupervised, 10, 14, 10),
                total(AgentKind::Unsupervised, 11, 14, 1),
                total(AgentKind::SemiSupervised, 10, 14, 303),
                total(AgentKind::SemiSupervised, 12, 15, 7),
                total(AgentKind::SemiSupervised, 13, 16, u64::MAX),
            ]
        );
        assert_eq!(
            store.engine_exclusion_totals(2).unwrap(),
            vec![
                total(AgentKind::Unsupervised, 10, 14, 77),
                total(AgentKind::SemiSupervised, 10, 14, 1000),
            ]
        );
        assert_eq!(
            store.engine_exclusion_totals(3).unwrap(),
            Vec::<EngineExclusionTotal>::new()
        );

        // A removed agent's counts leave the totals with it.
        update(store, &node_a, &without_agent(&node_a, OTHER_HOG)).unwrap();
        assert_eq!(
            store.engine_exclusion_totals(1).unwrap(),
            vec![
                total(AgentKind::Unsupervised, 10, 14, 10),
                total(AgentKind::Unsupervised, 11, 14, 1),
                total(AgentKind::SemiSupervised, 10, 14, 103),
                total(AgentKind::SemiSupervised, 12, 15, 7),
                total(AgentKind::SemiSupervised, 13, 16, u64::MAX),
            ]
        );
    }

    #[test]
    fn exclusion_totals_count_an_agent_listed_twice_once() {
        let t = setup_store();
        let store = &t.store;
        let node = insert_node_at(store, "a", "a", hog_agents());
        let node = set_engine_excluded(
            store,
            &node,
            "a",
            [vec![excluded(10, 14, 4)], vec![excluded(10, 14, 6)]],
        );
        store
            .set_engine_exclusion_report(
                &instance(node.id, HOG),
                &report(vec![excluded(10, 14, 5)]),
            )
            .unwrap();
        let expected = vec![
            total(AgentKind::Unsupervised, 10, 14, 10),
            total(AgentKind::SemiSupervised, 10, 14, 5),
        ];
        assert_eq!(store.engine_exclusion_totals(1).unwrap(), expected);

        // The node lists `ENGINE` and `HOG` a second time; both listings
        // read the same stored rows.
        let mut doubled = node.clone();
        let again: Vec<Agent> = node
            .agents
            .iter()
            .filter(|a| a.key == ENGINE || a.key == HOG)
            .cloned()
            .collect();
        doubled.agents.extend(again);
        let doubled = update(store, &node, &doubled).unwrap();
        assert_eq!(
            doubled
                .agents
                .iter()
                .filter(|a| a.key == ENGINE || a.key == HOG)
                .count(),
            4
        );
        assert_eq!(store.engine_exclusion_totals(1).unwrap(), expected);
    }
}
