//! The configuration revisions of engine instances, read and maintained
//! through the [`Store`].
//!
//! Every writer of an agent row records the revisions itself, in the same
//! transaction as the row; what is here reads them, removes a customer's
//! history, and completes the stored applied documents again.

use std::fmt;

use anyhow::{Context, Result};
use tracing::warn;

use crate::{
    Agent, AgentConfig, AgentKind, CompletionMode, ConfigRevisionRecord, ModelInstance, Store,
    Table, complete_engine_document,
    tables::{CustomerOf, is_engine},
};

/// An applied engine document that [`Store::recomplete_applied_documents`]
/// or [`Store::complete_run`] changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecompletedDocument {
    /// The engine instance whose `config` changed.
    pub instance: ModelInstance,
    /// The revision the change recorded.
    pub revision: u64,
    /// The completed document now stored.
    pub document: String,
}

/// The failure that ended [`Store::recomplete_applied_documents`], with the
/// changes it had committed before the failure.
///
/// The failure is any error other than a failure of document completion,
/// which the call logs and skips: reading the agents, a stored row or a model
/// record, converting a completed document into an [`AgentConfig`], updating
/// the agent, or committing other than on a write conflict.
#[derive(Debug)]
pub struct RecompletionError {
    /// Exactly the changes the call committed before it failed, in the order
    /// it committed them; they stay in place.
    pub committed: Vec<RecompletedDocument>,
    /// The error that ended the call, one of the failures listed above; an
    /// error from the agent update is passed on whatever it is, including
    /// `old value mismatch` after a successful completion.
    pub error: anyhow::Error,
}

impl fmt::Display for RecompletionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot complete the applied engine documents again after {} committed changes: {}",
            self.committed.len(),
            self.error
        )
    }
}

impl std::error::Error for RecompletionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

/// A hook the tests run before each commit of
/// [`Store::recomplete_applied_documents`]; an error it returns ends the call
/// with a [`RecompletionError`], as any other error after completion does.
#[cfg(test)]
pub(crate) type RecompletionHook =
    std::sync::Arc<dyn Fn(&ModelInstance) -> Result<()> + Send + Sync>;

impl Store {
    /// Returns the current configuration revision of `instance`: the number
    /// recorded by the write that stored its current `config`.
    ///
    /// Returns `None` if the agent is absent, is not an engine kind, or has
    /// no `config`, and for a `config` stored before revisions were recorded
    /// until the first write that records one. Removing history rows does not
    /// change it.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn config_revision(&self, instance: &ModelInstance) -> Result<Option<u64>> {
        self.states
            .config_revisions()
            .current(self.states.agents().raw().cf, instance)
    }

    /// Returns the history row of revision `revision` of `instance`, or
    /// `None` if that revision was never issued or its row was removed.
    ///
    /// The row is returned whatever the agent's current kind, and also if the
    /// agent or its node no longer exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn config_revision_record(
        &self,
        instance: &ModelInstance,
        revision: u64,
    ) -> Result<Option<ConfigRevisionRecord>> {
        self.states.config_revisions().record(instance, revision)
    }

    /// Removes, in one transaction, every configuration history row whose
    /// customer id is `customer_id`, whether or not its node still exists,
    /// and returns how many it removed.
    ///
    /// The revision numbers and current revisions stay as they are: a
    /// removed row's number is never issued again.
    ///
    /// # Errors
    ///
    /// Returns an error, and removes nothing, if the database operation
    /// fails.
    pub fn remove_customer_config_history(&self, customer_id: u32) -> Result<usize> {
        self.states
            .config_revisions()
            .remove_customer_history(customer_id)
    }

    /// Completes the stored applied document, `config`, of every engine
    /// instance that has one with [`complete_engine_document`] in
    /// [`CompletionMode::Recomplete`], and returns an entry for each instance
    /// it changed.
    ///
    /// A Hog document is completed as it was read. An Unsupervised Engine
    /// document is completed within the transaction that reads its row again
    /// and stores it, with the clustering model type of each model its
    /// detectors name read within that transaction: sections the type no
    /// longer allows are removed, and allowed sections are filled.
    ///
    /// A document that fails completion is logged as a warning, naming the
    /// node id, agent key and error, and left unchanged with its history; the
    /// call goes on with the next instance. A document whose completion
    /// equals its stored bytes is not written. Any other is stored completed
    /// with a new revision, in a transaction of its own, so a later failure
    /// leaves earlier changes in place. A `config` that another write changed
    /// after this call read it is never overwritten. A commit that conflicts
    /// with another write is retried. A draft is never changed.
    ///
    /// # Errors
    ///
    /// Returns a [`RecompletionError`], ending the call, on any error other
    /// than a failure of completion:
    ///
    /// * the agents, the stored row of an instance being changed, or the
    ///   record of a model an Unsupervised Engine document names, cannot be
    ///   read;
    /// * the completed document cannot be converted into an [`AgentConfig`];
    /// * the agent update fails, whatever its error. This includes `old value
    ///   mismatch` after a successful completion, for a stored row whose
    ///   bytes differ from its re-encoding, such as a Hog row with an unknown
    ///   lifecycle index;
    /// * the commit fails other than on a write conflict.
    ///
    /// Its `committed` lists exactly the changes this call committed before
    /// the failure.
    pub fn recomplete_applied_documents(
        &self,
    ) -> std::result::Result<Vec<RecompletedDocument>, RecompletionError> {
        let agents = self.states.agents();
        let mut committed = Vec::new();
        let candidates = match engine_agents_with_config(&agents) {
            Ok(candidates) => candidates,
            Err(error) => return Err(RecompletionError { committed, error }),
        };
        for read in candidates {
            let Some(config) = read.config.as_ref() else {
                continue;
            };
            let completed = if read.kind == AgentKind::Unsupervised {
                None
            } else {
                match complete_engine_document(
                    read.kind,
                    config.as_ref(),
                    &|_| None,
                    &|_| None,
                    CompletionMode::Recomplete,
                ) {
                    Ok(completed) if completed == config.as_ref() => continue,
                    Ok(completed) => Some(completed),
                    Err(error) => {
                        warn_left_unchanged(&read, &error);
                        continue;
                    }
                }
            };
            match self.store_recompleted(&agents, &read, completed.as_deref()) {
                Ok(Some(entry)) => committed.push(entry),
                Ok(None) => {}
                Err(error) => return Err(RecompletionError { committed, error }),
            }
        }
        Ok(committed)
    }

    /// Stores the completion of the `config` of the agent `read` was read as,
    /// with a new revision, unless the stored row no longer has the kind and
    /// `config` of `read`; returns the change, or `None` if it made none.
    ///
    /// The completion is `completed`, or, when it is `None`, made within the
    /// transaction by [`Store::recomplete_in_transaction`].
    fn store_recompleted(
        &self,
        agents: &Table<'_, Agent>,
        read: &Agent,
        completed: Option<&str>,
    ) -> Result<Option<RecompletedDocument>> {
        let key = read.unique_key_bytes();
        loop {
            let txn = self.states.db().transaction();
            let Some(stored) = agents.get_for_update(&txn, &key)? else {
                return Ok(None);
            };
            if stored.kind != read.kind || stored.config != read.config {
                return Ok(None);
            }
            let staged = match completed {
                Some(completed) => stage_recompleted(&txn, agents, &stored, completed.to_owned())?,
                None => self.recomplete_in_transaction(&txn, agents, &stored)?,
            };
            let Some(entry) = staged else {
                return Ok(None);
            };
            #[cfg(test)]
            self.run_recompletion_hook(&entry.instance)?;
            match txn.commit() {
                Ok(()) => return Ok(Some(entry)),
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).with_context(|| {
                            format!(
                                "failed to store the completed engine document of agent {} on \
                                 node {}",
                                entry.instance.agent_key, entry.instance.node_id
                            )
                        });
                    }
                }
            }
        }
    }

    /// Completes the applied document of `stored`, an agent row read for
    /// update within `txn`, again in [`CompletionMode::Recomplete`] within
    /// `txn`, and stages it with a new revision when the completion differs
    /// from the stored bytes; returns the change, or `None` if it staged none.
    ///
    /// A completion failure is logged as a warning, naming the node id, agent
    /// key and error, and stages nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if a model record cannot be read, or if staging the
    /// change fails.
    pub(crate) fn recomplete_in_transaction(
        &self,
        txn: &rocksdb::Transaction<'_, rocksdb::OptimisticTransactionDB>,
        agents: &Table<'_, Agent>,
        stored: &Agent,
    ) -> Result<Option<RecompletedDocument>> {
        let Some(config) = stored.config.as_ref() else {
            return Ok(None);
        };
        match self.states.config_revisions().complete_in_transaction(
            txn,
            stored.kind,
            config.as_ref(),
            CompletionMode::Recomplete,
        )? {
            Ok(completed) => stage_recompleted(txn, agents, stored, completed),
            Err(error) => {
                warn_left_unchanged(stored, &error);
                Ok(None)
            }
        }
    }
}

/// Stages, within `txn`, `completed` as the `config` of `stored`, an
/// agent row read for update within `txn`, with a new revision, unless it
/// equals the stored bytes; returns the change, or `None` if it staged
/// none.
fn stage_recompleted(
    txn: &rocksdb::Transaction<'_, rocksdb::OptimisticTransactionDB>,
    agents: &Table<'_, Agent>,
    stored: &Agent,
    completed: String,
) -> Result<Option<RecompletedDocument>> {
    if stored
        .config
        .as_ref()
        .is_some_and(|config| config.as_ref() == completed)
    {
        return Ok(None);
    }
    let config = AgentConfig::try_from(completed)
        .context("the completed engine document is not valid TOML")?;
    let mut new = stored.clone();
    new.config = Some(config.clone());
    let written = agents.update_in_transaction(txn, stored, &new, CustomerOf::Node)?;
    Ok(written.revision.map(|revision| RecompletedDocument {
        instance: ModelInstance {
            node_id: stored.node_id,
            agent_key: stored.key.clone(),
        },
        revision,
        document: config.as_ref().to_owned(),
    }))
}

/// Logs that the applied document of `agent` failed completion and is left
/// unchanged.
fn warn_left_unchanged(agent: &Agent, error: &crate::DetectionModelsSectionError) {
    warn!(
        node_id = agent.node_id,
        agent_key = %agent.key,
        %error,
        "cannot complete the applied engine document; left unchanged"
    );
}

/// Returns every stored agent of an engine kind that has a `config`.
fn engine_agents_with_config(agents: &Table<'_, Agent>) -> Result<Vec<Agent>> {
    use crate::Iterable;

    let mut found = Vec::new();
    for agent in agents.iter(rocksdb::Direction::Forward, None) {
        let agent = agent.context("cannot read agents")?;
        if is_engine(agent.kind) && agent.config.is_some() {
            found.push(agent);
        }
    }
    Ok(found)
}

#[cfg(test)]
impl Store {
    pub(crate) fn set_recompletion_hook(&self, hook: Option<RecompletionHook>) {
        *self
            .recompletion_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    fn run_recompletion_hook(&self, instance: &ModelInstance) -> Result<()> {
        let hook = self
            .recompletion_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        hook.map_or(Ok(()), |hook| hook(instance))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use jiff::Timestamp;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        AgentKind, AgentStatus, ClusteringModelTypeRef, DetectionModelsSectionError,
        EngineDocumentError, EngineDocumentRefs, EngineDocumentWrite, Iterable, ModelOwner, Node,
        NodeProfile, NodeTable, TrainedWith, UniqueKey,
        collections::{Indexed, IndexedMap},
        tables::{
            ConfigRevisions, HookPoint, InnerNode, NODES, Value as _, fail_model_reads, set_hook,
        },
        test::{DbGuard, acquire_db_permit, capture_warnings},
    };

    const CUSTOMER: u32 = 7;
    const OTHER_CUSTOMER: u32 = 8;
    const HOG: &str = "001.hog";
    const OTHER_HOG: &str = "002.hog";
    const UNSUPERVISED: &str = "001.reconverge";
    const SENSOR: &str = "001.piglet";
    /// A Hog document with no `[detection_models]`, which completion extends.
    const HOG_A: &str = "data_store_port = 1\n";
    const HOG_B: &str = "data_store_port = 2\n";
    /// A Hog document that is valid TOML and fails completion.
    const FAILING_HOG: &str = "[detection_models.no_such_model]\nenabled = true\n";
    const UNSUPERVISED_A: &str = "threshold = 1\n";
    const UNSUPERVISED_B: &str = "threshold = 2\n";
    const SENSOR_DOC: &str = "data_store_port = 3\n";

    struct Fixture {
        store: Store,
        _dirs: (TempDir, TempDir),
        _permit: DbGuard<'static>,
    }

    fn setup() -> Fixture {
        let permit = acquire_db_permit();
        let db = tempfile::tempdir().unwrap();
        let backup = tempfile::tempdir().unwrap();
        let store = Store::new(db.path(), backup.path(), None).unwrap();
        Fixture {
            store,
            _dirs: (db, backup),
            _permit: permit,
        }
    }

    fn completed(document: &str) -> String {
        complete_engine_document(
            AgentKind::SemiSupervised,
            document,
            &|_| None,
            &|_| None,
            CompletionMode::Apply,
        )
        .unwrap()
    }

    /// An Unsupervised Engine model of the `http_url` type.
    const WEB: &str = "web";
    /// A custom Unsupervised Engine model.
    const CUSTOM_MODEL: &str = "custom";
    const FAR_OUTLIER: &str = "[detectors.detection_models.far_outlier]\nenabled = true\n";

    fn http_url() -> ClusteringModelTypeRef {
        ClusteringModelTypeRef::Catalog {
            id: "http_url".to_string(),
            version: 1,
        }
    }

    /// Stores the model `name` of the clustering model type `model_type`
    /// with [`Store::replace_model`], which changes no applied document.
    fn put_model(store: &Store, name: &str, model_type: ClusteringModelTypeRef) {
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
            clustering_model_type: model_type,
            training_read: crate::TrainingRead::default(),
            detection_model_states: Vec::new(),
        };
        store
            .replace_model(
                body,
                ModelOwner {
                    customer_id: CUSTOMER,
                    instance: instance(1, UNSUPERVISED),
                },
                Timestamp::UNIX_EPOCH,
                TrainedWith {
                    run_id: 1,
                    definition: "eps = 5.0".to_string(),
                    sources: Vec::new(),
                },
            )
            .unwrap();
    }

    /// An Unsupervised Engine document with one detector running `model`.
    fn detector(model: &str) -> String {
        format!("[[detectors]]\nmodel = \"{model}\"\n")
    }

    /// [`detector`] completed for a model of the `http_url` type.
    fn complete_web(model: &str) -> String {
        format!(
            "{}\n[detectors.detection_models.label_db_match]\nenabled = true\nevent_range = \
             100\nmin_events_ratio = 10\ncolumns = []\n\n{FAR_OUTLIER}",
            detector(model)
        )
    }

    fn unsupervised(node_id: u32, key: &str, config: Option<&str>) -> Agent {
        agent(node_id, key, AgentKind::Unsupervised, config)
    }

    fn agent(node_id: u32, key: &str, kind: AgentKind, config: Option<&str>) -> Agent {
        Agent::new(
            node_id,
            key.to_string(),
            kind,
            AgentStatus::Enabled,
            config.map(ToString::to_string),
            None,
        )
        .unwrap()
    }

    fn hog(node_id: u32, key: &str, config: Option<&str>) -> Agent {
        agent(node_id, key, AgentKind::SemiSupervised, config)
    }

    fn document(text: &str) -> AgentConfig {
        text.to_string().try_into().unwrap()
    }

    fn profile(customer_id: u32, hostname: &str) -> NodeProfile {
        NodeProfile {
            customer_id,
            description: String::new(),
            hostname: hostname.to_string(),
        }
    }

    fn new_node(name: &str, customer_id: u32, agents: Vec<Agent>) -> Node {
        Node {
            id: 0,
            name: name.to_string(),
            name_draft: None,
            profile: Some(profile(customer_id, name)),
            profile_draft: None,
            agents,
            external_services: Vec::new(),
            creation_time: Timestamp::UNIX_EPOCH,
        }
    }

    /// Puts a node named `name` and returns it as stored.
    fn put_node(store: &Store, name: &str, customer_id: u32, agents: Vec<Agent>) -> Node {
        let id = store
            .node_map()
            .put(&new_node(name, customer_id, agents))
            .unwrap();
        stored(store, id)
    }

    fn stored(store: &Store, id: u32) -> Node {
        store.node_map().get_by_id(id).unwrap().unwrap().0
    }

    fn stored_agent(store: &Store, node_id: u32, key: &str) -> Option<Agent> {
        store.agents_map().get(node_id, key).unwrap()
    }

    fn update_node(store: &Store, old: &Node, new: &Node) -> Result<Node> {
        store
            .node_map()
            .update(old.id, &old.clone().into(), &new.clone().into())
    }

    fn update_node_with_documents(
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

    /// Returns `node` with the agent under `key` replaced by `agent`, or
    /// `agent` added if there is none.
    fn with_agent(node: &Node, agent: &Agent) -> Node {
        let mut node = node.clone();
        if let Some(slot) = node.agents.iter_mut().find(|a| a.key == agent.key) {
            *slot = agent.clone();
        } else {
            node.agents.push(agent.clone());
        }
        node
    }

    fn without_agent(node: &Node, key: &str) -> Node {
        let mut node = node.clone();
        node.agents.retain(|a| a.key != key);
        node
    }

    fn instance(node_id: u32, agent_key: &str) -> ModelInstance {
        ModelInstance {
            node_id,
            agent_key: agent_key.to_string(),
        }
    }

    fn revision(store: &Store, node_id: u32, key: &str) -> Option<u64> {
        store.config_revision(&instance(node_id, key)).unwrap()
    }

    fn record(store: &Store, node_id: u32, key: &str, n: u64) -> Option<ConfigRevisionRecord> {
        store
            .config_revision_record(&instance(node_id, key), n)
            .unwrap()
    }

    fn recorded_document(store: &Store, node_id: u32, key: &str, n: u64) -> Option<String> {
        record(store, node_id, key, n).map(|r| r.document)
    }

    fn config_of(agent: &Agent) -> Option<&str> {
        agent.config.as_ref().map(AsRef::as_ref)
    }

    /// Stores `agent` as is, bypassing every writer, as a row written before
    /// revisions were recorded.
    fn put_raw(store: &Store, agent: &Agent) {
        store
            .agents_map()
            .raw()
            .put(&agent.unique_key(), &agent.value())
            .unwrap();
    }

    fn assert_completion_error(error: &anyhow::Error) {
        assert!(
            error
                .downcast_ref::<DetectionModelsSectionError>()
                .is_some(),
            "{error:#}"
        );
    }

    /// The writers that can replace a stored agent: each takes the stored row
    /// and its replacement under the same key.
    type Replace = fn(&Store, &Agent, &Agent) -> Result<()>;

    fn replacing_paths() -> Vec<(&'static str, Replace)> {
        vec![
            ("NodeTable::update", |store, old, new| {
                let node = stored(store, old.node_id);
                update_node(store, &node, &with_agent(&node, new)).map(drop)
            }),
            (
                "NodeTable::update_with_engine_documents",
                |store, old, new| {
                    let node = stored(store, old.node_id);
                    update_node_with_documents(store, &node, &with_agent(&node, new), &[]).map(drop)
                },
            ),
            ("agents put", |store, _, new| store.agents_map().put(new)),
            ("agents put_with_transaction", |store, _, new| {
                let agents = store.agents_map();
                let txn = agents.transaction();
                agents.put_with_transaction(new, &txn)?;
                Ok(txn.commit()?)
            }),
            ("agents update", |store, old, new| {
                store.agents_map().update(old, new)
            }),
            ("agents update_with_transaction", |store, old, new| {
                let agents = store.agents_map();
                let txn = agents.transaction();
                agents.update_with_transaction(old, new, &txn)?;
                Ok(txn.commit()?)
            }),
        ]
    }

    /// The writers that can create an agent on node `node`, which holds no
    /// agent under its key.
    type Create = fn(&Store, &Node, &Agent) -> Result<()>;

    fn creating_paths() -> Vec<(&'static str, Create)> {
        vec![
            ("NodeTable::update", |store, node, new| {
                update_node(store, node, &with_agent(node, new)).map(drop)
            }),
            (
                "NodeTable::update_with_engine_documents",
                |store, node, new| {
                    update_node_with_documents(store, node, &with_agent(node, new), &[]).map(drop)
                },
            ),
            ("agents put", |store, _, new| store.agents_map().put(new)),
            ("agents put_with_transaction", |store, _, new| {
                let agents = store.agents_map();
                let txn = agents.transaction();
                agents.put_with_transaction(new, &txn)?;
                Ok(txn.commit()?)
            }),
            ("agents insert", |store, _, new| {
                store.agents_map().insert(new)
            }),
            ("agents insert_with_transaction", |store, _, new| {
                let agents = store.agents_map();
                let txn = agents.transaction();
                agents.insert_with_transaction(new, &txn)?;
                Ok(txn.commit()?)
            }),
            ("agents update to a new key", |store, node, new| {
                // A row with no engine document is moved onto the new key.
                let mut placeholder = new.clone();
                placeholder.key = format!("{}.placeholder", new.key);
                placeholder.kind = AgentKind::Sensor;
                placeholder.config = None;
                placeholder.node_id = node.id;
                let agents = store.agents_map();
                agents.put(&placeholder)?;
                agents.update(&placeholder, new)
            }),
        ]
    }

    #[test]
    fn first_apply_records_revision_one_and_a_change_records_two() {
        let f = setup();
        let store = &f.store;
        let before = Timestamp::now();
        let node = put_node(store, "n", CUSTOMER, vec![hog(0, HOG, Some(HOG_A))]);
        let after = Timestamp::now();

        assert_eq!(config_of(&node.agents[0]), Some(completed(HOG_A).as_str()));
        assert_eq!(revision(store, node.id, HOG), Some(1));
        let first = record(store, node.id, HOG, 1).unwrap();
        assert_eq!(first.document, completed(HOG_A));
        assert_eq!(first.customer_id, Some(CUSTOMER));
        assert!(before <= first.applied_at && first.applied_at <= after);

        let mut changed = node.agents[0].clone();
        changed.config = Some(document(HOG_B));
        let returned = update_node(store, &node, &with_agent(&node, &changed)).unwrap();
        assert_eq!(returned, stored(store, node.id));
        assert_eq!(
            config_of(&returned.agents[0]),
            Some(completed(HOG_B).as_str())
        );
        assert_eq!(revision(store, node.id, HOG), Some(2));
        assert_eq!(
            recorded_document(store, node.id, HOG, 2),
            Some(completed(HOG_B))
        );
        assert_eq!(record(store, node.id, HOG, 1).unwrap(), first);
        assert_eq!(record(store, node.id, HOG, 3), None);
    }

    #[test]
    fn every_creating_path_completes_and_records() {
        for (name, create) in creating_paths() {
            let f = setup();
            let store = &f.store;
            let node = put_node(store, "n", CUSTOMER, Vec::new());
            create(store, &node, &hog(node.id, HOG, Some(HOG_A))).unwrap();

            let agent = stored_agent(store, node.id, HOG).unwrap();
            assert_eq!(config_of(&agent), Some(completed(HOG_A).as_str()), "{name}");
            assert_eq!(revision(store, node.id, HOG), Some(1), "{name}");
            let first = record(store, node.id, HOG, 1).unwrap();
            assert_eq!(first.document, completed(HOG_A), "{name}");
            assert_eq!(first.customer_id, Some(CUSTOMER), "{name}");
        }
    }

    #[test]
    fn every_creating_path_refuses_a_failing_document() {
        for (name, create) in creating_paths() {
            let f = setup();
            let store = &f.store;
            let node = put_node(store, "n", CUSTOMER, Vec::new());
            let error = create(store, &node, &hog(node.id, HOG, Some(FAILING_HOG))).unwrap_err();
            assert_completion_error(&error);
            assert_eq!(stored_agent(store, node.id, HOG), None, "{name}");
            assert_eq!(stored(store, node.id), node, "{name}");
            assert_eq!(revision(store, node.id, HOG), None, "{name}");
            assert_eq!(record(store, node.id, HOG, 1), None, "{name}");
        }

        let f = setup();
        let store = &f.store;
        let error = store
            .node_map()
            .put(&new_node(
                "n",
                CUSTOMER,
                vec![hog(0, HOG, Some(FAILING_HOG))],
            ))
            .unwrap_err();
        assert_completion_error(&error);
        assert_eq!(store.node_map().count().unwrap(), 0);
        assert_eq!(
            store
                .agents_map()
                .iter(rocksdb::Direction::Forward, None)
                .count(),
            0
        );
    }

    /// A completion failure is returned, not retried as a write conflict,
    /// whatever text its agent key holds.
    #[test]
    fn a_completion_failure_is_refused_whatever_the_agent_key_says() {
        for key in ["001.already exists.hog", "001.Resource busy:.hog"] {
            let f = setup();
            let store = &f.store;
            let error = store
                .node_map()
                .put(&new_node(
                    "n",
                    CUSTOMER,
                    vec![hog(0, key, Some(FAILING_HOG))],
                ))
                .unwrap_err();
            assert_completion_error(&error);
            assert_eq!(store.node_map().count().unwrap(), 0, "{key}");

            let node = put_node(store, "m", CUSTOMER, Vec::new());
            for (name, create) in &creating_paths()[..2] {
                let error =
                    create(store, &node, &hog(node.id, key, Some(FAILING_HOG))).unwrap_err();
                assert_completion_error(&error);
                assert_eq!(stored(store, node.id), node, "{name} {key}");
            }

            let node = put_node(store, "o", CUSTOMER, vec![hog(0, key, Some(HOG_A))]);
            let old = stored_agent(store, node.id, key).unwrap();
            let mut failing = old.clone();
            failing.config = Some(document(FAILING_HOG));
            for (name, replace) in &replacing_paths()[..2] {
                let error = replace(store, &old, &failing).unwrap_err();
                assert_completion_error(&error);
                assert_eq!(stored(store, node.id), node, "{name} {key}");
                assert_eq!(revision(store, node.id, key), Some(1), "{name} {key}");
            }
        }
    }

    /// Every scenario the replacing paths support, each on a fresh store.
    #[test]
    fn every_replacing_path_completes_changes_and_keeps_the_rest() {
        for (name, replace) in replacing_paths() {
            // A changed document records the next revision.
            let f = setup();
            let store = &f.store;
            let node = put_node(store, "n", CUSTOMER, vec![hog(0, HOG, Some(HOG_A))]);
            let old = node.agents[0].clone();
            let mut new = old.clone();
            new.config = Some(document(HOG_B));
            replace(store, &old, &new).unwrap();
            let agent = stored_agent(store, node.id, HOG).unwrap();
            assert_eq!(config_of(&agent), Some(completed(HOG_B).as_str()), "{name}");
            assert_eq!(revision(store, node.id, HOG), Some(2), "{name}");
            assert_eq!(
                recorded_document(store, node.id, HOG, 2),
                Some(completed(HOG_B)),
                "{name}"
            );

            // The same bytes, with another field changed, record nothing.
            let old = agent;
            let mut new = old.clone();
            new.status = AgentStatus::Disabled;
            replace(store, &old, &new).unwrap();
            assert_eq!(
                stored_agent(store, node.id, HOG),
                Some(new.clone()),
                "{name}"
            );
            assert_eq!(revision(store, node.id, HOG), Some(2), "{name}");
            assert_eq!(record(store, node.id, HOG, 3), None, "{name}");

            // A document that completes to the stored one records nothing and
            // keeps the stored bytes.
            let old = new;
            let mut new = old.clone();
            new.config = Some(document(HOG_B));
            replace(store, &old, &new).unwrap();
            assert_eq!(
                stored_agent(store, node.id, HOG),
                Some(old.clone()),
                "{name}"
            );
            assert_eq!(revision(store, node.id, HOG), Some(2), "{name}");
            assert_eq!(record(store, node.id, HOG, 3), None, "{name}");

            // A failing document is refused and changes nothing.
            let mut new = old.clone();
            new.config = Some(document(FAILING_HOG));
            let error = replace(store, &old, &new).unwrap_err();
            assert_completion_error(&error);
            assert_eq!(
                stored_agent(store, node.id, HOG),
                Some(old.clone()),
                "{name}"
            );
            assert_eq!(revision(store, node.id, HOG), Some(2), "{name}");
            assert_eq!(record(store, node.id, HOG, 3), None, "{name}");

            // Status-only and draft-only writes over a stored `config` that
            // fails completion succeed and leave it and its revision as they
            // are.
            let f = setup();
            let store = &f.store;
            let node = put_node(store, "n", CUSTOMER, vec![hog(0, HOG, None)]);
            let failing = hog(node.id, HOG, Some(FAILING_HOG));
            put_raw(store, &failing);
            let mut status_only = failing.clone();
            status_only.status = AgentStatus::Disabled;
            replace(store, &failing, &status_only).unwrap();
            assert_eq!(
                stored_agent(store, node.id, HOG),
                Some(status_only.clone()),
                "{name}"
            );
            let mut draft_only = status_only.clone();
            draft_only.draft = Some(document(HOG_B));
            replace(store, &status_only, &draft_only).unwrap();
            assert_eq!(
                stored_agent(store, node.id, HOG),
                Some(draft_only),
                "{name}"
            );
            assert_eq!(revision(store, node.id, HOG), None, "{name}");
            assert_eq!(record(store, node.id, HOG, 1), None, "{name}");
        }
    }

    #[test]
    fn a_draft_is_stored_without_completion_and_records_nothing() {
        let f = setup();
        let store = &f.store;
        let node = put_node(store, "n", CUSTOMER, vec![hog(0, HOG, Some(HOG_A))]);
        for draft in [HOG_B, FAILING_HOG] {
            let node = stored(store, node.id);
            let mut drafted = node.agents[0].clone();
            drafted.draft = Some(document(draft));
            let returned = update_node(store, &node, &with_agent(&node, &drafted)).unwrap();
            assert_eq!(returned.agents[0].draft.as_ref().unwrap().as_ref(), draft);
            assert_eq!(returned, stored(store, node.id));
        }
        let created = hog(node.id, OTHER_HOG, None);
        let mut created = created;
        created.draft = Some(document(HOG_A));
        store.agents_map().put(&created).unwrap();
        assert_eq!(stored_agent(store, node.id, OTHER_HOG), Some(created));
        assert_eq!(revision(store, node.id, HOG), Some(1));
        assert_eq!(record(store, node.id, HOG, 2), None);
        assert_eq!(revision(store, node.id, OTHER_HOG), None);
        assert_eq!(record(store, node.id, OTHER_HOG, 1), None);
    }

    #[test]
    fn refused_writes_in_a_committed_transaction_change_nothing() {
        let f = setup();
        let store = &f.store;
        let node = put_node(
            store,
            "n",
            CUSTOMER,
            vec![hog(0, HOG, Some(HOG_A)), hog(0, OTHER_HOG, Some(HOG_B))],
        );
        let first = stored_agent(store, node.id, HOG).unwrap();
        let second = stored_agent(store, node.id, OTHER_HOG).unwrap();
        let agents = store.agents_map();

        // An update onto an occupied key, then a completion failure and an
        // insert onto an occupied key, each caught by a caller that commits
        // other work in the same transaction.
        let txn = agents.transaction();
        let mut moved = first.clone();
        moved.key = OTHER_HOG.to_string();
        assert!(
            agents
                .update_with_transaction(&first, &moved, &txn)
                .is_err()
        );
        let mut failing = first.clone();
        failing.config = Some(document(FAILING_HOG));
        assert_completion_error(&agents.put_with_transaction(&failing, &txn).unwrap_err());
        assert!(agents.insert_with_transaction(&failing, &txn).is_err());
        let mut moved_failing = failing.clone();
        moved_failing.key = "003.hog".to_string();
        assert_completion_error(
            &agents
                .update_with_transaction(&first, &moved_failing, &txn)
                .unwrap_err(),
        );
        let sensor = agent(node.id, SENSOR, AgentKind::Sensor, Some(SENSOR_DOC));
        agents.put_with_transaction(&sensor, &txn).unwrap();
        txn.commit().unwrap();

        assert_eq!(stored_agent(store, node.id, HOG), Some(first.clone()));
        assert_eq!(stored_agent(store, node.id, OTHER_HOG), Some(second));
        assert_eq!(stored_agent(store, node.id, "003.hog"), None);
        assert_eq!(stored_agent(store, node.id, SENSOR), Some(sensor));
        assert_eq!(revision(store, node.id, HOG), Some(1));
        assert_eq!(revision(store, node.id, OTHER_HOG), Some(1));
        assert_eq!(revision(store, node.id, "003.hog"), None);
        assert_eq!(record(store, node.id, HOG, 2), None);
        assert_eq!(record(store, node.id, OTHER_HOG, 2), None);

        // The next issued numbers are as they were.
        let mut changed = first;
        changed.config = Some(document(HOG_B));
        agents.put(&changed).unwrap();
        assert_eq!(revision(store, node.id, HOG), Some(2));
    }

    #[test]
    fn a_rolled_back_transaction_leaves_the_revision_as_it_was() {
        let f = setup();
        let store = &f.store;
        let node = put_node(store, "n", CUSTOMER, vec![hog(0, HOG, Some(HOG_A))]);
        let agents = store.agents_map();
        let mut changed = node.agents[0].clone();
        changed.config = Some(document(HOG_B));

        let txn = agents.transaction();
        agents.put_with_transaction(&changed, &txn).unwrap();
        txn.rollback().unwrap();
        drop(txn);

        assert_eq!(
            stored_agent(store, node.id, HOG),
            Some(node.agents[0].clone())
        );
        assert_eq!(revision(store, node.id, HOG), Some(1));
        assert_eq!(record(store, node.id, HOG, 2), None);
        agents.put(&changed).unwrap();
        assert_eq!(revision(store, node.id, HOG), Some(2));
        assert_eq!(record(store, node.id, HOG, 3), None);
    }

    #[test]
    fn returned_nodes_equal_the_committed_rows() {
        let f = setup();
        let store = &f.store;
        let node = put_node(
            store,
            "n",
            CUSTOMER,
            vec![
                hog(0, HOG, Some(HOG_A)),
                hog(0, OTHER_HOG, Some(HOG_A)),
                hog(0, "003.hog", None),
                agent(0, SENSOR, AgentKind::Sensor, Some(SENSOR_DOC)),
            ],
        );
        // A `config` stored incomplete, before revisions were recorded.
        put_raw(store, &hog(node.id, "003.hog", Some(HOG_B)));
        let node = stored(store, node.id);

        let mut changed = node.agents[0].clone();
        changed.config = Some(document(HOG_B));
        let mut cleared = node.agents[1].clone();
        cleared.config = None;
        let mut carried = node.agents[2].clone();
        carried.status = AgentStatus::Disabled;
        let added = hog(node.id, "004.hog", Some(HOG_A));
        let new = [&changed, &cleared, &carried, &added]
            .into_iter()
            .fold(node.clone(), |node, agent| with_agent(&node, agent));

        let returned = update_node(store, &node, &new).unwrap();
        assert_eq!(returned, stored(store, node.id));
        let by_key = |key: &str| returned.agents.iter().find(|a| a.key == key).unwrap();
        assert_eq!(config_of(by_key(HOG)), Some(completed(HOG_B).as_str()));
        assert_eq!(config_of(by_key(OTHER_HOG)), None);
        assert_eq!(config_of(by_key("003.hog")), Some(HOG_B));
        assert_eq!(
            config_of(by_key("004.hog")),
            Some(completed(HOG_A).as_str())
        );
        assert_eq!(config_of(by_key(SENSOR)), Some(SENSOR_DOC));
        assert_eq!(revision(store, node.id, OTHER_HOG), None);
        assert_eq!(revision(store, node.id, "003.hog"), None);

        let node = stored(store, node.id);
        let mut changed = node.agents[0].clone();
        changed.config = Some(document(HOG_A));
        let returned =
            update_node_with_documents(store, &node, &with_agent(&node, &changed), &[]).unwrap();
        assert_eq!(returned, stored(store, node.id));
        assert_eq!(
            config_of(returned.agents.iter().find(|a| a.key == HOG).unwrap()),
            Some(completed(HOG_A).as_str())
        );
    }

    #[test]
    fn non_engine_agents_get_no_completion_and_no_history() {
        let f = setup();
        let store = &f.store;
        let node = put_node(
            store,
            "n",
            CUSTOMER,
            vec![agent(0, SENSOR, AgentKind::Sensor, Some(FAILING_HOG))],
        );
        let collector = agent(
            node.id,
            "001.reproduce",
            AgentKind::LogCollector,
            Some(HOG_A),
        );
        store.agents_map().put(&collector).unwrap();

        assert_eq!(config_of(&node.agents[0]), Some(FAILING_HOG));
        assert_eq!(
            stored_agent(store, node.id, "001.reproduce"),
            Some(collector)
        );
        for key in [SENSOR, "001.reproduce"] {
            assert_eq!(revision(store, node.id, key), None);
            assert_eq!(record(store, node.id, key, 1), None);
        }
    }

    #[test]
    fn an_unsupervised_change_is_recorded_with_its_reference_checks() {
        let f = setup();
        let store = &f.store;
        let engine = agent(
            0,
            UNSUPERVISED,
            AgentKind::Unsupervised,
            Some(UNSUPERVISED_A),
        );
        let node = put_node(store, "n", CUSTOMER, vec![engine]);
        assert_eq!(config_of(&node.agents[0]), Some(UNSUPERVISED_A));
        assert_eq!(revision(store, node.id, UNSUPERVISED), Some(1));

        let mut changed = node.agents[0].clone();
        changed.config = Some(document(UNSUPERVISED_B));
        let new = with_agent(&node, &changed);
        let error = update_node(store, &node, &new).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<EngineDocumentError>(),
            Some(EngineDocumentError::RequiresEngineDocuments { .. })
        ));
        let error = update_node_with_documents(store, &node, &new, &[]).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<EngineDocumentError>(),
            Some(EngineDocumentError::ConfigWithoutReferences { .. })
        ));
        assert_eq!(revision(store, node.id, UNSUPERVISED), Some(1));

        let documents = [EngineDocumentWrite {
            agent_key: UNSUPERVISED.to_string(),
            applied: Some(EngineDocumentRefs::default()),
            pending: None,
        }];
        let returned = update_node_with_documents(store, &node, &new, &documents).unwrap();
        assert_eq!(returned, stored(store, node.id));
        assert_eq!(config_of(&returned.agents[0]), Some(UNSUPERVISED_B));
        assert_eq!(revision(store, node.id, UNSUPERVISED), Some(2));
        assert_eq!(
            recorded_document(store, node.id, UNSUPERVISED, 2),
            Some(UNSUPERVISED_B.to_string())
        );
        assert_eq!(
            store
                .engine_instance_state(&instance(node.id, UNSUPERVISED))
                .unwrap()
                .applied,
            EngineDocumentRefs::default()
        );
    }

    #[test]
    fn clearing_then_reapplying_records_the_next_revision() {
        let f = setup();
        let store = &f.store;
        let node = put_node(store, "n", CUSTOMER, vec![hog(0, HOG, Some(HOG_A))]);
        let applied = node.agents[0].clone();
        let mut cleared = applied.clone();
        cleared.config = None;
        store.agents_map().update(&applied, &cleared).unwrap();
        assert_eq!(revision(store, node.id, HOG), None);
        assert_eq!(
            recorded_document(store, node.id, HOG, 1),
            Some(completed(HOG_A))
        );

        store.agents_map().update(&cleared, &applied).unwrap();
        assert_eq!(revision(store, node.id, HOG), Some(2));
        assert_eq!(
            recorded_document(store, node.id, HOG, 2),
            Some(completed(HOG_A))
        );
    }

    #[test]
    fn a_recreated_agent_continues_from_the_highest_issued_number() {
        let f = setup();
        let store = &f.store;
        let node = put_node(store, "n", CUSTOMER, vec![hog(0, HOG, Some(HOG_A))]);

        // Directly through the agent table.
        store.agents_map().delete(node.id, HOG).unwrap();
        assert_eq!(revision(store, node.id, HOG), None);
        store
            .agents_map()
            .put(&hog(node.id, HOG, Some(HOG_A)))
            .unwrap();
        assert_eq!(revision(store, node.id, HOG), Some(2));

        // Through node updates.
        let node = stored(store, node.id);
        let removed = update_node(store, &node, &without_agent(&node, HOG)).unwrap();
        assert_eq!(revision(store, node.id, HOG), None);
        update_node(
            store,
            &removed,
            &with_agent(&removed, &hog(node.id, HOG, Some(HOG_A))),
        )
        .unwrap();
        assert_eq!(revision(store, node.id, HOG), Some(3));
        for n in 1..=3 {
            assert_eq!(
                recorded_document(store, node.id, HOG, n),
                Some(completed(HOG_A))
            );
        }
    }

    #[test]
    fn a_key_move_leaves_the_old_key_its_history_and_starts_the_new_one() {
        let f = setup();
        let store = &f.store;
        let agents = store.agents_map();
        let node = put_node(
            store,
            "n",
            CUSTOMER,
            vec![
                hog(0, HOG, Some(HOG_A)),
                hog(0, "003.hog", None),
                agent(0, SENSOR, AgentKind::Sensor, Some(SENSOR_DOC)),
            ],
        );
        // The new key has issued revision 1 before.
        agents.put(&hog(node.id, OTHER_HOG, Some(HOG_B))).unwrap();
        agents.delete(node.id, OTHER_HOG).unwrap();

        // An engine agent with a `config`, its bytes unchanged.
        let from = stored_agent(store, node.id, HOG).unwrap();
        let mut to = from.clone();
        to.key = OTHER_HOG.to_string();
        agents.update(&from, &to).unwrap();
        assert_eq!(stored_agent(store, node.id, HOG), None);
        assert_eq!(revision(store, node.id, HOG), None);
        assert_eq!(
            recorded_document(store, node.id, HOG, 1),
            Some(completed(HOG_A))
        );
        assert_eq!(revision(store, node.id, OTHER_HOG), Some(2));
        assert_eq!(
            recorded_document(store, node.id, OTHER_HOG, 2),
            Some(completed(HOG_A))
        );

        // An engine agent without a `config`, and a non-engine agent.
        for (key, moved) in [("003.hog", "004.hog"), (SENSOR, "002.piglet")] {
            let from = stored_agent(store, node.id, key).unwrap();
            let mut to = from.clone();
            to.key = moved.to_string();
            agents.update(&from, &to).unwrap();
            assert_eq!(stored_agent(store, node.id, moved), Some(to));
            for key in [key, moved] {
                assert_eq!(revision(store, node.id, key), None);
                assert_eq!(record(store, node.id, key, 1), None);
            }
        }

        // Moving back onto the old key issues its next number.
        let from = stored_agent(store, node.id, OTHER_HOG).unwrap();
        let mut to = from.clone();
        to.key = HOG.to_string();
        agents.update(&from, &to).unwrap();
        assert_eq!(revision(store, node.id, HOG), Some(2));
        assert_eq!(revision(store, node.id, OTHER_HOG), None);
    }

    #[test]
    fn a_key_move_in_a_committed_caller_transaction_is_recorded() {
        let f = setup();
        let store = &f.store;
        let agents = store.agents_map();
        let node = put_node(store, "n", CUSTOMER, vec![hog(0, HOG, Some(HOG_A))]);
        // The new key has issued revision 1 before.
        agents.put(&hog(node.id, OTHER_HOG, Some(HOG_A))).unwrap();
        agents.delete(node.id, OTHER_HOG).unwrap();

        let from = stored_agent(store, node.id, HOG).unwrap();
        let mut to = from.clone();
        to.key = OTHER_HOG.to_string();
        to.config = Some(document(HOG_B));
        let txn = agents.transaction();
        agents.update_with_transaction(&from, &to, &txn).unwrap();
        txn.commit().unwrap();

        assert_eq!(stored_agent(store, node.id, HOG), None);
        assert_eq!(revision(store, node.id, HOG), None);
        assert_eq!(
            recorded_document(store, node.id, HOG, 1),
            Some(completed(HOG_A))
        );
        assert_eq!(record(store, node.id, HOG, 2), None);

        let moved = stored_agent(store, node.id, OTHER_HOG).unwrap();
        assert_eq!(config_of(&moved), Some(completed(HOG_B).as_str()));
        assert_eq!(revision(store, node.id, OTHER_HOG), Some(2));
        assert_eq!(
            recorded_document(store, node.id, OTHER_HOG, 2),
            Some(completed(HOG_B))
        );
        assert_eq!(
            recorded_document(store, node.id, OTHER_HOG, 1),
            Some(completed(HOG_A))
        );
    }

    #[test]
    fn a_key_taken_over_by_a_non_engine_agent_starts_over_when_it_returns() {
        let f = setup();
        let store = &f.store;
        let node = put_node(store, "n", CUSTOMER, vec![hog(0, HOG, Some(HOG_A))]);
        let engine = node.agents[0].clone();
        let mut sensor = engine.clone();
        sensor.kind = AgentKind::Sensor;
        let node = stored(store, node.id);
        let node = update_node(store, &node, &with_agent(&node, &sensor)).unwrap();
        assert_eq!(revision(store, node.id, HOG), None);
        assert_eq!(
            recorded_document(store, node.id, HOG, 1),
            Some(completed(HOG_A))
        );

        // The outgoing bytes are complete already, and still record a
        // revision.
        update_node(store, &node, &with_agent(&node, &engine)).unwrap();
        assert_eq!(revision(store, node.id, HOG), Some(2));
        assert_eq!(stored_agent(store, node.id, HOG), Some(engine));
    }

    #[test]
    fn a_purge_after_a_customer_transfer_keeps_the_current_revision() {
        let f = setup();
        let store = &f.store;
        let node = put_node(store, "n", CUSTOMER, vec![hog(0, HOG, Some(HOG_A))]);
        let mut changed = node.agents[0].clone();
        changed.config = Some(document(HOG_B));
        let node = update_node(store, &node, &with_agent(&node, &changed)).unwrap();
        assert_eq!(revision(store, node.id, HOG), Some(2));

        let mut transferred = node.clone();
        transferred.profile = Some(profile(OTHER_CUSTOMER, "n"));
        let node = update_node(store, &node, &transferred).unwrap();
        assert_eq!(store.remove_customer_config_history(CUSTOMER).unwrap(), 2);

        assert_eq!(revision(store, node.id, HOG), Some(2));
        assert_eq!(record(store, node.id, HOG, 1), None);
        assert_eq!(record(store, node.id, HOG, 2), None);
        let mut changed = node.agents[0].clone();
        changed.config = Some(document(HOG_A));
        update_node(store, &node, &with_agent(&node, &changed)).unwrap();
        assert_eq!(revision(store, node.id, HOG), Some(3));
        assert_eq!(
            record(store, node.id, HOG, 3).unwrap().customer_id,
            Some(OTHER_CUSTOMER)
        );
    }

    #[test]
    fn the_draft_profile_gives_the_customer_without_an_applied_one() {
        let f = setup();
        let store = &f.store;
        let mut node = new_node("n", CUSTOMER, Vec::new());
        node.profile_draft = node.profile.take();
        let id = store.node_map().put(&node).unwrap();
        store.agents_map().put(&hog(id, HOG, Some(HOG_A))).unwrap();
        assert_eq!(
            record(store, id, HOG, 1).unwrap().customer_id,
            Some(CUSTOMER)
        );

        // An agent of no node records no customer.
        store.agents_map().put(&hog(99, HOG, Some(HOG_A))).unwrap();
        assert_eq!(record(store, 99, HOG, 1).unwrap().customer_id, None);
    }

    #[test]
    fn a_rename_during_the_customer_lookup_records_the_customer_of_the_node() {
        let f = setup();
        let store = &f.store;
        let node = put_node(store, "n", CUSTOMER, Vec::new());
        let node_id = node.id;
        let mut renamed = node.clone();
        renamed.name = "m".to_string();
        let mut taker = new_node("n", OTHER_CUSTOMER, Vec::new());
        taker.profile = Some(profile(OTHER_CUSTOMER, "other"));

        // Between the index read and the node read, the node is renamed and
        // another node of another customer takes its old name.
        set_hook(HookPoint::NodeLookup, move |db| {
            let mut nodes = NodeTable::open(db).unwrap();
            nodes
                .update(node.id, &node.into(), &renamed.into())
                .unwrap();
            nodes.put(&taker).unwrap();
        });
        store
            .agents_map()
            .put(&hog(node_id, HOG, Some(HOG_A)))
            .unwrap();
        assert_eq!(stored(store, node_id).name, "m");
        assert_eq!(
            record(store, node_id, HOG, 1).unwrap().customer_id,
            Some(CUSTOMER)
        );
    }

    #[test]
    fn concurrent_history_removals_count_each_row_once() {
        let f = setup();
        let store = &f.store;
        put_node(store, "a", CUSTOMER, vec![hog(0, HOG, Some(HOG_A))]);
        put_node(store, "b", CUSTOMER, vec![hog(0, HOG, Some(HOG_A))]);

        // Another removal commits after this one has begun its scan.
        let concurrent = std::rc::Rc::new(std::cell::Cell::new(None));
        let reported = std::rc::Rc::clone(&concurrent);
        set_hook(HookPoint::HistoryScan, move |db| {
            let removed = ConfigRevisions::open(db)
                .unwrap()
                .remove_customer_history(CUSTOMER)
                .unwrap();
            reported.set(Some(removed));
        });
        assert_eq!(store.remove_customer_config_history(CUSTOMER).unwrap(), 0);
        assert_eq!(concurrent.get(), Some(2));
    }

    #[test]
    fn concurrent_changes_record_distinct_increasing_revisions() {
        let f = setup();
        let store = &f.store;
        let node = put_node(store, "n", CUSTOMER, vec![hog(0, HOG, Some(HOG_A))]);
        let agents = store.agents_map();

        // Two transactions that both change the instance: the second to
        // commit conflicts, and its retry records the next number.
        let mut first = node.agents[0].clone();
        first.config = Some(document(HOG_B));
        let mut second = node.agents[0].clone();
        second.config = Some(document("data_store_port = 3\n"));
        let first_txn = agents.transaction();
        let second_txn = agents.transaction();
        agents.put_with_transaction(&first, &first_txn).unwrap();
        agents.put_with_transaction(&second, &second_txn).unwrap();
        first_txn.commit().unwrap();
        assert!(second_txn.commit().is_err());
        agents.put(&second).unwrap();
        assert_eq!(
            recorded_document(store, node.id, HOG, 2),
            Some(completed(HOG_B))
        );
        assert_eq!(
            recorded_document(store, node.id, HOG, 3),
            Some(completed("data_store_port = 3\n"))
        );

        // Writers on several threads.
        let documents: Vec<String> = (10..18)
            .map(|i| format!("data_store_port = {i}\n"))
            .collect();
        std::thread::scope(|scope| {
            for document_text in &documents {
                scope.spawn(move || {
                    store
                        .agents_map()
                        .put(&hog(node.id, HOG, Some(document_text)))
                        .unwrap();
                });
            }
        });
        let last = 3 + u64::try_from(documents.len()).unwrap();
        assert_eq!(revision(store, node.id, HOG), Some(last));
        let mut recorded: Vec<String> = (4..=last)
            .map(|n| recorded_document(store, node.id, HOG, n).unwrap())
            .collect();
        let mut expected: Vec<String> = documents.iter().map(|d| completed(d)).collect();
        recorded.sort_unstable();
        expected.sort_unstable();
        assert_eq!(recorded, expected);
        assert_eq!(record(store, node.id, HOG, last + 1), None);
        assert_eq!(
            config_of(&stored_agent(store, node.id, HOG).unwrap()).map(ToString::to_string),
            recorded_document(store, node.id, HOG, last)
        );
    }

    #[test]
    fn no_revision_for_instances_without_a_recorded_config() {
        let f = setup();
        let store = &f.store;
        let node = put_node(store, "n", CUSTOMER, vec![hog(0, HOG, None)]);
        assert_eq!(revision(store, node.id, HOG), None);
        assert_eq!(revision(store, node.id, "absent"), None);

        // Re-created without a `config`.
        store
            .agents_map()
            .put(&hog(node.id, OTHER_HOG, Some(HOG_A)))
            .unwrap();
        store.agents_map().delete(node.id, OTHER_HOG).unwrap();
        store
            .agents_map()
            .put(&hog(node.id, OTHER_HOG, None))
            .unwrap();
        assert_eq!(revision(store, node.id, OTHER_HOG), None);

        // A complete `config` stored before revisions were recorded, also
        // after a re-completion that finds nothing to change.
        put_raw(store, &hog(node.id, "003.hog", Some(&completed(HOG_A))));
        assert_eq!(revision(store, node.id, "003.hog"), None);
        assert_eq!(store.recomplete_applied_documents().unwrap(), Vec::new());
        assert_eq!(revision(store, node.id, "003.hog"), None);
    }

    #[test]
    fn removing_customer_history_removes_exactly_its_rows() {
        let f = setup();
        let store = &f.store;
        let first = put_node(store, "a", CUSTOMER, vec![hog(0, HOG, Some(HOG_A))]);
        let mut changed = first.agents[0].clone();
        changed.config = Some(document(HOG_B));
        update_node(store, &first, &with_agent(&first, &changed)).unwrap();
        let other = put_node(store, "b", OTHER_CUSTOMER, vec![hog(0, HOG, Some(HOG_A))]);
        let removed = put_node(store, "c", CUSTOMER, vec![hog(0, HOG, Some(HOG_A))]);
        store.node_map().remove(removed.id).unwrap();
        assert!(record(store, removed.id, HOG, 1).is_some());

        assert_eq!(store.remove_customer_config_history(CUSTOMER).unwrap(), 3);
        assert_eq!(record(store, first.id, HOG, 1), None);
        assert_eq!(record(store, first.id, HOG, 2), None);
        assert_eq!(record(store, removed.id, HOG, 1), None);
        assert_eq!(
            record(store, other.id, HOG, 1).unwrap().customer_id,
            Some(OTHER_CUSTOMER)
        );
        assert_eq!(store.remove_customer_config_history(CUSTOMER).unwrap(), 0);
    }

    #[test]
    fn node_ids_are_never_reused() {
        let f = setup();
        let store = &f.store;
        let removed = put_node(store, "a", CUSTOMER, vec![hog(0, HOG, Some(HOG_A))]);
        store.node_map().remove(removed.id).unwrap();
        let next = put_node(store, "b", CUSTOMER, vec![hog(0, HOG, Some(HOG_B))]);
        assert_ne!(next.id, removed.id);
        assert_eq!(
            recorded_document(store, removed.id, HOG, 1),
            Some(completed(HOG_A))
        );
        assert_eq!(revision(store, removed.id, HOG), None);
        assert_eq!(revision(store, next.id, HOG), Some(1));

        // An id an older build left on the free list.
        let freed = put_node(store, "c", CUSTOMER, Vec::new());
        let later = put_node(store, "d", CUSTOMER, Vec::new());
        let nodes = IndexedMap::new(store.states.db(), NODES).unwrap();
        nodes.remove::<InnerNode>(freed.id).unwrap();
        let ids: Vec<u32> = ["e", "f"]
            .into_iter()
            .map(|name| put_node(store, name, CUSTOMER, Vec::new()).id)
            .collect();
        for id in ids {
            assert!(![removed.id, next.id, freed.id, later.id].contains(&id));
        }
    }

    #[test]
    fn recompletion_completes_incomplete_documents_once() {
        let f = setup();
        let store = &f.store;
        put_model(store, WEB, http_url());
        let node = put_node(store, "n", CUSTOMER, Vec::new());
        put_raw(store, &hog(node.id, HOG, Some(HOG_A)));
        put_raw(store, &hog(node.id, OTHER_HOG, Some(FAILING_HOG)));
        put_raw(
            store,
            &unsupervised(node.id, UNSUPERVISED, Some(&detector(WEB))),
        );
        put_raw(
            store,
            &agent(node.id, SENSOR, AgentKind::Sensor, Some(HOG_A)),
        );

        let changed = store.recomplete_applied_documents().unwrap();
        assert_eq!(
            changed,
            vec![
                RecompletedDocument {
                    instance: instance(node.id, HOG),
                    revision: 1,
                    document: completed(HOG_A),
                },
                RecompletedDocument {
                    instance: instance(node.id, UNSUPERVISED),
                    revision: 1,
                    document: complete_web(WEB),
                },
            ]
        );
        assert_eq!(
            config_of(&stored_agent(store, node.id, HOG).unwrap()),
            Some(completed(HOG_A).as_str())
        );
        let first = record(store, node.id, HOG, 1).unwrap();
        assert_eq!(first.document, completed(HOG_A));
        assert_eq!(first.customer_id, Some(CUSTOMER));
        assert_eq!(revision(store, node.id, HOG), Some(1));
        assert_eq!(
            config_of(&stored_agent(store, node.id, UNSUPERVISED).unwrap()),
            Some(complete_web(WEB).as_str())
        );
        assert_eq!(
            recorded_document(store, node.id, UNSUPERVISED, 1),
            Some(complete_web(WEB))
        );
        assert_eq!(
            config_of(&stored_agent(store, node.id, OTHER_HOG).unwrap()),
            Some(FAILING_HOG)
        );
        assert_eq!(
            config_of(&stored_agent(store, node.id, SENSOR).unwrap()),
            Some(HOG_A)
        );
        for key in [OTHER_HOG, SENSOR] {
            assert_eq!(revision(store, node.id, key), None);
        }

        assert_eq!(store.recomplete_applied_documents().unwrap(), Vec::new());
        assert_eq!(revision(store, node.id, HOG), Some(1));
        assert_eq!(record(store, node.id, HOG, 2), None);
        assert_eq!(revision(store, node.id, UNSUPERVISED), Some(1));
        assert_eq!(record(store, node.id, UNSUPERVISED, 2), None);
    }

    #[test]
    fn recompletion_follows_the_model_types_of_unsupervised_documents() {
        const FILLED: &str = "001.reconverge";
        const PRUNED: &str = "002.reconverge";
        const COMPLETE: &str = "003.reconverge";
        const INVALID: &str = "004.reconverge";

        let f = setup();
        let store = &f.store;
        put_model(store, WEB, http_url());
        put_model(store, CUSTOM_MODEL, ClusteringModelTypeRef::Custom);
        let node = put_node(store, "n", CUSTOMER, Vec::new());
        let disallowed = format!("{}{FAR_OUTLIER}", detector(CUSTOM_MODEL));
        let invalid = format!(
            "{}[detectors.detection_models.far_outlier]\nenabled = 1\n",
            detector(WEB)
        );
        // Revision 1 is recorded by a write, before the stored document
        // becomes incomplete under the type its model has now.
        store
            .agents_map()
            .put(&unsupervised(node.id, FILLED, Some(&detector("later"))))
            .unwrap();
        let mut filled = unsupervised(node.id, FILLED, Some(&detector(WEB)));
        filled.draft = Some(document(&disallowed));
        put_raw(store, &filled);
        put_raw(store, &unsupervised(node.id, PRUNED, Some(&disallowed)));
        put_raw(
            store,
            &unsupervised(node.id, COMPLETE, Some(&complete_web(WEB))),
        );
        put_raw(store, &unsupervised(node.id, INVALID, Some(&invalid)));

        let (changed, warnings) = capture_warnings(|| store.recomplete_applied_documents());
        assert_eq!(
            changed.unwrap(),
            vec![
                RecompletedDocument {
                    instance: instance(node.id, FILLED),
                    revision: 2,
                    document: complete_web(WEB),
                },
                RecompletedDocument {
                    instance: instance(node.id, PRUNED),
                    revision: 1,
                    document: detector(CUSTOM_MODEL),
                },
            ]
        );
        let filled = stored_agent(store, node.id, FILLED).unwrap();
        assert_eq!(config_of(&filled), Some(complete_web(WEB).as_str()));
        assert_eq!(revision(store, node.id, FILLED), Some(2));
        assert_eq!(
            recorded_document(store, node.id, FILLED, 2),
            Some(complete_web(WEB))
        );
        assert_eq!(
            recorded_document(store, node.id, FILLED, 1),
            Some(detector("later"))
        );
        assert_eq!(
            filled.draft.as_ref().map(AsRef::as_ref),
            Some(disallowed.as_str())
        );
        assert_eq!(
            config_of(&stored_agent(store, node.id, PRUNED).unwrap()),
            Some(detector(CUSTOM_MODEL).as_str())
        );
        assert_eq!(
            recorded_document(store, node.id, PRUNED, 1),
            Some(detector(CUSTOM_MODEL))
        );
        assert_eq!(
            config_of(&stored_agent(store, node.id, COMPLETE).unwrap()),
            Some(complete_web(WEB).as_str())
        );
        assert_eq!(
            config_of(&stored_agent(store, node.id, INVALID).unwrap()),
            Some(invalid.as_str())
        );
        for key in [COMPLETE, INVALID] {
            assert_eq!(revision(store, node.id, key), None);
            assert_eq!(record(store, node.id, key, 1), None);
        }
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let warning = &warnings[0];
        assert!(
            warning.contains(&format!("node_id={}", node.id))
                && warning.contains(INVALID)
                && warning.contains("must be a boolean"),
            "{warning}"
        );

        assert_eq!(store.recomplete_applied_documents().unwrap(), Vec::new());
    }

    #[test]
    fn a_model_read_failure_ends_recompletion_with_what_it_committed() {
        let f = setup();
        let store = &f.store;
        put_model(store, WEB, http_url());
        let node = put_node(store, "n", CUSTOMER, Vec::new());
        put_raw(store, &hog(node.id, HOG, Some(HOG_A)));
        put_raw(
            store,
            &unsupervised(node.id, UNSUPERVISED, Some(&detector(WEB))),
        );

        fail_model_reads(true);
        let error = store.recomplete_applied_documents().unwrap_err();
        fail_model_reads(false);
        assert_eq!(
            error.committed,
            vec![RecompletedDocument {
                instance: instance(node.id, HOG),
                revision: 1,
                document: completed(HOG_A),
            }]
        );
        assert!(error.to_string().contains("injected failure"), "{error}");
        assert_eq!(
            config_of(&stored_agent(store, node.id, UNSUPERVISED).unwrap()),
            Some(detector(WEB).as_str())
        );
        assert_eq!(revision(store, node.id, UNSUPERVISED), None);
        assert_eq!(record(store, node.id, UNSUPERVISED, 1), None);
    }

    /// The writers that can replace a stored Unsupervised Engine agent: each
    /// takes the stored row and its replacement under the same key.
    fn unsupervised_replacing_paths() -> Vec<(&'static str, Replace)> {
        let mut paths: Vec<(&'static str, Replace)> = vec![(
            "NodeTable::update_with_engine_documents",
            |store, old, new| {
                let node = stored(store, old.node_id);
                let documents = [EngineDocumentWrite {
                    agent_key: new.key.clone(),
                    applied: Some(EngineDocumentRefs::default()),
                    pending: None,
                }];
                update_node_with_documents(store, &node, &with_agent(&node, new), &documents)
                    .map(drop)
            },
        )];
        paths.extend(
            replacing_paths()
                .into_iter()
                .filter(|(name, _)| !name.starts_with("NodeTable")),
        );
        paths
    }

    /// The writers that can create an Unsupervised Engine agent on node
    /// `node`, which holds no agent under its key: [`creating_paths`] and
    /// `NodeTable::put`, which stores a new node holding the agent.
    fn unsupervised_creating_paths() -> Vec<(&'static str, Create)> {
        let mut paths = creating_paths();
        paths.push(("NodeTable::put", |store, node, new| {
            store
                .node_map()
                .put(&new_node(
                    &format!("{}-put", node.name),
                    CUSTOMER,
                    vec![new.clone()],
                ))
                .map(drop)
        }));
        paths
    }

    #[test]
    fn every_path_completes_an_unsupervised_document_in_apply_mode() {
        for (name, replace) in unsupervised_replacing_paths() {
            let f = setup();
            let store = &f.store;
            put_model(store, WEB, http_url());
            put_model(store, CUSTOM_MODEL, ClusteringModelTypeRef::Custom);
            let node = put_node(
                store,
                "n",
                CUSTOMER,
                vec![unsupervised(0, UNSUPERVISED, Some(&detector("missing")))],
            );
            assert_eq!(
                config_of(&node.agents[0]),
                Some(detector("missing").as_str()),
                "{name}"
            );
            assert_eq!(revision(store, node.id, UNSUPERVISED), Some(1), "{name}");
            let change = |config: &str| {
                let old = stored_agent(store, node.id, UNSUPERVISED).unwrap();
                let mut new = old.clone();
                new.config = Some(document(config));
                replace(store, &old, &new)
            };

            change(&detector(WEB)).unwrap();
            let stored_config = || {
                config_of(&stored_agent(store, node.id, UNSUPERVISED).unwrap())
                    .map(ToOwned::to_owned)
            };
            assert_eq!(stored_config(), Some(complete_web(WEB)), "{name}");
            assert_eq!(revision(store, node.id, UNSUPERVISED), Some(2), "{name}");
            assert_eq!(
                recorded_document(store, node.id, UNSUPERVISED, 2),
                Some(complete_web(WEB)),
                "{name}"
            );

            // Refused in apply mode, changing nothing.
            let error = change(&format!("{}{FAR_OUTLIER}", detector(CUSTOM_MODEL))).unwrap_err();
            match error.downcast_ref::<DetectionModelsSectionError>() {
                Some(DetectionModelsSectionError::Detector(detector)) => assert_eq!(
                    detector.error,
                    DetectionModelsSectionError::DisallowedModel {
                        section: "far_outlier".to_string()
                    },
                    "{name}"
                ),
                other => panic!("{name}: {other:?}: {error:#}"),
            }
            assert_eq!(stored_config(), Some(complete_web(WEB)), "{name}");
            assert_eq!(revision(store, node.id, UNSUPERVISED), Some(2), "{name}");

            // An input completing to the stored bytes records nothing.
            change(&detector(WEB)).unwrap();
            assert_eq!(stored_config(), Some(complete_web(WEB)), "{name}");
            assert_eq!(revision(store, node.id, UNSUPERVISED), Some(2), "{name}");
            assert_eq!(record(store, node.id, UNSUPERVISED, 3), None, "{name}");

            // A model record read failure fails the write, changing nothing.
            fail_model_reads(true);
            let error = change(&detector(CUSTOM_MODEL)).unwrap_err();
            fail_model_reads(false);
            assert!(
                error
                    .downcast_ref::<DetectionModelsSectionError>()
                    .is_none(),
                "{name}: {error:#}"
            );
            assert!(format!("{error:#}").contains("injected failure"), "{name}");
            assert_eq!(stored_config(), Some(complete_web(WEB)), "{name}");
            assert_eq!(revision(store, node.id, UNSUPERVISED), Some(2), "{name}");
            assert_eq!(record(store, node.id, UNSUPERVISED, 3), None, "{name}");
        }
    }

    #[test]
    fn every_creating_path_completes_an_unsupervised_document_in_apply_mode() {
        for (name, create) in unsupervised_creating_paths() {
            let f = setup();
            let store = &f.store;
            put_model(store, WEB, http_url());
            put_model(store, CUSTOM_MODEL, ClusteringModelTypeRef::Custom);
            let node = put_node(store, "n", CUSTOMER, Vec::new());
            // `NodeTable::put` stores a node of its own, with the next id.
            let node_id = if name == "NodeTable::put" {
                node.id + 1
            } else {
                node.id
            };

            let refused = format!("{}{FAR_OUTLIER}", detector(CUSTOM_MODEL));
            let error = create(
                store,
                &node,
                &unsupervised(node_id, UNSUPERVISED, Some(&refused)),
            )
            .unwrap_err();
            assert_completion_error(&error);
            assert_eq!(revision(store, node_id, UNSUPERVISED), None, "{name}");

            create(
                store,
                &node,
                &unsupervised(node_id, UNSUPERVISED, Some(&detector(WEB))),
            )
            .unwrap();
            let agent = stored_agent(store, node_id, UNSUPERVISED).unwrap();
            assert_eq!(
                config_of(&agent),
                Some(complete_web(WEB).as_str()),
                "{name}"
            );
            assert_eq!(revision(store, node_id, UNSUPERVISED), Some(1), "{name}");
            assert_eq!(
                recorded_document(store, node_id, UNSUPERVISED, 1),
                Some(complete_web(WEB)),
                "{name}"
            );
        }
    }

    #[test]
    fn a_model_read_failure_fails_every_creating_path_and_stores_nothing() {
        for (name, create) in unsupervised_creating_paths() {
            let f = setup();
            let store = &f.store;
            put_model(store, WEB, http_url());
            let node = put_node(store, "n", CUSTOMER, Vec::new());
            // `NodeTable::put` stores a node of its own, with the next id.
            let node_id = if name == "NodeTable::put" {
                node.id + 1
            } else {
                node.id
            };
            let nodes = store.node_map().count().unwrap();
            let new = unsupervised(node_id, UNSUPERVISED, Some(&detector(WEB)));

            fail_model_reads(true);
            let result = create(store, &node, &new);
            fail_model_reads(false);
            let error = result.unwrap_err();
            assert!(
                error
                    .downcast_ref::<DetectionModelsSectionError>()
                    .is_none(),
                "{name}: {error:#}"
            );
            assert!(
                format!("{error:#}").contains("injected failure"),
                "{name}: {error:#}"
            );
            assert_eq!(stored_agent(store, node_id, UNSUPERVISED), None, "{name}");
            assert_eq!(revision(store, node_id, UNSUPERVISED), None, "{name}");
            assert_eq!(record(store, node_id, UNSUPERVISED, 1), None, "{name}");
            assert_eq!(stored(store, node.id), node, "{name}");
            assert_eq!(store.node_map().count().unwrap(), nodes, "{name}");
            if name == "agents update to a new key" {
                // The placeholder the path stores before its move stays.
                let placeholder = format!("{UNSUPERVISED}.placeholder");
                let row = stored_agent(store, node.id, &placeholder);
                assert_eq!(row.map(|a| a.kind), Some(AgentKind::Sensor), "{name}");
            }

            // Without the injection, the same path stores the same document.
            create(store, &node, &new).unwrap();
            let agent = stored_agent(store, node_id, UNSUPERVISED).unwrap();
            assert_eq!(
                config_of(&agent),
                Some(complete_web(WEB).as_str()),
                "{name}"
            );
            assert_eq!(revision(store, node_id, UNSUPERVISED), Some(1), "{name}");
        }
    }

    #[test]
    fn a_write_keeping_an_unsupervised_config_looks_up_no_model() {
        let f = setup();
        let store = &f.store;
        put_model(store, CUSTOM_MODEL, ClusteringModelTypeRef::Custom);
        let node = put_node(store, "n", CUSTOMER, Vec::new());
        // A stored document apply mode would refuse.
        let refused = format!("{}{FAR_OUTLIER}", detector(CUSTOM_MODEL));
        let stored_row = unsupervised(node.id, UNSUPERVISED, Some(&refused));
        put_raw(store, &stored_row);

        let mut new = stored_row.clone();
        new.status = AgentStatus::Disabled;
        fail_model_reads(true);
        let result = store.agents_map().update(&stored_row, &new);
        fail_model_reads(false);
        result.unwrap();
        let agent = stored_agent(store, node.id, UNSUPERVISED).unwrap();
        assert_eq!(agent.status, AgentStatus::Disabled);
        assert_eq!(config_of(&agent), Some(refused.as_str()));
        assert_eq!(revision(store, node.id, UNSUPERVISED), None);
    }

    #[test]
    fn recompletion_never_overwrites_a_concurrent_apply() {
        let f = setup();
        let store = Arc::new(f.store);
        let node = put_node(&store, "n", CUSTOMER, Vec::new());
        put_raw(&store, &hog(node.id, HOG, Some(HOG_A)));

        let applied = Arc::new(AtomicUsize::new(0));
        let hook_store = Arc::downgrade(&store);
        let hook_applied = Arc::clone(&applied);
        store.set_recompletion_hook(Some(Arc::new(move |instance| {
            if hook_applied.fetch_add(1, Ordering::SeqCst) == 0 {
                let store = hook_store.upgrade().expect("the test holds the store");
                store
                    .agents_map()
                    .put(&hog(instance.node_id, &instance.agent_key, Some(HOG_B)))?;
            }
            Ok(())
        })));

        assert_eq!(store.recomplete_applied_documents().unwrap(), Vec::new());
        store.set_recompletion_hook(None);
        assert_eq!(applied.load(Ordering::SeqCst), 1);
        assert_eq!(
            config_of(&stored_agent(&store, node.id, HOG).unwrap()),
            Some(completed(HOG_B).as_str())
        );
        assert_eq!(revision(&store, node.id, HOG), Some(1));
        assert_eq!(
            recorded_document(&store, node.id, HOG, 1),
            Some(completed(HOG_B))
        );
        assert_eq!(record(&store, node.id, HOG, 2), None);
    }

    #[test]
    fn a_recompletion_database_failure_reports_what_it_committed() {
        let f = setup();
        let store = &f.store;
        let node = put_node(store, "n", CUSTOMER, Vec::new());
        put_raw(store, &hog(node.id, HOG, Some(HOG_A)));
        put_raw(store, &hog(node.id, OTHER_HOG, Some(HOG_B)));

        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = Arc::clone(&calls);
        store.set_recompletion_hook(Some(Arc::new(move |_| {
            if hook_calls.fetch_add(1, Ordering::SeqCst) == 1 {
                anyhow::bail!("injected database failure");
            }
            Ok(())
        })));
        let error = store.recomplete_applied_documents().unwrap_err();
        store.set_recompletion_hook(None);

        assert_eq!(
            error.committed,
            vec![RecompletedDocument {
                instance: instance(node.id, HOG),
                revision: 1,
                document: completed(HOG_A),
            }]
        );
        assert!(error.to_string().contains("injected database failure"));
        assert_eq!(
            config_of(&stored_agent(store, node.id, HOG).unwrap()),
            Some(completed(HOG_A).as_str())
        );
        assert_eq!(
            recorded_document(store, node.id, HOG, 1),
            Some(completed(HOG_A))
        );
        assert_eq!(
            config_of(&stored_agent(store, node.id, OTHER_HOG).unwrap()),
            Some(HOG_B)
        );
        assert_eq!(revision(store, node.id, OTHER_HOG), None);
        assert_eq!(record(store, node.id, OTHER_HOG, 1), None);
    }

    #[test]
    fn the_format_marker_is_unchanged() {
        assert_eq!(crate::migration::DATABASE_FORMAT_VERSION, "0.63.0");
    }

    /// An Unsupervised Engine model of the `server_daily_tls` time-series
    /// type.
    const TLS_MODEL: &str = "tls";
    const WINDOW_OUTLIER: &str = "[detectors.detection_models.window_outlier]\nenabled = true\n";

    /// Inserts a custom time series generation policy `name` of
    /// [`CUSTOMER`], reading `sensors`, and returns its id.
    fn put_policy(store: &Store, name: &str, sensors: &[&str]) -> u32 {
        use review_protocol::types::{CounterpartScope, GroupByUnit, Measure, RawEventKind};

        store
            .time_series_generation_policy_map()
            .insert(crate::NewTimeSeriesGenerationPolicy {
                name: name.to_string(),
                raw_event_kind: RawEventKind::Tls,
                measure: Measure::Count,
                group_by: None,
                group_by_unit: GroupByUnit::Ip,
                counterpart_scope: CounterpartScope::Any,
                slot_size: crate::SlotSize::FiveMinutes,
                window_size: crate::WindowSize::OneDay,
                utc_offset: 0,
                src_ip: None,
                dst_ip: None,
                sensors: sensors.iter().map(ToString::to_string).collect(),
                time_series_type: None,
                customer_id: CUSTOMER,
            })
            .unwrap()
    }

    /// A [`TLS_MODEL`] detector reading the policies `ids`.
    fn tls_detector(ids: &[String]) -> String {
        let sources: Vec<_> = ids.iter().map(|id| format!("\"{id}\"")).collect();
        format!(
            "{}sources = [{}]\n",
            detector(TLS_MODEL),
            sources.join(", ")
        )
    }

    /// [`tls_detector`] completed with `source_sensors`, given as TOML.
    fn complete_tls(ids: &[String], source_sensors: &str) -> String {
        format!(
            "{}source_sensors = {source_sensors}\n\n{WINDOW_OUTLIER}",
            tls_detector(ids)
        )
    }

    fn server_daily_tls() -> ClusteringModelTypeRef {
        ClusteringModelTypeRef::Catalog {
            id: "server_daily_tls".to_string(),
            version: 1,
        }
    }

    #[test]
    fn an_applied_unsupervised_document_gets_the_sensors_of_its_source_policies() {
        let f = setup();
        let store = &f.store;
        put_model(store, TLS_MODEL, server_daily_tls());
        let a = put_policy(store, "a", &["s2", "s1"]);
        let b = put_policy(store, "b", &["s3"]);
        let ids = [a.to_string(), b.to_string(), "999".to_string()];
        let applied = tls_detector(&ids);
        let expected = complete_tls(
            &ids,
            &format!(r#"{{ "{a}" = ["s2", "s1"], "{b}" = ["s3"] }}"#),
        );

        let node = put_node(
            store,
            "n",
            CUSTOMER,
            vec![unsupervised(0, UNSUPERVISED, Some(&applied))],
        );
        let stored_row = stored_agent(store, node.id, UNSUPERVISED).unwrap();
        assert_eq!(config_of(&stored_row), Some(expected.as_str()));
        assert_eq!(revision(store, node.id, UNSUPERVISED), Some(1));
        assert_eq!(
            recorded_document(store, node.id, UNSUPERVISED, 1),
            Some(expected.clone())
        );

        // A draft is stored as it is given.
        let mut drafted = stored_row.clone();
        drafted.draft = Some(document(&applied));
        let documents = [EngineDocumentWrite {
            agent_key: UNSUPERVISED.to_string(),
            applied: None,
            pending: Some(EngineDocumentRefs::default()),
        }];
        update_node_with_documents(store, &node, &with_agent(&node, &drafted), &documents).unwrap();
        let stored_row = stored_agent(store, node.id, UNSUPERVISED).unwrap();
        assert_eq!(
            stored_row.draft.as_ref().map(AsRef::as_ref),
            Some(applied.as_str())
        );
        assert_eq!(config_of(&stored_row), Some(expected.as_str()));
        assert_eq!(revision(store, node.id, UNSUPERVISED), Some(1));

        // Recompletion follows a change of a policy's sensors.
        let policies = store.time_series_generation_policy_map();
        let old = policies.get_by_id(a).unwrap().unwrap();
        let mut new: crate::TimeSeriesGenerationPolicyUpdate = old.clone().into();
        new.sensors = vec!["s4".to_string()];
        let mut policies = policies;
        policies.update(a, &old.into(), &new).unwrap();
        let recompleted = complete_tls(&ids, &format!(r#"{{ "{a}" = ["s4"], "{b}" = ["s3"] }}"#));
        assert_eq!(
            store.recomplete_applied_documents().unwrap(),
            vec![RecompletedDocument {
                instance: instance(node.id, UNSUPERVISED),
                revision: 2,
                document: recompleted.clone(),
            }]
        );
        let stored_row = stored_agent(store, node.id, UNSUPERVISED).unwrap();
        assert_eq!(config_of(&stored_row), Some(recompleted.as_str()));
        assert_eq!(
            stored_row.draft.as_ref().map(AsRef::as_ref),
            Some(applied.as_str())
        );
        assert_eq!(store.recomplete_applied_documents().unwrap(), Vec::new());
    }

    #[test]
    fn a_policy_changed_during_completion_conflicts_with_the_write() {
        let f = setup();
        let store = &f.store;
        put_model(store, TLS_MODEL, server_daily_tls());
        let a = put_policy(store, "a", &["s1"]);
        let ids = [a.to_string()];

        // The policy's sensors change after the write read them, so the write
        // conflicts and is retried with the new sensors.
        set_hook(HookPoint::ModelLookup, move |db| {
            let map = IndexedMap::new(db, "time series generation policy").unwrap();
            let mut policy: crate::TimeSeriesGenerationPolicy = map.get_by_id(a).unwrap().unwrap();
            policy.sensors = vec!["late".to_string()];
            db.put_cf(
                map.cf(),
                crate::Indexable::indexed_key(&policy),
                crate::Indexable::value(&policy),
            )
            .unwrap();
        });
        let node = put_node(
            store,
            "n",
            CUSTOMER,
            vec![unsupervised(0, UNSUPERVISED, Some(&tls_detector(&ids)))],
        );
        assert_eq!(
            config_of(&stored_agent(store, node.id, UNSUPERVISED).unwrap()),
            Some(complete_tls(&ids, &format!(r#"{{ "{a}" = ["late"] }}"#)).as_str())
        );
        assert_eq!(revision(store, node.id, UNSUPERVISED), Some(1));
    }
}
