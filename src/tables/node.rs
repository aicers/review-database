//! The `network` table.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fmt::Display,
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use num_derive::{FromPrimitive, ToPrimitive};
use rocksdb::{Direction, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use super::{
    EngineInstances, Model, ModelInstance, ModelRuns, SamplingPolicy, TableIter as TI,
    TrainingDefinitions,
    agent::sensor_hostname,
    engine_instance::{self, EngineDetectorRef, EngineDocumentError, EngineDocumentWrite},
};
use crate::{
    Agent, AgentKind, EXCLUSIVE, ExternalService, Indexable, IndexedMap, IndexedMapUpdate,
    IndexedTable, Iterable, Map, Table as CrateTable, UniqueKey, collections::Indexed,
    model_guard::InstanceRecords, training::INSTANCE_REMOVED, types::FromKeyValue,
};

#[derive(
    Serialize,
    Default,
    Deserialize,
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    EnumString,
    FromPrimitive,
    ToPrimitive,
)]
#[repr(u8)]
#[strum(serialize_all = "snake_case")]
pub enum Status {
    Disabled = 0,
    #[default]
    Enabled = 1,
    ReloadFailed = 2,
    Unknown = u8::MAX,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Default)]
pub struct Config {
    inner: String,
}

impl TryFrom<String> for Config {
    type Error = anyhow::Error;

    fn try_from(inner: String) -> Result<Self> {
        let _ = &inner.parse::<toml::Table>()?;
        Ok(Self { inner })
    }
}

impl AsRef<str> for Config {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Debug)]
pub struct Node {
    pub id: u32,
    pub name: String,
    pub name_draft: Option<String>,
    pub profile: Option<Profile>,
    pub profile_draft: Option<Profile>,
    pub agents: Vec<Agent>,
    pub external_services: Vec<ExternalService>,
    pub creation_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct Update {
    pub name: Option<String>,
    pub name_draft: Option<String>,
    pub profile: Option<Profile>,
    pub profile_draft: Option<Profile>,
    pub agents: Vec<Agent>,
    pub external_services: Vec<ExternalService>,
}

impl UniqueKey for Node {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl From<Node> for Update {
    fn from(input: Node) -> Self {
        Self {
            name: Some(input.name),
            name_draft: input.name_draft,
            profile: input.profile,
            profile_draft: input.profile_draft,
            agents: input.agents,
            external_services: input.external_services,
        }
    }
}

impl<'i, 'j> Iterable<'i, TableIter<'j>> for Table<'_>
where
    'i: 'j,
{
    fn iter(&'i self, direction: Direction, from: Option<&[u8]>) -> TableIter<'j> {
        TableIter {
            node: self.node.iter(direction, from),
            agent: self.agent.clone(),
            external_service: self.external_service.clone(),
        }
    }

    fn prefix_iter(
        &'i self,
        direction: Direction,
        from: Option<&[u8]>,
        prefix: &[u8],
    ) -> TableIter<'j> {
        let iter = self.node.prefix_iter(direction, from, prefix);
        TableIter {
            node: iter,
            agent: self.agent.clone(),
            external_service: self.external_service.clone(),
        }
    }
}

pub struct Table<'d> {
    node: IndexedTable<'d, Inner>,
    agent: CrateTable<'d, Agent>,
    external_service: CrateTable<'d, ExternalService>,
    engine_instances: EngineInstances<'d>,
    model: IndexedTable<'d, Model>,
    model_indicator: Map<'d>,
    model_runs: ModelRuns<'d>,
    sampling_policies: IndexedTable<'d, SamplingPolicy>,
    training_definitions: TrainingDefinitions<'d>,
    /// Run by every writer after its checks and before its commit.
    #[cfg(test)]
    before_commit_hook: Option<BeforeCommitHook<'d>>,
}

/// A hook the tests run before a node writer commits; an error it returns
/// ends the write with that error.
#[cfg(test)]
pub(crate) type BeforeCommitHook<'d> = Box<dyn Fn() -> Result<()> + 'd>;

type NodeWithInvalidAgentExternalService = (Node, Vec<String>, Vec<String>);

impl<'d> Table<'d> {
    /// Opens the node table in the database.
    ///
    /// Returns `None` if the table does not exist.
    ///
    /// # Panics
    ///
    /// Panics if node map doesn't exist.
    pub fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        let node = IndexedMap::new(db, super::NODES)
            .map(IndexedTable::new)
            .expect("{super::NODES} must be present");
        let agent = Map::open(db, super::AGENTS).map(CrateTable::new)?;
        let external_service = Map::open(db, super::EXTERNAL_SERVICES).map(CrateTable::new)?;
        let engine_instances = EngineInstances::open(db)?;
        let model = IndexedTable::<Model>::open(db)?;
        let model_indicator = Map::open(db, super::MODEL_INDICATORS)?;
        let model_runs = ModelRuns::open(db)?;
        let sampling_policies = IndexedTable::<SamplingPolicy>::open(db)?;
        let training_definitions = TrainingDefinitions::open(db)?;
        Some(Self {
            node,
            agent,
            external_service,
            engine_instances,
            model,
            model_indicator,
            model_runs,
            sampling_policies,
            training_definitions,
            #[cfg(test)]
            before_commit_hook: None,
        })
    }

    /// Sets the hook every writer runs after its checks and before its
    /// commit.
    #[cfg(test)]
    pub(crate) fn set_before_commit_hook(&mut self, hook: Option<BeforeCommitHook<'d>>) {
        self.before_commit_hook = hook;
    }

    #[cfg(test)]
    fn run_before_commit_hook(&self) -> Result<()> {
        self.before_commit_hook
            .as_ref()
            .map_or(Ok(()), |hook| hook())
    }

    /// Detaches, within `txn`, the records an agent leaves behind when it is
    /// removed from node `node_id`: the runs its instance performs fail with
    /// the reason "instance removed", a clone among them removing the target
    /// definition it reserved, as does a clone creating a definition on the
    /// instance; its models and training definitions are left with no
    /// instance; its `engine instances` row, with its references, detector
    /// statuses and stopped state, is deleted; and every sampling policy
    /// assigned to it is left unassigned, its `data_store` unchanged, since
    /// a later agent of a reused node id and the same key would otherwise
    /// inherit the assignment.
    ///
    /// Every writer that removes an agent calls this for each agent key it
    /// removes, whatever the agent's kind: the agent row may already be
    /// missing, and an agent without records changes nothing. The run id
    /// counter, the runs, definitions and models it changes and the deleted
    /// row are tracked by the transaction, so a concurrent write of any of
    /// them conflicts with the removal instead of leaving a record behind;
    /// a record that gains the instance after the scans conflicts through
    /// the counter or the agent row the writer removes.
    fn remove_agent_records(
        &self,
        txn: &rocksdb::Transaction<OptimisticTransactionDB>,
        node_id: u32,
        agent_key: &str,
    ) -> Result<()> {
        let instance = ModelInstance {
            node_id,
            agent_key: agent_key.to_string(),
        };
        InstanceRecords {
            runs: &self.model_runs,
            definitions: &self.training_definitions,
            models: &self.model,
            engine_instances: &self.engine_instances,
        }
        .detach(txn, &instance, INSTANCE_REMOVED)?;
        self.sampling_policies
            .unassign_in_transaction(txn, &instance)
    }

    /// Returns whether `name` is a sensor name of customer `customer_id` as
    /// `txn` sees the nodes: the [`AgentKind::Sensor`] package-id, a dot and
    /// the non-empty hostname of the applied profile of a node of the
    /// customer that carries an [`AgentKind::Sensor`] agent.
    ///
    /// The node and agent rows that decide it are read for update, so a
    /// concurrent change of one conflicts with `txn`; the scan that finds
    /// the node is not tracked.
    pub(crate) fn is_sensor_name_in_transaction(
        &self,
        txn: &rocksdb::Transaction<OptimisticTransactionDB>,
        customer_id: u32,
        name: &str,
    ) -> Result<bool> {
        let Some(hostname) = sensor_hostname(name) else {
            return Ok(false);
        };
        let of_customer = |inner: &Inner| {
            inner
                .profile
                .as_ref()
                .is_some_and(|p| p.customer_id == customer_id && p.hostname == hostname)
        };
        for item in txn.iterator_cf(self.node.raw().cf(), rocksdb::IteratorMode::Start) {
            let (key, value) = item.context("cannot read nodes")?;
            if key.is_empty() {
                continue;
            }
            let scanned: Inner = super::deserialize(&value)?;
            if !of_customer(&scanned) {
                continue;
            }
            let Some(inner) = self.node.get_by_id_in_transaction(scanned.id, txn)? else {
                continue;
            };
            if !of_customer(&inner) {
                continue;
            }
            for agent_key in &inner.agents {
                let key = engine_instance::key(inner.id, agent_key);
                if crate::engine_instance::agent_for_update(txn, self.agent.raw().cf, &key)?
                    .is_some_and(|agent| agent.kind == AgentKind::Sensor)
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Returns the applied profile of node `id`, read for update within
    /// `txn`; `None` if the node has none or does not exist.
    pub(crate) fn applied_profile_in_transaction(
        &self,
        id: u32,
        txn: &rocksdb::Transaction<OptimisticTransactionDB>,
    ) -> Result<Option<Profile>> {
        Ok(self
            .node
            .get_by_id_in_transaction(id, txn)?
            .and_then(|node| node.profile))
    }

    #[allow(unused)]
    pub(crate) fn agent_raw(&self) -> &Map<'_> {
        self.agent.raw()
    }

    /// Returns the total count of nodes available.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn count(&self) -> Result<usize> {
        self.node.count()
    }

    /// Checks if a hostname is already in use by any node within a transaction.
    /// This is used to atomically check hostname uniqueness.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn is_hostname_in_use_transaction(
        &self,
        txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
        hostname: &str,
    ) -> Result<bool> {
        use rocksdb::IteratorMode;

        let iter = txn.iterator_cf(self.node.raw().cf(), IteratorMode::Start);

        for item in iter {
            let (key, value) = item.context("Failed to read item from transaction iterator")?;

            // Skip the index entry (empty key)
            if key.is_empty() {
                continue;
            }

            let inner: Inner = super::deserialize(&value)?;

            if let Some(profile) = &inner.profile
                && profile.hostname == hostname
            {
                return Ok(true);
            }
            if let Some(profile_draft) = &inner.profile_draft
                && profile_draft.hostname == hostname
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Checks if a hostname is already in use by any node except the specified node ID within a transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn is_hostname_in_use_except_transaction(
        &self,
        txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
        hostname: &str,
        except_id: u32,
    ) -> Result<bool> {
        use rocksdb::IteratorMode;

        let iter = txn.iterator_cf(self.node.raw().cf(), IteratorMode::Start);

        for item in iter {
            let (key, value) = item.context("Failed to read item from transaction iterator")?;

            // Skip the index entry (empty key)
            if key.is_empty() {
                continue;
            }

            let inner: Inner = super::deserialize(&value)?;

            if inner.id == except_id {
                continue;
            }

            if let Some(profile) = &inner.profile
                && profile.hostname == hostname
            {
                return Ok(true);
            }
            if let Some(profile_draft) = &inner.profile_draft
                && profile_draft.hostname == hostname
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Returns a tuple of `(node, invalid_agents, invalid_external_services)` when node with `id` exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn get_by_id(&self, id: u32) -> Result<Option<NodeWithInvalidAgentExternalService>> {
        let Some(inner) = self.node.get_by_id(id)? else {
            return Ok(None);
        };

        let mut agents = vec![];
        let mut invalid_agents = vec![];
        for aid in inner.agents {
            if let Some(agent) = self.agent.get(id, &aid)? {
                agents.push(agent);
            } else {
                invalid_agents.push(aid);
            }
        }

        let mut external_services = vec![];
        let mut invalid_external_services = vec![];
        for es_id in inner.external_services {
            if let Some(external_service) = self.external_service.get(id, &es_id)? {
                external_services.push(external_service);
            } else {
                invalid_external_services.push(es_id);
            }
        }

        let node = Node {
            id: inner.id,
            name: inner.name,
            name_draft: inner.name_draft,
            profile: inner.profile,
            profile_draft: inner.profile_draft,
            agents,
            external_services,
            creation_time: inner.creation_time,
        };
        Ok(Some((node, invalid_agents, invalid_external_services)))
    }

    /// Inserts a node entry, returns the `id` of the inserted node.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or if the hostname is already in use.
    pub fn put(&self, entry: &Node) -> Result<u32> {
        // Use optimistic transactions to atomically check hostname uniqueness and perform all writes
        // This ensures no race condition can occur between the check and insert
        'outer: loop {
            let txn = self.node.raw().db().transaction();

            // Check hostname uniqueness within the transaction
            if let Some(profile) = &entry.profile
                && self.is_hostname_in_use_transaction(&txn, &profile.hostname)?
            {
                bail!(
                    "Hostname '{}' is already in use by another node",
                    profile.hostname
                );
            }

            if let Some(profile_draft) = &entry.profile_draft
                && self.is_hostname_in_use_transaction(&txn, &profile_draft.hostname)?
            {
                bail!(
                    "Hostname '{}' is already in use by another node",
                    profile_draft.hostname
                );
            }

            // Create the inner node entry
            let inner = Inner {
                id: entry.id,
                name: entry.name.clone(),
                name_draft: entry.name_draft.clone(),
                profile: entry.profile.clone(),
                profile_draft: entry.profile_draft.clone(),
                creation_time: entry.creation_time,
                agents: entry.agents.iter().map(|a| a.key.clone()).collect(),
                external_services: entry
                    .external_services
                    .iter()
                    .map(|a| a.key.clone())
                    .collect(),
            };

            // Insert the node within the same transaction
            let node_id = match self.node.put_with_transaction(inner, &txn) {
                Ok(id) => id,
                Err(e) => {
                    if e.to_string().contains("Resource busy")
                        || e.to_string().contains("already exists")
                    {
                        continue 'outer;
                    }
                    return Err(e);
                }
            };

            // Insert agents within the same transaction
            for agent in &entry.agents {
                let mut agent = agent.clone();
                agent.node_id = node_id;
                if let Err(e) = self.agent.put_with_transaction(&agent, &txn) {
                    if e.to_string().contains("Resource busy")
                        || e.to_string().contains("already exists")
                    {
                        continue 'outer;
                    }
                    return Err(e);
                }
            }

            // Insert external services within the same transaction
            for external_service in &entry.external_services {
                let mut external_service = external_service.clone();
                external_service.node_id = node_id;
                if let Err(e) = self
                    .external_service
                    .put_with_transaction(&external_service, &txn)
                {
                    if e.to_string().contains("Resource busy")
                        || e.to_string().contains("already exists")
                    {
                        continue 'outer;
                    }
                    return Err(e);
                }
            }

            // Commit the entire transaction atomically
            match txn.commit() {
                Ok(()) => return Ok(node_id),
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to insert node and associated data");
                    }
                    // Transaction failed due to conflict, retry
                }
            }
        }
    }

    /// Removes a node with given `id`, with its agents, its external
    /// services and the records of its agents, detaching each agent's
    /// instance as [`Table::update`] does, returns `(key, invalid_agents,
    /// invalid_external_services)`.
    ///
    /// Everything is removed in one transaction, so a failure removes
    /// nothing, and the two lists of agents and external services that could
    /// not be removed are always empty.
    ///
    /// # Errors
    ///
    /// Returns an error if no node has the `id` or the database operation
    /// fails.
    pub fn remove(&self, id: u32) -> Result<(Vec<u8>, Vec<String>, Vec<String>)> {
        loop {
            let txn = self.node.raw().db().transaction();
            let inner: Inner = self
                .node
                .get_by_id_in_transaction(id, &txn)?
                .ok_or_else(|| anyhow::anyhow!("No such id"))?;
            for agent in &inner.agents {
                let mut key = id.to_be_bytes().to_vec();
                key.extend(agent.as_bytes());
                self.agent.delete_with_transaction(&key, &txn)?;
                self.remove_agent_records(&txn, id, agent)?;
            }
            for external_service in &inner.external_services {
                let mut key = id.to_be_bytes().to_vec();
                key.extend(external_service.as_bytes());
                self.external_service.delete_with_transaction(&key, &txn)?;
            }
            let key = self.node.remove_with_transaction(id, &txn)?;
            #[cfg(test)]
            self.run_before_commit_hook()?;
            match txn.commit() {
                Ok(()) => return Ok((key, Vec::new(), Vec::new())),
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to remove node");
                    }
                    // Transaction failed due to conflict, retry
                }
            }
        }
    }

    #[must_use]
    pub fn iter(&self, direction: Direction, from: Option<&[u8]>) -> TableIter<'_> {
        TableIter {
            node: self.node.iter(direction, from),
            agent: self.agent.clone(),
            external_service: self.external_service.clone(),
        }
    }

    /// Updates the `Node` from `old` to `new` using the specified `id`. The `id` is used for both
    /// the `Agent::node_id` and `ExternalService::node_id` fields, meaning those fields on each agent
    /// in both `old.agents` and `new.agents`, as well as each external service in both
    /// `old.external_services` and `new.external_services`, will be disregarded.
    ///
    /// All `Node`, `Agent`, and `ExternalService` writes execute inside a single optimistic
    /// transaction; either the entire update commits or no state change is observable.
    /// Returns the post-update `Node` constructed from the successfully-committed
    /// transaction attempt, with `creation_time` preserved from the existing record.
    ///
    /// Removing an agent removes its engine records — an Unsupervised Engine
    /// instance's document references, detector statuses and stopped state —
    /// in the same transaction, and detaches its instance there: the runs it
    /// performs, and a clone creating a definition on it, fail with the
    /// reason "instance removed", and its models and training definitions are
    /// left with no instance.
    ///
    /// An engine document is written only together with its references, by
    /// [`Table::update_with_engine_documents`]; this method refuses to change
    /// the `config`, `draft` or `kind` of an agent kept under one key in `old`
    /// and `new` when either side is [`AgentKind::Unsupervised`]. Adding or
    /// removing such an agent, or changing its install state, is accepted.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid, the database operation fails, or if the hostname is already in use.
    ///
    /// Returns an [`EngineDocumentError::RequiresEngineDocuments`] inside the
    /// error, and changes nothing, if the update changes an Unsupervised
    /// Engine agent's `config`, `draft` or `kind`.
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<Node> {
        refuse_engine_document_changes(old, new)?;
        self.update_in_transaction(id, old, new, &[])
    }

    /// Updates the `Node` from `old` to `new` as [`Table::update`] does, and
    /// writes, in the same optimistic transaction, the references of the
    /// engine documents of the node's Unsupervised Engine agents listed in
    /// `documents`.
    ///
    /// For each listed agent, a slot given as `Some` replaces the stored
    /// `applied` (the references of the agent's `config`) or `pending` (those
    /// of its `draft`) references, and the detector statuses of detector ids
    /// that appear in neither slot afterwards are dropped. An Unsupervised
    /// Engine agent kept from `old` whose `draft` changes has to be listed
    /// with `pending`, and one whose `config` changes with `applied`, so that
    /// a document never changes without its references.
    ///
    /// The models and indicators the written slots name, and the stored rows
    /// of the listed agents kept from `old`, are read within the transaction,
    /// so a concurrent removal of any of them, or a concurrent write of a
    /// listed agent's document, makes the update retry and check again.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if [`Table::update`] would fail
    /// for any reason other than the engine document changes it refuses, or
    /// if the database operation fails. Returns an [`EngineDocumentError`]
    /// inside the error, and changes nothing, if
    ///
    /// - an agent key is listed twice, or does not name an
    ///   [`AgentKind::Unsupervised`] agent of `new` on the node (for an agent
    ///   kept from `old`, of its stored row);
    /// - an agent kept under one key changes its kind to or from
    ///   [`AgentKind::Unsupervised`];
    /// - a written slot names a model that does not exist or whose instance
    ///   is not the listed agent, names a model twice, repeats a detector id,
    ///   or names an indicator that does not exist;
    /// - an Unsupervised Engine agent's `draft` or `config` changes without
    ///   the matching slot;
    /// - a written slot's document, the stored `config` for `applied` or the
    ///   stored `draft` for `pending` of an agent kept from `old`, is not the
    ///   one in `old`.
    pub fn update_with_engine_documents(
        &mut self,
        id: u32,
        old: &Update,
        new: &Update,
        documents: &[EngineDocumentWrite],
    ) -> Result<Node> {
        check_engine_documents(id, old, new, documents)?;
        self.update_in_transaction(id, old, new, documents)
    }

    /// Checks, within `txn`, what the documents to write rely on in the
    /// database: the stored row of each listed agent kept from `old`, and the
    /// models and indicators of each written slot.
    fn check_engine_documents_in_transaction(
        &self,
        txn: &rocksdb::Transaction<OptimisticTransactionDB>,
        id: u32,
        old: &Update,
        documents: &[EngineDocumentWrite],
    ) -> Result<()> {
        for document in documents {
            let agent_key = &document.agent_key;
            if let Some(old_agent) = old.agents.iter().find(|a| a.key == *agent_key) {
                let key = engine_instance::key(id, agent_key);
                let stored = txn
                    .get_for_update_cf(self.agent.raw().cf, &key, EXCLUSIVE)
                    .context("cannot read agent")?
                    .map(|value| Agent::from_key_value(&key, &value))
                    .transpose()?;
                let Some(stored) = stored.filter(|agent| agent.kind == AgentKind::Unsupervised)
                else {
                    return Err(EngineDocumentError::NotUnsupervisedAgent {
                        node_id: id,
                        agent_key: agent_key.clone(),
                    }
                    .into());
                };
                // The agent update below compares the stored row with `old`
                // only when the agent changes, so a document kept unchanged
                // would otherwise have its references replaced from a stale
                // `old`.
                if (document.applied.is_some() && stored.config != old_agent.config)
                    || (document.pending.is_some() && stored.draft != old_agent.draft)
                {
                    return Err(EngineDocumentError::StaleDocument {
                        agent_key: agent_key.clone(),
                    }
                    .into());
                }
            }
            let instance = ModelInstance {
                node_id: id,
                agent_key: agent_key.clone(),
            };
            for detector in written_detectors(document) {
                let Some(model) = self
                    .model
                    .load_model_by_name_in_transaction(&detector.model, txn)?
                else {
                    return Err(EngineDocumentError::ModelNotFound {
                        agent_key: agent_key.clone(),
                        model: detector.model.clone(),
                    }
                    .into());
                };
                if model.instance.as_ref() != Some(&instance) {
                    return Err(EngineDocumentError::ModelOfAnotherInstance {
                        agent_key: agent_key.clone(),
                        model: detector.model.clone(),
                    }
                    .into());
                }
                if let Some(indicator) = &detector.indicator
                    && txn
                        .get_for_update_cf(self.model_indicator.cf, indicator.as_bytes(), EXCLUSIVE)
                        .context("cannot read model indicator")?
                        .is_none()
                {
                    return Err(EngineDocumentError::IndicatorNotFound {
                        agent_key: agent_key.clone(),
                        indicator: indicator.clone(),
                    }
                    .into());
                }
            }
        }
        Ok(())
    }

    /// Writes, within `txn`, the references of each listed agent, dropping
    /// the statuses of detector ids neither slot has afterwards.
    fn write_engine_documents(
        &self,
        txn: &rocksdb::Transaction<OptimisticTransactionDB>,
        id: u32,
        documents: &[EngineDocumentWrite],
    ) -> Result<()> {
        for document in documents {
            let key = engine_instance::key(id, &document.agent_key);
            let mut row = self
                .engine_instances
                .get_for_update(txn, &key)?
                .unwrap_or_default();
            if let Some(applied) = &document.applied {
                row.applied.clone_from(applied);
            }
            if let Some(pending) = &document.pending {
                row.pending.clone_from(pending);
            }
            row.retain_named_statuses();
            self.engine_instances.put(txn, &key, &row)?;
        }
        Ok(())
    }

    /// Updates the node as [`Table::update`] describes, and writes
    /// `documents`, which [`check_engine_documents`] has accepted, in the
    /// same transaction.
    #[allow(clippy::too_many_lines)]
    fn update_in_transaction(
        &mut self,
        id: u32,
        old: &Update,
        new: &Update,
        documents: &[EngineDocumentWrite],
    ) -> Result<Node> {
        use crate::collections::Indexed;

        let old_inner = InnerUpdate {
            name: old.name.clone(),
            name_draft: old.name_draft.clone(),
            profile: old.profile.clone(),
            profile_draft: old.profile_draft.clone(),
            agents: old.agents.iter().map(|a| a.key.clone()).collect(),
            external_services: old
                .external_services
                .iter()
                .map(|a| a.key.clone())
                .collect(),
        };
        let new_inner = InnerUpdate {
            name: new.name.clone(),
            name_draft: new.name_draft.clone(),
            profile: new.profile.clone(),
            profile_draft: new.profile_draft.clone(),
            agents: new.agents.iter().map(|a| a.key.clone()).collect(),
            external_services: new
                .external_services
                .iter()
                .map(|a| a.key.clone())
                .collect(),
        };

        'outer: loop {
            let txn = self.node.raw().db().transaction();

            // Check hostname uniqueness within the transaction
            if let Some(new_profile) = &new.profile
                && self.is_hostname_in_use_except_transaction(&txn, &new_profile.hostname, id)?
            {
                bail!(
                    "Hostname '{}' is already in use by another node",
                    new_profile.hostname
                );
            }

            if let Some(new_profile_draft) = &new.profile_draft
                && self.is_hostname_in_use_except_transaction(
                    &txn,
                    &new_profile_draft.hostname,
                    id,
                )?
            {
                bail!(
                    "Hostname '{}' is already in use by another node",
                    new_profile_draft.hostname
                );
            }

            // Read the existing inner record under this transaction so the returned
            // Node observes the same snapshot that ultimately commits.
            let existing_inner: Inner = match self.node.get_by_id_in_transaction(id, &txn)? {
                Some(inner) => inner,
                None => bail!("no such id"),
            };

            self.check_engine_documents_in_transaction(&txn, id, old, documents)?;

            if let Err(e) = self
                .node
                .update_with_transaction(id, &old_inner, &new_inner, &txn)
            {
                if e.to_string().contains("Resource busy") {
                    continue 'outer;
                }
                return Err(e);
            }

            // Process Agent diffs within the same transaction
            let mut old_agents: HashMap<_, _> = old.agents.iter().map(|a| (&a.key, a)).collect();
            let mut new_agents: HashMap<_, _> = new.agents.iter().map(|a| (&a.key, a)).collect();

            for to_remove in old_agents.keys().filter(|k| !new_agents.contains_key(*k)) {
                let mut key = id.to_be_bytes().to_vec();
                key.extend(to_remove.as_bytes());
                if let Err(e) = self.agent.delete_with_transaction(&key, &txn) {
                    if e.to_string().contains("Resource busy") {
                        continue 'outer;
                    }
                    return Err(e);
                }
                self.remove_agent_records(&txn, id, to_remove)?;
            }
            old_agents.retain(|&k, _| new_agents.contains_key(k));

            for to_insert in new_agents
                .values()
                .filter(|v| !old_agents.contains_key(&v.key))
            {
                let mut to_insert: Agent = (*to_insert).clone();
                to_insert.node_id = id;
                if let Err(e) = self.agent.put_with_transaction(&to_insert, &txn) {
                    if e.to_string().contains("Resource busy") {
                        continue 'outer;
                    }
                    return Err(e);
                }
            }
            new_agents.retain(|&k, _| old_agents.contains_key(k));

            let mut old_agents_v: Vec<_> = old_agents.values().collect();
            old_agents_v.sort_unstable_by_key(|a| a.key.clone());
            let mut new_agents_v: Vec<_> = new_agents.values().collect();
            new_agents_v.sort_unstable_by_key(|a| a.key.clone());
            for (old_a, new_a) in old_agents_v
                .into_iter()
                .zip(new_agents_v)
                .filter(|(o, n)| **o != **n)
            {
                let mut old_a = (*old_a).clone();
                old_a.node_id = id;
                let mut new_a = (*new_a).clone();
                new_a.node_id = id;
                if let Err(e) = self.agent.update_with_transaction(&old_a, &new_a, &txn) {
                    if e.to_string().contains("Resource busy") {
                        continue 'outer;
                    }
                    return Err(e);
                }
            }

            // Process ExternalService diffs within the same transaction
            let mut old_external_services: HashMap<_, _> =
                old.external_services.iter().map(|a| (&a.key, a)).collect();
            let mut new_external_services: HashMap<_, _> =
                new.external_services.iter().map(|a| (&a.key, a)).collect();

            for to_remove in old_external_services
                .keys()
                .filter(|k| !new_external_services.contains_key(*k))
            {
                let mut key = id.to_be_bytes().to_vec();
                key.extend(to_remove.as_bytes());
                if let Err(e) = self.external_service.delete_with_transaction(&key, &txn) {
                    if e.to_string().contains("Resource busy") {
                        continue 'outer;
                    }
                    return Err(e);
                }
            }
            old_external_services.retain(|&k, _| new_external_services.contains_key(k));

            for to_insert in new_external_services
                .values()
                .filter(|v| !old_external_services.contains_key(&v.key))
            {
                let mut to_insert: ExternalService = (*to_insert).clone();
                to_insert.node_id = id;
                if let Err(e) = self.external_service.put_with_transaction(&to_insert, &txn) {
                    if e.to_string().contains("Resource busy") {
                        continue 'outer;
                    }
                    return Err(e);
                }
            }
            new_external_services.retain(|&k, _| old_external_services.contains_key(k));

            let mut old_es_v: Vec<_> = old_external_services.values().collect();
            old_es_v.sort_unstable_by_key(|a| a.key.clone());
            let mut new_es_v: Vec<_> = new_external_services.values().collect();
            new_es_v.sort_unstable_by_key(|a| a.key.clone());
            for (old_es, new_es) in old_es_v
                .into_iter()
                .zip(new_es_v)
                .filter(|(o, n)| **o != **n)
            {
                let mut old_es = (*old_es).clone();
                old_es.node_id = id;
                let mut new_es = (*new_es).clone();
                new_es.node_id = id;
                if let Err(e) = self
                    .external_service
                    .update_with_transaction(&old_es, &new_es, &txn)
                {
                    if e.to_string().contains("Resource busy") {
                        continue 'outer;
                    }
                    return Err(e);
                }
            }

            self.write_engine_documents(&txn, id, documents)?;

            #[cfg(test)]
            self.run_before_commit_hook()?;

            // Commit all writes atomically
            match txn.commit() {
                Ok(()) => {
                    // Build the post-update Node from this committed attempt's snapshot.
                    let final_name = new
                        .name
                        .clone()
                        .unwrap_or_else(|| existing_inner.name.clone());
                    let final_agents: Vec<Agent> = new
                        .agents
                        .iter()
                        .map(|a| {
                            let mut a = a.clone();
                            a.node_id = id;
                            a
                        })
                        .collect();
                    let final_external_services: Vec<ExternalService> = new
                        .external_services
                        .iter()
                        .map(|a| {
                            let mut a = a.clone();
                            a.node_id = id;
                            a
                        })
                        .collect();
                    return Ok(Node {
                        id,
                        name: final_name,
                        name_draft: new.name_draft.clone(),
                        profile: new.profile.clone(),
                        profile_draft: new.profile_draft.clone(),
                        agents: final_agents,
                        external_services: final_external_services,
                        creation_time: existing_inner.creation_time,
                    });
                }
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to update node");
                    }
                    // Transaction failed due to conflict, retry
                }
            }
        }
    }

    /// Updates the status of an agent specified by `agent_key`, which belongs to the node whose
    /// hostname matches the given `hostname`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - An error occurs while iterating over nodes.
    /// - No node exists with a profile matching the given `hostname`.
    /// - No agent exists with the given `agent_key`.
    /// - The database operation fails.
    pub fn update_agent_status_by_hostname(
        &mut self,
        hostname: &str,
        agent_key: &str,
        new_status: Status,
    ) -> Result<()> {
        let mut target_node = None;
        for result in self.iter(Direction::Forward, None) {
            let node = result.context("Failed to iterate over nodes")?;
            if node
                .profile
                .as_ref()
                .is_some_and(|p| p.hostname == hostname)
            {
                target_node = Some(node);
                break;
            }
        }
        let node =
            target_node.ok_or_else(|| anyhow::anyhow!("No node found for hostname: {hostname}"))?;

        let agent = node
            .agents
            .iter()
            .find(|agent| agent.key == agent_key)
            .ok_or_else(|| {
                anyhow::anyhow!("No agent found with key: {agent_key} for hostname: {hostname}")
            })?;
        let mut updated_agent = agent.clone();
        updated_agent.status = new_status;
        self.agent.update(agent, &updated_agent)
    }
}

/// Refuses, for [`Table::update`], a change of the `config`, `draft` or
/// `kind` of an agent kept under one key when either side is
/// [`AgentKind::Unsupervised`].
fn refuse_engine_document_changes(old: &Update, new: &Update) -> Result<()> {
    for (old_agent, new_agent) in kept_agents(old, new) {
        if (old_agent.kind == AgentKind::Unsupervised || new_agent.kind == AgentKind::Unsupervised)
            && (old_agent.kind != new_agent.kind
                || old_agent.config != new_agent.config
                || old_agent.draft != new_agent.draft)
        {
            return Err(EngineDocumentError::RequiresEngineDocuments {
                agent_key: new_agent.key.clone(),
            }
            .into());
        }
    }
    Ok(())
}

/// Checks, for [`Table::update_with_engine_documents`], what `documents`
/// require of `old` and `new` and of themselves.
fn check_engine_documents(
    id: u32,
    old: &Update,
    new: &Update,
    documents: &[EngineDocumentWrite],
) -> Result<()> {
    for (old_agent, new_agent) in kept_agents(old, new) {
        if old_agent.kind != new_agent.kind
            && (old_agent.kind == AgentKind::Unsupervised
                || new_agent.kind == AgentKind::Unsupervised)
        {
            return Err(EngineDocumentError::KindChanged {
                agent_key: new_agent.key.clone(),
            }
            .into());
        }
    }

    let mut listed = HashSet::new();
    for document in documents {
        let agent_key = &document.agent_key;
        if !listed.insert(agent_key.as_str()) {
            return Err(EngineDocumentError::DuplicateAgentKey {
                agent_key: agent_key.clone(),
            }
            .into());
        }
        if !new
            .agents
            .iter()
            .any(|a| a.key == *agent_key && a.kind == AgentKind::Unsupervised)
        {
            return Err(EngineDocumentError::NotUnsupervisedAgent {
                node_id: id,
                agent_key: agent_key.clone(),
            }
            .into());
        }
        for refs in [&document.applied, &document.pending].into_iter().flatten() {
            let mut models = HashSet::new();
            let mut detector_ids = HashSet::new();
            for detector in &refs.detectors {
                if !detector_ids.insert(detector.id) {
                    return Err(EngineDocumentError::DuplicateDetectorId {
                        agent_key: agent_key.clone(),
                        detector_id: detector.id,
                    }
                    .into());
                }
                if !models.insert(detector.model.as_str()) {
                    return Err(EngineDocumentError::DuplicateModel {
                        agent_key: agent_key.clone(),
                        model: detector.model.clone(),
                    }
                    .into());
                }
            }
        }
    }

    for (old_agent, new_agent) in kept_agents(old, new) {
        if new_agent.kind != AgentKind::Unsupervised {
            continue;
        }
        let document = documents.iter().find(|d| d.agent_key == new_agent.key);
        if old_agent.draft != new_agent.draft && document.is_none_or(|d| d.pending.is_none()) {
            return Err(EngineDocumentError::DraftWithoutReferences {
                agent_key: new_agent.key.clone(),
            }
            .into());
        }
        if old_agent.config != new_agent.config && document.is_none_or(|d| d.applied.is_none()) {
            return Err(EngineDocumentError::ConfigWithoutReferences {
                agent_key: new_agent.key.clone(),
            }
            .into());
        }
    }
    Ok(())
}

/// Returns the agents kept under one key in `old` and `new`, as `(old, new)`
/// pairs.
fn kept_agents<'a>(
    old: &'a Update,
    new: &'a Update,
) -> impl Iterator<Item = (&'a Agent, &'a Agent)> + 'a {
    new.agents.iter().filter_map(|new_agent| {
        old.agents
            .iter()
            .find(|a| a.key == new_agent.key)
            .map(|old_agent| (old_agent, new_agent))
    })
}

/// Returns the detectors of the slots `document` writes.
fn written_detectors(document: &EngineDocumentWrite) -> impl Iterator<Item = &EngineDetectorRef> {
    [&document.applied, &document.pending]
        .into_iter()
        .flatten()
        .flat_map(|refs| &refs.detectors)
}

pub struct TableIter<'d> {
    node: TI<'d, Inner>,
    agent: CrateTable<'d, Agent>,
    external_service: CrateTable<'d, ExternalService>,
}

impl Iterator for TableIter<'_> {
    type Item = Result<Node, anyhow::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.node.next().map(|res| {
            res.map(|inner| {
                let mut agents = vec![];
                for aid in inner.agents {
                    if let Ok(Some(agent)) = self.agent.get(inner.id, &aid) {
                        agents.push(agent);
                    }
                }

                let mut external_services = vec![];
                for es_id in inner.external_services {
                    if let Ok(Some(external_service)) = self.external_service.get(inner.id, &es_id)
                    {
                        external_services.push(external_service);
                    }
                }

                Node {
                    id: inner.id,
                    name: inner.name,
                    name_draft: inner.name_draft,
                    profile: inner.profile,
                    profile_draft: inner.profile_draft,
                    agents,
                    external_services,
                    creation_time: inner.creation_time,
                }
            })
        })
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Debug, Default)]
pub struct Profile {
    pub customer_id: u32,
    pub description: String,
    pub hostname: String,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Debug)]
pub(crate) struct Inner {
    pub id: u32,
    pub name: String,
    pub name_draft: Option<String>,
    pub profile: Option<Profile>,
    pub profile_draft: Option<Profile>,
    pub creation_time: DateTime<Utc>,
    pub agents: Vec<String>,
    pub external_services: Vec<String>,
}

impl FromKeyValue for Inner {
    fn from_key_value(_key: &[u8], value: &[u8]) -> anyhow::Result<Self> {
        super::deserialize(value)
    }
}

impl Indexable for Inner {
    fn key(&self) -> Cow<'_, [u8]> {
        Cow::from(self.name.as_bytes())
    }

    fn index(&self) -> u32 {
        self.id
    }

    fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
        key
    }

    fn value(&self) -> Vec<u8> {
        super::serialize(self).expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

/// Functions for the `node` indexed map.
impl IndexedTable<'_, Inner> {
    pub(crate) fn raw(&self) -> &IndexedMap<'_> {
        &self.indexed_map
    }
}

struct InnerUpdate {
    pub name: Option<String>,
    pub name_draft: Option<String>,
    pub profile: Option<Profile>,
    pub profile_draft: Option<Profile>,
    pub agents: Vec<String>,
    pub external_services: Vec<String>,
}

impl From<Inner> for InnerUpdate {
    fn from(input: Inner) -> InnerUpdate {
        Self {
            name: Some(input.name),
            name_draft: input.name_draft,
            profile: input.profile,
            profile_draft: input.profile_draft,
            agents: input.agents,
            external_services: input.external_services,
        }
    }
}

impl IndexedMapUpdate for InnerUpdate {
    type Entry = Inner;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        self.name.as_deref().map(|n| Cow::Borrowed(n.as_bytes()))
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        if let Some(n) = self.name.as_deref() {
            n.clone_into(&mut value.name);
        }
        value.name_draft.clone_from(&self.name_draft);
        value.profile.clone_from(&self.profile);
        value.profile_draft.clone_from(&self.profile_draft);
        value.agents.clone_from(&self.agents);
        value.external_services.clone_from(&self.external_services);
        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if let Some(n) = self.name.as_deref()
            && n != value.name
        {
            return false;
        }
        if self.name_draft != value.name_draft {
            return false;
        }
        if self.profile != value.profile {
            return false;
        }
        if self.profile_draft != value.profile_draft {
            return false;
        }
        if self.agents != value.agents {
            return false;
        }
        self.external_services == value.external_services
    }
}

#[cfg(test)]
mod test {
    use std::{
        net::{IpAddr, SocketAddr},
        sync::Arc,
    };

    use num_traits::ToPrimitive;

    use super::*;
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{AgentKind, ExternalServiceKind, Lifecycle, Store};

    type PortNumber = u16;

    #[allow(clippy::struct_excessive_bools)]
    #[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct Piglet {
        pub data_store_ip: Option<IpAddr>,
        pub data_store_port: Option<PortNumber>,
        pub save_packets: bool,
        pub http: bool,
        pub office: bool,
        pub exe: bool,
        pub pdf: bool,
        pub vbs: bool,
        pub txt: bool,
        pub smtp_eml: bool,
        pub ftp: bool,
    }

    #[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct Hog {
        pub data_store_ip: Option<IpAddr>,
        pub data_store_port: Option<PortNumber>,
        pub protocols: Option<Vec<String>>,

        pub sensors: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct DataStore {
        pub data_store_addr: SocketAddr,
        pub ack_transmission: u16,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TiContainer {
        pub ti_container_graphql_addr: SocketAddr,
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path(), None).unwrap());
        (permit, store)
    }

    fn create_node(
        id: u32,
        name: &str,
        name_draft: Option<&str>,
        profile: Option<Profile>,
        profile_draft: Option<Profile>,
        agents: Vec<Agent>,
        external_services: Vec<ExternalService>,
    ) -> Node {
        let creation_time = Utc::now();
        Node {
            id,
            name: name.to_string(),
            name_draft: name_draft.map(ToString::to_string),
            profile,
            profile_draft,
            agents,
            external_services,
            creation_time,
        }
    }

    fn create_agents(
        node_id: u32,
        kinds: &[AgentKind],
        configs: &[Option<Config>],
        drafts: &[Option<Config>],
    ) -> Vec<Agent> {
        kinds
            .iter()
            .zip(configs)
            .zip(drafts)
            .map(|((kind, config), draft)| Agent {
                node_id,
                key: kind.to_u32().unwrap().to_string(),
                kind: *kind,
                status: Status::Enabled,
                config: config.clone(),
                draft: draft.clone(),
                installed_version: None,
                installed_commit: None,
                lifecycle: Lifecycle::NotInstalled,
                bound_addrs: Vec::new(),
                instance: None,
            })
            .collect()
    }

    fn create_external_services(
        node_id: u32,
        kinds: &[ExternalServiceKind],
        drafts: &[Option<Config>],
    ) -> Vec<ExternalService> {
        kinds
            .iter()
            .zip(drafts)
            .map(|(kind, draft)| ExternalService {
                node_id,
                key: kind.to_u32().unwrap().to_string(),
                kind: *kind,
                status: Status::Enabled,
                draft: draft.clone(),
                installed_version: None,
                installed_commit: None,
                lifecycle: Lifecycle::NotInstalled,
                bound_addrs: Vec::new(),
                instance: None,
            })
            .collect()
    }

    fn create_agent_configs(kinds: &[AgentKind]) -> Vec<Option<Config>> {
        let ip = "127.0.0.1".parse::<IpAddr>().unwrap();
        let data_store_port = 1234;

        kinds
            .iter()
            .map(|kind| match kind {
                AgentKind::SemiSupervised => {
                    let config = Hog {
                        data_store_ip: Some(ip),
                        data_store_port: Some(data_store_port),
                        ..Default::default()
                    };
                    Some(toml::to_string(&config).unwrap().try_into().unwrap())
                }
                AgentKind::Sensor => {
                    let config = Piglet {
                        data_store_ip: Some(ip),
                        data_store_port: Some(data_store_port),
                        ..Default::default()
                    };
                    Some(toml::to_string(&config).unwrap().try_into().unwrap())
                }
                AgentKind::TimeSeriesGenerator
                | AgentKind::Unsupervised
                | AgentKind::LogCollector => Some(String::new().try_into().unwrap()),
            })
            .collect()
    }

    fn create_external_service_configs(kinds: &[ExternalServiceKind]) -> Vec<Option<Config>> {
        let ip = "127.0.0.1".parse::<IpAddr>().unwrap();
        let data_store_port = 1234;
        let ti_container_port = 4567;

        kinds
            .iter()
            .map(|kind| match kind {
                ExternalServiceKind::DataStore => {
                    let config = DataStore {
                        data_store_addr: SocketAddr::new(ip, data_store_port),
                        ack_transmission: 1000,
                    };
                    Some(toml::to_string(&config).unwrap().try_into().unwrap())
                }
                ExternalServiceKind::TiContainer => {
                    let config = TiContainer {
                        ti_container_graphql_addr: SocketAddr::new(ip, ti_container_port),
                    };
                    Some(toml::to_string(&config).unwrap().try_into().unwrap())
                }
            })
            .collect()
    }

    const FIXTURE_AGENT_CONFIG: &str = "enabled = true";
    const FIXTURE_AGENT_DRAFT: &str = "enabled = false";
    const FIXTURE_EXTERNAL_SERVICE_DRAFT: &str = "port = 8080";

    /// Builds a deterministic public `Node` for the serde baseline test.
    fn deterministic_node() -> Node {
        let creation_time = DateTime::parse_from_rfc3339("2000-02-29T12:34:56.123456789Z")
            .expect("valid RFC3339 timestamp")
            .with_timezone(&Utc);
        Node {
            id: 42,
            name: "fixture-node".to_string(),
            name_draft: Some("fixture-draft".to_string()),
            profile: Some(Profile {
                customer_id: 7,
                description: "fixture profile".to_string(),
                hostname: "fixture.example.com".to_string(),
            }),
            profile_draft: Some(Profile {
                customer_id: 8,
                description: "fixture profile draft".to_string(),
                hostname: "draft.fixture.example.com".to_string(),
            }),
            agents: vec![
                Agent::new(
                    42,
                    "1".to_string(),
                    AgentKind::Unsupervised,
                    Status::Enabled,
                    Some(FIXTURE_AGENT_CONFIG.to_string()),
                    None,
                )
                .expect("valid agent config"),
                Agent::new(
                    42,
                    "3".to_string(),
                    AgentKind::SemiSupervised,
                    Status::Enabled,
                    None,
                    Some(FIXTURE_AGENT_DRAFT.to_string()),
                )
                .expect("valid agent draft"),
            ],
            external_services: vec![
                ExternalService::new(
                    42,
                    "0".to_string(),
                    ExternalServiceKind::DataStore,
                    Status::Enabled,
                    None,
                )
                .expect("valid external service"),
                ExternalService::new(
                    42,
                    "1".to_string(),
                    ExternalServiceKind::TiContainer,
                    Status::Enabled,
                    Some(FIXTURE_EXTERNAL_SERVICE_DRAFT.to_string()),
                )
                .expect("valid external service draft"),
            ],
            creation_time,
        }
    }

    /// Builds a deterministic `Inner` for the literal-byte contract test.
    fn deterministic_node_inner() -> Inner {
        let creation_time = DateTime::parse_from_rfc3339("2000-02-29T12:34:56.123456789Z")
            .expect("valid RFC3339 timestamp")
            .with_timezone(&Utc);
        Inner {
            id: 42,
            name: "fixture-node".to_string(),
            name_draft: Some("fixture-draft".to_string()),
            profile: Some(Profile {
                customer_id: 7,
                description: "fixture profile".to_string(),
                hostname: "fixture.example.com".to_string(),
            }),
            profile_draft: Some(Profile {
                customer_id: 8,
                description: "fixture profile draft".to_string(),
                hostname: "draft.fixture.example.com".to_string(),
            }),
            creation_time,
            agents: vec!["1".to_string(), "3".to_string()],
            external_services: vec!["0".to_string(), "1".to_string()],
        }
    }

    /// Locks the on-disk bincode byte contract for the persisted `Inner` record.
    ///
    /// Expected bytes come from the committed literal fixture (not from the
    /// production serializer inside this test). `creation_time` is pinned to
    /// `2000-02-29T12:34:56.123456789Z` so the encoding stays deterministic.
    #[test]
    fn node_inner_literal_bytes_contract() -> Result<()> {
        const FIXTURE_BYTES: &[u8] = include_bytes!("../../tests/fixtures/node_inner_literal.bin");

        let decoded = Inner::from_key_value(b"fixture-node", FIXTURE_BYTES)?;
        let expected = deterministic_node_inner();
        assert_eq!(decoded, expected);

        let serialized = Indexable::value(&expected);
        assert_eq!(serialized.as_slice(), FIXTURE_BYTES);

        Ok(())
    }

    /// Locks the public `Node` serde contract separately from the persisted
    /// `Inner` record.
    ///
    /// Expected JSON comes from the committed literal fixture (not from the
    /// production serializer inside this test). `creation_time` is pinned to
    /// `2000-02-29T12:34:56.123456789Z` so the encoding stays deterministic.
    #[test]
    fn node_public_serde_baseline() -> Result<()> {
        const FIXTURE_JSON: &str = include_str!("../../tests/fixtures/node_public_serde.json");

        let expected = deterministic_node();
        let decoded: Node = serde_json::from_str(FIXTURE_JSON)?;
        assert_eq!(decoded, expected);

        let serialized = serde_json::to_string(&expected)?;
        assert_eq!(serialized, FIXTURE_JSON);

        Ok(())
    }

    #[test]
    fn node_creation() {
        let agent_kinds = vec![
            AgentKind::Unsupervised,
            AgentKind::Sensor,
            AgentKind::SemiSupervised,
            AgentKind::TimeSeriesGenerator,
        ];
        let agent_configs1 = create_agent_configs(&agent_kinds);
        let agent_configs2 = vec![None, None, None, None];
        let profile = Profile::default();
        let agents = create_agents(1, &agent_kinds, &agent_configs1, &agent_configs2);

        let external_service_kinds = vec![
            ExternalServiceKind::DataStore,
            ExternalServiceKind::TiContainer,
        ];
        let external_service_config = create_external_service_configs(&external_service_kinds);
        let external_services =
            create_external_services(1, &external_service_kinds, &external_service_config);

        let node = create_node(
            1,
            "test",
            None,
            Some(profile),
            None,
            agents,
            external_services,
        );
        assert_eq!(
            node.agents.into_iter().map(|a| a.key).collect::<Vec<_>>(),
            agent_kinds
                .into_iter()
                .map(|k| k.to_u32().unwrap().to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            node.external_services
                .into_iter()
                .map(|a| a.key)
                .collect::<Vec<_>>(),
            external_service_kinds
                .into_iter()
                .map(|k| k.to_u32().unwrap().to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn put_and_get() {
        let (_permit, store) = setup_store();

        let agent_kinds = vec![
            AgentKind::Unsupervised,
            AgentKind::Sensor,
            AgentKind::SemiSupervised,
        ];
        let agent_configs1: Vec<_> = create_agent_configs(&agent_kinds);
        let agent_configs2 = vec![None, None, None];
        let profile = Profile::default();
        let agents = create_agents(456, &agent_kinds, &agent_configs1, &agent_configs2);

        let external_service_kinds = vec![
            ExternalServiceKind::DataStore,
            ExternalServiceKind::TiContainer,
        ];
        let external_service_config = create_external_service_configs(&external_service_kinds);
        let external_services =
            create_external_services(456, &external_service_kinds, &external_service_config);

        let mut node = create_node(
            123,
            "test",
            None,
            Some(profile),
            None,
            agents,
            external_services,
        );
        let node_table = store.node_map();
        assert_eq!(node_table.count().unwrap(), 0);
        let res = node_table.put(&node);
        assert!(res.is_ok());

        // update node id to the actual id in database.
        node.id = res.unwrap();
        node.agents.iter_mut().for_each(|a| a.node_id = node.id);
        node.external_services
            .iter_mut()
            .for_each(|a| a.node_id = node.id);

        let res = node_table.get_by_id(node.id).unwrap();
        assert!(res.is_some());

        let (returned, invalid_agents, invalid_external_services) = res.unwrap();
        assert_eq!(invalid_agents, Vec::<String>::new());
        assert_eq!(invalid_external_services, Vec::<String>::new());
        assert_eq!(returned, node);
    }

    /// `NodeTable` writes its own `Iterable` implementation over an
    /// `IndexedTable<Inner>`, so it is the one iteration route that is neither
    /// the blanket `Table` implementation nor a table-specific inherent
    /// iterator, and it composes each `Node` from three column families. Its
    /// inherent `iter` shadows the trait method under method syntax, so that
    /// half is called through UFCS to keep the trait route the thing under
    /// test.
    #[test]
    fn generic_iteration_yields_every_stored_node() {
        let (_permit, store) = setup_store();

        let agent_kinds = vec![AgentKind::Sensor];
        let agent_configs = create_agent_configs(&agent_kinds);
        let external_service_kinds = vec![ExternalServiceKind::DataStore];
        let external_service_configs = create_external_service_configs(&external_service_kinds);

        let node_table = store.node_map();
        let mut names = vec![];
        for name in ["node-a", "node-b"] {
            // Two nodes cannot share a hostname, so each carries its own.
            let profile = Profile {
                hostname: format!("{name}.example.com"),
                ..Profile::default()
            };
            let node = create_node(
                0,
                name,
                None,
                Some(profile),
                None,
                create_agents(0, &agent_kinds, &agent_configs, &[None]),
                create_external_services(0, &external_service_kinds, &external_service_configs),
            );
            node_table.put(&node).unwrap();
            names.push(name.to_string());
        }

        for iterated in [
            Iterable::iter(&node_table, Direction::Forward, None)
                .collect::<Result<Vec<_>>>()
                .unwrap(),
            node_table
                .prefix_iter(Direction::Forward, None, b"")
                .collect::<Result<Vec<_>>>()
                .unwrap(),
        ] {
            let mut read: Vec<_> = iterated
                .iter()
                .map(|node| node.name.clone())
                .collect::<Vec<_>>();
            read.sort_unstable();
            assert_eq!(read, names);
            // The agent and the external service come from their own column
            // families, so an empty one would mean the composition was skipped.
            for node in &iterated {
                assert_eq!(node.agents.len(), 1);
                assert_eq!(node.external_services.len(), 1);
            }
        }
    }

    #[test]
    fn remove() {
        let (_permit, store) = setup_store();

        let agent_kinds = vec![
            AgentKind::Unsupervised,
            AgentKind::Sensor,
            AgentKind::SemiSupervised,
        ];
        let agent_configs1: Vec<_> = create_agent_configs(&agent_kinds);
        let agent_configs2 = vec![None, None, None];
        let profile = Profile::default();
        let agents = create_agents(1, &agent_kinds, &agent_configs1, &agent_configs2);

        let external_service_kinds = vec![
            ExternalServiceKind::DataStore,
            ExternalServiceKind::TiContainer,
        ];
        let external_service_config = create_external_service_configs(&external_service_kinds);
        let external_services =
            create_external_services(1, &external_service_kinds, &external_service_config);

        let mut node = create_node(
            1,
            "test",
            None,
            None,
            Some(profile),
            agents,
            external_services,
        );

        let node_table = store.node_map();
        assert_eq!(node_table.count().unwrap(), 0);
        assert_eq!(store.agents_map().iter(Direction::Forward, None).count(), 0);
        assert_eq!(
            store
                .external_service_map()
                .iter(Direction::Forward, None)
                .count(),
            0
        );
        let res = node_table.put(&node);
        assert!(res.is_ok());

        // update node id to the actual id in database.
        node.id = res.unwrap();
        node.agents.iter_mut().for_each(|a| a.node_id = node.id);
        node.external_services
            .iter_mut()
            .for_each(|a| a.node_id = node.id);

        assert_eq!(node_table.count().unwrap(), 1);
        assert_eq!(store.agents_map().iter(Direction::Forward, None).count(), 3);
        assert_eq!(
            store
                .external_service_map()
                .iter(Direction::Forward, None)
                .count(),
            2
        );

        assert!(node_table.remove(node.id).is_ok());
        let res = node_table.get_by_id(node.id).unwrap();
        assert!(res.is_none());

        assert_eq!(store.agents_map().iter(Direction::Forward, None).count(), 0);
        assert_eq!(
            store
                .external_service_map()
                .iter(Direction::Forward, None)
                .count(),
            0
        );
    }

    #[test]
    fn update() {
        let (_permit, store) = setup_store();

        let agent_kinds = vec![
            AgentKind::Unsupervised,
            AgentKind::Sensor,
            AgentKind::SemiSupervised,
        ];
        let agent_configs1: Vec<_> = create_agent_configs(&agent_kinds);
        let agent_configs2 = vec![None, None, None];
        let profile = Profile::default();
        let agents = create_agents(123, &agent_kinds, &agent_configs1, &agent_configs2);

        let external_service_kinds = vec![
            ExternalServiceKind::DataStore,
            ExternalServiceKind::TiContainer,
        ];
        let external_service_config = create_external_service_configs(&external_service_kinds);
        let external_services =
            create_external_services(123, &external_service_kinds, &external_service_config);

        let mut node = create_node(
            456,
            "test",
            None,
            None,
            Some(profile.clone()),
            agents.clone(),
            external_services.clone(),
        );
        let mut node_table = store.node_map();

        let res = node_table.put(&node);
        assert!(res.is_ok());

        // update node id to the actual id in database.
        node.id = res.unwrap();
        node.agents.iter_mut().for_each(|a| a.node_id = node.id);
        node.external_services
            .iter_mut()
            .for_each(|a| a.node_id = node.id);

        let id = node.id;

        let update = Update {
            name: Some("test".to_string()),
            name_draft: Some("update".to_string()),
            profile: Some(profile.clone()),
            profile_draft: Some(profile.clone()),
            agents: agents[1..].to_vec(),
            external_services: external_services[1..].to_vec(),
        };
        let old = node.clone().into();

        let returned = node_table.update(id, &old, &update).unwrap();

        let updated = node_table.get_by_id(id).unwrap();
        assert!(updated.is_some());
        let (updated, invalid_agents, invalid_external_services) = updated.unwrap();

        assert_eq!(invalid_agents, Vec::<String>::new());
        assert_eq!(invalid_external_services, Vec::<String>::new());

        node.name_draft = Some("update".to_string());
        node.profile = Some(profile.clone());
        node.profile_draft = Some(profile.clone());
        node.agents = node.agents.into_iter().skip(1).collect();
        node.external_services = node.external_services.into_iter().skip(1).collect();

        assert_eq!(updated, node);
        assert_eq!(returned, node);
    }

    #[test]
    fn update_agents_drafts_only() {
        let (_permit, store) = setup_store();

        let agent_kinds = vec![AgentKind::Unsupervised, AgentKind::SemiSupervised];
        let agent_configs1: Vec<_> = create_agent_configs(&agent_kinds);
        let agent_configs2 = vec![None, None, None];
        let profile = Profile::default();
        let agents = create_agents(123, &agent_kinds, &agent_configs1, &agent_configs2);

        let external_service_kinds = vec![
            ExternalServiceKind::DataStore,
            ExternalServiceKind::TiContainer,
        ];
        let external_service_config = create_external_service_configs(&external_service_kinds);
        let external_services =
            create_external_services(123, &external_service_kinds, &external_service_config);

        let mut node = create_node(
            456,
            "test",
            None,
            None,
            Some(profile.clone()),
            agents.clone(),
            external_services.clone(),
        );

        let mut node_table = store.node_map();

        let res = node_table.put(&node);
        assert!(res.is_ok());

        // update node id to the actual id in database.
        node.id = res.unwrap();
        node.agents.iter_mut().for_each(|a| a.node_id = node.id);
        node.external_services
            .iter_mut()
            .for_each(|a| a.node_id = node.id);

        let id = node.id;

        let old = node.clone().into();
        let mut update = node.clone();
        let mut update_agents: Vec<_> = update
            .agents
            .into_iter()
            .skip(1) // remove Reconverge
            .map(|mut a| {
                // update draft of Hog
                a.draft = Some("my_key=10".to_string().try_into().unwrap());
                a
            })
            .collect();
        update_agents.extend(create_agents(
            id,
            &[AgentKind::Sensor],
            &[Some(
                toml::to_string(&Piglet::default())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )],
            &[Some("my_key=10".to_string().try_into().unwrap())],
        )); // Add Piglet
        update.agents = update_agents;

        let update = update.into();
        assert!(node_table.update(id, &old, &update).is_ok());

        let updated = node_table.get_by_id(id).unwrap();
        assert!(updated.is_some());
        let (updated, invalid_agents, invalid_external_services) = updated.unwrap();
        assert_eq!(invalid_agents, Vec::<String>::new());
        assert_eq!(invalid_external_services, Vec::<String>::new());

        assert_eq!(updated.agents, update.agents);
    }

    #[test]
    fn update_agent_status_by_hostname() {
        let (_permit, store) = setup_store();
        let kinds = vec![AgentKind::Sensor, AgentKind::SemiSupervised];
        let configs: Vec<_> = create_agent_configs(&kinds);

        let profile = Profile {
            hostname: "test-hostname".to_string(),
            ..Default::default()
        };

        let agents = create_agents(456, &kinds, &configs, &configs);

        let mut node = create_node(
            456,
            "test",
            Some("test"),
            Some(profile.clone()),
            Some(profile.clone()),
            agents.clone(),
            vec![],
        );

        let mut node_table = store.node_map();

        let res = node_table.put(&node);
        assert!(res.is_ok());

        node.id = res.unwrap();
        node.agents.iter_mut().for_each(|a| a.node_id = node.id);

        let id = node.id;

        assert!(
            node_table
                .update_agent_status_by_hostname(
                    "test-hostname",
                    "3", // The agent key of `AgentKind::SemiSupervised` was set to "3" in `create_agents`.
                    Status::Disabled
                )
                .is_ok()
        );

        let updated = node_table.get_by_id(id).unwrap();
        assert!(updated.is_some());
        let (updated, invalid, _) = updated.unwrap();
        assert_eq!(invalid, Vec::<String>::new());

        // Check that the status of the `AgentKind::Sensor` agent was not updated.
        assert_eq!(updated.agents[0].status, Status::Enabled);

        // Check that the status of the `AgentKind::SemiSupervised` agent was updated.
        assert_eq!(updated.agents[1].status, Status::Disabled);
    }

    /// Writing a status must not disturb the install state stored beside it, and
    /// the read that returns the new status must return the lifecycle with it.
    ///
    /// `update_agent_status_by_hostname` is the crate's only status-only write
    /// path, so it is the one place where a record rebuilt from a status instead
    /// of read back whole would silently reset the four install fields.
    #[test]
    fn update_agent_status_by_hostname_preserves_install_state() {
        let (_permit, store) = setup_store();
        let kinds = vec![AgentKind::Sensor, AgentKind::SemiSupervised];
        let configs: Vec<_> = create_agent_configs(&kinds);

        let profile = Profile {
            hostname: "test-hostname".to_string(),
            ..Default::default()
        };

        let mut agents = create_agents(456, &kinds, &configs, &configs);
        let target = agents.get_mut(1).expect("two agents");
        target.installed_version = Some("1.2.3".to_string());
        target.installed_commit = Some("deadbeef".to_string());
        target.lifecycle = Lifecycle::Running;
        target.bound_addrs = vec![("addr".to_string(), "127.0.0.1:1111".to_string())];

        let mut node = create_node(
            456,
            "test",
            Some("test"),
            Some(profile.clone()),
            Some(profile),
            agents,
            vec![],
        );

        let mut node_table = store.node_map();
        let id = node_table.put(&node).unwrap();
        node.id = id;
        node.agents.iter_mut().for_each(|a| a.node_id = id);

        node_table
            .update_agent_status_by_hostname("test-hostname", "3", Status::Disabled)
            .unwrap();

        let (updated, invalid_agents, invalid_external_services) =
            node_table.get_by_id(id).unwrap().unwrap();
        assert_eq!(invalid_agents, Vec::<String>::new());
        assert_eq!(invalid_external_services, Vec::<String>::new());

        // One read returns the new status and the untouched lifecycle together.
        let updated_agent = updated.agents.get(1).expect("two agents");
        assert_eq!(updated_agent.status, Status::Disabled);
        assert_eq!(updated_agent.lifecycle, Lifecycle::Running);
        assert_eq!(updated_agent.installed_version.as_deref(), Some("1.2.3"));
        assert_eq!(updated_agent.installed_commit.as_deref(), Some("deadbeef"));
        assert_eq!(
            updated_agent.bound_addrs,
            vec![("addr".to_string(), "127.0.0.1:1111".to_string())]
        );

        // The agent that was not targeted is untouched in both fields.
        let untouched = updated.agents.first().expect("two agents");
        assert_eq!(untouched.status, Status::Enabled);
        assert_eq!(untouched.lifecycle, Lifecycle::NotInstalled);
    }

    #[test]
    fn hostname_uniqueness_on_put() {
        let (_permit, store) = setup_store();
        let node_table = store.node_map();

        let profile1 = Profile {
            customer_id: 1,
            description: "Customer 1 Node".to_string(),
            hostname: "unique-hostname".to_string(),
        };

        let profile2 = Profile {
            customer_id: 2,
            description: "Customer 2 Node".to_string(),
            hostname: "unique-hostname".to_string(), // Same hostname as profile1
        };

        let node1 = create_node(0, "node1", None, Some(profile1), None, vec![], vec![]);
        let node2 = create_node(0, "node2", None, Some(profile2), None, vec![], vec![]);

        // First node should succeed
        let result1 = node_table.put(&node1);
        assert!(result1.is_ok());

        // Second node with same hostname should fail
        let result2 = node_table.put(&node2);
        assert!(result2.is_err());
        assert!(
            result2
                .unwrap_err()
                .to_string()
                .contains("Hostname 'unique-hostname' is already in use")
        );
    }

    #[test]
    fn hostname_uniqueness_on_put_with_draft() {
        let (_permit, store) = setup_store();
        let node_table = store.node_map();

        let profile = Profile {
            customer_id: 1,
            description: "Node with profile".to_string(),
            hostname: "hostname-in-use".to_string(),
        };

        let draft_profile = Profile {
            customer_id: 2,
            description: "Node with draft".to_string(),
            hostname: "hostname-in-use".to_string(), // Same hostname as profile
        };

        let node1 = create_node(0, "node1", None, Some(profile), None, vec![], vec![]);
        let node2 = create_node(0, "node2", None, None, Some(draft_profile), vec![], vec![]);

        // First node should succeed
        let result1 = node_table.put(&node1);
        assert!(result1.is_ok());

        // Second node with same hostname in draft should fail
        let result2 = node_table.put(&node2);
        assert!(result2.is_err());
        assert!(
            result2
                .unwrap_err()
                .to_string()
                .contains("Hostname 'hostname-in-use' is already in use")
        );
    }

    #[test]
    fn hostname_uniqueness_on_update() {
        let (_permit, store) = setup_store();
        let mut node_table = store.node_map();

        let profile1 = Profile {
            customer_id: 1,
            description: "Node 1".to_string(),
            hostname: "hostname1".to_string(),
        };

        let profile2 = Profile {
            customer_id: 2,
            description: "Node 2".to_string(),
            hostname: "hostname2".to_string(),
        };

        let node1 = create_node(
            0,
            "node1",
            None,
            Some(profile1.clone()),
            None,
            vec![],
            vec![],
        );
        let node2 = create_node(0, "node2", None, Some(profile2), None, vec![], vec![]);

        let _id1 = node_table.put(&node1).unwrap();
        let id2 = node_table.put(&node2).unwrap();

        // Try to update node2 to use the same hostname as node1
        let old = Update {
            name: Some("node2".to_string()),
            name_draft: None,
            profile: Some(Profile {
                customer_id: 2,
                description: "Node 2".to_string(),
                hostname: "hostname2".to_string(),
            }),
            profile_draft: None,
            agents: vec![],
            external_services: vec![],
        };

        let new = Update {
            name: Some("node2".to_string()),
            name_draft: None,
            profile: Some(Profile {
                customer_id: 2,
                description: "Node 2".to_string(),
                hostname: "hostname1".to_string(), // Trying to use hostname1
            }),
            profile_draft: None,
            agents: vec![],
            external_services: vec![],
        };

        // Update should fail due to hostname conflict
        let result = node_table.update(id2, &old, &new);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Hostname 'hostname1' is already in use")
        );
    }

    #[test]
    fn hostname_uniqueness_allows_same_node_update() {
        let (_permit, store) = setup_store();
        let mut node_table = store.node_map();

        let profile = Profile {
            customer_id: 1,
            description: "Node 1".to_string(),
            hostname: "hostname1".to_string(),
        };

        let node = create_node(
            0,
            "node1",
            None,
            Some(profile.clone()),
            None,
            vec![],
            vec![],
        );
        let id = node_table.put(&node).unwrap();

        // Update the same node with the same hostname should succeed
        let old = Update {
            name: Some("node1".to_string()),
            name_draft: None,
            profile: Some(profile.clone()),
            profile_draft: None,
            agents: vec![],
            external_services: vec![],
        };

        let new = Update {
            name: Some("node1".to_string()),
            name_draft: Some("updated-node1".to_string()),
            profile: Some(profile), // Same hostname
            profile_draft: None,
            agents: vec![],
            external_services: vec![],
        };

        // Update should succeed since it's the same node
        let result = node_table.update(id, &old, &new);
        assert!(result.is_ok());
    }

    #[test]
    fn hostname_uniqueness_different_hostnames_allowed() {
        let (_permit, store) = setup_store();
        let node_table = store.node_map();

        let profile1 = Profile {
            customer_id: 1,
            description: "Customer 1 Node".to_string(),
            hostname: "hostname1".to_string(),
        };

        let profile2 = Profile {
            customer_id: 2,
            description: "Customer 2 Node".to_string(),
            hostname: "hostname2".to_string(), // Different hostname
        };

        let node1 = create_node(0, "node1", None, Some(profile1), None, vec![], vec![]);
        let node2 = create_node(0, "node2", None, Some(profile2), None, vec![], vec![]);

        // Both nodes should succeed as they have different hostnames
        let result1 = node_table.put(&node1);
        assert!(result1.is_ok());

        let result2 = node_table.put(&node2);
        assert!(result2.is_ok());
    }

    #[test]
    fn update_external_services_draft() {
        let (_permit, store) = setup_store();

        let agent_kinds = vec![AgentKind::Unsupervised, AgentKind::SemiSupervised];
        let agent_configs1: Vec<_> = create_agent_configs(&agent_kinds);
        let agent_configs2 = vec![None, None, None];
        let profile = Profile::default();
        let agents = create_agents(123, &agent_kinds, &agent_configs1, &agent_configs2);

        let external_service_kinds = vec![
            ExternalServiceKind::DataStore,
            ExternalServiceKind::TiContainer,
        ];
        let external_service_config = create_external_service_configs(&external_service_kinds);
        let external_services =
            create_external_services(123, &external_service_kinds, &external_service_config);

        let mut node = create_node(
            456,
            "test",
            None,
            None,
            Some(profile.clone()),
            agents.clone(),
            external_services.clone(),
        );

        let mut node_table = store.node_map();

        let res = node_table.put(&node);
        assert!(res.is_ok());

        // update node id to the actual id in database.
        node.id = res.unwrap();
        node.agents.iter_mut().for_each(|a| a.node_id = node.id);
        node.external_services
            .iter_mut()
            .for_each(|a| a.node_id = node.id);

        let id = node.id;

        let old = node.clone().into();
        let mut update = node.clone();
        let update_external_services: Vec<_> = update
            .external_services
            .into_iter()
            .skip(1) // remove Reconverge
            .map(|mut a| {
                // update draft of ti container
                a.draft = Some("my_key=10".to_string().try_into().unwrap());
                a
            })
            .collect();
        update.external_services = update_external_services;

        let update = update.into();
        assert!(node_table.update(id, &old, &update).is_ok());

        let updated = node_table.get_by_id(id).unwrap();
        assert!(updated.is_some());
        let (updated, invalid_agents, invalid_external_services) = updated.unwrap();
        assert_eq!(invalid_agents, Vec::<String>::new());
        assert_eq!(invalid_external_services, Vec::<String>::new());

        assert_eq!(updated.external_services, update.external_services);
    }

    /// The install state written on an agent and on an external service must
    /// survive `Node::update`'s single atomic diff, which compares whole
    /// records, and must not disturb `config` or `draft`.
    #[test]
    fn update_install_state_on_agents_and_external_services() {
        let (_permit, store) = setup_store();

        let agent_kinds = vec![AgentKind::Unsupervised, AgentKind::SemiSupervised];
        let agent_configs = create_agent_configs(&agent_kinds);
        let agent_drafts = vec![None, None];
        let agents = create_agents(0, &agent_kinds, &agent_configs, &agent_drafts);

        let external_service_kinds = vec![ExternalServiceKind::DataStore];
        let external_service_drafts = create_external_service_configs(&external_service_kinds);
        let external_services =
            create_external_services(0, &external_service_kinds, &external_service_drafts);

        let mut node = create_node(
            0,
            "test",
            None,
            Some(Profile::default()),
            None,
            agents,
            external_services,
        );

        let mut node_table = store.node_map();
        let id = node_table.put(&node).unwrap();
        node.id = id;
        node.agents.iter_mut().for_each(|a| a.node_id = id);
        node.external_services
            .iter_mut()
            .for_each(|e| e.node_id = id);

        let old: Update = node.clone().into();

        let mut new_node = node.clone();
        let agent = new_node.agents.get_mut(1).expect("two agents");
        agent.installed_version = Some("1.2.3".to_string());
        agent.installed_commit = Some("f0f0f0f".to_string());
        agent.lifecycle = Lifecycle::Running;
        agent.status = Status::ReloadFailed;
        // Agents bind no service address in practice, but the diff must carry
        // whatever is on the record rather than assuming the field is empty.
        agent.bound_addrs = vec![("addr".to_string(), "127.0.0.1:1111".to_string())];
        let external_service = new_node
            .external_services
            .first_mut()
            .expect("one external service");
        external_service.installed_version = Some("0.9.0-alpha".to_string());
        external_service.installed_commit = Some("abcdef1".to_string());
        external_service.lifecycle = Lifecycle::Failed;
        external_service.bound_addrs = vec![
            ("ingest_srv_addr".to_string(), "10.0.0.1:38370".to_string()),
            ("publish_srv_addr".to_string(), "10.0.0.1:38371".to_string()),
        ];
        let new: Update = new_node.clone().into();

        let returned = node_table.update(id, &old, &new).unwrap();
        assert_eq!(returned.agents, new_node.agents);
        assert_eq!(returned.external_services, new_node.external_services);

        // A single read returns `status` and `lifecycle` together.
        let (updated, invalid_agents, invalid_external_services) =
            node_table.get_by_id(id).unwrap().unwrap();
        assert_eq!(invalid_agents, Vec::<String>::new());
        assert_eq!(invalid_external_services, Vec::<String>::new());

        let updated_agent = updated.agents.get(1).expect("two agents");
        assert_eq!(updated_agent.installed_version.as_deref(), Some("1.2.3"));
        assert_eq!(updated_agent.installed_commit.as_deref(), Some("f0f0f0f"));
        assert_eq!(updated_agent.lifecycle, Lifecycle::Running);
        assert_eq!(updated_agent.status, Status::ReloadFailed);
        assert_eq!(
            updated_agent.bound_addrs,
            vec![("addr".to_string(), "127.0.0.1:1111".to_string())]
        );
        assert_eq!(updated_agent.config, node.agents.get(1).unwrap().config);
        assert_eq!(updated_agent.draft, node.agents.get(1).unwrap().draft);

        // The untouched agent keeps the values it was registered with.
        let untouched_agent = updated.agents.first().expect("two agents");
        assert_eq!(untouched_agent.installed_version, None);
        assert_eq!(untouched_agent.installed_commit, None);
        assert_eq!(untouched_agent.lifecycle, Lifecycle::NotInstalled);
        assert_eq!(untouched_agent.bound_addrs, Vec::<(String, String)>::new());

        let updated_external_service = updated
            .external_services
            .first()
            .expect("one external service");
        assert_eq!(
            updated_external_service.installed_version.as_deref(),
            Some("0.9.0-alpha")
        );
        assert_eq!(
            updated_external_service.installed_commit.as_deref(),
            Some("abcdef1")
        );
        assert_eq!(updated_external_service.lifecycle, Lifecycle::Failed);
        assert_eq!(
            updated_external_service.bound_addrs,
            vec![
                ("ingest_srv_addr".to_string(), "10.0.0.1:38370".to_string()),
                ("publish_srv_addr".to_string(), "10.0.0.1:38371".to_string()),
            ]
        );
        assert_eq!(
            updated_external_service.draft,
            node.external_services.first().unwrap().draft
        );
    }

    /// Returns `value` with the byte encoding the lifecycle replaced by
    /// `number`.
    ///
    /// The byte is located by comparing `value` against the same record
    /// serialized under a different lifecycle, so the forgery does not hard-code
    /// the layout of the private persisted struct.
    fn forge_lifecycle_byte(value: &[u8], other: &[u8], number: u8) -> Vec<u8> {
        let position = value
            .iter()
            .zip(other)
            .position(|(a, b)| a != b)
            .expect("the two records differ in the lifecycle byte");
        let mut forged = value.to_vec();
        *forged.get_mut(position).expect("position is in bounds") = number;
        forged
    }

    /// A node read must still return an agent and an external service whose
    /// stored lifecycle number this build does not recognize.
    ///
    /// `get_by_id` propagates a failed record deserialization, so storing the
    /// lifecycle as a `Lifecycle` instead of a raw index would not merely lose
    /// the field: a single row written by a newer build would fail the whole
    /// node read. `TableIter` is worse still — it drops such a record silently,
    /// so the instance would vanish from the node it belongs to.
    #[test]
    fn node_read_survives_an_unknown_lifecycle_number() {
        use crate::tables::Value as ValueTrait;

        let (_permit, store) = setup_store();

        let agent_kinds = vec![AgentKind::Unsupervised];
        let agent_configs = create_agent_configs(&agent_kinds);
        let agents = create_agents(0, &agent_kinds, &agent_configs, &agent_configs);

        let external_service_kinds = vec![ExternalServiceKind::DataStore];
        let external_service_drafts = create_external_service_configs(&external_service_kinds);
        let external_services =
            create_external_services(0, &external_service_kinds, &external_service_drafts);

        let mut node = create_node(
            0,
            "test",
            None,
            Some(Profile::default()),
            None,
            agents,
            external_services,
        );

        let node_table = store.node_map();
        let id = node_table.put(&node).unwrap();
        node.id = id;
        node.agents.iter_mut().for_each(|a| a.node_id = id);
        node.external_services
            .iter_mut()
            .for_each(|e| e.node_id = id);

        let agent = node.agents.first().expect("one agent").clone();
        let mut relabelled_agent = agent.clone();
        relabelled_agent.lifecycle = Lifecycle::Removing;
        let agent_table = store.agents_map();
        agent_table
            .raw()
            .put(
                &agent.unique_key(),
                &forge_lifecycle_byte(&agent.value(), &relabelled_agent.value(), 9),
            )
            .unwrap();

        let external_service = node
            .external_services
            .first()
            .expect("one external service")
            .clone();
        let mut relabelled_external_service = external_service.clone();
        relabelled_external_service.lifecycle = Lifecycle::Removing;
        let external_service_table = store.external_service_map();
        external_service_table
            .raw()
            .put(
                &external_service.unique_key(),
                &forge_lifecycle_byte(
                    &external_service.value(),
                    &relabelled_external_service.value(),
                    9,
                ),
            )
            .unwrap();

        let (read, invalid_agents, invalid_external_services) =
            node_table.get_by_id(id).unwrap().unwrap();
        assert_eq!(invalid_agents, Vec::<String>::new());
        assert_eq!(invalid_external_services, Vec::<String>::new());

        let read_agent = read.agents.first().expect("one agent");
        assert_eq!(read_agent.lifecycle, Lifecycle::Unknown);
        assert_ne!(read_agent.lifecycle, Lifecycle::NotInstalled);
        assert_eq!(read_agent.key, agent.key);
        assert_eq!(read_agent.kind, agent.kind);
        assert_eq!(read_agent.status, agent.status);
        assert_eq!(read_agent.config, agent.config);
        assert_eq!(read_agent.draft, agent.draft);

        let read_external_service = read
            .external_services
            .first()
            .expect("one external service");
        assert_eq!(read_external_service.lifecycle, Lifecycle::Unknown);
        assert_ne!(read_external_service.lifecycle, Lifecycle::NotInstalled);
        assert_eq!(read_external_service.key, external_service.key);
        assert_eq!(read_external_service.kind, external_service.kind);
        assert_eq!(read_external_service.status, external_service.status);
        assert_eq!(read_external_service.draft, external_service.draft);
    }

    #[test]
    fn update_returns_node_with_added_agent() {
        let (_permit, store) = setup_store();

        let initial_kinds = vec![AgentKind::Unsupervised];
        let initial_configs = create_agent_configs(&initial_kinds);
        let initial_drafts = vec![None];
        let profile = Profile::default();
        let agents = create_agents(0, &initial_kinds, &initial_configs, &initial_drafts);

        let mut node = create_node(0, "test", None, Some(profile), None, agents, vec![]);
        let mut node_table = store.node_map();
        let id = node_table.put(&node).unwrap();
        node.id = id;
        node.agents.iter_mut().for_each(|a| a.node_id = id);

        let old: Update = node.clone().into();
        let added_kinds = vec![AgentKind::Sensor];
        let added_configs = create_agent_configs(&added_kinds);
        let added_drafts = vec![None];
        let added = create_agents(id, &added_kinds, &added_configs, &added_drafts);

        let mut new_agents = node.agents.clone();
        new_agents.extend(added.clone());
        let new = Update {
            name: Some(node.name.clone()),
            name_draft: node.name_draft.clone(),
            profile: node.profile.clone(),
            profile_draft: node.profile_draft.clone(),
            agents: new_agents.clone(),
            external_services: vec![],
        };

        let returned = node_table.update(id, &old, &new).unwrap();
        assert_eq!(returned.agents, new_agents);
    }

    #[test]
    fn update_returns_node_with_removed_agent() {
        let (_permit, store) = setup_store();

        let kinds = vec![AgentKind::Unsupervised, AgentKind::Sensor];
        let configs = create_agent_configs(&kinds);
        let drafts = vec![None, None];
        let profile = Profile::default();
        let agents = create_agents(0, &kinds, &configs, &drafts);

        let mut node = create_node(0, "test", None, Some(profile), None, agents, vec![]);
        let mut node_table = store.node_map();
        let id = node_table.put(&node).unwrap();
        node.id = id;
        node.agents.iter_mut().for_each(|a| a.node_id = id);

        let old: Update = node.clone().into();
        let kept_agents: Vec<_> = node.agents.iter().take(1).cloned().collect();
        let new = Update {
            name: Some(node.name.clone()),
            name_draft: node.name_draft.clone(),
            profile: node.profile.clone(),
            profile_draft: node.profile_draft.clone(),
            agents: kept_agents.clone(),
            external_services: vec![],
        };

        let returned = node_table.update(id, &old, &new).unwrap();
        assert_eq!(returned.agents, kept_agents);
        assert_eq!(returned.agents.len(), 1);
    }

    #[test]
    fn update_returns_node_with_changed_profile() {
        let (_permit, store) = setup_store();

        let initial_profile = Profile {
            customer_id: 1,
            description: "initial".to_string(),
            hostname: "initial-host".to_string(),
        };
        let mut node = create_node(
            0,
            "test",
            None,
            Some(initial_profile.clone()),
            None,
            vec![],
            vec![],
        );
        let mut node_table = store.node_map();
        let id = node_table.put(&node).unwrap();
        node.id = id;

        let new_profile = Profile {
            customer_id: 1,
            description: "updated".to_string(),
            hostname: "updated-host".to_string(),
        };

        let old: Update = node.clone().into();
        let new = Update {
            name: Some(node.name.clone()),
            name_draft: None,
            profile: Some(new_profile.clone()),
            profile_draft: None,
            agents: vec![],
            external_services: vec![],
        };

        let returned = node_table.update(id, &old, &new).unwrap();
        assert_eq!(returned.profile, Some(new_profile));
    }

    #[test]
    fn update_preserves_creation_time() {
        let (_permit, store) = setup_store();

        let profile = Profile::default();
        let mut node = create_node(0, "test", None, Some(profile), None, vec![], vec![]);
        let original_creation_time = node.creation_time;

        let mut node_table = store.node_map();
        let id = node_table.put(&node).unwrap();
        node.id = id;

        let old: Update = node.clone().into();
        let new = Update {
            name: Some(node.name.clone()),
            name_draft: Some("draft".to_string()),
            profile: node.profile.clone(),
            profile_draft: None,
            agents: vec![],
            external_services: vec![],
        };

        let returned = node_table.update(id, &old, &new).unwrap();
        assert_eq!(returned.creation_time, original_creation_time);
    }

    #[test]
    fn update_noop_returns_unchanged_node() {
        let (_permit, store) = setup_store();

        let kinds = vec![AgentKind::Unsupervised];
        let configs = create_agent_configs(&kinds);
        let drafts = vec![None];
        let profile = Profile::default();
        let agents = create_agents(0, &kinds, &configs, &drafts);
        let mut node = create_node(
            0,
            "test",
            Some("draft"),
            Some(profile),
            None,
            agents,
            vec![],
        );

        let mut node_table = store.node_map();
        let id = node_table.put(&node).unwrap();
        node.id = id;
        node.agents.iter_mut().for_each(|a| a.node_id = id);

        let old: Update = node.clone().into();
        let new: Update = node.clone().into();

        let returned = node_table.update(id, &old, &new).unwrap();
        assert_eq!(returned, node);
    }

    #[test]
    fn update_atomic_rollback_on_agent_failure() {
        let (_permit, store) = setup_store();

        let kinds = vec![AgentKind::Sensor];
        let configs = create_agent_configs(&kinds);
        let drafts = vec![None];
        let profile = Profile {
            customer_id: 1,
            description: "original".to_string(),
            hostname: "original-host".to_string(),
        };
        let agents = create_agents(0, &kinds, &configs, &drafts);
        let mut node = create_node(0, "test", None, Some(profile.clone()), None, agents, vec![]);

        let mut node_table = store.node_map();
        let id = node_table.put(&node).unwrap();
        node.id = id;
        node.agents.iter_mut().for_each(|a| a.node_id = id);

        // Construct an `old` with a stale agent value (different draft) so the
        // agent.update_with_transaction step fails with "old value mismatch"
        // *after* the node-inner update has already been staged within the txn.
        let stale_drafts: Vec<Option<Config>> =
            vec![Some("stale_key=1".to_string().try_into().unwrap())];
        let stale_agents = create_agents(id, &kinds, &configs, &stale_drafts);

        let old = Update {
            name: Some(node.name.clone()),
            name_draft: None,
            profile: Some(profile.clone()),
            profile_draft: None,
            agents: stale_agents,
            external_services: vec![],
        };
        let new_profile = Profile {
            customer_id: 1,
            description: "modified".to_string(),
            hostname: "modified-host".to_string(),
        };
        let new_drafts: Vec<Option<Config>> =
            vec![Some("new_key=2".to_string().try_into().unwrap())];
        let new_agents = create_agents(id, &kinds, &configs, &new_drafts);
        let new = Update {
            name: Some(node.name.clone()),
            name_draft: None,
            profile: Some(new_profile),
            profile_draft: None,
            agents: new_agents,
            external_services: vec![],
        };

        let result = node_table.update(id, &old, &new);
        assert!(result.is_err());

        // Verify that no state change occurred — the node and its agent still
        // reflect the pre-update state.
        let (after, invalid_agents, _) = node_table.get_by_id(id).unwrap().unwrap();
        assert_eq!(invalid_agents, Vec::<String>::new());
        assert_eq!(after.profile, Some(profile));
        assert_eq!(after.agents, node.agents);
    }
}
