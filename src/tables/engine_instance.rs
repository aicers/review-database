//! The `engine instances` table: what each Unsupervised Engine instance's
//! documents reference, its detectors' statuses and whether it is stopped.
//!
//! One row per instance, keyed as the agents table keys the instance's agent
//! row: the node id in big-endian, then the agent key. Every writer of an
//! instance's records writes that one key, so RocksDB's optimistic conflict
//! check orders them. An instance without a row is not stopped, references
//! nothing and has no statuses.

use std::{collections::BTreeMap, mem::size_of};

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use rocksdb::{IteratorMode, OptimisticTransactionDB, Transaction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::ModelInstance;
use crate::{EXCLUSIVE, Map};

/// What one `[[detectors]]` entry of an engine document references.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EngineDetectorRef {
    /// The detector id.
    pub id: i32,
    /// The name of the model the detector serves.
    pub model: String,
    /// The sensor names the detector reads.
    pub sources: Vec<String>,
    /// The name of the model indicator in `suspicious_tokens`, if any.
    pub indicator: Option<String>,
}

/// The references of one engine document; an empty document has none.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EngineDocumentRefs {
    pub detectors: Vec<EngineDetectorRef>,
}

impl EngineDocumentRefs {
    fn names_detector(&self, id: i32) -> bool {
        self.detectors.iter().any(|d| d.id == id)
    }
}

/// The references to write for one engine instance of the node being
/// updated by
/// [`NodeTable::update_with_engine_documents`](crate::NodeTable::update_with_engine_documents).
///
/// `applied` describes the agent's `config` and `pending` its `draft`; `None`
/// leaves that slot as stored.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EngineDocumentWrite {
    pub agent_key: String,
    pub applied: Option<EngineDocumentRefs>,
    pub pending: Option<EngineDocumentRefs>,
}

/// The stored state of one engine instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineInstanceState {
    pub instance: ModelInstance,
    /// Whether the instance was last recorded as stopped.
    pub stopped: bool,
    /// The references of the agent's `config`.
    pub applied: EngineDocumentRefs,
    /// The references of the agent's `draft`.
    pub pending: EngineDocumentRefs,
}

/// A detector of an engine instance whose applied or pending document names
/// a model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelUse {
    pub instance: ModelInstance,
    pub detector_id: i32,
    /// Whether the applied document's detector names the model.
    pub applied: bool,
    /// Whether the pending document's detector names the model.
    pub pending: bool,
}

/// The status a detector last reported, and when it was stored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DetectorStatus {
    pub state: DetectorState,
    /// When the detector's last round finished.
    pub finished_at: Option<DateTime<Utc>>,
    /// The outcome of the detector's last round.
    pub outcome: Option<RoundOutcome>,
    pub reason: Option<String>,
    /// The number of events the detector's last round produced.
    pub events: u64,
    pub sources: Vec<DetectorSourceStatus>,
    /// When the Central Manager stored the report.
    pub reported_at: DateTime<Utc>,
}

/// The state of a detector.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DetectorState {
    Running,
    Disabled,
    NoModel,
    PausedForRun,
}

/// The outcome of a detector's round.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RoundOutcome {
    Succeeded,
    Failed,
}

/// The status of one source of a detector.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DetectorSourceStatus {
    pub source: String,
    pub state: SourceState,
    pub reason: Option<String>,
}

/// The state of a detector's source.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SourceState {
    Served,
    ServedByNoNode,
    Failed,
}

/// A refusal to write an engine document's references, a detector status or
/// an engine instance's stopped state.
///
/// It is returned inside the `anyhow::Error` of the refusing method, so a
/// caller can `downcast_ref` it.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EngineDocumentError {
    /// The agent key does not name an Unsupervised Engine agent of the node.
    #[error("agent {agent_key:?} of node {node_id} is not an Unsupervised Engine agent")]
    NotUnsupervisedAgent { node_id: u32, agent_key: String },
    /// The agent key is listed twice among the documents to write.
    #[error("agent {agent_key:?} is listed more than once")]
    DuplicateAgentKey { agent_key: String },
    /// An agent kept under one key changes its kind to or from Unsupervised.
    #[error("agent {agent_key:?} cannot change its kind to or from Unsupervised")]
    KindChanged { agent_key: String },
    /// A detector names a model that does not exist.
    #[error("agent {agent_key:?} names model {model:?}, which does not exist")]
    ModelNotFound { agent_key: String, model: String },
    /// A detector names a model that belongs to another instance.
    #[error("agent {agent_key:?} names model {model:?}, which belongs to another instance")]
    ModelOfAnotherInstance { agent_key: String, model: String },
    /// Two detectors of one document name the same model.
    #[error("a document of agent {agent_key:?} names model {model:?} more than once")]
    DuplicateModel { agent_key: String, model: String },
    /// Two detectors of one document have the same id.
    #[error("a document of agent {agent_key:?} has detector id {detector_id} more than once")]
    DuplicateDetectorId { agent_key: String, detector_id: i32 },
    /// A detector names a model indicator that does not exist.
    #[error("agent {agent_key:?} names indicator {indicator:?}, which does not exist")]
    IndicatorNotFound {
        agent_key: String,
        indicator: String,
    },
    /// The agent's `draft` changes without its pending references.
    #[error("the draft of agent {agent_key:?} changes without its pending references")]
    DraftWithoutReferences { agent_key: String },
    /// The agent's `config` changes without its applied references.
    #[error("the config of agent {agent_key:?} changes without its applied references")]
    ConfigWithoutReferences { agent_key: String },
    /// The stored document a written slot describes, the agent's `config`
    /// for the applied references or its `draft` for the pending ones, is
    /// not the one the update was made from.
    #[error("the stored config or draft of agent {agent_key:?} is not the one in `old`")]
    StaleDocument { agent_key: String },
    /// A plain node update changes an engine document or an engine agent's
    /// kind.
    #[error(
        "the config, draft or kind of Unsupervised Engine agent {agent_key:?} changes only \
         through NodeTable::update_with_engine_documents"
    )]
    RequiresEngineDocuments { agent_key: String },
    /// A detector status names a detector id in neither document.
    #[error(
        "detector {detector_id} is in neither document of agent {agent_key:?} of node {node_id}"
    )]
    UnknownDetector {
        node_id: u32,
        agent_key: String,
        detector_id: i32,
    },
}

/// The stored record of one engine instance.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct Row {
    pub(crate) stopped: bool,
    pub(crate) applied: EngineDocumentRefs,
    pub(crate) pending: EngineDocumentRefs,
    /// The last status of each detector, by detector id.
    pub(crate) statuses: BTreeMap<i32, DetectorStatus>,
}

impl Row {
    /// Returns whether either slot has a detector with the id.
    pub(crate) fn names_detector(&self, id: i32) -> bool {
        self.applied.names_detector(id) || self.pending.names_detector(id)
    }

    /// Drops the statuses of detector ids that appear in neither slot.
    pub(crate) fn retain_named_statuses(&mut self) {
        let Self {
            applied,
            pending,
            statuses,
            ..
        } = self;
        statuses.retain(|id, _| applied.names_detector(*id) || pending.names_detector(*id));
    }

    pub(crate) fn into_state(self, instance: ModelInstance) -> EngineInstanceState {
        EngineInstanceState {
            instance,
            stopped: self.stopped,
            applied: self.applied,
            pending: self.pending,
        }
    }
}

/// Returns the key of the instance's row, which is also the key of its
/// agent row.
pub(crate) fn key(node_id: u32, agent_key: &str) -> Vec<u8> {
    let mut key = node_id.to_be_bytes().to_vec();
    key.extend(agent_key.as_bytes());
    key
}

fn instance_of(key: &[u8]) -> Result<ModelInstance> {
    let (node_id, agent_key) = key
        .split_at_checked(size_of::<u32>())
        .ok_or_else(|| anyhow!("engine instance key is too short"))?;
    let node_id = u32::from_be_bytes(node_id.try_into()?);
    let agent_key = std::str::from_utf8(agent_key)
        .context("engine instance key is not UTF-8")?
        .to_string();
    Ok(ModelInstance { node_id, agent_key })
}

/// The `engine instances` column family.
pub(crate) struct EngineInstances<'d> {
    map: Map<'d>,
}

impl<'d> EngineInstances<'d> {
    pub(crate) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::ENGINE_INSTANCES).map(|map| Self { map })
    }

    /// Returns the row at `key`, read for update within `txn`.
    pub(crate) fn get_for_update(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
        key: &[u8],
    ) -> Result<Option<Row>> {
        txn.get_for_update_cf(self.map.cf, key, EXCLUSIVE)
            .context("cannot read engine instance")?
            .map(|value| super::deserialize(&value))
            .transpose()
    }

    /// Returns the row of `instance`.
    pub(crate) fn get(&self, instance: &ModelInstance) -> Result<Option<Row>> {
        self.map
            .get(&key(instance.node_id, &instance.agent_key))?
            .map(|value| super::deserialize(value.as_ref()))
            .transpose()
    }

    /// Writes the row at `key` within `txn`.
    pub(crate) fn put(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
        key: &[u8],
        row: &Row,
    ) -> Result<()> {
        self.map
            .put_with_transaction(key, &super::serialize(row)?, txn)
    }

    /// Deletes the row at `key` within `txn`; an absent row is not an error.
    pub(crate) fn delete(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
        key: &[u8],
    ) -> Result<()> {
        self.map.delete_with_transaction(key, txn)
    }

    /// Returns every stored row with its instance, ordered by key.
    pub(crate) fn all(&self) -> Result<Vec<(ModelInstance, Row)>> {
        self.map
            .db
            .iterator_cf(self.map.cf, IteratorMode::Start)
            .map(|entry| {
                let (key, value) = entry.context("cannot read engine instances")?;
                Ok((instance_of(&key)?, super::deserialize(&value)?))
            })
            .collect()
    }
}
