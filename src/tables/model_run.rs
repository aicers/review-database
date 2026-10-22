//! The `model runs` table: every training or clone run the Central Manager
//! issued, with its state, and the run id counter.
//!
//! A run is keyed by its id in big-endian, so iterating the family yields
//! runs in id order. The counter is a key of the `meta` family holding the
//! last allocated id; every run creation reads it for update and writes it,
//! which also makes it the anchor of "the instance has an active run": a
//! check that reads it for update before scanning the runs conflicts with
//! any run created after that read.

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use rocksdb::{IteratorMode, OptimisticTransactionDB, Transaction};
use serde::{Deserialize, Serialize};

use super::ModelInstance;
use crate::{EXCLUSIVE, Map};

/// The id of a model run, issued by the Central Manager.
pub type RunId = u32;

/// What a run does.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RunKind {
    /// Trains the model of a training definition.
    Train,
    /// Clones the model `source` into the run's model.
    Clone {
        source: String,
        /// Whether the clone leaves out the source's events, which is the
        /// case exactly when the target belongs to another customer.
        strip_events: bool,
    },
}

/// The state of a run. `Requested` and `Started` are active; the other three
/// are finished and never change again.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RunState {
    Requested,
    Started,
    Succeeded,
    Failed,
    Cancelled,
}

impl RunState {
    /// Returns whether a run in this state is active.
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(self, Self::Requested | Self::Started)
    }
}

/// A run state an engine reports.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReportedRunState {
    Started,
    Failed,
    Cancelled,
}

/// A training or clone run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelRun {
    pub id: RunId,
    pub kind: RunKind,
    /// The model the run creates or replaces; for a clone, the target name.
    pub model: String,
    /// The instance that performs the run; for a clone, the source model's
    /// instance.
    pub instance: ModelInstance,
    pub state: RunState,
    /// The reason given with the last state change, if any.
    pub reason: Option<String>,
    pub requested_at: DateTime<Utc>,
    /// When the state last changed; `requested_at` until it first does.
    pub updated_at: DateTime<Utc>,
}

impl ModelRun {
    /// Returns whether the run creates or replaces `model`, or clones from it.
    pub(crate) fn concerns(&self, model: &str) -> bool {
        self.model == model
            || matches!(&self.kind, RunKind::Clone { source, .. } if source == model)
    }
}

fn key(id: RunId) -> [u8; 4] {
    id.to_be_bytes()
}

/// The `model runs` column family, with the run id counter in `meta`.
pub(crate) struct ModelRuns<'d> {
    map: Map<'d>,
    meta: Map<'d>,
}

impl<'d> ModelRuns<'d> {
    pub(crate) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Some(Self {
            map: Map::open(db, super::MODEL_RUNS)?,
            meta: Map::open(db, super::META)?,
        })
    }

    /// Reads the run id counter for update within `txn`, returning the last
    /// allocated id, `None` before the first run.
    ///
    /// Reading it is what anchors a scan for an instance's active runs: a
    /// run created after this read conflicts with `txn`.
    pub(crate) fn last_id_for_update(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
    ) -> Result<Option<RunId>> {
        txn.get_for_update_cf(self.meta.cf, super::MODEL_RUN_ID_COUNTER, EXCLUSIVE)
            .context("cannot read the model run id counter")?
            .map(|value| {
                let bytes: [u8; 4] = value
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("the model run id counter is not 4 bytes"))?;
                Ok(RunId::from_be_bytes(bytes))
            })
            .transpose()
    }

    /// Allocates the next run id within `txn`, writing it as the last one.
    ///
    /// # Errors
    ///
    /// Returns an error if every id has been allocated or a database
    /// operation fails.
    pub(crate) fn allocate_id(&self, txn: &Transaction<OptimisticTransactionDB>) -> Result<RunId> {
        let id = match self.last_id_for_update(txn)? {
            None => 1,
            Some(last) => last
                .checked_add(1)
                .ok_or_else(|| anyhow!("every model run id has been allocated"))?,
        };
        self.meta
            .put_with_transaction(super::MODEL_RUN_ID_COUNTER, &id.to_be_bytes(), txn)?;
        Ok(id)
    }

    /// Returns the run `id`, read for update within `txn`.
    pub(crate) fn get_for_update(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
        id: RunId,
    ) -> Result<Option<ModelRun>> {
        txn.get_for_update_cf(self.map.cf, key(id), EXCLUSIVE)
            .context("cannot read model run")?
            .map(|value| super::deserialize(&value))
            .transpose()
    }

    /// Returns the run `id`.
    pub(crate) fn get(&self, id: RunId) -> Result<Option<ModelRun>> {
        self.map
            .get(&key(id))?
            .map(|value| super::deserialize(value.as_ref()))
            .transpose()
    }

    /// Returns the run `id` as `snapshot` holds it.
    pub(crate) fn get_in_snapshot(
        &self,
        snapshot: &rocksdb::SnapshotWithThreadMode<'_, OptimisticTransactionDB>,
        id: RunId,
    ) -> Result<Option<ModelRun>> {
        snapshot
            .get_cf(self.map.cf, key(id))
            .context("cannot read model run")?
            .map(|value| super::deserialize(&value))
            .transpose()
    }

    /// Writes `run` within `txn`.
    pub(crate) fn put(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
        run: &ModelRun,
    ) -> Result<()> {
        self.map
            .put_with_transaction(&key(run.id), &super::serialize(run)?, txn)
    }

    /// Deletes the run `id` within `txn`; an absent run is not an error.
    pub(crate) fn delete(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
        id: RunId,
    ) -> Result<()> {
        self.map.delete_with_transaction(&key(id), txn)
    }

    /// Returns every run as `txn` sees it, in id order.
    ///
    /// The scan is not tracked by `txn`: a run written after it does not
    /// conflict with the transaction.
    pub(crate) fn scan(&self, txn: &Transaction<OptimisticTransactionDB>) -> Result<Vec<ModelRun>> {
        txn.iterator_cf(self.map.cf, IteratorMode::Start)
            .map(|entry| {
                let (_, value) = entry.context("cannot read model runs")?;
                super::deserialize(&value)
            })
            .collect()
    }

    /// Returns every run, in id order.
    pub(crate) fn all(&self) -> Result<Vec<ModelRun>> {
        self.map
            .db
            .iterator_cf(self.map.cf, IteratorMode::Start)
            .map(|entry| {
                let (_, value) = entry.context("cannot read model runs")?;
                super::deserialize(&value)
            })
            .collect()
    }
}
