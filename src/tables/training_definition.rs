//! The `training definitions` table: the definition each Unsupervised
//! Engine model is trained from, keyed by its name, which models share.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rocksdb::{IteratorMode, OptimisticTransactionDB, Transaction};
use serde::{Deserialize, Serialize};

use super::{ModelInstance, RunId};
use crate::{EXCLUSIVE, Map};

/// The clustering method a training definition trains a model with.
///
/// A model record's `kind` names it as `Multifield`, `Prefix` or
/// `Timeseries`; the `Distribution` method is not trained by runs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ModelMethod {
    Multidimension,
    Prefix,
    Timeseries,
}

/// The definition a model is trained from.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrainingDefinition {
    /// The name of the definition, which is also the name of its model.
    pub name: String,
    pub customer_id: u32,
    /// The engine instance the definition trains on; `None` is the "no
    /// instance" state.
    pub instance: Option<ModelInstance>,
    pub method: ModelMethod,
    pub event_kind: String,
    pub sources: Vec<String>,
    /// The name of the model indicator in `suspicious_tokens`, if any.
    pub indicator: Option<String>,
    /// The definition's TOML text as the caller validated it: the settings
    /// of the model's next training, editable between runs. The settings
    /// that trained the current model are the model record's
    /// `trained_definition`, which editing this never changes.
    pub definition: String,
    /// Whether the definition was created by a clone that has not succeeded
    /// yet.
    pub cloning: bool,
    /// The last run of the definition.
    pub last_run: Option<RunId>,
    pub created_at: DateTime<Utc>,
    /// When the definition was last changed by
    /// [`Store::update_training_definition`](crate::Store::update_training_definition).
    pub updated_at: DateTime<Utc>,
}

/// A training definition to create.
///
/// `method`, `event_kind`, `sources` and `indicator` are what the caller
/// extracted from its own parse of `definition`; nothing in this crate
/// parses it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewTrainingDefinition {
    pub name: String,
    pub customer_id: u32,
    pub instance: ModelInstance,
    pub method: ModelMethod,
    pub event_kind: String,
    pub sources: Vec<String>,
    pub indicator: Option<String>,
    pub definition: String,
}

/// The new settings of a training definition, extracted by the caller from
/// its own parse of `definition`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrainingDefinitionUpdate {
    pub method: ModelMethod,
    pub event_kind: String,
    pub sources: Vec<String>,
    pub indicator: Option<String>,
    pub definition: String,
}

/// The `training definitions` column family.
pub(crate) struct TrainingDefinitions<'d> {
    map: Map<'d>,
}

impl<'d> TrainingDefinitions<'d> {
    pub(crate) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::TRAINING_DEFINITIONS).map(|map| Self { map })
    }

    /// Returns the definition `name`, read for update within `txn`.
    pub(crate) fn get_for_update(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
        name: &str,
    ) -> Result<Option<TrainingDefinition>> {
        txn.get_for_update_cf(self.map.cf, name.as_bytes(), EXCLUSIVE)
            .context("cannot read training definition")?
            .map(|value| super::deserialize(&value))
            .transpose()
    }

    /// Returns the definition `name`.
    pub(crate) fn get(&self, name: &str) -> Result<Option<TrainingDefinition>> {
        self.map
            .get(name.as_bytes())?
            .map(|value| super::deserialize(value.as_ref()))
            .transpose()
    }

    /// Returns the definition `name` as `snapshot` holds it.
    pub(crate) fn get_in_snapshot(
        &self,
        snapshot: &rocksdb::SnapshotWithThreadMode<'_, OptimisticTransactionDB>,
        name: &str,
    ) -> Result<Option<TrainingDefinition>> {
        snapshot
            .get_cf(self.map.cf, name.as_bytes())
            .context("cannot read training definition")?
            .map(|value| super::deserialize(&value))
            .transpose()
    }

    /// Writes `definition` under its name within `txn`.
    pub(crate) fn put(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
        definition: &TrainingDefinition,
    ) -> Result<()> {
        self.map.put_with_transaction(
            definition.name.as_bytes(),
            &super::serialize(definition)?,
            txn,
        )
    }

    /// Deletes the definition `name` within `txn`; an absent definition is
    /// not an error.
    pub(crate) fn delete(
        &self,
        txn: &Transaction<OptimisticTransactionDB>,
        name: &str,
    ) -> Result<()> {
        self.map.delete_with_transaction(name.as_bytes(), txn)
    }

    /// Returns every definition, ordered by name.
    pub(crate) fn all(&self) -> Result<Vec<TrainingDefinition>> {
        self.map
            .db
            .iterator_cf(self.map.cf, IteratorMode::Start)
            .map(|entry| {
                let (_, value) = entry.context("cannot read training definitions")?;
                super::deserialize(&value)
            })
            .collect()
    }
}
