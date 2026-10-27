//! The guarded writes of Unsupervised Engine models and model indicators,
//! and the detach of an uninstalled engine instance (RFC 0006 §5.3, §5.4,
//! §5.11 of Clumit Security Web).
//!
//! A model in use cannot be deleted, and an indicator in use can neither be
//! changed nor removed: a detector of an applied or pending engine document,
//! or a training definition, holds what it names. An uninstalled instance's
//! models and definitions are detached, left with no instance, and can be
//! assigned to another instance of their customer.
//!
//! # Transactions
//!
//! Every writer is one optimistic transaction, retried from the start on a
//! commit conflict; a refusal returns without committing and changes
//! nothing. A guard scans every `engine instances` row and every training
//! definition inside the writer's transaction and reads each one it examines
//! for update, so a concurrent change of an existing row or definition
//! conflicts. A scan is not tracked: a row or definition created by a
//! concurrent transaction after the scan does not conflict, which
//! aicers/review-web's engine configuration lock covers. Active runs are
//! found through the run id counter, as in `training`.
//!
//! The removal of a customer's records closes that gap for the indicators
//! it deletes. Every writer that names an indicator, in a training
//! definition or a detector, reads it for update and writes it back
//! unchanged, and the removal reads each indicator of a model for update
//! before it scans the holders: a reference committed after that read
//! makes the removal conflict, one committed before it is in the scan, and
//! one committing after the removal conflicts on the deleted indicator and
//! is refused on its retry. An indicator the model gains after that read
//! was not checked, so the removal retries if it would delete one.
//!
//! The detach has no such gap. Every record that gains an instance does so
//! in a transaction that either writes a key the detach reads (the run id
//! counter, a run) or writes the instance's agent row back unchanged, which
//! the removal that runs the detach deletes; whichever commits second
//! conflicts.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use anyhow::{Context, Result};
use rocksdb::{ColumnFamily, IteratorMode, OptimisticTransactionDB, Transaction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AgentKind, EXCLUSIVE, EngineDetectorRef, IndexedTable, Iterable, ModelIndicator, ModelInstance,
    RunId, RunState, Store, TrainingDefinition, TrainingError,
    engine_instance::agent_for_update,
    model_lifecycle::column_family,
    tables::{
        self, EngineInstanceRow as Row, EngineInstances, Model, ModelRuns, TrainingDefinitions,
    },
    training,
    types::FromKeyValue,
};

type Txn<'a> = Transaction<'a, OptimisticTransactionDB>;

/// What names a model indicator or a source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Referrer {
    /// A detector of the instance's applied or pending engine document.
    Detector {
        instance: ModelInstance,
        detector_id: i32,
    },
    /// A training definition.
    Definition { name: String },
}

impl fmt::Display for Referrer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Detector {
                instance,
                detector_id,
            } => write!(
                f,
                "detector {detector_id} of agent {:?} of node {}",
                instance.agent_key, instance.node_id
            ),
            Self::Definition { name } => write!(f, "training definition {name:?}"),
        }
    }
}

/// A detector or a training definition that lists a source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceReference {
    pub source: String,
    pub by: Referrer,
}

/// A refusal of
/// [`Store::remove_customer_unsupervised_records`](crate::Store::remove_customer_unsupervised_records).
///
/// It is returned inside the `anyhow::Error` of the call, so a caller can
/// `downcast_ref` it. `ModelReferenced` and `RunActive` cannot happen once
/// the customer's nodes are removed; each makes a removal called before that
/// fail instead of leaving a detector without its model or a run that can
/// never complete. `IndicatorReferenced` can happen after that too, since
/// another customer's definition or detector can name one of the customer's
/// indicators; it makes the removal fail instead of leaving that holder
/// naming an indicator that is gone. The refused transaction changes
/// nothing, but the models and definitions removed before it stay removed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RemovalRefused {
    /// A detector of an applied or pending engine document names the model.
    #[error(
        "model {model:?} is referenced by detector {detector_id} of agent {:?} of node {}",
        instance.agent_key,
        instance.node_id
    )]
    ModelReferenced {
        model: String,
        instance: ModelInstance,
        detector_id: i32,
    },
    /// An active run creates or replaces the model or definition, or clones
    /// from the model.
    #[error("model run {run_id} is active")]
    RunActive { run_id: RunId },
    /// A detector of an applied or pending engine document, or a training
    /// definition of another customer, names an indicator of the model.
    #[error("model indicator {indicator:?} of model {model:?} is used by {by}")]
    IndicatorReferenced {
        model: String,
        indicator: String,
        by: Referrer,
    },
}

/// The tables the records of an engine instance live in, as the detach
/// reaches them.
pub(crate) struct InstanceRecords<'a, 'd> {
    pub(crate) runs: &'a ModelRuns<'d>,
    pub(crate) definitions: &'a TrainingDefinitions<'d>,
    pub(crate) models: &'a IndexedTable<'d, Model>,
    pub(crate) engine_instances: &'a EngineInstances<'d>,
}

impl InstanceRecords<'_, '_> {
    /// Detaches, within `txn`, the records of `instance`, whose agent row is
    /// gone or being removed in `txn`.
    ///
    /// Every active run the instance performs fails with `reason`, a clone
    /// among them removing the target definition it reserved. A definition
    /// of the instance being created by an active clone is removed with
    /// that run, which fails with `reason`; every other definition and every
    /// model of the instance is left with no instance. The instance's
    /// `engine instances` row is deleted. An instance with no records
    /// changes nothing.
    pub(crate) fn detach(
        &self,
        txn: &Txn<'_>,
        instance: &ModelInstance,
        reason: &str,
    ) -> Result<()> {
        training::fail_active_runs(txn, self.runs, self.definitions, instance, reason)?;

        for scanned in self.definitions.scan(txn)? {
            if scanned.instance.as_ref() != Some(instance) {
                continue;
            }
            let Some(mut definition) = self.definitions.get_for_update(txn, &scanned.name)? else {
                continue;
            };
            if definition.instance.as_ref() != Some(instance) {
                continue;
            }
            if definition.cloning
                && let Some(id) = definition.last_run
                && let Some(run) = self.runs.get_for_update(txn, id)?
                && run.state.is_active()
            {
                training::end_run(
                    txn,
                    self.runs,
                    self.definitions,
                    run,
                    RunState::Failed,
                    Some(reason),
                )?;
                continue;
            }
            definition.instance = None;
            self.definitions.put(txn, &definition)?;
        }

        for scanned in self.models.scan(txn)? {
            if scanned.instance.as_ref() != Some(instance) {
                continue;
            }
            let Some(model) = self
                .models
                .load_model_by_name_in_transaction(&scanned.name, txn)?
            else {
                continue;
            };
            if model.instance.as_ref() != Some(instance) {
                continue;
            }
            let detached = Model {
                instance: None,
                ..model.clone()
            };
            self.models
                .update_model_with_transaction(&model, &detached, txn)?;
        }

        self.engine_instances.delete(
            txn,
            &tables::engine_instance_key(instance.node_id, &instance.agent_key),
        )
    }
}

/// The `engine instances` rows and training definitions a guard examines,
/// each read for update within the guard's transaction.
struct References {
    /// In key order: node id, then agent key.
    rows: Vec<(ModelInstance, Row)>,
    /// In name order.
    definitions: Vec<TrainingDefinition>,
}

impl References {
    fn read(store: &Store, txn: &Txn<'_>) -> Result<Self> {
        let rows = Self::read_rows(store, txn)?;
        let training_definitions = store.states.training_definitions();
        let mut definitions = Vec::new();
        for scanned in training_definitions.scan(txn)? {
            if let Some(definition) = training_definitions.get_for_update(txn, &scanned.name)? {
                definitions.push(definition);
            }
        }
        Ok(Self { rows, definitions })
    }

    fn read_rows(store: &Store, txn: &Txn<'_>) -> Result<Vec<(ModelInstance, Row)>> {
        let engine_instances = store.states.engine_instances();
        let mut rows = Vec::new();
        for (instance, _) in engine_instances.scan(txn)? {
            let key = tables::engine_instance_key(instance.node_id, &instance.agent_key);
            if let Some(row) = engine_instances.get_for_update(txn, &key)? {
                rows.push((instance, row));
            }
        }
        Ok(rows)
    }

    /// Returns the first detector of an applied or pending document that
    /// `names` accepts, in row order, then detector id.
    fn first_detector(
        &self,
        names: impl Fn(&EngineDetectorRef) -> bool,
    ) -> Option<(&ModelInstance, i32)> {
        self.rows.iter().find_map(|(instance, row)| {
            row.applied
                .detectors
                .iter()
                .chain(&row.pending.detectors)
                .filter(|detector| names(detector))
                .map(|detector| detector.id)
                .min()
                .map(|detector_id| (instance, detector_id))
        })
    }

    /// Returns the first holder of the indicator: a detector, in the order
    /// of [`References::first_detector`], then a definition `holds`
    /// accepts, in name order.
    fn indicator_holder(
        &self,
        indicator: &str,
        holds: impl Fn(&TrainingDefinition) -> bool,
    ) -> Option<Referrer> {
        if let Some((instance, detector_id)) =
            self.first_detector(|detector| detector.indicator.as_deref() == Some(indicator))
        {
            return Some(Referrer::Detector {
                instance: instance.clone(),
                detector_id,
            });
        }
        self.definitions
            .iter()
            .find(|definition| {
                definition.indicator.as_deref() == Some(indicator) && holds(definition)
            })
            .map(|definition| Referrer::Definition {
                name: definition.name.clone(),
            })
    }
}

impl Store {
    /// Stores a model indicator under a new name.
    ///
    /// Whether its `model_id` names an existing model is not checked.
    ///
    /// # Errors
    ///
    /// Returns a [`TrainingError`] inside the error, and changes nothing:
    /// `IndicatorExists` if an indicator has the name; an existing one is
    /// replaced through [`Store::update_model_indicator`]. Returns an error,
    /// and changes nothing, if the indicator cannot be serialized or a
    /// database operation fails.
    pub fn insert_model_indicator(&self, indicator: ModelIndicator) -> Result<()> {
        let cf = column_family(self.states.db(), tables::MODEL_INDICATORS)?;
        let name = indicator.name.clone();
        let (key, value) = indicator.into_key_value()?;
        self.write_training(|txn| {
            if indicator_for_update(txn, cf, &name)?.is_some() {
                return Err(TrainingError::IndicatorExists {
                    indicator: name.clone(),
                }
                .into());
            }
            txn.put_cf(cf, &key, &value)
                .context("cannot write model indicator")
        })
    }

    /// Replaces the model indicator of the same name with `indicator` as
    /// given, `last_modification_time` included.
    ///
    /// # Errors
    ///
    /// Returns a [`TrainingError`] inside the error, and changes nothing,
    /// checked in this order: `IndicatorNotFound` if no indicator has the
    /// name; `IndicatorModelChange` if `indicator.model_id` is not the
    /// stored one; `IndicatorInUse` while a detector of an applied or
    /// pending engine document or a training definition names it, naming
    /// the first such detector, in node id, agent key, then detector id
    /// order, or else the first such definition by name. Returns an error,
    /// and changes nothing, if the indicator cannot be serialized or a
    /// database operation fails.
    pub fn update_model_indicator(&self, indicator: ModelIndicator) -> Result<()> {
        let cf = column_family(self.states.db(), tables::MODEL_INDICATORS)?;
        let name = indicator.name.clone();
        let new_model_id = indicator.model_id;
        let (key, value) = indicator.into_key_value()?;
        self.write_training(|txn| {
            let Some(stored) = indicator_for_update(txn, cf, &name)? else {
                return Err(TrainingError::IndicatorNotFound {
                    indicator: name.clone(),
                }
                .into());
            };
            if stored.model_id != new_model_id {
                return Err(TrainingError::IndicatorModelChange {
                    indicator: name.clone(),
                    model_id: stored.model_id,
                    new_model_id,
                }
                .into());
            }
            if let Some(by) = References::read(self, txn)?.indicator_holder(&name, |_| true) {
                return Err(TrainingError::IndicatorInUse {
                    indicator: name.clone(),
                    by,
                }
                .into());
            }
            txn.put_cf(cf, &key, &value)
                .context("cannot write model indicator")
        })
    }

    /// Removes the model indicators with the given names, all or none.
    ///
    /// A name no indicator has is skipped.
    ///
    /// # Errors
    ///
    /// Returns a [`TrainingError`] inside the error, and changes nothing:
    /// `IndicatorInUse` for the first of `names`, in the given order, that a
    /// detector of an applied or pending engine document or a training
    /// definition names, as [`Store::update_model_indicator`] reports it.
    /// Returns an error, and changes nothing, if a database operation fails.
    pub fn remove_model_indicators(&self, names: &[String]) -> Result<()> {
        let cf = column_family(self.states.db(), tables::MODEL_INDICATORS)?;
        self.write_training(|txn| {
            let references = References::read(self, txn)?;
            let mut present = Vec::new();
            for name in names {
                if indicator_for_update(txn, cf, name)?.is_none() {
                    continue;
                }
                if let Some(by) = references.indicator_holder(name, |_| true) {
                    return Err(TrainingError::IndicatorInUse {
                        indicator: name.clone(),
                        by,
                    }
                    .into());
                }
                present.push(name);
            }
            for name in present {
                txn.delete_cf(cf, name.as_bytes())
                    .context("cannot remove model indicator")?;
            }
            Ok(())
        })
    }

    /// Gives a model with no instance, and its training definition if one
    /// exists, the instance `target`, in one transaction.
    ///
    /// Nothing else of the model or the definition changes, the definition's
    /// `updated_at` included. The model's customer stays: `target` has to
    /// belong to it.
    ///
    /// # Errors
    ///
    /// Returns a [`TrainingError`] inside the error, and changes nothing,
    /// checked in this order: `ModelNotFound`; `ModelHasInstance` if the
    /// model has an instance; `InstanceNotEligible` if `target` is not an
    /// [`AgentKind::Unsupervised`] agent row with an instance number;
    /// `NoAppliedProfile` if the target's node has no applied profile;
    /// `CustomerMismatch` if that profile's customer is not the model's.
    /// Returns an error, and changes nothing, if a database operation fails.
    pub fn assign_model(&self, name: &str, target: &ModelInstance) -> Result<()> {
        let models = self.model_map();
        let definitions = self.states.training_definitions();
        self.write_training(|txn| {
            let Some(model) = models.load_model_by_name_in_transaction(name, txn)? else {
                return Err(TrainingError::ModelNotFound {
                    name: name.to_string(),
                }
                .into());
            };
            if let Some(instance) = &model.instance {
                return Err(TrainingError::ModelHasInstance {
                    name: name.to_string(),
                    instance: instance.clone(),
                }
                .into());
            }
            self.check_instance_eligible(txn, target)?;
            self.hold_agent_row(txn, target)?;
            let Some(profile) = self
                .states
                .nodes()
                .applied_profile_in_transaction(target.node_id, txn)?
            else {
                return Err(TrainingError::NoAppliedProfile {
                    node_id: target.node_id,
                }
                .into());
            };
            if profile.customer_id != model.customer_id {
                return Err(TrainingError::CustomerMismatch {
                    node_id: target.node_id,
                    node_customer_id: profile.customer_id,
                    customer_id: model.customer_id,
                }
                .into());
            }

            if let Some(mut definition) = definitions.get_for_update(txn, name)? {
                definition.instance = Some(target.clone());
                definitions.put(txn, &definition)?;
            }
            let assigned = Model {
                instance: Some(target.clone()),
                ..model.clone()
            };
            models.update_model_with_transaction(&model, &assigned, txn)
        })
    }

    /// Detaches the records of an engine instance whose agent row is gone:
    /// fails its active runs with `reason`, and leaves its models and
    /// training definitions with no instance and it with no
    /// `engine instances` row, as removing its agent through a
    /// [`NodeTable`](crate::NodeTable) writer does.
    ///
    /// It is for a removal that has already deleted the agent row, such as
    /// a re-finalized uninstall or a raw
    /// [`Table<Agent>::delete`](crate::Table::delete). While the row is an
    /// [`AgentKind::Unsupervised`] agent, nothing changes: an installed
    /// instance, including one reinstalled under the same key, keeps its
    /// records. Calling it again, or for an instance without records,
    /// changes nothing.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if a database operation fails.
    pub fn detach_engine_instance(&self, instance: &ModelInstance, reason: &str) -> Result<()> {
        let runs = self.states.model_runs();
        let definitions = self.states.training_definitions();
        let models = self.model_map();
        let engine_instances = self.states.engine_instances();
        let records = InstanceRecords {
            runs: &runs,
            definitions: &definitions,
            models: &models,
            engine_instances: &engine_instances,
        };
        let key = tables::engine_instance_key(instance.node_id, &instance.agent_key);
        self.write_training(|txn| {
            if agent_for_update(txn, self.states.agents().raw().cf, &key)?
                .is_some_and(|agent| agent.kind == AgentKind::Unsupervised)
            {
                return Ok(());
            }
            records.detach(txn, instance, reason)
        })
    }

    /// Returns the names of the models and training definitions, cloning
    /// reservations included, whose instance is `instance`, ascending and
    /// without duplicates; empty if it owns none.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn engine_instance_owns_models(&self, instance: &ModelInstance) -> Result<Vec<String>> {
        let mut names = BTreeSet::new();
        for model in self.model_map().iter(rocksdb::Direction::Forward, None) {
            let model = model?;
            if model.instance.as_ref() == Some(instance) {
                names.insert(model.name);
            }
        }
        for definition in self.states.training_definitions().all()? {
            if definition.instance.as_ref() == Some(instance) {
                names.insert(definition.name);
            }
        }
        Ok(names.into_iter().collect())
    }

    /// Returns, for each of `sources`, every detector and training
    /// definition that lists it.
    ///
    /// Detectors of applied and pending engine documents come first, in node
    /// id, agent key, then detector id order, a detector's sources being
    /// those of both documents; then definitions, in name order. A holder
    /// listing several of `sources` yields one entry per source, in the
    /// order of `sources`; a source given twice is reported once.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn source_references(&self, sources: &[String]) -> Result<Vec<SourceReference>> {
        let mut seen = BTreeSet::new();
        let sources: Vec<&String> = sources
            .iter()
            .filter(|source| seen.insert(source.as_str()))
            .collect();
        let mut references = Vec::new();
        for (instance, row) in self.states.engine_instances().all()? {
            let mut detectors: BTreeMap<i32, BTreeSet<&str>> = BTreeMap::new();
            for detector in row.applied.detectors.iter().chain(&row.pending.detectors) {
                detectors
                    .entry(detector.id)
                    .or_default()
                    .extend(detector.sources.iter().map(String::as_str));
            }
            for (detector_id, listed) in detectors {
                for &source in &sources {
                    if listed.contains(source.as_str()) {
                        references.push(SourceReference {
                            source: source.clone(),
                            by: Referrer::Detector {
                                instance: instance.clone(),
                                detector_id,
                            },
                        });
                    }
                }
            }
        }
        for definition in self.states.training_definitions().all()? {
            for &source in &sources {
                if definition.sources.contains(source) {
                    references.push(SourceReference {
                        source: source.clone(),
                        by: Referrer::Definition {
                            name: definition.name.clone(),
                        },
                    });
                }
            }
        }
        Ok(references)
    }

    /// Refuses, within `txn` and before any write, the delete of `model`
    /// that [`Store::delete_model`] refuses.
    pub(crate) fn check_model_unused(&self, txn: &Txn<'_>, model: &Model) -> Result<()> {
        let name = &model.name;
        self.hold_instance_row(txn, model)?;
        let references = References::read(self, txn)?;
        if let Some((instance, detector_id)) =
            references.first_detector(|detector| detector.model == *name)
        {
            return Err(TrainingError::ModelInUse {
                name: name.clone(),
                instance: instance.clone(),
                detector_id,
            }
            .into());
        }

        if let Some(run_id) = self.active_run_concerning(txn, name)? {
            return Err(TrainingError::RunInProgress { run_id }.into());
        }

        let indicators = column_family(self.states.db(), tables::MODEL_INDICATORS)?;
        for entry in txn.iterator_cf(indicators, IteratorMode::Start) {
            let (key, value) = entry.context("cannot read model indicators")?;
            let indicator = ModelIndicator::from_key_value(&key, &value)?;
            if indicator.model_id != model.id {
                continue;
            }
            if let Some(by) =
                references.indicator_holder(&indicator.name, |definition| definition.name != *name)
            {
                return Err(TrainingError::IndicatorInUse {
                    indicator: indicator.name,
                    by,
                }
                .into());
            }
        }
        Ok(())
    }

    /// Refuses, within `txn` and before any write, the removal of `model`
    /// that [`Store::remove_customer_unsupervised_records`] refuses:
    /// `ModelReferenced`, then `RunActive`, then `IndicatorReferenced`;
    /// returns the names of the indicators it checked, in name order.
    ///
    /// A definition of the model's customer, which the removal also
    /// removes, does not hold an indicator; another customer's does, even
    /// one sharing the model's name. An indicator the model gains after
    /// the check is not covered: the removal deletes only what it checked
    /// or retries.
    pub(crate) fn check_model_unreferenced(
        &self,
        txn: &Txn<'_>,
        model: &Model,
    ) -> Result<Vec<String>> {
        let name = &model.name;
        self.hold_instance_row(txn, model)?;
        // Read before the holders: a writer that names an indicator writes
        // it back, so one committing after this read makes the removal
        // conflict, and one committing before it is in the scan below.
        let indicators = self.indicators_for_update(txn, model.id)?;
        let references = References::read(self, txn)?;
        if let Some((instance, detector_id)) =
            references.first_detector(|detector| detector.model == *name)
        {
            return Err(RemovalRefused::ModelReferenced {
                model: name.clone(),
                instance: instance.clone(),
                detector_id,
            }
            .into());
        }
        self.check_no_active_run_concerning(txn, name)?;
        for indicator in &indicators {
            if let Some(by) = references.indicator_holder(indicator, |definition| {
                definition.customer_id != model.customer_id
            }) {
                return Err(RemovalRefused::IndicatorReferenced {
                    model: name.clone(),
                    indicator: indicator.clone(),
                    by,
                }
                .into());
            }
        }
        Ok(indicators)
    }

    /// Returns the names of the indicators of model `id`, in name order,
    /// each read for update within `txn`.
    fn indicators_for_update(&self, txn: &Txn<'_>, id: u32) -> Result<Vec<String>> {
        let cf = column_family(self.states.db(), tables::MODEL_INDICATORS)?;
        let mut names = Vec::new();
        for entry in txn.iterator_cf(cf, IteratorMode::Start) {
            let (key, value) = entry.context("cannot read model indicators")?;
            let indicator = ModelIndicator::from_key_value(&key, &value)?;
            if indicator.model_id != id {
                continue;
            }
            if indicator_for_update(txn, cf, &indicator.name)?.is_some_and(|i| i.model_id == id) {
                names.push(indicator.name);
            }
        }
        Ok(names)
    }

    /// Refuses, within `txn` and before any write, with `RunActive` while
    /// an active run creates or replaces `name`, or clones from it.
    pub(crate) fn check_no_active_run_concerning(&self, txn: &Txn<'_>, name: &str) -> Result<()> {
        if let Some(run_id) = self.active_run_concerning(txn, name)? {
            return Err(RemovalRefused::RunActive { run_id }.into());
        }
        Ok(())
    }

    /// Reads the `engine instances` row of `model`'s instance for update
    /// within `txn`, if the model has an instance.
    fn hold_instance_row(&self, txn: &Txn<'_>, model: &Model) -> Result<()> {
        if let Some(instance) = &model.instance {
            // A document names only a model of its own instance, so reading
            // this key, even while it is absent, makes that instance's first
            // link to the model conflict with the delete.
            self.states.engine_instances().get_for_update(
                txn,
                &tables::engine_instance_key(instance.node_id, &instance.agent_key),
            )?;
        }
        Ok(())
    }

    /// Returns the first active run, in id order, that creates or replaces
    /// `name`, or clones from it, reading the run id counter for update
    /// before scanning the runs.
    fn active_run_concerning(&self, txn: &Txn<'_>, name: &str) -> Result<Option<RunId>> {
        let runs = self.states.model_runs();
        runs.last_id_for_update(txn)?;
        for scanned in runs.scan(txn)? {
            if !scanned.state.is_active() || !scanned.concerns(name) {
                continue;
            }
            if let Some(run) = runs.get_for_update(txn, scanned.id)?
                && run.state.is_active()
                && run.concerns(name)
            {
                return Ok(Some(run.id));
            }
        }
        Ok(None)
    }

    /// Removes, within `txn`, the training definition `name` and every run
    /// record whose model is `name`, for the delete of the model, returning
    /// whether the definition existed.
    ///
    /// With `customer_id`, a definition of another customer, which can
    /// share the name of a model [`Store::replace_model`] stored, stays
    /// with its runs, and `false` is returned.
    pub(crate) fn remove_training_records(
        &self,
        txn: &Txn<'_>,
        name: &str,
        customer_id: Option<u32>,
    ) -> Result<bool> {
        let definitions = self.states.training_definitions();
        let Some(definition) = definitions.get_for_update(txn, name)? else {
            self.remove_runs_of(txn, name)?;
            return Ok(false);
        };
        if customer_id.is_some_and(|id| id != definition.customer_id) {
            return Ok(false);
        }
        definitions.delete(txn, name)?;
        self.remove_runs_of(txn, name)?;
        Ok(true)
    }

    /// Removes, within `txn`, every run record whose model is `name`.
    fn remove_runs_of(&self, txn: &Txn<'_>, name: &str) -> Result<()> {
        let runs = self.states.model_runs();
        for run in runs.scan(txn)?.into_iter().filter(|run| run.model == name) {
            runs.get_for_update(txn, run.id)?;
            runs.delete(txn, run.id)?;
        }
        Ok(())
    }
}

/// Returns the model indicator `name`, read for update within `txn`.
fn indicator_for_update(
    txn: &Txn<'_>,
    cf: &ColumnFamily,
    name: &str,
) -> Result<Option<ModelIndicator>> {
    txn.get_for_update_cf(cf, name.as_bytes(), EXCLUSIVE)
        .context("cannot read model indicator")?
        .map(|value| ModelIndicator::from_key_value(name.as_bytes(), &value))
        .transpose()
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use chrono::Utc;

    use super::*;
    use crate::{
        Agent, AgentStatus, EngineDocumentError, EngineDocumentRefs, EngineDocumentWrite,
        EngineInstanceState, ModelMethod, ModelOwner, ModelRun, NewTrainingDefinition, Node,
        NodeProfile, NodeTable, RemovedUnsupervisedRecords, RunId, TrainedWith,
        TrainingDefinitionState, TrainingDefinitionUpdate,
        model_lifecycle::ModelFilesPoint,
        test::{DbGuard, acquire_db_permit},
        training::{INSTANCE_REMOVED, TrainingHook},
    };

    const ENGINE: &str = "reconverge";
    const OTHER_ENGINE: &str = "reconverge-2";
    const UNNUMBERED: &str = "reconverge-unnumbered";
    const SENSOR: &str = "piglet";
    const CUSTOMER: u32 = 1;
    const OTHER_CUSTOMER: u32 = 2;
    const INDICATOR: &str = "tokens";
    const REASON: &str = "uninstalled";

    type Entries = Vec<(Vec<u8>, Vec<u8>)>;

    /// A store with three nodes: `node` of [`CUSTOMER`] with the engines
    /// [`ENGINE`] and [`OTHER_ENGINE`], an Unsupervised agent with no
    /// instance number and a sensor; `other_node` of [`OTHER_CUSTOMER`] with
    /// [`ENGINE`]; `bare_node`, with no applied profile, with [`ENGINE`].
    ///
    /// The store is shared so that a model-files hook can reach it.
    struct Fixture {
        _permit: DbGuard<'static>,
        store: Arc<Store>,
        _db_dir: tempfile::TempDir,
        _backup_dir: tempfile::TempDir,
        node: u32,
        other_node: u32,
        bare_node: u32,
    }

    impl Fixture {
        fn store(&self) -> &Store {
            &self.store
        }

        fn engine(&self) -> ModelInstance {
            instance(self.node, ENGINE)
        }

        fn other_engine(&self) -> ModelInstance {
            instance(self.node, OTHER_ENGINE)
        }
    }

    fn agent(key: &str, kind: AgentKind, instance: Option<u32>) -> Agent {
        let mut agent =
            Agent::new(0, key.to_string(), kind, AgentStatus::Enabled, None, None).unwrap();
        agent.instance = instance;
        agent
    }

    fn node_agents() -> Vec<Agent> {
        vec![
            agent(ENGINE, AgentKind::Unsupervised, Some(1)),
            agent(OTHER_ENGINE, AgentKind::Unsupervised, Some(2)),
            agent(UNNUMBERED, AgentKind::Unsupervised, None),
            agent(SENSOR, AgentKind::Sensor, Some(1)),
        ]
    }

    fn insert_node(store: &Store, name: &str, customer: Option<u32>, agents: Vec<Agent>) -> u32 {
        let node = Node {
            id: 0,
            name: name.to_string(),
            name_draft: None,
            profile: customer.map(|customer_id| NodeProfile {
                customer_id,
                description: String::new(),
                hostname: format!("{name}.example"),
            }),
            profile_draft: None,
            agents,
            external_services: Vec::new(),
            creation_time: Utc::now(),
        };
        store.node_map().put(&node).unwrap()
    }

    fn setup() -> Fixture {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
        let node = insert_node(&store, "node", Some(CUSTOMER), node_agents());
        let other_node = insert_node(
            &store,
            "other-node",
            Some(OTHER_CUSTOMER),
            vec![agent(ENGINE, AgentKind::Unsupervised, Some(1))],
        );
        let bare_node = insert_node(
            &store,
            "bare-node",
            None,
            vec![agent(ENGINE, AgentKind::Unsupervised, Some(1))],
        );
        Fixture {
            _permit: permit,
            store: Arc::new(store),
            _db_dir: db_dir,
            _backup_dir: backup_dir,
            node,
            other_node,
            bare_node,
        }
    }

    fn instance(node_id: u32, agent_key: &str) -> ModelInstance {
        ModelInstance {
            node_id,
            agent_key: agent_key.to_string(),
        }
    }

    fn new_definition(name: &str, instance: &ModelInstance) -> NewTrainingDefinition {
        NewTrainingDefinition {
            name: name.to_string(),
            customer_id: CUSTOMER,
            instance: instance.clone(),
            method: ModelMethod::Multidimension,
            event_kind: "http".to_string(),
            sources: vec!["sensor-a".to_string()],
            indicator: None,
            definition: "eps = 5.0".to_string(),
        }
    }

    fn define(store: &Store, name: &str, instance: &ModelInstance) {
        store
            .insert_training_definition(new_definition(name, instance))
            .unwrap();
    }

    /// An upload of a multidimension model of `http` events named `name`.
    fn body(name: &str) -> crate::model::Model {
        crate::model::Model {
            id: 0,
            name: name.to_string(),
            version: 1,
            kind: "Multifield".to_string(),
            serialized_classifier: b"classifier".to_vec(),
            max_event_id_num: 10,
            event_kind: "http".to_string(),
            classification_id: 1,
            batch_info: Vec::new(),
            scores: [(1, 0.5)].into_iter().collect(),
        }
    }

    /// Starts and completes a training run of the definition `name` on
    /// `instance`, returning the run id.
    fn train(store: &Store, name: &str, instance: &ModelInstance) -> RunId {
        let started = store.start_training_run(name).unwrap();
        store
            .complete_run(started.run.id, instance, body(name))
            .unwrap();
        started.run.id
    }

    /// Defines and trains the model `name` on `instance`.
    fn trained_model(store: &Store, name: &str, instance: &ModelInstance) -> RunId {
        define(store, name, instance);
        train(store, name, instance)
    }

    /// Starts a clone of `source` into a new definition `target` on `on`.
    fn start_clone(store: &Store, source: &str, target: &str, on: &ModelInstance) -> ModelRun {
        store
            .start_clone_run(
                source,
                model(store, source).trained_run_id,
                new_definition(target, on),
            )
            .unwrap()
    }

    fn model(store: &Store, name: &str) -> Model {
        store.model_map().load_model_by_name(name).unwrap()
    }

    fn has_model(store: &Store, name: &str) -> bool {
        store.model_map().load_model_by_name(name).is_ok()
    }

    fn run(store: &Store, id: RunId) -> ModelRun {
        store.model_run(id).unwrap().unwrap()
    }

    fn definition(store: &Store, name: &str) -> TrainingDefinition {
        store.training_definition(name).unwrap().unwrap()
    }

    fn state(store: &Store, name: &str) -> TrainingDefinitionState {
        store.training_definition_state(name).unwrap().unwrap()
    }

    fn add_indicator(store: &Store, name: &str, model_id: u32) {
        store
            .insert_model_indicator(ModelIndicator {
                name: name.to_string(),
                model_id,
                ..ModelIndicator::default()
            })
            .unwrap();
    }

    fn has_indicator(store: &Store, name: &str) -> bool {
        store.model_indicator_map().get(name).unwrap().is_some()
    }

    /// Gives the definition `name` the indicator `indicator`.
    fn set_definition_indicator(store: &Store, name: &str, indicator: &str) {
        let stored = definition(store, name);
        store
            .update_training_definition(
                name,
                TrainingDefinitionUpdate {
                    method: stored.method,
                    event_kind: stored.event_kind,
                    sources: stored.sources,
                    indicator: Some(indicator.to_string()),
                    definition: stored.definition,
                },
            )
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

    /// Writes the references of the agent `agent_key` of node `node_id`
    /// through [`NodeTable::update_with_engine_documents`], leaving the node
    /// as stored.
    fn link(
        store: &Store,
        node_id: u32,
        agent_key: &str,
        applied: Option<Vec<EngineDetectorRef>>,
        pending: Option<Vec<EngineDetectorRef>>,
    ) -> Result<()> {
        link_in(&mut store.node_map(), node_id, agent_key, applied, pending)
    }

    /// Writes the references as [`link`] does, through `nodes`.
    fn link_in(
        nodes: &mut NodeTable<'_>,
        node_id: u32,
        agent_key: &str,
        applied: Option<Vec<EngineDetectorRef>>,
        pending: Option<Vec<EngineDetectorRef>>,
    ) -> Result<()> {
        let node = nodes.get_by_id(node_id)?.unwrap().0;
        nodes.update_with_engine_documents(
            node_id,
            &node.clone().into(),
            &node.into(),
            &[EngineDocumentWrite {
                agent_key: agent_key.to_string(),
                applied: applied.map(|detectors| EngineDocumentRefs { detectors }),
                pending: pending.map(|detectors| EngineDocumentRefs { detectors }),
            }],
        )?;
        Ok(())
    }

    /// Writes the `engine instances` row of `instance` as is, past every
    /// check.
    fn put_row(store: &Store, instance: &ModelInstance, row: &Row) {
        let txn = store.states.db().transaction();
        store
            .states
            .engine_instances()
            .put(
                &txn,
                &tables::engine_instance_key(instance.node_id, &instance.agent_key),
                row,
            )
            .unwrap();
        txn.commit().unwrap();
    }

    /// Leaves the model `name` and its definition, if any, with no
    /// instance, past every check.
    fn unassign(store: &Store, name: &str) {
        let txn = store.states.db().transaction();
        let models = store.model_map();
        let record = models
            .load_model_by_name_in_transaction(name, &txn)
            .unwrap()
            .unwrap();
        models
            .update_model_with_transaction(
                &record,
                &Model {
                    instance: None,
                    ..record.clone()
                },
                &txn,
            )
            .unwrap();
        let definitions = store.states.training_definitions();
        if let Some(mut stored) = definitions.get_for_update(&txn, name).unwrap() {
            stored.instance = None;
            definitions.put(&txn, &stored).unwrap();
        }
        txn.commit().unwrap();
    }

    /// Returns `node` as stored, and as it is without the agent `key`.
    fn without_agent(store: &Store, node_id: u32, key: &str) -> (Node, Node) {
        let node = store.node_map().get_by_id(node_id).unwrap().unwrap().0;
        let mut without = node.clone();
        without.agents.retain(|a| a.key != key);
        (node, without)
    }

    /// Removes the agent `key` of node `node_id` through
    /// [`NodeTable::update`].
    fn uninstall(store: &Store, node_id: u32, key: &str) {
        let (node, without) = without_agent(store, node_id, key);
        store
            .node_map()
            .update(node_id, &node.into(), &without.into())
            .unwrap();
    }

    fn family(store: &Store, name: &str) -> Entries {
        let db = store.states.db();
        db.iterator_cf(db.cf_handle(name).unwrap(), IteratorMode::Start)
            .map(|entry| {
                let (key, value) = entry.unwrap();
                (key.to_vec(), value.to_vec())
            })
            .collect()
    }

    /// The families a guarded write or a detach reads or writes, but for
    /// the agents and nodes.
    const RECORD_FAMILIES: [&str; 10] = [
        tables::TRAINING_DEFINITIONS,
        tables::MODEL_RUNS,
        tables::META,
        tables::MODELS,
        tables::SCORES,
        tables::BATCH_INFO,
        tables::PREVIOUS_SCORES,
        tables::PREVIOUS_BATCH_INFO,
        tables::ENGINE_INSTANCES,
        tables::MODEL_INDICATORS,
    ];

    fn dump_records(store: &Store) -> Vec<Entries> {
        RECORD_FAMILIES
            .into_iter()
            .map(|name| family(store, name))
            .collect()
    }

    /// Every row of the families a guarded write or a detach reads or
    /// writes.
    fn dump(store: &Store) -> Vec<Entries> {
        let mut entries = dump_records(store);
        entries.push(family(store, tables::AGENTS));
        entries.push(family(store, tables::NODES));
        entries
    }

    /// Runs `write`, asserting that it is refused with a [`TrainingError`]
    /// and changes nothing, and returns the refusal.
    fn refusal<T: std::fmt::Debug>(
        store: &Store,
        write: impl FnOnce(&Store) -> Result<T>,
    ) -> TrainingError {
        let before = dump(store);
        let error = write(store).unwrap_err();
        assert_eq!(dump(store), before, "a refusal changes nothing: {error:#}");
        error
            .downcast_ref::<TrainingError>()
            .unwrap_or_else(|| panic!("not a training error: {error:#}"))
            .clone()
    }

    /// Returns a training hook that runs `action` the first time it is
    /// called and does nothing afterwards.
    fn once(action: impl Fn(&Store) + Send + Sync + 'static) -> TrainingHook {
        let fired = AtomicBool::new(false);
        Arc::new(move |store| {
            if !fired.swap(true, Ordering::SeqCst) {
                action(store);
            }
            Ok(())
        })
    }

    /// Sets a model-files hook that runs `action` at the first
    /// `BeforeCommit`, and returns the number of `BeforeCommit` points
    /// reached.
    fn once_before_commit(
        f: &Fixture,
        action: impl Fn(&Store) + Send + Sync + 'static,
    ) -> Arc<AtomicUsize> {
        let reached = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reached);
        let store = Arc::downgrade(&f.store);
        f.store.set_model_files_hook(Some(Arc::new(move |point| {
            if point == ModelFilesPoint::BeforeCommit
                && counter.fetch_add(1, Ordering::SeqCst) == 0
                && let Some(store) = store.upgrade()
            {
                action(&store);
            }
            Ok(())
        })));
        reached
    }

    fn in_use(name: &str, instance: ModelInstance, detector_id: i32) -> TrainingError {
        TrainingError::ModelInUse {
            name: name.to_string(),
            instance,
            detector_id,
        }
    }

    fn by_detector(instance: ModelInstance, detector_id: i32) -> Referrer {
        Referrer::Detector {
            instance,
            detector_id,
        }
    }

    fn by_definition(name: &str) -> Referrer {
        Referrer::Definition {
            name: name.to_string(),
        }
    }

    fn indicator_in_use(indicator: &str, by: Referrer) -> TrainingError {
        TrainingError::IndicatorInUse {
            indicator: indicator.to_string(),
            by,
        }
    }

    #[test]
    fn delete_refuses_a_model_a_document_links() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        trained_model(store, "m", &engine);
        trained_model(store, "n", &engine);

        link(
            store,
            f.node,
            ENGINE,
            Some(vec![detector(3, "n", None)]),
            Some(vec![detector(4, "n", None), detector(5, "m", None)]),
        )
        .unwrap();
        assert_eq!(
            refusal(store, |s| s.delete_model("m")),
            in_use("m", engine.clone(), 5)
        );

        // The applied document's detector comes first by id. Detector 3
        // keeps its id, which the applied document already names, and now
        // serves `m`.
        link(
            store,
            f.node,
            ENGINE,
            Some(vec![detector(3, "m", None)]),
            None,
        )
        .unwrap();
        assert_eq!(
            refusal(store, |s| s.delete_model("m")),
            in_use("m", engine.clone(), 3)
        );

        link(store, f.node, ENGINE, None, Some(Vec::new())).unwrap();
        assert_eq!(
            refusal(store, |s| s.delete_model("m")),
            in_use("m", engine.clone(), 3)
        );

        link(store, f.node, ENGINE, Some(Vec::new()), None).unwrap();
        store.delete_model("m").unwrap();
        assert!(!has_model(store, "m"));
    }

    /// A reference on another instance that names the model, written past
    /// every check, also refuses the delete; the first in table order is named.
    #[test]
    fn delete_refuses_a_model_a_reference_on_another_instance_names() {
        let f = setup();
        let store = f.store();
        trained_model(store, "m", &f.engine());
        put_row(
            store,
            &instance(f.other_node, ENGINE),
            &Row {
                applied: EngineDocumentRefs {
                    detectors: vec![detector(1, "m", None)],
                },
                ..Row::default()
            },
        );
        put_row(
            store,
            &f.other_engine(),
            &Row {
                pending: EngineDocumentRefs {
                    detectors: vec![detector(7, "m", None)],
                },
                ..Row::default()
            },
        );
        assert_eq!(
            refusal(store, |s| s.delete_model("m")),
            in_use("m", f.other_engine(), 7)
        );
    }

    #[test]
    fn delete_refuses_a_model_with_an_active_run() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        trained_model(store, "m", &engine);

        let retrain = store.start_training_run("m").unwrap().run.id;
        assert_eq!(
            refusal(store, |s| s.delete_model("m")),
            TrainingError::RunInProgress { run_id: retrain }
        );
        store.fail_run(retrain, "unreachable").unwrap();

        let clone = start_clone(store, "m", "c", &f.other_engine());
        assert_eq!(
            refusal(store, |s| s.delete_model("m")),
            TrainingError::RunInProgress { run_id: clone.id }
        );
        store.fail_run(clone.id, "unreachable").unwrap();
        store.delete_model("m").unwrap();
    }

    #[test]
    fn delete_refuses_a_model_whose_indicator_is_named() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        trained_model(store, "m", &engine);
        trained_model(store, "n", &engine);
        let id = model(store, "m").id;
        add_indicator(store, "a-unused", id);
        add_indicator(store, INDICATOR, id);

        // A detector of another model's document.
        link(
            store,
            f.node,
            ENGINE,
            None,
            Some(vec![detector(2, "n", Some(INDICATOR))]),
        )
        .unwrap();
        assert_eq!(
            refusal(store, |s| s.delete_model("m")),
            indicator_in_use(INDICATOR, by_detector(engine.clone(), 2))
        );
        link(store, f.node, ENGINE, None, Some(Vec::new())).unwrap();

        // Another model's definition.
        set_definition_indicator(store, "n", INDICATOR);
        assert_eq!(
            refusal(store, |s| s.delete_model("m")),
            indicator_in_use(INDICATOR, by_definition("n"))
        );
    }

    #[test]
    fn its_own_definition_naming_its_indicator_does_not_block_a_delete() {
        let f = setup();
        let store = f.store();
        trained_model(store, "m", &f.engine());
        add_indicator(store, INDICATOR, model(store, "m").id);
        set_definition_indicator(store, "m", INDICATOR);

        store.delete_model("m").unwrap();
        assert!(!has_model(store, "m"));
        assert!(!has_indicator(store, INDICATOR));
        assert_eq!(store.training_definition("m").unwrap(), None);
    }

    #[test]
    fn a_delete_removes_the_definition_runs_and_previous_result() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        let first = trained_model(store, "m", &engine);
        let second = train(store, "m", &engine);
        let failed = store.start_training_run("m").unwrap().run.id;
        store.fail_run(failed, "unreachable").unwrap();
        assert!(model(store, "m").previous.is_some());
        assert_ne!(family(store, tables::PREVIOUS_SCORES), Entries::new());

        // A clone from it creates another model, whose run history it is.
        let clone = start_clone(store, "m", "c", &f.other_engine());
        store.complete_run(clone.id, &engine, body("c")).unwrap();

        store.delete_model("m").unwrap();
        assert!(!has_model(store, "m"));
        assert_eq!(store.training_definition("m").unwrap(), None);
        for id in [first, second, failed] {
            assert_eq!(store.model_run(id).unwrap(), None);
        }
        assert_eq!(family(store, tables::PREVIOUS_SCORES), Entries::new());
        assert_eq!(family(store, tables::PREVIOUS_BATCH_INFO), Entries::new());
        assert_eq!(run(store, clone.id).state, RunState::Succeeded);
        assert_eq!(store.model_runs("m").unwrap(), vec![run(store, clone.id)]);
        assert!(has_model(store, "c"));
        assert_eq!(state(store, "c"), TrainingDefinitionState::Ready);
    }

    #[test]
    fn delete_refuses_an_unknown_model() {
        let f = setup();
        let store = f.store();
        let refused = refusal(store, |s| s.delete_model("missing"));
        assert_eq!(
            refused,
            TrainingError::ModelNotFound {
                name: "missing".to_string()
            }
        );
        assert_eq!(refused.to_string(), "model \"missing\" not found");
    }

    #[test]
    fn insert_model_indicator_refuses_an_existing_name() {
        let f = setup();
        let store = f.store();
        add_indicator(store, INDICATOR, 3);
        assert_eq!(
            refusal(store, |s| s.insert_model_indicator(ModelIndicator {
                name: INDICATOR.to_string(),
                model_id: 4,
                ..ModelIndicator::default()
            })),
            TrainingError::IndicatorExists {
                indicator: INDICATOR.to_string()
            }
        );
        let stored = store.model_indicator_map().get(INDICATOR).unwrap().unwrap();
        assert_eq!(stored.model_id, 3);
    }

    #[test]
    fn update_model_indicator_refusals() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        trained_model(store, "m", &engine);
        let id = model(store, "m").id;
        add_indicator(store, INDICATOR, id);
        let changed = |model_id| ModelIndicator {
            name: INDICATOR.to_string(),
            description: "changed".to_string(),
            model_id,
            ..ModelIndicator::default()
        };

        assert_eq!(
            refusal(store, |s| s.update_model_indicator(ModelIndicator {
                name: "missing".to_string(),
                ..ModelIndicator::default()
            })),
            TrainingError::IndicatorNotFound {
                indicator: "missing".to_string()
            }
        );
        assert_eq!(
            refusal(store, |s| s.update_model_indicator(changed(id + 1))),
            TrainingError::IndicatorModelChange {
                indicator: INDICATOR.to_string(),
                model_id: id,
                new_model_id: id + 1,
            }
        );

        link(
            store,
            f.node,
            ENGINE,
            None,
            Some(vec![detector(6, "m", Some(INDICATOR))]),
        )
        .unwrap();
        assert_eq!(
            refusal(store, |s| s.update_model_indicator(changed(id))),
            indicator_in_use(INDICATOR, by_detector(engine.clone(), 6))
        );
        link(
            store,
            f.node,
            ENGINE,
            Some(vec![detector(8, "m", Some(INDICATOR))]),
            Some(Vec::new()),
        )
        .unwrap();
        assert_eq!(
            refusal(store, |s| s.update_model_indicator(changed(id))),
            indicator_in_use(INDICATOR, by_detector(engine.clone(), 8))
        );
        link(store, f.node, ENGINE, Some(Vec::new()), None).unwrap();

        // Its own model's definition holds it too.
        set_definition_indicator(store, "m", INDICATOR);
        assert_eq!(
            refusal(store, |s| s.update_model_indicator(changed(id))),
            indicator_in_use(INDICATOR, by_definition("m"))
        );
    }

    #[test]
    fn update_model_indicator_replaces_it_as_given() {
        let f = setup();
        let store = f.store();
        add_indicator(store, INDICATOR, 3);
        let modified = chrono::DateTime::from_timestamp(1_000, 0).unwrap();
        store
            .update_model_indicator(ModelIndicator {
                name: INDICATOR.to_string(),
                description: "changed".to_string(),
                model_id: 3,
                tokens: [vec!["a".to_string()]].into_iter().collect(),
                last_modification_time: modified,
            })
            .unwrap();
        let stored = store.model_indicator_map().get(INDICATOR).unwrap().unwrap();
        assert_eq!(stored.description, "changed");
        assert_eq!(stored.model_id, 3);
        assert_eq!(stored.tokens.len(), 1);
        assert_eq!(stored.last_modification_time, modified);
    }

    #[test]
    fn remove_model_indicators_is_all_or_none() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        trained_model(store, "m", &engine);
        let id = model(store, "m").id;
        for name in ["a", "b", "c"] {
            add_indicator(store, name, id);
        }
        link(
            store,
            f.node,
            ENGINE,
            None,
            Some(vec![detector(1, "m", Some("c"))]),
        )
        .unwrap();
        define(store, "d", &engine);
        set_definition_indicator(store, "d", "b");

        let names =
            |names: &[&str]| -> Vec<String> { names.iter().map(ToString::to_string).collect() };
        assert_eq!(
            refusal(store, |s| s
                .remove_model_indicators(&names(&["a", "c", "b"]))),
            indicator_in_use("c", by_detector(engine.clone(), 1))
        );
        assert_eq!(
            refusal(store, |s| s
                .remove_model_indicators(&names(&["a", "b", "c"]))),
            indicator_in_use("b", by_definition("d"))
        );
        assert!(has_indicator(store, "a"));

        let before = dump(store);
        store.remove_model_indicators(&[]).unwrap();
        assert_eq!(dump(store), before);

        store
            .remove_model_indicators(&names(&["missing", "a"]))
            .unwrap();
        assert!(!has_indicator(store, "a"));
        assert!(has_indicator(store, "b"));
        assert!(has_indicator(store, "c"));
    }

    #[test]
    fn assign_model_refusals() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        trained_model(store, "m", &f.other_engine());

        assert_eq!(
            refusal(store, |s| s.assign_model("missing", &engine)),
            TrainingError::ModelNotFound {
                name: "missing".to_string()
            }
        );
        assert_eq!(
            refusal(store, |s| s.assign_model("m", &engine)),
            TrainingError::ModelHasInstance {
                name: "m".to_string(),
                instance: f.other_engine(),
            }
        );

        unassign(store, "m");
        for target in [
            instance(f.node, "missing"),
            instance(f.node, UNNUMBERED),
            instance(f.node, SENSOR),
        ] {
            assert_eq!(
                refusal(store, |s| s.assign_model("m", &target)),
                TrainingError::InstanceNotEligible {
                    node_id: f.node,
                    agent_key: target.agent_key.clone(),
                }
            );
        }
        assert_eq!(
            refusal(store, |s| s
                .assign_model("m", &instance(f.bare_node, ENGINE))),
            TrainingError::NoAppliedProfile {
                node_id: f.bare_node
            }
        );
        assert_eq!(
            refusal(store, |s| s
                .assign_model("m", &instance(f.other_node, ENGINE))),
            TrainingError::CustomerMismatch {
                node_id: f.other_node,
                node_customer_id: OTHER_CUSTOMER,
                customer_id: CUSTOMER,
            }
        );
    }

    #[test]
    fn assign_model_moves_the_model_and_its_definition() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        trained_model(store, "m", &f.other_engine());
        unassign(store, "m");
        assert_eq!(state(store, "m"), TrainingDefinitionState::NoInstance);
        let record = model(store, "m");
        let stored = definition(store, "m");

        store.assign_model("m", &engine).unwrap();
        assert_eq!(
            model(store, "m"),
            Model {
                instance: Some(engine.clone()),
                ..record
            }
        );
        assert_eq!(
            definition(store, "m"),
            TrainingDefinition {
                instance: Some(engine.clone()),
                ..stored
            }
        );
        assert_eq!(state(store, "m"), TrainingDefinitionState::Ready);
        assert_eq!(
            store.engine_instance_owns_models(&engine).unwrap(),
            ["m".to_string()]
        );
    }

    #[test]
    fn assign_model_moves_a_model_without_a_definition() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        store
            .replace_model(
                body("bare"),
                ModelOwner {
                    customer_id: CUSTOMER,
                    instance: f.other_engine(),
                },
                Utc::now(),
                TrainedWith {
                    run_id: 0,
                    definition: "eps = 1.0".to_string(),
                    sources: Vec::new(),
                },
            )
            .unwrap();
        unassign(store, "bare");

        store.assign_model("bare", &engine).unwrap();
        assert_eq!(model(store, "bare").instance, Some(engine));
        assert_eq!(store.training_definition("bare").unwrap(), None);
    }

    /// The records of [`populate`].
    struct Populated {
        /// The active training run of `a` on `ENGINE`.
        training: RunId,
        /// The active clone run `OTHER_ENGINE` performs from `s` into `t` on
        /// `ENGINE`.
        clone: RunId,
    }

    /// Gives `ENGINE` the model and definition `a` with an active training
    /// run, the definition `b`, the cloning reservation `t` of a clone that
    /// `OTHER_ENGINE` performs from its model `s`, a pending reference to
    /// `a` and a detector status.
    fn populate(f: &Fixture) -> Populated {
        let store = f.store();
        let engine = f.engine();
        trained_model(store, "a", &engine);
        define(store, "b", &engine);
        trained_model(store, "s", &f.other_engine());
        let clone = start_clone(store, "s", "t", &engine).id;
        let training = store.start_training_run("a").unwrap().run.id;
        link(
            store,
            f.node,
            ENGINE,
            None,
            Some(vec![detector(1, "a", None)]),
        )
        .unwrap();
        store
            .set_detector_status(
                &engine,
                1,
                &crate::DetectorStatus {
                    state: crate::DetectorState::Running,
                    finished_at: None,
                    outcome: None,
                    reason: None,
                    events: 0,
                    sources: Vec::new(),
                    reported_at: Utc::now(),
                },
            )
            .unwrap();
        assert_eq!(
            store.engine_instance_owns_models(&engine).unwrap(),
            ["a", "b", "t"]
        );
        assert_eq!(
            store
                .engine_instance_owns_models(&f.other_engine())
                .unwrap(),
            ["s"]
        );
        Populated { training, clone }
    }

    /// Asserts that `ENGINE` is detached as [`populate`] left it, its
    /// training run failed with `reason`.
    fn assert_detached(f: &Fixture, populated: &Populated, reason: &str) {
        let store = f.store();
        let engine = f.engine();
        assert_eq!(model(store, "a").instance, None);
        for name in ["a", "b"] {
            assert_eq!(definition(store, name).instance, None);
            assert_eq!(state(store, name), TrainingDefinitionState::NoInstance);
        }
        let failed = run(store, populated.training);
        assert_eq!(failed.state, RunState::Failed);
        assert_eq!(failed.reason.as_deref(), Some(reason));
        assert_eq!(store.model_run(populated.clone).unwrap(), None);
        assert_eq!(store.training_definition("t").unwrap(), None);
        // The detector id mark, 1 from the detector `populate` links,
        // outlives the detach; it is read through the node's hostname, so it
        // reads 0 once the node is gone.
        let node_kept = store.node_map().get_by_id(f.node).unwrap().is_some();
        assert_eq!(
            store.engine_instance_state(&engine).unwrap(),
            EngineInstanceState {
                instance: engine.clone(),
                stopped: false,
                applied: EngineDocumentRefs::default(),
                pending: EngineDocumentRefs::default(),
                last_detector_id: i32::from(node_kept),
            }
        );
        assert!(
            store
                .engine_instance_states()
                .unwrap()
                .iter()
                .all(|state| state.instance != engine)
        );
        assert_eq!(store.detector_statuses(&engine).unwrap(), Vec::new());
        assert_eq!(
            store.engine_instance_owns_models(&engine).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn detach_engine_instance_detaches_an_instance_whose_row_is_gone() {
        let f = setup();
        let store = f.store();
        let populated = populate(&f);
        let kept = model(store, "s");
        let id = model(store, "a").id;
        add_indicator(store, INDICATOR, id);

        store.agents_map().delete(f.node, ENGINE).unwrap();
        store.detach_engine_instance(&f.engine(), REASON).unwrap();
        assert_detached(&f, &populated, REASON);
        assert_eq!(model(store, "s"), kept);
        assert!(has_indicator(store, INDICATOR));

        // The freed name can be taken again.
        define(store, "t", &f.other_engine());

        let before = dump(store);
        store.detach_engine_instance(&f.engine(), REASON).unwrap();
        assert_eq!(dump(store), before, "a second detach changes nothing");
    }

    #[test]
    fn detach_fails_a_clone_the_instance_performs() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        trained_model(store, "a", &engine);
        let clone = start_clone(store, "a", "u", &f.other_engine());

        store.agents_map().delete(f.node, ENGINE).unwrap();
        store.detach_engine_instance(&engine, REASON).unwrap();
        assert_eq!(store.model_run(clone.id).unwrap(), None);
        assert_eq!(store.training_definition("u").unwrap(), None);
        assert_eq!(model(store, "a").instance, None);
        define(store, "u", &f.other_engine());
    }

    #[test]
    fn detach_removes_the_row_and_stopped_state() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        store.set_engine_instance_stopped(&engine, true).unwrap();
        store.agents_map().delete(f.node, ENGINE).unwrap();
        store.detach_engine_instance(&engine, REASON).unwrap();
        assert!(!store.engine_instance_state(&engine).unwrap().stopped);
        assert_eq!(
            store.engine_instance_states().unwrap(),
            Vec::<EngineInstanceState>::new()
        );
    }

    #[test]
    fn detach_of_a_key_without_records_changes_nothing() {
        let f = setup();
        let store = f.store();
        populate(&f);
        let before = dump(store);
        for key in [SENSOR, "missing"] {
            store
                .detach_engine_instance(&instance(f.node, key), REASON)
                .unwrap();
        }
        store
            .detach_engine_instance(&instance(f.other_node + 100, ENGINE), REASON)
            .unwrap();
        assert_eq!(dump(store), before);
    }

    #[test]
    fn detach_changes_nothing_while_an_unsupervised_row_exists() {
        let f = setup();
        let store = f.store();
        populate(&f);
        let before = dump(store);
        store.detach_engine_instance(&f.engine(), REASON).unwrap();
        // An Unsupervised row with no instance number is installed too.
        store
            .detach_engine_instance(&instance(f.node, UNNUMBERED), REASON)
            .unwrap();
        assert_eq!(dump(store), before);
    }

    #[test]
    fn source_references_lists_detectors_then_definitions() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        let other = f.other_engine();
        trained_model(store, "m", &engine);
        trained_model(store, "n", &engine);
        trained_model(store, "o", &other);
        let with_sources = |id, model: &str, sources: &[&str]| EngineDetectorRef {
            sources: sources.iter().map(ToString::to_string).collect(),
            ..detector(id, model, None)
        };
        link(
            store,
            f.node,
            ENGINE,
            Some(vec![with_sources(1, "m", &["x", "y"])]),
            Some(vec![
                with_sources(1, "m", &["z"]),
                with_sources(2, "n", &["y"]),
            ]),
        )
        .unwrap();
        link(
            store,
            f.node,
            OTHER_ENGINE,
            None,
            Some(vec![with_sources(3, "o", &["x"])]),
        )
        .unwrap();
        for (name, sources) in [("d1", vec!["y", "x"]), ("d0", vec!["w"])] {
            let mut new = new_definition(name, &engine);
            new.sources = sources.into_iter().map(ToString::to_string).collect();
            store.insert_training_definition(new).unwrap();
        }

        let query: Vec<String> = ["y", "x", "y", "q", "z"]
            .into_iter()
            .map(ToString::to_string)
            .collect();
        let reference = |source: &str, by: Referrer| SourceReference {
            source: source.to_string(),
            by,
        };
        assert_eq!(
            store.source_references(&query).unwrap(),
            vec![
                reference("y", by_detector(engine.clone(), 1)),
                reference("x", by_detector(engine.clone(), 1)),
                reference("z", by_detector(engine.clone(), 1)),
                reference("y", by_detector(engine.clone(), 2)),
                reference("x", by_detector(other.clone(), 3)),
                reference("y", by_definition("d1")),
                reference("x", by_definition("d1")),
            ]
        );
        assert_eq!(store.source_references(&[]).unwrap(), Vec::new());
    }

    #[test]
    fn uninstall_through_update_detaches_the_instance() {
        let f = setup();
        let store = f.store();
        let populated = populate(&f);
        let (node, without) = without_agent(store, f.node, ENGINE);
        store
            .node_map()
            .update(f.node, &node.clone().into(), &without.clone().into())
            .unwrap();
        assert_detached(&f, &populated, INSTANCE_REMOVED);

        // Reinstalling under the same key reattaches nothing.
        store
            .node_map()
            .update(f.node, &without.into(), &node.into())
            .unwrap();
        assert_eq!(
            store.engine_instance_owns_models(&f.engine()).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(state(store, "a"), TrainingDefinitionState::NoInstance);
    }

    #[test]
    fn uninstall_through_update_with_engine_documents_detaches_the_instance() {
        let f = setup();
        let store = f.store();
        let populated = populate(&f);
        let (node, without) = without_agent(store, f.node, ENGINE);
        store
            .node_map()
            .update_with_engine_documents(f.node, &node.into(), &without.into(), &[])
            .unwrap();
        assert_detached(&f, &populated, INSTANCE_REMOVED);
    }

    #[test]
    fn removing_the_node_detaches_its_instances() {
        let f = setup();
        let store = f.store();
        let populated = populate(&f);
        store.node_map().remove(f.node).unwrap();
        assert_detached(&f, &populated, INSTANCE_REMOVED);
        assert_eq!(model(store, "s").instance, None);
        assert_eq!(definition(store, "s").instance, None);

        let reinserted = insert_node(store, "reinserted", Some(CUSTOMER), node_agents());
        assert_eq!(reinserted, f.node, "the node id is reused");
        for key in [ENGINE, OTHER_ENGINE] {
            assert_eq!(
                store
                    .engine_instance_owns_models(&instance(f.node, key))
                    .unwrap(),
                Vec::<String>::new()
            );
        }
    }

    #[test]
    fn removing_an_agent_without_records_changes_nothing_else() {
        let f = setup();
        let store = f.store();
        populate(&f);
        let before = dump_records(store);
        uninstall(store, f.node, SENSOR);
        assert!(store.agents_map().get(f.node, SENSOR).unwrap().is_none());
        assert_eq!(dump_records(store), before);
    }

    /// A link written after the delete's guard read and before its commit
    /// makes the delete retry and refuse, whether the instance's row
    /// existed or the link is its first.
    #[test]
    fn a_link_racing_a_delete_refuses_it() {
        for row_exists in [true, false] {
            let f = setup();
            let store = f.store();
            let engine = f.engine();
            trained_model(store, "m", &engine);
            trained_model(store, "n", &engine);
            if row_exists {
                link(
                    store,
                    f.node,
                    ENGINE,
                    None,
                    Some(vec![detector(1, "n", None)]),
                )
                .unwrap();
            }
            let node = f.node;
            let reached = once_before_commit(&f, move |store| {
                link(
                    store,
                    node,
                    ENGINE,
                    None,
                    Some(vec![detector(1, "n", None), detector(2, "m", None)]),
                )
                .unwrap();
            });
            let error = store.delete_model("m").unwrap_err();
            store.set_model_files_hook(None);
            assert_eq!(reached.load(Ordering::SeqCst), 1, "the retry refuses");
            assert_eq!(
                error.downcast_ref::<TrainingError>(),
                Some(&in_use("m", engine.clone(), 2)),
                "{row_exists}"
            );
            assert!(has_model(store, "m"));
        }
    }

    #[test]
    fn a_clone_racing_a_delete_refuses_it() {
        let f = setup();
        let store = f.store();
        trained_model(store, "m", &f.engine());
        let target = f.other_engine();
        let reached = once_before_commit(&f, move |store| {
            start_clone(store, "m", "c", &target);
        });
        let error = store.delete_model("m").unwrap_err();
        store.set_model_files_hook(None);
        assert_eq!(reached.load(Ordering::SeqCst), 1, "the retry refuses");
        let clone = definition(store, "c").last_run.unwrap();
        assert_eq!(
            error.downcast_ref::<TrainingError>(),
            Some(&TrainingError::RunInProgress { run_id: clone })
        );
        assert!(has_model(store, "m"));
    }

    #[test]
    fn a_link_racing_an_indicator_removal_refuses_it() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        trained_model(store, "m", &engine);
        add_indicator(store, INDICATOR, model(store, "m").id);
        link(
            store,
            f.node,
            ENGINE,
            None,
            Some(vec![detector(1, "m", None)]),
        )
        .unwrap();
        let node = f.node;
        store.set_training_hook(Some(once(move |store| {
            link(
                store,
                node,
                ENGINE,
                None,
                Some(vec![detector(1, "m", Some(INDICATOR))]),
            )
            .unwrap();
        })));
        let error = store
            .remove_model_indicators(&[INDICATOR.to_string()])
            .unwrap_err();
        store.set_training_hook(None);
        assert_eq!(
            error.downcast_ref::<TrainingError>(),
            Some(&indicator_in_use(INDICATOR, by_detector(engine, 1)))
        );
        assert!(has_indicator(store, INDICATOR));
    }

    /// Removes `ENGINE` through [`NodeTable::update`] with a before-commit
    /// hook that runs `action` once, asserting that the removal retried.
    fn uninstall_racing(f: &Fixture, action: impl Fn(&Store) -> Result<()>) {
        let store = f.store();
        let (node, without) = without_agent(store, f.node, ENGINE);
        let fired = Cell::new(0);
        let mut nodes = store.node_map();
        nodes.set_before_commit_hook(Some(Box::new(|| {
            fired.set(fired.get() + 1);
            if fired.get() == 1 {
                action(store)?;
            }
            Ok(())
        })));
        nodes.update(f.node, &node.into(), &without.into()).unwrap();
        drop(nodes);
        assert_eq!(fired.get(), 2, "the removal retried");
    }

    #[test]
    fn a_run_started_before_an_uninstall_commits_is_failed() {
        let f = setup();
        let store = f.store();
        define(store, "a", &f.engine());
        uninstall_racing(&f, |store| store.start_training_run("a").map(|_| ()));
        let failed = run(store, definition(store, "a").last_run.unwrap());
        assert_eq!(failed.state, RunState::Failed);
        assert_eq!(failed.reason.as_deref(), Some(INSTANCE_REMOVED));
        assert_eq!(state(store, "a"), TrainingDefinitionState::NoInstance);
    }

    #[test]
    fn a_run_completed_before_an_uninstall_commits_leaves_its_model_detached() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        trained_model(store, "a", &engine);
        let retrain = store.start_training_run("a").unwrap().run.id;

        uninstall_racing(&f, |store| {
            store
                .complete_run(retrain, &f.engine(), body("a"))
                .map(|_| ())
        });
        assert_eq!(run(store, retrain).state, RunState::Succeeded);
        let completed = model(store, "a");
        assert_eq!(completed.trained_run_id, retrain);
        assert_eq!(completed.instance, None);
        assert_eq!(definition(store, "a").instance, None);
    }

    #[test]
    fn a_model_assigned_before_an_uninstall_commits_is_detached() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        trained_model(store, "free", &f.other_engine());
        unassign(store, "free");
        trained_model(store, "late", &f.other_engine());
        unassign(store, "late");

        uninstall_racing(&f, |store| store.assign_model("free", &engine));
        assert_eq!(model(store, "free").instance, None);
        assert_eq!(definition(store, "free").instance, None);

        assert_eq!(
            refusal(store, |s| s.assign_model("late", &engine)),
            TrainingError::InstanceNotEligible {
                node_id: f.node,
                agent_key: ENGINE.to_string(),
            }
        );
    }

    #[test]
    fn an_uninstall_committing_first_refuses_an_assign() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        trained_model(store, "free", &f.other_engine());
        unassign(store, "free");
        let node = f.node;
        store.set_training_hook(Some(once(move |store| {
            uninstall(store, node, ENGINE);
        })));
        let error = store.assign_model("free", &engine).unwrap_err();
        store.set_training_hook(None);
        assert_eq!(
            error.downcast_ref::<TrainingError>(),
            Some(&TrainingError::InstanceNotEligible {
                node_id: f.node,
                agent_key: ENGINE.to_string(),
            })
        );
        assert_eq!(model(store, "free").instance, None);
    }

    #[test]
    fn a_definition_inserted_before_an_uninstall_commits_is_detached() {
        let f = setup();
        let store = f.store();
        let engine = f.engine();
        uninstall_racing(&f, |store| {
            store.insert_training_definition(new_definition("late", &engine))
        });
        assert_eq!(definition(store, "late").instance, None);
        assert_eq!(state(store, "late"), TrainingDefinitionState::NoInstance);

        assert_eq!(
            refusal(store, |s| s
                .insert_training_definition(new_definition("later", &engine))),
            TrainingError::InstanceNotEligible {
                node_id: f.node,
                agent_key: ENGINE.to_string(),
            }
        );
    }

    /// The model whose indicator [`INDICATOR`] another customer's holder
    /// names.
    const NAMED: &str = "m";
    /// The model of [`OTHER_CUSTOMER`] a holder's detector names.
    const FOREIGN: &str = "o";
    /// The definition of [`OTHER_CUSTOMER`] that names [`INDICATOR`].
    const HOLDER: &str = "x";

    /// What names an indicator of a customer being removed, written
    /// through the public writers.
    #[derive(Clone, Copy, Debug)]
    enum Holder {
        /// A definition of another customer, created naming it.
        NewDefinition,
        /// A definition of another customer, updated to name it.
        UpdatedDefinition,
        /// A detector of another customer's applied document.
        Applied,
        /// A detector of another customer's pending document.
        Pending,
    }

    impl Holder {
        const ALL: [Self; 4] = [
            Self::NewDefinition,
            Self::UpdatedDefinition,
            Self::Applied,
            Self::Pending,
        ];

        /// Writes, before the reference, what it is written to.
        fn prepare(self, f: &Fixture) {
            if let Self::UpdatedDefinition = self {
                define_foreign(f.store(), HOLDER, f.other_node, None);
            }
        }

        /// Writes the reference to [`INDICATOR`].
        fn write(self, store: &Store, other_node: u32) -> Result<()> {
            self.write_in(store, &mut store.node_map(), other_node, Some(INDICATOR))
        }

        /// Writes the reference to `indicator`, or removes it if `None`, a
        /// detector through `nodes`.
        fn write_in(
            self,
            store: &Store,
            nodes: &mut NodeTable<'_>,
            other_node: u32,
            indicator: Option<&str>,
        ) -> Result<()> {
            let detectors = vec![detector(1, FOREIGN, indicator)];
            match self {
                Self::NewDefinition => {
                    if indicator.is_none() {
                        return store.remove_training_definition(HOLDER);
                    }
                    store.insert_training_definition(foreign_definition(
                        HOLDER, other_node, indicator,
                    ))
                }
                Self::UpdatedDefinition => {
                    let stored = definition(store, HOLDER);
                    store.update_training_definition(
                        HOLDER,
                        TrainingDefinitionUpdate {
                            method: stored.method,
                            event_kind: stored.event_kind,
                            sources: stored.sources,
                            indicator: indicator.map(ToString::to_string),
                            definition: stored.definition,
                        },
                    )
                }
                Self::Applied => link_in(nodes, other_node, ENGINE, Some(detectors), None),
                Self::Pending => link_in(nodes, other_node, ENGINE, None, Some(detectors)),
            }
        }

        /// Removes the reference.
        fn release(self, store: &Store, other_node: u32) {
            self.write_in(store, &mut store.node_map(), other_node, None)
                .unwrap();
        }

        fn referrer(self, f: &Fixture) -> Referrer {
            match self {
                Self::NewDefinition | Self::UpdatedDefinition => by_definition(HOLDER),
                Self::Applied | Self::Pending => by_detector(instance(f.other_node, ENGINE), 1),
            }
        }

        /// Writes the reference with `action` run once after the writer's
        /// checks and before its first commit, returning what the writer
        /// returns.
        fn write_racing(
            self,
            f: &Fixture,
            action: impl Fn(&Store) + Send + Sync + 'static,
        ) -> Result<()> {
            let store = f.store();
            match self {
                Self::NewDefinition | Self::UpdatedDefinition => {
                    store.set_training_hook(Some(once(action)));
                    let written = self.write(store, f.other_node);
                    store.set_training_hook(None);
                    written
                }
                Self::Applied | Self::Pending => {
                    let fired = Cell::new(0);
                    let mut nodes = store.node_map();
                    nodes.set_before_commit_hook(Some(Box::new(|| {
                        fired.set(fired.get() + 1);
                        if fired.get() == 1 {
                            action(store);
                        }
                        Ok(())
                    })));
                    let written = self.write_in(store, &mut nodes, f.other_node, Some(INDICATOR));
                    drop(nodes);
                    assert_eq!(fired.get(), 1, "the retry refuses before its commit");
                    written
                }
            }
        }
    }

    fn foreign_definition(
        name: &str,
        other_node: u32,
        indicator: Option<&str>,
    ) -> NewTrainingDefinition {
        NewTrainingDefinition {
            customer_id: OTHER_CUSTOMER,
            indicator: indicator.map(ToString::to_string),
            ..new_definition(name, &instance(other_node, ENGINE))
        }
    }

    fn define_foreign(store: &Store, name: &str, other_node: u32, indicator: Option<&str>) {
        store
            .insert_training_definition(foreign_definition(name, other_node, indicator))
            .unwrap();
    }

    /// A store where [`CUSTOMER`] has the trained model [`NAMED`] with the
    /// indicator [`INDICATOR`] and, if `earlier`, the trained model `a`
    /// before it in name order, and the definition `d` naming
    /// [`INDICATOR`]; [`OTHER_CUSTOMER`] has the trained model [`FOREIGN`].
    fn removal_fixture(earlier: bool) -> Fixture {
        let f = setup();
        let store = f.store();
        if earlier {
            trained_model(store, "a", &f.engine());
        }
        trained_model(store, NAMED, &f.engine());
        add_indicator(store, INDICATOR, model(store, NAMED).id);
        define(store, "d", &f.engine());
        set_definition_indicator(store, "d", INDICATOR);
        let other = instance(f.other_node, ENGINE);
        define_foreign(store, FOREIGN, f.other_node, None);
        train(store, FOREIGN, &other);
        f
    }

    fn indicator_referenced(by: Referrer) -> RemovalRefused {
        RemovalRefused::IndicatorReferenced {
            model: NAMED.to_string(),
            indicator: INDICATOR.to_string(),
            by,
        }
    }

    fn removed(models: &[&str], definitions: &[&str]) -> RemovedUnsupervisedRecords {
        RemovedUnsupervisedRecords {
            models: models.iter().map(ToString::to_string).collect(),
            definitions: definitions.iter().map(ToString::to_string).collect(),
        }
    }

    /// Every classifier file of model `name`, with its contents.
    fn classifier_files(store: &Store, name: &str) -> Vec<(std::path::PathBuf, Vec<u8>)> {
        let dir = store.classifier_fm.model_dir(model(store, name).id);
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let contents = std::fs::read(&path).unwrap();
                (path, contents)
            })
            .collect();
        files.sort_unstable();
        files
    }

    /// Asserts that every indicator a definition or a detector names
    /// exists.
    fn assert_no_dangling_indicator(store: &Store) {
        for definition in store.states.training_definitions().all().unwrap() {
            if let Some(indicator) = &definition.indicator {
                assert!(has_indicator(store, indicator), "{definition:?}");
            }
        }
        for (instance, row) in store.states.engine_instances().all().unwrap() {
            for detector in row.applied.detectors.iter().chain(&row.pending.detectors) {
                if let Some(indicator) = &detector.indicator {
                    assert!(
                        has_indicator(store, indicator),
                        "{instance:?}: {detector:?}"
                    );
                }
            }
        }
    }

    /// A definition of another customer or a detector naming the
    /// customer's indicator, accepted by its public writer, refuses the
    /// removal of the indicator's model until it is removed; the
    /// customer's own definition naming it does not.
    #[test]
    fn customer_removal_refuses_an_indicator_another_holder_names() {
        for holder in Holder::ALL {
            let f = removal_fixture(true);
            let store = f.store();
            holder.prepare(&f);
            holder.write(store, f.other_node).unwrap();
            let classifiers = classifier_files(store, NAMED);
            let held = (
                store.training_definition(HOLDER).unwrap(),
                store
                    .engine_instance_state(&instance(f.other_node, ENGINE))
                    .unwrap(),
                model(store, FOREIGN),
                definition(store, FOREIGN),
                model(store, NAMED),
                definition(store, NAMED),
                definition(store, "d"),
                store
                    .model_indicator_map()
                    .get(INDICATOR)
                    .unwrap()
                    .map(|indicator| indicator.model_id),
            );

            let error = store
                .remove_customer_unsupervised_records(CUSTOMER)
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<RemovalRefused>(),
                Some(&indicator_referenced(holder.referrer(&f))),
                "{holder:?}"
            );
            // The model before it stays removed; the refused one, its
            // records and the holder's stay.
            assert!(!has_model(store, "a"));
            assert!(store.training_definition("a").unwrap().is_none());
            assert_eq!(
                (
                    store.training_definition(HOLDER).unwrap(),
                    store
                        .engine_instance_state(&instance(f.other_node, ENGINE))
                        .unwrap(),
                    model(store, FOREIGN),
                    definition(store, FOREIGN),
                    model(store, NAMED),
                    definition(store, NAMED),
                    definition(store, "d"),
                    store
                        .model_indicator_map()
                        .get(INDICATOR)
                        .unwrap()
                        .map(|indicator| indicator.model_id),
                ),
                held,
                "{holder:?}"
            );
            assert_eq!(classifier_files(store, NAMED), classifiers);

            // A refusal with nothing before it changes nothing.
            let before = dump(store);
            let error = store
                .remove_customer_unsupervised_records(CUSTOMER)
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<RemovalRefused>(),
                Some(&indicator_referenced(holder.referrer(&f))),
                "{holder:?}"
            );
            assert_eq!(dump(store), before, "{holder:?}");
            assert_eq!(classifier_files(store, NAMED), classifiers);

            holder.release(store, f.other_node);
            assert_eq!(
                store
                    .remove_customer_unsupervised_records(CUSTOMER)
                    .unwrap(),
                removed(&[NAMED], &["d", NAMED]),
                "{holder:?}"
            );
            assert!(!has_indicator(store, INDICATOR));
            assert!(has_model(store, FOREIGN));
            assert_no_dangling_indicator(store);
            assert_eq!(
                store
                    .remove_customer_unsupervised_records(CUSTOMER)
                    .unwrap(),
                RemovedUnsupervisedRecords::default()
            );
        }
    }

    /// Another customer's definition sharing the model's name, which
    /// `Store::replace_model` does not check, refuses the removal while it
    /// names the model's indicator, and stays unchanged, with its runs,
    /// also once the removal completes after the reference is released.
    #[test]
    fn customer_removal_refuses_an_indicator_a_same_named_foreign_definition_names() {
        let f = setup();
        let store = f.store();
        define_foreign(store, NAMED, f.other_node, None);
        let failed = store.start_training_run(NAMED).unwrap().run.id;
        store.fail_run(failed, "unreachable").unwrap();
        store
            .replace_model(
                body(NAMED),
                ModelOwner {
                    customer_id: CUSTOMER,
                    instance: f.engine(),
                },
                Utc::now(),
                TrainedWith {
                    run_id: 0,
                    definition: "eps = 1.0".to_string(),
                    sources: Vec::new(),
                },
            )
            .unwrap();
        add_indicator(store, INDICATOR, model(store, NAMED).id);
        set_definition_indicator(store, NAMED, INDICATOR);
        let held = (model(store, NAMED), definition(store, NAMED));
        let classifiers = classifier_files(store, NAMED);

        let before = dump(store);
        let error = store
            .remove_customer_unsupervised_records(CUSTOMER)
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<RemovalRefused>(),
            Some(&indicator_referenced(by_definition(NAMED)))
        );
        assert_eq!(dump(store), before);
        assert_eq!((model(store, NAMED), definition(store, NAMED)), held);
        assert_eq!(definition(store, NAMED).customer_id, OTHER_CUSTOMER);
        assert!(has_indicator(store, INDICATOR));
        assert_eq!(classifier_files(store, NAMED), classifiers);
        assert_no_dangling_indicator(store);

        let stored = definition(store, NAMED);
        store
            .update_training_definition(
                NAMED,
                TrainingDefinitionUpdate {
                    method: stored.method,
                    event_kind: stored.event_kind,
                    sources: stored.sources,
                    indicator: None,
                    definition: stored.definition,
                },
            )
            .unwrap();
        let released = definition(store, NAMED);
        let runs = store.model_runs(NAMED).unwrap();
        assert_eq!(runs, vec![run(store, failed)]);
        assert_eq!(
            store
                .remove_customer_unsupervised_records(CUSTOMER)
                .unwrap(),
            removed(&[NAMED], &[])
        );
        assert!(!has_model(store, NAMED));
        assert!(!has_indicator(store, INDICATOR));
        assert_eq!(definition(store, NAMED), released);
        assert_eq!(store.model_runs(NAMED).unwrap(), runs);
        assert_no_dangling_indicator(store);
        assert_eq!(
            store
                .remove_customer_unsupervised_records(CUSTOMER)
                .unwrap(),
            RemovedUnsupervisedRecords::default()
        );
        assert_eq!(definition(store, NAMED), released);
        assert_eq!(store.model_runs(NAMED).unwrap(), runs);
    }

    /// A detector of the customer's own instance naming one of its
    /// indicators survives the removal too, and refuses it.
    #[test]
    fn customer_removal_refuses_an_indicator_its_own_detector_names() {
        let f = removal_fixture(false);
        let store = f.store();
        trained_model(store, "n", &f.engine());
        link(
            store,
            f.node,
            ENGINE,
            None,
            Some(vec![detector(2, "n", Some(INDICATOR))]),
        )
        .unwrap();
        let error = store
            .remove_customer_unsupervised_records(CUSTOMER)
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<RemovalRefused>(),
            Some(&indicator_referenced(by_detector(f.engine(), 2)))
        );
        assert!(has_model(store, NAMED));
        assert!(has_indicator(store, INDICATOR));
    }

    /// A reference committed after the removal's guard read and before its
    /// commit makes the removal retry and refuse, also one that creates a
    /// definition or an `engine instances` row the guard did not see.
    #[test]
    fn a_reference_committed_before_a_customer_removal_refuses_it() {
        for holder in Holder::ALL {
            let f = removal_fixture(false);
            let store = f.store();
            holder.prepare(&f);
            let other_node = f.other_node;
            let reached = once_before_commit(&f, move |store| {
                holder.write(store, other_node).unwrap();
            });
            let error = store
                .remove_customer_unsupervised_records(CUSTOMER)
                .unwrap_err();
            store.set_model_files_hook(None);
            assert_eq!(
                reached.load(Ordering::SeqCst),
                1,
                "{holder:?}: the retry refuses"
            );
            assert_eq!(
                error.downcast_ref::<RemovalRefused>(),
                Some(&indicator_referenced(holder.referrer(&f))),
                "{holder:?}"
            );
            assert!(has_model(store, NAMED));
            assert!(has_indicator(store, INDICATOR));
            assert_no_dangling_indicator(store);
        }
    }

    /// An indicator the model gains after the removal's guard read its
    /// indicators, named by another customer's definition before the
    /// removal deletes it, makes the removal retry and refuse.
    #[test]
    fn an_indicator_added_after_a_customer_removal_guard_refuses_it() {
        const LATE: &str = "late";
        let f = removal_fixture(false);
        let store = f.store();
        let model_id = model(store, NAMED).id;
        let other_node = f.other_node;
        let reached = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reached);
        let weak = Arc::downgrade(&f.store);
        store.set_model_files_hook(Some(Arc::new(move |point| {
            if point == ModelFilesPoint::Checked
                && counter.fetch_add(1, Ordering::SeqCst) == 0
                && let Some(store) = weak.upgrade()
            {
                add_indicator(&store, LATE, model_id);
                define_foreign(&store, HOLDER, other_node, Some(LATE));
            }
            Ok(())
        })));
        let error = store
            .remove_customer_unsupervised_records(CUSTOMER)
            .unwrap_err();
        store.set_model_files_hook(None);
        assert_eq!(reached.load(Ordering::SeqCst), 1, "the retry refuses");
        assert_eq!(
            error.downcast_ref::<RemovalRefused>(),
            Some(&RemovalRefused::IndicatorReferenced {
                model: NAMED.to_string(),
                indicator: LATE.to_string(),
                by: by_definition(HOLDER),
            })
        );
        assert!(has_model(store, NAMED));
        assert!(has_indicator(store, LATE));
        assert_no_dangling_indicator(store);
    }

    /// A removal committed after a reference's checks and before its commit
    /// makes the reference retry and refuse the indicator that is gone.
    #[test]
    fn a_customer_removal_committed_before_a_reference_refuses_it() {
        for holder in Holder::ALL {
            let f = removal_fixture(false);
            let store = f.store();
            holder.prepare(&f);
            let error = holder
                .write_racing(&f, |store| {
                    assert_eq!(
                        store
                            .remove_customer_unsupervised_records(CUSTOMER)
                            .unwrap(),
                        removed(&[NAMED], &["d", NAMED])
                    );
                })
                .unwrap_err();
            match holder {
                Holder::NewDefinition | Holder::UpdatedDefinition => assert_eq!(
                    error.downcast_ref::<TrainingError>(),
                    Some(&TrainingError::IndicatorNotFound {
                        indicator: INDICATOR.to_string(),
                    })
                ),
                Holder::Applied | Holder::Pending => assert_eq!(
                    error.downcast_ref::<EngineDocumentError>(),
                    Some(&EngineDocumentError::IndicatorNotFound {
                        agent_key: ENGINE.to_string(),
                        indicator: INDICATOR.to_string(),
                    })
                ),
            }
            assert!(!has_model(store, NAMED), "{holder:?}");
            assert!(!has_indicator(store, INDICATOR));
            assert_no_dangling_indicator(store);
        }
    }
}
