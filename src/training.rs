//! Training definitions and the runs that train or clone Unsupervised Engine
//! models (RFC 0006 §5.5, §5.6, §5.10 of Clumit Security Web).
//!
//! A definition is the settings a model is trained from, under the model's
//! name: definition and model names share one namespace. Every model comes
//! from a run, issued here with an id from the run id counter: a training
//! of a definition on the definition's instance, or a clone performed by the
//! source model's instance. A run ends as succeeded only in the transaction
//! that accepts its uploaded model, [`Store::complete_run`].
//!
//! # Transactions
//!
//! Every writer is one optimistic transaction, retried from the start on a
//! commit conflict. Each attempt reads every key a check relies on for
//! update, so a concurrent write of it makes the commit conflict instead of
//! slipping past the check: the definition, the run, the model of the name,
//! the instance's agent row and `engine instances` row, the node row for its
//! applied profile, and the named indicator.
//!
//! An engine runs one run at a time, so an instance performs at most one
//! active run. "The instance has an active run" cannot be read from one
//! key; it is anchored on the run id counter instead. A run becomes active
//! only when it is created, and every creation reads the counter for update
//! and writes it, so a check that reads the counter for update before it
//! scans the runs either sees a run in the scan or conflicts with its
//! creation. Leaving an active state needs no anchor: each such write reads
//! the run itself for update and acts on what that read returns.

use std::{collections::BTreeSet, fmt};

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use rocksdb::{OptimisticTransactionDB, Transaction};
use serde::{Deserialize, Serialize};

use crate::{
    AgentKind, ModelInstance, ModelMethod, ModelOwner, ModelRun, NewTrainingDefinition, Referrer,
    ReplacedModel, ReportedRunState, RunId, RunKind, RunState, Store, TrainedWith,
    TrainingDefinition, TrainingDefinitionUpdate,
    classifier_fs::{self, ClassifierFsError},
    engine_instance::agent_for_update,
    model_lifecycle::column_family,
    tables::{self, ModelRuns, TrainingDefinitions},
};

type Txn<'a> = Transaction<'a, OptimisticTransactionDB>;

/// The reason an instance's active runs fail when it is stopped.
pub(crate) const INSTANCE_STOPPED: &str = "instance stopped";

/// The reason an instance's active runs fail when its agent is removed.
pub(crate) const INSTANCE_REMOVED: &str = "instance removed";

/// The reason a run fails when its instance reconnects without it.
const NOT_RUNNING_AFTER_RECONNECT: &str = "not running on the instance after it reconnected";

/// The state of a training definition (RFC 0006 §5.10).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrainingDefinitionState {
    /// The definition has no instance.
    NoInstance,
    /// The definition was created by a clone that has not succeeded yet.
    Cloning,
    /// A training run of the definition is active, also while a model
    /// exists.
    Training,
    /// A model of the definition's name exists; a failed or cancelled
    /// retrain leaves it ready.
    Ready,
    /// No model exists and the last run failed.
    TrainingFailed,
    /// No model exists and no run failed: there was no run yet, or the last
    /// one was cancelled.
    NeverTrained,
}

/// A training run just requested, with the definition text the caller
/// relays to the engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartedTrainingRun {
    pub run: ModelRun,
    /// The definition's text, read in the transaction that created the run.
    /// It is also the text [`Store::complete_run`] records as the model's
    /// `trained_definition`, since the definition cannot change while the
    /// run is active.
    pub definition: String,
}

/// The outcome of [`Store::reconcile_runs`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunReconciliation {
    /// The runs held active for the instance that it did not report, now
    /// failed, ascending.
    pub failed: Vec<RunId>,
    /// The reported runs the instance has to cancel, ascending: unknown,
    /// finished or held for another instance.
    pub to_cancel: Vec<RunId>,
}

/// A field of a training definition that is fixed once a model of its name
/// exists.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FixedField {
    Method,
    EventKind,
}

/// A refusal of a training definition, model run, model or model indicator
/// write.
///
/// It is returned inside the `anyhow::Error` of the refusing method, so a
/// caller can `downcast_ref` it. A refused write changes nothing.
///
/// `Display` and `Error` are written by hand rather than derived with
/// `thiserror`, which takes a field named `source` for the error's cause.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrainingError {
    /// A model or a training definition already has the name.
    NameTaken { name: String },
    /// The model-name rule refuses the name.
    InvalidName { name: String, reason: String },
    /// The instance is not an Unsupervised Engine agent row with an instance
    /// number.
    InstanceNotEligible { node_id: u32, agent_key: String },
    /// The instance's node has no applied profile.
    NoAppliedProfile { node_id: u32 },
    /// The customer is not the one of the node's applied profile.
    CustomerMismatch {
        node_id: u32,
        node_customer_id: u32,
        customer_id: u32,
    },
    /// No training definition has the name.
    DefinitionNotFound { name: String },
    /// No model has the name.
    ModelNotFound { name: String },
    /// No run has the id.
    RunNotFound { run_id: RunId },
    /// No model indicator has the name.
    IndicatorNotFound { indicator: String },
    /// The training definition or the clone source model has no instance.
    NoInstance { name: String },
    /// The instance is stopped.
    InstanceStopped { node_id: u32, agent_key: String },
    /// The definition or the performing instance has an active run.
    RunInProgress { run_id: RunId },
    /// The clone source was trained by another run than the one the target
    /// was built from.
    SourceRetrained {
        source: String,
        expected: RunId,
        current: RunId,
    },
    /// A field that is fixed once a model of the name exists would change.
    FieldFixed { name: String, field: FixedField },
    /// A model of the name exists.
    HasModel { name: String },
    /// The run is finished.
    RunNotActive { run_id: RunId, state: RunState },
    /// The run is performed by another instance.
    RunOfAnotherInstance { run_id: RunId },
    /// The run cannot go from its state to the reported one.
    InvalidTransition {
        run_id: RunId,
        from: RunState,
        to: ReportedRunState,
    },
    /// The uploaded model is not the one the run creates or replaces.
    ModelNameMismatch {
        run_id: RunId,
        expected: String,
        uploaded: String,
    },
    /// An uploaded model or a clone source uses another method than the
    /// definition's.
    MethodMismatch {
        name: String,
        expected: ModelMethod,
        actual: String,
    },
    /// An uploaded model or a clone source reads another event kind than the
    /// definition's.
    EventKindMismatch {
        name: String,
        expected: String,
        actual: String,
    },
    /// A detector of an applied or pending engine document names the model.
    ModelInUse {
        name: String,
        instance: ModelInstance,
        detector_id: i32,
    },
    /// A detector of an applied or pending engine document, or a training
    /// definition, names the model indicator.
    IndicatorInUse { indicator: String, by: Referrer },
    /// A model indicator already has the name.
    IndicatorExists { indicator: String },
    /// The update would move the model indicator to another model.
    IndicatorModelChange {
        indicator: String,
        model_id: u32,
        new_model_id: u32,
    },
    /// The model has an instance.
    ModelHasInstance {
        name: String,
        instance: ModelInstance,
    },
}

impl fmt::Display for TrainingError {
    // One arm per variant, each a message of its own.
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameTaken { name } => {
                write!(
                    f,
                    "the name {name:?} is taken by a model or a training definition"
                )
            }
            Self::InvalidName { name, reason } => {
                write!(f, "invalid model name {name:?}: {reason}")
            }
            Self::InstanceNotEligible { node_id, agent_key } => write!(
                f,
                "agent {agent_key:?} of node {node_id} is not an Unsupervised Engine instance \
                 that can train models"
            ),
            Self::NoAppliedProfile { node_id } => {
                write!(f, "node {node_id} has no applied profile")
            }
            Self::CustomerMismatch {
                node_id,
                node_customer_id,
                customer_id,
            } => write!(
                f,
                "node {node_id} belongs to customer {node_customer_id}, not {customer_id}"
            ),
            Self::DefinitionNotFound { name } => {
                write!(f, "training definition {name:?} not found")
            }
            Self::ModelNotFound { name } => write!(f, "model {name:?} not found"),
            Self::RunNotFound { run_id } => write!(f, "model run {run_id} not found"),
            Self::IndicatorNotFound { indicator } => {
                write!(f, "model indicator {indicator:?} not found")
            }
            Self::NoInstance { name } => write!(f, "{name:?} has no instance"),
            Self::InstanceStopped { node_id, agent_key } => {
                write!(f, "agent {agent_key:?} of node {node_id} is stopped")
            }
            Self::RunInProgress { run_id } => write!(f, "model run {run_id} is in progress"),
            Self::SourceRetrained {
                source,
                expected,
                current,
            } => write!(
                f,
                "model {source:?} was trained by run {current}, not {expected}"
            ),
            Self::FieldFixed { name, field } => write!(
                f,
                "the {field:?} of training definition {name:?} is fixed once its model exists"
            ),
            Self::HasModel { name } => write!(f, "training definition {name:?} has a model"),
            Self::RunNotActive { run_id, state } => {
                write!(f, "model run {run_id} is {state:?}, not active")
            }
            Self::RunOfAnotherInstance { run_id } => {
                write!(f, "model run {run_id} is performed by another instance")
            }
            Self::InvalidTransition { run_id, from, to } => {
                write!(f, "model run {run_id} cannot go from {from:?} to {to:?}")
            }
            Self::ModelNameMismatch {
                run_id,
                expected,
                uploaded,
            } => write!(
                f,
                "model run {run_id} creates {expected:?}, not {uploaded:?}"
            ),
            Self::MethodMismatch {
                name,
                expected,
                actual,
            } => write!(
                f,
                "{name:?} trains with the {expected:?} method, not {actual:?}"
            ),
            Self::EventKindMismatch {
                name,
                expected,
                actual,
            } => write!(f, "{name:?} reads {expected:?} events, not {actual:?}"),
            Self::ModelInUse {
                name,
                instance,
                detector_id,
            } => write!(
                f,
                "model {name:?} is used by detector {detector_id} of agent {:?} of node {}",
                instance.agent_key, instance.node_id
            ),
            Self::IndicatorInUse { indicator, by } => {
                write!(f, "model indicator {indicator:?} is used by {by}")
            }
            Self::IndicatorExists { indicator } => {
                write!(f, "model indicator {indicator:?} already exists")
            }
            Self::IndicatorModelChange {
                indicator,
                model_id,
                new_model_id,
            } => write!(
                f,
                "model indicator {indicator:?} belongs to model {model_id}, not {new_model_id}"
            ),
            Self::ModelHasInstance { name, instance } => write!(
                f,
                "model {name:?} belongs to agent {:?} of node {}",
                instance.agent_key, instance.node_id
            ),
        }
    }
}

impl std::error::Error for TrainingError {}

impl Store {
    /// Stores a new training definition, not cloning and with no run yet.
    ///
    /// # Errors
    ///
    /// Returns a [`TrainingError`] inside the error, and changes nothing,
    /// checked in this order: `NameTaken` if a model or a definition has the
    /// name; `InvalidName` if the model-name rule refuses it;
    /// `InstanceNotEligible` if the instance is not an
    /// [`AgentKind::Unsupervised`] agent row with an instance number;
    /// `NoAppliedProfile` if the instance's node has no applied profile;
    /// `CustomerMismatch` if `customer_id` is not that profile's customer;
    /// `IndicatorNotFound` if the indicator does not exist. Returns an error,
    /// and changes nothing, if a database operation fails.
    pub fn insert_training_definition(&self, definition: NewTrainingDefinition) -> Result<()> {
        let definitions = self.states.training_definitions();
        let mut record = new_record(definition, false);
        self.write_training(|txn| {
            self.check_new_definition(txn, &record)?;
            if let Some(instance) = &record.instance {
                self.hold_agent_row(txn, instance)?;
            }
            let now = Utc::now();
            record.created_at = now;
            record.updated_at = now;
            definitions.put(txn, &record)
        })
    }

    /// Replaces the settings of a training definition: its method, event
    /// kind, sources, indicator and text. Its customer and instance stay.
    ///
    /// # Errors
    ///
    /// Returns a [`TrainingError`] inside the error, and changes nothing,
    /// checked in this order: `DefinitionNotFound`; `RunInProgress` while
    /// the definition's last run is active, which includes a definition
    /// being cloned; `FieldFixed` if a model of the name exists and the
    /// method or the event kind would change; `IndicatorNotFound` if the
    /// indicator does not exist. Returns an error, and changes nothing, if a
    /// database operation fails.
    // The settings are handed over by value, as the caller's parse yields
    // them; a retry after a commit conflict reads them again.
    #[allow(clippy::needless_pass_by_value)]
    pub fn update_training_definition(
        &self,
        name: &str,
        update: TrainingDefinitionUpdate,
    ) -> Result<()> {
        let definitions = self.states.training_definitions();
        self.write_training(|txn| {
            let mut definition = self.definition_for_update(txn, name)?;
            self.check_no_active_run(txn, definition.last_run)?;
            if self
                .model_map()
                .load_model_by_name_in_transaction(name, txn)?
                .is_some()
            {
                let field = if update.method != definition.method {
                    Some(FixedField::Method)
                } else if update.event_kind != definition.event_kind {
                    Some(FixedField::EventKind)
                } else {
                    None
                };
                if let Some(field) = field {
                    return Err(TrainingError::FieldFixed {
                        name: name.to_string(),
                        field,
                    }
                    .into());
                }
            }
            self.check_indicator(txn, update.indicator.as_deref())?;
            definition.method = update.method;
            definition.event_kind.clone_from(&update.event_kind);
            definition.sources.clone_from(&update.sources);
            definition.indicator.clone_from(&update.indicator);
            definition.definition.clone_from(&update.definition);
            definition.updated_at = Utc::now();
            definitions.put(txn, &definition)
        })
    }

    /// Removes a training definition with every run record whose model is
    /// its name.
    ///
    /// A definition whose model exists goes only with the model.
    ///
    /// # Errors
    ///
    /// Returns a [`TrainingError`] inside the error, and changes nothing,
    /// checked in this order: `DefinitionNotFound`; `HasModel` while a model
    /// of the name exists; `RunInProgress` while the definition's last run
    /// is active. Returns an error, and changes nothing, if a database
    /// operation fails.
    pub fn remove_training_definition(&self, name: &str) -> Result<()> {
        let definitions = self.states.training_definitions();
        let runs = self.states.model_runs();
        self.write_training(|txn| {
            let definition = self.definition_for_update(txn, name)?;
            if self
                .model_map()
                .load_model_by_name_in_transaction(name, txn)?
                .is_some()
            {
                return Err(TrainingError::HasModel {
                    name: name.to_string(),
                }
                .into());
            }
            self.check_no_active_run(txn, definition.last_run)?;
            definitions.delete(txn, name)?;
            for run in runs.scan(txn)?.into_iter().filter(|run| run.model == name) {
                runs.get_for_update(txn, run.id)?;
                runs.delete(txn, run.id)?;
            }
            Ok(())
        })
    }

    /// Returns the training definition `name`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn training_definition(&self, name: &str) -> Result<Option<TrainingDefinition>> {
        self.states.training_definitions().get(name)
    }

    /// Returns every training definition, ordered by name.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn training_definitions(&self) -> Result<Vec<TrainingDefinition>> {
        self.states.training_definitions().all()
    }

    /// Returns the state of the training definition `name`, `None` if no
    /// definition has the name.
    ///
    /// The definition, its last run and the model of the name are read from
    /// one snapshot. The first state that applies wins: `NoInstance`,
    /// `Cloning`, `Training` (the last run is an active training run, also
    /// while a model exists), `Ready` (a model of the name exists),
    /// `TrainingFailed` (the last run failed), then `NeverTrained`.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn training_definition_state(&self, name: &str) -> Result<Option<TrainingDefinitionState>> {
        let snapshot = self.states.db().snapshot();
        let Some(definition) = self
            .states
            .training_definitions()
            .get_in_snapshot(&snapshot, name)?
        else {
            return Ok(None);
        };
        let last_run = match definition.last_run {
            Some(id) => self.states.model_runs().get_in_snapshot(&snapshot, id)?,
            None => None,
        };
        let has_model = self
            .model_map()
            .load_model_by_name_in_snapshot(name, &snapshot)?
            .is_some();
        let state = if definition.instance.is_none() {
            TrainingDefinitionState::NoInstance
        } else if definition.cloning {
            TrainingDefinitionState::Cloning
        } else if last_run
            .as_ref()
            .is_some_and(|run| run.kind == RunKind::Train && run.state.is_active())
        {
            TrainingDefinitionState::Training
        } else if has_model {
            TrainingDefinitionState::Ready
        } else if last_run
            .as_ref()
            .is_some_and(|run| run.state == RunState::Failed)
        {
            TrainingDefinitionState::TrainingFailed
        } else {
            TrainingDefinitionState::NeverTrained
        };
        Ok(Some(state))
    }

    /// Requests a training run of the definition `name` on its instance,
    /// returning the run with the definition text read in the same
    /// transaction.
    ///
    /// The run is stored `Requested` and becomes the definition's last run.
    /// The caller relays exactly the returned text to the engine; since the
    /// definition cannot be updated while the run is active, it is also the
    /// text [`Store::complete_run`] records.
    ///
    /// # Errors
    ///
    /// Returns a [`TrainingError`] inside the error, and changes nothing,
    /// checked in this order: `DefinitionNotFound`; `NoInstance` if the
    /// definition has no instance; `InstanceNotEligible` if the instance is
    /// no longer an [`AgentKind::Unsupervised`] agent row with an instance
    /// number; `InstanceStopped`; `RunInProgress` if the definition's last
    /// run is active or the instance performs an active run. Returns an
    /// error, and changes nothing, if every run id has been allocated or a
    /// database operation fails.
    pub fn start_training_run(&self, name: &str) -> Result<StartedTrainingRun> {
        let definitions = self.states.training_definitions();
        let runs = self.states.model_runs();
        self.write_training(|txn| {
            let mut definition = self.definition_for_update(txn, name)?;
            let Some(instance) = definition.instance.clone() else {
                return Err(TrainingError::NoInstance {
                    name: name.to_string(),
                }
                .into());
            };
            self.check_instance_eligible(txn, &instance)?;
            self.check_instance_not_stopped(txn, &instance)?;
            self.check_no_active_run(txn, definition.last_run)?;
            self.check_instance_idle(txn, &instance)?;

            let now = Utc::now();
            let run = ModelRun {
                id: runs.allocate_id(txn)?,
                kind: RunKind::Train,
                model: name.to_string(),
                instance,
                state: RunState::Requested,
                reason: None,
                requested_at: now,
                updated_at: now,
            };
            runs.put(txn, &run)?;
            definition.last_run = Some(run.id);
            definitions.put(txn, &definition)?;
            Ok(StartedTrainingRun {
                run,
                definition: definition.definition,
            })
        })
    }

    /// Requests a clone of the model `source` into a new model, creating
    /// the target's definition in the same transaction.
    ///
    /// The caller builds `target.definition` from the source model's
    /// `trained_definition`, the definition that produced the source's
    /// classifier, not from the source's editable definition, and passes the
    /// source's `trained_run_id` it read with it as `source_trained_run_id`.
    ///
    /// The target's definition is stored cloning, with the new run as its
    /// last run, which reserves the name. The run is stored `Requested`,
    /// creates the target and is performed by the source's instance; it
    /// strips the source's events exactly when the target belongs to
    /// another customer than the source. Who may clone across customers is
    /// the caller's decision.
    ///
    /// # Errors
    ///
    /// Returns a [`TrainingError`] inside the error, and changes nothing,
    /// checked in this order: `ModelNotFound` if no model is named `source`;
    /// `NoInstance` if it has no instance; `SourceRetrained` if its
    /// `trained_run_id` is not `source_trained_run_id`; `MethodMismatch` or
    /// `EventKindMismatch` if the target's method or event kind is not the
    /// source's; `InstanceNotEligible`, `InstanceStopped` or `RunInProgress`
    /// for the source's instance, as [`Store::start_training_run`] checks
    /// them; then every refusal of [`Store::insert_training_definition`] for
    /// the target. Returns an error, and changes nothing, if every run id
    /// has been allocated or a database operation fails.
    pub fn start_clone_run(
        &self,
        source: &str,
        source_trained_run_id: RunId,
        target: NewTrainingDefinition,
    ) -> Result<ModelRun> {
        let definitions = self.states.training_definitions();
        let runs = self.states.model_runs();
        let mut record = new_record(target, true);
        self.write_training(|txn| {
            let Some(model) = self
                .model_map()
                .load_model_by_name_in_transaction(source, txn)?
            else {
                return Err(TrainingError::ModelNotFound {
                    name: source.to_string(),
                }
                .into());
            };
            let Some(instance) = model.instance.clone() else {
                return Err(TrainingError::NoInstance {
                    name: source.to_string(),
                }
                .into());
            };
            if model.trained_run_id != source_trained_run_id {
                return Err(TrainingError::SourceRetrained {
                    source: source.to_string(),
                    expected: source_trained_run_id,
                    current: model.trained_run_id,
                }
                .into());
            }
            if model.kind != method_kind(record.method) {
                return Err(TrainingError::MethodMismatch {
                    name: record.name.clone(),
                    expected: record.method,
                    actual: model.kind,
                }
                .into());
            }
            if model.event_kind != record.event_kind {
                return Err(TrainingError::EventKindMismatch {
                    name: record.name.clone(),
                    expected: record.event_kind.clone(),
                    actual: model.event_kind,
                }
                .into());
            }
            self.check_instance_eligible(txn, &instance)?;
            self.check_instance_not_stopped(txn, &instance)?;
            self.check_instance_idle(txn, &instance)?;
            self.check_new_definition(txn, &record)?;

            let now = Utc::now();
            let run = ModelRun {
                id: runs.allocate_id(txn)?,
                kind: RunKind::Clone {
                    source: source.to_string(),
                    strip_events: record.customer_id != model.customer_id,
                },
                model: record.name.clone(),
                instance,
                state: RunState::Requested,
                reason: None,
                requested_at: now,
                updated_at: now,
            };
            runs.put(txn, &run)?;
            record.last_run = Some(run.id);
            record.created_at = now;
            record.updated_at = now;
            definitions.put(txn, &record)?;
            Ok(run)
        })
    }

    /// Records the state an engine reports for one of its runs: `Started`
    /// for a `Requested` run, `Failed` or `Cancelled` for an active one,
    /// replacing the run's reason with `reason`.
    ///
    /// A clone run that ends failed or cancelled is removed with the target
    /// definition it reserved, which frees the name; a later report of it is
    /// refused with `RunNotFound`. A training run that ends so stays the
    /// last run of its definition.
    ///
    /// # Errors
    ///
    /// Returns a [`TrainingError`] inside the error, and changes nothing,
    /// checked in this order: `RunNotFound`; `RunOfAnotherInstance` if
    /// `caller` does not perform the run; `RunNotActive` for a finished run;
    /// `InvalidTransition` for `Started` reported for a started run. Returns
    /// an error, and changes nothing, if a database operation fails.
    pub fn report_run(
        &self,
        run_id: RunId,
        caller: &ModelInstance,
        state: ReportedRunState,
        reason: Option<&str>,
    ) -> Result<()> {
        let runs = self.states.model_runs();
        self.write_training(|txn| {
            let run = self.active_run_of_caller(txn, run_id, caller)?;
            match state {
                ReportedRunState::Started => {
                    if run.state == RunState::Started {
                        return Err(TrainingError::InvalidTransition {
                            run_id,
                            from: run.state,
                            to: state,
                        }
                        .into());
                    }
                    runs.put(
                        txn,
                        &ModelRun {
                            state: RunState::Started,
                            reason: reason.map(ToString::to_string),
                            updated_at: Utc::now(),
                            ..run
                        },
                    )
                }
                ReportedRunState::Failed => {
                    self.end_run_with_transaction(txn, run, RunState::Failed, reason)
                }
                ReportedRunState::Cancelled => {
                    self.end_run_with_transaction(txn, run, RunState::Cancelled, reason)
                }
            }
        })
    }

    /// Ends an active run as failed with `reason`, for a failure of the
    /// Central Manager's own, such as a request or a cancel it cannot
    /// deliver.
    ///
    /// A clone run is removed with the target definition it reserved, as
    /// [`Store::report_run`] describes.
    ///
    /// # Errors
    ///
    /// Returns a [`TrainingError`] inside the error, and changes nothing:
    /// `RunNotFound`, or `RunNotActive` for a finished run. Returns an
    /// error, and changes nothing, if a database operation fails.
    pub fn fail_run(&self, run_id: RunId, reason: &str) -> Result<()> {
        let runs = self.states.model_runs();
        self.write_training(|txn| {
            let Some(run) = runs.get_for_update(txn, run_id)? else {
                return Err(TrainingError::RunNotFound { run_id }.into());
            };
            if !run.state.is_active() {
                return Err(TrainingError::RunNotActive {
                    run_id,
                    state: run.state,
                }
                .into());
            }
            self.end_run_with_transaction(txn, run, RunState::Failed, Some(reason))
        })
    }

    /// Accepts the model a run uploaded: inserts or replaces it, as
    /// [`Store::replace_model`] describes, and ends the run as succeeded, in
    /// one transaction.
    ///
    /// The model is stored for the customer and instance of the definition
    /// the run's model names, trained now, with the run's id and the
    /// definition's text as the training it records. For a training run
    /// that text is the one [`Store::start_training_run`] returned; for a
    /// clone it is the target definition [`Store::start_clone_run`] stored,
    /// which becomes both the clone's snapshot and its editable definition.
    /// The definition stops cloning.
    ///
    /// # Errors
    ///
    /// Returns a [`TrainingError`] inside the error, and changes nothing,
    /// checked in this order: `RunNotFound`; `RunOfAnotherInstance` if
    /// `caller` does not perform the run; `RunNotActive` for a finished run;
    /// `ModelNameMismatch` if `model.name` is not the run's model;
    /// `DefinitionNotFound`; `NoInstance` if the definition has no instance;
    /// `MethodMismatch` or `EventKindMismatch` if the model's method or
    /// event kind is not the definition's. Returns an error, leaving the
    /// run active and the model unchanged, if [`Store::replace_model`]
    /// refuses the model or a file or database operation fails.
    // The upload is handed over by value, as its decoded body is; the retry
    // after a commit conflict reads it again, so the body works on references.
    #[allow(clippy::needless_pass_by_value)]
    pub fn complete_run(
        &self,
        run_id: RunId,
        caller: &ModelInstance,
        model: crate::model::Model,
    ) -> Result<ReplacedModel> {
        let files = self.lock_model_files();
        let definitions = self.states.training_definitions();
        let runs = self.states.model_runs();
        loop {
            let txn = self.model_transaction();
            let run = self.active_run_of_caller(&txn, run_id, caller)?;
            if model.name != run.model {
                return Err(TrainingError::ModelNameMismatch {
                    run_id,
                    expected: run.model,
                    uploaded: model.name.clone(),
                }
                .into());
            }
            let mut definition = self.definition_for_update(&txn, &run.model)?;
            let Some(instance) = definition.instance.clone() else {
                return Err(TrainingError::NoInstance {
                    name: definition.name,
                }
                .into());
            };
            let method = model
                .method()
                .ok()
                .and_then(|method| ModelMethod::try_from(method).ok());
            if method != Some(definition.method) {
                return Err(TrainingError::MethodMismatch {
                    name: definition.name,
                    expected: definition.method,
                    actual: model.kind.clone(),
                }
                .into());
            }
            if model.event_kind != definition.event_kind {
                return Err(TrainingError::EventKindMismatch {
                    name: definition.name,
                    expected: definition.event_kind,
                    actual: model.event_kind.clone(),
                }
                .into());
            }

            let now = Utc::now();
            let owner = ModelOwner {
                customer_id: definition.customer_id,
                instance,
            };
            let trained = TrainedWith {
                run_id,
                definition: definition.definition.clone(),
            };
            let pending =
                self.replace_model_with_transaction(&files, &txn, &model, &owner, now, &trained)?;
            definition.cloning = false;
            definitions.put(&txn, &definition)?;
            runs.put(
                &txn,
                &ModelRun {
                    state: RunState::Succeeded,
                    reason: None,
                    updated_at: now,
                    ..run
                },
            )?;
            #[cfg(test)]
            self.run_model_files_hook(crate::model_lifecycle::ModelFilesPoint::BeforeCommit)?;
            if txn.commit_or_retry()? {
                #[cfg(test)]
                self.run_model_files_hook(crate::model_lifecycle::ModelFilesPoint::AfterCommit)?;
                return Ok(self.finish_model_replace(&files, &pending));
            }
        }
    }

    /// Reconciles the runs held for an instance with the runs it reports
    /// running when it reconnects, in one transaction.
    ///
    /// Every run held active for `caller` that `reported` does not list
    /// fails with the reason "not running on the instance after it
    /// reconnected"; a clone among them is removed with the target
    /// definition it reserved. Every reported id that is unknown, finished
    /// or held for another instance is returned for the caller to cancel. A
    /// reported active run of `caller` stays as it is. A run created after
    /// the scan of the held runs is not stale and is left alone.
    ///
    /// aicers/review orders a reconciliation before it relays any run on the
    /// reconnected instance's connection (RFC 0006 §5.5, §5.12), and sends
    /// the cancels itself.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if a database operation fails.
    pub fn reconcile_runs(
        &self,
        caller: &ModelInstance,
        reported: &[RunId],
    ) -> Result<RunReconciliation> {
        let runs = self.states.model_runs();
        let reported: BTreeSet<RunId> = reported.iter().copied().collect();
        self.write_training(|txn| {
            let mut to_cancel = Vec::new();
            for &id in &reported {
                let held = runs
                    .get_for_update(txn, id)?
                    .is_some_and(|run| run.state.is_active() && run.instance == *caller);
                if !held {
                    to_cancel.push(id);
                }
            }
            let mut failed = Vec::new();
            for scanned in runs.scan(txn)? {
                if !scanned.state.is_active()
                    || scanned.instance != *caller
                    || reported.contains(&scanned.id)
                {
                    continue;
                }
                let Some(run) = runs.get_for_update(txn, scanned.id)? else {
                    continue;
                };
                if !run.state.is_active() {
                    continue;
                }
                failed.push(run.id);
                self.end_run_with_transaction(
                    txn,
                    run,
                    RunState::Failed,
                    Some(NOT_RUNNING_AFTER_RECONNECT),
                )?;
            }
            Ok(RunReconciliation { failed, to_cancel })
        })
    }

    /// Returns the run `run_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn model_run(&self, run_id: RunId) -> Result<Option<ModelRun>> {
        self.states.model_runs().get(run_id)
    }

    /// Returns the runs that create or replace the model `model` and the
    /// clone runs from it, ascending by id.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn model_runs(&self, model: &str) -> Result<Vec<ModelRun>> {
        Ok(self
            .states
            .model_runs()
            .all()?
            .into_iter()
            .filter(|run| run.concerns(model))
            .collect())
    }

    /// Returns the active run that creates or replaces the model `model` or
    /// clones from it.
    ///
    /// At most one exists: a clone from a model and a retrain of it both run
    /// on the model's instance, and a clone creating it holds its
    /// definition's last run.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn active_run(&self, model: &str) -> Result<Option<ModelRun>> {
        Ok(self
            .states
            .model_runs()
            .all()?
            .into_iter()
            .find(|run| run.state.is_active() && run.concerns(model)))
    }

    /// Ends `run`, active as read for update within `txn`, as `state`,
    /// `Failed` or `Cancelled`, with `reason`, as [`end_run`] does.
    pub(crate) fn end_run_with_transaction(
        &self,
        txn: &Txn<'_>,
        run: ModelRun,
        state: RunState,
        reason: Option<&str>,
    ) -> Result<()> {
        end_run(
            txn,
            &self.states.model_runs(),
            &self.states.training_definitions(),
            run,
            state,
            reason,
        )
    }

    /// Fails, within `txn`, every active run `instance` performs, with
    /// `reason`, as [`fail_active_runs`] does.
    pub(crate) fn fail_active_runs_of_instance(
        &self,
        txn: &Txn<'_>,
        instance: &ModelInstance,
        reason: &str,
    ) -> Result<()> {
        fail_active_runs(
            txn,
            &self.states.model_runs(),
            &self.states.training_definitions(),
            instance,
            reason,
        )
    }

    /// Runs `attempt` in an optimistic transaction and commits it, retrying
    /// from the start on a commit conflict. A refusal `attempt` returns ends
    /// the write without committing.
    pub(crate) fn write_training<T>(
        &self,
        mut attempt: impl FnMut(&Txn<'_>) -> Result<T>,
    ) -> Result<T> {
        let db = self.states.db();
        loop {
            let txn = db.transaction();
            let value = attempt(&txn)?;
            #[cfg(test)]
            self.run_training_hook()?;
            match txn.commit() {
                Ok(()) => return Ok(value),
                Err(e) if e.as_ref().starts_with("Resource busy:") => {}
                Err(e) => return Err(e).context("failed to commit training changes"),
            }
        }
    }

    /// Returns the definition `name`, read for update within `txn`, refusing
    /// a name no definition has.
    fn definition_for_update(&self, txn: &Txn<'_>, name: &str) -> Result<TrainingDefinition> {
        self.states
            .training_definitions()
            .get_for_update(txn, name)?
            .ok_or_else(|| {
                TrainingError::DefinitionNotFound {
                    name: name.to_string(),
                }
                .into()
            })
    }

    /// Returns the run `run_id`, read for update within `txn`, refusing an
    /// unknown run, a run `caller` does not perform and a finished run.
    fn active_run_of_caller(
        &self,
        txn: &Txn<'_>,
        run_id: RunId,
        caller: &ModelInstance,
    ) -> Result<ModelRun> {
        let Some(run) = self.states.model_runs().get_for_update(txn, run_id)? else {
            return Err(TrainingError::RunNotFound { run_id }.into());
        };
        if run.instance != *caller {
            return Err(TrainingError::RunOfAnotherInstance { run_id }.into());
        }
        if !run.state.is_active() {
            return Err(TrainingError::RunNotActive {
                run_id,
                state: run.state,
            }
            .into());
        }
        Ok(run)
    }

    /// Refuses, within `txn`, a definition to be stored as `record` that
    /// [`Store::insert_training_definition`] refuses.
    fn check_new_definition(&self, txn: &Txn<'_>, record: &TrainingDefinition) -> Result<()> {
        let name = &record.name;
        if self
            .model_map()
            .load_model_by_name_in_transaction(name, txn)?
            .is_some()
            || self
                .states
                .training_definitions()
                .get_for_update(txn, name)?
                .is_some()
        {
            return Err(TrainingError::NameTaken { name: name.clone() }.into());
        }
        if let Err(e) = classifier_fs::validate_name(name) {
            let reason = match e {
                ClassifierFsError::InvalidName(reason) => reason,
                other => other.to_string(),
            };
            return Err(TrainingError::InvalidName {
                name: name.clone(),
                reason,
            }
            .into());
        }
        let instance = record
            .instance
            .as_ref()
            .ok_or_else(|| anyhow!("a new training definition has an instance"))?;
        self.check_instance_eligible(txn, instance)?;
        let Some(profile) = self
            .states
            .nodes()
            .applied_profile_in_transaction(instance.node_id, txn)?
        else {
            return Err(TrainingError::NoAppliedProfile {
                node_id: instance.node_id,
            }
            .into());
        };
        if profile.customer_id != record.customer_id {
            return Err(TrainingError::CustomerMismatch {
                node_id: instance.node_id,
                node_customer_id: profile.customer_id,
                customer_id: record.customer_id,
            }
            .into());
        }
        self.check_indicator(txn, record.indicator.as_deref())
    }

    /// Refuses, within `txn`, an instance that is not an
    /// [`AgentKind::Unsupervised`] agent row with an instance number.
    pub(crate) fn check_instance_eligible(
        &self,
        txn: &Txn<'_>,
        instance: &ModelInstance,
    ) -> Result<()> {
        let key = tables::engine_instance_key(instance.node_id, &instance.agent_key);
        let eligible = agent_for_update(txn, self.states.agents().raw().cf, &key)?
            .is_some_and(|agent| agent.kind == AgentKind::Unsupervised && agent.instance.is_some());
        if eligible {
            Ok(())
        } else {
            Err(TrainingError::InstanceNotEligible {
                node_id: instance.node_id,
                agent_key: instance.agent_key.clone(),
            }
            .into())
        }
    }

    /// Writes the agent row of `instance`, read for update within `txn`,
    /// back unchanged; an absent row stays absent.
    ///
    /// A writer that gives a record this instance calls it after
    /// [`Store::check_instance_eligible`], when nothing else it writes is a
    /// key the detach of an uninstalled instance reads: the removal deletes
    /// the row, so whichever of the two commits second conflicts, and either
    /// the removal's retry detaches the new record or the writer's retry
    /// refuses the instance.
    pub(crate) fn hold_agent_row(&self, txn: &Txn<'_>, instance: &ModelInstance) -> Result<()> {
        let agents = self.states.agents();
        let key = tables::engine_instance_key(instance.node_id, &instance.agent_key);
        if let Some(value) = txn
            .get_for_update_cf(agents.raw().cf, &key, crate::EXCLUSIVE)
            .context("cannot read agent")?
        {
            agents.raw().put_with_transaction(&key, &value, txn)?;
        }
        Ok(())
    }

    /// Refuses, within `txn`, an instance recorded as stopped.
    fn check_instance_not_stopped(&self, txn: &Txn<'_>, instance: &ModelInstance) -> Result<()> {
        let key = tables::engine_instance_key(instance.node_id, &instance.agent_key);
        if self
            .states
            .engine_instances()
            .get_for_update(txn, &key)?
            .is_some_and(|row| row.stopped)
        {
            return Err(TrainingError::InstanceStopped {
                node_id: instance.node_id,
                agent_key: instance.agent_key.clone(),
            }
            .into());
        }
        Ok(())
    }

    /// Refuses, within `txn`, a last run that is active.
    fn check_no_active_run(&self, txn: &Txn<'_>, last_run: Option<RunId>) -> Result<()> {
        let Some(id) = last_run else {
            return Ok(());
        };
        if self
            .states
            .model_runs()
            .get_for_update(txn, id)?
            .is_some_and(|run| run.state.is_active())
        {
            return Err(TrainingError::RunInProgress { run_id: id }.into());
        }
        Ok(())
    }

    /// Refuses, within `txn`, an instance that performs an active run,
    /// reading the run id counter for update before scanning the runs.
    fn check_instance_idle(&self, txn: &Txn<'_>, instance: &ModelInstance) -> Result<()> {
        let runs = self.states.model_runs();
        runs.last_id_for_update(txn)?;
        for scanned in runs.scan(txn)? {
            if !scanned.state.is_active() || scanned.instance != *instance {
                continue;
            }
            if let Some(run) = runs.get_for_update(txn, scanned.id)?
                && run.state.is_active()
            {
                return Err(TrainingError::RunInProgress { run_id: run.id }.into());
            }
        }
        Ok(())
    }

    /// Refuses, within `txn`, an indicator no model indicator row has.
    fn check_indicator(&self, txn: &Txn<'_>, indicator: Option<&str>) -> Result<()> {
        let Some(indicator) = indicator else {
            return Ok(());
        };
        if txn
            .get_for_update_cf(
                column_family(self.states.db(), tables::MODEL_INDICATORS)?,
                indicator.as_bytes(),
                crate::EXCLUSIVE,
            )
            .context("cannot read model indicator")?
            .is_none()
        {
            return Err(TrainingError::IndicatorNotFound {
                indicator: indicator.to_string(),
            }
            .into());
        }
        Ok(())
    }
}

/// Ends `run`, active as read for update within `txn`, as `state`, `Failed`
/// or `Cancelled`, with `reason`.
///
/// A training run stays the last run of its definition. A clone run is
/// removed with the target definition it reserved, which frees the name.
pub(crate) fn end_run(
    txn: &Txn<'_>,
    runs: &ModelRuns<'_>,
    definitions: &TrainingDefinitions<'_>,
    run: ModelRun,
    state: RunState,
    reason: Option<&str>,
) -> Result<()> {
    if !matches!(state, RunState::Failed | RunState::Cancelled) {
        bail!("a run ends here only as failed or cancelled, not {state:?}");
    }
    if let RunKind::Clone { .. } = run.kind {
        if definitions
            .get_for_update(txn, &run.model)?
            .is_some_and(|target| target.cloning && target.last_run == Some(run.id))
        {
            definitions.delete(txn, &run.model)?;
        }
        return runs.delete(txn, run.id);
    }
    runs.put(
        txn,
        &ModelRun {
            state,
            reason: reason.map(ToString::to_string),
            updated_at: Utc::now(),
            ..run
        },
    )
}

/// Fails, within `txn`, every active run `instance` performs, with `reason`,
/// reading the run id counter for update before scanning the runs.
pub(crate) fn fail_active_runs(
    txn: &Txn<'_>,
    runs: &ModelRuns<'_>,
    definitions: &TrainingDefinitions<'_>,
    instance: &ModelInstance,
    reason: &str,
) -> Result<()> {
    runs.last_id_for_update(txn)?;
    for scanned in runs.scan(txn)? {
        if !scanned.state.is_active() || scanned.instance != *instance {
            continue;
        }
        if let Some(run) = runs.get_for_update(txn, scanned.id)?
            && run.state.is_active()
        {
            end_run(txn, runs, definitions, run, RunState::Failed, Some(reason))?;
        }
    }
    Ok(())
}

/// Returns the stored form of a new definition, its timestamps to be set
/// when it is written.
fn new_record(definition: NewTrainingDefinition, cloning: bool) -> TrainingDefinition {
    let now = Utc::now();
    TrainingDefinition {
        name: definition.name,
        customer_id: definition.customer_id,
        instance: Some(definition.instance),
        method: definition.method,
        event_kind: definition.event_kind,
        sources: definition.sources,
        indicator: definition.indicator,
        definition: definition.definition,
        cloning,
        last_run: None,
        created_at: now,
        updated_at: now,
    }
}

/// Returns the model record `kind` of `method`.
fn method_kind(method: ModelMethod) -> String {
    crate::model::ClusteringMethod::from(method).to_string()
}

/// A hook the tests run in every training writer, except
/// [`Store::complete_run`], after its checks and before its commit, with the
/// store running the writer; an error it returns ends the writer with that
/// error.
#[cfg(test)]
pub(crate) type TrainingHook = std::sync::Arc<dyn Fn(&Store) -> Result<()> + Send + Sync>;

#[cfg(test)]
impl Store {
    pub(crate) fn set_training_hook(&self, hook: Option<TrainingHook>) {
        *self
            .training_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    pub(crate) fn run_training_hook(&self) -> Result<()> {
        let hook = self
            .training_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        hook.map_or(Ok(()), |hook| hook(self))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;
    use crate::{
        Agent, AgentStatus, ModelIndicator, Node, NodeProfile,
        model_lifecycle::ModelFilesPoint,
        test::{DbGuard, acquire_db_permit},
    };

    const ENGINE: &str = "reconverge";
    const OTHER_ENGINE: &str = "reconverge-2";
    const UNNUMBERED: &str = "reconverge-unnumbered";
    const SENSOR: &str = "piglet";
    const CUSTOMER: u32 = 1;
    const OTHER_CUSTOMER: u32 = 2;
    const INDICATOR: &str = "tokens";

    type Entries = Vec<(Vec<u8>, Vec<u8>)>;

    struct TestStore {
        _permit: DbGuard<'static>,
        store: Store,
        db_dir: tempfile::TempDir,
        backup_dir: tempfile::TempDir,
    }

    /// A store with three nodes: `node` of [`CUSTOMER`] with the engines
    /// [`ENGINE`] and [`OTHER_ENGINE`], an Unsupervised agent with no
    /// instance number and a sensor; `other_node` of [`OTHER_CUSTOMER`] with
    /// [`ENGINE`]; `bare_node`, with no applied profile, with [`ENGINE`]. The
    /// model indicator [`INDICATOR`] exists.
    struct Fixture {
        t: TestStore,
        node: u32,
        other_node: u32,
        bare_node: u32,
    }

    impl Fixture {
        fn store(&self) -> &Store {
            &self.t.store
        }
    }

    fn agent(key: &str, kind: AgentKind, instance: Option<u32>) -> Agent {
        let mut agent =
            Agent::new(0, key.to_string(), kind, AgentStatus::Enabled, None, None).unwrap();
        agent.instance = instance;
        agent
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
        let node = insert_node(
            &store,
            "node",
            Some(CUSTOMER),
            vec![
                agent(ENGINE, AgentKind::Unsupervised, Some(1)),
                agent(OTHER_ENGINE, AgentKind::Unsupervised, Some(2)),
                agent(UNNUMBERED, AgentKind::Unsupervised, None),
                agent(SENSOR, AgentKind::Sensor, Some(1)),
            ],
        );
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
        store
            .model_indicator_map()
            .insert(ModelIndicator {
                name: INDICATOR.to_string(),
                ..ModelIndicator::default()
            })
            .unwrap();
        Fixture {
            t: TestStore {
                _permit: permit,
                store,
                db_dir,
                backup_dir,
            },
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

    fn eps(value: &str) -> String {
        format!("eps = {value}")
    }

    /// A multidimension definition of `http` events, of [`CUSTOMER`] unless
    /// changed.
    fn new_definition(name: &str, instance: ModelInstance) -> NewTrainingDefinition {
        NewTrainingDefinition {
            name: name.to_string(),
            customer_id: CUSTOMER,
            instance,
            method: ModelMethod::Multidimension,
            event_kind: "http".to_string(),
            sources: vec!["sensor-a".to_string()],
            indicator: None,
            definition: eps("5.0"),
        }
    }

    fn update_with(definition: &str) -> TrainingDefinitionUpdate {
        TrainingDefinitionUpdate {
            method: ModelMethod::Multidimension,
            event_kind: "http".to_string(),
            sources: vec!["sensor-a".to_string()],
            indicator: None,
            definition: definition.to_string(),
        }
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

    fn model(store: &Store, name: &str) -> tables::Model {
        store.model_map().load_model_by_name(name).unwrap()
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

    /// Writes `definition` as is, past every check.
    fn put_definition(store: &Store, definition: &TrainingDefinition) {
        let txn = store.states.db().transaction();
        store
            .states
            .training_definitions()
            .put(&txn, definition)
            .unwrap();
        txn.commit().unwrap();
    }

    /// Writes `run` as is, past every check.
    fn put_run(store: &Store, run: &ModelRun) {
        let txn = store.states.db().transaction();
        store.states.model_runs().put(&txn, run).unwrap();
        txn.commit().unwrap();
    }

    fn counter(store: &Store) -> Option<RunId> {
        let txn = store.states.db().transaction();
        store.states.model_runs().last_id_for_update(&txn).unwrap()
    }

    /// Every row of the families a training writer reads or writes.
    fn dump(store: &Store) -> Vec<Entries> {
        let db = store.states.db();
        [
            tables::TRAINING_DEFINITIONS,
            tables::MODEL_RUNS,
            tables::META,
            tables::MODELS,
            tables::SCORES,
            tables::PREVIOUS_SCORES,
            tables::ENGINE_INSTANCES,
            tables::AGENTS,
            tables::NODES,
            tables::MODEL_INDICATORS,
        ]
        .into_iter()
        .map(|name| {
            db.iterator_cf(db.cf_handle(name).unwrap(), rocksdb::IteratorMode::Start)
                .map(|entry| {
                    let (key, value) = entry.unwrap();
                    (key.to_vec(), value.to_vec())
                })
                .collect()
        })
        .collect()
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

    /// Returns a hook that runs `action` the first time it is called and does
    /// nothing afterwards.
    fn once(action: impl Fn(&Store) + Send + Sync + 'static) -> TrainingHook {
        let fired = AtomicBool::new(false);
        Arc::new(move |store| {
            if !fired.swap(true, Ordering::SeqCst) {
                action(store);
            }
            Ok(())
        })
    }

    #[test]
    fn model_method_maps_to_model_kinds() {
        for (method, kind) in [
            (ModelMethod::Multidimension, "Multifield"),
            (ModelMethod::Prefix, "Prefix"),
            (ModelMethod::Timeseries, "Timeseries"),
        ] {
            assert_eq!(method_kind(method), kind);
            let clustering: crate::model::ClusteringMethod = kind.parse().unwrap();
            assert_eq!(ModelMethod::try_from(clustering).unwrap(), method);
        }
        assert!(ModelMethod::try_from(crate::model::ClusteringMethod::Distribution).is_err());
    }

    #[test]
    fn insert_stores_a_definition_with_no_run() {
        let f = setup();
        let store = f.store();
        let before = Utc::now();
        let mut second = new_definition("b", instance(f.node, ENGINE));
        second.indicator = Some(INDICATOR.to_string());
        store.insert_training_definition(second).unwrap();
        store
            .insert_training_definition(new_definition("a", instance(f.node, OTHER_ENGINE)))
            .unwrap();

        let stored = definition(store, "b");
        assert!(stored.created_at >= before);
        assert_eq!(
            stored,
            TrainingDefinition {
                name: "b".to_string(),
                customer_id: CUSTOMER,
                instance: Some(instance(f.node, ENGINE)),
                method: ModelMethod::Multidimension,
                event_kind: "http".to_string(),
                sources: vec!["sensor-a".to_string()],
                indicator: Some(INDICATOR.to_string()),
                definition: eps("5.0"),
                cloning: false,
                last_run: None,
                created_at: stored.created_at,
                updated_at: stored.created_at,
            }
        );
        let names: Vec<String> = store
            .training_definitions()
            .unwrap()
            .into_iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(names, ["a", "b"]);
        assert_eq!(state(store, "b"), TrainingDefinitionState::NeverTrained);
        assert_eq!(store.training_definition("c").unwrap(), None);
        assert_eq!(store.training_definition_state("c").unwrap(), None);
    }

    #[test]
    fn definition_and_model_names_share_one_namespace() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        store
            .insert_training_definition(new_definition("taken", engine.clone()))
            .unwrap();
        assert_eq!(
            refusal(store, |s| s.insert_training_definition(new_definition(
                "taken",
                instance(f.node, OTHER_ENGINE)
            ))),
            TrainingError::NameTaken {
                name: "taken".to_string()
            }
        );

        // A model stored without a definition still takes its name.
        store
            .replace_model(
                body("bare"),
                ModelOwner {
                    customer_id: CUSTOMER,
                    instance: engine.clone(),
                },
                Utc::now(),
                TrainedWith {
                    run_id: 0,
                    definition: eps("1.0"),
                },
            )
            .unwrap();
        assert_eq!(
            refusal(store, |s| s.insert_training_definition(new_definition(
                "bare",
                engine.clone()
            ))),
            TrainingError::NameTaken {
                name: "bare".to_string()
            }
        );
    }

    #[test]
    fn insert_refuses_names_instances_customers_and_indicators() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);

        for (name, reason) in [
            ("", "must be 1-255 bytes"),
            ("a/b", "contains path separators or traversal sequences"),
            ("a..b", "contains path separators or traversal sequences"),
            ("a:b", "contains forbidden characters"),
        ] {
            assert_eq!(
                refusal(store, |s| s.insert_training_definition(new_definition(
                    name,
                    engine.clone()
                ))),
                TrainingError::InvalidName {
                    name: name.to_string(),
                    reason: reason.to_string(),
                }
            );
        }
        let long = "x".repeat(256);
        assert!(matches!(
            refusal(store, |s| s.insert_training_definition(new_definition(
                &long,
                engine.clone()
            ))),
            TrainingError::InvalidName { .. }
        ));

        for (node_id, agent_key) in [
            (f.node, SENSOR),
            (f.node, UNNUMBERED),
            (f.node, "missing"),
            (99, ENGINE),
        ] {
            assert_eq!(
                refusal(store, |s| s.insert_training_definition(new_definition(
                    "d",
                    instance(node_id, agent_key)
                ))),
                TrainingError::InstanceNotEligible {
                    node_id,
                    agent_key: agent_key.to_string(),
                }
            );
        }

        assert_eq!(
            refusal(store, |s| s.insert_training_definition(new_definition(
                "d",
                instance(f.bare_node, ENGINE)
            ))),
            TrainingError::NoAppliedProfile {
                node_id: f.bare_node
            }
        );

        let mut foreign = new_definition("d", engine.clone());
        foreign.customer_id = OTHER_CUSTOMER;
        assert_eq!(
            refusal(store, |s| s.insert_training_definition(foreign)),
            TrainingError::CustomerMismatch {
                node_id: f.node,
                node_customer_id: CUSTOMER,
                customer_id: OTHER_CUSTOMER,
            }
        );

        let mut missing = new_definition("d", engine.clone());
        missing.indicator = Some("missing".to_string());
        assert_eq!(
            refusal(store, |s| s.insert_training_definition(missing)),
            TrainingError::IndicatorNotFound {
                indicator: "missing".to_string()
            }
        );

        let mut other = new_definition("d", instance(f.other_node, ENGINE));
        other.customer_id = OTHER_CUSTOMER;
        store.insert_training_definition(other).unwrap();
    }

    #[test]
    fn update_replaces_the_settings_between_runs() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        store
            .insert_training_definition(new_definition("d", engine.clone()))
            .unwrap();
        let created = definition(store, "d");

        assert_eq!(
            refusal(store, |s| s
                .update_training_definition("x", update_with("x"))),
            TrainingError::DefinitionNotFound {
                name: "x".to_string()
            }
        );

        // Before a model exists, the method and the event kind may change.
        let update = TrainingDefinitionUpdate {
            method: ModelMethod::Prefix,
            event_kind: "dns".to_string(),
            sources: vec!["sensor-b".to_string()],
            indicator: Some(INDICATOR.to_string()),
            definition: eps("3.0"),
        };
        store
            .update_training_definition("d", update.clone())
            .unwrap();
        let updated = definition(store, "d");
        assert!(updated.updated_at >= created.updated_at);
        assert_eq!(
            updated,
            TrainingDefinition {
                method: ModelMethod::Prefix,
                event_kind: "dns".to_string(),
                sources: vec!["sensor-b".to_string()],
                indicator: Some(INDICATOR.to_string()),
                definition: eps("3.0"),
                updated_at: updated.updated_at,
                ..created.clone()
            }
        );

        let mut missing = update_with("x");
        missing.indicator = Some("missing".to_string());
        assert_eq!(
            refusal(store, |s| s.update_training_definition("d", missing)),
            TrainingError::IndicatorNotFound {
                indicator: "missing".to_string()
            }
        );

        store
            .update_training_definition("d", update_with(&eps("5.0")))
            .unwrap();
        let started = store.start_training_run("d").unwrap();
        assert_eq!(
            refusal(store, |s| s
                .update_training_definition("d", update_with("x"))),
            TrainingError::RunInProgress {
                run_id: started.run.id
            }
        );
        store
            .report_run(started.run.id, &engine, ReportedRunState::Started, None)
            .unwrap();
        assert_eq!(
            refusal(store, |s| s
                .update_training_definition("d", update_with("x"))),
            TrainingError::RunInProgress {
                run_id: started.run.id
            }
        );
        store
            .complete_run(started.run.id, &engine, body("d"))
            .unwrap();

        // Once the model exists, the method and the event kind are fixed.
        let mut method = update_with("x");
        method.method = ModelMethod::Timeseries;
        assert_eq!(
            refusal(store, |s| s.update_training_definition("d", method)),
            TrainingError::FieldFixed {
                name: "d".to_string(),
                field: FixedField::Method,
            }
        );
        let mut event_kind = update_with("x");
        event_kind.event_kind = "dns".to_string();
        assert_eq!(
            refusal(store, |s| s.update_training_definition("d", event_kind)),
            TrainingError::FieldFixed {
                name: "d".to_string(),
                field: FixedField::EventKind,
            }
        );
        store
            .update_training_definition("d", update_with(&eps("2.0")))
            .unwrap();
        let after = definition(store, "d");
        assert_eq!(after.definition, eps("2.0"));
        assert_eq!(after.customer_id, CUSTOMER);
        assert_eq!(after.instance, Some(engine));
        assert_eq!(after.last_run, Some(started.run.id));
        assert_eq!(after.created_at, created.created_at);
    }

    #[test]
    fn remove_takes_the_definition_with_its_runs() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        store
            .insert_training_definition(new_definition("d", engine.clone()))
            .unwrap();
        store
            .insert_training_definition(new_definition("kept", instance(f.node, OTHER_ENGINE)))
            .unwrap();

        assert_eq!(
            refusal(store, |s| s.remove_training_definition("x")),
            TrainingError::DefinitionNotFound {
                name: "x".to_string()
            }
        );

        let first = store.start_training_run("d").unwrap().run.id;
        assert_eq!(
            refusal(store, |s| s.remove_training_definition("d")),
            TrainingError::RunInProgress { run_id: first }
        );
        store.fail_run(first, "unreachable").unwrap();
        let second = store.start_training_run("d").unwrap().run.id;
        store
            .report_run(second, &engine, ReportedRunState::Cancelled, None)
            .unwrap();
        let kept = store.start_training_run("kept").unwrap().run.id;

        store.remove_training_definition("d").unwrap();
        assert_eq!(store.training_definition("d").unwrap(), None);
        assert_eq!(store.model_run(first).unwrap(), None);
        assert_eq!(store.model_run(second).unwrap(), None);
        assert_eq!(store.model_runs("d").unwrap(), Vec::new());
        assert_eq!(run(store, kept).model, "kept");

        // A definition with a model goes only with the model.
        store.fail_run(kept, "unreachable").unwrap();
        train(store, "kept", &instance(f.node, OTHER_ENGINE));
        assert_eq!(
            refusal(store, |s| s.remove_training_definition("kept")),
            TrainingError::HasModel {
                name: "kept".to_string()
            }
        );
    }

    #[test]
    fn run_ids_increase_across_removal_and_reopen() {
        let f = setup();
        let Fixture { t, node, .. } = f;
        let engine = instance(node, ENGINE);
        assert_eq!(counter(&t.store), None);
        t.store
            .insert_training_definition(new_definition("d", engine.clone()))
            .unwrap();
        let first = t.store.start_training_run("d").unwrap().run.id;
        assert_eq!(first, 1);
        t.store.fail_run(first, "unreachable").unwrap();
        t.store.remove_training_definition("d").unwrap();
        t.store
            .insert_training_definition(new_definition("d", engine.clone()))
            .unwrap();
        let second = t.store.start_training_run("d").unwrap().run.id;
        assert_eq!(second, 2);
        t.store.fail_run(second, "unreachable").unwrap();
        assert_eq!(counter(&t.store), Some(2));

        let TestStore {
            _permit,
            store,
            db_dir,
            backup_dir,
        } = t;
        drop(store);
        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
        assert_eq!(counter(&store), Some(2));
        assert_eq!(store.start_training_run("d").unwrap().run.id, 3);
    }

    #[test]
    fn run_ids_run_out_at_the_maximum() {
        let f = setup();
        let store = f.store();
        store
            .insert_training_definition(new_definition("d", instance(f.node, ENGINE)))
            .unwrap();
        let txn = store.states.db().transaction();
        txn.put_cf(
            store.states.db().cf_handle(tables::META).unwrap(),
            tables::MODEL_RUN_ID_COUNTER,
            RunId::MAX.to_be_bytes(),
        )
        .unwrap();
        txn.commit().unwrap();

        let before = dump(store);
        let error = store.start_training_run("d").unwrap_err();
        assert!(error.downcast_ref::<TrainingError>().is_none());
        assert_eq!(dump(store), before);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn run_states_move_only_forward() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        let other = instance(f.node, OTHER_ENGINE);
        store
            .insert_training_definition(new_definition("d", engine.clone()))
            .unwrap();

        let started = store.start_training_run("d").unwrap();
        let id = started.run.id;
        assert_eq!(started.run.kind, RunKind::Train);
        assert_eq!(started.run.model, "d");
        assert_eq!(started.run.instance, engine);
        assert_eq!(started.run.state, RunState::Requested);
        assert_eq!(started.run.reason, None);
        assert_eq!(started.run.updated_at, started.run.requested_at);
        assert_eq!(run(store, id), started.run);
        assert_eq!(definition(store, "d").last_run, Some(id));

        assert_eq!(
            refusal(store, |s| s.report_run(
                99,
                &engine,
                ReportedRunState::Started,
                None
            )),
            TrainingError::RunNotFound { run_id: 99 }
        );
        assert_eq!(
            refusal(store, |s| s.report_run(
                id,
                &other,
                ReportedRunState::Started,
                None
            )),
            TrainingError::RunOfAnotherInstance { run_id: id }
        );
        assert_eq!(
            refusal(store, |s| s.complete_run(id, &other, body("d"))),
            TrainingError::RunOfAnotherInstance { run_id: id }
        );

        store
            .report_run(id, &engine, ReportedRunState::Started, Some("loading"))
            .unwrap();
        let reported = run(store, id);
        assert_eq!(reported.state, RunState::Started);
        assert_eq!(reported.reason.as_deref(), Some("loading"));
        assert!(reported.updated_at >= reported.requested_at);
        assert_eq!(
            refusal(store, |s| s.report_run(
                id,
                &engine,
                ReportedRunState::Started,
                None
            )),
            TrainingError::InvalidTransition {
                run_id: id,
                from: RunState::Started,
                to: ReportedRunState::Started,
            }
        );

        store
            .report_run(id, &engine, ReportedRunState::Failed, Some("out of memory"))
            .unwrap();
        let failed = run(store, id);
        assert_eq!(failed.state, RunState::Failed);
        assert_eq!(failed.reason.as_deref(), Some("out of memory"));
        for reported in [
            ReportedRunState::Started,
            ReportedRunState::Failed,
            ReportedRunState::Cancelled,
        ] {
            assert_eq!(
                refusal(store, |s| s.report_run(id, &engine, reported, None)),
                TrainingError::RunNotActive {
                    run_id: id,
                    state: RunState::Failed,
                }
            );
        }
        assert_eq!(
            refusal(store, |s| s.fail_run(id, "again")),
            TrainingError::RunNotActive {
                run_id: id,
                state: RunState::Failed,
            }
        );
        assert_eq!(
            refusal(store, |s| s.complete_run(id, &engine, body("d"))),
            TrainingError::RunNotActive {
                run_id: id,
                state: RunState::Failed,
            }
        );
        assert_eq!(
            refusal(store, |s| s.fail_run(99, "unknown")),
            TrainingError::RunNotFound { run_id: 99 }
        );

        // `Cancelled` from either active state, `Failed` through `fail_run`
        // from either active state.
        let id = store.start_training_run("d").unwrap().run.id;
        store
            .report_run(id, &engine, ReportedRunState::Cancelled, None)
            .unwrap();
        assert_eq!(run(store, id).state, RunState::Cancelled);
        let id = store.start_training_run("d").unwrap().run.id;
        store
            .report_run(id, &engine, ReportedRunState::Started, None)
            .unwrap();
        store
            .report_run(id, &engine, ReportedRunState::Cancelled, Some("asked"))
            .unwrap();
        assert_eq!(run(store, id).state, RunState::Cancelled);
        assert_eq!(run(store, id).reason.as_deref(), Some("asked"));
        let id = store.start_training_run("d").unwrap().run.id;
        store.fail_run(id, "instance unreachable").unwrap();
        assert_eq!(run(store, id).state, RunState::Failed);
        assert_eq!(
            run(store, id).reason.as_deref(),
            Some("instance unreachable")
        );
        let id = store.start_training_run("d").unwrap().run.id;
        store
            .report_run(id, &engine, ReportedRunState::Started, None)
            .unwrap();
        store.fail_run(id, "instance unreachable").unwrap();
        assert_eq!(run(store, id).state, RunState::Failed);

        // `Succeeded` from either active state.
        let id = store.start_training_run("d").unwrap().run.id;
        store.complete_run(id, &engine, body("d")).unwrap();
        assert_eq!(run(store, id).state, RunState::Succeeded);
        assert_eq!(run(store, id).reason, None);
        let id = store.start_training_run("d").unwrap().run.id;
        store
            .report_run(id, &engine, ReportedRunState::Started, Some("loading"))
            .unwrap();
        store.complete_run(id, &engine, body("d")).unwrap();
        assert_eq!(run(store, id).state, RunState::Succeeded);
        assert_eq!(run(store, id).reason, None);
        assert_eq!(
            refusal(store, |s| s.complete_run(id, &engine, body("d"))),
            TrainingError::RunNotActive {
                run_id: id,
                state: RunState::Succeeded,
            }
        );
        let ids: Vec<RunId> = store
            .model_runs("d")
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(ids, (1..=7).collect::<Vec<_>>());
    }

    #[test]
    fn start_training_run_refusals() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        store
            .insert_training_definition(new_definition("d", engine.clone()))
            .unwrap();
        store
            .insert_training_definition(new_definition("e", engine.clone()))
            .unwrap();
        store
            .insert_training_definition(new_definition("o", instance(f.node, OTHER_ENGINE)))
            .unwrap();

        assert_eq!(
            refusal(store, |s| s.start_training_run("x")),
            TrainingError::DefinitionNotFound {
                name: "x".to_string()
            }
        );
        put_definition(
            store,
            &TrainingDefinition {
                name: "detached".to_string(),
                instance: None,
                ..definition(store, "d")
            },
        );
        assert_eq!(
            refusal(store, |s| s.start_training_run("detached")),
            TrainingError::NoInstance {
                name: "detached".to_string()
            }
        );

        // One active run per definition and per instance; another instance
        // runs independently.
        let id = store.start_training_run("d").unwrap().run.id;
        assert_eq!(
            refusal(store, |s| s.start_training_run("d")),
            TrainingError::RunInProgress { run_id: id }
        );
        assert_eq!(
            refusal(store, |s| s.start_training_run("e")),
            TrainingError::RunInProgress { run_id: id }
        );
        let other = store.start_training_run("o").unwrap().run.id;
        store
            .report_run(id, &engine, ReportedRunState::Started, None)
            .unwrap();
        assert_eq!(
            refusal(store, |s| s.start_training_run("e")),
            TrainingError::RunInProgress { run_id: id }
        );
        store.fail_run(id, "unreachable").unwrap();
        let e = store.start_training_run("e").unwrap().run.id;
        store.fail_run(e, "unreachable").unwrap();
        store.fail_run(other, "unreachable").unwrap();

        store.set_engine_instance_stopped(&engine, true).unwrap();
        assert_eq!(
            refusal(store, |s| s.start_training_run("d")),
            TrainingError::InstanceStopped {
                node_id: f.node,
                agent_key: ENGINE.to_string(),
            }
        );
        store.set_engine_instance_stopped(&engine, false).unwrap();

        // An instance whose agent row is gone, its records still attached.
        store.agents_map().delete(f.node, ENGINE).unwrap();
        assert_eq!(
            refusal(store, |s| s.start_training_run("d")),
            TrainingError::InstanceNotEligible {
                node_id: f.node,
                agent_key: ENGINE.to_string(),
            }
        );
    }

    #[test]
    fn stopping_an_instance_fails_its_active_runs() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        let other = instance(f.node, OTHER_ENGINE);
        store
            .insert_training_definition(new_definition("d", engine.clone()))
            .unwrap();
        store
            .insert_training_definition(new_definition("o", other.clone()))
            .unwrap();
        let id = store.start_training_run("d").unwrap().run.id;
        let kept = store.start_training_run("o").unwrap().run.id;

        // Recording that an instance is not stopped changes no run.
        store.set_engine_instance_stopped(&engine, false).unwrap();
        assert_eq!(run(store, id).state, RunState::Requested);

        store
            .report_run(id, &engine, ReportedRunState::Started, None)
            .unwrap();
        store.set_engine_instance_stopped(&engine, true).unwrap();
        let failed = run(store, id);
        assert_eq!(failed.state, RunState::Failed);
        assert_eq!(failed.reason.as_deref(), Some(INSTANCE_STOPPED));
        assert_eq!(definition(store, "d").last_run, Some(id));
        assert_eq!(run(store, kept).state, RunState::Requested);
        assert!(store.engine_instance_state(&engine).unwrap().stopped);
        assert_eq!(state(store, "d"), TrainingDefinitionState::TrainingFailed);
    }

    #[test]
    fn complete_run_inserts_then_replaces_the_model() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        store
            .insert_training_definition(new_definition("d", engine.clone()))
            .unwrap();

        let first = store.start_training_run("d").unwrap();
        let before = Utc::now();
        let replaced = store
            .complete_run(first.run.id, &engine, body("d"))
            .unwrap();
        assert!(replaced.inserted);
        let record = model(store, "d");
        assert_eq!(record.id, replaced.id);
        assert_eq!(record.customer_id, CUSTOMER);
        assert_eq!(record.instance, Some(engine.clone()));
        assert_eq!(record.trained_run_id, first.run.id);
        assert_eq!(record.trained_definition, first.definition);
        assert!(record.trained_at >= before);
        assert_eq!(record.previous, None);
        let succeeded = run(store, first.run.id);
        assert_eq!(succeeded.state, RunState::Succeeded);
        assert!(succeeded.updated_at >= before);
        assert_eq!(state(store, "d"), TrainingDefinitionState::Ready);

        store
            .update_training_definition("d", update_with(&eps("2.0")))
            .unwrap();
        let second = store.start_training_run("d").unwrap();
        assert_eq!(second.definition, eps("2.0"));
        assert_eq!(state(store, "d"), TrainingDefinitionState::Training);
        let replaced = store
            .complete_run(second.run.id, &engine, body("d"))
            .unwrap();
        assert!(!replaced.inserted);
        let record = model(store, "d");
        assert_eq!(record.id, replaced.id);
        assert_eq!(record.trained_run_id, second.run.id);
        assert_eq!(record.trained_definition, eps("2.0"));
        let previous = record.previous.unwrap();
        assert_eq!(previous.trained_run_id, first.run.id);
        assert_eq!(previous.trained_definition, eps("5.0"));
    }

    #[test]
    fn complete_run_refusals_leave_the_run_active() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        store
            .insert_training_definition(new_definition("d", engine.clone()))
            .unwrap();
        let id = store.start_training_run("d").unwrap().run.id;

        assert_eq!(
            refusal(store, |s| s.complete_run(99, &engine, body("d"))),
            TrainingError::RunNotFound { run_id: 99 }
        );
        assert_eq!(
            refusal(store, |s| s.complete_run(id, &engine, body("other"))),
            TrainingError::ModelNameMismatch {
                run_id: id,
                expected: "d".to_string(),
                uploaded: "other".to_string(),
            }
        );
        for kind in ["Prefix", "Distribution", "Unknown"] {
            let mut upload = body("d");
            upload.kind = kind.to_string();
            assert_eq!(
                refusal(store, |s| s.complete_run(id, &engine, upload)),
                TrainingError::MethodMismatch {
                    name: "d".to_string(),
                    expected: ModelMethod::Multidimension,
                    actual: kind.to_string(),
                }
            );
        }
        let mut upload = body("d");
        upload.event_kind = "dns".to_string();
        assert_eq!(
            refusal(store, |s| s.complete_run(id, &engine, upload)),
            TrainingError::EventKindMismatch {
                name: "d".to_string(),
                expected: "http".to_string(),
                actual: "dns".to_string(),
            }
        );

        let stored = definition(store, "d");
        put_definition(
            store,
            &TrainingDefinition {
                instance: None,
                ..stored.clone()
            },
        );
        assert_eq!(
            refusal(store, |s| s.complete_run(id, &engine, body("d"))),
            TrainingError::NoInstance {
                name: "d".to_string()
            }
        );
        let txn = store.states.db().transaction();
        store
            .states
            .training_definitions()
            .delete(&txn, "d")
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(
            refusal(store, |s| s.complete_run(id, &engine, body("d"))),
            TrainingError::DefinitionNotFound {
                name: "d".to_string()
            }
        );
        put_definition(store, &stored);

        assert_eq!(run(store, id).state, RunState::Requested);
        assert!(store.model_map().load_model_by_name("d").is_err());
        store.complete_run(id, &engine, body("d")).unwrap();
    }

    #[test]
    fn complete_run_refused_by_the_replace_core_leaves_the_run_active() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        store
            .insert_training_definition(new_definition("d", engine.clone()))
            .unwrap();
        train(store, "d", &engine);
        let id = store.start_training_run("d").unwrap().run.id;

        // The model now belongs to another owner than the definition.
        let models = store.model_map();
        let txn = store.states.db().transaction();
        let record = models
            .load_model_by_name_in_transaction("d", &txn)
            .unwrap()
            .unwrap();
        models
            .update_model_with_transaction(
                &record,
                &tables::Model {
                    customer_id: OTHER_CUSTOMER,
                    ..record.clone()
                },
                &txn,
            )
            .unwrap();
        txn.commit().unwrap();

        let before = dump(store);
        let error = store.complete_run(id, &engine, body("d")).unwrap_err();
        assert!(error.to_string().contains("another owner"), "{error:#}");
        assert_eq!(dump(store), before);
        assert_eq!(run(store, id).state, RunState::Requested);
    }

    #[test]
    fn complete_run_failing_before_its_commit_changes_nothing() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        store
            .insert_training_definition(new_definition("d", engine.clone()))
            .unwrap();
        train(store, "d", &engine);
        let id = store.start_training_run("d").unwrap().run.id;

        let fired = Arc::new(AtomicBool::new(false));
        let hook_fired = fired.clone();
        store.set_model_files_hook(Some(Arc::new(move |point| {
            if point == ModelFilesPoint::BeforeCommit && !hook_fired.swap(true, Ordering::SeqCst) {
                return Err(anyhow!("crash before the commit"));
            }
            Ok(())
        })));
        let before = dump(store);
        let record = model(store, "d");
        let error = store.complete_run(id, &engine, body("d")).unwrap_err();
        assert!(fired.load(Ordering::SeqCst));
        assert_eq!(error.to_string(), "crash before the commit");
        assert_eq!(dump(store), before);
        assert_eq!(model(store, "d"), record);
        assert_eq!(run(store, id).state, RunState::Requested);

        let replaced = store.complete_run(id, &engine, body("d")).unwrap();
        assert!(!replaced.inserted);
        assert_eq!(run(store, id).state, RunState::Succeeded);
        assert_eq!(model(store, "d").trained_run_id, id);
        store.set_model_files_hook(None);
    }

    #[test]
    fn complete_run_records_the_text_start_returned() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        let mut new = new_definition("d", engine.clone());
        new.definition = "eps = 4.0\nmin_samples = 3\n".to_string();
        store.insert_training_definition(new).unwrap();

        let started = store.start_training_run("d").unwrap();
        assert_eq!(started.definition, "eps = 4.0\nmin_samples = 3\n");
        assert_eq!(
            refusal(store, |s| s
                .update_training_definition("d", update_with("x"))),
            TrainingError::RunInProgress {
                run_id: started.run.id
            }
        );
        store
            .complete_run(started.run.id, &engine, body("d"))
            .unwrap();
        let record = model(store, "d");
        assert_eq!(record.trained_definition, started.definition);
        assert_eq!(record.trained_run_id, started.run.id);
        store
            .update_training_definition("d", update_with("x"))
            .unwrap();
    }

    /// Train with `eps = 5.0`, then edit the definition to `eps = 2.0`: the
    /// model keeps the snapshot it was trained with, a clone built from that
    /// snapshot carries it, and a retrain moves it into `previous`.
    #[test]
    fn the_trained_definition_is_a_snapshot() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        store
            .insert_training_definition(new_definition("source", engine.clone()))
            .unwrap();
        let first = train(store, "source", &engine);
        store
            .update_training_definition("source", update_with(&eps("2.0")))
            .unwrap();

        // (a)
        let record = model(store, "source");
        assert_eq!(record.trained_definition, eps("5.0"));
        assert_eq!(record.trained_run_id, first);
        assert_eq!(definition(store, "source").definition, eps("2.0"));

        // (b)
        let mut target = new_definition("clone", instance(f.node, OTHER_ENGINE));
        target.definition.clone_from(&record.trained_definition);
        let clone = store
            .start_clone_run("source", record.trained_run_id, target)
            .unwrap();
        assert_eq!(clone.instance, engine);
        store
            .complete_run(clone.id, &engine, body("clone"))
            .unwrap();
        let cloned = model(store, "clone");
        assert_eq!(cloned.trained_definition, eps("5.0"));
        assert_eq!(cloned.trained_run_id, clone.id);
        assert_eq!(cloned.instance, Some(instance(f.node, OTHER_ENGINE)));
        let target = definition(store, "clone");
        assert_eq!(target.definition, eps("5.0"));
        assert!(!target.cloning);
        assert_eq!(target.last_run, Some(clone.id));
        assert_eq!(state(store, "clone"), TrainingDefinitionState::Ready);

        // (c)
        let retrain = train(store, "source", &engine);
        let record = model(store, "source");
        assert_eq!(record.trained_definition, eps("2.0"));
        assert_eq!(record.trained_run_id, retrain);
        let previous = record.previous.unwrap();
        assert_eq!(previous.trained_definition, eps("5.0"));
        assert_eq!(previous.trained_run_id, first);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn clone_reserves_its_target_and_checks_its_source() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        let other = instance(f.node, OTHER_ENGINE);
        store
            .insert_training_definition(new_definition("source", engine.clone()))
            .unwrap();
        let trained = train(store, "source", &engine);
        let target = || new_definition("target", other.clone());

        assert_eq!(
            refusal(store, |s| s.start_clone_run("missing", trained, target())),
            TrainingError::ModelNotFound {
                name: "missing".to_string()
            }
        );
        assert_eq!(
            refusal(store, |s| s.start_clone_run(
                "source",
                trained + 1,
                target()
            )),
            TrainingError::SourceRetrained {
                source: "source".to_string(),
                expected: trained + 1,
                current: trained,
            }
        );
        let mut method = target();
        method.method = ModelMethod::Prefix;
        assert_eq!(
            refusal(store, |s| s.start_clone_run("source", trained, method)),
            TrainingError::MethodMismatch {
                name: "target".to_string(),
                expected: ModelMethod::Prefix,
                actual: "Multifield".to_string(),
            }
        );
        let mut event_kind = target();
        event_kind.event_kind = "dns".to_string();
        assert_eq!(
            refusal(store, |s| s.start_clone_run("source", trained, event_kind)),
            TrainingError::EventKindMismatch {
                name: "target".to_string(),
                expected: "dns".to_string(),
                actual: "http".to_string(),
            }
        );

        // The source's instance.
        let retrain = store.start_training_run("source").unwrap().run.id;
        assert_eq!(
            refusal(store, |s| s.start_clone_run("source", trained, target())),
            TrainingError::RunInProgress { run_id: retrain }
        );
        store.fail_run(retrain, "unreachable").unwrap();
        store.set_engine_instance_stopped(&engine, true).unwrap();
        assert_eq!(
            refusal(store, |s| s.start_clone_run("source", trained, target())),
            TrainingError::InstanceStopped {
                node_id: f.node,
                agent_key: ENGINE.to_string(),
            }
        );
        store.set_engine_instance_stopped(&engine, false).unwrap();

        // The target, as a definition insert checks it.
        store
            .insert_training_definition(new_definition("existing", other.clone()))
            .unwrap();
        let mut taken = target();
        taken.name = "existing".to_string();
        assert_eq!(
            refusal(store, |s| s.start_clone_run("source", trained, taken)),
            TrainingError::NameTaken {
                name: "existing".to_string()
            }
        );
        let mut taken = target();
        taken.name = "source".to_string();
        assert_eq!(
            refusal(store, |s| s.start_clone_run("source", trained, taken)),
            TrainingError::NameTaken {
                name: "source".to_string()
            }
        );
        let mut invalid = target();
        invalid.name = "a/b".to_string();
        assert!(matches!(
            refusal(store, |s| s.start_clone_run("source", trained, invalid)),
            TrainingError::InvalidName { .. }
        ));
        let mut sensor = target();
        sensor.instance = instance(f.node, SENSOR);
        assert_eq!(
            refusal(store, |s| s.start_clone_run("source", trained, sensor)),
            TrainingError::InstanceNotEligible {
                node_id: f.node,
                agent_key: SENSOR.to_string(),
            }
        );
        let mut bare = target();
        bare.instance = instance(f.bare_node, ENGINE);
        assert_eq!(
            refusal(store, |s| s.start_clone_run("source", trained, bare)),
            TrainingError::NoAppliedProfile {
                node_id: f.bare_node
            }
        );
        let mut foreign = target();
        foreign.customer_id = OTHER_CUSTOMER;
        assert_eq!(
            refusal(store, |s| s.start_clone_run("source", trained, foreign)),
            TrainingError::CustomerMismatch {
                node_id: f.node,
                node_customer_id: CUSTOMER,
                customer_id: OTHER_CUSTOMER,
            }
        );
        let mut indicator = target();
        indicator.indicator = Some("missing".to_string());
        assert_eq!(
            refusal(store, |s| s.start_clone_run("source", trained, indicator)),
            TrainingError::IndicatorNotFound {
                indicator: "missing".to_string()
            }
        );

        // A clone reserves its target's name at once.
        let clone = store.start_clone_run("source", trained, target()).unwrap();
        assert_eq!(
            clone.kind,
            RunKind::Clone {
                source: "source".to_string(),
                strip_events: false,
            }
        );
        assert_eq!(clone.model, "target");
        assert_eq!(clone.instance, engine);
        assert_eq!(clone.state, RunState::Requested);
        assert_eq!(run(store, clone.id), clone);
        let reserved = definition(store, "target");
        assert!(reserved.cloning);
        assert_eq!(reserved.last_run, Some(clone.id));
        assert_eq!(reserved.instance, Some(other.clone()));
        assert_eq!(state(store, "target"), TrainingDefinitionState::Cloning);
        assert_eq!(
            refusal(store, |s| s.insert_training_definition(new_definition(
                "target",
                other.clone()
            ))),
            TrainingError::NameTaken {
                name: "target".to_string()
            }
        );
        assert_eq!(
            refusal(store, |s| s
                .update_training_definition("target", update_with("x"))),
            TrainingError::RunInProgress { run_id: clone.id }
        );
        assert_eq!(
            refusal(store, |s| s.remove_training_definition("target")),
            TrainingError::RunInProgress { run_id: clone.id }
        );
        assert_eq!(
            refusal(store, |s| s.start_training_run("target")),
            TrainingError::RunInProgress { run_id: clone.id }
        );
        // The clone runs on the source's instance, which runs one run at a
        // time.
        assert_eq!(
            refusal(store, |s| s.start_training_run("source")),
            TrainingError::RunInProgress { run_id: clone.id }
        );
        assert_eq!(
            refusal(store, |s| s.complete_run(clone.id, &other, body("target"))),
            TrainingError::RunOfAnotherInstance { run_id: clone.id }
        );
    }

    #[test]
    fn clone_strips_events_exactly_across_customers() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        store
            .insert_training_definition(new_definition("source", engine.clone()))
            .unwrap();
        let trained = train(store, "source", &engine);

        let mut foreign = new_definition("foreign", instance(f.other_node, ENGINE));
        foreign.customer_id = OTHER_CUSTOMER;
        let clone = store.start_clone_run("source", trained, foreign).unwrap();
        assert_eq!(
            clone.kind,
            RunKind::Clone {
                source: "source".to_string(),
                strip_events: true,
            }
        );
        let replaced = store
            .complete_run(clone.id, &engine, body("foreign"))
            .unwrap();
        assert!(replaced.inserted);
        let record = model(store, "foreign");
        assert_eq!(record.customer_id, OTHER_CUSTOMER);
        assert_eq!(record.instance, Some(instance(f.other_node, ENGINE)));
    }

    #[test]
    fn clone_from_a_source_without_an_instance_is_refused() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        store
            .insert_training_definition(new_definition("source", engine.clone()))
            .unwrap();
        let trained = train(store, "source", &engine);
        let models = store.model_map();
        let txn = store.states.db().transaction();
        let record = models
            .load_model_by_name_in_transaction("source", &txn)
            .unwrap()
            .unwrap();
        models
            .update_model_with_transaction(
                &record,
                &tables::Model {
                    instance: None,
                    ..record.clone()
                },
                &txn,
            )
            .unwrap();
        txn.commit().unwrap();

        assert_eq!(
            refusal(store, |s| s.start_clone_run(
                "source",
                trained,
                new_definition("target", engine.clone())
            )),
            TrainingError::NoInstance {
                name: "source".to_string()
            }
        );
    }

    #[test]
    fn clone_from_an_uninstalled_instance_is_refused() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        store
            .insert_training_definition(new_definition("source", engine.clone()))
            .unwrap();
        let trained = train(store, "source", &engine);
        // The agent row is gone, the model still attached to its instance.
        store.agents_map().delete(f.node, ENGINE).unwrap();

        assert_eq!(
            refusal(store, |s| s.start_clone_run(
                "source",
                trained,
                new_definition("target", instance(f.node, OTHER_ENGINE))
            )),
            TrainingError::InstanceNotEligible {
                node_id: f.node,
                agent_key: ENGINE.to_string(),
            }
        );
    }

    /// A clone that ends failed or cancelled, by any path, removes its
    /// target definition and its own run record, which frees the name for a
    /// definition of any customer.
    #[test]
    fn an_unsuccessful_clone_frees_its_target_name() {
        type End = Box<dyn Fn(&Store, RunId, &ModelInstance)>;
        let ends: Vec<(&str, End)> = vec![
            (
                "report failed",
                Box::new(|store, id, engine| {
                    store
                        .report_run(id, engine, ReportedRunState::Failed, Some("crash"))
                        .unwrap();
                }),
            ),
            (
                "report cancelled",
                Box::new(|store, id, engine| {
                    store
                        .report_run(id, engine, ReportedRunState::Started, None)
                        .unwrap();
                    store
                        .report_run(id, engine, ReportedRunState::Cancelled, None)
                        .unwrap();
                }),
            ),
            (
                "fail",
                Box::new(|store, id, _| {
                    store.fail_run(id, "instance unreachable").unwrap();
                }),
            ),
            (
                "reconcile",
                Box::new(|store, id, engine| {
                    assert_eq!(
                        store.reconcile_runs(engine, &[]).unwrap(),
                        RunReconciliation {
                            failed: vec![id],
                            to_cancel: Vec::new(),
                        }
                    );
                }),
            ),
            (
                "stop",
                Box::new(|store, _, engine| {
                    store.set_engine_instance_stopped(engine, true).unwrap();
                    store.set_engine_instance_stopped(engine, false).unwrap();
                }),
            ),
        ];
        for (path, end) in ends {
            let f = setup();
            let store = f.store();
            let engine = instance(f.node, ENGINE);
            store
                .insert_training_definition(new_definition("source", engine.clone()))
                .unwrap();
            let trained = train(store, "source", &engine);
            let clone = store
                .start_clone_run(
                    "source",
                    trained,
                    new_definition("target", instance(f.node, OTHER_ENGINE)),
                )
                .unwrap();

            end(store, clone.id, &engine);
            assert_eq!(store.training_definition("target").unwrap(), None, "{path}");
            assert_eq!(store.model_run(clone.id).unwrap(), None, "{path}");
            assert_eq!(store.active_run("source").unwrap(), None, "{path}");
            assert_eq!(
                refusal(store, |s| s.report_run(
                    clone.id,
                    &engine,
                    ReportedRunState::Started,
                    None
                )),
                TrainingError::RunNotFound { run_id: clone.id },
                "{path}"
            );
            assert_eq!(
                store.reconcile_runs(&engine, &[clone.id]).unwrap(),
                RunReconciliation {
                    failed: Vec::new(),
                    to_cancel: vec![clone.id],
                },
                "{path}"
            );

            let mut other = new_definition("target", instance(f.other_node, ENGINE));
            other.customer_id = OTHER_CUSTOMER;
            store.insert_training_definition(other).unwrap();
            let freed = definition(store, "target");
            assert_eq!(freed.last_run, None, "{path}");
            assert_eq!(
                state(store, "target"),
                TrainingDefinitionState::NeverTrained,
                "{path}"
            );
        }
    }

    #[test]
    fn definition_states_follow_their_precedence() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        let other = instance(f.node, OTHER_ENGINE);
        store
            .insert_training_definition(new_definition("d", engine.clone()))
            .unwrap();
        assert_eq!(state(store, "d"), TrainingDefinitionState::NeverTrained);

        // A cancelled first training is never trained; a failed one failed.
        let id = store.start_training_run("d").unwrap().run.id;
        assert_eq!(state(store, "d"), TrainingDefinitionState::Training);
        store
            .report_run(id, &engine, ReportedRunState::Cancelled, None)
            .unwrap();
        assert_eq!(state(store, "d"), TrainingDefinitionState::NeverTrained);
        let id = store.start_training_run("d").unwrap().run.id;
        store
            .report_run(id, &engine, ReportedRunState::Started, None)
            .unwrap();
        assert_eq!(state(store, "d"), TrainingDefinitionState::Training);
        store
            .report_run(id, &engine, ReportedRunState::Failed, None)
            .unwrap();
        assert_eq!(state(store, "d"), TrainingDefinitionState::TrainingFailed);

        // Ready once trained; a retrain is training, and a failed or
        // cancelled one leaves it ready.
        train(store, "d", &engine);
        assert_eq!(state(store, "d"), TrainingDefinitionState::Ready);
        let id = store.start_training_run("d").unwrap().run.id;
        assert_eq!(state(store, "d"), TrainingDefinitionState::Training);
        store.fail_run(id, "unreachable").unwrap();
        assert_eq!(state(store, "d"), TrainingDefinitionState::Ready);
        let id = store.start_training_run("d").unwrap().run.id;
        store
            .report_run(id, &engine, ReportedRunState::Cancelled, None)
            .unwrap();
        assert_eq!(state(store, "d"), TrainingDefinitionState::Ready);

        // Cloning, while the clone runs, even with the run active.
        let clone = store
            .start_clone_run(
                "d",
                model(store, "d").trained_run_id,
                new_definition("c", other.clone()),
            )
            .unwrap();
        assert_eq!(state(store, "c"), TrainingDefinitionState::Cloning);
        assert_eq!(state(store, "d"), TrainingDefinitionState::Ready);
        store.complete_run(clone.id, &engine, body("c")).unwrap();
        assert_eq!(state(store, "c"), TrainingDefinitionState::Ready);

        // No instance wins over every other state.
        let stored = definition(store, "c");
        put_definition(
            store,
            &TrainingDefinition {
                instance: None,
                cloning: true,
                ..stored
            },
        );
        assert_eq!(state(store, "c"), TrainingDefinitionState::NoInstance);
    }

    #[test]
    fn reconcile_fails_unreported_runs_and_returns_runs_to_cancel() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        let other = instance(f.node, OTHER_ENGINE);
        store
            .insert_training_definition(new_definition("d", engine.clone()))
            .unwrap();
        store
            .insert_training_definition(new_definition("o", other.clone()))
            .unwrap();
        let finished = store.start_training_run("d").unwrap().run.id;
        store.fail_run(finished, "unreachable").unwrap();
        let reported = store.start_training_run("d").unwrap().run.id;
        let others = store.start_training_run("o").unwrap().run.id;
        // A second active run held for the instance, which only a store
        // written before the one-run rule could hold.
        let stale = ModelRun {
            id: 50,
            model: "stale".to_string(),
            ..run(store, reported)
        };
        put_run(store, &stale);

        let outcome = store
            .reconcile_runs(&engine, &[99, others, reported, finished, reported, 99])
            .unwrap();
        assert_eq!(
            outcome,
            RunReconciliation {
                failed: vec![50],
                to_cancel: vec![finished, others, 99],
            }
        );
        let failed = run(store, 50);
        assert_eq!(failed.state, RunState::Failed);
        assert_eq!(failed.reason.as_deref(), Some(NOT_RUNNING_AFTER_RECONNECT));
        assert_eq!(run(store, reported).state, RunState::Requested);
        assert_eq!(run(store, others).state, RunState::Requested);
        assert_eq!(run(store, finished).state, RunState::Failed);

        assert_eq!(
            store.reconcile_runs(&engine, &[]).unwrap(),
            RunReconciliation {
                failed: vec![reported],
                to_cancel: Vec::new(),
            }
        );
        assert_eq!(run(store, reported).state, RunState::Failed);
        assert_eq!(run(store, others).state, RunState::Requested);
    }

    #[test]
    fn active_run_and_model_runs_cover_clones() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        let other = instance(f.node, OTHER_ENGINE);
        store
            .insert_training_definition(new_definition("source", engine.clone()))
            .unwrap();
        assert_eq!(store.active_run("source").unwrap(), None);

        let training = store.start_training_run("source").unwrap().run;
        assert_eq!(store.active_run("source").unwrap(), Some(training.clone()));
        store
            .complete_run(training.id, &engine, body("source"))
            .unwrap();
        assert_eq!(store.active_run("source").unwrap(), None);

        let clone = store
            .start_clone_run(
                "source",
                training.id,
                new_definition("target", other.clone()),
            )
            .unwrap();
        assert_eq!(store.active_run("target").unwrap(), Some(clone.clone()));
        assert_eq!(store.active_run("source").unwrap(), Some(clone.clone()));
        store
            .complete_run(clone.id, &engine, body("target"))
            .unwrap();
        let retrain = store.start_training_run("target").unwrap().run;
        assert_eq!(store.active_run("target").unwrap(), Some(retrain.clone()));
        assert_eq!(store.active_run("source").unwrap(), None);
        store.fail_run(retrain.id, "unreachable").unwrap();

        let ids = |model: &str| -> Vec<RunId> {
            store
                .model_runs(model)
                .unwrap()
                .into_iter()
                .map(|r| r.id)
                .collect()
        };
        assert_eq!(ids("source"), [training.id, clone.id]);
        assert_eq!(ids("target"), [clone.id, retrain.id]);
        assert_eq!(ids("none"), Vec::<RunId>::new());
    }

    /// Reading the source's trained run id and definition, then retraining
    /// it before the clone is requested, makes the clone refused.
    #[test]
    fn a_clone_prepared_before_a_retrain_is_refused() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        store
            .insert_training_definition(new_definition("source", engine.clone()))
            .unwrap();
        train(store, "source", &engine);
        let read = model(store, "source");
        let mut target = new_definition("target", instance(f.node, OTHER_ENGINE));
        target.definition.clone_from(&read.trained_definition);

        let retrain = train(store, "source", &engine);
        assert_eq!(
            refusal(store, |s| s.start_clone_run(
                "source",
                read.trained_run_id,
                target.clone()
            )),
            TrainingError::SourceRetrained {
                source: "source".to_string(),
                expected: read.trained_run_id,
                current: retrain,
            }
        );
        assert_eq!(store.training_definition("target").unwrap(), None);
        store.start_clone_run("source", retrain, target).unwrap();
    }

    #[test]
    fn a_clone_racing_a_definition_insert_is_refused() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        let other = instance(f.node, OTHER_ENGINE);
        store
            .insert_training_definition(new_definition("source", engine.clone()))
            .unwrap();
        let trained = train(store, "source", &engine);
        let last = counter(store);

        let target = new_definition("target", other.clone());
        let inserted = target.clone();
        store.set_training_hook(Some(once(move |store| {
            store.insert_training_definition(inserted.clone()).unwrap();
        })));
        let error = store
            .start_clone_run("source", trained, target)
            .unwrap_err();
        store.set_training_hook(None);
        assert_eq!(
            error.downcast_ref::<TrainingError>(),
            Some(&TrainingError::NameTaken {
                name: "target".to_string()
            })
        );
        let kept = definition(store, "target");
        assert!(!kept.cloning);
        assert_eq!(kept.last_run, None);
        assert_eq!(counter(store), last);
        assert_eq!(store.model_runs("target").unwrap(), Vec::new());
    }

    #[test]
    fn a_definition_insert_racing_a_clone_is_refused() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        let other = instance(f.node, OTHER_ENGINE);
        store
            .insert_training_definition(new_definition("source", engine.clone()))
            .unwrap();
        let trained = train(store, "source", &engine);

        let target = new_definition("target", other.clone());
        let cloned = target.clone();
        store.set_training_hook(Some(once(move |store| {
            store
                .start_clone_run("source", trained, cloned.clone())
                .unwrap();
        })));
        let error = store.insert_training_definition(target).unwrap_err();
        store.set_training_hook(None);
        assert_eq!(
            error.downcast_ref::<TrainingError>(),
            Some(&TrainingError::NameTaken {
                name: "target".to_string()
            })
        );
        let reserved = definition(store, "target");
        assert!(reserved.cloning);
        let clone = run(store, reserved.last_run.unwrap());
        assert_eq!(clone.model, "target");
        assert_eq!(clone.state, RunState::Requested);
    }

    #[test]
    fn a_start_racing_a_stop_is_refused() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        store
            .insert_training_definition(new_definition("d", engine.clone()))
            .unwrap();

        let stopped = engine.clone();
        store.set_training_hook(Some(once(move |store| {
            store.set_engine_instance_stopped(&stopped, true).unwrap();
        })));
        let error = store.start_training_run("d").unwrap_err();
        store.set_training_hook(None);
        assert_eq!(
            error.downcast_ref::<TrainingError>(),
            Some(&TrainingError::InstanceStopped {
                node_id: f.node,
                agent_key: ENGINE.to_string(),
            })
        );
        assert_eq!(definition(store, "d").last_run, None);
        assert_eq!(counter(store), None);
        assert!(store.engine_instance_state(&engine).unwrap().stopped);
    }

    #[test]
    fn a_start_racing_another_start_on_the_instance_is_refused() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        store
            .insert_training_definition(new_definition("d", engine.clone()))
            .unwrap();
        store
            .insert_training_definition(new_definition("e", engine.clone()))
            .unwrap();

        store.set_training_hook(Some(once(|store| {
            store.start_training_run("e").unwrap();
        })));
        let error = store.start_training_run("d").unwrap_err();
        store.set_training_hook(None);
        let other = definition(store, "e").last_run.unwrap();
        assert_eq!(
            error.downcast_ref::<TrainingError>(),
            Some(&TrainingError::RunInProgress { run_id: other })
        );
        assert_eq!(definition(store, "d").last_run, None);
        assert_eq!(run(store, other).state, RunState::Requested);
        assert_eq!(counter(store), Some(other));
    }

    #[test]
    fn a_stop_racing_a_start_fails_the_new_run() {
        let f = setup();
        let store = f.store();
        let engine = instance(f.node, ENGINE);
        store
            .insert_training_definition(new_definition("d", engine.clone()))
            .unwrap();

        store.set_training_hook(Some(once(|store| {
            store.start_training_run("d").unwrap();
        })));
        store.set_engine_instance_stopped(&engine, true).unwrap();
        store.set_training_hook(None);
        let id = definition(store, "d").last_run.unwrap();
        let failed = run(store, id);
        assert_eq!(failed.state, RunState::Failed);
        assert_eq!(failed.reason.as_deref(), Some(INSTANCE_STOPPED));
        assert!(store.engine_instance_state(&engine).unwrap().stopped);
    }

    #[test]
    fn a_hook_error_ends_the_writer() {
        let f = setup();
        let store = f.store();
        store.set_training_hook(Some(Arc::new(|_| Err(anyhow!("hook failed")))));
        let before = dump(store);
        let error = store
            .insert_training_definition(new_definition("d", instance(f.node, ENGINE)))
            .unwrap_err();
        store.set_training_hook(None);
        assert_eq!(error.to_string(), "hook failed");
        assert_eq!(dump(store), before);
    }
}
