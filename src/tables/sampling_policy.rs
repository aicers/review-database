//! The `SamplingPolicy` table.
//!
//! A sampling policy is a `Draft` until it is fixed, and `Fixed` from then
//! on. A draft's definition and name can change, and it cannot be assigned;
//! a fixed policy's definition is frozen, only its name can change, and it
//! is assigned to a Time Series Generator agent through
//! [`IndexedTable::assign`]. A policy is in use while a timeseries training
//! definition, a detector of a timeseries model or a timeseries model names
//! its ID as a source, and is deleted only by
//! [`IndexedTable::remove_unused`], which refuses while it is in use, or by
//! [`IndexedTable::remove_customer_policies`], for the deletion of its
//! customer.
//!
//! Every writer is one optimistic transaction, retried from the start on a
//! commit conflict; a refusal returns without committing and changes
//! nothing. The uses a writer checks are found by scanning the training
//! definitions, the `engine instances` rows and the models inside its
//! transaction, reading each one examined for update, so a concurrent change
//! of an existing one conflicts. A scan is not tracked: a use created by a
//! concurrent transaction after the scan does not conflict, as with the
//! guards of `model_guard`.

use std::{borrow::Cow, collections::BTreeMap, fmt, net::IpAddr};

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use rocksdb::{IteratorMode, OptimisticTransactionDB, Transaction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    EngineInstanceRow, EngineInstances, Model, ModelInstance, ModelMethod, TrainingDefinition,
    TrainingDefinitions, UniqueKey, engine_instance_key,
};
use crate::{
    Agent, AgentKind, EXCLUSIVE, Indexable, IndexedMap, IndexedMapUpdate, IndexedTable, Iterable,
    Map, NodeTable, collections::Indexed, model::ClusteringMethod, types::FromKeyValue,
};

/// The key of the Data Store name in a Time Series Generator's configuration.
const GIGANTO_NAME: &str = "giganto_name";

type Txn<'a> = Transaction<'a, OptimisticTransactionDB>;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SamplingPolicy {
    pub id: u32,
    pub name: String,
    pub kind: Kind,
    pub interval: Interval,
    pub period: Period,
    pub offset: i32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub node: Option<String>,
    pub column: Option<u32>,
    /// The customer the policy belongs to. Every policy inserted has one;
    /// it is `None` only for a policy stored before customers were recorded
    /// whose customer could not be derived.
    pub customer_id: Option<u32>,
    pub state: PolicyState,
    /// The Time Series Generator agent the policy is assigned to.
    pub assignee: Option<ModelInstance>,
    /// The `giganto_name` of the generator the policy was last assigned to,
    /// `None` if that generator had none. Unassigning the policy and
    /// removing the generator leave it as it is.
    pub data_store: Option<String>,
    pub creation_time: DateTime<Utc>,
}

impl FromKeyValue for SamplingPolicy {
    fn from_key_value(_key: &[u8], value: &[u8]) -> anyhow::Result<Self> {
        super::deserialize(value)
    }
}

impl UniqueKey for SamplingPolicy {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl Indexable for SamplingPolicy {
    fn key(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.name.as_bytes())
    }

    fn index(&self) -> u32 {
        self.id
    }

    fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
        key
    }

    fn value(&self) -> Vec<u8> {
        super::serialize(&self).expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[repr(u32)]
pub enum Interval {
    FiveMinutes = 0,
    TenMinutes = 1,
    FifteenMinutes = 2,
    ThirtyMinutes = 3,
    OneHour = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[repr(u32)]
pub enum Period {
    SixHours = 0,
    TwelveHours = 1,
    OneDay = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[repr(u32)]
pub enum Kind {
    Conn = 0,
    Dns = 1,
    Http = 2,
    Rdp = 3,
}

/// The state of a sampling policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum PolicyState {
    /// The definition and the name can change, and the policy cannot be
    /// assigned.
    Draft,
    /// The definition is frozen and only the name can change. A policy never
    /// leaves this state.
    Fixed,
}

/// A sampling policy to insert: its name, its sampling definition and its
/// customer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewSamplingPolicy {
    pub name: String,
    pub kind: Kind,
    pub interval: Interval,
    pub period: Period,
    pub offset: i32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub node: Option<String>,
    pub column: Option<u32>,
    pub customer_id: u32,
}

/// What uses a sampling policy, by naming its decimal ID as a source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyUse {
    /// A timeseries training definition.
    Definition { name: String },
    /// A detector of an engine instance's applied or pending document, whose
    /// model is a timeseries model.
    Detector {
        instance: ModelInstance,
        detector_id: i32,
        /// Whether the applied document's detector names the policy.
        applied: bool,
        /// Whether the pending document's detector names the policy.
        pending: bool,
    },
    /// A timeseries model whose current classifier was trained on the
    /// policy.
    Model { name: String },
}

impl fmt::Display for PolicyUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Definition { name } => write!(f, "training definition {name:?}"),
            Self::Detector {
                instance,
                detector_id,
                applied,
                pending,
            } => {
                let documents = match (applied, pending) {
                    (true, true) => "applied and pending",
                    (true, false) => "applied",
                    _ => "pending",
                };
                write!(
                    f,
                    "detector {detector_id} of the {documents} document of agent {:?} of node {}",
                    instance.agent_key, instance.node_id
                )
            }
            Self::Model { name } => write!(f, "model {name:?}"),
        }
    }
}

/// Lists `uses` for an error message.
fn list_uses(uses: &[PolicyUse]) -> String {
    uses.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// A refusal of a sampling-policy write.
///
/// It is returned inside the `anyhow::Error` of the refusing method, so a
/// caller can `downcast_ref` it.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SamplingPolicyError {
    /// No sampling policy has the ID.
    #[error("no sampling policy has ID {id}")]
    NotFound { id: u32 },
    /// An update changes the definition of a fixed policy.
    #[error("sampling policy {id} is fixed; only its name can change")]
    DefinitionFixed { id: u32 },
    /// An assignment names a draft without fixing it.
    #[error("sampling policy {id} is a draft; fix the policy before assigning it")]
    Draft { id: u32 },
    /// An unassignment asks to fix the policy.
    #[error("sampling policy {id} can be fixed only by assigning it")]
    FixWithoutAssignee { id: u32 },
    /// The assignee is not a Time Series Generator agent.
    #[error("agent {agent_key:?} of node {node_id} is not a Time Series Generator agent")]
    NotTimeSeriesGenerator { node_id: u32, agent_key: String },
    /// The policy has no customer.
    #[error("sampling policy {id} has no customer")]
    NoCustomer { id: u32 },
    /// The assignee's node has no applied profile, or one of another
    /// customer.
    #[error("node {node_id} does not belong to customer {customer_id}")]
    CustomerMismatch {
        node_id: u32,
        /// The customer of the node's applied profile; `None` if it has none.
        node_customer_id: Option<u32>,
        customer_id: u32,
    },
    /// The policy's `node` is not a sensor name of its customer.
    #[error("sampling policy {id} reads {node:?}, which is not a sensor of customer {customer_id}")]
    NotSensorOfCustomer {
        id: u32,
        node: Option<String>,
        customer_id: u32,
    },
    /// The policy is in use, which refuses its unassignment and its delete.
    #[error("the sampling policy is in use by {}", list_uses(.0))]
    PolicyInUse(Vec<PolicyUse>),
    /// The policy is in use, and the new assignee's Data Store is not the
    /// one the policy's series are kept in.
    #[error(
        "sampling policy {id} is in use by {}; the generator's Data Store {giganto_name:?} is \
         not the policy's {data_store:?}",
        list_uses(uses)
    )]
    DataStoreMismatch {
        id: u32,
        data_store: Option<String>,
        /// The new assignee's `giganto_name`; `None` if it has none or an
        /// empty one.
        giganto_name: Option<String>,
        uses: Vec<PolicyUse>,
    },
}

/// Functions for the `sampling_policy` indexed map.
///
/// A sampling-policy ID is never reused: the Data Store keeps a policy's time
/// series, and the Time Series Generator its checkpoint, under that ID after
/// the policy is deleted. A policy is deleted with
/// [`remove_unused`](IndexedTable::remove_unused), or with
/// [`remove_customer_policies`](IndexedTable::remove_customer_policies), both
/// of which retire its ID, and the recycling `remove` writers are not
/// available for this table.
impl<'d> IndexedTable<'d, SamplingPolicy> {
    /// Opens the `sampling policy` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::SAMPLING_POLICY)
            .map(IndexedTable::new)
            .ok()
    }

    /// Inserts a new policy, a [`PolicyState::Draft`] with no assignee and no
    /// Data Store, and returns its ID.
    ///
    /// # Errors
    ///
    /// Returns an error if a policy has the name, the name is empty, or the
    /// database operation fails.
    pub fn insert(&self, policy: NewSamplingPolicy) -> Result<u32> {
        self.indexed_map.insert(SamplingPolicy {
            id: 0,
            name: policy.name,
            kind: policy.kind,
            interval: policy.interval,
            period: policy.period,
            offset: policy.offset,
            src_ip: policy.src_ip,
            dst_ip: policy.dst_ip,
            node: policy.node,
            column: policy.column,
            customer_id: Some(policy.customer_id),
            state: PolicyState::Draft,
            assignee: None,
            data_store: None,
            creation_time: Utc::now(),
        })
    }

    /// Updates the `SamplingPolicy` from `old` to `new`, given `id`.
    ///
    /// Only the name and the definition change. The definition of a
    /// [`PolicyState::Fixed`] policy cannot change.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid, the stored policy is not
    /// `old`, or the database operation fails. Returns
    /// [`SamplingPolicyError::DefinitionFixed`] inside the error, and changes
    /// nothing, if the policy is fixed and `new` has another definition.
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        self.indexed_map.update(id, old, new)
    }

    /// Moves a [`PolicyState::Draft`] policy to [`PolicyState::Fixed`].
    ///
    /// Fixing a fixed policy changes nothing and succeeds. Nothing moves a
    /// policy back to a draft.
    ///
    /// # Errors
    ///
    /// Returns [`SamplingPolicyError::NotFound`] inside the error if no
    /// policy has the ID. Returns an error, and changes nothing, if the
    /// database operation fails.
    pub fn fix(&self, id: u32) -> Result<()> {
        self.write(|txn| {
            let mut policy = self.policy_for_update(txn, id)?;
            if policy.state == PolicyState::Fixed {
                return Ok(());
            }
            policy.state = PolicyState::Fixed;
            self.put_row(txn, &policy)
        })
    }

    /// Assigns the policy to the Time Series Generator agent `assignee`, or
    /// unassigns it if `assignee` is `None`, in one transaction.
    ///
    /// With `fix`, a draft is fixed and assigned in the same transaction; a
    /// refused assignment leaves it a draft. An assignment sets
    /// `data_store` to the generator's applied `giganto_name`, or to `None`
    /// if it has none or an empty one; an unassignment leaves it as it is.
    ///
    /// # Errors
    ///
    /// Returns a [`SamplingPolicyError`] inside the error, and changes
    /// nothing, checked in this order: `NotFound`. For an unassignment:
    /// `FixWithoutAssignee` if `fix` is set; `PolicyInUse` while the policy
    /// is in use. For an assignment: `Draft` if the policy is a draft and
    /// `fix` is not set; `NotTimeSeriesGenerator` if `assignee` is not an
    /// [`AgentKind::TimeSeriesGenerator`] agent; `NoCustomer` if the policy
    /// has no customer; `CustomerMismatch` if the assignee's node has no
    /// applied profile or one of another customer; `NotSensorOfCustomer` if
    /// the policy's `node` is not a sensor name of its customer;
    /// `DataStoreMismatch` while the policy is in use, unless the
    /// generator's `giganto_name` is non-empty and equals `data_store`.
    /// Returns an error, and changes nothing, if the database operation
    /// fails.
    pub fn assign(&self, id: u32, assignee: Option<&ModelInstance>, fix: bool) -> Result<()> {
        let db = self.indexed_map.db();
        let nodes = NodeTable::open(db).context("node table must be present")?;
        let agents = Map::open(db, super::AGENTS).context("agent table must be present")?;
        self.write(|txn| {
            let mut policy = self.policy_for_update(txn, id)?;
            let Some(assignee) = assignee else {
                if fix {
                    return Err(SamplingPolicyError::FixWithoutAssignee { id }.into());
                }
                let uses = uses_in_transaction(db, txn, id)?;
                if !uses.is_empty() {
                    return Err(SamplingPolicyError::PolicyInUse(uses).into());
                }
                policy.assignee = None;
                return self.put_row(txn, &policy);
            };

            if policy.state == PolicyState::Draft && !fix {
                return Err(SamplingPolicyError::Draft { id }.into());
            }
            let agent_key = engine_instance_key(assignee.node_id, &assignee.agent_key);
            let stored = txn
                .get_for_update_cf(agents.cf, &agent_key, EXCLUSIVE)
                .context("cannot read agent")?;
            let generator = stored
                .as_deref()
                .map(|value| Agent::from_key_value(&agent_key, value))
                .transpose()?
                .filter(|agent| agent.kind == AgentKind::TimeSeriesGenerator);
            let (Some(agent), Some(stored)) = (generator, stored) else {
                return Err(SamplingPolicyError::NotTimeSeriesGenerator {
                    node_id: assignee.node_id,
                    agent_key: assignee.agent_key.clone(),
                }
                .into());
            };
            // Writing the agent row back unchanged makes a removal of the
            // agent, which deletes the row and clears its assignments,
            // conflict with this assignment whichever commits second.
            agents.put_with_transaction(&agent_key, &stored, txn)?;
            let Some(customer_id) = policy.customer_id else {
                return Err(SamplingPolicyError::NoCustomer { id }.into());
            };
            let node_customer_id = nodes
                .applied_profile_in_transaction(assignee.node_id, txn)?
                .map(|profile| profile.customer_id);
            if node_customer_id != Some(customer_id) {
                return Err(SamplingPolicyError::CustomerMismatch {
                    node_id: assignee.node_id,
                    node_customer_id,
                    customer_id,
                }
                .into());
            }
            let is_sensor = match &policy.node {
                Some(node) => nodes.is_sensor_name_in_transaction(txn, customer_id, node)?,
                None => false,
            };
            if !is_sensor {
                return Err(SamplingPolicyError::NotSensorOfCustomer {
                    id,
                    node: policy.node.clone(),
                    customer_id,
                }
                .into());
            }
            let giganto_name = giganto_name(&agent);
            let uses = uses_in_transaction(db, txn, id)?;
            if !uses.is_empty() && (giganto_name.is_none() || giganto_name != policy.data_store) {
                return Err(SamplingPolicyError::DataStoreMismatch {
                    id,
                    data_store: policy.data_store.clone(),
                    giganto_name,
                    uses,
                }
                .into());
            }

            policy.state = PolicyState::Fixed;
            policy.assignee = Some(assignee.clone());
            policy.data_store = giganto_name;
            self.put_row(txn, &policy)
        })
    }

    /// Deletes the policy unless it is in use, reading its uses and
    /// deleting it in one transaction, and returns its key. Its ID is
    /// retired, so no later insert is given it.
    ///
    /// # Errors
    ///
    /// Returns a [`SamplingPolicyError`] inside the error, and changes
    /// nothing: `NotFound` if no policy has the ID; `PolicyInUse`, listing
    /// every use, while the policy is in use. Returns an error, and changes
    /// nothing, if the database operation fails.
    pub fn remove_unused(&self, id: u32) -> Result<Vec<u8>> {
        let db = self.indexed_map.db();
        self.write(|txn| {
            self.policy_for_update(txn, id)?;
            let uses = uses_in_transaction(db, txn, id)?;
            if !uses.is_empty() {
                return Err(SamplingPolicyError::PolicyInUse(uses).into());
            }
            self.indexed_map.deactivate_with_transaction(id, txn)
        })
    }

    /// Deletes every policy of the customer `customer_id`, in use or not, in
    /// one transaction, and returns their IDs in ascending order. Their IDs
    /// are retired, so no later insert is given one.
    ///
    /// This is for the deletion of the customer only. Any other delete goes
    /// through [`remove_unused`](Self::remove_unused), which refuses a policy
    /// in use.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if the database operation
    /// fails.
    pub fn remove_customer_policies(&self, customer_id: u32) -> Result<Vec<u32>> {
        self.write(|txn| {
            let mut ids: Vec<u32> = self
                .scan(txn)?
                .into_iter()
                .filter(|policy| policy.customer_id == Some(customer_id))
                .map(|policy| policy.id)
                .collect();
            ids.sort_unstable();
            for &id in &ids {
                self.indexed_map.deactivate_with_transaction(id, txn)?;
            }
            Ok(ids)
        })
    }

    /// Clears, within `txn`, every assignment to `instance`, leaving each
    /// policy's `data_store` as it is.
    ///
    /// The policies it clears are read for update, so a concurrent change
    /// of one conflicts with `txn`; the scan that finds them is not tracked.
    pub(crate) fn unassign_in_transaction(
        &self,
        txn: &Txn<'_>,
        instance: &ModelInstance,
    ) -> Result<()> {
        for scanned in self.scan(txn)? {
            if scanned.assignee.as_ref() != Some(instance) {
                continue;
            }
            let Some(mut policy) = self.get_by_id_in_transaction(scanned.id, txn)? else {
                continue;
            };
            if policy.assignee.as_ref() != Some(instance) {
                continue;
            }
            policy.assignee = None;
            self.put_row(txn, &policy)?;
        }
        Ok(())
    }

    /// Returns the policies assigned to `instance`, in name order.
    pub(crate) fn assigned_to(&self, instance: &ModelInstance) -> Result<Vec<SamplingPolicy>> {
        let mut policies = Vec::new();
        for policy in self.iter(rocksdb::Direction::Forward, None) {
            let policy = policy?;
            if policy.assignee.as_ref() == Some(instance) {
                policies.push(policy);
            }
        }
        Ok(policies)
    }

    /// Returns the uses of the policy `id`, as
    /// [`Store::sampling_policy_uses`](crate::Store::sampling_policy_uses)
    /// describes them.
    pub(crate) fn uses(&self, id: u32) -> Result<Vec<PolicyUse>> {
        let db = self.indexed_map.db();
        let definitions = TrainingDefinitions::open(db)
            .context("training definition table must be present")?
            .all()?;
        let rows = EngineInstances::open(db)
            .context("engine instance table must be present")?
            .all()?;
        let models = IndexedTable::<Model>::open(db)
            .context("model table must be present")?
            .iter(rocksdb::Direction::Forward, None)
            .collect::<Result<Vec<_>>>()?;
        Ok(collect_uses(id, &definitions, &rows, &models))
    }

    /// Returns the policy `id`, read for update within `txn`, refusing an ID
    /// no policy has.
    fn policy_for_update(&self, txn: &Txn<'_>, id: u32) -> Result<SamplingPolicy> {
        self.get_by_id_in_transaction(id, txn)?
            .ok_or_else(|| SamplingPolicyError::NotFound { id }.into())
    }

    /// Writes `policy` over its stored row within `txn`. Its name, and so
    /// its key and the index, must be the stored one.
    fn put_row(&self, txn: &Txn<'_>, policy: &SamplingPolicy) -> Result<()> {
        txn.put_cf(
            self.indexed_map.cf(),
            policy.indexed_key(),
            Indexable::value(policy),
        )
        .context("failed to write sampling policy")
    }

    /// Returns every policy as `txn` sees it, ordered by name.
    ///
    /// The scan is not tracked by `txn`: a policy written after it does not
    /// conflict with the transaction.
    fn scan(&self, txn: &Txn<'_>) -> Result<Vec<SamplingPolicy>> {
        txn.iterator_cf(self.indexed_map.cf(), IteratorMode::Start)
            .filter_map(|entry| match entry {
                Ok((key, _)) if key.is_empty() => None,
                Ok((_, value)) => Some(super::deserialize(&value)),
                Err(e) => Some(Err(anyhow!("cannot read sampling policies: {e}"))),
            })
            .collect()
    }

    /// Runs `attempt` in an optimistic transaction and commits it, retrying
    /// from the start on a commit conflict. A refusal `attempt` returns ends
    /// the write without committing.
    fn write<T>(&self, mut attempt: impl FnMut(&Txn<'_>) -> Result<T>) -> Result<T> {
        let db = self.indexed_map.db();
        loop {
            let txn = db.transaction();
            let value = attempt(&txn)?;
            match txn.commit() {
                Ok(()) => return Ok(value),
                Err(e) if e.as_ref().starts_with("Resource busy:") => {}
                Err(e) => return Err(e).context("failed to commit sampling policy changes"),
            }
        }
    }
}

/// Returns the applied `giganto_name` of a Time Series Generator agent;
/// `None` if its configuration has none or an empty one.
fn giganto_name(agent: &Agent) -> Option<String> {
    let config = agent.config.as_ref()?;
    let table = config.as_ref().parse::<toml::Table>().ok()?;
    table
        .get(GIGANTO_NAME)?
        .as_str()
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

/// Returns the uses of the policy `id` as `txn` sees them, reading every
/// training definition, `engine instances` row and model it examines for
/// update, so a concurrent change of one conflicts with `txn`. The scans
/// that find them are not tracked.
fn uses_in_transaction(
    db: &OptimisticTransactionDB,
    txn: &Txn<'_>,
    id: u32,
) -> Result<Vec<PolicyUse>> {
    let training_definitions =
        TrainingDefinitions::open(db).context("training definition table must be present")?;
    let mut definitions = Vec::new();
    for scanned in training_definitions.scan(txn)? {
        if let Some(definition) = training_definitions.get_for_update(txn, &scanned.name)? {
            definitions.push(definition);
        }
    }
    let engine_instances =
        EngineInstances::open(db).context("engine instance table must be present")?;
    let mut rows = Vec::new();
    for (instance, _) in engine_instances.scan(txn)? {
        let key = engine_instance_key(instance.node_id, &instance.agent_key);
        if let Some(row) = engine_instances.get_for_update(txn, &key)? {
            rows.push((instance, row));
        }
    }
    let model_table = IndexedTable::<Model>::open(db).context("model table must be present")?;
    let mut models = Vec::new();
    for scanned in model_table.scan(txn)? {
        if let Some(model) = model_table.load_model_by_name_in_transaction(&scanned.name, txn)? {
            models.push(model);
        }
    }
    Ok(collect_uses(id, &definitions, &rows, &models))
}

/// Returns the uses of the policy `id` among `definitions`, `rows` and
/// `models`: the timeseries definitions, in the order given, then the
/// detectors of timeseries models, in the order of `rows`, then detector id,
/// then the timeseries models, in the order given, that name the policy's
/// decimal ID as a source.
///
/// A detector's model is timeseries if the model record of its name has the
/// timeseries method or, while no model of that name exists, the training
/// definition of its name has.
fn collect_uses(
    id: u32,
    definitions: &[TrainingDefinition],
    rows: &[(ModelInstance, EngineInstanceRow)],
    models: &[Model],
) -> Vec<PolicyUse> {
    let source = id.to_string();
    let timeseries_kind = ClusteringMethod::Timeseries.to_string();
    let model_is_timeseries = |name: &str| match models.iter().find(|model| model.name == name) {
        Some(model) => model.kind == timeseries_kind,
        None => definitions.iter().any(|definition| {
            definition.name == name && definition.method == ModelMethod::Timeseries
        }),
    };

    let mut uses: Vec<PolicyUse> = definitions
        .iter()
        .filter(|definition| {
            definition.method == ModelMethod::Timeseries && definition.sources.contains(&source)
        })
        .map(|definition| PolicyUse::Definition {
            name: definition.name.clone(),
        })
        .collect();

    for (instance, row) in rows {
        let mut detectors: BTreeMap<i32, (bool, bool)> = BTreeMap::new();
        let names_policy = |detector: &&super::EngineDetectorRef| {
            detector.sources.contains(&source) && model_is_timeseries(&detector.model)
        };
        for detector in row.applied.detectors.iter().filter(names_policy) {
            detectors.entry(detector.id).or_default().0 = true;
        }
        for detector in row.pending.detectors.iter().filter(names_policy) {
            detectors.entry(detector.id).or_default().1 = true;
        }
        uses.extend(
            detectors
                .into_iter()
                .map(|(detector_id, (applied, pending))| PolicyUse::Detector {
                    instance: instance.clone(),
                    detector_id,
                    applied,
                    pending,
                }),
        );
    }

    uses.extend(
        models
            .iter()
            .filter(|model| {
                model.kind == timeseries_kind && model.trained_sources.contains(&source)
            })
            .map(|model| PolicyUse::Model {
                name: model.name.clone(),
            }),
    );
    uses
}

/// The name and the sampling definition of a policy, for
/// [`IndexedTable::update`].
#[derive(Clone)]
pub struct Update {
    pub name: String,
    pub kind: Kind,
    pub interval: Interval,
    pub period: Period,
    pub offset: i32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub node: Option<String>,
    pub column: Option<u32>,
}

impl Update {
    /// Returns whether the definition is that of `value`; the name is not
    /// part of it.
    fn same_definition(&self, value: &SamplingPolicy) -> bool {
        self.kind == value.kind
            && self.interval == value.interval
            && self.period == value.period
            && self.offset == value.offset
            && self.src_ip == value.src_ip
            && self.dst_ip == value.dst_ip
            && self.node == value.node
            && self.column == value.column
    }
}

impl From<SamplingPolicy> for Update {
    fn from(input: SamplingPolicy) -> Self {
        Self {
            name: input.name,
            kind: input.kind,
            interval: input.interval,
            period: input.period,
            offset: input.offset,
            src_ip: input.src_ip,
            dst_ip: input.dst_ip,
            node: input.node,
            column: input.column,
        }
    }
}

impl IndexedMapUpdate for Update {
    type Entry = SamplingPolicy;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        Some(Cow::Borrowed(self.name.as_bytes()))
    }

    /// Applies the name and the definition to the stored `value`, refusing a
    /// change of a fixed policy's definition.
    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        if value.state == PolicyState::Fixed && !self.same_definition(&value) {
            return Err(SamplingPolicyError::DefinitionFixed { id: value.id }.into());
        }
        value.name.clone_from(&self.name);
        value.kind = self.kind;
        value.interval = self.interval;
        value.period = self.period;
        value.offset = self.offset;
        value.src_ip = self.src_ip;
        value.dst_ip = self.dst_ip;
        value.node.clone_from(&self.node);
        value.column = self.column;
        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        self.name == value.name && self.same_definition(value)
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr};

    use anyhow::Result;
    use chrono::DateTime;
    use rocksdb::Direction;

    use super::*;
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{
        AgentStatus, EngineDetectorRef, EngineDocumentRefs, EngineDocumentWrite, ModelOwner,
        NewTrainingDefinition, Node, NodeProfile, SamplingInterval, SamplingKind, SamplingPeriod,
        SamplingPolicyUpdate, Store, TrainedWith,
    };

    const CUSTOMER: u32 = 1;
    const OTHER_CUSTOMER: u32 = 2;
    const SENSOR_HOST: &str = "sensor.example";
    const SENSOR_NAME: &str = "piglet.sensor.example";
    const OTHER_SENSOR_NAME: &str = "piglet.other.example";
    const GENERATOR: &str = "crusher@ds-a";
    const OTHER_STORE_GENERATOR: &str = "crusher@ds-b";
    const EMPTY_STORE_GENERATOR: &str = "crusher@empty";
    const NO_STORE_GENERATOR: &str = "crusher@none";
    const SAME_STORE_GENERATOR: &str = "crusher@ds-a-2";
    const ENGINE: &str = "reconverge";
    const SENSOR: &str = "piglet";

    /// A store with two nodes of [`CUSTOMER`] and one of [`OTHER_CUSTOMER`].
    ///
    /// `node` is the sensor at [`SENSOR_HOST`], with the generator
    /// [`GENERATOR`] (Data Store `ds-a`) and an Unsupervised Engine;
    /// `generators` has the generators [`OTHER_STORE_GENERATOR`] (`ds-b`),
    /// [`EMPTY_STORE_GENERATOR`] (an empty one), [`NO_STORE_GENERATOR`] (none)
    /// and [`SAME_STORE_GENERATOR`] (`ds-a`); `other_node` is the sensor
    /// `other.example` with a generator of Data Store `ds-a`.
    struct Fixture {
        _permit: DbGuard<'static>,
        store: Store,
        _db_dir: tempfile::TempDir,
        _backup_dir: tempfile::TempDir,
        node: u32,
        generators: u32,
        other_node: u32,
    }

    impl Fixture {
        fn generator(&self) -> ModelInstance {
            instance(self.node, GENERATOR)
        }

        fn table(&self) -> IndexedTable<'_, SamplingPolicy> {
            self.store.sampling_policy_map()
        }

        fn policy(&self, id: u32) -> SamplingPolicy {
            self.table().get_by_id(id).unwrap().unwrap()
        }

        fn insert(&self, name: &str) -> u32 {
            self.table().insert(new_policy(name)).unwrap()
        }

        /// Inserts a fixed policy assigned to [`GENERATOR`].
        fn assigned(&self, name: &str) -> u32 {
            let id = self.insert(name);
            self.table()
                .assign(id, Some(&self.generator()), true)
                .unwrap();
            id
        }
    }

    fn instance(node_id: u32, agent_key: &str) -> ModelInstance {
        ModelInstance {
            node_id,
            agent_key: agent_key.to_string(),
        }
    }

    fn agent(key: &str, kind: AgentKind, config: Option<&str>) -> Agent {
        let mut agent = Agent::new(
            0,
            key.to_string(),
            kind,
            AgentStatus::Enabled,
            config.map(ToString::to_string),
            None,
        )
        .unwrap();
        agent.instance = Some(1);
        agent
    }

    fn insert_node(
        store: &Store,
        name: &str,
        customer_id: u32,
        hostname: &str,
        agents: Vec<Agent>,
    ) -> u32 {
        store
            .node_map()
            .put(&Node {
                id: 0,
                name: name.to_string(),
                name_draft: None,
                profile: Some(NodeProfile {
                    customer_id,
                    description: String::new(),
                    hostname: hostname.to_string(),
                }),
                profile_draft: None,
                agents,
                external_services: Vec::new(),
                creation_time: Utc::now(),
            })
            .unwrap()
    }

    fn setup() -> Fixture {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
        let node = insert_node(
            &store,
            "node",
            CUSTOMER,
            SENSOR_HOST,
            vec![
                agent(SENSOR, AgentKind::Sensor, None),
                agent(
                    GENERATOR,
                    AgentKind::TimeSeriesGenerator,
                    Some("giganto_name = \"ds-a\""),
                ),
                agent(ENGINE, AgentKind::Unsupervised, None),
            ],
        );
        let generators = insert_node(
            &store,
            "generators",
            CUSTOMER,
            "generators.example",
            vec![
                agent(
                    OTHER_STORE_GENERATOR,
                    AgentKind::TimeSeriesGenerator,
                    Some("giganto_name = \"ds-b\""),
                ),
                agent(
                    EMPTY_STORE_GENERATOR,
                    AgentKind::TimeSeriesGenerator,
                    Some("giganto_name = \"\""),
                ),
                agent(NO_STORE_GENERATOR, AgentKind::TimeSeriesGenerator, None),
                agent(
                    SAME_STORE_GENERATOR,
                    AgentKind::TimeSeriesGenerator,
                    Some("giganto_name = \"ds-a\"\nlog_path = \"/tmp\""),
                ),
            ],
        );
        let other_node = insert_node(
            &store,
            "other-node",
            OTHER_CUSTOMER,
            "other.example",
            vec![
                agent(SENSOR, AgentKind::Sensor, None),
                agent(
                    GENERATOR,
                    AgentKind::TimeSeriesGenerator,
                    Some("giganto_name = \"ds-a\""),
                ),
            ],
        );
        Fixture {
            _permit: permit,
            store,
            _db_dir: db_dir,
            _backup_dir: backup_dir,
            node,
            generators,
            other_node,
        }
    }

    fn new_policy(name: &str) -> NewSamplingPolicy {
        NewSamplingPolicy {
            name: name.to_string(),
            kind: SamplingKind::Conn,
            interval: SamplingInterval::FifteenMinutes,
            period: SamplingPeriod::TwelveHours,
            offset: 0,
            src_ip: None,
            dst_ip: None,
            node: Some(SENSOR_NAME.to_string()),
            column: None,
            customer_id: CUSTOMER,
        }
    }

    fn policy_error(error: &anyhow::Error) -> &SamplingPolicyError {
        error
            .downcast_ref::<SamplingPolicyError>()
            .unwrap_or_else(|| panic!("not a sampling policy error: {error:#}"))
    }

    /// Builds a deterministic `SamplingPolicy` for the literal-byte contract
    /// test.
    fn deterministic_sampling_policy() -> SamplingPolicy {
        let creation_time =
            DateTime::from_timestamp(1_700_000_000, 123_456_789).expect("valid timestamp");
        SamplingPolicy {
            id: 42,
            name: "fixture-policy".to_string(),
            kind: SamplingKind::Http,
            interval: SamplingInterval::ThirtyMinutes,
            period: SamplingPeriod::OneDay,
            offset: -300,
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            node: Some("piglet.sensor-node-1".to_string()),
            column: Some(7),
            customer_id: Some(3),
            state: PolicyState::Fixed,
            assignee: Some(instance(5, "crusher@sensor-node-1")),
            data_store: Some("001.giganto.store-node".to_string()),
            creation_time,
        }
    }

    /// Locks the on-disk bincode byte contract for the persisted
    /// `SamplingPolicy` record.
    ///
    /// Expected bytes come from the committed literal fixture (not from the
    /// production serializer inside this test). `creation_time` is pinned to
    /// `2023-11-14T22:13:20.123456789Z` so the encoding stays deterministic.
    /// Regenerate with `dump_sampling_policy_literal_fixture_bytes` if the
    /// stored layout changes; the layout before it is pinned in `migration`.
    ///
    /// Variants not covered: `Kind::{Conn,Dns,Rdp}`; `Interval` values other
    /// than `ThirtyMinutes`; `Period` values other than `OneDay`;
    /// `PolicyState::Draft`; `None` optional fields; zero `offset`; `IPv6`
    /// addresses; empty `name`.
    #[test]
    fn sampling_policy_literal_bytes_contract() -> Result<()> {
        const FIXTURE_BYTES: &[u8] =
            include_bytes!("../../tests/fixtures/sampling_policy_literal_bytes.bin");

        let decoded = SamplingPolicy::from_key_value(b"fixture-policy", FIXTURE_BYTES)?;
        let expected = deterministic_sampling_policy();
        assert_eq!(decoded, expected);

        let serialized = Indexable::value(&expected);
        assert_eq!(serialized.as_slice(), FIXTURE_BYTES);

        Ok(())
    }

    #[test]
    #[ignore = "run manually to regenerate tests/fixtures/sampling_policy_literal_bytes.bin"]
    fn dump_sampling_policy_literal_fixture_bytes() {
        let bytes = Indexable::value(&deterministic_sampling_policy());
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sampling_policy_literal_bytes.bin");
        std::fs::write(path, bytes).expect("write fixture");
    }

    #[test]
    fn a_new_policy_is_an_unassigned_draft() {
        let f = setup();
        let id = f.insert("a");
        let policy = f.policy(id);
        assert_eq!(policy.state, PolicyState::Draft);
        assert_eq!(policy.assignee, None);
        assert_eq!(policy.data_store, None);
        assert_eq!(policy.customer_id, Some(CUSTOMER));
        assert_eq!(policy.node.as_deref(), Some(SENSOR_NAME));
    }

    #[test]
    fn a_draft_definition_and_name_can_be_updated() {
        let f = setup();
        let id = f.insert("a");
        let old: SamplingPolicyUpdate = f.policy(id).into();
        let new = SamplingPolicyUpdate {
            name: "b".to_string(),
            kind: SamplingKind::Dns,
            interval: SamplingInterval::OneHour,
            period: SamplingPeriod::OneDay,
            offset: 60,
            src_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::BROADCAST)),
            node: Some(OTHER_SENSOR_NAME.to_string()),
            column: Some(2),
        };

        f.table().update(id, &old, &new).unwrap();

        let policy = f.policy(id);
        assert_eq!(policy.name, "b");
        assert!(new.verify(&policy));
        assert_eq!(policy.state, PolicyState::Draft);
        assert_eq!(f.table().count().unwrap(), 1);
    }

    #[test]
    fn fix_is_one_way_and_repeatable() {
        let f = setup();
        let id = f.insert("a");

        f.table().fix(id).unwrap();
        let fixed = f.policy(id);
        assert_eq!(fixed.state, PolicyState::Fixed);

        f.table().fix(id).unwrap();
        assert_eq!(f.policy(id), fixed);

        let error = f.table().fix(id + 1).unwrap_err();
        assert_eq!(
            policy_error(&error),
            &SamplingPolicyError::NotFound { id: id + 1 }
        );
    }

    #[test]
    fn a_fixed_definition_cannot_change_but_its_name_can() {
        let f = setup();
        let id = f.insert("a");
        f.table().fix(id).unwrap();
        let old: SamplingPolicyUpdate = f.policy(id).into();

        let changes: [fn(&mut SamplingPolicyUpdate); 8] = [
            |u| u.kind = SamplingKind::Http,
            |u| u.interval = SamplingInterval::FiveMinutes,
            |u| u.period = SamplingPeriod::SixHours,
            |u| u.offset = 1,
            |u| u.src_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            |u| u.dst_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            |u| u.node = Some(OTHER_SENSOR_NAME.to_string()),
            |u| u.column = Some(1),
        ];
        for change in changes {
            let mut new = old.clone();
            new.name = "renamed".to_string();
            change(&mut new);
            let error = f.table().update(id, &old, &new).unwrap_err();
            assert_eq!(
                policy_error(&error),
                &SamplingPolicyError::DefinitionFixed { id }
            );
            assert_eq!(f.policy(id).name, "a");
        }

        let mut renamed = old.clone();
        renamed.name = "renamed".to_string();
        f.table().update(id, &old, &renamed).unwrap();
        let policy = f.policy(id);
        assert_eq!(policy.name, "renamed");
        assert_eq!(policy.state, PolicyState::Fixed);
    }

    #[test]
    fn assigning_a_draft_without_fix_is_refused() {
        let f = setup();
        let id = f.insert("a");

        let error = f
            .table()
            .assign(id, Some(&f.generator()), false)
            .unwrap_err();
        assert_eq!(policy_error(&error), &SamplingPolicyError::Draft { id });
        let policy = f.policy(id);
        assert_eq!(policy.state, PolicyState::Draft);
        assert_eq!(policy.assignee, None);
    }

    #[test]
    fn assigning_with_fix_fixes_and_assigns_together() {
        let f = setup();
        let id = f.insert("a");

        f.table().assign(id, Some(&f.generator()), true).unwrap();

        let policy = f.policy(id);
        assert_eq!(policy.state, PolicyState::Fixed);
        assert_eq!(policy.assignee, Some(f.generator()));
        assert_eq!(policy.data_store.as_deref(), Some("ds-a"));
        assert_eq!(
            f.store
                .sampling_policies_assigned_to(&f.generator())
                .unwrap(),
            vec![policy]
        );
    }

    #[test]
    fn a_refused_assignment_with_fix_leaves_a_draft() {
        let f = setup();
        let id = f.insert("a");

        let error = f
            .table()
            .assign(id, Some(&instance(f.node, ENGINE)), true)
            .unwrap_err();
        assert!(matches!(
            policy_error(&error),
            SamplingPolicyError::NotTimeSeriesGenerator { .. }
        ));
        let policy = f.policy(id);
        assert_eq!(policy.state, PolicyState::Draft);
        assert_eq!(policy.assignee, None);
    }

    #[test]
    fn assignment_refusals() {
        let f = setup();
        let id = f.insert("a");
        f.table().fix(id).unwrap();
        let refusal = |assignee: &ModelInstance| {
            let error = f.table().assign(id, Some(assignee), false).unwrap_err();
            policy_error(&error).clone()
        };

        for agent_key in [ENGINE, SENSOR, "missing"] {
            assert_eq!(
                refusal(&instance(f.node, agent_key)),
                SamplingPolicyError::NotTimeSeriesGenerator {
                    node_id: f.node,
                    agent_key: agent_key.to_string(),
                }
            );
        }
        assert_eq!(
            refusal(&instance(f.other_node, GENERATOR)),
            SamplingPolicyError::CustomerMismatch {
                node_id: f.other_node,
                node_customer_id: Some(OTHER_CUSTOMER),
                customer_id: CUSTOMER,
            }
        );

        for node in [
            Some(SENSOR_HOST.to_string()),
            None,
            Some(OTHER_SENSOR_NAME.to_string()),
            Some("piglet.generators.example".to_string()),
            Some("piglet.".to_string()),
        ] {
            let draft = f.insert(&format!("draft-{node:?}"));
            let policy = f.policy(draft);
            let new = SamplingPolicyUpdate {
                node: node.clone(),
                ..policy.clone().into()
            };
            f.table().update(draft, &policy.into(), &new).unwrap();
            let error = f
                .table()
                .assign(draft, Some(&f.generator()), true)
                .unwrap_err();
            assert_eq!(
                policy_error(&error),
                &SamplingPolicyError::NotSensorOfCustomer {
                    id: draft,
                    node,
                    customer_id: CUSTOMER,
                }
            );
            assert_eq!(f.policy(draft).state, PolicyState::Draft);
        }

        // A legacy policy without a customer.
        let mut legacy = f.policy(id);
        legacy.customer_id = None;
        let txn = f.store.states.db().transaction();
        f.table().put_row(&txn, &legacy).unwrap();
        txn.commit().unwrap();
        assert_eq!(
            refusal(&f.generator()),
            SamplingPolicyError::NoCustomer { id }
        );

        let error = f.table().assign(id, None, true).unwrap_err();
        assert_eq!(
            policy_error(&error),
            &SamplingPolicyError::FixWithoutAssignee { id }
        );
        assert_eq!(f.policy(id).assignee, None);
    }

    #[test]
    fn an_unused_policy_is_reassigned_and_unassigned_freely() {
        let f = setup();
        let id = f.assigned("a");

        for (agent_key, data_store) in [
            (EMPTY_STORE_GENERATOR, None),
            (OTHER_STORE_GENERATOR, Some("ds-b")),
            (NO_STORE_GENERATOR, None),
        ] {
            let assignee = instance(f.generators, agent_key);
            f.table().assign(id, Some(&assignee), false).unwrap();
            let policy = f.policy(id);
            assert_eq!(policy.assignee, Some(assignee));
            assert_eq!(policy.data_store.as_deref(), data_store);
        }

        f.table()
            .assign(
                id,
                Some(&instance(f.generators, OTHER_STORE_GENERATOR)),
                false,
            )
            .unwrap();
        f.table().assign(id, None, false).unwrap();
        let policy = f.policy(id);
        assert_eq!(policy.assignee, None);
        assert_eq!(policy.data_store.as_deref(), Some("ds-b"));
        assert_eq!(policy.state, PolicyState::Fixed);
    }

    #[test]
    fn a_policy_in_use_keeps_its_data_store() {
        let f = setup();
        let id = f.assigned("a");
        define(&f, "series", ModelMethod::Timeseries, &id.to_string());
        let uses = vec![PolicyUse::Definition {
            name: "series".to_string(),
        }];

        let error = f.table().assign(id, None, false).unwrap_err();
        assert_eq!(
            policy_error(&error),
            &SamplingPolicyError::PolicyInUse(uses.clone())
        );
        assert!(error.to_string().contains("training definition \"series\""));
        assert_eq!(f.policy(id).assignee, Some(f.generator()));

        for (agent_key, giganto_name) in [
            (OTHER_STORE_GENERATOR, Some("ds-b")),
            (EMPTY_STORE_GENERATOR, None),
            (NO_STORE_GENERATOR, None),
        ] {
            let error = f
                .table()
                .assign(id, Some(&instance(f.generators, agent_key)), false)
                .unwrap_err();
            assert_eq!(
                policy_error(&error),
                &SamplingPolicyError::DataStoreMismatch {
                    id,
                    data_store: Some("ds-a".to_string()),
                    giganto_name: giganto_name.map(ToString::to_string),
                    uses: uses.clone(),
                }
            );
            assert_eq!(f.policy(id).assignee, Some(f.generator()));
        }

        let same_store = instance(f.generators, SAME_STORE_GENERATOR);
        f.table().assign(id, Some(&same_store), false).unwrap();
        let policy = f.policy(id);
        assert_eq!(policy.assignee, Some(same_store));
        assert_eq!(policy.data_store.as_deref(), Some("ds-a"));
    }

    #[test]
    fn a_policy_in_use_without_a_data_store_cannot_be_reassigned() {
        let f = setup();
        let id = f.insert("a");
        f.table()
            .assign(
                id,
                Some(&instance(f.generators, EMPTY_STORE_GENERATOR)),
                true,
            )
            .unwrap();
        assert_eq!(f.policy(id).data_store, None);
        define(&f, "series", ModelMethod::Timeseries, &id.to_string());

        for agent_key in [EMPTY_STORE_GENERATOR, NO_STORE_GENERATOR] {
            let error = f
                .table()
                .assign(id, Some(&instance(f.generators, agent_key)), false)
                .unwrap_err();
            assert!(matches!(
                policy_error(&error),
                SamplingPolicyError::DataStoreMismatch { .. }
            ));
        }
        let error = f
            .table()
            .assign(id, Some(&f.generator()), false)
            .unwrap_err();
        assert!(matches!(
            policy_error(&error),
            SamplingPolicyError::DataStoreMismatch { .. }
        ));
    }

    #[test]
    fn removing_the_generator_unassigns_its_policies_in_the_same_commit() {
        let f = setup();
        let first = f.assigned("a");
        let second = f.assigned("b");
        let other = f.insert("c");
        let other_generator = instance(f.generators, OTHER_STORE_GENERATOR);
        f.table()
            .assign(other, Some(&other_generator), true)
            .unwrap();

        let stored = f.store.node_map().get_by_id(f.node).unwrap().unwrap().0;
        let mut without = stored.clone();
        without.agents.retain(|agent| agent.key != GENERATOR);

        let mut failing = f.store.node_map();
        failing.set_before_commit_hook(Some(Box::new(|| Err(anyhow!("crash")))));
        failing
            .update(f.node, &stored.clone().into(), &without.clone().into())
            .unwrap_err();
        assert_eq!(f.policy(first).assignee, Some(f.generator()));

        f.store
            .node_map()
            .update(f.node, &stored.into(), &without.into())
            .unwrap();
        for id in [first, second] {
            let policy = f.policy(id);
            assert_eq!(policy.assignee, None);
            assert_eq!(policy.data_store.as_deref(), Some("ds-a"));
            assert_eq!(policy.state, PolicyState::Fixed);
        }
        assert_eq!(f.policy(other).assignee, Some(other_generator.clone()));
        assert_eq!(
            f.store
                .sampling_policies_assigned_to(&f.generator())
                .unwrap(),
            Vec::new()
        );

        f.store.node_map().remove(f.generators).unwrap();
        let policy = f.policy(other);
        assert_eq!(policy.assignee, None);
        assert_eq!(policy.data_store.as_deref(), Some("ds-b"));
    }

    /// Stores a training definition `name` on the Unsupervised Engine of
    /// `node` that lists `source`.
    fn define(f: &Fixture, name: &str, method: ModelMethod, source: &str) {
        f.store
            .insert_training_definition(NewTrainingDefinition {
                name: name.to_string(),
                customer_id: CUSTOMER,
                instance: instance(f.node, ENGINE),
                method,
                event_kind: "conn".to_string(),
                sources: vec![source.to_string()],
                indicator: None,
                definition: "eps = 5.0".to_string(),
            })
            .unwrap();
    }

    /// Stores a model `name` of the Unsupervised Engine of `node`, of the
    /// method `kind`, trained on `sources`.
    fn add_model(f: &Fixture, name: &str, kind: &str, sources: &[String]) {
        let body = crate::model::Model {
            id: 0,
            name: name.to_string(),
            version: 1,
            kind: kind.to_string(),
            serialized_classifier: b"classifier".to_vec(),
            max_event_id_num: 10,
            event_kind: "conn".to_string(),
            classification_id: 1,
            batch_info: Vec::new(),
            scores: [(1, 0.5)].into_iter().collect(),
        };
        f.store
            .replace_model(
                body,
                ModelOwner {
                    customer_id: CUSTOMER,
                    instance: instance(f.node, ENGINE),
                },
                Utc::now(),
                TrainedWith {
                    run_id: 1,
                    definition: "eps = 5.0".to_string(),
                    sources: sources.to_vec(),
                },
            )
            .unwrap();
    }

    fn detector(id: i32, model: &str, source: &str) -> EngineDetectorRef {
        EngineDetectorRef {
            id,
            model: model.to_string(),
            sources: vec![source.to_string()],
            indicator: None,
        }
    }

    /// Writes the applied and pending documents of the Unsupervised Engine
    /// of `node`.
    fn write_documents(
        f: &Fixture,
        applied: Vec<EngineDetectorRef>,
        pending: Vec<EngineDetectorRef>,
    ) {
        let stored = f.store.node_map().get_by_id(f.node).unwrap().unwrap().0;
        let mut new = stored.clone();
        let engine = new.agents.iter_mut().find(|a| a.key == ENGINE).unwrap();
        engine.config = Some("detectors = 1".to_string().try_into().unwrap());
        engine.draft = Some("detectors = 2".to_string().try_into().unwrap());
        f.store
            .node_map()
            .update_with_engine_documents(
                f.node,
                &stored.into(),
                &new.into(),
                &[EngineDocumentWrite {
                    agent_key: ENGINE.to_string(),
                    applied: Some(EngineDocumentRefs { detectors: applied }),
                    pending: Some(EngineDocumentRefs { detectors: pending }),
                }],
            )
            .unwrap();
    }

    /// Makes the policy `id` used by a timeseries definition, applied and
    /// pending detectors and a model, and names it from a multidimension
    /// definition, model and detector that do not use it.
    fn use_everywhere(f: &Fixture, id: u32) -> Vec<PolicyUse> {
        let source = id.to_string();
        define(f, "a-series", ModelMethod::Timeseries, &source);
        define(f, "b-multi", ModelMethod::Multidimension, &source);
        add_model(f, "series", "Timeseries", std::slice::from_ref(&source));
        add_model(f, "series-2", "Timeseries", &[]);
        add_model(f, "series-3", "Timeseries", &[]);
        add_model(f, "multi", "Multifield", std::slice::from_ref(&source));
        write_documents(
            f,
            vec![
                detector(1, "series", &source),
                detector(2, "multi", &source),
                detector(3, "series-3", "99"),
            ],
            vec![
                detector(1, "series", &source),
                detector(4, "series-2", &source),
            ],
        );
        let engine = instance(f.node, ENGINE);
        vec![
            PolicyUse::Definition {
                name: "a-series".to_string(),
            },
            PolicyUse::Detector {
                instance: engine.clone(),
                detector_id: 1,
                applied: true,
                pending: true,
            },
            PolicyUse::Detector {
                instance: engine,
                detector_id: 4,
                applied: false,
                pending: true,
            },
            PolicyUse::Model {
                name: "series".to_string(),
            },
        ]
    }

    #[test]
    fn uses_list_timeseries_definitions_detectors_and_models() {
        let f = setup();
        let id = f.assigned("a");
        let unused = f.insert("b");
        let uses = use_everywhere(&f, id);

        assert_eq!(f.store.sampling_policy_uses(id).unwrap(), uses);
        assert_eq!(f.store.sampling_policy_uses(unused).unwrap(), Vec::new());

        // The transaction's view finds the same uses.
        let txn = f.store.states.db().transaction();
        assert_eq!(
            uses_in_transaction(f.store.states.db(), &txn, id).unwrap(),
            uses
        );
    }

    #[test]
    fn a_non_timeseries_definition_is_not_a_use() {
        let f = setup();
        for name in ["a", "b", "c", "d"] {
            f.insert(name);
        }
        define(&f, "multi", ModelMethod::Multidimension, "3");
        define(&f, "prefix", ModelMethod::Prefix, "3");
        assert_eq!(f.store.sampling_policy_uses(3).unwrap(), Vec::new());
        f.table().remove_unused(3).unwrap();
    }

    #[test]
    fn a_detector_of_a_model_not_yet_trained_uses_its_definition_method() {
        let f = setup();
        let id = f.assigned("a");
        let source = id.to_string();
        let definitions = vec![TrainingDefinition {
            name: "series".to_string(),
            customer_id: CUSTOMER,
            instance: None,
            method: ModelMethod::Timeseries,
            event_kind: "conn".to_string(),
            sources: Vec::new(),
            indicator: None,
            definition: String::new(),
            cloning: false,
            last_run: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }];
        let row = EngineInstanceRow {
            stopped: false,
            applied: EngineDocumentRefs {
                detectors: vec![
                    detector(1, "series", &source),
                    detector(2, "unknown", &source),
                ],
            },
            pending: EngineDocumentRefs::default(),
            statuses: BTreeMap::new(),
        };
        let engine = instance(f.node, ENGINE);
        assert_eq!(
            collect_uses(id, &definitions, &[(engine.clone(), row)], &[]),
            vec![PolicyUse::Detector {
                instance: engine,
                detector_id: 1,
                applied: true,
                pending: false,
            }]
        );
    }

    #[test]
    fn remove_unused_refuses_a_policy_in_use() {
        let f = setup();
        let id = f.assigned("a");
        let uses = use_everywhere(&f, id);

        let error = f.table().remove_unused(id).unwrap_err();
        assert_eq!(
            policy_error(&error),
            &SamplingPolicyError::PolicyInUse(uses)
        );
        assert!(f.table().get_by_id(id).unwrap().is_some());

        let error = f.table().remove_unused(id + 1).unwrap_err();
        assert_eq!(
            policy_error(&error),
            &SamplingPolicyError::NotFound { id: id + 1 }
        );
    }

    #[test]
    fn a_draft_can_always_be_removed() {
        let f = setup();
        let id = f.insert("a");
        assert_eq!(f.table().remove_unused(id).unwrap(), b"a".to_vec());
        assert!(f.table().get_by_id(id).unwrap().is_none());
    }

    #[test]
    fn remove_customer_policies_removes_policies_in_use() {
        let f = setup();
        let used = f.assigned("a");
        let draft = f.insert("b");
        let other = f
            .table()
            .insert(NewSamplingPolicy {
                customer_id: OTHER_CUSTOMER,
                ..new_policy("c")
            })
            .unwrap();
        use_everywhere(&f, used);

        assert_eq!(
            f.table().remove_customer_policies(CUSTOMER).unwrap(),
            vec![used, draft]
        );
        assert!(f.table().get_by_id(used).unwrap().is_none());
        assert!(f.table().get_by_id(draft).unwrap().is_none());
        assert!(f.table().get_by_id(other).unwrap().is_some());
        assert_eq!(
            f.table().remove_customer_policies(CUSTOMER).unwrap(),
            Vec::<u32>::new()
        );
        assert_eq!(f.insert("d"), other + 1);
    }

    #[test]
    fn deleted_id_is_not_reused() {
        let f = setup();
        let ids: Vec<u32> = ["a", "b", "c"]
            .into_iter()
            .map(|name| f.insert(name))
            .collect();
        assert_eq!(ids, vec![0, 1, 2]);

        f.table().remove_unused(1).unwrap();
        assert!(f.table().get_by_id(1).unwrap().is_none());
        assert_eq!(f.insert("d"), 3);
    }

    #[test]
    fn insert_after_deleting_every_policy_takes_a_new_id() {
        let f = setup();
        for name in ["a", "b", "c"] {
            f.insert(name);
        }
        for id in [2, 0, 1] {
            f.table().remove_unused(id).unwrap();
        }
        assert_eq!(f.table().count().unwrap(), 0);
        assert_eq!(f.insert("d"), 3);
    }

    #[test]
    fn deleted_name_is_reusable_under_a_new_id() {
        let f = setup();
        let old = f.insert("a");
        f.table().remove_unused(old).unwrap();

        let new = f.insert("a");
        assert_ne!(new, old);
        assert!(f.table().get_by_id(old).unwrap().is_none());
        assert_eq!(f.policy(new).name, "a");
    }

    #[test]
    fn count_and_iteration_skip_deleted_ids() {
        let f = setup();
        for name in ["a", "b", "c"] {
            f.insert(name);
        }
        f.table().remove_unused(1).unwrap();

        assert_eq!(f.table().count().unwrap(), 2);
        let ids: Vec<u32> = f
            .table()
            .iter(Direction::Forward, None)
            .map(|policy| policy.unwrap().id)
            .collect();
        assert_eq!(ids, vec![0, 2]);
    }
}
