//! The `TimeSeriesGenerationPolicy` table.
//!
//! A time series generation policy is a `Draft` until it is fixed, and
//! `Fixed` from then on. A draft's generation spec and name can change, and
//! it cannot be assigned; a fixed policy's spec is frozen, only its name can
//! change, and it is assigned to a Time Series Generator agent through
//! [`IndexedTable::assign`]. A policy is in use while a timeseries training
//! definition, a detector of a timeseries model or a timeseries model names
//! its ID as a source, and is deleted only by
//! [`IndexedTable::remove_unused`], which refuses while it is in use, or by
//! [`IndexedTable::remove_customer_policies`], for the deletion of its
//! customer.
//!
//! The spec of a policy is checked as it is inserted and as a draft is
//! updated, against the network raw event kinds, the time-series type
//! catalog, the customer's networks and the customer's device identification
//! (DAI) sites, within which its `sensors` must lie; see
//! [`TimeSeriesGenerationPolicyError`]. The site check reads and increments
//! the customer's `dai site policy guard` row first, as every write of the
//! customer's sites does, so a policy save and a site change racing for one
//! customer conflict and the retried one checks again.
//!
//! Every writer is one optimistic transaction, retried from the start on a
//! commit conflict; a refusal returns without committing and changes
//! nothing. The uses a writer checks are found by scanning the training
//! definitions, the `engine instances` rows and the models inside its
//! transaction, reading each one examined for update, so a concurrent change
//! of an existing one conflicts. A scan is not tracked: a use created by a
//! concurrent transaction after the scan does not conflict, as with the
//! guards of `model_guard`.

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashSet},
    fmt,
    net::IpAddr,
};

use anyhow::{Context, Result, anyhow};
use jiff::Timestamp;
use review_protocol::types::{
    CounterpartScope, EndpointRole, GroupByUnit, Measure, RawEventKind, TimeSeriesTypeRef,
};
use rocksdb::{IteratorMode, OptimisticTransactionDB, Transaction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    Clock, Dai, EngineInstanceRow, EngineInstances, Model, ModelInstance, ModelMethod,
    OwnedNetworkTable, TrainingDefinition, TrainingDefinitions, UniqueKey, engine_instance_key,
    now_nanos,
};
use crate::{
    Agent, AgentKind, EXCLUSIVE, Indexable, IndexedMap, IndexedMapUpdate, IndexedTable, Iterable,
    Map, NodeTable, TimeSeriesType,
    collections::Indexed,
    model::ClusteringMethod,
    time_series_type::{find as find_time_series_type, time_series_types},
    types::FromKeyValue,
};

/// The key of the Data Store name in a Time Series Generator's configuration.
const GIGANTO_NAME: &str = "giganto_name";

/// The raw event kinds a policy may count: the network kinds.
pub(crate) const NETWORK_RAW_EVENT_KINDS: [RawEventKind; 20] = [
    RawEventKind::Bootp,
    RawEventKind::Conn,
    RawEventKind::DceRpc,
    RawEventKind::Dhcp,
    RawEventKind::Dns,
    RawEventKind::Ftp,
    RawEventKind::Http,
    RawEventKind::Icmp,
    RawEventKind::Kerberos,
    RawEventKind::Ldap,
    RawEventKind::MalformedDns,
    RawEventKind::Mqtt,
    RawEventKind::Nfs,
    RawEventKind::Ntlm,
    RawEventKind::Radius,
    RawEventKind::Rdp,
    RawEventKind::Smb,
    RawEventKind::Smtp,
    RawEventKind::Ssh,
    RawEventKind::Tls,
];

/// The step a policy's `utc_offset` must be a multiple of, in seconds.
const UTC_OFFSET_STEP: i32 = 3600;
/// The lowest `utc_offset`, in seconds: UTC−12.
const MIN_UTC_OFFSET: i32 = -43_200;
/// The highest `utc_offset`, in seconds: UTC+14.
const MAX_UTC_OFFSET: i32 = 50_400;

type Txn<'a> = Transaction<'a, OptimisticTransactionDB>;

/// A time series generation policy: what a Time Series Generator counts, how
/// it splits the counts into series, and how it slots and windows them.
///
/// The fields from `raw_event_kind` to `time_series_type` are the generation
/// spec. The customer's internal networks, which the policy is sent with, are
/// not stored: the Central Manager fills them when it sends the policy.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct TimeSeriesGenerationPolicy {
    pub id: u32,
    pub name: String,
    /// The raw event kind the policy counts, one of the network kinds.
    pub raw_event_kind: RawEventKind,
    /// The value counted per slot.
    pub measure: Measure,
    /// The endpoint whose internal IP splits the series; `None` for one
    /// series for the whole policy.
    pub group_by: Option<EndpointRole>,
    /// The unit `group_by` splits by.
    pub group_by_unit: GroupByUnit,
    /// The filter on whether the other endpoint is internal.
    pub counterpart_scope: CounterpartScope,
    pub slot_size: SlotSize,
    pub window_size: WindowSize,
    /// The offset from UTC, in seconds, that aligns window boundaries to
    /// local time.
    pub utc_offset: i32,
    /// The source IP a raw event must have to be counted, if any.
    pub src_ip: Option<IpAddr>,
    /// The destination IP a raw event must have to be counted, if any.
    pub dst_ip: Option<IpAddr>,
    /// The names of the sensors whose raw events are counted.
    pub sensors: Vec<String>,
    /// The catalog type the policy was made from; `None` for a custom
    /// policy.
    pub time_series_type: Option<TimeSeriesTypeRef>,
    /// The customer the policy belongs to.
    pub customer_id: u32,
    pub state: PolicyState,
    /// The Time Series Generator agent the policy is assigned to.
    pub assignee: Option<ModelInstance>,
    /// The `giganto_name` of the generator the policy was last assigned to,
    /// `None` if that generator had none. Unassigning the policy and
    /// removing the generator leave it as it is.
    pub data_store: Option<String>,
    #[serde(with = "crate::timestamp::ts_nanoseconds_saturating")]
    pub creation_time: Timestamp,
}

impl FromKeyValue for TimeSeriesGenerationPolicy {
    fn from_key_value(_key: &[u8], value: &[u8]) -> anyhow::Result<Self> {
        super::deserialize(value)
    }
}

impl UniqueKey for TimeSeriesGenerationPolicy {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl Indexable for TimeSeriesGenerationPolicy {
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

/// The length of one slot of a series.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[repr(u32)]
pub enum SlotSize {
    FiveMinutes = 0,
    TenMinutes = 1,
    FifteenMinutes = 2,
    ThirtyMinutes = 3,
    OneHour = 4,
}

/// The length of one window of a series, which is one series sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[repr(u32)]
pub enum WindowSize {
    SixHours = 0,
    TwelveHours = 1,
    OneDay = 2,
}

/// The state of a time series generation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum PolicyState {
    /// The generation spec and the name can change, and the policy cannot be
    /// assigned.
    Draft,
    /// The generation spec is frozen and only the name can change. A policy
    /// never leaves this state.
    Fixed,
}

/// A time series generation policy to insert: its name, its generation spec
/// and its customer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewTimeSeriesGenerationPolicy {
    pub name: String,
    pub raw_event_kind: RawEventKind,
    pub measure: Measure,
    pub group_by: Option<EndpointRole>,
    pub group_by_unit: GroupByUnit,
    pub counterpart_scope: CounterpartScope,
    pub slot_size: SlotSize,
    pub window_size: WindowSize,
    pub utc_offset: i32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub sensors: Vec<String>,
    pub time_series_type: Option<TimeSeriesTypeRef>,
    pub customer_id: u32,
}

/// What uses a time series generation policy, by naming its decimal ID as a
/// source.
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

/// A refusal of a time series generation policy write.
///
/// It is returned inside the `anyhow::Error` of the refusing method, so a
/// caller can `downcast_ref` it.
///
/// The spec checks run as a policy is inserted and as a draft is updated, in
/// the order of the variants from `UnsupportedRawEventKind` to
/// `SensorsSpanSites`, and the first that fails is returned. The site
/// condition, `SensorsSpanSites`, is checked last, inside the transaction
/// that writes the policy; an update that leaves a fixed policy's spec as it
/// is does not check it, and neither do the other writers.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TimeSeriesGenerationPolicyError {
    /// No time series generation policy has the ID.
    #[error("no time series generation policy has ID {id}")]
    NotFound { id: u32 },
    /// An update changes the generation spec of a fixed policy.
    #[error("time series generation policy {id} is fixed; only its name can change")]
    SpecFixed { id: u32 },
    /// An assignment names a draft without fixing it.
    #[error("time series generation policy {id} is a draft; fix the policy before assigning it")]
    Draft { id: u32 },
    /// An unassignment asks to fix the policy.
    #[error("time series generation policy {id} can be fixed only by assigning it")]
    FixWithoutAssignee { id: u32 },
    /// The assignee is not a Time Series Generator agent.
    #[error("agent {agent_key:?} of node {node_id} is not a Time Series Generator agent")]
    NotTimeSeriesGenerator { node_id: u32, agent_key: String },
    /// The assignee's node has no applied profile, or one of another
    /// customer.
    #[error("node {node_id} does not belong to customer {customer_id}")]
    CustomerMismatch {
        node_id: u32,
        /// The customer of the node's applied profile; `None` if it has none.
        node_customer_id: Option<u32>,
        customer_id: u32,
    },
    /// An entry of the policy's `sensors`, the first in order, is not a
    /// sensor name of its customer.
    #[error(
        "time series generation policy {id} reads {sensor:?}, which is not a sensor of customer \
         {customer_id}"
    )]
    NotSensorOfCustomer {
        id: u32,
        sensor: String,
        customer_id: u32,
    },
    /// The policy is in use, which refuses its unassignment and its delete.
    #[error("the time series generation policy is in use by {}", list_uses(.0))]
    PolicyInUse(Vec<PolicyUse>),
    /// The policy is in use, and the new assignee's Data Store is not the
    /// one the policy's series are kept in.
    #[error(
        "time series generation policy {id} is in use by {}; the generator's Data Store \
         {giganto_name:?} is not the policy's {data_store:?}",
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
    /// `raw_event_kind` is not one of the network raw event kinds.
    #[error("raw event kind {raw_event_kind:?} is not a network raw event kind")]
    UnsupportedRawEventKind { raw_event_kind: RawEventKind },
    /// `measure` sums a Conn field, and `raw_event_kind` is not Conn.
    #[error("a sum is measured only on Conn, not on {raw_event_kind:?}")]
    SumRequiresConn { raw_event_kind: RawEventKind },
    /// `utc_offset` is not a whole number of hours from −12 to +14 hours.
    #[error("UTC offset {utc_offset} is not a multiple of 3600 seconds from -43200 through 50400")]
    InvalidUtcOffset { utc_offset: i32 },
    /// `sensors` is empty, or has an empty name or a name twice.
    #[error("sensors must be one or more distinct, non-empty names")]
    InvalidSensors,
    /// `group_by` is `None`, and `group_by_unit` is not `Ip` or
    /// `counterpart_scope` is not `Any`.
    #[error("a policy without group_by has the group_by_unit Ip and the counterpart_scope Any")]
    UngroupedScope,
    /// `group_by_unit` is not `Ip`.
    #[error("only the group_by_unit Ip is supported")]
    NetworkUnitNotSupported,
    /// A custom policy filters by the IP of the endpoint it groups by.
    #[error("a custom policy grouped by {group_by:?} cannot filter by the IP of that endpoint")]
    SameRoleAddressFilter { group_by: EndpointRole },
    /// The catalog has no time-series type of the id, or has it at another
    /// version.
    #[error("no time-series type {id:?} at version {version}")]
    UnknownTimeSeriesType { id: String, version: u32 },
    /// A spec value of a policy made from a type is not the type's.
    #[error("{field} differs from the time-series type's")]
    TypeMismatch {
        /// The name of the first policy field that differs.
        field: &'static str,
    },
    /// A policy made from a type filters by IP.
    #[error("a policy made from a time-series type cannot filter by IP")]
    AddressFilterWithType,
    /// The policy groups by an endpoint, and its customer has no internal
    /// address: no address whose narrowest containing network is an
    /// `Intranet` or `Gateway` network.
    #[error("customer {customer_id} has no Intranet or Gateway network to group by")]
    NoInternalNetwork { customer_id: u32 },
    /// The policy's sensors are in more than one site of its customer, under
    /// the assignment in effect at the time of the save or under the one the
    /// site table states, which takes effect at the next 5-minute boundary.
    #[error(
        "the sensors of the policy are in more than one site of customer {customer_id}: {}",
        list_sites(sites)
    )]
    SensorsSpanSites {
        customer_id: u32,
        /// Each site token of the failing assignment, the one in effect when
        /// both fail, with the policy's sensors in it; sites ordered by
        /// token, sensors in the policy's order.
        sites: Vec<(String, Vec<String>)>,
    },
}

/// Lists `sites` for an error message.
fn list_sites(sites: &[(String, Vec<String>)]) -> String {
    sites
        .iter()
        .map(|(site, sensors)| format!("{site} ({})", sensors.join(", ")))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Functions for the `time series generation policy` indexed map.
///
/// A time series generation policy ID is never reused: the Data Store keeps
/// a policy's time series, and the Time Series Generator its checkpoint,
/// under that ID after the policy is deleted. A policy is deleted with
/// [`remove_unused`](IndexedTable::remove_unused), or with
/// [`remove_customer_policies`](IndexedTable::remove_customer_policies), both
/// of which retire its ID, and the recycling `remove` writers are not
/// available for this table.
impl<'d> IndexedTable<'d, TimeSeriesGenerationPolicy> {
    /// Opens the `time series generation policy` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::TIME_SERIES_GENERATION_POLICY)
            .map(IndexedTable::new)
            .ok()
    }

    /// Inserts a new policy, a [`PolicyState::Draft`] with no assignee and no
    /// Data Store, and returns its ID.
    ///
    /// The spec is checked first; the customer's networks, and its DAI sites
    /// for the site condition, are read in the transaction that writes the
    /// policy.
    ///
    /// # Errors
    ///
    /// Returns the first [`TimeSeriesGenerationPolicyError`] spec check that
    /// fails inside the error, and changes nothing. Returns an error if a
    /// policy has the name, the name is empty, or the database operation
    /// fails.
    pub fn insert(&self, policy: NewTimeSeriesGenerationPolicy) -> Result<u32> {
        self.insert_with_catalog(policy, time_series_types(), &now_nanos)
    }

    /// Inserts a new policy as [`insert`](Self::insert) does, checking a
    /// policy made from a type against `catalog` and the site condition at
    /// the time `clock` gives in each attempt of the transaction.
    pub(crate) fn insert_with_catalog(
        &self,
        policy: NewTimeSeriesGenerationPolicy,
        catalog: &[TimeSeriesType],
        clock: &dyn Clock,
    ) -> Result<u32> {
        let networks = self.customer_networks()?;
        let dai = self.dai()?;
        let record = TimeSeriesGenerationPolicy {
            id: 0,
            name: policy.name,
            raw_event_kind: policy.raw_event_kind,
            measure: policy.measure,
            group_by: policy.group_by,
            group_by_unit: policy.group_by_unit,
            counterpart_scope: policy.counterpart_scope,
            slot_size: policy.slot_size,
            window_size: policy.window_size,
            utc_offset: policy.utc_offset,
            src_ip: policy.src_ip,
            dst_ip: policy.dst_ip,
            sensors: policy.sensors,
            time_series_type: policy.time_series_type,
            customer_id: policy.customer_id,
            state: PolicyState::Draft,
            assignee: None,
            data_store: None,
            creation_time: Timestamp::now(),
        };
        check_spec(&record, catalog)?;
        self.write(|txn| {
            dai.lock_customer(txn, record.customer_id)?;
            let now = clock.now()?;
            check_internal_network(&networks, txn, &record)?;
            dai.check_policy_sites(txn, record.customer_id, &record.sensors, now)?;
            self.indexed_map
                .insert_with_transaction(record.clone(), txn)
        })
    }

    /// Updates the `TimeSeriesGenerationPolicy` from `old` to `new`, given
    /// `id`.
    ///
    /// Only the name and the generation spec change. The stored policy is
    /// read first, as its state and customer decide the checks. The spec of
    /// a [`PolicyState::Draft`] policy is checked as [`insert`](Self::insert)
    /// checks it, in the same transaction as the write. The spec of a
    /// [`PolicyState::Fixed`] policy cannot change, and is not checked.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid, the stored policy is not
    /// `old`, the new name is empty or another policy's, or the database
    /// operation fails. Returns, inside the error, and changes nothing:
    /// [`TimeSeriesGenerationPolicyError::SpecFixed`] if the policy is fixed
    /// and `new` has another spec; the first spec check that fails if the
    /// policy is a draft.
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        self.update_with_catalog(id, old, new, time_series_types(), &now_nanos)
    }

    /// Updates the policy as [`update`](Self::update) does, checking a draft
    /// made from a type against `catalog` and the site condition of a draft
    /// at the time `clock` gives in each attempt of the transaction.
    pub(crate) fn update_with_catalog(
        &self,
        id: u32,
        old: &Update,
        new: &Update,
        catalog: &[TimeSeriesType],
        clock: &dyn Clock,
    ) -> Result<()> {
        let networks = self.customer_networks()?;
        let dai = self.dai()?;
        self.write(|txn| {
            // An unknown ID, and a stored policy that is not `old`, are
            // refused by the write below; a fixed policy's spec is refused
            // by `Update::apply`.
            if let Some(stored) = self.get_by_id_in_transaction(id, txn)?
                && stored.state == PolicyState::Draft
                && old.verify(&stored)
            {
                let updated = new.apply(stored)?;
                check_spec(&updated, catalog)?;
                dai.lock_customer(txn, updated.customer_id)?;
                let now = clock.now()?;
                check_internal_network(&networks, txn, &updated)?;
                dai.check_policy_sites(txn, updated.customer_id, &updated.sensors, now)?;
            }
            self.indexed_map.update_with_transaction(id, old, new, txn)
        })
    }

    /// Moves a [`PolicyState::Draft`] policy to [`PolicyState::Fixed`].
    ///
    /// Fixing a fixed policy changes nothing and succeeds. Nothing moves a
    /// policy back to a draft.
    ///
    /// # Errors
    ///
    /// Returns [`TimeSeriesGenerationPolicyError::NotFound`] inside the error
    /// if no policy has the ID. Returns an error, and changes nothing, if the
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
    /// Returns a [`TimeSeriesGenerationPolicyError`] inside the error, and
    /// changes nothing, checked in this order: `NotFound`. For an
    /// unassignment: `FixWithoutAssignee` if `fix` is set; `PolicyInUse`
    /// while the policy is in use. For an assignment: `Draft` if the policy
    /// is a draft and `fix` is not set; `NotTimeSeriesGenerator` if
    /// `assignee` is not an [`AgentKind::TimeSeriesGenerator`] agent;
    /// `CustomerMismatch` if the assignee's node has no applied profile or
    /// one of another customer; `NotSensorOfCustomer`, naming the first
    /// entry of the policy's `sensors` that is not a sensor name of its
    /// customer;
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
                    return Err(TimeSeriesGenerationPolicyError::FixWithoutAssignee { id }.into());
                }
                let uses = uses_in_transaction(db, txn, id)?;
                if !uses.is_empty() {
                    return Err(TimeSeriesGenerationPolicyError::PolicyInUse(uses).into());
                }
                policy.assignee = None;
                return self.put_row(txn, &policy);
            };

            if policy.state == PolicyState::Draft && !fix {
                return Err(TimeSeriesGenerationPolicyError::Draft { id }.into());
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
                return Err(TimeSeriesGenerationPolicyError::NotTimeSeriesGenerator {
                    node_id: assignee.node_id,
                    agent_key: assignee.agent_key.clone(),
                }
                .into());
            };
            // Writing the agent row back unchanged makes a removal of the
            // agent, which deletes the row and clears its assignments,
            // conflict with this assignment whichever commits second.
            agents.put_with_transaction(&agent_key, &stored, txn)?;
            let customer_id = policy.customer_id;
            let node_customer_id = nodes
                .applied_profile_in_transaction(assignee.node_id, txn)?
                .map(|profile| profile.customer_id);
            if node_customer_id != Some(customer_id) {
                return Err(TimeSeriesGenerationPolicyError::CustomerMismatch {
                    node_id: assignee.node_id,
                    node_customer_id,
                    customer_id,
                }
                .into());
            }
            for sensor in &policy.sensors {
                if !nodes.is_sensor_name_in_transaction(txn, customer_id, sensor)? {
                    return Err(TimeSeriesGenerationPolicyError::NotSensorOfCustomer {
                        id,
                        sensor: sensor.clone(),
                        customer_id,
                    }
                    .into());
                }
            }
            let giganto_name = giganto_name(&agent);
            let uses = uses_in_transaction(db, txn, id)?;
            if !uses.is_empty() && (giganto_name.is_none() || giganto_name != policy.data_store) {
                return Err(TimeSeriesGenerationPolicyError::DataStoreMismatch {
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
    /// Returns a [`TimeSeriesGenerationPolicyError`] inside the error, and
    /// changes nothing: `NotFound` if no policy has the ID; `PolicyInUse`,
    /// listing every use, while the policy is in use. Returns an error, and
    /// changes nothing, if the database operation fails.
    pub fn remove_unused(&self, id: u32) -> Result<Vec<u8>> {
        let db = self.indexed_map.db();
        self.write(|txn| {
            self.policy_for_update(txn, id)?;
            let uses = uses_in_transaction(db, txn, id)?;
            if !uses.is_empty() {
                return Err(TimeSeriesGenerationPolicyError::PolicyInUse(uses).into());
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
                .filter(|policy| policy.customer_id == customer_id)
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
    pub(crate) fn assigned_to(
        &self,
        instance: &ModelInstance,
    ) -> Result<Vec<TimeSeriesGenerationPolicy>> {
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
    /// [`Store::time_series_generation_policy_uses`](crate::Store::time_series_generation_policy_uses)
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

    /// Returns the sensors of the policy `id` as `txn` sees it, or `None` if
    /// no policy has the ID.
    ///
    /// The index and the policy are read for update, and the policy is
    /// written back unchanged, so that a concurrent change or removal of it
    /// conflicts with `txn` whichever of the two commits first.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub(crate) fn sensors_in_transaction(
        &self,
        txn: &Txn<'_>,
        id: u32,
    ) -> Result<Option<Vec<String>>> {
        let Some(policy) = self
            .get_by_id_in_transaction(id, txn)
            .with_context(|| format!("cannot read time series generation policy {id}"))?
        else {
            return Ok(None);
        };
        self.put_row(txn, &policy)?;
        Ok(Some(policy.sensors))
    }

    /// Returns the policy `id`, read for update within `txn`, refusing an ID
    /// no policy has.
    fn policy_for_update(&self, txn: &Txn<'_>, id: u32) -> Result<TimeSeriesGenerationPolicy> {
        self.get_by_id_in_transaction(id, txn)?
            .ok_or_else(|| TimeSeriesGenerationPolicyError::NotFound { id }.into())
    }

    /// Writes `policy` over its stored row within `txn`. Its name, and so
    /// its key and the index, must be the stored one.
    fn put_row(&self, txn: &Txn<'_>, policy: &TimeSeriesGenerationPolicy) -> Result<()> {
        txn.put_cf(
            self.indexed_map.cf(),
            policy.indexed_key(),
            Indexable::value(policy),
        )
        .context("failed to write time series generation policy")
    }

    /// Returns every policy as `txn` sees it, ordered by name.
    ///
    /// The scan is not tracked by `txn`: a policy written after it does not
    /// conflict with the transaction.
    pub(super) fn scan(&self, txn: &Txn<'_>) -> Result<Vec<TimeSeriesGenerationPolicy>> {
        txn.iterator_cf(self.indexed_map.cf(), IteratorMode::Start)
            .filter_map(|entry| match entry {
                Ok((key, _)) if key.is_empty() => None,
                Ok((_, value)) => Some(super::deserialize(&value)),
                Err(e) => Some(Err(anyhow!(
                    "cannot read time series generation policies: {e}"
                ))),
            })
            .collect()
    }

    /// Opens the DAI configuration tables of the policy's database.
    fn dai(&self) -> Result<Dai<'_>> {
        Dai::open(self.indexed_map.db()).context("DAI configuration tables must be present")
    }

    /// Opens the `customer networks` table of the policy's database.
    fn customer_networks(&self) -> Result<OwnedNetworkTable<'_>> {
        OwnedNetworkTable::open(self.indexed_map.db())
            .context("customer networks table must be present")
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
                Err(e) => {
                    return Err(e)
                        .context("failed to commit time series generation policy changes");
                }
            }
        }
    }
}

/// Checks the spec of `policy`, the checks that need no database read, and
/// returns the first that fails. A policy made from a type is checked
/// against `catalog`.
fn check_spec(
    policy: &TimeSeriesGenerationPolicy,
    catalog: &[TimeSeriesType],
) -> Result<(), TimeSeriesGenerationPolicyError> {
    use TimeSeriesGenerationPolicyError as E;

    if !NETWORK_RAW_EVENT_KINDS.contains(&policy.raw_event_kind) {
        return Err(E::UnsupportedRawEventKind {
            raw_event_kind: policy.raw_event_kind,
        });
    }
    if matches!(policy.measure, Measure::Sum(_)) && policy.raw_event_kind != RawEventKind::Conn {
        return Err(E::SumRequiresConn {
            raw_event_kind: policy.raw_event_kind,
        });
    }
    if policy.utc_offset % UTC_OFFSET_STEP != 0
        || !(MIN_UTC_OFFSET..=MAX_UTC_OFFSET).contains(&policy.utc_offset)
    {
        return Err(E::InvalidUtcOffset {
            utc_offset: policy.utc_offset,
        });
    }
    let mut seen = HashSet::with_capacity(policy.sensors.len());
    if policy.sensors.is_empty()
        || policy
            .sensors
            .iter()
            .any(|sensor| sensor.is_empty() || !seen.insert(sensor.as_str()))
    {
        return Err(E::InvalidSensors);
    }
    if policy.group_by.is_none()
        && (policy.group_by_unit != GroupByUnit::Ip
            || policy.counterpart_scope != CounterpartScope::Any)
    {
        return Err(E::UngroupedScope);
    }
    if policy.group_by_unit != GroupByUnit::Ip {
        return Err(E::NetworkUnitNotSupported);
    }
    let Some(type_ref) = &policy.time_series_type else {
        let same_role_filter = match policy.group_by {
            Some(EndpointRole::Source) => policy.src_ip.is_some(),
            Some(EndpointRole::Destination) => policy.dst_ip.is_some(),
            None => false,
        };
        if let (true, Some(group_by)) = (same_role_filter, policy.group_by) {
            return Err(E::SameRoleAddressFilter { group_by });
        }
        return Ok(());
    };
    let Some(ts_type) = find_time_series_type(catalog, &type_ref.id)
        .filter(|ts_type| ts_type.version == type_ref.version)
    else {
        return Err(E::UnknownTimeSeriesType {
            id: type_ref.id.clone(),
            version: type_ref.version,
        });
    };
    if let Some(field) = first_type_mismatch(policy, ts_type) {
        return Err(E::TypeMismatch { field });
    }
    if policy.src_ip.is_some() || policy.dst_ip.is_some() {
        return Err(E::AddressFilterWithType);
    }
    Ok(())
}

/// Returns the name of the first spec field of `policy` that is not the
/// value of `ts_type`, comparing the fields a type fixes in the order of
/// [`TimeSeriesType`]; `None` if every one is the type's.
fn first_type_mismatch(
    policy: &TimeSeriesGenerationPolicy,
    ts_type: &TimeSeriesType,
) -> Option<&'static str> {
    [
        (
            "raw_event_kind",
            policy.raw_event_kind == ts_type.raw_event_kind,
        ),
        ("measure", policy.measure == ts_type.measure),
        ("group_by", policy.group_by == Some(ts_type.group_by)),
        (
            "group_by_unit",
            policy.group_by_unit == ts_type.group_by_unit,
        ),
        (
            "counterpart_scope",
            policy.counterpart_scope == ts_type.counterpart_scope,
        ),
        ("slot_size", policy.slot_size == ts_type.slot_size),
        ("window_size", policy.window_size == ts_type.window_size),
    ]
    .into_iter()
    .find_map(|(field, same)| (!same).then_some(field))
}

/// Checks, within `txn`, that the customer of a `policy` that groups by an
/// endpoint has at least one internal address, the
/// [`OwnedNetworkSet::internal_group`](crate::OwnedNetworkSet::internal_group)
/// of its networks being the IPs the policy splits its series by. The
/// customer's networks are read for update, so a concurrent change of them
/// conflicts with `txn`.
fn check_internal_network(
    networks: &OwnedNetworkTable<'_>,
    txn: &Txn<'_>,
    policy: &TimeSeriesGenerationPolicy,
) -> Result<()> {
    if policy.group_by.is_none() {
        return Ok(());
    }
    let has_internal = networks
        .get_in_transaction(txn, policy.customer_id)?
        .is_some_and(|set| !set.internal_groups().is_empty());
    if has_internal {
        Ok(())
    } else {
        Err(TimeSeriesGenerationPolicyError::NoInternalNetwork {
            customer_id: policy.customer_id,
        }
        .into())
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
/// timeseries method. Engine documents name only stored models, and a model
/// cannot be deleted while a detector names it, so every detector's model is
/// among `models`.
fn collect_uses(
    id: u32,
    definitions: &[TrainingDefinition],
    rows: &[(ModelInstance, EngineInstanceRow)],
    models: &[Model],
) -> Vec<PolicyUse> {
    let source = id.to_string();
    let timeseries_kind = ClusteringMethod::Timeseries.to_string();
    let model_is_timeseries = |name: &str| {
        models
            .iter()
            .any(|model| model.name == name && model.kind == timeseries_kind)
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

/// The name and the generation spec of a policy, for
/// [`IndexedTable::update`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Update {
    pub name: String,
    pub raw_event_kind: RawEventKind,
    pub measure: Measure,
    pub group_by: Option<EndpointRole>,
    pub group_by_unit: GroupByUnit,
    pub counterpart_scope: CounterpartScope,
    pub slot_size: SlotSize,
    pub window_size: WindowSize,
    pub utc_offset: i32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub sensors: Vec<String>,
    pub time_series_type: Option<TimeSeriesTypeRef>,
}

impl Update {
    /// Returns whether the generation spec is that of `value`; the name is
    /// not part of it.
    fn same_spec(&self, value: &TimeSeriesGenerationPolicy) -> bool {
        self.raw_event_kind == value.raw_event_kind
            && self.measure == value.measure
            && self.group_by == value.group_by
            && self.group_by_unit == value.group_by_unit
            && self.counterpart_scope == value.counterpart_scope
            && self.slot_size == value.slot_size
            && self.window_size == value.window_size
            && self.utc_offset == value.utc_offset
            && self.src_ip == value.src_ip
            && self.dst_ip == value.dst_ip
            && self.sensors == value.sensors
            && self.time_series_type == value.time_series_type
    }
}

impl From<TimeSeriesGenerationPolicy> for Update {
    fn from(input: TimeSeriesGenerationPolicy) -> Self {
        Self {
            name: input.name,
            raw_event_kind: input.raw_event_kind,
            measure: input.measure,
            group_by: input.group_by,
            group_by_unit: input.group_by_unit,
            counterpart_scope: input.counterpart_scope,
            slot_size: input.slot_size,
            window_size: input.window_size,
            utc_offset: input.utc_offset,
            src_ip: input.src_ip,
            dst_ip: input.dst_ip,
            sensors: input.sensors,
            time_series_type: input.time_series_type,
        }
    }
}

impl IndexedMapUpdate for Update {
    type Entry = TimeSeriesGenerationPolicy;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        Some(Cow::Borrowed(self.name.as_bytes()))
    }

    /// Applies the name and the generation spec to the stored `value`,
    /// refusing a change of a fixed policy's spec.
    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        if value.state == PolicyState::Fixed && !self.same_spec(&value) {
            return Err(TimeSeriesGenerationPolicyError::SpecFixed { id: value.id }.into());
        }
        value.name.clone_from(&self.name);
        value.raw_event_kind = self.raw_event_kind;
        value.measure = self.measure;
        value.group_by = self.group_by;
        value.group_by_unit = self.group_by_unit;
        value.counterpart_scope = self.counterpart_scope;
        value.slot_size = self.slot_size;
        value.window_size = self.window_size;
        value.utc_offset = self.utc_offset;
        value.src_ip = self.src_ip;
        value.dst_ip = self.dst_ip;
        value.sensors.clone_from(&self.sensors);
        value.time_series_type.clone_from(&self.time_series_type);
        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        self.name == value.name && self.same_spec(value)
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr};

    use anyhow::Result;
    use review_protocol::types::{ConnField, DetectionModel, ThreatRole};
    use rocksdb::Direction;

    use super::*;
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{
        AgentStatus, EngineDetectorRef, EngineDocumentRefs, EngineDocumentWrite, HostNetworkGroup,
        ModelOwner, NewTrainingDefinition, Node, NodeProfile, OwnedNetwork, Store,
        TimeSeriesGenerationPolicyUpdate, TrainedWith, event::NetworkType,
    };

    const CUSTOMER: u32 = 1;
    const OTHER_CUSTOMER: u32 = 2;
    /// A customer with no nodes, whose networks the network check tests set.
    const NETWORK_CUSTOMER: u32 = 3;
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

    /// A store with two nodes of [`CUSTOMER`] and one of [`OTHER_CUSTOMER`],
    /// each customer with an `Intranet` network.
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

        fn table(&self) -> IndexedTable<'_, TimeSeriesGenerationPolicy> {
            self.store.time_series_generation_policy_map()
        }

        fn policy(&self, id: u32) -> TimeSeriesGenerationPolicy {
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
                creation_time: jiff::Timestamp::now(),
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
        for customer_id in [CUSTOMER, OTHER_CUSTOMER] {
            set_networks(&store, customer_id, &[NetworkType::Intranet]);
        }
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

    /// Replaces the networks of `customer_id` with one network of each of
    /// `types`.
    fn set_networks(store: &Store, customer_id: u32, types: &[NetworkType]) {
        let table = store.customer_networks_map();
        let revision = table
            .get(customer_id)
            .unwrap()
            .map_or(0, |set| set.revision + 1);
        let networks = types
            .iter()
            .zip(1_u8..)
            .map(|(network_type, n)| OwnedNetwork {
                name: format!("network-{n}"),
                network_type: *network_type,
                group: HostNetworkGroup::new(
                    Vec::new(),
                    vec![format!("10.{n}.0.0/16").parse().unwrap()],
                    Vec::new(),
                ),
            })
            .collect();
        table.replace(customer_id, revision, networks).unwrap();
    }

    /// A valid custom policy of [`CUSTOMER`], grouped by source, reading
    /// [`SENSOR_NAME`].
    fn new_policy(name: &str) -> NewTimeSeriesGenerationPolicy {
        NewTimeSeriesGenerationPolicy {
            name: name.to_string(),
            raw_event_kind: RawEventKind::Conn,
            measure: Measure::Count,
            group_by: Some(EndpointRole::Source),
            group_by_unit: GroupByUnit::Ip,
            counterpart_scope: CounterpartScope::Any,
            slot_size: SlotSize::FifteenMinutes,
            window_size: WindowSize::TwelveHours,
            utc_offset: 0,
            src_ip: None,
            dst_ip: None,
            sensors: vec![SENSOR_NAME.to_string()],
            time_series_type: None,
            customer_id: CUSTOMER,
        }
    }

    fn policy_error(error: &anyhow::Error) -> &TimeSeriesGenerationPolicyError {
        error
            .downcast_ref::<TimeSeriesGenerationPolicyError>()
            .unwrap_or_else(|| panic!("not a time series generation policy error: {error:#}"))
    }

    /// Builds a deterministic `TimeSeriesGenerationPolicy` for the
    /// literal-byte contract test. It locks the encoding only, and does not
    /// pass the spec checks.
    fn deterministic_time_series_generation_policy() -> TimeSeriesGenerationPolicy {
        let creation_time = crate::test::from_second(1_700_000_000, 123_456_789);
        TimeSeriesGenerationPolicy {
            id: 42,
            name: "fixture-policy".to_string(),
            raw_event_kind: RawEventKind::Conn,
            measure: Measure::Sum(ConnField::RespBytes),
            group_by: Some(EndpointRole::Destination),
            group_by_unit: GroupByUnit::Ip,
            counterpart_scope: CounterpartScope::External,
            slot_size: SlotSize::ThirtyMinutes,
            window_size: WindowSize::OneDay,
            utc_offset: -18_000,
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            sensors: vec![
                "piglet.sensor-node-1".to_string(),
                "piglet.sensor-node-2".to_string(),
            ],
            time_series_type: Some(TimeSeriesTypeRef {
                id: "conn_resp_bytes".to_string(),
                version: 2,
            }),
            customer_id: 3,
            state: PolicyState::Fixed,
            assignee: Some(instance(5, "crusher@sensor-node-1")),
            data_store: Some("001.giganto.store-node".to_string()),
            creation_time,
        }
    }

    /// Locks the on-disk bincode byte contract for the persisted
    /// `TimeSeriesGenerationPolicy` record.
    ///
    /// Expected bytes come from the committed literal fixture (not from the
    /// production serializer inside this test). `creation_time` is pinned to
    /// `2023-11-14T22:13:20.123456789Z` so the encoding stays deterministic.
    /// Regenerate with `dump_time_series_generation_policy_literal_fixture_bytes`
    /// if the stored layout changes.
    ///
    /// Variants not covered: raw event kinds other than `Conn`;
    /// `Measure::Count`; `ConnField` values other than `RespBytes`;
    /// `EndpointRole::Source`; `GroupByUnit::OwnedNetwork`;
    /// `CounterpartScope::{Any,Internal}`; `SlotSize` values other than
    /// `ThirtyMinutes`; `WindowSize` values other than `OneDay`;
    /// `PolicyState::Draft`; `None` optional fields; zero `utc_offset`; empty
    /// `sensors`; `IPv6` addresses; empty `name`.
    #[test]
    fn time_series_generation_policy_literal_bytes_contract() -> Result<()> {
        const FIXTURE_BYTES: &[u8] = include_bytes!(
            "../../tests/fixtures/time_series_generation_policy_literal_bytes_v0_63.bin"
        );

        let decoded = TimeSeriesGenerationPolicy::from_key_value(b"fixture-policy", FIXTURE_BYTES)?;
        let expected = deterministic_time_series_generation_policy();
        assert_eq!(decoded, expected);

        let serialized = Indexable::value(&expected);
        assert_eq!(serialized.as_slice(), FIXTURE_BYTES);

        Ok(())
    }

    #[test]
    #[ignore = "run manually to regenerate \
                tests/fixtures/time_series_generation_policy_literal_bytes_v0_63.bin"]
    fn dump_time_series_generation_policy_literal_fixture_bytes() {
        let bytes = Indexable::value(&deterministic_time_series_generation_policy());
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/time_series_generation_policy_literal_bytes_v0_63.bin");
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
        assert_eq!(policy.customer_id, CUSTOMER);
        assert_eq!(policy.sensors, [SENSOR_NAME]);
        let new = new_policy("a");
        let stored: TimeSeriesGenerationPolicyUpdate = policy.into();
        assert_eq!(
            stored,
            TimeSeriesGenerationPolicyUpdate {
                name: new.name,
                raw_event_kind: new.raw_event_kind,
                measure: new.measure,
                group_by: new.group_by,
                group_by_unit: new.group_by_unit,
                counterpart_scope: new.counterpart_scope,
                slot_size: new.slot_size,
                window_size: new.window_size,
                utc_offset: new.utc_offset,
                src_ip: new.src_ip,
                dst_ip: new.dst_ip,
                sensors: new.sensors,
                time_series_type: new.time_series_type,
            }
        );
    }

    #[test]
    fn a_draft_spec_and_name_can_be_updated() {
        let f = setup();
        let id = f.insert("a");
        let old: TimeSeriesGenerationPolicyUpdate = f.policy(id).into();
        let new = TimeSeriesGenerationPolicyUpdate {
            name: "b".to_string(),
            raw_event_kind: RawEventKind::Dns,
            measure: Measure::Count,
            group_by: Some(EndpointRole::Destination),
            group_by_unit: GroupByUnit::Ip,
            counterpart_scope: CounterpartScope::Internal,
            slot_size: SlotSize::OneHour,
            window_size: WindowSize::OneDay,
            utc_offset: 3600,
            src_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_ip: None,
            sensors: vec![OTHER_SENSOR_NAME.to_string(), SENSOR_NAME.to_string()],
            time_series_type: None,
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
            &TimeSeriesGenerationPolicyError::NotFound { id: id + 1 }
        );
    }

    /// A fixed policy refuses a change of any spec field, without running
    /// the spec checks, and its name changes freely, even after its
    /// customer's networks no longer pass them.
    #[test]
    fn a_fixed_spec_cannot_change_but_its_name_can() {
        let f = setup();
        let id = f.insert("a");
        f.table().fix(id).unwrap();
        let old: TimeSeriesGenerationPolicyUpdate = f.policy(id).into();

        let changes: [fn(&mut TimeSeriesGenerationPolicyUpdate); 12] = [
            |u| u.raw_event_kind = RawEventKind::Http,
            |u| u.measure = Measure::Sum(ConnField::OrigBytes),
            |u| u.group_by = None,
            |u| u.group_by_unit = GroupByUnit::OwnedNetwork,
            |u| u.counterpart_scope = CounterpartScope::Internal,
            |u| u.slot_size = SlotSize::FiveMinutes,
            |u| u.window_size = WindowSize::SixHours,
            |u| u.utc_offset = 1,
            |u| u.src_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            |u| u.dst_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            |u| u.sensors = vec![OTHER_SENSOR_NAME.to_string()],
            |u| {
                u.time_series_type = Some(TimeSeriesTypeRef {
                    id: "conn_count".to_string(),
                    version: 1,
                });
            },
        ];
        for change in changes {
            let mut new = old.clone();
            new.name = "renamed".to_string();
            change(&mut new);
            let error = f.table().update(id, &old, &new).unwrap_err();
            assert_eq!(
                policy_error(&error),
                &TimeSeriesGenerationPolicyError::SpecFixed { id }
            );
            assert!(
                format!("{error:#}").contains(&format!(
                    "time series generation policy {id} is fixed; only its name can change"
                )),
                "{error:#}"
            );
            assert_eq!(f.policy(id).name, "a");
        }

        set_networks(&f.store, CUSTOMER, &[NetworkType::Extranet]);
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
        assert_eq!(
            policy_error(&error),
            &TimeSeriesGenerationPolicyError::Draft { id }
        );
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
                .time_series_generation_policies_assigned_to(&f.generator())
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
            TimeSeriesGenerationPolicyError::NotTimeSeriesGenerator { .. }
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
                TimeSeriesGenerationPolicyError::NotTimeSeriesGenerator {
                    node_id: f.node,
                    agent_key: agent_key.to_string(),
                }
            );
        }
        assert_eq!(
            refusal(&instance(f.other_node, GENERATOR)),
            TimeSeriesGenerationPolicyError::CustomerMismatch {
                node_id: f.other_node,
                node_customer_id: Some(OTHER_CUSTOMER),
                customer_id: CUSTOMER,
            }
        );

        // Each list names, first, a sensor that is not the customer's, after
        // any number of the customer's.
        for (sensors, not_a_sensor) in [
            // The second sensor belongs to another customer.
            (vec![SENSOR_NAME, OTHER_SENSOR_NAME], OTHER_SENSOR_NAME),
            (vec![OTHER_SENSOR_NAME, SENSOR_HOST], OTHER_SENSOR_NAME),
            (vec![SENSOR_HOST], SENSOR_HOST),
            (
                vec![SENSOR_NAME, "piglet.generators.example"],
                "piglet.generators.example",
            ),
            (vec!["piglet."], "piglet."),
        ] {
            let draft = f
                .table()
                .insert(NewTimeSeriesGenerationPolicy {
                    sensors: sensors.iter().map(ToString::to_string).collect(),
                    ..new_policy(&format!("draft-{sensors:?}"))
                })
                .unwrap();
            let error = f
                .table()
                .assign(draft, Some(&f.generator()), true)
                .unwrap_err();
            assert_eq!(
                policy_error(&error),
                &TimeSeriesGenerationPolicyError::NotSensorOfCustomer {
                    id: draft,
                    sensor: not_a_sensor.to_string(),
                    customer_id: CUSTOMER,
                }
            );
            assert_eq!(f.policy(draft).state, PolicyState::Draft);
            assert_eq!(f.policy(draft).assignee, None);
        }

        let error = f.table().assign(id, None, true).unwrap_err();
        assert_eq!(
            policy_error(&error),
            &TimeSeriesGenerationPolicyError::FixWithoutAssignee { id }
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
            &TimeSeriesGenerationPolicyError::PolicyInUse(uses.clone())
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
                &TimeSeriesGenerationPolicyError::DataStoreMismatch {
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
                TimeSeriesGenerationPolicyError::DataStoreMismatch { .. }
            ));
        }
        let error = f
            .table()
            .assign(id, Some(&f.generator()), false)
            .unwrap_err();
        assert!(matches!(
            policy_error(&error),
            TimeSeriesGenerationPolicyError::DataStoreMismatch { .. }
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
                .time_series_generation_policies_assigned_to(&f.generator())
                .unwrap(),
            Vec::new()
        );

        f.store.node_map().remove(f.generators).unwrap();
        let policy = f.policy(other);
        assert_eq!(policy.assignee, None);
        assert_eq!(policy.data_store.as_deref(), Some("ds-b"));
    }

    /// An assignment committed while the removal of its generator is in
    /// flight, after the removal found the policies to clear, makes the
    /// removal retry and clear it too.
    #[test]
    fn an_assignment_racing_the_generator_removal_is_cleared() {
        use std::cell::Cell;

        let f = setup();
        let id = f.insert("a");
        f.table().fix(id).unwrap();
        let stored = f.store.node_map().get_by_id(f.node).unwrap().unwrap().0;
        let mut without = stored.clone();
        without.agents.retain(|agent| agent.key != GENERATOR);

        let attempts = Cell::new(0);
        let mut nodes = f.store.node_map();
        nodes.set_before_commit_hook(Some(Box::new(|| {
            attempts.set(attempts.get() + 1);
            if attempts.get() == 1 {
                f.table().assign(id, Some(&f.generator()), false)?;
            }
            Ok(())
        })));
        nodes
            .update(f.node, &stored.into(), &without.into())
            .unwrap();
        drop(nodes);

        assert_eq!(attempts.get(), 2);
        let policy = f.policy(id);
        assert_eq!(policy.assignee, None);
        assert_eq!(policy.data_store.as_deref(), Some("ds-a"));
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
                raw_event_kind: "conn".to_string(),
                log_kind: None,
                sources: vec![source.to_string()],
                indicator: None,
                clustering_model_type: crate::ClusteringModelTypeRef::Custom,
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
            raw_event_kind: "conn".to_string(),
            classification_id: 1,
            batch_info: Vec::new(),
            scores: [(1, 0.5)].into_iter().collect(),
            log_kind: None,
            clustering_model_type: crate::ClusteringModelTypeRef::Custom,
            training_read: crate::TrainingRead::default(),
            detection_model_states: Vec::new(),
        };
        f.store
            .replace_model(
                body,
                ModelOwner {
                    customer_id: CUSTOMER,
                    instance: instance(f.node, ENGINE),
                },
                jiff::Timestamp::now(),
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
        engine.config = Some("revision = 1".to_string().try_into().unwrap());
        engine.draft = Some("revision = 2".to_string().try_into().unwrap());
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

        assert_eq!(
            f.store.time_series_generation_policy_uses(id).unwrap(),
            uses
        );
        assert_eq!(
            f.store.time_series_generation_policy_uses(unused).unwrap(),
            Vec::new()
        );

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
        assert_eq!(
            f.store.time_series_generation_policy_uses(3).unwrap(),
            Vec::new()
        );
        f.table().remove_unused(3).unwrap();
    }

    #[test]
    fn remove_unused_refuses_a_policy_in_use() {
        let f = setup();
        let id = f.assigned("a");
        let uses = use_everywhere(&f, id);

        let error = f.table().remove_unused(id).unwrap_err();
        assert_eq!(
            policy_error(&error),
            &TimeSeriesGenerationPolicyError::PolicyInUse(uses)
        );
        assert!(f.table().get_by_id(id).unwrap().is_some());

        let error = f.table().remove_unused(id + 1).unwrap_err();
        assert_eq!(
            policy_error(&error),
            &TimeSeriesGenerationPolicyError::NotFound { id: id + 1 }
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
            .insert(NewTimeSeriesGenerationPolicy {
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

    /// Test-only time-series types, not part of the shipped catalog.
    const TEST_TYPES: &[TimeSeriesType] = &[
        test_type(
            "test_conn_bytes",
            2,
            RawEventKind::Conn,
            Measure::Sum(ConnField::OrigBytes),
            EndpointRole::Source,
            GroupByUnit::Ip,
            CounterpartScope::External,
        ),
        test_type(
            "test_dns_count",
            1,
            RawEventKind::Dns,
            Measure::Count,
            EndpointRole::Destination,
            GroupByUnit::Ip,
            CounterpartScope::Internal,
        ),
        test_type(
            "test_network_unit",
            1,
            RawEventKind::Conn,
            Measure::Count,
            EndpointRole::Source,
            GroupByUnit::OwnedNetwork,
            CounterpartScope::Any,
        ),
    ];

    const fn test_type(
        id: &'static str,
        version: u32,
        raw_event_kind: RawEventKind,
        measure: Measure,
        group_by: EndpointRole,
        group_by_unit: GroupByUnit,
        counterpart_scope: CounterpartScope,
    ) -> TimeSeriesType {
        TimeSeriesType {
            id,
            version,
            order: 0,
            raw_event_kind,
            method: ModelMethod::Timeseries,
            measure,
            group_by,
            group_by_unit,
            counterpart_scope,
            slot_size: SlotSize::FifteenMinutes,
            window_size: WindowSize::OneDay,
            threat_role: ThreatRole::Actor,
            fixed: &[],
            operator_values: &[],
            detection_models: &[DetectionModel::WindowOutlier],
            ip_columns: &[],
            description_en: "",
            description_ko: "",
        }
    }

    /// A policy of [`CUSTOMER`] made from the test type `test_conn_bytes`,
    /// with every value of the type.
    fn typed_policy(name: &str) -> NewTimeSeriesGenerationPolicy {
        NewTimeSeriesGenerationPolicy {
            measure: Measure::Sum(ConnField::OrigBytes),
            counterpart_scope: CounterpartScope::External,
            window_size: WindowSize::OneDay,
            time_series_type: Some(TimeSeriesTypeRef {
                id: "test_conn_bytes".to_string(),
                version: 2,
            }),
            ..new_policy(name)
        }
    }

    /// Inserts `policy`, checked against [`TEST_TYPES`].
    fn try_insert(f: &Fixture, policy: NewTimeSeriesGenerationPolicy) -> Result<u32> {
        f.table().insert_with_catalog(policy, TEST_TYPES, &0)
    }

    /// Inserts `policy`, checked against [`TEST_TYPES`], asserting that it
    /// is accepted.
    fn accepted(f: &Fixture, policy: NewTimeSeriesGenerationPolicy) {
        let name = policy.name.clone();
        let id = try_insert(f, policy).unwrap_or_else(|e| panic!("{name}: {e:#}"));
        assert_eq!(f.policy(id).name, name);
    }

    /// Inserts `policy`, checked against [`TEST_TYPES`], asserting that it is
    /// refused with a spec error and nothing is written, and returns the
    /// error.
    fn refused(
        f: &Fixture,
        policy: NewTimeSeriesGenerationPolicy,
    ) -> TimeSeriesGenerationPolicyError {
        let before = f.table().count().unwrap();
        let error = try_insert(f, policy).unwrap_err();
        assert_eq!(f.table().count().unwrap(), before);
        policy_error(&error).clone()
    }

    /// A custom policy `name` changed by `change`.
    fn custom(
        name: &str,
        change: impl FnOnce(&mut NewTimeSeriesGenerationPolicy),
    ) -> NewTimeSeriesGenerationPolicy {
        let mut policy = new_policy(name);
        change(&mut policy);
        policy
    }

    /// A policy `name` made from `test_conn_bytes` changed by `change`.
    fn typed(
        name: &str,
        change: impl FnOnce(&mut NewTimeSeriesGenerationPolicy),
    ) -> NewTimeSeriesGenerationPolicy {
        let mut policy = typed_policy(name);
        change(&mut policy);
        policy
    }

    #[test]
    fn only_network_raw_event_kinds_are_accepted() {
        let f = setup();
        for kind in NETWORK_RAW_EVENT_KINDS {
            accepted(
                &f,
                custom(&format!("{kind:?}"), |p| p.raw_event_kind = kind),
            );
        }
        for kind in [
            RawEventKind::ProcessCreate,
            RawEventKind::Netflow5,
            RawEventKind::Netflow9,
            RawEventKind::FileCreate,
        ] {
            assert_eq!(
                refused(&f, custom("refused", |p| p.raw_event_kind = kind)),
                TimeSeriesGenerationPolicyError::UnsupportedRawEventKind {
                    raw_event_kind: kind
                }
            );
        }
    }

    #[test]
    fn a_sum_requires_conn() {
        let f = setup();
        accepted(
            &f,
            custom("conn-sum", |p| {
                p.measure = Measure::Sum(ConnField::Duration);
            }),
        );
        assert_eq!(
            refused(
                &f,
                custom("dns-sum", |p| {
                    p.raw_event_kind = RawEventKind::Dns;
                    p.measure = Measure::Sum(ConnField::OrigPkts);
                })
            ),
            TimeSeriesGenerationPolicyError::SumRequiresConn {
                raw_event_kind: RawEventKind::Dns
            }
        );
        accepted(
            &f,
            custom("dns-count", |p| p.raw_event_kind = RawEventKind::Dns),
        );
    }

    #[test]
    fn the_utc_offset_is_a_whole_hour_from_minus_12_to_plus_14() {
        let f = setup();
        for utc_offset in [-43_200, -3600, 0, 3600, 32_400, 50_400] {
            accepted(
                &f,
                custom(&format!("offset{utc_offset}"), |p| {
                    p.utc_offset = utc_offset;
                }),
            );
        }
        for utc_offset in [50_401, 1800, -1800, 54_000, -46_800, 1, i32::MIN, i32::MAX] {
            assert_eq!(
                refused(&f, custom("refused", |p| p.utc_offset = utc_offset)),
                TimeSeriesGenerationPolicyError::InvalidUtcOffset { utc_offset }
            );
        }
    }

    #[test]
    fn sensors_are_distinct_non_empty_names() {
        let f = setup();
        for sensors in [
            Vec::new(),
            vec![String::new()],
            vec![SENSOR_NAME.to_string(), String::new()],
            vec![SENSOR_NAME.to_string(), SENSOR_NAME.to_string()],
            vec![
                SENSOR_NAME.to_string(),
                OTHER_SENSOR_NAME.to_string(),
                SENSOR_NAME.to_string(),
            ],
        ] {
            assert_eq!(
                refused(&f, custom("refused", |p| p.sensors = sensors.clone())),
                TimeSeriesGenerationPolicyError::InvalidSensors,
                "{sensors:?}"
            );
        }
        // Whether a sensor is the customer's is checked at assignment only.
        accepted(
            &f,
            custom("two-sensors", |p| {
                p.sensors = vec![SENSOR_NAME.to_string(), OTHER_SENSOR_NAME.to_string()];
            }),
        );
    }

    #[test]
    fn an_ungrouped_policy_counts_every_counterpart_by_ip() {
        let f = setup();
        accepted(&f, custom("ungrouped", |p| p.group_by = None));
        for scope in [CounterpartScope::Internal, CounterpartScope::External] {
            assert_eq!(
                refused(
                    &f,
                    custom("refused", |p| {
                        p.group_by = None;
                        p.counterpart_scope = scope;
                    })
                ),
                TimeSeriesGenerationPolicyError::UngroupedScope
            );
        }
        assert_eq!(
            refused(
                &f,
                custom("refused", |p| {
                    p.group_by = None;
                    p.group_by_unit = GroupByUnit::OwnedNetwork;
                })
            ),
            TimeSeriesGenerationPolicyError::UngroupedScope
        );
        for scope in [CounterpartScope::Internal, CounterpartScope::External] {
            accepted(
                &f,
                custom(&format!("grouped-{scope:?}"), |p| {
                    p.counterpart_scope = scope;
                }),
            );
        }
    }

    #[test]
    fn the_owned_network_unit_is_not_supported() {
        let f = setup();
        assert_eq!(
            refused(
                &f,
                custom("refused", |p| p.group_by_unit = GroupByUnit::OwnedNetwork)
            ),
            TimeSeriesGenerationPolicyError::NetworkUnitNotSupported
        );
        // The check comes before the type is looked up.
        assert_eq!(
            refused(
                &f,
                custom("refused", |p| {
                    p.group_by_unit = GroupByUnit::OwnedNetwork;
                    p.time_series_type = Some(TimeSeriesTypeRef {
                        id: "test_network_unit".to_string(),
                        version: 1,
                    });
                })
            ),
            TimeSeriesGenerationPolicyError::NetworkUnitNotSupported
        );
    }

    #[test]
    fn a_custom_policy_cannot_filter_by_the_ip_it_groups_by() {
        let f = setup();
        let ip = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        for (group_by, src_ip, dst_ip) in [
            (EndpointRole::Source, ip, None),
            (EndpointRole::Source, ip, ip),
            (EndpointRole::Destination, None, ip),
            (EndpointRole::Destination, ip, ip),
        ] {
            assert_eq!(
                refused(
                    &f,
                    custom("refused", |p| {
                        p.group_by = Some(group_by);
                        p.src_ip = src_ip;
                        p.dst_ip = dst_ip;
                    })
                ),
                TimeSeriesGenerationPolicyError::SameRoleAddressFilter { group_by }
            );
        }
        accepted(
            &f,
            custom("source-dst-filter", |p| {
                p.group_by = Some(EndpointRole::Source);
                p.dst_ip = ip;
            }),
        );
        accepted(
            &f,
            custom("destination-src-filter", |p| {
                p.group_by = Some(EndpointRole::Destination);
                p.src_ip = ip;
            }),
        );
        accepted(
            &f,
            custom("ungrouped-filters", |p| {
                p.group_by = None;
                p.src_ip = ip;
                p.dst_ip = ip;
            }),
        );
    }

    #[test]
    fn a_type_policy_names_a_catalog_type_at_its_version() {
        let f = setup();
        accepted(&f, typed_policy("typed"));
        for (id, version) in [
            ("unknown_type", 2),
            ("test_conn_bytes", 1),
            ("test_conn_bytes", 3),
        ] {
            assert_eq!(
                refused(
                    &f,
                    typed("refused", |p| {
                        p.time_series_type = Some(TimeSeriesTypeRef {
                            id: id.to_string(),
                            version,
                        });
                    })
                ),
                TimeSeriesGenerationPolicyError::UnknownTimeSeriesType {
                    id: id.to_string(),
                    version
                }
            );
        }
        // `insert` checks against the shipped catalog, which has no
        // `test_conn_bytes`.
        let error = f.table().insert(typed_policy("shipped")).unwrap_err();
        assert_eq!(
            policy_error(&error),
            &TimeSeriesGenerationPolicyError::UnknownTimeSeriesType {
                id: "test_conn_bytes".to_string(),
                version: 2
            }
        );
    }

    #[test]
    fn a_policy_of_each_shipped_type_passes_every_save_check() {
        let f = setup();
        assert_eq!(time_series_types().len(), 12);
        for t in time_series_types() {
            let policy = NewTimeSeriesGenerationPolicy {
                name: t.id.to_string(),
                raw_event_kind: t.raw_event_kind,
                measure: t.measure,
                group_by: Some(t.group_by),
                group_by_unit: t.group_by_unit,
                counterpart_scope: t.counterpart_scope,
                slot_size: t.slot_size,
                window_size: t.window_size,
                utc_offset: 0,
                src_ip: None,
                dst_ip: None,
                sensors: vec![SENSOR_NAME.to_string()],
                time_series_type: Some(TimeSeriesTypeRef {
                    id: t.id.to_string(),
                    version: t.version,
                }),
                customer_id: CUSTOMER,
            };
            let id = f
                .table()
                .insert(policy)
                .unwrap_or_else(|e| panic!("{}: {e:#}", t.id));
            assert_eq!(f.policy(id).name, t.id);
        }
    }

    #[test]
    // Every field a type fixes is checked in turn; splitting the test would
    // only scatter the order the comparison follows.
    #[allow(clippy::too_many_lines)]
    fn a_type_policy_has_the_type_values() {
        let f = setup();
        let mismatch = |field| TimeSeriesGenerationPolicyError::TypeMismatch { field };
        let dns_type = Some(TimeSeriesTypeRef {
            id: "test_dns_count".to_string(),
            version: 1,
        });
        // `test_dns_count` counts Dns, so a Count policy of another kind
        // reaches the type comparison.
        assert_eq!(
            refused(
                &f,
                custom("refused", |p| {
                    p.raw_event_kind = RawEventKind::Http;
                    p.group_by = Some(EndpointRole::Destination);
                    p.counterpart_scope = CounterpartScope::Internal;
                    p.window_size = WindowSize::OneDay;
                    p.time_series_type.clone_from(&dns_type);
                })
            ),
            mismatch("raw_event_kind")
        );
        assert_eq!(
            refused(&f, typed("refused", |p| p.measure = Measure::Count)),
            mismatch("measure")
        );
        assert_eq!(
            refused(
                &f,
                typed("refused", |p| p.measure =
                    Measure::Sum(ConnField::RespBytes))
            ),
            mismatch("measure")
        );
        assert_eq!(
            refused(
                &f,
                typed("refused", |p| p.group_by = Some(EndpointRole::Destination))
            ),
            mismatch("group_by")
        );
        // An ungrouped policy counts every counterpart, which a type that
        // filters them does not.
        assert_eq!(
            refused(
                &f,
                custom("refused", |p| {
                    p.group_by = None;
                    p.time_series_type = Some(TimeSeriesTypeRef {
                        id: "test_network_unit".to_string(),
                        version: 1,
                    });
                })
            ),
            mismatch("group_by")
        );
        assert_eq!(
            refused(
                &f,
                custom("refused", |p| {
                    p.time_series_type = Some(TimeSeriesTypeRef {
                        id: "test_network_unit".to_string(),
                        version: 1,
                    });
                    p.window_size = WindowSize::OneDay;
                })
            ),
            mismatch("group_by_unit")
        );
        assert_eq!(
            refused(
                &f,
                typed("refused", |p| p.counterpart_scope = CounterpartScope::Any)
            ),
            mismatch("counterpart_scope")
        );
        assert_eq!(
            refused(&f, typed("refused", |p| p.slot_size = SlotSize::OneHour)),
            mismatch("slot_size")
        );
        assert_eq!(
            refused(
                &f,
                typed("refused", |p| p.window_size = WindowSize::SixHours)
            ),
            mismatch("window_size")
        );
        // The first field that differs is named.
        assert_eq!(
            refused(
                &f,
                typed("refused", |p| {
                    p.measure = Measure::Count;
                    p.slot_size = SlotSize::OneHour;
                    p.window_size = WindowSize::SixHours;
                })
            ),
            mismatch("measure")
        );
        assert_eq!(
            refused(
                &f,
                typed("refused", |p| {
                    p.counterpart_scope = CounterpartScope::Any;
                    p.window_size = WindowSize::SixHours;
                })
            ),
            mismatch("counterpart_scope")
        );
        // The operator values are the policy's own.
        accepted(
            &f,
            typed("typed-operator-values", |p| {
                p.utc_offset = 32_400;
                p.sensors = vec![OTHER_SENSOR_NAME.to_string(), SENSOR_NAME.to_string()];
            }),
        );
        accepted(
            &f,
            custom("typed-dns", |p| {
                p.raw_event_kind = RawEventKind::Dns;
                p.group_by = Some(EndpointRole::Destination);
                p.counterpart_scope = CounterpartScope::Internal;
                p.window_size = WindowSize::OneDay;
                p.time_series_type = dns_type;
            }),
        );
    }

    #[test]
    fn a_type_policy_cannot_filter_by_ip() {
        let f = setup();
        let ip = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        for (src_ip, dst_ip) in [(ip, None), (None, ip), (ip, ip)] {
            assert_eq!(
                refused(
                    &f,
                    typed("refused", |p| {
                        p.src_ip = src_ip;
                        p.dst_ip = dst_ip;
                    })
                ),
                TimeSeriesGenerationPolicyError::AddressFilterWithType
            );
        }
    }

    #[test]
    fn a_grouped_policy_needs_an_internal_network() {
        let f = setup();
        let of_customer = |name: &str, group_by| {
            custom(name, |p| {
                p.customer_id = NETWORK_CUSTOMER;
                p.group_by = group_by;
            })
        };
        let no_internal = TimeSeriesGenerationPolicyError::NoInternalNetwork {
            customer_id: NETWORK_CUSTOMER,
        };

        // No networks stored at all.
        assert_eq!(
            refused(&f, of_customer("refused", Some(EndpointRole::Source))),
            no_internal
        );
        for types in [
            Vec::new(),
            vec![NetworkType::Extranet],
            vec![NetworkType::Extranet, NetworkType::Extranet],
        ] {
            set_networks(&f.store, NETWORK_CUSTOMER, &types);
            for group_by in [EndpointRole::Source, EndpointRole::Destination] {
                assert_eq!(
                    refused(&f, of_customer("refused", Some(group_by))),
                    no_internal,
                    "{types:?}"
                );
            }
        }
        // An ungrouped policy splits by no IP.
        accepted(&f, of_customer("ungrouped", None));
        // A type policy groups too.
        assert_eq!(
            refused(&f, typed("refused", |p| p.customer_id = NETWORK_CUSTOMER)),
            no_internal
        );

        for types in [
            vec![NetworkType::Intranet],
            vec![NetworkType::Gateway],
            vec![NetworkType::Extranet, NetworkType::Gateway],
        ] {
            set_networks(&f.store, NETWORK_CUSTOMER, &types);
            accepted(
                &f,
                of_customer(&format!("grouped-{types:?}"), Some(EndpointRole::Source)),
            );
        }
    }

    /// The customer's internal addresses are decided by the narrowest owned
    /// network, so an Intranet network an Extranet network matches leaves
    /// nothing to group by.
    #[test]
    fn a_grouped_policy_needs_an_internal_address() {
        let f = setup();
        let replace = |networks: &[(NetworkType, &[&str])]| {
            let table = f.store.customer_networks_map();
            let revision = table
                .get(NETWORK_CUSTOMER)
                .unwrap()
                .map_or(0, |set| set.revision + 1);
            let networks = networks
                .iter()
                .zip(1_u8..)
                .map(|((network_type, cidrs), n)| OwnedNetwork {
                    name: format!("network-{n}"),
                    network_type: *network_type,
                    group: HostNetworkGroup::new(
                        Vec::new(),
                        cidrs.iter().map(|cidr| cidr.parse().unwrap()).collect(),
                        Vec::new(),
                    ),
                })
                .collect();
            table.replace(NETWORK_CUSTOMER, revision, networks).unwrap();
        };
        let grouped = |name: &str| {
            custom(name, |p| {
                p.customer_id = NETWORK_CUSTOMER;
                p.group_by = Some(EndpointRole::Source);
            })
        };
        let no_internal = TimeSeriesGenerationPolicyError::NoInternalNetwork {
            customer_id: NETWORK_CUSTOMER,
        };

        for networks in [
            // The only Intranet entry is also an Extranet one.
            &[
                (NetworkType::Intranet, &["10.1.0.0/16"][..]),
                (NetworkType::Extranet, &["10.1.0.0/16", "192.0.2.0/24"][..]),
            ][..],
            // An Intranet network with no entries.
            &[
                (NetworkType::Intranet, &[][..]),
                (NetworkType::Extranet, &["10.1.0.0/16"][..]),
            ][..],
        ] {
            replace(networks);
            assert_eq!(refused(&f, grouped("refused")), no_internal, "{networks:?}");
        }

        replace(&[
            (NetworkType::Intranet, &["10.0.0.0/8"]),
            (NetworkType::Extranet, &["10.200.0.0/16"]),
        ]);
        accepted(&f, grouped("grouped"));
    }

    /// A policy that breaks several requirements is refused for the
    /// lowest-numbered one; fixing that one reveals the next.
    #[test]
    fn the_first_failing_check_is_reported() {
        use TimeSeriesGenerationPolicyError as E;
        type Fix = fn(&mut NewTimeSeriesGenerationPolicy);

        let f = setup();
        set_networks(&f.store, NETWORK_CUSTOMER, &[NetworkType::Extranet]);
        let ip = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let mut policy = new_policy("broken");
        policy.raw_event_kind = RawEventKind::ProcessCreate;
        policy.measure = Measure::Sum(ConnField::OrigBytes);
        policy.utc_offset = 1800;
        policy.sensors = Vec::new();
        policy.group_by = None;
        policy.counterpart_scope = CounterpartScope::Internal;
        policy.group_by_unit = GroupByUnit::OwnedNetwork;
        policy.src_ip = ip;
        policy.customer_id = NETWORK_CUSTOMER;

        let steps: [(E, Fix); 6] = [
            (
                E::UnsupportedRawEventKind {
                    raw_event_kind: RawEventKind::ProcessCreate,
                },
                |p| p.raw_event_kind = RawEventKind::Dns,
            ),
            (
                E::SumRequiresConn {
                    raw_event_kind: RawEventKind::Dns,
                },
                |p| p.raw_event_kind = RawEventKind::Conn,
            ),
            (E::InvalidUtcOffset { utc_offset: 1800 }, |p| {
                p.utc_offset = 3600;
            }),
            (E::InvalidSensors, |p| {
                p.sensors = vec![SENSOR_NAME.to_string()];
            }),
            (E::UngroupedScope, |p| {
                p.group_by = Some(EndpointRole::Source);
            }),
            (E::NetworkUnitNotSupported, |p| {
                p.group_by_unit = GroupByUnit::Ip;
            }),
        ];
        for (expected, fix) in steps {
            assert_eq!(refused(&f, policy.clone()), expected);
            fix(&mut policy);
        }
        assert_eq!(
            refused(&f, policy.clone()),
            E::SameRoleAddressFilter {
                group_by: EndpointRole::Source
            }
        );
        policy.src_ip = None;
        assert_eq!(
            refused(&f, policy.clone()),
            E::NoInternalNetwork {
                customer_id: NETWORK_CUSTOMER
            }
        );

        // With a type, the type checks come before the network check, in
        // their order.
        let mut policy = typed("broken-typed", |p| {
            p.customer_id = NETWORK_CUSTOMER;
            p.measure = Measure::Count;
            p.src_ip = ip;
            p.time_series_type = Some(TimeSeriesTypeRef {
                id: "test_conn_bytes".to_string(),
                version: 1,
            });
        });
        assert_eq!(
            refused(&f, policy.clone()),
            E::UnknownTimeSeriesType {
                id: "test_conn_bytes".to_string(),
                version: 1
            }
        );
        policy.time_series_type = typed_policy("").time_series_type;
        assert_eq!(
            refused(&f, policy.clone()),
            E::TypeMismatch { field: "measure" }
        );
        policy.measure = Measure::Sum(ConnField::OrigBytes);
        assert_eq!(refused(&f, policy.clone()), E::AddressFilterWithType);
        policy.src_ip = None;
        assert_eq!(
            refused(&f, policy.clone()),
            E::NoInternalNetwork {
                customer_id: NETWORK_CUSTOMER
            }
        );
        set_networks(&f.store, NETWORK_CUSTOMER, &[NetworkType::Gateway]);
        accepted(&f, policy);
    }

    /// A draft update runs the spec checks of an insert, against the stored
    /// policy's customer, and a refused one changes nothing.
    #[test]
    // One refusal per spec check, then the accepted updates, on one draft.
    #[allow(clippy::too_many_lines)]
    fn a_draft_update_runs_the_spec_checks() {
        use TimeSeriesGenerationPolicyError as E;
        type Change = fn(&mut TimeSeriesGenerationPolicyUpdate);

        let f = setup();
        let id = f.insert("a");
        let old: TimeSeriesGenerationPolicyUpdate = f.policy(id).into();
        let stored = f.policy(id);
        let update = |new: &TimeSeriesGenerationPolicyUpdate| {
            f.table().update_with_catalog(id, &old, new, TEST_TYPES, &0)
        };
        let ip = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let type_ref = typed_policy("").time_series_type;

        let refusals: [(Change, E); 10] = [
            (
                |u| u.raw_event_kind = RawEventKind::Netflow5,
                E::UnsupportedRawEventKind {
                    raw_event_kind: RawEventKind::Netflow5,
                },
            ),
            (
                |u| {
                    u.raw_event_kind = RawEventKind::Dns;
                    u.measure = Measure::Sum(ConnField::Duration);
                },
                E::SumRequiresConn {
                    raw_event_kind: RawEventKind::Dns,
                },
            ),
            (
                |u| u.utc_offset = 50_401,
                E::InvalidUtcOffset { utc_offset: 50_401 },
            ),
            (|u| u.sensors = Vec::new(), E::InvalidSensors),
            (
                |u| {
                    u.group_by = None;
                    u.counterpart_scope = CounterpartScope::Internal;
                },
                E::UngroupedScope,
            ),
            (
                |u| u.group_by_unit = GroupByUnit::OwnedNetwork,
                E::NetworkUnitNotSupported,
            ),
            (
                |u| u.src_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                E::SameRoleAddressFilter {
                    group_by: EndpointRole::Source,
                },
            ),
            (
                |u| {
                    u.time_series_type = Some(TimeSeriesTypeRef {
                        id: "unknown_type".to_string(),
                        version: 1,
                    });
                },
                E::UnknownTimeSeriesType {
                    id: "unknown_type".to_string(),
                    version: 1,
                },
            ),
            (
                |u| {
                    u.time_series_type = Some(TimeSeriesTypeRef {
                        id: "test_conn_bytes".to_string(),
                        version: 2,
                    });
                },
                E::TypeMismatch { field: "measure" },
            ),
            (
                |u| {
                    u.measure = Measure::Sum(ConnField::OrigBytes);
                    u.counterpart_scope = CounterpartScope::External;
                    u.window_size = WindowSize::OneDay;
                    u.dst_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
                    u.time_series_type = Some(TimeSeriesTypeRef {
                        id: "test_conn_bytes".to_string(),
                        version: 2,
                    });
                },
                E::AddressFilterWithType,
            ),
        ];
        for (change, expected) in refusals {
            let mut new = old.clone();
            new.name = "renamed".to_string();
            change(&mut new);
            let error = update(&new).unwrap_err();
            assert_eq!(policy_error(&error), &expected, "{new:?}");
            assert_eq!(f.policy(id), stored);
        }

        // The customer's networks are read as the draft is updated.
        set_networks(&f.store, CUSTOMER, &[NetworkType::Extranet]);
        let mut renamed = old.clone();
        renamed.name = "renamed".to_string();
        let error = update(&renamed).unwrap_err();
        assert_eq!(
            policy_error(&error),
            &E::NoInternalNetwork {
                customer_id: CUSTOMER
            }
        );
        assert_eq!(f.policy(id), stored);
        let ungrouped = TimeSeriesGenerationPolicyUpdate {
            group_by: None,
            dst_ip: ip,
            src_ip: ip,
            ..renamed.clone()
        };
        update(&ungrouped).unwrap();
        assert!(ungrouped.verify(&f.policy(id)));

        // A type policy that matches its type is accepted.
        set_networks(&f.store, CUSTOMER, &[NetworkType::Gateway]);
        let typed_update = TimeSeriesGenerationPolicyUpdate {
            name: "typed".to_string(),
            measure: Measure::Sum(ConnField::OrigBytes),
            group_by: Some(EndpointRole::Source),
            counterpart_scope: CounterpartScope::External,
            window_size: WindowSize::OneDay,
            src_ip: None,
            dst_ip: None,
            time_series_type: type_ref,
            ..ungrouped.clone()
        };
        f.table()
            .update_with_catalog(id, &ungrouped, &typed_update, TEST_TYPES, &0)
            .unwrap();
        let policy = f.policy(id);
        assert!(typed_update.verify(&policy));
        assert_eq!(policy.state, PolicyState::Draft);
    }

    /// An unknown ID, and a stored policy that is not `old`, are refused
    /// before the spec checks.
    #[test]
    fn an_update_refuses_an_unknown_or_changed_policy_before_the_checks() {
        let f = setup();
        let id = f.insert("a");
        let old: TimeSeriesGenerationPolicyUpdate = f.policy(id).into();
        let invalid = TimeSeriesGenerationPolicyUpdate {
            raw_event_kind: RawEventKind::Netflow5,
            ..old.clone()
        };

        let error = f.table().update(id + 1, &old, &invalid).unwrap_err();
        assert!(
            error
                .downcast_ref::<TimeSeriesGenerationPolicyError>()
                .is_none(),
            "{error:#}"
        );

        let stale = TimeSeriesGenerationPolicyUpdate {
            utc_offset: 3600,
            ..old.clone()
        };
        let error = f.table().update(id, &stale, &invalid).unwrap_err();
        assert!(
            error
                .downcast_ref::<TimeSeriesGenerationPolicyError>()
                .is_none(),
            "{error:#}"
        );
        assert_eq!(f.policy(id).raw_event_kind, RawEventKind::Conn);
    }

    /// The existing name refusals stay: an empty name, and another policy's
    /// name, are refused on insert and update.
    #[test]
    fn empty_and_duplicate_names_are_refused() {
        let f = setup();
        let id = f.insert("a");
        f.insert("b");
        assert!(f.table().insert(new_policy("")).is_err());
        assert!(f.table().insert(new_policy("a")).is_err());
        assert_eq!(f.table().count().unwrap(), 2);

        let old: TimeSeriesGenerationPolicyUpdate = f.policy(id).into();
        for name in ["", "b"] {
            let new = TimeSeriesGenerationPolicyUpdate {
                name: name.to_string(),
                ..old.clone()
            };
            assert!(f.table().update(id, &old, &new).is_err());
            assert_eq!(f.policy(id).name, "a");
        }
    }
}
