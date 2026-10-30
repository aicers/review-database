mod agent;
mod backup_config;
mod batch_info;
mod category;
mod cluster;
mod column_stats;
mod config;
mod core_component;
mod csv_column_extra;
mod customer_data_deletion_job;
mod engine_instance;
mod external_service;
mod hosts;
mod instance_allocation;
mod label_db;
mod lifecycle;
mod model;
mod model_indicator;
mod model_run;
mod network;
mod network_list;
mod node;
mod operation_attempt;
mod outlier_info;
mod owned_network;
mod port_allocation;
mod previous_training;
mod qualifier;
mod retention_config;
mod sampling_policy;
mod scores;
mod status;
mod system_log_collector;
mod template;
mod time_series;
mod tor_exit_node;
mod traffic_filter;
mod training_definition;
mod triage_policy;
mod triage_response;
mod trusted_domain;
mod trusted_user_agent;

use std::{
    collections::BTreeSet,
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, PoisonError},
};

use anyhow::{Result, anyhow};
use rocksdb::Direction;
use serde::{Deserialize, Serialize};

pub(crate) use self::agent::sensor_hostname;
pub use self::agent::{Agent, AgentKind};
pub use self::backup_config::{BackupConfig, BackupConfigUpdate};
pub use self::cluster::Cluster;
pub use self::column_stats::{ColumnStats, TopColumnsOfCluster, TopMultimaps};
pub use self::config::{
    KEY_BACKUP_DURATION, KEY_BACKUP_TIME, KEY_EVENT_RETENTION_PERIOD_DAYS,
    KEY_NUM_OF_BACKUPS_TO_KEEP, KEY_RETENTION_PERIOD,
};
pub use self::core_component::CoreComponent;
pub use self::csv_column_extra::CsvColumnExtra;
pub(crate) use self::customer_data_deletion_job::StoredCustomerDataDeletionJob;
pub use self::customer_data_deletion_job::{
    CustomerDataDeletionJob, CustomerDataDeletionService, CustomerDataDeletionServiceResult,
    CustomerDataDeletionStatus,
};
pub(crate) use self::engine_instance::{
    DetectorIdMarks, EngineInstances, Row as EngineInstanceRow, key as engine_instance_key,
    lookup_key as agent_lookup_key,
};
pub use self::engine_instance::{
    DetectorSourceStatus, DetectorState, DetectorStatus, EngineDetectorRef, EngineDocumentError,
    EngineDocumentRefs, EngineDocumentWrite, EngineInstanceState, ModelUse, RoundOutcome,
    SourceState,
};
pub use self::external_service::{ExternalService, ExternalServiceKind};
pub use self::hosts::{Host, UserAgent};
pub use self::instance_allocation::{InstanceAllocation, InstanceAllocationError};
pub use self::label_db::{
    Kind as LabelDbKind, LabelDb, Rule as LabelDbRule, RuleKind as LabelDbRuleKind,
};
pub use self::lifecycle::Lifecycle;
pub use self::model::{
    Model, ModelInstance, ModelOwner, PreviousTraining, ReplacedModel, TrainedWith,
};
pub use self::model_indicator::ModelIndicator;
pub(crate) use self::model_run::ModelRuns;
pub use self::model_run::{ModelRun, ReportedRunState, RunId, RunKind, RunState};
pub use self::network::{Network, Update as NetworkUpdate};
pub use self::network_list::{
    NetworkListEntry, NetworkListReplaceOutcome, NetworkListSet, NetworkListTable,
};
pub(crate) use self::node::Inner as InnerNode;
pub use self::node::{
    Config as AgentConfig, Config as ExternalServiceConfig, Node, Profile as NodeProfile,
    Status as AgentStatus, Status as ExternalServiceStatus, Table as NodeTable,
    Update as NodeUpdate,
};
pub use self::operation_attempt::{
    Action as OperationAction, AddressAllocationError, BuildSelector,
    CleanupState as OperationCleanupState, FailureKind as OperationFailureKind, InstallIntent,
    OnFailure as OperationOnFailure, OperationAttempt, Outcome as OperationOutcome,
    Phase as OperationPhase, RequestKeyError, RetentionBound as OperationRetentionBound,
    RetryPolicy as OperationRetryPolicy,
};
pub use self::outlier_info::{Key as OutlierInfoKey, OutlierInfo, Value as OutlierInfoValue};
pub use self::owned_network::{OwnedNetwork, OwnedNetworkSet, OwnedNetworkTable, ReplaceOutcome};
pub use self::port_allocation::{
    ListenerBinding, PortAllocation, PortAllocationError, PortOwner, Transport as ListenerTransport,
};
pub use self::previous_training::PreviousTrainingResults;
pub use self::retention_config::{RetentionConfig, RetentionConfigUpdate};
pub use self::sampling_policy::{
    Interval as SamplingInterval, Kind as SamplingKind, NewSamplingPolicy,
    Period as SamplingPeriod, PolicyState, PolicyUse, SamplingPolicy, SamplingPolicyError,
    Update as SamplingPolicyUpdate,
};
pub use self::system_log_collector::{
    SystemInstallRecord, SystemLogCollector, SystemLogCollectorRefusal, SystemLogCollectorTable,
};
pub use self::template::{
    Structured, StructuredClusteringAlgorithm, Template, Unstructured,
    UnstructuredClusteringAlgorithm,
};
pub use self::time_series::{Cluster as ClusterTimeSeries, Column as ColumnTimeSeries, TimeSeries};
pub use self::tor_exit_node::TorExitNode;
pub use self::traffic_filter::{ProtocolPorts, TrafficFilter};
pub(crate) use self::training_definition::TrainingDefinitions;
pub use self::training_definition::{
    ModelMethod, NewTrainingDefinition, TrainingDefinition, TrainingDefinitionUpdate,
};
pub use self::triage_policy::{
    AttrCmpKind, Confidence, ExclusionReason, NetworkFilter, PacketAttr, Response, ResponseKind,
    TriageExclusion, TriagePolicyInput, ValueKind,
};
pub use self::triage_response::{TriageResponse, Update as TriageResponseUpdate};
pub use self::trusted_domain::TrustedDomain;
pub use self::trusted_user_agent::TrustedUserAgent;
use super::{IndexedMap, Map, event};
use crate::{
    Indexable, IndexedMapUpdate,
    batch_info::BatchInfo,
    category::Category,
    collections::{Indexed, IndexedSet},
    migration::DATABASE_FORMAT_VERSION,
    scores::Scores,
    types::{FromKeyValue, Qualifier, Status},
};

// Key-value map names in `Database`.
pub(super) const ACCESS_TOKENS: &str = "access_tokens";
pub(super) const ACCOUNTS: &str = "accounts";
pub(super) const AGENTS: &str = "agents";
pub(super) const ALLOW_NETWORKS: &str = "allow networks";
pub(super) const BATCH_INFO: &str = "batch_info";
pub(super) const BLOCK_NETWORKS: &str = "block networks";
pub(super) const CATEGORY: &str = "category";
pub(super) const CLUSTER: &str = "cluster";
pub(super) const COLUMN_STATS: &str = "column stats";
pub(super) const CONFIGS: &str = "configs";
pub(super) const CORE_COMPONENTS: &str = "core components";
pub(super) const CSV_COLUMN_EXTRAS: &str = "csv column extras";
pub(crate) const CUSTOMERS: &str = "customers";
pub(super) const CUSTOMER_DELETION_JOBS: &str = "customer deletion jobs";
pub(super) const CUSTOMER_NETWORKS: &str = "customer networks";
pub(super) const DATA_SOURCES: &str = "data sources";
pub(super) const DETECTOR_ID_MARKS: &str = "detector id marks";
pub(super) const ENGINE_INSTANCES: &str = "engine instances";
pub(super) const FILTERS: &str = "filters";
/// An empty column family that exists only so that `check_backup_format` can
/// tell a 0.61 backup from an older one.
///
/// The 0.61 format changes row layouts and no family otherwise, and an online
/// restore recognizes a backup's format by its column families alone. Nothing
/// reads or writes rows in it.
pub(super) const FORMAT_0_61: &str = "format 0.61";
pub(super) const HOSTS: &str = "hosts";
pub(super) const INSTANCE_ALLOCATIONS: &str = "instance allocations";
pub(super) const MODELS: &str = "models";
pub(super) const MODEL_INDICATORS: &str = "model indicators";
pub(crate) const META: &str = "meta";
pub(super) const MODEL_RUNS: &str = "model runs";
pub(super) const NETWORK_LISTS: &str = "network lists";
pub(super) const SYSTEM_LOG_COLLECTORS: &str = "system log collectors";
pub(super) const NETWORKS: &str = "networks";
pub(super) const NODES: &str = "nodes";
pub(super) const OPERATION_ATTEMPTS: &str = "operation attempts";
/// The column family holding the `operation_attempt` latest pointer.
pub(super) const OPERATION_ATTEMPT_LATEST: &str = "operation attempt latest";
pub(super) const OUTLIERS: &str = "outliers";
// The three column families of the port allocation table. They are one table
// and are registered together — a primary without an index would let a row be
// written that neither of its readers can find.
pub(super) const PORT_ALLOCATIONS: &str = "port allocations";
pub(super) const PORT_ALLOCATIONS_BY_ATTEMPT: &str = "port allocations by attempt";
pub(super) const PORT_ALLOCATIONS_BY_INSTANCE: &str = "port allocations by instance";
// The previous training result of each model: one mirror of each per-model
// column family a replace moves rows out of, with the same row layout.
pub(super) const PREVIOUS_BATCH_INFO: &str = "previous batch_info";
pub(super) const PREVIOUS_CLUSTER: &str = "previous cluster";
pub(super) const PREVIOUS_COLUMN_STATS: &str = "previous column stats";
pub(super) const PREVIOUS_CSV_COLUMN_EXTRAS: &str = "previous csv column extras";
pub(super) const PREVIOUS_OUTLIERS: &str = "previous outliers";
pub(super) const PREVIOUS_SCORES: &str = "previous scores";
pub(super) const PREVIOUS_TIME_SERIES: &str = "previous time series";
pub(super) const QUALIFIERS: &str = "qualifiers";
pub(super) const EXTERNAL_SERVICES: &str = "external services";
pub(super) const SAMPLING_POLICY: &str = "sampling policy";
pub(super) const SCORES: &str = "scores";
pub(super) const STATUSES: &str = "statuses";
pub(super) const TEMPLATES: &str = "templates";
pub(super) const LABEL_DB: &str = "label database";
pub(super) const TIME_SERIES: &str = "time series";
pub(super) const TOR_EXIT_NODES: &str = "Tor exit nodes";
pub(super) const TRAFFIC_FILTER_RULES: &str = "traffic filter rules";
pub(super) const TRAINING_DEFINITIONS: &str = "training definitions";
pub(super) const TRIAGE_EXCLUSION_REASON: &str = "triage exclusion reason";
pub(super) const TRIAGE_POLICY: &str = "triage policy";
pub(super) const TRIAGE_RESPONSE: &str = "triage response";
pub(super) const TRUSTED_DNS_SERVERS: &str = "trusted DNS servers";
pub(super) const TRUSTED_USER_AGENTS: &str = "trusted user agents";

pub(crate) const MAP_NAMES: [&str; 50] = [
    AGENTS,
    BATCH_INFO,
    CATEGORY,
    CLUSTER,
    COLUMN_STATS,
    CONFIGS,
    CORE_COMPONENTS,
    CSV_COLUMN_EXTRAS,
    CUSTOMER_DELETION_JOBS,
    CUSTOMER_NETWORKS,
    DETECTOR_ID_MARKS,
    ENGINE_INSTANCES,
    HOSTS,
    INSTANCE_ALLOCATIONS,
    MODELS,
    MODEL_INDICATORS,
    META,
    MODEL_RUNS,
    NETWORK_LISTS,
    NETWORKS,
    NODES,
    OPERATION_ATTEMPTS,
    OPERATION_ATTEMPT_LATEST,
    OUTLIERS,
    PORT_ALLOCATIONS,
    PORT_ALLOCATIONS_BY_ATTEMPT,
    PORT_ALLOCATIONS_BY_INSTANCE,
    PREVIOUS_BATCH_INFO,
    PREVIOUS_CLUSTER,
    PREVIOUS_COLUMN_STATS,
    PREVIOUS_CSV_COLUMN_EXTRAS,
    PREVIOUS_OUTLIERS,
    PREVIOUS_SCORES,
    PREVIOUS_TIME_SERIES,
    QUALIFIERS,
    EXTERNAL_SERVICES,
    FORMAT_0_61,
    SAMPLING_POLICY,
    SCORES,
    STATUSES,
    SYSTEM_LOG_COLLECTORS,
    TEMPLATES,
    LABEL_DB,
    TIME_SERIES,
    TOR_EXIT_NODES,
    TRAFFIC_FILTER_RULES,
    TRAINING_DEFINITIONS,
    TRIAGE_RESPONSE,
    TRUSTED_DNS_SERVERS,
    TRUSTED_USER_AGENTS,
];

// Keys for the meta map.
pub(super) const EVENT_TAGS: &[u8] = b"event tags";
pub(super) const NETWORK_TAGS: &[u8] = b"network tags";
pub(super) const WORKFLOW_TAGS: &[u8] = b"workflow tags";
/// The last allocated model run id, as a big-endian `u32`; absent before the
/// first run.
pub(super) const MODEL_RUN_ID_COUNTER: &[u8] = b"model run id counter";

/// The directories of the states databases a [`StateDb`] in this process has
/// open.
///
/// RocksDB recognizes a lock this process holds only under the path string it
/// was taken with, and probing the same database under another spelling of
/// its path releases that lock instead of reporting it. Directories are
/// therefore recorded by file system identity, which every spelling shares,
/// for [`crate::backup::restore_states_offline`] to refuse them. A [`StateDb`]
/// is recorded before it opens its database, so a caller that holds this lock
/// keeps any more from opening one until it lets go.
static OPEN_STATE_DBS: Mutex<Vec<DirId>> = Mutex::new(Vec::new());

/// Locks the record of the states databases open in this process.
pub(crate) fn open_state_dbs() -> MutexGuard<'static, Vec<DirId>> {
    // Nothing panics while holding the lock with the list half-changed.
    OPEN_STATE_DBS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// The file system identity of a directory, shared by every path to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirId {
    dev: u64,
    ino: u64,
}

impl DirId {
    /// Returns the identity of the directory at `path`, or `None` if `path`
    /// is not a directory.
    pub(crate) fn of_dir(path: &Path) -> Option<Self> {
        let metadata = std::fs::metadata(path).ok()?;
        metadata.is_dir().then(|| Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
}

/// An entry in [`OPEN_STATE_DBS`], removed again when dropped.
struct OpenStateDb(DirId);

impl Drop for OpenStateDb {
    fn drop(&mut self) {
        let mut open = open_state_dbs();
        if let Some(i) = open.iter().position(|id| *id == self.0) {
            open.swap_remove(i);
        }
    }
}

#[allow(clippy::module_name_repetitions)]
pub(crate) struct StateDb {
    inner: Option<rocksdb::OptimisticTransactionDB>,
    backup: PathBuf,
    db: PathBuf,
    /// Declared after `inner` so that the database is closed by the time the
    /// entry is removed.
    _open: OpenStateDb,
}

impl StateDb {
    pub fn open(path: &Path, backup: PathBuf) -> Result<Self> {
        let open = Self::record_open(path)?;
        Self::open_db(path).map(|db| Self {
            inner: Some(db),
            backup,
            db: path.to_owned(),
            _open: open,
        })
    }

    /// Records the database directory at `path` in [`OPEN_STATE_DBS`],
    /// creating it as RocksDB would if it is missing.
    fn record_open(path: &Path) -> Result<OpenStateDb> {
        let mut open = open_state_dbs();
        match std::fs::create_dir(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let id = DirId::of_dir(path)
            .ok_or_else(|| anyhow!("states database {} is not a directory", path.display()))?;
        open.push(id);
        Ok(OpenStateDb(id))
    }

    /// Returns the open database.
    pub(crate) fn db(&self) -> &rocksdb::OptimisticTransactionDB {
        self.inner.as_ref().expect("database must be open")
    }

    /// Returns the read view of the previous training results.
    #[must_use]
    pub(crate) fn previous_training_results(&self) -> PreviousTrainingResults<'_> {
        PreviousTrainingResults::open(self.db())
            .expect("StateDb::open creates every previous-result column family")
    }

    #[must_use]
    pub(crate) fn agents(&self) -> Table<'_, Agent> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Agent>::open(inner).expect("{AGENTS} table must be present")
    }

    #[must_use]
    pub(crate) fn external_service(&self) -> Table<'_, ExternalService> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<ExternalService>::open(inner).expect("{EXTERNAL_SERVICES} table must be present")
    }

    #[must_use]
    pub(crate) fn batch_info(&self) -> Table<'_, BatchInfo> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<BatchInfo>::open(inner).expect("{BATCH_INFO} table must be present")
    }

    #[must_use]
    pub(crate) fn model_indicators(&self) -> Table<'_, ModelIndicator> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<ModelIndicator>::open(inner).expect("{MODEL_INDICATORS} table must be present")
    }

    #[must_use]
    pub(crate) fn scores(&self) -> Table<'_, Scores> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Scores>::open(inner).expect("{SCORES} table must be present")
    }

    #[must_use]
    pub(crate) fn templates(&self) -> Table<'_, Template> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Template>::open(inner).expect("{TEMPLATES} table must be present")
    }

    #[must_use]
    pub(crate) fn tor_exit_nodes(&self) -> Table<'_, TorExitNode> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<TorExitNode>::open(inner).expect("{TOR_EXIT_NODES} table must be present")
    }

    #[must_use]
    pub(crate) fn categories(&self) -> IndexedTable<'_, Category> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Category>::open(inner).expect("{CATEGORY} table must be present")
    }

    #[must_use]
    pub(crate) fn qualifiers(&self) -> IndexedTable<'_, Qualifier> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Qualifier>::open(inner).expect("{QUALIFIERS} table must be present")
    }

    #[must_use]
    pub(crate) fn statuses(&self) -> IndexedTable<'_, Status> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Status>::open(inner).expect("{STATUSES} table must be present")
    }

    #[must_use]
    pub(crate) fn csv_column_extras(&self) -> IndexedTable<'_, CsvColumnExtra> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<CsvColumnExtra>::open(inner)
            .expect("{CSV_COLUMN_EXTRAS} table must be present")
    }

    #[must_use]
    pub(crate) fn triage_responses(&self) -> IndexedTable<'_, TriageResponse> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<TriageResponse>::open(inner)
            .expect("{TRIAGE_RESPONSE} table must be present")
    }

    #[must_use]
    pub(crate) fn networks(&self) -> IndexedTable<'_, Network> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Network>::open(inner).expect("{NETWORKS} table must be present")
    }

    #[must_use]
    pub(crate) fn sampling_policies(&self) -> IndexedTable<'_, SamplingPolicy> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<SamplingPolicy>::open(inner)
            .expect("{SAMPLING_POLICY} table must be present")
    }

    #[must_use]
    pub(crate) fn customer_networks(&self) -> OwnedNetworkTable<'_> {
        let inner = self
            .inner
            .as_ref()
            .expect("table access requires a successfully opened StateDb");
        OwnedNetworkTable::open(inner)
            .expect("StateDb::open initializes the customer networks column family")
    }

    #[must_use]
    pub(crate) fn network_lists(&self) -> NetworkListTable<'_> {
        let inner = self
            .inner
            .as_ref()
            .expect("table access requires a successfully opened StateDb");
        NetworkListTable::open(inner)
            .expect("StateDb::open initializes the network lists column family")
    }

    #[must_use]
    pub(crate) fn system_log_collectors(&self) -> SystemLogCollectorTable<'_> {
        let inner = self
            .inner
            .as_ref()
            .expect("table access requires a successfully opened StateDb");
        SystemLogCollectorTable::open(inner)
            .expect("StateDb::open initializes the system log collectors column family")
    }

    #[must_use]
    pub(crate) fn customer_data_deletion_jobs(&self) -> Table<'_, CustomerDataDeletionJob> {
        let inner = self
            .inner
            .as_ref()
            .expect("table access requires a successfully opened StateDb");
        Table::<CustomerDataDeletionJob>::open(inner)
            .expect("StateDb::open initializes the customer deletion jobs column family")
    }

    #[must_use]
    pub(crate) fn core_components(&self) -> Table<'_, CoreComponent> {
        let inner = self
            .inner
            .as_ref()
            .expect("table access requires a successfully opened StateDb");
        Table::<CoreComponent>::open(inner)
            .expect("StateDb::open initializes the core components column family")
    }

    #[must_use]
    pub(crate) fn operation_attempts(&self) -> Table<'_, OperationAttempt> {
        let inner = self
            .inner
            .as_ref()
            .expect("table access requires a successfully opened StateDb");
        Table::<OperationAttempt>::open(inner)
            .expect("StateDb::open initializes the operation attempts column family")
    }

    #[must_use]
    pub(crate) fn port_allocations(&self) -> Table<'_, PortAllocation> {
        let inner = self
            .inner
            .as_ref()
            .expect("table access requires a successfully opened StateDb");
        Table::<PortAllocation>::open(inner)
            .expect("StateDb::open initializes the port allocation column families")
    }

    #[must_use]
    pub(crate) fn instance_allocations(&self) -> Table<'_, InstanceAllocation> {
        let inner = self
            .inner
            .as_ref()
            .expect("table access requires a successfully opened StateDb");
        Table::<InstanceAllocation>::open(inner)
            .expect("StateDb::open initializes the instance allocation column family")
    }

    pub(crate) fn engine_instances(&self) -> EngineInstances<'_> {
        EngineInstances::open(self.db()).expect("StateDb::open creates the engine instances family")
    }

    pub(crate) fn training_definitions(&self) -> TrainingDefinitions<'_> {
        TrainingDefinitions::open(self.db())
            .expect("StateDb::open creates the training definitions family")
    }

    pub(crate) fn model_runs(&self) -> ModelRuns<'_> {
        ModelRuns::open(self.db()).expect("StateDb::open creates the model runs and meta families")
    }

    pub(crate) fn nodes(&self) -> NodeTable<'_> {
        let inner = self.inner.as_ref().expect("database must be open");
        NodeTable::open(inner).expect("{NETWORKS} table must be present")
    }

    #[must_use]
    pub(crate) fn label_dbs(&self) -> Table<'_, LabelDb> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<LabelDb>::open(inner).expect("{LABEL_DB} table must be present")
    }

    #[must_use]
    pub(crate) fn trusted_domains(&self) -> Table<'_, TrustedDomain> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<TrustedDomain>::open(inner).expect("{TRUSTED_DNS_SERVERS} table must be present")
    }

    pub(crate) fn trusted_user_agents(&self) -> Table<'_, TrustedUserAgent> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<TrustedUserAgent>::open(inner).expect("{TRUSTED_USER_AGENTS} table must be present")
    }

    pub(crate) fn traffic_filters(&self) -> Table<'_, TrafficFilter> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<TrafficFilter>::open(inner).expect("{TRAFFIC_FILTER_RULES} table must be present")
    }

    pub(crate) fn outlier_infos(&self) -> Table<'_, OutlierInfo> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<OutlierInfo>::open(inner).expect("{OUTLIERS} table must be present")
    }

    #[must_use]
    pub fn events(
        &self,
        country_lookup: Option<crate::geo::SharedCountryLookup>,
    ) -> event::EventDb<'_> {
        let inner = self.inner.as_ref().expect("database must be open");
        event::EventDb::new_with_country_lookup(inner, country_lookup)
    }

    #[must_use]
    pub(crate) fn column_stats(&self) -> Table<'_, ColumnStats> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<ColumnStats>::open(inner).expect("{COLUMN_STATS} table must be present")
    }

    #[must_use]
    pub(crate) fn time_series(&self) -> Table<'_, TimeSeries> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<TimeSeries>::open(inner).expect("{TIME_SERIES} table must be present")
    }

    #[must_use]
    pub(crate) fn clusters(&self) -> Table<'_, Cluster> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Cluster>::open(inner).expect("{CLUSTER} table must be present")
    }

    #[must_use]
    pub(crate) fn models(&self) -> IndexedTable<'_, Model> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Model>::open(inner).expect("{MODELS} table must be present")
    }

    #[must_use]
    pub(crate) fn configs(&self) -> Table<'_, String> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<String>::open(inner).expect("{CONFIGS} table must be present")
    }

    #[must_use]
    pub(crate) fn hosts(&self) -> Table<'_, Host> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Host>::open(inner).expect("{HOSTS} table must be present")
    }

    #[must_use]
    pub(super) fn indexed_set(&self, name: &'static [u8]) -> Option<IndexedSet<'_>> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedSet::new(inner, META, name).ok()
    }

    pub(super) fn create_new_backup_flush(
        &mut self,
        flush: bool,
        num_of_backups_to_keep: u32,
    ) -> Result<()> {
        let mut engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        let inner = self
            .inner
            .as_ref()
            .ok_or(anyhow!("unable to backup, database has closed"))?;
        engine.create_new_backup_flush(inner, flush)?;

        engine
            .purge_old_backups(num_of_backups_to_keep as usize)
            .or_else(|_| self.reboot())
    }

    /// Restores the latest backup over the database and reopens it.
    ///
    /// # Errors
    ///
    /// Returns an error, before closing anything, if there is no backup, or
    /// if the format of the latest backup cannot be determined or is not the
    /// current one. Only the latest backup is checked; an older one is never
    /// restored in its place. A refused call leaves `states.db`, the backups
    /// and the `VERSION` markers unchanged, and the database stays open. A
    /// backup taken at another format is restored offline with
    /// [`crate::backup::restore_states_offline`] followed by
    /// [`crate::write_version_markers`].
    ///
    /// Returns an error if the backup engine fails to restore the backup or
    /// the restored database cannot be reopened, in which case the database
    /// is left closed.
    pub fn restore_from_latest_backup(&mut self) -> Result<()> {
        let mut engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        let latest = engine
            .get_backup_info()
            .iter()
            .map(|info| info.backup_id)
            .max()
            .ok_or_else(|| anyhow!("no backup to restore; nothing was restored"))?;
        check_backup_format(&engine, &self.backup, latest)?;

        let mut opts = rocksdb::backup::RestoreOptions::default();
        opts.set_keep_log_files(true);

        self.close();

        engine.restore_from_backup(&self.db, &self.db, &opts, latest)?;

        self.reboot()
    }

    /// Restores backup `id` over the database and reopens it.
    ///
    /// # Errors
    ///
    /// Returns an error, before closing anything, if no backup has id `id`,
    /// or if the backup's format cannot be determined or is not the current
    /// one. A refused call leaves `states.db`, the backups and the `VERSION`
    /// markers unchanged, and the database stays open. A backup taken at
    /// another format is restored offline with
    /// [`crate::backup::restore_states_offline`] followed by
    /// [`crate::write_version_markers`].
    ///
    /// Returns an error if the backup engine fails to restore the backup or
    /// the restored database cannot be reopened, in which case the database
    /// is left closed.
    pub fn restore_from_backup(&mut self, id: u32) -> Result<()> {
        let mut engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        check_backup_format(&engine, &self.backup, id)?;

        self.close();

        restore_rocksdb_backup(&mut engine, &self.db, id)?;

        self.reboot()
    }

    pub fn get_backup_info(&self) -> Result<Vec<rocksdb::backup::BackupEngineInfo>> {
        let engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        Ok(engine.get_backup_info())
    }

    pub fn purge_old_backups(&mut self, num_of_backups_to_keep: u32) -> Result<()> {
        let mut engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        if engine
            .purge_old_backups(num_of_backups_to_keep as usize)
            .is_err()
        {
            self.reboot()?;
        }
        Ok(())
    }

    fn close(&mut self) {
        if let Some(db) = self.inner.as_ref() {
            db.cancel_all_background_work(true);
        }
        self.inner = None;
    }

    fn reboot(&mut self) -> Result<()> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = rocksdb::OptimisticTransactionDB::open_cf(&opts, &self.db, MAP_NAMES)?;

        self.inner = Some(db);
        Ok(())
    }

    fn open_db(path: &Path) -> Result<rocksdb::OptimisticTransactionDB> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        Ok(rocksdb::OptimisticTransactionDB::open_cf(
            &opts, path, MAP_NAMES,
        )?)
    }
}

/// The opt-in list of record types whose [`Table`] may be scanned generically.
///
/// A [`Table`] scan covers the whole column family, so it is safe only where
/// the column family holds nothing but records. Most tables are of that shape
/// and are listed below; `operation_attempt` is not, because it reserves the
/// top of its key space for secondary indexes, and is therefore deliberately
/// absent. `port_allocation` is absent too, for a different reason: its rows
/// are reachable from outside the crate through
/// [`Store::port_allocation_map`](crate::Store::port_allocation_map), which
/// promises its three keyed reads and nothing more.
///
/// The trait is not exported, so this list is the only way in: nothing outside
/// the crate can implement it, and a record type added here gets generic
/// iteration only once someone writes it down. That is the point — the
/// exclusion holds unless it is removed on purpose, rather than lapsing the
/// next time a bound elsewhere is broadened.
mod iteration {
    use crate::{tables, types};

    pub trait Eligible {}

    impl Eligible for tables::Agent {}
    impl Eligible for crate::BatchInfo {}
    impl Eligible for crate::Category {}
    impl Eligible for tables::Cluster {}
    impl Eligible for tables::ColumnStats {}
    impl Eligible for tables::CoreComponent {}
    impl Eligible for tables::CsvColumnExtra {}
    impl Eligible for tables::CustomerDataDeletionJob {}
    impl Eligible for tables::ExternalService {}
    impl Eligible for tables::Host {}
    impl Eligible for tables::InstanceAllocation {}
    impl Eligible for tables::InnerNode {}
    impl Eligible for tables::LabelDb {}
    impl Eligible for tables::Model {}
    impl Eligible for tables::ModelIndicator {}
    impl Eligible for tables::Network {}
    impl Eligible for tables::OutlierInfo {}
    impl Eligible for types::Qualifier {}
    impl Eligible for tables::SamplingPolicy {}
    impl Eligible for types::Status {}
    impl Eligible for tables::Template {}
    impl Eligible for tables::TimeSeries {}
    impl Eligible for tables::TorExitNode {}
    impl Eligible for tables::TrafficFilter {}
    impl Eligible for tables::TriageResponse {}
    impl Eligible for tables::TrustedDomain {}
    impl Eligible for tables::TrustedUserAgent {}
}

/// The opt-in list of record types whose [`IndexedTable`] may be written
/// through the generic method `update_with_transaction`, and, for the subsets
/// that also implement [`indexed_writes::Inserting`],
/// [`indexed_writes::Deactivating`] or [`indexed_writes::Recycling`], `put`,
/// `deactivate` or `remove`.
///
/// `tables::Model` is deliberately absent: a model row is created, changed
/// and removed only together with its per-model records and classifier files,
/// through the `Store` methods that hold the model-files lock, or has its
/// instance alone changed by `Store::assign_model` and by the detach of an
/// uninstalled engine instance, which write no classifier file and so take
/// no lock. The generic writers are not reachable for it. As with
/// [`iteration`], the trait is not exported, so nothing outside the crate can
/// add a type to the list.
mod indexed_writes {
    use crate::{tables, types};

    pub trait Eligible {}

    impl Eligible for crate::Category {}
    impl Eligible for tables::CsvColumnExtra {}
    impl Eligible for tables::InnerNode {}
    impl Eligible for tables::Network {}
    impl Eligible for types::Qualifier {}
    impl Eligible for tables::SamplingPolicy {}
    impl Eligible for types::Status {}
    impl Eligible for tables::TriageResponse {}

    /// The opt-in list of [`Eligible`] record types whose [`IndexedTable`]
    /// may be written through `remove` and `remove_with_transaction`, which
    /// put the freed ID on the free list for the next insert to reuse.
    ///
    /// `tables::SamplingPolicy` is deliberately absent: a sampling-policy ID
    /// is never reused, because the Data Store keeps a policy's time series
    /// and the Time Series Generator its checkpoint under that ID after the
    /// policy is deleted, and a new policy under a reused ID would inherit
    /// both. A sampling policy is deleted with the table's `remove_unused`
    /// instead, which retires its ID. Every other `Eligible` type recycles.
    ///
    /// [`IndexedTable`]: super::IndexedTable
    pub trait Recycling: Eligible {}

    impl Recycling for crate::Category {}
    impl Recycling for tables::CsvColumnExtra {}
    impl Recycling for tables::InnerNode {}
    impl Recycling for tables::Network {}
    impl Recycling for types::Qualifier {}
    impl Recycling for types::Status {}
    impl Recycling for tables::TriageResponse {}

    /// The opt-in list of [`Eligible`] record types whose [`IndexedTable`]
    /// may be written through `put` and `put_with_transaction`, which store
    /// a record exactly as the caller built it.
    ///
    /// `tables::SamplingPolicy` is deliberately absent: every new sampling
    /// policy is a draft with no assignee and no Data Store, which the
    /// table's own `insert` sets, so a caller cannot store one fixed or
    /// assigned. Every other `Eligible` type is inserted freely.
    ///
    /// [`IndexedTable`]: super::IndexedTable
    pub trait Inserting: Eligible {}

    impl Inserting for crate::Category {}
    impl Inserting for tables::CsvColumnExtra {}
    impl Inserting for tables::InnerNode {}
    impl Inserting for tables::Network {}
    impl Inserting for types::Qualifier {}
    impl Inserting for types::Status {}
    impl Inserting for tables::TriageResponse {}

    /// The opt-in list of [`Eligible`] record types whose [`IndexedTable`]
    /// may be written through `deactivate`, which deletes a record without
    /// asking what still refers to it.
    ///
    /// `tables::SamplingPolicy` is deliberately absent: a sampling policy is
    /// deleted only by the table's `remove_unused`, which refuses while a
    /// training definition, a detector or a model uses it, or by
    /// `remove_customer_policies`, for the deletion of its customer. Every
    /// other `Eligible` type is deactivated freely.
    ///
    /// [`IndexedTable`]: super::IndexedTable
    pub trait Deactivating: Eligible {}

    impl Deactivating for crate::Category {}
    impl Deactivating for tables::CsvColumnExtra {}
    impl Deactivating for tables::InnerNode {}
    impl Deactivating for tables::Network {}
    impl Deactivating for types::Qualifier {}
    impl Deactivating for types::Status {}
    impl Deactivating for tables::TriageResponse {}
}

/// Represents a table that can be iterated over.
///
/// A [`Table`] offers this only for a record type whose column family holds
/// records and nothing else, because both scans cover key ranges the caller
/// does not choose: [`iter`](Iterable::iter) covers the whole column family,
/// and [`prefix_iter`](Iterable::prefix_iter) covers whatever the given
/// prefix spans, which for an empty prefix is again the whole of it. A table
/// that reserves part of its key space for secondary index entries — at
/// present only `operation_attempt`, whose keys are described on
/// [`OperationAttempt`] — is therefore left out, and offers a bounded
/// iterator of its own that stops below the reserved range. `port_allocation`
/// is left out as well, so that the view
/// [`Store::port_allocation_map`](crate::Store::port_allocation_map) returns
/// reads its rows only by key.
pub trait Iterable<'i, I>
where
    I: Iterator,
{
    /// Returns an iterator over the records in the table.
    fn iter(&'i self, direction: Direction, from: Option<&[u8]>) -> I;
    /// Returns an iterator over the records with prefix in the table.
    fn prefix_iter(&'i self, direction: Direction, from: Option<&[u8]>, prefix: &[u8]) -> I;
}

/// An iterator over the records in a table.
pub struct TableIter<'i, R> {
    inner: rocksdb::DBIteratorWithThreadMode<
        'i,
        rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
    >,
    _phantom: std::marker::PhantomData<R>,
}

impl<'i, R> TableIter<'i, R> {
    fn new(
        inner: rocksdb::DBIteratorWithThreadMode<
            'i,
            rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
        >,
    ) -> Self {
        Self {
            inner,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<R> Iterator for TableIter<'_, R>
where
    R: FromKeyValue,
{
    type Item = Result<R, anyhow::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let serialized_item = self.inner.next()?;
        match serialized_item {
            Ok((mut key, mut value)) => {
                if key.is_empty() {
                    match self.inner.next()? {
                        Ok((k, v)) => {
                            key = k;
                            value = v;
                        }
                        Err(e) => return Some(Err(e.into())),
                    }
                }
                let item = R::from_key_value(&key, &value);
                Some(item)
            }
            Err(e) => Some(Err(e.into())),
        }
    }
}

/// A database table storing records of type `R`.
#[derive(Clone)]
pub struct Table<'d, R> {
    map: Map<'d>,
    _phantom: std::marker::PhantomData<R>,
}

impl<'d, R> Table<'d, R> {
    fn new(map: Map<'d>) -> Self {
        Self {
            map,
            _phantom: std::marker::PhantomData,
        }
    }
    pub(crate) fn transaction(&self) -> rocksdb::Transaction<'_, rocksdb::OptimisticTransactionDB> {
        self.map.db.transaction()
    }
}

impl<R: UniqueKey + Value> Table<'_, R> {
    /// Stores a record into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn put(&self, record: &R) -> Result<()> {
        self.map
            .put(record.unique_key().as_ref(), record.value().as_ref())
    }

    /// Stores a record into the database within a transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn put_with_transaction(
        &self,
        record: &R,
        txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
    ) -> Result<()> {
        self.map
            .put_with_transaction(record.unique_key().as_ref(), record.value().as_ref(), txn)
    }

    /// Adds a record into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the record with the same key exists, or the database
    /// operation fails.
    pub fn insert(&self, record: &R) -> Result<()> {
        self.map
            .insert(record.unique_key().as_ref(), record.value().as_ref())
    }

    /// Adds a record into the database within a transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the record with the same key exists, or the database
    /// operation fails.
    pub fn insert_with_transaction(
        &self,
        record: &R,
        txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
    ) -> Result<()> {
        self.map
            .insert_with_transaction(record.unique_key().as_ref(), record.value().as_ref(), txn)
    }

    /// Updates a record in the database within a transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the old value does not match the value in the database, the old key does
    /// not exist, or the database operation fails.
    pub fn update_with_transaction(
        &self,
        old: &R,
        new: &R,
        txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
    ) -> Result<()>
    where
        R: Value,
    {
        self.map.update_with_transaction(
            (old.unique_key().as_ref(), old.value().as_ref()),
            (new.unique_key().as_ref(), new.value().as_ref()),
            txn,
        )
    }

    /// Deletes a record from the database within a transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the key does not exist or the database operation fails.
    pub fn delete_with_transaction(
        &self,
        key: &[u8],
        txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
    ) -> Result<()> {
        self.map.delete_with_transaction(key, txn)
    }
}

// The `iteration::Eligible` bound is what keeps `Table<OperationAttempt>` out
// of this implementation, whose scans reach the index key spaces that table
// reserves, and `Table<PortAllocation>`, whose public view offers only keyed
// reads. `IndexedTable` below does not carry the bound: no table that
// reserves part of its key space is indexed, and `NodeTable` iterates through
// that implementation.
impl<'i, 'j, 'k, R> Iterable<'i, TableIter<'k, R>> for Table<'j, R>
where
    'j: 'k,
    'i: 'k,
    R: FromKeyValue + iteration::Eligible,
{
    fn iter(&self, direction: Direction, from: Option<&[u8]>) -> TableIter<'k, R> {
        use rocksdb::IteratorMode;

        match direction {
            Direction::Forward => match from {
                Some(from) => TableIter::new(
                    self.map
                        .db
                        .iterator_cf(self.map.cf, IteratorMode::From(from, Direction::Forward)),
                ),
                None => TableIter::new(self.map.db.iterator_cf(self.map.cf, IteratorMode::Start)),
            },
            Direction::Reverse => match from {
                Some(from) => TableIter::new(
                    self.map
                        .db
                        .iterator_cf(self.map.cf, IteratorMode::From(from, Direction::Reverse)),
                ),
                None => TableIter::new(self.map.db.iterator_cf(self.map.cf, IteratorMode::End)),
            },
        }
    }

    fn prefix_iter(
        &'i self,
        direction: Direction,
        from: Option<&[u8]>,
        prefix: &[u8],
    ) -> TableIter<'k, R> {
        let mut readopts = rocksdb::ReadOptions::default();
        readopts.set_iterate_range(rocksdb::PrefixRange(prefix));
        let mode = {
            match from {
                Some(from) => rocksdb::IteratorMode::From(from, direction),
                None => match direction {
                    Direction::Forward => rocksdb::IteratorMode::Start,
                    Direction::Reverse => rocksdb::IteratorMode::End,
                },
            }
        };
        let iter = self.map.db.iterator_cf_opt(self.map.cf, readopts, mode);

        TableIter::new(iter)
    }
}

pub struct IndexedTable<'d, R> {
    indexed_map: IndexedMap<'d>,
    _phantom: std::marker::PhantomData<R>,
}

impl<'d, R> IndexedTable<'d, R> {
    fn new(indexed_map: IndexedMap<'d>) -> Self {
        Self {
            indexed_map,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Returns the number of entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the map index is not found or the database operation fails.
    pub fn count(&self) -> Result<usize> {
        self.indexed_map.count()
    }

    /// Stores a record with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn put(&self, entry: R) -> Result<u32>
    where
        R: Indexable + indexed_writes::Inserting,
    {
        self.indexed_map.insert(entry)
    }

    /// Stores a record with the given ID within a transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn put_with_transaction(
        &self,
        entry: R,
        txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
    ) -> Result<u32>
    where
        R: Indexable + indexed_writes::Inserting,
    {
        self.indexed_map.insert_with_transaction(entry, txn)
    }

    /// Removes a record with the given ID.
    ///
    /// The ID goes on the free list, and the next insert reuses it. A table
    /// whose IDs must not be reused deletes in a way that retires the ID,
    /// such as [`deactivate`](Self::deactivate).
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn remove(&self, id: u32) -> Result<Vec<u8>>
    where
        R: Indexable + indexed_writes::Recycling,
    {
        self.indexed_map.remove::<R>(id)
    }

    /// Removes a record with the given ID within a transaction.
    ///
    /// The ID goes on the free list, as with [`remove`](Self::remove).
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn remove_with_transaction(
        &self,
        id: u32,
        txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
    ) -> Result<Vec<u8>>
    where
        R: Indexable + indexed_writes::Recycling,
    {
        self.indexed_map.remove_with_transaction::<R>(id, txn)
    }

    /// Get a record with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn get_by_id(&self, id: u32) -> Result<Option<R>>
    where
        R: Indexable + FromKeyValue,
    {
        self.indexed_map.get_by_id(id)
    }

    /// Gets a record with the given ID within a transaction, acquiring an
    /// exclusive lock on the entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn get_by_id_in_transaction(
        &self,
        id: u32,
        txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
    ) -> Result<Option<R>>
    where
        R: Indexable + FromKeyValue,
    {
        self.indexed_map.get_by_id_in_transaction(id, txn)
    }

    /// Deactivates a key-value pair with the given ID.
    ///
    /// The record is deleted and its ID marked inactive, so no later insert
    /// is given it.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn deactivate(&self, id: u32) -> Result<Vec<u8>>
    where
        R: indexed_writes::Deactivating,
    {
        self.indexed_map.deactivate(id)
    }

    /// Updates a record within a transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn update_with_transaction<O, V>(
        &self,
        id: u32,
        old: &O,
        new: &V,
        txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
    ) -> Result<()>
    where
        R: indexed_writes::Eligible,
        O: IndexedMapUpdate,
        O::Entry: Indexable + FromKeyValue,
        V: IndexedMapUpdate,
        V::Entry: Indexable + From<O::Entry>,
    {
        self.indexed_map.update_with_transaction(id, old, new, txn)
    }
}

impl<'i, 'j, 'k, R> Iterable<'i, TableIter<'k, R>> for IndexedTable<'j, R>
where
    'j: 'k,
    'i: 'k,
    R: FromKeyValue,
{
    fn iter(&'i self, direction: Direction, from: Option<&[u8]>) -> TableIter<'k, R> {
        use rocksdb::IteratorMode;

        match direction {
            Direction::Forward => match from {
                Some(from) => TableIter::new(self.indexed_map.db().iterator_cf(
                    self.indexed_map.cf(),
                    IteratorMode::From(from, Direction::Forward),
                )),
                None => TableIter::new(
                    self.indexed_map
                        .db()
                        .iterator_cf(self.indexed_map.cf(), IteratorMode::Start),
                ),
            },
            Direction::Reverse => match from {
                Some(from) => TableIter::new(self.indexed_map.db().iterator_cf(
                    self.indexed_map.cf(),
                    IteratorMode::From(from, Direction::Reverse),
                )),
                None => TableIter::new(
                    self.indexed_map
                        .db()
                        .iterator_cf(self.indexed_map.cf(), IteratorMode::End),
                ),
            },
        }
    }

    fn prefix_iter(
        &'i self,
        direction: Direction,
        from: Option<&[u8]>,
        prefix: &[u8],
    ) -> TableIter<'k, R> {
        let mut readopts = rocksdb::ReadOptions::default();
        readopts.set_iterate_range(rocksdb::PrefixRange(prefix));
        let mode = {
            match from {
                Some(from) => rocksdb::IteratorMode::From(from, direction),
                None => match direction {
                    Direction::Forward => rocksdb::IteratorMode::Start,
                    Direction::Reverse => rocksdb::IteratorMode::End,
                },
            }
        };
        let iter = self
            .indexed_map
            .db()
            .iterator_cf_opt(self.indexed_map.cf(), readopts, mode);

        TableIter::new(iter)
    }
}

/// Represents entities that can be uniquely identified by a key.
///
/// The `UniqueKey` trait is designed to provide a standardized way to retrieve
/// a unique, opaque key for instances of structs that implement this trait. The
/// key is returned as a `AsRef<[u8]>`, allowing for flexible ownership
/// models.
///
/// Implementing this trait allows for unique identification of instances, which
/// can be used for indexing, identification in collections, or any scenario
/// where a distinct, non-colliding identifier is necessary.
///
/// # Examples
///
/// ```
/// # use review_database::UniqueKey;
/// struct User {
///     id: u32,
///     username: String,
/// }
///
/// impl UniqueKey for User {
///     type AsBytes<'a> = [u8; 4];
///
///     fn unique_key(&self) -> [u8; 4] {
///         self.id.to_be_bytes()
///     }
/// }
/// ```
pub trait UniqueKey {
    type AsBytes<'a>: AsRef<[u8]> + 'a
    where
        Self: 'a;

    /// Returns a unique, opaque key for the instance.
    ///
    /// This method should return an object that implements `AsRef<[u8]>` and
    /// uniquely identifies the instance of the struct.
    ///
    /// # Examples
    ///
    /// Using the `UniqueKey` implementation for a `User` struct defined in the
    /// trait-level documentation:
    ///
    /// ```
    /// # use review_database::UniqueKey;
    /// # struct User {
    /// #     id: u32,
    /// #     username: String,
    /// # }
    /// # impl UniqueKey for User {
    /// #     type AsBytes<'a> = [u8; 4];
    /// #     fn unique_key(&self) -> [u8; 4] {
    /// #         self.id.to_be_bytes()
    /// #     }
    /// # }
    /// let user = User { id: 1, username: String::from("alice") };
    /// assert_eq!(user.unique_key().as_ref(), b"\x00\x00\x00\x01");
    /// ```
    ///
    /// In this example, the `unique_key` method returns the user's `id` as a
    /// byte array, providing a unique key for the user instance.
    fn unique_key(&self) -> Self::AsBytes<'_>;
}

pub trait Value {
    type AsBytes<'a>: AsRef<[u8]> + 'a
    where
        Self: 'a;

    fn value(&self) -> Self::AsBytes<'_>;
}

fn serialize<I: Serialize>(input: &I) -> anyhow::Result<Vec<u8>> {
    use bincode::Options;
    Ok(bincode::DefaultOptions::new().serialize(input)?)
}

fn deserialize<'de, O: Deserialize<'de>>(input: &'de [u8]) -> anyhow::Result<O> {
    use bincode::Options;
    Ok(bincode::DefaultOptions::new().deserialize(input)?)
}

/// Opens a RocksDB backup engine using the default options and environment.
pub(crate) fn open_rocksdb_backup_engine(
    path: &Path,
) -> Result<rocksdb::backup::BackupEngine, rocksdb::Error> {
    let opts = rocksdb::backup::BackupEngineOptions::new(path)?;
    let db_env = rocksdb::Env::new()?;
    rocksdb::backup::BackupEngine::open(&opts, &db_env)
}

/// Checks that backup `id` in the backup engine directory `backup` exists and
/// is in the current database format, without restoring it.
///
/// A backup is taken to be in [`DATABASE_FORMAT_VERSION`] exactly when its
/// column families other than `default` are [`MAP_NAMES`]. The backup engine
/// keeps each backup's `CURRENT` and `MANIFEST` in `private/<id>`, which is
/// where RocksDB opens a backup from, so the families are listed from there.
/// Listing them reads those two files only and writes nothing.
///
/// Every message is the error's own `Display` text, with no context layered
/// on, because callers such as review-web show only the outermost one.
fn check_backup_format(
    engine: &rocksdb::backup::BackupEngine,
    backup: &Path,
    id: u32,
) -> Result<()> {
    fn quoted<'a>(names: impl Iterator<Item = &'a &'a str>) -> String {
        names
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(", ")
    }

    if !engine
        .get_backup_info()
        .iter()
        .any(|info| info.backup_id == id)
    {
        return Err(anyhow!("no backup with id {id}; nothing was restored"));
    }

    let families = rocksdb::DB::list_cf(
        &rocksdb::Options::default(),
        backup.join("private").join(id.to_string()),
    )
    .map_err(|e| {
        anyhow!("cannot determine the database format of backup {id}: {e}; nothing was restored")
    })?;

    let found: BTreeSet<&str> = families
        .iter()
        .map(String::as_str)
        .filter(|name| *name != "default")
        .collect();
    let expected: BTreeSet<&str> = MAP_NAMES.into_iter().collect();
    if found == expected {
        return Ok(());
    }

    Err(anyhow!(
        "backup {id} is not in database format {DATABASE_FORMAT_VERSION}: unexpected column \
         families [{}], missing column families [{}]; nothing was restored",
        quoted(found.difference(&expected)),
        quoted(expected.difference(&found)),
    ))
}

/// Restores backup `id` into the closed database at `db`.
///
/// Both the online restore through [`StateDb::restore_from_backup`] and the
/// offline one in [`crate::backup::restore_states_offline`] go through here,
/// so the two write the same files with the same options.
pub(crate) fn restore_rocksdb_backup(
    engine: &mut rocksdb::backup::BackupEngine,
    db: &Path,
    id: u32,
) -> Result<(), rocksdb::Error> {
    let opts = rocksdb::backup::RestoreOptions::default();
    engine.restore_from_backup(db, db, &opts, id)
}
