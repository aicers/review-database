mod access_token;
mod accounts;
mod agent;
mod allow_network;
mod backup_config;
mod batch_info;
mod block_network;
mod category;
mod cluster;
mod column_stats;
mod config;
mod csv_column_extra;
mod customer;
mod data_source;
mod external_service;
mod filter;
mod hosts;
mod label_db;
mod model;
mod model_indicator;
mod network;
mod node;
mod outlier_info;
mod qualifier;
mod sampling_policy;
mod scores;
mod status;
mod template;
mod time_series;
mod tor_exit_node;
mod traffic_filter;
mod triage_policy;
mod triage_response;
mod trusted_domain;
mod trusted_user_agent;

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use rocksdb::Direction;
use serde::{Deserialize, Serialize};

pub use self::access_token::AccessToken;
pub use self::agent::{Agent, AgentKind};
pub use self::allow_network::{AllowNetwork, Update as AllowNetworkUpdate};
pub use self::backup_config::BackupConfig;
pub use self::block_network::{BlockNetwork, Update as BlockNetworkUpdate};
pub use self::cluster::Cluster;
pub use self::column_stats::{ColumnStats, RetentionResult, TopColumnsOfCluster, TopMultimaps};
pub use self::config::{
    KEY_EXPIRY_PERIOD, KEY_LOCKOUT_DURATION, KEY_LOCKOUT_THRESHOLD, KEY_SUSPENSION_THRESHOLD,
};
pub use self::csv_column_extra::CsvColumnExtra;
pub use self::customer::{Customer, Network as CustomerNetwork, Update as CustomerUpdate};
pub use self::data_source::{DataSource, DataType, Update as DataSourceUpdate};
pub use self::external_service::{ExternalService, ExternalServiceKind};
pub use self::filter::{Filter, PeriodForSearch, Value as FilterValue};
pub use self::hosts::{Host, UserAgent};
pub use self::label_db::{
    Kind as LabelDbKind, LabelDb, Rule as LabelDbRule, RuleKind as LabelDbRuleKind,
};
pub use self::model::Model;
pub use self::model_indicator::ModelIndicator;
pub use self::network::{Network, Update as NetworkUpdate};
pub(crate) use self::node::Inner as InnerNode;
pub use self::node::{
    Config as AgentConfig, Config as ExternalServiceConfig, Node, Profile as NodeProfile,
    Status as AgentStatus, Status as ExternalServiceStatus, Table as NodeTable,
    Update as NodeUpdate,
};
pub use self::outlier_info::{Key as OutlierInfoKey, OutlierInfo, Value as OutlierInfoValue};
pub use self::sampling_policy::{
    Interval as SamplingInterval, Kind as SamplingKind, Period as SamplingPeriod, SamplingPolicy,
    Update as SamplingPolicyUpdate,
};
pub use self::template::{
    Structured, StructuredClusteringAlgorithm, Template, Unstructured,
    UnstructuredClusteringAlgorithm,
};
pub use self::time_series::{Cluster as ClusterTimeSeries, Column as ColumnTimeSeries, TimeSeries};
pub use self::tor_exit_node::TorExitNode;
pub use self::traffic_filter::{ProtocolPorts, TrafficFilter};
pub use self::triage_policy::{
    AttrCmpKind, Confidence, ExclusionReason, NetworkFilter, PacketAttr, Response, ResponseKind,
    TriageExclusion, TriageExclusionReason, TriageExclusionReasonUpdate, TriagePolicy,
    TriagePolicyInput, Update as TriagePolicyUpdate, ValueKind,
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
    scores::Scores,
    types::{Account, FromKeyValue, Qualifier, Status},
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
pub(super) const CSV_COLUMN_EXTRAS: &str = "csv column extras";
pub(super) const CUSTOMERS: &str = "customers";
pub(super) const DATA_SOURCES: &str = "data sources";
pub(super) const FILTERS: &str = "filters";
pub(super) const HOSTS: &str = "hosts";
pub(super) const MODELS: &str = "models";
pub(super) const MODEL_INDICATORS: &str = "model indicators";
const META: &str = "meta";
pub(super) const NETWORKS: &str = "networks";
pub(super) const NODES: &str = "nodes";
pub(super) const OUTLIERS: &str = "outliers";
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
pub(super) const TRIAGE_EXCLUSION_REASON: &str = "triage exclusion reason";
pub(super) const TRIAGE_POLICY: &str = "triage policy";
pub(super) const TRIAGE_RESPONSE: &str = "triage response";
pub(super) const TRUSTED_DNS_SERVERS: &str = "trusted DNS servers";
pub(super) const TRUSTED_USER_AGENTS: &str = "trusted user agents";

pub(crate) const MAP_NAMES: [&str; 36] = [
    ACCESS_TOKENS,
    ACCOUNTS,
    AGENTS,
    ALLOW_NETWORKS,
    BATCH_INFO,
    BLOCK_NETWORKS,
    CATEGORY,
    CLUSTER,
    COLUMN_STATS,
    CONFIGS,
    CSV_COLUMN_EXTRAS,
    CUSTOMERS,
    DATA_SOURCES,
    FILTERS,
    HOSTS,
    MODELS,
    MODEL_INDICATORS,
    META,
    NETWORKS,
    NODES,
    OUTLIERS,
    QUALIFIERS,
    EXTERNAL_SERVICES,
    SAMPLING_POLICY,
    SCORES,
    STATUSES,
    TEMPLATES,
    LABEL_DB,
    TIME_SERIES,
    TOR_EXIT_NODES,
    TRAFFIC_FILTER_RULES,
    TRIAGE_EXCLUSION_REASON,
    TRIAGE_POLICY,
    TRIAGE_RESPONSE,
    TRUSTED_DNS_SERVERS,
    TRUSTED_USER_AGENTS,
];

// Keys for the meta map.
pub(super) const EVENT_TAGS: &[u8] = b"event tags";
pub(super) const NETWORK_TAGS: &[u8] = b"network tags";
pub(super) const WORKFLOW_TAGS: &[u8] = b"workflow tags";

#[allow(clippy::module_name_repetitions)]
pub(crate) struct StateDb {
    inner: Option<rocksdb::OptimisticTransactionDB>,
    backup: PathBuf,
    db: PathBuf,
}

impl StateDb {
    pub fn open(path: &Path, backup: PathBuf) -> Result<Self> {
        Self::open_db(path).map(|db| Self {
            inner: Some(db),
            backup,
            db: path.to_owned(),
        })
    }

    #[must_use]
    pub(crate) fn access_tokens(&self) -> Table<'_, AccessToken> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<AccessToken>::open(inner).expect("{ACCESS_TOKENS} table must be present")
    }

    #[must_use]
    pub(crate) fn accounts(&self) -> Table<'_, Account> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Account>::open(inner).expect("{ACCOUNTS} table must be present")
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
    pub(crate) fn filters(&self) -> Table<'_, Filter> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Filter>::open(inner).expect("{FILTERS} table must be present")
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
    pub(crate) fn allow_networks(&self) -> IndexedTable<'_, AllowNetwork> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<AllowNetwork>::open(inner).expect("{ALLOW_NETWORKS} table must be present")
    }

    #[must_use]
    pub(crate) fn block_networks(&self) -> IndexedTable<'_, BlockNetwork> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<BlockNetwork>::open(inner).expect("{BLOCK_NETWORKS} table must be present")
    }

    #[must_use]
    pub(crate) fn sampling_policies(&self) -> IndexedTable<'_, SamplingPolicy> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<SamplingPolicy>::open(inner)
            .expect("{SAMPLING_POLICY} table must be present")
    }

    #[must_use]
    pub(crate) fn customers(&self) -> IndexedTable<'_, Customer> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Customer>::open(inner).expect("{CUSTOMERS} table must be present")
    }

    #[must_use]
    pub(crate) fn data_sources(&self) -> IndexedTable<'_, DataSource> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<DataSource>::open(inner).expect("{DATA_SOURCES} table must be present")
    }

    pub(crate) fn nodes(&self) -> NodeTable<'_> {
        let inner = self.inner.as_ref().expect("database must be open");
        NodeTable::open(inner).expect("{NETWORKS} table must be present")
    }

    #[must_use]
    pub(crate) fn triage_exclusion_reasons(&self) -> IndexedTable<'_, TriageExclusionReason> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<TriageExclusionReason>::open(inner)
            .expect("{TRIAGE_EXCLUSION_REASON} table must be present")
    }

    #[must_use]
    pub(crate) fn triage_policies(&self) -> IndexedTable<'_, TriagePolicy> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<TriagePolicy>::open(inner).expect("{TRIAGE_POLICY} table must be present")
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
    pub fn events(&self) -> event::EventDb<'_> {
        let inner = self.inner.as_ref().expect("database must be open");
        event::EventDb::new(inner)
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
    pub(crate) fn backup_configs(&self) -> Table<'_, BackupConfig> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<BackupConfig>::open(inner).expect("{CONFIGS} table must be present")
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

    pub fn restore_from_latest_backup(&mut self) -> Result<()> {
        let mut engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        let mut opts = rocksdb::backup::RestoreOptions::default();
        opts.set_keep_log_files(true);

        self.close();

        engine.restore_from_latest_backup(&self.db, &self.db, &opts)?;

        self.reboot()
    }

    pub fn restore_from_backup(&mut self, id: u32) -> Result<()> {
        let mut engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        let opts = rocksdb::backup::RestoreOptions::default();

        self.close();

        engine.restore_from_backup(&self.db, &self.db, &opts, id)?;

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

/// Represents a table that can be iterated over.
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

impl<'i, 'j, 'k, R> Iterable<'i, TableIter<'k, R>> for Table<'j, R>
where
    'j: 'k,
    'i: 'k,
    R: FromKeyValue,
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
        R: Indexable,
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
        R: Indexable,
    {
        self.indexed_map.insert_with_transaction(entry, txn)
    }

    /// Removes a record with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn remove(&self, id: u32) -> Result<Vec<u8>>
    where
        R: Indexable,
    {
        self.indexed_map.remove::<R>(id)
    }

    /// Removes a record with the given ID within a transaction.
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
        R: Indexable,
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

    /// Deactivates a key-value pair with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn deactivate(&self, id: u32) -> Result<Vec<u8>> {
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
fn open_rocksdb_backup_engine(
    path: &Path,
) -> Result<rocksdb::backup::BackupEngine, rocksdb::Error> {
    let opts = rocksdb::backup::BackupEngineOptions::new(path)?;
    let db_env = rocksdb::Env::new()?;
    rocksdb::backup::BackupEngine::open(&opts, &db_env)
}
