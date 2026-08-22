//! Routines to check the database format version and migrate it if necessary.
#![allow(clippy::too_many_lines)]
mod migration_structures;
use std::{
    fs::{File, create_dir_all, remove_file, rename},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use bincode::Options;
use num_traits::FromPrimitive;
use semver::{Version, VersionReq};
use tracing::{info, warn};

use crate::{
    AllowNetwork, BlockNetwork, Customer,
    event::{EventKind, resolve_stored_country_codes},
    geo::{CountryLookup, Ip2LocationResolver},
    migration::migration_structures::{
        AgentValueV0_47Alpha1, AgentValueV0_47Alpha2, AllowNetworkV0_42, BlockNetworkV0_42,
        BlocklistDceRpcFieldsStoredV0_42, BlocklistDceRpcFieldsStoredV0_44,
        BlocklistDhcpFieldsStoredV0_42, BlocklistDhcpFieldsStoredV0_44,
        ExternalServiceValueV0_47Alpha1, ExternalServiceValueV0_47Alpha2,
        HttpThreatFieldsStoredV0_43, HttpThreatFieldsStoredV0_44,
        migrate_event_stored_schema_to_v0_46, validate_event_stored_schema_v0_46,
    },
    tables::{NETWORK_TAGS, TRIAGE_EXCLUSION_REASON},
};

/// The range of versions that use the current database format.
///
/// The range should include all the earlier, released versions that use the
/// current database format, and exclude the first future version that uses a
/// new database format.
///
/// # Examples
///
/// ```rust
/// // [Case 1: Stable Patch Version, No Format Change]
/// // The current version is 0.4.1 and the database format hasn't been changed
/// // since 0.3.0. This should include future patch versions such as 0.4.2,
/// // 0.4.3, etc. since they won't change the database format.
/// const COMPATIBLE_VERSION: &str = ">=0.3,<0.5.0-alpha";
/// ```
///
/// ```rust
/// // [Case 2: Alpha Patch Version, No RocksDB Format Change]
/// // The current version is 3.4.6-alpha.2 and the database format hasn't been
/// // changed since 1.0.0. Future pre-release versions such as 3.4.6-alpha.3
/// // are compatible since they won't change the database format.
/// const COMPATIBLE_VERSION: &str = ">=1.0.0,<3.5.0-alpha";
/// ```
///
/// ```rust
/// // [Case 3: Transition to New Alpha Version, No RocksDB Format Change]
/// // The current version is 3.4.5 and the database format hasn't been changed
/// // since 1.0.0. The next version to pre-release is 3.5.0-alpha.1, if no
/// // database format change is involved, then compatible version should be
/// // extended to 3.5.0-alpha.1.
/// const COMPATIBLE_VERSION: &str = ">=1.0.0,<=3.5.0-alpha.1";
/// ```
///
/// ```rust
/// // [Case 4: Transition to Stable Major Version, No RocksDB Format Change]
/// // The current version is 3.4.5 and the database format hasn't been changed
/// // since 1.0.0. The next version to release is 3.5.0 (stable), if no
/// // database format change is involved, then migration is not needed, while
/// // compatible version should be extended to 3.5.0., including all future
/// // patch versions.
/// const COMPATIBLE_VERSION: &str = ">=1.0.0,<3.6.0-alpha";
/// ```
///
/// ```rust
/// // [Case 5: Transition from Alpha to Stable Version, No RocksDB Format Change]
/// // The current version is 3.4.5-alpha.3 and the database format hasn't been
/// // changed since 1.0.0. The next version to release is 3.5.0 (stable), with
/// // compatibility extended to future patch versions.
/// const COMPATIBLE_VERSION: &str = ">=1.0.0,<3.6.0-alpha";
/// ```
///
/// ```rust
/// // [Case 6: Transition to New Alpha Version, RocksDB Format Change]
/// // The current version is 3.4.5 and the database format is changing in
/// // 3.5.0-alpha.1. The compatibility is now restricted to 3.5.0-alpha.1,
/// // requiring a migration from the 1.0.0 format.
/// const COMPATIBLE_VERSION: &str = ">=3.5.0-alpha.1,<3.5.0-alpha.2";
/// // Migration: `migrate_1_0_to_3_5` must handle changes from 1.0.0 to
/// // 3.5.0-alpha.1.
/// ```
///
/// ```rust
/// // [Case 7: Transition Between Alpha Versions, RocksDB Format Change]
/// // The current version is 3.5.0-alpha.2 and the database format is changing in
/// // 3.5.0-alpha.3. The compatibility is now restricted to 3.5.0-alpha.3,
/// // requiring a migration from the 1.0.0 format.
/// const COMPATIBLE_VERSION: &str = ">=3.5.0-alpha.3,<3.5.0-alpha.4";
/// // Migration: `migrate_1_0_to_3_5` must handle changes from 1.0.0 to
/// // 3.5.0-alpha.3, including prior alpha changes.
///```
///
/// ```rust
/// // [Case 8: Transition from Alpha to Stable Version, RocksDB Format Finalized]
/// // The current version is 3.5.0-alpha.2 and the database format is
/// // finalized in 3.5.0. The compatibility is extended to all 3.5.0 versions,
/// // requiring a migration from the 1.0.0 format.
/// const COMPATIBLE_VERSION: &str = ">=3.5.0,<3.6.0-alpha";
/// // Migration: `migrate_1_0_to_3_5` must handle changes from 1.0.0 (last
/// // release that involves database format change) to 3.5.0, including
/// // all alpha changes finalized in 3.5.0.
/// ```
const COMPATIBLE_VERSION_REQ: &str = ">=0.47.0-alpha.2,<0.47.0-alpha.3";

/// Number of event records applied in each atomic migration write.
const EVENT_MIGRATION_BATCH_SIZE: usize = 100;

/// The name of the file recording the database format version.
const VERSION_FILE_NAME: &str = "VERSION";

/// The name of the temporary file that [`create_version_file`] renames over
/// [`VERSION_FILE_NAME`].
///
/// The name is fixed rather than unique, so every writer of a marker in one
/// directory collides with every other. Both writers this crate has require
/// exclusive access to each directory they touch for that reason:
/// `migrate_data_dir` runs once at startup, and [`write_version_markers`] is a
/// rollback step the caller serializes against it and against any other
/// rollback. In exchange, an interrupted write can leave behind only this one
/// file, which the next start recognizes.
const VERSION_TMP_FILE_NAME: &str = "VERSION.tmp";

/// Migrates the data directory to the up-to-date format if necessary.
///
/// Migration is supported between released versions only. The prelease versions (alpha, beta,
/// etc.) should be assumed to be incompatible with each other.
/// Pass a shared `IP2Location` database handle when available so endpoint
/// country-code fields can be resolved during the stored event schema
/// migration. If no locator is provided, endpoint country codes remain at the
/// pre-lookup value `ZZ`.
///
/// # Errors
///
/// Returns an error if the data directory doesn't exist and cannot be created,
/// or if the data directory exists but is in the format incompatible with the
/// current version.
pub fn migrate_data_dir<P: AsRef<Path>>(
    data_dir: P,
    backup_dir: P,
    ip2location: Option<Arc<ip2location::DB>>,
) -> Result<()> {
    type Migration = (
        VersionReq,
        Version,
        fn(&Path, &Path, Option<&dyn CountryLookup>) -> anyhow::Result<()>,
    );

    let data_dir = data_dir.as_ref();
    let backup_dir = backup_dir.as_ref();
    let resolver = ip2location.map(Ip2LocationResolver::new);
    let locator = resolver
        .as_ref()
        .map(|resolver| resolver as &dyn CountryLookup);

    let Ok(compatible) = VersionReq::parse(COMPATIBLE_VERSION_REQ) else {
        unreachable!("COMPATIBLE_VERSION_REQ must be valid")
    };

    let (data, data_ver) = retrieve_or_create_version(data_dir)?;
    let (backup, backup_ver) = retrieve_or_create_version(backup_dir)?;

    if data_ver != backup_ver {
        return Err(anyhow!(
            "mismatched database version {data_ver} and backup version {backup_ver}"
        ));
    }

    let mut version = data_ver;
    if compatible.matches(&version) {
        return Ok(());
    }

    // A list of migrations where each item is a tuple of (version requirement, to version,
    // migration function).
    //
    // Every migration body below writes only inside `data_dir/states.db`. A
    // rollback snapshot taken before an update therefore has to cover that one
    // database and nothing else, and restoring it does not restore the two
    // `VERSION` files, which this function writes after the whole chain
    // succeeds and which a rollback must put back separately, through
    // `write_version_markers`.
    //
    // * The "version requirement" should include all the earlier, released versions that use the
    //   database format the migration function can handle, and exclude the first future version
    //   that uses a new database format.
    // * The "to version" should be the first future version that uses a new database format.
    // * The "migration function" should migrate the database from the version before "to version"
    //   to "to version". The function name should be in the form of "migrate_A_to_B" where A is
    //   the first version (major.minor) in the "version requirement" and B is the "to version"
    //   (major.minor). (NOTE: Once we release 1.0.0, A and B will contain the major version only.)
    let migration: Vec<Migration> = vec![
        (
            VersionReq::parse(">=0.42.0,<0.43.0")?,
            Version::parse("0.43.0")?,
            |data_dir, _backup_dir, _locator| migrate_0_42_to_0_43(data_dir),
        ),
        (
            VersionReq::parse(">=0.43.0,<0.44.0")?,
            Version::parse("0.44.0")?,
            |data_dir, _backup_dir, _locator| migrate_0_43_to_0_44(data_dir),
        ),
        (
            VersionReq::parse(">=0.44.0,<0.45.0")?,
            Version::parse("0.45.0")?,
            |data_dir, _backup_dir, _locator| migrate_0_44_to_0_45(data_dir),
        ),
        (
            VersionReq::parse(">=0.45.0,<0.46.0")?,
            Version::parse("0.46.0")?,
            |data_dir, _backup_dir, locator| migrate_0_45_to_0_46(data_dir, locator),
        ),
        (
            VersionReq::parse(">=0.46.0,<0.47.0-alpha.2")?,
            Version::parse("0.47.0-alpha.2")?,
            |data_dir, _backup_dir, _locator| migrate_0_46_to_0_47(data_dir),
        ),
    ];

    while let Some((_req, to, m)) = migration
        .iter()
        .find(|(req, _to, _m)| req.matches(&version))
    {
        info!("Migrating database to {to}");
        m(data_dir, backup_dir, locator)?;
        version = to.clone();
        if compatible.matches(&version) {
            create_version_file(&backup, env!("CARGO_PKG_VERSION"))
                .context("failed to update VERSION")?;
            return create_version_file(&data, env!("CARGO_PKG_VERSION"))
                .context("failed to update VERSION");
        }
    }

    Err(anyhow!("migration from {version} is not supported"))
}

fn migrate_0_45_to_0_46(data_dir: &Path, locator: Option<&dyn CountryLookup>) -> Result<()> {
    migrate_event_country_codes(data_dir, locator).map(|_| ())
}

/// Migrates a database in any supported 0.46.x or 0.47.0-alpha.1 format to
/// 0.47.0-alpha.2.
///
/// The two alpha formats share one migration because the format is still
/// changing during the prerelease: an alpha-to-alpha change extends the
/// migration that produced the earlier alpha instead of adding one beside it,
/// so a 0.46.x database reaches the newest alpha in a single step.
///
/// Opening the pinned 0.47.0-alpha.2 list with
/// [`create_missing_column_families`](rocksdb::Options::create_missing_column_families)
/// creates whichever of the customer deletion jobs, core components and
/// operation attempts families is absent and leaves the rest alone, so a retry
/// after an interrupted run finds nothing to do rather than failing on a family
/// that already exists.
fn migrate_0_46_to_0_47(data_dir: &Path) -> Result<()> {
    let db_path = data_dir.join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(true);

    let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, MAP_NAMES_V0_47_ALPHA_2)
            .context("failed to open database for the 0.47.0-alpha.2 migration")?;

    migrate_install_state::<AgentValueV0_47Alpha2, AgentValueV0_47Alpha1>(
        &db,
        crate::tables::AGENTS,
        "agent",
    )?;
    migrate_install_state::<ExternalServiceValueV0_47Alpha2, ExternalServiceValueV0_47Alpha1>(
        &db,
        crate::tables::EXTERNAL_SERVICES,
        "external service",
    )?;
    Ok(())
}

/// Rewrites every value in `cf_name` that predates the install-state fields.
///
/// `Current` is probed first, so a row already carrying the four fields is
/// recognized as it is and its stored bytes are left untouched; only a row that
/// fails that probe is read back as `Old` and rewritten with the documented
/// defaults. A value that matches neither layout aborts the migration with its
/// raw key and both decoding errors, rather than being skipped or overwritten.
///
/// Both layouts are table values, so they are encoded with
/// [`bincode::DefaultOptions`] — the varint encoding `crate::tables` uses — and
/// not with the fixint helpers the event records go through.
fn migrate_install_state<Current, Old>(
    db: &rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
    cf_name: &str,
    record: &str,
) -> Result<()>
where
    Current: serde::Serialize + serde::de::DeserializeOwned + From<Old>,
    Old: serde::de::DeserializeOwned,
{
    let cf = db
        .cf_handle(cf_name)
        .with_context(|| format!("{cf_name} column family not found"))?;

    let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();
    let mut converted = 0usize;
    let mut already_current = 0usize;

    for entry in db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
        let (key, value) = entry.with_context(|| format!("failed to read a {record} record"))?;
        let Err(current_error) = bincode::DefaultOptions::new().deserialize::<Current>(&value)
        else {
            already_current += 1;
            continue;
        };
        let old: Old = bincode::DefaultOptions::new()
            .deserialize(&value)
            .map_err(|previous_error| {
                anyhow!(
                    "{record} record with key {} matches neither the current nor the previous stored schema: current schema error: {current_error}; previous schema error: {previous_error}",
                    data_encoding::HEXLOWER.encode(&key)
                )
            })?;
        let migrated = bincode::DefaultOptions::new()
            .serialize(&Current::from(old))
            .with_context(|| format!("failed to serialize the migrated {record} record"))?;
        batch.put_cf(&cf, &key, migrated);
        converted += 1;

        if batch.len() >= EVENT_MIGRATION_BATCH_SIZE {
            write_migration_batch(db, &mut batch, record)?;
        }
    }

    write_migration_batch(db, &mut batch, record)?;
    info!(
        "Install-state migration of {record} records complete: converted_count={converted}, already_current_count={already_current}"
    );
    Ok(())
}

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct EventMigrationStats {
    processed: usize,
    converted: usize,
    already_current: usize,
}

pub(crate) fn migrate_event_country_codes(
    data_dir: &Path,
    locator: Option<&dyn CountryLookup>,
) -> Result<EventMigrationStats> {
    let db_path = data_dir.join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, &db_path)?;
    let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, column_families)
            .context("failed to open database for event country-code migration")?;

    let mut stats = EventMigrationStats::default();
    let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();

    for entry in db.iterator(rocksdb::IteratorMode::Start) {
        let (key, value) = entry.context("failed to read event entry")?;
        if key.len() != 16 {
            continue;
        }
        let key_i128 = i128::from_be_bytes(key.as_ref().try_into().expect("checked length"));
        let kind_num = (key_i128 & 0xffff_ffff_0000_0000) >> 32;
        let Some(kind) = EventKind::from_i128(kind_num) else {
            continue;
        };

        match validate_event_stored_schema_v0_46(kind, &value) {
            Ok(()) => {
                stats.already_current += 1;
            }
            Err(current_error) => {
                let v0_46 = migrate_event_stored_schema_to_v0_46(kind, &value).map_err(
                    |previous_error| {
                        anyhow!(
                            "event record with key {key_i128} matches neither the previous nor the current stored schema: previous schema error: {previous_error:#}; current schema error: {current_error:#}"
                        )
                    },
                )?;
                let resolved = resolve_stored_country_codes(kind, &v0_46, locator)?;
                if resolved.as_slice() != value.as_ref() {
                    batch.put(&key, resolved);
                }
                stats.converted += 1;
            }
        }
        stats.processed += 1;

        if batch.len() >= EVENT_MIGRATION_BATCH_SIZE {
            write_migration_batch(&db, &mut batch, "event country-code")?;
        }
    }

    write_migration_batch(&db, &mut batch, "event country-code")?;
    info!(
        "Event country-code migration complete: processed_count={}, converted_count={}, already_current_count={}",
        stats.processed, stats.converted, stats.already_current
    );
    Ok(stats)
}

/// Commits and clears `batch`, naming `what` in the error if the write fails.
fn write_migration_batch(
    db: &rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
    batch: &mut rocksdb::WriteBatchWithTransaction<true>,
    what: &str,
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }

    let pending = std::mem::take(batch);
    db.write(pending)
        .with_context(|| format!("failed to commit {what} migration batch"))
}

/// Column family names for version 0.42 (includes the deprecated "account policy" column family)
#[cfg(test)]
const MAP_NAMES_V0_42: [&str; 36] = [
    "access_tokens",
    "accounts",
    "account policy",
    "agents",
    "allow networks",
    "batch_info",
    "block networks",
    "category",
    "cluster",
    "column stats",
    "configs",
    "csv column extras",
    "customers",
    "data sources",
    "filters",
    "hosts",
    "models",
    "model indicators",
    "meta",
    "networks",
    "nodes",
    "outliers",
    "qualifiers",
    "external services",
    "sampling policy",
    "scores",
    "statuses",
    "templates",
    "TI database",
    "time series",
    "Tor exit nodes",
    "traffic filter rules",
    "triage policy",
    "triage response",
    "trusted DNS servers",
    "trusted user agents",
];

/// Lists column family names shared by database formats 0.43 through 0.46.
#[cfg(test)]
const MAP_NAMES_V0_43_TO_V0_46: [&str; 36] = [
    "access_tokens",
    "accounts",
    "agents",
    "allow networks",
    "batch_info",
    "block networks",
    "category",
    "cluster",
    "column stats",
    "configs",
    "csv column extras",
    "customers",
    "data sources",
    "filters",
    "hosts",
    "models",
    "model indicators",
    "meta",
    "networks",
    "nodes",
    "outliers",
    "qualifiers",
    "external services",
    "sampling policy",
    "scores",
    "statuses",
    "templates",
    "label database",
    "time series",
    "Tor exit nodes",
    "traffic filter rules",
    "triage exclusion reason",
    "triage policy",
    "triage response",
    "trusted DNS servers",
    "trusted user agents",
];

/// Lists column family names for database format 0.47.0-alpha.1, which added
/// "customer deletion jobs" to the 0.43-through-0.46 set.
#[cfg(test)]
const MAP_NAMES_V0_47_ALPHA_1: [&str; 37] = [
    "access_tokens",
    "accounts",
    "agents",
    "allow networks",
    "batch_info",
    "block networks",
    "category",
    "cluster",
    "column stats",
    "configs",
    "csv column extras",
    "customers",
    "customer deletion jobs",
    "data sources",
    "filters",
    "hosts",
    "models",
    "model indicators",
    "meta",
    "networks",
    "nodes",
    "outliers",
    "qualifiers",
    "external services",
    "sampling policy",
    "scores",
    "statuses",
    "templates",
    "label database",
    "time series",
    "Tor exit nodes",
    "traffic filter rules",
    "triage exclusion reason",
    "triage policy",
    "triage response",
    "trusted DNS servers",
    "trusted user agents",
];

/// Lists column family names for database format 0.47.0-alpha.2, which added
/// "core components" and "operation attempts" to the 0.47.0-alpha.1 set.
///
/// The names are written out rather than taken from
/// [`crate::tables::MAP_NAMES`], as every other list here is: this one is what
/// [`migrate_0_46_to_0_47`] creates, and a later rename or format bump must
/// change what a future migration creates, never what this historical one did.
const MAP_NAMES_V0_47_ALPHA_2: [&str; 39] = [
    "access_tokens",
    "accounts",
    "agents",
    "allow networks",
    "batch_info",
    "block networks",
    "category",
    "cluster",
    "column stats",
    "configs",
    "core components",
    "csv column extras",
    "customers",
    "customer deletion jobs",
    "data sources",
    "filters",
    "hosts",
    "models",
    "model indicators",
    "meta",
    "networks",
    "nodes",
    "operation attempts",
    "outliers",
    "qualifiers",
    "external services",
    "sampling policy",
    "scores",
    "statuses",
    "templates",
    "label database",
    "time series",
    "Tor exit nodes",
    "traffic filter rules",
    "triage exclusion reason",
    "triage policy",
    "triage response",
    "trusted DNS servers",
    "trusted user agents",
];

/// Returns the column families an intermediate migration must open.
///
/// `VERSION` is updated only after the complete migration chain succeeds, so a
/// process that stops part-way leaves a marker older than the families that are
/// physically there. A retry then starts from that older version and reaches
/// these migrations again, and RocksDB refuses an open that names a family the
/// database does not have or omits one it does. The physical set is therefore
/// read back rather than chosen from a static list or inferred from a count:
/// between 0.46 and 0.47.0-alpha.2 alone it may hold the 36 legacy families,
/// all 37 of 0.47.0-alpha.1, or those plus either or both of the two families
/// 0.47.0-alpha.2 adds. Opening exactly what is there lets the retry run
/// through to [`migrate_0_46_to_0_47`], which repairs whichever families are
/// still missing.
fn map_names_for_existing_format(opts: &rocksdb::Options, db_path: &Path) -> Result<Vec<String>> {
    existing_map_names(opts, db_path)
}

/// Returns the non-default column families that physically exist.
fn existing_map_names(opts: &rocksdb::Options, db_path: &Path) -> Result<Vec<String>> {
    rocksdb::OptimisticTransactionDB::<rocksdb::SingleThreaded>::list_cf(opts, db_path)
        .context("failed to list column families for migration")
        .map(|names| names.into_iter().filter(|name| name != "default").collect())
}

/// Returns column family names from 0.43 without "triage exclusion reason".
#[cfg(test)]
fn map_names_v0_43_without_triage_exclusion_reason() -> Vec<&'static str> {
    MAP_NAMES_V0_43_TO_V0_46
        .iter()
        .copied()
        .filter(|name| *name != TRIAGE_EXCLUSION_REASON)
        .collect()
}

fn migrate_0_42_to_0_43(data_dir: &Path) -> Result<()> {
    let db_path = data_dir.join("states.db");

    // Step 1: Drop "account policy" column family if it exists (from 0.42)
    migrate_drop_account_policy(&db_path)?;

    // Step 2: Rename "TI database" to "label database"
    migrate_rename_tidb_to_label_db(&db_path)?;

    // Step 3: Create the "triage exclusion reason" column family
    migrate_create_triage_exclusion_reason_cf(&db_path)?;

    // Step 4: Migrate AllowNetwork and BlockNetwork to customer-specific format
    migrate_customer_specific_networks(&db_path)?;

    Ok(())
}

fn migrate_0_43_to_0_44(data_dir: &Path) -> Result<()> {
    // Migrate network tags to customer-scoped format
    migrate_network_tags_to_customer_scoped(data_dir)?;

    // Migrate Network table to enforce global name uniqueness
    migrate_network_cf(data_dir)?;

    // Migrate event fields in a single pass over the events database:
    // - HttpThreat: cluster_id from Option<usize> to Option<u32>
    // - BlocklistDceRpc: replace rtt/named_pipe/endpoint/operation with context/request
    // - BlocklistDhcp: add the new `options` field
    migrate_event_fields(data_dir)?;

    Ok(())
}

fn migrate_0_44_to_0_45(data_dir: &Path) -> Result<()> {
    // Migrate triage policy Confidence.threat_category from EventCategory to
    // Option<EventCategory>, wrapping old values in Some(...)
    migrate_triage_policy_confidence(data_dir)?;

    Ok(())
}

/// Migrates triage policy records so that `Confidence.threat_category` is
/// wrapped in `Some(...)` to match the new `Option<EventCategory>` layout.
fn migrate_triage_policy_confidence(dir: &Path) -> Result<()> {
    use bincode::Options;

    use crate::Indexable;
    use crate::migration::migration_structures::TriagePolicyV0_44;

    let db_path = dir.join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, &db_path)?;

    let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, column_families)
            .context("Failed to open database for triage policy migration")?;

    let cf = db
        .cf_handle(crate::tables::TRIAGE_POLICY)
        .context("triage policy column family not found")?;

    let entries: Vec<(Vec<u8>, Vec<u8>)> = db
        .iterator_cf(&cf, rocksdb::IteratorMode::Start)
        .filter_map(|item| match item {
            Ok((key, value)) if !key.is_empty() => Some(Ok((key.to_vec(), value.to_vec()))),
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<_, _>>()
        .context("failed to read triage policy entries")?;

    let txn = db.transaction();
    for (key, value) in &entries {
        let old: TriagePolicyV0_44 = bincode::DefaultOptions::new()
            .deserialize(value)
            .context("failed to deserialize old triage policy")?;
        let new = crate::TriagePolicy::from(old);
        txn.put_cf(&cf, key, new.value())
            .context("failed to write migrated triage policy")?;
    }
    txn.commit()
        .context("failed to commit triage policy migration")?;

    info!(
        "Migrated {} triage policy records (Confidence.threat_category -> Option)",
        entries.len()
    );
    Ok(())
}

/// Drops the "account policy" column family from the main database only.
///
/// This function handles both the case where the column family exists (0.42.x)
/// and where it has already been dropped (0.43.0-alpha.1).
fn migrate_drop_account_policy(db_path: &Path) -> Result<()> {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);

    let existing = existing_map_names(&opts, db_path)?;
    if !existing.iter().any(|name| name == "account policy") {
        return Ok(());
    }

    let mut db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, &existing)
            .context("Failed to open database for account policy removal")?;
    info!("Dropping 'account policy' column family");
    db.drop_cf("account policy")
        .context("Failed to drop 'account policy' column family")?;

    Ok(())
}

/// Renames the "TI database" column family to "label database" in the main database only
fn migrate_rename_tidb_to_label_db(db_path: &Path) -> Result<()> {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);

    let existing = existing_map_names(&opts, db_path)?;
    let ti_database_exists = existing.iter().any(|name| name == "TI database");
    if !ti_database_exists {
        return Ok(());
    }
    let label_database_exists = existing.iter().any(|name| name == "label database");

    let mut db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, &existing)
            .context("Failed to open database for TI database rename")?;

    let data = {
        let old_cf = db
            .cf_handle("TI database")
            .context("Failed to get 'TI database' column family handle")?;
        db.iterator_cf(old_cf, rocksdb::IteratorMode::Start)
            .map(|item| {
                let (key, value) = item.context("Failed to iterate 'TI database'")?;
                Ok((key.to_vec(), value.to_vec()))
            })
            .collect::<Result<Vec<_>>>()?
    };

    info!("Renaming 'TI database' column family to 'label database'");

    if !label_database_exists {
        db.create_cf("label database", &rocksdb::Options::default())
            .context("Failed to create 'label database' column family")?;
    }

    let new_cf = db
        .cf_handle("label database")
        .context("Failed to get 'label database' column family handle")?;

    for (key, value) in &data {
        match db
            .get_cf(new_cf, key)
            .context("Failed to read existing data from 'label database'")?
        {
            Some(existing) if existing.as_slice() != value.as_slice() => {
                return Err(anyhow!(
                    "conflicting values for key in 'TI database' and 'label database'"
                ));
            }
            Some(_) => {}
            None => db
                .put_cf(new_cf, key, value)
                .context("Failed to copy data to 'label database'")?,
        }
    }

    // Drop the old "TI database" column family
    db.drop_cf("TI database")
        .context("Failed to drop 'TI database' column family")?;

    info!("Successfully renamed 'TI database' to 'label database'");
    Ok(())
}

/// Creates the "triage exclusion reason" column family in the main database.
fn migrate_create_triage_exclusion_reason_cf(db_path: &Path) -> Result<()> {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);

    let existing = existing_map_names(&opts, db_path)?;
    if existing.iter().any(|name| name == TRIAGE_EXCLUSION_REASON) {
        return Ok(());
    }

    let mut db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, &existing)
            .context("Failed to open database for triage exclusion reason creation")?;

    db.create_cf(TRIAGE_EXCLUSION_REASON, &rocksdb::Options::default())
        .context("Failed to create 'triage exclusion reason' column family")?;
    Ok(())
}

/// A trait for creating a new, customer-specific network structure from an old one.
trait CustomerSpecificNetwork<T>: crate::Indexable + Sized {
    /// Creates a new instance from a version 0.42 object and a customer ID.
    fn from_v0_42(old: T, customer_id: u32) -> Self;
}

impl CustomerSpecificNetwork<AllowNetworkV0_42> for AllowNetwork {
    fn from_v0_42(old: AllowNetworkV0_42, customer_id: u32) -> Self {
        Self {
            id: u32::MAX, // A temporary ID that will be replaced.
            name: old.name,
            networks: old.networks,
            description: old.description,
            customer_id,
        }
    }
}

impl CustomerSpecificNetwork<BlockNetworkV0_42> for BlockNetwork {
    fn from_v0_42(old: BlockNetworkV0_42, customer_id: u32) -> Self {
        Self {
            id: u32::MAX, // A temporary ID that will be replaced.
            name: old.name,
            networks: old.networks,
            description: old.description,
            customer_id,
        }
    }
}

/// A generic function to migrate a list of items in a column family.
fn migrate_list<T, K>(
    db: &rocksdb::OptimisticTransactionDB,
    txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
    customer_ids: &[u32],
    cf_name: &str,
) -> Result<()>
where
    T: CustomerSpecificNetwork<K> + crate::types::FromKeyValue + std::fmt::Debug,
    K: serde::de::DeserializeOwned + Clone,
{
    use crate::collections::KeyIndex;

    let cf = db
        .cf_handle(cf_name)
        .ok_or_else(|| anyhow!("'{cf_name}' column family not found"))?;

    let entries_to_migrate = db
        .iterator_cf(cf, rocksdb::IteratorMode::Start)
        .filter_map(|item| match item {
            // The empty key is reserved for the `KeyIndex`, so we process only entries
            // with non-empty keys.
            Ok((key, value)) if !key.is_empty() => Some(Ok((key.to_vec(), value.to_vec()))),
            Ok(_) => None, // Skip the index entry.
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<Vec<(Vec<u8>, Vec<u8>)>, _>>()?;

    if entries_to_migrate.is_empty() {
        info!("No entries to migrate in '{cf_name}', skipping.");
        return Ok(());
    }

    let current_entry_count = entries_to_migrate
        .iter()
        .filter(|(key, value)| {
            <T as crate::types::FromKeyValue>::from_key_value(key, value).is_ok()
        })
        .count();
    if current_entry_count == entries_to_migrate.len() {
        info!("Entries in '{cf_name}' are already customer-specific, skipping.");
        return Ok(());
    }
    if current_entry_count != 0 {
        return Err(anyhow!(
            "'{cf_name}' contains a mix of old and customer-specific entries"
        ));
    }

    let mut new_index = KeyIndex::default();
    for (old_key, old_value) in &entries_to_migrate {
        txn.delete_cf(cf, old_key)?;

        let old_entry: K = bincode::DefaultOptions::new()
            .deserialize(old_value)
            .with_context(|| format!("failed to deserialize old entry for '{cf_name}'"))?;

        for &customer_id in customer_ids {
            let mut new_entry = T::from_v0_42(old_entry.clone(), customer_id);
            let new_id = new_index.insert(&new_entry.key())?;
            new_entry.set_index(new_id);
            txn.put_cf(cf, new_entry.indexed_key(), new_entry.value())?;
        }
    }

    let index_bytes = bincode::DefaultOptions::new()
        .serialize(&new_index)
        .context("failed to serialize index")?;
    txn.put_cf(cf, [], &index_bytes)?;

    info!(
        "Migrated {} entries for '{cf_name}'.",
        entries_to_migrate.len(),
    );

    Ok(())
}

/// The main migration function to convert `AllowNetwork` and `BlockNetwork` to a
/// customer-specific format. This function manages transactions and calls the generic
/// migration function.
fn migrate_customer_specific_networks(db_path: &Path) -> Result<()> {
    info!("Migrating AllowNetwork and BlockNetwork to customer-specific format");

    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, db_path)?;

    let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, column_families)
            .context("Failed to open database")?;

    // Fetches all customer IDs once.
    let customer_ids = {
        let cf = db
            .cf_handle("customers")
            .ok_or_else(|| anyhow!("customers column family not found"))?;
        db.iterator_cf(cf, rocksdb::IteratorMode::Start)
            .map(|item| {
                let (key, value) = item?;
                // The empty key is reserved for the `KeyIndex`, so we skip it to process
                // only the actual customer data.
                if key.is_empty() {
                    return Ok(None);
                }
                let customer: Customer = bincode::DefaultOptions::new().deserialize(&value)?;
                Ok(Some(customer.id))
            })
            .filter_map(Result::transpose)
            .collect::<Result<Vec<u32>>>()
            .context("failed to deserialize customer")?
    };
    info!("Found {} customer(s) for migration.", customer_ids.len());

    // Starts a single transaction.
    let txn = db.transaction();

    // Calls the generic function for each type.
    migrate_list::<AllowNetwork, AllowNetworkV0_42>(&db, &txn, &customer_ids, "allow networks")?;
    migrate_list::<BlockNetwork, BlockNetworkV0_42>(&db, &txn, &customer_ids, "block networks")?;

    // Commits the transaction once after all operations are done.
    txn.commit().context("failed to commit migration")?;
    info!("Successfully migrated AllowNetwork and BlockNetwork");
    Ok(())
}

/// Migrates network tags in a single database to customer-scoped format.
fn migrate_network_tags_to_customer_scoped(dir: &Path) -> Result<()> {
    use bincode::Options;

    use crate::collections::KeyIndex;
    use crate::tables::{CUSTOMERS, META};

    let db_path = dir.join("states.db");

    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, &db_path)?;

    let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, column_families)
            .context("Failed to open database for network tag migration")?;

    // Find the smallest customer ID from the customer_map
    let smallest_customer_id = {
        let cf = db
            .cf_handle(CUSTOMERS)
            .ok_or_else(|| anyhow!("customers column family not found"))?;

        // Read the index to get all customer IDs
        let Some(index_bytes) = db.get_cf(cf, []).context("failed to read customer index")? else {
            info!("No customers found, skipping network tag migration");
            return Ok(());
        };

        let index = KeyIndex::from_bytes(&index_bytes).context("invalid customer index")?;
        let customer_ids: Vec<u32> = index.iter().map(|(id, _)| id).collect();

        if customer_ids.is_empty() {
            info!("No customers found, skipping network tag migration");
            return Ok(());
        }

        *customer_ids.iter().min().expect("non-empty list")
    };

    info!(
        "Migrating network tags to customer-scoped format with customer_id={}",
        smallest_customer_id
    );

    // Get the meta column family which contains network tags
    let meta_cf = db
        .cf_handle(META)
        .ok_or_else(|| anyhow!("meta column family not found"))?;

    // Read the network tags index
    let Some(index_bytes) = db
        .get_cf(meta_cf, NETWORK_TAGS)
        .context("failed to read network tags index")?
    else {
        info!("No network tags found, migration complete");
        return Ok(());
    };

    let index = KeyIndex::from_bytes(&index_bytes).context("invalid network tags index")?;

    let prefix = format!("{smallest_customer_id}\0");

    // Collect tags that need migration
    let mut tags_to_migrate: Vec<(u32, Vec<u8>)> = Vec::new();
    for (id, key) in index.iter() {
        if !key.contains(&0) {
            // Not prefixed, needs migration
            tags_to_migrate.push((id, key.to_vec()));
        }
    }

    if tags_to_migrate.is_empty() {
        info!("No unprefixed network tags found, migration complete");
        return Ok(());
    }

    // Create new index with prefixed keys
    let mut new_index = index;

    for (id, old_key) in &tags_to_migrate {
        // Create new prefixed key
        let mut new_key = prefix.as_bytes().to_vec();
        new_key.extend(old_key);

        // Update the index entry
        new_index
            .update(*id, &new_key)
            .with_context(|| format!("failed to update index for tag id {id}"))?;
    }

    // Write the updated index
    let serialized_index = bincode::DefaultOptions::new()
        .serialize(&new_index)
        .context("failed to serialize updated network tags index")?;

    db.put_cf(meta_cf, NETWORK_TAGS, &serialized_index)
        .context("failed to write updated network tags index")?;

    info!(
        "Successfully migrated {} network tags to customer-scoped format",
        tags_to_migrate.len()
    );

    Ok(())
}

/// Migrates the Network table from 0.43 to 0.44.
///
/// This migration:
/// 1. Reads all existing Network entries (old format: key = name + id, value without id)
/// 2. Deduplicates by name, keeping only the entry with the smallest id
/// 3. Clears the network column family
/// 4. Re-inserts networks with new format: key = name only, value contains id (no `customer_ids`)
fn migrate_network_cf(data_dir: &Path) -> Result<()> {
    let db_path = data_dir.join("states.db");

    info!("Migrating Network table to enforce global name uniqueness");

    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, &db_path)?;
    let column_families: Vec<&str> = column_families.iter().map(String::as_str).collect();

    migrate_network_cf_inner(&db_path, &opts, &column_families)?;

    info!("Successfully migrated Network table");
    Ok(())
}

/// Migrates the network column family in a single database.
#[allow(clippy::items_after_statements)]
fn migrate_network_cf_inner(
    db_path: &Path,
    opts: &rocksdb::Options,
    cf_names: &[&str],
) -> Result<()> {
    use std::collections::HashMap;
    use std::mem::size_of;

    use bincode::Options;
    use serde::{Deserialize, Serialize};

    use self::migration_structures::NetworkValueV0_43;

    // New value format: id + description + networks + tag_ids + creation_time (no customer_ids)
    #[derive(Serialize)]
    struct NewNetworkValue {
        id: u32,
        description: String,
        networks: crate::types::HostNetworkGroup,
        tag_ids: Vec<u32>,
        creation_time: chrono::DateTime<chrono::Utc>,
    }

    // Build a new index using the same structure as KeyIndex
    // KeyIndex is a Vec<KeyIndexEntry> + available: u32 + inactive: Option<u32>
    #[derive(Clone, Deserialize, Serialize)]
    enum KeyIndexEntry {
        Key(Vec<u8>),
        Index(u32),
        Inactive(Option<u32>),
    }

    #[derive(Default, Deserialize, Serialize)]
    struct KeyIndex {
        keys: Vec<KeyIndexEntry>,
        available: u32,
        inactive: Option<u32>,
    }

    let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(opts, db_path, cf_names)
            .context("Failed to open database for network migration")?;

    let cf = db
        .cf_handle("networks")
        .ok_or_else(|| anyhow!("networks column family not found"))?;

    // Step 1: Read all existing entries and collect by name
    // Old key format: name bytes + id (4 bytes big-endian)
    // Old value format: NetworkValueV0_43 (without id, with customer_ids)
    let mut networks_by_name: HashMap<String, (u32, NetworkValueV0_43)> = HashMap::new();
    let mut duplicate_count = 0usize;

    let iter = db.iterator_cf(cf, rocksdb::IteratorMode::Start);
    for item in iter {
        let (key, value) = item.context("Failed to read network entry")?;

        // Skip the index entry (empty key)
        if key.is_empty() {
            continue;
        }

        // Parse old key format: name + id (4 bytes)
        if key.len() < size_of::<u32>() {
            info!("Skipping malformed network key (too short)");
            continue;
        }

        let (name_bytes, id_bytes) = key.split_at(key.len() - size_of::<u32>());
        let name = match std::str::from_utf8(name_bytes) {
            Ok(n) => n.to_owned(),
            Err(e) => {
                info!("Skipping network with invalid UTF-8 name: {e}");
                continue;
            }
        };

        let mut buf = [0u8; size_of::<u32>()];
        buf.copy_from_slice(id_bytes);
        let id = u32::from_be_bytes(buf);

        let old_value: NetworkValueV0_43 = bincode::DefaultOptions::new()
            .deserialize(&value)
            .context("Failed to deserialize old network value")?;

        // Keep entry with smallest id for each name
        match networks_by_name.get(&name) {
            Some((existing_id, _)) if *existing_id <= id => {
                duplicate_count += 1;
                info!(
                    "Discarding duplicate network '{}' with id {} (keeping id {})",
                    name, id, existing_id
                );
            }
            Some((existing_id, _)) => {
                duplicate_count += 1;
                info!(
                    "Replacing network '{}' id {} with smaller id {}",
                    name, existing_id, id
                );
                networks_by_name.insert(name, (id, old_value));
            }
            None => {
                networks_by_name.insert(name, (id, old_value));
            }
        }
    }

    info!(
        "Found {} unique networks, discarded {} duplicates",
        networks_by_name.len(),
        duplicate_count
    );

    // Step 2: Clear the network column family
    // We need to delete all keys
    let txn = db.transaction();
    let iter = db.iterator_cf(cf, rocksdb::IteratorMode::Start);
    for item in iter {
        let (key, _) = item.context("Failed to read key for deletion")?;
        txn.delete_cf(cf, &key)
            .context("Failed to delete old network entry")?;
    }
    txn.commit()
        .context("Failed to commit deletion transaction")?;

    // Step 3: Re-insert with new format
    // New key format: name bytes only (for global uniqueness)

    // Sort entries by id to maintain proper index order
    let mut entries: Vec<_> = networks_by_name.into_iter().collect();
    entries.sort_by_key(|(_, (id, _))| *id);

    let mut key_index = KeyIndex::default();

    let txn = db.transaction();
    for (name, (id, old_value)) in &entries {
        let new_value = NewNetworkValue {
            id: *id,
            description: old_value.description.clone(),
            networks: old_value.networks.clone(),
            tag_ids: old_value.tag_ids.clone(),
            creation_time: old_value.creation_time,
        };

        let value_bytes = bincode::DefaultOptions::new()
            .serialize(&new_value)
            .context("Failed to serialize new network value")?;

        // New key is just the name
        let key = name.as_bytes();

        txn.put_cf(cf, key, value_bytes)
            .context("Failed to insert migrated network")?;

        // We'll rebuild the index after all inserts to preserve gaps correctly.
    }

    if !entries.is_empty() {
        let max_id = entries
            .last()
            .map(|(_, (id, _))| *id)
            .expect("non-empty entries");
        let len = usize::try_from(max_id)
            .context("Too many index entries")?
            .saturating_add(1);

        let mut keys = vec![KeyIndexEntry::Index(0); len];
        let mut used = vec![false; len];

        for (name, (id, _)) in &entries {
            let idx = usize::try_from(*id).context("Too many index entries")?;
            keys[idx] = KeyIndexEntry::Key(name.as_bytes().to_vec());
            used[idx] = true;
        }

        let gaps: Vec<usize> = used
            .iter()
            .enumerate()
            .filter_map(|(idx, in_use)| if *in_use { None } else { Some(idx) })
            .collect();

        if gaps.is_empty() {
            key_index.available = u32::try_from(len).context("Too many index entries")?;
        } else {
            for (pos, gap_idx) in gaps.iter().enumerate() {
                let next = gaps.get(pos + 1).copied().unwrap_or(len);
                let next = u32::try_from(next).context("Too many index entries")?;
                keys[*gap_idx] = KeyIndexEntry::Index(next);
            }
            key_index.available = u32::try_from(gaps[0]).context("Too many index entries")?;
        }

        key_index.keys = keys;
        key_index.inactive = None;
    }

    // Store the index
    let index_bytes = bincode::DefaultOptions::new()
        .serialize(&key_index)
        .context("Failed to serialize key index")?;
    txn.put_cf(cf, [], index_bytes)
        .context("Failed to store key index")?;

    txn.commit()
        .context("Failed to commit migration transaction")?;

    drop(db);

    Ok(())
}

/// Migrates `ModelIndicator` entries with `model_id` from `i32` to `u32`.
///
/// This migration handles the serialization change for `ModelIndicator::Value`.
/// Since bincode's `DefaultOptions` uses varint encoding, the i32→u32 change
/// is NOT byte-compatible for non-zero values, requiring migration.
/// Migrates `HttpThreat` events with `cluster_id` from `Option<usize>` to `Option<u32>`.
///
/// This migration handles the serialization change for `HttpThreat` events.
/// The serialization of `Option<usize>` differs from `Option<u32>` in bincode because
/// `usize` is architecture-dependent (8 bytes on 64-bit systems) while `u32` is 4 bytes.
///
/// Note: Other event types (`ExtraThreat`, `WindowsThreat`, `NetworkThreat`) are not generated
/// on production servers, so their migration is unnecessary.
/// Migrates event fields in a single pass over the events database.
///
/// Handles three event kinds:
/// - `HttpThreat`: `cluster_id` from `Option<usize>` to `Option<u32>`
/// - `BlocklistDceRpc`: replace `rtt`/`named_pipe`/`endpoint`/`operation` with
///   `context` (`Vec<DceRpcContext>`) and `request` (`Vec<String>`)
/// - `BlocklistDhcp`: add the new `options` field
fn migrate_event_fields(dir: &Path) -> Result<()> {
    use num_traits::FromPrimitive;

    /// Number of records to commit per transaction batch to bound memory usage.
    const BATCH_SIZE: usize = 100;

    let db_path = dir.join("states.db");

    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, &db_path)?;

    let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, column_families)
            .context("Failed to open database for event migration")?;

    let mut http_threat_migrated = 0usize;
    let mut http_threat_errors = 0usize;
    let mut dcerpc_migrated = 0usize;
    let mut dcerpc_errors = 0usize;
    let mut dhcp_migrated = 0usize;
    let mut dhcp_errors = 0usize;
    let mut batch: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(BATCH_SIZE);

    for item in db.iterator(rocksdb::IteratorMode::Start) {
        let (key, value) = item.context("failed to read event entry")?;

        // Extract event kind from the key
        // Key format: (timestamp_nanos << 64) | (event_kind << 32) | random_bits
        // Key is stored as big-endian i128 (16 bytes)
        if key.len() != 16 {
            continue;
        }

        let key_i128 = i128::from_be_bytes(key.as_ref().try_into().unwrap_or([0; 16]));
        let event_kind_val = ((key_i128 >> 32) & 0xFFFF_FFFF) as i32;

        let Some(event_kind) = EventKind::from_i32(event_kind_val) else {
            continue;
        };

        let migrated = match event_kind {
            EventKind::HttpThreat => {
                if let Some(new_val) = migrate_http_threat_fields(&value) {
                    http_threat_migrated += 1;
                    Some(new_val)
                } else {
                    http_threat_errors += 1;
                    None
                }
            }
            EventKind::BlocklistDceRpc => {
                if let Some(new_val) = migrate_blocklist_dcerpc_fields(&value) {
                    dcerpc_migrated += 1;
                    Some(new_val)
                } else {
                    dcerpc_errors += 1;
                    None
                }
            }
            EventKind::BlocklistDhcp => {
                if let Some(new_val) = migrate_blocklist_dhcp_fields(&value) {
                    dhcp_migrated += 1;
                    Some(new_val)
                } else {
                    dhcp_errors += 1;
                    None
                }
            }
            _ => None,
        };

        if let Some(new_val) = migrated {
            batch.push((key.to_vec(), new_val));

            if batch.len() >= BATCH_SIZE {
                let txn = db.transaction();
                for (k, v) in batch.drain(..) {
                    txn.put(&k, &v)?;
                }
                txn.commit()
                    .context("failed to commit event migration batch")?;
            }
        }
    }

    // Commit any remaining entries in the final batch
    if !batch.is_empty() {
        let txn = db.transaction();
        for (k, v) in batch.drain(..) {
            txn.put(&k, &v)?;
        }
        txn.commit()
            .context("failed to commit final event migration batch")?;
    }

    info!(
        "Event migration complete: HttpThreat({} migrated, {} skipped), \
         BlocklistDceRpc({} migrated, {} skipped), \
         BlocklistDhcp({} migrated, {} skipped)",
        http_threat_migrated,
        http_threat_errors,
        dcerpc_migrated,
        dcerpc_errors,
        dhcp_migrated,
        dhcp_errors,
    );

    Ok(())
}

/// Migrates stored `HttpThreatFields` from `Option<usize>` to `Option<u32>`
/// for `cluster_id`.
fn migrate_http_threat_fields(value: &[u8]) -> Option<Vec<u8>> {
    // Try to deserialize with old format. Production events are stored using
    // `bincode::serialize` (fixint encoding), so we must use the matching
    // `bincode::deserialize` here rather than `DefaultOptions` (varint).
    let old: HttpThreatFieldsStoredV0_43 = bincode::deserialize(value)
        .map_err(|e| warn!("failed to deserialize HttpThreatFieldsStoredV0_43: {e}"))
        .ok()?;

    let new = HttpThreatFieldsStoredV0_44 {
        time: old.time,
        sensor: old.sensor,
        orig_addr: old.orig_addr,
        orig_port: old.orig_port,
        resp_addr: old.resp_addr,
        resp_port: old.resp_port,
        proto: old.proto,
        start_time: old.start_time,
        duration: old.duration,
        orig_pkts: old.orig_pkts,
        resp_pkts: old.resp_pkts,
        orig_l2_bytes: old.orig_l2_bytes,
        resp_l2_bytes: old.resp_l2_bytes,
        method: old.method,
        host: old.host,
        uri: old.uri,
        referer: old.referer,
        version: old.version,
        user_agent: old.user_agent,
        request_len: old.request_len,
        response_len: old.response_len,
        status_code: old.status_code,
        status_msg: old.status_msg,
        username: old.username,
        password: old.password,
        cookie: old.cookie,
        content_encoding: old.content_encoding,
        content_type: old.content_type,
        cache_control: old.cache_control,
        filenames: old.filenames,
        mime_types: old.mime_types,
        body: old.body,
        state: old.state,
        db_name: old.db_name,
        rule_id: old.rule_id,
        matched_to: old.matched_to,
        cluster_id: old.cluster_id.and_then(|v| u32::try_from(v).ok()),
        attack_kind: old.attack_kind,
        confidence: old.confidence,
        category: old.category,
    };

    bincode::serialize(&new)
        .map_err(|e| warn!("failed to serialize HttpThreatFieldsStoredV0_44: {e}"))
        .ok()
}

fn migrate_blocklist_dcerpc_fields(value: &[u8]) -> Option<Vec<u8>> {
    // Production events are stored using `bincode::serialize` (fixint encoding).
    let old: BlocklistDceRpcFieldsStoredV0_42 = bincode::deserialize(value)
        .map_err(|e| warn!("failed to deserialize BlocklistDceRpcFieldsStoredV0_42: {e}"))
        .ok()?;

    let new = BlocklistDceRpcFieldsStoredV0_44 {
        sensor: old.sensor,
        orig_addr: old.orig_addr,
        orig_port: old.orig_port,
        resp_addr: old.resp_addr,
        resp_port: old.resp_port,
        proto: old.proto,
        start_time: old.start_time,
        duration: old.duration,
        orig_pkts: old.orig_pkts,
        resp_pkts: old.resp_pkts,
        orig_l2_bytes: old.orig_l2_bytes,
        resp_l2_bytes: old.resp_l2_bytes,
        context: Vec::new(),
        request: Vec::new(),
        confidence: old.confidence,
        category: old.category,
    };

    bincode::serialize(&new)
        .map_err(|e| warn!("failed to serialize BlocklistDceRpcFieldsStoredV0_44: {e}"))
        .ok()
}

/// Migrates a single stored `BlocklistDhcpFields` record by adding an empty
/// `options` field.
fn migrate_blocklist_dhcp_fields(value: &[u8]) -> Option<Vec<u8>> {
    // Production events are stored using `bincode::serialize` (fixint encoding).
    let old: BlocklistDhcpFieldsStoredV0_42 = bincode::deserialize(value)
        .map_err(|e| warn!("failed to deserialize BlocklistDhcpFieldsStoredV0_42: {e}"))
        .ok()?;

    let new = BlocklistDhcpFieldsStoredV0_44 {
        sensor: old.sensor,
        orig_addr: old.orig_addr,
        orig_port: old.orig_port,
        resp_addr: old.resp_addr,
        resp_port: old.resp_port,
        proto: old.proto,
        start_time: old.start_time,
        duration: old.duration,
        orig_pkts: old.orig_pkts,
        resp_pkts: old.resp_pkts,
        orig_l2_bytes: old.orig_l2_bytes,
        resp_l2_bytes: old.resp_l2_bytes,
        msg_type: old.msg_type,
        ciaddr: old.ciaddr,
        yiaddr: old.yiaddr,
        siaddr: old.siaddr,
        giaddr: old.giaddr,
        subnet_mask: old.subnet_mask,
        router: old.router,
        domain_name_server: old.domain_name_server,
        req_ip_addr: old.req_ip_addr,
        lease_time: old.lease_time,
        server_id: old.server_id,
        param_req_list: old.param_req_list,
        message: old.message,
        renewal_time: old.renewal_time,
        rebinding_time: old.rebinding_time,
        class_id: old.class_id,
        client_id_type: old.client_id_type,
        client_id: old.client_id,
        options: vec![],
        confidence: old.confidence,
        category: old.category,
    };

    bincode::serialize(&new)
        .map_err(|e| warn!("failed to serialize BlocklistDhcpFieldsStoredV0_44: {e}"))
        .ok()
}

/// Recursively creates `path` if not existed, creates the VERSION file
/// under `path` if missing with current version number. Returns VERSION
/// file path with VERSION number written on file.
///
/// # Errors
///
/// Returns an error if VERSION cannot be retrieved or created.
fn retrieve_or_create_version<P: AsRef<Path>>(path: P) -> Result<(PathBuf, Version)> {
    let path = path.as_ref();
    let file = path.join(VERSION_FILE_NAME);

    if !path.exists() {
        create_dir_all(path)?;
    }

    // A temporary left behind by an interrupted write must not make an
    // otherwise empty directory look populated, or VERSION would never be
    // created here and the read below would fail on a fresh data directory.
    // Only that one name is forgiven: a directory holding anything else but
    // no VERSION stays an error, since creating one would stamp the current
    // version onto an existing tree and skip its migration entirely.
    let tmp = path.join(VERSION_TMP_FILE_NAME);
    let populated = path
        .read_dir()
        .context("cannot read data dir")?
        .any(|entry| match entry {
            Ok(entry) => entry.path() != tmp,
            Err(_) => true,
        });
    if !populated {
        create_version_file(&file, env!("CARGO_PKG_VERSION"))?;
    }

    let version = read_version_file(&file)?;
    Ok((file, version))
}

/// Writes `version` to the VERSION file at `path`, creating it if it does not
/// exist.
///
/// The file is replaced rather than rewritten: the version goes to a
/// temporary in the same directory and is renamed over VERSION, so an
/// interrupted write cannot leave VERSION empty or partial.
///
/// `version` is written verbatim, so every caller passes a string it has
/// already validated: the current crate version during migration, and the
/// canonical form of a parsed [`Version`] from [`write_version_markers`].
///
/// # Errors
///
/// Returns an error if the temporary file cannot be created, written, or
/// flushed, if it cannot be renamed over the VERSION file, or if the
/// containing directory cannot be flushed.
fn create_version_file(path: &Path, version: &str) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(VERSION_TMP_FILE_NAME);

    // No mode is requested here. `rename` installs this inode at the
    // destination, so the temporary's mode becomes VERSION's, and
    // `File::create` asks for `0o666` and lets the umask narrow it — which is
    // what VERSION has had all along. It records a format version, not a
    // secret, so there is nothing to tighten.
    let mut f = File::create(&tmp).context("cannot create temporary VERSION")?;
    f.write_all(version.as_bytes())
        .context("cannot write temporary VERSION")?;

    // Flush before the rename. `migrate_data_dir` writes VERSION only once the
    // migration has already rewritten the database, and the next start reads
    // it back to decide whether to migrate again, so a rename reaching disk
    // ahead of these bytes would leave a version that cannot be parsed and a
    // database that will not open.
    f.sync_all().context("cannot flush temporary VERSION")?;
    drop(f);

    if let Err(rename_err) = rename(&tmp, path) {
        // Leave nothing behind that would make an empty data directory look
        // populated to `retrieve_or_create_version`.
        return match remove_file(&tmp) {
            Ok(()) => Err(rename_err).context("cannot replace VERSION"),
            Err(remove_err) => {
                Err(remove_err).context("cannot remove temporary VERSION after a failed rename")
            }
        };
    }

    // Flush the directory as well: the rename is what makes the new version
    // visible, and until that directory entry is on disk a power loss can
    // still lose it, leaving a migrated database recorded as the version it
    // held before the migration.
    File::open(dir)
        .and_then(|dir| dir.sync_all())
        .context("cannot flush the directory holding VERSION")?;

    Ok(())
}

/// Reads the VERSION file in the data directory and returns its contents.
///
/// # Errors
///
/// Returns an error if the VERSION file cannot be read or parsed.
fn read_version_file(path: &Path) -> Result<Version> {
    let mut ver = String::new();
    File::open(path)
        .context("cannot open VERSION")?
        .read_to_string(&mut ver)
        .context("cannot read VERSION")?;
    Version::parse(&ver).context("cannot parse VERSION")
}

/// Records `version` as the database format version of both `data_dir` and
/// `backup_dir`.
///
/// This is the metadata companion to restoring a rollback snapshot. The
/// migration bodies rewrite `data_dir/states.db` only, while the format
/// version lives beside it in the two `VERSION` files, so restoring the
/// snapshot taken before an update puts the older database back under markers
/// that still name the newer format, and the earlier binary finds no migration
/// for a marker it does not know. After restoring the snapshot, the caller
/// passes the format version it recorded before the update — the
/// `pre_update_version` of the operation attempt — and both markers again
/// describe the restored contents.
///
/// `version` is parsed as a [`semver::Version`] before anything is written,
/// and it is the parsed value's canonical `to_string()` form that reaches each
/// file, with no trailing bytes. Validation is syntactic only: this function
/// does not read `states.db`, does not read the markers it replaces, and does
/// not judge whether any binary can migrate from `version`. Choosing a version
/// the rollback binary supports remains the caller's responsibility.
///
/// A missing directory, and any missing component of its path, is created.
/// Each marker is replaced through the same write-to-a-temporary, sync,
/// rename, and directory-sync path a migration uses, so an interruption cannot
/// leave a marker empty or partially written. The two files can live on
/// different filesystems, so there is no cross-directory atomic commit: a
/// failure on the second leaves the first already updated. The operation is
/// idempotent — correct the filesystem failure and call it again with the same
/// paths and version, and both markers end up canonical and equal.
///
/// `VERSION.tmp`, the temporary each replacement goes through, is a fixed name,
/// so the caller must serialize this call against migration and against any
/// other marker write for each directory involved.
///
/// # Errors
///
/// Returns an error if `version` is not a complete semantic version, if either
/// directory is missing and cannot be created, or if either marker cannot be
/// written, renamed into place, or flushed. The error identifies which of the
/// two directories the failing operation belonged to.
pub fn write_version_markers<P: AsRef<Path>, Q: AsRef<Path>>(
    data_dir: P,
    backup_dir: Q,
    version: &str,
) -> Result<()> {
    let parsed = Version::parse(version)
        .with_context(|| format!("cannot parse the requested format version {version}"))?;
    let canonical = parsed.to_string();

    let data_dir = data_dir.as_ref();
    let backup_dir = backup_dir.as_ref();

    write_version_marker(data_dir, &canonical).with_context(|| {
        format!(
            "cannot write the data directory VERSION in {}",
            data_dir.display()
        )
    })?;
    write_version_marker(backup_dir, &canonical).with_context(|| {
        format!(
            "cannot write the backup directory VERSION in {}",
            backup_dir.display()
        )
    })
}

/// Creates `dir` if it is missing and replaces the VERSION file in it with
/// `version`.
///
/// # Errors
///
/// Returns an error if `dir` cannot be created or if the marker cannot be
/// replaced.
fn write_version_marker(dir: &Path, version: &str) -> Result<()> {
    create_dir_all(dir).context("cannot create the directory")?;
    create_version_file(&dir.join(VERSION_FILE_NAME), version)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, io::Write, net::IpAddr, path::Path};

    use bincode::Options;
    use num_traits::ToPrimitive;
    use semver::{Version, VersionReq};

    use super::{
        COMPATIBLE_VERSION_REQ, VERSION_FILE_NAME, VERSION_TMP_FILE_NAME, create_version_file,
        migrate_data_dir, migrate_event_country_codes, migrate_event_stored_schema_to_v0_46,
        read_version_file, retrieve_or_create_version, write_version_markers,
    };
    use crate::event::{
        BlocklistConnFields, BlocklistConnFieldsStored, EventKind, EventMessage,
        MultiHostPortScanFieldsStored, resolve_stored_country_codes,
    };
    use crate::geo::CountryLookup;
    use crate::migration::migration_structures::{
        AgentValueV0_47Alpha1, AgentValueV0_47Alpha2, BlocklistConnFieldsStoredV0_42,
        ExternalServiceValueV0_47Alpha1, ExternalServiceValueV0_47Alpha2,
        MultiHostPortScanFieldsStoredV0_42,
    };
    use crate::tables::NETWORK_TAGS;
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{
        Agent, AgentConfig, AgentKind, AgentStatus, CoreComponent, ExternalService,
        ExternalServiceConfig, ExternalServiceKind, ExternalServiceStatus, Indexable, Lifecycle,
        Store,
    };

    #[derive(Default)]
    struct FakeCountryLookup {
        codes: HashMap<IpAddr, [u8; 2]>,
    }

    impl CountryLookup for FakeCountryLookup {
        fn lookup_country_code(&self, addr: IpAddr) -> [u8; 2] {
            self.codes
                .get(&addr)
                .copied()
                .unwrap_or(crate::util::COUNTRY_CODE_INVALID)
        }
    }

    /// Helper to write a specific version to a VERSION file.
    fn write_version(path: &Path, version: &str) {
        let version_file = path.join("VERSION");
        let mut f = std::fs::File::create(&version_file).unwrap();
        f.write_all(version.as_bytes()).unwrap();
    }

    fn legacy_blocklist_conn() -> BlocklistConnFieldsStoredV0_42 {
        BlocklistConnFieldsStoredV0_42 {
            sensor: "collector1".to_string(),
            orig_addr: "192.0.2.1".parse().unwrap(),
            orig_port: 12345,
            resp_addr: "198.51.100.1".parse().unwrap(),
            resp_port: 443,
            proto: 6,
            conn_state: "SF".to_string(),
            start_time: 100,
            duration: 200,
            service: "https".to_string(),
            orig_bytes: 10,
            resp_bytes: 20,
            orig_pkts: 1,
            resp_pkts: 2,
            orig_l2_bytes: 42,
            resp_l2_bytes: 84,
            confidence: 0.9,
            category: None,
        }
    }

    fn blocklist_conn_message(legacy: &BlocklistConnFieldsStoredV0_42) -> EventMessage {
        EventMessage {
            time: crate::event::timestamp::from_chrono(chrono::Utc::now())
                .expect("current time fits i64 nanoseconds"),
            kind: EventKind::BlocklistConn,
            fields: bincode::serialize(&BlocklistConnFields {
                sensor: legacy.sensor.clone(),
                orig_addr: legacy.orig_addr,
                orig_port: legacy.orig_port,
                resp_addr: legacy.resp_addr,
                resp_port: legacy.resp_port,
                proto: legacy.proto,
                conn_state: legacy.conn_state.clone(),
                start_time: legacy.start_time,
                duration: legacy.duration,
                service: legacy.service.clone(),
                orig_bytes: legacy.orig_bytes,
                resp_bytes: legacy.resp_bytes,
                orig_pkts: legacy.orig_pkts,
                resp_pkts: legacy.resp_pkts,
                orig_l2_bytes: legacy.orig_l2_bytes,
                resp_l2_bytes: legacy.resp_l2_bytes,
                confidence: legacy.confidence,
                category: legacy.category,
            })
            .unwrap(),
        }
    }

    #[test]
    fn stored_schema_migration_dispatches_endpoint_event() {
        let old = legacy_blocklist_conn();
        let converted = migrate_event_stored_schema_to_v0_46(
            EventKind::BlocklistConn,
            &bincode::serialize(&old).unwrap(),
        )
        .unwrap();
        let current: BlocklistConnFieldsStored = bincode::deserialize(&converted).unwrap();

        assert_eq!(current.orig_addr, old.orig_addr);
        assert_eq!(current.orig_port, old.orig_port);
        assert_eq!(current.orig_country_code, crate::util::COUNTRY_CODE_PENDING);
        assert_eq!(current.resp_addr, old.resp_addr);
        assert_eq!(current.resp_port, old.resp_port);
        assert_eq!(current.resp_country_code, crate::util::COUNTRY_CODE_PENDING);
        assert_eq!(current.conn_state, old.conn_state);
    }

    #[test]
    fn stored_schema_migration_preserves_endpoint_vectors() {
        let old = MultiHostPortScanFieldsStoredV0_42 {
            sensor: "collector1".to_string(),
            orig_addr: "192.0.2.1".parse().unwrap(),
            resp_port: 22,
            resp_addrs: vec![
                "198.51.100.1".parse().unwrap(),
                "198.51.100.2".parse().unwrap(),
            ],
            proto: 6,
            start_time: 100,
            end_time: 200,
            confidence: 0.7,
            category: None,
        };
        let resp_count = old.resp_addrs.len();
        let converted = migrate_event_stored_schema_to_v0_46(
            EventKind::MultiHostPortScan,
            &bincode::serialize(&old).unwrap(),
        )
        .unwrap();
        let current: MultiHostPortScanFieldsStored = bincode::deserialize(&converted).unwrap();

        assert_eq!(current.orig_addr, old.orig_addr);
        assert_eq!(current.orig_country_code, crate::util::COUNTRY_CODE_PENDING);
        assert_eq!(current.resp_addrs, old.resp_addrs);
        assert_eq!(current.resp_port, old.resp_port);
        assert_eq!(
            current.resp_country_codes,
            vec![crate::util::COUNTRY_CODE_PENDING; resp_count]
        );
    }

    #[test]
    fn country_code_resolution_without_locator_preserves_serialized_bytes() {
        let converted = migrate_event_stored_schema_to_v0_46(
            EventKind::BlocklistConn,
            &bincode::serialize(&legacy_blocklist_conn()).unwrap(),
        )
        .unwrap();

        let resolved =
            resolve_stored_country_codes(EventKind::BlocklistConn, &converted, None).unwrap();

        assert_eq!(resolved, converted);
    }

    #[test]
    fn event_country_code_migration_rewrites_legacy_record_through_event_db() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        let events = store.events();
        let legacy = legacy_blocklist_conn();
        let message = blocklist_conn_message(&legacy);
        events.put(&message).unwrap();
        let (key, current_value) = events.raw_iter().next().unwrap().unwrap();
        let legacy_value = bincode::serialize(&legacy).unwrap();
        events
            .update((&key, &current_value), (&key, &legacy_value))
            .unwrap();

        drop(events);
        drop(store);

        let stats = migrate_event_country_codes(data_dir.path(), None).unwrap();
        assert_eq!(stats.processed, 1);
        assert_eq!(stats.converted, 1);
        assert_eq!(stats.already_current, 0);

        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        let events = store.events();
        let (migrated_key, migrated_value) = events.raw_iter().next().unwrap().unwrap();
        let migrated: BlocklistConnFieldsStored = bincode::deserialize(&migrated_value).unwrap();
        assert_eq!(migrated_key, key);
        assert_ne!(migrated_value, legacy_value);
        assert_eq!(migrated.orig_addr, legacy.orig_addr);
        assert_eq!(
            migrated.orig_country_code,
            crate::util::COUNTRY_CODE_PENDING
        );
        assert_eq!(migrated.resp_addr, legacy.resp_addr);
        assert_eq!(
            migrated.resp_country_code,
            crate::util::COUNTRY_CODE_PENDING
        );

        drop(events);
        drop(store);
        let rerun_stats = migrate_event_country_codes(data_dir.path(), None).unwrap();
        assert_eq!(rerun_stats.processed, 1);
        assert_eq!(rerun_stats.converted, 0);
        assert_eq!(rerun_stats.already_current, 1);
    }

    #[test]
    fn event_country_code_migration_recognizes_every_event_kind_on_rerun() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        drop(store);

        let db_path = data_dir.path().join("states.db");
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(false);
        opts.create_missing_column_families(false);
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, crate::tables::MAP_NAMES)
                .unwrap();
        let samples = crate::event::stored_event_samples_v0_46();
        let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();
        for (index, (kind, value)) in samples.iter().enumerate() {
            let key =
                (1_i128 << 64) | (kind.to_i128().unwrap() << 32) | i128::try_from(index).unwrap();
            batch.put(key.to_be_bytes(), value);
        }
        db.write(batch).unwrap();
        drop(db);

        let initial_stats = migrate_event_country_codes(data_dir.path(), None).unwrap();
        assert_eq!(initial_stats.processed, samples.len());
        assert_eq!(initial_stats.converted, 0);
        assert_eq!(initial_stats.already_current, samples.len());

        let rerun_stats = migrate_event_country_codes(data_dir.path(), None).unwrap();
        assert_eq!(rerun_stats.processed, samples.len());
        assert_eq!(rerun_stats.converted, 0);
        assert_eq!(rerun_stats.already_current, samples.len());
    }

    #[test]
    fn event_country_code_migration_resolves_codes_with_locator() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        let events = store.events();
        let legacy = legacy_blocklist_conn();
        let message = blocklist_conn_message(&legacy);
        events.put(&message).unwrap();
        let (key, current_value) = events.raw_iter().next().unwrap().unwrap();
        let legacy_value = bincode::serialize(&legacy).unwrap();
        events
            .update((&key, &current_value), (&key, &legacy_value))
            .unwrap();

        let lookup = FakeCountryLookup {
            codes: HashMap::from([(legacy.orig_addr, *b"US"), (legacy.resp_addr, *b"KR")]),
        };
        drop(events);
        drop(store);

        let stats = migrate_event_country_codes(data_dir.path(), Some(&lookup)).unwrap();
        assert_eq!(stats.converted, 1);
        assert_eq!(stats.already_current, 0);

        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        let events = store.events();
        let (migrated_key, migrated_value) = events.raw_iter().next().unwrap().unwrap();
        let migrated: BlocklistConnFieldsStored = bincode::deserialize(&migrated_value).unwrap();
        assert_eq!(migrated_key, key);
        assert_ne!(migrated_value, legacy_value);
        assert_eq!(migrated.orig_addr, legacy.orig_addr);
        assert_eq!(migrated.orig_country_code, *b"US");
        assert_eq!(migrated.resp_addr, legacy.resp_addr);
        assert_eq!(migrated.resp_country_code, *b"KR");
    }

    #[test]
    fn event_country_code_migration_resumes_mixed_schema_database() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        let events = store.events();
        let legacy = legacy_blocklist_conn();
        let message = blocklist_conn_message(&legacy);
        events.put(&message).unwrap();
        events.put(&message).unwrap();

        let (key, current_value) = events.raw_iter().next().unwrap().unwrap();
        let legacy_value = bincode::serialize(&legacy).unwrap();
        events
            .update((&key, &current_value), (&key, &legacy_value))
            .unwrap();
        drop(events);
        drop(store);

        let stats = migrate_event_country_codes(data_dir.path(), None).unwrap();
        assert_eq!(stats.processed, 2);
        assert_eq!(stats.converted, 1);
        assert_eq!(stats.already_current, 1);

        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        assert_eq!(
            store
                .events()
                .iter_forward()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn event_country_code_migration_rejects_corrupt_record_and_preserves_version() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        let events = store.events();
        let message = blocklist_conn_message(&legacy_blocklist_conn());
        events.put(&message).unwrap();
        let (key, current_value) = events.raw_iter().next().unwrap().unwrap();
        events.update((&key, &current_value), (&key, &[])).unwrap();
        drop(events);
        drop(store);

        write_version(data_dir.path(), "0.45.0");
        write_version(backup_dir.path(), "0.45.0");
        let error = migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap_err();

        assert!(
            format!("{error:#}")
                .contains("matches neither the previous nor the current stored schema")
        );
        assert_eq!(
            read_version_file(&data_dir.path().join("VERSION")).unwrap(),
            Version::parse("0.45.0").unwrap()
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join("VERSION")).unwrap(),
            Version::parse("0.45.0").unwrap()
        );
    }

    // =========================================================================
    // Tests for migrate_data_dir
    // =========================================================================

    /// Test that migration is skipped when the version is already compatible.
    #[test]
    fn migration_skipped_when_version_compatible() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        // Write the current compatible version to both directories
        let current_version = env!("CARGO_PKG_VERSION");
        write_version(data_dir.path(), current_version);
        write_version(backup_dir.path(), current_version);

        // This should succeed without calling any migration
        let result = migrate_data_dir(data_dir.path(), backup_dir.path(), None);
        assert!(result.is_ok());

        // VERSION should remain unchanged
        let version = read_version_file(&data_dir.path().join("VERSION")).unwrap();
        assert_eq!(version, Version::parse(current_version).unwrap());
    }

    /// Test that error is returned when data and backup versions mismatch.
    #[test]
    fn error_on_version_mismatch() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let mut data_version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        if !data_version.pre.is_empty() {
            data_version = Version::new(data_version.major, data_version.minor, data_version.patch);
        }
        let mut backup_version = data_version.clone();
        backup_version.patch += 1;

        // Different versions in data and backup
        write_version(data_dir.path(), &data_version.to_string());
        write_version(backup_dir.path(), &backup_version.to_string());

        let result = migrate_data_dir(data_dir.path(), backup_dir.path(), None);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains(&format!(
            "mismatched database version {data_version} and backup version {backup_version}"
        )));
    }

    /// Test that `VERSION` file is created when directory is empty.
    #[test]
    fn version_file_created_for_empty_directory() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        // Don't write any VERSION files - directories are empty

        let result = migrate_data_dir(data_dir.path(), backup_dir.path(), None);

        // Should succeed (empty dir gets current version)
        assert!(result.is_ok());

        // VERSION should be created with current package version
        let data_version = read_version_file(&data_dir.path().join("VERSION")).unwrap();
        let backup_version = read_version_file(&backup_dir.path().join("VERSION")).unwrap();
        let current_version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        assert_eq!(data_version, current_version);
        assert_eq!(backup_version, current_version);
    }

    /// Test that error is returned when `VERSION` file contains invalid content.
    #[test]
    fn error_on_invalid_version_content() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        // Write invalid version content
        let version_file = data_dir.path().join("VERSION");
        let mut f = std::fs::File::create(&version_file).unwrap();
        f.write_all(b"not-a-valid-version").unwrap();

        // Also need a file in backup to prevent it from being treated as empty
        write_version(backup_dir.path(), env!("CARGO_PKG_VERSION"));

        let result = migrate_data_dir(data_dir.path(), backup_dir.path(), None);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot parse VERSION"));
    }

    /// Test that non-existent data directory is created.
    #[test]
    fn non_existent_directory_is_created() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("new_data_dir");
        let backup_dir = temp.path().join("new_backup_dir");

        // Directories don't exist yet
        assert!(!data_dir.exists());
        assert!(!backup_dir.exists());

        let result = migrate_data_dir(&data_dir, &backup_dir, None);

        // Should succeed
        assert!(result.is_ok());

        // Directories should now exist
        assert!(data_dir.exists());
        assert!(backup_dir.exists());

        // VERSION files should exist
        assert!(data_dir.join("VERSION").exists());
        assert!(backup_dir.join("VERSION").exists());
    }

    /// Test that migration fails for unsupported old versions.
    #[test]
    fn migration_fails_for_unsupported_version() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        // Write a version that's too old and not in the migration list
        write_version(data_dir.path(), "0.30.0");
        write_version(backup_dir.path(), "0.30.0");

        let result = migrate_data_dir(data_dir.path(), backup_dir.path(), None);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("migration from 0.30.0 is not supported"));
    }

    /// Test `read_version_file` and `create_version_file` helper functions.
    #[test]
    fn version_file_helpers() {
        let temp = tempfile::tempdir().unwrap();
        let version_path = temp.path().join("VERSION");

        // Create a version file
        create_version_file(&version_path, env!("CARGO_PKG_VERSION")).unwrap();

        // Read it back
        let version = read_version_file(&version_path).unwrap();
        assert_eq!(version, Version::parse(env!("CARGO_PKG_VERSION")).unwrap());
    }

    /// Test that writing over an existing `VERSION` leaves the current version
    /// readable and no temporary behind.
    ///
    /// The ordering the flushes in `create_version_file` buy cannot be
    /// observed without fault injection, so this covers the states a test can
    /// reach: the replacement itself, and the directory it leaves.
    #[test]
    fn version_file_is_replaced() {
        let temp = tempfile::tempdir().unwrap();
        write_version(temp.path(), "0.45.0");
        let version_path = temp.path().join(VERSION_FILE_NAME);

        create_version_file(&version_path, env!("CARGO_PKG_VERSION")).unwrap();

        assert_eq!(
            read_version_file(&version_path).unwrap(),
            Version::parse(env!("CARGO_PKG_VERSION")).unwrap()
        );
        assert!(!temp.path().join(VERSION_TMP_FILE_NAME).exists());
    }

    /// Test that a temporary left behind by an interrupted write does not stop
    /// `VERSION` from being created in an otherwise empty data directory.
    #[test]
    fn stale_version_temp_does_not_block_creation() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join(VERSION_TMP_FILE_NAME), b"0.4").unwrap();

        let (path, version) = retrieve_or_create_version(temp.path()).unwrap();

        assert_eq!(path, temp.path().join(VERSION_FILE_NAME));
        assert_eq!(version, Version::parse(env!("CARGO_PKG_VERSION")).unwrap());
    }

    /// Test that a populated data directory without a `VERSION` file is still
    /// rejected rather than stamped with the current version, which would skip
    /// the migration its contents need.
    #[test]
    fn populated_dir_without_version_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("states.db"), b"not a version file").unwrap();

        let result = retrieve_or_create_version(temp.path());

        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot open VERSION"));
    }

    /// Test that reading a non-existent `VERSION` file returns an error.
    #[test]
    fn read_nonexistent_version_file_error() {
        let temp = tempfile::tempdir().unwrap();
        let version_path = temp.path().join("NONEXISTENT_VERSION");

        let result = read_version_file(&version_path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot open VERSION"));
    }

    /// Test that the public marker writer puts the canonical form of the
    /// parsed version in both directories, byte for byte.
    #[test]
    fn write_version_markers_writes_canonical_markers() {
        const REQUESTED: &str = "0.46.0";

        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        write_version_markers(data_dir.path(), backup_dir.path(), REQUESTED).unwrap();

        let expected = Version::parse(REQUESTED).unwrap().to_string();
        for dir in [data_dir.path(), backup_dir.path()] {
            let marker = std::fs::read_to_string(dir.join(VERSION_FILE_NAME)).unwrap();
            assert_eq!(marker, expected);
        }
    }

    /// Test that a prerelease marker survives the round trip unchanged, so the
    /// alpha format versions this crate migrates between can be recorded.
    #[test]
    fn write_version_markers_keeps_prerelease_versions() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        write_version_markers(data_dir.path(), backup_dir.path(), "0.47.0-alpha.1").unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            Version::parse("0.47.0-alpha.1").unwrap()
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            Version::parse("0.47.0-alpha.1").unwrap()
        );
    }

    /// Test that missing marker directories, including intermediate
    /// components, are created and receive their markers.
    #[test]
    fn write_version_markers_creates_missing_directories() {
        let root = tempfile::tempdir().unwrap();
        let data_dir = root.path().join("restored").join("data");
        let backup_dir = root.path().join("restored").join("backup");

        write_version_markers(&data_dir, &backup_dir, "0.46.0").unwrap();

        for dir in [&data_dir, &backup_dir] {
            assert!(dir.is_dir());
            assert_eq!(
                std::fs::read_to_string(dir.join(VERSION_FILE_NAME)).unwrap(),
                "0.46.0"
            );
        }
    }

    /// Test that an unparsable version is rejected before any filesystem
    /// change: no directory appears, and an existing marker keeps its
    /// contents.
    #[test]
    fn write_version_markers_rejects_invalid_versions() {
        for invalid in ["", "0.46", "not a version", "0.46.0 ", "0.46.0extra"] {
            let root = tempfile::tempdir().unwrap();
            let data_dir = root.path().join("data");
            let backup_dir = root.path().join("backup");

            assert!(
                write_version_markers(&data_dir, &backup_dir, invalid).is_err(),
                "{invalid:?} must be rejected"
            );
            assert!(
                !data_dir.exists(),
                "{invalid:?} must not create a directory"
            );
            assert!(
                !backup_dir.exists(),
                "{invalid:?} must not create a directory"
            );

            let existing_data = tempfile::tempdir().unwrap();
            let existing_backup = tempfile::tempdir().unwrap();
            write_version(existing_data.path(), "0.45.0");
            write_version(existing_backup.path(), "0.45.0");

            assert!(
                write_version_markers(existing_data.path(), existing_backup.path(), invalid)
                    .is_err(),
                "{invalid:?} must be rejected"
            );
            for dir in [existing_data.path(), existing_backup.path()] {
                assert_eq!(
                    std::fs::read_to_string(dir.join(VERSION_FILE_NAME)).unwrap(),
                    "0.45.0",
                    "{invalid:?} must leave the existing marker alone"
                );
                assert!(!dir.join(VERSION_TMP_FILE_NAME).exists());
            }
        }
    }

    /// Test that an existing marker is replaced rather than appended to, even
    /// when it names a newer format or was not stored canonically. This is the
    /// rollback case: the update left both markers at the version being rolled
    /// back from.
    #[test]
    fn write_version_markers_replaces_existing_markers() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        write_version(data_dir.path(), env!("CARGO_PKG_VERSION"));
        write_version(backup_dir.path(), "0.47.0-alpha.2\n");

        write_version_markers(data_dir.path(), backup_dir.path(), "0.46.0").unwrap();

        for dir in [data_dir.path(), backup_dir.path()] {
            assert_eq!(
                std::fs::read_to_string(dir.join(VERSION_FILE_NAME)).unwrap(),
                "0.46.0"
            );
            assert!(!dir.join(VERSION_TMP_FILE_NAME).exists());
        }
    }

    /// Test that a failure on the backup marker names the backup directory and
    /// that the same call, repeated after the failure is corrected, leaves both
    /// markers canonical and equal.
    #[test]
    fn write_version_markers_reports_the_failing_directory_and_retries() {
        let root = tempfile::tempdir().unwrap();
        let data_dir = root.path().join("data");
        let backup_dir = root.path().join("backup");
        std::fs::write(&backup_dir, b"a regular file, not a directory").unwrap();

        let err = write_version_markers(&data_dir, &backup_dir, "0.46.0")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("backup directory VERSION"),
            "the error must name the backup directory, got {err}"
        );

        std::fs::remove_file(&backup_dir).unwrap();
        write_version_markers(&data_dir, &backup_dir, "0.46.0").unwrap();

        let data_marker = std::fs::read_to_string(data_dir.join(VERSION_FILE_NAME)).unwrap();
        let backup_marker = std::fs::read_to_string(backup_dir.join(VERSION_FILE_NAME)).unwrap();
        assert_eq!(data_marker, Version::parse("0.46.0").unwrap().to_string());
        assert_eq!(data_marker, backup_marker);
    }

    /// Test that a failure on the data marker names the data directory and
    /// stops before the backup one, so the pair is never left describing two
    /// different formats.
    #[test]
    fn write_version_markers_reports_a_failing_data_directory() {
        let root = tempfile::tempdir().unwrap();
        let data_dir = root.path().join("data");
        std::fs::write(&data_dir, b"a regular file, not a directory").unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        write_version(backup_dir.path(), "0.45.0");

        let err = write_version_markers(&data_dir, backup_dir.path(), "0.46.0")
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("data directory VERSION"),
            "the error must name the data directory, got {err}"
        );
        assert_eq!(
            std::fs::read_to_string(backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            "0.45.0",
            "the backup marker must be left alone"
        );
        assert!(!backup_dir.path().join(VERSION_TMP_FILE_NAME).exists());
    }

    /// Test that migrations from `START_VERSION` up to the current version succeed and update `VERSION` files.
    ///
    /// NOTE: `START_VERSION` is the oldest supported migration start for this test. If the supported
    /// migration window changes and older versions are removed from the migration list, update
    /// the start version here accordingly. This test assumes column families match the current
    /// schema; if a migration includes column family changes, validate that path separately with
    /// a schema-specific test.
    #[test]
    fn migration_from_supported_minors() {
        const START_VERSION: &str = "0.43.0";
        let current_pkg_version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        let current_base = if current_pkg_version.pre.is_empty() {
            current_pkg_version.clone()
        } else {
            Version::new(
                current_pkg_version.major,
                current_pkg_version.minor,
                current_pkg_version.patch,
            )
        };

        let start_version = Version::parse(START_VERSION).unwrap();
        assert!(
            current_base.major == start_version.major,
            "`START_VERSION` must be updated for major version bump (current {current_base}, start {start_version})"
        );
        assert!(
            current_base.minor >= start_version.minor,
            "`START_VERSION` {start_version} is ahead of current {current_base}; please correct it"
        );

        for minor in start_version.minor..=current_base.minor {
            let version = if minor == current_base.minor {
                current_pkg_version.clone()
            } else {
                Version::new(start_version.major, minor, 0)
            };

            let data_dir = tempfile::tempdir().unwrap();
            let backup_dir = tempfile::tempdir().unwrap();

            let db_path = data_dir.path().join("states.db");
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);

            let db: rocksdb::OptimisticTransactionDB = rocksdb::OptimisticTransactionDB::open_cf(
                &opts,
                &db_path,
                crate::tables::MAP_NAMES,
            )
            .unwrap();
            drop(db);

            write_version(data_dir.path(), &version.to_string());
            write_version(backup_dir.path(), &version.to_string());

            let result = migrate_data_dir(data_dir.path(), backup_dir.path(), None);
            assert!(result.is_ok(), "Migration should succeed from {version}");

            let data_version = read_version_file(&data_dir.path().join("VERSION")).unwrap();
            let backup_version = read_version_file(&backup_dir.path().join("VERSION")).unwrap();
            assert_eq!(data_version, current_pkg_version);
            assert_eq!(backup_version, current_pkg_version);
        }
    }

    /// Migrates a database in the 0.43-through-0.46 layout, recorded as
    /// `version`, and asserts that it reaches the current format with its agent
    /// and external-service values converted.
    fn assert_migration_creates_new_column_families(version: &str) {
        let current_version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();

        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        create_states_db(&db_path, super::MAP_NAMES_V0_43_TO_V0_46);
        let (agents, external_services) = old_install_state_fixture();
        put_entries(
            &db_path,
            super::MAP_NAMES_V0_43_TO_V0_46,
            crate::tables::AGENTS,
            &agents,
        );
        put_entries(
            &db_path,
            super::MAP_NAMES_V0_43_TO_V0_46,
            crate::tables::EXTERNAL_SERVICES,
            &external_services,
        );

        write_version(data_dir.path(), version);
        write_version(backup_dir.path(), version);
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        let mut open_opts = rocksdb::Options::default();
        open_opts.create_if_missing(false);
        open_opts.create_missing_column_families(false);
        let db: rocksdb::OptimisticTransactionDB = rocksdb::OptimisticTransactionDB::open_cf(
            &open_opts,
            &db_path,
            crate::tables::MAP_NAMES,
        )
        .unwrap();
        for name in [
            crate::tables::CUSTOMER_DELETION_JOBS,
            crate::tables::CORE_COMPONENTS,
            crate::tables::OPERATION_ATTEMPTS,
        ] {
            assert!(db.cf_handle(name).is_some(), "{name} must exist");
        }
        drop(db);

        for (list, name) in [
            (
                super::MAP_NAMES_V0_43_TO_V0_46.as_slice(),
                "0.43-through-0.46",
            ),
            (super::MAP_NAMES_V0_47_ALPHA_1.as_slice(), "0.47.0-alpha.1"),
        ] {
            assert!(
                rocksdb::OptimisticTransactionDB::<rocksdb::SingleThreaded>::open_cf(
                    &open_opts, &db_path, list,
                )
                .is_err(),
                "the {name} column-family list must not open the migrated format"
            );
        }

        let migrated = raw_value(
            &db_path,
            crate::tables::MAP_NAMES,
            crate::tables::AGENTS,
            &record_key(1, "sensor@host1"),
        )
        .unwrap();
        let value: AgentValueV0_47Alpha2 = bincode::DefaultOptions::new()
            .deserialize(&migrated)
            .unwrap();
        assert_eq!(value.lifecycle, 0);
        assert!(value.bound_addrs.is_empty());

        assert_eq!(
            read_version_file(&data_dir.path().join("VERSION")).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join("VERSION")).unwrap(),
            current_version
        );
    }

    #[test]
    fn migration_from_v0_43_schema_creates_new_column_families() {
        assert_migration_creates_new_column_families("0.43.0");
    }

    #[test]
    fn migration_from_v0_44_schema_creates_new_column_families() {
        assert_migration_creates_new_column_families("0.44.0");
    }

    #[test]
    fn migration_from_v0_45_schema_creates_new_column_families() {
        assert_migration_creates_new_column_families("0.45.0");
    }

    #[test]
    fn migration_from_v0_46_schema_creates_new_column_families() {
        assert_migration_creates_new_column_families("0.46.0");
    }

    /// Test the rollback path end to end: a populated 0.46-format store whose
    /// markers are set through the public API migrates forward exactly as one
    /// whose markers were written by hand.
    ///
    /// This is what a rollback leaves behind — the restored `states.db` of the
    /// prior format under markers naming that format — so the next start must
    /// select the 0.46 migration rather than refuse the version.
    #[test]
    fn markers_written_for_rollback_let_migration_run_again() {
        let current_version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();

        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        create_states_db(&db_path, super::MAP_NAMES_V0_43_TO_V0_46);
        let (agents, external_services) = old_install_state_fixture();
        put_entries(
            &db_path,
            super::MAP_NAMES_V0_43_TO_V0_46,
            crate::tables::AGENTS,
            &agents,
        );
        put_entries(
            &db_path,
            super::MAP_NAMES_V0_43_TO_V0_46,
            crate::tables::EXTERNAL_SERVICES,
            &external_services,
        );

        // What the update left behind: both markers name the newer format even
        // though the restored `states.db` above is the older one.
        write_version(data_dir.path(), env!("CARGO_PKG_VERSION"));
        write_version(backup_dir.path(), env!("CARGO_PKG_VERSION"));

        write_version_markers(data_dir.path(), backup_dir.path(), "0.46.0").unwrap();

        let result = migrate_data_dir(data_dir.path(), backup_dir.path(), None);
        assert!(
            result.is_ok(),
            "migration must run from the marker this API wrote, got {:?}",
            result.as_ref().err().map(ToString::to_string)
        );

        let db = open_states_db(&db_path, crate::tables::MAP_NAMES);
        for name in [
            crate::tables::CUSTOMER_DELETION_JOBS,
            crate::tables::CORE_COMPONENTS,
            crate::tables::OPERATION_ATTEMPTS,
        ] {
            assert!(db.cf_handle(name).is_some(), "{name} must exist");
        }
        drop(db);

        for (key, _) in &agents {
            let migrated = raw_value(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::AGENTS,
                key,
            )
            .unwrap();
            let value: AgentValueV0_47Alpha2 = bincode::DefaultOptions::new()
                .deserialize(&migrated)
                .unwrap();
            assert_eq!(value.lifecycle, 0);
            assert!(value.bound_addrs.is_empty());
        }
        for (key, _) in &external_services {
            let migrated = raw_value(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::EXTERNAL_SERVICES,
                key,
            )
            .unwrap();
            let value: ExternalServiceValueV0_47Alpha2 = bincode::DefaultOptions::new()
                .deserialize(&migrated)
                .unwrap();
            assert_eq!(value.lifecycle, 0);
            assert!(value.bound_addrs.is_empty());
        }

        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
    }

    #[test]
    fn migration_retries_after_customer_deletion_jobs_cf_creation() {
        let current_version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db: rocksdb::OptimisticTransactionDB = rocksdb::OptimisticTransactionDB::open_cf(
            &opts,
            &db_path,
            super::MAP_NAMES_V0_43_TO_V0_46,
        )
        .unwrap();
        drop(db);

        super::migrate_0_46_to_0_47(data_dir.path()).unwrap();
        write_version(data_dir.path(), "0.45.0");
        write_version(backup_dir.path(), "0.45.0");

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join("VERSION")).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join("VERSION")).unwrap(),
            current_version
        );
    }

    // ---------------------------------------------------------------------
    // 0.47.0-alpha.2: install-state values and the two new column families
    // ---------------------------------------------------------------------

    /// The stored key of an agent or external-service record.
    fn record_key(node_id: u32, key: &str) -> Vec<u8> {
        let mut buf = node_id.to_be_bytes().to_vec();
        buf.extend(key.as_bytes());
        buf
    }

    /// Serializes an agent value in the layout stored up to 0.47.0-alpha.1.
    fn old_agent_value(
        kind: AgentKind,
        status: AgentStatus,
        config: Option<&str>,
        draft: Option<&str>,
    ) -> Vec<u8> {
        let value = AgentValueV0_47Alpha1 {
            kind,
            status,
            config: config.map(|c| AgentConfig::try_from(c.to_string()).unwrap()),
            draft: draft.map(|d| AgentConfig::try_from(d.to_string()).unwrap()),
        };
        bincode::DefaultOptions::new().serialize(&value).unwrap()
    }

    /// Serializes an external-service value in the layout stored up to
    /// 0.47.0-alpha.1.
    fn old_external_service_value(
        kind: ExternalServiceKind,
        status: ExternalServiceStatus,
        draft: Option<&str>,
    ) -> Vec<u8> {
        let value = ExternalServiceValueV0_47Alpha1 {
            kind,
            status,
            draft: draft.map(|d| ExternalServiceConfig::try_from(d.to_string()).unwrap()),
        };
        bincode::DefaultOptions::new().serialize(&value).unwrap()
    }

    fn create_states_db<'a>(db_path: &Path, families: impl IntoIterator<Item = &'a str>) {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, families).unwrap();
        drop(db);
    }

    fn open_states_db<'a>(
        db_path: &Path,
        families: impl IntoIterator<Item = &'a str>,
    ) -> rocksdb::OptimisticTransactionDB {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(false);
        opts.create_missing_column_families(false);
        rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, families).unwrap()
    }

    /// Writes the given entries into `cf_name` of an existing database.
    fn put_entries<'a>(
        db_path: &Path,
        families: impl IntoIterator<Item = &'a str>,
        cf_name: &str,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) {
        let db = open_states_db(db_path, families);
        let cf = db.cf_handle(cf_name).unwrap();
        for (key, value) in entries {
            db.put_cf(&cf, key, value).unwrap();
        }
    }

    fn raw_value<'a>(
        db_path: &Path,
        families: impl IntoIterator<Item = &'a str>,
        cf_name: &str,
        key: &[u8],
    ) -> Option<Vec<u8>> {
        let db = open_states_db(db_path, families);
        let cf = db.cf_handle(cf_name).unwrap();
        db.get_cf(&cf, key).unwrap()
    }

    /// A column family's worth of raw entries.
    type Entries = Vec<(Vec<u8>, Vec<u8>)>;

    /// The agents and external services an alpha.1 fixture holds, in the layout
    /// that format stored.
    fn old_install_state_fixture() -> (Entries, Entries) {
        let agents = vec![
            (
                record_key(1, "sensor@host1"),
                old_agent_value(
                    AgentKind::Sensor,
                    AgentStatus::Enabled,
                    Some("a = 1"),
                    Some("a = 2"),
                ),
            ),
            (
                record_key(2, "unsupervised@host2"),
                old_agent_value(AgentKind::Unsupervised, AgentStatus::Disabled, None, None),
            ),
            (
                record_key(3, "semi@host3"),
                old_agent_value(
                    AgentKind::SemiSupervised,
                    AgentStatus::ReloadFailed,
                    Some("b = \"x\""),
                    None,
                ),
            ),
        ];
        let external_services = vec![
            (
                record_key(1, "datastore@host1"),
                old_external_service_value(
                    ExternalServiceKind::DataStore,
                    ExternalServiceStatus::Enabled,
                    Some("c = 3"),
                ),
            ),
            (
                record_key(4, "ti@host4"),
                old_external_service_value(
                    ExternalServiceKind::TiContainer,
                    ExternalServiceStatus::Disabled,
                    None,
                ),
            ),
        ];
        (agents, external_services)
    }

    #[test]
    fn migration_from_v0_47_alpha_1_fills_install_state_defaults() {
        let permit = acquire_db_permit();
        let current_version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        create_states_db(&db_path, super::MAP_NAMES_V0_47_ALPHA_1);
        let (agents, external_services) = old_install_state_fixture();
        put_entries(
            &db_path,
            super::MAP_NAMES_V0_47_ALPHA_1,
            crate::tables::AGENTS,
            &agents,
        );
        put_entries(
            &db_path,
            super::MAP_NAMES_V0_47_ALPHA_1,
            crate::tables::EXTERNAL_SERVICES,
            &external_services,
        );

        write_version(data_dir.path(), "0.47.0-alpha.1");
        write_version(backup_dir.path(), "0.47.0-alpha.1");
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join("VERSION")).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join("VERSION")).unwrap(),
            current_version
        );
        assert_eq!(current_version.to_string(), "0.47.0-alpha.2");

        // The migration created both new families, and they start empty.
        {
            let db = open_states_db(&db_path, crate::tables::MAP_NAMES);
            for name in [
                crate::tables::CORE_COMPONENTS,
                crate::tables::OPERATION_ATTEMPTS,
            ] {
                let cf = db.cf_handle(name).unwrap();
                assert!(
                    db.iterator_cf(&cf, rocksdb::IteratorMode::Start)
                        .next()
                        .is_none()
                );
            }
        }

        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();

        let agent_map = store.agents_map();
        let sensor = agent_map.get(1, "sensor@host1").unwrap().unwrap();
        assert_eq!(sensor.node_id, 1);
        assert_eq!(sensor.key, "sensor@host1");
        assert_eq!(sensor.kind, AgentKind::Sensor);
        assert_eq!(sensor.status, AgentStatus::Enabled);
        assert_eq!(sensor.config.as_ref().map(AsRef::as_ref), Some("a = 1"));
        assert_eq!(sensor.draft.as_ref().map(AsRef::as_ref), Some("a = 2"));
        assert_eq!(sensor.installed_version, None);
        assert_eq!(sensor.installed_commit, None);
        assert_eq!(sensor.lifecycle, Lifecycle::NotInstalled);
        assert!(sensor.bound_addrs.is_empty());

        let unsupervised = agent_map.get(2, "unsupervised@host2").unwrap().unwrap();
        assert_eq!(unsupervised.kind, AgentKind::Unsupervised);
        assert_eq!(unsupervised.status, AgentStatus::Disabled);
        assert_eq!(unsupervised.config, None);
        assert_eq!(unsupervised.draft, None);
        assert_eq!(unsupervised.lifecycle, Lifecycle::NotInstalled);

        let semi = agent_map.get(3, "semi@host3").unwrap().unwrap();
        assert_eq!(semi.status, AgentStatus::ReloadFailed);
        assert_eq!(semi.config.as_ref().map(AsRef::as_ref), Some("b = \"x\""));
        assert_eq!(semi.draft, None);

        let external_service_map = store.external_service_map();
        let datastore = external_service_map
            .get(1, "datastore@host1")
            .unwrap()
            .unwrap();
        assert_eq!(datastore.node_id, 1);
        assert_eq!(datastore.key, "datastore@host1");
        assert_eq!(datastore.kind, ExternalServiceKind::DataStore);
        assert_eq!(datastore.status, ExternalServiceStatus::Enabled);
        assert_eq!(datastore.draft.as_ref().map(AsRef::as_ref), Some("c = 3"));
        assert_eq!(datastore.installed_version, None);
        assert_eq!(datastore.installed_commit, None);
        assert_eq!(datastore.lifecycle, Lifecycle::NotInstalled);
        assert!(datastore.bound_addrs.is_empty());

        let ti = external_service_map.get(4, "ti@host4").unwrap().unwrap();
        assert_eq!(ti.kind, ExternalServiceKind::TiContainer);
        assert_eq!(ti.status, ExternalServiceStatus::Disabled);
        assert_eq!(ti.draft, None);

        // Both new tables are reachable from `Store` and usable.
        let core_components = store.core_component_map();
        let component = CoreComponent {
            component: "roxyd".to_string(),
            host: "host1.example".to_string(),
            installed_version: Some("0.47.0".to_string()),
            installed_commit: Some("c0ffee".to_string()),
            lifecycle: Lifecycle::Running,
            installer_managed: false,
        };
        core_components.insert(&component).unwrap();
        assert_eq!(
            core_components.get("roxyd", "host1.example").unwrap(),
            Some(component)
        );

        let operation_attempts = store.operation_attempt_map();
        assert!(operation_attempts.get("no-such-key").unwrap().is_none());
        assert_eq!(
            operation_attempts
                .iter(rocksdb::Direction::Forward, None)
                .count(),
            0
        );

        drop(store);
        drop(permit);
    }

    /// Builds an alpha.1 database that also holds `extra` families, rewinds the
    /// version marker, and asserts that the retry completes.
    fn assert_retry_completes_with_families(extra: &[&str]) {
        let current_version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        let families: Vec<&str> = super::MAP_NAMES_V0_47_ALPHA_1
            .iter()
            .copied()
            .chain(extra.iter().copied())
            .collect();
        create_states_db(&db_path, families.iter().copied());

        let (agents, external_services) = old_install_state_fixture();
        put_entries(
            &db_path,
            families.iter().copied(),
            crate::tables::AGENTS,
            &agents,
        );
        put_entries(
            &db_path,
            families.iter().copied(),
            crate::tables::EXTERNAL_SERVICES,
            &external_services,
        );

        // A marker older than the families physically present: the chain reruns
        // the intermediate migrations, which must open exactly this set.
        write_version(data_dir.path(), "0.45.0");
        write_version(backup_dir.path(), "0.45.0");
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join("VERSION")).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join("VERSION")).unwrap(),
            current_version
        );

        let db = open_states_db(&db_path, crate::tables::MAP_NAMES);
        let cf = db.cf_handle(crate::tables::AGENTS).unwrap();
        let migrated = db
            .get_cf(&cf, record_key(1, "sensor@host1"))
            .unwrap()
            .unwrap();
        let value: AgentValueV0_47Alpha2 = bincode::DefaultOptions::new()
            .deserialize(&migrated)
            .unwrap();
        assert_eq!(value.lifecycle, 0);
    }

    #[test]
    fn migration_retries_with_neither_new_family() {
        assert_retry_completes_with_families(&[]);
    }

    #[test]
    fn migration_retries_with_core_components_only() {
        assert_retry_completes_with_families(&[crate::tables::CORE_COMPONENTS]);
    }

    #[test]
    fn migration_retries_with_operation_attempts_only() {
        assert_retry_completes_with_families(&[crate::tables::OPERATION_ATTEMPTS]);
    }

    #[test]
    fn migration_retries_with_both_new_families() {
        assert_retry_completes_with_families(&[
            crate::tables::CORE_COMPONENTS,
            crate::tables::OPERATION_ATTEMPTS,
        ]);
    }

    #[test]
    fn migration_leaves_current_values_byte_identical() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        create_states_db(&db_path, super::MAP_NAMES_V0_47_ALPHA_1);

        // A current-shaped agent carrying a lifecycle index no variant is
        // stored as, which must survive the migration untouched.
        let unrecognized_lifecycle = 9_u8;
        let current_agent = bincode::DefaultOptions::new()
            .serialize(&AgentValueV0_47Alpha2 {
                kind: AgentKind::TimeSeriesGenerator,
                status: AgentStatus::Enabled,
                config: None,
                draft: Some(AgentConfig::try_from("d = 4".to_string()).unwrap()),
                installed_version: Some("0.47.0".to_string()),
                installed_commit: Some("c0ffee".to_string()),
                lifecycle: unrecognized_lifecycle,
                bound_addrs: vec![("addr".to_string(), "host:1234".to_string())],
            })
            .unwrap();
        let current_external_service = bincode::DefaultOptions::new()
            .serialize(&ExternalServiceValueV0_47Alpha2 {
                kind: ExternalServiceKind::DataStore,
                status: ExternalServiceStatus::Enabled,
                draft: None,
                installed_version: Some("0.47.0".to_string()),
                installed_commit: None,
                lifecycle: unrecognized_lifecycle,
                bound_addrs: vec![("rpc".to_string(), "host:5678".to_string())],
            })
            .unwrap();

        let old_agent =
            old_agent_value(AgentKind::Sensor, AgentStatus::Enabled, Some("a = 1"), None);
        let old_external_service = old_external_service_value(
            ExternalServiceKind::TiContainer,
            ExternalServiceStatus::Disabled,
            Some("c = 3"),
        );

        put_entries(
            &db_path,
            super::MAP_NAMES_V0_47_ALPHA_1,
            crate::tables::AGENTS,
            &[
                (record_key(1, "old"), old_agent.clone()),
                (record_key(2, "current"), current_agent.clone()),
            ],
        );
        put_entries(
            &db_path,
            super::MAP_NAMES_V0_47_ALPHA_1,
            crate::tables::EXTERNAL_SERVICES,
            &[
                (record_key(1, "old"), old_external_service.clone()),
                (record_key(2, "current"), current_external_service.clone()),
            ],
        );

        write_version(data_dir.path(), "0.47.0-alpha.1");
        write_version(backup_dir.path(), "0.47.0-alpha.1");
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            raw_value(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::AGENTS,
                &record_key(2, "current")
            ),
            Some(current_agent)
        );
        assert_eq!(
            raw_value(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::EXTERNAL_SERVICES,
                &record_key(2, "current")
            ),
            Some(current_external_service)
        );
        assert_ne!(
            raw_value(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::AGENTS,
                &record_key(1, "old")
            ),
            Some(old_agent)
        );
        assert_ne!(
            raw_value(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::EXTERNAL_SERVICES,
                &record_key(1, "old")
            ),
            Some(old_external_service)
        );

        // The unrecognized lifecycle still reads back, as `Unknown`.
        let permit = acquire_db_permit();
        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        let agent = store.agents_map().get(2, "current").unwrap().unwrap();
        assert_eq!(agent.lifecycle, Lifecycle::Unknown);
        assert_eq!(
            agent.bound_addrs,
            vec![("addr".to_string(), "host:1234".to_string())]
        );
        let external_service = store
            .external_service_map()
            .get(2, "current")
            .unwrap()
            .unwrap();
        assert_eq!(external_service.lifecycle, Lifecycle::Unknown);
        let old = store.agents_map().get(1, "old").unwrap().unwrap();
        assert_eq!(old.lifecycle, Lifecycle::NotInstalled);
        drop(store);
        drop(permit);
    }

    /// A value matching neither pinned layout: the leading byte is a variant
    /// index neither `AgentKind` nor `ExternalServiceKind` defines.
    const FOREIGN_VALUE: &[u8] = b"\x09foreign value";

    fn assert_migration_rejects_foreign_value(cf_name: &str, record: &str) {
        let data_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        create_states_db(&db_path, super::MAP_NAMES_V0_47_ALPHA_1);
        let key = record_key(7, "foreign");
        put_entries(
            &db_path,
            super::MAP_NAMES_V0_47_ALPHA_1,
            cf_name,
            &[(key.clone(), FOREIGN_VALUE.to_vec())],
        );

        let error = super::migrate_0_46_to_0_47(data_dir.path()).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(record), "{message}");
        assert!(
            message.contains(&data_encoding::HEXLOWER.encode(&key)),
            "{message}"
        );
        assert!(message.contains("current schema error"), "{message}");
        assert!(message.contains("previous schema error"), "{message}");

        assert_eq!(
            raw_value(&db_path, crate::tables::MAP_NAMES, cf_name, &key),
            Some(FOREIGN_VALUE.to_vec()),
            "the unreadable value must be left as it was"
        );
    }

    #[test]
    fn migration_rejects_agent_value_matching_neither_schema() {
        assert_migration_rejects_foreign_value(crate::tables::AGENTS, "agent");
    }

    #[test]
    fn migration_rejects_external_service_value_matching_neither_schema() {
        assert_migration_rejects_foreign_value(
            crate::tables::EXTERNAL_SERVICES,
            "external service",
        );
    }

    /// Holds the pinned current layouts against the live table encodings they
    /// mirror, so a change to either side of that deliberate coupling fails
    /// here rather than at the next migration.
    ///
    /// Field-by-field comparison alone would not notice a field appended to a
    /// live `Value`, because `bincode` ignores bytes left over after the last
    /// field it was asked for. Re-encoding the pinned layout and demanding the
    /// same bytes back closes that, and an appended field is exactly the drift
    /// that would make this migration write values missing it.
    #[test]
    fn pinned_current_layouts_match_live_table_values() {
        use crate::tables::Value as ValueTrait;

        let agent = Agent {
            node_id: 11,
            key: "sensor@host".to_string(),
            kind: AgentKind::Sensor,
            status: AgentStatus::ReloadFailed,
            config: Some(AgentConfig::try_from("a = 1".to_string()).unwrap()),
            draft: Some(AgentConfig::try_from("a = 2".to_string()).unwrap()),
            installed_version: Some("0.47.0".to_string()),
            installed_commit: Some("c0ffee".to_string()),
            lifecycle: Lifecycle::Running,
            bound_addrs: vec![("addr".to_string(), "host:1234".to_string())],
        };
        let stored = agent.value();
        let pinned: AgentValueV0_47Alpha2 = bincode::DefaultOptions::new()
            .deserialize(stored.as_ref())
            .unwrap();
        assert_eq!(pinned.kind, agent.kind);
        assert_eq!(pinned.status, agent.status);
        assert_eq!(pinned.config, agent.config);
        assert_eq!(pinned.draft, agent.draft);
        assert_eq!(pinned.installed_version, agent.installed_version);
        assert_eq!(pinned.installed_commit, agent.installed_commit);
        assert_eq!(pinned.lifecycle, agent.lifecycle.to_stored_index());
        assert_eq!(pinned.bound_addrs, agent.bound_addrs);
        assert_eq!(
            bincode::DefaultOptions::new().serialize(&pinned).unwrap(),
            stored,
            "the pinned agent layout must re-encode to the live table value"
        );

        let external_service = ExternalService {
            node_id: 12,
            key: "datastore@host".to_string(),
            kind: ExternalServiceKind::DataStore,
            status: ExternalServiceStatus::Enabled,
            draft: Some(ExternalServiceConfig::try_from("c = 3".to_string()).unwrap()),
            installed_version: Some("0.47.0".to_string()),
            installed_commit: None,
            lifecycle: Lifecycle::Stopped,
            bound_addrs: vec![("rpc".to_string(), "host:5678".to_string())],
        };
        let stored = external_service.value();
        let pinned: ExternalServiceValueV0_47Alpha2 = bincode::DefaultOptions::new()
            .deserialize(stored.as_ref())
            .unwrap();
        assert_eq!(pinned.kind, external_service.kind);
        assert_eq!(pinned.status, external_service.status);
        assert_eq!(pinned.draft, external_service.draft);
        assert_eq!(pinned.installed_version, external_service.installed_version);
        assert_eq!(pinned.installed_commit, external_service.installed_commit);
        assert_eq!(
            pinned.lifecycle,
            external_service.lifecycle.to_stored_index()
        );
        assert_eq!(pinned.bound_addrs, external_service.bound_addrs);
        assert_eq!(
            bincode::DefaultOptions::new().serialize(&pinned).unwrap(),
            stored,
            "the pinned external-service layout must re-encode to the live table value"
        );
    }

    #[test]
    fn migration_body_writes_only_states_db() {
        let data_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        create_states_db(&db_path, super::MAP_NAMES_V0_47_ALPHA_1);
        let (agents, external_services) = old_install_state_fixture();
        put_entries(
            &db_path,
            super::MAP_NAMES_V0_47_ALPHA_1,
            crate::tables::AGENTS,
            &agents,
        );
        put_entries(
            &db_path,
            super::MAP_NAMES_V0_47_ALPHA_1,
            crate::tables::EXTERNAL_SERVICES,
            &external_services,
        );
        std::fs::write(data_dir.path().join("untouched"), b"keep me").unwrap();
        std::fs::create_dir(data_dir.path().join("events.db")).unwrap();
        std::fs::write(data_dir.path().join("events.db").join("CURRENT"), b"events").unwrap();

        let before = entries_outside_states_db(data_dir.path());
        super::migrate_0_46_to_0_47(data_dir.path()).unwrap();
        assert_eq!(entries_outside_states_db(data_dir.path()), before);
    }

    /// Every file under `data_dir` except the `states.db` directory, with its
    /// contents.
    fn entries_outside_states_db(data_dir: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
        fn collect(dir: &Path, entries: &mut Vec<(std::path::PathBuf, Vec<u8>)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    collect(&path, entries);
                } else {
                    entries.push((path.clone(), std::fs::read(&path).unwrap()));
                }
            }
        }

        let mut entries = Vec::new();
        for entry in std::fs::read_dir(data_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().is_some_and(|name| name == "states.db") {
                continue;
            }
            if path.is_dir() {
                collect(&path, &mut entries);
            } else {
                entries.push((path.clone(), std::fs::read(&path).unwrap()));
            }
        }
        entries.sort_unstable();
        entries
    }

    /// Test that the `0.42`-specific migration loop runs and updates `VERSION` files.
    #[test]
    fn migration_from_v0_42_schema() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let db_path = data_dir.path().join("states.db");
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, super::MAP_NAMES_V0_42)
                .unwrap();
        drop(db);

        let (agents, external_services) = old_install_state_fixture();
        put_entries(
            &db_path,
            super::MAP_NAMES_V0_42,
            crate::tables::AGENTS,
            &agents,
        );
        put_entries(
            &db_path,
            super::MAP_NAMES_V0_42,
            crate::tables::EXTERNAL_SERVICES,
            &external_services,
        );

        // Write an old version that needs migration
        write_version(data_dir.path(), "0.42.0");
        write_version(backup_dir.path(), "0.42.0");

        // Run the migration
        let result = migrate_data_dir(data_dir.path(), backup_dir.path(), None);
        assert!(result.is_ok(), "Migration should succeed");

        // Verify database opens with the current column families
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();
        assert!(db.cf_handle("label database").is_some());
        assert!(db.cf_handle("TI database").is_none());
        for name in [
            crate::tables::CUSTOMER_DELETION_JOBS,
            crate::tables::CORE_COMPONENTS,
            crate::tables::OPERATION_ATTEMPTS,
        ] {
            assert!(db.cf_handle(name).is_some(), "{name} must exist");
        }
        drop(db);

        // The install-state conversion also runs at the end of the longest
        // chain, over a database that started three formats back.
        for (cf_name, key) in [
            (crate::tables::AGENTS, record_key(1, "sensor@host1")),
            (
                crate::tables::EXTERNAL_SERVICES,
                record_key(1, "datastore@host1"),
            ),
        ] {
            let migrated =
                raw_value(&db_path, crate::tables::MAP_NAMES, cf_name, &key).expect("{cf_name}");
            let lifecycle = if cf_name == crate::tables::AGENTS {
                bincode::DefaultOptions::new()
                    .deserialize::<AgentValueV0_47Alpha2>(&migrated)
                    .unwrap()
                    .lifecycle
            } else {
                bincode::DefaultOptions::new()
                    .deserialize::<ExternalServiceValueV0_47Alpha2>(&migrated)
                    .unwrap()
                    .lifecycle
            };
            assert_eq!(lifecycle, 0, "{cf_name}");
        }

        // Verify both VERSION files are updated to the current package version
        let data_version = read_version_file(&data_dir.path().join("VERSION")).unwrap();
        let backup_version = read_version_file(&backup_dir.path().join("VERSION")).unwrap();

        let current_pkg_version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        assert_eq!(
            data_version, current_pkg_version,
            "Data VERSION should be updated to current package version"
        );
        assert_eq!(
            backup_version, current_pkg_version,
            "Backup VERSION should be updated to current package version"
        );
    }

    fn create_v0_42_database(db_path: &Path) {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, super::MAP_NAMES_V0_42)
                .unwrap();
        drop(db);
    }

    fn retry_migration_from_v0_42(data_dir: &Path, backup_dir: &Path) {
        write_version(data_dir, "0.42.0");
        write_version(backup_dir, "0.42.0");
        migrate_data_dir(data_dir, backup_dir, None).unwrap();

        let current_version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        assert_eq!(
            read_version_file(&data_dir.join("VERSION")).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.join("VERSION")).unwrap(),
            current_version
        );
    }

    fn assert_current_cf_value(db_path: &Path, cf_name: &str, key: &[u8], value: &[u8]) {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(false);
        opts.create_missing_column_families(false);
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, crate::tables::MAP_NAMES)
                .unwrap();
        let cf = db.cf_handle(cf_name).unwrap();
        assert_eq!(db.get_cf(cf, key).unwrap().as_deref(), Some(value));
    }

    #[test]
    fn migration_retries_after_account_policy_was_dropped() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_v0_42_database(&db_path);

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(false);
        opts.create_missing_column_families(false);
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, super::MAP_NAMES_V0_42)
                .unwrap();
        db.put_cf(db.cf_handle("TI database").unwrap(), b"ti-key", b"ti-value")
            .unwrap();
        drop(db);
        super::migrate_drop_account_policy(&db_path).unwrap();

        retry_migration_from_v0_42(data_dir.path(), backup_dir.path());
        assert_current_cf_value(&db_path, "label database", b"ti-key", b"ti-value");
    }

    #[test]
    fn migration_retries_while_ti_and_label_databases_both_exist() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_v0_42_database(&db_path);
        super::migrate_drop_account_policy(&db_path).unwrap();

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(false);
        opts.create_missing_column_families(false);
        let existing = super::existing_map_names(&opts, &db_path).unwrap();
        let mut db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, &existing).unwrap();
        let ti_cf = db.cf_handle("TI database").unwrap();
        db.put_cf(ti_cf, b"copied-key", b"copied-value").unwrap();
        db.put_cf(ti_cf, b"ti-only-key", b"ti-only-value").unwrap();
        db.create_cf("label database", &rocksdb::Options::default())
            .unwrap();
        let label_cf = db.cf_handle("label database").unwrap();
        db.put_cf(label_cf, b"copied-key", b"copied-value").unwrap();
        db.put_cf(label_cf, b"label-only-key", b"label-only-value")
            .unwrap();
        drop(db);

        retry_migration_from_v0_42(data_dir.path(), backup_dir.path());
        assert_current_cf_value(&db_path, "label database", b"copied-key", b"copied-value");
        assert_current_cf_value(&db_path, "label database", b"ti-only-key", b"ti-only-value");
        assert_current_cf_value(
            &db_path,
            "label database",
            b"label-only-key",
            b"label-only-value",
        );
    }

    #[test]
    fn migration_retries_after_ti_database_was_renamed() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_v0_42_database(&db_path);

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(false);
        opts.create_missing_column_families(false);
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, super::MAP_NAMES_V0_42)
                .unwrap();
        db.put_cf(
            db.cf_handle("TI database").unwrap(),
            b"label-key",
            b"label-value",
        )
        .unwrap();
        drop(db);
        super::migrate_drop_account_policy(&db_path).unwrap();
        super::migrate_rename_tidb_to_label_db(&db_path).unwrap();

        retry_migration_from_v0_42(data_dir.path(), backup_dir.path());
        assert_current_cf_value(&db_path, "label database", b"label-key", b"label-value");
    }

    #[test]
    fn migration_retries_after_triage_exclusion_reason_was_created() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_v0_42_database(&db_path);
        super::migrate_drop_account_policy(&db_path).unwrap();
        super::migrate_rename_tidb_to_label_db(&db_path).unwrap();
        super::migrate_create_triage_exclusion_reason_cf(&db_path).unwrap();

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(false);
        opts.create_missing_column_families(false);
        let db: rocksdb::OptimisticTransactionDB = rocksdb::OptimisticTransactionDB::open_cf(
            &opts,
            &db_path,
            super::MAP_NAMES_V0_43_TO_V0_46,
        )
        .unwrap();
        db.put_cf(
            db.cf_handle(crate::tables::TRIAGE_EXCLUSION_REASON)
                .unwrap(),
            b"reason-key",
            b"reason-value",
        )
        .unwrap();
        drop(db);

        retry_migration_from_v0_42(data_dir.path(), backup_dir.path());
        assert_current_cf_value(
            &db_path,
            crate::tables::TRIAGE_EXCLUSION_REASON,
            b"reason-key",
            b"reason-value",
        );
    }

    #[test]
    fn migration_retries_after_customer_specific_networks_were_migrated() {
        use bincode::Options;

        use crate::collections::KeyIndex;
        use crate::migration::migration_structures::{AllowNetworkV0_42, BlockNetworkV0_42};
        use crate::{Customer, HostNetworkGroup};

        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_v0_42_database(&db_path);

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(false);
        opts.create_missing_column_families(false);
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, super::MAP_NAMES_V0_42)
                .unwrap();
        let txn = db.transaction();

        let mut customer = Customer {
            id: u32::MAX,
            name: "Customer".to_string(),
            description: String::new(),
            networks: Vec::new(),
            creation_time: chrono::Utc::now(),
        };
        let mut customer_index = KeyIndex::default();
        let customer_id = customer_index.insert(customer.key().as_ref()).unwrap();
        customer.set_index(customer_id);
        let customers_cf = db.cf_handle("customers").unwrap();
        txn.put_cf(customers_cf, customer.indexed_key(), customer.value())
            .unwrap();
        txn.put_cf(
            customers_cf,
            [],
            bincode::DefaultOptions::new()
                .serialize(&customer_index)
                .unwrap(),
        )
        .unwrap();

        let old_allow = AllowNetworkV0_42 {
            id: u32::MAX,
            name: "Old Allow".to_string(),
            networks: HostNetworkGroup::default(),
            description: "allow description".to_string(),
        };
        txn.put_cf(
            db.cf_handle("allow networks").unwrap(),
            old_allow.name.as_bytes(),
            bincode::DefaultOptions::new()
                .serialize(&old_allow)
                .unwrap(),
        )
        .unwrap();

        let old_block = BlockNetworkV0_42 {
            id: u32::MAX,
            name: "Old Block".to_string(),
            networks: HostNetworkGroup::default(),
            description: "block description".to_string(),
        };
        txn.put_cf(
            db.cf_handle("block networks").unwrap(),
            old_block.name.as_bytes(),
            bincode::DefaultOptions::new()
                .serialize(&old_block)
                .unwrap(),
        )
        .unwrap();
        txn.commit().unwrap();
        drop(db);

        super::migrate_0_42_to_0_43(data_dir.path()).unwrap();
        retry_migration_from_v0_42(data_dir.path(), backup_dir.path());

        let mut allow_key = customer_id.to_be_bytes().to_vec();
        allow_key.extend_from_slice(b"Old Allow");
        let mut block_key = customer_id.to_be_bytes().to_vec();
        block_key.extend_from_slice(b"Old Block");
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(false);
        opts.create_missing_column_families(false);
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();
        assert!(
            db.get_cf(db.cf_handle("allow networks").unwrap(), allow_key)
                .unwrap()
                .is_some()
        );
        assert!(
            db.get_cf(db.cf_handle("block networks").unwrap(), block_key)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn migration_retries_from_current_cf_set_with_v0_42_version() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();
        db.put_cf(
            db.cf_handle(crate::tables::CUSTOMER_DELETION_JOBS).unwrap(),
            b"job-key",
            b"job-value",
        )
        .unwrap();
        drop(db);

        retry_migration_from_v0_42(data_dir.path(), backup_dir.path());
        assert_current_cf_value(
            &db_path,
            crate::tables::CUSTOMER_DELETION_JOBS,
            b"job-key",
            b"job-value",
        );
    }

    #[allow(dead_code)]
    struct TestSchema {
        permit: DbGuard<'static>,
        db_dir: tempfile::TempDir,
        backup_dir: tempfile::TempDir,
        store: Store,
    }

    impl TestSchema {
        #[allow(dead_code)]
        fn new() -> Self {
            let permit = acquire_db_permit();
            let db_dir = tempfile::tempdir().unwrap();
            let backup_dir = tempfile::tempdir().unwrap();
            let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
            TestSchema {
                permit,
                db_dir,
                backup_dir,
                store,
            }
        }

        #[allow(dead_code)]
        fn new_with_dir(
            permit: DbGuard<'static>,
            db_dir: tempfile::TempDir,
            backup_dir: tempfile::TempDir,
        ) -> Self {
            let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
            TestSchema {
                permit,
                db_dir,
                backup_dir,
                store,
            }
        }

        #[allow(dead_code)]
        fn close(self) -> (DbGuard<'static>, tempfile::TempDir, tempfile::TempDir) {
            (self.permit, self.db_dir, self.backup_dir)
        }
    }

    #[test]
    fn version() {
        let compatible = VersionReq::parse(COMPATIBLE_VERSION_REQ).expect("valid semver");
        let current = Version::parse(env!("CARGO_PKG_VERSION")).expect("valid semver");

        // The current version must match the compatible version requirement.
        if current.pre.is_empty() {
            assert!(compatible.matches(&current));
        } else if current.major == 0 && current.patch != 0 || current.major >= 1 {
            // A pre-release for a backward-compatible version.
            let non_pre = Version::new(current.major, current.minor, current.patch);
            assert!(compatible.matches(&non_pre));
        } else {
            assert!(compatible.matches(&current));
        }

        // A future, backward-incompatible version must not match the compatible version.
        let breaking = {
            let mut breaking = current;
            if breaking.major == 0 {
                breaking.minor += 1;
            } else {
                breaking.major += 1;
            }
            breaking
        };
        assert!(!compatible.matches(&breaking));
    }

    #[test]
    fn migrate_0_42_to_0_43_updates_column_families() {
        // Create test directories
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("states.db");

        // Create a database with the old column family list (including "account policy")
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Create database with V0_42 schema and add test data to "TI database"
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, super::MAP_NAMES_V0_42)
                .unwrap();

        // Add test data to "TI database" column family
        let ti_cf = db.cf_handle("TI database").unwrap();
        db.put_cf(ti_cf, b"test_key_1", b"test_value_1").unwrap();
        db.put_cf(ti_cf, b"test_key_2", b"test_value_2").unwrap();
        drop(db);

        // Run the migration
        super::migrate_drop_account_policy(&db_path).unwrap();
        super::migrate_rename_tidb_to_label_db(&db_path).unwrap();

        let mut strict_opts = rocksdb::Options::default();
        strict_opts.create_if_missing(false);
        strict_opts.create_missing_column_families(false);

        // Verify the rename produces the intermediate schema without the new column family.
        let db: rocksdb::OptimisticTransactionDB = rocksdb::OptimisticTransactionDB::open_cf(
            &strict_opts,
            &db_path,
            super::map_names_v0_43_without_triage_exclusion_reason(),
        )
        .unwrap();

        // Verify "account policy" is dropped
        assert!(db.cf_handle("account policy").is_none());

        // Verify "TI database" is dropped
        assert!(db.cf_handle("TI database").is_none());

        // Verify "triage exclusion reason" has not been created by the rename.
        assert!(
            db.cf_handle(crate::tables::TRIAGE_EXCLUSION_REASON)
                .is_none()
        );

        // Verify "label database" exists and contains the migrated data
        let label_cf = db.cf_handle("label database").unwrap();
        assert_eq!(
            db.get_cf(label_cf, b"test_key_1").unwrap().as_deref(),
            Some(b"test_value_1".as_slice())
        );
        assert_eq!(
            db.get_cf(label_cf, b"test_key_2").unwrap().as_deref(),
            Some(b"test_value_2".as_slice())
        );
        drop(db);

        // Verify the dedicated migration creates the new column family.
        super::migrate_create_triage_exclusion_reason_cf(&db_path).unwrap();

        let db: rocksdb::OptimisticTransactionDB = rocksdb::OptimisticTransactionDB::open_cf(
            &strict_opts,
            &db_path,
            super::MAP_NAMES_V0_43_TO_V0_46,
        )
        .unwrap();
        assert!(
            db.cf_handle(crate::tables::TRIAGE_EXCLUSION_REASON)
                .is_some()
        );
        drop(db);
    }

    #[test]
    fn test_migrate_customer_specific_networks() {
        use bincode::Options;

        use super::{
            migrate_customer_specific_networks,
            migration_structures::{AllowNetworkV0_42, BlockNetworkV0_42},
        };
        use crate::{Customer, HostNetworkGroup, Iterable, collections::KeyIndex};

        // 1. Setup: Create database, customers, and old-format data
        let db_dir = tempfile::tempdir().unwrap();
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let db_path = db_dir.path().join("states.db");
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();
        let txn = db.transaction();

        // Insert two customers
        let customers_cf = db.cf_handle("customers").unwrap();
        let customers = [
            Customer {
                id: u32::MAX,
                name: "Customer A".to_string(),
                description: String::new(),
                networks: Vec::new(),
                creation_time: chrono::Utc::now(),
            },
            Customer {
                id: u32::MAX,
                name: "Customer B".to_string(),
                description: String::new(),
                networks: Vec::new(),
                creation_time: chrono::Utc::now(),
            },
        ];
        let mut customer_index = KeyIndex::default();
        for mut customer in customers {
            let id = customer_index.insert(customer.key().as_ref()).unwrap();
            customer.set_index(id);
            txn.put_cf(customers_cf, customer.indexed_key(), customer.value())
                .unwrap();
        }
        let customer_index_bytes = bincode::DefaultOptions::new()
            .serialize(&customer_index)
            .unwrap();
        txn.put_cf(customers_cf, [], &customer_index_bytes).unwrap();

        // Insert one old AllowNetwork
        let allow_cf = db.cf_handle("allow networks").unwrap();
        let old_allow = AllowNetworkV0_42 {
            id: u32::MAX,
            name: "Old Allow".to_string(),
            networks: HostNetworkGroup::default(),
            description: "Old Allow Description".to_string(),
        };
        let allow_value = bincode::DefaultOptions::new()
            .serialize(&old_allow)
            .unwrap();
        txn.put_cf(allow_cf, old_allow.name.as_bytes(), &allow_value)
            .unwrap();

        // Insert one old BlockNetwork
        let block_cf = db.cf_handle("block networks").unwrap();
        let old_block = BlockNetworkV0_42 {
            id: u32::MAX,
            name: "Old Block".to_string(),
            networks: HostNetworkGroup::default(),
            description: "Old Block Description".to_string(),
        };
        let block_value = bincode::DefaultOptions::new()
            .serialize(&old_block)
            .unwrap();
        txn.put_cf(block_cf, old_block.name.as_bytes(), &block_value)
            .unwrap();
        txn.commit().unwrap();
        drop(db);

        // 2. Run the migration
        migrate_customer_specific_networks(&db_path).unwrap();

        // 3. Verification
        let test_schema =
            TestSchema::new_with_dir(acquire_db_permit(), db_dir, tempfile::tempdir().unwrap());

        let customers = test_schema
            .store
            .customer_map()
            .iter(rocksdb::Direction::Forward, None)
            .filter_map(Result::ok)
            .map(|s| s.id)
            .collect::<Vec<_>>();
        assert_eq!(customers.len(), 2, "Should have 2 customer entries");

        // Verify AllowNetwork
        let all_allows = test_schema
            .store
            .allow_network_map()
            .iter(rocksdb::Direction::Forward, None)
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        assert_eq!(
            all_allows.len(),
            2,
            "Should have 2 AllowNetwork entries after migration"
        );

        let customer_one_allows: Vec<_> = test_schema
            .store
            .allow_network_map()
            .prefix_iter(
                rocksdb::Direction::Forward,
                None,
                &customers[0].to_be_bytes(),
            )
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        assert_eq!(customer_one_allows.len(), 1);
        assert_eq!(customer_one_allows[0].customer_id, 0);
        assert_eq!(customer_one_allows[0].name, "Old Allow");
        assert_eq!(customer_one_allows[0].description, "Old Allow Description");

        let customer_two_allows: Vec<_> = test_schema
            .store
            .allow_network_map()
            .prefix_iter(
                rocksdb::Direction::Forward,
                None,
                &customers[1].to_be_bytes(),
            )
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        assert_eq!(customer_two_allows.len(), 1);
        assert_eq!(customer_two_allows[0].customer_id, 1);
        assert_eq!(customer_two_allows[0].name, "Old Allow");
        assert_eq!(customer_two_allows[0].description, "Old Allow Description");

        // Verify BlockNetwork
        let all_blocks = test_schema
            .store
            .block_network_map()
            .iter(rocksdb::Direction::Forward, None)
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        assert_eq!(
            all_blocks.len(),
            2,
            "Should have 2 AllowNetwork entries after migration"
        );

        let customer_one_blocks: Vec<_> = test_schema
            .store
            .block_network_map()
            .prefix_iter(
                rocksdb::Direction::Forward,
                None,
                &customers[0].to_be_bytes(),
            )
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        assert_eq!(customer_one_blocks.len(), 1);
        assert_eq!(customer_one_blocks[0].customer_id, 0);
        assert_eq!(customer_one_blocks[0].name, "Old Block");
        assert_eq!(customer_one_blocks[0].description, "Old Block Description");

        let customer_two_blocks: Vec<_> = test_schema
            .store
            .block_network_map()
            .prefix_iter(
                rocksdb::Direction::Forward,
                None,
                &customers[1].to_be_bytes(),
            )
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        assert_eq!(customer_two_blocks.len(), 1);
        assert_eq!(customer_two_blocks[0].customer_id, 1);
        assert_eq!(customer_two_blocks[0].name, "Old Block");
        assert_eq!(customer_two_blocks[0].description, "Old Block Description");
    }

    #[test]
    fn migrate_network_tags_to_customer_scoped() {
        use std::fs;
        use std::io::Write;

        use bincode::Options;

        use crate::collections::KeyIndex;
        use crate::tables::{CUSTOMERS, META};

        let _permit = acquire_db_permit();

        // Create test directories
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let db_path = db_dir.path().join("states.db");
        let backup_path = backup_dir.path().join("states.db");

        // Create a database with the current column families
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Open and set up the main database
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();

        // Create a customer with ID 5
        let customers_cf = db.cf_handle(CUSTOMERS).unwrap();
        let mut customer_index = KeyIndex::default();
        // Insert customer with name "test_customer" - this will get ID 0, not 5
        // But we can't easily set a specific ID. Let's insert multiple to get ID 5
        for _ in 0..5 {
            customer_index
                .insert(b"dummy")
                .expect("insert should succeed");
        }
        // Now insert one more to have a valid customer
        customer_index
            .insert(b"test_customer")
            .expect("insert should succeed");
        let serialized_customer_index = bincode::DefaultOptions::new()
            .serialize(&customer_index)
            .unwrap();
        db.put_cf(customers_cf, [], &serialized_customer_index)
            .unwrap();

        // Create network tags without prefix
        let meta_cf = db.cf_handle(META).unwrap();
        let mut network_tags_index = KeyIndex::default();
        network_tags_index.insert(b"tag1").unwrap();
        network_tags_index.insert(b"tag2").unwrap();
        network_tags_index.insert(b"tag3").unwrap();
        let serialized_tags = bincode::DefaultOptions::new()
            .serialize(&network_tags_index)
            .unwrap();
        db.put_cf(meta_cf, NETWORK_TAGS, &serialized_tags).unwrap();

        drop(db);

        // Create backup database with the same structure
        let backup_db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(
                &opts,
                &backup_path,
                crate::tables::MAP_NAMES,
            )
            .unwrap();
        let backup_customers_cf = backup_db.cf_handle(CUSTOMERS).unwrap();
        backup_db
            .put_cf(backup_customers_cf, [], &serialized_customer_index)
            .unwrap();
        let backup_meta_cf = backup_db.cf_handle(META).unwrap();
        backup_db
            .put_cf(backup_meta_cf, NETWORK_TAGS, &serialized_tags)
            .unwrap();
        drop(backup_db);

        // Create VERSION files with 0.43.0-alpha.1
        let mut version_file = fs::File::create(db_dir.path().join("VERSION")).unwrap();
        version_file.write_all(b"0.43.0-alpha.1").unwrap();
        drop(version_file);

        let mut backup_version_file = fs::File::create(backup_dir.path().join("VERSION")).unwrap();
        backup_version_file.write_all(b"0.43.0-alpha.1").unwrap();
        drop(backup_version_file);

        // Run the migration on both directories
        super::migrate_network_tags_to_customer_scoped(db_dir.path()).unwrap();
        super::migrate_network_tags_to_customer_scoped(backup_dir.path()).unwrap();

        // Verify the tags have been prefixed in main database
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();
        let meta_cf = db.cf_handle(META).unwrap();
        let index_bytes = db.get_cf(meta_cf, NETWORK_TAGS).unwrap().unwrap();
        let index = KeyIndex::from_bytes(&index_bytes).unwrap();

        // The smallest customer ID should be 0 (first inserted dummy customer)
        let prefix = b"0\0";
        for (_id, key) in index.iter() {
            assert!(
                key.starts_with(prefix),
                "Tag key should be prefixed with '0\\0': {:?}",
                String::from_utf8_lossy(key)
            );
            // Extract the actual tag name
            let tag_name = &key[prefix.len()..];
            assert!(
                tag_name == b"tag1" || tag_name == b"tag2" || tag_name == b"tag3",
                "Unexpected tag name: {:?}",
                String::from_utf8_lossy(tag_name)
            );
        }
        drop(db);

        // Verify the tags have been prefixed in backup database
        let backup_db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(
                &opts,
                &backup_path,
                crate::tables::MAP_NAMES,
            )
            .unwrap();
        let backup_meta_cf = backup_db.cf_handle(META).unwrap();
        let backup_index_bytes = backup_db
            .get_cf(backup_meta_cf, NETWORK_TAGS)
            .unwrap()
            .unwrap();
        let backup_index = KeyIndex::from_bytes(&backup_index_bytes).unwrap();

        for (_id, key) in backup_index.iter() {
            assert!(
                key.starts_with(prefix),
                "Backup tag key should be prefixed: {:?}",
                String::from_utf8_lossy(key)
            );
        }
    }

    #[test]
    fn migrate_network_tags_no_customers_skips() {
        use std::fs;
        use std::io::Write;

        use bincode::Options;

        use crate::collections::KeyIndex;
        use crate::tables::META;

        let _permit = acquire_db_permit();

        // Create test directories
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let db_path = db_dir.path().join("states.db");
        let backup_path = backup_dir.path().join("states.db");

        // Create a database with the current column families
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Open and set up the main database - NO customers
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();

        // Create network tags without prefix
        let meta_cf = db.cf_handle(META).unwrap();
        let mut network_tags_index = KeyIndex::default();
        network_tags_index.insert(b"tag1").unwrap();
        network_tags_index.insert(b"tag2").unwrap();
        let serialized_tags = bincode::DefaultOptions::new()
            .serialize(&network_tags_index)
            .unwrap();
        db.put_cf(meta_cf, NETWORK_TAGS, &serialized_tags).unwrap();

        drop(db);

        // Create backup database with the same structure
        let backup_db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(
                &opts,
                &backup_path,
                crate::tables::MAP_NAMES,
            )
            .unwrap();
        let backup_meta_cf = backup_db.cf_handle(META).unwrap();
        backup_db
            .put_cf(backup_meta_cf, NETWORK_TAGS, &serialized_tags)
            .unwrap();
        drop(backup_db);

        // Create VERSION files with 0.43.0-alpha.1
        let mut version_file = fs::File::create(db_dir.path().join("VERSION")).unwrap();
        version_file.write_all(b"0.43.0-alpha.1").unwrap();
        drop(version_file);

        let mut backup_version_file = fs::File::create(backup_dir.path().join("VERSION")).unwrap();
        backup_version_file.write_all(b"0.43.0-alpha.1").unwrap();
        drop(backup_version_file);

        // Run the migration - should not fail
        super::migrate_network_tags_to_customer_scoped(db_dir.path()).unwrap();

        // Verify the tags are NOT prefixed (migration was skipped)
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();
        let meta_cf = db.cf_handle(META).unwrap();
        let index_bytes = db.get_cf(meta_cf, NETWORK_TAGS).unwrap().unwrap();
        let index = KeyIndex::from_bytes(&index_bytes).unwrap();

        for (_id, key) in index.iter() {
            // Tags should NOT have a null byte (not prefixed)
            assert!(
                !key.contains(&0),
                "Tag key should not be prefixed when no customers exist: {:?}",
                String::from_utf8_lossy(key)
            );
        }
    }

    #[test]
    fn migrate_network_tags_already_prefixed_skips() {
        use std::fs;
        use std::io::Write;

        use bincode::Options;

        use crate::collections::KeyIndex;
        use crate::tables::{CUSTOMERS, META};

        let _permit = acquire_db_permit();

        // Create test directories
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let db_path = db_dir.path().join("states.db");
        let backup_path = backup_dir.path().join("states.db");

        // Create a database with the current column families
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Open and set up the main database
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();

        // Create a customer
        let customers_cf = db.cf_handle(CUSTOMERS).unwrap();
        let mut customer_index = KeyIndex::default();
        customer_index
            .insert(b"test_customer")
            .expect("insert should succeed");
        let serialized_customer_index = bincode::DefaultOptions::new()
            .serialize(&customer_index)
            .unwrap();
        db.put_cf(customers_cf, [], &serialized_customer_index)
            .unwrap();

        // Create network tags that are already prefixed
        let meta_cf = db.cf_handle(META).unwrap();
        let mut network_tags_index = KeyIndex::default();
        network_tags_index.insert(b"0\0tag1").unwrap(); // Already prefixed
        network_tags_index.insert(b"0\0tag2").unwrap(); // Already prefixed
        let serialized_tags = bincode::DefaultOptions::new()
            .serialize(&network_tags_index)
            .unwrap();
        db.put_cf(meta_cf, NETWORK_TAGS, &serialized_tags).unwrap();

        drop(db);

        // Create backup database with the same structure
        let backup_db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(
                &opts,
                &backup_path,
                crate::tables::MAP_NAMES,
            )
            .unwrap();
        let backup_customers_cf = backup_db.cf_handle(CUSTOMERS).unwrap();
        backup_db
            .put_cf(backup_customers_cf, [], &serialized_customer_index)
            .unwrap();
        let backup_meta_cf = backup_db.cf_handle(META).unwrap();
        backup_db
            .put_cf(backup_meta_cf, NETWORK_TAGS, &serialized_tags)
            .unwrap();
        drop(backup_db);

        // Create VERSION files with 0.43.0-alpha.1
        let mut version_file = fs::File::create(db_dir.path().join("VERSION")).unwrap();
        version_file.write_all(b"0.43.0-alpha.1").unwrap();
        drop(version_file);

        let mut backup_version_file = fs::File::create(backup_dir.path().join("VERSION")).unwrap();
        backup_version_file.write_all(b"0.43.0-alpha.1").unwrap();
        drop(backup_version_file);

        // Run the migration - should skip since already prefixed
        super::migrate_network_tags_to_customer_scoped(db_dir.path()).unwrap();

        // Verify the tags remain the same (not double-prefixed)
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();
        let meta_cf = db.cf_handle(META).unwrap();
        let index_bytes = db.get_cf(meta_cf, NETWORK_TAGS).unwrap().unwrap();
        let index = KeyIndex::from_bytes(&index_bytes).unwrap();

        let prefix = b"0\0";
        for (_id, key) in index.iter() {
            // Should still have the original prefix
            assert!(key.starts_with(prefix));
            // Should NOT be double-prefixed (e.g., "0\00\0tag1")
            let after_prefix = &key[prefix.len()..];
            assert!(
                !after_prefix.starts_with(prefix),
                "Tag should not be double-prefixed"
            );
        }
    }

    /// Helper to create an old-format network key (name + id as 4-byte big-endian)
    fn make_old_network_key(name: &str, id: u32) -> Vec<u8> {
        let mut key = name.as_bytes().to_vec();
        key.extend_from_slice(&id.to_be_bytes());
        key
    }

    #[test]
    fn migrate_network_cf_single_entry() {
        use bincode::Options;

        use super::migration_structures::NetworkValueV0_43;
        use crate::{HostNetworkGroup, Iterable};

        let permit = acquire_db_permit();

        // Create test database
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("states.db");

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Create database and insert old-format network entry
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();

        let networks_cf = db.cf_handle("networks").unwrap();

        // Create old-format network entry
        // Old key: name bytes + id (4 bytes big-endian)
        // Old value: NetworkValueV0_43 (without id, with customer_ids)
        let old_value = NetworkValueV0_43 {
            description: "Test network description".to_string(),
            networks: HostNetworkGroup::default(),
            customer_ids: vec![1, 2, 3],
            tag_ids: vec![10, 20],
            creation_time: chrono::Utc::now(),
        };

        let old_key = make_old_network_key("TestNetwork", 5);
        let old_value_bytes = bincode::DefaultOptions::new()
            .serialize(&old_value)
            .unwrap();

        db.put_cf(networks_cf, &old_key, &old_value_bytes).unwrap();
        drop(db);

        // Run the migration
        super::migrate_network_cf_inner(&db_path, &opts, &crate::tables::MAP_NAMES).unwrap();

        // Verify the migration
        let test_schema = TestSchema::new_with_dir(permit, db_dir, tempfile::tempdir().unwrap());

        let networks: Vec<_> = test_schema
            .store
            .network_map()
            .iter(rocksdb::Direction::Forward, None)
            .filter_map(Result::ok)
            .collect();

        assert_eq!(networks.len(), 1, "Should have exactly one network");
        assert_eq!(networks[0].name, "TestNetwork");
        assert_eq!(networks[0].id, 5);
        assert_eq!(networks[0].description, "Test network description");
        assert_eq!(networks[0].tag_ids(), &[10, 20]);
        // customer_ids should be gone (not part of the new schema)
    }

    #[test]
    fn migrate_network_cf_deduplicates_by_name_keeps_smallest_id() {
        use bincode::Options;

        use super::migration_structures::NetworkValueV0_43;
        use crate::{HostNetworkGroup, Iterable};

        let permit = acquire_db_permit();

        // Create test database
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("states.db");

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Create database and insert multiple old-format network entries with same name
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();

        let networks_cf = db.cf_handle("networks").unwrap();

        let creation_time = chrono::Utc::now();

        // Entry 1: "DuplicateNet" with id=10
        let old_value1 = NetworkValueV0_43 {
            description: "Description for id 10".to_string(),
            networks: HostNetworkGroup::default(),
            customer_ids: vec![1],
            tag_ids: vec![100],
            creation_time,
        };
        let old_key1 = make_old_network_key("DuplicateNet", 10);
        let old_value_bytes1 = bincode::DefaultOptions::new()
            .serialize(&old_value1)
            .unwrap();
        db.put_cf(networks_cf, &old_key1, &old_value_bytes1)
            .unwrap();

        // Entry 2: "DuplicateNet" with id=3 (smallest - should be kept)
        let old_value2 = NetworkValueV0_43 {
            description: "Description for id 3".to_string(),
            networks: HostNetworkGroup::default(),
            customer_ids: vec![2],
            tag_ids: vec![200],
            creation_time,
        };
        let old_key2 = make_old_network_key("DuplicateNet", 3);
        let old_value_bytes2 = bincode::DefaultOptions::new()
            .serialize(&old_value2)
            .unwrap();
        db.put_cf(networks_cf, &old_key2, &old_value_bytes2)
            .unwrap();

        // Entry 3: "DuplicateNet" with id=7
        let old_value3 = NetworkValueV0_43 {
            description: "Description for id 7".to_string(),
            networks: HostNetworkGroup::default(),
            customer_ids: vec![3],
            tag_ids: vec![300],
            creation_time,
        };
        let old_key3 = make_old_network_key("DuplicateNet", 7);
        let old_value_bytes3 = bincode::DefaultOptions::new()
            .serialize(&old_value3)
            .unwrap();
        db.put_cf(networks_cf, &old_key3, &old_value_bytes3)
            .unwrap();

        // Entry 4: "UniqueNet" with id=1 (different name, should be preserved)
        let old_value4 = NetworkValueV0_43 {
            description: "Unique network".to_string(),
            networks: HostNetworkGroup::default(),
            customer_ids: vec![4],
            tag_ids: vec![400],
            creation_time,
        };
        let old_key4 = make_old_network_key("UniqueNet", 1);
        let old_value_bytes4 = bincode::DefaultOptions::new()
            .serialize(&old_value4)
            .unwrap();
        db.put_cf(networks_cf, &old_key4, &old_value_bytes4)
            .unwrap();

        drop(db);

        // Run the migration
        super::migrate_network_cf_inner(&db_path, &opts, &crate::tables::MAP_NAMES).unwrap();

        // Verify the migration
        let test_schema = TestSchema::new_with_dir(permit, db_dir, tempfile::tempdir().unwrap());

        let networks: Vec<_> = test_schema
            .store
            .network_map()
            .iter(rocksdb::Direction::Forward, None)
            .filter_map(Result::ok)
            .collect();

        assert_eq!(
            networks.len(),
            2,
            "Should have exactly two networks (duplicates removed)"
        );

        // Find the DuplicateNet entry - should have id=3 (smallest)
        let duplicate_net = networks.iter().find(|n| n.name == "DuplicateNet").unwrap();
        assert_eq!(
            duplicate_net.id, 3,
            "Should keep the entry with smallest id"
        );
        assert_eq!(duplicate_net.description, "Description for id 3");
        assert_eq!(duplicate_net.tag_ids(), &[200]);

        // Find the UniqueNet entry - should be preserved
        let unique_net = networks.iter().find(|n| n.name == "UniqueNet").unwrap();
        assert_eq!(unique_net.id, 1);
        assert_eq!(unique_net.description, "Unique network");
        assert_eq!(unique_net.tag_ids(), &[400]);
    }

    #[test]
    fn migrate_network_cf_empty_column_family() {
        use crate::Iterable;

        let permit = acquire_db_permit();

        // Create test database
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("states.db");

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Create empty database with networks column family
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();
        drop(db);

        // Run the migration - should not fail on empty column family
        super::migrate_network_cf_inner(&db_path, &opts, &crate::tables::MAP_NAMES).unwrap();

        // Verify the migration produced an empty result
        let test_schema = TestSchema::new_with_dir(permit, db_dir, tempfile::tempdir().unwrap());

        let networks: Vec<_> = test_schema
            .store
            .network_map()
            .iter(rocksdb::Direction::Forward, None)
            .filter_map(Result::ok)
            .collect();

        assert_eq!(networks.len(), 0, "Should have no networks");
    }

    #[test]
    fn migrate_network_cf_multiple_unique_networks() {
        use bincode::Options;

        use super::migration_structures::NetworkValueV0_43;
        use crate::{HostNetworkGroup, Iterable};

        let permit = acquire_db_permit();

        // Create test database
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("states.db");

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Create database and insert multiple unique network entries
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();

        let networks_cf = db.cf_handle("networks").unwrap();

        let creation_time = chrono::Utc::now();

        // Create 5 unique networks with different names and IDs
        let network_data = [
            ("NetworkA", 2, "Description A", vec![1]),
            ("NetworkB", 5, "Description B", vec![2, 3]),
            ("NetworkC", 1, "Description C", vec![]),
            ("NetworkD", 8, "Description D", vec![4, 5, 6]),
            ("NetworkE", 3, "Description E", vec![7]),
        ];

        for (name, id, desc, tags) in &network_data {
            let old_value = NetworkValueV0_43 {
                description: desc.to_string(),
                networks: HostNetworkGroup::default(),
                customer_ids: vec![1, 2],
                tag_ids: tags.clone(),
                creation_time,
            };
            let old_key = make_old_network_key(name, *id);
            let old_value_bytes = bincode::DefaultOptions::new()
                .serialize(&old_value)
                .unwrap();
            db.put_cf(networks_cf, &old_key, &old_value_bytes).unwrap();
        }

        drop(db);

        // Run the migration
        super::migrate_network_cf_inner(&db_path, &opts, &crate::tables::MAP_NAMES).unwrap();

        // Verify the migration
        let test_schema = TestSchema::new_with_dir(permit, db_dir, tempfile::tempdir().unwrap());

        let networks: Vec<_> = test_schema
            .store
            .network_map()
            .iter(rocksdb::Direction::Forward, None)
            .filter_map(Result::ok)
            .collect();

        assert_eq!(networks.len(), 5, "Should have all 5 unique networks");

        // Verify each network was migrated correctly
        for (name, id, desc, tags) in &network_data {
            let network = networks.iter().find(|n| n.name == *name).unwrap();
            assert_eq!(network.id, *id, "ID should be preserved for {name}");
            assert_eq!(
                network.description, *desc,
                "Description should be preserved for {name}"
            );
            assert_eq!(
                network.tag_ids(),
                tags.as_slice(),
                "Tag IDs should be preserved for {name}"
            );
        }
    }

    #[test]
    fn migrate_network_cf_rebuilds_index_with_gaps() {
        use bincode::Options;

        use super::migration_structures::NetworkValueV0_43;
        use crate::{HostNetworkGroup, Network};

        let permit = acquire_db_permit();

        // Create test database
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("states.db");

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Create database and insert old-format network entries with gaps in ids
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();

        let networks_cf = db.cf_handle("networks").unwrap();

        let creation_time = chrono::Utc::now();
        let entries = [("NetA", 1), ("NetB", 3)];
        for (name, id) in entries {
            let old_value = NetworkValueV0_43 {
                description: format!("Description {id}"),
                networks: HostNetworkGroup::default(),
                customer_ids: vec![1],
                tag_ids: vec![],
                creation_time,
            };
            let old_key = make_old_network_key(name, id);
            let old_value_bytes = bincode::DefaultOptions::new()
                .serialize(&old_value)
                .unwrap();
            db.put_cf(networks_cf, &old_key, &old_value_bytes).unwrap();
        }

        drop(db);

        // Run the migration
        super::migrate_network_cf_inner(&db_path, &opts, &crate::tables::MAP_NAMES).unwrap();

        // Verify the index reuses gaps
        let test_schema = TestSchema::new_with_dir(permit, db_dir, tempfile::tempdir().unwrap());
        let table = test_schema.store.network_map();

        let id0 = table
            .insert(Network::new(
                "GapNet".to_string(),
                "Gap description".to_string(),
                HostNetworkGroup::default(),
                vec![],
            ))
            .unwrap();
        assert_eq!(id0, 0, "First available id should fill the gap at 0");

        let id2 = table
            .insert(Network::new(
                "GapNet2".to_string(),
                "Gap description 2".to_string(),
                HostNetworkGroup::default(),
                vec![],
            ))
            .unwrap();
        assert_eq!(id2, 2, "Second available id should fill the gap at 2");
    }

    #[test]
    fn test_migrate_http_threat_events() {
        use std::net::IpAddr;

        use super::migration_structures::{
            HttpThreatFieldsStoredV0_43, HttpThreatFieldsStoredV0_44,
        };
        use crate::event::EventKind;

        // Create test directory and database
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("states.db");

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();

        // Create old-format stored HttpThreatFields with Option<usize> cluster_id
        let old_event = HttpThreatFieldsStoredV0_43 {
            time: chrono::Utc::now(),
            sensor: "test-sensor".to_string(),
            orig_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            orig_port: 12345,
            resp_addr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            start_time: 1000,
            duration: 100,
            orig_pkts: 10,
            resp_pkts: 20,
            orig_l2_bytes: 1000,
            resp_l2_bytes: 2000,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/test".to_string(),
            referer: String::new(),
            version: "HTTP/1.1".to_string(),
            user_agent: "test-agent".to_string(),
            request_len: 100,
            response_len: 200,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: "text/html".to_string(),
            cache_control: String::new(),
            filenames: vec![],
            mime_types: vec![],
            body: vec![],
            state: String::new(),
            db_name: "test_db".to_string(),
            rule_id: 1,
            matched_to: "test_rule".to_string(),
            cluster_id: Some(42_usize), // OLD TYPE: Option<usize>
            attack_kind: "test_attack".to_string(),
            confidence: 0.9,
            category: None,
        };

        // Serialize old-format value using the same encoder as production code.
        let serialized = bincode::serialize(&old_event).unwrap();

        // Create event key: (timestamp_nanos << 64) | (event_kind << 32) | random_bits
        // EventKind::HttpThreat = 1
        let timestamp_nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let event_kind = EventKind::HttpThreat as i32;
        let random_bits: u32 = 12345;
        let key_i128: i128 = (i128::from(timestamp_nanos) << 64)
            | (i128::from(event_kind) << 32)
            | i128::from(random_bits);
        let key_bytes = key_i128.to_be_bytes();

        // Store in default column family (where events are stored)
        db.put(key_bytes, &serialized).unwrap();
        drop(db);

        // Run the migration
        super::migrate_event_fields(db_dir.path()).unwrap();

        // Verify the migration by reading back and checking new format
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();

        let value = db.get(key_bytes).unwrap().unwrap();
        let new_event: HttpThreatFieldsStoredV0_44 = bincode::deserialize(&value).unwrap();

        // Verify the cluster_id was migrated from Option<usize> to Option<u32>
        assert_eq!(new_event.cluster_id, Some(42_u32));
        assert_eq!(new_event.sensor, "test-sensor");
        assert_eq!(new_event.host, "example.com");
        assert_eq!(new_event.method, "GET");
    }

    #[test]
    fn test_migrate_event_fields_empty_db() {
        // Test that migration succeeds when there are no events to migrate
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("states.db");

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();
        drop(db);

        // Run the migration - should succeed with no events
        let result = super::migrate_event_fields(db_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_migrate_blocklist_dcerpc_events() {
        use std::net::IpAddr;

        use super::migration_structures::{
            BlocklistDceRpcFieldsStoredV0_42, BlocklistDceRpcFieldsStoredV0_44,
        };
        use crate::event::EventKind;

        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("states.db");

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();

        let old_event = BlocklistDceRpcFieldsStoredV0_42 {
            sensor: "test-sensor".to_string(),
            orig_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            orig_port: 12345,
            resp_addr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            resp_port: 135,
            proto: 6,
            start_time: 1000,
            duration: 100,
            orig_pkts: 10,
            resp_pkts: 20,
            orig_l2_bytes: 1000,
            resp_l2_bytes: 2000,
            rtt: 42,
            named_pipe: "svcctl".to_string(),
            endpoint: "epmapper".to_string(),
            operation: "bind".to_string(),
            confidence: 0.95,
            category: None,
        };

        let serialized = bincode::serialize(&old_event).unwrap();

        let timestamp_nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let event_kind = EventKind::BlocklistDceRpc as i32;
        let random_bits: u32 = 12345;
        let key_i128: i128 = (i128::from(timestamp_nanos) << 64)
            | (i128::from(event_kind) << 32)
            | i128::from(random_bits);
        let key_bytes = key_i128.to_be_bytes();

        db.put(key_bytes, &serialized).unwrap();
        drop(db);

        super::migrate_event_fields(db_dir.path()).unwrap();

        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();

        let value = db.get(key_bytes).unwrap().unwrap();
        let new_event: BlocklistDceRpcFieldsStoredV0_44 = bincode::deserialize(&value).unwrap();

        assert_eq!(new_event.sensor, "test-sensor");
        assert_eq!(new_event.orig_port, 12345);
        assert_eq!(new_event.resp_port, 135);
        assert!(new_event.context.is_empty());
        assert!(new_event.request.is_empty());
        assert!((new_event.confidence - 0.95).abs() < f32::EPSILON);
    }

    #[test]
    fn test_migrate_blocklist_dcerpc_fields_empty_strings() {
        use std::net::IpAddr;

        use super::migration_structures::{
            BlocklistDceRpcFieldsStoredV0_42, BlocklistDceRpcFieldsStoredV0_44,
        };

        let old_event = BlocklistDceRpcFieldsStoredV0_42 {
            sensor: "sensor".to_string(),
            orig_addr: "127.0.0.1".parse::<IpAddr>().unwrap(),
            orig_port: 1000,
            resp_addr: "127.0.0.2".parse::<IpAddr>().unwrap(),
            resp_port: 135,
            proto: 6,
            start_time: 0,
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            rtt: 0,
            named_pipe: String::new(),
            endpoint: String::new(),
            operation: String::new(),
            confidence: 1.0,
            category: None,
        };

        let serialized = bincode::serialize(&old_event).unwrap();

        let new_val = super::migrate_blocklist_dcerpc_fields(&serialized).unwrap();
        let new_event: BlocklistDceRpcFieldsStoredV0_44 = bincode::deserialize(&new_val).unwrap();

        assert!(new_event.context.is_empty());
        assert!(new_event.request.is_empty());
    }

    #[test]
    fn test_migrate_blocklist_dhcp_events() {
        use std::net::IpAddr;

        use super::migration_structures::{
            BlocklistDhcpFieldsStoredV0_42, BlocklistDhcpFieldsStoredV0_44,
        };
        use crate::event::EventKind;

        // Create test directory and database
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("states.db");

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();

        // Create old-format stored BlocklistDhcpFields without `options` field
        let old_event = BlocklistDhcpFieldsStoredV0_42 {
            sensor: "test-sensor".to_string(),
            orig_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            orig_port: 68,
            resp_addr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            resp_port: 67,
            proto: 17,
            start_time: 1000,
            duration: 100,
            orig_pkts: 1,
            resp_pkts: 1,
            orig_l2_bytes: 300,
            resp_l2_bytes: 300,
            msg_type: 1,
            ciaddr: "0.0.0.0".parse::<IpAddr>().unwrap(),
            yiaddr: "192.168.1.100".parse::<IpAddr>().unwrap(),
            siaddr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            giaddr: "0.0.0.0".parse::<IpAddr>().unwrap(),
            subnet_mask: "255.255.255.0".parse::<IpAddr>().unwrap(),
            router: vec!["10.0.0.1".parse::<IpAddr>().unwrap()],
            domain_name_server: vec!["8.8.8.8".parse::<IpAddr>().unwrap()],
            req_ip_addr: "192.168.1.100".parse::<IpAddr>().unwrap(),
            lease_time: 3600,
            server_id: "10.0.0.1".parse::<IpAddr>().unwrap(),
            param_req_list: vec![1, 3, 6],
            message: String::new(),
            renewal_time: 1800,
            rebinding_time: 3150,
            class_id: vec![],
            client_id_type: 1,
            client_id: vec![0xaa, 0xbb, 0xcc],
            confidence: 0.8,
            category: None,
        };

        // Serialize old-format value using the same encoder as production code.
        let serialized = bincode::serialize(&old_event).unwrap();

        // Create event key: (timestamp_nanos << 64) | (event_kind << 32) | random_bits
        let timestamp_nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let event_kind = EventKind::BlocklistDhcp as i32;
        let random_bits: u32 = 12345;
        let key_i128: i128 = (i128::from(timestamp_nanos) << 64)
            | (i128::from(event_kind) << 32)
            | i128::from(random_bits);
        let key_bytes = key_i128.to_be_bytes();

        // Store in default column family (where events are stored)
        db.put(key_bytes, &serialized).unwrap();
        drop(db);

        // Run the migration
        super::migrate_event_fields(db_dir.path()).unwrap();

        // Verify the migration by reading back and checking new format
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();

        let value = db.get(key_bytes).unwrap().unwrap();
        let new_event: BlocklistDhcpFieldsStoredV0_44 = bincode::deserialize(&value).unwrap();

        // Verify all fields were correctly migrated
        assert!(new_event.options.is_empty());
        assert_eq!(new_event.sensor, "test-sensor");
        assert_eq!(
            new_event.orig_addr,
            "192.168.1.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(new_event.orig_port, 68);
        assert_eq!(new_event.resp_addr, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(new_event.resp_port, 67);
        assert_eq!(new_event.proto, 17);
        assert_eq!(new_event.start_time, 1000);
        assert_eq!(new_event.duration, 100);
        assert_eq!(new_event.orig_pkts, 1);
        assert_eq!(new_event.resp_pkts, 1);
        assert_eq!(new_event.orig_l2_bytes, 300);
        assert_eq!(new_event.resp_l2_bytes, 300);
        assert_eq!(new_event.msg_type, 1);
        assert_eq!(new_event.ciaddr, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(new_event.yiaddr, "192.168.1.100".parse::<IpAddr>().unwrap());
        assert_eq!(new_event.siaddr, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(new_event.giaddr, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(
            new_event.subnet_mask,
            "255.255.255.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            new_event.router,
            vec!["10.0.0.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            new_event.domain_name_server,
            vec!["8.8.8.8".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            new_event.req_ip_addr,
            "192.168.1.100".parse::<IpAddr>().unwrap()
        );
        assert_eq!(new_event.lease_time, 3600);
        assert_eq!(new_event.server_id, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(new_event.param_req_list, vec![1, 3, 6]);
        assert!(new_event.message.is_empty());
        assert_eq!(new_event.renewal_time, 1800);
        assert_eq!(new_event.rebinding_time, 3150);
        assert!(new_event.class_id.is_empty());
        assert_eq!(new_event.client_id_type, 1);
        assert_eq!(new_event.client_id, vec![0xaa, 0xbb, 0xcc]);
        assert!((new_event.confidence - 0.8).abs() < f32::EPSILON);
        assert!(new_event.category.is_none());
    }

    /// Test that triage policy migration converts `Confidence.threat_category`
    /// from `EventCategory` to `Some(EventCategory)`.
    #[test]
    fn migrate_triage_policy_confidence_wraps_category() {
        use bincode::Options;

        use super::migration_structures::{ConfidenceV0_44, TriagePolicyV0_44};
        use crate::EventCategory;

        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("states.db");

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Create database and insert an old-format triage policy
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();

        let cf = db.cf_handle(crate::tables::TRIAGE_POLICY).unwrap();

        let old_policy = TriagePolicyV0_44 {
            id: 1,
            name: "test_policy".to_string(),
            triage_exclusion_id: vec![],
            packet_attr: vec![],
            confidence: vec![
                ConfidenceV0_44 {
                    threat_category: EventCategory::Reconnaissance,
                    threat_kind: "scan".to_string(),
                    confidence: 0.9,
                    weight: Some(2.0),
                },
                ConfidenceV0_44 {
                    threat_category: EventCategory::Exfiltration,
                    threat_kind: "dns_tunnel".to_string(),
                    confidence: 0.5,
                    weight: None,
                },
            ],
            response: vec![],
            creation_time: chrono::Utc::now(),
            customer_id: None,
        };

        // Build the key: customer_id (u32::MAX for None) + name
        let mut key = Vec::new();
        key.extend_from_slice(&u32::MAX.to_be_bytes());
        key.extend_from_slice(b"test_policy");

        let old_value = bincode::DefaultOptions::new()
            .serialize(&old_policy)
            .unwrap();
        db.put_cf(&cf, &key, &old_value).unwrap();
        drop(db);

        // Run the migration
        super::migrate_triage_policy_confidence(db_dir.path()).unwrap();

        // Reopen and verify
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();
        let cf = db.cf_handle(crate::tables::TRIAGE_POLICY).unwrap();

        let migrated_bytes = db.get_cf(&cf, &key).unwrap().unwrap();
        let migrated: crate::TriagePolicy = bincode::DefaultOptions::new()
            .deserialize(&migrated_bytes)
            .unwrap();

        assert_eq!(migrated.confidence.len(), 2);
        assert_eq!(
            migrated.confidence[0].threat_category,
            Some(EventCategory::Reconnaissance)
        );
        assert_eq!(migrated.confidence[0].threat_kind, "scan");
        assert_eq!(
            migrated.confidence[1].threat_category,
            Some(EventCategory::Exfiltration)
        );
        assert_eq!(migrated.confidence[1].threat_kind, "dns_tunnel");
    }
}
