//! Routines to check the database format version and migrate it if necessary.
#![allow(clippy::too_many_lines)]
pub(crate) mod migration_structures;
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
    collections::Indexed,
    event::{EventKind, resolve_stored_country_codes, swap_stored_country_code_placeholders},
    geo::{CountryLookup, Ip2LocationResolver},
    migration::migration_structures::{
        AgentValueV0_46, AgentValueV0_47, BlocklistDceRpcFieldsStoredV0_42,
        BlocklistDceRpcFieldsStoredV0_44, BlocklistDhcpFieldsStoredV0_42,
        BlocklistDhcpFieldsStoredV0_44, CustomerDataDeletionJobValueV0_58, EngineInstanceRefsV0_57,
        ExternalServiceValueV0_46, ExternalServiceValueV0_47, HttpThreatFieldsStoredV0_43,
        HttpThreatFieldsStoredV0_44, ModelV0_56, NodeV0_56, OperationAttemptValueV0_47,
        OperationAttemptValueV0_48, OperationAttemptValueV0_49, SamplingPolicyV0_56,
        TrainingDefinitionV0_56, V0_46_COUNTRY_CODE_LOOKUP_FAILED,
        migrate_event_stored_schema_to_v0_46, validate_event_stored_schema_v0_46,
    },
    tables::{
        ACCESS_TOKENS, ACCOUNTS, ALLOW_NETWORKS, BLOCK_NETWORKS, CUSTOMERS, FILTERS, NETWORK_TAGS,
        TRIAGE_EXCLUSION_REASON, TRIAGE_POLICY,
    },
};

/// The database format marker written to `VERSION`.
///
/// It names the current database format and is independent of the crate
/// package version: a release does not move it, and a format change does,
/// whatever the crate version is at the time.
pub(crate) const DATABASE_FORMAT_VERSION: &str = "0.59.0";

/// The range of format markers that use the current database format.
///
/// The versions here, and in the migration table of [`migrate_data_dir`], are
/// database format markers, independent of the crate version.
/// [`DATABASE_FORMAT_VERSION`] names the current format as a stable `X.Y.0`.
/// A format change moves it to the next minor, sets this requirement to
/// `">=X.Y.0,<X.(Y+1).0"` and appends a step to the migration table. A
/// release, or any change without a format change, leaves all three as they
/// are. No build writes a prerelease marker.
const COMPATIBLE_VERSION_REQ: &str = ">=0.59.0,<0.60.0";

/// Number of event records applied in each atomic migration write.
const EVENT_MIGRATION_BATCH_SIZE: usize = 100;

/// Last default-column-family key durably processed by the placeholder swap.
const COUNTRY_CODE_SWAP_CHECKPOINT_KEY: &[u8] =
    b"migration/0.47.0/country-code-placeholder-swap/checkpoint";

/// Durable marker preventing the placeholder swap from being applied twice.
const COUNTRY_CODE_SWAP_COMPLETED_KEY: &[u8] =
    b"migration/0.47.0/country-code-placeholder-swap/completed";

/// The name of the file recording the database format version.
const VERSION_FILE_NAME: &str = "VERSION";

/// The first key byte the 0.47 layout of the "operation attempts" column
/// family reserves for its index entries.
///
/// Every record key, an idempotency key and so a non-empty UTF-8 string, sorts
/// below it, and every index entry starts at or above it. This is the 0.47
/// layout's reserved byte, written out rather than taken from the live table:
/// [`migrate_0_47_to_0_48`] describes the layout it migrates, and a later
/// change to the live layout must not change what it walks.
const OPERATION_ATTEMPT_RESERVED_V0_47: u8 = 0xf8;

/// The first key byte the 0.48 layout of the "operation attempts" column
/// family reserves for its index entries.
///
/// Every record key, an idempotency key and so a non-empty UTF-8 string, sorts
/// below it, and every index entry starts at or above it. This is the 0.48
/// layout's reserved byte, written out rather than taken from the live table:
/// [`migrate_0_48_to_0_49`] describes the layout it migrates, and a later
/// change to the live layout must not change what it walks.
const OPERATION_ATTEMPT_RESERVED_V0_48: u8 = 0xf8;

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
/// The versions this function reads, compares and writes are database format
/// markers, independent of the crate version: `DATABASE_FORMAT_VERSION`
/// names the current format.
///
/// Migration is supported between stable format markers only. A prerelease
/// marker, such as `0.46.0-alpha.1` or `0.47.0-alpha.6`, is refused with
/// "migration from {version} is not supported": neither
/// `COMPATIBLE_VERSION_REQ` nor any requirement in the migration table carries
/// a prerelease, so under semver's matching rule none of them admits it.
///
/// Pass a shared `IP2Location` database handle when available so endpoint
/// country-code fields can be resolved during the stored event schema
/// migration. If no locator is provided, endpoint country codes remain at the
/// unresolved value [`crate::COUNTRY_CODE_UNRESOLVED`].
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
    // Every migration body below writes only inside `data_dir/states.db`,
    // except `migrate_0_53_to_0_55`, which also removes the `classifiers`
    // directory and declares itself non-rollbackable (see its doc comment).
    // For every other step, a rollback snapshot taken before an update
    // therefore has to cover that one database and nothing else, and
    // restoring it does not restore the two `VERSION` files, which this
    // function writes after the whole chain succeeds and which a rollback
    // must put back separately, through `write_version_markers`.
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
            VersionReq::parse(">=0.46.0,<0.47.0")?,
            Version::parse("0.47.0")?,
            |data_dir, _backup_dir, _locator| migrate_0_46_to_0_47(data_dir),
        ),
        (
            VersionReq::parse(">=0.47.0,<0.48.0")?,
            Version::parse("0.48.0")?,
            |data_dir, _backup_dir, _locator| migrate_0_47_to_0_48(data_dir),
        ),
        (
            VersionReq::parse(">=0.48.0,<0.49.0")?,
            Version::parse("0.49.0")?,
            |data_dir, _backup_dir, _locator| migrate_0_48_to_0_49(data_dir),
        ),
        (
            VersionReq::parse(">=0.49.0,<0.50.0")?,
            Version::parse("0.50.0")?,
            |data_dir, _backup_dir, _locator| migrate_0_49_to_0_50(data_dir),
        ),
        (
            VersionReq::parse(">=0.50.0,<0.52.0")?,
            Version::parse("0.52.0")?,
            |data_dir, _backup_dir, _locator| migrate_0_50_to_0_52(data_dir),
        ),
        (
            VersionReq::parse(">=0.52.0,<0.53.0")?,
            Version::parse("0.53.0")?,
            |data_dir, _backup_dir, _locator| migrate_0_52_to_0_53(data_dir),
        ),
        (
            VersionReq::parse(">=0.53.0,<0.55.0")?,
            Version::parse("0.55.0")?,
            |data_dir, _backup_dir, _locator| migrate_0_53_to_0_55(data_dir),
        ),
        (
            VersionReq::parse(">=0.55.0,<0.56.0")?,
            Version::parse("0.56.0")?,
            |data_dir, _backup_dir, _locator| migrate_0_55_to_0_56(data_dir),
        ),
        (
            VersionReq::parse(">=0.56.0,<0.57.0")?,
            Version::parse("0.57.0")?,
            |data_dir, _backup_dir, _locator| migrate_0_56_to_0_57(data_dir),
        ),
        (
            VersionReq::parse(">=0.57.0,<0.58.0")?,
            Version::parse("0.58.0")?,
            |data_dir, _backup_dir, _locator| migrate_0_57_to_0_58(data_dir),
        ),
        (
            VersionReq::parse(">=0.58.0,<0.59.0")?,
            Version::parse("0.59.0")?,
            |data_dir, _backup_dir, _locator| migrate_0_58_to_0_59(data_dir),
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
            create_version_file(&backup, DATABASE_FORMAT_VERSION)
                .context("failed to update VERSION")?;
            return create_version_file(&data, DATABASE_FORMAT_VERSION)
                .context("failed to update VERSION");
        }
    }

    Err(anyhow!("migration from {version} is not supported"))
}

fn migrate_0_45_to_0_46(data_dir: &Path, locator: Option<&dyn CountryLookup>) -> Result<()> {
    migrate_event_country_codes(data_dir, locator).map(|_| ())
}

/// Migrates a database in the 0.46.x format to 0.47.0.
///
/// Opening [`MAP_NAMES_FOR_V0_47_MIGRATION`] with
/// [`create_missing_column_families`](rocksdb::Options::create_missing_column_families)
/// creates the eight families a 0.46.0 store lacks — customer deletion jobs,
/// core components, operation attempts, instance allocations, the operation
/// attempt latest pointer and the three port allocation families — and
/// leaves the rest alone, so a retry after an interrupted run finds nothing to
/// do rather than failing on a family that already exists. Any family a later
/// step of an interrupted chain already created is opened as well, since
/// RocksDB refuses an open that omits one, but is not created here.
///
/// Once every other step has finished, this drops the "triage policy" and
/// "triage exclusion reason" families, with every row in them. The list still
/// names them, so a retry recreates them empty on open and drops them again.
/// The list also names the `access_tokens`, `accounts`, `allow networks`,
/// `block networks`, `customers` and `filters` families, so a retry after
/// [`migrate_0_50_to_0_52`] dropped them recreates them empty as well, and
/// that step, which every chain through this one ends with, drops them again.
///
/// Agent and external-service values are in the 0.46 layout, or already in the
/// 0.47 one where an interrupted run converted them. Each row is read as
/// whichever layout decodes it and rewritten only if it is in the 0.46 one.
///
/// Event placeholder rewrites commit a last-processed key in the `meta` column
/// family atomically with each event batch. Retries resume strictly after that
/// key, and a durable completion marker prevents a second swap if the database
/// migration completed before the two on-disk `VERSION` files were updated.
fn migrate_0_46_to_0_47(data_dir: &Path) -> Result<()> {
    let db_path = data_dir.join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(true);

    let mut column_families: Vec<String> = MAP_NAMES_FOR_V0_47_MIGRATION
        .iter()
        .map(ToString::to_string)
        .collect();
    for name in existing_map_names(&opts, &db_path)? {
        if !column_families.contains(&name) {
            column_families.push(name);
        }
    }
    let mut db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, column_families)
            .context("failed to open database for the 0.47.0 migration")?;

    migrate_record_layout(
        &db,
        crate::tables::AGENTS,
        "agent",
        None,
        &[("0.46", |bytes| {
            bincode::DefaultOptions::new()
                .deserialize::<AgentValueV0_46>(bytes)
                .map(AgentValueV0_47::from)
        })],
        &[],
    )?;
    migrate_record_layout(
        &db,
        crate::tables::EXTERNAL_SERVICES,
        "external service",
        None,
        &[("0.46", |bytes| {
            bincode::DefaultOptions::new()
                .deserialize::<ExternalServiceValueV0_46>(bytes)
                .map(ExternalServiceValueV0_47::from)
        })],
        &[],
    )?;
    migrate_country_code_placeholders(&db)?;
    migrate_drop_triage_column_families(&mut db)?;
    Ok(())
}

/// Migrates a database in the 0.47.x format to 0.48.0.
///
/// The one stored-shape change is `failure_kind`, appended to the value of
/// every operation attempt. This rewrites each attempt still in the 0.47
/// layout into the 0.48 one, with `failure_kind = Some(Other)` where its
/// `outcome` is `Failed` and `None` otherwise: 0.47 never recorded why an
/// attempt failed, and `Other` keeps a failed attempt that still owes a
/// teardown dischargeable, since the write path refuses a `Failed` row with no
/// kind. Nothing reconstructs a specific kind.
///
/// It walks the record key space of the "operation attempts" family only —
/// every key below [`OPERATION_ATTEMPT_RESERVED_V0_47`] — and never reads the
/// index entries above that byte, which share the family but are not records
/// and do not decode as one. The index entries, the "operation attempt
/// latest" family, every record key and every other family are left as they
/// are, and no column family is created or dropped, so the store is opened
/// with exactly the families it physically holds.
///
/// A rerun is safe. `VERSION` is written only after the whole chain succeeds,
/// so a run interrupted after some batches committed restarts from `0.47.0`.
/// Each value is probed as the 0.48 layout and the later 0.49 layout, so a row
/// already in either is left byte for byte, including after a partial or
/// complete 0.49 step. A store with no attempts has nothing to do.
fn migrate_0_47_to_0_48(data_dir: &Path) -> Result<()> {
    let db_path = data_dir.join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, &db_path)?;
    let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, column_families)
            .context("failed to open database for the 0.48.0 migration")?;

    migrate_record_layout(
        &db,
        crate::tables::OPERATION_ATTEMPTS,
        "operation attempt",
        Some(&[OPERATION_ATTEMPT_RESERVED_V0_47]),
        &[("0.47", |bytes| {
            bincode::DefaultOptions::new()
                .deserialize::<OperationAttemptValueV0_47>(bytes)
                .map(OperationAttemptValueV0_48::from)
        })],
        &[|bytes| {
            bincode::DefaultOptions::new()
                .deserialize::<OperationAttemptValueV0_49>(bytes)
                .map(|_| ())
        }],
    )
}

/// Migrates a database in the 0.48.x format to 0.49.0.
///
/// Appends `config_template: None` to every operation attempt record: no
/// earlier install carried a template. Only keys below
/// [`OPERATION_ATTEMPT_RESERVED_V0_48`] in the operation attempts family are
/// walked. Every other field, record key, index entry, latest pointer and
/// other family is untouched; no column family is created or dropped.
///
/// A rerun is safe: rows already decoding as 0.49 are left byte for byte.
/// `VERSION` is written only after the whole chain succeeds, so interrupted
/// batches can be retried. A store without attempts has nothing to do.
fn migrate_0_48_to_0_49(data_dir: &Path) -> Result<()> {
    let db_path = data_dir.join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, &db_path)?;
    let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, column_families)
            .context("failed to open database for the 0.49.0 migration")?;

    migrate_record_layout(
        &db,
        crate::tables::OPERATION_ATTEMPTS,
        "operation attempt",
        Some(&[OPERATION_ATTEMPT_RESERVED_V0_48]),
        &[("0.48", |bytes| {
            bincode::DefaultOptions::new()
                .deserialize::<OperationAttemptValueV0_48>(bytes)
                .map(OperationAttemptValueV0_49::from)
        })],
        &[],
    )
}

/// Migrates a database in the 0.49.x format to 0.50.0.
///
/// Creates the empty "customer networks" column family. Nothing is copied into
/// it, and no other column family is read or written: the networks of the
/// "customers" family are not the owned networks the new family records.
///
/// A rerun is safe: the family is created only if it is missing, so a chain
/// interrupted after this step finds it there and leaves it as it is.
fn migrate_0_49_to_0_50(data_dir: &Path) -> Result<()> {
    let db_path = data_dir.join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, &db_path)?;
    let mut db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, column_families)
            .context("failed to open database for the 0.50.0 migration")?;

    if db.cf_handle(crate::tables::CUSTOMER_NETWORKS).is_none() {
        info!(
            "Creating '{}' column family",
            crate::tables::CUSTOMER_NETWORKS
        );
        db.create_cf(
            crate::tables::CUSTOMER_NETWORKS,
            &rocksdb::Options::default(),
        )
        .context("failed to create customer networks column family")?;
    }
    Ok(())
}

/// Migrates a database in the 0.50.x or 0.51.x format to 0.52.0.
///
/// Deletes the "network tags" key from the "meta" family and drops the
/// `access_tokens`, `accounts`, `allow networks`, `block networks`,
/// `customers` and `filters` families, with every row in them. Nothing reads
/// any of them any more, and their rows are discarded rather than converted.
/// No other family is read or written.
///
/// A rerun is safe: the key is deleted and each family dropped only if it is
/// still there, so a run interrupted part-way, or a retried chain whose 0.47
/// step recreated the families empty, completes on the next start.
fn migrate_0_50_to_0_52(data_dir: &Path) -> Result<()> {
    let db_path = data_dir.join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, &db_path)?;
    let mut db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, column_families)
            .context("failed to open database for the 0.52.0 migration")?;

    let meta = db
        .cf_handle(crate::tables::META)
        .context("meta column family not found")?;
    if db
        .get_cf(meta, NETWORK_TAGS)
        .context("failed to read network tags")?
        .is_some()
    {
        info!("Deleting network tags");
        db.delete_cf(meta, NETWORK_TAGS)
            .context("failed to delete network tags")?;
    }

    for name in [
        ACCESS_TOKENS,
        ACCOUNTS,
        ALLOW_NETWORKS,
        BLOCK_NETWORKS,
        CUSTOMERS,
        FILTERS,
    ] {
        if db.cf_handle(name).is_none() {
            continue;
        }
        info!("Dropping '{name}' column family");
        db.drop_cf(name)
            .with_context(|| format!("failed to drop '{name}' column family"))?;
    }
    Ok(())
}

/// Migrates a database in the 0.52.x format to 0.53.0.
///
/// Creates the empty "network lists" column family. Nothing is copied into
/// it, and no other column family is read or written.
///
/// A rerun is safe: the family is created only if it is missing, so a chain
/// interrupted after this step finds it there and leaves it as it is.
fn migrate_0_52_to_0_53(data_dir: &Path) -> Result<()> {
    let db_path = data_dir.join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, &db_path)?;
    let mut db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, column_families)
            .context("failed to open database for the 0.53.0 migration")?;

    if db.cf_handle(crate::tables::NETWORK_LISTS).is_none() {
        info!("Creating '{}' column family", crate::tables::NETWORK_LISTS);
        db.create_cf(crate::tables::NETWORK_LISTS, &rocksdb::Options::default())
            .context("failed to create network lists column family")?;
    }
    Ok(())
}

/// The per-model column families the 0.55.0 migration empties.
const PER_MODEL_FAMILIES_V0_53: [&str; 9] = [
    crate::tables::MODELS,
    crate::tables::BATCH_INFO,
    crate::tables::SCORES,
    crate::tables::CLUSTER,
    crate::tables::COLUMN_STATS,
    crate::tables::CSV_COLUMN_EXTRAS,
    crate::tables::TIME_SERIES,
    crate::tables::MODEL_INDICATORS,
    crate::tables::OUTLIERS,
];

/// The previous-result column families the 0.55.0 format adds.
const PREVIOUS_RESULT_FAMILIES_V0_55: [&str; 7] = [
    crate::tables::PREVIOUS_BATCH_INFO,
    crate::tables::PREVIOUS_SCORES,
    crate::tables::PREVIOUS_CLUSTER,
    crate::tables::PREVIOUS_COLUMN_STATS,
    crate::tables::PREVIOUS_CSV_COLUMN_EXTRAS,
    crate::tables::PREVIOUS_TIME_SERIES,
    crate::tables::PREVIOUS_OUTLIERS,
];

/// The training definition and model run column families the 0.55.0 format
/// adds, which hold per-model data.
const TRAINING_FAMILIES_V0_55: [&str; 2] = [
    crate::tables::TRAINING_DEFINITIONS,
    crate::tables::MODEL_RUNS,
];

/// Migrates a database in the 0.53.x format to 0.55.0: model format 2,
/// removing every model stored before it.
///
/// Models before format 2 record no owner and no event kind, and none is
/// converted:
///
/// 1. the database is opened over the column families it physically holds;
/// 2. the per-model families, [`PER_MODEL_FAMILIES_V0_53`], are dropped and
///    created again empty, so every per-model row goes, including rows
///    orphaned by earlier removals whose model row is already gone;
/// 3. the seven previous-result families, [`PREVIOUS_RESULT_FAMILIES_V0_55`],
///    then the `training definitions` and `model runs` families,
///    [`TRAINING_FAMILIES_V0_55`], are dropped where present and created
///    again empty, and the `engine instances` family is created when
///    missing;
/// 4. the `classifiers` directory under `data_dir` is removed with every
///    classifier file in it.
///
/// No other column family is read or written, so detection events stay,
/// and `meta`, which holds the run id counter, is not touched.
///
/// Every step is safe to rerun: a family is dropped only when present and
/// created only when missing, and a missing directory is not an error, so a
/// chain interrupted anywhere in this step retries it from the start.
///
/// # Rollback
///
/// This step writes outside `states.db`, and is not rollbackable by a
/// pre-update snapshot of `states.db`: restoring one brings back the model
/// rows cleared here but not the classifier files removed here, so each
/// restored pre-format-2 model fails to load with "Classifier file not
/// found" and has to be deleted, which is the outcome RFC 0006 §3 of
/// Clumit Security Web accepts for those models.
fn migrate_0_53_to_0_55(data_dir: &Path) -> Result<()> {
    let db_path = data_dir.join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, &db_path)?;
    let mut db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, column_families)
            .context("failed to open database for the 0.55.0 migration")?;

    for name in PER_MODEL_FAMILIES_V0_53
        .into_iter()
        .chain(PREVIOUS_RESULT_FAMILIES_V0_55)
        .chain(TRAINING_FAMILIES_V0_55)
    {
        if db.cf_handle(name).is_some() {
            info!("Dropping '{name}' column family");
            db.drop_cf(name)
                .with_context(|| format!("failed to drop '{name}' column family"))?;
        }
        info!("Creating '{name}' column family");
        db.create_cf(name, &rocksdb::Options::default())
            .with_context(|| format!("failed to create '{name}' column family"))?;
    }
    let name = crate::tables::ENGINE_INSTANCES;
    if db.cf_handle(name).is_none() {
        info!("Creating '{name}' column family");
        db.create_cf(name, &rocksdb::Options::default())
            .with_context(|| format!("failed to create '{name}' column family"))?;
    }
    drop(db);

    let classifiers = data_dir.join(crate::classifier_fs::CLASSIFIERS_DIR);
    match std::fs::remove_dir_all(&classifiers) {
        Ok(()) => info!("Removed '{}'", classifiers.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).with_context(|| format!("failed to remove {}", classifiers.display()));
        }
    }
    Ok(())
}

/// Migrates a database in the 0.55.x format to 0.56.0.
///
/// Creates the empty "system log collectors" column family. Nothing is copied
/// into it, and no other column family is read or written.
///
/// A rerun is safe: the family is created only if it is missing, so a chain
/// interrupted after this step finds it there and leaves it as it is.
fn migrate_0_55_to_0_56(data_dir: &Path) -> Result<()> {
    let db_path = data_dir.join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, &db_path)?;
    let mut db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, column_families)
            .context("failed to open database for the 0.56.0 migration")?;

    let name = crate::tables::SYSTEM_LOG_COLLECTORS;
    if db.cf_handle(name).is_none() {
        info!("Creating '{name}' column family");
        db.create_cf(name, &rocksdb::Options::default())
            .context("failed to create system log collectors column family")?;
    }
    Ok(())
}

/// Migrates a database in the 0.56.x format to 0.57.0.
///
/// 1. Retires every ID on the free list of the "sampling policy" family, so
///    that no ID a policy was deleted under before the upgrade is handed out
///    again: the Data Store and the Time Series Generator keep data under
///    it. Each such ID becomes inactive, and the next insert takes the first
///    ID never used. An index without a free list, an empty table's
///    included, is left as it is.
/// 2. Rewrites every sampling-policy record in the 0.56 layout into the 0.57
///    one: `immutable` is dropped, every policy becomes `Fixed`, since a
///    policy of either kind may already have series stored under its ID,
///    with no assignee and no Data Store, and its customer is the one whose
///    node its `node` is the sensor name of, or `None` if it names no sensor.
/// 3. Rewrites every model record in the 0.56 layout into the 0.57 one,
///    whose `trained_sources` is the `sources` of the training definition of
///    the model's name for a timeseries model, and empty otherwise.
///
/// No other family is written. A rerun is safe: once retired, the free list
/// is empty; a record already in the 0.57 layout is recognized by decoding
/// and left as it is; and each family's records are rewritten in one atomic
/// batch.
fn migrate_0_56_to_0_57(data_dir: &Path) -> Result<()> {
    let db_path = data_dir.join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, &db_path)?;
    let db: rocksdb::OptimisticTransactionDB =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, column_families)
            .context("failed to open database for the 0.57.0 migration")?;

    migrate_retire_sampling_policy_ids(&db)?;
    migrate_sampling_policy_records_v0_57(&db)?;
    migrate_model_trained_sources_v0_57(&db)
}

/// Migrates a database in the 0.57.x format to 0.58.0.
///
/// Creates the "detector id marks" column family, and gives every stored
/// "engine instances" row the mark of its agent lookup key,
/// `<agent_key>.<hostname>`: the highest detector id of its applied and
/// pending references, or 0. The hostname is that of the node's applied
/// profile, or of its draft profile when it has none. A row whose node is
/// missing or has no hostname has no lookup key and gets no mark.
///
/// No other family is written. A rerun is safe: the family is created only if
/// it is missing, and a mark is never lowered, so a rerun over the same rows
/// writes the same marks.
fn migrate_0_57_to_0_58(data_dir: &Path) -> Result<()> {
    let db_path = data_dir.join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, &db_path)?;
    let mut db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, column_families)
            .context("failed to open database for the 0.58.0 migration")?;

    let name = crate::tables::DETECTOR_ID_MARKS;
    if db.cf_handle(name).is_none() {
        info!("Creating '{name}' column family");
        db.create_cf(name, &rocksdb::Options::default())
            .with_context(|| format!("failed to create '{name}' column family"))?;
    }
    migrate_detector_id_marks_v0_58(&db)
}

/// Migrates a database in the 0.58.x format to 0.59.0.
///
/// Rewrites every stored customer deletion job, whose value in the 0.58
/// layout is its service results alone, into the 0.59 layout: its service
/// results, no periodic time series IDs and no abandoned hosts.
///
/// No other family is written. A rerun is safe: a value is read as the 0.59
/// layout first and left as it is if it decodes. Bincode rejects trailing
/// bytes, so neither layout decodes as the other, and a value matching
/// neither fails the migration.
fn migrate_0_58_to_0_59(data_dir: &Path) -> Result<()> {
    let db_path = data_dir.join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, &db_path)?;
    let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, column_families)
            .context("failed to open database for the 0.59.0 migration")?;

    let cf = db
        .cf_handle(crate::tables::CUSTOMER_DELETION_JOBS)
        .context("customer deletion jobs column family not found")?;
    let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();
    let mut converted = 0usize;
    for entry in db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
        let (key, value) = entry.context("failed to read a customer deletion job")?;
        if bincode::DefaultOptions::new()
            .deserialize::<crate::tables::StoredCustomerDataDeletionJob>(&value)
            .is_ok()
        {
            continue;
        }
        let service_results: CustomerDataDeletionJobValueV0_58 = bincode::DefaultOptions::new()
            .deserialize(&value)
            .with_context(|| {
                format!(
                    "customer deletion job with key {} matches neither the 0.59 nor the 0.58 layout",
                    data_encoding::HEXLOWER.encode(&key)
                )
            })?;
        let migrated: crate::tables::StoredCustomerDataDeletionJob =
            (service_results, Vec::new(), Vec::new());
        batch.put_cf(
            cf,
            &key,
            bincode::DefaultOptions::new().serialize(&migrated)?,
        );
        converted += 1;
    }
    write_migration_batch(&db, &mut batch, "customer deletion job")?;
    info!("Layout migration of customer deletion jobs complete: converted_count={converted}");
    Ok(())
}

/// Writes the detector id marks of the engine instance rows of `db`, as
/// [`migrate_0_57_to_0_58`] describes.
fn migrate_detector_id_marks_v0_58(
    db: &rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
) -> Result<()> {
    let marks_cf = db
        .cf_handle(crate::tables::DETECTOR_ID_MARKS)
        .context("detector id marks column family not found")?;
    let rows = db
        .cf_handle(crate::tables::ENGINE_INSTANCES)
        .context("engine instances column family not found")?;
    let nodes = db
        .cf_handle(crate::tables::NODES)
        .context("nodes column family not found")?;

    let mut hostnames = std::collections::HashMap::new();
    for entry in db.iterator_cf(nodes, rocksdb::IteratorMode::Start) {
        let (key, value) = entry.context("failed to read a node record")?;
        if key.is_empty() {
            continue;
        }
        let node: NodeV0_56 = bincode::DefaultOptions::new()
            .deserialize(&value)
            .context("failed to read a node record in the 0.57 layout")?;
        if let Some(profile) = node
            .profile
            .or(node.profile_draft)
            .filter(|profile| !profile.hostname.is_empty())
        {
            hostnames.insert(node.id, profile.hostname);
        }
    }

    let mut marks: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
    for entry in db.iterator_cf(rows, rocksdb::IteratorMode::Start) {
        let (key, value) = entry.context("failed to read an engine instance record")?;
        let (node_id, agent_key) = key
            .split_at_checked(std::mem::size_of::<u32>())
            .context("engine instance key is too short")?;
        let node_id = u32::from_be_bytes(node_id.try_into()?);
        let agent_key =
            std::str::from_utf8(agent_key).context("engine instance key is not UTF-8")?;
        let row: EngineInstanceRefsV0_57 = bincode::DefaultOptions::new()
            .allow_trailing_bytes()
            .deserialize(&value)
            .context("failed to read an engine instance record in the 0.57 layout")?;
        let Some(hostname) = hostnames.get(&node_id) else {
            continue;
        };
        let mark = marks
            .entry(crate::tables::agent_lookup_key(agent_key, hostname))
            .or_default();
        *mark = (*mark).max(row.last_detector_id());
    }

    let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();
    for (lookup_key, mark) in &marks {
        let stored: i32 = db
            .get_cf(marks_cf, lookup_key.as_bytes())
            .context("failed to read a detector id mark")?
            .map(|value| bincode::DefaultOptions::new().deserialize(&value))
            .transpose()
            .context("failed to read a detector id mark")?
            .unwrap_or_default();
        batch.put_cf(
            marks_cf,
            lookup_key.as_bytes(),
            bincode::DefaultOptions::new().serialize(&stored.max(*mark))?,
        );
    }
    write_migration_batch(db, &mut batch, "detector id mark")?;
    info!("Detector id marks written: count={}", marks.len());
    Ok(())
}

/// Retires the free IDs of the "sampling policy" family in `db`.
fn migrate_retire_sampling_policy_ids(db: &rocksdb::OptimisticTransactionDB) -> Result<()> {
    let name = crate::tables::SAMPLING_POLICY;
    let retired = crate::IndexedMap::new(db, name)?
        .retire_available()
        .with_context(|| format!("failed to retire the free IDs of '{name}'"))?;
    if retired > 0 {
        info!("Retired {retired} free IDs of '{name}'");
    }
    Ok(())
}

/// Rewrites the sampling-policy records of `db` still in the 0.56 layout
/// into the 0.57 one, as step 2 of [`migrate_0_56_to_0_57`] describes.
///
/// A record is read as the 0.57 layout first. A 0.56 record never decodes as
/// one: the 0.57 `customer_id` is read from the 0.56 `immutable`, and the
/// `state` after it from the `creation_time` string's length if `immutable`
/// is false, or from its first character if it is true. No RFC 3339
/// timestamp's length or leading digit is small enough to be a variant.
fn migrate_sampling_policy_records_v0_57(db: &rocksdb::OptimisticTransactionDB) -> Result<()> {
    use crate::Indexable;

    let name = crate::tables::SAMPLING_POLICY;
    let cf = db
        .cf_handle(name)
        .with_context(|| format!("{name} column family not found"))?;
    let customers = sensor_customers_v0_56(db)?;
    let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();
    let mut converted = 0usize;
    for entry in db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
        let (key, value) = entry.context("failed to read a sampling policy record")?;
        if key.is_empty()
            || bincode::DefaultOptions::new()
                .deserialize::<crate::SamplingPolicy>(&value)
                .is_ok()
        {
            continue;
        }
        let old: SamplingPolicyV0_56 = bincode::DefaultOptions::new()
            .deserialize(&value)
            .with_context(|| {
                format!(
                    "sampling policy record with key {} matches neither the 0.57 nor the 0.56 layout",
                    data_encoding::HEXLOWER.encode(&key)
                )
            })?;
        let customer_id = old
            .node
            .as_deref()
            .and_then(crate::tables::sensor_hostname)
            .and_then(|hostname| customers.get(hostname).copied());
        batch.put_cf(cf, &key, old.into_fixed(customer_id).value());
        converted += 1;
    }
    write_migration_batch(db, &mut batch, "sampling policy")?;
    info!("Layout migration of sampling policy records complete: converted_count={converted}");
    Ok(())
}

/// Returns the customer of each hostname that the applied profile of a node
/// carrying an [`AgentKind::Sensor`](crate::AgentKind::Sensor) agent has, as
/// the 0.56 layout of `db` stores them; an empty hostname is left out.
fn sensor_customers_v0_56(
    db: &rocksdb::OptimisticTransactionDB,
) -> Result<std::collections::HashMap<String, u32>> {
    let nodes = db
        .cf_handle(crate::tables::NODES)
        .context("nodes column family not found")?;
    let agents = db
        .cf_handle(crate::tables::AGENTS)
        .context("agents column family not found")?;
    let mut customers = std::collections::HashMap::new();
    for entry in db.iterator_cf(nodes, rocksdb::IteratorMode::Start) {
        let (key, value) = entry.context("failed to read a node record")?;
        if key.is_empty() {
            continue;
        }
        let node: NodeV0_56 = bincode::DefaultOptions::new()
            .deserialize(&value)
            .context("failed to read a node record in the 0.56 layout")?;
        let Some(profile) = node.profile.filter(|profile| !profile.hostname.is_empty()) else {
            continue;
        };
        for agent_key in &node.agents {
            let mut key = node.id.to_be_bytes().to_vec();
            key.extend(agent_key.as_bytes());
            let Some(value) = db.get_cf(agents, &key).context("failed to read an agent")? else {
                continue;
            };
            let agent: AgentValueV0_47 = bincode::DefaultOptions::new()
                .deserialize(&value)
                .context("failed to read an agent record in the 0.47 layout")?;
            if agent.kind == crate::AgentKind::Sensor {
                customers.insert(profile.hostname.clone(), profile.customer_id);
                break;
            }
        }
    }
    Ok(customers)
}

/// Rewrites the model records of `db` still in the 0.56 layout into the 0.57
/// one, as step 3 of [`migrate_0_56_to_0_57`] describes.
///
/// A record is read as the 0.57 layout first. The 0.57 layout appends
/// `trained_sources` to the 0.56 one, so neither decodes the other's
/// records.
fn migrate_model_trained_sources_v0_57(db: &rocksdb::OptimisticTransactionDB) -> Result<()> {
    use crate::Indexable;

    let name = crate::tables::MODELS;
    let cf = db
        .cf_handle(name)
        .with_context(|| format!("{name} column family not found"))?;
    let definitions = db
        .cf_handle(crate::tables::TRAINING_DEFINITIONS)
        .context("training definitions column family not found")?;
    let timeseries = crate::model::ClusteringMethod::Timeseries.to_string();
    let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();
    let mut converted = 0usize;
    for entry in db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
        let (key, value) = entry.context("failed to read a model record")?;
        if key.is_empty()
            || bincode::DefaultOptions::new()
                .deserialize::<crate::tables::Model>(&value)
                .is_ok()
        {
            continue;
        }
        let old: ModelV0_56 = bincode::DefaultOptions::new()
            .deserialize(&value)
            .with_context(|| {
                format!(
                    "model record with key {} matches neither the 0.57 nor the 0.56 layout",
                    data_encoding::HEXLOWER.encode(&key)
                )
            })?;
        let trained_sources = if old.kind == timeseries {
            db.get_cf(definitions, old.name.as_bytes())
                .context("failed to read a training definition")?
                .map(|value| {
                    bincode::DefaultOptions::new()
                        .deserialize::<TrainingDefinitionV0_56>(&value)
                        .context("failed to read a training definition in the 0.56 layout")
                })
                .transpose()?
                .map(|definition| definition.sources)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        batch.put_cf(cf, &key, old.with_trained_sources(trained_sources).value());
        converted += 1;
    }
    write_migration_batch(db, &mut batch, "model")?;
    info!("Layout migration of model records complete: converted_count={converted}");
    Ok(())
}

/// Drops the "triage policy" and "triage exclusion reason" column families,
/// and every row in them, from the main database.
///
/// Triage policies and exclusion reasons are no longer stored in this
/// database. Either family may already be gone, so each is dropped only if it
/// exists.
fn migrate_drop_triage_column_families(
    db: &mut rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
) -> Result<()> {
    for name in [TRIAGE_POLICY, TRIAGE_EXCLUSION_REASON] {
        if db.cf_handle(name).is_none() {
            continue;
        }
        info!("Dropping '{name}' column family");
        db.drop_cf(name)
            .with_context(|| format!("failed to drop '{name}' column family"))?;
    }
    Ok(())
}

/// Swaps the 0.46 country-code placeholders with a durable resume checkpoint.
fn migrate_country_code_placeholders(
    db: &rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
) -> Result<()> {
    migrate_country_code_placeholders_inner(db, None).map(|_| ())
}

/// Runs the placeholder migration, optionally stopping after committed batches.
///
/// The limit exists for crash-and-resume tests. A `false` result means the
/// checkpoint was committed but the completion marker was intentionally not.
fn migrate_country_code_placeholders_inner(
    db: &rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
    batch_limit: Option<usize>,
) -> Result<bool> {
    let meta = db
        .cf_handle(crate::tables::META)
        .context("meta column family not found")?;
    if db
        .get_cf(&meta, COUNTRY_CODE_SWAP_COMPLETED_KEY)
        .context("failed to read country-code placeholder migration completion marker")?
        .is_some()
    {
        return Ok(true);
    }

    let checkpoint = db
        .get_cf(&meta, COUNTRY_CODE_SWAP_CHECKPOINT_KEY)
        .context("failed to read country-code placeholder migration checkpoint")?;
    let mode = checkpoint
        .as_deref()
        .map_or(rocksdb::IteratorMode::Start, |key| {
            rocksdb::IteratorMode::From(key, rocksdb::Direction::Forward)
        });
    let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();
    let mut scanned = 0usize;
    let mut converted = 0usize;
    let mut last_processed = None;
    let mut committed_batches = 0usize;

    for entry in db.iterator(mode) {
        let (key, value) = entry.context("failed to read event entry for placeholder migration")?;
        if checkpoint.as_deref() == Some(key.as_ref()) {
            continue;
        }

        if key.len() == 16 {
            let key_i128 = i128::from_be_bytes(key.as_ref().try_into().expect("checked length"));
            let kind_num = (key_i128 & 0xffff_ffff_0000_0000) >> 32;
            if let Some(kind) = EventKind::from_i128(kind_num) {
                let swapped = swap_stored_country_code_placeholders(kind, &value)
                    .with_context(|| format!("failed to swap placeholders in event {key_i128}"))?;
                if swapped.as_slice() != value.as_ref() {
                    batch.put(&key, swapped);
                    converted += 1;
                }
            }
        }

        last_processed = Some(key.to_vec());
        scanned += 1;
        if scanned == EVENT_MIGRATION_BATCH_SIZE {
            let key = last_processed
                .as_deref()
                .expect("a full migration batch has a last processed key");
            batch.put_cf(&meta, COUNTRY_CODE_SWAP_CHECKPOINT_KEY, key);
            write_migration_batch(db, &mut batch, "country-code placeholder")?;
            scanned = 0;
            committed_batches += 1;
            if batch_limit == Some(committed_batches) {
                return Ok(false);
            }
        }
    }

    if let Some(key) = last_processed.as_deref()
        && scanned != 0
    {
        batch.put_cf(&meta, COUNTRY_CODE_SWAP_CHECKPOINT_KEY, key);
        write_migration_batch(db, &mut batch, "country-code placeholder")?;
    }

    let mut completion = rocksdb::WriteBatchWithTransaction::<true>::default();
    completion.put_cf(&meta, COUNTRY_CODE_SWAP_COMPLETED_KEY, b"1");
    completion.delete_cf(&meta, COUNTRY_CODE_SWAP_CHECKPOINT_KEY);
    db.write(completion)
        .context("failed to complete country-code placeholder migration")?;
    info!("Country-code placeholder migration complete: converted_count={converted}");
    Ok(true)
}

/// Reads one historical layout of a table value and converts it to the current
/// one.
///
/// A non-capturing closure coerces to this, so each entry of the list a caller
/// hands [`migrate_record_layout`] is written inline: deserialize that layout,
/// then convert up the `From` chain to `Current`.
type PreviousLayout<Current> = fn(&[u8]) -> Result<Current, bincode::Error>;

/// Recognizes a later stored layout without converting or rewriting it.
type LaterLayout = fn(&[u8]) -> Result<(), bincode::Error>;

/// Rewrites every value in `cf_name` that is not already in the `Current`
/// layout or any of the `later` layouts.
///
/// With `upper_bound` set to `Some(bound)`, only values whose key sorts below
/// `bound` are read or rewritten, and nothing at or above it is touched; with
/// `None`, the whole column family is. A family that shares its key space
/// between records and entries of another shape bounds the scan below the
/// first key the other entries can take.
///
/// `Current` is probed first, so a row already in that layout is recognized as
/// it is and its stored bytes are left untouched. A row decoding under any
/// `later` probe is also left untouched and counted with `already_current`.
/// Only a row that fails all of those probes is read back through `previous`,
/// newest layout first, and rewritten as the first one that decodes. A value
/// that matches no layout aborts the migration with its raw key and every
/// decoding error, rather than being skipped or overwritten.
///
/// Every later stored layout of a record must be added to the later-layout
/// probes of each earlier step that walks the same records, so retrying a
/// chain before its `VERSION` marker was written remains safe.
///
/// Which layout a row is in is decided by decoding alone, and that is sound
/// because [`bincode`] rejects bytes left over after the last field it was
/// asked for. Each of these layouts appends fields to the one before it, so
/// its encoding is a strict prefix of the next: read as an older layout a
/// current value has bytes remaining, and read as a newer one an old value
/// runs out. Either way the probe fails rather than silently mis-reading, and
/// no layout can claim another's rows.
///
/// All the layouts are table values, so they are encoded with
/// [`bincode::DefaultOptions`] — the varint encoding `crate::tables` uses — and
/// not with the fixint helpers the event records go through.
fn migrate_record_layout<Current>(
    db: &rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
    cf_name: &str,
    record: &str,
    upper_bound: Option<&[u8]>,
    previous: &[(&str, PreviousLayout<Current>)],
    later: &[LaterLayout],
) -> Result<()>
where
    Current: serde::Serialize + serde::de::DeserializeOwned,
{
    // Anonymous, because `std::io::Write` is in scope for the module and this
    // needs only `write!` on a `String`.
    use std::fmt::Write as _;

    let cf = db
        .cf_handle(cf_name)
        .with_context(|| format!("{cf_name} column family not found"))?;

    let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();
    let mut converted = 0usize;
    let mut already_current = 0usize;

    let mut readopts = rocksdb::ReadOptions::default();
    if let Some(bound) = upper_bound {
        readopts.set_iterate_upper_bound(bound);
    }
    for entry in db.iterator_cf_opt(&cf, readopts, rocksdb::IteratorMode::Start) {
        let (key, value) = entry.with_context(|| format!("failed to read a {record} record"))?;
        let Err(current_error) = bincode::DefaultOptions::new().deserialize::<Current>(&value)
        else {
            already_current += 1;
            continue;
        };
        if later.iter().any(|probe| probe(&value).is_ok()) {
            already_current += 1;
            continue;
        }
        let mut errors = format!("current schema error: {current_error}");
        let mut decoded = None;
        for (layout, deserialize) in previous {
            match deserialize(&value) {
                Ok(old) => {
                    decoded = Some(old);
                    break;
                }
                Err(error) => {
                    // Writing to a `String` cannot fail.
                    let _ = write!(errors, "; previous schema error ({layout}): {error}");
                }
            }
        }
        let Some(old) = decoded else {
            return Err(anyhow!(
                "{record} record with key {} matches neither the current nor any previous stored schema: {errors}",
                data_encoding::HEXLOWER.encode(&key)
            ));
        };
        let migrated = bincode::DefaultOptions::new()
            .serialize(&old)
            .with_context(|| format!("failed to serialize the migrated {record} record"))?;
        batch.put_cf(&cf, &key, migrated);
        converted += 1;

        if batch.len() >= EVENT_MIGRATION_BATCH_SIZE {
            write_migration_batch(db, &mut batch, record)?;
        }
    }

    write_migration_batch(db, &mut batch, record)?;
    info!(
        "Layout migration of {record} records complete: converted_count={converted}, already_current_count={already_current}"
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
                let resolved = resolve_country_codes_for_v0_46(kind, &v0_46, locator)?;
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

/// Resolves codes using the byte meanings of the historical 0.46 output.
fn resolve_country_codes_for_v0_46(
    kind: EventKind,
    bytes: &[u8],
    locator: Option<&dyn CountryLookup>,
) -> Result<Vec<u8>> {
    struct HistoricalLookup<'a>(&'a dyn CountryLookup);

    impl CountryLookup for HistoricalLookup<'_> {
        fn lookup_country_code(&self, addr: std::net::IpAddr) -> [u8; 2] {
            match self.0.lookup_country_code(addr) {
                crate::COUNTRY_CODE_UNKNOWN => V0_46_COUNTRY_CODE_LOOKUP_FAILED,
                country => country,
            }
        }
    }

    match locator {
        Some(locator) => {
            let historical = HistoricalLookup(locator);
            resolve_stored_country_codes(kind, bytes, Some(&historical))
        }
        None => resolve_stored_country_codes(kind, bytes, None),
    }
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

/// Lists the column family names [`migrate_0_46_to_0_47`] opens: the 0.47
/// set, plus the "triage policy" and "triage exclusion reason" families a
/// 0.46 store still holds, which RocksDB requires an open to name and which
/// that migration drops after opening this list.
///
/// The names are written out rather than taken from
/// [`crate::tables::MAP_NAMES`], as every other list here is: this one is what
/// [`migrate_0_46_to_0_47`] creates, and a later rename or format bump must
/// change what a future migration creates, never what this historical one did.
const MAP_NAMES_FOR_V0_47_MIGRATION: [&str; 44] = [
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
    "instance allocations",
    "models",
    "model indicators",
    "meta",
    "networks",
    "nodes",
    "operation attempts",
    "operation attempt latest",
    "outliers",
    "port allocations",
    "port allocations by attempt",
    "port allocations by instance",
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

/// Lists column family names for database formats 0.47 through 0.49: the
/// families [`migrate_0_46_to_0_47`] leaves behind, without the "customer
/// networks" family 0.50.0 adds.
#[cfg(test)]
const MAP_NAMES_V0_47_TO_V0_49: [&str; 42] = [
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
    "instance allocations",
    "models",
    "model indicators",
    "meta",
    "networks",
    "nodes",
    "operation attempts",
    "operation attempt latest",
    "outliers",
    "port allocations",
    "port allocations by attempt",
    "port allocations by instance",
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
    "triage response",
    "trusted DNS servers",
    "trusted user agents",
];

/// Lists column family names for database formats 0.50 and 0.51: the 0.47
/// through 0.49 families with the "customer networks" family 0.50 adds,
/// before [`migrate_0_50_to_0_52`] drops six of them.
#[cfg(test)]
const MAP_NAMES_V0_50_TO_V0_51: [&str; 43] = [
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
    "customer networks",
    "data sources",
    "filters",
    "hosts",
    "instance allocations",
    "models",
    "model indicators",
    "meta",
    "networks",
    "nodes",
    "operation attempts",
    "operation attempt latest",
    "outliers",
    "port allocations",
    "port allocations by attempt",
    "port allocations by instance",
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
    "triage response",
    "trusted DNS servers",
    "trusted user agents",
];

/// Lists column family names for database format 0.52, before
/// [`migrate_0_52_to_0_53`] adds "network lists".
#[cfg(test)]
const MAP_NAMES_V0_52: [&str; 37] = [
    "agents",
    "batch_info",
    "category",
    "cluster",
    "column stats",
    "configs",
    "core components",
    "csv column extras",
    "customer deletion jobs",
    "customer networks",
    "data sources",
    "hosts",
    "instance allocations",
    "models",
    "model indicators",
    "meta",
    "networks",
    "nodes",
    "operation attempts",
    "operation attempt latest",
    "outliers",
    "port allocations",
    "port allocations by attempt",
    "port allocations by instance",
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
    "triage response",
    "trusted DNS servers",
    "trusted user agents",
];

/// Lists column family names for database format 0.53, before
/// [`migrate_0_53_to_0_55`] adds the previous-result families.
#[cfg(test)]
const MAP_NAMES_V0_53: [&str; 38] = [
    "agents",
    "batch_info",
    "category",
    "cluster",
    "column stats",
    "configs",
    "core components",
    "csv column extras",
    "customer deletion jobs",
    "customer networks",
    "data sources",
    "hosts",
    "instance allocations",
    "models",
    "model indicators",
    "meta",
    "network lists",
    "networks",
    "nodes",
    "operation attempts",
    "operation attempt latest",
    "outliers",
    "port allocations",
    "port allocations by attempt",
    "port allocations by instance",
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
    "triage response",
    "trusted DNS servers",
    "trusted user agents",
];

/// Lists column family names for database format 0.55, before
/// [`migrate_0_55_to_0_56`] adds the system log collectors family.
#[cfg(test)]
const MAP_NAMES_V0_55: [&str; 48] = [
    "agents",
    "batch_info",
    "category",
    "cluster",
    "column stats",
    "configs",
    "core components",
    "csv column extras",
    "customer deletion jobs",
    "customer networks",
    "data sources",
    "engine instances",
    "hosts",
    "instance allocations",
    "models",
    "model indicators",
    "meta",
    "model runs",
    "network lists",
    "networks",
    "nodes",
    "operation attempts",
    "operation attempt latest",
    "outliers",
    "port allocations",
    "port allocations by attempt",
    "port allocations by instance",
    "previous batch_info",
    "previous cluster",
    "previous column stats",
    "previous csv column extras",
    "previous outliers",
    "previous scores",
    "previous time series",
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
    "training definitions",
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
/// a store whose marker still names 0.45, for example, may already hold the
/// families the 0.47 migration creates, with or without the two triage
/// families it drops. Opening exactly what is there lets the retry run
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

    // The rows of the "allow networks" and "block networks" families are no
    // longer rewritten into one row per entry of the "customers" family: the
    // 0.52 step, which every chain through this one ends with, drops all
    // three families, so nothing would read what was rewritten.

    Ok(())
}

fn migrate_0_43_to_0_44(data_dir: &Path) -> Result<()> {
    // The "network tags" key of the "meta" family is no longer rewritten into
    // one entry per entry of the "customers" family: the 0.52 step, which
    // every chain through this one ends with, deletes the key and drops the
    // "customers" family, so nothing would read what was rewritten.

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

    use crate::migration::migration_structures::{TriagePolicyV0_44, TriagePolicyV0_45};

    let db_path = dir.join("states.db");
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);
    let column_families = map_names_for_existing_format(&opts, &db_path)?;

    let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, column_families)
            .context("Failed to open database for triage policy migration")?;

    // `migrate_0_46_to_0_47` drops this family, and `VERSION` is written only
    // after the whole chain succeeds, so a chain from 0.44 retried after that
    // drop finds no family here and has nothing to migrate.
    let Some(cf) = db.cf_handle(crate::tables::TRIAGE_POLICY) else {
        return Ok(());
    };

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
        let new = TriagePolicyV0_45::from(old);
        let value = bincode::DefaultOptions::new()
            .serialize(&new)
            .context("failed to serialize migrated triage policy")?;
        txn.put_cf(&cf, key, value)
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
        create_version_file(&file, DATABASE_FORMAT_VERSION)?;
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
/// already validated: `DATABASE_FORMAT_VERSION` during migration, and the
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
        COMPATIBLE_VERSION_REQ, COUNTRY_CODE_SWAP_CHECKPOINT_KEY, COUNTRY_CODE_SWAP_COMPLETED_KEY,
        DATABASE_FORMAT_VERSION, VERSION_FILE_NAME, VERSION_TMP_FILE_NAME, create_version_file,
        migrate_0_46_to_0_47, migrate_0_56_to_0_57, migrate_0_57_to_0_58, migrate_0_58_to_0_59,
        migrate_country_code_placeholders_inner, migrate_data_dir, migrate_event_country_codes,
        migrate_event_stored_schema_to_v0_46, read_version_file, retrieve_or_create_version,
        write_version_markers,
    };
    use crate::event::{
        BlocklistConnFields, BlocklistConnFieldsStored, EventKind, EventMessage,
        MultiHostPortScanFieldsStored, resolve_stored_country_codes,
    };
    use crate::geo::CountryLookup;
    use crate::migration::migration_structures::{
        AgentValueV0_46, AgentValueV0_47, BlocklistConnFieldsStoredV0_42,
        ExternalServiceValueV0_46, ExternalServiceValueV0_47, ModelV0_56,
        MultiHostPortScanFieldsStoredV0_42, NodeProfileV0_56, NodeV0_56,
        OperationAttemptValueV0_47, OperationAttemptValueV0_48, OperationAttemptValueV0_49,
        SamplingPolicyV0_56, TrainingDefinitionV0_56, V0_46_COUNTRY_CODE_UNRESOLVED,
    };
    use crate::tables::NETWORK_TAGS;
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{
        Agent, AgentConfig, AgentKind, AgentStatus, CoreComponent, ExternalService,
        ExternalServiceConfig, ExternalServiceKind, ExternalServiceStatus, Lifecycle,
        OperationAction, OperationAttempt, OperationCleanupState, OperationFailureKind,
        OperationOutcome, OperationPhase, OperationRetryPolicy, Store,
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
                .unwrap_or(crate::util::COUNTRY_CODE_UNKNOWN)
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
        assert_eq!(
            current.orig_country_code,
            crate::migration::migration_structures::V0_46_COUNTRY_CODE_UNRESOLVED
        );
        assert_eq!(current.resp_addr, old.resp_addr);
        assert_eq!(current.resp_port, old.resp_port);
        assert_eq!(
            current.resp_country_code,
            crate::migration::migration_structures::V0_46_COUNTRY_CODE_UNRESOLVED
        );
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
        assert_eq!(
            current.orig_country_code,
            crate::migration::migration_structures::V0_46_COUNTRY_CODE_UNRESOLVED
        );
        assert_eq!(current.resp_addrs, old.resp_addrs);
        assert_eq!(current.resp_port, old.resp_port);
        assert_eq!(
            current.resp_country_codes,
            vec![crate::migration::migration_structures::V0_46_COUNTRY_CODE_UNRESOLVED; resp_count]
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
            crate::migration::migration_structures::V0_46_COUNTRY_CODE_UNRESOLVED
        );
        assert_eq!(migrated.resp_addr, legacy.resp_addr);
        assert_eq!(
            migrated.resp_country_code,
            crate::migration::migration_structures::V0_46_COUNTRY_CODE_UNRESOLVED
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
            codes: HashMap::from([(legacy.orig_addr, *b"US")]),
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
        assert_eq!(
            migrated.resp_country_code,
            crate::migration::migration_structures::V0_46_COUNTRY_CODE_LOOKUP_FAILED
        );

        let current = crate::event::swap_stored_country_code_placeholders(
            EventKind::BlocklistConn,
            &migrated_value,
        )
        .unwrap();
        let current: BlocklistConnFieldsStored = bincode::deserialize(&current).unwrap();
        assert_eq!(current.orig_country_code, *b"US");
        assert_eq!(current.resp_country_code, crate::COUNTRY_CODE_UNKNOWN);
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
        let current_version = DATABASE_FORMAT_VERSION;
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

        let mut data_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
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

        // VERSION should be created with the current format marker
        let data_version = read_version_file(&data_dir.path().join("VERSION")).unwrap();
        let backup_version = read_version_file(&backup_dir.path().join("VERSION")).unwrap();
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
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
        write_version(backup_dir.path(), DATABASE_FORMAT_VERSION);

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

    /// Test that prerelease markers are refused and their `VERSION` files left
    /// unchanged.
    ///
    /// Migration is supported between released versions only, as the
    /// `migrate_data_dir` doc comment records. The markers cover older
    /// prereleases, the 0.47 through 0.50 cycles, the 0.52 and 0.53
    /// prereleases, and prereleases of the format migrated to.
    #[test]
    fn migration_refuses_unsupported_prerelease_markers() {
        for marker in [
            "0.43.0-alpha.1",
            "0.44.0-alpha.2",
            "0.46.0-alpha.1",
            "0.47.0-alpha.1",
            "0.47.0-alpha.6",
            "0.48.0-alpha.1",
            "0.48.0-alpha.2",
            "0.49.0-alpha.1",
            "0.49.0-alpha.2",
            "0.50.0-alpha.1",
            "0.50.0-alpha.2",
            "0.52.0-alpha.1",
            "0.52.0-alpha.2",
            "0.53.0-alpha.1",
            "0.53.0-alpha.2",
            "0.55.0-alpha.1",
            "0.55.0-alpha.2",
            "0.55.0-alpha.3",
            "0.55.0-alpha.4",
            "0.56.0-alpha.1",
        ] {
            let data_dir = tempfile::tempdir().unwrap();
            let backup_dir = tempfile::tempdir().unwrap();
            write_version(data_dir.path(), marker);
            write_version(backup_dir.path(), marker);

            let result = migrate_data_dir(data_dir.path(), backup_dir.path(), None);

            let err = result.unwrap_err().to_string();
            assert!(
                err.contains(&format!("migration from {marker} is not supported")),
                "unexpected error for {marker}: {err}"
            );
            let expected = Version::parse(marker).unwrap();
            assert_eq!(
                read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
                expected
            );
            assert_eq!(
                read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
                expected
            );
        }
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

        create_version_file(&version_path, DATABASE_FORMAT_VERSION).unwrap();

        assert_eq!(
            read_version_file(&version_path).unwrap(),
            Version::parse(DATABASE_FORMAT_VERSION).unwrap()
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
        assert_eq!(version, Version::parse(DATABASE_FORMAT_VERSION).unwrap());
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

        write_version(data_dir.path(), DATABASE_FORMAT_VERSION);
        write_version(backup_dir.path(), "0.47.0\n");

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
        let current_base = Version::parse(DATABASE_FORMAT_VERSION).unwrap();

        let start_version = Version::parse(START_VERSION).unwrap();
        assert!(
            current_base.major == start_version.major,
            "`START_VERSION` must be updated for major version bump (current {current_base}, start {start_version})"
        );
        assert!(
            current_base.minor >= start_version.minor,
            "`START_VERSION` {start_version} is ahead of current {current_base}; please correct it"
        );

        let compatible = VersionReq::parse(COMPATIBLE_VERSION_REQ).unwrap();
        for minor in start_version.minor..=current_base.minor {
            let version = Version::new(start_version.major, minor, 0);

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
            // A store already in the current format keeps its own marker.
            let expected = if compatible.matches(&version) {
                version.clone()
            } else {
                current_base.clone()
            };
            assert_eq!(data_version, expected);
            assert_eq!(backup_version, expected);
        }
    }

    /// The column families a `0.46.0` store lacks and the migration must create.
    const FAMILIES_ABSENT_AT_V0_46: [&str; 8] = [
        crate::tables::CUSTOMER_DELETION_JOBS,
        crate::tables::CORE_COMPONENTS,
        crate::tables::OPERATION_ATTEMPTS,
        crate::tables::INSTANCE_ALLOCATIONS,
        crate::tables::OPERATION_ATTEMPT_LATEST,
        crate::tables::PORT_ALLOCATIONS,
        crate::tables::PORT_ALLOCATIONS_BY_ATTEMPT,
        crate::tables::PORT_ALLOCATIONS_BY_INSTANCE,
    ];

    /// The column families the 0.47 format removes from `MAP_NAMES` and the
    /// migration drops from every migrated store.
    const FAMILIES_REMOVED_BY_V0_47: [&str; 2] = [
        crate::tables::TRIAGE_EXCLUSION_REASON,
        crate::tables::TRIAGE_POLICY,
    ];

    /// The column families the 0.50.0 format adds to the 0.49 set.
    const FAMILIES_ADDED_BY_V0_50: [&str; 1] = [crate::tables::CUSTOMER_NETWORKS];

    /// The column families the 0.52.0 format removes from the 0.50
    /// set and the migration drops from every migrated store.
    const FAMILIES_REMOVED_BY_V0_52: [&str; 6] = [
        crate::tables::ACCESS_TOKENS,
        crate::tables::ACCOUNTS,
        crate::tables::ALLOW_NETWORKS,
        crate::tables::BLOCK_NETWORKS,
        crate::tables::CUSTOMERS,
        crate::tables::FILTERS,
    ];

    /// The column families the 0.53.0 format adds to the 0.52 set.
    const FAMILIES_ADDED_BY_V0_53: [&str; 1] = [crate::tables::NETWORK_LISTS];

    /// The column families the 0.55.0 format adds to the 0.53 set,
    /// in the order the 0.53 step creates them.
    const FAMILIES_ADDED_BY_V0_55: [&str; 10] = [
        crate::tables::PREVIOUS_BATCH_INFO,
        crate::tables::PREVIOUS_SCORES,
        crate::tables::PREVIOUS_CLUSTER,
        crate::tables::PREVIOUS_COLUMN_STATS,
        crate::tables::PREVIOUS_CSV_COLUMN_EXTRAS,
        crate::tables::PREVIOUS_TIME_SERIES,
        crate::tables::PREVIOUS_OUTLIERS,
        crate::tables::TRAINING_DEFINITIONS,
        crate::tables::MODEL_RUNS,
        crate::tables::ENGINE_INSTANCES,
    ];

    /// The column families the 0.56.0 format adds to the 0.55 set.
    const FAMILIES_ADDED_BY_V0_56: [&str; 1] = [crate::tables::SYSTEM_LOG_COLLECTORS];

    /// The column families the 0.58.0 format adds to the 0.57 set.
    const FAMILIES_ADDED_BY_V0_58: [&str; 1] = [crate::tables::DETECTOR_ID_MARKS];

    /// Migrates a database in the 0.43-through-0.46 layout, recorded as
    /// `version`, and asserts that it reaches the current format with its agent
    /// and external-service values converted.
    fn assert_migration_creates_new_column_families(version: &str) {
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();

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
        for name in FAMILIES_ABSENT_AT_V0_46
            .into_iter()
            .chain(FAMILIES_ADDED_BY_V0_50)
            .chain(FAMILIES_ADDED_BY_V0_53)
            .chain(FAMILIES_ADDED_BY_V0_55)
            .chain(FAMILIES_ADDED_BY_V0_56)
            .chain(FAMILIES_ADDED_BY_V0_58)
        {
            assert!(db.cf_handle(name).is_some(), "{name} must exist");
        }
        assert_eq!(
            FAMILIES_ABSENT_AT_V0_46.len()
                + FAMILIES_ADDED_BY_V0_50.len()
                + FAMILIES_ADDED_BY_V0_53.len()
                + FAMILIES_ADDED_BY_V0_55.len()
                + FAMILIES_ADDED_BY_V0_56.len()
                + FAMILIES_ADDED_BY_V0_58.len()
                - FAMILIES_REMOVED_BY_V0_47.len()
                - FAMILIES_REMOVED_BY_V0_52.len(),
            crate::tables::MAP_NAMES.len() - super::MAP_NAMES_V0_43_TO_V0_46.len()
        );
        assert_eq!(
            super::MAP_NAMES_V0_47_TO_V0_49.len()
                + FAMILIES_ADDED_BY_V0_50.len()
                + FAMILIES_ADDED_BY_V0_53.len()
                + FAMILIES_ADDED_BY_V0_55.len()
                + FAMILIES_ADDED_BY_V0_56.len()
                + FAMILIES_ADDED_BY_V0_58.len()
                - FAMILIES_REMOVED_BY_V0_52.len(),
            crate::tables::MAP_NAMES.len()
        );
        assert_eq!(
            super::MAP_NAMES_V0_53.len()
                + FAMILIES_ADDED_BY_V0_55.len()
                + FAMILIES_ADDED_BY_V0_56.len()
                + FAMILIES_ADDED_BY_V0_58.len(),
            crate::tables::MAP_NAMES.len()
        );
        assert_eq!(
            super::MAP_NAMES_V0_55.len()
                + FAMILIES_ADDED_BY_V0_56.len()
                + FAMILIES_ADDED_BY_V0_58.len(),
            crate::tables::MAP_NAMES.len()
        );
        drop(db);

        assert!(
            rocksdb::OptimisticTransactionDB::<rocksdb::SingleThreaded>::open_cf(
                &open_opts,
                &db_path,
                super::MAP_NAMES_V0_43_TO_V0_46,
            )
            .is_err(),
            "the 0.43-through-0.46 column-family list must not open the migrated format"
        );
        assert_triage_families_absent(&db_path);

        for (key, _) in &agents {
            let migrated = raw_value(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::AGENTS,
                key,
            )
            .unwrap();
            let value: AgentValueV0_47 = bincode::DefaultOptions::new()
                .deserialize(&migrated)
                .unwrap();
            assert_eq!(value.lifecycle, 0);
            assert_eq!(value.bound_addrs, Vec::<(String, String)>::new());
            assert_eq!(value.instance, None);
        }
        for (key, _) in &external_services {
            let migrated = raw_value(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::EXTERNAL_SERVICES,
                key,
            )
            .unwrap();
            let value: ExternalServiceValueV0_47 = bincode::DefaultOptions::new()
                .deserialize(&migrated)
                .unwrap();
            assert_eq!(value.lifecycle, 0);
            assert_eq!(value.bound_addrs, Vec::<(String, String)>::new());
            assert_eq!(value.instance, None);
        }

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
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();

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
        write_version(data_dir.path(), DATABASE_FORMAT_VERSION);
        write_version(backup_dir.path(), DATABASE_FORMAT_VERSION);

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
            let value: AgentValueV0_47 = bincode::DefaultOptions::new()
                .deserialize(&migrated)
                .unwrap();
            assert_eq!(value.lifecycle, 0);
            assert_eq!(value.bound_addrs, Vec::<(String, String)>::new());
            assert_eq!(value.instance, None);
        }
        for (key, _) in &external_services {
            let migrated = raw_value(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::EXTERNAL_SERVICES,
                key,
            )
            .unwrap();
            let value: ExternalServiceValueV0_47 = bincode::DefaultOptions::new()
                .deserialize(&migrated)
                .unwrap();
            assert_eq!(value.lifecycle, 0);
            assert_eq!(value.bound_addrs, Vec::<(String, String)>::new());
            assert_eq!(value.instance, None);
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
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
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
    // 0.46 → 0.47: agent and external-service values and column families
    // ---------------------------------------------------------------------

    /// The stored key of an agent or external-service record.
    fn record_key(node_id: u32, key: &str) -> Vec<u8> {
        let mut buf = node_id.to_be_bytes().to_vec();
        buf.extend(key.as_bytes());
        buf
    }

    /// Serializes an agent value in the layout stored up to 0.46.
    fn old_agent_value(
        kind: AgentKind,
        status: AgentStatus,
        config: Option<&str>,
        draft: Option<&str>,
    ) -> Vec<u8> {
        let value = AgentValueV0_46 {
            kind,
            status,
            config: config.map(|c| AgentConfig::try_from(c.to_string()).unwrap()),
            draft: draft.map(|d| AgentConfig::try_from(d.to_string()).unwrap()),
        };
        bincode::DefaultOptions::new().serialize(&value).unwrap()
    }

    /// Serializes an external-service value in the layout stored up to 0.46.
    fn old_external_service_value(
        kind: ExternalServiceKind,
        status: ExternalServiceStatus,
        draft: Option<&str>,
    ) -> Vec<u8> {
        let value = ExternalServiceValueV0_46 {
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

    fn placeholder_event_entries(count: usize) -> Entries {
        let (kind, value) = crate::event::stored_event_samples_v0_46()
            .into_iter()
            .find(|(kind, _)| *kind == EventKind::DnsCovertChannel)
            .expect("DNS sample exists");
        (0..count)
            .map(|index| {
                let key = (i128::try_from(index).unwrap() << 64)
                    | (kind.to_i128().unwrap() << 32)
                    | i128::try_from(index).unwrap();
                (key.to_be_bytes().to_vec(), value.clone())
            })
            .collect()
    }

    fn put_default_entries(db_path: &Path, entries: &Entries) {
        let db = open_states_db(db_path, crate::tables::MAP_NAMES);
        let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();
        for (key, value) in entries {
            batch.put(key, value);
        }
        db.write(batch).unwrap();
    }

    fn default_entries(db_path: &Path) -> Entries {
        let families = super::existing_map_names(&rocksdb::Options::default(), db_path).unwrap();
        let db = open_states_db(db_path, families.iter().map(String::as_str));
        db.iterator(rocksdb::IteratorMode::Start)
            .map(|entry| {
                let (key, value) = entry.unwrap();
                (key.to_vec(), value.to_vec())
            })
            .collect()
    }

    /// A column family's worth of raw entries.
    type Entries = Vec<(Vec<u8>, Vec<u8>)>;

    /// The agents and external services a 0.46 fixture holds, in the layout
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
    fn country_code_placeholder_migration_resumes_without_double_swapping() {
        let _permit = acquire_db_permit();
        let uninterrupted_dir = tempfile::tempdir().unwrap();
        let resumed_dir = tempfile::tempdir().unwrap();
        let uninterrupted_path = uninterrupted_dir.path().join("states.db");
        let resumed_path = resumed_dir.path().join("states.db");
        let entries = placeholder_event_entries(205);

        for path in [&uninterrupted_path, &resumed_path] {
            create_states_db(path, crate::tables::MAP_NAMES);
            put_default_entries(path, &entries);
        }

        migrate_0_46_to_0_47(uninterrupted_dir.path()).unwrap();

        {
            let db = open_states_db(&resumed_path, crate::tables::MAP_NAMES);
            assert!(!migrate_country_code_placeholders_inner(&db, Some(1)).unwrap());
            let meta = db.cf_handle(crate::tables::META).unwrap();
            assert!(
                db.get_cf(&meta, COUNTRY_CODE_SWAP_CHECKPOINT_KEY)
                    .unwrap()
                    .is_some()
            );
            assert!(
                db.get_cf(&meta, COUNTRY_CODE_SWAP_COMPLETED_KEY)
                    .unwrap()
                    .is_none()
            );

            let values: Vec<_> = db
                .iterator(rocksdb::IteratorMode::Start)
                .map(|entry| entry.unwrap().1)
                .collect();
            let first: crate::event::DnsEventFieldsStoredV0_46 =
                bincode::deserialize(values.first().unwrap()).unwrap();
            let after_checkpoint: crate::event::DnsEventFieldsStoredV0_46 =
                bincode::deserialize(values.get(100).unwrap()).unwrap();
            assert_eq!(first.orig_country_code, crate::COUNTRY_CODE_UNRESOLVED);
            assert_eq!(
                after_checkpoint.orig_country_code,
                V0_46_COUNTRY_CODE_UNRESOLVED
            );
        }

        migrate_0_46_to_0_47(resumed_dir.path()).unwrap();
        let expected = default_entries(&uninterrupted_path);
        assert_eq!(default_entries(&resumed_path), expected);

        // This models a process restart after DB completion but before either
        // VERSION file was updated. The durable marker makes the rerun a no-op.
        migrate_0_46_to_0_47(resumed_dir.path()).unwrap();
        assert_eq!(default_entries(&resumed_path), expected);

        let families =
            super::existing_map_names(&rocksdb::Options::default(), &resumed_path).unwrap();
        let db = open_states_db(&resumed_path, families.iter().map(String::as_str));
        let meta = db.cf_handle(crate::tables::META).unwrap();
        assert!(
            db.get_cf(&meta, COUNTRY_CODE_SWAP_COMPLETED_KEY)
                .unwrap()
                .is_some()
        );
        assert!(
            db.get_cf(&meta, COUNTRY_CODE_SWAP_CHECKPOINT_KEY)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn migration_from_v0_46_swaps_placeholders() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_states_db(&db_path, super::MAP_NAMES_V0_43_TO_V0_46);
        {
            let db = open_states_db(&db_path, super::MAP_NAMES_V0_43_TO_V0_46);
            let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();
            for (key, value) in placeholder_event_entries(1) {
                batch.put(key, value);
            }
            db.write(batch).unwrap();
        }
        write_version(data_dir.path(), "0.46.0");
        write_version(backup_dir.path(), "0.46.0");

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        let entries = default_entries(&db_path);
        let stored: crate::event::DnsEventFieldsStoredV0_46 =
            bincode::deserialize(&entries.first().unwrap().1).unwrap();
        assert_eq!(stored.orig_country_code, crate::COUNTRY_CODE_UNRESOLVED);
        assert_eq!(stored.resp_country_code, crate::COUNTRY_CODE_UNRESOLVED);
        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            Version::parse(DATABASE_FORMAT_VERSION).unwrap()
        );
    }

    #[test]
    fn migration_from_v0_45_keeps_historical_intermediate_then_swaps() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_states_db(&db_path, crate::tables::MAP_NAMES);

        let legacy = legacy_blocklist_conn();
        let key = ((EventKind::BlocklistConn.to_i128().unwrap() << 32) | 1)
            .to_be_bytes()
            .to_vec();
        let entries = vec![(key, bincode::serialize(&legacy).unwrap())];
        put_default_entries(&db_path, &entries);
        write_version(data_dir.path(), "0.45.0");
        write_version(backup_dir.path(), "0.45.0");

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        let entries = default_entries(&db_path);
        let stored: BlocklistConnFieldsStored =
            bincode::deserialize(&entries.first().unwrap().1).unwrap();
        assert_eq!(stored.orig_country_code, crate::COUNTRY_CODE_UNRESOLVED);
        assert_eq!(stored.resp_country_code, crate::COUNTRY_CODE_UNRESOLVED);
    }

    #[test]
    fn migration_from_v0_46_fills_install_state_defaults() {
        let permit = acquire_db_permit();
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
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

        write_version(data_dir.path(), "0.46.0");
        write_version(backup_dir.path(), "0.46.0");
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join("VERSION")).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join("VERSION")).unwrap(),
            current_version
        );

        // The migration created every family a 0.46.0 store lacked, and each
        // starts empty.
        {
            let db = open_states_db(&db_path, crate::tables::MAP_NAMES);
            for name in FAMILIES_ABSENT_AT_V0_46 {
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
        assert_eq!(sensor.bound_addrs, Vec::<(String, String)>::new());
        assert_eq!(sensor.instance, None);

        let unsupervised = agent_map.get(2, "unsupervised@host2").unwrap().unwrap();
        assert_eq!(unsupervised.kind, AgentKind::Unsupervised);
        assert_eq!(unsupervised.status, AgentStatus::Disabled);
        assert_eq!(unsupervised.config, None);
        assert_eq!(unsupervised.draft, None);
        assert_eq!(unsupervised.lifecycle, Lifecycle::NotInstalled);
        assert_eq!(unsupervised.instance, None);

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
        assert_eq!(datastore.bound_addrs, Vec::<(String, String)>::new());
        assert_eq!(datastore.instance, None);

        let ti = external_service_map.get(4, "ti@host4").unwrap().unwrap();
        assert_eq!(ti.kind, ExternalServiceKind::TiContainer);
        assert_eq!(ti.status, ExternalServiceStatus::Disabled);
        assert_eq!(ti.draft, None);
        assert_eq!(ti.instance, None);

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

    /// A chain started from `0.45.0` that stopped right after the `0.47`
    /// migration opened the store holds every family that migration creates
    /// beside the 0.46 ones, while its marker and its records are still those
    /// of `0.45.0`. The retry must open exactly that set and complete.
    #[test]
    fn migration_retries_with_every_new_family() {
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        let families: Vec<&str> = super::MAP_NAMES_V0_43_TO_V0_46
            .iter()
            .copied()
            .chain(FAMILIES_ABSENT_AT_V0_46)
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
        let value: AgentValueV0_47 = bincode::DefaultOptions::new()
            .deserialize(&migrated)
            .unwrap();
        assert_eq!(value.lifecycle, 0);
        assert_eq!(value.instance, None);
    }

    /// Creates a `0.46.0` store holding one row in each of the two triage
    /// families 0.47 removes, and marks both directories with that version.
    fn create_v0_46_store_with_triage_rows(data_dir: &Path, backup_dir: &Path) {
        let db_path = data_dir.join("states.db");
        create_states_db(&db_path, super::MAP_NAMES_V0_43_TO_V0_46);
        for name in FAMILIES_REMOVED_BY_V0_47 {
            put_entries(
                &db_path,
                super::MAP_NAMES_V0_43_TO_V0_46,
                name,
                &[(b"row".to_vec(), b"value".to_vec())],
            );
        }
        write_version(data_dir, "0.46.0");
        write_version(backup_dir, "0.46.0");
    }

    /// Asserts that neither triage family exists in the store at `db_path`.
    fn assert_triage_families_absent(db_path: &Path) {
        let present = super::existing_map_names(&rocksdb::Options::default(), db_path).unwrap();
        for name in FAMILIES_REMOVED_BY_V0_47 {
            assert!(
                !present.iter().any(|existing| existing == name),
                "{name} must be dropped"
            );
        }
    }

    /// A `0.46.0` store holding triage rows migrates to the current format with
    /// both triage families, and every row in them, gone, and opens through
    /// `Store::new` afterwards.
    #[test]
    fn migration_from_v0_46_drops_triage_families() {
        let _permit = acquire_db_permit();
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_v0_46_store_with_triage_rows(data_dir.path(), backup_dir.path());

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_triage_families_absent(&db_path);

        let mut present =
            super::existing_map_names(&rocksdb::Options::default(), &db_path).unwrap();
        present.sort_unstable();
        let mut expected: Vec<String> = crate::tables::MAP_NAMES
            .into_iter()
            .map(str::to_string)
            .collect();
        expected.sort_unstable();
        assert_eq!(present, expected);

        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        drop(store);
        assert_triage_families_absent(&db_path);
    }

    /// `VERSION` is written only after the whole chain succeeds, so a chain
    /// interrupted after the triage families were dropped retries from its
    /// original marker. A retry from `0.44.0` reaches the triage policy
    /// conversion with no "triage policy" family and must still succeed.
    #[test]
    fn migration_from_v0_44_retried_after_triage_families_were_dropped() {
        let _permit = acquire_db_permit();
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_v0_46_store_with_triage_rows(data_dir.path(), backup_dir.path());

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();
        assert_triage_families_absent(&db_path);

        write_version(data_dir.path(), "0.44.0");
        write_version(backup_dir.path(), "0.44.0");
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_triage_families_absent(&db_path);
    }

    /// A crash between "column families created" and "version written" leaves
    /// the directory at `0.46.0` with the new families already there; the
    /// resumed run must create nothing and leave the converted records alone.
    #[test]
    fn migration_resumes_after_crash_before_the_version_was_written() {
        let permit = acquire_db_permit();
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();

        let clean_dir = tempfile::tempdir().unwrap();
        let resumed_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let (agents, external_services) = old_install_state_fixture();

        for dir in [clean_dir.path(), resumed_dir.path()] {
            let db_path = dir.join("states.db");
            create_states_db(&db_path, super::MAP_NAMES_V0_43_TO_V0_46);
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
            write_version(dir, "0.46.0");
        }

        // The interrupted run: the migration body completed, so the families
        // are there and the records are converted, but `VERSION` still reads
        // 0.46.0.
        migrate_0_46_to_0_47(resumed_dir.path()).unwrap();
        assert_eq!(
            read_version_file(&resumed_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            Version::parse("0.46.0").unwrap()
        );
        let after_crash = open_states_db(
            &resumed_dir.path().join("states.db"),
            super::MAP_NAMES_V0_47_TO_V0_49,
        );
        for name in FAMILIES_ABSENT_AT_V0_46 {
            assert!(after_crash.cf_handle(name).is_some(), "{name} must exist");
        }
        drop(after_crash);

        for dir in [clean_dir.path(), resumed_dir.path()] {
            write_version(backup_dir.path(), "0.46.0");
            migrate_data_dir(dir, backup_dir.path(), None).unwrap();
            assert_eq!(
                read_version_file(&dir.join(VERSION_FILE_NAME)).unwrap(),
                current_version
            );
        }

        // The resumed run created nothing further and rewrote nothing: it ends
        // with exactly the families and the bytes the clean run produced.
        let clean_path = clean_dir.path().join("states.db");
        let resumed_path = resumed_dir.path().join("states.db");
        let opts = rocksdb::Options::default();
        let mut clean_families = super::existing_map_names(&opts, &clean_path).unwrap();
        let mut resumed_families = super::existing_map_names(&opts, &resumed_path).unwrap();
        clean_families.sort_unstable();
        resumed_families.sort_unstable();
        assert_eq!(clean_families, resumed_families);
        assert_eq!(clean_families.len(), crate::tables::MAP_NAMES.len());

        for (cf_name, entries) in [
            (crate::tables::AGENTS, &agents),
            (crate::tables::EXTERNAL_SERVICES, &external_services),
        ] {
            for (key, _) in entries {
                let converted =
                    raw_value(&clean_path, crate::tables::MAP_NAMES, cf_name, key).unwrap();
                assert_eq!(
                    raw_value(&resumed_path, crate::tables::MAP_NAMES, cf_name, key),
                    Some(converted)
                );
            }
        }

        drop(permit);
    }

    /// Builds a family of `total` rows, keyed in order, as a conversion that
    /// committed its first `converted` rows and stopped leaves it: those rows
    /// in the 0.47 layout and the rest still in the 0.46 one. Returns the rows
    /// as stored and every row as the finished migration must leave it.
    fn partly_converted_rows(
        total: usize,
        converted: usize,
        old_value: fn(usize) -> Vec<u8>,
        convert: fn(&[u8]) -> Vec<u8>,
    ) -> (Entries, Entries) {
        let mut stored = Vec::new();
        let mut expected = Vec::new();
        for index in 0..total {
            let key = record_key(1, &format!("row-{index:03}"));
            let old = old_value(index);
            let new = convert(&old);
            stored.push((
                key.clone(),
                if index < converted { new.clone() } else { old },
            ));
            expected.push((key, new));
        }
        (stored, expected)
    }

    fn partly_converted_agents(total: usize, converted: usize) -> (Entries, Entries) {
        partly_converted_rows(
            total,
            converted,
            |index| {
                old_agent_value(
                    AgentKind::Sensor,
                    AgentStatus::Enabled,
                    Some(&format!("a = {index}")),
                    None,
                )
            },
            |bytes| {
                bincode::DefaultOptions::new()
                    .serialize(&AgentValueV0_47::from(
                        bincode::DefaultOptions::new()
                            .deserialize::<AgentValueV0_46>(bytes)
                            .unwrap(),
                    ))
                    .unwrap()
            },
        )
    }

    fn partly_converted_external_services(total: usize, converted: usize) -> (Entries, Entries) {
        partly_converted_rows(
            total,
            converted,
            |index| {
                old_external_service_value(
                    ExternalServiceKind::DataStore,
                    ExternalServiceStatus::Enabled,
                    Some(&format!("c = {index}")),
                )
            },
            |bytes| {
                bincode::DefaultOptions::new()
                    .serialize(&ExternalServiceValueV0_47::from(
                        bincode::DefaultOptions::new()
                            .deserialize::<ExternalServiceValueV0_46>(bytes)
                            .unwrap(),
                    ))
                    .unwrap()
            },
        )
    }

    /// Resumes the 0.47 migration over a store an interrupted run left with
    /// `agents` and `external_services` as stored, and asserts that both end
    /// up as expected.
    ///
    /// The store is the one the interrupted run opened: the open created
    /// every family the migration adds, and the triage families are still
    /// there. Its marker still names `0.46.0`, because `VERSION` is written
    /// only once the whole migration has succeeded.
    fn assert_migration_resumes_over(
        (agents, expected_agents): (Entries, Entries),
        (external_services, expected_external_services): (Entries, Entries),
    ) {
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        create_states_db(&db_path, super::MAP_NAMES_FOR_V0_47_MIGRATION);
        put_entries(
            &db_path,
            super::MAP_NAMES_FOR_V0_47_MIGRATION,
            crate::tables::AGENTS,
            &agents,
        );
        put_entries(
            &db_path,
            super::MAP_NAMES_FOR_V0_47_MIGRATION,
            crate::tables::EXTERNAL_SERVICES,
            &external_services,
        );

        write_version(data_dir.path(), "0.46.0");
        write_version(backup_dir.path(), "0.46.0");
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        let db = open_states_db(&db_path, crate::tables::MAP_NAMES);
        for (cf_name, expected) in [
            (crate::tables::AGENTS, &expected_agents),
            (
                crate::tables::EXTERNAL_SERVICES,
                &expected_external_services,
            ),
        ] {
            let cf = db.cf_handle(cf_name).unwrap();
            let actual: Entries = db
                .iterator_cf(&cf, rocksdb::IteratorMode::Start)
                .map(|entry| {
                    let (key, value) = entry.unwrap();
                    (key.to_vec(), value.to_vec())
                })
                .collect();
            assert_eq!(&actual, expected, "{cf_name}");
        }
    }

    /// The migration converts agents before external services and commits
    /// every `EVENT_MIGRATION_BATCH_SIZE` converted rows, so a run
    /// interrupted part-way through the agents leaves the first batches of
    /// agents converted, the rest of them and every external service still in
    /// the 0.46 layout. The retry converts the rest and leaves the converted
    /// rows as they were.
    #[test]
    fn migration_resumes_part_way_through_agents() {
        assert_migration_resumes_over(
            partly_converted_agents(
                super::EVENT_MIGRATION_BATCH_SIZE + super::EVENT_MIGRATION_BATCH_SIZE / 2,
                super::EVENT_MIGRATION_BATCH_SIZE,
            ),
            partly_converted_external_services(3, 0),
        );
    }

    /// A run interrupted part-way through the external services has converted
    /// every agent and the first batches of external services. The retry
    /// converts the rest and leaves the converted rows as they were.
    #[test]
    fn migration_resumes_part_way_through_external_services() {
        assert_migration_resumes_over(
            partly_converted_agents(3, 3),
            partly_converted_external_services(
                super::EVENT_MIGRATION_BATCH_SIZE + super::EVENT_MIGRATION_BATCH_SIZE / 2,
                super::EVENT_MIGRATION_BATCH_SIZE,
            ),
        );
    }

    /// A row written before the field existed records no instance number, and
    /// starts with the install state of a host that has reported nothing.
    ///
    /// `Some(1)` would be the tempting guess for a store that has only ever
    /// run one instance of a module, and it is the wrong one: nothing
    /// allocated that number, so nothing may assert it.
    #[test]
    fn conversion_to_the_v0_47_layout_records_no_instance() {
        let agent = AgentValueV0_47::from(AgentValueV0_46 {
            kind: AgentKind::Sensor,
            status: AgentStatus::ReloadFailed,
            config: Some(AgentConfig::try_from("a = 1".to_string()).unwrap()),
            draft: Some(AgentConfig::try_from("a = 2".to_string()).unwrap()),
        });
        assert_eq!(agent.instance, None);
        assert_eq!(agent.kind, AgentKind::Sensor);
        assert_eq!(agent.status, AgentStatus::ReloadFailed);
        assert_eq!(agent.config.as_ref().map(AsRef::as_ref), Some("a = 1"));
        assert_eq!(agent.draft.as_ref().map(AsRef::as_ref), Some("a = 2"));
        assert_eq!(agent.installed_version, None);
        assert_eq!(agent.installed_commit, None);
        assert_eq!(agent.lifecycle, Lifecycle::NotInstalled.to_stored_index());
        assert_eq!(agent.bound_addrs, Vec::<(String, String)>::new());

        let external_service = ExternalServiceValueV0_47::from(ExternalServiceValueV0_46 {
            kind: ExternalServiceKind::DataStore,
            status: ExternalServiceStatus::Enabled,
            draft: Some(ExternalServiceConfig::try_from("c = 3".to_string()).unwrap()),
        });
        assert_eq!(external_service.instance, None);
        assert_eq!(external_service.kind, ExternalServiceKind::DataStore);
        assert_eq!(external_service.status, ExternalServiceStatus::Enabled);
        assert_eq!(
            external_service.draft.as_ref().map(AsRef::as_ref),
            Some("c = 3")
        );
        assert_eq!(external_service.installed_version, None);
        assert_eq!(external_service.installed_commit, None);
        assert_eq!(
            external_service.lifecycle,
            Lifecycle::NotInstalled.to_stored_index()
        );
        assert_eq!(external_service.bound_addrs, Vec::<(String, String)>::new());
    }

    /// A value matching neither pinned layout: the leading byte is a variant
    /// index neither `AgentKind` nor `ExternalServiceKind` defines.
    const FOREIGN_VALUE: &[u8] = b"\x09foreign value";

    fn assert_migration_rejects_foreign_value(cf_name: &str, record: &str) {
        let data_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        create_states_db(&db_path, super::MAP_NAMES_V0_43_TO_V0_46);
        let key = record_key(7, "foreign");
        put_entries(
            &db_path,
            super::MAP_NAMES_V0_43_TO_V0_46,
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
        // The layout that was tried is named, so the report says which shape
        // was ruled out rather than that an unnamed one was.
        assert!(
            message.contains("previous schema error (0.46)"),
            "{message}"
        );

        // The failed run stopped before dropping the triage families, so the
        // store holds what the migration opened.
        assert_eq!(
            raw_value(
                &db_path,
                super::MAP_NAMES_FOR_V0_47_MIGRATION,
                cf_name,
                &key
            ),
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
    /// Decoding alone already fails on a field appended to or dropped from
    /// either side, because [`bincode::DefaultOptions`] rejects both a short
    /// read and trailing bytes. The field-by-field comparison catches two
    /// fields of one type trading places, which decodes cleanly. Re-encoding
    /// the pinned layout and demanding the same bytes back pins the last
    /// thing: that what the migration writes through the pinned layout is,
    /// byte for byte, what the live table writes.
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
            instance: Some(7),
        };
        let stored = agent.value();
        let pinned: AgentValueV0_47 = bincode::DefaultOptions::new()
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
        assert_eq!(pinned.instance, agent.instance);
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
            instance: Some(8),
        };
        let stored = external_service.value();
        let pinned: ExternalServiceValueV0_47 = bincode::DefaultOptions::new()
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
        assert_eq!(pinned.instance, external_service.instance);
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
        std::fs::write(data_dir.path().join("untouched"), b"keep me").unwrap();
        std::fs::create_dir(data_dir.path().join("events.db")).unwrap();
        std::fs::write(data_dir.path().join("events.db").join("CURRENT"), b"events").unwrap();

        let before = entries_outside_states_db(data_dir.path());
        super::migrate_0_46_to_0_47(data_dir.path()).unwrap();
        assert_eq!(entries_outside_states_db(data_dir.path()), before);

        // The 0.47→0.48 step over a store holding operation attempts in the
        // 0.47 layout writes nowhere else either.
        let attempts = operation_attempt_rows()
            .into_iter()
            .map(|row| (row.idempotency_key.as_bytes().to_vec(), v0_47_value(&row)))
            .collect::<Vec<_>>();
        put_entries(
            &db_path,
            super::MAP_NAMES_V0_47_TO_V0_49,
            crate::tables::OPERATION_ATTEMPTS,
            &attempts,
        );
        let before = entries_outside_states_db(data_dir.path());
        super::migrate_0_47_to_0_48(data_dir.path()).unwrap();
        assert_eq!(entries_outside_states_db(data_dir.path()), before);
        let (records, _) = operation_attempt_families(&db_path);
        assert_eq!(records.len(), attempts.len());
        for (_, value) in records {
            assert!(
                bincode::DefaultOptions::new()
                    .deserialize::<OperationAttemptValueV0_48>(&value)
                    .is_ok()
            );
        }
        super::migrate_0_48_to_0_49(data_dir.path()).unwrap();
        assert_eq!(entries_outside_states_db(data_dir.path()), before);
        let (records, _) = operation_attempt_families(&db_path);
        for (_, value) in records {
            assert!(
                bincode::DefaultOptions::new()
                    .deserialize::<OperationAttemptValueV0_49>(&value)
                    .is_ok()
            );
        }
        super::migrate_0_49_to_0_50(data_dir.path()).unwrap();
        assert_eq!(entries_outside_states_db(data_dir.path()), before);
        super::migrate_0_50_to_0_52(data_dir.path()).unwrap();
        assert_eq!(entries_outside_states_db(data_dir.path()), before);
    }

    /// Every entry of the column family `cf_name`, in key order.
    fn cf_entries<'a>(
        db_path: &Path,
        families: impl IntoIterator<Item = &'a str>,
        cf_name: &str,
    ) -> Entries {
        let db = open_states_db(db_path, families);
        let cf = db.cf_handle(cf_name).unwrap();
        db.iterator_cf(&cf, rocksdb::IteratorMode::Start)
            .map(|entry| {
                let (key, value) = entry.unwrap();
                (key.to_vec(), value.to_vec())
            })
            .collect()
    }

    /// Every file under `dir`, with its contents.
    fn files_under(dir: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
        let mut entries = Vec::new();
        let mut pending = vec![dir.to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    let contents = std::fs::read(&path).unwrap();
                    entries.push((path, contents));
                }
            }
        }
        entries.sort_unstable();
        entries
    }

    /// A `0.49.0` store with customers migrates to the current format with an
    /// empty "customer networks" family, the "customers" family dropped, and
    /// both markers naming the current version; a second start finds the store
    /// current and touches nothing.
    #[test]
    fn migration_from_v0_49_creates_empty_customer_networks() {
        let _permit = acquire_db_permit();
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        create_states_db(&db_path, super::MAP_NAMES_V0_47_TO_V0_49);
        put_entries(
            &db_path,
            super::MAP_NAMES_V0_47_TO_V0_49,
            crate::tables::CUSTOMERS,
            &[(b"acme".to_vec(), b"a customer".to_vec())],
        );
        write_version(data_dir.path(), "0.49.0");
        write_version(backup_dir.path(), "0.49.0");

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        let mut present =
            super::existing_map_names(&rocksdb::Options::default(), &db_path).unwrap();
        present.sort_unstable();
        let mut expected: Vec<String> = crate::tables::MAP_NAMES
            .into_iter()
            .map(str::to_string)
            .collect();
        expected.sort_unstable();
        assert_eq!(present, expected);
        assert!(!present.iter().any(|name| name == crate::tables::CUSTOMERS));
        assert_eq!(
            cf_entries(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::CUSTOMER_NETWORKS
            ),
            Entries::new()
        );

        // A second start is a no-op: nothing under either directory changes.
        let before = (files_under(data_dir.path()), files_under(backup_dir.path()));
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();
        assert_eq!(
            (files_under(data_dir.path()), files_under(backup_dir.path())),
            before
        );

        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        assert_eq!(store.customer_networks_map().iter().count(), 0);
    }

    /// Returns a serialized tag index holding `names`, as the "meta" family
    /// stores it under a tag-set key.
    fn tag_index_bytes(names: &[&str]) -> Vec<u8> {
        let mut index = crate::collections::KeyIndex::default();
        for name in names {
            index.insert(name.as_bytes()).unwrap();
        }
        bincode::DefaultOptions::new().serialize(&index).unwrap()
    }

    /// Every entry of the default family and of each family in `MAP_NAMES`,
    /// read from a store whose families are opened as they physically exist.
    /// A family in `MAP_NAMES` the store does not have, such as one a later
    /// migration step creates, is recorded with no entries; whether it is
    /// present is asserted separately.
    fn kept_family_entries(db_path: &Path) -> Vec<(String, Entries)> {
        let families = super::existing_map_names(&rocksdb::Options::default(), db_path).unwrap();
        let db = open_states_db(db_path, families.iter().map(String::as_str));
        let mut entries = vec![(
            "default".to_string(),
            db.iterator(rocksdb::IteratorMode::Start)
                .map(|entry| {
                    let (key, value) = entry.unwrap();
                    (key.to_vec(), value.to_vec())
                })
                .collect(),
        )];
        for name in crate::tables::MAP_NAMES {
            let Some(cf) = db.cf_handle(name) else {
                entries.push((name.to_string(), Entries::new()));
                continue;
            };
            entries.push((
                name.to_string(),
                db.iterator_cf(&cf, rocksdb::IteratorMode::Start)
                    .map(|entry| {
                        let (key, value) = entry.unwrap();
                        (key.to_vec(), value.to_vec())
                    })
                    .collect(),
            ));
        }
        entries
    }

    /// Returns the non-default families physically present, sorted.
    fn present_families(db_path: &Path) -> Vec<String> {
        let mut present = super::existing_map_names(&rocksdb::Options::default(), db_path).unwrap();
        present.sort_unstable();
        present
    }

    /// Returns the names in `MAP_NAMES`, sorted.
    fn current_families() -> Vec<String> {
        let mut expected: Vec<String> = crate::tables::MAP_NAMES
            .into_iter()
            .map(str::to_string)
            .collect();
        expected.sort_unstable();
        expected
    }

    /// Creates a store over `families`, a subset of the 0.50 and 0.51 set,
    /// marked `version`, with a row in each of the families the 0.52 step
    /// drops that `families` names, network, event and workflow tags and the
    /// 0.47 country-code swap keys in "meta", a
    /// "networks" row carrying tag IDs, and a row in "customer networks" and
    /// in "configs".
    fn create_v0_51_store(data_dir: &Path, backup_dir: &Path, version: &str, families: &[&str]) {
        const NETWORK_FIXTURE: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/network_projected_private_value.bin"
        ));

        let db_path = data_dir.join("states.db");
        create_states_db(&db_path, families.iter().copied());
        for name in FAMILIES_REMOVED_BY_V0_52 {
            if families.contains(&name) {
                put_entries(
                    &db_path,
                    families.iter().copied(),
                    name,
                    &[(b"row-key".to_vec(), format!("{name} row").into_bytes())],
                );
            }
        }
        put_entries(
            &db_path,
            families.iter().copied(),
            crate::tables::META,
            &[
                (
                    NETWORK_TAGS.to_vec(),
                    tag_index_bytes(&["0\0network-tag", "1\0other-tag"]),
                ),
                (
                    crate::tables::EVENT_TAGS.to_vec(),
                    tag_index_bytes(&["event-tag"]),
                ),
                (
                    crate::tables::WORKFLOW_TAGS.to_vec(),
                    tag_index_bytes(&["workflow-tag"]),
                ),
                (
                    COUNTRY_CODE_SWAP_CHECKPOINT_KEY.to_vec(),
                    b"checkpoint".to_vec(),
                ),
                (
                    COUNTRY_CODE_SWAP_COMPLETED_KEY.to_vec(),
                    b"completed".to_vec(),
                ),
            ],
        );
        put_entries(
            &db_path,
            families.iter().copied(),
            crate::tables::NETWORKS,
            &[(b"fixture-network".to_vec(), NETWORK_FIXTURE.to_vec())],
        );
        put_entries(
            &db_path,
            families.iter().copied(),
            crate::tables::CUSTOMER_NETWORKS,
            &[(
                1_u32.to_be_bytes().to_vec(),
                b"customer networks row".to_vec(),
            )],
        );
        put_entries(
            &db_path,
            families.iter().copied(),
            crate::tables::CONFIGS,
            &[(
                crate::tables::KEY_BACKUP_DURATION.as_bytes().to_vec(),
                b"7".to_vec(),
            )],
        );
        write_version(data_dir, version);
        write_version(backup_dir, version);
    }

    /// Migrates the store `create_v0_51_store` built over `families`, marked
    /// `version`, and asserts that it reaches the current format with the six
    /// families and the network tags gone and every other row unchanged; a
    /// second start then changes nothing.
    fn assert_migration_from_v0_51_store(version: &str, families: &[&str]) {
        let _permit = acquire_db_permit();
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_v0_51_store(data_dir.path(), backup_dir.path(), version, families);
        let mut expected = kept_family_entries(&db_path);
        for (name, entries) in &mut expected {
            if name == crate::tables::META {
                entries.retain(|(key, _)| key != NETWORK_TAGS);
            }
        }

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(present_families(&db_path), current_families());
        assert_eq!(
            raw_value(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::META,
                NETWORK_TAGS
            ),
            None
        );
        assert_eq!(
            raw_value(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::META,
                crate::tables::EVENT_TAGS
            ),
            Some(tag_index_bytes(&["event-tag"]))
        );
        assert_eq!(kept_family_entries(&db_path), expected);

        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        drop(store);

        // A second start is a no-op: nothing under either directory changes.
        let before = (files_under(data_dir.path()), files_under(backup_dir.path()));
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();
        assert_eq!(
            (files_under(data_dir.path()), files_under(backup_dir.path())),
            before
        );

        // Running the steps again on the migrated store finds nothing to do.
        super::migrate_0_50_to_0_52(data_dir.path()).unwrap();
        assert_eq!(present_families(&db_path), current_families());
        assert_eq!(kept_family_entries(&db_path), expected);
        super::migrate_0_52_to_0_53(data_dir.path()).unwrap();
        assert_eq!(present_families(&db_path), current_families());
        assert_eq!(kept_family_entries(&db_path), expected);
    }

    /// A `0.51.0` store loses the six families and the network tags, keeps
    /// every other row byte for byte, and is marked with the current version.
    #[test]
    fn migration_from_v0_51_drops_removed_families_and_network_tags() {
        assert_migration_from_v0_51_store("0.51.0", &super::MAP_NAMES_V0_50_TO_V0_51);
    }

    /// A `0.50.0` store reaches the same state as a `0.51.0` one.
    #[test]
    fn migration_from_v0_50_drops_removed_families_and_network_tags() {
        assert_migration_from_v0_51_store("0.50.0", &super::MAP_NAMES_V0_50_TO_V0_51);
    }

    /// A store whose 0.52 step was interrupted after dropping some of the six
    /// families, with the network tags still there, completes on retry.
    #[test]
    fn migration_from_v0_51_completes_a_partial_run() {
        let families: Vec<&str> = super::MAP_NAMES_V0_50_TO_V0_51
            .into_iter()
            .filter(|name| {
                ![
                    crate::tables::ACCESS_TOKENS,
                    crate::tables::BLOCK_NETWORKS,
                    crate::tables::FILTERS,
                ]
                .contains(name)
            })
            .collect();
        assert_migration_from_v0_51_store("0.51.0", &families);
    }

    /// Asserts that none of the six families the 0.52 step drops is present.
    fn assert_v0_52_removed_families_absent(db_path: &Path) {
        let present = super::existing_map_names(&rocksdb::Options::default(), db_path).unwrap();
        for name in FAMILIES_REMOVED_BY_V0_52 {
            assert!(
                !present.iter().any(|existing| existing == name),
                "{name} must be dropped"
            );
        }
    }

    /// A chain from `0.46.0` retried after the 0.52 step dropped the six
    /// families recreates them empty in the 0.47 step and drops them again.
    #[test]
    fn migration_from_v0_46_retried_after_removed_families_were_dropped() {
        let _permit = acquire_db_permit();
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_states_db(&db_path, super::MAP_NAMES_V0_43_TO_V0_46);
        for name in FAMILIES_REMOVED_BY_V0_52 {
            put_entries(
                &db_path,
                super::MAP_NAMES_V0_43_TO_V0_46,
                name,
                &[(b"row-key".to_vec(), b"row-value".to_vec())],
            );
        }
        write_version(data_dir.path(), "0.46.0");
        write_version(backup_dir.path(), "0.46.0");

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();
        assert_v0_52_removed_families_absent(&db_path);
        assert_eq!(present_families(&db_path), current_families());

        write_version(data_dir.path(), "0.46.0");
        write_version(backup_dir.path(), "0.46.0");
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_v0_52_removed_families_absent(&db_path);
        assert_eq!(present_families(&db_path), current_families());
    }

    /// A store marked `version` over `families` holds bytes no layout decodes
    /// in "customers", "allow networks" and "block networks", and an
    /// unprefixed network tag index. It migrates to the current format with
    /// all of them gone, and a retry from the same marker once the families
    /// are absent succeeds with the same families present.
    fn assert_migration_discards_unconverted_rows(version: &str, families: &[&str]) {
        let _permit = acquire_db_permit();
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_states_db(&db_path, families.iter().copied());
        for name in [
            crate::tables::CUSTOMERS,
            crate::tables::ALLOW_NETWORKS,
            crate::tables::BLOCK_NETWORKS,
        ] {
            put_entries(
                &db_path,
                families.iter().copied(),
                name,
                &[(b"not-a-row".to_vec(), vec![0xff; 3])],
            );
        }
        put_entries(
            &db_path,
            families.iter().copied(),
            crate::tables::META,
            &[(NETWORK_TAGS.to_vec(), tag_index_bytes(&["unprefixed-tag"]))],
        );

        for run in ["first run", "retry"] {
            write_version(data_dir.path(), version);
            write_version(backup_dir.path(), version);
            migrate_data_dir(data_dir.path(), backup_dir.path(), None)
                .unwrap_or_else(|e| panic!("{run} from {version} failed: {e:#}"));

            assert_eq!(
                read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
                current_version
            );
            assert_eq!(
                read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
                current_version
            );
            assert_eq!(present_families(&db_path), current_families());
            assert_eq!(
                raw_value(
                    &db_path,
                    crate::tables::MAP_NAMES,
                    crate::tables::META,
                    NETWORK_TAGS
                ),
                None
            );
            let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
            drop(store);
        }
    }

    #[test]
    fn migration_from_v0_42_discards_unconverted_rows() {
        assert_migration_discards_unconverted_rows("0.42.0", &super::MAP_NAMES_V0_42);
    }

    #[test]
    fn migration_from_v0_43_discards_unconverted_rows() {
        assert_migration_discards_unconverted_rows("0.43.0", &super::MAP_NAMES_V0_43_TO_V0_46);
    }

    /// `VERSION` is written only after the whole chain succeeds, so a chain
    /// from `0.46.0` interrupted after the "customer networks" family was
    /// created retries from that marker with the family already there. Every
    /// earlier step must open it, and the retry must complete without creating
    /// it again.
    #[test]
    fn migration_from_v0_46_retried_after_customer_networks_was_created() {
        let _permit = acquire_db_permit();
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        create_states_db(
            &db_path,
            super::MAP_NAMES_V0_43_TO_V0_46
                .into_iter()
                .chain(FAMILIES_ADDED_BY_V0_50),
        );
        put_entries(
            &db_path,
            super::MAP_NAMES_V0_43_TO_V0_46
                .into_iter()
                .chain(FAMILIES_ADDED_BY_V0_50),
            crate::tables::CUSTOMER_NETWORKS,
            &[(1u32.to_be_bytes().to_vec(), b"kept".to_vec())],
        );
        write_version(data_dir.path(), "0.46.0");
        write_version(backup_dir.path(), "0.46.0");

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        let mut present =
            super::existing_map_names(&rocksdb::Options::default(), &db_path).unwrap();
        present.sort_unstable();
        let mut expected: Vec<String> = crate::tables::MAP_NAMES
            .into_iter()
            .map(str::to_string)
            .collect();
        expected.sort_unstable();
        assert_eq!(present, expected);
        assert_eq!(
            cf_entries(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::CUSTOMER_NETWORKS
            ),
            vec![(1u32.to_be_bytes().to_vec(), b"kept".to_vec())]
        );
    }

    /// Creates a store over `families`, the 0.52 set or a superset of it,
    /// marked `0.52.0`, with an entry in the default family and a row in
    /// "customer networks", "configs" and "meta".
    fn create_v0_52_store(data_dir: &Path, backup_dir: &Path, families: &[&str]) {
        let db_path = data_dir.join("states.db");
        create_states_db(&db_path, families.iter().copied());
        open_states_db(&db_path, families.iter().copied())
            .put(b"default-key", b"default value")
            .unwrap();
        put_entries(
            &db_path,
            families.iter().copied(),
            crate::tables::CUSTOMER_NETWORKS,
            &[(
                1_u32.to_be_bytes().to_vec(),
                b"customer networks row".to_vec(),
            )],
        );
        put_entries(
            &db_path,
            families.iter().copied(),
            crate::tables::CONFIGS,
            &[(
                crate::tables::KEY_BACKUP_DURATION.as_bytes().to_vec(),
                b"7".to_vec(),
            )],
        );
        put_entries(
            &db_path,
            families.iter().copied(),
            crate::tables::META,
            &[(
                crate::tables::EVENT_TAGS.to_vec(),
                tag_index_bytes(&["event-tag"]),
            )],
        );
        write_version(data_dir, "0.52.0");
        write_version(backup_dir, "0.52.0");
    }

    /// A `0.52.0` store migrates to the current format with an empty "network
    /// lists" family, every other family unchanged byte for byte, and both
    /// markers naming the current version; a second start finds the store
    /// current and touches nothing.
    #[test]
    fn migration_from_v0_52_creates_empty_network_lists() {
        let _permit = acquire_db_permit();
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        let mut v0_53: Vec<&str> = super::MAP_NAMES_V0_52
            .into_iter()
            .chain(FAMILIES_ADDED_BY_V0_53)
            .collect();
        v0_53.sort_unstable();
        let mut listed_v0_53 = super::MAP_NAMES_V0_53;
        listed_v0_53.sort_unstable();
        assert_eq!(v0_53, listed_v0_53);
        let mut v0_55: Vec<&str> = v0_53.into_iter().chain(FAMILIES_ADDED_BY_V0_55).collect();
        v0_55.sort_unstable();
        let mut listed_v0_55 = super::MAP_NAMES_V0_55;
        listed_v0_55.sort_unstable();
        assert_eq!(v0_55, listed_v0_55);
        let mut v0_58: Vec<&str> = v0_55
            .into_iter()
            .chain(FAMILIES_ADDED_BY_V0_56)
            .chain(FAMILIES_ADDED_BY_V0_58)
            .collect();
        v0_58.sort_unstable();
        let mut current = crate::tables::MAP_NAMES;
        current.sort_unstable();
        assert_eq!(v0_58, current);

        create_v0_52_store(data_dir.path(), backup_dir.path(), &super::MAP_NAMES_V0_52);
        assert!(
            !present_families(&db_path)
                .iter()
                .any(|name| name == crate::tables::NETWORK_LISTS)
        );
        let expected = kept_family_entries(&db_path);

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(present_families(&db_path), current_families());
        assert_eq!(
            cf_entries(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::NETWORK_LISTS
            ),
            Entries::new()
        );
        assert_eq!(kept_family_entries(&db_path), expected);

        // A second start is a no-op: nothing under either directory changes.
        let before = (files_under(data_dir.path()), files_under(backup_dir.path()));
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();
        assert_eq!(
            (files_under(data_dir.path()), files_under(backup_dir.path())),
            before
        );

        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        assert_eq!(store.network_lists_map().iter().count(), 0);
    }

    /// `VERSION` is written only after the whole chain succeeds, so a
    /// migration from `0.52.0` interrupted after the "network lists" family
    /// was created retries from that marker with the family already there.
    /// The retry must complete without creating it again, keeping its rows.
    #[test]
    fn migration_from_v0_52_retried_after_network_lists_was_created() {
        let _permit = acquire_db_permit();
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        let families: Vec<&str> = super::MAP_NAMES_V0_52
            .into_iter()
            .chain(FAMILIES_ADDED_BY_V0_53)
            .collect();
        create_v0_52_store(data_dir.path(), backup_dir.path(), &families);
        put_entries(
            &db_path,
            families.iter().copied(),
            crate::tables::NETWORK_LISTS,
            &[(1u32.to_be_bytes().to_vec(), b"kept".to_vec())],
        );
        let expected = kept_family_entries(&db_path);

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(present_families(&db_path), current_families());
        assert_eq!(
            cf_entries(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::NETWORK_LISTS
            ),
            vec![(1u32.to_be_bytes().to_vec(), b"kept".to_vec())]
        );
        assert_eq!(kept_family_entries(&db_path), expected);
    }

    /// Creates a store over `families`, the 0.55 set or a superset of it,
    /// marked `0.55.0`, with an entry in the default family and a row in
    /// "network lists", "configs" and "meta".
    fn create_v0_55_store(data_dir: &Path, backup_dir: &Path, families: &[&str]) {
        let db_path = data_dir.join("states.db");
        create_states_db(&db_path, families.iter().copied());
        open_states_db(&db_path, families.iter().copied())
            .put(b"default-key", b"default value")
            .unwrap();
        put_entries(
            &db_path,
            families.iter().copied(),
            crate::tables::NETWORK_LISTS,
            &[(1_u32.to_be_bytes().to_vec(), b"network lists row".to_vec())],
        );
        put_entries(
            &db_path,
            families.iter().copied(),
            crate::tables::CONFIGS,
            &[(
                crate::tables::KEY_BACKUP_DURATION.as_bytes().to_vec(),
                b"7".to_vec(),
            )],
        );
        put_entries(
            &db_path,
            families.iter().copied(),
            crate::tables::META,
            &[(
                crate::tables::EVENT_TAGS.to_vec(),
                tag_index_bytes(&["event-tag"]),
            )],
        );
        write_version(data_dir, "0.55.0");
        write_version(backup_dir, "0.55.0");
    }

    /// A `0.55.0` store migrates to the current format with an empty "system
    /// log collectors" family, every other family unchanged byte for byte,
    /// and both markers naming the current format; a second start finds the
    /// store current and touches nothing.
    #[test]
    fn migration_from_v0_55_creates_empty_system_log_collectors() {
        let _permit = acquire_db_permit();
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        create_v0_55_store(data_dir.path(), backup_dir.path(), &super::MAP_NAMES_V0_55);
        assert!(
            !present_families(&db_path)
                .iter()
                .any(|name| name == crate::tables::SYSTEM_LOG_COLLECTORS)
        );
        let expected = kept_family_entries(&db_path);

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(present_families(&db_path), current_families());
        assert_eq!(
            cf_entries(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::SYSTEM_LOG_COLLECTORS
            ),
            Entries::new()
        );
        assert_eq!(kept_family_entries(&db_path), expected);

        // A second start is a no-op: nothing under either directory changes.
        let before = (files_under(data_dir.path()), files_under(backup_dir.path()));
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();
        assert_eq!(
            (files_under(data_dir.path()), files_under(backup_dir.path())),
            before
        );

        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        assert_eq!(store.system_log_collector_map().list().unwrap(), Vec::new());
    }

    /// `VERSION` is written only after the whole chain succeeds, so a
    /// migration from `0.55.0` interrupted after the "system log collectors"
    /// family was created retries from that marker with the family already
    /// there. The retry must complete without creating it again, keeping its
    /// rows.
    #[test]
    fn migration_from_v0_55_retried_after_system_log_collectors_was_created() {
        let _permit = acquire_db_permit();
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        let families: Vec<&str> = super::MAP_NAMES_V0_55
            .into_iter()
            .chain(FAMILIES_ADDED_BY_V0_56)
            .collect();
        create_v0_55_store(data_dir.path(), backup_dir.path(), &families);
        put_entries(
            &db_path,
            families.iter().copied(),
            crate::tables::SYSTEM_LOG_COLLECTORS,
            &[(b"host-a.example".to_vec(), b"kept".to_vec())],
        );
        let expected = kept_family_entries(&db_path);

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(present_families(&db_path), current_families());
        assert_eq!(
            cf_entries(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::SYSTEM_LOG_COLLECTORS
            ),
            vec![(b"host-a.example".to_vec(), b"kept".to_vec())]
        );
        assert_eq!(kept_family_entries(&db_path), expected);
    }

    /// Rows a 0.53 store holds in each per-model family: those of model "m"
    /// (id 0), with records in every per-model family, and orphan clusters
    /// and outliers of model id 7, which has no model row. The values need
    /// not decode: the migration drops the families wholesale.
    fn per_model_rows_v0_53() -> Vec<(&'static str, Entries)> {
        let key = |id: u32, rest: &[u8]| {
            let mut key = id.to_be_bytes().to_vec();
            key.extend_from_slice(rest);
            key
        };
        vec![
            (
                crate::tables::MODELS,
                vec![
                    (Vec::new(), b"model index".to_vec()),
                    (b"m".to_vec(), b"format 1 model".to_vec()),
                ],
            ),
            (
                crate::tables::BATCH_INFO,
                vec![(key(0, &1_i64.to_be_bytes()), b"batch".to_vec())],
            ),
            (crate::tables::SCORES, vec![(vec![0], b"scores".to_vec())]),
            (
                crate::tables::CLUSTER,
                vec![
                    (key(0, &1_u32.to_be_bytes()), b"cluster".to_vec()),
                    (key(7, &1_u32.to_be_bytes()), b"orphan cluster".to_vec()),
                ],
            ),
            (
                crate::tables::COLUMN_STATS,
                vec![(key(0, &[0; 16]), b"column stats".to_vec())],
            ),
            (
                crate::tables::CSV_COLUMN_EXTRAS,
                vec![
                    (Vec::new(), b"extra index".to_vec()),
                    (key(0, &[]), b"extra".to_vec()),
                ],
            ),
            (
                crate::tables::TIME_SERIES,
                vec![(key(0, &[0; 20]), b"time series".to_vec())],
            ),
            (
                crate::tables::MODEL_INDICATORS,
                vec![(b"indicator".to_vec(), b"indicator".to_vec())],
            ),
            (
                crate::tables::OUTLIERS,
                vec![
                    (key(0, &[0; 24]), b"outlier".to_vec()),
                    (key(7, &[0; 24]), b"orphan outlier".to_vec()),
                ],
            ),
        ]
    }

    /// Creates a store over `families`, a 0.53-and-later set, marked
    /// `0.53.0`, with the rows of [`create_v0_52_store`], a row in "network
    /// lists", the rows of [`per_model_rows_v0_53`] in each per-model family
    /// `families` has if `per_model_rows` is set, and, under `classifiers`,
    /// the files of `classifier_dirs`.
    fn create_v0_53_store(
        data_dir: &Path,
        backup_dir: &Path,
        families: &[&str],
        per_model_rows: bool,
        classifier_dirs: &[&str],
    ) {
        let db_path = data_dir.join("states.db");
        create_v0_52_store(data_dir, backup_dir, families);
        put_entries(
            &db_path,
            families.iter().copied(),
            crate::tables::NETWORK_LISTS,
            &[(1_u32.to_be_bytes().to_vec(), b"network lists row".to_vec())],
        );
        if per_model_rows {
            for (family, rows) in per_model_rows_v0_53() {
                if families.contains(&family) {
                    put_entries(&db_path, families.iter().copied(), family, &rows);
                }
            }
        }
        for dir in classifier_dirs {
            let dir = data_dir.join("classifiers").join(dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("classifier_m.bin"), b"format 1 classifier").unwrap();
        }
        std::fs::write(data_dir.join("untouched"), b"keep me").unwrap();
        write_version(data_dir, "0.53.0");
        write_version(backup_dir, "0.53.0");
    }

    /// What [`kept_family_entries`] reads from `db_path` once the per-model
    /// families are emptied.
    fn entries_without_models(db_path: &Path) -> Vec<(String, Entries)> {
        kept_family_entries(db_path)
            .into_iter()
            .map(|(name, entries)| {
                if super::PER_MODEL_FAMILIES_V0_53.contains(&name.as_str())
                    || super::PREVIOUS_RESULT_FAMILIES_V0_55.contains(&name.as_str())
                    || super::TRAINING_FAMILIES_V0_55.contains(&name.as_str())
                {
                    (name, Entries::new())
                } else {
                    (name, entries)
                }
            })
            .collect()
    }

    /// Asserts that the store migrated from 0.53 has every current family,
    /// with no row in the per-model and previous-result families and every
    /// other family as `expected` holds it, that `classifiers` is gone and
    /// nothing else outside `states.db` changed, and that both markers name
    /// the current version.
    fn assert_migrated_from_v0_53(
        data_dir: &Path,
        backup_dir: &Path,
        expected: &[(String, Entries)],
    ) {
        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        let db_path = data_dir.join("states.db");
        assert_eq!(
            read_version_file(&data_dir.join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(
            read_version_file(&backup_dir.join(VERSION_FILE_NAME)).unwrap(),
            current_version
        );
        assert_eq!(present_families(&db_path), current_families());
        for name in super::PER_MODEL_FAMILIES_V0_53
            .into_iter()
            .chain(FAMILIES_ADDED_BY_V0_55)
        {
            assert_eq!(
                cf_entries(&db_path, crate::tables::MAP_NAMES, name),
                Entries::new(),
                "{name} must be empty"
            );
        }
        assert_eq!(kept_family_entries(&db_path), expected);
        assert!(!data_dir.join("classifiers").exists());
        assert_eq!(
            entries_outside_states_db(data_dir),
            vec![
                (
                    data_dir.join("VERSION"),
                    current_version.to_string().into_bytes()
                ),
                (data_dir.join("untouched"), b"keep me".to_vec()),
            ]
        );

        let store = Store::new(data_dir, backup_dir, None).unwrap();
        assert_eq!(store.model_map().count_models().unwrap(), 0);
        assert_eq!(store.network_lists_map().iter().count(), 1);
    }

    /// A populated `0.53.0` store — models, every per-model record, orphan
    /// clusters and outliers of a model id with no model row, and classifier
    /// files — loses every model: the nine per-model families end empty, the
    /// seven previous-result families exist empty, the `classifiers`
    /// directory is gone, and every other family is unchanged byte for byte.
    /// A second start finds the store current and touches nothing.
    #[test]
    fn migration_from_v0_53_removes_every_model() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        create_v0_53_store(
            data_dir.path(),
            backup_dir.path(),
            &super::MAP_NAMES_V0_53,
            true,
            &["model_0", "model_7"],
        );
        for (family, rows) in per_model_rows_v0_53() {
            assert_eq!(
                cf_entries(&db_path, super::MAP_NAMES_V0_53, family),
                rows,
                "the fixture fills {family}"
            );
        }
        let expected = entries_without_models(&db_path);

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();
        assert_migrated_from_v0_53(data_dir.path(), backup_dir.path(), &expected);

        let before = (files_under(data_dir.path()), files_under(backup_dir.path()));
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();
        assert_eq!(
            (files_under(data_dir.path()), files_under(backup_dir.path())),
            before
        );
    }

    /// `VERSION` is written only after the whole chain succeeds, so a
    /// migration from `0.53.0` interrupted at any point of its step retries
    /// that step from the start. Each interruption point leaves a different
    /// store; the retry completes from every one of them.
    #[test]
    fn migration_from_v0_53_completes_after_an_interruption_at_each_step() {
        let _permit = acquire_db_permit();
        let without = |dropped: &[&str]| -> Vec<&'static str> {
            super::MAP_NAMES_V0_53
                .into_iter()
                .filter(|name| !dropped.contains(name))
                .collect()
        };
        let with_previous = |count: usize| -> Vec<&'static str> {
            super::MAP_NAMES_V0_53
                .into_iter()
                .chain(FAMILIES_ADDED_BY_V0_55.into_iter().take(count))
                .collect()
        };
        // (families present, per-model rows left, classifier directories left)
        let interruptions: Vec<(Vec<&str>, bool, &[&str])> = vec![
            // In step 2, after the first families were dropped and before
            // they were created again.
            (
                without(&[crate::tables::MODELS, crate::tables::BATCH_INFO]),
                true,
                &["model_0", "model_7"],
            ),
            // In step 2, after the first families were emptied.
            (
                super::MAP_NAMES_V0_53.to_vec(),
                true,
                &["model_0", "model_7"],
            ),
            // In step 3, after some previous-result families were created.
            (with_previous(3), false, &["model_0", "model_7"]),
            // In step 3, after the previous-result families were created and
            // before "training definitions" was.
            (with_previous(7), false, &["model_0", "model_7"]),
            // In step 3, after "training definitions" was created and before
            // "model runs" was.
            (with_previous(8), false, &["model_0", "model_7"]),
            // In step 3, after "model runs" was created and before "engine
            // instances" was.
            (with_previous(9), false, &["model_0", "model_7"]),
            // In step 4, part-way through the classifier files.
            (with_previous(10), false, &["model_7"]),
            // After step 4, before `VERSION` was written.
            (with_previous(10), false, &[]),
        ];
        for (families, per_model_rows, classifier_dirs) in interruptions {
            let data_dir = tempfile::tempdir().unwrap();
            let backup_dir = tempfile::tempdir().unwrap();
            let db_path = data_dir.path().join("states.db");
            create_v0_53_store(
                data_dir.path(),
                backup_dir.path(),
                &families,
                per_model_rows,
                classifier_dirs,
            );
            let expected = entries_without_models(&db_path);

            migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();
            assert_migrated_from_v0_53(data_dir.path(), backup_dir.path(), &expected);
        }

        // The step itself, run again over a migrated store, changes nothing.
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_v0_53_store(
            data_dir.path(),
            backup_dir.path(),
            &super::MAP_NAMES_V0_53,
            true,
            &["model_0"],
        );
        let expected = entries_without_models(&db_path);
        super::migrate_0_53_to_0_55(data_dir.path()).unwrap();
        super::migrate_0_53_to_0_55(data_dir.path()).unwrap();
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();
        assert_migrated_from_v0_53(data_dir.path(), backup_dir.path(), &expected);
    }

    /// A `0.54.0` store, in the same format as `0.53.x`, migrates as one
    /// stamped `0.53.0` does: every model is removed and the new families,
    /// "engine instances" among them, are created empty. A second start
    /// finds the store current and touches nothing.
    #[test]
    fn migration_from_v0_54_creates_engine_instances() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        create_v0_53_store(
            data_dir.path(),
            backup_dir.path(),
            &super::MAP_NAMES_V0_53,
            true,
            &["model_0"],
        );
        write_version(data_dir.path(), "0.54.0");
        write_version(backup_dir.path(), "0.54.0");
        let expected = entries_without_models(&db_path);

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();
        assert_migrated_from_v0_53(data_dir.path(), backup_dir.path(), &expected);

        let before = (files_under(data_dir.path()), files_under(backup_dir.path()));
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();
        assert_eq!(
            (files_under(data_dir.path()), files_under(backup_dir.path())),
            before
        );
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
                let value = bincode::DefaultOptions::new()
                    .deserialize::<AgentValueV0_47>(&migrated)
                    .unwrap();
                assert_eq!(value.instance, None, "{cf_name}");
                value.lifecycle
            } else {
                let value = bincode::DefaultOptions::new()
                    .deserialize::<ExternalServiceValueV0_47>(&migrated)
                    .unwrap();
                assert_eq!(value.instance, None, "{cf_name}");
                value.lifecycle
            };
            assert_eq!(lifecycle, 0, "{cf_name}");
        }

        // Verify both VERSION files are updated to the current format marker
        let data_version = read_version_file(&data_dir.path().join("VERSION")).unwrap();
        let backup_version = read_version_file(&backup_dir.path().join("VERSION")).unwrap();

        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        assert_eq!(
            data_version, current_version,
            "Data VERSION should be updated to the current format marker"
        );
        assert_eq!(
            backup_version, current_version,
            "Backup VERSION should be updated to the current format marker"
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

        let current_version = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
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

        // Retrying the 0.42 step leaves the family the earlier run created,
        // and the row in it, alone.
        super::migrate_0_42_to_0_43(data_dir.path()).unwrap();
        assert_eq!(
            raw_value(
                &db_path,
                super::MAP_NAMES_V0_43_TO_V0_46,
                crate::tables::TRIAGE_EXCLUSION_REASON,
                b"reason-key",
            )
            .as_deref(),
            Some(b"reason-value".as_slice())
        );

        // The rest of the chain then drops the family with its rows.
        retry_migration_from_v0_42(data_dir.path(), backup_dir.path());
        assert_triage_families_absent(&db_path);
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
        let service_results = vec![crate::CustomerDataDeletionServiceResult {
            service: crate::CustomerDataDeletionService::Review,
            host_fqdns: vec!["review.example".to_string()],
            status: crate::CustomerDataDeletionStatus::InProgress,
            requested_at: 1,
            completed_at: None,
            error: None,
        }];
        db.put_cf(
            db.cf_handle(crate::tables::CUSTOMER_DELETION_JOBS).unwrap(),
            1_u32.to_be_bytes(),
            bincode::DefaultOptions::new()
                .serialize(&service_results)
                .unwrap(),
        )
        .unwrap();
        drop(db);

        retry_migration_from_v0_42(data_dir.path(), backup_dir.path());
        assert_current_cf_value(
            &db_path,
            crate::tables::CUSTOMER_DELETION_JOBS,
            &1_u32.to_be_bytes(),
            &bincode::DefaultOptions::new()
                .serialize(&(service_results, Vec::<String>::new(), Vec::<String>::new()))
                .unwrap(),
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
        let current = Version::parse(DATABASE_FORMAT_VERSION).expect("valid semver");
        assert!(compatible.matches(&current));

        // The next format must not be taken for the current one.
        let next = Version::new(current.major, current.minor + 1, 0);
        assert!(!compatible.matches(&next));

        // A release built before this format must not take it for its own.
        let previous = VersionReq::parse(">=0.55.0,<0.56.0").expect("valid semver");
        assert!(!previous.matches(&current));
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
            ))
            .unwrap();
        assert_eq!(id0, 0, "First available id should fill the gap at 0");

        let id2 = table
            .insert(Network::new(
                "GapNet2".to_string(),
                "Gap description 2".to_string(),
                HostNetworkGroup::default(),
            ))
            .unwrap();
        assert_eq!(id2, 2, "Second available id should fill the gap at 2");
    }

    /// An entry of the sampling-policy index, in the layout the 0.56 format
    /// serializes `KeyIndex` entries in.
    #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
    enum KeyIndexEntryV0_56 {
        Key(Vec<u8>),
        Index(u32),
        Inactive(Option<u32>),
    }

    /// The sampling-policy index, in the layout the 0.56 format serializes
    /// `KeyIndex` in.
    #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
    struct KeyIndexV0_56 {
        keys: Vec<KeyIndexEntryV0_56>,
        available: u32,
        inactive: Option<u32>,
    }

    /// Creates a `0.56.0` store whose sampling-policy family holds `index`
    /// under the empty key and `policies` as rows.
    fn create_v0_56_sampling_policy_store(
        data_dir: &Path,
        backup_dir: &Path,
        index: &KeyIndexV0_56,
        policies: &[SamplingPolicyV0_56],
    ) {
        let db_path = data_dir.join("states.db");
        create_states_db(&db_path, crate::tables::MAP_NAMES);
        let mut entries = vec![(
            Vec::new(),
            bincode::DefaultOptions::new().serialize(index).unwrap(),
        )];
        entries.extend(policies.iter().map(|policy| {
            (
                policy.name.as_bytes().to_vec(),
                bincode::DefaultOptions::new().serialize(policy).unwrap(),
            )
        }));
        put_entries(
            &db_path,
            crate::tables::MAP_NAMES,
            crate::tables::SAMPLING_POLICY,
            &entries,
        );
        write_version(data_dir, "0.56.0");
        write_version(backup_dir, "0.56.0");
    }

    /// Reads back the sampling-policy index of the store at `db_path`.
    fn sampling_policy_index(db_path: &Path) -> KeyIndexV0_56 {
        let bytes = raw_value(
            db_path,
            crate::tables::MAP_NAMES,
            crate::tables::SAMPLING_POLICY,
            &[],
        )
        .unwrap();
        bincode::DefaultOptions::new().deserialize(&bytes).unwrap()
    }

    fn sampling_policy_v0_56(id: u32, name: &str) -> SamplingPolicyV0_56 {
        SamplingPolicyV0_56 {
            id,
            name: name.to_string(),
            kind: crate::SamplingKind::Conn,
            interval: crate::SamplingInterval::FiveMinutes,
            period: crate::SamplingPeriod::OneDay,
            offset: 0,
            src_ip: None,
            dst_ip: None,
            node: None,
            column: None,
            immutable: false,
            creation_time: chrono::Utc::now(),
        }
    }

    /// A new sampling policy named `name` of customer 1.
    fn new_sampling_policy(name: &str) -> crate::NewSamplingPolicy {
        crate::NewSamplingPolicy {
            name: name.to_string(),
            kind: crate::SamplingKind::Conn,
            interval: crate::SamplingInterval::FiveMinutes,
            period: crate::SamplingPeriod::OneDay,
            offset: 0,
            src_ip: None,
            dst_ip: None,
            node: None,
            column: None,
            customer_id: 1,
        }
    }

    /// The 0.57 step retires every free sampling-policy ID: an index whose
    /// entries 0..=2 are all on the free list becomes all inactive, and the
    /// next insert takes ID 3.
    #[test]
    fn migration_from_v0_56_retires_free_sampling_policy_ids() {
        use KeyIndexEntryV0_56::{Inactive, Index};

        let permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        let index = KeyIndexV0_56 {
            keys: vec![Index(1), Index(2), Index(3)],
            available: 0,
            inactive: None,
        };
        create_v0_56_sampling_policy_store(data_dir.path(), backup_dir.path(), &index, &[]);

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        let migrated = sampling_policy_index(&db_path);
        assert_eq!(migrated.available, 3);
        assert_eq!(migrated.keys.len(), 3);
        assert!(
            migrated
                .keys
                .iter()
                .all(|entry| matches!(entry, Inactive(_)))
        );
        assert!(migrated.inactive.is_some());
        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            Version::parse(DATABASE_FORMAT_VERSION).unwrap()
        );

        // A second start finds the store current and touches nothing.
        let before = (files_under(data_dir.path()), files_under(backup_dir.path()));
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();
        assert_eq!(
            (files_under(data_dir.path()), files_under(backup_dir.path())),
            before
        );

        let test_schema = TestSchema::new_with_dir(permit, data_dir, backup_dir);
        let table = test_schema.store.sampling_policy_map();
        assert_eq!(table.count().unwrap(), 0);
        for id in 0..=2 {
            assert!(table.get_by_id(id).unwrap().is_none());
        }
        assert_eq!(table.insert(new_sampling_policy("new")).unwrap(), 3);
    }

    /// Records survive the 0.57 step under their IDs, the freed IDs between
    /// them are retired, and `count` and iteration skip the retired ones.
    #[test]
    fn migration_from_v0_56_keeps_sampling_policies_and_retires_gaps() {
        use KeyIndexEntryV0_56::{Inactive, Index, Key};

        use crate::Iterable;

        let permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        // ID 1 is free, then ID 3; ID 4 was deactivated.
        let index = KeyIndexV0_56 {
            keys: vec![
                Key(b"a".to_vec()),
                Index(3),
                Key(b"c".to_vec()),
                Index(5),
                Inactive(None),
            ],
            available: 1,
            inactive: Some(4),
        };
        let policies = [sampling_policy_v0_56(0, "a"), sampling_policy_v0_56(2, "c")];
        create_v0_56_sampling_policy_store(data_dir.path(), backup_dir.path(), &index, &policies);

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        let migrated = sampling_policy_index(&db_path);
        assert_eq!(migrated.available, 5);
        assert_eq!(migrated.keys[0], Key(b"a".to_vec()));
        assert_eq!(migrated.keys[2], Key(b"c".to_vec()));
        for i in [1, 3, 4] {
            assert!(matches!(migrated.keys[i], Inactive(_)));
        }

        let test_schema = TestSchema::new_with_dir(permit, data_dir, backup_dir);
        let table = test_schema.store.sampling_policy_map();
        assert_eq!(table.count().unwrap(), 2);
        assert_eq!(
            table.get_by_id(0).unwrap().map(|policy| policy.name),
            Some("a".to_string())
        );
        assert_eq!(
            table.get_by_id(2).unwrap().map(|policy| policy.name),
            Some("c".to_string())
        );
        for id in [1, 3, 4] {
            assert!(table.get_by_id(id).unwrap().is_none());
        }
        let ids: Vec<u32> = table
            .iter(rocksdb::Direction::Forward, None)
            .map(|policy| policy.unwrap().id)
            .collect();
        assert_eq!(ids, vec![0, 2]);
        assert_eq!(table.insert(new_sampling_policy("d")).unwrap(), 5);
    }

    /// Locks the 0.56 layout of a stored sampling policy, which the 0.57 step
    /// reads, to the committed literal bytes of the released format.
    #[test]
    fn sampling_policy_v0_56_literal_bytes_contract() {
        const FIXTURE_BYTES: &[u8] =
            include_bytes!("../tests/fixtures/sampling_policy_v0_56_literal_bytes.bin");

        let expected = SamplingPolicyV0_56 {
            id: 42,
            name: "fixture-policy".to_string(),
            kind: crate::SamplingKind::Http,
            interval: crate::SamplingInterval::ThirtyMinutes,
            period: crate::SamplingPeriod::OneDay,
            offset: -300,
            src_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 10))),
            dst_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 5))),
            node: Some("sensor-node-1".to_string()),
            column: Some(7),
            immutable: true,
            creation_time: chrono::DateTime::from_timestamp(1_700_000_000, 123_456_789).unwrap(),
        };
        let decoded: SamplingPolicyV0_56 = bincode::DefaultOptions::new()
            .deserialize(FIXTURE_BYTES)
            .unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(
            bincode::DefaultOptions::new().serialize(&expected).unwrap(),
            FIXTURE_BYTES
        );
        assert!(
            bincode::DefaultOptions::new()
                .deserialize::<crate::SamplingPolicy>(FIXTURE_BYTES)
                .is_err(),
            "a 0.56 record must not decode as the 0.57 layout"
        );
    }

    const SENSOR_HOST: &str = "sensor.example";
    const PLAIN_HOST: &str = "plain.example";
    const SENSOR_CUSTOMER: u32 = 7;

    /// Writes, in the 0.56 layout, a node of [`SENSOR_CUSTOMER`] at
    /// [`SENSOR_HOST`] carrying a sensor, and a node of customer 8 at
    /// [`PLAIN_HOST`] carrying only a Time Series Generator.
    fn put_v0_56_nodes(db_path: &Path) {
        let node = |id: u32, name: &str, customer_id: u32, hostname: &str, agent: &str| NodeV0_56 {
            id,
            name: name.to_string(),
            name_draft: None,
            profile: Some(NodeProfileV0_56 {
                customer_id,
                description: String::new(),
                hostname: hostname.to_string(),
            }),
            profile_draft: None,
            creation_time: chrono::Utc::now(),
            agents: vec![agent.to_string()],
            external_services: Vec::new(),
        };
        let nodes = [
            node(
                0,
                "sensor-node",
                SENSOR_CUSTOMER,
                SENSOR_HOST,
                "piglet@sensor",
            ),
            node(1, "plain-node", 8, PLAIN_HOST, "crusher@plain"),
        ];
        let entries: Entries = nodes
            .iter()
            .map(|node| {
                (
                    node.name.as_bytes().to_vec(),
                    bincode::DefaultOptions::new().serialize(node).unwrap(),
                )
            })
            .collect();
        put_entries(
            db_path,
            crate::tables::MAP_NAMES,
            crate::tables::NODES,
            &entries,
        );
        let agent = |node_id: u32, key: &str, kind: AgentKind| {
            let mut stored = node_id.to_be_bytes().to_vec();
            stored.extend(key.as_bytes());
            let value = AgentValueV0_47 {
                kind,
                status: AgentStatus::Enabled,
                config: None,
                draft: None,
                installed_version: None,
                installed_commit: None,
                lifecycle: 0,
                bound_addrs: Vec::new(),
                instance: Some(1),
            };
            (
                stored,
                bincode::DefaultOptions::new().serialize(&value).unwrap(),
            )
        };
        put_entries(
            db_path,
            crate::tables::MAP_NAMES,
            crate::tables::AGENTS,
            &[
                agent(0, "piglet@sensor", AgentKind::Sensor),
                agent(1, "crusher@plain", AgentKind::TimeSeriesGenerator),
            ],
        );
    }

    /// The 0.57 step makes every policy `Fixed`, `immutable` or not, with no
    /// assignee and no Data Store; gives a sensor-named policy its sensor's
    /// customer and every other policy none; and drops `immutable`. A rerun
    /// changes nothing.
    #[test]
    fn migration_from_v0_56_rewrites_sampling_policies() {
        use KeyIndexEntryV0_56::Key;

        let permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");

        let policy =
            |id: u32, name: &str, node: Option<String>, immutable: bool| SamplingPolicyV0_56 {
                node,
                immutable,
                ..sampling_policy_v0_56(id, name)
            };
        let policies = [
            policy(
                0,
                "sensor-named",
                Some(format!("piglet.{SENSOR_HOST}")),
                true,
            ),
            policy(1, "mutable", Some(format!("piglet.{SENSOR_HOST}")), false),
            policy(2, "hostname", Some(SENSOR_HOST.to_string()), true),
            policy(3, "node-less", None, false),
            policy(4, "no-sensor", Some(format!("piglet.{PLAIN_HOST}")), true),
        ];
        let index = KeyIndexV0_56 {
            keys: policies
                .iter()
                .map(|policy| Key(policy.name.as_bytes().to_vec()))
                .collect(),
            available: 5,
            inactive: None,
        };
        create_v0_56_sampling_policy_store(data_dir.path(), backup_dir.path(), &index, &policies);
        put_v0_56_nodes(&db_path);

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        let stored = |name: &str| {
            raw_value(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::SAMPLING_POLICY,
                name.as_bytes(),
            )
            .unwrap()
        };
        for old in &policies {
            let bytes = stored(&old.name);
            assert!(
                bincode::DefaultOptions::new()
                    .deserialize::<SamplingPolicyV0_56>(&bytes)
                    .is_err(),
                "`immutable` is gone from {:?}",
                old.name
            );
            let migrated: crate::SamplingPolicy =
                bincode::DefaultOptions::new().deserialize(&bytes).unwrap();
            let customer_id =
                matches!(old.name.as_str(), "sensor-named" | "mutable").then_some(SENSOR_CUSTOMER);
            assert_eq!(migrated, old.clone().into_fixed(customer_id));
            assert_eq!(migrated.state, crate::PolicyState::Fixed);
            assert_eq!(migrated.assignee, None);
            assert_eq!(migrated.data_store, None);
        }

        // An interrupted chain runs the step again over migrated records.
        let snapshot: Vec<Vec<u8>> = policies.iter().map(|p| stored(&p.name)).collect();
        migrate_0_56_to_0_57(data_dir.path()).unwrap();
        let after: Vec<Vec<u8>> = policies.iter().map(|p| stored(&p.name)).collect();
        assert_eq!(after, snapshot);

        let test_schema = TestSchema::new_with_dir(permit, data_dir, backup_dir);
        let table = test_schema.store.sampling_policy_map();
        assert_eq!(table.count().unwrap(), 5);
        assert_eq!(
            table.get_by_id(0).unwrap().unwrap().customer_id,
            Some(SENSOR_CUSTOMER)
        );
    }

    /// The 0.57 step gives a timeseries model the sources of its training
    /// definition, and every other model an empty `trained_sources`. A rerun
    /// changes nothing.
    #[test]
    fn migration_from_v0_56_adds_trained_sources() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_states_db(&db_path, crate::tables::MAP_NAMES);
        write_version(data_dir.path(), "0.56.0");
        write_version(backup_dir.path(), "0.56.0");

        let model = |id: u32, name: &str, kind: &str| ModelV0_56 {
            id,
            name: name.to_string(),
            version: 1,
            kind: kind.to_string(),
            max_event_id_num: 10,
            classification_id: Some(1),
            event_kind: "conn".to_string(),
            customer_id: 1,
            instance: None,
            trained_at: chrono::Utc::now(),
            classifier_generation: 1,
            trained_run_id: 1,
            trained_definition: "eps = 5.0".to_string(),
            previous: None,
            clusters_applied: None,
        };
        let models = [
            model(0, "multi", "Multifield"),
            model(1, "series", "Timeseries"),
            model(2, "orphan-series", "Timeseries"),
        ];
        let entries: Entries = models
            .iter()
            .map(|model| {
                (
                    model.name.as_bytes().to_vec(),
                    bincode::DefaultOptions::new().serialize(model).unwrap(),
                )
            })
            .collect();
        put_entries(
            &db_path,
            crate::tables::MAP_NAMES,
            crate::tables::MODELS,
            &entries,
        );
        let definition = |name: &str, method: crate::ModelMethod, sources: &[&str]| {
            let definition = TrainingDefinitionV0_56 {
                name: name.to_string(),
                customer_id: 1,
                instance: None,
                method,
                event_kind: "conn".to_string(),
                sources: sources.iter().map(ToString::to_string).collect(),
                indicator: None,
                definition: "eps = 5.0".to_string(),
                cloning: false,
                last_run: Some(1),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            (
                name.as_bytes().to_vec(),
                bincode::DefaultOptions::new()
                    .serialize(&definition)
                    .unwrap(),
            )
        };
        put_entries(
            &db_path,
            crate::tables::MAP_NAMES,
            crate::tables::TRAINING_DEFINITIONS,
            &[
                definition("multi", crate::ModelMethod::Multidimension, &["piglet.a"]),
                definition("series", crate::ModelMethod::Timeseries, &["3", "5"]),
            ],
        );

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        let stored = |name: &str| {
            raw_value(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::MODELS,
                name.as_bytes(),
            )
            .unwrap()
        };
        let migrated = |name: &str| -> crate::tables::Model {
            bincode::DefaultOptions::new()
                .deserialize(&stored(name))
                .unwrap()
        };
        assert_eq!(
            migrated("multi"),
            models[0].clone().with_trained_sources(Vec::new())
        );
        assert_eq!(
            migrated("series"),
            models[1]
                .clone()
                .with_trained_sources(vec!["3".to_string(), "5".to_string()])
        );
        assert_eq!(
            migrated("orphan-series"),
            models[2].clone().with_trained_sources(Vec::new())
        );

        let snapshot: Vec<Vec<u8>> = models.iter().map(|m| stored(&m.name)).collect();
        migrate_0_56_to_0_57(data_dir.path()).unwrap();
        let after: Vec<Vec<u8>> = models.iter().map(|m| stored(&m.name)).collect();
        assert_eq!(after, snapshot);
    }

    /// The 0.58 step gives every engine instance row the detector id mark of
    /// its agent lookup key: the highest id of its applied and pending
    /// references, or 0. The hostname is the node's applied profile's, or its
    /// draft's when it has none; a row whose node has no hostname gets no
    /// mark. A rerun changes nothing.
    #[test]
    fn migration_from_v0_57_writes_detector_id_marks() {
        use crate::tables::EngineInstanceRow;
        use crate::{EngineDetectorRef, EngineDocumentRefs};

        let permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        let families_v0_57: Vec<&str> = crate::tables::MAP_NAMES
            .into_iter()
            .filter(|name| !FAMILIES_ADDED_BY_V0_58.contains(name))
            .collect();
        create_states_db(&db_path, families_v0_57.iter().copied());
        write_version(data_dir.path(), "0.57.0");
        write_version(backup_dir.path(), "0.57.0");

        let profile = |hostname: &str| NodeProfileV0_56 {
            customer_id: 1,
            description: String::new(),
            hostname: hostname.to_string(),
        };
        let node = |id: u32, applied: Option<&str>, draft: Option<&str>| NodeV0_56 {
            id,
            name: format!("node-{id}"),
            name_draft: None,
            profile: applied.map(profile),
            profile_draft: draft.map(profile),
            creation_time: chrono::Utc::now(),
            agents: vec!["reconverge".to_string()],
            external_services: Vec::new(),
        };
        let nodes = [
            node(0, Some("applied.example"), Some("draft.example")),
            node(1, None, Some("drafted.example")),
            node(2, None, None),
        ];
        // The index lets the store find each node by its id.
        let index = KeyIndexV0_56 {
            keys: nodes
                .iter()
                .map(|node| KeyIndexEntryV0_56::Key(node.name.as_bytes().to_vec()))
                .collect(),
            available: 3,
            inactive: None,
        };
        let mut entries: Entries = vec![(
            Vec::new(),
            bincode::DefaultOptions::new().serialize(&index).unwrap(),
        )];
        entries.extend(nodes.iter().map(|node| {
            (
                node.name.as_bytes().to_vec(),
                bincode::DefaultOptions::new().serialize(node).unwrap(),
            )
        }));
        put_entries(
            &db_path,
            families_v0_57.iter().copied(),
            crate::tables::NODES,
            &entries,
        );

        let refs = |ids: &[i32]| EngineDocumentRefs {
            detectors: ids
                .iter()
                .map(|id| EngineDetectorRef {
                    id: *id,
                    model: format!("m{id}"),
                    sources: vec!["sensor-a".to_string()],
                    indicator: None,
                })
                .collect(),
        };
        let status = crate::DetectorStatus {
            state: crate::DetectorState::Running,
            finished_at: None,
            outcome: None,
            reason: None,
            events: 3,
            sources: Vec::new(),
            reported_at: chrono::Utc::now(),
        };
        let row = |node_id: u32, agent_key: &str, row: &EngineInstanceRow| {
            (
                crate::tables::engine_instance_key(node_id, agent_key),
                bincode::DefaultOptions::new().serialize(row).unwrap(),
            )
        };
        put_entries(
            &db_path,
            families_v0_57.iter().copied(),
            crate::tables::ENGINE_INSTANCES,
            &[
                row(
                    0,
                    "reconverge",
                    &EngineInstanceRow {
                        stopped: true,
                        applied: refs(&[1, 4]),
                        pending: refs(&[1, 6]),
                        statuses: [(1, status)].into_iter().collect(),
                    },
                ),
                row(1, "reconverge", &EngineInstanceRow::default()),
                row(
                    2,
                    "reconverge",
                    &EngineInstanceRow {
                        pending: refs(&[2]),
                        ..EngineInstanceRow::default()
                    },
                ),
                row(
                    3,
                    "reconverge",
                    &EngineInstanceRow {
                        pending: refs(&[3]),
                        ..EngineInstanceRow::default()
                    },
                ),
            ],
        );

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        let marks = || -> Vec<(String, i32)> {
            let db = open_states_db(&db_path, crate::tables::MAP_NAMES);
            let cf = db.cf_handle(crate::tables::DETECTOR_ID_MARKS).unwrap();
            db.iterator_cf(&cf, rocksdb::IteratorMode::Start)
                .map(|entry| {
                    let (key, value) = entry.unwrap();
                    (
                        String::from_utf8(key.to_vec()).unwrap(),
                        bincode::DefaultOptions::new().deserialize(&value).unwrap(),
                    )
                })
                .collect()
        };
        let expected = vec![
            ("reconverge.applied.example".to_string(), 6),
            ("reconverge.drafted.example".to_string(), 0),
        ];
        assert_eq!(marks(), expected);

        // An interrupted chain runs the step again.
        migrate_0_57_to_0_58(data_dir.path()).unwrap();
        assert_eq!(marks(), expected);

        let test_schema = TestSchema::new_with_dir(permit, data_dir, backup_dir);
        let store = &test_schema.store;
        let state = |node_id: u32| {
            store
                .engine_instance_state(&crate::ModelInstance {
                    node_id,
                    agent_key: "reconverge".to_string(),
                })
                .unwrap()
        };
        let migrated = state(0);
        assert_eq!(migrated.last_detector_id, 6);
        assert!(migrated.stopped);
        assert_eq!(migrated.pending, refs(&[1, 6]));
        assert_eq!(
            store.detector_statuses(&migrated.instance).unwrap().len(),
            1
        );
        assert_eq!(state(1).last_detector_id, 0);
        assert_eq!(state(2).last_detector_id, 0);
    }

    /// The 0.59 step rewrites every customer deletion job stored as its
    /// service results alone into its service results, no periodic time
    /// series IDs and no abandoned hosts. A job already in the 0.59 layout is
    /// left as it is, and a rerun changes nothing.
    #[test]
    fn migration_from_v0_58_adds_job_lists() {
        use crate::{
            CustomerDataDeletionJob, CustomerDataDeletionService,
            CustomerDataDeletionServiceResult, CustomerDataDeletionStatus,
        };

        let permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_states_db(&db_path, crate::tables::MAP_NAMES);
        write_version(data_dir.path(), "0.58.0");
        write_version(backup_dir.path(), "0.58.0");

        let result = |service, host: &str, status| CustomerDataDeletionServiceResult {
            service,
            host_fqdns: vec![host.to_string()],
            status,
            requested_at: 10,
            completed_at: Some(20),
            error: None,
        };
        let old_results = vec![
            result(
                CustomerDataDeletionService::Review,
                "a.example",
                CustomerDataDeletionStatus::Succeeded,
            ),
            result(
                CustomerDataDeletionService::Sensor,
                "a.example",
                CustomerDataDeletionStatus::Failed,
            ),
        ];
        let current = CustomerDataDeletionJob {
            customer_id: 2,
            service_results: vec![result(
                CustomerDataDeletionService::Review,
                "b.example",
                CustomerDataDeletionStatus::InProgress,
            )],
            periodic_time_series_ids: vec!["3".to_string()],
            abandoned_hosts: vec!["b.example".to_string()],
        };
        let current_value = bincode::DefaultOptions::new()
            .serialize(&(
                &current.service_results,
                &current.periodic_time_series_ids,
                &current.abandoned_hosts,
            ))
            .unwrap();
        put_entries(
            &db_path,
            crate::tables::MAP_NAMES,
            crate::tables::CUSTOMER_DELETION_JOBS,
            &[
                (
                    1_u32.to_be_bytes().to_vec(),
                    bincode::DefaultOptions::new()
                        .serialize(&old_results)
                        .unwrap(),
                ),
                (current.customer_id.to_be_bytes().to_vec(), current_value),
            ],
        );

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();
        let jobs = || -> Entries {
            let db = open_states_db(&db_path, crate::tables::MAP_NAMES);
            all_entries(&db, crate::tables::CUSTOMER_DELETION_JOBS)
        };
        let migrated = jobs();

        // An interrupted chain runs the step again.
        migrate_0_58_to_0_59(data_dir.path()).unwrap();
        assert_eq!(jobs(), migrated);

        let test_schema = TestSchema::new_with_dir(permit, data_dir, backup_dir);
        let table = test_schema.store.customer_data_deletion_map();
        assert_eq!(
            table.get(1).unwrap(),
            Some(CustomerDataDeletionJob::new(1, old_results))
        );
        assert_eq!(table.get(current.customer_id).unwrap(), Some(current));
    }

    /// A customer deletion job matching neither the 0.59 nor the 0.58 layout
    /// fails the 0.59 step and is left as it is.
    #[test]
    fn migration_from_v0_58_rejects_a_job_matching_neither_layout() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_states_db(&db_path, crate::tables::MAP_NAMES);
        write_version(data_dir.path(), "0.58.0");
        write_version(backup_dir.path(), "0.58.0");
        put_entries(
            &db_path,
            crate::tables::MAP_NAMES,
            crate::tables::CUSTOMER_DELETION_JOBS,
            &[(1_u32.to_be_bytes().to_vec(), b"job-value".to_vec())],
        );

        let error = migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap_err();

        assert!(
            format!("{error:#}").contains("matches neither the 0.59 nor the 0.58 layout"),
            "{error:#}"
        );
        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            Version::parse("0.58.0").unwrap()
        );
        assert_current_cf_value(
            &db_path,
            crate::tables::CUSTOMER_DELETION_JOBS,
            &1_u32.to_be_bytes(),
            b"job-value",
        );
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
        assert_eq!(new_event.request, Vec::<String>::new());
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
        assert_eq!(new_event.request, Vec::<String>::new());
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
        assert_eq!(new_event.options, Vec::<(u8, Vec<u8>)>::new());
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
        assert_eq!(new_event.message, "");
        assert_eq!(new_event.renewal_time, 1800);
        assert_eq!(new_event.rebinding_time, 3150);
        assert_eq!(new_event.class_id, Vec::<u8>::new());
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

        use super::migration_structures::{ConfidenceV0_44, TriagePolicyV0_44, TriagePolicyV0_45};
        use crate::EventCategory;

        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("states.db");

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Create a database in the 0.44 layout and insert an old-format
        // triage policy
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(
                &opts,
                &db_path,
                super::MAP_NAMES_V0_43_TO_V0_46,
            )
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
            rocksdb::OptimisticTransactionDB::open_cf(
                &opts,
                &db_path,
                super::MAP_NAMES_V0_43_TO_V0_46,
            )
            .unwrap();
        let cf = db.cf_handle(crate::tables::TRIAGE_POLICY).unwrap();

        let migrated_bytes = db.get_cf(&cf, &key).unwrap().unwrap();
        let migrated: TriagePolicyV0_45 = bincode::DefaultOptions::new()
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

    /// Decodes the committed literal fixture of a stored triage policy as
    /// [`TriagePolicyV0_45`] and re-encodes it.
    ///
    /// The expected bytes come from the committed fixture, not from the
    /// serializer under test. `migrate_0_44_to_0_45` writes this layout, so
    /// the fixture pins the bytes that migration produces. The layout is
    /// frozen and the fixture is never regenerated. `creation_time` is pinned
    /// to `2024-03-15T10:30:45.123456789Z` so the encoding stays
    /// deterministic.
    #[test]
    fn triage_policy_v0_45_matches_literal_fixture() {
        use attrievent::attribute::RawEventKind;
        use chrono::{TimeZone, Utc};

        use super::migration_structures::TriagePolicyV0_45;
        use crate::{
            AttrCmpKind, Confidence, EventCategory, PacketAttr, Response, ResponseKind, ValueKind,
        };

        const FIXTURE_BYTES: &[u8] =
            include_bytes!("../tests/fixtures/triage_policy_literal_bytes.bin");

        let creation_time = Utc.with_ymd_and_hms(2024, 3, 15, 10, 30, 45).unwrap()
            + chrono::Duration::nanoseconds(123_456_789);
        let expected = TriagePolicyV0_45 {
            id: 42,
            name: "fixture-policy".to_string(),
            triage_exclusion_id: vec![1, 2],
            packet_attr: vec![PacketAttr {
                raw_event_kind: RawEventKind::Http,
                attr_name: "host".to_string(),
                value_kind: ValueKind::String,
                cmp_kind: AttrCmpKind::Contain,
                first_value: b"example.com".to_vec(),
                second_value: None,
                weight: Some(1.5),
            }],
            confidence: vec![
                Confidence {
                    threat_category: Some(EventCategory::Reconnaissance),
                    threat_kind: "port_scan".to_string(),
                    confidence: 0.85,
                    weight: Some(2.0),
                },
                Confidence {
                    threat_category: None,
                    threat_kind: "generic".to_string(),
                    confidence: 0.3,
                    weight: None,
                },
            ],
            response: vec![Response {
                minimum_score: 0.7,
                kind: ResponseKind::Manual,
            }],
            creation_time,
            customer_id: Some(1001),
        };

        let decoded: TriagePolicyV0_45 = bincode::DefaultOptions::new()
            .deserialize(FIXTURE_BYTES)
            .expect("fixture must decode");
        assert_eq!(decoded.id, expected.id);
        assert_eq!(decoded.name, expected.name);
        assert_eq!(decoded.triage_exclusion_id, expected.triage_exclusion_id);
        assert!(decoded.packet_attr == expected.packet_attr);
        assert_eq!(decoded.confidence, expected.confidence);
        assert!(decoded.response == expected.response);
        assert_eq!(decoded.creation_time, expected.creation_time);
        assert_eq!(decoded.customer_id, expected.customer_id);

        let encoded = bincode::DefaultOptions::new()
            .serialize(&expected)
            .expect("serializable");
        assert_eq!(encoded.as_slice(), FIXTURE_BYTES);
    }

    /// The idempotency keys of the rows [`operation_attempt_rows`] builds.
    const FAILED_OWING: &str = "op-failed-owing";
    const FAILED_DONE: &str = "op-failed-done";
    const SUCCEEDED: &str = "op-succeeded";
    const ROLLED_BACK: &str = "op-rolled-back";
    const CANCELLED: &str = "op-cancelled";
    const LIVE: &str = "op-live";
    const ONBOARD: &str = "op-onboard";

    /// The host and package the operation-attempt fixtures run on.
    const ATTEMPT_HOST: &str = "host-a.example";
    const ATTEMPT_TARGET: &str = "sensor";

    fn attempt_timestamp(secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(secs, 0).unwrap()
    }

    /// A non-terminal update on `(ATTEMPT_HOST, ATTEMPT_TARGET, instance)`.
    fn update_attempt(idempotency_key: &str, instance: u32) -> OperationAttempt {
        OperationAttempt {
            idempotency_key: idempotency_key.to_string(),
            host: ATTEMPT_HOST.to_string(),
            target: ATTEMPT_TARGET.to_string(),
            instance: Some(instance),
            action: OperationAction::Update,
            install_intent: None,
            config_template: None,
            package_digest: "sha256:aaa".to_string(),
            resolved_version: "1.2.3".to_string(),
            resolved_commit: "c0ffee".to_string(),
            phase: OperationPhase::Dispatched,
            cleanup_state: None,
            started_at: attempt_timestamp(1_700_000_000),
            retry_policy: OperationRetryPolicy {
                max_attempts: 5,
                attempts_made: 1,
                backoff_seconds: 30,
            },
            outcome: None,
            failure_kind: None,
            finalized_at: None,
            expires_at: attempt_timestamp(1_700_086_400),
            backup_id: Some(instance),
            pre_update_version: Some("0.47.0".to_string()),
        }
    }

    /// The same attempt, terminal with `outcome`: finalized where it owes
    /// nothing, and carrying `HostDiskSpace` where it failed, which the write
    /// path demands and the 0.47 layout cannot hold.
    fn terminated(mut attempt: OperationAttempt, outcome: OperationOutcome) -> OperationAttempt {
        attempt.phase = OperationPhase::Completed;
        attempt.outcome = Some(outcome);
        attempt.failure_kind =
            (outcome == OperationOutcome::Failed).then_some(OperationFailureKind::HostDiskSpace);
        if attempt.cleanup_state.is_none() {
            attempt.finalized_at = Some(attempt_timestamp(1_700_000_900));
        }
        attempt
    }

    /// One row in every state the 0.47→0.48 conversion tells apart: failed
    /// and still owing a teardown, failed and finalized, each other terminal
    /// outcome, non-terminal, and an onboarding owing its identity teardown.
    fn operation_attempt_rows() -> Vec<OperationAttempt> {
        let mut failed_owing = update_attempt(FAILED_OWING, 1);
        failed_owing.cleanup_state = Some(OperationCleanupState::PendingDeregister);
        let onboard = OperationAttempt {
            idempotency_key: ONBOARD.to_string(),
            host: "pending.example".to_string(),
            target: String::new(),
            instance: None,
            action: OperationAction::Onboard,
            install_intent: None,
            config_template: None,
            package_digest: String::new(),
            resolved_version: String::new(),
            resolved_commit: String::new(),
            phase: OperationPhase::Pending,
            cleanup_state: Some(OperationCleanupState::PendingIdentityTeardown),
            started_at: attempt_timestamp(1_700_000_200),
            retry_policy: OperationRetryPolicy {
                max_attempts: 1,
                attempts_made: 0,
                backoff_seconds: 0,
            },
            outcome: None,
            failure_kind: None,
            finalized_at: None,
            expires_at: attempt_timestamp(1_700_003_800),
            backup_id: None,
            pre_update_version: None,
        };
        vec![
            terminated(failed_owing, OperationOutcome::Failed),
            terminated(update_attempt(FAILED_DONE, 2), OperationOutcome::Failed),
            terminated(update_attempt(SUCCEEDED, 3), OperationOutcome::Succeeded),
            terminated(update_attempt(ROLLED_BACK, 4), OperationOutcome::RolledBack),
            terminated(update_attempt(CANCELLED, 5), OperationOutcome::Cancelled),
            update_attempt(LIVE, 6),
            onboard,
        ]
    }

    /// The 0.47 encoding of a value the live table wrote: the same fields,
    /// without the `failure_kind` and `config_template` 0.47 does not have.
    fn v0_47_encoding(live: &[u8]) -> Vec<u8> {
        let current: OperationAttemptValueV0_49 =
            bincode::DefaultOptions::new().deserialize(live).unwrap();
        let old = OperationAttemptValueV0_47 {
            host: current.host,
            target: current.target,
            instance: current.instance,
            action: current.action,
            install_intent: current.install_intent,
            package_digest: current.package_digest,
            resolved_version: current.resolved_version,
            resolved_commit: current.resolved_commit,
            phase: current.phase,
            cleanup_state: current.cleanup_state,
            started_at: current.started_at,
            retry_policy: current.retry_policy,
            outcome: current.outcome,
            finalized_at: current.finalized_at,
            expires_at: current.expires_at,
            backup_id: current.backup_id,
            pre_update_version: current.pre_update_version,
        };
        bincode::DefaultOptions::new().serialize(&old).unwrap()
    }

    /// The 0.47 encoding of `row`, built from its public fields rather than
    /// through the table, for a store that holds no live table to write it.
    fn v0_47_value(row: &OperationAttempt) -> Vec<u8> {
        let old = OperationAttemptValueV0_47 {
            host: row.host.clone(),
            target: row.target.clone(),
            instance: row.instance,
            action: row.action,
            install_intent: row.install_intent,
            package_digest: row.package_digest.clone(),
            resolved_version: row.resolved_version.clone(),
            resolved_commit: row.resolved_commit.clone(),
            phase: row.phase,
            cleanup_state: row.cleanup_state,
            started_at: row.started_at,
            retry_policy: row.retry_policy,
            outcome: row.outcome,
            finalized_at: row.finalized_at,
            expires_at: row.expires_at,
            backup_id: row.backup_id,
            pre_update_version: row.pre_update_version.clone(),
        };
        bincode::DefaultOptions::new().serialize(&old).unwrap()
    }

    /// Every entry of `cf_name`, in key order.
    fn all_entries(db: &rocksdb::OptimisticTransactionDB, cf_name: &str) -> Entries {
        let cf = db.cf_handle(cf_name).unwrap();
        db.iterator_cf(&cf, rocksdb::IteratorMode::Start)
            .map(|entry| {
                let (key, value) = entry.unwrap();
                (key.to_vec(), value.to_vec())
            })
            .collect()
    }

    /// Every entry of both operation-attempt families, the records, index
    /// entries and latest pointers alike.
    fn operation_attempt_families(db_path: &Path) -> (Entries, Entries) {
        let families = super::existing_map_names(&rocksdb::Options::default(), db_path).unwrap();
        let db = open_states_db(db_path, families.iter().map(String::as_str));
        (
            all_entries(&db, crate::tables::OPERATION_ATTEMPTS),
            all_entries(&db, crate::tables::OPERATION_ATTEMPT_LATEST),
        )
    }

    /// The index entries of the "operation attempts" family, at or above its
    /// reserved byte, and every latest pointer.
    fn operation_attempt_index_entries(db_path: &Path) -> (Entries, Entries) {
        let (attempts, latest) = operation_attempt_families(db_path);
        let indexes = attempts
            .into_iter()
            .filter(|(key, _)| {
                key.first()
                    .is_some_and(|lead| *lead >= super::OPERATION_ATTEMPT_RESERVED_V0_47)
            })
            .collect();
        (indexes, latest)
    }

    /// Writes `rows` through the live table, so every index entry and latest
    /// pointer is the one the table writes — and 0.47.0 wrote, since this
    /// change alters no key — then rewrites the record of each row not named
    /// in `keep_current` into the 0.47 layout and marks both directories
    /// `0.47.0`.
    fn operation_attempt_store_v0_47(
        data_dir: &Path,
        backup_dir: &Path,
        rows: &[OperationAttempt],
        keep_current: &[&str],
    ) {
        {
            let store = Store::new(data_dir, backup_dir, None).unwrap();
            let table = store.operation_attempt_map();
            for row in rows {
                table.upsert(row).unwrap();
            }
        }

        let db = open_states_db(&data_dir.join("states.db"), crate::tables::MAP_NAMES);
        let cf = db.cf_handle(crate::tables::OPERATION_ATTEMPTS).unwrap();
        for row in rows {
            if keep_current.contains(&row.idempotency_key.as_str()) {
                continue;
            }
            let key = row.idempotency_key.as_bytes();
            let live = db.get_cf(&cf, key).unwrap().unwrap();
            db.put_cf(&cf, key, v0_47_encoding(&live)).unwrap();
        }
        drop(db);
        write_version(data_dir, "0.47.0");
        write_version(backup_dir, "0.47.0");
    }

    /// The row as 0.48 reads it after the migration: `Other` where it failed,
    /// and no kind otherwise.
    fn migrated(mut row: OperationAttempt) -> OperationAttempt {
        row.failure_kind =
            (row.outcome == Some(OperationOutcome::Failed)).then_some(OperationFailureKind::Other);
        row
    }

    /// Decodes the committed fixture of one operation attempt as the released
    /// 0.47.0 layout stores it, and re-encodes it.
    ///
    /// The fixture was produced once, by the unmodified 0.47.0 `Value`, before
    /// `failure_kind` was added; the code that wrote it no longer exists, so
    /// it is never regenerated. It pins [`OperationAttemptValueV0_47`] to the
    /// release, and the 0.48 encoding of the same row to that one followed by
    /// the `failure_kind` bytes alone.
    #[test]
    fn operation_attempt_v0_47_matches_literal_fixture() {
        const FIXTURE_BYTES: &[u8] =
            include_bytes!("../tests/fixtures/operation_attempt_v0_47_literal.bin");

        let expected = OperationAttemptValueV0_47 {
            host: "host-a.example".to_string(),
            target: "sensor".to_string(),
            instance: Some(7),
            action: OperationAction::Install,
            install_intent: Some([0xab; 32]),
            package_digest: "sha256:0123456789abcdef".to_string(),
            resolved_version: "1.2.3".to_string(),
            resolved_commit: "c0ffee".to_string(),
            phase: OperationPhase::AwaitingReport,
            cleanup_state: Some(OperationCleanupState::PendingDeregister),
            started_at: chrono::DateTime::from_timestamp(1_700_000_000, 123_456_789).unwrap(),
            retry_policy: OperationRetryPolicy {
                max_attempts: 5,
                attempts_made: 2,
                backoff_seconds: 30,
            },
            outcome: Some(OperationOutcome::Failed),
            finalized_at: Some(
                chrono::DateTime::from_timestamp(1_700_000_500, 987_654_321).unwrap(),
            ),
            expires_at: chrono::DateTime::from_timestamp(1_700_086_400, 42).unwrap(),
            backup_id: Some(9),
            pre_update_version: Some("0.46.0".to_string()),
        };

        let decoded: OperationAttemptValueV0_47 = bincode::DefaultOptions::new()
            .deserialize(FIXTURE_BYTES)
            .unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(
            bincode::DefaultOptions::new().serialize(&decoded).unwrap(),
            FIXTURE_BYTES
        );
        // A 0.47 value is not a 0.48 one: it ends where `failure_kind` starts.
        assert!(
            bincode::DefaultOptions::new()
                .deserialize::<OperationAttemptValueV0_48>(FIXTURE_BYTES)
                .is_err()
        );

        // The conversion keeps every field and, the row having failed, gives
        // it `Other`: index 9 behind the `Some` tag. The 0.48 encoding is the
        // 0.47 one followed by those bytes and nothing else.
        let converted = OperationAttemptValueV0_48::from(decoded);
        assert_eq!(converted.failure_kind, Some(OperationFailureKind::Other));
        let encoded = bincode::DefaultOptions::new()
            .serialize(&converted)
            .unwrap();
        assert_eq!(encoded.strip_prefix(FIXTURE_BYTES), Some(&[1, 9][..]));
        // And a 0.48 value is not a 0.47 one: its trailing bytes are refused.
        assert!(
            bincode::DefaultOptions::new()
                .deserialize::<OperationAttemptValueV0_47>(&encoded)
                .is_err()
        );

        let mut without_kind = converted;
        without_kind.failure_kind = None;
        let encoded = bincode::DefaultOptions::new()
            .serialize(&without_kind)
            .unwrap();
        assert_eq!(encoded.strip_prefix(FIXTURE_BYTES), Some(&[0][..]));
    }

    /// The conversion gives `Other` to a failed attempt and no kind to any
    /// other, a non-terminal one included.
    #[test]
    fn operation_attempt_conversion_derives_the_kind_from_the_outcome() {
        let fixture: OperationAttemptValueV0_47 = bincode::DefaultOptions::new()
            .deserialize(include_bytes!(
                "../tests/fixtures/operation_attempt_v0_47_literal.bin"
            ))
            .unwrap();
        for (outcome, expected) in [
            (
                Some(OperationOutcome::Failed),
                Some(OperationFailureKind::Other),
            ),
            (Some(OperationOutcome::Succeeded), None),
            (Some(OperationOutcome::RolledBack), None),
            (Some(OperationOutcome::Cancelled), None),
            (None, None),
        ] {
            let mut old = fixture.clone();
            old.outcome = outcome;
            let converted = OperationAttemptValueV0_48::from(old.clone());
            assert_eq!(converted.failure_kind, expected, "{outcome:?}");
            assert_eq!(converted.outcome, outcome);
            assert_eq!(converted.host, old.host);
            assert_eq!(converted.pre_update_version, old.pre_update_version);
            // Every field but the kind is copied as it was.
            let mut encoded = bincode::DefaultOptions::new()
                .serialize(&converted)
                .unwrap();
            encoded.truncate(encoded.len() - if expected.is_some() { 2 } else { 1 });
            assert_eq!(
                encoded,
                bincode::DefaultOptions::new().serialize(&old).unwrap()
            );
        }
    }

    /// Pins the released 0.48 layout to a fixture produced once before
    /// `config_template` was added. The fixture is never regenerated.
    #[test]
    fn operation_attempt_v0_48_matches_literal_fixture() {
        const FIXTURE_BYTES: &[u8] =
            include_bytes!("../tests/fixtures/operation_attempt_v0_48_literal.bin");
        let old: OperationAttemptValueV0_47 = bincode::DefaultOptions::new()
            .deserialize(include_bytes!(
                "../tests/fixtures/operation_attempt_v0_47_literal.bin"
            ))
            .unwrap();
        let expected = OperationAttemptValueV0_48::from(old);
        let decoded: OperationAttemptValueV0_48 = bincode::DefaultOptions::new()
            .deserialize(FIXTURE_BYTES)
            .unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(
            bincode::DefaultOptions::new().serialize(&decoded).unwrap(),
            FIXTURE_BYTES
        );
        assert!(
            bincode::DefaultOptions::new()
                .deserialize::<OperationAttemptValueV0_49>(FIXTURE_BYTES)
                .is_err()
        );
        let converted = OperationAttemptValueV0_49::from(decoded);
        assert_eq!(converted.config_template, None);
        let encoded = bincode::DefaultOptions::new()
            .serialize(&converted)
            .unwrap();
        assert_eq!(encoded.strip_prefix(FIXTURE_BYTES), Some(&[0][..]));
        assert!(
            bincode::DefaultOptions::new()
                .deserialize::<OperationAttemptValueV0_48>(&encoded)
                .is_err()
        );
    }

    /// The released 0.48 encoding, removing only the final template field.
    fn v0_48_encoding(live: &[u8]) -> Vec<u8> {
        let current: OperationAttemptValueV0_49 =
            bincode::DefaultOptions::new().deserialize(live).unwrap();
        let old = OperationAttemptValueV0_48 {
            host: current.host,
            target: current.target,
            instance: current.instance,
            action: current.action,
            install_intent: current.install_intent,
            package_digest: current.package_digest,
            resolved_version: current.resolved_version,
            resolved_commit: current.resolved_commit,
            phase: current.phase,
            cleanup_state: current.cleanup_state,
            started_at: current.started_at,
            retry_policy: current.retry_policy,
            outcome: current.outcome,
            finalized_at: current.finalized_at,
            expires_at: current.expires_at,
            backup_id: current.backup_id,
            pre_update_version: current.pre_update_version,
            failure_kind: current.failure_kind,
        };
        bincode::DefaultOptions::new().serialize(&old).unwrap()
    }

    const INSTALL: &str = "9d5cb6e0-0a3f-41de-9f0a-6b0f4e5c1a27";

    /// Covers the existing states plus an install carrying a request digest.
    fn operation_attempt_rows_v0_48() -> Vec<OperationAttempt> {
        let mut rows = operation_attempt_rows();
        let mut install = update_attempt(INSTALL, 7);
        install.action = OperationAction::Install;
        install.install_intent = Some([0xab; 32]);
        rows.push(install);
        rows
    }

    /// Writes indexed live rows, replaces records outside `keep_current`
    /// with their released 0.48 encoding, and marks both directories 0.48.0.
    fn operation_attempt_store_v0_48(
        data_dir: &Path,
        backup_dir: &Path,
        rows: &[OperationAttempt],
        keep_current: &[&str],
    ) {
        {
            let store = Store::new(data_dir, backup_dir, None).unwrap();
            let table = store.operation_attempt_map();
            for row in rows {
                if row.action == OperationAction::Install {
                    table.create_or_resolve(row).unwrap();
                } else {
                    table.upsert(row).unwrap();
                }
            }
        }
        let db = open_states_db(&data_dir.join("states.db"), crate::tables::MAP_NAMES);
        let cf = db.cf_handle(crate::tables::OPERATION_ATTEMPTS).unwrap();
        for row in rows {
            if !keep_current.contains(&row.idempotency_key.as_str()) {
                let key = row.idempotency_key.as_bytes();
                let live = db.get_cf(&cf, key).unwrap().unwrap();
                db.put_cf(&cf, key, v0_48_encoding(&live)).unwrap();
            }
        }
        drop(db);
        write_version(data_dir, "0.48.0");
        write_version(backup_dir, "0.48.0");
    }

    #[test]
    fn migration_from_v0_47_records_a_failure_kind() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        let rows = operation_attempt_rows();
        operation_attempt_store_v0_47(data_dir.path(), backup_dir.path(), &rows, &[]);

        // Every record is now in the 0.47 layout, which 0.48 cannot read.
        let (records_before, _) = operation_attempt_families(&db_path);
        for (key, value) in &records_before {
            if key.first() < Some(&super::OPERATION_ATTEMPT_RESERVED_V0_47) {
                assert!(
                    bincode::DefaultOptions::new()
                        .deserialize::<OperationAttemptValueV0_47>(value)
                        .is_ok()
                );
            }
        }
        let indexes_before = operation_attempt_index_entries(&db_path);
        // An `expires_at` entry for each of the seven rows, a non-terminal one
        // for the live row and the onboarding, an owed-cleanup one for the
        // two owing a teardown, and a latest pointer for each finalized row.
        assert_eq!(indexes_before.0.len(), 7 + 2 + 2);
        assert_eq!(indexes_before.1.len(), 4);
        let other_families_before = {
            let db = open_states_db(&db_path, crate::tables::MAP_NAMES);
            let names = crate::tables::MAP_NAMES
                .iter()
                .filter(|name| {
                    **name != crate::tables::OPERATION_ATTEMPTS
                        && **name != crate::tables::OPERATION_ATTEMPT_LATEST
                })
                .collect::<Vec<_>>();
            names
                .into_iter()
                .map(|name| all_entries(&db, name))
                .collect::<Vec<_>>()
        };

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        let current = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current
        );
        // No index entry, latest pointer, other family or family name moved.
        assert_eq!(operation_attempt_index_entries(&db_path), indexes_before);
        {
            let db = open_states_db(&db_path, crate::tables::MAP_NAMES);
            let after = crate::tables::MAP_NAMES
                .iter()
                .filter(|name| {
                    **name != crate::tables::OPERATION_ATTEMPTS
                        && **name != crate::tables::OPERATION_ATTEMPT_LATEST
                })
                .map(|name| all_entries(&db, name))
                .collect::<Vec<_>>();
            assert_eq!(after, other_families_before);
        }
        let mut families = super::existing_map_names(&rocksdb::Options::default(), &db_path)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        families.sort_unstable();
        let mut expected_families = crate::tables::MAP_NAMES
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        expected_families.sort_unstable();
        assert_eq!(families, expected_families);

        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        let table = store.operation_attempt_map();
        for row in &rows {
            assert_eq!(
                table.get(&row.idempotency_key).unwrap(),
                Some(migrated(row.clone())),
                "{}",
                row.idempotency_key
            );
        }
        assert_eq!(
            table.get(FAILED_OWING).unwrap().unwrap().failure_kind,
            Some(OperationFailureKind::Other)
        );
        assert_eq!(
            table.get(FAILED_DONE).unwrap().unwrap().failure_kind,
            Some(OperationFailureKind::Other)
        );

        // The failed attempt that still owed a teardown can be discharged,
        // carrying the kind the migration gave it.
        let mut discharged = table.get(FAILED_OWING).unwrap().unwrap();
        discharged.cleanup_state = None;
        discharged.finalized_at = Some(attempt_timestamp(1_700_001_000));
        table.upsert(&discharged).unwrap();
        assert_eq!(
            table
                .attempt_owing_cleanup(ATTEMPT_TARGET, ATTEMPT_HOST, Some(1))
                .unwrap(),
            None
        );
        let latest = table
            .latest_attempt(ATTEMPT_HOST, ATTEMPT_TARGET, Some(1))
            .unwrap()
            .unwrap();
        assert_eq!(latest, discharged);
        assert_eq!(latest.failure_kind, Some(OperationFailureKind::Other));
    }

    #[test]
    fn migration_from_v0_47_is_rerun_safe() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        operation_attempt_store_v0_47(
            data_dir.path(),
            backup_dir.path(),
            &operation_attempt_rows(),
            &[],
        );
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        let migrated_store = operation_attempt_families(&db_path);
        super::migrate_0_47_to_0_48(data_dir.path()).unwrap();
        assert_eq!(operation_attempt_families(&db_path), migrated_store);
    }

    #[test]
    fn migration_from_a_partly_migrated_v0_47_store_rewrites_only_old_rows() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        let rows = operation_attempt_rows();
        // A run interrupted after converting these two left them in the 0.49
        // layout, the failed one with a kind other than `Other`, and the
        // markers at `0.47.0`.
        let already = [FAILED_OWING, SUCCEEDED];
        operation_attempt_store_v0_47(data_dir.path(), backup_dir.path(), &rows, &already);
        let (before, _) = operation_attempt_families(&db_path);

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        let (after, _) = operation_attempt_families(&db_path);
        assert_eq!(after.len(), before.len());
        for ((key, old), (new_key, new)) in before.iter().zip(&after) {
            assert_eq!(key, new_key);
            let untouched = key.first() >= Some(&super::OPERATION_ATTEMPT_RESERVED_V0_47)
                || already.iter().any(|name| name.as_bytes() == key.as_slice());
            assert_eq!(old == new, untouched, "{}", String::from_utf8_lossy(key));
        }

        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        let table = store.operation_attempt_map();
        for row in rows {
            let expected = if already.contains(&row.idempotency_key.as_str()) {
                row.clone()
            } else {
                migrated(row.clone())
            };
            assert_eq!(table.get(&row.idempotency_key).unwrap(), Some(expected));
        }
        assert_eq!(
            table.get(FAILED_OWING).unwrap().unwrap().failure_kind,
            Some(OperationFailureKind::HostDiskSpace)
        );
    }

    #[test]
    fn migration_from_v0_48_records_no_template() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        let rows = operation_attempt_rows_v0_48();
        operation_attempt_store_v0_48(data_dir.path(), backup_dir.path(), &rows, &[]);
        // Populate an unrelated family so its preservation is not vacuous.
        put_entries(
            &db_path,
            crate::tables::MAP_NAMES,
            crate::tables::NETWORKS,
            &[(b"unrelated-key".to_vec(), FOREIGN_VALUE.to_vec())],
        );

        // Every record is now in the 0.48 layout, which 0.49 cannot read.
        let (records_before, _) = operation_attempt_families(&db_path);
        for (key, value) in &records_before {
            if key.first() < Some(&super::OPERATION_ATTEMPT_RESERVED_V0_48) {
                assert!(
                    bincode::DefaultOptions::new()
                        .deserialize::<OperationAttemptValueV0_48>(value)
                        .is_ok()
                );
            }
        }
        let indexes_before = operation_attempt_index_entries(&db_path);
        // An `expires_at` entry for each of the eight rows, a non-terminal one
        // for the live row, install and onboarding, an owed-cleanup one for the
        // two owing a teardown, and a latest pointer for each finalized row.
        assert_eq!(indexes_before.0.len(), 8 + 3 + 2);
        assert_eq!(indexes_before.1.len(), 4);
        let other_families_before = {
            let db = open_states_db(&db_path, crate::tables::MAP_NAMES);
            let names = crate::tables::MAP_NAMES
                .iter()
                .filter(|name| {
                    **name != crate::tables::OPERATION_ATTEMPTS
                        && **name != crate::tables::OPERATION_ATTEMPT_LATEST
                })
                .collect::<Vec<_>>();
            names
                .into_iter()
                .map(|name| all_entries(&db, name))
                .collect::<Vec<_>>()
        };

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        let current = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            current
        );
        // No index entry, latest pointer, other family or family name moved.
        assert_eq!(operation_attempt_index_entries(&db_path), indexes_before);
        {
            let db = open_states_db(&db_path, crate::tables::MAP_NAMES);
            let after = crate::tables::MAP_NAMES
                .iter()
                .filter(|name| {
                    **name != crate::tables::OPERATION_ATTEMPTS
                        && **name != crate::tables::OPERATION_ATTEMPT_LATEST
                })
                .map(|name| all_entries(&db, name))
                .collect::<Vec<_>>();
            assert_eq!(after, other_families_before);
        }
        let mut families = super::existing_map_names(&rocksdb::Options::default(), &db_path)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        families.sort_unstable();
        let mut expected_families = crate::tables::MAP_NAMES
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        expected_families.sort_unstable();
        assert_eq!(families, expected_families);

        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        let table = store.operation_attempt_map();
        for row in &rows {
            assert_eq!(
                table
                    .get(&row.idempotency_key)
                    .unwrap()
                    .unwrap()
                    .config_template,
                None
            );
            assert_eq!(
                table.get(&row.idempotency_key).unwrap(),
                Some(row.clone()),
                "{}",
                row.idempotency_key
            );
        }
        assert_eq!(
            table.get(FAILED_OWING).unwrap().unwrap().failure_kind,
            Some(OperationFailureKind::HostDiskSpace)
        );
        assert_eq!(
            table.get(FAILED_DONE).unwrap().unwrap().failure_kind,
            Some(OperationFailureKind::HostDiskSpace)
        );

        // The failed attempt that still owes a teardown remains dischargeable.
        let mut discharged = table.get(FAILED_OWING).unwrap().unwrap();
        discharged.cleanup_state = None;
        discharged.finalized_at = Some(attempt_timestamp(1_700_001_000));
        table.upsert(&discharged).unwrap();
        assert_eq!(
            table
                .attempt_owing_cleanup(ATTEMPT_TARGET, ATTEMPT_HOST, Some(1))
                .unwrap(),
            None
        );
        let latest = table
            .latest_attempt(ATTEMPT_HOST, ATTEMPT_TARGET, Some(1))
            .unwrap()
            .unwrap();
        assert_eq!(latest, discharged);
        assert_eq!(
            latest.failure_kind,
            Some(OperationFailureKind::HostDiskSpace)
        );
    }

    #[test]
    fn migration_from_v0_48_is_rerun_safe() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        operation_attempt_store_v0_48(
            data_dir.path(),
            backup_dir.path(),
            &operation_attempt_rows_v0_48(),
            &[],
        );
        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        let migrated_store = operation_attempt_families(&db_path);
        super::migrate_0_48_to_0_49(data_dir.path()).unwrap();
        assert_eq!(operation_attempt_families(&db_path), migrated_store);
    }

    #[test]
    fn migration_from_a_partly_migrated_v0_48_store_rewrites_only_old_rows() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        let mut rows = operation_attempt_rows_v0_48();
        rows.iter_mut()
            .find(|row| row.idempotency_key == INSTALL)
            .unwrap()
            .config_template = Some("baseline".to_string());
        // A run interrupted after converting these rows left them in the 0.49
        // layout, the failed one with a kind other than `Other`, and the
        // markers at `0.48.0`.
        let already = [FAILED_OWING, SUCCEEDED, INSTALL];
        operation_attempt_store_v0_48(data_dir.path(), backup_dir.path(), &rows, &already);
        let (before, _) = operation_attempt_families(&db_path);

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        let (after, _) = operation_attempt_families(&db_path);
        assert_eq!(after.len(), before.len());
        for ((key, old), (new_key, new)) in before.iter().zip(&after) {
            assert_eq!(key, new_key);
            let untouched = key.first() >= Some(&super::OPERATION_ATTEMPT_RESERVED_V0_48)
                || already.iter().any(|name| name.as_bytes() == key.as_slice());
            assert_eq!(old == new, untouched, "{}", String::from_utf8_lossy(key));
        }

        let store = Store::new(data_dir.path(), backup_dir.path(), None).unwrap();
        let table = store.operation_attempt_map();
        for row in rows {
            let expected = row.clone();
            assert_eq!(table.get(&row.idempotency_key).unwrap(), Some(expected));
        }
        assert_eq!(
            table.get(FAILED_OWING).unwrap().unwrap().failure_kind,
            Some(OperationFailureKind::HostDiskSpace)
        );
    }

    #[test]
    fn migration_from_v0_47_rejects_an_operation_attempt_matching_neither_layout() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_states_db(&db_path, crate::tables::MAP_NAMES);
        let key = b"op-foreign".to_vec();
        put_entries(
            &db_path,
            crate::tables::MAP_NAMES,
            crate::tables::OPERATION_ATTEMPTS,
            &[(key.clone(), FOREIGN_VALUE.to_vec())],
        );
        write_version(data_dir.path(), "0.47.0");
        write_version(backup_dir.path(), "0.47.0");

        let error = migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("operation attempt"), "{message}");
        assert!(
            message.contains(&data_encoding::HEXLOWER.encode(&key)),
            "{message}"
        );
        assert!(message.contains("current schema error"), "{message}");
        assert!(
            message.contains("previous schema error (0.47)"),
            "{message}"
        );

        let marker = Version::parse("0.47.0").unwrap();
        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            marker
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            marker
        );
        assert_eq!(
            raw_value(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::OPERATION_ATTEMPTS,
                &key
            ),
            Some(FOREIGN_VALUE.to_vec()),
            "the unreadable value must be left as it was"
        );
    }

    /// A store with no operation attempts at all has nothing for the step to
    /// do, and reaches the current format.
    #[test]
    fn migration_from_v0_47_without_operation_attempts() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_states_db(&db_path, crate::tables::MAP_NAMES);
        write_version(data_dir.path(), "0.47.0");
        write_version(backup_dir.path(), "0.47.0");

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            Version::parse(DATABASE_FORMAT_VERSION).unwrap()
        );
        assert_eq!(
            operation_attempt_families(&db_path),
            (Vec::new(), Vec::new())
        );
    }
    #[test]
    fn migration_from_v0_48_rejects_an_operation_attempt_matching_neither_layout() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_states_db(&db_path, crate::tables::MAP_NAMES);
        let key = b"op-foreign".to_vec();
        put_entries(
            &db_path,
            crate::tables::MAP_NAMES,
            crate::tables::OPERATION_ATTEMPTS,
            &[(key.clone(), FOREIGN_VALUE.to_vec())],
        );
        write_version(data_dir.path(), "0.48.0");
        write_version(backup_dir.path(), "0.48.0");

        let error = migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("operation attempt"), "{message}");
        assert!(
            message.contains(&data_encoding::HEXLOWER.encode(&key)),
            "{message}"
        );
        assert!(message.contains("current schema error"), "{message}");
        assert!(
            message.contains("previous schema error (0.48)"),
            "{message}"
        );

        let marker = Version::parse("0.48.0").unwrap();
        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            marker
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            marker
        );
        assert_eq!(
            raw_value(
                &db_path,
                crate::tables::MAP_NAMES,
                crate::tables::OPERATION_ATTEMPTS,
                &key
            ),
            Some(FOREIGN_VALUE.to_vec()),
            "the unreadable value must be left as it was"
        );
    }

    /// A store with no operation attempts at all has nothing for the step to
    /// do, and reaches the current format.
    #[test]
    fn migration_from_v0_48_without_operation_attempts() {
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let db_path = data_dir.path().join("states.db");
        create_states_db(&db_path, crate::tables::MAP_NAMES);
        write_version(data_dir.path(), "0.48.0");
        write_version(backup_dir.path(), "0.48.0");

        migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();

        assert_eq!(
            read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            Version::parse(DATABASE_FORMAT_VERSION).unwrap()
        );
        assert_eq!(
            read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
            Version::parse(DATABASE_FORMAT_VERSION).unwrap()
        );
        assert_eq!(
            operation_attempt_families(&db_path),
            (Vec::new(), Vec::new())
        );
    }

    #[test]
    fn migration_from_v0_47_resumes_after_an_interrupted_0_49_step() {
        let _permit = acquire_db_permit();
        let rows = operation_attempt_rows();
        let clean_data = tempfile::tempdir().unwrap();
        let clean_backup = tempfile::tempdir().unwrap();
        operation_attempt_store_v0_47(clean_data.path(), clean_backup.path(), &rows, &[]);
        migrate_data_dir(clean_data.path(), clean_backup.path(), None).unwrap();
        let expected = operation_attempt_families(&clean_data.path().join("states.db"));

        for partly in [false, true] {
            let data_dir = tempfile::tempdir().unwrap();
            let backup_dir = tempfile::tempdir().unwrap();
            operation_attempt_store_v0_47(data_dir.path(), backup_dir.path(), &rows, &[]);
            super::migrate_0_47_to_0_48(data_dir.path()).unwrap();
            if partly {
                let db =
                    open_states_db(&data_dir.path().join("states.db"), crate::tables::MAP_NAMES);
                let cf = db.cf_handle(crate::tables::OPERATION_ATTEMPTS).unwrap();
                for row in rows.iter().take(2) {
                    let key = row.idempotency_key.as_bytes();
                    let old: OperationAttemptValueV0_48 = bincode::DefaultOptions::new()
                        .deserialize(&db.get_cf(&cf, key).unwrap().unwrap())
                        .unwrap();
                    let new = bincode::DefaultOptions::new()
                        .serialize(&OperationAttemptValueV0_49::from(old))
                        .unwrap();
                    db.put_cf(&cf, key, new).unwrap();
                }
            } else {
                super::migrate_0_48_to_0_49(data_dir.path()).unwrap();
            }
            assert_eq!(
                read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
                Version::parse("0.47.0").unwrap()
            );
            migrate_data_dir(data_dir.path(), backup_dir.path(), None).unwrap();
            let current = Version::parse(DATABASE_FORMAT_VERSION).unwrap();
            assert_eq!(
                read_version_file(&data_dir.path().join(VERSION_FILE_NAME)).unwrap(),
                current
            );
            assert_eq!(
                read_version_file(&backup_dir.path().join(VERSION_FILE_NAME)).unwrap(),
                current
            );
            assert_eq!(
                operation_attempt_families(&data_dir.path().join("states.db")),
                expected
            );
        }
    }
}
