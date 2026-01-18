//! Routines to check the database format version and migrate it if necessary.
#![allow(clippy::too_many_lines)]
mod migration_structures;

use std::{
    fs::{File, create_dir_all},
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use bincode::Options;
use semver::{Version, VersionReq};
use tracing::info;

use crate::{
    AllowNetwork, BlockNetwork, Customer, EventKind,
    migration::migration_structures::{AllowNetworkV0_42, BlockNetworkV0_42},
    tables::NETWORK_TAGS,
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
const COMPATIBLE_VERSION_REQ: &str = ">=0.44.0-alpha.1,<0.44.0-alpha.2";

/// Migrates the data directory to the up-to-date format if necessary.
///
/// Migration is supported between released versions only. The prelease versions (alpha, beta,
/// etc.) should be assumed to be incompatible with each other.
///
/// # Arguments
///
/// * `data_dir` - Path to the data directory containing the database
/// * `backup_dir` - Path to the backup directory
/// * `locator` - Optional IP geolocation database for resolving country codes during migration.
///   If `None`, country code fields will be set to "ZZ" (unknown) for migrated records.
///
/// # Errors
///
/// Returns an error if the data directory doesn't exist and cannot be created,
/// or if the data directory exists but is in the format incompatible with the
/// current version.
pub fn migrate_data_dir<P: AsRef<Path>>(
    data_dir: P,
    backup_dir: P,
    locator: Option<&ip2location::DB>,
) -> Result<()> {
    type Migration = (
        VersionReq,
        Version,
        fn(&Path, &Path, Option<&ip2location::DB>) -> anyhow::Result<()>,
    );

    let data_dir = data_dir.as_ref();
    let backup_dir = backup_dir.as_ref();

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
            migrate_0_42_to_0_43,
        ),
        (
            VersionReq::parse(">=0.43.0,<0.44.0-alpha.1")?,
            Version::parse("0.44.0-alpha.1")?,
            migrate_0_43_to_0_44,
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
            create_version_file(&backup).context("failed to update VERSION")?;
            return create_version_file(&data).context("failed to update VERSION");
        }
    }

    Err(anyhow!("migration from {version} is not supported",))
}

/// Column family names for version 0.42 (includes the deprecated "account policy" column family)
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

/// Returns column family names from 0.42 without "account policy".
fn map_names_v0_42_without_account_policy() -> Vec<&'static str> {
    MAP_NAMES_V0_42
        .iter()
        .copied()
        .filter(|name| *name != "account policy")
        .collect()
}

fn migrate_0_42_to_0_43(
    data_dir: &Path,
    _backup_dir: &Path,
    _locator: Option<&ip2location::DB>,
) -> Result<()> {
    let db_path = data_dir.join("states.db");

    // Step 1: Drop "account policy" column family if it exists (from 0.42)
    migrate_drop_account_policy(&db_path)?;

    // Step 2: Rename "TI database" to "label database"
    migrate_rename_tidb_to_label_db(&db_path)?;

    // Step 3: Migrate AllowNetwork and BlockNetwork to customer-specific format
    migrate_customer_specific_networks(&db_path)?;

    Ok(())
}

fn migrate_0_43_to_0_44(
    data_dir: &Path,
    backup_dir: &Path,
    locator: Option<&ip2location::DB>,
) -> Result<()> {
    // Step 1: Migrate network tags to customer-scoped format
    // This requires direct database access for low-level meta column family operations
    migrate_network_tags_to_customer_scoped(data_dir)?;

    // Step 2: Migrate event fields to add country codes using Store abstraction
    let store = crate::Store::new(data_dir, backup_dir)
        .context("Failed to open Store for event migration")?;
    migrate_event_country_codes(&store, locator)?;

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

    // Try to open with MAP_NAMES_V0_42 (which includes "account policy")
    if let Ok(db) = rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, MAP_NAMES_V0_42) {
        info!("Dropping 'account policy' column family");
        db.drop_cf("account policy")
            .context("Failed to drop 'account policy' column family")?;
        drop(db);
    }
    // If the database doesn't have "account policy", it's already been dropped

    Ok(())
}

/// Renames the "TI database" column family to "label database" in the main database only
fn migrate_rename_tidb_to_label_db(db_path: &Path) -> Result<()> {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);

    // Process main database (without "account policy" which was already dropped)
    let cf_names = map_names_v0_42_without_account_policy();

    // First, read all data from "TI database" into memory
    let data = {
        let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, &cf_names)
                .context("Failed to open database for TI database read")?;

        // Check if "TI database" column family exists
        let Some(old_cf) = db.cf_handle("TI database") else {
            // Column family already renamed or doesn't exist
            return Ok(());
        };

        info!("Reading data from 'TI database' column family");

        // Collect all key-value pairs
        let iter = db.iterator_cf(old_cf, rocksdb::IteratorMode::Start);
        let data: Vec<(Vec<u8>, Vec<u8>)> = iter
            .map(|item| {
                let (key, value) = item.expect("Failed to iterate 'TI database'");
                (key.to_vec(), value.to_vec())
            })
            .collect();

        data
    };
    // db is dropped here

    // Now reopen, create new CF, write data, and drop old CF
    let mut db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, &cf_names)
            .context("Failed to reopen database for TI database rename")?;

    info!("Renaming 'TI database' column family to 'label database'");

    // Create the new "label database" column family
    let cf_opts = rocksdb::Options::default();
    db.create_cf("label database", &cf_opts)
        .context("Failed to create 'label database' column family")?;

    let new_cf = db
        .cf_handle("label database")
        .context("Failed to get 'label database' column family handle")?;

    // Write all data to "label database"
    for (key, value) in &data {
        db.put_cf(new_cf, key, value)
            .context("Failed to copy data to 'label database'")?;
    }

    // Drop the old "TI database" column family
    db.drop_cf("TI database")
        .context("Failed to drop 'TI database' column family")?;

    drop(db);

    info!("Successfully renamed 'TI database' to 'label database'");
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
    T: CustomerSpecificNetwork<K> + std::fmt::Debug,
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
    opts.create_missing_column_families(true);

    let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, crate::tables::MAP_NAMES)
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

    let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
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

/// Migrates event fields from `V0_43` format (without country codes) to `V0_44` format
/// (with country codes). If a locator is provided, country codes are resolved from
/// IP addresses. Otherwise, country codes are set to None.
fn migrate_event_country_codes(
    store: &crate::Store,
    locator: Option<&ip2location::DB>,
) -> Result<()> {
    use num_traits::FromPrimitive;

    use crate::migration::migration_structures::{
        BlocklistBootpFieldsV0_43, BlocklistConnFieldsV0_43, BlocklistDceRpcFieldsV0_43,
        BlocklistDhcpFieldsV0_43, BlocklistDnsFieldsV0_43, BlocklistKerberosFieldsV0_43,
        BlocklistMalformedDnsFieldsV0_43, BlocklistMqttFieldsV0_43, BlocklistNfsFieldsV0_43,
        BlocklistNtlmFieldsV0_43, BlocklistRadiusFieldsV0_43, BlocklistRdpFieldsV0_43,
        BlocklistSmbFieldsV0_43, BlocklistSmtpFieldsV0_43, BlocklistSshFieldsV0_43,
        BlocklistTlsFieldsV0_43, CryptocurrencyMiningPoolFieldsV0_43, DgaFieldsV0_43,
        DnsEventFieldsV0_43, ExternalDdosFieldsV0_43, FtpBruteForceFieldsV0_43,
        FtpEventFieldsV0_43, HttpEventFieldsV0_43, HttpThreatFieldsV0_43,
        LdapBruteForceFieldsV0_43, LdapEventFieldsV0_43, MultiHostPortScanFieldsV0_43,
        NetworkThreatV0_43, PortScanFieldsV0_43, RdpBruteForceFieldsV0_43,
        RepeatedHttpSessionsFieldsV0_43, UnusualDestinationPatternFieldsV0_43,
    };

    info!("Migrating event fields to add country codes");

    let events = store.events();

    // Collect all events that need migration using raw iterator
    let entries_to_migrate: Vec<(Vec<u8>, Vec<u8>)> = events
        .raw_iter()
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect();

    if entries_to_migrate.is_empty() {
        info!("No events to migrate");
        return Ok(());
    }

    info!("Found {} events to migrate", entries_to_migrate.len());

    let mut migrated_count = 0usize;
    let mut skipped_count = 0usize;

    for (key, value) in &entries_to_migrate {
        // Extract the event kind from the key (bits 32-63 of the 128-bit key)
        let kind_value = if key.len() >= 16 {
            let key_i128 = i128::from_be_bytes(key[..16].try_into().unwrap_or([0; 16]));
            ((key_i128 >> 32) & 0xFFFF_FFFF) as i32
        } else {
            skipped_count += 1;
            continue;
        };

        let Some(kind) = EventKind::from_i32(kind_value) else {
            skipped_count += 1;
            continue;
        };

        // Migrate the fields based on event kind
        // Events store raw field bytes directly (not EventMessage wrapper)
        let new_fields: Vec<u8> = match kind {
            EventKind::DnsCovertChannel | EventKind::LockyRansomware => {
                migrate_fields::<DnsEventFieldsV0_43, DnsEventFields>(value, locator)?
            }
            EventKind::HttpThreat => {
                migrate_fields::<HttpThreatFieldsV0_43, HttpThreatFields>(value, locator)?
            }
            EventKind::RdpBruteForce => {
                migrate_fields::<RdpBruteForceFieldsV0_43, RdpBruteForceFields>(value, locator)?
            }
            EventKind::RepeatedHttpSessions => migrate_fields::<
                RepeatedHttpSessionsFieldsV0_43,
                RepeatedHttpSessionsFields,
            >(value, locator)?,
            EventKind::TorConnection | EventKind::NonBrowser | EventKind::BlocklistHttp => {
                migrate_fields::<HttpEventFieldsV0_43, HttpEventFields>(value, locator)?
            }
            EventKind::TorConnectionConn | EventKind::BlocklistConn => {
                migrate_fields::<BlocklistConnFieldsV0_43, BlocklistConnFields>(value, locator)?
            }
            EventKind::DomainGenerationAlgorithm => {
                migrate_fields::<DgaFieldsV0_43, DgaFields>(value, locator)?
            }
            EventKind::FtpBruteForce => {
                migrate_fields::<FtpBruteForceFieldsV0_43, FtpBruteForceFields>(value, locator)?
            }
            EventKind::FtpPlainText | EventKind::BlocklistFtp => {
                migrate_fields::<FtpEventFieldsV0_43, FtpEventFields>(value, locator)?
            }
            EventKind::PortScan => {
                migrate_fields::<PortScanFieldsV0_43, PortScanFields>(value, locator)?
            }
            EventKind::MultiHostPortScan => migrate_fields::<
                MultiHostPortScanFieldsV0_43,
                MultiHostPortScanFields,
            >(value, locator)?,
            EventKind::ExternalDdos => {
                migrate_fields::<ExternalDdosFieldsV0_43, ExternalDdosFields>(value, locator)?
            }
            EventKind::LdapBruteForce => {
                migrate_fields::<LdapBruteForceFieldsV0_43, LdapBruteForceFields>(value, locator)?
            }
            EventKind::LdapPlainText | EventKind::BlocklistLdap => {
                migrate_fields::<LdapEventFieldsV0_43, LdapEventFields>(value, locator)?
            }
            EventKind::CryptocurrencyMiningPool => migrate_fields::<
                CryptocurrencyMiningPoolFieldsV0_43,
                CryptocurrencyMiningPoolFields,
            >(value, locator)?,
            EventKind::BlocklistBootp => {
                migrate_fields::<BlocklistBootpFieldsV0_43, BlocklistBootpFields>(value, locator)?
            }
            EventKind::BlocklistDceRpc => {
                migrate_fields::<BlocklistDceRpcFieldsV0_43, BlocklistDceRpcFields>(value, locator)?
            }
            EventKind::BlocklistDhcp => {
                migrate_fields::<BlocklistDhcpFieldsV0_43, BlocklistDhcpFields>(value, locator)?
            }
            EventKind::BlocklistDns => {
                migrate_fields::<BlocklistDnsFieldsV0_43, BlocklistDnsFields>(value, locator)?
            }
            EventKind::BlocklistKerberos => migrate_fields::<
                BlocklistKerberosFieldsV0_43,
                BlocklistKerberosFields,
            >(value, locator)?,
            EventKind::BlocklistMalformedDns => migrate_fields::<
                BlocklistMalformedDnsFieldsV0_43,
                BlocklistMalformedDnsFields,
            >(value, locator)?,
            EventKind::BlocklistMqtt => {
                migrate_fields::<BlocklistMqttFieldsV0_43, BlocklistMqttFields>(value, locator)?
            }
            EventKind::BlocklistNfs => {
                migrate_fields::<BlocklistNfsFieldsV0_43, BlocklistNfsFields>(value, locator)?
            }
            EventKind::BlocklistNtlm => {
                migrate_fields::<BlocklistNtlmFieldsV0_43, BlocklistNtlmFields>(value, locator)?
            }
            EventKind::BlocklistRadius => {
                migrate_fields::<BlocklistRadiusFieldsV0_43, BlocklistRadiusFields>(value, locator)?
            }
            EventKind::BlocklistRdp => {
                migrate_fields::<BlocklistRdpFieldsV0_43, BlocklistRdpFields>(value, locator)?
            }
            EventKind::BlocklistSmb => {
                migrate_fields::<BlocklistSmbFieldsV0_43, BlocklistSmbFields>(value, locator)?
            }
            EventKind::BlocklistSmtp => {
                migrate_fields::<BlocklistSmtpFieldsV0_43, BlocklistSmtpFields>(value, locator)?
            }
            EventKind::BlocklistSsh => {
                migrate_fields::<BlocklistSshFieldsV0_43, BlocklistSshFields>(value, locator)?
            }
            EventKind::BlocklistTls | EventKind::SuspiciousTlsTraffic => {
                migrate_fields::<BlocklistTlsFieldsV0_43, BlocklistTlsFields>(value, locator)?
            }
            EventKind::UnusualDestinationPattern => migrate_fields::<
                UnusualDestinationPatternFieldsV0_43,
                UnusualDestinationPatternFields,
            >(value, locator)?,
            EventKind::NetworkThreat => {
                migrate_fields::<NetworkThreatV0_43, NetworkThreat>(value, locator)?
            }
            // These event types don't have country code fields or use different structures
            EventKind::WindowsThreat | EventKind::ExtraThreat => {
                // Skip migration for these types - they don't have the standard
                // orig_addr/resp_addr fields or use different serialization
                skipped_count += 1;
                continue;
            }
        };

        // Update the event with migrated fields using raw_update
        events
            .raw_update(key, value, &new_fields)
            .context("failed to update migrated event")?;
        migrated_count += 1;
    }

    info!(
        "Successfully migrated {} events ({} skipped)",
        migrated_count, skipped_count
    );
    Ok(())
}

/// Trait for applying country code resolution to migrated event fields.
///
/// Types implementing this trait can have their country code fields populated
/// from IP addresses using an ip2location database.
trait ResolveCountryCodes {
    /// Resolves country codes from IP addresses using the provided locator.
    fn resolve_country_codes(&mut self, locator: &ip2location::DB);
}

/// Looks up the country code for an IP address using the ip2location database.
/// Returns the 2-letter country code as bytes, or "XX" if the lookup fails or
/// returns an invalid code.
fn lookup_country_code(locator: &ip2location::DB, addr: IpAddr) -> [u8; 2] {
    crate::util::country_code_to_bytes(&crate::util::find_ip_country(locator, addr))
}

// =============================================================================
// ResolveCountryCodes implementations for event field types
// =============================================================================

use crate::event::{
    BlocklistBootpFields, BlocklistConnFields, BlocklistDceRpcFields, BlocklistDhcpFields,
    BlocklistDnsFields, BlocklistKerberosFields, BlocklistMalformedDnsFields, BlocklistMqttFields,
    BlocklistNfsFields, BlocklistNtlmFields, BlocklistRadiusFields, BlocklistRdpFields,
    BlocklistSmbFields, BlocklistSmtpFields, BlocklistSshFields, BlocklistTlsFields,
    CryptocurrencyMiningPoolFields, DgaFields, DnsEventFields, ExternalDdosFields,
    FtpBruteForceFields, FtpEventFields, HttpEventFields, HttpThreatFields, LdapBruteForceFields,
    LdapEventFields, MultiHostPortScanFields, NetworkThreat, PortScanFields, RdpBruteForceFields,
    RepeatedHttpSessionsFields, UnusualDestinationPatternFields,
};

impl ResolveCountryCodes for PortScanFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for MultiHostPortScanFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_codes = self
            .resp_addrs
            .iter()
            .map(|addr| lookup_country_code(locator, *addr))
            .collect();
    }
}

impl ResolveCountryCodes for ExternalDdosFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_codes = self
            .orig_addrs
            .iter()
            .map(|addr| lookup_country_code(locator, *addr))
            .collect();
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for BlocklistConnFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for DnsEventFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for CryptocurrencyMiningPoolFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for BlocklistDnsFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for HttpEventFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for RepeatedHttpSessionsFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for HttpThreatFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for DgaFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for RdpBruteForceFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_codes = self
            .resp_addrs
            .iter()
            .map(|addr| lookup_country_code(locator, *addr))
            .collect();
    }
}

impl ResolveCountryCodes for BlocklistRdpFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for FtpBruteForceFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for FtpEventFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for LdapBruteForceFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for LdapEventFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for BlocklistSshFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for BlocklistTlsFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for BlocklistKerberosFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for BlocklistSmtpFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for BlocklistNfsFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for BlocklistDhcpFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for BlocklistDceRpcFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for BlocklistNtlmFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for BlocklistSmbFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for BlocklistMqttFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for BlocklistBootpFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for BlocklistRadiusFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for BlocklistMalformedDnsFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

impl ResolveCountryCodes for UnusualDestinationPatternFields {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.resp_country_codes = self
            .destination_ips
            .iter()
            .map(|addr| lookup_country_code(locator, *addr))
            .collect();
    }
}

impl ResolveCountryCodes for NetworkThreat {
    fn resolve_country_codes(&mut self, locator: &ip2location::DB) {
        self.orig_country_code = lookup_country_code(locator, self.orig_addr);
        self.resp_country_code = lookup_country_code(locator, self.resp_addr);
    }
}

/// Helper function to migrate event fields from old format to new format
fn migrate_fields<O, N>(old_data: &[u8], locator: Option<&ip2location::DB>) -> Result<Vec<u8>>
where
    O: serde::de::DeserializeOwned,
    N: serde::Serialize + serde::de::DeserializeOwned + From<O> + ResolveCountryCodes,
{
    // First try to deserialize as the new format (already migrated)
    if bincode::DefaultOptions::new()
        .deserialize::<N>(old_data)
        .is_ok()
    {
        // Already in new format, no migration needed
        return Ok(old_data.to_vec());
    }

    // Deserialize as old format and convert
    let old_fields: O = bincode::DefaultOptions::new()
        .deserialize(old_data)
        .context("failed to deserialize old event fields")?;

    let mut new_fields: N = old_fields.into();

    // Apply country code resolution if locator is provided
    if let Some(loc) = locator {
        new_fields.resolve_country_codes(loc);
    }

    bincode::DefaultOptions::new()
        .serialize(&new_fields)
        .context("failed to serialize new event fields")
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
    let file = path.join("VERSION");

    if !path.exists() {
        create_dir_all(path)?;
    }
    if path
        .read_dir()
        .context("cannot read data dir")?
        .next()
        .is_none()
    {
        create_version_file(&file)?;
    }

    let version = read_version_file(&file)?;
    Ok((file, version))
}

/// Creates the VERSION file in the data directory.
///
/// # Errors
///
/// Returns an error if the VERSION file cannot be created or written.
fn create_version_file(path: &Path) -> Result<()> {
    let mut f = File::create(path).context("cannot create VERSION")?;
    f.write_all(env!("CARGO_PKG_VERSION").as_bytes())
        .context("cannot write VERSION")?;
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

#[cfg(test)]
mod tests {
    use semver::{Version, VersionReq};

    use super::COMPATIBLE_VERSION_REQ;
    use crate::tables::NETWORK_TAGS;
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Indexable, Store};

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
            let store = Store::new(db_dir.path(), backup_dir.path()).unwrap();
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
            let store = Store::new(db_dir.path(), backup_dir.path()).unwrap();
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
    fn migrate_0_42_to_0_43_drops_account_policy_and_renames_tidb() {
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

        // Verify the column family has been dropped and renamed by opening with new list
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();

        // Verify "account policy" is dropped
        assert!(db.cf_handle("account policy").is_none());

        // Verify "TI database" is dropped
        assert!(db.cf_handle("TI database").is_none());

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
}
