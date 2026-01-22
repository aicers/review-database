//! Routines to check the database format version and migrate it if necessary.
#![allow(clippy::too_many_lines)]
mod migration_structures;

use std::{
    fs::{File, create_dir_all},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use bincode::Options;
use semver::{Version, VersionReq};
use tracing::info;

use crate::{
    AllowNetwork, BlockNetwork, Customer,
    event::{EventKind, HttpThreatFields},
    migration::migration_structures::{
        AllowNetworkV0_42, BlockNetworkV0_42, HttpThreatFieldsV0_43,
    },
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
const COMPATIBLE_VERSION_REQ: &str = ">=0.44.0-alpha.2,<0.44.0-alpha.3";

/// Migrates the data directory to the up-to-date format if necessary.
///
/// Migration is supported between released versions only. The prelease versions (alpha, beta,
/// etc.) should be assumed to be incompatible with each other.
///
/// # Errors
///
/// Returns an error if the data directory doesn't exist and cannot be created,
/// or if the data directory exists but is in the format incompatible with the
/// current version.
pub fn migrate_data_dir<P: AsRef<Path>>(data_dir: P, backup_dir: P) -> Result<()> {
    type Migration = (VersionReq, Version, fn(&Path) -> anyhow::Result<()>);

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
            VersionReq::parse(">=0.43.0,<0.44.0-alpha.2")?,
            Version::parse("0.44.0-alpha.2")?,
            migrate_0_43_to_0_44,
        ),
    ];

    while let Some((_req, to, m)) = migration
        .iter()
        .find(|(req, _to, _m)| req.matches(&version))
    {
        info!("Migrating database to {to}");
        m(data_dir)?;
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

fn migrate_0_42_to_0_43(data_dir: &Path) -> Result<()> {
    let db_path = data_dir.join("states.db");

    // Step 1: Drop "account policy" column family if it exists (from 0.42)
    migrate_drop_account_policy(&db_path)?;

    // Step 2: Rename "TI database" to "label database"
    migrate_rename_tidb_to_label_db(&db_path)?;

    // Step 3: Migrate AllowNetwork and BlockNetwork to customer-specific format
    migrate_customer_specific_networks(&db_path)?;

    Ok(())
}

fn migrate_0_43_to_0_44(data_dir: &Path) -> Result<()> {
    // Migrate network tags to customer-scoped format
    migrate_network_tags_to_customer_scoped(data_dir)?;

    // Migrate Network table to enforce global name uniqueness
    migrate_network_cf(data_dir)?;

    // Migrate HttpThreat events with cluster_id from Option<usize> to Option<u32>
    // Note: Cluster and TimeSeries table migrations are not needed because the
    // big-endian byte representation is identical between i32 and u32 for non-negative
    // values, and the unsupervised engine never produces negative cluster_id values.
    // Other event types (ExtraThreat, WindowsThreat, NetworkThreat) are not generated
    // on production servers, so only HttpThreat migration is needed.
    migrate_http_threat_events(data_dir)?;

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

/// Migrates the Network table from 0.43 to 0.44.
///
/// This migration:
/// 1. Reads all existing Network entries (old format: key = name + id, value without id)
/// 2. Deduplicates by name, keeping only the entry with the smallest id
/// 3. Clears the network column family
/// 4. Re-inserts networks with new format: key = name only, value contains id (no `customer_ids`)
fn migrate_network_cf(data_dir: &Path) -> Result<()> {
    use crate::tables::MAP_NAMES;

    let db_path = data_dir.join("states.db");

    info!("Migrating Network table to enforce global name uniqueness");

    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);

    migrate_network_cf_inner(&db_path, &opts, &MAP_NAMES)?;

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

/// Migrates `HttpThreat` events with `cluster_id` from `Option<usize>` to `Option<u32>`.
///
/// This migration handles the serialization change for `HttpThreat` events.
/// The serialization of `Option<usize>` differs from `Option<u32>` in bincode because
/// `usize` is architecture-dependent (8 bytes on 64-bit systems) while `u32` is 4 bytes.
///
/// Note: Other event types (`ExtraThreat`, `WindowsThreat`, `NetworkThreat`) are not generated
/// on production servers, so their migration is unnecessary.
fn migrate_http_threat_events(dir: &Path) -> Result<()> {
    use num_traits::FromPrimitive;

    let db_path = dir.join("states.db");

    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);

    let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
        rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
            .context("Failed to open database for HttpThreat event migration")?;

    // Events are stored in the default column family
    let mut migrated_count = 0usize;
    let mut entries_to_update: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut errors = 0usize;

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

        // Try to convert to EventKind
        let Some(event_kind) = EventKind::from_i32(event_kind_val) else {
            continue;
        };

        // Only migrate HttpThreat events
        if event_kind == EventKind::HttpThreat {
            if let Some(new_val) = migrate_http_threat_fields(&value) {
                entries_to_update.push((key.to_vec(), new_val));
                migrated_count += 1;
            } else {
                // If we couldn't migrate, it might already be in the new format
                // or there was an error. We'll count it but not fail the migration.
                errors += 1;
            }
        }
    }

    if !entries_to_update.is_empty() {
        let txn = db.transaction();
        for (key, new_value) in &entries_to_update {
            txn.put(key, new_value)?;
        }
        txn.commit()
            .context("failed to commit HttpThreat event migration")?;
    }

    if errors > 0 {
        info!(
            "HttpThreat event migration: migrated {} events, {} events skipped (possibly already migrated)",
            migrated_count, errors
        );
    } else {
        info!(
            "Migrated {} HttpThreat events with cluster_id type change",
            migrated_count
        );
    }

    Ok(())
}

/// Migrates `HttpThreatFields` from Option<usize> to Option<u32> for `cluster_id`.
fn migrate_http_threat_fields(value: &[u8]) -> Option<Vec<u8>> {
    // Try to deserialize with old format
    let old: HttpThreatFieldsV0_43 = bincode::DefaultOptions::new().deserialize(value).ok()?;

    // Convert to new format
    let new = HttpThreatFields {
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

    bincode::DefaultOptions::new().serialize(&new).ok()
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
    use std::io::Write;
    use std::path::Path;

    use semver::{Version, VersionReq};

    use super::{COMPATIBLE_VERSION_REQ, create_version_file, migrate_data_dir, read_version_file};
    use crate::tables::NETWORK_TAGS;
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Indexable, Store};

    /// Helper to write a specific version to a VERSION file.
    fn write_version(path: &Path, version: &str) {
        let version_file = path.join("VERSION");
        let mut f = std::fs::File::create(&version_file).unwrap();
        f.write_all(version.as_bytes()).unwrap();
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
        let result = migrate_data_dir(data_dir.path(), backup_dir.path());
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

        let result = migrate_data_dir(data_dir.path(), backup_dir.path());

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

        let result = migrate_data_dir(data_dir.path(), backup_dir.path());

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

        let result = migrate_data_dir(data_dir.path(), backup_dir.path());

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

        let result = migrate_data_dir(&data_dir, &backup_dir);

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

        let result = migrate_data_dir(data_dir.path(), backup_dir.path());

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
        create_version_file(&version_path).unwrap();

        // Read it back
        let version = read_version_file(&version_path).unwrap();
        assert_eq!(version, Version::parse(env!("CARGO_PKG_VERSION")).unwrap());
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

            let result = migrate_data_dir(data_dir.path(), backup_dir.path());
            assert!(result.is_ok(), "Migration should succeed from {version}");

            let data_version = read_version_file(&data_dir.path().join("VERSION")).unwrap();
            let backup_version = read_version_file(&backup_dir.path().join("VERSION")).unwrap();
            assert_eq!(data_version, current_pkg_version);
            assert_eq!(backup_version, current_pkg_version);
        }
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

        // Write an old version that needs migration
        write_version(data_dir.path(), "0.42.0");
        write_version(backup_dir.path(), "0.42.0");

        // Run the migration
        let result = migrate_data_dir(data_dir.path(), backup_dir.path());
        assert!(result.is_ok(), "Migration should succeed");

        // Verify database opens with the current column families
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();
        assert!(db.cf_handle("label database").is_some());
        assert!(db.cf_handle("TI database").is_none());
        drop(db);

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
}
