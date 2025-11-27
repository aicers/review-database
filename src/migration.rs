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
    migration::migration_structures::{AllowNetworkV0_42, BlockNetworkV0_42},
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
const COMPATIBLE_VERSION_REQ: &str = ">=0.43.0-alpha.2,<0.43.0-alpha.3";

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
    type Migration = (VersionReq, Version, fn(&Path, &Path) -> anyhow::Result<()>);

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
    let migration: Vec<Migration> = vec![(
        VersionReq::parse(">=0.42.0,<0.43.0-alpha.2")?,
        Version::parse("0.43.0-alpha.2")?,
        migrate_0_42_to_0_43,
    )];

    while let Some((_req, to, m)) = migration
        .iter()
        .find(|(req, _to, _m)| req.matches(&version))
    {
        info!("Migrating database to {to}");
        m(data_dir, backup_dir)?;
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

fn migrate_drop_account_policy(data_dir: &Path, backup_dir: &Path) -> Result<()> {
    // Open the database with the old column family list (including "account policy")
    let db_path = data_dir.join("states.db");
    let backup_path = backup_dir.join("states.db");

    info!("Opening database with legacy column families to drop 'account policy'");

    // Open the database with the old column family names
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(false);

    let db = rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, MAP_NAMES_V0_42)
        .context("Failed to open database with legacy column families")?;

    // Drop the "account policy" column family
    info!("Dropping 'account policy' column family");
    db.drop_cf("account policy")
        .context("Failed to drop 'account policy' column family")?;

    // Close the database by dropping it
    drop(db);

    // Also drop from backup database
    let backup_db = rocksdb::OptimisticTransactionDB::open_cf(&opts, &backup_path, MAP_NAMES_V0_42)
        .context("Failed to open backup database with legacy column families")?;

    info!("Dropping 'account policy' column family from backup");
    backup_db
        .drop_cf("account policy")
        .context("Failed to drop 'account policy' column family from backup")?;

    drop(backup_db);

    info!("Successfully removed 'account policy' column family");
    Ok(())
}

fn migrate_0_42_to_0_43(data_dir: &Path, backup_dir: &Path) -> Result<()> {
    migrate_drop_account_policy(data_dir, backup_dir)?;
    migrate_customer_specific_networks(data_dir, backup_dir)
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
fn migrate_customer_specific_networks(data_dir: &Path, backup_dir: &Path) -> Result<()> {
    use crate::{AllowNetwork, BlockNetwork};

    // A closure to run the common migration logic on a given database path.
    let migrate_db = |db_path: &Path| -> Result<()> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(false);
        opts.create_missing_column_families(false);
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
        migrate_list::<AllowNetwork, AllowNetworkV0_42>(
            &db,
            &txn,
            &customer_ids,
            "allow networks",
        )?;
        migrate_list::<BlockNetwork, BlockNetworkV0_42>(
            &db,
            &txn,
            &customer_ids,
            "block networks",
        )?;

        // Commits the transaction once after all operations are done.
        txn.commit().context("failed to commit migration")?;

        Ok(())
    };

    info!("Migrating AllowNetwork and BlockNetwork to customer-specific format");
    migrate_db(&data_dir.join("states.db")).context("Failed to migrate main database")?;

    info!("Migrating backup AllowNetwork and BlockNetwork to customer-specific format");
    migrate_db(&backup_dir.join("states.db")).context("Failed to migrate backup database")?;

    info!("Successfully migrated AllowNetwork and BlockNetwork");
    Ok(())
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
    use crate::{Indexable, Store};

    #[allow(dead_code)]
    struct TestSchema {
        db_dir: tempfile::TempDir,
        backup_dir: tempfile::TempDir,
        store: Store,
    }

    impl TestSchema {
        #[allow(dead_code)]
        fn new() -> Self {
            let db_dir = tempfile::tempdir().unwrap();
            let backup_dir = tempfile::tempdir().unwrap();
            let store = Store::new(db_dir.path(), backup_dir.path()).unwrap();
            TestSchema {
                db_dir,
                backup_dir,
                store,
            }
        }

        #[allow(dead_code)]
        fn new_with_dir(db_dir: tempfile::TempDir, backup_dir: tempfile::TempDir) -> Self {
            let store = Store::new(db_dir.path(), backup_dir.path()).unwrap();
            TestSchema {
                db_dir,
                backup_dir,
                store,
            }
        }

        #[allow(dead_code)]
        fn close(self) -> (tempfile::TempDir, tempfile::TempDir) {
            (self.db_dir, self.backup_dir)
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
    fn migrate_0_42_to_0_43_drops_account_policy() {
        use std::fs;
        use std::io::Write;

        // Create test directories
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let db_path = db_dir.path().join("states.db");
        let backup_path = backup_dir.path().join("states.db");

        // Create a database with the old column family list (including "account policy")
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, super::MAP_NAMES_V0_42)
                .unwrap();
        drop(db);

        let backup_db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &backup_path, super::MAP_NAMES_V0_42)
                .unwrap();
        drop(backup_db);

        // Create VERSION files with 0.42.0-alpha.5
        let mut version_file = fs::File::create(db_dir.path().join("VERSION")).unwrap();
        version_file.write_all(b"0.42.0-alpha.5").unwrap();
        drop(version_file);

        let mut backup_version_file = fs::File::create(backup_dir.path().join("VERSION")).unwrap();
        backup_version_file.write_all(b"0.42.0-alpha.5").unwrap();
        drop(backup_version_file);

        // Run the migration
        super::migrate_0_42_to_0_43(db_dir.path(), backup_dir.path()).unwrap();

        // Verify the column family has been dropped by opening with the new list
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();

        // Try to access "account policy" - should fail since it was dropped
        assert!(db.cf_handle("account policy").is_none());

        // Close and reopen to ensure it still works
        drop(db);

        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(&opts, &db_path, crate::tables::MAP_NAMES)
                .unwrap();
        assert!(db.cf_handle("account policy").is_none());
        drop(db);

        // Verify backup database too
        let backup_db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(
                &opts,
                &backup_path,
                crate::tables::MAP_NAMES,
            )
            .unwrap();
        assert!(backup_db.cf_handle("account policy").is_none());

        // Close and reopen backup database to ensure it still works
        drop(backup_db);

        let backup_db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::open_cf(
                &opts,
                &backup_path,
                crate::tables::MAP_NAMES,
            )
            .unwrap();
        assert!(backup_db.cf_handle("account policy").is_none());
    }

    #[test]
    fn test_migrate_customer_specific_networks() {
        use std::fs;
        use std::io::Write;

        use bincode::Options;

        use super::{
            migrate_customer_specific_networks,
            migration_structures::{AllowNetworkV0_42, BlockNetworkV0_42},
        };
        use crate::{Customer, HostNetworkGroup, Iterable, collections::KeyIndex};

        // 1. Setup: Create database, customers, and old-format data
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        for dir in [&db_dir, &backup_dir] {
            let mut version_file = fs::File::create(dir.path().join("VERSION")).unwrap();
            version_file.write_all(b"0.43.0-alpha.1").unwrap();
        }

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        for db_path in [
            db_dir.path().join("states.db"),
            backup_dir.path().join("states.db"),
        ] {
            let db: rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded> =
                rocksdb::OptimisticTransactionDB::open_cf(
                    &opts,
                    &db_path,
                    crate::tables::MAP_NAMES,
                )
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
        }

        // 2. Run the migration
        migrate_customer_specific_networks(db_dir.path(), backup_dir.path()).unwrap();

        // 3. Verification
        let store = Store::new(db_dir.path(), backup_dir.path()).unwrap();

        let customers = store
            .customer_map()
            .iter(rocksdb::Direction::Forward, None)
            .filter_map(Result::ok)
            .map(|s| s.id)
            .collect::<Vec<_>>();
        assert_eq!(customers.len(), 2, "Should have 2 customer entries");

        // Verify AllowNetwork
        let all_allows = store
            .allow_network_map()
            .iter(rocksdb::Direction::Forward, None)
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        assert_eq!(
            all_allows.len(),
            2,
            "Should have 2 AllowNetwork entries after migration"
        );

        let customer_one_allows: Vec<_> = store
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

        let customer_two_allows: Vec<_> = store
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
        let all_blocks = store
            .block_network_map()
            .iter(rocksdb::Direction::Forward, None)
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        assert_eq!(
            all_blocks.len(),
            2,
            "Should have 2 AllowNetwork entries after migration"
        );

        let customer_one_blocks: Vec<_> = store
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

        let customer_two_blocks: Vec<_> = store
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
}
