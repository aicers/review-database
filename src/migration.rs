//! Routines to check the database format version and migrate it if necessary.
#![allow(clippy::too_many_lines)]
mod migration_structures;

use std::{
    fs::{File, create_dir_all},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use semver::{Version, VersionReq};
use tracing::info;

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
    use crate::Store;
    use crate::test::{DbGuard, acquire_db_permit};

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
        super::migrate_0_42_to_0_43(db_dir.path()).unwrap();

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
}
