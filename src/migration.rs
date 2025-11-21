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
const COMPATIBLE_VERSION_REQ: &str = ">=0.43.0-alpha.1,<0.43.0-alpha.2";

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
    let migration: Vec<Migration> = vec![
        (
            VersionReq::parse(">=0.41.0,<0.42.0-alpha.5")?,
            Version::parse("0.42.0-alpha.5")?,
            migrate_0_41_to_0_42,
        ),
        (
            VersionReq::parse(">=0.42.0-alpha.5,<0.43.0-alpha.1")?,
            Version::parse("0.43.0-alpha.1")?,
            migrate_0_42_to_0_43,
        ),
    ];

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

fn migrate_0_41_to_0_42(data_dir: &Path, backup_dir: &Path) -> Result<()> {
    let store = super::Store::new(data_dir, backup_dir)?;
    migrate_0_41_events(&store)?;
    migrate_account_policy(&store)?;
    migrate_0_42_filter(&store)?;
    Ok(())
}

fn migrate_0_42_to_0_43(data_dir: &Path, backup_dir: &Path) -> Result<()> {
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

fn migrate_0_43_triage_policy(store: &super::Store) -> Result<()> {
    use bincode::Options;

    use self::migration_structures::TriagePolicyV0_42;
    use crate::TriagePolicy;
    use crate::collections::Indexed;

    let map = store.triage_policy_map();
    let raw_map = map.raw_indexed_map();

    // Collect all entries to migrate
    let mut updates = Vec::new();
    let iter = raw_map
        .db()
        .iterator_cf(raw_map.cf(), rocksdb::IteratorMode::Start);
    for item in iter {
        let (key, value) = item.context("Failed to read from database")?;

        // Try to deserialize as old format
        let old_policy: TriagePolicyV0_42 = bincode::DefaultOptions::new()
            .deserialize(value.as_ref())
            .context("Failed to deserialize old triage policy")?;

        // Convert to new format
        let new_policy = TriagePolicy::from(old_policy);
        let new_value = bincode::DefaultOptions::new()
            .serialize(&new_policy)
            .context("Failed to serialize new triage policy")?;

        updates.push((key.to_vec(), new_value));
    }

    // Apply updates
    for (key, value) in updates {
        raw_map.db().put_cf(raw_map.cf(), &key, &value)?;
    }

    Ok(())
}

fn migrate_0_43_tidb(store: &super::Store) -> Result<()> {
    use bincode::Options;

    use self::migration_structures::TidbV0_42;
    use crate::Tidb;

    let map = store.tidb_map();
    let raw = map.raw();

    // Collect all entries to migrate
    let mut updates = Vec::new();
    let iter = raw.db.iterator_cf(raw.cf, rocksdb::IteratorMode::Start);
    for item in iter {
        let (key, value) = item.context("Failed to read from database")?;

        // Try to deserialize as old format
        let old_tidb: TidbV0_42 = bincode::DefaultOptions::new()
            .deserialize(value.as_ref())
            .context("Failed to deserialize old tidb")?;

        // Convert to new format
        let new_tidb = Tidb::from(old_tidb);
        let new_value = bincode::DefaultOptions::new()
            .serialize(&new_tidb)
            .context("Failed to serialize new tidb")?;

        updates.push((key.to_vec(), new_value));
    }

    // Apply updates
    for (key, value) in updates {
        raw.db.put_cf(raw.cf, &key, &value)?;
    }

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
    fn migrate_0_41_to_0_42_events() {
        use std::net::IpAddr;

        use chrono::{DateTime, Duration};

        use crate::event::{
            BlocklistBootpFieldsV0_41, BlocklistConnFieldsV0_41, BlocklistDnsFieldsV0_41,
            DnsEventFieldsV0_41, HttpEventFieldsV0_41, HttpThreatFieldsV0_41,
        };
        use crate::types::{EventCategoryV0_41, EventCategoryV0_42};

        let schema = TestSchema::new();
        let event_db = schema.store.events();
        let mut time = DateTime::UNIX_EPOCH;

        // Test BlocklistBootp migration with non-Unknown category
        time += Duration::minutes(1);
        let bootp_value = BlocklistBootpFieldsV0_41 {
            sensor: "test-sensor".to_string(),
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            src_port: 8080,
            dst_addr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            end_time: (time + Duration::seconds(1)).timestamp_nanos_opt().unwrap(),
            op: 1,
            htype: 1,
            hops: 1,
            xid: 1,
            ciaddr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            yiaddr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            siaddr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            giaddr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            chaddr: vec![1, 2, 3, 4, 5, 6],
            sname: "test-sname".to_string(),
            file: "test-file".to_string(),
            confidence: 0.5,
            category: EventCategoryV0_41::Reconnaissance,
        };
        let msg = EventMessage {
            time,
            kind: EventKind::BlocklistBootp,
            fields: bincode::serialize(&bootp_value).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test BlocklistBootp migration with Unknown category
        time += Duration::minutes(1);
        let bootp_value_unknown = BlocklistBootpFieldsV0_41 {
            sensor: "test-sensor".to_string(),
            src_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            src_port: 8080,
            dst_addr: "10.0.0.2".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            end_time: (time + Duration::seconds(1)).timestamp_nanos_opt().unwrap(),
            op: 1,
            htype: 1,
            hops: 1,
            xid: 1,
            ciaddr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            yiaddr: "10.0.0.2".parse::<IpAddr>().unwrap(),
            siaddr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            giaddr: "10.0.0.2".parse::<IpAddr>().unwrap(),
            chaddr: vec![1, 2, 3, 4, 5, 6],
            sname: "test-sname".to_string(),
            file: "test-file".to_string(),
            confidence: 0.5,
            category: EventCategoryV0_41::Unknown,
        };
        let msg = EventMessage {
            time,
            kind: EventKind::BlocklistBootp,
            fields: bincode::serialize(&bootp_value_unknown).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test BlocklistConn migration with non-Unknown category
        time += Duration::minutes(1);
        let mut conn_value = BlocklistConnFieldsV0_41 {
            sensor: "test-sensor".to_string(),
            src_addr: "192.168.1.3".parse::<IpAddr>().unwrap(),
            src_port: 443,
            dst_addr: "10.0.0.3".parse::<IpAddr>().unwrap(),
            dst_port: 443,
            proto: 6,
            conn_state: "SF".to_string(),
            end_time: (time + Duration::seconds(1)).timestamp_nanos_opt().unwrap(),
            service: "https".to_string(),
            orig_bytes: 1024,
            resp_bytes: 2048,
            orig_pkts: 10,
            resp_pkts: 15,
            orig_l2_bytes: 1100,
            resp_l2_bytes: 2200,
            confidence: 0.7,
            category: EventCategoryV0_41::CommandAndControl,
        };
        let msg = EventMessage {
            time,
            kind: EventKind::BlocklistConn,
            fields: bincode::serialize(&conn_value).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test TorConnectionConn migration with non-Unknown category
        time += Duration::minutes(1);
        conn_value.category = EventCategoryV0_41::InitialAccess;
        let msg = EventMessage {
            time,
            kind: EventKind::TorConnectionConn,
            fields: bincode::serialize(&conn_value).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test BlocklistConn migration with Unknown category
        time += Duration::minutes(1);
        let conn_value_unknown = BlocklistConnFieldsV0_41 {
            sensor: "test-sensor".to_string(),
            src_addr: "192.168.1.4".parse::<IpAddr>().unwrap(),
            src_port: 80,
            dst_addr: "10.0.0.4".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            conn_state: "S0".to_string(),
            end_time: (time + Duration::seconds(1)).timestamp_nanos_opt().unwrap(),
            service: "http".to_string(),
            orig_bytes: 0,
            resp_bytes: 0,
            orig_pkts: 1,
            resp_pkts: 0,
            orig_l2_bytes: 60,
            resp_l2_bytes: 0,
            confidence: 0.5,
            category: EventCategoryV0_41::Unknown,
        };
        let msg = EventMessage {
            time,
            kind: EventKind::BlocklistConn,
            fields: bincode::serialize(&conn_value_unknown).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test BlocklistDns migration
        time += Duration::minutes(1);
        let dns_value = BlocklistDnsFieldsV0_41 {
            sensor: "test-sensor".to_string(),
            src_addr: "192.168.1.5".parse::<IpAddr>().unwrap(),
            src_port: 53,
            dst_addr: "8.8.8.8".parse::<IpAddr>().unwrap(),
            dst_port: 53,
            proto: 17,
            end_time: (time + Duration::seconds(1)).timestamp_nanos_opt().unwrap(),
            query: "example.com".to_string(),
            answer: vec!["93.184.216.34".to_string()],
            trans_id: 1234,
            rtt: 100,
            qclass: 1,
            qtype: 1,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: true,
            ra_flag: true,
            ttl: vec![3600],
            confidence: 0.9,
            category: EventCategoryV0_41::CommandAndControl,
        };
        let msg = EventMessage {
            time,
            kind: EventKind::BlocklistDns,
            fields: bincode::serialize(&dns_value).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test TorConnection migration with Unknown category
        time += Duration::minutes(1);
        let mut tor_conn = HttpEventFieldsV0_41 {
            sensor: "test-sensor".to_string(),
            end_time: 0,
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            src_port: 8080,
            dst_addr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/test".to_string(),
            referer: "https://referer.com".to_string(),
            version: "1.1".to_string(),
            user_agent: "test-agent".to_string(),
            request_len: 100,
            response_len: 200,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            cookie: "session=123".to_string(),
            content_encoding: "gzip".to_string(),
            content_type: "text/html".to_string(),
            cache_control: "no-cache".to_string(),
            filenames: vec!["file1.txt".to_string(), "file2.txt".to_string()],
            mime_types: vec!["text/plain".to_string(), "application/json".to_string()],
            body: b"test body content".to_vec(),
            state: "active".to_string(),
            confidence: 1.0,
            category: EventCategoryV0_41::Unknown,
        };
        let msg = EventMessage {
            time,
            kind: EventKind::TorConnection,
            fields: bincode::serialize(&tor_conn).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test NonBrowser migration
        time += Duration::minutes(1);
        tor_conn.category = EventCategoryV0_41::InitialAccess;
        let msg = EventMessage {
            time,
            kind: EventKind::NonBrowser,
            fields: bincode::serialize(&tor_conn).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test HttpThreat migration with Unknown category
        time += Duration::minutes(1);
        let http_threat = HttpThreatFieldsV0_41 {
            time,
            sensor: "test-sensor".to_string(),
            src_addr: "192.168.1.6".parse::<IpAddr>().unwrap(),
            src_port: 12345,
            dst_addr: "10.0.0.6".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            end_time: (time + Duration::seconds(1)).timestamp_nanos_opt().unwrap(),
            method: "GET".to_string(),
            host: "malicious.com".to_string(),
            uri: "/malware.exe".to_string(),
            referer: String::new(),
            version: "HTTP/1.1".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            request_len: 200,
            response_len: 1200,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: "application/octet-stream".to_string(),
            cache_control: String::new(),
            filenames: vec![],
            mime_types: vec![],
            body: vec![],
            state: "closed".to_string(),
            db_name: String::new(),
            rule_id: 1001,
            matched_to: "uri".to_string(),
            cluster_id: Some(1),
            attack_kind: "malware".to_string(),
            confidence: 0.95,
            category: EventCategoryV0_41::Unknown,
        };
        let msg = EventMessage {
            time,
            kind: EventKind::HttpThreat,
            fields: bincode::serialize(&http_threat).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Test DnsCovertChannel migration
        time += Duration::minutes(1);
        let mut dns_covert = DnsEventFieldsV0_41 {
            sensor: "test-sensor".to_string(),
            end_time: (time + Duration::seconds(1))
                .timestamp_nanos_opt()
                .unwrap_or_default(),
            src_addr: "192.168.1.7".parse::<IpAddr>().unwrap(),
            src_port: 54321,
            dst_addr: "8.8.4.4".parse::<IpAddr>().unwrap(),
            dst_port: 53,
            proto: 17,
            query: "suspicious-domain.com".to_string(),
            answer: vec!["1.2.3.4".to_string()],
            trans_id: 5678,
            rtt: 50,
            qclass: 1,
            qtype: 1,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: true,
            ra_flag: true,
            ttl: vec![300],
            confidence: 0.8,
            category: EventCategoryV0_41::Exfiltration,
        };
        let msg = EventMessage {
            time,
            kind: EventKind::DnsCovertChannel,
            fields: bincode::serialize(&dns_covert).unwrap(),
        };

        // Test LockyRansomware migration
        time += Duration::minutes(1);
        dns_covert.category = EventCategoryV0_41::Impact;
        event_db.put(&msg).unwrap();
        let msg = EventMessage {
            time,
            kind: EventKind::LockyRansomware,
            fields: bincode::serialize(&dns_covert).unwrap(),
        };
        event_db.put(&msg).unwrap();

        // Run migration
        super::migrate_0_41_events(&schema.store).unwrap();

        // Verify migrations
        let mut iter = event_db.iter_forward();

        // Verify BlocklistBootp with non-Unknown category
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::Blocklist(RecordType::Bootp(event)) = event else {
            panic!("expected BlocklistBootp event");
        };
        assert_eq!(event.category, Some(EventCategoryV0_42::Reconnaissance));

        // Verify BlocklistBootp with Unknown -> None
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::Blocklist(RecordType::Bootp(event)) = event else {
            panic!("expected BlocklistBootp event");
        };
        assert_eq!(event.category, None);

        // Verify BlocklistConn with non-Unknown category
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::Blocklist(RecordType::Conn(event)) = event else {
            panic!("expected BlocklistConn event");
        };
        assert_eq!(event.category, Some(EventCategoryV0_42::CommandAndControl));

        // Verify TorConnectionConn
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::TorConnectionConn(event) = event else {
            panic!("expected TorConnectionConn event");
        };
        assert_eq!(event.category, Some(EventCategoryV0_42::InitialAccess));

        // Verify BlocklistConn with Unknown -> None
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::Blocklist(RecordType::Conn(event)) = event else {
            panic!("expected BlocklistConn event");
        };
        assert_eq!(event.category, None);

        // Verify BlocklistDns with non-Unknown category
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::Blocklist(RecordType::Dns(event)) = event else {
            panic!("expected BlocklistDns event");
        };
        assert_eq!(event.category, Some(EventCategoryV0_42::CommandAndControl));

        // Verify TorConnection with Unknown -> None
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::TorConnection(event) = event else {
            panic!("expected TorConnection event");
        };
        assert_eq!(event.category, None);

        // Verify NonBrowser with Unknown -> None
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::NonBrowser(event) = event else {
            panic!("expected NonBrowser event");
        };
        assert_eq!(event.category, Some(EventCategoryV0_42::InitialAccess));

        // Verify HttpThreat with Unknown -> None
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::HttpThreat(event) = event else {
            panic!("expected HttpThreat event");
        };
        assert_eq!(event.category, None);

        // Verify DnsCovertChannel with non-Unknown category
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::DnsCovertChannel(event) = event else {
            panic!("expected DnsCovertChannel event");
        };
        assert_eq!(event.category, Some(EventCategoryV0_42::Exfiltration));

        // Verify LockyRansomware with non-Unknown category
        let (_, event) = iter.next().unwrap().unwrap();
        let Event::LockyRansomware(event) = event else {
            panic!("expected LockyRansomware event");
        };
        assert_eq!(event.category, Some(EventCategoryV0_42::Impact));
    }

    #[test]
    fn migrate_0_42_filter_with_column_family() {
        use bincode::Options;

        use crate::migration::migration_structures::FilterValueV0_41;
        use crate::{FilterValue, PeriodForSearch};

        let schema = TestSchema::new();
        let filter_map = schema.store.filter_map();

        // Create an old filter with the V0_41 structure
        let old_filter = FilterValueV0_41 {
            directions: None,
            keywords: Some(vec!["test".to_string()]),
            network_tags: None,
            customers: None,
            endpoints: None,
            sensors: Some(vec!["sensor1".to_string()]),
            os: None,
            devices: None,
            hostnames: None,
            user_ids: None,
            user_names: None,
            user_departments: None,
            countries: None,
            categories: None,
            levels: None,
            kinds: Some(vec!["DnsCovertChannel".to_string()]),
            learning_methods: None,
            confidence: Some(0.5),
            period: PeriodForSearch::Recent("1d".to_string()),
        };

        // Serialize and store it using the old format
        let key = b"test_user3\x00test_filter3";
        let old_value = bincode::DefaultOptions::new()
            .serialize(&old_filter)
            .unwrap();
        filter_map.raw().put(key, &old_value).unwrap();

        // Also add another filter to ensure we iterate correctly
        let old_filter2 = FilterValueV0_41 {
            directions: None,
            keywords: Some(vec!["another".to_string()]),
            network_tags: None,
            customers: None,
            endpoints: None,
            sensors: Some(vec!["sensor2".to_string()]),
            os: None,
            devices: None,
            hostnames: None,
            user_ids: None,
            user_names: None,
            user_departments: None,
            countries: None,
            categories: None,
            levels: None,
            kinds: None,
            learning_methods: None,
            confidence: Some(0.8),
            period: PeriodForSearch::Recent("7d".to_string()),
        };

        let key2 = b"test_user2\x00another_filter2";
        let old_value2 = bincode::DefaultOptions::new()
            .serialize(&old_filter2)
            .unwrap();
        filter_map.raw().put(key2, &old_value2).unwrap();

        // Run the migration
        super::migrate_0_42_filter(&schema.store).unwrap();

        // Verify the migration was successful
        let raw = filter_map.raw();
        let mut iter = raw.db.iterator_cf(raw.cf, rocksdb::IteratorMode::Start);

        let item1 = iter.next().unwrap();
        let (key, value) = item1.unwrap();
        let new_filter: FilterValue = bincode::DefaultOptions::new()
            .deserialize(value.as_ref())
            .unwrap();
        assert_eq!(key.as_ref(), b"test_user2\x00another_filter2");
        assert_eq!(new_filter.confidence_min, Some(0.8));
        assert_eq!(new_filter.confidence_max, None);
        assert_eq!(new_filter.keywords, Some(vec!["another".to_string()]));

        let item2 = iter.next().unwrap();
        let (key, value) = item2.unwrap();
        let new_filter: FilterValue = bincode::DefaultOptions::new()
            .deserialize(value.as_ref())
            .unwrap();
        assert_eq!(key.as_ref(), b"test_user3\x00test_filter3");
        assert_eq!(new_filter.confidence_min, Some(0.5));
        assert_eq!(new_filter.confidence_max, None);
        assert_eq!(new_filter.keywords, Some(vec!["test".to_string()]));
        assert_eq!(new_filter.kinds, Some(vec!["DnsCovertChannel".to_string()]));

        // Verify that we migrated exactly 2 filters
        let count = raw
            .db
            .iterator_cf(raw.cf, rocksdb::IteratorMode::Start)
            .count();
        assert_eq!(count, 2);
    }

    #[test]
    fn migrate_0_43_triage_policy_test() {
        use bincode::Options;
        use chrono::Utc;

        use crate::TriagePolicy;
        use crate::collections::Indexed;
        use crate::migration::migration_structures::TriagePolicyV0_42;

        let schema = TestSchema::new();
        let map = schema.store.triage_policy_map();
        let raw_map = map.raw_indexed_map();

        // Create old triage policy entries without customer_ids
        let old_policy1 = TriagePolicyV0_42 {
            id: 1,
            name: "policy1".to_string(),
            ti_db: vec![],
            packet_attr: vec![],
            confidence: vec![],
            response: vec![],
            creation_time: Utc::now(),
        };

        let old_policy2 = TriagePolicyV0_42 {
            id: 2,
            name: "policy2".to_string(),
            ti_db: vec![],
            packet_attr: vec![],
            confidence: vec![],
            response: vec![],
            creation_time: Utc::now(),
        };

        // Serialize and store using old format
        let key1 = b"policy1";
        let value1 = bincode::DefaultOptions::new()
            .serialize(&old_policy1)
            .unwrap();
        raw_map.db().put_cf(raw_map.cf(), key1, &value1).unwrap();

        let key2 = b"policy2";
        let value2 = bincode::DefaultOptions::new()
            .serialize(&old_policy2)
            .unwrap();
        raw_map.db().put_cf(raw_map.cf(), key2, &value2).unwrap();

        // Run migration
        super::migrate_0_43_triage_policy(&schema.store).unwrap();

        // Verify migration
        let iter = raw_map
            .db()
            .iterator_cf(raw_map.cf(), rocksdb::IteratorMode::Start);
        for item in iter {
            let (_key, value) = item.unwrap();
            let new_policy: TriagePolicy = bincode::DefaultOptions::new()
                .deserialize(value.as_ref())
                .unwrap();
            // Verify customer_ids is set to None
            assert_eq!(new_policy.customer_ids, None);
        }
    }

    #[test]
    fn migrate_0_43_tidb_test() {
        use bincode::Options;

        use crate::migration::migration_structures::TidbV0_42;
        use crate::{EventCategory, Tidb, TidbKind};

        let schema = TestSchema::new();
        let map = schema.store.tidb_map();
        let raw = map.raw();

        // Create old tidb entries without customer_ids
        let old_tidb1 = TidbV0_42 {
            id: 1,
            name: "tidb1".to_string(),
            description: Some("Test TI database 1".to_string()),
            kind: TidbKind::Regex,
            category: EventCategory::Reconnaissance,
            version: "1.0".to_string(),
            patterns: vec![],
        };

        let old_tidb2 = TidbV0_42 {
            id: 2,
            name: "tidb2".to_string(),
            description: Some("Test TI database 2".to_string()),
            kind: TidbKind::Ip,
            category: EventCategory::CommandAndControl,
            version: "2.0".to_string(),
            patterns: vec![],
        };

        // Serialize and store using old format
        let key1 = b"tidb1";
        let value1 = bincode::DefaultOptions::new()
            .serialize(&old_tidb1)
            .unwrap();
        raw.db.put_cf(raw.cf, key1, &value1).unwrap();

        let key2 = b"tidb2";
        let value2 = bincode::DefaultOptions::new()
            .serialize(&old_tidb2)
            .unwrap();
        raw.db.put_cf(raw.cf, key2, &value2).unwrap();

        // Run migration
        super::migrate_0_43_tidb(&schema.store).unwrap();

        // Verify migration
        let iter = raw.db.iterator_cf(raw.cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (_key, value) = item.unwrap();
            let new_tidb: Tidb = bincode::DefaultOptions::new()
                .deserialize(value.as_ref())
                .unwrap();
            // Verify customer_ids is set to None
            assert_eq!(new_tidb.customer_ids, None);
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
}
