//! Database backup utilities.

use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::Result;
use chrono::{DateTime, TimeZone, Utc};
use rocksdb::backup::BackupEngineInfo;

use crate::{
    DEFAULT_STATES, Store,
    tables::{open_rocksdb_backup_engine, restore_rocksdb_backup},
};

/// The directory, beside `states.db` in the data directory, that receives the
/// info log RocksDB writes while [`restore_states_offline`] checks whether the
/// database is in use.
///
/// Left to itself, RocksDB would rotate the database's own `LOG` before it
/// even reaches the lock, which would disturb a live database the check then
/// refuses to touch.
const LOCK_PROBE_LOG_DIR: &str = "states.db.lock-probe";

#[allow(clippy::module_name_repetitions)]
pub struct BackupInfo {
    pub id: u32,
    pub timestamp: DateTime<Utc>,
    pub size: u64,
}

impl From<BackupEngineInfo> for BackupInfo {
    fn from(backup: BackupEngineInfo) -> Self {
        Self {
            id: backup.backup_id,
            timestamp: DateTime::from_timestamp(backup.timestamp, 0)
                .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap()),
            size: backup.size,
        }
    }
}

/// Creates a new database backup, keeping the specified number of backups.
///
/// # Errors
///
/// Returns an error if backup fails.
///
/// # Panics
///
/// Panics if the lock is poisoned, which should never happen as the backup
/// operation does not panic.
pub fn create(store: &Arc<RwLock<Store>>, flush: bool, backups_to_keep: u32) -> Result<()> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    let mut store = store
        .write()
        .expect("write lock should not be poisoned as backup does not panic");
    store.backup(flush, backups_to_keep)
}

/// Lists the backup information of the database.
///
/// # Errors
///
/// Returns an error if backup list fails to create
///
/// # Panics
///
/// Panics if the lock is poisoned, which should never happen as reading backup
/// info does not panic.
pub fn list(store: &Arc<RwLock<Store>>) -> Result<Vec<BackupInfo>> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    let backup_list = {
        let store = store
            .read()
            .expect("read lock should not be poisoned as get_backup_info does not panic");
        store.get_backup_info()?
    };
    Ok(backup_list
        .into_iter()
        .map(std::convert::Into::into)
        .collect())
}

/// Restores the database from a backup with the specified ID.
///
/// # Errors
///
/// Returns an error if the restore operation fails.
///
/// # Panics
///
/// Panics if the lock is poisoned, which should never happen as the restore
/// operation does not panic.
pub fn restore(store: &Arc<RwLock<Store>>, backup_id: Option<u32>) -> Result<()> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    let mut store = store
        .write()
        .expect("write lock should not be poisoned as restore does not panic");
    match &backup_id {
        Some(id) => store.restore_from_backup(*id),
        None => store.restore_from_latest_backup(),
    }
}

/// An error returned by [`restore_states_offline`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OfflineRestoreError {
    /// The backup directory holds no backup with the requested id.
    #[error("no states backup with id {id} in {}", backup.display())]
    BackupNotFound {
        /// The requested backup id.
        id: u32,
        /// The states backup directory that was searched.
        backup: PathBuf,
    },
    /// Another process, or another handle in this one, holds the lock of the
    /// states database.
    #[error("states database {} is in use", database.display())]
    DatabaseInUse {
        /// The states database directory.
        database: PathBuf,
        /// The lock failure RocksDB reported.
        #[source]
        source: rocksdb::Error,
    },
    /// The backup engine could not be opened.
    #[error("cannot open the states backup engine in {}", backup.display())]
    OpenBackupEngine {
        /// The states backup directory.
        backup: PathBuf,
        /// The error RocksDB reported.
        #[source]
        source: rocksdb::Error,
    },
    /// Whether the states database is in use could not be determined.
    #[error("cannot check whether states database {} is in use", database.display())]
    LockCheck {
        /// The states database directory.
        database: PathBuf,
        /// The error RocksDB reported.
        #[source]
        source: rocksdb::Error,
    },
    /// The backup engine failed while restoring the backup.
    #[error("cannot restore states backup {id} into {}", database.display())]
    Restore {
        /// The requested backup id.
        id: u32,
        /// The states database directory.
        database: PathBuf,
        /// The error RocksDB reported.
        #[source]
        source: rocksdb::Error,
    },
}

/// Restores the states database from the backup with the specified ID
/// without opening the current database.
///
/// This is the offline counterpart of [`restore`]. It needs no [`Store`] and
/// never reads or migrates the database it replaces, touching it only to take
/// and release its lock (see below) before restoring over it, so it works when
/// that database was left in a shape the running binary cannot open, such as
/// one a newer build has already migrated. The database is
/// `data_dir/states.db` and the backup is `backup_dir/states.db`, the same
/// layout [`Store::new`] opens. Only the backup engine is opened, and the
/// restore uses the same options as the online path, so both write the same
/// files. The latest backup is never substituted for a missing `backup_id`.
///
/// This function does not touch the `VERSION` markers. A rollback runs these
/// steps in order:
///
/// 1. Stop every process that opens the data directory (`REview`).
/// 2. Call this function with the backup id taken before the update.
/// 3. Call [`write_version_markers`](crate::write_version_markers) with
///    `data_dir`, `backup_dir`, and the format version recorded with that
///    backup, so both markers describe the restored contents.
/// 4. Start `REview` again.
///
/// The caller serializes this sequence against
/// [`migrate_data_dir`](crate::migrate_data_dir), against [`Store::new`], and
/// against any other restore or marker write for the same directories.
///
/// Before restoring, the database's RocksDB lock is taken and released once,
/// and the call is refused if another holder has it. This catches a process
/// that still has the database open, but the lock is not held across the
/// restore itself, so a process opening the database after the check is not
/// excluded; stopping it beforehand remains the caller's duty.
///
/// # Errors
///
/// Returns [`OfflineRestoreError::BackupNotFound`] if `backup_dir` holds no
/// backup with `backup_id`, and [`OfflineRestoreError::DatabaseInUse`] if
/// another holder has the database's lock. Neither changes the database or
/// the backups. Returns another variant if the backup engine cannot be
/// opened, if the lock cannot be checked, or if the restore fails.
pub fn restore_states_offline(
    data_dir: &Path,
    backup_dir: &Path,
    backup_id: u32,
) -> Result<(), OfflineRestoreError> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    let database = data_dir.join(DEFAULT_STATES);
    let backup = backup_dir.join(DEFAULT_STATES);

    // Opening the backup engine creates its directory, which would leave an
    // empty backup directory behind a call that is about to be refused.
    if !backup.is_dir() {
        return Err(OfflineRestoreError::BackupNotFound {
            id: backup_id,
            backup,
        });
    }
    let mut engine = match open_rocksdb_backup_engine(&backup) {
        Ok(engine) => engine,
        Err(source) => return Err(OfflineRestoreError::OpenBackupEngine { backup, source }),
    };
    if !engine
        .get_backup_info()
        .iter()
        .any(|info| info.backup_id == backup_id)
    {
        return Err(OfflineRestoreError::BackupNotFound {
            id: backup_id,
            backup,
        });
    }

    if database.is_dir() {
        check_not_in_use(data_dir, &database)?;
    }

    restore_rocksdb_backup(&mut engine, &database, backup_id).map_err(|source| {
        OfflineRestoreError::Restore {
            id: backup_id,
            database,
            source,
        }
    })
}

/// Takes and releases the RocksDB lock of the database at `database`.
///
/// RocksDB offers no way to take its lock without an open attempt, so this
/// opens the database with `error_if_exists` set and `create_if_missing`
/// cleared. RocksDB takes the lock before it reads anything, and then fails
/// on one of those two options before it writes anything, releasing the lock
/// again.
///
/// # Errors
///
/// Returns [`OfflineRestoreError::DatabaseInUse`] if the lock is held, or
/// [`OfflineRestoreError::LockCheck`] if the attempt fails in any other way.
fn check_not_in_use(data_dir: &Path, database: &Path) -> Result<(), OfflineRestoreError> {
    let log_dir = data_dir.join(LOCK_PROBE_LOG_DIR);
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.set_error_if_exists(true);
    opts.set_db_log_dir(&log_dir);

    let result = rocksdb::DB::open(&opts, database);
    if let Err(e) = std::fs::remove_dir_all(&log_dir)
        && e.kind() != io::ErrorKind::NotFound
    {
        tracing::warn!(
            "cannot remove the lock-check log directory {}: {e}",
            log_dir.display()
        );
    }

    // Success is unreachable with the options above, but the lock was free.
    let Err(source) = result else {
        return Ok(());
    };
    if is_lock_conflict(&source) {
        return Err(OfflineRestoreError::DatabaseInUse {
            database: database.to_path_buf(),
            source,
        });
    }
    if passed_lock(&source) {
        return Ok(());
    }
    Err(OfflineRestoreError::LockCheck {
        database: database.to_path_buf(),
        source,
    })
}

/// Returns whether `error` is RocksDB reporting that its lock is held.
///
/// `PosixFileSystem::LockFile` reports a lock held by another process as
/// "While lock file", and one held by this process as "lock hold by current
/// process".
fn is_lock_conflict(error: &rocksdb::Error) -> bool {
    let message: &str = error.as_ref();
    error.kind() == rocksdb::ErrorKind::IOError
        && (message.contains("While lock file") || message.contains("lock hold by current process"))
}

/// Returns whether `error` is one an open attempt reports only after taking
/// the lock, which the options in [`check_not_in_use`] make it fail with.
fn passed_lock(error: &rocksdb::Error) -> bool {
    let message: &str = error.as_ref();
    error.kind() == rocksdb::ErrorKind::InvalidArgument
        && (message.contains("error_if_exists is true")
            || message.contains("create_if_missing is false"))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        ffi::OsString,
        io::{BufRead, BufReader, Read, Write},
        net::{IpAddr, Ipv4Addr},
        path::Path,
        process::{Command, Stdio},
        sync::{Arc, RwLock},
    };

    use chrono::{DateTime, TimeZone, Utc};
    use jiff::Timestamp;

    use super::{LOCK_PROBE_LOG_DIR, OfflineRestoreError, create, list, restore_states_offline};
    use crate::event::timestamp;
    use crate::test::acquire_db_permit;
    use crate::{
        DEFAULT_STATES, Store,
        event::{DnsEventFields, EventKind, EventMessage},
    };

    fn msg_time(time: DateTime<Utc>) -> Timestamp {
        timestamp::from_chrono(time).expect("test event message time must fit i64 nanoseconds")
    }

    fn example_message() -> EventMessage {
        let fields = DnsEventFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 53,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            query: "foo.com".to_string(),
            answer: vec!["1.1.1.1".to_string()],
            trans_id: 1,
            rtt: 1,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: false,
            ttl: vec![1; 5],
            confidence: 0.8,
            category: Some(crate::EventCategory::CommandAndControl),
        };
        EventMessage {
            time: msg_time(Utc::now()),
            kind: EventKind::DnsCovertChannel,
            fields: bincode::serialize(&fields).expect("serializable"),
        }
    }

    #[test]
    fn db_backup_list() {
        let _permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let store = Arc::new(RwLock::new(
            Store::new(db_dir.path(), backup_dir.path(), None).unwrap(),
        ));

        {
            let store = store.read().expect("test holds no other locks");
            let db = store.events();
            assert!(db.iter_forward().next().is_none());
        }

        let msg = example_message();

        // backing up 1
        {
            let mut store = store.write().expect("test holds no other locks");
            let db = store.events();
            db.put(&msg).unwrap();
            let res = store.backup(true, 3);
            assert!(res.is_ok());
        }
        // backing up 2
        {
            let mut store = store.write().expect("test holds no other locks");
            let db = store.events();
            db.put(&msg).unwrap();
            let res = store.backup(true, 3);
            assert!(res.is_ok());
        }

        // backing up 3
        {
            let mut store = store.write().expect("test holds no other locks");
            let db = store.events();
            db.put(&msg).unwrap();
            let res = store.backup(true, 3);
            assert!(res.is_ok());
        }

        // get backup list
        let backup_list = list(&store).unwrap();
        assert_eq!(backup_list.len(), 3);
        assert_eq!(backup_list[0].id, 1);
        assert_eq!(backup_list[1].id, 2);
        assert_eq!(backup_list[2].id, 3);
    }

    /// Names the environment variable that points [`hold_states_db_lock`] at
    /// the database whose lock it holds.
    const LOCK_HOLDER_DB_ENV: &str = "REVIEW_DATABASE_TEST_LOCK_HOLDER_DB";
    /// The line [`hold_states_db_lock`] prints once it holds the lock.
    const LOCK_HELD_LINE: &str = "states-db-lock-held";

    fn open_store(data_dir: &Path, backup_dir: &Path) -> Arc<RwLock<Store>> {
        Arc::new(RwLock::new(Store::new(data_dir, backup_dir, None).unwrap()))
    }

    fn put_event(store: &Arc<RwLock<Store>>) {
        let store = store.read().expect("test holds no other locks");
        store.events().put(&example_message()).unwrap();
    }

    fn event_count(data_dir: &Path, backup_dir: &Path) -> usize {
        let store = Store::new(data_dir, backup_dir, None).unwrap();
        store.events().iter_forward().count()
    }

    fn dir_entries(dir: &Path) -> BTreeSet<OsString> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect()
    }

    /// Creates a store holding one event in backup 1 and two in backup 2,
    /// then writes a third event after both backups.
    fn store_with_two_backups(data_dir: &Path, backup_dir: &Path) {
        let store = open_store(data_dir, backup_dir);
        put_event(&store);
        create(&store, true, 3).unwrap();
        put_event(&store);
        create(&store, true, 3).unwrap();
        put_event(&store);
        let ids: Vec<u32> = list(&store).unwrap().iter().map(|b| b.id).collect();
        assert_eq!(ids, [1, 2]);
    }

    #[test]
    fn offline_restore_restores_the_requested_backup() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        store_with_two_backups(data_dir.path(), backup_dir.path());
        assert_eq!(event_count(data_dir.path(), backup_dir.path()), 3);

        restore_states_offline(data_dir.path(), backup_dir.path(), 1).unwrap();

        assert_eq!(event_count(data_dir.path(), backup_dir.path()), 1);
        assert!(!data_dir.path().join(LOCK_PROBE_LOG_DIR).exists());
    }

    #[test]
    fn offline_restore_replaces_a_newer_migrated_database() {
        const NEWER_VERSION: &str = "99.0.0";
        const FUTURE_CF: &str = "future_cf";

        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let database = data_dir.path().join(DEFAULT_STATES);
        store_with_two_backups(data_dir.path(), backup_dir.path());

        // Leave the database as a newer build would after migrating it: a
        // newer marker, a column family this build does not know, and keys
        // written after the backup.
        std::fs::write(data_dir.path().join("VERSION"), NEWER_VERSION).unwrap();
        {
            let mut opts = rocksdb::Options::default();
            opts.create_missing_column_families(true);
            let mut cfs = rocksdb::DB::list_cf(&opts, &database).unwrap();
            cfs.push(FUTURE_CF.to_string());
            let db = rocksdb::DB::open_cf(&opts, &database, &cfs).unwrap();
            let future = db.cf_handle(FUTURE_CF).unwrap();
            db.put_cf(future, b"future key", b"future value").unwrap();
            db.put(b"future default key", b"future value").unwrap();
        }
        assert!(Store::new(data_dir.path(), backup_dir.path(), None).is_err());

        restore_states_offline(data_dir.path(), backup_dir.path(), 1).unwrap();

        // The restore neither migrated nor stamped anything.
        assert_eq!(
            std::fs::read_to_string(data_dir.path().join("VERSION")).unwrap(),
            NEWER_VERSION
        );
        let cfs = rocksdb::DB::list_cf(&rocksdb::Options::default(), &database).unwrap();
        assert!(!cfs.iter().any(|cf| cf == FUTURE_CF));
        {
            let db = rocksdb::DB::open_cf_for_read_only(
                &rocksdb::Options::default(),
                &database,
                &cfs,
                false,
            )
            .unwrap();
            assert!(db.get(b"future default key").unwrap().is_none());
        }

        crate::write_version_markers(
            data_dir.path(),
            backup_dir.path(),
            env!("CARGO_PKG_VERSION"),
        )
        .unwrap();
        assert_eq!(event_count(data_dir.path(), backup_dir.path()), 1);
    }

    #[test]
    fn offline_restore_refuses_a_missing_backup_id() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let database = data_dir.path().join(DEFAULT_STATES);
        let backup = backup_dir.path().join(DEFAULT_STATES);
        store_with_two_backups(data_dir.path(), backup_dir.path());
        let database_before = dir_entries(&database);
        let backup_before = dir_entries(&backup);

        let err = restore_states_offline(data_dir.path(), backup_dir.path(), 3).unwrap_err();

        assert!(
            matches!(err, OfflineRestoreError::BackupNotFound { id: 3, .. }),
            "{err:?}"
        );
        assert_eq!(dir_entries(&database), database_before);
        assert_eq!(dir_entries(&backup), backup_before);
        assert_eq!(event_count(data_dir.path(), backup_dir.path()), 3);
    }

    #[test]
    fn offline_restore_refuses_a_missing_backup_directory() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let err = restore_states_offline(data_dir.path(), backup_dir.path(), 1).unwrap_err();

        assert!(
            matches!(err, OfflineRestoreError::BackupNotFound { id: 1, .. }),
            "{err:?}"
        );
        assert!(dir_entries(backup_dir.path()).is_empty());
        assert!(dir_entries(data_dir.path()).is_empty());
    }

    #[test]
    fn offline_restore_refuses_a_database_open_in_this_process() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let database = data_dir.path().join(DEFAULT_STATES);
        store_with_two_backups(data_dir.path(), backup_dir.path());

        {
            let _store = open_store(data_dir.path(), backup_dir.path());
            let before = dir_entries(&database);

            let err = restore_states_offline(data_dir.path(), backup_dir.path(), 1).unwrap_err();

            assert!(
                matches!(err, OfflineRestoreError::DatabaseInUse { .. }),
                "{err:?}"
            );
            assert_eq!(dir_entries(&database), before);
            assert!(!data_dir.path().join(LOCK_PROBE_LOG_DIR).exists());
        }
        assert_eq!(event_count(data_dir.path(), backup_dir.path()), 3);
    }

    #[test]
    fn offline_restore_refuses_a_database_open_in_another_process() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let database = data_dir.path().join(DEFAULT_STATES);
        store_with_two_backups(data_dir.path(), backup_dir.path());

        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backup::tests::hold_states_db_lock",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(LOCK_HOLDER_DB_ENV, &database)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut held = false;
        let mut line = String::new();
        while stdout.read_line(&mut line).unwrap() > 0 {
            if line.contains(LOCK_HELD_LINE) {
                held = true;
                break;
            }
            line.clear();
        }
        assert!(held, "the child process did not take the lock");
        let before = dir_entries(&database);

        let err = restore_states_offline(data_dir.path(), backup_dir.path(), 1).unwrap_err();

        assert!(
            matches!(err, OfflineRestoreError::DatabaseInUse { .. }),
            "{err:?}"
        );
        assert_eq!(dir_entries(&database), before);
        drop(child.stdin.take());
        std::io::copy(&mut stdout, &mut std::io::sink()).unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(event_count(data_dir.path(), backup_dir.path()), 3);
    }

    /// Holds the lock of the database named by [`LOCK_HOLDER_DB_ENV`] until
    /// stdin closes.
    ///
    /// This runs only as the child process of
    /// `offline_restore_refuses_a_database_open_in_another_process`, since
    /// RocksDB's file lock does not conflict with itself within one process.
    #[test]
    #[ignore = "run as a child process by offline_restore_refuses_a_database_open_in_another_process"]
    fn hold_states_db_lock() {
        let Some(database) = std::env::var_os(LOCK_HOLDER_DB_ENV) else {
            return;
        };
        let opts = rocksdb::Options::default();
        let cfs = rocksdb::DB::list_cf(&opts, &database).unwrap();
        let _db = rocksdb::DB::open_cf(&opts, &database, cfs).unwrap();
        let mut stdout = std::io::stdout();
        writeln!(stdout, "{LOCK_HELD_LINE}").unwrap();
        stdout.flush().unwrap();
        std::io::stdin().read_to_end(&mut Vec::new()).unwrap();
    }

    #[test]
    fn test_backup_info_timestamp_conversion() {
        use chrono::{DateTime, Datelike};
        use rocksdb::backup::BackupEngineInfo;

        use super::BackupInfo;

        // Test with a known timestamp in seconds (September 25, 2025, 00:42:20 UTC)
        let timestamp_seconds: i64 = 1_758_760_940;
        let backup_engine_info = BackupEngineInfo {
            backup_id: 1,
            timestamp: timestamp_seconds,
            size: 697_860,
            num_files: 10,
        };

        let backup_info: BackupInfo = backup_engine_info.into();

        // Verify the timestamp is correctly interpreted as seconds
        assert_eq!(backup_info.id, 1);
        assert_eq!(backup_info.size, 697_860);

        // The timestamp should be in 2025, not 1970
        let expected_timestamp = DateTime::from_timestamp(timestamp_seconds, 0).unwrap();
        assert_eq!(backup_info.timestamp, expected_timestamp);
        assert_eq!(backup_info.timestamp.year(), 2025);
    }
}
