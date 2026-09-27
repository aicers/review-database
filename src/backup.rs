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
    tables::{DirId, open_rocksdb_backup_engine, open_state_dbs, restore_rocksdb_backup},
};

/// The number of names [`restore_states_offline`] tries for its working
/// directory before giving up.
const WORK_DIR_ATTEMPTS: u32 = 100;
/// The directory, inside the working directory, the backup is restored into.
const RESTORED_DIR: &str = "restored";
/// The directory, inside the working directory, the replaced database is moved
/// to until the restored one has taken its place.
const REPLACED_DIR: &str = "replaced";
/// The directory, inside the working directory, that receives the info log
/// RocksDB writes while [`check_not_in_use`] probes a database's lock.
///
/// Left to itself, RocksDB would rotate the database's own `LOG` before it
/// even reaches the lock, which would disturb a live database the check then
/// refuses to touch.
const PROBE_LOG_DIR: &str = "probe-log";
/// The file RocksDB locks inside a database directory.
const LOCK_FILE: &str = "LOCK";

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
        /// The lock failure RocksDB reported, or `None` if a [`Store`] in this
        /// process has the database open, under whatever path.
        #[source]
        source: Option<rocksdb::Error>,
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
    /// The working directory the backup is restored into could not be
    /// created.
    #[error("cannot create the restore working directory {}", path.display())]
    WorkDir {
        /// The working directory that could not be created.
        path: PathBuf,
        /// The error the file system reported.
        #[source]
        source: io::Error,
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
        /// The directory the backup was being restored into.
        database: PathBuf,
        /// The error RocksDB reported.
        #[source]
        source: rocksdb::Error,
    },
    /// The restored database could not take the place of the states
    /// database, which is left as it was.
    #[error("cannot replace states database {} with the restored backup", database.display())]
    Replace {
        /// The states database directory.
        database: PathBuf,
        /// The error the file system reported.
        #[source]
        source: io::Error,
    },
    /// The states database was moved aside, but neither the restored
    /// database nor the original could then be put in its place.
    #[error(
        "cannot replace states database {} with the restored backup; the original is in {}",
        database.display(),
        original.display()
    )]
    ReplaceIncomplete {
        /// The states database directory.
        database: PathBuf,
        /// Where the original states database now is.
        original: PathBuf,
        /// The error the file system reported.
        #[source]
        source: io::Error,
    },
    /// The restored database is in place, but the data directory recording
    /// that could not be flushed to disk.
    #[error("cannot flush data directory {}", data_dir.display())]
    Sync {
        /// The data directory.
        data_dir: PathBuf,
        /// The error the file system reported.
        #[source]
        source: io::Error,
    },
}

/// Restores the states database from the backup with the specified ID
/// without loading or migrating the current database.
///
/// This is the offline counterpart of [`restore`]. It needs no [`Store`] and
/// never loads or migrates the database it replaces, so it works when that
/// database was left in a shape the running binary cannot open, such as one a
/// newer build has already migrated. The database is `data_dir/states.db` and
/// the backup is `backup_dir/states.db`, the same layout [`Store::new`] opens.
/// The backup engine is the only thing opened in full. The current database
/// is touched only to move it aside and to probe its lock with open attempts
/// that stop before reading it (see below). The restore uses the same options
/// as the online path, so both write the same files. The latest backup is
/// never substituted for a missing `backup_id`.
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
/// # Protecting a live database
///
/// Should a process still have the database open despite step 1, the call is
/// refused rather than restoring beneath it.
///
/// A [`Store`] in this process is recognized by the directory it has open
/// rather than by the path it was given, so one opened through another path
/// to the same database, such as `data_dir/.` or a symbolic link, is refused
/// too. This check comes before any probe of the lock below, because probing
/// the database under a path the [`Store`] did not use would release its lock.
/// From that check until the restored database is in place, opening a
/// [`Store`] in this process waits for this call.
///
/// Every other holder is recognized through RocksDB's lock. RocksDB's restore
/// deletes the
/// database's `LOCK` file along with everything else in the directory it
/// restores into, so no lock can exclude other processes from a restore in
/// place. The backup is therefore restored into a new directory that no other
/// process opens, and swapped in only afterwards:
///
/// 1. The database's RocksDB lock is probed, and the call refused if another
///    holder has it. RocksDB offers no way to take its lock without starting
///    an open, so the probe starts one that fails, by its options, right
///    after taking the lock and before reading anything.
/// 2. The backup is restored into `restored` inside a working directory,
///    `states.db.restore-<pid>-<n>`, which this call creates beside the
///    database under a name nothing else holds.
/// 3. The lock is probed again, catching a process that opened the database
///    during the restore. The [`Store`] check above is repeated first, and
///    held from here until step 5 has moved the restored database in.
/// 4. The database is moved into the working directory as `replaced`, and the
///    lock probed twice more, catching a holder that opened the database
///    between the previous probe and the move. RocksDB recognizes a lock held
///    by this process only under the path it was taken at, so an empty
///    directory briefly stands in at `states.db` while that path is probed.
///    A handle opened in this process other than through a [`Store`], such as
///    by [`migrate_data_dir`](crate::migrate_data_dir), is recognized only
///    if it spelled the path the same way, which is why the caller serializes
///    the two.
///    A lock held by another process follows the file, so `replaced` is
///    probed next. If either lock is held, the database is moved back and the
///    call refused.
/// 5. The restored database is moved to `states.db`, the data directory is
///    flushed to disk so the version markers the caller writes next cannot
///    outlive the swap, and the working directory is removed.
///
/// A process that opens `states.db` between moving the database aside in
/// step 4 and moving the restored one in during step 5 finds no database
/// there. The restore needs free space for a full copy of the backup beside
/// the database until the swap, and the restored directory takes over the
/// permissions of the one it replaces. If this process is killed before it
/// finishes, the working directory is left behind and may hold the original
/// database as `replaced`.
///
/// # Errors
///
/// Returns [`OfflineRestoreError::BackupNotFound`] if `backup_dir` holds no
/// backup with `backup_id`, and [`OfflineRestoreError::DatabaseInUse`] if
/// another holder has the database's lock. Neither changes the database or
/// the backups. Returns [`OfflineRestoreError::ReplaceIncomplete`], naming
/// where the original database was left, if it was moved aside and could not
/// be moved back. Returns another variant if the backup engine or the
/// working directory cannot be opened or created, if the lock cannot be
/// checked, if the restore or the swap fails, or if the data directory
/// cannot be flushed.
pub fn restore_states_offline(
    data_dir: &Path,
    backup_dir: &Path,
    backup_id: u32,
) -> Result<(), OfflineRestoreError> {
    restore_states_offline_with(data_dir, backup_dir, backup_id, || {})
}

/// Runs [`restore_states_offline`], calling `before_swap` after the last
/// probe of the database in place and before it is moved aside.
///
/// `before_swap` runs while opening a [`Store`] in this process waits, so a
/// [`Store`] it opens on this thread never finishes opening.
fn restore_states_offline_with(
    data_dir: &Path,
    backup_dir: &Path,
    backup_id: u32,
    before_swap: impl FnOnce(),
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

    let work = create_work_dir(data_dir)?;
    let result = restore_through(
        &work,
        data_dir,
        &database,
        &mut engine,
        backup_id,
        before_swap,
    );
    // The working directory holds the original database when it could not
    // be moved back, and is kept for the caller to recover it from.
    if !matches!(result, Err(OfflineRestoreError::ReplaceIncomplete { .. }))
        && let Err(e) = std::fs::remove_dir_all(&work)
    {
        tracing::warn!(
            "cannot remove the restore working directory {}: {e}",
            work.display()
        );
    }
    result
}

/// Creates a working directory beside the states database that no other
/// caller holds, and returns its path.
fn create_work_dir(data_dir: &Path) -> Result<PathBuf, OfflineRestoreError> {
    let pid = std::process::id();
    let mut attempt = 0;
    loop {
        let path = data_dir.join(format!("{DEFAULT_STATES}.restore-{pid}-{attempt}"));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e)
                if e.kind() == io::ErrorKind::AlreadyExists && attempt + 1 < WORK_DIR_ATTEMPTS =>
            {
                attempt += 1;
            }
            Err(source) => return Err(OfflineRestoreError::WorkDir { path, source }),
        }
    }
}

/// Restores backup `backup_id` into `work` and swaps it in for `database`.
fn restore_through(
    work: &Path,
    data_dir: &Path,
    database: &Path,
    engine: &mut rocksdb::backup::BackupEngine,
    backup_id: u32,
    before_swap: impl FnOnce(),
) -> Result<(), OfflineRestoreError> {
    let log_dir = work.join(PROBE_LOG_DIR);
    let restored = work.join(RESTORED_DIR);
    let replaced = work.join(REPLACED_DIR);

    // Refuse a database that is in use before spending a restore on it.
    {
        let open = open_state_dbs();
        if let Some(id) = DirId::of_dir(database) {
            check_not_open_here(&open, id, database)?;
            check_not_in_use(database, database, &log_dir)?;
        }
    }

    restore_rocksdb_backup(engine, &restored, backup_id).map_err(|source| {
        OfflineRestoreError::Restore {
            id: backup_id,
            database: restored.clone(),
            source,
        }
    })?;

    let replace_err = |source| OfflineRestoreError::Replace {
        database: database.to_path_buf(),
        source,
    };
    // Held until the restored database is in place, so that no `Store` in
    // this process opens the database in the meantime.
    let open = open_state_dbs();
    let moved_aside = if let Some(id) = DirId::of_dir(database) {
        check_not_open_here(&open, id, database)?;
        check_not_in_use(database, database, &log_dir)?;
        let permissions = std::fs::metadata(database)
            .map_err(replace_err)?
            .permissions();
        std::fs::set_permissions(&restored, permissions).map_err(replace_err)?;
        before_swap();
        std::fs::rename(database, &replaced).map_err(replace_err)?;
        if let Err(e) = check_moved_aside_not_in_use(database, &replaced, &log_dir) {
            put_back(database, &replaced)?;
            return Err(e);
        }
        true
    } else {
        before_swap();
        false
    };

    if let Err(source) = std::fs::rename(&restored, database) {
        if moved_aside {
            put_back(database, &replaced)?;
        }
        return Err(replace_err(source));
    }
    drop(open);

    // The caller writes the version markers next. Without this, a power loss
    // could keep those markers but lose the swap, pairing them with the
    // database this call replaced.
    std::fs::File::open(data_dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|source| OfflineRestoreError::Sync {
            data_dir: data_dir.to_path_buf(),
            source,
        })
}

/// Checks that no [`Store`] in this process has the database with identity
/// `id` open, whatever path it was opened under.
///
/// # Errors
///
/// Returns [`OfflineRestoreError::DatabaseInUse`], naming `database`, if one
/// does.
fn check_not_open_here(
    open: &[DirId],
    id: DirId,
    database: &Path,
) -> Result<(), OfflineRestoreError> {
    if open.contains(&id) {
        return Err(OfflineRestoreError::DatabaseInUse {
            database: database.to_path_buf(),
            source: None,
        });
    }
    Ok(())
}

/// Checks that nothing opened the database between the last probe of it in
/// place and its move from `database` to `replaced`.
///
/// A handle in this process is recognized only under the path it opened, so
/// an empty directory stands in for the database at `database` while that
/// path is probed, and is removed again afterwards. Only then is `replaced`
/// probed for a handle in another process, whose lock follows the file. The
/// order matters: probing `replaced` opens its `LOCK` file, and closing that
/// again would release a lock this process held on the same file.
///
/// # Errors
///
/// Returns [`OfflineRestoreError::DatabaseInUse`] if either probe finds the
/// lock held, [`OfflineRestoreError::LockCheck`] if either cannot tell, or
/// [`OfflineRestoreError::Replace`] if the stand-in cannot be created or
/// removed.
fn check_moved_aside_not_in_use(
    database: &Path,
    replaced: &Path,
    log_dir: &Path,
) -> Result<(), OfflineRestoreError> {
    let replace_err = |source| OfflineRestoreError::Replace {
        database: database.to_path_buf(),
        source,
    };
    std::fs::create_dir(database).map_err(replace_err)?;
    let probed = check_not_in_use(database, database, log_dir);
    // A free lock leaves the probe's `LOCK` file behind in the stand-in.
    match std::fs::remove_file(database.join(LOCK_FILE)) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(replace_err(source)),
    }
    std::fs::remove_dir(database).map_err(replace_err)?;
    probed?;
    check_not_in_use(database, replaced, log_dir)
}

/// Moves the original database back from `replaced` to `database`.
///
/// # Errors
///
/// Returns [`OfflineRestoreError::ReplaceIncomplete`] if the move fails.
fn put_back(database: &Path, replaced: &Path) -> Result<(), OfflineRestoreError> {
    std::fs::rename(replaced, database).map_err(|source| OfflineRestoreError::ReplaceIncomplete {
        database: database.to_path_buf(),
        original: replaced.to_path_buf(),
        source,
    })
}

/// Takes and releases the RocksDB lock of the database at `path`.
///
/// RocksDB offers no way to take its lock without an open attempt, so this
/// opens the database with `error_if_exists` set and `create_if_missing`
/// cleared. RocksDB takes the lock before it reads anything, and then fails
/// on one of those two options before it writes anything, releasing the lock
/// again. Its info log goes to `log_dir` rather than into the database.
///
/// A lock held by this process is recognized only at the path it was taken
/// under, while one held by another process is recognized wherever the
/// database has since been moved.
///
/// # Errors
///
/// Returns [`OfflineRestoreError::DatabaseInUse`] if the lock is held, or
/// [`OfflineRestoreError::LockCheck`] if the attempt fails in any other way;
/// both name `database`.
fn check_not_in_use(
    database: &Path,
    path: &Path,
    log_dir: &Path,
) -> Result<(), OfflineRestoreError> {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    opts.set_error_if_exists(true);
    opts.set_db_log_dir(log_dir);

    // Success is unreachable with the options above, but the lock was free.
    let Err(source) = rocksdb::DB::open(&opts, path) else {
        return Ok(());
    };
    if is_lock_conflict(&source) {
        return Err(OfflineRestoreError::DatabaseInUse {
            database: database.to_path_buf(),
            source: Some(source),
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
        process::{Child, ChildStdout, Command, Stdio},
        sync::{Arc, RwLock},
    };

    use chrono::{DateTime, TimeZone, Utc};
    use jiff::Timestamp;

    use super::{OfflineRestoreError, create, list, restore_states_offline};
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
    /// The file each directory [`add_neighbors`] creates holds.
    const NEIGHBOR_FILE: &str = "keep";

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

    /// Creates, beside the database, directories an offline restore must not
    /// touch: one under the working-directory name this process tries first,
    /// and one under the name an earlier version of the probe used.
    fn add_neighbors(data_dir: &Path) -> Vec<std::path::PathBuf> {
        let neighbors = vec![
            data_dir.join(format!("{DEFAULT_STATES}.restore-{}-0", std::process::id())),
            data_dir.join(format!("{DEFAULT_STATES}.lock-probe")),
        ];
        for dir in &neighbors {
            std::fs::create_dir(dir).unwrap();
            std::fs::write(dir.join(NEIGHBOR_FILE), dir.as_os_str().as_encoded_bytes()).unwrap();
        }
        neighbors
    }

    fn assert_neighbors_kept(neighbors: &[std::path::PathBuf]) {
        for dir in neighbors {
            assert_eq!(dir_entries(dir), BTreeSet::from([NEIGHBOR_FILE.into()]));
            assert_eq!(
                std::fs::read(dir.join(NEIGHBOR_FILE)).unwrap(),
                dir.as_os_str().as_encoded_bytes()
            );
        }
    }

    /// A child test process holding the RocksDB lock of a database.
    ///
    /// RocksDB's file lock does not conflict with itself within one process,
    /// so a lock held elsewhere needs another process.
    struct LockHolder {
        child: Child,
        stdout: BufReader<ChildStdout>,
    }

    impl LockHolder {
        /// Starts a child process and waits until it holds the lock of
        /// `database`.
        fn start(database: &Path) -> Self {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "backup::tests::hold_states_db_lock",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(LOCK_HOLDER_DB_ENV, database)
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
            if !held {
                let status = child.wait().unwrap();
                panic!("the child process exited with {status} before taking the lock");
            }
            Self { child, stdout }
        }

        /// Makes the child release the lock and asserts it exits cleanly.
        fn stop(mut self) {
            drop(self.child.stdin.take());
            std::io::copy(&mut self.stdout, &mut std::io::sink()).unwrap();
            assert!(self.child.wait().unwrap().success());
        }
    }

    #[test]
    fn offline_restore_restores_the_requested_backup() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        store_with_two_backups(data_dir.path(), backup_dir.path());
        assert_eq!(event_count(data_dir.path(), backup_dir.path()), 3);
        let neighbors = add_neighbors(data_dir.path());
        let before = dir_entries(data_dir.path());

        restore_states_offline(data_dir.path(), backup_dir.path(), 1).unwrap();

        assert_eq!(dir_entries(data_dir.path()), before);
        assert_neighbors_kept(&neighbors);
        assert_eq!(event_count(data_dir.path(), backup_dir.path()), 1);
    }

    #[cfg(unix)]
    #[test]
    fn offline_restore_keeps_the_database_permissions() {
        use std::os::unix::fs::PermissionsExt;

        const MODE: u32 = 0o700;

        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let database = data_dir.path().join(DEFAULT_STATES);
        store_with_two_backups(data_dir.path(), backup_dir.path());
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(MODE)).unwrap();

        restore_states_offline(data_dir.path(), backup_dir.path(), 1).unwrap();

        let mode = std::fs::metadata(&database).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, MODE);
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
    fn offline_restore_recreates_a_missing_database() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        store_with_two_backups(data_dir.path(), backup_dir.path());
        let before = dir_entries(data_dir.path());
        std::fs::remove_dir_all(data_dir.path().join(DEFAULT_STATES)).unwrap();

        restore_states_offline(data_dir.path(), backup_dir.path(), 2).unwrap();

        assert_eq!(dir_entries(data_dir.path()), before);
        assert_eq!(event_count(data_dir.path(), backup_dir.path()), 2);
    }

    #[test]
    fn offline_restore_refuses_a_missing_backup_id() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let database = data_dir.path().join(DEFAULT_STATES);
        let backup = backup_dir.path().join(DEFAULT_STATES);
        store_with_two_backups(data_dir.path(), backup_dir.path());
        let data_before = dir_entries(data_dir.path());
        let database_before = dir_entries(&database);
        let backup_before = dir_entries(&backup);

        let err = restore_states_offline(data_dir.path(), backup_dir.path(), 3).unwrap_err();

        assert!(
            matches!(err, OfflineRestoreError::BackupNotFound { id: 3, .. }),
            "{err:?}"
        );
        assert_eq!(dir_entries(data_dir.path()), data_before);
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
        let neighbors = add_neighbors(data_dir.path());

        {
            let _store = open_store(data_dir.path(), backup_dir.path());
            let data_before = dir_entries(data_dir.path());
            let database_before = dir_entries(&database);

            let err = restore_states_offline(data_dir.path(), backup_dir.path(), 1).unwrap_err();

            assert!(
                matches!(err, OfflineRestoreError::DatabaseInUse { .. }),
                "{err:?}"
            );
            assert_eq!(dir_entries(data_dir.path()), data_before);
            assert_eq!(dir_entries(&database), database_before);
            assert_neighbors_kept(&neighbors);
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
        let neighbors = add_neighbors(data_dir.path());

        let holder = LockHolder::start(&database);
        let data_before = dir_entries(data_dir.path());
        let database_before = dir_entries(&database);

        let err = restore_states_offline(data_dir.path(), backup_dir.path(), 1).unwrap_err();

        assert!(
            matches!(err, OfflineRestoreError::DatabaseInUse { .. }),
            "{err:?}"
        );
        assert_eq!(dir_entries(data_dir.path()), data_before);
        assert_eq!(dir_entries(&database), database_before);
        assert_neighbors_kept(&neighbors);
        holder.stop();
        assert_eq!(event_count(data_dir.path(), backup_dir.path()), 3);
    }

    #[test]
    fn offline_restore_refuses_a_database_opened_just_before_the_swap() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let database = data_dir.path().join(DEFAULT_STATES);
        store_with_two_backups(data_dir.path(), backup_dir.path());
        let neighbors = add_neighbors(data_dir.path());
        let data_before = dir_entries(data_dir.path());

        // Another process opens the database after every probe of it in
        // place has passed, with the backup already restored beside it.
        let mut holder = None;
        let mut database_before = BTreeSet::new();
        let err = super::restore_states_offline_with(data_dir.path(), backup_dir.path(), 1, || {
            holder = Some(LockHolder::start(&database));
            database_before = dir_entries(&database);
        })
        .unwrap_err();

        assert!(
            matches!(err, OfflineRestoreError::DatabaseInUse { .. }),
            "{err:?}"
        );
        assert_eq!(dir_entries(data_dir.path()), data_before);
        assert_eq!(dir_entries(&database), database_before);
        assert_neighbors_kept(&neighbors);
        holder.expect("the swap was reached").stop();
        assert_eq!(event_count(data_dir.path(), backup_dir.path()), 3);
    }

    #[test]
    fn offline_restore_refuses_a_database_open_in_this_process_under_another_path() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let links = tempfile::tempdir().unwrap();
        let database = data_dir.path().join(DEFAULT_STATES);
        store_with_two_backups(data_dir.path(), backup_dir.path());
        let neighbors = add_neighbors(data_dir.path());
        let link = links.path().join("data");
        std::os::unix::fs::symlink(data_dir.path(), &link).unwrap();

        let store = open_store(data_dir.path(), backup_dir.path());
        let data_before = dir_entries(data_dir.path());
        let database_before = dir_entries(&database);
        for alias in [data_dir.path().join("."), link] {
            let err = restore_states_offline(&alias, backup_dir.path(), 1).unwrap_err();

            assert!(
                matches!(err, OfflineRestoreError::DatabaseInUse { source: None, .. }),
                "{alias:?}: {err:?}"
            );
            assert_eq!(dir_entries(data_dir.path()), data_before);
            assert_eq!(dir_entries(&database), database_before);
            assert_neighbors_kept(&neighbors);
        }
        put_event(&store);
        drop(store);
        assert_eq!(event_count(data_dir.path(), backup_dir.path()), 4);
    }

    #[test]
    fn offline_restore_makes_a_store_opened_in_this_process_during_the_swap_wait() {
        let _permit = acquire_db_permit();
        let data_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        store_with_two_backups(data_dir.path(), backup_dir.path());
        let neighbors = add_neighbors(data_dir.path());
        let data_before = dir_entries(data_dir.path());
        let alias = data_dir.path().join(".");

        // Another thread opens a store, through another path to the database,
        // after every probe of it in place has passed. The store must end up
        // with the restored database rather than the one being replaced.
        let events_seen = std::thread::scope(|scope| {
            let mut opener = None;
            super::restore_states_offline_with(data_dir.path(), backup_dir.path(), 1, || {
                opener = Some(scope.spawn(|| {
                    let store = open_store(&alias, backup_dir.path());
                    let count = store.read().unwrap().events().iter_forward().count();
                    put_event(&store);
                    count
                }));
            })
            .unwrap();
            opener.expect("the swap was reached").join().unwrap()
        });

        assert_eq!(events_seen, 1);
        assert_eq!(dir_entries(data_dir.path()), data_before);
        assert_neighbors_kept(&neighbors);
        assert_eq!(event_count(data_dir.path(), backup_dir.path()), 2);
    }

    /// Holds the lock of the database named by [`LOCK_HOLDER_DB_ENV`] until
    /// stdin closes.
    ///
    /// This runs only as the child process of [`LockHolder::start`].
    #[test]
    #[ignore = "run as a child process by LockHolder::start"]
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
