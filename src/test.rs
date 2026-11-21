//! # Test Utilities Module
//!
//! The `test` module provides shared utilities and data structures for
//! conducting unit tests throughout the `review-database` crate. Its primary
//! focus is on facilitating the setup and management of a test database
//! environment, utilizing the `OptimisticTransactionDB` from the `rocksdb`
//! crate. This setup is crucial for tests that require interaction with a
//! database, ensuring they run against a realistic and isolated environment.
//!
//! ## Concurrency Control
//!
//! To prevent "Too many open files" errors when running tests in parallel,
//! this module provides [`DbGuard`] and [`acquire_db_permit`] to limit the
//! number of concurrent database instances.

use std::sync::{Condvar, Mutex};

use rocksdb::OptimisticTransactionDB;

use crate::collections::IndexedSet;

/// Maximum number of concurrent test database instances.
///
/// This limit prevents "Too many open files" errors when running tests in
/// parallel, as each RocksDB instance opens many file descriptors.
const MAX_CONCURRENT_DBS: usize = 4;

/// A semaphore that limits the number of concurrent database instances.
struct DbSemaphore {
    state: Mutex<usize>,
    condvar: Condvar,
    max: usize,
}

impl DbSemaphore {
    /// Creates a new semaphore with the given maximum count.
    const fn new(max: usize) -> Self {
        Self {
            state: Mutex::new(0),
            condvar: Condvar::new(),
            max,
        }
    }

    /// Acquires a permit from the semaphore, blocking if necessary.
    fn acquire(&self) -> DbGuard<'_> {
        let mut count = self.state.lock().unwrap();
        while *count >= self.max {
            count = self.condvar.wait(count).unwrap();
        }
        *count += 1;
        DbGuard(self)
    }

    /// Releases a permit back to the semaphore.
    fn release(&self) {
        let mut count = self.state.lock().unwrap();
        *count -= 1;
        self.condvar.notify_one();
    }
}

static DB_SEMAPHORE: DbSemaphore = DbSemaphore::new(MAX_CONCURRENT_DBS);

/// A guard that holds a permit for creating a test database.
///
/// When dropped, the permit is released, allowing another test to proceed.
pub(crate) struct DbGuard<'a>(&'a DbSemaphore);

impl Drop for DbGuard<'_> {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// Acquires a permit for creating a test database.
///
/// This function blocks if the maximum number of concurrent database instances
/// has been reached. The permit is released when the returned guard is dropped.
pub(crate) fn acquire_db_permit() -> DbGuard<'static> {
    DB_SEMAPHORE.acquire()
}

pub(super) struct Store {
    db: OptimisticTransactionDB,
}

impl Store {
    pub(super) fn new() -> Self {
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("test.db");

        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = rocksdb::OptimisticTransactionDB::open_cf(&opts, db_path, ["test_cf"]).unwrap();
        Self { db }
    }

    pub(super) fn indexed_set(&self) -> IndexedSet<'_> {
        IndexedSet::new(&self.db, "test_cf", b"indexed set").unwrap()
    }
}

pub(crate) fn sst_files(path: &std::path::Path) -> std::collections::HashSet<std::path::PathBuf> {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sst"))
        .collect()
}

pub(crate) fn corrupt_new_sst(
    path: &std::path::Path,
    before: &std::collections::HashSet<std::path::PathBuf>,
) {
    use std::io::{Read, Seek, SeekFrom, Write};

    let after = sst_files(path);
    let new: Vec<_> = after.difference(before).collect();
    assert_eq!(new.len(), 1);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(new[0])
        .unwrap();
    let offset = file.metadata().unwrap().len() / 2;
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut bytes = [0; 32];
    file.read_exact(&mut bytes).unwrap();
    for byte in &mut bytes {
        *byte ^= 0xff;
    }
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&bytes).unwrap();
}

/// Returns the UTC timestamp of the given civil date and time.
pub(crate) fn utc(
    year: i16,
    month: i8,
    day: i8,
    hour: i8,
    minute: i8,
    second: i8,
) -> jiff::Timestamp {
    jiff::tz::TimeZone::UTC
        .to_timestamp(jiff::civil::datetime(
            year, month, day, hour, minute, second, 0,
        ))
        .expect("test date and time must be a valid UTC timestamp")
}

/// Returns the `i64` Unix-epoch nanoseconds of the given civil date and time
/// in UTC.
pub(crate) fn utc_nanos(year: i16, month: i8, day: i8, hour: i8, minute: i8, second: i8) -> i64 {
    crate::timestamp::to_i64_nanos(utc(year, month, day, hour, minute, second))
        .expect("test date and time must fit i64 nanoseconds")
}

/// Returns the timestamp `seconds` and `nanos` after the Unix epoch.
pub(crate) fn from_second(seconds: i64, nanos: i32) -> jiff::Timestamp {
    jiff::Timestamp::new(seconds, nanos).expect("test timestamp must be valid")
}

/// Returns the UTC timestamp of the given civil date and time with
/// nanoseconds.
pub(crate) fn utc_nano(
    year: i16,
    month: i8,
    day: i8,
    hour: i8,
    minute: i8,
    second: i8,
    nanosecond: i32,
) -> jiff::Timestamp {
    jiff::tz::TimeZone::UTC
        .to_timestamp(jiff::civil::datetime(
            year, month, day, hour, minute, second, nanosecond,
        ))
        .expect("test date and time must be a valid UTC timestamp")
}

/// Returns the subsecond part of `time` the way the 0.61 format wrote it:
/// nothing for a whole second, else three, six or nine digits, whichever is
/// the fewest that holds the value.
fn v0_61_fraction(time: jiff::Timestamp) -> String {
    let nanos = time.as_nanosecond().rem_euclid(1_000_000_000);
    if nanos == 0 {
        String::new()
    } else if nanos % 1_000_000 == 0 {
        format!(".{:03}", nanos / 1_000_000)
    } else if nanos % 1_000 == 0 {
        format!(".{:06}", nanos / 1_000)
    } else {
        format!(".{nanos:09}")
    }
}

/// Returns `time` as the 0.61 format stored a `DateTime<Utc>` with chrono's
/// default serde, such as `2026-03-15T15:00:04.100Z`.
pub(crate) fn v0_61_serde_string(time: jiff::Timestamp) -> String {
    format!(
        "{}{}Z",
        time.strftime("%Y-%m-%dT%H:%M:%S"),
        v0_61_fraction(time)
    )
}

/// Returns `time` as the 0.61 format stored a `NaiveDateTime` with chrono's
/// default serde, such as `2026-03-15T15:00:04.100`.
pub(crate) fn v0_61_naive_string(time: jiff::Timestamp) -> String {
    format!(
        "{}{}",
        time.strftime("%Y-%m-%dT%H:%M:%S"),
        v0_61_fraction(time)
    )
}

/// Returns `time` as the 0.61 format stored a `DateTime<Utc>` as chrono's
/// `Display` text, such as `2026-03-15 15:00:04.100 UTC`.
pub(crate) fn v0_61_display_string(time: jiff::Timestamp) -> String {
    format!(
        "{}{} UTC",
        time.strftime("%Y-%m-%d %H:%M:%S"),
        v0_61_fraction(time)
    )
}
