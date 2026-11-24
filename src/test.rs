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

/// A subscriber that records the fields of every warning event, each event
/// as one line of ` name=value` pairs.
struct WarningLog(std::sync::Arc<Mutex<Vec<String>>>);

/// Formats the fields of an event.
struct Fields(String);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;

        let _ = write!(self.0, " {}={value:?}", field.name());
    }
}

impl tracing::Subscriber for WarningLog {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() == tracing::Level::WARN
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(fields.0);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// A subscriber that wants no event but keeps every callsite asking the
/// current subscriber, registered once for the rest of the test process by
/// [`capture_warnings`].
///
/// While only one dispatcher is registered, `tracing` decides the interest
/// of a callsite first hit on any thread from that thread's own subscriber.
/// A test thread without one then caches the callsite as unwanted, and a
/// warning a concurrent [`capture_warnings`] logs there is dropped. With this
/// one always registered beside the capturing one, every callsite is decided
/// from both, and is asked per event.
struct KeepInterest;

impl tracing::Subscriber for KeepInterest {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        false
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, _: &tracing::Event<'_>) {}

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// The [`KeepInterest`] dispatcher, registered while it lives.
static KEEP_INTEREST: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();

/// Runs `f` with every warning logged on this thread recorded, and returns
/// its output with the warnings, each as one line of ` name=value` pairs.
pub(crate) fn capture_warnings<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
    KEEP_INTEREST.get_or_init(|| tracing::Dispatch::new(KeepInterest));
    let log = std::sync::Arc::new(Mutex::new(Vec::new()));
    let output = tracing::subscriber::with_default(WarningLog(log.clone()), || {
        // A callsite caches whether any subscriber wants it when it is first
        // hit. Another test thread hitting the same callsite with no
        // subscriber while this one's subscriber is being registered can
        // cache it as unwanted, and this thread's warnings are then dropped
        // before reaching the subscriber. Recomputing the cache now, with the
        // subscriber registered, makes every registered callsite see it.
        tracing::callsite::rebuild_interest_cache();
        f()
    });
    let warnings = log
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    (output, warnings)
}

mod tests {
    /// Logs a warning from a callsite no other code hits.
    fn warn_once_more() {
        tracing::warn!(probe = 1, "capture probe");
    }

    #[test]
    fn a_warning_is_captured_after_another_thread_first_hits_its_callsite() {
        let ((), warnings) = super::capture_warnings(|| {
            std::thread::spawn(warn_once_more).join().unwrap();
            warn_once_more();
        });
        assert_eq!(warnings, [" message=capture probe probe=1"]);
    }
}
