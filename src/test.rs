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
