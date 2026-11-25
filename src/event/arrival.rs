//! The arrival-order index of detection events.
//!
//! Every record [`EventDb::put`](super::EventDb::put) or
//! [`EventDb::put_unless_stored`](super::EventDb::put_unless_stored) stores
//! gets a row in the `detection event arrival` column family, written in the
//! same transaction. Its key is the record's arrival time, in epoch
//! nanoseconds as a big-endian `i64`, followed by the record's key as a
//! big-endian `i128`; its value is empty.
//!
//! Arrival times are stamped and committed under one lock per opened store,
//! in the same order, and every one is later than the one before. The rows a
//! reader can see are therefore always a prefix of the index in key order: a
//! row committed after a read began sorts after every row that read saw, so
//! a reader that goes on from the last row it scanned misses none.

#[cfg(test)]
use std::sync::Arc;
use std::sync::{Mutex, MutexGuard, PoisonError};

use anyhow::{Context, Result, anyhow};
use thiserror::Error;

use super::StoredDetectionEvent;
#[cfg(test)]
use crate::tables::Clock;

/// The length of an [`ArrivalKey`] in bytes.
const ARRIVAL_KEY_LEN: usize = 24;
/// The length of the leading bytes of an [`ArrivalKey`] that hold its arrival
/// time.
const ARRIVAL_TIME_LEN: usize = 8;

/// The key of a row of the detection-event arrival index: when a record
/// arrived, and the record's key.
///
/// It converts to and from its 24 stored bytes, the arrival time as a
/// big-endian `i64` followed by the record's key as a big-endian `i128`, so a
/// caller can keep one as a cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ArrivalKey {
    arrival: i64,
    event_key: i128,
}

impl ArrivalKey {
    /// Creates the key of the row of the record `event_key` that arrived at
    /// `arrival`, in epoch nanoseconds.
    #[must_use]
    pub fn new(arrival: i64, event_key: i128) -> Self {
        Self { arrival, event_key }
    }

    /// Returns when the record arrived, in epoch nanoseconds.
    #[must_use]
    pub fn arrival(&self) -> i64 {
        self.arrival
    }

    /// Returns the key of the record.
    #[must_use]
    pub fn event_key(&self) -> i128 {
        self.event_key
    }

    /// Returns the 24 bytes the key is stored as.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ARRIVAL_KEY_LEN] {
        let mut bytes = [0; ARRIVAL_KEY_LEN];
        let (arrival, event_key) = bytes.split_at_mut(ARRIVAL_TIME_LEN);
        arrival.copy_from_slice(&self.arrival.to_be_bytes());
        event_key.copy_from_slice(&self.event_key.to_be_bytes());
        bytes
    }
}

impl From<[u8; ARRIVAL_KEY_LEN]> for ArrivalKey {
    fn from(bytes: [u8; ARRIVAL_KEY_LEN]) -> Self {
        let (arrival, event_key) = bytes.split_at(ARRIVAL_TIME_LEN);
        Self {
            arrival: i64::from_be_bytes(arrival.try_into().expect("the split leaves 8 bytes")),
            event_key: i128::from_be_bytes(
                event_key.try_into().expect("the split leaves 16 bytes"),
            ),
        }
    }
}

impl From<ArrivalKey> for [u8; ARRIVAL_KEY_LEN] {
    fn from(key: ArrivalKey) -> Self {
        key.to_bytes()
    }
}

impl TryFrom<&[u8]> for ArrivalKey {
    type Error = ArrivalKeyLengthError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; ARRIVAL_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| ArrivalKeyLengthError(bytes.len()))?;
        Ok(Self::from(bytes))
    }
}

/// The error of reading an [`ArrivalKey`] from bytes that are not 24 long.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("an arrival key is 24 bytes long, not {0}")]
pub struct ArrivalKeyLengthError(pub usize);

/// What [`EventDb::read_by_arrival`](super::EventDb::read_by_arrival)
/// returns.
#[derive(Clone, Debug)]
pub struct ArrivalPage {
    /// The matching records, in arrival order, each with its key.
    pub events: Vec<(i128, StoredDetectionEvent)>,
    /// The last index row the read scanned, or `None` if it scanned none.
    /// The next read goes on from it.
    pub last_scanned: Option<ArrivalKey>,
    /// Whether an index row exists after `last_scanned`, or after the
    /// cursor when nothing was scanned.
    pub has_more: bool,
}

/// The points of a write at which the tests' hook runs.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArrivalHookPoint {
    /// Before the write takes the arrival lock.
    BeforeLock,
    /// After the write stamped this arrival time, holding the lock, before
    /// it commits.
    Stamped(i64),
    /// After a removal wrote one batch of deletions, before it goes on.
    Removed,
}

/// A hook the tests run at every [`ArrivalHookPoint`] of a write or a
/// removal.
#[cfg(test)]
pub(crate) type ArrivalHook = Arc<dyn Fn(ArrivalHookPoint) + Send + Sync>;

/// The arrival lock of an opened store, which every [`super::EventDb`] view
/// of it shares.
///
/// It guards the last arrival time stamped, `None` until it has been read
/// from the `meta` column family. A write holds it from stamping its arrival
/// time until the write commits.
///
/// It also holds the removal lock, which a removal of records holds from
/// taking its snapshot until it has deleted the last of them; see
/// [`super::EventDb::remove_before`].
#[derive(Default)]
pub(crate) struct ArrivalState {
    last: Mutex<Option<i64>>,
    removal: Mutex<()>,
    #[cfg(test)]
    clock: Mutex<Option<Arc<dyn Clock + Send + Sync>>>,
    #[cfg(test)]
    hook: Mutex<Option<ArrivalHook>>,
}

impl ArrivalState {
    /// Takes the arrival lock.
    pub(super) fn lock(&self) -> MutexGuard<'_, Option<i64>> {
        // The last arrival time changes only after a commit succeeds, so a
        // panic while holding the lock leaves it as true as before.
        self.last.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes the removal lock.
    pub(super) fn lock_removal(&self) -> MutexGuard<'_, ()> {
        // It guards no data, so a panic while holding it leaves nothing to
        // repair.
        self.removal.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Forgets the last arrival time, so that the next write reads it from
    /// the `meta` column family again; for a database just reopened.
    pub(crate) fn forget(&self) {
        *self.lock() = None;
    }

    /// Returns the current time in epoch nanoseconds.
    // Only the tests' clock, which outside the tests does not exist, is read
    // from `self`; the method stays one so the writes need not tell them
    // apart.
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    pub(super) fn now(&self) -> Result<i64> {
        #[cfg(test)]
        if let Some(clock) = self
            .clock
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            return clock.now();
        }
        crate::tables::now_nanos()
    }

    /// Makes the writes read the time from `clock`.
    #[cfg(test)]
    pub(crate) fn set_clock(&self, clock: Arc<dyn Clock + Send + Sync>) {
        *self.clock.lock().unwrap_or_else(PoisonError::into_inner) = Some(clock);
    }

    /// Makes the writes and the removals run `hook` at every
    /// [`ArrivalHookPoint`].
    #[cfg(test)]
    pub(crate) fn set_hook(&self, hook: Option<ArrivalHook>) {
        *self.hook.lock().unwrap_or_else(PoisonError::into_inner) = hook;
    }

    /// Runs the tests' hook, if any, at `point`.
    #[cfg(test)]
    pub(super) fn run_hook(&self, point: ArrivalHookPoint) {
        // The hook is cloned out so that a hook that blocks does not keep
        // another write from running it.
        let hook = self
            .hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(hook) = hook {
            hook(point);
        }
    }
}

/// Returns the arrival time to stamp at `now`, after the last one `last`.
///
/// It is `now`, raised to 0 if it is negative, so that the big-endian bytes
/// of every arrival time sort as its value, and to one nanosecond after
/// `last` if it is not later.
pub(super) fn next_arrival(now: i64, last: Option<i64>) -> Result<i64> {
    let now = now.max(0);
    let Some(last) = last else {
        return Ok(now);
    };
    let after = last
        .checked_add(1)
        .ok_or_else(|| anyhow!("no arrival time is left after {last}"))?;
    Ok(now.max(after))
}

/// Reads the last arrival time stored in the `meta` value `value`.
pub(super) fn decode_last_arrival(value: &[u8]) -> Result<i64> {
    let bytes: [u8; ARRIVAL_TIME_LEN] = value.try_into().with_context(|| {
        format!(
            "the last detection-event arrival time must be 8 bytes, got {}",
            value.len()
        )
    })?;
    Ok(i64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests;
