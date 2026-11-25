//! The detection events a detection engine reports, as the database stores
//! them.
//!
//! A record holds one [`DetectionEvent`] together with the
//! [`DetectionEventStamp`] its receiver recorded and the country code of
//! each of its endpoint addresses. Its key is
//! `(time_ns << 64) | (detection_model << 32) | seq`, where `time_ns` is the
//! event's `time` in signed epoch nanoseconds, `detection_model` the number
//! of its [`DetectionModel`], and `seq` tells apart records sharing both.
//!
//! Each record also has a row in the arrival-order index, which
//! [`EventDb::read_by_arrival`] follows; see [`ArrivalKey`].

mod arrival;
mod filter;
mod record;
mod triage;

#[cfg(test)]
mod endpoint_tests;
#[cfg(test)]
pub(crate) mod fixture;
#[cfg(test)]
mod format_baseline;
#[cfg(test)]
mod key_baseline;

use std::{collections::HashSet, sync::Arc};

use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use rand::{Rng, rng};
use review_protocol::types::{DetectionEvent, DetectionModel, RawEventKind};
pub use rocksdb::Direction;
use rocksdb::IteratorMode;
use serde::{Deserialize, Serialize};
use tracing::warn;

#[cfg(test)]
pub(crate) use self::arrival::ArrivalHookPoint;
pub(crate) use self::arrival::ArrivalState;
pub use self::{
    arrival::{ArrivalKey, ArrivalKeyLengthError, ArrivalPage},
    filter::{EventFilter, InternalNetworks, LearningMethod, TimeSeriesPolicySensors},
    record::{DetectionEventStamp, StoredDetectionEvent},
    triage::TriageScore,
};
use super::timestamp;
use crate::tables::{DETECTION_EVENT_ARRIVAL, LAST_DETECTION_EVENT_ARRIVAL, META};

const EVENT_DELETION_BATCH_SIZE: usize = 1000;
const FIRST_NON_NEGATIVE_EVENT_KEY: [u8; 16] = 0_i128.to_be_bytes();
const FIRST_NEGATIVE_EVENT_KEY: [u8; 16] = i128::MIN.to_be_bytes();
/// The length of the leading bytes of an event key that hold its time.
const EVENT_KEY_TIME_LEN: usize = 8;
/// The length of the leading bytes of an event key that hold its time and
/// detection model; the remaining four tell apart records sharing both.
const EVENT_KEY_TIME_AND_MODEL_LEN: usize = 12;
const TOO_MANY_EVENTS: &str = "too many events with the same timestamp";

/// The most raw event keys one [`EventDb::find_by_raw_event_keys`] call
/// accepts.
pub const MAX_RAW_EVENT_KEYS: usize = 1000;

type PhysicalEventDb = rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>;
type PhysicalEventIterator<'i> = rocksdb::DBIteratorWithThreadMode<'i, PhysicalEventDb>;
type PhysicalEventSnapshot<'i> = rocksdb::SnapshotWithThreadMode<'i, PhysicalEventDb>;

#[derive(Clone, Copy)]
enum EventKeyRegion {
    NonNegative,
    Negative,
}

fn signed_event_key(key_bytes: &[u8]) -> Option<i128> {
    let key_bytes: [u8; 16] = key_bytes.try_into().ok()?;
    Some(i128::from_be_bytes(key_bytes))
}

fn is_signed_negative(key_bytes: &[u8]) -> bool {
    signed_event_key(key_bytes).is_some_and(i128::is_negative)
}

/// Returns the detection model number a key holds.
fn key_detection_model_number(key: i128) -> u32 {
    let bytes = key.to_be_bytes();
    u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]])
}

fn event_region_read_options(region: EventKeyRegion) -> rocksdb::ReadOptions {
    let mut readopts = rocksdb::ReadOptions::default();
    match region {
        // The physical database starts with non-negative i128 keys. The first
        // negative key is therefore the exclusive end of this region.
        EventKeyRegion::NonNegative => {
            readopts.set_iterate_upper_bound(FIRST_NEGATIVE_EVENT_KEY);
        }
        // Negative i128 keys occupy the remainder of the physical key space.
        EventKeyRegion::Negative => {
            readopts.set_iterate_lower_bound(FIRST_NEGATIVE_EVENT_KEY);
        }
    }
    readopts
}

fn physical_event_iterator<'i>(
    snapshot: &PhysicalEventSnapshot<'i>,
    region: EventKeyRegion,
    mode: IteratorMode<'_>,
) -> PhysicalEventIterator<'i> {
    snapshot.iterator_opt(mode, event_region_read_options(region))
}

/// The outcome of [`EventDb::put_unless_stored`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PutOutcome {
    /// The event was stored under this key.
    Stored(i128),
    /// The same event was already stored; nothing was written.
    AlreadyStored,
    /// The event can never be stored, for the given reason; nothing was
    /// written.
    Rejected(String),
}

/// A raw event, named by what identifies it: its kind, its sensor and its
/// time, the Giganto key timestamp.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawEventKey {
    pub raw_event_kind: RawEventKind,
    pub sensor: String,
    pub time: Timestamp,
}

/// Returns the key of `event` with its time and detection model and a zero
/// counter.
fn event_key_base(event: &DetectionEvent) -> i128 {
    (i128::from(timestamp::event_key_nanos(event.time)) << 64)
        | (i128::from(u32::from(event.detection_model)) << 32)
}

#[cfg(test)]
thread_local! {
    /// Makes [`free_event_key`] find no free key on this thread, so that the
    /// tests can reach the outcome of a full time and detection model
    /// without writing 2^32 records.
    static NO_FREE_KEY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Returns a key no record occupies with the time and detection model of
/// `base`, read for update within `txn`, or `None` if every one is taken.
fn free_event_key(
    txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
    base: i128,
) -> Result<Option<i128>> {
    #[cfg(test)]
    if NO_FREE_KEY.get() {
        return Ok(None);
    }
    let mut key = base;
    if txn
        .get_for_update(key.to_be_bytes(), super::EXCLUSIVE)
        .context("cannot read from event database")?
        .is_some()
    {
        let start = i128::from(rng().next_u32());
        key |= start;
        #[allow(clippy::cast_possible_wrap)] // bit pattern
        while txn
            .get_for_update(key.to_be_bytes(), super::EXCLUSIVE)
            .context("cannot read from event database")?
            .is_some()
        {
            let next = (key + 1) & 0xffff_ffff;
            if next == start {
                return Ok(None);
            }
            key = key & 0xffff_ffff_ffff_ffff_ffff_ffff_0000_0000_u128 as i128 | next;
        }
    }
    Ok(Some(key))
}

#[allow(clippy::module_name_repetitions)]
pub struct EventDb<'a> {
    inner: &'a rocksdb::OptimisticTransactionDB,
    /// The arrival lock, shared by every view of an opened store.
    arrival: Arc<ArrivalState>,
    country_lookup: Option<crate::geo::SharedCountryLookup>,
}

impl<'a> EventDb<'a> {
    /// Creates a view of `inner` with an arrival lock of its own, not shared
    /// with any other view.
    ///
    /// Writes through it and through another view of the same database are
    /// not stamped under one lock, so a reader of the arrival index could
    /// miss a record; only the tests, which open a database by itself, use
    /// it.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(inner: &'a rocksdb::OptimisticTransactionDB) -> EventDb<'a> {
        Self {
            inner,
            arrival: Arc::default(),
            country_lookup: None,
        }
    }

    #[must_use]
    pub(crate) fn new_with_country_lookup(
        inner: &'a rocksdb::OptimisticTransactionDB,
        arrival: Arc<ArrivalState>,
        country_lookup: Option<crate::geo::SharedCountryLookup>,
    ) -> EventDb<'a> {
        Self {
            inner,
            arrival,
            country_lookup,
        }
    }

    /// Returns the column family of the arrival index.
    fn arrival_cf(&self) -> Result<&rocksdb::ColumnFamily> {
        self.inner
            .cf_handle(DETECTION_EVENT_ARRIVAL)
            .with_context(|| format!("the column family \"{DETECTION_EVENT_ARRIVAL}\" is missing"))
    }

    /// Returns the `meta` column family.
    fn meta_cf(&self) -> Result<&rocksdb::ColumnFamily> {
        self.inner
            .cf_handle(META)
            .with_context(|| format!("the column family \"{META}\" is missing"))
    }

    /// Returns the arrival time to stamp on the next record, holding the
    /// arrival lock as `last`.
    ///
    /// The last arrival time is read from the `meta` column family the first
    /// time; `last` is not changed otherwise, so a write that does not commit
    /// leaves it as it was.
    fn stamp_arrival(&self, last: &mut Option<i64>) -> Result<i64> {
        if last.is_none() {
            *last = self
                .inner
                .get_cf(self.meta_cf()?, LAST_DETECTION_EVENT_ARRIVAL)
                .context("cannot read the last detection-event arrival time")?
                .map(|value| arrival::decode_last_arrival(&value))
                .transpose()?;
        }
        let arrival = arrival::next_arrival(self.arrival.now()?, *last)?;
        #[cfg(test)]
        self.arrival.run_hook(ArrivalHookPoint::Stamped(arrival));
        Ok(arrival)
    }

    /// Writes, within `txn`, the index row of the record `key` arriving at
    /// `arrival`, and `arrival` as the last arrival time.
    fn put_arrival(
        &self,
        txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
        arrival: i64,
        key: i128,
    ) -> Result<()> {
        txn.put_cf(
            self.arrival_cf()?,
            ArrivalKey::new(arrival, key).to_bytes(),
            [],
        )
        .context("cannot write the detection-event arrival index")?;
        txn.put_cf(
            self.meta_cf()?,
            LAST_DETECTION_EVENT_ARRIVAL,
            arrival.to_be_bytes(),
        )
        .context("cannot write the last detection-event arrival time")
    }

    /// Takes the arrival lock.
    fn lock_arrival(&self) -> std::sync::MutexGuard<'_, Option<i64>> {
        #[cfg(test)]
        self.arrival.run_hook(ArrivalHookPoint::BeforeLock);
        self.arrival.lock()
    }

    /// Creates an iterator over the stored records, starting inclusively
    /// from `key`.
    ///
    /// Keys are interpreted as signed `i128` values without changing their
    /// stored bytes. Forward iteration yields the nearest key greater than or
    /// equal to `key` first; reverse iteration yields the nearest key less than
    /// or equal to `key` first. Both directions follow signed chronological
    /// order across the Unix epoch.
    #[must_use]
    pub fn iter_from(&self, key: i128, direction: Direction) -> EventIterator<'_> {
        let key_bytes = key.to_be_bytes();
        match (is_signed_negative(&key_bytes), direction) {
            (true, Direction::Forward) => EventIterator::new(
                self.inner,
                EventKeyRegion::Negative,
                IteratorMode::From(&key_bytes, Direction::Forward),
                Some(EventKeyRegion::NonNegative),
                Direction::Forward,
            ),
            (true, Direction::Reverse) => EventIterator::new(
                self.inner,
                EventKeyRegion::Negative,
                IteratorMode::From(&key_bytes, Direction::Reverse),
                None,
                Direction::Reverse,
            ),
            (false, Direction::Forward) => EventIterator::new(
                self.inner,
                EventKeyRegion::NonNegative,
                IteratorMode::From(&key_bytes, Direction::Forward),
                None,
                Direction::Forward,
            ),
            (false, Direction::Reverse) => EventIterator::new(
                self.inner,
                EventKeyRegion::NonNegative,
                IteratorMode::From(&key_bytes, Direction::Reverse),
                Some(EventKeyRegion::Negative),
                Direction::Reverse,
            ),
        }
    }

    /// Creates an iterator over all records in ascending signed `i128`
    /// chronological key order.
    #[must_use]
    pub fn iter_forward(&self) -> EventIterator<'_> {
        EventIterator::new(
            self.inner,
            EventKeyRegion::Negative,
            IteratorMode::From(&FIRST_NEGATIVE_EVENT_KEY, Direction::Forward),
            Some(EventKeyRegion::NonNegative),
            Direction::Forward,
        )
    }

    /// Creates an iterator over all records in descending signed `i128`
    /// chronological key order.
    #[must_use]
    pub fn iter_reverse(&self) -> EventIterator<'_> {
        EventIterator::new(
            self.inner,
            EventKeyRegion::NonNegative,
            IteratorMode::End,
            Some(EventKeyRegion::Negative),
            Direction::Reverse,
        )
    }

    /// Stores a detection event and its stamp, and returns the record's key.
    ///
    /// The event is stored as given: it is not validated, and a record
    /// already holding the same event is not looked for. The country code of
    /// each endpoint address is looked up and stored with the record; without
    /// a country lookup every one is [`crate::COUNTRY_CODE_UNRESOLVED`].
    ///
    /// The record's row in the arrival index is written with it, under an
    /// arrival time later than every one stamped before; see [`ArrivalKey`].
    ///
    /// # Errors
    ///
    /// Returns an error if the event cannot be serialized, if no key is free
    /// at its time and detection model, or if a database operation fails,
    /// including when the database lacks the arrival index or `meta` column
    /// family.
    pub fn put(&self, event: &DetectionEvent, stamp: &DetectionEventStamp) -> Result<i128> {
        let event_bytes = record::encode_event(event)?;
        let value = record::encode_record(
            &event_bytes,
            stamp,
            &record::country_codes(event, self.country_lookup.as_deref()),
        )?;
        let base = event_key_base(event);
        // Held until the write commits, so that the records commit in the
        // order of their arrival times.
        let mut last = self.lock_arrival();
        loop {
            let txn = self.inner.transaction();
            let Some(key) = free_event_key(&txn, base)? else {
                bail!(TOO_MANY_EVENTS);
            };
            txn.put(key.to_be_bytes(), value.as_slice())
                .context("cannot write event")?;
            let arrival = self.stamp_arrival(&mut last)?;
            self.put_arrival(&txn, arrival, key)?;
            match txn.commit() {
                Ok(()) => {
                    *last = Some(arrival);
                    return Ok(key);
                }
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to store event");
                    }
                }
            }
        }
    }

    /// Stores a detection event and its stamp unless the same event is
    /// already stored.
    ///
    /// The event is already stored when a record of the same time and
    /// detection model holds a `DetectionEvent` serialized to identical
    /// bytes, with the same `engine_instance` and `clustering_model_id` in
    /// its stamp; the other stamp fields and the country codes are not
    /// compared. Then nothing is written and the outcome is
    /// [`PutOutcome::AlreadyStored`]. Otherwise the event is stored as
    /// [`EventDb::put`] stores it and the outcome is [`PutOutcome::Stored`]
    /// with its key. An event that can never be stored — it cannot be
    /// serialized, or no key is free at its time and detection model — is
    /// [`PutOutcome::Rejected`] with the reason, and nothing is written.
    /// A stored record gets its row in the arrival index as with
    /// [`EventDb::put`]; an event already stored or rejected gets none.
    ///
    /// # Errors
    ///
    /// Returns an error only if a database operation fails, including when
    /// the database lacks the arrival index or `meta` column family.
    pub fn put_unless_stored(
        &self,
        event: &DetectionEvent,
        stamp: &DetectionEventStamp,
    ) -> Result<PutOutcome> {
        let event_bytes = match record::encode_event(event) {
            Ok(bytes) => bytes,
            Err(e) => return Ok(PutOutcome::Rejected(format!("{e:#}"))),
        };
        let value = match record::encode_record(
            &event_bytes,
            stamp,
            &record::country_codes(event, self.country_lookup.as_deref()),
        ) {
            Ok(value) => value,
            Err(e) => return Ok(PutOutcome::Rejected(format!("{e:#}"))),
        };
        let base = event_key_base(event);
        let key = base.to_be_bytes();
        // An `i128` key is 16 bytes, longer than its time and model.
        let prefix = &key[..EVENT_KEY_TIME_AND_MODEL_LEN];
        // Held until the write commits, so that the records commit in the
        // order of their arrival times.
        let mut last = self.lock_arrival();
        loop {
            let txn = self.inner.transaction();
            // The scan below is not tracked for conflicts, and two calls for
            // one event find different free keys when the first key of its
            // time and model is taken. That first key is read for update
            // before the scan, and written back unchanged when taken: a call
            // committing after this read conflicts with this one, which then
            // retries, and one committing before it is seen by the scan.
            if let Some(first) = txn
                .get_for_update(key, super::EXCLUSIVE)
                .context("cannot read from event database")?
            {
                txn.put(key, first).context("cannot write event")?;
            }
            let mut readopts = rocksdb::ReadOptions::default();
            readopts.set_iterate_range(rocksdb::PrefixRange(prefix));
            for entry in txn.iterator_opt(IteratorMode::From(prefix, Direction::Forward), readopts)
            {
                let (_, stored) = entry.context("cannot read from event database")?;
                if record::is_same_event(&stored, &event_bytes, stamp) {
                    return Ok(PutOutcome::AlreadyStored);
                }
            }
            let Some(key) = free_event_key(&txn, base)? else {
                return Ok(PutOutcome::Rejected(TOO_MANY_EVENTS.to_string()));
            };
            txn.put(key.to_be_bytes(), value.as_slice())
                .context("cannot write event")?;
            let arrival = self.stamp_arrival(&mut last)?;
            self.put_arrival(&txn, arrival, key)?;
            match txn.commit() {
                Ok(()) => {
                    *last = Some(arrival);
                    return Ok(PutOutcome::Stored(key));
                }
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to store event");
                    }
                }
            }
        }
    }

    /// Returns, for each raw event key and in the order given, the records
    /// of detection events about that raw event.
    ///
    /// A key's list holds, in key order and whatever their detection model,
    /// the records whose target is a [`Target::RawEvent`] at the key's
    /// `time`, whose `time` is that time as well, whose `raw_event_kind` is
    /// the key's and whose `sensor` is the key's sensor. Only the records of
    /// that time's nanosecond are read; every list is read from one snapshot.
    /// A record with an unknown detection model number is skipped with a
    /// warning.
    ///
    /// [`Target::RawEvent`]: review_protocol::types::Target::RawEvent
    ///
    /// # Errors
    ///
    /// Returns an error, and no result, if `keys` holds more than
    /// [`MAX_RAW_EVENT_KEYS`] keys, if a record read cannot be decoded, or
    /// if a database operation fails.
    pub fn find_by_raw_event_keys(
        &self,
        keys: &[RawEventKey],
    ) -> Result<Vec<Vec<(i128, StoredDetectionEvent)>>> {
        if keys.len() > MAX_RAW_EVENT_KEYS {
            bail!(
                "{} raw event keys exceed the maximum of {MAX_RAW_EVENT_KEYS}",
                keys.len()
            );
        }
        let snapshot = self.inner.snapshot();
        keys.iter()
            .map(|raw_event| {
                let prefix: [u8; EVENT_KEY_TIME_LEN] =
                    timestamp::event_key_nanos(raw_event.time).to_be_bytes();
                // The range ends where the prefix, read as a big-endian
                // number, would be incremented. For the last nanosecond before
                // the Unix epoch the prefix is all `0xff`, and the range runs
                // to the end of the key space, where the keys of that
                // nanosecond are the last ones.
                let mut readopts = rocksdb::ReadOptions::default();
                readopts.set_iterate_range(rocksdb::PrefixRange(&prefix[..]));
                let mut found = Vec::new();
                for entry in
                    snapshot.iterator_opt(IteratorMode::From(&prefix, Direction::Forward), readopts)
                {
                    let (key, value) = entry.context("cannot read from event database")?;
                    let key = signed_event_key(&key).with_context(|| {
                        format!("event key must be 16 bytes, got {}", key.len())
                    })?;
                    let model = key_detection_model_number(key);
                    if DetectionModel::try_from(model).is_err() {
                        warn!("Unknown detection model: {model}; skipped");
                        continue;
                    }
                    let record = record::decode_record(&value)
                        .with_context(|| format!("invalid event record at key {key}"))?;
                    if record.is_about_raw_event(raw_event) {
                        found.push((key, record));
                    }
                }
                Ok(found)
            })
            .collect()
    }

    /// Reads the records matching `filter` in the order they arrived,
    /// following the arrival index from the row after `after`, or from its
    /// start when `after` is `None`.
    ///
    /// The read stops once it has `first` matching records or has scanned
    /// `max_scan` index rows, whichever comes first, or at the end of the
    /// index. Every row it looks at counts as scanned: one whose record
    /// matches, one whose record does not, and one whose record is gone,
    /// which is skipped. A row whose record has an unknown detection model
    /// number or cannot be decoded is skipped with a warning and counted as
    /// scanned too, so that the next read goes past it.
    ///
    /// A record matches exactly when [`StoredDetectionEvent::matches`]
    /// says it does, as in the reads in key order; the read adds no condition
    /// and drops none. The index and the records are read from one snapshot.
    ///
    /// A row committed after another always has a later key, so a read from
    /// the last row a read scanned misses no record stored since.
    ///
    /// # Errors
    ///
    /// Returns an error if the database lacks the arrival index, if an index
    /// key is not 24 bytes long, or if a database operation fails.
    pub fn read_by_arrival(
        &self,
        filter: &EventFilter,
        after: Option<ArrivalKey>,
        first: usize,
        max_scan: usize,
    ) -> Result<ArrivalPage> {
        let index = self.arrival_cf()?;
        let snapshot = self.inner.snapshot();
        let start = after.map(|key| key.to_bytes());
        let mode = match &start {
            Some(start) => IteratorMode::From(start, Direction::Forward),
            None => IteratorMode::Start,
        };
        let mut rows = snapshot.iterator_cf_opt(index, rocksdb::ReadOptions::default(), mode);
        let mut page = ArrivalPage {
            events: Vec::new(),
            last_scanned: None,
            has_more: false,
        };
        let mut scanned = 0_usize;
        for row in &mut rows {
            let (row_key, _) = row.context("cannot read the detection-event arrival index")?;
            let row_key = ArrivalKey::try_from(&*row_key)
                .context("invalid detection-event arrival index key")?;
            if Some(row_key) == after {
                continue;
            }
            if scanned == max_scan || page.events.len() == first {
                page.has_more = true;
                break;
            }
            scanned += 1;
            page.last_scanned = Some(row_key);

            let key = row_key.event_key();
            let Some(value) = snapshot
                .get(key.to_be_bytes())
                .context("cannot read from event database")?
            else {
                continue;
            };
            let model = key_detection_model_number(key);
            if DetectionModel::try_from(model).is_err() {
                warn!("Unknown detection model: {model} at event key {key}; skipped");
                continue;
            }
            let record = match record::decode_record(&value) {
                Ok(record) => record,
                Err(e) => {
                    warn!("Invalid event record at key {key}: {e:#}; skipped");
                    continue;
                }
            };
            if record.matches(filter)?.0 {
                page.events.push((key, record));
            }
        }
        Ok(page)
    }

    /// Removes all records whose timestamp is strictly before `before`.
    ///
    /// Event keys are interpreted in signed `i128` chronological order. The
    /// upper 64 bits encode signed epoch nanoseconds. A record exactly at
    /// `before` is retained, and cutoffs outside the supported `i64`
    /// epoch-nanosecond range delete none or all records as appropriate.
    ///
    /// Each record removed goes in the same write as its arrival index rows,
    /// so that no row outlives its record and comes to name a record stored
    /// later under the same key. Rows before `before` whose record was
    /// already gone are removed as well; no other row is. The rows of the
    /// records removed are held in memory until they are deleted.
    ///
    /// Returns the number of records deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails, including when the
    /// database lacks the arrival index column family.
    pub fn remove_before(&self, before: Timestamp) -> Result<u64> {
        const CONTEXT: &str = "failed to delete expired events";

        let cutoff_nanos = before.as_nanosecond();
        if cutoff_nanos <= i128::from(i64::MIN) {
            return Ok(0);
        }

        // Held until the last record is removed, so that no other removal
        // deletes a record stored under a key this one freed; see
        // `Removal`.
        let _removal = self.arrival.lock_removal();
        // The records and the index rows removed are those of one snapshot,
        // so that a record stored meanwhile keeps its index row.
        let snapshot = self.inner.snapshot();
        if cutoff_nanos > i128::from(i64::MAX) {
            let mut removal = Removal::new(self, self.arrival_rows(&snapshot, |_| true)?, CONTEXT)?;
            removal.remove_region(&snapshot, EventKeyRegion::Negative, None)?;
            removal.remove_region(&snapshot, EventKeyRegion::NonNegative, None)?;
            return removal.finish();
        }

        let cutoff_nanos = i64::try_from(cutoff_nanos)
            .context("cutoff within the checked i64 epoch-nanosecond range")?;
        let cutoff = i128::from(cutoff_nanos) << 64;
        let cutoff_key = cutoff.to_be_bytes();
        let mut removal = Removal::new(
            self,
            self.arrival_rows(&snapshot, |key| key < cutoff)?,
            CONTEXT,
        )?;
        if cutoff_nanos < 0 {
            removal.remove_region(&snapshot, EventKeyRegion::Negative, Some(cutoff_key))?;
        } else {
            removal.remove_region(&snapshot, EventKeyRegion::Negative, None)?;
            if cutoff_key != FIRST_NON_NEGATIVE_EVENT_KEY {
                removal.remove_region(&snapshot, EventKeyRegion::NonNegative, Some(cutoff_key))?;
            }
        }
        removal.finish()
    }

    /// Returns the arrival index rows in `snapshot` whose record key
    /// `removed` accepts, sorted by record key and then by arrival time.
    fn arrival_rows(
        &self,
        snapshot: &PhysicalEventSnapshot<'_>,
        removed: impl Fn(i128) -> bool,
    ) -> Result<Vec<ArrivalKey>> {
        let rows = snapshot.iterator_cf_opt(
            self.arrival_cf()?,
            rocksdb::ReadOptions::default(),
            IteratorMode::Start,
        );
        let mut found = Vec::new();
        for row in rows {
            let (row_key, _) = row.context("cannot read the detection-event arrival index")?;
            let Ok(key) = ArrivalKey::try_from(&*row_key) else {
                continue;
            };
            if removed(key.event_key()) {
                found.push(key);
            }
        }
        found.sort_unstable_by_key(|key| (key.event_key(), key.arrival()));
        Ok(found)
    }

    /// Removes all records whose event's `sensor` is `Some` and exactly
    /// matches one of `sensors`. A record with no sensor is kept.
    ///
    /// Each record removed goes in the same write as its arrival index rows,
    /// as in [`EventDb::remove_before`], and no other row is removed. The
    /// keys of the records removed, and their rows, are held in memory until
    /// they are deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if a record cannot be read or decoded, or if a
    /// database operation fails, including when the database lacks the
    /// arrival index column family.
    pub fn remove_by_sensors(&self, sensors: &[String]) -> Result<()> {
        if sensors.is_empty() {
            return Ok(());
        }

        let sensors: HashSet<&str> = sensors.iter().map(String::as_str).collect();
        // Held until the last record is removed; see `remove_before`.
        let _removal = self.arrival.lock_removal();
        // The records and the index rows removed are those of one snapshot,
        // so that a record stored meanwhile keeps its index row.
        let snapshot = self.inner.snapshot();
        let mut removed = Vec::new();
        for item in snapshot.iterator(IteratorMode::Start) {
            let (key, value) = item.context("cannot read from event database")?;
            let Some(signed_key) = signed_event_key(&key) else {
                bail!("event key must be 16 bytes, got {}", key.len());
            };
            let record = record::decode_record(&value).context("invalid event value")?;
            if record
                .event
                .sensor
                .as_deref()
                .is_some_and(|sensor| sensors.contains(sensor))
            {
                removed.push(signed_key);
            }
        }
        if removed.is_empty() {
            return Ok(());
        }

        removed.sort_unstable();
        let rows = self.arrival_rows(&snapshot, |key| removed.binary_search(&key).is_ok())?;
        let mut removal = Removal::new(self, rows, "failed to delete events by sensor")?;
        for key in removed {
            removal.remove(key)?;
        }
        removal.finish()?;
        Ok(())
    }

    /// Inserts a raw key-value pair into the event database.
    #[cfg(test)]
    fn put_raw(&self, key: &[u8], value: &[u8]) {
        self.inner.put(key, value).expect("put_raw should succeed");
    }

    /// Returns the number of key-value pairs in the event database.
    #[cfg(test)]
    fn raw_count(&self) -> usize {
        self.inner.iterator(IteratorMode::Start).count()
    }

    /// Returns the first record's on-disk key bytes in physical order.
    #[cfg(test)]
    fn first_raw_event_key(&self) -> Result<Option<[u8; 16]>> {
        let mut iter = self.inner.iterator(IteratorMode::Start);
        match iter
            .next()
            .transpose()
            .context("cannot read from event database")?
        {
            None => Ok(None),
            Some((key, _value)) => {
                let key_bytes: [u8; 16] = key.as_ref().try_into().map_err(|_| {
                    anyhow::anyhow!("event key must be 16 bytes, got {}", key.len())
                })?;
                Ok(Some(key_bytes))
            }
        }
    }
}

/// A removal of records, written in batches that each hold the records'
/// arrival index rows along with them.
///
/// A record and its rows are deleted in one write, so that a reader of the
/// index never sees a row whose record key is free: a record stored under
/// that key later would be read where the old row sorts, ahead of records
/// that arrived before it. The removal lock, held by the caller, keeps a
/// second removal from deleting, by a key it read before this one freed it,
/// a record stored there since, which would leave that record's row behind
/// in the same way.
struct Removal<'d> {
    inner: &'d rocksdb::OptimisticTransactionDB,
    #[cfg(test)]
    arrival: &'d ArrivalState,
    index: &'d rocksdb::ColumnFamily,
    /// The rows to remove, sorted by record key and then by arrival time.
    rows: Vec<ArrivalKey>,
    /// Whether each of `rows` has been put in a batch.
    queued: Vec<bool>,
    context: &'static str,
    batch: rocksdb::WriteBatchWithTransaction<true>,
    batch_count: usize,
    removed: u64,
}

impl<'d> Removal<'d> {
    /// Starts a removal of records whose arrival index rows are among
    /// `rows`, with `context` for the errors of its writes.
    fn new(db: &'d EventDb<'_>, rows: Vec<ArrivalKey>, context: &'static str) -> Result<Self> {
        Ok(Self {
            inner: db.inner,
            #[cfg(test)]
            arrival: &db.arrival,
            index: db.arrival_cf()?,
            queued: vec![false; rows.len()],
            rows,
            context,
            batch: rocksdb::WriteBatchWithTransaction::default(),
            batch_count: 0,
            removed: 0,
        })
    }

    /// Removes the record `key` and its rows, in the same batch.
    fn remove(&mut self, key: i128) -> Result<()> {
        self.batch.delete(key.to_be_bytes());
        self.batch_count += 1;
        let start = self.rows.partition_point(|row| row.event_key() < key);
        // `partition_point` returns at most `rows.len()`.
        for (row, queued) in self.rows[start..]
            .iter()
            .zip(&mut self.queued[start..])
            .take_while(|(row, _)| row.event_key() == key)
        {
            self.batch.delete_cf(self.index, row.to_bytes());
            self.batch_count += 1;
            *queued = true;
        }
        self.removed += 1;
        if self.batch_count >= EVENT_DELETION_BATCH_SIZE {
            self.write()?;
        }
        Ok(())
    }

    /// Removes the records of `region` in `snapshot` whose key is before
    /// `upper_bound`, or all of them.
    fn remove_region(
        &mut self,
        snapshot: &PhysicalEventSnapshot<'_>,
        region: EventKeyRegion,
        upper_bound: Option<[u8; 16]>,
    ) -> Result<()> {
        let mut readopts = event_region_read_options(region);
        if let Some(upper_bound) = upper_bound {
            readopts.set_iterate_upper_bound(upper_bound);
        }
        let mode = match region {
            EventKeyRegion::NonNegative => IteratorMode::Start,
            EventKeyRegion::Negative => {
                IteratorMode::From(&FIRST_NEGATIVE_EVENT_KEY, Direction::Forward)
            }
        };
        for item in snapshot.iterator_opt(mode, readopts) {
            let (key, _value) = item.context("cannot read from event database")?;
            let Some(key) = signed_event_key(&key) else {
                continue;
            };
            self.remove(key)?;
        }
        Ok(())
    }

    /// Removes the rows whose record was not removed, which were left
    /// behind with no record, writes what remains, and returns the number
    /// of records removed.
    fn finish(mut self) -> Result<u64> {
        let rows = std::mem::take(&mut self.rows);
        let queued = std::mem::take(&mut self.queued);
        for (row, _) in rows.iter().zip(queued).filter(|(_, queued)| !queued) {
            self.batch.delete_cf(self.index, row.to_bytes());
            self.batch_count += 1;
            if self.batch_count >= EVENT_DELETION_BATCH_SIZE {
                self.write()?;
            }
        }
        self.write()?;
        Ok(self.removed)
    }

    /// Writes the batch, if it holds anything.
    fn write(&mut self) -> Result<()> {
        if self.batch_count == 0 {
            return Ok(());
        }
        self.inner
            .write(std::mem::take(&mut self.batch))
            .context(self.context)?;
        self.batch_count = 0;
        #[cfg(test)]
        self.arrival.run_hook(ArrivalHookPoint::Removed);
        Ok(())
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct EventIterator<'i> {
    // The iterator must be dropped before the snapshot it uses.
    inner: PhysicalEventIterator<'i>,
    snapshot: PhysicalEventSnapshot<'i>,
    next_region: Option<EventKeyRegion>,
    direction: Direction,
    failed: bool,
}

impl<'i> EventIterator<'i> {
    fn new(
        db: &'i rocksdb::OptimisticTransactionDB,
        region: EventKeyRegion,
        mode: IteratorMode<'_>,
        next_region: Option<EventKeyRegion>,
        direction: Direction,
    ) -> Self {
        let snapshot = db.snapshot();
        let inner = physical_event_iterator(&snapshot, region, mode);
        Self {
            inner,
            snapshot,
            next_region,
            direction,
            failed: false,
        }
    }

    fn advance_region(&mut self) -> bool {
        let Some(region) = self.next_region.take() else {
            return false;
        };
        let mode = match self.direction {
            Direction::Forward => IteratorMode::Start,
            Direction::Reverse => IteratorMode::End,
        };
        self.inner = physical_event_iterator(&self.snapshot, region, mode);
        true
    }
}

impl Iterator for EventIterator<'_> {
    type Item = Result<(i128, StoredDetectionEvent), InvalidEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        loop {
            let (k, v) = match self.inner.next() {
                Some(Ok(item)) => item,
                None if self.advance_region() => continue,
                Some(Err(error)) => {
                    self.failed = true;
                    return Some(Err(InvalidEvent::Iteration(error)));
                }
                None => return None,
            };

            let Some(key) = signed_event_key(&k) else {
                return Some(Err(InvalidEvent::Key(k)));
            };
            let model = key_detection_model_number(key);
            if DetectionModel::try_from(model).is_err() {
                warn!("Unknown detection model: {model}; skipped");
                continue;
            }
            return Some(match record::decode_record(&v) {
                Ok(record) => Ok((key, record)),
                Err(_) => Err(InvalidEvent::Value(v)),
            });
        }
    }
}

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum InvalidEvent {
    Iteration(rocksdb::Error),
    Key(Box<[u8]>),
    Value(Box<[u8]>),
}

/// Traffic flow direction.
#[derive(Clone, Copy, Eq, PartialEq, Deserialize, Serialize, Debug)]
pub enum FlowKind {
    Inbound,
    Outbound,
    Internal,
}

/// Possible network types of `OwnedNetwork`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum NetworkType {
    Intranet,
    Extranet,
    Gateway,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize, Debug)]
pub enum TrafficDirection {
    From,
    To,
}

#[cfg(test)]
mod tests;
