//! The detection events a detection engine reports, as the database stores
//! them.
//!
//! A record holds one [`DetectionEvent`] together with the
//! [`DetectionEventStamp`] its receiver recorded and the country code of
//! each of its endpoint addresses. Its key is
//! `(time_ns << 64) | (detection_model << 32) | seq`, where `time_ns` is the
//! event's `time` in signed epoch nanoseconds, `detection_model` the number
//! of its [`DetectionModel`], and `seq` tells apart records sharing both.

mod filter;
mod record;
mod triage;

#[cfg(test)]
pub(crate) mod fixture;
#[cfg(test)]
mod key_baseline;

use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use rand::{Rng, rng};
use review_protocol::types::{DetectionEvent, DetectionModel, RawEventKind};
pub use rocksdb::Direction;
use rocksdb::IteratorMode;
use serde::{Deserialize, Serialize};
use tracing::warn;

pub use self::{
    filter::{EventFilter, InternalNetworks, LearningMethod, TimeSeriesPolicySensors},
    record::{DetectionEventStamp, StoredDetectionEvent},
    triage::TriageScore,
};
use super::timestamp;

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

/// Returns a key no record occupies with the time and detection model of
/// `base`, read for update within `txn`, or `None` if every one is taken.
fn free_event_key(
    txn: &rocksdb::Transaction<rocksdb::OptimisticTransactionDB>,
    base: i128,
) -> Result<Option<i128>> {
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
    country_lookup: Option<crate::geo::SharedCountryLookup>,
}

impl<'a> EventDb<'a> {
    #[must_use]
    pub fn new(inner: &'a rocksdb::OptimisticTransactionDB) -> EventDb<'a> {
        Self {
            inner,
            country_lookup: None,
        }
    }

    #[must_use]
    pub(crate) fn new_with_country_lookup(
        inner: &'a rocksdb::OptimisticTransactionDB,
        country_lookup: Option<crate::geo::SharedCountryLookup>,
    ) -> EventDb<'a> {
        Self {
            inner,
            country_lookup,
        }
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
    /// # Errors
    ///
    /// Returns an error if the event cannot be serialized, if no key is free
    /// at its time and detection model, or if a database operation fails.
    pub fn put(&self, event: &DetectionEvent, stamp: &DetectionEventStamp) -> Result<i128> {
        let event_bytes = record::encode_event(event)?;
        let value = record::encode_record(
            &event_bytes,
            stamp,
            &record::country_codes(event, self.country_lookup.as_deref()),
        )?;
        let base = event_key_base(event);
        loop {
            let txn = self.inner.transaction();
            let Some(key) = free_event_key(&txn, base)? else {
                bail!(TOO_MANY_EVENTS);
            };
            txn.put(key.to_be_bytes(), value.as_slice())
                .context("cannot write event")?;
            match txn.commit() {
                Ok(()) => return Ok(key),
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
    ///
    /// # Errors
    ///
    /// Returns an error only if a database operation fails.
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
            match txn.commit() {
                Ok(()) => return Ok(PutOutcome::Stored(key)),
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

    /// Removes all records whose timestamp is strictly before `before`.
    ///
    /// Event keys are interpreted in signed `i128` chronological order. The
    /// upper 64 bits encode signed epoch nanoseconds. A record exactly at
    /// `before` is retained, and cutoffs outside the supported `i64`
    /// epoch-nanosecond range delete none or all records as appropriate.
    ///
    /// Returns the number of records deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn remove_before(&self, before: Timestamp) -> Result<u64> {
        let cutoff_nanos = before.as_nanosecond();
        if cutoff_nanos <= i128::from(i64::MIN) {
            return Ok(0);
        }

        if cutoff_nanos > i128::from(i64::MAX) {
            let negative = self.delete_event_region(EventKeyRegion::Negative, None)?;
            let non_negative = self.delete_event_region(EventKeyRegion::NonNegative, None)?;
            return Ok(negative + non_negative);
        }

        let cutoff_nanos = i64::try_from(cutoff_nanos)
            .context("cutoff within the checked i64 epoch-nanosecond range")?;
        let cutoff_key = (i128::from(cutoff_nanos) << 64).to_be_bytes();
        if cutoff_nanos < 0 {
            self.delete_event_region(EventKeyRegion::Negative, Some(cutoff_key))
        } else {
            let negative = self.delete_event_region(EventKeyRegion::Negative, None)?;
            let non_negative = if cutoff_key == FIRST_NON_NEGATIVE_EVENT_KEY {
                0
            } else {
                self.delete_event_region(EventKeyRegion::NonNegative, Some(cutoff_key))?
            };
            Ok(negative + non_negative)
        }
    }

    fn delete_event_region(
        &self,
        region: EventKeyRegion,
        upper_bound: Option<[u8; 16]>,
    ) -> Result<u64> {
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
        let iter = self.inner.iterator_opt(mode, readopts);
        let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();
        let mut batch_count = 0_usize;
        let mut deleted = 0_u64;

        for item in iter {
            let (key, _value) = item.context("cannot read from event database")?;
            if signed_event_key(&key).is_none() {
                continue;
            }
            batch.delete(&key);
            batch_count += 1;

            if batch_count == EVENT_DELETION_BATCH_SIZE {
                self.inner
                    .write(std::mem::take(&mut batch))
                    .context("failed to delete expired events")?;
                deleted += u64::try_from(batch_count).expect("batch size fits in u64");
                batch_count = 0;
            }
        }

        if batch_count > 0 {
            self.inner
                .write(batch)
                .context("failed to delete expired events")?;
            deleted += u64::try_from(batch_count).expect("batch size fits in u64");
        }
        Ok(deleted)
    }

    /// Removes all records whose event's `sensor` is `Some` and exactly
    /// matches one of `sensors`. A record with no sensor is kept.
    ///
    /// # Errors
    ///
    /// Returns an error if a record cannot be read or decoded, or if a
    /// database operation fails.
    pub fn remove_by_sensors(&self, sensors: &[String]) -> Result<()> {
        if sensors.is_empty() {
            return Ok(());
        }

        let sensors: HashSet<&str> = sensors.iter().map(String::as_str).collect();
        let iter = self.inner.iterator(IteratorMode::Start);
        let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();
        let mut batch_count = 0;

        for item in iter {
            let (key, value) = item.context("cannot read from event database")?;
            if signed_event_key(&key).is_none() {
                bail!("event key must be 16 bytes, got {}", key.len());
            }
            let record = record::decode_record(&value).context("invalid event value")?;
            if record
                .event
                .sensor
                .as_deref()
                .is_some_and(|sensor| sensors.contains(sensor))
            {
                batch.delete(&key);
                batch_count += 1;
            }

            if batch_count >= EVENT_DELETION_BATCH_SIZE {
                self.inner
                    .write(std::mem::take(&mut batch))
                    .context("failed to delete events by sensor")?;
                batch_count = 0;
            }
        }

        if batch_count > 0 {
            self.inner
                .write(batch)
                .context("failed to delete events by sensor")?;
        }

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
