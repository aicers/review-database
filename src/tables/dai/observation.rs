//! Storing a send of observations.
//!
//! An agent sends each slot of each (sensor, kind) as one send, a random
//! `send_id` with parts `0..part_count`. The parts are staged in
//! `dai send parts` under the send's `dai slot sends` row, and only the
//! arrival of the last missing part applies them: the observations are
//! filtered and upserted, the cursor, the marks, the gaps and the counters
//! move, and the send is marked finished with the marks it returned.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use anyhow::{Context, Result, anyhow};
use review_protocol::types::{
    DaiLateSlot, DaiObservation, DaiObservationBatch, DaiObservationBody, DaiObservationKind,
    DaiReextractMark,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    Dai, FIVE_MINUTES, KeyReader, KeyWriter, SensorState, Txn,
    cursor::{CursorRow, DAY, date_of, pair_key, slot_floor},
    customer_key, dai_network_digest,
    hash::{IDENTIFIER_HASH_LEN, identifier_hash},
    kind_number,
};
use crate::{EXCLUSIVE, OwnedNetworkTable};

/// The slot length, in seconds.
const SLOT_LEN_SECS: u32 = 300;
/// The number of slots confirmed after the cursor a cursor row keeps at
/// most: 7 days of slots.
const MAX_CONFIRMED: usize = 2_016;
/// The age of a slot start after which its observations are kept only in
/// the summaries: 7 days.
pub(super) const PER_SLOT_AGE: i64 = 7 * DAY;
/// The longest string, in bytes, an observation body may hold.
const MAX_STRING_LEN: usize = 512;

/// An identifier hash.
pub(super) type IdHash = [u8; IDENTIFIER_HASH_LEN];

/// The result of storing one part of a send of observations, with the
/// current restore generation.
///
/// The caller answers the agent with the matching `DaiStoreAck`;
/// `NotCollected` is answered as `Stored` with no marks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaiStoreOutcome {
    /// The part is staged and the send is not complete yet.
    Staged {
        /// The current restore generation.
        restore_generation: u64,
    },
    /// The send is complete and its slot is stored.
    Stored {
        /// The current restore generation.
        restore_generation: u64,
        /// The marks assigned to the send's late slots, in their order.
        marks: Vec<DaiReextractMark>,
    },
    /// Nothing was stored; the agent refetches its cursors or configuration
    /// and counts again.
    Resync {
        /// The current restore generation.
        restore_generation: u64,
    },
    /// The sensor is not collected: for observations, it is not a customer
    /// sensor or its customer has device identification off; for a range
    /// day, it is not a customer sensor. Nothing was written.
    NotCollected {
        /// The current restore generation.
        restore_generation: u64,
    },
}

/// A refusal of an invalid part of a send of observations.
///
/// It is returned inside the `anyhow::Error` of
/// [`Store::store_dai_observations`](crate::Store::store_dai_observations),
/// so a caller can `downcast_ref` it. A refused part writes nothing.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DaiBatchError {
    /// The slot length is not 300 seconds.
    #[error("the slot length {secs} s is not 300 s")]
    SlotLength { secs: u32 },
    /// The slot start is not a multiple of 300 seconds.
    #[error("slot start {slot_start} is not a multiple of 300 s")]
    SlotStart { slot_start: i64 },
    /// The part count is 0.
    #[error("the part count is 0")]
    ZeroPartCount,
    /// The part index is not below the part count.
    #[error("part {part} is not below the part count {part_count}")]
    PartOutOfRange { part: u32, part_count: u32 },
    /// `counted_from` is outside the slot.
    #[error("counted_from {counted_from} is outside the slot starting at {slot_start}")]
    CountedFrom { counted_from: i64, slot_start: i64 },
    /// The slot start of a late slot is not a multiple of 300 seconds.
    #[error("late slot start {slot_start} is not a multiple of 300 s")]
    LateSlotStart { slot_start: i64 },
}

/// The kind of a DAI counter, with its fixed number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DaiCounterKind {
    /// Observations filtered at receipt.
    FilteredAtReceipt,
    /// Pending observations deleted before they were applied.
    NotApplied,
    /// Relay DHCP observations whose site could not be determined.
    // Written by the change that applies pending observations, which this
    // one prepares the counter for.
    #[allow(dead_code)]
    RelaySiteUnknown,
    /// Slots skipped by the catch-up limit.
    SkippedByCatchup,
}

impl DaiCounterKind {
    /// Returns the number of the counter kind, the byte its keys hold.
    pub(super) fn number(self) -> u8 {
        match self {
            Self::FilteredAtReceipt => 1,
            Self::NotApplied => 2,
            Self::RelaySiteUnknown => 3,
            Self::SkippedByCatchup => 4,
        }
    }
}

/// The metadata every part of a send carries alike.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SendMeta {
    last_record_time: Option<i64>,
    late_slots: Vec<DaiLateSlot>,
    reextract_mark: Option<u64>,
    lost_before: Option<i64>,
    counted_from: i64,
}

impl SendMeta {
    fn of(batch: &DaiObservationBatch) -> Self {
        Self {
            last_record_time: batch.last_record_time,
            late_slots: batch.late_slots.clone(),
            reextract_mark: batch.reextract_mark,
            lost_before: batch.lost_before,
            counted_from: batch.counted_from,
        }
    }
}

/// The stored value of a `dai slot sends` row.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct SendRow {
    part_count: u32,
    /// The indices of the parts received.
    received: BTreeSet<u32>,
    restore_generation: u64,
    config_epoch: u64,
    network_digest: u64,
    meta: SendMeta,
    /// When the send's first part arrived.
    pub(super) created: i64,
    finished: bool,
    /// The marks the finished send returned.
    marks: Vec<DaiReextractMark>,
}

/// The stored value of a `dai observations` row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct ObservationRow {
    pub(super) customer_id: u32,
    pub(super) site: String,
    pub(super) body: DaiObservationBody,
    pub(super) first_seen: i64,
    pub(super) last_seen: i64,
    pub(super) count: u32,
}

/// The stored value of a `dai observation summaries` or `dai pending` row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct SeenRow {
    pub(super) body: DaiObservationBody,
    pub(super) first_seen: i64,
    pub(super) last_seen: i64,
}

impl SeenRow {
    /// Returns `self` widened by an observation of `body` seen from `first`
    /// to `last`, by the upsert rules.
    pub(super) fn widened(&self, body: &DaiObservationBody, first: i64, last: i64) -> Self {
        Self {
            body: merge_body(&self.body, body),
            first_seen: self.first_seen.min(first),
            last_seen: self.last_seen.max(last),
        }
    }
}

/// The stored value of a `dai ip activity` row.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct ActivityRow {
    pub(super) first_seen: i64,
    pub(super) last_seen: i64,
}

// ---- Keys ----

fn send_key(sensor: &str, kind: DaiObservationKind, slot_start: i64, send_id: u64) -> Vec<u8> {
    KeyWriter::default()
        .str(sensor)
        .dai_kind(kind)
        .i64(slot_start)
        .u64(send_id)
        .finish()
}

/// Returns the key of part `part` of the send whose key is `send`.
pub(super) fn part_key(send: &[u8], part: u32) -> Vec<u8> {
    let mut key = send.to_vec();
    key.extend_from_slice(&part.to_be_bytes());
    key
}

fn gap_key(sensor: &str, kind: DaiObservationKind, start: i64) -> Vec<u8> {
    KeyWriter::default()
        .str(sensor)
        .dai_kind(kind)
        .i64(start)
        .finish()
}

/// Decodes the key of a `dai catchup gaps` row.
pub(super) fn decode_gap_key(key: &[u8]) -> Result<(String, DaiObservationKind, i64)> {
    let mut reader = KeyReader::new(key);
    let sensor = reader.str()?;
    let kind = reader.dai_kind()?;
    let start = reader.i64()?;
    reader.finish()?;
    Ok((sensor, kind, start))
}

pub(super) fn counter_key(customer_id: u32, counter: u8, date: i32) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer_id)
        .byte(counter)
        .date(date)
        .finish()
}

/// Decodes the key of a `dai counters` row.
pub(super) fn decode_counter_key(key: &[u8]) -> Result<(u32, u8, i32)> {
    let mut reader = KeyReader::new(key);
    let customer_id = reader.u32()?;
    let counter = reader.byte()?;
    let date = reader.date()?;
    reader.finish()?;
    Ok((customer_id, counter, date))
}

fn observation_key(
    sensor: &str,
    kind: DaiObservationKind,
    slot_start: i64,
    hash: &IdHash,
) -> Vec<u8> {
    KeyWriter::default()
        .str(sensor)
        .dai_kind(kind)
        .i64(slot_start)
        .hash(hash)
        .finish()
}

/// Decodes the key of a `dai observations` row.
pub(super) fn decode_observation_key(
    key: &[u8],
) -> Result<(String, DaiObservationKind, i64, IdHash)> {
    let mut reader = KeyReader::new(key);
    let sensor = reader.str()?;
    let kind = reader.dai_kind()?;
    let slot_start = reader.i64()?;
    let hash = reader.hash()?;
    reader.finish()?;
    Ok((sensor, kind, slot_start, hash))
}

pub(super) fn summary_key(sensor: &str, kind: DaiObservationKind, hash: &IdHash) -> Vec<u8> {
    KeyWriter::default()
        .str(sensor)
        .dai_kind(kind)
        .hash(hash)
        .finish()
}

pub(super) fn pending_key(
    sensor: &str,
    slot_start: i64,
    kind: DaiObservationKind,
    hash: &IdHash,
) -> Vec<u8> {
    KeyWriter::default()
        .str(sensor)
        .i64(slot_start)
        .dai_kind(kind)
        .hash(hash)
        .finish()
}

/// Decodes the key of a `dai pending` row.
pub(super) fn decode_pending_key(key: &[u8]) -> Result<(String, i64, DaiObservationKind, IdHash)> {
    let mut reader = KeyReader::new(key);
    let sensor = reader.str()?;
    let slot_start = reader.i64()?;
    let kind = reader.dai_kind()?;
    let hash = reader.hash()?;
    reader.finish()?;
    Ok((sensor, slot_start, kind, hash))
}

fn ip_activity_key(customer_id: u32, site: &str, ip: IpAddr) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer_id)
        .str(site)
        .ip(ip)
        .finish()
}

// ---- Checks ----

/// Checks the fields of a part, and returns the end of its slot.
fn check_batch(batch: &DaiObservationBatch) -> Result<i64, DaiBatchError> {
    if batch.slot_len_secs != SLOT_LEN_SECS {
        return Err(DaiBatchError::SlotLength {
            secs: batch.slot_len_secs,
        });
    }
    let slot_start = batch.slot_start;
    let slot_end = if slot_start.rem_euclid(FIVE_MINUTES) == 0 {
        slot_start.checked_add(FIVE_MINUTES)
    } else {
        None
    }
    .ok_or(DaiBatchError::SlotStart { slot_start })?;
    if batch.part_count == 0 {
        return Err(DaiBatchError::ZeroPartCount);
    }
    if batch.part >= batch.part_count {
        return Err(DaiBatchError::PartOutOfRange {
            part: batch.part,
            part_count: batch.part_count,
        });
    }
    if !(slot_start..slot_end).contains(&batch.counted_from) {
        return Err(DaiBatchError::CountedFrom {
            counted_from: batch.counted_from,
            slot_start,
        });
    }
    if let Some(late) = batch
        .late_slots
        .iter()
        .find(|late| late.slot_start.rem_euclid(FIVE_MINUTES) != 0)
    {
        return Err(DaiBatchError::LateSlotStart {
            slot_start: late.slot_start,
        });
    }
    Ok(slot_end)
}

/// Returns the kind of the observations of `body`'s variant.
fn body_kind(body: &DaiObservationBody) -> DaiObservationKind {
    match body {
        DaiObservationBody::DhcpLease { .. } => DaiObservationKind::DhcpLease,
        DaiObservationBody::DhcpServer { .. } => DaiObservationKind::DhcpServer,
        DaiObservationBody::Kerberos { .. } => DaiObservationKind::Kerberos,
        DaiObservationBody::Ntlm { .. } => DaiObservationKind::Ntlm,
        DaiObservationBody::Service { .. } => DaiObservationKind::Service,
        DaiObservationBody::SoftwareString { .. } => DaiObservationKind::SoftwareString,
        DaiObservationBody::DnsName { .. } => DaiObservationKind::DnsName,
        DaiObservationBody::IpActivity { .. } => DaiObservationKind::IpActivity,
    }
}

/// Returns whether a string of `body` is longer than [`MAX_STRING_LEN`]
/// bytes.
fn has_long_string(body: &DaiObservationBody) -> bool {
    let long = |text: &String| text.len() > MAX_STRING_LEN;
    match body {
        DaiObservationBody::DhcpLease { hostname, .. } => hostname.as_ref().is_some_and(long),
        DaiObservationBody::Kerberos {
            realm,
            cname,
            sname,
            ..
        } => long(realm) || cname.iter().chain(sname).any(long),
        DaiObservationBody::Ntlm {
            workstation,
            user,
            domain,
            ..
        } => long(workstation) || long(user) || long(domain),
        DaiObservationBody::SoftwareString { text, .. } => long(text),
        DaiObservationBody::DnsName { name, .. } => long(name),
        DaiObservationBody::DhcpServer { .. }
        | DaiObservationBody::Service { .. }
        | DaiObservationBody::IpActivity { .. } => false,
    }
}

/// Returns why `observation` is filtered at receipt from a part of `kind`
/// whose slot is `slot`, or `None` if it is kept.
fn rejection(
    observation: &DaiObservation,
    kind: DaiObservationKind,
    slot: &std::ops::Range<i64>,
) -> Option<&'static str> {
    if body_kind(&observation.body) != kind {
        return Some("its body does not match the batch kind");
    }
    if !slot.contains(&observation.first_seen) || !slot.contains(&observation.last_seen) {
        return Some("its first or last seen time is outside the slot");
    }
    if let DaiObservationBody::DhcpLease { time, .. } = observation.body
        && !slot.contains(&time)
    {
        return Some("its DHCP lease time is outside the slot");
    }
    if has_long_string(&observation.body) {
        return Some("a string of its body is longer than 512 bytes");
    }
    None
}

// ---- Merging ----

/// Returns the body stored as `stored` merged with `new` of the same
/// identifier: in `DhcpLease`, an empty `client_id`, `hostname`,
/// `lease_secs`, `subnet_mask` or `routers` loses to a filled one, and
/// the stored one stays when both are filled; `Service.external_client`
/// is the logical OR; every other field is the stored one.
pub(super) fn merge_body(
    stored: &DaiObservationBody,
    new: &DaiObservationBody,
) -> DaiObservationBody {
    let mut merged = stored.clone();
    match (&mut merged, new) {
        (
            DaiObservationBody::DhcpLease {
                client_id,
                hostname,
                lease_secs,
                subnet_mask,
                routers,
                ..
            },
            DaiObservationBody::DhcpLease {
                client_id: new_client_id,
                hostname: new_hostname,
                lease_secs: new_lease_secs,
                subnet_mask: new_subnet_mask,
                routers: new_routers,
                ..
            },
        ) => {
            if client_id.as_ref().is_none_or(Vec::is_empty) {
                client_id.clone_from(new_client_id);
            }
            if hostname.as_ref().is_none_or(String::is_empty) {
                hostname.clone_from(new_hostname);
            }
            if lease_secs.is_none() {
                *lease_secs = *new_lease_secs;
            }
            if subnet_mask.is_none() {
                *subnet_mask = *new_subnet_mask;
            }
            if routers.is_empty() {
                routers.clone_from(new_routers);
            }
        }
        (
            DaiObservationBody::Service {
                external_client, ..
            },
            DaiObservationBody::Service {
                external_client: new_external_client,
                ..
            },
        ) => *external_client |= *new_external_client,
        _ => {}
    }
    merged
}

/// Subtracts `[cut_start, cut_end)` from each of the ordered, disjoint
/// `ranges`, keeping them ordered.
fn subtract(ranges: &[(i64, i64)], cut_start: i64, cut_end: i64) -> Vec<(i64, i64)> {
    let mut rest = Vec::with_capacity(ranges.len() + 1);
    for &(start, end) in ranges {
        if cut_end <= start || end <= cut_start {
            rest.push((start, end));
            continue;
        }
        if start < cut_start {
            rest.push((start, cut_start));
        }
        if cut_end < end {
            rest.push((cut_end, end));
        }
    }
    rest
}

/// Returns the slot after the one starting at `slot_start`.
fn next_slot(slot_start: i64) -> Result<i64> {
    slot_start
        .checked_add(FIVE_MINUTES)
        .ok_or_else(|| anyhow!("slot {slot_start} has no slot after it"))
}

/// Returns the slots the non-empty range `[start, end)` touches, as the
/// start of the first and the end of the last.
fn slot_span(start: i64, end: i64) -> Result<(i64, i64)> {
    let last = end
        .checked_sub(1)
        .ok_or_else(|| anyhow!("range end {end} has no time before it"))?;
    Ok((slot_floor(start)?, next_slot(slot_floor(last)?)?))
}

impl Dai<'_> {
    /// Stores one part of a send of observations at the time `now`, as
    /// [`Store::store_dai_observations`](crate::Store::store_dai_observations)
    /// describes.
    pub(crate) fn store_observations(
        &self,
        batch: &DaiObservationBatch,
        now: i64,
    ) -> Result<DaiStoreOutcome> {
        let send = send_key(&batch.sensor, batch.kind, batch.slot_start, batch.send_id);
        self.write_if(|txn| self.store_attempt(txn, batch, &send, now))
    }

    /// Runs one attempt of [`store_observations`](Self::store_observations)
    /// within `txn`, and returns its outcome and whether to commit.
    #[allow(clippy::too_many_lines)] // The checks of one store, in their documented order.
    fn store_attempt(
        &self,
        txn: &Txn<'_>,
        batch: &DaiObservationBatch,
        send: &[u8],
        now: i64,
    ) -> Result<(DaiStoreOutcome, bool)> {
        let restore_generation = self.current_generation(txn)?;
        let stored: Option<SendRow> = Self::get_row(txn, &self.slot_sends, send)?;

        // 1. A repeated part of a send finished under this generation.
        if let Some(row) = &stored
            && row.finished
            && row.restore_generation == restore_generation
        {
            let marks = row.marks.clone();
            return Ok((
                DaiStoreOutcome::Stored {
                    restore_generation,
                    marks,
                },
                false,
            ));
        }

        // 2. A sensor that is not collected.
        let not_collected = Ok((DaiStoreOutcome::NotCollected { restore_generation }, false));
        let Some(customer) = self.customer_sensors_in(txn)?.customer(&batch.sensor) else {
            return not_collected;
        };
        txn.get_for_update_cf(self.guard.cf, customer_key(customer), EXCLUSIVE)
            .context("cannot read the DAI site policy guard")?;
        let settings = self.stored_settings(txn, customer)?.unwrap_or_default();
        if !settings.device_account_identification {
            return not_collected;
        }

        // 3. Invalid fields.
        let slot_end = check_batch(batch)?;

        // 4. A part counted against another state.
        let resync = Ok((DaiStoreOutcome::Resync { restore_generation }, false));
        let mut state = self.sensor_state_for_update(txn, &batch.sensor)?;
        let networks = OwnedNetworkTable::open(self.db)
            .context("customer network table must be present")?
            .get_in_transaction(txn, customer)?;
        let digest = dai_network_digest(networks.as_ref())?.digest;
        if batch.restore_generation != restore_generation
            || batch.config_epoch != state.epoch
            || batch.network_digest != digest
        {
            return resync;
        }
        let mut cursors = BTreeMap::new();
        for kind in std::iter::once(batch.kind).chain(batch.late_slots.iter().map(|l| l.kind)) {
            if cursors.contains_key(&kind_number(kind)) {
                continue;
            }
            let Some(row) = self.cursor_in(txn, &batch.sensor, kind)? else {
                return resync;
            };
            cursors.insert(kind_number(kind), (kind, row));
        }

        // 5. A part that disagrees with the earlier parts of its send.
        let meta = SendMeta::of(batch);
        let mut row = match stored {
            Some(row) => {
                if row.part_count != batch.part_count
                    || row.restore_generation != batch.restore_generation
                    || row.config_epoch != batch.config_epoch
                    || row.network_digest != batch.network_digest
                    || row.meta != meta
                {
                    self.discard_send(txn, send, &row)?;
                    return Ok((DaiStoreOutcome::Resync { restore_generation }, true));
                }
                row
            }
            None => SendRow {
                part_count: batch.part_count,
                received: BTreeSet::new(),
                restore_generation: batch.restore_generation,
                config_epoch: batch.config_epoch,
                network_digest: batch.network_digest,
                meta,
                created: now,
                finished: false,
                marks: Vec::new(),
            },
        };

        // 6. Stage.
        row.received.insert(batch.part);
        let complete = u32::try_from(row.received.len()).is_ok_and(|n| n == row.part_count);
        if !complete {
            Self::put_row(
                txn,
                &self.send_parts,
                &part_key(send, batch.part),
                &batch.observations,
            )?;
            Self::put_row(txn, &self.slot_sends, send, &row)?;
            #[cfg(test)]
            super::run_before_commit_hook(self.db);
            return Ok((DaiStoreOutcome::Staged { restore_generation }, true));
        }

        // 7. Finish.
        let mut observations = Vec::new();
        for part in &row.received {
            let key = part_key(send, *part);
            let staged: Option<Vec<DaiObservation>> = Self::get_row(txn, &self.send_parts, &key)?;
            if *part == batch.part {
                observations.extend(batch.observations.iter().cloned());
            } else {
                observations.extend(
                    staged
                        .with_context(|| format!("staged part {part} of a DAI send is missing"))?,
                );
            }
            Self::delete_row(txn, &self.send_parts, &key)?;
        }
        let slot = batch.slot_start..slot_end;
        let marks = self.finish(
            txn,
            batch,
            &slot,
            customer,
            &mut state,
            &mut cursors,
            &observations,
            now,
        )?;
        for (kind, cursor) in cursors.values() {
            self.put_cursor(txn, &batch.sensor, *kind, cursor)?;
        }
        self.put_sensor_state(txn, &batch.sensor, &state)?;
        row.finished = true;
        row.marks.clone_from(&marks);
        Self::put_row(txn, &self.slot_sends, send, &row)?;
        #[cfg(test)]
        super::run_before_commit_hook(self.db);
        Ok((
            DaiStoreOutcome::Stored {
                restore_generation,
                marks,
            },
            true,
        ))
    }

    /// Deletes, within `txn`, the send whose key is `send` and its staged
    /// parts.
    fn discard_send(&self, txn: &Txn<'_>, send: &[u8], row: &SendRow) -> Result<()> {
        for part in &row.received {
            Self::delete_row(txn, &self.send_parts, &part_key(send, *part))?;
        }
        Self::delete_row(txn, &self.slot_sends, send)
    }

    /// Applies, within `txn`, a send whose last missing part arrived, and
    /// returns the marks assigned to its late slots.
    ///
    /// `cursors` holds the cursor rows of the batch kind and of every
    /// late-slot kind, keyed by kind number, which the caller writes back.
    #[allow(clippy::too_many_arguments)] // The state of one send, passed apart to borrow it.
    fn finish(
        &self,
        txn: &Txn<'_>,
        batch: &DaiObservationBatch,
        slot: &std::ops::Range<i64>,
        customer: u32,
        state: &mut SensorState,
        cursors: &mut BTreeMap<u8, (DaiObservationKind, CursorRow)>,
        observations: &[DaiObservation],
        now: i64,
    ) -> Result<Vec<DaiReextractMark>> {
        let sensor = batch.sensor.as_str();
        let kind = batch.kind;
        let site = self.site_at(txn, customer, sensor, slot.start)?;
        let summary_only = slot.start < now.saturating_sub(PER_SLOT_AGE);

        // Filter and upsert.
        let mut filtered = 0_u64;
        let mut stored = 0_usize;
        for observation in observations {
            if let Some(reason) = rejection(observation, kind, slot) {
                tracing::warn!(
                    "dropping a DAI observation of sensor {sensor:?}, kind {}, slot {}: {reason}",
                    kind_number(kind),
                    slot.start
                );
                filtered += 1;
                continue;
            }
            self.upsert(
                txn,
                &Upsert {
                    sensor,
                    kind,
                    slot_start: slot.start,
                    customer,
                    site: &site,
                    summary_only,
                },
                observation,
            )?;
            stored += 1;
        }
        if filtered > 0 {
            self.add_counter(
                txn,
                customer,
                DaiCounterKind::FilteredAtReceipt,
                now,
                filtered,
            )?;
        }

        let (_, row) = cursors
            .get_mut(&kind_number(kind))
            .context("the cursor row of the batch kind is read")?;

        // Catch-up skip.
        if let Some(lost_before) = batch.lost_before
            && lost_before > row.cursor
        {
            self.skip(txn, sensor, kind, customer, row, lost_before, now)?;
        }

        // Clear the re-extract mark.
        if let Some(mark) = batch.reextract_mark
            && row.marks.get(&slot.start) == Some(&mark)
        {
            row.marks.remove(&slot.start);
        }

        // Confirm the slot.
        confirm(row, slot.end, batch.counted_from, state)?;

        // Shrink gaps.
        self.shrink_gaps(txn, sensor, kind, batch.counted_from, slot.end)?;

        // Marks.
        let today = date_of(now)?;
        let mut marks = Vec::new();
        let mut marked = BTreeSet::new();
        for late in &batch.late_slots {
            let (_, row) = cursors
                .get_mut(&kind_number(late.kind))
                .context("the cursor row of a late-slot kind is read")?;
            row.record_delay(today, late.delay_ns.max(0));
            if marked.insert((kind_number(late.kind), late.slot_start)) {
                let mark = state.take_mark();
                row.marks.insert(late.slot_start, mark);
                marks.push(DaiReextractMark {
                    kind: late.kind,
                    slot_start: late.slot_start,
                    mark,
                });
            }
        }

        // State.
        state.last_record_time = match (state.last_record_time, batch.last_record_time) {
            (Some(stored), Some(new)) => Some(stored.max(new)),
            (stored, new) => stored.or(new),
        };
        state.last_store_time = Some(now);
        if stored > 0 {
            let key = pair_key(sensor, kind);
            Self::get_row::<i64>(txn, &self.sensor_kind_state, &key)?;
            Self::put_row(txn, &self.sensor_kind_state, &key, &now)?;
        }
        Ok(marks)
    }

    /// Returns the token of the site `sensor` was in, in the customer's
    /// network, at the time `time`, as `txn` sees it.
    fn site_at(&self, txn: &Txn<'_>, customer: u32, sensor: &str, time: i64) -> Result<String> {
        self.sensor_site_in(txn, customer, sensor, time)?
            .ok_or_else(|| anyhow!("customer {customer} has no default DAI site"))
    }

    /// Widens, within `txn`, the summary of an observation of a slot that
    /// started more than 7 days ago, and returns the body and times to
    /// enqueue if it changed.
    ///
    /// A per-slot row retention has not folded yet is folded here first, so
    /// the summary and the pending row start from what the slot already
    /// stored rather than losing a filled value to this observation.
    fn upsert_summary(
        &self,
        txn: &Txn<'_>,
        at: &Upsert<'_>,
        hash: &IdHash,
        observation: &DaiObservation,
    ) -> Result<Option<(DaiObservationBody, i64, i64)>> {
        let (sensor, kind) = (at.sensor, at.kind);
        let first = observation.first_seen;
        let last = observation.last_seen;
        let key = summary_key(sensor, kind, hash);
        let summary: Option<SeenRow> = Self::get_row(txn, &self.summaries, &key)?;
        let slot_key = observation_key(sensor, kind, at.slot_start, hash);
        let slot_row: Option<ObservationRow> = Self::get_row(txn, &self.observations, &slot_key)?;
        let stored = match (&summary, &slot_row) {
            (Some(summary), Some(row)) => {
                Some(summary.widened(&row.body, row.first_seen, row.last_seen))
            }
            (Some(summary), None) => Some(summary.clone()),
            (None, Some(row)) => Some(SeenRow {
                body: row.body.clone(),
                first_seen: row.first_seen,
                last_seen: row.last_seen,
            }),
            (None, None) => None,
        };
        let merged = stored.as_ref().map_or_else(
            || SeenRow {
                body: observation.body.clone(),
                first_seen: first,
                last_seen: last,
            },
            |stored| stored.widened(&observation.body, first, last),
        );
        if slot_row.is_some() {
            Self::delete_row(txn, &self.observations, &slot_key)?;
        }
        if summary.as_ref() != Some(&merged) {
            Self::put_row(txn, &self.summaries, &key, &merged)?;
        }
        // The slot's own times stay inside the slot, unlike the
        // summary's.
        let (first, last) = slot_row.as_ref().map_or((first, last), |row| {
            (row.first_seen.min(first), row.last_seen.max(last))
        });
        Ok((stored.as_ref() != Some(&merged)).then_some((merged.body, first, last)))
    }

    /// Upserts one observation within `txn`, enqueues it if it changed, and
    /// widens the address activity of an `IpActivity` observation.
    fn upsert(&self, txn: &Txn<'_>, at: &Upsert<'_>, observation: &DaiObservation) -> Result<()> {
        let hash = identifier_hash(&observation.body)?;
        let (sensor, kind) = (at.sensor, at.kind);
        let first = observation.first_seen;
        let last = observation.last_seen;
        let enqueued = if at.summary_only {
            self.upsert_summary(txn, at, &hash, observation)?
        } else {
            let key = observation_key(sensor, kind, at.slot_start, &hash);
            let existing: Option<ObservationRow> = Self::get_row(txn, &self.observations, &key)?;
            let merged = match &existing {
                None => ObservationRow {
                    customer_id: at.customer,
                    site: at.site.to_string(),
                    body: observation.body.clone(),
                    first_seen: first,
                    last_seen: last,
                    count: observation.count,
                },
                Some(row) => ObservationRow {
                    customer_id: row.customer_id,
                    site: row.site.clone(),
                    body: merge_body(&row.body, &observation.body),
                    first_seen: row.first_seen.min(first),
                    last_seen: row.last_seen.max(last),
                    count: row.count.max(observation.count),
                },
            };
            let changed = existing.as_ref().is_none_or(|row| {
                row.body != merged.body
                    || row.first_seen != merged.first_seen
                    || row.last_seen != merged.last_seen
            });
            if existing.as_ref() != Some(&merged) {
                Self::put_row(txn, &self.observations, &key, &merged)?;
            }
            changed.then_some((merged.body, merged.first_seen, merged.last_seen))
        };

        if let DaiObservationBody::IpActivity { ip, .. } = observation.body {
            let key = ip_activity_key(at.customer, at.site, ip);
            let existing: Option<ActivityRow> = Self::get_row(txn, &self.ip_activity, &key)?;
            let widened = existing.map_or(
                ActivityRow {
                    first_seen: first,
                    last_seen: last,
                },
                |activity| ActivityRow {
                    first_seen: activity.first_seen.min(first),
                    last_seen: activity.last_seen.max(last),
                },
            );
            if existing != Some(widened) {
                Self::put_row(txn, &self.ip_activity, &key, &widened)?;
            }
        } else if let Some((body, first, last)) = enqueued {
            let key = pending_key(sensor, at.slot_start, kind, &hash);
            let existing: Option<SeenRow> = Self::get_row(txn, &self.pending, &key)?;
            let mut pending = SeenRow {
                body,
                first_seen: first,
                last_seen: last,
            };
            if at.summary_only
                && let Some(existing) = existing
            {
                pending.first_seen = pending.first_seen.min(existing.first_seen);
                pending.last_seen = pending.last_seen.max(existing.last_seen);
            }
            Self::put_row(txn, &self.pending, &key, &pending)?;
            self.lower_earliest_pending(txn, sensor, kind, at.slot_start)?;
        }
        Ok(())
    }

    /// Lowers, within `txn`, the earliest pending slot of (`sensor`,
    /// `kind`) to `slot_start` if that is earlier, writing the row even when
    /// its value stays, so that a transaction recomputing it from a scan
    /// conflicts with the pending row just added.
    fn lower_earliest_pending(
        &self,
        txn: &Txn<'_>,
        sensor: &str,
        kind: DaiObservationKind,
        slot_start: i64,
    ) -> Result<()> {
        let key = pair_key(sensor, kind);
        let earliest = Self::get_row::<i64>(txn, &self.earliest_pending, &key)?
            .map_or(slot_start, |earliest| earliest.min(slot_start));
        Self::put_row(txn, &self.earliest_pending, &key, &earliest)
    }

    /// Adds `count` to the customer's counter of `counter` for the date of
    /// `now`, within `txn`.
    pub(crate) fn add_counter(
        &self,
        txn: &Txn<'_>,
        customer_id: u32,
        counter: DaiCounterKind,
        now: i64,
        count: u64,
    ) -> Result<()> {
        let key = counter_key(customer_id, counter.number(), date_of(now)?);
        let stored: u64 = Self::get_row(txn, &self.counters, &key)?.unwrap_or_default();
        Self::put_row(txn, &self.counters, &key, &stored.saturating_add(count))
    }

    /// Returns the customer's counter of `counter` for `date`, 0 if it has
    /// none.
    #[cfg(test)]
    pub(super) fn counter(&self, customer_id: u32, counter: DaiCounterKind, date: i32) -> u64 {
        let key = counter_key(customer_id, counter.number(), date);
        self.read(|txn| Ok(Self::get_row::<u64>(txn, &self.counters, &key)?.unwrap_or_default()))
            .expect("the counter is readable")
    }

    /// Returns the catch-up gaps of (`sensor`, `kind`) as `txn` sees them,
    /// in start order.
    pub(super) fn gaps_in(
        &self,
        txn: &Txn<'_>,
        sensor: &str,
        kind: DaiObservationKind,
    ) -> Result<Vec<(i64, i64)>> {
        Self::scan(&self.catchup_gaps, txn, &pair_key(sensor, kind))?
            .into_iter()
            .map(|(key, value)| {
                let (_, _, start) = decode_gap_key(&key)?;
                Ok((start, super::super::deserialize(&value)?))
            })
            .collect()
    }

    /// Skips, within `txn`, everything of (`sensor`, `kind`) before
    /// `lost_before`, which is after the cursor of `row`: writes the gaps,
    /// counts the slots they touch, drops the confirmed slots before the
    /// slot holding `lost_before`, and moves the cursor and the read floor.
    #[allow(clippy::too_many_arguments)] // The state of one send, passed apart to borrow it.
    fn skip(
        &self,
        txn: &Txn<'_>,
        sensor: &str,
        kind: DaiObservationKind,
        customer: u32,
        row: &mut CursorRow,
        lost_before: i64,
        now: i64,
    ) -> Result<()> {
        let lost_slot = slot_floor(lost_before)?;
        // The scan is not tracked, so only the starts it finds are used: each
        // gap is reread for update, and a commit conflicts if another
        // transaction changes or deletes it after that read.
        let scanned = self.gaps_in(txn, sensor, kind)?;
        #[cfg(test)]
        super::run_gaps_scanned_hook(self.db);
        let mut existing = Vec::with_capacity(scanned.len());
        for (start, _) in scanned {
            let key = gap_key(sensor, kind, start);
            if let Some(end) = Self::get_row::<i64>(txn, &self.catchup_gaps, &key)? {
                existing.push((start, end));
            }
        }
        let mut gaps = vec![(row.cursor, lost_before)];
        for (end, counted_from) in &row.confirmed {
            gaps = subtract(&gaps, *counted_from, *end);
        }
        // A gap written by an earlier skip may reach past the cursor, into
        // the slot that skip moved the cursor to. Its range is not written
        // again, and the slots it touches were counted by that skip.
        for (start, end) in &existing {
            gaps = subtract(&gaps, *start, *end);
        }

        // The slots the new gaps touch, as ordered, disjoint ranges of slot
        // starts, less those an existing gap touches.
        let mut slots: Vec<(i64, i64)> = Vec::new();
        for (start, end) in &gaps {
            let (first, past) = slot_span(*start, *end)?;
            match slots.last_mut() {
                Some(last) if first <= last.1 => last.1 = last.1.max(past),
                _ => slots.push((first, past)),
            }
            let key = gap_key(sensor, kind, *start);
            Self::get_row::<i64>(txn, &self.catchup_gaps, &key)?;
            Self::put_row(txn, &self.catchup_gaps, &key, end)?;
        }
        for (start, end) in &existing {
            let (first, past) = slot_span(*start, *end)?;
            slots = subtract(&slots, first, past);
        }
        let mut skipped = 0_u64;
        for (first, past) in &slots {
            skipped +=
                u64::try_from((past - first) / FIVE_MINUTES).context("a slot count is negative")?;
        }
        if skipped > 0 {
            self.add_counter(
                txn,
                customer,
                DaiCounterKind::SkippedByCatchup,
                now,
                skipped,
            )?;
        }

        row.confirmed.retain(|end, _| *end > lost_slot);
        row.cursor = row.cursor.max(lost_slot);
        row.read_floor = row.read_floor.max(lost_before);
        Ok(())
    }

    /// Removes `[from, to)` from the catch-up gaps of (`sensor`, `kind`)
    /// within `txn`, shortening or splitting them.
    fn shrink_gaps(
        &self,
        txn: &Txn<'_>,
        sensor: &str,
        kind: DaiObservationKind,
        from: i64,
        to: i64,
    ) -> Result<()> {
        for (start, _) in self.gaps_in(txn, sensor, kind)? {
            let key = gap_key(sensor, kind, start);
            let Some(end) = Self::get_row::<i64>(txn, &self.catchup_gaps, &key)? else {
                continue;
            };
            if end <= from || to <= start {
                continue;
            }
            Self::delete_row(txn, &self.catchup_gaps, &key)?;
            if start < from {
                Self::put_row(txn, &self.catchup_gaps, &key, &from)?;
            }
            if to < end {
                let rest = gap_key(sensor, kind, to);
                Self::get_row::<i64>(txn, &self.catchup_gaps, &rest)?;
                Self::put_row(txn, &self.catchup_gaps, &rest, &end)?;
            }
        }
        Ok(())
    }
}

/// Where an observation is upserted.
struct Upsert<'a> {
    sensor: &'a str,
    kind: DaiObservationKind,
    slot_start: i64,
    customer: u32,
    site: &'a str,
    /// Whether the slot is old enough to go to the summaries only.
    summary_only: bool,
}

/// Confirms the slot ending at `slot_end`, counted from `counted_from`, in
/// `row`: adds it to the confirmed slots if it ends after the cursor, moves
/// the cursor over the contiguous ones, and, while more than
/// [`MAX_CONFIRMED`] remain, marks every slot from the cursor through the
/// earliest confirmed one for re-extraction and drops that one.
fn confirm(
    row: &mut CursorRow,
    slot_end: i64,
    counted_from: i64,
    state: &mut SensorState,
) -> Result<()> {
    if slot_end > row.cursor {
        let entry = row.confirmed.entry(slot_end).or_insert(counted_from);
        *entry = (*entry).min(counted_from);
    }
    loop {
        let next = next_slot(row.cursor)?;
        if row.confirmed.remove(&next).is_none() {
            break;
        }
        row.cursor = next;
    }
    while row.confirmed.len() > MAX_CONFIRMED {
        let Some((&end, _)) = row.confirmed.first_key_value() else {
            break;
        };
        let mut slot_start = row.cursor;
        while slot_start < end {
            row.marks
                .entry(slot_start)
                .or_insert_with(|| state.take_mark());
            slot_start = next_slot(slot_start)?;
        }
        row.confirmed.remove(&end);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subtract_shortens_and_splits() {
        assert_eq!(subtract(&[(0, 10)], 3, 5), [(0, 3), (5, 10)]);
        assert_eq!(subtract(&[(0, 10)], 0, 5), [(5, 10)]);
        assert_eq!(subtract(&[(0, 10)], 5, 10), [(0, 5)]);
        assert_eq!(subtract(&[(0, 10)], 10, 20), [(0, 10)]);
        assert_eq!(subtract(&[(0, 10)], -5, 20), []);
        assert_eq!(subtract(&[(0, 4), (6, 10)], 3, 7), [(0, 3), (7, 10)]);
    }
}
