//! The unregistered range tables of device identification.
//!
//! Per sensor and per UTC date, an agent counts the private and CGNAT
//! source addresses it saw outside the customer's registered networks, per
//! /24 (`IPv6` /64) block, with the DHCP subnets seen that day, and sends them
//! as one *range day*. A **unit** is (sensor, date, evidence). It is
//! collected under a **lease**: a begin grants a new **version** with a
//! random **lease token**, and only a complete result of the newest granted
//! version replaces the unit's stored counts. Late records reported after a
//! unit was stored give it a **recollect mark**, drawn from the sensor's
//! mark counter that the slot marks use too, and the unit is listed for
//! recollection until a result carrying the mark is stored.
//!
//! The blocks and subnets of a unit are stored under the sensor's customer
//! at the time of the send. The candidate read folds the blocks of the last
//! 14 complete dates into ranges, widening each block to the widest DHCP
//! subnet seen around it, and lists the ranges seen on at least 3 dates that
//! are private, not registered and not ignored.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use anyhow::{Context, Result, anyhow};
use ipnet::IpNet;
use review_protocol::types::{
    DaiRangeBlock, DaiRangeDay, DaiRangeDayState, DaiRangeEvidence, DaiRangeGrant, DaiRangeLate,
    DaiRangeMark, DaiRangeUnit,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    Dai, DaiStoreOutcome, FIVE_MINUTES, KeyReader, KeyWriter, SensorSite, SensorState, Txn,
    cursor::{DAY, LOOKBACK, RECENT_DAYS, RestoredCursor, date_of, is_recent},
    customer_key, dai_network_digest, decode_sensor_site, sensor_key,
};
use crate::{EXCLUSIVE, OwnedNetworkTable, Store};

/// How long a range day lease lasts: 10 minutes, in nanoseconds.
const LEASE: i64 = 10 * 60 * 1_000_000_000;
/// The delay the agent allows a record of a date after the date ends: 5
/// minutes, in nanoseconds.
const ALLOWED_DELAY: i64 = FIVE_MINUTES;
/// The time, after a date's end and the allowed delay, before the date is
/// listed for collection: 1 hour, in nanoseconds.
const COLLECTION_MARGIN: i64 = 60 * 60 * 1_000_000_000;
/// The number of dates, ending with the last date that has ended, whose
/// blocks the candidate read folds.
const WINDOW_DAYS: i32 = 14;
/// The number of distinct dates of the window on which a range needs a
/// value to be a candidate.
const MIN_DATES: usize = 3;
/// The number of distinct addresses a saturated block counts.
const SATURATED_ADDRS: u64 = 65_536;
/// The prefix length of an `IPv4` block.
const V4_BLOCK_LEN: u8 = 24;
/// The prefix length of an `IPv6` block.
const V6_BLOCK_LEN: u8 = 64;
/// The number of days after today a range day may be dated.
const MAX_DAYS_AHEAD: i64 = 1;
/// The range evidence variants, in the order of their numbers.
const EVIDENCES: [DaiRangeEvidence; 1] = [DaiRangeEvidence::Sensor];
/// The CGNAT prefix, `100.64.0.0/10`.
const CGNAT: IpNet = IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10);
/// The private prefixes a candidate range lies in.
const PRIVATE: [IpNet; 5] = [
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
    CGNAT,
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7),
];

/// Returns the number of a range evidence, the byte its keys hold.
pub(in crate::tables) fn evidence_number(evidence: DaiRangeEvidence) -> u8 {
    match evidence {
        DaiRangeEvidence::Sensor => 1,
    }
}

/// Returns the range evidence of number `number`, or `None` if no evidence
/// has it.
pub(in crate::tables) fn evidence_from_number(number: u8) -> Option<DaiRangeEvidence> {
    EVIDENCES
        .into_iter()
        .find(|evidence| evidence_number(*evidence) == number)
}

/// A refusal of an invalid range day request.
///
/// It is returned inside the `anyhow::Error` of the refusing method, so a
/// caller can `downcast_ref` it. A refused request writes nothing.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DaiRangeError {
    /// The date is more than one day after today's UTC date.
    #[error("range date {date} is more than one day after today ({today})")]
    FutureDate { date: i32, today: i32 },
    /// The version of a send is 0, which is never granted.
    #[error("range version 0 is never granted")]
    ZeroVersion,
    /// The version of a send is above the unit's last granted version.
    #[error("range version {version} is above the last granted version {last_granted}")]
    UngrantedVersion { version: u64, last_granted: u64 },
    /// A block is not an `IPv4` /24 or `IPv6` /64 network address.
    #[error("range block {block} is not an IPv4 /24 or IPv6 /64 network address")]
    InvalidBlock { block: IpNet },
    /// A send lists a block twice.
    #[error("range block {block} is listed twice")]
    DuplicateBlock { block: IpNet },
    /// The restore generation of a late report is not the current one.
    #[error("the restore generation {restore_generation} is not the current one")]
    StaleRestoreGeneration { restore_generation: u64 },
}

/// A candidate unregistered internal range of a customer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiRangeCandidate {
    /// The range, a network address.
    pub range: IpNet,
    /// The largest number of distinct addresses one sensor saw in the range
    /// on one date of the window.
    pub seen_addrs: u64,
    /// Whether `seen_addrs` is a lower bound: a (sensor, date) value equal
    /// to it includes a saturated block.
    pub seen_addrs_at_least: bool,
    /// The number of (sensor, date) values of the range in the window, per
    /// evidence variant; every variant is listed.
    pub values: BTreeMap<DaiRangeEvidence, u64>,
    /// The first date of the window with a value.
    pub first_date: i32,
    /// The last date of the window with a value.
    pub last_date: i32,
    /// The tokens of the sites the contributing sensors were in on the dates
    /// of their values, sorted and deduplicated; empty if the customer has
    /// no default site.
    pub sites: Vec<String>,
    /// Whether the range lies within `100.64.0.0/10`.
    pub cgnat: bool,
}

/// A range a customer ignores.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiIgnoredRange {
    /// The range, a network address.
    pub range: IpNet,
    /// When it was ignored, in nanoseconds since the UNIX epoch.
    pub ignored_at: i64,
    /// The name of the account that ignored it.
    pub account: String,
}

/// The stored value of a `dai range blocks` row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct BlockRow {
    pub(super) version: u64,
    pub(super) distinct_addrs: u32,
    pub(super) conns: u64,
    pub(super) saturated: bool,
}

impl BlockRow {
    /// Returns the row of `block` of `day`, of its version.
    fn of(day: &DaiRangeDay, block: &DaiRangeBlock) -> Self {
        Self {
            version: day.version,
            distinct_addrs: block.distinct_addrs,
            conns: block.conns,
            saturated: block.saturated,
        }
    }
}

/// The stored value of a `dai range days` row. A missing row reads as the
/// [`Default`].
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct DayRow {
    /// The last version granted; 0 if none was.
    pub(super) last_granted: u64,
    /// The current lease token.
    pub(super) lease_token: Option<u64>,
    /// When the current lease ends.
    pub(super) lease_end: Option<i64>,
    /// The version whose counts are stored, if any.
    pub(super) stored_version: Option<u64>,
    /// The recollect mark.
    pub(super) mark: Option<u64>,
    /// The subnets late records were seen in, as network addresses.
    pub(super) late_subnets: BTreeSet<IpNet>,
    /// The longest delay of a late record reported for the unit, in
    /// nanoseconds.
    pub(super) longest_delay: i64,
}

/// The rows of a sensor's units: each key with its date and row.
type UnitRows = Vec<(Box<[u8]>, i32, DayRow)>;

/// The values of a range, per (sensor, date, evidence).
type Values = BTreeMap<(String, i32, DaiRangeEvidence), Value>;

/// The stored value of a `dai range ignores` row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct IgnoreRow {
    ignored_at: i64,
    account: String,
}

/// The value of one (sensor, date, evidence) for a range.
#[derive(Clone, Copy, Debug, Default)]
struct Value {
    addrs: u64,
    conns: u64,
    saturated: bool,
}

// ---- Keys ----

pub(super) fn block_key(
    customer_id: u32,
    sensor: &str,
    date: i32,
    evidence: DaiRangeEvidence,
    block: IpNet,
) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer_id)
        .str(sensor)
        .date(date)
        .range_evidence(evidence)
        .ip_net(block)
        .finish()
}

/// Returns the key prefix of the blocks of a unit under a customer.
fn unit_blocks_prefix(
    customer_id: u32,
    sensor: &str,
    date: i32,
    evidence: DaiRangeEvidence,
) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer_id)
        .str(sensor)
        .date(date)
        .range_evidence(evidence)
        .finish()
}

/// Decodes the key of a `dai range blocks` row.
pub(super) fn decode_block_key(key: &[u8]) -> Result<(u32, String, i32, DaiRangeEvidence, IpNet)> {
    let mut reader = KeyReader::new(key);
    let customer_id = reader.u32()?;
    let sensor = reader.str()?;
    let date = reader.date()?;
    let evidence = reader.range_evidence()?;
    let block = reader.ip_net()?;
    reader.finish()?;
    Ok((customer_id, sensor, date, evidence, block))
}

pub(super) fn subnet_key(customer_id: u32, sensor: &str, date: i32, subnet: IpNet) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer_id)
        .str(sensor)
        .date(date)
        .ip_net(subnet)
        .finish()
}

/// Returns the key prefix of the subnets a sensor saw on a date under a
/// customer.
fn date_subnets_prefix(customer_id: u32, sensor: &str, date: i32) -> Vec<u8> {
    KeyWriter::default()
        .u32(customer_id)
        .str(sensor)
        .date(date)
        .finish()
}

/// Decodes the key of a `dai range subnets` row.
pub(super) fn decode_subnet_key(key: &[u8]) -> Result<(u32, String, i32, IpNet)> {
    let mut reader = KeyReader::new(key);
    let customer_id = reader.u32()?;
    let sensor = reader.str()?;
    let date = reader.date()?;
    let subnet = reader.ip_net()?;
    reader.finish()?;
    Ok((customer_id, sensor, date, subnet))
}

pub(super) fn day_key(sensor: &str, date: i32, evidence: DaiRangeEvidence) -> Vec<u8> {
    KeyWriter::default()
        .str(sensor)
        .date(date)
        .range_evidence(evidence)
        .finish()
}

/// Decodes the key of a `dai range days` row.
pub(super) fn decode_day_key(key: &[u8]) -> Result<(String, i32, DaiRangeEvidence)> {
    let mut reader = KeyReader::new(key);
    let sensor = reader.str()?;
    let date = reader.date()?;
    let evidence = reader.range_evidence()?;
    reader.finish()?;
    Ok((sensor, date, evidence))
}

pub(super) fn ignore_key(customer_id: u32, range: IpNet) -> Vec<u8> {
    KeyWriter::default().u32(customer_id).ip_net(range).finish()
}

/// Decodes the key of a `dai range ignores` row.
fn decode_ignore_key(key: &[u8]) -> Result<(u32, IpNet)> {
    let mut reader = KeyReader::new(key);
    let customer_id = reader.u32()?;
    let range = reader.ip_net()?;
    reader.finish()?;
    Ok((customer_id, range))
}

// ---- Checks and normalization ----

/// Refuses `date` if it is more than one day after the date of `now`.
fn check_date(date: i32, now: i64) -> Result<()> {
    let today = date_of(now)?;
    if i64::from(date) > i64::from(today) + MAX_DAYS_AHEAD {
        return Err(DaiRangeError::FutureDate { date, today }.into());
    }
    Ok(())
}

/// Returns whether `block` is an `IPv4` /24 or `IPv6` /64 network address.
fn is_block(block: &IpNet) -> bool {
    let len = match block {
        IpNet::V4(_) => V4_BLOCK_LEN,
        IpNet::V6(_) => V6_BLOCK_LEN,
    };
    block.prefix_len() == len && block.addr() == block.network()
}

/// Checks the version and the blocks of a send against `row`, the unit's
/// row.
fn check_day(day: &DaiRangeDay, row: &DayRow) -> Result<(), DaiRangeError> {
    if day.version == 0 {
        return Err(DaiRangeError::ZeroVersion);
    }
    if day.version > row.last_granted {
        return Err(DaiRangeError::UngrantedVersion {
            version: day.version,
            last_granted: row.last_granted,
        });
    }
    let mut seen = BTreeSet::new();
    for DaiRangeBlock { block, .. } in &day.blocks {
        if !is_block(block) {
            return Err(DaiRangeError::InvalidBlock { block: *block });
        }
        if !seen.insert(*block) {
            return Err(DaiRangeError::DuplicateBlock { block: *block });
        }
    }
    Ok(())
}

/// Returns `subnet` as it is stored: its network address, an `IPv4` subnet
/// longer than /24 as its /24 and an `IPv6` subnet longer than /64 as its
/// /64.
fn normalize_subnet(subnet: IpNet) -> IpNet {
    let longest = match subnet {
        IpNet::V4(_) => V4_BLOCK_LEN,
        IpNet::V6(_) => V6_BLOCK_LEN,
    };
    if subnet.prefix_len() > longest {
        IpNet::new(subnet.addr(), longest).unwrap_or(subnet).trunc()
    } else {
        subnet.trunc()
    }
}

/// Returns whether `net` lies within one of the private prefixes.
fn is_private(net: &IpNet) -> bool {
    PRIVATE.iter().any(|prefix| prefix.contains(net))
}

/// Returns a random lease token other than `current`.
fn new_token(current: Option<u64>) -> u64 {
    loop {
        let token = rand::random();
        if Some(token) != current {
            return token;
        }
    }
}

/// Returns the end of the lease that a grant or a renewal at `now` gives.
fn lease_end(now: i64) -> Result<i64> {
    now.checked_add(LEASE)
        .ok_or_else(|| anyhow!("time {now} has no lease end after it"))
}

/// Returns whether `date` ended, with the allowed delay and the collection
/// margin, at or before `now`.
fn collectable(date: i64, now: i64) -> bool {
    let ready = (i128::from(date) + 1) * i128::from(DAY)
        + i128::from(ALLOWED_DELAY)
        + i128::from(COLLECTION_MARGIN);
    ready <= i128::from(now)
}

/// Returns the start of `date`, in nanoseconds, saturating at the limits of
/// an `i64`.
fn date_start(date: i32) -> i64 {
    i64::from(date).saturating_mul(DAY)
}

/// Returns whether the IP address range `start..=end` contains `range`.
fn range_contains(start: IpAddr, end: IpAddr, range: &IpNet) -> bool {
    let same_family = matches!(
        (start, end, range),
        (IpAddr::V4(_), IpAddr::V4(_), IpNet::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_), IpNet::V6(_))
    );
    same_family && start <= range.network() && range.broadcast() <= end
}

impl Dai<'_> {
    /// Returns the row of a unit, read for update within `txn`, or the
    /// default if there is none.
    fn day_row(&self, txn: &Txn<'_>, key: &[u8]) -> Result<DayRow> {
        Ok(Self::get_row(txn, &self.range_days, key)?.unwrap_or_default())
    }

    /// Begins a round of collection of `unit` at the time `now`, as
    /// [`Store::begin_dai_range_day`] describes.
    pub(super) fn begin_range_day(
        &self,
        unit: &DaiRangeUnit,
        restore_generation: u64,
        now: i64,
    ) -> Result<Option<DaiRangeGrant>> {
        self.write_if(|txn| {
            if self
                .customer_sensors_in(txn)?
                .customer(&unit.sensor)
                .is_none()
            {
                return Ok((None, false));
            }
            if self.current_generation(txn)? != restore_generation {
                return Ok((Some(DaiRangeGrant::Resync), false));
            }
            check_date(unit.date, now)?;
            let key = day_key(&unit.sensor, unit.date, unit.evidence);
            let mut row = self.day_row(txn, &key)?;
            if let Some(end) = row.lease_end
                && end > now
            {
                return Ok((
                    Some(DaiRangeGrant::InProgress {
                        lease_expires_at: end,
                    }),
                    false,
                ));
            }
            let version = row
                .last_granted
                .checked_add(1)
                .context("the range day version is exhausted")?;
            let token = new_token(row.lease_token);
            let end = lease_end(now)?;
            row.last_granted = version;
            row.lease_token = Some(token);
            row.lease_end = Some(end);
            Self::put_row(txn, &self.range_days, &key, &row)?;
            Ok((
                Some(DaiRangeGrant::Granted {
                    version,
                    lease_token: token,
                    lease_expires_at: end,
                }),
                true,
            ))
        })
    }

    /// Renews the lease `lease_token` of `unit` at the time `now`, as
    /// [`Store::renew_dai_range_day`] describes.
    pub(super) fn renew_range_day(
        &self,
        unit: &DaiRangeUnit,
        lease_token: u64,
        now: i64,
    ) -> Result<Option<i64>> {
        let key = day_key(&unit.sensor, unit.date, unit.evidence);
        self.write_if(|txn| {
            let Some(mut row) = Self::get_row::<DayRow>(txn, &self.range_days, &key)? else {
                return Ok((None, false));
            };
            if row.lease_token != Some(lease_token) {
                return Ok((None, false));
            }
            let end = lease_end(now)?;
            row.lease_end = Some(end);
            Self::put_row(txn, &self.range_days, &key, &row)?;
            Ok((Some(end), true))
        })
    }

    /// Stores the counts of a range day, as [`Store::send_dai_range_day`]
    /// describes.
    pub(super) fn send_range_day(&self, day: &DaiRangeDay) -> Result<DaiStoreOutcome> {
        self.write_if(|txn| self.send_attempt(txn, day))
    }

    /// Runs one attempt of [`send_range_day`](Self::send_range_day) within
    /// `txn`, and returns its outcome and whether to commit.
    fn send_attempt(&self, txn: &Txn<'_>, day: &DaiRangeDay) -> Result<(DaiStoreOutcome, bool)> {
        let unit = &day.unit;
        let restore_generation = self.current_generation(txn)?;

        // 1. A sensor that is not a customer sensor.
        let Some(customer) = self.customer_sensors_in(txn)?.customer(&unit.sensor) else {
            return Ok((DaiStoreOutcome::NotCollected { restore_generation }, false));
        };

        // 2. A day counted against another state.
        txn.get_for_update_cf(self.guard.cf, customer_key(customer), EXCLUSIVE)
            .context("cannot read the DAI site policy guard")?;
        let state = self.sensor_state_for_update(txn, &unit.sensor)?;
        let networks = OwnedNetworkTable::open(self.db)
            .context("customer network table must be present")?
            .get_in_transaction(txn, customer)?;
        let digest = dai_network_digest(networks.as_ref())?.digest;
        if day.restore_generation != restore_generation
            || day.config_epoch != state.epoch
            || day.network_digest != digest
        {
            return Ok((DaiStoreOutcome::Resync { restore_generation }, false));
        }

        // 3. Invalid fields.
        let key = day_key(&unit.sensor, unit.date, unit.evidence);
        let mut row = self.day_row(txn, &key)?;
        check_day(day, &row)?;

        // 4. A result of a superseded lease.
        let stored = Ok((
            DaiStoreOutcome::Stored {
                restore_generation,
                marks: Vec::new(),
            },
            false,
        ));
        if row.lease_token != Some(day.lease_token) || day.version < row.last_granted {
            return stored;
        }

        if row.stored_version.is_none_or(|stored| day.version > stored) {
            // 5. Replace.
            self.replace_counts(txn, customer, day)?;
            row.stored_version = Some(day.version);
        } else if row.stored_version == Some(day.version) {
            // 6. Resend.
            self.merge_counts(txn, customer, day)?;
        } else {
            // The stored version is above the last granted one, which no
            // write leaves; the result changes nothing.
            return stored;
        }
        for subnet in &day.subnets {
            let key = subnet_key(customer, &unit.sensor, unit.date, normalize_subnet(*subnet));
            txn.put_cf(self.range_subnets.cf, key, [])
                .context("cannot write DAI range subnets")?;
        }

        // 7. The recollect mark.
        if let Some(mark) = day.mark
            && row.mark == Some(mark)
        {
            row.mark = None;
        }
        Self::put_row(txn, &self.range_days, &key, &row)?;
        #[cfg(test)]
        super::run_before_commit_hook(self.db);
        Ok((
            DaiStoreOutcome::Stored {
                restore_generation,
                marks: Vec::new(),
            },
            true,
        ))
    }

    /// Replaces, within `txn`, the unit's blocks and the sensor's subnets of
    /// the date under `customer` with the blocks of `day`, of its version;
    /// the caller adds the subnets.
    fn replace_counts(&self, txn: &Txn<'_>, customer: u32, day: &DaiRangeDay) -> Result<()> {
        let unit = &day.unit;
        let prefix = unit_blocks_prefix(customer, &unit.sensor, unit.date, unit.evidence);
        for (block, _) in Self::scan(&self.range_blocks, txn, &prefix)? {
            Self::delete_row(txn, &self.range_blocks, &block)?;
        }
        let prefix = date_subnets_prefix(customer, &unit.sensor, unit.date);
        for (subnet, _) in Self::scan(&self.range_subnets, txn, &prefix)? {
            Self::delete_row(txn, &self.range_subnets, &subnet)?;
        }
        for block in &day.blocks {
            let key = block_key(
                customer,
                &unit.sensor,
                unit.date,
                unit.evidence,
                block.block,
            );
            Self::put_row(txn, &self.range_blocks, &key, &BlockRow::of(day, block))?;
        }
        Ok(())
    }

    /// Merges, within `txn`, the blocks of `day` into the unit's blocks
    /// under `customer`, each read for update: the larger counts are kept
    /// and `saturated` is the logical OR.
    fn merge_counts(&self, txn: &Txn<'_>, customer: u32, day: &DaiRangeDay) -> Result<()> {
        let unit = &day.unit;
        for block in &day.blocks {
            let key = block_key(
                customer,
                &unit.sensor,
                unit.date,
                unit.evidence,
                block.block,
            );
            let merged = match Self::get_row::<BlockRow>(txn, &self.range_blocks, &key)? {
                Some(stored) => BlockRow {
                    version: stored.version,
                    distinct_addrs: stored.distinct_addrs.max(block.distinct_addrs),
                    conns: stored.conns.max(block.conns),
                    saturated: stored.saturated || block.saturated,
                },
                None => BlockRow::of(day, block),
            };
            Self::put_row(txn, &self.range_blocks, &key, &merged)?;
        }
        Ok(())
    }

    /// Records late range records at the time `now`, as
    /// [`Store::report_dai_range_late`] describes.
    pub(super) fn report_range_late(
        &self,
        late: &DaiRangeLate,
        now: i64,
    ) -> Result<Vec<DaiRangeMark>> {
        self.write_if(|txn| {
            if self
                .customer_sensors_in(txn)?
                .customer(&late.sensor)
                .is_none()
            {
                return Ok((Vec::new(), false));
            }
            if self.current_generation(txn)? != late.restore_generation {
                return Err(DaiRangeError::StaleRestoreGeneration {
                    restore_generation: late.restore_generation,
                }
                .into());
            }
            for date in late
                .late_days
                .iter()
                .map(|day| day.date)
                .chain(late.late_subnets.iter().map(|subnet| subnet.date))
            {
                check_date(date, now)?;
            }

            let mut rows: BTreeMap<Vec<u8>, DayRow> = BTreeMap::new();
            let mut state: Option<SensorState> = None;
            let mut marks = Vec::new();
            let mut marked = BTreeSet::new();
            for late_day in &late.late_days {
                let key = day_key(&late.sensor, late_day.date, late_day.evidence);
                if !rows.contains_key(&key) {
                    let row = self.day_row(txn, &key)?;
                    rows.insert(key.clone(), row);
                }
                let row = rows.get_mut(&key).context("the unit row is read")?;
                row.longest_delay = row.longest_delay.max(late_day.delay_ns.max(0));
                if marked.insert(key) {
                    if state.is_none() {
                        state = Some(self.sensor_state_for_update(txn, &late.sensor)?);
                    }
                    let state = state.as_mut().context("the sensor state is read")?;
                    let mark = state.take_mark();
                    row.mark = Some(mark);
                    marks.push(DaiRangeMark {
                        date: late_day.date,
                        evidence: late_day.evidence,
                        mark,
                    });
                }
            }
            for late_subnet in &late.late_subnets {
                let key = day_key(&late.sensor, late_subnet.date, DaiRangeEvidence::Sensor);
                if !rows.contains_key(&key) {
                    let row = self.day_row(txn, &key)?;
                    rows.insert(key.clone(), row);
                }
                rows.get_mut(&key)
                    .context("the unit row is read")?
                    .late_subnets
                    .insert(normalize_subnet(late_subnet.subnet));
            }
            for (key, row) in &rows {
                Self::put_row(txn, &self.range_days, key, row)?;
            }
            if let Some(state) = &state {
                self.put_sensor_state(txn, &late.sensor, state)?;
            }
            let commit = !rows.is_empty();
            Ok((marks, commit))
        })
    }

    /// Returns, as `txn` sees them and reading nothing for update, the range
    /// days `sensors` still have to collect or recollect at the time `now`,
    /// as [`Store::dai_cursors`](crate::Store::dai_cursors) describes,
    /// ordered by sensor in the order given, then date, then evidence.
    pub(super) fn range_days_in<'s>(
        &self,
        txn: &Txn<'_>,
        sensors: impl IntoIterator<Item = &'s str>,
        now: i64,
    ) -> Result<Vec<DaiRangeDayState>> {
        let today = i64::from(date_of(now)?);
        let mut days = Vec::new();
        for sensor in sensors {
            let Some(first) = self.first_cursor_time_in(txn, sensor)? else {
                continue;
            };
            let first_date = i64::from(date_of(first)?);
            let from = (today - i64::from(RECENT_DAYS) + 1).max(first_date + 1);
            for date in from..=today {
                if !collectable(date, now) {
                    break;
                }
                let date = i32::try_from(date).context("a range date is out of range")?;
                for evidence in EVIDENCES {
                    let row: Option<DayRow> = txn
                        .get_cf(self.range_days.cf, day_key(sensor, date, evidence))
                        .context("cannot read DAI range days")?
                        .map(|value| super::super::deserialize(&value))
                        .transpose()?;
                    let (mark, stored_version) = match row {
                        None => (None, None),
                        Some(row) if row.mark.is_some() || row.stored_version.is_none() => {
                            (row.mark, row.stored_version)
                        }
                        Some(_) => continue,
                    };
                    days.push(DaiRangeDayState {
                        sensor: sensor.to_string(),
                        date,
                        evidence,
                        mark,
                        stored_version,
                    });
                }
            }
        }
        Ok(days)
    }

    /// Brings the range days up to date after a restore, within `txn` at the
    /// time `now`, as
    /// [`Store::restore_from_backup`](crate::Store::restore_from_backup)
    /// describes: gives every unit a new lease token whose lease ends at
    /// `now`, and marks for recollection, for each sensor of `restored`, the
    /// stored units dated on or after the date of its latest restored cursor
    /// less its lookback window.
    pub(super) fn restore_range_days(
        &self,
        txn: &Txn<'_>,
        restored: &[RestoredCursor],
        now: i64,
    ) -> Result<()> {
        let today = date_of(now)?;
        // The latest restored cursor and the longest recent arrival delay of
        // each sensor.
        let mut cursors: BTreeMap<&str, (i64, i64)> = BTreeMap::new();
        for cursor in restored {
            let delay = cursor.row.longest_recent_delay(today);
            let entry = cursors
                .entry(cursor.sensor.as_str())
                .or_insert((cursor.row.cursor, delay));
            entry.0 = entry.0.max(cursor.row.cursor);
            entry.1 = entry.1.max(delay);
        }

        let mut units: BTreeMap<String, UnitRows> = BTreeMap::new();
        for (key, _) in Self::scan(&self.range_days, txn, &[])? {
            let (sensor, date, _) = decode_day_key(&key)?;
            let Some(mut row) = Self::get_row::<DayRow>(txn, &self.range_days, &key)? else {
                continue;
            };
            row.lease_token = Some(new_token(row.lease_token));
            row.lease_end = Some(now);
            units.entry(sensor).or_default().push((key, date, row));
        }

        for (sensor, rows) in &mut units {
            let Some(&(latest, delay)) = cursors.get(sensor.as_str()) else {
                continue;
            };
            let reported = rows
                .iter()
                .filter(|(_, date, _)| is_recent(*date, today))
                .map(|(_, _, row)| row.longest_delay)
                .max()
                .unwrap_or(0);
            let lookback = LOOKBACK.max(delay).max(reported);
            let from = date_of(latest.saturating_sub(lookback))?;
            let mut state: Option<SensorState> = None;
            for (_, date, row) in rows.iter_mut() {
                if row.stored_version.is_none() || *date < from {
                    continue;
                }
                if state.is_none() {
                    state = Some(self.sensor_state_for_update(txn, sensor)?);
                }
                let state = state.as_mut().context("the sensor state is read")?;
                row.mark = Some(state.take_mark());
            }
            if let Some(state) = &state {
                self.put_sensor_state(txn, sensor, state)?;
            }
        }

        for rows in units.values() {
            for (key, _, row) in rows {
                Self::put_row(txn, &self.range_days, key, row)?;
            }
        }
        Ok(())
    }

    /// Deletes the range blocks, subnets and days dated more than 30 days
    /// before the date of `now`.
    pub(super) fn expire_range_rows(&self, now: i64) -> Result<()> {
        let oldest = i64::from(date_of(now)?) - i64::from(RECENT_DAYS);
        self.delete_where(&self.range_blocks, |key, _| {
            Ok(i64::from(decode_block_key(key)?.2) < oldest)
        })?;
        self.delete_where(&self.range_subnets, |key, _| {
            Ok(i64::from(decode_subnet_key(key)?.2) < oldest)
        })?;
        self.delete_where(&self.range_days, |key, _| {
            Ok(i64::from(decode_day_key(key)?.1) < oldest)
        })
    }

    /// Returns the customer's candidate ranges at the time `now`, as
    /// [`Store::dai_range_candidates`] describes.
    #[allow(clippy::too_many_lines)] // The steps of one read, in their documented order.
    pub(super) fn range_candidates(
        &self,
        customer_id: u32,
        now: i64,
    ) -> Result<Vec<DaiRangeCandidate>> {
        self.read(|txn| {
            let reference = i64::from(date_of(now)?) - 1;
            let window_start = reference - i64::from(WINDOW_DAYS) + 1;
            let in_window = |date: i32| (window_start..=reference).contains(&i64::from(date));
            let prefix = customer_key(customer_id);

            // The blocks of the window.
            let mut blocks = Vec::new();
            let mut sensors = BTreeSet::new();
            for (key, value) in Self::scan(&self.range_blocks, txn, &prefix)? {
                let (_, sensor, date, evidence, block) = decode_block_key(&key)?;
                if !in_window(date) {
                    continue;
                }
                let row: BlockRow = super::super::deserialize(&value)?;
                sensors.insert(sensor.clone());
                blocks.push((sensor, date, evidence, block, row));
            }

            // The private subnets each sensor saw, under the customer and
            // late, from 13 dates before the window on.
            let subnets_from = window_start - i64::from(WINDOW_DAYS) + 1;
            let near = |date: i32| (subnets_from..=reference).contains(&i64::from(date));
            let mut subnets: BTreeMap<String, Vec<(i32, IpNet)>> = BTreeMap::new();
            for (key, _) in Self::scan(&self.range_subnets, txn, &prefix)? {
                let (_, sensor, date, subnet) = decode_subnet_key(&key)?;
                if sensors.contains(&sensor) && near(date) && is_private(&subnet) {
                    subnets.entry(sensor).or_default().push((date, subnet));
                }
            }
            for sensor in &sensors {
                for (key, value) in Self::scan(&self.range_days, txn, &sensor_key(sensor))? {
                    let (_, date, evidence) = decode_day_key(&key)?;
                    if evidence != DaiRangeEvidence::Sensor || !near(date) {
                        continue;
                    }
                    let row: DayRow = super::super::deserialize(&value)?;
                    let entry = subnets.entry(sensor.clone()).or_default();
                    for subnet in row.late_subnets.iter().filter(|s| is_private(s)) {
                        entry.push((date, *subnet));
                    }
                }
            }

            // The value of each range per (sensor, date, evidence).
            let mut ranges: BTreeMap<IpNet, Values> = BTreeMap::new();
            for (sensor, date, evidence, block, row) in blocks {
                let earliest = i64::from(date) - i64::from(WINDOW_DAYS) + 1;
                let range = subnets
                    .get(&sensor)
                    .into_iter()
                    .flatten()
                    .filter(|(subnet_date, subnet)| {
                        (earliest..=i64::from(date)).contains(&i64::from(*subnet_date))
                            && subnet.contains(&block)
                    })
                    .map(|(_, subnet)| *subnet)
                    .min_by_key(IpNet::prefix_len)
                    .unwrap_or(block);
                let value = ranges
                    .entry(range)
                    .or_default()
                    .entry((sensor, date, evidence))
                    .or_default();
                let addrs = if row.saturated {
                    SATURATED_ADDRS
                } else {
                    u64::from(row.distinct_addrs)
                };
                value.addrs = value.addrs.saturating_add(addrs);
                value.conns = value.conns.saturating_add(row.conns);
                value.saturated |= row.saturated;
            }

            // The exclusions.
            let ignored: BTreeSet<IpNet> = Self::scan(&self.range_ignores, txn, &prefix)?
                .into_iter()
                .map(|(key, _)| decode_ignore_key(&key).map(|(_, range)| range))
                .collect::<Result<_>>()?;
            let networks = OwnedNetworkTable::open(self.db)
                .context("customer network table must be present")?
                .get_in_transaction(txn, customer_id)?;
            let registered = dai_network_digest(networks.as_ref())?.registered;
            let is_registered = |range: &IpNet| {
                registered.networks.iter().any(|net| net.contains(range))
                    || registered
                        .ip_ranges
                        .iter()
                        .any(|ip_range| range_contains(*ip_range.start(), *ip_range.end(), range))
            };

            // The sites.
            let default_site = self
                .sites_in(txn, customer_id)?
                .into_iter()
                .find(|site| site.is_default)
                .map(|site| site.token);
            let mut histories: BTreeMap<String, Vec<(i64, SensorSite)>> = BTreeMap::new();

            let mut candidates = Vec::new();
            for (range, values) in ranges {
                if ignored.contains(&range) || is_registered(&range) || !is_private(&range) {
                    continue;
                }
                let dates: BTreeSet<i32> = values.keys().map(|(_, date, _)| *date).collect();
                if dates.len() < MIN_DATES {
                    continue;
                }
                let (Some(&first_date), Some(&last_date)) = (dates.first(), dates.last()) else {
                    continue;
                };
                let seen_addrs = values.values().map(|v| v.addrs).max().unwrap_or(0);
                let seen_addrs_at_least = values
                    .values()
                    .any(|v| v.addrs == seen_addrs && v.saturated);
                let mut counts: BTreeMap<DaiRangeEvidence, u64> = EVIDENCES
                    .into_iter()
                    .map(|evidence| (evidence, 0))
                    .collect();
                for (_, _, evidence) in values.keys() {
                    *counts.entry(*evidence).or_default() += 1;
                }
                let mut sites = BTreeSet::new();
                if let Some(default) = &default_site {
                    let sensor_dates: BTreeSet<(&str, i32)> = values
                        .keys()
                        .map(|(sensor, date, _)| (sensor.as_str(), *date))
                        .collect();
                    for (sensor, date) in sensor_dates {
                        if !histories.contains_key(sensor) {
                            let history = self.sensor_history(txn, customer_id, sensor)?;
                            histories.insert(sensor.to_string(), history);
                        }
                        let history = histories
                            .get(sensor)
                            .context("the sensor site history is read")?;
                        let start = date_start(date);
                        let end = date_start(date.saturating_add(1));
                        sites.insert(site_at(history, default, start));
                        for (effective, _) in history {
                            if (start..end).contains(effective) {
                                sites.insert(site_at(history, default, *effective));
                            }
                        }
                    }
                }
                candidates.push(DaiRangeCandidate {
                    range,
                    seen_addrs,
                    seen_addrs_at_least,
                    values: counts,
                    first_date,
                    last_date,
                    sites: sites.into_iter().collect(),
                    cgnat: CGNAT.contains(&range),
                });
            }
            candidates.sort_unstable_by_key(|candidate| {
                (candidate.range.network(), candidate.range.prefix_len())
            });
            Ok(candidates)
        })
    }

    /// Returns the `dai sensor sites` rows of `sensor` naming the customer,
    /// as `txn` sees them, in effective time order.
    fn sensor_history(
        &self,
        txn: &Txn<'_>,
        customer_id: u32,
        sensor: &str,
    ) -> Result<Vec<(i64, SensorSite)>> {
        let mut history = Vec::new();
        for (key, value) in Self::scan(&self.sensor_sites, txn, &sensor_key(sensor))? {
            let (_, effective, row) = decode_sensor_site(&key, &value)?;
            if row.customer_id == customer_id {
                history.push((effective, row));
            }
        }
        Ok(history)
    }

    /// Ignores `range` for the customer at the time `now`, as
    /// [`Store::ignore_dai_range`] describes.
    pub(super) fn ignore_range(
        &self,
        customer_id: u32,
        range: IpNet,
        account: &str,
        now: i64,
    ) -> Result<IpNet> {
        let range = range.trunc();
        let key = ignore_key(customer_id, range);
        self.write_if(|txn| {
            if Self::get_row::<IgnoreRow>(txn, &self.range_ignores, &key)?.is_some() {
                return Ok((range, false));
            }
            let row = IgnoreRow {
                ignored_at: now,
                account: account.to_string(),
            };
            Self::put_row(txn, &self.range_ignores, &key, &row)?;
            Ok((range, true))
        })
    }

    /// Stops ignoring `range` for the customer, as
    /// [`Store::unignore_dai_range`] describes.
    pub(super) fn unignore_range(&self, customer_id: u32, range: IpNet) -> Result<bool> {
        let key = ignore_key(customer_id, range.trunc());
        self.write_if(|txn| {
            if Self::get_row::<IgnoreRow>(txn, &self.range_ignores, &key)?.is_none() {
                return Ok((false, false));
            }
            Self::delete_row(txn, &self.range_ignores, &key)?;
            Ok((true, true))
        })
    }

    /// Returns the ranges the customer ignores, in key order.
    pub(super) fn ignored_ranges(&self, customer_id: u32) -> Result<Vec<DaiIgnoredRange>> {
        self.read(|txn| {
            Self::scan(&self.range_ignores, txn, &customer_key(customer_id))?
                .into_iter()
                .map(|(key, value)| {
                    let (_, range) = decode_ignore_key(&key)?;
                    let row: IgnoreRow = super::super::deserialize(&value)?;
                    Ok(DaiIgnoredRange {
                        range,
                        ignored_at: row.ignored_at,
                        account: row.account,
                    })
                })
                .collect()
        })
    }
}

/// Returns the site at the time `time` by the sensor site lookup: the site
/// of the latest row of `history` effective at or before `time`, or
/// `default`.
fn site_at(history: &[(i64, SensorSite)], default: &str, time: i64) -> String {
    history
        .iter()
        .take_while(|(effective, _)| *effective <= time)
        .last()
        .map_or(default, |(_, row)| row.site.as_str())
        .to_string()
}

impl Store {
    /// Begins a round of collection of the DAI range day `unit` at the time
    /// `now`, for a `begin_dai_range_day` request carrying
    /// `restore_generation`.
    ///
    /// In this order: `None`, the not-collected answer, writing nothing, if
    /// the sensor is not a customer sensor (for a customer with device
    /// identification off too, the sensor is handled like any other);
    /// [`DaiRangeGrant::Resync`], writing nothing, if `restore_generation`
    /// is not the current restore generation; a refusal if the date is more
    /// than one day after the date of `now`;
    /// [`DaiRangeGrant::InProgress`] with the lease end, writing nothing, if
    /// the unit's lease ends after `now`. Otherwise the unit's version is
    /// incremented (the first grant is version 1), a new random lease token
    /// other than the unit's current one replaces it, the lease ends 10
    /// minutes after `now`, and the answer is [`DaiRangeGrant::Granted`].
    ///
    /// # Errors
    ///
    /// Returns [`DaiRangeError::FutureDate`] inside the error, writing
    /// nothing, if the date is more than one day after today. Returns an
    /// error if the database operation fails.
    pub fn begin_dai_range_day(
        &self,
        unit: &DaiRangeUnit,
        restore_generation: u64,
        now: i64,
    ) -> Result<Option<DaiRangeGrant>> {
        self.states
            .dai()
            .begin_range_day(unit, restore_generation, now)
    }

    /// Renews the lease `lease_token` of the DAI range day `unit` at the
    /// time `now`, and returns the new lease end, 10 minutes after `now`.
    ///
    /// The token is accepted while it is the unit's current one, even after
    /// its lease has ended, until a new begin replaces it. Any other token
    /// gets `None` and writes nothing. Neither the sensor's customer nor the
    /// restore generation is checked: a restore replaces every token.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn renew_dai_range_day(
        &self,
        unit: &DaiRangeUnit,
        lease_token: u64,
        now: i64,
    ) -> Result<Option<i64>> {
        self.states.dai().renew_range_day(unit, lease_token, now)
    }

    /// Stores the counts of a DAI range day at the time `now`, in one
    /// optimistic transaction, and returns the outcome with the current
    /// restore generation: [`DaiStoreOutcome::Stored`] with no marks,
    /// [`DaiStoreOutcome::Resync`] or [`DaiStoreOutcome::NotCollected`],
    /// never [`DaiStoreOutcome::Staged`].
    ///
    /// The checks run in this order:
    ///
    /// 1. If the sensor is not a customer sensor, the outcome is
    ///    `NotCollected`, and nothing is written. A customer with device
    ///    identification off is handled like any other.
    /// 2. If the restore generation, the configuration epoch or the network
    ///    digest is not the current one, the outcome is `Resync`, and
    ///    nothing is written.
    /// 3. An invalid field is refused with a [`DaiRangeError`], writing
    ///    nothing.
    /// 4. If the lease token is not the unit's current one, or the version
    ///    is below the last granted version, the outcome is `Stored` and
    ///    nothing is written: a superseded result never changes the counts
    ///    or the mark.
    /// 5. If the version is above the stored version, or none is stored, the
    ///    unit's blocks and the sensor's subnets of the date under the
    ///    sensor's customer are replaced by the new ones, and the stored
    ///    version is set. The unit's late subnets stay.
    /// 6. If the version is the stored version, the blocks are merged: per
    ///    block the larger distinct address and connection counts are kept
    ///    and `saturated` is the logical OR; the subnets are added.
    /// 7. In cases 5 and 6, a `mark` equal to the unit's recollect mark
    ///    clears it.
    ///
    /// A subnet is stored as its network address, an `IPv4` subnet longer
    /// than /24 as its /24 and an `IPv6` subnet longer than /64 as its /64.
    /// No check depends on `now`, the time of the request, and no date is
    /// refused for its age: retention removes old rows. The method reads the
    /// customer's `dai site policy guard` row for update before it reads the
    /// configuration epoch or the networks, so a send racing a configuration
    /// write of the customer conflicts with it and is checked again.
    ///
    /// # Errors
    ///
    /// Returns, inside the error and writing nothing, a [`DaiRangeError`]:
    /// `ZeroVersion` if `version` is 0, `UngrantedVersion` if it is above
    /// the unit's last granted version, `InvalidBlock` if a block is not an
    /// `IPv4` /24 or `IPv6` /64 network address, and `DuplicateBlock` if a
    /// block is listed twice. Returns an error if the customer's networks
    /// cannot be encoded or if the database operation fails.
    pub fn send_dai_range_day(&self, day: &DaiRangeDay, now: i64) -> Result<DaiStoreOutcome> {
        // Taken, as by every other range day method, for the time of the
        // request, which no check of a send depends on.
        let _ = now;
        self.states.dai().send_range_day(day)
    }

    /// Records the late DAI range records of a `report_dai_range_late`
    /// request at the time `now`, and returns the marks assigned to its
    /// late days.
    ///
    /// If the sensor is not a customer sensor, the list is empty and nothing
    /// is written; a customer with device identification off is handled
    /// like any other. Each distinct (date, evidence) of `late_days` gets a
    /// new recollect mark from the sensor's mark counter, which the slot
    /// re-extract marks use too and whose numbers are never reused,
    /// replacing any earlier mark, and the list holds one mark per distinct
    /// unit, in the order of first appearance. Each entry's delay, a
    /// negative one as 0, becomes the unit's longest reported delay if it is
    /// longer. Each `late_subnets` entry adds its subnet, as its network
    /// address (an `IPv4` subnet longer than /24 as its /24, an `IPv6` one
    /// longer than /64 as its /64), to the late subnets of the unit (sensor,
    /// date, `Sensor`); a later replace of the unit keeps it. A unit row is
    /// created if it has none.
    ///
    /// # Errors
    ///
    /// Returns, inside the error and writing nothing,
    /// [`DaiRangeError::StaleRestoreGeneration`] if the restore generation
    /// is not the current one, and [`DaiRangeError::FutureDate`] if a date
    /// is more than one day after the date of `now`. Returns an error if the
    /// database operation fails.
    pub fn report_dai_range_late(
        &self,
        late: &DaiRangeLate,
        now: i64,
    ) -> Result<Vec<DaiRangeMark>> {
        self.states.dai().report_range_late(late, now)
    }

    /// Returns the customer's candidate unregistered internal ranges at the
    /// time `now`, ordered by range: `IPv4` before `IPv6`, then by address,
    /// then by prefix length.
    ///
    /// The window is the 14 dates ending with the last date that has ended,
    /// the date before the date of `now`. A block of sensor S on date D,
    /// stored under the customer, belongs to the widest subnet containing it
    /// among S's subnets under the customer and S's late subnets dated D − 13
    /// through D that lie in a private prefix, or to the block itself. The
    /// value of a range for (sensor, date) sums those of the sensor's blocks
    /// of the date: their distinct addresses (65,536 for a saturated block)
    /// and connections, saturating, and whether one is saturated. A range
    /// valued on at least 3 dates of the window is a candidate, unless the
    /// customer ignores it, a network or an IP range of the customer's
    /// registered networks contains it, or it is not within `10.0.0.0/8`,
    /// `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` or `fc00::/7`.
    /// Ranges from different sensors are never merged, but one range from
    /// two sensors is one candidate. See [`DaiRangeCandidate`] for the
    /// fields; a sensor's site on a date is its site at the start of the
    /// date and at each change of its site within the date.
    ///
    /// # Errors
    ///
    /// Returns an error if the customer's networks cannot be encoded or if
    /// the database operation fails.
    pub fn dai_range_candidates(
        &self,
        customer_id: u32,
        now: i64,
    ) -> Result<Vec<DaiRangeCandidate>> {
        self.states.dai().range_candidates(customer_id, now)
    }

    /// Returns the number of the customer's candidate ranges at the time
    /// `now`, as [`dai_range_candidates`](Self::dai_range_candidates)
    /// computes them.
    // Read by the collection status, which a later change adds.
    #[allow(dead_code)]
    pub(crate) fn dai_range_candidate_count(&self, customer_id: u32, now: i64) -> Result<usize> {
        Ok(self.dai_range_candidates(customer_id, now)?.len())
    }

    /// Ignores the candidate range `range` for the customer, recording
    /// `now` and `account`, and returns the range normalized to its network
    /// address, as it is stored.
    ///
    /// Ignoring a range already ignored changes nothing: the first time and
    /// account stay. Ignored ranges are not subject to retention.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn ignore_dai_range(
        &self,
        customer_id: u32,
        range: IpNet,
        account: &str,
        now: i64,
    ) -> Result<IpNet> {
        self.states
            .dai()
            .ignore_range(customer_id, range, account, now)
    }

    /// Stops ignoring the range `range`, normalized to its network address,
    /// for the customer, and returns whether it was ignored.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn unignore_dai_range(&self, customer_id: u32, range: IpNet) -> Result<bool> {
        self.states.dai().unignore_range(customer_id, range)
    }

    /// Returns the ranges the customer ignores, ordered by range as the
    /// candidates are.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn dai_ignored_ranges(&self, customer_id: u32) -> Result<Vec<DaiIgnoredRange>> {
        self.states.dai().ignored_ranges(customer_id)
    }
}
