//! The restore generation and the read cursors of device identification.
//!
//! Per (sensor, kind) a cursor row holds the **cursor**, the slot boundary up
//! to which every slot is confirmed stored, and the **read floor**, the time
//! before which the agent counts no record, with the slots confirmed out of
//! order, the slots marked for re-extraction and the longest arrival delay
//! of late records per date. The **restore generation** in `dai meta` tells
//! the agent that a backup was restored and its state is stale.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::{Context, Result, anyhow};
use review_protocol::types::{DaiCursorEntry, DaiCursors, DaiObservationKind, DaiReextractMark};
use serde::{Deserialize, Serialize};

use super::{CustomerSensors, Dai, DaiSettings, FIVE_MINUTES, KINDS, Txn, sensor_key};
use crate::EXCLUSIVE;

/// The key of the restore generation in `dai meta`.
const RESTORE_GENERATION: &[u8] = b"restore generation";
/// The key, in the `default` column family, of the marker an offline restore
/// leaves for the next open to move the cursors back.
pub(in crate::tables) const RESTORE_MARKER: &[u8] = b"dai restore pending";
/// The number of nanoseconds in a day.
pub(super) const DAY: i64 = 24 * 60 * 60 * 1_000_000_000;
/// The shortest lookback window of a restore: 24 hours.
pub(super) const LOOKBACK: i64 = DAY;
/// The number of days arrival delays and re-extract marks are kept.
pub(super) const RECENT_DAYS: i32 = 30;
/// The list a request names to mean every customer sensor.
const ALL_SENSORS: &str = "all";

/// The stored value of a `dai cursors` row.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct CursorRow {
    /// The slot boundary up to which every slot is confirmed stored.
    pub(super) cursor: i64,
    /// The time before which no record is counted.
    pub(super) read_floor: i64,
    /// The slots confirmed after the cursor: each slot's end with the
    /// `counted_from` of the send that confirmed it.
    pub(super) confirmed: BTreeMap<i64, i64>,
    /// The slots marked for re-extraction: each slot's start with its mark.
    pub(super) marks: BTreeMap<i64, u64>,
    /// The longest arrival delay of a late record, in nanoseconds, per date
    /// it was recorded on, for the last [`RECENT_DAYS`] days.
    pub(super) delays: BTreeMap<i32, i64>,
}

impl CursorRow {
    /// Returns a new row whose read floor is `read_floor` and whose cursor
    /// is the start of the slot holding it.
    fn at(read_floor: i64) -> Result<Self> {
        Ok(Self {
            cursor: slot_floor(read_floor)?,
            read_floor,
            ..Self::default()
        })
    }

    /// Returns the longest arrival delay recorded on a date within the
    /// [`RECENT_DAYS`] days up to `today`.
    pub(super) fn longest_recent_delay(&self, today: i32) -> i64 {
        self.delays
            .iter()
            .filter(|(date, _)| is_recent(**date, today))
            .map(|(_, delay)| *delay)
            .max()
            .unwrap_or(0)
    }

    /// Records `delay` on `today`, keeping the longest per date, and drops
    /// the dates older than [`RECENT_DAYS`] days.
    pub(super) fn record_delay(&mut self, today: i32, delay: i64) {
        let longest = self.delays.entry(today).or_insert(delay);
        *longest = (*longest).max(delay);
        self.delays.retain(|date, _| is_recent(*date, today));
    }
}

/// Returns whether `date` is one of the [`RECENT_DAYS`] days ending with
/// `today`; a date after `today` is not.
pub(super) fn is_recent(date: i32, today: i32) -> bool {
    i64::from(date) > i64::from(today) - i64::from(RECENT_DAYS) && date <= today
}

/// Returns the start of the slot holding `time`.
pub(super) fn slot_floor(time: i64) -> Result<i64> {
    time.div_euclid(FIVE_MINUTES)
        .checked_mul(FIVE_MINUTES)
        .ok_or_else(|| anyhow!("time {time} has no slot"))
}

/// Returns the date, days since the UNIX epoch in UTC, of `time`.
pub(super) fn date_of(time: i64) -> Result<i32> {
    i32::try_from(time.div_euclid(DAY)).context("a date is out of range")
}

/// Returns the key of a row keyed by (sensor, kind).
pub(super) fn pair_key(sensor: &str, kind: DaiObservationKind) -> Vec<u8> {
    super::KeyWriter::default()
        .str(sensor)
        .dai_kind(kind)
        .finish()
}

/// Decodes the key of a row keyed by (sensor, kind).
pub(super) fn decode_pair_key(key: &[u8]) -> Result<(String, DaiObservationKind)> {
    let mut reader = super::KeyReader::new(key);
    let sensor = reader.str()?;
    let kind = reader.dai_kind()?;
    reader.finish()?;
    Ok((sensor, kind))
}

/// A cursor row as a restore found it, before it is moved back.
pub(super) struct RestoredCursor {
    pub(super) sensor: String,
    pub(super) kind: DaiObservationKind,
    pub(super) row: CursorRow,
}

impl Dai<'_> {
    // ---- The restore generation ----

    /// Returns the restore generation as `txn` sees it, read for update, or
    /// `None` if there is none.
    pub(super) fn generation_in(&self, txn: &Txn<'_>) -> Result<Option<u64>> {
        Self::get_row(txn, &self.meta, RESTORE_GENERATION)
    }

    /// Writes a new random restore generation within `txn`, after reading
    /// the old one for update.
    fn renew_generation(&self, txn: &Txn<'_>) -> Result<u64> {
        self.generation_in(txn)?;
        let generation = rand::random();
        Self::put_row(txn, &self.meta, RESTORE_GENERATION, &generation)?;
        Ok(generation)
    }

    /// Returns the restore generation, drawing a random one first if the
    /// store has none.
    ///
    /// The key is read for update, so concurrent first reads return the
    /// same value. Opening the states database calls this, so the store,
    /// cursor and restore methods always find a generation and never draw
    /// one.
    pub(crate) fn restore_generation(&self) -> Result<u64> {
        self.write_if(|txn| {
            if let Some(generation) = self.generation_in(txn)? {
                return Ok((generation, false));
            }
            let generation = rand::random();
            Self::put_row(txn, &self.meta, RESTORE_GENERATION, &generation)?;
            Ok((generation, true))
        })
    }

    /// Returns the restore generation within `txn`, read for update.
    ///
    /// Opening the states database draws one if it has none, so it is
    /// missing only if a restore reopened the database and failed to write
    /// the new one, which the next open then writes.
    pub(super) fn current_generation(&self, txn: &Txn<'_>) -> Result<u64> {
        self.generation_in(txn)?
            .context("the DAI restore generation is missing")
    }

    // ---- Cursors ----

    /// Returns the cursor row of (`sensor`, `kind`) as `txn` sees it, read
    /// for update, or `None` if there is none.
    pub(super) fn cursor_in(
        &self,
        txn: &Txn<'_>,
        sensor: &str,
        kind: DaiObservationKind,
    ) -> Result<Option<CursorRow>> {
        Self::get_row(txn, &self.cursors, &pair_key(sensor, kind))
    }

    /// Writes the cursor row of (`sensor`, `kind`) within `txn`.
    pub(super) fn put_cursor(
        &self,
        txn: &Txn<'_>,
        sensor: &str,
        kind: DaiObservationKind,
        row: &CursorRow,
    ) -> Result<()> {
        Self::put_row(txn, &self.cursors, &pair_key(sensor, kind), row)
    }

    /// Returns the cursors of the customer sensors `sensors` names, creating
    /// the missing rows, as
    /// [`Store::dai_cursors`](crate::Store::dai_cursors) describes.
    pub(crate) fn cursors(&self, sensors: &[String], now: i64) -> Result<DaiCursors> {
        self.write_if(|txn| {
            let restore_generation = self.current_generation(txn)?;
            let customers = self.customer_sensors_in(txn)?;
            let selected = select_sensors(sensors, &customers);

            let mut rows: BTreeMap<(&str, u8), (DaiObservationKind, CursorRow)> = BTreeMap::new();
            let mut missing: BTreeMap<u32, BTreeMap<&str, Vec<DaiObservationKind>>> =
                BTreeMap::new();
            for (sensor, customer) in &selected {
                for kind in KINDS {
                    match self.cursor_in(txn, sensor, kind)? {
                        Some(row) => {
                            rows.insert((sensor, super::kind_number(kind)), (kind, row));
                        }
                        None => missing
                            .entry(*customer)
                            .or_default()
                            .entry(sensor)
                            .or_default()
                            .push(kind),
                    }
                }
            }

            let create = !missing.is_empty();
            for (customer, sensors) in missing {
                self.lock_customer(txn, customer)?;
                let settings = self.stored_settings(txn, customer)?.unwrap_or_default();
                let read_floor = creation_floor(&settings, now);
                for (sensor, kinds) in sensors {
                    let mut state = self.sensor_state_for_update(txn, sensor)?;
                    if state.first_cursor_time.is_none() {
                        state.first_cursor_time = Some(now);
                        self.put_sensor_state(txn, sensor, &state)?;
                    }
                    for kind in kinds {
                        let row = CursorRow::at(read_floor)?;
                        self.put_cursor(txn, sensor, kind, &row)?;
                        rows.insert((sensor, super::kind_number(kind)), (kind, row));
                    }
                }
            }

            let entries = rows
                .into_iter()
                .map(|((sensor, _), (kind, row))| DaiCursorEntry {
                    sensor: sensor.to_string(),
                    kind,
                    cursor: row.cursor,
                    read_floor: row.read_floor,
                    reextract: row
                        .marks
                        .iter()
                        .map(|(slot_start, mark)| DaiReextractMark {
                            kind,
                            slot_start: *slot_start,
                            mark: *mark,
                        })
                        .collect(),
                })
                .collect();
            let range_days = self.range_days_in(txn, selected.keys().copied(), now)?;
            let cursors = DaiCursors {
                restore_generation,
                entries,
                range_days,
            };
            #[cfg(test)]
            if create {
                super::run_before_commit_hook(self.db);
            }
            Ok((cursors, create))
        })
    }

    /// Returns the first cursor time of `sensor`, the time of the cursor
    /// read that created its first cursor row, or `None` if it has none.
    pub(crate) fn first_cursor_time(&self, sensor: &str) -> Result<Option<i64>> {
        self.read(|txn| self.first_cursor_time_in(txn, sensor))
    }

    /// Returns the first cursor time of `sensor` as `txn` sees it, without
    /// reading it for update.
    pub(super) fn first_cursor_time_in(&self, txn: &Txn<'_>, sensor: &str) -> Result<Option<i64>> {
        Ok(txn
            .get_cf(self.sensor_state.cf, sensor_key(sensor))
            .context("cannot read DAI sensor state")?
            .map(|value| super::super::deserialize::<super::SensorState>(&value))
            .transpose()?
            .and_then(|state| state.first_cursor_time))
    }

    /// Moves, within `txn`, every cursor row of `sensors` to the enable time
    /// `enabled_at`: the read floor to it, the cursor to the start of the
    /// slot holding it, with no confirmed slot and no re-extract mark.
    pub(super) fn move_cursors_to_enable(
        &self,
        txn: &Txn<'_>,
        sensors: &BTreeSet<String>,
        enabled_at: i64,
    ) -> Result<()> {
        for sensor in sensors {
            for (key, _) in Self::scan(&self.cursors, txn, &sensor_key(sensor))? {
                let Some(row) = Self::get_row::<CursorRow>(txn, &self.cursors, &key)? else {
                    continue;
                };
                let moved = CursorRow {
                    delays: row.delays,
                    ..CursorRow::at(enabled_at)?
                };
                Self::put_row(txn, &self.cursors, &key, &moved)?;
            }
        }
        Ok(())
    }

    // ---- After a restore ----

    /// Brings the restored state up to date at the time `now`, in one
    /// transaction: writes a new random restore generation, removes the
    /// restore marker, gives every range day a new lease token ending at
    /// `now` and marks for recollection the stored range days within each
    /// sensor's lookback window, and moves every cursor back by its lookback
    /// window, as
    /// [`Store::restore_from_backup`](crate::Store::restore_from_backup)
    /// describes.
    ///
    /// The cursor rows are read, as restored, before any of them moves; a
    /// step that needs the restored cursors and arrival delays goes between
    /// [`restored_cursors`](Self::restored_cursors) and
    /// [`move_cursors_back`](Self::move_cursors_back).
    pub(crate) fn after_restore(&self, now: i64) -> Result<()> {
        self.write(|txn| {
            self.renew_generation(txn)?;
            txn.get_for_update(RESTORE_MARKER, EXCLUSIVE)
                .context("cannot read the DAI restore marker")?;
            txn.delete(RESTORE_MARKER)
                .context("cannot delete the DAI restore marker")?;
            let restored = self.restored_cursors(txn)?;
            self.restore_range_days(txn, &restored, now)?;
            self.move_cursors_back(txn, restored, now)
        })
    }

    /// Returns every cursor row as `txn` sees it, each read for update.
    fn restored_cursors(&self, txn: &Txn<'_>) -> Result<Vec<RestoredCursor>> {
        let mut restored = Vec::new();
        for (key, _) in Self::scan(&self.cursors, txn, &[])? {
            let (sensor, kind) = decode_pair_key(&key)?;
            if let Some(row) = Self::get_row(txn, &self.cursors, &key)? {
                restored.push(RestoredCursor { sensor, kind, row });
            }
        }
        Ok(restored)
    }

    /// Moves each of the `restored` cursors back within `txn`: by the longer
    /// of 24 hours and the longest arrival delay recorded in the last 30
    /// days up to `now`, rounded down to a slot boundary, never before the
    /// start of the slot holding the read floor nor of the slot holding the
    /// last-enabled time of the sensor's customer, and never after the
    /// restored cursor. The confirmed slots are cleared; the read floor and
    /// the re-extract marks stay.
    fn move_cursors_back(
        &self,
        txn: &Txn<'_>,
        restored: Vec<RestoredCursor>,
        now: i64,
    ) -> Result<()> {
        let today = date_of(now)?;
        let customers = self.customer_sensors_in(txn)?;
        let mut enabled_at: BTreeMap<u32, Option<i64>> = BTreeMap::new();
        for RestoredCursor {
            sensor,
            kind,
            mut row,
        } in restored
        {
            let lookback = LOOKBACK.max(row.longest_recent_delay(today));
            let mut cursor = slot_floor(row.cursor.saturating_sub(lookback))?;
            cursor = cursor.max(slot_floor(row.read_floor)?);
            if let Some(customer) = customers.customer(&sensor) {
                let last_enabled = if let Some(time) = enabled_at.get(&customer) {
                    *time
                } else {
                    let time = self
                        .stored_settings(txn, customer)?
                        .and_then(|settings| settings.last_enabled_time);
                    enabled_at.insert(customer, time);
                    time
                };
                if let Some(time) = last_enabled {
                    cursor = cursor.max(slot_floor(time)?);
                }
            }
            row.cursor = cursor.min(row.cursor);
            row.confirmed.clear();
            self.put_cursor(txn, &sensor, kind, &row)?;
        }
        Ok(())
    }
}

/// Returns the read floor of a cursor row created at `now` for a sensor of
/// a customer with `settings`: `now`, or the last-enabled time if the
/// customer is enabled and that is later.
fn creation_floor(settings: &DaiSettings, now: i64) -> i64 {
    match settings.last_enabled_time {
        Some(enabled) if settings.device_account_identification => now.max(enabled),
        _ => now,
    }
}

/// Returns the customer sensors a sensor list names, with their customers,
/// in name order: every customer sensor for a list that is exactly
/// `["all"]`, and otherwise the named ones that are customer sensors.
fn select_sensors<'a>(
    sensors: &'a [String],
    customers: &'a CustomerSensors,
) -> BTreeMap<&'a str, u32> {
    if let [only] = sensors
        && only == ALL_SENSORS
    {
        return customers.iter().collect();
    }
    sensors
        .iter()
        .filter_map(|sensor| {
            customers
                .customer(sensor)
                .map(|customer| (sensor.as_str(), customer))
        })
        .collect()
}

/// Leaves, in the restored states database at `path`, a marker the next
/// open of the store applies: a new restore generation and every cursor
/// moved back. An offline restore leaves it for the next store; an online
/// restore leaves it before it reopens the database and applies it right
/// after, so a process stopped in between applies it at its next open.
///
/// A database without the `dai meta` and `dai cursors` families, which an
/// earlier build left, needs nothing: its first opened store draws a fresh
/// generation and has no cursor row. The database is opened with the
/// families it has, so one of another format gets no family it lacks.
///
/// # Errors
///
/// Returns an error if the database cannot be opened or written.
pub(crate) fn mark_restored(path: &Path) -> Result<(), rocksdb::Error> {
    let families = rocksdb::DB::list_cf(&rocksdb::Options::default(), path)?;
    let has = |name: &str| families.iter().any(|family| family == name);
    if !has(super::super::DAI_META) || !has(super::super::DAI_CURSORS) {
        return Ok(());
    }
    let db = rocksdb::DB::open_cf(&rocksdb::Options::default(), path, &families)?;
    let mut opts = rocksdb::WriteOptions::default();
    // The marker must survive a crash once the restored database is swapped
    // in, or the restore would keep the backup's generation and cursors.
    opts.set_sync(true);
    db.put_opt(RESTORE_MARKER, [], &opts)
}

/// Returns whether the states database `db` holds the marker
/// [`mark_restored`] leaves.
pub(crate) fn is_marked_restored(db: &rocksdb::OptimisticTransactionDB) -> Result<bool> {
    Ok(db
        .get(RESTORE_MARKER)
        .context("cannot read the DAI restore marker")?
        .is_some())
}
