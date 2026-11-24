//! The retention of the DAI observation tables, and their part of a
//! customer's deletion.
//!
//! Retention scans each table outside any transaction and then removes or
//! folds what it found in transactions of at most
//! [`ROWS_PER_TRANSACTION`](super::ROWS_PER_TRANSACTION) rows, each row read
//! for update and checked again before it is changed, so a row a concurrent
//! write changed in between is decided from its new value.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use review_protocol::types::DaiObservationKind;

use super::{
    Dai, DeletionNames, ROWS_PER_TRANSACTION, Txn,
    cursor::{CursorRow, DAY, RECENT_DAYS, date_of, decode_pair_key, pair_key},
    customer_key,
    observation::{
        ActivityRow, DaiCounterKind, ObservationRow, PER_SLOT_AGE, SeenRow, SendRow,
        decode_counter_key, decode_observation_key, decode_pending_key, summary_key,
    },
    sensor_key,
};
use crate::Map;

/// The age after which a pending observation is deleted unapplied, and a
/// re-extract mark removed: 30 days.
const RECENT_AGE: i64 = 30 * DAY;
/// The age after which a send is deleted, finished or not: one day.
const SEND_AGE: i64 = DAY;
/// The age after which a summary, an address activity or a catch-up gap is
/// deleted: 180 days.
const LONG_AGE: i64 = 180 * DAY;

impl Dai<'_> {
    /// Applies the retention rules at the time `now`, as
    /// [`Store::apply_dai_retention`](crate::Store::apply_dai_retention)
    /// describes.
    pub(crate) fn apply_retention(&self, now: i64) -> Result<()> {
        self.fold_observations(now)?;
        self.expire_pending(now)?;
        self.expire_sends(now)?;
        self.expire_marks(now)?;
        let long_ago = now.saturating_sub(LONG_AGE);
        self.delete_where(&self.summaries, |_, value| {
            Ok(super::super::deserialize::<SeenRow>(value)?.last_seen < long_ago)
        })?;
        self.delete_where(&self.ip_activity, |_, value| {
            Ok(super::super::deserialize::<ActivityRow>(value)?.last_seen < long_ago)
        })?;
        self.delete_where(&self.catchup_gaps, |_, value| {
            Ok(super::super::deserialize::<i64>(value)? < long_ago)
        })?;
        let oldest_counter = i64::from(date_of(now)?) - i64::from(RECENT_DAYS);
        self.delete_where(&self.counters, |key, _| {
            let (_, _, date) = decode_counter_key(key)?;
            Ok(i64::from(date) < oldest_counter)
        })?;
        self.expire_range_rows(now)?;
        self.apply_device_retention(now)
    }

    /// Deletes every row of `map` that `expired` selects, each read for
    /// update and checked again in the transaction that deletes it.
    pub(super) fn delete_where(
        &self,
        map: &Map<'_>,
        expired: impl Fn(&[u8], &[u8]) -> Result<bool>,
    ) -> Result<()> {
        let rows = self.scan_rows(map, &[], |key, value| expired(key, value))?;
        for chunk in rows.chunks(ROWS_PER_TRANSACTION) {
            self.write(|txn| {
                for (key, _) in chunk {
                    let Some(value) = txn
                        .get_for_update_cf(map.cf, key, crate::EXCLUSIVE)
                        .map_err(anyhow::Error::from)?
                    else {
                        continue;
                    };
                    if expired(key, &value)? {
                        Self::delete_row(txn, map, key)?;
                    }
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Folds the per-slot observations whose slot started more than 7 days
    /// before `now` into the summaries, deleting them; each row's summary
    /// write and deletion are one transaction.
    fn fold_observations(&self, now: i64) -> Result<()> {
        let oldest = now.saturating_sub(PER_SLOT_AGE);
        let old = |key: &[u8]| -> Result<bool> {
            let (_, _, slot_start, _) = decode_observation_key(key)?;
            Ok(slot_start < oldest)
        };
        let rows = self.scan_rows(&self.observations, &[], |key, _| old(key))?;
        for chunk in rows.chunks(ROWS_PER_TRANSACTION) {
            self.write(|txn| {
                for (key, _) in chunk {
                    let Some(row) = Self::get_row::<ObservationRow>(txn, &self.observations, key)?
                    else {
                        continue;
                    };
                    let (sensor, kind, _, hash) = decode_observation_key(key)?;
                    let summary = summary_key(&sensor, kind, &hash);
                    let folded = match Self::get_row::<SeenRow>(txn, &self.summaries, &summary)? {
                        Some(stored) => stored.widened(&row.body, row.first_seen, row.last_seen),
                        None => SeenRow {
                            body: row.body,
                            first_seen: row.first_seen,
                            last_seen: row.last_seen,
                        },
                    };
                    Self::put_row(txn, &self.summaries, &summary, &folded)?;
                    Self::delete_row(txn, &self.observations, key)?;
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Deletes the pending observations whose slot started more than 30
    /// days before `now`, adding each to the "not applied" counter of its
    /// sensor's current customer, and recomputes the earliest pending slot
    /// of each (sensor, kind) it deleted from and the sensor's resolver
    /// point, if it has one, in one transaction per sensor.
    fn expire_pending(&self, now: i64) -> Result<()> {
        let oldest = now.saturating_sub(RECENT_AGE);
        let rows = self.scan_rows(&self.pending, &[], |key, _| {
            let (_, slot_start, _, _) = decode_pending_key(key)?;
            Ok(slot_start < oldest)
        })?;
        let mut by_sensor: BTreeMap<String, Vec<Box<[u8]>>> = BTreeMap::new();
        for (key, _) in rows {
            let (sensor, _, _, _) = decode_pending_key(&key)?;
            by_sensor.entry(sensor).or_default().push(key);
        }
        for (sensor, keys) in by_sensor {
            for chunk in keys.chunks(ROWS_PER_TRANSACTION) {
                self.write(|txn| {
                    let mut deleted = 0_u64;
                    let mut kinds = BTreeSet::new();
                    for key in chunk {
                        if Self::get_row::<SeenRow>(txn, &self.pending, key)?.is_none() {
                            continue;
                        }
                        let (_, _, kind, _) = decode_pending_key(key)?;
                        Self::delete_row(txn, &self.pending, key)?;
                        deleted += 1;
                        kinds.insert(super::kind_number(kind));
                    }
                    if deleted > 0
                        && let Some(customer) = self.customer_sensors_in(txn)?.customer(&sensor)
                    {
                        self.add_counter(txn, customer, DaiCounterKind::NotApplied, now, deleted)?;
                    }
                    self.recompute_earliest_pending_of(txn, &sensor, kinds)?;
                    let point = super::device::resolver_point_key(&sensor);
                    if Self::get_row::<Option<i64>>(txn, &self.resolver_points, &point)?.is_some() {
                        self.write_resolver_point(txn, &sensor)?;
                    }
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    /// Sets, within `txn`, the earliest pending slot of (`sensor`, `kind`)
    /// to the earliest slot start among its pending rows as `txn` sees them,
    /// or removes it if there is none.
    ///
    /// The earliest pending row is read for update before the untracked scan
    /// of the pending rows, so a store that adds a pending row after that
    /// read, and so writes the earliest pending row, conflicts with `txn`;
    /// one that committed before it is seen by the scan.
    pub(super) fn recompute_earliest_pending(
        &self,
        txn: &Txn<'_>,
        sensor: &str,
        kind: DaiObservationKind,
    ) -> Result<()> {
        let key = pair_key(sensor, kind);
        Self::get_row::<i64>(txn, &self.earliest_pending, &key)?;
        let mut earliest = None;
        for (pending, _) in Self::scan(&self.pending, txn, &sensor_key(sensor))? {
            let (_, slot_start, row_kind, _) = decode_pending_key(&pending)?;
            if row_kind == kind {
                earliest = Some(slot_start);
                break;
            }
        }
        #[cfg(test)]
        super::run_pending_scanned_hook(self.db);
        match earliest {
            Some(slot_start) => Self::put_row(txn, &self.earliest_pending, &key, &slot_start),
            None => Self::delete_row(txn, &self.earliest_pending, &key),
        }
    }

    /// Deletes the sends created more than one day before `now`, finished
    /// or not, with their staged parts.
    fn expire_sends(&self, now: i64) -> Result<()> {
        let oldest = now.saturating_sub(SEND_AGE);
        let expired = |value: &[u8]| -> Result<bool> {
            Ok(super::super::deserialize::<SendRow>(value)?.created < oldest)
        };
        let rows = self.scan_rows(&self.slot_sends, &[], |_, value| expired(value))?;
        for chunk in rows.chunks(ROWS_PER_TRANSACTION) {
            self.write(|txn| {
                for (key, _) in chunk {
                    let Some(row) = Self::get_row::<SendRow>(txn, &self.slot_sends, key)? else {
                        continue;
                    };
                    if row.created >= oldest {
                        continue;
                    }
                    for (part, _) in Self::scan(&self.send_parts, txn, key)? {
                        Self::delete_row(txn, &self.send_parts, &part)?;
                    }
                    Self::delete_row(txn, &self.slot_sends, key)?;
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Removes from every cursor row the re-extract marks whose slot
    /// started more than 30 days before `now`.
    fn expire_marks(&self, now: i64) -> Result<()> {
        let oldest = now.saturating_sub(RECENT_AGE);
        let has_old = |row: &CursorRow| row.marks.keys().next().is_some_and(|s| *s < oldest);
        let rows = self.scan_rows(&self.cursors, &[], |_, value| {
            Ok(has_old(&super::super::deserialize(value)?))
        })?;
        for chunk in rows.chunks(ROWS_PER_TRANSACTION) {
            self.write(|txn| {
                for (key, _) in chunk {
                    let Some(mut row) = Self::get_row::<CursorRow>(txn, &self.cursors, key)? else {
                        continue;
                    };
                    if has_old(&row) {
                        row.marks.retain(|slot_start, _| *slot_start >= oldest);
                        Self::put_row(txn, &self.cursors, key, &row)?;
                    }
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    // ---- Customer deletion ----

    /// Deletes the sensor-keyed observation and range day rows of the names
    /// `names` owns, with their resolver points after their pending rows,
    /// and, for each name it collected that the node table shows as a sensor
    /// of another customer, the `dai observations` rows naming the customer.
    pub(super) fn delete_observation_rows(
        &self,
        customer_id: u32,
        names: &DeletionNames,
    ) -> Result<()> {
        let maps = [
            &self.cursors,
            &self.slot_sends,
            &self.send_parts,
            &self.catchup_gaps,
            &self.sensor_kind_state,
            &self.observations,
            &self.summaries,
            &self.range_days,
        ];
        for name in &names.own {
            let prefix = sensor_key(name);
            for map in maps {
                self.delete_prefix(map, &prefix)?;
            }
            self.delete_pending_of(name)?;
            self.delete_resolver_point(name)?;
        }
        for name in &names.collected_of_others {
            let rows = self.scan_rows(&self.observations, &sensor_key(name), |_, value| {
                Ok(super::super::deserialize::<ObservationRow>(value)?.customer_id == customer_id)
            })?;
            for chunk in rows.chunks(ROWS_PER_TRANSACTION) {
                self.write(|txn| {
                    for (key, _) in chunk {
                        let Some(row) =
                            Self::get_row::<ObservationRow>(txn, &self.observations, key)?
                        else {
                            continue;
                        };
                        if row.customer_id == customer_id {
                            Self::delete_row(txn, &self.observations, key)?;
                        }
                    }
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    /// Deletes the pending observations of `sensor` and its earliest
    /// pending rows.
    ///
    /// Each transaction that deletes pending rows recomputes the earliest
    /// pending slot of every (sensor, kind) it deleted from, so the earliest
    /// pending rows stay correct between the transactions and after an
    /// interrupted call; the last one recomputes those of the kinds that
    /// still have an earliest pending row.
    fn delete_pending_of(&self, sensor: &str) -> Result<()> {
        let prefix = sensor_key(sensor);
        let rows = self.scan_rows(&self.pending, &prefix, |_, _| Ok(true))?;
        for chunk in rows.chunks(ROWS_PER_TRANSACTION) {
            self.write(|txn| {
                let mut kinds = BTreeSet::new();
                for (key, _) in chunk {
                    if Self::get_row::<SeenRow>(txn, &self.pending, key)?.is_none() {
                        continue;
                    }
                    let (_, _, kind, _) = decode_pending_key(key)?;
                    Self::delete_row(txn, &self.pending, key)?;
                    kinds.insert(super::kind_number(kind));
                }
                self.recompute_earliest_pending_of(txn, sensor, kinds)
            })?;
        }
        let mut kinds = BTreeSet::new();
        for (key, _) in self.scan_rows(&self.earliest_pending, &prefix, |_, _| Ok(true))? {
            let (_, kind) = decode_pair_key(&key)?;
            kinds.insert(super::kind_number(kind));
        }
        if kinds.is_empty() {
            return Ok(());
        }
        self.write(|txn| self.recompute_earliest_pending_of(txn, sensor, kinds.clone()))
    }

    /// Recomputes, within `txn`, the earliest pending slot of (`sensor`,
    /// kind) for each kind number in `kinds`.
    fn recompute_earliest_pending_of(
        &self,
        txn: &Txn<'_>,
        sensor: &str,
        kinds: BTreeSet<u8>,
    ) -> Result<()> {
        for number in kinds {
            if let Some(kind) = super::kind_from_number(number) {
                self.recompute_earliest_pending(txn, sensor, kind)?;
            }
        }
        Ok(())
    }

    /// Deletes the customer's counters, address activity, range blocks,
    /// range subnets and ignored ranges.
    pub(super) fn delete_customer_observation_rows(&self, customer_id: u32) -> Result<()> {
        let prefix = customer_key(customer_id);
        self.delete_prefix(&self.counters, &prefix)?;
        self.delete_prefix(&self.ip_activity, &prefix)?;
        self.delete_prefix(&self.range_blocks, &prefix)?;
        self.delete_prefix(&self.range_subnets, &prefix)?;
        self.delete_prefix(&self.range_ignores, &prefix)
    }
}
