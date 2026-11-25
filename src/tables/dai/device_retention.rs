//! The retention of the DAI device tables, and their part of a customer's
//! deletion.
//!
//! As for the observation tables, each step scans a table outside any
//! transaction and changes what it found in transactions of at most
//! [`ROWS_PER_TRANSACTION`](super::ROWS_PER_TRANSACTION) rows, each row read
//! for update and checked again before it is changed. A step that changes
//! a binding or evidence row first reads the address's `dai ip state` row
//! for update and writes it back, as every writer of those rows does.

use std::{
    collections::{HashMap, hash_map::Entry},
    net::IpAddr,
};

use anyhow::Result;
use uuid::Uuid;

use super::{
    Dai, KeyReader, ROWS_PER_TRANSACTION, Txn,
    cursor::DAY,
    customer_key,
    device::{
        Activity, AliasRow, BindingRow, ChangeEntry, ChangeSource, ConflictRow, DeviceEdits,
        DeviceRow, EvidenceRow, Identifier, IdentifierKind, IdentifierRow, IpStateLock, NameSource,
        OrderKey, SeenTimes, ServiceRow, binding_key, decode_binding_key,
        decode_device_binding_key, decode_evidence_key, device_binding_key, resolver_point_key,
    },
};

/// The time after which a device holding a MAC or an operator asset id that
/// was not seen becomes "not seen": 90 days.
const NOT_SEEN_AGE: i64 = 90 * DAY;
/// The age after which the history rows of the device tables are deleted:
/// 180 days.
const HISTORY_AGE: i64 = 180 * DAY;

#[cfg(test)]
thread_local! {
    /// A hook the tests run once, in the thread that set it, in the next
    /// transaction of the earlier-owner expiry, after it decided which
    /// owners to keep and before it commits.
    static OWNERS_CHECKED: std::cell::RefCell<Option<super::TestHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Sets the hook the next earlier-owner expiry transaction in this thread
/// runs before it commits.
#[cfg(test)]
pub(super) fn set_owners_checked_hook(hook: super::TestHook) {
    OWNERS_CHECKED.with(|cell| *cell.borrow_mut() = Some(hook));
}

/// Decodes the key of a `dai devices` row.
fn decode_device_key(key: &[u8]) -> Result<(u32, Uuid)> {
    let mut reader = KeyReader::new(key);
    let customer = reader.u32()?;
    let device = reader.uuid()?;
    reader.finish()?;
    Ok((customer, device))
}

/// Decodes the key of a `dai device identifiers` row.
fn decode_identifier_key(key: &[u8]) -> Result<(u32, Identifier)> {
    let mut reader = KeyReader::new(key);
    let customer = reader.u32()?;
    let number = reader.byte()?;
    let value = reader.str()?;
    reader.finish()?;
    let kind = IdentifierKind::from_number(number)
        .ok_or_else(|| anyhow::anyhow!("invalid DAI identifier kind {number} in the key"))?;
    Ok((customer, Identifier { kind, value }))
}

/// The IP state locks one retention transaction took, keyed by address.
#[derive(Default)]
struct Locks(HashMap<(u32, String, IpAddr), IpStateLock>);

impl Locks {
    /// Reads the IP state of the address for update the first time.
    fn lock(
        &mut self,
        dai: &Dai<'_>,
        txn: &Txn<'_>,
        customer: u32,
        site: &str,
        ip: IpAddr,
    ) -> Result<()> {
        if let Entry::Vacant(entry) = self.0.entry((customer, site.to_string(), ip)) {
            entry.insert(dai.lock_ip_state(txn, customer, site, ip)?);
        }
        Ok(())
    }

    /// Writes back every IP state locked.
    fn write(self, dai: &Dai<'_>, txn: &Txn<'_>) -> Result<()> {
        for lock in self.0.values() {
            dai.write_ip_state(txn, lock)?;
        }
        Ok(())
    }
}

impl Dai<'_> {
    /// Applies the retention rules of the device tables at the time `now`.
    pub(super) fn apply_device_retention(&self, now: i64) -> Result<()> {
        self.estimate_binding_ends(now)?;
        self.expire_activity(now)?;
        let long_ago = now.saturating_sub(HISTORY_AGE);
        self.delete_ended_bindings(long_ago)?;
        self.delete_old_evidence(long_ago)?;
        self.delete_where(&self.aliases, |_, value| {
            Ok(super::super::deserialize::<AliasRow>(value)?.time < long_ago)
        })?;
        self.delete_where(&self.changes, |_, value| {
            Ok(super::super::deserialize::<ChangeEntry>(value)?.time < long_ago)
        })?;
        self.delete_where(&self.conflicts, |_, value| {
            Ok(super::super::deserialize::<ConflictRow>(value)?.last < long_ago)
        })?;
        self.delete_where(&self.services, |_, value| {
            Ok(super::super::deserialize::<ServiceRow>(value)?.last_seen < long_ago)
        })?;
        self.delete_where(&self.software, |_, value| {
            Ok(super::super::deserialize::<SeenTimes>(value)?.last_seen < long_ago)
        })?;
        self.delete_where(&self.ip_state, |_, value| {
            Ok(super::super::deserialize::<OrderKey>(value)?.time < long_ago)
        })?;
        self.expire_earlier_owners(long_ago)?;
        self.expire_names(now, long_ago)
    }

    /// Changes, in transactions of at most [`ROWS_PER_TRANSACTION`] rows,
    /// each binding `selected` selects as `change` says, after reading its
    /// address's IP state for update, and writes the IP state back.
    fn change_bindings(
        &self,
        selected: impl Fn(&BindingRow) -> bool,
        change: impl Fn(&mut BindingRow) -> bool,
    ) -> Result<()> {
        let rows = self.scan_rows(&self.bindings, &[], |_, value| {
            Ok(selected(&super::super::deserialize(value)?))
        })?;
        for chunk in rows.chunks(ROWS_PER_TRANSACTION) {
            self.write(|txn| {
                let mut locks = Locks::default();
                for (key, _) in chunk {
                    let (customer, site, ip, start) = decode_binding_key(key)?;
                    locks.lock(self, txn, customer, &site, ip)?;
                    let Some(mut row) = Self::get_row::<BindingRow>(txn, &self.bindings, key)?
                    else {
                        continue;
                    };
                    if !selected(&row) {
                        continue;
                    }
                    if change(&mut row) {
                        Self::put_row(txn, &self.bindings, key, &row)?;
                    } else {
                        Self::delete_row(txn, &self.bindings, key)?;
                        Self::delete_row(
                            txn,
                            &self.device_bindings,
                            &device_binding_key(customer, row.device, &site, ip, start),
                        )?;
                    }
                }
                locks.write(self, txn)
            })?;
        }
        Ok(())
    }

    /// Writes the estimated end `last_strong + inactivity` of every binding
    /// with no end past that time at `now`.
    fn estimate_binding_ends(&self, now: i64) -> Result<()> {
        self.change_bindings(
            |row| row.end.is_none() && row.last_strong.saturating_add(row.inactivity) < now,
            |row| {
                row.end = Some(row.last_strong.saturating_add(row.inactivity));
                row.end_estimated = true;
                true
            },
        )
    }

    /// Deletes every binding that ended before `long_ago`, with its reverse
    /// index row.
    fn delete_ended_bindings(&self, long_ago: i64) -> Result<()> {
        self.change_bindings(|row| row.end.is_some_and(|end| end < long_ago), |_| false)
    }

    /// Deletes every evidence row last seen before `long_ago`, except binding
    /// evidence at or after the start of a stored binding of its address
    /// that has no end or ended at or after `long_ago`, which a
    /// recomputation may still replay.
    fn delete_old_evidence(&self, long_ago: i64) -> Result<()> {
        let rows = self.scan_rows(&self.evidence, &[], |key, _| {
            Ok(decode_evidence_key(key)?.last_seen < long_ago)
        })?;
        for chunk in rows.chunks(ROWS_PER_TRANSACTION) {
            self.write(|txn| {
                let mut locks = Locks::default();
                let mut kept_from: HashMap<(u32, String, IpAddr), Option<i64>> = HashMap::new();
                for (key, _) in chunk {
                    let decoded = decode_evidence_key(key)?;
                    let address = (decoded.customer, decoded.site.clone(), decoded.ip);
                    locks.lock(self, txn, decoded.customer, &decoded.site, decoded.ip)?;
                    if !kept_from.contains_key(&address) {
                        let live = self
                            .bindings_in(txn, decoded.customer, &decoded.site, decoded.ip)?
                            .into_iter()
                            .filter(|(_, row)| row.end.is_none_or(|end| end >= long_ago))
                            .map(|(start, _)| start)
                            .min();
                        kept_from.insert(address.clone(), live);
                    }
                    let Some(row) = Self::get_row::<EvidenceRow>(txn, &self.evidence, key)? else {
                        continue;
                    };
                    let keep_from = kept_from.get(&address).copied().flatten();
                    let order = OrderKey::of(&row.body, row.first_seen, &decoded.hash);
                    if row.is_binding_evidence() && keep_from.is_some_and(|from| order.time >= from)
                    {
                        continue;
                    }
                    Self::delete_row(txn, &self.evidence, key)?;
                }
                locks.write(self, txn)
            })?;
        }
        Ok(())
    }

    /// Changes, in transactions of at most [`ROWS_PER_TRANSACTION`] rows,
    /// each device `selected` selects as `change` says, writing one change
    /// entry of source expiry at `now` per device it changes.
    fn change_devices(
        &self,
        now: i64,
        selected: impl Fn(&DeviceRow) -> bool,
        change: impl Fn(&mut super::device::DeviceEdit),
    ) -> Result<()> {
        let rows = self.scan_rows(&self.devices, &[], |_, value| {
            Ok(selected(&super::super::deserialize(value)?))
        })?;
        let mut by_customer: Vec<(u32, Vec<Uuid>)> = Vec::new();
        for (key, _) in &rows {
            let (customer, device) = decode_device_key(key)?;
            match by_customer.last_mut() {
                Some((last, devices)) if *last == customer => devices.push(device),
                _ => by_customer.push((customer, vec![device])),
            }
        }
        for (customer, devices) in by_customer {
            for chunk in devices.chunks(ROWS_PER_TRANSACTION) {
                self.write(|txn| {
                    for device in chunk {
                        let mut edits = DeviceEdits::default();
                        if let Some(edit) = edits.get(self, txn, customer, *device)?
                            && selected(&edit.row)
                        {
                            change(edit);
                        }
                        edits.flush(self, txn, customer, ChangeSource::Expiry, now)?;
                    }
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    /// Makes every active device holding a MAC or an operator asset id last
    /// seen more than 90 days before `now` "not seen".
    fn expire_activity(&self, now: i64) -> Result<()> {
        let oldest = now.saturating_sub(NOT_SEEN_AGE);
        self.change_devices(
            now,
            |row| {
                row.activity == Activity::Active
                    && row.last_seen < oldest
                    && row.has_strong_hardware_identifier()
            },
            |edit| edit.set_activity(Activity::NotSeen),
        )
    }

    /// Removes from every device the names of source DHCP or DNS last seen
    /// before `long_ago`.
    fn expire_names(&self, now: i64, long_ago: i64) -> Result<()> {
        let expired = move |source: NameSource, last_seen: i64| {
            source != NameSource::Operator && last_seen < long_ago
        };
        self.change_devices(
            now,
            |row| {
                row.names
                    .iter()
                    .any(|name| expired(name.source, name.last_seen))
            },
            |edit| edit.remove_names(|name| expired(name.source, name.last_seen)),
        )
    }

    /// Removes from every identifier row the earlier owners the identifier
    /// left before `long_ago`, except one whose device still has a stored
    /// binding with that identifier as its evidence identifier.
    ///
    /// The bindings are read without tracking; what makes the decision safe
    /// is the identifier row, read for update and rewritten here, which
    /// every application or replay of an ACK binding an earlier owner of the
    /// identifier writes too, unchanged if need be. So a binding of that
    /// owner added after the scan of [`binds_by`](Self::binds_by) makes this
    /// transaction conflict and the retry see it.
    fn expire_earlier_owners(&self, long_ago: i64) -> Result<()> {
        let has_old = |row: &IdentifierRow| row.earlier_owners.iter().any(|o| o.left < long_ago);
        let rows = self.scan_rows(&self.identifiers, &[], |_, value| {
            Ok(has_old(&super::super::deserialize(value)?))
        })?;
        for chunk in rows.chunks(ROWS_PER_TRANSACTION) {
            self.write(|txn| {
                for (key, _) in chunk {
                    let Some(mut row) =
                        Self::get_row::<IdentifierRow>(txn, &self.identifiers, key)?
                    else {
                        continue;
                    };
                    if !has_old(&row) {
                        continue;
                    }
                    let (customer, id) = decode_identifier_key(key)?;
                    let mut kept = Vec::with_capacity(row.earlier_owners.len());
                    for owner in &row.earlier_owners {
                        if owner.left >= long_ago
                            || self.binds_by(txn, customer, owner.device, &id)?
                        {
                            kept.push(*owner);
                        }
                    }
                    row.earlier_owners = kept;
                    Self::put_row(txn, &self.identifiers, key, &row)?;
                }
                #[cfg(test)]
                if let Some(hook) = OWNERS_CHECKED.with(|cell| cell.borrow_mut().take()) {
                    hook(self.db);
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Returns whether `device` has a stored binding whose evidence
    /// identifier is `id`, as `txn` sees them.
    fn binds_by(
        &self,
        txn: &Txn<'_>,
        customer: u32,
        device: Uuid,
        id: &Identifier,
    ) -> Result<bool> {
        let prefix = super::KeyWriter::default()
            .u32(customer)
            .uuid(device)
            .finish();
        for (key, _) in Self::scan(&self.device_bindings, txn, &prefix)? {
            let (_, _, site, ip, start) = decode_device_binding_key(&key)?;
            let binding = txn
                .get_cf(self.bindings.cf, binding_key(customer, &site, ip, start))
                .map_err(anyhow::Error::from)?
                .map(|value| super::super::deserialize::<BindingRow>(&value))
                .transpose()?;
            if binding.is_some_and(|binding| binding.evidence_identifier == *id) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // ---- Customer deletion ----

    /// Deletes the resolver point of `sensor`.
    pub(super) fn delete_resolver_point(&self, sensor: &str) -> Result<()> {
        self.write(|txn| Self::delete_row(txn, &self.resolver_points, &resolver_point_key(sensor)))
    }

    /// Deletes the customer's rows of every customer-keyed device table.
    pub(super) fn delete_customer_device_rows(&self, customer_id: u32) -> Result<()> {
        let prefix = customer_key(customer_id);
        for map in [
            &self.devices,
            &self.identifiers,
            &self.aliases,
            &self.bindings,
            &self.device_bindings,
            &self.evidence,
            &self.ip_state,
            &self.fixed_ips,
            &self.conflicts,
            &self.services,
            &self.software,
            &self.changes,
        ] {
            self.delete_prefix(map, &prefix)?;
        }
        Ok(())
    }
}
