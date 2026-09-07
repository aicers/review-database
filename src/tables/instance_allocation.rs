//! The `instance_allocation` table.
//!
//! A host may run several instances of one module, and every one of them needs
//! a number that no other instance of the same module on that host holds. This
//! table is that allocator's state: one row per allocated number, keyed
//! `(host, component, instance)`, carrying the idempotency key of the attempt
//! that allocated it.
//!
//! # Existence means taken
//!
//! The row has no state column and no released marker. A number is taken
//! exactly while a row for it exists, so the uniqueness the allocator needs is
//! the row's own key: this crate is RocksDB, which has no partial index and no
//! way to say "unique among the rows that are not released", and a released
//! row left behind would make its number permanently unusable. Release is
//! therefore a delete.
//!
//! # Writing
//!
//! Existence being the whole invariant is also why nothing may write a row
//! directly. A number is taken only after a conflict-detecting read has
//! established that it was free, and a blind put would take one without that
//! read. `Table::allocate_with_transaction` is the only function that creates
//! one.
//!
//! Neither half of a number's life has a public entry point here, and for the
//! same reason in both directions: a number is taken by the write that records
//! the operation taking it, and given back by the write that justifies giving
//! it back, and by nothing else. So both live on the other side, in
//! `Table<'_, OperationAttempt>`:
//! [`allocate_instance`](Table::allocate_instance) takes a number and writes
//! the attempt that owns it in one transaction, and every writer of an
//! `operation_attempt` row releases what the row it stores gives back, in that
//! row's own transaction. No entry point takes a number without recording the
//! attempt that holds it, and none records a terminal attempt without giving
//! back what it held, so the half states the schema forbids — a number held by
//! an attempt that was never written, given back with no record justifying it,
//! or a record with the number still held — cannot be reached by choosing the
//! wrong call.
//!
//! Nor by re-driving one. A release names its row by the owning attempt's
//! `(host, target, instance)`, so a re-drive that moved the row to another
//! triple while its number stood would carry that number's only release away
//! with it. Such a write is refused rather than allowed to strand it, which is
//! what [`holds_number_for`](Table::holds_number_for) is asked.
//!
//! That a row cannot be written or deleted directly is enforced by the
//! compiler rather than by convention: the generic write API on [`Table`] is
//! bounded by [`UniqueKey`](crate::UniqueKey) and [`Value`](super::Value), and
//! [`InstanceAllocation`] implements neither, so `put`, `insert`,
//! `update_with_transaction` and `delete_with_transaction` do not exist for
//! this table at all.
//!
//! Reading is unrestricted. The column family holds these rows and nothing
//! else — no index key space is reserved in it — so the generic
//! [`Iterable`](crate::Iterable) API stays available, and a prefix scan over
//! `(host, component)` is what the allocator itself reads.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use rocksdb::{Direction, OptimisticTransactionDB, Transaction};
use serde::{Deserialize, Serialize};

use super::{OperationAction, OperationAttempt, OperationOutcome};
use crate::{EXCLUSIVE, Iterable, Map, Table, types::FromKeyValue};

/// The smallest instance number the allocator hands out.
const MIN_INSTANCE: u32 = 1;

/// The largest instance number the allocator hands out.
///
/// The ceiling is a contract rather than a tuning knob: a registration
/// identity pins the instance to a three-digit zero-padded segment, and a
/// four-digit number would not fit the shape every certificate and registry
/// entry is composed from. The allocator refuses at `1000` instead of wrapping.
const MAX_INSTANCE: u32 = 999;

/// The width of the length prefix a variable-length key segment carries.
const SEGMENT_LEN: usize = 4;

/// An instance number allocated to a module on a host.
///
/// # Identity
///
/// The row is keyed by `(host, component, instance)`, and the key is the whole
/// of the uniqueness: a second row for a number already held cannot exist,
/// because it would be the same key. The pair leads the key so that every
/// number allocated for one `(host, component)` is one prefix scan away, which
/// is what the smallest-free selection reads, and the number is encoded big
/// endian so that the scan yields the numbers in ascending order.
///
/// # Core components have no row
///
/// Only the five modules are multi-instance. A core component — `review`,
/// `aice-web-next`, `roxyd` or `bootroot` — has no instance dimension at all,
/// so it takes no number here and its attempts record `instance = None`. A
/// second install of one is refused by the single row per `(component, host)`
/// in [`CoreComponent`](super::CoreComponent), not given another number.
///
/// [`allocate_instance`](Table::allocate_instance) refuses a number to any of
/// the four by package-id, with no registry row required, so the first install
/// of one on a fresh store is refused as firmly as the second; it refuses one
/// for a pair that registry already holds; and it refuses one for anything but
/// an install naming a component, since an update and a removal concern an
/// instance that has its number already and an onboarding names no component
/// at all.
///
/// # Writing
///
/// A row is written by the allocator alone. A record that implements
/// [`UniqueKey`](crate::UniqueKey) is admitted to the generic write API:
///
/// ```
/// fn generic_write_api<R: review_database::UniqueKey>() {}
/// generic_write_api::<review_database::TorExitNode>();
/// ```
///
/// An `InstanceAllocation` is not, which is what stops a caller from taking a
/// number without the conflict-detecting read that makes two concurrent
/// installs pick different ones:
///
/// ```compile_fail
/// fn generic_write_api<R: review_database::UniqueKey>() {}
/// generic_write_api::<review_database::InstanceAllocation>();
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstanceAllocation {
    /// The host the instance runs on.
    pub host: String,
    /// The canonical package-id of the module the number belongs to.
    pub component: String,
    /// The allocated number, between 1 and 999.
    pub instance: u32,
    /// The idempotency key of the attempt that allocated the number.
    ///
    /// This is what lets a re-driven attempt recognize its own allocation
    /// instead of taking a second number, and what ties the row to the record
    /// whose write releases it. Never empty.
    pub idempotency_key: String,
}

impl FromKeyValue for InstanceAllocation {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let (host, component, instance) = decode_key(key)?;
        let idempotency_key = std::str::from_utf8(value)
            .context("an instance allocation holds an invalid idempotency key")?;
        if idempotency_key.is_empty() {
            bail!("an instance allocation must name the attempt that owns it");
        }

        Ok(Self {
            host,
            component,
            instance,
            idempotency_key: idempotency_key.to_string(),
        })
    }
}

/// Why a write releases the number an attempt names.
///
/// The two differ in whose row they delete, and collapsing them would be
/// wrong in both directions: an update that failed does not tear down the
/// instance it was updating, and a removal deletes a number the install
/// attempt — not the removal — allocated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Release {
    /// The attempt that allocated the number did not reach a running
    /// instance, so it gives its own row back. A row owned by another attempt
    /// is left alone.
    OwnedByTheAttempt,
    /// The instance itself is gone, so its row goes whoever allocated it.
    ConfirmedRemoval,
}

/// Why storing `attempt` releases the number it names, or `None` if it does
/// not.
///
/// A release rides one of three writes, and each of them is terminal and owes
/// no cleanup: the write recording an attempt that **did not succeed** —
/// failed, cancelled, rolled back, or expired and finalized as failed by the
/// sweep — the `cleanup_state` **discharge**, and the **confirmed removal**. A
/// terminal **success** is deliberately not one of them — an install that
/// succeeded is owed its number for as long as the instance exists, and
/// releasing it would hand it to the next install while the instance is still
/// running.
fn release_of(attempt: &OperationAttempt) -> Option<Release> {
    if attempt.instance.is_none() || !attempt.is_terminal() || attempt.cleanup_state.is_some() {
        return None;
    }
    let succeeded = attempt.outcome == Some(OperationOutcome::Succeeded);
    match (attempt.action, succeeded) {
        (OperationAction::Remove, true) => Some(Release::ConfirmedRemoval),
        (_, true) => None,
        (_, false) => Some(Release::OwnedByTheAttempt),
    }
}

/// Appends a length-prefixed segment to a key.
///
/// Both `host` and `component` are variable-length, so their bytes are never
/// concatenated bare: without the prefix `("ab", "c")` and `("a", "bc")` would
/// encode to the same key.
fn push_segment(key: &mut Vec<u8>, segment: &str) -> Result<()> {
    let len =
        u32::try_from(segment.len()).context("instance allocation key segment is too long")?;
    key.extend_from_slice(&len.to_be_bytes());
    key.extend_from_slice(segment.as_bytes());
    Ok(())
}

/// Reads back one segment [`push_segment`] wrote, and returns the rest.
fn take_segment(bytes: &[u8]) -> Result<(String, &[u8])> {
    let len = bytes
        .get(..SEGMENT_LEN)
        .and_then(|len| <[u8; SEGMENT_LEN]>::try_from(len).ok())
        .context("an instance allocation key is missing a segment length")?;
    let len = usize::try_from(u32::from_be_bytes(len))
        .context("an instance allocation key segment is too long")?;
    let end = SEGMENT_LEN
        .checked_add(len)
        .context("an instance allocation key segment is too long")?;
    let segment = bytes
        .get(SEGMENT_LEN..end)
        .context("an instance allocation key segment runs past its end")?;
    let segment = std::str::from_utf8(segment)
        .context("an instance allocation key segment is not valid UTF-8")?;
    Ok((segment.to_string(), &bytes[end..]))
}

/// The key space of one `(host, component)` pair.
///
/// Every number allocated for the pair sorts under this prefix, and nothing
/// else does, so the smallest-free scan reads exactly the rows it has to.
fn pair_prefix(host: &str, component: &str) -> Result<Vec<u8>> {
    let mut key = Vec::new();
    push_segment(&mut key, host)?;
    push_segment(&mut key, component)?;
    Ok(key)
}

/// The key of one allocated number.
fn row_key(host: &str, component: &str, instance: u32) -> Result<Vec<u8>> {
    let mut key = pair_prefix(host, component)?;
    key.extend_from_slice(&instance.to_be_bytes());
    Ok(key)
}

/// Decodes the `(host, component, instance)` triple [`row_key`] wrote.
fn decode_key(bytes: &[u8]) -> Result<(String, String, u32)> {
    let (host, rest) = take_segment(bytes)?;
    let (component, rest) = take_segment(rest)?;
    let instance = <[u8; 4]>::try_from(rest)
        .ok()
        .map(u32::from_be_bytes)
        .context("an instance allocation key is missing its number")?;
    Ok((host, component, instance))
}

/// What went wrong while allocating an instance number.
#[derive(Debug, thiserror::Error)]
pub enum InstanceAllocationError {
    /// Every number in `1..=999` is taken for the pair.
    ///
    /// The ceiling is fixed by the three-digit segment a registration identity
    /// carries, not by a deployment setting, so there is no wrap and no reuse
    /// of a number whose row still exists.
    #[error("every instance number is taken for component {component} on host {host}")]
    InstanceNumbersExhausted { component: String, host: String },
    /// The database read or write failed, or a stored row was invalid.
    #[error(transparent)]
    Database(#[from] anyhow::Error),
}

/// Functions for the `instance_allocation` table.
impl<'d> Table<'d, InstanceAllocation> {
    /// Opens the `instance_allocation` table in the database.
    ///
    /// Returns `None` if the table does not exist, which is the state of every
    /// store until the database format bump registers the column family:
    /// `migrate_data_dir` returns early for a data dir already at a compatible
    /// version, so registering it in `MAP_NAMES` now would add a column family
    /// with no version change. A store without it holds no allocation, which
    /// is why the release path can treat the `None` as nothing to release.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::INSTANCE_ALLOCATIONS).map(Table::new)
    }

    /// Returns the row for `(host, component, instance)`, or `None` if the
    /// number is free.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored row is invalid or the database operation
    /// fails.
    pub fn get(
        &self,
        host: &str,
        component: &str,
        instance: u32,
    ) -> Result<Option<InstanceAllocation>> {
        let key = row_key(host, component, instance)?;
        let Some(value) = self.map.get(&key)? else {
            return Ok(None);
        };
        Ok(Some(InstanceAllocation::from_key_value(
            &key,
            value.as_ref(),
        )?))
    }

    /// Returns every number allocated for `(host, component)`, in ascending
    /// order.
    ///
    /// # Errors
    ///
    /// Returns an error if a stored row is invalid or the database operation
    /// fails.
    pub fn allocated(&self, host: &str, component: &str) -> Result<Vec<InstanceAllocation>> {
        let prefix = pair_prefix(host, component)?;
        self.rows_under(&prefix)
    }

    /// Returns the row `idempotency_key` allocated for `(host, component)`, or
    /// `None` if that attempt holds no number for the pair.
    ///
    /// This is how a re-driven attempt recognizes its own allocation instead
    /// of taking a second number.
    ///
    /// # Errors
    ///
    /// Returns an error if a stored row is invalid or the database operation
    /// fails.
    pub fn allocated_by(
        &self,
        host: &str,
        component: &str,
        idempotency_key: &str,
    ) -> Result<Option<InstanceAllocation>> {
        Ok(self
            .allocated(host, component)?
            .into_iter()
            .find(|row| row.idempotency_key == idempotency_key))
    }

    /// Allocates the smallest free number for `(host, component)` within
    /// `txn`, and returns it, or returns the number `idempotency_key` already
    /// holds for the pair.
    ///
    /// A re-driven attempt is given its own number back rather than a second
    /// one: that is what the owning key on the row is for. The row is read for
    /// update before it is trusted, so a release that committed since the scan
    /// is not mistaken for a live allocation, and the read is registered for
    /// conflict detection — one committing while this transaction is open
    /// fails the commit rather than leaving the caller holding a number that
    /// was given away. Two drives of one attempt running at the same time are
    /// serialized by the `operation_attempt` row they both write, which is one
    /// row per idempotency key: the loser's commit fails and its re-run finds
    /// the allocation the winner made.
    ///
    /// The number is the smallest free `u32` in `1..=999`, found by a prefix
    /// scan over the rows of the pair. Smallest-free rather than monotonic,
    /// because a number is reused once its instance is torn down and a counter
    /// would drift upward forever while the reused numbers sat free; the scan
    /// is affordable precisely because the count is small.
    ///
    /// The scan alone does **not** serialize two concurrent allocations — both
    /// would read the same free number and both would write it — so the
    /// candidate is read with `get_for_update` before it is written. Locking
    /// an absent key orders the writers: one commits and the other's commit
    /// fails, and the loser picks a different number when the caller re-runs
    /// the transaction.
    ///
    /// Deliberately not public, and there is no self-committing allocation at
    /// all: a number taken by a transaction of its own is held by nothing if
    /// the process stops before the attempt is recorded, and nothing would
    /// ever give it back, because a release is justified by the very record
    /// that was never written. The number and the attempt that owns it land
    /// together or not at all, which is what
    /// [`Table::allocate_instance`] does; the port
    /// rows keyed on the number join the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`InstanceAllocationError::InstanceNumbersExhausted`] if every
    /// number in `1..=999` is taken for the pair, or
    /// [`InstanceAllocationError::Database`] if `idempotency_key` is empty or
    /// the database operation fails.
    pub(super) fn allocate_with_transaction(
        &self,
        host: &str,
        component: &str,
        idempotency_key: &str,
        txn: &Transaction<'_, OptimisticTransactionDB>,
    ) -> Result<u32, InstanceAllocationError> {
        if idempotency_key.is_empty() {
            return Err(anyhow::anyhow!(
                "an instance allocation must name the attempt that owns it"
            )
            .into());
        }
        let rows = self
            .allocated(host, component)
            .map_err(InstanceAllocationError::Database)?;

        // A re-drive holds the number it already took: the row naming it is
        // returned instead of a second one being allocated. The scan ran
        // outside the transaction, so the row is read for update before it is
        // believed — one released since is someone else's to take.
        if let Some(row) = rows
            .iter()
            .find(|row| row.idempotency_key == idempotency_key)
        {
            let key = row_key(host, component, row.instance)?;
            if txn
                .get_for_update_cf(self.map.cf, &key, EXCLUSIVE)
                .context("cannot read the instance allocation")?
                .as_deref()
                == Some(idempotency_key.as_bytes())
            {
                return Ok(row.instance);
            }
        }

        let taken: BTreeSet<u32> = rows.into_iter().map(|row| row.instance).collect();

        for instance in MIN_INSTANCE..=MAX_INSTANCE {
            if taken.contains(&instance) {
                continue;
            }
            let key = row_key(host, component, instance)?;
            // The scan above ran outside the transaction, so a number it read
            // as free may have been taken by a transaction that committed
            // since — including by this very attempt, re-driven. The locking
            // read is what decides, and it also orders this write against a
            // concurrent one for the same number.
            if let Some(owner) = txn
                .get_for_update_cf(self.map.cf, &key, EXCLUSIVE)
                .context("cannot read the instance allocation")?
            {
                if owner.as_slice() == idempotency_key.as_bytes() {
                    return Ok(instance);
                }
                continue;
            }
            self.map
                .put_with_transaction(&key, idempotency_key.as_bytes(), txn)?;
            return Ok(instance);
        }

        Err(InstanceAllocationError::InstanceNumbersExhausted {
            component: component.to_string(),
            host: host.to_string(),
        })
    }

    /// Releases the number held for `(host, component, instance)` within
    /// `txn`.
    ///
    /// Releasing a number that is already free is not an error, so a re-driven
    /// cleanup need not check first.
    ///
    /// There is deliberately no public release, and none that commits on its
    /// own. A release is only ever justified by a record — an attempt that
    /// ended owing nothing, a discharge, a confirmed removal — and it has to
    /// land in the same transaction as that record, or a crash between the two
    /// leaves a number held by an attempt with nothing left to revisit it, or
    /// given back with nothing recording why. `release_for_attempt` is the
    /// only caller, and it runs from every writer of an `operation_attempt`
    /// row rather than from one a caller has to select.
    /// This stays crate-visible for the composed transaction that the port
    /// rows keyed on the same number will join.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub(crate) fn release_with_transaction(
        &self,
        host: &str,
        component: &str,
        instance: u32,
        txn: &Transaction<'_, OptimisticTransactionDB>,
    ) -> Result<()> {
        self.map
            .delete_with_transaction(&row_key(host, component, instance)?, txn)
    }

    /// Deletes the row `attempt` releases, if it releases one.
    ///
    /// Three writes release a number, and each of them is terminal and owes no
    /// cleanup: the one recording an attempt that **did not succeed** —
    /// failed, cancelled, rolled back, or expired and finalized as failed by
    /// `Table<'_, OperationAttempt>::sweep_expired` — the `cleanup_state`
    /// **discharge**, and the **confirmed removal**. A terminal **success** is
    /// not one of them: the number is owed to the instance for as long as it
    /// exists.
    ///
    /// The first two release the row **the attempt itself allocated**, so an
    /// update that failed does not release the number of the instance it was
    /// updating. A confirmed removal releases the row whichever attempt
    /// allocated it, because the instance it belongs to is gone.
    ///
    /// The delete rides the write that justifies it because "the number stays
    /// held" is not a safe crash answer on its own: an attempt that is
    /// terminal and owes no cleanup has nothing left that would revisit it, so
    /// a lost delete is a permanent leak rather than a pause. Either both land
    /// or neither does, and a re-drive then finds the work still owed.
    ///
    /// Releasing a number that is already free is not an error, so a re-driven
    /// terminal write need not check first.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub(super) fn release_for_attempt(
        &self,
        attempt: &OperationAttempt,
        txn: &Transaction<'_, OptimisticTransactionDB>,
    ) -> Result<()> {
        let (Some(instance), Some(release)) = (attempt.instance, release_of(attempt)) else {
            return Ok(());
        };
        let key = row_key(&attempt.host, &attempt.target, instance)?;
        let Some(owner) = txn
            .get_for_update_cf(self.map.cf, &key, EXCLUSIVE)
            .context("cannot read the instance allocation")?
        else {
            return Ok(());
        };
        if release == Release::OwnedByTheAttempt
            && owner.as_slice() != attempt.idempotency_key.as_bytes()
        {
            return Ok(());
        }
        self.release_with_transaction(&attempt.host, &attempt.target, instance, txn)
    }

    /// Returns whether the number `attempt` names is held by `attempt` itself.
    ///
    /// A number is only ever released through the row that owns it, which
    /// [`release_for_attempt`](Table::release_for_attempt) finds by the
    /// attempt's `(host, target, instance)`. That is why a writer asks this
    /// before letting a re-drive change that triple: an attempt still holding
    /// its number is the only record that can give it back, so a row moved off
    /// the triple takes the number's one release with it.
    ///
    /// The read is a `get_for_update`, so the answer orders the write it
    /// guards against a release committing beside it rather than merely
    /// preceding one.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub(super) fn holds_number_for(
        &self,
        attempt: &OperationAttempt,
        txn: &Transaction<'_, OptimisticTransactionDB>,
    ) -> Result<bool> {
        let Some(instance) = attempt.instance else {
            return Ok(false);
        };
        let key = row_key(&attempt.host, &attempt.target, instance)?;
        Ok(txn
            .get_for_update_cf(self.map.cf, &key, EXCLUSIVE)
            .context("cannot read the instance allocation")?
            .as_deref()
            == Some(attempt.idempotency_key.as_bytes()))
    }

    /// Reads every row under `prefix`, in key order.
    fn rows_under(&self, prefix: &[u8]) -> Result<Vec<InstanceAllocation>> {
        self.prefix_iter(Direction::Forward, None, prefix)
            .collect::<Result<Vec<_>>>()
            .context("cannot read the instance allocations")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{DateTime, Utc};

    use super::*;
    use crate::tables::{
        BuildSelector, InstallIntent, OperationCleanupState, OperationOnFailure, OperationPhase,
        OperationRetryPolicy,
    };
    use crate::test::{DbGuard, acquire_db_permit};

    const HOST: &str = "host-a.example";
    const COMPONENT: &str = "giganto";
    const OTHER_HOST: &str = "host-b.example";
    const OTHER_COMPONENT: &str = "sensor";

    /// A database carrying this table's column family, which `StateDb::open`
    /// does not yet create because the name is not in `MAP_NAMES`.
    struct TestDb {
        db: OptimisticTransactionDB,
        _dir: tempfile::TempDir,
        _permit: DbGuard<'static>,
    }

    impl TestDb {
        fn new() -> Self {
            let permit = acquire_db_permit();
            let dir = tempfile::tempdir().unwrap();
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
            let mut column_families = super::super::MAP_NAMES.to_vec();
            column_families.push(super::super::INSTANCE_ALLOCATIONS);
            // Neither this table nor the latest-pointer family is in
            // `MAP_NAMES`: the migration that bumps the database format
            // registers them, so a test opens them beside the rest here.
            column_families.push(super::super::OPERATION_ATTEMPT_LATEST);
            let db = OptimisticTransactionDB::open_cf(
                &opts,
                dir.path().join("states.db"),
                column_families,
            )
            .unwrap();
            Self {
                db,
                _dir: dir,
                _permit: permit,
            }
        }

        fn table(&self) -> Table<'_, InstanceAllocation> {
            Table::<InstanceAllocation>::open(&self.db).unwrap()
        }

        fn attempts(&self) -> Table<'_, OperationAttempt> {
            Table::<OperationAttempt>::open(&self.db).unwrap()
        }
    }

    fn timestamp(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    /// A canonical `UUIDv4` request key derived from a short test name.
    ///
    /// An install records the digest of the request it was submitted with,
    /// and a row carrying one is reachable only under a key of that shape, so
    /// the tests name their attempts through here rather than with the bare
    /// labels they read as. The mapping is a pure function of the name, so a
    /// test that stores under one name and asserts under the same one sees
    /// the same key.
    fn key(name: &str) -> String {
        const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01b3;

        let mut state = OFFSET;
        let fold = |state: &mut u64| {
            for byte in name.as_bytes() {
                *state ^= u64::from(*byte);
                *state = state.wrapping_mul(PRIME);
            }
            *state
        };
        let low = fold(&mut state);
        let high = fold(&mut state);
        let mut nibbles: Vec<char> = format!("{low:016x}{high:016x}").chars().collect();
        // The version nibble is `4`, and the variant nibble is one of `8`,
        // `9`, `a` or `b`; every other nibble carries the hash. The string is
        // two `{:016x}` of a `u64` each, so both indexes are in bounds.
        nibbles[12] = '4';
        nibbles[16] = '9';
        let hex: String = nibbles.into_iter().collect();
        format!(
            "{}-{}-{}-{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32]
        )
    }

    /// The request an install in these tests was submitted with.
    ///
    /// Its digest is what the row carries; nothing here compares it against
    /// the attempt's own fields, so one request stands for every install.
    fn intent() -> InstallIntent {
        InstallIntent {
            host: HOST.to_string(),
            target: COMPONENT.to_string(),
            selector: BuildSelector::Version("1.2.3".to_string()),
            on_failure: OperationOnFailure::Rollback,
            bind_addrs: None,
        }
    }

    /// The digest [`intent`] hashes to.
    fn intent_digest() -> [u8; 32] {
        intent().digest().unwrap()
    }

    /// An install attempt that holds `instance` on `(HOST, COMPONENT)`.
    fn install(idempotency_key: &str, instance: Option<u32>) -> OperationAttempt {
        OperationAttempt {
            idempotency_key: key(idempotency_key),
            host: HOST.to_string(),
            target: COMPONENT.to_string(),
            instance,
            action: OperationAction::Install,
            package_digest: "sha256:aaa".to_string(),
            resolved_version: "1.2.3".to_string(),
            resolved_commit: "c0ffee".to_string(),
            phase: OperationPhase::Pending,
            cleanup_state: None,
            started_at: timestamp(1_700_000_000),
            retry_policy: OperationRetryPolicy {
                max_attempts: 5,
                attempts_made: 0,
                backoff_seconds: 30,
            },
            outcome: None,
            expires_at: timestamp(1_700_086_400),
            backup_id: None,
            pre_update_version: None,
            install_intent: Some(intent_digest()),
            finalized_at: None,
        }
    }

    /// A terminal attempt of `action` on the instance the install took.
    fn terminal(
        idempotency_key: &str,
        instance: u32,
        action: OperationAction,
        outcome: OperationOutcome,
    ) -> OperationAttempt {
        let mut attempt = install(idempotency_key, Some(instance));
        attempt.action = action;
        // Only an install records the request digest, and a row that is
        // terminal and owes nothing carries the instant it was finished with.
        if action != OperationAction::Install {
            attempt.install_intent = None;
        }
        attempt.phase = OperationPhase::Completed;
        attempt.outcome = Some(outcome);
        attempt.finalized_at = Some(timestamp(1_700_000_500));
        attempt
    }

    /// Sets `cleanup_state`, keeping `finalized_at` in step with it.
    ///
    /// The two are tied together by the schema — an attempt carries a
    /// finalization instant exactly when it is terminal and owes no cleanup —
    /// so a test that takes on or discharges an obligation moves both.
    fn with_cleanup(
        mut attempt: OperationAttempt,
        cleanup_state: Option<OperationCleanupState>,
    ) -> OperationAttempt {
        attempt.cleanup_state = cleanup_state;
        attempt.finalized_at = attempt
            .is_fully_discharged()
            .then(|| timestamp(1_700_000_500));
        attempt
    }

    /// Takes a number for `(host, component)` on behalf of `idempotency_key`,
    /// through the only entry point there is: the number and the
    /// `operation_attempt` that owns it land in one transaction.
    fn allocate_for(
        test_db: &TestDb,
        host: &str,
        component: &str,
        idempotency_key: &str,
    ) -> Result<u32, InstanceAllocationError> {
        let mut attempt = install(idempotency_key, None);
        attempt.host = host.to_string();
        attempt.target = component.to_string();
        let stored = test_db.attempts().allocate_instance(&attempt)?;
        Ok(stored
            .instance
            .expect("the allocator sets the number it picked"))
    }

    /// [`allocate_for`] on the pair the tests below are about.
    fn allocate(test_db: &TestDb, idempotency_key: &str) -> Result<u32, InstanceAllocationError> {
        allocate_for(test_db, HOST, COMPONENT, idempotency_key)
    }

    /// Frees `instance` for `(HOST, COMPONENT)`, for the tests that need a
    /// hole in the range without an attempt to justify one. The release the
    /// schema describes rides an `operation_attempt` write, and `upsert` and
    /// `sweep_expired` are what the tests below exercise it through.
    fn free(table: &Table<'_, InstanceAllocation>, instance: u32) {
        table
            .map
            .delete(&row_key(HOST, COMPONENT, instance).unwrap())
            .unwrap();
    }

    /// The numbers held for `(HOST, COMPONENT)`.
    fn held(table: &Table<'_, InstanceAllocation>) -> Vec<u32> {
        table
            .allocated(HOST, COMPONENT)
            .unwrap()
            .into_iter()
            .map(|row| row.instance)
            .collect()
    }

    /// The owning idempotency key is what identifies the attempt that holds
    /// the number, so it has to survive the round trip through the store.
    #[test]
    fn the_owning_idempotency_key_round_trips() {
        let test_db = TestDb::new();
        let table = test_db.table();

        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);

        let row = table.get(HOST, COMPONENT, 1).unwrap().unwrap();
        assert_eq!(
            row,
            InstanceAllocation {
                host: HOST.to_string(),
                component: COMPONENT.to_string(),
                instance: 1,
                idempotency_key: key("attempt-1"),
            }
        );
        assert_eq!(table.allocated(HOST, COMPONENT).unwrap(), vec![row.clone()]);
        assert_eq!(
            table
                .allocated_by(HOST, COMPONENT, &key("attempt-1"))
                .unwrap()
                .unwrap(),
            row
        );
        assert_eq!(
            table
                .allocated_by(HOST, COMPONENT, &key("attempt-2"))
                .unwrap(),
            None
        );
    }

    /// The number is the smallest free one, not the next one up: with `1` and
    /// `3` taken the hole at `2` is filled, which is what fails against a
    /// monotonic counter.
    #[test]
    fn allocates_the_smallest_free_number_over_a_hole() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);
        assert_eq!(allocate(&test_db, "attempt-2").unwrap(), 2);
        assert_eq!(allocate(&test_db, "attempt-3").unwrap(), 3);

        // Released as the schema describes: the write recording the attempt
        // ending is what gives its number back.
        attempts
            .upsert(&terminal(
                "attempt-2",
                2,
                OperationAction::Install,
                OperationOutcome::Failed,
            ))
            .unwrap();
        assert_eq!(held(&table), vec![1, 3]);

        assert_eq!(allocate(&test_db, "attempt-4").unwrap(), 2);
        assert_eq!(held(&table), vec![1, 2, 3]);
        assert_eq!(
            table
                .get(HOST, COMPONENT, 2)
                .unwrap()
                .unwrap()
                .idempotency_key,
            key("attempt-4")
        );
    }

    /// A first install takes `1`, a second takes `2` rather than being
    /// refused, and once the first is torn down a third reuses `1`.
    #[test]
    fn a_second_install_is_numbered_and_a_released_number_is_reused() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);
        assert_eq!(allocate(&test_db, "attempt-2").unwrap(), 2);

        // Released as the schema describes: the write recording the attempt
        // ending is what gives its number back.
        attempts
            .upsert(&terminal(
                "attempt-1",
                1,
                OperationAction::Install,
                OperationOutcome::Failed,
            ))
            .unwrap();
        assert_eq!(allocate(&test_db, "attempt-3").unwrap(), 1);
        assert_eq!(
            table
                .get(HOST, COMPONENT, 1)
                .unwrap()
                .unwrap()
                .idempotency_key,
            key("attempt-3")
        );
    }

    /// Releasing a number that is already free is not an error, so a re-driven
    /// cleanup need not check first.
    #[test]
    fn a_re_driven_release_is_not_an_error() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);
        let failed = terminal(
            "attempt-1",
            1,
            OperationAction::Install,
            OperationOutcome::Failed,
        );
        attempts.upsert(&failed).unwrap();
        assert_eq!(held(&table), Vec::<u32>::new());

        // The same write again, over a row that is already gone.
        attempts.upsert(&failed).unwrap();
        assert_eq!(held(&table), Vec::<u32>::new());
        assert_eq!(attempts.get(&key("attempt-1")).unwrap().unwrap(), failed);
    }

    /// The owning key is what a re-driven attempt recognizes its own
    /// allocation by, so presenting it again returns the number already held
    /// rather than taking a second one. Without this an interrupted install
    /// re-driven under one key would walk the range one number per drive.
    #[test]
    fn a_re_driven_attempt_is_given_its_own_number_back() {
        let test_db = TestDb::new();
        let table = test_db.table();

        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);
        assert_eq!(allocate(&test_db, "attempt-2").unwrap(), 2);

        // However often, and through either entry point.
        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);
        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);
        let txn = table.transaction();
        assert_eq!(
            table
                .allocate_with_transaction(HOST, COMPONENT, &key("attempt-2"), &txn)
                .unwrap(),
            2
        );
        txn.commit().unwrap();

        assert_eq!(held(&table), vec![1, 2]);
        assert_eq!(
            table
                .get(HOST, COMPONENT, 1)
                .unwrap()
                .unwrap()
                .idempotency_key,
            key("attempt-1")
        );
    }

    /// A key that already names an attempt is that attempt: the entry point
    /// returns the row as it stands and allocates nothing, however the attempt
    /// ended and however long ago. Selecting again would make one operator
    /// action two instances, and would overwrite the record of how the first
    /// one ended with a fresh non-terminal attempt.
    #[test]
    fn a_re_drive_of_a_recorded_attempt_allocates_nothing() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);
        // Released as the schema describes: the write recording the attempt
        // ending is what gives its number back. The number is then taken by
        // another attempt, so nothing of the first one's allocation is left.
        let failed = terminal(
            "attempt-1",
            1,
            OperationAction::Install,
            OperationOutcome::Failed,
        );
        attempts.upsert(&failed).unwrap();
        assert_eq!(allocate(&test_db, "attempt-2").unwrap(), 1);

        let stored = attempts
            .allocate_instance(&install("attempt-1", None))
            .unwrap();
        assert_eq!(stored, failed);
        assert_eq!(held(&table), vec![1]);
        assert_eq!(
            table
                .get(HOST, COMPONENT, 1)
                .unwrap()
                .unwrap()
                .idempotency_key,
            key("attempt-2")
        );
    }

    /// The key lookup precedes every eligibility check, so a re-drive of a
    /// recorded attempt is answered by the row rather than refused by a
    /// payload the call was never going to act on. The checks below the
    /// lookup decide what may take a *fresh* number, and this key takes none.
    #[test]
    fn a_re_drive_of_a_recorded_attempt_is_not_refused_by_its_payload() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);
        let recorded = attempts.get(&key("attempt-1")).unwrap().unwrap();

        // Each of these would be refused outright had no row been recorded
        // under the key: an action that takes no number, a component with no
        // instance dimension, and an install naming nothing.
        let mut updating = install("attempt-1", None);
        updating.action = OperationAction::Update;
        let mut core = install("attempt-1", None);
        core.target = "review".to_string();
        let mut unnamed = install("attempt-1", None);
        unnamed.target = String::new();

        for presented in [updating, core, unnamed] {
            let returned = attempts.allocate_instance(&presented).unwrap();
            assert_eq!(returned, recorded);
            assert_eq!(attempts.get(&key("attempt-1")).unwrap().unwrap(), recorded);
            assert_eq!(held(&table), vec![1]);
            assert_eq!(
                table
                    .get(HOST, COMPONENT, 1)
                    .unwrap()
                    .unwrap()
                    .idempotency_key,
                key("attempt-1")
            );
        }
    }

    /// The instant between deciding a key is free and writing the row under it
    /// is what the locked key read closes. Here a competing drive commits the
    /// attempt in exactly that instant: the pass that read the key as free
    /// cannot commit over it, and the re-run — the ordinary entry point —
    /// returns the committed row as it stands and allocates nothing. Reading
    /// the key before opening the transaction would leave that commit
    /// unopposed, because the transaction would begin after it and the write
    /// path would read the row as the one it is replacing.
    #[test]
    fn an_attempt_committed_after_the_key_read_is_not_overwritten() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        // The pass `allocate_instance` runs: its transaction's first read
        // locks the idempotency key and finds nothing under it, so a number is
        // selected.
        let txn = attempts.transaction();
        assert!(
            txn.get_for_update_cf(attempts.map.cf, key("attempt-1").as_bytes(), EXCLUSIVE)
                .unwrap()
                .is_none()
        );
        let instance = table
            .allocate_with_transaction(HOST, COMPONENT, &key("attempt-1"), &txn)
            .unwrap();
        assert_eq!(instance, 1);

        // A competing drive of the same key commits in that instant, and the
        // attempt it records has already ended.
        let failed = terminal(
            "attempt-1",
            2,
            OperationAction::Install,
            OperationOutcome::Failed,
        );
        attempts.create_or_resolve(&failed).unwrap();

        attempts
            .upsert_with_transaction(&install("attempt-1", Some(instance)), &txn)
            .unwrap();
        let conflict = txn.commit().unwrap_err();
        assert!(
            conflict.as_ref().starts_with("Resource busy:"),
            "expected a commit conflict, got {conflict}"
        );
        assert!(held(&table).is_empty());

        // The re-run, which is what the caller does with the conflict: the
        // committed row is returned untouched and no number is taken for it.
        let stored = attempts
            .allocate_instance(&install("attempt-1", None))
            .unwrap();
        assert_eq!(stored, failed);
        assert!(held(&table).is_empty());

        // Why the read has to be the transaction's first, shown at the level
        // where the other ordering can be expressed: a transaction opened
        // after that same commit conflicts with nothing, and the write path
        // reads the committed row as the one it is replacing and overwrites
        // it. A key read taken before the transaction would put the entry
        // point on this side of the ordering.
        let late = attempts.transaction();
        attempts
            .upsert_with_transaction(&install("attempt-1", Some(1)), &late)
            .unwrap();
        late.commit().unwrap();
        assert_eq!(
            attempts.get(&key("attempt-1")).unwrap().unwrap().phase,
            OperationPhase::Pending
        );
    }

    /// It is the row that the selection recognizes, not the key on its own:
    /// once the number an attempt held has been released and taken by another,
    /// selecting for that key picks a free number rather than claiming one
    /// that is now someone else's.
    #[test]
    fn a_number_taken_by_another_attempt_is_not_recognized() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);
        // Released as the schema describes: the write recording the attempt
        // ending is what gives its number back.
        attempts
            .upsert(&terminal(
                "attempt-1",
                1,
                OperationAction::Install,
                OperationOutcome::Failed,
            ))
            .unwrap();
        assert_eq!(allocate(&test_db, "attempt-2").unwrap(), 1);

        // Below the entry point, where the key check no longer stands in the
        // way: the selection itself does not claim `1` back.
        let txn = table.transaction();
        assert_eq!(
            table
                .allocate_with_transaction(HOST, COMPONENT, &key("attempt-1"), &txn)
                .unwrap(),
            2
        );
        txn.commit().unwrap();

        assert_eq!(held(&table), vec![1, 2]);
        assert_eq!(
            table
                .get(HOST, COMPONENT, 1)
                .unwrap()
                .unwrap()
                .idempotency_key,
            key("attempt-2")
        );
    }

    /// Two drives of one attempt racing are serialized by the
    /// `operation_attempt` row they both write — one row per idempotency key —
    /// so the loser's commit fails and its re-run is given the allocation the
    /// winner made rather than a second number.
    #[test]
    fn a_race_between_two_drives_of_one_attempt_leaves_one_number() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        let winner = table.transaction();
        let loser = table.transaction();
        for txn in [&winner, &loser] {
            let instance = table
                .allocate_with_transaction(HOST, COMPONENT, &key("attempt-1"), txn)
                .unwrap();
            assert_eq!(instance, 1);
            attempts
                .upsert_with_transaction(&install("attempt-1", Some(instance)), txn)
                .unwrap();
        }

        winner.commit().unwrap();
        let conflict = loser.commit().unwrap_err();
        assert!(
            conflict.as_ref().starts_with("Resource busy:"),
            "expected a commit conflict, got {conflict}"
        );

        // The re-run, which is what the caller does with the conflict.
        let retry = table.transaction();
        let instance = table
            .allocate_with_transaction(HOST, COMPONENT, &key("attempt-1"), &retry)
            .unwrap();
        assert_eq!(instance, 1);
        attempts
            .upsert_with_transaction(&install("attempt-1", Some(instance)), &retry)
            .unwrap();
        retry.commit().unwrap();

        assert_eq!(held(&table), vec![1]);
        assert_eq!(
            attempts.get(&key("attempt-1")).unwrap().unwrap().instance,
            Some(1)
        );
    }

    /// Two transactions that both read the prefix as empty both pick `1`. The
    /// locking read is what orders them: one commits and the other's commit
    /// fails, so the number is never committed twice, and the loser re-running
    /// the transaction picks `2`.
    #[test]
    fn concurrent_allocations_cannot_double_commit() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let winner = table.transaction();
        let loser = table.transaction();
        let first = table
            .allocate_with_transaction(HOST, COMPONENT, &key("attempt-a"), &winner)
            .unwrap();
        let second = table
            .allocate_with_transaction(HOST, COMPONENT, &key("attempt-b"), &loser)
            .unwrap();
        assert_eq!(first, 1);
        assert_eq!(second, 1);

        winner.commit().unwrap();
        let conflict = loser.commit().unwrap_err();
        assert!(
            conflict.as_ref().starts_with("Resource busy:"),
            "expected a commit conflict, got {conflict}"
        );

        // One number, one row, and it belongs to the transaction that
        // committed.
        assert_eq!(held(&table), vec![1]);
        assert_eq!(
            table
                .get(HOST, COMPONENT, 1)
                .unwrap()
                .unwrap()
                .idempotency_key,
            key("attempt-a")
        );

        // The loser re-runs the whole transaction, re-reads the prefix, and
        // now sees `1` taken.
        assert_eq!(allocate(&test_db, "attempt-b").unwrap(), 2);
    }

    /// The same race run by two threads through the retrying entry point: the
    /// loser retries rather than failing, and the two numbers differ.
    #[test]
    fn racing_threads_are_given_different_numbers() {
        let test_db = TestDb::new();

        let (first, second) = std::thread::scope(|scope| {
            let db = &test_db.db;
            let take = move |idempotency_key: &'static str| {
                move || {
                    Table::<OperationAttempt>::open(db)
                        .unwrap()
                        .allocate_instance(&install(idempotency_key, None))
                        .unwrap()
                        .instance
                        .unwrap()
                }
            };
            let a = scope.spawn(take("attempt-a"));
            let b = scope.spawn(take("attempt-b"));
            (a.join().unwrap(), b.join().unwrap())
        });

        assert_ne!(first, second);
        assert_eq!([first, second].into_iter().collect::<BTreeSet<_>>(), {
            let mut expected = BTreeSet::new();
            expected.insert(1);
            expected.insert(2);
            expected
        });

        let table = test_db.table();
        assert_eq!(held(&table), vec![1, 2]);
        let owners: BTreeSet<String> = table
            .allocated(HOST, COMPONENT)
            .unwrap()
            .into_iter()
            .map(|row| row.idempotency_key)
            .collect();
        assert_eq!(
            owners,
            [key("attempt-a"), key("attempt-b")].into_iter().collect()
        );
    }

    /// Two concurrent requests carrying **one** idempotency key are one
    /// operator action, and must produce one instance. The drive that loses
    /// the commit race re-reads the key before it re-selects, finds the
    /// attempt the winner recorded, and returns that rather than taking a
    /// second number.
    #[test]
    fn racing_drives_of_one_attempt_produce_one_number() {
        let test_db = TestDb::new();

        let (first, second) = std::thread::scope(|scope| {
            let db = &test_db.db;
            let drive = move || {
                Table::<OperationAttempt>::open(db)
                    .unwrap()
                    .allocate_instance(&install("attempt-1", None))
                    .unwrap()
                    .instance
                    .unwrap()
            };
            let a = scope.spawn(drive);
            let b = scope.spawn(drive);
            (a.join().unwrap(), b.join().unwrap())
        });

        assert_eq!(first, 1);
        assert_eq!(second, 1);

        let table = test_db.table();
        assert_eq!(held(&table), vec![1]);
        assert_eq!(
            table
                .get(HOST, COMPONENT, 1)
                .unwrap()
                .unwrap()
                .idempotency_key,
            key("attempt-1")
        );
        assert_eq!(
            test_db
                .attempts()
                .get(&key("attempt-1"))
                .unwrap()
                .unwrap()
                .instance,
            Some(1)
        );
    }

    /// With every number in `1..=999` taken the allocator refuses by name
    /// rather than wrapping or reusing a number whose row still exists.
    #[test]
    fn exhaustion_is_a_typed_refusal() {
        let test_db = TestDb::new();
        let table = test_db.table();

        for instance in MIN_INSTANCE..=MAX_INSTANCE {
            table
                .map
                .put(
                    &row_key(HOST, COMPONENT, instance).unwrap(),
                    key("attempt-x").as_bytes(),
                )
                .unwrap();
        }

        let error = allocate(&test_db, "attempt-1000").expect_err("every number is taken");
        match error {
            InstanceAllocationError::InstanceNumbersExhausted { component, host } => {
                assert_eq!(component, COMPONENT);
                assert_eq!(host, HOST);
            }
            other @ InstanceAllocationError::Database(_) => {
                panic!("expected an exhaustion refusal, got {other:?}")
            }
        }

        // Nothing wrapped: no row outside the range, and the range is intact.
        assert_eq!(table.allocated(HOST, COMPONENT).unwrap().len(), 999);
        assert_eq!(table.get(HOST, COMPONENT, 0).unwrap(), None);
        assert_eq!(table.get(HOST, COMPONENT, 1000).unwrap(), None);

        // A single release is enough to make the pair allocatable again.
        free(&table, 500);
        assert_eq!(allocate(&test_db, "attempt-1000").unwrap(), 500);
    }

    /// The pair leads the key, so one pair's numbers are invisible to another
    /// and the counts are independent.
    #[test]
    fn each_pair_is_numbered_on_its_own() {
        let test_db = TestDb::new();
        let table = test_db.table();

        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);
        assert_eq!(
            allocate_for(&test_db, HOST, OTHER_COMPONENT, "attempt-2").unwrap(),
            1
        );
        assert_eq!(
            allocate_for(&test_db, OTHER_HOST, COMPONENT, "attempt-3").unwrap(),
            1
        );
        assert_eq!(allocate(&test_db, "attempt-4").unwrap(), 2);

        assert_eq!(held(&table), vec![1, 2]);
        assert_eq!(table.allocated(HOST, OTHER_COMPONENT).unwrap().len(), 1);
        assert_eq!(table.allocated(OTHER_HOST, COMPONENT).unwrap().len(), 1);
    }

    /// Both halves of the pair are variable-length, so a naive concatenation
    /// would map these onto the same prefix and let one pair's numbers hide
    /// the other's.
    #[test]
    fn key_encoding_is_collision_safe() {
        assert_ne!(
            row_key("ab", "c", 1).unwrap(),
            row_key("a", "bc", 1).unwrap()
        );

        let test_db = TestDb::new();
        let table = test_db.table();

        assert_eq!(allocate_for(&test_db, "ab", "c", "attempt-1").unwrap(), 1);
        assert_eq!(allocate_for(&test_db, "a", "bc", "attempt-2").unwrap(), 1);
        assert_eq!(
            table.get("ab", "c", 1).unwrap().unwrap().idempotency_key,
            key("attempt-1")
        );
        assert_eq!(
            table.get("a", "bc", 1).unwrap().unwrap().idempotency_key,
            key("attempt-2")
        );
    }

    #[test]
    fn key_round_trips_and_rejects_what_it_never_wrote() {
        for (host, component, instance) in [
            (HOST, COMPONENT, 1u32),
            ("ab", "c", 999),
            ("a", "bc", 42),
            ("", "", 1),
        ] {
            let bytes = row_key(host, component, instance).unwrap();
            assert_eq!(
                decode_key(&bytes).unwrap(),
                (host.to_string(), component.to_string(), instance)
            );
        }

        let mut trailing = row_key(HOST, COMPONENT, 1).unwrap();
        trailing.push(0);
        assert!(decode_key(&trailing).is_err());
        assert!(decode_key(b"").is_err());
        assert!(decode_key(b"\x00\x00\x00\x09ab").is_err());
        assert!(decode_key(&pair_prefix(HOST, COMPONENT).unwrap()).is_err());
    }

    /// The number is encoded big endian, so the prefix scan reads the numbers
    /// in ascending order and `10` does not sort between `1` and `2`.
    #[test]
    fn the_scan_reads_the_numbers_in_ascending_order() {
        let test_db = TestDb::new();
        let table = test_db.table();

        for instance in [11u32, 2, 100, 1, 20] {
            table
                .map
                .put(
                    &row_key(HOST, COMPONENT, instance).unwrap(),
                    key("attempt-x").as_bytes(),
                )
                .unwrap();
        }

        assert_eq!(held(&table), vec![1, 2, 11, 20, 100]);
        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 3);
    }

    /// A row must name the attempt that owns it, so an empty key is refused
    /// rather than stored.
    #[test]
    fn an_unowned_row_is_refused() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let mut unowned = install("attempt-unowned", None);
        unowned.idempotency_key = String::new();
        assert!(test_db.attempts().allocate_instance(&unowned).is_err());
        assert_eq!(held(&table), Vec::<u32>::new());

        table
            .map
            .put(&row_key(HOST, COMPONENT, 1).unwrap(), b"")
            .unwrap();
        assert!(table.get(HOST, COMPONENT, 1).is_err());
        assert!(table.allocated(HOST, COMPONENT).is_err());
    }

    /// The first install of a core component meets a store with no registry
    /// row for it — the row is what that install would go on to write. So the
    /// refusal cannot wait for one: each canonical package-id is refused a
    /// number on an empty store, and neither the allocation nor the attempt is
    /// written.
    #[test]
    fn a_fresh_core_component_install_is_refused_with_no_registry_row() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();
        let core_components = Table::<super::super::CoreComponent>::open(&test_db.db).unwrap();

        for (i, component) in ["review", "aice-web-next", "roxyd", "bootroot"]
            .into_iter()
            .enumerate()
        {
            let key = format!("attempt-fresh-core-{i}");
            assert!(core_components.get(component, HOST).unwrap().is_none());

            let refused = allocate_for(&test_db, HOST, component, &key);
            assert!(matches!(refused, Err(InstanceAllocationError::Database(_))));
            assert_eq!(table.allocated(HOST, component).unwrap(), Vec::new());
            assert!(attempts.get(&key).unwrap().is_none());
        }

        // The module beside them is still numbered, so the refusal is the
        // package-id and not the empty store.
        assert_eq!(
            allocate_for(&test_db, HOST, COMPONENT, "attempt-module").unwrap(),
            1
        );
    }

    /// Only the five modules are multi-instance. A core component takes no
    /// number at all — its attempts record `None` — and a second install of
    /// one is refused by the single row per `(component, host)` its own
    /// registry holds, not given another number. The registry read behind that
    /// refusal answers for a registered package-id this build does not
    /// classify, too.
    #[test]
    fn a_core_component_takes_no_number_and_a_second_install_is_refused() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();
        let core_components = Table::<super::super::CoreComponent>::open(&test_db.db).unwrap();

        let installed = super::super::CoreComponent {
            component: "review".to_string(),
            host: HOST.to_string(),
            installed_version: Some("0.47.0".to_string()),
            installed_commit: Some("c0ffee".to_string()),
            lifecycle: super::super::Lifecycle::Running,
            installer_managed: false,
        };
        core_components.insert(&installed).unwrap();
        assert!(core_components.insert(&installed).is_err());

        // The allocator refuses the pair the registry holds, so the entry
        // point cannot hand a core component a number even if it is asked.
        let refused = allocate_for(&test_db, HOST, "review", "attempt-core-alloc");
        assert!(matches!(refused, Err(InstanceAllocationError::Database(_))));
        assert_eq!(table.allocated(HOST, "review").unwrap(), Vec::new());
        assert!(attempts.get(&key("attempt-core-alloc")).unwrap().is_none());

        let mut attempt = install("attempt-core", None);
        attempt.target = "review".to_string();
        attempts.create_or_resolve(&attempt).unwrap();
        assert_eq!(
            attempts
                .get(&key("attempt-core"))
                .unwrap()
                .unwrap()
                .instance,
            None
        );

        // Nothing was allocated, and finalizing the attempt releases nothing.
        assert_eq!(table.allocated(HOST, "review").unwrap(), Vec::new());
        attempt.phase = OperationPhase::Completed;
        attempt.outcome = Some(OperationOutcome::Failed);
        attempt.finalized_at = Some(timestamp(1_700_000_500));
        attempts.upsert(&attempt).unwrap();
        assert_eq!(table.allocated(HOST, "review").unwrap(), Vec::new());

        // A package-id this build does not classify, registered as a core
        // component by one that does: the registry read is what refuses it.
        let registered = super::super::CoreComponent {
            component: "successor-core".to_string(),
            ..installed
        };
        core_components.insert(&registered).unwrap();
        let refused = allocate_for(&test_db, HOST, "successor-core", "attempt-unknown-core");
        assert!(matches!(refused, Err(InstanceAllocationError::Database(_))));
        assert_eq!(table.allocated(HOST, "successor-core").unwrap(), Vec::new());
        assert!(
            attempts
                .get(&key("attempt-unknown-core"))
                .unwrap()
                .is_none()
        );
    }

    /// The registry read is a locked read, so a registration that commits
    /// while the allocating transaction is open fails that transaction's
    /// commit rather than going unseen. Here the row for the pair is inserted
    /// in exactly the instant between the read and the write: the pass that
    /// saw no registration cannot commit a number over it, and the re-run —
    /// the ordinary entry point — refuses the pair and writes nothing. An
    /// unlocked `get_cf` would leave that commit unopposed, because an
    /// optimistic transaction validates only the keys it read for update, and
    /// the pair would end up with both a registry row and an instance number.
    #[test]
    fn a_registration_committed_after_the_registry_read_fails_the_allocation() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();
        let core_components = Table::<super::super::CoreComponent>::open(&test_db.db).unwrap();

        // The pass `allocate_instance` runs, up to the point where it has
        // decided the pair is not a core component: the locked key read finds
        // nothing, and so does the locked registry read.
        let txn = attempts.transaction();
        assert!(
            txn.get_for_update_cf(attempts.map.cf, key("attempt-1").as_bytes(), EXCLUSIVE)
                .unwrap()
                .is_none()
        );
        assert!(
            !core_components
                .is_registered("successor-core", HOST, &txn)
                .unwrap()
        );

        // The registration commits in that instant, under a package-id this
        // build does not classify — the case only the registry read answers.
        core_components
            .insert(&super::super::CoreComponent {
                component: "successor-core".to_string(),
                host: HOST.to_string(),
                installed_version: Some("0.47.0".to_string()),
                installed_commit: Some("c0ffee".to_string()),
                lifecycle: super::super::Lifecycle::Running,
                installer_managed: false,
            })
            .unwrap();

        let instance = table
            .allocate_with_transaction(HOST, "successor-core", &key("attempt-1"), &txn)
            .unwrap();
        let mut allocated = install("attempt-1", Some(instance));
        allocated.target = "successor-core".to_string();
        attempts.upsert_with_transaction(&allocated, &txn).unwrap();
        let conflict = txn.commit().unwrap_err();
        assert!(
            conflict.as_ref().starts_with("Resource busy:"),
            "expected a commit conflict, got {conflict}"
        );
        assert_eq!(table.allocated(HOST, "successor-core").unwrap(), Vec::new());
        assert!(attempts.get(&key("attempt-1")).unwrap().is_none());

        // The re-run, which is what the caller does with the conflict: the
        // registration is now visible and the pair is refused outright.
        let refused = allocate_for(&test_db, HOST, "successor-core", "attempt-1");
        assert!(matches!(refused, Err(InstanceAllocationError::Database(_))));
        assert_eq!(table.allocated(HOST, "successor-core").unwrap(), Vec::new());
        assert!(attempts.get(&key("attempt-1")).unwrap().is_none());
    }

    /// Only the install that creates an instance takes a number. An update
    /// and a removal concern an instance that has one already, an onboarding
    /// names no component at all, and neither the allocation nor the attempt
    /// is written for any of them.
    #[test]
    fn only_an_install_naming_a_component_takes_a_number() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        for (name, action) in [
            ("attempt-update", OperationAction::Update),
            ("attempt-remove", OperationAction::Remove),
            ("attempt-onboard", OperationAction::Onboard),
        ] {
            let mut attempt = install(name, None);
            attempt.action = action;
            attempt.install_intent = None;
            let refused = attempts.allocate_instance(&attempt);
            assert!(matches!(refused, Err(InstanceAllocationError::Database(_))));
            assert!(attempts.get(&key(name)).unwrap().is_none());
        }

        // An install carrying no component would key a row on an unnamed one.
        let mut unnamed = install("attempt-unnamed", None);
        unnamed.target = String::new();
        let refused = attempts.allocate_instance(&unnamed);
        assert!(matches!(refused, Err(InstanceAllocationError::Database(_))));
        assert!(attempts.get(&key("attempt-unnamed")).unwrap().is_none());

        assert_eq!(held(&table), Vec::<u32>::new());
        assert_eq!(allocate(&test_db, "attempt-install").unwrap(), 1);
    }

    /// A terminal success keeps the number: the instance owns it from then on,
    /// and releasing it would hand it to the next install while the instance
    /// is still running.
    #[test]
    fn a_terminal_success_keeps_the_number() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);
        let succeeded = terminal(
            "attempt-1",
            1,
            OperationAction::Install,
            OperationOutcome::Succeeded,
        );
        attempts.upsert(&succeeded).unwrap();

        assert_eq!(held(&table), vec![1]);
        assert_eq!(attempts.get(&key("attempt-1")).unwrap().unwrap(), succeeded);
        // The next install is therefore given a different number.
        assert_eq!(allocate(&test_db, "attempt-2").unwrap(), 2);
    }

    /// An attempt that owes no cleanup and did not succeed gives its own
    /// number back, in the write that records the outcome. Rolling back counts
    /// with failing and cancelling: an install that rolled back left no
    /// instance behind.
    ///
    /// The write is the ordinary `upsert`, not a release a caller had to
    /// select: there is no way to record this outcome and keep the number.
    #[test]
    fn an_unsuccessful_attempt_releases_its_own_number() {
        for outcome in [
            OperationOutcome::Failed,
            OperationOutcome::Cancelled,
            OperationOutcome::RolledBack,
        ] {
            let test_db = TestDb::new();
            let table = test_db.table();
            let attempts = test_db.attempts();

            assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);
            let finalized = terminal("attempt-1", 1, OperationAction::Install, outcome);
            attempts.upsert(&finalized).unwrap();

            assert_eq!(held(&table), Vec::<u32>::new(), "outcome {outcome:?}");
            assert_eq!(attempts.get(&key("attempt-1")).unwrap().unwrap(), finalized);
            // The number is immediately re-allocatable, which is the
            // observable consequence of release being a delete.
            assert_eq!(allocate(&test_db, "attempt-2").unwrap(), 1);
        }
    }

    /// A terminal attempt that still owes a cleanup keeps its number: the
    /// discharge is the write that releases it.
    #[test]
    fn the_number_is_held_until_the_cleanup_is_discharged() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);
        let owing = terminal(
            "attempt-1",
            1,
            OperationAction::Install,
            OperationOutcome::Failed,
        );
        let owing = with_cleanup(owing, Some(OperationCleanupState::PendingIdentityTeardown));
        attempts.upsert(&owing).unwrap();
        assert_eq!(held(&table), vec![1]);

        let discharged = with_cleanup(owing.clone(), None);
        attempts.upsert(&discharged).unwrap();

        assert_eq!(held(&table), Vec::<u32>::new());
        assert_eq!(
            attempts.get(&key("attempt-1")).unwrap().unwrap(),
            discharged
        );
    }

    /// A confirmed removal releases the number whichever attempt allocated it:
    /// the install took it, the removal ends the instance that owns it.
    #[test]
    fn a_confirmed_removal_releases_the_number_the_install_took() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        assert_eq!(allocate(&test_db, "attempt-install").unwrap(), 1);
        attempts
            .upsert(&terminal(
                "attempt-install",
                1,
                OperationAction::Install,
                OperationOutcome::Succeeded,
            ))
            .unwrap();
        assert_eq!(held(&table), vec![1]);

        let removed = terminal(
            "attempt-remove",
            1,
            OperationAction::Remove,
            OperationOutcome::Succeeded,
        );
        attempts.upsert(&removed).unwrap();

        assert_eq!(held(&table), Vec::<u32>::new());
        assert_eq!(
            attempts.get(&key("attempt-remove")).unwrap().unwrap(),
            removed
        );
        assert_eq!(allocate(&test_db, "attempt-3").unwrap(), 1);
    }

    /// A removal that failed does not release the number: the instance is
    /// still there, and the row it holds was never this attempt's.
    #[test]
    fn a_failed_removal_leaves_the_instance_its_number() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        assert_eq!(allocate(&test_db, "attempt-install").unwrap(), 1);
        attempts
            .upsert(&terminal(
                "attempt-remove",
                1,
                OperationAction::Remove,
                OperationOutcome::Failed,
            ))
            .unwrap();

        assert_eq!(held(&table), vec![1]);
        assert_eq!(
            table
                .get(HOST, COMPONENT, 1)
                .unwrap()
                .unwrap()
                .idempotency_key,
            key("attempt-install")
        );
    }

    /// An update that failed does not tear down the instance it was updating,
    /// so the number stays with the attempt that allocated it. This is what
    /// the owner on the row decides.
    #[test]
    fn a_failed_update_leaves_the_running_instance_its_number() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        assert_eq!(allocate(&test_db, "attempt-install").unwrap(), 1);
        for outcome in [
            OperationOutcome::Failed,
            OperationOutcome::Cancelled,
            OperationOutcome::RolledBack,
        ] {
            let mut update = terminal("attempt-update", 1, OperationAction::Update, outcome);
            update.idempotency_key = key(&format!("attempt-update-{outcome:?}"));
            attempts.upsert(&update).unwrap();
            assert_eq!(held(&table), vec![1], "outcome {outcome:?}");
        }

        assert_eq!(
            table
                .get(HOST, COMPONENT, 1)
                .unwrap()
                .unwrap()
                .idempotency_key,
            key("attempt-install")
        );
    }

    /// A re-drive may restate any field but the `(host, target, instance)`
    /// triple its number is held under, and only while it is held. The release
    /// is found by the attempt's own triple, so a row that walked to another
    /// one would leave the number held by a record that no longer names it —
    /// and by nothing else, since no later write could name it either.
    #[test]
    fn a_re_drive_cannot_walk_away_from_its_own_number() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);

        // A terminal failure recorded against another host under the same key.
        // The release it would carry looks up a triple that never held a
        // number, so the one this key holds would be stranded.
        let mut elsewhere = terminal(
            "attempt-1",
            1,
            OperationAction::Install,
            OperationOutcome::Failed,
        );
        elsewhere.host = OTHER_HOST.to_string();
        assert!(attempts.upsert(&elsewhere).is_err());
        // Neither half of the refused write landed.
        assert_eq!(held(&table), vec![1]);
        assert_eq!(attempts.get(&key("attempt-1")).unwrap().unwrap().host, HOST);

        // The other two thirds of the triple are refused on the same ground.
        let mut other_component = elsewhere.clone();
        other_component.host = HOST.to_string();
        other_component.target = OTHER_COMPONENT.to_string();
        assert!(attempts.upsert(&other_component).is_err());
        let mut other_number = elsewhere.clone();
        other_number.host = HOST.to_string();
        other_number.instance = Some(2);
        assert!(attempts.upsert(&other_number).is_err());
        assert_eq!(held(&table), vec![1]);

        // Finalizing on the triple the number was taken for is the write the
        // attempt is owed, and it gives the number back.
        attempts
            .upsert(&terminal(
                "attempt-1",
                1,
                OperationAction::Install,
                OperationOutcome::Failed,
            ))
            .unwrap();
        assert_eq!(held(&table), Vec::<u32>::new());

        // With the number gone the key is free to move: there is nothing left
        // to strand.
        attempts.upsert(&elsewhere).unwrap();
        assert_eq!(
            attempts.get(&key("attempt-1")).unwrap().unwrap().host,
            OTHER_HOST
        );
    }

    /// An attempt whose host never returned is finalized by the sweep, and the
    /// number it holds goes back in that same write.
    #[test]
    fn an_expired_attempt_releases_its_number_in_the_sweep() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);
        attempts.upsert(&install("attempt-1", Some(1))).unwrap();
        assert_eq!(held(&table), vec![1]);

        assert_eq!(
            attempts.sweep_expired(timestamp(1_700_000_000)).unwrap(),
            0,
            "the deadline has not passed"
        );
        assert_eq!(held(&table), vec![1]);

        assert_eq!(attempts.sweep_expired(timestamp(1_700_086_400)).unwrap(), 1);
        let swept = attempts.get(&key("attempt-1")).unwrap().unwrap();
        assert_eq!(swept.outcome, Some(OperationOutcome::Failed));
        assert_eq!(held(&table), Vec::<u32>::new());

        // The sweep reads no clock of its own, so a second run over swept
        // state finalizes nothing and releases nothing.
        assert_eq!(attempts.sweep_expired(timestamp(1_700_086_400)).unwrap(), 0);
    }

    /// The sweep leaves an owed cleanup recorded, so the number it names stays
    /// held until the discharge releases it.
    #[test]
    fn a_swept_attempt_still_owing_cleanup_keeps_its_number() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);
        let mut owing = install("attempt-1", Some(1));
        owing.cleanup_state = Some(OperationCleanupState::PendingIdentityTeardown);
        attempts.upsert(&owing).unwrap();

        assert_eq!(attempts.sweep_expired(timestamp(1_700_086_400)).unwrap(), 1);
        assert_eq!(held(&table), vec![1]);

        let discharged = with_cleanup(attempts.get(&key("attempt-1")).unwrap().unwrap(), None);
        attempts.upsert(&discharged).unwrap();
        assert_eq!(held(&table), Vec::<u32>::new());
    }

    /// The delete rides the write that justifies it, so a transaction that
    /// never commits leaves neither half: the number is still held and the
    /// record that would have justified giving it back was never written, so a
    /// re-drive finds the work still owed.
    #[test]
    fn a_fault_in_the_releasing_transaction_leaves_neither_half() {
        let failed = terminal(
            "attempt-1",
            1,
            OperationAction::Install,
            OperationOutcome::Failed,
        );
        let owing = with_cleanup(
            failed.clone(),
            Some(OperationCleanupState::PendingIdentityTeardown),
        );
        let occasions = [
            ("a failed attempt owing no cleanup", None, failed.clone()),
            ("the cleanup discharge", Some(owing), failed),
            (
                "a confirmed removal",
                None,
                terminal(
                    "attempt-remove",
                    1,
                    OperationAction::Remove,
                    OperationOutcome::Succeeded,
                ),
            ),
        ];

        for (occasion, owed, attempt) in occasions {
            let test_db = TestDb::new();
            let table = test_db.table();
            let attempts = test_db.attempts();

            assert_eq!(allocate(&test_db, "attempt-1").unwrap(), 1);
            // The discharge releases only what the write before it left owed.
            let stored_cleanup = owed.as_ref().and_then(|owed| owed.cleanup_state);
            if let Some(owed) = owed {
                attempts.upsert(&owed).unwrap();
                assert_eq!(held(&table), vec![1], "{occasion}");
            }

            // The transaction `upsert` builds, abandoned before it commits.
            let txn = table.transaction();
            attempts.upsert_with_transaction(&attempt, &txn).unwrap();
            drop(txn);

            assert_eq!(held(&table), vec![1], "{occasion}");
            assert_eq!(
                attempts
                    .get(&attempt.idempotency_key)
                    .unwrap()
                    .and_then(|stored| stored.cleanup_state),
                stored_cleanup,
                "{occasion}"
            );

            // Committed, both halves land.
            attempts.upsert(&attempt).unwrap();
            assert_eq!(held(&table), Vec::<u32>::new(), "{occasion}");
            assert!(attempts.get(&attempt.idempotency_key).unwrap().is_some());
        }
    }

    /// The allocation and the `operation_attempt` that owns it are written in
    /// one transaction, which is what the port rows keyed on the number will
    /// join. A transaction that never commits leaves neither half, so no
    /// number is held by an attempt that was never recorded.
    #[test]
    fn an_allocation_and_the_attempt_that_owns_it_land_together() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        // Abandoned before it commits: the number is not held and the attempt
        // was never recorded.
        let txn = table.transaction();
        let instance = table
            .allocate_with_transaction(HOST, COMPONENT, &key("attempt-1"), &txn)
            .unwrap();
        assert_eq!(instance, 1);
        attempts
            .upsert_with_transaction(&install("attempt-1", Some(instance)), &txn)
            .unwrap();
        drop(txn);

        assert_eq!(held(&table), Vec::<u32>::new());
        assert_eq!(attempts.get(&key("attempt-1")).unwrap(), None);

        // Which is what the public entry point does: one transaction, and the
        // row names the attempt that owns it — how a re-drive recognizes its
        // own allocation instead of taking a second number.
        let stored = attempts
            .allocate_instance(&install("attempt-1", None))
            .unwrap();
        assert_eq!(stored.instance, Some(1));
        assert_eq!(held(&table), vec![1]);
        assert_eq!(attempts.get(&key("attempt-1")).unwrap().unwrap(), stored);
        assert_eq!(
            table
                .allocated_by(HOST, COMPONENT, &key("attempt-1"))
                .unwrap()
                .unwrap()
                .instance,
            1
        );
    }

    /// The transaction the port rows keyed on the number will join: the
    /// allocation and the attempt write are composed by the caller and
    /// committed once, and both halves land.
    #[test]
    fn a_composed_transaction_commits_both_halves() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        let txn = table.transaction();
        let instance = table
            .allocate_with_transaction(HOST, COMPONENT, &key("attempt-1"), &txn)
            .unwrap();
        attempts
            .upsert_with_transaction(&install("attempt-1", Some(instance)), &txn)
            .unwrap();
        txn.commit().unwrap();

        assert_eq!(held(&table), vec![1]);
        assert_eq!(
            attempts.get(&key("attempt-1")).unwrap().unwrap().instance,
            Some(1)
        );
        assert_eq!(
            table
                .allocated_by(HOST, COMPONENT, &key("attempt-1"))
                .unwrap()
                .unwrap()
                .instance,
            1
        );
    }
}
