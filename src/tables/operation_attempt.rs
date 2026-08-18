//! The `operation_attempt` table.
//!
//! This is the durable ledger of the package operations `REview` executes on
//! hosts. It exists so that a `REview` restart can tell which operation was in
//! flight, which build it had resolved to, and which compensation it still
//! owes.
//!
//! # Key spaces
//!
//! The column family holds the records and the three secondary indexes that
//! answer "is there a live operation for this?", "what is still owed?" and
//! "what has run out of time?". They are told apart by the first byte of the
//! key. A record key is the idempotency key, which is a non-empty UTF-8
//! string, and the largest lead byte UTF-8 defines is `0xf4`, so every byte
//! from [`RESERVED`] up is free for the indexes and an index key can never
//! collide with a record key.
//!
//! | First byte | Key space |
//! | --- | --- |
//! | below [`RESERVED`] | a record, keyed by its idempotency key |
//! | [`NON_TERMINAL`] | the non-terminal `(host, target, instance)` index |
//! | [`OWED_CLEANUP`] | the owed-cleanup `(target, host, instance)` index |
//! | [`EXPIRES_AT`] | the `expires_at` index |
//! | above [`EXPIRES_AT`] | reserved for further indexes |
//!
//! Each composite key is built by exactly one function, and every variable
//! length segment in it is length-prefixed, so `(host = "ab", target = "c")`
//! and `(host = "a", target = "bc")` cannot encode to the same bytes. Every
//! index entry holds the idempotency key of the row it points at as its value.
//!
//! Every index entry is written and removed in the same transaction as its
//! row, so one can never outlive the other. [`Table::upsert`],
//! [`Table::delete`], [`Table::sweep_expired`] and [`Table::prune`] are
//! therefore this table's only writers, and that is enforced by the compiler
//! rather than by convention: the generic write API on [`Table`] is bounded by
//! [`UniqueKey`](crate::UniqueKey) and [`Value`](super::Value), and
//! [`OperationAttempt`] implements neither. `put`, `insert`,
//! `update_with_transaction` and `delete_with_transaction` therefore do not
//! exist for this table at all, so no caller can store a row the indexes never
//! learn about, or drop one and leave its entries behind. The record's key and
//! serialized value are reached through [`OperationAttempt::record_key`] and
//! [`OperationAttempt::record_value`], which are private to this module.

use std::borrow::Cow;
use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, TimeDelta, Utc};
use rocksdb::{Direction, IteratorMode, OptimisticTransactionDB, ReadOptions, Transaction};
use serde::{Deserialize, Serialize};

use crate::{EXCLUSIVE, Map, Table, types::FromKeyValue};

/// The first byte reserved for the index key spaces.
///
/// No valid UTF-8 string starts with a byte this large, so no record key can
/// reach this space and no index key can reach the record space.
const RESERVED: u8 = 0xf8;

/// The leading byte of the non-terminal `(host, target, instance)` index.
const NON_TERMINAL: u8 = 0xf8;

/// The leading byte of the owed-cleanup `(target, host, instance)` index.
const OWED_CLEANUP: u8 = 0xf9;

/// The leading byte of the `expires_at` index.
const EXPIRES_AT: u8 = 0xfa;

/// The width of an encoded timestamp: the seconds, then the nanoseconds.
const TIMESTAMP_LEN: usize = 12;

/// The operator's intent for an attempt.
///
/// This is recorded for display and audit; it is not a wire distinction,
/// because installing and updating a package are the same operation on the
/// wire. `Install` versus `Update` reflects only whether the target already
/// had a build.
///
/// Adding a variant later is cheap: the stored encoding is the variant index,
/// so appending one does not disturb existing rows.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum Action {
    Install = 1,
    Update = 2,
    Remove = 3,
    /// A pending host onboarding: no package, and the host has not checked in
    /// yet.
    Onboard = 4,
}

/// How far `REview` has driven an attempt.
///
/// Coarse by design. The manager sets it at the boundaries it controls; the
/// fine verify/enroll/start sub-steps are roxyd-internal and are not stored
/// here.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum Phase {
    Pending = 1,
    Dispatched = 2,
    AwaitingReport = 3,
    Completed = 4,
}

/// The compensation an attempt still owes.
///
/// Held behind an `Option` on the record, so "nothing owed" is `None` rather
/// than a sentinel variant.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum CleanupState {
    /// A `Deregister` is owed against the registrar.
    PendingDeregister = 1,
    /// A minted identity that never checked in is owed a teardown.
    PendingIdentityTeardown = 2,
}

/// The terminal result of an apply.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum Outcome {
    Succeeded = 1,
    Failed = 2,
    RolledBack = 3,
    Cancelled = 4,
}

/// The terminating retry budget of an apply.
///
/// This crate stores the budget; `review` advances and enforces it. Unlike the
/// enums above, the field set here is a persisted shape: changing it needs its
/// own migration, so it stays minimal.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub attempts_made: u32,
    pub backoff_seconds: u32,
}

/// A package operation `REview` is executing on a host, or a pending host
/// onboarding.
///
/// # Not `apply_attempts`
///
/// `operation_attempt` is **not** aice-web-next's `apply_attempts` table, and
/// neither replaces the other. `apply_attempts` lives in aice-web-next's auth
/// database and tracks **one operator's config-Apply run through the UI** —
/// which drafts that click intended to dispatch, and whether the browser-side
/// run still holds its lock. `operation_attempt` tracks **the package
/// operation `REview` is executing on a host**, survives a `REview` restart,
/// and carries the compensation owed to bootroot. They sit on different sides of
/// the API, key on different things, and have different lifetimes: the UI
/// ledger cannot answer "is there an owed `Deregister`", and this one cannot
/// answer "did that click finish dispatching". Do not collapse them or drive
/// one from the other.
///
/// # Absent values
///
/// Every package-scoped field — `target`, `package_digest`,
/// `resolved_version`, `resolved_commit` — is a plain `String` that is empty
/// exactly when `action` is [`Action::Onboard`], so a reader never has to
/// guess which absent encoding a given field uses. `backup_id` and
/// `pre_update_version` are core-update-scoped rather than package-scoped, and
/// use `Option` as each other does.
///
/// # Identity
///
/// The row is keyed by `idempotency_key` alone: `REview` generates a distinct
/// key per logical operation, so a re-drive or a resume with the same key
/// finds or upserts the same row and never creates a duplicate. `host`,
/// `target` and `instance` are data on the row, not part of the key. The key
/// is never empty, and both the write and the decode path reject an empty one:
/// the shared table iterator reads an empty key as indexed-table metadata and
/// skips it, so such a row would be invisible to the very scans this ledger
/// exists to support.
///
/// # Writing
///
/// Every write to this table has to maintain the three secondary indexes in
/// the same transaction as the row, so the record is written only through the
/// index-aware `upsert`, `delete`, `sweep_expired` and `prune` on
/// `Table<'_, OperationAttempt>`. Nothing else can write it: the generic write
/// API on [`Table`] — `put`, `insert`,
/// `update_with_transaction`, `delete_with_transaction` — is bounded by
/// [`UniqueKey`](crate::UniqueKey) and the crate's `Value` trait, and this
/// record implements neither, so those methods do not exist for its table.
///
/// A record that does implement [`UniqueKey`](crate::UniqueKey) is admitted:
///
/// ```
/// fn generic_write_api<R: review_database::UniqueKey>() {}
/// generic_write_api::<review_database::TorExitNode>();
/// ```
///
/// An `OperationAttempt` is not, which is what stops a caller from storing a
/// live row that `live_attempt` and the sweep would never see:
///
/// ```compile_fail
/// fn generic_write_api<R: review_database::UniqueKey>() {}
/// generic_write_api::<review_database::OperationAttempt>();
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct OperationAttempt {
    /// The globally unique key of the logical operation. Never empty.
    pub idempotency_key: String,
    /// The host the operation applies to.
    pub host: String,
    /// The host-agnostic package id. Empty for [`Action::Onboard`].
    pub target: String,
    /// The instance number this operation concerns, or `None` for a component
    /// whose class has no instance dimension.
    ///
    /// This is the number, not a composed name, and it is the same type the
    /// wire carries, so nothing has to convert or compare string forms; the
    /// three-digit zero-padded rendering belongs to the certificate SAN and
    /// the registration id. In v1 it is `Some(1)` for a module and `None` for
    /// a core component.
    pub instance: Option<u32>,
    /// The operator's intent.
    pub action: Action,
    /// The digest of the package being applied. Empty for [`Action::Onboard`].
    pub package_digest: String,
    /// The version the selector resolved to. Empty for [`Action::Onboard`].
    pub resolved_version: String,
    /// The commit the selector resolved to. Empty for [`Action::Onboard`].
    ///
    /// Recorded alongside `resolved_version`, never version alone: the same
    /// version may carry different commits.
    pub resolved_commit: String,
    /// How far `REview` has driven the attempt.
    pub phase: Phase,
    /// The compensation still owed, or `None` when nothing is owed.
    ///
    /// Tracked separately from `outcome`, because the obligation is durable
    /// and is not bounded by the apply's retry budget: an apply may terminate
    /// `Failed` with a teardown still owed, and that owed work is re-driven
    /// once the registrar becomes reachable.
    pub cleanup_state: Option<CleanupState>,
    pub started_at: DateTime<Utc>,
    /// The apply's terminating retry budget.
    pub retry_policy: RetryPolicy,
    /// The terminal result, or `None` while the attempt is non-terminal.
    pub outcome: Option<Outcome>,
    /// The durable absolute deadline, set for every action.
    ///
    /// For an [`Action::Onboard`] it is the join-token wrap TTL at mint, so
    /// the expiry clock survives a `REview` restart; the single-use token itself
    /// is never persisted. For the other actions it is a generous absolute
    /// deadline, large enough that a slow link carrying a core-component image
    /// is normal. It exists because the retry budget is advanced only on a
    /// host check-in, so a host that never returns would otherwise leave its
    /// attempt non-terminal forever.
    pub expires_at: DateTime<Utc>,
    /// The id returned by the pre-update `backup::create`, set only for a
    /// core-component update of `REview`.
    pub backup_id: Option<u32>,
    /// The database format version in effect before the swap, set only for a
    /// core-component update of `REview`.
    pub pre_update_version: Option<String>,
}

impl OperationAttempt {
    /// Returns whether the apply has reached a terminal result.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.outcome.is_some()
    }

    /// Returns whether the attempt is terminal and owes no compensation.
    ///
    /// A discharged attempt is finalized in place and retained: the terminal
    /// record is the only thing that can answer whether the last operation
    /// succeeded, failed, or rolled back.
    #[must_use]
    pub fn is_fully_discharged(&self) -> bool {
        self.is_terminal() && self.cleanup_state.is_none()
    }

    /// Returns the key the record is stored under.
    ///
    /// This is deliberately not a [`UniqueKey`](crate::UniqueKey)
    /// implementation: that trait, together with [`Value`](super::Value), is
    /// what admits a record to the generic write API on [`Table`], which
    /// writes the row alone. See the module documentation.
    fn record_key(&self) -> &[u8] {
        self.idempotency_key.as_bytes()
    }

    /// Returns the record's serialized value.
    ///
    /// Private for the same reason as [`OperationAttempt::record_key`].
    fn record_value(&self) -> Vec<u8> {
        let value = Value {
            host: Cow::Borrowed(&self.host),
            target: Cow::Borrowed(&self.target),
            instance: self.instance,
            action: self.action,
            package_digest: Cow::Borrowed(&self.package_digest),
            resolved_version: Cow::Borrowed(&self.resolved_version),
            resolved_commit: Cow::Borrowed(&self.resolved_commit),
            phase: self.phase,
            cleanup_state: self.cleanup_state,
            started_at: self.started_at,
            retry_policy: self.retry_policy,
            outcome: self.outcome,
            expires_at: self.expires_at,
            backup_id: self.backup_id,
            pre_update_version: self.pre_update_version.as_deref().map(Cow::Borrowed),
        };
        super::serialize(&value).expect("serializable")
    }
}

impl FromKeyValue for OperationAttempt {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        if key.is_empty() {
            bail!("an operation attempt key must not be empty");
        }
        let idempotency_key = std::str::from_utf8(key)?.to_string();
        let value: Value = super::deserialize(value)?;

        Ok(Self {
            idempotency_key,
            host: value.host.into_owned(),
            target: value.target.into_owned(),
            instance: value.instance,
            action: value.action,
            package_digest: value.package_digest.into_owned(),
            resolved_version: value.resolved_version.into_owned(),
            resolved_commit: value.resolved_commit.into_owned(),
            phase: value.phase,
            cleanup_state: value.cleanup_state,
            started_at: value.started_at,
            retry_policy: value.retry_policy,
            outcome: value.outcome,
            expires_at: value.expires_at,
            backup_id: value.backup_id,
            pre_update_version: value.pre_update_version.map(Cow::into_owned),
        })
    }
}

/// The stored form of everything but the key.
///
/// The string fields are `Cow` so that a write borrows them from the record
/// and a read owns them, without a second struct whose field order could
/// silently drift from this one: bincode writes no field names, so a field
/// present on one side and missing on the other would be dropped on read
/// rather than rejected.
#[derive(Deserialize, Serialize)]
struct Value<'a> {
    host: Cow<'a, str>,
    target: Cow<'a, str>,
    instance: Option<u32>,
    action: Action,
    package_digest: Cow<'a, str>,
    resolved_version: Cow<'a, str>,
    resolved_commit: Cow<'a, str>,
    phase: Phase,
    cleanup_state: Option<CleanupState>,
    started_at: DateTime<Utc>,
    retry_policy: RetryPolicy,
    outcome: Option<Outcome>,
    expires_at: DateTime<Utc>,
    backup_id: Option<u32>,
    pre_update_version: Option<Cow<'a, str>>,
}

/// What a [`Table::prune`] call keeps.
///
/// Both bounds are required and they are OR'd: a prunable attempt is removed
/// once it exceeds either one, whichever fires first. A caller that does not
/// want one axis to bite passes a value loose enough that it never fires,
/// which keeps every call total.
///
/// Neither bound reaches the attempts the prune keeps unconditionally — the
/// most recent terminal attempt of each `(host, target, instance)` triple, and
/// every attempt that is still non-terminal or still owes a cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionBound {
    /// The greatest age a prunable attempt may reach, measured from its
    /// `started_at` against the instant handed to [`Table::prune`].
    ///
    /// An attempt exactly this old is kept: the bound removes one only once
    /// its age is greater. The measurement is from `started_at` and never from
    /// `expires_at`, which is a per-action deadline and would order attempts
    /// by the policy that set it rather than by when the work happened.
    pub max_age: TimeDelta,
    /// How many terminal attempts one `(host, target, instance)` triple keeps,
    /// counting down from the most recent.
    ///
    /// A triple holding exactly this many terminal attempts loses none of
    /// them: the bound removes only the ones past the count. Every terminal
    /// attempt of the triple is counted, including one that owes a cleanup and
    /// is therefore kept anyway.
    pub max_terminal_per_triple: usize,
}

/// Appends a length-prefixed segment to an index key.
///
/// The length prefix is what makes a composite key unambiguous: without it
/// `("ab", "c")` and `("a", "bc")` would encode to the same bytes.
fn push_segment(key: &mut Vec<u8>, segment: &str) -> Result<()> {
    let len = u32::try_from(segment.len()).context("index key segment is too long")?;
    key.extend_from_slice(&len.to_be_bytes());
    key.extend_from_slice(segment.as_bytes());
    Ok(())
}

/// Appends an instance number, `None` included, in a fixed five bytes.
fn push_instance(key: &mut Vec<u8>, instance: Option<u32>) {
    key.push(u8::from(instance.is_some()));
    key.extend_from_slice(&instance.unwrap_or_default().to_be_bytes());
}

/// Encodes a timestamp so that byte order is time order.
fn timestamp_bytes(at: DateTime<Utc>) -> Vec<u8> {
    let mut seconds = at.timestamp().to_be_bytes();
    if let Some(first) = seconds.first_mut() {
        // Flip the sign bit, so that an instant before the epoch sorts before
        // one after it instead of after every one of them.
        *first ^= 0x80;
    }
    let mut key = Vec::with_capacity(TIMESTAMP_LEN);
    key.extend_from_slice(&seconds);
    key.extend_from_slice(&at.timestamp_subsec_nanos().to_be_bytes());
    key
}

/// The single-flight key of a `(host, target, instance)` triple.
///
/// The instance is part of the key because a host may run several instances of
/// one module: keying on `(host, target)` alone would block adding a second
/// instance while the first one's install is still running.
fn non_terminal_key(host: &str, target: &str, instance: Option<u32>) -> Result<Vec<u8>> {
    let mut key = vec![NON_TERMINAL];
    push_segment(&mut key, host)?;
    push_segment(&mut key, target)?;
    push_instance(&mut key, instance);
    Ok(key)
}

/// The owed-cleanup key space of a `(target, host, instance)` triple.
fn owed_cleanup_prefix(target: &str, host: &str, instance: Option<u32>) -> Result<Vec<u8>> {
    let mut key = vec![OWED_CLEANUP];
    push_segment(&mut key, target)?;
    push_segment(&mut key, host)?;
    push_instance(&mut key, instance);
    Ok(key)
}

/// The owed-cleanup key of one attempt.
///
/// Several attempts may owe a cleanup for one triple, so the idempotency key
/// is part of the key rather than the value alone.
fn owed_cleanup_key(attempt: &OperationAttempt) -> Result<Vec<u8>> {
    let mut key = owed_cleanup_prefix(&attempt.target, &attempt.host, attempt.instance)?;
    push_segment(&mut key, &attempt.idempotency_key)?;
    Ok(key)
}

/// The `expires_at` key of one attempt.
fn expires_at_key(attempt: &OperationAttempt) -> Result<Vec<u8>> {
    let mut key = vec![EXPIRES_AT];
    key.extend_from_slice(&timestamp_bytes(attempt.expires_at));
    push_segment(&mut key, &attempt.idempotency_key)?;
    Ok(key)
}

/// The index entries an attempt owns in the state it is in.
///
/// Every attempt is in the `expires_at` index, whatever its action: the
/// deadline is not an [`Action::Onboard`] affair, and the sweep scans them
/// all.
fn index_keys(attempt: &OperationAttempt) -> Result<Vec<Vec<u8>>> {
    let mut keys = vec![expires_at_key(attempt)?];
    if !attempt.is_terminal() {
        keys.push(non_terminal_key(
            &attempt.host,
            &attempt.target,
            attempt.instance,
        )?);
    }
    if attempt.cleanup_state.is_some() {
        keys.push(owed_cleanup_key(attempt)?);
    }
    Ok(keys)
}

/// Functions for the `operation_attempt` table.
impl<'d> Table<'d, OperationAttempt> {
    /// Opens the `operation_attempt` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    // Allowed as unused because the column family is not in `MAP_NAMES` yet:
    // registering it and adding the `Store` accessor that calls this belong with
    // the database format bump. Until then only the tests below open the table.
    #[allow(dead_code)]
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::OPERATION_ATTEMPTS).map(Table::new)
    }

    /// Returns an iterator over the stored attempts, whose keys are the
    /// idempotency keys in lexicographic order.
    ///
    /// This shadows the blanket [`Iterable::iter`](crate::Iterable)
    /// implementation on [`Table`], whose scan covers the whole column family
    /// and would therefore also yield the index key spaces, which are not
    /// records and do not decode as one.
    #[must_use]
    pub fn iter(
        &self,
        direction: Direction,
        from: Option<&[u8]>,
    ) -> super::TableIter<'_, OperationAttempt> {
        let mut readopts = ReadOptions::default();
        readopts.set_iterate_upper_bound([RESERVED]);
        let mode = match from {
            Some(from) => IteratorMode::From(from, direction),
            None => match direction {
                Direction::Forward => IteratorMode::Start,
                Direction::Reverse => IteratorMode::End,
            },
        };
        super::TableIter::new(self.map.db.iterator_cf_opt(self.map.cf, readopts, mode))
    }

    /// Returns the attempt with the given idempotency key, or `None` if no
    /// such attempt exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored value is invalid or the database
    /// operation fails.
    pub fn get(&self, idempotency_key: &str) -> Result<Option<OperationAttempt>> {
        let key = idempotency_key.as_bytes();
        let Some(value) = self.map.get(key)? else {
            return Ok(None);
        };
        Ok(Some(OperationAttempt::from_key_value(key, value.as_ref())?))
    }

    /// Returns the live attempt for `(host, target, instance)`, or `None` if
    /// the triple has none.
    ///
    /// This is the single-flight guard's read side, and it survives a `REview`
    /// restart because the answer is in the database rather than in process
    /// memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored value is invalid or the database
    /// operation fails.
    pub fn live_attempt(
        &self,
        host: &str,
        target: &str,
        instance: Option<u32>,
    ) -> Result<Option<OperationAttempt>> {
        let key = non_terminal_key(host, target, instance)?;
        let Some(idempotency_key) = self.map.get(&key)? else {
            return Ok(None);
        };
        let idempotency_key = std::str::from_utf8(idempotency_key.as_ref())
            .context("the non-terminal index holds an invalid idempotency key")?;
        self.get(idempotency_key)
    }

    /// Returns every attempt that owes a cleanup for `(target, host,
    /// instance)`, in idempotency-key order.
    ///
    /// A terminal attempt is included: the obligation outlives the outcome,
    /// and this is what "a re-onboard is blocked while a teardown is owed"
    /// reads.
    ///
    /// # Errors
    ///
    /// Returns an error if a stored value is invalid or the database operation
    /// fails.
    pub fn attempts_owing_cleanup(
        &self,
        target: &str,
        host: &str,
        instance: Option<u32>,
    ) -> Result<Vec<OperationAttempt>> {
        let prefix = owed_cleanup_prefix(target, host, instance)?;
        let mut attempts = self.attempts_in_index(&prefix, None)?;
        attempts.sort_unstable_by(|a, b| a.idempotency_key.cmp(&b.idempotency_key));
        Ok(attempts)
    }

    /// Returns every attempt whose deadline had passed at `instant`, the
    /// earliest deadline first.
    ///
    /// The comparison is inclusive: an attempt whose `expires_at` is exactly
    /// `instant` has expired. Terminal attempts are included, because the
    /// index covers every row; [`Table::sweep_expired`] is what acts only on
    /// the non-terminal ones.
    ///
    /// # Errors
    ///
    /// Returns an error if a stored value is invalid or the database operation
    /// fails.
    pub fn expired_attempts(&self, instant: DateTime<Utc>) -> Result<Vec<OperationAttempt>> {
        let cutoff = timestamp_bytes(instant);
        self.attempts_in_index(&[EXPIRES_AT], Some(&cutoff))
    }

    /// Stores an attempt, replacing any attempt already held under the same
    /// idempotency key, and brings every index in line with it.
    ///
    /// A re-drive or a resume therefore finalizes the existing row in place
    /// instead of adding a second row for the same logical operation. The row
    /// and its index entries are written in one transaction, so a row leaves
    /// the non-terminal index in the same write that makes it terminal, and
    /// leaves the owed-cleanup index in the same write that clears its
    /// `cleanup_state`.
    ///
    /// # Errors
    ///
    /// Returns an error if the attempt's idempotency key is empty, if the
    /// attempt is non-terminal and a different attempt is already live for its
    /// `(host, target, instance)` triple, or if the database operation fails.
    ///
    /// An empty key is rejected rather than stored because the shared table
    /// iterator skips one as indexed-table metadata, which would leave an
    /// in-flight or cleanup-owing attempt out of every scan.
    pub fn upsert(&self, attempt: &OperationAttempt) -> Result<()> {
        if attempt.idempotency_key.is_empty() {
            bail!("an operation attempt key must not be empty");
        }
        loop {
            let txn = self.transaction();
            let stored = self.get_for_update(&attempt.idempotency_key, &txn)?;
            self.write_with_transaction(stored.as_ref(), attempt, &txn)?;
            match txn.commit() {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to store the operation attempt");
                    }
                }
            }
        }
    }

    /// Deletes the attempt with the given idempotency key, along with its
    /// index entries.
    ///
    /// This is for a row that should never have existed; a completed attempt
    /// is finalized in place and retained until [`Table::prune`] decides
    /// otherwise, not deleted. The key is not checked for emptiness, so this
    /// stays usable to clear a stray empty-key row that some other writer left
    /// behind.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, idempotency_key: &str) -> Result<()> {
        loop {
            let txn = self.transaction();
            let key = idempotency_key.as_bytes();
            let Some(value) = txn
                .get_for_update_cf(self.map.cf, key, EXCLUSIVE)
                .context("cannot read the operation attempt")?
            else {
                return Ok(());
            };
            // A row that does not decode cannot name its index entries, and
            // leaving them is not an option: the single-flight entry is checked
            // as raw presence, so an orphan holds its triple's slot for good.
            // Reading them back out of the index space costs a scan of it,
            // which is the right trade on a repair path a sound row never
            // reaches.
            let index_keys = match OperationAttempt::from_key_value(key, &value) {
                Ok(attempt) => index_keys(&attempt)?,
                Err(_) => self.index_keys_naming(key)?,
            };
            for index_key in index_keys {
                self.map.delete_with_transaction(&index_key, &txn)?;
            }
            self.map.delete_with_transaction(key, &txn)?;
            match txn.commit() {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to delete the operation attempt");
                    }
                }
            }
        }
    }

    /// Finalizes every non-terminal attempt whose deadline had passed at
    /// `instant`, and returns how many it finalized.
    ///
    /// A finalized attempt gets `outcome = Some(Outcome::Failed)` and nothing
    /// else: `phase`, `retry_policy` and above all `cleanup_state` are left as
    /// they were. Clearing an owed cleanup here is what would orphan a minted
    /// bootroot identity, so the sweep never does it. The attempt leaves the
    /// non-terminal index, which frees the single-flight slot, and stays in
    /// the owed-cleanup index for `review` to discharge once the registrar is
    /// reachable. A host that never returns therefore leaks neither the slot
    /// nor the record of what is still owed.
    ///
    /// `instant` is the caller's, and the sweep reads no clock of its own, so
    /// a second run over already-swept state finalizes nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if a stored value is invalid or the database operation
    /// fails.
    pub fn sweep_expired(&self, instant: DateTime<Utc>) -> Result<usize> {
        loop {
            let txn = self.transaction();
            let mut finalized = 0;
            for expired in self.expired_attempts(instant)? {
                // A row stays in the `expires_at` index once it is finalized,
                // so the whole retained history of a past deadline comes back
                // on every later sweep. Dropping the terminal ones before the
                // lock keeps a sweep from reading and validating each of them
                // again; the re-read below is what actually decides.
                if expired.is_terminal() {
                    continue;
                }
                let Some(stored) = self.get_for_update(&expired.idempotency_key, &txn)? else {
                    continue;
                };
                if stored.is_terminal() || stored.expires_at > instant {
                    continue;
                }
                let mut failed = stored.clone();
                failed.outcome = Some(Outcome::Failed);
                self.write_with_transaction(Some(&stored), &failed, &txn)?;
                finalized += 1;
            }
            match txn.commit() {
                Ok(()) => return Ok(finalized),
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to sweep the expired operation attempts");
                    }
                }
            }
        }
    }

    /// Removes the terminal attempts that `bound` no longer keeps, and returns
    /// how many it removed.
    ///
    /// Two keep-rules come first, and they are a floor rather than a
    /// preference: the most recent terminal attempt of each `(host, target,
    /// instance)` triple is kept however far it is past either bound, and an
    /// attempt that is still non-terminal or still owes a `cleanup_state` is
    /// never removed at all. Only a terminal attempt that is not the most
    /// recent of its triple is ever eligible, and it goes once it exceeds
    /// [`RetentionBound::max_age`] or [`RetentionBound::max_terminal_per_triple`].
    /// An attempt exactly at either bound is kept.
    ///
    /// "Most recent" is the greatest `(started_at, idempotency_key)` pair: the
    /// greatest `started_at`, and on a tie the greater idempotency key, which
    /// is unique and therefore makes the order total. Age is measured from
    /// `started_at` too, never from `expires_at`.
    ///
    /// Every input the outcome depends on is a parameter of the call: the
    /// prune reads no wall clock and no configuration, so running it twice
    /// with the same arguments removes nothing the second time.
    ///
    /// # Errors
    ///
    /// Returns an error if a stored value is invalid or the database operation
    /// fails.
    pub fn prune(&self, bound: RetentionBound, instant: DateTime<Utc>) -> Result<usize> {
        loop {
            let txn = self.transaction();
            let mut removed = 0;
            for attempt in self.prunable(bound, instant)? {
                let Some(stored) = self.get_for_update(&attempt.idempotency_key, &txn)? else {
                    continue;
                };
                if stored != attempt {
                    continue;
                }
                self.remove_with_transaction(&stored, &txn)?;
                removed += 1;
            }
            match txn.commit() {
                Ok(()) => return Ok(removed),
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to prune the operation attempts");
                    }
                }
            }
        }
    }

    /// Returns the terminal attempts that neither keep-rule holds on to and
    /// that exceed `bound`.
    fn prunable(
        &self,
        bound: RetentionBound,
        instant: DateTime<Utc>,
    ) -> Result<Vec<OperationAttempt>> {
        let mut by_triple: HashMap<(String, String, Option<u32>), Vec<OperationAttempt>> =
            HashMap::new();
        for attempt in self.iter(Direction::Forward, None) {
            let attempt = attempt?;
            // A non-terminal attempt is kept whatever the bound says.
            if !attempt.is_terminal() {
                continue;
            }
            by_triple
                .entry((
                    attempt.host.clone(),
                    attempt.target.clone(),
                    attempt.instance,
                ))
                .or_default()
                .push(attempt);
        }

        let mut prunable = Vec::new();
        for mut attempts in by_triple.into_values() {
            // Greatest `(started_at, idempotency_key)` first, so the attempt
            // the first keep-rule holds on to is the one at rank 1.
            attempts.sort_unstable_by(|a, b| {
                b.started_at
                    .cmp(&a.started_at)
                    .then_with(|| b.idempotency_key.cmp(&a.idempotency_key))
            });
            for (index, attempt) in attempts.into_iter().enumerate() {
                let rank = index + 1;
                if rank == 1 || attempt.cleanup_state.is_some() {
                    continue;
                }
                let too_old = instant.signed_duration_since(attempt.started_at) > bound.max_age;
                let too_many = rank > bound.max_terminal_per_triple;
                if too_old || too_many {
                    prunable.push(attempt);
                }
            }
        }
        Ok(prunable)
    }

    /// Reads the rows an index key space points at.
    ///
    /// `cutoff`, where given, stops the scan at the first entry whose
    /// timestamp is past it. The scan runs in key order and the timestamp
    /// leads the key, so nothing beyond that entry is within the cutoff
    /// either.
    fn attempts_in_index(
        &self,
        prefix: &[u8],
        cutoff: Option<&[u8]>,
    ) -> Result<Vec<OperationAttempt>> {
        let mut readopts = ReadOptions::default();
        readopts.set_iterate_range(rocksdb::PrefixRange(prefix));
        let iter = self
            .map
            .db
            .iterator_cf_opt(self.map.cf, readopts, IteratorMode::Start);

        let mut attempts = Vec::new();
        for entry in iter {
            let (key, value) = entry.context("cannot read the index")?;
            if let Some(cutoff) = cutoff {
                let timestamp = key
                    .get(prefix.len()..prefix.len() + TIMESTAMP_LEN)
                    .context("the index holds a key without a timestamp")?;
                if timestamp > cutoff {
                    break;
                }
            }
            let idempotency_key = std::str::from_utf8(&value)
                .context("the index holds an invalid idempotency key")?;
            if let Some(attempt) = self.get(idempotency_key)? {
                attempts.push(attempt);
            }
        }
        Ok(attempts)
    }

    /// Returns every index entry that names `idempotency_key`.
    ///
    /// This scans the whole index space, so it is only for the repair path in
    /// [`Table::delete`], where the row is unreadable and there is nothing
    /// left to derive its entries from. The idempotency key is unique, so no
    /// entry of another row can name it.
    fn index_keys_naming(&self, idempotency_key: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut readopts = ReadOptions::default();
        readopts.set_iterate_lower_bound([RESERVED]);
        let iter = self
            .map
            .db
            .iterator_cf_opt(self.map.cf, readopts, IteratorMode::Start);

        let mut keys = Vec::new();
        for entry in iter {
            let (key, value) = entry.context("cannot read the index")?;
            if value.as_ref() == idempotency_key {
                keys.push(key.to_vec());
            }
        }
        Ok(keys)
    }

    /// Reads an attempt within a transaction, locking its key.
    fn get_for_update(
        &self,
        idempotency_key: &str,
        txn: &Transaction<'_, OptimisticTransactionDB>,
    ) -> Result<Option<OperationAttempt>> {
        let key = idempotency_key.as_bytes();
        let Some(value) = txn
            .get_for_update_cf(self.map.cf, key, EXCLUSIVE)
            .context("cannot read the operation attempt")?
        else {
            return Ok(None);
        };
        Ok(Some(OperationAttempt::from_key_value(key, &value)?))
    }

    /// Writes `new` and brings every index in line with it, dropping whatever
    /// entries `stored` — the row currently held under the same key, if any —
    /// owned and no longer does.
    fn write_with_transaction(
        &self,
        stored: Option<&OperationAttempt>,
        new: &OperationAttempt,
        txn: &Transaction<'_, OptimisticTransactionDB>,
    ) -> Result<()> {
        let keys = index_keys(new)?;
        if let Some(stored) = stored {
            for key in index_keys(stored)? {
                if !keys.contains(&key) {
                    self.map.delete_with_transaction(&key, txn)?;
                }
            }
        }
        // Read after that removal, so that a row moving to another triple, or
        // becoming terminal, is not held up by the slot it is giving up.
        if !new.is_terminal() {
            let key = non_terminal_key(&new.host, &new.target, new.instance)?;
            if let Some(holder) = txn
                .get_for_update_cf(self.map.cf, &key, EXCLUSIVE)
                .context("cannot read the non-terminal index")?
                && holder.as_slice() != new.idempotency_key.as_bytes()
            {
                bail!(
                    "another operation attempt is already live for host {}, target {} and instance {:?}",
                    new.host,
                    new.target,
                    new.instance
                );
            }
        }
        self.map
            .put_with_transaction(new.record_key(), &new.record_value(), txn)?;
        for key in keys {
            self.map
                .put_with_transaction(&key, new.idempotency_key.as_bytes(), txn)?;
        }
        Ok(())
    }

    /// Deletes an attempt and every index entry it owns.
    fn remove_with_transaction(
        &self,
        attempt: &OperationAttempt,
        txn: &Transaction<'_, OptimisticTransactionDB>,
    ) -> Result<()> {
        for key in index_keys(attempt)? {
            self.map.delete_with_transaction(&key, txn)?;
        }
        self.map
            .delete_with_transaction(attempt.idempotency_key.as_bytes(), txn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::{DbGuard, acquire_db_permit};

    const HOST: &str = "host-a.example";
    const TARGET: &str = "piglet";

    const ACTIONS: [Action; 4] = [
        Action::Install,
        Action::Update,
        Action::Remove,
        Action::Onboard,
    ];
    const PHASES: [Phase; 4] = [
        Phase::Pending,
        Phase::Dispatched,
        Phase::AwaitingReport,
        Phase::Completed,
    ];
    const CLEANUP_STATES: [CleanupState; 2] = [
        CleanupState::PendingDeregister,
        CleanupState::PendingIdentityTeardown,
    ];
    const OUTCOMES: [Outcome; 4] = [
        Outcome::Succeeded,
        Outcome::Failed,
        Outcome::RolledBack,
        Outcome::Cancelled,
    ];

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
            column_families.push(super::super::OPERATION_ATTEMPTS);
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

        fn table(&self) -> Table<'_, OperationAttempt> {
            Table::<OperationAttempt>::open(&self.db).unwrap()
        }

        /// Every key in the column family, the index entries included.
        fn raw_keys(&self) -> Vec<Vec<u8>> {
            let cf = self.db.cf_handle(super::super::OPERATION_ATTEMPTS).unwrap();
            self.db
                .iterator_cf(cf, IteratorMode::Start)
                .map(|entry| entry.unwrap().0.to_vec())
                .collect()
        }
    }

    fn timestamp(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    /// A module attempt: the instance dimension applies, so it is recorded.
    fn module_attempt(idempotency_key: &str) -> OperationAttempt {
        OperationAttempt {
            idempotency_key: idempotency_key.to_string(),
            host: "host-a.example".to_string(),
            target: "sensor".to_string(),
            instance: Some(1),
            action: Action::Install,
            package_digest: "sha256:aaa".to_string(),
            resolved_version: "1.2.3".to_string(),
            resolved_commit: "c0ffee".to_string(),
            phase: Phase::Pending,
            cleanup_state: None,
            started_at: timestamp(1_700_000_000),
            retry_policy: RetryPolicy {
                max_attempts: 5,
                attempts_made: 0,
                backoff_seconds: 30,
            },
            outcome: None,
            expires_at: timestamp(1_700_086_400),
            backup_id: None,
            pre_update_version: None,
        }
    }

    /// A core-component attempt: its class has no instance dimension.
    fn core_attempt(idempotency_key: &str) -> OperationAttempt {
        OperationAttempt {
            idempotency_key: idempotency_key.to_string(),
            host: "host-b.example".to_string(),
            target: "review".to_string(),
            instance: None,
            action: Action::Update,
            package_digest: "sha256:bbb".to_string(),
            resolved_version: "0.47.0".to_string(),
            resolved_commit: "deadbeef".to_string(),
            phase: Phase::Dispatched,
            cleanup_state: None,
            started_at: timestamp(1_700_000_100),
            retry_policy: RetryPolicy {
                max_attempts: 3,
                attempts_made: 1,
                backoff_seconds: 60,
            },
            outcome: None,
            expires_at: timestamp(1_700_100_000),
            backup_id: None,
            pre_update_version: None,
        }
    }

    /// An onboarding attempt: no package yet, so every package-scoped field is
    /// the empty string.
    fn onboard_attempt(idempotency_key: &str) -> OperationAttempt {
        OperationAttempt {
            idempotency_key: idempotency_key.to_string(),
            host: "pending.example".to_string(),
            target: String::new(),
            instance: None,
            action: Action::Onboard,
            package_digest: String::new(),
            resolved_version: String::new(),
            resolved_commit: String::new(),
            phase: Phase::Pending,
            cleanup_state: Some(CleanupState::PendingIdentityTeardown),
            started_at: timestamp(1_700_000_200),
            retry_policy: RetryPolicy {
                max_attempts: 1,
                attempts_made: 0,
                backoff_seconds: 0,
            },
            outcome: None,
            expires_at: timestamp(1_700_003_800),
            backup_id: None,
            pre_update_version: None,
        }
    }

    /// A live attempt on the given triple.
    fn live_attempt(
        idempotency_key: &str,
        host: &str,
        target: &str,
        instance: Option<u32>,
    ) -> OperationAttempt {
        let mut attempt = module_attempt(idempotency_key);
        attempt.host = host.to_string();
        attempt.target = target.to_string();
        attempt.instance = instance;
        attempt
    }

    /// A terminal attempt on the given triple, with `started_at` and
    /// `expires_at` set apart so that a test can tell which of the two an
    /// implementation ordered by.
    fn terminal_attempt(
        idempotency_key: &str,
        host: &str,
        target: &str,
        instance: Option<u32>,
        started_at: i64,
        expires_at: i64,
    ) -> OperationAttempt {
        let mut attempt = live_attempt(idempotency_key, host, target, instance);
        attempt.phase = Phase::Completed;
        attempt.outcome = Some(Outcome::Succeeded);
        attempt.started_at = timestamp(started_at);
        attempt.expires_at = timestamp(expires_at);
        attempt
    }

    fn bound(max_age_seconds: i64, max_terminal_per_triple: usize) -> RetentionBound {
        RetentionBound {
            max_age: TimeDelta::seconds(max_age_seconds),
            max_terminal_per_triple,
        }
    }

    fn round_trip(attempt: &OperationAttempt) -> OperationAttempt {
        OperationAttempt::from_key_value(attempt.record_key(), &attempt.record_value()).unwrap()
    }

    fn keys(
        table: &Table<'_, OperationAttempt>,
        direction: Direction,
        from: Option<&[u8]>,
    ) -> Vec<String> {
        table
            .iter(direction, from)
            .map(|attempt| attempt.map(|attempt| attempt.idempotency_key))
            .collect::<Result<Vec<_>>>()
            .unwrap()
    }

    #[test]
    fn keys_by_idempotency_key_alone() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let first = module_attempt("op-1");
        table.upsert(&first).unwrap();

        // The same logical operation, re-driven with new field values.
        let mut second = first.clone();
        second.host = "host-z.example".to_string();
        second.phase = Phase::Completed;
        second.outcome = Some(Outcome::Succeeded);
        second.retry_policy.attempts_made = 2;
        table.upsert(&second).unwrap();

        let stored = table
            .iter(Direction::Forward, None)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(stored, vec![second.clone()]);
        assert_eq!(table.get("op-1").unwrap(), Some(second));

        assert_eq!(table.get("op-missing").unwrap(), None);
        table.delete("op-1").unwrap();
        assert_eq!(table.get("op-1").unwrap(), None);
        // The row's index entries go with it, leaving nothing behind.
        assert!(test_db.raw_keys().is_empty());
    }

    #[test]
    fn records_the_instance_without_allocating_it() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let module = module_attempt("op-module");
        let core = core_attempt("op-core");
        table.upsert(&module).unwrap();
        table.upsert(&core).unwrap();

        assert_eq!(table.get("op-module").unwrap().unwrap().instance, Some(1));
        assert_eq!(table.get("op-core").unwrap().unwrap().instance, None);
        assert_eq!(round_trip(&module), module);
        assert_eq!(round_trip(&core), core);
    }

    #[test]
    fn onboard_attempt_leaves_every_package_field_empty() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let onboard = onboard_attempt("op-onboard");
        table.upsert(&onboard).unwrap();

        let stored = table.get("op-onboard").unwrap().unwrap();
        assert_eq!(stored, onboard);
        assert_eq!(stored.action, Action::Onboard);
        assert!(stored.target.is_empty());
        assert!(stored.package_digest.is_empty());
        assert!(stored.resolved_version.is_empty());
        assert!(stored.resolved_commit.is_empty());
        assert_eq!(stored.instance, None);
        assert_eq!(stored.expires_at, timestamp(1_700_003_800));
    }

    #[test]
    fn core_update_backup_fields_are_set_or_unset_together() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let mut with_backup = core_attempt("op-review-update");
        with_backup.backup_id = Some(7);
        with_backup.pre_update_version = Some("0.46.0".to_string());
        let without_backup = module_attempt("op-plain");

        for attempt in [&with_backup, &without_backup] {
            assert_eq!(
                attempt.backup_id.is_some(),
                attempt.pre_update_version.is_some()
            );
            table.upsert(attempt).unwrap();
            assert_eq!(
                table.get(&attempt.idempotency_key).unwrap().as_ref(),
                Some(attempt)
            );
            assert_eq!(round_trip(attempt), *attempt);
        }
    }

    #[test]
    fn distinguishes_hosts_and_commits_of_the_same_target() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let mut on_host_a = module_attempt("op-host-a");
        on_host_a.host = "host-a.example".to_string();
        let mut on_host_b = module_attempt("op-host-b");
        on_host_b.host = "host-b.example".to_string();

        // Finished attempts: one triple holds at most one live attempt, and
        // `op-host-a` already holds this one.
        let mut first_commit = module_attempt("op-commit-1");
        first_commit.resolved_commit = "1111111".to_string();
        first_commit.outcome = Some(Outcome::Succeeded);
        let mut second_commit = module_attempt("op-commit-2");
        second_commit.resolved_commit = "2222222".to_string();
        second_commit.outcome = Some(Outcome::Succeeded);

        for attempt in [&on_host_a, &on_host_b, &first_commit, &second_commit] {
            table.upsert(attempt).unwrap();
        }

        assert_eq!(on_host_a.target, on_host_b.target);
        assert_eq!(
            table.get("op-host-a").unwrap().unwrap().host,
            "host-a.example"
        );
        assert_eq!(
            table.get("op-host-b").unwrap().unwrap().host,
            "host-b.example"
        );

        assert_eq!(
            first_commit.resolved_version,
            second_commit.resolved_version
        );
        assert_eq!(
            table.get("op-commit-1").unwrap().unwrap().resolved_commit,
            "1111111"
        );
        assert_eq!(
            table.get("op-commit-2").unwrap().unwrap().resolved_commit,
            "2222222"
        );

        assert_eq!(
            keys(&table, Direction::Forward, None),
            ["op-commit-1", "op-commit-2", "op-host-a", "op-host-b"],
            "four distinct idempotency keys must yield four rows, in key order"
        );
    }

    #[test]
    fn iterates_in_key_order_from_either_end_and_from_a_seek_key() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // Each on its own instance, because one triple holds at most one live
        // attempt.
        for (instance, key) in ["op-1", "op-2", "op-3"].into_iter().enumerate() {
            let mut attempt = module_attempt(key);
            attempt.instance = u32::try_from(instance).ok();
            table.upsert(&attempt).unwrap();
        }

        assert_eq!(
            keys(&table, Direction::Reverse, None),
            ["op-3", "op-2", "op-1"]
        );
        // A resumed scan seeks to a key, and the key it seeks to is included.
        assert_eq!(
            keys(&table, Direction::Forward, Some(b"op-2")),
            ["op-2", "op-3"]
        );
        assert_eq!(
            keys(&table, Direction::Reverse, Some(b"op-2")),
            ["op-2", "op-1"]
        );
        // A key that was never written seeks to the next one in the direction
        // of travel, so a scan resuming past a deleted row does not stall.
        assert_eq!(keys(&table, Direction::Forward, Some(b"op-25")), ["op-3"]);
    }

    #[test]
    fn reports_an_undecodable_value_and_tolerates_a_missing_key() {
        let test_db = TestDb::new();
        let table = test_db.table();

        table.map.put(b"op-corrupt", b"not a stored value").unwrap();
        assert!(table.get("op-corrupt").is_err());

        // Deleting a key that was never written is not an error, so a re-driven
        // cleanup need not check first.
        table.delete("op-never-written").unwrap();
    }

    #[test]
    fn deleting_an_undecodable_row_takes_its_index_entries_with_it() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let mut attempt = live_attempt("op-1", HOST, TARGET, Some(1));
        attempt.cleanup_state = Some(CleanupState::PendingDeregister);
        table.upsert(&attempt).unwrap();
        // Corrupt the row in place, leaving its three index entries behind.
        table.map.put(b"op-1", b"not a stored value").unwrap();

        table.delete("op-1").unwrap();
        assert_eq!(table.get("op-1").unwrap(), None);
        // Nothing of it is left, the single-flight entry included: an orphaned
        // one is checked as raw presence, so it would hold the triple's slot
        // against every later attempt while `live_attempt` reported it free.
        assert!(test_db.raw_keys().is_empty());
        assert_eq!(table.live_attempt(HOST, TARGET, Some(1)).unwrap(), None);
        table
            .upsert(&live_attempt("op-2", HOST, TARGET, Some(1)))
            .unwrap();
    }

    #[test]
    fn rejects_an_empty_idempotency_key() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let empty_key = module_attempt("");
        assert!(table.upsert(&empty_key).is_err());
        assert_eq!(table.iter(Direction::Forward, None).count(), 0);

        // Why the write path rejects it rather than storing an odd-looking row:
        // the shared iterator reads an empty key as indexed-table metadata and
        // skips it, so an attempt stored under one would be invisible to every
        // scan this ledger exists to support, including the owed-cleanup scan.
        table.map.put(b"", &empty_key.record_value()).unwrap();
        assert_eq!(table.iter(Direction::Forward, None).count(), 0);
        assert!(table.get("").is_err());

        // A real row alongside it still reads back, and the stray one stays
        // absent from the scan until `delete` clears it.
        table.upsert(&module_attempt("op-1")).unwrap();
        assert_eq!(keys(&table, Direction::Forward, None), ["op-1"]);
        table.delete("").unwrap();
        assert_eq!(table.get("").unwrap(), None);
    }

    #[test]
    fn reports_a_key_that_is_not_an_idempotency_key() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // `get` cannot reach this, because its key comes from a `&str`;
        // iteration is the one path that hands `from_key_value` raw bytes.
        // Below the reserved space, so the scan still reaches it: a key from
        // `RESERVED` up belongs to an index and is not read as a record.
        let attempt = module_attempt("op-1");
        table.map.put(b"op-\xff", &attempt.record_value()).unwrap();

        assert!(
            table
                .iter(Direction::Forward, None)
                .collect::<Result<Vec<_>>>()
                .is_err()
        );
    }

    #[test]
    fn every_variant_round_trips() {
        let mut attempt = module_attempt("op-variants");

        for action in ACTIONS {
            attempt.action = action;
            assert_eq!(round_trip(&attempt).action, action);
        }
        for phase in PHASES {
            attempt.phase = phase;
            assert_eq!(round_trip(&attempt).phase, phase);
        }
        for cleanup_state in CLEANUP_STATES.map(Some).into_iter().chain([None]) {
            attempt.cleanup_state = cleanup_state;
            assert_eq!(round_trip(&attempt).cleanup_state, cleanup_state);
        }
        for outcome in OUTCOMES.map(Some).into_iter().chain([None]) {
            attempt.outcome = outcome;
            assert_eq!(round_trip(&attempt).outcome, outcome);
        }
        for retry_policy in [
            RetryPolicy {
                max_attempts: 5,
                attempts_made: 0,
                backoff_seconds: 30,
            },
            RetryPolicy {
                max_attempts: 5,
                attempts_made: 3,
                backoff_seconds: 30,
            },
        ] {
            attempt.retry_policy = retry_policy;
            assert_eq!(round_trip(&attempt).retry_policy, retry_policy);
        }
    }

    #[test]
    fn terminality_tracks_outcome_and_discharge_tracks_cleanup() {
        let mut attempt = module_attempt("op-terminality");
        assert!(!attempt.is_terminal());
        assert!(!attempt.is_fully_discharged());

        attempt.cleanup_state = Some(CleanupState::PendingDeregister);
        assert!(!attempt.is_terminal());
        assert!(!attempt.is_fully_discharged());

        // A failed apply may still owe compensation: the obligation is not
        // bounded by the retry budget.
        attempt.outcome = Some(Outcome::Failed);
        assert!(attempt.is_terminal());
        assert!(!attempt.is_fully_discharged());

        attempt.cleanup_state = None;
        assert!(attempt.is_terminal());
        assert!(attempt.is_fully_discharged());
    }

    #[test]
    fn finalizing_in_place_preserves_identity_and_resolved_build() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let started = module_attempt("op-finalize");
        table.upsert(&started).unwrap();

        let mut finalized = table.get("op-finalize").unwrap().unwrap();
        finalized.phase = Phase::Completed;
        finalized.outcome = Some(Outcome::Succeeded);
        finalized.retry_policy.attempts_made = 1;
        table.upsert(&finalized).unwrap();

        let stored = table.get("op-finalize").unwrap().unwrap();
        assert_eq!(stored.idempotency_key, started.idempotency_key);
        assert_eq!(stored.started_at, started.started_at);
        assert_eq!(stored.resolved_version, started.resolved_version);
        assert_eq!(stored.resolved_commit, started.resolved_commit);
        assert_eq!(stored.package_digest, started.package_digest);
        assert_eq!(stored.outcome, Some(Outcome::Succeeded));
        assert!(stored.is_fully_discharged());
        assert_eq!(table.iter(Direction::Forward, None).count(), 1);
    }
    #[test]
    fn refuses_a_second_live_attempt_for_one_triple() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let first = live_attempt("op-1", HOST, TARGET, Some(1));
        table.upsert(&first).unwrap();
        assert_eq!(
            table.live_attempt(HOST, TARGET, Some(1)).unwrap(),
            Some(first.clone())
        );

        let second = live_attempt("op-2", HOST, TARGET, Some(1));
        assert!(table.upsert(&second).is_err());
        assert_eq!(table.get("op-2").unwrap(), None);

        // Re-driving the attempt that holds the slot is not a second attempt.
        let mut redriven = first;
        redriven.phase = Phase::Dispatched;
        table.upsert(&redriven).unwrap();

        // The slot is free the moment its holder becomes terminal.
        let mut finished = redriven;
        finished.outcome = Some(Outcome::Succeeded);
        table.upsert(&finished).unwrap();
        assert_eq!(table.live_attempt(HOST, TARGET, Some(1)).unwrap(), None);

        table.upsert(&second).unwrap();
        assert_eq!(
            table.live_attempt(HOST, TARGET, Some(1)).unwrap(),
            Some(second)
        );
        assert_eq!(keys(&table, Direction::Forward, None), ["op-1", "op-2"]);
    }

    #[test]
    fn refuses_a_second_live_attempt_racing_the_first() {
        // The guard is a read of the index entry inside the write's own
        // transaction, so it is the commit that has to reject the loser. A
        // check outside the transaction would let two racing writers both pass
        // it, which is the double-click this table exists to stop.
        for round in 0..8 {
            let test_db = TestDb::new();
            let accepted = std::sync::atomic::AtomicUsize::new(0);
            std::thread::scope(|scope| {
                for n in 0..4 {
                    let db = &test_db.db;
                    let accepted = &accepted;
                    scope.spawn(move || {
                        let table = Table::<OperationAttempt>::open(db).unwrap();
                        let attempt = live_attempt(&format!("op-{n}"), HOST, TARGET, Some(1));
                        if table.upsert(&attempt).is_ok() {
                            accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    });
                }
            });

            let table = test_db.table();
            assert_eq!(
                accepted.load(std::sync::atomic::Ordering::Relaxed),
                1,
                "round {round}: more than one racing writer took the slot"
            );
            assert!(table.live_attempt(HOST, TARGET, Some(1)).unwrap().is_some());
            // The refused writers left no row behind either.
            assert_eq!(keys(&table, Direction::Forward, None).len(), 1);
        }
    }

    #[test]
    fn a_second_instance_installs_while_the_first_one_is_running() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let first = live_attempt("op-1", HOST, TARGET, Some(1));
        let second = live_attempt("op-2", HOST, TARGET, Some(2));
        // A core component's class has no instance dimension. `None` is a slot
        // of its own, not a wildcard over the numbered ones.
        let core = live_attempt("op-3", HOST, TARGET, None);
        for attempt in [&first, &second, &core] {
            table.upsert(attempt).unwrap();
        }

        assert_eq!(
            table.live_attempt(HOST, TARGET, Some(1)).unwrap(),
            Some(first)
        );
        assert_eq!(
            table.live_attempt(HOST, TARGET, Some(2)).unwrap(),
            Some(second)
        );
        assert_eq!(table.live_attempt(HOST, TARGET, None).unwrap(), Some(core));
        assert_eq!(table.live_attempt(HOST, TARGET, Some(3)).unwrap(), None);
    }

    #[test]
    fn two_hosts_run_the_same_target_at_once() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let here = live_attempt("op-1", HOST, TARGET, Some(1));
        let there = live_attempt("op-2", "host-b.example", TARGET, Some(1));
        table.upsert(&here).unwrap();
        table.upsert(&there).unwrap();

        assert_eq!(
            table.live_attempt(HOST, TARGET, Some(1)).unwrap(),
            Some(here)
        );
        assert_eq!(
            table
                .live_attempt("host-b.example", TARGET, Some(1))
                .unwrap(),
            Some(there)
        );
    }

    #[test]
    fn finalizes_an_attempt_whose_host_never_returned() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let mut attempt = live_attempt("op-install", HOST, TARGET, Some(1));
        attempt.action = Action::Install;
        attempt.started_at = timestamp(1_700_000_000);
        attempt.expires_at = timestamp(1_700_000_500);
        attempt.cleanup_state = Some(CleanupState::PendingIdentityTeardown);
        table.upsert(&attempt).unwrap();

        let instant = timestamp(1_700_000_501);
        assert_eq!(
            table.expired_attempts(instant).unwrap(),
            vec![attempt.clone()]
        );
        assert_eq!(table.sweep_expired(instant).unwrap(), 1);

        let swept = table.get("op-install").unwrap().unwrap();
        assert_eq!(swept.outcome, Some(Outcome::Failed));
        // The sweep records the outcome and nothing else.
        assert_eq!(swept.phase, attempt.phase);
        assert_eq!(swept.retry_policy, attempt.retry_policy);
        assert_eq!(swept.expires_at, attempt.expires_at);

        // The single-flight slot is free again ...
        assert_eq!(table.live_attempt(HOST, TARGET, Some(1)).unwrap(), None);
        // ... and the minted identity is still recorded as owed a teardown.
        assert_eq!(
            swept.cleanup_state,
            Some(CleanupState::PendingIdentityTeardown)
        );
        assert_eq!(
            table.attempts_owing_cleanup(TARGET, HOST, Some(1)).unwrap(),
            vec![swept.clone()]
        );

        // Running the sweep again over swept state finalizes nothing.
        assert_eq!(table.sweep_expired(instant).unwrap(), 0);
        assert_eq!(table.get("op-install").unwrap(), Some(swept));
    }

    #[test]
    fn leaves_a_deadline_that_has_not_passed_alone() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // Real time is years past these instants, so a sweep reading a clock
        // of its own would finalize this attempt on the first call.
        let mut attempt = live_attempt("op-1", HOST, TARGET, Some(1));
        attempt.expires_at = timestamp(1_700_000_500);
        table.upsert(&attempt).unwrap();

        assert!(
            table
                .expired_attempts(timestamp(1_700_000_499))
                .unwrap()
                .is_empty()
        );
        assert_eq!(table.sweep_expired(timestamp(1_700_000_499)).unwrap(), 0);
        assert_eq!(table.get("op-1").unwrap(), Some(attempt));

        // A deadline reached exactly has passed.
        assert_eq!(table.sweep_expired(timestamp(1_700_000_500)).unwrap(), 1);
        assert_eq!(
            table.get("op-1").unwrap().unwrap().outcome,
            Some(Outcome::Failed)
        );
    }

    #[test]
    fn an_onboard_attempt_expires_by_the_same_path_as_an_install() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let onboard = onboard_attempt("op-onboard");
        let mut install = live_attempt("op-install", HOST, TARGET, Some(1));
        install.action = Action::Install;
        install.expires_at = onboard.expires_at;
        table.upsert(&onboard).unwrap();
        table.upsert(&install).unwrap();

        // The deadline belongs to every action, so one sweep takes both.
        assert_eq!(table.sweep_expired(onboard.expires_at).unwrap(), 2);
        for key in ["op-onboard", "op-install"] {
            assert_eq!(
                table.get(key).unwrap().unwrap().outcome,
                Some(Outcome::Failed)
            );
        }
        assert_eq!(
            table.get("op-onboard").unwrap().unwrap().cleanup_state,
            Some(CleanupState::PendingIdentityTeardown)
        );
    }

    #[test]
    fn owed_cleanup_lookup_follows_the_cleanup_state() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let mut owing = live_attempt("op-owing", HOST, TARGET, Some(1));
        owing.cleanup_state = Some(CleanupState::PendingDeregister);
        let owes_nothing = live_attempt("op-clear", HOST, TARGET, Some(2));
        let mut terminal_owing =
            terminal_attempt("op-terminal", HOST, TARGET, Some(3), 1_000, 9_000);
        terminal_owing.cleanup_state = Some(CleanupState::PendingIdentityTeardown);
        for attempt in [&owing, &owes_nothing, &terminal_owing] {
            table.upsert(attempt).unwrap();
        }

        assert_eq!(
            table.attempts_owing_cleanup(TARGET, HOST, Some(1)).unwrap(),
            vec![owing.clone()]
        );
        assert!(
            table
                .attempts_owing_cleanup(TARGET, HOST, Some(2))
                .unwrap()
                .is_empty()
        );
        // The obligation outlives the outcome, so a terminal row is listed.
        assert_eq!(
            table.attempts_owing_cleanup(TARGET, HOST, Some(3)).unwrap(),
            vec![terminal_owing]
        );

        // Clearing the cleanup drops the row from the index.
        owing.cleanup_state = None;
        table.upsert(&owing).unwrap();
        assert!(
            table
                .attempts_owing_cleanup(TARGET, HOST, Some(1))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn index_keys_never_collide_with_record_keys() {
        // `("ab", "c")` and `("a", "bc")` are the pair a naive concatenation
        // collides on.
        assert_ne!(
            non_terminal_key("ab", "c", Some(1)).unwrap(),
            non_terminal_key("a", "bc", Some(1)).unwrap()
        );
        assert_ne!(
            owed_cleanup_prefix("ab", "c", Some(1)).unwrap(),
            owed_cleanup_prefix("a", "bc", Some(1)).unwrap()
        );

        let test_db = TestDb::new();
        let table = test_db.table();

        let mut first = live_attempt("op-ab-c", "ab", "c", Some(1));
        first.cleanup_state = Some(CleanupState::PendingDeregister);
        let mut second = live_attempt("op-a-bc", "a", "bc", Some(1));
        second.cleanup_state = Some(CleanupState::PendingDeregister);
        table.upsert(&first).unwrap();
        table.upsert(&second).unwrap();

        assert_eq!(
            table.live_attempt("ab", "c", Some(1)).unwrap(),
            Some(first.clone())
        );
        assert_eq!(
            table.live_attempt("a", "bc", Some(1)).unwrap(),
            Some(second.clone())
        );
        assert_eq!(
            table.attempts_owing_cleanup("c", "ab", Some(1)).unwrap(),
            vec![first]
        );
        assert_eq!(
            table.attempts_owing_cleanup("bc", "a", Some(1)).unwrap(),
            vec![second]
        );

        // The column family holds four keys for each attempt — the row, and
        // its three index entries — and iterating the records yields the two
        // rows alone.
        assert_eq!(
            keys(&table, Direction::Forward, None),
            ["op-a-bc", "op-ab-c"]
        );
        let raw = test_db.raw_keys();
        assert_eq!(raw.len(), 8);
        for key in raw {
            assert!(
                key == b"op-a-bc" || key == b"op-ab-c" || key.first() >= Some(&RESERVED),
                "a key is neither a record nor in the reserved index space: {key:?}"
            );
        }
    }

    #[test]
    fn retention_keeps_the_greatest_started_at_not_the_greatest_deadline() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // `started_at` ascending, `expires_at` deliberately the other way
        // round, so an implementation ordering by the deadline keeps the wrong
        // attempt.
        let oldest = terminal_attempt("op-1", HOST, TARGET, Some(1), 1_000, 9_000);
        let middle = terminal_attempt("op-2", HOST, TARGET, Some(1), 2_000, 8_000);
        let newest = terminal_attempt("op-3", HOST, TARGET, Some(1), 3_000, 7_000);
        for attempt in [&oldest, &middle, &newest] {
            table.upsert(attempt).unwrap();
        }

        // A bound no attempt is within, so only the keep-rule decides.
        assert_eq!(table.prune(bound(0, 0), timestamp(10_000)).unwrap(), 2);
        assert_eq!(keys(&table, Direction::Forward, None), ["op-3"]);
        // The pruned rows take their index entries with them, leaving the
        // survivor's row and its `expires_at` entry.
        assert_eq!(test_db.raw_keys().len(), 2);
    }

    #[test]
    fn retention_breaks_a_started_at_tie_on_the_greater_key() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let lesser = terminal_attempt("op-a", HOST, TARGET, Some(1), 1_000, 9_000);
        let greater = terminal_attempt("op-b", HOST, TARGET, Some(1), 1_000, 5_000);
        table.upsert(&lesser).unwrap();
        table.upsert(&greater).unwrap();

        assert_eq!(table.prune(bound(0, 0), timestamp(10_000)).unwrap(), 1);
        assert_eq!(keys(&table, Direction::Forward, None), ["op-b"]);
    }

    #[test]
    fn retention_keeps_one_terminal_attempt_for_each_triple() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let mut owing = terminal_attempt("op-owing", HOST, TARGET, Some(8), 1_000, 9_000);
        owing.cleanup_state = Some(CleanupState::PendingDeregister);
        let attempts = [
            terminal_attempt("op-1-old", HOST, TARGET, Some(1), 1_000, 9_000),
            terminal_attempt("op-1-new", HOST, TARGET, Some(1), 2_000, 9_000),
            // A second instance of the same module on the same host keeps its
            // own record rather than collapsing into its sibling's.
            terminal_attempt("op-2-old", HOST, TARGET, Some(2), 1_000, 9_000),
            terminal_attempt("op-2-new", HOST, TARGET, Some(2), 2_000, 9_000),
            terminal_attempt("op-h2-old", "host-b.example", TARGET, Some(1), 1_000, 9_000),
            terminal_attempt("op-h2-new", "host-b.example", TARGET, Some(1), 2_000, 9_000),
            live_attempt("op-live", HOST, TARGET, Some(9)),
            owing,
            terminal_attempt("op-owing-newer", HOST, TARGET, Some(8), 2_000, 9_000),
        ];
        for attempt in &attempts {
            table.upsert(attempt).unwrap();
        }

        assert_eq!(table.prune(bound(0, 0), timestamp(10_000)).unwrap(), 3);
        assert_eq!(
            keys(&table, Direction::Forward, None),
            [
                "op-1-new",
                "op-2-new",
                "op-h2-new",
                "op-live",
                "op-owing",
                "op-owing-newer",
            ]
        );
    }

    #[test]
    fn retention_prunes_on_the_age_bound_alone() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // `expires_at` runs against `started_at`, so an age measured from the
        // deadline would pick the other pair.
        let attempts = [
            terminal_attempt("op-1", HOST, TARGET, Some(1), 1_000, 7_000),
            terminal_attempt("op-2", HOST, TARGET, Some(1), 2_000, 6_000),
            terminal_attempt("op-3", HOST, TARGET, Some(1), 2_500, 5_000),
            terminal_attempt("op-4", HOST, TARGET, Some(1), 3_000, 4_000),
        ];
        for attempt in &attempts {
            table.upsert(attempt).unwrap();
        }

        // At the boundary: `op-3` is exactly 1,000 seconds old and stays;
        // `op-2` and `op-1` are older and go. The count bound never fires.
        assert_eq!(table.prune(bound(1_000, 10), timestamp(3_500)).unwrap(), 2);
        assert_eq!(keys(&table, Direction::Forward, None), ["op-3", "op-4"]);
    }

    #[test]
    fn retention_prunes_on_the_count_bound_alone() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let attempts = [
            terminal_attempt("op-1", HOST, TARGET, Some(1), 1_000, 9_000),
            terminal_attempt("op-2", HOST, TARGET, Some(1), 2_000, 9_000),
            terminal_attempt("op-3", HOST, TARGET, Some(1), 3_000, 9_000),
            terminal_attempt("op-4", HOST, TARGET, Some(1), 4_000, 9_000),
            // A triple holding exactly the count loses none of its attempts.
            terminal_attempt("op-5", HOST, TARGET, Some(2), 1_000, 9_000),
            terminal_attempt("op-6", HOST, TARGET, Some(2), 2_000, 9_000),
        ];
        for attempt in &attempts {
            table.upsert(attempt).unwrap();
        }

        // The age bound never fires.
        assert_eq!(
            table.prune(bound(1_000_000, 2), timestamp(5_000)).unwrap(),
            2
        );
        assert_eq!(
            keys(&table, Direction::Forward, None),
            ["op-3", "op-4", "op-5", "op-6"]
        );
    }

    #[test]
    fn retention_prunes_the_union_when_both_bounds_fire() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let attempts = [
            terminal_attempt("op-1", HOST, TARGET, Some(1), 2_000, 9_000),
            terminal_attempt("op-2", HOST, TARGET, Some(1), 3_000, 9_000),
            terminal_attempt("op-3", HOST, TARGET, Some(1), 3_500, 9_000),
            terminal_attempt("op-4", HOST, TARGET, Some(1), 4_000, 9_000),
        ];
        for attempt in &attempts {
            table.upsert(attempt).unwrap();
        }

        // At an instant of 5,000 the age bound catches `op-2` (2,000 seconds
        // old) and `op-1` (3,000), while the count bound catches `op-1` alone.
        // What goes is the union of the two, not their intersection.
        assert_eq!(table.prune(bound(1_800, 3), timestamp(5_000)).unwrap(), 2);
        assert_eq!(keys(&table, Direction::Forward, None), ["op-3", "op-4"]);
    }

    #[test]
    fn retention_prunes_nothing_when_neither_bound_fires() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let attempts = [
            terminal_attempt("op-1", HOST, TARGET, Some(1), 1_000, 9_000),
            terminal_attempt("op-2", HOST, TARGET, Some(1), 2_000, 9_000),
            terminal_attempt("op-3", HOST, TARGET, Some(1), 3_000, 9_000),
        ];
        for attempt in &attempts {
            table.upsert(attempt).unwrap();
        }

        assert_eq!(
            table.prune(bound(1_000_000, 10), timestamp(5_000)).unwrap(),
            0
        );
        assert_eq!(
            keys(&table, Direction::Forward, None),
            ["op-1", "op-2", "op-3"]
        );
    }

    #[test]
    fn retention_keep_rules_beat_the_bound() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let mut owing = terminal_attempt("op-owing", HOST, TARGET, Some(3), 1_000, 9_000);
        owing.cleanup_state = Some(CleanupState::PendingIdentityTeardown);
        let attempts = [
            terminal_attempt("op-newest", HOST, TARGET, Some(1), 1_000, 9_000),
            live_attempt("op-live", HOST, TARGET, Some(2)),
            owing,
            terminal_attempt("op-owing-newer", HOST, TARGET, Some(3), 2_000, 9_000),
        ];
        for attempt in &attempts {
            table.upsert(attempt).unwrap();
        }

        // A bound every attempt is far outside, at an instant far past them
        // all: the most recent terminal attempt of each triple, the live one,
        // and the one that still owes a cleanup all survive it.
        assert_eq!(table.prune(bound(0, 0), timestamp(1_000_000)).unwrap(), 0);
        assert_eq!(
            keys(&table, Direction::Forward, None),
            ["op-live", "op-newest", "op-owing", "op-owing-newer"]
        );
    }

    #[test]
    fn retention_is_idempotent_and_reads_no_clock() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let attempts = [
            terminal_attempt("op-1", HOST, TARGET, Some(1), 1_000, 9_000),
            terminal_attempt("op-2", HOST, TARGET, Some(1), 2_000, 9_000),
            terminal_attempt("op-3", HOST, TARGET, Some(1), 3_000, 9_000),
        ];
        for attempt in &attempts {
            table.upsert(attempt).unwrap();
        }
        let policy = bound(2_500, 10);

        // Real time is years past every one of these instants, so a prune
        // reading the wall clock would empty the triple down to its survivor
        // on the first call.
        assert_eq!(table.prune(policy, timestamp(3_000)).unwrap(), 0);
        assert_eq!(table.prune(policy, timestamp(3_000)).unwrap(), 0);
        assert_eq!(
            keys(&table, Direction::Forward, None),
            ["op-1", "op-2", "op-3"]
        );

        // Advancing the supplied instant, and nothing else, is what makes an
        // attempt eligible.
        assert_eq!(table.prune(policy, timestamp(4_000)).unwrap(), 1);
        assert_eq!(table.prune(policy, timestamp(4_000)).unwrap(), 0);
        assert_eq!(keys(&table, Direction::Forward, None), ["op-2", "op-3"]);

        assert_eq!(table.prune(policy, timestamp(6_000)).unwrap(), 1);
        assert_eq!(keys(&table, Direction::Forward, None), ["op-3"]);
    }

    #[test]
    fn owed_cleanup_lists_every_attempt_of_one_triple() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // One triple owes several cleanups at once: a re-drive leaves the
        // earlier attempt's obligation standing, so the index key carries the
        // idempotency key and the lookup answers with all of them.
        let mut live = live_attempt("op-c", HOST, TARGET, Some(1));
        live.cleanup_state = Some(CleanupState::PendingDeregister);
        let mut first = terminal_attempt("op-a", HOST, TARGET, Some(1), 1_000, 9_000);
        first.cleanup_state = Some(CleanupState::PendingIdentityTeardown);
        let mut second = terminal_attempt("op-b", HOST, TARGET, Some(1), 2_000, 9_000);
        second.cleanup_state = Some(CleanupState::PendingDeregister);
        for attempt in [&first, &second, &live] {
            table.upsert(attempt).unwrap();
        }

        assert_eq!(
            table.attempts_owing_cleanup(TARGET, HOST, Some(1)).unwrap(),
            vec![first.clone(), second.clone(), live.clone()],
            "the lookup answers in idempotency-key order"
        );

        // Discharging one leaves the other two owed.
        second.cleanup_state = None;
        table.upsert(&second).unwrap();
        assert_eq!(
            table.attempts_owing_cleanup(TARGET, HOST, Some(1)).unwrap(),
            vec![first, live]
        );
    }

    #[test]
    fn an_onboard_attempt_owes_its_teardown_under_an_empty_target() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // An onboarding has no package, so its `target` segment is empty. The
        // length prefix is what keeps that from swallowing the host segment
        // beside it.
        let here = onboard_attempt("op-onboard");
        let mut there = onboard_attempt("op-elsewhere");
        there.host = "other.example".to_string();
        table.upsert(&here).unwrap();
        table.upsert(&there).unwrap();

        assert_eq!(
            table.attempts_owing_cleanup("", &here.host, None).unwrap(),
            vec![here.clone()]
        );
        assert_eq!(
            table.attempts_owing_cleanup("", &there.host, None).unwrap(),
            vec![there]
        );

        // Per-hostname onboard idempotency falls out of the same index: a
        // second onboarding of a host already being onboarded is refused,
        // while another host onboards alongside it.
        assert_eq!(
            table.live_attempt(&here.host, "", None).unwrap(),
            Some(here.clone())
        );
        let mut again = onboard_attempt("op-onboard-again");
        again.host.clone_from(&here.host);
        assert!(table.upsert(&again).is_err());

        // The teardown stays owed once the onboarding times out, which is what
        // blocks a re-onboard until `review` has discharged it.
        assert_eq!(table.sweep_expired(here.expires_at).unwrap(), 2);
        assert_eq!(table.live_attempt(&here.host, "", None).unwrap(), None);
        let mut owed = here;
        owed.outcome = Some(Outcome::Failed);
        assert_eq!(
            table.attempts_owing_cleanup("", &owed.host, None).unwrap(),
            vec![owed]
        );
    }

    #[test]
    fn expired_attempts_come_back_earliest_deadline_first() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // A deadline before the epoch sorts before one after it, which the
        // two's-complement bytes would otherwise invert.
        let before_epoch = terminal_attempt("op-3", HOST, TARGET, Some(3), 1_000, -60);
        let at_epoch = terminal_attempt("op-2", HOST, TARGET, Some(2), 1_000, 0);
        let after_epoch = terminal_attempt("op-1", HOST, TARGET, Some(1), 1_000, 60);
        for attempt in [&after_epoch, &at_epoch, &before_epoch] {
            table.upsert(attempt).unwrap();
        }

        assert_eq!(
            table
                .expired_attempts(timestamp(60))
                .unwrap()
                .into_iter()
                .map(|attempt| attempt.idempotency_key)
                .collect::<Vec<_>>(),
            ["op-3", "op-2", "op-1"],
            "the scan runs in deadline order, not in idempotency-key order"
        );
        // The cutoff is inclusive and stops the scan where it should.
        assert_eq!(
            table
                .expired_attempts(timestamp(0))
                .unwrap()
                .into_iter()
                .map(|attempt| attempt.idempotency_key)
                .collect::<Vec<_>>(),
            ["op-3", "op-2"]
        );
        assert!(table.expired_attempts(timestamp(-61)).unwrap().is_empty());
    }
}
