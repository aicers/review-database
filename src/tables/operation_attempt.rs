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
//! # The latest pointer
//!
//! One more structure lives outside this column family: the latest pointer,
//! `(host, target, instance)` to an idempotency key, in a column family of
//! its own. It answers "which attempt is the current one for this triple",
//! which none of the three indexes above can, and it is overwritten by the
//! same transaction that stamps [`OperationAttempt::finalized_at`] — last
//! writer in transaction order wins, so nothing compares timestamps and there
//! is no tie to break.
//!
//! It is **not** the whole answer, and [`Table::latest_attempt`] rather than
//! the pointer is what a reader asks. A terminal attempt that still owes a
//! cleanup carries no `finalized_at` and therefore no pointer entry, so a
//! reader consulting finalized rows alone would report a superseded attempt
//! as current while newer work is still owed.
//!
//! Its column family is registered by the migration that bumps the database
//! format, not by this table, so on a store predating that bump every write
//! that would stamp `finalized_at` reports the family's absence instead of
//! silently dropping a pointer nothing could then read.
//!
//! Every index entry is written and removed in the same transaction as its
//! row, so one can never outlive the other. [`Table::upsert`],
//! [`Table::allocate_instance`], [`Table::delete`], [`Table::sweep_expired`]
//! and [`Table::prune`] are
//! therefore this table's only writers, and that is enforced by the compiler
//! rather than by convention: the generic write API on [`Table`] is bounded by
//! [`UniqueKey`](crate::UniqueKey) and [`Value`](super::Value), and
//! [`OperationAttempt`] implements neither. `put`, `insert`,
//! `update_with_transaction` and `delete_with_transaction` therefore do not
//! exist for this table at all, so no caller can store a row the indexes never
//! learn about, or drop one and leave its entries behind. The record's key and
//! serialized value are reached through [`OperationAttempt::record_key`] and
//! [`OperationAttempt::record_value`], which are private to this module.
//!
//! The same boundary governs reading. [`Table::iter`] bounds its scan below
//! [`RESERVED`], so it yields records and nothing else, and the generic
//! [`Iterable`](crate::Iterable) API is not implemented for this record at
//! all. Its scans cover key ranges the caller does not choose — the whole
//! column family for `iter`, and for `prefix_iter` whatever the prefix spans,
//! which an empty or deliberately reserved prefix extends over the index
//! entries — and an index key is not a record and does not decode as one, so
//! such a scan would yield a decoding error rather than a row. That exclusion
//! is enforced as the write one is, by a bound this record does not satisfy
//! rather than by convention.

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::SocketAddr;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, TimeDelta, Utc};
use ring::digest;
use rocksdb::{Direction, IteratorMode, OptimisticTransactionDB, ReadOptions, Transaction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::core_component::is_core_component;
use super::{CoreComponent, InstanceAllocation, InstanceAllocationError};
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

/// The width of a SHA-256 digest.
const DIGEST_LEN: usize = 32;

/// The length of a UUID in its canonical hyphenated form.
const UUID_LEN: usize = 36;

/// The domain and version separation the install-intent transcript opens
/// with.
const INSTALL_INTENT_DOMAIN: &[u8; 24] = b"clumit-install-intent-v1";

/// The transcript tag of a [`BuildSelector::Version`].
///
/// The selector tags are pinned here, beside the transcript they belong to,
/// rather than derived from the declaration order of [`BuildSelector`]: a
/// table beside the type would let two implementations number them
/// differently and disagree on every digest.
const SELECTOR_VERSION_TAG: u8 = 0;

/// The transcript tag of a [`BuildSelector::Commit`].
const SELECTOR_COMMIT_TAG: u8 = 1;

/// The transcript tag of [`OnFailure::Rollback`].
const ON_FAILURE_ROLLBACK_TAG: u8 = 0;

/// The transcript tag of [`OnFailure::Hold`].
const ON_FAILURE_HOLD_TAG: u8 = 1;

/// The bind-address count that encodes an absent list.
///
/// `None` and an empty list are different requests, so they cannot share the
/// count `0`. A list this long cannot be encoded, and is refused rather than
/// allowed to read back as `None`.
const ABSENT_BIND_ADDRS: u32 = u32::MAX;

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

/// The build an operator asked for, as submitted.
///
/// A selector names a version or a commit, never both, and it is the request
/// rather than its resolution: a selector that resolves to a different commit
/// a week later is still the same request, which is why the install-intent
/// transcript carries the selector and not the resolved build.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildSelector {
    /// A version, which the resolver turns into a build.
    Version(String),
    /// An exact commit.
    Commit(String),
}

/// What an apply does with a host it could not finish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnFailure {
    /// Put the build that was there back.
    Rollback,
    /// Leave the failure standing for an operator to look at.
    Hold,
}

/// The request an allocating install was submitted with.
///
/// An allocating install forms a fresh `(host, target, instance)` on every
/// attempt, so only the client-supplied request key can dedupe the operator's
/// intent across a retry — and the row cannot compare the request itself,
/// since it records the build the selector resolved to rather than the
/// selector. So it holds [`InstallIntent::digest`] of this, and the only
/// question ever asked of the digest is equality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallIntent {
    /// The host the package is to be installed on.
    pub host: String,
    /// The host-agnostic package id.
    pub target: String,
    /// The build the operator asked for.
    pub selector: BuildSelector,
    /// What to do if the apply fails.
    pub on_failure: OnFailure,
    /// The addresses the instance is to bind, by listener key.
    ///
    /// `None` and an empty list are distinct requests and hash to distinct
    /// digests: the first leaves the addresses to the component, the second
    /// asks for none at all.
    pub bind_addrs: Option<Vec<(String, SocketAddr)>>,
}

impl InstallIntent {
    /// Returns the SHA-256 digest of this request.
    ///
    /// # Errors
    ///
    /// Returns an error if a segment is longer than `u32::MAX` bytes, or if
    /// the request carries `u32::MAX` bind addresses or more, which is the
    /// count reserved for an absent list.
    pub fn digest(&self) -> Result<[u8; DIGEST_LEN]> {
        let transcript = self.transcript()?;
        digest::digest(&digest::SHA256, &transcript)
            .as_ref()
            .try_into()
            .context("a SHA-256 digest is 32 bytes wide")
    }

    /// Returns the byte-exact transcript the digest is taken over.
    ///
    /// The encoding is fixed here rather than left to each caller. "Length
    /// prefixed" is not a specification, and a digest two `REview` builds
    /// computed differently would turn every retry that crossed an update
    /// into a reused-request-key refusal, so a golden vector holds this
    /// still: every length and count is a fixed-width big-endian `u32`, so no
    /// field boundary can shift, and nothing but the fields below enters it —
    /// not the instance number, which the call allocates, and no timestamp.
    fn transcript(&self) -> Result<Vec<u8>> {
        let mut transcript = INSTALL_INTENT_DOMAIN.to_vec();
        push_segment(&mut transcript, &self.host)?;
        push_segment(&mut transcript, &self.target)?;
        let (tag, value) = match &self.selector {
            BuildSelector::Version(version) => (SELECTOR_VERSION_TAG, version),
            BuildSelector::Commit(commit) => (SELECTOR_COMMIT_TAG, commit),
        };
        transcript.push(tag);
        push_segment(&mut transcript, value)?;
        transcript.push(match self.on_failure {
            OnFailure::Rollback => ON_FAILURE_ROLLBACK_TAG,
            OnFailure::Hold => ON_FAILURE_HOLD_TAG,
        });
        let Some(bind_addrs) = &self.bind_addrs else {
            transcript.extend_from_slice(&ABSENT_BIND_ADDRS.to_be_bytes());
            return Ok(transcript);
        };
        let count = u32::try_from(bind_addrs.len())
            .ok()
            .filter(|count| *count != ABSENT_BIND_ADDRS);
        let count = count.context("too many bind addresses to encode")?;
        transcript.extend_from_slice(&count.to_be_bytes());
        // The caller's order is not the transcript's: two requests that name
        // the same listeners in a different order are the same request. The
        // address breaks a tie between two entries under one listener key,
        // which the key alone leaves to the caller's order and so to chance.
        let mut sorted: Vec<&(String, SocketAddr)> = bind_addrs.iter().collect();
        sorted.sort_unstable_by(|left, right| {
            left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1))
        });
        for (listener_key, addr) in sorted {
            push_segment(&mut transcript, listener_key)?;
            // `SocketAddr`'s own `Display`, named rather than re-derived: an
            // IPv6 address in square brackets, lowercase and compressed as
            // RFC 5952 says.
            push_segment(&mut transcript, &addr.to_string())?;
        }
        Ok(transcript)
    }
}

/// Why a request key could not be resolved to an attempt.
#[derive(Debug, Error)]
pub enum RequestKeyError {
    /// The request key is not a `UUIDv4` in its canonical hyphenated form.
    ///
    /// Canonical is lowercase, so an otherwise well-formed key spelled with
    /// uppercase hex digits lands here rather than becoming a second key for
    /// the same UUID.
    #[error(
        "the request key {request_key} is not a UUIDv4 in canonical hyphenated form, which is lowercase"
    )]
    MalformedRequestKey {
        /// The key as submitted.
        request_key: String,
    },
    /// The request key already names an attempt submitted with a different
    /// request.
    ///
    /// The refusal names the key rather than the difference, for the same
    /// reason the row stores a digest rather than the fields: the difference
    /// is not recoverable from what is held, and a client that reused a key
    /// has a bug rather than a question.
    #[error("the request key {request_key} was already used for a different request")]
    RequestKeyReused {
        /// The key as submitted.
        request_key: String,
    },
    /// The lookup itself failed.
    #[error("cannot resolve the request key")]
    Read(#[source] anyhow::Error),
}

impl RequestKeyError {
    /// Returns whether resubmitting the same request could still succeed.
    ///
    /// Only a failed read can: a malformed or reused key is a client bug, and
    /// sending it again produces the same refusal.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Read(_))
    }
}

/// Returns whether `key` is a `UUIDv4` in its canonical hyphenated form.
///
/// Canonical means lowercase: RFC 9562 renders a UUID with `a`-`f` and
/// nothing else, and a key is compared here as the byte string it is keyed
/// by. Accepting uppercase would let one UUID arrive as two distinct request
/// keys, each finding no row under the other and each starting its own
/// install — the deduplication the key exists for, defeated by a spelling.
///
/// This is a shape check and nothing more. It does not stop a client sending
/// a constant or replaying a stored value: not re-using a key is a client
/// obligation, and the server cannot verify it.
fn is_uuid_v4(key: &str) -> bool {
    if key.len() != UUID_LEN {
        return false;
    }
    let bytes = key.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if *byte != b'-' {
                return false;
            }
        } else if !matches!(byte, b'0'..=b'9' | b'a'..=b'f') {
            return false;
        }
    }
    // The version nibble is `4`, and the variant nibble is one of `8`, `9`,
    // `a` or `b`.
    bytes.get(14) == Some(&b'4') && matches!(bytes.get(19), Some(b'8' | b'9' | b'a' | b'b'))
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
/// use `Option` as each other does. `install_intent` and `finalized_at` are
/// neither: each is absent for a state the row is genuinely in — an operation
/// that dedupes on something other than a request digest, and an attempt that
/// is not finished with — so each is an `Option` too.
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
/// Every write to this table has to maintain the three secondary indexes, and
/// the latest pointer where it finalizes the row, in the same transaction as
/// the row, so the record is written only through the
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
///
/// # Iterating
///
/// The record space and the index spaces share one column family, so a scan
/// whose range the caller does not choose can run off the records and into the
/// index entries, which are not records and do not decode as one. The generic
/// [`Iterable`](crate::Iterable) API on [`Table`] is therefore not implemented
/// for this record: `iter` there covers the whole column family, and
/// `prefix_iter` covers whatever the prefix spans, which for an empty or
/// deliberately reserved prefix is the index entries too. `Table::iter` on
/// this table is the supported record iterator, and it bounds its scan below
/// the reserved range.
///
/// A record whose column family holds records alone is admitted:
///
/// ```
/// use review_database::{Iterable, Table, TorExitNode};
///
/// fn generic_iteration(table: &Table<TorExitNode>) {
///     let _ = table.prefix_iter(todo!(), None, b"");
/// }
/// ```
///
/// An `OperationAttempt` is not, which is what stops a caller from reaching an
/// index entry through a scan that expects a row:
///
/// ```compile_fail,E0599
/// use review_database::{Iterable, OperationAttempt, Table};
///
/// fn generic_iteration(table: &Table<OperationAttempt>) {
///     let _ = table.prefix_iter(todo!(), None, b"");
/// }
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
    /// the registration id. For a module it is the number
    /// [`InstanceAllocation`] holds for the attempt — the smallest free one in
    /// `1..=999` for the `(host, target)` pair when
    /// [`Table::allocate_instance`] picked it. A core component's class has no
    /// instance dimension at all, so it is `None` and no number is taken.
    pub instance: Option<u32>,
    /// The operator's intent.
    pub action: Action,
    /// The digest of the request an allocating install was submitted with, or
    /// `None` for every other operation.
    ///
    /// It is what resolves a resubmitted request key: an equal digest returns
    /// this row, which is what makes a retry idempotent, and a different one
    /// is refused. Update, remove and onboard are keyed by a
    /// `REview`-generated value that is unique by construction, so they have
    /// nothing to compare and store none — and a stored `None` presented with
    /// a digest is a refusal like any other mismatch. The write path holds
    /// the two sides together: an [`Action::Install`] without a digest is
    /// refused, as is a digest under any other action. An attempt that carries
    /// one is keyed by the request key the client supplied, which is a `UUIDv4`
    /// in canonical hyphenated form. See [`InstallIntent::digest`] and
    /// [`Table::resolve_request_key`].
    pub install_intent: Option<[u8; DIGEST_LEN]>,
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
    /// When the attempt was finished with, or `None` while it still has work
    /// to do.
    ///
    /// It is `Some` **if and only if** `outcome` is terminal and
    /// `cleanup_state` is empty — the fully discharged state, not merely the
    /// terminal one — and [`Table::upsert`] refuses a row that says otherwise.
    /// An apply that terminated `Failed` with a teardown still owed is
    /// terminal and not finished, so it carries `None` and the retention
    /// sweep cannot reach it; the later transaction that discharges the last
    /// of its `cleanup_state` is what stamps this, together with the latest
    /// pointer.
    ///
    /// `started_at` and `expires_at` cannot stand in for it: the first is
    /// when the attempt began, and the second a deadline it may never reach.
    pub finalized_at: Option<DateTime<Utc>>,
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
            install_intent: self.install_intent,
            package_digest: Cow::Borrowed(&self.package_digest),
            resolved_version: Cow::Borrowed(&self.resolved_version),
            resolved_commit: Cow::Borrowed(&self.resolved_commit),
            phase: self.phase,
            cleanup_state: self.cleanup_state,
            started_at: self.started_at,
            retry_policy: self.retry_policy,
            outcome: self.outcome,
            finalized_at: self.finalized_at,
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
            install_intent: value.install_intent,
            package_digest: value.package_digest.into_owned(),
            resolved_version: value.resolved_version.into_owned(),
            resolved_commit: value.resolved_commit.into_owned(),
            phase: value.phase,
            cleanup_state: value.cleanup_state,
            started_at: value.started_at,
            retry_policy: value.retry_policy,
            outcome: value.outcome,
            finalized_at: value.finalized_at,
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
    install_intent: Option<[u8; DIGEST_LEN]>,
    package_digest: Cow<'a, str>,
    resolved_version: Cow<'a, str>,
    resolved_commit: Cow<'a, str>,
    phase: Phase,
    cleanup_state: Option<CleanupState>,
    started_at: DateTime<Utc>,
    retry_policy: RetryPolicy,
    outcome: Option<Outcome>,
    finalized_at: Option<DateTime<Utc>>,
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
/// attempt the latest pointer names for each `(host, target, instance)`
/// triple, and every attempt that is still non-terminal or still owes a
/// cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionBound {
    /// The greatest age a prunable attempt may reach, measured from its
    /// `finalized_at` against the instant handed to [`Table::prune`]. The
    /// design this table implements puts it at 30 days.
    ///
    /// An attempt exactly this old is kept: the bound removes one only once
    /// its age is greater. The measurement is from `finalized_at`, which is
    /// when the attempt was finished with, and never from `started_at`, which
    /// is when it began, or from `expires_at`, which is a per-action deadline
    /// and would order attempts by the policy that set it rather than by when
    /// the work happened.
    pub max_age: TimeDelta,
    /// How many terminal attempts one `(host, target, instance)` triple keeps,
    /// counting down from the one the latest pointer names.
    ///
    /// A triple holding exactly this many terminal attempts loses none of
    /// them: the bound removes only the ones past the count. Every terminal
    /// attempt of the triple is counted, including one that owes a cleanup and
    /// is therefore kept anyway.
    pub max_terminal_per_triple: usize,
}

/// Appends a length-prefixed segment to an index key or an install-intent
/// transcript.
///
/// The length prefix is what makes a composite key unambiguous: without it
/// `("ab", "c")` and `("a", "bc")` would encode to the same bytes. The
/// transcript shares this function rather than restating the encoding beside
/// itself, so the two cannot drift apart; the golden vector is what pins the
/// bytes either of them produce.
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

/// The owed-cleanup key of a `(target, host, instance)` triple.
///
/// The triple alone: the key carries no idempotency key to tell two attempts
/// of one triple apart, so a second attempt owing a cleanup for it overwrites
/// the entry rather than queueing beside it. That is the storage half of the
/// invariant that at most one attempt owes a cleanup per triple, which is
/// what lets [`Table::latest_attempt`] have a single row to return. That a
/// second one never arises is not this crate's to enforce: the guard that
/// refuses the update, remove or re-onboard which would create one lives in
/// the repository driving that path.
fn owed_cleanup_key(target: &str, host: &str, instance: Option<u32>) -> Result<Vec<u8>> {
    let mut key = vec![OWED_CLEANUP];
    push_segment(&mut key, target)?;
    push_segment(&mut key, host)?;
    push_instance(&mut key, instance);
    Ok(key)
}

/// The latest-pointer key of a `(host, target, instance)` triple.
///
/// It carries no lead byte, because it lives in a column family of its own:
/// there is no record space beside it to stay clear of.
fn latest_pointer_key(host: &str, target: &str, instance: Option<u32>) -> Result<Vec<u8>> {
    let mut key = Vec::new();
    push_segment(&mut key, host)?;
    push_segment(&mut key, target)?;
    push_instance(&mut key, instance);
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
        keys.push(owed_cleanup_key(
            &attempt.target,
            &attempt.host,
            attempt.instance,
        )?);
    }
    Ok(keys)
}

/// Functions for the `operation_attempt` table.
impl<'d> Table<'d, OperationAttempt> {
    /// Opens the `operation_attempt` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::OPERATION_ATTEMPTS).map(Table::new)
    }

    /// Returns an iterator over the stored attempts, whose keys are the
    /// idempotency keys in lexicographic order.
    ///
    /// This is the table's only iterator. The generic
    /// [`Iterable`](crate::Iterable) API on [`Table`] is not implemented for
    /// this record, because its scans cover key ranges the caller does not
    /// choose and would therefore also yield the index key spaces, which are
    /// not records and do not decode as one. This one stops below the first
    /// byte the index key spaces reserve, so it yields records and nothing
    /// else.
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

    /// Returns the attempt that owes a cleanup for `(target, host, instance)`,
    /// or `None` if the triple owes none.
    ///
    /// At most one attempt can: the owed-cleanup key is the triple alone, so
    /// a second write for it overwrites the first rather than queueing beside
    /// it. A terminal attempt is included, because the obligation outlives
    /// the outcome, and this is what "a re-onboard is blocked while a
    /// teardown is owed" reads.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored value is invalid or the database
    /// operation fails.
    pub fn attempt_owing_cleanup(
        &self,
        target: &str,
        host: &str,
        instance: Option<u32>,
    ) -> Result<Option<OperationAttempt>> {
        let key = owed_cleanup_key(target, host, instance)?;
        let Some(idempotency_key) = self.map.get(&key)? else {
            return Ok(None);
        };
        let idempotency_key = std::str::from_utf8(idempotency_key.as_ref())
            .context("the owed-cleanup index holds an invalid idempotency key")?;
        self.get(idempotency_key)
    }

    /// Returns the current attempt for `(host, target, instance)`, or `None`
    /// if the triple has none.
    ///
    /// This is one ordered lookup rather than three, and the order is the
    /// rule:
    ///
    /// 1. a non-terminal row for the triple, if there is one. At most one
    ///    can be, since the non-terminal index admits a single live attempt
    ///    per triple — and an allocating install forms a fresh triple, so it
    ///    never contends for the slot;
    /// 2. otherwise the row that still owes a cleanup, if there is one. It
    ///    carries no `finalized_at` and so no pointer entry, and consulting
    ///    the pointer first would report a superseded attempt as current
    ///    while newer work is still owed;
    /// 3. otherwise the row the latest pointer names.
    ///
    /// What the three can overlap on is one row, not two: a single in-flight
    /// attempt that is non-terminal and already carries the `cleanup_state`
    /// armed before its mint appears under both indexes, and both steps name
    /// it.
    ///
    /// # Errors
    ///
    /// Returns an error if a stored value is invalid, if the latest-pointer
    /// column family is not registered, or if the database operation fails.
    pub fn latest_attempt(
        &self,
        host: &str,
        target: &str,
        instance: Option<u32>,
    ) -> Result<Option<OperationAttempt>> {
        if let Some(live) = self.live_attempt(host, target, instance)? {
            return Ok(Some(live));
        }
        if let Some(owing) = self.attempt_owing_cleanup(target, host, instance)? {
            return Ok(Some(owing));
        }
        self.pointed_at_attempt(host, target, instance)
    }

    /// Returns the attempt a resubmitted request key names, or `None` if no
    /// attempt is held under it.
    ///
    /// A key whose stored digest equals `install_intent` returns that row,
    /// which is what makes a retry idempotent. A key whose stored digest
    /// differs — a stored `None` included, since an operation that dedupes on
    /// something else stores none — is refused with
    /// [`RequestKeyError::RequestKeyReused`], because overwriting the first
    /// row would destroy a live attempt's record along with the allocations
    /// that hang off it.
    ///
    /// A `None` here is not a reservation, and it is not the decision to
    /// create. Two requests sharing one key can both be told it is free, so
    /// the install itself is written with [`Table::create_or_resolve`], which
    /// makes that decision again under the key's own lock and in the
    /// transaction that writes: the request that gets there second is
    /// answered with the attempt the first created, or refused where the
    /// request differs, rather than writing over it.
    ///
    /// The guarantee is bounded by retention: a client that replays a request
    /// after the row is gone gets a new install, and there is no tombstone.
    ///
    /// # Errors
    ///
    /// Returns [`RequestKeyError::MalformedRequestKey`] if `request_key` is
    /// not a `UUIDv4` in canonical hyphenated form,
    /// [`RequestKeyError::RequestKeyReused`] if it names an attempt submitted
    /// with a different request, and [`RequestKeyError::Read`] if the lookup
    /// itself fails. Only the last is retryable.
    pub fn resolve_request_key(
        &self,
        request_key: &str,
        install_intent: &[u8; DIGEST_LEN],
    ) -> Result<Option<OperationAttempt>, RequestKeyError> {
        if !is_uuid_v4(request_key) {
            return Err(RequestKeyError::MalformedRequestKey {
                request_key: request_key.to_string(),
            });
        }
        let Some(attempt) = self.get(request_key).map_err(RequestKeyError::Read)? else {
            return Ok(None);
        };
        let reused = || RequestKeyError::RequestKeyReused {
            request_key: request_key.to_string(),
        };
        let Some(stored) = attempt.install_intent else {
            return Err(reused());
        };
        // A plain comparison: this digest is not a secret. It is taken over a
        // request the client composed and still holds, so what its timing
        // could leak is what the client sent in the same call.
        if stored != *install_intent {
            return Err(reused());
        }
        Ok(Some(attempt))
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

    /// Creates the attempt under the request key it carries, or returns the
    /// attempt already held under that key where the request is the same.
    ///
    /// This is how an install comes into existence. The three answers the
    /// request key allows — create it, return the attempt already running
    /// under it, refuse it as a reuse — are decided under that key's own lock
    /// and in the transaction that writes, so the decision cannot be
    /// overtaken between being made and being acted on. Two requests carrying
    /// one key are both told it is free by
    /// [`Table::resolve_request_key`], which answers outside any transaction;
    /// here the one that reads second, or whose commit conflicts and re-runs,
    /// finds the row the first wrote and is answered with it.
    ///
    /// The attempt returned is the one the store holds: this call's own row
    /// where it created it, and the first request's row where it did not. A
    /// caller told it did not create the row allocated an instance nothing
    /// now refers to, and releases it.
    ///
    /// [`Table::upsert`] carries an attempt already held under its key
    /// forward. It does not create one carrying an `install_intent`, so this
    /// decision has no way around it.
    ///
    /// # Errors
    ///
    /// Returns an error if the attempt carries no `install_intent`, since
    /// every other action is keyed by a value unique by construction and is
    /// written with [`Table::upsert`], or if the database operation fails.
    ///
    /// A refusal that concerns the request key carries a [`RequestKeyError`]
    /// a caller can downcast to: [`RequestKeyError::MalformedRequestKey`]
    /// where the key is not a `UUIDv4` in canonical hyphenated form, and
    /// [`RequestKeyError::RequestKeyReused`] where the key already names an
    /// attempt submitted with a different request.
    pub fn create_or_resolve(&self, attempt: &OperationAttempt) -> Result<OperationAttempt> {
        let Some(install_intent) = attempt.install_intent else {
            bail!(
                "only an attempt carrying an install intent is created under a request key; every other action is written with `upsert`"
            );
        };
        if !is_uuid_v4(&attempt.idempotency_key) {
            return Err(RequestKeyError::MalformedRequestKey {
                request_key: attempt.idempotency_key.clone(),
            }
            .into());
        }
        loop {
            let txn = self.transaction();
            if let Some(stored) = self.get_for_update(&attempt.idempotency_key, &txn)? {
                // The key is taken, and nothing is written either way. An
                // equal digest is this request resubmitted, and is answered
                // with the attempt already held under it — the row keeps its
                // record and the allocations that hang off it, and the
                // instance this caller allocated is the one released.
                // Anything else is a key used for a second request.
                if stored.install_intent == Some(install_intent) {
                    return Ok(stored);
                }
                return Err(RequestKeyError::RequestKeyReused {
                    request_key: attempt.idempotency_key.clone(),
                }
                .into());
            }
            self.write_with_transaction(None, attempt, &txn)?;
            match txn.commit() {
                Ok(()) => return Ok(attempt.clone()),
                Err(e) => {
                    // The retry re-reads the key before anything else, so a
                    // loser that conflicted on a create finds the winner's
                    // row above rather than composing its write again.
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to store the operation attempt");
                    }
                }
            }
        }
    }

    /// Stores an attempt already held under its idempotency key, replacing it
    /// and bringing every index in line with the new row.
    ///
    /// A re-drive or a resume therefore finalizes the existing row in place
    /// instead of adding a second row for the same logical operation. The row
    /// and its index entries are written in one transaction, so a row leaves
    /// the non-terminal index in the same write that makes it terminal, and
    /// leaves the owed-cleanup index in the same write that clears its
    /// `cleanup_state`.
    ///
    /// A write that leaves the attempt terminal and owing nothing carries
    /// `finalized_at`, and the write that first stamps it moves the latest
    /// pointer for its triple in the same transaction, so the two can never
    /// disagree. A later re-write of a row finalized earlier leaves the
    /// pointer alone, so an idempotent replay cannot name a superseded
    /// attempt current again. A write that moves the attempt to another
    /// triple takes the pointer with it, dropping the entry it left behind in
    /// that same transaction where it still names this attempt, so no triple
    /// is left pointing at a row that has since moved off it.
    ///
    /// An attempt carrying an `install_intent` is not created here: a write
    /// that finds no row under its key is refused, because deciding whether a
    /// request key is free is [`Table::create_or_resolve`]'s to make under
    /// that key's lock. Two requests sharing one key can both find it free in
    /// [`Table::resolve_request_key`], and a create through this path would
    /// let the second write over the attempt the first created. The row being
    /// replaced is read under an exclusive lock and its `install_intent` must
    /// match the one being written, so a write carrying a different request
    /// is refused here too.
    ///
    /// The same transaction releases the instance number the attempt holds,
    /// when the state it records is one that releases it. That is not
    /// something the caller opts into: an attempt that is terminal and owes no
    /// cleanup has nothing left that would revisit it, so a release left to a
    /// second write is a permanent leak if it never happens.
    ///
    /// The one field group a re-drive may not restate is the
    /// `(host, target, instance)` triple, and only while the key still holds
    /// an instance number for it. That number is released through the attempt
    /// that names it, so a row that moved off the triple would leave it held
    /// by a record that no longer mentions it and can no longer give it back.
    ///
    /// # Errors
    ///
    /// Returns an error if the attempt's idempotency key is empty, if
    /// `finalized_at` is set for an attempt that is not fully discharged or
    /// unset for one that is, if an install carries no `install_intent` or an
    /// `install_intent` is carried by an attempt that is not an install, if
    /// the attempt carries an `install_intent` and no row is held under its
    /// key, which is [`Table::create_or_resolve`]'s decision to make, if
    /// the attempt is non-terminal and a different
    /// attempt is already live for its `(host, target, instance)` triple, if
    /// it moves the row off a `(host, target, instance)` triple whose
    /// instance number the key still holds, if the write moves the latest
    /// pointer and that column family is not registered, or if the database
    /// operation fails.
    ///
    /// A refusal that concerns the request key carries a [`RequestKeyError`] a
    /// caller can downcast to: [`RequestKeyError::MalformedRequestKey`] where
    /// an `install_intent` is keyed by something other than a `UUIDv4` in
    /// canonical hyphenated form, and [`RequestKeyError::RequestKeyReused`]
    /// where the row already held under the key was submitted with a different
    /// request.
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
            // Read under the key's lock, so this is the same reading the
            // write below is composed against: an install the store holds no
            // row for is a create, and a create is decided in
            // `create_or_resolve` rather than here, where two requests
            // carrying one key would each write their own allocation. The
            // check lives here rather than in `upsert_with_transaction`,
            // which `allocate_instance` uses to create exactly such a row
            // once it has decided the key is free.
            if attempt.install_intent.is_some()
                && self
                    .get_for_update(&attempt.idempotency_key, &txn)?
                    .is_none()
            {
                bail!(
                    "an install attempt is created with `create_or_resolve`, which decides under the request key's lock whether it is free; `upsert` carries forward an attempt already held under its key"
                );
            }
            self.upsert_with_transaction(attempt, &txn)?;
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

    /// Takes an instance number for the attempt's `(host, target)` pair and
    /// stores the attempt carrying it, and returns the stored attempt.
    ///
    /// This is how an attempt that installs a new instance of a module is
    /// first recorded. The number is the smallest free one in `1..=999` for
    /// the pair, and `attempt.instance` is whatever the allocator picked, not
    /// whatever was passed in, so passing a number in is neither required nor
    /// harmful.
    ///
    /// The returned attempt is whatever the key names once the call is done:
    /// the row just written, or — when the key already named one — that row
    /// exactly as it stands, which the call did not touch.
    ///
    /// The allocation and the attempt row are one transaction, which is not a
    /// convenience: a number taken by a transaction of its own is held by
    /// nothing if the process stops before the attempt is recorded, and
    /// nothing would ever give it back, because every release is justified by
    /// a record that in that case was never written. Either both land or
    /// neither does, and there is no entry point that takes a number without
    /// the attempt that owns it. The port rows keyed on the number will join
    /// this same transaction.
    ///
    /// Storing the attempt releases what it gives back, exactly as
    /// [`Table::upsert`] does, so a terminal attempt that gives its number
    /// back gives back the one it has just been handed. Only the write that
    /// starts an operation belongs here.
    ///
    /// # What may take a number
    ///
    /// Every condition below governs a *fresh* allocation, and is read only
    /// after the key lookup has found nothing. A key that already names an
    /// attempt takes no number, so none of them can refuse it: the row is
    /// returned whatever the payload presented alongside the key now says.
    ///
    /// Only an [`Action::Install`] naming a component. An update and a
    /// removal concern an instance that already has its number, and taking a
    /// second one for either would hand out a number nothing releases; an
    /// [`Action::Onboard`] carries no package at all, and its empty `target`
    /// would key a row on an unnamed component. All three are refused here
    /// rather than left to a caller to avoid, and so is an install whose
    /// `target` is empty.
    ///
    /// A core component has no instance dimension at all and takes no number:
    /// its attempts are recorded with [`Table::upsert`] and `instance = None`,
    /// and a second install of one is refused by the single row per
    /// `(component, host)` in [`CoreComponent`](super::CoreComponent). Two
    /// checks refuse one a number here, and the first does not need a row to
    /// exist: a `target` naming a canonical core-component package-id —
    /// `review`, `aice-web-next`, `roxyd` or `bootroot` — is refused outright,
    /// on a fresh store as much as a populated one, which is when the first
    /// install of one arrives. The registry read then catches a pair this
    /// build was told about under some other package-id.
    ///
    /// Classifying the four ids is not a fork of the packaging layer's
    /// registry into this crate's schema: no row stores it, nothing migrates
    /// when it changes, and `component` stays a `String` for the reasons under
    /// *Why `component` is a `String`* on
    /// [`CoreComponent`](super::CoreComponent). What is left to the caller is
    /// only a package-id neither check knows, which is not a core component
    /// this platform ships.
    ///
    /// Every pass reads the idempotency key **first**, the first pass as much
    /// as a re-run after a commit conflict, and a row under that key is the
    /// answer: it is returned as it stands and nothing is allocated. One key
    /// is one operator action, whether the second request for it arrives while
    /// the first is still committing or long after it finished, and selecting
    /// a number without that check is exactly how one action becomes two
    /// instances — and, for an action that already ended, how the record of
    /// how it ended is overwritten by a fresh attempt. Only when no such row
    /// exists is a number selected, and only then is anything about the
    /// presented attempt examined at all: an operator re-driving a recorded
    /// key gets the recorded answer, not a refusal earned by a payload the
    /// call was never going to act on.
    ///
    /// That read is the transaction's first, and it is a `get_for_update`, so
    /// there is no instant between deciding the key is free and writing it in
    /// which another drive can commit the row unseen. A competing commit
    /// either precedes the locked read, and is returned untouched, or follows
    /// it, and fails this commit — whereupon the re-run reads it and returns
    /// it. Reading the key before opening the transaction would leave exactly
    /// that gap: a row committed inside it is read by the write path as the
    /// row being replaced, with no conflict to stop the overwrite, because the
    /// transaction began after the commit it would have had to conflict with.
    ///
    /// # Errors
    ///
    /// None of these are reached when the idempotency key already names an
    /// attempt; that row is returned instead.
    ///
    /// Returns [`InstanceAllocationError::InstanceNumbersExhausted`] if every
    /// number in `1..=999` is taken for the pair, or
    /// [`InstanceAllocationError::Database`] if the attempt's action is not
    /// [`Action::Install`], if its `target` is empty, if that `target` names a
    /// core component or is registered as one on its `host`, if the database has no
    /// `instance_allocation` column family, if the attempt's idempotency key
    /// is empty, if the attempt is non-terminal and a different attempt is
    /// already live for its `(host, target, instance)` triple, or if the
    /// database operation fails.
    pub fn allocate_instance(
        &self,
        attempt: &OperationAttempt,
    ) -> Result<OperationAttempt, InstanceAllocationError> {
        let allocations = Table::<InstanceAllocation>::open(self.map.db);
        let core_components = Table::<CoreComponent>::open(self.map.db);
        loop {
            let txn = self.transaction();
            // The key check every pass begins with, and the first thing the
            // transaction does. A row under this key is the operator action
            // already recorded — by a drive that has just committed, or by one
            // that finished long ago — so it is the answer, and selecting a
            // number would make one action two instances. The read locks the
            // key, so a drive committing it after this point cannot slip in
            // between the check and the write: the commit below fails and the
            // re-run reads the row.
            //
            // It precedes every check below because those decide what may
            // take a *fresh* number, and a key that already names an attempt
            // takes none: the row is returned whatever the payload presented
            // alongside the key now says, which is what makes a re-drive
            // idempotent rather than a second chance to fail validation.
            if let Some(stored) = self.get_for_update(&attempt.idempotency_key, &txn)? {
                return Ok(stored);
            }
            if attempt.action != Action::Install {
                return Err(anyhow!(
                    "an instance number is taken by the install that creates the instance, and operation attempt {} is a {:?}",
                    attempt.idempotency_key,
                    attempt.action
                )
                .into());
            }
            if attempt.target.is_empty() {
                return Err(anyhow!(
                    "operation attempt {} names no component to take an instance number for",
                    attempt.idempotency_key
                )
                .into());
            }
            // A core component is host-fixed infrastructure with no instance
            // dimension, so it takes no number. Refused from the package-id
            // alone, before any registry read, because the first install of
            // one meets a store with no row for it yet — which is exactly when
            // a number would be handed out that nothing ever asked for.
            if is_core_component(&attempt.target) {
                return Err(anyhow!(
                    "component {} is a core component, and a core component has no instance dimension",
                    attempt.target
                )
                .into());
            }
            let Some(allocations) = allocations.as_ref() else {
                return Err(anyhow!(
                    "the database has no instance allocation table to take a number from"
                )
                .into());
            };
            // A component the registry holds is host-fixed infrastructure and
            // has no instance dimension, so there is no number to take for it
            // and its second install is refused by that registry's own single
            // row per pair rather than given one. Read inside the transaction,
            // and read for update, so a registration committing while this one
            // is open fails this commit instead of going unseen.
            if let Some(core_components) = core_components.as_ref()
                && core_components.is_registered(&attempt.target, &attempt.host, &txn)?
            {
                return Err(anyhow!(
                    "component {} is registered as a core component on host {}, and a core component has no instance dimension",
                    attempt.target,
                    attempt.host
                )
                .into());
            }
            let instance = allocations.allocate_with_transaction(
                &attempt.host,
                &attempt.target,
                &attempt.idempotency_key,
                &txn,
            )?;
            let mut allocated = attempt.clone();
            allocated.instance = Some(instance);
            self.upsert_with_transaction(&allocated, &txn)?;
            match txn.commit() {
                Ok(()) => return Ok(allocated),
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(anyhow::Error::new(e)
                            .context("failed to store the operation attempt")
                            .into());
                    }
                }
            }
        }
    }

    /// Stores an attempt within `txn`, releasing what it gives back, exactly
    /// as [`Table::upsert`] does, so that the write can be paired with another
    /// the caller has to land or lose together with it.
    ///
    /// The caller owns the commit, and with it the conflict retry: a commit
    /// that fails with `Resource busy:` means the whole transaction has to run
    /// again.
    ///
    /// Deliberately not public: a caller that owns the commit can abandon the
    /// transaction, and the public entry points are the ones that do not let
    /// half of it land. This exists for the composed transaction an allocation
    /// joins — the instance number the attempt takes, and the ports keyed on
    /// it — which has to be one transaction with the attempt write.
    ///
    /// # Errors
    ///
    /// Returns an error if the attempt's idempotency key is empty, if the
    /// attempt is non-terminal and a different attempt is already live for its
    /// `(host, target, instance)` triple, if it moves the row off a
    /// `(host, target, instance)` triple whose instance number the key still
    /// holds, or if the database operation fails.
    pub(super) fn upsert_with_transaction(
        &self,
        attempt: &OperationAttempt,
        txn: &Transaction<'_, OptimisticTransactionDB>,
    ) -> Result<()> {
        if attempt.idempotency_key.is_empty() {
            bail!("an operation attempt key must not be empty");
        }
        let stored = self.get_for_update(&attempt.idempotency_key, txn)?;
        if let Some(stored) = stored.as_ref() {
            self.refuse_moving_off_an_allocation(stored, attempt, txn)?;
        }
        self.write_with_transaction(stored.as_ref(), attempt, txn)?;
        self.release_resources(attempt, txn)
    }

    /// Refuses a write that would move the row off the triple whose instance
    /// number its own key still holds.
    ///
    /// A re-drive is otherwise free to restate any field, which is what lets
    /// one row be finalized in place instead of a second being added. The
    /// instance number is the exception, because it is released through the
    /// attempt that names it and by `(host, target, instance)`: a row that
    /// walks to another triple while its number is still allocated carries
    /// that number's only release away with it, and nothing left can name the
    /// row again. Neither half of the alternative is better — releasing the
    /// number the stored row named would give it back on the strength of a
    /// record that no longer mentions it, and following the move with it would
    /// hand out a number for a pair that was never scanned. So the write is
    /// refused, and the caller either finishes the operation on the triple it
    /// took a number for, or drives the other triple under a key of its own.
    ///
    /// A store whose `instance_allocation` column family does not exist yet
    /// can hold no allocation, so it has nothing to strand and nothing is
    /// refused there.
    fn refuse_moving_off_an_allocation(
        &self,
        stored: &OperationAttempt,
        new: &OperationAttempt,
        txn: &Transaction<'_, OptimisticTransactionDB>,
    ) -> Result<()> {
        if (
            stored.host.as_str(),
            stored.target.as_str(),
            stored.instance,
        ) == (new.host.as_str(), new.target.as_str(), new.instance)
        {
            return Ok(());
        }
        let Some(allocations) = Table::<InstanceAllocation>::open(self.map.db) else {
            return Ok(());
        };
        if allocations.holds_number_for(stored, txn)? {
            bail!(
                "operation attempt {} holds instance number {:?} for host {}, target {}, and cannot be re-driven onto host {}, target {}, instance {:?}",
                stored.idempotency_key,
                stored.instance,
                stored.host,
                stored.target,
                new.host,
                new.target,
                new.instance
            );
        }
        Ok(())
    }

    /// Releases within `txn` the resources `attempt` gives back, if the state
    /// it records gives any back.
    ///
    /// Every writer of a row goes through here, so the release is not a step a
    /// caller can skip: recording an attempt that ended owing nothing,
    /// discharging its `cleanup_state`, and confirming a removal each delete
    /// the instance allocation in the very transaction that records why. The
    /// alternative is a half state the schema forbids — a number held by an
    /// attempt that nothing will revisit, or given back with no record saying
    /// so.
    ///
    /// A store whose `instance_allocation` column family does not exist yet
    /// can hold no allocation, so there is nothing to release and the call is
    /// a no-op. That is the state of a database at format `0.46.0`, which the
    /// column family reaches only with the format bump that registers it.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn release_resources(
        &self,
        attempt: &OperationAttempt,
        txn: &Transaction<'_, OptimisticTransactionDB>,
    ) -> Result<()> {
        let Some(allocations) = Table::<InstanceAllocation>::open(self.map.db) else {
            return Ok(());
        };
        allocations.release_for_attempt(attempt, txn)
    }

    /// Deletes the attempt with the given idempotency key, along with its
    /// index entries and the latest pointer, where one names it.
    ///
    /// This is for a row that should never have existed; a completed attempt
    /// is finalized in place and retained until [`Table::prune`] decides
    /// otherwise, not deleted. The key is not checked for emptiness, so this
    /// stays usable to clear a stray empty-key row that some other writer left
    /// behind.
    ///
    /// # Errors
    ///
    /// Returns an error if the latest-pointer column family is not
    /// registered, or if the database operation fails.
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
            let (index_keys, pointer_keys) = match OperationAttempt::from_key_value(key, &value) {
                Ok(attempt) => (index_keys(&attempt)?, self.pointer_keys_held_by(&attempt)?),
                Err(_) => (self.index_keys_naming(key)?, self.pointer_keys_naming(key)?),
            };
            for index_key in index_keys {
                // The owed-cleanup key carries no idempotency key, so the
                // entry this row wrote may since have come to name another
                // attempt of the same triple. Dropping it then would lose
                // that attempt's obligation silently, so an entry goes only
                // while it still names this row.
                let holder = txn
                    .get_for_update_cf(self.map.cf, &index_key, EXCLUSIVE)
                    .context("cannot read the index")?;
                if holder.is_some_and(|holder| holder != key) {
                    continue;
                }
                self.map.delete_with_transaction(&index_key, &txn)?;
            }
            let latest = self.latest_pointer()?;
            for pointer_key in pointer_keys {
                latest.delete_with_transaction(&pointer_key, &txn)?;
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
    /// A finalized attempt gets `outcome = Some(Outcome::Failed)`, and
    /// `finalized_at` together with the latest pointer where it owes no
    /// cleanup: `phase`, `retry_policy` and above all `cleanup_state` are left
    /// as they were. Clearing an owed cleanup here is what would orphan a minted
    /// bootroot identity, so the sweep never does it. The attempt leaves the
    /// non-terminal index, which frees the single-flight slot, and stays in
    /// the owed-cleanup index for `review` to discharge once the registrar is
    /// reachable. A host that never returns therefore leaks neither the slot
    /// nor the record of what is still owed.
    ///
    /// An expired attempt that owes no cleanup is one of the three writes that
    /// release an instance number, so the sweep gives back what each attempt
    /// it finalizes holds, in the transaction that finalizes it. One still
    /// owing a cleanup keeps its number until the discharge, exactly as it
    /// keeps the record of what is owed.
    ///
    /// `instant` is the caller's, and the sweep reads no clock of its own, so
    /// a second run over already-swept state finalizes nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if a stored value is invalid, if the sweep stamps
    /// `finalized_at` and the latest-pointer column family is not registered,
    /// or if the database operation fails.
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
                // Nothing owed means the attempt is finished with, so the
                // same write stamps it and moves the pointer. One that still
                // owes a cleanup is terminal and not finished, and stays out
                // of reach of the retention sweep until the discharge.
                if failed.cleanup_state.is_none() {
                    failed.finalized_at = Some(instant);
                }
                self.write_with_transaction(Some(&stored), &failed, &txn)?;
                self.release_resources(&failed, &txn)?;
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
    /// preference: the attempt the latest pointer names for each `(host,
    /// target, instance)` triple is kept however far it is past either bound,
    /// and an attempt that is still non-terminal or still owes a
    /// `cleanup_state` is never removed at all. Only a terminal attempt that
    /// the pointer does not name is ever eligible, and it goes once it exceeds
    /// [`RetentionBound::max_age`] or [`RetentionBound::max_terminal_per_triple`].
    /// An attempt exactly at either bound is kept.
    ///
    /// "The current attempt" is the pointer's answer and nothing else, which
    /// is the finalization that committed last. Nothing here compares
    /// timestamps to find it, so two attempts finalized in the same nanosecond
    /// need no tie-break. Where the pointer names nothing — no attempt of the
    /// triple has been finalized — the rule falls back to the greatest
    /// `(finalized_at, idempotency_key)` pair, which is also the order the
    /// count bound counts down from.
    ///
    /// Because it never removes the row the pointer names, the delete is a
    /// single row and needs no pairing with a pointer write.
    ///
    /// Every input the outcome depends on is a parameter of the call: the
    /// prune reads no wall clock and no configuration, so running it twice
    /// with the same arguments removes nothing the second time.
    ///
    /// # Errors
    ///
    /// Returns an error if a stored value is invalid, if the latest-pointer
    /// column family is not registered, or if the database operation fails.
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
                // The ranking above read the pointer outside this
                // transaction. Reading it again here locks it, so a
                // finalization that has moved it onto this attempt since is
                // seen, and one that moves it during the commit fails the
                // commit rather than leaving the pointer naming a row this
                // delete took.
                if self.pointer_names(&stored, &txn)? {
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
        for ((host, target, instance), mut attempts) in by_triple {
            // Greatest `(finalized_at, idempotency_key)` first, which is the
            // order the count bound counts down from.
            attempts.sort_unstable_by(|a, b| {
                b.finalized_at
                    .cmp(&a.finalized_at)
                    .then_with(|| b.idempotency_key.cmp(&a.idempotency_key))
            });
            // The current attempt is whichever the pointer names, whatever
            // its timestamps say, so it takes rank 1 from whoever sorted
            // there. Only where the pointer names nothing does the order
            // above decide which attempt the first keep-rule holds on to.
            if let Some(pointed_at) = self.pointed_at_key(&host, &target, instance)?
                && let Some(index) = attempts
                    .iter()
                    .position(|attempt| attempt.idempotency_key == pointed_at)
            {
                let current = attempts.remove(index);
                attempts.insert(0, current);
            }
            for (index, attempt) in attempts.into_iter().enumerate() {
                let rank = index + 1;
                if rank == 1 || attempt.cleanup_state.is_some() {
                    continue;
                }
                // Every attempt past this point is terminal and owes nothing,
                // so it carries a finalization instant.
                let Some(finalized_at) = attempt.finalized_at else {
                    continue;
                };
                let too_old = instant.signed_duration_since(finalized_at) > bound.max_age;
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
        if new.finalized_at.is_some() != new.is_fully_discharged() {
            bail!(
                "an operation attempt carries a finalization instant exactly when it is terminal and owes no cleanup"
            );
        }
        // An install is the one action submitted with a request the client
        // holds across retries, so it is the one action that records that
        // request's digest. Without it the resubmission has nothing to
        // compare and allocates a second instance instead of returning the
        // first; with it under any other action there is nothing the digest
        // could ever be compared against.
        if (new.action == Action::Install) != new.install_intent.is_some() {
            bail!(
                "an install records the digest of the request it was submitted with, and no other action does"
            );
        }
        // An install is keyed by the request key the client supplied, and that
        // is the only shape `resolve_request_key` can reach a row under: a key
        // it refuses as malformed leaves the row unfindable.
        if new.install_intent.is_some() && !is_uuid_v4(&new.idempotency_key) {
            return Err(RequestKeyError::MalformedRequestKey {
                request_key: new.idempotency_key.clone(),
            }
            .into());
        }
        // `resolve_request_key` answers before the write and outside it, so
        // two requests carrying one key can both find it free. The row this
        // write replaces is read under an exclusive lock, and the loser of
        // that race re-reads the winner's row instead of committing over it,
        // so comparing the digests here is what makes the create-or-resolve
        // decision atomic with the write: the second request is refused as a
        // reuse rather than replacing the first attempt's record and stranding
        // the allocations that hang off it. An attempt's own re-writes carry
        // the digest unchanged, and a change in whether one is carried at all
        // is a change of action, which is a different request too.
        if let Some(stored) = stored
            && stored.install_intent != new.install_intent
        {
            return Err(RequestKeyError::RequestKeyReused {
                request_key: new.idempotency_key.clone(),
            }
            .into());
        }
        let keys = index_keys(new)?;
        if let Some(stored) = stored {
            for key in index_keys(stored)? {
                if keys.contains(&key) {
                    continue;
                }
                // The owed-cleanup key carries no idempotency key, so a
                // second attempt owing a cleanup for one triple overwrites
                // the entry. Dropping an entry that has come to name another
                // row would lose that row's obligation silently, so a stale
                // key goes only while it still names this attempt.
                let holder = txn
                    .get_for_update_cf(self.map.cf, &key, EXCLUSIVE)
                    .context("cannot read the index")?;
                if holder.is_some_and(|holder| holder != new.idempotency_key.as_bytes()) {
                    continue;
                }
                self.map.delete_with_transaction(&key, txn)?;
            }
        }
        // The pointer lives in a column family of its own, so it is not among
        // the index keys above and nothing there sweeps it up. A row that
        // moves to another triple leaves the pointer it stamped naming it,
        // and `latest_attempt` for the triple it left would answer with a row
        // whose own fields name a different one. Where the family is not
        // registered there is no pointer to strand, so its absence is not an
        // error here — unlike a finalization, which would lose the record of
        // which attempt is current.
        let pointer_key = latest_pointer_key(&new.host, &new.target, new.instance)?;
        let vacated = match stored {
            Some(stored) => {
                let vacated = latest_pointer_key(&stored.host, &stored.target, stored.instance)?;
                (vacated != pointer_key).then_some(vacated)
            }
            None => None,
        };
        if let Some(vacated) = &vacated
            && let Some(latest) = Map::open(self.map.db, super::OPERATION_ATTEMPT_LATEST)
        {
            let holder = txn
                .get_for_update_cf(latest.cf, vacated, EXCLUSIVE)
                .context("cannot read the latest pointer")?;
            if holder.is_some_and(|holder| holder == new.idempotency_key.as_bytes()) {
                latest.delete_with_transaction(vacated, txn)?;
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
        // The row and the pointer are two column families and one
        // transaction. A crash between them would leave a pointer naming an
        // attempt that is no longer current, silently, because nothing else
        // records which attempt is latest.
        //
        // The write that stamps the finalization is what moves the pointer,
        // along with one that carries an already-finalized row to another
        // triple, which is the one other way a triple's latest attempt
        // changes. A re-write of a row finalized earlier is neither: it
        // finalizes nothing, and stamping the pointer again would name it
        // current over an attempt that finalized after it.
        let newly_finalized = stored.is_none_or(|stored| stored.finalized_at.is_none());
        if new.finalized_at.is_some() && (newly_finalized || vacated.is_some()) {
            self.latest_pointer()?.put_with_transaction(
                &pointer_key,
                new.idempotency_key.as_bytes(),
                txn,
            )?;
        }
        Ok(())
    }

    /// Returns the column family holding the latest pointers.
    ///
    /// It is registered by the migration that bumps the database format, not
    /// by this table, so a store predating that bump has none. Reporting its
    /// absence is the whole point: a finalization that quietly skipped the
    /// pointer would leave the triple with no record of which attempt is
    /// current, which is exactly what the pointer exists to hold.
    fn latest_pointer(&self) -> Result<Map<'_>> {
        Map::open(self.map.db, super::OPERATION_ATTEMPT_LATEST)
            .context("the latest operation attempt column family is not registered")
    }

    /// Returns the idempotency key the latest pointer holds for the triple.
    fn pointed_at_key(
        &self,
        host: &str,
        target: &str,
        instance: Option<u32>,
    ) -> Result<Option<String>> {
        let key = latest_pointer_key(host, target, instance)?;
        let latest = self.latest_pointer()?;
        let Some(idempotency_key) = latest.get(&key)? else {
            return Ok(None);
        };
        Ok(Some(
            std::str::from_utf8(idempotency_key.as_ref())
                .context("the latest pointer holds an invalid idempotency key")?
                .to_string(),
        ))
    }

    /// Returns the attempt the latest pointer names for the triple.
    ///
    /// Private, because the pointer is the last of the three steps
    /// [`Table::latest_attempt`] takes and not an answer on its own: a
    /// terminal attempt still owing a cleanup has no pointer entry, so a
    /// reader that came here directly would be told about a superseded
    /// attempt while newer work is still owed.
    fn pointed_at_attempt(
        &self,
        host: &str,
        target: &str,
        instance: Option<u32>,
    ) -> Result<Option<OperationAttempt>> {
        let Some(idempotency_key) = self.pointed_at_key(host, target, instance)? else {
            return Ok(None);
        };
        self.get(&idempotency_key)
    }

    /// Returns the latest-pointer key of the attempt's triple, if the pointer
    /// there names this attempt, and nothing otherwise.
    ///
    /// At most one pointer can name a row: the pointer is keyed by the
    /// triple, and a row names one triple.
    fn pointer_keys_held_by(&self, attempt: &OperationAttempt) -> Result<Vec<Vec<u8>>> {
        let pointed_at = self.pointed_at_key(&attempt.host, &attempt.target, attempt.instance)?;
        if pointed_at.as_deref() != Some(attempt.idempotency_key.as_str()) {
            return Ok(Vec::new());
        }
        Ok(vec![latest_pointer_key(
            &attempt.host,
            &attempt.target,
            attempt.instance,
        )?])
    }

    /// Returns whether the latest pointer names this attempt, locking the
    /// pointer entry for the duration of `txn`.
    ///
    /// This is the transactional form of the rank-1 keep-rule that
    /// [`Table::prunable`] applies, and it is what makes "the prune never
    /// removes the row the pointer names" hold against a concurrent
    /// finalization rather than only against the snapshot the ranking read.
    fn pointer_names(
        &self,
        attempt: &OperationAttempt,
        txn: &Transaction<'_, OptimisticTransactionDB>,
    ) -> Result<bool> {
        let key = latest_pointer_key(&attempt.host, &attempt.target, attempt.instance)?;
        let latest = self.latest_pointer()?;
        let Some(named) = txn
            .get_for_update_cf(latest.cf, &key, EXCLUSIVE)
            .context("cannot read the latest pointer")?
        else {
            return Ok(false);
        };
        Ok(named == attempt.idempotency_key.as_bytes())
    }

    /// Returns every latest-pointer key naming `idempotency_key`.
    ///
    /// This scans the pointer family, so it is only for the repair path in
    /// [`Table::delete`], where the row is unreadable and there is nothing
    /// left to derive its triple from.
    fn pointer_keys_naming(&self, idempotency_key: &[u8]) -> Result<Vec<Vec<u8>>> {
        let latest = self.latest_pointer()?;
        let iter = latest.db.iterator_cf(latest.cf, IteratorMode::Start);

        let mut keys = Vec::new();
        for entry in iter {
            let (key, value) = entry.context("cannot read the latest pointer")?;
            if value.as_ref() == idempotency_key {
                keys.push(key.to_vec());
            }
        }
        Ok(keys)
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

    /// A request key in the form the client-supplied one takes: a `UUIDv4`,
    /// canonical and hyphenated, and so lowercase.
    const REQUEST_KEY: &str = "9d5cb6e0-0a3f-41de-9f0a-6b0f4e5c1a27";
    const OTHER_REQUEST_KEY: &str = "3f2c8b41-5e6d-4a7b-b8c9-0d1e2f3a4b5c";

    /// The digest of [`golden_intent`], which pins the transcript.
    const GOLDEN_DIGEST: &str = "4b3062211c665de1d18371cdc00bd92ee3ca139c40bd8e9c0c8cbe138295b6d1";

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

    /// A database carrying this table's column family.
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
            // The latest-pointer family is not in `MAP_NAMES`: the migration
            // that bumps the database format registers it, so a test opens it
            // beside the rest here rather than waiting for that.
            let names: Vec<&str> = super::super::MAP_NAMES
                .into_iter()
                .chain([super::super::OPERATION_ATTEMPT_LATEST])
                .collect();
            let db = OptimisticTransactionDB::open_cf(&opts, dir.path().join("states.db"), names)
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

        /// Every idempotency key the latest pointers name.
        fn pointed_at_keys(&self) -> Vec<String> {
            let cf = self
                .db
                .cf_handle(super::super::OPERATION_ATTEMPT_LATEST)
                .unwrap();
            self.db
                .iterator_cf(cf, IteratorMode::Start)
                .map(|entry| String::from_utf8(entry.unwrap().1.to_vec()).unwrap())
                .collect()
        }
    }

    fn timestamp(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    /// A module attempt: the instance dimension applies, so it is recorded.
    ///
    /// It is an update rather than an install, because an update is keyed by
    /// a `REview`-generated value and carries no request digest — which is
    /// what lets the tests below key one by a readable name. An install is
    /// built by [`install_attempt`].
    fn module_attempt(idempotency_key: &str) -> OperationAttempt {
        OperationAttempt {
            idempotency_key: idempotency_key.to_string(),
            host: "host-a.example".to_string(),
            target: "sensor".to_string(),
            instance: Some(1),
            action: Action::Update,
            install_intent: None,
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
            finalized_at: None,
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
            install_intent: None,
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
            finalized_at: None,
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
            install_intent: None,
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
            finalized_at: None,
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

    /// An install on the given triple: keyed by the request key the client
    /// supplied and carrying the digest of the request it was submitted with,
    /// which is the only shape the store accepts an install in.
    fn install_attempt(
        request_key: &str,
        host: &str,
        target: &str,
        instance: Option<u32>,
    ) -> OperationAttempt {
        let mut attempt = live_attempt(request_key, host, target, instance);
        attempt.action = Action::Install;
        attempt.install_intent = Some(golden_intent().digest().unwrap());
        attempt
    }

    /// A terminal attempt on the given triple, owing nothing, with
    /// `started_at` and `expires_at` set apart so that a test can tell which
    /// of the two an implementation ordered by.
    ///
    /// It is finalized at its `started_at`, so a test that cares about the
    /// two separately moves `finalized_at` itself.
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
        attempt.finalized_at = Some(timestamp(started_at));
        attempt.expires_at = timestamp(expires_at);
        attempt
    }

    /// The same attempt, owing a cleanup: the obligation is what takes the
    /// finalization instant back off it.
    fn owing(mut attempt: OperationAttempt, cleanup_state: CleanupState) -> OperationAttempt {
        attempt.cleanup_state = Some(cleanup_state);
        attempt.finalized_at = None;
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

    /// How many entries the owed-cleanup key space holds.
    fn owed_cleanup_entries(test_db: &TestDb) -> usize {
        test_db
            .raw_keys()
            .into_iter()
            .filter(|key| key.first() == Some(&OWED_CLEANUP))
            .count()
    }

    /// The request the golden vector is taken over.
    ///
    /// The listener keys are deliberately out of order and the addresses of
    /// both families, so the vector pins the sort and the rendering as well
    /// as the field order.
    fn golden_intent() -> InstallIntent {
        InstallIntent {
            host: "host-a.example".to_string(),
            target: "giganto".to_string(),
            selector: BuildSelector::Version("1.2.3".to_string()),
            on_failure: OnFailure::Rollback,
            bind_addrs: Some(vec![
                (
                    "ingest".to_string(),
                    "[2001:DB8:0:0:0:0:0:1]:38370".parse().unwrap(),
                ),
                ("graphql".to_string(), "192.168.0.1:8443".parse().unwrap()),
            ]),
        }
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
        second.finalized_at = Some(timestamp(1_700_000_100));
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
        // The row's index entries and the pointer that named it go with it,
        // leaving nothing behind.
        assert!(test_db.raw_keys().is_empty());
        assert!(test_db.pointed_at_keys().is_empty());
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
        first_commit.finalized_at = Some(timestamp(1_700_000_300));
        let mut second_commit = module_attempt("op-commit-2");
        second_commit.resolved_commit = "2222222".to_string();
        second_commit.outcome = Some(Outcome::Succeeded);
        second_commit.finalized_at = Some(timestamp(1_700_000_400));

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

        // An attempt that is non-terminal and still owes a cleanup owns an
        // entry in all three indexes, so it is the case that puts the most of
        // the reserved space in the iterator's way.
        let mut owes_cleanup = module_attempt("op-4");
        owes_cleanup.instance = Some(3);
        owes_cleanup.cleanup_state = Some(CleanupState::PendingDeregister);
        table.upsert(&owes_cleanup).unwrap();
        let index_entries = test_db
            .raw_keys()
            .into_iter()
            .filter(|key| key.first().is_some_and(|first| *first >= RESERVED))
            .count();
        assert_eq!(
            index_entries, 9,
            "the three earlier attempts own two entries each, and this one owns three"
        );

        // `keys` unwraps the decode of every item, so this is also the
        // assertion that the bounded scan yields no index key.
        assert_eq!(
            keys(&table, Direction::Forward, None),
            ["op-1", "op-2", "op-3", "op-4"]
        );
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

        // The same holds for the pointer, which a corrupt row cannot name
        // either: it is found by scanning for the key it holds.
        let finalized = terminal_attempt("op-3", HOST, TARGET, Some(2), 1_000, 9_000);
        table.upsert(&finalized).unwrap();
        assert_eq!(test_db.pointed_at_keys(), ["op-3"]);
        table.map.put(b"op-3", b"not a stored value").unwrap();
        table.delete("op-3").unwrap();
        assert!(test_db.pointed_at_keys().is_empty());
        assert_eq!(table.latest_attempt(HOST, TARGET, Some(2)).unwrap(), None);
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
        finalized.finalized_at = Some(timestamp(1_700_000_900));
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
        finished.finalized_at = Some(timestamp(1_700_000_900));
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

    /// Every writer releases the instance number the row it stores gives
    /// back, and reaches for the `instance_allocation` column family to do it.
    /// A store that predates the format bump registering that column family
    /// has none, and can hold no allocation either, so the release is a no-op
    /// rather than a failure: the writes go through exactly as they did. This
    /// `TestDb` is such a store — it opens `MAP_NAMES`, which the column
    /// family is deliberately absent from — so every other test here covers
    /// the same ground; this one says so.
    #[test]
    fn a_store_without_the_allocation_table_writes_as_it_always_did() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // A failed install of a numbered instance: the one write that would
        // release a number if there were a column family holding one.
        let mut failed = module_attempt("attempt-1");
        failed.phase = Phase::Completed;
        failed.outcome = Some(Outcome::Failed);
        failed.finalized_at = Some(timestamp(1_700_000_500));
        table.upsert(&failed).unwrap();
        assert_eq!(table.get("attempt-1").unwrap().unwrap(), failed);

        let live = live_attempt("attempt-2", "host-b.example", "sensor", Some(1));
        table.upsert(&live).unwrap();
        assert_eq!(table.sweep_expired(timestamp(1_700_086_400)).unwrap(), 1);
        assert_eq!(
            table.get("attempt-2").unwrap().unwrap().outcome,
            Some(Outcome::Failed)
        );
    }

    /// Taking a number is the other direction, and there the absent column
    /// family is a refusal rather than a no-op: there is nowhere to record
    /// that the number is taken, so handing one out would number an instance
    /// against nothing. Nothing is written at all.
    #[test]
    fn a_store_without_the_allocation_table_cannot_hand_out_a_number() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let attempt = module_attempt("attempt-1");
        let error = table
            .allocate_instance(&attempt)
            .expect_err("there is no column family to take a number from");
        assert!(
            matches!(error, InstanceAllocationError::Database(_)),
            "expected a database refusal, got {error:?}"
        );
        assert_eq!(table.get("attempt-1").unwrap(), None);
    }

    #[test]
    fn finalizes_an_attempt_whose_host_never_returned() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let mut attempt = install_attempt(REQUEST_KEY, HOST, TARGET, Some(1));
        attempt.started_at = timestamp(1_700_000_000);
        attempt.expires_at = timestamp(1_700_000_500);
        attempt.cleanup_state = Some(CleanupState::PendingIdentityTeardown);
        table.create_or_resolve(&attempt).unwrap();

        let instant = timestamp(1_700_000_501);
        assert_eq!(
            table.expired_attempts(instant).unwrap(),
            vec![attempt.clone()]
        );
        assert_eq!(table.sweep_expired(instant).unwrap(), 1);

        let swept = table.get(REQUEST_KEY).unwrap().unwrap();
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
            table.attempt_owing_cleanup(TARGET, HOST, Some(1)).unwrap(),
            Some(swept.clone())
        );
        // It is terminal and not finished with, so nothing stamped it and the
        // retention sweep cannot reach it.
        assert_eq!(swept.finalized_at, None);

        // Running the sweep again over swept state finalizes nothing.
        assert_eq!(table.sweep_expired(instant).unwrap(), 0);
        assert_eq!(table.get(REQUEST_KEY).unwrap(), Some(swept));
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
        let mut install = install_attempt(REQUEST_KEY, HOST, TARGET, Some(1));
        install.expires_at = onboard.expires_at;
        table.upsert(&onboard).unwrap();
        table.create_or_resolve(&install).unwrap();

        // The deadline belongs to every action, so one sweep takes both.
        assert_eq!(table.sweep_expired(onboard.expires_at).unwrap(), 2);
        for key in ["op-onboard", REQUEST_KEY] {
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

        let mut owing_attempt = owing(
            live_attempt("op-owing", HOST, TARGET, Some(1)),
            CleanupState::PendingDeregister,
        );
        let owes_nothing = live_attempt("op-clear", HOST, TARGET, Some(2));
        let terminal_owing = owing(
            terminal_attempt("op-terminal", HOST, TARGET, Some(3), 1_000, 9_000),
            CleanupState::PendingIdentityTeardown,
        );
        for attempt in [&owing_attempt, &owes_nothing, &terminal_owing] {
            table.upsert(attempt).unwrap();
        }

        assert_eq!(
            table.attempt_owing_cleanup(TARGET, HOST, Some(1)).unwrap(),
            Some(owing_attempt.clone())
        );
        assert_eq!(
            table.attempt_owing_cleanup(TARGET, HOST, Some(2)).unwrap(),
            None
        );
        // The obligation outlives the outcome, so a terminal row answers.
        assert_eq!(
            table.attempt_owing_cleanup(TARGET, HOST, Some(3)).unwrap(),
            Some(terminal_owing)
        );

        // Clearing the cleanup drops the row from the index.
        owing_attempt.cleanup_state = None;
        table.upsert(&owing_attempt).unwrap();
        assert_eq!(
            table.attempt_owing_cleanup(TARGET, HOST, Some(1)).unwrap(),
            None
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
            owed_cleanup_key("ab", "c", Some(1)).unwrap(),
            owed_cleanup_key("a", "bc", Some(1)).unwrap()
        );
        assert_ne!(
            latest_pointer_key("ab", "c", Some(1)).unwrap(),
            latest_pointer_key("a", "bc", Some(1)).unwrap()
        );

        let test_db = TestDb::new();
        let table = test_db.table();

        let first = owing(
            live_attempt("op-ab-c", "ab", "c", Some(1)),
            CleanupState::PendingDeregister,
        );
        let second = owing(
            live_attempt("op-a-bc", "a", "bc", Some(1)),
            CleanupState::PendingDeregister,
        );
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
            table.attempt_owing_cleanup("c", "ab", Some(1)).unwrap(),
            Some(first)
        );
        assert_eq!(
            table.attempt_owing_cleanup("bc", "a", Some(1)).unwrap(),
            Some(second)
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
    fn retention_keeps_the_attempt_the_pointer_names() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // The attempt that finalized last has the lesser `started_at`, the
        // lesser `finalized_at` and the lesser idempotency key, so every
        // ordering an implementation could derive "latest" from picks the
        // other one.
        let superseded = terminal_attempt("op-z", HOST, TARGET, Some(1), 3_000, 7_000);
        let current = terminal_attempt("op-a", HOST, TARGET, Some(1), 1_000, 9_000);
        table.upsert(&superseded).unwrap();
        table.upsert(&current).unwrap();

        // A bound no attempt is within, so only the keep-rule decides.
        assert_eq!(table.prune(bound(0, 0), timestamp(10_000)).unwrap(), 1);
        assert_eq!(keys(&table, Direction::Forward, None), ["op-a"]);
        // The pruned row takes its index entries with it, leaving the
        // survivor's row and its `expires_at` entry.
        assert_eq!(test_db.raw_keys().len(), 2);
        assert_eq!(test_db.pointed_at_keys(), ["op-a"]);
    }

    #[test]
    fn the_pointer_names_the_attempt_that_committed_second() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // Both triples finalize the same pair of keys in the same nanosecond,
        // and take them in opposite orders. Nothing but the commit order
        // tells the two apart, so a pointer derived from a timestamp or from
        // key order would answer the same on both.
        let at = DateTime::from_timestamp(1_000, 123_456_789).unwrap();
        let mut attempts = Vec::new();
        for (instance, keys) in [(1, ["op-a1", "op-b1"]), (2, ["op-b2", "op-a2"])] {
            for key in keys {
                let mut attempt = terminal_attempt(key, HOST, TARGET, Some(instance), 1_000, 9_000);
                attempt.finalized_at = Some(at);
                table.upsert(&attempt).unwrap();
                attempts.push(attempt);
            }
        }

        assert_eq!(
            table
                .latest_attempt(HOST, TARGET, Some(1))
                .unwrap()
                .map(|attempt| attempt.idempotency_key),
            Some("op-b1".to_string())
        );
        assert_eq!(
            table
                .latest_attempt(HOST, TARGET, Some(2))
                .unwrap()
                .map(|attempt| attempt.idempotency_key),
            Some("op-a2".to_string())
        );

        // And the keep-rule follows the pointer rather than the tie: what
        // survives a bound nothing is within is what committed second.
        assert_eq!(table.prune(bound(0, 0), timestamp(10_000)).unwrap(), 2);
        assert_eq!(keys(&table, Direction::Forward, None), ["op-a2", "op-b1"]);
    }

    #[test]
    fn retention_measures_age_from_the_finalization_and_not_the_start() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // The two candidates' `started_at` order is the reverse of their
        // `finalized_at` order, so an age measured from the start prunes
        // exactly the other one.
        let mut late_finish = terminal_attempt("op-late", HOST, TARGET, Some(1), 1_000, 9_000);
        late_finish.finalized_at = Some(timestamp(5_000));
        let mut early_finish = terminal_attempt("op-early", HOST, TARGET, Some(1), 4_000, 9_000);
        early_finish.finalized_at = Some(timestamp(2_000));
        let mut current = terminal_attempt("op-current", HOST, TARGET, Some(1), 4_500, 9_000);
        current.finalized_at = Some(timestamp(5_400));
        for attempt in [&late_finish, &early_finish, &current] {
            table.upsert(attempt).unwrap();
        }

        // The count bound never fires, so the age bound alone decides.
        assert_eq!(table.prune(bound(2_000, 10), timestamp(5_500)).unwrap(), 1);
        assert_eq!(
            keys(&table, Direction::Forward, None),
            ["op-current", "op-late"]
        );
    }

    #[test]
    fn retention_keeps_the_current_attempt_well_past_thirty_days() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // The rule this table is built to: an older terminal attempt goes 30
        // days past its finalization, and the current one never does.
        let thirty_days = RetentionBound {
            max_age: TimeDelta::days(30),
            max_terminal_per_triple: usize::MAX,
        };
        let superseded = terminal_attempt("op-1-old", HOST, TARGET, Some(1), 1_000, 9_000);
        let current = terminal_attempt("op-1-current", HOST, TARGET, Some(1), 2_000, 9_000);
        // A second instance of the same module on the same host is a triple
        // of its own, and a newer attempt on `(host, target)` does not
        // collapse it away.
        let sibling = terminal_attempt("op-2-only", HOST, TARGET, Some(2), 1_000, 9_000);
        for attempt in [&superseded, &current, &sibling] {
            table.upsert(attempt).unwrap();
        }

        let a_year_on = timestamp(1_000) + TimeDelta::days(365);
        assert_eq!(table.prune(thirty_days, a_year_on).unwrap(), 1);
        assert_eq!(
            keys(&table, Direction::Forward, None),
            ["op-1-current", "op-2-only"]
        );
        assert_eq!(
            table.latest_attempt(HOST, TARGET, Some(1)).unwrap(),
            Some(current)
        );
        assert_eq!(
            table.latest_attempt(HOST, TARGET, Some(2)).unwrap(),
            Some(sibling)
        );
    }

    #[test]
    fn retention_keeps_one_terminal_attempt_for_each_triple() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let owes_cleanup = owing(
            terminal_attempt("op-owing", HOST, TARGET, Some(8), 1_000, 9_000),
            CleanupState::PendingDeregister,
        );
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
            owes_cleanup,
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

        let owes_cleanup = owing(
            terminal_attempt("op-owing", HOST, TARGET, Some(3), 1_000, 9_000),
            CleanupState::PendingIdentityTeardown,
        );
        let attempts = [
            terminal_attempt("op-newest", HOST, TARGET, Some(1), 1_000, 9_000),
            live_attempt("op-live", HOST, TARGET, Some(2)),
            owes_cleanup,
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
    fn the_owed_cleanup_index_holds_one_entry_for_each_triple() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // What this crate asserts is what the store does when a second row
        // for one triple is written: the entry is overwritten rather than
        // queued beside the first, so the lookup always has a single row to
        // return. That a second row never arises in the first place is the
        // owed-teardown guard, and it is asserted in the repository whose
        // orchestration drives that path.
        let mut first = owing(
            terminal_attempt("op-a", HOST, TARGET, Some(1), 1_000, 9_000),
            CleanupState::PendingIdentityTeardown,
        );
        let mut second = owing(
            terminal_attempt("op-b", HOST, TARGET, Some(1), 2_000, 9_000),
            CleanupState::PendingDeregister,
        );
        table.upsert(&first).unwrap();
        table.upsert(&second).unwrap();

        assert_eq!(
            table.attempt_owing_cleanup(TARGET, HOST, Some(1)).unwrap(),
            Some(second.clone())
        );
        assert_eq!(owed_cleanup_entries(&test_db), 1);

        // Discharging the row the entry no longer names leaves it standing:
        // dropping it there would lose an obligation that is still owed.
        first.cleanup_state = None;
        first.finalized_at = Some(timestamp(3_000));
        table.upsert(&first).unwrap();
        assert_eq!(
            table.attempt_owing_cleanup(TARGET, HOST, Some(1)).unwrap(),
            Some(second.clone())
        );
        assert_eq!(owed_cleanup_entries(&test_db), 1);

        // Discharging the row it does name clears it.
        second.cleanup_state = None;
        second.finalized_at = Some(timestamp(4_000));
        table.upsert(&second).unwrap();
        assert_eq!(
            table.attempt_owing_cleanup(TARGET, HOST, Some(1)).unwrap(),
            None
        );
        assert_eq!(owed_cleanup_entries(&test_db), 0);
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
            table.attempt_owing_cleanup("", &here.host, None).unwrap(),
            Some(here.clone())
        );
        assert_eq!(
            table.attempt_owing_cleanup("", &there.host, None).unwrap(),
            Some(there)
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
            table.attempt_owing_cleanup("", &owed.host, None).unwrap(),
            Some(owed)
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

    #[test]
    fn the_latest_attempt_is_one_ordered_lookup_over_three_branches() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // One triple walked through the states the three branches answer in,
        // rather than three lookups set up apart: the order is the rule, and
        // a branch tested on its own would not exercise it.
        //
        // An earlier attempt, finished with, so the pointer names it.
        let older = terminal_attempt("op-older", HOST, TARGET, Some(1), 1_000, 9_000);
        table.upsert(&older).unwrap();
        assert_eq!(
            table.latest_attempt(HOST, TARGET, Some(1)).unwrap(),
            Some(older)
        );

        // A new attempt starts with the teardown of its minted identity armed
        // before it, so it is non-terminal and owes a cleanup at once and
        // stands under both indexes while the pointer still names the older
        // row. The first branch answers.
        let running = owing(
            live_attempt("op-newer", HOST, TARGET, Some(1)),
            CleanupState::PendingIdentityTeardown,
        );
        table.upsert(&running).unwrap();
        assert_eq!(
            table.pointed_at_key(HOST, TARGET, Some(1)).unwrap(),
            Some("op-older".to_string())
        );
        assert_eq!(
            table.latest_attempt(HOST, TARGET, Some(1)).unwrap(),
            Some(running.clone())
        );

        // It fails with the teardown still owed. The first branch is empty,
        // it carries no finalization instant so the pointer still names the
        // older row, and the second branch is what answers — the newer work
        // rather than the row the pointer names.
        let mut failed = running;
        failed.outcome = Some(Outcome::Failed);
        table.upsert(&failed).unwrap();
        assert_eq!(table.live_attempt(HOST, TARGET, Some(1)).unwrap(), None);
        assert_eq!(
            table.pointed_at_key(HOST, TARGET, Some(1)).unwrap(),
            Some("op-older".to_string())
        );
        assert_eq!(
            table.latest_attempt(HOST, TARGET, Some(1)).unwrap(),
            Some(failed.clone())
        );

        // The teardown is discharged, which stamps the row and moves the
        // pointer in the same transaction. The first two branches are empty
        // and the pointer answers.
        let mut discharged = failed;
        discharged.cleanup_state = None;
        discharged.finalized_at = Some(timestamp(4_000));
        table.upsert(&discharged).unwrap();
        assert_eq!(
            table.attempt_owing_cleanup(TARGET, HOST, Some(1)).unwrap(),
            None
        );
        assert_eq!(
            table.pointed_at_key(HOST, TARGET, Some(1)).unwrap(),
            Some("op-newer".to_string())
        );
        assert_eq!(
            table.latest_attempt(HOST, TARGET, Some(1)).unwrap(),
            Some(discharged)
        );

        // A triple nothing was ever written for has no answer at all.
        assert_eq!(table.latest_attempt(HOST, TARGET, Some(2)).unwrap(), None);
    }

    #[test]
    fn finalization_is_stamped_exactly_when_the_attempt_is_finished_with() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // Terminal and owing nothing, but unstamped: the row would be
        // finished with and no retention clock would ever start on it.
        let mut unstamped = terminal_attempt("op-1", HOST, TARGET, Some(1), 1_000, 9_000);
        unstamped.finalized_at = None;
        assert!(table.upsert(&unstamped).is_err());

        // Stamped while still running.
        let mut running = live_attempt("op-1", HOST, TARGET, Some(1));
        running.finalized_at = Some(timestamp(1_000));
        assert!(table.upsert(&running).is_err());

        // Stamped while a teardown is still owed, which is the case the
        // distinction exists for: an apply that terminated `Failed` with work
        // outstanding is terminal and not finished with.
        let mut owing_and_stamped = owing(
            terminal_attempt("op-1", HOST, TARGET, Some(1), 1_000, 9_000),
            CleanupState::PendingIdentityTeardown,
        );
        owing_and_stamped.finalized_at = Some(timestamp(1_000));
        assert!(table.upsert(&owing_and_stamped).is_err());
        assert_eq!(table.get("op-1").unwrap(), None);

        // The same row without the stamp is accepted, is not reachable by the
        // retention sweep, and names no pointer.
        let terminal_owing = owing(
            terminal_attempt("op-1", HOST, TARGET, Some(1), 1_000, 9_000),
            CleanupState::PendingIdentityTeardown,
        );
        table.upsert(&terminal_owing).unwrap();
        assert_eq!(
            table.prune(bound(0, 0), timestamp(1_000_000)).unwrap(),
            0,
            "a terminal attempt that still owes a cleanup is out of the sweep's reach"
        );
        assert!(test_db.pointed_at_keys().is_empty());

        // Discharging the last owed item stamps it and moves the pointer, in
        // the transaction that discharges it.
        let mut discharged = terminal_owing;
        discharged.cleanup_state = None;
        discharged.finalized_at = Some(timestamp(2_000));
        table.upsert(&discharged).unwrap();
        assert_eq!(
            table.get("op-1").unwrap().unwrap().finalized_at,
            Some(timestamp(2_000))
        );
        assert_eq!(test_db.pointed_at_keys(), ["op-1"]);
    }

    #[test]
    fn a_finalization_that_does_not_commit_leaves_neither_the_row_nor_the_pointer() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let running = live_attempt("op-1", HOST, TARGET, Some(1));
        table.upsert(&running).unwrap();

        let mut finalized = running.clone();
        finalized.outcome = Some(Outcome::Succeeded);
        finalized.finalized_at = Some(timestamp(2_000));

        // The fault, injected between the two writes the pair is made of: the
        // transaction carries both and commits neither.
        let txn = table.transaction();
        table
            .write_with_transaction(Some(&running), &finalized, &txn)
            .unwrap();
        drop(txn);

        assert_eq!(table.get("op-1").unwrap(), Some(running.clone()));
        assert!(
            test_db.pointed_at_keys().is_empty(),
            "no pointer may name an attempt whose finalization did not land"
        );
        assert_eq!(
            table.latest_attempt(HOST, TARGET, Some(1)).unwrap(),
            Some(running.clone())
        );

        // The same pair, committed, lands whole.
        let txn = table.transaction();
        table
            .write_with_transaction(Some(&running), &finalized, &txn)
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(table.get("op-1").unwrap(), Some(finalized.clone()));
        assert_eq!(test_db.pointed_at_keys(), ["op-1"]);
        assert_eq!(
            table.latest_attempt(HOST, TARGET, Some(1)).unwrap(),
            Some(finalized)
        );
    }

    #[test]
    fn the_install_intent_is_stored_for_an_install_alone() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let digest = golden_intent().digest().unwrap();
        let mut install = module_attempt(REQUEST_KEY);
        install.action = Action::Install;
        install.install_intent = Some(digest);
        table.create_or_resolve(&install).unwrap();
        assert_eq!(
            table.get(REQUEST_KEY).unwrap().unwrap().install_intent,
            Some(digest)
        );
        assert_eq!(round_trip(&install), install);

        // An attempt carrying one is keyed by the request key the client
        // supplied, so a key that is not one of those is refused: nothing
        // could ever resolve the row again.
        let mut generated_key = install.clone();
        generated_key.idempotency_key = "op-install".to_string();
        generated_key.instance = Some(5);
        assert!(matches!(
            table
                .create_or_resolve(&generated_key)
                .unwrap_err()
                .downcast_ref::<RequestKeyError>(),
            Some(RequestKeyError::MalformedRequestKey { .. })
        ));

        // And an install without one is refused for the same reason from the
        // other side: nothing could compare a resubmission against it, so the
        // retry would allocate a second instance instead of returning this
        // row.
        let mut without_intent = install.clone();
        without_intent.install_intent = None;
        assert!(table.upsert(&without_intent).is_err());

        // Update, remove and onboard are keyed by a value that is unique by
        // construction, so they have nothing to compare and store none.
        for (key, action, instance) in [
            ("op-update", Action::Update, 2),
            ("op-remove", Action::Remove, 3),
            ("op-onboard", Action::Onboard, 4),
        ] {
            let mut attempt = module_attempt(key);
            attempt.action = action;
            attempt.instance = Some(instance);
            table.upsert(&attempt).unwrap();
            assert_eq!(table.get(key).unwrap().unwrap().install_intent, None);

            attempt.install_intent = Some(digest);
            assert!(table.upsert(&attempt).is_err());
        }
    }

    #[test]
    fn the_install_intent_digest_matches_its_golden_vector() {
        // Written out byte by byte rather than derived, so a change to the
        // transcript fails here rather than in a deployment, where it would
        // turn every retry that crossed an update into a refusal.
        let mut expected = Vec::new();
        expected.extend_from_slice(b"clumit-install-intent-v1");
        expected.extend_from_slice(&[0, 0, 0, 14]);
        expected.extend_from_slice(b"host-a.example");
        expected.extend_from_slice(&[0, 0, 0, 7]);
        expected.extend_from_slice(b"giganto");
        // The selector kind, then its value as submitted.
        expected.push(0);
        expected.extend_from_slice(&[0, 0, 0, 5]);
        expected.extend_from_slice(b"1.2.3");
        // `on_failure`.
        expected.push(0);
        // Two bind addresses, in ascending listener-key order rather than the
        // order they were handed over in, each rendered by `SocketAddr`'s own
        // `Display`: lowercase, compressed, and in brackets for IPv6.
        expected.extend_from_slice(&[0, 0, 0, 2]);
        expected.extend_from_slice(&[0, 0, 0, 7]);
        expected.extend_from_slice(b"graphql");
        expected.extend_from_slice(&[0, 0, 0, 16]);
        expected.extend_from_slice(b"192.168.0.1:8443");
        expected.extend_from_slice(&[0, 0, 0, 6]);
        expected.extend_from_slice(b"ingest");
        expected.extend_from_slice(&[0, 0, 0, 19]);
        expected.extend_from_slice(b"[2001:db8::1]:38370");

        let intent = golden_intent();
        assert_eq!(intent.transcript().unwrap(), expected);
        assert_eq!(
            data_encoding::HEXLOWER.encode(&intent.digest().unwrap()),
            GOLDEN_DIGEST
        );

        // The listener order the caller used is not the transcript's, so two
        // requests naming the same listeners hash alike.
        let mut reordered = intent.clone();
        reordered.bind_addrs.as_mut().unwrap().reverse();
        assert_eq!(reordered.digest().unwrap(), intent.digest().unwrap());
    }

    #[test]
    fn no_two_requests_share_an_install_intent_digest() {
        let intent = golden_intent();
        let digest = intent.digest().unwrap();

        // `None` leaves the addresses to the component and an empty list asks
        // for none at all, so the two are different requests.
        let mut absent = intent.clone();
        absent.bind_addrs = None;
        let mut empty = intent.clone();
        empty.bind_addrs = Some(Vec::new());
        assert_ne!(absent.digest().unwrap(), empty.digest().unwrap());

        let mut other_host = intent.clone();
        other_host.host = "host-b.example".to_string();
        let mut other_target = intent.clone();
        other_target.target = "piglet".to_string();
        // The kind tag is what tells a version from a commit that reads alike.
        let mut as_commit = intent.clone();
        as_commit.selector = BuildSelector::Commit("1.2.3".to_string());
        let mut on_hold = intent.clone();
        on_hold.on_failure = OnFailure::Hold;
        let mut other_listener = intent.clone();
        other_listener.bind_addrs.as_mut().unwrap()[0].0 = "ingestion".to_string();
        let mut other_addr = intent.clone();
        other_addr.bind_addrs.as_mut().unwrap()[1].1 = "192.168.0.1:8444".parse().unwrap();
        // The length prefixes are what stop a field boundary from shifting.
        let mut shifted = intent.clone();
        shifted.host = "host-a.exampl".to_string();
        shifted.target = "egiganto".to_string();

        for other in [
            absent,
            empty,
            other_host,
            other_target,
            as_commit,
            on_hold,
            other_listener,
            other_addr,
            shifted,
        ] {
            assert_ne!(other.digest().unwrap(), digest);
        }
    }

    #[test]
    fn a_resubmitted_request_key_returns_its_attempt_or_is_refused() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let intent = golden_intent();
        let digest = intent.digest().unwrap();
        let mut other = intent.clone();
        other.selector = BuildSelector::Version("1.2.4".to_string());
        let other_digest = other.digest().unwrap();

        // A key that is not a UUIDv4 in canonical hyphenated form is refused
        // on its shape, before anything is read.
        for malformed in [
            "",
            "op-1",
            REQUEST_KEY.trim_end_matches('7'),
            &REQUEST_KEY.replace('-', ""),
            // The version nibble is not `4`.
            "9d5cb6e0-0a3f-31de-9f0a-6b0f4e5c1a27",
            // The variant nibble is none of `8`, `9`, `a` or `b`.
            "9d5cb6e0-0a3f-41de-7f0a-6b0f4e5c1a27",
            // A hyphen out of place.
            "9d5cb6e00-a3f-41de-9f0a-6b0f4e5c1a27",
            // Not a hex digit.
            "9d5cb6e0-0a3f-41de-9f0a-6b0f4e5c1a2g",
        ] {
            let error = table.resolve_request_key(malformed, &digest).unwrap_err();
            assert!(matches!(error, RequestKeyError::MalformedRequestKey { .. }));
            assert!(!error.is_retryable());
        }

        // A key nothing is held under is free, and the install proceeds.
        assert_eq!(
            table.resolve_request_key(REQUEST_KEY, &digest).unwrap(),
            None
        );

        let mut install = module_attempt(REQUEST_KEY);
        install.action = Action::Install;
        install.install_intent = Some(digest);
        table.create_or_resolve(&install).unwrap();

        // The same request returns the first attempt, which is what makes a
        // retry idempotent.
        assert_eq!(
            table.resolve_request_key(REQUEST_KEY, &digest).unwrap(),
            Some(install)
        );

        // A different one is a client bug, and sending it again would refuse
        // it again.
        let error = table
            .resolve_request_key(REQUEST_KEY, &other_digest)
            .unwrap_err();
        assert!(matches!(
            error,
            RequestKeyError::RequestKeyReused { request_key } if request_key == REQUEST_KEY
        ));
        assert!(
            !table
                .resolve_request_key(REQUEST_KEY, &other_digest)
                .unwrap_err()
                .is_retryable()
        );

        // A stored `None` presented with a digest is refused in the same way:
        // an operation that dedupes on something else has nothing to compare.
        let mut update = module_attempt(OTHER_REQUEST_KEY);
        update.action = Action::Update;
        update.instance = Some(2);
        table.upsert(&update).unwrap();
        let error = table
            .resolve_request_key(OTHER_REQUEST_KEY, &digest)
            .unwrap_err();
        assert!(matches!(error, RequestKeyError::RequestKeyReused { .. }));
        assert!(!error.is_retryable());
    }

    #[test]
    fn an_uppercase_request_key_is_refused_on_both_paths() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let digest = golden_intent().digest().unwrap();

        // Canonical is lowercase, so an uppercase spelling of an otherwise
        // well-formed key is refused rather than admitted as a second key for
        // the one UUID.
        for uppercase in [
            REQUEST_KEY.to_uppercase(),
            // A single uppercase hex digit is enough.
            REQUEST_KEY.replace("de", "De"),
            // The variant nibble included, which this key spells `b`.
            OTHER_REQUEST_KEY.replace("-b8c9-", "-B8c9-"),
        ] {
            assert!(!is_uuid_v4(&uppercase));

            let error = table.resolve_request_key(&uppercase, &digest).unwrap_err();
            assert!(matches!(error, RequestKeyError::MalformedRequestKey { .. }));
            assert!(!error.is_retryable());

            // The write path refuses it too: a row keyed by a spelling
            // `resolve_request_key` will not take is a row no retry can find.
            let install = install_attempt(&uppercase, HOST, TARGET, Some(1));
            assert!(matches!(
                table
                    .create_or_resolve(&install)
                    .unwrap_err()
                    .downcast_ref::<RequestKeyError>(),
                Some(RequestKeyError::MalformedRequestKey { .. })
            ));
            assert_eq!(table.get(&uppercase).unwrap(), None);
        }

        // The lowercase key holds the row, and the uppercase spelling of that
        // same UUID does not reach it.
        let install = install_attempt(REQUEST_KEY, HOST, TARGET, Some(1));
        table.create_or_resolve(&install).unwrap();
        assert_eq!(
            table.resolve_request_key(REQUEST_KEY, &digest).unwrap(),
            Some(install)
        );
        assert!(matches!(
            table
                .resolve_request_key(&REQUEST_KEY.to_uppercase(), &digest)
                .unwrap_err(),
            RequestKeyError::MalformedRequestKey { .. }
        ));
    }

    #[test]
    fn a_second_request_under_one_key_cannot_overwrite_the_first_attempt() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let intent = golden_intent();
        let digest = intent.digest().unwrap();
        let mut other = intent.clone();
        other.selector = BuildSelector::Version("1.2.4".to_string());
        let other_digest = other.digest().unwrap();

        let first = install_attempt(REQUEST_KEY, HOST, TARGET, Some(1));
        let mut second = install_attempt(REQUEST_KEY, HOST, TARGET, Some(2));
        second.install_intent = Some(other_digest);

        // The race `resolve_request_key` cannot close on its own: it answers
        // before the write and outside it, so both requests read the key while
        // nothing is held under it and both believe they are creating the row.
        assert_eq!(
            table.resolve_request_key(REQUEST_KEY, &digest).unwrap(),
            None
        );
        assert_eq!(
            table
                .resolve_request_key(REQUEST_KEY, &other_digest)
                .unwrap(),
            None
        );

        let losing = table.transaction();
        assert_eq!(table.get_for_update(REQUEST_KEY, &losing).unwrap(), None);
        assert_eq!(table.create_or_resolve(&first).unwrap(), first);

        // The write composed against that reading does not land: it read the
        // key as free and the winner has since taken it.
        table
            .write_with_transaction(None, &second, &losing)
            .unwrap();
        assert!(losing.commit().is_err());
        assert_eq!(table.get(REQUEST_KEY).unwrap(), Some(first.clone()));

        // And the retry that conflict drives — which is what
        // `create_or_resolve` does on its own — refuses the second request
        // rather than replacing the row the first created, so the first
        // attempt keeps its record and the allocations that hang off it.
        let error = table.create_or_resolve(&second).unwrap_err();
        let error = error.downcast::<RequestKeyError>().unwrap();
        assert!(matches!(
            &error,
            RequestKeyError::RequestKeyReused { request_key } if request_key == REQUEST_KEY
        ));
        assert!(!error.is_retryable());
        assert_eq!(table.get(REQUEST_KEY).unwrap(), Some(first.clone()));
        assert_eq!(
            table.resolve_request_key(REQUEST_KEY, &digest).unwrap(),
            Some(first.clone())
        );

        // The attempt's own re-writes carry the digest unchanged and are not
        // refused: this is the same request, still running.
        let mut progressed = first.clone();
        progressed.phase = Phase::Dispatched;
        table.upsert(&progressed).unwrap();
        assert_eq!(table.get(REQUEST_KEY).unwrap(), Some(progressed));

        // A change in whether a digest is carried at all is a change of
        // action, which is a different request too.
        let mut update = module_attempt(REQUEST_KEY);
        update.instance = Some(3);
        let error = table.upsert(&update).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<RequestKeyError>(),
            Some(RequestKeyError::RequestKeyReused { .. })
        ));
    }

    #[test]
    fn a_same_intent_retry_returns_the_first_attempt_rather_than_replacing_it() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let digest = golden_intent().digest().unwrap();

        // One request submitted twice: the same digest, and two rows composed
        // against two independent allocations of the instance number, because
        // each caller believed it was the one creating the attempt.
        let first = install_attempt(REQUEST_KEY, HOST, TARGET, Some(1));
        let mut second = install_attempt(REQUEST_KEY, HOST, TARGET, Some(2));
        second.started_at = timestamp(2_000);

        // Neither learns of the other from the lookup: it answers before the
        // write and outside it, so both are told the key is free.
        for _ in 0..2 {
            assert_eq!(
                table.resolve_request_key(REQUEST_KEY, &digest).unwrap(),
                None
            );
        }

        let losing = table.transaction();
        assert_eq!(table.get_for_update(REQUEST_KEY, &losing).unwrap(), None);
        assert_eq!(table.create_or_resolve(&first).unwrap(), first);

        // The write composed against that reading does not land: it read the
        // key as free and the winner has since taken it.
        table
            .write_with_transaction(None, &second, &losing)
            .unwrap();
        assert!(losing.commit().is_err());

        // The retry that conflict drives re-reads the key before anything
        // else, so the second request is answered with the attempt the first
        // created rather than overwriting it with its own allocation. An
        // equal digest returns the first attempt, which is the whole of the
        // retry guarantee — and the row, its single-flight slot and the
        // lookup all go on naming that attempt.
        assert_eq!(table.create_or_resolve(&second).unwrap(), first);
        assert_eq!(table.get(REQUEST_KEY).unwrap(), Some(first.clone()));
        assert_eq!(
            table.live_attempt(HOST, TARGET, Some(1)).unwrap(),
            Some(first.clone())
        );
        assert_eq!(table.live_attempt(HOST, TARGET, Some(2)).unwrap(), None);
        assert_eq!(
            table.resolve_request_key(REQUEST_KEY, &digest).unwrap(),
            Some(first.clone())
        );

        // `upsert` carries an attempt forward and does not create one: an
        // install it finds no row under is refused, so the decision above
        // cannot be reached around by writing the row directly.
        table.delete(REQUEST_KEY).unwrap();
        assert!(table.upsert(&first).is_err());
        assert_eq!(table.get(REQUEST_KEY).unwrap(), None);
    }

    #[test]
    fn deleting_an_attempt_leaves_the_owed_cleanup_entry_another_row_has_taken() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // The owed-cleanup key is the triple alone, so the second attempt's
        // entry replaces the first's. Deleting the first must not take the
        // entry the second now holds with it: the row would still record the
        // obligation while nothing could find it.
        let first = owing(
            terminal_attempt("op-first", HOST, TARGET, Some(1), 1_000, 9_000),
            CleanupState::PendingIdentityTeardown,
        );
        let second = owing(
            terminal_attempt("op-second", HOST, TARGET, Some(1), 2_000, 9_000),
            CleanupState::PendingDeregister,
        );
        table.upsert(&first).unwrap();
        table.upsert(&second).unwrap();
        assert_eq!(
            table.attempt_owing_cleanup(TARGET, HOST, Some(1)).unwrap(),
            Some(second.clone())
        );

        table.delete("op-first").unwrap();
        assert_eq!(table.get("op-first").unwrap(), None);
        assert_eq!(
            table.attempt_owing_cleanup(TARGET, HOST, Some(1)).unwrap(),
            Some(second)
        );
        assert_eq!(owed_cleanup_entries(&test_db), 1);
    }

    #[test]
    fn two_addresses_under_one_listener_key_are_ordered_by_the_address_too() {
        // The listener keys tie, so an order taken from them alone would
        // leave the transcript in the caller's order, and the same request
        // sent twice would be free to hash differently.
        let mut intent = golden_intent();
        intent.bind_addrs = Some(vec![
            ("ingest".to_string(), "192.168.0.2:38370".parse().unwrap()),
            ("ingest".to_string(), "192.168.0.1:38370".parse().unwrap()),
        ]);
        let mut reordered = intent.clone();
        reordered.bind_addrs.as_mut().unwrap().reverse();
        assert_eq!(intent.digest().unwrap(), reordered.digest().unwrap());
    }

    #[test]
    fn moving_a_finalized_attempt_off_a_triple_takes_its_pointer_with_it() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // The instance is what the allocating call fills in, so a row can
        // come to name another triple. The pointer it stamped on the triple
        // it left would otherwise go on naming it, and a lookup there would
        // answer with a row whose own fields name a different triple.
        let finalized = terminal_attempt("op-move", HOST, TARGET, Some(1), 1_000, 9_000);
        table.upsert(&finalized).unwrap();
        assert_eq!(
            table.latest_attempt(HOST, TARGET, Some(1)).unwrap(),
            Some(finalized.clone())
        );

        let mut moved = finalized.clone();
        moved.instance = Some(2);
        table.upsert(&moved).unwrap();

        assert_eq!(table.latest_attempt(HOST, TARGET, Some(1)).unwrap(), None);
        assert_eq!(
            table.latest_attempt(HOST, TARGET, Some(2)).unwrap(),
            Some(moved)
        );
        assert_eq!(test_db.pointed_at_keys(), vec!["op-move".to_string()]);

        // The pointer another attempt has since taken is not this one's to
        // drop: the entry goes only while it still names the row moving off
        // the triple, so a later finalization there stays findable.
        let sibling = terminal_attempt("op-sibling", HOST, TARGET, Some(2), 3_000, 9_000);
        table.upsert(&sibling).unwrap();
        let mut away = table.get("op-move").unwrap().unwrap();
        away.instance = Some(3);
        table.upsert(&away).unwrap();
        assert_eq!(
            table.latest_attempt(HOST, TARGET, Some(2)).unwrap(),
            Some(sibling)
        );
    }

    #[test]
    fn re_writing_an_older_finalized_attempt_leaves_the_pointer_where_it_is() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // The pointer moves on the write that finalizes, and a row finalized
        // earlier can be written again — a replayed upsert, a field corrected
        // after the fact. Neither finalizes anything, so neither may take the
        // triple back from the attempt that finalized after it.
        let superseded = terminal_attempt("op-a", HOST, TARGET, Some(1), 1_000, 9_000);
        let current = terminal_attempt("op-b", HOST, TARGET, Some(1), 2_000, 9_000);
        table.upsert(&superseded).unwrap();
        table.upsert(&current).unwrap();
        assert_eq!(test_db.pointed_at_keys(), ["op-b"]);

        table.upsert(&superseded).unwrap();
        let mut amended = superseded.clone();
        amended.expires_at = timestamp(11_000);
        table.upsert(&amended).unwrap();

        assert_eq!(test_db.pointed_at_keys(), ["op-b"]);
        assert_eq!(
            table.latest_attempt(HOST, TARGET, Some(1)).unwrap(),
            Some(current)
        );
        // And retention keeps what the pointer names, not what was written
        // last: a bound nothing is within leaves the later finalization.
        assert_eq!(table.prune(bound(0, 0), timestamp(12_000)).unwrap(), 1);
        assert_eq!(keys(&table, Direction::Forward, None), ["op-b"]);
    }

    #[test]
    fn the_dedupe_guarantee_ends_where_retention_does() {
        let test_db = TestDb::new();
        let table = test_db.table();

        // There is no tombstone: a client replaying a request after its row is
        // gone gets a new install rather than a refusal.
        let digest = golden_intent().digest().unwrap();
        let mut superseded = terminal_attempt(REQUEST_KEY, HOST, TARGET, Some(1), 1_000, 9_000);
        superseded.action = Action::Install;
        superseded.install_intent = Some(digest);
        let current = terminal_attempt(OTHER_REQUEST_KEY, HOST, TARGET, Some(1), 2_000, 9_000);
        table.create_or_resolve(&superseded).unwrap();
        table.upsert(&current).unwrap();

        assert!(
            table
                .resolve_request_key(REQUEST_KEY, &digest)
                .unwrap()
                .is_some()
        );
        assert_eq!(table.prune(bound(0, 0), timestamp(10_000)).unwrap(), 1);
        assert_eq!(
            table.resolve_request_key(REQUEST_KEY, &digest).unwrap(),
            None
        );
    }
}
