//! The `operation_attempt` table.
//!
//! This is the durable ledger of the package operations `REview` executes on
//! hosts. It exists so that a `REview` restart can tell which operation was in
//! flight, which build it had resolved to, and which compensation it still
//! owes.

use std::borrow::Cow;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use crate::{Map, Table, UniqueKey, tables::Value as ValueTrait, types::FromKeyValue};

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
}

impl UniqueKey for OperationAttempt {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.idempotency_key.as_bytes()
    }
}

impl ValueTrait for OperationAttempt {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
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

/// Functions for the `operation_attempt` table.
///
/// Iteration comes from the blanket [`Iterable`](crate::Iterable)
/// implementation on [`Table`], whose keys are the idempotency keys in
/// lexicographic order.
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

    /// Stores an attempt, replacing any attempt already held under the same
    /// idempotency key.
    ///
    /// A re-drive or a resume therefore finalizes the existing row in place
    /// instead of adding a second row for the same logical operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the attempt's idempotency key is empty, or if the
    /// database operation fails. An empty key is rejected rather than stored
    /// because the shared table iterator skips one as indexed-table metadata,
    /// which would leave an in-flight or cleanup-owing attempt out of every
    /// scan.
    pub fn upsert(&self, attempt: &OperationAttempt) -> Result<()> {
        if attempt.idempotency_key.is_empty() {
            bail!("an operation attempt key must not be empty");
        }
        self.put(attempt)
    }

    /// Deletes the attempt with the given idempotency key.
    ///
    /// This is for a row that should never have existed; a completed attempt
    /// is finalized in place and retained, not deleted. The key is not checked
    /// for emptiness, so this stays usable to clear a stray empty-key row that
    /// some other writer left behind.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, idempotency_key: &str) -> Result<()> {
        self.map.delete(idempotency_key.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use rocksdb::Direction;

    use super::*;
    use crate::Iterable;
    use crate::test::{DbGuard, acquire_db_permit};

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

    fn round_trip(attempt: &OperationAttempt) -> OperationAttempt {
        OperationAttempt::from_key_value(attempt.unique_key(), &attempt.value()).unwrap()
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

        let mut first_commit = module_attempt("op-commit-1");
        first_commit.resolved_commit = "1111111".to_string();
        let mut second_commit = module_attempt("op-commit-2");
        second_commit.resolved_commit = "2222222".to_string();

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

        for key in ["op-1", "op-2", "op-3"] {
            table.upsert(&module_attempt(key)).unwrap();
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
        table.map.put(b"", &empty_key.value()).unwrap();
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
        let attempt = module_attempt("op-1");
        table.map.put(b"\xff\xfe", &attempt.value()).unwrap();

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
}
