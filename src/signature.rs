//! The signature rule sources a Central Manager keeps for the
//! Semi-supervised Engine's signature models, and what the engines report
//! about them.
//!
//! Per [`SignatureSource`] the store keeps the versions it received, each
//! with its original archive and, once converted, the converter's rule set
//! and result summary, and which of them is applied, kept for rollback or
//! staged for review. It also keeps the rules an operator turned off, the
//! revision of the rule sets pushed to engines, each engine instance's last
//! [`SignatureStatusReport`] and the daily sums of the detection events the
//! engines cut.
//!
//! The archive, the rule set and the summary are opaque here: they are
//! stored and returned unchanged. Source versions, order keys, digests and
//! every time are the caller's; no operation reads the clock.
//!
//! Every operation on a version or a source runs in one transaction that
//! reads the source's row for update and, when it changes anything, writes
//! it, so concurrent operations on one source conflict and are retried one
//! after another. Every read of a transaction sees the snapshot taken when
//! it began, so an operation refuses only on a state that existed. An
//! operation that returns an error changes nothing.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow};
use jiff::{Timestamp, civil::Date, tz::TimeZone};
use review_protocol::types::{DetectionModel, SignatureSource, SignatureStatusReport};
use rocksdb::{
    ColumnFamily, DBIteratorWithThreadMode, Direction, IteratorMode, OptimisticTransactionDB,
    OptimisticTransactionOptions, ReadOptions, Transaction, WriteOptions,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Agent, AgentKind, EXCLUSIVE, EngineDocumentError, ModelInstance, Store, tables,
    types::FromKeyValue,
};

/// The most kept versions a source has.
const MAX_KEPT: usize = 2;

/// The key of the single row of the `signature push revision` family.
const PUSH_REVISION_KEY: &[u8] = b"revision";

/// The states a reconversion takes.
const RECONVERTIBLE: &[SignatureVersionState] = &[
    SignatureVersionState::Applied,
    SignatureVersionState::Kept,
    SignatureVersionState::Staged,
];

/// An optimistic transaction whose reads all see the snapshot taken when it
/// began.
///
/// Without a snapshot each read sees whatever was committed by then, so
/// reads made after a concurrent commit mix two states, and an operation
/// may refuse on a state that never existed — a row it read naming a
/// version the concurrent commit has since deleted. Only a commit checks
/// for conflicts, and an operation that refuses never commits. Reading the
/// snapshot makes a refusal reflect the state at the transaction's start,
/// and the commit, which checks every key read or written against the
/// same snapshot, fails when anything read has changed since.
struct Txn<'d>(Transaction<'d, OptimisticTransactionDB>);

impl<'d> Txn<'d> {
    fn begin(db: &'d OptimisticTransactionDB) -> Self {
        let mut options = OptimisticTransactionOptions::new();
        options.set_snapshot(true);
        Self(db.transaction_opt(&WriteOptions::default(), &options))
    }

    /// Returns read options reading the transaction's snapshot.
    ///
    /// The snapshot belongs to the transaction, which `set_snapshot` made
    /// take it at its start; the handle `snapshot()` returns only wraps it,
    /// and the read options keep the snapshot itself, so dropping the
    /// handle here leaves them valid for as long as the transaction lives.
    fn snapshot_read(&self) -> ReadOptions {
        let mut read = ReadOptions::default();
        read.set_snapshot(&self.0.snapshot());
        read
    }

    fn get_for_update_cf(
        &self,
        cf: &ColumnFamily,
        key: impl AsRef<[u8]>,
        exclusive: bool,
    ) -> Result<Option<Vec<u8>>, rocksdb::Error> {
        self.0
            .get_for_update_cf_opt(cf, key, exclusive, &self.snapshot_read())
    }

    fn iterator_cf(
        &self,
        cf: &ColumnFamily,
        mode: IteratorMode,
    ) -> DBIteratorWithThreadMode<'_, Transaction<'d, OptimisticTransactionDB>> {
        self.0.iterator_cf_opt(cf, self.snapshot_read(), mode)
    }

    fn put_cf(
        &self,
        cf: &ColumnFamily,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), rocksdb::Error> {
        self.0.put_cf(cf, key, value)
    }

    fn delete_cf(&self, cf: &ColumnFamily, key: impl AsRef<[u8]>) -> Result<(), rocksdb::Error> {
        self.0.delete_cf(cf, key)
    }

    fn commit(self) -> Result<(), rocksdb::Error> {
        self.0.commit()
    }
}

/// Where a signature rule source's version sorts among the versions of its
/// source: a UTC date and, for sources that number their releases, a
/// number.
///
/// The order is partial: see [`is_earlier_than`](Self::is_earlier_than).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignatureOrderKey {
    /// The UTC date of the version.
    pub date: Date,
    /// The version's number within its date, if the source numbers them.
    pub number: Option<u64>,
}

impl SignatureOrderKey {
    /// Returns whether this key is earlier than `other`: its date is
    /// earlier, or the dates are equal, both keys have a number and this
    /// key's is smaller.
    ///
    /// Keys with equal dates of which only one has a number are not earlier
    /// than each other.
    #[must_use]
    pub fn is_earlier_than(&self, other: &Self) -> bool {
        match (self.number, other.number) {
            (Some(a), Some(b)) if self.date == other.date => a < b,
            _ => self.date < other.date,
        }
    }
}

/// How a signature source version was received.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SignatureOrigin {
    /// Fetched from the source's publisher.
    Fetch,
    /// Uploaded by an operator.
    Upload,
}

/// The state of a signature source version.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SignatureVersionState {
    /// Received, its conversion not finished.
    Converting,
    /// Converted and waiting for review; at most one per source.
    Staged,
    /// The version engines match against; at most one per source.
    Applied,
    /// Applied earlier and kept for rollback; at most two per source.
    Kept,
    /// Its conversion failed; only the most recent one per source is kept,
    /// without its archive.
    Failed,
    /// Discarded or replaced while staged; only the most recent one per
    /// source is kept, without its archive and rule set.
    Discarded,
}

/// The record of a signature source version, without its archive and rule
/// set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignatureVersion {
    /// The id this crate assigned: unique across sources and never reused.
    pub id: u64,
    pub source: SignatureSource,
    /// The version of the source's rule set, as the caller named it.
    pub source_version: String,
    pub order_key: SignatureOrderKey,
    /// The label a fetcher passed with the archive.
    pub fetch_label: Option<String>,
    /// The version of the converter that produced the rule set; `None`
    /// until a conversion succeeds.
    pub converter_version: Option<String>,
    pub origin: SignatureOrigin,
    /// The URL the archive was fetched from.
    pub fetched_url: Option<String>,
    /// The SHA-256 digest of the archive.
    pub archive_sha256: [u8; 32],
    /// The digest of the archive's content, compared byte for byte.
    pub content_digest: Vec<u8>,
    /// When the archive was received.
    #[serde(with = "crate::timestamp::ts_nanoseconds_saturating")]
    pub received_at: Timestamp,
    pub state: SignatureVersionState,
    /// Why the conversion failed; set in the `Failed` state.
    pub failure_reason: Option<String>,
    /// The converter's result summary, opaque to this crate.
    pub summary: Option<String>,
}

/// A version of a signature source to store with
/// [`Store::ingest_signature_version`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewSignatureVersion<'a> {
    pub source: SignatureSource,
    pub source_version: &'a str,
    pub order_key: SignatureOrderKey,
    pub fetch_label: Option<&'a str>,
    pub origin: SignatureOrigin,
    pub fetched_url: Option<&'a str>,
    pub archive_sha256: [u8; 32],
    pub content_digest: &'a [u8],
    pub received_at: Timestamp,
    /// The original archive.
    pub archive: &'a [u8],
}

/// The outcome of a reconversion of a signature source version.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SignatureReconversionOutcome {
    /// The reconversion succeeded, with the rule counts the caller gave.
    Succeeded {
        /// The number of rules the previous rule set accepted; `None` when
        /// the caller could not determine it.
        previous_rule_count: Option<u64>,
        /// The number of rules the new rule set accepts.
        rule_count: u64,
    },
    /// The reconversion failed for the reason given.
    Failed { reason: String },
}

/// The record of the last reconversion of a source's version.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignatureReconversion {
    /// When the reconversion finished, as the caller gave it.
    #[serde(with = "crate::timestamp::ts_nanoseconds_saturating")]
    pub time: Timestamp,
    /// The version reconverted.
    pub version_id: u64,
    /// The converter version the version had before the reconversion.
    pub previous_converter_version: Option<String>,
    /// The converter version the reconversion used.
    pub attempted_converter_version: String,
    pub outcome: SignatureReconversionOutcome,
}

/// A successful reconversion, given to
/// [`Store::complete_signature_reconversion`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureReconversionSuccess<'a> {
    /// The converter version that produced `rule_set`.
    pub converter_version: &'a str,
    /// The new serialized rule set.
    pub rule_set: &'a [u8],
    /// The converter's new result summary.
    pub summary: &'a str,
    /// The number of rules the previous rule set accepted; `None` when it
    /// could not be determined.
    pub previous_rule_count: Option<u64>,
    /// The number of rules the new rule set accepts.
    pub rule_count: u64,
    /// When the reconversion finished.
    pub time: Timestamp,
}

/// The state of a signature source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureSourceState {
    pub source: SignatureSource,
    /// Whether the source's rules are pushed to engines.
    pub enabled: bool,
    /// The applied version.
    pub applied: Option<u64>,
    /// The versions kept for rollback, newest first, at most two.
    pub kept: Vec<u64>,
    /// The version staged for review.
    pub staged: Option<u64>,
    /// The record of the last reconversion of one of the source's versions.
    pub last_reconversion: Option<SignatureReconversion>,
}

/// A signature rule an operator turned off.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureRuleOverride {
    pub source: SignatureSource,
    /// The rule's id within its source.
    pub rule_id: String,
    /// The account that turned the rule off.
    pub account: String,
    /// When the rule was turned off.
    pub time: Timestamp,
}

/// The last signature status report of an engine instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignatureStatus {
    pub report: SignatureStatusReport,
    /// When the report was received.
    #[serde(with = "crate::timestamp::ts_nanoseconds_saturating")]
    pub received_at: Timestamp,
}

/// The number of detection events of one model and rule the engines cut on
/// one UTC date, summed over every report received.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureTruncationDaily {
    /// The UTC date of the windows the counts are of.
    pub date: Date,
    pub detection_model: DetectionModel,
    pub source: SignatureSource,
    pub rule_id: String,
    /// The sum of the counts, saturating at `u64::MAX`.
    pub count: u64,
}

/// A refusal of a signature source operation.
///
/// It is returned inside the `anyhow::Error` of the refusing method, so a
/// caller can `downcast_ref` it.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SignatureError {
    /// The content digest is that of the source's applied or staged
    /// version.
    #[error("the content is already present as signature version {version_id}")]
    AlreadyPresent { version_id: u64 },
    /// The order key is earlier than that of the source's applied version.
    #[error("the version is older than applied signature version {applied_version_id}")]
    OlderThanApplied { applied_version_id: u64 },
    /// No version has the id.
    #[error("signature version {version_id} does not exist")]
    UnknownVersion { version_id: u64 },
    /// The version is in a state the operation does not take.
    #[error("signature version {version_id} is {state:?}, which the operation does not take")]
    InvalidState {
        version_id: u64,
        state: SignatureVersionState,
    },
}

/// A state in which a version keeps neither archive nor rule set, and of
/// which a source keeps only the most recent version.
#[derive(Clone, Copy)]
enum Retired {
    Failed,
    Discarded,
}

/// The stored row of a source.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct SourceRow {
    enabled: bool,
    applied: Option<u64>,
    kept: Vec<u64>,
    staged: Option<u64>,
    /// The most recent `Failed` version, the only one kept.
    failed: Option<u64>,
    /// The most recent `Discarded` version, the only one kept.
    discarded: Option<u64>,
    last_reconversion: Option<SignatureReconversion>,
}

impl SourceRow {
    fn into_state(self, source: SignatureSource) -> SignatureSourceState {
        SignatureSourceState {
            source,
            enabled: self.enabled,
            applied: self.applied,
            kept: self.kept,
            staged: self.staged,
            last_reconversion: self.last_reconversion,
        }
    }
}

/// The stored row of a rule override.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct OverrideRow {
    account: String,
    #[serde(with = "crate::timestamp::ts_nanoseconds_saturating")]
    time: Timestamp,
}

/// The column families of the signature records.
struct Families<'d> {
    db: &'d OptimisticTransactionDB,
    sources: &'d ColumnFamily,
    versions: &'d ColumnFamily,
    archives: &'d ColumnFamily,
    rule_sets: &'d ColumnFamily,
    overrides: &'d ColumnFamily,
    revision: &'d ColumnFamily,
    status: &'d ColumnFamily,
    daily: &'d ColumnFamily,
    meta: &'d ColumnFamily,
}

fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    use bincode::Options;
    Ok(bincode::DefaultOptions::new().serialize(value)?)
}

fn deserialize<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T> {
    use bincode::Options;
    Ok(bincode::DefaultOptions::new().deserialize(bytes)?)
}

fn source_key(source: SignatureSource) -> [u8; 4] {
    u32::from(source).to_be_bytes()
}

fn source_of(bytes: &[u8]) -> Result<SignatureSource> {
    let number = u32::from_be_bytes(
        bytes
            .try_into()
            .context("signature source key is not four bytes")?,
    );
    SignatureSource::try_from(number).map_err(|_| anyhow!("unknown signature source {number}"))
}

fn override_key(source: SignatureSource, rule_id: &str) -> Vec<u8> {
    let mut key = source_key(source).to_vec();
    key.extend(rule_id.as_bytes());
    key
}

fn override_of(key: &[u8]) -> Result<(SignatureSource, String)> {
    let (source, rule_id) = key
        .split_at_checked(4)
        .context("signature rule override key is too short")?;
    let rule_id = std::str::from_utf8(rule_id)
        .context("signature rule id is not UTF-8")?
        .to_owned();
    Ok((source_of(source)?, rule_id))
}

/// Returns the four bytes a date sorts by in a daily key: the year with its
/// sign bit flipped, the month and the day.
fn date_key(date: Date) -> [u8; 4] {
    let [y0, y1] = (u16::from_be_bytes(date.year().to_be_bytes()) ^ 0x8000).to_be_bytes();
    [
        y0,
        y1,
        date.month().unsigned_abs(),
        date.day().unsigned_abs(),
    ]
}

fn daily_key(date: Date, model: DetectionModel, source: SignatureSource, rule_id: &str) -> Vec<u8> {
    let mut key = date_key(date).to_vec();
    key.extend(u32::from(model).to_be_bytes());
    key.extend(source_key(source));
    key.extend(rule_id.as_bytes());
    key
}

fn daily_of(key: &[u8], value: &[u8]) -> Result<SignatureTruncationDaily> {
    let malformed = || anyhow!("malformed signature truncation daily key");
    let (date, rest) = key.split_at_checked(4).ok_or_else(malformed)?;
    let (model, rest) = rest.split_at_checked(4).ok_or_else(malformed)?;
    let (source, rule_id) = rest.split_at_checked(4).ok_or_else(malformed)?;
    let &[y0, y1, month, day] = date else {
        return Err(malformed());
    };
    let year = i16::from_be_bytes((u16::from_be_bytes([y0, y1]) ^ 0x8000).to_be_bytes());
    let date = Date::new(year, i8::try_from(month)?, i8::try_from(day)?)?;
    let model = u32::from_be_bytes(model.try_into()?);
    let detection_model =
        DetectionModel::try_from(model).map_err(|_| anyhow!("unknown detection model {model}"))?;
    Ok(SignatureTruncationDaily {
        date,
        detection_model,
        source: source_of(source)?,
        rule_id: std::str::from_utf8(rule_id)
            .context("signature rule id is not UTF-8")?
            .to_owned(),
        count: u64_of(value)?,
    })
}

fn u64_of(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        bytes
            .try_into()
            .context("stored counter is not eight bytes")?,
    ))
}

/// Returns whether a commit failed because a concurrent write conflicted
/// with it, so that the operation is to be run again.
fn is_retryable(error: &rocksdb::Error) -> bool {
    matches!(
        error.kind(),
        rocksdb::ErrorKind::Busy | rocksdb::ErrorKind::TryAgain
    )
}

impl<'d> Families<'d> {
    fn open(db: &'d OptimisticTransactionDB) -> Self {
        let cf = |name| {
            db.cf_handle(name)
                .expect("StateDb::open creates every family of MAP_NAMES")
        };
        Self {
            db,
            sources: cf(tables::SIGNATURE_SOURCES),
            versions: cf(tables::SIGNATURE_SOURCE_VERSIONS),
            archives: cf(tables::SIGNATURE_SOURCE_ARCHIVES),
            rule_sets: cf(tables::SIGNATURE_RULE_SETS),
            overrides: cf(tables::SIGNATURE_RULE_OVERRIDES),
            revision: cf(tables::SIGNATURE_PUSH_REVISION),
            status: cf(tables::SIGNATURE_STATUS),
            daily: cf(tables::SIGNATURE_TRUNCATION_DAILY),
            meta: cf(tables::META),
        }
    }

    /// Runs `body` in a transaction and commits it, running both again
    /// while the commit conflicts with a concurrent write. An error `body`
    /// returns ends the operation with nothing written.
    fn run<T>(&self, what: &str, mut body: impl FnMut(&Txn<'d>) -> Result<T>) -> Result<T> {
        loop {
            let txn = Txn::begin(self.db);
            let value = body(&txn)?;
            match txn.commit() {
                Ok(()) => return Ok(value),
                Err(e) if is_retryable(&e) => {}
                Err(e) => return Err(e).with_context(|| format!("failed to {what}")),
            }
        }
    }

    fn source_for_update(&self, txn: &Txn<'d>, source: SignatureSource) -> Result<SourceRow> {
        let row = txn
            .get_for_update_cf(self.sources, source_key(source), EXCLUSIVE)
            .context("cannot read signature source")?;
        #[cfg(test)]
        tests::AFTER_SOURCE_READ.with_borrow_mut(|hook| {
            if let Some(hook) = hook {
                hook();
            }
        });
        row.map_or_else(|| Ok(SourceRow::default()), |value| deserialize(&value))
    }

    fn put_source(&self, txn: &Txn<'d>, source: SignatureSource, row: &SourceRow) -> Result<()> {
        txn.put_cf(self.sources, source_key(source), serialize(row)?)
            .context("cannot write signature source")
    }

    fn version_for_update(&self, txn: &Txn<'d>, id: u64) -> Result<Option<SignatureVersion>> {
        txn.get_for_update_cf(self.versions, id.to_be_bytes(), EXCLUSIVE)
            .context("cannot read signature version")?
            .map(|value| deserialize(&value))
            .transpose()
    }

    /// Reads version `id` for update, refusing an unknown id or a state not
    /// in `allowed`.
    fn version_in(
        &self,
        txn: &Txn<'d>,
        id: u64,
        allowed: &[SignatureVersionState],
    ) -> Result<SignatureVersion> {
        let version = self
            .version_for_update(txn, id)?
            .ok_or(SignatureError::UnknownVersion { version_id: id })?;
        if !allowed.contains(&version.state) {
            return Err(SignatureError::InvalidState {
                version_id: id,
                state: version.state,
            }
            .into());
        }
        Ok(version)
    }

    fn put_version(&self, txn: &Txn<'d>, version: &SignatureVersion) -> Result<()> {
        txn.put_cf(self.versions, version.id.to_be_bytes(), serialize(version)?)
            .context("cannot write signature version")
    }

    fn put_rule_set(&self, txn: &Txn<'d>, id: u64, rule_set: &[u8]) -> Result<()> {
        txn.put_cf(self.rule_sets, id.to_be_bytes(), rule_set)
            .context("cannot write signature rule set")
    }

    /// Deletes the archive and the rule set of version `id`.
    fn delete_bytes(&self, txn: &Txn<'d>, id: u64) -> Result<()> {
        let key = id.to_be_bytes();
        txn.delete_cf(self.archives, key)
            .context("cannot delete signature archive")?;
        txn.delete_cf(self.rule_sets, key)
            .context("cannot delete signature rule set")
    }

    /// Deletes version `id`: its record, archive and rule set.
    fn delete_version(&self, txn: &Txn<'d>, id: u64) -> Result<()> {
        txn.delete_cf(self.versions, id.to_be_bytes())
            .context("cannot delete signature version")?;
        self.delete_bytes(txn, id)
    }

    /// Moves `version` to `Failed` or `Discarded`, dropping its archive and
    /// rule set and deleting the source's earlier version of that state.
    fn retire(
        &self,
        txn: &Txn<'d>,
        row: &mut SourceRow,
        mut version: SignatureVersion,
        retired: Retired,
    ) -> Result<()> {
        let (slot, state) = match retired {
            Retired::Failed => (&mut row.failed, SignatureVersionState::Failed),
            Retired::Discarded => (&mut row.discarded, SignatureVersionState::Discarded),
        };
        if let Some(earlier) = slot.replace(version.id)
            && earlier != version.id
        {
            self.delete_version(txn, earlier)?;
        }
        version.state = state;
        self.delete_bytes(txn, version.id)?;
        self.put_version(txn, &version)
    }

    /// Raises the push revision by one within `txn`, returning the new
    /// value.
    fn raise_revision(&self, txn: &Txn<'d>) -> Result<u64> {
        let current = txn
            .get_for_update_cf(self.revision, PUSH_REVISION_KEY, EXCLUSIVE)
            .context("cannot read signature push revision")?
            .map_or(Ok(0), |value| u64_of(&value))?;
        let next = current
            .checked_add(1)
            .context("signature push revision overflows")?;
        txn.put_cf(self.revision, PUSH_REVISION_KEY, next.to_be_bytes())
            .context("cannot write signature push revision")?;
        Ok(next)
    }

    /// Allocates a version id within `txn`.
    fn next_version_id(&self, txn: &Txn<'d>) -> Result<u64> {
        let last = txn
            .get_for_update_cf(self.meta, tables::SIGNATURE_VERSION_ID_COUNTER, EXCLUSIVE)
            .context("cannot read signature version id counter")?
            .map_or(Ok(0), |value| u64_of(&value))?;
        let id = last
            .checked_add(1)
            .context("signature version ids are exhausted")?;
        txn.put_cf(
            self.meta,
            tables::SIGNATURE_VERSION_ID_COUNTER,
            id.to_be_bytes(),
        )
        .context("cannot write signature version id counter")?;
        Ok(id)
    }

    fn versions(&self) -> Result<Vec<SignatureVersion>> {
        self.db
            .iterator_cf(self.versions, IteratorMode::Start)
            .map(|entry| {
                let (_, value) = entry.context("cannot read signature versions")?;
                deserialize(&value)
            })
            .collect()
    }

    fn get_bytes(&self, cf: &ColumnFamily, id: u64, what: &str) -> Result<Option<Vec<u8>>> {
        self.db
            .get_cf(cf, id.to_be_bytes())
            .with_context(|| format!("cannot read signature {what}"))
    }
}

impl Store {
    fn signature_families(&self) -> Families<'_> {
        Families::open(self.states.db())
    }

    /// Stores a received version of a signature source as `Converting`,
    /// with its archive, and returns its new id.
    ///
    /// Several versions of one source may be `Converting` at once. The
    /// source's enabled flag plays no part.
    ///
    /// # Errors
    ///
    /// Returns an error, and stores nothing, if the database operation
    /// fails. Returns a [`SignatureError`] inside the error, and stores
    /// nothing, checked in this order:
    ///
    /// - [`SignatureError::AlreadyPresent`] if the content digest is that of
    ///   the source's applied or staged version, naming that version, the
    ///   applied one if both;
    /// - [`SignatureError::OlderThanApplied`] if the order key is earlier
    ///   than the applied version's.
    pub fn ingest_signature_version(&self, new: &NewSignatureVersion<'_>) -> Result<u64> {
        let f = self.signature_families();
        f.run("store a signature version", |txn| {
            let row = f.source_for_update(txn, new.source)?;
            let applied = row
                .applied
                .map(|id| f.version_for_update(txn, id))
                .transpose()?
                .flatten();
            let staged = row
                .staged
                .map(|id| f.version_for_update(txn, id))
                .transpose()?
                .flatten();
            if let Some(present) = [&applied, &staged]
                .into_iter()
                .flatten()
                .find(|v| v.content_digest == new.content_digest)
            {
                return Err(SignatureError::AlreadyPresent {
                    version_id: present.id,
                }
                .into());
            }
            if let Some(applied) = &applied
                && new.order_key.is_earlier_than(&applied.order_key)
            {
                return Err(SignatureError::OlderThanApplied {
                    applied_version_id: applied.id,
                }
                .into());
            }
            let id = f.next_version_id(txn)?;
            let version = SignatureVersion {
                id,
                source: new.source,
                source_version: new.source_version.to_owned(),
                order_key: new.order_key,
                fetch_label: new.fetch_label.map(ToOwned::to_owned),
                converter_version: None,
                origin: new.origin,
                fetched_url: new.fetched_url.map(ToOwned::to_owned),
                archive_sha256: new.archive_sha256,
                content_digest: new.content_digest.to_vec(),
                received_at: new.received_at,
                state: SignatureVersionState::Converting,
                failure_reason: None,
                summary: None,
            };
            f.put_version(txn, &version)?;
            txn.put_cf(f.archives, id.to_be_bytes(), new.archive)
                .context("cannot write signature archive")?;
            Ok(id)
        })
    }

    /// Records the successful conversion of a `Converting` version: it
    /// becomes `Staged` with the converter version, rule set and summary,
    /// and the source's previously staged version, if any, becomes
    /// `Discarded`.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if the database operation
    /// fails, or with a [`SignatureError`] inside if the version does not
    /// exist or is not `Converting`.
    pub fn complete_signature_conversion(
        &self,
        version_id: u64,
        converter_version: &str,
        rule_set: &[u8],
        summary: &str,
    ) -> Result<()> {
        let f = self.signature_families();
        f.run("record a signature conversion", |txn| {
            let mut version =
                f.version_in(txn, version_id, &[SignatureVersionState::Converting])?;
            let mut row = f.source_for_update(txn, version.source)?;
            if let Some(previous) = row.staged.take()
                && previous != version_id
            {
                let previous = f
                    .version_for_update(txn, previous)?
                    .ok_or_else(|| anyhow!("staged signature version {previous} is missing"))?;
                f.retire(txn, &mut row, previous, Retired::Discarded)?;
            }
            row.staged = Some(version_id);
            version.state = SignatureVersionState::Staged;
            version.converter_version = Some(converter_version.to_owned());
            version.summary = Some(summary.to_owned());
            f.put_version(txn, &version)?;
            f.put_rule_set(txn, version_id, rule_set)?;
            f.put_source(txn, version.source, &row)
        })
    }

    /// Records the failed conversion of a `Converting` version: it becomes
    /// `Failed` with `reason` and loses its archive, and the source's
    /// earlier `Failed` version, if any, is deleted.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if the database operation
    /// fails, or with a [`SignatureError`] inside if the version does not
    /// exist or is not `Converting`.
    pub fn fail_signature_conversion(&self, version_id: u64, reason: &str) -> Result<()> {
        let f = self.signature_families();
        f.run("record a signature conversion failure", |txn| {
            let mut version =
                f.version_in(txn, version_id, &[SignatureVersionState::Converting])?;
            let source = version.source;
            let mut row = f.source_for_update(txn, source)?;
            version.failure_reason = Some(reason.to_owned());
            f.retire(txn, &mut row, version, Retired::Failed)?;
            f.put_source(txn, source, &row)
        })
    }

    /// Discards a `Staged` version: it becomes `Discarded`, loses its
    /// archive and rule set, and leaves the source's staged slot empty; the
    /// source's earlier `Discarded` version, if any, is deleted.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if the database operation
    /// fails, or with a [`SignatureError`] inside if the version does not
    /// exist or is not `Staged`.
    pub fn discard_signature_version(&self, version_id: u64) -> Result<()> {
        let f = self.signature_families();
        f.run("discard a signature version", |txn| {
            let version = f.version_in(txn, version_id, &[SignatureVersionState::Staged])?;
            let source = version.source;
            let mut row = f.source_for_update(txn, source)?;
            if row.staged == Some(version_id) {
                row.staged = None;
            }
            f.retire(txn, &mut row, version, Retired::Discarded)?;
            f.put_source(txn, source, &row)
        })
    }

    /// Applies a `Staged` or `Kept` version of its source and returns the
    /// new push revision.
    ///
    /// The version becomes `Applied` and leaves the staged slot or the kept
    /// list. The previously applied version, if any, becomes `Kept` at the
    /// front of the kept list, and a version the list's limit of two cuts
    /// off is deleted with its archive and rule set. Applying a `Kept`
    /// version is a rollback; no order key is compared.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if the database operation
    /// fails, or with a [`SignatureError`] inside if the version does not
    /// exist or is neither `Staged` nor `Kept`.
    pub fn apply_signature_version(&self, version_id: u64) -> Result<u64> {
        let f = self.signature_families();
        f.run("apply a signature version", |txn| {
            let mut version = f.version_in(
                txn,
                version_id,
                &[SignatureVersionState::Staged, SignatureVersionState::Kept],
            )?;
            let source = version.source;
            let mut row = f.source_for_update(txn, source)?;
            if row.staged == Some(version_id) {
                row.staged = None;
            }
            row.kept.retain(|id| *id != version_id);
            if let Some(previous) = row.applied.replace(version_id) {
                let mut previous = f
                    .version_for_update(txn, previous)?
                    .ok_or_else(|| anyhow!("applied signature version {previous} is missing"))?;
                previous.state = SignatureVersionState::Kept;
                f.put_version(txn, &previous)?;
                row.kept.insert(0, previous.id);
            }
            for cut in row.kept.split_off(row.kept.len().min(MAX_KEPT)) {
                f.delete_version(txn, cut)?;
            }
            version.state = SignatureVersionState::Applied;
            f.put_version(txn, &version)?;
            f.put_source(txn, source, &row)?;
            f.raise_revision(txn)
        })
    }

    /// Records the successful reconversion of an `Applied`, `Kept` or
    /// `Staged` version: its converter version, rule set and summary are
    /// replaced, its state is kept, and the reconversion is recorded on its
    /// source.
    ///
    /// Returns the new push revision if the version is the applied one,
    /// which raises it, and `None` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if the database operation
    /// fails, or with a [`SignatureError`] inside if the version does not
    /// exist or is in another state.
    pub fn complete_signature_reconversion(
        &self,
        version_id: u64,
        success: &SignatureReconversionSuccess<'_>,
    ) -> Result<Option<u64>> {
        let f = self.signature_families();
        f.run("record a signature reconversion", |txn| {
            let mut version = f.version_in(txn, version_id, RECONVERTIBLE)?;
            let mut row = f.source_for_update(txn, version.source)?;
            let previous_converter_version = version
                .converter_version
                .replace(success.converter_version.to_owned());
            version.summary = Some(success.summary.to_owned());
            row.last_reconversion = Some(SignatureReconversion {
                time: success.time,
                version_id,
                previous_converter_version,
                attempted_converter_version: success.converter_version.to_owned(),
                outcome: SignatureReconversionOutcome::Succeeded {
                    previous_rule_count: success.previous_rule_count,
                    rule_count: success.rule_count,
                },
            });
            f.put_version(txn, &version)?;
            f.put_rule_set(txn, version_id, success.rule_set)?;
            f.put_source(txn, version.source, &row)?;
            if version.state == SignatureVersionState::Applied {
                f.raise_revision(txn).map(Some)
            } else {
                Ok(None)
            }
        })
    }

    /// Records the failed reconversion of an `Applied`, `Kept` or `Staged`
    /// version with `converter_version`: the version's source is disabled,
    /// and the reconversion is recorded on it with the version's stored
    /// converter version and `reason`. Versions are left as they are.
    ///
    /// Returns the new push revision if the source was enabled, which
    /// raises it, and `None` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if the database operation
    /// fails, or with a [`SignatureError`] inside if the version does not
    /// exist or is in another state.
    pub fn fail_signature_reconversion(
        &self,
        version_id: u64,
        converter_version: &str,
        reason: &str,
        time: Timestamp,
    ) -> Result<Option<u64>> {
        let f = self.signature_families();
        f.run("record a signature reconversion failure", |txn| {
            let version = f.version_in(txn, version_id, RECONVERTIBLE)?;
            let mut row = f.source_for_update(txn, version.source)?;
            let was_enabled = std::mem::replace(&mut row.enabled, false);
            row.last_reconversion = Some(SignatureReconversion {
                time,
                version_id,
                previous_converter_version: version.converter_version,
                attempted_converter_version: converter_version.to_owned(),
                outcome: SignatureReconversionOutcome::Failed {
                    reason: reason.to_owned(),
                },
            });
            f.put_source(txn, version.source, &row)?;
            if was_enabled {
                f.raise_revision(txn).map(Some)
            } else {
                Ok(None)
            }
        })
    }

    /// Turns a signature source on or off; its versions are left as they
    /// are, and enabling needs no applied version.
    ///
    /// Returns the new push revision if the flag changed, which raises it,
    /// and `None` if it already had the value.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if the database operation
    /// fails.
    pub fn set_signature_source_enabled(
        &self,
        source: SignatureSource,
        enabled: bool,
    ) -> Result<Option<u64>> {
        let f = self.signature_families();
        f.run("set a signature source's enabled flag", |txn| {
            let mut row = f.source_for_update(txn, source)?;
            if row.enabled == enabled {
                return Ok(None);
            }
            row.enabled = enabled;
            f.put_source(txn, source, &row)?;
            f.raise_revision(txn).map(Some)
        })
    }

    /// Turns a signature rule off, recording `account` and `time`.
    ///
    /// Returns the new push revision if the rule was on, which raises it,
    /// and `None` if it was already off, in which case the account and
    /// time stored first are kept.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if the database operation
    /// fails.
    pub fn disable_signature_rule(
        &self,
        source: SignatureSource,
        rule_id: &str,
        account: &str,
        time: Timestamp,
    ) -> Result<Option<u64>> {
        let f = self.signature_families();
        let key = override_key(source, rule_id);
        f.run("turn a signature rule off", |txn| {
            if txn
                .get_for_update_cf(f.overrides, &key, EXCLUSIVE)
                .context("cannot read signature rule override")?
                .is_some()
            {
                return Ok(None);
            }
            let row = OverrideRow {
                account: account.to_owned(),
                time,
            };
            txn.put_cf(f.overrides, &key, serialize(&row)?)
                .context("cannot write signature rule override")?;
            f.raise_revision(txn).map(Some)
        })
    }

    /// Turns a signature rule back on.
    ///
    /// Returns the new push revision if the rule was off, which raises it,
    /// and `None` if it was not.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if the database operation
    /// fails.
    pub fn enable_signature_rule(
        &self,
        source: SignatureSource,
        rule_id: &str,
    ) -> Result<Option<u64>> {
        let f = self.signature_families();
        let key = override_key(source, rule_id);
        f.run("turn a signature rule on", |txn| {
            if txn
                .get_for_update_cf(f.overrides, &key, EXCLUSIVE)
                .context("cannot read signature rule override")?
                .is_none()
            {
                return Ok(None);
            }
            txn.delete_cf(f.overrides, &key)
                .context("cannot delete signature rule override")?;
            f.raise_revision(txn).map(Some)
        })
    }

    /// Returns every signature rule turned off, with who turned it off and
    /// when, ordered by source, then rule id.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored row
    /// cannot be decoded.
    pub fn signature_rule_overrides(&self) -> Result<Vec<SignatureRuleOverride>> {
        let f = self.signature_families();
        f.db.iterator_cf(f.overrides, IteratorMode::Start)
            .map(|entry| {
                let (key, value) = entry.context("cannot read signature rule overrides")?;
                let (source, rule_id) = override_of(&key)?;
                let row: OverrideRow = deserialize(&value)?;
                Ok(SignatureRuleOverride {
                    source,
                    rule_id,
                    account: row.account,
                    time: row.time,
                })
            })
            .collect()
    }

    /// Returns every signature rule turned off as its source and rule id,
    /// the shape of [`SignatureRules::disabled_rules`], ordered by source,
    /// then rule id.
    ///
    /// [`SignatureRules::disabled_rules`]: review_protocol::types::SignatureRules::disabled_rules
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored key
    /// cannot be decoded.
    pub fn signature_disabled_rules(&self) -> Result<Vec<(SignatureSource, String)>> {
        let f = self.signature_families();
        f.db.iterator_cf(f.overrides, IteratorMode::Start)
            .map(|entry| {
                let (key, _) = entry.context("cannot read signature rule overrides")?;
                override_of(&key)
            })
            .collect()
    }

    /// Returns the push revision of the signature rule sets; 0 before any
    /// operation raised it.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored value
    /// cannot be decoded.
    pub fn signature_push_revision(&self) -> Result<u64> {
        let f = self.signature_families();
        f.db.get_cf(f.revision, PUSH_REVISION_KEY)
            .context("cannot read signature push revision")?
            .map_or(Ok(0), |value| u64_of(&value))
    }

    /// Returns the state of a signature source; a source with no record is
    /// disabled with no versions.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row
    /// cannot be decoded.
    pub fn signature_source(&self, source: SignatureSource) -> Result<SignatureSourceState> {
        let f = self.signature_families();
        let row: SourceRow =
            f.db.get_cf(f.sources, source_key(source))
                .context("cannot read signature source")?
                .map_or_else(|| Ok(SourceRow::default()), |value| deserialize(&value))?;
        Ok(row.into_state(source))
    }

    /// Returns the record of a signature source version, without its
    /// archive and rule set, or `None` if no version has the id.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored
    /// record cannot be decoded.
    pub fn signature_version(&self, version_id: u64) -> Result<Option<SignatureVersion>> {
        let f = self.signature_families();
        f.db.get_cf(f.versions, version_id.to_be_bytes())
            .context("cannot read signature version")?
            .map(|value| deserialize(&value))
            .transpose()
    }

    /// Returns the original archive of a signature source version, or
    /// `None` if it has none: it does not exist, or is `Failed` or
    /// `Discarded`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn signature_archive(&self, version_id: u64) -> Result<Option<Vec<u8>>> {
        let f = self.signature_families();
        f.get_bytes(f.archives, version_id, "archive")
    }

    /// Returns the serialized rule set of a signature source version, or
    /// `None` if it has none: it does not exist, has not been converted, or
    /// is `Failed` or `Discarded`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn signature_rule_set(&self, version_id: u64) -> Result<Option<Vec<u8>>> {
        let f = self.signature_families();
        f.get_bytes(f.rule_sets, version_id, "rule set")
    }

    /// Returns the record of every stored version of a signature source,
    /// ordered by id.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored record
    /// cannot be decoded.
    pub fn signature_versions_of_source(
        &self,
        source: SignatureSource,
    ) -> Result<Vec<SignatureVersion>> {
        let mut versions = self.signature_families().versions()?;
        versions.retain(|v| v.source == source);
        Ok(versions)
    }

    /// Returns the record of every stored signature source version in
    /// `state`, of any source, ordered by id.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored record
    /// cannot be decoded.
    pub fn signature_versions_in_state(
        &self,
        state: SignatureVersionState,
    ) -> Result<Vec<SignatureVersion>> {
        let mut versions = self.signature_families().versions()?;
        versions.retain(|v| v.state == state);
        Ok(versions)
    }

    /// Stores the signature status report a Semi-supervised Engine instance
    /// sent and when it was received, replacing the one stored before, and
    /// adds each of its `truncated` counts to the daily sum of the UTC date
    /// of its window's start, its model, source and rule id, saturating at
    /// `u64::MAX`.
    ///
    /// The write is one transaction that reads the instance's agent row for
    /// update, so a write racing the agent's removal conflicts with it.
    ///
    /// # Errors
    ///
    /// Returns an error, and changes nothing, if the database operation
    /// fails. Returns an [`EngineDocumentError`] inside the error, and
    /// changes nothing, if the instance's agent row is missing or is not an
    /// [`AgentKind::SemiSupervised`] agent.
    pub fn set_signature_status_report(
        &self,
        instance: &ModelInstance,
        report: &SignatureStatusReport,
        received_at: Timestamp,
    ) -> Result<()> {
        let mut sums: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
        for entry in &report.truncated {
            let date = Timestamp::from_nanosecond(i128::from(entry.window_start))
                .context("window start of a truncated count is out of range")?
                .to_zoned_datetime(TimeZone::UTC)
                .date();
            let sum = sums
                .entry(daily_key(
                    date,
                    entry.detection_model,
                    entry.source,
                    &entry.rule_id,
                ))
                .or_default();
            *sum = sum.saturating_add(entry.count);
        }
        let value = serialize(&SignatureStatus {
            report: report.clone(),
            received_at,
        })?;
        let agents = self.states.agents();
        let f = self.signature_families();
        let key = tables::engine_instance_key(instance.node_id, &instance.agent_key);
        f.run("store a signature status report", |txn| {
            if txn
                .get_for_update_cf(agents.raw().cf, &key, EXCLUSIVE)
                .context("cannot read agent")?
                .map(|value| Agent::from_key_value(&key, &value))
                .transpose()?
                .is_none_or(|agent| agent.kind != AgentKind::SemiSupervised)
            {
                return Err(EngineDocumentError::NotSemiSupervisedAgent {
                    node_id: instance.node_id,
                    agent_key: instance.agent_key.clone(),
                }
                .into());
            }
            txn.put_cf(f.status, &key, &value)
                .context("cannot write signature status")?;
            for (daily, count) in &sums {
                let stored = txn
                    .get_for_update_cf(f.daily, daily, EXCLUSIVE)
                    .context("cannot read signature truncation daily sum")?
                    .map_or(Ok(0), |value| u64_of(&value))?;
                txn.put_cf(f.daily, daily, stored.saturating_add(*count).to_be_bytes())
                    .context("cannot write signature truncation daily sum")?;
            }
            Ok(())
        })
    }

    /// Returns the last signature status report of an engine instance and
    /// when it was received, or `None` if none is stored.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored
    /// report cannot be decoded.
    pub fn signature_status(&self, instance: &ModelInstance) -> Result<Option<SignatureStatus>> {
        let f = self.signature_families();
        f.db.get_cf(
            f.status,
            tables::engine_instance_key(instance.node_id, &instance.agent_key),
        )
        .context("cannot read signature status")?
        .map(|value| deserialize(&value))
        .transpose()
    }

    /// Returns every stored signature status report with its engine
    /// instance, ordered by node id, then agent key.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored row
    /// cannot be decoded.
    pub fn signature_statuses(&self) -> Result<Vec<(ModelInstance, SignatureStatus)>> {
        let f = self.signature_families();
        f.db.iterator_cf(f.status, IteratorMode::Start)
            .map(|entry| {
                let (key, value) = entry.context("cannot read signature statuses")?;
                let (node_id, agent_key) = key
                    .split_at_checked(4)
                    .context("signature status key is too short")?;
                let instance = ModelInstance {
                    node_id: u32::from_be_bytes(node_id.try_into()?),
                    agent_key: std::str::from_utf8(agent_key)
                        .context("signature status key is not UTF-8")?
                        .to_owned(),
                };
                Ok((instance, deserialize(&value)?))
            })
            .collect()
    }

    /// Returns the daily sums of the truncated signature detection counts
    /// of the UTC date `date`, ordered by model, source, then rule id.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored row
    /// cannot be decoded.
    pub fn signature_truncation_daily(&self, date: Date) -> Result<Vec<SignatureTruncationDaily>> {
        let f = self.signature_families();
        let prefix = date_key(date);
        let mut sums = Vec::new();
        for entry in
            f.db.iterator_cf(f.daily, IteratorMode::From(&prefix, Direction::Forward))
        {
            let (key, value) = entry.context("cannot read signature truncation daily sums")?;
            if !key.starts_with(&prefix) {
                break;
            }
            sums.push(daily_of(&key, &value)?);
        }
        Ok(sums)
    }

    /// Deletes every daily sum of the truncated signature detection counts
    /// dated before the UTC date `before`, and returns the number deleted.
    ///
    /// # Errors
    ///
    /// Returns an error, and deletes nothing, if the database operation
    /// fails.
    pub fn prune_signature_truncation_daily(&self, before: Date) -> Result<usize> {
        let f = self.signature_families();
        let end = date_key(before);
        f.run("prune signature truncation daily sums", |txn| {
            let mut deleted = 0;
            for entry in txn.iterator_cf(f.daily, IteratorMode::Start) {
                let (key, _) = entry.context("cannot read signature truncation daily sums")?;
                if *key >= end[..] {
                    break;
                }
                txn.delete_cf(f.daily, &key)
                    .context("cannot delete signature truncation daily sum")?;
                deleted += 1;
            }
            Ok(deleted)
        })
    }
}
