//! The trust-state, document, enrollment and command tables of Clumit
//! Endpoint (`senta`) agents (taco RFC 0016 §4.4, §4.6, §7).
//!
//! Per customer `REview` keeps a trust state, the signed documents it
//! received, the endpoints it enrolled and their commands. This crate stores
//! them and interprets none of them: a trust state, a JWK, a JWS, a request or
//! a command result is kept as the bytes or text it was given.
//!
//! # Keys
//!
//! Integers are stored big-endian, so they iterate numerically. A string
//! component is stored as its UTF-8 bytes with every `0x00` escaped as
//! `0x00 0xFF` and followed by the terminator `0x00 0x01`. The encoding keeps
//! the byte order of the strings, and no encoded string is a prefix of another
//! one, so a prefix read by a string component returns the rows of that string
//! alone even when it is a prefix of another string.
//!
//! # Writes
//!
//! No table here is written through the generic writers of [`Table`]. The rows
//! of the customer, keyset-document, current-document, address-root and
//! command tables are created only by the transaction methods of
//! [`Store`](crate::Store) in `senta_endpoint`, each of which checks the
//! customer's data deletion job in the same transaction; the other tables are
//! created by the narrow writers below. Later changes of an endpoint, an
//! enrollment attempt or a command only update a row that exists.

use std::net::IpAddr;

use anyhow::{Context, Result, anyhow, bail};
use rocksdb::{IteratorMode, OptimisticTransactionDB, Transaction};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{EXCLUSIVE, Map, Table, types::FromKeyValue};

/// An optimistic transaction of the states database.
pub(crate) type Txn<'d> = Transaction<'d, OptimisticTransactionDB>;

/// The length of an SPKI hash or a certificate fingerprint.
const HASH_LEN: usize = 32;

/// The terminator ending every string component of a key.
const STRING_END: [u8; 2] = [0x00, 0x01];

/// The escape of a `0x00` byte inside a string component of a key.
const ESCAPED_NUL: [u8; 2] = [0x00, 0xFF];

/// A version of a customer's keyset: the recovery epoch it was signed in and
/// its version within that epoch.
///
/// Versions order by epoch first, then by version.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct SentaEndpointKeysetVersion {
    pub recovery_epoch: u64,
    pub keyset_version: u64,
}

/// The trust state of one customer, keyed by the customer ID.
///
/// `trust_state` is a senta-protocol `TrustState` as `REview` encoded it; it is
/// stored and returned byte for byte. The other fields are copies of values in
/// the trust state, kept so that they can be read without decoding it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentaEndpointCustomer {
    /// The ID of the customer in aice-web-next.
    pub customer_id: u32,
    pub trust_state: Vec<u8>,
    pub customer_endpoint_id: Uuid,
    pub customer_key_name: String,
    /// The ID of the install whose recovery key the customer's trust state
    /// rests on.
    pub install_id: String,
    pub last_keyset: SentaEndpointKeysetVersion,
    pub recovery_key_version: u64,
}

/// The recovery keys of one install, keyed by the install ID.
///
/// The first recovery key and its version are set when the install is
/// registered and never change; the current ones change with every
/// recovery-key rotation. Keys are JWKs in their JSON text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentaEndpointInstall {
    pub install_id: String,
    pub first_recovery_key: String,
    pub first_recovery_key_version: u64,
    pub current_recovery_key: String,
    pub current_recovery_key_version: u64,
}

/// An enrolled endpoint, keyed by its endpoint ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentaEndpoint {
    pub endpoint_id: Uuid,
    pub customer_id: u32,
    pub customer_endpoint_id: Uuid,
    pub spki_hash: [u8; HASH_LEN],
    /// The endpoint's standing on the active list, as `REview` wrote it.
    pub standing: String,
    pub host_name: String,
    pub os: String,
    pub senta_version: String,
    pub bundle: String,
    /// When the endpoint was enrolled, in nanoseconds since the Unix epoch.
    pub enrolled_at: i64,
    /// When the endpoint last connected, in nanoseconds since the Unix epoch.
    pub last_connected_at: i64,
    /// Whether the endpoint is connected now.
    pub connected: bool,
}

/// The result of an enrollment attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SentaEndpointEnrollmentResult {
    /// The attempt waits for a decision, for `reason`.
    Pending { reason: String },
    /// The attempt was approved; `result` is the enrollment-result JWS.
    Approved { result: String },
    /// The attempt was denied, for `reason`.
    Denied { reason: String },
}

/// An enrollment attempt, keyed by the SPKI hash of the endpoint's key and the
/// attempt ID.
///
/// `customer_id` is the customer `REview` resolved for the attempt before it
/// queued it, so that the customer's attempts can be found when the customer's
/// data is deleted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentaEndpointEnrollmentAttempt {
    pub spki_hash: [u8; HASH_LEN],
    pub attempt_id: Uuid,
    pub customer_id: u32,
    /// The request as it was received.
    pub request: Vec<u8>,
    pub source_address: IpAddr,
    /// When the attempt was received, in nanoseconds since the Unix epoch.
    pub received_at: i64,
    pub result: SentaEndpointEnrollmentResult,
}

/// A keyset document of a customer, keyed by the customer ID, the recovery
/// epoch, the keyset version and the ID of the key that signed it.
///
/// Two copies of one keyset version signed by different keys are two rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentaEndpointKeysetDocument {
    pub customer_id: u32,
    pub recovery_epoch: u64,
    pub keyset_version: u64,
    pub signing_kid: String,
    pub jws: String,
}

/// A recovery-key document of an install, keyed by the install ID and the
/// recovery key version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentaEndpointRecoveryKeyDocument {
    pub install_id: String,
    pub recovery_key_version: u64,
    pub jws: String,
}

/// The current document of a customer for a `typ` and a target, keyed by the
/// three.
///
/// `typ` and `target` are the caller's text forms and are not interpreted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentaEndpointCurrentDocument {
    pub customer_id: u32,
    pub typ: String,
    pub target: String,
    pub recovery_epoch: u64,
    pub version: u64,
    pub jws: String,
    /// When the document was put, in nanoseconds since the Unix epoch.
    pub put_at: i64,
}

/// The fingerprint of a root certificate an address document of a customer
/// names, keyed by the customer ID, the document's recovery epoch and version,
/// and the fingerprint. The row has no value: its presence is the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SentaEndpointAddressRoot {
    pub customer_id: u32,
    pub recovery_epoch: u64,
    pub version: u64,
    pub fingerprint: [u8; HASH_LEN],
}

/// The state of a command sent to an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SentaEndpointCommandState {
    Pending,
    Sent,
    Result,
    Expired,
}

/// A command for an endpoint, keyed by the command ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentaEndpointCommand {
    pub command_id: Uuid,
    pub endpoint_id: Uuid,
    pub sequence: u64,
    pub jws: String,
    /// When the command expires, in nanoseconds since the Unix epoch.
    pub expires_at: i64,
    pub state: SentaEndpointCommandState,
    /// The result the endpoint reported, as it was received.
    pub result: Option<Vec<u8>>,
}

/// Whether a customer's data deletion job is unfinished or done, as
/// [`SentaEndpointError::CustomerDeletion`] reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SentaEndpointDeletionState {
    /// A service result of the job is not `Succeeded`.
    InProgress,
    /// Every service result of the job is `Succeeded`.
    AlreadyDeleted,
}

/// What went wrong in a write of the Clumit Endpoint tables.
///
/// Every variant but [`Database`](Self::Database) is a refusal, after which
/// nothing was written.
#[derive(Debug, Error)]
pub enum SentaEndpointError {
    /// The customer has a data deletion job, so nothing of the customer is
    /// written.
    #[error("customer {customer_id} has a data deletion job ({state:?})")]
    CustomerDeletion {
        customer_id: u32,
        state: SentaEndpointDeletionState,
    },
    /// A deletion job of the customer already exists, unfinished or done as
    /// `state` tells.
    #[error("customer {customer_id} already has a data deletion job ({state:?})")]
    DeletionJobExists {
        customer_id: u32,
        state: SentaEndpointDeletionState,
    },
    /// The deletion job to create is invalid.
    #[error("invalid customer data deletion job: {0:#}")]
    InvalidDeletionJob(anyhow::Error),
    /// The install has no row.
    #[error("no senta endpoint install {install_id:?}")]
    InstallNotFound { install_id: String },
    /// The install is registered with another first recovery key or version.
    #[error("senta endpoint install {install_id:?} is registered with another first recovery key")]
    InstallConflict { install_id: String },
    /// The install's current recovery key version is not the one the customer
    /// row carries.
    #[error(
        "the current recovery key version of senta endpoint install {install_id:?} is \
         {install_version}, not {customer_version}"
    )]
    RecoveryKeyVersionMismatch {
        install_id: String,
        install_version: u64,
        customer_version: u64,
    },
    /// The customer already has a row.
    #[error("senta endpoint customer {customer_id} already exists")]
    CustomerExists { customer_id: u32 },
    /// The customer has no row.
    #[error("no senta endpoint customer {customer_id}")]
    CustomerNotFound { customer_id: u32 },
    /// A document or a row given with a customer row names another customer.
    #[error("the document does not belong to senta endpoint customer {customer_id}")]
    DocumentOfAnotherCustomer { customer_id: u32 },
    /// A new customer row changes a column only registration or a
    /// recovery-key rotation sets.
    #[error("the new row of senta endpoint customer {customer_id} changes its {column}")]
    CustomerColumnChanged {
        customer_id: u32,
        column: &'static str,
    },
    /// A recovery-key rotation was given two rows of one customer.
    #[error("two new rows of senta endpoint customer {customer_id}")]
    DuplicateCustomerRow { customer_id: u32 },
    /// A customer of the install has no deletion job and no new row was given
    /// for it.
    #[error("no new row of senta endpoint customer {customer_id}")]
    CustomerRowMissing { customer_id: u32 },
    /// A new customer row is not of a customer of the install.
    #[error("senta endpoint customer {customer_id} is not a customer of install {install_id:?}")]
    CustomerNotOfInstall {
        customer_id: u32,
        install_id: String,
    },
    /// A new customer row carries another recovery key version than the
    /// rotation's.
    #[error(
        "the new row of senta endpoint customer {customer_id} carries recovery key version \
         {found}, not {expected}"
    )]
    CustomerRecoveryKeyVersion {
        customer_id: u32,
        expected: u64,
        found: u64,
    },
    /// The endpoint has no row.
    #[error("no senta endpoint {endpoint_id}")]
    EndpointNotFound { endpoint_id: Uuid },
    /// The endpoint already has a row.
    #[error("senta endpoint {endpoint_id} already exists")]
    EndpointExists { endpoint_id: Uuid },
    /// The endpoint belongs to another customer.
    #[error("senta endpoint {endpoint_id} does not belong to customer {customer_id}")]
    EndpointOfAnotherCustomer { endpoint_id: Uuid, customer_id: u32 },
    /// The enrollment attempt has no row.
    #[error("no senta endpoint enrollment attempt {attempt_id}")]
    AttemptNotFound { attempt_id: Uuid },
    /// The enrollment attempt is already approved.
    #[error("senta endpoint enrollment attempt {attempt_id} is already approved")]
    AttemptApproved { attempt_id: Uuid },
    /// The enrollment attempt is pending or denied, so it has no approved
    /// result to replace.
    #[error("senta endpoint enrollment attempt {attempt_id} is not approved")]
    AttemptNotApproved { attempt_id: Uuid },
    /// An approved result was given outside the approval of an enrollment.
    #[error("enrollment attempt {attempt_id} can be approved only with its endpoint")]
    ApprovalWithoutEndpoint { attempt_id: Uuid },
    /// The endpoint to enroll does not match its enrollment attempt.
    #[error("the endpoint does not match senta endpoint enrollment attempt {attempt_id}")]
    AttemptMismatch { attempt_id: Uuid },
    /// The command has no row.
    #[error("no senta endpoint command {command_id}")]
    CommandNotFound { command_id: Uuid },
    /// The command already has a row.
    #[error("senta endpoint command {command_id} already exists")]
    CommandExists { command_id: Uuid },
    /// A command to insert is not pending or already carries a result.
    #[error("senta endpoint command {command_id} must be inserted pending without a result")]
    CommandNotPending { command_id: Uuid },
    /// The database read or write failed, or a stored row was invalid.
    #[error(transparent)]
    Database(#[from] anyhow::Error),
}

impl From<rocksdb::Error> for SentaEndpointError {
    fn from(error: rocksdb::Error) -> Self {
        Self::Database(error.into())
    }
}

/// Returns whether `error`, from a commit, is a write conflict, after which
/// the whole transaction runs again.
pub(crate) fn is_conflict(error: &rocksdb::Error) -> bool {
    error.kind() == rocksdb::ErrorKind::Busy
}

/// A record of one of the Clumit Endpoint tables.
///
/// The trait is `pub` because it bounds the generic `impl` of [`Table`]
/// below, which `private_bounds` requires; this module is private and does
/// not export it.
pub trait Row: FromKeyValue {
    /// The name of the record's column family.
    const FAMILY: &'static str;
    /// What the record is called in an error message.
    const NAME: &'static str;

    /// Returns the record's key.
    fn key(&self) -> Vec<u8>;

    /// Returns the record's stored value.
    fn value(&self) -> Result<Vec<u8>>;
}

/// The key encodings of the Clumit Endpoint tables.
pub(crate) mod keys {
    use uuid::Uuid;

    use super::{ESCAPED_NUL, HASH_LEN, STRING_END};

    /// Appends the string component `s` to `key`.
    fn push_str(key: &mut Vec<u8>, s: &str) {
        for &byte in s.as_bytes() {
            if byte == 0 {
                key.extend_from_slice(&ESCAPED_NUL);
            } else {
                key.push(byte);
            }
        }
        key.extend_from_slice(&STRING_END);
    }

    pub(crate) fn customer(customer_id: u32) -> Vec<u8> {
        customer_id.to_be_bytes().to_vec()
    }

    pub(crate) fn install(install_id: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(install_id.len() + STRING_END.len());
        push_str(&mut key, install_id);
        key
    }

    pub(crate) fn endpoint(endpoint_id: Uuid) -> Vec<u8> {
        endpoint_id.as_bytes().to_vec()
    }

    pub(crate) fn attempt_prefix(spki_hash: &[u8; HASH_LEN]) -> Vec<u8> {
        spki_hash.to_vec()
    }

    pub(crate) fn attempt(spki_hash: &[u8; HASH_LEN], attempt_id: Uuid) -> Vec<u8> {
        let mut key = attempt_prefix(spki_hash);
        key.extend_from_slice(attempt_id.as_bytes());
        key
    }

    pub(crate) fn keyset_document(
        customer_id: u32,
        recovery_epoch: u64,
        keyset_version: u64,
        signing_kid: &str,
    ) -> Vec<u8> {
        let mut key = customer(customer_id);
        key.extend_from_slice(&recovery_epoch.to_be_bytes());
        key.extend_from_slice(&keyset_version.to_be_bytes());
        push_str(&mut key, signing_kid);
        key
    }

    pub(crate) fn recovery_key_document(install_id: &str, recovery_key_version: u64) -> Vec<u8> {
        let mut key = install(install_id);
        key.extend_from_slice(&recovery_key_version.to_be_bytes());
        key
    }

    pub(crate) fn current_document_prefix(customer_id: u32, typ: &str) -> Vec<u8> {
        let mut key = customer(customer_id);
        push_str(&mut key, typ);
        key
    }

    pub(crate) fn current_document(customer_id: u32, typ: &str, target: &str) -> Vec<u8> {
        let mut key = current_document_prefix(customer_id, typ);
        push_str(&mut key, target);
        key
    }

    pub(crate) fn address_root_prefix(
        customer_id: u32,
        recovery_epoch: u64,
        version: u64,
    ) -> Vec<u8> {
        let mut key = customer(customer_id);
        key.extend_from_slice(&recovery_epoch.to_be_bytes());
        key.extend_from_slice(&version.to_be_bytes());
        key
    }

    pub(crate) fn address_root(
        customer_id: u32,
        recovery_epoch: u64,
        version: u64,
        fingerprint: &[u8; HASH_LEN],
    ) -> Vec<u8> {
        let mut key = address_root_prefix(customer_id, recovery_epoch, version);
        key.extend_from_slice(fingerprint);
        key
    }

    pub(crate) fn command(command_id: Uuid) -> Vec<u8> {
        command_id.as_bytes().to_vec()
    }
}

/// A reader of the components of a stored key.
struct KeyReader<'a> {
    rest: &'a [u8],
    name: &'static str,
}

impl<'a> KeyReader<'a> {
    fn new(key: &'a [u8], name: &'static str) -> Self {
        Self { rest: key, name }
    }

    fn truncated(&self) -> anyhow::Error {
        anyhow!("truncated {} key", self.name)
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, rest) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or_else(|| self.truncated())?;
        self.rest = rest;
        Ok(*head)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn uuid(&mut self) -> Result<Uuid> {
        Ok(Uuid::from_bytes(self.take()?))
    }

    fn string(&mut self) -> Result<String> {
        let mut bytes = Vec::new();
        loop {
            let (&byte, rest) = self.rest.split_first().ok_or_else(|| self.truncated())?;
            if byte != 0 {
                bytes.push(byte);
                self.rest = rest;
                continue;
            }
            let (&marker, rest) = rest.split_first().ok_or_else(|| self.truncated())?;
            self.rest = rest;
            match [byte, marker] {
                STRING_END => break,
                ESCAPED_NUL => bytes.push(0),
                _ => bail!("invalid string in {} key", self.name),
            }
        }
        String::from_utf8(bytes).with_context(|| format!("invalid string in {} key", self.name))
    }

    fn finish(self) -> Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(anyhow!("trailing bytes in {} key", self.name))
        }
    }
}

/// The stored value of a customer row.
type CustomerValue = (
    Vec<u8>,
    Uuid,
    String,
    String,
    SentaEndpointKeysetVersion,
    u64,
);

impl Row for SentaEndpointCustomer {
    const FAMILY: &'static str = crate::tables::SENTA_ENDPOINT_CUSTOMERS;
    const NAME: &'static str = "senta endpoint customer";

    fn key(&self) -> Vec<u8> {
        keys::customer(self.customer_id)
    }

    fn value(&self) -> Result<Vec<u8>> {
        crate::tables::serialize(&(
            &self.trust_state,
            &self.customer_endpoint_id,
            &self.customer_key_name,
            &self.install_id,
            &self.last_keyset,
            self.recovery_key_version,
        ))
    }
}

impl FromKeyValue for SentaEndpointCustomer {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let mut reader = KeyReader::new(key, Self::NAME);
        let customer_id = reader.u32()?;
        reader.finish()?;
        let (
            trust_state,
            customer_endpoint_id,
            customer_key_name,
            install_id,
            last_keyset,
            recovery_key_version,
        ): CustomerValue = crate::tables::deserialize(value)
            .with_context(|| format!("invalid row of senta endpoint customer {customer_id}"))?;
        Ok(Self {
            customer_id,
            trust_state,
            customer_endpoint_id,
            customer_key_name,
            install_id,
            last_keyset,
            recovery_key_version,
        })
    }
}

/// The stored value of an install row.
type InstallValue = (String, u64, String, u64);

impl Row for SentaEndpointInstall {
    const FAMILY: &'static str = crate::tables::SENTA_ENDPOINT_INSTALLS;
    const NAME: &'static str = "senta endpoint install";

    fn key(&self) -> Vec<u8> {
        keys::install(&self.install_id)
    }

    fn value(&self) -> Result<Vec<u8>> {
        crate::tables::serialize(&(
            &self.first_recovery_key,
            self.first_recovery_key_version,
            &self.current_recovery_key,
            self.current_recovery_key_version,
        ))
    }
}

impl FromKeyValue for SentaEndpointInstall {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let mut reader = KeyReader::new(key, Self::NAME);
        let install_id = reader.string()?;
        reader.finish()?;
        let (
            first_recovery_key,
            first_recovery_key_version,
            current_recovery_key,
            current_recovery_key_version,
        ): InstallValue = crate::tables::deserialize(value)
            .with_context(|| format!("invalid row of senta endpoint install {install_id:?}"))?;
        Ok(Self {
            install_id,
            first_recovery_key,
            first_recovery_key_version,
            current_recovery_key,
            current_recovery_key_version,
        })
    }
}

/// The stored value of an endpoint row.
#[derive(Serialize, Deserialize)]
struct EndpointValue {
    customer_id: u32,
    customer_endpoint_id: Uuid,
    spki_hash: [u8; HASH_LEN],
    standing: String,
    host_name: String,
    os: String,
    senta_version: String,
    bundle: String,
    enrolled_at: i64,
    last_connected_at: i64,
    connected: bool,
}

impl Row for SentaEndpoint {
    const FAMILY: &'static str = crate::tables::SENTA_ENDPOINTS;
    const NAME: &'static str = "senta endpoint";

    fn key(&self) -> Vec<u8> {
        keys::endpoint(self.endpoint_id)
    }

    fn value(&self) -> Result<Vec<u8>> {
        crate::tables::serialize(&EndpointValue {
            customer_id: self.customer_id,
            customer_endpoint_id: self.customer_endpoint_id,
            spki_hash: self.spki_hash,
            standing: self.standing.clone(),
            host_name: self.host_name.clone(),
            os: self.os.clone(),
            senta_version: self.senta_version.clone(),
            bundle: self.bundle.clone(),
            enrolled_at: self.enrolled_at,
            last_connected_at: self.last_connected_at,
            connected: self.connected,
        })
    }
}

impl FromKeyValue for SentaEndpoint {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let mut reader = KeyReader::new(key, Self::NAME);
        let endpoint_id = reader.uuid()?;
        reader.finish()?;
        let value: EndpointValue = crate::tables::deserialize(value)
            .with_context(|| format!("invalid row of senta endpoint {endpoint_id}"))?;
        Ok(Self {
            endpoint_id,
            customer_id: value.customer_id,
            customer_endpoint_id: value.customer_endpoint_id,
            spki_hash: value.spki_hash,
            standing: value.standing,
            host_name: value.host_name,
            os: value.os,
            senta_version: value.senta_version,
            bundle: value.bundle,
            enrolled_at: value.enrolled_at,
            last_connected_at: value.last_connected_at,
            connected: value.connected,
        })
    }
}

/// The stored value of an enrollment attempt row.
type AttemptValue = (u32, Vec<u8>, IpAddr, i64, SentaEndpointEnrollmentResult);

impl Row for SentaEndpointEnrollmentAttempt {
    const FAMILY: &'static str = crate::tables::SENTA_ENDPOINT_ENROLLMENT_ATTEMPTS;
    const NAME: &'static str = "senta endpoint enrollment attempt";

    fn key(&self) -> Vec<u8> {
        keys::attempt(&self.spki_hash, self.attempt_id)
    }

    fn value(&self) -> Result<Vec<u8>> {
        crate::tables::serialize(&(
            self.customer_id,
            &self.request,
            &self.source_address,
            self.received_at,
            &self.result,
        ))
    }
}

impl FromKeyValue for SentaEndpointEnrollmentAttempt {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let mut reader = KeyReader::new(key, Self::NAME);
        let spki_hash = reader.take()?;
        let attempt_id = reader.uuid()?;
        reader.finish()?;
        let (customer_id, request, source_address, received_at, result): AttemptValue =
            crate::tables::deserialize(value).with_context(|| {
                format!("invalid row of senta endpoint enrollment attempt {attempt_id}")
            })?;
        Ok(Self {
            spki_hash,
            attempt_id,
            customer_id,
            request,
            source_address,
            received_at,
            result,
        })
    }
}

impl Row for SentaEndpointKeysetDocument {
    const FAMILY: &'static str = crate::tables::SENTA_ENDPOINT_KEYSET_DOCUMENTS;
    const NAME: &'static str = "senta endpoint keyset document";

    fn key(&self) -> Vec<u8> {
        keys::keyset_document(
            self.customer_id,
            self.recovery_epoch,
            self.keyset_version,
            &self.signing_kid,
        )
    }

    fn value(&self) -> Result<Vec<u8>> {
        crate::tables::serialize(&self.jws)
    }
}

impl FromKeyValue for SentaEndpointKeysetDocument {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let mut reader = KeyReader::new(key, Self::NAME);
        let customer_id = reader.u32()?;
        let recovery_epoch = reader.u64()?;
        let keyset_version = reader.u64()?;
        let signing_kid = reader.string()?;
        reader.finish()?;
        let jws = crate::tables::deserialize(value).with_context(|| {
            format!("invalid keyset document of senta endpoint customer {customer_id}")
        })?;
        Ok(Self {
            customer_id,
            recovery_epoch,
            keyset_version,
            signing_kid,
            jws,
        })
    }
}

impl Row for SentaEndpointRecoveryKeyDocument {
    const FAMILY: &'static str = crate::tables::SENTA_ENDPOINT_RECOVERY_KEY_DOCUMENTS;
    const NAME: &'static str = "senta endpoint recovery-key document";

    fn key(&self) -> Vec<u8> {
        keys::recovery_key_document(&self.install_id, self.recovery_key_version)
    }

    fn value(&self) -> Result<Vec<u8>> {
        crate::tables::serialize(&self.jws)
    }
}

impl FromKeyValue for SentaEndpointRecoveryKeyDocument {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let mut reader = KeyReader::new(key, Self::NAME);
        let install_id = reader.string()?;
        let recovery_key_version = reader.u64()?;
        reader.finish()?;
        let jws = crate::tables::deserialize(value).with_context(|| {
            format!("invalid recovery-key document of senta endpoint install {install_id:?}")
        })?;
        Ok(Self {
            install_id,
            recovery_key_version,
            jws,
        })
    }
}

/// The stored value of a current-document row.
type CurrentDocumentValue = (u64, u64, String, i64);

impl Row for SentaEndpointCurrentDocument {
    const FAMILY: &'static str = crate::tables::SENTA_ENDPOINT_CURRENT_DOCUMENTS;
    const NAME: &'static str = "senta endpoint current document";

    fn key(&self) -> Vec<u8> {
        keys::current_document(self.customer_id, &self.typ, &self.target)
    }

    fn value(&self) -> Result<Vec<u8>> {
        crate::tables::serialize(&(self.recovery_epoch, self.version, &self.jws, self.put_at))
    }
}

impl FromKeyValue for SentaEndpointCurrentDocument {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let mut reader = KeyReader::new(key, Self::NAME);
        let customer_id = reader.u32()?;
        let typ = reader.string()?;
        let target = reader.string()?;
        reader.finish()?;
        let (recovery_epoch, version, jws, put_at): CurrentDocumentValue =
            crate::tables::deserialize(value).with_context(|| {
                format!("invalid current document of senta endpoint customer {customer_id}")
            })?;
        Ok(Self {
            customer_id,
            typ,
            target,
            recovery_epoch,
            version,
            jws,
            put_at,
        })
    }
}

impl Row for SentaEndpointAddressRoot {
    const FAMILY: &'static str = crate::tables::SENTA_ENDPOINT_ADDRESS_ROOTS;
    const NAME: &'static str = "senta endpoint address-document root";

    fn key(&self) -> Vec<u8> {
        keys::address_root(
            self.customer_id,
            self.recovery_epoch,
            self.version,
            &self.fingerprint,
        )
    }

    fn value(&self) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

impl FromKeyValue for SentaEndpointAddressRoot {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let mut reader = KeyReader::new(key, Self::NAME);
        let customer_id = reader.u32()?;
        let recovery_epoch = reader.u64()?;
        let version = reader.u64()?;
        let fingerprint = reader.take()?;
        reader.finish()?;
        if !value.is_empty() {
            bail!("an address-document root of senta endpoint customer {customer_id} has a value");
        }
        Ok(Self {
            customer_id,
            recovery_epoch,
            version,
            fingerprint,
        })
    }
}

/// The stored value of a command row.
type CommandValue = (
    Uuid,
    u64,
    String,
    i64,
    SentaEndpointCommandState,
    Option<Vec<u8>>,
);

impl Row for SentaEndpointCommand {
    const FAMILY: &'static str = crate::tables::SENTA_ENDPOINT_COMMANDS;
    const NAME: &'static str = "senta endpoint command";

    fn key(&self) -> Vec<u8> {
        keys::command(self.command_id)
    }

    fn value(&self) -> Result<Vec<u8>> {
        crate::tables::serialize(&(
            &self.endpoint_id,
            self.sequence,
            &self.jws,
            self.expires_at,
            self.state,
            &self.result,
        ))
    }
}

impl FromKeyValue for SentaEndpointCommand {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let mut reader = KeyReader::new(key, Self::NAME);
        let command_id = reader.uuid()?;
        reader.finish()?;
        let (endpoint_id, sequence, jws, expires_at, state, result): CommandValue =
            crate::tables::deserialize(value)
                .with_context(|| format!("invalid row of senta endpoint command {command_id}"))?;
        Ok(Self {
            command_id,
            endpoint_id,
            sequence,
            jws,
            expires_at,
            state,
            result,
        })
    }
}

/// The generic reads and writes of the Clumit Endpoint tables.
impl<'d, R: Row> Table<'d, R> {
    /// Opens the table of `R` in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(in crate::tables) fn open_senta_endpoint(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, R::FAMILY).map(Self::new)
    }

    /// Returns the row stored under `key`.
    fn row(&self, key: &[u8]) -> Result<Option<R>> {
        self.map
            .db
            .get_cf(self.map.cf, key)
            .with_context(|| format!("failed to read {}", R::NAME))?
            .map(|value| R::from_key_value(key, &value))
            .transpose()
    }

    /// Returns every row whose key starts with `prefix`, in key order.
    fn rows_with_prefix(&self, prefix: &[u8]) -> Result<Vec<R>> {
        let mut opts = rocksdb::ReadOptions::default();
        opts.set_iterate_range(rocksdb::PrefixRange(prefix));
        self.map
            .db
            .iterator_cf_opt(self.map.cf, opts, IteratorMode::Start)
            .map(|entry| {
                let (key, value) = entry.with_context(|| format!("failed to read {}", R::NAME))?;
                R::from_key_value(&key, &value)
            })
            .collect()
    }

    /// Returns every row for which `keep` holds, in key order.
    ///
    /// The scan reads the latest committed rows and is not tracked by any
    /// transaction.
    pub(crate) fn rows_where(&self, mut keep: impl FnMut(&R) -> bool) -> Result<Vec<R>> {
        let mut rows = Vec::new();
        for entry in self.map.db.iterator_cf(self.map.cf, IteratorMode::Start) {
            let (key, value) = entry.with_context(|| format!("failed to read {}", R::NAME))?;
            let row = R::from_key_value(&key, &value)?;
            if keep(&row) {
                rows.push(row);
            }
        }
        Ok(rows)
    }

    /// Returns the row stored under `key`, read for update within `txn`.
    pub(crate) fn row_for_update(&self, txn: &Txn<'_>, key: &[u8]) -> Result<Option<R>> {
        txn.get_for_update_cf(self.map.cf, key, EXCLUSIVE)
            .with_context(|| format!("failed to read {}", R::NAME))?
            .map(|value| R::from_key_value(key, &value))
            .transpose()
    }

    /// Returns whether a row is stored under `key`, read for update within
    /// `txn`, without decoding it.
    pub(crate) fn exists_for_update(&self, txn: &Txn<'_>, key: &[u8]) -> Result<bool> {
        Ok(txn
            .get_for_update_cf(self.map.cf, key, EXCLUSIVE)
            .with_context(|| format!("failed to read {}", R::NAME))?
            .is_some())
    }

    /// Writes `row` within `txn`.
    pub(crate) fn write_row(&self, txn: &Txn<'_>, row: &R) -> Result<()> {
        let value = row
            .value()
            .with_context(|| format!("failed to serialize {}", R::NAME))?;
        txn.put_cf(self.map.cf, row.key(), value)
            .with_context(|| format!("failed to write {}", R::NAME))
    }

    /// Deletes the row under `key`, if any.
    fn delete_key(&self, key: &[u8]) -> Result<()> {
        self.map
            .db
            .delete_cf(self.map.cf, key)
            .with_context(|| format!("failed to delete {}", R::NAME))
    }

    /// Deletes every row whose key starts with `prefix`, and returns how many
    /// were deleted.
    fn delete_prefix(&self, prefix: &[u8]) -> Result<usize> {
        loop {
            let txn = self.map.db.transaction();
            let mut opts = rocksdb::ReadOptions::default();
            opts.set_iterate_range(rocksdb::PrefixRange(prefix));
            let mut deleted = 0;
            for entry in self
                .map
                .db
                .iterator_cf_opt(self.map.cf, opts, IteratorMode::Start)
            {
                let (key, _) = entry.with_context(|| format!("failed to read {}", R::NAME))?;
                txn.delete_cf(self.map.cf, &key)
                    .with_context(|| format!("failed to delete {}", R::NAME))?;
                deleted += 1;
            }
            match txn.commit() {
                Ok(()) => return Ok(deleted),
                Err(e) if is_conflict(&e) => {}
                Err(e) => {
                    return Err(e).with_context(|| format!("failed to delete {} rows", R::NAME));
                }
            }
        }
    }

    /// Reads the row under `key` for update, applies `change` to it and writes
    /// the result, committing with a retry on a conflicting write.
    ///
    /// No row is created: an absent row is refused with `absent`. A refusal
    /// `change` returns writes nothing.
    fn update_row(
        &self,
        key: &[u8],
        absent: impl Fn() -> SentaEndpointError,
        mut change: impl FnMut(&mut R) -> Result<(), SentaEndpointError>,
    ) -> Result<R, SentaEndpointError> {
        loop {
            let txn = self.map.db.transaction();
            let Some(mut row) = self.row_for_update(&txn, key)? else {
                return Err(absent());
            };
            change(&mut row)?;
            self.write_row(&txn, &row)?;
            match txn.commit() {
                Ok(()) => return Ok(row),
                Err(e) if is_conflict(&e) => {}
                Err(e) => {
                    return Err(anyhow::Error::from(e)
                        .context(format!("failed to update {}", R::NAME))
                        .into());
                }
            }
        }
    }
}

/// Functions for the senta endpoint customer table.
impl Table<'_, SentaEndpointCustomer> {
    /// Returns the row of `customer_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row is
    /// invalid.
    pub fn get(&self, customer_id: u32) -> Result<Option<SentaEndpointCustomer>> {
        self.row(&keys::customer(customer_id))
    }

    /// Returns the rows of every customer of `install_id`, in order of the
    /// customer ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored row is
    /// invalid.
    pub fn of_install(&self, install_id: &str) -> Result<Vec<SentaEndpointCustomer>> {
        self.rows_where(|row| row.install_id == install_id)
    }

    /// Deletes the row of `customer_id`, if any. The table holds one row per
    /// customer, so this is also the deletion of the customer's rows.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, customer_id: u32) -> Result<()> {
        self.delete_key(&keys::customer(customer_id))
    }
}

/// Functions for the senta endpoint install table.
impl Table<'_, SentaEndpointInstall> {
    /// Returns the row of `install_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row is
    /// invalid.
    pub fn get(&self, install_id: &str) -> Result<Option<SentaEndpointInstall>> {
        self.row(&keys::install(install_id))
    }

    /// Registers `install_id` with its first recovery key, which is also its
    /// current one, and returns whether a row was written.
    ///
    /// An install already registered with the same first recovery key and
    /// version is left as it is, also after a rotation changed its current
    /// key, and `Ok(false)` is returned.
    ///
    /// # Errors
    ///
    /// Returns [`SentaEndpointError::InstallConflict`] if the install is
    /// registered with another first recovery key or version, or
    /// [`SentaEndpointError::Database`] if the database operation fails or the
    /// stored row is invalid.
    pub fn register(
        &self,
        install_id: &str,
        first_recovery_key: &str,
        first_recovery_key_version: u64,
    ) -> Result<bool, SentaEndpointError> {
        let key = keys::install(install_id);
        loop {
            let txn = self.map.db.transaction();
            if let Some(stored) = self.row_for_update(&txn, &key)? {
                if stored.first_recovery_key == first_recovery_key
                    && stored.first_recovery_key_version == first_recovery_key_version
                {
                    return Ok(false);
                }
                return Err(SentaEndpointError::InstallConflict {
                    install_id: install_id.to_string(),
                });
            }
            self.write_row(
                &txn,
                &SentaEndpointInstall {
                    install_id: install_id.to_string(),
                    first_recovery_key: first_recovery_key.to_string(),
                    first_recovery_key_version,
                    current_recovery_key: first_recovery_key.to_string(),
                    current_recovery_key_version: first_recovery_key_version,
                },
            )?;
            match txn.commit() {
                Ok(()) => return Ok(true),
                Err(e) if is_conflict(&e) => {}
                Err(e) => {
                    return Err(anyhow::Error::from(e)
                        .context(format!(
                            "failed to register senta endpoint install {install_id:?}"
                        ))
                        .into());
                }
            }
        }
    }

    /// Deletes the row of `install_id`, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, install_id: &str) -> Result<()> {
        self.delete_key(&keys::install(install_id))
    }
}

/// Functions for the senta endpoint table.
impl Table<'_, SentaEndpoint> {
    /// Returns the row of `endpoint_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row is
    /// invalid.
    pub fn get(&self, endpoint_id: Uuid) -> Result<Option<SentaEndpoint>> {
        self.row(&keys::endpoint(endpoint_id))
    }

    /// Returns the rows of every endpoint of `customer_id`, in order of the
    /// endpoint ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored row is
    /// invalid.
    pub fn of_customer(&self, customer_id: u32) -> Result<Vec<SentaEndpoint>> {
        self.rows_where(|row| row.customer_id == customer_id)
    }

    /// Sets the active-list standing of an existing endpoint, and returns the
    /// stored row.
    ///
    /// # Errors
    ///
    /// Returns [`SentaEndpointError::EndpointNotFound`] if the endpoint has no
    /// row, or [`SentaEndpointError::Database`] if the database operation
    /// fails or the stored row is invalid.
    pub fn set_standing(
        &self,
        endpoint_id: Uuid,
        standing: &str,
    ) -> Result<SentaEndpoint, SentaEndpointError> {
        self.update_endpoint(endpoint_id, |row| standing.clone_into(&mut row.standing))
    }

    /// Sets the host name, OS, senta version and bundle of an existing
    /// endpoint, and returns the stored row.
    ///
    /// # Errors
    ///
    /// Returns [`SentaEndpointError::EndpointNotFound`] if the endpoint has no
    /// row, or [`SentaEndpointError::Database`] if the database operation
    /// fails or the stored row is invalid.
    pub fn set_host(
        &self,
        endpoint_id: Uuid,
        host_name: &str,
        os: &str,
        senta_version: &str,
        bundle: &str,
    ) -> Result<SentaEndpoint, SentaEndpointError> {
        self.update_endpoint(endpoint_id, |row| {
            host_name.clone_into(&mut row.host_name);
            os.clone_into(&mut row.os);
            senta_version.clone_into(&mut row.senta_version);
            bundle.clone_into(&mut row.bundle);
        })
    }

    /// Sets the connection state of an existing endpoint: whether it is
    /// connected now and when it last connected. Returns the stored row.
    ///
    /// # Errors
    ///
    /// Returns [`SentaEndpointError::EndpointNotFound`] if the endpoint has no
    /// row, or [`SentaEndpointError::Database`] if the database operation
    /// fails or the stored row is invalid.
    pub fn set_connection(
        &self,
        endpoint_id: Uuid,
        connected: bool,
        last_connected_at: i64,
    ) -> Result<SentaEndpoint, SentaEndpointError> {
        self.update_endpoint(endpoint_id, |row| {
            row.connected = connected;
            row.last_connected_at = last_connected_at;
        })
    }

    fn update_endpoint(
        &self,
        endpoint_id: Uuid,
        change: impl Fn(&mut SentaEndpoint),
    ) -> Result<SentaEndpoint, SentaEndpointError> {
        self.update_row(
            &keys::endpoint(endpoint_id),
            || SentaEndpointError::EndpointNotFound { endpoint_id },
            |row| {
                change(row);
                Ok(())
            },
        )
    }

    /// Deletes the row of `endpoint_id`, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, endpoint_id: Uuid) -> Result<()> {
        self.delete_key(&keys::endpoint(endpoint_id))
    }
}

/// Functions for the senta endpoint enrollment attempt table.
impl Table<'_, SentaEndpointEnrollmentAttempt> {
    /// Returns the attempt `attempt_id` of the key whose SPKI hash is
    /// `spki_hash`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row is
    /// invalid.
    pub fn get(
        &self,
        spki_hash: &[u8; HASH_LEN],
        attempt_id: Uuid,
    ) -> Result<Option<SentaEndpointEnrollmentAttempt>> {
        self.row(&keys::attempt(spki_hash, attempt_id))
    }

    /// Returns every attempt of the key whose SPKI hash is `spki_hash`, in
    /// order of the attempt ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored row is
    /// invalid.
    pub fn of_spki_hash(
        &self,
        spki_hash: &[u8; HASH_LEN],
    ) -> Result<Vec<SentaEndpointEnrollmentAttempt>> {
        self.rows_with_prefix(&keys::attempt_prefix(spki_hash))
    }

    /// Returns every attempt of `customer_id`, in key order.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored row is
    /// invalid.
    pub fn of_customer(&self, customer_id: u32) -> Result<Vec<SentaEndpointEnrollmentAttempt>> {
        self.rows_where(|row| row.customer_id == customer_id)
    }

    /// Inserts `attempt` unless an attempt is stored under its key, and returns
    /// whether it was written. A stored attempt is left as it is.
    ///
    /// Only [`Store::approve_senta_endpoint_enrollment`] writes an approved
    /// result, and only [`Store::replace_senta_endpoint_enrollment_result`]
    /// changes one, so `attempt` must be pending or denied.
    ///
    /// [`Store::approve_senta_endpoint_enrollment`]: crate::Store::approve_senta_endpoint_enrollment
    /// [`Store::replace_senta_endpoint_enrollment_result`]: crate::Store::replace_senta_endpoint_enrollment_result
    ///
    /// # Errors
    ///
    /// Returns [`SentaEndpointError::ApprovalWithoutEndpoint`], writing
    /// nothing, if the result of `attempt` is approved, or
    /// [`SentaEndpointError::Database`] if the database operation fails.
    pub fn insert(
        &self,
        attempt: &SentaEndpointEnrollmentAttempt,
    ) -> Result<bool, SentaEndpointError> {
        if matches!(
            attempt.result,
            SentaEndpointEnrollmentResult::Approved { .. }
        ) {
            return Err(SentaEndpointError::ApprovalWithoutEndpoint {
                attempt_id: attempt.attempt_id,
            });
        }
        let key = attempt.key();
        loop {
            let txn = self.map.db.transaction();
            if self.exists_for_update(&txn, &key)? {
                return Ok(false);
            }
            self.write_row(&txn, attempt)?;
            match txn.commit() {
                Ok(()) => return Ok(true),
                Err(e) if is_conflict(&e) => {}
                Err(e) => {
                    return Err(anyhow::Error::from(e)
                        .context(format!(
                            "failed to insert senta endpoint enrollment attempt {}",
                            attempt.attempt_id
                        ))
                        .into());
                }
            }
        }
    }

    /// Sets the result of an existing attempt to pending or denied, and
    /// returns the stored attempt.
    ///
    /// Only [`Store::approve_senta_endpoint_enrollment`] writes an approved
    /// result, and an approved attempt is not changed here; only
    /// [`Store::replace_senta_endpoint_enrollment_result`] replaces its
    /// result.
    ///
    /// [`Store::approve_senta_endpoint_enrollment`]: crate::Store::approve_senta_endpoint_enrollment
    /// [`Store::replace_senta_endpoint_enrollment_result`]: crate::Store::replace_senta_endpoint_enrollment_result
    ///
    /// # Errors
    ///
    /// Returns [`SentaEndpointError::ApprovalWithoutEndpoint`] if `result` is
    /// approved, [`SentaEndpointError::AttemptNotFound`] if the attempt has no
    /// row, [`SentaEndpointError::AttemptApproved`] if its stored result is
    /// approved, or [`SentaEndpointError::Database`] if the database operation
    /// fails or the stored row is invalid.
    pub fn set_result(
        &self,
        spki_hash: &[u8; HASH_LEN],
        attempt_id: Uuid,
        result: &SentaEndpointEnrollmentResult,
    ) -> Result<SentaEndpointEnrollmentAttempt, SentaEndpointError> {
        if matches!(result, SentaEndpointEnrollmentResult::Approved { .. }) {
            return Err(SentaEndpointError::ApprovalWithoutEndpoint { attempt_id });
        }
        self.update_row(
            &keys::attempt(spki_hash, attempt_id),
            || SentaEndpointError::AttemptNotFound { attempt_id },
            |row| {
                if matches!(row.result, SentaEndpointEnrollmentResult::Approved { .. }) {
                    return Err(SentaEndpointError::AttemptApproved { attempt_id });
                }
                row.result.clone_from(result);
                Ok(())
            },
        )
    }

    /// Deletes the attempt `attempt_id` of the key whose SPKI hash is
    /// `spki_hash`, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, spki_hash: &[u8; HASH_LEN], attempt_id: Uuid) -> Result<()> {
        self.delete_key(&keys::attempt(spki_hash, attempt_id))
    }
}

/// Functions for the senta endpoint keyset document table.
impl Table<'_, SentaEndpointKeysetDocument> {
    /// Returns the keyset document of `customer_id` at `(recovery_epoch,
    /// keyset_version)` signed by `signing_kid`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row is
    /// invalid.
    pub fn get(
        &self,
        customer_id: u32,
        recovery_epoch: u64,
        keyset_version: u64,
        signing_kid: &str,
    ) -> Result<Option<SentaEndpointKeysetDocument>> {
        self.row(&keys::keyset_document(
            customer_id,
            recovery_epoch,
            keyset_version,
            signing_kid,
        ))
    }

    /// Returns every keyset document of `customer_id`, in order of the
    /// recovery epoch, the keyset version and the signing key ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored row is
    /// invalid.
    pub fn of_customer(&self, customer_id: u32) -> Result<Vec<SentaEndpointKeysetDocument>> {
        self.rows_with_prefix(&keys::customer(customer_id))
    }

    /// Deletes one keyset document, if it is stored.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(
        &self,
        customer_id: u32,
        recovery_epoch: u64,
        keyset_version: u64,
        signing_kid: &str,
    ) -> Result<()> {
        self.delete_key(&keys::keyset_document(
            customer_id,
            recovery_epoch,
            keyset_version,
            signing_kid,
        ))
    }

    /// Deletes every keyset document of `customer_id`, and returns how many
    /// were deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete_customer(&self, customer_id: u32) -> Result<usize> {
        self.delete_prefix(&keys::customer(customer_id))
    }
}

/// Functions for the senta endpoint recovery-key document table.
impl Table<'_, SentaEndpointRecoveryKeyDocument> {
    /// Returns the recovery-key document of `install_id` at
    /// `recovery_key_version`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row is
    /// invalid.
    pub fn get(
        &self,
        install_id: &str,
        recovery_key_version: u64,
    ) -> Result<Option<SentaEndpointRecoveryKeyDocument>> {
        self.row(&keys::recovery_key_document(
            install_id,
            recovery_key_version,
        ))
    }

    /// Returns every recovery-key document of `install_id`, in order of the
    /// recovery key version.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored row is
    /// invalid.
    pub fn of_install(&self, install_id: &str) -> Result<Vec<SentaEndpointRecoveryKeyDocument>> {
        self.rows_with_prefix(&keys::install(install_id))
    }

    /// Deletes one recovery-key document, if it is stored.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, install_id: &str, recovery_key_version: u64) -> Result<()> {
        self.delete_key(&keys::recovery_key_document(
            install_id,
            recovery_key_version,
        ))
    }
}

/// Functions for the senta endpoint current document table.
impl Table<'_, SentaEndpointCurrentDocument> {
    /// Returns the current document of `customer_id` for `typ` and `target`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row is
    /// invalid.
    pub fn get(
        &self,
        customer_id: u32,
        typ: &str,
        target: &str,
    ) -> Result<Option<SentaEndpointCurrentDocument>> {
        self.row(&keys::current_document(customer_id, typ, target))
    }

    /// Returns every current document of `customer_id`, in key order.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored row is
    /// invalid.
    pub fn of_customer(&self, customer_id: u32) -> Result<Vec<SentaEndpointCurrentDocument>> {
        self.rows_with_prefix(&keys::customer(customer_id))
    }

    /// Returns every current document of `customer_id` for `typ`, in key
    /// order.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored row is
    /// invalid.
    pub fn of_customer_typ(
        &self,
        customer_id: u32,
        typ: &str,
    ) -> Result<Vec<SentaEndpointCurrentDocument>> {
        self.rows_with_prefix(&keys::current_document_prefix(customer_id, typ))
    }

    /// Deletes one current document, if it is stored.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, customer_id: u32, typ: &str, target: &str) -> Result<()> {
        self.delete_key(&keys::current_document(customer_id, typ, target))
    }

    /// Deletes every current document of `customer_id`, and returns how many
    /// were deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete_customer(&self, customer_id: u32) -> Result<usize> {
        self.delete_prefix(&keys::customer(customer_id))
    }
}

/// Functions for the senta endpoint address-document root table.
impl Table<'_, SentaEndpointAddressRoot> {
    /// Returns whether `root` is stored.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row is
    /// invalid.
    pub fn contains(&self, root: &SentaEndpointAddressRoot) -> Result<bool> {
        Ok(self.row(&root.key())?.is_some())
    }

    /// Returns every root of the address document of `customer_id` at
    /// `(recovery_epoch, version)`, in order of the fingerprint.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored row is
    /// invalid.
    pub fn of_document(
        &self,
        customer_id: u32,
        recovery_epoch: u64,
        version: u64,
    ) -> Result<Vec<SentaEndpointAddressRoot>> {
        self.rows_with_prefix(&keys::address_root_prefix(
            customer_id,
            recovery_epoch,
            version,
        ))
    }

    /// Returns every root of `customer_id`, in order of the recovery epoch,
    /// the version and the fingerprint.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored row is
    /// invalid.
    pub fn of_customer(&self, customer_id: u32) -> Result<Vec<SentaEndpointAddressRoot>> {
        self.rows_with_prefix(&keys::customer(customer_id))
    }

    /// Deletes `root`, if it is stored.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, root: &SentaEndpointAddressRoot) -> Result<()> {
        self.delete_key(&root.key())
    }

    /// Deletes every root of `customer_id`, and returns how many were
    /// deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete_customer(&self, customer_id: u32) -> Result<usize> {
        self.delete_prefix(&keys::customer(customer_id))
    }
}

/// Functions for the senta endpoint command table.
impl Table<'_, SentaEndpointCommand> {
    /// Returns the command `command_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row is
    /// invalid.
    pub fn get(&self, command_id: Uuid) -> Result<Option<SentaEndpointCommand>> {
        self.row(&keys::command(command_id))
    }

    /// Returns every command of `endpoint_id`, in order of the command ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored row is
    /// invalid.
    pub fn of_endpoint(&self, endpoint_id: Uuid) -> Result<Vec<SentaEndpointCommand>> {
        self.rows_where(|row| row.endpoint_id == endpoint_id)
    }

    /// Sets the state and the result of an existing command, and returns the
    /// stored row.
    ///
    /// # Errors
    ///
    /// Returns [`SentaEndpointError::CommandNotFound`] if the command has no
    /// row, or [`SentaEndpointError::Database`] if the database operation
    /// fails or the stored row is invalid.
    pub fn set_state(
        &self,
        command_id: Uuid,
        state: SentaEndpointCommandState,
        result: Option<&[u8]>,
    ) -> Result<SentaEndpointCommand, SentaEndpointError> {
        self.update_row(
            &keys::command(command_id),
            || SentaEndpointError::CommandNotFound { command_id },
            |row| {
                row.state = state;
                row.result = result.map(<[u8]>::to_vec);
                Ok(())
            },
        )
    }

    /// Deletes the command `command_id`, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, command_id: Uuid) -> Result<()> {
        self.delete_key(&keys::command(command_id))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rocksdb::Direction;

    use super::*;
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Iterable, Store};

    fn setup_store() -> (
        DbGuard<'static>,
        tempfile::TempDir,
        tempfile::TempDir,
        Store,
    ) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
        (permit, db_dir, backup_dir, store)
    }

    fn all<R>(table: &Table<'_, R>) -> Vec<R>
    where
        R: FromKeyValue + crate::tables::iteration::Eligible,
    {
        table
            .iter(Direction::Forward, None)
            .collect::<Result<Vec<_>>>()
            .unwrap()
    }

    fn write<R: Row>(store: &Store, table: &Table<'_, R>, row: &R) {
        let txn = store.states.db().transaction();
        table.write_row(&txn, row).unwrap();
        txn.commit().unwrap();
    }

    fn customer(customer_id: u32, install_id: &str) -> SentaEndpointCustomer {
        SentaEndpointCustomer {
            customer_id,
            trust_state: vec![0xa1, 0x00, 0xff, 0x00, 0x01, 0x7f],
            customer_endpoint_id: Uuid::from_u128(u128::from(customer_id) << 64 | 7),
            customer_key_name: format!("key-{customer_id}"),
            install_id: install_id.to_string(),
            last_keyset: SentaEndpointKeysetVersion {
                recovery_epoch: 2,
                keyset_version: 9,
            },
            recovery_key_version: 3,
        }
    }

    fn keyset(
        customer_id: u32,
        epoch: u64,
        version: u64,
        kid: &str,
    ) -> SentaEndpointKeysetDocument {
        SentaEndpointKeysetDocument {
            customer_id,
            recovery_epoch: epoch,
            keyset_version: version,
            signing_kid: kid.to_string(),
            jws: format!("jws-{customer_id}-{epoch}-{version}-{kid}"),
        }
    }

    fn endpoint(id: u128, customer_id: u32) -> SentaEndpoint {
        SentaEndpoint {
            endpoint_id: Uuid::from_u128(id),
            customer_id,
            customer_endpoint_id: Uuid::from_u128(id + 1000),
            spki_hash: [u8::try_from(id % 256).unwrap(); 32],
            standing: "active".to_string(),
            host_name: "host".to_string(),
            os: "linux".to_string(),
            senta_version: "1.0.0".to_string(),
            bundle: "bundle".to_string(),
            enrolled_at: 10,
            last_connected_at: 20,
            connected: true,
        }
    }

    fn attempt(spki: u8, id: u128, customer_id: u32) -> SentaEndpointEnrollmentAttempt {
        SentaEndpointEnrollmentAttempt {
            spki_hash: [spki; 32],
            attempt_id: Uuid::from_u128(id),
            customer_id,
            request: vec![1, 2, 3],
            source_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            received_at: 30,
            result: SentaEndpointEnrollmentResult::Pending {
                reason: "queued".to_string(),
            },
        }
    }

    fn command(id: u128, endpoint_id: u128) -> SentaEndpointCommand {
        SentaEndpointCommand {
            command_id: Uuid::from_u128(id),
            endpoint_id: Uuid::from_u128(endpoint_id),
            sequence: 4,
            jws: "command-jws".to_string(),
            expires_at: 40,
            state: SentaEndpointCommandState::Pending,
            result: None,
        }
    }

    #[test]
    fn string_components_keep_order_and_exact_prefixes() {
        let strings = ["", "\0", "\0\0", "a", "a\0", "a\0b", "ab", "abc", "b"];
        let encoded: Vec<Vec<u8>> = strings.iter().map(|s| keys::install(s)).collect();
        let mut sorted = encoded.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted, encoded,
            "the encoding keeps the order of the strings"
        );
        for (i, a) in encoded.iter().enumerate() {
            for (j, b) in encoded.iter().enumerate() {
                if i != j {
                    assert!(
                        !b.starts_with(a),
                        "{:?} prefixes {:?}",
                        strings[i],
                        strings[j]
                    );
                }
            }
            let mut reader = KeyReader::new(a, "test");
            assert_eq!(reader.string().unwrap(), strings[i]);
            reader.finish().unwrap();
        }
        assert!(KeyReader::new(b"a", "test").string().is_err());
        assert!(KeyReader::new(b"a\0\x02", "test").string().is_err());
    }

    #[test]
    fn customer_rows_round_trip_with_their_trust_state() {
        let (_permit, _db, _backup, store) = setup_store();
        let table = store.senta_endpoint_customer_map();
        let first = customer(0x0100, "install-a");
        let second = customer(2, "install-ab");
        let third = customer(3, "install-a");
        for row in [&first, &second, &third] {
            write(&store, &table, row);
        }

        let stored = table.get(first.customer_id).unwrap().unwrap();
        assert_eq!(stored, first);
        assert_eq!(stored.trust_state, vec![0xa1, 0x00, 0xff, 0x00, 0x01, 0x7f]);
        assert_eq!(table.get(4).unwrap(), None);
        assert_eq!(
            all(&table),
            vec![second.clone(), third.clone(), first.clone()]
        );
        assert_eq!(
            table.of_install("install-a").unwrap(),
            vec![third, first.clone()]
        );
        assert_eq!(table.of_install("install-ab").unwrap(), vec![second]);
        assert_eq!(table.of_install("install").unwrap(), vec![]);

        table.delete(first.customer_id).unwrap();
        assert_eq!(table.get(first.customer_id).unwrap(), None);
    }

    #[test]
    fn install_registration_keeps_the_first_key() {
        let (_permit, _db, _backup, store) = setup_store();
        let table = store.senta_endpoint_install_map();
        assert!(table.register("install", "{\"k\":1}", 1).unwrap());
        let registered = table.get("install").unwrap().unwrap();
        assert_eq!(
            registered,
            SentaEndpointInstall {
                install_id: "install".to_string(),
                first_recovery_key: "{\"k\":1}".to_string(),
                first_recovery_key_version: 1,
                current_recovery_key: "{\"k\":1}".to_string(),
                current_recovery_key_version: 1,
            }
        );

        // The same values succeed without a write.
        assert!(!table.register("install", "{\"k\":1}", 1).unwrap());
        // Other values are refused.
        assert!(matches!(
            table.register("install", "{\"k\":2}", 1),
            Err(SentaEndpointError::InstallConflict { install_id }) if install_id == "install"
        ));
        assert!(matches!(
            table.register("install", "{\"k\":1}", 2),
            Err(SentaEndpointError::InstallConflict { .. })
        ));
        assert_eq!(table.get("install").unwrap(), Some(registered.clone()));

        // After a rotation, the same first key still succeeds without a write.
        let rotated = SentaEndpointInstall {
            current_recovery_key: "{\"k\":2}".to_string(),
            current_recovery_key_version: 2,
            ..registered
        };
        write(&store, &table, &rotated);
        assert!(!table.register("install", "{\"k\":1}", 1).unwrap());
        assert_eq!(table.get("install").unwrap(), Some(rotated.clone()));

        assert!(table.register("install-2", "{}", 5).unwrap());
        assert_eq!(all(&table).len(), 2);
        table.delete("install-2").unwrap();
        assert_eq!(all(&table), vec![rotated]);
    }

    #[test]
    fn endpoint_rows_change_only_when_they_exist() {
        let (_permit, _db, _backup, store) = setup_store();
        let table = store.senta_endpoint_map();
        let first = endpoint(2, 1);
        let second = endpoint(1, 2);
        let third = endpoint(3, 1);
        for row in [&first, &second, &third] {
            write(&store, &table, row);
        }
        assert_eq!(table.get(first.endpoint_id).unwrap(), Some(first.clone()));
        assert_eq!(
            all(&table),
            vec![second.clone(), first.clone(), third.clone()]
        );
        assert_eq!(table.of_customer(1).unwrap(), vec![first.clone(), third]);
        assert_eq!(table.of_customer(2).unwrap(), vec![second]);

        let changed = table.set_standing(first.endpoint_id, "blocked").unwrap();
        assert_eq!(changed.standing, "blocked");
        let changed = table
            .set_host(first.endpoint_id, "host-2", "windows", "1.1.0", "bundle-2")
            .unwrap();
        assert_eq!(
            (
                changed.host_name.as_str(),
                changed.os.as_str(),
                changed.senta_version.as_str(),
                changed.bundle.as_str()
            ),
            ("host-2", "windows", "1.1.0", "bundle-2")
        );
        let changed = table.set_connection(first.endpoint_id, false, 50).unwrap();
        assert!(!changed.connected);
        assert_eq!(changed.last_connected_at, 50);
        assert_eq!(table.get(first.endpoint_id).unwrap(), Some(changed));

        let absent = Uuid::from_u128(99);
        assert!(matches!(
            table.set_standing(absent, "blocked"),
            Err(SentaEndpointError::EndpointNotFound { endpoint_id }) if endpoint_id == absent
        ));
        assert!(table.set_host(absent, "h", "o", "v", "b").is_err());
        assert!(table.set_connection(absent, true, 1).is_err());
        assert_eq!(table.get(absent).unwrap(), None);

        table.delete(first.endpoint_id).unwrap();
        assert_eq!(table.get(first.endpoint_id).unwrap(), None);
    }

    #[test]
    fn enrollment_attempts_insert_once_and_change_their_result() {
        let (_permit, _db, _backup, store) = setup_store();
        let table = store.senta_endpoint_enrollment_attempt_map();
        let first = attempt(1, 2, 7);
        let second = attempt(1, 1, 8);
        let third = attempt(0, 3, 7);
        for row in [&first, &second, &third] {
            assert!(table.insert(row).unwrap());
        }
        let mut again = first.clone();
        again.request = vec![9];
        assert!(!table.insert(&again).unwrap());

        // Only the approval writes an approved result, also on insertion.
        let mut approved_insert = attempt(2, 4, 7);
        approved_insert.result = SentaEndpointEnrollmentResult::Approved {
            result: "jws".to_string(),
        };
        assert!(matches!(
            table.insert(&approved_insert),
            Err(SentaEndpointError::ApprovalWithoutEndpoint { attempt_id })
                if attempt_id == approved_insert.attempt_id
        ));
        assert_eq!(
            table
                .get(&approved_insert.spki_hash, approved_insert.attempt_id)
                .unwrap(),
            None
        );
        assert_eq!(
            table.get(&first.spki_hash, first.attempt_id).unwrap(),
            Some(first.clone())
        );
        assert_eq!(
            all(&table),
            vec![third.clone(), second.clone(), first.clone()]
        );
        assert_eq!(
            table.of_spki_hash(&[1; 32]).unwrap(),
            vec![second.clone(), first.clone()]
        );
        assert_eq!(table.of_customer(7).unwrap(), vec![third, first.clone()]);

        let denied = SentaEndpointEnrollmentResult::Denied {
            reason: "no".to_string(),
        };
        let pending = SentaEndpointEnrollmentResult::Pending {
            reason: "again".to_string(),
        };
        let stored = table
            .set_result(&first.spki_hash, first.attempt_id, &denied)
            .unwrap();
        assert_eq!(stored.result, denied);
        let stored = table
            .set_result(&first.spki_hash, first.attempt_id, &pending)
            .unwrap();
        assert_eq!(stored.result, pending);
        assert_eq!(
            table.get(&first.spki_hash, first.attempt_id).unwrap(),
            Some(stored)
        );

        // No row is created for an absent key.
        let absent = Uuid::from_u128(42);
        assert!(matches!(
            table.set_result(&first.spki_hash, absent, &denied),
            Err(SentaEndpointError::AttemptNotFound { attempt_id }) if attempt_id == absent
        ));
        assert_eq!(table.get(&first.spki_hash, absent).unwrap(), None);

        // Only the approval writes an approved result.
        let approved = SentaEndpointEnrollmentResult::Approved {
            result: "jws".to_string(),
        };
        assert!(matches!(
            table.set_result(&first.spki_hash, first.attempt_id, &approved),
            Err(SentaEndpointError::ApprovalWithoutEndpoint { .. })
        ));
        let mut approved_attempt = second.clone();
        approved_attempt.result = approved.clone();
        write(&store, &table, &approved_attempt);
        assert!(matches!(
            table.set_result(&second.spki_hash, second.attempt_id, &denied),
            Err(SentaEndpointError::AttemptApproved { .. })
        ));
        assert_eq!(
            table.get(&second.spki_hash, second.attempt_id).unwrap(),
            Some(approved_attempt)
        );

        table.delete(&second.spki_hash, second.attempt_id).unwrap();
        assert_eq!(
            table.get(&second.spki_hash, second.attempt_id).unwrap(),
            None
        );
    }

    #[test]
    fn keyset_documents_iterate_by_epoch_version_and_kid() {
        let (_permit, _db, _backup, store) = setup_store();
        let table = store.senta_endpoint_keyset_document_map();
        let rows = [
            keyset(1, 2, 1, "kid-a"),
            keyset(1, 1, 3, "kid-b"),
            keyset(1, 1, 2, "kid-b"),
            keyset(1, 1, 2, "kid-a"),
            keyset(1, 256, 0, "kid"),
            keyset(2, 0, 0, "kid"),
            keyset(0x0100, 0, 0, "kid"),
        ];
        for row in &rows {
            write(&store, &table, row);
        }
        let of_customer = table.of_customer(1).unwrap();
        let order: Vec<(u64, u64, &str)> = of_customer
            .iter()
            .map(|doc| {
                (
                    doc.recovery_epoch,
                    doc.keyset_version,
                    doc.signing_kid.as_str(),
                )
            })
            .collect();
        assert_eq!(
            order,
            vec![
                (1, 2, "kid-a"),
                (1, 2, "kid-b"),
                (1, 3, "kid-b"),
                (2, 1, "kid-a"),
                (256, 0, "kid"),
            ]
        );
        assert_eq!(table.of_customer(2).unwrap(), vec![rows[5].clone()]);
        assert_eq!(table.of_customer(3).unwrap(), vec![]);
        assert_eq!(all(&table).len(), rows.len());
        assert_eq!(table.get(1, 1, 2, "kid-b").unwrap(), Some(rows[2].clone()));
        assert_eq!(table.get(1, 1, 2, "kid").unwrap(), None);

        table.delete(1, 1, 2, "kid-b").unwrap();
        assert_eq!(table.get(1, 1, 2, "kid-b").unwrap(), None);
        assert_eq!(table.delete_customer(1).unwrap(), 4);
        assert_eq!(table.of_customer(1).unwrap(), vec![]);
        assert_eq!(all(&table), vec![rows[5].clone(), rows[6].clone()]);
    }

    #[test]
    fn recovery_key_documents_read_by_install() {
        let (_permit, _db, _backup, store) = setup_store();
        let table = store.senta_endpoint_recovery_key_document_map();
        let doc = |install: &str, version| SentaEndpointRecoveryKeyDocument {
            install_id: install.to_string(),
            recovery_key_version: version,
            jws: format!("{install}-{version}"),
        };
        let rows = [doc("a", 256), doc("a", 2), doc("ab", 1), doc("b", 1)];
        for row in &rows {
            write(&store, &table, row);
        }
        assert_eq!(
            table.of_install("a").unwrap(),
            vec![rows[1].clone(), rows[0].clone()]
        );
        assert_eq!(table.of_install("ab").unwrap(), vec![rows[2].clone()]);
        assert_eq!(table.of_install("").unwrap(), vec![]);
        assert_eq!(table.get("a", 2).unwrap(), Some(rows[1].clone()));
        assert_eq!(table.get("a", 1).unwrap(), None);
        assert_eq!(all(&table).len(), 4);
        table.delete("a", 2).unwrap();
        assert_eq!(table.of_install("a").unwrap(), vec![rows[0].clone()]);
    }

    #[test]
    fn current_documents_read_by_customer_and_typ() {
        let (_permit, _db, _backup, store) = setup_store();
        let table = store.senta_endpoint_current_document_map();
        let doc = |customer_id, typ: &str, target: &str| SentaEndpointCurrentDocument {
            customer_id,
            typ: typ.to_string(),
            target: target.to_string(),
            recovery_epoch: 1,
            version: 2,
            jws: format!("{customer_id}-{typ}-{target}"),
            put_at: 3,
        };
        let rows = [
            doc(1, "address", ""),
            doc(1, "address", "t"),
            doc(1, "addr", "t"),
            doc(1, "policy", "x"),
            doc(2, "address", ""),
        ];
        for row in &rows {
            write(&store, &table, row);
        }
        assert_eq!(table.get(1, "address", "t").unwrap(), Some(rows[1].clone()));
        assert_eq!(table.get(1, "address", "u").unwrap(), None);
        assert_eq!(
            table.of_customer_typ(1, "address").unwrap(),
            vec![rows[0].clone(), rows[1].clone()]
        );
        assert_eq!(
            table.of_customer_typ(1, "addr").unwrap(),
            vec![rows[2].clone()]
        );
        assert_eq!(table.of_customer(1).unwrap().len(), 4);
        assert_eq!(table.of_customer(2).unwrap(), vec![rows[4].clone()]);
        assert_eq!(all(&table).len(), 5);

        table.delete(1, "policy", "x").unwrap();
        assert_eq!(table.get(1, "policy", "x").unwrap(), None);
        assert_eq!(table.delete_customer(1).unwrap(), 3);
        assert_eq!(all(&table), vec![rows[4].clone()]);
    }

    #[test]
    fn address_roots_iterate_by_epoch_version_and_fingerprint() {
        let (_permit, _db, _backup, store) = setup_store();
        let table = store.senta_endpoint_address_root_map();
        let root = |customer_id, recovery_epoch, version, fingerprint| SentaEndpointAddressRoot {
            customer_id,
            recovery_epoch,
            version,
            fingerprint: [fingerprint; 32],
        };
        let rows = [
            root(1, 2, 0, 0),
            root(1, 1, 256, 1),
            root(1, 1, 2, 9),
            root(1, 1, 2, 3),
            root(2, 1, 2, 3),
        ];
        for row in &rows {
            write(&store, &table, row);
        }
        assert_eq!(
            table.of_customer(1).unwrap(),
            vec![rows[3], rows[2], rows[1], rows[0]]
        );
        assert_eq!(table.of_document(1, 1, 2).unwrap(), vec![rows[3], rows[2]]);
        assert_eq!(table.of_document(1, 1, 3).unwrap(), vec![]);
        assert_eq!(table.of_customer(2).unwrap(), vec![rows[4]]);
        assert!(table.contains(&rows[2]).unwrap());
        assert!(!table.contains(&root(1, 1, 2, 4)).unwrap());
        assert_eq!(all(&table).len(), 5);

        table.delete(&rows[2]).unwrap();
        assert!(!table.contains(&rows[2]).unwrap());
        assert_eq!(table.delete_customer(1).unwrap(), 3);
        assert_eq!(all(&table), vec![rows[4]]);
    }

    #[test]
    fn commands_change_only_when_they_exist() {
        let (_permit, _db, _backup, store) = setup_store();
        let table = store.senta_endpoint_command_map();
        let first = command(2, 10);
        let second = command(1, 11);
        let third = command(3, 10);
        for row in [&first, &second, &third] {
            write(&store, &table, row);
        }
        assert_eq!(table.get(first.command_id).unwrap(), Some(first.clone()));
        assert_eq!(all(&table), vec![second, first.clone(), third.clone()]);
        assert_eq!(
            table.of_endpoint(Uuid::from_u128(10)).unwrap(),
            vec![first.clone(), third]
        );

        let sent = table
            .set_state(first.command_id, SentaEndpointCommandState::Sent, None)
            .unwrap();
        assert_eq!(sent.state, SentaEndpointCommandState::Sent);
        let result = table
            .set_state(
                first.command_id,
                SentaEndpointCommandState::Result,
                Some(&[0, 1, 2]),
            )
            .unwrap();
        assert_eq!(result.result, Some(vec![0, 1, 2]));
        assert_eq!(table.get(first.command_id).unwrap(), Some(result));

        let absent = Uuid::from_u128(77);
        assert!(matches!(
            table.set_state(absent, SentaEndpointCommandState::Expired, None),
            Err(SentaEndpointError::CommandNotFound { command_id }) if command_id == absent
        ));
        assert_eq!(table.get(absent).unwrap(), None);

        table.delete(first.command_id).unwrap();
        assert_eq!(table.get(first.command_id).unwrap(), None);
    }

    #[test]
    fn an_existing_store_gets_the_tables_empty() {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        drop(Store::new(db_dir.path(), backup_dir.path(), None).unwrap());
        let states = db_dir.path().join(crate::DEFAULT_STATES);
        {
            let mut db = rocksdb::DB::open_cf(
                &rocksdb::Options::default(),
                &states,
                crate::tables::MAP_NAMES,
            )
            .unwrap();
            for name in crate::tables::ADDED_WITHIN_FORMAT {
                db.drop_cf(name).unwrap();
            }
        }
        let families = rocksdb::DB::list_cf(&rocksdb::Options::default(), &states).unwrap();
        assert!(
            !families
                .iter()
                .any(|name| name == crate::tables::SENTA_ENDPOINTS)
        );

        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
        let families = rocksdb::DB::list_cf(&rocksdb::Options::default(), &states).unwrap();
        for name in crate::tables::ADDED_WITHIN_FORMAT {
            assert!(
                families.iter().any(|family| family == name),
                "{name} is created"
            );
        }
        assert_eq!(all(&store.senta_endpoint_customer_map()), vec![]);
        assert_eq!(all(&store.senta_endpoint_install_map()), vec![]);
        assert_eq!(all(&store.senta_endpoint_map()), vec![]);
        assert_eq!(all(&store.senta_endpoint_enrollment_attempt_map()), vec![]);
        assert_eq!(all(&store.senta_endpoint_keyset_document_map()), vec![]);
        assert_eq!(
            all(&store.senta_endpoint_recovery_key_document_map()),
            vec![]
        );
        assert_eq!(all(&store.senta_endpoint_current_document_map()), vec![]);
        assert_eq!(all(&store.senta_endpoint_address_root_map()), vec![]);
        assert_eq!(all(&store.senta_endpoint_command_map()), vec![]);
        drop(store);
        drop(permit);
    }
}
