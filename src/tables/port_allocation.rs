//! The `port_allocation` table.
//!
//! An instance binds one address per listener, and no two instances on a host
//! may bind the same one. This table is that allocator's state: one row per
//! allocated address, keyed `(host, transport, port)`, carrying the owner the
//! address belongs to, the address itself, and the idempotency key of the
//! attempt that took it.
//!
//! # The key is the uniqueness, and the value is where the address survives
//!
//! `(host, transport, port)` is the whole of the conflict model, and it is
//! deliberately address-blind: two listeners on one host and one transport
//! cannot share a port whatever addresses they name it with. The key
//! therefore drops the address, which makes the row the only place the
//! address survives — a retry rebuilding the request map it sent has nowhere
//! else to read it from — so the full [`SocketAddr`] is a value.
//!
//! The owner is a triple, `(component, instance, listener_key)`, because one
//! Giganto instance owns three listeners, two of them UDP: `(component,
//! instance)` alone cannot say which row is which listener's.
//!
//! # Existence means taken
//!
//! The row has no state column and no released marker, exactly as the
//! instance row of [`InstanceAllocation`](super::InstanceAllocation) has
//! none. `Released` is not a state; it is the absence of a row. A state
//! column would make a released row indistinguishable from a live one to any
//! reader that forgot to filter, and this crate is RocksDB, which has no
//! partial index and no way to say "unique among the rows that are not
//! released" — so a released row left behind would make its port permanently
//! unusable. Release is a delete.
//!
//! # Two secondary indexes, both with the discriminator in the key
//!
//! Nothing reads a row by the port it already knows, and one attempt and one
//! instance each own three of Giganto's rows, so an index keyed on the
//! attempt or the instance alone would have its entries overwrite one another
//! in a store with no multi-map. Each index therefore carries the listener key
//! as its last segment, and each lives in a column family of its own:
//!
//! | Column family | Key | Value |
//! | --- | --- | --- |
//! | [`PORT_ALLOCATIONS`](super::PORT_ALLOCATIONS) | `(host, transport, port)` | the owner, the address and the owning key |
//! | [`PORT_ALLOCATIONS_BY_ATTEMPT`](super::PORT_ALLOCATIONS_BY_ATTEMPT) | `(idempotency_key, listener_key)` | the primary key |
//! | [`PORT_ALLOCATIONS_BY_INSTANCE`](super::PORT_ALLOCATIONS_BY_INSTANCE) | `(host, component, instance, listener_key)` | the primary key |
//!
//! A re-driven attempt restores its own rows by prefix scan on
//! `idempotency_key`; a removal deletes an instance's rows, and a reader lists
//! them, both by prefix scan on `(host, component, instance)`.
//!
//! Every index entry is written and deleted in the **same transaction** as the
//! primary row. A half-updated index is not a safe pause; it is a row the only
//! two readers can no longer find.
//!
//! # Writing
//!
//! Nothing may write a row directly. Two concurrent installs write
//! **different** `operation_attempt` rows, so their transactions do not
//! conflict and "in the same transaction" does not stop both committing the
//! same port — the unique key does. A plain atomic write batch is not that
//! primitive either: two batches writing one key both succeed and the second
//! overwrites the first. Every key is therefore read with
//! `get_for_update_cf(..., EXCLUSIVE)` before it is written, which is what
//! [`Map::insert_with_transaction`](crate::Map::insert_with_transaction) does,
//! spelled out here so that the loser can name the winner rather than only
//! failing.
//!
//! What is written is what the install request asked for. The attempt row
//! keeps that request's digest and not its addresses, so these rows are the
//! only place a retry can read them back from, and nothing downstream could
//! tell rows taken for one request from rows taken for another. The addresses
//! are therefore checked against the request the attempt records before any
//! of them is taken, at the entry point below that sees both.
//!
//! As with the instance number, neither half of an address's life has a public
//! entry point here: an address is taken by the write that records the
//! operation taking it, and given back by the write that justifies giving it
//! back. Both live on the other side, in `Table<'_, OperationAttempt>`:
//! [`allocate_instance_and_addrs`](Table::allocate_instance_and_addrs) takes
//! the instance number, the addresses and the attempt that owns them in one
//! transaction, and every writer of an `operation_attempt` row releases what
//! the row it stores gives back, in that row's own transaction.
//!
//! That a row cannot be written or deleted directly is enforced by the
//! compiler rather than by convention: the generic write API on [`Table`] is
//! bounded by [`UniqueKey`](crate::UniqueKey) and [`Value`](super::Value), and
//! [`PortAllocation`] implements neither, so `put`, `insert`,
//! `update_with_transaction` and `delete_with_transaction` do not exist for
//! this table at all.
//!
//! Reading is unrestricted. The primary column family holds these rows and
//! nothing else — the index entries have families of their own — so the
//! generic [`Iterable`](crate::Iterable) API stays available.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;

use anyhow::{Context, Result, anyhow, bail};
use rocksdb::{IteratorMode, OptimisticTransactionDB, ReadOptions, Transaction};
use serde::{Deserialize, Serialize};

use super::OperationAttempt;
use super::instance_allocation::{Release, release_of};
use crate::{EXCLUSIVE, Map, Table, types::FromKeyValue};

/// The width of the length prefix a variable-length key segment carries.
const SEGMENT_LEN: usize = 4;

/// The key tag of [`Transport::Tcp`].
const TCP_TAG: u8 = 1;

/// The key tag of [`Transport::Udp`].
const UDP_TAG: u8 = 2;

/// The transport an address is bound on.
///
/// It is part of the allocation key rather than of the value: a TCP and a UDP
/// listener on one host may hold the same port number without conflicting,
/// which is exactly the case a Giganto instance presents.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
pub enum Transport {
    Tcp = TCP_TAG,
    Udp = UDP_TAG,
}

impl Transport {
    /// Returns the byte the key encodes this transport as.
    fn tag(self) -> u8 {
        match self {
            Self::Tcp => TCP_TAG,
            Self::Udp => UDP_TAG,
        }
    }

    /// Reads back the byte [`Transport::tag`] wrote.
    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            TCP_TAG => Ok(Self::Tcp),
            UDP_TAG => Ok(Self::Udp),
            _ => bail!("a port allocation key names no transport this build knows"),
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => f.write_str("TCP"),
            Self::Udp => f.write_str("UDP"),
        }
    }
}

/// One address an install asks its instance to bind.
///
/// The listener key is the caller's name for the listener, and it is what
/// tells one of an instance's rows from another: it is the last segment of
/// both index keys, so two bindings of one attempt may not share it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerBinding {
    /// The name the component knows the listener by. Never empty.
    pub listener_key: String,
    /// The transport the listener binds on.
    pub transport: Transport,
    /// The address the listener binds.
    pub addr: SocketAddr,
}

/// Who an allocated address belongs to.
///
/// `(component, instance)` alone cannot say which of an instance's rows this
/// is — one Giganto instance owns three listeners, two of them UDP — so the
/// listener key is part of the owner rather than a detail of the value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortOwner {
    /// The canonical package-id of the component the address belongs to.
    pub component: String,
    /// The instance number the address belongs to.
    pub instance: u32,
    /// The name the component knows the listener by.
    pub listener_key: String,
}

impl fmt::Display for PortOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "listener {} of instance {} of component {}",
            self.listener_key, self.instance, self.component
        )
    }
}

/// An address allocated to one listener of one instance on a host.
///
/// # Identity
///
/// The row is keyed by `(host, transport, port)`, and the key is the whole of
/// the uniqueness: a second row for an address already held cannot exist,
/// because it would be the same key. The key is address-blind on purpose, so
/// the value carries the full [`SocketAddr`] — the row is the only place it
/// survives.
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
/// A `PortAllocation` is not, which is what stops a caller from taking an
/// address without the conflict-detecting read that makes two concurrent
/// installs pick different ones, and from dropping a row while its index
/// entries stand:
///
/// ```compile_fail
/// fn generic_write_api<R: review_database::UniqueKey>() {}
/// generic_write_api::<review_database::PortAllocation>();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortAllocation {
    /// The host the address is bound on.
    pub host: String,
    /// The transport the address is bound on.
    pub transport: Transport,
    /// The port the address is bound on, which is `addr`'s own.
    pub port: u16,
    /// The canonical package-id of the component the address belongs to.
    pub component: String,
    /// The instance number the address belongs to.
    pub instance: u32,
    /// The name the component knows the listener by. Never empty.
    pub listener_key: String,
    /// The full address, which the key drops.
    pub addr: SocketAddr,
    /// The idempotency key of the attempt that allocated the address.
    ///
    /// This is what lets a re-driven attempt find its own rows instead of
    /// taking a second set, and what ties the row to the record whose write
    /// releases it. Never empty.
    pub idempotency_key: String,
}

impl PortAllocation {
    /// Returns the triple the address belongs to.
    #[must_use]
    pub fn owner(&self) -> PortOwner {
        PortOwner {
            component: self.component.clone(),
            instance: self.instance,
            listener_key: self.listener_key.clone(),
        }
    }

    /// Returns the entry of the request map this row restores.
    ///
    /// A re-driven attempt rebuilds exactly what it sent from these, which is
    /// why the address is on the row rather than only in the key it was
    /// hashed into.
    #[must_use]
    pub fn binding(&self) -> ListenerBinding {
        ListenerBinding {
            listener_key: self.listener_key.clone(),
            transport: self.transport,
            addr: self.addr,
        }
    }

    /// Returns the record's serialized value.
    fn record_value(&self) -> Vec<u8> {
        let value = Value {
            component: Cow::Borrowed(&self.component),
            instance: self.instance,
            listener_key: Cow::Borrowed(&self.listener_key),
            addr: self.addr,
            idempotency_key: Cow::Borrowed(&self.idempotency_key),
        };
        super::serialize(&value).expect("serializable")
    }
}

/// The stored shape of a [`PortAllocation`]'s value.
///
/// The key carries `(host, transport, port)`, so nothing here repeats them.
#[derive(Deserialize, Serialize)]
struct Value<'a> {
    component: Cow<'a, str>,
    instance: u32,
    listener_key: Cow<'a, str>,
    addr: SocketAddr,
    idempotency_key: Cow<'a, str>,
}

impl FromKeyValue for PortAllocation {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let (host, transport, port) = decode_row_key(key)?;
        let value: Value = super::deserialize(value)?;
        if value.idempotency_key.is_empty() {
            bail!("a port allocation must name the attempt that owns it");
        }
        if value.listener_key.is_empty() {
            bail!("a port allocation must name the listener it belongs to");
        }
        if value.addr.port() != port {
            bail!("a port allocation holds an address bound on another port");
        }

        Ok(Self {
            host,
            transport,
            port,
            component: value.component.into_owned(),
            instance: value.instance,
            listener_key: value.listener_key.into_owned(),
            addr: value.addr,
            idempotency_key: value.idempotency_key.into_owned(),
        })
    }
}

/// What went wrong while allocating an address.
#[derive(Debug, thiserror::Error)]
pub enum PortAllocationError {
    /// Another owner already holds `(host, transport, port)`.
    ///
    /// The refusal carries the winner's owner triple, which is why the loser
    /// of a commit race looks again rather than reporting the bare conflict:
    /// the transaction that failed knows only that it failed, and the row
    /// naming the winner is readable only on the pass after it committed.
    #[error("{transport} port {port} on host {host} is already allocated to {owner}")]
    PortAllocationConflict {
        /// The host the contended address is bound on.
        host: String,
        /// The transport the contended address is bound on.
        transport: Transport,
        /// The contended port.
        port: u16,
        /// Who holds it.
        owner: PortOwner,
    },
    /// The database read or write failed, or a stored row was invalid.
    #[error(transparent)]
    Database(#[from] anyhow::Error),
}

/// Appends a length-prefixed segment to a key.
///
/// Every variable-length segment is prefixed, so `("ab", "c")` and
/// `("a", "bc")` cannot encode to the same key.
fn push_segment(key: &mut Vec<u8>, segment: &str) -> Result<()> {
    let len = u32::try_from(segment.len()).context("port allocation key segment is too long")?;
    key.extend_from_slice(&len.to_be_bytes());
    key.extend_from_slice(segment.as_bytes());
    Ok(())
}

/// Reads back one segment [`push_segment`] wrote, and returns the rest.
fn take_segment(bytes: &[u8]) -> Result<(String, &[u8])> {
    let len = bytes
        .get(..SEGMENT_LEN)
        .and_then(|len| <[u8; SEGMENT_LEN]>::try_from(len).ok())
        .context("a port allocation key is missing a segment length")?;
    let len = usize::try_from(u32::from_be_bytes(len))
        .context("a port allocation key segment is too long")?;
    let end = SEGMENT_LEN
        .checked_add(len)
        .context("a port allocation key segment is too long")?;
    let segment = bytes
        .get(SEGMENT_LEN..end)
        .context("a port allocation key segment runs past its end")?;
    let segment =
        std::str::from_utf8(segment).context("a port allocation key segment is not valid UTF-8")?;
    Ok((segment.to_string(), &bytes[end..]))
}

/// The key of one allocated address.
fn row_key(host: &str, transport: Transport, port: u16) -> Result<Vec<u8>> {
    let mut key = Vec::new();
    push_segment(&mut key, host)?;
    key.push(transport.tag());
    key.extend_from_slice(&port.to_be_bytes());
    Ok(key)
}

/// Decodes the `(host, transport, port)` triple [`row_key`] wrote.
fn decode_row_key(bytes: &[u8]) -> Result<(String, Transport, u16)> {
    let (host, rest) = take_segment(bytes)?;
    let (tag, rest) = rest
        .split_first()
        .context("a port allocation key is missing its transport")?;
    let transport = Transport::from_tag(*tag)?;
    let port = <[u8; 2]>::try_from(rest)
        .ok()
        .map(u16::from_be_bytes)
        .context("a port allocation key is missing its port")?;
    Ok((host, transport, port))
}

/// The attempt index's key space of one attempt.
fn attempt_prefix(idempotency_key: &str) -> Result<Vec<u8>> {
    let mut key = Vec::new();
    push_segment(&mut key, idempotency_key)?;
    Ok(key)
}

/// The attempt index's key of one listener of one attempt.
fn attempt_index_key(idempotency_key: &str, listener_key: &str) -> Result<Vec<u8>> {
    let mut key = attempt_prefix(idempotency_key)?;
    push_segment(&mut key, listener_key)?;
    Ok(key)
}

/// The instance index's key space of one instance.
fn instance_prefix(host: &str, component: &str, instance: u32) -> Result<Vec<u8>> {
    let mut key = Vec::new();
    push_segment(&mut key, host)?;
    push_segment(&mut key, component)?;
    key.extend_from_slice(&instance.to_be_bytes());
    Ok(key)
}

/// The instance index's key of one listener of one instance.
fn instance_index_key(
    host: &str,
    component: &str,
    instance: u32,
    listener_key: &str,
) -> Result<Vec<u8>> {
    let mut key = instance_prefix(host, component, instance)?;
    push_segment(&mut key, listener_key)?;
    Ok(key)
}

/// Reads every index entry under `prefix` as `(entry key, primary key)`.
fn index_entries(index: &Map<'_>, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    collect_entries(
        index
            .db
            .iterator_cf_opt(index.cf, prefix_range(prefix), IteratorMode::Start),
    )
}

/// [`index_entries`], reading through `txn` so that the entries this
/// transaction has written are seen alongside the committed ones.
fn index_entries_within(
    index: &Map<'_>,
    prefix: &[u8],
    txn: &Transaction<'_, OptimisticTransactionDB>,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    collect_entries(txn.iterator_cf_opt(index.cf, prefix_range(prefix), IteratorMode::Start))
}

/// The read options that bound a scan to `prefix`.
fn prefix_range(prefix: &[u8]) -> ReadOptions {
    let mut readopts = ReadOptions::default();
    readopts.set_iterate_range(rocksdb::PrefixRange(prefix));
    readopts
}

/// Drains an index iterator into owned `(entry key, primary key)` pairs.
fn collect_entries<I, K, V>(iter: I) -> Result<Vec<(Vec<u8>, Vec<u8>)>>
where
    I: Iterator<Item = Result<(K, V), rocksdb::Error>>,
    K: AsRef<[u8]>,
    V: AsRef<[u8]>,
{
    let mut entries = Vec::new();
    for entry in iter {
        let (key, value) = entry.context("cannot read the port allocation index")?;
        entries.push((key.as_ref().to_vec(), value.as_ref().to_vec()));
    }
    Ok(entries)
}

/// Functions for the `port_allocation` table.
impl<'d> Table<'d, PortAllocation> {
    /// Opens the `port_allocation` table in the database.
    ///
    /// Returns `None` unless all three column families are present, which is
    /// the state of every store until the database format bump registers
    /// them: `migrate_data_dir` returns early for a data dir already at a
    /// compatible version, so registering them in `MAP_NAMES` now would add
    /// column families with no version change. The three are one table and
    /// are opened as one — a primary without an index would let a row be
    /// written that neither reader can find. A store without them holds no
    /// allocation, which is why the release path can treat the `None` as
    /// nothing to release.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        let primary = Map::open(db, super::PORT_ALLOCATIONS)?;
        Map::open(db, super::PORT_ALLOCATIONS_BY_ATTEMPT)?;
        Map::open(db, super::PORT_ALLOCATIONS_BY_INSTANCE)?;
        Some(Table::new(primary))
    }

    /// Returns the row for `(host, transport, port)`, or `None` if the
    /// address is free.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored row is invalid or the database operation
    /// fails.
    pub fn get(
        &self,
        host: &str,
        transport: Transport,
        port: u16,
    ) -> Result<Option<PortAllocation>> {
        let key = row_key(host, transport, port)?;
        let Some(value) = self.map.get(&key)? else {
            return Ok(None);
        };
        Ok(Some(PortAllocation::from_key_value(&key, value.as_ref())?))
    }

    /// Returns every address `idempotency_key` allocated, in the index's own
    /// key order — by the listener key's length, then its bytes, which is
    /// what a length-prefixed segment sorts as.
    ///
    /// This is the one prefix scan a re-driven attempt rebuilds its request
    /// map from: every row carries the full address, so the reconstruction is
    /// exactly what the attempt sent.
    ///
    /// # Errors
    ///
    /// Returns an error if the attempt index is not registered, if an entry
    /// names a row that does not exist, if a stored row is invalid, or if the
    /// database operation fails.
    pub fn allocated_by(&self, idempotency_key: &str) -> Result<Vec<PortAllocation>> {
        let index = self.by_attempt()?;
        self.rows_named_by(&index_entries(&index, &attempt_prefix(idempotency_key)?)?)
    }

    /// Returns every address allocated to `(host, component, instance)`, in
    /// the same order [`Table::allocated_by`] reads, whichever attempt took
    /// it.
    ///
    /// # Errors
    ///
    /// Returns an error if the instance index is not registered, if an entry
    /// names a row that does not exist, if a stored row is invalid, or if the
    /// database operation fails.
    pub fn allocated_for(
        &self,
        host: &str,
        component: &str,
        instance: u32,
    ) -> Result<Vec<PortAllocation>> {
        let index = self.by_instance()?;
        self.rows_named_by(&index_entries(
            &index,
            &instance_prefix(host, component, instance)?,
        )?)
    }

    /// Allocates every address in `bindings` to `(host, component, instance)`
    /// within `txn`, and returns the rows.
    ///
    /// Each key is read with `get_for_update` before it is written, which is
    /// the whole of what stops a double allocation: two concurrent installs
    /// write different `operation_attempt` rows, so their transactions do not
    /// conflict on that, and a plain write batch would let the second
    /// overwrite the first. Locking the key orders the writers, so one commits
    /// and the other's commit fails; the re-run then reads the winner's row
    /// and answers [`PortAllocationError::PortAllocationConflict`] naming it.
    ///
    /// A row this attempt already holds, unchanged, is left as it stands, so
    /// a re-drive of one transaction is idempotent rather than a conflict with
    /// itself.
    ///
    /// The primary row and both index entries are written together. A partial
    /// failure leaves none of them, because they are one transaction and the
    /// caller commits it once.
    ///
    /// Deliberately not public, and there is no self-committing allocation at
    /// all: an address taken by a transaction of its own is held by nothing if
    /// the process stops before the attempt is recorded, and nothing would
    /// ever give it back, because every release is justified by the record
    /// that in that case was never written. The addresses, the instance
    /// number keyed into their owner, and the attempt that owns them land
    /// together or not at all, which is what
    /// [`Table::allocate_instance_and_addrs`] does.
    ///
    /// # Errors
    ///
    /// Returns [`PortAllocationError::PortAllocationConflict`] if another
    /// owner already holds one of the addresses, or
    /// [`PortAllocationError::Database`] if `idempotency_key` is empty, if a
    /// listener key is empty or named twice, if an index is not registered,
    /// or if the database operation fails.
    pub(super) fn allocate_with_transaction(
        &self,
        host: &str,
        component: &str,
        instance: u32,
        idempotency_key: &str,
        bindings: &[ListenerBinding],
        txn: &Transaction<'_, OptimisticTransactionDB>,
    ) -> Result<Vec<PortAllocation>, PortAllocationError> {
        if idempotency_key.is_empty() {
            return Err(anyhow!("a port allocation must name the attempt that owns it").into());
        }
        // The listener key is the last segment of both index keys, so two
        // bindings sharing one would have the second entry overwrite the
        // first and leave a row neither reader could find. Refused rather
        // than written, because the row that vanishes from the indexes is
        // still holding its port.
        let mut listener_keys = BTreeSet::new();
        for binding in bindings {
            if binding.listener_key.is_empty() {
                return Err(anyhow!(
                    "operation attempt {idempotency_key} names an address with no listener key"
                )
                .into());
            }
            if !listener_keys.insert(binding.listener_key.as_str()) {
                return Err(anyhow!(
                    "operation attempt {idempotency_key} names listener {} twice, and one listener holds one address",
                    binding.listener_key
                )
                .into());
            }
        }

        let by_attempt = self.by_attempt()?;
        let by_instance = self.by_instance()?;
        let mut rows = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let row = PortAllocation {
                host: host.to_string(),
                transport: binding.transport,
                port: binding.addr.port(),
                component: component.to_string(),
                instance,
                listener_key: binding.listener_key.clone(),
                addr: binding.addr,
                idempotency_key: idempotency_key.to_string(),
            };
            let key = row_key(host, row.transport, row.port)?;
            if let Some(stored) = txn
                .get_for_update_cf(self.map.cf, &key, EXCLUSIVE)
                .context("cannot read the port allocation")?
            {
                let stored = PortAllocation::from_key_value(&key, &stored)?;
                if stored != row {
                    let owner = stored.owner();
                    return Err(PortAllocationError::PortAllocationConflict {
                        host: stored.host,
                        transport: stored.transport,
                        port: stored.port,
                        owner,
                    });
                }
                rows.push(stored);
                continue;
            }
            self.map
                .put_with_transaction(&key, &row.record_value(), txn)?;
            by_attempt.put_with_transaction(
                &attempt_index_key(idempotency_key, &row.listener_key)?,
                &key,
                txn,
            )?;
            by_instance.put_with_transaction(
                &instance_index_key(host, component, instance, &row.listener_key)?,
                &key,
                txn,
            )?;
            rows.push(row);
        }
        Ok(rows)
    }

    /// Deletes the rows `attempt` releases, if it releases any.
    ///
    /// Three writes release an address, and each of them is terminal and owes
    /// no cleanup: the one recording an attempt that **did not succeed** —
    /// failed, cancelled, rolled back, or expired and finalized as failed by
    /// `Table<'_, OperationAttempt>::sweep_expired` — the `cleanup_state`
    /// **discharge**, and the **confirmed removal**. These are the same three
    /// occasions that release the instance number the owner is keyed on, and
    /// they are the same transaction, so the two can never disagree.
    ///
    /// A terminal **success** is deliberately not one of them, and releasing
    /// on success would be worse than never writing the row: a stopped
    /// service reports nothing, so its ports would read as free and collide
    /// the moment it starts again. Before success the row is subordinate to
    /// the attempt, whose durable `expires_at` and sweep already bound it;
    /// after success the instance owns it, and it outlives its attempt.
    ///
    /// The first two release **the rows the attempt itself allocated**, found
    /// through the attempt index, so an update that failed does not release
    /// the addresses of the instance it was updating. A confirmed removal
    /// releases the rows of the instance, found through the instance index,
    /// whichever attempt allocated them, because the instance they belong to
    /// is gone.
    ///
    /// The delete rides the write that justifies it because "the port stays
    /// held" is not a safe crash answer on its own: an attempt that is
    /// terminal and owes no cleanup has nothing left that would revisit it,
    /// so a lost delete is a permanent leak rather than a pause. Either the
    /// row, both its index entries and the record all land or none of them
    /// does.
    ///
    /// Releasing an address that is already free is not an error, so a
    /// re-driven terminal write need not check first.
    ///
    /// # Errors
    ///
    /// Returns an error if an index is not registered, if a stored row is
    /// invalid, or if the database operation fails.
    pub(super) fn release_for_attempt(
        &self,
        attempt: &OperationAttempt,
        txn: &Transaction<'_, OptimisticTransactionDB>,
    ) -> Result<()> {
        let (Some(instance), Some(release)) = (attempt.instance, release_of(attempt)) else {
            return Ok(());
        };
        let (index, prefix) = match release {
            Release::OwnedByTheAttempt => (
                self.by_attempt()?,
                attempt_prefix(&attempt.idempotency_key)?,
            ),
            Release::ConfirmedRemoval => (
                self.by_instance()?,
                instance_prefix(&attempt.host, &attempt.target, instance)?,
            ),
        };
        for (entry_key, primary_key) in index_entries_within(&index, &prefix, txn)? {
            // The row is read for update before it is believed, so this
            // delete is ordered against a write for the same address rather
            // than merely following the scan that found it.
            let Some(value) = txn
                .get_for_update_cf(self.map.cf, &primary_key, EXCLUSIVE)
                .context("cannot read the port allocation")?
            else {
                // A row and its entries go together, so an entry naming
                // nothing is left over from a repair rather than a state this
                // table writes. It goes with this delete rather than
                // outliving it.
                index.delete_with_transaction(&entry_key, txn)?;
                continue;
            };
            let row = PortAllocation::from_key_value(&primary_key, &value)?;
            if release == Release::OwnedByTheAttempt
                && row.idempotency_key != attempt.idempotency_key
            {
                continue;
            }
            self.remove_with_transaction(&row, txn)?;
        }
        Ok(())
    }

    /// Deletes a row and both index entries naming it, within `txn`.
    fn remove_with_transaction(
        &self,
        row: &PortAllocation,
        txn: &Transaction<'_, OptimisticTransactionDB>,
    ) -> Result<()> {
        self.by_attempt()?.delete_with_transaction(
            &attempt_index_key(&row.idempotency_key, &row.listener_key)?,
            txn,
        )?;
        self.by_instance()?.delete_with_transaction(
            &instance_index_key(&row.host, &row.component, row.instance, &row.listener_key)?,
            txn,
        )?;
        self.map
            .delete_with_transaction(&row_key(&row.host, row.transport, row.port)?, txn)
    }

    /// Returns the rows the given index entries name, in the order they were
    /// read.
    fn rows_named_by(&self, entries: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<PortAllocation>> {
        let mut rows = Vec::with_capacity(entries.len());
        for (_, primary_key) in entries {
            let value = self
                .map
                .get(primary_key)?
                .context("a port allocation index entry names a row that does not exist")?;
            rows.push(PortAllocation::from_key_value(primary_key, value.as_ref())?);
        }
        Ok(rows)
    }

    /// Opens the `(idempotency_key, listener_key)` index.
    fn by_attempt(&self) -> Result<Map<'_>> {
        Map::open(self.map.db, super::PORT_ALLOCATIONS_BY_ATTEMPT)
            .context("the port allocation attempt index is not registered")
    }

    /// Opens the `(host, component, instance, listener_key)` index.
    fn by_instance(&self) -> Result<Map<'_>> {
        Map::open(self.map.db, super::PORT_ALLOCATIONS_BY_INSTANCE)
            .context("the port allocation instance index is not registered")
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use chrono::{DateTime, Utc};

    use super::*;
    use crate::tables::operation_attempt::AddressAllocationError;
    use crate::tables::{
        BuildSelector, InstallIntent, InstanceAllocation, InstanceAllocationError, OperationAction,
        OperationCleanupState, OperationOnFailure, OperationOutcome, OperationPhase,
        OperationRetryPolicy,
    };
    use crate::test::{DbGuard, acquire_db_permit};

    const HOST: &str = "host-a.example";
    const COMPONENT: &str = "giganto";
    const OTHER_HOST: &str = "host-b.example";
    const OTHER_COMPONENT: &str = "piglet";

    /// The three listeners a Giganto instance owns, two of them UDP. This is
    /// the shape every one-to-many claim in this module is tested against: an
    /// index keyed without the listener would keep only the last of them.
    const INGEST: &str = "ingest";
    const PUBLISH: &str = "publish";
    const GRAPHQL: &str = "graphql";

    /// A database carrying this table's three column families, which
    /// `StateDb::open` does not yet create because their names are not in
    /// `MAP_NAMES`.
    struct TestDb {
        db: OptimisticTransactionDB,
        _dir: tempfile::TempDir,
        _permit: DbGuard<'static>,
    }

    impl TestDb {
        fn new() -> Self {
            Self::with_column_families(&[
                super::super::INSTANCE_ALLOCATIONS,
                super::super::OPERATION_ATTEMPT_LATEST,
                super::super::PORT_ALLOCATIONS,
                super::super::PORT_ALLOCATIONS_BY_ATTEMPT,
                super::super::PORT_ALLOCATIONS_BY_INSTANCE,
            ])
        }

        /// A store carrying `MAP_NAMES` and the named families and nothing
        /// else, so that a test can open one the format bump has not reached.
        fn with_column_families(extra: &[&str]) -> Self {
            let permit = acquire_db_permit();
            let dir = tempfile::tempdir().unwrap();
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
            let mut column_families = super::super::MAP_NAMES.to_vec();
            column_families.extend_from_slice(extra);
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

        fn table(&self) -> Table<'_, PortAllocation> {
            Table::<PortAllocation>::open(&self.db).unwrap()
        }

        fn attempts(&self) -> Table<'_, OperationAttempt> {
            Table::<OperationAttempt>::open(&self.db).unwrap()
        }

        fn instances(&self) -> Table<'_, InstanceAllocation> {
            Table::<InstanceAllocation>::open(&self.db).unwrap()
        }

        /// Every entry in one of the index column families, as
        /// `(entry key, primary key)`.
        fn index(&self, name: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
            let map = Map::open(&self.db, name).unwrap();
            collect_entries(map.db.iterator_cf(map.cf, IteratorMode::Start)).unwrap()
        }

        fn attempt_index(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
            self.index(super::super::PORT_ALLOCATIONS_BY_ATTEMPT)
        }

        fn instance_index(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
            self.index(super::super::PORT_ALLOCATIONS_BY_INSTANCE)
        }

        /// Every primary row in the table, in key order.
        fn rows(&self) -> Vec<PortAllocation> {
            let map = Map::open(&self.db, super::super::PORT_ALLOCATIONS).unwrap();
            let mut rows = Vec::new();
            for entry in map.db.iterator_cf(map.cf, IteratorMode::Start) {
                let (key, value) = entry.unwrap();
                rows.push(PortAllocation::from_key_value(&key, &value).unwrap());
            }
            rows
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
    /// labels they read as.
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

    /// The request an install of `target` on `host` naming `bindings` was
    /// submitted with.
    ///
    /// An empty `bindings` is the install that leaves the addresses to the
    /// component, which is an absent `bind_addrs` rather than an empty list.
    fn request_for(host: &str, target: &str, bindings: &[ListenerBinding]) -> InstallIntent {
        InstallIntent {
            host: host.to_string(),
            target: target.to_string(),
            selector: BuildSelector::Version("1.2.3".to_string()),
            on_failure: OperationOnFailure::Rollback,
            bind_addrs: (!bindings.is_empty()).then(|| {
                bindings
                    .iter()
                    .map(|binding| (binding.listener_key.clone(), binding.addr))
                    .collect()
            }),
        }
    }

    /// Stamps `attempt` with the digest of the request that names `bindings`
    /// on its own pair, and returns that request.
    ///
    /// The allocator takes nothing for an attempt presented with a request
    /// other than the one it records, so a test that moves an attempt to
    /// another pair, or gives it addresses, submits it through here.
    fn submit(attempt: &mut OperationAttempt, bindings: &[ListenerBinding]) -> InstallIntent {
        let request = request_for(&attempt.host, &attempt.target, bindings);
        attempt.install_intent = Some(request.digest().unwrap());
        request
    }

    /// An install attempt on `(HOST, COMPONENT)`.
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
            install_intent: Some(request_for(HOST, COMPONENT, &[]).digest().unwrap()),
            finalized_at: None,
        }
    }

    /// A terminal attempt of `action` on the instance an install of the three
    /// Giganto listeners took.
    fn terminal(
        idempotency_key: &str,
        instance: u32,
        action: OperationAction,
        outcome: OperationOutcome,
    ) -> OperationAttempt {
        terminal_for(
            idempotency_key,
            instance,
            action,
            outcome,
            &giganto_bindings(),
        )
    }

    /// [`terminal`] for an instance whose install named `bindings`.
    fn terminal_for(
        idempotency_key: &str,
        instance: u32,
        action: OperationAction,
        outcome: OperationOutcome,
        bindings: &[ListenerBinding],
    ) -> OperationAttempt {
        let mut attempt = install(idempotency_key, Some(instance));
        attempt.action = action;
        // Only an install records the request digest, and a row that is
        // terminal and owes nothing carries the instant it was finished with.
        // A terminal install is a second write under the key the allocation
        // recorded, and `upsert` answers a key presented with any other
        // request by refusing it, so the digest is of the request that took
        // these very addresses.
        if action == OperationAction::Install {
            submit(&mut attempt, bindings);
        } else {
            attempt.install_intent = None;
        }
        attempt.phase = OperationPhase::Completed;
        attempt.outcome = Some(outcome);
        attempt.finalized_at = Some(timestamp(1_700_000_500));
        attempt
    }

    /// Sets `cleanup_state`, keeping `finalized_at` in step with it.
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

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
    }

    fn binding(listener_key: &str, transport: Transport, port: u16) -> ListenerBinding {
        ListenerBinding {
            listener_key: listener_key.to_string(),
            transport,
            addr: addr(port),
        }
    }

    /// The three listeners of one Giganto instance, two of them UDP.
    fn giganto_bindings() -> Vec<ListenerBinding> {
        vec![
            binding(INGEST, Transport::Tcp, 38_370),
            binding(PUBLISH, Transport::Udp, 38_371),
            binding(GRAPHQL, Transport::Udp, 8442),
        ]
    }

    /// Takes an instance number and `bindings` on behalf of `idempotency_key`,
    /// through the only entry point there is: the number, the addresses and
    /// the `operation_attempt` that owns them land in one transaction.
    fn allocate(
        test_db: &TestDb,
        idempotency_key: &str,
        bindings: &[ListenerBinding],
    ) -> Result<OperationAttempt, AddressAllocationError> {
        let mut attempt = install(idempotency_key, None);
        let request = submit(&mut attempt, bindings);
        test_db
            .attempts()
            .allocate_instance_and_addrs(&attempt, &request, bindings)
    }

    /// The request map a re-driven attempt rebuilds, sorted by listener key
    /// so that a comparison does not depend on the index's key order.
    fn request_map(rows: &[PortAllocation]) -> Vec<(String, SocketAddr)> {
        let mut map: Vec<(String, SocketAddr)> = rows
            .iter()
            .map(|row| (row.listener_key.clone(), row.addr))
            .collect();
        map.sort_unstable();
        map
    }

    /// The row carries the owner triple, the full address the key drops, and
    /// the attempt that took it, and all of it survives the round trip.
    #[test]
    fn the_row_round_trips_with_its_owner_and_address() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let stored = allocate(&test_db, "attempt-1", &giganto_bindings()).unwrap();
        assert_eq!(stored.instance, Some(1));

        let row = table.get(HOST, Transport::Udp, 38_371).unwrap().unwrap();
        assert_eq!(row.host, HOST);
        assert_eq!(row.transport, Transport::Udp);
        assert_eq!(row.port, 38_371);
        assert_eq!(row.component, COMPONENT);
        assert_eq!(row.instance, 1);
        assert_eq!(row.listener_key, PUBLISH);
        assert_eq!(row.addr, addr(38_371));
        assert_eq!(row.idempotency_key, key("attempt-1"));
        assert_eq!(
            row.owner(),
            PortOwner {
                component: COMPONENT.to_string(),
                instance: 1,
                listener_key: PUBLISH.to_string(),
            }
        );

        // The port of a free address answers nothing, and so does the other
        // transport of a port that is taken.
        assert_eq!(table.get(HOST, Transport::Tcp, 38_371).unwrap(), None);
        assert_eq!(table.get(OTHER_HOST, Transport::Udp, 38_371).unwrap(), None);
    }

    /// The acceptance criterion the address is on the row for: all three of
    /// one instance's rows come back from **one** prefix scan on the
    /// idempotency key, each carrying its full `SocketAddr`, so the re-driven
    /// attempt reconstructs exactly what it sent. A row holding only the key
    /// would leave the address nowhere to be read from, since
    /// `(host, transport, port)` deliberately drops it.
    #[test]
    fn a_retry_rebuilds_the_request_map_from_the_rows() {
        let test_db = TestDb::new();
        let table = test_db.table();

        allocate(&test_db, "attempt-1", &giganto_bindings()).unwrap();

        let rows = table.allocated_by(&key("attempt-1")).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(
            request_map(&rows),
            vec![
                (GRAPHQL.to_string(), addr(8442)),
                (INGEST.to_string(), addr(38_370)),
                (PUBLISH.to_string(), addr(38_371)),
            ]
        );
        // The transport the key carries comes back with them, so the whole
        // binding is restored rather than only the pair the request map holds.
        let mut restored = rows.iter().map(PortAllocation::binding).collect::<Vec<_>>();
        restored.sort_unstable_by(|left, right| left.listener_key.cmp(&right.listener_key));
        let mut sent = giganto_bindings();
        sent.sort_unstable_by(|left, right| left.listener_key.cmp(&right.listener_key));
        assert_eq!(restored, sent);

        // Another attempt's rows are not in the scan.
        allocate(
            &test_db,
            "attempt-2",
            &[binding("ingest", Transport::Tcp, 9000)],
        )
        .unwrap();
        assert_eq!(table.allocated_by(&key("attempt-1")).unwrap().len(), 3);
        assert_eq!(table.allocated_by(&key("attempt-2")).unwrap().len(), 1);
        assert_eq!(table.allocated_by(&key("attempt-3")).unwrap(), Vec::new());
    }

    /// Both indexes carry the listener key as their last segment, so all
    /// three of one instance's entries survive in **each**. An index keyed on
    /// `idempotency_key` or `(host, component, instance)` alone would have the
    /// third entry overwrite the first two, which is what the counts here
    /// fail against.
    #[test]
    fn both_indexes_hold_an_entry_for_every_listener() {
        let test_db = TestDb::new();
        let table = test_db.table();

        allocate(&test_db, "attempt-1", &giganto_bindings()).unwrap();

        assert_eq!(test_db.attempt_index().len(), 3);
        assert_eq!(test_db.instance_index().len(), 3);
        assert_eq!(test_db.rows().len(), 3);

        // Every entry of one attempt sorts under the attempt's prefix, and no
        // two share a key: the discriminator is what makes the index
        // one-to-many.
        let prefix = attempt_prefix(&key("attempt-1")).unwrap();
        let attempt_keys: BTreeSet<Vec<u8>> = test_db
            .attempt_index()
            .into_iter()
            .map(|(entry_key, _)| entry_key)
            .collect();
        assert_eq!(attempt_keys.len(), 3);
        assert!(attempt_keys.iter().all(|entry| entry.starts_with(&prefix)));

        let prefix = instance_prefix(HOST, COMPONENT, 1).unwrap();
        let instance_keys: BTreeSet<Vec<u8>> = test_db
            .instance_index()
            .into_iter()
            .map(|(entry_key, _)| entry_key)
            .collect();
        assert_eq!(instance_keys.len(), 3);
        assert!(instance_keys.iter().all(|entry| entry.starts_with(&prefix)));

        // And both readers see all three.
        assert_eq!(table.allocated_by(&key("attempt-1")).unwrap().len(), 3);
        assert_eq!(table.allocated_for(HOST, COMPONENT, 1).unwrap().len(), 3);
        assert_eq!(
            request_map(&table.allocated_for(HOST, COMPONENT, 1).unwrap()),
            request_map(&table.allocated_by(&key("attempt-1")).unwrap())
        );
    }

    /// A fault between the primary write and either index write leaves
    /// **none** of them: the row and both entries are one transaction, so no
    /// entry can outlive its row and no row can hide from its readers.
    #[test]
    fn a_fault_before_the_commit_leaves_neither_the_row_nor_its_entries() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let txn = table.transaction();
        let rows = table
            .allocate_with_transaction(
                HOST,
                COMPONENT,
                1,
                &key("attempt-1"),
                &giganto_bindings(),
                &txn,
            )
            .unwrap();
        assert_eq!(rows.len(), 3);
        drop(txn);

        assert_eq!(test_db.rows(), Vec::new());
        assert_eq!(test_db.attempt_index(), Vec::new());
        assert_eq!(test_db.instance_index(), Vec::new());

        // Committed, all three halves land together.
        let txn = table.transaction();
        table
            .allocate_with_transaction(
                HOST,
                COMPONENT,
                1,
                &key("attempt-1"),
                &giganto_bindings(),
                &txn,
            )
            .unwrap();
        txn.commit().unwrap();

        assert_eq!(test_db.rows().len(), 3);
        assert_eq!(test_db.attempt_index().len(), 3);
        assert_eq!(test_db.instance_index().len(), 3);
    }

    /// The delete is one transaction too, so a fault leaves every row and
    /// every entry standing rather than an entry orphaned from its siblings.
    #[test]
    fn a_fault_in_the_releasing_transaction_leaves_every_row_and_entry() {
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

            allocate(&test_db, "attempt-1", &giganto_bindings()).unwrap();
            let stored_cleanup = owed.as_ref().and_then(|owed| owed.cleanup_state);
            if let Some(owed) = owed {
                attempts.upsert(&owed).unwrap();
                assert_eq!(test_db.rows().len(), 3, "{occasion}");
            }

            // The transaction `upsert` builds, abandoned before it commits.
            let txn = table.transaction();
            attempts.upsert_with_transaction(&attempt, &txn).unwrap();
            drop(txn);

            assert_eq!(test_db.rows().len(), 3, "{occasion}");
            assert_eq!(test_db.attempt_index().len(), 3, "{occasion}");
            assert_eq!(test_db.instance_index().len(), 3, "{occasion}");
            assert_eq!(
                attempts
                    .get(&attempt.idempotency_key)
                    .unwrap()
                    .and_then(|stored| stored.cleanup_state),
                stored_cleanup,
                "{occasion}"
            );

            // Committed, the rows, both indexes and the record that justifies
            // the release all move together.
            attempts.upsert(&attempt).unwrap();
            assert_eq!(test_db.rows(), Vec::new(), "{occasion}");
            assert_eq!(test_db.attempt_index(), Vec::new(), "{occasion}");
            assert_eq!(test_db.instance_index(), Vec::new(), "{occasion}");
            assert!(attempts.get(&attempt.idempotency_key).unwrap().is_some());
        }
    }

    /// Two concurrent installs write **different** `operation_attempt` rows,
    /// so their transactions do not conflict on that and "in the same
    /// transaction" does not stop both committing one port — the unique key
    /// does. Two sequential calls would pass against a plain write batch, so
    /// this drives the real race: both transactions are open at once, and the
    /// second commit fails.
    #[test]
    fn concurrent_allocations_for_one_address_cannot_double_commit() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let winner = table.transaction();
        let loser = table.transaction();
        table
            .allocate_with_transaction(
                HOST,
                COMPONENT,
                1,
                &key("attempt-a"),
                &[binding(INGEST, Transport::Tcp, 38_370)],
                &winner,
            )
            .unwrap();
        table
            .allocate_with_transaction(
                HOST,
                COMPONENT,
                2,
                &key("attempt-b"),
                &[binding(INGEST, Transport::Tcp, 38_370)],
                &loser,
            )
            .unwrap();

        winner.commit().unwrap();
        let conflict = loser.commit().unwrap_err();
        assert!(
            conflict.as_ref().starts_with("Resource busy:"),
            "expected a commit conflict, got {conflict}"
        );

        // One address, one row, and it belongs to the transaction that
        // committed.
        assert_eq!(test_db.rows().len(), 1);
        assert_eq!(
            table
                .get(HOST, Transport::Tcp, 38_370)
                .unwrap()
                .unwrap()
                .idempotency_key,
            key("attempt-a")
        );

        // The loser looks again, which is what turns a bare commit conflict
        // into a refusal naming the winner.
        let refusal = table
            .allocate_with_transaction(
                HOST,
                COMPONENT,
                2,
                &key("attempt-b"),
                &[binding(INGEST, Transport::Tcp, 38_370)],
                &table.transaction(),
            )
            .unwrap_err();
        let PortAllocationError::PortAllocationConflict {
            host,
            transport,
            port,
            owner,
        } = refusal
        else {
            panic!("expected a port allocation conflict, got {refusal}");
        };
        assert_eq!(host, HOST);
        assert_eq!(transport, Transport::Tcp);
        assert_eq!(port, 38_370);
        assert_eq!(
            owner,
            PortOwner {
                component: COMPONENT.to_string(),
                instance: 1,
                listener_key: INGEST.to_string(),
            }
        );
    }

    /// The same race run by two threads through the public entry point: one
    /// winner, one typed conflict carrying the winner's owner triple, and
    /// never two rows. The loser's transaction is abandoned whole, so the
    /// instance number it selected is not left held either.
    ///
    /// The two install **different** components, which is what leaves the
    /// address as the only thing they contend for: the port key is
    /// `(host, transport, port)` and is blind to whose port it is, while
    /// every other resource the two take — the instance number, the
    /// single-flight slot of a `(host, target, instance)` triple — is keyed
    /// by a component they do not share.
    #[test]
    fn racing_threads_produce_one_winner_and_one_typed_conflict() {
        let test_db = TestDb::new();

        let (first, second) = std::thread::scope(|scope| {
            let db = &test_db.db;
            let take = move |idempotency_key: &'static str, component: &'static str| {
                move || {
                    let bindings = [binding(INGEST, Transport::Tcp, 38_370)];
                    let mut attempt = install(idempotency_key, None);
                    attempt.target = component.to_string();
                    let request = submit(&mut attempt, &bindings);
                    Table::<OperationAttempt>::open(db)
                        .unwrap()
                        .allocate_instance_and_addrs(&attempt, &request, &bindings)
                }
            };
            let a = scope.spawn(take("attempt-a", COMPONENT));
            let b = scope.spawn(take("attempt-b", OTHER_COMPONENT));
            (a.join().unwrap(), b.join().unwrap())
        });

        let (winner, loser) = match (first, second) {
            (Ok(winner), Err(loser)) | (Err(loser), Ok(winner)) => (winner, loser),
            (Ok(_), Ok(_)) => panic!("two rows were written for one address"),
            (Err(first), Err(second)) => {
                panic!("neither attempt took the address: {first}, {second}")
            }
        };

        let AddressAllocationError::PortAllocationConflict {
            host,
            transport,
            port,
            owner,
        } = loser
        else {
            panic!("expected a port allocation conflict, got {loser}");
        };
        assert_eq!(host, HOST);
        assert_eq!(transport, Transport::Tcp);
        assert_eq!(port, 38_370);
        assert_eq!(
            owner,
            PortOwner {
                component: winner.target.clone(),
                instance: winner.instance.unwrap(),
                listener_key: INGEST.to_string(),
            }
        );

        let table = test_db.table();
        assert_eq!(test_db.rows().len(), 1);
        assert_eq!(test_db.attempt_index().len(), 1);
        assert_eq!(test_db.instance_index().len(), 1);
        assert_eq!(
            table
                .get(HOST, Transport::Tcp, 38_370)
                .unwrap()
                .unwrap()
                .idempotency_key,
            winner.idempotency_key
        );
        // The loser committed nothing at all, so neither an instance number
        // nor an attempt row is left behind by the drive that took no
        // address.
        let instances = test_db.instances();
        assert_eq!(instances.allocated(HOST, &winner.target).unwrap().len(), 1);
        let loser_component = if winner.target == COMPONENT {
            OTHER_COMPONENT
        } else {
            COMPONENT
        };
        assert_eq!(
            instances.allocated(HOST, loser_component).unwrap(),
            Vec::new()
        );
    }

    /// Two installs of **one** component race for the instance number, each
    /// naming addresses of its own. The pass that loses is doomed to fail its
    /// commit on the number the winner took, so it must retry and take the
    /// next one — not report the winner it now finds live on the triple as a
    /// refusal, which would answer a lost race with a state the caller never
    /// asked about, on a number it was never given. Both therefore get a
    /// number, and the loser's address rows are keyed on the number its retry
    /// ended up with rather than the one its first pass selected.
    ///
    /// The window the losing pass has to be caught in is the one between its
    /// locking read of the number and its read of the triple, so the race is
    /// staged rather than left to chance: the two start together on a
    /// barrier, and the pass that is to lose names enough addresses that the
    /// other reaches its commit while it is still writing rows. The rounds
    /// are there because a scheduler may still order one round the other way
    /// round, not because a single one is expected to miss.
    #[test]
    fn a_pass_that_loses_the_instance_race_retries_with_its_addresses() {
        const ROUNDS: usize = 8;
        const SHORT: u16 = 1;
        const LONG: u16 = 64;

        for _ in 0..ROUNDS {
            let test_db = TestDb::new();
            let start = std::sync::Barrier::new(2);
            let (first, second) = std::thread::scope(|scope| {
                let db = &test_db.db;
                let start = &start;
                let take = move |idempotency_key: &'static str, base: u16, listeners: u16| {
                    move || {
                        let bindings: Vec<ListenerBinding> = (0..listeners)
                            .map(|n| binding(&format!("listener-{n}"), Transport::Tcp, base + n))
                            .collect();
                        let mut attempt = install(idempotency_key, None);
                        let request = submit(&mut attempt, &bindings);
                        start.wait();
                        (
                            Table::<OperationAttempt>::open(db)
                                .unwrap()
                                .allocate_instance_and_addrs(&attempt, &request, &bindings)
                                .unwrap(),
                            listeners,
                        )
                    }
                };
                let a = scope.spawn(take("attempt-a", 38_400, SHORT));
                let b = scope.spawn(take("attempt-b", 38_500, LONG));
                (a.join().unwrap(), b.join().unwrap())
            });

            let table = test_db.table();
            let mut instances = BTreeSet::new();
            for ((attempt, listeners), base) in [(first, 38_400), (second, 38_500)] {
                let instance = attempt.instance.unwrap();
                instances.insert(instance);

                // Every address the pass named is keyed on the number that
                // pass ended up holding, so a retry left nothing behind on
                // the number its first pass selected.
                let rows = table.allocated_by(&attempt.idempotency_key).unwrap();
                assert_eq!(rows.len(), usize::from(listeners));
                assert_eq!(
                    table.allocated_for(HOST, COMPONENT, instance).unwrap(),
                    rows
                );
                for row in rows {
                    assert_eq!(row.instance, instance);
                    assert!((base..base + listeners).contains(&row.port));
                }
            }
            assert_eq!(instances, [1, 2].into_iter().collect());
            assert_eq!(test_db.rows().len(), usize::from(SHORT + LONG));
        }
    }

    /// A terminal **success** keeps its addresses. Releasing on success would
    /// be worse than never writing the row: a stopped service reports nothing,
    /// so its ports would read as free and collide the moment it starts again.
    #[test]
    fn a_terminal_success_keeps_its_addresses() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        allocate(&test_db, "attempt-1", &giganto_bindings()).unwrap();
        attempts
            .upsert(&terminal(
                "attempt-1",
                1,
                OperationAction::Install,
                OperationOutcome::Succeeded,
            ))
            .unwrap();

        assert_eq!(test_db.rows().len(), 3);
        assert_eq!(table.allocated_for(HOST, COMPONENT, 1).unwrap().len(), 3);
        // And the number their owner is keyed on is kept with them.
        assert_eq!(
            test_db
                .instances()
                .allocated(HOST, COMPONENT)
                .unwrap()
                .len(),
            1
        );
    }

    /// The other three occasions release, each in the same transaction as the
    /// record that justifies it, and a released address is immediately
    /// re-allocatable — the observable consequence of release being a delete.
    #[test]
    fn the_other_three_occasions_release_and_the_address_is_free_again() {
        let failed = terminal(
            "attempt-1",
            1,
            OperationAction::Install,
            OperationOutcome::Failed,
        );
        let occasions = [
            (
                "a failed attempt owing no cleanup",
                Vec::new(),
                failed.clone(),
            ),
            (
                "the cleanup discharge",
                vec![with_cleanup(
                    failed.clone(),
                    Some(OperationCleanupState::PendingDeregister),
                )],
                failed,
            ),
            (
                "a confirmed removal",
                vec![terminal(
                    "attempt-1",
                    1,
                    OperationAction::Install,
                    OperationOutcome::Succeeded,
                )],
                terminal(
                    "attempt-remove",
                    1,
                    OperationAction::Remove,
                    OperationOutcome::Succeeded,
                ),
            ),
        ];

        for (occasion, before, attempt) in occasions {
            let test_db = TestDb::new();
            let table = test_db.table();
            let attempts = test_db.attempts();

            allocate(&test_db, "attempt-1", &giganto_bindings()).unwrap();
            for earlier in &before {
                attempts.upsert(earlier).unwrap();
                // A terminal attempt that still owes a cleanup, and a
                // terminal success, both keep what they hold.
                assert_eq!(test_db.rows().len(), 3, "{occasion}");
                assert_eq!(test_db.attempt_index().len(), 3, "{occasion}");
            }

            attempts.upsert(&attempt).unwrap();

            assert_eq!(test_db.rows(), Vec::new(), "{occasion}");
            assert_eq!(test_db.attempt_index(), Vec::new(), "{occasion}");
            assert_eq!(test_db.instance_index(), Vec::new(), "{occasion}");
            assert_eq!(
                table.allocated_by(&key("attempt-1")).unwrap(),
                Vec::new(),
                "{occasion}"
            );

            // Immediately re-allocatable, by another attempt.
            let stored = allocate(&test_db, "attempt-next", &giganto_bindings()).unwrap();
            assert_eq!(stored.instance, Some(1), "{occasion}");
            assert_eq!(test_db.rows().len(), 3, "{occasion}");
        }
    }

    /// A failed update does not tear down the instance it was updating, so it
    /// releases nothing: its rows are the install's, and it holds none of its
    /// own.
    #[test]
    fn a_failed_update_leaves_the_running_instance_its_addresses() {
        let test_db = TestDb::new();
        let attempts = test_db.attempts();

        allocate(&test_db, "attempt-install", &giganto_bindings()).unwrap();
        attempts
            .upsert(&terminal(
                "attempt-install",
                1,
                OperationAction::Install,
                OperationOutcome::Succeeded,
            ))
            .unwrap();

        attempts
            .upsert(&terminal(
                "attempt-update",
                1,
                OperationAction::Update,
                OperationOutcome::Failed,
            ))
            .unwrap();

        assert_eq!(test_db.rows().len(), 3);
        assert_eq!(
            test_db
                .table()
                .allocated_by(&key("attempt-install"))
                .unwrap()
                .len(),
            3
        );
    }

    /// A confirmed removal releases the instance's rows whichever attempt
    /// allocated them, because the instance they belong to is gone.
    #[test]
    fn a_confirmed_removal_releases_the_addresses_the_install_took() {
        let test_db = TestDb::new();
        let attempts = test_db.attempts();

        allocate(&test_db, "attempt-install", &giganto_bindings()).unwrap();
        attempts
            .upsert(&terminal(
                "attempt-install",
                1,
                OperationAction::Install,
                OperationOutcome::Succeeded,
            ))
            .unwrap();
        assert_eq!(test_db.rows().len(), 3);

        attempts
            .upsert(&terminal(
                "attempt-remove",
                1,
                OperationAction::Remove,
                OperationOutcome::Succeeded,
            ))
            .unwrap();

        assert_eq!(test_db.rows(), Vec::new());
        assert_eq!(test_db.attempt_index(), Vec::new());
        assert_eq!(test_db.instance_index(), Vec::new());
    }

    /// Two instances of one component on one host is the case this table
    /// exists for, and a confirmed removal reaches its rows by prefix scan on
    /// `(host, component, instance)` — so all three segments have to bound
    /// that prefix. A removal is a delete, and a prefix reaching past its own
    /// instance number or its own component would take a running instance's
    /// addresses with it, which is the one failure here that a live service
    /// cannot survive.
    #[test]
    fn a_removal_leaves_the_sibling_instance_and_component_their_addresses() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let attempts = test_db.attempts();

        let first = allocate(&test_db, "attempt-1", &giganto_bindings()).unwrap();
        let second_bindings = vec![
            binding(INGEST, Transport::Tcp, 38_470),
            binding(PUBLISH, Transport::Udp, 38_471),
            binding(GRAPHQL, Transport::Udp, 8542),
        ];
        let second = allocate(&test_db, "attempt-2", &second_bindings).unwrap();
        assert_eq!((first.instance, second.instance), (Some(1), Some(2)));

        // A component of its own on the same host, numbered from its own
        // sequence: `(host, component)` is what the number counts within, so
        // this one is instance 1 alongside the first above.
        let neighbour_bindings = [binding(INGEST, Transport::Tcp, 39_370)];
        let mut neighbour = install("attempt-3", None);
        neighbour.target = OTHER_COMPONENT.to_string();
        let neighbour_request = submit(&mut neighbour, &neighbour_bindings);
        let neighbour = attempts
            .allocate_instance_and_addrs(&neighbour, &neighbour_request, &neighbour_bindings)
            .unwrap();
        assert_eq!(neighbour.instance, Some(1));

        // Each reader answers for the triple it was asked about and no other.
        assert_eq!(
            request_map(&table.allocated_for(HOST, COMPONENT, 1).unwrap()),
            request_map(&table.allocated_by(&key("attempt-1")).unwrap())
        );
        assert_eq!(
            request_map(&table.allocated_for(HOST, COMPONENT, 2).unwrap()),
            request_map(&table.allocated_by(&key("attempt-2")).unwrap())
        );
        assert_eq!(table.allocated_for(HOST, COMPONENT, 1).unwrap().len(), 3);
        assert_eq!(table.allocated_for(HOST, COMPONENT, 2).unwrap().len(), 3);
        assert_eq!(
            table.allocated_for(HOST, OTHER_COMPONENT, 1).unwrap().len(),
            1
        );
        assert_eq!(table.allocated_for(HOST, COMPONENT, 3).unwrap(), Vec::new());

        attempts
            .upsert(&terminal(
                "attempt-remove",
                2,
                OperationAction::Remove,
                OperationOutcome::Succeeded,
            ))
            .unwrap();

        // Only the removed instance's rows go, and both indexes lose exactly
        // its three entries.
        assert_eq!(table.allocated_for(HOST, COMPONENT, 2).unwrap(), Vec::new());
        assert_eq!(
            request_map(&table.allocated_for(HOST, COMPONENT, 1).unwrap()),
            request_map(&table.allocated_by(&key("attempt-1")).unwrap())
        );
        assert_eq!(table.allocated_for(HOST, COMPONENT, 1).unwrap().len(), 3);
        assert_eq!(
            table.allocated_for(HOST, OTHER_COMPONENT, 1).unwrap().len(),
            1
        );
        assert_eq!(test_db.rows().len(), 4);
        assert_eq!(test_db.attempt_index().len(), 4);
        assert_eq!(test_db.instance_index().len(), 4);
    }

    /// A removal that failed is not a confirmed removal, so the instance
    /// keeps what it holds.
    #[test]
    fn a_failed_removal_leaves_the_instance_its_addresses() {
        let test_db = TestDb::new();
        let attempts = test_db.attempts();

        allocate(&test_db, "attempt-install", &giganto_bindings()).unwrap();
        attempts
            .upsert(&terminal(
                "attempt-install",
                1,
                OperationAction::Install,
                OperationOutcome::Succeeded,
            ))
            .unwrap();
        attempts
            .upsert(&terminal(
                "attempt-remove",
                1,
                OperationAction::Remove,
                OperationOutcome::Failed,
            ))
            .unwrap();

        assert_eq!(test_db.rows().len(), 3);
    }

    /// An attempt whose host never returned is finalized by the sweep, and
    /// the sweep's own transaction gives the addresses back.
    #[test]
    fn an_expired_attempt_releases_its_addresses_in_the_sweep() {
        let test_db = TestDb::new();
        let attempts = test_db.attempts();

        allocate(&test_db, "attempt-1", &giganto_bindings()).unwrap();
        assert_eq!(test_db.rows().len(), 3);

        assert_eq!(attempts.sweep_expired(timestamp(1_700_090_000)).unwrap(), 1);

        assert_eq!(test_db.rows(), Vec::new());
        assert_eq!(test_db.attempt_index(), Vec::new());
        assert_eq!(test_db.instance_index(), Vec::new());
    }

    /// The instance row and the address rows are one transaction, instance
    /// first: a fault after the number is taken leaves neither it nor the
    /// rows keyed on it, because a held number owning no ports is a leak
    /// nothing collects.
    #[test]
    fn the_instance_row_and_the_address_rows_land_together() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let instances = test_db.instances();
        let attempts = test_db.attempts();

        let txn = table.transaction();
        let instance = instances
            .allocate_with_transaction(HOST, COMPONENT, &key("attempt-1"), &txn)
            .unwrap();
        assert_eq!(instance, 1);
        table
            .allocate_with_transaction(
                HOST,
                COMPONENT,
                instance,
                &key("attempt-1"),
                &giganto_bindings(),
                &txn,
            )
            .unwrap();
        attempts
            .upsert_with_transaction(&install("attempt-1", Some(instance)), &txn)
            .unwrap();
        drop(txn);

        assert_eq!(instances.allocated(HOST, COMPONENT).unwrap(), Vec::new());
        assert_eq!(test_db.rows(), Vec::new());
        assert_eq!(test_db.attempt_index(), Vec::new());
        assert_eq!(attempts.get(&key("attempt-1")).unwrap(), None);

        // Which is what the public entry point does, in one transaction.
        let stored = allocate(&test_db, "attempt-1", &giganto_bindings()).unwrap();
        assert_eq!(stored.instance, Some(1));
        assert_eq!(instances.allocated(HOST, COMPONENT).unwrap().len(), 1);
        assert_eq!(test_db.rows().len(), 3);
        assert_eq!(attempts.get(&key("attempt-1")).unwrap().unwrap(), stored);
    }

    /// A re-drive of a recorded key allocates nothing at all: the row under
    /// the key is the answer, and its addresses stand exactly as they were.
    #[test]
    fn a_re_drive_of_a_recorded_attempt_allocates_nothing() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let first = allocate(&test_db, "attempt-1", &giganto_bindings()).unwrap();
        let again = allocate(
            &test_db,
            "attempt-1",
            &[binding("something-else", Transport::Tcp, 9999)],
        )
        .unwrap();

        assert_eq!(first, again);
        assert_eq!(test_db.rows().len(), 3);
        assert_eq!(table.get(HOST, Transport::Tcp, 9999).unwrap(), None);
        assert_eq!(
            request_map(&table.allocated_by(&key("attempt-1")).unwrap()),
            vec![
                (GRAPHQL.to_string(), addr(8442)),
                (INGEST.to_string(), addr(38_370)),
                (PUBLISH.to_string(), addr(38_371)),
            ]
        );
    }

    /// Re-running the allocating transaction after a commit conflict must not
    /// refuse the attempt its own rows, which is the one case where an
    /// occupied key is not a conflict.
    #[test]
    fn an_attempt_re_takes_the_rows_it_already_holds() {
        let test_db = TestDb::new();
        let table = test_db.table();

        let txn = table.transaction();
        table
            .allocate_with_transaction(
                HOST,
                COMPONENT,
                1,
                &key("attempt-1"),
                &giganto_bindings(),
                &txn,
            )
            .unwrap();
        txn.commit().unwrap();

        let txn = table.transaction();
        let rows = table
            .allocate_with_transaction(
                HOST,
                COMPONENT,
                1,
                &key("attempt-1"),
                &giganto_bindings(),
                &txn,
            )
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(test_db.rows().len(), 3);
        assert_eq!(test_db.attempt_index().len(), 3);

        // The same key on the same address for a different listener is a
        // conflict with itself rather than a silent move.
        let txn = table.transaction();
        let refusal = table
            .allocate_with_transaction(
                HOST,
                COMPONENT,
                1,
                &key("attempt-1"),
                &[binding("another", Transport::Tcp, 38_370)],
                &txn,
            )
            .unwrap_err();
        assert!(matches!(
            refusal,
            PortAllocationError::PortAllocationConflict { .. }
        ));
    }

    /// The transport is part of the key, so one port number carries a TCP and
    /// a UDP row at once — the case a Giganto instance presents.
    #[test]
    fn one_port_number_holds_a_row_for_each_transport() {
        let test_db = TestDb::new();
        let table = test_db.table();

        allocate(
            &test_db,
            "attempt-1",
            &[
                binding(INGEST, Transport::Tcp, 38_370),
                binding(PUBLISH, Transport::Udp, 38_370),
            ],
        )
        .unwrap();

        assert_eq!(test_db.rows().len(), 2);
        assert_eq!(
            table
                .get(HOST, Transport::Tcp, 38_370)
                .unwrap()
                .unwrap()
                .listener_key,
            INGEST
        );
        assert_eq!(
            table
                .get(HOST, Transport::Udp, 38_370)
                .unwrap()
                .unwrap()
                .listener_key,
            PUBLISH
        );
    }

    /// One host's allocation says nothing about another's: the host leads
    /// every key.
    #[test]
    fn each_host_is_allocated_on_its_own() {
        let test_db = TestDb::new();
        let table = test_db.table();

        allocate(
            &test_db,
            "attempt-a",
            &[binding(INGEST, Transport::Tcp, 38_370)],
        )
        .unwrap();
        let bindings = [binding(INGEST, Transport::Tcp, 38_370)];
        let mut attempt = install("attempt-b", None);
        attempt.host = OTHER_HOST.to_string();
        let request = submit(&mut attempt, &bindings);
        test_db
            .attempts()
            .allocate_instance_and_addrs(&attempt, &request, &bindings)
            .unwrap();

        assert_eq!(test_db.rows().len(), 2);
        assert_eq!(
            table
                .get(OTHER_HOST, Transport::Tcp, 38_370)
                .unwrap()
                .unwrap()
                .idempotency_key,
            key("attempt-b")
        );
    }

    /// Every variable-length segment is length-prefixed, so no two distinct
    /// tuples encode to one key.
    #[test]
    fn key_encoding_is_collision_safe() {
        assert_ne!(
            row_key("ab", Transport::Tcp, 1).unwrap(),
            row_key("a", Transport::Tcp, 1).unwrap()
        );
        assert_ne!(
            row_key("a", Transport::Tcp, 1).unwrap(),
            row_key("a", Transport::Udp, 1).unwrap()
        );
        assert_ne!(
            attempt_index_key("ab", "c").unwrap(),
            attempt_index_key("a", "bc").unwrap()
        );
        assert_ne!(
            instance_index_key("ab", "c", 1, "d").unwrap(),
            instance_index_key("a", "bc", 1, "d").unwrap()
        );
        assert_ne!(
            instance_index_key(HOST, COMPONENT, 1, "ab").unwrap(),
            instance_index_key(HOST, COMPONENT, 1, "a").unwrap()
        );
        // And an instance prefix does not reach into its neighbour's entries.
        assert!(
            !instance_index_key(HOST, COMPONENT, 2, INGEST)
                .unwrap()
                .starts_with(&instance_prefix(HOST, COMPONENT, 1).unwrap())
        );
    }

    /// The key round-trips, and refuses what it never wrote.
    #[test]
    fn key_round_trips_and_rejects_what_it_never_wrote() {
        let key = row_key(HOST, Transport::Udp, 38_371).unwrap();
        assert_eq!(
            decode_row_key(&key).unwrap(),
            (HOST.to_string(), Transport::Udp, 38_371)
        );

        assert!(decode_row_key(&[]).is_err());
        assert!(decode_row_key(&key[..key.len() - 1]).is_err());
        let mut unknown_transport = key.clone();
        let tail = unknown_transport.len() - 3;
        unknown_transport[tail] = 9;
        assert!(decode_row_key(&unknown_transport).is_err());
    }

    /// An `IPv6` address round-trips as itself: the address is a `SocketAddr`
    /// on the row rather than a rendering of one.
    #[test]
    fn an_ipv6_address_round_trips() {
        let test_db = TestDb::new();
        let table = test_db.table();
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 38_370);

        let bindings = [ListenerBinding {
            listener_key: INGEST.to_string(),
            transport: Transport::Tcp,
            addr,
        }];
        let mut attempt = install("attempt-1", None);
        let request = submit(&mut attempt, &bindings);
        test_db
            .attempts()
            .allocate_instance_and_addrs(&attempt, &request, &bindings)
            .unwrap();

        assert_eq!(
            table
                .get(HOST, Transport::Tcp, 38_370)
                .unwrap()
                .unwrap()
                .addr,
            addr
        );
    }

    /// The listener key is the last segment of both index keys, so two
    /// bindings sharing one would have the second entry overwrite the first
    /// and leave a row neither reader could find. It is refused instead.
    #[test]
    fn one_listener_named_twice_is_refused() {
        let test_db = TestDb::new();

        let refusal = allocate(
            &test_db,
            "attempt-1",
            &[
                binding(INGEST, Transport::Tcp, 38_370),
                binding(INGEST, Transport::Udp, 38_371),
            ],
        )
        .unwrap_err();
        assert!(matches!(refusal, AddressAllocationError::Database(_)));
        assert!(refusal.to_string().contains("twice"), "{refusal}");
        assert_eq!(test_db.rows(), Vec::new());

        let refusal =
            allocate(&test_db, "attempt-2", &[binding("", Transport::Tcp, 1)]).unwrap_err();
        assert!(matches!(refusal, AddressAllocationError::Database(_)));
        assert_eq!(test_db.rows(), Vec::new());
    }

    /// The rows are the only place the addresses survive, and the attempt row
    /// keeps the request's digest rather than the request, so an allocation
    /// made for one request under an attempt recorded for another would be
    /// indistinguishable afterwards: a retry resolves its key by that digest
    /// and rebuilds the map it sent from these rows, and would be answered
    /// with addresses nobody submitted. The two are tied at the only
    /// boundary that sees both, and none of these is written.
    #[test]
    fn an_allocation_the_request_does_not_ask_for_is_refused() {
        let test_db = TestDb::new();
        let attempts = test_db.attempts();
        let bindings = giganto_bindings();

        // An attempt recorded for a request that leaves the addresses to the
        // component, taking three of them.
        let refused = attempts.allocate_instance_and_addrs(
            &install("attempt-1", None),
            &request_for(HOST, COMPONENT, &[]),
            &bindings,
        );
        assert!(matches!(refused, Err(AddressAllocationError::Database(_))));

        // The same the other way about: a request naming three addresses,
        // taking none — which is exactly what `allocate_instance` does with
        // one.
        let mut asking = install("attempt-1", None);
        let asked = submit(&mut asking, &bindings);
        let refused = attempts.allocate_instance(&asking, &asked);
        assert!(matches!(refused, Err(InstanceAllocationError::Database(_))));

        // One address of some other map: the pairs are compared, not their
        // count.
        let mut renumbered = bindings.clone();
        renumbered[2] = binding(GRAPHQL, Transport::Udp, 8543);
        let refused = attempts.allocate_instance_and_addrs(&asking, &asked, &renumbered);
        assert!(matches!(refused, Err(AddressAllocationError::Database(_))));

        // A request the attempt records the digest of, for another host: the
        // rows are keyed on the attempt's host, and this is not that host's
        // request.
        let elsewhere = request_for(OTHER_HOST, COMPONENT, &bindings);
        let mut moved = install("attempt-1", None);
        moved.install_intent = Some(elsewhere.digest().unwrap());
        let refused = attempts.allocate_instance_and_addrs(&moved, &elsewhere, &bindings);
        assert!(matches!(refused, Err(AddressAllocationError::Database(_))));

        // And a request that is not the one the row records at all: the same
        // addresses on the same pair, submitted for another build.
        let mut resubmitted = asked.clone();
        resubmitted.selector = BuildSelector::Commit("c0ffee".to_string());
        let refused = attempts.allocate_instance_and_addrs(&asking, &resubmitted, &bindings);
        assert!(matches!(refused, Err(AddressAllocationError::Database(_))));

        assert_eq!(test_db.rows(), Vec::new());
        assert_eq!(test_db.attempt_index(), Vec::new());
        assert_eq!(test_db.instance_index(), Vec::new());
        assert_eq!(attempts.get(&key("attempt-1")).unwrap(), None);
        assert!(
            test_db
                .instances()
                .allocated(HOST, COMPONENT)
                .unwrap()
                .is_empty()
        );

        // The request the attempt records, asking for the addresses it takes.
        let stored = attempts
            .allocate_instance_and_addrs(&asking, &asked, &bindings)
            .unwrap();
        assert_eq!(stored.instance, Some(1));
        assert_eq!(test_db.rows().len(), 3);

        // An absent list and an empty one are distinct requests — the digest
        // encodes them differently — and both take no address, so neither is
        // refused for taking none.
        let mut none_at_all = request_for(HOST, COMPONENT, &[]);
        none_at_all.bind_addrs = Some(Vec::new());
        let mut asking_none = install("attempt-2", None);
        asking_none.install_intent = Some(none_at_all.digest().unwrap());
        let stored = attempts
            .allocate_instance_and_addrs(&asking_none, &none_at_all, &[])
            .unwrap();
        assert_eq!(stored.instance, Some(2));
        assert_eq!(test_db.rows().len(), 3);
    }

    /// A request whose second address is taken leaves none of the first: the
    /// refusal comes after the free one is already written into the
    /// transaction, so the guarantee is the transaction's rather than the
    /// order the bindings happen to be in. An install that cannot bind all of
    /// its listeners holds none of the addresses it asked for, and takes no
    /// instance number either.
    #[test]
    fn a_conflict_part_way_through_takes_none_of_the_addresses() {
        let test_db = TestDb::new();
        let table = test_db.table();

        allocate(
            &test_db,
            "attempt-a",
            &[binding(INGEST, Transport::Tcp, 38_370)],
        )
        .unwrap();

        let refusal = allocate(
            &test_db,
            "attempt-b",
            &[
                binding(PUBLISH, Transport::Udp, 38_371),
                binding(INGEST, Transport::Tcp, 38_370),
            ],
        )
        .unwrap_err();
        assert!(matches!(
            refusal,
            AddressAllocationError::PortAllocationConflict { .. }
        ));

        // The free address the request named first is not held, and the
        // winner's row stands alone in the table and in both indexes.
        assert_eq!(table.get(HOST, Transport::Udp, 38_371).unwrap(), None);
        assert_eq!(test_db.rows().len(), 1);
        assert_eq!(test_db.attempt_index().len(), 1);
        assert_eq!(test_db.instance_index().len(), 1);
        assert_eq!(table.allocated_by(&key("attempt-b")).unwrap(), Vec::new());

        // And the drive that took no address recorded no attempt and holds no
        // number, because all of it was the one transaction.
        assert_eq!(test_db.attempts().get(&key("attempt-b")).unwrap(), None);
        assert_eq!(
            test_db
                .instances()
                .allocated(HOST, COMPONENT)
                .unwrap()
                .len(),
            1
        );
    }

    /// A store the format bump has not reached has no port allocation table,
    /// so an install naming an address is refused rather than recorded with
    /// its addresses silently dropped — while one naming none writes exactly
    /// as it always did.
    #[test]
    fn a_store_without_the_port_tables_refuses_an_address() {
        let test_db = TestDb::with_column_families(&[
            super::super::INSTANCE_ALLOCATIONS,
            super::super::OPERATION_ATTEMPT_LATEST,
        ]);
        let attempts = test_db.attempts();

        assert!(Table::<PortAllocation>::open(&test_db.db).is_none());

        let bindings = giganto_bindings();
        let mut attempt = install("attempt-1", None);
        let request = submit(&mut attempt, &bindings);
        let refusal = attempts
            .allocate_instance_and_addrs(&attempt, &request, &bindings)
            .unwrap_err();
        assert!(matches!(refusal, AddressAllocationError::Database(_)));
        assert_eq!(attempts.get(&key("attempt-1")).unwrap(), None);

        let stored = attempts
            .allocate_instance_and_addrs(
                &install("attempt-2", None),
                &request_for(HOST, COMPONENT, &[]),
                &[],
            )
            .unwrap();
        assert_eq!(stored.instance, Some(1));
    }

    /// None of the three names is in `MAP_NAMES`, because `StateDb::open`
    /// creates every family named there while `migrate_data_dir` returns
    /// early for a data dir already at a compatible version: registering them
    /// before the format bump would add the families to a `0.46.0` store with
    /// no migration record. The tests above open a store that would fail on a
    /// duplicate family name, so this is already load-bearing; it is asserted
    /// here so that the reason is stated rather than inferred from a
    /// `rocksdb` error.
    #[test]
    fn the_column_families_are_not_registered_before_the_format_bump() {
        for name in [
            super::super::PORT_ALLOCATIONS,
            super::super::PORT_ALLOCATIONS_BY_ATTEMPT,
            super::super::PORT_ALLOCATIONS_BY_INSTANCE,
        ] {
            assert!(
                !super::super::MAP_NAMES.contains(&name),
                "{name} is registered before the format bump that creates it"
            );
        }
    }

    /// A store carrying the primary family alone is not this table: a row
    /// written there would be one neither reader could find.
    #[test]
    fn the_three_column_families_are_opened_as_one() {
        let test_db = TestDb::with_column_families(&[super::super::PORT_ALLOCATIONS]);
        assert!(Table::<PortAllocation>::open(&test_db.db).is_none());

        let test_db = TestDb::with_column_families(&[
            super::super::PORT_ALLOCATIONS,
            super::super::PORT_ALLOCATIONS_BY_ATTEMPT,
        ]);
        assert!(Table::<PortAllocation>::open(&test_db.db).is_none());
    }
}
