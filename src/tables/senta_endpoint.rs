//! The tables of Clumit Endpoint (`senta`) agents.
//!
//! The nine tables holding the customers' trust states, the signed
//! documents, the enrolled endpoints, their enrollment attempts and their
//! commands, which the deletion-guarded transaction methods of
//! [`Store`](crate::Store) write together, are in `trust`, with their own
//! key encoding. The rest of this module is the observation tables.
//!
//! `REview` keeps what it observes of its endpoints in eight tables: the
//! active list it applied, the state of each Giganto node's endpoint entry,
//! unenroll requests, the last document result per endpoint and document,
//! the last status report, `DuplicateKey` events, and the loss records and
//! last-received times it fetches from Giganto nodes. Each table is one
//! column family, and none of them is written together with another table.
//!
//! The tables interpret none of the text or bytes they store: an entry state,
//! a document result or a status report is the text form `REview` writes, and
//! is returned as it was given.
//!
//! # Keys
//!
//! A key is the concatenation of its components, each encoded so that the
//! byte order of keys is the order of their components:
//!
//! - a [`Uuid`] as its 16 bytes;
//! - a `u32` or `u64` big-endian;
//! - an `i64` big-endian with its sign bit flipped, so negative values sort
//!   before positive ones;
//! - a string as its UTF-8 bytes, each `0x00` byte written as `0x00 0xFF`,
//!   followed by `0x00 0x00`, so strings sort in byte order and none is the
//!   prefix of the encoding of another;
//! - a Giganto node as its host name and then its instance.
//!
//! Every per-endpoint table starts its key with the endpoint id, whose
//! encoding has a fixed length, so a read by endpoint id covers exactly the
//! rows of that endpoint.

mod active_list;
mod document_result;
mod event;
mod giganto_entry;
mod giganto_last_received;
mod giganto_loss;
mod status_report;
pub(super) mod trust;
mod unenroll_request;

use std::marker::PhantomData;

use anyhow::{Context, Result, anyhow};
use rocksdb::{IteratorMode, OptimisticTransactionDB, WriteBatchWithTransaction};
use uuid::Uuid;

pub use self::active_list::{
    SentaEndpointActiveList, SentaEndpointActiveListEntry, SentaEndpointActiveListTable,
};
pub use self::document_result::{
    SentaEndpointDocumentResult, SentaEndpointDocumentResultKey, SentaEndpointDocumentResultTable,
};
pub use self::event::{
    SentaEndpointEvent, SentaEndpointEventKey, SentaEndpointEventSource, SentaEndpointEventTable,
};
pub use self::giganto_entry::{SentaEndpointGigantoEntry, SentaEndpointGigantoEntryTable};
pub use self::giganto_last_received::{
    SentaEndpointGigantoLastReceived, SentaEndpointGigantoLastReceivedKey,
    SentaEndpointGigantoLastReceivedTable,
};
pub use self::giganto_loss::{
    SentaEndpointGigantoLoss, SentaEndpointGigantoLossKey, SentaEndpointGigantoLossTable,
};
pub use self::status_report::{SentaEndpointStatusReport, SentaEndpointStatusReportTable};
pub use self::unenroll_request::{SentaEndpointUnenrollRequest, SentaEndpointUnenrollRequestTable};
use crate::{EXCLUSIVE, Map};

/// The byte that follows `0x00` to stand for a `0x00` byte of a string.
const ESCAPED_ZERO: u8 = 0xFF;
/// The byte that follows `0x00` to end a string.
const STRING_END: u8 = 0x00;
/// The sign bit of an `i64`, flipped so that its encoding sorts numerically.
const SIGN_BIT: u64 = 1 << 63;

/// A Giganto node, identified as its service row is elsewhere in `REview`:
/// by the host name and the instance number of Giganto on that host.
///
/// Nodes order by host name, in byte order, and then by instance, which is
/// the order in which every key that holds one sorts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SentaEndpointGigantoNode {
    /// The host name of the node.
    pub host: String,
    /// The instance number of Giganto on the host.
    pub instance: u32,
}

/// A row of one of the observation tables: how its key and value are
/// encoded and decoded.
trait Row: Sized {
    /// The name of the table's column family, which error messages give too.
    const TABLE: &'static str;

    /// Returns the encoded key of the row.
    fn key(&self) -> Vec<u8>;

    /// Returns the encoded value of the row.
    fn value(&self) -> Result<Vec<u8>>;

    /// Decodes the row stored under `key` with the value `value`.
    fn decode(key: &[u8], value: &[u8]) -> Result<Self>;
}

/// The column family of an observation table holding rows of type `R`.
struct Rows<'d, R> {
    map: Map<'d>,
    _row: PhantomData<R>,
}

impl<R> Clone for Rows<'_, R> {
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
            _row: PhantomData,
        }
    }
}

impl<'d, R: Row> Rows<'d, R> {
    /// Opens the column family of `R`, or returns `None` if it does not
    /// exist.
    fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, R::TABLE).map(|map| Self {
            map,
            _row: PhantomData,
        })
    }

    /// Returns the row stored under `key`, or `None` if there is none.
    fn get(&self, key: &[u8]) -> Result<Option<R>> {
        self.map
            .db
            .get_cf(self.map.cf, key)
            .with_context(|| format!("failed to read {}", R::TABLE))?
            .map(|value| decode::<R>(key, &value))
            .transpose()
    }

    /// Stores `row` under its key, replacing any row stored there.
    fn put(&self, row: &R) -> Result<()> {
        let value = row.value()?;
        self.map
            .db
            .put_cf(self.map.cf, row.key(), value)
            .with_context(|| format!("failed to write {}", R::TABLE))
    }

    /// Stores `row` under its key if no row is stored there, and returns
    /// whether it did; an existing row is left as it is.
    fn insert(&self, row: &R) -> Result<bool> {
        let key = row.key();
        let value = row.value()?;
        loop {
            let txn = self.map.db.transaction();
            if txn
                .get_for_update_cf(self.map.cf, &key, EXCLUSIVE)
                .with_context(|| format!("failed to read {}", R::TABLE))?
                .is_some()
            {
                return Ok(false);
            }
            txn.put_cf(self.map.cf, &key, &value)
                .with_context(|| format!("failed to write {}", R::TABLE))?;
            match txn.commit() {
                Ok(()) => return Ok(true),
                // A concurrent write of the key committed first; the next
                // round finds it.
                Err(e) if e.kind() == rocksdb::ErrorKind::Busy => {}
                Err(e) => return Err(e).with_context(|| format!("failed to write {}", R::TABLE)),
            }
        }
    }

    /// Deletes the row stored under `key`, if any.
    fn delete(&self, key: &[u8]) -> Result<()> {
        self.map
            .db
            .delete_cf(self.map.cf, key)
            .with_context(|| format!("failed to delete from {}", R::TABLE))
    }

    /// Deletes, in one write, every row whose key starts with `prefix`, and
    /// returns how many it deleted.
    fn delete_prefix(&self, prefix: &[u8]) -> Result<usize> {
        let mut batch = WriteBatchWithTransaction::<true>::default();
        let mut deleted = 0;
        for entry in self.raw_iter(prefix) {
            let (key, _) = entry.with_context(|| format!("failed to read {}", R::TABLE))?;
            batch.delete_cf(self.map.cf, key);
            deleted += 1;
        }
        self.map
            .db
            .write(batch)
            .with_context(|| format!("failed to delete from {}", R::TABLE))?;
        Ok(deleted)
    }

    /// Returns an iterator over the rows whose key starts with `prefix`, in
    /// key order; an empty prefix covers every row.
    fn iter(&self, prefix: &[u8]) -> impl Iterator<Item = Result<R>> + use<'d, R> {
        self.raw_iter(prefix).map(|entry| {
            let (key, value) = entry.with_context(|| format!("failed to read {}", R::TABLE))?;
            decode::<R>(&key, &value)
        })
    }

    /// Returns whether any row satisfies `matches`, scanning every row in
    /// key order.
    fn any(&self, mut matches: impl FnMut(&R) -> bool) -> Result<bool> {
        for row in self.iter(&[]) {
            if matches(&row?) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn raw_iter(
        &self,
        prefix: &[u8],
    ) -> rocksdb::DBIteratorWithThreadMode<'d, OptimisticTransactionDB> {
        if prefix.is_empty() {
            return self.map.db.iterator_cf(self.map.cf, IteratorMode::Start);
        }
        let mut opts = rocksdb::ReadOptions::default();
        opts.set_iterate_range(rocksdb::PrefixRange(prefix));
        self.map
            .db
            .iterator_cf_opt(self.map.cf, opts, IteratorMode::Start)
    }
}

/// Decodes the row of type `R` stored under `key` with the value `value`.
fn decode<R: Row>(key: &[u8], value: &[u8]) -> Result<R> {
    R::decode(key, value).with_context(|| {
        format!(
            "failed to decode {} row {}",
            R::TABLE,
            data_encoding::HEXLOWER.encode(key)
        )
    })
}

/// Builds a key from its components, in the encoding the module
/// documentation describes.
#[derive(Default)]
struct KeyWriter(Vec<u8>);

impl KeyWriter {
    fn uuid(mut self, id: Uuid) -> Self {
        self.0.extend_from_slice(id.as_bytes());
        self
    }

    fn u32(mut self, value: u32) -> Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    fn u64(mut self, value: u64) -> Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    fn i64(self, value: i64) -> Self {
        self.u64(u64::from_be_bytes(value.to_be_bytes()) ^ SIGN_BIT)
    }

    fn byte(mut self, value: u8) -> Self {
        self.0.push(value);
        self
    }

    fn str(mut self, value: &str) -> Self {
        for &byte in value.as_bytes() {
            if byte == 0 {
                self.0.extend_from_slice(&[0, ESCAPED_ZERO]);
            } else {
                self.0.push(byte);
            }
        }
        self.0.extend_from_slice(&[0, STRING_END]);
        self
    }

    fn node(self, node: &SentaEndpointGigantoNode) -> Self {
        self.str(&node.host).u32(node.instance)
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Reads the components of a key written by [`KeyWriter`], in order.
struct KeyReader<'a> {
    rest: &'a [u8],
}

impl<'a> KeyReader<'a> {
    fn new(key: &'a [u8]) -> Self {
        Self { rest: key }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, rest) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or_else(|| anyhow!("the key ends early"))?;
        self.rest = rest;
        Ok(*head)
    }

    fn uuid(&mut self) -> Result<Uuid> {
        Ok(Uuid::from_bytes(self.take()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes((self.u64()? ^ SIGN_BIT).to_be_bytes()))
    }

    fn byte(&mut self) -> Result<u8> {
        let [byte] = self.take()?;
        Ok(byte)
    }

    fn str(&mut self) -> Result<String> {
        let mut bytes = Vec::new();
        loop {
            match self.byte()? {
                0 => match self.byte()? {
                    STRING_END => break,
                    ESCAPED_ZERO => bytes.push(0),
                    other => return Err(anyhow!("invalid escape 0x00 0x{other:02x} in a string")),
                },
                byte => bytes.push(byte),
            }
        }
        String::from_utf8(bytes).context("a string in the key is not UTF-8")
    }

    fn node(&mut self) -> Result<SentaEndpointGigantoNode> {
        let host = self.str()?;
        let instance = self.u32()?;
        Ok(SentaEndpointGigantoNode { host, instance })
    }

    /// Checks that every byte of the key has been read.
    fn finish(self) -> Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(anyhow!("the key has {} trailing bytes", self.rest.len()))
        }
    }
}

/// Returns the key prefix of the rows of endpoint `endpoint_id`.
fn endpoint_prefix(endpoint_id: Uuid) -> Vec<u8> {
    KeyWriter::default().uuid(endpoint_id).finish()
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::Store;
    use crate::test::{DbGuard, acquire_db_permit};

    /// A store in a temporary directory, with the permit that limits how many
    /// tests hold a database at once.
    pub(super) struct TestStore {
        pub(super) store: Store,
        _permit: DbGuard<'static>,
        _dirs: (TempDir, TempDir),
    }

    impl TestStore {
        pub(super) fn new() -> Self {
            let permit = acquire_db_permit();
            let data = tempfile::tempdir().unwrap();
            let backup = tempfile::tempdir().unwrap();
            let store = Store::new(data.path(), backup.path(), None).unwrap();
            Self {
                store,
                _permit: permit,
                _dirs: (data, backup),
            }
        }
    }

    /// The column families of the observation tables.
    const OBSERVATION_TABLES: [&str; 8] = [
        crate::tables::SENTA_ACTIVE_LIST,
        crate::tables::SENTA_DOCUMENT_RESULTS,
        crate::tables::SENTA_ENDPOINT_EVENTS,
        crate::tables::SENTA_GIGANTO_ENTRIES,
        crate::tables::SENTA_GIGANTO_LAST_RECEIVED,
        crate::tables::SENTA_GIGANTO_LOSSES,
        crate::tables::SENTA_STATUS_REPORTS,
        crate::tables::SENTA_UNENROLL_REQUESTS,
    ];

    /// The endpoint id whose 16 bytes are all `n`.
    pub(super) fn endpoint(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    pub(super) fn node(host: &str, instance: u32) -> SentaEndpointGigantoNode {
        SentaEndpointGigantoNode {
            host: host.to_string(),
            instance,
        }
    }

    /// A store of the current format written by a build without the endpoint
    /// observation tables gets them, empty, when it opens, and keeps the rows
    /// it had.
    #[test]
    fn opening_a_store_without_the_tables_creates_them_empty() {
        let _permit = acquire_db_permit();
        let data = tempfile::tempdir().unwrap();
        let backup = tempfile::tempdir().unwrap();
        {
            let store = Store::new(data.path(), backup.path(), None).unwrap();
            let db = store.states.db();
            db.put_cf(db.cf_handle(crate::tables::HOSTS).unwrap(), b"kept", b"row")
                .unwrap();
            store
                .senta_endpoint_unenroll_request_map()
                .put(&SentaEndpointUnenrollRequest {
                    endpoint_id: endpoint(1),
                    received_at: 1,
                })
                .unwrap();
        }
        let states = data.path().join(crate::DEFAULT_STATES);
        {
            let mut db = rocksdb::DB::open_cf(
                &rocksdb::Options::default(),
                &states,
                crate::tables::MAP_NAMES,
            )
            .unwrap();
            for name in OBSERVATION_TABLES {
                db.drop_cf(name).unwrap();
            }
        }
        let families = rocksdb::DB::list_cf(&rocksdb::Options::default(), &states).unwrap();
        assert!(
            OBSERVATION_TABLES
                .iter()
                .all(|name| !families.iter().any(|family| family == name))
        );

        let store = Store::new(data.path(), backup.path(), None).unwrap();
        let families = rocksdb::DB::list_cf(&rocksdb::Options::default(), &states).unwrap();
        assert!(
            OBSERVATION_TABLES
                .iter()
                .all(|name| families.iter().any(|family| family == name))
        );
        assert_eq!(store.senta_endpoint_active_list_map().get().unwrap(), None);
        assert_eq!(store.senta_endpoint_giganto_entry_map().iter().count(), 0);
        assert_eq!(
            store.senta_endpoint_unenroll_request_map().iter().count(),
            0
        );
        assert_eq!(store.senta_endpoint_document_result_map().iter().count(), 0);
        assert_eq!(store.senta_endpoint_status_report_map().iter().count(), 0);
        assert_eq!(store.senta_endpoint_event_map().iter().count(), 0);
        assert_eq!(store.senta_endpoint_giganto_loss_map().iter().count(), 0);
        assert_eq!(
            store
                .senta_endpoint_giganto_last_received_map()
                .iter()
                .count(),
            0
        );
        let db = store.states.db();
        assert_eq!(
            db.get_cf(db.cf_handle(crate::tables::HOSTS).unwrap(), b"kept")
                .unwrap()
                .as_deref(),
            Some(b"row".as_slice())
        );
    }

    /// Concurrent inserts of one key store exactly one of the rows: one
    /// insert reports the write, every other reports none, and the stored
    /// row is the one whose insert reported it.
    #[test]
    fn concurrent_inserts_of_one_key_write_once() {
        const WRITERS: u8 = 8;

        let store = TestStore::new();
        let table = store.store.senta_endpoint_giganto_loss_map();
        let key = SentaEndpointGigantoLossKey {
            endpoint_id: endpoint(1),
            received_at: 1,
            node: node("a", 1),
            stream_id: endpoint(2),
            range_from: 0,
            range_to: 1,
            reason_code: "overflow".to_string(),
        };
        let barrier = std::sync::Barrier::new(usize::from(WRITERS));
        let written: Vec<SentaEndpointGigantoLoss> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..WRITERS)
                .map(|n| {
                    let loss = SentaEndpointGigantoLoss {
                        key: key.clone(),
                        reason_detail: format!("writer {n}"),
                        fetched_at: i64::from(n),
                    };
                    let table = table.clone();
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        table.insert(&loss).unwrap().then_some(loss)
                    })
                })
                .collect();
            handles
                .into_iter()
                .filter_map(|handle| handle.join().unwrap())
                .collect()
        });
        assert_eq!(written.len(), 1, "{written:?}");
        assert_eq!(table.get(&key).unwrap().as_ref(), written.first());
    }

    /// A stored row that does not decode is an error naming the table and
    /// the key, for a read by key and for an iteration alike.
    #[test]
    fn an_undecodable_row_is_an_error_naming_the_table() {
        let store = TestStore::new();
        let db = store.store.states.db();
        let cf = db
            .cf_handle(crate::tables::SENTA_UNENROLL_REQUESTS)
            .unwrap();
        let id = endpoint(1);
        db.put_cf(cf, endpoint_prefix(id), b"").unwrap();
        db.put_cf(cf, b"short", 1_i64.to_le_bytes()).unwrap();

        let table = store.store.senta_endpoint_unenroll_request_map();
        let error = format!("{:#}", table.get(id).unwrap_err());
        assert!(
            error.contains("senta unenroll requests")
                && error.contains(&data_encoding::HEXLOWER.encode(id.as_bytes())),
            "{error}"
        );
        let errors: Vec<String> = table
            .iter()
            .map(|row| format!("{:#}", row.unwrap_err()))
            .collect();
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(
            errors
                .iter()
                .any(|e| e.contains("senta unenroll requests") && e.contains("the key ends early")),
            "{errors:?}"
        );
    }

    fn encoded_str(value: &str) -> Vec<u8> {
        KeyWriter::default().str(value).finish()
    }

    #[test]
    fn strings_sort_in_byte_order_and_round_trip() {
        let mut values = vec![
            "", "\0", "\0\0", "a", "a\0", "a\0b", "a\x01", "ab", "b", "é",
        ];
        values.sort_unstable();
        let encoded: Vec<Vec<u8>> = values.iter().map(|v| encoded_str(v)).collect();
        let mut sorted = encoded.clone();
        sorted.sort_unstable();
        assert_eq!(encoded, sorted);
        for (value, bytes) in values.iter().zip(&encoded) {
            let mut reader = KeyReader::new(bytes);
            assert_eq!(reader.str().unwrap(), *value);
            reader.finish().unwrap();
        }
    }

    #[test]
    fn a_string_followed_by_more_components_does_not_collide() {
        // "a" then 1 must not equal "a\0" then anything, and must sort first.
        let one = KeyWriter::default().str("a").u32(u32::MAX).finish();
        let two = KeyWriter::default().str("a\0").u32(0).finish();
        assert_ne!(one, two);
        assert!(one < two);
    }

    #[test]
    fn integers_sort_numerically() {
        let signed = [i64::MIN, -256, -1, 0, 1, 255, 256, i64::MAX];
        let keys: Vec<Vec<u8>> = signed
            .iter()
            .map(|v| KeyWriter::default().i64(*v).finish())
            .collect();
        assert!(keys.windows(2).all(|pair| pair.first() < pair.last()));
        for (value, key) in signed.iter().zip(&keys) {
            let mut reader = KeyReader::new(key);
            assert_eq!(reader.i64().unwrap(), *value);
            reader.finish().unwrap();
        }

        let unsigned = [0, 1, 255, 256, 65_536, u64::MAX];
        let keys: Vec<Vec<u8>> = unsigned
            .iter()
            .map(|v| KeyWriter::default().u64(*v).finish())
            .collect();
        assert!(keys.windows(2).all(|pair| pair.first() < pair.last()));
    }

    #[test]
    fn malformed_keys_are_refused() {
        assert!(KeyReader::new(b"ab").str().is_err());
        assert!(KeyReader::new(b"a\0\x01").str().is_err());
        assert!(KeyReader::new(&[0xFF, 0, 0]).str().is_err());
        assert!(KeyReader::new(&[1, 2, 3]).u32().is_err());
        assert!(KeyReader::new(&[1]).finish().is_err());
    }
}
