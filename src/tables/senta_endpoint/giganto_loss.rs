//! The `senta giganto losses` table: the loss records `REview` fetched from
//! Giganto nodes.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use uuid::Uuid;

use super::{KeyReader, KeyWriter, Row, Rows, SentaEndpointGigantoNode, endpoint_prefix};

/// The key of a [`SentaEndpointGigantoLoss`].
///
/// Keys order by their fields in the order they are declared, each string in
/// byte order, which is the order the table iterates in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SentaEndpointGigantoLossKey {
    /// The endpoint whose data was lost.
    pub endpoint_id: Uuid,
    /// When the node received the loss record, in nanoseconds since the Unix
    /// epoch.
    pub received_at: i64,
    /// The node the record was fetched from.
    pub node: SentaEndpointGigantoNode,
    /// The stream the loss was in.
    pub stream_id: Uuid,
    /// The first sequence number of the lost range.
    pub range_from: u64,
    /// The last sequence number of the lost range.
    pub range_to: u64,
    /// The code of the reason for the loss, as given.
    pub reason_code: String,
}

impl SentaEndpointGigantoLossKey {
    fn encode(&self) -> Vec<u8> {
        KeyWriter::default()
            .uuid(self.endpoint_id)
            .i64(self.received_at)
            .node(&self.node)
            .uuid(self.stream_id)
            .u64(self.range_from)
            .u64(self.range_to)
            .str(&self.reason_code)
            .finish()
    }

    fn decode(key: &[u8]) -> Result<Self> {
        let mut reader = KeyReader::new(key);
        let decoded = Self {
            endpoint_id: reader.uuid()?,
            received_at: reader.i64()?,
            node: reader.node()?,
            stream_id: reader.uuid()?,
            range_from: reader.u64()?,
            range_to: reader.u64()?,
            reason_code: reader.str()?,
        };
        reader.finish()?;
        Ok(decoded)
    }
}

/// A loss record fetched from a Giganto node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentaEndpointGigantoLoss {
    /// The key of the row.
    pub key: SentaEndpointGigantoLossKey,
    /// The detail of the reason for the loss, as given.
    pub reason_detail: String,
    /// When `REview` fetched the record, in nanoseconds since the Unix epoch.
    pub fetched_at: i64,
}

impl Row for SentaEndpointGigantoLoss {
    const TABLE: &'static str = crate::tables::SENTA_GIGANTO_LOSSES;

    fn key(&self) -> Vec<u8> {
        self.key.encode()
    }

    fn value(&self) -> Result<Vec<u8>> {
        crate::tables::serialize(&(&self.reason_detail, self.fetched_at))
    }

    fn decode(key: &[u8], value: &[u8]) -> Result<Self> {
        let key = SentaEndpointGigantoLossKey::decode(key)?;
        let (reason_detail, fetched_at) = crate::tables::deserialize(value)?;
        Ok(Self {
            key,
            reason_detail,
            fetched_at,
        })
    }
}

/// The `senta giganto losses` table, holding one [`SentaEndpointGigantoLoss`]
/// per key, in key order.
///
/// A record is written only by [`insert`](Self::insert), which leaves an
/// existing row as it is.
#[derive(Clone)]
pub struct SentaEndpointGigantoLossTable<'d> {
    rows: Rows<'d, SentaEndpointGigantoLoss>,
}

impl<'d> SentaEndpointGigantoLossTable<'d> {
    pub(crate) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Rows::open(db).map(|rows| Self { rows })
    }

    /// Returns the record stored under `key`, or `None` if there is none.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row
    /// cannot be decoded.
    pub fn get(
        &self,
        key: &SentaEndpointGigantoLossKey,
    ) -> Result<Option<SentaEndpointGigantoLoss>> {
        self.rows.get(&key.encode())
    }

    /// Stores `loss` under its key if no record is stored there, and returns
    /// whether it did. A record already stored under the key is left as it
    /// is, and `Ok(false)` is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn insert(&self, loss: &SentaEndpointGigantoLoss) -> Result<bool> {
        self.rows.insert(loss)
    }

    /// Deletes the record stored under `key`, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, key: &SentaEndpointGigantoLossKey) -> Result<()> {
        self.rows.delete(&key.encode())
    }

    /// Deletes every record of endpoint `endpoint_id`, and returns how many
    /// it deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete_endpoint(&self, endpoint_id: Uuid) -> Result<usize> {
        self.rows.delete_prefix(&endpoint_prefix(endpoint_id))
    }

    /// Returns an iterator over every record, in key order.
    pub fn iter(&self) -> impl Iterator<Item = Result<SentaEndpointGigantoLoss>> + 'd + use<'d> {
        self.rows.iter(&[])
    }

    /// Returns an iterator over the records of endpoint `endpoint_id`, by
    /// received time and then the rest of the key.
    pub fn iter_endpoint(
        &self,
        endpoint_id: Uuid,
    ) -> impl Iterator<Item = Result<SentaEndpointGigantoLoss>> + 'd + use<'d> {
        self.rows.iter(&endpoint_prefix(endpoint_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::senta_endpoint::tests::{TestStore, endpoint, node};

    fn loss(
        n: u8,
        received_at: i64,
        host: &str,
        range_from: u64,
        code: &str,
    ) -> SentaEndpointGigantoLoss {
        SentaEndpointGigantoLoss {
            key: SentaEndpointGigantoLossKey {
                endpoint_id: endpoint(n),
                received_at,
                node: node(host, 1),
                stream_id: Uuid::from_bytes([9; 16]),
                range_from,
                range_to: range_from + 10,
                reason_code: code.to_string(),
            },
            reason_detail: format!("{code} detail"),
            fetched_at: received_at + 100,
        }
    }

    #[test]
    fn iterates_by_received_time_then_the_rest_of_the_key() {
        let store = TestStore::new();
        let table = store.store.senta_endpoint_giganto_loss_map();
        let mut losses = vec![
            loss(1, 256, "a", 0, "overflow"),
            loss(1, 1, "b", 0, "overflow"),
            loss(1, 1, "a", 256, "overflow"),
            loss(1, 1, "a", 2, "overflow"),
            loss(1, 1, "a", 2, "dropped"),
            loss(1, -7, "z", 0, "overflow"),
            loss(1, 2, "a", 0, ""),
        ];
        let mut other_stream = loss(1, 1, "a", 2, "dropped");
        other_stream.key.stream_id = Uuid::from_bytes([1; 16]);
        losses.push(other_stream);
        for loss in &losses {
            assert!(table.insert(loss).unwrap());
        }
        losses.sort_unstable_by(|x, y| x.key.cmp(&y.key));
        let stored: Vec<_> = table
            .iter_endpoint(endpoint(1))
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(stored, losses);
        assert_eq!(
            stored.iter().map(|l| l.key.received_at).collect::<Vec<_>>(),
            [-7, 1, 1, 1, 1, 1, 2, 256]
        );
        let at_one: Vec<_> = stored
            .iter()
            .filter(|l| l.key.received_at == 1)
            .map(|l| {
                (
                    l.key.node.host.as_str(),
                    l.key.stream_id.as_bytes()[0],
                    l.key.range_from,
                    l.key.reason_code.as_str(),
                )
            })
            .collect();
        assert_eq!(
            at_one,
            [
                ("a", 1, 2, "dropped"),
                ("a", 9, 2, "dropped"),
                ("a", 9, 2, "overflow"),
                ("a", 9, 256, "overflow"),
                ("b", 9, 0, "overflow"),
            ]
        );
    }

    #[test]
    fn insert_leaves_an_existing_record_and_reports_no_write() {
        let store = TestStore::new();
        let table = store.store.senta_endpoint_giganto_loss_map();
        let first = loss(1, 5, "a", 0, "overflow");
        assert_eq!(table.get(&first.key).unwrap(), None);
        assert!(table.insert(&first).unwrap());
        let second = SentaEndpointGigantoLoss {
            reason_detail: "another detail".to_string(),
            fetched_at: 0,
            ..first.clone()
        };
        assert!(!table.insert(&second).unwrap());
        assert_eq!(table.get(&first.key).unwrap(), Some(first.clone()));
        table.delete(&first.key).unwrap();
        assert_eq!(table.get(&first.key).unwrap(), None);
    }

    #[test]
    fn reads_and_deletes_by_endpoint_leave_other_endpoints() {
        let store = TestStore::new();
        let table = store.store.senta_endpoint_giganto_loss_map();
        let one = [loss(1, 1, "a", 0, "x"), loss(1, 2, "a", 0, "x")];
        let others = [loss(0, 3, "a", 0, "x"), loss(2, 0, "a", 0, "x")];
        for loss in one.iter().chain(&others) {
            assert!(table.insert(loss).unwrap());
        }
        let read: Vec<_> = table
            .iter_endpoint(endpoint(1))
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(read, one);
        assert_eq!(table.delete_endpoint(endpoint(1)).unwrap(), 2);
        let rest: Vec<_> = table.iter().collect::<Result<_>>().unwrap();
        assert_eq!(rest, others);
    }
}
