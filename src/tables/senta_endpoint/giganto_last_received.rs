//! The `senta giganto last received` table: when each Giganto node last
//! received data from each endpoint.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use uuid::Uuid;

use super::{KeyReader, KeyWriter, Row, Rows, SentaEndpointGigantoNode, endpoint_prefix};

/// The key of a [`SentaEndpointGigantoLastReceived`].
///
/// Keys order by endpoint id and then node, which is the order the table
/// iterates in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SentaEndpointGigantoLastReceivedKey {
    /// The endpoint that sent the data.
    pub endpoint_id: Uuid,
    /// The node that received it.
    pub node: SentaEndpointGigantoNode,
}

impl SentaEndpointGigantoLastReceivedKey {
    fn encode(&self) -> Vec<u8> {
        KeyWriter::default()
            .uuid(self.endpoint_id)
            .node(&self.node)
            .finish()
    }
}

/// When a Giganto node last received data from an endpoint, as `REview`
/// fetched it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentaEndpointGigantoLastReceived {
    /// The key of the row.
    pub key: SentaEndpointGigantoLastReceivedKey,
    /// When the node last received data from the endpoint, in nanoseconds
    /// since the Unix epoch.
    pub last_received_at: i64,
    /// When `REview` fetched that time, in nanoseconds since the Unix epoch.
    pub fetched_at: i64,
}

impl Row for SentaEndpointGigantoLastReceived {
    const TABLE: &'static str = crate::tables::SENTA_GIGANTO_LAST_RECEIVED;

    fn key(&self) -> Vec<u8> {
        self.key.encode()
    }

    fn value(&self) -> Result<Vec<u8>> {
        crate::tables::serialize(&(self.last_received_at, self.fetched_at))
    }

    fn decode(key: &[u8], value: &[u8]) -> Result<Self> {
        let mut reader = KeyReader::new(key);
        let endpoint_id = reader.uuid()?;
        let node = reader.node()?;
        reader.finish()?;
        let (last_received_at, fetched_at) = crate::tables::deserialize(value)?;
        Ok(Self {
            key: SentaEndpointGigantoLastReceivedKey { endpoint_id, node },
            last_received_at,
            fetched_at,
        })
    }
}

/// The `senta giganto last received` table, holding one
/// [`SentaEndpointGigantoLastReceived`] per endpoint and node, in key order.
#[derive(Clone)]
pub struct SentaEndpointGigantoLastReceivedTable<'d> {
    rows: Rows<'d, SentaEndpointGigantoLastReceived>,
}

impl<'d> SentaEndpointGigantoLastReceivedTable<'d> {
    pub(crate) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Rows::open(db).map(|rows| Self { rows })
    }

    /// Returns the row stored under `key`, or `None` if there is none.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row
    /// cannot be decoded.
    pub fn get(
        &self,
        key: &SentaEndpointGigantoLastReceivedKey,
    ) -> Result<Option<SentaEndpointGigantoLastReceived>> {
        self.rows.get(&key.encode())
    }

    /// Stores `row` under its key, replacing any row stored there.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn put(&self, row: &SentaEndpointGigantoLastReceived) -> Result<()> {
        self.rows.put(row)
    }

    /// Deletes the row stored under `key`, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, key: &SentaEndpointGigantoLastReceivedKey) -> Result<()> {
        self.rows.delete(&key.encode())
    }

    /// Deletes every row of endpoint `endpoint_id`, and returns how many it
    /// deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete_endpoint(&self, endpoint_id: Uuid) -> Result<usize> {
        self.rows.delete_prefix(&endpoint_prefix(endpoint_id))
    }

    /// Returns an iterator over every row, in key order.
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = Result<SentaEndpointGigantoLastReceived>> + 'd + use<'d> {
        self.rows.iter(&[])
    }

    /// Returns an iterator over the rows of endpoint `endpoint_id`, by node.
    pub fn iter_endpoint(
        &self,
        endpoint_id: Uuid,
    ) -> impl Iterator<Item = Result<SentaEndpointGigantoLastReceived>> + 'd + use<'d> {
        self.rows.iter(&endpoint_prefix(endpoint_id))
    }

    /// Returns whether any row names `node`, scanning every row.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or a stored row
    /// cannot be decoded.
    pub fn names_node(&self, node: &SentaEndpointGigantoNode) -> Result<bool> {
        self.rows.any(|row| row.key.node == *node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::senta_endpoint::tests::{TestStore, endpoint, node};

    fn row(n: u8, host: &str, instance: u32) -> SentaEndpointGigantoLastReceived {
        SentaEndpointGigantoLastReceived {
            key: SentaEndpointGigantoLastReceivedKey {
                endpoint_id: endpoint(n),
                node: node(host, instance),
            },
            last_received_at: i64::from(instance),
            fetched_at: i64::from(n),
        }
    }

    #[test]
    fn round_trips_reads_and_deletes_by_endpoint() {
        let store = TestStore::new();
        let table = store.store.senta_endpoint_giganto_last_received_map();
        let one = [row(1, "a", 1), row(1, "a", 256), row(1, "b", 0)];
        let others = [row(0, "a", 1), row(2, "a", 1)];
        for row in [&one[2], &others[1], &one[1], &others[0], &one[0]] {
            table.put(row).unwrap();
        }
        assert_eq!(table.get(&one[1].key).unwrap(), Some(one[1].clone()));
        let replaced = SentaEndpointGigantoLastReceived {
            last_received_at: -1,
            fetched_at: 77,
            ..one[1].clone()
        };
        table.put(&replaced).unwrap();
        assert_eq!(table.get(&one[1].key).unwrap(), Some(replaced.clone()));

        let read: Vec<_> = table
            .iter_endpoint(endpoint(1))
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(read, [one[0].clone(), replaced, one[2].clone()]);

        assert_eq!(table.delete_endpoint(endpoint(1)).unwrap(), 3);
        let rest: Vec<_> = table.iter().collect::<Result<_>>().unwrap();
        assert_eq!(rest, others);
        table.delete(&others[0].key).unwrap();
        assert_eq!(table.get(&others[0].key).unwrap(), None);
    }

    #[test]
    fn names_node_finds_only_nodes_with_rows() {
        let store = TestStore::new();
        let table = store.store.senta_endpoint_giganto_last_received_map();
        assert!(!table.names_node(&node("a", 1)).unwrap());
        table.put(&row(1, "a", 1)).unwrap();
        table.put(&row(2, "ab", 2)).unwrap();
        assert!(table.names_node(&node("a", 1)).unwrap());
        assert!(table.names_node(&node("ab", 2)).unwrap());
        assert!(!table.names_node(&node("a", 2)).unwrap());
        assert!(!table.names_node(&node("ab", 1)).unwrap());
        assert!(!table.names_node(&node("b", 1)).unwrap());
        table.delete_endpoint(endpoint(1)).unwrap();
        assert!(!table.names_node(&node("a", 1)).unwrap());
    }
}
