//! The `senta giganto entries` table: the state of the endpoint entry of each
//! Giganto node.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use uuid::Uuid;

use super::{KeyReader, KeyWriter, Row, Rows, SentaEndpointGigantoNode};

/// The state of a Giganto node's endpoint entry, as `REview` keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentaEndpointGigantoEntry {
    /// The Giganto node, the key of the row.
    pub node: SentaEndpointGigantoNode,
    /// The id of the node's endpoint entry.
    pub entry_id: Uuid,
    /// The server name of the entry, as given.
    pub server_name: String,
    /// The host of the entry, as given.
    pub host: String,
    /// The version of the active list the node applied, if any.
    pub applied_version: Option<u64>,
    /// When the node last confirmed the entry, in nanoseconds since the Unix
    /// epoch, if ever.
    pub last_confirmed_at: Option<i64>,
    /// The received time, in nanoseconds since the Unix epoch, through which
    /// `REview` fetched the node's loss records, if it fetched any.
    pub losses_fetched_through: Option<i64>,
    /// The received time, in nanoseconds since the Unix epoch, through which
    /// `REview` fetched the node's endpoint events, if it fetched any.
    pub events_fetched_through: Option<i64>,
}

/// The stored value of a [`SentaEndpointGigantoEntry`]: every field but the
/// node.
type Value = (
    Uuid,
    String,
    String,
    Option<u64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

fn key(node: &SentaEndpointGigantoNode) -> Vec<u8> {
    KeyWriter::default().node(node).finish()
}

impl Row for SentaEndpointGigantoEntry {
    const TABLE: &'static str = crate::tables::SENTA_GIGANTO_ENTRIES;

    fn key(&self) -> Vec<u8> {
        key(&self.node)
    }

    fn value(&self) -> Result<Vec<u8>> {
        crate::tables::serialize(&(
            self.entry_id,
            &self.server_name,
            &self.host,
            self.applied_version,
            self.last_confirmed_at,
            self.losses_fetched_through,
            self.events_fetched_through,
        ))
    }

    fn decode(key: &[u8], value: &[u8]) -> Result<Self> {
        let mut reader = KeyReader::new(key);
        let node = reader.node()?;
        reader.finish()?;
        let (
            entry_id,
            server_name,
            host,
            applied_version,
            last_confirmed_at,
            losses_fetched_through,
            events_fetched_through,
        ): Value = crate::tables::deserialize(value)?;
        Ok(Self {
            node,
            entry_id,
            server_name,
            host,
            applied_version,
            last_confirmed_at,
            losses_fetched_through,
            events_fetched_through,
        })
    }
}

/// The `senta giganto entries` table, holding one
/// [`SentaEndpointGigantoEntry`] per Giganto node, in node order.
#[derive(Clone)]
pub struct SentaEndpointGigantoEntryTable<'d> {
    rows: Rows<'d, SentaEndpointGigantoEntry>,
}

impl<'d> SentaEndpointGigantoEntryTable<'d> {
    pub(crate) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Rows::open(db).map(|rows| Self { rows })
    }

    /// Returns the entry of `node`, or `None` if there is none.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row
    /// cannot be decoded.
    pub fn get(
        &self,
        node: &SentaEndpointGigantoNode,
    ) -> Result<Option<SentaEndpointGigantoEntry>> {
        self.rows.get(&key(node))
    }

    /// Stores `entry` under its node, replacing any entry stored there.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn put(&self, entry: &SentaEndpointGigantoEntry) -> Result<()> {
        self.rows.put(entry)
    }

    /// Deletes the entry of `node`, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, node: &SentaEndpointGigantoNode) -> Result<()> {
        self.rows.delete(&key(node))
    }

    /// Returns an iterator over every entry, by host name and then instance.
    pub fn iter(&self) -> impl Iterator<Item = Result<SentaEndpointGigantoEntry>> + 'd + use<'d> {
        self.rows.iter(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::senta_endpoint::tests::{TestStore, node};

    fn entry(host: &str, instance: u32) -> SentaEndpointGigantoEntry {
        SentaEndpointGigantoEntry {
            node: node(host, instance),
            entry_id: Uuid::from_bytes([7; 16]),
            server_name: format!("{instance:03}.giganto.{host}"),
            host: host.to_string(),
            applied_version: None,
            last_confirmed_at: None,
            losses_fetched_through: None,
            events_fetched_through: None,
        }
    }

    #[test]
    fn round_trips_with_and_without_optional_fields() {
        let store = TestStore::new();
        let table = store.store.senta_endpoint_giganto_entry_map();
        let bare = entry("a.example", 1);
        assert_eq!(table.get(&bare.node).unwrap(), None);
        table.put(&bare).unwrap();
        assert_eq!(table.get(&bare.node).unwrap(), Some(bare.clone()));

        let full = SentaEndpointGigantoEntry {
            applied_version: Some(9),
            last_confirmed_at: Some(-5),
            losses_fetched_through: Some(1_700_000_000_000_000_000),
            events_fetched_through: Some(i64::MAX),
            ..bare.clone()
        };
        table.put(&full).unwrap();
        assert_eq!(table.get(&bare.node).unwrap(), Some(full));

        table.delete(&bare.node).unwrap();
        assert_eq!(table.get(&bare.node).unwrap(), None);
    }

    #[test]
    fn iterates_by_host_name_then_numeric_instance() {
        let store = TestStore::new();
        let table = store.store.senta_endpoint_giganto_entry_map();
        let mut entries = vec![
            entry("b", 1),
            entry("a", 256),
            entry("ab", 0),
            entry("a", 2),
            entry("a", 1),
        ];
        for entry in &entries {
            table.put(entry).unwrap();
        }
        entries.sort_unstable_by(|x, y| x.node.cmp(&y.node));
        let all: Vec<_> = table.iter().collect::<Result<_>>().unwrap();
        assert_eq!(all, entries);
        assert_eq!(
            all.iter()
                .map(|e| (e.node.host.as_str(), e.node.instance))
                .collect::<Vec<_>>(),
            [("a", 1), ("a", 2), ("a", 256), ("ab", 0), ("b", 1)]
        );
    }
}
