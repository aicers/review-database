//! The `senta endpoint events` table: the `DuplicateKey` events of each
//! endpoint.

use anyhow::{Result, bail};
use rocksdb::OptimisticTransactionDB;
use uuid::Uuid;

use super::{KeyReader, KeyWriter, Row, Rows, SentaEndpointGigantoNode, endpoint_prefix};

/// The key byte of [`SentaEndpointEventSource::Review`].
const SOURCE_REVIEW: u8 = 0;
/// The key byte of [`SentaEndpointEventSource::Node`].
const SOURCE_NODE: u8 = 1;

/// Where an endpoint event was observed.
///
/// `Review` sorts before every node, and nodes sort by host name and then
/// instance.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SentaEndpointEventSource {
    /// `REview` itself observed the event.
    Review,
    /// The event was fetched from this Giganto node.
    Node(SentaEndpointGigantoNode),
}

/// The key of a [`SentaEndpointEvent`].
///
/// Keys order by endpoint id, then time, then source, then sequence, which is
/// the order the table iterates in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SentaEndpointEventKey {
    /// The endpoint the event is about.
    pub endpoint_id: Uuid,
    /// When the event happened, in nanoseconds since the Unix epoch.
    pub at: i64,
    /// Where the event was observed.
    pub source: SentaEndpointEventSource,
    /// For a node source, the sequence in that node's `endpoint_events` key;
    /// for the `REview` source, a counter `REview` assigns among its events
    /// of the same time.
    pub sequence: u64,
}

impl SentaEndpointEventKey {
    fn encode(&self) -> Vec<u8> {
        let writer = KeyWriter::default().uuid(self.endpoint_id).i64(self.at);
        let writer = match &self.source {
            SentaEndpointEventSource::Review => writer.byte(SOURCE_REVIEW),
            SentaEndpointEventSource::Node(node) => writer.byte(SOURCE_NODE).node(node),
        };
        writer.u64(self.sequence).finish()
    }

    fn decode(key: &[u8]) -> Result<Self> {
        let mut reader = KeyReader::new(key);
        let endpoint_id = reader.uuid()?;
        let at = reader.i64()?;
        let source = match reader.byte()? {
            SOURCE_REVIEW => SentaEndpointEventSource::Review,
            SOURCE_NODE => SentaEndpointEventSource::Node(reader.node()?),
            other => bail!("unknown event source 0x{other:02x}"),
        };
        let sequence = reader.u64()?;
        reader.finish()?;
        Ok(Self {
            endpoint_id,
            at,
            source,
            sequence,
        })
    }
}

/// A `DuplicateKey` event of an endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentaEndpointEvent {
    /// The key of the row.
    pub key: SentaEndpointEventKey,
    /// The SHA-256 hash of the subject public key info the event names.
    pub spki_hash: [u8; 32],
    /// The addresses the event names, as given.
    pub addresses: Vec<String>,
    /// The replacement count the event carries.
    pub replacement_count: u64,
    /// When `REview` fetched the event from its node, in nanoseconds since
    /// the Unix epoch; `None` for an event of the `REview` source.
    pub fetched_at: Option<i64>,
}

impl Row for SentaEndpointEvent {
    const TABLE: &'static str = crate::tables::SENTA_ENDPOINT_EVENTS;

    fn key(&self) -> Vec<u8> {
        self.key.encode()
    }

    fn value(&self) -> Result<Vec<u8>> {
        crate::tables::serialize(&(
            self.spki_hash,
            &self.addresses,
            self.replacement_count,
            self.fetched_at,
        ))
    }

    fn decode(key: &[u8], value: &[u8]) -> Result<Self> {
        let key = SentaEndpointEventKey::decode(key)?;
        let (spki_hash, addresses, replacement_count, fetched_at) =
            crate::tables::deserialize(value)?;
        Ok(Self {
            key,
            spki_hash,
            addresses,
            replacement_count,
            fetched_at,
        })
    }
}

/// The `senta endpoint events` table, holding one [`SentaEndpointEvent`] per
/// key, in key order.
///
/// An event is written only by [`insert`](Self::insert), which leaves an
/// existing row as it is.
#[derive(Clone)]
pub struct SentaEndpointEventTable<'d> {
    rows: Rows<'d, SentaEndpointEvent>,
}

impl<'d> SentaEndpointEventTable<'d> {
    pub(crate) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Rows::open(db).map(|rows| Self { rows })
    }

    /// Returns the event stored under `key`, or `None` if there is none.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row
    /// cannot be decoded.
    pub fn get(&self, key: &SentaEndpointEventKey) -> Result<Option<SentaEndpointEvent>> {
        self.rows.get(&key.encode())
    }

    /// Stores `event` under its key if no event is stored there, and returns
    /// whether it did. An event already stored under the key is left as it
    /// is, and `Ok(false)` is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn insert(&self, event: &SentaEndpointEvent) -> Result<bool> {
        self.rows.insert(event)
    }

    /// Deletes the event stored under `key`, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, key: &SentaEndpointEventKey) -> Result<()> {
        self.rows.delete(&key.encode())
    }

    /// Deletes every event of endpoint `endpoint_id`, and returns how many it
    /// deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete_endpoint(&self, endpoint_id: Uuid) -> Result<usize> {
        self.rows.delete_prefix(&endpoint_prefix(endpoint_id))
    }

    /// Returns an iterator over every event, in key order.
    pub fn iter(&self) -> impl Iterator<Item = Result<SentaEndpointEvent>> + 'd + use<'d> {
        self.rows.iter(&[])
    }

    /// Returns an iterator over the events of endpoint `endpoint_id`, by
    /// time, then source, then sequence.
    pub fn iter_endpoint(
        &self,
        endpoint_id: Uuid,
    ) -> impl Iterator<Item = Result<SentaEndpointEvent>> + 'd + use<'d> {
        self.rows.iter(&endpoint_prefix(endpoint_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::senta_endpoint::tests::{TestStore, endpoint, node};

    fn event(
        n: u8,
        at: i64,
        source: SentaEndpointEventSource,
        sequence: u64,
    ) -> SentaEndpointEvent {
        let fetched_at = match source {
            SentaEndpointEventSource::Review => None,
            SentaEndpointEventSource::Node(_) => Some(at + 1),
        };
        SentaEndpointEvent {
            key: SentaEndpointEventKey {
                endpoint_id: endpoint(n),
                at,
                source,
                sequence,
            },
            spki_hash: [n; 32],
            addresses: vec!["10.0.0.1".to_string(), "fe80::1".to_string()],
            replacement_count: sequence,
            fetched_at,
        }
    }

    fn from(host: &str, instance: u32) -> SentaEndpointEventSource {
        SentaEndpointEventSource::Node(node(host, instance))
    }

    #[test]
    fn iterates_by_time_then_review_first_then_node_then_sequence() {
        let store = TestStore::new();
        let table = store.store.senta_endpoint_event_map();
        let mut events = vec![
            event(1, 5, from("b", 1), 0),
            event(1, 5, from("a", 256), 0),
            event(1, 5, from("a", 2), 7),
            event(1, 5, from("a", 2), 256),
            event(1, 5, from("ab", 0), 0),
            event(1, 5, SentaEndpointEventSource::Review, 2),
            event(1, 5, SentaEndpointEventSource::Review, 1),
            event(1, -1, from("z", 9), 0),
            event(1, 256, SentaEndpointEventSource::Review, 0),
            event(1, 6, from("a", 1), u64::MAX),
        ];
        for event in &events {
            assert!(table.insert(event).unwrap());
        }
        events.sort_unstable_by(|x, y| x.key.cmp(&y.key));
        let stored: Vec<_> = table
            .iter_endpoint(endpoint(1))
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(stored, events);
        let order: Vec<_> = stored
            .iter()
            .map(|e| {
                let source = match &e.key.source {
                    SentaEndpointEventSource::Review => ("REview", 0),
                    SentaEndpointEventSource::Node(node) => (node.host.as_str(), node.instance),
                };
                (e.key.at, source, e.key.sequence)
            })
            .collect();
        assert_eq!(
            order,
            [
                (-1, ("z", 9), 0),
                (5, ("REview", 0), 1),
                (5, ("REview", 0), 2),
                (5, ("a", 2), 7),
                (5, ("a", 2), 256),
                (5, ("a", 256), 0),
                (5, ("ab", 0), 0),
                (5, ("b", 1), 0),
                (6, ("a", 1), u64::MAX),
                (256, ("REview", 0), 0),
            ]
        );
    }

    #[test]
    fn insert_leaves_an_existing_event_and_reports_no_write() {
        let store = TestStore::new();
        let table = store.store.senta_endpoint_event_map();
        let first = event(1, 5, from("a", 1), 3);
        assert_eq!(table.get(&first.key).unwrap(), None);
        assert!(table.insert(&first).unwrap());
        assert_eq!(table.get(&first.key).unwrap(), Some(first.clone()));

        let second = SentaEndpointEvent {
            spki_hash: [0xEE; 32],
            addresses: Vec::new(),
            replacement_count: 99,
            fetched_at: None,
            ..first.clone()
        };
        assert!(!table.insert(&second).unwrap());
        assert_eq!(table.get(&first.key).unwrap(), Some(first.clone()));

        table.delete(&first.key).unwrap();
        assert_eq!(table.get(&first.key).unwrap(), None);
        assert!(table.insert(&second).unwrap());
        assert_eq!(table.get(&first.key).unwrap(), Some(second));
    }

    #[test]
    fn reads_and_deletes_by_endpoint_leave_other_endpoints() {
        let store = TestStore::new();
        let table = store.store.senta_endpoint_event_map();
        let one = [
            event(1, 1, SentaEndpointEventSource::Review, 0),
            event(1, 2, from("a", 1), 0),
        ];
        let two = [
            event(2, 0, SentaEndpointEventSource::Review, 0),
            event(2, 1, from("a", 1), 0),
        ];
        let before = [event(0, 9, from("a", 1), 0)];
        for event in one.iter().chain(&two).chain(&before) {
            assert!(table.insert(event).unwrap());
        }
        let read: Vec<_> = table
            .iter_endpoint(endpoint(1))
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(read, one);

        assert_eq!(table.delete_endpoint(endpoint(1)).unwrap(), 2);
        assert_eq!(table.iter_endpoint(endpoint(1)).count(), 0);
        let rest: Vec<_> = table.iter().collect::<Result<_>>().unwrap();
        assert_eq!(rest, [before.as_slice(), two.as_slice()].concat());
    }
}
