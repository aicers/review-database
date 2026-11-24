//! The `senta document results` table: the last result each endpoint reported
//! for each document.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use uuid::Uuid;

use super::{KeyReader, KeyWriter, Row, Rows, endpoint_prefix};

/// The key of a [`SentaEndpointDocumentResult`].
///
/// Keys order by endpoint id, then `typ`, then target, each string in byte
/// order, which is the order the table iterates in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SentaEndpointDocumentResultKey {
    /// The endpoint that reported the result.
    pub endpoint_id: Uuid,
    /// The `typ` of the document, as the caller gives it; empty for a result
    /// that names no document.
    pub typ: String,
    /// The target of the document, as the caller gives it; empty for a
    /// result that names no document.
    pub target: String,
}

impl SentaEndpointDocumentResultKey {
    fn encode(&self) -> Vec<u8> {
        KeyWriter::default()
            .uuid(self.endpoint_id)
            .str(&self.typ)
            .str(&self.target)
            .finish()
    }
}

/// The last result an endpoint reported for a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentaEndpointDocumentResult {
    /// The key of the row.
    pub key: SentaEndpointDocumentResultKey,
    /// The version of the document the result is for, if the result names
    /// one.
    pub version: Option<u64>,
    /// The result, in the text form of the endpoint's `DocumentResult`;
    /// stored as given.
    pub result: String,
    /// When the result was reported, in nanoseconds since the Unix epoch.
    pub at: i64,
}

impl Row for SentaEndpointDocumentResult {
    const TABLE: &'static str = crate::tables::SENTA_DOCUMENT_RESULTS;

    fn key(&self) -> Vec<u8> {
        self.key.encode()
    }

    fn value(&self) -> Result<Vec<u8>> {
        crate::tables::serialize(&(self.version, &self.result, self.at))
    }

    fn decode(key: &[u8], value: &[u8]) -> Result<Self> {
        let mut reader = KeyReader::new(key);
        let endpoint_id = reader.uuid()?;
        let typ = reader.str()?;
        let target = reader.str()?;
        reader.finish()?;
        let (version, result, at) = crate::tables::deserialize(value)?;
        Ok(Self {
            key: SentaEndpointDocumentResultKey {
                endpoint_id,
                typ,
                target,
            },
            version,
            result,
            at,
        })
    }
}

/// The `senta document results` table, holding one
/// [`SentaEndpointDocumentResult`] per key, in key order.
#[derive(Clone)]
pub struct SentaEndpointDocumentResultTable<'d> {
    rows: Rows<'d, SentaEndpointDocumentResult>,
}

impl<'d> SentaEndpointDocumentResultTable<'d> {
    pub(crate) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Rows::open(db).map(|rows| Self { rows })
    }

    /// Returns the result stored under `key`, or `None` if there is none.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row
    /// cannot be decoded.
    pub fn get(
        &self,
        key: &SentaEndpointDocumentResultKey,
    ) -> Result<Option<SentaEndpointDocumentResult>> {
        self.rows.get(&key.encode())
    }

    /// Stores `result` under its key, replacing any result stored there.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn put(&self, result: &SentaEndpointDocumentResult) -> Result<()> {
        self.rows.put(result)
    }

    /// Deletes the result stored under `key`, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, key: &SentaEndpointDocumentResultKey) -> Result<()> {
        self.rows.delete(&key.encode())
    }

    /// Deletes every result of endpoint `endpoint_id`, and returns how many
    /// it deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete_endpoint(&self, endpoint_id: Uuid) -> Result<usize> {
        self.rows.delete_prefix(&endpoint_prefix(endpoint_id))
    }

    /// Returns an iterator over every result, in key order.
    pub fn iter(&self) -> impl Iterator<Item = Result<SentaEndpointDocumentResult>> + 'd + use<'d> {
        self.rows.iter(&[])
    }

    /// Returns an iterator over the results of endpoint `endpoint_id`, in key
    /// order.
    pub fn iter_endpoint(
        &self,
        endpoint_id: Uuid,
    ) -> impl Iterator<Item = Result<SentaEndpointDocumentResult>> + 'd + use<'d> {
        self.rows.iter(&endpoint_prefix(endpoint_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::senta_endpoint::tests::{TestStore, endpoint};

    fn result(n: u8, typ: &str, target: &str, version: Option<u64>) -> SentaEndpointDocumentResult {
        SentaEndpointDocumentResult {
            key: SentaEndpointDocumentResultKey {
                endpoint_id: endpoint(n),
                typ: typ.to_string(),
                target: target.to_string(),
            },
            version,
            result: format!("applied {typ}"),
            at: i64::from(n),
        }
    }

    #[test]
    fn round_trips_including_the_empty_key_and_reads_by_endpoint() {
        let store = TestStore::new();
        let table = store.store.senta_endpoint_document_result_map();
        let identity_less = result(1, "", "", None);
        let keyset = result(1, "keyset", "", Some(3));
        let address = result(1, "address", "eth0", Some(u64::MAX));
        let address_prefix = result(1, "address", "eth", Some(1));
        let other = result(2, "", "", Some(1));
        for row in [&keyset, &other, &address, &identity_less, &address_prefix] {
            table.put(row).unwrap();
        }

        assert_eq!(
            table.get(&identity_less.key).unwrap(),
            Some(identity_less.clone())
        );
        assert_eq!(table.get(&keyset.key).unwrap(), Some(keyset.clone()));
        let mut missing = keyset.key.clone();
        missing.target = "x".to_string();
        assert_eq!(table.get(&missing).unwrap(), None);

        let first: Vec<_> = table
            .iter_endpoint(endpoint(1))
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(
            first,
            [
                identity_less.clone(),
                address_prefix.clone(),
                address.clone(),
                keyset.clone()
            ]
        );
        let all: Vec<_> = table.iter().collect::<Result<_>>().unwrap();
        assert_eq!(
            all,
            [
                identity_less.clone(),
                address_prefix,
                address,
                keyset.clone(),
                other.clone()
            ]
        );

        let replaced = SentaEndpointDocumentResult {
            version: None,
            result: "rejected".to_string(),
            ..keyset.clone()
        };
        table.put(&replaced).unwrap();
        assert_eq!(table.get(&keyset.key).unwrap(), Some(replaced));

        table.delete(&identity_less.key).unwrap();
        assert_eq!(table.get(&identity_less.key).unwrap(), None);
        assert_eq!(table.delete_endpoint(endpoint(1)).unwrap(), 3);
        assert_eq!(table.iter_endpoint(endpoint(1)).count(), 0);
        let rest: Vec<_> = table.iter().collect::<Result<_>>().unwrap();
        assert_eq!(rest, [other]);
    }
}
