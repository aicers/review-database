//! The `senta unenroll requests` table: the unenroll request of each
//! endpoint.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use uuid::Uuid;

use super::{KeyReader, Row, Rows, endpoint_prefix};

/// An unenroll request of an endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentaEndpointUnenrollRequest {
    /// The endpoint that asked to be unenrolled, the key of the row.
    pub endpoint_id: Uuid,
    /// When `REview` received the request, in nanoseconds since the Unix
    /// epoch.
    pub received_at: i64,
}

impl Row for SentaEndpointUnenrollRequest {
    const TABLE: &'static str = crate::tables::SENTA_UNENROLL_REQUESTS;

    fn key(&self) -> Vec<u8> {
        endpoint_prefix(self.endpoint_id)
    }

    fn value(&self) -> Result<Vec<u8>> {
        crate::tables::serialize(&self.received_at)
    }

    fn decode(key: &[u8], value: &[u8]) -> Result<Self> {
        let mut reader = KeyReader::new(key);
        let endpoint_id = reader.uuid()?;
        reader.finish()?;
        Ok(Self {
            endpoint_id,
            received_at: crate::tables::deserialize(value)?,
        })
    }
}

/// The `senta unenroll requests` table, holding at most one
/// [`SentaEndpointUnenrollRequest`] per endpoint, in endpoint id order.
#[derive(Clone)]
pub struct SentaEndpointUnenrollRequestTable<'d> {
    rows: Rows<'d, SentaEndpointUnenrollRequest>,
}

impl<'d> SentaEndpointUnenrollRequestTable<'d> {
    pub(crate) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Rows::open(db).map(|rows| Self { rows })
    }

    /// Returns the request of endpoint `endpoint_id`, or `None` if there is
    /// none.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row
    /// cannot be decoded.
    pub fn get(&self, endpoint_id: Uuid) -> Result<Option<SentaEndpointUnenrollRequest>> {
        self.rows.get(&endpoint_prefix(endpoint_id))
    }

    /// Stores `request` under its endpoint, replacing any request stored
    /// there.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn put(&self, request: &SentaEndpointUnenrollRequest) -> Result<()> {
        self.rows.put(request)
    }

    /// Deletes the request of endpoint `endpoint_id`, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, endpoint_id: Uuid) -> Result<()> {
        self.rows.delete(&endpoint_prefix(endpoint_id))
    }

    /// Deletes every row of endpoint `endpoint_id`, which is its request if
    /// it has one, and returns how many it deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete_endpoint(&self, endpoint_id: Uuid) -> Result<usize> {
        self.rows.delete_prefix(&endpoint_prefix(endpoint_id))
    }

    /// Returns an iterator over every request, by endpoint id.
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = Result<SentaEndpointUnenrollRequest>> + 'd + use<'d> {
        self.rows.iter(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::senta_endpoint::tests::{TestStore, endpoint};

    #[test]
    fn round_trips_and_deletes_by_endpoint() {
        let store = TestStore::new();
        let table = store.store.senta_endpoint_unenroll_request_map();
        let one = SentaEndpointUnenrollRequest {
            endpoint_id: endpoint(1),
            received_at: 10,
        };
        let two = SentaEndpointUnenrollRequest {
            endpoint_id: endpoint(2),
            received_at: -3,
        };
        assert_eq!(table.get(one.endpoint_id).unwrap(), None);
        table.put(&two).unwrap();
        table.put(&one).unwrap();
        assert_eq!(table.get(one.endpoint_id).unwrap(), Some(one.clone()));
        let replaced = SentaEndpointUnenrollRequest {
            received_at: 11,
            ..one.clone()
        };
        table.put(&replaced).unwrap();
        let all: Vec<_> = table.iter().collect::<Result<_>>().unwrap();
        assert_eq!(all, [replaced, two.clone()]);

        assert_eq!(table.delete_endpoint(one.endpoint_id).unwrap(), 1);
        assert_eq!(table.delete_endpoint(one.endpoint_id).unwrap(), 0);
        assert_eq!(table.get(one.endpoint_id).unwrap(), None);
        assert_eq!(table.get(two.endpoint_id).unwrap(), Some(two.clone()));

        table.delete(two.endpoint_id).unwrap();
        assert_eq!(table.iter().count(), 0);
    }
}
