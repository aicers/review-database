//! The `senta status reports` table: the last status report of each
//! endpoint.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;
use uuid::Uuid;

use super::{KeyReader, Row, Rows, endpoint_prefix};

/// The last status report of an endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentaEndpointStatusReport {
    /// The endpoint that sent the report, the key of the row.
    pub endpoint_id: Uuid,
    /// The report, stored as given and not interpreted.
    pub report: String,
    /// When `REview` received the report, in nanoseconds since the Unix
    /// epoch.
    pub received_at: i64,
    /// The slot of the address document the report names, as its recovery
    /// epoch and version, if it names one.
    pub address_document_slot: Option<(u64, u64)>,
}

impl Row for SentaEndpointStatusReport {
    const TABLE: &'static str = crate::tables::SENTA_STATUS_REPORTS;

    fn key(&self) -> Vec<u8> {
        endpoint_prefix(self.endpoint_id)
    }

    fn value(&self) -> Result<Vec<u8>> {
        crate::tables::serialize(&(&self.report, self.received_at, self.address_document_slot))
    }

    fn decode(key: &[u8], value: &[u8]) -> Result<Self> {
        let mut reader = KeyReader::new(key);
        let endpoint_id = reader.uuid()?;
        reader.finish()?;
        let (report, received_at, address_document_slot) = crate::tables::deserialize(value)?;
        Ok(Self {
            endpoint_id,
            report,
            received_at,
            address_document_slot,
        })
    }
}

/// The `senta status reports` table, holding at most one
/// [`SentaEndpointStatusReport`] per endpoint, in endpoint id order.
#[derive(Clone)]
pub struct SentaEndpointStatusReportTable<'d> {
    rows: Rows<'d, SentaEndpointStatusReport>,
}

impl<'d> SentaEndpointStatusReportTable<'d> {
    pub(crate) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Rows::open(db).map(|rows| Self { rows })
    }

    /// Returns the report of endpoint `endpoint_id`, or `None` if there is
    /// none.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row
    /// cannot be decoded.
    pub fn get(&self, endpoint_id: Uuid) -> Result<Option<SentaEndpointStatusReport>> {
        self.rows.get(&endpoint_prefix(endpoint_id))
    }

    /// Stores `report` under its endpoint, replacing any report stored there.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn put(&self, report: &SentaEndpointStatusReport) -> Result<()> {
        self.rows.put(report)
    }

    /// Deletes the report of endpoint `endpoint_id`, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self, endpoint_id: Uuid) -> Result<()> {
        self.rows.delete(&endpoint_prefix(endpoint_id))
    }

    /// Deletes every row of endpoint `endpoint_id`, which is its report if it
    /// has one, and returns how many it deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete_endpoint(&self, endpoint_id: Uuid) -> Result<usize> {
        self.rows.delete_prefix(&endpoint_prefix(endpoint_id))
    }

    /// Returns an iterator over every report, by endpoint id.
    pub fn iter(&self) -> impl Iterator<Item = Result<SentaEndpointStatusReport>> + 'd + use<'d> {
        self.rows.iter(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::senta_endpoint::tests::{TestStore, endpoint};

    #[test]
    fn round_trips_with_and_without_a_slot_and_deletes_by_endpoint() {
        let store = TestStore::new();
        let table = store.store.senta_endpoint_status_report_map();
        let one = SentaEndpointStatusReport {
            endpoint_id: endpoint(1),
            report: "{\"opaque\": true}".to_string(),
            received_at: 5,
            address_document_slot: None,
        };
        let two = SentaEndpointStatusReport {
            endpoint_id: endpoint(2),
            report: String::new(),
            received_at: 6,
            address_document_slot: Some((3, u64::MAX)),
        };
        assert_eq!(table.get(one.endpoint_id).unwrap(), None);
        table.put(&one).unwrap();
        table.put(&two).unwrap();
        assert_eq!(table.get(one.endpoint_id).unwrap(), Some(one.clone()));
        assert_eq!(table.get(two.endpoint_id).unwrap(), Some(two.clone()));

        let replaced = SentaEndpointStatusReport {
            address_document_slot: Some((1, 2)),
            ..one.clone()
        };
        table.put(&replaced).unwrap();
        let all: Vec<_> = table.iter().collect::<Result<_>>().unwrap();
        assert_eq!(all, [replaced, two.clone()]);

        assert_eq!(table.delete_endpoint(one.endpoint_id).unwrap(), 1);
        assert_eq!(table.get(one.endpoint_id).unwrap(), None);
        assert_eq!(table.get(two.endpoint_id).unwrap(), Some(two.clone()));
        table.delete(two.endpoint_id).unwrap();
        assert_eq!(table.iter().count(), 0);
    }
}
