//! The `senta active list` table: the active list `REview` applied.

use anyhow::{Result, bail};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Row, Rows};

/// The key of the table's single row.
const KEY: &[u8] = b"active list";

/// One entry of the active list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentaEndpointActiveListEntry {
    /// The endpoint the entry names.
    pub endpoint_id: Uuid,
    /// The SHA-256 hash of the endpoint's subject public key info.
    pub spki_hash: [u8; 32],
    /// The customer endpoint id of the endpoint's customer.
    pub customer_endpoint_id: Uuid,
    /// The state of the entry, in `REview`'s text form, including a
    /// suspension reason; stored as given.
    pub state: String,
}

/// The active list `REview` applied: its version and its entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentaEndpointActiveList {
    /// The version of the list.
    pub version: u64,
    /// The entries of the list, in the order they were given.
    pub entries: Vec<SentaEndpointActiveListEntry>,
}

impl Row for SentaEndpointActiveList {
    const TABLE: &'static str = crate::tables::SENTA_ACTIVE_LIST;

    fn key(&self) -> Vec<u8> {
        KEY.to_vec()
    }

    fn value(&self) -> Result<Vec<u8>> {
        crate::tables::serialize(&(self.version, &self.entries))
    }

    fn decode(key: &[u8], value: &[u8]) -> Result<Self> {
        if key != KEY {
            bail!("the key is not that of the active list");
        }
        let (version, entries) = crate::tables::deserialize(value)?;
        Ok(Self { version, entries })
    }
}

/// The `senta active list` table, holding at most one
/// [`SentaEndpointActiveList`]: the one `REview` applied last.
#[derive(Clone)]
pub struct SentaEndpointActiveListTable<'d> {
    rows: Rows<'d, SentaEndpointActiveList>,
}

impl<'d> SentaEndpointActiveListTable<'d> {
    pub(crate) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Rows::open(db).map(|rows| Self { rows })
    }

    /// Returns the stored active list, or `None` if there is none.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails or the stored row
    /// cannot be decoded.
    pub fn get(&self) -> Result<Option<SentaEndpointActiveList>> {
        self.rows.get(KEY)
    }

    /// Replaces the stored active list with `list`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn put(&self, list: &SentaEndpointActiveList) -> Result<()> {
        self.rows.put(list)
    }

    /// Deletes the stored active list, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete(&self) -> Result<()> {
        self.rows.delete(KEY)
    }

    /// Returns an iterator over the stored rows, which is the active list if
    /// there is one and nothing otherwise.
    pub fn iter(&self) -> impl Iterator<Item = Result<SentaEndpointActiveList>> + 'd + use<'d> {
        self.rows.iter(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::senta_endpoint::tests::TestStore;

    fn entry(n: u8, state: &str) -> SentaEndpointActiveListEntry {
        SentaEndpointActiveListEntry {
            endpoint_id: Uuid::from_bytes([n; 16]),
            spki_hash: [n.wrapping_add(0x80); 32],
            customer_endpoint_id: Uuid::from_bytes([n.wrapping_add(1); 16]),
            state: state.to_string(),
        }
    }

    #[test]
    fn put_replaces_the_single_row_and_round_trips() {
        let store = TestStore::new();
        let table = store.store.senta_endpoint_active_list_map();
        assert_eq!(table.get().unwrap(), None);
        assert_eq!(table.iter().count(), 0);

        let first = SentaEndpointActiveList {
            version: 1,
            entries: vec![entry(1, "active"), entry(2, "suspended: lost key")],
        };
        table.put(&first).unwrap();
        assert_eq!(table.get().unwrap(), Some(first));

        let second = SentaEndpointActiveList {
            version: u64::MAX,
            entries: vec![entry(3, "")],
        };
        table.put(&second).unwrap();
        assert_eq!(table.get().unwrap(), Some(second.clone()));
        let all: Vec<_> = table.iter().collect::<Result<_>>().unwrap();
        assert_eq!(all, [second]);

        let empty = SentaEndpointActiveList {
            version: 0,
            entries: Vec::new(),
        };
        table.put(&empty).unwrap();
        assert_eq!(table.get().unwrap(), Some(empty));

        table.delete().unwrap();
        assert_eq!(table.get().unwrap(), None);
    }
}
