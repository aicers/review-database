//! The `tor_exit_node` table.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rocksdb::OptimisticTransactionDB;

use crate::{Map, Table, UniqueKey, types::FromKeyValue};

pub struct TorExitNode {
    pub ip_address: String,
    pub updated_at: DateTime<Utc>,
}

impl TorExitNode {
    fn into_key_value(self) -> (Vec<u8>, Vec<u8>) {
        (
            self.ip_address.into_bytes(),
            self.updated_at.to_string().into_bytes(),
        )
    }
}

impl UniqueKey for TorExitNode {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.ip_address.as_bytes()
    }
}

impl FromKeyValue for TorExitNode {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let ip_address =
            String::from_utf8(key.to_vec()).context("invalid IP address in database")?;
        let updated_at = String::from_utf8(value.to_vec())
            .context("invalid timestamp in database")?
            .parse()
            .context("invalid timestamp in database")?;
        Ok(TorExitNode {
            ip_address,
            updated_at,
        })
    }
}

/// Functions for the `tor_exit_node` map.
impl<'d> Table<'d, TorExitNode> {
    /// Opens the  `tor_exit_node` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::TOR_EXIT_NODES).map(Table::new)
    }

    /// Deletes all existing entries and add new IP address(es)
    ///
    /// # Errors
    ///
    /// Returns an error the database operation fails.
    pub fn replace_all(&self, entries: impl Iterator<Item = TorExitNode>) -> Result<()> {
        let data: Vec<_> = entries.map(TorExitNode::into_key_value).collect();
        let entries: Vec<_> = data
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect();
        self.map.replace_all(&entries)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use rocksdb::Direction;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Iterable, Store, TorExitNode};

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    #[test]
    fn operations() {
        let (_permit, store) = setup_store();
        let table = store.tor_exit_node_map();

        let t1 = Utc::now();
        let tester1 = TorExitNode {
            ip_address: "127.0.0.1".to_string(),
            updated_at: t1,
        };
        assert!(table.replace_all(std::iter::once(tester1)).is_ok());

        let iter = table.iter(Direction::Forward, None);
        assert_eq!(iter.count(), 1);

        let t2 = Utc::now();
        let tester2 = TorExitNode {
            ip_address: "1.0.0.127".to_string(),
            updated_at: t2,
        };
        assert!(table.replace_all(std::iter::once(tester2)).is_ok());

        let iter = table.iter(Direction::Forward, None);
        let entries: Result<Vec<_>, anyhow::Error> = iter.collect();
        assert!(entries.is_ok());
        let entries = entries.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(&entries[0].ip_address, "1.0.0.127");
        assert_eq!(entries[0].updated_at, t2);
    }
}
