//! The `trusted_domain` table.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use super::Value;
use crate::{Map, Table, UniqueKey, types::FromKeyValue};

#[derive(Debug, Clone, PartialEq)]
pub struct TrustedDomain {
    pub name: String,
    pub remarks: String,
}

impl FromKeyValue for TrustedDomain {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self, anyhow::Error> {
        Ok(TrustedDomain {
            name: std::str::from_utf8(key)?.to_owned(),
            remarks: std::str::from_utf8(value)?.to_owned(),
        })
    }
}

impl UniqueKey for TrustedDomain {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl Value for TrustedDomain {
    type AsBytes<'a> = &'a [u8];

    fn value(&self) -> &[u8] {
        self.remarks.as_bytes()
    }
}

/// Functions for the `trusted_domain` map.
impl<'d> Table<'d, TrustedDomain> {
    /// Opens the  `trusted_domain` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::TRUSTED_DNS_SERVERS).map(Table::new)
    }

    /// Updates the `TrustedDomain` in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization fails or the database operation fails.
    pub fn update(&self, old: &TrustedDomain, new: &TrustedDomain) -> Result<()> {
        self.map.update(
            (old.unique_key(), old.value()),
            (new.unique_key(), new.value()),
        )
    }

    /// Removes a `TrustedDomain` with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn remove(&self, name: &str) -> Result<()> {
        self.map.delete(name.as_bytes())
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use rocksdb::Direction;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::types::FromKeyValue;
    use crate::{Iterable, Store, TrustedDomain};

    #[test]
    fn operations() {
        let (_permit, store) = setup_store();
        let table = store.trusted_domain_map();

        let a = create_entry("a");
        assert!(table.put(&a).is_ok());

        let b = create_entry("b");
        assert!(table.insert(&b).is_ok());

        assert_eq!(table.iter(Direction::Forward, None).count(), 2);
        assert!(table.remove(b.name.as_str()).is_ok());
        assert!(table.remove(a.name.as_str()).is_ok());
        assert_eq!(table.iter(Direction::Forward, None).count(), 0);
    }

    #[test]
    fn update_test() {
        let (_permit, store) = setup_store();
        let table = store.trusted_domain_map();
        let origin = create_entry("origin");
        assert!(table.put(&origin).is_ok());

        let updated = TrustedDomain {
            name: "updated".to_string(),
            remarks: "updated remarks".to_string(),
        };
        assert!(table.update(&origin, &updated).is_ok());

        let key = b"origin";
        let value = table.map.get(key).unwrap();
        assert!(value.is_none());

        let key = b"updated";
        let value = table.map.get(key).unwrap().unwrap();
        let update_in_table = TrustedDomain::from_key_value(key, value.as_ref()).unwrap();
        assert_eq!(updated, update_in_table);
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    fn create_entry(name: &str) -> TrustedDomain {
        TrustedDomain {
            name: name.to_string(),
            remarks: "remarks".to_string(),
        }
    }
}
