//! The `access_token` map.

use anyhow::Result;
use rocksdb::OptimisticTransactionDB;

use super::TableIter;
use crate::{Iterable, Map, Table, types::FromKeyValue};

#[derive(Debug, PartialEq)]
pub struct AccessToken {
    pub username: String,
    pub token: String,
}

impl AccessToken {
    fn create_key_value(username: &str, token: &str) -> (Vec<u8>, Vec<u8>) {
        let mut key = username.as_bytes().to_owned();
        key.push(0);
        key.extend(token.as_bytes());
        (key, vec![])
    }
}

impl FromKeyValue for AccessToken {
    fn from_key_value(key: &[u8], _value: &[u8]) -> Result<Self> {
        use anyhow::anyhow;

        let sep = key
            .iter()
            .position(|c| *c == 0)
            .ok_or(anyhow!("corruptted access token"))?;
        let username = String::from_utf8_lossy(&key[..sep]).into_owned();
        let token = String::from_utf8_lossy(&key[sep + 1..]).into_owned();
        Ok(AccessToken { username, token })
    }
}

/// Functions for the `access_token` map.
impl<'d> Table<'d, AccessToken> {
    /// Opens the  `access_token` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::ACCESS_TOKENS).map(Table::new)
    }

    /// Inserts `(username, token)` into map in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn insert(&self, username: &str, token: &str) -> Result<()> {
        let (key, value) = AccessToken::create_key_value(username, token);
        self.map.insert(&key, &value)
    }

    /// Removes `(username, token)` from map in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the combo does not exist or the database operation fails.
    pub fn revoke(&self, username: &str, token: &str) -> Result<()> {
        let (key, _value) = AccessToken::create_key_value(username, token);

        self.map.delete(&key)
    }

    /// Finds whether `username` `token` exists in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn contains(&self, username: &str, token: &str) -> Result<bool> {
        let (key, _value) = AccessToken::create_key_value(username, token);
        self.map.get(&key).map(|v| v.is_some())
    }

    /// Finds all tokens for `username` in the database.
    #[must_use]
    pub fn tokens(&self, username: &str) -> TableIter<'_, AccessToken> {
        use rocksdb::Direction;

        let mut prefix = username.as_bytes().to_owned();
        prefix.push(0);
        self.prefix_iter(Direction::Forward, None, &prefix)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::Store;
    use crate::test::{DbGuard, acquire_db_permit};

    #[test]
    fn operations() {
        let (_permit, store) = setup_store();
        let table = store.access_token_map();
        let names = &["abc", "abcd", "def"];

        for (count, name) in names.iter().enumerate() {
            for i in 0..=count {
                assert!(table.insert(name, &i.to_string()).is_ok());
            }
        }

        for (count, name) in names.iter().enumerate() {
            assert_eq!(count + 1, table.tokens(name).count());
            for i in 0..=count {
                assert!(table.contains(name, &i.to_string()).unwrap());
            }
            assert!(table.revoke(name, &0.to_string()).is_ok());
            assert!(!table.contains(name, &0.to_string()).unwrap());
        }
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }
}
