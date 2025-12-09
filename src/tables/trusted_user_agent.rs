//! The `trusted_user_agent` map.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rocksdb::OptimisticTransactionDB;

use super::Value;
use crate::{Map, Table, UniqueKey, types::FromKeyValue};

pub struct TrustedUserAgent {
    pub user_agent: String,
    pub updated_at: DateTime<Utc>,
}

impl FromKeyValue for TrustedUserAgent {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let user_agent = std::str::from_utf8(key)
            .context("invalid user-agent in database")?
            .to_owned();
        let updated_at = std::str::from_utf8(value)
            .context("invalid timestamp in database")?
            .parse()
            .context("invalid timestamp in database")?;
        Ok(TrustedUserAgent {
            user_agent,
            updated_at,
        })
    }
}

impl UniqueKey for TrustedUserAgent {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.user_agent.as_bytes()
    }
}

impl Value for TrustedUserAgent {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        self.updated_at.to_string().into_bytes()
    }
}

/// Functions for the `trusted_user_agent` map.
impl<'d> Table<'d, TrustedUserAgent> {
    /// Opens the  `trusted_user_agent` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::TRUSTED_USER_AGENTS).map(Table::new)
    }

    /// Removes a `trusted_user_agent` with the given name.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn remove(&self, name: &str) -> Result<()> {
        self.map.delete(name.as_bytes())
    }

    /// Update a `trusted_user_agent`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn update(&self, old: &str, new: &TrustedUserAgent) -> Result<()> {
        let Some(value) = self.map.get(old.as_bytes())? else {
            return Err(anyhow::anyhow!("{old} doesn't exist in database"));
        };

        self.map.update(
            (old.as_bytes(), value.as_ref()),
            (new.unique_key(), &new.value()),
        )
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use anyhow::Result;
    use chrono::Utc;
    use rocksdb::Direction;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Iterable, Store, TrustedUserAgent};

    #[test]
    fn operations() {
        let (_permit, store) = setup_store();
        let table = store.trusted_user_agent_map();

        let a = create_entry("a");
        assert!(table.put(&a).is_ok());

        let b = create_entry("b");
        assert!(table.insert(&b).is_ok());

        let c = create_entry("c");
        assert!(table.update("b", &a).is_err());
        assert!(table.update("d", &a).is_err());
        assert!(table.update("b", &c).is_ok());

        assert_eq!(table.iter(Direction::Forward, None).count(), 2);
        assert_eq!(
            table
                .iter(Direction::Forward, None)
                .collect::<Result<Vec<_>>>()
                .unwrap()
                .into_iter()
                .map(|u| u.user_agent)
                .collect::<Vec<_>>(),
            vec!["a".to_string(), "c".to_string()]
        );

        assert!(table.remove(a.user_agent.as_str()).is_ok());
        assert!(table.remove(c.user_agent.as_str()).is_ok());
        assert_eq!(table.iter(Direction::Forward, None).count(), 0);
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    fn create_entry(name: &str) -> TrustedUserAgent {
        TrustedUserAgent {
            user_agent: name.to_string(),
            updated_at: Utc::now(),
        }
    }
}
