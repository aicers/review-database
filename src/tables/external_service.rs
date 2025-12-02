//! The external service table.

use std::mem::size_of;

use anyhow::Result;
use num_derive::{FromPrimitive, ToPrimitive};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use super::{ExternalServiceConfig, ExternalServiceStatus};
use crate::{Map, Table, UniqueKey, tables::Value as ValueTrait, types::FromKeyValue};

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    EnumString,
    FromPrimitive,
    ToPrimitive,
)]
#[repr(u32)]
#[strum(serialize_all = "snake_case")]
pub enum ExternalServiceKind {
    DataStore = 1,
    TiContainer = 2,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ExternalService {
    pub node: u32,
    pub key: String,
    pub kind: ExternalServiceKind,
    pub status: ExternalServiceStatus,
    pub draft: Option<ExternalServiceConfig>,
}

impl ExternalService {
    /// # Errors
    ///
    /// Returns an error if `config` fails to be `validate`-ed.
    pub fn new(
        node: u32,
        key: String,
        kind: ExternalServiceKind,
        status: ExternalServiceStatus,
        draft: Option<String>,
    ) -> Result<Self> {
        let draft = draft.map(TryInto::try_into).transpose()?;
        Ok(Self {
            node,
            key,
            kind,
            status,
            draft,
        })
    }
}

impl FromKeyValue for ExternalService {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let value: Value = super::deserialize(value)?;

        let (node, key) = key.split_at(size_of::<u32>());
        let mut buf = [0; size_of::<u32>()];
        buf.copy_from_slice(node);
        let node = u32::from_be_bytes(buf);
        let key = std::str::from_utf8(key)?.to_string();

        Ok(Self {
            node,
            key,
            kind: value.kind,
            status: value.status,
            draft: value.draft,
        })
    }
}

impl UniqueKey for ExternalService {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        let mut buf = self.node.to_be_bytes().to_vec();
        buf.extend(self.key.as_bytes());
        buf
    }
}

impl ValueTrait for ExternalService {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        let value = Value {
            kind: self.kind,
            status: self.status,
            draft: self.draft.clone(),
        };
        super::serialize(&value).expect("serializable")
    }
}

#[derive(Serialize, Deserialize)]
struct Value {
    kind: ExternalServiceKind,
    status: ExternalServiceStatus,
    draft: Option<ExternalServiceConfig>,
}

/// Functions for the external services table.
impl<'d> Table<'d, ExternalService> {
    /// Opens the `external services` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::EXTERNAL_SERVICES).map(Table::new)
    }

    /// Returns an external service with the given `node` and `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the external service does not exist or the database operation fails.
    pub fn get(&self, node: u32, id: &str) -> Result<Option<ExternalService>> {
        let mut key = node.to_be_bytes().to_vec();
        key.extend(id.as_bytes());
        let Some(value) = self.map.get(&key)? else {
            return Ok(None);
        };
        Ok(Some(ExternalService::from_key_value(&key, value.as_ref())?))
    }

    /// Deletes the external service with given `node` and `id`.
    ///
    /// # Errors
    ///
    /// Returns `None` if the table does not exist.
    pub fn delete(&self, node: u32, id: &str) -> Result<()> {
        let mut key = node.to_be_bytes().to_vec();
        key.extend(id.as_bytes());
        self.map.delete(&key)
    }

    /// Updates the `ExternalService` in the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization fails or the database operation fails.
    pub fn update(&self, old: &ExternalService, new: &ExternalService) -> Result<()> {
        let (ok, ov) = (old.unique_key(), old.value());
        let (nk, nv) = (new.unique_key(), new.value());
        self.map.update((&ok, &ov), (&nk, &nv))
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::*;
    use crate::Store;
    use crate::test::{DbGuard, acquire_db_permit};

    const VALID_TOML: &str = r#"test = "true""#;

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    fn create_external_service(
        node: u32,
        key: &str,
        kind: ExternalServiceKind,
        draft: Option<&str>,
    ) -> ExternalService {
        ExternalService::new(
            node,
            key.to_string(),
            kind,
            ExternalServiceStatus::Enabled,
            draft.map(ToString::to_string),
        )
        .unwrap()
    }

    #[test]
    fn external_service_creation() {
        let external_service = create_external_service(
            1,
            "test_key",
            ExternalServiceKind::DataStore,
            Some(VALID_TOML),
        );
        assert_eq!(external_service.node, 1);
        assert_eq!(external_service.key, "test_key");
        assert_eq!(external_service.kind, ExternalServiceKind::DataStore);
        assert_eq!(
            external_service.draft.as_ref().unwrap().as_ref(),
            VALID_TOML
        );

        let invalid = "invalid";
        assert!(
            ExternalService::new(
                1,
                "test_key".to_string(),
                ExternalServiceKind::DataStore,
                ExternalServiceStatus::Enabled,
                Some(invalid.to_string()),
            )
            .is_err()
        );
    }

    #[test]
    fn config_try_from() {
        let config = ExternalServiceConfig::try_from(VALID_TOML.to_string()).unwrap();
        assert_eq!(config.as_ref(), VALID_TOML);
    }

    #[test]
    fn serialization() {
        let external_service = create_external_service(
            1,
            "test_key",
            ExternalServiceKind::TiContainer,
            Some(VALID_TOML),
        );
        let serialized = external_service.value();
        let deserialized =
            ExternalService::from_key_value(&external_service.unique_key(), &serialized).unwrap();
        assert_eq!(external_service, deserialized);
    }

    #[test]
    fn operations() {
        let (_permit, store) = setup_store();
        let table = store.external_service_map();

        let external_service =
            create_external_service(1, "test_key", ExternalServiceKind::DataStore, None);

        // Insert and retrieve external service
        assert!(table.insert(&external_service).is_ok());
        let retrieved_external_service = table.get(1, "test_key").unwrap().unwrap();
        assert_eq!(external_service, retrieved_external_service);

        let new_toml = r#"another_test = "abc""#;
        // Update external service
        let updated_external_service = create_external_service(
            1,
            "test_key",
            ExternalServiceKind::TiContainer,
            Some(new_toml),
        );
        table
            .update(&external_service, &updated_external_service)
            .unwrap();
        let retrieved_updated_external_service = table.get(1, "test_key").unwrap().unwrap();
        assert_eq!(updated_external_service, retrieved_updated_external_service);

        // Delete external service
        table.delete(1, "test_key").unwrap();
        let result = table.get(1, "test_key").unwrap();
        assert!(result.is_none());
    }
}
