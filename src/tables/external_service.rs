//! The external service table.

use std::mem::size_of;

use anyhow::Result;
use num_derive::{FromPrimitive, ToPrimitive};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};
use strum_macros::EnumString;

use super::{ExternalServiceConfig, ExternalServiceStatus, Lifecycle};
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
    pub node_id: u32,
    pub key: String,
    pub kind: ExternalServiceKind,
    pub status: ExternalServiceStatus,
    pub draft: Option<ExternalServiceConfig>,
    /// The version of the build installed on the host, as the host reports it.
    ///
    /// An opaque display label, not required to be semver. Build identity is
    /// `(installed_version, installed_commit)`; the version alone does not
    /// identify a build.
    pub installed_version: Option<String>,
    /// The commit of the build installed on the host, as the host reports it.
    pub installed_commit: Option<String>,
    /// The install and run state of the build on the host.
    pub lifecycle: Lifecycle,
    /// The addresses this instance actually bound, as `(config key, host:port)`
    /// pairs reported by the host.
    ///
    /// Only the host knows where the instance ended up, and its first bind
    /// precedes its first configuration, so this is recorded rather than derived
    /// from `draft`. It is observed state, while `draft` carries intent; a later
    /// configuration edit must not rewrite what the host reported.
    pub bound_addrs: Vec<(String, String)>,
}

impl ExternalService {
    /// Creates a newly registered external service, with no build installed yet.
    ///
    /// `installed_version`, `installed_commit`, `lifecycle` and `bound_addrs`
    /// describe what a host reports, and registration precedes any report, so
    /// they start empty and [`Lifecycle::NotInstalled`] respectively. Install
    /// state is written afterwards by assigning to the fields of a record read
    /// back from the database.
    ///
    /// # Errors
    ///
    /// Returns an error if `config` fails to be `validate`-ed.
    pub fn new(
        node_id: u32,
        key: String,
        kind: ExternalServiceKind,
        status: ExternalServiceStatus,
        draft: Option<String>,
    ) -> Result<Self> {
        let draft = draft.map(TryInto::try_into).transpose()?;
        Ok(Self {
            node_id,
            key,
            kind,
            status,
            draft,
            installed_version: None,
            installed_commit: None,
            lifecycle: Lifecycle::NotInstalled,
            bound_addrs: Vec::new(),
        })
    }
}

impl FromKeyValue for ExternalService {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let value: Value = super::deserialize(value)?;

        let (node_id, key) = key.split_at(size_of::<u32>());
        let mut buf = [0; size_of::<u32>()];
        buf.copy_from_slice(node_id);
        let node_id = u32::from_be_bytes(buf);
        let key = std::str::from_utf8(key)?.to_string();

        Ok(Self {
            node_id,
            key,
            kind: value.kind,
            status: value.status,
            draft: value.draft,
            installed_version: value.installed_version,
            installed_commit: value.installed_commit,
            lifecycle: Lifecycle::from_stored_index(value.lifecycle),
            bound_addrs: value.bound_addrs,
        })
    }
}

impl UniqueKey for ExternalService {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        let mut buf = self.node_id.to_be_bytes().to_vec();
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
            installed_version: self.installed_version.clone(),
            installed_commit: self.installed_commit.clone(),
            lifecycle: self.lifecycle.to_stored_index(),
            bound_addrs: self.bound_addrs.clone(),
        };
        super::serialize(&value).expect("serializable")
    }
}

/// The persisted form of an [`ExternalService`].
///
/// `lifecycle` is the [`Lifecycle`] variant index rather than the enum itself:
/// a derived enum field fails the whole row when it meets a variant index this
/// build does not know, whereas a `u8` reads back and resolves to
/// [`Lifecycle::Unknown`]. The bytes are the same either way.
#[derive(Serialize, Deserialize)]
struct Value {
    kind: ExternalServiceKind,
    status: ExternalServiceStatus,
    draft: Option<ExternalServiceConfig>,
    installed_version: Option<String>,
    installed_commit: Option<String>,
    lifecycle: u8,
    bound_addrs: Vec<(String, String)>,
}

/// Functions for the external services table.
impl<'d> Table<'d, ExternalService> {
    /// Opens the `external services` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::EXTERNAL_SERVICES).map(Table::new)
    }

    /// Returns the underlying map, so a test can write bytes this crate would
    /// never produce — a record from a build that knows more lifecycle values
    /// than this one.
    #[cfg(test)]
    pub(crate) fn raw(&self) -> &Map<'_> {
        &self.map
    }

    /// Returns an external service with the given `node_id` and `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the external service does not exist or the database operation fails.
    pub fn get(&self, node_id: u32, id: &str) -> Result<Option<ExternalService>> {
        let mut key = node_id.to_be_bytes().to_vec();
        key.extend(id.as_bytes());
        let Some(value) = self.map.get(&key)? else {
            return Ok(None);
        };
        Ok(Some(ExternalService::from_key_value(&key, value.as_ref())?))
    }

    /// Deletes the external service with given `node_id` and `id`.
    ///
    /// # Errors
    ///
    /// Returns `None` if the table does not exist.
    pub fn delete(&self, node_id: u32, id: &str) -> Result<()> {
        let mut key = node_id.to_be_bytes().to_vec();
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
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path(), None).unwrap());
        (permit, store)
    }

    fn create_external_service(
        node_id: u32,
        key: &str,
        kind: ExternalServiceKind,
        draft: Option<&str>,
    ) -> ExternalService {
        ExternalService::new(
            node_id,
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
        assert_eq!(external_service.node_id, 1);
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

    #[test]
    fn new_external_service_has_no_install_state() {
        let external_service = create_external_service(
            1,
            "test_key",
            ExternalServiceKind::DataStore,
            Some(VALID_TOML),
        );
        assert_eq!(external_service.installed_version, None);
        assert_eq!(external_service.installed_commit, None);
        assert_eq!(external_service.lifecycle, Lifecycle::NotInstalled);
        assert!(external_service.bound_addrs.is_empty());
    }

    #[test]
    fn install_state_round_trips() {
        let empty = create_external_service(
            1,
            "test_key",
            ExternalServiceKind::DataStore,
            Some(VALID_TOML),
        );
        let restored =
            ExternalService::from_key_value(&empty.unique_key(), &empty.value()).unwrap();
        assert_eq!(empty, restored);

        let mut populated = empty;
        populated.installed_version = Some("1.2.3".to_string());
        populated.installed_commit = Some("0123456789abcdef".to_string());
        populated.lifecycle = Lifecycle::Running;
        populated.bound_addrs = vec![
            ("ingest_srv_addr".to_string(), "10.0.0.1:38370".to_string()),
            ("publish_srv_addr".to_string(), "10.0.0.1:38371".to_string()),
            ("graphql_srv_addr".to_string(), "[::1]:8442".to_string()),
        ];
        let restored =
            ExternalService::from_key_value(&populated.unique_key(), &populated.value()).unwrap();
        assert_eq!(populated, restored);
        // The reported order is preserved.
        assert_eq!(restored.bound_addrs, populated.bound_addrs);
    }

    #[test]
    fn every_lifecycle_round_trips_on_a_record() {
        let external_service =
            create_external_service(1, "test_key", ExternalServiceKind::DataStore, None);
        for lifecycle in [
            Lifecycle::NotInstalled,
            Lifecycle::Installing,
            Lifecycle::Running,
            Lifecycle::Stopped,
            Lifecycle::Failed,
            Lifecycle::Removing,
            Lifecycle::Unknown,
        ] {
            let mut external_service = external_service.clone();
            external_service.lifecycle = lifecycle;
            let restored = ExternalService::from_key_value(
                &external_service.unique_key(),
                &external_service.value(),
            )
            .unwrap();
            assert_eq!(restored.lifecycle, lifecycle);
        }
    }

    /// `status` and `lifecycle` are orthogonal: a config reload may have failed
    /// on a service that is up.
    #[test]
    fn status_and_lifecycle_are_independent() {
        let mut external_service =
            create_external_service(1, "test_key", ExternalServiceKind::DataStore, None);
        external_service.status = ExternalServiceStatus::ReloadFailed;
        external_service.lifecycle = Lifecycle::Running;
        let restored = ExternalService::from_key_value(
            &external_service.unique_key(),
            &external_service.value(),
        )
        .unwrap();
        assert_eq!(restored.status, ExternalServiceStatus::ReloadFailed);
        assert_eq!(restored.lifecycle, Lifecycle::Running);
    }

    /// A row carrying a lifecycle number this build does not know stays
    /// readable: it reads back as `Unknown`, with every other field intact.
    ///
    /// This is what fails if the persisted field is ever changed back to the
    /// `Lifecycle` type — the row would then error with `invalid value: integer
    /// 9, expected variant index 0 <= i < 7`.
    #[test]
    fn forged_lifecycle_number_still_deserializes() {
        let forged = Value {
            kind: ExternalServiceKind::TiContainer,
            status: ExternalServiceStatus::ReloadFailed,
            draft: Some(VALID_TOML.to_string().try_into().unwrap()),
            installed_version: Some("1.2.3".to_string()),
            installed_commit: Some("cafebabe".to_string()),
            lifecycle: 9,
            bound_addrs: vec![("addr".to_string(), "127.0.0.1:1111".to_string())],
        };
        let serialized = super::super::serialize(&forged).unwrap();

        let mut key = 1_u32.to_be_bytes().to_vec();
        key.extend(b"test_key");
        let external_service = ExternalService::from_key_value(&key, &serialized).unwrap();

        assert_eq!(external_service.lifecycle, Lifecycle::Unknown);
        assert_ne!(external_service.lifecycle, Lifecycle::NotInstalled);
        assert_eq!(external_service.kind, ExternalServiceKind::TiContainer);
        assert_eq!(external_service.status, ExternalServiceStatus::ReloadFailed);
        assert_eq!(
            external_service.draft.as_ref().unwrap().as_ref(),
            VALID_TOML
        );
        assert_eq!(external_service.installed_version.as_deref(), Some("1.2.3"));
        assert_eq!(
            external_service.installed_commit.as_deref(),
            Some("cafebabe")
        );
        assert_eq!(
            external_service.bound_addrs,
            vec![("addr".to_string(), "127.0.0.1:1111".to_string())]
        );
    }

    /// Storing the variant index in a `u8` is a representation choice, not a
    /// format change: the bytes are what a derived enum field would write.
    #[test]
    fn raw_index_is_byte_identical_to_a_derived_enum_field() {
        #[derive(Serialize)]
        struct ValueWithEnum {
            kind: ExternalServiceKind,
            status: ExternalServiceStatus,
            draft: Option<ExternalServiceConfig>,
            installed_version: Option<String>,
            installed_commit: Option<String>,
            lifecycle: Lifecycle,
            bound_addrs: Vec<(String, String)>,
        }

        for lifecycle in [
            Lifecycle::NotInstalled,
            Lifecycle::Installing,
            Lifecycle::Running,
            Lifecycle::Stopped,
            Lifecycle::Failed,
            Lifecycle::Removing,
            Lifecycle::Unknown,
        ] {
            let raw = Value {
                kind: ExternalServiceKind::DataStore,
                status: ExternalServiceStatus::Enabled,
                draft: Some(VALID_TOML.to_string().try_into().unwrap()),
                installed_version: Some("1.2.3".to_string()),
                installed_commit: None,
                lifecycle: lifecycle.to_stored_index(),
                bound_addrs: vec![("addr".to_string(), "127.0.0.1:1111".to_string())],
            };
            let with_enum = ValueWithEnum {
                kind: raw.kind,
                status: raw.status,
                draft: raw.draft.clone(),
                installed_version: raw.installed_version.clone(),
                installed_commit: raw.installed_commit.clone(),
                lifecycle,
                bound_addrs: raw.bound_addrs.clone(),
            };
            assert_eq!(
                super::super::serialize(&raw).unwrap(),
                super::super::serialize(&with_enum).unwrap()
            );
        }
    }

    #[test]
    fn table_operations_preserve_install_state() {
        let (_permit, store) = setup_store();
        let table = store.external_service_map();

        let mut external_service = create_external_service(
            1,
            "001.giganto",
            ExternalServiceKind::DataStore,
            Some(VALID_TOML),
        );
        external_service.installed_version = Some("1.2.3".to_string());
        external_service.installed_commit = Some("deadbeef".to_string());
        external_service.lifecycle = Lifecycle::Installing;
        external_service.bound_addrs =
            vec![("ingest_srv_addr".to_string(), "10.0.0.1:38370".to_string())];
        table.insert(&external_service).unwrap();
        assert_eq!(
            table.get(1, "001.giganto").unwrap().unwrap(),
            external_service
        );

        // Update only `lifecycle`.
        let mut running = external_service.clone();
        running.lifecycle = Lifecycle::Running;
        table.update(&external_service, &running).unwrap();
        let stored = table.get(1, "001.giganto").unwrap().unwrap();
        assert_eq!(stored, running);
        assert_eq!(stored.lifecycle, Lifecycle::Running);
        assert_eq!(stored.installed_commit.as_deref(), Some("deadbeef"));

        // Update only `installed_commit`.
        let mut rebuilt = running.clone();
        rebuilt.installed_commit = Some("feedface".to_string());
        table.update(&running, &rebuilt).unwrap();
        let stored = table.get(1, "001.giganto").unwrap().unwrap();
        assert_eq!(stored, rebuilt);
        assert_eq!(stored.installed_commit.as_deref(), Some("feedface"));
        assert_eq!(stored.lifecycle, Lifecycle::Running);
        assert_eq!(
            stored.bound_addrs,
            vec![("ingest_srv_addr".to_string(), "10.0.0.1:38370".to_string())]
        );

        table.delete(1, "001.giganto").unwrap();
        assert!(table.get(1, "001.giganto").unwrap().is_none());
    }
}
