//! The `system log collectors` table.
//!
//! Each row records the operational-log collector `REview` owns on one host —
//! the host's system instance — keyed by the host alone. The instance belongs
//! to the host rather than to a node or a customer, so it is not an agent row.

use std::collections::HashSet;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use rocksdb::{IteratorMode, OptimisticTransactionDB, Transaction};
use serde::{Deserialize, Serialize};

use super::operation_attempt::is_uuid_v4;
use crate::{EXCLUSIVE, Map};

/// The operational-log collector `REview` owns on one host (RFC 0002 §4.9).
///
/// The collector belongs to the host: the row has no customer and no node.
///
/// Build identity is `(installed_version, installed_commit)`; the two are
/// either both set or both `None`.
///
/// The table validates nothing about `host`, `data_store` or `config`; it
/// stores what it is given.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemLogCollector {
    /// The host, in the `host.domain` form a node profile's `hostname` and a
    /// SAN's last labels use.
    pub host: String,
    /// The instance number of `reproduce` on the host, once an install
    /// succeeded.
    pub instance: Option<u32>,
    /// Every install request key `REview` used for this host, oldest first,
    /// newest last.
    pub install_keys: Vec<String>,
    pub installed_version: Option<String>,
    pub installed_commit: Option<String>,
    /// The server name of the Data Store `REview` chose,
    /// `<instance:03>.giganto.<host>`.
    pub data_store: Option<String>,
    /// The configuration text `REview` rendered and serves to the instance.
    pub config: Option<String>,
    /// The last refusal of an install call, if any.
    pub last_refusal: Option<SystemLogCollectorRefusal>,
}

impl SystemLogCollector {
    /// Returns an empty row for `host`.
    fn new(host: &str) -> Self {
        Self {
            host: host.to_string(),
            instance: None,
            install_keys: Vec::new(),
            installed_version: None,
            installed_commit: None,
            data_store: None,
            config: None,
            last_refusal: None,
        }
    }

    fn set_build(&mut self, version: &str, commit: &str) {
        self.installed_version = Some(version.to_string());
        self.installed_commit = Some(commit.to_string());
    }
}

/// A refusal of an install call of a host's system log collector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemLogCollectorRefusal {
    /// When the call was refused.
    pub at: DateTime<Utc>,
    /// The reason the call was refused, as reported.
    pub message: String,
}

/// The result of [`SystemLogCollectorTable::record_install`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SystemInstallRecord {
    /// No row holds the key; nothing was written.
    NoRow,
    /// The install was recorded; this is the stored row.
    Recorded(SystemLogCollector),
    /// The row already holds the different instance `stored`; nothing was
    /// written.
    InstanceConflict { stored: u32 },
}

/// The `system log collectors` table, holding one [`SystemLogCollector`] per
/// host.
///
/// A row is keyed by the UTF-8 bytes of its host, so the table iterates in
/// byte order of the host. A lookup by anything other than the host scans the
/// rows; there is one row per host, so the table stays small.
#[derive(Clone)]
pub struct SystemLogCollectorTable<'d> {
    map: Map<'d>,
}

impl<'d> SystemLogCollectorTable<'d> {
    /// Opens the `system log collectors` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::SYSTEM_LOG_COLLECTORS).map(|map| Self { map })
    }

    /// Returns the row of `host`, or `None` if there is none.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails or the stored row cannot
    /// be decoded.
    pub fn get(&self, host: &str) -> Result<Option<SystemLogCollector>> {
        self.map
            .get(host.as_bytes())?
            .map(|value| decode(host, value.as_ref()))
            .transpose()
    }

    /// Returns every row, in byte order of the host.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails or any stored row cannot
    /// be decoded; a row that does not decode is never skipped.
    pub fn list(&self) -> Result<Vec<SystemLogCollector>> {
        self.map
            .db
            .iterator_cf(self.map.cf, IteratorMode::Start)
            .map(|entry| {
                let (key, value) = entry.context("failed to read system log collectors")?;
                let host = std::str::from_utf8(&key).map_err(|_| {
                    anyhow!(
                        "invalid system log collector key {}",
                        data_encoding::HEXLOWER.encode(&key)
                    )
                })?;
                decode(host, &value)
            })
            .collect()
    }

    /// Returns the row of `host` if it holds the instance `instance`, or
    /// `None` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails or the stored row cannot
    /// be decoded.
    pub fn get_by_instance(&self, host: &str, instance: u32) -> Result<Option<SystemLogCollector>> {
        Ok(self.get(host)?.filter(|row| row.instance == Some(instance)))
    }

    /// Returns every install key of every row.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails or any stored row cannot
    /// be decoded.
    pub fn install_keys(&self) -> Result<HashSet<String>> {
        Ok(self
            .list()?
            .into_iter()
            .flat_map(|row| row.install_keys)
            .collect())
    }

    /// Appends `key` as the newest install key of `host`, creating the row if
    /// it is missing, and returns the stored row.
    ///
    /// When `superseded` names the row's newest key, that key is removed
    /// before `key` is appended, so a request that never reached the ledger
    /// leaves at most one key behind however often installs are refused. A
    /// `superseded` that is not the newest key is ignored.
    ///
    /// The row of `host` is read and written in one transaction. The rows of
    /// other hosts are read without being locked, so two concurrent appends
    /// of one key to two different hosts are not guaranteed to be refused.
    ///
    /// # Errors
    ///
    /// Returns an error, writing nothing, if `key` is not a `UUIDv4` in its
    /// canonical lowercase hyphenated form, if any row already holds `key`, if
    /// a stored row cannot be decoded, or if the database operation fails.
    pub fn append_install_key(
        &self,
        host: &str,
        key: &str,
        superseded: Option<&str>,
    ) -> Result<SystemLogCollector> {
        if !is_uuid_v4(key) {
            bail!("malformed install key {key:?} for host {host:?}");
        }
        let stored = self.write(host, |row| {
            if let Some(holder) = self.host_holding(key)?
                && holder != host
            {
                bail!("install key {key:?} is already held by host {holder:?}");
            }
            let mut row = row.unwrap_or_else(|| SystemLogCollector::new(host));
            if row.install_keys.iter().any(|held| held == key) {
                bail!("install key {key:?} is already held by host {host:?}");
            }
            if let Some(superseded) = superseded
                && row.install_keys.last().map(String::as_str) == Some(superseded)
            {
                row.install_keys.pop();
            }
            row.install_keys.push(key.to_string());
            Ok(Some(row))
        })?;
        stored.context("an append always writes the row")
    }

    /// Records that the install requested under `key` produced the instance
    /// `instance` running the build `(version, commit)`.
    ///
    /// The row holding `key` takes the instance and the build, and its last
    /// refusal is cleared, unless it already holds a different instance, in
    /// which case nothing is written. Repeating the call with the same
    /// arguments converges.
    ///
    /// # Errors
    ///
    /// Returns an error if a stored row cannot be decoded or if the database
    /// operation fails.
    pub fn record_install(
        &self,
        key: &str,
        instance: u32,
        version: &str,
        commit: &str,
    ) -> Result<SystemInstallRecord> {
        let Some(host) = self.host_holding(key)? else {
            return Ok(SystemInstallRecord::NoRow);
        };
        let mut conflict = None;
        let stored = self.write(&host, |row| {
            conflict = None;
            // The row was found by an unlocked scan, and a concurrent prune
            // may have dropped the key since.
            let Some(mut row) = row.filter(|row| row.install_keys.iter().any(|held| held == key))
            else {
                return Ok(None);
            };
            if let Some(stored) = row.instance
                && stored != instance
            {
                conflict = Some(stored);
                return Ok(None);
            }
            row.instance = Some(instance);
            row.set_build(version, commit);
            row.last_refusal = None;
            Ok(Some(row))
        })?;
        Ok(match (stored, conflict) {
            (Some(row), _) => SystemInstallRecord::Recorded(row),
            (None, Some(stored)) => SystemInstallRecord::InstanceConflict { stored },
            (None, None) => SystemInstallRecord::NoRow,
        })
    }

    /// Sets the build of `host` to `(version, commit)` if its row holds the
    /// instance `instance`, and returns the stored row; returns `None`,
    /// writing nothing, otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored row cannot be decoded or if the database
    /// operation fails.
    pub fn record_build(
        &self,
        host: &str,
        instance: u32,
        version: &str,
        commit: &str,
    ) -> Result<Option<SystemLogCollector>> {
        self.write(host, |row| {
            let Some(mut row) = row.filter(|row| row.instance == Some(instance)) else {
                return Ok(None);
            };
            row.set_build(version, commit);
            Ok(Some(row))
        })
    }

    /// Replaces the Data Store of `host` with `server_name`, and returns the
    /// stored row.
    ///
    /// # Errors
    ///
    /// Returns an error, writing nothing, if `host` has no row; or if the
    /// stored row cannot be decoded or the database operation fails.
    pub fn set_data_store(
        &self,
        host: &str,
        server_name: Option<String>,
    ) -> Result<SystemLogCollector> {
        self.replace(host, move |row| row.data_store.clone_from(&server_name))
    }

    /// Replaces the Data Store of `host` with `server_name` only if the stored
    /// Data Store equals `expected`, and returns the stored row; returns
    /// `None`, writing nothing, if it differs.
    ///
    /// The comparison and the write are one transaction, so a reconcile can
    /// persist its own choice without overwriting a choice made after it read
    /// the row.
    ///
    /// # Errors
    ///
    /// Returns an error, writing nothing, if `host` has no row; or if the
    /// stored row cannot be decoded or the database operation fails.
    pub fn set_data_store_if(
        &self,
        host: &str,
        expected: Option<&str>,
        server_name: Option<String>,
    ) -> Result<Option<SystemLogCollector>> {
        self.write(host, move |row| {
            let Some(mut row) = row else {
                bail!("no system log collector for host {host:?}");
            };
            if row.data_store.as_deref() != expected {
                return Ok(None);
            }
            row.data_store.clone_from(&server_name);
            Ok(Some(row))
        })
    }

    /// Replaces the configuration of `host` with `config`, and returns the
    /// stored row.
    ///
    /// # Errors
    ///
    /// Returns an error, writing nothing, if `host` has no row; or if the
    /// stored row cannot be decoded or the database operation fails.
    pub fn set_config(&self, host: &str, config: Option<String>) -> Result<SystemLogCollector> {
        self.replace(host, move |row| row.config.clone_from(&config))
    }

    /// Replaces the last install refusal of `host` with `refusal`, and returns
    /// the stored row.
    ///
    /// # Errors
    ///
    /// Returns an error, writing nothing, if `host` has no row; or if the
    /// stored row cannot be decoded or the database operation fails.
    pub fn set_last_refusal(
        &self,
        host: &str,
        refusal: Option<SystemLogCollectorRefusal>,
    ) -> Result<SystemLogCollector> {
        self.replace(host, move |row| row.last_refusal.clone_from(&refusal))
    }

    /// Removes within `txn` every key in `removed` from every row holding it,
    /// keeping the order of the other keys.
    ///
    /// The rows are found by an unlocked scan; each row holding a removed key
    /// is then read for update in `txn`, and the keys are dropped from that
    /// value. A row holding none of them is not written.
    ///
    /// # Errors
    ///
    /// Returns an error if a stored row cannot be decoded or if the database
    /// operation fails.
    pub(crate) fn drop_install_keys(
        &self,
        txn: &Transaction<'_, OptimisticTransactionDB>,
        removed: &HashSet<String>,
    ) -> Result<()> {
        if removed.is_empty() {
            return Ok(());
        }
        for scanned in self.list()? {
            if !scanned.install_keys.iter().any(|key| removed.contains(key)) {
                continue;
            }
            let host = scanned.host.as_str();
            let Some(mut row) = self.get_for_update(txn, host)? else {
                continue;
            };
            let held = row.install_keys.len();
            row.install_keys.retain(|key| !removed.contains(key));
            if row.install_keys.len() != held {
                self.put(txn, &row)?;
            }
        }
        Ok(())
    }

    /// Returns the host whose row holds `key`, if any.
    fn host_holding(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .list()?
            .into_iter()
            .find(|row| row.install_keys.iter().any(|held| held == key))
            .map(|row| row.host))
    }

    /// Applies `change` to the existing row of `host` and writes the result,
    /// failing if there is no row.
    fn replace(
        &self,
        host: &str,
        change: impl Fn(&mut SystemLogCollector),
    ) -> Result<SystemLogCollector> {
        let stored = self.write(host, |row| {
            let Some(mut row) = row else {
                bail!("no system log collector for host {host:?}");
            };
            change(&mut row);
            Ok(Some(row))
        })?;
        stored.context("a replacement always writes the row")
    }

    /// Reads the row of `host` for update, passes it to `change`, and writes
    /// the row `change` returns, committing with a retry on a conflicting
    /// write; returns the written row.
    ///
    /// `change` returning `None` writes nothing, and so does it returning an
    /// error, which is passed on. On a conflict `change` runs again on the
    /// row as it is then.
    fn write(
        &self,
        host: &str,
        mut change: impl FnMut(Option<SystemLogCollector>) -> Result<Option<SystemLogCollector>>,
    ) -> Result<Option<SystemLogCollector>> {
        loop {
            let txn = self.map.db.transaction();
            let row = self.get_for_update(&txn, host)?;
            let Some(row) = change(row)? else {
                return Ok(None);
            };
            self.put(&txn, &row)?;
            match txn.commit() {
                Ok(()) => return Ok(Some(row)),
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).with_context(|| {
                            format!("failed to write system log collector of host {host:?}")
                        });
                    }
                }
            }
        }
    }

    /// Reads the row of `host` within `txn`, locking its key.
    fn get_for_update(
        &self,
        txn: &Transaction<'_, OptimisticTransactionDB>,
        host: &str,
    ) -> Result<Option<SystemLogCollector>> {
        txn.get_for_update_cf(self.map.cf, host.as_bytes(), EXCLUSIVE)
            .with_context(|| format!("failed to read system log collector of host {host:?}"))?
            .map(|stored| decode(host, &stored))
            .transpose()
    }

    /// Writes `row` within `txn` under its host.
    fn put(
        &self,
        txn: &Transaction<'_, OptimisticTransactionDB>,
        row: &SystemLogCollector,
    ) -> Result<()> {
        let value = super::serialize(row).with_context(|| {
            format!(
                "failed to serialize system log collector of host {:?}",
                row.host
            )
        })?;
        txn.put_cf(self.map.cf, row.host.as_bytes(), value)
            .with_context(|| {
                format!(
                    "failed to write system log collector of host {:?}",
                    row.host
                )
            })
    }
}

/// Decodes the stored row of `host`.
fn decode(host: &str, value: &[u8]) -> Result<SystemLogCollector> {
    super::deserialize(value)
        .with_context(|| format!("failed to decode system log collector of host {host:?}"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::Store;
    use crate::test::{DbGuard, acquire_db_permit};

    const HOST: &str = "host-a.example";
    const OTHER_HOST: &str = "host-b.example";
    const KEY_1: &str = "9d5cb6e0-0a3f-41de-9f0a-6b0f4e5c1a27";
    const KEY_2: &str = "3f2c8b41-5e6d-4a7b-b8c9-0d1e2f3a4b5c";
    const KEY_3: &str = "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f";

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path(), None).unwrap());
        (permit, store)
    }

    /// Every key and value in the column family.
    fn raw(table: &SystemLogCollectorTable) -> Vec<(Vec<u8>, Vec<u8>)> {
        table
            .map
            .db
            .iterator_cf(table.map.cf, IteratorMode::Start)
            .map(|entry| {
                let (key, value) = entry.unwrap();
                (key.to_vec(), value.to_vec())
            })
            .collect()
    }

    fn refusal(message: &str) -> SystemLogCollectorRefusal {
        SystemLogCollectorRefusal {
            at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            message: message.to_string(),
        }
    }

    /// The row of `HOST` with the instance `instance`, recorded under
    /// `KEY_1`.
    fn installed(table: &SystemLogCollectorTable, instance: u32) -> SystemLogCollector {
        table.append_install_key(HOST, KEY_1, None).unwrap();
        let SystemInstallRecord::Recorded(row) = table
            .record_install(KEY_1, instance, "1.0.0", "c0ffee")
            .unwrap()
        else {
            panic!("the install must be recorded");
        };
        row
    }

    #[test]
    fn fresh_store_has_an_empty_table() {
        let (_permit, store) = setup_store();
        let table = store.system_log_collector_map();
        assert_eq!(table.list().unwrap(), Vec::new());
        assert_eq!(table.get(HOST).unwrap(), None);
        assert_eq!(table.install_keys().unwrap(), HashSet::new());
    }

    #[test]
    fn append_creates_the_row_and_appends_newest_last() {
        let (_permit, store) = setup_store();
        let table = store.system_log_collector_map();

        let created = table.append_install_key(HOST, KEY_1, None).unwrap();
        let mut expected = SystemLogCollector::new(HOST);
        expected.install_keys = vec![KEY_1.to_string()];
        assert_eq!(created, expected);
        assert_eq!(table.get(HOST).unwrap(), Some(expected.clone()));

        let appended = table.append_install_key(HOST, KEY_2, None).unwrap();
        expected.install_keys.push(KEY_2.to_string());
        assert_eq!(appended, expected);
        assert_eq!(table.get(HOST).unwrap(), Some(expected));

        // The key is the host's UTF-8 bytes and nothing else, and the value
        // is the row in the crate's encoding.
        let rows = raw(&table);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, HOST.as_bytes());
        assert_eq!(rows[0].1, super::super::serialize(&appended).unwrap());
    }

    #[test]
    fn append_with_superseded_replaces_only_the_newest_key() {
        let (_permit, store) = setup_store();
        let table = store.system_log_collector_map();
        table.append_install_key(HOST, KEY_1, None).unwrap();
        table.append_install_key(HOST, KEY_2, None).unwrap();

        // An older key is not the newest: the new key is only appended.
        let row = table.append_install_key(HOST, KEY_3, Some(KEY_1)).unwrap();
        assert_eq!(row.install_keys, [KEY_1, KEY_2, KEY_3]);

        // The newest key is replaced by the new one.
        let replacement = "0b1c2d3e-4f50-4617-a283-94a5b6c7d8e9";
        let row = table
            .append_install_key(HOST, replacement, Some(KEY_3))
            .unwrap();
        assert_eq!(row.install_keys, [KEY_1, KEY_2, replacement]);
        assert_eq!(table.get(HOST).unwrap(), Some(row));
    }

    #[test]
    fn append_with_superseded_on_a_missing_row_creates_it() {
        let (_permit, store) = setup_store();
        let table = store.system_log_collector_map();
        let row = table.append_install_key(HOST, KEY_2, Some(KEY_1)).unwrap();
        assert_eq!(row.install_keys, [KEY_2]);
    }

    #[test]
    fn append_refuses_a_malformed_key_and_writes_nothing() {
        let (_permit, store) = setup_store();
        let table = store.system_log_collector_map();
        for malformed in [
            // Uppercase.
            "9D5CB6E0-0A3F-41DE-9F0A-6B0F4E5C1A27",
            // Version nibble 1.
            "9d5cb6e0-0a3f-11de-9f0a-6b0f4e5c1a27",
            // Too short and too long.
            "9d5cb6e0-0a3f-41de-9f0a-6b0f4e5c1a2",
            "9d5cb6e0-0a3f-41de-9f0a-6b0f4e5c1a277",
            "",
        ] {
            let err = table.append_install_key(HOST, malformed, None).unwrap_err();
            assert!(
                err.to_string().contains("malformed install key"),
                "{malformed:?}: {err:#}"
            );
        }
        assert_eq!(raw(&table), Vec::new());

        table.append_install_key(HOST, KEY_1, None).unwrap();
        let before = raw(&table);
        assert!(
            table
                .append_install_key(HOST, "9D5CB6E0-0A3F-41DE-9F0A-6B0F4E5C1A27", Some(KEY_1))
                .is_err()
        );
        assert_eq!(raw(&table), before);
    }

    #[test]
    fn append_refuses_a_key_any_row_holds_and_writes_nothing() {
        let (_permit, store) = setup_store();
        let table = store.system_log_collector_map();
        table.append_install_key(HOST, KEY_1, None).unwrap();
        table.append_install_key(HOST, KEY_2, None).unwrap();
        let before = raw(&table);

        // Another host's row.
        let err = table
            .append_install_key(OTHER_HOST, KEY_1, None)
            .unwrap_err();
        assert!(err.to_string().contains("already held"), "{err:#}");
        // The same host's row, including as its own superseded key.
        assert!(table.append_install_key(HOST, KEY_1, None).is_err());
        assert!(table.append_install_key(HOST, KEY_2, Some(KEY_2)).is_err());

        assert_eq!(raw(&table), before);
        assert_eq!(table.get(OTHER_HOST).unwrap(), None);
    }

    #[test]
    fn list_and_install_keys_cover_every_row_in_host_order() {
        let (_permit, store) = setup_store();
        let table = store.system_log_collector_map();
        table.append_install_key(OTHER_HOST, KEY_3, None).unwrap();
        table.append_install_key(HOST, KEY_1, None).unwrap();
        table.append_install_key(HOST, KEY_2, None).unwrap();

        let hosts: Vec<String> = table.list().unwrap().into_iter().map(|r| r.host).collect();
        assert_eq!(hosts, [HOST, OTHER_HOST]);
        assert_eq!(
            table.install_keys().unwrap(),
            [KEY_1, KEY_2, KEY_3]
                .into_iter()
                .map(str::to_string)
                .collect()
        );
    }

    #[test]
    fn list_fails_on_a_row_that_does_not_decode() {
        let (_permit, store) = setup_store();
        let table = store.system_log_collector_map();
        table.append_install_key(HOST, KEY_1, None).unwrap();
        table
            .map
            .db
            .put_cf(table.map.cf, OTHER_HOST.as_bytes(), [0xff])
            .unwrap();
        assert!(table.list().is_err());
        assert!(table.install_keys().is_err());
        assert!(table.get(OTHER_HOST).is_err());
    }

    #[test]
    fn get_by_instance_matches_only_the_stored_instance_of_the_host() {
        let (_permit, store) = setup_store();
        let table = store.system_log_collector_map();
        table.append_install_key(OTHER_HOST, KEY_2, None).unwrap();
        // No instance yet.
        assert_eq!(table.get_by_instance(OTHER_HOST, 1).unwrap(), None);

        let row = installed(&table, 3);
        assert_eq!(table.get_by_instance(HOST, 3).unwrap(), Some(row));
        assert_eq!(table.get_by_instance(HOST, 1).unwrap(), None);
        assert_eq!(table.get_by_instance(OTHER_HOST, 3).unwrap(), None);
        assert_eq!(table.get_by_instance("unknown.example", 3).unwrap(), None);
    }

    #[test]
    fn record_install_sets_the_instance_and_build_and_clears_the_refusal() {
        let (_permit, store) = setup_store();
        let table = store.system_log_collector_map();
        table.append_install_key(HOST, KEY_1, None).unwrap();
        table.append_install_key(HOST, KEY_2, None).unwrap();
        table.set_last_refusal(HOST, Some(refusal("busy"))).unwrap();

        // Any key of the row finds it, not only the newest.
        let recorded = table.record_install(KEY_1, 2, "1.0.0", "c0ffee").unwrap();
        let mut expected = SystemLogCollector::new(HOST);
        expected.install_keys = vec![KEY_1.to_string(), KEY_2.to_string()];
        expected.instance = Some(2);
        expected.installed_version = Some("1.0.0".to_string());
        expected.installed_commit = Some("c0ffee".to_string());
        assert_eq!(recorded, SystemInstallRecord::Recorded(expected.clone()));
        assert_eq!(table.get(HOST).unwrap(), Some(expected.clone()));

        // A repeat converges on the same row.
        let before = raw(&table);
        assert_eq!(
            table.record_install(KEY_1, 2, "1.0.0", "c0ffee").unwrap(),
            SystemInstallRecord::Recorded(expected.clone())
        );
        assert_eq!(raw(&table), before);

        // The same instance under another key takes the new build.
        let SystemInstallRecord::Recorded(row) =
            table.record_install(KEY_2, 2, "1.1.0", "beef").unwrap()
        else {
            panic!("the same instance must be recorded");
        };
        assert_eq!(row.instance, Some(2));
        assert_eq!(row.installed_version.as_deref(), Some("1.1.0"));
        assert_eq!(row.installed_commit.as_deref(), Some("beef"));
    }

    #[test]
    fn record_install_answers_no_row_for_an_unknown_key() {
        let (_permit, store) = setup_store();
        let table = store.system_log_collector_map();
        assert_eq!(
            table.record_install(KEY_1, 1, "1.0.0", "c0ffee").unwrap(),
            SystemInstallRecord::NoRow
        );
        table.append_install_key(HOST, KEY_1, None).unwrap();
        let before = raw(&table);
        assert_eq!(
            table.record_install(KEY_2, 1, "1.0.0", "c0ffee").unwrap(),
            SystemInstallRecord::NoRow
        );
        assert_eq!(raw(&table), before);
    }

    #[test]
    fn record_install_answers_instance_conflict_and_writes_nothing() {
        let (_permit, store) = setup_store();
        let table = store.system_log_collector_map();
        installed(&table, 1);
        table.append_install_key(HOST, KEY_2, None).unwrap();
        table.set_last_refusal(HOST, Some(refusal("busy"))).unwrap();
        let before = raw(&table);

        assert_eq!(
            table.record_install(KEY_2, 2, "2.0.0", "beef").unwrap(),
            SystemInstallRecord::InstanceConflict { stored: 1 }
        );
        assert_eq!(raw(&table), before);
    }

    #[test]
    fn record_build_updates_only_the_matching_host_and_instance() {
        let (_permit, store) = setup_store();
        let table = store.system_log_collector_map();
        table.append_install_key(OTHER_HOST, KEY_2, None).unwrap();
        installed(&table, 1);
        let before = raw(&table);

        assert_eq!(table.record_build(HOST, 2, "2.0.0", "beef").unwrap(), None);
        assert_eq!(
            table.record_build(OTHER_HOST, 1, "2.0.0", "beef").unwrap(),
            None
        );
        assert_eq!(
            table
                .record_build("unknown.example", 1, "2.0.0", "beef")
                .unwrap(),
            None
        );
        assert_eq!(raw(&table), before);

        let row = table
            .record_build(HOST, 1, "2.0.0", "beef")
            .unwrap()
            .unwrap();
        assert_eq!(row.installed_version.as_deref(), Some("2.0.0"));
        assert_eq!(row.installed_commit.as_deref(), Some("beef"));
        assert_eq!(row.instance, Some(1));
        assert_eq!(table.get(HOST).unwrap(), Some(row));
    }

    #[test]
    fn setters_replace_one_field_and_refuse_a_missing_row() {
        let (_permit, store) = setup_store();
        let table = store.system_log_collector_map();

        assert!(
            table
                .set_data_store(HOST, Some("001.giganto.host-a.example".to_string()))
                .is_err()
        );
        assert!(table.set_config(HOST, Some("config".to_string())).is_err());
        assert!(table.set_last_refusal(HOST, Some(refusal("busy"))).is_err());
        assert!(table.set_data_store_if(HOST, None, None).is_err());
        assert_eq!(raw(&table), Vec::new());

        let mut expected = table.append_install_key(HOST, KEY_1, None).unwrap();

        let row = table
            .set_data_store(HOST, Some("001.giganto.host-a.example".to_string()))
            .unwrap();
        expected.data_store = Some("001.giganto.host-a.example".to_string());
        assert_eq!(row, expected);

        let row = table
            .set_config(HOST, Some("[journal]\n".to_string()))
            .unwrap();
        expected.config = Some("[journal]\n".to_string());
        assert_eq!(row, expected);

        let row = table.set_last_refusal(HOST, Some(refusal("busy"))).unwrap();
        expected.last_refusal = Some(refusal("busy"));
        assert_eq!(row, expected);
        assert_eq!(table.get(HOST).unwrap(), Some(expected.clone()));

        // Each clears its field with `None`.
        table.set_data_store(HOST, None).unwrap();
        table.set_config(HOST, None).unwrap();
        let row = table.set_last_refusal(HOST, None).unwrap();
        expected.data_store = None;
        expected.config = None;
        expected.last_refusal = None;
        assert_eq!(row, expected);
        assert_eq!(table.get(HOST).unwrap(), Some(expected));
    }

    #[test]
    fn set_data_store_if_writes_only_over_the_expected_value() {
        let (_permit, store) = setup_store();
        let table = store.system_log_collector_map();
        table.append_install_key(HOST, KEY_1, None).unwrap();
        let first = "001.giganto.host-a.example";
        let second = "002.giganto.host-a.example";

        // Stored `None`, expected `Some`: nothing is written.
        let before = raw(&table);
        assert_eq!(
            table
                .set_data_store_if(HOST, Some(first), Some(second.to_string()))
                .unwrap(),
            None
        );
        assert_eq!(raw(&table), before);

        // Stored `None`, expected `None`: written.
        let row = table
            .set_data_store_if(HOST, None, Some(first.to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(row.data_store.as_deref(), Some(first));
        assert_eq!(table.get(HOST).unwrap(), Some(row));

        // Stored `Some`, expected `None` or another value: nothing is written.
        let before = raw(&table);
        assert_eq!(
            table
                .set_data_store_if(HOST, None, Some(second.to_string()))
                .unwrap(),
            None
        );
        assert_eq!(
            table.set_data_store_if(HOST, Some(second), None).unwrap(),
            None
        );
        assert_eq!(raw(&table), before);

        // Stored `Some`, expected the same: written.
        let row = table
            .set_data_store_if(HOST, Some(first), Some(second.to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(row.data_store.as_deref(), Some(second));
        let row = table
            .set_data_store_if(HOST, Some(second), None)
            .unwrap()
            .unwrap();
        assert_eq!(row.data_store, None);
        assert_eq!(table.get(HOST).unwrap(), Some(row));
    }

    #[test]
    fn drop_install_keys_removes_the_keys_and_keeps_the_rest_of_the_row() {
        let (_permit, store) = setup_store();
        let table = store.system_log_collector_map();
        installed(&table, 4);
        table.append_install_key(HOST, KEY_2, None).unwrap();
        table.append_install_key(HOST, KEY_3, None).unwrap();
        let untouched_key = "0b1c2d3e-4f50-4617-a283-94a5b6c7d8e9";
        table
            .append_install_key(OTHER_HOST, untouched_key, None)
            .unwrap();
        let other_before = table.map.get(OTHER_HOST.as_bytes()).unwrap().unwrap();
        let other_before = other_before.as_ref().to_vec();

        let removed: HashSet<String> = [KEY_2, "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let txn = table.map.db.transaction();
        table.drop_install_keys(&txn, &removed).unwrap();
        txn.commit().unwrap();

        let row = table.get(HOST).unwrap().unwrap();
        assert_eq!(row.install_keys, [KEY_1, KEY_3]);
        assert_eq!(row.instance, Some(4));
        assert_eq!(row.installed_version.as_deref(), Some("1.0.0"));
        assert_eq!(
            table
                .map
                .get(OTHER_HOST.as_bytes())
                .unwrap()
                .unwrap()
                .as_ref(),
            other_before
        );

        // Every key may go; the row stays.
        let removed: HashSet<String> = [KEY_1, KEY_3].into_iter().map(str::to_string).collect();
        let txn = table.map.db.transaction();
        table.drop_install_keys(&txn, &removed).unwrap();
        txn.commit().unwrap();
        let row = table.get(HOST).unwrap().unwrap();
        assert_eq!(row.install_keys, Vec::<String>::new());
        assert_eq!(row.instance, Some(4));
    }

    #[test]
    fn concurrent_appends_on_one_host_all_land() {
        const THREADS: usize = 8;
        let (_permit, store) = setup_store();

        for round in 0..5_u16 {
            let host = format!("host-{round}.example");
            let barrier = std::sync::Barrier::new(THREADS);
            let round_keys: Vec<String> = (0..THREADS)
                .map(|i| format!("{i:08x}-0a3f-41de-9f0a-6b0f4e5c{round:04x}"))
                .collect();
            std::thread::scope(|scope| {
                for key in &round_keys {
                    let store = &store;
                    let barrier = &barrier;
                    let host = host.as_str();
                    scope.spawn(move || {
                        barrier.wait();
                        store
                            .system_log_collector_map()
                            .append_install_key(host, key, None)
                            .unwrap();
                    });
                }
            });

            let row = store
                .system_log_collector_map()
                .get(&host)
                .unwrap()
                .unwrap();
            let mut stored = row.install_keys.clone();
            stored.sort_unstable();
            let mut expected = round_keys.clone();
            expected.sort_unstable();
            assert_eq!(stored, expected);
        }
    }
}
