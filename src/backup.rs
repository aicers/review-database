//! Database backup utilities.

use std::sync::{Arc, RwLock};

use anyhow::Result;
use chrono::{DateTime, TimeZone, Utc};
use rocksdb::backup::BackupEngineInfo;

use crate::Store;

#[allow(clippy::module_name_repetitions)]
pub struct BackupInfo {
    pub id: u32,
    pub timestamp: DateTime<Utc>,
    pub size: u64,
}

impl From<BackupEngineInfo> for BackupInfo {
    fn from(backup: BackupEngineInfo) -> Self {
        Self {
            id: backup.backup_id,
            timestamp: DateTime::from_timestamp(backup.timestamp, 0)
                .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap()),
            size: backup.size,
        }
    }
}

/// Creates a new database backup, keeping the specified number of backups.
///
/// # Errors
///
/// Returns an error if backup fails.
///
/// # Panics
///
/// Panics if the lock is poisoned, which should never happen as the backup
/// operation does not panic.
pub fn create(store: &Arc<RwLock<Store>>, flush: bool, backups_to_keep: u32) -> Result<()> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    let mut store = store
        .write()
        .expect("write lock should not be poisoned as backup does not panic");
    store.backup(flush, backups_to_keep)
}

/// Lists the backup information of the database.
///
/// # Errors
///
/// Returns an error if backup list fails to create
///
/// # Panics
///
/// Panics if the lock is poisoned, which should never happen as reading backup
/// info does not panic.
pub fn list(store: &Arc<RwLock<Store>>) -> Result<Vec<BackupInfo>> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    let backup_list = {
        let store = store
            .read()
            .expect("read lock should not be poisoned as get_backup_info does not panic");
        store.get_backup_info()?
    };
    Ok(backup_list
        .into_iter()
        .map(std::convert::Into::into)
        .collect())
}

/// Restores the database from a backup with the specified ID.
///
/// # Errors
///
/// Returns an error if the restore operation fails.
///
/// # Panics
///
/// Panics if the lock is poisoned, which should never happen as the restore
/// operation does not panic.
pub fn restore(store: &Arc<RwLock<Store>>, backup_id: Option<u32>) -> Result<()> {
    // TODO: This function should be expanded to support PostgreSQL backups as well.
    let mut store = store
        .write()
        .expect("write lock should not be poisoned as restore does not panic");
    match &backup_id {
        Some(id) => store.restore_from_backup(*id),
        None => store.restore_from_latest_backup(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
    };

    use bincode::Options;
    use chrono::{TimeZone, Utc};

    use crate::test::acquire_db_permit;
    use crate::{
        Store,
        event::{DnsEventFields, EventKind, EventMessage},
    };

    fn example_message() -> EventMessage {
        let codec = bincode::DefaultOptions::new();
        let fields = DnsEventFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 53,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            query: "foo.com".to_string(),
            answer: vec!["1.1.1.1".to_string()],
            trans_id: 1,
            rtt: 1,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: false,
            ttl: vec![1; 5],
            confidence: 0.8,
            threat_level: 3,
            category: Some(crate::EventCategory::CommandAndControl),
        };
        EventMessage {
            time: Utc::now(),
            kind: EventKind::DnsCovertChannel,
            fields: codec.serialize(&fields).expect("serializable"),
        }
    }

    #[test]
    fn db_backup_list() {
        use std::sync::RwLock;

        use crate::backup::list;

        let _permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let store = Arc::new(RwLock::new(
            Store::new(db_dir.path(), backup_dir.path()).unwrap(),
        ));

        {
            let store = store.read().expect("test holds no other locks");
            let db = store.events();
            assert!(db.iter_forward().next().is_none());
        }

        let msg = example_message();

        // backing up 1
        {
            let mut store = store.write().expect("test holds no other locks");
            let db = store.events();
            db.put(&msg).unwrap();
            let res = store.backup(true, 3);
            assert!(res.is_ok());
        }
        // backing up 2
        {
            let mut store = store.write().expect("test holds no other locks");
            let db = store.events();
            db.put(&msg).unwrap();
            let res = store.backup(true, 3);
            assert!(res.is_ok());
        }

        // backing up 3
        {
            let mut store = store.write().expect("test holds no other locks");
            let db = store.events();
            db.put(&msg).unwrap();
            let res = store.backup(true, 3);
            assert!(res.is_ok());
        }

        // get backup list
        let backup_list = list(&store).unwrap();
        assert_eq!(backup_list.len(), 3);
        assert_eq!(backup_list[0].id, 1);
        assert_eq!(backup_list[1].id, 2);
        assert_eq!(backup_list[2].id, 3);
    }

    #[test]
    fn test_backup_info_timestamp_conversion() {
        use chrono::{DateTime, Datelike};
        use rocksdb::backup::BackupEngineInfo;

        use super::BackupInfo;

        // Test with a known timestamp in seconds (September 25, 2025, 00:42:20 UTC)
        let timestamp_seconds: i64 = 1_758_760_940;
        let backup_engine_info = BackupEngineInfo {
            backup_id: 1,
            timestamp: timestamp_seconds,
            size: 697_860,
            num_files: 10,
        };

        let backup_info: BackupInfo = backup_engine_info.into();

        // Verify the timestamp is correctly interpreted as seconds
        assert_eq!(backup_info.id, 1);
        assert_eq!(backup_info.size, 697_860);

        // The timestamp should be in 2025, not 1970
        let expected_timestamp = DateTime::from_timestamp(timestamp_seconds, 0).unwrap();
        assert_eq!(backup_info.timestamp, expected_timestamp);
        assert!(backup_info.timestamp.year() == 2025);
    }
}
