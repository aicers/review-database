//! The `customer` table.

use std::{borrow::Cow, net::IpAddr};

use anyhow::Result;
use chrono::{DateTime, Utc};
use rocksdb::OptimisticTransactionDB;
use serde::{Deserialize, Serialize};

use super::UniqueKey;
use crate::{
    HostNetworkGroup, Indexable, IndexedMap, IndexedMapUpdate, IndexedTable, collections::Indexed,
    event::NetworkType, types::FromKeyValue,
};

#[derive(Clone, Deserialize, Serialize)]
pub struct Customer {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub networks: Vec<Network>,
    pub creation_time: DateTime<Utc>,
}

impl FromKeyValue for Customer {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self> {
        super::deserialize(value)
    }
}

impl UniqueKey for Customer {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl Indexable for Customer {
    fn key(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.name.as_bytes())
    }
    fn index(&self) -> u32 {
        self.id
    }
    fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
        key
    }
    fn value(&self) -> Vec<u8> {
        super::serialize(self).expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

impl Customer {
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.networks.iter().any(|n| n.contains(addr))
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq)]
pub struct Network {
    pub name: String,
    pub description: String,
    pub network_type: NetworkType,
    pub network_group: HostNetworkGroup,
}

impl Network {
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.network_group.contains(addr)
    }
}

#[derive(Clone)]
pub struct Update {
    pub name: Option<String>,
    pub description: Option<String>,
    pub networks: Option<Vec<Network>>,
}

impl IndexedMapUpdate for Update {
    type Entry = Customer;

    fn key(&self) -> Option<Cow<'_, [u8]>> {
        self.name.as_deref().map(str::as_bytes).map(Cow::Borrowed)
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry> {
        if let Some(name) = self.name.as_deref() {
            value.name.clear();
            value.name.push_str(name);
        }
        if let Some(description) = self.description.as_deref() {
            value.description.clear();
            value.description.push_str(description);
        }
        if let Some(networks) = self.networks.as_deref() {
            value.networks.clear();
            value.networks.extend(networks.iter().cloned());
        }
        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if let Some(v) = self.name.as_deref()
            && v != value.name
        {
            return false;
        }
        if let Some(v) = self.description.as_deref()
            && v != value.description
        {
            return false;
        }
        if let Some(v) = self.networks.as_deref() {
            if v.len() != value.networks.len() {
                return false;
            }
            if !v
                .iter()
                .zip(value.networks.iter())
                .all(|(lhs, rhs)| lhs == rhs)
            {
                return false;
            }
        }
        true
    }
}

/// Functions for the `customer` indexed map.
impl<'d> IndexedTable<'d, Customer> {
    /// Opens the `customer` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        IndexedMap::new(db, super::CUSTOMERS)
            .map(IndexedTable::new)
            .ok()
    }

    /// Updates the `Cutomer` from `old` to `new`, given `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `id` is invalid or the database operation fails.
    pub fn update(&mut self, id: u32, old: &Update, new: &Update) -> Result<()> {
        self.indexed_map.update(id, old, new)
    }
}

#[cfg(test)]
mod test {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        ops::RangeInclusive,
        str::FromStr,
        sync::Arc,
    };

    use chrono::{DateTime, Utc};
    use ipnet::IpNet;

    use crate::event::NetworkType;
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{
        Customer, CustomerNetwork, CustomerUpdate, HostNetworkGroup, Indexable, Store,
        types::FromKeyValue,
    };

    /// Canonical timestamp for deterministic Customer value-byte fixtures.
    const FIXTURE_CREATION_TIME: &str = "2000-02-29T12:34:56.123456789Z";

    /// Historical `Customer` stored value bytes for the deterministic fixture
    /// record below.
    ///
    /// Captured once from `review-database` v0.45.0 (`3dd96ec`) via the
    /// production `Indexable::value` path (bincode `DefaultOptions`).
    const CUSTOMER_STORED_VALUE_V0: &[u8] = &[
        0x07, 0x09, 0x61, 0x63, 0x6d, 0x65, 0x2d, 0x63, 0x6f, 0x72, 0x70, 0x1e, 0x44, 0x65, 0x74,
        0x65, 0x72, 0x6d, 0x69, 0x6e, 0x69, 0x73, 0x74, 0x69, 0x63, 0x20, 0x66, 0x69, 0x78, 0x74,
        0x75, 0x72, 0x65, 0x20, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x65, 0x72, 0x03, 0x0e, 0x69,
        0x6e, 0x74, 0x72, 0x61, 0x6e, 0x65, 0x74, 0x2d, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x18, 0x50,
        0x72, 0x69, 0x6d, 0x61, 0x72, 0x79, 0x20, 0x69, 0x6e, 0x74, 0x72, 0x61, 0x6e, 0x65, 0x74,
        0x20, 0x73, 0x65, 0x67, 0x6d, 0x65, 0x6e, 0x74, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x00, 0x01,
        0x00, 0xc0, 0xa8, 0x01, 0x0a, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0xac,
        0x10, 0x00, 0x01, 0x00, 0xac, 0x10, 0xff, 0xfe, 0x0c, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61,
        0x79, 0x2d, 0x62, 0x65, 0x74, 0x61, 0x10, 0x45, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c,
        0x20, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x02, 0x01, 0x01, 0x20, 0x01, 0x0d, 0xb8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x20,
        0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x0e, 0x65, 0x78, 0x74, 0x72, 0x61, 0x6e, 0x65, 0x74, 0x2d, 0x67, 0x61, 0x6d,
        0x6d, 0x61, 0x10, 0x50, 0x61, 0x72, 0x74, 0x6e, 0x65, 0x72, 0x20, 0x65, 0x78, 0x74, 0x72,
        0x61, 0x6e, 0x65, 0x74, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x32, 0x30, 0x30, 0x30, 0x2d, 0x30,
        0x32, 0x2d, 0x32, 0x39, 0x54, 0x31, 0x32, 0x3a, 0x33, 0x34, 0x3a, 0x35, 0x36, 0x2e, 0x31,
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x5a,
    ];

    #[test]
    fn update() {
        let (_permit, store) = setup_store();
        let mut table = store.customer_map();

        let entry = create_entry("a");
        let id = table.put(entry.clone()).unwrap();

        let old = CustomerUpdate {
            name: Some("a".to_string()),
            description: None,
            networks: None,
        };

        let update = CustomerUpdate {
            name: Some("b".to_string()),
            description: None,
            networks: None,
        };

        assert!(table.update(id, &old, &update).is_ok());
        assert_eq!(table.count().unwrap(), 1);
        let entry = table.get_by_id(id).unwrap();
        assert_eq!(entry.map(|e| e.name), Some("b".to_string()));
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path(), None).unwrap());
        (permit, store)
    }

    fn create_entry(name: &str) -> Customer {
        Customer {
            id: u32::MAX,
            name: name.to_string(),
            description: "description".to_string(),
            networks: Vec::new(),
            creation_time: chrono::Utc::now(),
        }
    }

    fn fixture_creation_time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(FIXTURE_CREATION_TIME)
            .expect("valid RFC 3339 timestamp")
            .with_timezone(&Utc)
    }

    /// Builds a deterministic `Customer` covering all stored value fields.
    fn deterministic_fixture_customer() -> Customer {
        let intranet_group = HostNetworkGroup::new(
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            ],
            vec![IpNet::from_str("10.0.0.0/8").expect("valid CIDR")],
            vec![
                IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))
                    ..=IpAddr::V4(Ipv4Addr::new(172, 16, 255, 254)),
            ],
        );
        let gateway_group = HostNetworkGroup::new(
            vec![IpAddr::V6(
                Ipv6Addr::from_str("2001:db8::1").expect("valid IPv6"),
            )],
            vec![IpNet::from_str("2001:db8::/32").expect("valid CIDR")],
            Vec::<RangeInclusive<IpAddr>>::new(),
        );

        Customer {
            id: 7,
            name: "acme-corp".to_string(),
            description: "Deterministic fixture customer".to_string(),
            networks: vec![
                CustomerNetwork {
                    name: "intranet-alpha".to_string(),
                    description: "Primary intranet segment".to_string(),
                    network_type: NetworkType::Intranet,
                    network_group: intranet_group,
                },
                CustomerNetwork {
                    name: "gateway-beta".to_string(),
                    description: "External gateway".to_string(),
                    network_type: NetworkType::Gateway,
                    network_group: gateway_group,
                },
                CustomerNetwork {
                    name: "extranet-gamma".to_string(),
                    description: "Partner extranet".to_string(),
                    network_type: NetworkType::Extranet,
                    network_group: HostNetworkGroup::default(),
                },
            ],
            creation_time: fixture_creation_time(),
        }
    }

    #[test]
    fn customer_stored_value_backward_compatibility() -> anyhow::Result<()> {
        let expected = deterministic_fixture_customer();

        let decoded = Customer::from_key_value(expected.name.as_bytes(), CUSTOMER_STORED_VALUE_V0)?;
        assert_eq!(decoded.id, expected.id);
        assert_eq!(decoded.name, expected.name);
        assert_eq!(decoded.description, expected.description);
        assert_eq!(decoded.creation_time, expected.creation_time);
        assert_eq!(decoded.networks.len(), expected.networks.len());
        for (decoded_network, expected_network) in
            decoded.networks.iter().zip(expected.networks.iter())
        {
            assert_eq!(decoded_network.name, expected_network.name);
            assert_eq!(decoded_network.description, expected_network.description);
            assert!(
                decoded_network.network_type == expected_network.network_type,
                "network_type mismatch"
            );
            assert_eq!(
                decoded_network.network_group,
                expected_network.network_group
            );
        }

        let written = expected.value();
        assert_eq!(written.as_slice(), CUSTOMER_STORED_VALUE_V0);

        Ok(())
    }
}
