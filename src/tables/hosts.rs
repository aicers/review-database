//! The `hosts` table.

use std::{
    collections::HashMap,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use anyhow::Result;
use chrono::Utc;
use rocksdb::{Direction, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};

use crate::{
    Iterable, Map, Table, TidbRuleKind, UniqueKey, tables::Value as ValueTrait, types::FromKeyValue,
};

// IpAddr: (port, proto), used count
type OpenedPorts = HashMap<IpAddr, HashMap<(u16, u8), u32>>;

#[derive(Clone, Deserialize, Serialize)]
pub struct UserAgent {
    pub name: String,
    pub header: String,
    pub kind: TidbRuleKind,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Host {
    pub customer_id: u32,
    pub ip: IpAddr,
    pub creation_time: i64,
    pub opened_ports: HashMap<(u16, u8), u32>, // (port, proto), used count
    pub known_agents: Vec<UserAgent>,
    pub unknown_agents: Vec<String>,
}

/// Functions for the `hosts` table.
impl<'d> Table<'d, Host> {
    /// Opens the  `hosts` table in the database.
    ///
    /// Returns `None` if the table does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::HOSTS).map(Table::new)
    }

    /// Returns the `Host` with the given key.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn get(&self, customer_id: u32, ip: IpAddr) -> Result<Option<Host>> {
        let key = Key::new(customer_id, ip).to_bytes();
        self.map
            .get(&key)?
            .map(|v| Host::from_key_value(&key, v.as_ref()))
            .transpose()
    }

    /// Update opened ports to Hosts database
    ///
    /// # Errors
    ///
    /// * Returns an error if the Hosts database name does not match
    /// * Returns an error if it fails to encode Hosts database
    /// * Returns an error if it fails to delete or save Hosts database
    pub fn update_opened_ports(&self, customer_id: u32, entry: &OpenedPorts) -> Result<()> {
        for (ip, opened_ports) in entry {
            let host = match self.get(customer_id, *ip)? {
                Some(mut host_entry) => {
                    for (port_proto, count) in opened_ports {
                        let user_counts = host_entry.opened_ports.entry(*port_proto).or_default();
                        if *user_counts < *count {
                            *user_counts = *count;
                        }
                    }
                    host_entry
                }
                None => Host {
                    customer_id,
                    ip: *ip,
                    creation_time: Utc::now().timestamp_nanos_opt().unwrap_or_default(),
                    opened_ports: opened_ports.clone(),
                    known_agents: Vec::new(),
                    unknown_agents: Vec::new(),
                },
            };
            self.map.put(&host.unique_key(), &host.value())?;
        }
        Ok(())
    }

    /// Update OS and client software info to Hosts database
    ///
    /// # Errors
    ///
    /// * Returns an error if the Hosts database name does not match
    /// * Returns an error if it fails to encode Hosts database
    /// * Returns an error if it fails to delete or save Hosts database
    pub fn update_agents(
        &self,
        customer_id: u32,
        ip: IpAddr,
        known_agents: &Vec<UserAgent>,
        unknown_agents: &[String],
    ) -> Result<()> {
        let mut host = match self.get(customer_id, ip)? {
            Some(entry) => entry,
            None => Host {
                customer_id,
                ip,
                creation_time: Utc::now().timestamp_nanos_opt().unwrap_or_default(),
                opened_ports: HashMap::new(),
                known_agents: Vec::new(),
                unknown_agents: Vec::new(),
            },
        };

        for agent_info in known_agents {
            if !host.known_agents.iter().any(|a| a.name == agent_info.name) {
                host.known_agents.push(agent_info.clone());
            }
        }

        host.known_agents.sort_by(|a, b| a.name.cmp(&b.name));

        host.unknown_agents.extend(unknown_agents.iter().cloned());
        host.unknown_agents.sort();
        host.unknown_agents.dedup();

        self.map.put(&host.unique_key(), &host.value())?;
        Ok(())
    }

    /// Removes all Hosts db entries for the `customer_id`
    ///
    /// # Errors
    ///
    /// * Returns an error if it failes to remove value from database
    pub fn remove_by_customer_id(&self, customer_id: u32) -> Result<()> {
        let prefix = customer_id.to_be_bytes();
        let iter = self.prefix_iter(Direction::Forward, None, &prefix);
        for result in iter {
            let hosts = result?;
            self.map.delete(&hosts.unique_key())?;
        }
        Ok(())
    }

    /// Removes the Hosts db entry for the key(`customer_id` + `ip`)
    ///
    /// # Errors
    ///
    /// * Returns an error if it failes to remove value from database
    pub fn remove(&self, customer_id: u32, ip: IpAddr) -> Result<()> {
        let key = Key::new(customer_id, ip).to_bytes();
        self.map.delete(&key)
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct Value {
    creation_time: i64,
    opened_ports: HashMap<(u16, u8), u32>, // (port, proto), used count
    known_agents: Vec<UserAgent>,
    unknown_agents: Vec<String>,
}

impl ValueTrait for Host {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        super::serialize(&Value {
            creation_time: self.creation_time,
            opened_ports: self.opened_ports.clone(),
            known_agents: self.known_agents.clone(),
            unknown_agents: self.unknown_agents.clone(),
        })
        .expect("serializable")
    }
}

struct Key {
    customer_id: u32,
    ip: IpAddr,
}

impl FromKeyValue for Host {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self> {
        let key = Key::from_be_bytes(key);
        let host: Value = super::deserialize(value)?;
        Ok(Self {
            customer_id: key.customer_id,
            ip: key.ip,
            creation_time: host.creation_time,
            opened_ports: host.opened_ports,
            known_agents: host.known_agents,
            unknown_agents: host.unknown_agents,
        })
    }
}

impl UniqueKey for Host {
    type AsBytes<'a> = Vec<u8>;

    fn unique_key(&self) -> Vec<u8> {
        Key {
            customer_id: self.customer_id,
            ip: self.ip,
        }
        .to_bytes()
    }
}

impl Key {
    fn new(customer_id: u32, ip: IpAddr) -> Self {
        Self { customer_id, ip }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend(self.customer_id.to_be_bytes());

        match self.ip {
            IpAddr::V4(addr) => {
                buf.extend(addr.octets());
            }
            IpAddr::V6(addr) => {
                buf.extend(addr.octets());
            }
        }
        buf
    }

    pub fn from_be_bytes(buf: &[u8]) -> Self {
        let (val, rest) = buf.split_at(size_of::<u32>());
        let mut buf_u32 = [0; size_of::<u32>()];
        buf_u32.copy_from_slice(val);
        let customer_id = u32::from_be_bytes(buf_u32);

        let ip = if rest.len() == size_of::<Ipv6Addr>() {
            // IPv6
            let mut buf_ipv6 = [0; size_of::<Ipv6Addr>()];
            buf_ipv6.copy_from_slice(&rest[..size_of::<Ipv6Addr>()]);
            IpAddr::V6(Ipv6Addr::from(buf_ipv6))
        } else {
            // IPv4
            let mut buf_ipv4 = [0; size_of::<Ipv4Addr>()];
            buf_ipv4.copy_from_slice(&rest[..size_of::<Ipv4Addr>()]);
            IpAddr::V4(Ipv4Addr::from(buf_ipv4))
        };
        Self { customer_id, ip }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use super::*;
    use crate::Store;
    use crate::test::{DbGuard, acquire_db_permit};

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    #[test]
    fn test_update_opened_ports() {
        let (_permit, store) = setup_store();
        let hosts_table = store.hosts_map();

        let customer_id = 1;
        let ip1: IpAddr = Ipv4Addr::new(192, 168, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(192, 168, 0, 2).into();

        // Scenario 1: Add new hosts and ports
        let mut opened_ports_entry1 = HashMap::new();
        let mut ports_for_ip1 = HashMap::new();
        ports_for_ip1.insert((80, 6), 1); // (port, proto), (used_count, service_name)
        ports_for_ip1.insert((443, 6), 1);
        opened_ports_entry1.insert(ip1, ports_for_ip1);

        let mut ports_for_ip2 = HashMap::new();
        ports_for_ip2.insert((22, 6), 1);
        opened_ports_entry1.insert(ip2, ports_for_ip2);

        let rst = hosts_table.update_opened_ports(customer_id, &opened_ports_entry1);
        assert!(rst.is_ok());

        // Verify IP1
        let hosts_ip1 = hosts_table.get(customer_id, ip1);
        assert!(hosts_ip1.is_ok());
        let hosts_ip1 = hosts_ip1.unwrap().unwrap();
        assert_eq!(hosts_ip1.customer_id, customer_id);
        assert_eq!(hosts_ip1.ip, ip1);
        assert_eq!(hosts_ip1.opened_ports.len(), 2);
        assert_eq!(hosts_ip1.opened_ports.get(&(80, 6)).unwrap(), &1);
        assert_eq!(hosts_ip1.opened_ports.get(&(443, 6)).unwrap(), &1);

        // Verify IP2
        let hosts_ip2 = hosts_table.get(customer_id, ip2).unwrap().unwrap();
        assert_eq!(hosts_ip2.customer_id, customer_id);
        assert_eq!(hosts_ip2.ip, ip2);
        assert_eq!(hosts_ip2.opened_ports.len(), 1);
        assert_eq!(hosts_ip2.opened_ports.get(&(22, 6)).unwrap(), &1);

        // Scenario 2: Update existing hosts, add new ports, and update existing ports
        let mut opened_ports_entry2 = HashMap::new();
        let mut ports_for_ip1_update = HashMap::new();
        ports_for_ip1_update.insert((80, 6), 2); // Update existing port
        ports_for_ip1_update.insert((21, 6), 1); // Add new port
        opened_ports_entry2.insert(ip1, ports_for_ip1_update);

        hosts_table
            .update_opened_ports(customer_id, &opened_ports_entry2)
            .unwrap();

        // Verify IP1 after update
        let hosts_ip1_updated = hosts_table.get(customer_id, ip1).unwrap().unwrap();
        assert_eq!(hosts_ip1_updated.opened_ports.len(), 3); // 2 old + 1 new
        assert_eq!(hosts_ip1_updated.opened_ports.get(&(80, 6)).unwrap(), &2);
        assert_eq!(hosts_ip1_updated.opened_ports.get(&(443, 6)).unwrap(), &1);
        assert_eq!(hosts_ip1_updated.opened_ports.get(&(21, 6)).unwrap(), &1);

        // Ensure IP2 is unchanged
        let hosts_ip2_unchanged = hosts_table.get(customer_id, ip2).unwrap().unwrap();
        assert_eq!(hosts_ip2_unchanged.opened_ports.len(), 1);
        assert_eq!(hosts_ip2_unchanged.opened_ports.get(&(22, 6)).unwrap(), &1);
    }

    #[test]
    fn test_update_os_agents() {
        let (_permit, store) = setup_store();
        let hosts_table = store.hosts_map();

        let customer_id = 1;
        let ip1: IpAddr = Ipv4Addr::new(192, 168, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(192, 168, 0, 2).into();

        // Scenario 1: Add new hosts and OS agents
        let os_agents_entry1 = vec![
            UserAgent {
                name: "Firefox".to_string(),
                kind: TidbRuleKind::AgentSoftware,
                header: "Mozilla/5.0 (Firefox)".to_string(),
            },
            UserAgent {
                name: "Chrome".to_string(),
                kind: TidbRuleKind::AgentSoftware,
                header: "Mozilla/5.0 (Chrome)".to_string(),
            },
        ];
        let unknown_user_agents1 = vec!["Unknown1".to_string(), "Unknown2".to_string()];

        hosts_table
            .update_agents(customer_id, ip1, &os_agents_entry1, &unknown_user_agents1)
            .unwrap();

        // Verify IP1
        let hosts_ip1 = hosts_table.get(customer_id, ip1).unwrap().unwrap();
        assert_eq!(hosts_ip1.customer_id, customer_id);
        assert_eq!(hosts_ip1.ip, ip1);
        assert_eq!(hosts_ip1.known_agents.len(), 2);
        assert_eq!(
            hosts_ip1.known_agents.iter().fold(0, |sum, agent| {
                if ["Firefox", "Chrome"].contains(&agent.name.as_str()) {
                    sum + 1
                } else {
                    sum
                }
            }),
            2
        );
        assert_eq!(hosts_ip1.unknown_agents.len(), 2);
        assert!(hosts_ip1.unknown_agents.contains(&"Unknown1".to_string()));
        assert!(hosts_ip1.unknown_agents.contains(&"Unknown2".to_string()));

        // Scenario 2: Update existing hosts, add new agents, and update existing agents
        let os_agents_entry2 = vec![
            UserAgent {
                name: "Firefox".to_string(),
                kind: TidbRuleKind::AgentSoftware,
                header: "Mozilla/5.0 (Firefox Updated)".to_string(), // Updated user agent
            },
            UserAgent {
                name: "Edge".to_string(),
                kind: TidbRuleKind::AgentSoftware,
                header: "Mozilla/5.0 (Edge)".to_string(), // New agent
            },
        ];
        let unknown_user_agents2 = vec!["Unknown3".to_string()]; // New unknown agent

        hosts_table
            .update_agents(customer_id, ip1, &os_agents_entry2, &unknown_user_agents2)
            .unwrap();

        // Verify IP1 after update
        let hosts_ip1_updated = hosts_table.get(customer_id, ip1).unwrap().unwrap();
        assert_eq!(hosts_ip1_updated.known_agents.len(), 3); // 2 old + 1 new
        assert_eq!(
            hosts_ip1_updated.known_agents.iter().fold(0, |sum, agent| {
                if ["Firefox", "Chrome", "Edge"].contains(&agent.name.as_str()) {
                    sum + 1
                } else {
                    sum
                }
            }),
            3
        );
        assert_eq!(hosts_ip1_updated.unknown_agents.len(), 3); // 2 old + 1 new
        assert_eq!(
            hosts_ip1_updated
                .unknown_agents
                .iter()
                .fold(0, |sum, agent| {
                    if ["Unknown1", "Unknown2", "Unknown3"].contains(&agent.as_str()) {
                        sum + 1
                    } else {
                        sum
                    }
                }),
            3
        );

        // Ensure IP2 is unchanged (or created if it didn't exist)
        let os_agents_ip2 = Vec::new();
        let unknown_user_agents_ip2 = vec!["Unknown_IP2".to_string()];
        hosts_table
            .update_agents(customer_id, ip2, &os_agents_ip2, &unknown_user_agents_ip2)
            .unwrap();
        let hosts_ip2_unchanged = hosts_table.get(customer_id, ip2).unwrap().unwrap();
        assert_eq!(hosts_ip2_unchanged.known_agents.len(), 0);
        assert_eq!(hosts_ip2_unchanged.unknown_agents.len(), 1);
        assert!(
            hosts_ip2_unchanged
                .unknown_agents
                .contains(&"Unknown_IP2".to_string())
        );
    }

    #[test]
    fn test_remove_by_customer_id() {
        let (_permit, store) = setup_store();
        let hosts_table = store.hosts_map();

        let customer_id1 = 1;
        let customer_id2 = 2;

        let ip1: IpAddr = Ipv4Addr::new(192, 168, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(192, 168, 0, 2).into();
        let ip3: IpAddr = Ipv4Addr::new(192, 168, 0, 3).into();
        let ip4: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into();

        let mut entry1: OpenedPorts = HashMap::new();
        entry1.insert(ip1, HashMap::new());
        entry1.insert(ip2, HashMap::new());
        entry1.insert(ip4, HashMap::new());

        let mut entry2: OpenedPorts = HashMap::new();
        entry2.insert(ip1, HashMap::new());
        entry2.insert(ip3, HashMap::new());
        entry2.insert(ip4, HashMap::new());

        hosts_table
            .update_opened_ports(customer_id1, &entry1)
            .unwrap();
        hosts_table
            .update_opened_ports(customer_id2, &entry2)
            .unwrap();

        // Verify initial state
        assert!(hosts_table.get(customer_id1, ip1).unwrap().is_some());
        assert!(hosts_table.get(customer_id1, ip2).unwrap().is_some());
        assert!(hosts_table.get(customer_id2, ip1).unwrap().is_some());
        assert!(hosts_table.get(customer_id2, ip3).unwrap().is_some());
        assert!(hosts_table.get(customer_id1, ip4).unwrap().is_some());
        assert!(hosts_table.get(customer_id2, ip4).unwrap().is_some());

        // Remove hosts for customer_id1
        assert!(hosts_table.remove_by_customer_id(customer_id1).is_ok());

        // Verify customer_id1 hosts are removed
        assert!(hosts_table.get(customer_id1, ip1).unwrap().is_none());
        assert!(hosts_table.get(customer_id1, ip2).unwrap().is_none());
        assert!(hosts_table.get(customer_id1, ip4).unwrap().is_none());

        // Verify customer_id2 hosts remain
        assert!(hosts_table.get(customer_id2, ip1).unwrap().is_some());
        assert!(hosts_table.get(customer_id2, ip3).unwrap().is_some());
        assert!(hosts_table.get(customer_id2, ip4).unwrap().is_some());

        // Test removing a customer_id that doesn't exist
        hosts_table.remove_by_customer_id(999).unwrap();
        assert!(hosts_table.get(customer_id2, ip3).unwrap().is_some());
    }

    #[test]
    fn test_remove_by_customer_id_and_ip() {
        let (_permit, store) = setup_store();
        let hosts_table = store.hosts_map();

        let customer_id1 = 1;
        let customer_id2 = 2;

        let ip1: IpAddr = Ipv4Addr::new(192, 168, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(192, 168, 0, 2).into();
        let ip3: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into();

        let mut entry1: OpenedPorts = HashMap::new();
        entry1.insert(ip1, HashMap::new());
        entry1.insert(ip2, HashMap::new());
        entry1.insert(ip3, HashMap::new());

        let mut entry2: OpenedPorts = HashMap::new();
        entry2.insert(ip1, HashMap::new());

        hosts_table
            .update_opened_ports(customer_id1, &entry1)
            .unwrap();
        hosts_table
            .update_opened_ports(customer_id2, &entry2)
            .unwrap();

        // Verify initial state
        assert!(hosts_table.get(customer_id1, ip1).unwrap().is_some());
        assert!(hosts_table.get(customer_id1, ip2).unwrap().is_some());
        assert!(hosts_table.get(customer_id1, ip3).unwrap().is_some());
        assert!(hosts_table.get(customer_id2, ip1).unwrap().is_some());

        // Remove ip1 for customer_id1
        hosts_table.remove(customer_id1, ip1).unwrap();

        // Verify ip1 for customer_id1 is removed
        assert!(hosts_table.get(customer_id1, ip1).unwrap().is_none());

        // Verify other hosts remain
        assert!(hosts_table.get(customer_id1, ip2).unwrap().is_some());
        assert!(hosts_table.get(customer_id1, ip3).unwrap().is_some());
        assert!(hosts_table.get(customer_id2, ip1).unwrap().is_some());

        // Test removing a host that doesn't exist
        let ip4: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        hosts_table.remove(customer_id1, ip4).unwrap(); // Should not panic
        assert!(hosts_table.get(customer_id1, ip2).unwrap().is_some());
        assert!(hosts_table.get(customer_id2, ip1).unwrap().is_some());
    }
}
