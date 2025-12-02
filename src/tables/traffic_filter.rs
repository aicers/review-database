//! The `traffic_filter` map.

use std::collections::HashMap;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use rocksdb::{Direction, OptimisticTransactionDB};
use serde::{Deserialize, Serialize};

use super::Value;
use crate::{Iterable, Map, Table, UniqueKey, types::FromKeyValue};

#[derive(Clone, Deserialize, Serialize)]
pub struct TrafficFilter {
    pub agent: String,
    pub rules: HashMap<IpNet, ProtocolPorts>,
    pub last_modification_time: DateTime<Utc>,
    pub update_time: Option<DateTime<Utc>>,
    pub description: Option<String>,
}

impl FromKeyValue for TrafficFilter {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self> {
        super::deserialize(value)
    }
}

impl UniqueKey for TrafficFilter {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> &[u8] {
        self.agent.as_bytes()
    }
}

impl Value for TrafficFilter {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        super::serialize(self).expect("serializable")
    }
}

type RuleList = Vec<(IpNet, Option<Vec<u16>>, Option<Vec<u16>>)>;

impl TrafficFilter {
    #[must_use]
    pub fn new(
        agent: &str,
        net: IpNet,
        tcp_ports: Option<Vec<u16>>,
        udp_ports: Option<Vec<u16>>,
        description: Option<String>,
    ) -> Self {
        let mut rules = HashMap::new();
        rules.insert(
            net,
            ProtocolPorts {
                tcp_ports,
                udp_ports,
            },
        );
        Self {
            agent: agent.to_string(),
            rules,
            last_modification_time: Utc::now(),
            update_time: None,
            description,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    #[must_use]
    pub fn rules(&self) -> RuleList {
        self.rules
            .iter()
            .map(|(net, ports)| (*net, ports.tcp_ports().clone(), ports.udp_ports().clone()))
            .collect()
    }

    fn check_duplicate(&self, network: IpNet) -> Option<IpNet> {
        if network.addr().is_unspecified() && self.rules.contains_key(&network) {
            return Some(network);
        }
        self.rules
            .keys()
            .find(|net| {
                if net.addr().is_unspecified() {
                    false
                } else {
                    **net == network || net.contains(&network) || network.contains(*net)
                }
            })
            .copied()
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct ProtocolPorts {
    tcp_ports: Option<Vec<u16>>,
    udp_ports: Option<Vec<u16>>,
}

impl ProtocolPorts {
    fn update(&mut self, tcp_ports: Option<Vec<u16>>, udp_ports: Option<Vec<u16>>) {
        self.tcp_ports = tcp_ports;
        if let Some(tcp_ports) = &mut self.tcp_ports {
            tcp_ports.sort_unstable();
            tcp_ports.dedup();
        }

        self.udp_ports = udp_ports;
        if let Some(udp_ports) = &mut self.udp_ports {
            udp_ports.sort_unstable();
            udp_ports.dedup();
        }
    }

    #[must_use]
    pub fn tcp_ports(&self) -> &Option<Vec<u16>> {
        &self.tcp_ports
    }

    #[must_use]
    pub fn udp_ports(&self) -> &Option<Vec<u16>> {
        &self.udp_ports
    }
}

/// Functions for the `traffic_filter` map.
impl<'d> Table<'d, TrafficFilter> {
    /// Opens the  `traffic_filter` map in the database.
    ///
    /// Returns `None` if the map does not exist.
    pub(super) fn open(db: &'d OptimisticTransactionDB) -> Option<Self> {
        Map::open(db, super::TRAFFIC_FILTER_RULES).map(Table::new)
    }

    /// Returns `traffic_filter` given `agent`
    ///
    /// # Errors
    ///
    /// * Return an error if it fails to get rules from database
    /// * Return an error if it fails to decode rules
    pub fn get(&self, agent: &str) -> Result<Option<TrafficFilter>> {
        self.map
            .get(agent.as_bytes())?
            .map(|value| TrafficFilter::from_key_value(agent.as_bytes(), value.as_ref()))
            .transpose()
    }

    /// Returns `traffic_filter`s available in the database from `Some(agents)`
    /// or all the traffic filters in the database when None is supplied.
    ///
    /// # Errors
    ///
    /// * Return an error if it fails to open database
    /// * Return an error if it fails to decode rules
    pub fn get_list<S: AsRef<str>>(
        &self,
        agents: &Option<Vec<S>>,
    ) -> Result<Option<Vec<TrafficFilter>>> {
        let Some(agents) = agents else {
            return self
                .iter(Direction::Forward, None)
                .collect::<Result<Vec<_>>>()
                .map(|list| if list.is_empty() { None } else { Some(list) });
        };

        agents
            .iter()
            .filter_map(|agent| self.get(agent.as_ref()).transpose())
            .collect::<Result<Vec<_>>>()
            .map(|list| if list.is_empty() { None } else { Some(list) })
    }

    /// Adds new rules
    ///
    /// # Errors
    ///
    /// * Returns an error if duplicate rule is already exist in database
    /// * Returns an error if it fails to open database
    /// * Returns an error if it fails to encode rules
    /// * Returns an error if it fails to insert rule in database
    pub fn add_rules(
        &self,
        agent: &str,
        network: IpNet,
        tcp_ports: Option<Vec<u16>>,
        udp_ports: Option<Vec<u16>>,
        description: Option<String>,
    ) -> Result<usize> {
        let Some(mut entry) = self.get(agent)? else {
            let entry = TrafficFilter::new(agent, network, tcp_ports, udp_ports, description);
            return self.put(&entry).map(|()| entry.len());
        };
        if let Some(net) = entry.check_duplicate(network) {
            bail!("Duplicate rule found. \"{net}\"");
        }
        entry.rules.insert(
            network,
            ProtocolPorts {
                tcp_ports,
                udp_ports,
            },
        );
        entry.last_modification_time = Utc::now();
        self.put(&entry).map(|()| entry.len())
    }

    /// Updates ports or description of network
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to open database
    /// * Returns an error if agent is not exist in database
    /// * Returns an error if network of agent is not exist in the rules of agent
    /// * Returns an error if it fails to write updated rules in database
    pub fn update(
        &self,
        agent: &str,
        network: IpNet,
        tcp_ports: Option<Vec<u16>>,
        udp_ports: Option<Vec<u16>>,
        description: Option<String>,
    ) -> Result<usize> {
        let Some(mut entry) = self.get(agent)? else {
            bail!("Agent not found");
        };
        if let Some(ports) = entry.rules.get_mut(&network) {
            ports.update(tcp_ports, udp_ports);
            if let Some(description) = description {
                entry.description = Some(description);
            }
            entry.last_modification_time = Utc::now();
        } else {
            bail!("Rule not found");
        }
        self.put(&entry).map(|()| entry.len())
    }

    /// Removes some rules. Agent will be removed if rules is empty
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to open database
    /// * Returns an error if rule is not exist
    /// * Returns an error if it fails to write updated rules in database
    pub fn remove_rules(&self, agent: &str, networks: &[IpNet]) -> Result<usize> {
        let Some(mut entry) = self.get(agent)? else {
            return Ok(0);
        };
        for network in networks {
            _ = entry.rules.remove(network); // ignore when the network doesn't exist
        }
        entry.last_modification_time = Utc::now();
        if entry.rules.is_empty() {
            self.remove(agent).map(|()| 0)
        } else {
            self.put(&entry).map(|()| entry.len())
        }
    }

    /// Updates `update_time` for given `agent`
    ///
    /// # Errors
    ///
    /// * Returns an error if it fails to open database
    /// * Returns an error if rule is not exist
    /// * Returns an error if it fails to write updated rules in database
    pub fn update_time(&self, agent: &str) -> Result<()> {
        let Some(mut entry) = self.get(agent)? else {
            return Ok(());
        };
        entry.update_time = Some(Utc::now());

        self.put(&entry)
    }

    /// Removes a `traffic_filter` with the given `agent`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn remove(&self, agent: &str) -> Result<()> {
        self.map.delete(agent.as_bytes())
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use rocksdb::Direction;

    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{Iterable, Store, TrafficFilter};

    #[test]
    fn insert_get_remove() {
        let (_permit, store) = setup_store();
        let table = store.traffic_filter_map();

        assert_eq!(table.iter(Direction::Forward, None).count(), 0);

        let agent = "piglet@node1";
        let network = "172.30.1.0/24";
        let tcp_ports = Some(vec![80, 8000]);

        let entry = create_entry(agent, network, tcp_ports);

        assert!(table.insert(&entry).is_ok());
        assert_eq!(table.iter(Direction::Forward, None).count(), 1);

        let res = table.get(agent);
        assert!(res.is_ok());
        if let Ok(tf) = res {
            assert!(tf.is_some());
            if let Some(tf) = tf {
                assert!(tf.update_time.is_none());
                assert_eq!(&tf.agent, agent);
                assert!(tf.rules.contains_key(&network.parse().unwrap()));
            }
        }

        let res = table.get_list(&Option::<Vec<String>>::None);
        assert!(res.is_ok());
        assert_eq!(res.unwrap().map(|r| r.len()), Some(1));

        assert_eq!(table.remove_rules("something else", &[]).ok(), Some(0));
        assert_eq!(
            table.remove_rules(agent, &[network.parse().unwrap()]).ok(),
            Some(0)
        );
        assert_eq!(table.iter(Direction::Forward, None).count(), 0);
    }

    #[test]
    fn check_duplicate_update() {
        let (_permit, store) = setup_store();
        let table = store.traffic_filter_map();

        assert!(table.get("unknown_host").unwrap().is_none());

        let agent = "node1";
        let any = "0.0.0.0/0";
        let tcp = Some(vec![80, 8000]);
        let entry = create_entry(agent, any, tcp.clone());
        assert!(table.insert(&entry).is_ok());

        assert!(
            table
                .add_rules(agent, any.parse().unwrap(), Some(vec![80]), None, None)
                .is_err()
        );

        let network = "172.30.0.0/16".parse().unwrap();
        assert!(table.add_rules(agent, network, tcp, None, None).is_ok());

        let new_tcp_ports = vec![8080, 8888];
        let subnet_network = "172.30.1.0/24".parse().unwrap();
        assert!(
            table
                .add_rules(
                    agent,
                    subnet_network,
                    Some(new_tcp_ports.clone()),
                    None,
                    None
                )
                .is_err()
        );

        assert!(
            table
                .update(agent, network, Some(new_tcp_ports), None, None)
                .is_ok()
        );

        let r = table.get(agent);
        assert!(r.is_ok());
        if let Ok(Some(tf)) = r
            && let Some(rule) = tf.rules.get(&network)
        {
            assert_eq!(rule.tcp_ports, Some(vec![8080, 8888]));
        }
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        (permit, store)
    }

    fn create_entry(name: &str, network: &str, tcp_ports: Option<Vec<u16>>) -> TrafficFilter {
        TrafficFilter::new(name, network.parse().unwrap(), tcp_ports, None, None)
    }
}
