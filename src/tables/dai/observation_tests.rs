//! Tests of the DAI observation, cursor and restore tables.

use std::{
    net::IpAddr,
    sync::{Arc, RwLock},
};

use review_protocol::types::{
    DaiDhcpMsg, DaiLateSlot, DaiObservation, DaiObservationBatch, DaiObservationBody,
    DaiObservationKind as Kind, DaiReextractMark, DaiSide, DaiSoftwareSource,
    HostNetworkGroup as ProtocolGroup,
};
use tempfile::TempDir;

use super::cursor::{CursorRow, DAY, date_of, pair_key, slot_floor};
use super::hash::identifier_hash;
use super::observation::{
    ActivityRow, DaiCounterKind, ObservationRow, SeenRow, decode_observation_key,
    decode_pending_key, summary_key,
};
use super::*;
use crate::test::{DbGuard, acquire_db_permit};
use crate::{
    Agent, AgentKind, AgentStatus, DaiBatchError, DaiStoreOutcome, HostNetworkGroup, Node,
    NodeProfile, OwnedNetwork, OwnedNetworkSet, OwnedNetworkTable, Store, dai_network_digest,
    event::NetworkType,
};

const NS: i64 = 1_000_000_000;
const MINUTE: i64 = 60 * NS;
const HOUR: i64 = 60 * MINUTE;
/// "12:00", a slot boundary: 1,700,000,100 is a multiple of 300.
const NOON: i64 = 1_700_000_100 * NS;
const CUSTOMER: u32 = 1;
const OTHER: u32 = 2;
const A: &str = "piglet.a.example";
const B: &str = "piglet.b.example";
/// A sensor of [`CUSTOMER`] that moves to [`OTHER`] in a deletion test.
const C: &str = "piglet.c.example";
/// The sensor of [`OTHER`].
const D: &str = "piglet.d.example";
/// A sensor of [`CUSTOMER`] whose node a deletion test removes.
const GONE: &str = "piglet.g.example";
/// A name nodes of both customers give, so not a customer sensor.
const SHARED: &str = "piglet.s.example";
/// The DAI column families.
const FAMILIES: [&str; 18] = [
    super::super::DAI_CUSTOMER_SETTINGS,
    super::super::DAI_RELAY_SITES,
    super::super::DAI_SENSOR_SITES,
    super::super::DAI_SENSOR_STATE,
    super::super::DAI_SITE_POLICY_GUARD,
    super::super::DAI_SITES,
    super::super::DAI_META,
    super::super::DAI_CURSORS,
    super::super::DAI_SLOT_SENDS,
    super::super::DAI_SEND_PARTS,
    super::super::DAI_CATCHUP_GAPS,
    super::super::DAI_SENSOR_KIND_STATE,
    super::super::DAI_COUNTERS,
    super::super::DAI_EARLIEST_PENDING,
    super::super::DAI_OBSERVATIONS,
    super::super::DAI_OBSERVATION_SUMMARIES,
    super::super::DAI_PENDING,
    super::super::DAI_IP_ACTIVITY,
];

/// Returns the time `minutes` after [`NOON`].
fn at(minutes: i64) -> i64 {
    NOON + minutes * MINUTE
}

fn ip(addr: &str) -> IpAddr {
    addr.parse().unwrap()
}

fn agent(key: &str, kind: AgentKind) -> Agent {
    let mut agent = Agent::new(0, key.to_string(), kind, AgentStatus::Enabled, None, None).unwrap();
    agent.instance = Some(1);
    agent
}

fn node(name: &str, customer_id: u32, hostname: &str) -> Node {
    Node {
        id: 0,
        name: name.to_string(),
        name_draft: None,
        profile: Some(NodeProfile {
            customer_id,
            description: String::new(),
            hostname: hostname.to_string(),
        }),
        profile_draft: None,
        agents: vec![agent("piglet", AgentKind::Sensor)],
        external_services: Vec::new(),
        creation_time: jiff::Timestamp::now(),
    }
}

fn network(name: &str, network_type: NetworkType, group: HostNetworkGroup) -> OwnedNetwork {
    OwnedNetwork {
        name: name.to_string(),
        network_type,
        group,
    }
}

fn cidr_group(cidrs: &[&str]) -> HostNetworkGroup {
    HostNetworkGroup::new(
        Vec::new(),
        cidrs.iter().map(|cidr| cidr.parse().unwrap()).collect(),
        Vec::new(),
    )
}

fn settings_update(enabled: bool) -> DaiSettingsUpdate {
    DaiSettingsUpdate {
        device_account_identification: enabled,
        inactivity_multiplier: 2,
        no_lease_inactivity_secs: 3600,
        evidence_aging_secs: 86_400,
        kerberos_preauth_realms: Vec::new(),
    }
}

/// Fills a store with the nodes of the sensors [`A`], [`B`], [`C`] and
/// [`GONE`] of [`CUSTOMER`], [`D`] of [`OTHER`], and [`SHARED`] of both,
/// gives [`CUSTOMER`] an `Intranet` network, and turns [`CUSTOMER`] on at
/// `enabled_at`.
fn populate(store: &Store, enabled_at: i64) {
    for (name, customer, host) in [
        ("a", CUSTOMER, "a.example"),
        ("b", CUSTOMER, "b.example"),
        ("c", CUSTOMER, "c.example"),
        ("g", CUSTOMER, "g.example"),
        ("d", OTHER, "d.example"),
        ("s1", CUSTOMER, "s.example"),
        ("s2", OTHER, "s2.example"),
    ] {
        store.node_map().put(&node(name, customer, host)).unwrap();
    }
    // The node table refuses a hostname in use, so the second node giving
    // the shared name is written as a stored row would hold it.
    let db = store.states.db();
    let nodes = db.cf_handle(super::super::NODES).unwrap();
    for entry in db.iterator_cf(nodes, rocksdb::IteratorMode::Start) {
        let (key, value) = entry.unwrap();
        if key.is_empty() {
            continue;
        }
        let mut inner: crate::tables::InnerNode = super::super::deserialize(&value).unwrap();
        if inner.name == "s2" {
            inner.profile.as_mut().unwrap().hostname = "s.example".to_string();
            db.put_cf(nodes, key, super::super::serialize(&inner).unwrap())
                .unwrap();
        }
    }
    store
        .customer_networks_map()
        .replace(
            CUSTOMER,
            1,
            vec![network(
                "intranet",
                NetworkType::Intranet,
                cidr_group(&["10.0.0.0/8"]),
            )],
        )
        .unwrap();
    store
        .states
        .dai()
        .set_settings(CUSTOMER, 0, &settings_update(true), &enabled_at)
        .unwrap();
}

struct Fixture {
    store: Store,
    _permit: DbGuard<'static>,
    _dirs: (TempDir, TempDir),
}

/// A store [`populate`]d with [`CUSTOMER`] turned on an hour before
/// [`NOON`].
fn setup() -> Fixture {
    let permit = acquire_db_permit();
    let data = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    let store = Store::new(data.path(), backup.path(), None).unwrap();
    populate(&store, at(-60));
    Fixture {
        store,
        _permit: permit,
        _dirs: (data, backup),
    }
}

impl Fixture {
    fn dai(&self) -> Dai<'_> {
        self.store.states.dai()
    }

    fn set_enabled(&self, customer: u32, enabled: bool, now: i64) {
        set_enabled(&self.dai(), customer, enabled, now);
    }

    fn cursors(&self, sensors: &[&str], now: i64) -> review_protocol::types::DaiCursors {
        let sensors: Vec<String> = sensors.iter().map(ToString::to_string).collect();
        self.store.dai_cursors(&sensors, now).unwrap()
    }

    fn row(&self, sensor: &str, kind: Kind) -> Option<CursorRow> {
        let dai = self.dai();
        dai.read(|txn| dai.cursor_in(txn, sensor, kind)).unwrap()
    }

    /// Returns a one-part send of `observations` in the slot starting at
    /// `slot_start`, counted from the slot start, with the current check
    /// values of `sensor`.
    fn batch(
        &self,
        sensor: &str,
        kind: Kind,
        slot_start: i64,
        observations: Vec<DaiObservation>,
    ) -> DaiObservationBatch {
        let dai = self.dai();
        let customer = dai
            .read(|txn| Ok(dai.customer_sensors_in(txn)?.customer(sensor)))
            .unwrap();
        let networks = customer.and_then(|c| self.store.customer_networks_map().get(c).unwrap());
        DaiObservationBatch {
            restore_generation: self.store.dai_restore_generation().unwrap(),
            config_epoch: self.store.dai_sensor_config_epoch(sensor).unwrap(),
            network_digest: dai_network_digest(networks.as_ref()).unwrap().digest,
            sensor: sensor.to_string(),
            kind,
            slot_start,
            slot_len_secs: 300,
            send_id: rand::random(),
            part: 0,
            part_count: 1,
            observations,
            last_record_time: None,
            late_slots: Vec::new(),
            reextract_mark: None,
            lost_before: None,
            counted_from: slot_start,
        }
    }

    fn store(&self, batch: &DaiObservationBatch, now: i64) -> DaiStoreOutcome {
        self.store.store_dai_observations(batch, now).unwrap()
    }

    /// Stores `batch` and asserts it finished.
    fn stored(&self, batch: &DaiObservationBatch, now: i64) -> Vec<DaiReextractMark> {
        match self.store(batch, now) {
            DaiStoreOutcome::Stored { marks, .. } => marks,
            other => panic!("not stored: {other:?}"),
        }
    }

    fn generation(&self) -> u64 {
        self.store.dai_restore_generation().unwrap()
    }

    fn rows(&self, family: &str) -> Vec<RawRow> {
        let txn = self.store.states.db().transaction();
        let map = Map::open(self.store.states.db(), family).unwrap();
        Dai::scan(&map, &txn, &[]).unwrap()
    }

    /// Returns every row of the DAI families.
    fn dump(&self) -> Vec<Vec<RawRow>> {
        FAMILIES.iter().map(|family| self.rows(family)).collect()
    }

    fn observations(&self) -> Vec<(String, Kind, i64, ObservationRow)> {
        self.rows(super::super::DAI_OBSERVATIONS)
            .into_iter()
            .map(|(key, value)| {
                let (sensor, kind, slot, _) = decode_observation_key(&key).unwrap();
                (
                    sensor,
                    kind,
                    slot,
                    super::super::deserialize(&value).unwrap(),
                )
            })
            .collect()
    }

    fn pending(&self) -> Vec<(String, i64, Kind, SeenRow)> {
        self.rows(super::super::DAI_PENDING)
            .into_iter()
            .map(|(key, value)| {
                let (sensor, slot, kind, _) = decode_pending_key(&key).unwrap();
                (
                    sensor,
                    slot,
                    kind,
                    super::super::deserialize(&value).unwrap(),
                )
            })
            .collect()
    }

    fn summaries(&self) -> Vec<SeenRow> {
        self.rows(super::super::DAI_OBSERVATION_SUMMARIES)
            .into_iter()
            .map(|(_, value)| super::super::deserialize(&value).unwrap())
            .collect()
    }

    fn earliest(&self, sensor: &str, kind: Kind) -> Option<i64> {
        let dai = self.dai();
        dai.read(|txn| Dai::get_row(txn, &dai.earliest_pending, &pair_key(sensor, kind)))
            .unwrap()
    }

    fn gaps(&self, sensor: &str, kind: Kind) -> Vec<(i64, i64)> {
        let dai = self.dai();
        dai.read(|txn| dai.gaps_in(txn, sensor, kind)).unwrap()
    }

    fn counter(&self, customer: u32, counter: DaiCounterKind, now: i64) -> u64 {
        self.dai().counter(customer, counter, date_of(now).unwrap())
    }

    fn sensor_state(&self, sensor: &str) -> SensorState {
        let dai = self.dai();
        dai.read(|txn| dai.sensor_state_for_update(txn, sensor))
            .unwrap()
    }

    /// Deletes every pending row and earliest pending slot, as applying
    /// them would.
    fn clear_pending(&self) {
        let dai = self.dai();
        dai.write(|txn| {
            for map in [&dai.pending, &dai.earliest_pending] {
                for (key, _) in Dai::scan(map, txn, &[])? {
                    txn.delete_cf(map.cf, key)?;
                }
            }
            Ok(())
        })
        .unwrap();
    }
}

fn set_enabled(dai: &Dai<'_>, customer: u32, enabled: bool, now: i64) {
    let revision = dai.settings(customer).unwrap().revision;
    dai.set_settings(customer, revision, &settings_update(enabled), &now)
        .unwrap();
}

fn dns(name: &str, first: i64, last: i64, count: u32) -> DaiObservation {
    DaiObservation {
        first_seen: first,
        last_seen: last,
        count,
        body: DaiObservationBody::DnsName {
            name: name.to_string(),
            ip: ip("10.0.0.1"),
        },
    }
}

fn lease_body(time: i64, hostname: Option<&str>) -> DaiObservationBody {
    DaiObservationBody::DhcpLease {
        time,
        msg: DaiDhcpMsg::Ack,
        ip: ip("10.0.0.5"),
        chaddr: vec![0, 1, 2, 3, 4, 5],
        xid: 7,
        server_ip: ip("10.0.0.254"),
        server_id: None,
        giaddr: ip("0.0.0.0"),
        client_id: None,
        hostname: hostname.map(ToString::to_string),
        lease_secs: None,
        subnet_mask: None,
        routers: Vec::new(),
    }
}

fn lease(time: i64, hostname: Option<&str>) -> DaiObservation {
    DaiObservation {
        first_seen: time,
        last_seen: time,
        count: 1,
        body: lease_body(time, hostname),
    }
}

fn activity(addr: &str, first: i64, last: i64) -> DaiObservation {
    DaiObservation {
        first_seen: first,
        last_seen: last,
        count: 1,
        body: DaiObservationBody::IpActivity {
            ip: ip(addr),
            side: DaiSide::Client,
        },
    }
}

fn kerberos(first: i64, last: i64) -> DaiObservation {
    DaiObservation {
        first_seen: first,
        last_seen: last,
        count: 1,
        body: DaiObservationBody::Kerberos {
            client_ip: ip("10.0.0.2"),
            realm: "EXAMPLE.COM".to_string(),
            cname: vec!["alice".to_string()],
            sname: vec!["krbtgt".to_string()],
            msg_type: 10,
            accepted: true,
            preauth: 2,
            error_code: None,
        },
    }
}

fn late(kind: Kind, slot_start: i64, delay_ns: i64) -> DaiLateSlot {
    DaiLateSlot {
        kind,
        slot_start,
        delay_ns,
    }
}

fn batch_error(error: &anyhow::Error) -> &DaiBatchError {
    error
        .downcast_ref::<DaiBatchError>()
        .unwrap_or_else(|| panic!("not a DAI batch error: {error:#}"))
}

// ---- Hashes ----

/// Returns the identifier hash by the documented formula.
fn expected_hash<T: serde::Serialize>(identifier: &T) -> [u8; 16] {
    let encoded = bincode2::serde::encode_to_vec(identifier, bincode2::config::standard()).unwrap();
    let sha = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &encoded);
    *sha.as_ref().first_chunk::<16>().unwrap()
}

#[test]
fn the_identifier_hash_covers_the_identifier_fields_only() {
    let lease = lease_body(at(1), None);
    let DaiObservationBody::DhcpLease {
        time,
        msg,
        ip: addr,
        chaddr,
        xid,
        server_ip,
        server_id,
        giaddr,
        ..
    } = lease.clone()
    else {
        unreachable!()
    };
    assert_eq!(
        identifier_hash(&lease).unwrap(),
        expected_hash(&(time, msg, addr, chaddr, xid, server_ip, server_id, giaddr))
    );
    let dns_body = DaiObservationBody::DnsName {
        name: "host".to_string(),
        ip: ip("10.0.0.1"),
    };
    assert_eq!(
        identifier_hash(&dns_body).unwrap(),
        expected_hash(&("host", ip("10.0.0.1")))
    );

    // The value fields leave it as it is.
    let hash = identifier_hash(&lease).unwrap();
    let mut filled = lease.clone();
    if let DaiObservationBody::DhcpLease {
        client_id,
        hostname,
        lease_secs,
        subnet_mask,
        routers,
        ..
    } = &mut filled
    {
        *client_id = Some(vec![9]);
        *hostname = Some("host".to_string());
        *lease_secs = Some(3600);
        *subnet_mask = Some(ip("255.255.255.0"));
        *routers = vec![ip("10.0.0.254")];
    }
    assert_eq!(identifier_hash(&filled).unwrap(), hash);
    let service = |external_client| DaiObservationBody::Service {
        server_ip: ip("10.0.0.3"),
        port: 443,
        proto: 6,
        external_client,
    };
    assert_eq!(
        identifier_hash(&service(false)).unwrap(),
        identifier_hash(&service(true)).unwrap()
    );
}

/// A change of an observation body, for the tests.
type Edit = Box<dyn Fn(&mut DaiObservationBody)>;

#[test]
#[allow(clippy::too_many_lines)] // One scenario, checked step by step.
fn every_identifier_field_changes_the_identifier_hash() {
    let lease = lease_body(at(1), None);
    let hash = identifier_hash(&lease).unwrap();
    let service = |external_client| DaiObservationBody::Service {
        server_ip: ip("10.0.0.3"),
        port: 443,
        proto: 6,
        external_client,
    };
    let edits: Vec<Edit> = vec![
        Box::new(|b| {
            if let DaiObservationBody::DhcpLease { time, .. } = b {
                *time += 1;
            }
        }),
        Box::new(|b| {
            if let DaiObservationBody::DhcpLease { msg, .. } = b {
                *msg = DaiDhcpMsg::Release;
            }
        }),
        Box::new(|b| {
            if let DaiObservationBody::DhcpLease { ip: addr, .. } = b {
                *addr = ip("10.0.0.6");
            }
        }),
        Box::new(|b| {
            if let DaiObservationBody::DhcpLease { chaddr, .. } = b {
                chaddr.push(6);
            }
        }),
        Box::new(|b| {
            if let DaiObservationBody::DhcpLease { xid, .. } = b {
                *xid += 1;
            }
        }),
        Box::new(|b| {
            if let DaiObservationBody::DhcpLease { server_ip, .. } = b {
                *server_ip = ip("10.0.0.253");
            }
        }),
        Box::new(|b| {
            if let DaiObservationBody::DhcpLease { server_id, .. } = b {
                *server_id = Some(ip("10.0.0.254"));
            }
        }),
        Box::new(|b| {
            if let DaiObservationBody::DhcpLease { giaddr, .. } = b {
                *giaddr = ip("10.1.0.1");
            }
        }),
    ];
    for edit in &edits {
        let mut changed = lease.clone();
        edit(&mut changed);
        assert_ne!(changed, lease);
        assert_ne!(identifier_hash(&changed).unwrap(), hash, "{changed:?}");
    }
    assert_ne!(
        identifier_hash(&service(false)).unwrap(),
        identifier_hash(&DaiObservationBody::Service {
            server_ip: ip("10.0.0.3"),
            port: 80,
            proto: 6,
            external_client: false,
        })
        .unwrap()
    );
    let software = |text: &str, side| DaiObservationBody::SoftwareString {
        ip: ip("10.0.0.3"),
        side,
        source: DaiSoftwareSource::Ssh,
        text: text.to_string(),
    };
    let base = identifier_hash(&software("a", DaiSide::Client)).unwrap();
    assert_ne!(
        identifier_hash(&software("b", DaiSide::Client)).unwrap(),
        base
    );
    assert_ne!(
        identifier_hash(&software("a", DaiSide::Server)).unwrap(),
        base
    );
    let ntlm = |user: &str, success| DaiObservationBody::Ntlm {
        ip: ip("10.0.0.3"),
        workstation: "ws".to_string(),
        user: user.to_string(),
        domain: "d".to_string(),
        success,
    };
    let base = identifier_hash(&ntlm("u", true)).unwrap();
    assert_ne!(identifier_hash(&ntlm("v", true)).unwrap(), base);
    assert_ne!(identifier_hash(&ntlm("u", false)).unwrap(), base);
    let server = |server_id| DaiObservationBody::DhcpServer {
        server_ip: ip("10.0.0.3"),
        server_id,
    };
    assert_ne!(
        identifier_hash(&server(None)).unwrap(),
        identifier_hash(&server(Some(ip("10.0.0.3")))).unwrap()
    );
    assert_ne!(
        identifier_hash(&activity("10.0.0.1", 0, 0).body).unwrap(),
        identifier_hash(&activity("10.0.0.2", 0, 0).body).unwrap()
    );
    let mut realm = kerberos(0, 0).body;
    if let DaiObservationBody::Kerberos { realm: r, .. } = &mut realm {
        *r = "OTHER".to_string();
    }
    assert_ne!(
        identifier_hash(&kerberos(0, 0).body).unwrap(),
        identifier_hash(&realm).unwrap()
    );
}

fn set_of(networks: Vec<OwnedNetwork>) -> OwnedNetworkSet {
    OwnedNetworkSet {
        revision: 1,
        networks,
        updated_at: jiff::Timestamp::now(),
    }
}

fn digest(networks: Vec<OwnedNetwork>) -> u64 {
    dai_network_digest(Some(&set_of(networks))).unwrap().digest
}

#[test]
fn the_network_digest_follows_the_documented_formula() {
    let set = set_of(vec![
        network(
            "intranet",
            NetworkType::Intranet,
            HostNetworkGroup::new(
                vec![ip("10.0.0.9"), ip("10.0.0.1")],
                vec!["10.1.0.0/16".parse().unwrap()],
                vec![ip("10.2.0.1")..=ip("10.2.0.9")],
            ),
        ),
        network(
            "gateway",
            NetworkType::Gateway,
            HostNetworkGroup::new(vec![ip("10.0.0.1")], Vec::new(), Vec::new()),
        ),
        network(
            "extranet",
            NetworkType::Extranet,
            HostNetworkGroup::new(
                vec![ip("192.0.2.1")],
                vec!["198.51.100.0/24".parse().unwrap()],
                Vec::new(),
            ),
        ),
    ]);
    let networks = dai_network_digest(Some(&set)).unwrap();
    assert_eq!(networks.internal.hosts, [ip("10.0.0.1"), ip("10.0.0.9")]);
    assert_eq!(
        networks.internal.networks,
        ["10.1.0.0/16".parse::<ipnet::IpNet>().unwrap()]
    );
    assert_eq!(
        networks.internal.ip_ranges,
        [ip("10.2.0.1")..=ip("10.2.0.9")]
    );
    assert_eq!(
        networks.registered.hosts,
        [ip("10.0.0.1"), ip("10.0.0.9"), ip("192.0.2.1")]
    );
    assert_eq!(networks.registered.networks.len(), 2);

    let encoded = bincode2::serde::encode_to_vec(
        (&networks.internal, &networks.registered),
        bincode2::config::standard(),
    )
    .unwrap();
    let sha = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &encoded);
    let expected = u64::from_le_bytes(*sha.as_ref().first_chunk::<8>().unwrap());
    assert_eq!(networks.digest, expected);

    // No row: two empty groups and their digest.
    let none = dai_network_digest(None).unwrap();
    assert_eq!(none.internal, ProtocolGroup::default());
    assert_eq!(none.registered, ProtocolGroup::default());
    let encoded = bincode2::serde::encode_to_vec(
        (&none.internal, &none.registered),
        bincode2::config::standard(),
    )
    .unwrap();
    let sha = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &encoded);
    assert_eq!(
        none.digest,
        u64::from_le_bytes(*sha.as_ref().first_chunk::<8>().unwrap())
    );
    assert_eq!(digest(Vec::new()), none.digest);
}

#[test]
fn the_network_digest_depends_only_on_the_groups() {
    let intranet = |name: &str, hosts: &[&str]| {
        network(
            name,
            NetworkType::Intranet,
            HostNetworkGroup::new(
                hosts.iter().map(|h| ip(h)).collect(),
                vec!["10.1.0.0/16".parse().unwrap()],
                Vec::new(),
            ),
        )
    };
    let extranet = || {
        network(
            "partner",
            NetworkType::Extranet,
            cidr_group(&["198.51.100.0/24"]),
        )
    };
    let base = digest(vec![intranet("lan", &["10.0.0.1", "10.0.0.2"]), extranet()]);

    // The order of networks and of the lists inside them.
    assert_eq!(
        digest(vec![extranet(), intranet("lan", &["10.0.0.2", "10.0.0.1"])]),
        base
    );
    // Renaming a network.
    assert_eq!(
        digest(vec![
            intranet("office", &["10.0.0.1", "10.0.0.2"]),
            extranet()
        ]),
        base
    );
    // A network whose entries already appear in the groups it joins.
    assert_eq!(
        digest(vec![
            intranet("lan", &["10.0.0.1", "10.0.0.2"]),
            extranet(),
            intranet("again", &["10.0.0.1"]),
        ]),
        base
    );
    // Moving a network between Intranet and Gateway.
    let mut gateway = intranet("lan", &["10.0.0.1", "10.0.0.2"]);
    gateway.network_type = NetworkType::Gateway;
    assert_eq!(digest(vec![gateway, extranet()]), base);

    // A change of either group.
    assert_ne!(
        digest(vec![intranet("lan", &["10.0.0.1", "10.0.0.3"]), extranet()]),
        base
    );
    assert_ne!(
        digest(vec![
            intranet("lan", &["10.0.0.1", "10.0.0.2"]),
            network(
                "partner",
                NetworkType::Extranet,
                cidr_group(&["203.0.113.0/24"])
            ),
        ]),
        base
    );
    // Moving a network between internal and registered only.
    let mut moved = intranet("lan", &["10.0.0.1", "10.0.0.2"]);
    moved.network_type = NetworkType::Extranet;
    assert_ne!(digest(vec![moved, extranet()]), base);
}

// ---- Cursors ----

#[test]
fn a_cursor_read_creates_the_missing_rows() {
    let f = setup();
    let cursors = f.cursors(&[B, A, "piglet.unknown", SHARED, D], at(1));
    assert_eq!(cursors.restore_generation, f.generation());
    assert!(cursors.range_days.is_empty(), "{:?}", cursors.range_days);
    let expected: Vec<(String, Kind)> = [A, B, D]
        .iter()
        .flat_map(|sensor| KINDS.map(|kind| (sensor.to_string(), kind)))
        .collect();
    let got: Vec<(String, Kind)> = cursors
        .entries
        .iter()
        .map(|entry| (entry.sensor.clone(), entry.kind))
        .collect();
    assert_eq!(got, expected);
    for entry in &cursors.entries {
        assert_eq!(entry.read_floor, at(1));
        assert_eq!(entry.cursor, at(0));
        assert!(entry.reextract.is_empty(), "{:?}", entry.reextract);
    }
    assert_eq!(f.store.dai_first_cursor_time(A).unwrap(), Some(at(1)));
    assert_eq!(f.store.dai_first_cursor_time(D).unwrap(), Some(at(1)));
    assert_eq!(f.store.dai_first_cursor_time(SHARED).unwrap(), None);

    // A later read returns the same rows and keeps the first cursor time.
    let again = f.cursors(&[A, B, D], at(7));
    assert_eq!(again, cursors);
    assert_eq!(f.store.dai_first_cursor_time(A).unwrap(), Some(at(1)));
}

#[test]
fn a_creation_takes_the_later_last_enabled_time() {
    let f = setup();
    f.set_enabled(OTHER, true, at(20));
    let cursors = f.cursors(&[A, D], at(10));
    for entry in &cursors.entries {
        let expected = if entry.sensor == D { at(20) } else { at(10) };
        assert_eq!(entry.read_floor, expected, "{entry:?}");
        assert_eq!(entry.cursor, expected);
    }
    // A disabled customer's last-enabled time is not used.
    f.set_enabled(CUSTOMER, false, at(30));
    f.set_enabled(CUSTOMER, true, at(40));
    f.set_enabled(CUSTOMER, false, at(41));
    let cursors = f.cursors(&[B], at(32));
    assert!(cursors.entries.iter().all(|e| e.read_floor == at(32)));
}

#[test]
fn all_stands_for_every_customer_sensor() {
    let f = setup();
    let cursors = f.cursors(&["all"], at(0));
    let mut sensors: Vec<&str> = cursors.entries.iter().map(|e| e.sensor.as_str()).collect();
    sensors.dedup();
    assert_eq!(sensors, [A, B, C, D, GONE]);
    let named = f.cursors(&["all", A], at(0));
    assert!(named.entries.iter().all(|e| e.sensor == A));
    assert_eq!(named.entries.len(), KINDS.len());
}

#[test]
fn a_cursor_read_that_creates_nothing_writes_nothing() {
    let f = setup();
    f.cursors(&[A], at(0));
    let before = f.dump();
    f.cursors(&[A, SHARED], at(5));
    assert_eq!(f.dump(), before);
}

#[test]
fn turning_the_setting_on_again_moves_every_cursor_of_the_customer() {
    let f = setup();
    f.cursors(&[A, B, D], at(-30));
    let mut batch = f.batch(A, Kind::DnsName, at(5), Vec::new());
    batch.late_slots = vec![late(Kind::DnsName, at(-5), 0)];
    f.stored(&batch, at(11));
    let row = f.row(A, Kind::DnsName).unwrap();
    assert_eq!(row.confirmed.len(), 1);
    assert_eq!(row.marks.len(), 1);

    f.set_enabled(CUSTOMER, false, at(30));
    assert_eq!(f.row(A, Kind::DnsName).unwrap(), row);
    f.set_enabled(CUSTOMER, true, at(62));
    for sensor in [A, B] {
        for kind in KINDS {
            let row = f.row(sensor, kind).unwrap();
            assert_eq!(row.read_floor, at(62));
            assert_eq!(row.cursor, at(60));
            assert!(row.confirmed.is_empty(), "{:?}", row.confirmed);
            assert!(row.marks.is_empty(), "{:?}", row.marks);
        }
    }
    let other = f.row(D, Kind::DnsName).unwrap();
    assert_eq!(other.read_floor, at(-30));
}

#[test]
fn a_slot_of_the_enable_time_is_counted_from_it() {
    let f = setup();
    f.cursors(&[A], at(-30));
    f.set_enabled(CUSTOMER, false, at(-10));
    f.set_enabled(CUSTOMER, true, at(2));
    let row = f.row(A, Kind::DnsName).unwrap();
    assert_eq!(row.read_floor, at(2));
    assert_eq!(row.cursor, at(0));
    let mut batch = f.batch(A, Kind::DnsName, at(0), Vec::new());
    batch.counted_from = at(2);
    f.stored(&batch, at(6));
    assert_eq!(f.row(A, Kind::DnsName).unwrap().cursor, at(5));
}

#[test]
fn a_creation_racing_an_enable_ends_after_the_enable_time() {
    let f = setup();
    f.set_enabled(CUSTOMER, false, at(-30));
    set_before_commit_hook(Box::new(|db| {
        set_enabled(&Dai::open(db).unwrap(), CUSTOMER, true, at(20));
    }));
    let cursors = f.cursors(&[A], at(10));
    assert_eq!(cursors.entries.len(), KINDS.len());
    for entry in &cursors.entries {
        assert_eq!(entry.read_floor, at(20));
        assert_eq!(entry.cursor, at(20));
    }
    assert_eq!(
        f.store.dai_settings(CUSTOMER).unwrap().last_enabled_time,
        Some(at(20))
    );
    assert_eq!(f.row(A, Kind::Ntlm).unwrap().read_floor, at(20));
}

#[test]
fn concurrent_first_reads_return_one_generation() {
    let f = setup();
    let generations: Vec<u64> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| f.store.dai_restore_generation().unwrap()))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(generations.windows(2).all(|w| w.first() == w.last()));
    assert_eq!(f.generation(), *generations.first().unwrap());
}

// ---- After a restore ----

/// The cursor rows a restore test writes, at slot boundary `base`, and the
/// cursor each must have after a restore.
fn restore_rows(base: i64, today: i32) -> Vec<(&'static str, Kind, CursorRow, i64)> {
    let row = |cursor, read_floor| CursorRow {
        cursor,
        read_floor,
        ..CursorRow::default()
    };
    let mut plain = row(base, base - 3 * DAY);
    plain
        .confirmed
        .insert(base + 10 * MINUTE, base + 5 * MINUTE);
    plain.marks.insert(base - HOUR, 7);
    let mut long_delay = row(base, base - 3 * DAY);
    long_delay.delays.insert(today, 30 * HOUR + MINUTE);
    let mut old_delay = row(base, base - 3 * DAY);
    old_delay.delays.insert(today - 31, 40 * HOUR);
    vec![
        // D's customer was never enabled: the lookback alone.
        (D, Kind::DnsName, plain, base - 24 * HOUR),
        (D, Kind::Kerberos, long_delay, base - 30 * HOUR - 5 * MINUTE),
        (D, Kind::Ntlm, old_delay, base - 24 * HOUR),
        (
            D,
            Kind::Service,
            row(base, base - 2 * HOUR - 2 * MINUTE),
            base - 2 * HOUR - 5 * MINUTE,
        ),
        // Not a customer sensor: no last-enabled time.
        (
            SHARED,
            Kind::DnsName,
            row(base, base - 3 * DAY),
            base - 24 * HOUR,
        ),
        // CUSTOMER was turned on 5 hours before `base`.
        (A, Kind::DnsName, row(base, base - 3 * DAY), base - 5 * HOUR),
        // Never later than the restored cursor.
        (
            A,
            Kind::Service,
            row(base - 6 * HOUR, base - 3 * DAY),
            base - 6 * HOUR,
        ),
    ]
}

/// Fills `store` for a restore test at the current time, and returns the
/// slot boundary the rows are written at.
fn prepare_restore(store: &Store) -> i64 {
    let now = now_nanos().unwrap();
    let base = slot_floor(now).unwrap();
    populate(store, base - 5 * HOUR);
    let dai = store.states.dai();
    for (sensor, kind, row, _) in restore_rows(base, date_of(now).unwrap()) {
        dai.write(|txn| dai.put_cursor(txn, sensor, kind, &row))
            .unwrap();
    }
    store.dai_restore_generation().unwrap();
    base
}

/// Asserts that every cursor of [`restore_rows`] moved back as expected,
/// keeping its read floor, marks and delays, with no confirmed slot, and
/// that the restore generation is not one of `earlier`.
fn assert_restored(store: &Store, base: i64, earlier: &mut Vec<u64>) {
    let generation = store.dai_restore_generation().unwrap();
    assert!(!earlier.contains(&generation), "{generation} {earlier:?}");
    earlier.push(generation);
    let dai = store.states.dai();
    let today = date_of(now_nanos().unwrap()).unwrap();
    for (sensor, kind, written, expected) in restore_rows(base, today) {
        let row = dai
            .read(|txn| dai.cursor_in(txn, sensor, kind))
            .unwrap()
            .unwrap();
        assert_eq!(row.cursor, expected, "{sensor} {kind:?}");
        assert_eq!(row.read_floor, written.read_floor);
        assert_eq!(row.marks, written.marks);
        assert_eq!(row.delays, written.delays);
        assert!(row.confirmed.is_empty(), "{:?}", row.confirmed);
    }
}

/// Opens a store in `data` and `backup`, fills it for a restore test, backs
/// it up, and returns it with the slot boundary of its rows and its restore
/// generation.
fn backed_up_store(data: &TempDir, backup: &TempDir) -> (Arc<RwLock<Store>>, i64, u64) {
    let store = Arc::new(RwLock::new(
        Store::new(data.path(), backup.path(), None).unwrap(),
    ));
    let base = prepare_restore(&store.read().unwrap());
    let generation = store.read().unwrap().dai_restore_generation().unwrap();
    crate::backup::create(&store, true, 5).unwrap();
    (store, base, generation)
}

#[test]
fn every_online_restore_renews_the_generation_and_moves_the_cursors_back() {
    let _permit = acquire_db_permit();
    let data = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    let (store, base, generation) = backed_up_store(&data, &backup);
    let mut generations = vec![generation];
    crate::backup::restore(&store, Some(1)).unwrap();
    assert_restored(&store.read().unwrap(), base, &mut generations);
    store.write().unwrap().restore_from_backup(1).unwrap();
    assert_restored(&store.read().unwrap(), base, &mut generations);
    crate::backup::restore(&store, Some(1)).unwrap();
    assert_restored(&store.read().unwrap(), base, &mut generations);
}

#[test]
fn a_restore_of_the_latest_backup_moves_the_cursors_back() {
    let _permit = acquire_db_permit();
    for through_backup in [true, false] {
        let data = tempfile::tempdir().unwrap();
        let backup = tempfile::tempdir().unwrap();
        let (store, base, generation) = backed_up_store(&data, &backup);
        if through_backup {
            crate::backup::restore(&store, None).unwrap();
        } else {
            store.write().unwrap().restore_from_latest_backup().unwrap();
        }
        assert_restored(&store.read().unwrap(), base, &mut vec![generation]);
    }
}

#[test]
fn an_offline_restore_moves_the_cursors_back_at_the_next_open() {
    let _permit = acquire_db_permit();
    let data = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    let (base, mut generations) = {
        let (_store, base, generation) = backed_up_store(&data, &backup);
        (base, vec![generation])
    };
    for _ in 0..2 {
        crate::backup::restore_states_offline(data.path(), backup.path(), 1).unwrap();
        let store = Store::new(data.path(), backup.path(), None).unwrap();
        assert_restored(&store, base, &mut generations);
        // The marker is applied once.
        let generation = store.dai_restore_generation().unwrap();
        drop(store);
        let store = Store::new(data.path(), backup.path(), None).unwrap();
        assert_eq!(store.dai_restore_generation().unwrap(), generation);
    }
}

#[test]
fn an_offline_restore_of_a_backup_without_the_cursor_families_marks_nothing() {
    let _permit = acquire_db_permit();
    let data = tempfile::tempdir().unwrap();
    let source = tempfile::tempdir().unwrap();
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(true);
    let db = rocksdb::DB::open(&opts, source.path()).unwrap();
    let mut engine = crate::tables::open_rocksdb_backup_engine(data.path()).unwrap();
    engine.create_new_backup_flush(&db, true).unwrap();
    drop(db);
    let restored = tempfile::tempdir().unwrap();
    crate::tables::restore_rocksdb_backup(&mut engine, restored.path(), 1).unwrap();
    mark_restored(restored.path()).unwrap();
    let families = rocksdb::DB::list_cf(&rocksdb::Options::default(), restored.path()).unwrap();
    assert_eq!(families, ["default"]);
    let db = rocksdb::DB::open_default(restored.path()).unwrap();
    assert_eq!(db.get(super::cursor::RESTORE_MARKER).unwrap(), None);
}

// ---- The checks of a store, in order ----

#[test]
fn a_repeated_part_of_a_finished_send_gets_its_reply_again() {
    let f = setup();
    f.cursors(&[A], at(0));
    let mut batch = f.batch(A, Kind::DnsName, at(5), vec![dns("x", at(6), at(7), 1)]);
    batch.late_slots = vec![late(Kind::DnsName, at(0), MINUTE)];
    batch.lost_before = Some(at(3));
    let stored = f.store(&batch, at(11));
    assert!(matches!(&stored, DaiStoreOutcome::Stored { marks, .. } if marks.len() == 1));
    let before = f.dump();
    assert_eq!(f.store(&batch, at(12)), stored);
    assert_eq!(f.dump(), before);

    // After a configuration epoch change, and after an off → on cycle.
    f.dai().record_config_hash(A, b"changed").unwrap();
    assert_eq!(f.store(&batch, at(13)), stored);
    f.set_enabled(CUSTOMER, false, at(14));
    f.set_enabled(CUSTOMER, true, at(15));
    assert_eq!(f.store(&batch, at(16)), stored);
    f.set_enabled(CUSTOMER, false, at(17));
    assert_eq!(f.store(&batch, at(18)), stored);

    // After a restore.
    f.set_enabled(CUSTOMER, true, at(19));
    f.dai().after_restore(at(20)).unwrap();
    let before = f.dump();
    assert_eq!(
        f.store(&batch, at(21)),
        DaiStoreOutcome::Resync {
            restore_generation: f.generation()
        }
    );
    assert_eq!(f.dump(), before);
}

#[test]
fn sensors_that_are_not_collected_get_not_collected() {
    let f = setup();
    f.cursors(&["all"], at(0));
    let before = f.dump();
    for sensor in [SHARED, "piglet.unknown", D] {
        let batch = f.batch(
            sensor,
            Kind::DnsName,
            at(0),
            vec![dns("x", at(1), at(1), 1)],
        );
        assert_eq!(
            f.store(&batch, at(6)),
            DaiStoreOutcome::NotCollected {
                restore_generation: f.generation()
            },
            "{sensor}"
        );
    }
    assert_eq!(f.dump(), before);
    // A sensor of a customer that turned the setting off.
    f.set_enabled(CUSTOMER, false, at(1));
    let before_off = f.dump();
    let batch = f.batch(A, Kind::DnsName, at(0), Vec::new());
    assert!(matches!(
        f.store(&batch, at(6)),
        DaiStoreOutcome::NotCollected { .. }
    ));
    assert_eq!(f.dump(), before_off);
    assert_ne!(before, before_off);
}

#[test]
fn each_invalid_field_is_refused_with_its_own_variant() {
    let f = setup();
    f.cursors(&[A], at(0));
    let valid = f.batch(A, Kind::DnsName, at(0), vec![dns("x", at(1), at(1), 1)]);
    let mut cases: Vec<(DaiObservationBatch, DaiBatchError)> = Vec::new();
    let mut batch = valid.clone();
    batch.slot_len_secs = 60;
    cases.push((batch, DaiBatchError::SlotLength { secs: 60 }));
    let mut batch = valid.clone();
    batch.slot_start = at(1);
    batch.counted_from = at(1);
    cases.push((batch, DaiBatchError::SlotStart { slot_start: at(1) }));
    let mut batch = valid.clone();
    batch.part_count = 0;
    cases.push((batch, DaiBatchError::ZeroPartCount));
    let mut batch = valid.clone();
    batch.part = 3;
    batch.part_count = 3;
    cases.push((
        batch,
        DaiBatchError::PartOutOfRange {
            part: 3,
            part_count: 3,
        },
    ));
    for counted_from in [at(5), at(0) - 1] {
        let mut batch = valid.clone();
        batch.counted_from = counted_from;
        cases.push((
            batch,
            DaiBatchError::CountedFrom {
                counted_from,
                slot_start: at(0),
            },
        ));
    }
    let mut batch = valid.clone();
    batch.late_slots = vec![late(Kind::DnsName, at(-5), 0), late(Kind::Ntlm, at(-1), 0)];
    cases.push((batch, DaiBatchError::LateSlotStart { slot_start: at(-1) }));

    let before = f.dump();
    for (batch, expected) in cases {
        let error = f.store.store_dai_observations(&batch, at(6)).unwrap_err();
        assert_eq!(batch_error(&error), &expected);
        assert_eq!(f.dump(), before);
    }
    f.stored(&valid, at(6));
}

#[test]
fn each_resync_cause_writes_nothing() {
    let f = setup();
    f.cursors(&[A], at(0));
    let valid = f.batch(A, Kind::DnsName, at(0), vec![dns("x", at(1), at(1), 1)]);
    let mut cases = Vec::new();
    let mut batch = valid.clone();
    batch.restore_generation = batch.restore_generation.wrapping_add(1);
    cases.push(batch);
    let mut batch = valid.clone();
    batch.config_epoch += 1;
    cases.push(batch);
    let mut batch = valid.clone();
    batch.network_digest = batch.network_digest.wrapping_add(1);
    cases.push(batch);
    // No cursor row for the batch kind: B never read its cursors.
    cases.push(f.batch(B, Kind::DnsName, at(0), Vec::new()));
    // No cursor row for the kind of a late slot.
    let dai = f.dai();
    dai.write(|txn| Dai::delete_row(txn, &dai.cursors, &pair_key(A, Kind::Ntlm)))
        .unwrap();
    let mut batch = valid.clone();
    batch.late_slots = vec![late(Kind::Ntlm, at(-5), 0)];
    cases.push(batch);

    let before = f.dump();
    for batch in cases {
        assert_eq!(
            f.store(&batch, at(6)),
            DaiStoreOutcome::Resync {
                restore_generation: f.generation()
            },
            "{batch:?}"
        );
        assert_eq!(f.dump(), before);
    }
}

#[test]
fn a_batch_with_an_old_network_digest_gets_resync() {
    let f = setup();
    f.cursors(&[A], at(0));
    let old = f.batch(A, Kind::DnsName, at(0), Vec::new());
    let networks = f.store.customer_networks_map();
    let intranet = |cidr| {
        vec![network(
            "intranet",
            NetworkType::Intranet,
            cidr_group(&[cidr]),
        )]
    };

    // Replaced with different networks under the same revision.
    networks
        .replace(CUSTOMER, 1, intranet("192.168.0.0/16"))
        .unwrap();
    assert!(matches!(
        f.store(&old, at(6)),
        DaiStoreOutcome::Resync { .. }
    ));
    // Removed and recreated with an older revision and other content.
    networks.remove(CUSTOMER).unwrap();
    networks
        .replace(CUSTOMER, 0, intranet("172.16.0.0/12"))
        .unwrap();
    assert!(matches!(
        f.store(&old, at(6)),
        DaiStoreOutcome::Resync { .. }
    ));
    // Recreated with identical content.
    networks.remove(CUSTOMER).unwrap();
    networks
        .replace(CUSTOMER, 0, intranet("10.0.0.0/8"))
        .unwrap();
    f.stored(&old, at(6));
}

#[test]
fn a_store_racing_a_network_replace_is_retried() {
    let f = setup();
    f.cursors(&[A], at(0));
    let batch = f.batch(A, Kind::DnsName, at(0), vec![dns("x", at(1), at(1), 1)]);
    set_before_commit_hook(Box::new(|db| {
        OwnedNetworkTable::open(db)
            .unwrap()
            .replace(
                CUSTOMER,
                2,
                vec![network(
                    "intranet",
                    NetworkType::Intranet,
                    cidr_group(&["192.168.0.0/16"]),
                )],
            )
            .unwrap();
    }));
    assert!(matches!(
        f.store(&batch, at(6)),
        DaiStoreOutcome::Resync { .. }
    ));
    assert!(f.observations().is_empty(), "{:?}", f.observations());
    assert!(
        f.rows(super::super::DAI_SLOT_SENDS).is_empty(),
        "{:?}",
        f.rows(super::super::DAI_SLOT_SENDS)
    );
}

#[test]
fn a_store_racing_a_configuration_write_is_retried() {
    let f = setup();
    f.cursors(&[A], at(0));
    let batch = f.batch(A, Kind::DnsName, at(0), vec![dns("x", at(1), at(1), 1)]);
    set_before_commit_hook(Box::new(|db| {
        let dai = Dai::open(db).unwrap();
        let revision = dai.relay_sites(CUSTOMER).unwrap().revision;
        dai.replace_relay_sites(CUSTOMER, revision, &[]).unwrap();
    }));
    assert!(matches!(
        f.store(&batch, at(6)),
        DaiStoreOutcome::Resync { .. }
    ));
    assert!(f.observations().is_empty(), "{:?}", f.observations());

    let batch = f.batch(A, Kind::DnsName, at(0), vec![dns("x", at(1), at(1), 1)]);
    set_before_commit_hook(Box::new(|db| {
        set_enabled(&Dai::open(db).unwrap(), CUSTOMER, false, at(1));
    }));
    assert!(matches!(
        f.store(&batch, at(6)),
        DaiStoreOutcome::NotCollected { .. }
    ));
    assert!(f.observations().is_empty(), "{:?}", f.observations());
}

// ---- Staging and finishing ----

/// Returns part `part` of a three-part send of `send_id` carrying one
/// observation named after the part.
fn part(f: &Fixture, send_id: u64, part: u32) -> DaiObservationBatch {
    let mut batch = f.batch(
        A,
        Kind::DnsName,
        at(0),
        vec![dns(&format!("p{part}"), at(1), at(2), 1)],
    );
    batch.send_id = send_id;
    batch.part = part;
    batch.part_count = 3;
    batch.last_record_time = Some(at(4));
    batch
}

#[test]
fn a_send_is_stored_when_its_last_missing_part_arrives() {
    let f = setup();
    f.cursors(&[A], at(0));
    let staged = DaiStoreOutcome::Staged {
        restore_generation: f.generation(),
    };
    assert_eq!(f.store(&part(&f, 1, 2), at(6)), staged);
    assert_eq!(f.store(&part(&f, 1, 0), at(6)), staged);
    // A repeated part overwrites.
    assert_eq!(f.store(&part(&f, 1, 0), at(6)), staged);
    assert!(f.observations().is_empty(), "{:?}", f.observations());
    assert!(f.pending().is_empty(), "{:?}", f.pending());
    assert_eq!(f.row(A, Kind::DnsName).unwrap().cursor, at(0));
    f.stored(&part(&f, 1, 1), at(7));
    assert_eq!(f.observations().len(), 3);
    assert_eq!(f.pending().len(), 3);
    assert_eq!(f.row(A, Kind::DnsName).unwrap().cursor, at(5));
    assert!(
        f.rows(super::super::DAI_SEND_PARTS).is_empty(),
        "{:?}",
        f.rows(super::super::DAI_SEND_PARTS)
    );
    let state = f.sensor_state(A);
    assert_eq!(state.last_record_time, Some(at(4)));
    assert_eq!(state.last_store_time, Some(at(7)));
}

#[test]
fn a_send_with_a_missing_part_confirms_nothing() {
    let f = setup();
    f.cursors(&[A], at(0));
    f.store(&part(&f, 1, 2), at(6));
    f.store(&part(&f, 1, 0), at(6));
    assert_eq!(f.row(A, Kind::DnsName).unwrap().cursor, at(0));
    assert!(
        f.row(A, Kind::DnsName).unwrap().confirmed.is_empty(),
        "{:?}",
        f.row(A, Kind::DnsName).unwrap().confirmed
    );
    assert!(f.observations().is_empty(), "{:?}", f.observations());
}

#[test]
fn a_part_with_other_metadata_discards_the_send() {
    let f = setup();
    f.cursors(&[A], at(0));
    // The metadata of the first arriving part is what finishing applies.
    f.store(&part(&f, 1, 2), at(6));
    let mut other = part(&f, 1, 0);
    other.last_record_time = Some(at(3));
    let before = f.dump();
    assert_eq!(
        f.store(&other, at(6)),
        DaiStoreOutcome::Resync {
            restore_generation: f.generation()
        }
    );
    assert!(
        f.rows(super::super::DAI_SLOT_SENDS).is_empty(),
        "{:?}",
        f.rows(super::super::DAI_SLOT_SENDS)
    );
    assert!(
        f.rows(super::super::DAI_SEND_PARTS).is_empty(),
        "{:?}",
        f.rows(super::super::DAI_SEND_PARTS)
    );
    assert_ne!(f.dump(), before);
    assert_eq!(f.row(A, Kind::DnsName).unwrap().cursor, at(0));

    // A different part count.
    f.store(&part(&f, 2, 2), at(6));
    let mut other = part(&f, 2, 0);
    other.part_count = 4;
    assert!(matches!(
        f.store(&other, at(6)),
        DaiStoreOutcome::Resync { .. }
    ));
    assert!(
        f.rows(super::super::DAI_SEND_PARTS).is_empty(),
        "{:?}",
        f.rows(super::super::DAI_SEND_PARTS)
    );

    // Each piece of metadata.
    for change in [
        (|b: &mut DaiObservationBatch| b.late_slots = vec![late(Kind::DnsName, at(-5), 0)])
            as fn(&mut DaiObservationBatch),
        |b| b.reextract_mark = Some(1),
        |b| b.lost_before = Some(at(-1)),
        |b| b.counted_from = at(1),
    ] {
        f.store(&part(&f, 3, 2), at(6));
        let mut other = part(&f, 3, 1);
        change(&mut other);
        assert!(matches!(
            f.store(&other, at(6)),
            DaiStoreOutcome::Resync { .. }
        ));
        assert!(
            f.rows(super::super::DAI_SLOT_SENDS).is_empty(),
            "{:?}",
            f.rows(super::super::DAI_SLOT_SENDS)
        );
    }
}

#[test]
fn a_repeated_finishing_part_applies_once() {
    let f = setup();
    f.cursors(&[A], at(0));
    let mut batch = f.batch(
        A,
        Kind::DnsName,
        at(10),
        vec![dns("x", at(11), at(12), 1), dns("y", at(0), at(0), 1)],
    );
    batch.late_slots = vec![late(Kind::DnsName, at(0), MINUTE)];
    batch.lost_before = Some(at(7));
    let marks = f.stored(&batch, at(16));
    let before = f.dump();
    assert_eq!(f.stored(&batch, at(17)), marks);
    assert_eq!(f.dump(), before);
    assert_eq!(
        f.counter(CUSTOMER, DaiCounterKind::FilteredAtReceipt, at(16)),
        1
    );
    assert_eq!(
        f.counter(CUSTOMER, DaiCounterKind::SkippedByCatchup, at(16)),
        2
    );
}

#[test]
fn staged_parts_never_reach_the_observation_tables() {
    let f = setup();
    f.cursors(&[A], at(0));
    let mut unfinished = f.batch(
        A,
        Kind::DnsName,
        at(0),
        vec![dns("staged", at(1), at(1), 1)],
    );
    unfinished.part_count = 2;
    assert!(matches!(
        f.store(&unfinished, at(6)),
        DaiStoreOutcome::Staged { .. }
    ));
    f.stored(
        &f.batch(
            A,
            Kind::DnsName,
            at(0),
            vec![dns("finished", at(1), at(1), 1)],
        ),
        at(6),
    );
    let names: Vec<DaiObservationBody> = f
        .observations()
        .into_iter()
        .map(|(_, _, _, row)| row.body)
        .collect();
    assert_eq!(names, [dns("finished", 0, 0, 0).body]);
    assert_eq!(f.pending().len(), 1);
    assert_eq!(f.rows(super::super::DAI_SEND_PARTS).len(), 1);
}

// ---- Upserts and pending ----

#[test]
fn counts_grow_and_times_widen_only() {
    let f = setup();
    f.cursors(&[A], at(0));
    let store = |observation| {
        f.stored(&f.batch(A, Kind::DnsName, at(0), vec![observation]), at(6));
        let rows = f.observations();
        assert_eq!(rows.len(), 1);
        rows.into_iter().next().unwrap().3
    };
    assert_eq!(store(dns("x", at(1), at(2), 10)).count, 10);
    assert_eq!(store(dns("x", at(1), at(2), 11)).count, 11);
    let row = store(dns("x", at(1), at(2), 10));
    assert_eq!(row.count, 11);
    let row = store(dns("x", at(0), at(3), 1));
    assert_eq!(
        (row.first_seen, row.last_seen, row.count),
        (at(0), at(3), 11)
    );
    let row = store(dns("x", at(2), at(2), 1));
    assert_eq!((row.first_seen, row.last_seen), (at(0), at(3)));
    assert_eq!(row.customer_id, CUSTOMER);
}

#[test]
fn only_a_changed_observation_is_enqueued() {
    let f = setup();
    f.cursors(&[A], at(0));
    let store = |kind, observation| {
        f.stored(&f.batch(A, kind, at(0), vec![observation]), at(6));
    };
    store(Kind::DnsName, dns("x", at(1), at(2), 1));
    let pending = f.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        (pending[0].3.first_seen, pending[0].3.last_seen),
        (at(1), at(2))
    );
    assert_eq!(f.earliest(A, Kind::DnsName), Some(at(0)));
    f.clear_pending();

    // The same observation, and a count-only change.
    store(Kind::DnsName, dns("x", at(1), at(2), 1));
    store(Kind::DnsName, dns("x", at(1), at(2), 5));
    assert!(f.pending().is_empty(), "{:?}", f.pending());
    assert_eq!(f.earliest(A, Kind::DnsName), None);
    // A widened time.
    store(Kind::DnsName, dns("x", at(1), at(3), 1));
    let pending = f.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        (pending[0].3.first_seen, pending[0].3.last_seen),
        (at(1), at(3))
    );
    f.clear_pending();

    // A filled DHCP value, kept in one row.
    store(Kind::DhcpLease, lease(at(1), None));
    f.clear_pending();
    store(Kind::DhcpLease, lease(at(1), Some("host")));
    let pending = f.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].3.body, lease_body(at(1), Some("host")));
    f.clear_pending();
    store(Kind::DhcpLease, lease(at(1), Some("other")));
    store(Kind::DhcpLease, lease(at(1), None));
    assert!(f.pending().is_empty(), "{:?}", f.pending());
    let leases: Vec<ObservationRow> = f
        .observations()
        .into_iter()
        .filter(|(_, kind, _, _)| *kind == Kind::DhcpLease)
        .map(|(_, _, _, row)| row)
        .collect();
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].body, lease_body(at(1), Some("host")));
}

#[test]
fn the_service_external_client_is_merged_with_or() {
    let f = setup();
    f.cursors(&[A], at(0));
    let service = |external_client| DaiObservation {
        first_seen: at(1),
        last_seen: at(1),
        count: 1,
        body: DaiObservationBody::Service {
            server_ip: ip("10.0.0.3"),
            port: 22,
            proto: 6,
            external_client,
        },
    };
    for external in [false, true, false] {
        f.stored(
            &f.batch(A, Kind::Service, at(0), vec![service(external)]),
            at(6),
        );
    }
    let rows = f.observations();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].3.body, service(true).body);
}

#[test]
fn the_earliest_pending_slot_follows_the_pending_rows() {
    let f = setup();
    f.cursors(&[A], at(0));
    for (slot, name) in [(at(10), "a"), (at(0), "b"), (at(5), "c")] {
        f.stored(
            &f.batch(A, Kind::DnsName, slot, vec![dns(name, slot, slot, 1)]),
            at(16),
        );
    }
    assert_eq!(f.earliest(A, Kind::DnsName), Some(at(0)));
    assert_eq!(f.earliest(A, Kind::Ntlm), None);
}

#[test]
fn ip_activity_is_stored_and_widens_the_address_activity() {
    let f = setup();
    f.cursors(&[A], at(0));
    f.stored(
        &f.batch(
            A,
            Kind::IpActivity,
            at(0),
            vec![activity("10.0.0.9", at(1), at(2))],
        ),
        at(6),
    );
    f.stored(
        &f.batch(
            A,
            Kind::IpActivity,
            at(5),
            vec![activity("10.0.0.9", at(6), at(7))],
        ),
        at(11),
    );
    assert_eq!(f.observations().len(), 2);
    assert!(f.pending().is_empty(), "{:?}", f.pending());
    assert_eq!(f.earliest(A, Kind::IpActivity), None);
    let rows = f.rows(super::super::DAI_IP_ACTIVITY);
    assert_eq!(rows.len(), 1);
    let activity: ActivityRow = super::super::deserialize(&rows[0].1).unwrap();
    assert_eq!(
        activity,
        ActivityRow {
            first_seen: at(1),
            last_seen: at(7)
        }
    );
    let default = f
        .store
        .dai_sensor_site(CUSTOMER, A, at(0))
        .unwrap()
        .unwrap();
    assert!(
        rows[0]
            .0
            .starts_with(&KeyWriter::default().u32(CUSTOMER).str(&default).finish())
    );
}

#[test]
fn filtered_observations_are_counted_and_not_stored() {
    let f = setup();
    f.cursors(&[A], at(0));
    let observations = vec![
        dns("kept", at(1), at(1), 1),
        dns(&"x".repeat(512), at(1), at(1), 1),
        lease(at(1), None),
        dns("early", at(0) - 1, at(1), 1),
        dns("late", at(1), at(5), 1),
        dns(&"x".repeat(513), at(1), at(1), 1),
    ];
    f.stored(&f.batch(A, Kind::DnsName, at(0), observations), at(6));
    assert_eq!(f.observations().len(), 2);
    assert_eq!(
        f.counter(CUSTOMER, DaiCounterKind::FilteredAtReceipt, at(6)),
        4
    );

    // A DHCP lease whose own time is outside the slot.
    let mut outside = lease(at(1), None);
    outside.body = lease_body(at(6), None);
    f.stored(&f.batch(A, Kind::DhcpLease, at(0), vec![outside]), at(6));
    assert_eq!(
        f.counter(CUSTOMER, DaiCounterKind::FilteredAtReceipt, at(6)),
        5
    );
    // A Kerberos name over 512 bytes.
    let mut long = kerberos(at(1), at(1));
    if let DaiObservationBody::Kerberos { cname, .. } = &mut long.body {
        cname.push("n".repeat(513));
    }
    f.stored(&f.batch(A, Kind::Kerberos, at(0), vec![long]), at(6));
    assert_eq!(
        f.counter(CUSTOMER, DaiCounterKind::FilteredAtReceipt, at(6)),
        6
    );
    assert_eq!(f.observations().len(), 2);
    // Nothing stored, so no sensor kind state.
    let dai = f.dai();
    let state: Option<i64> = dai
        .read(|txn| Dai::get_row(txn, &dai.sensor_kind_state, &pair_key(A, Kind::Kerberos)))
        .unwrap();
    assert_eq!(state, None);
    let state: Option<i64> = dai
        .read(|txn| Dai::get_row(txn, &dai.sensor_kind_state, &pair_key(A, Kind::DnsName)))
        .unwrap();
    assert_eq!(state, Some(at(6)));
}

#[test]
fn an_old_slot_goes_to_the_summary_and_folding_keeps_pending() {
    let f = setup();
    f.cursors(&[A], at(0));
    let now = at(0) + 8 * DAY;
    let store = |observation| {
        f.stored(&f.batch(A, Kind::DnsName, at(0), vec![observation]), now);
    };
    store(dns("x", at(1), at(2), 1));
    assert!(f.observations().is_empty(), "{:?}", f.observations());
    let summaries = f.summaries();
    assert_eq!(summaries.len(), 1);
    assert_eq!(
        (summaries[0].first_seen, summaries[0].last_seen),
        (at(1), at(2))
    );
    assert_eq!(f.pending().len(), 1);
    f.clear_pending();
    store(dns("x", at(1), at(2), 3));
    assert!(f.pending().is_empty(), "{:?}", f.pending());
    store(dns("x", at(1), at(3), 1));
    let pending = f.pending();
    assert_eq!(
        (pending[0].3.first_seen, pending[0].3.last_seen),
        (at(1), at(3))
    );
    // The observation's own times widened by the pending row it overwrites.
    store(dns("x", at(0), at(1), 1));
    let pending = f.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        (pending[0].3.first_seen, pending[0].3.last_seen),
        (at(0), at(3))
    );
    assert_eq!(f.summaries()[0].first_seen, at(0));
    assert_eq!(f.earliest(A, Kind::DnsName), Some(at(0)));

    // Folding a recent slot later keeps its pending row.
    f.stored(
        &f.batch(A, Kind::DnsName, at(5), vec![dns("y", at(6), at(7), 1)]),
        at(11),
    );
    assert_eq!(f.observations().len(), 1);
    f.store.apply_dai_retention(at(5) + 8 * DAY).unwrap();
    assert!(f.observations().is_empty(), "{:?}", f.observations());
    assert_eq!(f.summaries().len(), 2);
    assert_eq!(f.pending().len(), 2);
}

// ---- Cursors, marks, skips and gaps ----

#[test]
fn the_cursor_stops_at_the_last_contiguous_boundary() {
    let f = setup();
    f.cursors(&[A], at(0));
    f.stored(&f.batch(A, Kind::DnsName, at(5), Vec::new()), at(11));
    f.stored(&f.batch(A, Kind::DnsName, at(10), Vec::new()), at(16));
    let row = f.row(A, Kind::DnsName).unwrap();
    assert_eq!(row.cursor, at(0));
    assert_eq!(
        row.confirmed.into_iter().collect::<Vec<_>>(),
        [(at(10), at(5)), (at(15), at(10))]
    );
    // An empty batch advances the cursor.
    f.stored(&f.batch(A, Kind::DnsName, at(0), Vec::new()), at(16));
    let row = f.row(A, Kind::DnsName).unwrap();
    assert_eq!(row.cursor, at(15));
    assert!(row.confirmed.is_empty(), "{:?}", row.confirmed);
}

#[test]
fn an_overflowing_confirmed_list_marks_the_gap_for_re_extraction() {
    const SLOTS: i64 = 2_017;
    let f = setup();
    f.cursors(&[A], at(0));
    let mut template = f.batch(A, Kind::DnsName, at(0), Vec::new());
    for i in 1..=SLOTS {
        template.slot_start = at(5 * i);
        template.counted_from = at(5 * i);
        template.send_id = u64::try_from(i).unwrap();
        f.stored(&template, at(5 * i + 6));
    }
    let row = f.row(A, Kind::DnsName).unwrap();
    assert_eq!(row.cursor, at(0));
    assert_eq!(row.confirmed.len(), 2_016);
    assert_eq!(row.confirmed.keys().next(), Some(&at(15)));
    let marks: Vec<(i64, u64)> = row.marks.into_iter().collect();
    assert_eq!(marks, [(at(0), 0), (at(5), 1)]);
    let entries = f.cursors(&[A], at(5 * SLOTS + 6)).entries;
    let entry = entries.iter().find(|e| e.kind == Kind::DnsName).unwrap();
    assert_eq!(entry.reextract.len(), 2);

    // Re-extracting them makes the cursor continue.
    let now = at(5 * SLOTS + 10);
    for (slot, mark) in marks {
        let mut batch = f.batch(A, Kind::DnsName, slot, Vec::new());
        batch.reextract_mark = Some(mark);
        f.stored(&batch, now);
    }
    let row = f.row(A, Kind::DnsName).unwrap();
    assert_eq!(row.cursor, at(5 * SLOTS + 5));
    assert!(row.confirmed.is_empty(), "{:?}", row.confirmed);
    assert!(row.marks.is_empty(), "{:?}", row.marks);
}

#[test]
fn late_slots_get_new_marks() {
    let f = setup();
    f.cursors(&[A], at(-30));
    let mut batch = f.batch(A, Kind::DnsName, at(0), Vec::new());
    batch.late_slots = vec![
        late(Kind::DnsName, at(-10), 5 * MINUTE),
        late(Kind::Kerberos, at(-10), 2 * MINUTE),
        late(Kind::DnsName, at(-10), 7 * MINUTE),
        late(Kind::DnsName, at(-5), -3),
    ];
    let marks = f.stored(&batch, at(6));
    let mark = |kind, slot_start, mark| DaiReextractMark {
        kind,
        slot_start,
        mark,
    };
    assert_eq!(
        marks,
        [
            mark(Kind::DnsName, at(-10), 0),
            mark(Kind::Kerberos, at(-10), 1),
            mark(Kind::DnsName, at(-5), 2),
        ]
    );
    let today = date_of(at(6)).unwrap();
    let dns_row = f.row(A, Kind::DnsName).unwrap();
    assert_eq!(
        dns_row.marks.into_iter().collect::<Vec<_>>(),
        [(at(-10), 0), (at(-5), 2)]
    );
    assert_eq!(dns_row.delays.get(&today), Some(&(7 * MINUTE)));
    let kerberos_row = f.row(A, Kind::Kerberos).unwrap();
    assert_eq!(kerberos_row.delays.get(&today), Some(&(2 * MINUTE)));
    let entries = f.cursors(&[A], at(7)).entries;
    let dns_entry = entries.iter().find(|e| e.kind == Kind::DnsName).unwrap();
    assert_eq!(
        dns_entry.reextract,
        [
            mark(Kind::DnsName, at(-10), 0),
            mark(Kind::DnsName, at(-5), 2)
        ]
    );

    // A newer mark replaces the old one; numbers are not reused.
    let mut batch = f.batch(A, Kind::DnsName, at(5), Vec::new());
    batch.late_slots = vec![late(Kind::DnsName, at(-10), 0)];
    assert_eq!(f.stored(&batch, at(11)), [mark(Kind::DnsName, at(-10), 3)]);
}

#[test]
fn an_older_mark_does_not_clear_a_newer_one() {
    let f = setup();
    f.cursors(&[A], at(-30));
    let mut batch = f.batch(A, Kind::DnsName, at(0), Vec::new());
    batch.late_slots = vec![late(Kind::DnsName, at(-10), 0)];
    let [first] = f.stored(&batch, at(6)).try_into().unwrap();

    // Two senders read the mark; one finishes.
    let mut one = f.batch(A, Kind::DnsName, at(-10), Vec::new());
    one.reextract_mark = Some(first.mark);
    let mut two = one.clone();
    two.send_id = one.send_id.wrapping_add(1);
    f.stored(&one, at(7));
    assert!(
        f.row(A, Kind::DnsName).unwrap().marks.is_empty(),
        "{:?}",
        f.row(A, Kind::DnsName).unwrap().marks
    );
    // A new late record is reported.
    let mut batch = f.batch(A, Kind::DnsName, at(5), Vec::new());
    batch.late_slots = vec![late(Kind::DnsName, at(-10), 0)];
    let [second] = f.stored(&batch, at(11)).try_into().unwrap();
    // The other's old result arrives.
    f.stored(&two, at(12));
    let marks = f.row(A, Kind::DnsName).unwrap().marks;
    assert_eq!(marks.get(&at(-10)), Some(&second.mark));

    // A late slot naming the batch slot keeps its new mark.
    let mut batch = f.batch(A, Kind::DnsName, at(-10), Vec::new());
    batch.reextract_mark = Some(second.mark);
    batch.late_slots = vec![late(Kind::DnsName, at(-10), 0)];
    let [third] = f.stored(&batch, at(13)).try_into().unwrap();
    let marks = f.row(A, Kind::DnsName).unwrap().marks;
    assert_eq!(marks.get(&at(-10)), Some(&third.mark));
}

#[test]
fn a_catch_up_skip_moves_the_cursor_and_counts_the_skipped_slots() {
    let f = setup();
    f.cursors(&[A], at(0));
    // A slot confirmed out of order inside the skipped range.
    f.stored(&f.batch(A, Kind::DnsName, at(10), Vec::new()), at(16));
    let mut batch = f.batch(A, Kind::DnsName, at(20), Vec::new());
    batch.lost_before = Some(at(17));
    f.stored(&batch, at(26));
    let row = f.row(A, Kind::DnsName).unwrap();
    assert_eq!(row.cursor, at(15));
    assert_eq!(row.read_floor, at(17));
    assert_eq!(row.confirmed.keys().copied().collect::<Vec<_>>(), [at(25)]);
    assert_eq!(
        f.gaps(A, Kind::DnsName),
        [(at(0), at(10)), (at(15), at(17))]
    );
    assert_eq!(
        f.counter(CUSTOMER, DaiCounterKind::SkippedByCatchup, at(26)),
        3
    );
}

#[test]
fn a_catch_up_skip_never_moves_the_read_floor_earlier() {
    let f = setup();
    f.cursors(&[A], at(2));
    let mut batch = f.batch(A, Kind::DnsName, at(5), Vec::new());
    batch.lost_before = Some(at(1));
    f.stored(&batch, at(11));
    let row = f.row(A, Kind::DnsName).unwrap();
    assert_eq!(row.read_floor, at(2));
    assert_eq!(f.gaps(A, Kind::DnsName), [(at(0), at(1))]);
    assert_eq!(
        f.counter(CUSTOMER, DaiCounterKind::SkippedByCatchup, at(11)),
        1
    );
}

#[test]
fn finishing_slots_shrinks_the_gaps_in_either_order() {
    for skip_first in [false, true] {
        let f = setup();
        f.cursors(&[A], at(0));
        let first = f.batch(A, Kind::DnsName, at(0), Vec::new());
        let mut second = f.batch(A, Kind::DnsName, at(5), Vec::new());
        second.counted_from = at(7);
        second.lost_before = Some(at(12));
        if skip_first {
            f.stored(&second, at(16));
            assert_eq!(f.gaps(A, Kind::DnsName), [(at(0), at(7)), (at(10), at(12))]);
            f.stored(&first, at(16));
        } else {
            f.stored(&first, at(16));
            f.stored(&second, at(16));
        }
        assert_eq!(
            f.gaps(A, Kind::DnsName),
            [(at(5), at(7)), (at(10), at(12))],
            "skip first: {skip_first}"
        );
        let expected = if skip_first { 3 } else { 2 };
        assert_eq!(
            f.counter(CUSTOMER, DaiCounterKind::SkippedByCatchup, at(16)),
            expected
        );
        let row = f.row(A, Kind::DnsName).unwrap();
        assert_eq!(row.cursor, at(10));
        assert_eq!(row.read_floor, at(12));
    }
}

#[test]
fn a_sensor_moved_to_another_site_stores_under_the_site_at_slot_start() {
    let f = setup();
    f.cursors(&[A], at(-10));
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    let seoul = f
        .dai()
        .create_site(CUSTOMER, "Seoul", &[A.to_string()], &at(2))
        .unwrap();
    f.stored(
        &f.batch(A, Kind::DnsName, at(0), vec![dns("old", at(1), at(1), 1)]),
        at(6),
    );
    f.stored(
        &f.batch(A, Kind::DnsName, at(5), vec![dns("new", at(6), at(6), 1)]),
        at(11),
    );
    let sites: Vec<(i64, String)> = f
        .observations()
        .into_iter()
        .map(|(_, _, slot, row)| (slot, row.site))
        .collect();
    assert_eq!(sites, [(at(0), default), (at(5), seoul)]);
}

// ---- Retention ----

#[test]
#[allow(clippy::too_many_lines)] // One scenario, checked step by step.
fn retention_removes_what_aged_out() {
    let f = setup();
    f.cursors(&[A], at(-30));
    let later = at(0) + 2 * DAY;
    // Pending observations at 12:00 (two kinds) and two days later.
    f.stored(
        &f.batch(A, Kind::DnsName, at(0), vec![dns("x", at(1), at(1), 1)]),
        at(6),
    );
    f.stored(
        &f.batch(A, Kind::Kerberos, at(0), vec![kerberos(at(1), at(1))]),
        at(6),
    );
    f.stored(
        &f.batch(A, Kind::DnsName, later, vec![dns("y", later, later, 1)]),
        later + 6 * MINUTE,
    );
    // Address activity at 12:00 and two days later.
    f.stored(
        &f.batch(
            A,
            Kind::IpActivity,
            at(0),
            vec![activity("10.0.0.1", at(1), at(1))],
        ),
        at(6),
    );
    f.stored(
        &f.batch(
            A,
            Kind::IpActivity,
            later,
            vec![activity("10.0.0.2", later, later)],
        ),
        later + 6 * MINUTE,
    );
    // A filtered observation, a mark at 11:35 and a gap ending at 12:00.
    let mut batch = f.batch(
        A,
        Kind::Ntlm,
        at(5),
        vec![dns("wrong kind", at(6), at(6), 1)],
    );
    batch.late_slots = vec![late(Kind::Ntlm, at(-25), 0)];
    batch.lost_before = Some(at(0));
    f.stored(&batch, at(11));
    // A recent mark, and a gap ending two days later.
    let mut batch = f.batch(A, Kind::Ntlm, later, Vec::new());
    batch.late_slots = vec![late(Kind::Ntlm, later - 5 * MINUTE, 0)];
    batch.lost_before = Some(later);
    f.stored(&batch, later + 6 * MINUTE);
    // An unfinished send at 12:00.
    let mut unfinished = f.batch(A, Kind::Service, at(0), Vec::new());
    unfinished.part_count = 2;
    f.store(&unfinished, at(6));
    assert_eq!(f.gaps(A, Kind::Ntlm).len(), 3);
    let sends = f.rows(super::super::DAI_SLOT_SENDS).len();

    // 31 days on.
    let now = at(0) + 31 * DAY;
    f.store.apply_dai_retention(now).unwrap();
    assert!(f.observations().is_empty(), "{:?}", f.observations());
    assert_eq!(f.summaries().len(), 5);
    let pending: Vec<(i64, Kind)> = f
        .pending()
        .into_iter()
        .map(|(_, slot, kind, _)| (slot, kind))
        .collect();
    assert_eq!(pending, [(later, Kind::DnsName)]);
    assert_eq!(f.earliest(A, Kind::DnsName), Some(later));
    assert_eq!(f.earliest(A, Kind::Kerberos), None);
    assert_eq!(f.counter(CUSTOMER, DaiCounterKind::NotApplied, now), 2);
    assert!(sends > 0);
    assert!(
        f.rows(super::super::DAI_SLOT_SENDS).is_empty(),
        "{:?}",
        f.rows(super::super::DAI_SLOT_SENDS)
    );
    assert!(
        f.rows(super::super::DAI_SEND_PARTS).is_empty(),
        "{:?}",
        f.rows(super::super::DAI_SEND_PARTS)
    );
    let marks: Vec<i64> = f.row(A, Kind::Ntlm).unwrap().marks.into_keys().collect();
    assert_eq!(marks, [later - 5 * MINUTE]);
    assert_eq!(
        f.counter(CUSTOMER, DaiCounterKind::FilteredAtReceipt, at(6)),
        0
    );
    assert_eq!(f.gaps(A, Kind::Ntlm).len(), 3);
    assert_eq!(f.rows(super::super::DAI_IP_ACTIVITY).len(), 2);

    // 181 days on.
    let now = at(0) + 181 * DAY;
    f.store.apply_dai_retention(now).unwrap();
    let summaries: Vec<i64> = f.summaries().into_iter().map(|s| s.last_seen).collect();
    assert_eq!(summaries.len(), 2);
    assert!(summaries.iter().all(|last| *last >= later));
    let activity = f.rows(super::super::DAI_IP_ACTIVITY);
    assert_eq!(activity.len(), 1);
    assert!(activity[0].0.ends_with(&[10, 0, 0, 2]));
    assert_eq!(
        f.gaps(A, Kind::Ntlm)
            .iter()
            .map(|g| g.1)
            .collect::<Vec<_>>(),
        [later]
    );
    assert_eq!(
        f.counter(CUSTOMER, DaiCounterKind::NotApplied, at(0) + 31 * DAY),
        0
    );
}

#[test]
fn expiring_pending_rows_counts_for_the_current_customer_only() {
    let f = setup();
    f.cursors(&[C], at(0));
    f.stored(
        &f.batch(C, Kind::DnsName, at(0), vec![dns("x", at(1), at(1), 1)]),
        at(6),
    );
    // C's node moves to OTHER's customer.
    change_node(&f, "c", OTHER);
    let now = at(0) + 31 * DAY;
    f.store.apply_dai_retention(now).unwrap();
    assert!(f.pending().is_empty(), "{:?}", f.pending());
    assert_eq!(f.counter(CUSTOMER, DaiCounterKind::NotApplied, now), 0);
    assert_eq!(f.counter(OTHER, DaiCounterKind::NotApplied, now), 1);
}

// ---- Customer deletion ----

/// Moves the node named `name` to `customer`.
fn change_node(f: &Fixture, name: &str, customer: u32) {
    let mut nodes = f.store.node_map();
    let node = nodes
        .iter(rocksdb::Direction::Forward, None)
        .map(Result::unwrap)
        .find(|node| node.name == name)
        .unwrap();
    let old = crate::NodeUpdate::from(node.clone());
    let mut new = crate::NodeUpdate::from(node.clone());
    if let Some(profile) = new.profile.as_mut() {
        profile.customer_id = customer;
    }
    nodes.update(node.id, &old, &new).unwrap();
}

/// Returns the rows of the sensor-keyed observation families whose key
/// starts with `sensor`.
fn sensor_rows(f: &Fixture, sensor: &str) -> Vec<RawRow> {
    [
        super::super::DAI_CURSORS,
        super::super::DAI_SLOT_SENDS,
        super::super::DAI_SEND_PARTS,
        super::super::DAI_CATCHUP_GAPS,
        super::super::DAI_SENSOR_KIND_STATE,
        super::super::DAI_EARLIEST_PENDING,
        super::super::DAI_OBSERVATIONS,
        super::super::DAI_OBSERVATION_SUMMARIES,
        super::super::DAI_PENDING,
    ]
    .iter()
    .flat_map(|family| f.rows(family))
    .filter(|(key, _)| key.starts_with(&sensor_key(sensor)))
    .collect()
}

#[test]
#[allow(clippy::too_many_lines)] // One scenario, checked step by step.
fn deleting_a_customer_removes_its_observation_rows_only() {
    let f = setup();
    f.set_enabled(OTHER, true, at(-60));
    f.cursors(&["all"], at(-30));
    let full = |sensor: &str, slot: i64| {
        let mut batch = f.batch(
            sensor,
            Kind::DnsName,
            slot,
            vec![dns("x", slot, slot, 1), lease(slot, None)],
        );
        batch.late_slots = vec![late(Kind::DnsName, at(-20), 0)];
        batch.lost_before = Some(at(-10));
        f.stored(&batch, slot + 6 * MINUTE);
        let mut unfinished = f.batch(sensor, Kind::Ntlm, slot, Vec::new());
        unfinished.part_count = 2;
        f.store(&unfinished, slot + 6 * MINUTE);
        f.stored(
            &f.batch(
                sensor,
                Kind::IpActivity,
                slot,
                vec![activity("10.0.0.1", slot, slot)],
            ),
            slot + 6 * MINUTE,
        );
        f.stored(
            &f.batch(
                sensor,
                Kind::DnsName,
                at(0) - 8 * DAY,
                vec![dns("old", at(0) - 8 * DAY, at(0) - 8 * DAY, 1)],
            ),
            slot + 6 * MINUTE,
        );
    };
    for sensor in [A, C, D, GONE] {
        full(sensor, at(0));
    }
    // C moves to OTHER's node; GONE's node is removed.
    change_node(&f, "c", OTHER);
    let gone = f
        .store
        .node_map()
        .iter(rocksdb::Direction::Forward, None)
        .map(Result::unwrap)
        .find(|node| node.name == "g")
        .unwrap();
    f.store.node_map().remove(gone.id).unwrap();
    // C stores for OTHER too.
    f.stored(
        &f.batch(
            C,
            Kind::DnsName,
            at(5),
            vec![dns("for other", at(6), at(6), 1)],
        ),
        at(11),
    );

    let d_rows = sensor_rows(&f, D);
    let c_rows = sensor_rows(&f, C);
    assert!(!sensor_rows(&f, A).is_empty(), "{:?}", sensor_rows(&f, A));
    assert!(
        !sensor_rows(&f, GONE).is_empty(),
        "{:?}",
        sensor_rows(&f, GONE)
    );
    let other_customer_rows = |family: &str| -> Vec<RawRow> {
        f.rows(family)
            .into_iter()
            .filter(|(key, _)| key.starts_with(&customer_key(OTHER)))
            .collect()
    };
    let other_counters = other_customer_rows(super::super::DAI_COUNTERS);
    let other_activity = other_customer_rows(super::super::DAI_IP_ACTIVITY);
    assert!(!other_counters.is_empty(), "{other_counters:?}");
    assert!(!other_activity.is_empty(), "{other_activity:?}");
    let meta = f.rows(super::super::DAI_META);

    let names = vec![GONE.to_string(), C.to_string()];
    f.store.delete_dai_customer(CUSTOMER, &names).unwrap();
    for sensor in [A, B, GONE] {
        assert!(sensor_rows(&f, sensor).is_empty(), "{sensor}");
    }
    assert_eq!(sensor_rows(&f, D), d_rows);
    // C keeps every row but its observations naming CUSTOMER.
    let c_after = sensor_rows(&f, C);
    let removed: Vec<&RawRow> = c_rows.iter().filter(|row| !c_after.contains(row)).collect();
    assert!(!removed.is_empty(), "{removed:?}");
    for (key, value) in removed {
        let row: ObservationRow = super::super::deserialize(value).unwrap();
        assert_eq!(row.customer_id, CUSTOMER);
        assert!(decode_observation_key(key).is_ok());
    }
    assert!(
        f.observations()
            .iter()
            .any(|(sensor, _, _, row)| sensor == C && row.customer_id == OTHER)
    );
    for family in [super::super::DAI_COUNTERS, super::super::DAI_IP_ACTIVITY] {
        assert!(
            f.rows(family)
                .iter()
                .all(|(key, _)| !key.starts_with(&customer_key(CUSTOMER))),
            "{family}"
        );
    }
    assert_eq!(
        other_customer_rows(super::super::DAI_COUNTERS),
        other_counters
    );
    assert_eq!(
        other_customer_rows(super::super::DAI_IP_ACTIVITY),
        other_activity
    );
    assert_eq!(f.rows(super::super::DAI_META), meta);

    let after = f.dump();
    f.store.delete_dai_customer(CUSTOMER, &names).unwrap();
    assert_eq!(f.dump(), after);
}

// ---- Keys ----

#[test]
fn observation_keys_read_back_and_order_by_their_components() {
    let hash = [7; 16];
    let key = super::observation::pending_key("s", at(0), Kind::IpActivity, &hash);
    assert_eq!(
        decode_pending_key(&key).unwrap(),
        ("s".to_string(), at(0), Kind::IpActivity, hash)
    );
    assert!(key.starts_with(&sensor_key("s")));
    assert!(
        summary_key("s", Kind::DhcpLease, &[0xFF; 16])
            < summary_key("s", Kind::DhcpServer, &[0; 16])
    );
    assert!(pair_key("s", Kind::DnsName) < pair_key("s", Kind::IpActivity));
    let counter = super::observation::counter_key(1, 4, -1);
    assert_eq!(
        super::observation::decode_counter_key(&counter).unwrap(),
        (1, 4, -1)
    );
    assert!(super::observation::counter_key(1, 4, -1) < super::observation::counter_key(1, 4, 0));
    for kind in KINDS {
        assert_eq!(kind_from_number(kind_number(kind)), Some(kind));
    }
    assert_eq!(kind_from_number(2), None);
}
