//! Tests of DAI slot application, the device tables, their retention and
//! their part of a customer's deletion.

use std::{collections::BTreeMap, net::IpAddr};

use review_protocol::types::{
    DaiDhcpMsg, DaiObservation, DaiObservationBatch, DaiObservationBody,
    DaiObservationKind as Kind, DaiSide, DaiSoftwareSource,
};
use tempfile::TempDir;
use uuid::Uuid;

use super::apply::{set_apply_scanned_hook, set_before_apply_commit_hook};
use super::cursor::{DAY, date_of, pair_key, slot_floor};
use super::device::{
    Activity, AliasReason, AliasRow, BindingRow, ChangeEntry, ChangeKind, ChangeOp, ChangeSource,
    ConflictRow, DeviceName, DeviceRow, EvidenceRow, Identifier, IdentifierKind, IdentifierRow,
    NameSource, OrderKey, SeenTimes, ServiceRow, Verdict, address_key, decode_binding_key,
    decode_evidence_key, device_key, identifier_key, resolver_point_key, service_key,
};
use super::device_retention::set_owners_checked_hook;
use super::hash::identifier_hash;
use super::observation::{DaiCounterKind, SeenRow, pending_key};
use super::*;
use crate::test::{DbGuard, acquire_db_permit};
use crate::{
    Agent, AgentKind, AgentStatus, DAI_APPLY_DEFAULT_MAX_COUNT, DaiPendingHead, DaiStoreOutcome,
    Node, NodeProfile, Store, dai_network_digest,
};

const NS: i64 = 1_000_000_000;
const MINUTE: i64 = 60 * NS;
const HOUR: i64 = 60 * MINUTE;
/// "12:00", a slot boundary: 1,700,000,100 is a multiple of 300.
const NOON: i64 = 1_700_000_100 * NS;
const CUSTOMER: u32 = 1;
/// A customer whose DAI configuration is never written, so it has no default
/// site.
const OTHER: u32 = 2;
const A: &str = "piglet.a.example";
const B: &str = "piglet.b.example";
/// The sensor of [`OTHER`].
const D: &str = "piglet.d.example";
/// A name nodes of both customers give, so not a customer sensor.
const SHARED: &str = "piglet.s.example";
/// The DHCP server.
const SERVER: &str = "10.0.0.254";
/// The confirmed Kerberos realm of [`CUSTOMER`].
const REALM: &str = "CORP.EXAMPLE";
/// The DAI device column families.
const DEVICE_FAMILIES: [&str; 13] = [
    super::super::DAI_RESOLVER_POINTS,
    super::super::DAI_DEVICES,
    super::super::DAI_DEVICE_IDENTIFIERS,
    super::super::DAI_DEVICE_ALIASES,
    super::super::DAI_BINDINGS,
    super::super::DAI_DEVICE_BINDINGS,
    super::super::DAI_EVIDENCE,
    super::super::DAI_IP_STATE,
    super::super::DAI_FIXED_IPS,
    super::super::DAI_CONFLICTS,
    super::super::DAI_SERVICES,
    super::super::DAI_SOFTWARE_STRINGS,
    super::super::DAI_DEVICE_CHANGES,
];

/// Returns the time `secs` seconds after [`NOON`].
fn t(secs: i64) -> i64 {
    NOON + secs * NS
}

/// Returns the time `minutes` minutes after [`NOON`].
fn m(minutes: i64) -> i64 {
    NOON + minutes * MINUTE
}

fn ip(addr: &str) -> IpAddr {
    addr.parse().unwrap()
}

/// Returns the `chaddr` of MAC `n`, a locally administered unicast MAC.
fn mac(n: u8) -> Vec<u8> {
    vec![0x02, 0, 0, 0, 0, n]
}

fn mac_id(n: u8) -> Identifier {
    Identifier::mac(&format!("02:00:00:00:00:{n:02x}"))
}

/// An O1 to build a body from.
#[derive(Clone)]
struct Lease {
    msg: DaiDhcpMsg,
    time: i64,
    ip: &'static str,
    chaddr: Vec<u8>,
    server_id: Option<&'static str>,
    giaddr: &'static str,
    hostname: Option<&'static str>,
    secs: Option<u32>,
}

impl Lease {
    fn new(msg: DaiDhcpMsg, time: i64, ip: &'static str, mac_n: u8) -> Self {
        Self {
            msg,
            time,
            ip,
            chaddr: mac(mac_n),
            server_id: Some(SERVER),
            giaddr: "0.0.0.0",
            hostname: None,
            secs: Some(300),
        }
    }

    fn ack(time: i64, ip: &'static str, mac_n: u8) -> Self {
        Self::new(DaiDhcpMsg::Ack, time, ip, mac_n)
    }

    fn release(time: i64, ip: &'static str, mac_n: u8) -> Self {
        Self::new(DaiDhcpMsg::Release, time, ip, mac_n)
    }

    fn body(&self) -> DaiObservationBody {
        DaiObservationBody::DhcpLease {
            time: self.time,
            msg: self.msg,
            ip: ip(self.ip),
            chaddr: self.chaddr.clone(),
            xid: 1,
            server_ip: ip(SERVER),
            server_id: self.server_id.map(ip),
            giaddr: ip(self.giaddr),
            client_id: None,
            hostname: self.hostname.map(ToString::to_string),
            lease_secs: self.secs,
            subnet_mask: None,
            routers: Vec::new(),
        }
    }
}

/// Returns an O4 body.
fn krb(client: &str, realm: &str, cname: &str, msg_type: u8, preauth: u8) -> DaiObservationBody {
    DaiObservationBody::Kerberos {
        client_ip: ip(client),
        realm: realm.to_string(),
        cname: vec![cname.to_string()],
        sname: vec!["krbtgt".to_string()],
        msg_type,
        accepted: true,
        preauth,
        error_code: None,
    }
}

/// Returns a verified O4 body under [`REALM`].
fn verified(client: &str, cname: &str) -> DaiObservationBody {
    krb(client, &REALM.to_ascii_lowercase(), cname, 11, 2)
}

fn ntlm(client: &str) -> DaiObservationBody {
    DaiObservationBody::Ntlm {
        ip: ip(client),
        workstation: "WS".to_string(),
        user: "user".to_string(),
        domain: "CORP".to_string(),
        success: true,
    }
}

fn dns(name: &str, addr: &str) -> DaiObservationBody {
    DaiObservationBody::DnsName {
        name: name.to_string(),
        ip: ip(addr),
    }
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

/// A binding as a test compares it: its site, IP, start, end, whether the
/// end is estimated, and its device.
type Bound = (String, IpAddr, i64, Option<i64>, bool, Uuid);

struct Fixture {
    store: Store,
    _permit: DbGuard<'static>,
    _dirs: (TempDir, TempDir),
}

/// A store whose nodes give [`CUSTOMER`] the sensors [`A`] and [`B`],
/// [`OTHER`] the sensor [`D`], and both [`SHARED`], with [`CUSTOMER`]'s
/// settings written an hour before [`NOON`]: device identification on, an
/// inactivity multiplier of 2, an hour without a lease, 180 days of evidence
/// aging and the realm [`REALM`].
fn setup() -> Fixture {
    let permit = acquire_db_permit();
    let data = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    let store = Store::new(data.path(), backup.path(), None).unwrap();
    for (name, customer, host) in [
        ("a", CUSTOMER, "a.example"),
        ("b", CUSTOMER, "b.example"),
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
    let fixture = Fixture {
        store,
        _permit: permit,
        _dirs: (data, backup),
    };
    fixture.update_settings(|_| {});
    fixture
}

impl Fixture {
    fn dai(&self) -> Dai<'_> {
        self.store.states.dai()
    }

    fn db(&self) -> &rocksdb::OptimisticTransactionDB {
        self.store.states.db()
    }

    /// Writes [`CUSTOMER`]'s settings as the fixture's, changed by `change`.
    fn update_settings(&self, change: impl FnOnce(&mut DaiSettingsUpdate)) {
        let mut update = DaiSettingsUpdate {
            device_account_identification: true,
            inactivity_multiplier: 2,
            no_lease_inactivity_secs: 3600,
            evidence_aging_secs: 180 * 86_400,
            kerberos_preauth_realms: vec![REALM.to_string()],
        };
        let stored = self.dai().settings(CUSTOMER).unwrap();
        if stored.revision > 0 {
            update.inactivity_multiplier = stored.inactivity_multiplier;
            update.no_lease_inactivity_secs = stored.no_lease_inactivity_secs;
            update.evidence_aging_secs = stored.evidence_aging_secs;
            update
                .kerberos_preauth_realms
                .clone_from(&stored.kerberos_preauth_realms);
        }
        change(&mut update);
        self.dai()
            .set_settings(CUSTOMER, stored.revision, &update, &(NOON - HOUR))
            .unwrap();
    }

    /// Queues an observation of `body` seen from `first` to `last` for
    /// `sensor` in the slot holding `first`, as a store does: the pending
    /// row, merged into one already there, and the earliest pending row.
    fn enqueue(&self, sensor: &str, body: &DaiObservationBody, first: i64, last: i64) {
        let dai = self.dai();
        let slot = slot_floor(first).unwrap();
        enqueue_in(&dai, sensor, slot, body, first, last);
    }

    /// Queues an O1 for `sensor` at its time.
    fn lease(&self, sensor: &str, lease: &Lease) {
        self.enqueue(sensor, &lease.body(), lease.time, lease.time);
    }

    /// Applies every pending row of `sensor`'s slot starting at `slot`.
    fn apply(&self, sensor: &str, slot: i64) -> Option<i64> {
        self.store
            .apply_dai_slot(sensor, slot, DAI_APPLY_DEFAULT_MAX_COUNT, NOON)
            .unwrap()
    }

    /// Applies every pending row of every sensor, slot by slot.
    fn apply_all(&self) {
        while let Some(head) = self.store.dai_pending_heads().unwrap().into_iter().next() {
            self.apply(&head.sensor, head.slot_start);
        }
    }

    /// Queues and applies one O1 of `sensor`.
    fn applied(&self, sensor: &str, lease: &Lease) {
        self.lease(sensor, lease);
        self.apply(sensor, slot_floor(lease.time).unwrap());
    }

    /// Queues and applies one observation of `sensor`.
    fn observed(&self, sensor: &str, body: &DaiObservationBody, first: i64, last: i64) {
        self.enqueue(sensor, body, first, last);
        self.apply(sensor, slot_floor(first).unwrap());
    }

    fn rows(&self, family: &str) -> Vec<RawRow> {
        let db = self.db();
        let cf = db.cf_handle(family).unwrap();
        db.iterator_cf(cf, rocksdb::IteratorMode::Start)
            .map(Result::unwrap)
            .collect()
    }

    fn count(&self, family: &str) -> usize {
        self.rows(family).len()
    }

    /// Returns the bindings of [`CUSTOMER`], in key order.
    fn bindings(&self) -> Vec<Bound> {
        self.bindings_of(CUSTOMER)
    }

    fn bindings_of(&self, customer: u32) -> Vec<Bound> {
        self.binding_rows(customer)
            .into_iter()
            .map(|(site, ip, start, row)| (site, ip, start, row.end, row.end_estimated, row.device))
            .collect()
    }

    fn binding_rows(&self, customer: u32) -> Vec<(String, IpAddr, i64, BindingRow)> {
        self.rows(super::super::DAI_BINDINGS)
            .into_iter()
            .filter_map(|(key, value)| {
                let (c, site, ip, start) = decode_binding_key(&key).unwrap();
                (c == customer)
                    .then(|| (site, ip, start, super::super::deserialize(&value).unwrap()))
            })
            .collect()
    }

    /// Returns the (start, end) of each binding of [`CUSTOMER`] at `addr`.
    fn spans(&self, addr: &str) -> Vec<(i64, Option<i64>)> {
        self.bindings()
            .into_iter()
            .filter(|(_, ip, ..)| *ip == self::ip(addr))
            .map(|(_, _, start, end, ..)| (start, end))
            .collect()
    }

    fn binding(&self, addr: &str, start: i64) -> BindingRow {
        self.binding_rows(CUSTOMER)
            .into_iter()
            .find(|(_, ip, s, _)| *ip == self::ip(addr) && *s == start)
            .map(|(.., row)| row)
            .expect("the binding exists")
    }

    fn devices(&self) -> BTreeMap<Uuid, DeviceRow> {
        self.rows(super::super::DAI_DEVICES)
            .into_iter()
            .filter(|(key, _)| key.starts_with(&customer_key(CUSTOMER)))
            .map(|(key, value)| {
                let mut reader = KeyReader::new(&key);
                reader.u32().unwrap();
                (
                    reader.uuid().unwrap(),
                    super::super::deserialize(&value).unwrap(),
                )
            })
            .collect()
    }

    fn device(&self, device: Uuid) -> DeviceRow {
        self.devices().remove(&device).expect("the device exists")
    }

    fn identifier(&self, id: &Identifier) -> Option<IdentifierRow> {
        let dai = self.dai();
        dai.read(|txn| dai.identifier_in(txn, CUSTOMER, id))
            .unwrap()
    }

    /// Returns the device holding MAC `n`.
    fn owner(&self, n: u8) -> Uuid {
        self.identifier(&mac_id(n)).expect("the MAC is held").device
    }

    fn evidence(&self) -> Vec<(i64, Kind, EvidenceRow)> {
        self.rows(super::super::DAI_EVIDENCE)
            .into_iter()
            .map(|(key, value)| {
                let key = decode_evidence_key(&key).unwrap();
                (
                    key.last_seen,
                    key.kind,
                    super::super::deserialize(&value).unwrap(),
                )
            })
            .collect()
    }

    fn changes(&self, device: Uuid) -> Vec<(u64, ChangeEntry)> {
        let prefix = KeyWriter::default().u32(CUSTOMER).uuid(device).finish();
        self.rows(super::super::DAI_DEVICE_CHANGES)
            .into_iter()
            .filter(|(key, _)| key.starts_with(&prefix))
            .map(|(key, value)| {
                let mut reader = KeyReader::new(&key);
                reader.u32().unwrap();
                reader.uuid().unwrap();
                (
                    reader.u64().unwrap(),
                    super::super::deserialize(&value).unwrap(),
                )
            })
            .collect()
    }

    fn counter(&self, customer: u32, kind: DaiCounterKind) -> u64 {
        self.dai().counter(customer, kind, date_of(NOON).unwrap())
    }

    /// Returns whether `sensor` has a resolver point row.
    fn has_resolver_point(&self, sensor: &str) -> bool {
        self.dai()
            .read(|txn| {
                Dai::get_row::<Option<i64>>(
                    txn,
                    &self.dai().resolver_points,
                    &resolver_point_key(sensor),
                )
            })
            .unwrap()
            .is_some()
    }

    /// Returns the resolver point of `sensor`, which has one.
    fn resolver_point(&self, sensor: &str) -> Option<i64> {
        let dai = self.dai();
        dai.read(|txn| Dai::get_row(txn, &dai.resolver_points, &resolver_point_key(sensor)))
            .unwrap()
            .expect("the sensor has a resolver point")
    }

    fn put<T: serde::Serialize>(&self, family: &str, key: &[u8], value: &T) {
        let db = self.db();
        db.put_cf(
            db.cf_handle(family).unwrap(),
            key,
            super::super::serialize(value).unwrap(),
        )
        .unwrap();
    }

    fn retention(&self, now: i64) {
        self.store.apply_dai_retention(now).unwrap();
    }
}

/// Queues, within one transaction of `dai`, an observation as a store does.
fn enqueue_in(
    dai: &Dai<'_>,
    sensor: &str,
    slot: i64,
    body: &DaiObservationBody,
    first: i64,
    last: i64,
) {
    let kind = super::observation::body_kind(body);
    let hash = identifier_hash(body).unwrap();
    let key = pending_key(sensor, slot, kind, &hash);
    dai.write(|txn| {
        let row = match Dai::get_row::<SeenRow>(txn, &dai.pending, &key)? {
            Some(stored) => stored.widened(body, first, last),
            None => SeenRow {
                body: body.clone(),
                first_seen: first,
                last_seen: last,
            },
        };
        Dai::put_row(txn, &dai.pending, &key, &row)?;
        let pair = pair_key(sensor, kind);
        let earliest = Dai::get_row::<i64>(txn, &dai.earliest_pending, &pair)?
            .map_or(slot, |earliest| earliest.min(slot));
        Dai::put_row(txn, &dai.earliest_pending, &pair, &earliest)
    })
    .unwrap();
}

// ---- The transaction ----

#[test]
fn apply_takes_up_to_max_count_in_order_and_sets_the_resolver_point() {
    let f = setup();
    let slot = NOON;
    f.lease(A, &Lease::ack(t(30), "10.0.0.1", 1));
    f.lease(A, &Lease::ack(t(10), "10.0.0.2", 2));
    f.lease(A, &Lease::ack(t(20), "10.0.0.3", 3));
    f.enqueue(A, &dns("later.example", "10.0.0.9"), m(10), m(10));

    // 0 is refused and writes nothing.
    assert!(f.store.apply_dai_slot(A, slot, 0, NOON).is_err());
    assert_eq!(f.count(super::super::DAI_PENDING), 4);
    assert!(!f.has_resolver_point(A));

    // The two earliest in apply order.
    assert_eq!(
        f.store.apply_dai_slot(A, slot, 2, NOON).unwrap(),
        Some(slot)
    );
    let started: Vec<i64> = f.bindings().iter().map(|b| b.2).collect();
    assert_eq!(started, [t(10), t(20)]);
    assert_eq!(f.resolver_point(A), Some(slot));
    assert_eq!(
        f.store.dai_pending_heads().unwrap(),
        [DaiPendingHead {
            sensor: A.to_string(),
            slot_start: slot
        }]
    );

    // The rest of the slot; the 12:10 slot remains.
    assert_eq!(f.apply(A, slot), Some(m(10)));
    assert_eq!(f.bindings().len(), 3);
    assert_eq!(f.store.dai_pending_heads().unwrap()[0].slot_start, m(10));
    // An empty slot changes nothing but the resolver point.
    assert_eq!(f.apply(A, m(5)), Some(m(10)));
    assert_eq!(f.apply(A, m(10)), None);
    assert_eq!(f.resolver_point(A), None);
    assert_eq!(f.store.dai_pending_heads().unwrap(), []);
    assert_eq!(f.count(super::super::DAI_PENDING), 0);
    assert_eq!(f.count(super::super::DAI_EARLIEST_PENDING), 0);
}

#[test]
fn pending_heads_list_each_sensor_with_its_earliest_slot() {
    let f = setup();
    f.enqueue(A, &dns("x", "10.0.0.1"), m(10), m(10));
    f.lease(A, &Lease::ack(m(5), "10.0.0.1", 1));
    f.lease(B, &Lease::ack(m(20), "10.0.0.2", 2));
    f.lease(SHARED, &Lease::ack(m(0), "10.0.0.3", 3));
    let heads = f.store.dai_pending_heads().unwrap();
    let heads: Vec<(&str, i64)> = heads
        .iter()
        .map(|head| (head.sensor.as_str(), head.slot_start))
        .collect();
    assert_eq!(heads, [(A, m(5)), (B, m(20)), (SHARED, m(0))]);
    f.apply_all();
    assert_eq!(f.store.dai_pending_heads().unwrap(), []);
    assert_eq!(f.resolver_point(B), None);
}

#[test]
fn a_non_customer_sensor_has_its_rows_deleted_unapplied() {
    let f = setup();
    f.lease(SHARED, &Lease::ack(t(10), "10.0.0.1", 1));
    assert_eq!(f.apply(SHARED, NOON), None);
    assert_eq!(f.count(super::super::DAI_PENDING), 0);
    assert_eq!(f.count(super::super::DAI_EARLIEST_PENDING), 0);
    assert_eq!(f.count(super::super::DAI_DEVICES), 0);
    assert_eq!(f.count(super::super::DAI_EVIDENCE), 0);
    assert_eq!(f.counter(CUSTOMER, DaiCounterKind::NotApplied), 0);
    assert_eq!(f.counter(OTHER, DaiCounterKind::NotApplied), 0);
}

#[test]
fn a_customer_without_a_default_site_does_not_apply() {
    let f = setup();
    f.lease(D, &Lease::ack(t(10), "10.0.0.1", 1));
    f.lease(D, &Lease::ack(t(20), "10.0.0.2", 2));
    assert_eq!(f.apply(D, NOON), None);
    assert_eq!(f.count(super::super::DAI_PENDING), 0);
    assert_eq!(f.count(super::super::DAI_DEVICES), 0);
    assert_eq!(f.counter(OTHER, DaiCounterKind::NotApplied), 2);
}

#[test]
fn a_folded_slot_is_applied() {
    let f = setup();
    let now = NOON + 8 * DAY;
    f.store.dai_cursors(&[A.to_string()], now).unwrap();
    let observation = DaiObservation {
        first_seen: t(10),
        last_seen: t(10),
        count: 1,
        body: Lease::ack(t(10), "10.0.0.1", 1).body(),
    };
    let batch = DaiObservationBatch {
        restore_generation: f.store.dai_restore_generation().unwrap(),
        config_epoch: f.store.dai_sensor_config_epoch(A).unwrap(),
        network_digest: dai_network_digest(None).unwrap().digest,
        sensor: A.to_string(),
        kind: Kind::DhcpLease,
        slot_start: NOON,
        slot_len_secs: 300,
        send_id: 1,
        part: 0,
        part_count: 1,
        observations: vec![observation],
        last_record_time: None,
        late_slots: Vec::new(),
        reextract_mark: None,
        lost_before: None,
        counted_from: NOON,
    };
    assert!(matches!(
        f.store.store_dai_observations(&batch, now).unwrap(),
        DaiStoreOutcome::Stored { .. }
    ));
    assert_eq!(f.count(super::super::DAI_OBSERVATIONS), 0);
    assert_eq!(f.count(super::super::DAI_OBSERVATION_SUMMARIES), 1);
    assert_eq!(f.apply(A, NOON), None);
    assert_eq!(f.spans("10.0.0.1"), [(t(10), None)]);
}

#[test]
fn a_store_overwriting_a_taken_row_is_applied_with_its_new_content() {
    let f = setup();
    let plain = Lease::ack(t(10), "10.0.0.1", 1);
    f.lease(A, &plain);
    let named = Lease {
        hostname: Some("laptop"),
        ..plain
    };
    set_before_apply_commit_hook(Box::new(move |db| {
        let dai = Dai::open(db).unwrap();
        enqueue_in(&dai, A, NOON, &named.body(), t(10), t(10));
    }));
    f.apply(A, NOON);
    let devices = f.devices();
    let device = devices.values().next().unwrap();
    assert_eq!(device.representative_name(), Some("laptop"));
    assert_eq!(f.count(super::super::DAI_PENDING), 0);
}

#[test]
fn a_store_adding_a_row_to_the_slot_is_seen_by_the_retry() {
    let f = setup();
    f.lease(A, &Lease::ack(t(10), "10.0.0.1", 1));
    set_before_apply_commit_hook(Box::new(move |db| {
        let dai = Dai::open(db).unwrap();
        let body = Lease::ack(t(20), "10.0.0.2", 2).body();
        enqueue_in(&dai, A, NOON, &body, t(20), t(20));
    }));
    assert_eq!(f.apply(A, NOON), None);
    assert_eq!(f.bindings().len(), 2);
    assert_eq!(f.count(super::super::DAI_PENDING), 0);
    assert_eq!(f.count(super::super::DAI_EARLIEST_PENDING), 0);
}

#[test]
fn a_store_adding_a_row_between_the_scan_and_its_reads_is_seen_by_the_retry() {
    let f = setup();
    // A service at second 15 bound only by the ACK at second 10 the store
    // adds after the scan; deciding it without that ACK would discard it.
    f.lease(A, &Lease::ack(t(20), "10.0.0.1", 1));
    f.enqueue(
        A,
        &DaiObservationBody::Service {
            server_ip: ip("10.0.0.1"),
            port: 22,
            proto: 6,
            external_client: false,
        },
        t(15),
        t(15),
    );
    set_apply_scanned_hook(Box::new(move |db| {
        let dai = Dai::open(db).unwrap();
        let body = Lease::ack(t(10), "10.0.0.1", 1).body();
        enqueue_in(&dai, A, NOON, &body, t(10), t(10));
    }));
    assert_eq!(f.apply(A, NOON), None);
    assert_eq!(f.spans("10.0.0.1"), [(t(10), None)]);
    let key = service_key(CUSTOMER, f.owner(1), 22, 6);
    let service: Option<ServiceRow> = f
        .dai()
        .read(|txn| Dai::get_row(txn, &f.dai().services, &key))
        .unwrap();
    assert_eq!(
        service.map(|row| (row.first_seen, row.last_seen)),
        Some((t(15), t(15)))
    );
    assert_eq!(f.count(super::super::DAI_PENDING), 0);
    assert_eq!(f.count(super::super::DAI_EARLIEST_PENDING), 0);
}

#[test]
fn a_configuration_write_racing_an_apply_is_read_by_the_retry() {
    let f = setup();
    f.lease(A, &Lease::ack(t(10), "10.0.0.1", 1));
    set_before_apply_commit_hook(Box::new(move |db| {
        let dai = Dai::open(db).unwrap();
        let stored = dai.settings(CUSTOMER).unwrap();
        let update = DaiSettingsUpdate {
            device_account_identification: true,
            inactivity_multiplier: 5,
            no_lease_inactivity_secs: stored.no_lease_inactivity_secs,
            evidence_aging_secs: stored.evidence_aging_secs,
            kerberos_preauth_realms: stored.kerberos_preauth_realms,
        };
        dai.set_settings(CUSTOMER, stored.revision, &update, &NOON)
            .unwrap();
    }));
    f.apply(A, NOON);
    assert_eq!(f.binding("10.0.0.1", t(10)).inactivity, 1500 * NS);
}

#[test]
fn two_sensors_of_one_site_racing_on_one_ip_end_as_if_sequential() {
    let f = setup();
    f.lease(A, &Lease::ack(t(10), "10.0.0.1", 1));
    set_before_apply_commit_hook(Box::new(move |db| {
        let dai = Dai::open(db).unwrap();
        let body = Lease::ack(t(20), "10.0.0.1", 2).body();
        enqueue_in(&dai, B, NOON, &body, t(20), t(20));
        dai.apply_slot(B, NOON, 500, NOON).unwrap();
    }));
    f.apply(A, NOON);
    let bound = f.bindings();
    assert_eq!(f.spans("10.0.0.1"), [(t(10), Some(t(20))), (t(20), None)]);
    assert_eq!(bound[0].5, f.owner(1));
    assert_eq!(bound[1].5, f.owner(2));
}

// ---- Devices and bindings ----

#[test]
fn only_an_ack_with_a_valid_mac_creates_a_device() {
    let f = setup();
    for (n, chaddr) in [
        vec![0x02, 0, 0, 0, 0],
        vec![0; 6],
        vec![0xff; 6],
        vec![0x03, 0, 0, 0, 0, 1],
        vec![0x02, 0, 0, 0, 0, 1, 0],
    ]
    .into_iter()
    .enumerate()
    {
        let lease = Lease {
            chaddr,
            ..Lease::ack(t(10 + i64::try_from(n).unwrap()), "10.0.0.1", 0)
        };
        f.applied(A, &lease);
    }
    assert_eq!(f.count(super::super::DAI_DEVICES), 0);
    assert_eq!(f.count(super::super::DAI_BINDINGS), 0);

    // O5, an unverified O4, O7, O8 and O22 alone, and a verified O4 alone.
    let alone = "10.0.0.2";
    f.observed(A, &ntlm(alone), t(30), t(30));
    f.observed(A, &krb(alone, REALM, "HOST$", 13, 2), t(31), t(31));
    f.observed(A, &verified(alone, "HOST$"), t(32), t(32));
    f.observed(
        A,
        &DaiObservationBody::Service {
            server_ip: ip(alone),
            port: 22,
            proto: 6,
            external_client: false,
        },
        t(33),
        t(33),
    );
    f.observed(
        A,
        &DaiObservationBody::SoftwareString {
            ip: ip(alone),
            side: DaiSide::Server,
            source: DaiSoftwareSource::Ssh,
            text: "OpenSSH".to_string(),
        },
        t(34),
        t(34),
    );
    f.observed(A, &dns("name.example", alone), t(35), t(35));
    assert_eq!(f.count(super::super::DAI_DEVICES), 0);
    assert_eq!(f.count(super::super::DAI_BINDINGS), 0);
    assert_eq!(f.count(super::super::DAI_DEVICE_IDENTIFIERS), 0);
    assert_eq!(f.count(super::super::DAI_SERVICES), 0);
    assert_eq!(f.count(super::super::DAI_SOFTWARE_STRINGS), 0);

    f.applied(A, &Lease::ack(t(40), "10.0.0.3", 7));
    let devices = f.devices();
    assert_eq!(devices.len(), 1);
    let (id, device) = devices.into_iter().next().unwrap();
    assert_eq!(id.get_version_num(), 4);
    assert_eq!(device.identifiers, [mac_id(7)]);
    assert_eq!(device.verdict, Verdict::Observed);
    assert_eq!(device.activity, Activity::Active);
    assert_eq!(device.origin, super::device::Origin::Observation);
    assert_eq!(
        (device.first_seen, device.last_seen, device.version),
        (t(40), t(40), 1)
    );
    let binding = f.binding("10.0.0.3", t(40));
    assert_eq!(binding.device, id);
    assert_eq!(binding.evidence_kind, 1);
    assert_eq!(binding.evidence_identifier, mac_id(7));
    assert_eq!(binding.server_id, Some(ip(SERVER)));
    assert_eq!(binding.inactivity, 600 * NS);
    let changes = f.changes(id);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].1.kind, ChangeKind::Created);
    assert_eq!(changes[0].1.source, ChangeSource::Observation(1));
    assert_eq!(changes[0].1.time, t(40));
}

#[test]
fn an_invalid_chaddr_still_closes_the_open_binding() {
    let f = setup();
    f.applied(A, &Lease::ack(t(10), "10.0.0.1", 1));
    let invalid = Lease {
        chaddr: vec![0; 6],
        ..Lease::ack(t(20), "10.0.0.1", 0)
    };
    f.applied(A, &invalid);
    assert_eq!(f.spans("10.0.0.1"), [(t(10), Some(t(20)))]);
    assert_eq!(f.count(super::super::DAI_DEVICES), 1);
}

#[test]
fn two_macs_with_one_hostname_are_two_devices() {
    let f = setup();
    f.applied(
        A,
        &Lease {
            hostname: Some("same"),
            ..Lease::ack(t(10), "10.0.0.1", 1)
        },
    );
    f.applied(
        A,
        &Lease {
            hostname: Some("same"),
            ..Lease::ack(t(20), "10.0.0.2", 2)
        },
    );
    assert_eq!(f.devices().len(), 2);
    assert_ne!(f.owner(1), f.owner(2));
}

#[test]
fn an_ip_moving_to_another_mac_closes_and_a_device_keeps_two_ips() {
    let f = setup();
    f.applied(A, &Lease::ack(t(10), "10.0.0.1", 1));
    f.applied(A, &Lease::ack(t(20), "10.0.0.2", 1));
    f.applied(A, &Lease::ack(t(30), "10.0.0.1", 2));
    assert_eq!(f.spans("10.0.0.1"), [(t(10), Some(t(30))), (t(30), None)]);
    assert_eq!(f.spans("10.0.0.2"), [(t(20), None)]);
    assert_eq!(f.binding("10.0.0.2", t(20)).device, f.owner(1));
    assert_eq!(f.binding("10.0.0.1", t(30)).device, f.owner(2));
    // The same device extends, with the latest ACK's server id.
    f.applied(
        A,
        &Lease {
            server_id: None,
            ..Lease::ack(t(40), "10.0.0.2", 1)
        },
    );
    let extended = f.binding("10.0.0.2", t(20));
    assert_eq!((extended.last_strong, extended.server_id), (t(40), None));
    assert_eq!(f.spans("10.0.0.2"), [(t(20), None)]);
}

#[test]
fn two_acks_at_one_time_leave_the_later_in_apply_order() {
    let f = setup();
    let first = Lease::ack(t(10), "10.0.0.1", 1);
    let second = Lease::ack(t(10), "10.0.0.1", 2);
    f.lease(A, &first);
    f.lease(A, &second);
    f.apply(A, NOON);
    let later =
        if identifier_hash(&first.body()).unwrap() < identifier_hash(&second.body()).unwrap() {
            2
        } else {
            1
        };
    assert_eq!(f.spans("10.0.0.1"), [(t(10), None)]);
    assert_eq!(f.binding("10.0.0.1", t(10)).device, f.owner(later));
    assert_eq!(f.count(super::super::DAI_DEVICE_BINDINGS), 1);
}

#[test]
fn inform_ack_o5_and_weak_o4_never_change_a_binding() {
    let f = setup();
    f.applied(A, &Lease::ack(t(10), "10.0.0.1", 1));
    let before = f.binding("10.0.0.1", t(10));
    let inform = Lease {
        hostname: Some("informed"),
        ..Lease::new(DaiDhcpMsg::InformAck, m(5), "10.0.0.1", 1)
    };
    f.applied(A, &inform);
    f.observed(A, &ntlm("10.0.0.1"), m(6), m(7));
    f.observed(A, &krb("10.0.0.1", REALM, "HOST$", 11, 1), m(8), m(8));
    assert_eq!(f.binding("10.0.0.1", t(10)), before);
    let device = f.device(f.owner(1));
    assert_eq!(device.last_seen, m(8));
    assert_eq!(device.representative_name(), Some("informed"));
    assert_eq!(f.identifier(&mac_id(1)).unwrap().last_confirmed, m(5));
    // Past the binding, an INFORM ACK creates nothing and confirms nothing.
    f.applied(A, &Lease::new(DaiDhcpMsg::InformAck, m(30), "10.0.0.1", 1));
    f.applied(A, &Lease::new(DaiDhcpMsg::InformAck, m(9), "10.0.0.5", 1));
    assert_eq!(f.bindings().len(), 1);
    assert_eq!(f.device(f.owner(1)).last_seen, m(8));
    assert_eq!(f.identifier(&mac_id(1)).unwrap().last_confirmed, m(5));
}

#[test]
fn a_binding_counts_as_ended_after_its_inactivity_time_and_retention_writes_it() {
    let f = setup();
    // 300 s × 2: a 10-minute inactivity time.
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    // Not covered past 12:10.
    f.observed(A, &ntlm("10.0.0.1"), m(11), m(11));
    assert_eq!(f.device(f.owner(1)).last_seen, m(0));
    f.observed(A, &ntlm("10.0.0.1"), m(9), m(9));
    assert_eq!(f.device(f.owner(1)).last_seen, m(9));
    // A same-MAC ACK past it starts a new binding.
    f.applied(A, &Lease::ack(m(12), "10.0.0.1", 1));
    assert_eq!(f.spans("10.0.0.1"), [(m(0), None), (m(12), None)]);
    f.retention(m(20));
    let ended = f.bindings();
    assert_eq!((ended[0].3, ended[0].4), (Some(m(10)), true));
    assert_eq!((ended[1].3, ended[1].4), (None, false));
}

/// Applies a 12:00 ACK with a 10-minute inactivity time, runs retention at
/// 12:20 if `retained`, and then applies `then`, returning the binding.
fn after_estimated_end(retained: bool, then: &Lease) -> (Vec<(i64, Option<i64>)>, BindingRow) {
    let f = setup();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    if retained {
        f.retention(m(20));
        let row = f.binding("10.0.0.1", m(0));
        assert_eq!((row.end, row.end_estimated), (Some(m(10)), true));
    }
    f.applied(A, then);
    let mut binding = f.binding("10.0.0.1", m(0));
    assert_eq!(binding.device, f.owner(1));
    // Device ids are random: two stores compare without them.
    binding.device = Uuid::nil();
    (f.spans("10.0.0.1"), binding)
}

#[test]
fn an_estimated_end_changes_no_rule() {
    let ack = Lease::ack(m(5), "10.0.0.1", 1);
    let before = after_estimated_end(false, &ack);
    let after = after_estimated_end(true, &ack);
    assert_eq!(before, after);
    assert_eq!(after.0, [(m(0), None)]);
    assert_eq!((after.1.end_estimated, after.1.last_strong), (false, m(5)));

    let release = Lease::release(m(5), "10.0.0.1", 1);
    let before = after_estimated_end(false, &release);
    let after = after_estimated_end(true, &release);
    assert_eq!(before, after);
    assert_eq!(after.0, [(m(0), Some(m(5)))]);
    assert!(!after.1.end_estimated);
}

#[test]
fn inactivity_comes_from_the_lease_and_the_settings_at_creation() {
    let f = setup();
    f.applied(A, &Lease::ack(t(10), "10.0.0.1", 1));
    f.applied(
        A,
        &Lease {
            secs: None,
            ..Lease::ack(t(20), "10.0.0.2", 2)
        },
    );
    f.applied(
        A,
        &Lease {
            secs: Some(0),
            ..Lease::ack(t(30), "10.0.0.3", 3)
        },
    );
    f.update_settings(|update| {
        update.inactivity_multiplier = 3;
        update.no_lease_inactivity_secs = 60;
    });
    f.applied(A, &Lease::ack(t(40), "10.0.0.4", 4));
    f.applied(A, &Lease::ack(t(50), "10.0.0.1", 1));
    assert_eq!(f.binding("10.0.0.1", t(10)).inactivity, 600 * NS);
    assert_eq!(f.binding("10.0.0.2", t(20)).inactivity, 3600 * NS);
    assert_eq!(f.binding("10.0.0.3", t(30)).inactivity, 3600 * NS);
    assert_eq!(f.binding("10.0.0.4", t(40)).inactivity, 900 * NS);
    f.applied(
        A,
        &Lease {
            secs: Some(u32::MAX),
            ..Lease::ack(t(60), "10.0.0.5", 5)
        },
    );
    // u32::MAX × 3 seconds is past i64::MAX nanoseconds: it saturates.
    assert_eq!(f.binding("10.0.0.5", t(60)).inactivity, i64::MAX);
}

#[test]
fn release_and_decline_close_only_a_matching_binding() {
    let f = setup();
    f.applied(A, &Lease::ack(t(10), "10.0.0.1", 1));
    f.applied(A, &Lease::release(t(20), "10.0.0.1", 2));
    f.applied(
        A,
        &Lease {
            server_id: Some("10.0.0.253"),
            ..Lease::release(t(21), "10.0.0.1", 1)
        },
    );
    f.applied(
        A,
        &Lease {
            server_id: None,
            ..Lease::release(t(22), "10.0.0.1", 1)
        },
    );
    assert_eq!(f.spans("10.0.0.1"), [(t(10), None)]);
    f.applied(A, &Lease::new(DaiDhcpMsg::Decline, t(30), "10.0.0.1", 1));
    assert_eq!(f.spans("10.0.0.1"), [(t(10), Some(t(30)))]);
    // No matching open binding: nothing is created or closed.
    f.applied(A, &Lease::release(t(40), "10.0.0.1", 1));
    f.applied(A, &Lease::release(t(40), "10.0.0.7", 7));
    assert_eq!(f.spans("10.0.0.1"), [(t(10), Some(t(30)))]);
    assert_eq!(f.devices().len(), 1);
    // They stay in the evidence index.
    assert_eq!(f.evidence().len(), 7);
}

/// How [`sequence`] delivers its observations.
#[derive(Clone, Copy, Debug)]
enum Delivery {
    /// All in one application.
    Together,
    /// One application each, in time order.
    InOrder,
    /// One application each, in reverse time order.
    Reversed,
    /// One application each, the RELEASE last.
    ReleaseLast,
}

/// Applies ACKs of one MAC at `acks` and a matching RELEASE at `release`,
/// times in units of `unit` after [`NOON`], and returns the spans.
fn sequence(acks: &[i64], release: i64, unit: i64, delivery: Delivery) -> Vec<(i64, Option<i64>)> {
    let f = setup();
    let at = |n: i64| NOON + n * unit;
    let mut events: Vec<Lease> = acks
        .iter()
        .map(|n| Lease {
            secs: Some(86_400),
            ..Lease::ack(at(*n), "10.0.0.1", 1)
        })
        .collect();
    events.push(Lease::release(at(release), "10.0.0.1", 1));
    events.sort_by_key(|lease| lease.time);
    match delivery {
        Delivery::Together => {
            for lease in &events {
                f.lease(A, lease);
            }
            f.apply_all();
        }
        Delivery::InOrder => events.iter().for_each(|lease| f.applied(A, lease)),
        Delivery::Reversed => events.iter().rev().for_each(|lease| f.applied(A, lease)),
        Delivery::ReleaseLast => {
            let (releases, acks): (Vec<_>, Vec<_>) = events
                .into_iter()
                .partition(|lease| lease.msg == DaiDhcpMsg::Release);
            acks.iter()
                .chain(&releases)
                .for_each(|lease| f.applied(A, lease));
        }
    }
    let owner = f.owner(1);
    assert!(f.bindings().iter().all(|bound| bound.5 == owner));
    f.spans("10.0.0.1")
        .into_iter()
        .map(|(start, end)| ((start - NOON) / unit, end.map(|end| (end - NOON) / unit)))
        .collect()
}

#[test]
fn release_sequences_give_the_same_bindings_however_they_arrive() {
    for delivery in [
        Delivery::Together,
        Delivery::InOrder,
        Delivery::Reversed,
        Delivery::ReleaseLast,
    ] {
        // One slot (seconds) and across slots (5 minutes).
        for unit in [NS, 5 * MINUTE] {
            assert_eq!(
                sequence(&[10, 20, 50], 30, unit, delivery),
                [(10, Some(30)), (50, None)],
                "{delivery:?}, {unit}"
            );
            assert_eq!(
                sequence(&[10, 40, 50], 30, unit, delivery),
                [(10, Some(30)), (40, None)],
                "{delivery:?}, {unit}"
            );
        }
    }
}

#[test]
fn a_release_and_an_ack_of_one_time_apply_release_first() {
    for late in [false, true] {
        let f = setup();
        f.applied(A, &Lease::ack(t(10), "10.0.0.1", 1));
        let ack = Lease::ack(t(20), "10.0.0.1", 1);
        let release = Lease::release(t(20), "10.0.0.1", 1);
        if late {
            f.applied(A, &ack);
            f.applied(A, &release);
        } else {
            f.lease(A, &ack);
            f.lease(A, &release);
            f.apply(A, NOON);
        }
        assert_eq!(
            f.spans("10.0.0.1"),
            [(t(10), Some(t(20))), (t(20), None)],
            "{late}"
        );
    }
}

#[test]
fn a_late_ack_recomputes_and_keeps_inactivity_times() {
    let f = setup();
    f.applied(A, &Lease::ack(t(10), "10.0.0.1", 1));
    f.applied(A, &Lease::ack(t(40), "10.0.0.1", 2));
    f.update_settings(|update| update.inactivity_multiplier = 7);
    // A late ACK of a third MAC between them.
    f.applied(A, &Lease::ack(t(20), "10.0.0.1", 3));
    assert_eq!(
        f.spans("10.0.0.1"),
        [(t(10), Some(t(20))), (t(20), Some(t(40))), (t(40), None)]
    );
    // Re-derived with the same start and device: the stored inactivity.
    assert_eq!(f.binding("10.0.0.1", t(10)).inactivity, 600 * NS);
    assert_eq!(f.binding("10.0.0.1", t(40)).inactivity, 600 * NS);
    assert_eq!(f.binding("10.0.0.1", t(20)).inactivity, 2100 * NS);
    assert_eq!(f.binding("10.0.0.1", t(20)).device, f.owner(3));
    assert_eq!(f.count(super::super::DAI_DEVICE_BINDINGS), 3);
}

#[test]
fn a_late_verified_o4_is_replayed_at_its_position() {
    let f = setup();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    // Past the 10-minute inactivity time: a new binding.
    f.applied(A, &Lease::ack(m(14), "10.0.0.1", 1));
    assert_eq!(f.spans("10.0.0.1"), [(m(0), None), (m(14), None)]);
    // A verified O4 at 12:08 arrives late; in order it would have kept the
    // first binding open past 12:14.
    f.observed(A, &verified("10.0.0.1", "HOST1$"), m(8), m(8));
    assert_eq!(f.spans("10.0.0.1"), [(m(0), None)]);
    let binding = f.binding("10.0.0.1", m(0));
    assert_eq!(binding.last_strong, m(14));
    let id = Identifier {
        kind: IdentifierKind::MachineAccount,
        value: "HOST1$@CORP.EXAMPLE".to_string(),
    };
    assert_eq!(f.identifier(&id).unwrap().device, f.owner(1));
    assert!(f.device(f.owner(1)).identifiers.contains(&id));
}

#[test]
fn a_late_verified_o4_has_its_device_effects_against_the_recomputed_bindings() {
    let f = setup();
    f.applied(A, &Lease::ack(t(10), "10.0.0.1", 1));
    f.applied(A, &Lease::release(t(30), "10.0.0.1", 1));
    let device = f.owner(1);
    // Late, and once the RELEASE is replayed after it no binding covers it.
    f.observed(A, &verified("10.0.0.1", "HOST1$"), t(20), t(40));
    assert_eq!(f.spans("10.0.0.1"), [(t(10), Some(t(30)))]);
    let id = Identifier {
        kind: IdentifierKind::MachineAccount,
        value: "HOST1$@CORP.EXAMPLE".to_string(),
    };
    assert!(f.identifier(&id).is_none());
    let row = f.device(device);
    assert!(!row.identifiers.contains(&id));
    assert_eq!((row.last_seen, row.version), (t(10), 1));
}

#[test]
fn a_replayed_verified_o4_with_an_unowned_account_moves_the_binding() {
    let f = setup();
    // A verified O4 with no binding to act on, then an ACK past what it
    // would have kept open, then a late ACK before both.
    f.observed(A, &verified("10.0.0.1", "HOST1$"), m(8), m(8));
    f.applied(A, &Lease::ack(m(14), "10.0.0.1", 1));
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    // In order, the O4 keeps the 12:00 binding open past 12:14.
    assert_eq!(f.spans("10.0.0.1"), [(m(0), None)]);
    assert_eq!(f.binding("10.0.0.1", m(0)).last_strong, m(14));
}

#[test]
fn late_evidence_replays_after_retention_removed_the_ip_state() {
    let f = setup();
    let forever = |time| Lease {
        secs: Some(u32::MAX),
        ..Lease::ack(time, "10.0.0.1", 1)
    };
    f.applied(A, &forever(NOON));
    f.applied(A, &forever(NOON + 2 * DAY));
    assert_eq!(f.spans("10.0.0.1"), [(NOON, None)]);
    f.retention(NOON + 200 * DAY);
    assert_eq!(f.count(super::super::DAI_IP_STATE), 0);
    assert_eq!(f.spans("10.0.0.1"), [(NOON, None)]);
    // A late RELEASE between the two ACKs: the day-2 ACK is replayed after
    // it and starts a binding of its own.
    f.applied(A, &Lease::release(NOON + DAY, "10.0.0.1", 1));
    assert_eq!(
        f.spans("10.0.0.1"),
        [(NOON, Some(NOON + DAY)), (NOON + 2 * DAY, None)]
    );
    assert_eq!(f.count(super::super::DAI_IP_STATE), 1);
}

#[test]
fn a_re_sent_observation_is_one_evidence_row() {
    let f = setup();
    let plain = Lease::ack(t(10), "10.0.0.1", 1);
    f.applied(A, &plain);
    f.applied(
        B,
        &Lease {
            hostname: Some("filled"),
            ..plain.clone()
        },
    );
    assert_eq!(f.evidence().len(), 1);
    assert_eq!(f.bindings().len(), 1);
    let (_, _, row) = &f.evidence()[0];
    assert_eq!(row.sensor, B);
    let device = f.device(f.owner(1));
    assert_eq!(device.representative_name(), Some("filled"));
    assert_eq!(device.version, 2);

    // An O4 re-sent with wider times in the same slot.
    f.observed(A, &ntlm("10.0.0.1"), m(1), m(1));
    f.observed(A, &ntlm("10.0.0.1"), t(50), m(2));
    let o5: Vec<_> = f
        .evidence()
        .into_iter()
        .filter(|(_, kind, _)| *kind == Kind::Ntlm)
        .collect();
    assert_eq!(o5.len(), 1);
    assert_eq!((o5[0].0, o5[0].2.first_seen), (m(2), t(50)));
    let o4 = krb("10.0.0.1", REALM, "HOST$", 13, 2);
    f.observed(A, &o4, m(3), m(3));
    f.observed(A, &o4, t(170), m(4));
    let o4: Vec<_> = f
        .evidence()
        .into_iter()
        .filter(|(_, kind, _)| *kind == Kind::Kerberos)
        .collect();
    assert_eq!(o4.len(), 1);
    assert_eq!((o4[0].0, o4[0].2.first_seen), (m(4), t(170)));
}

#[test]
fn a_verified_o4_re_sent_with_wider_times_moves_the_last_strong_time() {
    let f = setup();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    let device = f.owner(1);
    let o4 = verified("10.0.0.1", "HOST1$");
    f.observed(A, &o4, m(1), m(1));
    assert_eq!(f.binding("10.0.0.1", m(0)).last_strong, m(1));
    // Re-sent in the same slot with a later last seen; not late, so it
    // moves the binding as it would have arrived with those times.
    f.observed(A, &o4, m(1), m(4));
    let rows: Vec<_> = f
        .evidence()
        .into_iter()
        .filter(|(_, kind, _)| *kind == Kind::Kerberos)
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, m(4));
    assert_eq!(f.binding("10.0.0.1", m(0)).last_strong, m(4));
    // Covered until 12:14, so an O5 at 12:12 confirms the device.
    f.observed(A, &ntlm("10.0.0.1"), m(12), m(12));
    assert_eq!(f.device(device).last_seen, m(12));
    assert_eq!(f.spans("10.0.0.1"), [(m(0), None)]);
}

#[test]
fn an_o4_first_applied_unverified_is_binding_evidence_once_re_sent_verified() {
    let f = setup();
    let account = Identifier {
        kind: IdentifierKind::MachineAccount,
        value: "HOST1$@CORP.EXAMPLE".to_string(),
    };
    let o4 = verified("10.0.0.1", "HOST1$");

    // Not late: it attaches the account and moves the binding.
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    let device = f.owner(1);
    f.update_settings(|update| update.kerberos_preauth_realms.clear());
    f.observed(A, &o4, m(1), m(1));
    assert!(f.identifier(&account).is_none());
    assert_eq!(f.binding("10.0.0.1", m(0)).last_strong, m(0));
    f.update_settings(|update| update.kerberos_preauth_realms = vec![REALM.to_string()]);
    f.observed(A, &o4, m(1), m(3));
    assert_eq!(f.identifier(&account).unwrap().device, device);
    assert_eq!(f.binding("10.0.0.1", m(0)).last_strong, m(3));
    let rows: Vec<_> = f
        .evidence()
        .into_iter()
        .filter(|(_, kind, _)| *kind == Kind::Kerberos)
        .collect();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].2.verified);
}

#[test]
fn a_late_o4_first_applied_unverified_recomputes_once_re_sent_verified() {
    let f = setup();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    let o4 = verified("10.0.0.1", "HOST1$");
    f.update_settings(|update| update.kerberos_preauth_realms.clear());
    f.observed(A, &o4, m(1), m(1));
    // Past the 10-minute inactivity time: a new binding.
    f.applied(A, &Lease::ack(m(14), "10.0.0.1", 1));
    assert_eq!(f.spans("10.0.0.1"), [(m(0), None), (m(14), None)]);
    // Re-sent verified, it is late; in order it would have kept the first
    // binding open past 12:14.
    f.update_settings(|update| update.kerberos_preauth_realms = vec![REALM.to_string()]);
    f.observed(A, &o4, m(1), m(8));
    assert_eq!(f.spans("10.0.0.1"), [(m(0), None)]);
    assert_eq!(f.binding("10.0.0.1", m(0)).last_strong, m(14));
    let account = Identifier {
        kind: IdentifierKind::MachineAccount,
        value: "HOST1$@CORP.EXAMPLE".to_string(),
    };
    assert_eq!(f.identifier(&account).unwrap().device, f.owner(1));
}

#[test]
fn the_same_ack_from_two_sensors_triggers_no_recomputation() {
    let f = setup();
    f.applied(A, &Lease::ack(t(10), "10.0.0.1", 1));
    f.applied(A, &Lease::ack(t(30), "10.0.0.1", 2));
    // A recomputation would derive the second binding again from its ACK.
    let mut marked = f.binding("10.0.0.1", t(30));
    marked.server_id = Some(ip("10.0.0.250"));
    let site = f.bindings()[0].0.clone();
    f.put(
        super::super::DAI_BINDINGS,
        &super::device::binding_key(CUSTOMER, &site, ip("10.0.0.1"), t(30)),
        &marked,
    );
    // B sends A's first ACK again after the second: earlier in order, but
    // the same message.
    f.applied(B, &Lease::ack(t(10), "10.0.0.1", 1));
    assert_eq!(f.spans("10.0.0.1"), [(t(10), Some(t(30))), (t(30), None)]);
    assert_eq!(f.binding("10.0.0.1", t(30)), marked);
    assert_eq!(f.evidence().len(), 2);
}

// ---- Machine accounts ----

#[test]
fn a_verified_o4_attaches_a_machine_account_and_moves_the_last_strong_time() {
    let f = setup();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    let device = f.owner(1);
    f.observed(A, &verified("10.0.0.1", "host1$"), m(5), m(6));
    let account = |name: &str| Identifier {
        kind: IdentifierKind::MachineAccount,
        value: name.to_string(),
    };
    let host1 = account("HOST1$@CORP.EXAMPLE");
    assert_eq!(f.identifier(&host1).unwrap().device, device);
    assert_eq!(f.identifier(&host1).unwrap().last_confirmed, m(6));
    assert_eq!(f.binding("10.0.0.1", m(0)).last_strong, m(6));
    assert_eq!(f.device(device).version, 2);
    // Now covered until 12:16.
    f.observed(A, &ntlm("10.0.0.1"), m(14), m(15));
    assert_eq!(f.device(device).last_seen, m(15));
    // Weak O4s only confirm.
    for (n, (msg_type, preauth)) in [(11, 1), (11, 0), (13, 2), (10, 2), (30, 2)]
        .into_iter()
        .enumerate()
    {
        let when = m(15) + i64::try_from(n).unwrap() * NS;
        f.observed(
            A,
            &krb("10.0.0.1", REALM, &format!("weak{n}$"), msg_type, preauth),
            when,
            when,
        );
    }
    assert_eq!(f.binding("10.0.0.1", m(0)).last_strong, m(6));
    assert_eq!(f.device(device).identifiers.len(), 2);
    assert_eq!(f.device(device).last_seen, m(15) + 4 * NS);

    // A second device claiming the account: a conflict, the account stays.
    f.applied(A, &Lease::ack(m(1), "10.0.0.2", 2));
    let other = f.owner(2);
    f.observed(A, &verified("10.0.0.2", "HOST1$"), m(7), m(8));
    assert_eq!(f.identifier(&host1).unwrap().device, device);
    assert_eq!(f.binding("10.0.0.2", m(1)).last_strong, m(1));
    let (_, value) = f.rows(super::super::DAI_CONFLICTS).pop().unwrap();
    let conflict: ConflictRow = super::super::deserialize(&value).unwrap();
    assert_eq!(conflict.devices, [device, other].into_iter().collect());
    assert_eq!((conflict.first, conflict.last), (m(7), m(8)));
    assert_eq!(f.device(other).last_seen, m(8));

    // Without the realm confirmed, a verified-looking O4 attaches nothing.
    f.update_settings(|update| update.kerberos_preauth_realms.clear());
    let when = m(15) + 10 * NS;
    f.observed(A, &verified("10.0.0.1", "HOST2$"), when, when);
    assert_eq!(f.device(device).last_seen, when);
    assert!(f.identifier(&account("HOST2$@CORP.EXAMPLE")).is_none());
    assert_eq!(f.binding("10.0.0.1", m(0)).last_strong, m(6));
}

// ---- Sites ----

#[test]
fn relayed_dhcp_uses_the_relay_table_or_the_sensor_site() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    let relayed = |time, addr, n| Lease {
        giaddr: "10.9.0.1",
        ..Lease::ack(time, addr, n)
    };
    // Single-site: the sensor's site without a table.
    f.applied(A, &relayed(t(10), "10.1.0.1", 1));
    assert_eq!(f.bindings()[0].0, default);

    // Multi-site without an entry: not applied, counted.
    let east = f
        .dai()
        .create_site(CUSTOMER, "east", &[B.to_string()], &NOON)
        .unwrap();
    assert!(
        f.dai()
            .read(|txn| f.dai().is_multi_site_in(txn, CUSTOMER))
            .unwrap()
    );
    f.applied(A, &relayed(t(20), "10.1.0.2", 2));
    assert_eq!(f.counter(CUSTOMER, DaiCounterKind::RelaySiteUnknown), 1);
    assert_eq!(f.bindings().len(), 1);
    assert_eq!(f.evidence().len(), 1);
    assert_eq!(f.count(super::super::DAI_PENDING), 0);

    // With an entry: its site.
    let entry = DaiRelaySite {
        dhcp_server: ip(SERVER),
        giaddr: ip("10.9.0.1"),
        site: east.clone(),
    };
    let revision = f.store.dai_relay_sites(CUSTOMER).unwrap().revision;
    f.store
        .replace_dai_relay_sites(CUSTOMER, revision, &[entry])
        .unwrap();
    f.applied(A, &relayed(t(30), "10.1.0.3", 3));
    let bound = f.bindings();
    assert!(bound.iter().any(|b| b.0 == east && b.1 == ip("10.1.0.3")));
}

#[test]
fn a_moved_sensor_applies_by_slot_and_sites_stay_apart() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    // Written at 12:02, effective at 12:05.
    let west = f
        .dai()
        .create_site(CUSTOMER, "west", &[A.to_string()], &m(2))
        .unwrap();
    f.applied(A, &Lease::ack(m(1), "10.0.0.1", 1));
    f.applied(A, &Lease::ack(m(6), "10.0.0.1", 2));
    let bound = f.bindings();
    assert_eq!(bound.len(), 2);
    let site_of = |n| bound.iter().find(|b| b.5 == f.owner(n)).unwrap().0.clone();
    assert_eq!(site_of(1), default);
    assert_eq!(site_of(2), west);
    // Both stay open: one IP at two sites is two addresses.
    assert!(bound.iter().all(|b| b.3.is_none()));
}

// ---- Evidence aging ----

#[test]
fn evidence_aging_moves_a_mac_to_a_new_device() {
    let f = setup();
    f.update_settings(|update| update.evidence_aging_secs = 86_400);
    f.applied(A, &Lease::ack(NOON, "10.0.0.1", 1));
    let old = f.owner(1);
    f.applied(A, &Lease::ack(NOON + 2 * DAY, "10.0.0.1", 1));
    let new = f.owner(1);
    assert_ne!(old, new);
    assert_eq!(f.device(old).identifiers, []);
    assert_eq!(f.device(new).identifiers, [mac_id(1)]);
    let identifier = f.identifier(&mac_id(1)).unwrap();
    assert_eq!(identifier.earlier_owners.len(), 1);
    assert_eq!(
        (
            identifier.earlier_owners[0].device,
            identifier.earlier_owners[0].left
        ),
        (old, NOON + 2 * DAY)
    );
    let old_changes = f.changes(old);
    assert_eq!(old_changes.len(), 2);
    let moved = &old_changes[1].1;
    assert_eq!(
        (moved.kind, moved.related_device),
        (ChangeKind::Changed, Some(new))
    );
    assert_eq!(moved.fields[0].op, ChangeOp::Remove);
    let created = &f.changes(new)[0].1;
    assert_eq!(
        (created.kind, created.related_device),
        (ChangeKind::Created, Some(old))
    );
    // The old device keeps its binding.
    assert_eq!(f.binding("10.0.0.1", NOON).device, old);
    assert_eq!(f.binding("10.0.0.1", NOON + 2 * DAY).device, new);
}

#[test]
fn evidence_aging_keeps_the_mac_of_an_imported_or_confirmed_device() {
    for (asset, verdict) in [
        (Some("asset-1"), Verdict::Observed),
        (None, Verdict::Confirmed),
    ] {
        let f = setup();
        f.update_settings(|update| update.evidence_aging_secs = 86_400);
        f.applied(A, &Lease::ack(NOON, "10.0.0.1", 1));
        let device = f.owner(1);
        let mut row = f.device(device);
        row.operator_asset_id = asset.map(ToString::to_string);
        row.verdict = verdict;
        f.put(
            super::super::DAI_DEVICES,
            &device_key(CUSTOMER, device),
            &row,
        );
        f.applied(A, &Lease::ack(NOON + 2 * DAY, "10.0.0.1", 1));
        assert_eq!(f.owner(1), device);
        assert_eq!(f.devices().len(), 1);
        assert_eq!(
            f.identifier(&mac_id(1)).unwrap().last_confirmed,
            NOON + 2 * DAY
        );
    }
}

#[test]
fn a_late_release_or_ack_before_an_aging_move_stays_with_the_old_device() {
    let f = setup();
    f.update_settings(|update| update.evidence_aging_secs = 86_400);
    let long = |time, addr| Lease {
        secs: Some(86_400),
        ..Lease::ack(time, addr, 1)
    };
    f.applied(A, &long(NOON, "10.0.0.1"));
    let old = f.owner(1);
    f.applied(A, &long(NOON + 2 * DAY, "10.0.0.1"));
    let new = f.owner(1);
    f.applied(A, &Lease::release(NOON + 30 * MINUTE, "10.0.0.1", 1));
    let bound = f.bindings();
    assert_eq!(
        f.spans("10.0.0.1"),
        [(NOON, Some(NOON + 30 * MINUTE)), (NOON + 2 * DAY, None)]
    );
    assert_eq!((bound[0].5, bound[1].5), (old, new));
    // A late ACK before the move binds the old device.
    f.applied(A, &long(NOON + HOUR, "10.0.0.1"));
    let bound = f.bindings();
    assert_eq!(bound[1].2, NOON + HOUR);
    assert_eq!(bound[1].5, old);
    assert_eq!(bound[1].3, Some(NOON + 2 * DAY));
    assert_eq!(bound[2].5, new);
    assert_eq!(f.owner(1), new);
}

#[test]
fn a_late_ack_after_a_move_applies_to_the_device_of_its_time() {
    let f = setup();
    f.update_settings(|update| update.evidence_aging_secs = 86_400);
    f.applied(A, &Lease::ack(NOON, "10.0.0.1", 1));
    let a = f.owner(1);
    f.applied(A, &Lease::ack(NOON + 2 * DAY, "10.0.0.1", 1));
    let b = f.owner(1);
    f.applied(
        A,
        &Lease {
            hostname: Some("day1"),
            ..Lease::ack(NOON + DAY, "10.0.0.1", 1)
        },
    );
    assert_eq!(f.owner(1), b);
    let identifier = f.identifier(&mac_id(1)).unwrap();
    assert_eq!(identifier.last_confirmed, NOON + 2 * DAY);
    assert_eq!(identifier.earlier_owners.len(), 1);
    let bound = f.bindings();
    assert_eq!(
        bound.iter().map(|b| (b.2, b.5)).collect::<Vec<_>>(),
        [(NOON, a), (NOON + DAY, a), (NOON + 2 * DAY, b)]
    );
    assert_eq!(f.device(a).representative_name(), Some("day1"));
    assert_eq!(f.device(a).last_seen, NOON + DAY);
    assert_eq!(f.devices().len(), 2);
}

#[test]
fn an_older_ack_or_inform_ack_leaves_the_last_confirmed_time() {
    let f = setup();
    f.update_settings(|update| update.evidence_aging_secs = 60);
    f.applied(A, &Lease::ack(m(4), "10.0.0.1", 1));
    let device = f.owner(1);
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    f.applied(A, &Lease::new(DaiDhcpMsg::InformAck, m(1), "10.0.0.1", 1));
    assert_eq!(f.identifier(&mac_id(1)).unwrap().last_confirmed, m(4));
    assert_eq!(f.owner(1), device);
    assert_eq!(f.devices().len(), 1);
    // A late observation never moves first seen later or last seen earlier.
    let row = f.device(device);
    assert_eq!((row.first_seen, row.last_seen), (m(0), m(4)));
}

// ---- Attributes and history ----

#[test]
fn attributes_attach_through_the_covering_binding() {
    let f = setup();
    f.applied(
        A,
        &Lease {
            hostname: Some("dhcp-name"),
            secs: Some(86_400),
            ..Lease::ack(m(0), "10.0.0.1", 1)
        },
    );
    // A DNS server bound at 10.0.0.53.
    f.applied(
        A,
        &Lease {
            secs: Some(86_400),
            ..Lease::ack(m(0), "10.0.0.53", 2)
        },
    );
    let device = f.owner(1);
    let server = f.owner(2);
    assert_eq!(f.device(device).version, 1);

    f.observed(
        A,
        &DaiObservationBody::DhcpServer {
            server_ip: ip("10.0.0.1"),
            server_id: None,
        },
        m(1),
        m(1),
    );
    assert!(f.device(device).was_dhcp_server);
    assert_eq!(f.device(device).version, 2);

    let service = |external| DaiObservationBody::Service {
        server_ip: ip("10.0.0.1"),
        port: 22,
        proto: 6,
        external_client: external,
    };
    f.observed(A, &service(true), m(2), m(2));
    f.observed(A, &service(false), m(6), m(7));
    let key = service_key(CUSTOMER, device, 22, 6);
    let mut row: ServiceRow = f
        .dai()
        .read(|txn| Dai::get_row(txn, &f.dai().services, &key))
        .unwrap()
        .unwrap();
    assert_eq!(
        row,
        ServiceRow {
            external_client: true,
            first_seen: m(2),
            last_seen: m(7),
            removed: false
        }
    );
    row.removed = true;
    f.put(super::super::DAI_SERVICES, &key, &row);
    f.observed(A, &service(false), m(10), m(11));
    let row: ServiceRow = f
        .dai()
        .read(|txn| Dai::get_row(txn, &f.dai().services, &key))
        .unwrap()
        .unwrap();
    assert!(row.removed && row.external_client);
    assert_eq!(row.last_seen, m(11));

    let software = DaiObservationBody::SoftwareString {
        ip: ip("10.0.0.1"),
        side: DaiSide::Server,
        source: DaiSoftwareSource::Ssh,
        text: "SSH-2.0-OpenSSH_9.6".to_string(),
    };
    f.observed(A, &software, m(12), m(12));
    f.observed(A, &software, m(15), m(16));
    let (_, value) = f.rows(super::super::DAI_SOFTWARE_STRINGS).pop().unwrap();
    let times: SeenTimes = super::super::deserialize(&value).unwrap();
    assert_eq!((times.first_seen, times.last_seen), (m(12), m(16)));
    // Neither services nor software strings change the version.
    assert_eq!(f.device(device).version, 2);

    // The DNS answer names the device bound at the answer address.
    f.observed(A, &dns("dns-name.example", "10.0.0.1"), m(20), m(20));
    let row = f.device(device);
    assert_eq!(row.version, 3);
    assert!(
        row.names
            .iter()
            .any(|n| n.value == "dns-name.example" && n.source == NameSource::Dns)
    );
    assert_eq!(row.representative_name(), Some("dhcp-name"));
    assert_eq!(f.device(server).names, []);
    // Seen again: only the time moves.
    f.observed(A, &dns("dns-name.example", "10.0.0.1"), m(25), m(25));
    let row = f.device(device);
    assert_eq!(row.version, 3);
    let name = row
        .names
        .iter()
        .find(|n| n.source == NameSource::Dns)
        .unwrap();
    assert_eq!(name.last_seen, m(25));
    assert_eq!(f.changes(device).len(), 3);
    // Nothing attaches at an address without a covering binding.
    f.observed(A, &dns("nobody.example", "10.0.0.99"), m(26), m(26));
    assert_eq!(
        f.devices().values().map(|d| d.names.len()).sum::<usize>(),
        2
    );
}

#[test]
fn one_change_entry_per_substantive_change() {
    let f = setup();
    let named = Lease {
        hostname: Some("first"),
        ..Lease::ack(m(0), "10.0.0.1", 1)
    };
    f.applied(A, &named);
    let device = f.owner(1);
    // The creation entry holds the identifier and the name.
    let changes = f.changes(device);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].1.fields.len(), 2);
    // The same value again: no version.
    f.applied(
        A,
        &Lease {
            time: m(1),
            ..named.clone()
        },
    );
    assert_eq!(f.device(device).version, 1);
    // A new name: one version.
    f.applied(
        A,
        &Lease {
            hostname: Some("second"),
            ..Lease::ack(m(2), "10.0.0.1", 1)
        },
    );
    assert_eq!(f.device(device).version, 2);
    // A binding change alone: none.
    f.applied(A, &Lease::release(m(3), "10.0.0.1", 1));
    assert_eq!(f.device(device).version, 2);
    let versions: Vec<u64> = f.changes(device).iter().map(|(v, _)| *v).collect();
    assert_eq!(versions, [1, 2]);
}

#[test]
fn an_unseen_device_becomes_not_seen_and_returns_to_active() {
    let f = setup();
    f.applied(A, &Lease::ack(NOON, "10.0.0.1", 1));
    let device = f.owner(1);
    f.retention(NOON + 89 * DAY);
    assert_eq!(f.device(device).activity, Activity::Active);
    f.retention(NOON + 91 * DAY);
    let row = f.device(device);
    assert_eq!((row.activity, row.version), (Activity::NotSeen, 2));
    let (_, expired) = f.changes(device).pop().unwrap();
    assert_eq!(
        (expired.source, expired.time),
        (ChangeSource::Expiry, NOON + 91 * DAY)
    );
    // Retention again changes nothing.
    f.retention(NOON + 92 * DAY);
    assert_eq!(f.device(device).version, 2);
    // A hidden device stays hidden.
    let mut hidden = f.device(device);
    hidden.activity = Activity::Hidden;
    f.put(
        super::super::DAI_DEVICES,
        &device_key(CUSTOMER, device),
        &hidden,
    );
    f.applied(A, &Lease::ack(NOON + 93 * DAY, "10.0.0.1", 1));
    assert_eq!(f.device(device).activity, Activity::Hidden);
    hidden.activity = Activity::NotSeen;
    hidden.last_seen = NOON + 93 * DAY;
    f.put(
        super::super::DAI_DEVICES,
        &device_key(CUSTOMER, device),
        &hidden,
    );
    f.applied(A, &Lease::ack(NOON + 94 * DAY, "10.0.0.1", 1));
    let row = f.device(device);
    assert_eq!((row.activity, row.version), (Activity::Active, 3));
    let (_, back) = f.changes(device).pop().unwrap();
    assert_eq!(back.source, ChangeSource::Observation(1));
    assert_eq!(back.fields[0].path, "activity");
}

// ---- Retention ----

#[test]
fn an_ack_binding_an_earlier_owner_racing_its_expiry_keeps_it() {
    let f = setup();
    f.update_settings(|update| update.evidence_aging_secs = 86_400);
    f.applied(A, &Lease::ack(NOON, "10.0.0.1", 1));
    let old = f.owner(1);
    f.applied(A, &Lease::ack(NOON + 2 * DAY, "10.0.0.2", 1));
    let new = f.owner(1);
    assert_ne!(old, new);
    let now = NOON + 183 * DAY;
    // Retention finds no binding of the old owner left once it deleted the
    // ended one, and a late ACK before the move binds it before retention
    // commits.
    set_owners_checked_hook(Box::new(move |db| {
        let dai = Dai::open(db).unwrap();
        let time = NOON + DAY;
        let body = Lease {
            secs: Some(u32::MAX),
            ..Lease::ack(time, "10.0.0.3", 1)
        }
        .body();
        let slot = slot_floor(time).unwrap();
        enqueue_in(&dai, A, slot, &body, time, time);
        dai.apply_slot(A, slot, 500, now).unwrap();
    }));
    f.retention(now);
    let bound: Vec<(i64, Uuid)> = f
        .bindings()
        .into_iter()
        .filter(|b| b.1 == ip("10.0.0.3"))
        .map(|b| (b.2, b.5))
        .collect();
    assert_eq!(bound, [(NOON + DAY, old)]);
    let identifier = f.identifier(&mac_id(1)).unwrap();
    assert_eq!(identifier.device, new);
    assert_eq!(
        identifier
            .earlier_owners
            .iter()
            .map(|owner| (owner.device, owner.left))
            .collect::<Vec<_>>(),
        [(old, NOON + 2 * DAY)]
    );
}

#[test]
#[allow(clippy::too_many_lines)] // One timeline, checked after one retention run.
fn retention_deletes_old_history_and_keeps_what_a_replay_needs() {
    let f = setup();
    f.update_settings(|update| update.evidence_aging_secs = 86_400);
    let forever = |time, addr, n| Lease {
        secs: Some(u32::MAX),
        ..Lease::ack(time, addr, n)
    };
    // An ended binding with its evidence, a name, a service and a software
    // string.
    f.applied(
        A,
        &Lease {
            hostname: Some("old-name"),
            ..Lease::ack(NOON, "10.0.0.1", 1)
        },
    );
    f.applied(A, &Lease::release(NOON + MINUTE, "10.0.0.1", 1));
    let ended = f.owner(1);
    // A binding open since day 0, kept open by an ACK on day 175, with an
    // INFORM ACK on day 0.
    f.applied(A, &forever(NOON, "10.0.0.2", 2));
    f.applied(
        A,
        &Lease::new(DaiDhcpMsg::InformAck, NOON + MINUTE, "10.0.0.2", 2),
    );
    f.observed(
        A,
        &DaiObservationBody::Service {
            server_ip: ip("10.0.0.2"),
            port: 80,
            proto: 6,
            external_client: false,
        },
        NOON + MINUTE,
        NOON + MINUTE,
    );
    // An aging move whose old device has no binding left, and one whose old
    // device keeps an open binding.
    f.applied(A, &Lease::ack(NOON, "10.0.0.3", 3));
    f.applied(A, &Lease::ack(NOON + 2 * DAY, "10.0.0.3", 3));
    f.applied(A, &forever(NOON, "10.0.0.4", 4));
    f.applied(A, &forever(NOON + 2 * DAY, "10.0.0.5", 4));
    let kept_owner = f.identifier(&mac_id(4)).unwrap().earlier_owners[0].device;
    // An operator name never expires.
    let mut row = f.device(ended);
    row.names.push(DeviceName {
        value: "operator-name".to_string(),
        source: NameSource::Operator,
        last_seen: NOON,
    });
    f.put(
        super::super::DAI_DEVICES,
        &device_key(CUSTOMER, ended),
        &row,
    );
    // A conflict and an alias, both old.
    let conflict = ConflictRow {
        devices: [ended].into_iter().collect(),
        first: NOON,
        last: NOON,
    };
    f.put(
        super::super::DAI_CONFLICTS,
        &identifier_key(CUSTOMER, &mac_id(9)),
        &conflict,
    );
    let alias = AliasRow {
        current: ended,
        time: NOON,
        reason: AliasReason::Merged,
    };
    f.put(
        super::super::DAI_DEVICE_ALIASES,
        &device_key(CUSTOMER, Uuid::from_bytes([7; 16])),
        &alias,
    );
    let fixed = address_key(CUSTOMER, "site", ip("10.0.0.8"));
    f.put(super::super::DAI_FIXED_IPS, &fixed, &ended);

    let day175 = NOON + 175 * DAY;
    f.update_settings(|update| update.evidence_aging_secs = 180 * 86_400);
    f.applied(A, &forever(day175, "10.0.0.2", 2));
    let devices_before = f.devices().len();
    let identifiers_before = f.count(super::super::DAI_DEVICE_IDENTIFIERS);

    // Past 180 days after the aging moves of day 2.
    let now = NOON + 183 * DAY;
    f.retention(now);

    // Bindings: the ended one is gone with its reverse row; the open ones
    // stay.
    assert_eq!(f.spans("10.0.0.1"), []);
    assert_eq!(f.spans("10.0.0.2"), [(NOON, None)]);
    assert_eq!(
        f.count(super::super::DAI_DEVICE_BINDINGS),
        f.count(super::super::DAI_BINDINGS)
    );
    // Evidence: only the binding evidence a replay of a stored binding
    // needs, and the recent.
    let evidence: Vec<(IpAddr, i64)> = f
        .rows(super::super::DAI_EVIDENCE)
        .into_iter()
        .map(|(key, _)| {
            let key = decode_evidence_key(&key).unwrap();
            (key.ip, key.last_seen)
        })
        .collect();
    assert!(evidence.contains(&(ip("10.0.0.2"), NOON)));
    assert!(evidence.contains(&(ip("10.0.0.2"), day175)));
    assert!(!evidence.contains(&(ip("10.0.0.2"), NOON + MINUTE)));
    assert!(evidence.iter().all(|(addr, _)| *addr != ip("10.0.0.1")));
    assert!(evidence.contains(&(ip("10.0.0.4"), NOON)));
    // History rows.
    assert_eq!(f.count(super::super::DAI_DEVICE_ALIASES), 0);
    assert_eq!(f.count(super::super::DAI_CONFLICTS), 0);
    assert_eq!(f.count(super::super::DAI_SERVICES), 0);
    assert_eq!(f.count(super::super::DAI_SOFTWARE_STRINGS), 0);
    assert!(
        f.rows(super::super::DAI_DEVICE_CHANGES)
            .iter()
            .all(|(_, value)| super::super::deserialize::<ChangeEntry>(value)
                .unwrap()
                .time
                >= now - 180 * DAY)
    );
    let states: Vec<OrderKey> = f
        .rows(super::super::DAI_IP_STATE)
        .iter()
        .map(|(_, value)| super::super::deserialize(value).unwrap())
        .collect();
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].time, day175);
    // Earlier owners.
    assert_eq!(f.identifier(&mac_id(3)).unwrap().earlier_owners, []);
    let kept = f.identifier(&mac_id(4)).unwrap();
    assert_eq!(kept.earlier_owners.len(), 1);
    assert_eq!(kept.earlier_owners[0].device, kept_owner);
    // Names: the DHCP name expired, the operator name stays.
    let row = f.device(ended);
    assert_eq!(row.names.len(), 1);
    assert_eq!(row.names[0].source, NameSource::Operator);
    let (_, entry) = f.changes(ended).pop().unwrap();
    assert_eq!((entry.source, entry.time), (ChangeSource::Expiry, now));
    // Devices, identifiers and fixed IPs stay.
    assert_eq!(f.devices().len(), devices_before);
    assert_eq!(
        f.count(super::super::DAI_DEVICE_IDENTIFIERS),
        identifiers_before
    );
    assert_eq!(f.count(super::super::DAI_FIXED_IPS), 1);

    // A late RELEASE within the binding open since day 0 is recomputed from
    // the evidence retention kept.
    f.applied(A, &Lease::release(NOON + 170 * DAY, "10.0.0.2", 2));
    assert_eq!(
        f.spans("10.0.0.2"),
        [(NOON, Some(NOON + 170 * DAY)), (day175, None)]
    );
}

#[test]
fn pending_expiry_rewrites_the_resolver_point() {
    let f = setup();
    let old = NOON;
    let recent = NOON + 40 * DAY;
    f.lease(A, &Lease::ack(old + MINUTE, "10.0.0.1", 1));
    f.lease(A, &Lease::ack(recent + MINUTE, "10.0.0.1", 1));
    f.lease(B, &Lease::ack(old + MINUTE, "10.0.0.2", 2));
    assert_eq!(f.apply(A, NOON + DAY), Some(old));
    assert_eq!(f.apply(B, NOON + DAY), Some(old));
    f.retention(NOON + 45 * DAY);
    assert_eq!(f.resolver_point(A), Some(recent));
    assert_eq!(f.resolver_point(B), None);
    let heads = f.store.dai_pending_heads().unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!((heads[0].sensor.as_str(), heads[0].slot_start), (A, recent));
    // A sensor that never got a resolver point does not get one.
    f.lease(SHARED, &Lease::ack(old + MINUTE, "10.0.0.3", 3));
    f.retention(NOON + 45 * DAY);
    assert!(!f.has_resolver_point(SHARED));
}

// ---- Customer deletion ----

#[test]
fn customer_deletion_removes_the_device_rows_of_the_customer_only() {
    let f = setup();
    let other_site = f.store.ensure_default_site(OTHER).unwrap();
    f.applied(
        A,
        &Lease {
            hostname: Some("x"),
            ..Lease::ack(t(10), "10.0.0.1", 1)
        },
    );
    f.observed(
        A,
        &DaiObservationBody::Service {
            server_ip: ip("10.0.0.1"),
            port: 80,
            proto: 6,
            external_client: false,
        },
        t(20),
        t(20),
    );
    f.applied(D, &Lease::ack(t(10), "10.0.0.1", 1));
    for customer in [CUSTOMER, OTHER] {
        f.put(
            super::super::DAI_FIXED_IPS,
            &address_key(customer, &other_site, ip("10.0.0.1")),
            &Uuid::nil(),
        );
        f.put(
            super::super::DAI_DEVICE_ALIASES,
            &device_key(customer, Uuid::nil()),
            &AliasRow {
                current: Uuid::nil(),
                time: NOON,
                reason: AliasReason::Imported,
            },
        );
        f.put(
            super::super::DAI_CONFLICTS,
            &identifier_key(customer, &mac_id(1)),
            &ConflictRow {
                devices: [Uuid::nil()].into_iter().collect(),
                first: NOON,
                last: NOON,
            },
        );
    }
    f.lease(A, &Lease::ack(m(10), "10.0.0.1", 1));
    let other_rows = |f: &Fixture| -> Vec<usize> {
        DEVICE_FAMILIES
            .iter()
            .map(|family| {
                f.rows(family)
                    .iter()
                    .filter(|(key, _)| {
                        if *family == super::super::DAI_RESOLVER_POINTS {
                            key.as_ref() == resolver_point_key(D).as_slice()
                        } else {
                            key.starts_with(&customer_key(OTHER))
                        }
                    })
                    .count()
            })
            .collect()
    };
    let before = other_rows(&f);
    assert!(before.iter().filter(|count| **count > 0).count() >= 10);

    let sensors = [A.to_string(), B.to_string()];
    f.store.delete_dai_customer(CUSTOMER, &sensors).unwrap();
    for family in DEVICE_FAMILIES {
        let customer_rows = f
            .rows(family)
            .iter()
            .filter(|(key, _)| {
                if family == super::super::DAI_RESOLVER_POINTS {
                    key.as_ref() == resolver_point_key(A).as_slice()
                        || key.as_ref() == resolver_point_key(B).as_slice()
                } else {
                    key.starts_with(&customer_key(CUSTOMER))
                }
            })
            .count();
        assert_eq!(customer_rows, 0, "{family}");
    }
    assert_eq!(other_rows(&f), before);
    assert_eq!(f.count(super::super::DAI_PENDING), 0);
    assert_eq!(f.bindings_of(OTHER).len(), 1);

    // A repeated call changes nothing.
    let snapshot: Vec<_> = DEVICE_FAMILIES
        .iter()
        .map(|family| f.rows(family))
        .collect();
    f.store.delete_dai_customer(CUSTOMER, &sensors).unwrap();
    let again: Vec<_> = DEVICE_FAMILIES
        .iter()
        .map(|family| f.rows(family))
        .collect();
    assert_eq!(snapshot, again);
}
