//! Tests of the DAI unregistered range tables.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::{Arc, RwLock},
};

use ipnet::IpNet;
use review_protocol::types::{
    DaiCursors, DaiLateDay, DaiLateSlot, DaiLateSubnet, DaiObservationBatch,
    DaiObservationKind as Kind, DaiRangeBlock, DaiRangeDay, DaiRangeDayState,
    DaiRangeEvidence as Evidence, DaiRangeGrant, DaiRangeLate, DaiRangeMark, DaiRangeUnit,
};
use tempfile::TempDir;

use super::cursor::{CursorRow, DAY, date_of, slot_floor};
use super::range::{
    BlockRow, DayRow, block_key, day_key, decode_block_key, decode_day_key, decode_subnet_key,
    ignore_key, subnet_key,
};
use super::*;
use crate::test::{DbGuard, acquire_db_permit};
use crate::{
    Agent, AgentKind, AgentStatus, DaiRangeCandidate, DaiRangeError, DaiStoreOutcome,
    HostNetworkGroup, Node, NodeProfile, OwnedNetwork, OwnedNetworkTable, Store,
    dai_network_digest, event::NetworkType,
};

const NS: i64 = 1_000_000_000;
const MINUTE: i64 = 60 * NS;
const HOUR: i64 = 60 * MINUTE;
/// The date of [`NOW`].
const TODAY: i32 = 20_000;
/// Noon of [`TODAY`].
const NOW: i64 = 20_000 * DAY + 12 * HOUR;
/// The length of a lease.
const LEASE: i64 = 10 * MINUTE;
const CUSTOMER: u32 = 1;
const OTHER: u32 = 2;
const A: &str = "piglet.a.example";
const B: &str = "piglet.b.example";
/// A sensor of [`CUSTOMER`] that moves to [`OTHER`] in a deletion test.
const C: &str = "piglet.c.example";
/// The sensor of [`OTHER`].
const D: &str = "piglet.d.example";
/// A name nodes of both customers give, so not a customer sensor.
const SHARED: &str = "piglet.s.example";
/// A name no node gives.
const UNKNOWN: &str = "piglet.u.example";
/// The range families, with the sensor state, the guard and the meta
/// family the range methods also write.
const FAMILIES: [&str; 7] = [
    super::super::DAI_RANGE_BLOCKS,
    super::super::DAI_RANGE_SUBNETS,
    super::super::DAI_RANGE_DAYS,
    super::super::DAI_RANGE_IGNORES,
    super::super::DAI_SENSOR_STATE,
    super::super::DAI_SITE_POLICY_GUARD,
    super::super::DAI_META,
];

fn net(text: &str) -> IpNet {
    text.parse().unwrap()
}

fn addr(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn unit(sensor: &str, date: i32) -> DaiRangeUnit {
    DaiRangeUnit {
        sensor: sensor.to_string(),
        date,
        evidence: Evidence::Sensor,
    }
}

fn block(block: &str, distinct_addrs: u32, conns: u64, saturated: bool) -> DaiRangeBlock {
    DaiRangeBlock {
        block: net(block),
        distinct_addrs,
        conns,
        saturated,
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

/// Returns `CUSTOMER`'s networks: an `Intranet` network holding
/// `10.200.0.0/16` and the range `10.201.0.0`–`10.201.255.255`.
fn customer_networks() -> Vec<OwnedNetwork> {
    vec![OwnedNetwork {
        name: "intranet".to_string(),
        network_type: NetworkType::Intranet,
        group: HostNetworkGroup::new(
            Vec::new(),
            vec![net("10.200.0.0/16")],
            vec![addr("10.201.0.0")..=addr("10.201.255.255")],
        ),
    }]
}

/// Fills a store with the nodes of the sensors [`A`], [`B`] and [`C`] of
/// [`CUSTOMER`], [`D`] of [`OTHER`], and [`SHARED`] of both, gives
/// [`CUSTOMER`] its networks and its default site, and leaves device
/// identification off for both.
fn populate(store: &Store) {
    for (name, customer, host) in [
        ("a", CUSTOMER, "a.example"),
        ("b", CUSTOMER, "b.example"),
        ("c", CUSTOMER, "c.example"),
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
        .replace(CUSTOMER, 1, customer_networks())
        .unwrap();
    store.ensure_default_site(CUSTOMER).unwrap();
}

struct Fixture {
    store: Store,
    _permit: DbGuard<'static>,
    _dirs: (TempDir, TempDir),
}

fn setup() -> Fixture {
    let permit = acquire_db_permit();
    let data = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    let store = Store::new(data.path(), backup.path(), None).unwrap();
    populate(&store);
    Fixture {
        store,
        _permit: permit,
        _dirs: (data, backup),
    }
}

/// Returns a range day of `sensor` with the store's current check values.
fn range_day(
    store: &Store,
    sensor: &str,
    date: i32,
    version: u64,
    lease_token: u64,
    blocks: Vec<DaiRangeBlock>,
    subnets: &[&str],
) -> DaiRangeDay {
    let dai = store.states.dai();
    let customer = dai
        .read(|txn| Ok(dai.customer_sensors_in(txn)?.customer(sensor)))
        .unwrap();
    let networks = customer.and_then(|c| store.customer_networks_map().get(c).unwrap());
    DaiRangeDay {
        restore_generation: store.dai_restore_generation().unwrap(),
        config_epoch: store.dai_sensor_config_epoch(sensor).unwrap(),
        network_digest: dai_network_digest(networks.as_ref()).unwrap().digest,
        unit: unit(sensor, date),
        version,
        mark: None,
        lease_token,
        blocks,
        subnets: subnets.iter().map(|subnet| net(subnet)).collect(),
    }
}

/// Returns the version and the token of a grant, panicking on any other
/// answer.
fn granted(grant: Option<DaiRangeGrant>) -> (u64, u64) {
    match grant {
        Some(DaiRangeGrant::Granted {
            version,
            lease_token,
            ..
        }) => (version, lease_token),
        other => panic!("not granted: {other:?}"),
    }
}

fn range_error(error: &anyhow::Error) -> &DaiRangeError {
    error
        .downcast_ref::<DaiRangeError>()
        .unwrap_or_else(|| panic!("not a DAI range error: {error:#}"))
}

impl Fixture {
    fn dai(&self) -> Dai<'_> {
        self.store.states.dai()
    }

    fn generation(&self) -> u64 {
        self.store.dai_restore_generation().unwrap()
    }

    fn begin(&self, sensor: &str, date: i32, now: i64) -> Option<DaiRangeGrant> {
        self.store
            .begin_dai_range_day(&unit(sensor, date), self.generation(), now)
            .unwrap()
    }

    fn grant(&self, sensor: &str, date: i32, now: i64) -> (u64, u64) {
        granted(self.begin(sensor, date, now))
    }

    fn renew(&self, sensor: &str, date: i32, token: u64, now: i64) -> Option<i64> {
        self.store
            .renew_dai_range_day(&unit(sensor, date), token, now)
            .unwrap()
    }

    #[allow(clippy::too_many_arguments)] // The fields of one range day.
    fn day(
        &self,
        sensor: &str,
        date: i32,
        version: u64,
        token: u64,
        blocks: Vec<DaiRangeBlock>,
        subnets: &[&str],
    ) -> DaiRangeDay {
        range_day(&self.store, sensor, date, version, token, blocks, subnets)
    }

    fn send(&self, day: &DaiRangeDay, now: i64) -> DaiStoreOutcome {
        self.store.send_dai_range_day(day, now).unwrap()
    }

    /// Sends `day` and asserts it is answered as stored.
    fn stored(&self, day: &DaiRangeDay, now: i64) {
        assert_eq!(
            self.send(day, now),
            DaiStoreOutcome::Stored {
                restore_generation: self.generation(),
                marks: Vec::new(),
            }
        );
    }

    /// Grants a round of (`sensor`, `date`) at `now` and stores its result,
    /// returning the version and the token.
    fn store_day(
        &self,
        sensor: &str,
        date: i32,
        blocks: Vec<DaiRangeBlock>,
        subnets: &[&str],
        now: i64,
    ) -> (u64, u64) {
        let (version, token) = self.grant(sensor, date, now);
        self.stored(
            &self.day(sensor, date, version, token, blocks, subnets),
            now,
        );
        (version, token)
    }

    fn late(
        &self,
        sensor: &str,
        days: &[(i32, i64)],
        subnets: &[(i32, &str)],
    ) -> Vec<DaiRangeMark> {
        self.store
            .report_dai_range_late(&late_report(self.generation(), sensor, days, subnets), NOW)
            .unwrap()
    }

    fn day_row(&self, sensor: &str, date: i32) -> Option<DayRow> {
        let dai = self.dai();
        dai.read(|txn| {
            Dai::get_row(
                txn,
                &dai.range_days,
                &day_key(sensor, date, Evidence::Sensor),
            )
        })
        .unwrap()
    }

    /// Writes the row of (`sensor`, `date`, `Sensor`).
    fn put_day_row(&self, sensor: &str, date: i32, row: &DayRow) {
        let dai = self.dai();
        dai.write(|txn| {
            Dai::put_row(
                txn,
                &dai.range_days,
                &day_key(sensor, date, Evidence::Sensor),
                row,
            )
        })
        .unwrap();
    }

    fn blocks(&self, customer: u32, sensor: &str, date: i32) -> Vec<(IpNet, BlockRow)> {
        self.rows(super::super::DAI_RANGE_BLOCKS)
            .into_iter()
            .filter_map(|(key, value)| {
                let (c, s, d, evidence, block) = decode_block_key(&key).unwrap();
                assert_eq!(evidence, Evidence::Sensor);
                (c == customer && s == sensor && d == date)
                    .then(|| (block, super::super::deserialize(&value).unwrap()))
            })
            .collect()
    }

    fn subnets(&self, customer: u32, sensor: &str, date: i32) -> Vec<IpNet> {
        self.rows(super::super::DAI_RANGE_SUBNETS)
            .into_iter()
            .filter_map(|(key, _)| {
                let (c, s, d, subnet) = decode_subnet_key(&key).unwrap();
                (c == customer && s == sensor && d == date).then_some(subnet)
            })
            .collect()
    }

    fn rows(&self, family: &str) -> Vec<RawRow> {
        let txn = self.store.states.db().transaction();
        let map = Map::open(self.store.states.db(), family).unwrap();
        Dai::scan(&map, &txn, &[]).unwrap()
    }

    /// Returns every row of [`FAMILIES`].
    fn dump(&self) -> Vec<Vec<RawRow>> {
        FAMILIES.iter().map(|family| self.rows(family)).collect()
    }

    fn cursors(&self, sensors: &[&str], now: i64) -> DaiCursors {
        let sensors: Vec<String> = sensors.iter().map(ToString::to_string).collect();
        self.store.dai_cursors(&sensors, now).unwrap()
    }

    fn range_days(&self, sensors: &[&str], now: i64) -> Vec<DaiRangeDayState> {
        self.cursors(sensors, now).range_days
    }

    fn candidates(&self, customer: u32) -> Vec<DaiRangeCandidate> {
        let candidates = self.store.dai_range_candidates(customer, NOW).unwrap();
        assert_eq!(
            self.store
                .dai_collection_status(customer, NOW)
                .unwrap()
                .candidate_ranges,
            candidates.len()
        );
        candidates
    }

    fn sensor_state(&self, sensor: &str) -> SensorState {
        let dai = self.dai();
        dai.read(|txn| dai.sensor_state_for_update(txn, sensor))
            .unwrap()
    }
}

fn late_report(
    restore_generation: u64,
    sensor: &str,
    days: &[(i32, i64)],
    subnets: &[(i32, &str)],
) -> DaiRangeLate {
    DaiRangeLate {
        restore_generation,
        sensor: sensor.to_string(),
        late_days: days
            .iter()
            .map(|(date, delay_ns)| DaiLateDay {
                date: *date,
                evidence: Evidence::Sensor,
                delay_ns: *delay_ns,
            })
            .collect(),
        late_subnets: subnets
            .iter()
            .map(|(date, subnet)| DaiLateSubnet {
                date: *date,
                subnet: net(subnet),
            })
            .collect(),
    }
}

fn mark(date: i32, mark: u64) -> DaiRangeMark {
    DaiRangeMark {
        date,
        evidence: Evidence::Sensor,
        mark,
    }
}

// ---- Keys ----

#[test]
fn the_clock_constants_agree() {
    assert_eq!(date_of(NOW).unwrap(), TODAY);
}

#[test]
fn range_keys_read_back_and_select_by_prefix() {
    let blocks = [
        (1, "a", -1, "10.0.0.0/24"),
        (1, "a", 0, "10.0.0.0/24"),
        (1, "a", 0, "10.0.1.0/24"),
        (1, "a", 0, "fd00::/64"),
        (1, "a", 1, "10.0.0.0/24"),
        (1, "a\0", 0, "10.0.0.0/24"),
        (1, "b", 0, "10.0.0.0/24"),
        (2, "a", 0, "10.0.0.0/24"),
    ];
    let keys: Vec<Vec<u8>> = blocks
        .iter()
        .map(|(customer, sensor, date, block)| {
            block_key(*customer, sensor, *date, Evidence::Sensor, net(block))
        })
        .collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, keys);
    for (key, (customer, sensor, date, block)) in keys.iter().zip(blocks) {
        assert_eq!(
            decode_block_key(key).unwrap(),
            (
                customer,
                sensor.to_string(),
                date,
                Evidence::Sensor,
                net(block)
            )
        );
    }
    let prefix = KeyWriter::default().u32(1).str("a").date(0).finish();
    assert_eq!(
        keys.iter().filter(|key| key.starts_with(&prefix)).count(),
        3
    );
    let prefix = KeyWriter::default().u32(1).str("a").finish();
    assert_eq!(
        keys.iter().filter(|key| key.starts_with(&prefix)).count(),
        5
    );
    assert_eq!(
        keys.iter()
            .filter(|key| key.starts_with(&customer_key(1)))
            .count(),
        7
    );

    let subnet = subnet_key(3, "s", 5, net("10.1.0.0/22"));
    assert_eq!(
        decode_subnet_key(&subnet).unwrap(),
        (3, "s".to_string(), 5, net("10.1.0.0/22"))
    );
    let day = day_key("s", -7, Evidence::Sensor);
    assert_eq!(
        decode_day_key(&day).unwrap(),
        ("s".to_string(), -7, Evidence::Sensor)
    );
    assert!(day.starts_with(&sensor_key("s")));
    assert!(day.starts_with(&KeyWriter::default().str("s").date(-7).finish()));
    assert_eq!(day.last(), Some(&1), "Sensor is evidence 1");
    let ignore = ignore_key(3, net("fd00::/48"));
    assert!(ignore.starts_with(&customer_key(3)));

    // A prefix length beyond the family's is refused.
    let mut bad = KeyWriter::default().ip(addr("10.0.0.0")).finish();
    bad.push(33);
    assert!(KeyReader::new(&bad).ip_net().is_err());
    assert!(KeyReader::new(&[2]).range_evidence().is_err());
}

// ---- Lease and version ----

#[test]
fn a_begin_during_a_live_lease_is_in_progress() {
    let f = setup();
    let date = TODAY - 1;
    assert_eq!(f.grant(A, date, NOW).0, 1);
    assert_eq!(
        f.begin(A, date, NOW + LEASE - 1),
        Some(DaiRangeGrant::InProgress {
            lease_expires_at: NOW + LEASE
        })
    );
    // Other units are leased apart.
    assert_eq!(f.grant(A, date - 1, NOW).0, 1);
    assert_eq!(f.grant(B, date, NOW).0, 1);
}

#[test]
fn concurrent_begins_grant_once() {
    let f = setup();
    let generation = f.generation();
    let store = &f.store;
    let grants: Vec<Option<DaiRangeGrant>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    store
                        .begin_dai_range_day(&unit(A, TODAY - 1), generation, NOW)
                        .unwrap()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let granted = grants
        .iter()
        .filter(|g| matches!(g, Some(DaiRangeGrant::Granted { version: 1, .. })))
        .count();
    let in_progress = grants
        .iter()
        .filter(|g| {
            **g == Some(DaiRangeGrant::InProgress {
                lease_expires_at: NOW + LEASE,
            })
        })
        .count();
    assert_eq!((granted, in_progress), (1, 7), "{grants:?}");
}

#[test]
fn a_begin_after_the_lease_ends_gets_a_new_version_and_token() {
    let f = setup();
    let date = TODAY - 1;
    let (v1, t1) = f.grant(A, date, NOW);
    let (v2, t2) = f.grant(A, date, NOW + LEASE);
    assert_eq!((v1, v2), (1, 2));
    assert_ne!(t1, t2);
    assert_eq!(f.day_row(A, date).unwrap().lease_token, Some(t2));

    // The old token is not renewed, and its result changes nothing, though
    // its version is above the stored one (none).
    let before = f.dump();
    assert_eq!(f.renew(A, date, t1, NOW + LEASE + 1), None);
    f.stored(
        &f.day(
            A,
            date,
            v1,
            t1,
            vec![block("10.1.0.0/24", 1, 1, false)],
            &[],
        ),
        NOW + LEASE + 1,
    );
    assert_eq!(f.dump(), before);
}

#[test]
fn renewing_the_current_token_extends_the_lease_even_after_it_ended() {
    let f = setup();
    let date = TODAY - 1;
    let (version, token) = f.grant(A, date, NOW);
    assert_eq!(
        f.renew(A, date, token, NOW + 5 * MINUTE),
        Some(NOW + 15 * MINUTE)
    );
    assert_eq!(
        f.begin(A, date, NOW + 14 * MINUTE),
        Some(DaiRangeGrant::InProgress {
            lease_expires_at: NOW + 15 * MINUTE
        })
    );
    // The lease ended at +15 minutes and no begin came.
    assert_eq!(
        f.renew(A, date, token, NOW + 30 * MINUTE),
        Some(NOW + 40 * MINUTE)
    );
    f.stored(
        &f.day(
            A,
            date,
            version,
            token,
            vec![block("10.1.0.0/24", 3, 4, false)],
            &[],
        ),
        NOW + 31 * MINUTE,
    );
    assert_eq!(f.blocks(CUSTOMER, A, date).len(), 1);
    assert_eq!(f.day_row(A, date).unwrap().stored_version, Some(1));

    let before = f.dump();
    assert_eq!(f.renew(A, date, token ^ 1, NOW + 32 * MINUTE), None);
    assert_eq!(f.renew(A, date - 1, token, NOW + 32 * MINUTE), None);
    assert_eq!(f.dump(), before);
}

#[test]
fn a_date_more_than_a_day_ahead_is_refused() {
    let f = setup();
    let before = f.dump();
    let error = f
        .store
        .begin_dai_range_day(&unit(A, TODAY + 2), f.generation(), NOW)
        .unwrap_err();
    assert_eq!(
        range_error(&error),
        &DaiRangeError::FutureDate {
            date: TODAY + 2,
            today: TODAY
        }
    );
    for report in [
        late_report(f.generation(), A, &[(TODAY + 2, 0)], &[]),
        late_report(f.generation(), A, &[], &[(TODAY + 2, "10.0.0.0/24")]),
    ] {
        let error = f.store.report_dai_range_late(&report, NOW).unwrap_err();
        assert!(matches!(
            range_error(&error),
            DaiRangeError::FutureDate { .. }
        ));
    }
    assert_eq!(f.dump(), before);
    assert_eq!(f.grant(A, TODAY + 1, NOW).0, 1);
    assert_eq!(f.late(A, &[(TODAY + 1, 0)], &[]).len(), 1);
}

// ---- Storing a day ----

#[test]
fn each_invalid_field_is_refused_with_its_own_variant() {
    let f = setup();
    let date = TODAY - 1;
    let (version, token) = f.grant(A, date, NOW);
    let good = block("10.1.0.0/24", 1, 1, false);
    let cases = [
        (0, vec![good.clone()], DaiRangeError::ZeroVersion),
        (
            2,
            vec![good.clone()],
            DaiRangeError::UngrantedVersion {
                version: 2,
                last_granted: 1,
            },
        ),
        (
            version,
            vec![good.clone(), block("10.1.1.0/25", 1, 1, false)],
            DaiRangeError::InvalidBlock {
                block: net("10.1.1.0/25"),
            },
        ),
        (
            version,
            vec![block("10.1.1.1/24", 1, 1, false)],
            DaiRangeError::InvalidBlock {
                block: net("10.1.1.1/24"),
            },
        ),
        (
            version,
            vec![block("fd00::/48", 1, 1, false)],
            DaiRangeError::InvalidBlock {
                block: net("fd00::/48"),
            },
        ),
        (
            version,
            vec![good.clone(), block("fd00::/64", 1, 1, false), good.clone()],
            DaiRangeError::DuplicateBlock {
                block: net("10.1.0.0/24"),
            },
        ),
    ];
    let before = f.dump();
    for (version, blocks, expected) in cases {
        let day = f.day(A, date, version, token, blocks, &[]);
        let error = f.store.send_dai_range_day(&day, NOW).unwrap_err();
        assert_eq!(range_error(&error), &expected);
        assert_eq!(f.dump(), before, "{expected:?}");
    }
    f.stored(
        &f.day(
            A,
            date,
            version,
            token,
            vec![good, block("fd00::/64", 1, 1, false)],
            &[],
        ),
        NOW,
    );
    assert_eq!(f.blocks(CUSTOMER, A, date).len(), 2);
}

#[test]
fn a_result_of_a_lower_version_changes_neither_counts_nor_mark() {
    let f = setup();
    let date = TODAY - 1;
    f.store_day(A, date, vec![block("10.1.0.0/24", 5, 5, false)], &[], NOW);
    let [mark] = f.late(A, &[(date, 0)], &[]).try_into().unwrap();
    let (v2, t2) = f.grant(A, date, NOW + 20 * MINUTE);
    let (v3, _) = f.grant(A, date, NOW + 40 * MINUTE);
    assert_eq!((v2, v3), (2, 3));
    let before = f.dump();
    let mut day = f.day(
        A,
        date,
        v2,
        t2,
        vec![block("10.1.9.0/24", 9, 9, true)],
        &["10.1.0.0/16"],
    );
    day.mark = Some(mark.mark);
    f.stored(&day, NOW + 41 * MINUTE);
    assert_eq!(f.dump(), before);
    let row = f.day_row(A, date).unwrap();
    assert_eq!(row.mark, Some(mark.mark));
    assert_eq!(row.stored_version, Some(1));
}

#[test]
fn a_replace_removes_the_earlier_counts_and_keeps_late_subnets() {
    let f = setup();
    let date = TODAY - 1;
    f.store_day(
        A,
        date,
        vec![
            block("10.1.0.0/24", 5, 5, false),
            block("10.1.1.0/24", 6, 6, false),
        ],
        &["10.1.0.0/23"],
        NOW,
    );
    // Rows of another date and another sensor.
    f.store_day(
        A,
        date - 1,
        vec![block("10.1.0.0/24", 1, 1, false)],
        &["10.1.0.0/23"],
        NOW,
    );
    f.store_day(
        B,
        date,
        vec![block("10.1.0.0/24", 1, 1, false)],
        &["10.1.0.0/23"],
        NOW,
    );
    assert_eq!(f.late(A, &[], &[(date, "10.9.0.0/22")]), Vec::new());

    let (version, token) = f.grant(A, date, NOW + LEASE);
    f.stored(
        &f.day(
            A,
            date,
            version,
            token,
            vec![block("10.1.2.0/24", 7, 7, true)],
            &["10.1.2.0/24"],
        ),
        NOW + LEASE,
    );
    assert_eq!(
        f.blocks(CUSTOMER, A, date),
        [(
            net("10.1.2.0/24"),
            BlockRow {
                version: 2,
                distinct_addrs: 7,
                conns: 7,
                saturated: true
            }
        )]
    );
    assert_eq!(f.subnets(CUSTOMER, A, date), [net("10.1.2.0/24")]);
    let row = f.day_row(A, date).unwrap();
    assert_eq!(row.stored_version, Some(2));
    assert_eq!(row.late_subnets, BTreeSet::from([net("10.9.0.0/22")]));
    assert_eq!(f.blocks(CUSTOMER, A, date - 1).len(), 1);
    assert_eq!(f.subnets(CUSTOMER, A, date - 1), [net("10.1.0.0/23")]);
    assert_eq!(f.blocks(CUSTOMER, B, date).len(), 1);
}

#[test]
fn concurrent_sends_of_two_versions_leave_the_newer_only() {
    let f = setup();
    let date = TODAY - 1;
    let (v1, t1) = f.grant(A, date, NOW);
    let first = f.day(
        A,
        date,
        v1,
        t1,
        vec![block("10.1.0.0/24", 1, 1, false)],
        &["10.1.0.0/24"],
    );
    // Prepared before the hook runs, with the same check values.
    let generation = f.generation();
    let second_base = f.day(
        A,
        date,
        0,
        0,
        vec![block("10.1.1.0/24", 2, 2, false)],
        &["10.1.1.0/24"],
    );
    set_before_commit_hook(Box::new(move |db| {
        let dai = Dai::open(db).unwrap();
        let (version, token) = granted(
            dai.begin_range_day(&unit(A, date), generation, NOW + LEASE)
                .unwrap(),
        );
        let second = DaiRangeDay {
            version,
            lease_token: token,
            ..second_base
        };
        assert!(matches!(
            dai.send_range_day(&second).unwrap(),
            DaiStoreOutcome::Stored { .. }
        ));
    }));
    // The first send conflicts with the begin and the send of version 2,
    // and its retry finds its lease superseded.
    f.stored(&first, NOW + 1);
    assert_eq!(
        f.blocks(CUSTOMER, A, date)
            .into_iter()
            .map(|(block, row)| (block, row.version))
            .collect::<Vec<_>>(),
        [(net("10.1.1.0/24"), 2)]
    );
    assert_eq!(f.subnets(CUSTOMER, A, date), [net("10.1.1.0/24")]);
    assert_eq!(f.day_row(A, date).unwrap().stored_version, Some(2));
}

#[test]
fn a_resend_keeps_the_larger_counts_and_ors_saturated() {
    let f = setup();
    let date = TODAY - 1;
    let (version, token) = f.store_day(
        A,
        date,
        vec![
            block("10.1.0.0/24", 5, 100, false),
            block("10.1.1.0/24", 7, 1, true),
        ],
        &["10.1.0.0/23"],
        NOW,
    );
    f.stored(
        &f.day(
            A,
            date,
            version,
            token,
            vec![
                block("10.1.0.0/24", 3, 200, true),
                block("10.1.2.0/24", 1, 1, false),
            ],
            &["10.1.2.0/24", "10.1.0.0/23"],
        ),
        NOW + MINUTE,
    );
    let row = |distinct_addrs, conns, saturated| BlockRow {
        version: 1,
        distinct_addrs,
        conns,
        saturated,
    };
    assert_eq!(
        f.blocks(CUSTOMER, A, date),
        [
            (net("10.1.0.0/24"), row(5, 200, true)),
            (net("10.1.1.0/24"), row(7, 1, true)),
            (net("10.1.2.0/24"), row(1, 1, false)),
        ]
    );
    assert_eq!(
        f.subnets(CUSTOMER, A, date),
        [net("10.1.0.0/23"), net("10.1.2.0/24")]
    );
}

#[test]
fn subnets_are_stored_as_their_network_address_and_no_longer_than_a_block() {
    let f = setup();
    let date = TODAY - 1;
    f.store_day(
        A,
        date,
        Vec::new(),
        &[
            "10.1.0.5/22",
            "10.2.0.128/25",
            "fd00:1:2:3:4::/80",
            "fd00::1/48",
        ],
        NOW,
    );
    assert_eq!(
        f.subnets(CUSTOMER, A, date),
        [
            net("10.1.0.0/22"),
            net("10.2.0.0/24"),
            net("fd00::/48"),
            net("fd00:1:2:3::/64"),
        ]
    );
    f.late(A, &[], &[(date, "10.3.0.200/30")]);
    assert_eq!(
        f.day_row(A, date).unwrap().late_subnets,
        BTreeSet::from([net("10.3.0.0/24")])
    );
}

#[test]
fn a_send_carrying_the_mark_clears_it_and_a_newer_mark_stays() {
    let f = setup();
    let date = TODAY - 1;
    f.store_day(A, date, vec![block("10.1.0.0/24", 1, 1, false)], &[], NOW);
    let [first] = f.late(A, &[(date, 0)], &[]).try_into().unwrap();

    // Collector Q begins and lets its lease run out; collector P begins and
    // stores with the mark both read.
    let (vq, tq) = f.grant(A, date, NOW + LEASE);
    let (vp, tp) = f.grant(A, date, NOW + 2 * LEASE);
    let mut day = f.day(
        A,
        date,
        vp,
        tp,
        vec![block("10.1.0.0/24", 2, 2, false)],
        &[],
    );
    day.mark = Some(first.mark);
    f.stored(&day, NOW + 2 * LEASE);
    assert_eq!(f.day_row(A, date).unwrap().mark, None);

    // A new late record, then Q's old result: the new mark stays.
    let [second] = f.late(A, &[(date, 0)], &[]).try_into().unwrap();
    assert!(second.mark > first.mark);
    let mut old = f.day(
        A,
        date,
        vq,
        tq,
        vec![block("10.1.0.0/24", 9, 9, false)],
        &[],
    );
    old.mark = Some(first.mark);
    f.stored(&old, NOW + 2 * LEASE + 1);
    // A resend of P's own result with the old mark leaves it too.
    f.stored(&day, NOW + 2 * LEASE + 2);
    let row = f.day_row(A, date).unwrap();
    assert_eq!(row.mark, Some(second.mark));
    assert_eq!(row.stored_version, Some(vp));
    assert_eq!(f.blocks(CUSTOMER, A, date)[0].1.distinct_addrs, 2);
    // A send carrying no mark leaves the mark, and one carrying another
    // leaves it as well.
    let mut other = day.clone();
    other.mark = Some(second.mark + 1);
    f.stored(&other, NOW + 2 * LEASE + 3);
    assert_eq!(f.day_row(A, date).unwrap().mark, Some(second.mark));
}

#[test]
fn an_old_restore_generation_epoch_or_digest_gets_resync() {
    let f = setup();
    let date = TODAY - 1;
    let (version, token) = f.grant(A, date, NOW);
    let generation = f.generation();
    let resync = DaiStoreOutcome::Resync {
        restore_generation: generation,
    };
    let before = f.dump();

    assert_eq!(
        f.store
            .begin_dai_range_day(&unit(A, date - 1), generation ^ 1, NOW)
            .unwrap(),
        Some(DaiRangeGrant::Resync)
    );
    let good = f.day(
        A,
        date,
        version,
        token,
        vec![block("10.1.0.0/24", 1, 1, false)],
        &[],
    );
    // A field that would be refused is not checked before the resync.
    let changes: [fn(&mut DaiRangeDay); 4] = [
        |day: &mut DaiRangeDay| day.restore_generation ^= 1,
        |day: &mut DaiRangeDay| day.network_digest ^= 1,
        |day: &mut DaiRangeDay| day.config_epoch += 1,
        |day: &mut DaiRangeDay| {
            day.restore_generation ^= 1;
            day.version = 0;
        },
    ];
    for change in changes {
        let mut day = good.clone();
        change(&mut day);
        assert_eq!(f.send(&day, NOW), resync);
    }
    let error = f
        .store
        .report_dai_range_late(
            &late_report(generation ^ 1, A, &[(date, 0)], &[(date, "10.0.0.0/24")]),
            NOW,
        )
        .unwrap_err();
    assert_eq!(
        range_error(&error),
        &DaiRangeError::StaleRestoreGeneration {
            restore_generation: generation ^ 1
        }
    );
    assert_eq!(f.dump(), before);

    // A new configuration epoch makes the held one old.
    f.store.record_dai_sensor_config_hash(A, b"new").unwrap();
    let before = f.dump();
    assert_eq!(f.send(&good, NOW), resync);
    assert_eq!(f.dump(), before);
    f.stored(
        &f.day(
            A,
            date,
            version,
            token,
            vec![block("10.1.0.0/24", 1, 1, false)],
            &[],
        ),
        NOW,
    );
}

#[test]
fn a_send_racing_a_network_replace_is_retried() {
    let f = setup();
    let date = TODAY - 1;
    let (version, token) = f.grant(A, date, NOW);
    let day = f.day(
        A,
        date,
        version,
        token,
        vec![block("10.1.0.0/24", 1, 1, false)],
        &[],
    );
    set_before_commit_hook(Box::new(|db| {
        let mut networks = customer_networks();
        networks[0].name = "renamed".to_string();
        networks[0].group =
            HostNetworkGroup::new(Vec::new(), vec![net("10.250.0.0/16")], Vec::new());
        OwnedNetworkTable::open(db)
            .unwrap()
            .replace(CUSTOMER, 2, networks)
            .unwrap();
    }));
    assert!(matches!(f.send(&day, NOW), DaiStoreOutcome::Resync { .. }));
    assert_eq!(f.blocks(CUSTOMER, A, date), Vec::new());
    assert_eq!(f.day_row(A, date).unwrap().stored_version, None);
}

#[test]
fn sensors_that_are_not_customer_sensors_are_not_collected() {
    let f = setup();
    let date = TODAY - 1;
    let generation = f.generation();
    let before = f.dump();
    for sensor in [SHARED, UNKNOWN] {
        assert_eq!(f.begin(sensor, date, NOW), None);
        let day = f.day(
            sensor,
            date,
            1,
            1,
            vec![block("10.1.0.0/24", 1, 1, false)],
            &[],
        );
        assert_eq!(
            f.send(&day, NOW),
            DaiStoreOutcome::NotCollected {
                restore_generation: generation
            }
        );
        assert_eq!(f.late(sensor, &[(date, 0)], &[(date, "10.0.0.0/24")]), []);
    }
    assert_eq!(f.dump(), before);

    // A customer with device identification off is handled like any
    // other.
    assert!(
        !f.store
            .dai_settings(CUSTOMER)
            .unwrap()
            .device_account_identification
    );
    f.store_day(A, date, vec![block("10.1.0.0/24", 1, 1, false)], &[], NOW);
    assert_eq!(f.blocks(CUSTOMER, A, date).len(), 1);
    assert_eq!(f.late(A, &[(date, 0)], &[]).len(), 1);
}

#[test]
fn blocks_are_stored_under_the_customer_at_the_send() {
    let f = setup();
    let date = TODAY - 1;
    let (version, token) = f.grant(C, date, NOW);
    change_node(&f, "c", OTHER);
    f.stored(
        &f.day(
            C,
            date,
            version,
            token,
            vec![block("10.1.0.0/24", 1, 1, false)],
            &["10.1.0.0/23"],
        ),
        NOW,
    );
    assert_eq!(f.blocks(CUSTOMER, C, date), Vec::new());
    assert_eq!(f.blocks(OTHER, C, date).len(), 1);
    assert_eq!(f.subnets(OTHER, C, date), [net("10.1.0.0/23")]);
}

// ---- Late reports ----

/// Returns a one-part send of no observation in the slot `slot_start` of
/// `sensor`, with the current check values and one late slot.
fn late_slot_batch(f: &Fixture, sensor: &str, slot_start: i64) -> DaiObservationBatch {
    let networks = f.store.customer_networks_map().get(CUSTOMER).unwrap();
    DaiObservationBatch {
        restore_generation: f.generation(),
        config_epoch: f.store.dai_sensor_config_epoch(sensor).unwrap(),
        network_digest: dai_network_digest(networks.as_ref()).unwrap().digest,
        sensor: sensor.to_string(),
        kind: Kind::DnsName,
        slot_start,
        slot_len_secs: 300,
        send_id: rand::random(),
        part: 0,
        part_count: 1,
        observations: Vec::new(),
        last_record_time: None,
        late_slots: vec![DaiLateSlot {
            kind: Kind::DnsName,
            slot_start: slot_start - 5 * MINUTE,
            delay_ns: 1,
        }],
        reextract_mark: None,
        lost_before: None,
        counted_from: slot_start,
    }
}

/// Returns the slot marks a stored batch was answered.
fn slot_marks(f: &Fixture, batch: &DaiObservationBatch, now: i64) -> Vec<u64> {
    match f.store.store_dai_observations(batch, now).unwrap() {
        DaiStoreOutcome::Stored { marks, .. } => marks.into_iter().map(|m| m.mark).collect(),
        other => panic!("not stored: {other:?}"),
    }
}

#[test]
fn late_day_marks_and_slot_marks_share_one_counter() {
    let f = setup();
    let revision = f.store.dai_settings(CUSTOMER).unwrap().revision;
    f.dai()
        .set_settings(
            CUSTOMER,
            revision,
            &DaiSettingsUpdate {
                device_account_identification: true,
                inactivity_multiplier: 2,
                no_lease_inactivity_secs: 3600,
                evidence_aging_secs: 86_400,
                kerberos_preauth_realms: Vec::new(),
            },
            &(NOW - 2 * HOUR),
        )
        .unwrap();
    f.cursors(&[A], NOW - HOUR);
    let slot = slot_floor(NOW - 30 * MINUTE).unwrap();
    let date = TODAY - 1;

    let mut seen = Vec::new();
    seen.extend(slot_marks(&f, &late_slot_batch(&f, A, slot), NOW));
    seen.extend(f.late(A, &[(date, 0)], &[]).into_iter().map(|m| m.mark));
    seen.extend(slot_marks(
        &f,
        &late_slot_batch(&f, A, slot + 5 * MINUTE),
        NOW,
    ));
    // A mark cleared by a send is not drawn again.
    let (version, token) = f.grant(A, date, NOW);
    let mut day = f.day(A, date, version, token, Vec::new(), &[]);
    day.mark = f.day_row(A, date).unwrap().mark;
    f.stored(&day, NOW);
    assert_eq!(f.day_row(A, date).unwrap().mark, None);
    seen.extend(
        f.late(A, &[(date, 0), (date - 1, 0)], &[])
            .into_iter()
            .map(|m| m.mark),
    );
    seen.extend(slot_marks(
        &f,
        &late_slot_batch(&f, A, slot + 10 * MINUTE),
        NOW,
    ));
    let first = *seen.first().unwrap();
    assert_eq!(seen, (first..first + 6).collect::<Vec<_>>());
    assert_eq!(f.sensor_state(A).next_mark, first + 6);
}

#[test]
fn a_late_report_marks_each_unit_once_and_keeps_the_longest_delay() {
    let f = setup();
    let next = f.sensor_state(A).next_mark;
    let marks = f.late(
        A,
        &[
            (TODAY - 3, 5 * HOUR),
            (TODAY - 1, -HOUR),
            (TODAY - 3, 7 * HOUR),
            (TODAY - 3, 2 * HOUR),
        ],
        &[(TODAY - 2, "10.1.0.0/22"), (TODAY - 2, "10.1.0.0/22")],
    );
    assert_eq!(marks, [mark(TODAY - 3, next), mark(TODAY - 1, next + 1)]);
    let row = f.day_row(A, TODAY - 3).unwrap();
    assert_eq!(row.mark, Some(next));
    assert_eq!(row.longest_delay, 7 * HOUR);
    assert_eq!(row.stored_version, None);
    assert_eq!(f.day_row(A, TODAY - 1).unwrap().longest_delay, 0);
    let subnets = f.day_row(A, TODAY - 2).unwrap();
    assert_eq!(subnets.late_subnets, BTreeSet::from([net("10.1.0.0/22")]));
    assert_eq!((subnets.mark, subnets.last_granted), (None, 0));

    // A later report replaces the mark and keeps the longer delay.
    let [again] = f.late(A, &[(TODAY - 3, HOUR)], &[]).try_into().unwrap();
    assert_eq!(again, mark(TODAY - 3, next + 2));
    let row = f.day_row(A, TODAY - 3).unwrap();
    assert_eq!((row.mark, row.longest_delay), (Some(next + 2), 7 * HOUR));
}

#[test]
fn a_late_subnet_reported_before_the_replace_survives_it() {
    let f = setup();
    let date = TODAY - 2;
    f.cursors(&[A], NOW - 40 * DAY);
    f.store_day(
        A,
        date,
        vec![block("10.1.0.0/24", 1, 1, false)],
        &["10.1.0.0/24"],
        NOW,
    );
    let [late] = f.late(A, &[(date, 0)], &[]).try_into().unwrap();
    let listed: Vec<_> = f
        .range_days(&[A], NOW)
        .into_iter()
        .filter(|day| day.date == date)
        .collect();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].mark, Some(late.mark));
    assert_eq!(listed[0].stored_version, Some(1));

    let (version, token) = f.grant(A, date, NOW + LEASE);
    f.late(A, &[], &[(date, "10.1.4.0/22")]);
    let mut day = f.day(
        A,
        date,
        version,
        token,
        vec![block("10.1.1.0/24", 2, 2, false)],
        &[],
    );
    day.mark = listed[0].mark;
    f.stored(&day, NOW + LEASE);
    let row = f.day_row(A, date).unwrap();
    assert_eq!(row.late_subnets, BTreeSet::from([net("10.1.4.0/22")]));
    assert_eq!((row.mark, row.stored_version), (None, Some(2)));
    assert_eq!(f.subnets(CUSTOMER, A, date), Vec::new());
}

// ---- The recollection list ----

fn listed_dates(days: &[DaiRangeDayState], sensor: &str) -> Vec<i32> {
    days.iter()
        .filter(|day| day.sensor == sensor)
        .map(|day| day.date)
        .collect()
}

#[test]
fn range_days_list_the_days_to_collect() {
    let f = setup();
    f.cursors(&[A], NOW - 40 * DAY);
    f.cursors(&[B], NOW - 5 * DAY);
    // A: stored and unmarked, stored and marked, granted only, a late
    // subnet only, and no row at all.
    f.store_day(A, TODAY - 2, Vec::new(), &[], NOW);
    f.store_day(A, TODAY - 3, Vec::new(), &[], NOW);
    let [late] = f.late(A, &[(TODAY - 3, 0)], &[]).try_into().unwrap();
    f.grant(A, TODAY - 4, NOW);
    f.late(A, &[], &[(TODAY - 6, "10.0.0.0/24")]);
    // Rows outside the window are not listed either.
    f.store_day(A, TODAY - 30, Vec::new(), &[], NOW);
    f.late(A, &[(TODAY - 30, 0), (TODAY, 0)], &[]);

    let days = f.range_days(&["all"], NOW);
    // A read that creates no cursor row writes nothing.
    let before = f.dump();
    assert_eq!(f.range_days(&["all"], NOW), days);
    assert_eq!(f.dump(), before);

    let expected_a: Vec<i32> = (TODAY - 29..TODAY)
        .filter(|date| *date != TODAY - 2)
        .collect();
    assert_eq!(listed_dates(&days, A), expected_a);
    assert_eq!(
        listed_dates(&days, B),
        (TODAY - 4..TODAY).collect::<Vec<_>>()
    );
    // C, D and the other sensors got their first cursor rows in this read.
    assert_eq!(listed_dates(&days, C), Vec::<i32>::new());
    assert_eq!(listed_dates(&days, D), Vec::<i32>::new());
    let state = |date| {
        days.iter()
            .find(|day| day.sensor == A && day.date == date)
            .map(|day| (day.evidence, day.mark, day.stored_version))
            .unwrap()
    };
    assert_eq!(
        state(TODAY - 3),
        (Evidence::Sensor, Some(late.mark), Some(1))
    );
    assert_eq!(state(TODAY - 4), (Evidence::Sensor, None, None));
    assert_eq!(state(TODAY - 6), (Evidence::Sensor, None, None));
    assert_eq!(state(TODAY - 1), (Evidence::Sensor, None, None));
    // Ordered by sensor name, then date.
    let order: Vec<(&str, i32)> = days.iter().map(|d| (d.sensor.as_str(), d.date)).collect();
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(order, sorted);

    // Yesterday is listed once it ended 1 hour 5 minutes ago.
    let midnight = i64::from(TODAY) * DAY;
    let at = |now| listed_dates(&f.range_days(&[A], now), A);
    assert!(!at(midnight + 65 * MINUTE - 1).contains(&(TODAY - 1)));
    assert!(at(midnight + 65 * MINUTE).contains(&(TODAY - 1)));
    assert_eq!(f.dump(), before);

    // A sensor whose first cursor row a read creates lists none.
    drop(f);
    let f = setup();
    assert_eq!(f.range_days(&[A], NOW), Vec::new());
    assert_eq!(f.range_days(&[A], NOW + 3 * DAY).len(), 2);
}

// ---- After a restore ----

/// The units a restore test writes, as (sensor, days before today, stored,
/// longest delay).
fn restore_units() -> Vec<(&'static str, i32, bool, i64)> {
    let mut units = Vec::new();
    for sensor in [A, B, D, UNKNOWN] {
        for days in 1..=8 {
            units.push((sensor, days, true, 0));
        }
    }
    // Not stored: listed, never marked by a restore.
    units.push((A, 10, false, 0));
    // D reported a delay of 5 days on a recent unit; B one of 20 days on a
    // unit older than 30 days, which is not counted.
    units.push((D, 9, false, 5 * DAY));
    units.push((B, 40, true, 20 * DAY));
    units
}

/// The number of days before today from which a restore marks the stored
/// units of each sensor.
fn marked_from(sensor: &str) -> Option<i32> {
    match sensor {
        // The 24-hour lookback, from a cursor within today.
        A => Some(1),
        // A 3-day arrival delay.
        B => Some(3),
        // A 5-day reported delay.
        D => Some(5),
        // No cursor row.
        _ => None,
    }
}

/// The lease tokens a restore test writes, by unit.
type Tokens = BTreeMap<(String, i32), u64>;

/// The mark counter of [`A`] before a restore.
const NEXT_MARK: u64 = 100;

/// Fills `store` for a restore test at the current time, and returns the
/// lease tokens written, by unit.
fn prepare_restore(store: &Store) -> Tokens {
    populate(store);
    let now = now_nanos().unwrap();
    let today = date_of(now).unwrap();
    let base = slot_floor(now).unwrap();
    let dai = store.states.dai();
    for sensor in [A, B, D] {
        let mut row = CursorRow {
            cursor: base,
            read_floor: base - 3 * DAY,
            ..CursorRow::default()
        };
        if sensor == B {
            row.delays.insert(today, 3 * DAY);
        }
        dai.write(|txn| {
            dai.put_cursor(txn, sensor, Kind::DnsName, &row)?;
            let mut state = dai.sensor_state_for_update(txn, sensor)?;
            state.first_cursor_time = Some(base - 60 * DAY);
            if sensor == A {
                state.next_mark = NEXT_MARK;
            }
            dai.put_sensor_state(txn, sensor, &state)
        })
        .unwrap();
    }
    let mut tokens = BTreeMap::new();
    for (index, (sensor, days, stored, delay)) in restore_units().into_iter().enumerate() {
        let token = u64::try_from(index).unwrap() + 1;
        let row = DayRow {
            last_granted: 1,
            lease_token: Some(token),
            lease_end: Some(now + 365 * DAY),
            stored_version: stored.then_some(1),
            mark: None,
            late_subnets: BTreeSet::new(),
            longest_delay: delay,
        };
        let date = today - days;
        dai.write(|txn| {
            Dai::put_row(
                txn,
                &dai.range_days,
                &day_key(sensor, date, Evidence::Sensor),
                &row,
            )
        })
        .unwrap();
        tokens.insert((sensor.to_string(), date), token);
    }
    store.dai_restore_generation().unwrap();
    tokens
}

/// Asserts that every unit of [`restore_units`] got a new token whose lease
/// ended, that the stored units within each sensor's lookback window, and
/// only those, carry new marks, which `range_days` lists, and that a begin
/// is granted at once.
fn assert_range_restored(store: &Store, tokens: &Tokens) {
    let now = now_nanos().unwrap();
    let today = date_of(now).unwrap();
    let dai = store.states.dai();
    let mut marked: BTreeMap<&str, Vec<u64>> = BTreeMap::new();
    for (sensor, days, stored, _) in restore_units() {
        let date = today - days;
        let row: DayRow = dai
            .read(|txn| {
                Dai::get_row(
                    txn,
                    &dai.range_days,
                    &day_key(sensor, date, Evidence::Sensor),
                )
            })
            .unwrap()
            .unwrap();
        let old = tokens[&(sensor.to_string(), date)];
        assert!(row.lease_token.is_some_and(|token| token != old));
        assert!(
            row.lease_end.is_some_and(|end| end <= now),
            "{sensor} {days}"
        );
        let expect_mark = stored && marked_from(sensor).is_some_and(|from| days <= from);
        assert_eq!(row.mark.is_some(), expect_mark, "{sensor} {days}");
        if let Some(mark) = row.mark {
            marked.entry(sensor).or_default().push(mark);
        }
        assert_eq!(
            store
                .renew_dai_range_day(&unit(sensor, date), old, now)
                .unwrap(),
            None
        );
    }
    assert_eq!(marked[A], [NEXT_MARK]);
    assert_eq!(marked[B].len(), 3);
    assert_eq!(marked[D].len(), 5);
    assert!(!marked.contains_key(UNKNOWN));

    let sensors: Vec<String> = [A, B, D].iter().map(ToString::to_string).collect();
    let days = store.dai_cursors(&sensors, now).unwrap().range_days;
    for (sensor, offset, stored, _) in restore_units() {
        let date = today - offset;
        if sensor == UNKNOWN || i64::from(date) <= i64::from(today) - 30 {
            continue;
        }
        let ready = (i64::from(date) + 1) * DAY + 65 * MINUTE <= now;
        let expect = ready && (!stored || marked_from(sensor).is_some_and(|from| offset <= from));
        assert_eq!(
            days.iter()
                .any(|day| day.sensor == sensor && day.date == date),
            expect,
            "{sensor} {offset}"
        );
    }

    let generation = store.dai_restore_generation().unwrap();
    assert!(matches!(
        store
            .begin_dai_range_day(&unit(A, today - 1), generation, now)
            .unwrap(),
        Some(DaiRangeGrant::Granted { version: 2, .. })
    ));
}

fn backed_up_store(data: &TempDir, backup: &TempDir) -> (Arc<RwLock<Store>>, Tokens) {
    let store = Arc::new(RwLock::new(
        Store::new(data.path(), backup.path(), None).unwrap(),
    ));
    let tokens = prepare_restore(&store.read().unwrap());
    crate::backup::create(&store, true, 5).unwrap();
    (store, tokens)
}

#[test]
fn every_online_restore_marks_the_range_days_within_the_lookback() {
    let _permit = acquire_db_permit();
    let data = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    let (store, tokens) = backed_up_store(&data, &backup);
    crate::backup::restore(&store, Some(1)).unwrap();
    assert_range_restored(&store.read().unwrap(), &tokens);
    store.write().unwrap().restore_from_backup(1).unwrap();
    assert_range_restored(&store.read().unwrap(), &tokens);
}

#[test]
fn an_offline_restore_marks_the_range_days_at_the_next_open() {
    let _permit = acquire_db_permit();
    let data = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    let tokens = {
        let (_store, tokens) = backed_up_store(&data, &backup);
        tokens
    };
    crate::backup::restore_states_offline(data.path(), backup.path(), 1).unwrap();
    let store = Store::new(data.path(), backup.path(), None).unwrap();
    assert_range_restored(&store, &tokens);
}

#[test]
fn a_restore_marks_a_stored_day_of_any_date_without_overflow() {
    let f = setup();
    let dai = f.dai();
    let stored = DayRow {
        stored_version: Some(1),
        ..DayRow::default()
    };
    for date in [i32::MIN, i32::MAX] {
        f.put_day_row(A, date, &stored);
    }
    dai.write(|txn| {
        let row = CursorRow {
            cursor: i64::MAX,
            ..CursorRow::default()
        };
        dai.put_cursor(txn, A, Kind::DnsName, &row)
    })
    .unwrap();
    dai.after_restore(NOW).unwrap();
    assert_eq!(f.day_row(A, i32::MIN).unwrap().mark, None);
    assert!(f.day_row(A, i32::MAX).unwrap().mark.is_some());
}

#[test]
fn a_restore_ignores_the_delay_reported_on_a_future_date() {
    let f = setup();
    let dates: Vec<i32> = (1..=5).map(|days| TODAY - days).collect();
    store_on(&f, A, &dates, &[("10.1.0.0/24", 1)], &[]);
    // Tomorrow is accepted by a late report, but its delay of 5 days is not
    // one of the last 30 days and leaves the 24-hour lookback.
    assert_eq!(f.late(A, &[(TODAY + 1, 5 * DAY)], &[]).len(), 1);
    assert_eq!(f.day_row(A, TODAY + 1).unwrap().longest_delay, 5 * DAY);
    let dai = f.dai();
    dai.write(|txn| {
        let row = CursorRow {
            cursor: NOW,
            ..CursorRow::default()
        };
        dai.put_cursor(txn, A, Kind::DnsName, &row)
    })
    .unwrap();
    dai.after_restore(NOW).unwrap();
    for date in dates {
        assert_eq!(
            f.day_row(A, date).unwrap().mark.is_some(),
            date == TODAY - 1,
            "{date}"
        );
    }
}

// ---- Candidates ----

/// Stores `blocks` for `sensor` on each of `dates`, with `subnets`.
fn store_on(f: &Fixture, sensor: &str, dates: &[i32], blocks: &[(&str, u32)], subnets: &[&str]) {
    for date in dates {
        let blocks = blocks
            .iter()
            .map(|(net, addrs)| block(net, *addrs, u64::from(*addrs) * 10, false))
            .collect();
        f.store_day(sensor, *date, blocks, subnets, NOW);
    }
}

fn ranges(candidates: &[DaiRangeCandidate]) -> Vec<IpNet> {
    candidates.iter().map(|candidate| candidate.range).collect()
}

const WINDOW: [i32; 3] = [TODAY - 3, TODAY - 2, TODAY - 1];

#[test]
fn a_range_follows_the_dhcp_subnet_and_is_never_narrower_than_a_block() {
    let f = setup();
    // A /22 subnet on the first date covers the blocks of the next ones.
    store_on(
        &f,
        A,
        &WINDOW[..1],
        &[("10.1.0.0/24", 2), ("10.1.3.0/24", 3)],
        &["10.1.0.0/22"],
    );
    store_on(
        &f,
        A,
        &WINDOW[1..],
        &[("10.1.0.0/24", 2), ("10.1.3.0/24", 3)],
        &[],
    );
    // A /25 subnet is stored as its /24.
    store_on(
        &f,
        B,
        &WINDOW,
        &[("10.2.0.0/24", 1), ("10.2.1.0/24", 1)],
        &["10.2.0.128/25"],
    );
    let candidates = f.candidates(CUSTOMER);
    assert_eq!(
        ranges(&candidates),
        [net("10.1.0.0/22"), net("10.2.0.0/24"), net("10.2.1.0/24")]
    );
    let wide = &candidates[0];
    assert_eq!(wide.seen_addrs, 5);
    assert!(!wide.seen_addrs_at_least);
    assert_eq!(wide.values, BTreeMap::from([(Evidence::Sensor, 3)]));
    assert_eq!((wide.first_date, wide.last_date), (TODAY - 3, TODAY - 1));
    assert!(!wide.cgnat);
}

#[test]
fn the_widest_private_subnet_is_used() {
    let f = setup();
    store_on(
        &f,
        A,
        &WINDOW,
        &[("10.1.0.0/24", 1)],
        &["10.1.0.0/23", "10.1.0.0/22", "10.1.4.0/22"],
    );
    // A covering subnet outside the private prefixes is not used.
    store_on(&f, B, &WINDOW, &[("10.3.0.0/24", 1)], &["10.0.0.0/7"]);
    assert_eq!(
        ranges(&f.candidates(CUSTOMER)),
        [net("10.1.0.0/22"), net("10.3.0.0/24")]
    );
}

#[test]
fn a_late_subnet_widens_its_date_and_the_13_after() {
    let f = setup();
    store_on(
        &f,
        A,
        &WINDOW,
        &[("10.4.0.0/24", 1), ("10.4.1.0/24", 1)],
        &[],
    );
    f.late(A, &[], &[(TODAY - 14, "10.4.0.0/22")]);
    // One dated a day earlier covers all but the last date.
    store_on(
        &f,
        B,
        &[TODAY - 4, TODAY - 3, TODAY - 2, TODAY - 1],
        &[("10.5.0.0/24", 1), ("10.5.1.0/24", 1)],
        &[],
    );
    f.late(B, &[], &[(TODAY - 15, "10.5.0.0/22")]);
    let candidates = f.candidates(CUSTOMER);
    assert_eq!(
        ranges(&candidates),
        [net("10.4.0.0/22"), net("10.5.0.0/22")]
    );
    assert_eq!(candidates[1].last_date, TODAY - 2);
    // The late subnets marked nothing for recollection.
    assert_eq!(f.day_row(A, TODAY - 14).unwrap().mark, None);
}

#[test]
fn a_range_needs_values_on_three_dates_of_the_window() {
    let f = setup();
    store_on(&f, A, &[TODAY - 2, TODAY - 1], &[("10.1.0.0/24", 1)], &[]);
    // Dates outside the window count for nothing.
    store_on(&f, A, &[TODAY - 15, TODAY], &[("10.1.0.0/24", 1)], &[]);
    // Two sensors on one date make one date.
    store_on(&f, B, &[TODAY - 2], &[("10.1.0.0/24", 1)], &[]);
    assert_eq!(f.candidates(CUSTOMER), []);
    store_on(&f, B, &[TODAY - 14], &[("10.1.0.0/24", 1)], &[]);
    let candidates = f.candidates(CUSTOMER);
    assert_eq!(ranges(&candidates), [net("10.1.0.0/24")]);
    assert_eq!(
        candidates[0].values,
        BTreeMap::from([(Evidence::Sensor, 4)])
    );
    assert_eq!(
        (candidates[0].first_date, candidates[0].last_date),
        (TODAY - 14, TODAY - 1)
    );
}

#[test]
fn seen_addresses_are_the_largest_value_and_saturation_is_a_lower_bound() {
    let f = setup();
    // On each date, the sum of the blocks the /23 holds.
    let day = |blocks: Vec<DaiRangeBlock>| (blocks, vec!["10.1.0.0/23"]);
    for (date, (blocks, subnets)) in [
        (
            TODAY - 3,
            day(vec![
                block("10.1.0.0/24", 10, 1, false),
                block("10.1.1.0/24", 20, 2, false),
            ]),
        ),
        (
            TODAY - 2,
            day(vec![
                block("10.1.0.0/24", 5, u64::MAX, true),
                block("10.1.1.0/24", 1, 9, false),
            ]),
        ),
        (TODAY - 1, day(vec![block("10.1.0.0/24", 40, 3, false)])),
    ] {
        f.store_day(A, date, blocks, &subnets, NOW);
    }
    let [candidate] = f.candidates(CUSTOMER).try_into().unwrap();
    assert_eq!(candidate.seen_addrs, 65_537);
    assert!(candidate.seen_addrs_at_least);

    // The largest value, saturated, from another sensor.
    drop(f);
    let f = setup();
    for date in WINDOW {
        f.store_day(A, date, vec![block("10.1.0.0/24", 30, 1, false)], &[], NOW);
    }
    f.store_day(
        B,
        TODAY - 1,
        vec![block("10.1.0.0/24", 7, 1, true)],
        &[],
        NOW,
    );
    let [candidate] = f.candidates(CUSTOMER).try_into().unwrap();
    assert_eq!(candidate.seen_addrs, 65_536);
    assert!(candidate.seen_addrs_at_least);
    assert_eq!(candidate.values, BTreeMap::from([(Evidence::Sensor, 4)]));
}

#[test]
fn ranges_of_two_sensors_are_not_merged() {
    let f = setup();
    store_on(
        &f,
        A,
        &WINDOW,
        &[("10.6.0.0/24", 1), ("10.7.0.0/24", 1)],
        &["10.6.0.0/22"],
    );
    store_on(&f, B, &WINDOW, &[("10.6.0.0/24", 2)], &[]);
    // The same range from two sensors is one candidate.
    store_on(&f, B, &[TODAY - 5], &[("10.7.0.0/24", 1)], &[]);
    let candidates = f.candidates(CUSTOMER);
    assert_eq!(
        ranges(&candidates),
        [net("10.6.0.0/22"), net("10.6.0.0/24"), net("10.7.0.0/24")]
    );
    assert_eq!(candidates[2].values[&Evidence::Sensor], 4);
    assert_eq!(candidates[2].first_date, TODAY - 5);
}

#[test]
fn candidates_carry_the_sites_of_their_sensors() {
    let f = setup();
    let default = f.store.dai_sites(CUSTOMER).unwrap()[0].token.clone();
    // A moves to a new site at 12:05 on the middle date.
    let moved_at = i64::from(TODAY - 2) * DAY + 12 * HOUR;
    let site = f
        .dai()
        .create_site(CUSTOMER, "east", &[A.to_string()], &moved_at)
        .unwrap();
    store_on(
        &f,
        A,
        &WINDOW[..1],
        &[("10.1.0.0/24", 1), ("10.2.0.0/24", 1)],
        &[],
    );
    store_on(
        &f,
        A,
        &WINDOW[1..],
        &[("10.1.0.0/24", 1), ("10.3.0.0/24", 1)],
        &[],
    );
    store_on(&f, B, &[TODAY - 2, TODAY - 1], &[("10.2.0.0/24", 1)], &[]);
    store_on(&f, B, &[TODAY - 4], &[("10.3.0.0/24", 1)], &[]);
    let mut both = vec![default.clone(), site.clone()];
    both.sort_unstable();
    let candidates = f.candidates(CUSTOMER);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.sites.clone())
            .collect::<Vec<_>>(),
        [both.clone(), vec![default.clone()], both]
    );
    // A customer with no default site lists none.
    store_on(&f, D, &WINDOW, &[("10.1.0.0/24", 1)], &[]);
    let [other] = f.candidates(OTHER).try_into().unwrap();
    assert_eq!(other.sites, Vec::<String>::new());
    assert_eq!(f.store.dai_sites(OTHER).unwrap(), []);
}

#[test]
fn registered_public_and_ignored_ranges_are_excluded() {
    let f = setup();
    store_on(
        &f,
        A,
        &WINDOW,
        &[
            ("10.200.1.0/24", 1),
            ("10.201.7.0/24", 1),
            ("8.8.8.0/24", 1),
            ("2001:db8::/64", 1),
            ("fd00:1::/64", 1),
            ("172.16.5.0/24", 1),
            ("100.64.5.0/24", 1),
            ("192.168.9.0/24", 1),
        ],
        &[],
    );
    // A range only partly registered stays.
    store_on(&f, B, &WINDOW, &[("10.200.2.0/24", 1)], &["10.200.0.0/14"]);
    // The blocks are stored as sent.
    assert_eq!(f.blocks(CUSTOMER, A, TODAY - 1).len(), 8);
    let candidates = f.candidates(CUSTOMER);
    assert_eq!(
        ranges(&candidates),
        [
            net("10.200.0.0/14"),
            net("100.64.5.0/24"),
            net("172.16.5.0/24"),
            net("192.168.9.0/24"),
            net("fd00:1::/64"),
        ]
    );
    assert_eq!(
        candidates.iter().map(|c| c.cgnat).collect::<Vec<_>>(),
        [false, true, false, false, false]
    );

    // Ignoring.
    let ignored = f
        .store
        .ignore_dai_range(CUSTOMER, net("172.16.5.9/24"), "alice", NOW)
        .unwrap();
    assert_eq!(ignored, net("172.16.5.0/24"));
    assert_eq!(
        f.store
            .ignore_dai_range(CUSTOMER, net("172.16.5.0/24"), "bob", NOW + 1)
            .unwrap(),
        ignored
    );
    f.store
        .ignore_dai_range(CUSTOMER, net("10.0.0.0/8"), "bob", NOW + 2)
        .unwrap();
    f.store
        .ignore_dai_range(OTHER, net("172.16.5.0/24"), "carol", NOW + 3)
        .unwrap();
    let list = f.store.dai_ignored_ranges(CUSTOMER).unwrap();
    assert_eq!(
        list.iter()
            .map(|r| (r.range, r.ignored_at, r.account.as_str()))
            .collect::<Vec<_>>(),
        [
            (net("10.0.0.0/8"), NOW + 2, "bob"),
            (net("172.16.5.0/24"), NOW, "alice"),
        ]
    );
    // Only an exact match is excluded.
    assert_eq!(
        ranges(&f.candidates(CUSTOMER)),
        [
            net("10.200.0.0/14"),
            net("100.64.5.0/24"),
            net("192.168.9.0/24"),
            net("fd00:1::/64"),
        ]
    );
    assert!(
        f.store
            .unignore_dai_range(CUSTOMER, net("172.16.5.200/24"))
            .unwrap()
    );
    assert!(
        !f.store
            .unignore_dai_range(CUSTOMER, net("172.16.5.0/24"))
            .unwrap()
    );
    assert_eq!(f.candidates(CUSTOMER).len(), 5);
    assert_eq!(f.store.dai_ignored_ranges(CUSTOMER).unwrap().len(), 1);
    assert_eq!(f.store.dai_ignored_ranges(OTHER).unwrap().len(), 1);
}

#[test]
fn a_saturated_block_counts_65536_addresses() {
    let f = setup();
    for date in WINDOW {
        f.store_day(A, date, vec![block("100.64.0.0/24", 3, 1, true)], &[], NOW);
    }
    let [candidate] = f.candidates(CUSTOMER).try_into().unwrap();
    assert_eq!(
        candidate,
        DaiRangeCandidate {
            range: net("100.64.0.0/24"),
            seen_addrs: 65_536,
            seen_addrs_at_least: true,
            values: BTreeMap::from([(Evidence::Sensor, 3)]),
            first_date: TODAY - 3,
            last_date: TODAY - 1,
            sites: f
                .store
                .dai_sites(CUSTOMER)
                .unwrap()
                .into_iter()
                .map(|site| site.token)
                .collect(),
            cgnat: true,
        }
    );
}

// ---- Retention and customer deletion ----

#[test]
fn retention_removes_the_rows_older_than_30_days() {
    let f = setup();
    for date in [TODAY - 31, TODAY - 30] {
        f.store_day(
            A,
            date,
            vec![block("10.1.0.0/24", 1, 1, false)],
            &["10.1.0.0/24"],
            NOW,
        );
        f.late(A, &[], &[(date - 2, "10.2.0.0/24")]);
    }
    f.store
        .ignore_dai_range(CUSTOMER, net("10.1.0.0/24"), "alice", NOW - 400 * DAY)
        .unwrap();
    let ignores = f.rows(super::super::DAI_RANGE_IGNORES);
    f.store.apply_dai_retention(NOW).unwrap();
    assert_eq!(f.blocks(CUSTOMER, A, TODAY - 31), Vec::new());
    assert_eq!(f.subnets(CUSTOMER, A, TODAY - 31), Vec::new());
    assert_eq!(f.day_row(A, TODAY - 31), None);
    assert_eq!(f.day_row(A, TODAY - 32), None);
    assert_eq!(f.day_row(A, TODAY - 33), None);
    assert_eq!(f.blocks(CUSTOMER, A, TODAY - 30).len(), 1);
    assert_eq!(f.subnets(CUSTOMER, A, TODAY - 30).len(), 1);
    assert!(f.day_row(A, TODAY - 30).is_some());
    assert_eq!(f.rows(super::super::DAI_RANGE_IGNORES), ignores);
    let days: Vec<i32> = f
        .rows(super::super::DAI_RANGE_DAYS)
        .iter()
        .map(|(key, _)| decode_day_key(key).unwrap().1)
        .collect();
    assert_eq!(days, [TODAY - 30]);
}

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

#[test]
fn deleting_a_customer_removes_its_range_rows_only() {
    let f = setup();
    let date = TODAY - 1;
    for sensor in [A, C, D] {
        f.store_day(
            sensor,
            date,
            vec![block("10.1.0.0/24", 1, 1, false)],
            &["10.1.0.0/24"],
            NOW,
        );
        f.late(sensor, &[(date, 0)], &[(date, "10.2.0.0/24")]);
    }
    f.store
        .ignore_dai_range(CUSTOMER, net("10.1.0.0/24"), "alice", NOW)
        .unwrap();
    f.store
        .ignore_dai_range(OTHER, net("10.1.0.0/24"), "bob", NOW)
        .unwrap();
    // C moves to OTHER's node: its unit rows are OTHER's now.
    change_node(&f, "c", OTHER);
    let c_day = f.day_row(C, date);
    let d_day = f.day_row(D, date);
    let of = |family: &str, customer: u32| -> Vec<RawRow> {
        f.rows(family)
            .into_iter()
            .filter(|(key, _)| key.starts_with(&customer_key(customer)))
            .collect()
    };
    let other_rows: Vec<Vec<RawRow>> = [
        super::super::DAI_RANGE_BLOCKS,
        super::super::DAI_RANGE_SUBNETS,
        super::super::DAI_RANGE_IGNORES,
    ]
    .iter()
    .map(|family| of(family, OTHER))
    .collect();
    assert!(other_rows.iter().all(|rows| !rows.is_empty()));

    f.store.delete_dai_customer(CUSTOMER, &[]).unwrap();
    assert_eq!(f.day_row(A, date), None);
    assert_eq!(f.day_row(C, date), c_day);
    assert_eq!(f.day_row(D, date), d_day);
    for family in [
        super::super::DAI_RANGE_BLOCKS,
        super::super::DAI_RANGE_SUBNETS,
        super::super::DAI_RANGE_IGNORES,
    ] {
        assert_eq!(of(family, CUSTOMER), Vec::<RawRow>::new(), "{family}");
    }
    assert_eq!(
        [
            super::super::DAI_RANGE_BLOCKS,
            super::super::DAI_RANGE_SUBNETS,
            super::super::DAI_RANGE_IGNORES,
        ]
        .iter()
        .map(|family| of(family, OTHER))
        .collect::<Vec<_>>(),
        other_rows
    );
    let after = f.dump();
    f.store.delete_dai_customer(CUSTOMER, &[]).unwrap();
    assert_eq!(f.dump(), after);
}
