use std::net::IpAddr;

use review_protocol::types::{
    CounterpartScope, GroupByUnit, Measure, RawEventKind, TimeSeriesTypeRef,
};
use tempfile::TempDir;

use super::*;
use crate::test::{DbGuard, acquire_db_permit};
use crate::{
    Agent, AgentKind, AgentStatus, HostNetworkGroup, Iterable, NewTimeSeriesGenerationPolicy, Node,
    NodeProfile, OwnedNetwork, SlotSize, Store, TimeSeriesGenerationPolicyUpdate, WindowSize,
    event::NetworkType, sensor_name, time_series_types,
};

const NS: i64 = 1_000_000_000;
/// "12:00", a 5-minute boundary: 1,700,000,100 is a multiple of 300.
const NOON: i64 = 1_700_000_100 * NS;
const CUSTOMER: u32 = 1;
const OTHER_CUSTOMER: u32 = 2;
/// A customer with no node.
const EMPTY_CUSTOMER: u32 = 3;
const A: &str = "piglet.a.example";
const B: &str = "piglet.b.example";
const C: &str = "piglet.c.example";
/// The sensor of [`OTHER_CUSTOMER`].
const D: &str = "piglet.d.example";
/// The name of a node of [`CUSTOMER`] that carries no sensor agent.
const NOT_A_SENSOR: &str = "piglet.e.example";
/// The column families of the DAI configuration tables.
const FAMILIES: [&str; 6] = [
    super::super::DAI_CUSTOMER_SETTINGS,
    super::super::DAI_RELAY_SITES,
    super::super::DAI_SENSOR_SITES,
    super::super::DAI_SENSOR_STATE,
    super::super::DAI_SITE_POLICY_GUARD,
    super::super::DAI_SITES,
];

/// Returns the time `minutes` and `seconds` after [`NOON`].
fn at(minutes: i64, seconds: i64) -> i64 {
    NOON + (minutes * 60 + seconds) * NS
}

/// A store whose nodes give [`CUSTOMER`] the sensors [`A`], [`B`] and
/// [`C`] and [`OTHER_CUSTOMER`] the sensor [`D`]; [`CUSTOMER`] also has a
/// node `e.example` without a sensor agent.
struct Fixture {
    store: Store,
    _permit: DbGuard<'static>,
    _dirs: (TempDir, TempDir),
}

impl Fixture {
    fn dai(&self) -> Dai<'_> {
        self.store.states.dai()
    }

    fn db(&self) -> &OptimisticTransactionDB {
        self.store.states.db()
    }

    /// Returns every row of the DAI configuration families and of the
    /// policy table, to compare before and after a refusal.
    fn dump(&self) -> Vec<Vec<RawRow>> {
        let txn = self.db().transaction();
        FAMILIES
            .iter()
            .chain(&[super::super::TIME_SERIES_GENERATION_POLICY])
            .map(|name| {
                let map = Map::open(self.db(), name).unwrap();
                Dai::scan(&map, &txn, &[]).unwrap()
            })
            .collect()
    }

    /// Returns the `dai sensor sites` rows.
    fn history(&self) -> Vec<(String, i64, SensorSite)> {
        let dai = self.dai();
        dai.read(|txn| {
            Dai::scan(&dai.sensor_sites, txn, &[])?
                .into_iter()
                .map(|(key, value)| decode_sensor_site(&key, &value))
                .collect()
        })
        .unwrap()
    }

    fn epochs(&self, sensors: &[&str]) -> Vec<u64> {
        sensors
            .iter()
            .map(|sensor| self.store.dai_sensor_config_epoch(sensor).unwrap())
            .collect()
    }

    fn site_at(&self, sensor: &str, time: i64) -> String {
        self.store
            .dai_sensor_site(CUSTOMER, sensor, time)
            .unwrap()
            .unwrap()
    }

    fn create(&self, name: &str, sensors: &[&str], now: i64) -> Result<String> {
        self.dai().create_site(CUSTOMER, name, &names(sensors), now)
    }

    fn update(&self, token: &str, name: &str, sensors: &[&str], now: i64) -> Result<()> {
        self.dai()
            .update_site(CUSTOMER, token, name, &names(sensors), now)
    }

    fn insert_policy(&self, policy: NewTimeSeriesGenerationPolicy, now: i64) -> Result<u32> {
        self.store
            .time_series_generation_policy_map()
            .insert_with_catalog(policy, time_series_types(), now)
    }
}

fn agent(key: &str, kind: AgentKind) -> Agent {
    let mut agent = Agent::new(0, key.to_string(), kind, AgentStatus::Enabled, None, None).unwrap();
    agent.instance = Some(1);
    agent
}

fn node(name: &str, customer_id: u32, hostname: &str, agents: Vec<Agent>) -> Node {
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
        agents,
        external_services: Vec::new(),
        creation_time: jiff::Timestamp::now(),
    }
}

fn setup() -> Fixture {
    let permit = acquire_db_permit();
    let data = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    let store = Store::new(data.path(), backup.path(), None).unwrap();
    for (name, customer, sensor) in [
        ("a", CUSTOMER, true),
        ("b", CUSTOMER, true),
        ("c", CUSTOMER, true),
        ("d", OTHER_CUSTOMER, true),
        ("e", CUSTOMER, false),
    ] {
        let agents = if sensor {
            vec![agent("piglet", AgentKind::Sensor)]
        } else {
            vec![agent("crusher", AgentKind::TimeSeriesGenerator)]
        };
        store
            .node_map()
            .put(&node(name, customer, &format!("{name}.example"), agents))
            .unwrap();
    }
    Fixture {
        store,
        _permit: permit,
        _dirs: (data, backup),
    }
}

fn names(sensors: &[&str]) -> Vec<String> {
    sensors.iter().map(ToString::to_string).collect()
}

fn dai_error(error: &anyhow::Error) -> &DaiConfigError {
    error
        .downcast_ref::<DaiConfigError>()
        .unwrap_or_else(|| panic!("not a DAI configuration error: {error:#}"))
}

fn policy_error(error: &anyhow::Error) -> &TimeSeriesGenerationPolicyError {
    error
        .downcast_ref::<TimeSeriesGenerationPolicyError>()
        .unwrap_or_else(|| panic!("not a time series generation policy error: {error:#}"))
}

fn settings_update(enabled: bool) -> DaiSettingsUpdate {
    DaiSettingsUpdate {
        device_account_identification: enabled,
        inactivity_multiplier: 3,
        no_lease_inactivity_secs: 3600,
        evidence_aging_secs: 86_400,
        kerberos_preauth_realms: names(&["EXAMPLE.COM", "CORP.EXAMPLE"]),
    }
}

/// A custom, ungrouped policy of [`CUSTOMER`] reading `sensors`.
fn policy(name: &str, sensors: &[&str]) -> NewTimeSeriesGenerationPolicy {
    NewTimeSeriesGenerationPolicy {
        name: name.to_string(),
        raw_event_kind: RawEventKind::Conn,
        measure: Measure::Count,
        group_by: None,
        group_by_unit: GroupByUnit::Ip,
        counterpart_scope: CounterpartScope::Any,
        slot_size: SlotSize::FifteenMinutes,
        window_size: WindowSize::TwelveHours,
        utc_offset: 0,
        src_ip: None,
        dst_ip: None,
        sensors: names(sensors),
        time_series_type: None,
        customer_id: CUSTOMER,
    }
}

/// A policy of [`CUSTOMER`] made from the first shipped time-series type,
/// reading `sensors`, with an `Intranet` network for it to group by.
fn typed_policy(f: &Fixture, name: &str, sensors: &[&str]) -> NewTimeSeriesGenerationPolicy {
    let networks = f.store.customer_networks_map();
    if networks.get(CUSTOMER).unwrap().is_none() {
        let network = OwnedNetwork {
            name: "intranet".to_string(),
            network_type: NetworkType::Intranet,
            group: HostNetworkGroup::new(
                Vec::new(),
                vec!["10.0.0.0/8".parse().unwrap()],
                Vec::new(),
            ),
        };
        networks.replace(CUSTOMER, 0, vec![network]).unwrap();
    }
    let ts_type = time_series_types().first().unwrap();
    NewTimeSeriesGenerationPolicy {
        name: name.to_string(),
        raw_event_kind: ts_type.raw_event_kind,
        measure: ts_type.measure,
        group_by: Some(ts_type.group_by),
        group_by_unit: ts_type.group_by_unit,
        counterpart_scope: ts_type.counterpart_scope,
        slot_size: ts_type.slot_size,
        window_size: ts_type.window_size,
        utc_offset: 0,
        src_ip: None,
        dst_ip: None,
        sensors: names(sensors),
        time_series_type: Some(TimeSeriesTypeRef {
            id: ts_type.id.to_string(),
            version: ts_type.version,
        }),
        customer_id: CUSTOMER,
    }
}

fn ip(addr: &str) -> IpAddr {
    addr.parse().unwrap()
}

fn relay(server: &str, giaddr: &str, site: &str) -> DaiRelaySite {
    DaiRelaySite {
        dhcp_server: ip(server),
        giaddr: ip(giaddr),
        site: site.to_string(),
    }
}

// ---- Settings ----

#[test]
fn a_customer_without_settings_reads_the_defaults() {
    let f = setup();
    let settings = f.store.dai_settings(CUSTOMER).unwrap();
    assert_eq!(
        settings,
        DaiSettings {
            device_account_identification: false,
            last_enabled_time: None,
            inactivity_multiplier: 2,
            no_lease_inactivity_secs: 24 * 60 * 60,
            evidence_aging_secs: 180 * 24 * 60 * 60,
            kerberos_preauth_realms: Vec::new(),
            revision: 0,
            relay_revision: 0,
        }
    );
    assert_eq!(f.store.dai_sites(CUSTOMER).unwrap(), Vec::new());
    assert!(f.dump().iter().all(Vec::is_empty));
}

#[test]
fn a_settings_write_checks_the_revision_and_ensures_the_default_site() {
    let f = setup();
    let dai = f.dai();
    let before = f.dump();
    let err = dai
        .set_settings(CUSTOMER, 1, &settings_update(false), at(0, 0))
        .unwrap_err();
    assert_eq!(
        dai_error(&err),
        &DaiConfigError::StaleRevision { stored: 0 }
    );
    assert_eq!(f.dump(), before);

    let stored = dai
        .set_settings(CUSTOMER, 0, &settings_update(false), at(0, 0))
        .unwrap();
    assert_eq!(stored.revision, 1);
    assert_eq!(stored.relay_revision, 0);
    assert_eq!(stored.inactivity_multiplier, 3);
    assert_eq!(stored.no_lease_inactivity_secs, 3600);
    assert_eq!(stored.evidence_aging_secs, 86_400);
    assert_eq!(
        stored.kerberos_preauth_realms,
        names(&["EXAMPLE.COM", "CORP.EXAMPLE"])
    );
    assert_eq!(f.store.dai_settings(CUSTOMER).unwrap(), stored);
    let sites = f.store.dai_sites(CUSTOMER).unwrap();
    assert_eq!(sites.len(), 1);
    assert!(sites[0].is_default);
    assert_eq!(sites[0].name, "");
    assert_eq!(sites[0].sensors, Vec::<String>::new());

    // The relay revision is kept by a settings write, and the settings
    // revision by a relay replacement.
    dai.replace_relay_sites(CUSTOMER, 0, &[]).unwrap();
    let before = f.dump();
    let err = dai
        .set_settings(CUSTOMER, 0, &settings_update(false), at(0, 0))
        .unwrap_err();
    assert_eq!(
        dai_error(&err),
        &DaiConfigError::StaleRevision { stored: 1 }
    );
    assert_eq!(f.dump(), before);
    let stored = dai
        .set_settings(CUSTOMER, 1, &settings_update(false), at(0, 0))
        .unwrap();
    assert_eq!((stored.revision, stored.relay_revision), (2, 1));
    assert_eq!(f.store.dai_sites(CUSTOMER).unwrap(), sites);
}

#[test]
fn turning_the_setting_on_records_when_and_turning_it_off_keeps_it() {
    let f = setup();
    let dai = f.dai();
    let on = dai
        .set_settings(CUSTOMER, 0, &settings_update(true), at(1, 0))
        .unwrap();
    assert_eq!(on.last_enabled_time, Some(at(1, 0)));
    let still_on = dai
        .set_settings(CUSTOMER, 1, &settings_update(true), at(2, 0))
        .unwrap();
    assert_eq!(still_on.last_enabled_time, Some(at(1, 0)));
    let off = dai
        .set_settings(CUSTOMER, 2, &settings_update(false), at(3, 0))
        .unwrap();
    assert!(!off.device_account_identification);
    assert_eq!(off.last_enabled_time, Some(at(1, 0)));
    let again = dai
        .set_settings(CUSTOMER, 3, &settings_update(true), at(4, 0))
        .unwrap();
    assert_eq!(again.last_enabled_time, Some(at(4, 0)));
}

/// A change of a settings update.
type Change = fn(&mut DaiSettingsUpdate);

#[test]
fn out_of_range_settings_are_refused() {
    let f = setup();
    let before = f.dump();
    let cases: [(Change, &str); 5] = [
        (|u| u.inactivity_multiplier = 0, "inactivity_multiplier"),
        (
            |u| u.no_lease_inactivity_secs = 0,
            "no_lease_inactivity_secs",
        ),
        (|u| u.evidence_aging_secs = 0, "evidence_aging_secs"),
        (
            |u| u.kerberos_preauth_realms.push(String::new()),
            "kerberos_preauth_realms",
        ),
        (
            |u| u.kerberos_preauth_realms = vec![String::new()],
            "kerberos_preauth_realms",
        ),
    ];
    for (change, field) in cases {
        let mut update = settings_update(true);
        change(&mut update);
        let err = f.store.set_dai_settings(CUSTOMER, 0, &update).unwrap_err();
        assert_eq!(dai_error(&err), &DaiConfigError::InvalidSettings { field });
    }
    assert_eq!(f.dump(), before);
    let mut update = settings_update(true);
    update.inactivity_multiplier = 1;
    update.no_lease_inactivity_secs = 1;
    update.evidence_aging_secs = 1;
    update.kerberos_preauth_realms.clear();
    f.store.set_dai_settings(CUSTOMER, 0, &update).unwrap();
}

// ---- Sites ----

#[test]
fn the_default_site_is_created_once() {
    let f = setup();
    let token = f.store.ensure_default_site(CUSTOMER).unwrap();
    assert_eq!(token.len(), 8);
    assert!(
        token
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    );
    assert_eq!(f.store.ensure_default_site(CUSTOMER).unwrap(), token);
    assert_eq!(
        f.store.dai_sites(CUSTOMER).unwrap(),
        vec![DaiSite {
            token: token.clone(),
            name: String::new(),
            sensors: Vec::new(),
            is_default: true,
        }]
    );
    // No epoch and no history.
    assert_eq!(f.epochs(&[A, B, C]), [0, 0, 0]);
    assert_eq!(f.history(), Vec::new());
    // Another customer's default site is its own.
    let other = f.store.ensure_default_site(OTHER_CUSTOMER).unwrap();
    assert_eq!(f.store.dai_sites(OTHER_CUSTOMER).unwrap().len(), 1);
    assert_eq!(f.store.dai_sites(CUSTOMER).unwrap().len(), 1);
    assert_eq!(
        f.store
            .dai_site(OTHER_CUSTOMER, &other)
            .unwrap()
            .unwrap()
            .token,
        other
    );
}

#[test]
fn concurrent_calls_leave_one_default_site() {
    let f = setup();
    let tokens: Vec<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| f.store.ensure_default_site(CUSTOMER).unwrap()))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let sites = f.store.dai_sites(CUSTOMER).unwrap();
    assert_eq!(sites.len(), 1);
    assert!(sites[0].is_default);
    assert!(tokens.iter().all(|token| *token == sites[0].token));
}

#[test]
fn a_concurrent_site_write_and_default_site_creation_leave_one_default_site() {
    let f = setup();
    // The site write ensures the default site, and before it commits
    // another call creates one: the write conflicts on the guard and finds
    // that one on its retry.
    set_after_checks_hook(Box::new(|db| {
        Dai::open(db)
            .unwrap()
            .ensure_default_site(CUSTOMER)
            .unwrap();
    }));
    f.create("site", &[A], at(0, 0)).unwrap();
    let defaults = f
        .store
        .dai_sites(CUSTOMER)
        .unwrap()
        .into_iter()
        .filter(|site| site.is_default)
        .count();
    assert_eq!(defaults, 1);
}

#[test]
fn sites_are_created_updated_and_read() {
    let f = setup();
    let token = f.create("Seoul", &[A, B], at(0, 0)).unwrap();
    assert_eq!(token.len(), 8);
    assert!(
        token
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    );
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    assert_ne!(token, default);
    assert_eq!(
        f.store.dai_site(CUSTOMER, &token).unwrap(),
        Some(DaiSite {
            token: token.clone(),
            name: "Seoul".to_string(),
            sensors: names(&[A, B]),
            is_default: false,
        })
    );
    f.update(&token, "Busan", &[B], at(1, 0)).unwrap();
    let site = f.store.dai_site(CUSTOMER, &token).unwrap().unwrap();
    assert_eq!(site.token, token);
    assert_eq!(site.name, "Busan");
    assert_eq!(site.sensors, names(&[B]));
    let sites = f.store.dai_sites(CUSTOMER).unwrap();
    assert_eq!(sites.len(), 2);
    assert!(sites.windows(2).all(|w| w[0].token < w[1].token));
    assert_eq!(f.store.dai_site(CUSTOMER, "missing0").unwrap(), None);
    assert_eq!(f.store.dai_site(OTHER_CUSTOMER, &token).unwrap(), None);
}

#[test]
fn display_names_are_checked() {
    let f = setup();
    let token = f.create("Seoul", &[], at(0, 0)).unwrap();
    let before = f.dump();
    for name in ["", "a|b", "a;b", "a,b", "a\"b"] {
        let err = f.create(name, &[], at(0, 0)).unwrap_err();
        assert_eq!(
            dai_error(&err),
            &DaiConfigError::InvalidSiteName {
                name: name.to_string()
            }
        );
        let err = f.update(&token, name, &[], at(0, 0)).unwrap_err();
        assert!(matches!(
            dai_error(&err),
            DaiConfigError::InvalidSiteName { .. }
        ));
    }
    let err = f.create("Seoul", &[], at(0, 0)).unwrap_err();
    assert_eq!(
        dai_error(&err),
        &DaiConfigError::DuplicateSiteName {
            name: "Seoul".to_string()
        }
    );
    assert_eq!(f.dump(), before);
    // Names are compared exactly as given.
    let other = f.create("seoul", &[], at(0, 0)).unwrap();
    f.create(" Seoul", &[], at(0, 0)).unwrap();
    let err = f.update(&other, "Seoul", &[], at(0, 0)).unwrap_err();
    assert!(matches!(
        dai_error(&err),
        DaiConfigError::DuplicateSiteName { .. }
    ));
    // A site keeps its own name.
    f.update(&token, "Seoul", &[A], at(0, 0)).unwrap();
}

#[test]
fn the_default_site_cannot_be_updated_or_removed() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    let before = f.dump();
    let err = f.update(&default, "named", &[], at(0, 0)).unwrap_err();
    assert_eq!(
        dai_error(&err),
        &DaiConfigError::DefaultSiteFixed {
            token: default.clone()
        }
    );
    let err = f
        .dai()
        .remove_site(CUSTOMER, &default, at(0, 0))
        .unwrap_err();
    assert_eq!(
        dai_error(&err),
        &DaiConfigError::DefaultSiteFixed {
            token: default.clone()
        }
    );
    let err = f.update("unknown0", "named", &[], at(0, 0)).unwrap_err();
    assert_eq!(
        dai_error(&err),
        &DaiConfigError::SiteNotFound {
            token: "unknown0".to_string()
        }
    );
    let err = f
        .dai()
        .remove_site(CUSTOMER, "unknown0", at(0, 0))
        .unwrap_err();
    assert!(matches!(
        dai_error(&err),
        DaiConfigError::SiteNotFound { .. }
    ));
    assert_eq!(f.dump(), before);
}

#[test]
fn a_sensor_is_in_one_site_and_listed_once() {
    let f = setup();
    let seoul = f.create("Seoul", &[A], at(0, 0)).unwrap();
    let busan = f.create("Busan", &[B], at(0, 0)).unwrap();
    let before = f.dump();
    let err = f.create("Daegu", &[C, A], at(0, 0)).unwrap_err();
    assert_eq!(
        dai_error(&err),
        &DaiConfigError::SensorInOtherSite {
            sensor: A.to_string(),
            site_token: seoul.clone(),
            site_name: "Seoul".to_string(),
        }
    );
    let err = f.update(&busan, "Busan", &[B, A], at(0, 0)).unwrap_err();
    assert!(matches!(
        dai_error(&err),
        DaiConfigError::SensorInOtherSite { sensor, .. } if sensor == A
    ));
    let err = f.create("Daegu", &[C, C], at(0, 0)).unwrap_err();
    assert_eq!(
        dai_error(&err),
        &DaiConfigError::DuplicateSensor {
            sensor: C.to_string()
        }
    );
    for name in [D, NOT_A_SENSOR, "c.example", "piglet."] {
        let err = f.create("Daegu", &[C, name], at(0, 0)).unwrap_err();
        assert_eq!(
            dai_error(&err),
            &DaiConfigError::NotSensorOfCustomer {
                sensor: name.to_string()
            }
        );
    }
    assert_eq!(f.dump(), before);
    // A sensor moves between sites by leaving one and joining the other.
    f.update(&seoul, "Seoul", &[], at(0, 0)).unwrap();
    f.update(&busan, "Busan", &[B, A], at(0, 0)).unwrap();
}

#[test]
fn a_site_is_removed_only_when_nothing_puts_a_sensor_in_it() {
    let f = setup();
    let dai = f.dai();
    let site = f.create("Seoul", &[A], at(0, 0)).unwrap();
    let before = f.dump();
    let err = dai.remove_site(CUSTOMER, &site, at(10, 0)).unwrap_err();
    assert_eq!(
        dai_error(&err),
        &DaiConfigError::SiteHasSensors {
            token: site.clone()
        }
    );
    assert_eq!(f.dump(), before);

    // Emptied at 12:12, so A is in the site until 12:15.
    f.update(&site, "Seoul", &[], at(12, 0)).unwrap();
    let before = f.dump();
    for now in [at(12, 0), at(14, 59)] {
        let err = dai.remove_site(CUSTOMER, &site, now).unwrap_err();
        assert_eq!(
            dai_error(&err),
            &DaiConfigError::SiteStillAssigned {
                token: site.clone()
            }
        );
    }
    assert_eq!(f.dump(), before);

    // Named by the relay table.
    dai.replace_relay_sites(CUSTOMER, 0, &[relay("10.0.0.1", "10.1.0.1", &site)])
        .unwrap();
    let before = f.dump();
    let err = dai.remove_site(CUSTOMER, &site, at(15, 0)).unwrap_err();
    assert_eq!(
        dai_error(&err),
        &DaiConfigError::SiteInRelayTable {
            token: site.clone()
        }
    );
    assert_eq!(f.dump(), before);
    dai.replace_relay_sites(CUSTOMER, 1, &[]).unwrap();

    dai.remove_site(CUSTOMER, &site, at(15, 0)).unwrap();
    assert_eq!(f.store.dai_site(CUSTOMER, &site).unwrap(), None);
    assert_eq!(f.store.dai_sites(CUSTOMER).unwrap().len(), 1);
}

#[test]
fn a_site_a_row_in_effect_or_scheduled_names_is_not_removed() {
    let f = setup();
    let dai = f.dai();
    // A joins Seoul at 12:05 and leaves it at 12:10.
    let site = f.create("Seoul", &[A], at(2, 0)).unwrap();
    f.update(&site, "Seoul", &[], at(6, 0)).unwrap();
    // Seen from 12:03, the 12:05 row is a scheduled row naming the site; a
    // non-decreasing clock never shows one with the site empty, since the
    // change that empties it replaces the row, so the earlier time is used
    // to observe it.
    for now in [at(3, 0), at(5, 0), at(9, 59)] {
        let err = dai.remove_site(CUSTOMER, &site, now).unwrap_err();
        assert_eq!(
            dai_error(&err),
            &DaiConfigError::SiteStillAssigned {
                token: site.clone()
            }
        );
    }
    dai.remove_site(CUSTOMER, &site, at(10, 0)).unwrap();

    // A site joined and left before one boundary is not assigned.
    let busan = f.create("Busan", &[B], at(20, 0)).unwrap();
    f.update(&busan, "Busan", &[], at(21, 0)).unwrap();
    dai.remove_site(CUSTOMER, &busan, at(22, 0)).unwrap();
}

#[test]
fn reads_write_nothing() {
    let f = setup();
    assert_eq!(f.store.dai_sites(CUSTOMER).unwrap(), Vec::new());
    assert_eq!(f.store.dai_site(CUSTOMER, "abcdefgh").unwrap(), None);
    f.store.dai_settings(CUSTOMER).unwrap();
    f.store.dai_relay_sites(CUSTOMER).unwrap();
    assert_eq!(f.store.dai_sensor_site(CUSTOMER, A, NOON).unwrap(), None);
    assert_eq!(f.store.dai_sensor_config_epoch(A).unwrap(), 0);
    assert!(f.dump().iter().all(Vec::is_empty));
}

// ---- Sensor site history ----

#[test]
fn a_site_change_takes_effect_at_the_next_boundary() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    let site = f.create("Seoul", &[A], at(2, 0)).unwrap();
    assert_eq!(
        f.history(),
        [(
            A.to_string(),
            at(5, 0),
            SensorSite {
                customer_id: CUSTOMER,
                site: site.clone()
            }
        )]
    );
    for time in [at(0, 0), at(2, 0), at(4, 59)] {
        assert_eq!(f.site_at(A, time), default);
    }
    assert_eq!(f.site_at(A, at(5, 0) - 1), default);
    assert_eq!(f.site_at(A, at(5, 0)), site);
    assert_eq!(f.site_at(A, at(60, 0)), site);
    // A sensor no row names is in the default site.
    assert_eq!(f.site_at(B, at(60, 0)), default);
    // So is a name that is not a sensor of the customer.
    assert_eq!(f.site_at(D, at(60, 0)), default);
}

#[test]
fn a_change_on_a_boundary_takes_effect_at_the_next_one() {
    let f = setup();
    f.create("Seoul", &[A], at(5, 0)).unwrap();
    assert_eq!(f.history()[0].1, at(10, 0));
}

#[test]
fn a_second_change_before_the_boundary_replaces_the_scheduled_row() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    let seoul = f.create("Seoul", &[A], at(2, 0)).unwrap();
    let busan = f.create("Busan", &[], at(2, 0)).unwrap();
    f.update(&seoul, "Seoul", &[], at(3, 0)).unwrap();
    f.update(&busan, "Busan", &[A], at(3, 30)).unwrap();
    assert_eq!(
        f.history(),
        [(
            A.to_string(),
            at(5, 0),
            SensorSite {
                customer_id: CUSTOMER,
                site: busan.clone()
            }
        )]
    );
    assert_eq!(f.site_at(A, at(4, 0)), default);
    assert_eq!(f.site_at(A, at(5, 0)), busan);

    // A change after the boundary adds a row and leaves the effective one.
    f.update(&busan, "Busan", &[], at(6, 0)).unwrap();
    let history = f.history();
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[0],
        (
            A.to_string(),
            at(5, 0),
            SensorSite {
                customer_id: CUSTOMER,
                site: busan.clone()
            }
        )
    );
    assert_eq!(
        history[1],
        (
            A.to_string(),
            at(10, 0),
            SensorSite {
                customer_id: CUSTOMER,
                site: default.clone()
            }
        )
    );
    assert_eq!(f.site_at(A, at(9, 59)), busan);
    assert_eq!(f.site_at(A, at(10, 0)), default);
}

#[test]
fn the_lookup_is_per_customer() {
    let f = setup();
    let other_default = f.store.ensure_default_site(OTHER_CUSTOMER).unwrap();
    f.create("Seoul", &[A], at(2, 0)).unwrap();
    // A's row names CUSTOMER, so OTHER_CUSTOMER sees it in its default site.
    assert_eq!(
        f.store
            .dai_sensor_site(OTHER_CUSTOMER, A, at(10, 0))
            .unwrap(),
        Some(other_default)
    );
    // A customer with no default site has no answer.
    assert_eq!(
        f.store
            .dai_sensor_site(EMPTY_CUSTOMER, A, at(10, 0))
            .unwrap(),
        None
    );
}

// ---- Relay site table ----

#[test]
fn the_relay_table_is_replaced_whole() {
    let f = setup();
    let dai = f.dai();
    let site = f.create("Seoul", &[A], at(0, 0)).unwrap();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    let settings = f.store.dai_settings(CUSTOMER).unwrap();
    assert_eq!(
        f.store.dai_relay_sites(CUSTOMER).unwrap(),
        DaiRelaySites::default()
    );
    let entries = vec![
        relay("::1", "fe80::1", &site),
        relay("10.0.0.1", "10.2.0.1", &default),
        relay("10.0.0.1", "10.1.0.1", &site),
    ];
    assert_eq!(dai.replace_relay_sites(CUSTOMER, 0, &entries).unwrap(), 1);
    let stored = f.store.dai_relay_sites(CUSTOMER).unwrap();
    assert_eq!(stored.revision, 1);
    assert_eq!(
        stored.entries,
        vec![
            relay("10.0.0.1", "10.1.0.1", &site),
            relay("10.0.0.1", "10.2.0.1", &default),
            relay("::1", "fe80::1", &site),
        ]
    );
    let after = f.store.dai_settings(CUSTOMER).unwrap();
    assert_eq!(after.revision, settings.revision);
    assert_eq!(after.relay_revision, 1);

    let entries = vec![relay("10.0.0.2", "10.1.0.1", &default)];
    assert_eq!(dai.replace_relay_sites(CUSTOMER, 1, &entries).unwrap(), 2);
    assert_eq!(f.store.dai_relay_sites(CUSTOMER).unwrap().entries, entries);
    // Another customer's table is its own.
    assert_eq!(
        f.store.dai_relay_sites(OTHER_CUSTOMER).unwrap(),
        DaiRelaySites::default()
    );
}

#[test]
fn invalid_relay_tables_are_refused() {
    let f = setup();
    let dai = f.dai();
    let site = f.create("Seoul", &[], at(0, 0)).unwrap();
    let other = f
        .dai()
        .create_site(OTHER_CUSTOMER, "Other", &[], at(0, 0))
        .unwrap();
    dai.replace_relay_sites(CUSTOMER, 0, &[relay("10.0.0.1", "10.1.0.1", &site)])
        .unwrap();
    let before = f.dump();
    let cases = [
        (
            vec![relay("10.0.0.1", "10.1.0.1", &site)],
            0,
            DaiConfigError::StaleRevision { stored: 1 },
        ),
        (
            vec![relay("10.0.0.1", "0.0.0.0", &site)],
            1,
            DaiConfigError::UnspecifiedGiaddr {
                dhcp_server: ip("10.0.0.1"),
            },
        ),
        (
            vec![relay("::1", "::", &site)],
            1,
            DaiConfigError::UnspecifiedGiaddr {
                dhcp_server: ip("::1"),
            },
        ),
        (
            vec![
                relay("10.0.0.1", "10.1.0.1", &site),
                relay("10.0.0.1", "10.1.0.1", &site),
            ],
            1,
            DaiConfigError::DuplicateRelayEntry {
                dhcp_server: ip("10.0.0.1"),
                giaddr: ip("10.1.0.1"),
            },
        ),
        (
            vec![relay("10.0.0.1", "10.1.0.1", "unknown0")],
            1,
            DaiConfigError::UnknownRelaySite {
                site: "unknown0".to_string(),
            },
        ),
        (
            vec![relay("10.0.0.1", "10.1.0.1", &other)],
            1,
            DaiConfigError::UnknownRelaySite {
                site: other.clone(),
            },
        ),
    ];
    for (entries, revision, expected) in cases {
        let err = dai
            .replace_relay_sites(CUSTOMER, revision, &entries)
            .unwrap_err();
        assert_eq!(dai_error(&err), &expected);
    }
    assert_eq!(f.dump(), before);
}

#[test]
fn a_relay_replacement_creates_the_settings_row() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    f.dai()
        .replace_relay_sites(CUSTOMER, 0, &[relay("10.0.0.1", "10.1.0.1", &default)])
        .unwrap();
    assert_eq!(
        f.store.dai_settings(CUSTOMER).unwrap(),
        DaiSettings {
            relay_revision: 1,
            ..DaiSettings::default()
        }
    );
    // The relay table of a customer with no site is refused for any token.
    let err = f
        .dai()
        .replace_relay_sites(
            EMPTY_CUSTOMER,
            0,
            &[relay("10.0.0.1", "10.1.0.1", &default)],
        )
        .unwrap_err();
    assert!(matches!(
        dai_error(&err),
        DaiConfigError::UnknownRelaySite { .. }
    ));
}

// ---- Configuration epochs ----

#[test]
fn configuration_writes_increment_every_sensor_epoch() {
    let f = setup();
    let dai = f.dai();
    // A write that does not toggle the setting increments nothing.
    dai.set_settings(CUSTOMER, 0, &settings_update(false), at(0, 0))
        .unwrap();
    assert_eq!(f.epochs(&[A, B, C, D, NOT_A_SENSOR]), [0, 0, 0, 0, 0]);
    // Toggling it increments every sensor of the customer.
    dai.set_settings(CUSTOMER, 1, &settings_update(true), at(0, 0))
        .unwrap();
    assert_eq!(f.epochs(&[A, B, C, D, NOT_A_SENSOR]), [1, 1, 1, 0, 0]);
    dai.set_settings(CUSTOMER, 2, &settings_update(true), at(0, 0))
        .unwrap();
    assert_eq!(f.epochs(&[A, B, C]), [1, 1, 1]);
    // A site write.
    let site = f.create("Seoul", &[A], at(0, 0)).unwrap();
    assert_eq!(f.epochs(&[A, B, C, D]), [2, 2, 2, 0]);
    // A relay replacement.
    dai.replace_relay_sites(CUSTOMER, 0, &[]).unwrap();
    assert_eq!(f.epochs(&[A, B, C, D]), [3, 3, 3, 0]);
    // A sensor named only by a site, whose agent is gone from the node
    // table, is still incremented by the write that removes it.
    change_node(&f, "a", |update| update.agents = Vec::new());
    f.update(&site, "Seoul", &[], at(0, 0)).unwrap();
    assert_eq!(f.epochs(&[A, B, C, D]), [4, 4, 4, 0]);
    // A removal.
    dai.remove_site(CUSTOMER, &site, at(10, 0)).unwrap();
    assert_eq!(f.epochs(&[A, B, C, D]), [4, 5, 5, 0]);
}

#[test]
fn the_epoch_never_returns_to_an_earlier_value() {
    let f = setup();
    let dai = f.dai();
    let mut seen = vec![f.epochs(&[A])[0]];
    for (revision, enabled) in [(0, true), (1, false), (2, true), (3, false), (4, true)] {
        dai.set_settings(CUSTOMER, revision, &settings_update(enabled), at(0, 0))
            .unwrap();
        seen.push(f.epochs(&[A])[0]);
    }
    assert_eq!(seen, [0, 1, 2, 3, 4, 5]);
}

#[test]
fn recording_a_changed_hash_increments_the_epoch() {
    let f = setup();
    assert_eq!(f.store.record_dai_sensor_config_hash(A, b"one").unwrap(), 1);
    assert_eq!(f.store.record_dai_sensor_config_hash(A, b"one").unwrap(), 1);
    assert_eq!(f.store.record_dai_sensor_config_hash(A, b"two").unwrap(), 2);
    assert_eq!(f.store.dai_sensor_config_epoch(A).unwrap(), 2);
    assert_eq!(f.store.dai_sensor_config_epoch(B).unwrap(), 0);
    // A configuration write keeps the hash: the same hash is still not a
    // change.
    f.create("Seoul", &[A], at(0, 0)).unwrap();
    assert_eq!(f.store.dai_sensor_config_epoch(A).unwrap(), 3);
    assert_eq!(f.store.record_dai_sensor_config_hash(A, b"two").unwrap(), 3);
    assert_eq!(f.store.record_dai_sensor_config_hash(A, b"").unwrap(), 4);
}

// ---- The site condition ----

#[test]
fn a_customer_with_no_site_accepts_any_policy() {
    let f = setup();
    f.insert_policy(policy("any", &[A, B, D, "unknown"]), at(0, 0))
        .unwrap();
}

#[test]
fn a_policy_spanning_sites_in_effect_is_refused() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    let seoul = f.create("Seoul", &[A], at(0, 0)).unwrap();
    for new in [
        policy("custom", &[B, A, C]),
        typed_policy(&f, "typed", &[B, A, C]),
    ] {
        let before = f.dump();
        let err = f.insert_policy(new, at(10, 0)).unwrap_err();
        let mut expected = vec![
            (seoul.clone(), names(&[A])),
            (default.clone(), names(&[B, C])),
        ];
        expected.sort_unstable();
        assert_eq!(
            policy_error(&err),
            &TimeSeriesGenerationPolicyError::SensorsSpanSites {
                customer_id: CUSTOMER,
                sites: expected,
            }
        );
        assert_eq!(f.dump(), before);
    }
    // One site, or the default site alone, passes.
    f.insert_policy(policy("seoul", &[A]), at(10, 0)).unwrap();
    f.insert_policy(policy("default", &[B, C, "unknown"]), at(10, 0))
        .unwrap();
    f.insert_policy(typed_policy(&f, "typed default", &[B, C]), at(10, 0))
        .unwrap();
}

#[test]
fn a_policy_spanning_the_scheduled_sites_is_refused() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    // At 12:02 A is scheduled to leave the default site at 12:05.
    let seoul = f.create("Seoul", &[A], at(2, 0)).unwrap();
    let err = f.insert_policy(policy("p", &[A, B]), at(3, 0)).unwrap_err();
    let mut expected = vec![(seoul.clone(), names(&[A])), (default, names(&[B]))];
    expected.sort_unstable();
    assert_eq!(
        policy_error(&err),
        &TimeSeriesGenerationPolicyError::SensorsSpanSites {
            customer_id: CUSTOMER,
            sites: expected,
        }
    );
    // A policy over A alone spans nothing either way.
    f.insert_policy(policy("a", &[A]), at(3, 0)).unwrap();
}

#[test]
fn sensors_moved_into_one_site_are_accepted_from_the_boundary() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    let seoul = f.create("Seoul", &[A], at(-10, 0)).unwrap();
    // At 12:02 B joins A.
    f.update(&seoul, "Seoul", &[A, B], at(2, 0)).unwrap();
    // At 12:03 the assignment in effect still puts them in two sites.
    let err = f.insert_policy(policy("p", &[A, B]), at(3, 0)).unwrap_err();
    let mut expected = vec![(seoul.clone(), names(&[A])), (default, names(&[B]))];
    expected.sort_unstable();
    assert_eq!(
        policy_error(&err),
        &TimeSeriesGenerationPolicyError::SensorsSpanSites {
            customer_id: CUSTOMER,
            sites: expected,
        }
    );
    f.insert_policy(policy("p", &[A, B]), at(5, 0)).unwrap();
}

#[test]
fn the_failing_assignment_in_effect_is_reported_when_both_fail() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    let seoul = f.create("Seoul", &[A], at(-10, 0)).unwrap();
    let busan = f.create("Busan", &[], at(-10, 0)).unwrap();
    // In effect: A Seoul, B and C default. Scheduled: A Seoul, B Busan,
    // C default.
    f.update(&busan, "Busan", &[B], at(2, 0)).unwrap();
    let err = f
        .insert_policy(policy("p", &[A, B, C]), at(3, 0))
        .unwrap_err();
    let mut expected = vec![(seoul, names(&[A])), (default, names(&[B, C]))];
    expected.sort_unstable();
    assert_eq!(
        policy_error(&err),
        &TimeSeriesGenerationPolicyError::SensorsSpanSites {
            customer_id: CUSTOMER,
            sites: expected,
        }
    );
}

#[test]
fn a_draft_update_checks_the_site_condition() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    let mut table = f.store.time_series_generation_policy_map();
    let id = f.insert_policy(policy("p", &[A, B]), at(0, 0)).unwrap();
    let seoul = f.create("Seoul", &[C], at(0, 0)).unwrap();
    let old = TimeSeriesGenerationPolicyUpdate::from(table.get_by_id(id).unwrap().unwrap());
    let mut new = old.clone();
    new.sensors = names(&[A, C]);
    let before = f.dump();
    let err = table
        .update_with_catalog(id, &old, &new, time_series_types(), at(10, 0))
        .unwrap_err();
    let mut expected = vec![(seoul, names(&[C])), (default, names(&[A]))];
    expected.sort_unstable();
    assert_eq!(
        policy_error(&err),
        &TimeSeriesGenerationPolicyError::SensorsSpanSites {
            customer_id: CUSTOMER,
            sites: expected,
        }
    );
    assert_eq!(f.dump(), before);
    // Under the scheduled assignment too: at 12:01 C is still in the
    // default site, but scheduled for Seoul.
    let err = table
        .update_with_catalog(id, &old, &new, time_series_types(), at(1, 0))
        .unwrap_err();
    assert!(matches!(
        policy_error(&err),
        TimeSeriesGenerationPolicyError::SensorsSpanSites { .. }
    ));
    new.sensors = names(&[A, B, "piglet.gone.example"]);
    table.update(id, &old, &new).unwrap();

    // A fixed policy's name change is not checked, and neither is the fix.
    table.fix(id).unwrap();
    let old = new.clone();
    let mut renamed = old.clone();
    renamed.name = "renamed".to_string();
    table
        .update_with_catalog(id, &old, &renamed, time_series_types(), at(10, 0))
        .unwrap();
    assert_eq!(table.get_by_id(id).unwrap().unwrap().name, "renamed");
}

#[test]
fn other_policy_checks_come_first() {
    let f = setup();
    f.store.ensure_default_site(CUSTOMER).unwrap();
    f.create("Seoul", &[A], at(-10, 0)).unwrap();
    let mut invalid = policy("p", &[A, B]);
    invalid.utc_offset = 1;
    let err = f.insert_policy(invalid, at(0, 0)).unwrap_err();
    assert!(matches!(
        policy_error(&err),
        TimeSeriesGenerationPolicyError::InvalidUtcOffset { .. }
    ));
    let mut grouped = policy("p", &[A, B]);
    grouped.group_by = Some(review_protocol::types::EndpointRole::Source);
    let err = f.insert_policy(grouped, at(0, 0)).unwrap_err();
    assert!(matches!(
        policy_error(&err),
        TimeSeriesGenerationPolicyError::NoInternalNetwork { .. }
    ));
}

#[test]
fn a_site_write_that_would_split_a_policy_is_refused() {
    let f = setup();
    let first = f.insert_policy(policy("first", &[A, B]), at(0, 0)).unwrap();
    let second = f.insert_policy(policy("second", &[B]), at(0, 0)).unwrap();
    let third = f.insert_policy(policy("third", &[C, A]), at(0, 0)).unwrap();
    let mut other = policy("other customer", &[D, A]);
    other.customer_id = OTHER_CUSTOMER;
    f.insert_policy(other, at(0, 0)).unwrap();
    // A fixed policy counts as much as a draft.
    f.store
        .time_series_generation_policy_map()
        .fix(third)
        .unwrap();
    let seoul = f.create("Seoul", &[], at(0, 0)).unwrap();
    let before = f.dump();
    let err = f.update(&seoul, "Seoul", &[A], at(0, 0)).unwrap_err();
    assert_eq!(
        dai_error(&err),
        &DaiConfigError::PolicyWouldSpanSites {
            policies: vec![(first, "first".to_string()), (third, "third".to_string())],
        }
    );
    let err = f.create("Busan", &[B], at(0, 0)).unwrap_err();
    assert_eq!(
        dai_error(&err),
        &DaiConfigError::PolicyWouldSpanSites {
            policies: vec![(first, "first".to_string())],
        }
    );
    assert_eq!(f.dump(), before);
    assert!(second > first);
    // Moving every sensor of the policies together is accepted.
    f.update(&seoul, "Seoul", &[A, B, C], at(0, 0)).unwrap();
}

#[test]
fn a_policy_save_racing_a_site_change_is_checked_again() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    let seoul = f.create("Seoul", &[], at(0, 0)).unwrap();
    let token = seoul.clone();
    // The policy save checks A and B in the default site; the site change
    // commits before it does.
    set_after_checks_hook(Box::new(move |db| {
        Dai::open(db)
            .unwrap()
            .update_site(CUSTOMER, &token, "Seoul", &names(&[A]), at(10, 0))
            .unwrap();
    }));
    let err = f
        .insert_policy(policy("p", &[A, B]), at(10, 0))
        .unwrap_err();
    let mut expected = vec![(seoul.clone(), names(&[A])), (default, names(&[B]))];
    expected.sort_unstable();
    assert_eq!(
        policy_error(&err),
        &TimeSeriesGenerationPolicyError::SensorsSpanSites {
            customer_id: CUSTOMER,
            sites: expected,
        }
    );
    assert_eq!(
        f.store.time_series_generation_policy_map().count().unwrap(),
        0
    );
    assert_eq!(
        f.store.dai_site(CUSTOMER, &seoul).unwrap().unwrap().sensors,
        names(&[A])
    );
}

#[test]
fn a_site_change_racing_a_policy_save_is_checked_again() {
    let f = setup();
    let seoul = f.create("Seoul", &[], at(0, 0)).unwrap();
    // The site change finds no policy; the policy save commits before it
    // does.
    set_after_checks_hook(Box::new(|db| {
        IndexedTable::<TimeSeriesGenerationPolicy>::open(db)
            .unwrap()
            .insert_with_catalog(policy("p", &[A, B]), time_series_types(), at(10, 0))
            .unwrap();
    }));
    let err = f.update(&seoul, "Seoul", &[A], at(10, 0)).unwrap_err();
    let policies = f
        .store
        .time_series_generation_policy_map()
        .iter(rocksdb::Direction::Forward, None)
        .map(|policy| {
            let policy = policy.unwrap();
            (policy.id, policy.name)
        })
        .collect::<Vec<_>>();
    assert_eq!(policies.len(), 1);
    assert_eq!(
        dai_error(&err),
        &DaiConfigError::PolicyWouldSpanSites { policies }
    );
    assert_eq!(
        f.store.dai_site(CUSTOMER, &seoul).unwrap().unwrap().sensors,
        Vec::<String>::new()
    );
}

#[test]
fn concurrent_policy_saves_and_site_changes_never_span_sites() {
    let f = setup();
    let seoul = f.create("Seoul", &[], at(0, 0)).unwrap();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for i in 0..20 {
                let _ = f.insert_policy(policy(&format!("p{i}"), &[A, B]), at(10, 0));
            }
        });
        scope.spawn(|| {
            for i in 0..20 {
                let sensors: &[&str] = if i % 2 == 0 { &[A] } else { &[] };
                let _ = f.update(&seoul, "Seoul", sensors, at(10, 0));
            }
        });
    });
    let site = f.store.dai_site(CUSTOMER, &seoul).unwrap().unwrap();
    let policies = f.store.time_series_generation_policy_map().count().unwrap();
    assert!(site.sensors.is_empty() || policies == 0);
}

// ---- Sensor names ----

#[test]
fn a_node_with_a_profile_and_a_sensor_agent_has_a_sensor_name() {
    let sensor = node(
        "n",
        CUSTOMER,
        "host.example",
        vec![
            agent("crusher", AgentKind::TimeSeriesGenerator),
            agent("piglet", AgentKind::Sensor),
        ],
    );
    assert_eq!(sensor_name(&sensor).as_deref(), Some("piglet.host.example"));
    let no_sensor = node(
        "n",
        CUSTOMER,
        "host.example",
        vec![agent("crusher", AgentKind::TimeSeriesGenerator)],
    );
    assert_eq!(sensor_name(&no_sensor), None);
    let mut no_profile = sensor.clone();
    no_profile.profile = None;
    no_profile.profile_draft = sensor.profile.clone();
    assert_eq!(sensor_name(&no_profile), None);
    let empty_host = node("n", CUSTOMER, "", vec![agent("piglet", AgentKind::Sensor)]);
    assert_eq!(sensor_name(&empty_host), None);
}

// ---- Customer deletion ----

#[test]
fn deleting_a_customer_removes_its_rows_only() {
    let f = setup();
    let dai = f.dai();
    // CUSTOMER: settings, sites, relay table, history and states.
    dai.set_settings(CUSTOMER, 0, &settings_update(true), at(0, 0))
        .unwrap();
    let seoul = f.create("Seoul", &[A, B], at(0, 0)).unwrap();
    dai.replace_relay_sites(CUSTOMER, 0, &[relay("10.0.0.1", "10.1.0.1", &seoul)])
        .unwrap();
    // A sensor whose agent is already gone from the node table and that is
    // in no site, with a state row.
    dai.record_config_hash("piglet.gone.example", b"h").unwrap();
    // OTHER_CUSTOMER: the same kinds of rows.
    dai.set_settings(OTHER_CUSTOMER, 0, &settings_update(true), at(0, 0))
        .unwrap();
    let other_site = dai
        .create_site(OTHER_CUSTOMER, "Other", &names(&[D]), at(0, 0))
        .unwrap();
    dai.replace_relay_sites(
        OTHER_CUSTOMER,
        0,
        &[relay("10.0.0.1", "10.1.0.1", &other_site)],
    )
    .unwrap();
    // C moves to OTHER_CUSTOMER's node: its history of CUSTOMER goes, its
    // state row stays.
    f.create("Busan", &[C], at(0, 0)).unwrap();
    change_node(&f, "c", |update| {
        update.profile = Some(NodeProfile {
            customer_id: OTHER_CUSTOMER,
            description: String::new(),
            hostname: "c.example".to_string(),
        });
    });
    let other_before = other_rows(&f);
    assert_ne!(other_before, Vec::new());

    f.store
        .delete_dai_customer(CUSTOMER, &names(&["piglet.gone.example"]))
        .unwrap();
    let remaining = f.dump();
    let customer_rows = customer_rows(&f, CUSTOMER);
    assert!(customer_rows.is_empty(), "{customer_rows:?}");
    for sensor in [A, B, "piglet.gone.example"] {
        assert_eq!(f.store.dai_sensor_config_epoch(sensor).unwrap(), 0);
    }
    assert!(f.store.dai_sensor_config_epoch(C).unwrap() > 0);
    assert!(f.store.dai_sensor_config_epoch(D).unwrap() > 0);
    assert_eq!(other_rows(&f), other_before);
    assert_eq!(
        f.store.dai_settings(CUSTOMER).unwrap(),
        DaiSettings::default()
    );
    assert_eq!(f.store.dai_sites(CUSTOMER).unwrap(), Vec::new());
    assert!(
        f.history()
            .iter()
            .all(|(_, _, row)| row.customer_id != CUSTOMER)
    );

    // A repeated call changes nothing.
    f.store
        .delete_dai_customer(CUSTOMER, &names(&["piglet.gone.example"]))
        .unwrap();
    assert_eq!(f.dump(), remaining);
}

#[test]
fn an_interrupted_deletion_is_completed_by_a_repeated_call() {
    let f = setup();
    let dai = f.dai();
    f.create("Seoul", &[A], at(0, 0)).unwrap();
    // A call interrupted after its first transaction leaves the customer's
    // sites.
    dai.delete_sensor_rows(CUSTOMER, &[]).unwrap();
    assert_eq!(f.history(), Vec::new());
    assert_eq!(f.epochs(&[A, B, C]), [0, 0, 0]);
    assert_eq!(f.store.dai_sites(CUSTOMER).unwrap().len(), 2);
    f.store.delete_dai_customer(CUSTOMER, &[]).unwrap();
    assert_eq!(customer_rows(&f, CUSTOMER), Vec::new());
    assert!(f.dump().iter().all(Vec::is_empty));
}

/// Applies `change` to the node named `name`.
fn change_node(f: &Fixture, name: &str, change: impl FnOnce(&mut crate::NodeUpdate)) {
    let mut nodes = f.store.node_map();
    let node = nodes
        .iter(rocksdb::Direction::Forward, None)
        .map(Result::unwrap)
        .find(|node| node.name == name)
        .unwrap();
    let old = crate::NodeUpdate::from(node.clone());
    let mut new = crate::NodeUpdate::from(node.clone());
    change(&mut new);
    nodes.update(node.id, &old, &new).unwrap();
}

/// Returns the rows of [`OTHER_CUSTOMER`] and of its sensors' state.
fn other_rows(f: &Fixture) -> Vec<(usize, RawRow)> {
    let dump = f.dump();
    let mut rows = Vec::new();
    for (i, family) in dump.into_iter().enumerate().take(FAMILIES.len()) {
        for (key, value) in family {
            let ours = match FAMILIES[i] {
                super::super::DAI_SENSOR_SITES => {
                    decode_sensor_site(&key, &value).unwrap().2.customer_id == OTHER_CUSTOMER
                }
                super::super::DAI_SENSOR_STATE => {
                    key.as_ref() == sensor_key(C) || key.as_ref() == sensor_key(D)
                }
                _ => key.starts_with(&customer_key(OTHER_CUSTOMER)),
            };
            if ours {
                rows.push((i, (key, value)));
            }
        }
    }
    rows
}

/// Returns the rows of `customer_id` and of the state of its sensors
/// [`A`] and [`B`].
fn customer_rows(f: &Fixture, customer_id: u32) -> Vec<(usize, RawRow)> {
    let dump = f.dump();
    let mut rows = Vec::new();
    for (i, family) in dump.into_iter().enumerate().take(FAMILIES.len()) {
        for (key, value) in family {
            let ours = match FAMILIES[i] {
                super::super::DAI_SENSOR_SITES => {
                    decode_sensor_site(&key, &value).unwrap().2.customer_id == customer_id
                }
                super::super::DAI_SENSOR_STATE => {
                    key.as_ref() == sensor_key(A) || key.as_ref() == sensor_key(B)
                }
                _ => key.starts_with(&customer_key(customer_id)),
            };
            if ours {
                rows.push((i, (key, value)));
            }
        }
    }
    rows
}

// ---- Encoding ----

#[test]
fn next_boundary_is_strictly_after() {
    let minute = 60 * NS;
    assert_eq!(next_boundary(2 * minute).unwrap(), FIVE_MINUTES);
    assert_eq!(next_boundary(0).unwrap(), FIVE_MINUTES);
    assert_eq!(next_boundary(FIVE_MINUTES).unwrap(), 2 * FIVE_MINUTES);
    assert_eq!(next_boundary(-1).unwrap(), 0);
    assert_eq!(next_boundary(at(2, 0)).unwrap(), at(5, 0));
    assert_eq!(next_boundary(at(5, 0)).unwrap(), at(10, 0));
    assert!(next_boundary(i64::MAX).is_err());
}

#[test]
fn site_tokens_are_eight_lowercase_alphanumerics() {
    for _ in 0..100 {
        let token = new_site_token(|_| false);
        assert_eq!(token.len(), SITE_TOKEN_LEN);
        assert!(
            token
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        );
    }
}

#[test]
fn keys_order_by_their_components() {
    assert!(sensor_site_key("a", -1) < sensor_site_key("a", 0));
    assert!(sensor_site_key("a", i64::MAX) < sensor_site_key("a\u{1}", i64::MIN));
    assert!(site_key(1, "zzzzzzzz") < site_key(2, "aaaaaaaa"));
    let ipv4 = ip("10.0.0.1");
    let ipv6 = ip("::1");
    let key = relay_key(7, ipv6, ipv4);
    let entry = decode_relay(&key, &super::super::serialize(&"site").unwrap()).unwrap();
    assert_eq!(entry.dhcp_server, ipv6);
    assert_eq!(entry.giaddr, ipv4);
    assert!(relay_key(7, ipv4, ipv6) < key);
    assert!(key.starts_with(&customer_key(7)));
    // A prefix read by sensor name covers that sensor's rows only.
    assert!(!sensor_site_key("ab", 0).starts_with(&sensor_key("a")));
    assert!(sensor_site_key("a", 0).starts_with(&sensor_key("a")));
}
