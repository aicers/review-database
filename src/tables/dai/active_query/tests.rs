use std::sync::{Arc, Barrier};

use review_protocol::types::DaiObservationKind;
use tempfile::TempDir;
use uuid::Uuid;

use super::*;
use crate::{
    CustomerDataDeletionService, CustomerDataDeletionServiceResult, CustomerDataDeletionStatus,
    DaiImportOutcome, DaiImportRow, DaiPageDirection, DaiPageRequest, DaiResolveItem,
    DaiResolveWhen, DaiSubjectKind, HostNetworkGroup, OwnedNetwork, Store,
    event::NetworkType,
    tables::dai::{
        SensorState,
        cursor::{CursorRow, pair_key},
        device::{BindingRow, Identifier, binding_key},
        sensor_key,
    },
    test::{DbGuard, acquire_db_permit},
};

const CUSTOMER: u32 = 1;
const NOW: i64 = 1_700_000_000 * 1_000_000_000;
const HOUR: i64 = DAY / 24;

struct Fixture {
    store: Store,
    site: String,
    _dirs: (TempDir, TempDir),
    _permit: DbGuard<'static>,
}

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}
fn net(value: &str) -> IpNet {
    value.parse().unwrap()
}

impl Fixture {
    fn new() -> Self {
        let permit = acquire_db_permit();
        let data = tempfile::tempdir().unwrap();
        let backup = tempfile::tempdir().unwrap();
        let store = Store::new(data.path(), backup.path(), None).unwrap();
        let site = store.ensure_default_site(CUSTOMER).unwrap();
        Self {
            store,
            site,
            _dirs: (data, backup),
            _permit: permit,
        }
    }

    fn dai(&self) -> Dai<'_> {
        self.store.states.dai()
    }

    fn put<T: Serialize>(&self, map: &Map<'_>, key: &[u8], row: &T) {
        self.dai()
            .write(|txn| Dai::put_row(txn, map, key, row))
            .unwrap();
    }

    fn rows(&self, map: &Map<'_>) -> Vec<super::super::RawRow> {
        Dai::scan(map, &self.store.states.db().snapshot(), &[]).unwrap()
    }

    fn settings(&self, enabled: bool) {
        self.put(
            &self.dai().settings,
            &customer_key(CUSTOMER),
            &DaiSettings {
                device_account_identification: enabled,
                ..DaiSettings::default()
            },
        );
    }

    fn internal(&self, ranges: &[&str]) {
        self.store
            .customer_networks_map()
            .replace(
                CUSTOMER,
                1,
                vec![OwnedNetwork {
                    name: "internal".into(),
                    network_type: NetworkType::Intranet,
                    group: HostNetworkGroup::new(
                        Vec::new(),
                        ranges.iter().map(|s| net(s)).collect(),
                        Vec::new(),
                    ),
                }],
            )
            .unwrap();
    }

    fn ready(&self) {
        self.settings(true);
        self.internal(&["10.0.0.0/8", "fd00::/8"]);
        self.store
            .set_dai_active_query_settings(CUSTOMER, 0, true, &[])
            .unwrap();
        self.store
            .set_dai_active_query_site(
                CUSTOMER,
                &self.site,
                0,
                &[net("10.0.0.0/16"), net("fd00::/64")],
                &[ip("10.0.0.53")],
                20,
            )
            .unwrap();
    }

    fn activity(&self, address: &str, first: i64, last: i64) {
        self.put(
            &self.dai().ip_activity,
            &address_key(CUSTOMER, &self.site, ip(address)),
            &ActivityRow {
                first_seen: first,
                last_seen: last,
            },
        );
    }

    fn targets(&self, now: i64) -> Vec<IpAddr> {
        self.store
            .dai_active_query_targets(CUSTOMER, &self.site, now, 100)
            .unwrap()
    }

    fn send(&self, target: &str, dns: Option<&str>) -> bool {
        self.store
            .dai_active_query_send_allowed(CUSTOMER, &self.site, ip(target), dns.map(ip))
            .unwrap()
    }

    fn deleting(&self, statuses: &[CustomerDataDeletionStatus]) {
        let map = Map::open(
            self.store.states.db(),
            crate::tables::CUSTOMER_DELETION_JOBS,
        )
        .unwrap();
        let results: Vec<_> = statuses
            .iter()
            .map(|status| CustomerDataDeletionServiceResult {
                service: CustomerDataDeletionService::Review,
                host_fqdns: Vec::new(),
                status: *status,
                requested_at: NOW,
                completed_at: None,
                error: None,
            })
            .collect();
        // The deletion table's stored layout, including all empty payload lists.
        self.put(
            &map,
            &CUSTOMER.to_be_bytes(),
            &(
                results,
                Vec::<String>::new(),
                Vec::<String>::new(),
                Vec::<Uuid>::new(),
            ),
        );
    }

    fn round(&self, time: i64, results: &[DaiActiveQueryRound]) {
        self.store
            .store_dai_active_round(CUSTOMER, &self.site, time, results)
            .unwrap();
    }

    fn binding(&self, address: &str, start: i64, end: i64) {
        self.put(
            &self.dai().bindings,
            &binding_key(CUSTOMER, &self.site, ip(address), start),
            &BindingRow {
                end: Some(end),
                device: Uuid::nil(),
                evidence_kind: 1,
                evidence_identifier: Identifier::mac("02:00:00:00:00:01"),
                server_id: None,
                last_strong: start,
                inactivity: end - start,
                end_estimated: false,
            },
        );
    }
}

fn round(address: &str, ptr: DaiActiveQueryResult<Vec<String>>) -> DaiActiveQueryRound {
    DaiActiveQueryRound {
        ip: ip(address),
        ptr,
        nbns: DaiActiveQueryResult::NotSent,
        mdns: DaiActiveQueryResult::NotSent,
        ssdp: DaiActiveQueryResult::NotSent,
    }
}

fn named(address: &str, name: &str) -> DaiActiveQueryRound {
    round(address, DaiActiveQueryResult::Value(vec![name.to_owned()]))
}

fn assert_error<T: std::fmt::Debug>(result: Result<T>, expected: &DaiActiveQueryError) {
    assert_eq!(
        result
            .unwrap_err()
            .downcast_ref::<DaiActiveQueryError>()
            .unwrap(),
        expected
    );
}

fn assert_empty<T: std::fmt::Debug>(rows: &[T]) {
    assert_eq!(rows.len(), 0, "{rows:?}");
}

#[test]
fn settings_defaults_revisions_normalization_and_caps() {
    let f = Fixture::new();
    assert_eq!(
        f.store.dai_active_query_settings(CUSTOMER).unwrap(),
        DaiActiveQuerySettings::default()
    );
    assert_empty(&f.store.dai_active_query_sites(999).unwrap());
    assert_eq!(
        f.store.dai_active_query_sites(CUSTOMER).unwrap(),
        vec![DaiActiveQuerySite::absent(&f.site)]
    );
    let stored = f
        .store
        .set_dai_active_query_settings(
            CUSTOMER,
            0,
            true,
            &[net("10.1.2.3/8"), net("10.0.0.0/8"), net("fd00::1/64")],
        )
        .unwrap();
    assert_eq!(stored.revision, 1);
    assert_eq!(
        stored.excluded_ranges,
        vec![net("10.0.0.0/8"), net("fd00::/64")]
    );
    assert_error(
        f.store
            .set_dai_active_query_settings(CUSTOMER, 0, false, &[]),
        &DaiActiveQueryError::StaleRevision { stored: 1 },
    );
    let cap: Vec<_> = (0..257)
        .map(|n| IpNet::new(IpAddr::V4(n.into()), 32).unwrap())
        .collect();
    assert_error(
        f.store
            .set_dai_active_query_settings(CUSTOMER, 1, false, &cap),
        &DaiActiveQueryError::InvalidSetting {
            field: "excluded_ranges",
        },
    );
    assert_eq!(f.store.dai_active_query_settings(CUSTOMER).unwrap(), stored);
    let many_duplicates = vec![net("10.1.2.3/8"); 300];
    assert_eq!(
        f.store
            .set_dai_active_query_settings(CUSTOMER, 1, true, &many_duplicates)
            .unwrap()
            .excluded_ranges
            .len(),
        1
    );
    assert_eq!(
        f.store
            .set_dai_active_query_settings(CUSTOMER, 2, false, &cap[..256])
            .unwrap()
            .excluded_ranges
            .len(),
        256
    );
    let empty = f
        .store
        .set_dai_active_query_settings(CUSTOMER, 3, false, &[])
        .unwrap();
    assert_eq!(empty.revision, 4);
    assert_empty(&empty.excluded_ranges);
}

#[test]
fn site_validations_are_atomic_and_name_the_offending_field() {
    let f = Fixture::new();
    let store = &f.store;
    let set = |revision, ranges: &[IpNet], dns: &[IpAddr], rate| {
        store.set_dai_active_query_site(CUSTOMER, &f.site, revision, ranges, dns, rate)
    };
    assert_error(
        store.set_dai_active_query_site(CUSTOMER, "missing", 0, &[], &[], 20),
        &DaiActiveQueryError::SiteNotFound {
            token: "missing".into(),
        },
    );
    let ranges = [net("10.0.0.45/24"), net("10.0.0.0/24"), net("fd00::15/64")];
    let stored = set(
        0,
        &ranges,
        &[
            ip("10.0.0.2"),
            ip("fd00::1"),
            ip("10.0.0.2"),
            ip("10.0.0.1"),
        ],
        100,
    )
    .unwrap();
    assert_eq!(stored.query_ranges, [net("10.0.0.0/24"), net("fd00::/64")]);
    assert_eq!(
        stored.dns_servers,
        [ip("10.0.0.2"), ip("fd00::1"), ip("10.0.0.1")]
    );
    assert_eq!(stored.revision, 1);
    assert_error(
        set(0, &[], &[], 20),
        &DaiActiveQueryError::StaleRevision { stored: 1 },
    );
    for range in ["0.0.0.0/0", "::/0"] {
        assert_error(
            set(1, &[net(range)], &[], 20),
            &DaiActiveQueryError::InvalidSetting {
                field: "query_ranges",
            },
        );
    }
    let many: Vec<_> = (0..65)
        .map(|n| IpNet::new(IpAddr::V4(n.into()), 32).unwrap())
        .collect();
    assert_error(
        set(1, &many, &[], 20),
        &DaiActiveQueryError::InvalidSetting {
            field: "query_ranges",
        },
    );
    assert_eq!(set(1, &many[..64], &[], 20).unwrap().query_ranges.len(), 64);
    // Restore the prior state for the independent validation refusals.
    f.put(
        &f.dai().active_query_sites,
        &site_key(CUSTOMER, &f.site),
        &stored,
    );
    for rate in [0, 101] {
        assert_error(
            set(1, &ranges, &[], rate),
            &DaiActiveQueryError::InvalidSetting { field: "rate" },
        );
    }
    let too_many: Vec<_> = (1..=5).map(|n| IpAddr::from([10, 0, 0, n])).collect();
    assert_error(
        set(1, &ranges, &too_many, 20),
        &DaiActiveQueryError::InvalidSetting {
            field: "dns_servers",
        },
    );
    for address in ["10.1.0.1", "fd01::1"] {
        assert_error(
            set(1, &ranges, &[ip(address)], 20),
            &DaiActiveQueryError::InvalidSetting {
                field: "dns_servers",
            },
        );
    }
    for (range, address) in [
        ("0.0.0.0/8", "0.1.2.3"),
        ("127.0.0.0/8", "127.0.0.2"),
        ("224.0.0.0/4", "239.1.1.1"),
        ("240.0.0.0/4", "255.255.255.255"),
        ("::/64", "::"),
        ("::/64", "::1"),
        ("ff00::/8", "ff02::1"),
    ] {
        assert_error(
            set(1, &[net(range)], &[ip(address)], 20),
            &DaiActiveQueryError::InvalidSetting {
                field: "dns_servers",
            },
        );
    }
    assert_eq!(store.dai_active_query_sites(CUSTOMER).unwrap(), [stored]);
    let empty = set(1, &[], &[], 1).unwrap();
    assert_eq!(empty.revision, 2);
    assert_eq!(empty.rate, 1);
}

#[test]
fn global_overlaps_reveal_only_narrower_ranges_and_dns_must_belong_to_this_site() {
    let f = Fixture::new();
    let other = f.store.ensure_default_site(2).unwrap();
    let dns_error = || {
        f.store.set_dai_active_query_site(
            CUSTOMER,
            &f.site,
            0,
            &[net("10.1.0.0/16")],
            &[ip("10.2.0.1")],
            20,
        )
    };
    assert_error(
        dns_error(),
        &DaiActiveQueryError::InvalidSetting {
            field: "dns_servers",
        },
    );
    f.store
        .set_dai_active_query_site(
            2,
            &other,
            0,
            &[net("10.2.0.0/16"), net("fd00::/64")],
            &[],
            20,
        )
        .unwrap();
    assert_error(
        dns_error(),
        &DaiActiveQueryError::InvalidSetting {
            field: "dns_servers",
        },
    );
    let expected = DaiActiveQueryError::RangesOverlap {
        ranges: vec![net("10.2.0.0/16"), net("fd00::/80")],
    };
    assert_error(
        f.store.set_dai_active_query_site(
            CUSTOMER,
            &f.site,
            0,
            &[net("10.0.0.0/8"), net("fd00::/80")],
            &[],
            20,
        ),
        &expected,
    );
    assert_eq!(
        f.store.dai_active_query_sites(CUSTOMER).unwrap()[0].revision,
        0
    );
    let second = f.store.create_dai_site(2, "second", &[]).unwrap();
    assert_error(
        f.store
            .set_dai_active_query_site(2, &second, 0, &[net("10.2.3.0/24")], &[], 20),
        &DaiActiveQueryError::RangesOverlap {
            ranges: vec![net("10.2.3.0/24")],
        },
    );
    f.store
        .set_dai_active_query_site(CUSTOMER, &f.site, 0, &[net("10.3.0.0/16")], &[], 20)
        .unwrap();
}

#[test]
fn simultaneous_overlapping_site_writes_cannot_both_commit() {
    let f = Fixture::new();
    let other = f.store.ensure_default_site(2).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            ACTIVE_QUERY_RANGES_SCANNED
                .with(|hook| *hook.borrow_mut() = Some(Arc::clone(&barrier)));
            f.store
                .set_dai_active_query_site(CUSTOMER, &f.site, 0, &[net("10.0.0.0/16")], &[], 20)
        });
        let second = scope.spawn(|| {
            ACTIVE_QUERY_RANGES_SCANNED
                .with(|hook| *hook.borrow_mut() = Some(Arc::clone(&barrier)));
            f.store
                .set_dai_active_query_site(2, &other, 0, &[net("10.0.1.0/24")], &[], 20)
        });
        let results = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        let err = results.into_iter().find_map(Result::err).unwrap();
        assert_eq!(
            err.downcast_ref::<DaiActiveQueryError>(),
            Some(&DaiActiveQueryError::RangesOverlap {
                ranges: vec![net("10.0.1.0/24")]
            })
        );
    });
}

#[test]
fn enabled_sites_targets_and_send_check_follow_enable_flags_and_deletion_state() {
    let f = Fixture::new();
    f.ready();
    f.activity("10.0.0.1", NOW - HOUR, NOW);
    let check = |expected| {
        assert_eq!(f.send("10.0.0.1", Some("10.0.0.53")), expected);
        assert_eq!(!f.targets(NOW).is_empty(), expected);
        assert_eq!(
            !f.store.dai_active_query_sites_enabled().unwrap().is_empty(),
            expected
        );
    };
    check(true); // No deletion job row is allowed.
    f.settings(false);
    check(false);
    f.settings(true);
    check(true);
    f.store
        .set_dai_active_query_settings(CUSTOMER, 1, false, &[])
        .unwrap();
    check(false);
    f.store
        .set_dai_active_query_settings(CUSTOMER, 2, true, &[])
        .unwrap();
    check(true);
    for status in [
        CustomerDataDeletionStatus::InProgress,
        CustomerDataDeletionStatus::Failed,
    ] {
        f.deleting(&[CustomerDataDeletionStatus::Succeeded, status]);
        check(false);
    }
    f.deleting(&[CustomerDataDeletionStatus::Succeeded]);
    check(true);
    f.deleting(&[]);
    check(true);
    f.store
        .set_dai_active_query_site(CUSTOMER, &f.site, 1, &[], &[], 20)
        .unwrap();
    check(false);
    let enabled = f.store.dai_active_query_sites_enabled().unwrap();
    assert_empty(&enabled);
}

#[test]
fn send_check_requires_every_network_condition_and_reads_missing_rows_as_defaults() {
    let f = Fixture::new();
    assert!(!f.send("10.0.0.1", None));
    f.ready();
    assert!(f.send("10.0.0.1", None));
    assert!(f.send("fd00::1", Some("10.0.0.53")));
    assert!(!f.send("10.1.0.1", None));
    assert!(!f.send("10.0.0.1", Some("10.0.0.54")));
    assert!(
        !f.store
            .dai_active_query_send_allowed(CUSTOMER, "missing", ip("10.0.0.1"), None)
            .unwrap()
    );
    f.store
        .set_dai_active_query_settings(CUSTOMER, 1, true, &[net("10.0.0.0/24")])
        .unwrap();
    assert!(!f.send("10.0.0.1", None));
    f.store
        .set_dai_active_query_settings(CUSTOMER, 2, true, &[])
        .unwrap();
    // Simulate old or damaged configuration to verify the send-time range check independently.
    let mut site = f.store.dai_active_query_sites(CUSTOMER).unwrap().remove(0);
    site.dns_servers.push(ip("10.2.0.53"));
    f.put(
        &f.dai().active_query_sites,
        &site_key(CUSTOMER, &f.site),
        &site,
    );
    assert!(!f.send("10.0.0.1", Some("10.2.0.53")));
    f.internal(&["10.2.0.0/16"]);
    assert!(!f.send("10.0.0.1", None));
    let networks = Map::open(f.store.states.db(), crate::tables::CUSTOMER_NETWORKS).unwrap();
    f.dai()
        .write(|txn| Dai::delete_row(txn, &networks, &CUSTOMER.to_be_bytes()))
        .unwrap();
    assert!(!f.send("10.0.0.1", None));
    f.internal(&["10.0.0.0/8", "fd00::/8"]);
    for (map, key) in [
        (&f.dai().settings, customer_key(CUSTOMER)),
        (&f.dai().active_query_settings, customer_key(CUSTOMER)),
        (&f.dai().active_query_sites, site_key(CUSTOMER, &f.site)),
    ] {
        let previous = f.rows(map);
        assert!(f.send("10.0.0.1", None));
        f.dai()
            .write(|txn| Dai::delete_row(txn, map, &key))
            .unwrap();
        assert!(!f.send("10.0.0.1", None));
        f.dai()
            .db
            .put_cf(map.cf, &key, &previous.first().unwrap().1)
            .unwrap();
    }
}

#[test]
fn targets_exclude_bindings_fixed_ips_external_excluded_and_nonqueryable_addresses() {
    let f = Fixture::new();
    f.ready();
    for addr in [
        "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7",
        "10.0.0.8", "10.1.0.1", "fd00::1",
    ] {
        f.activity(addr, NOW - DAY, NOW - HOUR);
    }
    f.binding("10.0.0.2", NOW - DAY, NOW + DAY);
    // A binding opened after last activity still excludes the address at now.
    f.binding("10.0.0.3", NOW - HOUR / 2, NOW + DAY);
    // A binding only at last activity also excludes it.
    f.binding("10.0.0.4", NOW - DAY, NOW - HOUR / 2);
    // An expired binding before last activity does not exclude the address.
    f.binding("10.0.0.5", NOW - 2 * DAY, NOW - DAY);
    f.put(
        &f.dai().fixed_ips,
        &address_key(CUSTOMER, &f.site, ip("10.0.0.6")),
        &Uuid::nil(),
    );
    f.store
        .set_dai_active_query_settings(CUSTOMER, 1, true, &[net("10.0.0.7/32")])
        .unwrap();
    f.internal(&["10.0.0.0/24"]); // IPv6 is outside internal ranges.
    f.activity("10.0.0.8", NOW - 32 * DAY, NOW - 30 * DAY - 1);
    f.activity("10.0.0.9", NOW, NOW + 1);
    assert_eq!(f.targets(NOW), [ip("10.0.0.1"), ip("10.0.0.5")]);
    f.activity("10.0.0.10", NOW - 31 * DAY, NOW - 30 * DAY);
    assert!(f.targets(NOW).contains(&ip("10.0.0.10")));
    // Give all prohibited address categories query and internal ranges.
    let bad = [
        "0.1.2.3",
        "127.1.2.3",
        "224.0.0.1",
        "239.1.1.1",
        "240.1.1.1",
        "255.255.255.255",
        "::",
        "::1",
        "ff02::1",
    ];
    let ranges: Vec<_> = bad
        .iter()
        .map(|a| IpNet::new(ip(a), if ip(a).is_ipv4() { 32 } else { 128 }).unwrap())
        .collect();
    f.store
        .set_dai_active_query_site(CUSTOMER, &f.site, 1, &ranges, &[], 20)
        .unwrap();
    f.internal(&["0.0.0.0/0", "::/0"]);
    for address in bad {
        f.activity(address, NOW - DAY, NOW);
    }
    assert_empty(&f.targets(NOW));
}

#[test]
fn targets_respect_both_requery_boundaries_and_complete_ordering() {
    let f = Fixture::new();
    f.ready();
    for n in 1..=8 {
        f.activity(&format!("10.0.0.{n}"), NOW - 10 * DAY, NOW - HOUR);
    }
    f.activity("10.0.0.2", NOW - DAY, NOW);
    f.round(NOW - DAY + 1, &[named("10.0.0.3", "recent")]);
    f.round(
        NOW - 7 * DAY + 1,
        &[round("10.0.0.4", DaiActiveQueryResult::NoResponse)],
    );
    f.round(NOW - DAY, &[named("10.0.0.5", "at boundary")]);
    f.round(
        NOW - 7 * DAY,
        &[round("10.0.0.6", DaiActiveQueryResult::NoName)],
    );
    f.round(
        NOW - 8 * DAY,
        &[named("10.0.0.7", "old"), named("10.0.0.8", "old")],
    );
    f.activity("10.0.0.8", NOW - 10 * DAY, NOW);
    let expected = [2, 1, 8, 7, 6, 5].map(|n| IpAddr::from([10, 0, 0, n]));
    assert_eq!(f.targets(NOW), expected);
    assert_eq!(
        f.store
            .dai_active_query_targets(CUSTOMER, &f.site, NOW, 3)
            .unwrap(),
        expected[..3]
    );
    assert_empty(
        &f.store
            .dai_active_query_targets(CUSTOMER, &f.site, NOW, 0)
            .unwrap(),
    );
    assert_empty(
        &f.store
            .dai_active_query_targets(CUSTOMER, "missing", NOW, 100)
            .unwrap(),
    );
}

#[test]
fn targets_reuse_compared_time_with_fifteen_minute_boundary_and_absent_time() {
    let f = Fixture::new();
    f.ready();
    let sensor = "piglet.active.example";
    // Listed sensors suffice for CustomerView, without a node or real device.
    let token = f.site.clone();
    let mut site_value: super::super::SiteValue = f
        .dai()
        .read(|txn| Dai::get_row(txn, &f.dai().sites, &site_key(CUSTOMER, &token)))
        .unwrap()
        .unwrap();
    site_value.sensors.push(sensor.into());
    f.put(&f.dai().sites, &site_key(CUSTOMER, &token), &site_value);
    let first = NOW - HOUR;
    let threshold = first + ACTIVE_QUERY_RESOLUTION_DELAY;
    f.put(
        &f.dai().ip_activity,
        &address_key(CUSTOMER, &token, ip("10.0.0.1")),
        &ActivityRow {
            first_seen: first,
            last_seen: NOW,
        },
    );
    let targets = || {
        f.store
            .dai_active_query_targets(CUSTOMER, &token, NOW, 10)
            .unwrap()
    };
    assert_eq!(targets(), [ip("10.0.0.1")]);
    f.put(
        &f.dai().sensor_state,
        &sensor_key(sensor),
        &SensorState {
            last_record_time: Some(NOW),
            ..SensorState::default()
        },
    );
    for time in [threshold - 1, threshold, threshold + 1] {
        for kind in [
            DaiObservationKind::DhcpLease,
            DaiObservationKind::Kerberos,
            DaiObservationKind::Ntlm,
        ] {
            f.put(
                &f.dai().cursors,
                &pair_key(sensor, kind),
                &CursorRow {
                    cursor: time,
                    read_floor: time,
                    first_send_finished: true,
                    ..CursorRow::default()
                },
            );
        }
        assert_eq!(!targets().is_empty(), time >= threshold);
    }
}

#[test]
fn intervals_extend_at_48_hours_split_afterwards_and_preserve_transitions() {
    let f = Fixture::new();
    f.ready();
    let a = named("10.0.0.1", "A");
    let b = named("10.0.0.1", "B");
    f.round(NOW, std::slice::from_ref(&a));
    f.round(NOW + 2 * DAY, std::slice::from_ref(&a));
    let dai = f.dai();
    let rows = f.rows(&dai.active_answers);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        super::super::super::deserialize::<ActiveQueryAnswer>(&rows[0].1)
            .unwrap()
            .last_seen,
        NOW + 2 * DAY
    );
    f.round(NOW + 4 * DAY + 1, std::slice::from_ref(&a));
    f.round(NOW + 4 * DAY + 2, &[b]);
    f.round(NOW + 4 * DAY + 3, &[a]);
    assert_eq!(f.rows(&dai.active_answers).len(), 4);
    let other = named("10.0.0.2", "A");
    f.round(NOW, std::slice::from_ref(&other));
    f.round(NOW + 3 * DAY, &[other]);
    assert_eq!(
        Dai::scan(
            &dai.active_answers,
            &dai.db.snapshot(),
            &address_key(CUSTOMER, &f.site, ip("10.0.0.2"))
        )
        .unwrap()
        .len(),
        2
    );
    let values: Vec<_> = f
        .rows(&dai.active_answers)
        .iter()
        .map(|(_, v)| {
            super::super::super::deserialize::<ActiveQueryAnswer>(v)
                .unwrap()
                .value
        })
        .collect();
    assert!(
        values.contains(&DaiActiveQueryResult::Value(ActiveQueryValue::Ptr(vec![
            "A".into()
        ])))
    );
}

#[test]
fn rounds_store_each_kind_and_count_only_sent_and_value_results() {
    let f = Fixture::new();
    f.ready();
    let results = DaiActiveQueryRound {
        ip: ip("10.0.0.1"),
        ptr: DaiActiveQueryResult::Value(vec!["MiXeD".into(), "a".into()]),
        nbns: DaiActiveQueryResult::NoName,
        mdns: DaiActiveQueryResult::NoResponse,
        ssdp: DaiActiveQueryResult::NotSent,
    };
    f.round(NOW, std::slice::from_ref(&results));
    f.round(NOW + 1, &[results]);
    let dai = f.dai();
    assert_eq!(f.rows(&dai.active_answers).len(), 3);
    let state: ActiveQueryIp = Dai::value_in(
        &dai.db.snapshot(),
        &dai.active_query_ips,
        &address_key(CUSTOMER, &f.site, ip("10.0.0.1")),
    )
    .unwrap()
    .unwrap();
    assert!(state.had_answer);
    assert_eq!(state.last_query, NOW + 1);
    assert_eq!(
        state.results[0],
        DaiActiveQueryResult::Value(ActiveQueryValue::Ptr(vec!["MiXeD".into(), "a".into()]))
    );
    let daily = f.rows(&dai.active_query_daily);
    assert_eq!(daily.len(), 3);
    for (kind, (_, value)) in daily.iter().enumerate() {
        let counts: ActiveQueryDaily = super::super::super::deserialize(value).unwrap();
        assert_eq!(counts.sent, 2);
        assert_eq!(counts.with_value, if kind == 0 { 2 } else { 0 });
    }
    f.round(
        NOW + DAY,
        &[round("10.0.0.1", DaiActiveQueryResult::NoName)],
    );
    let state: ActiveQueryIp = Dai::value_in(
        &dai.db.snapshot(),
        &dai.active_query_ips,
        &address_key(CUSTOMER, &f.site, ip("10.0.0.1")),
    )
    .unwrap()
    .unwrap();
    assert!(!state.had_answer);
    assert_eq!(f.rows(&dai.active_query_daily).len(), 4);
}

#[test]
// Keep the atomicity comparisons together for all rejected and ignored results.
#[allow(clippy::too_many_lines)]
fn dropped_rounds_and_oversized_answers_change_nothing() {
    let f = Fixture::new();
    f.ready();
    f.round(NOW, &[named("10.0.0.1", "A")]);
    let dai = f.dai();
    let before = || {
        [
            f.rows(&dai.active_answers),
            f.rows(&dai.active_query_ips),
            f.rows(&dai.active_query_daily),
        ]
    };
    let original = before();
    f.round(NOW - 1, &[named("10.0.0.1", "B")]);
    f.round(
        NOW + 1,
        &[
            round("10.0.0.1", DaiActiveQueryResult::NotSent),
            round("10.0.0.2", DaiActiveQueryResult::NotSent),
            named("10.1.0.1", "outside"),
        ],
    );
    assert_eq!(before(), original);
    let mut oversized = named("10.0.0.2", "A");
    for (field, invalid_round) in [
        (
            "ptr",
            DaiActiveQueryRound {
                ptr: DaiActiveQueryResult::Value(vec!["name".into(); 9]),
                ..oversized.clone()
            },
        ),
        (
            "mdns",
            DaiActiveQueryRound {
                mdns: DaiActiveQueryResult::Value(DaiActiveQueryMdns {
                    host_name: None,
                    service_types: vec!["service".into(); 33],
                }),
                ..oversized.clone()
            },
        ),
        (
            "ssdp",
            DaiActiveQueryRound {
                ssdp: DaiActiveQueryResult::Value(vec![
                    DaiActiveQuerySsdp {
                        st: String::new(),
                        usn: String::new(),
                        server: String::new()
                    };
                    17
                ]),
                ..oversized.clone()
            },
        ),
    ] {
        assert_error(
            f.store.store_dai_active_round(
                CUSTOMER,
                &f.site,
                NOW + 1,
                &[oversized.clone(), invalid_round],
            ),
            &DaiActiveQueryError::InvalidSetting { field },
        );
        assert_eq!(before(), original);
    }
    oversized.ptr = DaiActiveQueryResult::Value(vec!["name".into(); 8]);
    oversized.mdns = DaiActiveQueryResult::Value(DaiActiveQueryMdns {
        host_name: Some("host".into()),
        service_types: vec!["service".into(); 32],
    });
    oversized.ssdp = DaiActiveQueryResult::Value(vec![
        DaiActiveQuerySsdp {
            st: "st".into(),
            usn: "usn".into(),
            server: "server".into()
        };
        16
    ]);
    oversized.nbns = DaiActiveQueryResult::Value(DaiActiveQueryNbns {
        computer_name: Some("name".into()),
        workgroup_or_domain: Some("domain".into()),
        mac: Some([2, 0, 0, 0, 0, 1]),
    });
    f.round(NOW + 1, &[oversized]);
    assert_eq!(f.rows(&dai.active_answers).len(), 5);
    f.store
        .set_dai_active_query_site(CUSTOMER, &f.site, 1, &[], &[], 20)
        .unwrap();
    let original = before();
    f.round(NOW + 2, &[named("10.0.0.1", "changed")]);
    assert_eq!(before(), original);
    f.store
        .store_dai_active_round(
            CUSTOMER,
            "missing",
            NOW + 3,
            &[named("10.0.0.1", "changed")],
        )
        .unwrap();
    assert_eq!(before(), original);
}

#[test]
fn range_changes_filter_inflight_rounds_and_release_old_ranges() {
    let f = Fixture::new();
    f.ready();
    f.round(NOW, &[named("10.0.0.1", "old")]);
    let dai = f.dai();
    let old_key = address_key(CUSTOMER, &f.site, ip("10.0.0.1"));
    let previous = dai.db.get_cf(dai.active_query_ips.cf, &old_key).unwrap();
    f.store
        .set_dai_active_query_site(CUSTOMER, &f.site, 1, &[net("10.1.0.0/16")], &[], 20)
        .unwrap();
    f.round(
        NOW + 1,
        &[named("10.0.0.1", "discarded"), named("10.1.0.1", "kept")],
    );
    assert_eq!(
        dai.db.get_cf(dai.active_query_ips.cf, &old_key).unwrap(),
        previous
    );
    assert_eq!(f.rows(&dai.active_answers).len(), 2);
    assert_eq!(f.rows(&dai.active_query_ips).len(), 2);
    let counts = f.rows(&dai.active_query_daily);
    let counts: ActiveQueryDaily =
        super::super::super::deserialize(&counts.first().unwrap().1).unwrap();
    assert_eq!(counts.sent, 2);
    assert_eq!(counts.with_value, 2);

    let other = f.store.ensure_default_site(2).unwrap();
    f.store
        .set_dai_active_query_site(2, &other, 0, &[net("10.0.0.0/16")], &[], 20)
        .unwrap();
    f.store
        .set_dai_active_query_site(CUSTOMER, &f.site, 2, &[], &[], 20)
        .unwrap();
    f.store
        .set_dai_active_query_site(
            2,
            &other,
            1,
            &[net("10.0.0.0/16"), net("10.1.0.0/16")],
            &[],
            20,
        )
        .unwrap();
}

#[test]
fn removing_a_site_deletes_only_its_configuration_and_refused_removal_deletes_nothing() {
    let f = Fixture::new();
    f.ready();
    assert!(f.store.remove_dai_site(CUSTOMER, &f.site).is_err());
    assert_eq!(
        f.store.dai_active_query_sites(CUSTOMER).unwrap()[0].revision,
        1
    );
    let token = f.store.create_dai_site(CUSTOMER, "temporary", &[]).unwrap();
    f.store
        .set_dai_active_query_site(CUSTOMER, &token, 0, &[net("10.1.0.0/16")], &[], 20)
        .unwrap();
    f.store
        .store_dai_active_round(CUSTOMER, &token, NOW, &[named("10.1.0.1", "A")])
        .unwrap();
    f.store.remove_dai_site(CUSTOMER, &token).unwrap();
    let dai = f.dai();
    assert!(
        Dai::value_in::<DaiActiveQuerySite>(
            &dai.db.snapshot(),
            &dai.active_query_sites,
            &site_key(CUSTOMER, &token)
        )
        .unwrap()
        .is_none()
    );
    for map in [
        &dai.active_answers,
        &dai.active_query_ips,
        &dai.active_query_daily,
    ] {
        assert_eq!(f.rows(map).len(), 1);
    }
    f.store
        .store_dai_active_round(CUSTOMER, &token, NOW + 1, &[named("10.1.0.1", "B")])
        .unwrap();
    assert_eq!(f.rows(&dai.active_answers).len(), 1);
    f.store.apply_dai_retention(NOW + 180 * DAY).unwrap();
    assert_eq!(f.rows(&dai.active_answers).len(), 1);
    assert_eq!(f.rows(&dai.active_query_ips).len(), 1);
    assert_empty(&f.rows(&dai.active_query_daily));
    f.store.apply_dai_retention(NOW + 180 * DAY + 1).unwrap();
    assert_empty(&f.rows(&dai.active_answers));
    assert_empty(&f.rows(&dai.active_query_ips));
}

#[test]
fn retention_boundaries_and_customer_deletion_preserve_other_customers_and_guard() {
    let f = Fixture::new();
    f.ready();
    let dai = f.dai();
    for (addr, time) in [
        ("10.0.0.1", NOW - 180 * DAY - 1),
        ("10.0.0.2", NOW - 180 * DAY),
        ("10.0.0.3", NOW - 30 * DAY),
        ("10.0.0.4", NOW - 31 * DAY),
    ] {
        f.round(time, &[named(addr, "A")]);
    }
    let other = f.store.ensure_default_site(2).unwrap();
    f.store
        .set_dai_active_query_settings(2, 0, true, &[])
        .unwrap();
    f.store
        .set_dai_active_query_site(2, &other, 0, &[net("10.2.0.0/16")], &[], 20)
        .unwrap();
    f.store
        .store_dai_active_round(2, &other, NOW, &[named("10.2.0.1", "other")])
        .unwrap();
    f.store
        .set_dai_active_query_settings(CUSTOMER, 1, false, &[])
        .unwrap();
    f.store.apply_dai_retention(NOW).unwrap();
    assert_eq!(f.rows(&dai.active_answers).len(), 4);
    assert_eq!(f.rows(&dai.active_query_ips).len(), 4);
    assert_eq!(f.rows(&dai.active_query_daily).len(), 2);
    let guard = f.rows(&dai.active_query_range_guard);
    let maps = [
        &dai.active_query_settings,
        &dai.active_query_sites,
        &dai.active_answers,
        &dai.active_query_ips,
        &dai.active_query_daily,
    ];
    let other_before: Vec<_> = maps
        .iter()
        .map(|m| Dai::scan(m, &dai.db.snapshot(), &customer_key(2)).unwrap())
        .collect();
    f.store.delete_dai_customer(CUSTOMER, &[]).unwrap();
    for (map, other_rows) in maps.iter().zip(other_before) {
        assert_empty(&Dai::scan(map, &dai.db.snapshot(), &customer_key(CUSTOMER)).unwrap());
        assert_eq!(
            Dai::scan(map, &dai.db.snapshot(), &customer_key(2)).unwrap(),
            other_rows
        );
    }
    assert_eq!(f.rows(&dai.active_query_range_guard), guard);
}

#[test]
fn enabled_sites_keep_customer_token_order_and_send_parameters() {
    let f = Fixture::new();
    f.ready();
    let second = f.store.create_dai_site(CUSTOMER, "second", &[]).unwrap();
    let other = f.store.ensure_default_site(2).unwrap();
    let _unconfigured = f
        .store
        .create_dai_site(CUSTOMER, "unconfigured", &[])
        .unwrap();
    f.store
        .set_dai_active_query_site(
            CUSTOMER,
            &second,
            0,
            &[net("10.2.0.0/16")],
            &[ip("10.2.0.54"), ip("10.2.0.53")],
            7,
        )
        .unwrap();
    f.store
        .set_dai_active_query_site(2, &other, 0, &[net("10.3.0.0/16")], &[], 100)
        .unwrap();
    f.store
        .set_dai_active_query_settings(2, 0, true, &[])
        .unwrap();
    f.put(
        &f.dai().settings,
        &customer_key(2),
        &DaiSettings {
            device_account_identification: true,
            ..DaiSettings::default()
        },
    );
    let mut expected = vec![
        DaiActiveQueryEnabledSite {
            customer_id: CUSTOMER,
            token: f.site.clone(),
            rate: 20,
            dns_servers: vec![ip("10.0.0.53")],
        },
        DaiActiveQueryEnabledSite {
            customer_id: CUSTOMER,
            token: second,
            rate: 7,
            dns_servers: vec![ip("10.2.0.54"), ip("10.2.0.53")],
        },
        DaiActiveQueryEnabledSite {
            customer_id: 2,
            token: other,
            rate: 100,
            dns_servers: Vec::new(),
        },
    ];
    expected.sort_unstable_by(|a, b| (a.customer_id, &a.token).cmp(&(b.customer_id, &b.token)));
    assert_eq!(f.store.dai_active_query_sites_enabled().unwrap(), expected);
}

#[test]
fn daily_counts_accumulate_multiple_ips_and_concurrent_rounds() {
    let f = Fixture::new();
    f.ready();
    f.round(NOW, &[named("10.0.0.1", "a"), named("10.0.0.2", "b")]);
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        let one = scope.spawn(|| {
            barrier.wait();
            f.round(NOW + 1, &[named("10.0.0.3", "c")]);
        });
        let two = scope.spawn(|| {
            barrier.wait();
            f.round(
                NOW + 1,
                &[round("10.0.0.4", DaiActiveQueryResult::NoResponse)],
            );
        });
        one.join().unwrap();
        two.join().unwrap();
    });
    let rows = f.rows(&f.dai().active_query_daily);
    assert_eq!(rows.len(), 1);
    let count: ActiveQueryDaily =
        super::super::super::deserialize(&rows.first().unwrap().1).unwrap();
    assert_eq!(count.sent, 4);
    assert_eq!(count.with_value, 3);
    assert_eq!(f.rows(&f.dai().active_query_ips).len(), 4);
}

#[test]
fn each_kind_keeps_its_interval_across_not_sent_and_compares_values_exactly() {
    let f = Fixture::new();
    f.ready();
    let original = DaiActiveQueryRound {
        ip: ip("10.0.0.1"),
        ptr: DaiActiveQueryResult::Value(vec!["B".into(), "a".into()]),
        nbns: DaiActiveQueryResult::Value(DaiActiveQueryNbns {
            computer_name: Some("Computer".into()),
            workgroup_or_domain: None,
            mac: Some([2, 0, 0, 0, 0, 1]),
        }),
        mdns: DaiActiveQueryResult::Value(DaiActiveQueryMdns {
            host_name: None,
            service_types: vec!["_http._tcp".into(), "_ssh._tcp".into()],
        }),
        ssdp: DaiActiveQueryResult::Value(vec![DaiActiveQuerySsdp {
            st: "ST".into(),
            usn: "USN".into(),
            server: "SERVER".into(),
        }]),
    };
    f.round(NOW, std::slice::from_ref(&original));
    // Sending only PTR must leave every other kind's interval untouched.
    f.round(NOW + DAY, &[named("10.0.0.1", "interim")]);
    f.round(NOW + 2 * DAY, std::slice::from_ref(&original));
    let dai = f.dai();
    for (kind, expected) in ACTIVE_QUERY_KINDS.into_iter().zip(original.results()) {
        let prefix = active_query_answer_prefix(CUSTOMER, &f.site, original.ip, kind.number());
        let rows = Dai::scan(&dai.active_answers, &dai.db.snapshot(), &prefix).unwrap();
        assert_eq!(
            rows.len(),
            if kind == DaiActiveQueryKind::Ptr {
                3
            } else {
                1
            }
        );
        let (key, value) = rows.last().unwrap();
        assert_eq!(
            key.as_ref(),
            &active_query_answer_key(
                CUSTOMER,
                &f.site,
                original.ip,
                kind.number(),
                if kind == DaiActiveQueryKind::Ptr {
                    NOW + 2 * DAY
                } else {
                    NOW
                },
            )
        );
        let answer: ActiveQueryAnswer = super::super::super::deserialize(value).unwrap();
        assert_eq!(answer.value, expected);
        assert_eq!(answer.last_seen, NOW + 2 * DAY);
    }
    let mut changed = original.clone();
    changed.ptr = DaiActiveQueryResult::Value(vec!["a".into(), "B".into()]);
    if let DaiActiveQueryResult::Value(value) = &mut changed.nbns {
        value.computer_name = Some("computer".into());
    }
    if let DaiActiveQueryResult::Value(value) = &mut changed.mdns {
        value.service_types.reverse();
    }
    if let DaiActiveQueryResult::Value(value) = &mut changed.ssdp {
        value.first_mut().unwrap().server = "server".into();
    }
    f.round(NOW + 2 * DAY + 1, std::slice::from_ref(&changed));
    assert_eq!(f.rows(&dai.active_answers).len(), 10);
    // A recent PTR query must not keep an unsent kind's old interval open.
    f.round(NOW + 4 * DAY, &[named("10.0.0.1", "recent")]);
    f.round(NOW + 5 * DAY, &[changed]);
    for kind in [
        DaiActiveQueryKind::Nbns,
        DaiActiveQueryKind::Mdns,
        DaiActiveQueryKind::Ssdp,
    ] {
        let prefix = active_query_answer_prefix(CUSTOMER, &f.site, ip("10.0.0.1"), kind.number());
        let rows = Dai::scan(&dai.active_answers, &dai.db.snapshot(), &prefix).unwrap();
        assert_eq!(rows.len(), 3);
    }
}

#[test]
fn daily_counts_use_utc_dates_and_intervals_order_times_across_the_epoch() {
    let f = Fixture::new();
    f.ready();
    let answer = round("10.0.0.1", DaiActiveQueryResult::NoName);
    f.round(-1, std::slice::from_ref(&answer));
    f.round(0, &[answer]);
    f.round(1, &[round("10.0.0.1", DaiActiveQueryResult::NoResponse)]);
    let dai = f.dai();
    let answers = f.rows(&dai.active_answers);
    assert_eq!(answers.len(), 2);
    let (key, value) = answers.first().unwrap();
    assert_eq!(
        key.as_ref(),
        &active_query_answer_key(CUSTOMER, &f.site, ip("10.0.0.1"), 0, -1)
    );
    let answer: ActiveQueryAnswer = super::super::super::deserialize(value).unwrap();
    assert_eq!(answer.value, DaiActiveQueryResult::NoName);
    assert_eq!(answer.last_seen, 0);
    let daily = f.rows(&dai.active_query_daily);
    assert_eq!(daily.len(), 2);
    for ((key, value), (date, sent)) in daily.iter().zip([(-1, 1), (0, 2)]) {
        let mut reader = KeyReader::new(key);
        assert_eq!(reader.u32().unwrap(), CUSTOMER);
        assert_eq!(reader.str().unwrap(), f.site);
        assert_eq!(reader.date().unwrap(), date);
        let counts: ActiveQueryDaily = super::super::super::deserialize(value).unwrap();
        assert_eq!(counts.sent, sent);
        assert_eq!(counts.with_value, 0);
    }
}

#[test]
fn concurrent_rounds_for_one_ip_keep_the_newest_state_and_interval() {
    let f = Fixture::new();
    f.ready();
    f.round(NOW, &[named("10.0.0.1", "same")]);
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        let older = scope.spawn(|| {
            barrier.wait();
            f.round(NOW + 1, &[named("10.0.0.1", "same")]);
        });
        let newer = scope.spawn(|| {
            barrier.wait();
            f.round(NOW + 2, &[named("10.0.0.1", "same")]);
        });
        older.join().unwrap();
        newer.join().unwrap();
    });
    let dai = f.dai();
    let states = f.rows(&dai.active_query_ips);
    assert_eq!(states.len(), 1);
    let state: ActiveQueryIp =
        super::super::super::deserialize(&states.first().unwrap().1).unwrap();
    assert_eq!(state.last_query, NOW + 2);
    assert!(state.had_answer);
    let answers = f.rows(&dai.active_answers);
    assert_eq!(answers.len(), 1);
    let answer: ActiveQueryAnswer =
        super::super::super::deserialize(&answers.first().unwrap().1).unwrap();
    assert_eq!(answer.last_seen, NOW + 2);
    let daily = f.rows(&dai.active_query_daily);
    let count: ActiveQueryDaily =
        super::super::super::deserialize(&daily.first().unwrap().1).unwrap();
    // The older round is either committed first or dropped after the newer round.
    assert!((2..=3).contains(&count.sent));
    assert_eq!(count.with_value, count.sent);
}

#[test]
fn active_answers_leave_devices_names_and_resolution_unchanged() {
    let f = Fixture::new();
    f.ready();
    f.activity("10.0.0.1", NOW - DAY, NOW);
    let imported = f
        .store
        .import_dai_devices(
            CUSTOMER,
            &[DaiImportRow {
                asset_id: "existing-device".into(),
                name: Some("operator name".into()),
                fixed_ips: vec![(f.site.clone(), ip("10.0.0.2"))],
                ..DaiImportRow::default()
            }],
        )
        .unwrap();
    assert!(matches!(
        imported.as_slice(),
        [DaiImportOutcome::Created { .. }]
    ));
    let items = ["10.0.0.1", "10.0.0.2"].map(|address| DaiResolveItem {
        site: Some(f.site.clone()),
        ip: ip(address),
        when: DaiResolveWhen::At(NOW),
    });
    let read = || {
        (
            f.store.dai_resolve(CUSTOMER, &items, true, NOW).unwrap(),
            f.store
                .dai_ip_only_devices(
                    CUSTOMER,
                    &crate::DaiIpDeviceFilter::default(),
                    &DaiPageRequest {
                        from: None,
                        direction: DaiPageDirection::Forward,
                        limit: 10,
                    },
                    NOW,
                )
                .unwrap(),
            f.store
                .dai_devices(
                    CUSTOMER,
                    &crate::DaiDeviceFilter::default(),
                    &DaiPageRequest {
                        from: None,
                        direction: DaiPageDirection::Forward,
                        limit: 10,
                    },
                    NOW,
                )
                .unwrap(),
        )
    };
    let before = read();
    assert_eq!(before.0[0].as_ref().unwrap().kind, DaiSubjectKind::Ip);
    assert_eq!(before.0[1].as_ref().unwrap().kind, DaiSubjectKind::Device);
    assert_eq!(before.1.total, 1);
    assert_eq!(before.2.total, 1);
    let dai = f.dai();
    let passive_rows = || {
        crate::tables::MAP_NAMES
            .into_iter()
            .filter(|name| {
                ![
                    crate::tables::DAI_ACTIVE_ANSWERS,
                    crate::tables::DAI_ACTIVE_QUERY_IPS,
                    crate::tables::DAI_ACTIVE_QUERY_DAILY,
                ]
                .contains(name)
            })
            .map(|name| (name, f.rows(&Map::open(dai.db, name).unwrap())))
            .collect::<Vec<_>>()
    };
    let rows_before = passive_rows();
    f.round(
        NOW,
        &[
            named("10.0.0.1", "new active name"),
            named("10.0.0.2", "replacement active name"),
        ],
    );
    f.round(NOW + 1, &[round("10.0.0.1", DaiActiveQueryResult::NoName)]);
    assert_eq!(f.rows(&dai.active_answers).len(), 3);
    assert_eq!(read(), before);
    assert_eq!(passive_rows(), rows_before);
}

fn ip_state(f: &Fixture, address: &str) -> ActiveQueryIp {
    let dai = f.dai();
    Dai::value_in(
        &dai.db.snapshot(),
        &dai.active_query_ips,
        &address_key(CUSTOMER, &f.site, ip(address)),
    )
    .unwrap()
    .unwrap()
}

fn ptr(name: &str) -> DaiActiveQueryResult<ActiveQueryValue> {
    DaiActiveQueryResult::Value(ActiveQueryValue::Ptr(vec![name.to_owned()]))
}

fn daily_counts(f: &Fixture) -> Vec<ActiveQueryDaily> {
    f.rows(&f.dai().active_query_daily)
        .iter()
        .map(|(_, v)| super::super::super::deserialize(v).unwrap())
        .collect()
}

fn answers(rows: &[super::super::RawRow]) -> Vec<ActiveQueryAnswer> {
    rows.iter()
        .map(|(_, v)| super::super::super::deserialize(v).unwrap())
        .collect()
}

#[test]
fn a_round_at_the_stored_query_time_is_dropped() {
    let f = Fixture::new();
    f.ready();
    let dai = f.dai();
    let stored = || {
        [
            f.rows(&dai.active_answers),
            f.rows(&dai.active_query_ips),
            f.rows(&dai.active_query_daily),
        ]
    };
    f.round(NOW, &[named("10.0.0.1", "A")]);
    let first = stored();
    f.round(NOW, &[named("10.0.0.1", "B")]);
    f.round(NOW, &[named("10.0.0.1", "A")]);
    assert_eq!(stored(), first);
    let answers = answers(&f.rows(&dai.active_answers));
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].value, ptr("A"));
    assert_eq!(answers[0].last_seen, NOW);
    let state = ip_state(&f, "10.0.0.1");
    assert_eq!(state.last_query, NOW);
    assert!(state.had_answer);
    assert_eq!(state.results[0], ptr("A"));
    let daily = daily_counts(&f);
    assert_eq!(daily.len(), 1);
    assert_eq!(daily[0].sent, 1);
    assert_eq!(daily[0].with_value, 1);
}

#[test]
fn rounds_one_nanosecond_apart_open_intervals_and_earlier_rounds_stay_dropped() {
    let f = Fixture::new();
    f.ready();
    f.round(NOW, &[named("10.0.0.1", "A")]);
    f.round(NOW + 1, &[named("10.0.0.1", "B")]);
    f.round(NOW + 2, &[named("10.0.0.1", "A")]);
    let dai = f.dai();
    let rows = f.rows(&dai.active_answers);
    let values: Vec<_> = answers(&rows)
        .into_iter()
        .map(|a| (a.value, a.last_seen))
        .collect();
    assert_eq!(
        values,
        [(ptr("A"), NOW), (ptr("B"), NOW + 1), (ptr("A"), NOW + 2)]
    );
    let states = f.rows(&dai.active_query_ips);
    let daily = f.rows(&dai.active_query_daily);
    f.round(NOW + 1, &[named("10.0.0.1", "C")]);
    assert_eq!(f.rows(&dai.active_answers), rows);
    assert_eq!(f.rows(&dai.active_query_ips), states);
    assert_eq!(f.rows(&dai.active_query_daily), daily);
    assert_eq!(ip_state(&f, "10.0.0.1").last_query, NOW + 2);
    assert_eq!(daily_counts(&f)[0].sent, 3);
}

#[test]
fn a_mixed_round_writes_later_ips_and_drops_an_ip_at_its_stored_time() {
    let f = Fixture::new();
    f.ready();
    f.round(NOW - 1, &[named("10.0.0.2", "A")]);
    f.round(NOW, &[named("10.0.0.1", "A")]);
    f.round(
        NOW,
        &[
            named("10.0.0.1", "B"),
            named("10.0.0.2", "B"),
            named("10.0.0.3", "B"),
        ],
    );
    let equal = ip_state(&f, "10.0.0.1");
    assert_eq!(equal.last_query, NOW);
    assert_eq!(equal.results[0], ptr("A"));
    for address in ["10.0.0.2", "10.0.0.3"] {
        let later = ip_state(&f, address);
        assert_eq!(later.last_query, NOW);
        assert_eq!(later.results[0], ptr("B"));
    }
    let dai = f.dai();
    let per_ip = |address: &str| {
        answers(
            &Dai::scan(
                &dai.active_answers,
                &dai.db.snapshot(),
                &address_key(CUSTOMER, &f.site, ip(address)),
            )
            .unwrap(),
        )
        .into_iter()
        .map(|a| a.value)
        .collect::<Vec<_>>()
    };
    assert_eq!(per_ip("10.0.0.1"), [ptr("A")]);
    assert_eq!(per_ip("10.0.0.2"), [ptr("A"), ptr("B")]);
    assert_eq!(per_ip("10.0.0.3"), [ptr("B")]);
    let daily = daily_counts(&f);
    assert_eq!(daily.len(), 1);
    assert_eq!(daily[0].sent, 4);
    assert_eq!(daily[0].with_value, 4);
}

#[test]
fn two_customers_never_hold_the_same_private_range_at_once() {
    let f = Fixture::new();
    f.ready();
    f.activity("10.0.0.1", NOW - 10 * DAY, NOW - HOUR);
    f.round(NOW - 2 * DAY, &[named("10.0.0.1", "first")]);
    let dai = f.dai();
    let maps = [
        &dai.active_answers,
        &dai.active_query_ips,
        &dai.active_query_daily,
    ];
    let rows_of = |customer: u32| -> Vec<_> {
        maps.iter()
            .map(|m| Dai::scan(m, &dai.db.snapshot(), &customer_key(customer)).unwrap())
            .collect()
    };
    let first = rows_of(CUSTOMER);
    assert_eq!(f.targets(NOW), [ip("10.0.0.1")]);
    let other = f.store.ensure_default_site(2).unwrap();
    f.store
        .set_dai_active_query_settings(2, 0, true, &[])
        .unwrap();
    let same_range = DaiActiveQueryError::RangesOverlap {
        ranges: vec![net("10.0.0.0/16")],
    };
    assert_error(
        f.store
            .set_dai_active_query_site(2, &other, 0, &[net("10.0.0.0/16")], &[], 20),
        &same_range,
    );
    assert_eq!(
        f.store.dai_active_query_sites(2).unwrap(),
        vec![DaiActiveQuerySite::absent(&other)]
    );
    f.store
        .store_dai_active_round(2, &other, NOW, &[named("10.0.0.1", "other")])
        .unwrap();
    for rows in rows_of(2) {
        assert_empty(&rows);
    }
    assert_eq!(rows_of(CUSTOMER), first);
    assert_eq!(f.targets(NOW), [ip("10.0.0.1")]);

    // Once the first customer releases the range, the second takes it with its own rows.
    f.store
        .set_dai_active_query_site(CUSTOMER, &f.site, 1, &[], &[], 20)
        .unwrap();
    f.store
        .set_dai_active_query_site(2, &other, 0, &[net("10.0.0.0/16")], &[], 20)
        .unwrap();
    f.store
        .store_dai_active_round(2, &other, NOW, &[named("10.0.0.1", "other")])
        .unwrap();
    let second = rows_of(2);
    assert_eq!(
        answers(&second[0])
            .into_iter()
            .map(|a| a.value)
            .collect::<Vec<_>>(),
        [ptr("other")]
    );
    assert_eq!(second[1].len(), 1);
    assert_eq!(rows_of(CUSTOMER), first);
    assert_empty(&f.targets(NOW));
    assert_error(
        f.store
            .set_dai_active_query_site(CUSTOMER, &f.site, 2, &[net("10.0.0.0/16")], &[], 20),
        &same_range,
    );
}
