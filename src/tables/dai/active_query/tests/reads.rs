use super::*;
use crate::{
    DaiActiveQuerySiteState, DaiActiveQueryStatus, DaiIpDeviceFilter, DaiSearchMatchKind,
    DaiSearchTarget,
};

impl Fixture {
    fn ip_rows(&self, now: i64) -> Vec<crate::DaiIpDeviceRow> {
        self.store
            .dai_ip_only_devices(
                CUSTOMER,
                &DaiIpDeviceFilter::default(),
                &DaiPageRequest {
                    from: None,
                    direction: DaiPageDirection::Forward,
                    limit: usize::MAX,
                },
                now,
            )
            .unwrap()
            .rows
    }

    fn resolve_at(&self, address: &str, when: DaiResolveWhen, now: i64) -> crate::DaiResolveAnswer {
        self.store
            .dai_resolve(
                CUSTOMER,
                &[DaiResolveItem {
                    site: Some(self.site.clone()),
                    ip: ip(address),
                    when,
                }],
                true,
                now,
            )
            .unwrap()
            .remove(0)
            .unwrap()
    }

    fn site_state(&self, now: i64) -> crate::DaiSiteActiveQuery {
        self.store
            .dai_collection_status(CUSTOMER, now)
            .unwrap()
            .sites
            .into_iter()
            .find(|s| s.site == self.site)
            .unwrap()
            .active_query
    }

    fn history(&self, address: &str) -> Vec<crate::DaiActiveAnswer> {
        self.store
            .dai_active_answers(CUSTOMER, &self.site, ip(address))
            .unwrap()
    }
}

fn ptr_name(answer: &crate::DaiActiveAnswer) -> &str {
    let DaiActiveQueryResult::Value(DaiActiveQueryValue::Ptr(names)) = &answer.value else {
        panic!("expected a PTR value: {answer:?}");
    };
    names.first().unwrap()
}

#[test]
// Exercise the full transition and boundary matrix through all answer reads.
#[allow(clippy::too_many_lines)]
fn validity_shared_by_resolve_ip_rows_and_search() {
    let f = Fixture::new();
    f.ready();
    // A -> B -> A, a timeout between identical values, separated values,
    // and a no-name response cutting a value short.
    for (address, rounds) in [
        (
            "10.0.0.1",
            vec![(0, Some("A")), (10, Some("B")), (20, Some("A"))],
        ),
        (
            "10.0.0.2",
            vec![(0, Some("A")), (10, None), (20, Some("A"))],
        ),
        ("10.0.0.3", vec![(0, Some("A")), (72, Some("A"))]),
        ("10.0.0.4", vec![(0, Some("A"))]),
        ("10.0.0.5", vec![(0, Some("A")), (48, Some("A"))]),
    ] {
        f.activity(address, NOW - DAY, NOW);
        for (hours, value) in rounds {
            f.round(
                NOW + hours * HOUR,
                &[match value {
                    Some(name) => named(address, name),
                    None => round(address, DaiActiveQueryResult::NoResponse),
                }],
            );
        }
    }
    f.round(
        NOW + 10 * HOUR,
        &[round("10.0.0.4", DaiActiveQueryResult::NoName)],
    );
    for (address, offset, expected) in [
        ("10.0.0.1", -1, None),
        ("10.0.0.1", 0, Some("A")),
        ("10.0.0.1", 10 * HOUR - 1, Some("A")),
        ("10.0.0.1", 10 * HOUR, Some("B")),
        ("10.0.0.1", 15 * HOUR, Some("B")),
        ("10.0.0.1", 20 * HOUR, Some("A")),
        ("10.0.0.1", 25 * HOUR, Some("A")),
        ("10.0.0.1", 68 * HOUR, Some("A")),
        ("10.0.0.1", 68 * HOUR + 1, None),
        ("10.0.0.2", 15 * HOUR, Some("A")),
        ("10.0.0.2", 20 * HOUR, Some("A")),
        ("10.0.0.2", 48 * HOUR, Some("A")),
        ("10.0.0.2", 48 * HOUR + 1, Some("A")),
        ("10.0.0.2", 68 * HOUR, Some("A")),
        ("10.0.0.2", 68 * HOUR + 1, None),
        ("10.0.0.3", 48 * HOUR, Some("A")),
        ("10.0.0.3", 48 * HOUR + 1, None),
        ("10.0.0.3", 60 * HOUR, None),
        ("10.0.0.3", 72 * HOUR - 1, None),
        ("10.0.0.3", 72 * HOUR, Some("A")),
        ("10.0.0.4", 10 * HOUR - 1, Some("A")),
        ("10.0.0.4", 10 * HOUR, None),
        ("10.0.0.5", 96 * HOUR, Some("A")),
        ("10.0.0.5", 96 * HOUR + 1, None),
    ] {
        let time = NOW + offset;
        let answer = f.resolve_at(address, DaiResolveWhen::At(time), time);
        assert_eq!(answer.kind, DaiSubjectKind::Ip);
        let active = answer.explanation.unwrap().active_answers;
        assert_eq!(
            active.first().map(ptr_name),
            expected,
            "{address} at {offset}"
        );
        // Before NOW the activity is in the future and therefore not listed.
        if offset < 0 {
            continue;
        }
        let row = f
            .ip_rows(time)
            .into_iter()
            .find(|r| r.ip == ip(address))
            .unwrap();
        assert_eq!(
            row.active_query
                .kinds
                .first()
                .unwrap()
                .answer
                .as_ref()
                .map(ptr_name),
            expected
        );
        let found = f.store.dai_search(CUSTOMER, " a ", time).unwrap();
        assert_eq!(found.matches.iter().any(|m| matches!(&m.target, DaiSearchTarget::IpDevice {ip: target, ..} if *target == ip(address))), expected == Some("A"));
    }
    let history = f.history("10.0.0.5");
    assert_eq!(history.len(), 1);
    assert_eq!(
        (history[0].first_seen, history[0].last_seen),
        (NOW, NOW + 48 * HOUR)
    );
    let window = f.resolve_at(
        "10.0.0.1",
        DaiResolveWhen::Window {
            from: NOW,
            to: NOW + 15 * HOUR,
        },
        NOW + DAY,
    );
    assert_eq!(
        ptr_name(&window.explanation.unwrap().active_answers[0]),
        "B"
    );
}

#[test]
fn ip_status_precedence_and_stored_data_in_every_status() {
    let f = Fixture::new();
    f.ready();
    f.activity("10.0.0.1", NOW - DAY, NOW);
    let check = |status| {
        let row = f.ip_rows(NOW).remove(0).active_query;
        assert_eq!(row.status, status);
        assert_eq!(
            row.kinds.iter().map(|k| k.kind).collect::<Vec<_>>(),
            ACTIVE_QUERY_KINDS
        );
        row
    };
    let row = check(Some(DaiActiveQueryStatus::NotQueriedYet));
    assert!(row.last_query.is_none());
    assert!(
        row.kinds
            .iter()
            .all(|k| k.last_result.is_none() && k.answer.is_none())
    );
    f.round(NOW, &[named("10.0.0.1", "stored")]);
    let stored = check(None);
    assert_eq!(stored.last_query, Some(NOW));
    assert_eq!(ptr_name(stored.kinds[0].answer.as_ref().unwrap()), "stored");
    assert_eq!(
        stored.kinds[1].last_result,
        Some(DaiActiveQueryResult::NotSent)
    );
    let check_stored = |status| {
        let row = check(Some(status));
        assert_eq!(row.last_query, stored.last_query);
        assert_eq!(row.kinds, stored.kinds);
    };
    f.settings(false);
    check_stored(DaiActiveQueryStatus::QueriesOff);
    f.settings(true);
    f.store
        .set_dai_active_query_settings(CUSTOMER, 1, false, &[])
        .unwrap();
    check_stored(DaiActiveQueryStatus::QueriesOff);
    f.store
        .set_dai_active_query_settings(CUSTOMER, 2, true, &[])
        .unwrap();
    f.deleting(&[CustomerDataDeletionStatus::Failed]);
    check_stored(DaiActiveQueryStatus::QueriesOff);
    f.deleting(&[CustomerDataDeletionStatus::Succeeded]);
    f.store
        .set_dai_active_query_site(CUSTOMER, &f.site, 1, &[], &[], 20)
        .unwrap();
    check_stored(DaiActiveQueryStatus::QueriesOff);
    f.dai()
        .write(|txn| {
            txn.delete_cf(f.dai().active_query_sites.cf, site_key(CUSTOMER, &f.site))?;
            Ok(())
        })
        .unwrap();
    check_stored(DaiActiveQueryStatus::QueriesOff);
    f.store
        .set_dai_active_query_site(CUSTOMER, &f.site, 0, &[net("10.0.0.0/16")], &[], 20)
        .unwrap();
    f.store
        .set_dai_active_query_settings(CUSTOMER, 3, true, &[net("10.0.0.1/32")])
        .unwrap();
    check_stored(DaiActiveQueryStatus::NotQueryTarget);
    f.store
        .set_dai_active_query_settings(CUSTOMER, 4, true, &[])
        .unwrap();
    f.internal(&["10.2.0.0/16"]);
    check_stored(DaiActiveQueryStatus::NotQueryTarget);
    f.internal(&["10.0.0.0/8"]);
    f.store
        .set_dai_active_query_site(CUSTOMER, &f.site, 1, &[net("10.1.0.0/16")], &[], 20)
        .unwrap();
    check_stored(DaiActiveQueryStatus::NotQueryTarget);
    f.store
        .set_dai_active_query_site(CUSTOMER, &f.site, 2, &[net("10.0.0.0/16")], &[], 20)
        .unwrap();
    f.put(
        &f.dai().fixed_ips,
        &address_key(CUSTOMER, &f.site, ip("10.0.0.1")),
        &Uuid::nil(),
    );
    check_stored(DaiActiveQueryStatus::NotQueryTarget);
    // Customer-level off takes precedence over target exclusions.
    f.settings(false);
    check_stored(DaiActiveQueryStatus::QueriesOff);
}

#[test]
fn nonqueryable_addresses_are_not_targets_in_ip_reads() {
    let f = Fixture::new();
    f.ready();
    let ranges = [
        "0.0.0.0/8",
        "127.0.0.0/8",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/64",
        "ff00::/8",
    ];
    f.internal(&ranges);
    f.store
        .set_dai_active_query_site(CUSTOMER, &f.site, 1, &ranges.map(net), &[], 20)
        .unwrap();
    for address in [
        "0.1.2.3",
        "127.0.0.2",
        "239.1.1.1",
        "255.255.255.255",
        "::",
        "::1",
        "ff02::1",
    ] {
        f.activity(address, NOW - DAY, NOW);
    }
    let rows = f.ip_rows(NOW);
    assert_eq!(rows.len(), 7);
    assert!(
        rows.iter()
            .all(|r| r.active_query.status == Some(DaiActiveQueryStatus::NotQueryTarget))
    );
    assert_empty(&f.targets(NOW));
}

#[test]
fn history_orders_all_kinds_and_survives_removed_site() {
    let f = Fixture::new();
    f.ready();
    let token = f.store.create_dai_site(CUSTOMER, "temporary", &[]).unwrap();
    f.store
        .set_dai_active_query_site(CUSTOMER, &token, 0, &[net("10.1.0.0/16")], &[], 20)
        .unwrap();
    let mut value = named("10.1.0.1", "A");
    value.nbns = DaiActiveQueryResult::NoName;
    value.mdns = DaiActiveQueryResult::NoResponse;
    value.ssdp = DaiActiveQueryResult::Value(Vec::new());
    f.store
        .store_dai_active_round(CUSTOMER, &token, NOW, &[value])
        .unwrap();
    f.store
        .store_dai_active_round(CUSTOMER, &token, NOW + HOUR, &[named("10.1.0.1", "B")])
        .unwrap();
    f.store.remove_dai_site(CUSTOMER, &token).unwrap();
    let rows = f
        .store
        .dai_active_answers(CUSTOMER, &token, ip("10.1.0.1"))
        .unwrap();
    assert_eq!(
        rows.iter()
            .map(|r| (r.first_seen, r.kind))
            .collect::<Vec<_>>(),
        vec![
            (NOW + HOUR, DaiActiveQueryKind::Ptr),
            (NOW, DaiActiveQueryKind::Ptr),
            (NOW, DaiActiveQueryKind::Nbns),
            (NOW, DaiActiveQueryKind::Mdns),
            (NOW, DaiActiveQueryKind::Ssdp),
        ]
    );
    assert_eq!(rows[2].value, DaiActiveQueryResult::NoName);
    assert_eq!(rows[3].value, DaiActiveQueryResult::NoResponse);
    assert_empty(&f.history("10.0.0.1"));
}

#[test]
fn search_only_valid_names_of_ip_device_rows_and_applies_cap() {
    let f = Fixture::new();
    f.ready();
    let mut value = named("10.0.0.1", "Ptr-Shared");
    value.nbns = DaiActiveQueryResult::Value(DaiActiveQueryNbns {
        computer_name: Some("NbNs-Shared".into()),
        workgroup_or_domain: Some("workgroup-only".into()),
        mac: None,
    });
    value.mdns = DaiActiveQueryResult::Value(DaiActiveQueryMdns {
        host_name: Some("MdNs-Shared".into()),
        service_types: vec!["service-only".into()],
    });
    value.ssdp = DaiActiveQueryResult::Value(vec![DaiActiveQuerySsdp {
        st: "ssdp-only".into(),
        usn: "ssdp-only".into(),
        server: "ssdp-only".into(),
    }]);
    f.activity("10.0.0.1", NOW - DAY, NOW);
    f.round(NOW, &[value]);
    for text in ["pTr-", "NBns-", "mDnS-", " SHARED "] {
        let found = f.store.dai_search(CUSTOMER, text, NOW).unwrap();
        assert_eq!(found.matches.len(), 1);
        assert_eq!(
            found.matches[0].matched,
            DaiSearchMatchKind::ActiveQueryName
        );
    }
    for text in ["workgroup-only", "service-only", "ssdp-only", "", "  "] {
        assert_empty(&f.store.dai_search(CUSTOMER, text, NOW).unwrap().matches);
    }
    assert_empty(
        &f.store
            .dai_search(CUSTOMER, "shared", NOW + 2 * DAY + 1)
            .unwrap()
            .matches,
    );
    f.binding("10.0.0.1", NOW - DAY, NOW + DAY);
    assert_empty(&f.store.dai_search(CUSTOMER, "shared", NOW).unwrap().matches);
    // Activity too old and future activity are also absent from IP device reads.
    for (address, time) in [("10.0.0.2", NOW - 31 * DAY), ("10.0.0.3", NOW + 1)] {
        f.activity(address, time, time);
        f.round(NOW, &[named(address, "shared")]);
    }
    assert_empty(&f.store.dai_search(CUSTOMER, "shared", NOW).unwrap().matches);
    for n in 10..111 {
        let address = format!("10.0.0.{n}");
        f.activity(&address, NOW - DAY, NOW);
        f.round(NOW, &[named(&address, "cap-name")]);
    }
    let found = f.store.dai_search(CUSTOMER, "cap-name", NOW).unwrap();
    assert_eq!(found.matches.len(), crate::DAI_SEARCH_MAX_MATCHES);
    assert!(found.truncated);
}

#[test]
fn collection_enable_state_dns_last_query_and_utc_counts() {
    let f = Fixture::new();
    assert_eq!(
        f.site_state(NOW).state,
        DaiActiveQuerySiteState::CustomerOff
    );
    assert!(f.site_state(NOW).no_dns_servers);
    f.ready();
    let end = (NOW / DAY + 1) * DAY;
    let now = end + 1;
    for (time, name) in [
        (end - 30 * DAY, "too old"),
        (end - 29 * DAY, "old"),
        (end - 1, "yesterday"),
        (end, "today"),
    ] {
        f.round(time, &[named("10.0.0.1", name)]);
    }
    let mut value = round("10.0.0.2", DaiActiveQueryResult::NoName);
    value.nbns = DaiActiveQueryResult::NoResponse;
    value.mdns = DaiActiveQueryResult::Value(DaiActiveQueryMdns {
        host_name: Some("host".into()),
        service_types: Vec::new(),
    });
    f.round(now, &[value]);
    // Future UTC dates are not part of today's window, but still contribute to last_query.
    f.round(end + DAY, &[named("10.0.0.3", "future")]);
    let on = f.site_state(now);
    assert_eq!(on.state, DaiActiveQuerySiteState::On);
    assert!(!on.no_dns_servers);
    assert_eq!(on.last_query, Some(end + DAY));
    assert_eq!(
        on.kinds
            .iter()
            .map(|k| (
                k.kind,
                k.sent_today,
                k.answered_today,
                k.sent_last_30_days,
                k.answered_last_30_days
            ))
            .collect::<Vec<_>>(),
        vec![
            (DaiActiveQueryKind::Ptr, 2, 1, 4, 3),
            (DaiActiveQueryKind::Nbns, 1, 0, 1, 0),
            (DaiActiveQueryKind::Mdns, 1, 1, 1, 1),
            (DaiActiveQueryKind::Ssdp, 0, 0, 0, 0),
        ]
    );
    f.settings(false);
    assert_eq!(
        f.site_state(now).state,
        DaiActiveQuerySiteState::CustomerOff
    );
    assert_eq!(f.site_state(now).kinds, on.kinds);
    f.settings(true);
    f.store
        .set_dai_active_query_settings(CUSTOMER, 1, false, &[])
        .unwrap();
    assert_eq!(
        f.site_state(now).state,
        DaiActiveQuerySiteState::CustomerOff
    );
    f.store
        .set_dai_active_query_settings(CUSTOMER, 2, true, &[])
        .unwrap();
    f.deleting(&[CustomerDataDeletionStatus::Failed]);
    assert_eq!(
        f.site_state(now).state,
        DaiActiveQuerySiteState::CustomerOff
    );
    f.deleting(&[CustomerDataDeletionStatus::Succeeded]);
    f.store
        .set_dai_active_query_site(CUSTOMER, &f.site, 1, &[], &[], 20)
        .unwrap();
    let no_ranges = f.site_state(now);
    assert_eq!(no_ranges.state, DaiActiveQuerySiteState::NoQueryRanges);
    assert!(no_ranges.no_dns_servers);
    assert_eq!(no_ranges.last_query, on.last_query);
    assert_eq!(
        (no_ranges.waiting_ips, no_ranges.waiting_ips_over_limit),
        (0, false)
    );
    f.dai()
        .write(|txn| {
            txn.delete_cf(f.dai().active_query_sites.cf, site_key(CUSTOMER, &f.site))?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        f.site_state(now).state,
        DaiActiveQuerySiteState::NoQueryRanges
    );
}

#[test]
fn collection_waiting_count_reuses_targets_and_caps_at_ten_thousand() {
    let f = Fixture::new();
    f.ready();
    let dai = f.dai();
    let add = |start: u32, end: u32| {
        dai.write(|txn| {
            for n in start..end {
                let address =
                    IpAddr::V4((u32::from(std::net::Ipv4Addr::new(10, 0, 0, 0)) + n).into());
                Dai::put_row(
                    txn,
                    &dai.ip_activity,
                    &address_key(CUSTOMER, &f.site, address),
                    &ActivityRow {
                        first_seen: NOW - DAY,
                        last_seen: NOW,
                    },
                )?;
            }
            Ok(())
        })
        .unwrap();
    };
    add(1, 10_000);
    let state = f.site_state(NOW);
    assert_eq!(
        (state.waiting_ips, state.waiting_ips_over_limit),
        (9_999, false)
    );
    add(10_000, 10_001);
    let state = f.site_state(NOW);
    assert_eq!(
        (state.waiting_ips, state.waiting_ips_over_limit),
        (10_000, false)
    );
    add(10_001, 10_002);
    let state = f.site_state(NOW);
    assert_eq!(
        (state.waiting_ips, state.waiting_ips_over_limit),
        (10_000, true)
    );
    f.round(NOW, &[named("10.0.0.1", "queried")]);
    let state = f.site_state(NOW);
    assert_eq!(
        (state.waiting_ips, state.waiting_ips_over_limit),
        (10_000, false)
    );
    assert_eq!(
        state.waiting_ips,
        f.store
            .dai_active_query_targets(CUSTOMER, &f.site, NOW, usize::MAX)
            .unwrap()
            .len()
    );
    f.deleting(&[CustomerDataDeletionStatus::Failed]);
    let state = f.site_state(NOW);
    assert_eq!(
        (state.waiting_ips, state.waiting_ips_over_limit),
        (0, false)
    );
}

#[test]
// Cover every subject kind with the same stored rounds and evidence.
#[allow(clippy::too_many_lines)]
fn resolve_only_enriches_ip_and_gap_explanations() {
    let f = Fixture::new();
    f.ready();
    f.binding("10.0.0.2", NOW - DAY, NOW + HOUR);
    f.binding("10.0.0.3", NOW - DAY, NOW);
    let key = binding_key(CUSTOMER, &f.site, ip("10.0.0.3"), NOW);
    f.put(
        &f.dai().bindings,
        &key,
        &BindingRow {
            end: Some(NOW + DAY),
            device: Uuid::from_u128(1),
            evidence_kind: 4,
            evidence_identifier: Identifier::mac("02:00:00:00:00:02"),
            server_id: None,
            last_strong: NOW,
            inactivity: DAY,
            end_estimated: false,
        },
    );
    let cases = [
        ("10.0.0.1", DaiResolveWhen::At(NOW), DaiSubjectKind::Ip),
        ("10.0.0.2", DaiResolveWhen::At(NOW), DaiSubjectKind::Device),
        (
            "10.0.0.3",
            DaiResolveWhen::Window {
                from: NOW - HOUR,
                to: NOW + HOUR,
            },
            DaiSubjectKind::Ambiguous,
        ),
    ];
    let before: Vec<_> = cases
        .iter()
        .map(|(address, when, kind)| {
            let answer = f.resolve_at(address, *when, NOW);
            assert_eq!(answer.kind, *kind);
            answer
        })
        .collect();
    let mut all = named("10.0.0.1", "ptr");
    all.nbns = DaiActiveQueryResult::Value(DaiActiveQueryNbns {
        computer_name: Some("nbns".into()),
        workgroup_or_domain: None,
        mac: None,
    });
    all.mdns = DaiActiveQueryResult::Value(DaiActiveQueryMdns {
        host_name: Some("mdns".into()),
        service_types: Vec::new(),
    });
    all.ssdp = DaiActiveQueryResult::Value(Vec::new());
    f.round(
        NOW,
        &[
            all,
            named("10.0.0.2", "device"),
            named("10.0.0.3", "ambiguous"),
        ],
    );
    for ((address, when, kind), original) in cases.iter().zip(before) {
        let mut answer = f.resolve_at(address, *when, NOW);
        let active = &mut answer.explanation.as_mut().unwrap().active_answers;
        if *kind == DaiSubjectKind::Ip {
            assert_eq!(
                active.iter().map(|a| a.kind).collect::<Vec<_>>(),
                ACTIVE_QUERY_KINDS
            );
        } else {
            assert_empty(active);
        }
        active.clear();
        assert_eq!(answer, original);
    }
    let sensor = "piglet.active.example";
    let mut site: crate::tables::dai::SiteValue = f
        .dai()
        .read(|txn| Dai::get_row(txn, &f.dai().sites, &site_key(CUSTOMER, &f.site)))
        .unwrap()
        .unwrap();
    site.sensors.push(sensor.into());
    f.put(&f.dai().sites, &site_key(CUSTOMER, &f.site), &site);
    f.put(
        &f.dai().sensor_state,
        &sensor_key(sensor),
        &SensorState {
            last_record_time: Some(NOW),
            ..SensorState::default()
        },
    );
    for kind in [
        DaiObservationKind::DhcpLease,
        DaiObservationKind::Kerberos,
        DaiObservationKind::Ntlm,
    ] {
        f.put(
            &f.dai().cursors,
            &pair_key(sensor, kind),
            &CursorRow {
                cursor: NOW - 1,
                read_floor: NOW - 1,
                first_send_finished: true,
                ..CursorRow::default()
            },
        );
    }
    // A gap can contain device evidence; it still gets active answers without
    // changing the provisional subject, devices or evidence sources.
    let mut gap = f.resolve_at("10.0.0.2", DaiResolveWhen::At(NOW), NOW);
    assert_eq!(gap.kind, DaiSubjectKind::EvidenceGap);
    assert_eq!(gap.explanation.as_ref().unwrap().active_answers.len(), 1);
    gap.explanation.as_mut().unwrap().active_answers.clear();
    f.dai()
        .delete_prefix(&f.dai().active_answers, &customer_key(CUSTOMER))
        .unwrap();
    assert_eq!(gap, f.resolve_at("10.0.0.2", DaiResolveWhen::At(NOW), NOW));
    let no_explanation = f
        .store
        .dai_resolve(
            CUSTOMER,
            &[DaiResolveItem {
                site: Some(f.site.clone()),
                ip: ip("10.0.0.1"),
                when: DaiResolveWhen::At(NOW),
            }],
            false,
            NOW,
        )
        .unwrap()
        .remove(0)
        .unwrap();
    assert!(no_explanation.explanation.is_none());
}

#[test]
fn active_read_helpers_keep_the_callers_snapshot() {
    let f = Fixture::new();
    f.ready();
    f.activity("10.0.0.1", NOW - DAY, NOW);
    f.round(NOW - DAY, &[named("10.0.0.1", "old")]);
    let dai = f.dai();
    let snapshot = dai.db.snapshot();
    let view = dai.customer_view(&snapshot, CUSTOMER).unwrap();
    let before_ip = dai
        .ip_active_query_in(&snapshot, &view, &f.site, ip("10.0.0.1"), NOW)
        .unwrap();
    let before_site = dai
        .site_active_query_in(&snapshot, CUSTOMER, &f.site, NOW)
        .unwrap();
    f.round(NOW, &[named("10.0.0.1", "new")]);
    f.deleting(&[CustomerDataDeletionStatus::Failed]);
    assert_eq!(
        dai.ip_active_query_in(&snapshot, &view, &f.site, ip("10.0.0.1"), NOW)
            .unwrap(),
        before_ip
    );
    assert_eq!(
        dai.site_active_query_in(&snapshot, CUSTOMER, &f.site, NOW)
            .unwrap(),
        before_site
    );
    assert_eq!(
        ptr_name(
            &dai.active_answers_at(&snapshot, CUSTOMER, &f.site, ip("10.0.0.1"), NOW)
                .unwrap()[0]
        ),
        "old"
    );
    assert_eq!(
        dai.active_answers_in(&snapshot, CUSTOMER, &f.site, ip("10.0.0.1"))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(f.history("10.0.0.1").len(), 2);
    assert_eq!(
        f.site_state(NOW).state,
        DaiActiveQuerySiteState::CustomerOff
    );
}

#[test]
fn latest_round_results_do_not_replace_valid_answers_of_other_kinds() {
    let f = Fixture::new();
    f.ready();
    f.activity("10.0.0.1", NOW - DAY, NOW);
    let mut initial = named("10.0.0.1", "ptr");
    initial.nbns = DaiActiveQueryResult::NoName;
    initial.mdns = DaiActiveQueryResult::NoResponse;
    initial.ssdp = DaiActiveQueryResult::Value(Vec::new());
    f.round(NOW, &[initial]);
    assert_eq!(
        f.resolve_at("10.0.0.1", DaiResolveWhen::At(NOW), NOW)
            .explanation
            .unwrap()
            .active_answers
            .iter()
            .map(|a| a.kind)
            .collect::<Vec<_>>(),
        vec![DaiActiveQueryKind::Ptr, DaiActiveQueryKind::Ssdp]
    );
    let mut next = round("10.0.0.1", DaiActiveQueryResult::NoResponse);
    next.nbns = DaiActiveQueryResult::Value(DaiActiveQueryNbns {
        computer_name: Some("nbns".into()),
        workgroup_or_domain: None,
        mac: None,
    });
    next.mdns = DaiActiveQueryResult::Value(DaiActiveQueryMdns {
        host_name: Some("mdns".into()),
        service_types: Vec::new(),
    });
    f.round(NOW + HOUR, &[next]);
    let mut latest = round("10.0.0.1", DaiActiveQueryResult::NotSent);
    latest.nbns = DaiActiveQueryResult::NoName;
    latest.mdns = DaiActiveQueryResult::NoResponse;
    latest.ssdp = DaiActiveQueryResult::NoResponse;
    let time = NOW + 2 * HOUR;
    f.round(time, &[latest]);
    let row = f.ip_rows(time).remove(0).active_query;
    assert_eq!(row.last_query, Some(time));
    assert_eq!(
        row.kinds
            .iter()
            .map(|k| (k.kind, k.answer.as_ref().map(|a| a.first_seen)))
            .collect::<Vec<_>>(),
        vec![
            (DaiActiveQueryKind::Ptr, Some(NOW)),
            (DaiActiveQueryKind::Nbns, None),
            (DaiActiveQueryKind::Mdns, Some(NOW + HOUR)),
            (DaiActiveQueryKind::Ssdp, Some(NOW)),
        ]
    );
    assert_eq!(
        row.kinds
            .iter()
            .map(|k| k.last_result.clone())
            .collect::<Vec<_>>(),
        vec![
            Some(DaiActiveQueryResult::NotSent),
            Some(DaiActiveQueryResult::NoName),
            Some(DaiActiveQueryResult::NoResponse),
            Some(DaiActiveQueryResult::NoResponse),
        ]
    );
    assert_eq!(
        f.resolve_at("10.0.0.1", DaiResolveWhen::At(time), time)
            .explanation
            .unwrap()
            .active_answers,
        row.kinds
            .into_iter()
            .filter_map(|k| k.answer)
            .collect::<Vec<_>>()
    );
    assert_empty(&f.store.dai_search(CUSTOMER, "nbns", time).unwrap().matches);
    for text in ["ptr", "mdns"] {
        assert_eq!(
            f.store
                .dai_search(CUSTOMER, text, time)
                .unwrap()
                .matches
                .len(),
            1
        );
    }
}

#[test]
fn active_answers_preserve_ip_filters_and_pages_in_both_directions() {
    let f = Fixture::new();
    f.ready();
    for n in 1..=5 {
        let address = format!("10.0.0.{n}");
        f.activity(&address, NOW - DAY, NOW);
        f.round(NOW, &[named(&address, &format!("host-{n}"))]);
    }
    let all = f.ip_rows(NOW);
    for (direction, from, limit, expected, more) in [
        (DaiPageDirection::Forward, None, 2, &all[..2], true),
        (
            DaiPageDirection::Forward,
            Some("10.0.0.2"),
            2,
            &all[2..4],
            true,
        ),
        (
            DaiPageDirection::Backward,
            Some("10.0.0.4"),
            2,
            &all[1..3],
            true,
        ),
        (DaiPageDirection::Backward, None, 2, &all[3..], true),
        (
            DaiPageDirection::Forward,
            Some("10.0.0.4"),
            2,
            &all[4..],
            false,
        ),
        (DaiPageDirection::Forward, None, 0, &all[..0], true),
    ] {
        let result = f
            .store
            .dai_ip_only_devices(
                CUSTOMER,
                &DaiIpDeviceFilter::default(),
                &DaiPageRequest {
                    from: from.map(|address| (f.site.clone(), ip(address))),
                    direction,
                    limit,
                },
                NOW,
            )
            .unwrap();
        assert_eq!(result.rows, expected);
        assert_eq!(result.total, 5);
        assert_eq!(result.has_more, more);
    }
    let filtered = f
        .store
        .dai_ip_only_devices(
            CUSTOMER,
            &DaiIpDeviceFilter {
                network: Some(net("10.0.0.0/30")),
                ..DaiIpDeviceFilter::default()
            },
            &DaiPageRequest {
                from: Some((f.site.clone(), ip("10.0.0.1"))),
                direction: DaiPageDirection::Forward,
                limit: 1,
            },
            NOW,
        )
        .unwrap();
    assert_eq!(filtered.rows, all[1..2]);
    assert_eq!(filtered.total, 3);
    assert!(filtered.has_more);
}

#[test]
fn timeouts_do_not_extend_positive_answer_validity() {
    let f = Fixture::new();
    f.ready();
    f.activity("10.0.0.1", NOW - DAY, NOW);
    f.activity("10.0.0.2", NOW - DAY, NOW);
    f.round(NOW, &[named("10.0.0.1", "original")]);
    for hours in [47, 49] {
        f.round(
            NOW + hours * HOUR,
            &[
                round("10.0.0.1", DaiActiveQueryResult::NoResponse),
                round("10.0.0.2", DaiActiveQueryResult::NoResponse),
            ],
        );
    }
    for (time, expected) in [
        (NOW + 48 * HOUR, Some("original")),
        (NOW + 48 * HOUR + 1, None),
    ] {
        for row in f.ip_rows(time) {
            let expected = if row.ip == ip("10.0.0.1") {
                expected
            } else {
                None
            };
            assert_eq!(
                row.active_query.kinds[0].answer.as_ref().map(ptr_name),
                expected
            );
            assert_eq!(
                f.resolve_at(&row.ip.to_string(), DaiResolveWhen::At(time), time)
                    .explanation
                    .unwrap()
                    .active_answers
                    .first()
                    .map(ptr_name),
                expected
            );
        }
        assert_eq!(
            f.store
                .dai_search(CUSTOMER, "original", time)
                .unwrap()
                .matches
                .len(),
            usize::from(expected.is_some())
        );
    }
    let history = f.history("10.0.0.1");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].value, DaiActiveQueryResult::NoResponse);
    assert_eq!(history[0].first_seen, NOW + 47 * HOUR);
    assert_eq!(history[0].last_seen, NOW + 49 * HOUR);
}

#[test]
fn active_reads_isolate_customers_sites_and_addresses() {
    let f = Fixture::new();
    f.ready();
    for (address, name) in [
        ("10.0.0.1", "first"),
        ("10.0.0.2", "neighbor"),
        ("fd00::1", "ipv6"),
    ] {
        f.activity(address, NOW - DAY, NOW);
        f.round(NOW, &[named(address, name)]);
    }
    // Move the query range between sites and customers, keeping old answers.
    f.store
        .set_dai_active_query_site(CUSTOMER, &f.site, 1, &[], &[], 20)
        .unwrap();
    let second = f.store.create_dai_site(CUSTOMER, "second", &[]).unwrap();
    let other = f.store.create_dai_site(2, "other", &[]).unwrap();
    for (customer, site, name, time) in [
        (CUSTOMER, &second, "second", NOW + 1),
        (2, &other, "other", NOW + 2),
    ] {
        f.store
            .set_dai_active_query_site(customer, site, 0, &[net("10.0.0.0/16")], &[], 20)
            .unwrap();
        f.store
            .store_dai_active_round(customer, site, time, &[named("10.0.0.1", name)])
            .unwrap();
        f.put(
            &f.dai().ip_activity,
            &address_key(customer, site, ip("10.0.0.1")),
            &ActivityRow {
                first_seen: NOW - DAY,
                last_seen: NOW,
            },
        );
        f.store
            .set_dai_active_query_site(customer, site, 1, &[], &[], 20)
            .unwrap();
    }
    for (customer, site, address, name) in [
        (CUSTOMER, &f.site, "10.0.0.1", "first"),
        (CUSTOMER, &f.site, "10.0.0.2", "neighbor"),
        (CUSTOMER, &f.site, "fd00::1", "ipv6"),
        (CUSTOMER, &second, "10.0.0.1", "second"),
        (2, &other, "10.0.0.1", "other"),
    ] {
        let history = f
            .store
            .dai_active_answers(customer, site, ip(address))
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(ptr_name(&history[0]), name);
        let found = f.store.dai_search(customer, name, NOW + 2).unwrap();
        assert_eq!(found.matches.len(), 1);
        assert_eq!(
            found.matches[0].target,
            DaiSearchTarget::IpDevice {
                site: site.clone(),
                ip: ip(address),
                last_seen: NOW,
            }
        );
    }
    assert_empty(
        &f.store
            .dai_search(CUSTOMER, "other", NOW + 2)
            .unwrap()
            .matches,
    );
    let rows = f.ip_rows(NOW + 2);
    assert_eq!(rows.len(), 4);
    for row in rows {
        assert_eq!(
            row.active_query.kinds[0].answer.as_ref(),
            f.store
                .dai_active_answers(CUSTOMER, &row.site, row.ip)
                .unwrap()
                .first()
        );
    }
    for site in f
        .store
        .dai_collection_status(CUSTOMER, NOW + 2)
        .unwrap()
        .sites
    {
        let (sent, last) = if site.site == f.site {
            (3, NOW)
        } else {
            (1, NOW + 1)
        };
        assert_eq!(site.active_query.last_query, Some(last));
        assert_eq!(site.active_query.kinds[0].sent_today, sent);
    }
}

#[test]
fn active_answer_reads_propagate_corrupt_stored_rows() {
    let f = Fixture::new();
    f.ready();
    f.activity("10.0.0.1", NOW - DAY, NOW);
    f.round(NOW, &[named("10.0.0.1", "stored")]);
    let dai = f.dai();
    let key = active_query_answer_key(
        CUSTOMER,
        &f.site,
        ip("10.0.0.1"),
        DaiActiveQueryKind::Ptr.number(),
        NOW,
    );
    // Simulate a damaged value after creating the row through the public writer.
    dai.write(|txn| {
        txn.put_cf(dai.active_answers.cf, &key, [])?;
        Ok(())
    })
    .unwrap();
    assert!(
        f.store
            .dai_active_answers(CUSTOMER, &f.site, ip("10.0.0.1"))
            .is_err()
    );
    assert!(
        f.store
            .dai_ip_only_devices(
                CUSTOMER,
                &DaiIpDeviceFilter::default(),
                &DaiPageRequest {
                    from: None,
                    direction: DaiPageDirection::Forward,
                    limit: 1,
                },
                NOW,
            )
            .is_err()
    );
    assert!(f.store.dai_search(CUSTOMER, "stored", NOW).is_err());
    let item = DaiResolveItem {
        site: Some(f.site.clone()),
        ip: ip("10.0.0.1"),
        when: DaiResolveWhen::At(NOW),
    };
    assert!(
        f.store
            .dai_resolve(CUSTOMER, std::slice::from_ref(&item), true, NOW)
            .is_err()
    );
    // Resolution without an explanation does not need the damaged answer.
    assert_eq!(
        f.store.dai_resolve(CUSTOMER, &[item], false, NOW).unwrap()[0]
            .as_ref()
            .unwrap()
            .kind,
        DaiSubjectKind::Ip
    );
}

#[test]
fn collection_reports_daily_aggregation_overflow() {
    let f = Fixture::new();
    f.ready();
    for time in [NOW - DAY, NOW] {
        f.round(time, &[named("10.0.0.1", "stored")]);
    }
    let dai = f.dai();
    let key = KeyWriter::default()
        .u32(CUSTOMER)
        .str(&f.site)
        .date(date_of(NOW - DAY).unwrap())
        .byte(DaiActiveQueryKind::Ptr.number())
        .finish();
    // Seed counts near the stored type's limit; the public writer adds one per round.
    for (sent, with_value, message) in [
        (u64::MAX, 1, "active query sent count overflow"),
        (u64::MAX - 1, u64::MAX, "active query answer count overflow"),
    ] {
        f.put(
            &dai.active_query_daily,
            &key,
            &ActiveQueryDaily { sent, with_value },
        );
        let error = f.store.dai_collection_status(CUSTOMER, NOW).unwrap_err();
        assert_eq!(error.to_string(), message);
    }
}
