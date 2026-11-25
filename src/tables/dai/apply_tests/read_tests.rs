//! Tests of the DAI reads: resolve with the evidence gap and its
//! explanation, the device list, the IP device rows, the device detail,
//! search and the collection status.

use ipnet::IpNet;

use super::super::cursor::CursorRow;
use super::super::device::{FixedIpRow, alias_key};
use super::super::observation::ActivityRow;
use super::*;
use crate::{
    DAI_RESOLVE_MAX_ITEMS, DAI_SEARCH_MAX_MATCHES, DaiActivity, DaiActivityChange, DaiAliasReason,
    DaiBindingSpan, DaiComparedValue, DaiCurrentIp, DaiDeviceFilter, DaiEvidenceSource,
    DaiGapCause, DaiIdentifier, DaiIdentifierKind, DaiImportOutcome, DaiImportRow,
    DaiIpDeviceFilter, DaiPageDirection, DaiPageRequest, DaiResolveAnswer, DaiResolveError,
    DaiResolveItem, DaiResolveItemError, DaiResolveWhen, DaiSearchMatch, DaiSearchMatchKind,
    DaiSearchTarget, DaiSubjectKind, DaiTimeRange, DaiVerdict, OwnedNetwork, event::NetworkType,
};

/// Asserts that `list` is empty, showing it if not.
fn assert_none<T: std::fmt::Debug>(list: &[T]) {
    assert_eq!(list.len(), 0, "{list:?}");
}

/// The time the reads run at, an hour after [`NOON`].
const NOW: i64 = NOON + HOUR;
/// A third sensor of [`CUSTOMER`], whose node only some tests add.
const C: &str = "piglet.c.example";

fn at(site: Option<&str>, addr: &str, time: i64) -> DaiResolveItem {
    DaiResolveItem {
        site: site.map(ToString::to_string),
        ip: ip(addr),
        when: DaiResolveWhen::At(time),
    }
}

fn window(site: Option<&str>, addr: &str, from: i64, to: i64) -> DaiResolveItem {
    DaiResolveItem {
        site: site.map(ToString::to_string),
        ip: ip(addr),
        when: DaiResolveWhen::Window { from, to },
    }
}

/// Resolves one item at [`NOW`], with an explanation, and returns its
/// answer.
fn answer(f: &Fixture, item: DaiResolveItem) -> DaiResolveAnswer {
    f.store
        .dai_resolve(CUSTOMER, &[item], true, NOW)
        .unwrap()
        .remove(0)
        .expect("the item is answered")
}

/// Returns the gap causes of the answer to `item`.
fn causes(f: &Fixture, item: DaiResolveItem) -> Vec<DaiGapCause> {
    answer(f, item).explanation.unwrap().gap_causes
}

/// Returns the compared-time cause of the answer to `item`, if any.
fn compared_cause(f: &Fixture, item: DaiResolveItem) -> Option<(String, DaiComparedValue, i64)> {
    causes(f, item).into_iter().find_map(|cause| match cause {
        DaiGapCause::AfterComparedTime {
            sensor,
            value,
            time,
        } => Some((sensor, value, time)),
        DaiGapCause::SkippedByCatchup { .. } => None,
    })
}

/// An ACK of MAC `n` at `addr` with a lease of a day, so its binding lasts
/// two days.
fn long_ack(time: i64, addr: &'static str, n: u8) -> Lease {
    Lease {
        secs: Some(86_400),
        ..Lease::ack(time, addr, n)
    }
}

fn import(f: &Fixture, customer: u32, row: DaiImportRow) -> Uuid {
    match f
        .store
        .import_dai_devices(customer, &[row])
        .unwrap()
        .remove(0)
    {
        DaiImportOutcome::Created { device }
        | DaiImportOutcome::Updated { device }
        | DaiImportOutcome::Attached { device } => device,
        DaiImportOutcome::Error(error) => panic!("the row was refused: {error}"),
    }
}

fn import_row(asset: &str, macs: &[u8], fixed: &[(&str, &str)]) -> DaiImportRow {
    DaiImportRow {
        asset_id: asset.to_string(),
        macs: macs.iter().map(|n| mac(*n)).collect(),
        fixed_ips: fixed
            .iter()
            .map(|(site, addr)| ((*site).to_string(), ip(addr)))
            .collect(),
        ..DaiImportRow::default()
    }
}

/// Writes the cursor row of (`sensor`, `kind`) at `cursor`, its first send
/// finished if `finished`.
fn set_cursor(f: &Fixture, sensor: &str, kind: Kind, cursor: i64, finished: bool) {
    let row = CursorRow {
        cursor,
        read_floor: cursor,
        first_send_finished: finished,
        ..CursorRow::default()
    };
    f.put(
        super::super::super::DAI_CURSORS,
        &pair_key(sensor, kind),
        &row,
    );
}

fn set_last_record(f: &Fixture, sensor: &str, time: i64) {
    let dai = f.dai();
    let mut state = dai
        .read(|txn| dai.sensor_state_for_update(txn, sensor))
        .unwrap();
    state.last_record_time = Some(time);
    f.put(
        super::super::super::DAI_SENSOR_STATE,
        &sensor_key(sensor),
        &state,
    );
}

/// Gives `sensor` cursors of O1, O4 and O5 at `time`, each with a finished
/// send, and a last received record time of `time`.
fn collecting(f: &Fixture, sensor: &str, time: i64) {
    for kind in [Kind::DhcpLease, Kind::Kerberos, Kind::Ntlm] {
        set_cursor(f, sensor, kind, time, true);
    }
    set_last_record(f, sensor, time);
}

fn set_earliest(f: &Fixture, sensor: &str, kind: Kind, slot: i64) {
    f.put(
        super::super::super::DAI_EARLIEST_PENDING,
        &pair_key(sensor, kind),
        &slot,
    );
}

fn set_resolver_point(f: &Fixture, sensor: &str, point: Option<i64>) {
    f.put(
        super::super::super::DAI_RESOLVER_POINTS,
        &resolver_point_key(sensor),
        &point,
    );
}

fn set_gap(f: &Fixture, sensor: &str, kind: Kind, start: i64, end: i64) {
    let key = KeyWriter::default()
        .str(sensor)
        .dai_kind(kind)
        .i64(start)
        .finish();
    f.put(super::super::super::DAI_CATCHUP_GAPS, &key, &end);
}

fn set_activity(f: &Fixture, site: &str, addr: &str, first: i64, last: i64) {
    f.put(
        super::super::super::DAI_IP_ACTIVITY,
        &address_key(CUSTOMER, site, ip(addr)),
        &ActivityRow {
            first_seen: first,
            last_seen: last,
        },
    );
}

/// Stores a finished one-part send of no observation of `kind` for
/// `sensor` in the slot starting at `slot_start`, at `now`.
fn send(
    f: &Fixture,
    sensor: &str,
    kind: Kind,
    slot_start: i64,
    counted_from: i64,
    lost_before: Option<i64>,
    now: i64,
) {
    let batch = DaiObservationBatch {
        restore_generation: f.store.dai_restore_generation().unwrap(),
        config_epoch: f.store.dai_sensor_config_epoch(sensor).unwrap(),
        network_digest: dai_network_digest(None).unwrap().digest,
        sensor: sensor.to_string(),
        kind,
        slot_start,
        slot_len_secs: 300,
        send_id: rand::random(),
        part: 0,
        part_count: 1,
        observations: Vec::new(),
        last_record_time: None,
        late_slots: Vec::new(),
        reextract_mark: None,
        lost_before,
        counted_from,
    };
    let outcome = f.store.store_dai_observations(&batch, now).unwrap();
    assert!(
        matches!(outcome, DaiStoreOutcome::Stored { .. }),
        "{outcome:?}"
    );
}

/// Adds the node of sensor [`C`] to [`CUSTOMER`].
fn add_sensor_c(f: &Fixture) {
    f.store
        .node_map()
        .put(&node("c", CUSTOMER, "c.example"))
        .unwrap();
}

// ---- Resolve: kinds ----

#[test]
fn a_time_answers_the_binding_in_effect_then_the_fixed_ip_then_the_ip() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    let device = f.owner(1);
    let found = answer(&f, at(None, "10.0.0.1", m(5)));
    assert_eq!(found.kind, DaiSubjectKind::Device);
    assert_eq!(found.subject, format!("dev:{device}"));
    assert_eq!(found.devices, [device]);
    assert_eq!(found.site, default);
    assert_eq!(
        found.evidence_sources,
        [DaiEvidenceSource::Observation(Kind::DhcpLease)]
    );

    // Past the last strong evidence time plus the inactivity time, before
    // retention writes the end.
    assert_eq!(f.binding("10.0.0.1", m(0)).end, None);
    let ended = answer(&f, at(None, "10.0.0.1", m(10)));
    assert_eq!(ended.kind, DaiSubjectKind::Ip);
    assert_eq!(ended.subject, "ip:10.0.0.1");
    assert_none(&ended.devices);
    assert_none(&ended.evidence_sources);
    let before = answer(&f, at(None, "10.0.0.1", m(-1)));
    assert_eq!(before.kind, DaiSubjectKind::Ip);

    // A close earlier than the inactivity end ends it there.
    f.applied(A, &Lease::ack(m(12), "10.0.0.1", 1));
    f.applied(A, &Lease::release(m(14), "10.0.0.1", 1));
    let closing = answer(&f, at(None, "10.0.0.1", m(13)));
    assert_eq!(closing.kind, DaiSubjectKind::Device);
    let binding = &closing.explanation.unwrap().bindings[0];
    assert_eq!(
        (binding.start, binding.end, binding.end_estimated),
        (m(12), Some(m(14)), false)
    );
    assert_eq!(
        answer(&f, at(None, "10.0.0.1", m(14))).kind,
        DaiSubjectKind::Ip
    );

    // No binding and no fixed IP.
    let unknown = answer(&f, at(None, "10.0.0.50", m(5)));
    assert_eq!(
        (unknown.kind, unknown.subject.as_str()),
        (DaiSubjectKind::Ip, "ip:10.0.0.50")
    );

    // A fixed IP answers its device where no binding is in effect.
    let fixed = import(
        &f,
        CUSTOMER,
        import_row("fx", &[], &[(&default, "10.0.0.9")]),
    );
    let found = answer(&f, at(None, "10.0.0.9", m(5)));
    assert_eq!(
        (found.kind, found.subject.clone()),
        (DaiSubjectKind::Device, format!("dev:{fixed}"))
    );
    assert_eq!(found.evidence_sources, [DaiEvidenceSource::OperatorFixedIp]);
    assert_none(&found.explanation.unwrap().bindings);
    f.applied(A, &Lease::ack(m(20), "10.0.0.9", 2));
    let bound = answer(&f, at(None, "10.0.0.9", m(21)));
    assert_eq!(bound.devices, [f.owner(2)]);
    assert_eq!(
        bound.evidence_sources,
        [DaiEvidenceSource::Observation(Kind::DhcpLease)]
    );
    assert_eq!(answer(&f, at(None, "10.0.0.9", m(35))).devices, [fixed]);
}

#[test]
fn a_window_collects_the_devices_of_its_bindings_and_of_an_unbound_part() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    // [12:00, 12:10) and [12:12, 12:22).
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    f.applied(A, &Lease::ack(m(12), "10.0.0.1", 2));
    let (one, two) = (f.owner(1), f.owner(2));

    let both = answer(&f, window(None, "10.0.0.1", m(1), m(13)));
    assert_eq!(both.kind, DaiSubjectKind::Ambiguous);
    assert_eq!(both.subject, "ip:10.0.0.1");
    let mut expected = vec![one, two];
    expected.sort_unstable();
    assert_eq!(both.devices, expected);
    assert_eq!(both.explanation.unwrap().bindings.len(), 2);
    let single = answer(&f, window(None, "10.0.0.1", m(1), m(5)));
    assert_eq!(
        (single.kind, single.devices),
        (DaiSubjectKind::Device, vec![one])
    );

    // Another device's fixed IP counts only where no binding is in effect.
    let fixed = import(
        &f,
        CUSTOMER,
        import_row("fx", &[], &[(&default, "10.0.0.1")]),
    );
    let covered = answer(&f, window(None, "10.0.0.1", m(1), m(9)));
    assert_eq!(
        (covered.kind, covered.devices),
        (DaiSubjectKind::Device, vec![one])
    );
    let unbound = answer(&f, window(None, "10.0.0.1", m(1), m(11)));
    assert_eq!(unbound.kind, DaiSubjectKind::Ambiguous);
    let mut expected = vec![one, fixed];
    expected.sort_unstable();
    assert_eq!(unbound.devices, expected);
    assert_eq!(
        unbound.evidence_sources,
        [
            DaiEvidenceSource::Observation(Kind::DhcpLease),
            DaiEvidenceSource::OperatorFixedIp
        ]
    );
    // The window's end is in it: a binding ending at 12:10 leaves 12:10
    // unbound.
    assert_eq!(
        answer(&f, window(None, "10.0.0.1", m(1), m(10))).kind,
        DaiSubjectKind::Ambiguous
    );
    let after = answer(&f, window(None, "10.0.0.1", m(30), m(40)));
    assert_eq!(
        (after.kind, after.devices),
        (DaiSubjectKind::Device, vec![fixed])
    );

    // The same device's fixed IP.
    f.applied(A, &Lease::ack(m(0), "10.0.0.3", 3));
    let three = f.owner(3);
    assert_eq!(
        import(
            &f,
            CUSTOMER,
            import_row("a3", &[3], &[(&default, "10.0.0.3")])
        ),
        three
    );
    let same = answer(&f, window(None, "10.0.0.3", m(1), m(15)));
    assert_eq!(
        (same.kind, same.subject.clone()),
        (DaiSubjectKind::Device, format!("dev:{three}"))
    );
    assert_eq!(
        same.evidence_sources,
        [
            DaiEvidenceSource::Observation(Kind::DhcpLease),
            DaiEvidenceSource::OperatorFixedIp
        ]
    );
}

#[test]
fn an_old_device_id_in_a_row_is_answered_as_the_current_one() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    f.applied(A, &Lease::ack(m(0), "10.0.0.2", 2));
    let (one, two) = (f.owner(1), f.owner(2));
    assert_eq!(
        f.store.merge_dai_devices(CUSTOMER, one, &[two]).unwrap(),
        one
    );
    assert_eq!(
        answer(&f, at(None, "10.0.0.2", m(5))).subject,
        format!("dev:{one}")
    );

    // Rows still naming an old id, as the operator change documents an
    // alias.
    let old = Uuid::from_u128(0x77);
    f.put(
        super::super::super::DAI_DEVICE_ALIASES,
        &alias_key(CUSTOMER, old),
        &AliasRow {
            current: one,
            time: NOON,
            reason: AliasReason::Merged,
        },
    );
    let fixed: FixedIpRow = old;
    f.put(
        super::super::super::DAI_FIXED_IPS,
        &address_key(CUSTOMER, &default, ip("10.0.0.8")),
        &fixed,
    );
    let found = answer(&f, at(None, "10.0.0.8", m(5)));
    assert_eq!(
        (found.subject.clone(), found.devices),
        (format!("dev:{one}"), vec![one])
    );
    f.put(
        super::super::super::DAI_BINDINGS,
        &binding_key(CUSTOMER, &default, ip("10.0.0.7"), m(0)),
        &BindingRow {
            end: None,
            device: old,
            evidence_kind: 1,
            evidence_identifier: mac_id(9),
            server_id: None,
            last_strong: m(0),
            inactivity: 10 * MINUTE,
            end_estimated: false,
        },
    );
    let found = answer(&f, at(None, "10.0.0.7", m(5)));
    assert_eq!(found.subject, format!("dev:{one}"));
    assert_eq!(found.explanation.unwrap().bindings[0].device, one);
}

#[test]
fn verdicts_activities_and_conflicts_change_no_answer() {
    let f = setup();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    let device = f.owner(1);
    let items = [
        at(None, "10.0.0.1", m(5)),
        window(None, "10.0.0.1", m(1), m(20)),
    ];
    let resolve = || f.store.dai_resolve(CUSTOMER, &items, true, NOW).unwrap();
    let before = resolve();

    // Not seen, by retention 100 days later.
    f.retention(NOON + 100 * DAY);
    assert_eq!(f.device(device).activity, Activity::NotSeen);
    assert_eq!(resolve(), before);

    f.store
        .set_dai_device_states(
            CUSTOMER,
            &[device],
            Some(DaiVerdict::Ignored),
            Some(DaiActivityChange::Hidden),
        )
        .unwrap();
    assert_eq!(resolve(), before);

    // Another device claiming the MAC leaves the stored binding.
    f.put(
        super::super::super::DAI_CONFLICTS,
        &identifier_key(CUSTOMER, &mac_id(1)),
        &ConflictRow {
            devices: [device, Uuid::from_u128(5)].into_iter().collect(),
            first: m(1),
            last: m(2),
        },
    );
    assert_eq!(resolve(), before);
}

#[test]
fn each_item_fails_alone_and_too_many_items_refuse_the_call() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));

    let too_many = vec![at(None, "10.0.0.1", m(5)); DAI_RESOLVE_MAX_ITEMS + 1];
    let error = f
        .store
        .dai_resolve(CUSTOMER, &too_many, false, NOW)
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<DaiResolveError>(),
        Some(&DaiResolveError::TooManyItems {
            count: DAI_RESOLVE_MAX_ITEMS + 1
        })
    );
    let most = f
        .store
        .dai_resolve(CUSTOMER, &too_many[1..], false, NOW)
        .unwrap();
    assert_eq!(most.len(), DAI_RESOLVE_MAX_ITEMS);
    assert!(
        most.iter()
            .all(|answer| answer.as_ref().unwrap().explanation.is_none())
    );

    let answers = f
        .store
        .dai_resolve(
            CUSTOMER,
            &[
                at(Some("nosuch00"), "10.0.0.1", m(5)),
                window(None, "10.0.0.1", m(5), m(4)),
                at(None, "10.0.0.1", m(5)),
                at(Some(&default), "10.0.0.1", m(5)),
            ],
            false,
            NOW,
        )
        .unwrap();
    assert_eq!(
        answers[0],
        Err(DaiResolveItemError::UnknownSite {
            site: "nosuch00".to_string()
        })
    );
    assert_eq!(
        answers[1],
        Err(DaiResolveItemError::InvertedWindow {
            from: m(5),
            to: m(4)
        })
    );
    // A single-site customer's item without a site is at its one site.
    let omitted = answers[2].as_ref().unwrap();
    assert_eq!(omitted.site, default);
    assert_eq!(answers[2], answers[3]);

    // Multi-site: a site is required.
    let east = f
        .dai()
        .create_site(CUSTOMER, "east", &[B.to_string()], &(NOON - HOUR))
        .unwrap();
    let answers = f
        .store
        .dai_resolve(
            CUSTOMER,
            &[
                at(None, "10.0.0.1", m(5)),
                at(Some(&default), "10.0.0.1", m(5)),
                at(Some(&east), "10.0.0.1", m(5)),
            ],
            false,
            NOW,
        )
        .unwrap();
    assert_eq!(answers[0], Err(DaiResolveItemError::SiteRequired));
    assert_eq!(answers[1].as_ref().unwrap().kind, DaiSubjectKind::Device);
    assert_eq!(answers[2].as_ref().unwrap().kind, DaiSubjectKind::Ip);

    // A customer with no site at all.
    let answers = f
        .store
        .dai_resolve(OTHER, &[at(None, "10.0.0.1", m(5))], false, NOW)
        .unwrap();
    assert_eq!(answers[0], Err(DaiResolveItemError::NoSite));
}

#[test]
fn the_ip_subject_carries_the_site_only_for_internal_ips_of_an_enabled_multi_site_customer() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    f.store
        .customer_networks_map()
        .replace(
            CUSTOMER,
            1,
            vec![
                OwnedNetwork {
                    name: "intranet".to_string(),
                    network_type: NetworkType::Intranet,
                    group: crate::HostNetworkGroup::new(
                        Vec::new(),
                        vec!["10.0.0.0/8".parse().unwrap()],
                        Vec::new(),
                    ),
                },
                OwnedNetwork {
                    name: "extranet".to_string(),
                    network_type: NetworkType::Extranet,
                    group: crate::HostNetworkGroup::new(
                        Vec::new(),
                        vec!["172.16.0.0/12".parse().unwrap()],
                        Vec::new(),
                    ),
                },
            ],
        )
        .unwrap();
    let subject = |site: Option<&str>, addr: &str| answer(&f, at(site, addr, m(5))).subject;
    // Single-site.
    assert_eq!(subject(None, "10.0.0.50"), "ip:10.0.0.50");
    assert_eq!(subject(None, "2001:DB8:0:0:0:0:0:1"), "ip:2001:db8::1");

    // Multi-site with the setting on.
    let east = f
        .dai()
        .create_site(CUSTOMER, "east", &[B.to_string()], &(NOON - HOUR))
        .unwrap();
    assert_eq!(
        subject(Some(&default), "10.0.0.50"),
        format!("ip:{default}/10.0.0.50")
    );
    assert_eq!(
        subject(Some(&east), "10.0.0.50"),
        format!("ip:{east}/10.0.0.50")
    );
    assert_eq!(subject(Some(&east), "172.16.0.1"), "ip:172.16.0.1");
    assert_eq!(subject(Some(&east), "192.168.0.1"), "ip:192.168.0.1");

    // Multi-site with the setting off.
    f.update_settings(|update| update.device_account_identification = false);
    assert_eq!(subject(Some(&default), "10.0.0.50"), "ip:10.0.0.50");
}

// ---- Resolve: the evidence gap ----

#[test]
fn the_compared_time_is_the_earliest_of_the_sensors_values() {
    let f = setup();
    f.store.ensure_default_site(CUSTOMER).unwrap();
    collecting(&f, A, m(10));
    let cause = |time| compared_cause(&f, at(None, "10.0.0.1", time));
    // No resolver point stored and nothing pending: the cursors, first.
    assert_eq!(cause(m(10)), None);
    assert_eq!(
        cause(m(11)),
        Some((
            A.to_string(),
            DaiComparedValue::Cursor(Kind::DhcpLease),
            m(10)
        ))
    );
    let found = answer(&f, at(None, "10.0.0.1", m(11)));
    assert_eq!(
        (found.kind, found.subject.as_str()),
        (DaiSubjectKind::EvidenceGap, "ip:10.0.0.1")
    );
    // A query without explanation sees the gap too.
    let plain = f
        .store
        .dai_resolve(CUSTOMER, &[at(None, "10.0.0.1", m(11))], false, NOW)
        .unwrap()
        .remove(0)
        .unwrap();
    assert_eq!(
        (plain.kind, plain.explanation),
        (DaiSubjectKind::EvidenceGap, None)
    );

    set_cursor(&f, A, Kind::Kerberos, m(9), true);
    assert_eq!(
        cause(m(10)).map(|c| c.1),
        Some(DaiComparedValue::Cursor(Kind::Kerberos))
    );
    set_last_record(&f, A, m(8));
    assert_eq!(
        cause(m(9)).map(|c| c.1),
        Some(DaiComparedValue::LastRecordTime)
    );
    // A stored "caught up" sets no limit: the earliest pending slot of O5
    // counts, that of a DNS name does not.
    set_resolver_point(&f, A, None);
    set_earliest(&f, A, Kind::Ntlm, m(7));
    assert_eq!(
        cause(m(8)),
        Some((
            A.to_string(),
            DaiComparedValue::EarliestPending(Kind::Ntlm),
            m(7)
        ))
    );
    set_earliest(&f, A, Kind::DnsName, m(6));
    assert_eq!(cause(m(7)), None);
    set_resolver_point(&f, A, Some(m(5)));
    assert_eq!(
        cause(m(6)),
        Some((A.to_string(), DaiComparedValue::ResolverPoint, m(5)))
    );
    assert_eq!(cause(m(5)), None);
    // With none stored, the earliest pending slot of any kind is the
    // resolver point.
    let db = f.db();
    db.delete_cf(
        db.cf_handle(super::super::super::DAI_RESOLVER_POINTS)
            .unwrap(),
        resolver_point_key(A),
    )
    .unwrap();
    assert_eq!(
        cause(m(7)),
        Some((A.to_string(), DaiComparedValue::ResolverPoint, m(6)))
    );
}

#[test]
fn the_resolver_point_holds_until_apply_leaves_nothing_pending() {
    let f = setup();
    f.store.ensure_default_site(CUSTOMER).unwrap();
    collecting(&f, A, m(10));
    f.lease(A, &Lease::ack(m(0), "10.0.0.1", 1));
    // An application that applies nothing writes the resolver point.
    assert_eq!(f.apply(A, m(100)), Some(m(0)));
    let found = answer(&f, at(None, "10.0.0.1", m(5)));
    assert_eq!(found.kind, DaiSubjectKind::EvidenceGap);
    assert_eq!(found.subject, "ip:10.0.0.1");
    assert_eq!(
        compared_cause(&f, at(None, "10.0.0.1", m(5))),
        Some((A.to_string(), DaiComparedValue::ResolverPoint, m(0)))
    );
    assert_eq!(f.apply(A, m(0)), None);
    let found = answer(&f, at(None, "10.0.0.1", m(5)));
    assert_eq!(found.kind, DaiSubjectKind::Device);
    assert_eq!(found.subject, format!("dev:{}", f.owner(1)));
    // Past the compared time again, with the evidence so far.
    let gap = answer(&f, at(None, "10.0.0.1", m(10) + 1));
    assert_eq!(gap.kind, DaiSubjectKind::EvidenceGap);
    assert_eq!(gap.subject, "ip:10.0.0.1");
    f.applied(A, &Lease::ack(m(5), "10.0.0.2", 2));
    set_cursor(&f, A, Kind::DhcpLease, m(3), true);
    let gap = answer(&f, at(None, "10.0.0.2", m(6)));
    assert_eq!(gap.kind, DaiSubjectKind::EvidenceGap);
    assert_eq!(gap.subject, format!("dev:{}", f.owner(2)));
}

#[test]
fn pending_expiry_moves_the_resolver_point_and_a_later_store_does_not() {
    let f = setup();
    f.store.ensure_default_site(CUSTOMER).unwrap();
    collecting(&f, A, m(10));
    let old = NOON - 40 * DAY;
    f.enqueue(
        A,
        &dns("old.example", "10.0.0.5"),
        old + MINUTE,
        old + MINUTE,
    );
    f.enqueue(A, &dns("new.example", "10.0.0.5"), m(7), m(7));
    assert_eq!(f.apply(A, m(100)), Some(old));
    let cause = |time| compared_cause(&f, at(None, "10.0.0.5", time));
    assert_eq!(
        cause(m(4)),
        Some((A.to_string(), DaiComparedValue::ResolverPoint, old))
    );

    // Retention deletes the old row: the point moves to the remaining one.
    f.retention(NOW);
    assert_eq!(f.resolver_point(A), Some(m(5)));
    assert_eq!(cause(m(4)), None);
    assert_eq!(
        cause(m(6)),
        Some((A.to_string(), DaiComparedValue::ResolverPoint, m(5)))
    );

    // Applied: caught up.
    assert_eq!(f.apply(A, m(5)), None);
    assert_eq!(cause(m(6)), None);
    // A row stored after the last application leaves the stored point.
    f.enqueue(A, &dns("later.example", "10.0.0.5"), m(1), m(1));
    assert_eq!(f.resolver_point(A), None);
    assert_eq!(cause(m(6)), None);

    // Retention moves a point it alone held back to "caught up".
    let f = setup();
    f.store.ensure_default_site(CUSTOMER).unwrap();
    collecting(&f, A, m(10));
    f.enqueue(
        A,
        &dns("old.example", "10.0.0.5"),
        old + MINUTE,
        old + MINUTE,
    );
    assert_eq!(f.apply(A, m(100)), Some(old));
    assert!(compared_cause(&f, at(None, "10.0.0.5", m(4))).is_some());
    f.retention(NOW);
    assert_eq!(f.resolver_point(A), None);
    assert_eq!(compared_cause(&f, at(None, "10.0.0.5", m(4))), None);
}

#[test]
fn a_pair_counts_once_its_first_send_has_finished() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    f.store.dai_cursors(&[A.to_string()], m(0)).unwrap();
    // Every pair is new: no compared time, no gap.
    assert_eq!(
        answer(&f, at(None, "10.0.0.1", m(60))).kind,
        DaiSubjectKind::Ip
    );
    let status = f.store.dai_collection_status(CUSTOMER, NOW).unwrap();
    assert_eq!(status.sites[0].site, default);
    assert_eq!(
        status.sites[0].unsent_pairs,
        [
            (A.to_string(), Kind::DhcpLease),
            (A.to_string(), Kind::Kerberos),
            (A.to_string(), Kind::Ntlm)
        ]
    );

    send(&f, A, Kind::DhcpLease, m(0), m(0), None, m(6));
    assert_eq!(
        compared_cause(&f, at(None, "10.0.0.1", m(60))),
        Some((
            A.to_string(),
            DaiComparedValue::Cursor(Kind::DhcpLease),
            m(5)
        ))
    );
    assert_eq!(compared_cause(&f, at(None, "10.0.0.1", m(5))), None);
    let status = f.store.dai_collection_status(CUSTOMER, NOW).unwrap();
    assert_eq!(
        status.sites[0].unsent_pairs,
        [(A.to_string(), Kind::Kerberos), (A.to_string(), Kind::Ntlm)]
    );

    // Turning the setting on again moves the cursor, not the flag.
    f.update_settings(|update| update.device_account_identification = false);
    f.update_settings(|update| update.device_account_identification = true);
    let status = f.store.dai_collection_status(CUSTOMER, NOW).unwrap();
    assert_eq!(status.sites[0].unsent_pairs.len(), 2);
}

#[test]
fn quiet_sensors_are_left_out_unless_every_sensor_is_quiet() {
    let f = setup();
    f.store.ensure_default_site(CUSTOMER).unwrap();
    collecting(&f, A, m(0));
    set_last_record(&f, A, NOW - 2 * DAY);
    collecting(&f, B, m(10));
    // A is quiet: B decides.
    assert_eq!(compared_cause(&f, at(None, "10.0.0.1", m(5))), None);
    assert_eq!(
        compared_cause(&f, at(None, "10.0.0.1", m(11))),
        Some((
            B.to_string(),
            DaiComparedValue::Cursor(Kind::DhcpLease),
            m(10)
        ))
    );
    let status = f.store.dai_collection_status(CUSTOMER, NOW).unwrap();
    assert_eq!(status.sites[0].quiet_sensors, [A.to_string()]);

    // A last received record time after now is not within the 24 hours
    // before now: A, with its old cursor, is still left out.
    set_last_record(&f, A, NOW + DAY);
    assert_eq!(compared_cause(&f, at(None, "10.0.0.1", m(5))), None);
    let status = f.store.dai_collection_status(CUSTOMER, NOW).unwrap();
    assert_eq!(status.sites[0].quiet_sensors, [A.to_string()]);
    set_last_record(&f, A, NOW - 2 * DAY);

    // Both quiet: the latest last received record time decides, though B's
    // compared time is earlier.
    set_last_record(&f, B, NOW - 3 * DAY);
    assert_eq!(
        compared_cause(&f, at(None, "10.0.0.1", m(5))),
        Some((
            A.to_string(),
            DaiComparedValue::LastRecordTime,
            NOW - 2 * DAY
        ))
    );
    let status = f.store.dai_collection_status(CUSTOMER, NOW).unwrap();
    assert_eq!(status.sites[0].quiet_sensors, [B.to_string()]);
}

#[test]
fn a_moved_sensor_counts_for_each_site_while_it_was_there() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    collecting(&f, A, m(30));
    collecting(&f, B, m(30));
    // A moves to west at 12:05.
    let west = f
        .dai()
        .create_site(CUSTOMER, "west", &[A.to_string()], &m(2))
        .unwrap();
    set_gap(&f, A, Kind::DhcpLease, m(1), m(4));
    set_gap(&f, A, Kind::DhcpLease, m(6), m(8));
    // Another kind's gap is not an evidence gap.
    set_gap(&f, A, Kind::DnsName, m(0), m(30));
    let skipped = |start, end| DaiGapCause::SkippedByCatchup {
        sensor: A.to_string(),
        kind: Kind::DhcpLease,
        start,
        end,
    };
    assert_eq!(
        causes(&f, at(Some(&default), "10.0.0.1", m(2))),
        [skipped(m(1), m(4))]
    );
    assert_none(&causes(&f, at(Some(&west), "10.0.0.1", m(2))));
    assert_eq!(
        causes(&f, at(Some(&west), "10.0.0.1", m(7))),
        [skipped(m(6), m(8))]
    );
    assert_none(&causes(&f, at(Some(&default), "10.0.0.1", m(7))));
    assert_eq!(
        causes(&f, window(Some(&default), "10.0.0.1", m(3), m(7))),
        [skipped(m(1), m(4))]
    );
    assert_eq!(
        causes(&f, window(Some(&west), "10.0.0.1", m(3), m(7))),
        [skipped(m(6), m(8))]
    );
    assert_eq!(
        answer(&f, at(Some(&west), "10.0.0.1", m(7))).kind,
        DaiSubjectKind::EvidenceGap
    );

    // The compared time.
    set_cursor(&f, A, Kind::DhcpLease, m(0), true);
    assert_eq!(
        compared_cause(&f, at(Some(&default), "10.0.0.1", m(3))).map(|c| c.0),
        Some(A.to_string())
    );
    assert_eq!(
        compared_cause(&f, at(Some(&default), "10.0.0.1", m(10))),
        None
    );
    assert_eq!(
        compared_cause(&f, at(Some(&west), "10.0.0.1", m(10))).map(|c| c.0),
        Some(A.to_string())
    );
    let status = f.store.dai_collection_status(CUSTOMER, NOW).unwrap();
    let site_of = |sensor: &str| {
        status
            .sensors
            .iter()
            .find(|s| s.sensor == sensor)
            .and_then(|s| s.site.clone())
    };
    assert_eq!(site_of(A), Some(west));
    assert_eq!(site_of(B), Some(default));
}

/// Skips O1 of [`A`] from 12:00 to 12:30 and sends the slot starting at
/// 12:10, counted from 12:12, before the skip if `late_first`, else after
/// it.
fn skipped(late_first: bool) -> Fixture {
    let f = setup();
    f.store.ensure_default_site(CUSTOMER).unwrap();
    f.store.dai_cursors(&[A.to_string()], m(0)).unwrap();
    if late_first {
        send(&f, A, Kind::DhcpLease, m(10), m(12), None, m(40));
    }
    send(&f, A, Kind::DhcpLease, m(30), m(30), Some(m(30)), m(40));
    if !late_first {
        send(&f, A, Kind::DhcpLease, m(10), m(12), None, m(40));
    }
    let gaps = f.dai().read(|txn| f.dai().gaps_in(txn, A, Kind::DhcpLease));
    assert_eq!(gaps.unwrap(), [(m(0), m(12)), (m(15), m(30))]);
    f
}

#[test]
fn a_catch_up_gap_is_an_evidence_gap_until_a_send_confirms_it() {
    for late_first in [true, false] {
        let f = skipped(late_first);
        // A binding opened in the gap by evidence applied later.
        f.applied(A, &Lease::ack(m(5), "10.0.0.1", 1));
        let found = answer(&f, at(None, "10.0.0.1", m(6)));
        assert_eq!(found.kind, DaiSubjectKind::EvidenceGap);
        assert_eq!(found.subject, format!("dev:{}", f.owner(1)));
        assert_eq!(
            found.explanation.unwrap().gap_causes,
            [DaiGapCause::SkippedByCatchup {
                sensor: A.to_string(),
                kind: Kind::DhcpLease,
                start: m(0),
                end: m(12),
            }]
        );
        // The counted part of the slot sent later is no longer a gap; the
        // part before its `counted_from` is.
        assert_eq!(
            answer(&f, at(None, "10.0.0.1", m(13))).kind,
            DaiSubjectKind::Device
        );
        assert_eq!(
            answer(&f, at(None, "10.0.0.1", m(12) - 1)).kind,
            DaiSubjectKind::EvidenceGap
        );
        assert_eq!(
            answer(&f, window(None, "10.0.0.1", m(10), m(13))).kind,
            DaiSubjectKind::EvidenceGap
        );
        assert_eq!(
            answer(&f, window(None, "10.0.0.1", m(12), m(14))).kind,
            DaiSubjectKind::Device
        );
        // A window crossing the rest of the gap.
        let crossing = answer(&f, window(None, "10.0.0.1", m(14), m(31)));
        assert_eq!(crossing.kind, DaiSubjectKind::EvidenceGap);
        let status = f.store.dai_collection_status(CUSTOMER, NOW).unwrap();
        assert_eq!(status.catchup_gaps.len(), 2);
        assert_eq!(status.skipped_by_catchup.len(), 1);
        assert_eq!(status.skipped_by_catchup[0].count, 6);
    }
}

// ---- Resolve: the explanation ----

#[test]
fn an_explanation_lists_the_newest_evidence_rows_and_no_names() {
    let f = setup();
    f.applied(
        A,
        &Lease {
            hostname: Some("host-one"),
            ..long_ack(m(0), "10.0.0.1", 1)
        },
    );
    for k in 1..=11 {
        f.observed(A, &ntlm("10.0.0.1"), m(5 * k), m(5 * k));
    }
    f.observed(A, &krb("10.0.0.1", REALM, "alice", 11, 2), m(57), m(57));
    f.observed(A, &verified("10.0.0.1", "host1$"), m(58), m(58));
    let device = f.owner(1);

    let found = answer(&f, at(None, "10.0.0.1", m(59)));
    let explanation = found.explanation.clone().unwrap();
    let binding = &explanation.bindings[0];
    assert_eq!(
        (
            binding.device,
            binding.start,
            binding.end,
            binding.end_estimated
        ),
        (device, m(0), None, false)
    );
    assert_eq!(binding.evidence_kind, Some(Kind::DhcpLease));
    let rows: Vec<(Kind, i64)> = binding
        .evidence
        .iter()
        .map(|row| (row.kind, row.last_seen))
        .collect();
    let mut expected = vec![(Kind::Kerberos, m(58)), (Kind::Kerberos, m(57))];
    expected.extend((4..=11).rev().map(|k| (Kind::Ntlm, m(5 * k))));
    assert_eq!(rows, expected);
    assert!(binding.evidence.iter().all(|row| row.sensor == A));

    let found_window = answer(&f, window(None, "10.0.0.1", m(20), m(30)));
    let rows: Vec<i64> = found_window.explanation.unwrap().bindings[0]
        .evidence
        .iter()
        .map(|row| row.last_seen)
        .collect();
    assert_eq!(rows, [m(30), m(25), m(20)]);
    let early = answer(&f, at(None, "10.0.0.1", m(3)));
    let rows: Vec<(Kind, i64)> = early.explanation.unwrap().bindings[0]
        .evidence
        .iter()
        .map(|row| (row.kind, row.last_seen))
        .collect();
    assert_eq!(rows, [(Kind::DhcpLease, m(0))]);

    // No user, account, realm or machine account name in any answer.
    for text in [
        format!("{found:?}"),
        format!(
            "{:?}",
            f.store
                .dai_devices(
                    CUSTOMER,
                    &DaiDeviceFilter::default(),
                    &forward(None, 10),
                    NOW
                )
                .unwrap()
        ),
        format!(
            "{:?}",
            f.store.dai_collection_status(CUSTOMER, NOW).unwrap()
        ),
    ] {
        for name in ["alice", "user", "CORP", "corp", "HOST1", "WS\""] {
            assert!(!text.contains(name), "{name} in {text}");
        }
    }
    // The machine account is an identifier in the detail only.
    let detail = f.store.dai_device(CUSTOMER, device, NOW).unwrap().unwrap();
    assert!(detail.identifiers.iter().any(|id| id.identifier
        == DaiIdentifier {
            kind: DaiIdentifierKind::MachineAccount,
            value: "HOST1$@CORP.EXAMPLE".to_string(),
        }));
    let search = f
        .store
        .dai_search(CUSTOMER, "HOST1$@CORP.EXAMPLE", NOW)
        .unwrap();
    assert_none(&search.matches);
    assert_none(&f.store.dai_search(CUSTOMER, "alice", NOW).unwrap().matches);
}

// ---- The device list and the IP device rows ----

fn forward<K>(from: Option<K>, limit: usize) -> DaiPageRequest<K> {
    DaiPageRequest {
        from,
        direction: DaiPageDirection::Forward,
        limit,
    }
}

fn backward<K>(from: Option<K>, limit: usize) -> DaiPageRequest<K> {
    DaiPageRequest {
        from,
        direction: DaiPageDirection::Backward,
        limit,
    }
}

#[test]
#[allow(clippy::too_many_lines)] // One fixture, read through every filter and both directions.
fn the_device_list_shows_current_ips_and_filters_and_pages() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    let east = f
        .dai()
        .create_site(CUSTOMER, "east", &[B.to_string()], &(NOON - HOUR))
        .unwrap();
    f.applied(
        A,
        &Lease {
            hostname: Some("Host-One"),
            ..long_ack(m(0), "10.0.0.1", 1)
        },
    );
    f.applied(A, &Lease::ack(m(0), "10.0.0.2", 2));
    f.applied(B, &long_ack(m(0), "192.168.1.5", 3));
    let (one, two, three) = (f.owner(1), f.owner(2), f.owner(3));
    let four = import(&f, CUSTOMER, import_row("asset-4", &[], &[]));
    f.store
        .set_dai_device_states(CUSTOMER, &[two], Some(DaiVerdict::Ignored), None)
        .unwrap();
    f.store
        .set_dai_device_states(CUSTOMER, &[three], None, Some(DaiActivityChange::Hidden))
        .unwrap();

    let rows_of = |filter: &DaiDeviceFilter| {
        let page = f
            .store
            .dai_devices(CUSTOMER, filter, &forward(None, 10), NOW)
            .unwrap();
        assert_eq!(page.total, page.rows.len());
        page.rows
    };
    let ids = |filter: &DaiDeviceFilter| -> Vec<Uuid> {
        rows_of(filter).into_iter().map(|row| row.device).collect()
    };
    let sorted = |mut ids: Vec<Uuid>| {
        ids.sort_unstable();
        ids
    };

    let all = rows_of(&DaiDeviceFilter::default());
    assert_eq!(
        all.iter().map(|row| row.device).collect::<Vec<_>>(),
        sorted(vec![one, two, three, four])
    );
    let row = |device| all.iter().find(|row| row.device == device).unwrap();
    assert_eq!(
        row(one).current_ips,
        [DaiCurrentIp {
            site: default.clone(),
            ip: ip("10.0.0.1"),
            start: m(0),
        }]
    );
    assert_eq!(row(one).latest_binding, None);
    assert_eq!(row(one).representative_name.as_deref(), Some("Host-One"));
    assert_eq!(
        (row(one).first_seen, row(one).last_seen),
        (Some(m(0)), Some(m(0)))
    );
    assert_none(&row(two).current_ips);
    assert_eq!(
        row(two).latest_binding,
        Some(DaiBindingSpan {
            site: default.clone(),
            ip: ip("10.0.0.2"),
            start: m(0),
            end: Some(m(10)),
            end_estimated: true,
        })
    );
    assert_eq!(
        (row(two).verdict, row(three).activity),
        (DaiVerdict::Ignored, DaiActivity::Hidden)
    );
    assert_eq!(row(three).current_ips[0].site, east);
    assert_none(&row(four).current_ips);
    assert_eq!(row(four).latest_binding, None);
    assert_eq!((row(four).first_seen, row(four).last_seen), (None, None));

    let filter = |change: fn(&mut DaiDeviceFilter)| {
        let mut filter = DaiDeviceFilter::default();
        change(&mut filter);
        filter
    };
    let network = |text: &str| -> IpNet { text.parse().unwrap() };
    let mut by_site = DaiDeviceFilter {
        sites: Some(vec![east.clone()]),
        ..DaiDeviceFilter::default()
    };
    assert_eq!(ids(&by_site), [three]);
    by_site.sites = Some(vec![default.clone()]);
    assert_eq!(ids(&by_site), sorted(vec![one, two]));
    let by_net = DaiDeviceFilter {
        network: Some(network("10.0.0.0/24")),
        ..DaiDeviceFilter::default()
    };
    assert_eq!(ids(&by_net), sorted(vec![one, two]));
    let by_host = DaiDeviceFilter {
        network: Some(network("10.0.0.1/32")),
        ..DaiDeviceFilter::default()
    };
    assert_eq!(ids(&by_host), [one]);
    let both = DaiDeviceFilter {
        sites: Some(vec![east.clone()]),
        network: Some(network("10.0.0.0/8")),
        ..DaiDeviceFilter::default()
    };
    assert_none(&ids(&both));
    assert_eq!(
        ids(&filter(|f| f.verdicts = Some(vec![DaiVerdict::Ignored]))),
        [two]
    );
    assert_eq!(
        ids(&filter(|f| f.activities = Some(vec![DaiActivity::Hidden]))),
        [three]
    );
    assert_eq!(
        ids(&filter(|f| f.activities = Some(vec![DaiActivity::Active]))),
        sorted(vec![one, two, four])
    );
    assert_none(&ids(&filter(|f| {
        f.seen = Some(DaiTimeRange {
            from: NOON - 10 * MINUTE,
            to: NOON - 5 * MINUTE,
        });
    })));
    assert_eq!(
        ids(&filter(|f| f.seen = Some(DaiTimeRange {
            from: NOON,
            to: NOON,
        }))),
        sorted(vec![one, two, three])
    );

    // Paging both ways covers every device once.
    let everything = sorted(vec![one, two, three, four]);
    let first = f
        .store
        .dai_devices(
            CUSTOMER,
            &DaiDeviceFilter::default(),
            &forward(None, 3),
            NOW,
        )
        .unwrap();
    assert_eq!(
        (first.rows.len(), first.has_more, first.total),
        (3, true, 4)
    );
    let next = f
        .store
        .dai_devices(
            CUSTOMER,
            &DaiDeviceFilter::default(),
            &forward(first.rows.last().map(|row| row.device), 3),
            NOW,
        )
        .unwrap();
    assert_eq!((next.rows.len(), next.has_more, next.total), (1, false, 4));
    let forwards: Vec<Uuid> = first
        .rows
        .iter()
        .chain(&next.rows)
        .map(|row| row.device)
        .collect();
    assert_eq!(forwards, everything);
    let last = f
        .store
        .dai_devices(
            CUSTOMER,
            &DaiDeviceFilter::default(),
            &backward(None, 3),
            NOW,
        )
        .unwrap();
    assert_eq!((last.rows.len(), last.has_more), (3, true));
    let previous = f
        .store
        .dai_devices(
            CUSTOMER,
            &DaiDeviceFilter::default(),
            &backward(last.rows.first().map(|row| row.device), 3),
            NOW,
        )
        .unwrap();
    assert_eq!((previous.rows.len(), previous.has_more), (1, false));
    let backwards: Vec<Uuid> = previous
        .rows
        .iter()
        .chain(&last.rows)
        .map(|row| row.device)
        .collect();
    assert_eq!(backwards, everything);
    // A filtered page counts the matching devices only.
    let page = f
        .store
        .dai_devices(CUSTOMER, &by_net, &forward(None, 1), NOW)
        .unwrap();
    assert_eq!((page.rows.len(), page.has_more, page.total), (1, true, 2));
}

#[test]
fn ip_device_rows_list_recent_unbound_addresses() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    f.applied(A, &long_ack(m(0), "10.0.0.1", 1));
    f.applied(A, &Lease::ack(m(0), "10.0.0.2", 2));
    set_activity(&f, &default, "10.0.0.50", m(1), m(20));
    // Bound until 12:10 only.
    set_activity(&f, &default, "10.0.0.2", m(0), m(20));
    // Bound at its last seen time.
    set_activity(&f, &default, "10.0.0.1", m(0), m(5));
    // Last seen more than 30 days ago.
    set_activity(&f, &default, "10.0.0.60", NOW - 40 * DAY, NOW - 31 * DAY);
    let list = |filter: &DaiIpDeviceFilter, request| {
        f.store
            .dai_ip_only_devices(CUSTOMER, filter, &request, NOW)
            .unwrap()
    };
    let all = list(&DaiIpDeviceFilter::default(), forward(None, 10));
    let addrs: Vec<IpAddr> = all.rows.iter().map(|row| row.ip).collect();
    assert_eq!(addrs, [ip("10.0.0.2"), ip("10.0.0.50")]);
    assert_eq!(all.total, 2);
    assert_eq!(
        (
            all.rows[1].site.as_str(),
            all.rows[1].first_seen,
            all.rows[1].last_seen
        ),
        (default.as_str(), m(1), m(20))
    );

    let filtered = |filter: DaiIpDeviceFilter| -> Vec<IpAddr> {
        list(&filter, forward(None, 10))
            .rows
            .into_iter()
            .map(|row| row.ip)
            .collect()
    };
    assert_eq!(
        filtered(DaiIpDeviceFilter {
            network: Some("10.0.0.50/32".parse().unwrap()),
            ..DaiIpDeviceFilter::default()
        }),
        [ip("10.0.0.50")]
    );
    assert_eq!(
        filtered(DaiIpDeviceFilter {
            seen: Some(DaiTimeRange {
                from: m(0),
                to: m(0)
            }),
            ..DaiIpDeviceFilter::default()
        }),
        [ip("10.0.0.2")]
    );
    assert_none(&filtered(DaiIpDeviceFilter {
        sites: Some(vec!["nosuch00".to_string()]),
        ..DaiIpDeviceFilter::default()
    }));

    let first = list(&DaiIpDeviceFilter::default(), forward(None, 1));
    assert_eq!((first.rows[0].ip, first.has_more), (ip("10.0.0.2"), true));
    let next = list(
        &DaiIpDeviceFilter::default(),
        forward(Some((default.clone(), ip("10.0.0.2"))), 1),
    );
    assert_eq!((next.rows[0].ip, next.has_more), (ip("10.0.0.50"), false));
    let back = list(
        &DaiIpDeviceFilter::default(),
        backward(Some((default.clone(), ip("10.0.0.50"))), 5),
    );
    assert_eq!((back.rows.len(), back.has_more), (1, false));

    // They are not devices.
    let devices = f
        .store
        .dai_devices(
            CUSTOMER,
            &DaiDeviceFilter::default(),
            &forward(None, 10),
            NOW,
        )
        .unwrap();
    assert_eq!(devices.total, 2);
}

#[test]
fn a_page_from_an_old_device_id_starts_at_the_current_device() {
    let f = setup();
    f.store.ensure_default_site(CUSTOMER).unwrap();
    for (n, addr) in (1..).zip(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]) {
        f.applied(A, &Lease::ack(m(0), addr, n));
    }
    // The lowest id absorbs the highest, so the old id lies on the far side
    // of every other device.
    let mut owners: Vec<Uuid> = (1..=5).map(|n| f.owner(n)).collect();
    owners.sort_unstable();
    let (survivor, absorbed) = (owners[0], owners[4]);
    f.store
        .merge_dai_devices(CUSTOMER, survivor, &[absorbed])
        .unwrap();
    let ids = |request: DaiPageRequest<Uuid>| -> Vec<Uuid> {
        f.store
            .dai_devices(CUSTOMER, &DaiDeviceFilter::default(), &request, NOW)
            .unwrap()
            .rows
            .into_iter()
            .map(|row| row.device)
            .collect()
    };
    let all = ids(forward(None, 10));
    assert_eq!(all.len(), 4);
    assert!(!all.contains(&absorbed));
    let at = all.iter().position(|id| *id == survivor).unwrap();
    let (before, after) = (all[..at].to_vec(), all[at + 1..].to_vec());

    assert_eq!(ids(forward(Some(survivor), 10)), after);
    assert_eq!(ids(forward(Some(absorbed), 10)), after);
    assert_eq!(ids(backward(Some(survivor), 10)), before);
    assert_eq!(ids(backward(Some(absorbed), 10)), before);
}

#[test]
fn ip_device_rows_and_search_leave_out_activity_after_now() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    set_activity(&f, &default, "10.0.0.1", m(0), NOW);
    set_activity(&f, &default, "10.0.0.2", NOW - 31 * DAY, NOW - 30 * DAY);
    set_activity(&f, &default, "10.0.0.3", m(0), NOW + 1);
    set_activity(&f, &default, "10.0.0.4", m(0), NOW + DAY);
    let list = f
        .store
        .dai_ip_only_devices(
            CUSTOMER,
            &DaiIpDeviceFilter::default(),
            &forward(None, 10),
            NOW,
        )
        .unwrap();
    let addrs: Vec<IpAddr> = list.rows.iter().map(|row| row.ip).collect();
    assert_eq!(addrs, [ip("10.0.0.1"), ip("10.0.0.2")]);
    assert_eq!(list.total, 2);

    let search = |text: &str| f.store.dai_search(CUSTOMER, text, NOW).unwrap().matches;
    assert_eq!(
        search("10.0.0.1"),
        [DaiSearchMatch {
            matched: DaiSearchMatchKind::Ip,
            target: DaiSearchTarget::IpDevice {
                site: default.clone(),
                ip: ip("10.0.0.1"),
                last_seen: NOW,
            },
        }]
    );
    assert_eq!(search("10.0.0.2").len(), 1);
    assert_none(&search("10.0.0.3"));
    assert_none(&search("10.0.0.4"));
}

// ---- The device detail ----

#[test]
#[allow(clippy::too_many_lines)] // One device, checked field by field.
fn the_detail_follows_an_alias_and_holds_every_attribute() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    f.applied(
        A,
        &Lease {
            hostname: Some("one"),
            ..Lease::ack(m(0), "10.0.0.1", 1)
        },
    );
    f.applied(A, &long_ack(m(12), "10.0.0.1", 1));
    f.observed(A, &verified("10.0.0.1", "host1$"), m(13), m(13));
    let service = DaiObservationBody::Service {
        server_ip: ip("10.0.0.1"),
        port: 22,
        proto: 6,
        external_client: true,
    };
    f.observed(A, &service, m(14), m(14));
    f.observed(A, &software("10.0.0.1", "OpenSSH_9"), m(14), m(14));
    let one = f.owner(1);
    let row = DaiImportRow {
        name: Some("Operator Name".to_string()),
        memo: Some("a memo".to_string()),
        ..import_row("asset-1", &[1], &[(&default, "10.0.0.99")])
    };
    assert_eq!(import(&f, CUSTOMER, row), one);
    f.applied(A, &Lease::ack(m(0), "10.0.0.2", 2));
    let two = f.owner(2);
    f.store.merge_dai_devices(CUSTOMER, one, &[two]).unwrap();

    let detail = f.store.dai_device(CUSTOMER, two, NOW).unwrap().unwrap();
    assert_eq!(
        (detail.requested, detail.device, detail.alias_followed),
        (two, one, true)
    );
    assert_eq!(detail.aliases.len(), 1);
    assert_eq!(
        (detail.aliases[0].device, detail.aliases[0].reason),
        (two, DaiAliasReason::Merged)
    );
    let direct = f.store.dai_device(CUSTOMER, one, NOW).unwrap().unwrap();
    assert!(!direct.alias_followed);
    assert_eq!(direct.device, one);

    let identifiers: Vec<(DaiIdentifierKind, &str)> = detail
        .identifiers
        .iter()
        .map(|id| (id.identifier.kind, id.identifier.value.as_str()))
        .collect();
    for expected in [
        (DaiIdentifierKind::Mac, "02:00:00:00:00:01"),
        (DaiIdentifierKind::Mac, "02:00:00:00:00:02"),
        (DaiIdentifierKind::MachineAccount, "HOST1$@CORP.EXAMPLE"),
        (DaiIdentifierKind::OperatorAssetId, "asset-1"),
    ] {
        assert!(
            identifiers.contains(&expected),
            "{expected:?} {identifiers:?}"
        );
    }
    assert!(
        detail
            .identifiers
            .iter()
            .all(|id| id.last_confirmed.is_some())
    );
    assert_eq!(detail.representative_name.as_deref(), Some("Operator Name"));
    assert!(detail.names.iter().any(|name| name.value == "one"));
    assert_eq!(detail.operator_asset_id.as_deref(), Some("asset-1"));
    assert_eq!(detail.memo, "a memo");
    assert_eq!(detail.fixed_ips, [(default.clone(), ip("10.0.0.99"))]);
    assert_eq!(
        (detail.first_seen, detail.last_seen),
        (Some(m(0)), Some(m(14)))
    );

    // The IP history, newest first, with estimated ends.
    let history: Vec<(IpAddr, i64, Option<i64>, bool)> = detail
        .ip_history
        .iter()
        .map(|b| (b.ip, b.start, b.end, b.end_estimated))
        .collect();
    assert_eq!(
        history,
        [
            (ip("10.0.0.1"), m(12), None, false),
            (ip("10.0.0.1"), m(0), Some(m(10)), true),
            (ip("10.0.0.2"), m(0), Some(m(10)), true),
        ]
    );
    assert_eq!(detail.ip_history[1].evidence_kind, Some(Kind::DhcpLease));
    assert_eq!(
        detail.ip_history[1].evidence_identifier,
        DaiIdentifier {
            kind: DaiIdentifierKind::Mac,
            value: "02:00:00:00:00:01".to_string()
        }
    );

    assert_eq!(detail.services.len(), 1);
    let service = &detail.services[0];
    assert_eq!(
        (service.port, service.protocol, service.external_client),
        (22, 6, true)
    );
    assert!(!service.not_seen && !service.removed);
    let later = f
        .store
        .dai_device(CUSTOMER, one, m(14) + 31 * DAY)
        .unwrap()
        .unwrap();
    assert!(later.services[0].not_seen);
    assert_eq!(detail.software.len(), 1);
    assert_eq!(
        (
            detail.software[0].side,
            detail.software[0].source,
            detail.software[0].text.as_str()
        ),
        (DaiSide::Server, DaiSoftwareSource::Ssh, "OpenSSH_9")
    );

    // The change history in version order, ending at the device's version.
    let versions: Vec<u64> = detail.changes.iter().map(|c| c.version).collect();
    assert!(versions.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(versions.last(), Some(&detail.version));
    let merged = detail
        .changes
        .iter()
        .find(|c| c.kind == crate::DaiChangeKind::Merged)
        .expect("the merge is in the history");
    // The absorbed id is answered as the current one; it is in the aliases.
    assert_eq!(merged.related_device, Some(one));
    assert!(
        detail
            .changes
            .iter()
            .all(|c| c.related_device.is_none_or(|related| related != two))
    );

    // Another customer's device, and an unknown id.
    let others = import(&f, OTHER, import_row("other", &[9], &[]));
    assert_eq!(f.store.dai_device(CUSTOMER, others, NOW).unwrap(), None);
    assert_eq!(
        f.store
            .dai_device(CUSTOMER, Uuid::from_u128(1), NOW)
            .unwrap(),
        None
    );
}

// ---- Search ----

#[test]
fn search_finds_by_each_kind() {
    let f = setup();
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    f.applied(
        A,
        &Lease {
            hostname: Some("Alpha-Host"),
            ..Lease::ack(m(0), "10.0.0.1", 1)
        },
    );
    f.applied(A, &Lease::ack(m(0), "10.0.0.2", 2));
    let (one, two) = (f.owner(1), f.owner(2));
    let fixed = import(
        &f,
        CUSTOMER,
        import_row("asset-9", &[], &[(&default, "10.0.0.9")]),
    );
    set_activity(&f, &default, "10.0.0.50", m(1), m(20));
    let search = |text: &str| -> Vec<(DaiSearchMatchKind, DaiSearchTarget)> {
        let result = f.store.dai_search(CUSTOMER, text, NOW).unwrap();
        assert!(!result.truncated);
        result
            .matches
            .into_iter()
            .map(|found| (found.matched, found.target))
            .collect()
    };
    let device = |kind, id| vec![(kind, DaiSearchTarget::Device(id))];

    assert_eq!(search("10.0.0.1"), device(DaiSearchMatchKind::Ip, one));
    assert_eq!(search(" 10.0.0.9 "), device(DaiSearchMatchKind::Ip, fixed));
    assert_eq!(
        search("10.0.0.50"),
        [(
            DaiSearchMatchKind::Ip,
            DaiSearchTarget::IpDevice {
                site: default.clone(),
                ip: ip("10.0.0.50"),
                last_seen: m(20),
            }
        )]
    );
    for text in [
        "02:00:00:00:00:01",
        "02-00-00-00-00-01",
        "0200.0000.0001",
        "02:0A:00:00:00:01",
    ] {
        let expected = if text.contains('A') {
            Vec::new()
        } else {
            device(DaiSearchMatchKind::Mac, one)
        };
        assert_eq!(search(text), expected, "{text}");
    }
    f.applied(A, &Lease::ack(m(0), "10.0.0.10", 0xab));
    let upper = f.owner(0xab);
    assert_eq!(
        search("02:00:00:00:00:AB"),
        device(DaiSearchMatchKind::Mac, upper)
    );
    assert_eq!(
        search("0200.0000.00AB"),
        device(DaiSearchMatchKind::Mac, upper)
    );
    assert_eq!(
        search("asset-9"),
        device(DaiSearchMatchKind::AssetId, fixed)
    );
    assert_none(&search("asset"));
    // An asset id is matched as given, its spaces included.
    let spaced = import(&f, CUSTOMER, import_row(" asset-9 ", &[], &[]));
    assert_eq!(
        search(" asset-9 "),
        device(DaiSearchMatchKind::AssetId, spaced)
    );
    assert_eq!(
        search("asset-9"),
        device(DaiSearchMatchKind::AssetId, fixed)
    );
    assert_eq!(
        search(&one.to_string()),
        device(DaiSearchMatchKind::DeviceId, one)
    );
    assert_eq!(search("alpha-h"), device(DaiSearchMatchKind::Name, one));
    assert_eq!(search("ALPHA"), device(DaiSearchMatchKind::Name, one));
    assert_none(&search(""));

    f.store.merge_dai_devices(CUSTOMER, one, &[two]).unwrap();
    assert_eq!(
        search(&two.to_string()),
        device(DaiSearchMatchKind::OldDeviceId, one)
    );
    // The absorbed device's binding now names the survivor.
    assert_eq!(search("10.0.0.2"), device(DaiSearchMatchKind::Ip, one));

    // A MAC an import removed belongs to no device.
    f.applied(A, &Lease::ack(m(0), "10.0.0.5", 5));
    let five = f.owner(5);
    assert_eq!(import(&f, CUSTOMER, import_row("asset-5", &[5], &[])), five);
    assert_eq!(
        search("02:00:00:00:00:05"),
        device(DaiSearchMatchKind::Mac, five)
    );
    assert_eq!(import(&f, CUSTOMER, import_row("asset-5", &[], &[])), five);
    assert_none(&search("02:00:00:00:00:05"));
}

#[test]
fn search_by_ip_finds_rows_under_tokens_no_site_holds() {
    let f = setup();
    f.store.ensure_default_site(CUSTOMER).unwrap();
    f.applied(A, &Lease::ack(m(0), "10.0.0.1", 1));
    let one = f.owner(1);
    let search = |text: &str| f.store.dai_search(CUSTOMER, text, NOW).unwrap();
    // Rows stored under tokens the site table does not hold, as a removed
    // site leaves them, one token a prefix of the other.
    f.put(
        super::super::super::DAI_BINDINGS,
        &binding_key(CUSTOMER, "gone", ip("10.0.0.60"), m(0)),
        &BindingRow {
            end: None,
            device: one,
            evidence_kind: 1,
            evidence_identifier: mac_id(1),
            server_id: None,
            last_strong: m(0),
            inactivity: 10 * MINUTE,
            end_estimated: false,
        },
    );
    set_activity(&f, "gone2", "10.0.0.60", m(1), m(20));
    assert_eq!(
        search("10.0.0.60").matches,
        [
            DaiSearchMatch {
                matched: DaiSearchMatchKind::Ip,
                target: DaiSearchTarget::Device(one),
            },
            DaiSearchMatch {
                matched: DaiSearchMatchKind::Ip,
                target: DaiSearchTarget::IpDevice {
                    site: "gone2".to_string(),
                    ip: ip("10.0.0.60"),
                    last_seen: m(20),
                },
            },
        ]
    );
}

#[test]
fn search_returns_at_most_the_limit() {
    let f = setup();
    let rows: Vec<DaiImportRow> = (0..=DAI_SEARCH_MAX_MATCHES)
        .map(|n| DaiImportRow {
            name: Some(format!("bulk device {n:03}")),
            ..import_row(&format!("bulk-{n}"), &[], &[])
        })
        .collect();
    f.store.import_dai_devices(CUSTOMER, &rows).unwrap();
    let all = f.store.dai_search(CUSTOMER, "Bulk", NOW).unwrap();
    assert_eq!(all.matches.len(), DAI_SEARCH_MAX_MATCHES);
    assert!(all.truncated);
    let one = f
        .store
        .dai_search(CUSTOMER, "bulk device 007", NOW)
        .unwrap();
    assert_eq!(one.matches.len(), 1);
    assert!(!one.truncated);
}

// ---- The collection status ----

#[test]
#[allow(clippy::too_many_lines)] // One store, checked field by field.
fn the_collection_status_reports_sites_sensors_gaps_and_counters() {
    let f = setup();
    add_sensor_c(&f);
    let default = f.store.ensure_default_site(CUSTOMER).unwrap();
    let east = f
        .dai()
        .create_site(CUSTOMER, "east", &[C.to_string()], &(NOON - HOUR))
        .unwrap();
    collecting(&f, A, m(10));
    set_cursor(&f, A, Kind::DnsName, m(20), true);
    set_cursor(&f, B, Kind::DhcpLease, m(30), true);
    set_cursor(&f, B, Kind::Kerberos, m(30), false);
    set_last_record(&f, B, NOW - 2 * DAY);
    collecting(&f, C, m(40));
    let receipt = |sensor: &str, kind, time: i64| {
        f.put(
            super::super::super::DAI_SENSOR_KIND_STATE,
            &pair_key(sensor, kind),
            &time,
        );
    };
    receipt(A, Kind::DhcpLease, m(11));
    receipt(B, Kind::DhcpLease, m(15));
    receipt(A, Kind::Kerberos, m(12));
    receipt(C, Kind::Ntlm, m(13));
    set_gap(&f, C, Kind::DnsName, m(2), m(3));
    set_gap(&f, A, Kind::DhcpLease, m(1), m(4));
    set_gap(&f, D, Kind::DhcpLease, m(1), m(4));
    let dai = f.dai();
    let today = date_of(NOW).unwrap();
    for (customer, kind, time, count) in [
        (CUSTOMER, DaiCounterKind::SkippedByCatchup, NOW, 3),
        (CUSTOMER, DaiCounterKind::SkippedByCatchup, NOW - DAY, 2),
        (CUSTOMER, DaiCounterKind::RelaySiteUnknown, NOW, 1),
        (CUSTOMER, DaiCounterKind::FilteredAtReceipt, NOW, 4),
        (CUSTOMER, DaiCounterKind::NotApplied, NOW, 5),
        (OTHER, DaiCounterKind::NotApplied, NOW, 7),
    ] {
        dai.write(|txn| dai.add_counter(txn, customer, kind, time, count))
            .unwrap();
    }

    let status = f.store.dai_collection_status(CUSTOMER, NOW).unwrap();
    let mut tokens = vec![default.clone(), east.clone()];
    tokens.sort_unstable();
    assert_eq!(
        status
            .sites
            .iter()
            .map(|s| s.site.clone())
            .collect::<Vec<_>>(),
        tokens
    );
    let site = |token: &str| status.sites.iter().find(|s| s.site == token).unwrap();
    let receipts = |token: &str| -> Vec<(Kind, Option<i64>, Option<String>)> {
        site(token)
            .receipts
            .iter()
            .map(|r| (r.kind, r.time, r.sensor.clone()))
            .collect()
    };
    assert_eq!(
        receipts(&default),
        [
            (Kind::DhcpLease, Some(m(15)), Some(B.to_string())),
            (Kind::Kerberos, Some(m(12)), Some(A.to_string())),
            (Kind::Ntlm, None, None),
        ]
    );
    assert_eq!(
        receipts(&east),
        [
            (Kind::DhcpLease, None, None),
            (Kind::Kerberos, None, None),
            (Kind::Ntlm, Some(m(13)), Some(C.to_string())),
        ]
    );
    assert_eq!(site(&default).quiet_sensors, [B.to_string()]);
    assert_none(&site(&east).quiet_sensors);
    assert_eq!(
        site(&default).unsent_pairs,
        [(B.to_string(), Kind::Kerberos)]
    );
    assert_none(&site(&east).unsent_pairs);

    // The customer sensors only, not a name two customers' nodes give.
    let sensors: Vec<(&str, Option<&str>, Option<i64>)> = status
        .sensors
        .iter()
        .map(|s| (s.sensor.as_str(), s.site.as_deref(), s.last_record_time))
        .collect();
    assert_eq!(
        sensors,
        [
            (A, Some(default.as_str()), Some(m(10))),
            (B, Some(default.as_str()), Some(NOW - 2 * DAY)),
            (C, Some(east.as_str()), Some(m(40))),
        ]
    );
    let lags: Vec<(Kind, i64, i64)> = status.sensors[0]
        .cursors
        .iter()
        .map(|c| (c.kind, c.cursor, c.lag))
        .collect();
    assert_eq!(
        lags,
        [
            (Kind::DhcpLease, m(10), NOW - m(10)),
            (Kind::Kerberos, m(10), NOW - m(10)),
            (Kind::Ntlm, m(10), NOW - m(10)),
            (Kind::DnsName, m(20), NOW - m(20)),
        ]
    );

    let gaps: Vec<(&str, Kind, i64, i64)> = status
        .catchup_gaps
        .iter()
        .map(|g| (g.sensor.as_str(), g.kind, g.start, g.end))
        .collect();
    assert_eq!(
        gaps,
        [
            (A, Kind::DhcpLease, m(1), m(4)),
            (C, Kind::DnsName, m(2), m(3)),
        ]
    );
    let counts = |list: &[crate::DaiDailyCount]| -> Vec<(i32, u64)> {
        list.iter().map(|c| (c.date, c.count)).collect()
    };
    assert_eq!(
        counts(&status.skipped_by_catchup),
        [(today - 1, 2), (today, 3)]
    );
    assert_eq!(counts(&status.relay_site_unknown), [(today, 1)]);
    assert_eq!(counts(&status.filtered_at_receipt), [(today, 4)]);
    assert_eq!(counts(&status.not_applied), [(today, 5)]);
    assert_eq!(
        status.candidate_ranges,
        f.store.dai_range_candidates(CUSTOMER, NOW).unwrap().len()
    );
}
