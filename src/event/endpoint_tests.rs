//! Tests of detection events about an endpoint, and of raw-event detection
//! events whose body carries a host header.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use review_protocol::types::{
    EndpointRole::{Destination, Source},
    RelatedIp,
};

use super::{
    EventFilter, FlowKind, InternalNetworks, RawEventKey, StoredDetectionEvent,
    TimeSeriesPolicySensors, TrafficDirection,
    fixture::{
        FakeCountryLookup, HEADER_DEFAULT_ROUTE, HEADER_IPS, SENSOR, endpoint_event,
        endpoint_sensor, header_bodies, host, ip, kind_of, raw_event_event, related, setup_store,
        setup_store_with_lookup, stamp, stored, stored_with, subject_event, time,
    },
};
use crate::{HostNetworkGroup, types::Endpoint};

const A: &str = "10.0.0.1";
const B: &str = "10.0.0.2";
/// An address that is neither an endpoint IP nor a related IP.
const OTHER: &str = "10.0.0.99";
/// A source-side related IP outside the endpoint's `ips`.
const SRC: &str = "203.0.113.1";
/// A destination-side related IP outside the endpoint's `ips`.
const DST: &str = "203.0.113.2";
/// A default route address in neither `ips` nor the related IPs.
const ROUTE: &str = "10.0.0.254";

fn empty() -> EventFilter {
    EventFilter::new(
        None, None, None, None, None, None, None, None, None, None, None, None, None,
    )
}

fn selects(record: &StoredDetectionEvent, filter: &EventFilter) -> bool {
    record.matches(filter).unwrap().0
}

fn originator(addr: &str) -> EventFilter {
    EventFilter {
        originator: Some(ip(addr)),
        ..empty()
    }
}

fn responder(addr: &str) -> EventFilter {
    EventFilter {
        responder: Some(ip(addr)),
        ..empty()
    }
}

fn endpoints(direction: Option<TrafficDirection>, addr: &str) -> EventFilter {
    EventFilter {
        endpoints: Some(vec![Endpoint {
            direction,
            network: group(&[&format!("{addr}/32")]),
        }]),
        ..empty()
    }
}

fn group(nets: &[&str]) -> HostNetworkGroup {
    HostNetworkGroup::new(
        Vec::new(),
        nets.iter().map(|net| net.parse().unwrap()).collect(),
        Vec::new(),
    )
}

/// A `directions` filter with every flow kind, whose internal networks for
/// `sensor` are `internal`.
fn directions_for(sensor: &str, kinds: Vec<FlowKind>, internal: &[&str]) -> EventFilter {
    EventFilter {
        directions: Some((
            kinds,
            InternalNetworks::PerSensor(HashMap::from([(
                sensor.to_string(),
                vec![group(internal)],
            )])),
        )),
        ..empty()
    }
}

fn all_flows() -> Vec<FlowKind> {
    vec![FlowKind::Internal, FlowKind::Outbound, FlowKind::Inbound]
}

/// Returns the flow kinds `record` is selected by when `internal` are the
/// internal networks of its sensor.
fn flows(record: &StoredDetectionEvent, internal: &[&str]) -> Vec<FlowKind> {
    let sensor = record.event().sensor.clone().unwrap();
    all_flows()
        .into_iter()
        .filter(|kind| selects(record, &directions_for(&sensor, vec![*kind], internal)))
        .collect()
}

fn countries(codes: Vec<[u8; 2]>) -> EventFilter {
    EventFilter {
        countries: Some(codes),
        ..empty()
    }
}

/// Returns whether `addr` matches each of the address conditions for
/// `record`: originator, responder, `endpoints` from, to and either way,
/// and `directions` with `addr` the only internal address.
fn address_matches(record: &StoredDetectionEvent, addr: &str) -> [bool; 6] {
    let sensor = record.event().sensor.clone().unwrap_or_default();
    [
        selects(record, &originator(addr)),
        selects(record, &responder(addr)),
        selects(record, &endpoints(Some(TrafficDirection::From), addr)),
        selects(record, &endpoints(Some(TrafficDirection::To), addr)),
        selects(record, &endpoints(None, addr)),
        selects(
            record,
            &directions_for(&sensor, all_flows(), &[&format!("{addr}/32")]),
        ),
    ]
}

/// Matches as a subject IP: on both sides.
const BOTH_SIDES: [bool; 6] = [true, true, true, true, true, true];
/// Matches as a source-side IP only.
const SOURCE_SIDE: [bool; 6] = [true, false, true, false, true, true];
/// Matches as a destination-side IP only.
const DESTINATION_SIDE: [bool; 6] = [false, true, false, true, true, true];
/// Matches no address condition.
const NO_SIDE: [bool; 6] = [false; 6];

fn endpoint_record(
    ips: &[&str],
    route: Option<&str>,
    related_ips: Vec<RelatedIp>,
) -> StoredDetectionEvent {
    stored(endpoint_event(ips, route, related_ips))
}

#[test]
fn every_endpoint_ip_matches_both_sides_and_related_ips_keep_their_role() {
    let record = endpoint_record(
        &[A, B],
        Some(ROUTE),
        vec![related(SRC, Source), related(DST, Destination)],
    );
    assert_eq!(address_matches(&record, A), BOTH_SIDES);
    assert_eq!(address_matches(&record, B), BOTH_SIDES);
    assert_eq!(address_matches(&record, SRC), SOURCE_SIDE);
    assert_eq!(address_matches(&record, DST), DESTINATION_SIDE);
    assert_eq!(address_matches(&record, OTHER), NO_SIDE);
    // The default route address adds no address of its own.
    assert_eq!(address_matches(&record, ROUTE), NO_SIDE);

    // Two different endpoint IPs select the event together.
    assert!(selects(
        &record,
        &EventFilter {
            originator: Some(ip(A)),
            responder: Some(ip(B)),
            ..empty()
        }
    ));
}

#[test]
fn a_default_route_equal_to_a_related_ip_matches_only_by_its_role() {
    let record = endpoint_record(&[A], Some(SRC), vec![related(SRC, Source)]);
    assert_eq!(address_matches(&record, SRC), SOURCE_SIDE);
    assert_eq!(address_matches(&record, A), BOTH_SIDES);

    let record = endpoint_record(&[A], Some(DST), vec![related(DST, Destination)]);
    assert_eq!(address_matches(&record, DST), DESTINATION_SIDE);
}

#[test]
fn directions_classify_endpoint_ips_as_internal_on_both_sides() {
    let record = endpoint_record(
        &[A, B],
        Some(ROUTE),
        vec![related(SRC, Source), related(DST, Destination)],
    );
    // Only an endpoint IP is internal: it is on both sides.
    assert_eq!(flows(&record, &[&format!("{B}/32")]), [FlowKind::Internal]);
    // Only a related IP is internal: by its role.
    assert_eq!(
        flows(&record, &[&format!("{SRC}/32")]),
        [FlowKind::Outbound]
    );
    assert_eq!(flows(&record, &[&format!("{DST}/32")]), [FlowKind::Inbound]);
    // Neither the default route nor another address is internal.
    assert_eq!(flows(&record, &[&format!("{ROUTE}/32")]), Vec::new());
    assert_eq!(flows(&record, &[&format!("{OTHER}/32")]), Vec::new());

    // The internal networks are those of the endpoint-id sensor.
    let other_sensor = directions_for(SENSOR, all_flows(), &["0.0.0.0/0"]);
    assert!(!selects(&record, &other_sensor));
}

#[test]
fn a_country_code_is_stored_for_each_endpoint_ip_before_the_related_ips() {
    let record = stored_with(
        endpoint_event(
            &[B, A],
            Some(ROUTE),
            vec![related(DST, Destination), related(SRC, Source)],
        ),
        &[
            (A, *b"KR"),
            (B, *b"US"),
            (SRC, *b"DE"),
            (DST, *b"JP"),
            (ROUTE, *b"FR"),
        ],
    );
    assert_eq!(
        record.country_codes().collect::<Vec<_>>(),
        [
            (ip(B), *b"US"),
            (ip(A), *b"KR"),
            (ip(DST), *b"JP"),
            (ip(SRC), *b"DE"),
        ]
    );
    for code in [*b"US", *b"KR", *b"JP", *b"DE"] {
        assert!(selects(&record, &countries(vec![code])), "{code:?}");
    }
    assert!(!selects(&record, &countries(vec![*b"FR"])));
    assert!(!selects(
        &record,
        &countries(vec![crate::COUNTRY_CODE_UNKNOWN])
    ));
}

fn pairs(record: &StoredDetectionEvent) -> HashMap<(IpAddr, IpAddr), usize> {
    let mut pairs = HashMap::new();
    record.count_ip_address_pair(&mut pairs, &empty()).unwrap();
    pairs
}

fn pair_set(entries: &[(&str, &str)]) -> HashMap<(IpAddr, IpAddr), usize> {
    entries
        .iter()
        .map(|(orig, resp)| ((ip(orig), ip(resp)), 1))
        .collect()
}

#[test]
fn endpoint_pairs_come_from_where_each_address_came_from() {
    let record = endpoint_record(
        &[A, B],
        Some(ROUTE),
        vec![related(SRC, Source), related(DST, Destination)],
    );
    let expected = pair_set(&[
        (A, A),
        (B, B),
        (SRC, A),
        (SRC, B),
        (A, DST),
        (B, DST),
        (SRC, DST),
    ]);
    assert_eq!(pairs(&record), expected);

    let mut with_model = HashMap::new();
    record
        .count_ip_address_pair_and_detection_model(&mut with_model, &empty())
        .unwrap();
    let model = record.event().detection_model;
    assert_eq!(
        with_model.keys().copied().collect::<HashSet<_>>(),
        expected
            .keys()
            .map(|&(orig, resp)| (orig, resp, model))
            .collect::<HashSet<_>>()
    );

    // A source-side related IP equal to an endpoint IP pairs with every
    // endpoint IP as a related IP; the reverse pair does not appear.
    let record = endpoint_record(&[A, B], None, vec![related(A, Source)]);
    assert_eq!(pairs(&record), pair_set(&[(A, A), (B, B), (A, B)]));
    assert!(!pairs(&record).contains_key(&(ip(B), ip(A))));

    // An endpoint with no IP pairs its related IPs only.
    let record = endpoint_record(
        &[],
        None,
        vec![related(SRC, Source), related(DST, Destination)],
    );
    assert_eq!(pairs(&record), pair_set(&[(SRC, DST)]));
    let record = endpoint_record(&[], None, vec![related(SRC, Source)]);
    assert_eq!(pairs(&record), HashMap::new());
}

#[test]
fn host_pairs_are_the_product_of_the_two_sides() {
    let record = stored(subject_event(
        host(A),
        vec![related(SRC, Source), related(DST, Destination)],
    ));
    assert_eq!(
        pairs(&record),
        pair_set(&[(A, A), (A, DST), (SRC, A), (SRC, DST)])
    );
}

#[test]
fn endpoint_ips_count_as_addresses_on_both_sides() {
    let record = endpoint_record(&[A, B], Some(ROUTE), vec![related(SRC, Source)]);
    let mut all = HashMap::new();
    record.count_ip_address(&mut all, &empty()).unwrap();
    assert_eq!(all, HashMap::from([(ip(A), 1), (ip(B), 1), (ip(SRC), 1)]));
    let mut origs = HashMap::new();
    record
        .count_originator_ip_address(&mut origs, &empty())
        .unwrap();
    assert_eq!(origs, HashMap::from([(ip(A), 1), (ip(B), 1), (ip(SRC), 1)]));
    let mut resps = HashMap::new();
    record
        .count_responder_ip_address(&mut resps, &empty())
        .unwrap();
    assert_eq!(resps, HashMap::from([(ip(A), 1), (ip(B), 1)]));
}

#[test]
fn header_bodies_have_no_endpoint_address() {
    let header_addrs = [HEADER_IPS[0], HEADER_IPS[1], HEADER_DEFAULT_ROUTE];
    for body in header_bodies() {
        let kind = kind_of(&body);
        let record = stored_with(
            raw_event_event(time(), &endpoint_sensor(), body),
            &[
                (HEADER_IPS[0], *b"KR"),
                (HEADER_IPS[1], *b"KR"),
                (HEADER_DEFAULT_ROUTE, *b"KR"),
            ],
        );
        assert_eq!(record.country_codes().count(), 0, "{kind:?}");
        assert_eq!(record.stored_country_codes(), &[] as &[[u8; 2]], "{kind:?}");
        for addr in header_addrs {
            assert_eq!(address_matches(&record, addr), NO_SIDE, "{kind:?} {addr}");
        }
        assert!(
            !selects(
                &record,
                &directions_for(&endpoint_sensor(), all_flows(), &["0.0.0.0/0", "::/0"])
            ),
            "{kind:?}"
        );
        assert!(
            !selects(
                &record,
                &countries(vec![
                    *b"KR",
                    crate::COUNTRY_CODE_UNRESOLVED,
                    crate::COUNTRY_CODE_UNKNOWN
                ])
            ),
            "{kind:?}"
        );
        assert_eq!(pairs(&record), HashMap::new(), "{kind:?}");
        // The record is still selected when no address condition is set.
        assert!(selects(&record, &empty()), "{kind:?}");
    }
}

#[test]
fn an_endpoint_event_is_stored_and_read_back() {
    let lookup = FakeCountryLookup {
        codes: HashMap::from([(ip(A), *b"KR"), (ip(B), *b"US"), (ip(SRC), *b"DE")]),
    };
    let (_permit, store) = setup_store_with_lookup(lookup);
    let db = store.events();
    let event = endpoint_event(&[A, B], Some(A), vec![related(SRC, Source)]);
    let key = db.put(&event, &stamp()).unwrap();

    let read: Vec<_> = db.iter_forward().map(Result::unwrap).collect();
    assert_eq!(read.len(), 1);
    let (read_key, record) = &read[0];
    assert_eq!(*read_key, key);
    assert_eq!(record.event(), &event);
    assert_eq!(record.stamp(), &stamp());
    assert_eq!(
        record.country_codes().collect::<Vec<_>>(),
        [(ip(A), *b"KR"), (ip(B), *b"US"), (ip(SRC), *b"DE")]
    );

    let page = db
        .read_by_arrival(&empty(), None, usize::MAX, usize::MAX)
        .unwrap();
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].0, key);
    assert_eq!(page.events[0].1.event(), &event);
}

fn sensors(sensors: &[&str]) -> EventFilter {
    EventFilter {
        sensors: Some((
            sensors.iter().map(ToString::to_string).collect(),
            TimeSeriesPolicySensors::new(HashMap::new()),
        )),
        ..empty()
    }
}

#[test]
fn endpoint_events_are_selected_looked_up_and_removed_by_the_endpoint_id() {
    let (_permit, store) = setup_store();
    let db = store.events();
    let endpoint = endpoint_sensor();
    let after = |secs| {
        time()
            .checked_add(jiff::SignedDuration::from_secs(secs))
            .unwrap()
    };

    let subject = endpoint_event(&[A], None, Vec::new());
    db.put(&subject, &stamp()).unwrap();
    let raw_times: Vec<_> = header_bodies()
        .into_iter()
        .zip(1..)
        .map(|(body, offset)| {
            let time = after(offset);
            let kind = kind_of(&body);
            db.put(&raw_event_event(time, &endpoint, body), &stamp())
                .unwrap();
            (kind, time)
        })
        .collect();
    let mut other = subject_event(host(A), Vec::new());
    other.time = after(100);
    db.put(&other, &stamp()).unwrap();

    let page = db
        .read_by_arrival(&sensors(&[&endpoint]), None, usize::MAX, usize::MAX)
        .unwrap();
    assert_eq!(page.events.len(), 1 + raw_times.len());
    assert!(
        page.events
            .iter()
            .all(|(_, record)| record.event().sensor.as_deref() == Some(endpoint.as_str()))
    );
    let page = db
        .read_by_arrival(&sensors(&[SENSOR]), None, usize::MAX, usize::MAX)
        .unwrap();
    assert_eq!(page.events.len(), 1);
    // The sensor is the lowercase form; another spelling selects nothing.
    let page = db
        .read_by_arrival(
            &sensors(&[&endpoint.to_uppercase()]),
            None,
            usize::MAX,
            usize::MAX,
        )
        .unwrap();
    assert_eq!(page.events.len(), 0);

    let keys: Vec<RawEventKey> = raw_times
        .iter()
        .map(|&(raw_event_kind, time)| RawEventKey {
            raw_event_kind,
            sensor: endpoint.clone(),
            time,
        })
        .collect();
    let found = db.find_by_raw_event_keys(&keys).unwrap();
    for (list, key) in found.iter().zip(&keys) {
        assert_eq!(list.len(), 1, "{:?}", key.raw_event_kind);
        assert_eq!(list[0].1.event().raw_event_kind, key.raw_event_kind);
        assert_eq!(list[0].1.event().time, key.time);
    }

    db.remove_by_sensors(std::slice::from_ref(&endpoint))
        .unwrap();
    let left: Vec<_> = db
        .iter_forward()
        .map(|item| item.unwrap().1.into_parts().0)
        .collect();
    assert_eq!(left, [other]);
    let page = db
        .read_by_arrival(&empty(), None, usize::MAX, usize::MAX)
        .unwrap();
    assert_eq!(page.events.len(), 1);
}
