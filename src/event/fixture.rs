//! Synthetic detection events shared by the event tests.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use jiff::Timestamp;
use review_protocol::types::{
    Detail, DetectionEvent, DetectionModel, EndpointRole, EventCategory, PortScanDetail,
    PrimarySubject, RawEventBody, RawEventKind, RelatedIp, Target, ThreatRole, TimeWindow,
    raw_event,
};

use super::{DetectionEventStamp, StoredDetectionEvent, record};
use crate::{ModelInstance, Store, test::DbGuard};

/// The sensor most fixtures name.
pub(crate) const SENSOR: &str = "sensor-1";

/// A country lookup with fixed answers; an address it does not know is
/// [`crate::COUNTRY_CODE_UNKNOWN`].
#[derive(Default)]
pub(crate) struct FakeCountryLookup {
    pub(crate) codes: HashMap<IpAddr, [u8; 2]>,
}

impl crate::geo::CountryLookup for FakeCountryLookup {
    fn lookup_country_code(&self, addr: IpAddr) -> [u8; 2] {
        self.codes
            .get(&addr)
            .copied()
            .unwrap_or(crate::util::COUNTRY_CODE_UNKNOWN)
    }
}

pub(crate) fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
    let permit = crate::test::acquire_db_permit();
    let db_dir = tempfile::tempdir().unwrap();
    let backup_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::new(db_dir.path(), backup_dir.path(), None).unwrap());
    (permit, store)
}

pub(crate) fn setup_store_with_lookup(lookup: FakeCountryLookup) -> (DbGuard<'static>, Arc<Store>) {
    let permit = crate::test::acquire_db_permit();
    let db_dir = tempfile::tempdir().unwrap();
    let backup_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::new_with_country_lookup(db_dir.path(), backup_dir.path(), Some(Arc::new(lookup)))
            .unwrap(),
    );
    (permit, store)
}

pub(crate) fn ip(text: &str) -> IpAddr {
    text.parse().expect("a test address")
}

pub(crate) fn at(nanos: i64) -> Timestamp {
    crate::timestamp::from_i64_nanos(nanos).expect("i64 nanoseconds fit a timestamp")
}

/// 2026-01-02T03:04:05Z.
pub(crate) fn time() -> Timestamp {
    crate::test::utc(2026, 1, 2, 3, 4, 5)
}

pub(crate) fn stamp() -> DetectionEventStamp {
    DetectionEventStamp {
        engine_instance: ModelInstance {
            node_id: 1,
            agent_key: "semi-supervised".to_string(),
        },
        clustering_model_id: None,
        trained_at: Some(crate::test::utc(2025, 12, 1, 0, 0, 0)),
        installed_version: Some("1.2.3".to_string()),
        installed_commit: Some("0123abcd".to_string()),
        config_revision: Some(7),
        clustering_model_type: None,
    }
}

pub(crate) fn conn_body(orig: IpAddr, resp: IpAddr) -> RawEventBody {
    RawEventBody::Conn(raw_event::Conn {
        orig_addr: orig,
        orig_port: 46378,
        resp_addr: resp,
        resp_port: 80,
        proto: 6,
        conn_state: "SF".to_string(),
        start_time: 1_700_000_000_000_000_000,
        duration: 1_234_567,
        service: "http".to_string(),
        orig_bytes: 77,
        resp_bytes: 295,
        orig_pkts: 3,
        resp_pkts: 4,
        orig_l2_bytes: 200,
        resp_l2_bytes: 400,
    })
}

pub(crate) fn http_body(orig: IpAddr, resp: IpAddr) -> RawEventBody {
    RawEventBody::Http(raw_event::Http {
        orig_addr: orig,
        orig_port: 50000,
        resp_addr: resp,
        resp_port: 80,
        proto: 6,
        start_time: 1_700_000_000_000_000_000,
        duration: 10,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 100,
        resp_l2_bytes: 100,
        method: "GET".to_string(),
        host: "example.com".to_string(),
        uri: "/index.html".to_string(),
        referer: String::new(),
        version: "1.1".to_string(),
        user_agent: "synthetic-agent".to_string(),
        request_len: 0,
        response_len: 1024,
        status_code: 200,
        status_msg: "OK".to_string(),
        username: String::new(),
        password: String::new(),
        cookie: String::new(),
        content_encoding: String::new(),
        content_type: "text/html".to_string(),
        cache_control: String::new(),
        filenames: vec!["index.html".to_string()],
        mime_types: vec!["text/html".to_string()],
        body: b"synthetic body".to_vec(),
        state: String::new(),
    })
}

pub(crate) fn dns_body(orig: IpAddr, resp: IpAddr) -> RawEventBody {
    RawEventBody::Dns(raw_event::Dns {
        orig_addr: orig,
        orig_port: 10000,
        resp_addr: resp,
        resp_port: 53,
        proto: 17,
        start_time: 1_700_000_000_000_000_000,
        duration: 0,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 80,
        resp_l2_bytes: 120,
        query: "example.com".to_string(),
        answer: vec!["192.0.2.80".to_string()],
        trans_id: 1,
        rtt: 1,
        qclass: 1,
        qtype: 1,
        rcode: 0,
        aa_flag: false,
        tc_flag: false,
        rd_flag: true,
        ra_flag: true,
        ttl: vec![60, 120],
    })
}

pub(crate) fn netflow5_body(src: IpAddr, dst: IpAddr) -> RawEventBody {
    RawEventBody::Netflow5(raw_event::Netflow5 {
        src_addr: src,
        dst_addr: dst,
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        input: 1,
        output: 2,
        d_pkts: 10,
        d_octets: 1500,
        first: 100,
        last: 200,
        src_port: 40000,
        dst_port: 443,
        tcp_flags: 0x18,
        prot: 6,
        tos: 0,
        src_as: 64512,
        dst_as: 64513,
        src_mask: 24,
        dst_mask: 24,
        sequence: 9,
        engine_type: 0,
        engine_id: 0,
        sampling_mode: 0,
        sampling_rate: 0,
    })
}

pub(crate) fn netflow9_body(orig: IpAddr, resp: IpAddr) -> RawEventBody {
    RawEventBody::Netflow9(raw_event::Netflow9 {
        sequence: 3,
        source_id: 5,
        template_id: 256,
        orig_addr: orig,
        orig_port: 40000,
        resp_addr: resp,
        resp_port: 8443,
        proto: 6,
        contents: "synthetic contents".to_string(),
    })
}

/// A Sysmon network-connect body. Its addresses are `source_ip` and
/// `destination_ip`, so it has no endpoint address.
pub(crate) fn network_connect_body(source: IpAddr, destination: IpAddr) -> RawEventBody {
    RawEventBody::NetworkConnect(raw_event::NetworkConnect {
        agent_name: "agent".to_string(),
        agent_id: "agent-id".to_string(),
        process_guid: "{guid}".to_string(),
        process_id: 4242,
        image: "C:\\synthetic.exe".to_string(),
        user: "user".to_string(),
        protocol: "tcp".to_string(),
        initiated: true,
        source_is_ipv6: false,
        source_ip: source,
        source_hostname: "src-host".to_string(),
        source_port: 50000,
        source_port_name: String::new(),
        destination_is_ipv6: false,
        destination_ip: destination,
        destination_hostname: "dst-host".to_string(),
        destination_port: 443,
        destination_port_name: "https".to_string(),
    })
}

/// Returns the kind of a body.
pub(crate) fn kind_of(body: &RawEventBody) -> RawEventKind {
    match body {
        RawEventBody::Conn(_) => RawEventKind::Conn,
        RawEventBody::Dns(_) => RawEventKind::Dns,
        RawEventBody::Http(_) => RawEventKind::Http,
        RawEventBody::Netflow5(_) => RawEventKind::Netflow5,
        RawEventBody::Netflow9(_) => RawEventKind::Netflow9,
        RawEventBody::NetworkConnect(_) => RawEventKind::NetworkConnect,
        other => panic!("no fixture kind for {other:?}"),
    }
}

/// A `NonBrowser` detection about one raw event at `time` from `sensor`.
pub(crate) fn raw_event_event(time: Timestamp, sensor: &str, body: RawEventBody) -> DetectionEvent {
    DetectionEvent {
        time,
        sensor: Some(sensor.to_string()),
        detection_model: DetectionModel::NonBrowser,
        raw_event_kind: kind_of(&body),
        category: Some(EventCategory::CommandAndControl),
        target: Target::RawEvent { time, body },
        score: 0.75,
        detail: Detail::NonBrowser,
    }
}

/// A conn raw event detection at [`time`] from [`SENSOR`].
pub(crate) fn conn_event(orig: &str, resp: &str) -> DetectionEvent {
    raw_event_event(time(), SENSOR, conn_body(ip(orig), ip(resp)))
}

pub(crate) fn related(addr: &str, role: EndpointRole) -> RelatedIp {
    RelatedIp { ip: ip(addr), role }
}

pub(crate) fn host(addr: &str) -> PrimarySubject {
    PrimarySubject::Host {
        ip: ip(addr),
        role: ThreatRole::Actor,
    }
}

/// A `PortScan` detection about `primary`, from [`SENSOR`] at [`time`].
pub(crate) fn subject_event(
    primary: PrimarySubject,
    related_ips: Vec<RelatedIp>,
) -> DetectionEvent {
    let time = time();
    DetectionEvent {
        time,
        sensor: Some(SENSOR.to_string()),
        detection_model: DetectionModel::PortScan,
        raw_event_kind: RawEventKind::Conn,
        category: Some(EventCategory::Reconnaissance),
        target: Target::Subject {
            primary,
            related_ips,
            window: TimeWindow {
                start: time
                    .checked_sub(jiff::SignedDuration::from_secs(60))
                    .expect("in range"),
                end: time,
            },
        },
        score: 3.0,
        detail: Detail::PortScan(PortScanDetail {
            resp_ports: vec![22, 80],
            proto: 6,
        }),
    }
}

/// Returns `event` as a stored record with unresolved country codes.
pub(crate) fn stored(event: DetectionEvent) -> StoredDetectionEvent {
    let country_codes = record::country_codes(&event, None);
    StoredDetectionEvent {
        event,
        stamp: stamp(),
        country_codes,
    }
}

/// Returns `event` as a stored record with the codes `lookup` gives.
pub(crate) fn stored_with(
    event: DetectionEvent,
    codes: &[(&str, [u8; 2])],
) -> StoredDetectionEvent {
    let lookup = FakeCountryLookup {
        codes: codes.iter().map(|(addr, code)| (ip(addr), *code)).collect(),
    };
    let country_codes = record::country_codes(&event, Some(&lookup));
    StoredDetectionEvent {
        event,
        stamp: stamp(),
        country_codes,
    }
}
