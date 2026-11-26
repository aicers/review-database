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
    raw_event::{
        self, AuditRecord, CollectionMode, EndpointHeader, EventData, LogField, LogValue,
        NetStateSource, OsFamily,
    },
};
use uuid::Uuid;

use super::{DetectionEventStamp, StoredDetectionEvent, record};
use crate::{ModelInstance, Store, test::DbGuard};

/// The sensor most fixtures name.
pub(crate) const SENSOR: &str = "sensor-1";

/// The endpoint id of the endpoint fixtures.
pub(crate) const ENDPOINT_ID: Uuid = Uuid::from_u128(0x0f1e_2d3c_4b5a_6978_8796_a5b4_c3d2_e1f0);

/// The sensor of an event about [`ENDPOINT_ID`]: its lowercase hyphenated
/// form.
pub(crate) fn endpoint_sensor() -> String {
    ENDPOINT_ID.to_string()
}

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
        endpoint: None,
    })
}

/// The host header of an endpoint record from [`ENDPOINT_ID`], with the
/// addresses `ips` and the default route address `default_route_ip`.
pub(crate) fn endpoint_header(ips: &[&str], default_route_ip: Option<&str>) -> EndpointHeader {
    EndpointHeader {
        endpoint_id: ENDPOINT_ID,
        stream: Uuid::from_u128(0x1111),
        seq: 42,
        event_time: 1_700_000_000_000_000_000,
        collected_at: 1_700_000_000_500_000_000,
        clock_offset: None,
        hostname: "endpoint-host".to_string(),
        ips: ips.iter().map(|addr| ip(addr)).collect(),
        default_route_ip: default_route_ip.map(ip),
        net_state_source: NetStateSource::Observed,
        os_family: OsFamily::Windows,
        os_version: "10.0.19045".to_string(),
        collection_mode: CollectionMode::Extended,
        process_key: None,
        schema: 1,
    }
}

/// The addresses of the host header of [`header_bodies`].
pub(crate) const HEADER_IPS: [&str; 2] = ["10.20.0.5", "2001:db8:20::5"];

/// The default route address of the host header of [`header_bodies`].
pub(crate) const HEADER_DEFAULT_ROUTE: &str = "10.20.0.1";

fn header() -> EndpointHeader {
    endpoint_header(&HEADER_IPS, Some(HEADER_DEFAULT_ROUTE))
}

/// A Sysmon network-connect body with a host header, whose `source_ip` and
/// `destination_ip` are header addresses.
pub(crate) fn network_connect_body_with_header() -> RawEventBody {
    let RawEventBody::NetworkConnect(mut body) =
        network_connect_body(ip(HEADER_IPS[0]), ip(HEADER_DEFAULT_ROUTE))
    else {
        unreachable!("network_connect_body returns a NetworkConnect body")
    };
    body.endpoint = Some(header());
    RawEventBody::NetworkConnect(body)
}

pub(crate) fn process_create_body(logon_id_full: Option<u64>) -> raw_event::ProcessCreate {
    raw_event::ProcessCreate {
        agent_name: "agent".to_string(),
        agent_id: "agent-id".to_string(),
        process_guid: "{process}".to_string(),
        process_id: 100,
        image: "C:\\synthetic.exe".to_string(),
        file_version: "1.0".to_string(),
        description: "synthetic".to_string(),
        product: "product".to_string(),
        company: "company".to_string(),
        original_file_name: "synthetic.exe".to_string(),
        command_line: "synthetic.exe /run".to_string(),
        current_directory: "C:\\".to_string(),
        user: "user".to_string(),
        logon_guid: "{logon}".to_string(),
        logon_id: u32::MAX,
        terminal_session_id: 1,
        integrity_level: "High".to_string(),
        hashes: vec!["SHA256=00".to_string()],
        parent_process_guid: "{parent}".to_string(),
        parent_process_id: 99,
        parent_image: "C:\\parent.exe".to_string(),
        parent_command_line: "parent.exe".to_string(),
        parent_user: "user".to_string(),
        endpoint: logon_id_full.map(|_| header()),
        logon_id_full,
    }
}

pub(crate) fn driver_load_body() -> raw_event::DriverLoad {
    raw_event::DriverLoad {
        agent_name: "agent".to_string(),
        agent_id: "agent-id".to_string(),
        image_loaded: "C:\\driver.sys".to_string(),
        hashes: vec!["SHA256=01".to_string(), "MD5=02".to_string()],
        signed: true,
        signature: "Vendor".to_string(),
        signature_status: "Valid".to_string(),
        endpoint: Some(header()),
    }
}

pub(crate) fn create_remote_thread_body() -> raw_event::CreateRemoteThread {
    raw_event::CreateRemoteThread {
        agent_name: "agent".to_string(),
        agent_id: "agent-id".to_string(),
        source_process_guid: "{source}".to_string(),
        source_process_id: 11,
        source_image: "C:\\source.exe".to_string(),
        target_process_guid: "{target}".to_string(),
        target_process_id: 12,
        target_image: "C:\\target.exe".to_string(),
        new_thread_id: 13,
        start_address: "0x7ff0".to_string(),
        start_module: "kernel32.dll".to_string(),
        start_function: "LoadLibraryW".to_string(),
        source_user: "source-user".to_string(),
        target_user: "target-user".to_string(),
        endpoint: Some(header()),
    }
}

pub(crate) fn raw_access_read_body() -> raw_event::RawAccessRead {
    raw_event::RawAccessRead {
        agent_name: "agent".to_string(),
        agent_id: "agent-id".to_string(),
        process_guid: "{process}".to_string(),
        process_id: 21,
        image: "C:\\reader.exe".to_string(),
        device: "\\Device\\HarddiskVolume2".to_string(),
        user: "user".to_string(),
        endpoint: Some(header()),
    }
}

pub(crate) fn process_access_body() -> raw_event::ProcessAccess {
    raw_event::ProcessAccess {
        agent_name: "agent".to_string(),
        agent_id: "agent-id".to_string(),
        source_process_guid: "{source}".to_string(),
        source_process_id: 31,
        source_thread_id: 32,
        source_image: "C:\\source.exe".to_string(),
        target_process_guid: "{target}".to_string(),
        target_process_id: 33,
        target_image: "C:\\lsass.exe".to_string(),
        granted_access: 0x1_0000_1010,
        call_trace: "ntdll.dll+9d204".to_string(),
        source_user: "source-user".to_string(),
        target_user: "target-user".to_string(),
        endpoint: Some(header()),
    }
}

pub(crate) fn registry_object_add_del_body() -> raw_event::RegistryObjectAddDel {
    raw_event::RegistryObjectAddDel {
        agent_name: "agent".to_string(),
        agent_id: "agent-id".to_string(),
        event_type: "CreateKey".to_string(),
        process_guid: "{process}".to_string(),
        process_id: 41,
        image: "C:\\reg.exe".to_string(),
        target_object: "HKLM\\Software\\Synthetic".to_string(),
        user: "user".to_string(),
        endpoint: Some(header()),
    }
}

/// A Windows event log body with every optional field set.
pub(crate) fn windows_event_log_body() -> raw_event::WindowsEventLog {
    raw_event::WindowsEventLog {
        channel: Some("Security".to_string()),
        provider: Some("Microsoft-Windows-Security-Auditing".to_string()),
        event_id: Some(4624),
        version: Some(2),
        level: Some(4),
        task: Some(12544),
        opcode: Some(0),
        keywords: Some(0x8020_0000_0000_0000),
        record_id: Some(123_456_789_012),
        computer: Some("endpoint-host".to_string()),
        user_sid: Some("S-1-5-18".to_string()),
        event_data: Some(vec![
            EventData {
                name: Some("TargetUserName".to_string()),
                value: "alice".to_string(),
            },
            EventData {
                name: None,
                value: "line 1\n\tline 2".to_string(),
            },
            EventData {
                name: Some("Empty".to_string()),
                value: String::new(),
            },
        ]),
        user_data_xml: Some("<UserData/>".to_string()),
        endpoint: header(),
    }
}

pub(crate) fn text_field(name: &str, value: &str) -> LogField {
    LogField {
        name: name.to_string(),
        value: LogValue::Text(value.to_string()),
    }
}

pub(crate) fn bytes_field(name: &str, value: &[u8]) -> LogField {
    LogField {
        name: name.to_string(),
        value: LogValue::Bytes(value.to_vec()),
    }
}

pub(crate) fn journald_body() -> raw_event::Journald {
    raw_event::Journald {
        fields: Some(vec![
            text_field("MESSAGE", "session opened"),
            bytes_field("_BOOT_ID", &[0x0a, 0xbc, 0xff]),
            bytes_field("EMPTY", &[]),
        ]),
        endpoint: header(),
    }
}

pub(crate) fn auditd_body() -> raw_event::Auditd {
    raw_event::Auditd {
        serial: Some(9001),
        records: Some(vec![
            AuditRecord {
                record_type: "SYSCALL".to_string(),
                fields: vec![text_field("arch", "c000003e"), text_field("syscall", "59")],
            },
            AuditRecord {
                record_type: "EOE".to_string(),
                fields: Vec::new(),
            },
        ]),
        endpoint: header(),
    }
}

/// A body of each kind that carries a host header: a Sysmon body whose
/// header is `Some`, and one of each kind added with the endpoint header.
pub(crate) fn header_bodies() -> Vec<RawEventBody> {
    vec![
        network_connect_body_with_header(),
        RawEventBody::ProcessCreate(process_create_body(Some(0x1_0000_0001))),
        RawEventBody::DriverLoad(driver_load_body()),
        RawEventBody::CreateRemoteThread(create_remote_thread_body()),
        RawEventBody::RawAccessRead(raw_access_read_body()),
        RawEventBody::ProcessAccess(process_access_body()),
        RawEventBody::RegistryObjectAddDel(registry_object_add_del_body()),
        RawEventBody::WindowsEventLog(windows_event_log_body()),
        RawEventBody::Journald(journald_body()),
        RawEventBody::Auditd(auditd_body()),
    ]
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
        RawEventBody::ProcessCreate(_) => RawEventKind::ProcessCreate,
        RawEventBody::DriverLoad(_) => RawEventKind::DriverLoad,
        RawEventBody::CreateRemoteThread(_) => RawEventKind::CreateRemoteThread,
        RawEventBody::RawAccessRead(_) => RawEventKind::RawAccessRead,
        RawEventBody::ProcessAccess(_) => RawEventKind::ProcessAccess,
        RawEventBody::RegistryObjectAddDel(_) => RawEventKind::RegistryObjectAddDel,
        RawEventBody::WindowsEventLog(_) => RawEventKind::WindowsEventLog,
        RawEventBody::Journald(_) => RawEventKind::Journald,
        RawEventBody::Auditd(_) => RawEventKind::Auditd,
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

/// An endpoint subject of [`ENDPOINT_ID`] with the addresses `ips` and the
/// default route address `default_route_ip`.
pub(crate) fn endpoint(ips: &[&str], default_route_ip: Option<&str>) -> PrimarySubject {
    PrimarySubject::Endpoint {
        endpoint_id: ENDPOINT_ID,
        ips: ips.iter().map(|addr| ip(addr)).collect(),
        default_route_ip: default_route_ip.map(ip),
        net_state_source: NetStateSource::Observed,
        role: ThreatRole::Actor,
    }
}

/// A detection about an endpoint subject with `ips`, `default_route_ip` and
/// `related_ips`, from [`endpoint_sensor`] at [`time`].
pub(crate) fn endpoint_event(
    ips: &[&str],
    default_route_ip: Option<&str>,
    related_ips: Vec<RelatedIp>,
) -> DetectionEvent {
    let mut event = subject_event(endpoint(ips, default_route_ip), related_ips);
    event.sensor = Some(endpoint_sensor());
    event
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
