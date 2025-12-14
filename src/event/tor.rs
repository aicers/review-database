use std::{fmt, net::IpAddr, num::NonZeroU8};

use attrievent::attribute::{ConnAttr, HttpAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, MEDIUM, TriageScore, common::Match};
use crate::TriageExclusion;
use crate::event::{
    common::{AttrValue, triage_scores_to_string},
    conn::{BlocklistConnFields, find_conn_attr_by_kind},
    http::{find_http_attr_by_kind, get_post_body},
};

#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize)]
pub struct TorConnection {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub referer: String,
    pub version: String,
    pub user_agent: String,
    pub request_len: usize,
    pub response_len: usize,
    pub status_code: u16,
    pub status_msg: String,
    pub username: String,
    pub password: String,
    pub cookie: String,
    pub content_encoding: String,
    pub content_type: String,
    pub cache_control: String,
    pub filenames: Vec<String>,
    pub mime_types: Vec<String>,
    pub body: Vec<u8>,
    pub state: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for TorConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} duration={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} method={:?} host={:?} uri={:?} referer={:?} version={:?} user_agent={:?} request_len={:?} response_len={:?} status_code={:?} status_msg={:?} username={:?} password={:?} cookie={:?} content_encoding={:?} content_type={:?} cache_control={:?} filenames={:?} mime_types={:?} body={:?} state={:?} triage_scores={:?}",
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            self.method,
            self.host,
            self.uri,
            self.referer,
            self.version,
            self.user_agent,
            self.request_len.to_string(),
            self.response_len.to_string(),
            self.status_code.to_string(),
            self.status_msg,
            self.username,
            self.password,
            self.cookie,
            self.content_encoding,
            self.content_type,
            self.cache_control,
            self.filenames.join(","),
            self.mime_types.join(","),
            get_post_body(&self.body),
            self.state,
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl TorConnection {
    pub(super) fn new(time: DateTime<Utc>, fields: &super::HttpEventFields) -> Self {
        TorConnection {
            time,
            sensor: fields.sensor.clone(),
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            proto: fields.proto,
            method: fields.method.clone(),
            host: fields.host.clone(),
            uri: fields.uri.clone(),
            referer: fields.referer.clone(),
            version: fields.version.clone(),
            user_agent: fields.user_agent.clone(),
            request_len: fields.request_len,
            response_len: fields.response_len,
            status_code: fields.status_code,
            status_msg: fields.status_msg.clone(),
            username: fields.username.clone(),
            password: fields.password.clone(),
            cookie: fields.cookie.clone(),
            content_encoding: fields.content_encoding.clone(),
            content_type: fields.content_type.clone(),
            cache_control: fields.cache_control.clone(),
            filenames: fields.filenames.clone(),
            mime_types: fields.mime_types.clone(),
            body: fields.body.clone(),
            state: fields.state.clone(),
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for TorConnection {
    fn src_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.orig_addr)
    }

    fn src_port(&self) -> u16 {
        self.orig_port
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.resp_addr)
    }

    fn dst_port(&self) -> u16 {
        self.resp_port
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> Option<EventCategory> {
        self.category
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &'static str {
        "tor exit nodes"
    }

    fn sensor(&self) -> &str {
        self.sensor.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        Some(self.confidence)
    }

    fn learning_method(&self) -> LearningMethod {
        LearningMethod::SemiSupervised
    }

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        find_http_attr_by_kind!(self, raw_event_attr)
    }

    fn score_by_triage_exclusion(&self, triage_exclusion: &[TriageExclusion]) -> f64 {
        let matched = triage_exclusion.iter().any(|ti| match ti {
            TriageExclusion::IpAddress(filter) => self
                .src_addrs()
                .iter()
                .chain(self.dst_addrs().iter())
                .any(|&ip| filter.contains(ip)),
            TriageExclusion::Domain(regex_set) => regex_set.is_match(&self.host),
            TriageExclusion::Hostname(hostnames) => hostnames.contains(&self.host),
            TriageExclusion::Uri(uris) => uris.contains(&self.uri),
        });
        if matched { f64::MIN } else { 0.0 }
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct TorConnectionConn {
    pub sensor: String,
    pub time: DateTime<Utc>,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub duration: i64,
    pub conn_state: String,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for TorConnectionConn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} resp_addr={:?} resp_port={:?} proto={:?} conn_state={:?} start_time={:?} duration={:?} service={:?} orig_bytes={:?} resp_bytes={:?} orig_pkts={:?} resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} triage_scores={:?}",
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            self.proto.to_string(),
            self.conn_state,
            self.start_time.to_rfc3339(),
            self.duration.to_string(),
            self.service,
            self.orig_bytes.to_string(),
            self.resp_bytes.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl TorConnectionConn {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistConnFields) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            proto: fields.proto,
            conn_state: fields.conn_state,
            duration: fields.duration,
            service: fields.service,
            orig_bytes: fields.orig_bytes,
            resp_bytes: fields.resp_bytes,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl Match for TorConnectionConn {
    fn src_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.orig_addr)
    }

    fn src_port(&self) -> u16 {
        self.orig_port
    }

    fn dst_addrs(&self) -> &[IpAddr] {
        std::slice::from_ref(&self.resp_addr)
    }

    fn dst_port(&self) -> u16 {
        self.resp_port
    }

    fn proto(&self) -> u8 {
        self.proto
    }

    fn category(&self) -> Option<EventCategory> {
        self.category
    }

    fn level(&self) -> NonZeroU8 {
        MEDIUM
    }

    fn kind(&self) -> &'static str {
        "tor exit nodes"
    }

    fn sensor(&self) -> &str {
        self.sensor.as_str()
    }

    fn confidence(&self) -> Option<f32> {
        Some(self.confidence)
    }

    fn learning_method(&self) -> LearningMethod {
        LearningMethod::SemiSupervised
    }

    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
        find_conn_attr_by_kind!(self, raw_event_attr)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use attrievent::attribute::{ConnAttr, RawEventAttrKind};
    use chrono::{TimeZone, Utc};

    use super::{Match, TorConnectionConn};
    use crate::event::{
        EventCategory, LearningMethod, MEDIUM, common::AttrValue, conn::BlocklistConnFields,
    };

    fn tor_connection_conn_fields() -> BlocklistConnFields {
        let start_time = Utc
            .with_ymd_and_hms(2023, 1, 1, 12, 0, 0)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap();
        BlocklistConnFields {
            sensor: "test-sensor".to_string(),
            src_country_code: None,
            orig_addr: "192.168.1.100".parse().unwrap(),
            orig_port: 12345,
            dst_country_code: None,
            resp_addr: "198.51.100.1".parse().unwrap(),
            resp_port: 443,
            proto: 6,
            conn_state: "SF".to_string(),
            start_time,
            duration: 1_000_000_000,
            service: "https".to_string(),
            orig_bytes: 1024,
            resp_bytes: 2048,
            orig_pkts: 10,
            resp_pkts: 15,
            orig_l2_bytes: 1100,
            resp_l2_bytes: 2200,
            confidence: 0.95,
            category: Some(EventCategory::CommandAndControl),
        }
    }

    #[test]
    fn tor_connection_conn_new() {
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let fields = tor_connection_conn_fields();

        let event = TorConnectionConn::new(time, fields);

        assert_eq!(event.time, time);
        assert_eq!(event.sensor, "test-sensor");
        assert_eq!(event.orig_addr, "192.168.1.100".parse::<IpAddr>().unwrap());
        assert_eq!(event.orig_port, 12345);
        assert_eq!(event.resp_addr, "198.51.100.1".parse::<IpAddr>().unwrap());
        assert_eq!(event.resp_port, 443);
        assert_eq!(event.proto, 6);
        assert_eq!(event.conn_state, "SF");
        assert_eq!(event.duration, 1_000_000_000);
        assert_eq!(event.service, "https");
        assert_eq!(event.orig_bytes, 1024);
        assert_eq!(event.resp_bytes, 2048);
        assert_eq!(event.orig_pkts, 10);
        assert_eq!(event.resp_pkts, 15);
        assert_eq!(event.orig_l2_bytes, 1100);
        assert_eq!(event.resp_l2_bytes, 2200);
        assert!((event.confidence - 0.95).abs() < f32::EPSILON);
        assert_eq!(event.category, Some(EventCategory::CommandAndControl));
        assert!(event.triage_scores.is_none());
    }

    #[test]
    fn tor_connection_conn_display() {
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let event = TorConnectionConn::new(time, tor_connection_conn_fields());

        let display_output = format!("{event}");
        assert!(display_output.contains("sensor=\"test-sensor\""));
        assert!(display_output.contains("orig_addr=\"192.168.1.100\""));
        assert!(display_output.contains("resp_addr=\"198.51.100.1\""));
        assert!(display_output.contains("conn_state=\"SF\""));
        assert!(display_output.contains("service=\"https\""));
    }

    #[test]
    fn tor_connection_conn_match_trait() {
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let event = TorConnectionConn::new(time, tor_connection_conn_fields());

        assert_eq!(
            event.src_addrs(),
            &["192.168.1.100".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(event.src_port(), 12345);
        assert_eq!(
            event.dst_addrs(),
            &["198.51.100.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(event.dst_port(), 443);
        assert_eq!(event.proto(), 6);
        assert_eq!(event.category(), Some(EventCategory::CommandAndControl));
        assert_eq!(event.level(), MEDIUM);
        assert_eq!(event.kind(), "tor exit nodes");
        assert_eq!(event.sensor(), "test-sensor");
        assert_eq!(event.confidence(), Some(0.95));
        assert!(matches!(
            event.learning_method(),
            LearningMethod::SemiSupervised
        ));
    }

    #[test]
    fn tor_connection_conn_find_attr_by_kind() {
        let time = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        let event = TorConnectionConn::new(time, tor_connection_conn_fields());

        // Test finding source address attribute
        let orig_addr_attr = RawEventAttrKind::Conn(ConnAttr::SrcAddr);
        if let Some(AttrValue::Addr(addr)) = event.find_attr_by_kind(orig_addr_attr) {
            assert_eq!(addr, "192.168.1.100".parse::<IpAddr>().unwrap());
        } else {
            panic!("Expected SrcAddr attribute");
        }

        // Test finding destination port attribute
        let resp_port_attr = RawEventAttrKind::Conn(ConnAttr::DstPort);
        if let Some(AttrValue::UInt(port)) = event.find_attr_by_kind(resp_port_attr) {
            assert_eq!(port, 443);
        } else {
            panic!("Expected DstPort attribute");
        }

        // Test finding protocol attribute
        let proto_attr = RawEventAttrKind::Conn(ConnAttr::Proto);
        if let Some(AttrValue::UInt(proto)) = event.find_attr_by_kind(proto_attr) {
            assert_eq!(proto, 6);
        } else {
            panic!("Expected Proto attribute");
        }

        // Test finding connection state attribute
        let conn_state_attr = RawEventAttrKind::Conn(ConnAttr::ConnState);
        if let Some(AttrValue::String(state)) = event.find_attr_by_kind(conn_state_attr) {
            assert_eq!(state, "SF");
        } else {
            panic!("Expected ConnState attribute");
        }

        // Test finding duration attribute
        let duration_attr = RawEventAttrKind::Conn(ConnAttr::Duration);
        if let Some(AttrValue::SInt(duration)) = event.find_attr_by_kind(duration_attr) {
            assert_eq!(duration, 1_000_000_000);
        } else {
            panic!("Expected Duration attribute");
        }

        // Test finding service attribute
        let service_attr = RawEventAttrKind::Conn(ConnAttr::Service);
        if let Some(AttrValue::String(service)) = event.find_attr_by_kind(service_attr) {
            assert_eq!(service, "https");
        } else {
            panic!("Expected Service attribute");
        }

        // Test finding byte count attributes
        let orig_bytes_attr = RawEventAttrKind::Conn(ConnAttr::OrigBytes);
        if let Some(AttrValue::UInt(bytes)) = event.find_attr_by_kind(orig_bytes_attr) {
            assert_eq!(bytes, 1024);
        } else {
            panic!("Expected OrigBytes attribute");
        }

        let resp_bytes_attr = RawEventAttrKind::Conn(ConnAttr::RespBytes);
        if let Some(AttrValue::UInt(bytes)) = event.find_attr_by_kind(resp_bytes_attr) {
            assert_eq!(bytes, 2048);
        } else {
            panic!("Expected RespBytes attribute");
        }

        // Test finding packet count attributes
        let orig_pkts_attr = RawEventAttrKind::Conn(ConnAttr::OrigPkts);
        if let Some(AttrValue::UInt(pkts)) = event.find_attr_by_kind(orig_pkts_attr) {
            assert_eq!(pkts, 10);
        } else {
            panic!("Expected OrigPkts attribute");
        }

        let resp_pkts_attr = RawEventAttrKind::Conn(ConnAttr::RespPkts);
        if let Some(AttrValue::UInt(pkts)) = event.find_attr_by_kind(resp_pkts_attr) {
            assert_eq!(pkts, 15);
        } else {
            panic!("Expected RespPkts attribute");
        }

        // Test finding L2 byte count attributes
        let orig_l2_bytes_attr = RawEventAttrKind::Conn(ConnAttr::OrigL2Bytes);
        if let Some(AttrValue::UInt(bytes)) = event.find_attr_by_kind(orig_l2_bytes_attr) {
            assert_eq!(bytes, 1100);
        } else {
            panic!("Expected OrigL2Bytes attribute");
        }

        let resp_l2_bytes_attr = RawEventAttrKind::Conn(ConnAttr::RespL2Bytes);
        if let Some(AttrValue::UInt(bytes)) = event.find_attr_by_kind(resp_l2_bytes_attr) {
            assert_eq!(bytes, 2200);
        } else {
            panic!("Expected RespL2Bytes attribute");
        }
    }
}
