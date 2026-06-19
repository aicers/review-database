use std::{fmt, net::IpAddr};

use attrievent::attribute::{DceRpcAttr, RawEventAttrKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{EventCategory, LearningMethod, ThreatLevel, TriageScore, common::Match};
use crate::event::common::{AttrValue, triage_scores_to_string};

// request entry format: "{context_id}:{opnum}"
const REQUEST_SEPARATOR: char = ':';

/// Converts a DCE/RPC syntax UUID (captured from wire and read as `be_u128`)
/// into canonical UUID text (`8-4-4-4-12`) for rule/log comparison.
///
/// Conversion steps:
/// 1) `be_u128` preserves the 16 wire octets; `to_be_bytes()` restores that
///    packet order.
/// 2) Per DCE/RPC GUID packet layout, the first three UUID fields
///    (`Data1` 4B, `Data2` 2B, `Data3` 2B) are decoded as little-endian
///    fields. The remaining octets are emitted in-order for canonical text
///    rendering.
fn format_dce_uuid(value: u128) -> String {
    let b = value.to_be_bytes();

    let g1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let g2 = u16::from_le_bytes([b[4], b[5]]);
    let g3 = u16::from_le_bytes([b[6], b[7]]);

    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g1, g2, g3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

fn collect_request_part(request: &[String], want_context_id: bool) -> Option<Vec<u64>> {
    if request.is_empty() {
        return None;
    }

    request
        .iter()
        .map(|entry| {
            let (context_id, opnum) = entry.split_once(REQUEST_SEPARATOR)?;
            let target = if want_context_id { context_id } else { opnum };
            target.parse::<u64>().ok()
        })
        .collect::<Option<Vec<_>>>()
}

macro_rules! find_dce_rpc_attr_by_kind {
    ($event: expr, $raw_event_attr: expr) => {{
        if let RawEventAttrKind::DceRpc(attr) = $raw_event_attr {
            let target_value = match attr {
                DceRpcAttr::SrcAddr => AttrValue::Addr($event.orig_addr),
                DceRpcAttr::SrcPort => AttrValue::UInt($event.orig_port.into()),
                DceRpcAttr::DstAddr => AttrValue::Addr($event.resp_addr),
                DceRpcAttr::DstPort => AttrValue::UInt($event.resp_port.into()),
                DceRpcAttr::Proto => AttrValue::UInt($event.proto.into()),
                DceRpcAttr::Duration => AttrValue::SInt($event.duration),
                DceRpcAttr::OrigPkts => AttrValue::UInt($event.orig_pkts),
                DceRpcAttr::RespPkts => AttrValue::UInt($event.resp_pkts),
                DceRpcAttr::OrigL2Bytes => AttrValue::UInt($event.orig_l2_bytes),
                DceRpcAttr::RespL2Bytes => AttrValue::UInt($event.resp_l2_bytes),
                DceRpcAttr::ContextId => {
                    let values = $event
                        .context
                        .iter()
                        .map(|c| u64::from(c.id))
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecUInt(std::borrow::Cow::Owned(values))
                }
                DceRpcAttr::AbstractSyntax => {
                    let values = $event
                        .context
                        .iter()
                        .map(|c| format_dce_uuid(c.abstract_syntax))
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecString(std::borrow::Cow::Owned(values))
                }
                DceRpcAttr::AbstractMajor => {
                    let values = $event
                        .context
                        .iter()
                        .map(|c| u64::from(c.abstract_major))
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecUInt(std::borrow::Cow::Owned(values))
                }
                DceRpcAttr::AbstractMinor => {
                    let values = $event
                        .context
                        .iter()
                        .map(|c| u64::from(c.abstract_minor))
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecUInt(std::borrow::Cow::Owned(values))
                }
                DceRpcAttr::TransferSyntax => {
                    let values = $event
                        .context
                        .iter()
                        .map(|c| format_dce_uuid(c.transfer_syntax))
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecString(std::borrow::Cow::Owned(values))
                }
                DceRpcAttr::TransferMajor => {
                    let values = $event
                        .context
                        .iter()
                        .map(|c| u64::from(c.transfer_major))
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecUInt(std::borrow::Cow::Owned(values))
                }
                DceRpcAttr::TransferMinor => {
                    let values = $event
                        .context
                        .iter()
                        .map(|c| u64::from(c.transfer_minor))
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecUInt(std::borrow::Cow::Owned(values))
                }
                DceRpcAttr::Acceptance => {
                    let values = $event
                        .context
                        .iter()
                        .map(|c| u64::from(c.acceptance))
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecUInt(std::borrow::Cow::Owned(values))
                }
                DceRpcAttr::Reason => {
                    let values = $event
                        .context
                        .iter()
                        .map(|c| u64::from(c.reason))
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        return None;
                    }
                    AttrValue::VecUInt(std::borrow::Cow::Owned(values))
                }
                DceRpcAttr::RequestContextId => {
                    let values = collect_request_part(&$event.request, true)?;
                    AttrValue::VecUInt(std::borrow::Cow::Owned(values))
                }
                DceRpcAttr::RequestOpnum => {
                    let values = collect_request_part(&$event.request, false)?;
                    AttrValue::VecUInt(std::borrow::Cow::Owned(values))
                }
            };
            Some(target_value)
        } else {
            None
        }
    }};
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DceRpcContext {
    pub id: u16,
    pub abstract_syntax: u128,
    pub abstract_major: u16,
    pub abstract_minor: u16,
    pub transfer_syntax: u128,
    pub transfer_major: u16,
    pub transfer_minor: u16,
    pub acceptance: u16,
    pub reason: u16,
}

#[derive(Serialize, Deserialize)]
pub struct BlocklistDceRpcFields {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    /// Timestamp in nanoseconds since the Unix epoch (UTC).
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub context: Vec<DceRpcContext>,
    pub request: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

pub(crate) type BlocklistDceRpcFieldsStored = BlocklistDceRpcFieldsStoredV0_46;

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistDceRpcFieldsStoredV0_46 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub context: Vec<DceRpcContext>,
    pub request: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<BlocklistDceRpcFields> for BlocklistDceRpcFieldsStored {
    fn from(value: BlocklistDceRpcFields) -> Self {
        Self {
            sensor: value.sensor,
            orig_addr: value.orig_addr,
            orig_port: value.orig_port,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: value.resp_addr,
            resp_port: value.resp_port,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: value.proto,
            start_time: value.start_time,
            duration: value.duration,
            orig_pkts: value.orig_pkts,
            resp_pkts: value.resp_pkts,
            orig_l2_bytes: value.orig_l2_bytes,
            resp_l2_bytes: value.resp_l2_bytes,
            context: value.context,
            request: value.request,
            confidence: value.confidence,
            category: value.category,
        }
    }
}

impl BlocklistDceRpcFields {
    #[must_use]
    pub fn syslog_rfc5424(&self) -> String {
        let start_time_dt = DateTime::from_timestamp_nanos(self.start_time);
        let context_str = self
            .context
            .iter()
            .map(|c| {
                format!(
                    "id={} abstract_syntax={:#x} abstract={}.{} \
                     transfer_syntax={:#x} transfer={}.{} \
                     acceptance={} reason={}",
                    c.id,
                    c.abstract_syntax,
                    c.abstract_major,
                    c.abstract_minor,
                    c.transfer_syntax,
                    c.transfer_major,
                    c.transfer_minor,
                    c.acceptance,
                    c.reason,
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let request_str = self.request.join(",");
        format!(
            "category={:?} sensor={:?} orig_addr={:?} orig_port={:?} \
             resp_addr={:?} resp_port={:?} proto={:?} start_time={:?} \
             duration={:?} orig_pkts={:?} resp_pkts={:?} \
             orig_l2_bytes={:?} resp_l2_bytes={:?} \
             context={:?} request={:?} confidence={:?}",
            self.category.as_ref().map_or_else(
                || "Unspecified".to_string(),
                std::string::ToString::to_string
            ),
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            self.proto.to_string(),
            start_time_dt.to_rfc3339(),
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            context_str,
            request_str,
            self.confidence.to_string()
        )
    }
}

pub struct BlocklistDceRpc {
    pub time: DateTime<Utc>,
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub orig_country_code: [u8; 2],
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub resp_country_code: [u8; 2],
    pub proto: u8,
    pub start_time: DateTime<Utc>,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub context: Vec<DceRpcContext>,
    pub request: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

impl fmt::Display for BlocklistDceRpc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let context_str = self
            .context
            .iter()
            .map(|c| {
                format!(
                    "id={} abstract_syntax={:#x} abstract={}.{} \
                     transfer_syntax={:#x} transfer={}.{} \
                     acceptance={} reason={}",
                    c.id,
                    c.abstract_syntax,
                    c.abstract_major,
                    c.abstract_minor,
                    c.transfer_syntax,
                    c.transfer_major,
                    c.transfer_minor,
                    c.acceptance,
                    c.reason,
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let request_str = self.request.join(",");
        write!(
            f,
            "sensor={:?} orig_addr={:?} orig_port={:?} orig_country_code={:?} \
             resp_addr={:?} resp_port={:?} resp_country_code={:?} proto={:?} \
             start_time={:?} duration={:?} orig_pkts={:?} \
             resp_pkts={:?} orig_l2_bytes={:?} resp_l2_bytes={:?} \
             context={:?} request={:?} triage_scores={:?}",
            self.sensor,
            self.orig_addr.to_string(),
            self.orig_port.to_string(),
            crate::util::country_code_as_str(&self.orig_country_code),
            self.resp_addr.to_string(),
            self.resp_port.to_string(),
            crate::util::country_code_as_str(&self.resp_country_code),
            self.proto.to_string(),
            self.start_time.to_rfc3339(),
            self.duration.to_string(),
            self.orig_pkts.to_string(),
            self.resp_pkts.to_string(),
            self.orig_l2_bytes.to_string(),
            self.resp_l2_bytes.to_string(),
            context_str,
            request_str,
            triage_scores_to_string(self.triage_scores.as_ref())
        )
    }
}

impl BlocklistDceRpc {
    pub(super) fn new(time: DateTime<Utc>, fields: BlocklistDceRpcFieldsStored) -> Self {
        Self {
            time,
            sensor: fields.sensor,
            orig_addr: fields.orig_addr,
            orig_port: fields.orig_port,
            orig_country_code: fields.orig_country_code,
            resp_addr: fields.resp_addr,
            resp_port: fields.resp_port,
            resp_country_code: fields.resp_country_code,
            proto: fields.proto,
            start_time: DateTime::from_timestamp_nanos(fields.start_time),
            duration: fields.duration,
            orig_pkts: fields.orig_pkts,
            resp_pkts: fields.resp_pkts,
            orig_l2_bytes: fields.orig_l2_bytes,
            resp_l2_bytes: fields.resp_l2_bytes,
            context: fields.context,
            request: fields.request,
            confidence: fields.confidence,
            category: fields.category,
            triage_scores: None,
        }
    }
}

impl BlocklistDceRpc {
    #[must_use]
    pub fn threat_level() -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl Match for BlocklistDceRpc {
    crate::event::common::impl_match_pair_country_codes!();
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

    fn level(&self) -> ThreatLevel {
        Self::threat_level()
    }

    fn kind(&self) -> &'static str {
        "blocklist dcerpc"
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
        find_dce_rpc_attr_by_kind!(self, raw_event_attr)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cmp::Ordering,
        net::{IpAddr, Ipv4Addr},
    };

    use attrievent::attribute::{DceRpcAttr, RawEventAttrKind, RawEventKind};
    use bincode::Options;
    use chrono::{TimeZone, Utc};
    use serde::Serialize;

    use super::{
        BlocklistDceRpc, BlocklistDceRpcFieldsStored, DceRpcContext, collect_request_part,
        format_dce_uuid,
    };
    use crate::{
        AttrCmpKind, PacketAttr, ValueKind,
        event::common::{AttrValue, Match},
    };

    #[test]
    fn format_dce_uuid_produces_canonical_text() {
        // Wire bytes for UUID 12345678-1234-5678-1234-56789abcdef0 in DCE/RPC layout.
        let wire = [
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0,
        ];
        let value = u128::from_be_bytes(wire);
        assert_eq!(
            format_dce_uuid(value),
            "12345678-1234-5678-1234-56789abcdef0"
        );
    }

    #[test]
    fn collect_request_part_splits_context_id_and_opnum() {
        let request = vec!["0:1".to_string(), "2:3".to_string()];
        assert_eq!(collect_request_part(&request, true), Some(vec![0, 2]));
        assert_eq!(collect_request_part(&request, false), Some(vec![1, 3]));
    }

    #[test]
    fn collect_request_part_returns_none_for_invalid_entries() {
        let request = vec!["0:1".to_string(), "invalid".to_string()];
        assert_eq!(collect_request_part(&request, true), None);
        assert_eq!(collect_request_part(&[], true), None);
    }

    fn dcerpc_fields_with_context() -> BlocklistDceRpcFieldsStored {
        BlocklistDceRpcFieldsStored {
            sensor: "sensor".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            orig_country_code: crate::util::COUNTRY_CODE_PENDING,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 135,
            resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 10,
            orig_pkts: 1,
            resp_pkts: 2,
            orig_l2_bytes: 100,
            resp_l2_bytes: 200,
            context: vec![DceRpcContext {
                id: 0,
                abstract_syntax: u128::from_be_bytes([
                    0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x12, 0x34, 0x56, 0x78, 0x9a,
                    0xbc, 0xde, 0xf0,
                ]),
                abstract_major: 1,
                abstract_minor: 0,
                transfer_syntax: u128::from_be_bytes([
                    0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x12, 0x34, 0x56, 0x78, 0x9a,
                    0xbc, 0xde, 0xf0,
                ]),
                transfer_major: 2,
                transfer_minor: 0,
                acceptance: 0,
                reason: 0,
            }],
            request: vec!["0:42".to_string()],
            confidence: 1.0,
            category: None,
        }
    }

    #[test]
    fn dcerpc_context_attr_mappings() {
        let time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        let event = BlocklistDceRpc::new(time, dcerpc_fields_with_context());

        let Some(AttrValue::VecUInt(ids)) =
            event.find_attr_by_kind(RawEventAttrKind::DceRpc(DceRpcAttr::ContextId))
        else {
            panic!("Expected ContextId");
        };
        assert_eq!(ids.as_ref(), &[0_u64]);

        let Some(AttrValue::VecString(syntaxes)) =
            event.find_attr_by_kind(RawEventAttrKind::DceRpc(DceRpcAttr::AbstractSyntax))
        else {
            panic!("Expected AbstractSyntax");
        };
        assert_eq!(
            syntaxes.as_ref(),
            &["12345678-1234-5678-1234-56789abcdef0".to_string()]
        );

        let Some(AttrValue::VecUInt(opnums)) =
            event.find_attr_by_kind(RawEventAttrKind::DceRpc(DceRpcAttr::RequestOpnum))
        else {
            panic!("Expected RequestOpnum");
        };
        assert_eq!(opnums.as_ref(), &[42_u64]);
    }

    #[test]
    fn dcerpc_empty_context_returns_none_for_vector_attrs() {
        let time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        let mut fields = dcerpc_fields_with_context();
        fields.context.clear();
        let event = BlocklistDceRpc::new(time, fields);

        assert!(
            event
                .find_attr_by_kind(RawEventAttrKind::DceRpc(DceRpcAttr::ContextId))
                .is_none()
        );
    }

    fn serialize<T>(value: &T) -> Option<Vec<u8>>
    where
        T: Serialize,
    {
        bincode::DefaultOptions::new().serialize(value).ok()
    }

    #[test]
    fn dcerpc_score_by_attr() {
        let time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        let event = BlocklistDceRpc::new(time, dcerpc_fields_with_context());

        let packet_attrs = vec![
            PacketAttr {
                raw_event_kind: RawEventKind::DceRpc,
                attr_name: DceRpcAttr::AbstractSyntax.to_string(),
                value_kind: ValueKind::String,
                cmp_kind: AttrCmpKind::Contain,
                first_value: serialize(&"12345678-1234-5678-1234-56789abcdef0").unwrap(),
                second_value: None,
                weight: Some(0.5),
            },
            PacketAttr {
                raw_event_kind: RawEventKind::DceRpc,
                attr_name: DceRpcAttr::RequestContextId.to_string(),
                value_kind: ValueKind::UInteger,
                cmp_kind: AttrCmpKind::Equal,
                first_value: serialize(&0_u64).unwrap(),
                second_value: None,
                weight: Some(0.25),
            },
            PacketAttr {
                raw_event_kind: RawEventKind::DceRpc,
                attr_name: DceRpcAttr::RequestOpnum.to_string(),
                value_kind: ValueKind::UInteger,
                cmp_kind: AttrCmpKind::Equal,
                first_value: serialize(&42_u64).unwrap(),
                second_value: None,
                weight: Some(0.25),
            },
        ];
        assert_eq!(
            event.score_by_attr(&packet_attrs).partial_cmp(&1.0),
            Some(Ordering::Equal)
        );
    }
}
