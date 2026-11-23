//! The catalog of time-series types: fixed recipes for generating time series
//! from one network raw event kind and training a timeseries model on them.
//!
//! A time-series generation policy either names a type, in which case the
//! type's generation-spec values cannot be changed and the policy may not
//! filter by IP, or is custom, in which case the operator sets every value.
//! Like the clustering model type catalog, the catalog is code that ships
//! with this crate's releases; it is never stored in the database, and
//! operators do not edit it. It holds only the current version of each type.

use review_protocol::types::{
    ConnField, CounterpartScope, DetectionModel, EndpointRole, GroupByUnit, Measure, RawEventKind,
    ThreatRole,
};

use crate::clustering_model_type::MIN_WINDOW;
use crate::{
    DefinitionValue, DefinitionValueRange, DefinitionValueType, FixedValue, ModelMethod, SlotSize,
    TypeOperatorValue, WindowSize,
};

/// A time-series type: a fixed recipe for generating time series from one
/// raw event kind and training a timeseries model on them.
///
/// The values a policy's operator sets whatever the type (its name, its
/// sensors, its assigned generator and its `utc_offset`) are not part of a
/// type.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TimeSeriesType {
    /// The snake-case identifier, never changed.
    pub id: &'static str,
    /// The version, raised by 1 whenever the fixed values or the allowed
    /// detection models change.
    pub version: u32,
    /// The position in the catalog.
    pub order: u32,
    /// The kind of the raw events the policy counts.
    pub raw_event_kind: RawEventKind,
    /// The clustering method of the model trained on the series.
    pub method: ModelMethod,
    /// The value counted per slot.
    pub measure: Measure,
    /// The endpoint whose IP splits the series. Every type splits by one.
    pub group_by: EndpointRole,
    /// The unit `group_by` splits by.
    pub group_by_unit: GroupByUnit,
    /// The filter on whether the other endpoint is internal.
    pub counterpart_scope: CounterpartScope,
    /// The length of one slot.
    pub slot_size: SlotSize,
    /// The length of one window, which is one series sample.
    pub window_size: WindowSize,
    /// The threat role of the primary subject of the type's detections.
    pub threat_role: ThreatRole,
    /// The training definition keys the type fixes, with their values.
    pub fixed: &'static [FixedValue],
    /// The training definition values the operator sets.
    pub operator_values: &'static [TypeOperatorValue],
    /// The detection models allowed to run on the model, in
    /// [`DetectionModel`] order.
    pub detection_models: &'static [DetectionModel],
    /// The names of the IP columns, kept in the series table but not used as
    /// features.
    pub ip_columns: &'static [&'static str],
    /// What the type counts and what its limits are, in English.
    pub description_en: &'static str,
    /// What the type counts and what its limits are, in Korean.
    pub description_ko: &'static str,
}

impl TimeSeriesType {
    /// Returns whether the Unsupervised Engine trains a model on the type,
    /// which a type that only Hog uses does not: whether the type fixes any
    /// training definition value.
    pub(crate) fn trains(&self) -> bool {
        !self.fixed.is_empty()
    }
}

/// Returns every time-series type, in catalog order.
#[must_use]
pub fn time_series_types() -> &'static [TimeSeriesType] {
    CATALOG
}

/// Returns the time-series type `id`, or `None` if the catalog has no type of
/// that id. The version is not compared.
#[must_use]
pub fn time_series_type(id: &str) -> Option<&'static TimeSeriesType> {
    find(CATALOG, id)
}

/// Returns the type `id` of `catalog`, or `None` if it has none of that id.
pub(crate) fn find<'c>(catalog: &'c [TimeSeriesType], id: &str) -> Option<&'c TimeSeriesType> {
    catalog.iter().find(|t| t.id == id)
}

/// Returns the snake-case name of `kind`, as a training definition's
/// `raw_event_kind` writes it, if it is a network kind.
pub(crate) const fn network_raw_event_kind_name(kind: RawEventKind) -> Option<&'static str> {
    Some(match kind {
        RawEventKind::Bootp => "bootp",
        RawEventKind::Conn => "conn",
        RawEventKind::DceRpc => "dce_rpc",
        RawEventKind::Dhcp => "dhcp",
        RawEventKind::Dns => "dns",
        RawEventKind::Ftp => "ftp",
        RawEventKind::Http => "http",
        RawEventKind::Icmp => "icmp",
        RawEventKind::Kerberos => "kerberos",
        RawEventKind::Ldap => "ldap",
        RawEventKind::MalformedDns => "malformed_dns",
        RawEventKind::Mqtt => "mqtt",
        RawEventKind::Nfs => "nfs",
        RawEventKind::Ntlm => "ntlm",
        RawEventKind::Radius => "radius",
        RawEventKind::Rdp => "rdp",
        RawEventKind::Smb => "smb",
        RawEventKind::Smtp => "smtp",
        RawEventKind::Ssh => "ssh",
        RawEventKind::Tls => "tls",
        _ => return None,
    })
}

/// The shipped catalog.
const CATALOG: &[TimeSeriesType] = &[
    HOST_DAILY_ACTIVITY_SOURCE,
    HOST_DAILY_ACTIVITY_DESTINATION,
    HOST_DAILY_SENT_BYTES,
    SERVER_DAILY_RESPONSE_BYTES,
    HOST_DAILY_DNS,
    SERVER_DAILY_RDP,
    HOST_DAILY_RDP,
    SERVER_DAILY_HTTP,
    HOST_DAILY_TLS,
    SERVER_DAILY_TLS,
    HOST_DAILY_EXTERNAL_INBOUND,
    SERVER_DAILY_EXTERNAL_RDP,
];

/// The length of one slot of every type, in seconds, as the training
/// definition's `slot_size` writes it.
const SLOT_SECONDS: i64 = 300;

/// The values every type shares. Each type sets the others; the ones given
/// here for them are only placeholders.
const IP_DAILY: TimeSeriesType = TimeSeriesType {
    id: "",
    version: 1,
    order: 0,
    raw_event_kind: RawEventKind::Conn,
    method: ModelMethod::Timeseries,
    measure: Measure::Count,
    group_by: EndpointRole::Source,
    group_by_unit: GroupByUnit::Ip,
    counterpart_scope: CounterpartScope::Any,
    slot_size: SlotSize::FiveMinutes,
    window_size: WindowSize::OneDay,
    threat_role: ThreatRole::Actor,
    fixed: &[],
    operator_values: &[],
    detection_models: &[],
    ip_columns: &[],
    description_en: "",
    description_ko: "",
};

/// Returns the fixed values of a type the Unsupervised Engine trains on: the
/// raw event kind `raw_event_kind`, the endpoint `group_by`, the threat role
/// `threat_role` and the input transform `transform`, as a definition writes
/// them, with the values every such type shares.
const fn trained_fixed(
    raw_event_kind: &'static str,
    group_by: &'static str,
    threat_role: &'static str,
    transform: &'static str,
) -> [FixedValue; 11] {
    [
        FixedValue {
            key: "raw_event_kind",
            value: DefinitionValue::String(raw_event_kind),
        },
        FixedValue {
            key: "method",
            value: DefinitionValue::String("timeseries"),
        },
        FixedValue {
            key: "group_by",
            value: DefinitionValue::String(group_by),
        },
        FixedValue {
            key: "threat_role",
            value: DefinitionValue::String(threat_role),
        },
        FixedValue {
            key: "slot_size",
            value: DefinitionValue::Integer(SLOT_SECONDS),
        },
        FixedValue {
            key: "eps",
            value: DefinitionValue::Float(2.0),
        },
        FixedValue {
            key: "min_cluster_size",
            value: DefinitionValue::Integer(3),
        },
        FixedValue {
            key: "transform",
            value: DefinitionValue::String(transform),
        },
        FixedValue {
            key: "algorithm",
            value: DefinitionValue::String("dbscan"),
        },
        FixedValue {
            key: "precision",
            value: DefinitionValue::Integer(2),
        },
        FixedValue {
            key: "numbers_of_top_n",
            value: DefinitionValue::IntegerList(&[]),
        },
    ]
}

/// The operator values of a type the Unsupervised Engine trains on.
const TRAINED_OPERATOR_VALUES: &[TypeOperatorValue] = &[
    TypeOperatorValue {
        name: "sources",
        value_type: DefinitionValueType::StringList,
        range: Some(DefinitionValueRange::NonEmpty),
        default: None,
        optional: false,
    },
    TypeOperatorValue {
        name: "window_start",
        value_type: DefinitionValueType::Timestamp,
        range: Some(DefinitionValueRange::Window { min: MIN_WINDOW }),
        default: None,
        optional: false,
    },
    TypeOperatorValue {
        name: "window_end",
        value_type: DefinitionValueType::Timestamp,
        range: Some(DefinitionValueRange::Window { min: MIN_WINDOW }),
        default: None,
        optional: false,
    },
    TypeOperatorValue {
        name: "batch_size",
        value_type: DefinitionValueType::Integer,
        range: Some(DefinitionValueRange::Integer {
            min: 10_000,
            max: 1_000_000,
        }),
        default: Some(DefinitionValue::Integer(1_000_000)),
        optional: false,
    },
    TypeOperatorValue {
        name: "max_event_id_num",
        value_type: DefinitionValueType::Integer,
        range: Some(DefinitionValueRange::Integer { min: 1, max: 100 }),
        default: Some(DefinitionValue::Integer(50)),
        optional: false,
    },
    TypeOperatorValue {
        name: "data_store",
        value_type: DefinitionValueType::Table,
        range: None,
        default: None,
        optional: false,
    },
];

const HOST_DAILY_ACTIVITY_SOURCE: TimeSeriesType = TimeSeriesType {
    id: "host_daily_activity_source",
    order: 0,
    raw_event_kind: RawEventKind::Conn,
    measure: Measure::Count,
    group_by: EndpointRole::Source,
    counterpart_scope: CounterpartScope::Any,
    threat_role: ThreatRole::Actor,
    fixed: &trained_fixed("conn", "source", "actor", "none"),
    operator_values: TRAINED_OPERATOR_VALUES,
    description_en: "Host daily activity (source). Counts the Conn events of each source IP, \
        per 5-minute slot of a day.",
    description_ko: "호스트 하루 행동(출발지). 출발지 IP마다 Conn 이벤트 수를 하루의 5분 \
        슬롯별로 센다.",
    ..IP_DAILY
};

const HOST_DAILY_ACTIVITY_DESTINATION: TimeSeriesType = TimeSeriesType {
    id: "host_daily_activity_destination",
    order: 1,
    raw_event_kind: RawEventKind::Conn,
    measure: Measure::Count,
    group_by: EndpointRole::Destination,
    counterpart_scope: CounterpartScope::Any,
    threat_role: ThreatRole::Target,
    fixed: &trained_fixed("conn", "destination", "target", "none"),
    operator_values: TRAINED_OPERATOR_VALUES,
    description_en: "Host daily activity (destination). Counts the Conn events of each \
        destination IP, per 5-minute slot of a day.",
    description_ko: "호스트 하루 행동(목적지). 목적지 IP마다 Conn 이벤트 수를 하루의 5분 \
        슬롯별로 센다.",
    ..IP_DAILY
};

const HOST_DAILY_SENT_BYTES: TimeSeriesType = TimeSeriesType {
    id: "host_daily_sent_bytes",
    order: 2,
    raw_event_kind: RawEventKind::Conn,
    measure: Measure::Sum(ConnField::OrigBytes),
    group_by: EndpointRole::Source,
    counterpart_scope: CounterpartScope::Any,
    threat_role: ThreatRole::Actor,
    fixed: &trained_fixed("conn", "source", "actor", "log1p"),
    operator_values: TRAINED_OPERATOR_VALUES,
    description_en: "Host daily bytes sent. Sums the bytes each source IP sent in its Conn \
        events, per 5-minute slot of a day.",
    description_ko: "호스트 하루 송신량. 출발지 IP마다 Conn 이벤트에서 보낸 바이트를 하루의 \
        5분 슬롯별로 합한다.",
    ..IP_DAILY
};

const SERVER_DAILY_RESPONSE_BYTES: TimeSeriesType = TimeSeriesType {
    id: "server_daily_response_bytes",
    order: 3,
    raw_event_kind: RawEventKind::Conn,
    measure: Measure::Sum(ConnField::RespBytes),
    group_by: EndpointRole::Destination,
    counterpart_scope: CounterpartScope::Any,
    // The server sending the bytes is the actor, though the series is
    // grouped by the destination.
    threat_role: ThreatRole::Actor,
    fixed: &trained_fixed("conn", "destination", "actor", "log1p"),
    operator_values: TRAINED_OPERATOR_VALUES,
    description_en: "Server daily response bytes. Sums the bytes each destination IP sent \
        back in its Conn events, per 5-minute slot of a day.",
    description_ko: "서버 하루 응답량. 목적지 IP마다 Conn 이벤트에서 응답으로 보낸 바이트를 \
        하루의 5분 슬롯별로 합한다.",
    ..IP_DAILY
};

const HOST_DAILY_DNS: TimeSeriesType = TimeSeriesType {
    id: "host_daily_dns",
    order: 4,
    raw_event_kind: RawEventKind::Dns,
    measure: Measure::Count,
    group_by: EndpointRole::Source,
    counterpart_scope: CounterpartScope::Any,
    threat_role: ThreatRole::Actor,
    fixed: &trained_fixed("dns", "source", "actor", "none"),
    operator_values: TRAINED_OPERATOR_VALUES,
    description_en: "Host daily DNS. Counts the DNS events of each source IP, per 5-minute \
        slot of a day.",
    description_ko: "호스트 하루 DNS. 출발지 IP마다 DNS 이벤트 수를 하루의 5분 슬롯별로 센다.",
    ..IP_DAILY
};

const SERVER_DAILY_RDP: TimeSeriesType = TimeSeriesType {
    id: "server_daily_rdp",
    order: 5,
    raw_event_kind: RawEventKind::Rdp,
    measure: Measure::Count,
    group_by: EndpointRole::Destination,
    counterpart_scope: CounterpartScope::Any,
    threat_role: ThreatRole::Target,
    fixed: &trained_fixed("rdp", "destination", "target", "none"),
    operator_values: TRAINED_OPERATOR_VALUES,
    description_en: "Server daily RDP. Counts the RDP events of each destination IP, per \
        5-minute slot of a day.",
    description_ko: "서버 하루 RDP. 목적지 IP마다 RDP 이벤트 수를 하루의 5분 슬롯별로 센다.",
    ..IP_DAILY
};

const HOST_DAILY_RDP: TimeSeriesType = TimeSeriesType {
    id: "host_daily_rdp",
    order: 6,
    raw_event_kind: RawEventKind::Rdp,
    measure: Measure::Count,
    group_by: EndpointRole::Source,
    counterpart_scope: CounterpartScope::Any,
    threat_role: ThreatRole::Actor,
    description_en: "Host daily RDP. Counts the RDP events of each source IP, per 5-minute \
        slot of a day.",
    description_ko: "호스트 하루 RDP. 출발지 IP마다 RDP 이벤트 수를 하루의 5분 슬롯별로 센다.",
    ..IP_DAILY
};

const SERVER_DAILY_HTTP: TimeSeriesType = TimeSeriesType {
    id: "server_daily_http",
    order: 7,
    raw_event_kind: RawEventKind::Http,
    measure: Measure::Count,
    group_by: EndpointRole::Destination,
    counterpart_scope: CounterpartScope::Any,
    threat_role: ThreatRole::Target,
    fixed: &trained_fixed("http", "destination", "target", "none"),
    operator_values: TRAINED_OPERATOR_VALUES,
    description_en: "Server daily HTTP. Counts the HTTP events of each destination IP, per \
        5-minute slot of a day.",
    description_ko: "서버 하루 HTTP. 목적지 IP마다 HTTP 이벤트 수를 하루의 5분 슬롯별로 센다.",
    ..IP_DAILY
};

const HOST_DAILY_TLS: TimeSeriesType = TimeSeriesType {
    id: "host_daily_tls",
    order: 8,
    raw_event_kind: RawEventKind::Tls,
    measure: Measure::Count,
    group_by: EndpointRole::Source,
    counterpart_scope: CounterpartScope::Any,
    threat_role: ThreatRole::Actor,
    fixed: &trained_fixed("tls", "source", "actor", "none"),
    operator_values: TRAINED_OPERATOR_VALUES,
    description_en: "Host daily TLS. Counts the TLS events of each source IP, per 5-minute \
        slot of a day.",
    description_ko: "호스트 하루 TLS. 출발지 IP마다 TLS 이벤트 수를 하루의 5분 슬롯별로 센다.",
    ..IP_DAILY
};

const SERVER_DAILY_TLS: TimeSeriesType = TimeSeriesType {
    id: "server_daily_tls",
    order: 9,
    raw_event_kind: RawEventKind::Tls,
    measure: Measure::Count,
    group_by: EndpointRole::Destination,
    counterpart_scope: CounterpartScope::Any,
    threat_role: ThreatRole::Target,
    fixed: &trained_fixed("tls", "destination", "target", "none"),
    operator_values: TRAINED_OPERATOR_VALUES,
    detection_models: &[DetectionModel::WindowOutlier],
    description_en: "Server daily TLS. Counts the TLS events of each destination IP, per \
        5-minute slot of a day.",
    description_ko: "서버 하루 TLS. 목적지 IP마다 TLS 이벤트 수를 하루의 5분 슬롯별로 센다.",
    ..IP_DAILY
};

const HOST_DAILY_EXTERNAL_INBOUND: TimeSeriesType = TimeSeriesType {
    id: "host_daily_external_inbound",
    order: 10,
    raw_event_kind: RawEventKind::Conn,
    measure: Measure::Count,
    group_by: EndpointRole::Destination,
    counterpart_scope: CounterpartScope::External,
    threat_role: ThreatRole::Target,
    description_en: "Host daily external inbound. Counts the Conn events from an external \
        source to each destination IP, per 5-minute slot of a day.",
    description_ko: "호스트 하루 외부 수신. 목적지 IP마다 외부 출발지에서 온 Conn 이벤트 수를 \
        하루의 5분 슬롯별로 센다.",
    ..IP_DAILY
};

const SERVER_DAILY_EXTERNAL_RDP: TimeSeriesType = TimeSeriesType {
    id: "server_daily_external_rdp",
    order: 11,
    raw_event_kind: RawEventKind::Rdp,
    measure: Measure::Count,
    group_by: EndpointRole::Destination,
    counterpart_scope: CounterpartScope::External,
    threat_role: ThreatRole::Target,
    description_en: "Server daily external RDP. Counts the RDP events from an external source \
        to each destination IP, per 5-minute slot of a day.",
    description_ko: "서버 하루 외부 RDP. 목적지 IP마다 외부 출발지에서 온 RDP 이벤트 수를 \
        하루의 5분 슬롯별로 센다.",
    ..IP_DAILY
};

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::clustering_model_types;

    /// One row of the catalog table: the id, the raw event kind, the
    /// measure, `group_by`, `counterpart_scope`, `threat_role`, the
    /// `transform` of a type the Unsupervised Engine trains on (`None` for a
    /// type it does not), and the detection models.
    type Row = (
        &'static str,
        RawEventKind,
        Measure,
        EndpointRole,
        CounterpartScope,
        ThreatRole,
        Option<&'static str>,
        &'static [DetectionModel],
    );

    #[test]
    // The expected catalog is written out row by row, as the contract states
    // it.
    #[allow(clippy::too_many_lines)]
    fn the_catalog_holds_the_twelve_ip_types_in_order() {
        use CounterpartScope::{Any, External};
        use EndpointRole::{Destination, Source};
        use RawEventKind::{Conn, Dns, Http, Rdp, Tls};
        use ThreatRole::{Actor, Target};

        let expected: [Row; 12] = [
            (
                "host_daily_activity_source",
                Conn,
                Measure::Count,
                Source,
                Any,
                Actor,
                Some("none"),
                &[],
            ),
            (
                "host_daily_activity_destination",
                Conn,
                Measure::Count,
                Destination,
                Any,
                Target,
                Some("none"),
                &[],
            ),
            (
                "host_daily_sent_bytes",
                Conn,
                Measure::Sum(ConnField::OrigBytes),
                Source,
                Any,
                Actor,
                Some("log1p"),
                &[],
            ),
            (
                "server_daily_response_bytes",
                Conn,
                Measure::Sum(ConnField::RespBytes),
                Destination,
                Any,
                Actor,
                Some("log1p"),
                &[],
            ),
            (
                "host_daily_dns",
                Dns,
                Measure::Count,
                Source,
                Any,
                Actor,
                Some("none"),
                &[],
            ),
            (
                "server_daily_rdp",
                Rdp,
                Measure::Count,
                Destination,
                Any,
                Target,
                Some("none"),
                &[],
            ),
            (
                "host_daily_rdp",
                Rdp,
                Measure::Count,
                Source,
                Any,
                Actor,
                None,
                &[],
            ),
            (
                "server_daily_http",
                Http,
                Measure::Count,
                Destination,
                Any,
                Target,
                Some("none"),
                &[],
            ),
            (
                "host_daily_tls",
                Tls,
                Measure::Count,
                Source,
                Any,
                Actor,
                Some("none"),
                &[],
            ),
            (
                "server_daily_tls",
                Tls,
                Measure::Count,
                Destination,
                Any,
                Target,
                Some("none"),
                &[DetectionModel::WindowOutlier],
            ),
            (
                "host_daily_external_inbound",
                Conn,
                Measure::Count,
                Destination,
                External,
                Target,
                None,
                &[],
            ),
            (
                "server_daily_external_rdp",
                Rdp,
                Measure::Count,
                Destination,
                External,
                Target,
                None,
                &[],
            ),
        ];

        let catalog = time_series_types();
        assert_eq!(catalog.len(), expected.len());
        for ((order, t), row) in (0_u32..).zip(catalog).zip(expected) {
            let (id, kind, measure, group_by, scope, threat_role, transform, models) = row;
            assert_eq!(t.id, id);
            assert_eq!(t.version, 1, "{id}");
            assert_eq!(t.order, order, "{id}");
            assert_eq!(t.raw_event_kind, kind, "{id}");
            assert_eq!(t.method, ModelMethod::Timeseries, "{id}");
            assert_eq!(t.measure, measure, "{id}");
            assert_eq!(t.group_by, group_by, "{id}");
            assert_eq!(t.group_by_unit, GroupByUnit::Ip, "{id}");
            assert_eq!(t.counterpart_scope, scope, "{id}");
            assert_eq!(t.slot_size, SlotSize::FiveMinutes, "{id}");
            assert_eq!(t.window_size, WindowSize::OneDay, "{id}");
            assert_eq!(t.threat_role, threat_role, "{id}");
            assert_eq!(t.detection_models, models, "{id}");
            assert_eq!(t.ip_columns, &[] as &[&str], "{id}");
            assert_eq!(t.trains(), transform.is_some(), "{id}");
            assert_eq!(
                t.fixed
                    .iter()
                    .find(|f| f.key == "transform")
                    .map(|f| f.value),
                transform.map(DefinitionValue::String),
                "{id}"
            );
            assert_eq!(time_series_type(id), Some(t));
        }
        for id in ["", "custom", "http_url", "Server_daily_tls"] {
            assert_eq!(time_series_type(id), None, "{id:?}");
        }
    }

    #[test]
    // The expected values are written out, as the contract states them.
    #[allow(clippy::too_many_lines)]
    fn trained_types_fix_the_definition_values() {
        let operator_values = |t: &TimeSeriesType| -> Vec<_> {
            t.operator_values
                .iter()
                .map(|v| (v.name, v.value_type, v.range, v.default, v.optional))
                .collect()
        };
        let window = Some(DefinitionValueRange::Window {
            min: jiff::SignedDuration::from_hours(7 * 24),
        });
        let expected_operator_values = [
            (
                "sources",
                DefinitionValueType::StringList,
                Some(DefinitionValueRange::NonEmpty),
                None,
                false,
            ),
            (
                "window_start",
                DefinitionValueType::Timestamp,
                window,
                None,
                false,
            ),
            (
                "window_end",
                DefinitionValueType::Timestamp,
                window,
                None,
                false,
            ),
            (
                "batch_size",
                DefinitionValueType::Integer,
                Some(DefinitionValueRange::Integer {
                    min: 10_000,
                    max: 1_000_000,
                }),
                Some(DefinitionValue::Integer(1_000_000)),
                false,
            ),
            (
                "max_event_id_num",
                DefinitionValueType::Integer,
                Some(DefinitionValueRange::Integer { min: 1, max: 100 }),
                Some(DefinitionValue::Integer(50)),
                false,
            ),
            ("data_store", DefinitionValueType::Table, None, None, false),
        ];

        let mut trained = 0;
        for t in time_series_types() {
            if [
                "host_daily_rdp",
                "host_daily_external_inbound",
                "server_daily_external_rdp",
            ]
            .contains(&t.id)
            {
                assert_eq!(t.fixed, &[] as &[FixedValue], "{}", t.id);
                assert_eq!(t.operator_values, &[] as &[TypeOperatorValue], "{}", t.id);
                assert!(!t.trains(), "{}", t.id);
                continue;
            }
            trained += 1;
            let transform = if matches!(t.measure, Measure::Sum(_)) {
                "log1p"
            } else {
                "none"
            };
            let group_by = match t.group_by {
                EndpointRole::Source => "source",
                EndpointRole::Destination => "destination",
            };
            let threat_role = match t.threat_role {
                ThreatRole::Actor => "actor",
                ThreatRole::Target => "target",
            };
            let kind = network_raw_event_kind_name(t.raw_event_kind).unwrap();
            let fixed: Vec<_> = t.fixed.iter().map(|f| (f.key, f.value)).collect();
            assert_eq!(
                fixed,
                [
                    ("raw_event_kind", DefinitionValue::String(kind)),
                    ("method", DefinitionValue::String("timeseries")),
                    ("group_by", DefinitionValue::String(group_by)),
                    ("threat_role", DefinitionValue::String(threat_role)),
                    ("slot_size", DefinitionValue::Integer(300)),
                    ("eps", DefinitionValue::Float(2.0)),
                    ("min_cluster_size", DefinitionValue::Integer(3)),
                    ("transform", DefinitionValue::String(transform)),
                    ("algorithm", DefinitionValue::String("dbscan")),
                    ("precision", DefinitionValue::Integer(2)),
                    ("numbers_of_top_n", DefinitionValue::IntegerList(&[])),
                ],
                "{}",
                t.id
            );
            assert_eq!(operator_values(t), expected_operator_values, "{}", t.id);
        }
        assert_eq!(trained, 9);
    }

    #[test]
    fn every_type_reads_a_network_kind() {
        let names: Vec<_> = crate::tables::NETWORK_RAW_EVENT_KINDS
            .iter()
            .map(|kind| network_raw_event_kind_name(*kind))
            .collect();
        assert_eq!(
            names,
            [
                "bootp",
                "conn",
                "dce_rpc",
                "dhcp",
                "dns",
                "ftp",
                "http",
                "icmp",
                "kerberos",
                "ldap",
                "malformed_dns",
                "mqtt",
                "nfs",
                "ntlm",
                "radius",
                "rdp",
                "smb",
                "smtp",
                "ssh",
                "tls",
            ]
            .map(Some)
        );
        assert_eq!(
            network_raw_event_kind_name(RawEventKind::ProcessCreate),
            None
        );
        assert_eq!(network_raw_event_kind_name(RawEventKind::Netflow5), None);
        for t in time_series_types() {
            assert!(
                crate::tables::NETWORK_RAW_EVENT_KINDS.contains(&t.raw_event_kind),
                "{}",
                t.id
            );
        }
    }

    #[test]
    fn ids_are_unique_and_disjoint_from_the_clustering_model_types() {
        let series: HashSet<_> = time_series_types().iter().map(|t| t.id).collect();
        assert_eq!(series.len(), time_series_types().len());
        for t in clustering_model_types() {
            assert!(!series.contains(t.id), "{}", t.id);
        }
    }

    #[test]
    fn descriptions_start_with_the_screen_name() {
        let names = [
            ("호스트 하루 행동(출발지)", "Host daily activity (source)"),
            (
                "호스트 하루 행동(목적지)",
                "Host daily activity (destination)",
            ),
            ("호스트 하루 송신량", "Host daily bytes sent"),
            ("서버 하루 응답량", "Server daily response bytes"),
            ("호스트 하루 DNS", "Host daily DNS"),
            ("서버 하루 RDP", "Server daily RDP"),
            ("호스트 하루 RDP", "Host daily RDP"),
            ("서버 하루 HTTP", "Server daily HTTP"),
            ("호스트 하루 TLS", "Host daily TLS"),
            ("서버 하루 TLS", "Server daily TLS"),
            ("호스트 하루 외부 수신", "Host daily external inbound"),
            ("서버 하루 외부 RDP", "Server daily external RDP"),
        ];
        assert_eq!(time_series_types().len(), names.len());
        for (t, (ko, en)) in time_series_types().iter().zip(names) {
            for (description, name) in [(t.description_ko, ko), (t.description_en, en)] {
                let sentence = description
                    .strip_prefix(name)
                    .and_then(|rest| rest.strip_prefix(". "))
                    .unwrap_or_else(|| panic!("{}: {description:?}", t.id));
                assert!(sentence.ends_with('.'), "{}: {description:?}", t.id);
                assert!(!sentence.contains("  "), "{}: {description:?}", t.id);
            }
        }
    }
}
