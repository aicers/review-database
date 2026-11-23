//! The catalog of clustering model types: fixed recipes for training a
//! clustering model on one raw event kind.
//!
//! A training definition either names a type, in which case the type's fixed
//! values cannot be changed and only the type's detection models may run on
//! the model, or is `custom`, in which case the operator sets every value and
//! no detection model runs. The catalog is code that ships with this crate's
//! releases, like the detection model property table; it is never stored in
//! the database, and operators do not edit it. It holds only the current
//! version of each type.

use jiff::SignedDuration;
use review_protocol::types::{DetectionModel, RawEventKind};
use serde::{Deserialize, Serialize};

use crate::{ModelMethod, time_series_types};

/// How a clustering model type groups raw events.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ClusteringApproach {
    /// Groups raw events by the leading tokens of their prefix columns.
    Prefix,
    /// Groups raw events around centroids of their feature vectors.
    Centroid,
}

/// The type of a value in a training definition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DefinitionValueType {
    /// A string.
    String,
    /// An RFC 3339 timestamp, written as a string.
    Timestamp,
    /// An integer.
    Integer,
    /// A float. A definition may write an integer for it, such as `5` for
    /// `5.0`; both are read as floats.
    Float,
    /// A list of strings.
    StringList,
    /// A list of integers.
    IntegerList,
    /// A table.
    Table,
    /// A list of tables.
    TableList,
}

/// A value of a training definition, with its type.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DefinitionValue {
    /// A string.
    String(&'static str),
    /// An integer.
    Integer(i64),
    /// A float.
    Float(f64),
    /// A list of integers.
    IntegerList(&'static [i64]),
    /// A table, as its keys and values.
    Table(&'static [FixedValue]),
    /// A list of tables, each as its keys and values.
    TableList(&'static [&'static [FixedValue]]),
}

impl DefinitionValue {
    /// Returns the type of the value.
    #[must_use]
    pub fn value_type(&self) -> DefinitionValueType {
        match self {
            Self::String(_) => DefinitionValueType::String,
            Self::Integer(_) => DefinitionValueType::Integer,
            Self::Float(_) => DefinitionValueType::Float,
            Self::IntegerList(_) => DefinitionValueType::IntegerList,
            Self::Table(_) => DefinitionValueType::Table,
            Self::TableList(_) => DefinitionValueType::TableList,
        }
    }
}

/// A key of a training definition and the value a clustering model type
/// fixes it to.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FixedValue {
    /// The key in the training definition, or in the table holding it.
    pub key: &'static str,
    /// The value, with its type.
    pub value: DefinitionValue,
}

/// What an operator value of a clustering model type may be set to.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DefinitionValueRange {
    /// An integer within `min..=max`.
    Integer { min: i64, max: i64 },
    /// A non-empty list. Its items are checked by the caller.
    NonEmpty,
    /// One end of the window from `window_start` (inclusive) to
    /// `window_end` (exclusive), which spans at least `min`. The upper bound,
    /// the data store's retention, is checked by the caller.
    Window { min: SignedDuration },
}

/// A value of a training definition that the operator sets for a clustering
/// model type.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TypeOperatorValue {
    /// The key in the training definition.
    pub name: &'static str,
    /// The type of the value.
    pub value_type: DefinitionValueType,
    /// The range the value must be within, where one applies. What it does
    /// not state is checked by the caller.
    pub range: Option<DefinitionValueRange>,
    /// The default, where one applies.
    pub default: Option<DefinitionValue>,
    /// Whether the value may be absent; absence is then its value.
    pub optional: bool,
}

/// A clustering model type: a fixed recipe for training a clustering model on
/// one raw event kind.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ClusteringModelType {
    /// The snake-case identifier, never changed.
    pub id: &'static str,
    /// The version, raised by 1 whenever the fixed values or the allowed
    /// detection models change.
    pub version: u32,
    /// The position in the catalog.
    pub order: u32,
    /// The kind of the raw events the model reads.
    pub raw_event_kind: RawEventKind,
    /// The clustering method.
    pub method: ModelMethod,
    /// How the model groups raw events.
    pub approach: ClusteringApproach,
    /// The training definition keys the type fixes, with their values.
    pub fixed: &'static [FixedValue],
    /// The training definition values the operator sets.
    pub operator_values: &'static [TypeOperatorValue],
    /// The detection models allowed to run on the model, in
    /// [`DetectionModel`] order.
    pub detection_models: &'static [DetectionModel],
    /// The names of the IP columns, kept in the raw event table but not used
    /// as features.
    pub ip_columns: &'static [&'static str],
    /// What the type groups and what its limits are, in English.
    pub description_en: &'static str,
    /// What the type groups and what its limits are, in Korean.
    pub description_ko: &'static str,
}

impl ClusteringModelType {
    /// Returns the value the type fixes for the top-level definition key
    /// `key`, or `None` if the type does not fix it.
    #[must_use]
    pub fn fixed_value(&self, key: &str) -> Option<&'static DefinitionValue> {
        self.fixed.iter().find(|f| f.key == key).map(|f| &f.value)
    }

    /// Returns the operator value `name`, or `None` if the type has none of
    /// that name.
    #[must_use]
    pub fn operator_value(&self, name: &str) -> Option<&'static TypeOperatorValue> {
        self.operator_values.iter().find(|v| v.name == name)
    }
}

/// The clustering model type a model was trained as.
///
/// Stored model bytes depend on the variant order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusteringModelTypeRef {
    /// A catalog type, at the version the model was trained with.
    Catalog { id: String, version: u32 },
    /// A definition whose every value the operator set.
    Custom,
}

/// Returns every clustering model type, in catalog order.
#[must_use]
pub fn clustering_model_types() -> &'static [ClusteringModelType] {
    CATALOG
}

/// Returns the clustering model type `id`, or `None` if the catalog has no
/// type of that id.
#[must_use]
pub fn clustering_model_type(id: &str) -> Option<&'static ClusteringModelType> {
    CATALOG.iter().find(|t| t.id == id)
}

/// Returns the raw event kind of every catalog type that allows `model`,
/// each kind once: the clustering model types first, then the time-series
/// types, each in catalog order.
pub(crate) fn raw_event_kinds_of(model: DetectionModel) -> Vec<RawEventKind> {
    let clustering = CATALOG
        .iter()
        .map(|t| (t.detection_models, t.raw_event_kind));
    let series = time_series_types()
        .iter()
        .map(|t| (t.detection_models, t.raw_event_kind));
    let mut kinds = Vec::new();
    for (models, kind) in clustering.chain(series) {
        if models.contains(&model) && !kinds.contains(&kind) {
            kinds.push(kind);
        }
    }
    kinds
}

const CATALOG: &[ClusteringModelType] = &[HTTP_URL];

/// The shortest training window of a type.
pub(crate) const MIN_WINDOW: SignedDuration = SignedDuration::from_hours(7 * 24);

/// Returns a `[csv]` `format` entry.
const fn column(name: &'static str, data_type: &'static str, weight: f64) -> [FixedValue; 3] {
    [
        FixedValue {
            key: "name",
            value: DefinitionValue::String(name),
        },
        FixedValue {
            key: "data_type",
            value: DefinitionValue::String(data_type),
        },
        FixedValue {
            key: "weight",
            value: DefinitionValue::Float(weight),
        },
    ]
}

/// The weight of `uri` in `http_url`: `i32::MAX`, so that the URI dominates
/// every other column.
const HTTP_URL_URI_WEIGHT: f64 = 2_147_483_647.0;

const HTTP_URL_FORMAT: &[&[FixedValue]] = &[
    &column("time", "utf8", 0.0),
    &column("source", "utf8", 0.0),
    &column("orig_addr", "utf8", 0.0),
    &column("orig_port", "enum", 0.0),
    &column("resp_addr", "utf8", 0.0),
    &column("resp_port", "enum", 0.0),
    &column("proto", "enum", 0.0),
    &column("start_time", "utf8", 0.0),
    &column("duration", "int64", 0.0),
    &column("orig_pkts", "int64", 0.0),
    &column("resp_pkts", "int64", 0.0),
    &column("orig_l2_bytes", "int64", 0.0),
    &column("resp_l2_bytes", "int64", 0.0),
    &column("method", "enum", 0.0),
    &column("host", "utf8", 1.0),
    &column("uri", "utf8", HTTP_URL_URI_WEIGHT),
    &column("referer", "utf8", 0.0),
    &column("version", "utf8", 0.0),
    &column("user_agent", "utf8", 0.0),
    &column("request_len", "int64", 0.0),
    &column("response_len", "int64", 0.0),
    &column("status_code", "int64", 0.0),
    &column("status_msg", "utf8", 0.0),
    &column("username", "utf8", 0.0),
    &column("password", "utf8", 0.0),
    &column("cookie", "utf8", 0.0),
    &column("content_encoding", "utf8", 0.0),
    &column("content_type", "utf8", 0.0),
    &column("cache_control", "utf8", 0.0),
    &column("filenames", "utf8", 0.0),
    &column("mime_types", "utf8", 0.0),
    &column("body", "utf8", 0.0),
    &column("state", "utf8", 0.0),
];

const HTTP_URL_CSV: &[FixedValue] = &[
    FixedValue {
        key: "reader",
        value: DefinitionValue::Table(&[
            FixedValue {
                key: "delimiter",
                value: DefinitionValue::Integer(9),
            },
            FixedValue {
                key: "quote",
                value: DefinitionValue::Integer(0),
            },
        ]),
    },
    FixedValue {
        key: "format",
        value: DefinitionValue::TableList(HTTP_URL_FORMAT),
    },
    FixedValue {
        key: "prefix_columns",
        value: DefinitionValue::IntegerList(&[14, 15]),
    },
    FixedValue {
        key: "time_intervals",
        value: DefinitionValue::IntegerList(&[60]),
    },
    FixedValue {
        key: "time_column",
        value: DefinitionValue::Integer(0),
    },
    FixedValue {
        key: "count_columns",
        value: DefinitionValue::IntegerList(&[0]),
    },
];

const HTTP_URL_FIXED: &[FixedValue] = &[
    FixedValue {
        key: "raw_event_kind",
        value: DefinitionValue::String("http"),
    },
    FixedValue {
        key: "method",
        value: DefinitionValue::String("multidimension"),
    },
    FixedValue {
        key: "csv",
        value: DefinitionValue::Table(HTTP_URL_CSV),
    },
    FixedValue {
        key: "numbers_of_top_n",
        value: DefinitionValue::IntegerList(&[30; 33]),
    },
    FixedValue {
        key: "precision",
        value: DefinitionValue::Integer(2),
    },
    FixedValue {
        key: "min_token_length",
        value: DefinitionValue::Integer(2),
    },
    FixedValue {
        key: "max_data_len",
        value: DefinitionValue::Integer(30),
    },
    FixedValue {
        key: "long_pattern_len",
        value: DefinitionValue::Integer(16000),
    },
    FixedValue {
        key: "algorithm",
        value: DefinitionValue::String("dbscan"),
    },
    FixedValue {
        key: "eps",
        value: DefinitionValue::Float(5.0),
    },
];

const HTTP_URL_OPERATOR_VALUES: &[TypeOperatorValue] = &[
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
        name: "suspicious_tokens",
        value_type: DefinitionValueType::String,
        range: None,
        default: None,
        optional: true,
    },
    TypeOperatorValue {
        name: "data_store",
        value_type: DefinitionValueType::Table,
        range: None,
        default: None,
        optional: false,
    },
];

const HTTP_URL: ClusteringModelType = ClusteringModelType {
    id: "http_url",
    version: 1,
    order: 0,
    raw_event_kind: RawEventKind::Http,
    method: ModelMethod::Multidimension,
    approach: ClusteringApproach::Prefix,
    fixed: HTTP_URL_FIXED,
    operator_values: HTTP_URL_OPERATOR_VALUES,
    detection_models: &[DetectionModel::LabelDbMatch, DetectionModel::FarOutlier],
    ip_columns: &["orig_addr", "resp_addr"],
    description_en: "Groups HTTP requests by the shape of their host and URI: requests whose \
        host+uri tokens share the same leading tokens form one cluster. It looks only at the \
        prefix of host and uri; every other column, the request body and the response are \
        not compared, and requests that differ only after the shared prefix, such as in a \
        query string, fall into the same cluster. The client and server IP addresses are kept \
        but are not features. It needs a training window of at least 7 days.",
    description_ko: "HTTP 요청의 host+uri 모양을 토큰 앞부분으로 묶는다. host와 uri를 이은 \
        토큰의 앞부분이 같은 요청이 한 클러스터가 된다. host와 uri의 앞부분만 보며, 다른 컬럼과 \
        요청 본문, 응답은 비교하지 않는다. 공통 앞부분 뒤에서만 다른 요청, 예를 들어 쿼리 \
        문자열만 다른 요청은 같은 클러스터에 들어간다. 클라이언트와 서버 IP 주소는 남기지만 \
        특징으로 쓰지 않는다. 학습 기간은 7일 이상이어야 한다.",
};

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};

    use bincode::Options;
    use review_protocol::types::raw_event;
    use serde::de::{self, Deserializer, Visitor};

    use super::*;

    const SNAPSHOT: &str = include_str!("../data/csv-column-snapshot.json");

    const HTTP_URL_COLUMNS: [&str; 33] = [
        "time",
        "source",
        "orig_addr",
        "orig_port",
        "resp_addr",
        "resp_port",
        "proto",
        "start_time",
        "duration",
        "orig_pkts",
        "resp_pkts",
        "orig_l2_bytes",
        "resp_l2_bytes",
        "method",
        "host",
        "uri",
        "referer",
        "version",
        "user_agent",
        "request_len",
        "response_len",
        "status_code",
        "status_msg",
        "username",
        "password",
        "cookie",
        "content_encoding",
        "content_type",
        "cache_control",
        "filenames",
        "mime_types",
        "body",
        "state",
    ];

    const HTTP_URL_DATA_TYPES: [&str; 33] = [
        "utf8", "utf8", "utf8", "enum", "utf8", "enum", "enum", "utf8", "int64", "int64", "int64",
        "int64", "int64", "enum", "utf8", "utf8", "utf8", "utf8", "utf8", "int64", "int64",
        "int64", "utf8", "utf8", "utf8", "utf8", "utf8", "utf8", "utf8", "utf8", "utf8", "utf8",
        "utf8",
    ];

    fn table_value<'a>(table: &'a [FixedValue], key: &str) -> &'a DefinitionValue {
        let found: Vec<_> = table.iter().filter(|f| f.key == key).collect();
        assert_eq!(found.len(), 1, "{key} is not in the table exactly once");
        &found[0].value
    }

    fn csv(t: &ClusteringModelType) -> &'static [FixedValue] {
        match t.fixed_value("csv") {
            Some(DefinitionValue::Table(csv)) => csv,
            other => panic!("[csv] of {} is {other:?}", t.id),
        }
    }

    fn format(t: &ClusteringModelType) -> &'static [&'static [FixedValue]] {
        match table_value(csv(t), "format") {
            DefinitionValue::TableList(format) => format,
            other => panic!("format of {} is {other:?}", t.id),
        }
    }

    fn integer_list(table: &[FixedValue], key: &str) -> &'static [i64] {
        match table_value(table, key) {
            DefinitionValue::IntegerList(list) => list,
            other => panic!("{key} is {other:?}"),
        }
    }

    fn string(table: &[FixedValue], key: &str) -> &'static str {
        match table_value(table, key) {
            DefinitionValue::String(s) => s,
            other => panic!("{key} is {other:?}"),
        }
    }

    fn float(table: &[FixedValue], key: &str) -> f64 {
        match table_value(table, key) {
            DefinitionValue::Float(f) => *f,
            other => panic!("{key} is {other:?}"),
        }
    }

    fn column_names(t: &ClusteringModelType) -> Vec<&'static str> {
        format(t).iter().map(|c| string(c, "name")).collect()
    }

    fn snapshot() -> serde_json::Value {
        serde_json::from_str(SNAPSHOT).unwrap()
    }

    #[test]
    fn catalog_holds_http_url_v1_only() {
        let types = clustering_model_types();
        assert_eq!(types.len(), 1);
        let t = &types[0];
        assert_eq!(t.id, "http_url");
        assert_eq!(t.version, 1);
        assert_eq!(t.order, 0);
        assert_eq!(t.raw_event_kind, RawEventKind::Http);
        assert_eq!(t.method, ModelMethod::Multidimension);
        assert_eq!(t.approach, ClusteringApproach::Prefix);
        assert_eq!(
            t.detection_models,
            [DetectionModel::LabelDbMatch, DetectionModel::FarOutlier]
        );
        assert_eq!(t.ip_columns, ["orig_addr", "resp_addr"]);
        assert!(t.description_en.contains("host+uri"));
        assert!(
            t.description_ko
                .contains("HTTP 요청의 host+uri 모양을 토큰 앞부분으로 묶는다")
        );
        assert!(t.description_en.contains("7 days"));
        assert!(t.description_ko.contains("7일"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn http_url_fixed_values() {
        let t = clustering_model_type("http_url").unwrap();
        let keys: Vec<_> = t.fixed.iter().map(|f| f.key).collect();
        assert_eq!(
            keys,
            [
                "raw_event_kind",
                "method",
                "csv",
                "numbers_of_top_n",
                "precision",
                "min_token_length",
                "max_data_len",
                "long_pattern_len",
                "algorithm",
                "eps",
            ]
        );
        assert_eq!(
            t.fixed_value("raw_event_kind"),
            Some(&DefinitionValue::String("http"))
        );
        assert_eq!(
            t.fixed_value("method"),
            Some(&DefinitionValue::String("multidimension"))
        );
        assert_eq!(
            t.fixed_value("numbers_of_top_n"),
            Some(&DefinitionValue::IntegerList(&[30; 33]))
        );
        for (key, value) in [
            ("precision", 2),
            ("min_token_length", 2),
            ("max_data_len", 30),
            ("long_pattern_len", 16000),
        ] {
            assert_eq!(
                t.fixed_value(key),
                Some(&DefinitionValue::Integer(value)),
                "{key}"
            );
        }
        assert_eq!(
            t.fixed_value("algorithm"),
            Some(&DefinitionValue::String("dbscan"))
        );
        let eps = t.fixed_value("eps").unwrap();
        assert_eq!(eps, &DefinitionValue::Float(5.0));
        assert_eq!(eps.value_type(), DefinitionValueType::Float);
        assert_eq!(t.fixed_value("max_token_length"), None);

        let csv = csv(t);
        let keys: Vec<_> = csv.iter().map(|f| f.key).collect();
        assert_eq!(
            keys,
            [
                "reader",
                "format",
                "prefix_columns",
                "time_intervals",
                "time_column",
                "count_columns",
            ]
        );
        assert_eq!(
            table_value(csv, "reader"),
            &DefinitionValue::Table(&[
                FixedValue {
                    key: "delimiter",
                    value: DefinitionValue::Integer(9),
                },
                FixedValue {
                    key: "quote",
                    value: DefinitionValue::Integer(0),
                },
            ])
        );
        assert_eq!(integer_list(csv, "prefix_columns"), [14, 15]);
        assert_eq!(integer_list(csv, "time_intervals"), [60]);
        assert_eq!(
            table_value(csv, "time_column"),
            &DefinitionValue::Integer(0)
        );
        assert_eq!(integer_list(csv, "count_columns"), [0]);

        let format = format(t);
        assert_eq!(format.len(), 33);
        for (i, column) in format.iter().enumerate() {
            let keys: Vec<_> = column.iter().map(|f| f.key).collect();
            assert_eq!(keys, ["name", "data_type", "weight"]);
            assert_eq!(string(column, "name"), HTTP_URL_COLUMNS[i]);
            assert_eq!(string(column, "data_type"), HTTP_URL_DATA_TYPES[i]);
            let expected_weight = match HTTP_URL_COLUMNS[i] {
                "host" => 1.0,
                "uri" => 2_147_483_647.0,
                _ => 0.0,
            };
            assert_eq!(
                float(column, "weight").to_bits(),
                f64::to_bits(expected_weight),
                "{}",
                HTTP_URL_COLUMNS[i]
            );
        }
    }

    #[test]
    fn http_url_operator_values() {
        let t = clustering_model_type("http_url").unwrap();
        let min = SignedDuration::from_hours(168);
        let expected = [
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
                range: Some(DefinitionValueRange::Window { min }),
                default: None,
                optional: false,
            },
            TypeOperatorValue {
                name: "window_end",
                value_type: DefinitionValueType::Timestamp,
                range: Some(DefinitionValueRange::Window { min }),
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
                name: "suspicious_tokens",
                value_type: DefinitionValueType::String,
                range: None,
                default: None,
                optional: true,
            },
            TypeOperatorValue {
                name: "data_store",
                value_type: DefinitionValueType::Table,
                range: None,
                default: None,
                optional: false,
            },
        ];
        assert_eq!(t.operator_values, expected);
        assert_eq!(
            t.operator_value("batch_size").map(|v| v.default),
            Some(Some(DefinitionValue::Integer(1_000_000)))
        );
        assert_eq!(t.operator_value("eps"), None);
        // No operator value is also a fixed value.
        for value in t.operator_values {
            assert_eq!(t.fixed_value(value.name), None, "{}", value.name);
        }
    }

    #[test]
    fn lookup_hits_and_misses() {
        assert_eq!(
            clustering_model_type("http_url"),
            Some(&clustering_model_types()[0])
        );
        assert_eq!(clustering_model_type("custom"), None);
        assert_eq!(clustering_model_type("no_such_type"), None);
        assert_eq!(clustering_model_type("HTTP_URL"), None);
        assert_eq!(clustering_model_type(""), None);
    }

    #[test]
    fn ids_and_orders_are_unique_and_types_are_in_order() {
        let types = clustering_model_types();
        let ids: HashSet<_> = types.iter().map(|t| t.id).collect();
        assert_eq!(ids.len(), types.len());
        let orders: HashSet<_> = types.iter().map(|t| t.order).collect();
        assert_eq!(orders.len(), types.len());
        assert!(types.windows(2).all(|w| w[0].order < w[1].order));
        assert!(!ids.contains("custom"));
        for t in types {
            assert!(
                t.id.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{} is not snake case",
                t.id
            );
        }
    }

    #[test]
    fn detection_models_are_in_model_order() {
        for t in clustering_model_types() {
            assert!(
                t.detection_models
                    .windows(2)
                    .all(|w| u32::from(w[0]) < u32::from(w[1])),
                "{}",
                t.id
            );
        }
    }

    #[test]
    fn ip_columns_have_weight_zero_and_are_not_prefix_columns() {
        for t in clustering_model_types() {
            let format = format(t);
            let prefix_columns = integer_list(csv(t), "prefix_columns");
            for ip_column in t.ip_columns {
                let positions: Vec<_> = format
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| string(c, "name") == *ip_column)
                    .map(|(i, _)| i)
                    .collect();
                assert_eq!(positions.len(), 1, "{}: {ip_column}", t.id);
                let i = positions[0];
                assert_eq!(float(format[i], "weight").to_bits(), 0.0_f64.to_bits());
                assert!(
                    !prefix_columns.contains(&i64::try_from(i).unwrap()),
                    "{}: {ip_column} is a prefix column",
                    t.id
                );
            }
        }
    }

    #[test]
    fn format_matches_the_snapshot() {
        let snapshot = snapshot();
        let object = snapshot.as_object().unwrap();
        let keys: Vec<_> = object.keys().map(String::as_str).collect();
        let mut expected_keys = vec!["giganto", "gigantoClient", "kinds"];
        expected_keys.sort_unstable();
        let mut keys_sorted = keys.clone();
        keys_sorted.sort_unstable();
        assert_eq!(keys_sorted, expected_keys);
        assert_eq!(snapshot["giganto"], "0.36.0");
        assert_eq!(snapshot["gigantoClient"], "0.29.1");
        let kinds: BTreeMap<String, Vec<String>> =
            serde_json::from_value(snapshot["kinds"].clone()).unwrap();
        assert_eq!(kinds.keys().collect::<Vec<_>>(), ["http"]);
        assert_eq!(kinds["http"], HTTP_URL_COLUMNS);

        for t in clustering_model_types() {
            let Some(DefinitionValue::String(kind)) = t.fixed_value("raw_event_kind") else {
                panic!("{} fixes no raw_event_kind", t.id);
            };
            let columns = kinds
                .get(*kind)
                .unwrap_or_else(|| panic!("the snapshot has no {kind}"));
            assert_eq!(&column_names(t), columns, "{}", t.id);
        }
    }

    /// A deserializer that records the field names of the struct asked of it
    /// and deserializes nothing.
    struct FieldNames(Option<&'static [&'static str]>);

    impl<'de> Deserializer<'de> for &mut FieldNames {
        type Error = de::value::Error;

        fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Self::Error> {
            Err(de::Error::custom("not a struct"))
        }

        fn deserialize_struct<V: Visitor<'de>>(
            self,
            _: &'static str,
            fields: &'static [&'static str],
            _: V,
        ) -> Result<V::Value, Self::Error> {
            self.0 = Some(fields);
            Err(de::Error::custom("field names recorded"))
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map enum identifier ignored_any
        }
    }

    fn serde_field_names<T: for<'de> Deserialize<'de>>() -> &'static [&'static str] {
        let mut names = FieldNames(None);
        assert!(T::deserialize(&mut names).is_err());
        names.0.expect("the type deserializes as a struct")
    }

    #[test]
    fn format_matches_the_body_struct() {
        for t in clustering_model_types() {
            let fields = match t.raw_event_kind {
                RawEventKind::Http => serde_field_names::<raw_event::Http>(),
                other => panic!("{}: no body struct for {other:?}", t.id),
            };
            let names = column_names(t);
            assert_eq!(names.get(..2), Some(["time", "source"].as_slice()));
            assert_eq!(&names[2..], fields, "{}", t.id);
        }
        assert_eq!(serde_field_names::<raw_event::Http>().len(), 31);
    }

    #[test]
    fn model_type_ref_bytes_and_round_trip() {
        let options = bincode::DefaultOptions::new();
        let custom = ClusteringModelTypeRef::Custom;
        let bytes = options.serialize(&custom).unwrap();
        assert_eq!(bytes, [0x01]);
        assert_eq!(
            options
                .deserialize::<ClusteringModelTypeRef>(&bytes)
                .unwrap(),
            custom
        );

        let catalog = ClusteringModelTypeRef::Catalog {
            id: "http_url".to_owned(),
            version: 1,
        };
        let bytes = options.serialize(&catalog).unwrap();
        assert_eq!(bytes.first(), Some(&0x00));
        assert_eq!(
            options
                .deserialize::<ClusteringModelTypeRef>(&bytes)
                .unwrap(),
            catalog
        );
    }

    #[test]
    fn catalog_is_reachable_from_the_crate_root() {
        let types: &[crate::ClusteringModelType] = crate::clustering_model_types();
        let t: Option<&crate::ClusteringModelType> = crate::clustering_model_type("http_url");
        assert_eq!(t, types.first());
        assert_eq!(
            t.map(|t| t.approach),
            Some(crate::ClusteringApproach::Prefix)
        );
        let _ = (
            crate::ClusteringApproach::Centroid,
            crate::ClusteringModelTypeRef::Custom,
        );
    }

    #[test]
    fn raw_event_kinds_follow_the_catalog() {
        assert_eq!(
            raw_event_kinds_of(DetectionModel::LabelDbMatch),
            [RawEventKind::Http]
        );
        assert_eq!(
            raw_event_kinds_of(DetectionModel::FarOutlier),
            [RawEventKind::Http]
        );
        assert_eq!(raw_event_kinds_of(DetectionModel::PortScan), []);
    }
}
