//! The check of a training definition's text against its clustering model
//! type, with the per-method key table and the defaults of a custom
//! definition.
//!
//! A training definition names a clustering model type in `type`: a catalog
//! `id`, at the version in `type_version`, or `custom`. A catalog type fixes
//! some values and bounds the ones the operator sets; a custom definition
//! sets every value, within the key table of its method. The key table and
//! the defaults are code, like the catalog; nothing about them is stored.

use std::collections::HashMap;

use jiff::{SignedDuration, Timestamp};
use num_traits::ToPrimitive;
use thiserror::Error;
use toml::{Table, Value};

use crate::{
    ClusteringModelType, ClusteringModelTypeRef, DefinitionValue, DefinitionValueRange,
    DefinitionValueType, FixedValue, ModelMethod, clustering_model_type, clustering_model_types,
};

/// The `type` of a definition whose every value the operator sets.
const CUSTOM: &str = "custom";

/// The raw event kind of every `prefix` definition.
const PREFIX_RAW_EVENT_KIND: &str = "log";

/// The largest `batch_size` of a custom definition.
const MAX_CUSTOM_BATCH_SIZE: i64 = 5_000_000;

/// The table of a definition's `[csv]` parts.
const CSV: &str = "csv";

/// The `sources` key, whose empty list is refused as an invalid document.
const SOURCES: &str = "sources";

const WINDOW_START: &str = "window_start";
const WINDOW_END: &str = "window_end";

/// Whether a training definition holds a key, for one method.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DefinitionKeyStatus {
    /// The key must be present; an absent key is refused.
    Required,
    /// The key must be present in a definition of a catalog type, and must
    /// be absent from a custom definition.
    RequiredForCatalogType,
    /// The key may be absent, with the meaning the row states.
    AbsentMeans,
    /// The method does not use the key; a present key is refused.
    Rejected,
}

/// A row of the key table: one key of a training definition and whether a
/// definition of one method holds it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DefinitionKey {
    /// The key, dotted from the top level, such as `batch_size` or
    /// `csv.format`.
    pub key: &'static str,
    /// Whether the key is required, may be absent or is rejected.
    pub status: DefinitionKeyStatus,
    /// One English line: what an absent key means, or how the engine fills
    /// a value shorter than it needs, where either applies.
    pub note: Option<&'static str>,
}

/// The code of a [`TrainingDefinitionRefusal`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TrainingDefinitionRefusalCode {
    /// Text that is not TOML, an absent or non-string `type`, a `type_version`
    /// that is not an integer, an absent, non-string or unknown `method`, a
    /// value of the wrong TOML type, or an empty `sources`.
    InvalidDocument,
    /// A key outside the key table of the method.
    UnknownField,
    /// A `type` that is neither a catalog type nor `custom`.
    UnknownModelType,
    /// A `type_version` that is absent or not the type's current version.
    ModelTypeVersionMismatch,
    /// A raw event kind the type or the method does not take.
    EventKindNotAllowed,
    /// A value different from the one the type fixes.
    FieldFixed,
    /// A key the definition must hold that is absent, or one it must not
    /// hold that is present.
    FieldNotAllowed,
    /// A value outside the range the type or the method allows.
    BoundViolated,
}

/// A refusal of a training definition's text by
/// [`check_training_definition`].
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct TrainingDefinitionRefusal {
    /// Why the definition is refused.
    pub code: TrainingDefinitionRefusalCode,
    /// The key the refusal is about, dotted from the top level and
    /// optionally followed by a list index, such as `csv.format[3]`; empty
    /// for text that is not TOML.
    pub key: String,
    /// The offending value as text, empty when the key is absent. A string
    /// is given without quotes, any other value as TOML.
    pub value: String,
    /// What is wrong, in English.
    pub message: String,
}

const fn row(
    key: &'static str,
    status: DefinitionKeyStatus,
    note: Option<&'static str>,
) -> DefinitionKey {
    DefinitionKey { key, status, note }
}

const fn required(key: &'static str) -> DefinitionKey {
    row(key, DefinitionKeyStatus::Required, None)
}

const fn absent_means(key: &'static str, meaning: &'static str) -> DefinitionKey {
    row(key, DefinitionKeyStatus::AbsentMeans, Some(meaning))
}

const fn rejected(key: &'static str) -> DefinitionKey {
    row(key, DefinitionKeyStatus::Rejected, None)
}

const TYPE: DefinitionKey = required("type");
const TYPE_VERSION: DefinitionKey = row(
    "type_version",
    DefinitionKeyStatus::RequiredForCatalogType,
    None,
);
const SUSPICIOUS_TOKENS: DefinitionKey = absent_means(
    "suspicious_tokens",
    "Absent means no model indicator is used.",
);
const MAX_DATA_LEN: DefinitionKey = absent_means("max_data_len", "Absent means no length limit.");

const MULTIDIMENSION_KEYS: &[DefinitionKey] = &[
    TYPE,
    TYPE_VERSION,
    required("raw_event_kind"),
    rejected("log_kind"),
    required("method"),
    required("sources"),
    required("window_start"),
    required("window_end"),
    required("data_store"),
    required("batch_size"),
    required("max_event_id_num"),
    SUSPICIOUS_TOKENS,
    required("algorithm"),
    required("eps"),
    required("precision"),
    row(
        "numbers_of_top_n",
        DefinitionKeyStatus::Required,
        Some(
            "When shorter than the [csv] columns, an empty list included, each remaining \
             DateTime column uses 336 and every other remaining column 30.",
        ),
    ),
    required("min_token_length"),
    required("long_pattern_len"),
    MAX_DATA_LEN,
    rejected("max_token_length"),
    required("csv"),
    required("csv.reader"),
    required("csv.format"),
    absent_means("csv.time_column", "Absent means none."),
    absent_means("csv.count_columns", "Absent means none."),
    absent_means(
        "csv.prefix_columns",
        "Absent means none, and the model uses the centroid approach.",
    ),
    absent_means(
        "csv.time_intervals",
        "When absent or shorter than the DateTime columns, each remaining DateTime column \
         uses 3600 seconds.",
    ),
    rejected("slot_size"),
    rejected("group_by"),
    rejected("threat_role"),
    rejected("min_cluster_size"),
    rejected("transform"),
];

const PREFIX_KEYS: &[DefinitionKey] = &[
    TYPE,
    TYPE_VERSION,
    row(
        "raw_event_kind",
        DefinitionKeyStatus::Required,
        Some("Always \"log\"."),
    ),
    required("log_kind"),
    required("method"),
    required("sources"),
    required("window_start"),
    required("window_end"),
    required("data_store"),
    required("batch_size"),
    required("max_event_id_num"),
    SUSPICIOUS_TOKENS,
    rejected("algorithm"),
    rejected("eps"),
    rejected("precision"),
    rejected("numbers_of_top_n"),
    required("min_token_length"),
    required("long_pattern_len"),
    MAX_DATA_LEN,
    absent_means("max_token_length", "Absent means no limit."),
    rejected("csv"),
    rejected("slot_size"),
    rejected("group_by"),
    rejected("threat_role"),
    rejected("min_cluster_size"),
    rejected("transform"),
];

const TIMESERIES_KEYS: &[DefinitionKey] = &[
    TYPE,
    TYPE_VERSION,
    required("raw_event_kind"),
    rejected("log_kind"),
    required("method"),
    required("sources"),
    required("window_start"),
    required("window_end"),
    required("data_store"),
    required("batch_size"),
    required("max_event_id_num"),
    SUSPICIOUS_TOKENS,
    required("algorithm"),
    required("eps"),
    required("precision"),
    required("numbers_of_top_n"),
    rejected("min_token_length"),
    rejected("long_pattern_len"),
    rejected("max_data_len"),
    rejected("max_token_length"),
    rejected("csv"),
];

const fn default(key: &'static str, value: DefinitionValue) -> FixedValue {
    FixedValue { key, value }
}

const DEFAULT_TYPE: FixedValue = default("type", DefinitionValue::String(CUSTOM));
const DEFAULT_BATCH_SIZE: FixedValue = default("batch_size", DefinitionValue::Integer(1_000_000));
const DEFAULT_MAX_EVENT_ID_NUM: FixedValue =
    default("max_event_id_num", DefinitionValue::Integer(25));
const DEFAULT_ALGORITHM: FixedValue = default("algorithm", DefinitionValue::String("dbscan"));
const DEFAULT_EPS: FixedValue = default("eps", DefinitionValue::Float(2.0));
const DEFAULT_PRECISION: FixedValue = default("precision", DefinitionValue::Integer(2));
const DEFAULT_NUMBERS_OF_TOP_N: FixedValue =
    default("numbers_of_top_n", DefinitionValue::IntegerList(&[]));
const DEFAULT_MIN_TOKEN_LENGTH: FixedValue =
    default("min_token_length", DefinitionValue::Integer(2));
const DEFAULT_LONG_PATTERN_LEN: FixedValue =
    default("long_pattern_len", DefinitionValue::Integer(16000));

const MULTIDIMENSION_DEFAULTS: &[FixedValue] = &[
    DEFAULT_TYPE,
    DEFAULT_BATCH_SIZE,
    DEFAULT_MAX_EVENT_ID_NUM,
    DEFAULT_ALGORITHM,
    DEFAULT_EPS,
    DEFAULT_PRECISION,
    DEFAULT_NUMBERS_OF_TOP_N,
    DEFAULT_MIN_TOKEN_LENGTH,
    DEFAULT_LONG_PATTERN_LEN,
];

const PREFIX_DEFAULTS: &[FixedValue] = &[
    DEFAULT_TYPE,
    DEFAULT_BATCH_SIZE,
    DEFAULT_MAX_EVENT_ID_NUM,
    DEFAULT_MIN_TOKEN_LENGTH,
    DEFAULT_LONG_PATTERN_LEN,
];

const TIMESERIES_DEFAULTS: &[FixedValue] = &[
    DEFAULT_TYPE,
    DEFAULT_BATCH_SIZE,
    DEFAULT_MAX_EVENT_ID_NUM,
    DEFAULT_ALGORITHM,
    DEFAULT_EPS,
    DEFAULT_PRECISION,
    DEFAULT_NUMBERS_OF_TOP_N,
];

/// Returns the key table of `method`: one row per key, in the table's order,
/// with each `[csv]` part of a `multidimension` definition as a row of its
/// own right after `csv`.
///
/// The time-series keys of the `timeseries` method are not defined yet, so
/// its table does not list them, and a definition holding one is refused as
/// unknown.
#[must_use]
pub fn definition_keys(method: ModelMethod) -> &'static [DefinitionKey] {
    match method {
        ModelMethod::Multidimension => MULTIDIMENSION_KEYS,
        ModelMethod::Prefix => PREFIX_KEYS,
        ModelMethod::Timeseries => TIMESERIES_KEYS,
    }
}

/// Returns the defaults of a custom definition of `method`, in key table
/// order, for the keys that have one.
///
/// The `[csv]` default of a `multidimension` definition depends on its raw
/// event kind; [`custom_csv_default`] returns it.
#[must_use]
pub fn custom_defaults(method: ModelMethod) -> &'static [FixedValue] {
    match method {
        ModelMethod::Multidimension => MULTIDIMENSION_DEFAULTS,
        ModelMethod::Prefix => PREFIX_DEFAULTS,
        ModelMethod::Timeseries => TIMESERIES_DEFAULTS,
    }
}

/// Returns the `[csv]` default of a custom `multidimension` definition of
/// the raw event kind `raw_event_kind`, a snake-case name such as `http`:
/// the `[csv]` fixed value of the kind's catalog type, every part included.
/// Returns `None` if no `multidimension` catalog type reads the kind.
#[must_use]
pub fn custom_csv_default(raw_event_kind: &str) -> Option<&'static [FixedValue]> {
    multidimension_type_of(raw_event_kind).and_then(|t| match t.fixed_value(CSV) {
        Some(DefinitionValue::Table(csv)) => Some(*csv),
        _ => None,
    })
}

/// Returns the first `multidimension` catalog type that reads
/// `raw_event_kind`.
fn multidimension_type_of(raw_event_kind: &str) -> Option<&'static ClusteringModelType> {
    clustering_model_types().iter().find(|t| {
        t.method == ModelMethod::Multidimension
            && matches!(
                t.fixed_value("raw_event_kind"),
                Some(DefinitionValue::String(kind)) if *kind == raw_event_kind
            )
    })
}

/// Checks a training definition's text against its clustering model type,
/// and returns the type it names.
///
/// It reads no store, so it leaves to the caller: the contents of
/// `sources`, `[data_store]` and `suspicious_tokens`, which must name things
/// of the customer; `window_start` before `window_end` in a custom
/// definition; the window's upper bound, the data store's retention; a
/// `prefix` definition's log kind name; and every bound on a custom
/// definition other than the largest `batch_size`.
///
/// # Errors
///
/// Returns a [`TrainingDefinitionRefusal`] for the first rule the text
/// breaks, the rules taken in this order:
///
/// 1. The text, `type` and `type_version`: text that is not TOML, or an
///    absent or non-string `type`, is `InvalidDocument`; a `type` that is
///    neither a catalog type nor `custom` is `UnknownModelType`; for a
///    catalog type, a `type_version` that is absent or another integer than
///    the type's version is `ModelTypeVersionMismatch`, and one that is not
///    an integer `InvalidDocument`.
/// 2. `method` and unknown keys: an absent, non-string or unknown `method`
///    is `InvalidDocument`, and a key outside the method's key table, at the
///    top level or directly inside `[csv]`, is `UnknownField`.
/// 3. A catalog type: another `method` is `FieldFixed`, another
///    `raw_event_kind` `EventKindNotAllowed`; a key the type does not allow,
///    or an absent fixed value or required operator value, is
///    `FieldNotAllowed`; a fixed value that differs is `FieldFixed`; an
///    operator value outside its range is `BoundViolated`, except an empty
///    `sources`, which is `InvalidDocument`.
/// 4. A custom definition: an absent required key or a present rejected one
///    (`type_version` included) is `FieldNotAllowed`; a `raw_event_kind` the
///    method does not take is `EventKindNotAllowed`; a `batch_size` above
///    5,000,000 is `BoundViolated`.
///
/// A value of the wrong TOML type is `InvalidDocument` within the rule that
/// reads it.
pub fn check_training_definition(
    definition: &str,
) -> Result<ClusteringModelTypeRef, TrainingDefinitionRefusal> {
    use TrainingDefinitionRefusalCode::InvalidDocument;

    let document: Table = toml::from_str(definition).map_err(|e| {
        let message = e.message();
        refusal(
            InvalidDocument,
            "",
            message,
            format!("invalid training definition: {message}"),
        )
    })?;
    let model_type = read_type(&document)?;
    let method = read_method(&document)?;
    check_unknown_keys(&document, method)?;
    if let Some(t) = model_type {
        check_catalog_type(&document, method, t)?;
        Ok(ClusteringModelTypeRef::Catalog {
            id: t.id.to_owned(),
            version: t.version,
        })
    } else {
        check_custom(&document, method)?;
        Ok(ClusteringModelTypeRef::Custom)
    }
}

fn refusal(
    code: TrainingDefinitionRefusalCode,
    key: impl Into<String>,
    value: impl Into<String>,
    message: impl Into<String>,
) -> TrainingDefinitionRefusal {
    TrainingDefinitionRefusal {
        code,
        key: key.into(),
        value: value.into(),
        message: message.into(),
    }
}

/// Returns `value` as the text of a refusal: a string without quotes, any
/// other value as TOML.
fn value_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Returns the name of `method` in a definition.
const fn method_name(method: ModelMethod) -> &'static str {
    match method {
        ModelMethod::Multidimension => "multidimension",
        ModelMethod::Prefix => "prefix",
        ModelMethod::Timeseries => "timeseries",
    }
}

/// Returns the catalog type `type` names, or `None` for `custom`, after
/// checking `type_version` against it (rule 1).
fn read_type(
    document: &Table,
) -> Result<Option<&'static ClusteringModelType>, TrainingDefinitionRefusal> {
    use TrainingDefinitionRefusalCode::{
        InvalidDocument, ModelTypeVersionMismatch, UnknownModelType,
    };

    let id = match document.get(TYPE.key) {
        Some(Value::String(id)) => id,
        Some(other) => {
            return Err(refusal(
                InvalidDocument,
                TYPE.key,
                value_text(other),
                "type is not a string",
            ));
        }
        None => return Err(refusal(InvalidDocument, TYPE.key, "", "type is missing")),
    };
    if id == CUSTOM {
        return Ok(None);
    }
    let Some(t) = clustering_model_type(id) else {
        return Err(refusal(
            UnknownModelType,
            TYPE.key,
            id.as_str(),
            format!("{id:?} is neither a clustering model type nor \"{CUSTOM}\""),
        ));
    };
    match document.get(TYPE_VERSION.key) {
        Some(Value::Integer(version)) if *version == i64::from(t.version) => Ok(Some(t)),
        Some(Value::Integer(version)) => Err(refusal(
            ModelTypeVersionMismatch,
            TYPE_VERSION.key,
            version.to_string(),
            format!("{} is at version {}, not {version}", t.id, t.version),
        )),
        Some(other) => Err(refusal(
            InvalidDocument,
            TYPE_VERSION.key,
            value_text(other),
            "type_version is not an integer",
        )),
        None => Err(refusal(
            ModelTypeVersionMismatch,
            TYPE_VERSION.key,
            "",
            format!(
                "type_version is missing; {} is at version {}",
                t.id, t.version
            ),
        )),
    }
}

/// Returns the method `method` names (rule 2).
fn read_method(document: &Table) -> Result<ModelMethod, TrainingDefinitionRefusal> {
    use TrainingDefinitionRefusalCode::InvalidDocument;

    const KEY: &str = "method";
    match document.get(KEY) {
        Some(Value::String(name)) => [
            ModelMethod::Multidimension,
            ModelMethod::Prefix,
            ModelMethod::Timeseries,
        ]
        .into_iter()
        .find(|m| method_name(*m) == name)
        .ok_or_else(|| {
            refusal(
                InvalidDocument,
                KEY,
                name.as_str(),
                format!("{name:?} is not a training method"),
            )
        }),
        Some(other) => Err(refusal(
            InvalidDocument,
            KEY,
            value_text(other),
            "method is not a string",
        )),
        None => Err(refusal(InvalidDocument, KEY, "", "method is missing")),
    }
}

/// Returns the row of the top-level key `key` in `rows`.
fn top_level_row(rows: &'static [DefinitionKey], key: &str) -> Option<&'static DefinitionKey> {
    if key.contains('.') {
        return None;
    }
    rows.iter().find(|r| r.key == key)
}

/// Returns the row of the `[csv]` part `part` in `rows`.
fn csv_part_row(rows: &'static [DefinitionKey], part: &str) -> Option<&'static DefinitionKey> {
    rows.iter()
        .find(|r| r.key.strip_prefix("csv.") == Some(part))
}

/// Refuses a key outside the key table of `method`, at the top level or,
/// for a method whose table lists the `[csv]` parts, directly inside
/// `[csv]` (rule 2).
fn check_unknown_keys(
    document: &Table,
    method: ModelMethod,
) -> Result<(), TrainingDefinitionRefusal> {
    use TrainingDefinitionRefusalCode::UnknownField;

    let rows = definition_keys(method);
    for (key, value) in document {
        if top_level_row(rows, key).is_none() {
            return Err(refusal(
                UnknownField,
                key.as_str(),
                value_text(value),
                format!("unknown key {key} for the {} method", method_name(method)),
            ));
        }
    }
    let lists_csv_parts = rows.iter().any(|r| r.key.starts_with("csv."));
    if lists_csv_parts && let Some(Value::Table(csv)) = document.get(CSV) {
        for (part, value) in csv {
            if csv_part_row(rows, part).is_none() {
                let key = format!("{CSV}.{part}");
                return Err(refusal(
                    UnknownField,
                    key.as_str(),
                    value_text(value),
                    format!("unknown key {key}"),
                ));
            }
        }
    }
    Ok(())
}

/// How a value differs from the one a type fixes.
#[derive(Debug, Eq, PartialEq)]
enum Mismatch {
    /// The value is not of the fixed value's type, at the list index if
    /// one is given.
    WrongType(Option<usize>),
    /// The value differs, at the list index if one is given.
    Differs(Option<usize>),
}

/// Compares `actual` with the fixed value `expected`.
///
/// A float accepts an integer or a float of the same value, and an integer
/// only an integer. Lists compare element by element in order, and tables
/// in full, so a key the fixed table lacks differs. For a list of tables,
/// the index of the first element that is not a table, or else of the first
/// that differs, is given; a list of another length differs at the first
/// index past the shorter one.
fn compare(expected: &DefinitionValue, actual: &Value) -> Result<(), Mismatch> {
    match expected {
        DefinitionValue::String(s) => match actual {
            Value::String(a) if a == s => Ok(()),
            Value::String(_) => Err(Mismatch::Differs(None)),
            _ => Err(Mismatch::WrongType(None)),
        },
        DefinitionValue::Integer(i) => match actual {
            Value::Integer(a) if a == i => Ok(()),
            Value::Integer(_) => Err(Mismatch::Differs(None)),
            _ => Err(Mismatch::WrongType(None)),
        },
        DefinitionValue::Float(f) => match float_equals(*f, actual) {
            Some(true) => Ok(()),
            Some(false) => Err(Mismatch::Differs(None)),
            None => Err(Mismatch::WrongType(None)),
        },
        DefinitionValue::IntegerList(list) => {
            let Value::Array(items) = actual else {
                return Err(Mismatch::WrongType(None));
            };
            let mut integers = Vec::with_capacity(items.len());
            for item in items {
                let Value::Integer(i) = item else {
                    return Err(Mismatch::WrongType(None));
                };
                integers.push(*i);
            }
            if integers == *list {
                Ok(())
            } else {
                Err(Mismatch::Differs(None))
            }
        }
        DefinitionValue::Table(fields) => {
            let Value::Table(table) = actual else {
                return Err(Mismatch::WrongType(None));
            };
            compare_table(fields, table)
        }
        DefinitionValue::TableList(tables) => {
            let Value::Array(items) = actual else {
                return Err(Mismatch::WrongType(None));
            };
            let mut actual_tables = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                let Value::Table(table) = item else {
                    return Err(Mismatch::WrongType(Some(i)));
                };
                actual_tables.push(table);
            }
            for (i, table) in actual_tables.iter().enumerate() {
                if let Some(fields) = tables.get(i)
                    && compare_table(fields, table) == Err(Mismatch::WrongType(None))
                {
                    return Err(Mismatch::WrongType(Some(i)));
                }
            }
            for i in 0..tables.len().max(actual_tables.len()) {
                match (tables.get(i), actual_tables.get(i)) {
                    (Some(fields), Some(table)) => {
                        if compare_table(fields, table).is_err() {
                            return Err(Mismatch::Differs(Some(i)));
                        }
                    }
                    _ => return Err(Mismatch::Differs(Some(i))),
                }
            }
            Ok(())
        }
    }
}

/// Compares `table` in full with the fixed table `fields`: a value of the
/// wrong type is reported before a difference.
fn compare_table(fields: &[FixedValue], table: &Table) -> Result<(), Mismatch> {
    let mut differs = table.keys().any(|key| !fields.iter().any(|f| f.key == key));
    for field in fields {
        match table
            .get(field.key)
            .map(|value| compare(&field.value, value))
        {
            None | Some(Err(Mismatch::Differs(_))) => differs = true,
            Some(Err(Mismatch::WrongType(_))) => return Err(Mismatch::WrongType(None)),
            Some(Ok(())) => {}
        }
    }
    if differs {
        Err(Mismatch::Differs(None))
    } else {
        Ok(())
    }
}

/// Returns whether `actual`, an integer or a float, equals `expected`, or
/// `None` if it is neither.
fn float_equals(expected: f64, actual: &Value) -> Option<bool> {
    match actual {
        // The definition must hold exactly the value the type fixes.
        #[allow(clippy::float_cmp)]
        Value::Float(a) => Some(*a == expected),
        Value::Integer(a) => Some(expected.fract() == 0.0 && expected.to_i64() == Some(*a)),
        _ => None,
    }
}

/// Returns `path`, followed by `[index]` if an index is given.
fn indexed(path: &str, index: Option<usize>) -> String {
    match index {
        Some(i) => format!("{path}[{i}]"),
        None => path.to_owned(),
    }
}

/// Returns the text of `actual` at `index`, or of `actual` itself if no
/// index is given; empty if `actual` has no element at `index`.
fn element_text(actual: &Value, index: Option<usize>) -> String {
    match index {
        None => value_text(actual),
        Some(i) => match actual {
            Value::Array(items) => items.get(i).map_or_default(value_text),
            _ => String::new(),
        },
    }
}

/// Refuses `actual`, the value at `path`, if it is not the fixed value
/// `expected` of `t`.
fn check_fixed_value(
    t: &ClusteringModelType,
    path: &str,
    expected: &DefinitionValue,
    actual: &Value,
) -> Result<(), TrainingDefinitionRefusal> {
    use TrainingDefinitionRefusalCode::{FieldFixed, InvalidDocument};

    match compare(expected, actual) {
        Ok(()) => Ok(()),
        Err(Mismatch::WrongType(index)) => {
            let key = indexed(path, index);
            Err(refusal(
                InvalidDocument,
                key.as_str(),
                element_text(actual, index),
                format!(
                    "{key} is not a {:?} as {} fixes it",
                    expected.value_type(),
                    t.id
                ),
            ))
        }
        Err(Mismatch::Differs(index)) => {
            let key = indexed(path, index);
            Err(refusal(
                FieldFixed,
                key.as_str(),
                element_text(actual, index),
                format!(
                    "{key} differs from the value {} version {} fixes",
                    t.id, t.version
                ),
            ))
        }
    }
}

/// Checks a definition of the catalog type `t` (rule 3).
fn check_catalog_type(
    document: &Table,
    method: ModelMethod,
    t: &'static ClusteringModelType,
) -> Result<(), TrainingDefinitionRefusal> {
    use TrainingDefinitionRefusalCode::{
        EventKindNotAllowed, FieldFixed, FieldNotAllowed, InvalidDocument,
    };

    const METHOD: &str = "method";
    const RAW_EVENT_KIND: &str = "raw_event_kind";

    if method != t.method {
        return Err(refusal(
            FieldFixed,
            METHOD,
            method_name(method),
            format!(
                "{} trains with the {} method, not {}",
                t.id,
                method_name(t.method),
                method_name(method)
            ),
        ));
    }
    if let Some(expected) = t.fixed_value(RAW_EVENT_KIND) {
        let Some(actual) = document.get(RAW_EVENT_KIND) else {
            return Err(refusal(
                FieldNotAllowed,
                RAW_EVENT_KIND,
                "",
                format!("{} requires raw_event_kind", t.id),
            ));
        };
        match compare(expected, actual) {
            Ok(()) => {}
            Err(Mismatch::WrongType(_)) => {
                return Err(refusal(
                    InvalidDocument,
                    RAW_EVENT_KIND,
                    value_text(actual),
                    "raw_event_kind is not a string",
                ));
            }
            Err(Mismatch::Differs(_)) => {
                return Err(refusal(
                    EventKindNotAllowed,
                    RAW_EVENT_KIND,
                    value_text(actual),
                    format!("{} does not read {} raw events", t.id, value_text(actual)),
                ));
            }
        }
    }

    for (key, value) in document {
        let allowed = key == TYPE.key
            || key == TYPE_VERSION.key
            || key == METHOD
            || key == RAW_EVENT_KIND
            || t.fixed_value(key).is_some()
            || t.operator_value(key).is_some();
        if !allowed {
            return Err(refusal(
                FieldNotAllowed,
                key.as_str(),
                value_text(value),
                format!("{} does not take {key}", t.id),
            ));
        }
    }

    for fixed in t.fixed {
        if fixed.key == METHOD || fixed.key == RAW_EVENT_KIND {
            continue;
        }
        let Some(actual) = document.get(fixed.key) else {
            return Err(refusal(
                FieldNotAllowed,
                fixed.key,
                "",
                format!("{} requires {}", t.id, fixed.key),
            ));
        };
        match &fixed.value {
            DefinitionValue::Table(parts) => check_fixed_table(t, fixed.key, parts, actual)?,
            expected => check_fixed_value(t, fixed.key, expected, actual)?,
        }
    }

    check_operator_values(document, t)
}

/// Checks the top-level table `key` of a definition of `t` against the
/// table `parts` it fixes: an absent part is `FieldNotAllowed`, and a part
/// that differs, or one the fixed table lacks, `FieldFixed`.
fn check_fixed_table(
    t: &ClusteringModelType,
    key: &str,
    parts: &[FixedValue],
    actual: &Value,
) -> Result<(), TrainingDefinitionRefusal> {
    use TrainingDefinitionRefusalCode::{FieldFixed, FieldNotAllowed, InvalidDocument};

    let Value::Table(table) = actual else {
        return Err(refusal(
            InvalidDocument,
            key,
            value_text(actual),
            format!("{key} is not a table"),
        ));
    };
    for part in parts {
        let path = format!("{key}.{}", part.key);
        let Some(value) = table.get(part.key) else {
            return Err(refusal(
                FieldNotAllowed,
                path.as_str(),
                "",
                format!("{} requires {path}", t.id),
            ));
        };
        check_fixed_value(t, &path, &part.value, value)?;
    }
    if let Some((part, value)) = table
        .iter()
        .find(|(part, _)| !parts.iter().any(|p| p.key == part.as_str()))
    {
        let path = format!("{key}.{part}");
        return Err(refusal(
            FieldFixed,
            path.as_str(),
            value_text(value),
            format!("{} fixes {key} without {part}", t.id),
        ));
    }
    Ok(())
}

/// Returns whether `value` is of `value_type`.
fn is_of_type(value_type: DefinitionValueType, value: &Value) -> bool {
    match value_type {
        DefinitionValueType::String => value.is_str(),
        DefinitionValueType::Timestamp => timestamp(value).is_some(),
        DefinitionValueType::Integer => value.is_integer(),
        DefinitionValueType::Float => value.is_integer() || value.is_float(),
        DefinitionValueType::StringList => value
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_str)),
        DefinitionValueType::IntegerList => value
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_integer)),
        DefinitionValueType::Table => value.is_table(),
        DefinitionValueType::TableList => value
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_table)),
    }
}

/// Returns the timestamp `value` holds, a string in RFC 3339 with an
/// offset.
///
/// The syntax is checked before parsing because `jiff` parses the broader
/// Temporal syntax, which also takes a time without seconds and a time
/// zone annotation.
fn timestamp(value: &Value) -> Option<Timestamp> {
    value
        .as_str()
        .filter(|s| is_rfc3339_date_time(s))
        .and_then(|s| s.parse().ok())
}

/// Returns whether `s` has the syntax of an RFC 3339 `date-time`:
/// `YYYY-MM-DDTHH:MM:SS`, optional fractional seconds, then `Z` or
/// `±HH:MM`. `T` and `Z` may be lowercase, as RFC 3339 allows. The values
/// of the fields are left to the parser.
fn is_rfc3339_date_time(s: &str) -> bool {
    /// Returns the rest of `s` after `pattern`, where `d` matches an ASCII
    /// digit and `T` either case of `T`.
    fn strip<'a>(s: &'a [u8], pattern: &[u8]) -> Option<&'a [u8]> {
        let head = s.get(..pattern.len())?;
        let matches = head.iter().zip(pattern).all(|(c, p)| match p {
            b'd' => c.is_ascii_digit(),
            b'T' => c.eq_ignore_ascii_case(&b'T'),
            _ => c == p,
        });
        matches.then(|| s.get(pattern.len()..)).flatten()
    }

    let Some(mut rest) = strip(s.as_bytes(), b"dddd-dd-ddTdd:dd:dd") else {
        return false;
    };
    if let Some(fraction) = rest.strip_prefix(b".") {
        let digits = fraction.iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 {
            return false;
        }
        rest = fraction.get(digits..).unwrap_or_default();
    }
    match rest {
        [b'Z' | b'z'] => true,
        [b'+' | b'-', offset @ ..] => strip(offset, b"dd:dd").is_some_and(<[u8]>::is_empty),
        _ => false,
    }
}

/// Returns whether `value`, a list, string or table, is empty.
fn is_empty(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.is_empty(),
        Value::String(s) => s.is_empty(),
        Value::Table(table) => table.is_empty(),
        _ => false,
    }
}

/// Checks the operator values of a definition of `t`: each must be present
/// unless the catalog marks it optional, of its type and within its range.
fn check_operator_values(
    document: &Table,
    t: &ClusteringModelType,
) -> Result<(), TrainingDefinitionRefusal> {
    use TrainingDefinitionRefusalCode::{BoundViolated, FieldNotAllowed, InvalidDocument};

    let mut window = HashMap::new();
    let mut min_window: Option<SignedDuration> = None;
    for operator_value in t.operator_values {
        let name = operator_value.name;
        let Some(value) = document.get(name) else {
            if operator_value.optional {
                continue;
            }
            return Err(refusal(
                FieldNotAllowed,
                name,
                "",
                format!("{} requires {name}", t.id),
            ));
        };
        if !is_of_type(operator_value.value_type, value) {
            return Err(refusal(
                InvalidDocument,
                name,
                value_text(value),
                format!("{name} is not a {:?}", operator_value.value_type),
            ));
        }
        match operator_value.range {
            Some(DefinitionValueRange::Integer { min, max }) => {
                if let Some(n) = value.as_integer()
                    && !(min..=max).contains(&n)
                {
                    return Err(refusal(
                        BoundViolated,
                        name,
                        n.to_string(),
                        format!("{name} must be within {min}..={max} for {}", t.id),
                    ));
                }
            }
            Some(DefinitionValueRange::NonEmpty) => {
                if is_empty(value) {
                    // An empty `sources` is refused as review-web refuses it.
                    return Err(if name == SOURCES {
                        refusal(InvalidDocument, name, "", "sources must not be empty")
                    } else {
                        refusal(
                            BoundViolated,
                            name,
                            value_text(value),
                            format!("{name} must not be empty"),
                        )
                    });
                }
            }
            Some(DefinitionValueRange::Window { min }) => {
                if let Some(at) = timestamp(value) {
                    window.insert(name, (at, value));
                }
                min_window = Some(min_window.map_or(min, |m| m.max(min)));
            }
            None => {}
        }
    }
    if let (Some(min), Some((start, _)), Some((end, end_value))) =
        (min_window, window.get(WINDOW_START), window.get(WINDOW_END))
        && end.duration_since(*start) < min
    {
        return Err(refusal(
            BoundViolated,
            WINDOW_END,
            value_text(end_value),
            format!("the training window of {} must span at least {min:#}", t.id),
        ));
    }
    Ok(())
}

/// Checks a custom definition of `method` (rule 4).
fn check_custom(document: &Table, method: ModelMethod) -> Result<(), TrainingDefinitionRefusal> {
    use TrainingDefinitionRefusalCode::{BoundViolated, EventKindNotAllowed};

    check_custom_keys(document, method)?;

    if let Some(Value::String(kind)) = document.get("raw_event_kind") {
        let allowed = match method {
            ModelMethod::Multidimension => multidimension_type_of(kind).is_some(),
            ModelMethod::Prefix => kind == PREFIX_RAW_EVENT_KIND,
            ModelMethod::Timeseries => true,
        };
        if !allowed {
            return Err(refusal(
                EventKindNotAllowed,
                "raw_event_kind",
                kind.as_str(),
                format!(
                    "the {} method does not take raw event kind {kind:?}",
                    method_name(method)
                ),
            ));
        }
    }

    if let Some(Value::Integer(batch_size)) = document.get("batch_size")
        && *batch_size > MAX_CUSTOM_BATCH_SIZE
    {
        return Err(refusal(
            BoundViolated,
            "batch_size",
            batch_size.to_string(),
            format!("batch_size is larger than {MAX_CUSTOM_BATCH_SIZE}"),
        ));
    }
    Ok(())
}

/// Checks that a custom definition of `method` holds every key the method
/// requires and none it rejects, and that the values it reads are of their
/// TOML types.
fn check_custom_keys(
    document: &Table,
    method: ModelMethod,
) -> Result<(), TrainingDefinitionRefusal> {
    use TrainingDefinitionRefusalCode::{FieldNotAllowed, InvalidDocument};

    let rows = definition_keys(method);
    for (key, value) in document {
        if top_level_row(rows, key).is_some_and(|r| {
            matches!(
                r.status,
                DefinitionKeyStatus::Rejected | DefinitionKeyStatus::RequiredForCatalogType
            )
        }) {
            return Err(refusal(
                FieldNotAllowed,
                key.as_str(),
                value_text(value),
                format!(
                    "a custom {} definition does not take {key}",
                    method_name(method)
                ),
            ));
        }
    }
    for r in rows {
        if r.status == DefinitionKeyStatus::Required
            && !r.key.contains('.')
            && !document.contains_key(r.key)
        {
            return Err(refusal(
                FieldNotAllowed,
                r.key,
                "",
                format!(
                    "a custom {} definition requires {}",
                    method_name(method),
                    r.key
                ),
            ));
        }
    }

    for (key, value_type) in [
        ("raw_event_kind", DefinitionValueType::String),
        ("log_kind", DefinitionValueType::String),
        ("batch_size", DefinitionValueType::Integer),
        (CSV, DefinitionValueType::Table),
    ] {
        if let Some(value) = document.get(key)
            && !is_of_type(value_type, value)
        {
            return Err(refusal(
                InvalidDocument,
                key,
                value_text(value),
                format!("{key} is not a {value_type:?}"),
            ));
        }
    }
    if let Some(Value::Table(csv)) = document.get(CSV) {
        for r in rows {
            if r.status == DefinitionKeyStatus::Required
                && let Some(part) = r.key.strip_prefix("csv.")
                && !csv.contains_key(part)
            {
                return Err(refusal(
                    FieldNotAllowed,
                    r.key,
                    "",
                    format!(
                        "a custom {} definition requires {}",
                        method_name(method),
                        r.key
                    ),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrainingDefinitionRefusalCode::{
        BoundViolated, EventKindNotAllowed, FieldFixed, FieldNotAllowed, InvalidDocument,
        ModelTypeVersionMismatch, UnknownField, UnknownModelType,
    };

    type Code = TrainingDefinitionRefusalCode;

    const METHODS: [ModelMethod; 3] = [
        ModelMethod::Multidimension,
        ModelMethod::Prefix,
        ModelMethod::Timeseries,
    ];

    /// Returns the value of the TOML text `text`.
    fn v(text: &str) -> Value {
        toml::from_str::<Table>(&format!("x = {text}"))
            .unwrap()
            .remove("x")
            .unwrap()
    }

    /// Returns `value` as TOML.
    fn toml_value(value: &DefinitionValue) -> Value {
        match value {
            DefinitionValue::String(s) => Value::String((*s).to_string()),
            DefinitionValue::Integer(i) => Value::Integer(*i),
            DefinitionValue::Float(f) => Value::Float(*f),
            DefinitionValue::IntegerList(list) => {
                Value::Array(list.iter().map(|i| Value::Integer(*i)).collect())
            }
            DefinitionValue::Table(fields) => Value::Table(toml_table(fields)),
            DefinitionValue::TableList(tables) => Value::Array(
                tables
                    .iter()
                    .map(|fields| Value::Table(toml_table(fields)))
                    .collect(),
            ),
        }
    }

    fn toml_table(fields: &[FixedValue]) -> Table {
        fields
            .iter()
            .map(|f| (f.key.to_string(), toml_value(&f.value)))
            .collect()
    }

    /// The values the operator sets in every complete definition: a window
    /// of exactly 7 days.
    fn operator_values() -> Table {
        toml::from_str(
            r#"
            sources = ["sensor-a"]
            window_start = "2026-01-01T00:00:00Z"
            window_end = "2026-01-08T00:00:00+00:00"
            batch_size = 1000000
            max_event_id_num = 50
            suspicious_tokens = "tokens"
            [data_store]
            server_name = "store-1"
            "#,
        )
        .unwrap()
    }

    /// A complete `http_url` v1 definition.
    fn http_url() -> Table {
        let t = clustering_model_type("http_url").unwrap();
        let mut table = operator_values();
        table.insert("type".to_string(), v(r#""http_url""#));
        table.insert("type_version".to_string(), v("1"));
        table.extend(toml_table(t.fixed));
        table
    }

    /// A valid custom definition of `method`.
    fn custom(method: ModelMethod) -> Table {
        let mut table = operator_values();
        let text = match method {
            ModelMethod::Multidimension => {
                r#"
                type = "custom"
                method = "multidimension"
                raw_event_kind = "http"
                algorithm = "dbscan"
                eps = 2.0
                precision = 2
                numbers_of_top_n = []
                min_token_length = 2
                long_pattern_len = 16000
                [csv]
                reader = { delimiter = 9 }
                format = [{ name = "a" }]
                "#
            }
            ModelMethod::Prefix => {
                r#"
                type = "custom"
                method = "prefix"
                raw_event_kind = "log"
                log_kind = "syslog"
                min_token_length = 2
                long_pattern_len = 16000
                "#
            }
            ModelMethod::Timeseries => {
                r#"
                type = "custom"
                method = "timeseries"
                raw_event_kind = "conn"
                algorithm = "dbscan"
                eps = 2
                precision = 2
                numbers_of_top_n = [1, 2]
                "#
            }
        };
        table.extend(toml::from_str::<Table>(text).unwrap());
        table
    }

    fn with(mut table: Table, key: &str, value: Value) -> Table {
        table.insert(key.to_string(), value);
        table
    }

    fn without(mut table: Table, key: &str) -> Table {
        assert!(table.remove(key).is_some(), "{key} is not in the table");
        table
    }

    fn csv_mut(table: &mut Table) -> &mut Table {
        table.get_mut(CSV).unwrap().as_table_mut().unwrap()
    }

    fn check(table: &Table) -> Result<ClusteringModelTypeRef, TrainingDefinitionRefusal> {
        check_training_definition(&toml::to_string(table).unwrap())
    }

    /// Returns the code, key and value of the refusal of `table`.
    fn refused(table: &Table) -> (Code, String, String) {
        let refusal = check(table).unwrap_err();
        assert_ne!(refusal.message, "");
        assert_eq!(refusal.to_string(), refusal.message);
        (refusal.code, refusal.key, refusal.value)
    }

    fn r(code: Code, key: &str, value: &str) -> (Code, String, String) {
        (code, key.to_string(), value.to_string())
    }

    fn http_url_v1() -> ClusteringModelTypeRef {
        ClusteringModelTypeRef::Catalog {
            id: "http_url".to_string(),
            version: 1,
        }
    }

    #[test]
    fn refusal_codes_are_exactly_eight() {
        let all = [
            InvalidDocument,
            UnknownField,
            UnknownModelType,
            ModelTypeVersionMismatch,
            EventKindNotAllowed,
            FieldFixed,
            FieldNotAllowed,
            BoundViolated,
        ];
        for code in all {
            // Exhaustive: a ninth case fails to compile here.
            match code {
                InvalidDocument
                | UnknownField
                | UnknownModelType
                | ModelTypeVersionMismatch
                | EventKindNotAllowed
                | FieldFixed
                | FieldNotAllowed
                | BoundViolated => {}
            }
        }
    }

    #[test]
    fn items_are_reachable_from_the_crate_root() {
        let check: fn(&str) -> Result<ClusteringModelTypeRef, crate::TrainingDefinitionRefusal> =
            crate::check_training_definition;
        let refusal = check("").unwrap_err();
        let _: crate::TrainingDefinitionRefusalCode = refusal.code;
        let keys: &[crate::DefinitionKey] = crate::definition_keys(ModelMethod::Prefix);
        assert_eq!(
            keys.first().map(|k| k.status),
            Some(crate::DefinitionKeyStatus::Required)
        );
        let defaults: &[FixedValue] = crate::custom_defaults(ModelMethod::Prefix);
        assert_ne!(defaults, []);
        assert!(crate::custom_csv_default("http").is_some());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn key_table_matches_the_contract() {
        use DefinitionKeyStatus::{AbsentMeans, Rejected, Required, RequiredForCatalogType};

        let rows = |method| -> Vec<(&str, DefinitionKeyStatus)> {
            definition_keys(method)
                .iter()
                .map(|k| (k.key, k.status))
                .collect()
        };
        let common_head = [
            ("type", Required),
            ("type_version", RequiredForCatalogType),
            ("raw_event_kind", Required),
        ];
        let common_middle = [
            ("method", Required),
            ("sources", Required),
            ("window_start", Required),
            ("window_end", Required),
            ("data_store", Required),
            ("batch_size", Required),
            ("max_event_id_num", Required),
            ("suspicious_tokens", AbsentMeans),
        ];
        let series_keys = [
            ("slot_size", Rejected),
            ("group_by", Rejected),
            ("threat_role", Rejected),
            ("min_cluster_size", Rejected),
            ("transform", Rejected),
        ];

        let mut multidimension = common_head.to_vec();
        multidimension.push(("log_kind", Rejected));
        multidimension.extend(common_middle);
        multidimension.extend([
            ("algorithm", Required),
            ("eps", Required),
            ("precision", Required),
            ("numbers_of_top_n", Required),
            ("min_token_length", Required),
            ("long_pattern_len", Required),
            ("max_data_len", AbsentMeans),
            ("max_token_length", Rejected),
            ("csv", Required),
            ("csv.reader", Required),
            ("csv.format", Required),
            ("csv.time_column", AbsentMeans),
            ("csv.count_columns", AbsentMeans),
            ("csv.prefix_columns", AbsentMeans),
            ("csv.time_intervals", AbsentMeans),
        ]);
        multidimension.extend(series_keys);
        assert_eq!(rows(ModelMethod::Multidimension), multidimension);

        let mut prefix = common_head.to_vec();
        prefix.push(("log_kind", Required));
        prefix.extend(common_middle);
        prefix.extend([
            ("algorithm", Rejected),
            ("eps", Rejected),
            ("precision", Rejected),
            ("numbers_of_top_n", Rejected),
            ("min_token_length", Required),
            ("long_pattern_len", Required),
            ("max_data_len", AbsentMeans),
            ("max_token_length", AbsentMeans),
            ("csv", Rejected),
        ]);
        prefix.extend(series_keys);
        assert_eq!(rows(ModelMethod::Prefix), prefix);

        let mut timeseries = common_head.to_vec();
        timeseries.push(("log_kind", Rejected));
        timeseries.extend(common_middle);
        timeseries.extend([
            ("algorithm", Required),
            ("eps", Required),
            ("precision", Required),
            ("numbers_of_top_n", Required),
            ("min_token_length", Rejected),
            ("long_pattern_len", Rejected),
            ("max_data_len", Rejected),
            ("max_token_length", Rejected),
            ("csv", Rejected),
        ]);
        assert_eq!(rows(ModelMethod::Timeseries), timeseries);

        // Every absent-means row states its meaning; the fill rules appear in
        // the multidimension entries only.
        let note = |method, key| {
            definition_keys(method)
                .iter()
                .find(|k| k.key == key)
                .unwrap()
                .note
        };
        for method in METHODS {
            for k in definition_keys(method) {
                if k.status == AbsentMeans {
                    assert!(k.note.is_some(), "{method:?} {}", k.key);
                }
            }
            assert_eq!(
                note(method, "suspicious_tokens"),
                Some("Absent means no model indicator is used.")
            );
        }
        for method in [ModelMethod::Multidimension, ModelMethod::Prefix] {
            assert_eq!(
                note(method, "max_data_len"),
                Some("Absent means no length limit.")
            );
        }
        assert_eq!(
            note(ModelMethod::Prefix, "max_token_length"),
            Some("Absent means no limit.")
        );
        assert_eq!(
            note(ModelMethod::Prefix, "raw_event_kind"),
            Some("Always \"log\".")
        );
        let top_n = note(ModelMethod::Multidimension, "numbers_of_top_n").unwrap();
        assert!(top_n.contains("336") && top_n.contains("30"), "{top_n}");
        let intervals = note(ModelMethod::Multidimension, "csv.time_intervals").unwrap();
        assert!(intervals.contains("3600"), "{intervals}");
        assert!(
            note(ModelMethod::Multidimension, "csv.prefix_columns")
                .unwrap()
                .contains("centroid")
        );
        assert_eq!(note(ModelMethod::Timeseries, "numbers_of_top_n"), None);
        for method in METHODS {
            for k in definition_keys(method) {
                let fill = k
                    .note
                    .is_some_and(|n| n.contains("336") || n.contains("3600"));
                assert_eq!(
                    fill,
                    method == ModelMethod::Multidimension
                        && ["numbers_of_top_n", "csv.time_intervals"].contains(&k.key),
                    "{method:?} {}",
                    k.key
                );
            }
        }
    }

    #[test]
    fn custom_defaults_match_the_contract() {
        let defaults = |method| -> Vec<(&str, DefinitionValue)> {
            custom_defaults(method)
                .iter()
                .map(|f| (f.key, f.value))
                .collect()
        };
        let type_ = ("type", DefinitionValue::String("custom"));
        let batch_size = ("batch_size", DefinitionValue::Integer(1_000_000));
        let max_event_id_num = ("max_event_id_num", DefinitionValue::Integer(25));
        let algorithm = ("algorithm", DefinitionValue::String("dbscan"));
        let eps = ("eps", DefinitionValue::Float(2.0));
        let precision = ("precision", DefinitionValue::Integer(2));
        let top_n = ("numbers_of_top_n", DefinitionValue::IntegerList(&[]));
        let min_token_length = ("min_token_length", DefinitionValue::Integer(2));
        let long_pattern_len = ("long_pattern_len", DefinitionValue::Integer(16000));
        assert_eq!(
            defaults(ModelMethod::Multidimension),
            [
                type_,
                batch_size,
                max_event_id_num,
                algorithm,
                eps,
                precision,
                top_n,
                min_token_length,
                long_pattern_len,
            ]
        );
        assert_eq!(
            defaults(ModelMethod::Prefix),
            [
                type_,
                batch_size,
                max_event_id_num,
                min_token_length,
                long_pattern_len,
            ]
        );
        assert_eq!(
            defaults(ModelMethod::Timeseries),
            [
                type_,
                batch_size,
                max_event_id_num,
                algorithm,
                eps,
                precision,
                top_n,
            ]
        );
        // No default is given for a key the method rejects.
        for method in METHODS {
            for f in custom_defaults(method) {
                let row = definition_keys(method)
                    .iter()
                    .find(|k| k.key == f.key)
                    .unwrap();
                assert_ne!(row.status, DefinitionKeyStatus::Rejected, "{}", f.key);
            }
        }

        let http_url = clustering_model_type("http_url").unwrap();
        assert_eq!(
            custom_csv_default("http").map(DefinitionValue::Table),
            http_url.fixed_value(CSV).copied()
        );
        assert_eq!(custom_csv_default("http").map(<[_]>::len), Some(6));
        for kind in ["log", "conn", "dns", "process_create", "", "HTTP"] {
            assert_eq!(custom_csv_default(kind), None, "{kind}");
        }
    }

    #[test]
    fn complete_definitions_pass() {
        assert_eq!(check(&http_url()), Ok(http_url_v1()));
        assert_eq!(
            check(&without(http_url(), "suspicious_tokens")),
            Ok(http_url_v1())
        );
        for method in METHODS {
            assert_eq!(
                check(&custom(method)),
                Ok(ClusteringModelTypeRef::Custom),
                "{method:?}"
            );
            let minimal = without(custom(method), "suspicious_tokens");
            assert_eq!(check(&minimal), Ok(ClusteringModelTypeRef::Custom));
        }
        let mut full = custom(ModelMethod::Multidimension);
        full.insert("max_data_len".to_string(), v("30"));
        let csv = csv_mut(&mut full);
        for (part, value) in [
            ("time_column", "0"),
            ("count_columns", "[0]"),
            ("prefix_columns", "[0]"),
            ("time_intervals", "[60]"),
        ] {
            csv.insert(part.to_string(), v(value));
        }
        assert_eq!(check(&full), Ok(ClusteringModelTypeRef::Custom));
        let mut full = custom(ModelMethod::Prefix);
        full.insert("max_data_len".to_string(), v("30"));
        full.insert("max_token_length".to_string(), v("40"));
        assert_eq!(check(&full), Ok(ClusteringModelTypeRef::Custom));
    }

    #[test]
    fn rule_1_parse_type_and_version() {
        let refusal = check_training_definition("type = ").unwrap_err();
        assert_eq!(refusal.code, InvalidDocument);
        assert_eq!(refusal.key, "");
        assert_ne!(refusal.value, "");
        assert!(refusal.message.contains(&refusal.value));

        assert_eq!(
            refused(&without(http_url(), "type")),
            r(InvalidDocument, "type", "")
        );
        assert_eq!(
            refused(&with(http_url(), "type", v("1"))),
            r(InvalidDocument, "type", "1")
        );
        assert_eq!(
            refused(&with(http_url(), "type", v(r#""dns_query""#))),
            r(UnknownModelType, "type", "dns_query")
        );
        assert_eq!(
            refused(&with(custom(ModelMethod::Prefix), "type", v(r#""Custom""#))),
            r(UnknownModelType, "type", "Custom")
        );
        // The type precedes an unknown key and an absent method.
        let unknown = with(without(http_url(), "method"), "event_kind", v(r#""http""#));
        assert_eq!(
            refused(&with(unknown, "type", v(r#""nope""#))),
            r(UnknownModelType, "type", "nope")
        );

        let version_refusals = [
            (Some("0"), r(ModelTypeVersionMismatch, "type_version", "0")),
            (Some("2"), r(ModelTypeVersionMismatch, "type_version", "2")),
            (None, r(ModelTypeVersionMismatch, "type_version", "")),
            (Some(r#""1""#), r(InvalidDocument, "type_version", "1")),
        ];
        let later_faults = [
            with(http_url(), "eps", v("3.0")),
            with(http_url(), "event_kind", v(r#""http""#)),
            with(http_url(), "batch_size", v(r#""large""#)),
            with(http_url(), "method", v(r#""distribution""#)),
            without(http_url(), "sources"),
            with(http_url(), "raw_event_kind", v(r#""log""#)),
        ];
        for (version, expected) in version_refusals {
            for fault in later_faults.iter().cloned().chain([http_url()]) {
                let table = match version {
                    Some(version) => with(fault, "type_version", v(version)),
                    None => without(fault, "type_version"),
                };
                assert_eq!(refused(&table), expected, "{version:?}");
            }
        }
    }

    #[test]
    fn rule_2_method_and_unknown_keys() {
        for base in [http_url(), custom(ModelMethod::Prefix)] {
            assert_eq!(
                refused(&without(base.clone(), "method")),
                r(InvalidDocument, "method", "")
            );
            assert_eq!(
                refused(&with(base.clone(), "method", v("[1]"))),
                r(InvalidDocument, "method", "[1]")
            );
            assert_eq!(
                refused(&with(base.clone(), "method", v(r#""distribution""#))),
                r(InvalidDocument, "method", "distribution")
            );
            // The method precedes an unknown key.
            let unknown = with(base.clone(), "event_kind", v(r#""http""#));
            assert_eq!(
                refused(&without(unknown, "method")),
                r(InvalidDocument, "method", "")
            );
        }

        // An unknown key precedes every later rule.
        for base in METHODS.map(custom).into_iter().chain([http_url()]) {
            let table = with(base, "event_kind", v(r#""http""#));
            assert_eq!(
                refused(&with(table.clone(), "batch_size", v(r#""large""#))),
                r(UnknownField, "event_kind", "http")
            );
            assert_eq!(
                refused(&without(table, "sources")),
                r(UnknownField, "event_kind", "http")
            );
        }
        assert_eq!(
            refused(&with(http_url(), "csv.reader", v("1"))),
            r(UnknownField, "csv.reader", "1")
        );

        // The time-series keys are rejected by multidimension and prefix and
        // unknown to timeseries.
        for key in [
            "slot_size",
            "group_by",
            "threat_role",
            "min_cluster_size",
            "transform",
        ] {
            for method in [ModelMethod::Multidimension, ModelMethod::Prefix] {
                assert_eq!(
                    refused(&with(custom(method), key, v("1"))),
                    r(FieldNotAllowed, key, "1")
                );
            }
            assert_eq!(
                refused(&with(http_url(), key, v("1"))),
                r(FieldNotAllowed, key, "1")
            );
            assert_eq!(
                refused(&with(custom(ModelMethod::Timeseries), key, v("1"))),
                r(UnknownField, key, "1")
            );
        }

        // A key directly inside [csv] outside the key table is unknown.
        for mut table in [http_url(), custom(ModelMethod::Multidimension)] {
            csv_mut(&mut table).insert("delimiter".to_string(), v("9"));
            assert_eq!(refused(&table), r(UnknownField, "csv.delimiter", "9"));
        }
    }

    #[test]
    fn http_url_fixed_values() {
        assert_eq!(check(&with(http_url(), "eps", v("5"))), Ok(http_url_v1()));
        assert_eq!(check(&with(http_url(), "eps", v("5.0"))), Ok(http_url_v1()));
        assert_eq!(
            refused(&with(http_url(), "eps", v("3.0"))),
            r(FieldFixed, "eps", "3.0")
        );
        assert_eq!(
            refused(&with(http_url(), "eps", v(r#""5.0""#))),
            r(InvalidDocument, "eps", "5.0")
        );
        assert_eq!(
            refused(&with(http_url(), "precision", v("2.0"))),
            r(InvalidDocument, "precision", "2.0")
        );
        assert_eq!(
            refused(&with(http_url(), "algorithm", v(r#""optics""#))),
            r(FieldFixed, "algorithm", "optics")
        );
        assert_eq!(
            refused(&with(http_url(), "numbers_of_top_n", v("[30]"))),
            r(FieldFixed, "numbers_of_top_n", "[30]")
        );
        assert_eq!(
            refused(&with(http_url(), "method", v(r#""prefix""#))),
            r(FieldFixed, "method", "prefix")
        );
        assert_eq!(
            refused(&with(http_url(), "raw_event_kind", v(r#""log""#))),
            r(EventKindNotAllowed, "raw_event_kind", "log")
        );
        assert_eq!(
            refused(&with(http_url(), "raw_event_kind", v("3"))),
            r(InvalidDocument, "raw_event_kind", "3")
        );
        assert_eq!(
            refused(&without(http_url(), "raw_event_kind")),
            r(FieldNotAllowed, "raw_event_kind", "")
        );

        let mut table = http_url();
        csv_mut(&mut table).insert("prefix_columns".to_string(), v("[14]"));
        assert_eq!(refused(&table), r(FieldFixed, "csv.prefix_columns", "[14]"));
        let mut table = http_url();
        csv_mut(&mut table).insert("reader".to_string(), v("{ delimiter = 9 }"));
        assert_eq!(
            refused(&table),
            r(FieldFixed, "csv.reader", "{ delimiter = 9 }")
        );
        let mut table = http_url();
        csv_mut(&mut table).insert(
            "reader".to_string(),
            v("{ delimiter = 9, quote = 0, x = 1 }"),
        );
        assert_eq!(refused(&table).1, "csv.reader");
        let mut table = http_url();
        csv_mut(&mut table).insert("reader".to_string(), v("1"));
        assert_eq!(refused(&table), r(InvalidDocument, "csv.reader", "1"));
        let table = with(http_url(), CSV, v(r#""bad""#));
        assert_eq!(refused(&table), r(InvalidDocument, "csv", "bad"));
    }

    fn format_mut(table: &mut Table) -> &mut Vec<Value> {
        csv_mut(table)
            .get_mut("format")
            .unwrap()
            .as_array_mut()
            .unwrap()
    }

    #[test]
    fn http_url_format_columns() {
        // One changed weight, given as an integer or a float.
        let mut table = http_url();
        let column = format_mut(&mut table)[15].as_table_mut().unwrap();
        column.insert("weight".to_string(), v("1"));
        let text = value_text(&format_mut(&mut table)[15]);
        assert!(text.contains("uri"), "{text}");
        assert_eq!(refused(&table), r(FieldFixed, "csv.format[15]", &text));

        // An integer weight equal to the fixed one passes.
        let mut table = http_url();
        let column = format_mut(&mut table)[15].as_table_mut().unwrap();
        column.insert("weight".to_string(), v("2147483647"));
        assert_eq!(check(&table), Ok(http_url_v1()));

        // A key the fixed column lacks differs.
        let mut table = http_url();
        let column = format_mut(&mut table)[3].as_table_mut().unwrap();
        column.insert("extra".to_string(), v("1"));
        let text = value_text(&format_mut(&mut table)[3]);
        assert_eq!(refused(&table), r(FieldFixed, "csv.format[3]", &text));

        // A missing key differs.
        let mut table = http_url();
        let column = format_mut(&mut table)[4].as_table_mut().unwrap();
        column.remove("data_type");
        let text = value_text(&format_mut(&mut table)[4]);
        assert_eq!(refused(&table), r(FieldFixed, "csv.format[4]", &text));

        // A shorter list differs at the first missing column, with an empty
        // value; a longer one at the first extra column.
        let mut table = http_url();
        format_mut(&mut table).truncate(30);
        assert_eq!(refused(&table), r(FieldFixed, "csv.format[30]", ""));
        let mut table = http_url();
        format_mut(&mut table).push(v(r#"{ name = "x", data_type = "utf8", weight = 0.0 }"#));
        let text = value_text(&format_mut(&mut table)[33]);
        assert_eq!(refused(&table), r(FieldFixed, "csv.format[33]", &text));

        // The first differing column is named.
        let mut table = http_url();
        let format = format_mut(&mut table);
        format.swap(1, 2);
        let text = value_text(&format[1]);
        assert_eq!(refused(&table), r(FieldFixed, "csv.format[1]", &text));

        // A column of the wrong type is an invalid document.
        let mut table = http_url();
        format_mut(&mut table)[7] = v("1");
        assert_eq!(refused(&table), r(InvalidDocument, "csv.format[7]", "1"));
        let mut table = http_url();
        let column = format_mut(&mut table)[8].as_table_mut().unwrap();
        column.insert("weight".to_string(), v(r#""heavy""#));
        let text = value_text(&format_mut(&mut table)[8]);
        assert_eq!(refused(&table), r(InvalidDocument, "csv.format[8]", &text));
    }

    #[test]
    fn http_url_requires_every_fixed_and_operator_value() {
        let t = clustering_model_type("http_url").unwrap();
        for fixed in t.fixed {
            let table = without(http_url(), fixed.key);
            if fixed.key == "method" {
                assert_eq!(refused(&table), r(InvalidDocument, "method", ""));
            } else {
                assert_eq!(
                    refused(&table),
                    r(FieldNotAllowed, fixed.key, ""),
                    "{}",
                    fixed.key
                );
            }
        }
        let Some(DefinitionValue::Table(parts)) = t.fixed_value(CSV) else {
            panic!("http_url fixes no [csv]");
        };
        for part in *parts {
            let mut table = http_url();
            csv_mut(&mut table).remove(part.key);
            let key = format!("csv.{}", part.key);
            assert_eq!(refused(&table), r(FieldNotAllowed, &key, ""));
        }
        for operator_value in t.operator_values {
            let table = without(http_url(), operator_value.name);
            if operator_value.optional {
                assert_eq!(check(&table), Ok(http_url_v1()));
            } else {
                assert_eq!(
                    refused(&table),
                    r(FieldNotAllowed, operator_value.name, ""),
                    "{}",
                    operator_value.name
                );
            }
        }
        assert_eq!(
            refused(&with(http_url(), "max_token_length", v("40"))),
            r(FieldNotAllowed, "max_token_length", "40")
        );
        assert_eq!(
            refused(&with(http_url(), "log_kind", v(r#""syslog""#))),
            r(FieldNotAllowed, "log_kind", "syslog")
        );
    }

    #[test]
    fn http_url_window_timestamps_are_rfc3339() {
        // The Temporal syntax `jiff` parses goes beyond RFC 3339; what it
        // adds is refused.
        for (key, value) in [
            (WINDOW_START, "2026-01-01T00:00Z"),
            (WINDOW_START, "2026-01-01T00:00:00Z[UTC]"),
            (WINDOW_START, "2026-01-01T09:00:00+09:00[Asia/Seoul]"),
            (WINDOW_START, "2026-01-01 00:00:00Z"),
            (WINDOW_START, "20260101T000000Z"),
            (WINDOW_START, "2026-01-01T00:00:00+0900"),
            (WINDOW_START, "2026-01-01T00:00:00+09"),
            (WINDOW_START, "2026-01-01T00:00:00.Z"),
            (WINDOW_START, "2026-01-01T00:00:00,5Z"),
            (WINDOW_START, "+002026-01-01T00:00:00Z"),
            (WINDOW_END, "2026-01-08T00:00Z"),
            (WINDOW_END, "2026-01-08T00:00:00Z[UTC]"),
            (WINDOW_END, "2026-01-08T09:00:00+09:00[Asia/Seoul]"),
            (WINDOW_END, "2026-01-08 00:00:00Z"),
            (WINDOW_END, "20260108T000000Z"),
            (WINDOW_END, "2026-01-08T00:00:00+0900"),
        ] {
            assert_eq!(
                refused(&with(http_url(), key, Value::String(value.to_string()))),
                r(InvalidDocument, key, value),
                "{key} {value}"
            );
        }
        // RFC 3339 allows fractional seconds and a lowercase `T` and `Z`.
        for (start, end) in [
            ("2026-01-01T00:00:00.5Z", "2026-01-08T00:00:00.5Z"),
            ("2026-01-01t00:00:00z", "2026-01-08t00:00:00z"),
            (
                "2026-01-01T00:00:00.123456789-05:00",
                "2026-01-09T00:00:00Z",
            ),
        ] {
            let table = with(http_url(), "window_start", Value::String(start.to_string()));
            let table = with(table, "window_end", Value::String(end.to_string()));
            assert_eq!(check(&table), Ok(http_url_v1()), "{start} {end}");
        }
    }

    #[test]
    fn http_url_operator_values() {
        assert_eq!(
            refused(&with(http_url(), "sources", v("[]"))),
            r(InvalidDocument, "sources", "")
        );
        assert_eq!(
            refused(&with(http_url(), "sources", v(r#""sensor-a""#))),
            r(InvalidDocument, "sources", "sensor-a")
        );
        assert_eq!(
            refused(&with(http_url(), "sources", v("[1]"))),
            r(InvalidDocument, "sources", "[1]")
        );
        assert_eq!(
            refused(&with(http_url(), "suspicious_tokens", v("1"))),
            r(InvalidDocument, "suspicious_tokens", "1")
        );
        assert_eq!(
            refused(&with(http_url(), "data_store", v(r#""store-1""#))),
            r(InvalidDocument, "data_store", "store-1")
        );
        assert_eq!(
            refused(&with(http_url(), "batch_size", v(r#""large""#))),
            r(InvalidDocument, "batch_size", "large")
        );

        // Timestamps are strings in RFC 3339 with an offset.
        let datetime = with(http_url(), "window_start", v("2026-01-01T00:00:00Z"));
        assert_eq!(refused(&datetime).0, InvalidDocument);
        assert_eq!(refused(&datetime).1, "window_start");
        assert_eq!(
            refused(&with(
                http_url(),
                "window_start",
                v(r#""2026-01-01T00:00:00""#)
            )),
            r(InvalidDocument, "window_start", "2026-01-01T00:00:00")
        );
        assert_eq!(
            refused(&with(http_url(), "window_end", v(r#""next week""#))),
            r(InvalidDocument, "window_end", "next week")
        );
        // The window spans at least 7 days.
        for (start, end) in [
            ("2026-01-01T00:00:00Z", "2026-01-08T00:00:00Z"),
            ("2026-01-01T09:00:00+09:00", "2026-01-08T00:00:00Z"),
            ("2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z"),
        ] {
            let table = with(http_url(), "window_start", Value::String(start.to_string()));
            let table = with(table, "window_end", Value::String(end.to_string()));
            assert_eq!(check(&table), Ok(http_url_v1()), "{start} {end}");
        }
        for (start, end) in [
            ("2026-01-01T00:00:01Z", "2026-01-08T00:00:00Z"),
            ("2026-01-01T00:00:00Z", "2026-01-07T23:59:59Z"),
            ("2026-01-08T00:00:00Z", "2026-01-01T00:00:00Z"),
            ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        ] {
            let table = with(http_url(), "window_start", Value::String(start.to_string()));
            let table = with(table, "window_end", Value::String(end.to_string()));
            assert_eq!(
                refused(&table),
                r(BoundViolated, "window_end", end),
                "{start} {end}"
            );
        }

        for (key, value) in [
            ("batch_size", 10_000),
            ("batch_size", 1_000_000),
            ("max_event_id_num", 1),
            ("max_event_id_num", 100),
        ] {
            assert_eq!(
                check(&with(http_url(), key, Value::Integer(value))),
                Ok(http_url_v1()),
                "{key} {value}"
            );
        }
        for (key, value) in [
            ("batch_size", 9_999),
            ("batch_size", 1_000_001),
            ("max_event_id_num", 0),
            ("max_event_id_num", 101),
        ] {
            assert_eq!(
                refused(&with(http_url(), key, Value::Integer(value))),
                r(BoundViolated, key, &value.to_string())
            );
        }
    }

    #[test]
    fn custom_required_and_rejected_keys() {
        for method in METHODS {
            for k in definition_keys(method) {
                match k.status {
                    DefinitionKeyStatus::Required if !["type", "method"].contains(&k.key) => {
                        let mut table = custom(method);
                        if let Some(part) = k.key.strip_prefix("csv.") {
                            csv_mut(&mut table).remove(part);
                        } else {
                            table = without(table, k.key);
                        }
                        assert_eq!(
                            refused(&table),
                            r(FieldNotAllowed, k.key, ""),
                            "{method:?} without {}",
                            k.key
                        );
                    }
                    DefinitionKeyStatus::Rejected | DefinitionKeyStatus::RequiredForCatalogType => {
                        let table = with(custom(method), k.key, v("1"));
                        assert_eq!(
                            refused(&table),
                            r(FieldNotAllowed, k.key, "1"),
                            "{method:?} with {}",
                            k.key
                        );
                    }
                    _ => {}
                }
            }
        }

        // A key that is not allowed is refused whatever its value.
        for method in METHODS {
            assert_eq!(
                refused(&with(custom(method), "type_version", v(r#""1""#))),
                r(FieldNotAllowed, "type_version", "1")
            );
        }
        for method in [ModelMethod::Prefix, ModelMethod::Timeseries] {
            assert_eq!(
                refused(&with(custom(method), CSV, v(r#""bad""#))),
                r(FieldNotAllowed, "csv", "bad")
            );
            assert_eq!(
                refused(&with(custom(method), CSV, v("{ reader = 1, x = 2 }"))).0,
                FieldNotAllowed
            );
        }
        assert_eq!(
            refused(&with(custom(ModelMethod::Timeseries), "log_kind", v("[]"))),
            r(FieldNotAllowed, "log_kind", "[]")
        );
    }

    #[test]
    fn custom_value_types() {
        for method in METHODS {
            assert_eq!(
                refused(&with(custom(method), "batch_size", v(r#""large""#))),
                r(InvalidDocument, "batch_size", "large")
            );
            assert_eq!(
                refused(&with(custom(method), "raw_event_kind", v("1"))),
                r(InvalidDocument, "raw_event_kind", "1")
            );
        }
        assert_eq!(
            refused(&with(custom(ModelMethod::Prefix), "log_kind", v("1"))),
            r(InvalidDocument, "log_kind", "1")
        );
        assert_eq!(
            refused(&with(
                custom(ModelMethod::Multidimension),
                CSV,
                v(r#""bad""#)
            )),
            r(InvalidDocument, "csv", "bad")
        );
        // Other values are not checked for their type, nor the [csv] parts.
        let table = with(custom(ModelMethod::Timeseries), "eps", v(r#""wide""#));
        assert_eq!(check(&table), Ok(ClusteringModelTypeRef::Custom));
        for format in [
            r#""anything""#,
            "[]",
            r#"[1, "x", { a = 1 }, [2.5]]"#,
            "{ nested = { deeper = true } }",
            "2026-01-01T00:00:00Z",
        ] {
            let mut table = custom(ModelMethod::Multidimension);
            csv_mut(&mut table).insert("format".to_string(), v(format));
            csv_mut(&mut table).insert("reader".to_string(), v(format));
            assert_eq!(
                check(&table),
                Ok(ClusteringModelTypeRef::Custom),
                "{format}"
            );
        }
        let mut table = custom(ModelMethod::Multidimension);
        csv_mut(&mut table).insert("time_intervals".to_string(), v(r#""x""#));
        assert_eq!(check(&table), Ok(ClusteringModelTypeRef::Custom));
    }

    #[test]
    fn custom_raw_event_kind_and_batch_size() {
        let multidimension = custom(ModelMethod::Multidimension);
        for kind in ["log", "dns", "conn", "HTTP", ""] {
            assert_eq!(
                refused(&with(
                    multidimension.clone(),
                    "raw_event_kind",
                    Value::String(kind.to_string())
                )),
                r(EventKindNotAllowed, "raw_event_kind", kind)
            );
        }
        for kind in ["http", "dns", "syslog", ""] {
            assert_eq!(
                refused(&with(
                    custom(ModelMethod::Prefix),
                    "raw_event_kind",
                    Value::String(kind.to_string())
                )),
                r(EventKindNotAllowed, "raw_event_kind", kind)
            );
        }
        for kind in ["http", "log", "anything", ""] {
            let table = with(
                custom(ModelMethod::Timeseries),
                "raw_event_kind",
                Value::String(kind.to_string()),
            );
            assert_eq!(check(&table), Ok(ClusteringModelTypeRef::Custom), "{kind}");
        }

        for method in METHODS {
            assert_eq!(
                check(&with(custom(method), "batch_size", v("5000000"))),
                Ok(ClusteringModelTypeRef::Custom)
            );
            assert_eq!(
                refused(&with(custom(method), "batch_size", v("5000001"))),
                r(BoundViolated, "batch_size", "5000001")
            );
            // Other bounds are the caller's.
            for (key, value) in [("batch_size", "1"), ("max_event_id_num", "1000")] {
                assert_eq!(
                    check(&with(custom(method), key, v(value))),
                    Ok(ClusteringModelTypeRef::Custom)
                );
            }
        }
        // Fixed values of a catalog type are not compared.
        let mut table = with(custom(ModelMethod::Multidimension), "eps", v("3.0"));
        csv_mut(&mut table).insert("prefix_columns".to_string(), v("[14]"));
        assert_eq!(check(&table), Ok(ClusteringModelTypeRef::Custom));
    }
}
