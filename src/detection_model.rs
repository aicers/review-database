//! The static properties of every detection model, and the completion of the
//! `[detection_models]` part of an engine configuration document.
//!
//! review-protocol names detection models with [`DetectionModel`] and keeps
//! nothing else about them. What a model means lives in the table
//! [`properties`] returns. It is code, never stored in the database.

use std::collections::BTreeMap;
use std::fmt;

use review_protocol::types::{DetectionModel, RawEventKind, ThreatRole};
use thiserror::Error;
use toml_edit::{Array, Document, InlineTable, Item, Table, Value};

use crate::event::LearningMethod;
use crate::{AgentKind, EventCategory};

/// The key of the table holding one section per detection model in an engine
/// configuration document.
const DETECTION_MODELS: &str = "detection_models";

/// The name of the operator value every model has, turning the model on or
/// off.
const ENABLED: &str = "enabled";

/// Every detection model, in number order.
const ALL_MODELS: [DetectionModel; 18] = [
    DetectionModel::WatchlistMatch,
    DetectionModel::CryptocurrencyMiningPool,
    DetectionModel::LockyRansomware,
    DetectionModel::SuspiciousTlsTraffic,
    DetectionModel::PortScan,
    DetectionModel::MultiHostPortScan,
    DetectionModel::ExternalDdos,
    DetectionModel::RdpBruteForce,
    DetectionModel::FtpBruteForce,
    DetectionModel::LdapBruteForce,
    DetectionModel::RepeatedHttpSessions,
    DetectionModel::FtpPlainText,
    DetectionModel::LdapPlainText,
    DetectionModel::NonBrowser,
    DetectionModel::TorExitNode,
    DetectionModel::DomainGenerationAlgorithm,
    DetectionModel::DnsCovertChannel,
    DetectionModel::UnusualDestinationPattern,
];

/// The operator values of a model that can only be turned on or off.
const ENABLED_ONLY: &[OperatorValueSpec] = &[OperatorValueSpec {
    name: ENABLED,
    kind: OperatorValueKind::Bool { default: true },
}];

/// The detection technique a model belongs to.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DetectionFamily {
    /// Matches traffic against a list of known threats.
    KnownThreat,
    /// Applies a classifier trained before deployment.
    PretrainedClassifier,
    /// Counts a behavior and reports when the count reaches a threshold.
    BehaviorThreshold,
    /// Reports traffic that breaks a policy.
    PolicyViolation,
    /// Measures how random a name is.
    Randomness,
    /// Reports a deviation from a learned baseline.
    BaselineDeviation,
    /// Reports what clustering finds anomalous.
    ClusteringAnomaly,
}

/// Where the threat role of a model's primary subject comes from.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RoleSource {
    /// The model always assigns this role.
    Fixed(ThreatRole),
    /// Each detection event sets the role.
    PerEvent,
    /// The time-series type sets the role.
    TimeSeriesType,
}

/// The kind of the primary subject a model's detection events are about.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrimarySubjectKind {
    /// No primary subject: the detection is about a raw event.
    RawEvent,
    /// A host, with the source of its threat role.
    Host(RoleSource),
    /// A cluster.
    Cluster,
    /// A sensor.
    Sensor,
    /// A network, with the source of its threat role.
    Network(RoleSource),
}

/// The type of an operator value, without its default or range.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperatorValueType {
    /// A boolean.
    Bool,
    /// A 64-bit signed integer.
    Integer,
    /// A 64-bit float.
    Float,
    /// A list of strings.
    StringList,
}

impl fmt::Display for OperatorValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bool => "a boolean",
            Self::Integer => "an integer",
            Self::Float => "a float",
            Self::StringList => "a list of strings",
        })
    }
}

/// The type of an operator value, with its default and, for a number, the
/// inclusive range an operator may set it within.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OperatorValueKind {
    /// A boolean.
    Bool { default: bool },
    /// An integer within `min..=max`.
    Integer { min: i64, max: i64, default: i64 },
    /// A float within `min..=max`.
    Float { min: f64, max: f64, default: f64 },
    /// A list of strings.
    StringList { default: &'static [&'static str] },
}

impl OperatorValueKind {
    /// Returns the type of the value, without its default or range.
    #[must_use]
    pub fn value_type(&self) -> OperatorValueType {
        match self {
            Self::Bool { .. } => OperatorValueType::Bool,
            Self::Integer { .. } => OperatorValueType::Integer,
            Self::Float { .. } => OperatorValueType::Float,
            Self::StringList { .. } => OperatorValueType::StringList,
        }
    }

    /// Returns the default as a TOML value.
    fn default_value(&self) -> Value {
        match *self {
            Self::Bool { default } => default.into(),
            Self::Integer { default, .. } => default.into(),
            Self::Float { default, .. } => default.into(),
            Self::StringList { default } => default.iter().copied().collect::<Array>().into(),
        }
    }
}

/// A value an operator may set for a detection model, in that model's section
/// of an engine configuration document.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OperatorValueSpec {
    /// The key of the value in the model's section.
    pub name: &'static str,
    /// The type of the value, with its default and range.
    pub kind: OperatorValueKind,
}

/// What a detection model means: the static properties shared by every
/// detection event it reports.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DetectionModelProperties {
    /// The detection technique.
    pub family: DetectionFamily,
    /// The MITRE tactics; empty when no tactic applies.
    pub categories: &'static [EventCategory],
    /// The engine that runs the model.
    pub learning_method: LearningMethod,
    /// The kinds of the raw events the model can report.
    pub raw_event_kinds: &'static [RawEventKind],
    /// What the model's detection events are about.
    pub primary_subject: PrimarySubjectKind,
    /// What the score measures, in one line. A higher score always means more
    /// suspicious.
    pub score_meaning: &'static str,
    /// Whether the model needs device and account identification.
    pub requires_device_account_identification: bool,
    /// The values an operator may set, in the order completion adds them.
    pub operator_values: &'static [OperatorValueSpec],
}

/// Returns the row of a model run by the Semi-supervised Engine that an
/// operator can only turn on or off.
const fn semi_supervised(
    family: DetectionFamily,
    categories: &'static [EventCategory],
    raw_event_kinds: &'static [RawEventKind],
    primary_subject: PrimarySubjectKind,
    score_meaning: &'static str,
) -> DetectionModelProperties {
    DetectionModelProperties {
        family,
        categories,
        learning_method: LearningMethod::SemiSupervised,
        raw_event_kinds,
        primary_subject,
        score_meaning,
        requires_device_account_identification: false,
        operator_values: ENABLED_ONLY,
    }
}

/// Returns the static properties of a detection model.
///
/// The match is exhaustive with no wildcard arm on purpose: a model added by a
/// later review-protocol release fails to compile until its row exists.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn properties(model: DetectionModel) -> &'static DetectionModelProperties {
    use DetectionFamily::{
        BaselineDeviation, BehaviorThreshold, KnownThreat, PolicyViolation, PretrainedClassifier,
        Randomness,
    };
    use PrimarySubjectKind::{Host, RawEvent, Sensor};
    use RoleSource::{Fixed, PerEvent};
    use ThreatRole::{Actor, Target};

    use crate::types::EventCategoryV0_42::{
        CommandAndControl, CredentialAccess, Discovery, Exfiltration, Impact, InitialAccess,
        LateralMovement, Reconnaissance,
    };

    match model {
        DetectionModel::WatchlistMatch => {
            const {
                &semi_supervised(
                    KnownThreat,
                    &[InitialAccess],
                    &[
                        RawEventKind::Conn,
                        RawEventKind::Dns,
                        RawEventKind::MalformedDns,
                        RawEventKind::DceRpc,
                        RawEventKind::Ftp,
                        RawEventKind::Http,
                        RawEventKind::Kerberos,
                        RawEventKind::Ldap,
                        RawEventKind::Mqtt,
                        RawEventKind::Nfs,
                        RawEventKind::Ntlm,
                        RawEventKind::Radius,
                        RawEventKind::Rdp,
                        RawEventKind::Smb,
                        RawEventKind::Smtp,
                        RawEventKind::Ssh,
                        RawEventKind::Tls,
                        RawEventKind::Bootp,
                        RawEventKind::Dhcp,
                    ],
                    Host(PerEvent),
                    "Always 1.0: a watchlist entry matched an endpoint of the raw event.",
                )
            }
        }
        DetectionModel::CryptocurrencyMiningPool => {
            const {
                &semi_supervised(
                    KnownThreat,
                    &[CommandAndControl],
                    &[RawEventKind::Dns],
                    RawEvent,
                    "Always 1.0: the DNS query named a known mining pool.",
                )
            }
        }
        DetectionModel::LockyRansomware => {
            const {
                &semi_supervised(
                    PretrainedClassifier,
                    &[Impact],
                    &[RawEventKind::Dns],
                    RawEvent,
                    "Always 0.85: the pretrained Locky classifier flagged the DNS query.",
                )
            }
        }
        DetectionModel::SuspiciousTlsTraffic => {
            const {
                &semi_supervised(
                    PretrainedClassifier,
                    &[CommandAndControl],
                    &[RawEventKind::Tls],
                    RawEvent,
                    "Always 0.85: the pretrained TLS classifier flagged the session.",
                )
            }
        }
        DetectionModel::PortScan => {
            const {
                &semi_supervised(
                    BehaviorThreshold,
                    &[Reconnaissance],
                    &[RawEventKind::Conn],
                    Host(Fixed(Actor)),
                    "0.3, 0.5 or 0.7 as the count of distinct responder ports one originator \
                 probed on one responder reaches the threshold, 1.5 times it, or twice it.",
                )
            }
        }
        DetectionModel::MultiHostPortScan => {
            const {
                &semi_supervised(
                    BehaviorThreshold,
                    &[Reconnaissance],
                    &[RawEventKind::Conn],
                    Host(Fixed(Actor)),
                    "0.3, 0.5 or 0.7 as the count of distinct responder hosts one originator \
                 probed on one port reaches the threshold, 1.5 times it, or twice it.",
                )
            }
        }
        DetectionModel::ExternalDdos => {
            const {
                &semi_supervised(
                    BehaviorThreshold,
                    &[Impact],
                    &[RawEventKind::Conn],
                    Host(Fixed(Target)),
                    "0.3, 0.5 or 0.7 as the count of distinct originator hosts contacting one \
                 responder reaches the threshold, 1.5 times it, or twice it.",
                )
            }
        }
        DetectionModel::RdpBruteForce => {
            const {
                &semi_supervised(
                    BehaviorThreshold,
                    &[Discovery],
                    &[RawEventKind::Rdp],
                    Host(Fixed(Actor)),
                    "0.3, 0.5 or 0.7 as the count of distinct responder hosts one originator \
                 tried over RDP reaches the threshold, 1.5 times it, or twice it.",
                )
            }
        }
        DetectionModel::FtpBruteForce => {
            const {
                &semi_supervised(
                    BehaviorThreshold,
                    &[CredentialAccess],
                    &[RawEventKind::Ftp],
                    Host(Fixed(Actor)),
                    "0.3, 0.5 or 0.7 as the count of distinct user names tried reaches the \
                 threshold, 1.5 times it, or twice it.",
                )
            }
        }
        DetectionModel::LdapBruteForce => {
            const {
                &semi_supervised(
                    BehaviorThreshold,
                    &[CredentialAccess],
                    &[RawEventKind::Ldap],
                    Host(Fixed(Actor)),
                    "0.3, 0.5 or 0.7 as the count of distinct user and password pairs tried \
                 reaches the threshold, 1.5 times it, or twice it.",
                )
            }
        }
        DetectionModel::RepeatedHttpSessions => {
            const {
                &semi_supervised(
                    BehaviorThreshold,
                    &[Exfiltration],
                    &[RawEventKind::Http],
                    Host(Fixed(Actor)),
                    "0.3, 0.5 or 0.7 as the total sessions between one originator and \
                 responder across the window reaches the threshold, 1.5 times it, or \
                 twice it; the pair qualifies only when it occupies at least the \
                 threshold number of time buckets.",
                )
            }
        }
        DetectionModel::FtpPlainText => {
            const {
                &semi_supervised(
                    PolicyViolation,
                    &[LateralMovement],
                    &[RawEventKind::Ftp],
                    RawEvent,
                    "Always 1.0: a non-anonymous FTP session carried a password in plain text.",
                )
            }
        }
        DetectionModel::LdapPlainText => {
            const {
                &semi_supervised(
                    PolicyViolation,
                    &[LateralMovement],
                    &[RawEventKind::Ldap],
                    RawEvent,
                    "Always 1.0: an LDAP request carried a password in plain text.",
                )
            }
        }
        DetectionModel::NonBrowser => {
            const {
                &semi_supervised(
                    PolicyViolation,
                    &[CommandAndControl],
                    &[RawEventKind::Http],
                    RawEvent,
                    "Always 1.0: an HTTP request's user agent is not on the trusted user-agent \
                 list.",
                )
            }
        }
        DetectionModel::TorExitNode => {
            const {
                &semi_supervised(
                    PolicyViolation,
                    &[CommandAndControl],
                    &[RawEventKind::Http, RawEventKind::Conn],
                    RawEvent,
                    "Always 1.0: an endpoint of the HTTP or Conn session is on the Tor exit \
                 node list.",
                )
            }
        }
        DetectionModel::DomainGenerationAlgorithm => {
            const {
                &semi_supervised(
                    Randomness,
                    &[CommandAndControl],
                    &[RawEventKind::Http],
                    RawEvent,
                    "Randomness of the HTTP host name's first label, 0.5 or above.",
                )
            }
        }
        DetectionModel::DnsCovertChannel => {
            const {
                &semi_supervised(
                    Randomness,
                    &[CommandAndControl, Exfiltration],
                    &[RawEventKind::Dns],
                    RawEvent,
                    "Randomness of the DNS query's first label, 0.5 or above.",
                )
            }
        }
        DetectionModel::UnusualDestinationPattern => {
            const {
                &semi_supervised(
                    BaselineDeviation,
                    &[Reconnaissance],
                    &[RawEventKind::Conn],
                    Sensor,
                    "0.3, 0.5 or 0.7 as the z-score of the session count in a sampled \
                 destination bucket reaches the z threshold, one step above it, or two \
                 steps above it.",
                )
            }
        }
    }
}

/// Returns the name of a model's section under `[detection_models]`: the
/// variant name in snake case.
pub(crate) fn section_name(model: DetectionModel) -> &'static str {
    match model {
        DetectionModel::WatchlistMatch => "watchlist_match",
        DetectionModel::CryptocurrencyMiningPool => "cryptocurrency_mining_pool",
        DetectionModel::LockyRansomware => "locky_ransomware",
        DetectionModel::SuspiciousTlsTraffic => "suspicious_tls_traffic",
        DetectionModel::PortScan => "port_scan",
        DetectionModel::MultiHostPortScan => "multi_host_port_scan",
        DetectionModel::ExternalDdos => "external_ddos",
        DetectionModel::RdpBruteForce => "rdp_brute_force",
        DetectionModel::FtpBruteForce => "ftp_brute_force",
        DetectionModel::LdapBruteForce => "ldap_brute_force",
        DetectionModel::RepeatedHttpSessions => "repeated_http_sessions",
        DetectionModel::FtpPlainText => "ftp_plain_text",
        DetectionModel::LdapPlainText => "ldap_plain_text",
        DetectionModel::NonBrowser => "non_browser",
        DetectionModel::TorExitNode => "tor_exit_node",
        DetectionModel::DomainGenerationAlgorithm => "domain_generation_algorithm",
        DetectionModel::DnsCovertChannel => "dns_covert_channel",
        DetectionModel::UnusualDestinationPattern => "unusual_destination_pattern",
    }
}

/// The reason the `[detection_models]` part of an engine configuration
/// document was rejected.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum DetectionModelsSectionError {
    /// The document is not valid TOML.
    #[error("the engine document is not valid TOML: {0}")]
    InvalidToml(String),
    /// `detection_models` is present but not a table.
    #[error("`detection_models` is not a table")]
    NotATable,
    /// An entry under `detection_models` is not a table.
    #[error("`detection_models.{section}` is not a table")]
    SectionNotATable { section: String },
    /// An entry under `detection_models` names no detection model.
    #[error("`detection_models.{section}` names no detection model")]
    UnknownModel { section: String },
    /// An entry under `detection_models` names a model another engine runs.
    #[error(
        "`detection_models.{section}` names a model of the {model_engine:?} engine, \
         not of the {document_engine:?} engine"
    )]
    ModelOfAnotherEngine {
        section: String,
        model_engine: LearningMethod,
        document_engine: LearningMethod,
    },
    /// A key in a model's section is not one of that model's operator values.
    #[error("`detection_models.{section}` has no operator value `{key}`")]
    UnknownKey { section: String, key: String },
    /// A value's type does not match its specification.
    #[error("`detection_models.{section}.{key}` must be {expected}")]
    TypeMismatch {
        section: String,
        key: String,
        expected: OperatorValueType,
    },
    /// A number is outside its specification's inclusive range.
    #[error("`detection_models.{section}.{key}` is {value}, outside the range {min} to {max}")]
    OutOfRange {
        section: String,
        key: String,
        value: String,
        min: String,
        max: String,
    },
}

/// Checks the `[detection_models]` part of an engine configuration document
/// and completes it with the defaults of the property table.
///
/// For [`AgentKind::SemiSupervised`], every missing section of a model the
/// Semi-supervised Engine runs is appended at the end of the document, in
/// model number order, as a standard `[detection_models.<section>]` table, and
/// every missing operator value is appended at the end of its section. When
/// `detection_models` is an inline table, missing sections are appended inside
/// it instead, since TOML cannot extend an inline table with a header. Values
/// already set are kept, and everything outside the model sections is kept
/// byte for byte. A complete document is returned unchanged, so completing
/// any output again is a no-op.
///
/// Every other kind is returned unchanged without being checked.
///
/// # Errors
///
/// For [`AgentKind::SemiSupervised`], returns an error if the document is not
/// valid TOML; if `detection_models` is not a table; or if an entry under it
/// is not a table, names no detection model or a model of another engine,
/// has a key that is not one of the model's operator values, or has a value
/// whose type or range does not match its specification.
pub fn complete_engine_document(
    kind: AgentKind,
    document: &str,
) -> Result<String, DetectionModelsSectionError> {
    match kind {
        AgentKind::SemiSupervised => complete(
            document,
            LearningMethod::SemiSupervised,
            &ALL_MODELS,
            properties,
        ),
        AgentKind::Unsupervised
        | AgentKind::Sensor
        | AgentKind::TimeSeriesGenerator
        | AgentKind::LogCollector => Ok(document.to_owned()),
    }
}

/// A TOML table, as a standard or dotted table or as an inline table.
#[derive(Clone, Copy)]
enum Node<'a> {
    Table(&'a Table),
    Inline(&'a InlineTable),
}

/// An entry of a [`Node`].
enum Child<'a> {
    Node(Node<'a>),
    Value(&'a Value),
    /// An array of tables.
    Other,
}

impl<'a> Child<'a> {
    fn from_item(item: &'a Item) -> Self {
        match item {
            Item::Table(t) => Self::Node(Node::Table(t)),
            Item::Value(v) => Self::from_value(v),
            Item::ArrayOfTables(_) | Item::None => Self::Other,
        }
    }

    fn from_value(value: &'a Value) -> Self {
        match value {
            Value::InlineTable(t) => Self::Node(Node::Inline(t)),
            v => Self::Value(v),
        }
    }
}

impl<'a> Node<'a> {
    fn entries(self) -> Vec<(&'a str, Child<'a>)> {
        match self {
            Self::Table(t) => t.iter().map(|(k, v)| (k, Child::from_item(v))).collect(),
            Self::Inline(t) => t.iter().map(|(k, v)| (k, Child::from_value(v))).collect(),
        }
    }

    fn contains_key(self, key: &str) -> bool {
        match self {
            Self::Table(t) => t.contains_key(key),
            Self::Inline(t) => t.contains_key(key),
        }
    }

    fn is_dotted(self) -> bool {
        match self {
            Self::Table(t) => t.is_dotted(),
            Self::Inline(t) => t.is_dotted(),
        }
    }

    /// Returns the offset just past the last value written in this table's
    /// body, or `None` if it has none. A header table under it is written
    /// elsewhere in the document and does not count.
    fn last_value_end(self) -> Option<usize> {
        self.entries()
            .into_iter()
            .filter_map(|(_, child)| match child {
                Child::Value(v) => v.span().map(|s| s.end),
                Child::Node(node) if node.is_dotted() => node.last_value_end(),
                Child::Node(Node::Inline(t)) => t.span().map(|s| s.end),
                Child::Node(Node::Table(_)) | Child::Other => None,
            })
            .max()
    }
}

/// A model section found in the document, with the operator values it lacks.
struct IncompleteSection<'a> {
    name: &'a str,
    node: Node<'a>,
    missing: Vec<&'static OperatorValueSpec>,
}

/// Checks and completes `document` for the engine running `engine` models.
///
/// `models` is every model a section may name, in number order, and
/// `properties` returns the row of each.
fn complete<'p>(
    document: &str,
    engine: LearningMethod,
    models: &[DetectionModel],
    properties: impl Fn(DetectionModel) -> &'p DetectionModelProperties,
) -> Result<String, DetectionModelsSectionError> {
    let parsed = Document::parse(document)
        .map_err(|e| DetectionModelsSectionError::InvalidToml(e.to_string()))?;
    let container = match parsed.as_table().get(DETECTION_MODELS) {
        None => None,
        Some(item) => match Child::from_item(item) {
            Child::Node(node) => Some(node),
            Child::Value(_) | Child::Other => return Err(DetectionModelsSectionError::NotATable),
        },
    };
    let incomplete = check_sections(container, engine, models, &properties)?;
    let missing_models: Vec<_> = models
        .iter()
        .copied()
        .filter(|m| {
            properties(*m).learning_method == engine
                && !container.is_some_and(|c| c.contains_key(section_name(*m)))
        })
        .collect();
    if incomplete.is_empty() && missing_models.is_empty() {
        return Ok(document.to_owned());
    }

    // Follow the document's first line ending, so a CRLF inside a multi-line
    // string of an LF document does not decide it.
    let newline = match document.split_once('\n') {
        Some((first_line, _)) if first_line.ends_with('\r') => "\r\n",
        _ => "\n",
    };
    // Text to insert, by offset into `document`. Insertions at the same offset
    // keep the order they were added in.
    let mut inserts: BTreeMap<usize, String> = BTreeMap::new();
    let container_is_dotted = container.is_some_and(Node::is_dotted);
    for section in &incomplete {
        let (offset, text) = section_insert(document, section, container_is_dotted, newline);
        inserts.entry(offset).or_default().push_str(&text);
    }
    if let Some(Node::Inline(table)) = container
        && !missing_models.is_empty()
    {
        let entries = missing_models.iter().map(|m| {
            let values = properties(*m).operator_values.iter().collect::<Vec<_>>();
            format!("{} = {{ {} }}", section_name(*m), inline_pairs(&values))
        });
        let (offset, text) = inline_insert(document, table, entries);
        inserts.entry(offset).or_default().push_str(&text);
    }

    let mut completed = String::with_capacity(document.len());
    let mut copied = 0;
    for (offset, text) in &inserts {
        completed.push_str(document.get(copied..*offset).unwrap_or_default());
        completed.push_str(text);
        copied = *offset;
    }
    completed.push_str(document.get(copied..).unwrap_or_default());
    if !matches!(container, Some(Node::Inline(_))) {
        for model in missing_models {
            append_section(&mut completed, model, properties(model), newline);
        }
    }
    Ok(completed)
}

/// Checks every section under `detection_models`, and returns those that
/// lack an operator value.
fn check_sections<'a, 'p>(
    container: Option<Node<'a>>,
    engine: LearningMethod,
    models: &[DetectionModel],
    properties: &impl Fn(DetectionModel) -> &'p DetectionModelProperties,
) -> Result<Vec<IncompleteSection<'a>>, DetectionModelsSectionError> {
    let mut incomplete = Vec::new();
    for (name, child) in container.map_or_default(Node::entries) {
        let Child::Node(node) = child else {
            return Err(DetectionModelsSectionError::SectionNotATable {
                section: name.to_owned(),
            });
        };
        let Some(model) = models.iter().copied().find(|m| section_name(*m) == name) else {
            return Err(DetectionModelsSectionError::UnknownModel {
                section: name.to_owned(),
            });
        };
        let props = properties(model);
        if props.learning_method != engine {
            return Err(DetectionModelsSectionError::ModelOfAnotherEngine {
                section: name.to_owned(),
                model_engine: props.learning_method,
                document_engine: engine,
            });
        }
        for (key, child) in node.entries() {
            let Some(spec) = props.operator_values.iter().find(|s| s.name == key) else {
                return Err(DetectionModelsSectionError::UnknownKey {
                    section: name.to_owned(),
                    key: key.to_owned(),
                });
            };
            check_value(name, spec, &child)?;
        }
        let missing: Vec<_> = props
            .operator_values
            .iter()
            .filter(|spec| !node.contains_key(spec.name))
            .collect();
        if !missing.is_empty() {
            incomplete.push(IncompleteSection {
                name,
                node,
                missing,
            });
        }
    }
    Ok(incomplete)
}

/// Appends a model's section, with every operator value at its default, as a
/// standard table at the end of `document`.
fn append_section(
    document: &mut String,
    model: DetectionModel,
    props: &DetectionModelProperties,
    newline: &str,
) {
    if !document.is_empty() {
        if !document.ends_with('\n') {
            document.push_str(newline);
        }
        document.push_str(newline);
    }
    document.push('[');
    document.push_str(DETECTION_MODELS);
    document.push('.');
    document.push_str(section_name(model));
    document.push(']');
    document.push_str(newline);
    for spec in props.operator_values {
        document.push_str(&assignment(spec));
        document.push_str(newline);
    }
}

/// Checks a value against its specification.
fn check_value(
    section: &str,
    spec: &OperatorValueSpec,
    child: &Child<'_>,
) -> Result<(), DetectionModelsSectionError> {
    fn out_of_range<T: ToString + Copy>(
        section: &str,
        spec: &OperatorValueSpec,
        value: T,
        min: T,
        max: T,
    ) -> DetectionModelsSectionError {
        DetectionModelsSectionError::OutOfRange {
            section: section.to_owned(),
            key: spec.name.to_owned(),
            value: value.to_string(),
            min: min.to_string(),
            max: max.to_string(),
        }
    }

    let Child::Value(value) = child else {
        return Err(type_mismatch(section, spec));
    };
    match (spec.kind, value) {
        (OperatorValueKind::Bool { .. }, Value::Boolean(_)) => Ok(()),
        (OperatorValueKind::Integer { min, max, .. }, Value::Integer(v)) => {
            let v = *v.value();
            if (min..=max).contains(&v) {
                Ok(())
            } else {
                Err(out_of_range(section, spec, v, min, max))
            }
        }
        (OperatorValueKind::Float { min, max, .. }, Value::Float(v)) => {
            let v = *v.value();
            if (min..=max).contains(&v) {
                Ok(())
            } else {
                Err(out_of_range(section, spec, v, min, max))
            }
        }
        (OperatorValueKind::StringList { .. }, Value::Array(items))
            if items.iter().all(|item| matches!(item, Value::String(_))) =>
        {
            Ok(())
        }
        _ => Err(type_mismatch(section, spec)),
    }
}

fn type_mismatch(section: &str, spec: &OperatorValueSpec) -> DetectionModelsSectionError {
    DetectionModelsSectionError::TypeMismatch {
        section: section.to_owned(),
        key: spec.name.to_owned(),
        expected: spec.kind.value_type(),
    }
}

/// Returns `key = default` for an operator value.
fn assignment(spec: &OperatorValueSpec) -> String {
    format!(
        "{} = {}",
        spec.name,
        spec.kind.default_value().decorated("", "")
    )
}

/// Returns `key = default` pairs separated by commas, as inside an inline
/// table.
fn inline_pairs(specs: &[&OperatorValueSpec]) -> String {
    specs
        .iter()
        .map(|spec| assignment(spec))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Returns where and what to insert to add a section's missing values at the
/// end of the section.
fn section_insert(
    document: &str,
    section: &IncompleteSection<'_>,
    container_is_dotted: bool,
    newline: &str,
) -> (usize, String) {
    match section.node {
        Node::Inline(table) if !table.is_dotted() => inline_insert(
            document,
            table,
            section.missing.iter().map(|spec| assignment(spec)),
        ),
        Node::Inline(_) => {
            // Dotted keys inside an inline `detection_models` table.
            let offset = section
                .node
                .last_value_end()
                .expect("a dotted table has at least one value, each with a span");
            let key = section.name_key();
            let mut text = String::new();
            for spec in &section.missing {
                text.push_str(", ");
                text.push_str(&key);
                text.push('.');
                text.push_str(&assignment(spec));
            }
            (offset, text)
        }
        Node::Table(table) => {
            let prefix = if !table.is_dotted() {
                String::new()
            } else if container_is_dotted {
                format!("{DETECTION_MODELS}.{}.", section.name_key())
            } else {
                format!("{}.", section.name_key())
            };
            let anchor = section
                .node
                .last_value_end()
                .unwrap_or_else(|| table.span().expect("a parsed table header has a span").end);
            let (offset, at_eof) = match document.get(anchor..).and_then(|rest| rest.find('\n')) {
                Some(i) => (anchor + i + 1, false),
                None => (document.len(), true),
            };
            let mut text = String::new();
            if at_eof {
                text.push_str(newline);
            }
            for spec in &section.missing {
                text.push_str(&prefix);
                text.push_str(&assignment(spec));
                text.push_str(newline);
            }
            (offset, text)
        }
    }
}

impl IncompleteSection<'_> {
    /// Returns the section's name as a TOML key.
    fn name_key(&self) -> String {
        toml_edit::Key::new(self.name).display_repr().into_owned()
    }
}

/// Returns where and what to insert to append `entries` at the end of an
/// inline table.
fn inline_insert(
    document: &str,
    table: &InlineTable,
    entries: impl Iterator<Item = String>,
) -> (usize, String) {
    let entries: Vec<_> = entries.collect();
    if let Some(end) = Node::Inline(table).last_value_end() {
        let text = entries.iter().fold(String::new(), |mut text, entry| {
            text.push_str(", ");
            text.push_str(entry);
            text
        });
        return (end, text);
    }
    let closing = table
        .span()
        .expect("a parsed inline table has a span")
        .end
        .saturating_sub(1);
    let before = document.get(..closing).unwrap_or_default();
    let lead = if before.ends_with(char::is_whitespace) {
        ""
    } else {
        " "
    };
    (closing, format!("{lead}{} ", entries.join(", ")))
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use review_protocol::types::{DetectionModel, RawEventKind as R, ThreatRole};

    use super::*;
    use crate::types::EventCategoryV0_42 as C;

    const ENABLED_TRUE: &[OperatorValueSpec] = &[OperatorValueSpec {
        name: "enabled",
        kind: OperatorValueKind::Bool { default: true },
    }];

    fn semi(document: &str) -> Result<String, DetectionModelsSectionError> {
        complete_engine_document(AgentKind::SemiSupervised, document)
    }

    /// Returns every section completion appends to an empty document.
    fn all_sections() -> String {
        ALL_MODELS
            .iter()
            .map(|m| format!("[detection_models.{}]\nenabled = true\n", section_name(*m)))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Returns the sections completion appends, without `skip`.
    fn sections_without(skip: &[&str]) -> String {
        ALL_MODELS
            .iter()
            .map(|m| section_name(*m))
            .filter(|name| !skip.contains(name))
            .map(|name| format!("[detection_models.{name}]\nenabled = true\n"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn assert_complete(output: &str) {
        assert!(Document::parse(output).is_ok(), "invalid output:\n{output}");
        assert_eq!(semi(output).unwrap(), output, "not a fixed point");
    }

    /// A row of the issue's tables: model, section name, family, categories,
    /// raw event kinds, primary subject and score meaning.
    type Row = (
        DetectionModel,
        &'static str,
        DetectionFamily,
        &'static [EventCategory],
        &'static [R],
        PrimarySubjectKind,
        &'static str,
    );

    #[test]
    #[allow(clippy::too_many_lines)]
    fn properties_match_the_table() {
        use DetectionFamily::{
            BaselineDeviation, BehaviorThreshold, KnownThreat, PolicyViolation,
            PretrainedClassifier, Randomness,
        };
        use PrimarySubjectKind::{Host, RawEvent, Sensor};
        use RoleSource::{Fixed, PerEvent};

        let rows: [Row; 18] = [
            (
                DetectionModel::WatchlistMatch,
                "watchlist_match",
                KnownThreat,
                &[C::InitialAccess],
                &[
                    R::Conn,
                    R::Dns,
                    R::MalformedDns,
                    R::DceRpc,
                    R::Ftp,
                    R::Http,
                    R::Kerberos,
                    R::Ldap,
                    R::Mqtt,
                    R::Nfs,
                    R::Ntlm,
                    R::Radius,
                    R::Rdp,
                    R::Smb,
                    R::Smtp,
                    R::Ssh,
                    R::Tls,
                    R::Bootp,
                    R::Dhcp,
                ],
                Host(PerEvent),
                "Always 1.0: a watchlist entry matched an endpoint of the raw event.",
            ),
            (
                DetectionModel::CryptocurrencyMiningPool,
                "cryptocurrency_mining_pool",
                KnownThreat,
                &[C::CommandAndControl],
                &[R::Dns],
                RawEvent,
                "Always 1.0: the DNS query named a known mining pool.",
            ),
            (
                DetectionModel::LockyRansomware,
                "locky_ransomware",
                PretrainedClassifier,
                &[C::Impact],
                &[R::Dns],
                RawEvent,
                "Always 0.85: the pretrained Locky classifier flagged the DNS query.",
            ),
            (
                DetectionModel::SuspiciousTlsTraffic,
                "suspicious_tls_traffic",
                PretrainedClassifier,
                &[C::CommandAndControl],
                &[R::Tls],
                RawEvent,
                "Always 0.85: the pretrained TLS classifier flagged the session.",
            ),
            (
                DetectionModel::PortScan,
                "port_scan",
                BehaviorThreshold,
                &[C::Reconnaissance],
                &[R::Conn],
                Host(Fixed(ThreatRole::Actor)),
                "0.3, 0.5 or 0.7 as the count of distinct responder ports one originator probed \
                 on one responder reaches the threshold, 1.5 times it, or twice it.",
            ),
            (
                DetectionModel::MultiHostPortScan,
                "multi_host_port_scan",
                BehaviorThreshold,
                &[C::Reconnaissance],
                &[R::Conn],
                Host(Fixed(ThreatRole::Actor)),
                "0.3, 0.5 or 0.7 as the count of distinct responder hosts one originator probed \
                 on one port reaches the threshold, 1.5 times it, or twice it.",
            ),
            (
                DetectionModel::ExternalDdos,
                "external_ddos",
                BehaviorThreshold,
                &[C::Impact],
                &[R::Conn],
                Host(Fixed(ThreatRole::Target)),
                "0.3, 0.5 or 0.7 as the count of distinct originator hosts contacting one \
                 responder reaches the threshold, 1.5 times it, or twice it.",
            ),
            (
                DetectionModel::RdpBruteForce,
                "rdp_brute_force",
                BehaviorThreshold,
                &[C::Discovery],
                &[R::Rdp],
                Host(Fixed(ThreatRole::Actor)),
                "0.3, 0.5 or 0.7 as the count of distinct responder hosts one originator tried \
                 over RDP reaches the threshold, 1.5 times it, or twice it.",
            ),
            (
                DetectionModel::FtpBruteForce,
                "ftp_brute_force",
                BehaviorThreshold,
                &[C::CredentialAccess],
                &[R::Ftp],
                Host(Fixed(ThreatRole::Actor)),
                "0.3, 0.5 or 0.7 as the count of distinct user names tried reaches the \
                 threshold, 1.5 times it, or twice it.",
            ),
            (
                DetectionModel::LdapBruteForce,
                "ldap_brute_force",
                BehaviorThreshold,
                &[C::CredentialAccess],
                &[R::Ldap],
                Host(Fixed(ThreatRole::Actor)),
                "0.3, 0.5 or 0.7 as the count of distinct user and password pairs tried reaches \
                 the threshold, 1.5 times it, or twice it.",
            ),
            (
                DetectionModel::RepeatedHttpSessions,
                "repeated_http_sessions",
                BehaviorThreshold,
                &[C::Exfiltration],
                &[R::Http],
                Host(Fixed(ThreatRole::Actor)),
                "0.3, 0.5 or 0.7 as the total sessions between one originator and responder \
                 across the window reaches the threshold, 1.5 times it, or twice it; the pair \
                 qualifies only when it occupies at least the threshold number of time buckets.",
            ),
            (
                DetectionModel::FtpPlainText,
                "ftp_plain_text",
                PolicyViolation,
                &[C::LateralMovement],
                &[R::Ftp],
                RawEvent,
                "Always 1.0: a non-anonymous FTP session carried a password in plain text.",
            ),
            (
                DetectionModel::LdapPlainText,
                "ldap_plain_text",
                PolicyViolation,
                &[C::LateralMovement],
                &[R::Ldap],
                RawEvent,
                "Always 1.0: an LDAP request carried a password in plain text.",
            ),
            (
                DetectionModel::NonBrowser,
                "non_browser",
                PolicyViolation,
                &[C::CommandAndControl],
                &[R::Http],
                RawEvent,
                "Always 1.0: an HTTP request's user agent is not on the trusted user-agent list.",
            ),
            (
                DetectionModel::TorExitNode,
                "tor_exit_node",
                PolicyViolation,
                &[C::CommandAndControl],
                &[R::Http, R::Conn],
                RawEvent,
                "Always 1.0: an endpoint of the HTTP or Conn session is on the Tor exit node list.",
            ),
            (
                DetectionModel::DomainGenerationAlgorithm,
                "domain_generation_algorithm",
                Randomness,
                &[C::CommandAndControl],
                &[R::Http],
                RawEvent,
                "Randomness of the HTTP host name's first label, 0.5 or above.",
            ),
            (
                DetectionModel::DnsCovertChannel,
                "dns_covert_channel",
                Randomness,
                &[C::CommandAndControl, C::Exfiltration],
                &[R::Dns],
                RawEvent,
                "Randomness of the DNS query's first label, 0.5 or above.",
            ),
            (
                DetectionModel::UnusualDestinationPattern,
                "unusual_destination_pattern",
                BaselineDeviation,
                &[C::Reconnaissance],
                &[R::Conn],
                Sensor,
                "0.3, 0.5 or 0.7 as the z-score of the session count in a sampled destination \
                 bucket reaches the z threshold, one step above it, or two steps above it.",
            ),
        ];

        for (i, (model, section, family, categories, kinds, subject, meaning)) in
            rows.into_iter().enumerate()
        {
            assert_eq!(u32::from(model), u32::try_from(i).unwrap());
            assert_eq!(ALL_MODELS.get(i), Some(&model));
            assert_eq!(section_name(model), section);
            let expected = DetectionModelProperties {
                family,
                categories,
                learning_method: LearningMethod::SemiSupervised,
                raw_event_kinds: kinds,
                primary_subject: subject,
                score_meaning: meaning,
                requires_device_account_identification: false,
                operator_values: ENABLED_TRUE,
            };
            assert_eq!(properties(model), &expected, "{model:?}");
        }
    }

    #[test]
    fn all_models_names_every_model_in_number_order() {
        for n in 0..=4096_u32 {
            if let Ok(model) = DetectionModel::try_from(n) {
                assert!(ALL_MODELS.contains(&model), "{model:?} is missing");
            }
        }
        assert!(
            ALL_MODELS
                .windows(2)
                .all(|w| u32::from(w[0]) < u32::from(w[1]))
        );
    }

    #[test]
    fn empty_document_gets_every_section() {
        let output = semi("").unwrap();
        assert_eq!(output, all_sections());
        assert!(output.starts_with("[detection_models.watchlist_match]\nenabled = true\n\n"));
        assert!(
            output
                .ends_with("\n\n[detection_models.unusual_destination_pattern]\nenabled = true\n")
        );
        assert_complete(&output);
    }

    #[test]
    fn missing_sections_are_appended_and_given_values_kept() {
        let document = "\
# engine settings
[server]
address = \"127.0.0.1\" # local

[detection_models.port_scan]
enabled = false # turned off

[detection_models.locky_ransomware]
enabled = true

[logging]
level = \"info\"
# trailing comment
";
        let output = semi(document).unwrap();
        assert_eq!(
            output,
            format!(
                "{document}\n{}",
                sections_without(&["port_scan", "locky_ransomware"])
            )
        );
        assert_complete(&output);
    }

    #[test]
    fn missing_enabled_is_added_at_the_end_of_its_section() {
        let document = "\
title = \"engine\"

# models
[detection_models.port_scan] # no values yet

# between
[detection_models.external_ddos]

[other]
key = 1
";
        let output = semi(document).unwrap();
        let expected_head = "\
title = \"engine\"

# models
[detection_models.port_scan] # no values yet
enabled = true

# between
[detection_models.external_ddos]
enabled = true

[other]
key = 1
";
        assert_eq!(
            output,
            format!(
                "{expected_head}\n{}",
                sections_without(&["port_scan", "external_ddos"])
            )
        );
        assert_complete(&output);
    }

    #[test]
    fn complete_document_is_returned_byte_for_byte() {
        let mut document = String::from("# header comment\nkey   =   'value'  \n\n");
        for (i, model) in ALL_MODELS.iter().enumerate() {
            let enabled = i % 2 == 0;
            writeln!(
                document,
                "[detection_models.{}]   # c{i}\n  enabled=  {enabled}\n",
                section_name(*model)
            )
            .unwrap();
        }
        document.push_str("[tail]\nx = [1, 2,\n  3]\n# end");
        assert_eq!(semi(&document).unwrap(), document);
    }

    #[test]
    fn document_without_trailing_newline() {
        let document = "[detection_models.port_scan]";
        let output = semi(document).unwrap();
        assert_eq!(
            output,
            format!(
                "[detection_models.port_scan]\nenabled = true\n\n{}",
                sections_without(&["port_scan"])
            )
        );
        assert_complete(&output);

        let document = "a = 1 # no newline";
        let output = semi(document).unwrap();
        assert_eq!(output, format!("a = 1 # no newline\n\n{}", all_sections()));
        assert_complete(&output);
    }

    #[test]
    fn crlf_document_keeps_crlf() {
        let document = "a = 1\r\n[detection_models.port_scan]\r\n";
        let output = semi(document).unwrap();
        assert!(
            output.starts_with("a = 1\r\n[detection_models.port_scan]\r\nenabled = true\r\n\r\n")
        );
        assert!(!output.replace("\r\n", "").contains('\n'));
        assert_complete(&output);

        let document = "a = 1\nb = \"\"\"\r\nx\"\"\"\n";
        let output = semi(document).unwrap();
        assert_eq!(output, format!("{document}\n{}", all_sections()));
        assert_complete(&output);
    }

    #[test]
    fn inline_and_dotted_sections_count_as_tables() {
        let document = "\
[detection_models]
port_scan = {}
external_ddos = { enabled = false }
rdp_brute_force.enabled = false
";
        let output = semi(document).unwrap();
        assert_eq!(
            output,
            format!(
                "\
[detection_models]
port_scan = {{ enabled = true }}
external_ddos = {{ enabled = false }}
rdp_brute_force.enabled = false

{}",
                sections_without(&["port_scan", "external_ddos", "rdp_brute_force"])
            )
        );
        assert_complete(&output);
    }

    #[test]
    fn root_dotted_detection_models() {
        let document = "detection_models.port_scan.enabled = false\n";
        let output = semi(document).unwrap();
        assert_eq!(
            output,
            format!("{document}\n{}", sections_without(&["port_scan"]))
        );
        assert_complete(&output);
    }

    #[test]
    fn inline_detection_models_is_completed_inside_its_braces() {
        let document = "detection_models = { port_scan = { enabled = false } }\nafter = 1\n";
        let output = semi(document).unwrap();
        let added = ALL_MODELS
            .iter()
            .map(|m| section_name(*m))
            .filter(|name| *name != "port_scan")
            .fold(String::new(), |mut added, name| {
                write!(added, ", {name} = {{ enabled = true }}").unwrap();
                added
            });
        assert_eq!(
            output,
            format!(
                "detection_models = {{ port_scan = {{ enabled = false }}{added} }}\nafter = 1\n"
            )
        );
        assert_complete(&output);

        let output = semi("detection_models = {}").unwrap();
        assert!(output.starts_with("detection_models = { watchlist_match = { enabled = true }, "));
        assert!(output.ends_with(", unusual_destination_pattern = { enabled = true } }"));
        assert_complete(&output);
    }

    #[test]
    fn invalid_toml_carries_the_parser_diagnostic() {
        let document = "[detection_models.port_scan\nenabled = true\n";
        let diagnostic = Document::parse(document).unwrap_err().to_string();
        assert_ne!(diagnostic, "");
        assert_eq!(
            semi(document),
            Err(DetectionModelsSectionError::InvalidToml(diagnostic))
        );
    }

    #[test]
    fn rejections() {
        let section = |s: &str| s.to_owned();
        let cases = [
            (
                "detection_models = 1",
                DetectionModelsSectionError::NotATable,
            ),
            (
                "[[detection_models]]\nport_scan = {}",
                DetectionModelsSectionError::NotATable,
            ),
            (
                "[detection_models]\nport_scan = true",
                DetectionModelsSectionError::SectionNotATable {
                    section: section("port_scan"),
                },
            ),
            (
                "[[detection_models.port_scan]]\nenabled = true",
                DetectionModelsSectionError::SectionNotATable {
                    section: section("port_scan"),
                },
            ),
            (
                "[detection_models.no_such_model]\nenabled = true",
                DetectionModelsSectionError::UnknownModel {
                    section: section("no_such_model"),
                },
            ),
            (
                "[detection_models.PortScan]\nenabled = true",
                DetectionModelsSectionError::UnknownModel {
                    section: section("PortScan"),
                },
            ),
            (
                "[detection_models.port_scan]\nthreshold = 3",
                DetectionModelsSectionError::UnknownKey {
                    section: section("port_scan"),
                    key: "threshold".to_owned(),
                },
            ),
            (
                "[detection_models.port_scan]\nenabled = 1",
                DetectionModelsSectionError::TypeMismatch {
                    section: section("port_scan"),
                    key: "enabled".to_owned(),
                    expected: OperatorValueType::Bool,
                },
            ),
            (
                "[detection_models.port_scan]\nenabled = \"true\"",
                DetectionModelsSectionError::TypeMismatch {
                    section: section("port_scan"),
                    key: "enabled".to_owned(),
                    expected: OperatorValueType::Bool,
                },
            ),
            (
                "[detection_models.port_scan.enabled]\nx = true",
                DetectionModelsSectionError::TypeMismatch {
                    section: section("port_scan"),
                    key: "enabled".to_owned(),
                    expected: OperatorValueType::Bool,
                },
            ),
        ];
        for (document, expected) in cases {
            let error = semi(document).unwrap_err();
            assert_eq!(error, expected, "{document}");
        }
    }

    #[test]
    fn error_messages_name_what_was_rejected() {
        let error = semi("[detection_models.port_scan]\nthreshold = 3").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("port_scan") && message.contains("threshold"));
        let error = semi("[detection_models.port_scan]\nenabled = 1").unwrap_err();
        assert_eq!(
            error.to_string(),
            "`detection_models.port_scan.enabled` must be a boolean"
        );
    }

    #[test]
    fn other_kinds_are_returned_unchanged() {
        for document in [
            "",
            "[detection_models.port_scan]",
            "not [valid toml",
            "x = 1\n",
        ] {
            for kind in [
                AgentKind::Unsupervised,
                AgentKind::Sensor,
                AgentKind::TimeSeriesGenerator,
                AgentKind::LogCollector,
            ] {
                assert_eq!(
                    complete_engine_document(kind, document).as_deref(),
                    Ok(document)
                );
            }
        }
    }

    // Synthetic properties exercising what the real table cannot reach: a
    // model of another engine, and integer, float and string-list values.

    const SYNTHETIC_MODELS: [DetectionModel; 2] =
        [DetectionModel::PortScan, DetectionModel::ExternalDdos];

    const SYNTHETIC_VALUES: &[OperatorValueSpec] = &[
        OperatorValueSpec {
            name: "enabled",
            kind: OperatorValueKind::Bool { default: true },
        },
        OperatorValueSpec {
            name: "threshold",
            kind: OperatorValueKind::Integer {
                min: 1,
                max: 100,
                default: 10,
            },
        },
        OperatorValueSpec {
            name: "ratio",
            kind: OperatorValueKind::Float {
                min: 0.25,
                max: 0.75,
                default: 0.5,
            },
        },
        OperatorValueSpec {
            name: "names",
            kind: OperatorValueKind::StringList {
                default: &["alpha", "beta"],
            },
        },
    ];

    const SYNTHETIC_SEMI: DetectionModelProperties = DetectionModelProperties {
        family: DetectionFamily::BehaviorThreshold,
        categories: &[],
        learning_method: LearningMethod::SemiSupervised,
        raw_event_kinds: &[R::Conn],
        primary_subject: PrimarySubjectKind::Cluster,
        score_meaning: "Synthetic.",
        requires_device_account_identification: true,
        operator_values: SYNTHETIC_VALUES,
    };

    const SYNTHETIC_UNSUPERVISED: DetectionModelProperties = DetectionModelProperties {
        family: DetectionFamily::ClusteringAnomaly,
        categories: &[],
        learning_method: LearningMethod::Unsupervised,
        raw_event_kinds: &[],
        primary_subject: PrimarySubjectKind::Network(RoleSource::TimeSeriesType),
        score_meaning: "Synthetic.",
        requires_device_account_identification: false,
        operator_values: ENABLED_TRUE,
    };

    fn synthetic(model: DetectionModel) -> &'static DetectionModelProperties {
        if model == DetectionModel::PortScan {
            &SYNTHETIC_SEMI
        } else {
            &SYNTHETIC_UNSUPERVISED
        }
    }

    fn complete_synthetic(document: &str) -> Result<String, DetectionModelsSectionError> {
        complete(
            document,
            LearningMethod::SemiSupervised,
            &SYNTHETIC_MODELS,
            synthetic,
        )
    }

    const SYNTHETIC_DEFAULTS: &str =
        "enabled = true\nthreshold = 10\nratio = 0.5\nnames = [\"alpha\", \"beta\"]\n";

    #[test]
    fn synthetic_model_of_another_engine_is_rejected() {
        assert_eq!(
            complete_synthetic("[detection_models.external_ddos]\nenabled = true\n"),
            Err(DetectionModelsSectionError::ModelOfAnotherEngine {
                section: "external_ddos".to_owned(),
                model_engine: LearningMethod::Unsupervised,
                document_engine: LearningMethod::SemiSupervised,
            })
        );
    }

    #[test]
    fn synthetic_completion_adds_only_models_of_the_engine() {
        let output = complete_synthetic("").unwrap();
        assert_eq!(
            output,
            format!("[detection_models.port_scan]\n{SYNTHETIC_DEFAULTS}")
        );
        assert_eq!(complete_synthetic(&output).unwrap(), output);
    }

    #[test]
    fn synthetic_missing_values_follow_operator_value_order() {
        let document = "[detection_models.port_scan]\nratio = 0.3\n\n[x]\ny = 1\n";
        let output = complete_synthetic(document).unwrap();
        assert_eq!(
            output,
            "[detection_models.port_scan]\nratio = 0.3\nenabled = true\nthreshold = 10\n\
             names = [\"alpha\", \"beta\"]\n\n[x]\ny = 1\n"
        );
        assert_eq!(complete_synthetic(&output).unwrap(), output);

        let document = "[detection_models]\nport_scan = { names = [] }\n";
        let output = complete_synthetic(document).unwrap();
        assert_eq!(
            output,
            "[detection_models]\nport_scan = { names = [], enabled = true, threshold = 10, \
             ratio = 0.5 }\n"
        );
        assert_eq!(complete_synthetic(&output).unwrap(), output);

        let document = "[detection_models]\nport_scan.threshold = 5 # five\nother = 1\n";
        // `other` is not a table, so the document is rejected before completion.
        assert!(matches!(
            complete_synthetic(document),
            Err(DetectionModelsSectionError::SectionNotATable { .. })
        ));
        let document = "[detection_models]\nport_scan.threshold = 5 # five\n[z]\n";
        let output = complete_synthetic(document).unwrap();
        assert_eq!(
            output,
            "[detection_models]\nport_scan.threshold = 5 # five\nport_scan.enabled = true\n\
             port_scan.ratio = 0.5\nport_scan.names = [\"alpha\", \"beta\"]\n[z]\n"
        );
        assert_eq!(complete_synthetic(&output).unwrap(), output);

        let document = "detection_models.port_scan.enabled = false";
        let output = complete_synthetic(document).unwrap();
        assert_eq!(
            output,
            "detection_models.port_scan.enabled = false\n\
             detection_models.port_scan.threshold = 10\n\
             detection_models.port_scan.ratio = 0.5\n\
             detection_models.port_scan.names = [\"alpha\", \"beta\"]\n"
        );
        assert_eq!(complete_synthetic(&output).unwrap(), output);

        let document = "detection_models = { port_scan.enabled = false }";
        let output = complete_synthetic(document).unwrap();
        assert_eq!(
            output,
            "detection_models = { port_scan.enabled = false, port_scan.threshold = 10, \
             port_scan.ratio = 0.5, port_scan.names = [\"alpha\", \"beta\"] }"
        );
        assert_eq!(complete_synthetic(&output).unwrap(), output);
    }

    fn synthetic_check(line: &str) -> Result<String, DetectionModelsSectionError> {
        complete_synthetic(&format!("[detection_models.port_scan]\n{line}\n"))
    }

    fn mismatch(key: &str, expected: OperatorValueType) -> DetectionModelsSectionError {
        DetectionModelsSectionError::TypeMismatch {
            section: "port_scan".to_owned(),
            key: key.to_owned(),
            expected,
        }
    }

    fn out_of_range(key: &str, value: &str, min: &str, max: &str) -> DetectionModelsSectionError {
        DetectionModelsSectionError::OutOfRange {
            section: "port_scan".to_owned(),
            key: key.to_owned(),
            value: value.to_owned(),
            min: min.to_owned(),
            max: max.to_owned(),
        }
    }

    #[test]
    fn synthetic_integer_checks() {
        assert!(synthetic_check("threshold = 1").is_ok());
        assert!(synthetic_check("threshold = 100").is_ok());
        assert_eq!(
            synthetic_check("threshold = 0"),
            Err(out_of_range("threshold", "0", "1", "100"))
        );
        assert_eq!(
            synthetic_check("threshold = 101"),
            Err(out_of_range("threshold", "101", "1", "100"))
        );
        for value in ["1.0", "\"5\"", "true", "[1]"] {
            assert_eq!(
                synthetic_check(&format!("threshold = {value}")),
                Err(mismatch("threshold", OperatorValueType::Integer)),
                "{value}"
            );
        }
    }

    #[test]
    fn synthetic_float_checks() {
        assert!(synthetic_check("ratio = 0.25").is_ok());
        assert!(synthetic_check("ratio = 0.75").is_ok());
        assert_eq!(
            synthetic_check("ratio = 0.2499"),
            Err(out_of_range("ratio", "0.2499", "0.25", "0.75"))
        );
        assert_eq!(
            synthetic_check("ratio = 0.7501"),
            Err(out_of_range("ratio", "0.7501", "0.25", "0.75"))
        );
        assert!(matches!(
            synthetic_check("ratio = nan"),
            Err(DetectionModelsSectionError::OutOfRange { .. })
        ));
        for value in ["1", "\"0.5\"", "false"] {
            assert_eq!(
                synthetic_check(&format!("ratio = {value}")),
                Err(mismatch("ratio", OperatorValueType::Float)),
                "{value}"
            );
        }
    }

    #[test]
    fn synthetic_string_list_checks() {
        assert!(synthetic_check("names = []").is_ok());
        assert!(synthetic_check("names = [\"a\", 'b']").is_ok());
        for value in ["\"a\"", "[\"a\", 1]", "[[\"a\"]]", "{ a = \"b\" }"] {
            assert_eq!(
                synthetic_check(&format!("names = {value}")),
                Err(mismatch("names", OperatorValueType::StringList)),
                "{value}"
            );
        }
    }
}
