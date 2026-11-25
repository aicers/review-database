//! Triage-policy scoring of stored detection events, and the raw event
//! attributes `packet_attr` entries compare.

use std::{
    borrow::Cow,
    fmt::{self, Formatter, Write as _},
    net::IpAddr,
};

use attrievent::attribute::{
    AuditdAttr, BootpAttr, ConnAttr, CreateRemoteThreadAttr, DceRpcAttr, DhcpAttr, DnsAttr,
    DnsQueryAttr, DriverLoadAttr, FileCreateAttr, FileCreateStreamHashAttr, FileCreateTimeAttr,
    FileDeleteAttr, FileDeleteDetectedAttr, FtpAttr, HttpAttr, IcmpAttr, ImageLoadAttr,
    JournaldAttr, KerberosAttr, LdapAttr, MalformedDnsAttr, MqttAttr, Netflow5Attr, Netflow9Attr,
    NetworkConnectAttr, NfsAttr, NtlmAttr, PipeEventAttr, ProcessAccessAttr, ProcessCreateAttr,
    ProcessTamperAttr, ProcessTerminateAttr, RadiusAttr, RawAccessReadAttr, RawEventAttrKind,
    RdpAttr, RegistryKeyRenameAttr, RegistryObjectAddDelAttr, RegistryValueSetAttr, SmbAttr,
    SmtpAttr, SshAttr, TlsAttr, WindowsEventLogAttr,
};
use bincode::Options;
use review_protocol::types::{
    RawEventBody, Target,
    raw_event::{AuditRecord, EventData, LogField, LogValue},
};
use serde::{Deserialize, Serialize};

use super::StoredDetectionEvent;
use crate::{AttrCmpKind, PacketAttr, ScoreCondition, TriagePolicyInput, ValueKind};

/// The separator between the context ID and the operation number of a
/// DCE/RPC request entry.
const REQUEST_SEPARATOR: char = ':';

/// The score a triage policy gave a detection event.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct TriageScore {
    pub policy_id: u32,
    pub score: f64,
}

impl fmt::Display for TriageScore {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}:{:.2}", self.policy_id, self.score)
    }
}

impl StoredDetectionEvent {
    /// Scores the event against each of `policies`.
    ///
    /// A policy's score is the sum of its `packet_attr` part and its `score`
    /// part:
    ///
    /// - Each `packet_attr` entry adds its `weight` (default 0) when its
    ///   attribute matches, and the total is truncated to two decimals. An
    ///   entry can match only a [`Target::RawEvent`] whose `raw_event_kind`
    ///   is the entry's, and an attribute name unknown for that kind never
    ///   matches.
    /// - Each [`ScoreCondition`] adds its `weight` (default 1.0) when its
    ///   `threat_category` is the event's category, its `detection_model` is
    ///   the event's, and the event's `score` is at least its `score`.
    ///
    /// A policy qualifies, and yields a [`TriageScore`], when its score
    /// reaches the `minimum_score` of at least one of its `response` entries;
    /// a policy with no `response` entries never qualifies.
    #[must_use]
    pub fn score_against_policies(&self, policies: &[TriagePolicyInput]) -> Vec<TriageScore> {
        policies
            .iter()
            .filter_map(|policy| {
                let score = self.score_by_packet_attr(&policy.packet_attr)
                    + self.score_by_conditions(&policy.score);
                policy
                    .response
                    .iter()
                    .any(|response| score >= response.minimum_score)
                    .then_some(TriageScore {
                        policy_id: policy.id,
                        score,
                    })
            })
            .collect()
    }

    /// Returns the sum of the weights of the matching `packet_attr` entries,
    /// truncated to two decimals.
    fn score_by_packet_attr(&self, packet_attr: &[PacketAttr]) -> f64 {
        let Target::RawEvent { body, .. } = &self.event.target else {
            return 0.0;
        };
        let total: f64 = packet_attr
            .iter()
            .filter(|attr| attr.raw_event_kind == self.event.raw_event_kind)
            .filter_map(|attr| {
                let kind = RawEventAttrKind::from_kind_and_attr_name(
                    &attr.raw_event_kind,
                    &attr.attr_name,
                )
                .ok()?;
                let value = attr_value(body, kind)?;
                is_attr_matched(value, attr).then(|| attr.weight.unwrap_or_default())
            })
            .sum();
        (total * 100.0).trunc() / 100.0
    }

    /// Returns the sum of the weights of the score conditions the event
    /// meets.
    fn score_by_conditions(&self, conditions: &[ScoreCondition]) -> f64 {
        let category = self.category();
        conditions
            .iter()
            .filter(|condition| {
                condition.threat_category == category
                    && condition.detection_model == self.event.detection_model
                    && self.event.score >= condition.score
            })
            .map(|condition| condition.weight.unwrap_or(1.0))
            .sum()
    }
}

/// A value read from a raw event body, in the form its comparison takes.
pub(super) enum AttrValue<'a> {
    Addr(IpAddr),
    Bool(bool),
    SInt(i64),
    UInt(u64),
    String(&'a str),
    VecAddr(Cow<'a, [IpAddr]>),
    VecBool(Cow<'a, [bool]>),
    VecSInt(Cow<'a, [i64]>),
    VecUInt(Cow<'a, [u64]>),
    VecString(Cow<'a, [String]>),
    VecRaw(&'a [u8]),
    VecRawList(Cow<'a, [&'a [u8]]>),
}

/// Formats a DCE/RPC UUID, stored in its wire byte order, as canonical text.
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

/// Returns the context IDs, or the operation numbers, of DCE/RPC request
/// entries; `None` when there is no entry or one is malformed.
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

/// Returns the values `f` reads from each of `items`, or `None` when there
/// is no item.
fn non_empty<T, U>(items: &[T], f: impl FnMut(&T) -> U) -> Option<Vec<U>> {
    if items.is_empty() {
        None
    } else {
        Some(items.iter().map(f).collect())
    }
}

/// Returns `values` widened to `u64`.
fn widened<T: Copy + Into<u64>>(values: &[T]) -> Cow<'static, [u64]> {
    Cow::Owned(values.iter().map(|&value| value.into()).collect())
}

/// One element of a list field of an endpoint log body, read by a triage
/// attribute as one string.
#[derive(Clone, Copy)]
pub(super) enum ListElement<'a> {
    /// An element of `WindowsEventLog.event_data`.
    EventData(&'a EventData),
    /// An element of `Journald.fields`, or a field of an [`AuditRecord`].
    LogField(&'a LogField),
    /// An element of `Auditd.records`.
    AuditRecord(&'a AuditRecord),
}

/// Returns the string a triage attribute reads for one element of a list
/// field.
///
/// The value is kept as it is, with no substitution for an empty value and
/// with tabs and newlines kept:
///
/// - an [`EventData`] is `name=value`, or `=value` when it has no name;
/// - a [`LogField`] is `name=` followed by its text, or by its bytes as
///   lowercase hex;
/// - an [`AuditRecord`] is `record_type:` followed by each of its fields as
///   a [`LogField`] is written, joined by one space.
pub(super) fn list_element_string(element: ListElement<'_>) -> String {
    match element {
        ListElement::EventData(data) => {
            format!(
                "{}={}",
                data.name.as_deref().unwrap_or_default(),
                data.value
            )
        }
        ListElement::LogField(field) => {
            let mut text = format!("{}=", field.name);
            match &field.value {
                LogValue::Text(value) => text.push_str(value),
                LogValue::Bytes(bytes) => {
                    for byte in bytes {
                        write!(text, "{byte:02x}").expect("writing to a String does not fail");
                    }
                }
            }
            text
        }
        ListElement::AuditRecord(record) => {
            let fields: Vec<String> = record
                .fields
                .iter()
                .map(|field| list_element_string(ListElement::LogField(field)))
                .collect();
            format!("{}:{}", record.record_type, fields.join(" "))
        }
    }
}

/// Returns the strings a triage attribute reads from a list field: one per
/// element, built by `element`, and none when the field is `None`.
fn list_strings<'a, T>(
    items: Option<&'a [T]>,
    element: impl Fn(&'a T) -> ListElement<'a>,
) -> AttrValue<'a> {
    AttrValue::VecString(Cow::Owned(
        items
            .unwrap_or_default()
            .iter()
            .map(|item| list_element_string(element(item)))
            .collect(),
    ))
}

/// Expands to a `match` over a network attribute enum, with the arms for the
/// connection fields every network body shares followed by `$rest`.
macro_rules! network_attr {
    ($attr:expr, $kind:ident, $body:ident, { $($rest:tt)* }) => {
        match $attr {
            $kind::SrcAddr => AttrValue::Addr($body.orig_addr),
            $kind::SrcPort => AttrValue::UInt($body.orig_port.into()),
            $kind::DstAddr => AttrValue::Addr($body.resp_addr),
            $kind::DstPort => AttrValue::UInt($body.resp_port.into()),
            $kind::Proto => AttrValue::UInt($body.proto.into()),
            $kind::Duration => AttrValue::SInt($body.duration),
            $kind::OrigPkts => AttrValue::UInt($body.orig_pkts),
            $kind::RespPkts => AttrValue::UInt($body.resp_pkts),
            $kind::OrigL2Bytes => AttrValue::UInt($body.orig_l2_bytes),
            $kind::RespL2Bytes => AttrValue::UInt($body.resp_l2_bytes),
            $($rest)*
        }
    };
}

/// Reads the attribute `attr` from `body`.
///
/// Returns `None` when `attr` belongs to another kind than `body`, for
/// the list attributes that read no value from an empty list, and for an
/// optional scalar field that is `None`. A list field of an endpoint log
/// body (`WindowsEventLog.event_data`, `Journald.fields`, `Auditd.records`)
/// reads as one string per element, built by [`list_element_string`], and
/// as an empty list when it is `None`. No attribute reads a body's host
/// header.
///
/// Every kind and every attribute has its own arm, with no wildcard, so
/// that an attribute added to attrievent fails to compile here until it is
/// read.
#[allow(clippy::too_many_lines)]
pub(super) fn attr_value(body: &RawEventBody, attr: RawEventAttrKind) -> Option<AttrValue<'_>> {
    let value = match attr {
        RawEventAttrKind::Conn(attr) => {
            let RawEventBody::Conn(b) = body else {
                return None;
            };
            network_attr!(attr, ConnAttr, b, {
                ConnAttr::ConnState => AttrValue::String(&b.conn_state),
                ConnAttr::Service => AttrValue::String(&b.service),
                ConnAttr::OrigBytes => AttrValue::UInt(b.orig_bytes),
                ConnAttr::RespBytes => AttrValue::UInt(b.resp_bytes),
            })
        }
        RawEventAttrKind::Dns(attr) => {
            let RawEventBody::Dns(b) = body else {
                return None;
            };
            network_attr!(attr, DnsAttr, b, {
                DnsAttr::Query => AttrValue::String(&b.query),
                DnsAttr::Answer => AttrValue::VecString(Cow::Borrowed(&b.answer)),
                DnsAttr::TransId => AttrValue::UInt(b.trans_id.into()),
                DnsAttr::Rtt => AttrValue::SInt(b.rtt),
                DnsAttr::QClass => AttrValue::UInt(b.qclass.into()),
                DnsAttr::QType => AttrValue::UInt(b.qtype.into()),
                DnsAttr::RCode => AttrValue::UInt(b.rcode.into()),
                DnsAttr::AA => AttrValue::Bool(b.aa_flag),
                DnsAttr::TC => AttrValue::Bool(b.tc_flag),
                DnsAttr::RD => AttrValue::Bool(b.rd_flag),
                DnsAttr::RA => AttrValue::Bool(b.ra_flag),
                DnsAttr::Ttl => AttrValue::VecSInt(Cow::Owned(
                    b.ttl.iter().map(|&ttl| i64::from(ttl)).collect(),
                )),
            })
        }
        RawEventAttrKind::Http(attr) => {
            let RawEventBody::Http(b) = body else {
                return None;
            };
            network_attr!(attr, HttpAttr, b, {
                HttpAttr::Method => AttrValue::String(&b.method),
                HttpAttr::Host => AttrValue::String(&b.host),
                HttpAttr::Uri => AttrValue::String(&b.uri),
                HttpAttr::Referer => AttrValue::String(&b.referer),
                HttpAttr::Version => AttrValue::String(&b.version),
                HttpAttr::UserAgent => AttrValue::String(&b.user_agent),
                HttpAttr::RequestLen => AttrValue::UInt(u64::try_from(b.request_len).ok()?),
                HttpAttr::ResponseLen => AttrValue::UInt(u64::try_from(b.response_len).ok()?),
                HttpAttr::StatusCode => AttrValue::UInt(b.status_code.into()),
                HttpAttr::StatusMsg => AttrValue::String(&b.status_msg),
                HttpAttr::Username => AttrValue::String(&b.username),
                HttpAttr::Password => AttrValue::String(&b.password),
                HttpAttr::Cookie => AttrValue::String(&b.cookie),
                HttpAttr::ContentEncoding => AttrValue::String(&b.content_encoding),
                HttpAttr::ContentType => AttrValue::String(&b.content_type),
                HttpAttr::CacheControl => AttrValue::String(&b.cache_control),
                HttpAttr::Filenames => AttrValue::VecString(Cow::Borrowed(&b.filenames)),
                HttpAttr::MimeTypes => AttrValue::VecString(Cow::Borrowed(&b.mime_types)),
                HttpAttr::Body => AttrValue::VecRaw(&b.body),
                HttpAttr::State => AttrValue::String(&b.state),
            })
        }
        RawEventAttrKind::Rdp(attr) => {
            let RawEventBody::Rdp(b) = body else {
                return None;
            };
            network_attr!(attr, RdpAttr, b, {
                RdpAttr::Cookie => AttrValue::String(&b.cookie),
            })
        }
        RawEventAttrKind::Smtp(attr) => {
            let RawEventBody::Smtp(b) = body else {
                return None;
            };
            network_attr!(attr, SmtpAttr, b, {
                SmtpAttr::MailFrom => AttrValue::String(&b.mailfrom),
                SmtpAttr::Date => AttrValue::String(&b.date),
                SmtpAttr::From => AttrValue::String(&b.from),
                SmtpAttr::To => AttrValue::String(&b.to),
                SmtpAttr::Subject => AttrValue::String(&b.subject),
                SmtpAttr::Agent => AttrValue::String(&b.agent),
                SmtpAttr::State => AttrValue::String(&b.state),
            })
        }
        RawEventAttrKind::Ntlm(attr) => {
            let RawEventBody::Ntlm(b) = body else {
                return None;
            };
            network_attr!(attr, NtlmAttr, b, {
                NtlmAttr::Protocol => AttrValue::String(&b.protocol),
                NtlmAttr::Username => AttrValue::String(&b.username),
                NtlmAttr::Hostname => AttrValue::String(&b.hostname),
                NtlmAttr::Domainname => AttrValue::String(&b.domainname),
                NtlmAttr::Success => AttrValue::String(&b.success),
            })
        }
        RawEventAttrKind::Kerberos(attr) => {
            let RawEventBody::Kerberos(b) = body else {
                return None;
            };
            network_attr!(attr, KerberosAttr, b, {
                KerberosAttr::ClientTime => AttrValue::SInt(b.client_time),
                KerberosAttr::ServerTime => AttrValue::SInt(b.server_time),
                KerberosAttr::ErrorCode => AttrValue::UInt(b.error_code.into()),
                KerberosAttr::ClientRealm => AttrValue::String(&b.client_realm),
                KerberosAttr::CnameType => AttrValue::UInt(b.cname_type.into()),
                KerberosAttr::ClientName => AttrValue::VecString(Cow::Borrowed(&b.cname)),
                KerberosAttr::Realm => AttrValue::String(&b.realm),
                KerberosAttr::SnameType => AttrValue::UInt(b.sname_type.into()),
                KerberosAttr::ServiceName => AttrValue::VecString(Cow::Borrowed(&b.sname)),
            })
        }
        RawEventAttrKind::Ssh(attr) => {
            let RawEventBody::Ssh(b) = body else {
                return None;
            };
            network_attr!(attr, SshAttr, b, {
                SshAttr::Client => AttrValue::String(&b.client),
                SshAttr::Server => AttrValue::String(&b.server),
                SshAttr::CipherAlg => AttrValue::String(&b.cipher_alg),
                SshAttr::MacAlg => AttrValue::String(&b.mac_alg),
                SshAttr::CompressionAlg => AttrValue::String(&b.compression_alg),
                SshAttr::KexAlg => AttrValue::String(&b.kex_alg),
                SshAttr::HostKeyAlg => AttrValue::String(&b.host_key_alg),
                SshAttr::HasshAlgorithms => AttrValue::String(&b.hassh_algorithms),
                SshAttr::Hassh => AttrValue::String(&b.hassh),
                SshAttr::HasshServerAlgorithms => AttrValue::String(&b.hassh_server_algorithms),
                SshAttr::HasshServer => AttrValue::String(&b.hassh_server),
                SshAttr::ClientShka => AttrValue::String(&b.client_shka),
                SshAttr::ServerShka => AttrValue::String(&b.server_shka),
            })
        }
        RawEventAttrKind::DceRpc(attr) => {
            let RawEventBody::DceRpc(b) = body else {
                return None;
            };
            network_attr!(attr, DceRpcAttr, b, {
                DceRpcAttr::ContextId => AttrValue::VecUInt(Cow::Owned(
                    non_empty(&b.context, |c| u64::from(c.id))?,
                )),
                DceRpcAttr::AbstractSyntax => AttrValue::VecString(Cow::Owned(
                    non_empty(&b.context, |c| format_dce_uuid(c.abstract_syntax))?,
                )),
                DceRpcAttr::AbstractMajor => AttrValue::VecUInt(Cow::Owned(
                    non_empty(&b.context, |c| u64::from(c.abstract_major))?,
                )),
                DceRpcAttr::AbstractMinor => AttrValue::VecUInt(Cow::Owned(
                    non_empty(&b.context, |c| u64::from(c.abstract_minor))?,
                )),
                DceRpcAttr::TransferSyntax => AttrValue::VecString(Cow::Owned(
                    non_empty(&b.context, |c| format_dce_uuid(c.transfer_syntax))?,
                )),
                DceRpcAttr::TransferMajor => AttrValue::VecUInt(Cow::Owned(
                    non_empty(&b.context, |c| u64::from(c.transfer_major))?,
                )),
                DceRpcAttr::TransferMinor => AttrValue::VecUInt(Cow::Owned(
                    non_empty(&b.context, |c| u64::from(c.transfer_minor))?,
                )),
                DceRpcAttr::Acceptance => AttrValue::VecUInt(Cow::Owned(
                    non_empty(&b.context, |c| u64::from(c.acceptance))?,
                )),
                DceRpcAttr::Reason => AttrValue::VecUInt(Cow::Owned(
                    non_empty(&b.context, |c| u64::from(c.reason))?,
                )),
                DceRpcAttr::RequestContextId => AttrValue::VecUInt(Cow::Owned(
                    collect_request_part(&b.request, true)?,
                )),
                DceRpcAttr::RequestOpnum => AttrValue::VecUInt(Cow::Owned(
                    collect_request_part(&b.request, false)?,
                )),
            })
        }
        RawEventAttrKind::Ftp(attr) => {
            let RawEventBody::Ftp(b) = body else {
                return None;
            };
            network_attr!(attr, FtpAttr, b, {
                FtpAttr::User => AttrValue::String(&b.user),
                FtpAttr::Password => AttrValue::String(&b.password),
                FtpAttr::Command => AttrValue::VecString(Cow::Owned(
                    non_empty(&b.commands, |c| c.command.clone())?,
                )),
                FtpAttr::ReplyCode => AttrValue::VecString(Cow::Owned(
                    non_empty(&b.commands, |c| c.reply_code.clone())?,
                )),
                FtpAttr::ReplyMsg => AttrValue::VecString(Cow::Owned(
                    non_empty(&b.commands, |c| c.reply_msg.clone())?,
                )),
                FtpAttr::DataPassive => AttrValue::VecBool(Cow::Owned(
                    non_empty(&b.commands, |c| c.data_passive)?,
                )),
                FtpAttr::DataOrigAddr => AttrValue::VecAddr(Cow::Owned(
                    non_empty(&b.commands, |c| c.data_orig_addr)?,
                )),
                FtpAttr::DataRespAddr => AttrValue::VecAddr(Cow::Owned(
                    non_empty(&b.commands, |c| c.data_resp_addr)?,
                )),
                FtpAttr::DataRespPort => AttrValue::VecUInt(Cow::Owned(
                    non_empty(&b.commands, |c| u64::from(c.data_resp_port))?,
                )),
                FtpAttr::File => AttrValue::VecString(Cow::Owned(
                    non_empty(&b.commands, |c| c.file.clone())?,
                )),
                FtpAttr::FileSize => AttrValue::VecUInt(Cow::Owned(
                    non_empty(&b.commands, |c| c.file_size)?,
                )),
                FtpAttr::FileId => AttrValue::VecString(Cow::Owned(
                    non_empty(&b.commands, |c| c.file_id.clone())?,
                )),
            })
        }
        RawEventAttrKind::Mqtt(attr) => {
            let RawEventBody::Mqtt(b) = body else {
                return None;
            };
            network_attr!(attr, MqttAttr, b, {
                MqttAttr::Protocol => AttrValue::String(&b.protocol),
                MqttAttr::Version => AttrValue::UInt(b.version.into()),
                MqttAttr::ClientId => AttrValue::String(&b.client_id),
                MqttAttr::ConnackReason => AttrValue::UInt(b.connack_reason.into()),
                MqttAttr::Subscribe => AttrValue::VecString(Cow::Borrowed(&b.subscribe)),
                MqttAttr::SubackReason => AttrValue::VecUInt(widened(&b.suback_reason)),
            })
        }
        RawEventAttrKind::Ldap(attr) => {
            let RawEventBody::Ldap(b) = body else {
                return None;
            };
            network_attr!(attr, LdapAttr, b, {
                LdapAttr::MessageId => AttrValue::UInt(b.message_id.into()),
                LdapAttr::Version => AttrValue::UInt(b.version.into()),
                LdapAttr::Opcode => AttrValue::VecString(Cow::Borrowed(&b.opcode)),
                LdapAttr::Result => AttrValue::VecString(Cow::Borrowed(&b.result)),
                LdapAttr::DiagnosticMessage => {
                    AttrValue::VecString(Cow::Borrowed(&b.diagnostic_message))
                }
                LdapAttr::Object => AttrValue::VecString(Cow::Borrowed(&b.object)),
                LdapAttr::Argument => AttrValue::VecString(Cow::Borrowed(&b.argument)),
            })
        }
        RawEventAttrKind::Tls(attr) => {
            let RawEventBody::Tls(b) = body else {
                return None;
            };
            network_attr!(attr, TlsAttr, b, {
                TlsAttr::ServerName => AttrValue::String(&b.server_name),
                // The per-kind TLS mapping this replaces read `server_name` here; the
                // attribute names the ALPN protocol, so it reads that field.
                TlsAttr::AlpnProtocol => AttrValue::String(&b.alpn_protocol),
                TlsAttr::Ja3 => AttrValue::String(&b.ja3),
                TlsAttr::Version => AttrValue::String(&b.version),
                TlsAttr::ClientCipherSuites => AttrValue::VecUInt(widened(&b.client_cipher_suites)),
                TlsAttr::ClientExtensions => AttrValue::VecUInt(widened(&b.client_extensions)),
                TlsAttr::Cipher => AttrValue::UInt(b.cipher.into()),
                TlsAttr::Extensions => AttrValue::VecUInt(widened(&b.extensions)),
                TlsAttr::Ja3s => AttrValue::String(&b.ja3s),
                TlsAttr::Serial => AttrValue::String(&b.serial),
                TlsAttr::SubjectCountry => AttrValue::String(&b.subject_country),
                TlsAttr::SubjectOrgName => AttrValue::String(&b.subject_org_name),
                TlsAttr::SubjectCommonName => AttrValue::String(&b.subject_common_name),
                TlsAttr::ValidityNotBefore => AttrValue::SInt(b.validity_not_before),
                TlsAttr::ValidityNotAfter => AttrValue::SInt(b.validity_not_after),
                TlsAttr::SubjectAltName => AttrValue::String(&b.subject_alt_name),
                TlsAttr::IssuerCountry => AttrValue::String(&b.issuer_country),
                TlsAttr::IssuerOrgName => AttrValue::String(&b.issuer_org_name),
                TlsAttr::IssuerOrgUnitName => AttrValue::String(&b.issuer_org_unit_name),
                TlsAttr::IssuerCommonName => AttrValue::String(&b.issuer_common_name),
                TlsAttr::LastAlert => AttrValue::UInt(b.last_alert.into()),
            })
        }
        RawEventAttrKind::Smb(attr) => {
            let RawEventBody::Smb(b) = body else {
                return None;
            };
            network_attr!(attr, SmbAttr, b, {
                SmbAttr::Command => AttrValue::UInt(b.command.into()),
                SmbAttr::Path => AttrValue::String(&b.path),
                SmbAttr::Service => AttrValue::String(&b.service),
                SmbAttr::FileName => AttrValue::String(&b.file_name),
                SmbAttr::FileSize => AttrValue::UInt(b.file_size),
                SmbAttr::ResourceType => AttrValue::UInt(b.resource_type.into()),
                SmbAttr::Fid => AttrValue::UInt(b.fid.into()),
                SmbAttr::CreateTime => AttrValue::SInt(b.create_time),
                SmbAttr::AccessTime => AttrValue::SInt(b.access_time),
                SmbAttr::WriteTime => AttrValue::SInt(b.write_time),
                SmbAttr::ChangeTime => AttrValue::SInt(b.change_time),
            })
        }
        RawEventAttrKind::Nfs(attr) => {
            let RawEventBody::Nfs(b) = body else {
                return None;
            };
            network_attr!(attr, NfsAttr, b, {
                NfsAttr::ReadFiles => AttrValue::VecString(Cow::Borrowed(&b.read_files)),
                NfsAttr::WriteFiles => AttrValue::VecString(Cow::Borrowed(&b.write_files)),
            })
        }
        RawEventAttrKind::Bootp(attr) => {
            let RawEventBody::Bootp(b) = body else {
                return None;
            };
            network_attr!(attr, BootpAttr, b, {
                BootpAttr::Op => AttrValue::UInt(b.op.into()),
                BootpAttr::Htype => AttrValue::UInt(b.htype.into()),
                BootpAttr::Hops => AttrValue::UInt(b.hops.into()),
                BootpAttr::Xid => AttrValue::UInt(b.xid.into()),
                BootpAttr::CiAddr => AttrValue::Addr(b.ciaddr),
                BootpAttr::YiAddr => AttrValue::Addr(b.yiaddr),
                BootpAttr::SiAddr => AttrValue::Addr(b.siaddr),
                BootpAttr::GiAddr => AttrValue::Addr(b.giaddr),
                BootpAttr::ChAddr => AttrValue::VecRaw(&b.chaddr),
                BootpAttr::SName => AttrValue::String(&b.sname),
                BootpAttr::File => AttrValue::String(&b.file),
            })
        }
        RawEventAttrKind::Dhcp(attr) => {
            let RawEventBody::Dhcp(b) = body else {
                return None;
            };
            network_attr!(attr, DhcpAttr, b, {
                DhcpAttr::MsgType => AttrValue::UInt(b.msg_type.into()),
                DhcpAttr::CiAddr => AttrValue::Addr(b.ciaddr),
                DhcpAttr::YiAddr => AttrValue::Addr(b.yiaddr),
                DhcpAttr::SiAddr => AttrValue::Addr(b.siaddr),
                DhcpAttr::GiAddr => AttrValue::Addr(b.giaddr),
                DhcpAttr::SubNetMask => AttrValue::Addr(b.subnet_mask),
                DhcpAttr::Router => AttrValue::VecAddr(Cow::Borrowed(&b.router)),
                DhcpAttr::DomainNameServer => {
                    AttrValue::VecAddr(Cow::Borrowed(&b.domain_name_server))
                }
                DhcpAttr::ReqIpAddr => AttrValue::Addr(b.req_ip_addr),
                DhcpAttr::LeaseTime => AttrValue::UInt(b.lease_time.into()),
                DhcpAttr::ServerId => AttrValue::Addr(b.server_id),
                DhcpAttr::ParamReqList => AttrValue::VecUInt(widened(&b.param_req_list)),
                DhcpAttr::Message => AttrValue::String(&b.message),
                DhcpAttr::RenewalTime => AttrValue::UInt(b.renewal_time.into()),
                DhcpAttr::RebindingTime => AttrValue::UInt(b.rebinding_time.into()),
                DhcpAttr::ClassId => AttrValue::VecRaw(&b.class_id),
                DhcpAttr::ClientIdType => AttrValue::UInt(b.client_id_type.into()),
                DhcpAttr::ClientId => AttrValue::VecRaw(&b.client_id),
                DhcpAttr::OptionCode => AttrValue::VecUInt(Cow::Owned(
                    b.options.iter().map(|(code, _)| u64::from(*code)).collect(),
                )),
                DhcpAttr::OptionData => AttrValue::VecRawList(Cow::Owned(
                    b.options.iter().map(|(_, data)| data.as_slice()).collect(),
                )),
            })
        }
        RawEventAttrKind::Radius(attr) => {
            let RawEventBody::Radius(b) = body else {
                return None;
            };
            network_attr!(attr, RadiusAttr, b, {
                RadiusAttr::Id => AttrValue::UInt(b.id.into()),
                RadiusAttr::Code => AttrValue::UInt(b.code.into()),
                RadiusAttr::RespCode => AttrValue::UInt(b.resp_code.into()),
                RadiusAttr::Auth => AttrValue::String(&b.auth),
                RadiusAttr::RespAuth => AttrValue::String(&b.resp_auth),
                RadiusAttr::UserName => AttrValue::VecRaw(&b.user_name),
                RadiusAttr::UserPasswd => AttrValue::VecRaw(&b.user_passwd),
                RadiusAttr::ChapPasswd => AttrValue::VecRaw(&b.chap_passwd),
                RadiusAttr::NasIp => AttrValue::Addr(b.nas_ip),
                RadiusAttr::NasPort => AttrValue::UInt(b.nas_port.into()),
                RadiusAttr::State => AttrValue::VecRaw(&b.state),
                RadiusAttr::NasId => AttrValue::VecRaw(&b.nas_id),
                RadiusAttr::NasPortType => AttrValue::UInt(b.nas_port_type.into()),
                RadiusAttr::Message => AttrValue::String(&b.message),
            })
        }
        RawEventAttrKind::MalformedDns(attr) => {
            let RawEventBody::MalformedDns(b) = body else {
                return None;
            };
            network_attr!(attr, MalformedDnsAttr, b, {
                MalformedDnsAttr::StartTime => AttrValue::SInt(b.start_time),
                MalformedDnsAttr::TransId => AttrValue::UInt(b.trans_id.into()),
                MalformedDnsAttr::Flags => AttrValue::UInt(b.flags.into()),
                MalformedDnsAttr::QuestionCount => AttrValue::UInt(b.question_count.into()),
                MalformedDnsAttr::AnswerCount => AttrValue::UInt(b.answer_count.into()),
                MalformedDnsAttr::AuthorityCount => AttrValue::UInt(b.authority_count.into()),
                MalformedDnsAttr::AdditionalCount => AttrValue::UInt(b.additional_count.into()),
                MalformedDnsAttr::QueryCount => AttrValue::UInt(b.query_count.into()),
                MalformedDnsAttr::RespCount => AttrValue::UInt(b.resp_count.into()),
                MalformedDnsAttr::QueryBytes => AttrValue::UInt(b.query_bytes),
                MalformedDnsAttr::RespBytes => AttrValue::UInt(b.resp_bytes),
                MalformedDnsAttr::QueryBody => AttrValue::VecRawList(Cow::Owned(
                    b.query_body.iter().map(Vec::as_slice).collect(),
                )),
                MalformedDnsAttr::RespBody => AttrValue::VecRawList(Cow::Owned(
                    b.resp_body.iter().map(Vec::as_slice).collect(),
                )),
            })
        }
        RawEventAttrKind::Icmp(attr) => {
            let RawEventBody::Icmp(b) = body else {
                return None;
            };
            match attr {
                IcmpAttr::SrcAddr => AttrValue::Addr(b.orig_addr),
                IcmpAttr::DstAddr => AttrValue::Addr(b.resp_addr),
                IcmpAttr::Proto => AttrValue::UInt(b.proto.into()),
                IcmpAttr::StartTime => AttrValue::SInt(b.start_time),
                IcmpAttr::Duration => AttrValue::SInt(b.duration),
                IcmpAttr::OrigPkts => AttrValue::UInt(b.orig_pkts),
                IcmpAttr::RespPkts => AttrValue::UInt(b.resp_pkts),
                IcmpAttr::OrigL2Bytes => AttrValue::UInt(b.orig_l2_bytes),
                IcmpAttr::RespL2Bytes => AttrValue::UInt(b.resp_l2_bytes),
                IcmpAttr::IcmpType => AttrValue::UInt(b.icmp_type.into()),
                IcmpAttr::IcmpCode => AttrValue::UInt(b.icmp_code.into()),
                IcmpAttr::Id => AttrValue::UInt(b.id.into()),
                IcmpAttr::SeqNum => AttrValue::UInt(b.seq_num.into()),
                IcmpAttr::DataLen => AttrValue::UInt(b.data_len.into()),
                IcmpAttr::Payload => AttrValue::VecRaw(&b.payload),
            }
        }
        RawEventAttrKind::ProcessCreate(attr) => {
            let RawEventBody::ProcessCreate(b) = body else {
                return None;
            };
            match attr {
                ProcessCreateAttr::AgentName => AttrValue::String(&b.agent_name),
                ProcessCreateAttr::AgentId => AttrValue::String(&b.agent_id),
                ProcessCreateAttr::ProcessGuid => AttrValue::String(&b.process_guid),
                ProcessCreateAttr::ProcessId => AttrValue::UInt(b.process_id.into()),
                ProcessCreateAttr::Image => AttrValue::String(&b.image),
                ProcessCreateAttr::FileVersion => AttrValue::String(&b.file_version),
                ProcessCreateAttr::Description => AttrValue::String(&b.description),
                ProcessCreateAttr::Product => AttrValue::String(&b.product),
                ProcessCreateAttr::Company => AttrValue::String(&b.company),
                ProcessCreateAttr::OriginalFileName => AttrValue::String(&b.original_file_name),
                ProcessCreateAttr::CommandLine => AttrValue::String(&b.command_line),
                ProcessCreateAttr::CurrentDirectory => AttrValue::String(&b.current_directory),
                ProcessCreateAttr::User => AttrValue::String(&b.user),
                ProcessCreateAttr::LogonGuid => AttrValue::String(&b.logon_guid),
                ProcessCreateAttr::LogonId => AttrValue::UInt(b.logon_id.into()),
                ProcessCreateAttr::TerminalSessionId => {
                    AttrValue::UInt(b.terminal_session_id.into())
                }
                ProcessCreateAttr::IntegrityLevel => AttrValue::String(&b.integrity_level),
                ProcessCreateAttr::Hashes => AttrValue::VecString(Cow::Borrowed(&b.hashes)),
                ProcessCreateAttr::ParentProcessGuid => AttrValue::String(&b.parent_process_guid),
                ProcessCreateAttr::ParentProcessId => AttrValue::UInt(b.parent_process_id.into()),
                ProcessCreateAttr::ParentImage => AttrValue::String(&b.parent_image),
                ProcessCreateAttr::ParentCommandLine => AttrValue::String(&b.parent_command_line),
                ProcessCreateAttr::ParentUser => AttrValue::String(&b.parent_user),
                ProcessCreateAttr::LogonIdFull => AttrValue::UInt(b.logon_id_full?),
            }
        }
        RawEventAttrKind::FileCreateTime(attr) => {
            let RawEventBody::FileCreateTime(b) = body else {
                return None;
            };
            match attr {
                FileCreateTimeAttr::AgentName => AttrValue::String(&b.agent_name),
                FileCreateTimeAttr::AgentId => AttrValue::String(&b.agent_id),
                FileCreateTimeAttr::ProcessGuid => AttrValue::String(&b.process_guid),
                FileCreateTimeAttr::ProcessId => AttrValue::UInt(b.process_id.into()),
                FileCreateTimeAttr::Image => AttrValue::String(&b.image),
                FileCreateTimeAttr::TargetFilename => AttrValue::String(&b.target_filename),
                FileCreateTimeAttr::CreationUtcTime => AttrValue::SInt(b.creation_utc_time),
                FileCreateTimeAttr::PreviousCreationUtcTime => {
                    AttrValue::SInt(b.previous_creation_utc_time)
                }
                FileCreateTimeAttr::User => AttrValue::String(&b.user),
            }
        }
        RawEventAttrKind::NetworkConnect(attr) => {
            let RawEventBody::NetworkConnect(b) = body else {
                return None;
            };
            match attr {
                NetworkConnectAttr::AgentName => AttrValue::String(&b.agent_name),
                NetworkConnectAttr::AgentId => AttrValue::String(&b.agent_id),
                NetworkConnectAttr::ProcessGuid => AttrValue::String(&b.process_guid),
                NetworkConnectAttr::ProcessId => AttrValue::UInt(b.process_id.into()),
                NetworkConnectAttr::Image => AttrValue::String(&b.image),
                NetworkConnectAttr::User => AttrValue::String(&b.user),
                NetworkConnectAttr::Protocol => AttrValue::String(&b.protocol),
                NetworkConnectAttr::Initiated => AttrValue::Bool(b.initiated),
                NetworkConnectAttr::SourceIsIpv6 => AttrValue::Bool(b.source_is_ipv6),
                NetworkConnectAttr::SourceIp => AttrValue::Addr(b.source_ip),
                NetworkConnectAttr::SourceHostname => AttrValue::String(&b.source_hostname),
                NetworkConnectAttr::SourcePort => AttrValue::UInt(b.source_port.into()),
                NetworkConnectAttr::SourcePortName => AttrValue::String(&b.source_port_name),
                NetworkConnectAttr::DestinationIsIpv6 => AttrValue::Bool(b.destination_is_ipv6),
                NetworkConnectAttr::DestinationIp => AttrValue::Addr(b.destination_ip),
                NetworkConnectAttr::DestinationHostname => {
                    AttrValue::String(&b.destination_hostname)
                }
                NetworkConnectAttr::DestinationPort => AttrValue::UInt(b.destination_port.into()),
                NetworkConnectAttr::DestinationPortName => {
                    AttrValue::String(&b.destination_port_name)
                }
            }
        }
        RawEventAttrKind::ProcessTerminate(attr) => {
            let RawEventBody::ProcessTerminate(b) = body else {
                return None;
            };
            match attr {
                ProcessTerminateAttr::AgentName => AttrValue::String(&b.agent_name),
                ProcessTerminateAttr::AgentId => AttrValue::String(&b.agent_id),
                ProcessTerminateAttr::ProcessGuid => AttrValue::String(&b.process_guid),
                ProcessTerminateAttr::ProcessId => AttrValue::UInt(b.process_id.into()),
                ProcessTerminateAttr::Image => AttrValue::String(&b.image),
                ProcessTerminateAttr::User => AttrValue::String(&b.user),
            }
        }
        RawEventAttrKind::ImageLoad(attr) => {
            let RawEventBody::ImageLoad(b) = body else {
                return None;
            };
            match attr {
                ImageLoadAttr::AgentName => AttrValue::String(&b.agent_name),
                ImageLoadAttr::AgentId => AttrValue::String(&b.agent_id),
                ImageLoadAttr::ProcessGuid => AttrValue::String(&b.process_guid),
                ImageLoadAttr::ProcessId => AttrValue::UInt(b.process_id.into()),
                ImageLoadAttr::Image => AttrValue::String(&b.image),
                ImageLoadAttr::ImageLoaded => AttrValue::String(&b.image_loaded),
                ImageLoadAttr::FileVersion => AttrValue::String(&b.file_version),
                ImageLoadAttr::Description => AttrValue::String(&b.description),
                ImageLoadAttr::Product => AttrValue::String(&b.product),
                ImageLoadAttr::Company => AttrValue::String(&b.company),
                ImageLoadAttr::OriginalFileName => AttrValue::String(&b.original_file_name),
                ImageLoadAttr::Hashes => AttrValue::VecString(Cow::Borrowed(&b.hashes)),
                ImageLoadAttr::Signed => AttrValue::Bool(b.signed),
                ImageLoadAttr::Signature => AttrValue::String(&b.signature),
                ImageLoadAttr::SignatureStatus => AttrValue::String(&b.signature_status),
                ImageLoadAttr::User => AttrValue::String(&b.user),
            }
        }
        RawEventAttrKind::FileCreate(attr) => {
            let RawEventBody::FileCreate(b) = body else {
                return None;
            };
            match attr {
                FileCreateAttr::AgentName => AttrValue::String(&b.agent_name),
                FileCreateAttr::AgentId => AttrValue::String(&b.agent_id),
                FileCreateAttr::ProcessGuid => AttrValue::String(&b.process_guid),
                FileCreateAttr::ProcessId => AttrValue::UInt(b.process_id.into()),
                FileCreateAttr::Image => AttrValue::String(&b.image),
                FileCreateAttr::TargetFilename => AttrValue::String(&b.target_filename),
                FileCreateAttr::CreationUtcTime => AttrValue::SInt(b.creation_utc_time),
                FileCreateAttr::User => AttrValue::String(&b.user),
            }
        }
        RawEventAttrKind::RegistryValueSet(attr) => {
            let RawEventBody::RegistryValueSet(b) = body else {
                return None;
            };
            match attr {
                RegistryValueSetAttr::AgentName => AttrValue::String(&b.agent_name),
                RegistryValueSetAttr::AgentId => AttrValue::String(&b.agent_id),
                RegistryValueSetAttr::EventType => AttrValue::String(&b.event_type),
                RegistryValueSetAttr::ProcessGuid => AttrValue::String(&b.process_guid),
                RegistryValueSetAttr::ProcessId => AttrValue::UInt(b.process_id.into()),
                RegistryValueSetAttr::Image => AttrValue::String(&b.image),
                RegistryValueSetAttr::TargetObject => AttrValue::String(&b.target_object),
                RegistryValueSetAttr::Details => AttrValue::String(&b.details),
                RegistryValueSetAttr::User => AttrValue::String(&b.user),
            }
        }
        RawEventAttrKind::RegistryKeyRename(attr) => {
            let RawEventBody::RegistryKeyRename(b) = body else {
                return None;
            };
            match attr {
                RegistryKeyRenameAttr::AgentName => AttrValue::String(&b.agent_name),
                RegistryKeyRenameAttr::AgentId => AttrValue::String(&b.agent_id),
                RegistryKeyRenameAttr::EventType => AttrValue::String(&b.event_type),
                RegistryKeyRenameAttr::ProcessGuid => AttrValue::String(&b.process_guid),
                RegistryKeyRenameAttr::ProcessId => AttrValue::UInt(b.process_id.into()),
                RegistryKeyRenameAttr::Image => AttrValue::String(&b.image),
                RegistryKeyRenameAttr::TargetObject => AttrValue::String(&b.target_object),
                RegistryKeyRenameAttr::NewName => AttrValue::String(&b.new_name),
                RegistryKeyRenameAttr::User => AttrValue::String(&b.user),
            }
        }
        RawEventAttrKind::FileCreateStreamHash(attr) => {
            let RawEventBody::FileCreateStreamHash(b) = body else {
                return None;
            };
            match attr {
                FileCreateStreamHashAttr::AgentName => AttrValue::String(&b.agent_name),
                FileCreateStreamHashAttr::AgentId => AttrValue::String(&b.agent_id),
                FileCreateStreamHashAttr::ProcessGuid => AttrValue::String(&b.process_guid),
                FileCreateStreamHashAttr::ProcessId => AttrValue::UInt(b.process_id.into()),
                FileCreateStreamHashAttr::Image => AttrValue::String(&b.image),
                FileCreateStreamHashAttr::TargetFilename => AttrValue::String(&b.target_filename),
                FileCreateStreamHashAttr::CreationUtcTime => AttrValue::SInt(b.creation_utc_time),
                FileCreateStreamHashAttr::Hash => AttrValue::VecString(Cow::Borrowed(&b.hash)),
                FileCreateStreamHashAttr::Contents => AttrValue::String(&b.contents),
                FileCreateStreamHashAttr::User => AttrValue::String(&b.user),
            }
        }
        RawEventAttrKind::PipeEvent(attr) => {
            let RawEventBody::PipeEvent(b) = body else {
                return None;
            };
            match attr {
                PipeEventAttr::AgentName => AttrValue::String(&b.agent_name),
                PipeEventAttr::AgentId => AttrValue::String(&b.agent_id),
                PipeEventAttr::EventType => AttrValue::String(&b.event_type),
                PipeEventAttr::ProcessGuid => AttrValue::String(&b.process_guid),
                PipeEventAttr::ProcessId => AttrValue::UInt(b.process_id.into()),
                PipeEventAttr::PipeName => AttrValue::String(&b.pipe_name),
                PipeEventAttr::Image => AttrValue::String(&b.image),
                PipeEventAttr::User => AttrValue::String(&b.user),
            }
        }
        RawEventAttrKind::DnsQuery(attr) => {
            let RawEventBody::DnsQuery(b) = body else {
                return None;
            };
            match attr {
                DnsQueryAttr::AgentName => AttrValue::String(&b.agent_name),
                DnsQueryAttr::AgentId => AttrValue::String(&b.agent_id),
                DnsQueryAttr::ProcessGuid => AttrValue::String(&b.process_guid),
                DnsQueryAttr::ProcessId => AttrValue::UInt(b.process_id.into()),
                DnsQueryAttr::QueryName => AttrValue::String(&b.query_name),
                DnsQueryAttr::QueryStatus => AttrValue::UInt(b.query_status.into()),
                DnsQueryAttr::QueryResults => AttrValue::VecString(Cow::Borrowed(&b.query_results)),
                DnsQueryAttr::Image => AttrValue::String(&b.image),
                DnsQueryAttr::User => AttrValue::String(&b.user),
            }
        }
        RawEventAttrKind::FileDelete(attr) => {
            let RawEventBody::FileDelete(b) = body else {
                return None;
            };
            match attr {
                FileDeleteAttr::AgentName => AttrValue::String(&b.agent_name),
                FileDeleteAttr::AgentId => AttrValue::String(&b.agent_id),
                FileDeleteAttr::ProcessGuid => AttrValue::String(&b.process_guid),
                FileDeleteAttr::ProcessId => AttrValue::UInt(b.process_id.into()),
                FileDeleteAttr::User => AttrValue::String(&b.user),
                FileDeleteAttr::Image => AttrValue::String(&b.image),
                FileDeleteAttr::TargetFilename => AttrValue::String(&b.target_filename),
                FileDeleteAttr::Hashes => AttrValue::VecString(Cow::Borrowed(&b.hashes)),
                FileDeleteAttr::IsExecutable => AttrValue::Bool(b.is_executable),
                FileDeleteAttr::Archived => AttrValue::Bool(b.archived),
            }
        }
        RawEventAttrKind::ProcessTamper(attr) => {
            let RawEventBody::ProcessTamper(b) = body else {
                return None;
            };
            match attr {
                ProcessTamperAttr::AgentName => AttrValue::String(&b.agent_name),
                ProcessTamperAttr::AgentId => AttrValue::String(&b.agent_id),
                ProcessTamperAttr::ProcessGuid => AttrValue::String(&b.process_guid),
                ProcessTamperAttr::ProcessId => AttrValue::UInt(b.process_id.into()),
                ProcessTamperAttr::Image => AttrValue::String(&b.image),
                ProcessTamperAttr::TamperType => AttrValue::String(&b.tamper_type),
                ProcessTamperAttr::User => AttrValue::String(&b.user),
            }
        }
        RawEventAttrKind::FileDeleteDetected(attr) => {
            let RawEventBody::FileDeleteDetected(b) = body else {
                return None;
            };
            match attr {
                FileDeleteDetectedAttr::AgentName => AttrValue::String(&b.agent_name),
                FileDeleteDetectedAttr::AgentId => AttrValue::String(&b.agent_id),
                FileDeleteDetectedAttr::ProcessGuid => AttrValue::String(&b.process_guid),
                FileDeleteDetectedAttr::ProcessId => AttrValue::UInt(b.process_id.into()),
                FileDeleteDetectedAttr::User => AttrValue::String(&b.user),
                FileDeleteDetectedAttr::Image => AttrValue::String(&b.image),
                FileDeleteDetectedAttr::TargetFilename => AttrValue::String(&b.target_filename),
                FileDeleteDetectedAttr::Hashes => AttrValue::VecString(Cow::Borrowed(&b.hashes)),
                FileDeleteDetectedAttr::IsExecutable => AttrValue::Bool(b.is_executable),
            }
        }
        RawEventAttrKind::Netflow5(attr) => {
            let RawEventBody::Netflow5(b) = body else {
                return None;
            };
            match attr {
                Netflow5Attr::SrcAddr => AttrValue::Addr(b.src_addr),
                Netflow5Attr::DstAddr => AttrValue::Addr(b.dst_addr),
                Netflow5Attr::NextHop => AttrValue::Addr(b.next_hop),
                Netflow5Attr::Input => AttrValue::UInt(b.input.into()),
                Netflow5Attr::Output => AttrValue::UInt(b.output.into()),
                Netflow5Attr::DPkts => AttrValue::UInt(b.d_pkts.into()),
                Netflow5Attr::DOctets => AttrValue::UInt(b.d_octets.into()),
                Netflow5Attr::First => AttrValue::UInt(b.first.into()),
                Netflow5Attr::Last => AttrValue::UInt(b.last.into()),
                Netflow5Attr::SrcPort => AttrValue::UInt(b.src_port.into()),
                Netflow5Attr::DstPort => AttrValue::UInt(b.dst_port.into()),
                Netflow5Attr::TcpFlags => AttrValue::UInt(b.tcp_flags.into()),
                Netflow5Attr::Prot => AttrValue::UInt(b.prot.into()),
                Netflow5Attr::Tos => AttrValue::UInt(b.tos.into()),
                Netflow5Attr::SrcAs => AttrValue::UInt(b.src_as.into()),
                Netflow5Attr::DstAs => AttrValue::UInt(b.dst_as.into()),
                Netflow5Attr::SrcMask => AttrValue::UInt(b.src_mask.into()),
                Netflow5Attr::DstMask => AttrValue::UInt(b.dst_mask.into()),
                Netflow5Attr::Sequence => AttrValue::UInt(b.sequence.into()),
                Netflow5Attr::EngineType => AttrValue::UInt(b.engine_type.into()),
                Netflow5Attr::EngineId => AttrValue::UInt(b.engine_id.into()),
                Netflow5Attr::SamplingMode => AttrValue::UInt(b.sampling_mode.into()),
                Netflow5Attr::SamplingRate => AttrValue::UInt(b.sampling_rate.into()),
            }
        }
        RawEventAttrKind::Netflow9(attr) => {
            let RawEventBody::Netflow9(b) = body else {
                return None;
            };
            match attr {
                Netflow9Attr::Sequence => AttrValue::UInt(b.sequence.into()),
                Netflow9Attr::SourceId => AttrValue::UInt(b.source_id.into()),
                Netflow9Attr::TemplateId => AttrValue::UInt(b.template_id.into()),
                Netflow9Attr::SrcAddr => AttrValue::Addr(b.orig_addr),
                Netflow9Attr::SrcPort => AttrValue::UInt(b.orig_port.into()),
                Netflow9Attr::DstAddr => AttrValue::Addr(b.resp_addr),
                Netflow9Attr::DstPort => AttrValue::UInt(b.resp_port.into()),
                Netflow9Attr::Proto => AttrValue::UInt(b.proto.into()),
                Netflow9Attr::Contents => AttrValue::String(&b.contents),
            }
        }
        RawEventAttrKind::DriverLoad(attr) => {
            let RawEventBody::DriverLoad(b) = body else {
                return None;
            };
            match attr {
                DriverLoadAttr::AgentName => AttrValue::String(&b.agent_name),
                DriverLoadAttr::AgentId => AttrValue::String(&b.agent_id),
                DriverLoadAttr::ImageLoaded => AttrValue::String(&b.image_loaded),
                DriverLoadAttr::Hashes => AttrValue::VecString(Cow::Borrowed(&b.hashes)),
                DriverLoadAttr::Signed => AttrValue::Bool(b.signed),
                DriverLoadAttr::Signature => AttrValue::String(&b.signature),
                DriverLoadAttr::SignatureStatus => AttrValue::String(&b.signature_status),
            }
        }
        RawEventAttrKind::CreateRemoteThread(attr) => {
            let RawEventBody::CreateRemoteThread(b) = body else {
                return None;
            };
            match attr {
                CreateRemoteThreadAttr::AgentName => AttrValue::String(&b.agent_name),
                CreateRemoteThreadAttr::AgentId => AttrValue::String(&b.agent_id),
                CreateRemoteThreadAttr::SourceProcessGuid => {
                    AttrValue::String(&b.source_process_guid)
                }
                CreateRemoteThreadAttr::SourceProcessId => {
                    AttrValue::UInt(b.source_process_id.into())
                }
                CreateRemoteThreadAttr::SourceImage => AttrValue::String(&b.source_image),
                CreateRemoteThreadAttr::TargetProcessGuid => {
                    AttrValue::String(&b.target_process_guid)
                }
                CreateRemoteThreadAttr::TargetProcessId => {
                    AttrValue::UInt(b.target_process_id.into())
                }
                CreateRemoteThreadAttr::TargetImage => AttrValue::String(&b.target_image),
                CreateRemoteThreadAttr::NewThreadId => AttrValue::UInt(b.new_thread_id.into()),
                CreateRemoteThreadAttr::StartAddress => AttrValue::String(&b.start_address),
                CreateRemoteThreadAttr::StartModule => AttrValue::String(&b.start_module),
                CreateRemoteThreadAttr::StartFunction => AttrValue::String(&b.start_function),
                CreateRemoteThreadAttr::SourceUser => AttrValue::String(&b.source_user),
                CreateRemoteThreadAttr::TargetUser => AttrValue::String(&b.target_user),
            }
        }
        RawEventAttrKind::RawAccessRead(attr) => {
            let RawEventBody::RawAccessRead(b) = body else {
                return None;
            };
            match attr {
                RawAccessReadAttr::AgentName => AttrValue::String(&b.agent_name),
                RawAccessReadAttr::AgentId => AttrValue::String(&b.agent_id),
                RawAccessReadAttr::ProcessGuid => AttrValue::String(&b.process_guid),
                RawAccessReadAttr::ProcessId => AttrValue::UInt(b.process_id.into()),
                RawAccessReadAttr::Image => AttrValue::String(&b.image),
                RawAccessReadAttr::Device => AttrValue::String(&b.device),
                RawAccessReadAttr::User => AttrValue::String(&b.user),
            }
        }
        RawEventAttrKind::ProcessAccess(attr) => {
            let RawEventBody::ProcessAccess(b) = body else {
                return None;
            };
            match attr {
                ProcessAccessAttr::AgentName => AttrValue::String(&b.agent_name),
                ProcessAccessAttr::AgentId => AttrValue::String(&b.agent_id),
                ProcessAccessAttr::SourceProcessGuid => AttrValue::String(&b.source_process_guid),
                ProcessAccessAttr::SourceProcessId => AttrValue::UInt(b.source_process_id.into()),
                ProcessAccessAttr::SourceThreadId => AttrValue::UInt(b.source_thread_id.into()),
                ProcessAccessAttr::SourceImage => AttrValue::String(&b.source_image),
                ProcessAccessAttr::TargetProcessGuid => AttrValue::String(&b.target_process_guid),
                ProcessAccessAttr::TargetProcessId => AttrValue::UInt(b.target_process_id.into()),
                ProcessAccessAttr::TargetImage => AttrValue::String(&b.target_image),
                ProcessAccessAttr::GrantedAccess => AttrValue::UInt(b.granted_access),
                ProcessAccessAttr::CallTrace => AttrValue::String(&b.call_trace),
                ProcessAccessAttr::SourceUser => AttrValue::String(&b.source_user),
                ProcessAccessAttr::TargetUser => AttrValue::String(&b.target_user),
            }
        }
        RawEventAttrKind::RegistryObjectAddDel(attr) => {
            let RawEventBody::RegistryObjectAddDel(b) = body else {
                return None;
            };
            match attr {
                RegistryObjectAddDelAttr::AgentName => AttrValue::String(&b.agent_name),
                RegistryObjectAddDelAttr::AgentId => AttrValue::String(&b.agent_id),
                RegistryObjectAddDelAttr::EventType => AttrValue::String(&b.event_type),
                RegistryObjectAddDelAttr::ProcessGuid => AttrValue::String(&b.process_guid),
                RegistryObjectAddDelAttr::ProcessId => AttrValue::UInt(b.process_id.into()),
                RegistryObjectAddDelAttr::Image => AttrValue::String(&b.image),
                RegistryObjectAddDelAttr::TargetObject => AttrValue::String(&b.target_object),
                RegistryObjectAddDelAttr::User => AttrValue::String(&b.user),
            }
        }
        RawEventAttrKind::WindowsEventLog(attr) => {
            let RawEventBody::WindowsEventLog(b) = body else {
                return None;
            };
            match attr {
                WindowsEventLogAttr::Channel => AttrValue::String(b.channel.as_deref()?),
                WindowsEventLogAttr::Provider => AttrValue::String(b.provider.as_deref()?),
                WindowsEventLogAttr::EventId => AttrValue::UInt(b.event_id?.into()),
                WindowsEventLogAttr::Version => AttrValue::UInt(b.version?.into()),
                WindowsEventLogAttr::Level => AttrValue::UInt(b.level?.into()),
                WindowsEventLogAttr::Task => AttrValue::UInt(b.task?.into()),
                WindowsEventLogAttr::Opcode => AttrValue::UInt(b.opcode?.into()),
                WindowsEventLogAttr::Keywords => AttrValue::UInt(b.keywords?),
                WindowsEventLogAttr::RecordId => AttrValue::UInt(b.record_id?),
                WindowsEventLogAttr::Computer => AttrValue::String(b.computer.as_deref()?),
                WindowsEventLogAttr::UserSid => AttrValue::String(b.user_sid.as_deref()?),
                WindowsEventLogAttr::EventData => {
                    list_strings(b.event_data.as_deref(), ListElement::EventData)
                }
                WindowsEventLogAttr::UserDataXml => AttrValue::String(b.user_data_xml.as_deref()?),
            }
        }
        RawEventAttrKind::Journald(attr) => {
            let RawEventBody::Journald(b) = body else {
                return None;
            };
            match attr {
                JournaldAttr::Fields => list_strings(b.fields.as_deref(), ListElement::LogField),
            }
        }
        RawEventAttrKind::Auditd(attr) => {
            let RawEventBody::Auditd(b) = body else {
                return None;
            };
            match attr {
                AuditdAttr::Serial => AttrValue::UInt(b.serial?),
                AuditdAttr::Records => list_strings(b.records.as_deref(), ListElement::AuditRecord),
            }
        }
    };
    Some(value)
}

fn is_matching_list<T, F>(attr_val: &[T], packet_attr: &PacketAttr, compare_fn: F) -> bool
where
    F: Fn(&T, &PacketAttr) -> bool,
{
    match packet_attr.cmp_kind {
        AttrCmpKind::NotEqual | AttrCmpKind::NotContain => {
            attr_val.iter().all(|x| compare_fn(x, packet_attr))
        }
        _ => attr_val.iter().any(|x| compare_fn(x, packet_attr)),
    }
}

/// Returns whether `target_value` meets the comparison of `attr`.
pub(super) fn is_attr_matched(target_value: AttrValue, attr: &PacketAttr) -> bool {
    match target_value {
        AttrValue::Addr(ip_addr) => matches_addr_attr(&ip_addr, attr),
        AttrValue::Bool(bool_val) => matches_bool_attr(bool_val, attr),
        AttrValue::SInt(signed_int_val) => matches_number_attr::<_, i64>(&signed_int_val, attr),
        AttrValue::UInt(unsigned_int_val) => matches_number_attr::<_, u64>(&unsigned_int_val, attr),
        AttrValue::String(str_val) => matches_string_attr(str_val, attr),
        AttrValue::VecAddr(vec_addr_val) => {
            is_matching_list(vec_addr_val.as_ref(), attr, matches_addr_attr)
        }
        AttrValue::VecBool(vec_bool_val) => {
            is_matching_list(vec_bool_val.as_ref(), attr, |val: &bool, attr| {
                matches_bool_attr(*val, attr)
            })
        }
        AttrValue::VecSInt(vec_sint_val) => {
            is_matching_list(vec_sint_val.as_ref(), attr, matches_number_attr::<_, i64>)
        }
        AttrValue::VecUInt(vec_uint_val) => {
            is_matching_list(vec_uint_val.as_ref(), attr, matches_number_attr::<_, u64>)
        }
        AttrValue::VecString(vec_str_val) => {
            is_matching_list(vec_str_val.as_ref(), attr, |val: &String, attr| {
                matches_string_attr(val.as_str(), attr)
            })
        }
        AttrValue::VecRaw(vec_raw_val) => matches_vec_raw_attr(vec_raw_val, attr),
        AttrValue::VecRawList(list) => is_matching_list(list.as_ref(), attr, |val, packet_attr| {
            matches_vec_raw_attr(val, packet_attr)
        }),
    }
}

fn deserialize<'de, T>(value: &'de [u8]) -> Option<T>
where
    T: Deserialize<'de>,
{
    bincode::DefaultOptions::new().deserialize::<T>(value).ok()
}

fn check_second_value<'de, T, K>(kind: AttrCmpKind, value: Option<&'de Vec<u8>>) -> Option<T>
where
    T: TryFrom<K> + std::cmp::PartialOrd,
    K: Deserialize<'de>,
{
    match kind {
        AttrCmpKind::OpenRange
        | AttrCmpKind::CloseRange
        | AttrCmpKind::LeftOpenRange
        | AttrCmpKind::RightOpenRange
        | AttrCmpKind::NotOpenRange
        | AttrCmpKind::NotCloseRange
        | AttrCmpKind::NotLeftOpenRange
        | AttrCmpKind::NotRightOpenRange => {
            let value = value.as_ref()?;
            let de_second_value: K = deserialize(value)?;
            T::try_from(de_second_value).ok()
        }
        _ => None,
    }
}

fn matches_attr<T>(
    cmp_kind: AttrCmpKind,
    attr_val: &T,
    first_val: &T,
    second_val: Option<T>,
) -> bool
where
    T: PartialOrd,
{
    match (cmp_kind, second_val) {
        (AttrCmpKind::Less, _) => attr_val < first_val,
        (AttrCmpKind::LessOrEqual, _) => attr_val <= first_val,
        (AttrCmpKind::Equal, _) => attr_val == first_val,
        (AttrCmpKind::NotEqual, _) => attr_val != first_val,
        (AttrCmpKind::Greater, _) => attr_val > first_val,
        (AttrCmpKind::GreaterOrEqual, _) => attr_val >= first_val,
        (AttrCmpKind::OpenRange, Some(second_val)) => {
            (first_val < attr_val) && (second_val > *attr_val)
        }
        (AttrCmpKind::CloseRange, Some(second_val)) => {
            (first_val <= attr_val) && (second_val >= *attr_val)
        }
        (AttrCmpKind::LeftOpenRange, Some(second_val)) => {
            (first_val < attr_val) && (second_val >= *attr_val)
        }
        (AttrCmpKind::RightOpenRange, Some(second_val)) => {
            (first_val <= attr_val) && (second_val > *attr_val)
        }
        (AttrCmpKind::NotOpenRange, Some(second_val)) => {
            !((first_val < attr_val) && (second_val > *attr_val))
        }
        (AttrCmpKind::NotCloseRange, Some(second_val)) => {
            !((first_val <= attr_val) && (second_val >= *attr_val))
        }
        (AttrCmpKind::NotLeftOpenRange, Some(second_val)) => {
            !((first_val < attr_val) && (second_val >= *attr_val))
        }
        (AttrCmpKind::NotRightOpenRange, Some(second_val)) => {
            !((first_val <= attr_val) && (second_val > *attr_val))
        }
        _ => false,
    }
}

fn matches_bool_attr(attr_val: bool, packet_attr: &PacketAttr) -> bool {
    deserialize::<bool>(&packet_attr.first_value).is_some_and(|compare_val| {
        match packet_attr.cmp_kind {
            AttrCmpKind::Equal => attr_val == compare_val,
            AttrCmpKind::NotEqual => attr_val != compare_val,
            _ => false,
        }
    })
}

fn matches_string_attr(attr_val: &str, packet_attr: &PacketAttr) -> bool {
    deserialize::<String>(&packet_attr.first_value).is_some_and(|compare_val| {
        let cmp_result = attr_val.contains(&compare_val);
        match packet_attr.cmp_kind {
            AttrCmpKind::Contain => cmp_result,
            AttrCmpKind::NotContain => !cmp_result,
            _ => false,
        }
    })
}

fn matches_addr_attr(attr_val: &IpAddr, packet_attr: &PacketAttr) -> bool {
    if let Some(first_val) = deserialize::<IpAddr>(&packet_attr.first_value) {
        let second_val = packet_attr
            .second_value
            .as_ref()
            .and_then(|serde_val| deserialize::<IpAddr>(serde_val));
        return matches_attr(packet_attr.cmp_kind, attr_val, &first_val, second_val);
    }
    false
}

fn matches_number_attr<T, K>(attr_val: &T, packet_attr: &PacketAttr) -> bool
where
    T: TryFrom<K> + PartialOrd,
    K: for<'de> Deserialize<'de>,
{
    if let Some(first_val) = deserialize::<K>(&packet_attr.first_value)
        && let Ok(first_val) = T::try_from(first_val)
    {
        let second_val =
            check_second_value::<T, K>(packet_attr.cmp_kind, packet_attr.second_value.as_ref());
        return matches_attr(packet_attr.cmp_kind, attr_val, &first_val, second_val);
    }
    false
}

fn matches_vec_raw_attr(attr_val: &[u8], packet_attr: &PacketAttr) -> bool {
    match packet_attr.value_kind {
        ValueKind::String => {
            deserialize::<String>(&packet_attr.first_value).is_some_and(|compare_val| {
                matches_byte_attr(packet_attr.cmp_kind, attr_val, compare_val.as_bytes())
            })
        }
        ValueKind::Vector => {
            matches_byte_attr(packet_attr.cmp_kind, attr_val, &packet_attr.first_value)
        }
        _ => false,
    }
}

fn matches_byte_attr(cmp_kind: AttrCmpKind, target_val: &[u8], compare_val: &[u8]) -> bool {
    let cmp_result = memchr::memmem::find(target_val, compare_val);
    match cmp_kind {
        AttrCmpKind::Contain => cmp_result.is_some(),
        AttrCmpKind::NotContain => cmp_result.is_none(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, fmt::Display, net::IpAddr};

    use attrievent::attribute::{
        AuditdAttr, ConnAttr, CreateRemoteThreadAttr, DhcpAttr, DnsAttr, DriverLoadAttr, HttpAttr,
        JournaldAttr, Netflow5Attr, Netflow9Attr, NetworkConnectAttr, ProcessAccessAttr,
        ProcessCreateAttr, RawAccessReadAttr, RawEventAttrKind, RegistryObjectAddDelAttr, TlsAttr,
        WindowsEventLogAttr,
    };
    use bincode::Options;
    use review_protocol::types::{
        DetectionModel, EndpointRole::Destination, RawEventBody, RawEventKind, raw_event,
    };
    use serde::Serialize;
    use strum::IntoEnumIterator;

    use super::{AttrValue, ListElement, attr_value, is_attr_matched, list_element_string};
    use crate::{
        AttrCmpKind, EventCategory, PacketAttr, Response, ResponseKind, ScoreCondition,
        TriagePolicyInput, ValueKind,
        event::{
            StoredDetectionEvent,
            fixture::{
                SENSOR, auditd_body, bytes_field, conn_body, create_remote_thread_body, dns_body,
                driver_load_body, endpoint_sensor, header_bodies, host, http_body, ip,
                journald_body, kind_of, netflow5_body, netflow9_body, network_connect_body,
                process_access_body, process_create_body, raw_access_read_body, raw_event_event,
                registry_object_add_del_body, related, stored, subject_event, text_field, time,
                windows_event_log_body,
            },
        },
    };

    fn serialize<T: Serialize>(value: &T) -> Vec<u8> {
        bincode::DefaultOptions::new()
            .serialize(value)
            .expect("serializable")
    }

    fn attr(
        kind: RawEventKind,
        name: impl Display,
        value_kind: ValueKind,
        cmp_kind: AttrCmpKind,
        first_value: Vec<u8>,
        weight: Option<f64>,
    ) -> PacketAttr {
        PacketAttr {
            raw_event_kind: kind,
            attr_name: name.to_string(),
            value_kind,
            cmp_kind,
            first_value,
            second_value: None,
            weight,
        }
    }

    fn addr_equal(kind: RawEventKind, name: impl Display, addr: &str, weight: f64) -> PacketAttr {
        attr(
            kind,
            name,
            ValueKind::IpAddr,
            AttrCmpKind::Equal,
            serialize(&ip(addr)),
            Some(weight),
        )
    }

    fn policy(
        id: u32,
        packet_attr: Vec<PacketAttr>,
        score: Vec<ScoreCondition>,
        minimum_score: f64,
    ) -> TriagePolicyInput {
        TriagePolicyInput {
            id,
            name: format!("policy-{id}"),
            creation_time: time(),
            packet_attr,
            score,
            response: vec![Response {
                minimum_score,
                kind: ResponseKind::Manual,
            }],
        }
    }

    /// Returns the score `policy` gives `record`, whatever its responses.
    fn score_of(record: &StoredDetectionEvent, mut policy: TriagePolicyInput) -> f64 {
        policy.response = vec![Response {
            minimum_score: f64::MIN,
            kind: ResponseKind::Manual,
        }];
        let scores = record.score_against_policies(&[policy]);
        assert_eq!(scores.len(), 1);
        scores[0].score
    }

    fn assert_score(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() < 1e-9,
            "score {actual}, expected {expected}"
        );
    }

    fn on(body: RawEventBody) -> StoredDetectionEvent {
        stored(raw_event_event(time(), SENSOR, body))
    }

    fn condition(
        category: Option<EventCategory>,
        model: DetectionModel,
        score: f64,
        weight: Option<f64>,
    ) -> ScoreCondition {
        ScoreCondition {
            threat_category: category,
            detection_model: model,
            score,
            weight,
        }
    }

    #[test]
    fn score_conditions_require_category_model_and_score_threshold() {
        // The record is NonBrowser, CommandAndControl, scoring 0.75.
        let record = on(conn_body(ip("192.0.2.1"), ip("198.51.100.1")));
        let c2 = Some(EventCategory::CommandAndControl);
        let model = DetectionModel::NonBrowser;
        let score = |conditions| score_of(&record, policy(1, Vec::new(), conditions, 0.0));

        assert_score(score(vec![condition(c2, model, 0.5, Some(2.0))]), 2.0);
        // The threshold is inclusive and exact.
        assert_score(score(vec![condition(c2, model, 0.75, Some(2.0))]), 2.0);
        assert_score(
            score(vec![condition(c2, model, 0.750_000_1, Some(2.0))]),
            0.0,
        );
        // Another category, no category, or another model adds nothing.
        assert_score(
            score(vec![condition(
                Some(EventCategory::Impact),
                model,
                0.5,
                None,
            )]),
            0.0,
        );
        assert_score(score(vec![condition(None, model, 0.5, None)]), 0.0);
        assert_score(
            score(vec![condition(c2, DetectionModel::PortScan, 0.5, None)]),
            0.0,
        );
        // The default weight is 1.0, and weights add up.
        assert_score(score(vec![condition(c2, model, 0.5, None)]), 1.0);
        assert_score(
            score(vec![
                condition(c2, model, 0.5, None),
                condition(c2, model, 0.1, Some(0.25)),
                condition(c2, model, 0.9, Some(5.0)),
            ]),
            1.25,
        );

        // A `None` category condition matches an event with no category.
        let mut uncategorized = raw_event_event(
            time(),
            SENSOR,
            conn_body(ip("192.0.2.1"), ip("198.51.100.1")),
        );
        uncategorized.category = None;
        let uncategorized = stored(uncategorized);
        assert_score(
            score_of(
                &uncategorized,
                policy(1, Vec::new(), vec![condition(None, model, 0.5, None)], 0.0),
            ),
            1.0,
        );
        assert_score(
            score_of(
                &uncategorized,
                policy(1, Vec::new(), vec![condition(c2, model, 0.5, None)], 0.0),
            ),
            0.0,
        );
    }

    #[test]
    fn a_policy_qualifies_when_its_score_reaches_a_response() {
        let record = on(conn_body(ip("192.0.2.1"), ip("198.51.100.1")));
        let conditions = vec![condition(
            Some(EventCategory::CommandAndControl),
            DetectionModel::NonBrowser,
            0.5,
            Some(1.5),
        )];
        let attrs = vec![addr_equal(
            RawEventKind::Conn,
            ConnAttr::SrcAddr,
            "192.0.2.1",
            0.5,
        )];

        let reached = policy(1, attrs.clone(), conditions.clone(), 2.0);
        let missed = policy(2, attrs.clone(), conditions.clone(), 2.01);
        let mut no_response = policy(3, attrs.clone(), conditions.clone(), 0.0);
        no_response.response.clear();
        let mut any_response = policy(4, attrs, conditions, 9.0);
        any_response.response.push(Response {
            minimum_score: 1.0,
            kind: ResponseKind::Watchlist,
        });

        let scores = record.score_against_policies(&[reached, missed, no_response, any_response]);
        let ids: Vec<_> = scores.iter().map(|score| score.policy_id).collect();
        assert_eq!(ids, [1, 4]);
        for score in &scores {
            assert_score(score.score, 2.0);
        }
        assert_eq!(scores[0].to_string(), "1:2.00");
    }

    #[test]
    fn packet_attr_matches_network_bodies() {
        let conn = on(conn_body(ip("192.0.2.1"), ip("198.51.100.1")));
        let mut close_range = attr(
            RawEventKind::Conn,
            ConnAttr::SrcAddr,
            ValueKind::IpAddr,
            AttrCmpKind::CloseRange,
            serialize(&ip("192.0.2.0")),
            Some(0.1),
        );
        close_range.second_value = Some(serialize(&ip("192.0.2.1")));
        let service = attr(
            RawEventKind::Conn,
            ConnAttr::Service,
            ValueKind::String,
            AttrCmpKind::Contain,
            serialize(&"htt"),
            Some(0.2),
        );
        let resp_port = attr(
            RawEventKind::Conn,
            ConnAttr::DstPort,
            ValueKind::UInteger,
            AttrCmpKind::Equal,
            serialize(&80_u64),
            Some(0.4),
        );
        let missed = attr(
            RawEventKind::Conn,
            ConnAttr::DstPort,
            ValueKind::UInteger,
            AttrCmpKind::Greater,
            serialize(&80_u64),
            Some(8.0),
        );
        assert_score(
            score_of(
                &conn,
                policy(
                    1,
                    vec![close_range, service, resp_port, missed],
                    Vec::new(),
                    0.0,
                ),
            ),
            0.7,
        );

        let http = on(http_body(ip("192.0.2.1"), ip("198.51.100.1")));
        let uri = attr(
            RawEventKind::Http,
            HttpAttr::Uri,
            ValueKind::String,
            AttrCmpKind::Contain,
            serialize(&"index"),
            Some(0.5),
        );
        let body = attr(
            RawEventKind::Http,
            HttpAttr::Body,
            ValueKind::Vector,
            AttrCmpKind::Contain,
            b"body".to_vec(),
            Some(0.25),
        );
        let mime = attr(
            RawEventKind::Http,
            HttpAttr::MimeTypes,
            ValueKind::String,
            AttrCmpKind::NotContain,
            serialize(&"image"),
            Some(0.125),
        );
        // 0.875 truncates to two decimals.
        assert_score(
            score_of(&http, policy(1, vec![uri, body, mime], Vec::new(), 0.0)),
            0.87,
        );

        let dns = on(dns_body(ip("192.0.2.1"), ip("198.51.100.1")));
        let ttl = attr(
            RawEventKind::Dns,
            DnsAttr::Ttl,
            ValueKind::Integer,
            AttrCmpKind::GreaterOrEqual,
            serialize(&120_i64),
            Some(1.0),
        );
        let rd = attr(
            RawEventKind::Dns,
            DnsAttr::RD,
            ValueKind::Bool,
            AttrCmpKind::Equal,
            serialize(&true),
            Some(1.0),
        );
        assert_score(
            score_of(&dns, policy(1, vec![ttl, rd], Vec::new(), 0.0)),
            2.0,
        );
    }

    #[test]
    fn packet_attr_matches_netflow_bodies() {
        let netflow5 = on(netflow5_body(ip("192.0.2.1"), ip("198.51.100.1")));
        let attrs = vec![
            addr_equal(
                RawEventKind::Netflow5,
                Netflow5Attr::SrcAddr,
                "192.0.2.1",
                1.0,
            ),
            addr_equal(
                RawEventKind::Netflow5,
                Netflow5Attr::DstAddr,
                "198.51.100.1",
                2.0,
            ),
            attr(
                RawEventKind::Netflow5,
                Netflow5Attr::DOctets,
                ValueKind::UInteger,
                AttrCmpKind::Greater,
                serialize(&1000_u64),
                Some(4.0),
            ),
        ];
        assert_score(score_of(&netflow5, policy(1, attrs, Vec::new(), 0.0)), 7.0);

        let netflow9 = on(netflow9_body(ip("192.0.2.1"), ip("198.51.100.1")));
        let attrs = vec![
            addr_equal(
                RawEventKind::Netflow9,
                Netflow9Attr::SrcAddr,
                "192.0.2.1",
                1.0,
            ),
            attr(
                RawEventKind::Netflow9,
                Netflow9Attr::Contents,
                ValueKind::String,
                AttrCmpKind::Contain,
                serialize(&"synthetic"),
                Some(2.0),
            ),
        ];
        assert_score(score_of(&netflow9, policy(1, attrs, Vec::new(), 0.0)), 3.0);
    }

    #[test]
    fn packet_attr_reads_sysmon_fields_outside_the_endpoint_addresses() {
        let sysmon = on(network_connect_body(ip("192.0.2.1"), ip("198.51.100.1")));
        // The record contributes no address bucket.
        let mut addrs = std::collections::HashMap::new();
        let filter = crate::event::EventFilter::new(
            None, None, None, None, None, None, None, None, None, None, None, None, None,
        );
        sysmon.count_ip_address(&mut addrs, &filter).unwrap();
        assert!(addrs.is_empty());

        let attrs = vec![
            addr_equal(
                RawEventKind::NetworkConnect,
                NetworkConnectAttr::SourceIp,
                "192.0.2.1",
                1.0,
            ),
            addr_equal(
                RawEventKind::NetworkConnect,
                NetworkConnectAttr::DestinationIp,
                "198.51.100.1",
                2.0,
            ),
            attr(
                RawEventKind::NetworkConnect,
                NetworkConnectAttr::Initiated,
                ValueKind::Bool,
                AttrCmpKind::Equal,
                serialize(&true),
                Some(4.0),
            ),
            attr(
                RawEventKind::NetworkConnect,
                NetworkConnectAttr::DestinationPort,
                ValueKind::UInteger,
                AttrCmpKind::Equal,
                serialize(&443_u64),
                Some(8.0),
            ),
        ];
        assert_score(score_of(&sysmon, policy(1, attrs, Vec::new(), 0.0)), 15.0);
    }

    #[test]
    fn packet_attr_never_matches_another_kind_an_unknown_name_or_a_subject() {
        let conn = on(conn_body(ip("192.0.2.1"), ip("198.51.100.1")));
        let http_src = addr_equal(RawEventKind::Http, HttpAttr::SrcAddr, "192.0.2.1", 1.0);
        let unknown = addr_equal(RawEventKind::Conn, "No Such Attribute", "192.0.2.1", 1.0);
        // "Query" names a DNS attribute, not a conn one.
        let other_kind_name = attr(
            RawEventKind::Conn,
            DnsAttr::Query,
            ValueKind::String,
            AttrCmpKind::Contain,
            serialize(&""),
            Some(1.0),
        );
        assert_score(
            score_of(
                &conn,
                policy(1, vec![http_src, unknown, other_kind_name], Vec::new(), 0.0),
            ),
            0.0,
        );

        // A body of another kind than the header's never matches either.
        let mut mismatched = raw_event_event(
            time(),
            SENSOR,
            conn_body(ip("192.0.2.1"), ip("198.51.100.1")),
        );
        mismatched.raw_event_kind = RawEventKind::Http;
        let mismatched = stored(mismatched);
        assert_score(
            score_of(
                &mismatched,
                policy(
                    1,
                    vec![
                        addr_equal(RawEventKind::Http, HttpAttr::SrcAddr, "192.0.2.1", 1.0),
                        addr_equal(RawEventKind::Conn, ConnAttr::SrcAddr, "192.0.2.1", 1.0),
                    ],
                    Vec::new(),
                    0.0,
                ),
            ),
            0.0,
        );

        // A subject target, whatever its addresses, never matches.
        let subject = stored(subject_event(
            host("192.0.2.1"),
            vec![related("198.51.100.1", Destination)],
        ));
        assert_score(
            score_of(
                &subject,
                policy(
                    1,
                    vec![
                        addr_equal(RawEventKind::Conn, ConnAttr::SrcAddr, "192.0.2.1", 1.0),
                        addr_equal(RawEventKind::Conn, ConnAttr::DstAddr, "198.51.100.1", 1.0),
                    ],
                    Vec::new(),
                    0.0,
                ),
            ),
            0.0,
        );
    }

    #[test]
    fn packet_attr_weight_defaults_to_zero() {
        let conn = on(conn_body(ip("192.0.2.1"), ip("198.51.100.1")));
        let mut unweighted = addr_equal(RawEventKind::Conn, ConnAttr::SrcAddr, "192.0.2.1", 0.0);
        unweighted.weight = None;
        let record_score = score_of(&conn, policy(1, vec![unweighted.clone()], Vec::new(), 0.0));
        assert_score(record_score, 0.0);
        // It still qualifies a policy whose minimum is zero, as any score does.
        assert_eq!(
            conn.score_against_policies(&[policy(1, vec![unweighted], Vec::new(), 0.0)])
                .len(),
            1
        );
    }

    #[test]
    fn watchlist_and_exclusion_list_responses_qualify_like_manual() {
        let conn = on(conn_body(ip("192.0.2.1"), ip("198.51.100.1")));
        let attrs = vec![addr_equal(
            RawEventKind::Conn,
            ConnAttr::SrcAddr,
            "192.0.2.1",
            0.5,
        )];
        let conditions = vec![condition(
            Some(EventCategory::CommandAndControl),
            DetectionModel::NonBrowser,
            0.5,
            None,
        )];
        let with_kind = |id, minimum_score, kind| {
            let mut input = policy(id, attrs.clone(), conditions.clone(), minimum_score);
            input.response = vec![Response {
                minimum_score,
                kind,
            }];
            input
        };

        // Each kind qualifies at the policy's score and not above it.
        let policies = [
            with_kind(1, 1.5, ResponseKind::Manual),
            with_kind(2, 1.5, ResponseKind::Watchlist),
            with_kind(3, 1.5, ResponseKind::ExclusionList),
            with_kind(4, 1.51, ResponseKind::Manual),
            with_kind(5, 1.51, ResponseKind::Watchlist),
            with_kind(6, 1.51, ResponseKind::ExclusionList),
        ];
        let scores = conn.score_against_policies(&policies);
        let ids: Vec<_> = scores.iter().map(|score| score.policy_id).collect();
        assert_eq!(ids, [1, 2, 3]);
        for score in &scores {
            assert_score(score.score, 1.5);
        }

        // Mixed kinds in one policy qualify when any one is reached.
        let mut mixed = with_kind(7, 9.0, ResponseKind::Watchlist);
        mixed.response.push(Response {
            minimum_score: 1.0,
            kind: ResponseKind::ExclusionList,
        });
        mixed.response.push(Response {
            minimum_score: 8.0,
            kind: ResponseKind::Manual,
        });
        let scores = conn.score_against_policies(&[mixed]);
        assert_eq!(scores.len(), 1);
        assert_score(scores[0].score, 1.5);
    }

    #[test]
    fn response_kind_keeps_its_stored_positions() {
        // `Watchlist` and `ExclusionList` take the variant indexes the
        // previous names held, so stored responses decode unchanged.
        for (kind, index) in [
            (ResponseKind::Manual, 0_u32),
            (ResponseKind::Watchlist, 1),
            (ResponseKind::ExclusionList, 2),
        ] {
            let bytes = bincode::serialize(&kind).unwrap();
            assert_eq!(bytes, index.to_le_bytes());
            let back: ResponseKind = bincode::deserialize(&bytes).unwrap();
            assert!(back == kind);
        }
    }

    /// Every attribute of a kind attrievent names resolves and reads a value
    /// from a body of that kind, and none from a body of another kind.
    #[test]
    fn every_attribute_of_the_fixture_kinds_reads_its_body() {
        fn check<A: IntoEnumIterator + Display>(kind: RawEventKind, body: &RawEventBody) {
            for attr in A::iter() {
                let name = attr.to_string();
                let parsed = RawEventAttrKind::from_kind_and_attr_name(&kind, &name)
                    .unwrap_or_else(|e| panic!("{kind:?} {name}: {e}"));
                assert!(attr_value(body, parsed).is_some(), "{kind:?} {name}");
                let other = RawEventAttrKind::from_kind_and_attr_name(&kind, &name).unwrap();
                let other_body = if kind == RawEventKind::Conn {
                    dns_body(ip("192.0.2.1"), ip("198.51.100.1"))
                } else {
                    conn_body(ip("192.0.2.1"), ip("198.51.100.1"))
                };
                assert!(attr_value(&other_body, other).is_none(), "{kind:?} {name}");
            }
        }

        let (orig, resp) = (ip("192.0.2.1"), ip("198.51.100.1"));
        check::<ConnAttr>(RawEventKind::Conn, &conn_body(orig, resp));
        check::<DnsAttr>(RawEventKind::Dns, &dns_body(orig, resp));
        check::<HttpAttr>(RawEventKind::Http, &http_body(orig, resp));
        check::<Netflow5Attr>(RawEventKind::Netflow5, &netflow5_body(orig, resp));
        check::<Netflow9Attr>(RawEventKind::Netflow9, &netflow9_body(orig, resp));
        check::<NetworkConnectAttr>(
            RawEventKind::NetworkConnect,
            &network_connect_body(orig, resp),
        );
    }

    #[test]
    fn tls_alpn_protocol_reads_the_alpn_protocol_field() {
        let body = RawEventBody::Tls(raw_event::Tls {
            orig_addr: ip("192.0.2.1"),
            orig_port: 50000,
            resp_addr: ip("198.51.100.1"),
            resp_port: 443,
            proto: 6,
            start_time: 0,
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            server_name: "server.example".to_string(),
            alpn_protocol: "h2".to_string(),
            ja3: String::new(),
            version: "TLSv1.3".to_string(),
            client_cipher_suites: vec![4865],
            client_extensions: Vec::new(),
            cipher: 4865,
            extensions: Vec::new(),
            ja3s: String::new(),
            serial: String::new(),
            subject_country: String::new(),
            subject_org_name: String::new(),
            subject_common_name: String::new(),
            validity_not_before: 0,
            validity_not_after: 0,
            subject_alt_name: String::new(),
            issuer_country: String::new(),
            issuer_org_name: String::new(),
            issuer_org_unit_name: String::new(),
            issuer_common_name: String::new(),
            last_alert: 0,
        });
        let Some(AttrValue::String(alpn)) =
            attr_value(&body, RawEventAttrKind::Tls(TlsAttr::AlpnProtocol))
        else {
            panic!("ALPN protocol is a string");
        };
        assert_eq!(alpn, "h2");
    }

    #[test]
    fn list_attributes_follow_the_list_comparison_rules() {
        let strings = vec!["alpha".to_string(), "beta".to_string()];
        let string_attr = |cmp_kind, value: &str| {
            attr(
                RawEventKind::Http,
                HttpAttr::MimeTypes,
                ValueKind::String,
                cmp_kind,
                serialize(&value),
                None,
            )
        };
        let borrowed = || AttrValue::VecString(Cow::Borrowed(&strings));
        assert!(is_attr_matched(
            borrowed(),
            &string_attr(AttrCmpKind::Contain, "beta")
        ));
        assert!(!is_attr_matched(
            borrowed(),
            &string_attr(AttrCmpKind::Contain, "gamma")
        ));
        // A negated comparison must hold for every element.
        assert!(is_attr_matched(
            borrowed(),
            &string_attr(AttrCmpKind::NotContain, "gamma")
        ));
        assert!(!is_attr_matched(
            borrowed(),
            &string_attr(AttrCmpKind::NotContain, "beta")
        ));

        let ports = || AttrValue::VecUInt(Cow::Owned(vec![100, 200]));
        let port_attr = |cmp_kind, value: u64| {
            attr(
                RawEventKind::Conn,
                ConnAttr::DstPort,
                ValueKind::UInteger,
                cmp_kind,
                serialize(&value),
                None,
            )
        };
        assert!(is_attr_matched(
            ports(),
            &port_attr(AttrCmpKind::Equal, 200)
        ));
        assert!(is_attr_matched(
            ports(),
            &port_attr(AttrCmpKind::NotEqual, 300)
        ));
        assert!(!is_attr_matched(
            ports(),
            &port_attr(AttrCmpKind::NotEqual, 200)
        ));

        let mut range = port_attr(AttrCmpKind::OpenRange, 100);
        range.second_value = Some(serialize(&200_u64));
        assert!(!is_attr_matched(AttrValue::UInt(100), &range));
        assert!(is_attr_matched(AttrValue::UInt(150), &range));
        range.cmp_kind = AttrCmpKind::CloseRange;
        assert!(is_attr_matched(AttrValue::UInt(100), &range));
        assert!(is_attr_matched(AttrValue::UInt(200), &range));
        range.cmp_kind = AttrCmpKind::NotCloseRange;
        assert!(is_attr_matched(AttrValue::UInt(201), &range));
        // A range without its second value never matches.
        range.second_value = None;
        assert!(!is_attr_matched(AttrValue::UInt(150), &range));
    }

    #[test]
    fn raw_byte_attributes_compare_as_strings_or_byte_vectors() {
        let options: Vec<Vec<u8>> = vec![vec![1], vec![0x01, 0x02, 0x03]];
        let slices: Vec<&[u8]> = options.iter().map(Vec::as_slice).collect();
        let data_attr = |value_kind, cmp_kind, first_value| {
            attr(
                RawEventKind::Dhcp,
                DhcpAttr::OptionData,
                value_kind,
                cmp_kind,
                first_value,
                None,
            )
        };
        let list = || AttrValue::VecRawList(Cow::Borrowed(&slices));
        assert!(is_attr_matched(
            list(),
            &data_attr(ValueKind::Vector, AttrCmpKind::Contain, vec![0x02, 0x03])
        ));
        assert!(is_attr_matched(
            list(),
            &data_attr(ValueKind::Vector, AttrCmpKind::NotContain, vec![0xff])
        ));
        assert!(!is_attr_matched(
            list(),
            &data_attr(ValueKind::Vector, AttrCmpKind::NotContain, vec![0x01])
        ));

        let raw = AttrValue::VecRaw(b"synthetic payload");
        assert!(is_attr_matched(
            raw,
            &data_attr(
                ValueKind::String,
                AttrCmpKind::Contain,
                serialize(&"payload")
            )
        ));
        // Any other value kind never matches raw bytes.
        assert!(!is_attr_matched(
            AttrValue::VecRaw(b"synthetic payload"),
            &data_attr(ValueKind::UInteger, AttrCmpKind::Contain, serialize(&1_u64))
        ));
    }

    #[test]
    fn ftp_and_dcerpc_lists_read_nothing_when_empty() {
        let ftp = RawEventBody::Ftp(raw_event::Ftp {
            orig_addr: ip("192.0.2.1"),
            orig_port: 50000,
            resp_addr: ip("198.51.100.1"),
            resp_port: 21,
            proto: 6,
            start_time: 0,
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            user: "anonymous".to_string(),
            password: "synthetic".to_string(),
            commands: Vec::new(),
        });
        assert!(
            attr_value(
                &ftp,
                RawEventAttrKind::Ftp(attrievent::attribute::FtpAttr::Command)
            )
            .is_none()
        );
        assert!(matches!(
            attr_value(
                &ftp,
                RawEventAttrKind::Ftp(attrievent::attribute::FtpAttr::User)
            ),
            Some(AttrValue::String("anonymous"))
        ));
    }

    #[test]
    fn format_dce_uuid_produces_canonical_text() {
        // Wire bytes for UUID 12345678-1234-5678-1234-56789abcdef0 in DCE/RPC layout.
        let wire = [
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0,
        ];
        assert_eq!(
            super::format_dce_uuid(u128::from_be_bytes(wire)),
            "12345678-1234-5678-1234-56789abcdef0"
        );
    }

    #[test]
    fn collect_request_part_splits_and_rejects_malformed_entries() {
        let request = vec!["0:1".to_string(), "2:3".to_string()];
        assert_eq!(
            super::collect_request_part(&request, true),
            Some(vec![0, 2])
        );
        assert_eq!(
            super::collect_request_part(&request, false),
            Some(vec![1, 3])
        );
        let malformed = vec!["0:1".to_string(), "invalid".to_string()];
        assert_eq!(super::collect_request_part(&malformed, true), None);
        assert_eq!(super::collect_request_part(&[], true), None);
    }

    #[test]
    fn addresses_compare_by_value() {
        let addr: IpAddr = ip("192.0.2.1");
        let equal = addr_equal(RawEventKind::Conn, ConnAttr::SrcAddr, "192.0.2.1", 1.0);
        assert!(is_attr_matched(AttrValue::Addr(addr), &equal));
        assert!(!is_attr_matched(AttrValue::Addr(ip("192.0.2.2")), &equal));
    }

    /// Returns `value` as text: a scalar as it prints, a list as its
    /// elements joined by `|`.
    fn text(value: AttrValue<'_>) -> String {
        fn join<T: ToString>(items: &[T]) -> String {
            items
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("|")
        }
        match value {
            AttrValue::Addr(addr) => addr.to_string(),
            AttrValue::Bool(value) => value.to_string(),
            AttrValue::SInt(value) => value.to_string(),
            AttrValue::UInt(value) => value.to_string(),
            AttrValue::String(value) => value.to_string(),
            AttrValue::VecAddr(items) => join(&items),
            AttrValue::VecBool(items) => join(&items),
            AttrValue::VecSInt(items) => join(&items),
            AttrValue::VecUInt(items) => join(&items),
            AttrValue::VecString(items) => join(&items),
            AttrValue::VecRaw(bytes) => format!("{bytes:?}"),
            AttrValue::VecRawList(items) => format!("{items:?}"),
        }
    }

    /// Asserts that each attribute of `A` reads, from `body` of `kind`, the
    /// text `expected` gives for it, and that `expected` names every
    /// attribute of `A`.
    fn check_values<A>(kind: RawEventKind, body: &RawEventBody, expected: &[(A, &str)])
    where
        A: IntoEnumIterator + Display + PartialEq,
    {
        for attr in A::iter() {
            let name = attr.to_string();
            let (_, want) = expected
                .iter()
                .find(|(listed, _)| *listed == attr)
                .unwrap_or_else(|| panic!("{kind:?} {name} has no expected value"));
            let parsed = RawEventAttrKind::from_kind_and_attr_name(&kind, &name)
                .unwrap_or_else(|e| panic!("{kind:?} {name}: {e}"));
            let value = attr_value(body, parsed).unwrap_or_else(|| panic!("{kind:?} {name}"));
            assert_eq!(text(value), *want, "{kind:?} {name}");
        }
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn each_attribute_of_the_endpoint_kinds_reads_its_field() {
        use CreateRemoteThreadAttr as Crt;
        use DriverLoadAttr as Dl;
        use ProcessAccessAttr as Pa;
        use ProcessCreateAttr as Pc;
        use RawAccessReadAttr as Rar;
        use RegistryObjectAddDelAttr as Roa;
        use WindowsEventLogAttr as Wel;
        check_values(
            RawEventKind::ProcessCreate,
            &RawEventBody::ProcessCreate(process_create_body(Some(0x1_0000_0001))),
            &[
                (Pc::AgentName, "agent"),
                (Pc::AgentId, "agent-id"),
                (Pc::ProcessGuid, "{process}"),
                (Pc::ProcessId, "100"),
                (Pc::Image, "C:\\synthetic.exe"),
                (Pc::FileVersion, "1.0"),
                (Pc::Description, "synthetic"),
                (Pc::Product, "product"),
                (Pc::Company, "company"),
                (Pc::OriginalFileName, "synthetic.exe"),
                (Pc::CommandLine, "synthetic.exe /run"),
                (Pc::CurrentDirectory, "C:\\"),
                (Pc::User, "user"),
                (Pc::LogonGuid, "{logon}"),
                (Pc::LogonId, "4294967295"),
                (Pc::TerminalSessionId, "1"),
                (Pc::IntegrityLevel, "High"),
                (Pc::Hashes, "SHA256=00"),
                (Pc::ParentProcessGuid, "{parent}"),
                (Pc::ParentProcessId, "99"),
                (Pc::ParentImage, "C:\\parent.exe"),
                (Pc::ParentCommandLine, "parent.exe"),
                (Pc::ParentUser, "user"),
                (Pc::LogonIdFull, "4294967297"),
            ],
        );
        check_values(
            RawEventKind::DriverLoad,
            &RawEventBody::DriverLoad(driver_load_body()),
            &[
                (Dl::AgentName, "agent"),
                (Dl::AgentId, "agent-id"),
                (Dl::ImageLoaded, "C:\\driver.sys"),
                (Dl::Hashes, "SHA256=01|MD5=02"),
                (Dl::Signed, "true"),
                (Dl::Signature, "Vendor"),
                (Dl::SignatureStatus, "Valid"),
            ],
        );
        check_values(
            RawEventKind::CreateRemoteThread,
            &RawEventBody::CreateRemoteThread(create_remote_thread_body()),
            &[
                (Crt::AgentName, "agent"),
                (Crt::AgentId, "agent-id"),
                (Crt::SourceProcessGuid, "{source}"),
                (Crt::SourceProcessId, "11"),
                (Crt::SourceImage, "C:\\source.exe"),
                (Crt::TargetProcessGuid, "{target}"),
                (Crt::TargetProcessId, "12"),
                (Crt::TargetImage, "C:\\target.exe"),
                (Crt::NewThreadId, "13"),
                (Crt::StartAddress, "0x7ff0"),
                (Crt::StartModule, "kernel32.dll"),
                (Crt::StartFunction, "LoadLibraryW"),
                (Crt::SourceUser, "source-user"),
                (Crt::TargetUser, "target-user"),
            ],
        );
        check_values(
            RawEventKind::RawAccessRead,
            &RawEventBody::RawAccessRead(raw_access_read_body()),
            &[
                (Rar::AgentName, "agent"),
                (Rar::AgentId, "agent-id"),
                (Rar::ProcessGuid, "{process}"),
                (Rar::ProcessId, "21"),
                (Rar::Image, "C:\\reader.exe"),
                (Rar::Device, "\\Device\\HarddiskVolume2"),
                (Rar::User, "user"),
            ],
        );
        check_values(
            RawEventKind::ProcessAccess,
            &RawEventBody::ProcessAccess(process_access_body()),
            &[
                (Pa::AgentName, "agent"),
                (Pa::AgentId, "agent-id"),
                (Pa::SourceProcessGuid, "{source}"),
                (Pa::SourceProcessId, "31"),
                (Pa::SourceThreadId, "32"),
                (Pa::SourceImage, "C:\\source.exe"),
                (Pa::TargetProcessGuid, "{target}"),
                (Pa::TargetProcessId, "33"),
                (Pa::TargetImage, "C:\\lsass.exe"),
                (Pa::GrantedAccess, "4294971408"),
                (Pa::CallTrace, "ntdll.dll+9d204"),
                (Pa::SourceUser, "source-user"),
                (Pa::TargetUser, "target-user"),
            ],
        );
        check_values(
            RawEventKind::RegistryObjectAddDel,
            &RawEventBody::RegistryObjectAddDel(registry_object_add_del_body()),
            &[
                (Roa::AgentName, "agent"),
                (Roa::AgentId, "agent-id"),
                (Roa::EventType, "CreateKey"),
                (Roa::ProcessGuid, "{process}"),
                (Roa::ProcessId, "41"),
                (Roa::Image, "C:\\reg.exe"),
                (Roa::TargetObject, "HKLM\\Software\\Synthetic"),
                (Roa::User, "user"),
            ],
        );
        check_values(
            RawEventKind::WindowsEventLog,
            &RawEventBody::WindowsEventLog(windows_event_log_body()),
            &[
                (Wel::Channel, "Security"),
                (Wel::Provider, "Microsoft-Windows-Security-Auditing"),
                (Wel::EventId, "4624"),
                (Wel::Version, "2"),
                (Wel::Level, "4"),
                (Wel::Task, "12544"),
                (Wel::Opcode, "0"),
                (Wel::Keywords, "9232379236109516800"),
                (Wel::RecordId, "123456789012"),
                (Wel::Computer, "endpoint-host"),
                (Wel::UserSid, "S-1-5-18"),
                (
                    Wel::EventData,
                    "TargetUserName=alice|=line 1\n\tline 2|Empty=",
                ),
                (Wel::UserDataXml, "<UserData/>"),
            ],
        );
        check_values(
            RawEventKind::Journald,
            &RawEventBody::Journald(journald_body()),
            &[(
                JournaldAttr::Fields,
                "MESSAGE=session opened|_BOOT_ID=0abcff|EMPTY=",
            )],
        );
        check_values(
            RawEventKind::Auditd,
            &RawEventBody::Auditd(auditd_body()),
            &[
                (AuditdAttr::Serial, "9001"),
                (AuditdAttr::Records, "SYSCALL:arch=c000003e syscall=59|EOE:"),
            ],
        );
    }

    #[test]
    fn endpoint_attributes_read_nothing_from_a_body_of_another_kind() {
        fn check<A: IntoEnumIterator + Display>(kind: RawEventKind) {
            for body in header_bodies() {
                if kind_of(&body) == kind {
                    continue;
                }
                for attr in A::iter() {
                    let name = attr.to_string();
                    let parsed = RawEventAttrKind::from_kind_and_attr_name(&kind, &name).unwrap();
                    assert!(attr_value(&body, parsed).is_none(), "{kind:?} {name}");
                }
            }
        }
        check::<ProcessCreateAttr>(RawEventKind::ProcessCreate);
        check::<DriverLoadAttr>(RawEventKind::DriverLoad);
        check::<CreateRemoteThreadAttr>(RawEventKind::CreateRemoteThread);
        check::<RawAccessReadAttr>(RawEventKind::RawAccessRead);
        check::<ProcessAccessAttr>(RawEventKind::ProcessAccess);
        check::<RegistryObjectAddDelAttr>(RawEventKind::RegistryObjectAddDel);
        check::<WindowsEventLogAttr>(RawEventKind::WindowsEventLog);
        check::<JournaldAttr>(RawEventKind::Journald);
        check::<AuditdAttr>(RawEventKind::Auditd);
    }

    #[test]
    fn list_elements_are_written_without_substitutions() {
        let unnamed = raw_event::EventData {
            name: None,
            value: "v\tw".to_string(),
        };
        assert_eq!(
            list_element_string(ListElement::EventData(&unnamed)),
            "=v\tw"
        );
        let named = raw_event::EventData {
            name: Some("n".to_string()),
            value: String::new(),
        };
        assert_eq!(list_element_string(ListElement::EventData(&named)), "n=");

        let text = text_field("k", "a b\n");
        assert_eq!(list_element_string(ListElement::LogField(&text)), "k=a b\n");
        let bytes = bytes_field("k", &[0x00, 0x7f, 0xab]);
        assert_eq!(
            list_element_string(ListElement::LogField(&bytes)),
            "k=007fab"
        );
        let empty = bytes_field("k", &[]);
        assert_eq!(list_element_string(ListElement::LogField(&empty)), "k=");

        let record = raw_event::AuditRecord {
            record_type: "PATH".to_string(),
            fields: vec![text_field("name", "/bin/sh"), bytes_field("raw", &[0x0f])],
        };
        assert_eq!(
            list_element_string(ListElement::AuditRecord(&record)),
            "PATH:name=/bin/sh raw=0f"
        );
        let bare = raw_event::AuditRecord {
            record_type: "EOE".to_string(),
            fields: Vec::new(),
        };
        assert_eq!(list_element_string(ListElement::AuditRecord(&bare)), "EOE:");
    }

    fn string_attr(
        kind: RawEventKind,
        name: impl Display,
        cmp_kind: AttrCmpKind,
        value: &str,
        weight: f64,
    ) -> PacketAttr {
        attr(
            kind,
            name,
            ValueKind::String,
            cmp_kind,
            serialize(&value),
            Some(weight),
        )
    }

    fn on_endpoint(body: RawEventBody) -> StoredDetectionEvent {
        stored(raw_event_event(time(), &endpoint_sensor(), body))
    }

    #[test]
    fn a_list_attribute_matches_when_one_element_matches() {
        let journald = on_endpoint(RawEventBody::Journald(journald_body()));
        let fields = |cmp_kind, value: &str, weight| {
            string_attr(
                RawEventKind::Journald,
                JournaldAttr::Fields,
                cmp_kind,
                value,
                weight,
            )
        };
        let attrs = vec![
            fields(AttrCmpKind::Contain, "_BOOT_ID=0abcff", 1.0),
            fields(AttrCmpKind::Contain, "MESSAGE=session", 2.0),
            fields(AttrCmpKind::Contain, "MESSAGE=closed", 4.0),
            fields(AttrCmpKind::NotContain, "MESSAGE=closed", 8.0),
            fields(AttrCmpKind::NotContain, "EMPTY=", 16.0),
        ];
        assert_score(score_of(&journald, policy(1, attrs, Vec::new(), 0.0)), 11.0);

        let auditd = on_endpoint(RawEventBody::Auditd(auditd_body()));
        let attrs = vec![
            string_attr(
                RawEventKind::Auditd,
                AuditdAttr::Records,
                AttrCmpKind::Contain,
                "SYSCALL:arch=c000003e syscall=59",
                1.0,
            ),
            string_attr(
                RawEventKind::Auditd,
                AuditdAttr::Records,
                AttrCmpKind::Contain,
                "EOE:",
                2.0,
            ),
            attr(
                RawEventKind::Auditd,
                AuditdAttr::Serial,
                ValueKind::UInteger,
                AttrCmpKind::Equal,
                serialize(&9001_u64),
                Some(4.0),
            ),
        ];
        assert_score(score_of(&auditd, policy(1, attrs, Vec::new(), 0.0)), 7.0);

        let windows = on_endpoint(RawEventBody::WindowsEventLog(windows_event_log_body()));
        let attrs = vec![string_attr(
            RawEventKind::WindowsEventLog,
            WindowsEventLogAttr::EventData,
            AttrCmpKind::Contain,
            "=line 1\n\tline 2",
            1.0,
        )];
        assert_score(score_of(&windows, policy(1, attrs, Vec::new(), 0.0)), 1.0);
    }

    #[test]
    fn a_none_scalar_field_matches_no_condition() {
        let mut body = windows_event_log_body();
        body.channel = None;
        body.provider = None;
        body.event_id = None;
        body.version = None;
        body.level = None;
        body.task = None;
        body.opcode = None;
        body.keywords = None;
        body.record_id = None;
        body.computer = None;
        body.user_sid = None;
        body.user_data_xml = None;
        let body = RawEventBody::WindowsEventLog(body);
        for attr in WindowsEventLogAttr::iter() {
            let is_list = attr == WindowsEventLogAttr::EventData;
            let name = attr.to_string();
            let read = attr_value(&body, RawEventAttrKind::WindowsEventLog(attr));
            // Only the list attribute still reads a value.
            assert_eq!(read.is_some(), is_list, "{name}");
        }
        let windows = on_endpoint(body);
        let attrs = vec![
            string_attr(
                RawEventKind::WindowsEventLog,
                WindowsEventLogAttr::Channel,
                AttrCmpKind::Contain,
                "",
                1.0,
            ),
            string_attr(
                RawEventKind::WindowsEventLog,
                WindowsEventLogAttr::Channel,
                AttrCmpKind::NotContain,
                "Security",
                2.0,
            ),
        ];
        assert_score(score_of(&windows, policy(1, attrs, Vec::new(), 0.0)), 0.0);

        let process = on_endpoint(RawEventBody::ProcessCreate(process_create_body(None)));
        let logon = |cmp_kind, value: u64, weight| {
            attr(
                RawEventKind::ProcessCreate,
                ProcessCreateAttr::LogonIdFull,
                ValueKind::UInteger,
                cmp_kind,
                serialize(&value),
                Some(weight),
            )
        };
        let attrs = vec![
            logon(AttrCmpKind::Equal, 0, 1.0),
            logon(AttrCmpKind::NotEqual, 0, 2.0),
            logon(AttrCmpKind::Greater, 0, 4.0),
        ];
        assert_score(score_of(&process, policy(1, attrs, Vec::new(), 0.0)), 0.0);
        let process = on_endpoint(RawEventBody::ProcessCreate(process_create_body(Some(7))));
        let attrs = vec![logon(AttrCmpKind::Equal, 7, 1.0)];
        assert_score(score_of(&process, policy(1, attrs, Vec::new(), 0.0)), 1.0);

        let mut auditd = auditd_body();
        auditd.serial = None;
        assert!(
            attr_value(
                &RawEventBody::Auditd(auditd),
                RawEventAttrKind::Auditd(AuditdAttr::Serial)
            )
            .is_none()
        );
    }

    #[test]
    fn a_none_list_field_reads_as_an_empty_list() {
        let mut windows = windows_event_log_body();
        windows.event_data = None;
        let mut journald = journald_body();
        journald.fields = None;
        let mut auditd = auditd_body();
        auditd.records = None;
        let cases = [
            (
                RawEventBody::WindowsEventLog(windows),
                RawEventAttrKind::WindowsEventLog(WindowsEventLogAttr::EventData),
            ),
            (
                RawEventBody::Journald(journald),
                RawEventAttrKind::Journald(JournaldAttr::Fields),
            ),
            (
                RawEventBody::Auditd(auditd),
                RawEventAttrKind::Auditd(AuditdAttr::Records),
            ),
        ];
        for (body, attr_kind) in cases {
            let Some(AttrValue::VecString(items)) = attr_value(&body, attr_kind) else {
                panic!("a list attribute reads a list of strings");
            };
            assert_eq!(items.len(), 0);
        }
    }
}
