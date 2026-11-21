//! Old data structures for migration purposes.
//!
//! These structures represent the schemas from previous releases
//! and must not be modified. They are used to migrate data from
//! old formats to new formats.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    AgentConfig, AgentKind, AgentStatus, ExternalServiceConfig, ExternalServiceKind,
    ExternalServiceStatus, OperationAction, OperationCleanupState, OperationFailureKind,
    OperationOutcome, OperationPhase, OperationRetryPolicy,
    event::{DceRpcContext, EventKind, FtpCommand, TriageScore},
    types::HostNetworkGroup,
};

/// Network value structure from version 0.43.x
///
/// This structure represents the old serialized value format where:
/// - The key was `name + id.to_be_bytes()` (name followed by 4-byte big-endian id)
/// - The value contained `customer_ids` field (now removed)
/// - The value did NOT contain `id` field (id was in the key)
#[derive(Serialize, Deserialize)]
pub(crate) struct NetworkValueV0_43 {
    pub(crate) description: String,
    pub(crate) networks: HostNetworkGroup,
    pub(crate) customer_ids: Vec<u32>,
    pub(crate) tag_ids: Vec<u32>,
    pub(crate) creation_time: String,
}

// ============================================================================
// Old triage policy structures for migration
// (Confidence.threat_category: EventCategory -> Option<EventCategory>)
// ============================================================================

use crate::{PacketAttr, Response};

/// `Confidence` structure from version 0.44.0 (before `threat_category`
/// became optional). In this version, `threat_category` was `EventCategory`.
/// From 0.45.0-alpha.1, it changed to `Option<EventCategory>`.
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct ConfidenceV0_44 {
    pub(crate) threat_category: EventCategory,
    pub(crate) threat_kind: String,
    pub(crate) confidence: f64,
    pub(crate) weight: Option<f64>,
}

/// `TriagePolicy` structure from version 0.44.0, containing
/// `ConfidenceV0_44` with non-optional `threat_category`.
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct TriagePolicyV0_44 {
    pub(crate) id: u32,
    pub(crate) name: String,
    pub(crate) triage_exclusion_id: Vec<u32>,
    pub(crate) packet_attr: Vec<PacketAttr>,
    pub(crate) confidence: Vec<ConfidenceV0_44>,
    pub(crate) response: Vec<Response>,
    pub(crate) creation_time: String,
    pub(crate) customer_id: Option<u32>,
}

/// The stored triage policy layout from version 0.45.0 onward, in which
/// `Confidence.threat_category` is `Option<EventCategory>`.
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct TriagePolicyV0_45 {
    pub(crate) id: u32,
    pub(crate) name: String,
    pub(crate) triage_exclusion_id: Vec<u32>,
    pub(crate) packet_attr: Vec<PacketAttr>,
    pub(crate) confidence: Vec<crate::Confidence>,
    pub(crate) response: Vec<Response>,
    pub(crate) creation_time: String,
    pub(crate) customer_id: Option<u32>,
}

impl From<TriagePolicyV0_44> for TriagePolicyV0_45 {
    fn from(old: TriagePolicyV0_44) -> Self {
        Self {
            id: old.id,
            name: old.name,
            triage_exclusion_id: old.triage_exclusion_id,
            packet_attr: old.packet_attr,
            confidence: old
                .confidence
                .into_iter()
                .map(|c| crate::Confidence {
                    threat_category: Some(c.threat_category),
                    threat_kind: c.threat_kind,
                    confidence: c.confidence,
                    weight: c.weight,
                })
                .collect(),
            response: old.response,
            creation_time: old.creation_time,
            customer_id: old.customer_id,
        }
    }
}

/// The stored `Agent` value up to database format 0.46, before the
/// install-state fields and `instance` were added.
///
/// The field order is the wire order: an encoded value of this layout is a
/// strict prefix of an [`AgentValueV0_47`] one. Reading a row is therefore a
/// matter of trying each layout, because `bincode` rejects both a short read
/// and bytes left over, so neither layout decodes the other's rows.
#[derive(Deserialize, Serialize)]
pub(crate) struct AgentValueV0_46 {
    pub kind: AgentKind,
    pub status: AgentStatus,
    pub config: Option<AgentConfig>,
    pub draft: Option<AgentConfig>,
}

/// The stored `Agent` value as of database format 0.47.
///
/// `lifecycle` is the stored variant index rather than the `Lifecycle` enum,
/// because a row written by a newer build may carry an index this build does
/// not recognize and must still read back.
///
/// It describes a released layout and must never be modified.
#[derive(Deserialize, Serialize)]
pub(crate) struct AgentValueV0_47 {
    pub kind: AgentKind,
    pub status: AgentStatus,
    pub config: Option<AgentConfig>,
    pub draft: Option<AgentConfig>,
    pub installed_version: Option<String>,
    pub installed_commit: Option<String>,
    pub lifecycle: u8,
    pub bound_addrs: Vec<(String, String)>,
    pub instance: Option<u32>,
}

impl From<AgentValueV0_46> for AgentValueV0_47 {
    /// Adds the install state a host has not reported yet, and leaves the
    /// instance number unrecorded.
    ///
    /// `lifecycle` is the literal `0` that `Lifecycle::NotInstalled` is stored
    /// as. A registered agent whose host has reported nothing has nothing
    /// installed, and the true state arrives with the next status report.
    ///
    /// A row written before `instance` existed describes an instance whose
    /// number was never stored, and `None` is the honest value for it. Any
    /// number chosen here would assert an allocation nothing made.
    fn from(old: AgentValueV0_46) -> Self {
        Self {
            kind: old.kind,
            status: old.status,
            config: old.config,
            draft: old.draft,
            installed_version: None,
            installed_commit: None,
            lifecycle: 0,
            bound_addrs: Vec::new(),
            instance: None,
        }
    }
}

/// The stored `Agent` value as of database format 0.61.
///
/// It is [`AgentValueV0_47`] with `run_as_root`, `run_as_root_draft` and
/// `privilege_profile` appended last, so an encoded [`AgentValueV0_47`] is a
/// strict prefix of one of these. It mirrors the private `Value` of the live
/// agents table, whose component types it deliberately reuses, and the drift
/// test in [`super`](crate::migration) holds the two together.
#[derive(Deserialize, Serialize)]
pub(crate) struct AgentValueV0_61 {
    pub kind: AgentKind,
    pub status: AgentStatus,
    pub config: Option<AgentConfig>,
    pub draft: Option<AgentConfig>,
    pub installed_version: Option<String>,
    pub installed_commit: Option<String>,
    pub lifecycle: u8,
    pub bound_addrs: Vec<(String, String)>,
    pub instance: Option<u32>,
    pub run_as_root: bool,
    pub run_as_root_draft: Option<bool>,
    pub privilege_profile: Option<String>,
}

impl From<AgentValueV0_47> for AgentValueV0_61 {
    /// Copies every field, with the switch off, no pending change to it and no
    /// confirmed profile: no earlier row recorded any of them.
    fn from(old: AgentValueV0_47) -> Self {
        Self {
            kind: old.kind,
            status: old.status,
            config: old.config,
            draft: old.draft,
            installed_version: old.installed_version,
            installed_commit: old.installed_commit,
            lifecycle: old.lifecycle,
            bound_addrs: old.bound_addrs,
            instance: old.instance,
            run_as_root: false,
            run_as_root_draft: None,
            privilege_profile: None,
        }
    }
}

/// The stored `ExternalService` value up to database format 0.46, before the
/// install-state fields and `instance` were added.
///
/// As with [`AgentValueV0_46`], an encoded value of this layout is a strict
/// prefix of an [`ExternalServiceValueV0_47`] one.
#[derive(Deserialize, Serialize)]
pub(crate) struct ExternalServiceValueV0_46 {
    pub kind: ExternalServiceKind,
    pub status: ExternalServiceStatus,
    pub draft: Option<ExternalServiceConfig>,
}

/// The stored `ExternalService` value as of database format 0.47, mirroring
/// the live external services table on the same terms as
/// [`AgentValueV0_47`].
#[derive(Deserialize, Serialize)]
pub(crate) struct ExternalServiceValueV0_47 {
    pub kind: ExternalServiceKind,
    pub status: ExternalServiceStatus,
    pub draft: Option<ExternalServiceConfig>,
    pub installed_version: Option<String>,
    pub installed_commit: Option<String>,
    pub lifecycle: u8,
    pub bound_addrs: Vec<(String, String)>,
    pub instance: Option<u32>,
}

impl From<ExternalServiceValueV0_46> for ExternalServiceValueV0_47 {
    /// Adds the install state a host has not reported yet, and leaves the
    /// instance number unrecorded, on the same terms as
    /// [`AgentValueV0_47::from`].
    fn from(old: ExternalServiceValueV0_46) -> Self {
        Self {
            kind: old.kind,
            status: old.status,
            draft: old.draft,
            installed_version: None,
            installed_commit: None,
            lifecycle: 0,
            bound_addrs: Vec::new(),
            instance: None,
        }
    }
}

/// The width of the request digest an operation attempt stores, a SHA-256
/// digest in the 0.47, 0.48 and 0.49 layouts.
const OPERATION_ATTEMPT_DIGEST_LEN: usize = 32;

/// The stored `OperationAttempt` value as of database format 0.47, before
/// `failure_kind` was added.
///
/// This mirrors, field for field and in order, the private `Value` of the
/// operation attempts table as the 0.47.0 release stores it, with owned
/// strings where that struct borrows them; serde encodes the two identically.
/// Its encoding is a strict prefix of an [`OperationAttemptValueV0_48`] one,
/// and because `bincode` rejects both a short read and bytes left over,
/// neither layout decodes the other's rows. It describes a released layout
/// and must never be modified; a committed fixture pins it to the release.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct OperationAttemptValueV0_47 {
    pub host: String,
    pub target: String,
    pub instance: Option<u32>,
    pub action: OperationAction,
    pub install_intent: Option<[u8; OPERATION_ATTEMPT_DIGEST_LEN]>,
    pub package_digest: String,
    pub resolved_version: String,
    pub resolved_commit: String,
    pub phase: OperationPhase,
    pub cleanup_state: Option<OperationCleanupState>,
    pub started_at: String,
    pub retry_policy: OperationRetryPolicy,
    pub outcome: Option<OperationOutcome>,
    pub finalized_at: Option<String>,
    pub expires_at: String,
    pub backup_id: Option<u32>,
    pub pre_update_version: Option<String>,
}

/// The stored `OperationAttempt` value as of the released database format
/// 0.48.0, before `config_template` was added.
///
/// It mirrors the private `Value` as 0.48.0 stores it, with owned strings
/// where that struct borrows them. Its encoding is a strict prefix of an
/// [`OperationAttemptValueV0_49`] one, and neither layout decodes the other's
/// rows. It describes a released layout and must never be modified; a
/// committed fixture pins it to the release.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct OperationAttemptValueV0_48 {
    pub host: String,
    pub target: String,
    pub instance: Option<u32>,
    pub action: OperationAction,
    pub install_intent: Option<[u8; OPERATION_ATTEMPT_DIGEST_LEN]>,
    pub package_digest: String,
    pub resolved_version: String,
    pub resolved_commit: String,
    pub phase: OperationPhase,
    pub cleanup_state: Option<OperationCleanupState>,
    pub started_at: String,
    pub retry_policy: OperationRetryPolicy,
    pub outcome: Option<OperationOutcome>,
    pub finalized_at: Option<String>,
    pub expires_at: String,
    pub backup_id: Option<u32>,
    pub pre_update_version: Option<String>,
    pub failure_kind: Option<OperationFailureKind>,
}

impl From<OperationAttemptValueV0_47> for OperationAttemptValueV0_48 {
    /// Copies every field and derives `failure_kind` from `outcome`.
    ///
    /// A `Failed` attempt gets [`OperationFailureKind::Other`]: 0.47 never
    /// recorded why it failed, and nothing reconstructs a specific kind, but
    /// a kind is what keeps the row writable — the discharge of a teardown
    /// it still owes is refused without one. Every other attempt, a
    /// non-terminal one included, gets `None`.
    fn from(old: OperationAttemptValueV0_47) -> Self {
        let failure_kind =
            (old.outcome == Some(OperationOutcome::Failed)).then_some(OperationFailureKind::Other);
        Self {
            host: old.host,
            target: old.target,
            instance: old.instance,
            action: old.action,
            install_intent: old.install_intent,
            package_digest: old.package_digest,
            resolved_version: old.resolved_version,
            resolved_commit: old.resolved_commit,
            phase: old.phase,
            cleanup_state: old.cleanup_state,
            started_at: old.started_at,
            retry_policy: old.retry_policy,
            outcome: old.outcome,
            finalized_at: old.finalized_at,
            expires_at: old.expires_at,
            backup_id: old.backup_id,
            pre_update_version: old.pre_update_version,
            failure_kind,
        }
    }
}

/// The stored `OperationAttempt` value as of database format 0.49.
///
/// It is [`OperationAttemptValueV0_48`] with `config_template` appended
/// last. It describes a released layout and must never be modified.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct OperationAttemptValueV0_49 {
    pub host: String,
    pub target: String,
    pub instance: Option<u32>,
    pub action: OperationAction,
    pub install_intent: Option<[u8; OPERATION_ATTEMPT_DIGEST_LEN]>,
    pub package_digest: String,
    pub resolved_version: String,
    pub resolved_commit: String,
    pub phase: OperationPhase,
    pub cleanup_state: Option<OperationCleanupState>,
    pub started_at: String,
    pub retry_policy: OperationRetryPolicy,
    pub outcome: Option<OperationOutcome>,
    pub finalized_at: Option<String>,
    pub expires_at: String,
    pub backup_id: Option<u32>,
    pub pre_update_version: Option<String>,
    pub failure_kind: Option<OperationFailureKind>,
    pub config_template: Option<String>,
}

impl From<OperationAttemptValueV0_48> for OperationAttemptValueV0_49 {
    /// Copies every field and records no template: no earlier install
    /// carried one.
    fn from(old: OperationAttemptValueV0_48) -> Self {
        Self {
            host: old.host,
            target: old.target,
            instance: old.instance,
            action: old.action,
            install_intent: old.install_intent,
            package_digest: old.package_digest,
            resolved_version: old.resolved_version,
            resolved_commit: old.resolved_commit,
            phase: old.phase,
            cleanup_state: old.cleanup_state,
            started_at: old.started_at,
            retry_policy: old.retry_policy,
            outcome: old.outcome,
            finalized_at: old.finalized_at,
            expires_at: old.expires_at,
            backup_id: old.backup_id,
            pre_update_version: old.pre_update_version,
            failure_kind: old.failure_kind,
            config_template: None,
        }
    }
}

/// The stored `OperationAttempt` value of database formats 0.61 and 0.62,
/// generic over how a timestamp is stored.
///
/// It is [`OperationAttemptValueV0_49`] with `privilege_profile` appended
/// last. 0.61 stores each timestamp as chrono's default serde string, which
/// [`OperationAttemptValueV0_61`] reads, and 0.62 as `i64` Unix-epoch
/// nanoseconds, which [`OperationAttemptValueV0_62`] reads. It mirrors the
/// private `Value` of the live operation attempts table, whose component
/// types it deliberately reuses, and the drift test beside that table holds
/// the two together.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct OperationAttemptValue<Ts> {
    pub host: String,
    pub target: String,
    pub instance: Option<u32>,
    pub action: OperationAction,
    pub install_intent: Option<[u8; OPERATION_ATTEMPT_DIGEST_LEN]>,
    pub package_digest: String,
    pub resolved_version: String,
    pub resolved_commit: String,
    pub phase: OperationPhase,
    pub cleanup_state: Option<OperationCleanupState>,
    pub started_at: Ts,
    pub retry_policy: OperationRetryPolicy,
    pub outcome: Option<OperationOutcome>,
    pub finalized_at: Option<Ts>,
    pub expires_at: Ts,
    pub backup_id: Option<u32>,
    pub pre_update_version: Option<String>,
    pub failure_kind: Option<OperationFailureKind>,
    pub config_template: Option<String>,
    pub privilege_profile: Option<String>,
}

/// The stored `OperationAttempt` value as of database format 0.61.
pub(crate) type OperationAttemptValueV0_61 = OperationAttemptValue<String>;

/// The stored `OperationAttempt` value as of database format 0.62.
#[cfg(test)]
pub(crate) type OperationAttemptValueV0_62 = OperationAttemptValue<i64>;

impl<Ts> OperationAttemptValue<Ts> {
    /// Converts every timestamp of the record with `ts`.
    pub(crate) fn map_timestamps<U>(
        self,
        ts: &mut TimestampConverter<'_, Ts, U>,
    ) -> Result<OperationAttemptValue<U>> {
        Ok(OperationAttemptValue {
            host: self.host,
            target: self.target,
            instance: self.instance,
            action: self.action,
            install_intent: self.install_intent,
            package_digest: self.package_digest,
            resolved_version: self.resolved_version,
            resolved_commit: self.resolved_commit,
            phase: self.phase,
            cleanup_state: self.cleanup_state,
            started_at: ts(self.started_at)?,
            retry_policy: self.retry_policy,
            outcome: self.outcome,
            finalized_at: self.finalized_at.map(&mut *ts).transpose()?,
            expires_at: ts(self.expires_at)?,
            backup_id: self.backup_id,
            pre_update_version: self.pre_update_version,
            failure_kind: self.failure_kind,
            config_template: self.config_template,
            privilege_profile: self.privilege_profile,
        })
    }
}

impl From<OperationAttemptValueV0_49> for OperationAttemptValueV0_61 {
    /// Copies every field and records no profile: no earlier attempt carried
    /// one, and on the wire `None` means keeping the profile last applied.
    fn from(old: OperationAttemptValueV0_49) -> Self {
        Self {
            host: old.host,
            target: old.target,
            instance: old.instance,
            action: old.action,
            install_intent: old.install_intent,
            package_digest: old.package_digest,
            resolved_version: old.resolved_version,
            resolved_commit: old.resolved_commit,
            phase: old.phase,
            cleanup_state: old.cleanup_state,
            started_at: old.started_at,
            retry_policy: old.retry_policy,
            outcome: old.outcome,
            finalized_at: old.finalized_at,
            expires_at: old.expires_at,
            backup_id: old.backup_id,
            pre_update_version: old.pre_update_version,
            failure_kind: old.failure_kind,
            config_template: old.config_template,
            privilege_profile: None,
        }
    }
}

// ============================================================================
// Historical persisted event schemas
// ============================================================================

/// Country code written by 0.46 when no lookup was performed.
pub(crate) const V0_46_COUNTRY_CODE_UNRESOLVED: [u8; 2] = *b"ZZ";

/// Country code written by 0.46 when a lookup failed or was invalid.
pub(crate) const V0_46_COUNTRY_CODE_LOOKUP_FAILED: [u8; 2] = *b"XX";

use std::net::IpAddr;

use crate::EventCategory;

#[derive(Serialize, Deserialize)]
pub(crate) struct BlocklistDceRpcFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub rtt: i64,
    pub named_pipe: String,
    pub endpoint: String,
    pub operation: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct BlocklistDhcpFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub msg_type: u8,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub subnet_mask: IpAddr,
    pub router: Vec<IpAddr>,
    pub domain_name_server: Vec<IpAddr>,
    pub req_ip_addr: IpAddr,
    pub lease_time: u32,
    pub server_id: IpAddr,
    pub param_req_list: Vec<u8>,
    pub message: String,
    pub renewal_time: u32,
    pub rebinding_time: u32,
    pub class_id: Vec<u8>,
    pub client_id_type: u8,
    pub client_id: Vec<u8>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct HttpThreatFieldsStoredV0_43 {
    pub time: i64,
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
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
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: Option<usize>,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistBootpFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub op: u8,
    pub htype: u8,
    pub hops: u8,
    pub xid: u32,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub chaddr: Vec<u8>,
    pub sname: String,
    pub file: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistMqttFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub protocol: String,
    pub version: u8,
    pub client_id: String,
    pub connack_reason: u8,
    pub subscribe: Vec<String>,
    pub suback_reason: Vec<u8>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistSmbFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub command: u8,
    pub path: String,
    pub service: String,
    pub file_name: String,
    pub file_size: u64,
    pub resource_type: u16,
    pub fid: u16,
    pub create_time: i64,
    pub access_time: i64,
    pub write_time: i64,
    pub change_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistNtlmFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub protocol: String,
    pub username: String,
    pub hostname: String,
    pub domainname: String,
    pub success: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct UnusualDestinationPatternFieldsStoredV0_45 {
    pub sensor: String,
    pub start_time: i64,
    pub end_time: i64,
    pub destination_ips: Vec<IpAddr>,
    pub count: usize,
    pub expected_mean: f64,
    pub std_deviation: f64,
    pub z_score: f64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct LdapBruteForceFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub user_pw_list: Vec<(String, String)>,
    pub start_time: i64,
    pub end_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct LdapEventFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub message_id: u32,
    pub version: u8,
    pub opcode: Vec<String>,
    pub result: Vec<String>,
    pub diagnostic_message: Vec<String>,
    pub object: Vec<String>,
    pub argument: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistMalformedDnsFieldsStoredV0_45 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub trans_id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    pub query_count: u32,
    pub resp_count: u32,
    pub query_bytes: u64,
    pub resp_bytes: u64,
    pub query_body: Vec<Vec<u8>>,
    pub resp_body: Vec<Vec<u8>>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Serialize)]
pub(crate) struct DnsEventFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Serialize)]
pub(crate) struct CryptocurrencyMiningPoolFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub coins: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistDnsFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub query: String,
    pub answer: Vec<String>,
    pub trans_id: u16,
    pub rtt: i64,
    pub qclass: u16,
    pub qtype: u16,
    pub rcode: u16,
    pub aa_flag: bool,
    pub tc_flag: bool,
    pub rd_flag: bool,
    pub ra_flag: bool,
    pub ttl: Vec<i32>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistDhcpFieldsStoredV0_44 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub msg_type: u8,
    pub ciaddr: IpAddr,
    pub yiaddr: IpAddr,
    pub siaddr: IpAddr,
    pub giaddr: IpAddr,
    pub subnet_mask: IpAddr,
    pub router: Vec<IpAddr>,
    pub domain_name_server: Vec<IpAddr>,
    pub req_ip_addr: IpAddr,
    pub lease_time: u32,
    pub server_id: IpAddr,
    pub param_req_list: Vec<u8>,
    pub message: String,
    pub renewal_time: u32,
    pub rebinding_time: u32,
    pub class_id: Vec<u8>,
    pub client_id_type: u8,
    pub client_id: Vec<u8>,
    pub options: Vec<(u8, Vec<u8>)>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct FtpBruteForceFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub user_list: Vec<String>,
    pub start_time: i64,
    pub end_time: i64,
    pub is_internal: bool,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct FtpEventFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub user: String,
    pub password: String,
    pub commands: Vec<FtpCommand>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct RdpBruteForceFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_addrs: Vec<IpAddr>,
    pub start_time: i64,
    pub end_time: i64,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistRdpFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub cookie: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistDceRpcFieldsStoredV0_44 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
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

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistSshFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub client: String,
    pub server: String,
    pub cipher_alg: String,
    pub mac_alg: String,
    pub compression_alg: String,
    pub kex_alg: String,
    pub host_key_alg: String,
    pub hassh_algorithms: String,
    pub hassh: String,
    pub hassh_server_algorithms: String,
    pub hassh_server: String,
    pub client_shka: String,
    pub server_shka: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct PortScanFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_addr: IpAddr,
    pub resp_ports: Vec<u16>,
    pub start_time: i64,
    pub end_time: i64,
    pub proto: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct MultiHostPortScanFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub resp_port: u16,
    pub resp_addrs: Vec<IpAddr>,
    pub proto: u8,
    pub start_time: i64,
    pub end_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct ExternalDdosFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addrs: Vec<IpAddr>,
    pub resp_addr: IpAddr,
    pub proto: u8,
    pub start_time: i64,
    pub end_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistConnFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub conn_state: String,
    pub start_time: i64,
    pub duration: i64,
    pub service: String,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct HttpEventFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
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
}

#[derive(Deserialize, Serialize)]
pub(crate) struct RepeatedHttpSessionsFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub end_time: i64,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct HttpThreatFieldsStoredV0_44 {
    pub time: i64,
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
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
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: Option<u32>,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct DgaFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
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
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistNfsFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub read_files: Vec<String>,
    pub write_files: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistRadiusFieldsStoredV0_45 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub id: u8,
    pub code: u8,
    pub resp_code: u8,
    pub auth: String,
    pub resp_auth: String,
    pub user_name: Vec<u8>,
    pub user_passwd: Vec<u8>,
    pub chap_passwd: Vec<u8>,
    pub nas_ip: IpAddr,
    pub nas_port: u32,
    pub state: Vec<u8>,
    pub nas_id: Vec<u8>,
    pub nas_port_type: u32,
    pub message: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistSmtpFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub mailfrom: String,
    pub date: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub agent: String,
    pub state: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistKerberosFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub client_time: i64,
    pub server_time: i64,
    pub error_code: u32,
    pub client_realm: String,
    pub cname_type: u8,
    pub cname: Vec<String>,
    pub realm: String,
    pub sname_type: u8,
    pub sname: Vec<String>,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct NetworkThreatFieldsStoredV0_45 {
    pub time: i64,
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub service: String,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub content: String,
    pub db_name: String,
    pub rule_id: u32,
    pub matched_to: String,
    pub cluster_id: Option<u32>,
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
    pub triage_scores: Option<Vec<TriageScore>>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct BlocklistTlsFieldsStoredV0_42 {
    pub sensor: String,
    pub orig_addr: IpAddr,
    pub orig_port: u16,
    pub resp_addr: IpAddr,
    pub resp_port: u16,
    pub proto: u8,
    pub start_time: i64,
    pub duration: i64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_l2_bytes: u64,
    pub resp_l2_bytes: u64,
    pub server_name: String,
    pub alpn_protocol: String,
    pub ja3: String,
    pub version: String,
    pub client_cipher_suites: Vec<u16>,
    pub client_extensions: Vec<u16>,
    pub cipher: u16,
    pub extensions: Vec<u16>,
    pub ja3s: String,
    pub serial: String,
    pub subject_country: String,
    pub subject_org_name: String,
    pub subject_common_name: String,
    pub validity_not_before: i64,
    pub validity_not_after: i64,
    pub subject_alt_name: String,
    pub issuer_country: String,
    pub issuer_org_name: String,
    pub issuer_org_unit_name: String,
    pub issuer_common_name: String,
    pub last_alert: u8,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

impl From<BlocklistBootpFieldsStoredV0_42> for crate::event::BlocklistBootpFieldsStoredV0_46 {
    fn from(old: BlocklistBootpFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            op: old.op,
            htype: old.htype,
            hops: old.hops,
            xid: old.xid,
            ciaddr: old.ciaddr,
            yiaddr: old.yiaddr,
            siaddr: old.siaddr,
            giaddr: old.giaddr,
            chaddr: old.chaddr,
            sname: old.sname,
            file: old.file,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistConnFieldsStoredV0_42> for crate::event::BlocklistConnFieldsStoredV0_46 {
    fn from(old: BlocklistConnFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            conn_state: old.conn_state,
            start_time: old.start_time,
            duration: old.duration,
            service: old.service,
            orig_bytes: old.orig_bytes,
            resp_bytes: old.resp_bytes,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistDceRpcFieldsStoredV0_44> for crate::event::BlocklistDceRpcFieldsStoredV0_46 {
    fn from(old: BlocklistDceRpcFieldsStoredV0_44) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            context: old.context,
            request: old.request,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistDhcpFieldsStoredV0_44> for crate::event::BlocklistDhcpFieldsStoredV0_46 {
    fn from(old: BlocklistDhcpFieldsStoredV0_44) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            msg_type: old.msg_type,
            ciaddr: old.ciaddr,
            yiaddr: old.yiaddr,
            siaddr: old.siaddr,
            giaddr: old.giaddr,
            subnet_mask: old.subnet_mask,
            router: old.router,
            domain_name_server: old.domain_name_server,
            req_ip_addr: old.req_ip_addr,
            lease_time: old.lease_time,
            server_id: old.server_id,
            param_req_list: old.param_req_list,
            message: old.message,
            renewal_time: old.renewal_time,
            rebinding_time: old.rebinding_time,
            class_id: old.class_id,
            client_id_type: old.client_id_type,
            client_id: old.client_id,
            options: old.options,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistDnsFieldsStoredV0_42> for crate::event::BlocklistDnsFieldsStoredV0_46 {
    fn from(old: BlocklistDnsFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            query: old.query,
            answer: old.answer,
            trans_id: old.trans_id,
            rtt: old.rtt,
            qclass: old.qclass,
            qtype: old.qtype,
            rcode: old.rcode,
            aa_flag: old.aa_flag,
            tc_flag: old.tc_flag,
            rd_flag: old.rd_flag,
            ra_flag: old.ra_flag,
            ttl: old.ttl,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<FtpEventFieldsStoredV0_42> for crate::event::FtpEventFieldsStoredV0_46 {
    fn from(old: FtpEventFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            user: old.user,
            password: old.password,
            commands: old.commands,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<DgaFieldsStoredV0_42> for crate::event::DgaFieldsStoredV0_46 {
    fn from(old: DgaFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            method: old.method,
            host: old.host,
            uri: old.uri,
            referer: old.referer,
            version: old.version,
            user_agent: old.user_agent,
            request_len: old.request_len,
            response_len: old.response_len,
            status_code: old.status_code,
            status_msg: old.status_msg,
            username: old.username,
            password: old.password,
            cookie: old.cookie,
            content_encoding: old.content_encoding,
            content_type: old.content_type,
            cache_control: old.cache_control,
            filenames: old.filenames,
            mime_types: old.mime_types,
            body: old.body,
            state: old.state,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistKerberosFieldsStoredV0_42> for crate::event::BlocklistKerberosFieldsStoredV0_46 {
    fn from(old: BlocklistKerberosFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            client_time: old.client_time,
            server_time: old.server_time,
            error_code: old.error_code,
            client_realm: old.client_realm,
            cname_type: old.cname_type,
            cname: old.cname,
            realm: old.realm,
            sname_type: old.sname_type,
            sname: old.sname,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<LdapEventFieldsStoredV0_42> for crate::event::LdapEventFieldsStoredV0_46 {
    fn from(old: LdapEventFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            message_id: old.message_id,
            version: old.version,
            opcode: old.opcode,
            result: old.result,
            diagnostic_message: old.diagnostic_message,
            object: old.object,
            argument: old.argument,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistMalformedDnsFieldsStoredV0_45>
    for crate::event::BlocklistMalformedDnsFieldsStoredV0_46
{
    fn from(old: BlocklistMalformedDnsFieldsStoredV0_45) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            trans_id: old.trans_id,
            flags: old.flags,
            question_count: old.question_count,
            answer_count: old.answer_count,
            authority_count: old.authority_count,
            additional_count: old.additional_count,
            query_count: old.query_count,
            resp_count: old.resp_count,
            query_bytes: old.query_bytes,
            resp_bytes: old.resp_bytes,
            query_body: old.query_body,
            resp_body: old.resp_body,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistMqttFieldsStoredV0_42> for crate::event::BlocklistMqttFieldsStoredV0_46 {
    fn from(old: BlocklistMqttFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            protocol: old.protocol,
            version: old.version,
            client_id: old.client_id,
            connack_reason: old.connack_reason,
            subscribe: old.subscribe,
            suback_reason: old.suback_reason,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistNfsFieldsStoredV0_42> for crate::event::BlocklistNfsFieldsStoredV0_46 {
    fn from(old: BlocklistNfsFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            read_files: old.read_files,
            write_files: old.write_files,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistNtlmFieldsStoredV0_42> for crate::event::BlocklistNtlmFieldsStoredV0_46 {
    fn from(old: BlocklistNtlmFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            protocol: old.protocol,
            username: old.username,
            hostname: old.hostname,
            domainname: old.domainname,
            success: old.success,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistRadiusFieldsStoredV0_45> for crate::event::BlocklistRadiusFieldsStoredV0_46 {
    fn from(old: BlocklistRadiusFieldsStoredV0_45) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            id: old.id,
            code: old.code,
            resp_code: old.resp_code,
            auth: old.auth,
            resp_auth: old.resp_auth,
            user_name: old.user_name,
            user_passwd: old.user_passwd,
            chap_passwd: old.chap_passwd,
            nas_ip: old.nas_ip,
            nas_port: old.nas_port,
            state: old.state,
            nas_id: old.nas_id,
            nas_port_type: old.nas_port_type,
            message: old.message,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistRdpFieldsStoredV0_42> for crate::event::BlocklistRdpFieldsStoredV0_46 {
    fn from(old: BlocklistRdpFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            cookie: old.cookie,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistSmbFieldsStoredV0_42> for crate::event::BlocklistSmbFieldsStoredV0_46 {
    fn from(old: BlocklistSmbFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            command: old.command,
            path: old.path,
            service: old.service,
            file_name: old.file_name,
            file_size: old.file_size,
            resource_type: old.resource_type,
            fid: old.fid,
            create_time: old.create_time,
            access_time: old.access_time,
            write_time: old.write_time,
            change_time: old.change_time,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistSmtpFieldsStoredV0_42> for crate::event::BlocklistSmtpFieldsStoredV0_46 {
    fn from(old: BlocklistSmtpFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            mailfrom: old.mailfrom,
            date: old.date,
            from: old.from,
            to: old.to,
            subject: old.subject,
            agent: old.agent,
            state: old.state,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistSshFieldsStoredV0_42> for crate::event::BlocklistSshFieldsStoredV0_46 {
    fn from(old: BlocklistSshFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            client: old.client,
            server: old.server,
            cipher_alg: old.cipher_alg,
            mac_alg: old.mac_alg,
            compression_alg: old.compression_alg,
            kex_alg: old.kex_alg,
            host_key_alg: old.host_key_alg,
            hassh_algorithms: old.hassh_algorithms,
            hassh: old.hassh,
            hassh_server_algorithms: old.hassh_server_algorithms,
            hassh_server: old.hassh_server,
            client_shka: old.client_shka,
            server_shka: old.server_shka,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<BlocklistTlsFieldsStoredV0_42> for crate::event::BlocklistTlsFieldsStoredV0_46 {
    fn from(old: BlocklistTlsFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            server_name: old.server_name,
            alpn_protocol: old.alpn_protocol,
            ja3: old.ja3,
            version: old.version,
            client_cipher_suites: old.client_cipher_suites,
            client_extensions: old.client_extensions,
            cipher: old.cipher,
            extensions: old.extensions,
            ja3s: old.ja3s,
            serial: old.serial,
            subject_country: old.subject_country,
            subject_org_name: old.subject_org_name,
            subject_common_name: old.subject_common_name,
            validity_not_before: old.validity_not_before,
            validity_not_after: old.validity_not_after,
            subject_alt_name: old.subject_alt_name,
            issuer_country: old.issuer_country,
            issuer_org_name: old.issuer_org_name,
            issuer_org_unit_name: old.issuer_org_unit_name,
            issuer_common_name: old.issuer_common_name,
            last_alert: old.last_alert,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<CryptocurrencyMiningPoolFieldsStoredV0_42>
    for crate::event::CryptocurrencyMiningPoolFieldsStoredV0_46
{
    fn from(old: CryptocurrencyMiningPoolFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            query: old.query,
            answer: old.answer,
            trans_id: old.trans_id,
            rtt: old.rtt,
            qclass: old.qclass,
            qtype: old.qtype,
            rcode: old.rcode,
            aa_flag: old.aa_flag,
            tc_flag: old.tc_flag,
            rd_flag: old.rd_flag,
            ra_flag: old.ra_flag,
            ttl: old.ttl,
            coins: old.coins,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<DnsEventFieldsStoredV0_42> for crate::event::DnsEventFieldsStoredV0_46 {
    fn from(old: DnsEventFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            query: old.query,
            answer: old.answer,
            trans_id: old.trans_id,
            rtt: old.rtt,
            qclass: old.qclass,
            qtype: old.qtype,
            rcode: old.rcode,
            aa_flag: old.aa_flag,
            tc_flag: old.tc_flag,
            rd_flag: old.rd_flag,
            ra_flag: old.ra_flag,
            ttl: old.ttl,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<ExternalDdosFieldsStoredV0_42> for crate::event::ExternalDdosFieldsStoredV0_46 {
    fn from(old: ExternalDdosFieldsStoredV0_42) -> Self {
        let orig_addr_count = old.orig_addrs.len();
        Self {
            sensor: old.sensor,
            orig_addrs: old.orig_addrs,
            orig_country_codes: vec![V0_46_COUNTRY_CODE_UNRESOLVED; orig_addr_count],
            resp_addr: old.resp_addr,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            first_event_start_time: old.start_time,
            last_event_start_time: old.end_time,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<FtpBruteForceFieldsStoredV0_42> for crate::event::FtpBruteForceFieldsStoredV0_46 {
    fn from(old: FtpBruteForceFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            user_list: old.user_list,
            first_event_start_time: old.start_time,
            last_event_start_time: old.end_time,
            is_internal: old.is_internal,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl TryFrom<HttpThreatFieldsStoredV0_44> for crate::event::HttpThreatFieldsStoredV0_46 {
    type Error = anyhow::Error;

    fn try_from(old: HttpThreatFieldsStoredV0_44) -> Result<Self> {
        Ok(Self {
            time: i64_nanos_to_timestamp(old.time)?,
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            method: old.method,
            host: old.host,
            uri: old.uri,
            referer: old.referer,
            version: old.version,
            user_agent: old.user_agent,
            request_len: old.request_len,
            response_len: old.response_len,
            status_code: old.status_code,
            status_msg: old.status_msg,
            username: old.username,
            password: old.password,
            cookie: old.cookie,
            content_encoding: old.content_encoding,
            content_type: old.content_type,
            cache_control: old.cache_control,
            filenames: old.filenames,
            mime_types: old.mime_types,
            body: old.body,
            state: old.state,
            db_name: old.db_name,
            rule_id: old.rule_id,
            matched_to: old.matched_to,
            cluster_id: old.cluster_id,
            attack_kind: old.attack_kind,
            confidence: old.confidence,
            category: old.category,
        })
    }
}

impl From<LdapBruteForceFieldsStoredV0_42> for crate::event::LdapBruteForceFieldsStoredV0_46 {
    fn from(old: LdapBruteForceFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            user_pw_list: old.user_pw_list,
            first_event_start_time: old.start_time,
            last_event_start_time: old.end_time,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<MultiHostPortScanFieldsStoredV0_42> for crate::event::MultiHostPortScanFieldsStoredV0_46 {
    fn from(old: MultiHostPortScanFieldsStoredV0_42) -> Self {
        let resp_addr_count = old.resp_addrs.len();
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addrs: old.resp_addrs,
            resp_port: old.resp_port,
            resp_country_codes: vec![V0_46_COUNTRY_CODE_UNRESOLVED; resp_addr_count],
            proto: old.proto,
            first_event_start_time: old.start_time,
            last_event_start_time: old.end_time,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl TryFrom<NetworkThreatFieldsStoredV0_45> for crate::event::NetworkThreatFieldsStoredV0_46 {
    type Error = anyhow::Error;

    fn try_from(old: NetworkThreatFieldsStoredV0_45) -> Result<Self> {
        Ok(Self {
            time: i64_nanos_to_timestamp(old.time)?,
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            service: old.service,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            content: old.content,
            db_name: old.db_name,
            rule_id: old.rule_id,
            matched_to: old.matched_to,
            cluster_id: old.cluster_id,
            attack_kind: old.attack_kind,
            confidence: old.confidence,
            category: old.category,
            triage_scores: old.triage_scores,
        })
    }
}

impl From<HttpEventFieldsStoredV0_42> for crate::event::HttpEventFieldsStoredV0_46 {
    fn from(old: HttpEventFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            start_time: old.start_time,
            duration: old.duration,
            orig_pkts: old.orig_pkts,
            resp_pkts: old.resp_pkts,
            orig_l2_bytes: old.orig_l2_bytes,
            resp_l2_bytes: old.resp_l2_bytes,
            method: old.method,
            host: old.host,
            uri: old.uri,
            referer: old.referer,
            version: old.version,
            user_agent: old.user_agent,
            request_len: old.request_len,
            response_len: old.response_len,
            status_code: old.status_code,
            status_msg: old.status_msg,
            username: old.username,
            password: old.password,
            cookie: old.cookie,
            content_encoding: old.content_encoding,
            content_type: old.content_type,
            cache_control: old.cache_control,
            filenames: old.filenames,
            mime_types: old.mime_types,
            body: old.body,
            state: old.state,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<PortScanFieldsStoredV0_42> for crate::event::PortScanFieldsStoredV0_46 {
    fn from(old: PortScanFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_ports: old.resp_ports,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            first_event_start_time: old.start_time,
            last_event_start_time: old.end_time,
            proto: old.proto,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<RdpBruteForceFieldsStoredV0_42> for crate::event::RdpBruteForceFieldsStoredV0_46 {
    fn from(old: RdpBruteForceFieldsStoredV0_42) -> Self {
        let resp_addr_count = old.resp_addrs.len();
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addrs: old.resp_addrs,
            resp_country_codes: vec![V0_46_COUNTRY_CODE_UNRESOLVED; resp_addr_count],
            first_event_start_time: old.start_time,
            last_event_start_time: old.end_time,
            proto: old.proto,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<RepeatedHttpSessionsFieldsStoredV0_42>
    for crate::event::RepeatedHttpSessionsFieldsStoredV0_46
{
    fn from(old: RepeatedHttpSessionsFieldsStoredV0_42) -> Self {
        Self {
            sensor: old.sensor,
            orig_addr: old.orig_addr,
            orig_port: old.orig_port,
            orig_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            resp_addr: old.resp_addr,
            resp_port: old.resp_port,
            resp_country_code: V0_46_COUNTRY_CODE_UNRESOLVED,
            proto: old.proto,
            first_event_start_time: old.start_time,
            last_event_start_time: old.end_time,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

impl From<UnusualDestinationPatternFieldsStoredV0_45>
    for crate::event::UnusualDestinationPatternFieldsStoredV0_46
{
    fn from(old: UnusualDestinationPatternFieldsStoredV0_45) -> Self {
        let destination_ip_count = old.destination_ips.len();
        Self {
            sensor: old.sensor,
            sampling_window_start_time: old.start_time,
            sampling_window_end_time: old.end_time,
            destination_ips: old.destination_ips,
            resp_country_codes: vec![V0_46_COUNTRY_CODE_UNRESOLVED; destination_ip_count],
            count: old.count,
            expected_mean: old.expected_mean,
            std_deviation: old.std_deviation,
            z_score: old.z_score,
            confidence: old.confidence,
            category: old.category,
        }
    }
}

fn i64_nanos_to_timestamp(nanos: i64) -> Result<jiff::Timestamp> {
    crate::timestamp::from_i64_nanos(nanos)
        .context("failed to convert i64 nanoseconds to Jiff timestamp")
}

fn convert_stored<Source, Target>(bytes: &[u8]) -> Result<Vec<u8>>
where
    Source: for<'de> Deserialize<'de>,
    Target: TryFrom<Source> + Serialize,
    Target::Error: std::fmt::Display + Send + Sync + 'static,
{
    let source: Source = bincode::deserialize(bytes)
        .context("failed to deserialize event fields as the previous stored schema")?;
    let target = Target::try_from(source)
        .map_err(|err| anyhow::anyhow!("{err}"))
        .context("failed to convert event fields to the current stored schema")?;
    bincode::serialize(&target).context("failed to serialize target stored schema")
}

pub(crate) fn migrate_event_stored_schema_to_v0_46(
    kind: EventKind,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    match kind {
        EventKind::BlocklistBootp => convert_stored::<
            BlocklistBootpFieldsStoredV0_42,
            crate::event::BlocklistBootpFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistConn | EventKind::TorConnectionConn => convert_stored::<
            BlocklistConnFieldsStoredV0_42,
            crate::event::BlocklistConnFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistDceRpc => convert_stored::<
            BlocklistDceRpcFieldsStoredV0_44,
            crate::event::BlocklistDceRpcFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistDhcp => convert_stored::<
            BlocklistDhcpFieldsStoredV0_44,
            crate::event::BlocklistDhcpFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistDns => convert_stored::<
            BlocklistDnsFieldsStoredV0_42,
            crate::event::BlocklistDnsFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistFtp | EventKind::FtpPlainText => convert_stored::<
            FtpEventFieldsStoredV0_42,
            crate::event::FtpEventFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistHttp | EventKind::DomainGenerationAlgorithm => {
            convert_stored::<DgaFieldsStoredV0_42, crate::event::DgaFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistKerberos => convert_stored::<
            BlocklistKerberosFieldsStoredV0_42,
            crate::event::BlocklistKerberosFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistLdap | EventKind::LdapPlainText => convert_stored::<
            LdapEventFieldsStoredV0_42,
            crate::event::LdapEventFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistMalformedDns => convert_stored::<
            BlocklistMalformedDnsFieldsStoredV0_45,
            crate::event::BlocklistMalformedDnsFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistMqtt => convert_stored::<
            BlocklistMqttFieldsStoredV0_42,
            crate::event::BlocklistMqttFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistNfs => convert_stored::<
            BlocklistNfsFieldsStoredV0_42,
            crate::event::BlocklistNfsFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistNtlm => convert_stored::<
            BlocklistNtlmFieldsStoredV0_42,
            crate::event::BlocklistNtlmFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistRadius => convert_stored::<
            BlocklistRadiusFieldsStoredV0_45,
            crate::event::BlocklistRadiusFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistRdp => convert_stored::<
            BlocklistRdpFieldsStoredV0_42,
            crate::event::BlocklistRdpFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistSmb => convert_stored::<
            BlocklistSmbFieldsStoredV0_42,
            crate::event::BlocklistSmbFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistSmtp => convert_stored::<
            BlocklistSmtpFieldsStoredV0_42,
            crate::event::BlocklistSmtpFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistSsh => convert_stored::<
            BlocklistSshFieldsStoredV0_42,
            crate::event::BlocklistSshFieldsStoredV0_46,
        >(bytes),
        EventKind::BlocklistTls | EventKind::SuspiciousTlsTraffic => convert_stored::<
            BlocklistTlsFieldsStoredV0_42,
            crate::event::BlocklistTlsFieldsStoredV0_46,
        >(bytes),
        EventKind::CryptocurrencyMiningPool => convert_stored::<
            CryptocurrencyMiningPoolFieldsStoredV0_42,
            crate::event::CryptocurrencyMiningPoolFieldsStoredV0_46,
        >(bytes),
        EventKind::DnsCovertChannel | EventKind::LockyRansomware => convert_stored::<
            DnsEventFieldsStoredV0_42,
            crate::event::DnsEventFieldsStoredV0_46,
        >(bytes),
        EventKind::ExternalDdos => convert_stored::<
            ExternalDdosFieldsStoredV0_42,
            crate::event::ExternalDdosFieldsStoredV0_46,
        >(bytes),
        EventKind::FtpBruteForce => convert_stored::<
            FtpBruteForceFieldsStoredV0_42,
            crate::event::FtpBruteForceFieldsStoredV0_46,
        >(bytes),
        EventKind::HttpThreat => convert_stored::<
            HttpThreatFieldsStoredV0_44,
            crate::event::HttpThreatFieldsStoredV0_46,
        >(bytes),
        EventKind::LdapBruteForce => convert_stored::<
            LdapBruteForceFieldsStoredV0_42,
            crate::event::LdapBruteForceFieldsStoredV0_46,
        >(bytes),
        EventKind::MultiHostPortScan => convert_stored::<
            MultiHostPortScanFieldsStoredV0_42,
            crate::event::MultiHostPortScanFieldsStoredV0_46,
        >(bytes),
        EventKind::NetworkThreat => convert_stored::<
            NetworkThreatFieldsStoredV0_45,
            crate::event::NetworkThreatFieldsStoredV0_46,
        >(bytes),
        EventKind::NonBrowser | EventKind::TorConnection => convert_stored::<
            HttpEventFieldsStoredV0_42,
            crate::event::HttpEventFieldsStoredV0_46,
        >(bytes),
        EventKind::PortScan => convert_stored::<
            PortScanFieldsStoredV0_42,
            crate::event::PortScanFieldsStoredV0_46,
        >(bytes),
        EventKind::RdpBruteForce => convert_stored::<
            RdpBruteForceFieldsStoredV0_42,
            crate::event::RdpBruteForceFieldsStoredV0_46,
        >(bytes),
        EventKind::RepeatedHttpSessions => convert_stored::<
            RepeatedHttpSessionsFieldsStoredV0_42,
            crate::event::RepeatedHttpSessionsFieldsStoredV0_46,
        >(bytes),
        EventKind::UnusualDestinationPattern => convert_stored::<
            UnusualDestinationPatternFieldsStoredV0_45,
            crate::event::UnusualDestinationPatternFieldsStoredV0_46,
        >(bytes),
        EventKind::ExtraThreat | EventKind::WindowsThreat => Ok(bytes.to_vec()),
    }
}

/// Validates that bytes use the output schema of the 0.46 event migration.
pub(super) fn validate_event_stored_schema_v0_46(kind: EventKind, bytes: &[u8]) -> Result<()> {
    fn validate<T>(bytes: &[u8]) -> Result<()>
    where
        T: for<'de> Deserialize<'de>,
    {
        bincode::deserialize::<T>(bytes)
            .map(|_| ())
            .context("failed to deserialize event fields as the 0.46 stored schema")
    }

    match kind {
        EventKind::BlocklistBootp => {
            validate::<crate::event::BlocklistBootpFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistConn | EventKind::TorConnectionConn => {
            validate::<crate::event::BlocklistConnFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistDceRpc => {
            validate::<crate::event::BlocklistDceRpcFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistDhcp => validate::<crate::event::BlocklistDhcpFieldsStoredV0_46>(bytes),
        EventKind::BlocklistDns => validate::<crate::event::BlocklistDnsFieldsStoredV0_46>(bytes),
        EventKind::BlocklistFtp | EventKind::FtpPlainText => {
            validate::<crate::event::FtpEventFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistHttp | EventKind::DomainGenerationAlgorithm => {
            validate::<crate::event::DgaFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistKerberos => {
            validate::<crate::event::BlocklistKerberosFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistLdap | EventKind::LdapPlainText => {
            validate::<crate::event::LdapEventFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistMalformedDns => {
            validate::<crate::event::BlocklistMalformedDnsFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistMqtt => validate::<crate::event::BlocklistMqttFieldsStoredV0_46>(bytes),
        EventKind::BlocklistNfs => validate::<crate::event::BlocklistNfsFieldsStoredV0_46>(bytes),
        EventKind::BlocklistNtlm => validate::<crate::event::BlocklistNtlmFieldsStoredV0_46>(bytes),
        EventKind::BlocklistRadius => {
            validate::<crate::event::BlocklistRadiusFieldsStoredV0_46>(bytes)
        }
        EventKind::BlocklistRdp => validate::<crate::event::BlocklistRdpFieldsStoredV0_46>(bytes),
        EventKind::BlocklistSmb => validate::<crate::event::BlocklistSmbFieldsStoredV0_46>(bytes),
        EventKind::BlocklistSmtp => validate::<crate::event::BlocklistSmtpFieldsStoredV0_46>(bytes),
        EventKind::BlocklistSsh => validate::<crate::event::BlocklistSshFieldsStoredV0_46>(bytes),
        EventKind::BlocklistTls | EventKind::SuspiciousTlsTraffic => {
            validate::<crate::event::BlocklistTlsFieldsStoredV0_46>(bytes)
        }
        EventKind::CryptocurrencyMiningPool => {
            validate::<crate::event::CryptocurrencyMiningPoolFieldsStoredV0_46>(bytes)
        }
        EventKind::DnsCovertChannel | EventKind::LockyRansomware => {
            validate::<crate::event::DnsEventFieldsStoredV0_46>(bytes)
        }
        EventKind::ExternalDdos => validate::<crate::event::ExternalDdosFieldsStoredV0_46>(bytes),
        EventKind::ExtraThreat => validate::<crate::event::ExtraThreatFieldsStoredV0_46>(bytes),
        EventKind::FtpBruteForce => validate::<crate::event::FtpBruteForceFieldsStoredV0_46>(bytes),
        EventKind::HttpThreat => validate::<crate::event::HttpThreatFieldsStoredV0_46>(bytes),
        EventKind::LdapBruteForce => {
            validate::<crate::event::LdapBruteForceFieldsStoredV0_46>(bytes)
        }
        EventKind::MultiHostPortScan => {
            validate::<crate::event::MultiHostPortScanFieldsStoredV0_46>(bytes)
        }
        EventKind::NetworkThreat => validate::<crate::event::NetworkThreatFieldsStoredV0_46>(bytes),
        EventKind::NonBrowser | EventKind::TorConnection => {
            validate::<crate::event::HttpEventFieldsStoredV0_46>(bytes)
        }
        EventKind::PortScan => validate::<crate::event::PortScanFieldsStoredV0_46>(bytes),
        EventKind::RdpBruteForce => validate::<crate::event::RdpBruteForceFieldsStoredV0_46>(bytes),
        EventKind::RepeatedHttpSessions => {
            validate::<crate::event::RepeatedHttpSessionsFieldsStoredV0_46>(bytes)
        }
        EventKind::UnusualDestinationPattern => {
            validate::<crate::event::UnusualDestinationPatternFieldsStoredV0_46>(bytes)
        }
        EventKind::WindowsThreat => validate::<crate::event::WindowsThreatFieldsStoredV0_46>(bytes),
    }
}

// ============================================================================
// Sampling policy, model, training definition and node structures of the
// 0.56 format, which the 0.57.0 migration reads
// ============================================================================

/// The stored `SamplingPolicy` record up to database format 0.56, with
/// `immutable` and without the customer, the state, the assignee and the
/// Data Store.
///
/// It describes a released layout and must never be modified; the committed
/// `sampling_policy_v0_56_literal_bytes.bin` fixture pins it to the release.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct SamplingPolicyV0_56 {
    pub id: u32,
    pub name: String,
    pub kind: crate::SamplingKind,
    pub interval: crate::SamplingInterval,
    pub period: crate::SamplingPeriod,
    pub offset: i32,
    pub src_ip: Option<std::net::IpAddr>,
    pub dst_ip: Option<std::net::IpAddr>,
    pub node: Option<String>,
    pub column: Option<u32>,
    pub immutable: bool,
    pub creation_time: String,
}

impl SamplingPolicyV0_56 {
    /// Converts the record to the 0.57 layout: a `Fixed` policy of
    /// `customer_id`, with no assignee and no Data Store. `immutable` is
    /// dropped.
    pub(crate) fn into_fixed(self, customer_id: Option<u32>) -> SamplingPolicyV0_61 {
        SamplingPolicyValue {
            id: self.id,
            name: self.name,
            kind: self.kind,
            interval: self.interval,
            period: self.period,
            offset: self.offset,
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            node: self.node,
            column: self.column,
            customer_id,
            state: crate::PolicyState::Fixed,
            assignee: None,
            data_store: None,
            creation_time: self.creation_time,
        }
    }
}

/// The stored `SamplingPolicy` record of database formats 0.57 through
/// 0.62, generic over how a timestamp is stored: chrono's default serde
/// string through 0.61, `i64` Unix-epoch nanoseconds in 0.62.
///
/// It describes released layouts and must never be modified; the committed
/// `sampling_policy_literal_bytes_v0_61.bin` and
/// `sampling_policy_literal_bytes_v0_62.bin` fixtures pin them to the releases.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct SamplingPolicyValue<Ts> {
    pub id: u32,
    pub name: String,
    pub kind: crate::SamplingKind,
    pub interval: crate::SamplingInterval,
    pub period: crate::SamplingPeriod,
    pub offset: i32,
    pub src_ip: Option<std::net::IpAddr>,
    pub dst_ip: Option<std::net::IpAddr>,
    pub node: Option<String>,
    pub column: Option<u32>,
    pub customer_id: Option<u32>,
    pub state: crate::PolicyState,
    pub assignee: Option<crate::ModelInstance>,
    pub data_store: Option<String>,
    pub creation_time: Ts,
}

/// The stored `SamplingPolicy` record of database formats 0.57 through 0.61.
pub(crate) type SamplingPolicyV0_61 = SamplingPolicyValue<String>;

impl SamplingPolicyV0_61 {
    /// Returns the stored bytes of the record.
    pub(crate) fn value(&self) -> Vec<u8> {
        use bincode::Options;
        bincode::DefaultOptions::new()
            .serialize(self)
            .expect("serializable")
    }
}

impl<Ts> SamplingPolicyValue<Ts> {
    /// Converts every timestamp of the record with `ts`.
    pub(crate) fn map_timestamps<U>(
        self,
        ts: &mut TimestampConverter<'_, Ts, U>,
    ) -> Result<SamplingPolicyValue<U>> {
        Ok(SamplingPolicyValue {
            id: self.id,
            name: self.name,
            kind: self.kind,
            interval: self.interval,
            period: self.period,
            offset: self.offset,
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            node: self.node,
            column: self.column,
            customer_id: self.customer_id,
            state: self.state,
            assignee: self.assignee,
            data_store: self.data_store,
            creation_time: ts(self.creation_time)?,
        })
    }
}

/// The stored `Model` record of database formats 0.55 and 0.56, before
/// `trained_sources` was appended.
///
/// The field order is the wire order, and the 0.57 record appends one field,
/// so an encoded value of this layout is a strict prefix of a 0.57 one.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ModelV0_56 {
    pub id: u32,
    pub name: String,
    pub version: i32,
    pub kind: String,
    pub max_event_id_num: i32,
    pub classification_id: Option<i64>,
    pub event_kind: String,
    pub customer_id: u32,
    pub instance: Option<crate::ModelInstance>,
    pub trained_at: String,
    pub classifier_generation: u64,
    pub trained_run_id: u32,
    pub trained_definition: String,
    pub previous: Option<PreviousTrainingV0_61>,
    pub clusters_applied: Option<i64>,
}

impl ModelV0_56 {
    /// Converts the record to the 0.57 layout with `trained_sources`.
    pub(crate) fn with_trained_sources(self, trained_sources: Vec<String>) -> ModelV0_61 {
        ModelValue {
            id: self.id,
            name: self.name,
            version: self.version,
            kind: self.kind,
            max_event_id_num: self.max_event_id_num,
            classification_id: self.classification_id,
            event_kind: self.event_kind,
            customer_id: self.customer_id,
            instance: self.instance,
            trained_at: self.trained_at,
            classifier_generation: self.classifier_generation,
            trained_run_id: self.trained_run_id,
            trained_definition: self.trained_definition,
            previous: self.previous,
            clusters_applied: self.clusters_applied,
            trained_sources,
        }
    }
}

/// The stored summary of a model's previous training result in database
/// formats 0.55 through 0.62, generic over how a timestamp is stored:
/// chrono's default serde string through 0.61, `i64` Unix-epoch nanoseconds
/// in 0.62.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct PreviousTrainingValue<Ts> {
    pub trained_at: Ts,
    pub version: i32,
    pub classifier_generation: u64,
    pub trained_run_id: u32,
    pub trained_definition: String,
}

/// The stored summary of a model's previous training result in database
/// formats 0.55 through 0.61.
pub(crate) type PreviousTrainingV0_61 = PreviousTrainingValue<String>;

impl<Ts> PreviousTrainingValue<Ts> {
    fn map_timestamps<U>(
        self,
        ts: &mut TimestampConverter<'_, Ts, U>,
    ) -> Result<PreviousTrainingValue<U>> {
        Ok(PreviousTrainingValue {
            trained_at: ts(self.trained_at)?,
            version: self.version,
            classifier_generation: self.classifier_generation,
            trained_run_id: self.trained_run_id,
            trained_definition: self.trained_definition,
        })
    }
}

/// The stored `Model` record of database formats 0.57 through 0.62, generic
/// over how a timestamp is stored: chrono's default serde string through
/// 0.61, `i64` Unix-epoch nanoseconds in 0.62.
///
/// It describes released layouts and must never be modified.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ModelValue<Ts> {
    pub id: u32,
    pub name: String,
    pub version: i32,
    pub kind: String,
    pub max_event_id_num: i32,
    pub classification_id: Option<i64>,
    pub event_kind: String,
    pub customer_id: u32,
    pub instance: Option<crate::ModelInstance>,
    pub trained_at: Ts,
    pub classifier_generation: u64,
    pub trained_run_id: u32,
    pub trained_definition: String,
    pub previous: Option<PreviousTrainingValue<Ts>>,
    pub clusters_applied: Option<i64>,
    pub trained_sources: Vec<String>,
}

/// The stored `Model` record of database formats 0.57 through 0.61.
pub(crate) type ModelV0_61 = ModelValue<String>;

impl ModelV0_61 {
    /// Returns the stored bytes of the record.
    pub(crate) fn value(&self) -> Vec<u8> {
        use bincode::Options;
        bincode::DefaultOptions::new()
            .serialize(self)
            .expect("serializable")
    }
}

impl<Ts> ModelValue<Ts> {
    /// Converts every timestamp of the record with `ts`.
    pub(crate) fn map_timestamps<U>(
        self,
        ts: &mut TimestampConverter<'_, Ts, U>,
    ) -> Result<ModelValue<U>> {
        Ok(ModelValue {
            id: self.id,
            name: self.name,
            version: self.version,
            kind: self.kind,
            max_event_id_num: self.max_event_id_num,
            classification_id: self.classification_id,
            event_kind: self.event_kind,
            customer_id: self.customer_id,
            instance: self.instance,
            trained_at: ts(self.trained_at)?,
            classifier_generation: self.classifier_generation,
            trained_run_id: self.trained_run_id,
            trained_definition: self.trained_definition,
            previous: self
                .previous
                .map(|previous| previous.map_timestamps(ts))
                .transpose()?,
            clusters_applied: self.clusters_applied,
            trained_sources: self.trained_sources,
        })
    }
}

/// The stored `TrainingDefinition` record of database formats 0.55 and 0.56,
/// mirroring the live record with its component types.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct TrainingDefinitionV0_56 {
    pub name: String,
    pub customer_id: u32,
    pub instance: Option<crate::ModelInstance>,
    pub method: crate::ModelMethod,
    pub event_kind: String,
    pub sources: Vec<String>,
    pub indicator: Option<String>,
    pub definition: String,
    pub cloning: bool,
    pub last_run: Option<crate::RunId>,
    pub created_at: String,
    pub updated_at: String,
}

/// The stored node profile of database format 0.56.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct NodeProfileV0_56 {
    pub customer_id: u32,
    pub description: String,
    pub hostname: String,
}

/// The stored node record of database formats 0.56 and 0.57, mirroring the
/// live `tables::InnerNode`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct NodeV0_56 {
    pub id: u32,
    pub name: String,
    pub name_draft: Option<String>,
    pub profile: Option<NodeProfileV0_56>,
    pub profile_draft: Option<NodeProfileV0_56>,
    pub creation_time: String,
    pub agents: Vec<String>,
    pub external_services: Vec<String>,
}

/// One `[[detectors]]` reference of an engine document, as the `engine
/// instances` rows of database format 0.57 store it.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct EngineDetectorRefV0_57 {
    pub id: i32,
    pub model: String,
    pub sources: Vec<String>,
    pub indicator: Option<String>,
}

/// The references of one engine document, as the `engine instances` rows of
/// database format 0.57 store them.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct EngineDocumentRefsV0_57 {
    pub detectors: Vec<EngineDetectorRefV0_57>,
}

/// The leading fields of an `engine instances` row of database format 0.57:
/// its stopped state and the references of its applied and pending
/// documents. The detector statuses the row stores after them are not read,
/// so a row is decoded with trailing bytes allowed.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct EngineInstanceRefsV0_57 {
    pub stopped: bool,
    pub applied: EngineDocumentRefsV0_57,
    pub pending: EngineDocumentRefsV0_57,
}

impl EngineInstanceRefsV0_57 {
    /// Returns the highest detector id either document names, or 0 if that
    /// is lower or neither names one.
    pub(crate) fn last_detector_id(&self) -> i32 {
        self.applied
            .detectors
            .iter()
            .chain(&self.pending.detectors)
            .map(|detector| detector.id)
            .fold(0, i32::max)
    }
}

/// The stored value of a customer deletion job in database formats 0.47
/// through 0.58: its service results alone, without the periodic time series
/// IDs and abandoned hosts that the 0.59 layout appends.
pub(crate) type CustomerDataDeletionJobValueV0_58 = Vec<crate::CustomerDataDeletionServiceResult>;

// ============================================================================
// Table values of the 0.61 format, which the 0.62.0 migration reads, and of
// the 0.62 format it writes
// ============================================================================

/// Converts one timestamp of a record from one stored form to another, such
/// as a 0.61 string to 0.62 `i64` nanoseconds.
pub(crate) type TimestampConverter<'a, Ts, U> = dyn FnMut(Ts) -> Result<U> + 'a;

/// The stored `TriageResponse` record of database formats 0.61 (`String`
/// timestamps) and 0.62 (`i64` nanoseconds).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct TriageResponseValue<Ts> {
    pub id: u32,
    pub key: Vec<u8>,
    pub sensor: String,
    pub time: Ts,
    pub tag_ids: Vec<u32>,
    pub remarks: String,
    pub creation_time: Ts,
    pub last_modified_time: Ts,
}

/// The stored `TriageResponse` record of database format 0.61.
pub(crate) type TriageResponseV0_61 = TriageResponseValue<String>;

impl<Ts> TriageResponseValue<Ts> {
    /// Converts every timestamp of the record with `ts`.
    pub(crate) fn map_timestamps<U>(
        self,
        ts: &mut TimestampConverter<'_, Ts, U>,
    ) -> Result<TriageResponseValue<U>> {
        Ok(TriageResponseValue {
            id: self.id,
            key: self.key,
            sensor: self.sensor,
            time: ts(self.time)?,
            tag_ids: self.tag_ids,
            remarks: self.remarks,
            creation_time: ts(self.creation_time)?,
            last_modified_time: ts(self.last_modified_time)?,
        })
    }
}

/// The stored value of a `cluster` or `previous cluster` row of database
/// formats 0.61 (chrono `NaiveDateTime` strings) and 0.62 (`i64`
/// nanoseconds).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ClusterValue<Ts> {
    pub category_id: i32,
    pub detector_id: i32,
    pub event_ids: Vec<i64>,
    pub sensors: Vec<String>,
    pub labels: Option<Vec<String>>,
    pub qualifier_id: i32,
    pub status_id: i32,
    pub signature: String,
    pub size: i64,
    pub score: Option<f64>,
    pub last_modification_time: Option<Ts>,
}

/// The stored cluster value of database format 0.61.
pub(crate) type ClusterValueV0_61 = ClusterValue<String>;

impl<Ts> ClusterValue<Ts> {
    /// Converts every timestamp of the record with `ts`.
    pub(crate) fn map_timestamps<U>(
        self,
        ts: &mut TimestampConverter<'_, Ts, U>,
    ) -> Result<ClusterValue<U>> {
        Ok(ClusterValue {
            category_id: self.category_id,
            detector_id: self.detector_id,
            event_ids: self.event_ids,
            sensors: self.sensors,
            labels: self.labels,
            qualifier_id: self.qualifier_id,
            status_id: self.status_id,
            signature: self.signature,
            size: self.size,
            score: self.score,
            last_modification_time: self.last_modification_time.map(ts).transpose()?,
        })
    }
}

/// The stored node record of database formats 0.61 (`String` timestamps)
/// and 0.62 (`i64` nanoseconds), mirroring the live `tables::InnerNode`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct NodeValue<Ts> {
    pub id: u32,
    pub name: String,
    pub name_draft: Option<String>,
    pub profile: Option<crate::NodeProfile>,
    pub profile_draft: Option<crate::NodeProfile>,
    pub creation_time: Ts,
    pub agents: Vec<String>,
    pub external_services: Vec<String>,
}

/// The stored node record of database format 0.61.
pub(crate) type NodeV0_61 = NodeValue<String>;

impl<Ts> NodeValue<Ts> {
    /// Converts every timestamp of the record with `ts`.
    pub(crate) fn map_timestamps<U>(
        self,
        ts: &mut TimestampConverter<'_, Ts, U>,
    ) -> Result<NodeValue<U>> {
        Ok(NodeValue {
            id: self.id,
            name: self.name,
            name_draft: self.name_draft,
            profile: self.profile,
            profile_draft: self.profile_draft,
            creation_time: ts(self.creation_time)?,
            agents: self.agents,
            external_services: self.external_services,
        })
    }
}

/// The stored network record of database formats 0.61 (`String`
/// timestamps) and 0.62 (`i64` nanoseconds).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct NetworkValue<Ts> {
    pub id: u32,
    pub description: String,
    pub networks: HostNetworkGroup,
    pub tag_ids: Vec<u32>,
    pub creation_time: Ts,
}

/// The stored network record of database format 0.61.
pub(crate) type NetworkValueV0_61 = NetworkValue<String>;

impl<Ts> NetworkValue<Ts> {
    /// Converts every timestamp of the record with `ts`.
    pub(crate) fn map_timestamps<U>(
        self,
        ts: &mut TimestampConverter<'_, Ts, U>,
    ) -> Result<NetworkValue<U>> {
        Ok(NetworkValue {
            id: self.id,
            description: self.description,
            networks: self.networks,
            tag_ids: self.tag_ids,
            creation_time: ts(self.creation_time)?,
        })
    }
}

/// The stored `NetworkListSet` of database formats 0.61 (`String`
/// timestamps) and 0.62 (`i64` nanoseconds).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct NetworkListSetValue<Ts> {
    pub revision: u64,
    pub allowlist: Vec<crate::NetworkListEntry>,
    pub blocklist: Vec<crate::NetworkListEntry>,
    pub updated_at: Ts,
}

/// The stored `NetworkListSet` of database format 0.61.
pub(crate) type NetworkListSetV0_61 = NetworkListSetValue<String>;

impl<Ts> NetworkListSetValue<Ts> {
    /// Converts every timestamp of the record with `ts`.
    pub(crate) fn map_timestamps<U>(
        self,
        ts: &mut TimestampConverter<'_, Ts, U>,
    ) -> Result<NetworkListSetValue<U>> {
        Ok(NetworkListSetValue {
            revision: self.revision,
            allowlist: self.allowlist,
            blocklist: self.blocklist,
            updated_at: ts(self.updated_at)?,
        })
    }
}

/// The stored `OwnedNetworkSet` of database formats 0.61 (`String`
/// timestamps) and 0.62 (`i64` nanoseconds).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct OwnedNetworkSetValue<Ts> {
    pub revision: u64,
    pub networks: Vec<crate::OwnedNetwork>,
    pub updated_at: Ts,
}

/// The stored `OwnedNetworkSet` of database format 0.61.
pub(crate) type OwnedNetworkSetV0_61 = OwnedNetworkSetValue<String>;

impl<Ts> OwnedNetworkSetValue<Ts> {
    /// Converts every timestamp of the record with `ts`.
    pub(crate) fn map_timestamps<U>(
        self,
        ts: &mut TimestampConverter<'_, Ts, U>,
    ) -> Result<OwnedNetworkSetValue<U>> {
        Ok(OwnedNetworkSetValue {
            revision: self.revision,
            networks: self.networks,
            updated_at: ts(self.updated_at)?,
        })
    }
}

/// The stored `TrafficFilter` of database formats 0.61 (`String`
/// timestamps) and 0.62 (`i64` nanoseconds).
///
/// `rules` is a map in the live struct. Bincode encodes a map exactly as a
/// sequence of key-value pairs, so it is read here as one, which keeps the
/// rules in their stored order instead of a hash map's.
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct TrafficFilterValue<Ts> {
    pub host_fqdn: String,
    pub rules: Vec<(ipnet::IpNet, crate::ProtocolPorts)>,
    pub last_modification_time: Ts,
    pub update_time: Option<Ts>,
    pub description: Option<String>,
}

/// The stored `TrafficFilter` of database format 0.61.
pub(crate) type TrafficFilterV0_61 = TrafficFilterValue<String>;

impl<Ts> TrafficFilterValue<Ts> {
    /// Converts every timestamp of the record with `ts`.
    pub(crate) fn map_timestamps<U>(
        self,
        ts: &mut TimestampConverter<'_, Ts, U>,
    ) -> Result<TrafficFilterValue<U>> {
        Ok(TrafficFilterValue {
            host_fqdn: self.host_fqdn,
            rules: self.rules,
            last_modification_time: ts(self.last_modification_time)?,
            update_time: self.update_time.map(&mut *ts).transpose()?,
            description: self.description,
        })
    }
}

/// The stored `TrainingDefinition` record of database formats 0.61
/// (`String` timestamps) and 0.62 (`i64` nanoseconds).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct TrainingDefinitionValue<Ts> {
    pub name: String,
    pub customer_id: u32,
    pub instance: Option<crate::ModelInstance>,
    pub method: crate::ModelMethod,
    pub event_kind: String,
    pub sources: Vec<String>,
    pub indicator: Option<String>,
    pub definition: String,
    pub cloning: bool,
    pub last_run: Option<crate::RunId>,
    pub created_at: Ts,
    pub updated_at: Ts,
}

/// The stored `TrainingDefinition` record of database format 0.61.
pub(crate) type TrainingDefinitionV0_61 = TrainingDefinitionValue<String>;

impl<Ts> TrainingDefinitionValue<Ts> {
    /// Converts every timestamp of the record with `ts`.
    pub(crate) fn map_timestamps<U>(
        self,
        ts: &mut TimestampConverter<'_, Ts, U>,
    ) -> Result<TrainingDefinitionValue<U>> {
        Ok(TrainingDefinitionValue {
            name: self.name,
            customer_id: self.customer_id,
            instance: self.instance,
            method: self.method,
            event_kind: self.event_kind,
            sources: self.sources,
            indicator: self.indicator,
            definition: self.definition,
            cloning: self.cloning,
            last_run: self.last_run,
            created_at: ts(self.created_at)?,
            updated_at: ts(self.updated_at)?,
        })
    }
}

/// The stored `ModelRun` record of database formats 0.61 (`String`
/// timestamps) and 0.62 (`i64` nanoseconds).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ModelRunValue<Ts> {
    pub id: crate::RunId,
    pub kind: crate::RunKind,
    pub model: String,
    pub instance: crate::ModelInstance,
    pub state: crate::RunState,
    pub reason: Option<String>,
    pub requested_at: Ts,
    pub updated_at: Ts,
}

/// The stored `ModelRun` record of database format 0.61.
pub(crate) type ModelRunV0_61 = ModelRunValue<String>;

impl<Ts> ModelRunValue<Ts> {
    /// Converts every timestamp of the record with `ts`.
    pub(crate) fn map_timestamps<U>(
        self,
        ts: &mut TimestampConverter<'_, Ts, U>,
    ) -> Result<ModelRunValue<U>> {
        Ok(ModelRunValue {
            id: self.id,
            kind: self.kind,
            model: self.model,
            instance: self.instance,
            state: self.state,
            reason: self.reason,
            requested_at: ts(self.requested_at)?,
            updated_at: ts(self.updated_at)?,
        })
    }
}

/// The stored `DetectorStatus` of database formats 0.61 (`String`
/// timestamps) and 0.62 (`i64` nanoseconds).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct DetectorStatusValue<Ts> {
    pub state: crate::DetectorState,
    pub finished_at: Option<Ts>,
    pub outcome: Option<crate::RoundOutcome>,
    pub reason: Option<String>,
    pub events: u64,
    pub sources: Vec<crate::DetectorSourceStatus>,
    pub reported_at: Ts,
}

/// The stored `engine instances` row of database formats 0.61 (`String`
/// timestamps) and 0.62 (`i64` nanoseconds), mirroring the live
/// `tables::EngineInstanceRow`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct EngineInstanceRowValue<Ts> {
    pub stopped: bool,
    pub applied: crate::EngineDocumentRefs,
    pub pending: crate::EngineDocumentRefs,
    pub statuses: std::collections::BTreeMap<i32, DetectorStatusValue<Ts>>,
}

/// The stored `engine instances` row of database format 0.61.
pub(crate) type EngineInstanceRowV0_61 = EngineInstanceRowValue<String>;

impl<Ts> EngineInstanceRowValue<Ts> {
    /// Converts every timestamp of the record with `ts`.
    pub(crate) fn map_timestamps<U>(
        self,
        ts: &mut TimestampConverter<'_, Ts, U>,
    ) -> Result<EngineInstanceRowValue<U>> {
        let statuses = self
            .statuses
            .into_iter()
            .map(|(id, status)| {
                Ok((
                    id,
                    DetectorStatusValue {
                        state: status.state,
                        finished_at: status.finished_at.map(&mut *ts).transpose()?,
                        outcome: status.outcome,
                        reason: status.reason,
                        events: status.events,
                        sources: status.sources,
                        reported_at: ts(status.reported_at)?,
                    },
                ))
            })
            .collect::<Result<_>>()?;
        Ok(EngineInstanceRowValue {
            stopped: self.stopped,
            applied: self.applied,
            pending: self.pending,
            statuses,
        })
    }
}

/// The stored `SystemLogCollectorRefusal` of database formats 0.61
/// (`String` timestamps) and 0.62 (`i64` nanoseconds).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct SystemLogCollectorRefusalValue<Ts> {
    pub at: Ts,
    pub message: String,
}

/// The stored `SystemLogCollector` of database formats 0.61 (`String`
/// timestamps) and 0.62 (`i64` nanoseconds).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct SystemLogCollectorValue<Ts> {
    pub host: String,
    pub instance: Option<u32>,
    pub install_keys: Vec<String>,
    pub installed_version: Option<String>,
    pub installed_commit: Option<String>,
    pub data_store: Option<String>,
    pub config: Option<String>,
    pub last_refusal: Option<SystemLogCollectorRefusalValue<Ts>>,
}

/// The stored `SystemLogCollector` of database format 0.61.
pub(crate) type SystemLogCollectorV0_61 = SystemLogCollectorValue<String>;

impl<Ts> SystemLogCollectorValue<Ts> {
    /// Converts every timestamp of the record with `ts`.
    pub(crate) fn map_timestamps<U>(
        self,
        ts: &mut TimestampConverter<'_, Ts, U>,
    ) -> Result<SystemLogCollectorValue<U>> {
        Ok(SystemLogCollectorValue {
            host: self.host,
            instance: self.instance,
            install_keys: self.install_keys,
            installed_version: self.installed_version,
            installed_commit: self.installed_commit,
            data_store: self.data_store,
            config: self.config,
            last_refusal: self
                .last_refusal
                .map(|refusal| {
                    Ok::<_, anyhow::Error>(SystemLogCollectorRefusalValue {
                        at: ts(refusal.at)?,
                        message: refusal.message,
                    })
                })
                .transpose()?,
        })
    }
}
