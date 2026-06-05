//! Old data structures for migration purposes.
//!
//! These structures represent the schemas from previous releases
//! and must not be modified. They are used to migrate data from
//! old formats to new formats.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    event::{
        EventKind, bootp, conn, dcerpc, dhcp, dns, ftp, http, kerberos, ldap, malformed_dns, mqtt,
        network, nfs, ntlm, radius, rdp, smb, smtp, ssh, tls, unusual_destination_pattern,
    },
    types::HostNetworkGroup,
};

/// `AllowNetwork` structure from version 0.42.x (before `customer_id` was added)
///
/// In version 0.42.x, `AllowNetwork` used only name as the key.
/// From 0.43.x, `customer_id` was added and the key became `customer_id` + name.
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct AllowNetworkV0_42 {
    pub(crate) id: u32,
    pub(crate) name: String,
    pub(crate) networks: HostNetworkGroup,
    pub(crate) description: String,
}

/// `BlockNetwork` structure from version 0.42.x (before `customer_id` was added)
///
/// In version 0.42.x, `BlockNetwork` used only name as the key.
/// From 0.43.x, `customer_id` was added and the key became `customer_id` + name.
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct BlockNetworkV0_42 {
    pub(crate) id: u32,
    pub(crate) name: String,
    pub(crate) networks: HostNetworkGroup,
    pub(crate) description: String,
}

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
    pub(crate) creation_time: DateTime<Utc>,
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
    pub(crate) creation_time: DateTime<Utc>,
    pub(crate) customer_id: Option<u32>,
}

impl From<TriagePolicyV0_44> for crate::TriagePolicy {
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

// ============================================================================
// Old event structures for migration
// ============================================================================

use std::net::IpAddr;

use chrono::serde::ts_nanoseconds;

use crate::EventCategory;

/// `BlocklistDceRpcFieldsStored` structure from version 0.42.x.
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

/// `BlocklistDhcpFieldsStored` structure from version 0.42.x
/// (before `options` field was added)
///
/// In 0.42.x, `BlocklistDhcpFieldsStored` did not have an `options` field.
/// From 0.44.x, `options: Vec<(u8, Vec<u8>)>` was added to the stored schema.
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

/// `HttpThreatFieldsStored` structure from version 0.43.x
/// (before `cluster_id` type change).
/// In 0.43.x, `cluster_id` was `Option<usize>`. From 0.44.x, it changed to
/// `Option<u32>` in the stored schema.
///
/// Note: Other event types (`NetworkThreat`, `WindowsThreat`, `ExtraThreat`) are not generated
/// on production servers, so their migration structures are not needed.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct HttpThreatFieldsStoredV0_43 {
    #[serde(with = "ts_nanoseconds")]
    pub time: DateTime<Utc>,
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
    pub cluster_id: Option<usize>, // OLD TYPE
    pub attack_kind: String,
    pub confidence: f32,
    pub category: Option<EventCategory>,
}

// ============================================================================
// Pre-0.46 stored event country-code migration
// ============================================================================

/// Converts pre-0.46 stored event bytes into the current stored schema.
///
/// This is migration-only logic. Unlike [`convert_for_storage`], the input is
/// already an internal stored record, not the producer-facing `*Fields` schema.
pub(crate) fn convert_legacy_stored_for_country_codes(
    kind: EventKind,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    macro_rules! serialize_current {
        ($current:expr) => {
            bincode::serialize(&$current).context("failed to serialize current stored schema")
        };
    }

    macro_rules! convert_pair {
        ($bytes:expr, $old_module:ident::$old:ident, $new_module:ident::$new:ident, [$($field:ident,)*]) => {{
            let old: $old_module::$old = bincode::deserialize($bytes)
                .context("failed to deserialize event fields as the previous stored schema")?;
            let current = $new_module::$new {
                $($field: old.$field,)*
                orig_country_code: crate::util::COUNTRY_CODE_PENDING,
                resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            };
            serialize_current!(current)
        }};
    }

    macro_rules! convert_resp_vector {
        ($bytes:expr, $old_module:ident::$old:ident, $new_module:ident::$new:ident, [$($field:ident,)*]) => {{
            let old: $old_module::$old = bincode::deserialize($bytes)
                .context("failed to deserialize event fields as the previous stored schema")?;
            let resp_country_codes =
                vec![crate::util::COUNTRY_CODE_PENDING; old.resp_addrs.len()];
            let current = $new_module::$new {
                $($field: old.$field,)*
                orig_country_code: crate::util::COUNTRY_CODE_PENDING,
                resp_country_codes,
            };
            serialize_current!(current)
        }};
    }

    macro_rules! convert_external_ddos {
        ($bytes:expr, $old_module:ident::$old:ident, $new_module:ident::$new:ident, [$($field:ident,)*]) => {{
            let old: $old_module::$old = bincode::deserialize($bytes)
                .context("failed to deserialize event fields as the previous stored schema")?;
            let orig_country_codes =
                vec![crate::util::COUNTRY_CODE_PENDING; old.orig_addrs.len()];
            let current = $new_module::$new {
                $($field: old.$field,)*
                orig_country_codes,
                resp_country_code: crate::util::COUNTRY_CODE_PENDING,
            };
            serialize_current!(current)
        }};
    }

    macro_rules! convert_unusual_destination_pattern {
        ($bytes:expr, $old_module:ident::$old:ident, $new_module:ident::$new:ident, [$($field:ident,)*]) => {{
            let old: $old_module::$old = bincode::deserialize($bytes)
                .context("failed to deserialize event fields as the previous stored schema")?;
            let resp_country_codes =
                vec![crate::util::COUNTRY_CODE_PENDING; old.destination_ips.len()];
            let current = $new_module::$new {
                $($field: old.$field,)*
                resp_country_codes,
            };
            serialize_current!(current)
        }};
    }

    match kind {
        EventKind::BlocklistBootp => convert_pair!(
            bytes,
            bootp::BlocklistBootpFieldsStoredV0_42,
            bootp::BlocklistBootpFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                op,
                htype,
                hops,
                xid,
                ciaddr,
                yiaddr,
                siaddr,
                giaddr,
                chaddr,
                sname,
                file,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistConn | EventKind::TorConnectionConn => convert_pair!(
            bytes,
            conn::BlocklistConnFieldsStoredV0_42,
            conn::BlocklistConnFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                conn_state,
                start_time,
                duration,
                service,
                orig_bytes,
                resp_bytes,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistDceRpc => convert_pair!(
            bytes,
            dcerpc::BlocklistDceRpcFieldsStoredV0_44,
            dcerpc::BlocklistDceRpcFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                context,
                request,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistDhcp => convert_pair!(
            bytes,
            dhcp::BlocklistDhcpFieldsStoredV0_44,
            dhcp::BlocklistDhcpFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                msg_type,
                ciaddr,
                yiaddr,
                siaddr,
                giaddr,
                subnet_mask,
                router,
                domain_name_server,
                req_ip_addr,
                lease_time,
                server_id,
                param_req_list,
                message,
                renewal_time,
                rebinding_time,
                class_id,
                client_id_type,
                client_id,
                options,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistDns => convert_pair!(
            bytes,
            dns::BlocklistDnsFieldsStoredV0_42,
            dns::BlocklistDnsFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                query,
                answer,
                trans_id,
                rtt,
                qclass,
                qtype,
                rcode,
                aa_flag,
                tc_flag,
                rd_flag,
                ra_flag,
                ttl,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistFtp | EventKind::FtpPlainText => convert_pair!(
            bytes,
            ftp::FtpEventFieldsStoredV0_42,
            ftp::FtpEventFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                user,
                password,
                commands,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistHttp | EventKind::DomainGenerationAlgorithm => convert_pair!(
            bytes,
            http::DgaFieldsStoredV0_42,
            http::DgaFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                method,
                host,
                uri,
                referer,
                version,
                user_agent,
                request_len,
                response_len,
                status_code,
                status_msg,
                username,
                password,
                cookie,
                content_encoding,
                content_type,
                cache_control,
                filenames,
                mime_types,
                body,
                state,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistKerberos => convert_pair!(
            bytes,
            kerberos::BlocklistKerberosFieldsStoredV0_42,
            kerberos::BlocklistKerberosFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                client_time,
                server_time,
                error_code,
                client_realm,
                cname_type,
                cname,
                realm,
                sname_type,
                sname,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistLdap | EventKind::LdapPlainText => convert_pair!(
            bytes,
            ldap::LdapEventFieldsStoredV0_42,
            ldap::LdapEventFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                message_id,
                version,
                opcode,
                result,
                diagnostic_message,
                object,
                argument,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistMalformedDns => convert_pair!(
            bytes,
            malformed_dns::BlocklistMalformedDnsFieldsStoredV0_45,
            malformed_dns::BlocklistMalformedDnsFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                trans_id,
                flags,
                question_count,
                answer_count,
                authority_count,
                additional_count,
                query_count,
                resp_count,
                query_bytes,
                resp_bytes,
                query_body,
                resp_body,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistMqtt => convert_pair!(
            bytes,
            mqtt::BlocklistMqttFieldsStoredV0_42,
            mqtt::BlocklistMqttFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                protocol,
                version,
                client_id,
                connack_reason,
                subscribe,
                suback_reason,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistNfs => convert_pair!(
            bytes,
            nfs::BlocklistNfsFieldsStoredV0_42,
            nfs::BlocklistNfsFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                read_files,
                write_files,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistNtlm => convert_pair!(
            bytes,
            ntlm::BlocklistNtlmFieldsStoredV0_42,
            ntlm::BlocklistNtlmFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                protocol,
                username,
                hostname,
                domainname,
                success,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistRadius => convert_pair!(
            bytes,
            radius::BlocklistRadiusFieldsStoredV0_45,
            radius::BlocklistRadiusFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                id,
                code,
                resp_code,
                auth,
                resp_auth,
                user_name,
                user_passwd,
                chap_passwd,
                nas_ip,
                nas_port,
                state,
                nas_id,
                nas_port_type,
                message,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistRdp => convert_pair!(
            bytes,
            rdp::BlocklistRdpFieldsStoredV0_42,
            rdp::BlocklistRdpFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                cookie,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistSmb => convert_pair!(
            bytes,
            smb::BlocklistSmbFieldsStoredV0_42,
            smb::BlocklistSmbFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                command,
                path,
                service,
                file_name,
                file_size,
                resource_type,
                fid,
                create_time,
                access_time,
                write_time,
                change_time,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistSmtp => convert_pair!(
            bytes,
            smtp::BlocklistSmtpFieldsStoredV0_42,
            smtp::BlocklistSmtpFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                mailfrom,
                date,
                from,
                to,
                subject,
                agent,
                state,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistSsh => convert_pair!(
            bytes,
            ssh::BlocklistSshFieldsStoredV0_42,
            ssh::BlocklistSshFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                client,
                server,
                cipher_alg,
                mac_alg,
                compression_alg,
                kex_alg,
                host_key_alg,
                hassh_algorithms,
                hassh,
                hassh_server_algorithms,
                hassh_server,
                client_shka,
                server_shka,
                confidence,
                category,
            ]
        ),
        EventKind::BlocklistTls | EventKind::SuspiciousTlsTraffic => convert_pair!(
            bytes,
            tls::BlocklistTlsFieldsStoredV0_42,
            tls::BlocklistTlsFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                server_name,
                alpn_protocol,
                ja3,
                version,
                client_cipher_suites,
                client_extensions,
                cipher,
                extensions,
                ja3s,
                serial,
                subject_country,
                subject_org_name,
                subject_common_name,
                validity_not_before,
                validity_not_after,
                subject_alt_name,
                issuer_country,
                issuer_org_name,
                issuer_org_unit_name,
                issuer_common_name,
                last_alert,
                confidence,
                category,
            ]
        ),
        EventKind::CryptocurrencyMiningPool => convert_pair!(
            bytes,
            dns::CryptocurrencyMiningPoolFieldsStoredV0_42,
            dns::CryptocurrencyMiningPoolFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                query,
                answer,
                trans_id,
                rtt,
                qclass,
                qtype,
                rcode,
                aa_flag,
                tc_flag,
                rd_flag,
                ra_flag,
                ttl,
                coins,
                confidence,
                category,
            ]
        ),
        EventKind::DnsCovertChannel | EventKind::LockyRansomware => convert_pair!(
            bytes,
            dns::DnsEventFieldsStoredV0_42,
            dns::DnsEventFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                query,
                answer,
                trans_id,
                rtt,
                qclass,
                qtype,
                rcode,
                aa_flag,
                tc_flag,
                rd_flag,
                ra_flag,
                ttl,
                confidence,
                category,
            ]
        ),
        EventKind::ExternalDdos => convert_external_ddos!(
            bytes,
            conn::ExternalDdosFieldsStoredV0_42,
            conn::ExternalDdosFieldsStoredV0_46,
            [
                sensor, orig_addrs, resp_addr, proto, start_time, end_time, confidence, category,
            ]
        ),
        EventKind::FtpBruteForce => convert_pair!(
            bytes,
            ftp::FtpBruteForceFieldsStoredV0_42,
            ftp::FtpBruteForceFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                resp_addr,
                resp_port,
                proto,
                user_list,
                start_time,
                end_time,
                is_internal,
                confidence,
                category,
            ]
        ),
        EventKind::HttpThreat => convert_pair!(
            bytes,
            http::HttpThreatFieldsStoredV0_42,
            http::HttpThreatFieldsStoredV0_46,
            [
                time,
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                method,
                host,
                uri,
                referer,
                version,
                user_agent,
                request_len,
                response_len,
                status_code,
                status_msg,
                username,
                password,
                cookie,
                content_encoding,
                content_type,
                cache_control,
                filenames,
                mime_types,
                body,
                state,
                db_name,
                rule_id,
                matched_to,
                cluster_id,
                attack_kind,
                confidence,
                category,
            ]
        ),
        EventKind::LdapBruteForce => convert_pair!(
            bytes,
            ldap::LdapBruteForceFieldsStoredV0_42,
            ldap::LdapBruteForceFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                resp_addr,
                resp_port,
                proto,
                user_pw_list,
                start_time,
                end_time,
                confidence,
                category,
            ]
        ),
        EventKind::MultiHostPortScan => convert_resp_vector!(
            bytes,
            conn::MultiHostPortScanFieldsStoredV0_42,
            conn::MultiHostPortScanFieldsStoredV0_46,
            [
                sensor, orig_addr, resp_addrs, resp_port, proto, start_time, end_time, confidence,
                category,
            ]
        ),
        EventKind::NetworkThreat => convert_pair!(
            bytes,
            network::NetworkThreatFieldsStoredV0_45,
            network::NetworkThreatFieldsStoredV0_46,
            [
                time,
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                service,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                content,
                db_name,
                rule_id,
                matched_to,
                cluster_id,
                attack_kind,
                confidence,
                category,
                triage_scores,
            ]
        ),
        EventKind::NonBrowser | EventKind::TorConnection => convert_pair!(
            bytes,
            http::HttpEventFieldsStoredV0_42,
            http::HttpEventFieldsStoredV0_46,
            [
                sensor,
                orig_addr,
                orig_port,
                resp_addr,
                resp_port,
                proto,
                start_time,
                duration,
                orig_pkts,
                resp_pkts,
                orig_l2_bytes,
                resp_l2_bytes,
                method,
                host,
                uri,
                referer,
                version,
                user_agent,
                request_len,
                response_len,
                status_code,
                status_msg,
                username,
                password,
                cookie,
                content_encoding,
                content_type,
                cache_control,
                filenames,
                mime_types,
                body,
                state,
                confidence,
                category,
            ]
        ),
        EventKind::PortScan => convert_pair!(
            bytes,
            conn::PortScanFieldsStoredV0_42,
            conn::PortScanFieldsStoredV0_46,
            [
                sensor, orig_addr, resp_addr, resp_ports, start_time, end_time, proto, confidence,
                category,
            ]
        ),
        EventKind::RdpBruteForce => convert_resp_vector!(
            bytes,
            rdp::RdpBruteForceFieldsStoredV0_42,
            rdp::RdpBruteForceFieldsStoredV0_46,
            [
                sensor, orig_addr, resp_addrs, start_time, end_time, proto, confidence, category,
            ]
        ),
        EventKind::RepeatedHttpSessions => convert_pair!(
            bytes,
            http::RepeatedHttpSessionsFieldsStoredV0_42,
            http::RepeatedHttpSessionsFieldsStoredV0_46,
            [
                sensor, orig_addr, orig_port, resp_addr, resp_port, proto, start_time, end_time,
                confidence, category,
            ]
        ),
        EventKind::UnusualDestinationPattern => convert_unusual_destination_pattern!(
            bytes,
            unusual_destination_pattern::UnusualDestinationPatternFieldsStoredV0_45,
            unusual_destination_pattern::UnusualDestinationPatternFieldsStoredV0_46,
            [
                sensor,
                start_time,
                end_time,
                destination_ips,
                count,
                expected_mean,
                std_deviation,
                z_score,
                confidence,
                category,
            ]
        ),
        EventKind::ExtraThreat | EventKind::WindowsThreat => Ok(bytes.to_vec()),
    }
}
