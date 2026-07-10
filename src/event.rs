#![allow(clippy::too_many_lines)]
mod bootp;
mod common;
mod conn;
mod dcerpc;
mod dhcp;
mod dns;
mod ftp;
mod http;
mod kerberos;
mod ldap;
mod log;
mod malformed_dns;
mod mqtt;
mod network;
mod nfs;
mod ntlm;
mod radius;
mod rdp;
mod smb;
mod smtp;
mod ssh;
mod sysmon;
pub(crate) mod timestamp;
mod tls;
mod tor;
mod unusual_destination_pattern;

#[cfg(test)]
mod key_baseline;

use std::{
    collections::HashMap,
    convert::TryInto,
    fmt::{self},
    net::IpAddr,
};

use aho_corasick::AhoCorasickBuilder;
use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use rand::{RngCore, rng};
pub use review_protocol::types::ThreatLevel;
pub use rocksdb::Direction;
use rocksdb::IteratorMode;
use serde::{Deserialize, Serialize};
use tracing::warn;

#[cfg(test)]
pub(crate) use self::common::tests::stored_event_samples_v0_46;
pub(crate) use self::conn::{BlocklistConnFieldsStored, MultiHostPortScanFieldsStored};
use self::{
    bootp::BlocklistBootpFieldsStored,
    common::Match,
    conn::{ExternalDdosFieldsStored, PortScanFieldsStored},
    dns::{BlocklistDnsFieldsStored, CryptocurrencyMiningPoolFieldsStored, DnsEventFieldsStored},
    ftp::{FtpBruteForceFieldsStored, FtpEventFieldsStored},
    http::{
        BlocklistHttpFieldsStored, DgaFieldsStored, HttpEventFieldsStored,
        RepeatedHttpSessionsFieldsStored,
    },
    kerberos::BlocklistKerberosFieldsStored,
    ldap::{LdapBruteForceFieldsStored, LdapEventFieldsStored},
    log::ExtraThreatFieldsStored,
    malformed_dns::BlocklistMalformedDnsFieldsStored,
    mqtt::BlocklistMqttFieldsStored,
    network::NetworkThreatFieldsStored,
    nfs::BlocklistNfsFieldsStored,
    ntlm::BlocklistNtlmFieldsStored,
    radius::BlocklistRadiusFieldsStored,
    rdp::{BlocklistRdpFieldsStored, RdpBruteForceFieldsStored},
    smb::BlocklistSmbFieldsStored,
    smtp::BlocklistSmtpFieldsStored,
    ssh::BlocklistSshFieldsStored,
    sysmon::WindowsThreatFieldsStored,
    tls::BlocklistTlsFieldsStored,
    unusual_destination_pattern::UnusualDestinationPatternFieldsStored,
};
pub(crate) use self::{
    bootp::BlocklistBootpFieldsStoredV0_46,
    conn::{
        BlocklistConnFieldsStoredV0_46, ExternalDdosFieldsStoredV0_46,
        MultiHostPortScanFieldsStoredV0_46, PortScanFieldsStoredV0_46,
    },
    dcerpc::{BlocklistDceRpcFieldsStored, BlocklistDceRpcFieldsStoredV0_46},
    dhcp::{BlocklistDhcpFieldsStored, BlocklistDhcpFieldsStoredV0_46},
    dns::{
        BlocklistDnsFieldsStoredV0_46, CryptocurrencyMiningPoolFieldsStoredV0_46,
        DnsEventFieldsStoredV0_46,
    },
    ftp::{FtpBruteForceFieldsStoredV0_46, FtpEventFieldsStoredV0_46},
    http::{
        DgaFieldsStoredV0_46, HttpEventFieldsStoredV0_46, HttpThreatFieldsStored,
        HttpThreatFieldsStoredV0_46, RepeatedHttpSessionsFieldsStoredV0_46,
    },
    kerberos::BlocklistKerberosFieldsStoredV0_46,
    ldap::{LdapBruteForceFieldsStoredV0_46, LdapEventFieldsStoredV0_46},
    malformed_dns::BlocklistMalformedDnsFieldsStoredV0_46,
    mqtt::BlocklistMqttFieldsStoredV0_46,
    network::NetworkThreatFieldsStoredV0_46,
    nfs::BlocklistNfsFieldsStoredV0_46,
    ntlm::BlocklistNtlmFieldsStoredV0_46,
    radius::BlocklistRadiusFieldsStoredV0_46,
    rdp::{BlocklistRdpFieldsStoredV0_46, RdpBruteForceFieldsStoredV0_46},
    smb::BlocklistSmbFieldsStoredV0_46,
    smtp::BlocklistSmtpFieldsStoredV0_46,
    ssh::BlocklistSshFieldsStoredV0_46,
    tls::BlocklistTlsFieldsStoredV0_46,
    unusual_destination_pattern::UnusualDestinationPatternFieldsStoredV0_46,
};
pub use self::{
    bootp::{BlocklistBootp, BlocklistBootpFields},
    common::TriageScore,
    conn::{
        BlocklistConn, BlocklistConnFields, ExternalDdos, ExternalDdosFields, MultiHostPortScan,
        MultiHostPortScanFields, PortScan, PortScanFields,
    },
    dcerpc::{BlocklistDceRpc, BlocklistDceRpcFields, DceRpcContext},
    dhcp::{BlocklistDhcp, BlocklistDhcpFields},
    dns::{
        BlocklistDns, BlocklistDnsFields, CryptocurrencyMiningPool, CryptocurrencyMiningPoolFields,
        DnsCovertChannel, DnsEventFields, LockyRansomware,
    },
    ftp::{
        BlocklistFtp, FtpBruteForce, FtpBruteForceFields, FtpCommand, FtpEventFields, FtpPlainText,
    },
    http::{
        BlocklistHttp, BlocklistHttpFields, DgaFields, DomainGenerationAlgorithm, HttpEventFields,
        HttpThreat, HttpThreatFields, NonBrowser, RepeatedHttpSessions, RepeatedHttpSessionsFields,
    },
    kerberos::{BlocklistKerberos, BlocklistKerberosFields},
    ldap::{BlocklistLdap, LdapBruteForce, LdapBruteForceFields, LdapEventFields, LdapPlainText},
    log::{ExtraThreat, ExtraThreatFields},
    malformed_dns::{BlocklistMalformedDns, BlocklistMalformedDnsFields},
    mqtt::{BlocklistMqtt, BlocklistMqttFields},
    network::{NetworkThreat, NetworkThreatFields},
    nfs::{BlocklistNfs, BlocklistNfsFields},
    ntlm::{BlocklistNtlm, BlocklistNtlmFields},
    radius::{BlocklistRadius, BlocklistRadiusFields},
    rdp::{BlocklistRdp, BlocklistRdpFields, RdpBruteForce, RdpBruteForceFields},
    smb::{BlocklistSmb, BlocklistSmbFields},
    smtp::{BlocklistSmtp, BlocklistSmtpFields},
    ssh::{BlocklistSsh, BlocklistSshFields},
    sysmon::{WindowsThreat, WindowsThreatFields},
    tls::{BlocklistTls, BlocklistTlsFields, SuspiciousTlsTraffic},
    tor::{TorConnection, TorConnectionConn},
    unusual_destination_pattern::{UnusualDestinationPattern, UnusualDestinationPatternFields},
};
use super::{
    Customer, EventCategory, Network, TriageExclusion, TriagePolicyInput,
    types::{Endpoint, HostNetworkGroup},
};

// event kind
const DNS_COVERT_CHANNEL: &str = "DNS Covert Channel";
const HTTP_THREAT: &str = "HTTP Threat";
const RDP_BRUTE_FORCE: &str = "RDP Brute Force";
const REPEATED_HTTP_SESSIONS: &str = "Repeated HTTP Sessions";
const TOR_CONNECTION: &str = "Tor Connection";
const TOR_CONNECTION_CONN: &str = "Tor Connection Conn";
const DOMAIN_GENERATION_ALGORITHM: &str = "Domain Generation Algorithm";
const FTP_BRUTE_FORCE: &str = "FTP Brute Force";
const FTP_PLAIN_TEXT: &str = "FTP Plain text";
const PORT_SCAN: &str = "Port Scan";
const MULTI_HOST_PORT_SCAN: &str = "Multi Host Port Scan";
const EXTERNAL_DDOS: &str = "External Ddos";
const NON_BROWSER: &str = "Non Browser";
const LDAP_BRUTE_FORCE: &str = "LDAP Brute Force";
const LDAP_PLAIN_TEXT: &str = "LDAP Plain Text";
const CRYPTOCURRENCY_MINING_POOL: &str = "Cryptocurrency Mining Pool";
const BLOCKLIST: &str = "Blocklist";
const WINDOWS_THREAT_EVENT: &str = "Windows Threat Events";
const NETWORK_THREAT_EVENT: &str = "Network Threat Events";
const MISC_LOG_THREAT: &str = "Log Threat";
const LOCKY_RANSOMWARE: &str = "Locky Ransomware";
const SUSPICIOUS_TLS_TRAFFIC: &str = "Suspicious TLS Traffic";
const UNUSUAL_DESTINATION_PATTERN: &str = "Unusual Destination Pattern";

pub enum Event {
    /// DNS requests and responses that convey unusual host names.
    DnsCovertChannel(DnsCovertChannel),

    /// HTTP-related threats.
    HttpThreat(HttpThreat),

    /// Brute force attacks against RDP, attempting to guess passwords.
    RdpBruteForce(RdpBruteForce),

    /// Multiple HTTP sessions with the same originator and responder that occur within a short time.
    /// This is a sign of a possible unauthorized communication channel.
    RepeatedHttpSessions(RepeatedHttpSessions),

    /// An HTTP connection to a Tor exit node.
    TorConnection(TorConnection),

    /// A network connection to a Tor exit node.
    TorConnectionConn(TorConnectionConn),

    /// DGA (Domain Generation Algorithm) generated hostname in HTTP request message
    DomainGenerationAlgorithm(DomainGenerationAlgorithm),

    /// Brute force attacks against FTP.
    FtpBruteForce(FtpBruteForce),

    /// Plain text password is used for the FTP connection.
    FtpPlainText(FtpPlainText),

    /// Large number of connection attempts are made to multiple ports
    /// on the same responder from the same originator.
    PortScan(PortScan),

    /// Specific host inside attempts to connect to a specific port on multiple host inside.
    MultiHostPortScan(MultiHostPortScan),

    /// multiple internal host attempt a DDOS attack against a specific external host.
    ExternalDdos(ExternalDdos),

    /// Non-browser user agent detected in HTTP request message.
    NonBrowser(NonBrowser),

    /// Brute force attacks against LDAP.
    LdapBruteForce(LdapBruteForce),

    /// Plain text password is used for the LDAP connection.
    LdapPlainText(LdapPlainText),

    /// An event that occurs when it is determined that there is a connection to a cryptocurrency mining network
    CryptocurrencyMiningPool(CryptocurrencyMiningPool),

    Blocklist(RecordType),

    WindowsThreat(WindowsThreat),

    NetworkThreat(NetworkThreat),

    ExtraThreat(ExtraThreat),

    LockyRansomware(LockyRansomware),

    SuspiciousTlsTraffic(SuspiciousTlsTraffic),
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (event_kind, category) = self.kind_and_category();
        let event_kind = format!("{event_kind:?}");
        let category = category
            .as_ref()
            .map_or_else(|| "Unspecified".to_string(), |c| format!("{c:?}"));

        match self {
            Event::DnsCovertChannel(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::HttpThreat(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::RdpBruteForce(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::RepeatedHttpSessions(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::TorConnection(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::TorConnectionConn(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::DomainGenerationAlgorithm(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::FtpBruteForce(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::FtpPlainText(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::PortScan(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::MultiHostPortScan(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::ExternalDdos(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::NonBrowser(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::LdapBruteForce(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::LdapPlainText(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::CryptocurrencyMiningPool(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::Conn(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::DceRpc(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::Dhcp(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::Dns(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::Ftp(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::Http(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::Kerberos(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::Ldap(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::MalformedDns(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::Mqtt(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::Nfs(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::Ntlm(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::Radius(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::Rdp(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::Smb(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::Smtp(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::Ssh(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::Tls(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
                RecordType::UnusualDestinationPattern(event) => {
                    write!(
                        f,
                        "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                        timestamp::format_rfc3339(event.time).unwrap_or_default(),
                    )
                }
            },
            Event::WindowsThreat(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::NetworkThreat(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::ExtraThreat(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::LockyRansomware(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
            Event::SuspiciousTlsTraffic(event) => {
                write!(
                    f,
                    "time={:?} event_kind={event_kind:?} category={category:?} {event}",
                    timestamp::format_rfc3339(event.time).unwrap_or_default(),
                )
            }
        }
    }
}

pub enum RecordType {
    Conn(BlocklistConn),
    Dns(BlocklistDns),
    DceRpc(BlocklistDceRpc),
    Ftp(BlocklistFtp),
    Http(BlocklistHttp),
    Kerberos(BlocklistKerberos),
    Ldap(BlocklistLdap),
    MalformedDns(BlocklistMalformedDns),
    Mqtt(BlocklistMqtt),
    Nfs(BlocklistNfs),
    Ntlm(BlocklistNtlm),
    Radius(BlocklistRadius),
    Rdp(BlocklistRdp),
    Smb(BlocklistSmb),
    Smtp(BlocklistSmtp),
    Ssh(BlocklistSsh),
    Tls(BlocklistTls),
    Bootp(BlocklistBootp),
    Dhcp(BlocklistDhcp),
    UnusualDestinationPattern(UnusualDestinationPattern),
}

impl Event {
    /// Returns whether the event matches the given filter. If the event matches, returns the
    /// triage score for the event.
    ///
    /// # Errors
    ///
    /// Returns an error if triage-policy scoring fails while evaluating a
    /// matching event.
    pub fn matches(&self, filter: &EventFilter) -> Result<(bool, Option<Vec<TriageScore>>)> {
        match self {
            Event::DnsCovertChannel(event) => event.matches(filter),
            Event::HttpThreat(event) => event.matches(filter),
            Event::RdpBruteForce(event) => event.matches(filter),
            Event::RepeatedHttpSessions(event) => event.matches(filter),
            Event::TorConnection(event) => event.matches(filter),
            Event::TorConnectionConn(event) => event.matches(filter),
            Event::DomainGenerationAlgorithm(event) => event.matches(filter),
            Event::FtpBruteForce(event) => event.matches(filter),
            Event::FtpPlainText(event) => event.matches(filter),
            Event::PortScan(event) => event.matches(filter),
            Event::MultiHostPortScan(event) => event.matches(filter),
            Event::ExternalDdos(event) => event.matches(filter),
            Event::NonBrowser(event) => event.matches(filter),
            Event::LdapBruteForce(event) => event.matches(filter),
            Event::LdapPlainText(event) => event.matches(filter),
            Event::CryptocurrencyMiningPool(event) => event.matches(filter),
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(bootp_event) => bootp_event.matches(filter),
                RecordType::Conn(conn_event) => conn_event.matches(filter),
                RecordType::DceRpc(dcerpc_event) => dcerpc_event.matches(filter),
                RecordType::Dhcp(dhcp_event) => dhcp_event.matches(filter),
                RecordType::Dns(dns_event) => dns_event.matches(filter),
                RecordType::Ftp(ftp_event) => ftp_event.matches(filter),
                RecordType::Http(http_event) => http_event.matches(filter),
                RecordType::Kerberos(kerberos_event) => kerberos_event.matches(filter),
                RecordType::Ldap(ldap_event) => ldap_event.matches(filter),
                RecordType::MalformedDns(malformed_dns_event) => {
                    malformed_dns_event.matches(filter)
                }
                RecordType::Mqtt(mqtt_event) => mqtt_event.matches(filter),
                RecordType::Nfs(nfs_event) => nfs_event.matches(filter),
                RecordType::Ntlm(ntlm_event) => ntlm_event.matches(filter),
                RecordType::Radius(radius_event) => radius_event.matches(filter),
                RecordType::Rdp(rdp_event) => rdp_event.matches(filter),
                RecordType::Smb(smb_event) => smb_event.matches(filter),
                RecordType::Smtp(smtp_event) => smtp_event.matches(filter),
                RecordType::Ssh(ssh_event) => ssh_event.matches(filter),
                RecordType::Tls(tls_event) => tls_event.matches(filter),
                RecordType::UnusualDestinationPattern(event) => event.matches(filter),
            },
            Event::WindowsThreat(event) => event.matches(filter),
            Event::NetworkThreat(event) => event.matches(filter),
            Event::ExtraThreat(event) => event.matches(filter),
            Event::LockyRansomware(event) => event.matches(filter),
            Event::SuspiciousTlsTraffic(event) => event.matches(filter),
        }
    }

    /// Returns whether any of `exclusions` matches this event.
    ///
    /// Dispatches through each event variant's `score_by_triage_exclusion`
    /// override so per-event semantics (DNS domain/hostname, HTTP URI/host,
    /// Tor domain, etc.) are preserved. The default implementation handles
    /// the `IpAddress` variant only; richer exclusion shapes for events
    /// without an override are not currently matched.
    #[must_use]
    pub fn matches_exclusion(&self, exclusions: &[TriageExclusion]) -> bool {
        match self {
            Event::DnsCovertChannel(event) => event.matched_any_exclusion(exclusions),
            Event::HttpThreat(event) => event.matched_any_exclusion(exclusions),
            Event::RdpBruteForce(event) => event.matched_any_exclusion(exclusions),
            Event::RepeatedHttpSessions(event) => event.matched_any_exclusion(exclusions),
            Event::TorConnection(event) => event.matched_any_exclusion(exclusions),
            Event::TorConnectionConn(event) => event.matched_any_exclusion(exclusions),
            Event::DomainGenerationAlgorithm(event) => event.matched_any_exclusion(exclusions),
            Event::FtpBruteForce(event) => event.matched_any_exclusion(exclusions),
            Event::FtpPlainText(event) => event.matched_any_exclusion(exclusions),
            Event::PortScan(event) => event.matched_any_exclusion(exclusions),
            Event::MultiHostPortScan(event) => event.matched_any_exclusion(exclusions),
            Event::ExternalDdos(event) => event.matched_any_exclusion(exclusions),
            Event::NonBrowser(event) => event.matched_any_exclusion(exclusions),
            Event::LdapBruteForce(event) => event.matched_any_exclusion(exclusions),
            Event::LdapPlainText(event) => event.matched_any_exclusion(exclusions),
            Event::CryptocurrencyMiningPool(event) => event.matched_any_exclusion(exclusions),
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(event) => event.matched_any_exclusion(exclusions),
                RecordType::Conn(event) => event.matched_any_exclusion(exclusions),
                RecordType::DceRpc(event) => event.matched_any_exclusion(exclusions),
                RecordType::Dhcp(event) => event.matched_any_exclusion(exclusions),
                RecordType::Dns(event) => event.matched_any_exclusion(exclusions),
                RecordType::Ftp(event) => event.matched_any_exclusion(exclusions),
                RecordType::Http(event) => event.matched_any_exclusion(exclusions),
                RecordType::Kerberos(event) => event.matched_any_exclusion(exclusions),
                RecordType::Ldap(event) => event.matched_any_exclusion(exclusions),
                RecordType::MalformedDns(event) => event.matched_any_exclusion(exclusions),
                RecordType::Mqtt(event) => event.matched_any_exclusion(exclusions),
                RecordType::Nfs(event) => event.matched_any_exclusion(exclusions),
                RecordType::Ntlm(event) => event.matched_any_exclusion(exclusions),
                RecordType::Radius(event) => event.matched_any_exclusion(exclusions),
                RecordType::Rdp(event) => event.matched_any_exclusion(exclusions),
                RecordType::Smb(event) => event.matched_any_exclusion(exclusions),
                RecordType::Smtp(event) => event.matched_any_exclusion(exclusions),
                RecordType::Ssh(event) => event.matched_any_exclusion(exclusions),
                RecordType::Tls(event) => event.matched_any_exclusion(exclusions),
                RecordType::UnusualDestinationPattern(event) => {
                    event.matched_any_exclusion(exclusions)
                }
            },
            Event::WindowsThreat(event) => event.matched_any_exclusion(exclusions),
            Event::NetworkThreat(event) => event.matched_any_exclusion(exclusions),
            Event::ExtraThreat(event) => event.matched_any_exclusion(exclusions),
            Event::LockyRansomware(event) => event.matched_any_exclusion(exclusions),
            Event::SuspiciousTlsTraffic(event) => event.matched_any_exclusion(exclusions),
        }
    }

    /// Computes inline triage scores for this event against each of `policies`.
    ///
    /// Each policy contributes a `TriageScore` only when
    /// `score_by_attr + score_by_confidence` reaches at least one of the
    /// policy's `response.minimum_score` thresholds; policies whose
    /// `response` is empty contribute nothing. Each policy's
    /// `triage_exclusion` is treated as already applied by the caller and
    /// must be empty (asserted in debug builds).
    #[must_use]
    pub fn score_against_policies(&self, policies: &[TriagePolicyInput]) -> Vec<TriageScore> {
        match self {
            Event::DnsCovertChannel(event) => event.inline_scores_against_policies(policies),
            Event::HttpThreat(event) => event.inline_scores_against_policies(policies),
            Event::RdpBruteForce(event) => event.inline_scores_against_policies(policies),
            Event::RepeatedHttpSessions(event) => event.inline_scores_against_policies(policies),
            Event::TorConnection(event) => event.inline_scores_against_policies(policies),
            Event::TorConnectionConn(event) => event.inline_scores_against_policies(policies),
            Event::DomainGenerationAlgorithm(event) => {
                event.inline_scores_against_policies(policies)
            }
            Event::FtpBruteForce(event) => event.inline_scores_against_policies(policies),
            Event::FtpPlainText(event) => event.inline_scores_against_policies(policies),
            Event::PortScan(event) => event.inline_scores_against_policies(policies),
            Event::MultiHostPortScan(event) => event.inline_scores_against_policies(policies),
            Event::ExternalDdos(event) => event.inline_scores_against_policies(policies),
            Event::NonBrowser(event) => event.inline_scores_against_policies(policies),
            Event::LdapBruteForce(event) => event.inline_scores_against_policies(policies),
            Event::LdapPlainText(event) => event.inline_scores_against_policies(policies),
            Event::CryptocurrencyMiningPool(event) => {
                event.inline_scores_against_policies(policies)
            }
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(event) => event.inline_scores_against_policies(policies),
                RecordType::Conn(event) => event.inline_scores_against_policies(policies),
                RecordType::DceRpc(event) => event.inline_scores_against_policies(policies),
                RecordType::Dhcp(event) => event.inline_scores_against_policies(policies),
                RecordType::Dns(event) => event.inline_scores_against_policies(policies),
                RecordType::Ftp(event) => event.inline_scores_against_policies(policies),
                RecordType::Http(event) => event.inline_scores_against_policies(policies),
                RecordType::Kerberos(event) => event.inline_scores_against_policies(policies),
                RecordType::Ldap(event) => event.inline_scores_against_policies(policies),
                RecordType::MalformedDns(event) => event.inline_scores_against_policies(policies),
                RecordType::Mqtt(event) => event.inline_scores_against_policies(policies),
                RecordType::Nfs(event) => event.inline_scores_against_policies(policies),
                RecordType::Ntlm(event) => event.inline_scores_against_policies(policies),
                RecordType::Radius(event) => event.inline_scores_against_policies(policies),
                RecordType::Rdp(event) => event.inline_scores_against_policies(policies),
                RecordType::Smb(event) => event.inline_scores_against_policies(policies),
                RecordType::Smtp(event) => event.inline_scores_against_policies(policies),
                RecordType::Ssh(event) => event.inline_scores_against_policies(policies),
                RecordType::Tls(event) => event.inline_scores_against_policies(policies),
                RecordType::UnusualDestinationPattern(event) => {
                    event.inline_scores_against_policies(policies)
                }
            },
            Event::WindowsThreat(event) => event.inline_scores_against_policies(policies),
            Event::NetworkThreat(event) => event.inline_scores_against_policies(policies),
            Event::ExtraThreat(event) => event.inline_scores_against_policies(policies),
            Event::LockyRansomware(event) => event.inline_scores_against_policies(policies),
            Event::SuspiciousTlsTraffic(event) => event.inline_scores_against_policies(policies),
        }
    }

    fn address_pair(&self, filter: &EventFilter) -> Result<(Option<IpAddr>, Option<IpAddr>)> {
        let mut addr_pair = (None, None);
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), None);
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
            Event::TorConnection(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
            Event::TorConnectionConn(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
            Event::PortScan(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), None);
                }
            }
            Event::ExternalDdos(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (None, Some(event.resp_addr));
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
            Event::CryptocurrencyMiningPool(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(bootp_event) => {
                    if bootp_event.matches(filter)?.0 {
                        addr_pair = (Some(bootp_event.orig_addr), Some(bootp_event.resp_addr));
                    }
                }
                RecordType::Conn(conn_event) => {
                    if conn_event.matches(filter)?.0 {
                        addr_pair = (Some(conn_event.orig_addr), Some(conn_event.resp_addr));
                    }
                }
                RecordType::DceRpc(dcerpc_event) => {
                    if dcerpc_event.matches(filter)?.0 {
                        addr_pair = (Some(dcerpc_event.orig_addr), Some(dcerpc_event.resp_addr));
                    }
                }
                RecordType::Dhcp(dhcp_event) => {
                    if dhcp_event.matches(filter)?.0 {
                        addr_pair = (Some(dhcp_event.orig_addr), Some(dhcp_event.resp_addr));
                    }
                }
                RecordType::Dns(dns_event) => {
                    if dns_event.matches(filter)?.0 {
                        addr_pair = (Some(dns_event.orig_addr), Some(dns_event.resp_addr));
                    }
                }
                RecordType::Ftp(ftp_event) => {
                    if ftp_event.matches(filter)?.0 {
                        addr_pair = (Some(ftp_event.orig_addr), Some(ftp_event.resp_addr));
                    }
                }
                RecordType::Http(http_event) => {
                    if http_event.matches(filter)?.0 {
                        addr_pair = (Some(http_event.orig_addr), Some(http_event.resp_addr));
                    }
                }
                RecordType::Kerberos(kerberos_event) => {
                    if kerberos_event.matches(filter)?.0 {
                        addr_pair = (
                            Some(kerberos_event.orig_addr),
                            Some(kerberos_event.resp_addr),
                        );
                    }
                }
                RecordType::Ldap(ldap_event) => {
                    if ldap_event.matches(filter)?.0 {
                        addr_pair = (Some(ldap_event.orig_addr), Some(ldap_event.resp_addr));
                    }
                }
                RecordType::MalformedDns(malformed_dns_event) => {
                    if malformed_dns_event.matches(filter)?.0 {
                        addr_pair = (
                            Some(malformed_dns_event.orig_addr),
                            Some(malformed_dns_event.resp_addr),
                        );
                    }
                }
                RecordType::Mqtt(mqtt_event) => {
                    if mqtt_event.matches(filter)?.0 {
                        addr_pair = (Some(mqtt_event.orig_addr), Some(mqtt_event.resp_addr));
                    }
                }
                RecordType::Nfs(nfs_event) => {
                    if nfs_event.matches(filter)?.0 {
                        addr_pair = (Some(nfs_event.orig_addr), Some(nfs_event.resp_addr));
                    }
                }
                RecordType::Ntlm(ntlm_event) => {
                    if ntlm_event.matches(filter)?.0 {
                        addr_pair = (Some(ntlm_event.orig_addr), Some(ntlm_event.resp_addr));
                    }
                }
                RecordType::Radius(radius_event) => {
                    if radius_event.matches(filter)?.0 {
                        addr_pair = (Some(radius_event.orig_addr), Some(radius_event.resp_addr));
                    }
                }
                RecordType::Rdp(rdp_event) => {
                    if rdp_event.matches(filter)?.0 {
                        addr_pair = (Some(rdp_event.orig_addr), Some(rdp_event.resp_addr));
                    }
                }
                RecordType::Smb(smb_event) => {
                    if smb_event.matches(filter)?.0 {
                        addr_pair = (Some(smb_event.orig_addr), Some(smb_event.resp_addr));
                    }
                }
                RecordType::Smtp(smtp_event) => {
                    if smtp_event.matches(filter)?.0 {
                        addr_pair = (Some(smtp_event.orig_addr), Some(smtp_event.resp_addr));
                    }
                }
                RecordType::Ssh(ssh_event) => {
                    if ssh_event.matches(filter)?.0 {
                        addr_pair = (Some(ssh_event.orig_addr), Some(ssh_event.resp_addr));
                    }
                }
                RecordType::Tls(tls_event) => {
                    if tls_event.matches(filter)?.0 {
                        addr_pair = (Some(tls_event.orig_addr), Some(tls_event.resp_addr));
                    }
                }
                RecordType::UnusualDestinationPattern(event) => {
                    if event.matches(filter)?.0 {
                        // UnusualDestinationPattern has multiple responder IPs but no originator.
                        // Use the first responder IP if available.
                        addr_pair = (None, event.destination_ips.first().copied());
                    }
                }
            },
            Event::WindowsThreat(_event) => {}
            Event::NetworkThreat(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
            Event::ExtraThreat(_event) => {}
            Event::LockyRansomware(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
            Event::SuspiciousTlsTraffic(event) => {
                if event.matches(filter)?.0 {
                    addr_pair = (Some(event.orig_addr), Some(event.resp_addr));
                }
            }
        }
        Ok(addr_pair)
    }

    fn kind(&self, filter: &EventFilter) -> Result<Option<&'static str>> {
        let mut kind = None;
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(DNS_COVERT_CHANNEL);
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(HTTP_THREAT);
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(RDP_BRUTE_FORCE);
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(REPEATED_HTTP_SESSIONS);
                }
            }
            Event::TorConnection(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(TOR_CONNECTION);
                }
            }
            Event::TorConnectionConn(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(TOR_CONNECTION_CONN);
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(DOMAIN_GENERATION_ALGORITHM);
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(FTP_BRUTE_FORCE);
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(FTP_PLAIN_TEXT);
                }
            }
            Event::PortScan(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(PORT_SCAN);
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(MULTI_HOST_PORT_SCAN);
                }
            }
            Event::ExternalDdos(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(EXTERNAL_DDOS);
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(NON_BROWSER);
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(LDAP_BRUTE_FORCE);
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(LDAP_PLAIN_TEXT);
                }
            }
            Event::CryptocurrencyMiningPool(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(CRYPTOCURRENCY_MINING_POOL);
                }
            }
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(bootp_event) => {
                    if bootp_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::Conn(conn_event) => {
                    if conn_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::DceRpc(dcerpc_event) => {
                    if dcerpc_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::Dhcp(dhcp_event) => {
                    if dhcp_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::Dns(dns_event) => {
                    if dns_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::Ftp(ftp_event) => {
                    if ftp_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::Http(http_event) => {
                    if http_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::Kerberos(kerberos_event) => {
                    if kerberos_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::Ldap(ldap_event) => {
                    if ldap_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::MalformedDns(malformed_dns_event) => {
                    if malformed_dns_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::Mqtt(mqtt_event) => {
                    if mqtt_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::Nfs(nfs_event) => {
                    if nfs_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::Ntlm(ntlm_event) => {
                    if ntlm_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::Radius(radius_event) => {
                    if radius_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::Rdp(rdp_event) => {
                    if rdp_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::Smb(smb_event) => {
                    if smb_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::Smtp(smtp_event) => {
                    if smtp_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::Ssh(ssh_event) => {
                    if ssh_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::Tls(tls_event) => {
                    if tls_event.matches(filter)?.0 {
                        kind = Some(BLOCKLIST);
                    }
                }
                RecordType::UnusualDestinationPattern(event) => {
                    if event.matches(filter)?.0 {
                        kind = Some(UNUSUAL_DESTINATION_PATTERN);
                    }
                }
            },
            Event::WindowsThreat(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(WINDOWS_THREAT_EVENT);
                }
            }
            Event::NetworkThreat(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(NETWORK_THREAT_EVENT);
                }
            }
            Event::ExtraThreat(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(MISC_LOG_THREAT);
                }
            }
            Event::LockyRansomware(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(LOCKY_RANSOMWARE);
                }
            }
            Event::SuspiciousTlsTraffic(event) => {
                if event.matches(filter)?.0 {
                    kind = Some(SUSPICIOUS_TLS_TRAFFIC);
                }
            }
        }
        Ok(kind)
    }

    fn kind_and_category(&self) -> (EventKind, Option<EventCategory>) {
        match self {
            Event::DnsCovertChannel(e) => (EventKind::DnsCovertChannel, e.category()),
            Event::HttpThreat(e) => (EventKind::HttpThreat, e.category()),
            Event::RdpBruteForce(e) => (EventKind::RdpBruteForce, e.category()),
            Event::RepeatedHttpSessions(e) => (EventKind::RepeatedHttpSessions, e.category()),
            Event::TorConnection(e) => (EventKind::TorConnection, e.category()),
            Event::TorConnectionConn(e) => (EventKind::TorConnectionConn, e.category()),
            Event::DomainGenerationAlgorithm(e) => {
                (EventKind::DomainGenerationAlgorithm, e.category())
            }
            Event::FtpBruteForce(e) => (EventKind::FtpBruteForce, e.category()),
            Event::FtpPlainText(e) => (EventKind::FtpPlainText, e.category()),
            Event::PortScan(e) => (EventKind::PortScan, e.category()),
            Event::MultiHostPortScan(e) => (EventKind::MultiHostPortScan, e.category()),
            Event::ExternalDdos(e) => (EventKind::ExternalDdos, e.category()),
            Event::NonBrowser(e) => (EventKind::NonBrowser, e.category()),
            Event::LdapBruteForce(e) => (EventKind::LdapBruteForce, e.category()),
            Event::LdapPlainText(e) => (EventKind::LdapPlainText, e.category()),
            Event::CryptocurrencyMiningPool(e) => {
                (EventKind::CryptocurrencyMiningPool, e.category())
            }
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(e) => (EventKind::BlocklistBootp, e.category()),
                RecordType::Conn(e) => (EventKind::BlocklistConn, e.category()),
                RecordType::DceRpc(e) => (EventKind::BlocklistDceRpc, e.category()),
                RecordType::Dhcp(e) => (EventKind::BlocklistDhcp, e.category()),
                RecordType::Dns(e) => (EventKind::BlocklistDns, e.category()),
                RecordType::Ftp(e) => (EventKind::BlocklistFtp, e.category()),
                RecordType::Http(e) => (EventKind::BlocklistHttp, e.category()),
                RecordType::Kerberos(e) => (EventKind::BlocklistKerberos, e.category()),
                RecordType::Ldap(e) => (EventKind::BlocklistLdap, e.category()),
                RecordType::MalformedDns(e) => (EventKind::BlocklistMalformedDns, e.category()),
                RecordType::Mqtt(e) => (EventKind::BlocklistMqtt, e.category()),
                RecordType::Nfs(e) => (EventKind::BlocklistNfs, e.category()),
                RecordType::Ntlm(e) => (EventKind::BlocklistNtlm, e.category()),
                RecordType::Radius(e) => (EventKind::BlocklistRadius, e.category()),
                RecordType::Rdp(e) => (EventKind::BlocklistRdp, e.category()),
                RecordType::Smb(e) => (EventKind::BlocklistSmb, e.category()),
                RecordType::Smtp(e) => (EventKind::BlocklistSmtp, e.category()),
                RecordType::Ssh(e) => (EventKind::BlocklistSsh, e.category()),
                RecordType::Tls(e) => (EventKind::BlocklistTls, e.category()),
                RecordType::UnusualDestinationPattern(e) => {
                    (EventKind::UnusualDestinationPattern, e.category())
                }
            },
            Event::WindowsThreat(e) => (EventKind::WindowsThreat, e.category()),
            Event::NetworkThreat(e) => (EventKind::NetworkThreat, e.category()),
            Event::ExtraThreat(e) => (EventKind::ExtraThreat, e.category()),
            Event::LockyRansomware(e) => (EventKind::LockyRansomware, e.category()),
            Event::SuspiciousTlsTraffic(e) => (EventKind::SuspiciousTlsTraffic, e.category()),
        }
    }

    /// Returns all MITRE ATT&CK categories that this event can match based on its kind.
    #[must_use]
    pub fn categories(&self) -> &'static [EventCategory] {
        let (kind, _) = self.kind_and_category();
        kind.categories()
    }

    // TODO: Need to implement country counting for `WindowsThreat`.
    // 1. for Network Connection: count country via ip
    // 2. for other Sysmon events: count the country by KR because the event does not have ip address.
    fn representative_stored_country_code(codes: &[[u8; 2]]) -> [u8; 2] {
        codes
            .first()
            .copied()
            .unwrap_or(crate::util::COUNTRY_CODE_PENDING)
    }

    /// Returns representative stored country codes for country aggregation.
    ///
    /// `address_pair` determines which endpoints contribute to the aggregation.
    fn stored_country_code_pair(&self) -> ([u8; 2], [u8; 2]) {
        match self {
            Event::DnsCovertChannel(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::HttpThreat(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::RdpBruteForce(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::RepeatedHttpSessions(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::TorConnection(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::TorConnectionConn(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::DomainGenerationAlgorithm(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::FtpBruteForce(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::FtpPlainText(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::PortScan(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::MultiHostPortScan(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::ExternalDdos(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::NonBrowser(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::LdapBruteForce(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::LdapPlainText(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::CryptocurrencyMiningPool(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(bootp_event) => (
                    Self::representative_stored_country_code(bootp_event.orig_country_codes()),
                    Self::representative_stored_country_code(bootp_event.resp_country_codes()),
                ),
                RecordType::Conn(conn_event) => (
                    Self::representative_stored_country_code(conn_event.orig_country_codes()),
                    Self::representative_stored_country_code(conn_event.resp_country_codes()),
                ),
                RecordType::DceRpc(dcerpc_event) => (
                    Self::representative_stored_country_code(dcerpc_event.orig_country_codes()),
                    Self::representative_stored_country_code(dcerpc_event.resp_country_codes()),
                ),
                RecordType::Dhcp(dhcp_event) => (
                    Self::representative_stored_country_code(dhcp_event.orig_country_codes()),
                    Self::representative_stored_country_code(dhcp_event.resp_country_codes()),
                ),
                RecordType::Dns(dns_event) => (
                    Self::representative_stored_country_code(dns_event.orig_country_codes()),
                    Self::representative_stored_country_code(dns_event.resp_country_codes()),
                ),
                RecordType::Ftp(ftp_event) => (
                    Self::representative_stored_country_code(ftp_event.orig_country_codes()),
                    Self::representative_stored_country_code(ftp_event.resp_country_codes()),
                ),
                RecordType::Http(http_event) => (
                    Self::representative_stored_country_code(http_event.orig_country_codes()),
                    Self::representative_stored_country_code(http_event.resp_country_codes()),
                ),
                RecordType::Kerberos(kerberos_event) => (
                    Self::representative_stored_country_code(kerberos_event.orig_country_codes()),
                    Self::representative_stored_country_code(kerberos_event.resp_country_codes()),
                ),
                RecordType::Ldap(ldap_event) => (
                    Self::representative_stored_country_code(ldap_event.orig_country_codes()),
                    Self::representative_stored_country_code(ldap_event.resp_country_codes()),
                ),
                RecordType::MalformedDns(malformed_dns_event) => (
                    Self::representative_stored_country_code(
                        malformed_dns_event.orig_country_codes(),
                    ),
                    Self::representative_stored_country_code(
                        malformed_dns_event.resp_country_codes(),
                    ),
                ),
                RecordType::Mqtt(mqtt_event) => (
                    Self::representative_stored_country_code(mqtt_event.orig_country_codes()),
                    Self::representative_stored_country_code(mqtt_event.resp_country_codes()),
                ),
                RecordType::Nfs(nfs_event) => (
                    Self::representative_stored_country_code(nfs_event.orig_country_codes()),
                    Self::representative_stored_country_code(nfs_event.resp_country_codes()),
                ),
                RecordType::Ntlm(ntlm_event) => (
                    Self::representative_stored_country_code(ntlm_event.orig_country_codes()),
                    Self::representative_stored_country_code(ntlm_event.resp_country_codes()),
                ),
                RecordType::Radius(radius_event) => (
                    Self::representative_stored_country_code(radius_event.orig_country_codes()),
                    Self::representative_stored_country_code(radius_event.resp_country_codes()),
                ),
                RecordType::Rdp(rdp_event) => (
                    Self::representative_stored_country_code(rdp_event.orig_country_codes()),
                    Self::representative_stored_country_code(rdp_event.resp_country_codes()),
                ),
                RecordType::Smb(smb_event) => (
                    Self::representative_stored_country_code(smb_event.orig_country_codes()),
                    Self::representative_stored_country_code(smb_event.resp_country_codes()),
                ),
                RecordType::Smtp(smtp_event) => (
                    Self::representative_stored_country_code(smtp_event.orig_country_codes()),
                    Self::representative_stored_country_code(smtp_event.resp_country_codes()),
                ),
                RecordType::Ssh(ssh_event) => (
                    Self::representative_stored_country_code(ssh_event.orig_country_codes()),
                    Self::representative_stored_country_code(ssh_event.resp_country_codes()),
                ),
                RecordType::Tls(tls_event) => (
                    Self::representative_stored_country_code(tls_event.orig_country_codes()),
                    Self::representative_stored_country_code(tls_event.resp_country_codes()),
                ),
                RecordType::UnusualDestinationPattern(event) => (
                    Self::representative_stored_country_code(event.orig_country_codes()),
                    Self::representative_stored_country_code(event.resp_country_codes()),
                ),
            },
            Event::WindowsThreat(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::NetworkThreat(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::ExtraThreat(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::LockyRansomware(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
            Event::SuspiciousTlsTraffic(event) => (
                Self::representative_stored_country_code(event.orig_country_codes()),
                Self::representative_stored_country_code(event.resp_country_codes()),
            ),
        }
    }

    fn increment_country_count(counter: &mut HashMap<String, usize>, country: &str) {
        if let Some(count) = counter.get_mut(country) {
            *count += 1;
        } else {
            counter.insert(country.to_string(), 1);
        }
    }

    /// Counts the number of events per country.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_country(
        &self,
        counter: &mut HashMap<String, usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        let addr_pair = self.address_pair(filter)?;
        let (orig_code, resp_code) = self.stored_country_code_pair();

        if addr_pair.1.is_some() {
            let resp_country = crate::util::country_code_as_str(&resp_code);
            if addr_pair.0.is_some() {
                let orig_country = crate::util::country_code_as_str(&orig_code);
                if orig_country != resp_country {
                    Self::increment_country_count(counter, orig_country);
                }
            }
            Self::increment_country_count(counter, resp_country);
        } else if addr_pair.0.is_some() {
            let orig_country = crate::util::country_code_as_str(&orig_code);
            Self::increment_country_count(counter, orig_country);
        }

        Ok(())
    }

    /// Counts the number of events per category.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_category(
        &self,
        counter: &mut HashMap<EventCategory, usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        let mut category = None;
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::TorConnection(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::TorConnectionConn(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::PortScan(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::ExternalDdos(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::CryptocurrencyMiningPool(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(bootp_event) => {
                    if bootp_event.matches(filter)?.0 {
                        category = bootp_event.category();
                    }
                }
                RecordType::Conn(conn_event) => {
                    if conn_event.matches(filter)?.0 {
                        category = conn_event.category();
                    }
                }
                RecordType::DceRpc(dcerpc_event) => {
                    if dcerpc_event.matches(filter)?.0 {
                        category = dcerpc_event.category();
                    }
                }
                RecordType::Dhcp(dhcp_event) => {
                    if dhcp_event.matches(filter)?.0 {
                        category = dhcp_event.category();
                    }
                }
                RecordType::Dns(dns_event) => {
                    if dns_event.matches(filter)?.0 {
                        category = dns_event.category();
                    }
                }
                RecordType::Ftp(ftp_event) => {
                    if ftp_event.matches(filter)?.0 {
                        category = ftp_event.category();
                    }
                }
                RecordType::Http(http_event) => {
                    if http_event.matches(filter)?.0 {
                        category = http_event.category();
                    }
                }
                RecordType::Kerberos(kerberos_event) => {
                    if kerberos_event.matches(filter)?.0 {
                        category = kerberos_event.category();
                    }
                }
                RecordType::Ldap(ldap_event) => {
                    if ldap_event.matches(filter)?.0 {
                        category = ldap_event.category();
                    }
                }
                RecordType::MalformedDns(malformed_dns_event) => {
                    if malformed_dns_event.matches(filter)?.0 {
                        category = malformed_dns_event.category();
                    }
                }
                RecordType::Mqtt(mqtt_event) => {
                    if mqtt_event.matches(filter)?.0 {
                        category = mqtt_event.category();
                    }
                }
                RecordType::Nfs(nfs_event) => {
                    if nfs_event.matches(filter)?.0 {
                        category = nfs_event.category();
                    }
                }
                RecordType::Ntlm(ntlm_event) => {
                    if ntlm_event.matches(filter)?.0 {
                        category = ntlm_event.category();
                    }
                }
                RecordType::Radius(radius_event) => {
                    if radius_event.matches(filter)?.0 {
                        category = radius_event.category();
                    }
                }
                RecordType::Rdp(rdp_event) => {
                    if rdp_event.matches(filter)?.0 {
                        category = rdp_event.category();
                    }
                }
                RecordType::Smb(smb_event) => {
                    if smb_event.matches(filter)?.0 {
                        category = smb_event.category();
                    }
                }
                RecordType::Smtp(smtp_event) => {
                    if smtp_event.matches(filter)?.0 {
                        category = smtp_event.category();
                    }
                }
                RecordType::Ssh(ssh_event) => {
                    if ssh_event.matches(filter)?.0 {
                        category = ssh_event.category();
                    }
                }
                RecordType::Tls(tls_event) => {
                    if tls_event.matches(filter)?.0 {
                        category = tls_event.category();
                    }
                }
                RecordType::UnusualDestinationPattern(event) => {
                    if event.matches(filter)?.0 {
                        category = event.category();
                    }
                }
            },
            Event::WindowsThreat(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::NetworkThreat(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::ExtraThreat(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::LockyRansomware(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
            Event::SuspiciousTlsTraffic(event) => {
                if event.matches(filter)?.0 {
                    category = event.category();
                }
            }
        }

        if let Some(category) = category {
            counter.entry(category).and_modify(|e| *e += 1).or_insert(1);
        }

        Ok(())
    }

    /// Counts the number of events per IP address.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_ip_address(
        &self,
        counter: &mut HashMap<IpAddr, usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        let addr_pair = self.address_pair(filter)?;

        if let Some(orig_addr) = addr_pair.0 {
            counter
                .entry(orig_addr)
                .and_modify(|e| *e += 1)
                .or_insert(1);
        }
        if let Some(resp_addr) = addr_pair.1 {
            counter
                .entry(resp_addr)
                .and_modify(|e| *e += 1)
                .or_insert(1);
        }

        Ok(())
    }

    /// Counts the number of events per IP address pair.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_ip_address_pair(
        &self,
        counter: &mut HashMap<(IpAddr, IpAddr), usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        let addr_pair = self.address_pair(filter)?;

        if let Some(orig_addr) = addr_pair.0
            && let Some(resp_addr) = addr_pair.1
        {
            counter
                .entry((orig_addr, resp_addr))
                .and_modify(|e| *e += 1)
                .or_insert(1);
        }

        Ok(())
    }

    /// Counts the number of events per IP address and event kind.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_ip_address_pair_and_kind(
        &self,
        counter: &mut HashMap<(IpAddr, IpAddr, &'static str), usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        let addr_pair = self.address_pair(filter)?;
        let kind = self.kind(filter)?;

        if let Some(orig_addr) = addr_pair.0
            && let Some(resp_addr) = addr_pair.1
            && let Some(kind) = kind
        {
            counter
                .entry((orig_addr, resp_addr, kind))
                .and_modify(|e| *e += 1)
                .or_insert(1);
        }

        Ok(())
    }

    /// Counts the number of events per originator IP address.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_originator_ip_address(
        &self,
        counter: &mut HashMap<IpAddr, usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        let addr_pair = self.address_pair(filter)?;

        if let Some(orig_addr) = addr_pair.0 {
            counter
                .entry(orig_addr)
                .and_modify(|e| *e += 1)
                .or_insert(1);
        }

        Ok(())
    }

    /// Counts the number of events per responder IP address.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_responder_ip_address(
        &self,
        counter: &mut HashMap<IpAddr, usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        let addr_pair = self.address_pair(filter)?;

        if let Some(resp_addr) = addr_pair.1 {
            counter
                .entry(resp_addr)
                .and_modify(|e| *e += 1)
                .or_insert(1);
        }

        Ok(())
    }

    /// Counts the number of events per event kind.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_kind(
        &self,
        counter: &mut HashMap<String, usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        let kind = if let Event::HttpThreat(event) = self {
            if event.matches(filter)?.0 {
                Some(event.attack_kind.clone())
            } else {
                None
            }
        } else {
            self.kind(filter)?.map(ToString::to_string)
        };

        if let Some(kind) = kind {
            counter.entry(kind).and_modify(|e| *e += 1).or_insert(1);
        }

        Ok(())
    }

    /// Counts the number of events per level.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_level(
        &self,
        counter: &mut HashMap<ThreatLevel, usize>,
        filter: &EventFilter,
    ) -> Result<()> {
        let mut level = None;
        match self {
            Event::DnsCovertChannel(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::HttpThreat(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::RdpBruteForce(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::RepeatedHttpSessions(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::TorConnection(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::TorConnectionConn(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::DomainGenerationAlgorithm(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::FtpBruteForce(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::FtpPlainText(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::PortScan(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::MultiHostPortScan(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::ExternalDdos(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::NonBrowser(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::LdapBruteForce(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::LdapPlainText(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::CryptocurrencyMiningPool(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(bootp_event) => {
                    if bootp_event.matches(filter)?.0 {
                        level = Some(bootp_event.level());
                    }
                }
                RecordType::Conn(conn_event) => {
                    if conn_event.matches(filter)?.0 {
                        level = Some(conn_event.level());
                    }
                }
                RecordType::DceRpc(dcerpc_event) => {
                    if dcerpc_event.matches(filter)?.0 {
                        level = Some(dcerpc_event.level());
                    }
                }
                RecordType::Dhcp(dhcp_event) => {
                    if dhcp_event.matches(filter)?.0 {
                        level = Some(dhcp_event.level());
                    }
                }
                RecordType::Dns(dns_event) => {
                    if dns_event.matches(filter)?.0 {
                        level = Some(dns_event.level());
                    }
                }
                RecordType::Ftp(ftp_event) => {
                    if ftp_event.matches(filter)?.0 {
                        level = Some(ftp_event.level());
                    }
                }
                RecordType::Http(http_event) => {
                    if http_event.matches(filter)?.0 {
                        level = Some(http_event.level());
                    }
                }
                RecordType::Kerberos(kerberos_event) => {
                    if kerberos_event.matches(filter)?.0 {
                        level = Some(kerberos_event.level());
                    }
                }
                RecordType::Ldap(ldap_event) => {
                    if ldap_event.matches(filter)?.0 {
                        level = Some(ldap_event.level());
                    }
                }
                RecordType::MalformedDns(malformed_dns_event) => {
                    if malformed_dns_event.matches(filter)?.0 {
                        level = Some(malformed_dns_event.level());
                    }
                }
                RecordType::Mqtt(mqtt_event) => {
                    if mqtt_event.matches(filter)?.0 {
                        level = Some(mqtt_event.level());
                    }
                }
                RecordType::Nfs(nfs_event) => {
                    if nfs_event.matches(filter)?.0 {
                        level = Some(nfs_event.level());
                    }
                }
                RecordType::Ntlm(ntlm_event) => {
                    if ntlm_event.matches(filter)?.0 {
                        level = Some(ntlm_event.level());
                    }
                }
                RecordType::Radius(radius_event) => {
                    if radius_event.matches(filter)?.0 {
                        level = Some(radius_event.level());
                    }
                }
                RecordType::Rdp(rdp_event) => {
                    if rdp_event.matches(filter)?.0 {
                        level = Some(rdp_event.level());
                    }
                }
                RecordType::Smb(smb_event) => {
                    if smb_event.matches(filter)?.0 {
                        level = Some(smb_event.level());
                    }
                }
                RecordType::Smtp(smtp_event) => {
                    if smtp_event.matches(filter)?.0 {
                        level = Some(smtp_event.level());
                    }
                }
                RecordType::Ssh(ssh_event) => {
                    if ssh_event.matches(filter)?.0 {
                        level = Some(ssh_event.level());
                    }
                }
                RecordType::Tls(tls_event) => {
                    if tls_event.matches(filter)?.0 {
                        level = Some(tls_event.level());
                    }
                }
                RecordType::UnusualDestinationPattern(event) => {
                    if event.matches(filter)?.0 {
                        level = Some(event.level());
                    }
                }
            },
            Event::WindowsThreat(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::NetworkThreat(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::ExtraThreat(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::LockyRansomware(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
            Event::SuspiciousTlsTraffic(event) => {
                if event.matches(filter)?.0 {
                    level = Some(event.level());
                }
            }
        }

        if let Some(level) = level {
            *counter.entry(level).or_insert(0) += 1;
        }

        Ok(())
    }

    /// Counts the number of events per network.
    ///
    /// # Errors
    ///
    /// Returns an error if matching the event against the filter fails.
    pub fn count_network(
        &self,
        counter: &mut HashMap<u32, usize>,
        networks: &[Network],
        filter: &EventFilter,
    ) -> Result<()> {
        let addr_pair = self.address_pair(filter)?;

        if let Some(orig_addr) = addr_pair.0
            && let Some(id) = find_network(orig_addr, networks)
        {
            counter.entry(id).and_modify(|e| *e += 1).or_insert(1);
        }
        if let Some(resp_addr) = addr_pair.1
            && let Some(id) = find_network(resp_addr, networks)
        {
            counter.entry(id).and_modify(|e| *e += 1).or_insert(1);
        }

        Ok(())
    }

    /// Sets the triage scores of the event.
    pub fn set_triage_scores(&mut self, triage_scores: Vec<TriageScore>) {
        match self {
            Event::DnsCovertChannel(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::HttpThreat(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::RdpBruteForce(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::RepeatedHttpSessions(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::TorConnection(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::TorConnectionConn(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::DomainGenerationAlgorithm(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::FtpBruteForce(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::FtpPlainText(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::PortScan(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::MultiHostPortScan(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::ExternalDdos(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::NonBrowser(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::LdapBruteForce(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::LdapPlainText(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::CryptocurrencyMiningPool(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(bootp_event) => {
                    bootp_event.triage_scores = Some(triage_scores);
                }
                RecordType::Conn(conn_event) => {
                    conn_event.triage_scores = Some(triage_scores);
                }
                RecordType::DceRpc(dcerpc_event) => {
                    dcerpc_event.triage_scores = Some(triage_scores);
                }
                RecordType::Dhcp(dhcp_event) => {
                    dhcp_event.triage_scores = Some(triage_scores);
                }
                RecordType::Dns(dns_event) => {
                    dns_event.triage_scores = Some(triage_scores);
                }
                RecordType::Ftp(ftp_event) => {
                    ftp_event.triage_scores = Some(triage_scores);
                }
                RecordType::Http(http_event) => {
                    http_event.triage_scores = Some(triage_scores);
                }
                RecordType::Kerberos(kerberos_event) => {
                    kerberos_event.triage_scores = Some(triage_scores);
                }
                RecordType::Ldap(ldap_event) => {
                    ldap_event.triage_scores = Some(triage_scores);
                }
                RecordType::MalformedDns(malformed_dns_event) => {
                    malformed_dns_event.triage_scores = Some(triage_scores);
                }
                RecordType::Mqtt(mqtt_event) => {
                    mqtt_event.triage_scores = Some(triage_scores);
                }
                RecordType::Nfs(nfs_event) => {
                    nfs_event.triage_scores = Some(triage_scores);
                }
                RecordType::Ntlm(ntlm_event) => {
                    ntlm_event.triage_scores = Some(triage_scores);
                }
                RecordType::Radius(radius_event) => {
                    radius_event.triage_scores = Some(triage_scores);
                }
                RecordType::Rdp(rdp_event) => {
                    rdp_event.triage_scores = Some(triage_scores);
                }
                RecordType::Smb(smb_event) => {
                    smb_event.triage_scores = Some(triage_scores);
                }
                RecordType::Smtp(smtp_event) => {
                    smtp_event.triage_scores = Some(triage_scores);
                }
                RecordType::Ssh(ssh_event) => {
                    ssh_event.triage_scores = Some(triage_scores);
                }
                RecordType::Tls(tls_event) => {
                    tls_event.triage_scores = Some(triage_scores);
                }
                RecordType::UnusualDestinationPattern(event) => {
                    event.triage_scores = Some(triage_scores);
                }
            },
            Event::WindowsThreat(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::NetworkThreat(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::ExtraThreat(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::LockyRansomware(event) => {
                event.triage_scores = Some(triage_scores);
            }
            Event::SuspiciousTlsTraffic(event) => {
                event.triage_scores = Some(triage_scores);
            }
        }
    }

    /// Generate syslog msgid and message body for RFC5424.
    #[must_use]
    pub fn syslog_message(&self) -> (String, String, String) {
        let (kind, _category) = self.kind_and_category();
        ("DETECT".to_string(), format!("{kind:?}"), format!("{self}"))
    }
}

fn find_network(ip: IpAddr, networks: &[Network]) -> Option<u32> {
    for net in networks {
        if net.networks.contains(ip) {
            return Some(net.id);
        }
    }
    None
}

#[derive(Serialize, Clone, Copy, Debug, Deserialize, Eq, FromPrimitive, PartialEq, ToPrimitive)]
#[repr(u32)]
#[non_exhaustive]
#[allow(clippy::module_name_repetitions)]
pub enum EventKind {
    DnsCovertChannel = 0,
    HttpThreat = 1,
    RdpBruteForce = 2,
    RepeatedHttpSessions = 3,
    ExtraThreat = 4,
    TorConnection = 5,
    DomainGenerationAlgorithm = 6,
    FtpBruteForce = 7,
    FtpPlainText = 8,
    PortScan = 9,
    MultiHostPortScan = 10,
    NonBrowser = 11,
    LdapBruteForce = 12,
    LdapPlainText = 13,
    ExternalDdos = 14,
    CryptocurrencyMiningPool = 15,
    BlocklistConn = 16,
    BlocklistDns = 17,
    BlocklistDceRpc = 18,
    BlocklistFtp = 19,
    BlocklistHttp = 20,
    BlocklistKerberos = 21,
    BlocklistLdap = 22,
    BlocklistMqtt = 23,
    BlocklistNfs = 24,
    BlocklistNtlm = 25,
    BlocklistRdp = 26,
    BlocklistSmb = 27,
    BlocklistSmtp = 28,
    BlocklistSsh = 29,
    BlocklistTls = 30,
    WindowsThreat = 31,
    NetworkThreat = 32,
    LockyRansomware = 33,
    SuspiciousTlsTraffic = 34,
    BlocklistBootp = 35,
    BlocklistDhcp = 36,
    TorConnectionConn = 37,
    BlocklistRadius = 38,
    BlocklistMalformedDns = 39,
    UnusualDestinationPattern = 40,
}

impl EventKind {
    /// Returns the MITRE ATT&CK categories that this event kind can match.
    ///
    /// Some event kinds like `DnsCovertChannel` can match multiple categories
    /// such as both `CommandAndControl` and `Exfiltration`.
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub fn categories(&self) -> &'static [EventCategory] {
        match self {
            Self::DnsCovertChannel => &[
                EventCategory::CommandAndControl,
                EventCategory::Exfiltration,
            ],
            Self::HttpThreat => &[EventCategory::Reconnaissance],
            Self::RdpBruteForce => &[EventCategory::Discovery],
            Self::RepeatedHttpSessions => &[EventCategory::Exfiltration],
            Self::ExtraThreat => &[EventCategory::Reconnaissance],
            Self::TorConnection => &[EventCategory::CommandAndControl],
            Self::TorConnectionConn => &[EventCategory::CommandAndControl],
            Self::DomainGenerationAlgorithm => &[EventCategory::CommandAndControl],
            Self::FtpBruteForce => &[EventCategory::CredentialAccess],
            Self::FtpPlainText => &[EventCategory::LateralMovement],
            Self::PortScan => &[EventCategory::Reconnaissance],
            Self::MultiHostPortScan => &[EventCategory::Reconnaissance],
            Self::NonBrowser => &[EventCategory::CommandAndControl],
            Self::LdapBruteForce => &[EventCategory::CredentialAccess],
            Self::LdapPlainText => &[EventCategory::LateralMovement],
            Self::ExternalDdos => &[EventCategory::Impact],
            Self::CryptocurrencyMiningPool => &[EventCategory::CommandAndControl],
            Self::BlocklistConn => &[EventCategory::InitialAccess],
            Self::BlocklistDns => &[EventCategory::InitialAccess],
            Self::BlocklistDceRpc => &[EventCategory::InitialAccess],
            Self::BlocklistFtp => &[EventCategory::InitialAccess],
            Self::BlocklistHttp => &[EventCategory::InitialAccess],
            Self::BlocklistKerberos => &[EventCategory::InitialAccess],
            Self::BlocklistLdap => &[EventCategory::InitialAccess],
            Self::BlocklistMalformedDns => &[EventCategory::InitialAccess],
            Self::BlocklistMqtt => &[EventCategory::InitialAccess],
            Self::BlocklistNfs => &[EventCategory::InitialAccess],
            Self::BlocklistNtlm => &[EventCategory::InitialAccess],
            Self::BlocklistRdp => &[EventCategory::InitialAccess],
            Self::BlocklistSmb => &[EventCategory::InitialAccess],
            Self::BlocklistSmtp => &[EventCategory::InitialAccess],
            Self::BlocklistSsh => &[EventCategory::InitialAccess],
            Self::BlocklistTls => &[EventCategory::InitialAccess],
            Self::WindowsThreat => &[EventCategory::Reconnaissance],
            Self::NetworkThreat => &[EventCategory::Reconnaissance],
            Self::LockyRansomware => &[EventCategory::Impact],
            Self::SuspiciousTlsTraffic => &[EventCategory::CommandAndControl],
            Self::BlocklistBootp => &[EventCategory::InitialAccess],
            Self::BlocklistDhcp => &[EventCategory::InitialAccess],
            Self::BlocklistRadius => &[EventCategory::InitialAccess],
            Self::UnusualDestinationPattern => &[EventCategory::Reconnaissance],
        }
    }
}

/// Machine Learning Method.
#[derive(Clone, Copy, Eq, PartialEq, Deserialize, Serialize, Debug)]
pub enum LearningMethod {
    Unsupervised,
    SemiSupervised,
}

/// A filter used to query events from the database.
///
/// # Notes
///
/// The `customers` field does **not** filter events by an explicit customer ID
/// stored on each event. Instead, the current implementation resolves each
/// customer's registered network ranges and matches an event if any of its
/// originator addresses (`orig_addrs`) or responder addresses (`resp_addrs`) fall
/// within those ranges.
///
/// In other words, customer filtering performs network-range matching against
/// the customer's registered networks, not direct per-event customer
/// attribution.
///
/// # Limitations
///
/// The event storage schema (`EventDb`) does not currently store an explicit
/// customer identifier for each event. Introducing explicit customer
/// attribution in storage would require a cross-cutting schema change and is
/// intentionally out of scope. See [issue #687] for context.
///
/// [issue #687]: https://github.com/aicers/review-database/issues/687
#[allow(clippy::module_name_repetitions)]
pub struct EventFilter {
    customers: Option<Vec<Customer>>,
    endpoints: Option<Vec<Endpoint>>,
    directions: Option<(Vec<FlowKind>, Vec<HostNetworkGroup>)>,
    originator: Option<IpAddr>,
    responder: Option<IpAddr>,
    countries: Option<Vec<[u8; 2]>>,
    categories: Option<Vec<Option<EventCategory>>>,
    levels: Option<Vec<ThreatLevel>>,
    kinds: Option<Vec<String>>,
    learning_methods: Option<Vec<LearningMethod>>,
    sensors: Option<Vec<String>>,
    confidence_min: Option<f32>,
    confidence_max: Option<f32>,
    triage_policies: Option<Vec<TriagePolicyInput>>,
}

impl EventFilter {
    /// Creates a new `EventFilter`.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        customers: Option<Vec<Customer>>,
        endpoints: Option<Vec<Endpoint>>,
        directions: Option<(Vec<FlowKind>, Vec<HostNetworkGroup>)>,
        originator: Option<IpAddr>,
        responder: Option<IpAddr>,
        countries: Option<Vec<[u8; 2]>>,
        categories: Option<Vec<Option<EventCategory>>>,
        levels: Option<Vec<ThreatLevel>>,
        kinds: Option<Vec<String>>,
        learning_methods: Option<Vec<LearningMethod>>,
        sensors: Option<Vec<String>>,
        confidence_min: Option<f32>,
        confidence_max: Option<f32>,
        triage_policies: Option<Vec<TriagePolicyInput>>,
    ) -> Self {
        Self {
            customers,
            endpoints,
            directions,
            originator,
            responder,
            countries,
            categories,
            levels,
            kinds,
            learning_methods,
            sensors,
            confidence_min,
            confidence_max,
            triage_policies,
        }
    }

    #[must_use]
    pub fn has_country(&self) -> bool {
        self.countries.is_some()
    }

    pub fn moderate_kinds(&mut self) {
        if let Some(kinds) = self.kinds.as_mut() {
            moderate_kinds_by(kinds, &["dns", "covert", "channel"], "dns covert channel");
            moderate_kinds_by(
                kinds,
                &["http", "covert", "channel", "repeated", "http", "sessions"],
                "repeated http sessions",
            );
            moderate_kinds_by(kinds, &["rdp", "brute", "force"], "rdp brute force");
            moderate_kinds_by(kinds, &["tor", "connection"], "tor exit nodes");
            moderate_kinds_by(kinds, &["tor", "connection", "conn"], "tor exit nodes");
            moderate_kinds_by(kinds, &["domain", "generation", "algorithm"], "dga");
            moderate_kinds_by(kinds, &["ftp", "brute", "force"], "ftp brute force");
            moderate_kinds_by(kinds, &["ftp", "plain", "text"], "ftp plain text");
            moderate_kinds_by(kinds, &["ldap", "brute", "force"], "ldap brute force");
            moderate_kinds_by(kinds, &["ldap", "plain", "text"], "ldap plain text");
            moderate_kinds_by(
                kinds,
                &["multi", "host", "port", "scan"],
                "multi host port scan",
            );
            moderate_kinds_by(kinds, &["external", "ddos", "dos"], "external ddos");
            moderate_kinds_by(kinds, &["port", "scan"], "port scan");
            moderate_kinds_by(
                kinds,
                &["non", "browser", "non-browser", "connection"],
                "non browser",
            );
            moderate_kinds_by(
                kinds,
                &["cryptocurrency", "mining", "pool", "network", "connection"],
                "cryptocurrency mining pool",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "bootp"],
                "blocklist bootp",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "conn"],
                "blocklist conn",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "dcerpc", "dce/rpc"],
                "blocklist dcerpc",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "dhcp"],
                "blocklist dhcp",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "dns"],
                "blocklist dns",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "ftp"],
                "blocklist ftp",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "http"],
                "blocklist http",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "kerberos"],
                "blocklist kerberos",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "ldap"],
                "blocklist ldap",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "malformed", "dns"],
                "blocklist malformed dns",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "mqtt"],
                "blocklist mqtt",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "nfs"],
                "blocklist nfs",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "ntlm"],
                "blocklist ntlm",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "radius"],
                "blocklist radius",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "rdp"],
                "blocklist rdp",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "smb"],
                "blocklist smb",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "smtp"],
                "blocklist smtp",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "ssh"],
                "blocklist ssh",
            );
            moderate_kinds_by(
                kinds,
                &["block", "list", "blocklist", "tls"],
                "blocklist tls",
            );
            moderate_kinds_by(kinds, &["windows", "threat"], "windows threat");
            moderate_kinds_by(kinds, &["network", "threat"], "network threat");
            moderate_kinds_by(kinds, &["extra", "threat"], "extra threat");
            moderate_kinds_by(kinds, &["locky", "ransomware"], "locky ransomware");
            moderate_kinds_by(
                kinds,
                &["suspicious", "tls", "traffic"],
                "suspicious tls traffic",
            );
        }
    }
}

fn moderate_kinds_by(kinds: &mut Vec<String>, patterns: &[&str], full_name: &str) {
    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(patterns)
        .expect("automatic build should not fail");
    if kinds.iter().any(|kind| {
        let words = kind
            .split_whitespace()
            .map(ToString::to_string)
            .collect::<Vec<String>>();
        words.iter().all(|w| ac.is_match(w))
    }) {
        kinds.push(full_name.to_string());
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct EventMessage {
    #[serde(with = "timestamp::ts_nanoseconds")]
    pub time: Timestamp,
    pub kind: EventKind,
    #[serde(with = "serde_bytes")]
    pub fields: Vec<u8>,
}

impl EventMessage {
    /// # Errors
    ///
    /// Returns an error if the deserialization of the event fields fails.
    pub fn syslog_rfc5424(&self) -> Result<(String, String, String)> {
        let msg = match self.kind {
            EventKind::DnsCovertChannel => bincode::deserialize::<DnsEventFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::HttpThreat => bincode::deserialize::<HttpThreatFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::RdpBruteForce => bincode::deserialize::<RdpBruteForceFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::RepeatedHttpSessions => {
                bincode::deserialize::<RepeatedHttpSessionsFields>(&self.fields)
                    .map(|fields| fields.syslog_rfc5424())
            }
            EventKind::TorConnection => bincode::deserialize::<HttpEventFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::TorConnectionConn => {
                bincode::deserialize::<BlocklistConnFields>(&self.fields)
                    .map(|fields| fields.syslog_rfc5424())
            }
            EventKind::DomainGenerationAlgorithm => bincode::deserialize::<DgaFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::FtpBruteForce => bincode::deserialize::<FtpBruteForceFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::FtpPlainText => bincode::deserialize::<FtpEventFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::PortScan => bincode::deserialize::<PortScanFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::MultiHostPortScan => {
                bincode::deserialize::<MultiHostPortScanFields>(&self.fields)
                    .map(|fields| fields.syslog_rfc5424())
            }
            EventKind::NonBrowser => bincode::deserialize::<HttpEventFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::LdapBruteForce => bincode::deserialize::<LdapBruteForceFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::LdapPlainText => bincode::deserialize::<LdapEventFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::ExternalDdos => bincode::deserialize::<ExternalDdosFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::CryptocurrencyMiningPool => {
                bincode::deserialize::<CryptocurrencyMiningPoolFields>(&self.fields)
                    .map(|fields| fields.syslog_rfc5424())
            }
            EventKind::BlocklistBootp => bincode::deserialize::<BlocklistBootpFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistConn => bincode::deserialize::<BlocklistConnFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistDceRpc => {
                bincode::deserialize::<BlocklistDceRpcFields>(&self.fields)
                    .map(|fields| fields.syslog_rfc5424())
            }
            EventKind::BlocklistDhcp => bincode::deserialize::<BlocklistDhcpFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistDns => bincode::deserialize::<BlocklistDnsFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistFtp => bincode::deserialize::<FtpEventFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistHttp => bincode::deserialize::<BlocklistHttpFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistKerberos => {
                bincode::deserialize::<BlocklistKerberosFields>(&self.fields)
                    .map(|fields| fields.syslog_rfc5424())
            }
            EventKind::BlocklistLdap => bincode::deserialize::<LdapEventFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistMalformedDns => {
                bincode::deserialize::<BlocklistMalformedDnsFields>(&self.fields)
                    .map(|fields| fields.syslog_rfc5424())
            }
            EventKind::BlocklistMqtt => bincode::deserialize::<BlocklistMqttFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistNfs => bincode::deserialize::<BlocklistNfsFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistNtlm => bincode::deserialize::<BlocklistNtlmFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistRadius => {
                bincode::deserialize::<BlocklistRadiusFields>(&self.fields)
                    .map(|fields| fields.syslog_rfc5424())
            }
            EventKind::BlocklistRdp => bincode::deserialize::<BlocklistRdpFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistSmb => bincode::deserialize::<BlocklistSmbFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistSmtp => bincode::deserialize::<BlocklistSmtpFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistSsh => bincode::deserialize::<BlocklistSshFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::BlocklistTls => bincode::deserialize::<BlocklistTlsFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::WindowsThreat => bincode::deserialize::<WindowsThreatFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::NetworkThreat => bincode::deserialize::<NetworkThreatFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::ExtraThreat => bincode::deserialize::<ExtraThreatFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::LockyRansomware => bincode::deserialize::<DnsEventFields>(&self.fields)
                .map(|fields| fields.syslog_rfc5424()),
            EventKind::SuspiciousTlsTraffic => {
                bincode::deserialize::<BlocklistTlsFields>(&self.fields)
                    .map(|fields| fields.syslog_rfc5424())
            }
            EventKind::UnusualDestinationPattern => {
                bincode::deserialize::<UnusualDestinationPatternFields>(&self.fields)
                    .map(|fields| fields.syslog_rfc5424())
            }
        };

        match msg {
            Ok(msg) => Ok((
                "DETECT".to_string(),
                format!("{:?}", self.kind),
                format!(
                    "time={:?} event_kind=\"{:?}\" {msg}",
                    timestamp::format_rfc3339(self.time)?,
                    self.kind
                ),
            )),
            Err(e) => Err(anyhow::anyhow!(
                "failed to deserialize event fields: {e}. time={:?}, event_kind={:?}",
                timestamp::format_rfc3339(self.time)?,
                self.kind
            )),
        }
    }
}

macro_rules! resolve_pair_country_codes {
    ($fields:ident, $locator:ident) => {
        $fields.orig_country_code = $locator.lookup_country_code($fields.orig_addr);
        $fields.resp_country_code = $locator.lookup_country_code($fields.resp_addr);
    };
}

macro_rules! resolve_resp_vec_country_codes {
    ($fields:ident, $locator:ident) => {
        $fields.orig_country_code = $locator.lookup_country_code($fields.orig_addr);
        $fields.resp_country_codes = $fields
            .resp_addrs
            .iter()
            .copied()
            .map(|addr| $locator.lookup_country_code(addr))
            .collect();
    };
}

fn deserialize_for_storage<S, T>(bytes: &[u8]) -> Result<T>
where
    S: for<'de> Deserialize<'de>,
    T: From<S>,
{
    let shared: S = bincode::deserialize(bytes)
        .context("failed to deserialize event fields as the producer-facing schema")?;
    Ok(shared.into())
}

fn serialize_stored_fields<T: Serialize>(stored: &T) -> Result<Vec<u8>> {
    bincode::serialize(stored).context("failed to serialize event fields for storage")
}

macro_rules! convert_pair_for_storage {
    ($bytes:expr, $prod:ty, $stored:ty, $locator:expr) => {{
        let mut stored: $stored = deserialize_for_storage::<$prod, $stored>($bytes)?;
        if let Some(locator) = $locator {
            resolve_pair_country_codes!(stored, locator);
        }
        serialize_stored_fields(&stored)
    }};
}

macro_rules! convert_resp_vec_for_storage {
    ($bytes:expr, $prod:ty, $stored:ty, $locator:expr) => {{
        let mut stored: $stored = deserialize_for_storage::<$prod, $stored>($bytes)?;
        if let Some(locator) = $locator {
            resolve_resp_vec_country_codes!(stored, locator);
        }
        serialize_stored_fields(&stored)
    }};
}

/// Converts producer-facing `*Fields` bytes into the on-disk
/// `*FieldsStored` representation for the given [`EventKind`].
///
/// When `locator` is provided, endpoint country codes are resolved during
/// conversion so the stored value is serialized only once.
fn convert_for_storage(
    kind: EventKind,
    bytes: &[u8],
    locator: Option<&dyn crate::geo::CountryLookup>,
) -> Result<Vec<u8>> {
    match kind {
        EventKind::BlocklistBootp => convert_pair_for_storage!(
            bytes,
            BlocklistBootpFields,
            BlocklistBootpFieldsStored,
            locator
        ),
        EventKind::BlocklistConn | EventKind::TorConnectionConn => convert_pair_for_storage!(
            bytes,
            BlocklistConnFields,
            BlocklistConnFieldsStored,
            locator
        ),
        EventKind::BlocklistDceRpc => convert_pair_for_storage!(
            bytes,
            BlocklistDceRpcFields,
            BlocklistDceRpcFieldsStored,
            locator
        ),
        EventKind::BlocklistDhcp => convert_pair_for_storage!(
            bytes,
            BlocklistDhcpFields,
            BlocklistDhcpFieldsStored,
            locator
        ),
        EventKind::BlocklistDns => {
            convert_pair_for_storage!(bytes, BlocklistDnsFields, BlocklistDnsFieldsStored, locator)
        }
        EventKind::BlocklistFtp | EventKind::FtpPlainText => {
            convert_pair_for_storage!(bytes, FtpEventFields, FtpEventFieldsStored, locator)
        }
        EventKind::BlocklistHttp => convert_pair_for_storage!(
            bytes,
            BlocklistHttpFields,
            BlocklistHttpFieldsStored,
            locator
        ),
        EventKind::BlocklistKerberos => convert_pair_for_storage!(
            bytes,
            BlocklistKerberosFields,
            BlocklistKerberosFieldsStored,
            locator
        ),
        EventKind::BlocklistLdap | EventKind::LdapPlainText => {
            convert_pair_for_storage!(bytes, LdapEventFields, LdapEventFieldsStored, locator)
        }
        EventKind::BlocklistMalformedDns => convert_pair_for_storage!(
            bytes,
            BlocklistMalformedDnsFields,
            BlocklistMalformedDnsFieldsStored,
            locator
        ),
        EventKind::BlocklistMqtt => {
            convert_pair_for_storage!(
                bytes,
                BlocklistMqttFields,
                BlocklistMqttFieldsStored,
                locator
            )
        }
        EventKind::BlocklistNfs => {
            convert_pair_for_storage!(bytes, BlocklistNfsFields, BlocklistNfsFieldsStored, locator)
        }
        EventKind::BlocklistNtlm => convert_pair_for_storage!(
            bytes,
            BlocklistNtlmFields,
            BlocklistNtlmFieldsStored,
            locator
        ),
        EventKind::BlocklistRadius => convert_pair_for_storage!(
            bytes,
            BlocklistRadiusFields,
            BlocklistRadiusFieldsStored,
            locator
        ),
        EventKind::BlocklistRdp => {
            convert_pair_for_storage!(bytes, BlocklistRdpFields, BlocklistRdpFieldsStored, locator)
        }
        EventKind::BlocklistSmb => {
            convert_pair_for_storage!(bytes, BlocklistSmbFields, BlocklistSmbFieldsStored, locator)
        }
        EventKind::BlocklistSmtp => {
            convert_pair_for_storage!(
                bytes,
                BlocklistSmtpFields,
                BlocklistSmtpFieldsStored,
                locator
            )
        }
        EventKind::BlocklistSsh => {
            convert_pair_for_storage!(bytes, BlocklistSshFields, BlocklistSshFieldsStored, locator)
        }
        EventKind::BlocklistTls | EventKind::SuspiciousTlsTraffic => {
            convert_pair_for_storage!(bytes, BlocklistTlsFields, BlocklistTlsFieldsStored, locator)
        }
        EventKind::CryptocurrencyMiningPool => convert_pair_for_storage!(
            bytes,
            CryptocurrencyMiningPoolFields,
            CryptocurrencyMiningPoolFieldsStored,
            locator
        ),
        EventKind::DnsCovertChannel | EventKind::LockyRansomware => {
            convert_pair_for_storage!(bytes, DnsEventFields, DnsEventFieldsStored, locator)
        }
        EventKind::DomainGenerationAlgorithm => {
            convert_pair_for_storage!(bytes, DgaFields, DgaFieldsStored, locator)
        }
        EventKind::ExternalDdos => {
            let mut stored: ExternalDdosFieldsStored =
                deserialize_for_storage::<ExternalDdosFields, _>(bytes)?;
            if let Some(locator) = locator {
                stored.orig_country_codes = stored
                    .orig_addrs
                    .iter()
                    .copied()
                    .map(|addr| locator.lookup_country_code(addr))
                    .collect();
                stored.resp_country_code = locator.lookup_country_code(stored.resp_addr);
            }
            serialize_stored_fields(&stored)
        }
        EventKind::FtpBruteForce => convert_pair_for_storage!(
            bytes,
            FtpBruteForceFields,
            FtpBruteForceFieldsStored,
            locator
        ),
        EventKind::HttpThreat => {
            convert_pair_for_storage!(bytes, HttpThreatFields, HttpThreatFieldsStored, locator)
        }
        EventKind::LdapBruteForce => convert_pair_for_storage!(
            bytes,
            LdapBruteForceFields,
            LdapBruteForceFieldsStored,
            locator
        ),
        EventKind::MultiHostPortScan => convert_resp_vec_for_storage!(
            bytes,
            MultiHostPortScanFields,
            MultiHostPortScanFieldsStored,
            locator
        ),
        EventKind::NonBrowser | EventKind::TorConnection => {
            convert_pair_for_storage!(bytes, HttpEventFields, HttpEventFieldsStored, locator)
        }
        EventKind::PortScan => {
            convert_pair_for_storage!(bytes, PortScanFields, PortScanFieldsStored, locator)
        }
        EventKind::RdpBruteForce => convert_resp_vec_for_storage!(
            bytes,
            RdpBruteForceFields,
            RdpBruteForceFieldsStored,
            locator
        ),
        EventKind::RepeatedHttpSessions => convert_pair_for_storage!(
            bytes,
            RepeatedHttpSessionsFields,
            RepeatedHttpSessionsFieldsStored,
            locator
        ),
        EventKind::UnusualDestinationPattern => {
            let mut stored: UnusualDestinationPatternFieldsStored =
                deserialize_for_storage::<UnusualDestinationPatternFields, _>(bytes)?;
            if let Some(locator) = locator {
                stored.resp_country_codes = stored
                    .destination_ips
                    .iter()
                    .copied()
                    .map(|addr| locator.lookup_country_code(addr))
                    .collect();
            }
            serialize_stored_fields(&stored)
        }
        EventKind::ExtraThreat => serialize_stored_fields(&deserialize_for_storage::<
            ExtraThreatFields,
            ExtraThreatFieldsStored,
        >(bytes)?),
        EventKind::NetworkThreat => convert_pair_for_storage!(
            bytes,
            NetworkThreatFields,
            NetworkThreatFieldsStored,
            locator
        ),
        EventKind::WindowsThreat => serialize_stored_fields(&deserialize_for_storage::<
            WindowsThreatFields,
            WindowsThreatFieldsStored,
        >(bytes)?),
    }
}

/// Resolves endpoint country codes on already-serialized stored event fields.
///
/// Retained for migration paths where records are already in the on-disk
/// `*FieldsStored` representation. Ingestion resolves country codes inside
/// [`convert_for_storage`] instead.
pub(crate) fn resolve_stored_country_codes(
    kind: EventKind,
    bytes: &[u8],
    locator: Option<&dyn crate::geo::CountryLookup>,
) -> Result<Vec<u8>> {
    fn reserialize<T, F>(bytes: &[u8], mut update: F) -> Result<Vec<u8>>
    where
        T: for<'de> Deserialize<'de> + Serialize,
        F: FnMut(&mut T),
    {
        let mut fields: T = bincode::deserialize(bytes)
            .context("failed to deserialize stored event fields for country-code resolution")?;
        update(&mut fields);
        bincode::serialize(&fields).context("failed to serialize resolved event fields")
    }

    let Some(locator) = locator else {
        return Ok(bytes.to_vec());
    };

    macro_rules! pair {
        ($ty:ty) => {
            reserialize::<$ty, _>(bytes, |fields| {
                resolve_pair_country_codes!(fields, locator);
            })
        };
    }
    macro_rules! resp_vec {
        ($ty:ty) => {
            reserialize::<$ty, _>(bytes, |fields| {
                resolve_resp_vec_country_codes!(fields, locator);
            })
        };
    }

    match kind {
        EventKind::BlocklistBootp => pair!(BlocklistBootpFieldsStored),
        EventKind::BlocklistConn | EventKind::TorConnectionConn => {
            pair!(BlocklistConnFieldsStored)
        }
        EventKind::BlocklistDceRpc => pair!(BlocklistDceRpcFieldsStored),
        EventKind::BlocklistDhcp => pair!(BlocklistDhcpFieldsStored),
        EventKind::BlocklistDns => pair!(BlocklistDnsFieldsStored),
        EventKind::BlocklistFtp | EventKind::FtpPlainText => pair!(FtpEventFieldsStored),
        EventKind::BlocklistHttp => pair!(BlocklistHttpFieldsStored),
        EventKind::BlocklistKerberos => pair!(BlocklistKerberosFieldsStored),
        EventKind::BlocklistLdap | EventKind::LdapPlainText => {
            pair!(LdapEventFieldsStored)
        }
        EventKind::BlocklistMalformedDns => pair!(BlocklistMalformedDnsFieldsStored),
        EventKind::BlocklistMqtt => pair!(BlocklistMqttFieldsStored),
        EventKind::BlocklistNfs => pair!(BlocklistNfsFieldsStored),
        EventKind::BlocklistNtlm => pair!(BlocklistNtlmFieldsStored),
        EventKind::BlocklistRadius => pair!(BlocklistRadiusFieldsStored),
        EventKind::BlocklistRdp => pair!(BlocklistRdpFieldsStored),
        EventKind::BlocklistSmb => pair!(BlocklistSmbFieldsStored),
        EventKind::BlocklistSmtp => pair!(BlocklistSmtpFieldsStored),
        EventKind::BlocklistSsh => pair!(BlocklistSshFieldsStored),
        EventKind::BlocklistTls | EventKind::SuspiciousTlsTraffic => {
            pair!(BlocklistTlsFieldsStored)
        }
        EventKind::CryptocurrencyMiningPool => pair!(CryptocurrencyMiningPoolFieldsStored),
        EventKind::DnsCovertChannel | EventKind::LockyRansomware => {
            pair!(DnsEventFieldsStored)
        }
        EventKind::DomainGenerationAlgorithm => pair!(DgaFieldsStored),
        EventKind::ExternalDdos => reserialize::<ExternalDdosFieldsStored, _>(bytes, |fields| {
            fields.orig_country_codes = fields
                .orig_addrs
                .iter()
                .copied()
                .map(|addr| locator.lookup_country_code(addr))
                .collect();
            fields.resp_country_code = locator.lookup_country_code(fields.resp_addr);
        }),
        EventKind::FtpBruteForce => pair!(FtpBruteForceFieldsStored),
        EventKind::HttpThreat => pair!(HttpThreatFieldsStored),
        EventKind::LdapBruteForce => pair!(LdapBruteForceFieldsStored),
        EventKind::MultiHostPortScan => resp_vec!(MultiHostPortScanFieldsStored),
        EventKind::NetworkThreat => pair!(NetworkThreatFieldsStored),
        EventKind::NonBrowser | EventKind::TorConnection => pair!(HttpEventFieldsStored),
        EventKind::PortScan => pair!(PortScanFieldsStored),
        EventKind::RdpBruteForce => resp_vec!(RdpBruteForceFieldsStored),
        EventKind::RepeatedHttpSessions => pair!(RepeatedHttpSessionsFieldsStored),
        EventKind::UnusualDestinationPattern => {
            reserialize::<UnusualDestinationPatternFieldsStored, _>(bytes, |fields| {
                fields.resp_country_codes = fields
                    .destination_ips
                    .iter()
                    .copied()
                    .map(|addr| locator.lookup_country_code(addr))
                    .collect();
            })
        }
        EventKind::ExtraThreat | EventKind::WindowsThreat => Ok(bytes.to_vec()),
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct EventDb<'a> {
    inner: &'a rocksdb::OptimisticTransactionDB,
    country_lookup: Option<crate::geo::SharedCountryLookup>,
}

impl<'a> EventDb<'a> {
    #[must_use]
    pub fn new(inner: &'a rocksdb::OptimisticTransactionDB) -> EventDb<'a> {
        Self {
            inner,
            country_lookup: None,
        }
    }

    #[must_use]
    pub(crate) fn new_with_country_lookup(
        inner: &'a rocksdb::OptimisticTransactionDB,
        country_lookup: Option<crate::geo::SharedCountryLookup>,
    ) -> EventDb<'a> {
        Self {
            inner,
            country_lookup,
        }
    }

    /// Creates an iterator over key-value pairs, starting from `key`.
    #[must_use]
    pub fn iter_from(&self, key: i128, direction: Direction) -> EventIterator<'_> {
        let iter = self
            .inner
            .iterator(IteratorMode::From(&key.to_be_bytes(), direction));
        EventIterator { inner: iter }
    }

    /// Creates an iterator over key-value pairs for the entire events.
    #[must_use]
    pub fn iter_forward(&self) -> EventIterator<'_> {
        let iter = self.inner.iterator(IteratorMode::Start);
        EventIterator { inner: iter }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn raw_iter(&self) -> RawEventIterator<'_> {
        let iter = self.inner.iterator(IteratorMode::Start);
        RawEventIterator { inner: iter }
    }

    /// Stores a new event into the database.
    ///
    /// Converts the producer-facing `*Fields` bytes into the repository-local
    /// `*FieldsStored` representation so that the on-disk schema can evolve
    /// independently of the ingestion schema.
    ///
    /// # Errors
    ///
    /// Returns an error if the fields cannot be deserialized as the
    /// producer-facing schema or if a database operation fails.
    pub fn put(&self, event: &EventMessage) -> Result<i128> {
        use anyhow::anyhow;
        let stored_fields =
            convert_for_storage(event.kind, &event.fields, self.country_lookup.as_deref())?;
        let mut key = (i128::from(timestamp::event_key_nanos(event.time)) << 64)
            | (event
                .kind
                .to_i128()
                .ok_or(anyhow!("`EventKind` exceeds i128::MAX"))?
                << 32);
        loop {
            let txn = self.inner.transaction();
            if txn
                .get_for_update(key.to_be_bytes(), super::EXCLUSIVE)
                .context("cannot read from event database")?
                .is_some()
            {
                let start = i128::from(rng().next_u32());
                key |= start;
                #[allow(clippy::cast_possible_wrap)] // bit pattern
                while txn
                    .get_for_update(key.to_be_bytes(), super::EXCLUSIVE)
                    .context("cannot read from event database")?
                    .is_some()
                {
                    let next = (key + 1) & 0xffff_ffff;
                    if next == start {
                        bail!("too many events with the same timestamp");
                    }
                    key = key & 0xffff_ffff_ffff_ffff_ffff_ffff_0000_0000_u128 as i128 | next;
                }
            }
            txn.put(key.to_be_bytes(), stored_fields.as_slice())
                .context("cannot write event")?;
            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to store event");
                    }
                }
            }
        }
        Ok(key)
    }

    /// Updates an old key-value pair to a new one.
    ///
    /// # Errors
    ///
    /// Returns an error if the old value does not match the value in the database, the old key does
    /// not exist, or the database operation fails.
    pub fn update(&self, old: (&[u8], &[u8]), new: (&[u8], &[u8])) -> Result<()> {
        loop {
            let txn = self.inner.transaction();
            if let Some(old_value) = txn
                .get_for_update(old.0, super::EXCLUSIVE)
                .context("cannot read old entry")?
            {
                if old.1 != old_value.as_slice() {
                    bail!("old value mismatch");
                }
            } else {
                bail!("no such entry");
            }

            txn.put(new.0, new.1).context("failed to write new entry")?;
            if old.0 != new.0 {
                txn.delete(old.0).context("failed to delete old entry")?;
            }

            match txn.commit() {
                Ok(()) => break,
                Err(e) => {
                    if !e.as_ref().starts_with("Resource busy:") {
                        return Err(e).context("failed to update entry");
                    }
                }
            }
        }
        Ok(())
    }

    /// Removes all events whose timestamp is strictly before `before`.
    ///
    /// Events are stored with an i128 key whose upper 64 bits encode the
    /// timestamp in nanoseconds. This method iterates from the beginning
    /// of the event database and deletes every entry whose timestamp is
    /// earlier than `before`, using batched writes for efficiency.
    ///
    /// Returns the number of events deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if a database operation fails.
    pub fn remove_before(&self, before: Timestamp) -> Result<u64> {
        const BATCH_SIZE: usize = 1000;

        let cutoff_nanos = match timestamp::to_i64_nanos(before) {
            Ok(nanos) => nanos,
            Err(timestamp::TimestampError::OutOfI64Range(nanos)) => {
                if nanos >= 0 {
                    i64::MAX // far-future cutoff → delete everything
                } else {
                    i64::MIN // far-past cutoff → delete nothing
                }
            }
            Err(timestamp::TimestampError::Invalid(err)) => return Err(err.into()),
        };
        let mut deleted: u64 = 0;

        loop {
            let iter = self.inner.iterator(IteratorMode::Start);
            let mut batch = rocksdb::WriteBatchWithTransaction::<true>::default();
            let mut batch_count = 0;

            for item in iter {
                let (k, _v) = item.context("cannot read from event database")?;
                let key_bytes: [u8; 16] = match k.as_ref().try_into() {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let key = i128::from_be_bytes(key_bytes);
                let ts = (key >> 64) as i64;

                if ts >= cutoff_nanos {
                    break;
                }

                batch.delete(&k);
                batch_count += 1;

                if batch_count >= BATCH_SIZE {
                    break;
                }
            }

            if batch_count == 0 {
                break;
            }

            self.inner
                .write(batch)
                .context("failed to delete expired events")?;
            deleted += batch_count as u64;
        }

        Ok(deleted)
    }

    /// Inserts a raw key-value pair into the event database.
    #[cfg(test)]
    fn put_raw(&self, key: &[u8], value: &[u8]) {
        self.inner.put(key, value).expect("put_raw should succeed");
    }

    /// Returns the first event's on-disk key bytes in forward iteration order.
    #[cfg(test)]
    fn first_raw_event_key(&self) -> Result<Option<[u8; 16]>> {
        let mut iter = self.inner.iterator(IteratorMode::Start);
        match iter
            .next()
            .transpose()
            .context("cannot read from event database")?
        {
            None => Ok(None),
            Some((key, _value)) => {
                let key_bytes: [u8; 16] = key.as_ref().try_into().map_err(|_| {
                    anyhow::anyhow!("event key must be 16 bytes, got {}", key.len())
                })?;
                Ok(Some(key_bytes))
            }
        }
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct EventIterator<'i> {
    inner: rocksdb::DBIteratorWithThreadMode<
        'i,
        rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
    >,
}

#[allow(clippy::module_name_repetitions)]
#[cfg(test)]
pub(crate) struct RawEventIterator<'i> {
    inner: rocksdb::DBIteratorWithThreadMode<
        'i,
        rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
    >,
}

#[cfg(test)]
impl Iterator for RawEventIterator<'_> {
    type Item = Result<(Vec<u8>, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|item| {
            let (key, value) = item.context("cannot read from event database")?;
            Ok((key.to_vec(), value.to_vec()))
        })
    }
}

impl Iterator for EventIterator<'_> {
    type Item = Result<(i128, Event), InvalidEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        let (key, kind, time, v) = loop {
            let (k, v) = self.inner.next().transpose().ok().flatten()?;

            let key: [u8; 16] = if let Ok(key) = k.as_ref().try_into() {
                key
            } else {
                return Some(Err(InvalidEvent::Key(k)));
            };
            let key = i128::from_be_bytes(key);
            let time = timestamp::from_i64_nanos((key >> 64).try_into().expect("valid i64"))
                .expect(timestamp::I64_NANOS_JIFF_INVARIANT);
            let kind_num = (key & 0xffff_ffff_0000_0000) >> 32;
            if let Some(kind) = EventKind::from_i128(kind_num) {
                break (key, kind, time, v);
            }
            warn!("Unknown event kind: {kind_num}; skipped");
        };
        match kind {
            EventKind::BlocklistBootp => {
                let Ok(fields) = bincode::deserialize::<BlocklistBootpFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Bootp(BlocklistBootp::new(time, fields))),
                )))
            }
            EventKind::BlocklistConn => {
                let Ok(fields) = bincode::deserialize::<BlocklistConnFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Conn(BlocklistConn::new(time, fields))),
                )))
            }
            EventKind::BlocklistDceRpc => {
                let Ok(fields) = bincode::deserialize::<BlocklistDceRpcFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::DceRpc(BlocklistDceRpc::new(time, fields))),
                )))
            }
            EventKind::BlocklistDhcp => {
                let Ok(fields) = bincode::deserialize::<BlocklistDhcpFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Dhcp(BlocklistDhcp::new(time, fields))),
                )))
            }
            EventKind::BlocklistDns => {
                let Ok(fields) = bincode::deserialize::<BlocklistDnsFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Dns(BlocklistDns::new(time, fields))),
                )))
            }
            EventKind::BlocklistFtp => {
                let Ok(fields) = bincode::deserialize::<FtpEventFieldsStored>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Ftp(BlocklistFtp::new(time, fields))),
                )))
            }
            EventKind::BlocklistHttp => {
                let Ok(fields) = bincode::deserialize::<BlocklistHttpFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Http(BlocklistHttp::new(time, fields))),
                )))
            }
            EventKind::BlocklistKerberos => {
                let Ok(fields) = bincode::deserialize::<BlocklistKerberosFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Kerberos(BlocklistKerberos::new(time, fields))),
                )))
            }
            EventKind::BlocklistLdap => {
                let Ok(fields) = bincode::deserialize::<LdapEventFieldsStored>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Ldap(BlocklistLdap::new(time, fields))),
                )))
            }
            EventKind::BlocklistMalformedDns => {
                let Ok(fields) =
                    bincode::deserialize::<BlocklistMalformedDnsFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::MalformedDns(BlocklistMalformedDns::new(
                        time, fields,
                    ))),
                )))
            }
            EventKind::BlocklistMqtt => {
                let Ok(fields) = bincode::deserialize::<BlocklistMqttFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Mqtt(BlocklistMqtt::new(time, fields))),
                )))
            }
            EventKind::BlocklistNfs => {
                let Ok(fields) = bincode::deserialize::<BlocklistNfsFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Nfs(BlocklistNfs::new(time, fields))),
                )))
            }
            EventKind::BlocklistNtlm => {
                let Ok(fields) = bincode::deserialize::<BlocklistNtlmFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Ntlm(BlocklistNtlm::new(time, fields))),
                )))
            }
            EventKind::BlocklistRadius => {
                let Ok(fields) = bincode::deserialize::<BlocklistRadiusFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Radius(BlocklistRadius::new(time, fields))),
                )))
            }
            EventKind::BlocklistRdp => {
                let Ok(fields) = bincode::deserialize::<BlocklistRdpFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Rdp(BlocklistRdp::new(time, fields))),
                )))
            }
            EventKind::BlocklistSmb => {
                let Ok(fields) = bincode::deserialize::<BlocklistSmbFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Smb(BlocklistSmb::new(time, fields))),
                )))
            }
            EventKind::BlocklistSmtp => {
                let Ok(fields) = bincode::deserialize::<BlocklistSmtpFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Smtp(BlocklistSmtp::new(time, fields))),
                )))
            }
            EventKind::BlocklistSsh => {
                let Ok(fields) = bincode::deserialize::<BlocklistSshFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Ssh(BlocklistSsh::new(time, fields))),
                )))
            }
            EventKind::BlocklistTls => {
                let Ok(fields) = bincode::deserialize::<BlocklistTlsFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::Tls(BlocklistTls::new(time, fields))),
                )))
            }
            EventKind::CryptocurrencyMiningPool => {
                let Ok(fields) =
                    bincode::deserialize::<CryptocurrencyMiningPoolFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::CryptocurrencyMiningPool(CryptocurrencyMiningPool::new(time, fields)),
                )))
            }
            EventKind::DnsCovertChannel => {
                let Ok(fields) = bincode::deserialize::<DnsEventFieldsStored>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::DnsCovertChannel(DnsCovertChannel::new(time, fields)),
                )))
            }
            EventKind::DomainGenerationAlgorithm => {
                let Ok(fields) = bincode::deserialize::<DgaFieldsStored>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::DomainGenerationAlgorithm(DomainGenerationAlgorithm::new(time, fields)),
                )))
            }
            EventKind::ExternalDdos => {
                let Ok(fields) = bincode::deserialize::<ExternalDdosFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::ExternalDdos(ExternalDdos::new(time, &fields)),
                )))
            }
            EventKind::ExtraThreat => {
                let Ok(fields) = bincode::deserialize::<ExtraThreatFieldsStored>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::ExtraThreat(ExtraThreat::new(fields.time, fields)),
                )))
            }
            EventKind::FtpBruteForce => {
                let Ok(fields) = bincode::deserialize::<FtpBruteForceFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::FtpBruteForce(FtpBruteForce::new(time, &fields)),
                )))
            }
            EventKind::FtpPlainText => {
                let Ok(fields) = bincode::deserialize::<FtpEventFieldsStored>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::FtpPlainText(FtpPlainText::new(time, fields)),
                )))
            }
            EventKind::HttpThreat => {
                let Ok(fields) = bincode::deserialize::<HttpThreatFieldsStored>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::HttpThreat(HttpThreat::new(fields.time, fields)),
                )))
            }
            EventKind::LdapBruteForce => {
                let Ok(fields) = bincode::deserialize::<LdapBruteForceFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::LdapBruteForce(LdapBruteForce::new(time, &fields)),
                )))
            }
            EventKind::LdapPlainText => {
                let Ok(fields) = bincode::deserialize::<LdapEventFieldsStored>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::LdapPlainText(LdapPlainText::new(time, fields)),
                )))
            }
            EventKind::LockyRansomware => {
                let Ok(fields) = bincode::deserialize::<DnsEventFieldsStored>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::LockyRansomware(LockyRansomware::new(time, fields)),
                )))
            }
            EventKind::MultiHostPortScan => {
                let Ok(fields) = bincode::deserialize::<MultiHostPortScanFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::MultiHostPortScan(MultiHostPortScan::new(time, &fields)),
                )))
            }
            EventKind::NetworkThreat => {
                let Ok(fields) = bincode::deserialize::<NetworkThreatFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::NetworkThreat(NetworkThreat::new(fields.time, fields)),
                )))
            }
            EventKind::NonBrowser => {
                let Ok(fields) = bincode::deserialize::<HttpEventFieldsStored>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((key, Event::NonBrowser(NonBrowser::new(time, &fields)))))
            }
            EventKind::PortScan => {
                let Ok(fields) = bincode::deserialize::<PortScanFieldsStored>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((key, Event::PortScan(PortScan::new(time, &fields)))))
            }
            EventKind::RdpBruteForce => {
                let Ok(fields) = bincode::deserialize::<RdpBruteForceFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::RdpBruteForce(RdpBruteForce::new(time, &fields)),
                )))
            }
            EventKind::RepeatedHttpSessions => {
                let Ok(fields) =
                    bincode::deserialize::<RepeatedHttpSessionsFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::RepeatedHttpSessions(RepeatedHttpSessions::new(time, &fields)),
                )))
            }
            EventKind::SuspiciousTlsTraffic => {
                let Ok(fields) = bincode::deserialize::<BlocklistTlsFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::SuspiciousTlsTraffic(SuspiciousTlsTraffic::new(time, fields)),
                )))
            }
            EventKind::UnusualDestinationPattern => {
                let Ok(fields) =
                    bincode::deserialize::<UnusualDestinationPatternFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::Blocklist(RecordType::UnusualDestinationPattern(
                        UnusualDestinationPattern::new(time, fields),
                    )),
                )))
            }
            EventKind::TorConnection => {
                let Ok(fields) = bincode::deserialize::<HttpEventFieldsStored>(v.as_ref()) else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::TorConnection(TorConnection::new(time, &fields)),
                )))
            }
            EventKind::TorConnectionConn => {
                let Ok(fields) = bincode::deserialize::<BlocklistConnFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::TorConnectionConn(TorConnectionConn::new(time, fields)),
                )))
            }
            EventKind::WindowsThreat => {
                let Ok(fields) = bincode::deserialize::<WindowsThreatFieldsStored>(v.as_ref())
                else {
                    return Some(Err(InvalidEvent::Value(v)));
                };
                Some(Ok((
                    key,
                    Event::WindowsThreat(WindowsThreat::new(fields.time, fields)),
                )))
            }
        }
    }
}

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum InvalidEvent {
    Key(Box<[u8]>),
    Value(Box<[u8]>),
}

pub type Id = u32;

#[derive(Clone, Deserialize, Serialize, PartialEq, Debug)]
pub struct FilterEndpoint {
    pub direction: Option<TrafficDirection>,
    pub predefined: Option<Id>,
    pub custom: Option<HostNetworkGroup>,
}

/// Traffic flow direction.
#[derive(Clone, Copy, Eq, PartialEq, Deserialize, Serialize, Debug)]
pub enum FlowKind {
    Inbound,
    Outbound,
    Internal,
}

/// Possible network types of `CustomerNetwork`.
#[derive(Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum NetworkType {
    Intranet,
    Extranet,
    Gateway,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize, Debug)]
pub enum TrafficDirection {
    From,
    To,
}

#[cfg(test)]
mod stored_timestamp_contract;

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        net::{IpAddr, Ipv4Addr},
        str::FromStr,
        sync::Arc,
    };

    use chrono::{DateTime, TimeZone, Utc};
    use jiff::Timestamp;

    use super::timestamp;
    use crate::test::{DbGuard, acquire_db_permit};
    use crate::{
        Store,
        event::{
            BlocklistBootp, BlocklistBootpFields, BlocklistConn, BlocklistConnFields,
            BlocklistDceRpc, BlocklistDceRpcFields, BlocklistDhcp, BlocklistDhcpFields,
            BlocklistDns, BlocklistDnsFields, BlocklistFtp, BlocklistHttp, BlocklistHttpFields,
            BlocklistKerberos, BlocklistKerberosFields, BlocklistLdap, BlocklistMalformedDns,
            BlocklistMalformedDnsFields, BlocklistMqtt, BlocklistMqttFields, BlocklistNfs,
            BlocklistNfsFields, BlocklistNtlm, BlocklistNtlmFields, BlocklistRadius,
            BlocklistRadiusFields, BlocklistRdp, BlocklistRdpFields, BlocklistSmb,
            BlocklistSmbFields, BlocklistSmtp, BlocklistSmtpFields, BlocklistSsh,
            BlocklistSshFields, BlocklistTls, BlocklistTlsFields, CryptocurrencyMiningPool,
            CryptocurrencyMiningPoolFields, DceRpcContext, DgaFields, DnsCovertChannel,
            DnsEventFields, DomainGenerationAlgorithm, Event, EventFilter, EventKind, EventMessage,
            ExternalDdos, ExternalDdosFields, ExtraThreat, ExtraThreatFields, FtpBruteForce,
            FtpBruteForceFields, FtpEventFields, FtpPlainText, HttpEventFields, HttpThreat,
            HttpThreatFields, LOCKY_RANSOMWARE, LdapBruteForce, LdapBruteForceFields,
            LdapEventFields, LdapPlainText, LockyRansomware, MultiHostPortScan,
            MultiHostPortScanFields, NetworkThreat, NetworkThreatFields, NonBrowser, PortScan,
            PortScanFields, RdpBruteForce, RdpBruteForceFields, RecordType, RepeatedHttpSessions,
            RepeatedHttpSessionsFields, SuspiciousTlsTraffic, TorConnection, TriageScore,
            UnusualDestinationPatternFields, WindowsThreat, WindowsThreatFields,
        },
        types::EventCategory,
    };

    #[derive(Default)]
    struct FakeCountryLookup {
        codes: HashMap<IpAddr, [u8; 2]>,
        failures: HashSet<IpAddr>,
    }

    fn msg_time(time: DateTime<Utc>) -> Timestamp {
        timestamp::from_chrono(time).expect("test event message time must fit i64 nanoseconds")
    }

    impl crate::geo::CountryLookup for FakeCountryLookup {
        fn lookup_country_code(&self, addr: IpAddr) -> [u8; 2] {
            if self.failures.contains(&addr) {
                return crate::util::COUNTRY_CODE_INVALID;
            }
            self.codes
                .get(&addr)
                .copied()
                .unwrap_or(crate::util::COUNTRY_CODE_INVALID)
        }
    }

    fn setup_store() -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path(), None).unwrap());
        (permit, store)
    }

    fn setup_store_with_lookup(lookup: FakeCountryLookup) -> (DbGuard<'static>, Arc<Store>) {
        let permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            Store::new_with_country_lookup(
                db_dir.path(),
                backup_dir.path(),
                Some(Arc::new(lookup)),
            )
            .unwrap(),
        );
        (permit, store)
    }

    fn example_message(kind: EventKind, category: EventCategory) -> EventMessage {
        let fields = DnsEventFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 53,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            query: "foo.com".to_string(),
            answer: vec!["1.1.1.1".to_string()],
            trans_id: 1,
            rtt: 1,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: false,
            ttl: vec![1; 5],
            confidence: 0.8,
            category: Some(category),
        };
        EventMessage {
            time: msg_time(Utc::now()),
            kind,
            fields: bincode::serialize(&fields).expect("serializable"),
        }
    }

    #[test]
    fn event_db_put() {
        let (_permit, store) = setup_store();
        let db = store.events();
        assert!(db.iter_forward().next().is_none());

        let msg = example_message(
            EventKind::DnsCovertChannel,
            EventCategory::CommandAndControl,
        );
        db.put(&msg).unwrap();
        let raw: Vec<_> = db
            .raw_iter()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        let stored: super::DnsEventFieldsStored = bincode::deserialize(&raw[0].1).unwrap();
        assert_eq!(stored.orig_country_code, crate::util::COUNTRY_CODE_PENDING);
        assert_eq!(stored.resp_country_code, crate::util::COUNTRY_CODE_PENDING);
        let mut iter = db.iter_forward();
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());

        db.put(&msg).unwrap();
        let mut iter = db.iter_forward();
        assert!(iter.next().is_some());
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
    }

    #[test]
    fn event_db_put_resolves_country_codes() {
        let orig_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let resp_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let lookup = FakeCountryLookup {
            codes: HashMap::from([(orig_addr, *b"US"), (resp_addr, *b"KR")]),
            failures: HashSet::new(),
        };
        let (_permit, store) = setup_store_with_lookup(lookup);
        let db = store.events();
        db.put(&example_message(
            EventKind::DnsCovertChannel,
            EventCategory::CommandAndControl,
        ))
        .unwrap();

        let (_, bytes) = db.raw_iter().next().unwrap().unwrap();
        let stored: super::DnsEventFieldsStored = bincode::deserialize(&bytes).unwrap();
        assert_eq!(stored.orig_country_code, *b"US");
        assert_eq!(stored.resp_country_code, *b"KR");
    }

    #[test]
    fn country_filter_search_uses_stored_codes_without_ip2location() {
        fn country_only_filter(country: [u8; 2]) -> EventFilter {
            EventFilter {
                customers: None,
                endpoints: None,
                directions: None,
                originator: None,
                responder: None,
                countries: Some(vec![country]),
                categories: None,
                levels: None,
                kinds: None,
                learning_methods: None,
                sensors: None,
                confidence_min: None,
                confidence_max: None,
                triage_policies: None,
            }
        }

        let orig_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let resp_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let lookup = FakeCountryLookup {
            codes: HashMap::from([(orig_addr, *b"US"), (resp_addr, *b"KR")]),
            failures: HashSet::new(),
        };
        let (_permit, store) = setup_store_with_lookup(lookup);
        let db = store.events();
        db.put(&example_message(
            EventKind::DnsCovertChannel,
            EventCategory::CommandAndControl,
        ))
        .unwrap();

        let event = db.iter_forward().next().unwrap().unwrap().1;

        assert!(event.matches(&country_only_filter(*b"US")).unwrap().0);
        assert!(event.matches(&country_only_filter(*b"KR")).unwrap().0);
        assert!(!event.matches(&country_only_filter(*b"JP")).unwrap().0);
    }

    #[test]
    fn event_db_put_resolves_vector_country_codes_in_address_order() {
        let orig_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let first_resp_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let second_resp_addr = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let resp_addrs = vec![first_resp_addr, second_resp_addr];
        let lookup = FakeCountryLookup {
            codes: HashMap::from([
                (orig_addr, *b"US"),
                (first_resp_addr, *b"JP"),
                (second_resp_addr, *b"DE"),
            ]),
            failures: HashSet::new(),
        };
        let (_permit, store) = setup_store_with_lookup(lookup);
        let db = store.events();
        let fields = MultiHostPortScanFields {
            sensor: "collector1".to_string(),
            orig_addr,
            resp_port: 443,
            resp_addrs,
            proto: 6,
            first_event_start_time: 1,
            last_event_start_time: 2,
            confidence: 0.9,
            category: Some(EventCategory::Reconnaissance),
        };
        db.put(&EventMessage {
            time: msg_time(Utc::now()),
            kind: EventKind::MultiHostPortScan,
            fields: bincode::serialize(&fields).unwrap(),
        })
        .unwrap();

        let (_, bytes) = db.raw_iter().next().unwrap().unwrap();
        let stored: super::MultiHostPortScanFieldsStored = bincode::deserialize(&bytes).unwrap();
        assert_eq!(stored.orig_country_code, *b"US");
        assert_eq!(stored.resp_country_codes, vec![*b"JP", *b"DE"]);
        assert_eq!(stored.resp_country_codes.len(), stored.resp_addrs.len());
    }

    #[test]
    fn event_db_put_uses_invalid_code_after_attempted_lookup_failure() {
        let orig_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let lookup = FakeCountryLookup {
            codes: HashMap::new(),
            failures: HashSet::from([orig_addr]),
        };
        let (_permit, store) = setup_store_with_lookup(lookup);
        let db = store.events();
        db.put(&example_message(
            EventKind::DnsCovertChannel,
            EventCategory::CommandAndControl,
        ))
        .unwrap();

        let (_, bytes) = db.raw_iter().next().unwrap().unwrap();
        let stored: super::DnsEventFieldsStored = bincode::deserialize(&bytes).unwrap();
        assert_eq!(stored.orig_country_code, crate::util::COUNTRY_CODE_INVALID);
        assert_eq!(stored.resp_country_code, crate::util::COUNTRY_CODE_INVALID);
    }

    fn legacy_storage_bytes(
        kind: EventKind,
        producer_bytes: &[u8],
        locator: Option<&dyn crate::geo::CountryLookup>,
    ) -> Vec<u8> {
        use super::{convert_for_storage, resolve_stored_country_codes};

        let converted = convert_for_storage(kind, producer_bytes, None).unwrap();
        resolve_stored_country_codes(kind, &converted, locator).unwrap()
    }

    fn assert_storage_bytes_equivalent(
        kind: EventKind,
        producer_bytes: &[u8],
        locator: Option<&FakeCountryLookup>,
    ) {
        use super::convert_for_storage;

        let locator_ref = locator.map(|lookup| lookup as &dyn crate::geo::CountryLookup);
        let expected = legacy_storage_bytes(kind, producer_bytes, locator_ref);
        let actual = convert_for_storage(kind, producer_bytes, locator_ref).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn convert_for_storage_matches_legacy_two_step_without_locator() {
        let msg = example_message(
            EventKind::DnsCovertChannel,
            EventCategory::CommandAndControl,
        );
        assert_storage_bytes_equivalent(EventKind::DnsCovertChannel, &msg.fields, None);
    }

    #[test]
    fn convert_for_storage_matches_legacy_two_step_with_locator() {
        let orig_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let resp_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let lookup = FakeCountryLookup {
            codes: HashMap::from([(orig_addr, *b"US"), (resp_addr, *b"KR")]),
            failures: HashSet::new(),
        };
        let msg = example_message(
            EventKind::DnsCovertChannel,
            EventCategory::CommandAndControl,
        );
        assert_storage_bytes_equivalent(EventKind::DnsCovertChannel, &msg.fields, Some(&lookup));
    }

    #[test]
    fn convert_for_storage_matches_legacy_two_step_with_lookup_failures() {
        let orig_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let lookup = FakeCountryLookup {
            codes: HashMap::new(),
            failures: HashSet::from([orig_addr]),
        };
        let msg = example_message(
            EventKind::DnsCovertChannel,
            EventCategory::CommandAndControl,
        );
        assert_storage_bytes_equivalent(EventKind::DnsCovertChannel, &msg.fields, Some(&lookup));
    }

    #[test]
    fn convert_for_storage_matches_legacy_two_step_for_vector_country_codes() {
        let orig_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let first_resp_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let second_resp_addr = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let lookup = FakeCountryLookup {
            codes: HashMap::from([
                (orig_addr, *b"US"),
                (first_resp_addr, *b"JP"),
                (second_resp_addr, *b"DE"),
            ]),
            failures: HashSet::new(),
        };
        let fields = MultiHostPortScanFields {
            sensor: "collector1".to_string(),
            orig_addr,
            resp_port: 443,
            resp_addrs: vec![first_resp_addr, second_resp_addr],
            proto: 6,
            first_event_start_time: 1,
            last_event_start_time: 2,
            confidence: 0.9,
            category: Some(EventCategory::Reconnaissance),
        };
        let producer_bytes = bincode::serialize(&fields).unwrap();
        let locator_ref = Some(&lookup as &dyn crate::geo::CountryLookup);
        let expected =
            legacy_storage_bytes(EventKind::MultiHostPortScan, &producer_bytes, locator_ref);
        let actual =
            super::convert_for_storage(EventKind::MultiHostPortScan, &producer_bytes, locator_ref)
                .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn convert_for_storage_matches_legacy_two_step_for_external_ddos_country_codes() {
        let first_orig_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let second_orig_addr = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let resp_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let lookup = FakeCountryLookup {
            codes: HashMap::from([
                (first_orig_addr, *b"US"),
                (second_orig_addr, *b"DE"),
                (resp_addr, *b"KR"),
            ]),
            failures: HashSet::new(),
        };
        let fields = ExternalDdosFields {
            sensor: "collector1".to_string(),
            orig_addrs: vec![first_orig_addr, second_orig_addr],
            resp_addr,
            proto: 6,
            first_event_start_time: 1,
            last_event_start_time: 2,
            confidence: 0.9,
            category: Some(EventCategory::Impact),
        };
        let producer_bytes = bincode::serialize(&fields).unwrap();
        let locator_ref = Some(&lookup as &dyn crate::geo::CountryLookup);
        let expected = legacy_storage_bytes(EventKind::ExternalDdos, &producer_bytes, locator_ref);
        let actual =
            super::convert_for_storage(EventKind::ExternalDdos, &producer_bytes, locator_ref)
                .unwrap();
        assert_eq!(actual, expected);

        let stored: super::ExternalDdosFieldsStored = bincode::deserialize(&actual).unwrap();
        assert_eq!(stored.orig_country_codes, vec![*b"US", *b"DE"]);
        assert_eq!(stored.orig_country_codes.len(), stored.orig_addrs.len());
        assert_eq!(stored.resp_country_code, *b"KR");
    }

    #[test]
    fn convert_for_storage_matches_legacy_two_step_for_unusual_destination_pattern_country_codes() {
        let first_destination_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let second_destination_ip = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let lookup = FakeCountryLookup {
            codes: HashMap::from([
                (first_destination_ip, *b"US"),
                (second_destination_ip, *b"DE"),
            ]),
            failures: HashSet::new(),
        };
        let fields = UnusualDestinationPatternFields {
            sensor: "collector1".to_string(),
            sampling_window_start_time: 1,
            sampling_window_end_time: 2,
            destination_ips: vec![first_destination_ip, second_destination_ip],
            count: 2,
            expected_mean: 1.0,
            std_deviation: 0.5,
            z_score: 2.0,
            confidence: 0.9,
            category: Some(EventCategory::Reconnaissance),
        };
        let producer_bytes = bincode::serialize(&fields).unwrap();
        let locator_ref = Some(&lookup as &dyn crate::geo::CountryLookup);
        let expected = legacy_storage_bytes(
            EventKind::UnusualDestinationPattern,
            &producer_bytes,
            locator_ref,
        );
        let actual = super::convert_for_storage(
            EventKind::UnusualDestinationPattern,
            &producer_bytes,
            locator_ref,
        )
        .unwrap();
        assert_eq!(actual, expected);

        let stored: super::UnusualDestinationPatternFieldsStored =
            bincode::deserialize(&actual).unwrap();
        assert_eq!(stored.resp_country_codes, vec![*b"US", *b"DE"]);
        assert_eq!(
            stored.resp_country_codes.len(),
            stored.destination_ips.len()
        );
    }

    #[test]
    fn event_boundary_rejects_invalid_producer_bytes() {
        use super::convert_for_storage;

        // Garbage bytes for a kind that owns a shared/stored split must fail
        // at ingestion, not silently reach the store.
        let err = convert_for_storage(EventKind::DnsCovertChannel, &[0x01, 0x02], None);
        assert!(err.is_err());
    }

    #[test]
    fn event_boundary_round_trip_through_db() {
        let (_permit, store) = setup_store();
        let db = store.events();
        let msg = example_message(
            EventKind::DnsCovertChannel,
            EventCategory::CommandAndControl,
        );
        db.put(&msg).unwrap();
        let (_key, event) = db.iter_forward().next().unwrap().unwrap();
        let Event::DnsCovertChannel(covert) = event else {
            panic!("expected DnsCovertChannel");
        };
        assert_eq!(covert.sensor, "collector1");
        assert_eq!(covert.query, "foo.com");
        assert!((covert.confidence - 0.8).abs() < f32::EPSILON);
        assert_eq!(covert.category, Some(EventCategory::CommandAndControl));
    }

    fn extra_threat_message() -> EventMessage {
        let fields = ExtraThreatFields {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            sensor: "collector1".to_string(),
            service: "service".to_string(),
            content: "content".to_string(),
            db_name: "db_name".to_string(),
            rule_id: 1,
            matched_to: "matched_to".to_string(),
            cluster_id: Some(1),
            attack_kind: "attack_kind".to_string(),
            confidence: 0.9,
            category: Some(EventCategory::Reconnaissance),
            triage_scores: None,
        };
        EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::ExtraThreat,
            fields: bincode::serialize(&fields).expect("serializable"),
        }
    }

    fn network_threat_message() -> EventMessage {
        let fields = NetworkThreatFields {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 80,
            proto: 6,
            service: "http".to_string(),
            start_time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap()),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            content: "content".to_string(),
            db_name: "db_name".to_string(),
            rule_id: 1,
            matched_to: "matched_to".to_string(),
            cluster_id: Some(1),
            attack_kind: "attack_kind".to_string(),
            confidence: 0.9,
            category: Some(EventCategory::Reconnaissance),
            triage_scores: None,
        };
        EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::NetworkThreat,
            fields: bincode::serialize(&fields).expect("serializable"),
        }
    }

    fn windows_threat_message() -> EventMessage {
        let fields = WindowsThreatFields {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            sensor: "collector1".to_string(),
            service: "notepad".to_string(),
            agent_name: "win64".to_string(),
            agent_id: "agent_id".to_string(),
            process_guid: "process_guid".to_string(),
            process_id: 2972,
            image: "image".to_string(),
            user: "user".to_string(),
            content: "content".to_string(),
            db_name: "db".to_string(),
            rule_id: 100,
            matched_to: "match".to_string(),
            cluster_id: Some(900),
            attack_kind: "attack_kind".to_string(),
            confidence: 0.9,
            category: Some(EventCategory::Impact),
            triage_scores: None,
        };
        EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            kind: EventKind::WindowsThreat,
            fields: bincode::serialize(&fields).expect("serializable"),
        }
    }

    #[test]
    fn extra_threat_boundary_rejects_invalid_producer_bytes() {
        use super::convert_for_storage;

        let err = convert_for_storage(EventKind::ExtraThreat, &[0x01, 0x02], None);
        assert!(err.is_err());
    }

    #[test]
    fn extra_threat_boundary_round_trip_through_db() {
        let (_permit, store) = setup_store();
        let db = store.events();
        db.put(&extra_threat_message()).unwrap();
        let (_key, event) = db.iter_forward().next().unwrap().unwrap();
        let Event::ExtraThreat(threat) = event else {
            panic!("expected ExtraThreat");
        };
        assert_eq!(threat.sensor, "collector1");
        assert_eq!(threat.service, "service");
        assert_eq!(threat.content, "content");
        assert_eq!(threat.category, Some(EventCategory::Reconnaissance));
    }

    #[test]
    fn network_threat_boundary_rejects_invalid_producer_bytes() {
        use super::convert_for_storage;

        let err = convert_for_storage(EventKind::NetworkThreat, &[0x01, 0x02], None);
        assert!(err.is_err());
    }

    #[test]
    fn network_threat_boundary_round_trip_through_db() {
        let (_permit, store) = setup_store();
        let db = store.events();
        db.put(&network_threat_message()).unwrap();
        let (_key, event) = db.iter_forward().next().unwrap().unwrap();
        let Event::NetworkThreat(threat) = event else {
            panic!("expected NetworkThreat");
        };
        assert_eq!(threat.sensor, "collector1");
        assert_eq!(threat.orig_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(threat.resp_addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
        assert_eq!(threat.service, "http");
        assert_eq!(threat.category, Some(EventCategory::Reconnaissance));
    }

    #[test]
    fn windows_threat_boundary_rejects_invalid_producer_bytes() {
        use super::convert_for_storage;

        let err = convert_for_storage(EventKind::WindowsThreat, &[0x01, 0x02], None);
        assert!(err.is_err());
    }

    #[test]
    fn windows_threat_boundary_round_trip_through_db() {
        let (_permit, store) = setup_store();
        let db = store.events();
        db.put(&windows_threat_message()).unwrap();
        let (_key, event) = db.iter_forward().next().unwrap().unwrap();
        let Event::WindowsThreat(threat) = event else {
            panic!("expected WindowsThreat");
        };
        assert_eq!(threat.sensor, "collector1");
        assert_eq!(threat.service, "notepad");
        assert_eq!(threat.agent_name, "win64");
        assert_eq!(threat.attack_kind, "attack_kind");
        assert_eq!(threat.category, Some(EventCategory::Impact));
    }

    #[test]
    fn threat_families_runtime_constructors_share_stored_layout() {
        // The three threat families now expose a shared/stored/runtime layering
        // similar to other event families. Verify the bridge: stored bytes
        // produced from `*Fields` deserialize as `*FieldsStored`, and the
        // runtime constructor copies through unchanged.
        let extra_fields = ExtraThreatFields {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap()),
            sensor: "s".to_string(),
            service: "svc".to_string(),
            content: "c".to_string(),
            db_name: "d".to_string(),
            rule_id: 7,
            matched_to: "m".to_string(),
            cluster_id: Some(1),
            attack_kind: "a".to_string(),
            confidence: 0.5,
            category: Some(EventCategory::Reconnaissance),
            triage_scores: None,
        };
        let stored: super::ExtraThreatFieldsStored = extra_fields.into();
        let runtime = ExtraThreat::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap()),
            stored,
        );
        assert_eq!(runtime.sensor, "s");
        assert!((runtime.confidence - 0.5).abs() < f32::EPSILON);

        let net_fields = NetworkThreatFields {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap()),
            sensor: "s".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 1,
            resp_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            resp_port: 2,
            proto: 6,
            service: "http".to_string(),
            start_time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap()),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            content: "c".to_string(),
            db_name: "d".to_string(),
            rule_id: 1,
            matched_to: "m".to_string(),
            cluster_id: None,
            attack_kind: "a".to_string(),
            confidence: 0.1,
            category: None,
            triage_scores: None,
        };
        let net_stored: super::NetworkThreatFieldsStored = net_fields.into();
        let net_runtime = NetworkThreat::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap()),
            net_stored,
        );
        assert_eq!(net_runtime.service, "http");

        let win_fields = WindowsThreatFields {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap()),
            sensor: "s".to_string(),
            service: "svc".to_string(),
            agent_name: "an".to_string(),
            agent_id: "ai".to_string(),
            process_guid: "pg".to_string(),
            process_id: 1,
            image: "img".to_string(),
            user: "u".to_string(),
            content: "c".to_string(),
            db_name: "d".to_string(),
            rule_id: 1,
            matched_to: "m".to_string(),
            cluster_id: None,
            attack_kind: "a".to_string(),
            confidence: 0.2,
            category: None,
            triage_scores: None,
        };
        let win_stored: super::WindowsThreatFieldsStored = win_fields.into();
        let win_runtime = WindowsThreat::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap()),
            win_stored,
        );
        assert_eq!(win_runtime.process_id, 1);
    }

    #[test]
    fn event_message() {
        let (_permit, store) = setup_store();
        let db = store.events();
        let msg = example_message(EventKind::LockyRansomware, EventCategory::Impact);
        db.put(&msg).unwrap();
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            originator: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            responder: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            countries: None,
            categories: None,
            levels: None,
            kinds: Some(vec!["locky ransomware".to_string()]),
            learning_methods: None,
            sensors: Some(vec!["collector1".to_string()]),
            confidence_min: Some(0.5),
            confidence_max: None,
            triage_policies: None,
        };
        assert_eq!(event.kind(&filter).unwrap(), Some(LOCKY_RANSOMWARE));
        let mut counter = HashMap::new();
        event.count_level(&mut counter, &filter).unwrap();
        assert_eq!(counter.len(), 1);

        let mut counter = HashMap::new();
        event.count_kind(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(LOCKY_RANSOMWARE), Some(&1));

        let mut counter = HashMap::new();
        event.count_category(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(&EventCategory::Impact), Some(&1));

        let mut counter = HashMap::new();
        event.count_ip_address_pair(&mut counter, &filter).unwrap();
        assert_eq!(
            counter.get(&(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            )),
            Some(&1)
        );
    }

    #[test]
    fn syslog_for_dga() {
        let fields = DgaFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 80,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/uri/path".to_string(),
            referer: "-".to_string(),
            version: "1.1".to_string(),
            user_agent: "browser".to_string(),
            request_len: 100,
            response_len: 100,
            status_code: 200,
            status_msg: "-".to_string(),
            username: "-".to_string(),
            password: "-".to_string(),
            cookie: "cookie".to_string(),
            content_encoding: "encoding type".to_string(),
            content_type: "content type".to_string(),
            cache_control: "no cache".to_string(),
            filenames: vec!["a1".to_string(), "a2".to_string()],
            mime_types: vec!["b1".to_string(), "b2".to_string()],
            body: "12345678901234567890".to_string().into_bytes(),
            state: String::new(),
            confidence: 0.8,
            category: Some(EventCategory::CommandAndControl),
        };
        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            kind: EventKind::DomainGenerationAlgorithm,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="DomainGenerationAlgorithm" category="CommandAndControl" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="80" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" method="GET" host="example.com" uri="/uri/path" referer="-" version="1.1" user_agent="browser" request_len="100" response_len="100" status_code="200" status_msg="-" username="-" password="-" cookie="cookie" content_encoding="encoding type" content_type="content type" cache_control="no cache" filenames="a1,a2" mime_types="b1,b2" body="1234567890..." state="" confidence="0.8""#
        );

        let dga = DomainGenerationAlgorithm::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            fields.into(),
        );
        let event = Event::DomainGenerationAlgorithm(dga);
        let dga_display = format!("{event}");
        assert_eq!(
            &dga_display,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="DomainGenerationAlgorithm" category="CommandAndControl" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="80" resp_country_code="ZZ" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" method="GET" host="example.com" uri="/uri/path" referer="-" version="1.1" user_agent="browser" request_len="100" response_len="100" status_code="200" status_msg="-" username="-" password="-" cookie="cookie" content_encoding="encoding type" content_type="content type" cache_control="no cache" filenames="a1,a2" mime_types="b1,b2" body="1234567890..." state="" confidence="0.8" triage_scores="""#
        );
    }

    #[test]
    fn event_db_backup() {
        use std::sync::RwLock;

        use rocksdb::backup::{BackupEngine, BackupEngineOptions, RestoreOptions};

        let _permit = acquire_db_permit();
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();

        let store = Arc::new(RwLock::new(
            Store::new(db_dir.path(), backup_dir.path(), None).unwrap(),
        ));
        {
            let store = store.read().expect("test holds no other locks");
            let db = store.events();
            assert!(db.iter_forward().next().is_none());

            let msg = example_message(
                EventKind::DnsCovertChannel,
                EventCategory::CommandAndControl,
            );

            db.put(&msg).unwrap();
            {
                let mut iter = db.iter_forward();
                assert!(iter.next().is_some());
                assert!(iter.next().is_none());
            }
        }
        // backing up
        {
            let mut store = store.write().expect("test holds no other locks");
            let res = store.backup(true, 1);
            assert!(res.is_ok());
        }

        // more operations
        {
            let store = store.read().expect("test holds no other locks");
            let db = store.events();
            let msg = example_message(EventKind::LockyRansomware, EventCategory::Impact);
            db.put(&msg).unwrap();
            {
                let mut iter = db.iter_forward();
                assert!(iter.next().is_some());
                assert!(iter.next().is_some());
                assert!(iter.next().is_none());
            }
        }
        // restoring the backup
        drop(store);

        let mut backup = BackupEngine::open(
            &BackupEngineOptions::new(backup_dir.path().join("states.db")).unwrap(),
            &rocksdb::Env::new().unwrap(),
        )
        .unwrap();
        assert!(
            backup
                .restore_from_backup(
                    db_dir.path().join("states.db"),
                    db_dir.path().join("states.db"),
                    &RestoreOptions::default(),
                    1,
                )
                .is_ok()
        );

        let store = Arc::new(RwLock::new(
            Store::new(db_dir.path(), backup_dir.path(), None).unwrap(),
        ));
        {
            let store = store.read().expect("test holds no other locks");
            let db = store.events();
            let mut iter = db.iter_forward();
            assert!(iter.next().is_some());
            assert!(iter.next().is_none());
        }
        let info = backup.get_backup_info();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].backup_id, 1);
    }

    #[test]
    fn syslog_for_httpthreat() {
        let fields = HttpThreatFields {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 80,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/uri/path".to_string(),
            referer: "-".to_string(),
            version: "1.1".to_string(),
            user_agent: "browser".to_string(),
            request_len: 100,
            response_len: 100,
            status_code: 200,
            status_msg: "-".to_string(),
            username: "-".to_string(),
            password: "-".to_string(),
            cookie: "cookie".to_string(),
            content_encoding: "encoding type".to_string(),
            content_type: "content type".to_string(),
            cache_control: "no cache".to_string(),
            filenames: vec!["a1".to_string(), "a2".to_string()],
            mime_types: vec!["b1".to_string(), "b2".to_string()],
            body: "12345678901234567890".to_string().into_bytes(),
            state: String::new(),
            db_name: "db".to_string(),
            rule_id: 12000,
            cluster_id: Some(1111),
            matched_to: "match".to_string(),
            attack_kind: "attack".to_string(),
            confidence: 0.8,
            category: Some(EventCategory::Reconnaissance),
        };
        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            kind: EventKind::HttpThreat,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        let start_time = timestamp::format_i64_nanos_rfc3339(0).expect("valid timestamp");
        assert_eq!(
            syslog_message,
            format!(
                "time=\"1970-01-01T00:01:01+00:00\" event_kind=\"HttpThreat\" category=\"Reconnaissance\" sensor=\"collector1\" orig_addr=\"127.0.0.1\" orig_port=\"10000\" resp_addr=\"127.0.0.2\" resp_port=\"80\" proto=\"6\" start_time=\"{start_time}\" duration=\"0\" orig_pkts=\"0\" resp_pkts=\"0\" orig_l2_bytes=\"0\" resp_l2_bytes=\"0\" method=\"GET\" host=\"example.com\" uri=\"/uri/path\" referer=\"-\" version=\"1.1\" user_agent=\"browser\" request_len=\"100\" response_len=\"100\" status_code=\"200\" status_msg=\"-\" username=\"-\" password=\"-\" cookie=\"cookie\" content_encoding=\"encoding type\" content_type=\"content type\" cache_control=\"no cache\" filenames=\"a1,a2\" mime_types=\"b1,b2\" body=\"1234567890...\" state=\"\" db_name=\"db\" rule_id=\"12000\" matched_to=\"match\" cluster_id=\"1111\" attack_kind=\"attack\" confidence=\"0.8\""
            )
        );

        let http_threat = HttpThreat::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            fields.into(),
        );
        let event = Event::HttpThreat(http_threat);
        let http_threat_display = format!("{event}");
        assert!(http_threat_display.contains("body=\"1234567890...\""));
        assert!(http_threat_display.contains("confidence=\"0.8\""));
    }

    #[test]
    fn syslog_for_nonbrowser() {
        let fields = HttpEventFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 80,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/uri/path".to_string(),
            referer: "-".to_string(),
            version: "1.1".to_string(),
            user_agent: "browser".to_string(),
            request_len: 100,
            response_len: 100,
            status_code: 200,
            status_msg: "-".to_string(),
            username: "-".to_string(),
            password: "-".to_string(),
            cookie: "cookie".to_string(),
            content_encoding: "encoding type".to_string(),
            content_type: "content type".to_string(),
            cache_control: "no cache".to_string(),
            filenames: vec!["a1".to_string(), "a2".to_string()],
            mime_types: vec!["b1".to_string(), "b2".to_string()],
            body: "12345678901234567890".to_string().into_bytes(),
            state: String::new(),
            confidence: 1.0,
            category: Some(EventCategory::CommandAndControl),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            kind: EventKind::NonBrowser,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="NonBrowser" category="CommandAndControl" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="80" proto="6" start_time="1970-01-01T00:01:01+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" method="GET" host="example.com" uri="/uri/path" referer="-" version="1.1" user_agent="browser" request_len="100" response_len="100" status_code="200" status_msg="-" username="-" password="-" cookie="cookie" content_encoding="encoding type" content_type="content type" cache_control="no cache" filenames="a1,a2" mime_types="b1,b2" body="1234567890..." state="" confidence="1""#
        );

        let non_browser = Event::NonBrowser(NonBrowser::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            &fields.into(),
        ))
        .to_string();
        assert!(non_browser.contains("body=\"1234567890...\""));
        assert!(non_browser.contains("state=\"\""));
    }

    #[test]
    fn syslog_for_blocklist_http() {
        let fields = BlocklistHttpFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 80,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/uri/path".to_string(),
            referer: "-".to_string(),
            version: "1.1".to_string(),
            user_agent: "browser".to_string(),
            request_len: 100,
            response_len: 100,
            status_code: 200,
            status_msg: "-".to_string(),
            username: "-".to_string(),
            password: "-".to_string(),
            cookie: "cookie".to_string(),
            content_encoding: "encoding type".to_string(),
            content_type: "content type".to_string(),
            cache_control: "no cache".to_string(),
            filenames: vec!["a1".to_string(), "a2".to_string()],
            mime_types: vec!["b1".to_string(), "b2".to_string()],
            body: "12345678901234567890".to_string().into_bytes(),
            state: String::new(),
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            kind: EventKind::BlocklistHttp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="BlocklistHttp" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="80" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" method="GET" host="example.com" uri="/uri/path" referer="-" version="1.1" user_agent="browser" request_len="100" response_len="100" status_code="200" status_msg="-" username="-" password="-" cookie="cookie" content_encoding="encoding type" content_type="content type" cache_control="no cache" filenames="a1,a2" mime_types="b1,b2" body="1234567890..." state="" confidence="1""#
        );

        let blocklist_http = Event::Blocklist(RecordType::Http(BlocklistHttp::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();

        assert!(blocklist_http.contains("body=\"1234567890...\""));
        assert!(blocklist_http.contains("mime_types=\"b1,b2\""));
    }

    #[test]
    fn syslog_for_lockyransomware() {
        let fields = DnsEventFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)),
            resp_port: 53,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            query: "locky.com".to_string(),
            answer: vec!["1.1.1.100".to_string()],
            trans_id: 1100,
            rtt: 1,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: true,
            rd_flag: false,
            ra_flag: false,
            ttl: vec![120; 5],
            confidence: 0.8,
            category: Some(EventCategory::Impact),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            kind: EventKind::LockyRansomware,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="LockyRansomware" category="Impact" sensor="collector1" orig_addr="127.0.0.3" orig_port="10000" resp_addr="127.0.0.4" resp_port="53" proto="17" start_time="1970-01-01T00:01:01+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" query="locky.com" answer="1.1.1.100" trans_id="1100" rtt="1" qclass="0" qtype="0" rcode="0" aa_flag="false" tc_flag="true" rd_flag="false" ra_flag="false" ttl="120,120,120,120,120" confidence="0.8""#
        );

        let locky_ransomware = Event::LockyRansomware(LockyRansomware::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            fields.into(),
        ))
        .to_string();
        assert!(locky_ransomware.contains("sensor=\"collector1\""));
        assert!(locky_ransomware.contains("query=\"locky.com\""));
        assert!(locky_ransomware.contains("ttl=\"120,120,120,120,120\""));
        assert!(locky_ransomware.contains("confidence=\"0.8\""));
        assert!(locky_ransomware.contains("triage_scores=\"\""));
    }

    #[test]
    fn syslog_for_portscan() {
        let fields = PortScanFields {
            sensor: String::new(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_ports: vec![80, 443, 8000, 8080, 8888, 8443, 9000, 9001, 9002],
            first_event_start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            last_event_start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 2)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            proto: 6,
            confidence: 0.3,
            category: Some(EventCategory::Reconnaissance),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            kind: EventKind::PortScan,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="PortScan" category="Reconnaissance" sensor="" orig_addr="127.0.0.1" resp_addr="127.0.0.2" resp_ports="80,443,8000,8080,8888,8443,9000,9001,9002" first_event_start_time="1970-01-01T00:01:01+00:00" last_event_start_time="1970-01-01T00:01:02+00:00" proto="6" confidence="0.3""#
        );

        let port_scan = Event::PortScan(PortScan::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            &fields.into(),
        ))
        .to_string();
        assert_eq!(
            &port_scan,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="PortScan" category="Reconnaissance" orig_addr="127.0.0.1" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_country_code="ZZ" resp_ports="80,443,8000,8080,8888,8443,9000,9001,9002" first_event_start_time="1970-01-01T00:01:01+00:00" last_event_start_time="1970-01-01T00:01:02+00:00" proto="6" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_multihostportscan() {
        let fields = MultiHostPortScanFields {
            sensor: String::new(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            resp_addrs: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            ],
            resp_port: 80,
            first_event_start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            last_event_start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 2)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            proto: 6,
            confidence: 0.3,
            category: Some(EventCategory::Reconnaissance),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            kind: EventKind::MultiHostPortScan,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="MultiHostPortScan" category="Reconnaissance" sensor="" orig_addr="127.0.0.1" resp_addrs="127.0.0.2,127.0.0.3" resp_port="80" proto="6" first_event_start_time="1970-01-01T00:01:01+00:00" last_event_start_time="1970-01-01T00:01:02+00:00" confidence="0.3""#
        );

        let multi_host_port_scan = Event::MultiHostPortScan(MultiHostPortScan::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            &fields.into(),
        ))
        .to_string();
        assert_eq!(
            &multi_host_port_scan,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="MultiHostPortScan" category="Reconnaissance" orig_addr="127.0.0.1" orig_country_code="ZZ" resp_addrs="127.0.0.2,127.0.0.3" resp_port="80" resp_country_codes="ZZ,ZZ" proto="6" first_event_start_time="1970-01-01T00:01:01+00:00" last_event_start_time="1970-01-01T00:01:02+00:00" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_externalddos() {
        let fields = ExternalDdosFields {
            sensor: String::new(),
            orig_addrs: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            ],
            resp_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            first_event_start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            last_event_start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 2)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            proto: 6,
            confidence: 0.3,
            category: Some(EventCategory::Impact),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::ExternalDdos,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="ExternalDdos" category="Impact" sensor="" orig_addrs="127.0.0.2,127.0.0.3" resp_addr="127.0.0.1" proto="6" first_event_start_time="1970-01-01T00:01:01+00:00" last_event_start_time="1970-01-01T00:01:02+00:00" confidence="0.3""#
        );

        let external_ddos = Event::ExternalDdos(ExternalDdos::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            &fields.into(),
        ))
        .to_string();
        assert_eq!(
            &external_ddos,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="ExternalDdos" category="Impact" orig_addrs="127.0.0.2,127.0.0.3" orig_country_codes="ZZ,ZZ" resp_addr="127.0.0.1" resp_country_code="ZZ" proto="6" first_event_start_time="1970-01-01T00:01:01+00:00" last_event_start_time="1970-01-01T00:01:02+00:00" triage_scores="""#
        );
    }

    fn blocklist_bootp_fields() -> BlocklistBootpFields {
        BlocklistBootpFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 68,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 67,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            op: 1,
            htype: 2,
            hops: 1,
            xid: 1,
            ciaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5)),
            yiaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 6)),
            siaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 7)),
            giaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 8)),
            chaddr: vec![1, 2, 3, 4, 5, 6],
            sname: "server_name".to_string(),
            file: "boot_file_name".to_string(),
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        }
    }

    #[test]
    fn syslog_for_blocklist_bootp() {
        let fields = blocklist_bootp_fields();

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistBootp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistBootp" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="68" resp_addr="127.0.0.2" resp_port="67" proto="17" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" op="1" htype="2" hops="1" xid="1" ciaddr="127.0.0.5" yiaddr="127.0.0.6" siaddr="127.0.0.7" giaddr="127.0.0.8" chaddr="01:02:03:04:05:06" sname="server_name" file="boot_file_name" confidence="1""#,
        );
        let blocklist_bootp = Event::Blocklist(RecordType::Bootp(BlocklistBootp::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();

        assert_eq!(
            &blocklist_bootp,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistBootp" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="68" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="67" resp_country_code="ZZ" proto="17" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" op="1" htype="2" hops="1" xid="1" ciaddr="127.0.0.5" yiaddr="127.0.0.6" siaddr="127.0.0.7" giaddr="127.0.0.8" chaddr="01:02:03:04:05:06" sname="server_name" file="boot_file_name" triage_scores="""#
        );
    }

    #[test]
    fn event_blocklist_bootp() {
        use super::{BLOCKLIST, ThreatLevel};

        let (_permit, store) = setup_store();

        let fields = blocklist_bootp_fields();
        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistBootp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let db = store.events();
        db.put(&message).unwrap();
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            originator: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            responder: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            countries: None,
            categories: None,
            levels: Some(vec![ThreatLevel::Medium]),
            kinds: Some(vec!["blocklist bootp".to_string()]),
            learning_methods: None,
            sensors: Some(vec!["collector1".to_string()]),
            confidence_min: None,
            confidence_max: None,
            triage_policies: None,
        };
        assert_eq!(
            event.address_pair(&filter).unwrap(),
            (
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            )
        );
        assert_eq!(event.kind(&filter).unwrap(), Some(BLOCKLIST));
        let mut counter = HashMap::new();
        event.count_level(&mut counter, &filter).unwrap();
        assert_eq!(counter.len(), 1);

        let mut counter = HashMap::new();
        event.count_kind(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(BLOCKLIST), Some(&1));

        let mut counter = HashMap::new();
        event.count_category(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(&EventCategory::InitialAccess), Some(&1));

        let mut counter = HashMap::new();
        event.count_ip_address_pair(&mut counter, &filter).unwrap();
        assert_eq!(
            counter.get(&(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            )),
            Some(&1)
        );
    }

    #[test]
    fn syslog_for_blocklist_conn() {
        let fields = BlocklistConnFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 80,
            proto: 6,
            conn_state: "SAF".to_string(),
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            service: "http".to_string(),
            orig_bytes: 100,
            orig_pkts: 1,
            resp_bytes: 100,
            resp_pkts: 1,
            orig_l2_bytes: 122,
            resp_l2_bytes: 122,
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistConn,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistConn" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="80" proto="6" conn_state="SAF" start_time="1970-01-01T00:00:00+00:00" duration="0" service="http" orig_bytes="100" resp_bytes="100" orig_pkts="1" resp_pkts="1" orig_l2_bytes="122" resp_l2_bytes="122" confidence="1""#
        );

        let blocklist_conn = Event::Blocklist(RecordType::Conn(BlocklistConn::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();
        assert_eq!(
            &blocklist_conn,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistConn" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="80" resp_country_code="ZZ" proto="6" conn_state="SAF" start_time="1970-01-01T00:00:00+00:00" duration="0" service="http" orig_bytes="100" resp_bytes="100" orig_pkts="1" resp_pkts="1" orig_l2_bytes="122" resp_l2_bytes="122" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_blocklist_dcerpc() {
        let fields = BlocklistDceRpcFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 135,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            context: vec![DceRpcContext {
                id: 0,
                abstract_syntax: 0x1234_5678_9abc_def0,
                abstract_major: 1,
                abstract_minor: 0,
                transfer_syntax: 0xfedc_ba98_7654_3210,
                transfer_major: 2,
                transfer_minor: 0,
                acceptance: 0,
                reason: 0,
            }],
            request: vec![
                "svcctl".to_string(),
                "epmapper".to_string(),
                "bind".to_string(),
            ],
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistDceRpc,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            "time=\"1970-01-01T01:01:01+00:00\" \
             event_kind=\"BlocklistDceRpc\" \
             category=\"InitialAccess\" \
             sensor=\"collector1\" \
             orig_addr=\"127.0.0.1\" \
             orig_port=\"10000\" \
             resp_addr=\"127.0.0.2\" \
             resp_port=\"135\" \
             proto=\"6\" \
             start_time=\"1970-01-01T00:00:00+00:00\" \
             duration=\"0\" \
             orig_pkts=\"0\" \
             resp_pkts=\"0\" \
             orig_l2_bytes=\"0\" \
             resp_l2_bytes=\"0\" \
             context=\"id=0 abstract_syntax=0x123456789abcdef0 \
             abstract=1.0 transfer_syntax=0xfedcba9876543210 \
             transfer=2.0 acceptance=0 reason=0\" \
             request=\"svcctl,epmapper,bind\" \
             confidence=\"1\""
        );

        let blocklist_dce_rpc = Event::Blocklist(RecordType::DceRpc(BlocklistDceRpc::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();
        assert_eq!(
            &blocklist_dce_rpc,
            "time=\"1970-01-01T01:01:01+00:00\" \
             event_kind=\"BlocklistDceRpc\" \
             category=\"InitialAccess\" \
             sensor=\"collector1\" \
             orig_addr=\"127.0.0.1\" \
             orig_port=\"10000\" \
             orig_country_code=\"ZZ\" \
             resp_addr=\"127.0.0.2\" \
             resp_port=\"135\" \
             resp_country_code=\"ZZ\" \
             proto=\"6\" \
             start_time=\"1970-01-01T00:00:00+00:00\" \
             duration=\"0\" \
             orig_pkts=\"0\" \
             resp_pkts=\"0\" \
             orig_l2_bytes=\"0\" \
             resp_l2_bytes=\"0\" \
             context=\"id=0 abstract_syntax=0x123456789abcdef0 \
             abstract=1.0 transfer_syntax=0xfedcba9876543210 \
             transfer=2.0 acceptance=0 reason=0\" \
             request=\"svcctl,epmapper,bind\" \
             triage_scores=\"\""
        );
    }

    fn blocklist_dhcp_fields() -> BlocklistDhcpFields {
        BlocklistDhcpFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::from_str("127.0.0.1").unwrap(),
            orig_port: 68,
            resp_addr: IpAddr::from_str("127.0.0.2").unwrap(),
            resp_port: 67,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            msg_type: 1,
            ciaddr: IpAddr::from_str("127.0.0.5").unwrap(),
            yiaddr: IpAddr::from_str("127.0.0.6").unwrap(),
            siaddr: IpAddr::from_str("127.0.0.7").unwrap(),
            giaddr: IpAddr::from_str("127.0.0.8").unwrap(),
            subnet_mask: IpAddr::from_str("255.255.255.0").unwrap(),
            router: vec![IpAddr::from_str("127.0.0.1").unwrap()],
            domain_name_server: vec![IpAddr::from_str("127.0.0.1").unwrap()],
            req_ip_addr: IpAddr::from_str("127.0.0.100").unwrap(),
            lease_time: 100,
            server_id: IpAddr::from_str("127.0.0.1").unwrap(),
            param_req_list: vec![1, 2, 3],
            message: "message".to_string(),
            renewal_time: 100,
            rebinding_time: 200,
            class_id: "MSFT 5.0".as_bytes().to_vec(),
            client_id_type: 1,
            client_id: vec![7, 8, 9],
            options: vec![(1, vec![1, 2, 3]), (3, vec![10, 11, 12])],
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        }
    }

    #[test]
    fn syslog_for_blocklist_dhcp() {
        let fields = blocklist_dhcp_fields();

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistDhcp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistDhcp" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="68" resp_addr="127.0.0.2" resp_port="67" proto="17" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" msg_type="1" ciaddr="127.0.0.5" yiaddr="127.0.0.6" siaddr="127.0.0.7" giaddr="127.0.0.8" subnet_mask="255.255.255.0" router="127.0.0.1" domain_name_server="127.0.0.1" req_ip_addr="127.0.0.100" lease_time="100" server_id="127.0.0.1" param_req_list="1,2,3" message="message" renewal_time="100" rebinding_time="200" class_id="MSFT 5.0" client_id_type="1" client_id="07:08:09" options="1:010203,3:0a0b0c" confidence="1""#,
        );

        let blocklist_dhcp = Event::Blocklist(RecordType::Dhcp(BlocklistDhcp::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();

        assert_eq!(
            &blocklist_dhcp,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistDhcp" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="68" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="67" resp_country_code="ZZ" proto="17" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" msg_type="1" ciaddr="127.0.0.5" yiaddr="127.0.0.6" siaddr="127.0.0.7" giaddr="127.0.0.8" subnet_mask="255.255.255.0" router="127.0.0.1" domain_name_server="127.0.0.1" req_ip_addr="127.0.0.100" lease_time="100" server_id="127.0.0.1" param_req_list="1,2,3" message="message" renewal_time="100" rebinding_time="200" class_id="MSFT 5.0" client_id_type="1" client_id="07:08:09" options="1:010203,3:0a0b0c" triage_scores="""#
        );
    }

    #[test]
    fn event_blocklist_dhcp() {
        use super::{BLOCKLIST, ThreatLevel};

        let (_permit, store) = setup_store();

        let fields = blocklist_dhcp_fields();
        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistDhcp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let db = store.events();
        db.put(&message).unwrap();
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            originator: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            responder: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            countries: None,
            categories: None,
            levels: Some(vec![ThreatLevel::Medium]),
            kinds: Some(vec!["blocklist dhcp".to_string()]),
            learning_methods: None,
            sensors: Some(vec!["collector1".to_string()]),
            confidence_min: None,
            confidence_max: None,
            triage_policies: None,
        };
        assert_eq!(
            event.address_pair(&filter).unwrap(),
            (
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            )
        );
        assert_eq!(event.kind(&filter).unwrap(), Some(BLOCKLIST));
        let mut counter = HashMap::new();
        event.count_level(&mut counter, &filter).unwrap();
        assert_eq!(counter.len(), 1);

        let mut counter = HashMap::new();
        event.count_kind(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(BLOCKLIST), Some(&1));

        let mut counter = HashMap::new();
        event.count_category(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(&EventCategory::InitialAccess), Some(&1));

        let mut counter = HashMap::new();
        event.count_ip_address_pair(&mut counter, &filter).unwrap();
        assert_eq!(
            counter.get(&(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            )),
            Some(&1)
        );
    }

    #[test]
    fn syslog_for_dnscovertchannel() {
        let fields = DnsEventFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 53,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            query: "foo.com".to_string(),
            answer: vec!["10.10.10.10".to_string(), "20.20.20.20".to_string()],
            trans_id: 123,
            rtt: 1,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: true,
            ttl: vec![120; 5],
            confidence: 0.9,
            category: Some(EventCategory::CommandAndControl),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::DnsCovertChannel,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="DnsCovertChannel" category="CommandAndControl" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="53" proto="17" start_time="1970-01-01T00:01:01+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" query="foo.com" answer="10.10.10.10,20.20.20.20" trans_id="123" rtt="1" qclass="0" qtype="0" rcode="0" aa_flag="false" tc_flag="false" rd_flag="false" ra_flag="true" ttl="120,120,120,120,120" confidence="0.9""#
        );

        let triage_scores = vec![TriageScore {
            policy_id: 109,
            score: 0.9,
        }];
        let mut dns_covert_channel = Event::DnsCovertChannel(DnsCovertChannel::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        ));
        dns_covert_channel.set_triage_scores(triage_scores);
        let dns_covert_channel = dns_covert_channel.to_string();

        assert_eq!(
            &dns_covert_channel,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="DnsCovertChannel" category="CommandAndControl" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="53" resp_country_code="ZZ" proto="17" start_time="1970-01-01T00:01:01+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" query="foo.com" answer="10.10.10.10,20.20.20.20" trans_id="123" rtt="1" qclass="0" qtype="0" rcode="0" aa_flag="false" tc_flag="false" rd_flag="false" ra_flag="true" ttl="120,120,120,120,120" confidence="0.9" triage_scores="109:0.90""#
        );
    }

    #[test]
    fn syslog_for_cryptocurrencyminingpool() {
        let fields = CryptocurrencyMiningPoolFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 53,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            query: "foo.com".to_string(),
            answer: vec!["10.10.10.10".to_string(), "20.20.20.20".to_string()],
            trans_id: 123,
            rtt: 1,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: true,
            ttl: vec![120; 5],
            coins: vec!["bitcoin".to_string(), "monero".to_string()],
            confidence: 1.0,
            category: Some(EventCategory::CommandAndControl),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::CryptocurrencyMiningPool,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="CryptocurrencyMiningPool" category="CommandAndControl" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="53" proto="17" start_time="1970-01-01T00:01:01+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" query="foo.com" answer="10.10.10.10,20.20.20.20" trans_id="123" rtt="1" qclass="0" qtype="0" rcode="0" aa_flag="false" tc_flag="false" rd_flag="false" ra_flag="true" ttl="120,120,120,120,120" coins="bitcoin,monero" confidence="1""#
        );

        let cryptocurrency_mining_pool =
            Event::CryptocurrencyMiningPool(CryptocurrencyMiningPool::new(
                msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
                fields.into(),
            ))
            .to_string();
        assert_eq!(
            &cryptocurrency_mining_pool,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="CryptocurrencyMiningPool" category="CommandAndControl" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="53" resp_country_code="ZZ" proto="17" start_time="1970-01-01T00:01:01+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" query="foo.com" answer="10.10.10.10,20.20.20.20" trans_id="123" rtt="1" qclass="0" qtype="0" rcode="0" aa_flag="false" tc_flag="false" rd_flag="false" ra_flag="true" ttl="120,120,120,120,120" coins="bitcoin,monero" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_blocklist_dns() {
        let fields = BlocklistDnsFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 53,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            query: "foo.com".to_string(),
            answer: vec!["10.10.10.10".to_string(), "20.20.20.20".to_string()],
            trans_id: 123,
            rtt: 1,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: true,
            ttl: vec![120; 5],
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistDns,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistDns" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="53" proto="17" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" query="foo.com" answer="10.10.10.10,20.20.20.20" trans_id="123" rtt="1" qclass="0" qtype="0" rcode="0" aa_flag="false" tc_flag="false" rd_flag="false" ra_flag="true" ttl="120,120,120,120,120" confidence="1""#
        );
        let blocklist_dns = Event::Blocklist(RecordType::Dns(BlocklistDns::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();
        assert_eq!(
            &blocklist_dns,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistDns" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="53" resp_country_code="ZZ" proto="17" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" query="foo.com" answer="10.10.10.10,20.20.20.20" trans_id="123" rtt="1" qclass="0" qtype="0" rcode="0" aa_flag="false" tc_flag="false" rd_flag="false" ra_flag="true" ttl="120,120,120,120,120" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_ftpbruteforce() {
        let fields = FtpBruteForceFields {
            sensor: String::new(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 21,
            proto: 6,
            user_list: vec!["user1".to_string(), "user_2".to_string()],
            first_event_start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            last_event_start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 2)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            is_internal: true,
            confidence: 0.3,
            category: Some(EventCategory::CredentialAccess),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            kind: EventKind::FtpBruteForce,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="FtpBruteForce" category="CredentialAccess" sensor="" orig_addr="127.0.0.1" resp_addr="127.0.0.2" resp_port="21" proto="6" user_list="user1,user_2" first_event_start_time="1970-01-01T00:01:01+00:00" last_event_start_time="1970-01-01T00:01:02+00:00" is_internal="true" confidence="0.3""#
        );

        let ftp_brute_force = Event::FtpBruteForce(FtpBruteForce::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            &fields.into(),
        ))
        .to_string();

        assert_eq!(
            &ftp_brute_force,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="FtpBruteForce" category="CredentialAccess" orig_addr="127.0.0.1" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="21" resp_country_code="ZZ" proto="6" user_list="user1,user_2" first_event_start_time="1970-01-01T00:01:01+00:00" last_event_start_time="1970-01-01T00:01:02+00:00" is_internal="true" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_ftpplaintext() {
        use crate::event::ftp::FtpCommand;

        let command = FtpCommand {
            command: "ls".to_string(),
            reply_code: "200".to_string(),
            reply_msg: "OK".to_string(),
            data_passive: false,
            data_orig_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            data_resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)),
            data_resp_port: 10001,
            file: "/etc/passwd".to_string(),
            file_size: 5000,
            file_id: "123".to_string(),
        };

        let fields = FtpEventFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 21,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            user: "user1".to_string(),
            password: "password".to_string(),
            commands: vec![command],
            confidence: 1.0,
            category: Some(EventCategory::LateralMovement),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::FtpPlainText,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="FtpPlainText" category="LateralMovement" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="21" proto="6" start_time="1970-01-01T00:01:01+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" user="user1" password="password" commands="ls:200:OK" confidence="1""#
        );

        let ftp_plain_text = Event::FtpPlainText(FtpPlainText::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        ))
        .to_string();
        assert_eq!(
            &ftp_plain_text,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="FtpPlainText" category="LateralMovement" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="21" resp_country_code="ZZ" proto="6" start_time="1970-01-01T00:01:01+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" user="user1" password="password" commands="ls:200:OK" triage_scores="""#
        );
    }

    fn ftpeventfields() -> FtpEventFields {
        use crate::event::ftp::FtpCommand;

        let command = FtpCommand {
            command: "ls".to_string(),
            reply_code: "200".to_string(),
            reply_msg: "OK".to_string(),
            data_passive: false,
            data_orig_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            data_resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)),
            data_resp_port: 10001,
            file: "/etc/passwd".to_string(),
            file_size: 5000,
            file_id: "123".to_string(),
        };

        FtpEventFields {
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 21,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            user: "user1".to_string(),
            password: "password".to_string(),
            commands: vec![command],
            sensor: "collector1".to_string(),
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        }
    }

    #[test]
    fn syslog_for_blocklist_ftp() {
        let fields = ftpeventfields();

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistFtp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistFtp" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="21" proto="6" start_time="1970-01-01T00:01:01+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" user="user1" password="password" commands="ls:200:OK" confidence="1""#
        );

        let blocklist_ftp = Event::Blocklist(RecordType::Ftp(BlocklistFtp::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();

        assert_eq!(
            &blocklist_ftp,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistFtp" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="21" resp_country_code="ZZ" proto="6" start_time="1970-01-01T00:01:01+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" user="user1" password="password" commands="ls:200:OK" triage_scores="""#
        );
    }

    #[test]
    fn event_blocklist_ftp() {
        use super::{BLOCKLIST, ThreatLevel};

        let (_permit, store) = setup_store();

        let fields = ftpeventfields();
        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistFtp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let db = store.events();
        db.put(&message).unwrap();
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            originator: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            responder: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            countries: None,
            categories: None,
            levels: Some(vec![ThreatLevel::Medium]),
            kinds: Some(vec!["blocklist ftp".to_string()]),
            learning_methods: None,
            sensors: Some(vec!["collector1".to_string()]),
            confidence_min: Some(0.5),
            confidence_max: None,
            triage_policies: None,
        };
        assert_eq!(
            event.address_pair(&filter).unwrap(),
            (
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            )
        );
        assert_eq!(event.kind(&filter).unwrap(), Some(BLOCKLIST));
        let mut counter = HashMap::new();
        event.count_level(&mut counter, &filter).unwrap();
        assert_eq!(counter.len(), 1);

        let mut counter = HashMap::new();
        event.count_kind(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(BLOCKLIST), Some(&1));

        let mut counter = HashMap::new();
        event.count_category(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(&EventCategory::InitialAccess), Some(&1));

        let mut counter = HashMap::new();
        event.count_ip_address_pair(&mut counter, &filter).unwrap();
        assert_eq!(
            counter.get(&(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            )),
            Some(&1)
        );
    }

    #[test]
    fn syslog_for_repeatedhttpsessions() {
        let now = Utc
            .with_ymd_and_hms(1970, 1, 1, 1, 1, 1)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap();
        let fields = RepeatedHttpSessionsFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 443,
            proto: 6,
            first_event_start_time: now,
            last_event_start_time: now,
            confidence: 0.3,
            category: Some(EventCategory::Exfiltration),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::RepeatedHttpSessions,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="RepeatedHttpSessions" category="Exfiltration" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="443" proto="6" first_event_start_time="1970-01-01T01:01:01+00:00" last_event_start_time="1970-01-01T01:01:01+00:00" confidence="0.3""#
        );
        let repeated_http_sessions = Event::RepeatedHttpSessions(RepeatedHttpSessions::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            &fields.into(),
        ))
        .to_string();
        assert_eq!(
            &repeated_http_sessions,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="RepeatedHttpSessions" category="Exfiltration" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="443" resp_country_code="ZZ" proto="6" first_event_start_time="1970-01-01T01:01:01+00:00" last_event_start_time="1970-01-01T01:01:01+00:00" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_blocklist_kerberos() {
        let fields = BlocklistKerberosFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 88,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            client_time: 100,
            server_time: 101,
            error_code: 0,
            client_realm: "EXAMPLE.COM".to_string(),
            cname_type: 1,
            cname: vec!["user1".to_string()],
            realm: "EXAMPLE.COM".to_string(),
            sname_type: 1,
            sname: vec!["krbtgt/EXAMPLE.COM".to_string()],
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistKerberos,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistKerberos" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="88" proto="17" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" client_time="100" server_time="101" error_code="0" client_realm="EXAMPLE.COM" cname_type="1" cname="user1" realm="EXAMPLE.COM" sname_type="1" sname="krbtgt/EXAMPLE.COM" confidence="1""#
        );

        let blocklist_kerberos = Event::Blocklist(RecordType::Kerberos(BlocklistKerberos::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();

        assert_eq!(
            &blocklist_kerberos,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistKerberos" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="88" resp_country_code="ZZ" proto="17" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" client_time="100" server_time="101" error_code="0" client_realm="EXAMPLE.COM" cname_type="1" cname="user1" realm="EXAMPLE.COM" sname_type="1" sname="krbtgt/EXAMPLE.COM" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_ldapbruteforce() {
        let fields = LdapBruteForceFields {
            sensor: String::new(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 389,
            proto: 6,
            user_pw_list: vec![
                ("user1".to_string(), "pw1".to_string()),
                ("user_2".to_string(), "pw2".to_string()),
            ],
            first_event_start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            last_event_start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 2)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            confidence: 0.3,
            category: Some(EventCategory::CredentialAccess),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            kind: EventKind::LdapBruteForce,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="LdapBruteForce" category="CredentialAccess" sensor="" orig_addr="127.0.0.1" resp_addr="127.0.0.2" resp_port="389" proto="6" user_pw_list="user1:pw1,user_2:pw2" first_event_start_time="1970-01-01T00:01:01+00:00" last_event_start_time="1970-01-01T00:01:02+00:00" confidence="0.3""#
        );

        let ldap_brute_force = Event::LdapBruteForce(LdapBruteForce::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            &fields.into(),
        ))
        .to_string();

        assert_eq!(
            &ldap_brute_force,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="LdapBruteForce" category="CredentialAccess" orig_addr="127.0.0.1" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="389" resp_country_code="ZZ" proto="6" user_pw_list="user1:pw1,user_2:pw2" first_event_start_time="1970-01-01T00:01:01+00:00" last_event_start_time="1970-01-01T00:01:02+00:00" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_ldapplaintext() {
        let fields = LdapEventFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 389,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            message_id: 1,
            version: 3,
            opcode: vec!["bind".to_string()],
            result: vec!["success".to_string()],
            diagnostic_message: vec!["msg".to_string()],
            object: vec!["object".to_string()],
            argument: vec!["argument".to_string()],
            confidence: 1.0,
            category: Some(EventCategory::LateralMovement),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::LdapPlainText,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="LdapPlainText" category="LateralMovement" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="389" proto="6" start_time="1970-01-01T00:01:01+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" message_id="1" version="3" opcode="bind" result="success" diagnostic_message="msg" object="object" argument="argument" confidence="1""#
        );

        let ldap_plain_text = Event::LdapPlainText(LdapPlainText::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        ))
        .to_string();

        assert_eq!(
            &ldap_plain_text,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="LdapPlainText" category="LateralMovement" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="389" resp_country_code="ZZ" proto="6" start_time="1970-01-01T00:01:01+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" message_id="1" version="3" opcode="bind" result="success" diagnostic_message="msg" object="object" argument="argument" triage_scores="""#
        );
    }

    fn ldapeventfields() -> LdapEventFields {
        LdapEventFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 389,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            message_id: 1,
            version: 3,
            opcode: vec!["bind".to_string()],
            result: vec!["success".to_string()],
            diagnostic_message: vec!["msg".to_string()],
            object: vec!["object".to_string()],
            argument: vec!["argument".to_string()],
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        }
    }

    #[test]
    fn syslog_for_blocklist_ldap() {
        let fields = ldapeventfields();

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistLdap,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistLdap" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="389" proto="6" start_time="1970-01-01T00:01:01+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" message_id="1" version="3" opcode="bind" result="success" diagnostic_message="msg" object="object" argument="argument" confidence="1""#
        );

        let blocklist_ldap = Event::Blocklist(RecordType::Ldap(BlocklistLdap::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();

        assert_eq!(
            &blocklist_ldap,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistLdap" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="389" resp_country_code="ZZ" proto="6" start_time="1970-01-01T00:01:01+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" message_id="1" version="3" opcode="bind" result="success" diagnostic_message="msg" object="object" argument="argument" triage_scores="""#
        );
    }

    #[test]
    fn event_blocklist_ldap() {
        use super::{BLOCKLIST, ThreatLevel};

        let (_permit, store) = setup_store();

        let fields = ldapeventfields();
        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistLdap,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let db = store.events();
        db.put(&message).unwrap();
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            originator: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            responder: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            countries: None,
            categories: None,
            levels: Some(vec![ThreatLevel::Medium]),
            kinds: Some(vec!["blocklist ldap".to_string()]),
            learning_methods: None,
            sensors: Some(vec!["collector1".to_string()]),
            confidence_min: Some(0.5),
            confidence_max: None,
            triage_policies: None,
        };
        assert_eq!(
            event.address_pair(&filter).unwrap(),
            (
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            )
        );
        assert_eq!(event.kind(&filter).unwrap(), Some(BLOCKLIST));
        let mut counter = HashMap::new();
        event.count_level(&mut counter, &filter).unwrap();
        assert_eq!(counter.len(), 1);

        let mut counter = HashMap::new();
        event.count_kind(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(BLOCKLIST), Some(&1));

        let mut counter = HashMap::new();
        event.count_category(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(&EventCategory::InitialAccess), Some(&1));

        let mut counter = HashMap::new();
        event.count_ip_address_pair(&mut counter, &filter).unwrap();
        assert_eq!(
            counter.get(&(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            )),
            Some(&1)
        );
    }

    fn blocklist_radius_fields() -> BlocklistRadiusFields {
        BlocklistRadiusFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 1812,
            proto: 17,
            start_time: 0,
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            id: 1,
            code: 1,
            resp_code: 2,
            auth: "auth_string".to_string(),
            resp_auth: "resp_auth_string".to_string(),
            user_name: b"user1".to_vec(),
            user_passwd: b"password".to_vec(),
            chap_passwd: b"chap_pass".to_vec(),
            nas_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            nas_port: 5060,
            state: b"state".to_vec(),
            nas_id: b"nas_identifier".to_vec(),
            nas_port_type: 15,
            message: "RADIUS message".to_string(),
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        }
    }

    #[test]
    fn event_blocklist_radius() {
        use super::{BLOCKLIST, ThreatLevel};

        let (_permit, store) = setup_store();

        let fields = blocklist_radius_fields();
        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistRadius,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let db = store.events();
        db.put(&message).unwrap();
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            originator: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            responder: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            countries: None,
            categories: None,
            levels: Some(vec![ThreatLevel::Medium]),
            kinds: Some(vec!["blocklist radius".to_string()]),
            learning_methods: None,
            sensors: Some(vec!["collector1".to_string()]),
            confidence_min: Some(0.5),
            confidence_max: None,
            triage_policies: None,
        };
        assert_eq!(
            event.address_pair(&filter).unwrap(),
            (
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            )
        );
        assert_eq!(event.kind(&filter).unwrap(), Some(BLOCKLIST));
        let mut counter = HashMap::new();
        event.count_level(&mut counter, &filter).unwrap();
        assert_eq!(counter.len(), 1);

        let mut counter = HashMap::new();
        event.count_kind(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(BLOCKLIST), Some(&1));

        let mut counter = HashMap::new();
        event.count_category(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(&EventCategory::InitialAccess), Some(&1));

        let mut counter = HashMap::new();
        event.count_ip_address_pair(&mut counter, &filter).unwrap();
        assert_eq!(
            counter.get(&(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            )),
            Some(&1)
        );
    }

    #[test]
    fn syslog_for_extrathreat() {
        let fields = ExtraThreatFields {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            sensor: "collector1".to_string(),
            service: "service".to_string(),
            content: "content".to_string(),
            db_name: "db_name".to_string(),
            rule_id: 1,
            matched_to: "matched_to".to_string(),
            cluster_id: Some(1),
            attack_kind: "attack_kind".to_string(),
            confidence: 0.9,
            category: Some(EventCategory::Reconnaissance),
            triage_scores: None,
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::ExtraThreat,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="ExtraThreat" category="Reconnaissance" sensor="collector1" service="service" content="content" db_name="db_name" rule_id="1" matched_to="matched_to" cluster_id="1" attack_kind="attack_kind" confidence="0.9""#
        );
    }

    #[test]
    fn syslog_for_blocklist_mqtt() {
        let fields = BlocklistMqttFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 1883,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            protocol: "mqtt".to_string(),
            version: 211,
            client_id: "client1".to_string(),
            connack_reason: 0,
            subscribe: vec!["topic".to_string()],
            suback_reason: "error".to_string().into_bytes(),
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistMqtt,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistMqtt" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="1883" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" protocol="mqtt" version="211" client_id="client1" connack_reason="0" subscribe="topic" suback_reason="error" confidence="1""#
        );

        let blocklist_mqtt = Event::Blocklist(RecordType::Mqtt(BlocklistMqtt::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();

        assert_eq!(
            &blocklist_mqtt,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistMqtt" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="1883" resp_country_code="ZZ" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" protocol="mqtt" version="211" client_id="client1" connack_reason="0" subscribe="topic" suback_reason="error" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_networkthreat() {
        let fields = NetworkThreatFields {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 80,
            proto: 6,
            service: "http".to_string(),
            start_time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap()),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            content: "content".to_string(),
            db_name: "db_name".to_string(),
            rule_id: 1,
            matched_to: "matched_to".to_string(),
            cluster_id: Some(1),
            attack_kind: "attack_kind".to_string(),
            confidence: 0.9,
            triage_scores: None,
            category: Some(EventCategory::Reconnaissance),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::NetworkThreat,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="NetworkThreat" category="Reconnaissance" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="80" proto="6" service="http" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" content="content" db_name="db_name" rule_id="1" matched_to="matched_to" cluster_id="1" attack_kind="attack_kind" confidence="0.9""#
        );
    }

    #[test]
    fn syslog_for_blocklist_nfs() {
        let fields = BlocklistNfsFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 2049,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            read_files: vec!["/etc/passwd".to_string()],
            write_files: vec!["/etc/shadow".to_string()],
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistNfs,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistNfs" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="2049" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" read_files="/etc/passwd" write_files="/etc/shadow" confidence="1""#
        );

        let blocklist_nfs = Event::Blocklist(RecordType::Nfs(BlocklistNfs::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();

        assert_eq!(
            &blocklist_nfs,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistNfs" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="2049" resp_country_code="ZZ" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" read_files="/etc/passwd" write_files="/etc/shadow" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_blocklist_ntlm() {
        let fields = BlocklistNtlmFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 445,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            protocol: "ntlm".to_string(),
            username: "user1".to_string(),
            hostname: "host1".to_string(),
            domainname: "domain1".to_string(),
            success: "true".to_string(),
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistNtlm,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistNtlm" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="445" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" protocol="ntlm" username="user1" hostname="host1" domainname="domain1" success="true" confidence="1""#
        );

        let blocklist_ntlm = Event::Blocklist(RecordType::Ntlm(BlocklistNtlm::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();

        assert_eq!(
            &blocklist_ntlm,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistNtlm" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="445" resp_country_code="ZZ" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" protocol="ntlm" username="user1" hostname="host1" domainname="domain1" success="true" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_blocklist_radius() {
        let fields = blocklist_radius_fields();

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistRadius,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistRadius" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="1812" proto="17" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" id="1" code="1" resp_code="2" auth="auth_string" resp_auth="resp_auth_string" user_name="user1" user_passwd="password" chap_passwd="chap_pass" nas_ip="127.0.0.3" nas_port="5060" state="state" nas_id="nas_identifier" nas_port_type="15" message="RADIUS message" confidence="1""#
        );

        let blocklist_radius = Event::Blocklist(RecordType::Radius(BlocklistRadius::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();

        assert_eq!(
            &blocklist_radius,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistRadius" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="1812" resp_country_code="ZZ" proto="17" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" id="1" code="1" resp_code="2" auth="auth_string" resp_auth="resp_auth_string" user_name="user1" user_passwd="password" chap_passwd="chap_pass" nas_ip="127.0.0.3" nas_port="5060" state="state" nas_id="nas_identifier" nas_port_type="15" message="RADIUS message" triage_scores="""#
        );
    }

    fn blocklist_malformed_dns_fields() -> BlocklistMalformedDnsFields {
        BlocklistMalformedDnsFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 53,
            proto: 17,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 1_000_000_000,
            orig_pkts: 10,
            resp_pkts: 5,
            orig_l2_bytes: 500,
            resp_l2_bytes: 300,
            trans_id: 1234,
            flags: 0x8180,
            question_count: 1,
            answer_count: 1,
            authority_count: 0,
            additional_count: 0,
            query_count: 1,
            resp_count: 1,
            query_bytes: 50,
            resp_bytes: 100,
            query_body: vec![b"example.com".to_vec()],
            resp_body: vec![b"192.0.2.1".to_vec()],
            confidence: 0.95,
            category: Some(EventCategory::InitialAccess),
        }
    }

    #[test]
    fn event_blocklist_malformed_dns() {
        use super::{BLOCKLIST, ThreatLevel};

        let (_permit, store) = setup_store();

        let fields = blocklist_malformed_dns_fields();
        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistMalformedDns,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let db = store.events();
        db.put(&message).unwrap();
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            originator: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            responder: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            countries: None,
            categories: None,
            levels: Some(vec![ThreatLevel::Medium]),
            kinds: Some(vec!["blocklist malformed dns".to_string()]),
            learning_methods: None,
            sensors: Some(vec!["collector1".to_string()]),
            confidence_min: Some(0.5),
            confidence_max: None,
            triage_policies: None,
        };
        assert_eq!(
            event.address_pair(&filter).unwrap(),
            (
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            )
        );
        assert_eq!(event.kind(&filter).unwrap(), Some(BLOCKLIST));
        let mut counter = HashMap::new();
        event.count_level(&mut counter, &filter).unwrap();
        assert_eq!(counter.len(), 1);

        let mut counter = HashMap::new();
        event.count_kind(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(BLOCKLIST), Some(&1));

        let mut counter = HashMap::new();
        event.count_category(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(&EventCategory::InitialAccess), Some(&1));

        let mut counter = HashMap::new();
        event.count_ip_address_pair(&mut counter, &filter).unwrap();
        assert_eq!(
            counter.get(&(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            )),
            Some(&1)
        );
    }

    #[test]
    fn syslog_for_blocklist_malformed_dns() {
        let fields = blocklist_malformed_dns_fields();

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistMalformedDns,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistMalformedDns" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="53" proto="17" start_time="1970-01-01T00:00:00+00:00" duration="1000000000" orig_pkts="10" resp_pkts="5" orig_l2_bytes="500" resp_l2_bytes="300" trans_id="1234" flags="33152" question_count="1" answer_count="1" authority_count="0" additional_count="0" query_count="1" resp_count="1" query_bytes="50" resp_bytes="100" query_body="example.com" resp_body="192.0.2.1" confidence="0.95""#
        );

        let blocklist_malformed_dns =
            Event::Blocklist(RecordType::MalformedDns(BlocklistMalformedDns::new(
                msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
                fields.into(),
            )))
            .to_string();

        assert_eq!(
            &blocklist_malformed_dns,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistMalformedDns" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="53" resp_country_code="ZZ" proto="17" start_time="1970-01-01T00:00:00+00:00" duration="1000000000" orig_pkts="10" resp_pkts="5" orig_l2_bytes="500" resp_l2_bytes="300" trans_id="1234" flags="33152" question_count="1" answer_count="1" authority_count="0" additional_count="0" query_count="1" resp_count="1" query_bytes="50" resp_bytes="100" query_body="example.com" resp_body="192.0.2.1" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_rdpbruteforce() {
        let fields = RdpBruteForceFields {
            sensor: String::new(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            resp_addrs: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            ],
            first_event_start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            last_event_start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 10, 2)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            proto: 6,
            confidence: 0.3,
            category: Some(EventCategory::Discovery),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            kind: EventKind::RdpBruteForce,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="RdpBruteForce" category="Discovery" sensor="" orig_addr="127.0.0.1" resp_addrs="127.0.0.2,127.0.0.3" first_event_start_time="1970-01-01T00:01:01+00:00" last_event_start_time="1970-01-01T00:10:02+00:00" proto="6" confidence="0.3""#
        );

        let rdp_brute_force = Event::RdpBruteForce(RdpBruteForce::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            &fields.into(),
        ))
        .to_string();

        assert_eq!(
            &rdp_brute_force,
            r#"time="1970-01-01T00:01:01+00:00" event_kind="RdpBruteForce" category="Discovery" orig_addr="127.0.0.1" orig_country_code="ZZ" resp_addrs="127.0.0.2,127.0.0.3" resp_country_codes="ZZ,ZZ" first_event_start_time="1970-01-01T00:01:01+00:00" last_event_start_time="1970-01-01T00:10:02+00:00" proto="6" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_blocklist_rdp() {
        let fields = BlocklistRdpFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 3389,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            cookie: "cookie".to_string(),
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistRdp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistRdp" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="3389" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" cookie="cookie" confidence="1""#
        );

        let blocklist_rdp = Event::Blocklist(RecordType::Rdp(BlocklistRdp::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();

        assert_eq!(
            &blocklist_rdp,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistRdp" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="3389" resp_country_code="ZZ" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" cookie="cookie" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_blocklist_smb() {
        let fields = BlocklistSmbFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 445,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            command: 1,
            path: "path".to_string(),
            service: "service".to_string(),
            file_name: "file_name".to_string(),
            file_size: 100,
            resource_type: 1,
            fid: 1,
            create_time: 100,
            access_time: 200,
            write_time: 300,
            change_time: 400,
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistSmb,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistSmb" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="445" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" command="1" path="path" service="service" file_name="file_name" file_size="100" resource_type="1" fid="1" create_time="100" access_time="200" write_time="300" change_time="400" confidence="1""#
        );

        let blocklist_smb = Event::Blocklist(RecordType::Smb(BlocklistSmb::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();

        assert_eq!(
            &blocklist_smb,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistSmb" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="445" resp_country_code="ZZ" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" command="1" path="path" service="service" file_name="file_name" file_size="100" resource_type="1" fid="1" create_time="100" access_time="200" write_time="300" change_time="400" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_blocklist_smtp() {
        let fields = BlocklistSmtpFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 25,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            mailfrom: "mailfrom".to_string(),
            date: "date".to_string(),
            from: "from".to_string(),
            to: "to".to_string(),
            subject: "subject".to_string(),
            agent: "agent".to_string(),
            state: "state".to_string(),
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistSmtp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistSmtp" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="25" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" mailfrom="mailfrom" date="date" from="from" to="to" subject="subject" agent="agent" state="state" confidence="1""#
        );

        let blocklist_smtp = Event::Blocklist(RecordType::Smtp(BlocklistSmtp::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();

        assert_eq!(
            &blocklist_smtp,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistSmtp" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="25" resp_country_code="ZZ" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" mailfrom="mailfrom" date="date" from="from" to="to" subject="subject" agent="agent" state="state" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_blocklist_ssh() {
        let fields = BlocklistSshFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 22,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            client: "client".to_string(),
            server: "server".to_string(),
            cipher_alg: "cipher_alg".to_string(),
            mac_alg: "mac_alg".to_string(),
            compression_alg: "compression_alg".to_string(),
            kex_alg: "kex_alg".to_string(),
            host_key_alg: "host_key_alg".to_string(),
            hassh_algorithms: "hassh_algorithms".to_string(),
            hassh: "hassh".to_string(),
            hassh_server_algorithms: "hassh_server_algorithms".to_string(),
            hassh_server: "hassh_server".to_string(),
            client_shka: "client_shka".to_string(),
            server_shka: "server_shka".to_string(),
            confidence: 1.0,
            category: Some(EventCategory::InitialAccess),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistSsh,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistSsh" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="22" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" client="client" server="server" cipher_alg="cipher_alg" mac_alg="mac_alg" compression_alg="compression_alg" kex_alg="kex_alg" host_key_alg="host_key_alg" hassh_algorithms="hassh_algorithms" hassh="hassh" hassh_server_algorithms="hassh_server_algorithms" hassh_server="hassh_server" client_shka="client_shka" server_shka="server_shka" confidence="1""#
        );

        let blocklist_ssh = Event::Blocklist(RecordType::Ssh(BlocklistSsh::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();

        assert_eq!(
            &blocklist_ssh,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistSsh" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="22" resp_country_code="ZZ" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" client="client" server="server" cipher_alg="cipher_alg" mac_alg="mac_alg" compression_alg="compression_alg" kex_alg="kex_alg" host_key_alg="host_key_alg" hassh_algorithms="hassh_algorithms" hassh="hassh" hassh_server_algorithms="hassh_server_algorithms" hassh_server="hassh_server" client_shka="client_shka" server_shka="server_shka" triage_scores="""#
        );
    }

    #[test]
    fn syslog_for_windowsthreat() {
        let fields = WindowsThreatFields {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            sensor: "collector1".to_string(),
            service: "notepad".to_string(),
            agent_name: "win64".to_string(),
            agent_id: "e7e2386a-5485-4da9-b388-b3e50ee7cbb0".to_string(),
            process_guid: "{bac98147-6b03-64d4-8200-000000000700}".to_string(),
            process_id: 2972,
            image: r"C:\Users\vboxuser\Desktop\mal_bazaar\ransomware\918504.exe".to_string(),
            user: r"WIN64\vboxuser".to_string(),
            content: r#"cmd /c "vssadmin.exe Delete Shadows /all /quiet""#.to_string(),
            db_name: "db".to_string(),
            rule_id: 100,
            matched_to: "match".to_string(),
            cluster_id: Some(900),
            attack_kind: "Ransomware_Alcatraz".to_string(),
            confidence: 0.9,
            triage_scores: None,
            category: Some(EventCategory::Impact),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            kind: EventKind::WindowsThreat,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            "time=\"1970-01-01T00:01:01+00:00\" event_kind=\"WindowsThreat\" category=\"Impact\" sensor=\"collector1\" service=\"notepad\" agent_name=\"win64\" agent_id=\"e7e2386a-5485-4da9-b388-b3e50ee7cbb0\" process_guid=\"{bac98147-6b03-64d4-8200-000000000700}\" process_id=\"2972\" image=\"C:\\Users\\vboxuser\\Desktop\\mal_bazaar\\ransomware\\918504.exe\" user=\"WIN64\\vboxuser\" content=\"cmd /c \"vssadmin.exe Delete Shadows /all /quiet\"\" db_name=\"db\" rule_id=\"100\" matched_to=\"match\" cluster_id=\"900\" attack_kind=\"Ransomware_Alcatraz\" confidence=\"0.9\""
        );
        assert!(syslog_message.contains("user=\"WIN64\\vboxuser\""));
        assert!(
            syslog_message
                .contains("content=\"cmd /c \"vssadmin.exe Delete Shadows /all /quiet\"\"")
        );

        let runtime = WindowsThreat::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap()),
            fields.into(),
        );
        let windows_threat = Event::WindowsThreat(runtime).to_string();
        assert_eq!(
            &windows_threat,
            "time=\"1970-01-01T00:01:01+00:00\" event_kind=\"WindowsThreat\" category=\"Impact\" sensor=\"collector1\" service=\"notepad\" agent_name=\"win64\" agent_id=\"e7e2386a-5485-4da9-b388-b3e50ee7cbb0\" process_guid=\"{bac98147-6b03-64d4-8200-000000000700}\" process_id=\"2972\" image=\"C:\\Users\\vboxuser\\Desktop\\mal_bazaar\\ransomware\\918504.exe\" user=\"WIN64\\vboxuser\" content=\"cmd /c \"vssadmin.exe Delete Shadows /all /quiet\"\" db_name=\"db\" rule_id=\"100\" matched_to=\"match\" cluster_id=\"900\" attack_kind=\"Ransomware_Alcatraz\" confidence=\"0.9\" triage_scores=\"\""
        );
        assert!(windows_threat.contains("process_guid=\"{bac98147-6b03-64d4-8200-000000000700}\""));
        assert!(
            windows_threat
                .contains(r#"image="C:\Users\vboxuser\Desktop\mal_bazaar\ransomware\918504.exe""#)
        );
    }

    #[test]
    fn syslog_for_blocklist_tls() {
        let fields = BlocklistTlsFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 443,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            server_name: "server".to_string(),
            alpn_protocol: "alpn".to_string(),
            ja3: "ja3".to_string(),
            version: "version".to_string(),
            client_cipher_suites: vec![1, 2, 3],
            client_extensions: vec![4, 5, 6],
            cipher: 1,
            extensions: vec![7, 8, 9],
            ja3s: "ja3s".to_string(),
            serial: "serial".to_string(),
            subject_country: "country".to_string(),
            subject_org_name: "org".to_string(),
            subject_common_name: "common".to_string(),
            validity_not_before: 100,
            validity_not_after: 200,
            subject_alt_name: "alt".to_string(),
            issuer_country: "country".to_string(),
            issuer_org_name: "org".to_string(),
            issuer_org_unit_name: "unit".to_string(),
            issuer_common_name: "common".to_string(),
            last_alert: 1,
            confidence: 0.9,
            category: Some(EventCategory::InitialAccess),
        };

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::BlocklistTls,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistTls" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="443" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" server_name="server" alpn_protocol="alpn" ja3="ja3" version="version" client_cipher_suites="1,2,3" client_extensions="4,5,6" cipher="1" extensions="7,8,9" ja3s="ja3s" serial="serial" subject_country="country" subject_org_name="org" subject_common_name="common" validity_not_before="100" validity_not_after="200" subject_alt_name="alt" issuer_country="country" issuer_org_name="org" issuer_org_unit_name="unit" issuer_common_name="common" last_alert="1" confidence="0.9""#
        );

        let blocklist_tls = Event::Blocklist(RecordType::Tls(BlocklistTls::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        )))
        .to_string();

        assert_eq!(
            &blocklist_tls,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="BlocklistTls" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="443" resp_country_code="ZZ" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" server_name="server" alpn_protocol="alpn" ja3="ja3" version="version" client_cipher_suites="1,2,3" client_extensions="4,5,6" cipher="1" extensions="7,8,9" ja3s="ja3s" serial="serial" subject_country="country" subject_org_name="org" subject_common_name="common" validity_not_before="100" validity_not_after="200" subject_alt_name="alt" issuer_country="country" issuer_org_name="org" issuer_org_unit_name="unit" issuer_common_name="common" last_alert="1" confidence="0.9" triage_scores="""#
        );
    }

    fn httpeventfields() -> HttpEventFields {
        HttpEventFields {
            sensor: "collector1".to_string(),
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 443,
            proto: 6,
            method: "GET".to_string(),
            host: "host".to_string(),
            uri: "uri".to_string(),
            referer: "referer".to_string(),
            version: "version".to_string(),
            user_agent: "user_agent".to_string(),
            request_len: 100,
            response_len: 200,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: "user".to_string(),
            password: "password".to_string(),
            cookie: "cookie".to_string(),
            content_encoding: "content_encoding".to_string(),
            content_type: "content_type".to_string(),
            cache_control: "cache_control".to_string(),
            filenames: vec!["filename".to_string()],
            mime_types: vec!["mime_type".to_string()],
            body: "post_body".as_bytes().to_vec(),
            state: "state".to_string(),
            confidence: 1.0,
            category: Some(EventCategory::CommandAndControl),
        }
    }

    #[test]
    fn syslog_for_torconnection() {
        let fields = httpeventfields();

        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::TorConnection,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="TorConnection" category="CommandAndControl" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="443" proto="6" start_time="1970-01-01T00:01:01+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" method="GET" host="host" uri="uri" referer="referer" version="version" user_agent="user_agent" request_len="100" response_len="200" status_code="200" status_msg="OK" username="user" password="password" cookie="cookie" content_encoding="content_encoding" content_type="content_type" cache_control="cache_control" filenames="filename" mime_types="mime_type" body="post_body" state="state" confidence="1""#
        );

        let tor_connection = Event::TorConnection(TorConnection::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            &fields.into(),
        ))
        .to_string();

        assert_eq!(
            &tor_connection,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="TorConnection" category="CommandAndControl" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="443" resp_country_code="ZZ" proto="6" start_time="1970-01-01T00:01:01+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" method="GET" host="host" uri="uri" referer="referer" version="version" user_agent="user_agent" request_len="100" response_len="200" status_code="200" status_msg="OK" username="user" password="password" cookie="cookie" content_encoding="content_encoding" content_type="content_type" cache_control="cache_control" filenames="filename" mime_types="mime_type" body="post_body" state="state" triage_scores="""#
        );
    }

    #[test]
    fn event_torconnection() {
        use super::{TOR_CONNECTION, ThreatLevel};

        let (_permit, store) = setup_store();

        let fields = httpeventfields();
        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::TorConnection,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let db = store.events();
        db.put(&message).unwrap();
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            originator: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            responder: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            countries: None,
            categories: None,
            levels: Some(vec![ThreatLevel::Medium]),
            kinds: Some(vec!["tor exit nodes".to_string()]),
            learning_methods: None,
            sensors: Some(vec!["collector1".to_string()]),
            confidence_min: Some(0.5),
            confidence_max: None,
            triage_policies: None,
        };
        assert_eq!(
            event.address_pair(&filter).unwrap(),
            (
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            )
        );
        assert_eq!(event.kind(&filter).unwrap(), Some(TOR_CONNECTION));
        let mut counter = HashMap::new();
        event.count_level(&mut counter, &filter).unwrap();
        assert_eq!(counter.len(), 1);

        let mut counter = HashMap::new();
        event.count_kind(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(TOR_CONNECTION), Some(&1));

        let mut counter = HashMap::new();
        event.count_category(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(&EventCategory::CommandAndControl), Some(&1));

        let mut counter = HashMap::new();
        event.count_ip_address_pair(&mut counter, &filter).unwrap();
        assert_eq!(
            counter.get(&(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            )),
            Some(&1)
        );
    }

    fn blocklist_tls_fields() -> BlocklistTlsFields {
        BlocklistTlsFields {
            sensor: "collector1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 443,
            proto: 6,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            server_name: "server".to_string(),
            alpn_protocol: "alpn".to_string(),
            ja3: "ja3".to_string(),
            version: "version".to_string(),
            client_cipher_suites: vec![1, 2, 3],
            client_extensions: vec![4, 5, 6],
            cipher: 1,
            extensions: vec![7, 8, 9],
            ja3s: "ja3s".to_string(),
            serial: "serial".to_string(),
            subject_country: "country".to_string(),
            subject_org_name: "org".to_string(),
            subject_common_name: "common".to_string(),
            validity_not_before: 100,
            validity_not_after: 200,
            subject_alt_name: "alt".to_string(),
            issuer_country: "country".to_string(),
            issuer_org_name: "org".to_string(),
            issuer_org_unit_name: "unit".to_string(),
            issuer_common_name: "common".to_string(),
            last_alert: 1,
            confidence: 0.9,
            category: Some(EventCategory::InitialAccess),
        }
    }

    #[test]
    fn syslog_for_suspicious_tls_traffic() {
        use super::common::Match;

        let fields = blocklist_tls_fields();
        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::SuspiciousTlsTraffic,
            fields: bincode::serialize(&fields).expect("serializable"),
        };

        let message = message.syslog_rfc5424();
        assert!(message.is_ok());
        let (_, _, syslog_message) = message.unwrap();
        assert_eq!(
            &syslog_message,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="SuspiciousTlsTraffic" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" resp_addr="127.0.0.2" resp_port="443" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" server_name="server" alpn_protocol="alpn" ja3="ja3" version="version" client_cipher_suites="1,2,3" client_extensions="4,5,6" cipher="1" extensions="7,8,9" ja3s="ja3s" serial="serial" subject_country="country" subject_org_name="org" subject_common_name="common" validity_not_before="100" validity_not_after="200" subject_alt_name="alt" issuer_country="country" issuer_org_name="org" issuer_org_unit_name="unit" issuer_common_name="common" last_alert="1" confidence="0.9""#
        );

        let suspicious_tls_traffic = SuspiciousTlsTraffic::new(
            msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            fields.into(),
        );
        assert_eq!(
            suspicious_tls_traffic.orig_addrs(),
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
        assert_eq!(
            suspicious_tls_traffic.resp_addrs(),
            &[IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]
        );
        assert_eq!(
            suspicious_tls_traffic.category(),
            Some(EventCategory::InitialAccess)
        );
        assert_eq!(suspicious_tls_traffic.orig_port(), 10000);
        assert_eq!(suspicious_tls_traffic.resp_port(), 443);
        assert_eq!(suspicious_tls_traffic.proto(), 6);
        let event = Event::SuspiciousTlsTraffic(suspicious_tls_traffic);
        let blocklist_tls = event.to_string();

        assert_eq!(
            &blocklist_tls,
            r#"time="1970-01-01T01:01:01+00:00" event_kind="SuspiciousTlsTraffic" category="InitialAccess" sensor="collector1" orig_addr="127.0.0.1" orig_port="10000" orig_country_code="ZZ" resp_addr="127.0.0.2" resp_port="443" resp_country_code="ZZ" proto="6" start_time="1970-01-01T00:00:00+00:00" duration="0" orig_pkts="0" resp_pkts="0" orig_l2_bytes="0" resp_l2_bytes="0" server_name="server" alpn_protocol="alpn" ja3="ja3" version="version" client_cipher_suites="1,2,3" client_extensions="4,5,6" cipher="1" extensions="7,8,9" ja3s="ja3s" serial="serial" subject_country="country" subject_org_name="org" subject_common_name="common" validity_not_before="100" validity_not_after="200" subject_alt_name="alt" issuer_country="country" issuer_org_name="org" issuer_org_unit_name="unit" issuer_common_name="common" last_alert="1" confidence="0.9" triage_scores="""#
        );
    }

    #[test]
    fn event_suspicious_tls_traffic() {
        use super::{SUSPICIOUS_TLS_TRAFFIC, ThreatLevel};

        let (_permit, store) = setup_store();

        let mut fields = blocklist_tls_fields();
        fields.category = None;
        let message = EventMessage {
            time: msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap()),
            kind: EventKind::SuspiciousTlsTraffic,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let db = store.events();
        db.put(&message).unwrap();
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            originator: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            responder: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            countries: None,
            categories: None,
            levels: Some(vec![ThreatLevel::Medium]),
            kinds: Some(vec!["suspicious tls traffic".to_string()]),
            learning_methods: None,
            sensors: Some(vec!["collector1".to_string()]),
            confidence_min: Some(0.5),
            confidence_max: None,
            triage_policies: None,
        };
        assert_eq!(
            event.address_pair(&filter).unwrap(),
            (
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            )
        );
        assert_eq!(event.kind(&filter).unwrap(), Some(SUSPICIOUS_TLS_TRAFFIC));
        let mut counter = HashMap::new();
        event.count_level(&mut counter, &filter).unwrap();
        assert_eq!(counter.len(), 1);

        let mut counter = HashMap::new();
        event.count_kind(&mut counter, &filter).unwrap();
        assert_eq!(counter.get(SUSPICIOUS_TLS_TRAFFIC), Some(&1));

        let mut counter = HashMap::new();
        event.count_category(&mut counter, &filter).unwrap();
        assert_eq!(counter.len(), 0);

        let mut counter = HashMap::new();
        event.count_ip_address_pair(&mut counter, &filter).unwrap();
        assert_eq!(
            counter.get(&(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            )),
            Some(&1)
        );
    }

    #[test]
    fn event_kind_categories() {
        use crate::types::EventCategory;

        // Test that DnsCovertChannel matches multiple categories
        let dns_categories = EventKind::DnsCovertChannel.categories();
        assert_eq!(dns_categories.len(), 2);
        assert!(dns_categories.contains(&EventCategory::CommandAndControl));
        assert!(dns_categories.contains(&EventCategory::Exfiltration));

        // Test that other events still work
        let port_scan_categories = EventKind::PortScan.categories();
        assert_eq!(port_scan_categories.len(), 1);
        assert!(port_scan_categories.contains(&EventCategory::Reconnaissance));

        // Test blocklist events
        let blocklist_categories = EventKind::BlocklistHttp.categories();
        assert_eq!(blocklist_categories.len(), 1);
        assert!(blocklist_categories.contains(&EventCategory::InitialAccess));
    }

    #[test]
    fn event_categories_method() {
        let (_permit, store) = setup_store();
        let db = store.events();

        // Create and store a DnsCovertChannel event
        let msg = example_message(
            EventKind::DnsCovertChannel,
            EventCategory::CommandAndControl,
        );
        db.put(&msg).unwrap();

        // Retrieve the event
        let mut iter = db.iter_forward();
        let e = iter.next();
        assert!(e.is_some());
        let (_key, event) = e.unwrap().unwrap();

        // Test that the event's categories method returns multiple categories
        let categories = event.categories();
        assert_eq!(categories.len(), 2);
        assert!(categories.contains(&EventCategory::CommandAndControl));
        assert!(categories.contains(&EventCategory::Exfiltration));
    }

    #[test]
    fn count_country_rdp_brute_force_counts_origin_only() {
        let time = msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap());
        let event = Event::RdpBruteForce(RdpBruteForce {
            sensor: String::new(),
            time,
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_country_code: *b"US",
            resp_addrs: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            ],
            resp_country_codes: vec![*b"KR", *b"JP"],
            first_event_start_time: time,
            last_event_start_time: time,
            proto: 6,
            confidence: 0.3,
            category: Some(EventCategory::Discovery),
            triage_scores: None,
        });
        let filter = EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            originator: None,
            responder: None,
            countries: None,
            categories: None,
            levels: None,
            kinds: None,
            learning_methods: None,
            sensors: None,
            confidence_min: None,
            confidence_max: None,
            triage_policies: None,
        };

        let mut counter = HashMap::new();
        event.count_country(&mut counter, &filter).unwrap();
        assert_eq!(counter.get("US"), Some(&1));
        assert!(!counter.contains_key("KR"));
        assert!(!counter.contains_key("JP"));
        assert_eq!(counter.len(), 1);
    }

    #[test]
    fn event_kind_stable_discriminants() {
        use num_traits::{FromPrimitive, ToPrimitive};

        // Test that ToPrimitive yields the expected numeric values.
        // These values must remain stable across versions.
        assert_eq!(EventKind::DnsCovertChannel.to_u32(), Some(0));
        assert_eq!(EventKind::HttpThreat.to_u32(), Some(1));
        assert_eq!(EventKind::RdpBruteForce.to_u32(), Some(2));
        assert_eq!(EventKind::RepeatedHttpSessions.to_u32(), Some(3));
        assert_eq!(EventKind::ExtraThreat.to_u32(), Some(4));
        assert_eq!(EventKind::TorConnection.to_u32(), Some(5));
        assert_eq!(EventKind::DomainGenerationAlgorithm.to_u32(), Some(6));
        assert_eq!(EventKind::FtpBruteForce.to_u32(), Some(7));
        assert_eq!(EventKind::FtpPlainText.to_u32(), Some(8));
        assert_eq!(EventKind::PortScan.to_u32(), Some(9));
        assert_eq!(EventKind::MultiHostPortScan.to_u32(), Some(10));
        assert_eq!(EventKind::NonBrowser.to_u32(), Some(11));
        assert_eq!(EventKind::LdapBruteForce.to_u32(), Some(12));
        assert_eq!(EventKind::LdapPlainText.to_u32(), Some(13));
        assert_eq!(EventKind::ExternalDdos.to_u32(), Some(14));
        assert_eq!(EventKind::CryptocurrencyMiningPool.to_u32(), Some(15));
        assert_eq!(EventKind::BlocklistConn.to_u32(), Some(16));
        assert_eq!(EventKind::BlocklistDns.to_u32(), Some(17));
        assert_eq!(EventKind::BlocklistDceRpc.to_u32(), Some(18));
        assert_eq!(EventKind::BlocklistFtp.to_u32(), Some(19));
        assert_eq!(EventKind::BlocklistHttp.to_u32(), Some(20));
        assert_eq!(EventKind::BlocklistKerberos.to_u32(), Some(21));
        assert_eq!(EventKind::BlocklistLdap.to_u32(), Some(22));
        assert_eq!(EventKind::BlocklistMqtt.to_u32(), Some(23));
        assert_eq!(EventKind::BlocklistNfs.to_u32(), Some(24));
        assert_eq!(EventKind::BlocklistNtlm.to_u32(), Some(25));
        assert_eq!(EventKind::BlocklistRdp.to_u32(), Some(26));
        assert_eq!(EventKind::BlocklistSmb.to_u32(), Some(27));
        assert_eq!(EventKind::BlocklistSmtp.to_u32(), Some(28));
        assert_eq!(EventKind::BlocklistSsh.to_u32(), Some(29));
        assert_eq!(EventKind::BlocklistTls.to_u32(), Some(30));
        assert_eq!(EventKind::WindowsThreat.to_u32(), Some(31));
        assert_eq!(EventKind::NetworkThreat.to_u32(), Some(32));
        assert_eq!(EventKind::LockyRansomware.to_u32(), Some(33));
        assert_eq!(EventKind::SuspiciousTlsTraffic.to_u32(), Some(34));
        assert_eq!(EventKind::BlocklistBootp.to_u32(), Some(35));
        assert_eq!(EventKind::BlocklistDhcp.to_u32(), Some(36));
        assert_eq!(EventKind::TorConnectionConn.to_u32(), Some(37));
        assert_eq!(EventKind::BlocklistRadius.to_u32(), Some(38));
        assert_eq!(EventKind::BlocklistMalformedDns.to_u32(), Some(39));
        assert_eq!(EventKind::UnusualDestinationPattern.to_u32(), Some(40));

        // Test FromPrimitive round-trip conversion
        assert_eq!(EventKind::from_u32(0), Some(EventKind::DnsCovertChannel));
        assert_eq!(EventKind::from_u32(1), Some(EventKind::HttpThreat));
        assert_eq!(EventKind::from_u32(20), Some(EventKind::BlocklistHttp));
        assert_eq!(
            EventKind::from_u32(40),
            Some(EventKind::UnusualDestinationPattern)
        );

        // Test that invalid values return None
        assert_eq!(EventKind::from_u32(41), None);
        assert_eq!(EventKind::from_u32(100), None);
        assert_eq!(EventKind::from_u32(u32::MAX), None);
    }

    #[test]
    fn event_kind_serde_round_trip() {
        // Test that serde serialization and deserialization round-trips correctly.
        // This ensures the numeric representation is preserved through bincode.
        let original = EventKind::BlocklistHttp;
        let serialized = bincode::serialize(&original).expect("serialization should succeed");
        let deserialized: EventKind =
            bincode::deserialize(&serialized).expect("deserialization should succeed");
        assert_eq!(original, deserialized);

        // Test all variants round-trip correctly
        let all_variants = [
            EventKind::DnsCovertChannel,
            EventKind::HttpThreat,
            EventKind::RdpBruteForce,
            EventKind::RepeatedHttpSessions,
            EventKind::ExtraThreat,
            EventKind::TorConnection,
            EventKind::DomainGenerationAlgorithm,
            EventKind::FtpBruteForce,
            EventKind::FtpPlainText,
            EventKind::PortScan,
            EventKind::MultiHostPortScan,
            EventKind::NonBrowser,
            EventKind::LdapBruteForce,
            EventKind::LdapPlainText,
            EventKind::ExternalDdos,
            EventKind::CryptocurrencyMiningPool,
            EventKind::BlocklistConn,
            EventKind::BlocklistDns,
            EventKind::BlocklistDceRpc,
            EventKind::BlocklistFtp,
            EventKind::BlocklistHttp,
            EventKind::BlocklistKerberos,
            EventKind::BlocklistLdap,
            EventKind::BlocklistMqtt,
            EventKind::BlocklistNfs,
            EventKind::BlocklistNtlm,
            EventKind::BlocklistRdp,
            EventKind::BlocklistSmb,
            EventKind::BlocklistSmtp,
            EventKind::BlocklistSsh,
            EventKind::BlocklistTls,
            EventKind::WindowsThreat,
            EventKind::NetworkThreat,
            EventKind::LockyRansomware,
            EventKind::SuspiciousTlsTraffic,
            EventKind::BlocklistBootp,
            EventKind::BlocklistDhcp,
            EventKind::TorConnectionConn,
            EventKind::BlocklistRadius,
            EventKind::BlocklistMalformedDns,
            EventKind::UnusualDestinationPattern,
        ];

        for variant in all_variants {
            let serialized = bincode::serialize(&variant).expect("serialization should succeed");
            let deserialized: EventKind =
                bincode::deserialize(&serialized).expect("deserialization should succeed");
            assert_eq!(variant, deserialized);
        }
    }

    #[test]
    fn iterator_skips_unknown_event_kind() {
        let (_permit, store) = setup_store();
        let db = store.events();

        // Insert an entry with an unknown event kind (kind = 9999).
        let unknown_kind: i128 = 9999;
        let ts: i128 = 1_000_000_000; // 1 second in nanos
        let unknown_key = (ts << 64) | (unknown_kind << 32);
        db.put_raw(&unknown_key.to_be_bytes(), b"dummy");

        // Insert a valid entry after the unknown one.
        let msg = example_message(
            EventKind::DnsCovertChannel,
            EventCategory::CommandAndControl,
        );
        db.put(&msg).unwrap();

        // The iterator should skip the unknown entry and yield
        // only the valid one.
        let mut iter = db.iter_forward();
        let item = iter.next();
        assert!(item.is_some_and(|r| r.is_ok()));
        assert!(iter.next().is_none());
    }

    #[test]
    fn iterator_returns_none_when_only_unknown_kinds() {
        let (_permit, store) = setup_store();
        let db = store.events();

        // Insert only entries with unknown event kinds.
        for kind_num in [9999_i128, 10000, 10001] {
            let ts: i128 = 1_000_000_000;
            let key = (ts << 64) | (kind_num << 32);
            db.put_raw(&key.to_be_bytes(), b"dummy");
        }

        let mut iter = db.iter_forward();
        assert!(
            iter.next().is_none(),
            "expected None when all entries have unknown kinds",
        );
    }

    #[test]
    fn iterator_errors_on_malformed_key() {
        let (_permit, store) = setup_store();
        let db = store.events();

        // Insert an entry with a key that is not 16 bytes.
        db.put_raw(&[0xAB; 8], b"dummy");

        let mut iter = db.iter_forward();
        let item = iter.next();
        assert!(item.is_some_and(|r| r.is_err()));
    }

    #[test]
    fn remove_before_deletes_old_events() {
        let (_permit, store) = setup_store();
        let db = store.events();

        // Insert events at different timestamps.
        let old_time = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let recent_time = Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap();

        let old_msg = EventMessage {
            time: msg_time(old_time),
            kind: EventKind::DnsCovertChannel,
            fields: bincode::serialize(&DnsEventFields {
                sensor: "s1".to_string(),
                orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                orig_port: 1000,
                resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                resp_port: 53,
                proto: 17,
                start_time: old_time.timestamp_nanos_opt().unwrap(),
                duration: 0,
                orig_pkts: 0,
                resp_pkts: 0,
                orig_l2_bytes: 0,
                resp_l2_bytes: 0,
                query: "old.com".to_string(),
                answer: vec![],
                trans_id: 1,
                rtt: 1,
                qclass: 0,
                qtype: 0,
                rcode: 0,
                aa_flag: false,
                tc_flag: false,
                rd_flag: false,
                ra_flag: false,
                ttl: vec![],
                confidence: 0.5,
                category: None,
            })
            .unwrap(),
        };

        let recent_msg = EventMessage {
            time: msg_time(recent_time),
            kind: EventKind::DnsCovertChannel,
            fields: old_msg.fields.clone(),
        };

        db.put(&old_msg).unwrap();
        db.put(&recent_msg).unwrap();

        // Verify both events exist.
        assert_eq!(db.iter_forward().count(), 2);

        // Remove events before 2024-01-01.
        let cutoff = msg_time(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap());
        let deleted = db.remove_before(cutoff).unwrap();
        assert_eq!(deleted, 1);

        // Only the recent event remains.
        assert_eq!(db.iter_forward().count(), 1);
    }

    #[test]
    fn remove_before_no_events_to_delete() {
        let (_permit, store) = setup_store();
        let db = store.events();

        let msg = example_message(
            EventKind::DnsCovertChannel,
            EventCategory::CommandAndControl,
        );
        db.put(&msg).unwrap();

        // Cutoff in the past — nothing to delete.
        let cutoff = msg_time(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap());
        let deleted = db.remove_before(cutoff).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(db.iter_forward().count(), 1);
    }

    #[test]
    fn remove_before_empty_db() {
        let (_permit, store) = setup_store();
        let db = store.events();

        let cutoff = msg_time(Utc::now());
        let deleted = db.remove_before(cutoff).unwrap();
        assert_eq!(deleted, 0);
    }

    #[test]
    fn remove_before_exact_cutoff_is_not_deleted() {
        let (_permit, store) = setup_store();
        let db = store.events();

        let exact_time = Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0).unwrap();
        let before_time = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();

        let msg_at_cutoff = EventMessage {
            time: msg_time(exact_time),
            kind: EventKind::DnsCovertChannel,
            fields: bincode::serialize(&DnsEventFields {
                sensor: "s1".to_string(),
                orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                orig_port: 1000,
                resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                resp_port: 53,
                proto: 17,
                start_time: exact_time.timestamp_nanos_opt().unwrap(),
                duration: 0,
                orig_pkts: 0,
                resp_pkts: 0,
                orig_l2_bytes: 0,
                resp_l2_bytes: 0,
                query: "exact.com".to_string(),
                answer: vec![],
                trans_id: 1,
                rtt: 1,
                qclass: 0,
                qtype: 0,
                rcode: 0,
                aa_flag: false,
                tc_flag: false,
                rd_flag: false,
                ra_flag: false,
                ttl: vec![],
                confidence: 0.5,
                category: None,
            })
            .unwrap(),
        };

        let msg_before = EventMessage {
            time: msg_time(before_time),
            kind: EventKind::DnsCovertChannel,
            fields: msg_at_cutoff.fields.clone(),
        };

        db.put(&msg_before).unwrap();
        db.put(&msg_at_cutoff).unwrap();
        assert_eq!(db.iter_forward().count(), 2);

        // Cutoff equal to exact_time: event at exact_time is NOT deleted
        // (strictly before).
        let deleted = db.remove_before(msg_time(exact_time)).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(db.iter_forward().count(), 1);
    }

    #[test]
    fn remove_before_far_past_cutoff_deletes_nothing() {
        let (_permit, store) = setup_store();
        let db = store.events();

        let msg = example_message(
            EventKind::DnsCovertChannel,
            EventCategory::CommandAndControl,
        );
        db.put(&msg).unwrap();

        // A cutoff so far in the past that nanoseconds overflow (before 1677).
        let far_past =
            Timestamp::from_nanosecond(i128::from(i64::MIN) - 1).expect("valid jiff timestamp");
        assert!(
            timestamp::to_i64_nanos(far_past).is_err(),
            "cutoff should overflow nanosecond representation"
        );
        let deleted = db.remove_before(far_past).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(db.iter_forward().count(), 1);
    }

    #[test]
    fn remove_before_far_future_cutoff_deletes_everything() {
        let (_permit, store) = setup_store();
        let db = store.events();

        let msg = example_message(
            EventKind::DnsCovertChannel,
            EventCategory::CommandAndControl,
        );
        db.put(&msg).unwrap();

        // A cutoff so far in the future that nanoseconds overflow (after 2262).
        let far_future =
            Timestamp::from_nanosecond(i128::from(i64::MAX) + 1).expect("valid jiff timestamp");
        assert!(
            timestamp::to_i64_nanos(far_future).is_err(),
            "cutoff should overflow nanosecond representation"
        );
        let deleted = db.remove_before(far_future).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(db.iter_forward().count(), 0);
    }

    #[test]
    fn remove_before_multiple_batches() {
        let (_permit, store) = setup_store();
        let db = store.events();

        // Insert more than BATCH_SIZE (1000) events so deletion spans
        // multiple batches.
        let base_time = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let fields = bincode::serialize(&DnsEventFields {
            sensor: "s1".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 1000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 53,
            proto: 17,
            start_time: base_time.timestamp_nanos_opt().unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            query: "batch.com".to_string(),
            answer: vec![],
            trans_id: 1,
            rtt: 1,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: false,
            ttl: vec![],
            confidence: 0.5,
            category: None,
        })
        .unwrap();

        let total: usize = 1_500;
        for i in 0..total {
            let time =
                base_time + chrono::Duration::seconds(i64::try_from(i).expect("small value"));
            let msg = EventMessage {
                time: msg_time(time),
                kind: EventKind::DnsCovertChannel,
                fields: fields.clone(),
            };
            db.put(&msg).unwrap();
        }

        assert_eq!(db.iter_forward().count(), total);

        // Cutoff well after all events.
        let cutoff = msg_time(Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap());
        let deleted = db.remove_before(cutoff).unwrap();
        assert_eq!(deleted, u64::try_from(total).unwrap());
        assert_eq!(db.iter_forward().count(), 0);
    }
}
