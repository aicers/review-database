//! External event-field types for the ingestion boundary.
//!
//! This module establishes a seam between the wire format that external
//! producers send and the internal `*Fields` types that the database layer
//! persists. [`EventDb::put_external`](super::EventDb::put_external) is the
//! ingestion entrypoint: it deserializes the incoming payload into the
//! corresponding external type, converts it into the internal type, and
//! stores the internal representation.
//!
//! Today each external type is declared as an alias of its internal
//! counterpart, so the conversion is an identity. The alias keeps the
//! boundary explicit in the public API and fixes the ingestion entrypoint.
//! A future change that diverges the internal schema from the wire format
//! (for example, populating fields that are not present on the wire) can
//! replace these aliases with distinct struct definitions and provide a real
//! [`From`] implementation, without touching the ingestion plumbing or
//! external callers.
//!
//! # Adding a new external event type
//!
//! 1. Add an alias (or a distinct struct) here for the external schema.
//! 2. If the type is distinct, implement [`From<External>`](From) for the
//!    internal `*Fields` type so [`EventDb::put_external`] can convert it.
//! 3. Add a match arm for the corresponding
//!    [`EventKind`](super::EventKind) in
//!    [`EventDb::put_external`](super::EventDb::put_external).

use super::{
    BlocklistBootpFields, BlocklistConnFields, BlocklistDceRpcFields, BlocklistDhcpFields,
    BlocklistDnsFields, BlocklistHttpFields, BlocklistKerberosFields, BlocklistMalformedDnsFields,
    BlocklistMqttFields, BlocklistNfsFields, BlocklistNtlmFields, BlocklistRadiusFields,
    BlocklistRdpFields, BlocklistSmbFields, BlocklistSmtpFields, BlocklistSshFields,
    BlocklistTlsFields, CryptocurrencyMiningPoolFields, DgaFields, DnsEventFields,
    ExternalDdosFields, ExtraThreat, FtpBruteForceFields, FtpEventFields, HttpEventFields,
    HttpThreatFields, LdapBruteForceFields, LdapEventFields, MultiHostPortScanFields,
    NetworkThreat, PortScanFields, RdpBruteForceFields, RepeatedHttpSessionsFields,
    UnusualDestinationPatternFields, WindowsThreat,
};

pub type BlocklistBootpFieldsExternal = BlocklistBootpFields;
pub type BlocklistConnFieldsExternal = BlocklistConnFields;
pub type BlocklistDceRpcFieldsExternal = BlocklistDceRpcFields;
pub type BlocklistDhcpFieldsExternal = BlocklistDhcpFields;
pub type BlocklistDnsFieldsExternal = BlocklistDnsFields;
pub type BlocklistHttpFieldsExternal = BlocklistHttpFields;
pub type BlocklistKerberosFieldsExternal = BlocklistKerberosFields;
pub type BlocklistMalformedDnsFieldsExternal = BlocklistMalformedDnsFields;
pub type BlocklistMqttFieldsExternal = BlocklistMqttFields;
pub type BlocklistNfsFieldsExternal = BlocklistNfsFields;
pub type BlocklistNtlmFieldsExternal = BlocklistNtlmFields;
pub type BlocklistRadiusFieldsExternal = BlocklistRadiusFields;
pub type BlocklistRdpFieldsExternal = BlocklistRdpFields;
pub type BlocklistSmbFieldsExternal = BlocklistSmbFields;
pub type BlocklistSmtpFieldsExternal = BlocklistSmtpFields;
pub type BlocklistSshFieldsExternal = BlocklistSshFields;
pub type BlocklistTlsFieldsExternal = BlocklistTlsFields;
pub type CryptocurrencyMiningPoolFieldsExternal = CryptocurrencyMiningPoolFields;
pub type DgaFieldsExternal = DgaFields;
pub type DnsEventFieldsExternal = DnsEventFields;
pub type ExternalDdosFieldsExternal = ExternalDdosFields;
pub type ExtraThreatExternal = ExtraThreat;
pub type FtpBruteForceFieldsExternal = FtpBruteForceFields;
pub type FtpEventFieldsExternal = FtpEventFields;
pub type HttpEventFieldsExternal = HttpEventFields;
pub type HttpThreatFieldsExternal = HttpThreatFields;
pub type LdapBruteForceFieldsExternal = LdapBruteForceFields;
pub type LdapEventFieldsExternal = LdapEventFields;
pub type MultiHostPortScanFieldsExternal = MultiHostPortScanFields;
pub type NetworkThreatExternal = NetworkThreat;
pub type PortScanFieldsExternal = PortScanFields;
pub type RdpBruteForceFieldsExternal = RdpBruteForceFields;
pub type RepeatedHttpSessionsFieldsExternal = RepeatedHttpSessionsFields;
pub type UnusualDestinationPatternFieldsExternal = UnusualDestinationPatternFields;
pub type WindowsThreatExternal = WindowsThreat;
