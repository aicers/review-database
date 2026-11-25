//! The identifier hash of an observation and the network digest of a
//! customer, as `review-protocol` defines them.
//!
//! Both are computed over the bincode 2 `config::standard()` serde encoding
//! of a value, the encoding of every request of the protocol, and SHA-256.

use anyhow::{Context, Result};
use aws_lc_rs::digest;
use review_protocol::types::{DaiObservationBody, HostNetworkGroup as ProtocolGroup};
use serde::Serialize;

use crate::{HostNetworkGroup, OwnedNetworkSet};

/// The number of bytes of an identifier hash.
pub(super) const IDENTIFIER_HASH_LEN: usize = 16;
/// The number of bytes of a network digest.
const DIGEST_LEN: usize = 8;

/// The networks of a customer as device identification hands them to an
/// agent, with their digest.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DaiNetworks {
    /// The customer's internal addresses, the
    /// [`OwnedNetworkSet::internal_group`] of its networks: those whose
    /// narrowest containing network is an `Intranet` or `Gateway` network.
    pub internal: ProtocolGroup,
    /// All of the customer's networks, of any kind, merged into one group.
    pub registered: ProtocolGroup,
    /// The network digest of `(internal, registered)`.
    pub digest: u64,
}

/// Returns the networks of a customer, `networks` being its
/// `customer networks` row or `None` if it has none, as device
/// identification hands them to an agent, with their network digest.
///
/// `internal` is [`OwnedNetworkSet::internal_group`]: the addresses whose
/// narrowest containing network is an `Intranet` or `Gateway` network, with
/// no `Extranet` network containing them as narrowly. It keeps every entry
/// of an `Intranet` or `Gateway` network that holds no other address, and
/// adds the internal addresses of the rest as ranges, so a set in which no
/// `Extranet` entry overlaps an `Intranet` or `Gateway` entry gives the
/// merge of its `Intranet` and `Gateway` networks. `registered` merges all
/// networks, of any kind. Each list inside both
/// groups is sorted ascending (`hosts` and `networks` by their `Ord`,
/// `ip_ranges` by `(start, end)`) and has no duplicates. The digest is the
/// first 8 bytes of SHA-256, read as a little-endian `u64`, over the bincode 2
/// `config::standard()` serde encoding of `(internal, registered)`, the rule
/// `review-protocol` documents for `network_digest`. It depends only on the
/// content of the two groups: not on the order or the names of the networks,
/// nor on an `Intranet` or `Gateway` network whose entries other networks of
/// those types already hold. An `Extranet` network can change both groups,
/// since an entry it shares with an `Intranet` network leaves that entry's
/// addresses out of `internal`. No row gives two empty groups.
///
/// # Errors
///
/// Returns an error if the groups cannot be encoded.
pub fn dai_network_digest(networks: Option<&OwnedNetworkSet>) -> Result<DaiNetworks> {
    let (internal, registered) = networks.map_or_else(
        || (HostNetworkGroup::default(), HostNetworkGroup::default()),
        |set| (set.internal_group(), set.merged_group()),
    );
    let internal = protocol_group(&internal);
    let registered = protocol_group(&registered);
    let encoded = encode(&(&internal, &registered)).context("cannot encode customer networks")?;
    let sha = digest::digest(&digest::SHA256, &encoded);
    let bytes = sha
        .as_ref()
        .first_chunk::<DIGEST_LEN>()
        .context("a SHA-256 digest is shorter than a network digest")?;
    Ok(DaiNetworks {
        internal,
        registered,
        digest: u64::from_le_bytes(*bytes),
    })
}

/// Returns `group` as the protocol's type. Its lists are already sorted and
/// deduplicated.
fn protocol_group(group: &HostNetworkGroup) -> ProtocolGroup {
    ProtocolGroup {
        hosts: group.hosts().to_vec(),
        networks: group.networks().to_vec(),
        ip_ranges: group.ip_ranges().to_vec(),
    }
}

/// Returns the identifier hash of an observation body: the first 16 bytes of
/// SHA-256 over the bincode 2 `config::standard()` serde encoding of the
/// tuple of its identifier fields, in declaration order.
///
/// The identifier fields are `time` through `giaddr` in `DhcpLease`, all
/// but `external_client` in `Service`, and all fields in every other
/// variant. The kind is not part of it.
pub(super) fn identifier_hash(body: &DaiObservationBody) -> Result<[u8; IDENTIFIER_HASH_LEN]> {
    let encoded = match body {
        DaiObservationBody::DhcpLease {
            time,
            msg,
            ip,
            chaddr,
            xid,
            server_ip,
            server_id,
            giaddr,
            ..
        } => encode(&(time, msg, ip, chaddr, xid, server_ip, server_id, giaddr)),
        DaiObservationBody::DhcpServer {
            server_ip,
            server_id,
        } => encode(&(server_ip, server_id)),
        DaiObservationBody::Kerberos {
            client_ip,
            realm,
            cname,
            sname,
            msg_type,
            accepted,
            preauth,
            error_code,
        } => encode(&(
            client_ip, realm, cname, sname, msg_type, accepted, preauth, error_code,
        )),
        DaiObservationBody::Ntlm {
            ip,
            workstation,
            user,
            domain,
            success,
        } => encode(&(ip, workstation, user, domain, success)),
        DaiObservationBody::Service {
            server_ip,
            port,
            proto,
            ..
        } => encode(&(server_ip, port, proto)),
        DaiObservationBody::SoftwareString {
            ip,
            side,
            source,
            text,
        } => encode(&(ip, side, source, text)),
        DaiObservationBody::DnsName { name, ip } => encode(&(name, ip)),
        DaiObservationBody::IpActivity { ip, side } => encode(&(ip, side)),
    }
    .context("cannot encode an observation identifier")?;
    let sha = digest::digest(&digest::SHA256, &encoded);
    sha.as_ref()
        .first_chunk::<IDENTIFIER_HASH_LEN>()
        .copied()
        .context("a SHA-256 digest is shorter than an identifier hash")
}

/// Returns the bincode 2 `config::standard()` serde encoding of `value`.
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(bincode2::serde::encode_to_vec(
        value,
        bincode2::config::standard(),
    )?)
}
