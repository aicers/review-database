//! The stored form of a detection event: the event, its stamp and the
//! country codes of its endpoint addresses.

use std::{borrow::Cow, net::IpAddr};

use anyhow::{Context, Result, bail};
use review_protocol::types::{
    Detail, DetectionEvent, EndpointRole, PrimarySubject, RawEventBody, RelatedIp, Target,
};
use serde::{Deserialize, Serialize};

use super::RawEventKey;
use crate::{ClusteringModelTypeRef, EventCategory, ModelInstance, geo::CountryLookup};

/// The bit pattern of `-0.0_f64`.
const NEGATIVE_ZERO_BITS: u64 = 0x8000_0000_0000_0000;

/// The bit pattern of `-0.0_f32`.
const NEGATIVE_ZERO_BITS_F32: u32 = 0x8000_0000;

/// What the receiver of a detection event records about it at receive time.
///
/// It is stored verbatim with the event; nothing in it is checked.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DetectionEventStamp {
    /// The engine instance that sent the event.
    pub engine_instance: ModelInstance,
    /// The clustering model the event is about, if one.
    pub clustering_model_id: Option<u32>,
    /// When the model that made the detection was trained, if known.
    #[serde(with = "optional_i128_nanoseconds")]
    pub trained_at: Option<jiff::Timestamp>,
    /// The version of the engine installed when the event was received.
    pub installed_version: Option<String>,
    /// The commit of the engine installed when the event was received.
    pub installed_commit: Option<String>,
    /// The revision of the engine configuration in effect.
    pub config_revision: Option<u64>,
    /// The clustering model type of the model that produced the event, as
    /// the caller decided it at receive time; `None` for an event not
    /// produced by a clustering model. It stays as stored when the model is
    /// later retrained as another type.
    pub clustering_model_type: Option<ClusteringModelTypeRef>,
}

/// Serde adapter for an optional timestamp as optional `i128` epoch
/// nanoseconds, which holds every timestamp exactly.
///
/// jiff's own optional nanosecond adapter writes an `i128` but reads an
/// `i64`, which a format that is not self-describing, such as bincode,
/// cannot decode.
mod optional_i128_nanoseconds {
    use jiff::Timestamp;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

    #[allow(clippy::ref_option)] // `serde(with)` passes the field by reference.
    pub(super) fn serialize<S: Serializer>(
        time: &Option<Timestamp>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        time.map(Timestamp::as_nanosecond).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Timestamp>, D::Error> {
        Option::<i128>::deserialize(deserializer)?
            .map(Timestamp::from_nanosecond)
            .transpose()
            .map_err(D::Error::custom)
    }
}

/// A stored detection event: the event, the stamp recorded with it, and the
/// country code of each of its endpoint addresses.
///
/// The endpoint addresses are the `orig_addr` and `resp_addr` of a
/// [`Target::RawEvent`] body that has both fields, and, for a
/// [`Target::Subject`], the host addresses of its primary subject (the IP of
/// a [`PrimarySubject::Host`], or every element of the `ips` of a
/// [`PrimarySubject::Endpoint`]) and every related IP. A body without both
/// fields, such as a Sysmon, an endpoint log or a Netflow v5 body, has no
/// endpoint address; the addresses in a body's host header never count.
#[derive(Clone, Debug, PartialEq)]
pub struct StoredDetectionEvent {
    pub(super) event: DetectionEvent,
    pub(super) stamp: DetectionEventStamp,
    /// One code per endpoint address, in [`endpoint_addresses`] order.
    pub(super) country_codes: Vec<[u8; 2]>,
}

impl StoredDetectionEvent {
    /// Returns the detection event.
    #[must_use]
    pub fn event(&self) -> &DetectionEvent {
        &self.event
    }

    /// Returns the stamp recorded with the event.
    #[must_use]
    pub fn stamp(&self) -> &DetectionEventStamp {
        &self.stamp
    }

    /// Returns each endpoint address with the country code stored for it.
    ///
    /// A host subject's IP, or an endpoint subject's `ips` in their order,
    /// comes first, then the related IPs in their order; for a raw event
    /// body, `orig_addr` comes before `resp_addr`.
    pub fn country_codes(&self) -> impl Iterator<Item = (IpAddr, [u8; 2])> + '_ {
        endpoint_addresses(&self.event).zip(self.country_codes.iter().copied())
    }

    /// Returns the detection event and the stamp, consuming the record.
    #[must_use]
    pub fn into_parts(self) -> (DetectionEvent, DetectionEventStamp) {
        (self.event, self.stamp)
    }

    /// Returns the event's category as the crate's [`EventCategory`].
    pub(super) fn category(&self) -> Option<EventCategory> {
        self.event.category.map(EventCategory::from)
    }

    /// Returns the originator-side endpoint addresses: a body's `orig_addr`,
    /// or a subject's host addresses and its related IPs observed as the
    /// source.
    pub(super) fn originator_addrs(&self) -> impl Iterator<Item = IpAddr> + '_ {
        side_addrs(&self.event, EndpointRole::Source)
    }

    /// Returns the responder-side endpoint addresses: a body's `resp_addr`,
    /// or a subject's host addresses and its related IPs observed as the
    /// destination.
    pub(super) fn responder_addrs(&self) -> impl Iterator<Item = IpAddr> + '_ {
        side_addrs(&self.event, EndpointRole::Destination)
    }

    /// Returns the `ips` and the related IPs of an endpoint subject, or
    /// `None` when the event is not about an endpoint.
    pub(super) fn endpoint_subject(&self) -> Option<(&[IpAddr], &[RelatedIp])> {
        match &self.event.target {
            Target::Subject {
                primary: PrimarySubject::Endpoint { ips, .. },
                related_ips,
                ..
            } => Some((ips, related_ips)),
            _ => None,
        }
    }

    /// Returns the stored country codes of the endpoint addresses.
    pub(super) fn stored_country_codes(&self) -> &[[u8; 2]] {
        &self.country_codes
    }

    /// Returns whether the record is about `raw_event`.
    pub(super) fn is_about_raw_event(&self, raw_event: &RawEventKey) -> bool {
        let event = &self.event;
        event.time == raw_event.time
            && event.raw_event_kind == raw_event.raw_event_kind
            && event.sensor.as_deref() == Some(raw_event.sensor.as_str())
            && matches!(&event.target, Target::RawEvent { time, .. } if *time == raw_event.time)
    }
}

/// Returns the `orig_addr` and `resp_addr` of a body that has both fields.
///
/// The match has no wildcard, so a body added to review-protocol must be
/// placed here.
pub(super) fn body_endpoints(body: &RawEventBody) -> Option<(IpAddr, IpAddr)> {
    match body {
        RawEventBody::Conn(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Dns(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Http(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Rdp(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Smtp(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Ntlm(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Kerberos(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Ssh(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::DceRpc(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Ftp(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Mqtt(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Ldap(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Tls(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Smb(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Nfs(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Bootp(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Dhcp(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Radius(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::MalformedDns(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Icmp(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::Netflow9(b) => Some((b.orig_addr, b.resp_addr)),
        RawEventBody::ProcessCreate(_)
        | RawEventBody::FileCreateTime(_)
        | RawEventBody::NetworkConnect(_)
        | RawEventBody::ProcessTerminate(_)
        | RawEventBody::ImageLoad(_)
        | RawEventBody::FileCreate(_)
        | RawEventBody::RegistryValueSet(_)
        | RawEventBody::RegistryKeyRename(_)
        | RawEventBody::FileCreateStreamHash(_)
        | RawEventBody::PipeEvent(_)
        | RawEventBody::DnsQuery(_)
        | RawEventBody::FileDelete(_)
        | RawEventBody::ProcessTamper(_)
        | RawEventBody::FileDeleteDetected(_)
        | RawEventBody::Netflow5(_)
        | RawEventBody::DriverLoad(_)
        | RawEventBody::CreateRemoteThread(_)
        | RawEventBody::RawAccessRead(_)
        | RawEventBody::ProcessAccess(_)
        | RawEventBody::RegistryObjectAddDel(_)
        | RawEventBody::WindowsEventLog(_)
        | RawEventBody::Journald(_)
        | RawEventBody::Auditd(_) => None,
    }
}

/// Returns the host addresses of a primary subject: the IP of a host, every
/// element of the `ips` of an endpoint in their order, and none for any
/// other subject.
///
/// An endpoint's `default_route_ip` is not added: it is expected to be one
/// of its `ips`, and one that is not is no host address.
fn host_ip(primary: &PrimarySubject) -> &[IpAddr] {
    match primary {
        PrimarySubject::Host { ip, .. } => std::slice::from_ref(ip),
        PrimarySubject::Endpoint { ips, .. } => ips,
        PrimarySubject::Cluster { .. }
        | PrimarySubject::Sensor
        | PrimarySubject::Network { .. } => &[],
    }
}

/// Returns the endpoint addresses of `event`, in the order their country
/// codes are stored.
fn endpoint_addresses(event: &DetectionEvent) -> impl Iterator<Item = IpAddr> + '_ {
    let (body, host, related): (Option<(IpAddr, IpAddr)>, &[IpAddr], &[RelatedIp]) =
        match &event.target {
            Target::RawEvent { body, .. } => (body_endpoints(body), &[], &[]),
            Target::Subject {
                primary,
                related_ips,
                ..
            } => (None, host_ip(primary), related_ips),
        };
    body.into_iter()
        .flat_map(|(orig, resp)| [orig, resp])
        .chain(host.iter().copied())
        .chain(related.iter().map(|related| related.ip))
}

/// Returns the endpoint addresses of one side of `event`.
///
/// The host addresses of a subject are on both sides; a related IP is on
/// the side of its endpoint role.
fn side_addrs(event: &DetectionEvent, role: EndpointRole) -> impl Iterator<Item = IpAddr> + '_ {
    let (body, host, related): (Option<IpAddr>, &[IpAddr], &[RelatedIp]) = match &event.target {
        Target::RawEvent { body, .. } => (
            body_endpoints(body).map(|(orig, resp)| match role {
                EndpointRole::Source => orig,
                EndpointRole::Destination => resp,
            }),
            &[],
            &[],
        ),
        Target::Subject {
            primary,
            related_ips,
            ..
        } => (None, host_ip(primary), related_ips),
    };
    body.into_iter().chain(host.iter().copied()).chain(
        related
            .iter()
            .filter(move |related| related.role == role)
            .map(|related| related.ip),
    )
}

/// Returns the country code of each endpoint address of `event`, looked up
/// with `lookup`, or [`crate::COUNTRY_CODE_UNRESOLVED`] for every one
/// without a lookup.
pub(super) fn country_codes(
    event: &DetectionEvent,
    lookup: Option<&dyn CountryLookup>,
) -> Vec<[u8; 2]> {
    endpoint_addresses(event)
        .map(|addr| {
            lookup.map_or(crate::util::COUNTRY_CODE_UNRESOLVED, |lookup| {
                lookup.lookup_country_code(addr)
            })
        })
        .collect()
}

/// Returns `value`, with a negative zero replaced by a positive one.
fn positive_zero(value: f64) -> f64 {
    if value.to_bits() == NEGATIVE_ZERO_BITS {
        0.0
    } else {
        value
    }
}

/// Returns whether `value` is a negative zero.
fn is_negative_zero(value: f64) -> bool {
    value.to_bits() == NEGATIVE_ZERO_BITS
}

/// Returns `value`, with a negative zero replaced by a positive one.
fn positive_zero_f32(value: f32) -> f32 {
    if is_negative_zero_f32(value) {
        0.0
    } else {
        value
    }
}

/// Returns whether `value` is a negative zero.
fn is_negative_zero_f32(value: f32) -> bool {
    value.to_bits() == NEGATIVE_ZERO_BITS_F32
}

/// Returns `event` with every negative zero replaced by a positive one.
///
/// `-0.0` and `0.0` are equal values with different bytes; replacing one by
/// the other keeps equal events at equal bytes.
fn without_negative_zeros(event: &DetectionEvent) -> Cow<'_, DetectionEvent> {
    let detail_has_negative_zero = match &event.detail {
        Detail::UnusualDestinationPattern(detail) => {
            is_negative_zero(detail.expected_mean)
                || is_negative_zero(detail.std_deviation)
                || is_negative_zero(detail.z_score)
        }
        Detail::LabelDbMatch(detail) => {
            is_negative_zero_f32(detail.match_score)
                || detail.rule_confidence.is_some_and(is_negative_zero_f32)
        }
        Detail::WindowOutlier(detail) => {
            is_negative_zero(detail.distance)
                || detail.top_slots.iter().any(|slot| {
                    is_negative_zero(slot.value) || is_negative_zero(slot.centroid_value)
                })
        }
        _ => false,
    };
    if !is_negative_zero(event.score) && !detail_has_negative_zero {
        return Cow::Borrowed(event);
    }
    let mut event = event.clone();
    event.score = positive_zero(event.score);
    match &mut event.detail {
        Detail::UnusualDestinationPattern(detail) => {
            detail.expected_mean = positive_zero(detail.expected_mean);
            detail.std_deviation = positive_zero(detail.std_deviation);
            detail.z_score = positive_zero(detail.z_score);
        }
        Detail::LabelDbMatch(detail) => {
            detail.match_score = positive_zero_f32(detail.match_score);
            detail.rule_confidence = detail.rule_confidence.map(positive_zero_f32);
        }
        Detail::WindowOutlier(detail) => {
            detail.distance = positive_zero(detail.distance);
            for slot in &mut detail.top_slots {
                slot.value = positive_zero(slot.value);
                slot.centroid_value = positive_zero(slot.centroid_value);
            }
        }
        _ => {}
    }
    Cow::Owned(event)
}

/// Serializes `event` deterministically: equal events give equal bytes.
pub(super) fn encode_event(event: &DetectionEvent) -> Result<Vec<u8>> {
    bincode::serialize(without_negative_zeros(event).as_ref())
        .context("failed to serialize detection event")
}

/// The stored value of a record, as written.
#[derive(Serialize)]
struct RecordOut<'a> {
    #[serde(with = "serde_bytes")]
    event: &'a [u8],
    stamp: &'a DetectionEventStamp,
    country_codes: &'a [[u8; 2]],
}

/// The stored value of a record, as read, with the event still serialized.
#[derive(Deserialize)]
struct RecordIn<'a> {
    #[serde(borrow, with = "serde_bytes")]
    event: &'a [u8],
    stamp: DetectionEventStamp,
    country_codes: Vec<[u8; 2]>,
}

/// Serializes a record from the serialized event, its stamp and its country
/// codes.
pub(super) fn encode_record(
    event: &[u8],
    stamp: &DetectionEventStamp,
    country_codes: &[[u8; 2]],
) -> Result<Vec<u8>> {
    bincode::serialize(&RecordOut {
        event,
        stamp,
        country_codes,
    })
    .context("failed to serialize event record")
}

/// Decodes a stored record.
pub(super) fn decode_record(value: &[u8]) -> Result<StoredDetectionEvent> {
    let record: RecordIn = bincode::deserialize(value).context("invalid event record")?;
    let event: DetectionEvent =
        bincode::deserialize(record.event).context("invalid detection event")?;
    let addresses = endpoint_addresses(&event).count();
    if addresses != record.country_codes.len() {
        bail!(
            "{} country codes stored for {addresses} endpoint addresses",
            record.country_codes.len()
        );
    }
    Ok(StoredDetectionEvent {
        event,
        stamp: record.stamp,
        country_codes: record.country_codes,
    })
}

/// Returns whether the stored record `value` holds the event serialized as
/// `event` with the same engine instance and clustering model as `stamp`.
///
/// A record that cannot be decoded holds no event.
pub(super) fn is_same_event(value: &[u8], event: &[u8], stamp: &DetectionEventStamp) -> bool {
    bincode::deserialize::<RecordIn>(value).is_ok_and(|stored| {
        stored.event == event
            && stored.stamp.engine_instance == stamp.engine_instance
            && stored.stamp.clustering_model_id == stamp.clustering_model_id
    })
}
