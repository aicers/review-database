use std::{
    borrow::Cow,
    fmt::{self, Formatter, Write},
    net::IpAddr,
    num::NonZeroU8,
};

use anyhow::Result;
use attrievent::attribute::RawEventAttrKind;
use bincode::Options;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};

use super::{
    EventCategory, EventFilter, FlowKind, LearningMethod, TrafficDirection, eq_ip_country,
};
use crate::{AttrCmpKind, Confidence, PacketAttr, TriageExclusion, ValueKind};

/// Epsilon value for inclusive confidence comparisons
const CONFIDENCE_EPSILON: f32 = 1e-6;

// TODO: Make new Match trait to support Windows Events

pub(super) trait Match {
    fn src_addrs(&self) -> &[IpAddr];
    #[allow(dead_code)] // for future use
    fn src_port(&self) -> u16;
    fn dst_addrs(&self) -> &[IpAddr];
    #[allow(dead_code)] // for future use
    fn dst_port(&self) -> u16;
    #[allow(dead_code)] // for future use
    fn proto(&self) -> u8;
    fn category(&self) -> Option<EventCategory>;
    fn level(&self) -> NonZeroU8;
    fn kind(&self) -> &str;
    fn sensor(&self) -> &str;
    fn confidence(&self) -> Option<f32>;
    fn learning_method(&self) -> LearningMethod;
    fn find_attr_by_kind(&self, raw_event_attr: RawEventAttrKind) -> Option<AttrValue<'_>>;
    fn score_by_attr(&self, attr_triage: &[PacketAttr]) -> f64 {
        let total_score = attr_triage.iter().fold(0.0, |score_acc, item| {
            let Ok(kind) =
                RawEventAttrKind::from_kind_and_attr_name(&item.raw_event_kind, &item.attr_name)
            else {
                return score_acc;
            };

            let Some(value) = self.find_attr_by_kind(kind) else {
                return score_acc;
            };

            if is_attr_matched(value, item) {
                score_acc + item.weight.unwrap_or_default()
            } else {
                score_acc
            }
        });
        (total_score * 100.0).trunc() / 100.0
    }

    /// Returns whether the event matches the filter and the triage scores. The triage scores are
    /// only returned if the event matches the filter.
    ///
    /// # Errors
    ///
    /// Returns an error if the filter contains a country filter but the ip2location database is
    /// not available.
    fn matches(
        &self,
        locator: Option<&ip2location::DB>,
        filter: &EventFilter,
    ) -> Result<(bool, Option<Vec<TriageScore>>)> {
        if !self.kind_matches(filter) {
            return Ok((false, None));
        }
        self.other_matches(filter, locator)
    }

    fn kind_matches(&self, filter: &EventFilter) -> bool {
        if let Some(kinds) = &filter.kinds
            && kinds.iter().all(|k| k != self.kind())
        {
            return false;
        }

        true
    }

    /// Returns whether the event matches the filter (excluding `kinds`) and the triage scores. The
    /// triage scores are only returned if the event matches the filter.
    ///
    /// # Errors
    ///
    /// Returns an error if the filter contains a country filter but the ip2location database is
    /// not available.
    #[allow(clippy::too_many_lines)]
    fn other_matches(
        &self,
        filter: &EventFilter,
        locator: Option<&ip2location::DB>,
    ) -> Result<(bool, Option<Vec<TriageScore>>)> {
        if let Some(customers) = &filter.customers
            && customers.iter().all(|customer| {
                self.src_addrs()
                    .iter()
                    .all(|&src_addr| !customer.contains(src_addr))
                    && self
                        .dst_addrs()
                        .iter()
                        .all(|&dst_addr| !customer.contains(dst_addr))
            })
        {
            return Ok((false, None));
        }

        if let Some(endpoints) = &filter.endpoints
            && endpoints.iter().all(|endpoint| match endpoint.direction {
                Some(TrafficDirection::From) => self
                    .src_addrs()
                    .iter()
                    .all(|&src_addr| !endpoint.network.contains(src_addr)),
                Some(TrafficDirection::To) => self
                    .dst_addrs()
                    .iter()
                    .all(|&dst_addr| !endpoint.network.contains(dst_addr)),
                None => {
                    self.src_addrs()
                        .iter()
                        .all(|&src_addr| !endpoint.network.contains(src_addr))
                        && self
                            .dst_addrs()
                            .iter()
                            .all(|&dst_addr| !endpoint.network.contains(dst_addr))
                }
            })
        {
            return Ok((false, None));
        }

        if let Some(addr) = filter.source
            && self.src_addrs().iter().all(|&src_addr| src_addr != addr)
        {
            return Ok((false, None));
        }

        if let Some(addr) = filter.destination
            && self.dst_addrs().iter().all(|&dst_addr| dst_addr != addr)
        {
            return Ok((false, None));
        }

        if let Some((kinds, internal)) = &filter.directions {
            let internal_src = internal.iter().any(|net| {
                self.src_addrs()
                    .iter()
                    .any(|&src_addr| net.contains(src_addr))
            });
            let internal_dst = internal.iter().any(|net| {
                self.dst_addrs()
                    .iter()
                    .any(|&dst_addr| net.contains(dst_addr))
            });
            match (internal_src, internal_dst) {
                (true, true) => {
                    if !kinds.contains(&FlowKind::Internal) {
                        return Ok((false, None));
                    }
                }
                (true, false) => {
                    if !kinds.contains(&FlowKind::Outbound) {
                        return Ok((false, None));
                    }
                }
                (false, true) => {
                    if !kinds.contains(&FlowKind::Inbound) {
                        return Ok((false, None));
                    }
                }
                (false, false) => return Ok((false, None)),
            }
        }

        if let Some(countries) = &filter.countries {
            if let Some(locator) = locator {
                if countries.iter().all(|country| {
                    self.src_addrs()
                        .iter()
                        .all(|&src_addr| !eq_ip_country(locator, src_addr, *country))
                        && self
                            .dst_addrs()
                            .iter()
                            .all(|&dst_addr| !eq_ip_country(locator, dst_addr, *country))
                }) {
                    return Ok((false, None));
                }
            } else {
                return Ok((false, None));
            }
        }

        if let Some(categories) = &filter.categories
            && categories
                .iter()
                .all(|category| *category != self.category())
        {
            return Ok((false, None));
        }

        if let Some(levels) = &filter.levels
            && levels.iter().all(|level| *level != self.level())
        {
            return Ok((false, None));
        }

        if let Some(learning_methods) = &filter.learning_methods
            && learning_methods
                .iter()
                .all(|learning_method| *learning_method != self.learning_method())
        {
            return Ok((false, None));
        }

        if let Some(sensors) = &filter.sensors
            && sensors.iter().all(|s| s != self.sensor())
        {
            return Ok((false, None));
        }

        if let Some(event_confidence) = self.confidence() {
            if let Some(confidence_min) = filter.confidence_min
                && event_confidence < confidence_min - CONFIDENCE_EPSILON
            {
                return Ok((false, None));
            }
            if let Some(confidence_max) = filter.confidence_max
                && event_confidence > confidence_max + CONFIDENCE_EPSILON
            {
                return Ok((false, None));
            }
        }

        if let Some(triage_policies) = &filter.triage_policies
            && !triage_policies.is_empty()
        {
            let triage_scores = triage_policies
                .iter()
                .filter_map(|triage| {
                    let score = self.score_by_triage_exclusion(&triage.triage_exclusion)
                        + self.score_by_attr(&triage.packet_attr)
                        + self.score_by_confidence(&triage.confidence);
                    if triage.response.iter().any(|r| score >= r.minimum_score) {
                        Some(TriageScore {
                            policy_id: triage.id,
                            score,
                        })
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            if triage_scores.is_empty() {
                return Ok((false, None));
            }
            return Ok((true, Some(triage_scores)));
        }

        Ok((true, None))
    }

    fn score_by_triage_exclusion(&self, triage_exclusion: &[TriageExclusion]) -> f64 {
        let matched = triage_exclusion.iter().any(|ti| {
            if let TriageExclusion::IpAddress(filter) = ti {
                self.src_addrs().iter().any(|&addr| filter.contains(addr))
                    || self.dst_addrs().iter().any(|&addr| filter.contains(addr))
            } else {
                false
            }
        });
        if matched { f64::MIN } else { 0.0 }
    }

    fn score_by_confidence(&self, confidence: &[Confidence]) -> f64 {
        confidence.iter().fold(0.0, |score, conf| {
            if Some(conf.threat_category) == self.category()
                && conf.threat_kind.to_lowercase() == self.kind().to_lowercase()
                && self
                    .confidence()
                    .is_none_or(|c| c.to_f64().expect("safe: f32 -> f64") >= conf.confidence)
            {
                score + conf.weight.unwrap_or(1.0)
            } else {
                score
            }
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TriageScore {
    pub policy_id: u32,
    pub score: f64,
}

impl fmt::Display for TriageScore {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}:{:.2}", self.policy_id, self.score)
    }
}

pub fn triage_scores_to_string(v: Option<&Vec<TriageScore>>) -> String {
    if let Some(v) = v {
        v.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    } else {
        String::new()
    }
}

pub fn vector_to_string<T: ToString>(v: &[T]) -> String {
    if v.is_empty() {
        String::new()
    } else {
        v.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Converts a hardware address to a colon-separated string.
pub fn to_hardware_address(chaddr: &[u8]) -> String {
    let mut iter = chaddr.iter();
    let Some(first) = iter.next() else {
        return String::new();
    };
    iter.fold(
        {
            let mut addr = String::with_capacity(chaddr.len() * 3 - 1);
            let _ = write!(addr, "{first:02x}");
            addr
        },
        |mut addr, byte| {
            let _ = write!(addr, ":{byte:02x}");
            addr
        },
    )
}

pub enum AttrValue<'a> {
    Addr(IpAddr),
    Bool(bool),
    #[allow(dead_code)]
    Float(f64),
    SInt(i64),
    UInt(u64),
    String(&'a str),
    VecAddr(Cow<'a, [IpAddr]>),
    VecBool(Cow<'a, [bool]>),
    #[allow(dead_code)]
    VecFloat(Cow<'a, [f64]>),
    VecSInt(Cow<'a, [i64]>),
    VecUInt(Cow<'a, [u64]>),
    VecString(Cow<'a, [String]>),
    VecRaw(&'a [u8]),
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

fn is_attr_matched(target_value: AttrValue, attr: &PacketAttr) -> bool {
    match target_value {
        AttrValue::Addr(ip_addr) => matches_addr_attr(&ip_addr, attr),
        AttrValue::Bool(bool_val) => matches_bool_attr(bool_val, attr),
        AttrValue::Float(float_val) => matches_number_attr::<_, f64>(&float_val, attr),
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
        AttrValue::VecFloat(vec_float_val) => {
            is_matching_list(vec_float_val.as_ref(), attr, matches_number_attr::<_, f64>)
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
    use std::{
        cmp::Ordering,
        net::{IpAddr, Ipv4Addr},
    };

    use attrievent::attribute::{
        ConnAttr, DhcpAttr, DnsAttr, FtpAttr, HttpAttr, RadiusAttr, RawEventKind,
    };
    use bincode::Options;
    use chrono::{TimeZone, Utc};
    use serde::Serialize;

    use super::{AttrValue, Match, is_attr_matched};
    use crate::{
        AttrCmpKind, Customer, CustomerNetwork, EventCategory, HostNetworkGroup, PacketAttr,
        ValueKind,
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
            CryptocurrencyMiningPoolFields, DgaFields, DnsCovertChannel, DnsEventFields,
            DomainGenerationAlgorithm, Event, EventFilter, ExternalDdos, ExternalDdosFields,
            ExtraThreat, FlowKind, FtpBruteForce, FtpBruteForceFields, FtpEventFields,
            FtpPlainText, HttpEventFields, HttpThreat, HttpThreatFields, LdapBruteForce,
            LdapBruteForceFields, LdapEventFields, LdapPlainText, LearningMethod, LockyRansomware,
            MultiHostPortScan, MultiHostPortScanFields, NetworkThreat, NetworkType, NonBrowser,
            PortScan, PortScanFields, RdpBruteForce, RdpBruteForceFields, RecordType,
            RepeatedHttpSessions, RepeatedHttpSessionsFields, SuspiciousTlsTraffic, TorConnection,
            UnusualDestinationPattern, UnusualDestinationPatternFields, WindowsThreat,
        },
        types::Endpoint,
    };

    #[test]
    fn empty_byte_slice_to_colon_separated_string() {
        assert_eq!(super::to_hardware_address(&[]), "");
    }

    #[test]
    fn non_empty_byte_slice_to_colon_separated_string() {
        assert_eq!(
            super::to_hardware_address(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]),
            "12:34:56:78:9a:bc"
        );
    }

    #[test]
    fn learning_method_match_on_semi_supervised_events() {
        let time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap();
        let mut semi_supervised_events = Vec::new();

        let dns_event = Event::DnsCovertChannel(DnsCovertChannel::new(time, dns_event_fields()));
        semi_supervised_events.push(dns_event);

        let port_scan_event = Event::PortScan(PortScan::new(time, &port_scan_fields()));
        semi_supervised_events.push(port_scan_event);

        let multi_host_port_scan_event =
            Event::MultiHostPortScan(MultiHostPortScan::new(time, &multi_host_port_scan_fields()));
        semi_supervised_events.push(multi_host_port_scan_event);

        let external_ddos_event =
            Event::ExternalDdos(ExternalDdos::new(time, &external_ddos_fields()));
        semi_supervised_events.push(external_ddos_event);

        let locky_ransomware_event =
            Event::LockyRansomware(LockyRansomware::new(time, dns_event_fields()));
        semi_supervised_events.push(locky_ransomware_event);

        let crypto_mining_pool_event = Event::CryptocurrencyMiningPool(
            CryptocurrencyMiningPool::new(time, crypto_miining_pool_fields()),
        );
        semi_supervised_events.push(crypto_mining_pool_event);

        let ftp_brute_force_event =
            Event::FtpBruteForce(FtpBruteForce::new(time, &ftp_brute_force_fields()));
        semi_supervised_events.push(ftp_brute_force_event);

        let ftp_plain_text_event = Event::FtpPlainText(FtpPlainText::new(time, ftp_event_fields()));
        semi_supervised_events.push(ftp_plain_text_event);

        let repeated_http_sessions_event = Event::RepeatedHttpSessions(RepeatedHttpSessions::new(
            time,
            &repeated_http_sessions_fiedls(),
        ));
        semi_supervised_events.push(repeated_http_sessions_event);

        let dga_event =
            Event::DomainGenerationAlgorithm(DomainGenerationAlgorithm::new(time, dga_fields()));
        semi_supervised_events.push(dga_event);

        let non_browser_event = Event::NonBrowser(NonBrowser::new(time, &http_event_fields()));
        semi_supervised_events.push(non_browser_event);

        let ldap_brute_force_event =
            Event::LdapBruteForce(LdapBruteForce::new(time, &ldap_brute_force_fields()));
        semi_supervised_events.push(ldap_brute_force_event);

        let ldap_plain_text_event =
            Event::LdapPlainText(LdapPlainText::new(time, ldap_event_fields()));
        semi_supervised_events.push(ldap_plain_text_event);

        let rdp_brute_force_event =
            Event::RdpBruteForce(RdpBruteForce::new(time, &rdp_brute_force_fields()));
        semi_supervised_events.push(rdp_brute_force_event);

        let suspicious_tls_traffic_event =
            Event::SuspiciousTlsTraffic(SuspiciousTlsTraffic::new(time, blocklist_tls_fields()));
        semi_supervised_events.push(suspicious_tls_traffic_event);

        let tor_connection_event =
            Event::TorConnection(TorConnection::new(time, &http_event_fields()));
        semi_supervised_events.push(tor_connection_event);

        let blocklist_bootp_event = Event::Blocklist(RecordType::Bootp(BlocklistBootp::new(
            time,
            blocklist_bootp_fields(),
        )));
        semi_supervised_events.push(blocklist_bootp_event);

        let blocklist_conn_event = Event::Blocklist(RecordType::Conn(BlocklistConn::new(
            time,
            blocklist_conn_fields(),
        )));
        semi_supervised_events.push(blocklist_conn_event);

        let blocklist_dcerpc_event = Event::Blocklist(RecordType::DceRpc(BlocklistDceRpc::new(
            time,
            blocklist_dcerpc_fields(),
        )));
        semi_supervised_events.push(blocklist_dcerpc_event);

        let blocklist_dhcp_event = Event::Blocklist(RecordType::Dhcp(BlocklistDhcp::new(
            time,
            blocklist_dhcp_fields(),
        )));
        semi_supervised_events.push(blocklist_dhcp_event);

        let blocklist_dns_event = Event::Blocklist(RecordType::Dns(BlocklistDns::new(
            time,
            blocklist_dns_fields(),
        )));
        semi_supervised_events.push(blocklist_dns_event);

        let blocklist_ftp_event =
            Event::Blocklist(RecordType::Ftp(BlocklistFtp::new(time, ftp_event_fields())));
        semi_supervised_events.push(blocklist_ftp_event);

        let blocklist_http_event = Event::Blocklist(RecordType::Http(BlocklistHttp::new(
            time,
            blocklist_http_fields(),
        )));
        semi_supervised_events.push(blocklist_http_event);

        let blocklist_kerberos_event = Event::Blocklist(RecordType::Kerberos(
            BlocklistKerberos::new(time, blocklist_kerberos_fields()),
        ));
        semi_supervised_events.push(blocklist_kerberos_event);

        let blocklist_ldap_event = Event::Blocklist(RecordType::Ldap(BlocklistLdap::new(
            time,
            ldap_event_fields(),
        )));
        semi_supervised_events.push(blocklist_ldap_event);

        let blocklist_mqtt_event = Event::Blocklist(RecordType::Mqtt(BlocklistMqtt::new(
            time,
            blocklist_mqtt_fields(),
        )));
        semi_supervised_events.push(blocklist_mqtt_event);

        let blocklist_nfs_event = Event::Blocklist(RecordType::Nfs(BlocklistNfs::new(
            time,
            blocklist_nfs_fields(),
        )));
        semi_supervised_events.push(blocklist_nfs_event);

        let blocklist_ntlm_event = Event::Blocklist(RecordType::Ntlm(BlocklistNtlm::new(
            time,
            blocklist_ntlm_fields(),
        )));
        semi_supervised_events.push(blocklist_ntlm_event);

        let blocklist_rdp_event = Event::Blocklist(RecordType::Rdp(BlocklistRdp::new(
            time,
            blocklist_rdp_fields(),
        )));
        semi_supervised_events.push(blocklist_rdp_event);

        let blocklist_smb_event = Event::Blocklist(RecordType::Smb(BlocklistSmb::new(
            time,
            blocklist_smb_fields(),
        )));
        semi_supervised_events.push(blocklist_smb_event);

        let blocklist_smtp_event = Event::Blocklist(RecordType::Smtp(BlocklistSmtp::new(
            time,
            blocklist_smtp_fields(),
        )));
        semi_supervised_events.push(blocklist_smtp_event);

        let blocklist_ssh_event = Event::Blocklist(RecordType::Ssh(BlocklistSsh::new(
            time,
            blocklist_ssh_fields(),
        )));
        semi_supervised_events.push(blocklist_ssh_event);

        let blocklist_tls_event = Event::Blocklist(RecordType::Tls(BlocklistTls::new(
            time,
            blocklist_tls_fields(),
        )));
        semi_supervised_events.push(blocklist_tls_event);

        let mut filter = event_filter();

        // Semi-supervised engine-generated event filtering
        filter.learning_methods = Some(vec![LearningMethod::SemiSupervised]);
        assert!(
            semi_supervised_events
                .iter()
                .all(|event| event.matches(None, &filter).unwrap().0)
        );

        // Unsupervised engine-generated event filtering
        filter.learning_methods = Some(vec![LearningMethod::Unsupervised]);
        assert!(
            semi_supervised_events
                .iter()
                .all(|event| !event.matches(None, &filter).unwrap().0)
        );

        // All event filtering
        filter.learning_methods = Some(vec![
            LearningMethod::SemiSupervised,
            LearningMethod::Unsupervised,
        ]);
        assert!(
            semi_supervised_events
                .iter()
                .all(|event| event.matches(None, &filter).unwrap().0)
        );
    }

    #[test]
    fn learning_method_match_on_unsupervised_events() {
        let mut unsupervised_events = Vec::new();

        let http_threat_event = Event::HttpThreat(HttpThreat::new(
            Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            http_threat_fields(),
        ));
        unsupervised_events.push(http_threat_event);

        let extra_threat_event = Event::ExtraThreat(extra_threat());
        unsupervised_events.push(extra_threat_event);

        let network_threat_event = Event::NetworkThreat(network_threat());
        unsupervised_events.push(network_threat_event);

        let windows_threat_event = Event::WindowsThreat(windows_threat());
        unsupervised_events.push(windows_threat_event);

        let mut filter = event_filter();

        // Semi-supervised engine-generated event filtering
        filter.learning_methods = Some(vec![LearningMethod::SemiSupervised]);
        assert!(
            unsupervised_events
                .iter()
                .all(|event| !event.matches(None, &filter).unwrap().0)
        );

        // Unsupervised engine-generated event filtering
        filter.learning_methods = Some(vec![LearningMethod::Unsupervised]);
        assert!(
            unsupervised_events
                .iter()
                .all(|event| event.matches(None, &filter).unwrap().0)
        );

        // All event filtering
        filter.learning_methods = Some(vec![
            LearningMethod::SemiSupervised,
            LearningMethod::Unsupervised,
        ]);
        assert!(
            unsupervised_events
                .iter()
                .all(|event| event.matches(None, &filter).unwrap().0)
        );
    }

    #[test]
    fn filter_events_by_address() {
        let time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap();
        let mut single_address_events = Vec::new();

        let dns_event = Event::DnsCovertChannel(DnsCovertChannel::new(time, dns_event_fields()));
        single_address_events.push(dns_event);

        let port_scan_event = Event::PortScan(PortScan::new(time, &port_scan_fields()));
        single_address_events.push(port_scan_event);

        let locky_ransomware_event =
            Event::LockyRansomware(LockyRansomware::new(time, dns_event_fields()));
        single_address_events.push(locky_ransomware_event);

        let crypto_mining_pool_event = Event::CryptocurrencyMiningPool(
            CryptocurrencyMiningPool::new(time, crypto_miining_pool_fields()),
        );
        single_address_events.push(crypto_mining_pool_event);

        let ftp_brute_force_event =
            Event::FtpBruteForce(FtpBruteForce::new(time, &ftp_brute_force_fields()));
        single_address_events.push(ftp_brute_force_event);

        let ftp_plain_text_event = Event::FtpPlainText(FtpPlainText::new(time, ftp_event_fields()));
        single_address_events.push(ftp_plain_text_event);

        let repeated_http_sessions_event = Event::RepeatedHttpSessions(RepeatedHttpSessions::new(
            time,
            &repeated_http_sessions_fiedls(),
        ));
        single_address_events.push(repeated_http_sessions_event);

        let dga_event =
            Event::DomainGenerationAlgorithm(DomainGenerationAlgorithm::new(time, dga_fields()));
        single_address_events.push(dga_event);

        let non_browser_event = Event::NonBrowser(NonBrowser::new(time, &http_event_fields()));
        single_address_events.push(non_browser_event);

        let ldap_brute_force_event =
            Event::LdapBruteForce(LdapBruteForce::new(time, &ldap_brute_force_fields()));
        single_address_events.push(ldap_brute_force_event);

        let ldap_plain_text_event =
            Event::LdapPlainText(LdapPlainText::new(time, ldap_event_fields()));
        single_address_events.push(ldap_plain_text_event);

        let suspicious_tls_traffic_event =
            Event::SuspiciousTlsTraffic(SuspiciousTlsTraffic::new(time, blocklist_tls_fields()));
        single_address_events.push(suspicious_tls_traffic_event);

        let tor_connection_event =
            Event::TorConnection(TorConnection::new(time, &http_event_fields()));
        single_address_events.push(tor_connection_event);

        let blocklist_bootp_event = Event::Blocklist(RecordType::Bootp(BlocklistBootp::new(
            time,
            blocklist_bootp_fields(),
        )));
        single_address_events.push(blocklist_bootp_event);

        let blocklist_conn_event = Event::Blocklist(RecordType::Conn(BlocklistConn::new(
            time,
            blocklist_conn_fields(),
        )));
        single_address_events.push(blocklist_conn_event);

        let blocklist_dcerpc_event = Event::Blocklist(RecordType::DceRpc(BlocklistDceRpc::new(
            time,
            blocklist_dcerpc_fields(),
        )));
        single_address_events.push(blocklist_dcerpc_event);

        let blocklist_dhcp_event = Event::Blocklist(RecordType::Dhcp(BlocklistDhcp::new(
            time,
            blocklist_dhcp_fields(),
        )));
        single_address_events.push(blocklist_dhcp_event);

        let blocklist_dns_event = Event::Blocklist(RecordType::Dns(BlocklistDns::new(
            time,
            blocklist_dns_fields(),
        )));
        single_address_events.push(blocklist_dns_event);

        let blocklist_ftp_event =
            Event::Blocklist(RecordType::Ftp(BlocklistFtp::new(time, ftp_event_fields())));
        single_address_events.push(blocklist_ftp_event);

        let blocklist_http_event = Event::Blocklist(RecordType::Http(BlocklistHttp::new(
            time,
            blocklist_http_fields(),
        )));
        single_address_events.push(blocklist_http_event);

        let blocklist_kerberos_event = Event::Blocklist(RecordType::Kerberos(
            BlocklistKerberos::new(time, blocklist_kerberos_fields()),
        ));
        single_address_events.push(blocklist_kerberos_event);

        let blocklist_ldap_event = Event::Blocklist(RecordType::Ldap(BlocklistLdap::new(
            time,
            ldap_event_fields(),
        )));
        single_address_events.push(blocklist_ldap_event);

        let blocklist_mqtt_event = Event::Blocklist(RecordType::Mqtt(BlocklistMqtt::new(
            time,
            blocklist_mqtt_fields(),
        )));
        single_address_events.push(blocklist_mqtt_event);

        let blocklist_nfs_event = Event::Blocklist(RecordType::Nfs(BlocklistNfs::new(
            time,
            blocklist_nfs_fields(),
        )));
        single_address_events.push(blocklist_nfs_event);

        let blocklist_ntlm_event = Event::Blocklist(RecordType::Ntlm(BlocklistNtlm::new(
            time,
            blocklist_ntlm_fields(),
        )));
        single_address_events.push(blocklist_ntlm_event);

        let blocklist_rdp_event = Event::Blocklist(RecordType::Rdp(BlocklistRdp::new(
            time,
            blocklist_rdp_fields(),
        )));
        single_address_events.push(blocklist_rdp_event);

        let blocklist_smb_event = Event::Blocklist(RecordType::Smb(BlocklistSmb::new(
            time,
            blocklist_smb_fields(),
        )));
        single_address_events.push(blocklist_smb_event);

        let blocklist_smtp_event = Event::Blocklist(RecordType::Smtp(BlocklistSmtp::new(
            time,
            blocklist_smtp_fields(),
        )));
        single_address_events.push(blocklist_smtp_event);

        let blocklist_ssh_event = Event::Blocklist(RecordType::Ssh(BlocklistSsh::new(
            time,
            blocklist_ssh_fields(),
        )));
        single_address_events.push(blocklist_ssh_event);

        let blocklist_tls_event = Event::Blocklist(RecordType::Tls(BlocklistTls::new(
            time,
            blocklist_tls_fields(),
        )));
        single_address_events.push(blocklist_tls_event);

        let http_threat_event = Event::HttpThreat(HttpThreat::new(time, http_threat_fields()));
        single_address_events.push(http_threat_event);

        let network_threat_event = Event::NetworkThreat(network_threat());
        single_address_events.push(network_threat_event);

        // Filtering success.
        let mut success_filter = event_filter();
        let src_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let dst_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        success_filter.customers = Some(vec![create_customer(src_addr)]);
        success_filter.endpoints = Some(vec![create_endpoint(src_addr)]);
        success_filter.source = Some(src_addr);
        success_filter.destination = Some(dst_addr);
        success_filter.directions = Some(create_directions(FlowKind::Outbound, src_addr));

        assert!(
            single_address_events
                .iter()
                .all(|event| event.matches(None, &success_filter).unwrap().0)
        );

        // Filtering fail.
        let fail_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10));

        let mut fail_filter = event_filter();
        fail_filter.customers = Some(vec![create_customer(fail_addr)]);
        assert!(
            single_address_events
                .iter()
                .all(|event| !event.matches(None, &fail_filter).unwrap().0)
        );

        let mut fail_filter = event_filter();
        fail_filter.endpoints = Some(vec![create_endpoint(fail_addr)]);
        assert!(
            single_address_events
                .iter()
                .all(|event| !event.matches(None, &fail_filter).unwrap().0)
        );

        let mut fail_filter = event_filter();
        fail_filter.source = Some(fail_addr);
        assert!(
            single_address_events
                .iter()
                .all(|event| !event.matches(None, &fail_filter).unwrap().0)
        );

        let mut fail_filter = event_filter();
        fail_filter.destination = Some(fail_addr);
        assert!(
            single_address_events
                .iter()
                .all(|event| !event.matches(None, &fail_filter).unwrap().0)
        );

        let mut fail_filter = event_filter();
        fail_filter.directions = Some(create_directions(FlowKind::Outbound, fail_addr));
        assert!(
            single_address_events
                .iter()
                .all(|event| !event.matches(None, &fail_filter).unwrap().0)
        );

        let mut multi_address_events = Vec::new();

        let multi_host_port_scan_event =
            Event::MultiHostPortScan(MultiHostPortScan::new(time, &multi_host_port_scan_fields()));
        multi_address_events.push(multi_host_port_scan_event);

        let external_ddos_event =
            Event::ExternalDdos(ExternalDdos::new(time, &external_ddos_fields()));
        multi_address_events.push(external_ddos_event);

        let rdp_brute_force_event =
            Event::RdpBruteForce(RdpBruteForce::new(time, &rdp_brute_force_fields()));
        multi_address_events.push(rdp_brute_force_event);

        // Filtering success.
        let mut success_filter = event_filter();
        let src_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let dst_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        success_filter.customers = Some(vec![create_customer(src_addr)]);
        success_filter.endpoints = Some(vec![create_endpoint(src_addr)]);
        success_filter.source = Some(src_addr);
        success_filter.destination = Some(dst_addr);
        success_filter.directions = Some(create_directions(FlowKind::Outbound, src_addr));

        assert!(
            multi_address_events
                .iter()
                .all(|event| event.matches(None, &success_filter).unwrap().0)
        );

        // Filtering fail.
        let fail_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10));

        let mut fail_filter = event_filter();
        fail_filter.customers = Some(vec![create_customer(fail_addr)]);
        assert!(
            multi_address_events
                .iter()
                .all(|event| !event.matches(None, &fail_filter).unwrap().0)
        );

        let mut fail_filter = event_filter();
        fail_filter.endpoints = Some(vec![create_endpoint(fail_addr)]);
        assert!(
            multi_address_events
                .iter()
                .all(|event| !event.matches(None, &fail_filter).unwrap().0)
        );

        let mut fail_filter = event_filter();
        fail_filter.source = Some(fail_addr);
        assert!(
            multi_address_events
                .iter()
                .all(|event| !event.matches(None, &fail_filter).unwrap().0)
        );

        let mut fail_filter = event_filter();
        fail_filter.destination = Some(fail_addr);
        assert!(
            multi_address_events
                .iter()
                .all(|event| !event.matches(None, &fail_filter).unwrap().0)
        );

        let mut fail_filter = event_filter();
        fail_filter.directions = Some(create_directions(FlowKind::Outbound, fail_addr));
        assert!(
            multi_address_events
                .iter()
                .all(|event| !event.matches(None, &fail_filter).unwrap().0)
        );

        let mut no_address_events = Vec::new();

        let extra_threat_event = Event::ExtraThreat(extra_threat());
        no_address_events.push(extra_threat_event);

        let windows_threat_event = Event::WindowsThreat(windows_threat());
        no_address_events.push(windows_threat_event);

        // `ExtraThreat`, `WindowsThreat` always fails filtering by address.
        let fail_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10));

        let mut fail_filter = event_filter();
        fail_filter.customers = Some(vec![create_customer(fail_addr)]);
        assert!(
            no_address_events
                .iter()
                .all(|event| !event.matches(None, &fail_filter).unwrap().0)
        );

        let mut fail_filter = event_filter();
        fail_filter.endpoints = Some(vec![create_endpoint(fail_addr)]);
        assert!(
            no_address_events
                .iter()
                .all(|event| !event.matches(None, &fail_filter).unwrap().0)
        );

        let mut fail_filter = event_filter();
        fail_filter.source = Some(fail_addr);
        assert!(
            no_address_events
                .iter()
                .all(|event| !event.matches(None, &fail_filter).unwrap().0)
        );

        let mut fail_filter = event_filter();
        fail_filter.destination = Some(fail_addr);
        assert!(
            no_address_events
                .iter()
                .all(|event| !event.matches(None, &fail_filter).unwrap().0)
        );

        let mut fail_filter = event_filter();
        fail_filter.directions = Some(create_directions(FlowKind::Outbound, fail_addr));
        assert!(
            no_address_events
                .iter()
                .all(|event| !event.matches(None, &fail_filter).unwrap().0)
        );
    }

    #[test]
    fn compare_attribute() {
        let time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap();

        // Compare `Addr`, `String`, `UInt`, `VecString` type
        let http_event = DomainGenerationAlgorithm::new(time, dga_fields());
        let success_packet_attr = vec![
            PacketAttr {
                raw_event_kind: RawEventKind::Http,
                attr_name: HttpAttr::SrcAddr.to_string(),
                value_kind: ValueKind::IpAddr,
                cmp_kind: AttrCmpKind::CloseRange,
                first_value: serialize(&IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap(),
                second_value: serialize(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
                weight: Some(0.1),
            },
            PacketAttr {
                raw_event_kind: RawEventKind::Http,
                attr_name: HttpAttr::Uri.to_string(),
                value_kind: ValueKind::String,
                cmp_kind: AttrCmpKind::Contain,
                first_value: serialize(&"path").unwrap(),
                second_value: None,
                weight: Some(0.2),
            },
        ];
        let score_result = http_event.score_by_attr(&success_packet_attr);
        assert_eq!(score_result.partial_cmp(&0.3), Some(Ordering::Equal));

        let fail_packet_attr = vec![
            PacketAttr {
                raw_event_kind: RawEventKind::Http,
                attr_name: HttpAttr::DstPort.to_string(),
                value_kind: ValueKind::UInteger,
                cmp_kind: AttrCmpKind::OpenRange,
                first_value: serialize(&80_u64).unwrap(),
                second_value: serialize(&82_u64),
                weight: Some(0.1),
            },
            PacketAttr {
                raw_event_kind: RawEventKind::Http,
                attr_name: HttpAttr::MimeTypes.to_string(),
                value_kind: ValueKind::String,
                cmp_kind: AttrCmpKind::NotContain,
                first_value: serialize(&"b1").unwrap(),
                second_value: None,
                weight: Some(0.1),
            },
        ];
        let score_result = http_event.score_by_attr(&fail_packet_attr);
        assert_eq!(score_result.partial_cmp(&0.0), Some(Ordering::Equal));

        // Compare `Bool`, `SInt`, `VecSInt` type
        let dns_event = DnsCovertChannel::new(time, dns_event_fields());
        let success_packet_attr = vec![
            PacketAttr {
                raw_event_kind: RawEventKind::Dns,
                attr_name: DnsAttr::Rtt.to_string(),
                value_kind: ValueKind::Integer,
                cmp_kind: AttrCmpKind::Less,
                first_value: serialize(&6_i64).unwrap(),
                second_value: None,
                weight: Some(0.3),
            },
            PacketAttr {
                raw_event_kind: RawEventKind::Dns,
                attr_name: DnsAttr::Ttl.to_string(),
                value_kind: ValueKind::Integer,
                cmp_kind: AttrCmpKind::NotEqual,
                first_value: serialize(&9_i64).unwrap(),
                second_value: None,
                weight: Some(0.5),
            },
        ];
        let score_result = dns_event.score_by_attr(&success_packet_attr);
        assert_eq!(score_result.partial_cmp(&0.8), Some(Ordering::Equal));

        let fail_packet_attr = vec![PacketAttr {
            raw_event_kind: RawEventKind::Dns,
            attr_name: DnsAttr::AA.to_string(),
            value_kind: ValueKind::Bool,
            cmp_kind: AttrCmpKind::Equal,
            first_value: serialize(&true).unwrap(),
            second_value: None,
            weight: Some(0.2),
        }];
        let score_result = dns_event.score_by_attr(&fail_packet_attr);
        assert_eq!(score_result.partial_cmp(&0.0), Some(Ordering::Equal));

        // Compare `VecAddr`, `VecUInt`, `VecRaw` type
        let dhcp_event = BlocklistDhcp::new(time, blocklist_dhcp_fields());
        let success_packet_attr = vec![
            PacketAttr {
                raw_event_kind: RawEventKind::Dhcp,
                attr_name: DhcpAttr::Router.to_string(),
                value_kind: ValueKind::IpAddr,
                cmp_kind: AttrCmpKind::LeftOpenRange,
                first_value: serialize(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0))).unwrap(),
                second_value: serialize(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
                weight: Some(0.15),
            },
            PacketAttr {
                raw_event_kind: RawEventKind::Dhcp,
                attr_name: DhcpAttr::ClientId.to_string(),
                value_kind: ValueKind::Vector,
                cmp_kind: AttrCmpKind::Contain,
                first_value: vec![7, 8, 9],
                second_value: None,
                weight: Some(0.2),
            },
        ];
        let score_result = dhcp_event.score_by_attr(&success_packet_attr);
        assert_eq!(score_result.partial_cmp(&0.35), Some(Ordering::Equal));

        let fail_packet_attr = vec![PacketAttr {
            raw_event_kind: RawEventKind::Dhcp,
            attr_name: DhcpAttr::ParamReqList.to_string(),
            value_kind: ValueKind::UInteger,
            cmp_kind: AttrCmpKind::RightOpenRange,
            first_value: serialize(&0_u64).unwrap(),
            second_value: serialize(&1_u64),
            weight: Some(0.35),
        }];
        let score_result = dhcp_event.score_by_attr(&fail_packet_attr);
        assert_eq!(score_result.partial_cmp(&0.0), Some(Ordering::Equal));

        // Compare `VecBool` type for FtpAttr::DataPassive
        let ftp_passive_event = FtpPlainText::new(time, {
            use crate::event::ftp::FtpCommand;
            let commands = vec![
                FtpCommand {
                    command: "USER".to_string(),
                    reply_code: "331".to_string(),
                    reply_msg: "Username okay, need password.".to_string(),
                    data_passive: true, // This will be true
                    data_orig_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
                    data_resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)),
                    data_resp_port: 10001,
                    file: String::new(),
                    file_size: 0,
                    file_id: String::new(),
                },
                FtpCommand {
                    command: "PASS".to_string(),
                    reply_code: "230".to_string(),
                    reply_msg: "User logged in, proceed.".to_string(),
                    data_passive: false, // This will be false
                    data_orig_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
                    data_resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)),
                    data_resp_port: 10001,
                    file: String::new(),
                    file_id: String::new(),
                    file_size: 0,
                },
                FtpCommand {
                    command: "LIST".to_string(),
                    reply_code: "150".to_string(),
                    reply_msg: "Opening ASCII mode data connection for file list".to_string(),
                    data_passive: true, // This will be true
                    data_orig_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
                    data_resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)),
                    data_resp_port: 10001,
                    file: "list.txt".to_string(),
                    file_size: 100,
                    file_id: "xyz".to_string(),
                },
            ];

            let mut fields = ftp_event_fields();
            fields.commands = commands;
            fields
        });

        // For Vec<Bool>, AttrCmpKind::Equal means score if at least one 'true' is found.
        let success_packet_attr_vec_bool_true = vec![PacketAttr {
            raw_event_kind: RawEventKind::Ftp,
            attr_name: FtpAttr::DataPassive.to_string(),
            value_kind: ValueKind::Bool,
            cmp_kind: AttrCmpKind::Equal,
            first_value: serialize(&true).unwrap(),
            second_value: None,
            weight: Some(0.6),
        }];
        let score_result_true = ftp_passive_event.score_by_attr(&success_packet_attr_vec_bool_true);
        assert_eq!(score_result_true.partial_cmp(&0.6), Some(Ordering::Equal));

        // For Vec<Bool>, AttrCmpKind::Equal means score if at least one 'false' is found.
        let success_packet_attr_vec_bool_false = vec![PacketAttr {
            raw_event_kind: RawEventKind::Ftp,
            attr_name: FtpAttr::DataPassive.to_string(),
            value_kind: ValueKind::Bool,
            cmp_kind: AttrCmpKind::Equal,
            first_value: serialize(&false).unwrap(),
            second_value: None,
            weight: Some(0.3),
        }];
        let score_result_false =
            ftp_passive_event.score_by_attr(&success_packet_attr_vec_bool_false);
        assert_eq!(score_result_false.partial_cmp(&0.3), Some(Ordering::Equal));

        // For Vec<Bool>, AttrCmpKind::NotEqual means score if NONE of the 'true' are found.
        let fail_packet_attr_vec_bool_not_true = vec![PacketAttr {
            raw_event_kind: RawEventKind::Ftp,
            attr_name: FtpAttr::DataPassive.to_string(),
            value_kind: ValueKind::Bool,
            cmp_kind: AttrCmpKind::NotEqual,
            first_value: serialize(&true).unwrap(),
            second_value: None,
            weight: Some(0.5),
        }];
        let score_result_not_true =
            ftp_passive_event.score_by_attr(&fail_packet_attr_vec_bool_not_true);
        assert_eq!(
            score_result_not_true.partial_cmp(&0.0),
            Some(Ordering::Equal)
        );
    }

    #[test]
    fn vec_attr_cow_matching() {
        // Borrowed VecString should match Contain/NotContain logic without allocation.
        let borrowed_strings = vec!["alpha".to_string(), "beta".to_string()];
        let contain_attr = PacketAttr {
            raw_event_kind: RawEventKind::Http,
            attr_name: "mime_types".to_string(),
            value_kind: ValueKind::String,
            cmp_kind: AttrCmpKind::Contain,
            first_value: serialize(&"beta").unwrap(),
            second_value: None,
            weight: None,
        };
        assert!(is_attr_matched(
            AttrValue::VecString(std::borrow::Cow::Borrowed(&borrowed_strings)),
            &contain_attr
        ));

        let not_contain_attr = PacketAttr {
            raw_event_kind: RawEventKind::Http,
            attr_name: "mime_types".to_string(),
            value_kind: ValueKind::String,
            cmp_kind: AttrCmpKind::NotContain,
            first_value: serialize(&"gamma").unwrap(),
            second_value: None,
            weight: None,
        };
        assert!(is_attr_matched(
            AttrValue::VecString(std::borrow::Cow::Borrowed(&borrowed_strings)),
            &not_contain_attr
        ));

        // Owned VecUInt should match numeric comparisons.
        let owned_ports = vec![100_u64, 200_u64];
        let equal_attr = PacketAttr {
            raw_event_kind: RawEventKind::Conn,
            attr_name: "dst_port".to_string(),
            value_kind: ValueKind::UInteger,
            cmp_kind: AttrCmpKind::Equal,
            first_value: serialize(&200_u64).unwrap(),
            second_value: None,
            weight: None,
        };
        assert!(is_attr_matched(
            AttrValue::VecUInt(std::borrow::Cow::Owned(owned_ports.clone())),
            &equal_attr
        ));

        let not_equal_attr = PacketAttr {
            raw_event_kind: RawEventKind::Conn,
            attr_name: "dst_port".to_string(),
            value_kind: ValueKind::UInteger,
            cmp_kind: AttrCmpKind::NotEqual,
            first_value: serialize(&300_u64).unwrap(),
            second_value: None,
            weight: None,
        };
        assert!(is_attr_matched(
            AttrValue::VecUInt(std::borrow::Cow::Owned(owned_ports)),
            &not_equal_attr
        ));
    }

    #[test]
    fn compare_attribute_new_protocols() {
        let time = Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap();

        // 1. Radius
        let radius_event = BlocklistRadius::new(time, blocklist_radius_fields());
        let radius_attr = vec![PacketAttr {
            raw_event_kind: RawEventKind::Radius,
            attr_name: RadiusAttr::NasIp.to_string(),
            value_kind: ValueKind::IpAddr,
            cmp_kind: AttrCmpKind::Equal,
            first_value: serialize(&IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap(),
            second_value: None,
            weight: Some(1.0),
        }];
        assert_eq!(
            radius_event.score_by_attr(&radius_attr).partial_cmp(&1.0),
            Some(Ordering::Equal)
        );

        // 2. Malformed DNS
        let malformed_dns_event =
            BlocklistMalformedDns::new(time, blocklist_malformed_dns_fields());
        let dns_attr = vec![PacketAttr {
            raw_event_kind: RawEventKind::Dns,
            attr_name: DnsAttr::TransId.to_string(),
            value_kind: ValueKind::UInteger,
            cmp_kind: AttrCmpKind::Equal,
            first_value: serialize(&12345_u64).unwrap(),
            second_value: None,
            weight: Some(1.0),
        }];
        assert_eq!(
            malformed_dns_event
                .score_by_attr(&dns_attr)
                .partial_cmp(&1.0),
            Some(Ordering::Equal)
        );

        // 3. Unusual Destination Pattern (Uses ConnAttr::DstAddr)
        let unusual_dest_event =
            UnusualDestinationPattern::new(time, unusual_destination_pattern_fields());
        // UnusualDestinationPattern maps ConnAttr::DstAddr to its destination_ips vector
        let conn_attr = vec![PacketAttr {
            raw_event_kind: RawEventKind::Conn,
            attr_name: ConnAttr::DstAddr.to_string(),
            value_kind: ValueKind::IpAddr,
            cmp_kind: AttrCmpKind::Equal, // Check if vector contains this IP
            first_value: serialize(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).unwrap(),
            second_value: None,
            weight: Some(1.0),
        }];
        assert_eq!(
            unusual_dest_event
                .score_by_attr(&conn_attr)
                .partial_cmp(&1.0),
            Some(Ordering::Equal)
        );
    }

    fn serialize<T>(v: &T) -> Option<Vec<u8>>
    where
        T: Serialize,
    {
        bincode::DefaultOptions::new().serialize(v).ok()
    }

    fn create_directions(kind: FlowKind, addr: IpAddr) -> (Vec<FlowKind>, Vec<HostNetworkGroup>) {
        (vec![kind], vec![create_host_network_group(addr)])
    }

    fn create_endpoint(addr: IpAddr) -> Endpoint {
        Endpoint {
            direction: None,
            network: create_host_network_group(addr),
        }
    }

    fn create_customer(addr: IpAddr) -> Customer {
        Customer {
            id: u32::MAX,
            name: "customer".to_string(),
            description: "description".to_string(),
            networks: vec![create_customer_network(addr)],
            creation_time: chrono::Utc::now(),
        }
    }

    fn create_customer_network(addr: IpAddr) -> CustomerNetwork {
        CustomerNetwork {
            name: "customer network".to_string(),
            description: "description".to_string(),
            network_type: NetworkType::Intranet,
            network_group: create_host_network_group(addr),
        }
    }

    fn create_host_network_group(addr: IpAddr) -> HostNetworkGroup {
        HostNetworkGroup::new(vec![addr], Vec::new(), Vec::new())
    }

    fn event_filter() -> EventFilter {
        EventFilter {
            customers: None,
            endpoints: None,
            directions: None,
            source: None,
            destination: None,
            countries: None,
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

    fn blocklist_bootp_fields() -> BlocklistBootpFields {
        BlocklistBootpFields {
            sensor: "sensor".to_string(),
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
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn blocklist_conn_fields() -> BlocklistConnFields {
        BlocklistConnFields {
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
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn blocklist_dcerpc_fields() -> BlocklistDceRpcFields {
        BlocklistDceRpcFields {
            sensor: "sensor".to_string(),
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
            rtt: 1,
            named_pipe: "svcctl".to_string(),
            endpoint: "epmapper".to_string(),
            operation: "bind".to_string(),
            confidence: 1.0,
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn blocklist_dhcp_fields() -> BlocklistDhcpFields {
        BlocklistDhcpFields {
            sensor: "sensor".to_string(),
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
            msg_type: 1,
            ciaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5)),
            yiaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 6)),
            siaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 7)),
            giaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 8)),
            subnet_mask: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
            router: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            domain_name_server: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            req_ip_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 100)),
            lease_time: 100,
            server_id: IpAddr::V4(Ipv4Addr::LOCALHOST),
            param_req_list: vec![1, 2, 3],
            message: "message".to_string(),
            renewal_time: 100,
            rebinding_time: 200,
            class_id: "MSFT 5.0".as_bytes().to_vec(),
            client_id_type: 1,
            client_id: vec![7, 8, 9],
            confidence: 1.0,
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn blocklist_dns_fields() -> BlocklistDnsFields {
        BlocklistDnsFields {
            sensor: "sensor".to_string(),
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
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn blocklist_http_fields() -> BlocklistHttpFields {
        BlocklistHttpFields {
            sensor: "sensor".to_string(),
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
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn blocklist_kerberos_fields() -> BlocklistKerberosFields {
        BlocklistKerberosFields {
            sensor: "sensor".to_string(),
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
            client_name: vec!["user1".to_string()],
            realm: "EXAMPLE.COM".to_string(),
            sname_type: 1,
            service_name: vec!["krbtgt/EXAMPLE.COM".to_string()],
            confidence: 1.0,
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn blocklist_mqtt_fields() -> BlocklistMqttFields {
        BlocklistMqttFields {
            sensor: "sensor".to_string(),
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
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn blocklist_nfs_fields() -> BlocklistNfsFields {
        BlocklistNfsFields {
            sensor: "sensor".to_string(),
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
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn blocklist_ntlm_fields() -> BlocklistNtlmFields {
        BlocklistNtlmFields {
            sensor: "sensor".to_string(),
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
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn blocklist_rdp_fields() -> BlocklistRdpFields {
        BlocklistRdpFields {
            sensor: "sensor".to_string(),
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
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn blocklist_smb_fields() -> BlocklistSmbFields {
        BlocklistSmbFields {
            sensor: "sensor".to_string(),
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
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn blocklist_smtp_fields() -> BlocklistSmtpFields {
        BlocklistSmtpFields {
            sensor: "sensor".to_string(),
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
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn blocklist_ssh_fields() -> BlocklistSshFields {
        BlocklistSshFields {
            sensor: "sensor".to_string(),
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
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn blocklist_tls_fields() -> BlocklistTlsFields {
        BlocklistTlsFields {
            sensor: "sensor".to_string(),
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
            confidence: 0.6,
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn ldap_event_fields() -> LdapEventFields {
        LdapEventFields {
            sensor: "sensor".to_string(),
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
            threat_level: 3,
            category: Some(EventCategory::LateralMovement),
        }
    }

    fn ftp_event_fields() -> FtpEventFields {
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
            threat_level: 3,
            category: Some(EventCategory::LateralMovement),
        }
    }

    fn port_scan_fields() -> PortScanFields {
        PortScanFields {
            sensor: String::new(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_ports: vec![80, 443, 8000, 8080, 8888, 8443, 9000, 9001, 9002],
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            end_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 2)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            proto: 6,
            confidence: 0.3,
            threat_level: 3,
            category: Some(EventCategory::Reconnaissance),
        }
    }

    fn multi_host_port_scan_fields() -> MultiHostPortScanFields {
        MultiHostPortScanFields {
            sensor: String::new(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            resp_addrs: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            ],
            resp_port: 80,
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            end_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 2)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            proto: 6,
            confidence: 0.3,
            threat_level: 3,
            category: Some(EventCategory::Reconnaissance),
        }
    }

    fn external_ddos_fields() -> ExternalDdosFields {
        ExternalDdosFields {
            sensor: String::new(),
            orig_addrs: vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            ],
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            end_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 2)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            proto: 6,
            confidence: 0.3,
            threat_level: 3,
            category: Some(EventCategory::Impact),
        }
    }

    fn crypto_miining_pool_fields() -> CryptocurrencyMiningPoolFields {
        CryptocurrencyMiningPoolFields {
            sensor: "sensro".to_string(),
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
            threat_level: 3,
            category: Some(EventCategory::CommandAndControl),
        }
    }

    fn ftp_brute_force_fields() -> FtpBruteForceFields {
        FtpBruteForceFields {
            sensor: String::new(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 21,
            proto: 6,
            user_list: vec!["user1".to_string(), "user_2".to_string()],
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            end_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 2)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            is_internal: true,
            confidence: 0.3,
            threat_level: 3,
            category: Some(EventCategory::CredentialAccess),
        }
    }

    fn repeated_http_sessions_fiedls() -> RepeatedHttpSessionsFields {
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap();
        RepeatedHttpSessionsFields {
            sensor: "sensor".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 443,
            proto: 6,
            start_time: now,
            end_time: now,
            confidence: 0.3,
            threat_level: 3,
            category: Some(EventCategory::Exfiltration),
        }
    }

    fn dga_fields() -> DgaFields {
        DgaFields {
            sensor: "sensor".to_string(),
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
            threat_level: 3,
            category: Some(EventCategory::CommandAndControl),
        }
    }

    fn http_event_fields() -> HttpEventFields {
        HttpEventFields {
            sensor: "sensor".to_string(),
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
            threat_level: 3,
            category: Some(EventCategory::CommandAndControl),
        }
    }

    fn ldap_brute_force_fields() -> LdapBruteForceFields {
        LdapBruteForceFields {
            sensor: String::new(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 389,
            proto: 6,
            user_pw_list: vec![
                ("user1".to_string(), "pw1".to_string()),
                ("user_2".to_string(), "pw2".to_string()),
            ],
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            end_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 2)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            confidence: 0.3,
            threat_level: 3,
            category: Some(EventCategory::CredentialAccess),
        }
    }

    fn rdp_brute_force_fields() -> RdpBruteForceFields {
        RdpBruteForceFields {
            sensor: String::new(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            resp_addrs: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            ],
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 1, 1)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            end_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 10, 2)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            proto: 6,
            confidence: 0.3,
            threat_level: 3,
            category: Some(EventCategory::Discovery),
        }
    }

    fn dns_event_fields() -> DnsEventFields {
        DnsEventFields {
            sensor: "sensor".to_string(),
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
            rtt: 5,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: false,
            ttl: vec![1, 3, 5, 7],
            confidence: 0.8,
            threat_level: 3,
            category: Some(EventCategory::CommandAndControl),
        }
    }

    fn network_threat() -> NetworkThreat {
        NetworkThreat {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            sensor: "sensor".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 80,
            proto: 6,
            service: "http".to_string(),
            start_time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap(),
            duration: 100,
            orig_pkts: 10,
            resp_pkts: 20,
            orig_l2_bytes: 1000,
            resp_l2_bytes: 2000,
            content: "content".to_string(),
            db_name: "db_name".to_string(),
            rule_id: 1,
            matched_to: "matched_to".to_string(),
            cluster_id: Some(1),
            attack_kind: "attack_kind".to_string(),
            confidence: 0.9,
            threat_level: 5,
            triage_scores: None,
            category: Some(EventCategory::Reconnaissance),
        }
    }

    fn extra_threat() -> ExtraThreat {
        ExtraThreat {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 1, 1, 1).unwrap(),
            sensor: "sensor".to_string(),
            service: "service".to_string(),
            content: "content".to_string(),
            db_name: "db_name".to_string(),
            rule_id: 1,
            matched_to: "matched_to".to_string(),
            cluster_id: Some(1),
            attack_kind: "attack_kind".to_string(),
            confidence: 0.9,
            threat_level: 3,
            category: Some(EventCategory::Reconnaissance),
            triage_scores: None,
        }
    }

    fn windows_threat() -> WindowsThreat {
        WindowsThreat {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            sensor: "sensor".to_string(),
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
            threat_level: 3,
            triage_scores: None,
            category: Some(EventCategory::Impact),
        }
    }

    fn http_threat_fields() -> HttpThreatFields {
        HttpThreatFields {
            time: Utc.with_ymd_and_hms(1970, 1, 1, 0, 1, 1).unwrap(),
            sensor: "sensor".to_string(),
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
            threat_level: 3,
            category: Some(EventCategory::Reconnaissance),
        }
    }
    fn blocklist_radius_fields() -> BlocklistRadiusFields {
        BlocklistRadiusFields {
            sensor: "sensor".to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 1812,
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
            id: 1,
            code: 1,
            resp_code: 2,
            auth: "auth".to_string(),
            resp_auth: "resp_auth".to_string(),
            user_name: vec![],
            user_passwd: vec![],
            chap_passwd: vec![],
            nas_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            nas_port: 0,
            state: vec![],
            nas_id: vec![],
            nas_port_type: 0,
            message: "msg".to_string(),
            confidence: 1.0,
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn blocklist_malformed_dns_fields() -> BlocklistMalformedDnsFields {
        BlocklistMalformedDnsFields {
            sensor: "sensor".to_string(),
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
            trans_id: 12345,
            flags: 0,
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
            query_count: 0,
            resp_count: 0,
            query_bytes: 0,
            resp_bytes: 0,
            query_body: vec![],
            resp_body: vec![],
            confidence: 1.0,
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }

    fn unusual_destination_pattern_fields() -> UnusualDestinationPatternFields {
        UnusualDestinationPatternFields {
            sensor: "sensor".to_string(),
            start_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            end_time: Utc
                .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
            destination_ips: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
            count: 1,
            expected_mean: 0.0,
            std_deviation: 0.0,
            z_score: 0.0,
            confidence: 1.0,
            threat_level: 3,
            category: Some(EventCategory::InitialAccess),
        }
    }
}
