//! Resolve: the subject an IP address at a site names at a time or over a
//! window, with the evidence gap and its explanation.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use anyhow::Result;
use review_protocol::types::DaiObservationKind;
use thiserror::Error;
use uuid::Uuid;

use super::{
    Dai, Snapshot,
    device::{BindingRow, address_key, decode_evidence_key, evidence_key_prefix},
    kind_from_number,
    view::{
        CustomerView, DaiComparedValue, EVIDENCE_KINDS, Gap, SensorCollection, in_effect_at,
        reported_end,
    },
};

/// The most items one [`Store::dai_resolve`](crate::Store::dai_resolve)
/// call takes.
pub const DAI_RESOLVE_MAX_ITEMS: usize = 1_000;
/// The most evidence rows an explanation lists per binding.
pub const DAI_EXPLANATION_EVIDENCE_ROWS: usize = 10;

/// When a resolve item asks about: a time or a closed window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiResolveWhen {
    /// The time `t`, in nanoseconds since the UNIX epoch.
    At(i64),
    /// The closed window `[from, to]`; `from` must not be after `to`.
    Window { from: i64, to: i64 },
}

/// One item of a resolve call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiResolveItem {
    /// The site token; `None` stands for the customer's one site in use,
    /// which only a customer that is not multi-site has.
    pub site: Option<String>,
    /// The IP address.
    pub ip: IpAddr,
    /// The time or window.
    pub when: DaiResolveWhen,
}

/// A refusal of a whole resolve call.
///
/// It is returned inside the `anyhow::Error` of
/// [`Store::dai_resolve`](crate::Store::dai_resolve), so a caller can
/// `downcast_ref` it.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DaiResolveError {
    /// The call has more than [`DAI_RESOLVE_MAX_ITEMS`] items.
    #[error("a resolve takes at most {DAI_RESOLVE_MAX_ITEMS} items, not {count}")]
    TooManyItems { count: usize },
}

/// Why one resolve item has no answer.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DaiResolveItemError {
    /// The site token is not one of the customer's sites.
    #[error("no site has token {site:?}")]
    UnknownSite { site: String },
    /// The item has no site token and the customer is multi-site.
    #[error("the customer is multi-site, so the item needs a site token")]
    SiteRequired,
    /// The item has no site token and the customer has no site at all.
    #[error("the customer has no site")]
    NoSite,
    /// The window's `from` is after its `to`.
    #[error("the window starts at {from}, after its end {to}")]
    InvertedWindow { from: i64, to: i64 },
}

/// The kind of a resolve answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiSubjectKind {
    /// One device.
    Device,
    /// No device: the IP address itself.
    Ip,
    /// Two or more devices over the window.
    Ambiguous,
    /// The evidence for the time is not complete yet, or was skipped.
    EvidenceGap,
}

/// What decided a resolve answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaiEvidenceSource {
    /// A binding started by an observation of the kind.
    Observation(DaiObservationKind),
    /// The device an operator fixed at the address.
    OperatorFixedIp,
}

/// An evidence row an explanation lists: the kind, last seen time and
/// sensor of an observation applied at the address, and nothing of its
/// body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiEvidenceRef {
    pub kind: DaiObservationKind,
    pub last_seen: i64,
    pub sensor: String,
}

/// A binding that decided a resolve answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiDecidingBinding {
    /// The current device of the binding.
    pub device: Uuid,
    pub start: i64,
    /// The effective end; `None` while the binding is open.
    pub end: Option<i64>,
    /// Whether `end` is an estimate rather than a stored close.
    pub end_estimated: bool,
    /// The kind of the observation that started the binding; `None` for a
    /// kind number no kind has.
    pub evidence_kind: Option<DaiObservationKind>,
    /// Up to [`DAI_EXPLANATION_EVIDENCE_ROWS`] evidence rows at the address
    /// last seen within the binding and at or before the time (within the
    /// window), newest first.
    pub evidence: Vec<DaiEvidenceRef>,
}

/// A cause of an evidence gap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaiGapCause {
    /// The time (a window's end) is after the site's compared time, which
    /// `value` of `sensor` set to `time`.
    AfterComparedTime {
        sensor: String,
        value: DaiComparedValue,
        time: i64,
    },
    /// The time (a part of the window) lies in a range the sensor's pair of
    /// the kind skipped by the catch-up limit, `[start, end)`.
    SkippedByCatchup {
        sensor: String,
        kind: DaiObservationKind,
        start: i64,
        end: i64,
    },
}

/// The explanation of a resolve answer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DaiExplanation {
    /// The bindings that decided the answer, in start order.
    pub bindings: Vec<DaiDecidingBinding>,
    /// The causes of an evidence gap; empty if there is none.
    pub gap_causes: Vec<DaiGapCause>,
}

/// The answer to one resolve item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaiResolveAnswer {
    pub kind: DaiSubjectKind,
    /// `dev:<device id>` for a device; otherwise `ip:<site token>/<IP>` for
    /// a multi-site customer with device identification on and the IP in
    /// one of its internal networks, else `ip:<IP>`. For an evidence gap it
    /// is the id the evidence so far gives.
    pub subject: String,
    /// The site the item was resolved at.
    pub site: String,
    /// The current devices the evidence gives, in id order.
    pub devices: Vec<Uuid>,
    /// The distinct sources of the bindings and fixed IP that decided it,
    /// observation kinds in kind number order and the fixed IP last; empty
    /// for an IP subject.
    pub evidence_sources: Vec<DaiEvidenceSource>,
    /// The explanation, if one was asked for.
    pub explanation: Option<DaiExplanation>,
}

/// The state every item of one resolve call reads.
struct ResolveContext<'a> {
    snapshot: &'a Snapshot<'a>,
    view: CustomerView,
    collections: BTreeMap<String, SensorCollection>,
    /// The catch-up gaps of the customer's sensors' O1, O4 and O5 pairs.
    gaps: Vec<Gap>,
    with_explanation: bool,
    now: i64,
}

impl Dai<'_> {
    /// Resolves `items` for the customer at `now`, as
    /// [`Store::dai_resolve`](crate::Store::dai_resolve) describes.
    pub(crate) fn resolve(
        &self,
        customer: u32,
        items: &[DaiResolveItem],
        with_explanation: bool,
        now: i64,
    ) -> Result<Vec<Result<DaiResolveAnswer, DaiResolveItemError>>> {
        if items.len() > DAI_RESOLVE_MAX_ITEMS {
            return Err(DaiResolveError::TooManyItems { count: items.len() }.into());
        }
        let snapshot = self.db.snapshot();
        let view = self.customer_view(&snapshot, customer)?;
        let collections = self.collections(&snapshot, &view)?;
        let gaps = self
            .customer_gaps(&snapshot, &view)?
            .into_iter()
            .filter(|gap| EVIDENCE_KINDS.contains(&gap.kind))
            .collect();
        let context = ResolveContext {
            snapshot: &snapshot,
            view,
            collections,
            gaps,
            with_explanation,
            now,
        };
        items
            .iter()
            .map(|item| self.resolve_item(&context, item))
            .collect()
    }

    /// Resolves one item; the outer error is a database failure, the inner
    /// one the item's own.
    fn resolve_item(
        &self,
        context: &ResolveContext<'_>,
        item: &DaiResolveItem,
    ) -> Result<Result<DaiResolveAnswer, DaiResolveItemError>> {
        let view = &context.view;
        let (from, to) = match item.when {
            DaiResolveWhen::At(time) => (time, time),
            DaiResolveWhen::Window { from, to } => {
                if from > to {
                    return Ok(Err(DaiResolveItemError::InvertedWindow { from, to }));
                }
                (from, to)
            }
        };
        let site = match &item.site {
            Some(site) => {
                if !view.has_site(site) {
                    return Ok(Err(DaiResolveItemError::UnknownSite { site: site.clone() }));
                }
                site.clone()
            }
            None if view.multi_site => return Ok(Err(DaiResolveItemError::SiteRequired)),
            None => match &view.single_site {
                Some(site) => site.clone(),
                None => return Ok(Err(DaiResolveItemError::NoSite)),
            },
        };
        let snapshot = context.snapshot;
        let customer = view.customer;

        // The bindings in effect at the time or anywhere in the window.
        let bindings: Vec<(i64, BindingRow)> = self
            .address_bindings(snapshot, customer, &site, item.ip)?
            .into_iter()
            .filter(|(start, row)| match item.when {
                DaiResolveWhen::At(time) => in_effect_at(*start, row, time),
                DaiResolveWhen::Window { from, to } => *start <= to && row.effective_end() > from,
            })
            .collect();
        let deciding: Vec<(i64, BindingRow)> = match item.when {
            // Bindings of one address do not overlap; of two that do, the
            // later start is the one in effect.
            DaiResolveWhen::At(_) => bindings.into_iter().last().into_iter().collect(),
            DaiResolveWhen::Window { .. } => bindings,
        };
        let uncovered = !covers(&deciding, from, to);
        let mut devices = BTreeSet::new();
        let mut kinds = BTreeSet::new();
        for (_, row) in &deciding {
            devices.insert(self.current_or_same(snapshot, customer, row.device)?);
            kinds.insert(row.evidence_kind);
        }
        let mut sources: Vec<DaiEvidenceSource> = kinds
            .into_iter()
            .filter_map(kind_from_number)
            .map(DaiEvidenceSource::Observation)
            .collect();
        if uncovered
            && let Some(fixed) = Self::value_in::<super::device::FixedIpRow>(
                snapshot,
                &self.fixed_ips,
                &address_key(customer, &site, item.ip),
            )?
        {
            devices.insert(self.current_or_same(snapshot, customer, fixed)?);
            sources.push(DaiEvidenceSource::OperatorFixedIp);
        }

        let mut kind = match devices.len() {
            0 => DaiSubjectKind::Ip,
            1 => DaiSubjectKind::Device,
            _ => DaiSubjectKind::Ambiguous,
        };
        let subject = match (kind, devices.first()) {
            (DaiSubjectKind::Device, Some(device)) => format!("dev:{device}"),
            _ => ip_subject(view, &site, item.ip),
        };

        let gap_causes = gap_causes(context, &site, from, to);
        if !gap_causes.is_empty() {
            kind = DaiSubjectKind::EvidenceGap;
        }

        let explanation = if context.with_explanation {
            // A time lists the evidence up to it, a window the evidence in
            // it.
            let since = match item.when {
                DaiResolveWhen::At(_) => i64::MIN,
                DaiResolveWhen::Window { from, .. } => from,
            };
            let mut explained = Vec::with_capacity(deciding.len());
            for (start, row) in &deciding {
                let span = ((*start).max(since), to);
                explained.push(self.explain_binding(context, &site, item.ip, *start, row, span)?);
            }
            Some(DaiExplanation {
                bindings: explained,
                gap_causes,
            })
        } else {
            None
        };

        Ok(Ok(DaiResolveAnswer {
            kind,
            subject,
            site,
            devices: devices.into_iter().collect(),
            evidence_sources: sources,
            explanation,
        }))
    }

    /// Returns the explanation of the binding of (`site`, `ip`) starting at
    /// `start`, listing its evidence rows last seen within the closed span
    /// `(since, until)`, which lies at or after `start`.
    fn explain_binding(
        &self,
        context: &ResolveContext<'_>,
        site: &str,
        ip: IpAddr,
        start: i64,
        row: &BindingRow,
        (since, until): (i64, i64),
    ) -> Result<DaiDecidingBinding> {
        let customer = context.view.customer;
        let snapshot = context.snapshot;
        // Last seen within the binding, `[start, effective end)`, and within
        // `[since, until]`.
        let past = row.effective_end().min(until.saturating_add(1));
        let mut evidence = Vec::new();
        if since < past {
            let low = evidence_key_prefix(customer, site, ip, since);
            let high = evidence_key_prefix(customer, site, ip, past);
            for (key, value) in Self::range_in(
                snapshot,
                &self.evidence,
                &low,
                &high,
                true,
                DAI_EXPLANATION_EVIDENCE_ROWS,
            )? {
                let key = decode_evidence_key(&key)?;
                let stored: super::device::EvidenceRow = super::super::deserialize(&value)?;
                evidence.push(DaiEvidenceRef {
                    kind: key.kind,
                    last_seen: key.last_seen,
                    sensor: stored.sensor,
                });
            }
        }
        let (end, end_estimated) = reported_end(row, context.now);
        Ok(DaiDecidingBinding {
            device: self.current_or_same(snapshot, customer, row.device)?,
            start,
            end,
            end_estimated,
            evidence_kind: kind_from_number(row.evidence_kind),
            evidence,
        })
    }
}

/// Returns the causes of an evidence gap of an item at `site` over
/// `[from, to]` (a time `t` is `[t, t]`).
fn gap_causes(context: &ResolveContext<'_>, site: &str, from: i64, to: i64) -> Vec<DaiGapCause> {
    let view = &context.view;
    let mut causes = Vec::new();
    let selection = view.select(&context.collections, site, to, context.now);
    if let Some(compared) = selection.compared
        && to > compared.time
    {
        causes.push(DaiGapCause::AfterComparedTime {
            sensor: compared.sensor,
            value: compared.value,
            time: compared.time,
        });
    }
    let past_to = to.saturating_add(1);
    for gap in &context.gaps {
        let lo = gap.start.max(from);
        let hi = gap.end.min(past_to);
        if view.in_site_during(&gap.sensor, site, lo, hi) {
            causes.push(DaiGapCause::SkippedByCatchup {
                sensor: gap.sensor.clone(),
                kind: gap.kind,
                start: gap.start,
                end: gap.end,
            });
        }
    }
    causes
}

/// Returns whether the bindings `bindings`, each in effect over `[start,
/// effective end)`, cover every time of the closed window `[from, to]`.
fn covers(bindings: &[(i64, BindingRow)], from: i64, to: i64) -> bool {
    let mut spans: Vec<(i64, i64)> = bindings
        .iter()
        .map(|(start, row)| (*start, row.effective_end()))
        .collect();
    spans.sort_unstable();
    let mut covered_to = from;
    for (start, end) in spans {
        if start > covered_to {
            return false;
        }
        covered_to = covered_to.max(end);
        if covered_to > to {
            return true;
        }
    }
    false
}

/// Returns the IP subject id of `ip` at `site`: `ip:<site>/<IP>` for a
/// multi-site customer with device identification on and `ip` in one of its
/// internal networks, else `ip:<IP>`.
pub(super) fn ip_subject(view: &CustomerView, site: &str, ip: IpAddr) -> String {
    if view.multi_site && view.settings.device_account_identification && view.is_internal(ip) {
        format!("ip:{site}/{ip}")
    } else {
        format!("ip:{ip}")
    }
}
