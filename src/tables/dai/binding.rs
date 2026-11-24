//! The bindings of one (customer, site, IP) in memory, and the rules that
//! start, extend and close them.
//!
//! A binding is *open* at a time `t` when it started at or before `t`, has
//! no non-estimated end at or before `t`, and `t` is before its last strong
//! evidence time plus its inactivity time. An estimated end retention wrote
//! is never by itself a reason for a binding not to be open, and past its
//! last strong evidence time plus its inactivity time a binding counts as
//! ended at that instant whether retention wrote the end or not; so every
//! rule here reads [`BindingRow::effective_end`] and none reads an estimated
//! end. A binding is *in effect* over `[start, effective_end)`.

use std::{collections::BTreeMap, net::IpAddr};

use uuid::Uuid;

use super::device::{BindingRow, Identifier};
use super::kind_number;

/// The bindings of one address, keyed by start.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Bindings(pub(crate) BTreeMap<i64, BindingRow>);

/// A binding a rule starts.
pub(crate) struct NewBinding<'a> {
    pub(crate) device: Uuid,
    pub(crate) mac: &'a str,
    pub(crate) server_id: Option<IpAddr>,
}

impl Bindings {
    /// Returns the start of the binding open at `time`, if any.
    pub(crate) fn open_at(&self, time: i64) -> Option<i64> {
        self.0
            .range(..=time)
            .rev()
            .find(|(_, row)| time < row.effective_end())
            .map(|(start, _)| *start)
    }

    /// Returns the start of the binding in effect over the whole of
    /// `[first, last]`, if any.
    pub(crate) fn covering(&self, first: i64, last: i64) -> Option<i64> {
        self.0
            .range(..=first)
            .rev()
            .find(|(_, row)| last < row.effective_end())
            .map(|(start, _)| *start)
    }

    pub(crate) fn get(&self, start: i64) -> Option<&BindingRow> {
        self.0.get(&start)
    }

    /// Closes the binding starting at `start` at `time`: a binding closed at
    /// its own start is removed, so no new binding's key collides with it,
    /// and any other gets `time` as its end, replacing an estimated one.
    pub(crate) fn close(&mut self, start: i64, time: i64) {
        if time <= start {
            self.0.remove(&start);
        } else if let Some(row) = self.0.get_mut(&start) {
            row.end = Some(time);
            row.end_estimated = false;
        }
    }

    /// Moves the last strong evidence time of the binding starting at
    /// `start` to `time` if that is later; extending a binding removes an
    /// estimated end, which retention writes again once the new one passes.
    pub(crate) fn extend(&mut self, start: i64, time: i64) {
        if let Some(row) = self.0.get_mut(&start) {
            row.last_strong = row.last_strong.max(time);
            if row.end_estimated {
                row.end = None;
                row.end_estimated = false;
            }
        }
    }

    /// Applies an ACK with a valid MAC at `time` that binds `new.device`:
    /// extends the device's open binding, or closes another device's open
    /// binding and starts a new one, or starts a new one. `inactivity` gives
    /// a new binding's inactivity time.
    pub(crate) fn ack(
        &mut self,
        time: i64,
        new: &NewBinding<'_>,
        inactivity: impl FnOnce() -> i64,
    ) {
        if let Some(start) = self.open_at(time) {
            if self
                .0
                .get(&start)
                .is_some_and(|row| row.device == new.device)
            {
                self.extend(start, time);
                if let Some(row) = self.0.get_mut(&start) {
                    row.server_id = new.server_id;
                }
                return;
            }
            self.close(start, time);
        }
        self.0.insert(
            time,
            BindingRow {
                end: None,
                device: new.device,
                evidence_kind: kind_number(review_protocol::types::DaiObservationKind::DhcpLease),
                evidence_identifier: Identifier::mac(new.mac),
                server_id: new.server_id,
                last_strong: time,
                inactivity: inactivity(),
                end_estimated: false,
            },
        );
    }

    /// Applies an ACK with an invalid `chaddr` at `time`: closes the binding
    /// open then, of any device.
    pub(crate) fn invalid_ack(&mut self, time: i64) {
        if let Some(start) = self.open_at(time) {
            self.close(start, time);
        }
    }

    /// Applies a RELEASE or DECLINE at `time`: closes the binding open then
    /// whose evidence MAC is `mac` and whose `server_id` is `server_id`
    /// (`None` matching only `None`). Otherwise nothing changes.
    pub(crate) fn release(&mut self, time: i64, mac: Option<&str>, server_id: Option<IpAddr>) {
        let Some(mac) = mac else {
            return;
        };
        let Some(start) = self.open_at(time) else {
            return;
        };
        if self.0.get(&start).is_some_and(|row| {
            row.evidence_identifier == Identifier::mac(mac) && row.server_id == server_id
        }) {
            self.close(start, time);
        }
    }

    /// Returns the start of the replay of a late observation at `time`: the
    /// start of the binding in effect at `time`, else of the latest binding
    /// starting before it, else `time`.
    pub(crate) fn replay_start(&self, time: i64) -> i64 {
        self.open_at(time)
            .or_else(|| self.0.range(..=time).next_back().map(|(start, _)| *start))
            .unwrap_or(time)
    }

    /// Removes the bindings starting at or after `from` and returns the
    /// inactivity time of each, keyed by (start, device).
    pub(crate) fn split_off(&mut self, from: i64) -> BTreeMap<(i64, Uuid), i64> {
        self.0
            .split_off(&from)
            .into_iter()
            .map(|(start, row)| ((start, row.device), row.inactivity))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC_A: &str = "02:00:00:00:00:0a";
    const MAC_B: &str = "02:00:00:00:00:0b";

    fn device(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    fn new(n: u8, mac: &str) -> NewBinding<'_> {
        NewBinding {
            device: device(n),
            mac,
            server_id: None,
        }
    }

    #[test]
    fn ack_extends_closes_and_starts() {
        let mut set = Bindings::default();
        set.ack(10, &new(1, MAC_A), || 100);
        set.ack(20, &new(1, MAC_A), || 100);
        assert_eq!(set.0.len(), 1);
        assert_eq!(set.get(10).unwrap().last_strong, 20);
        set.ack(30, &new(2, MAC_B), || 100);
        assert_eq!(set.get(10).unwrap().end, Some(30));
        assert_eq!(set.get(30).unwrap().device, device(2));
        // Past last strong + inactivity, the same device starts anew.
        set.ack(200, &new(2, MAC_B), || 100);
        assert_eq!(set.get(30).unwrap().end, None);
        assert_eq!(set.get(200).unwrap().device, device(2));
        assert_eq!(set.0.len(), 3);
    }

    #[test]
    fn same_time_acks_leave_the_later() {
        let mut set = Bindings::default();
        set.ack(10, &new(1, MAC_A), || 100);
        set.ack(10, &new(2, MAC_B), || 100);
        assert_eq!(set.0.len(), 1);
        assert_eq!(set.get(10).unwrap().device, device(2));
    }

    #[test]
    fn release_matches_mac_and_server_id() {
        let server: IpAddr = "10.0.0.254".parse().unwrap();
        let mut set = Bindings::default();
        set.ack(
            10,
            &NewBinding {
                device: device(1),
                mac: MAC_A,
                server_id: Some(server),
            },
            || 100,
        );
        set.release(20, Some(MAC_B), Some(server));
        set.release(20, Some(MAC_A), None);
        set.release(20, None, Some(server));
        assert_eq!(set.get(10).unwrap().end, None);
        set.release(20, Some(MAC_A), Some(server));
        assert_eq!(set.get(10).unwrap().end, Some(20));
        // Closed, it is no longer open.
        set.release(25, Some(MAC_A), Some(server));
        assert_eq!(set.get(10).unwrap().end, Some(20));
    }

    #[test]
    fn estimated_ends_do_not_end_bindings() {
        let mut set = Bindings::default();
        set.ack(10, &new(1, MAC_A), || 100);
        let row = set.0.get_mut(&10).unwrap();
        row.end = Some(110);
        row.end_estimated = true;
        assert_eq!(set.open_at(50), Some(10));
        assert_eq!(set.open_at(110), None);
        set.ack(50, &new(1, MAC_A), || 100);
        let row = set.get(10).unwrap();
        assert_eq!(
            (row.end, row.end_estimated, row.last_strong),
            (None, false, 50)
        );
        let row = set.0.get_mut(&10).unwrap();
        row.end = Some(150);
        row.end_estimated = true;
        set.release(60, Some(MAC_A), None);
        let row = set.get(10).unwrap();
        assert_eq!((row.end, row.end_estimated), (Some(60), false));
    }

    #[test]
    fn invalid_ack_closes_any_device() {
        let mut set = Bindings::default();
        set.ack(10, &new(1, MAC_A), || 100);
        set.invalid_ack(15);
        assert_eq!(set.get(10).unwrap().end, Some(15));
        set.invalid_ack(16);
        assert_eq!(set.0.len(), 1);
    }

    #[test]
    fn covering_needs_the_whole_range() {
        let mut set = Bindings::default();
        set.ack(10, &new(1, MAC_A), || 100);
        set.close(10, 50);
        assert_eq!(set.covering(10, 49), Some(10));
        assert_eq!(set.covering(10, 50), None);
        assert_eq!(set.covering(9, 20), None);
    }

    #[test]
    fn replay_starts() {
        let mut set = Bindings::default();
        assert_eq!(set.replay_start(5), 5);
        set.ack(10, &new(1, MAC_A), || 100);
        set.close(10, 30);
        set.ack(50, &new(1, MAC_A), || 100);
        assert_eq!(set.replay_start(20), 10);
        assert_eq!(set.replay_start(40), 10);
        assert_eq!(set.replay_start(60), 50);
        assert_eq!(set.replay_start(5), 5);
        let removed = set.split_off(10);
        assert_eq!(removed.len(), 2);
        assert!(set.0.is_empty());
    }
}
