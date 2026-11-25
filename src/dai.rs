//! Device identification (DAI): the configuration (the settings, the sites,
//! the relay site table, the sensor site history and the configuration
//! epochs of each customer's sensors), the observations agents send, their
//! read cursors and the restore generation, and the devices, bindings and
//! device attributes slot application derives from the observations.
//!
//! Every write here is one optimistic transaction, retried from the start on
//! a commit conflict, and a refusal commits nothing. Every write of a
//! customer's DAI configuration first reads and increments the customer's
//! `dai site policy guard` row, as does every time series generation policy
//! save, so two of them for one customer conflict and the retried one checks
//! again against the new state.
//!
//! Times are nanoseconds since the UNIX epoch (UTC). A site change takes
//! effect at the first 5-minute boundary (a whole multiple of 300 seconds)
//! strictly after the write: until then the change is scheduled, and the
//! sensor's site in effect is the one before it.
//!
//! # Observations
//!
//! An agent reduces sensor records to observations in 5-minute *slots*
//! (`[slot_start, slot_start + 300 s)`, `slot_start` a multiple of 300 s)
//! per (sensor, observation kind) and sends each slot as one send of one or
//! more parts. The store keeps, per (sensor, kind), the agent's read
//! position: the **cursor**, the slot boundary up to which every slot is
//! confirmed stored, the **read floor**, before which no record is counted,
//! and the slots marked for re-extraction. A **restore generation** tells
//! the agent that a backup was restored and its state is stale.
//!
//! A sensor's customer is the customer of the node carrying it, when the
//! node table names the sensor for exactly one customer; a name it gives
//! for no customer, or for two or more, is not a *customer sensor*.
//!
//! # Unregistered ranges
//!
//! Per sensor and per UTC date, an agent also sends the counts of the
//! private and CGNAT addresses it saw outside the customer's registered
//! networks, as a *range day* collected under a lease, and reports the late
//! records that mark a stored day for recollection. The store folds the
//! counts into candidate unregistered internal ranges, which an operator
//! registers or ignores. These methods, from
//! [`Store::begin_dai_range_day`] to [`Store::dai_ignored_ranges`], apply to
//! customers with device identification off as well.
//!
//! Every method here that writes observations, cursors or devices is one
//! optimistic transaction, retried from the start on a commit conflict,
//! except [`Store::apply_dai_retention`] and [`Store::delete_dai_customer`],
//! which commit in several. "Now" is passed in by the caller.
//!
//! # Devices
//!
//! [`Store::apply_dai_slot`] turns a sensor's pending observations into
//! *devices*, each identified by a random UUID v4 and holding strong
//! identifiers (a MAC, an operator asset id, a machine account), into
//! *bindings*, a device holding an IP address at a site from a start to an
//! end, and into device attributes. A (site, IP) with no binding at a time
//! is an *IP device*: a placeholder, never a row. O1 means `DhcpLease`, O3
//! `DhcpServer`, O4 `Kerberos`, O5 `Ntlm`, O7 `Service`, O8 `SoftwareString`
//! and O22 `DnsName`.

use anyhow::Result;
use review_protocol::types::{DaiCursors, DaiObservationBatch};

use crate::{
    DaiPendingHead, DaiRelaySite, DaiRelaySites, DaiSettings, DaiSettingsUpdate, DaiSite,
    DaiStoreOutcome, Store,
    tables::{Dai, now_nanos},
};

impl Store {
    fn dai(&self) -> Dai<'_> {
        self.states.dai()
    }

    /// Returns the DAI settings of the customer.
    ///
    /// A customer with no stored settings reads as [`DaiSettings::default`]:
    /// disabled, never enabled, an inactivity multiplier of 2, 24 hours
    /// without a lease, 180 days of evidence aging, no Kerberos realm and
    /// both revisions 0.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn dai_settings(&self, customer_id: u32) -> Result<DaiSettings> {
        self.dai().settings(customer_id)
    }

    /// Writes the settable DAI settings of the customer, given the expected
    /// settings revision, and returns the stored settings.
    ///
    /// The settings revision is incremented and the relay site table
    /// revision is left as it is. Turning `device_account_identification` on
    /// sets the last-enabled time to the time of the write; turning it off,
    /// or a write that leaves it on, keeps it. A write that changes
    /// `device_account_identification` increments the configuration epoch of
    /// every sensor of the customer. The customer's default site is created,
    /// in the same transaction, if it has none.
    ///
    /// Turning it on also moves, in the same transaction, every existing DAI
    /// cursor row of the customer's sensors to the time of the write: the
    /// read floor to it and the cursor to the start of the slot holding it,
    /// with no confirmed slot and no re-extract mark. So a re-enable never
    /// fills in the time it was off.
    ///
    /// # Errors
    ///
    /// Returns, inside the error and changing nothing,
    /// [`DaiConfigError::InvalidSettings`](crate::DaiConfigError::InvalidSettings)
    /// if the multiplier or a duration is 0 or a realm name is empty, and
    /// [`DaiConfigError::StaleRevision`](crate::DaiConfigError::StaleRevision)
    /// if `expected_revision` is not the stored settings revision. Returns an
    /// error if the database operation fails.
    pub fn set_dai_settings(
        &self,
        customer_id: u32,
        expected_revision: u64,
        update: &DaiSettingsUpdate,
    ) -> Result<DaiSettings> {
        self.dai()
            .set_settings(customer_id, expected_revision, update, &now_nanos)
    }

    /// Creates the customer's default site if it has none, and returns its
    /// token.
    ///
    /// The default site has an empty display name and lists no sensor: a
    /// sensor of the customer that no site lists is in it. Concurrent calls
    /// leave one default site. Creating it increments no configuration epoch
    /// and writes no sensor site history.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn ensure_default_site(&self, customer_id: u32) -> Result<String> {
        self.dai().ensure_default_site(customer_id)
    }

    /// Returns the customer's stored sites, in token order.
    ///
    /// Nothing is written: a customer whose default site was never created
    /// lists none.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn dai_sites(&self, customer_id: u32) -> Result<Vec<DaiSite>> {
        self.dai().sites(customer_id)
    }

    /// Returns the customer's site `token`, or `None` if it has none.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn dai_site(&self, customer_id: u32, token: &str) -> Result<Option<DaiSite>> {
        self.dai().site(customer_id, token)
    }

    /// Creates a site of the customer with the display name `name` listing
    /// `sensors`, and returns its token, 8 random characters of `[a-z0-9]`.
    ///
    /// The default site is created first if the customer has none. Each
    /// listed sensor moves out of the default site: a sensor site history row
    /// puts it in the new site from the first 5-minute boundary after the
    /// write. The configuration epoch of every sensor of the customer is
    /// incremented.
    ///
    /// # Errors
    ///
    /// Returns a [`DaiConfigError`](crate::DaiConfigError) inside the error,
    /// changing nothing: `InvalidSiteName` if `name` is empty or contains
    /// one of `|`, `;`, `,` and `"`; `DuplicateSiteName` if another site of
    /// the customer has the name; `DuplicateSensor` if `sensors` names one
    /// twice; `NotSensorOfCustomer` if a name is not a sensor of the
    /// customer; `SensorInOtherSite` if another site lists one;
    /// `PolicyWouldSpanSites` if a time series generation policy of the
    /// customer would read sensors of two sites. Returns an error if the
    /// database operation fails.
    pub fn create_dai_site(
        &self,
        customer_id: u32,
        name: &str,
        sensors: &[String],
    ) -> Result<String> {
        self.dai()
            .create_site(customer_id, name, sensors, &now_nanos)
    }

    /// Replaces the display name and the sensors of the customer's site
    /// `token`.
    ///
    /// A sensor added moves out of the default site, and one removed returns
    /// to it, from the first 5-minute boundary after the write; a change
    /// before that boundary replaces the one scheduled at it. The
    /// configuration epoch of every sensor of the customer, including one
    /// removed from the site, is incremented.
    ///
    /// # Errors
    ///
    /// Returns a [`DaiConfigError`](crate::DaiConfigError) inside the error,
    /// changing nothing: `SiteNotFound` if the customer has no such site;
    /// `DefaultSiteFixed` if it is the default site; otherwise as
    /// [`create_dai_site`](Self::create_dai_site). Returns an error if the
    /// database operation fails.
    pub fn update_dai_site(
        &self,
        customer_id: u32,
        token: &str,
        name: &str,
        sensors: &[String],
    ) -> Result<()> {
        self.dai()
            .update_site(customer_id, token, name, sensors, &now_nanos)
    }

    /// Removes the customer's site `token`, incrementing the configuration
    /// epoch of every sensor of the customer.
    ///
    /// # Errors
    ///
    /// Returns a [`DaiConfigError`](crate::DaiConfigError) inside the error,
    /// changing nothing: `SiteNotFound` if the customer has no such site;
    /// `DefaultSiteFixed` if it is the default site; `SiteHasSensors` while
    /// it lists sensors; `SiteInRelayTable` while the relay site table names
    /// it; `SiteStillAssigned` while the assignment in effect, or one
    /// scheduled, still puts a sensor in it. Returns an error if the
    /// database operation fails.
    pub fn remove_dai_site(&self, customer_id: u32, token: &str) -> Result<()> {
        self.dai().remove_site(customer_id, token, &now_nanos)
    }

    /// Returns the token of the site `sensor` was in, in the customer's
    /// network, at the time `time`.
    ///
    /// It is the site of the latest sensor site history row of the sensor
    /// effective at or before `time` that names the customer, or else the
    /// customer's default site. Returns `None` only if neither exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn dai_sensor_site(
        &self,
        customer_id: u32,
        sensor: &str,
        time: i64,
    ) -> Result<Option<String>> {
        self.dai().sensor_site(customer_id, sensor, time)
    }

    /// Returns the customer's relay site table and its revision.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn dai_relay_sites(&self, customer_id: u32) -> Result<DaiRelaySites> {
        self.dai().relay_sites(customer_id)
    }

    /// Replaces the customer's relay site table with `entries`, given the
    /// expected relay site table revision, and returns the new revision.
    ///
    /// The relay revision is incremented and the settings revision is left
    /// as it is; a customer with no stored settings gets the default ones.
    /// The configuration epoch of every sensor of the customer is
    /// incremented.
    ///
    /// # Errors
    ///
    /// Returns a [`DaiConfigError`](crate::DaiConfigError) inside the error,
    /// changing nothing: `StaleRevision` if `expected_revision` is not the
    /// stored relay revision; `UnspecifiedGiaddr` if an entry's `giaddr` is
    /// `0.0.0.0` or `::`; `DuplicateRelayEntry` if two entries have the same
    /// DHCP server IP and `giaddr`; `UnknownRelaySite` if an entry names a
    /// token that is not one of the customer's stored sites. Returns an
    /// error if the database operation fails.
    pub fn replace_dai_relay_sites(
        &self,
        customer_id: u32,
        expected_revision: u64,
        entries: &[DaiRelaySite],
    ) -> Result<u64> {
        self.dai()
            .replace_relay_sites(customer_id, expected_revision, entries)
    }

    /// Returns the configuration epoch of `sensor`, 0 if none was recorded.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn dai_sensor_config_epoch(&self, sensor: &str) -> Result<u64> {
        self.dai().config_epoch(sensor)
    }

    /// Records the hash of the configuration content of `sensor`, and
    /// returns its configuration epoch.
    ///
    /// The hash is opaque: it is only compared with the stored one. If it
    /// differs, or none is stored, it is stored and the epoch incremented.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn record_dai_sensor_config_hash(&self, sensor: &str, hash: &[u8]) -> Result<u64> {
        self.dai().record_config_hash(sensor, hash)
    }

    /// Deletes the customer's rows from the DAI tables.
    ///
    /// The sensor names it works on are fixed as it starts: `sensors`, the
    /// names the customer's sites list, and the customer's sensors per the
    /// node table. A name of `sensors` with no row is not an error; pass the
    /// names of the customer's sensors whose agents a customer data deletion
    /// has already removed from the node table. The names it *owns* are
    /// those, except a name the node table shows, as the method starts, as a
    /// sensor of another customer.
    ///
    /// It deletes, in this order and in separate transactions: the cursors,
    /// sends, staged parts, catch-up gaps, sensor kind states, earliest
    /// pending slots, observations, summaries, range days and pending
    /// observations of the names it owns, each name's resolver point after
    /// its pending observations, and, for a name it collected that the node
    /// table shows as a sensor of another customer, the observations naming
    /// this customer; every sensor site history row naming the customer, and
    /// the sensor state rows of the names it owns; the customer's counters,
    /// address activity, range blocks, range subnets and ignored ranges; the
    /// customer's devices, device identifiers and device aliases; its
    /// bindings with their reverse index rows, evidence and IP states, one
    /// address at a time, in transactions that read the address's IP state
    /// for update before its bindings and evidence and write it, so a writer
    /// of the address racing the deletion conflicts; its fixed IPs,
    /// conflicts, services, software strings and device changes; then the
    /// customer's settings, sites, relay site table and site policy guard.
    /// Every customer-keyed row is deleted after every sensor-keyed one, so
    /// an application racing the deletion conflicts on the pending
    /// observations it reads. The restore generation stays. An interrupted
    /// call repeated with the same names removes the rest, and a
    /// repeated call after success changes nothing. The customer's time
    /// series generation policies are left to
    /// [`IndexedTable::remove_customer_policies`](crate::IndexedTable::remove_customer_policies).
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn delete_dai_customer(&self, customer_id: u32, sensors: &[String]) -> Result<()> {
        self.dai().delete_customer(customer_id, sensors)
    }

    /// Returns the DAI restore generation.
    ///
    /// A store that has none gets a random one when it is opened, in a
    /// transaction that reads it for update, so concurrent first reads return
    /// the same value, and a method that writes nothing never draws it. Every
    /// restore of a backup replaces it with a new random one.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn dai_restore_generation(&self) -> Result<u64> {
        self.dai().restore_generation()
    }

    /// Returns the DAI read cursors of the sensors of a `get_dai_cursors`
    /// request at the time `now`, creating the missing ones.
    ///
    /// `sensors` that is exactly `["all"]` stands for every customer sensor;
    /// any other list is answered for its customer sensors only, and the
    /// other names are skipped. For each such sensor and each of the eight
    /// observation kinds, an entry holds the cursor, the read floor and the
    /// slots marked for re-extraction with their marks, ordered by slot
    /// start. Entries are ordered by sensor name and then kind number.
    ///
    /// `range_days` lists, for each such sensor and each range evidence, the
    /// dates within the 30 days ending with the date of `now`, strictly
    /// after the date of the sensor's first cursor time as this read sees it
    /// (so a sensor whose first cursor row this read creates lists none),
    /// whose end plus 5 minutes plus 1 hour is at or before `now`, and that
    /// carry a recollect mark or have no stored version, including dates
    /// with no range day row. Each entry carries the day's mark and stored
    /// version, both `None` for a date with no row, and they are ordered by
    /// sensor name, then date, then evidence. Listing them writes nothing.
    ///
    /// A missing (sensor, kind) row is created in the same transaction, for
    /// a disabled customer's sensor too: its read floor is `now`, or, for an
    /// enabled customer, the later of `now` and its last-enabled time, and
    /// its cursor the start of the slot holding the read floor. The first
    /// time a sensor gets cursor rows, `now` is recorded as its first cursor
    /// time. Before it creates a row for a customer's sensor, the read reads
    /// and increments the customer's `dai site policy guard` row and then
    /// reads its settings, so a creation racing a settings write that turns
    /// device identification on conflicts with it and is retried. A read
    /// that creates nothing writes nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn dai_cursors(&self, sensors: &[String], now: i64) -> Result<DaiCursors> {
        self.dai().cursors(sensors, now)
    }

    /// Returns the first cursor time of `sensor`: the `now` of the cursor
    /// read that created its first cursor row, or `None` if none did.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn dai_first_cursor_time(&self, sensor: &str) -> Result<Option<i64>> {
        self.dai().first_cursor_time(sensor)
    }

    /// Stores one part of a send of DAI observations at the time `now`, in
    /// one optimistic transaction, and returns the outcome with the current
    /// restore generation.
    ///
    /// The checks run in this order:
    ///
    /// 1. If the send (sensor, kind, slot start, `send_id`) is finished under
    ///    the current restore generation, the outcome is
    ///    [`DaiStoreOutcome::Stored`] with the marks it returned, and nothing
    ///    is written.
    /// 2. If the sensor is not a customer sensor, or its customer has device
    ///    identification off, the outcome is
    ///    [`DaiStoreOutcome::NotCollected`], and nothing is written.
    /// 3. An invalid field is refused with a
    ///    [`DaiBatchError`](crate::DaiBatchError), writing nothing.
    /// 4. If the batch's restore generation, configuration epoch or network
    ///    digest is not the current one, or the sensor has no cursor row for
    ///    the batch kind or the kind of a late slot, the outcome is
    ///    [`DaiStoreOutcome::Resync`], and nothing is written.
    /// 5. If the send has earlier parts whose part count, check values or
    ///    send metadata differ from this part's, the send and its staged
    ///    parts are deleted, and the outcome is [`DaiStoreOutcome::Resync`].
    /// 6. Until the last missing part arrives, the part is staged and the
    ///    outcome is [`DaiStoreOutcome::Staged`].
    /// 7. The last missing part finishes the send: its observations are
    ///    filtered and stored, the catch-up skip, the re-extract mark, the
    ///    cursor, the catch-up gaps, the late-slot marks and the sensor's
    ///    state are updated, and the outcome is [`DaiStoreOutcome::Stored`]
    ///    with the marks assigned to the late slots. An observation of a slot
    ///    that started more than 7 days before `now` widens the summary
    ///    instead of a per-slot row, first folding into it the slot's
    ///    per-slot row that retention has not folded yet.
    ///
    /// The method reads the customer's `dai site policy guard` row for update
    /// before it reads the settings, the configuration epoch, the site or
    /// the networks, so a store racing a configuration write of the customer
    /// conflicts with it and is checked again.
    ///
    /// # Errors
    ///
    /// Returns, inside the error and writing nothing, a
    /// [`DaiBatchError`](crate::DaiBatchError) if `slot_len_secs` is not 300,
    /// `slot_start` or a late slot's start is not a multiple of 300 seconds,
    /// `part_count` is 0, `part` is not below `part_count`, or
    /// `counted_from` is outside the slot. Returns an error if the
    /// customer's networks cannot be encoded, if an enabled customer has no
    /// default site, or if the database operation fails.
    pub fn store_dai_observations(
        &self,
        batch: &DaiObservationBatch,
        now: i64,
    ) -> Result<DaiStoreOutcome> {
        self.dai().store_observations(batch, now)
    }

    /// Applies the DAI retention rules at the time `now`; the caller runs it
    /// periodically.
    ///
    /// It folds the per-slot observations whose slot started more than 7
    /// days ago into the summaries; deletes the pending observations whose
    /// slot started more than 30 days ago, counting each as not applied for
    /// its sensor's current customer, and, in the transaction that deletes a
    /// sensor's expired pending observations, recomputes its earliest
    /// pending slots and rewrites its resolver point, if it has one, as
    /// [`apply_dai_slot`](Self::apply_dai_slot) computes it; deletes the
    /// sends created more than one day ago, finished or not, with their
    /// staged parts; removes the re-extract marks whose slot started more
    /// than 30 days ago; and deletes the summaries and address activity last
    /// seen more than 180 days ago, the catch-up gaps that ended more than
    /// 180 days ago, and the counters, range blocks, range subnets and range
    /// days dated more than 30 days before the date of `now`. Ignored ranges
    /// stay.
    ///
    /// Then, for the device tables, it:
    ///
    /// 1. gives every binding with no end whose last strong evidence time
    ///    plus inactivity time is before `now` that time as its end, marked
    ///    estimated (a rule applying an observation timed before it treats
    ///    the binding as it did before the end was written);
    /// 2. makes every active device holding a MAC or an operator asset id
    ///    last seen more than 90 days ago "not seen", with one change entry
    ///    of source expiry; a hidden device stays hidden;
    /// 3. deletes, when their time is more than 180 days ago: the ended
    ///    bindings (by end) with their reverse index rows; the evidence (by
    ///    last seen), except binding evidence at or after the start of a
    ///    stored binding of its (site, IP) that has no end or ended within
    ///    180 days, which a recomputation may still replay; the device
    ///    aliases (by change time); the device changes (by time); the
    ///    conflicts (by last time); the services and software strings (by
    ///    last seen); the IP states (by the time of their order key); and the
    ///    earlier owners of an identifier (by the time the identifier left
    ///    them), except one whose device still has a stored binding with that
    ///    identifier as its evidence identifier;
    /// 4. removes the names of source DHCP or DNS last seen more than 180
    ///    days ago, with one change entry of source expiry per device; a name
    ///    an operator set never expires.
    ///
    /// Devices, identifiers and fixed IPs are never removed by retention.
    /// A step that changes a binding or evidence row reads the address's IP
    /// state for update first and writes it back.
    ///
    /// It commits in several transactions, each row's change atomic.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn apply_dai_retention(&self, now: i64) -> Result<()> {
        self.dai().apply_retention(now)
    }

    /// Applies up to `max_count` of the pending observations of `sensor`'s
    /// slot starting at `slot_start`, in apply order, and returns the
    /// sensor's resolver point.
    ///
    /// [`DAI_APPLY_DEFAULT_MAX_COUNT`](crate::DAI_APPLY_DEFAULT_MAX_COUNT)
    /// is the default `max_count`. In one optimistic transaction, retried
    /// from the start on a commit conflict, it applies the observations by
    /// the rules below, deletes them, recomputes the earliest pending slot of
    /// each (sensor, kind) it took observations of, and sets the sensor's
    /// resolver point: the earliest slot start among its remaining pending
    /// observations of any kind, or `None`, "caught up", if none remain. The
    /// resolver point is written even when nothing was applied, so a caller
    /// can call again for the sensor until it is caught up. `now` is used
    /// only for the date of a counter.
    ///
    /// The rules read only the pending observation (body, first seen, last
    /// seen), so the observations of a slot already folded into the
    /// summaries apply too. The customer is the sensor's current customer;
    /// the pending observations of a sensor that is not a customer sensor
    /// are deleted unapplied with a warning. The customer's settings are
    /// read at apply time and apply to this application only; device
    /// identification being off does not stop it.
    ///
    /// - **Order.** Observations apply by order key (time, rank, identifier
    ///   hash): the time is `DhcpLease.time` for O1 and the first seen time
    ///   otherwise; O1 messages rank DECLINE, RELEASE, ACK, INFORM ACK, and
    ///   the other kinds after them by kind number.
    /// - **Site.** An observation's site is the sensor's site at the slot
    ///   start. A relayed O1 (a `giaddr` that is not unspecified) takes the
    ///   relay site table's entry for its `server_ip` and `giaddr`, else,
    ///   for a customer that is not multi-site, the sensor's site; a
    ///   multi-site customer without an entry does not apply it and counts it
    ///   as relay DHCP whose site could not be determined. A customer without
    ///   a default site does not apply it and counts it as not applied.
    /// - **Evidence.** Every O1, O4 and O5 applied is indexed at its site and
    ///   IP; the same observation applied again (stored again with a filled
    ///   value or wider times, or from another sensor of the site) merges
    ///   into the evidence of its slot, kind and identifier hash and changes
    ///   no binding.
    /// - **Bindings.** O1 ACK, RELEASE and DECLINE and a verified O4 are
    ///   binding evidence, the only observations that start, extend or close
    ///   bindings. An ACK whose `chaddr` is a MAC (6 bytes, not all `00` or
    ///   `FF`, group bit 0) creates the MAC's device if no device holds it,
    ///   extends that device's open binding at the address, or closes another
    ///   device's and starts its own, with an inactivity time fixed from its
    ///   `lease_secs` and the settings; an ACK with any other `chaddr` closes
    ///   the open binding. RELEASE and DECLINE close the open binding with
    ///   their MAC and `server_id`. Past its last strong evidence time plus
    ///   inactivity time a binding counts as ended.
    /// - **Late evidence.** Binding evidence earlier in order than the latest
    ///   applied at its address recomputes that address's bindings from the
    ///   binding in effect at its time, replaying the stored evidence, so
    ///   the bindings equal those of applying everything in order under the
    ///   identifier ownership history.
    /// - **Evidence aging.** An ACK whose MAC was last confirmed more than the
    ///   evidence aging time before it moves the MAC to a new device, unless
    ///   its device has an operator asset id or is confirmed.
    /// - **Other kinds.** An INFORM ACK confirms the open binding of its MAC.
    ///   O4, O5, O3, O7, O8 and O22 act only on the device of the one binding
    ///   in effect over their whole first-to-last-seen range: they confirm
    ///   it, and a verified O4 attaches its machine account (or records a
    ///   conflict if another device holds it) and moves the binding's last
    ///   strong evidence time, O3 sets the DHCP server flag, O7 widens a
    ///   service, O8 a software string and O22 adds a DNS name. None of them
    ///   creates a device or a binding.
    /// - **History.** Each substantive device change increments its version
    ///   and writes one change entry.
    ///
    /// The transaction reads the customer's `dai site policy guard` row for
    /// update, without incrementing it, before the configuration, so a
    /// configuration write racing it conflicts; reads every `dai earliest
    /// pending` row of the sensor for update before it scans the slot, so a
    /// store adding an observation the scan misses conflicts; reads each
    /// pending observation it applies for update, so a store overwriting it
    /// conflicts; and reads each address's `dai ip state` row for update
    /// before its bindings or evidence, writing it whenever it changes them,
    /// so two applications at one address conflict.
    ///
    /// # Errors
    ///
    /// Returns an error, writing nothing, if `max_count` is 0, and an error
    /// if the database operation fails.
    pub fn apply_dai_slot(
        &self,
        sensor: &str,
        slot_start: i64,
        max_count: usize,
        now: i64,
    ) -> Result<Option<i64>> {
        self.dai().apply_slot(sensor, slot_start, max_count, now)
    }

    /// Returns, ordered by sensor name, every sensor with pending DAI
    /// observations and its earliest pending slot start, of any kind.
    ///
    /// Sensors that are not customer sensors are listed too. A caller uses
    /// it to find the (sensor, slot) to pass to
    /// [`apply_dai_slot`](Self::apply_dai_slot) next.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn dai_pending_heads(&self) -> Result<Vec<DaiPendingHead>> {
        self.dai().pending_heads()
    }
}
