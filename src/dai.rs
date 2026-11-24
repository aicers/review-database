//! The configuration of device identification (DAI): the settings, the sites,
//! the relay site table, the sensor site history and the configuration
//! epochs of each customer's sensors.
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

use anyhow::Result;

use crate::{
    DaiRelaySite, DaiRelaySites, DaiSettings, DaiSettingsUpdate, DaiSite, Store,
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

    /// Deletes the customer's rows from the DAI configuration tables.
    ///
    /// The sensor names it works on are fixed as it starts: `sensors`, the
    /// names the customer's sites list, and the customer's sensors per the
    /// node table. A name of `sensors` with no row is not an error; pass the
    /// names of the customer's sensors whose agents a customer data deletion
    /// has already removed from the node table.
    ///
    /// It deletes, in this order and in separate transactions: every sensor
    /// site history row naming the customer, and the sensor state rows of
    /// those names, except a name the node table shows, as the method
    /// starts, as a sensor of another customer; then the customer's
    /// settings, sites, relay site table and site policy guard. An
    /// interrupted call repeated with the same names removes the rest, and a
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
}
