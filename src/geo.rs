use std::{net::IpAddr, sync::Arc};

use anyhow::Result;

pub(crate) trait CountryLookup: Send + Sync {
    fn lookup(&self, addr: IpAddr) -> Result<Option<[u8; 2]>>;
}

pub(crate) type SharedCountryLookup = Arc<dyn CountryLookup>;

pub(crate) struct Ip2LocationResolver {
    db: ip2location::DB,
}

impl Ip2LocationResolver {
    pub(crate) fn new(db: ip2location::DB) -> Self {
        Self { db }
    }
}

impl CountryLookup for Ip2LocationResolver {
    fn lookup(&self, addr: IpAddr) -> Result<Option<[u8; 2]>> {
        let record = self.db.ip_lookup(addr)?;
        Ok(crate::util::record_country_code(&record))
    }
}

impl CountryLookup for ip2location::DB {
    fn lookup(&self, addr: IpAddr) -> Result<Option<[u8; 2]>> {
        let record = self.ip_lookup(addr)?;
        Ok(crate::util::record_country_code(&record))
    }
}
