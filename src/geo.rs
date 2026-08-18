use std::{net::IpAddr, sync::Arc};

pub(crate) trait CountryLookup: Send + Sync {
    fn lookup_country_code(&self, addr: IpAddr) -> [u8; 2];
}

pub(crate) type SharedCountryLookup = Arc<dyn CountryLookup>;

pub(crate) struct Ip2LocationResolver {
    db: Arc<ip2location::DB>,
}

impl Ip2LocationResolver {
    pub(crate) fn new(db: Arc<ip2location::DB>) -> Self {
        Self { db }
    }
}

impl CountryLookup for Ip2LocationResolver {
    fn lookup_country_code(&self, addr: IpAddr) -> [u8; 2] {
        crate::util::lookup_country_code(&self.db, addr)
    }
}
