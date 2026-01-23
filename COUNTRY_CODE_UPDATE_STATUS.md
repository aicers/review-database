# Country Code Fields Update Status

## Summary
This document tracks the progress of adding country code fields (orig_country_code, resp_country_code) to all Display and syslog_rfc5424 implementations in src/event/ files.

## Pattern to Follow

### For Single Country Codes ([u8; 2])
**In syslog_rfc5424 format string:**
```rust
"... orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?} ..."
```

**In parameter list:**
```rust
std::str::from_utf8(&self.orig_country_code).unwrap_or("XX"),
std::str::from_utf8(&self.resp_country_code).unwrap_or("XX"),
```

### For Plural Country Codes (Vec<[u8; 2]>)
**Add before format! macro:**
```rust
let orig_country_codes_str: Vec<String> = self.orig_country_codes.iter()
    .map(|cc| std::str::from_utf8(cc).unwrap_or("XX").to_string())
    .collect();
let resp_country_codes_str: Vec<String> = self.resp_country_codes.iter()
    .map(|cc| std::str::from_utf8(cc).unwrap_or("XX").to_string())
    .collect();
```

**In format string:**
```rust
"... orig_country_codes={:?} ... resp_country_codes={:?} ..."
```

**In parameter list:**
```rust
vector_to_string(&orig_country_codes_str),
vector_to_string(&resp_country_codes_str),
```

## Completed Files

### ✅ src/event/conn.rs
- [x] PortScanFields::syslog_rfc5424
- [x] PortScan::Display
- [x] MultiHostPortScanFields::syslog_rfc5424 (with plural country codes)
- [x] MultiHostPortScan::Display (with plural country codes)
- [x] ExternalDdosFields::syslog_rfc5424 (with plural country codes)
- [x] ExternalDdos::Display (with plural country codes)
- [x] BlocklistConnFields::syslog_rfc5424
- [x] BlocklistConn::Display

### ✅ src/event/network.rs
- [x] NetworkThreat::syslog_rfc5424
- [x] NetworkThreat::Display

### ✅ src/event/http.rs
- [x] HttpEventFields::syslog_rfc5424
- [x] RepeatedHttpSessionsFields::syslog_rfc5424
- [x] RepeatedHttpSessions::Display
- [x] HttpThreatFields::syslog_rfc5424
- [x] HttpThreat::Display
- [x] DgaFields::syslog_rfc5424
- [x] DomainGenerationAlgorithm::Display
- [x] NonBrowser::Display
- [x] BlocklistHttp::Display

### ⏳ src/event/dns.rs (Partially Complete)
- [x] DnsEventFields::syslog_rfc5424
- [x] DnsCovertChannel::Display
- [x] LockyRansomware::Display
- [x] CryptocurrencyMiningPoolFields::syslog_rfc5424
- [ ] CryptocurrencyMiningPool::Display
- [ ] BlocklistDnsFields::syslog_rfc5424
- [ ] BlocklistDns::Display

## Remaining Files

The following files need to be updated following the same pattern:

### src/event/dns.rs (Complete remaining types)
- [ ] CryptocurrencyMiningPool::Display
- [ ] BlocklistDnsFields::syslog_rfc5424
- [ ] BlocklistDns::Display

### src/event/rdp.rs
- [ ] BlocklistRdpFields::syslog_rfc5424
- [ ] BlocklistRdp::Display

### src/event/tls.rs
- [ ] BlocklistTlsFields::syslog_rfc5424
- [ ] BlocklistTls::Display

### src/event/smtp.rs
- [ ] BlocklistSmtpFields::syslog_rfc5424
- [ ] BlocklistSmtp::Display

### src/event/ssh.rs
- [ ] BlocklistSshFields::syslog_rfc5424
- [ ] BlocklistSsh::Display

### src/event/ftp.rs
- [ ] FtpBruteForceFields::syslog_rfc5424
- [ ] FtpBruteForce::Display
- [ ] FtpEventFields::syslog_rfc5424 (if exists)
- [ ] FtpPlainText::Display (if exists)
- [ ] BlocklistFtp::Display

### src/event/kerberos.rs
- [ ] BlocklistKerberosFields::syslog_rfc5424
- [ ] BlocklistKerberos::Display

### src/event/ldap.rs
- [ ] LdapBruteForceFields::syslog_rfc5424
- [ ] LdapBruteForce::Display
- [ ] BlocklistLdapFields::syslog_rfc5424
- [ ] BlocklistLdap::Display

### src/event/ntlm.rs
- [ ] BlocklistNtlmFields::syslog_rfc5424
- [ ] BlocklistNtlm::Display

### src/event/smb.rs
- [ ] BlocklistSmbFields::syslog_rfc5424
- [ ] BlocklistSmb::Display

### src/event/mqtt.rs
- [ ] BlocklistMqttFields::syslog_rfc5424
- [ ] BlocklistMqtt::Display

### src/event/nfs.rs
- [ ] BlocklistNfsFields::syslog_rfc5424
- [ ] BlocklistNfs::Display

### src/event/radius.rs
- [ ] BlocklistRadiusFields::syslog_rfc5424
- [ ] BlocklistRadius::Display

### src/event/dcerpc.rs
- [ ] Check for types with country codes

### src/event/bootp.rs
- [ ] Check for types with country codes

### src/event/dhcp.rs
- [ ] Check for types with country codes

### src/event/malformed_dns.rs
- [ ] Check for types with country codes

### src/event/tor.rs
- [ ] Check for types with country codes

### src/event/unusual_destination_pattern.rs
- [ ] Check for types with country codes

### src/event/sysmon.rs
- [ ] Check for types with country codes

### src/event/log.rs
- [ ] Check for types with country codes

## Testing
After all updates are complete, run:
```bash
cargo test
cargo clippy
cargo build --release
```

## Notes
- All structs with `orig_country_code: [u8; 2]` and `resp_country_code: [u8; 2]` fields need updates
- For plural variants (`orig_country_codes: Vec<[u8; 2]>`), use the vector conversion pattern
- The country code conversion handles invalid UTF-8 by defaulting to "XX"
- Make sure to add country codes AFTER port fields and BEFORE proto/other fields for consistency
