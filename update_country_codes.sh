#!/bin/bash

# This script updates all remaining event files to add country codes to syslog_rfc5424 and Display implementations
# Pattern to add after orig_port: orig_country_code={:?}
# Pattern to add after resp_port: resp_country_code={:?}
# Value to add: std::str::from_utf8(&self.orig_country_code).unwrap_or("XX")
# Value to add: std::str::from_utf8(&self.resp_country_code).unwrap_or("XX")

# For plural country codes (orig_country_codes, resp_country_codes):
# Create a variable first:
# let orig_country_codes_str = self.orig_country_codes.iter().map(|cc| std::str::from_utf8(cc).unwrap_or("XX")).collect::<Vec<_>>().join(",");

echo "This script serves as documentation for the remaining updates needed:"
echo ""
echo "Files still needing updates:"
echo "1. dns.rs - LockyRansomware, CryptocurrencyMiningPoolFields, CryptocurrencyMiningPool, BlocklistDnsFields, BlocklistDns"
echo "2. ftp.rs - FtpBruteForceFields, FtpBruteForce, FtpEventFields, FtpPlainText, BlocklistFtp"
echo "3. http.rs - HttpEventFields, RepeatedHttpSessionsFields, RepeatedHttpSessions, HttpThreatFields, HttpThreat, DgaFields, DomainGenerationAlgorithm, NonBrowser, BlocklistHttp"
echo "4. network.rs - NetworkThreat"
echo "5. kerberos.rs - BlocklistKerberosFields, BlocklistKerberos"
echo "6. ldap.rs - LdapBruteForceFields, LdapBruteForce, BlocklistLdapFields, BlocklistLdap"
echo "7. mqtt.rs - BlocklistMqttFields, BlocklistMqtt"
echo "8. nfs.rs - BlocklistNfsFields, BlocklistNfs"
echo "9. ntlm.rs - BlocklistNtlmFields, BlocklistNtlm"
echo "10. radius.rs - BlocklistRadiusFields, BlocklistRadius"
echo "11. rdp.rs - BlocklistRdpFields, BlocklistRdp"
echo "12. smb.rs - BlocklistSmbFields, BlocklistSmb"
echo "13. smtp.rs - BlocklistSmtpFields, BlocklistSmtp"
echo "14. ssh.rs - BlocklistSshFields, BlocklistSsh"
echo "15. tls.rs - BlocklistTlsFields, BlocklistTls"
echo "16. malformed_dns.rs - (if it exists and has country code fields)"
echo ""
echo "Pattern for single country codes:"
echo "  In syslog_rfc5424 format string: orig_port={:?} orig_country_code={:?} resp_addr={:?} resp_port={:?} resp_country_code={:?}"
echo "  In parameter list: std::str::from_utf8(&self.orig_country_code).unwrap_or(\"XX\")"
echo ""
echo "Pattern for plural country codes (e.g., ExternalDdos):"
echo "  Add before format!: let orig_country_codes_str = self.orig_country_codes.iter().map(|cc| std::str::from_utf8(cc).unwrap_or(\"XX\")).collect::<Vec<_>>().join(\",\");"
echo "  In format string: orig_country_codes={:?}"
echo "  In parameter list: orig_country_codes_str"
