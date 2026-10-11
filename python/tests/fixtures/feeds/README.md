# Feed fixtures

Recorded or hand-made responses for the enrichment tests. No test touches the network.

- `nvd_dnsmasq_2.85.json`: three **real** NVD records for dnsmasq (fetched 2026-10-11, trimmed to the
  fields GnomeHome reads) plus **fake** `CVE-2099-*` records for edge cases (exact version, a
  non-vulnerable platform rule, a rejected CVE, a range that excludes 2.85, a missing CVSS score).
- `nvd_openssh_7.4.json`: one fake record.
- `kev.json`: real KEV format with one fake entry (`CVE-2099-0101`) and one real, trimmed entry.
- `epss.json`: real EPSS response format. Values for the fake CVEs are made up.
