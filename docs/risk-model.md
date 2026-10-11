# Risk model `risk-v1`

GnomeHome scores every non-protected asset once a day (FR-05) on a 0–100 scale. Every point comes from
a named factor with a plain-English reason, so the top risks are always explainable (Phase 3's
"done when"). The code lives in `python/gnomehome/risk.py`. `just risks` prints the factors.

## Inputs

| Input | Source | Refresh |
| --- | --- | --- |
| Open services, product, version, CPE | nmap service scan | every 4 hours |
| CVEs for each software version | NVD CVE API 2.0, re-checked locally against each CVE's configuration rules | daily |
| Probability of exploitation in the next 30 days | FIRST EPSS (percentile) | daily |
| Known exploited in the wild | CISA KEV catalog | daily |
| Device type, manufacturer | nmap OS detection, MAC vendor | every 4 hours |

## Formula

```
score = min(100, vulnerabilities + exposure + context)
```

**Vulnerabilities.** For each CVE matched to a service that is currently open (seen within 24 hours of the
asset's latest scan):

```
cve_points = CVSS × 10 × likelihood
likelihood = 1.0                              if the CVE is in CISA KEV
           = 0.25 + 0.75 × EPSS percentile    otherwise
```

Missing values are filled in conservatively, and the factor says so: CVSS 5.0, or the 50th percentile.
The worst CVE counts in full. Each other serious CVE (40 points or more) adds 5, up to 20, so ten
medium CVEs don't outweigh one exploited critical.

**Exposure.** Risky open ports add fixed points with a reason, for example Telnet 15, SMB 10, Remote
Desktop 10, VNC 10, FTP 8, RTSP 6, MQTT 6, UPnP 5. Every other open port adds 1, up to 10.

**Context.** Network equipment (router, access point) adds 5 because it carries everyone's traffic.
IoT device types (cameras, media devices, printers) add 5 because they're rarely updated. An unknown
manufacturer adds 3.

## Levels

| Level | Score | Shown as |
| --- | --- | --- |
| Low | under 30 | garden green, sprout icon |
| Medium | 30–59 | lantern amber, lantern icon |
| High | 60–79 | hat red, hat icon, bold word |
| Critical | 80+ | hat red, hat icon, bold word |

A CVE listed in KEV makes the asset at least **high**, whatever the arithmetic says.

## Why these choices

- **Likelihood beats severity.** EPSS and KEV say whether a flaw is actually being used. A CVSS 9.8 nobody
  exploits ranks below a CVSS 7.5 in KEV.
- **No false precision.** One decimal place, round point values, and the factor list is the explanation.
- **Version matching is ours, not NVD's.** NVD's search returns any CVE whose configuration *mentions* the
  product, even as a non-vulnerable platform. Each match is re-checked against the vulnerable rule's
  version range, so `match_method` and `confidence` are recorded per match.
- **Protected assets are never scored.** They have no services, by schema.

## Known gaps

- Services without a version banner can't be matched to CVEs (a data-quality issue the plan accepts).
  They still count as exposure.
- OS-level CVEs from nmap's OS guess aren't matched, because the guesses are ranges that are too broad.
- Weights are judgment calls for a home network. Phase 6 can check them against the gold-layer history.
