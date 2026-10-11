# GnomeHome Project Plan

Oct 11, 2026 · @Nick

## Overview

A hardened home network detection and response (NDR) system with a Raspberry Pi 3B+ as the sensor and first responder, Azure for the control plane, and Azure Databricks for analytics and ML. It doubles as a data, cloud, network, and AI engineering portfolio piece.

**Goals**

- Know every device on the home network, what it runs, and how exposed it is
- Score risk per asset using CVE, EPSS, and CISA KEV data
- Detect suspicious behavior from DNS and connection data and explain it in plain English
- Respond through an automated Blue Team with human approval for anything disruptive
- Hold a weekly AI check-in that summarizes what happened on the network

**Scope**

Phases 1 through 3 (foundation, asset inventory, risk scoring) are the minimum complete project. Everything after is upside.

**Out of scope for now**

- Always-on full packet capture of all traffic
- Inline firewalling of the whole network
- Anything beyond the home network

## Business understanding

Home networks have no security team. GnomeHome gives one household the core of a SOC (inventory, risk scoring, detection, and response) on a $35 computer, and reports it the way a risk team would.

**Problem statement**

The owner cannot currently answer four questions about the home network. What devices are on it, which are vulnerable, which are behaving strangely, and what was done about it.

**Stakeholders**

| Stakeholder | Interest | Involvement |
| --- | --- | --- |
| Owner | Visibility, control, portfolio value | Builds, operates, approves responses |
| Household members | Privacy, uninterrupted internet | Consent to DNS logging, unaffected by false positives |
| Employer (indirect) | Work laptop never touched | Protected asset list |
| Portfolio reviewers | Evidence of data, cloud, security, and AI engineering skill | Read the repo, docs, and demo |

**Success criteria and KPIs**

| KPI | Target |
| --- | --- |
| Devices inventoried out of devices present | 100% |
| Time from new device joining to alert | Under 15 minutes |
| Assets with a current risk score | 100%, refreshed daily |
| Known-bad domain lookups blocked automatically | 100% of feed matches |
| Disruptive actions taken without approval | 0 |
| Packets sent to protected assets | 0 |
| Monthly Azure spend | Under $25 budget alert |
| Weekly AI check-in delivered | Every week |

## Data understanding

Six internal sources and four external feeds. DNS queries are the highest-volume and most sensitive data, so they get the shortest local retention and the protected-asset filter before storage.

**Internal sources**

| Source | Key fields | Frequency | Sensitivity | Local retention |
| --- | --- | --- | --- | --- |
| Pi-hole DNS log | timestamp, client IP, domain, query type, status (allowed or blocked) | Continuous | High, reveals browsing | 30 days |
| nmap scans | IP, MAC, vendor, open ports, service, version banner, OS guess | Every few hours | Medium | 90 days |
| Router DHCP leases | MAC, IP, hostname, lease time | On change | Medium | 90 days |
| Router syslog | timestamp, facility, message (firewall drops, logins, DHCP events) | Continuous | Medium | 30 days |
| Router connection table | source IP, destination IP, ports, protocol, bytes, state | Every minute over SSH | High | 30 days |
| GnomeHome audit log | timestamp, user, action, target, result, previous hash | On every action | High | Never deleted |

**External feeds**

| Feed | Used for | Refresh |
| --- | --- | --- |
| NVD CVE API | CVEs and CVSS by CPE | Daily |
| FIRST EPSS | Probability a CVE is exploited | Daily |
| CISA KEV catalog | CVEs known to be exploited in the wild | Daily |
| Threat intel domain lists | Known-bad domains | Daily |

**Core entities**

- **Asset.** One per MAC, with protected flag, device type, first and last seen
- **Service.** One per asset, port, and protocol, mapped to a CPE
- **Vulnerability.** CVE linked to a service, with CVSS, EPSS, and KEV status
- **Risk score.** One per asset per day
- **Event.** A DNS query, flow, or log line tied to an asset
- **Incident.** A detection with its plain-English summary, playbook run, and outcome

**Medallion layers in Databricks**

| Layer | Contents |
| --- | --- |
| Bronze | Raw uploads from the Pi, unchanged, partitioned by date |
| Silver | Cleaned, deduplicated, typed, joined to assets |
| Gold | Daily risk scores, incident facts, device behavior features, model outputs |

**Known data quality issues**

- Devices using hardcoded DNS or DNS over HTTPS will be missing from DNS data
- Randomized MACs on phones can make one device look like several
- Version banners are often missing, so CPE matching will have gaps
- Router connection pulls can break after firmware updates

## Environment and constraints

The Pi is a weak box and the router runs stock firmware, so the Pi collects and does light processing while heavy work happens in the cloud.

| Component | Detail | Constraint it creates |
| --- | --- | --- |
| Raspberry Pi 3B+ | 1GB RAM, gigabit port capped near 300 Mbps by USB 2.0, no ARM AES acceleration | No full Suricata or Zeek at scale, no inline firewall, no on-device LLM, no on-device Rust builds |
| ASUS RT-AX3000 V2 | Stock ASUS firmware, 4 cores confirmed | No Asuswrt-Merlin, so no softflowd, no startup scripts, iptables rules lost on reboot |
| Network switch | None | Not needed. Mirroring a switch port would miss Wi-Fi traffic |
| Pi connection | Wired to a router LAN port | Pi is required for DNS while Pi-hole is primary |

**What the router can still provide**

- DNS server setting under LAN, then DHCP Server, pointed at the Pi
- Remote syslog to the Pi
- SSH (Administration, then System) for reading the connection table and pushing temporary block rules
- Per-device internet block, reachable Ithrough the unofficial asusrouter Python library

## Functional requirements

| ID | Requirement | Phase |
| --- | --- | --- |
| FR-01 | Discover all devices on a schedule with nmap and router DHCP data | 2 |
| FR-02 | Keep an asset table with MAC vendor, open ports, services, first seen, and last seen | 2 |
| FR-03 | Alert when a new device joins the network | 2 |
| FR-04 | Map services to CPEs and pull matching CVEs from NVD | 3 |
| FR-05 | Score each asset using CVSS, EPSS, CISA KEV, and exposure factors like open ports and device type | 3 |
| FR-06 | Log every DNS query per device through Pi-hole | 1 |
| FR-07 | Collect router syslog on the Pi | 1 |
| FR-08 | Pull per-device connection data from the router over SSH | 4 |
| FR-09 | Detect new domains per device, DNS beaconing, and DGA-style domains | 4 |
| FR-10 | Match DNS queries against free threat intel feeds of known-bad domains | 4 |
| FR-11 | Write alerts to a plain-English incident log with timestamp, device, what happened, and why it matters | 5 |
| FR-12 | Run anomaly detection and a device-type classifier in Databricks | 6 |
| FR-13 | Quarantine a device through the router block feature or a temporary iptables rule | 7 |
| FR-14 | Capture one suspicious device's traffic on demand via ARP spoofing for deeper inspection | 7 |
| FR-15 | Run playbooks that detect, enrich, decide, act, and report, with tiered automation | 7 |
| FR-16 | Send push notifications through Azure Monitor to the Azure mobile app on iPhone, with minimal payloads. Approve or deny in the dashboard | 7 |
| FR-17 | Run a weekly self-assessment covering new devices, newly exposed ports, and new CVEs | 7 |
| FR-18 | Hold a weekly AI agent check-in summarizing network activity | 8 |
| FR-19 | Serve a live dashboard on the Pi and an executive view in Power BI | 3 and later |

## Non-functional requirements

| ID | Category | Requirement |
| --- | --- | --- |
| NFR-01 | Security | Every user-facing surface requires authentication, MFA, and role-based authorization |
| NFR-02 | Security | All traffic between components uses mutual TLS or WireGuard. Nothing talks to anything unverified |
| NFR-03 | Security | Data encrypted at rest on the Pi (LUKS with Adiantum) and in Azure (customer-managed keys) |
| NFR-04 | Security | The AI agent communicates only with components inside this architecture |
| NFR-05 | Security | No component is exposed to the internet. Remote access only through Tailscale or WireGuard |
| NFR-06 | Security | Every login and action lands in a tamper-evident, hash-chained audit log |
| NFR-07 | Performance | Pi services fit within 1GB RAM with headroom for Pi-hole |
| NFR-08 | Performance | Heavy parsing and chart prep happen in the browser through Wasm, not on the Pi |
| NFR-09 | Reliability | Router keeps a backup DNS server so lookups survive a Pi outage |
| NFR-10 | Reliability | Pi runs on a reliable power supply |
| NFR-11 | Cost | Azure spend stays under a budget alert set on day one (starting point $25 a month) |
| NFR-12 | Maintainability | Rust dependencies checked with cargo audit on every build |
| NFR-13 | Maintainability | Playbooks written as YAML and mapped to MITRE ATT&CK |

## Architecture

The Pi is the sensor and first responder, the Container App runs the AI agent and weekly reports, and Databricks is the analytics layer. Every link between them runs over WireGuard with mutual TLS.

&#91;embedded content: system architecture · 3 zones, 9 components\]

DNS, syslog, and connection data land in SQLite on the Pi, ship nightly to ADLS, and become Delta tables that feed Power BI.

**Tech stack**

| Layer | Choice |
| --- | --- |
| Collectors | Pi-hole, nmap, router syslog, SSH pulls of the router connection table |
| Local storage | SQLite on the Pi |
| Backend | Rust with Axum, cross-compiled with `cross` |
| Frontend | Rust compiled to WebAssembly (Leptos), doing parsing, aggregation, and chart prep in the browser to keep load off the Pi |
| Response | Rust playbook engine with YAML playbooks, Pi-hole and router blocking, push notifications |
| Cloud services | Azure Container Apps for the AI agent, weekly report, and push notification relay. The Pi keeps collectors, dashboard, and playbooks so response works if the cloud is down |
| Secrets and keys | Azure Key Vault Standard, private step-ca for 24-hour certs, YubiKey |
| Analytics | Azure Databricks serverless with Unity Catalog, Delta tables, serverless SQL warehouse |
| Reporting | Power BI, plus a live dashboard served by the Rust backend |
| AI agent | Azure OpenAI in the owner's tenant, called from the Container App |
| Remote access | Tailscale or WireGuard |

**Language split**

Rust runs everything always-on or security-critical. Python runs data work and anything with a strong Python library. SQLite in WAL mode is the contract between them, so neither side calls the other directly.

| Language | Owns | Why |
| --- | --- | --- |
| Rust | Axum API and dashboard backend, Wasm frontend (Leptos), playbook engine, audit log, DNS log tailer | Long-running on a 1GB Pi, so low memory and memory safety matter most |
| Python | nmap orchestration, NVD, EPSS, and KEV enrichment, risk scoring, DNS analytics (beaconing, DGA), router control via asusrouter | Best libraries for the job. Runs as scheduled systemd timers, not daemons, so it only uses RAM while working |
| Python (PySpark) | Databricks jobs, anomaly detection, device classifier | Native language of Databricks |
| Python | AI check-in agent in the Container App | Azure OpenAI SDK and agent tooling are strongest in Python |

When a Rust playbook needs a Python-only capability, like quarantining through asusrouter, it runs a small Python helper script with fixed arguments. PyO3 bindings for shared code are a later option.

## Workflows

Three processes drive GnomeHome. Detection and response runs on every alert, the data pipeline runs nightly, and the AI check-in runs weekly. Diagrams follow BPMN 2.0 notation, with thin circles for start events, bold circles for end events, rounded boxes for tasks, and X diamonds for exclusive gateways.

**Detection and response**

&#91;embedded content: BPMN, detection and response · 3 lanes, 3 gateways\]

The protected-asset check runs before anything else, so the work laptop can never reach a response step. Only high-confidence, low-impact actions run automatically.

**Nightly data pipeline**

&#91;embedded content: BPMN, nightly data pipeline · 3 lanes, 1 gateway\]

A failed Databricks job stops before Power BI refreshes, so reports never show half-processed data, and the failure alert goes to the Azure app.

**Weekly AI check-in**

1. Container App job starts on a weekly schedule
2. Reads the week's gold-layer summaries (new devices, risk changes, incidents, playbook outcomes)
3. Sends the summary to Azure OpenAI with a fixed prompt that treats all network data as untrusted
4. Writes the check-in report and pushes a notification to the Azure app
5. Owner reviews the report in the dashboard and replies with questions or follow-ups
6. Any suggested action enters the detection and response flow above, at the approval step

## Security design

The Pi is the highest-value target because it holds router admin access and sees every DNS query, so it gets the strictest controls. MITM is defeated by authentication on both ends, not by stacking ciphers.

**AAA**

- **Authentication.** Local accounts with Argon2 password hashing, plus passkeys or TOTP for MFA
- **Authorization.** Viewer, analyst, and admin roles. Quarantine and other disruptive actions require admin plus a fresh MFA check
- **Accounting.** Append-only audit log of every login and action, hash-chained so tampering shows, also shipped to Databricks

**Hardening on the Pi**

- HTTPS only, secure session cookies, CSRF protection
- Each component runs as its own unprivileged user, sandboxed with systemd settings
- Packet-capture capabilities granted only to the binaries that need them
- Key-only SSH and a host firewall that allows the dashboard only from the LAN
- Rust binaries cross-compiled on a laptop with `cross`, never built on the Pi

**Encryption and keys**

| Layer | Control |
| --- | --- |
| In transit, Pi to Azure | WireGuard tunnel |
| In transit, service to service | Mutual TLS with certs from a private step-ca, issued for 24 hours |
| At rest, Pi | Full-disk LUKS using Adiantum, since the Pi 3 lacks AES hardware acceleration |
| At rest, Azure | Customer-managed keys in Key Vault Standard for storage and Databricks |
| Admin and signing | YubiKey held only by the owner |

Session keys already rotate constantly under WireGuard and TLS 1.3. The 24-hour certificates provide the daily key change. No custom or layered ciphers.

## Automated Blue Team and AI check-in

The Blue Team is a small SOAR engine in Rust. Each detection runs a YAML playbook that detects, enriches, decides, acts, and reports.

| Tier | When | Example |
| --- | --- | --- |
| Auto-act | High confidence, low impact | Block a known-bad domain in Pi-hole |
| Ask first | Disruptive to a device or user | Quarantine a device after push notification approval |
| Scheduled | Weekly | Self-assessment of new devices, newly exposed ports, and new CVEs |

**AI check-in agent**

- Runs weekly and summarizes network activity so the owner and the Blue Team stay aligned
- Model runs in Azure OpenAI inside the owner's tenant, called from the Container App. It never runs on the Pi
- Reads curated summaries only, never raw logs, with read-only access
- Any action it suggests goes through the same approval tiers as the Blue Team
- Treats every hostname, DNS query, and packet field as untrusted data, since a malicious device can plant prompt injection text in them

## Design system

GnomeHome looks like a classic garden gnome standing guard in a well-kept garden. Red hat, blue tunic, white beard, brown belt, black boots, and garden green, all checked against WCAG 2.2 AA in light and dark themes.

**Color tokens, light theme**

Background `#FBF7EF` (mushroom cream), surface `#FFFFFF`. Ratios are measured against the cream background.

| Token | Name | Hex | Contrast | Use |
| --- | --- | --- | --- | --- |
| text | Boot black | `#1F1A17` | 16.1:1 | Body text, headings |
| text-secondary | Soil | `#5A4F47` | 7.4:1 | Labels, captions |
| primary | Hat red | `#B3261E` | 6.1:1 | Primary buttons, brand, critical status |
| secondary | Tunic blue | `#1F4E9C` | 7.5:1 | Links, info status, focus ring |
| success | Garden green | `#2E6B3A` | 6.0:1 | Healthy, approved, low risk |
| warning | Lantern amber | `#8A5A00` | 5.6:1 | Medium risk, pending approval |
| accent | Belt brown | `#6B4423` | 7.9:1 | Section rules, secondary emphasis |
| border | Stone | `#8C7F73` | 3.6:1 | Input borders, dividers on controls |

White beard text `#FFFFFF` on hat red is 6.5:1, on tunic blue 8.0:1, and on garden green 6.4:1, so all three work as filled buttons.

**Color tokens, dark theme**

Background `#14181A` (night garden), surface `#1E2427`. Ratios are measured against the night background.

| Token | Name | Hex | Contrast |
| --- | --- | --- | --- |
| text | Beard white | `#F3EEE6` | 15.5:1 |
| text-secondary | Moss gray | `#BDB3A7` | 8.7:1 |
| primary | Hat red, lit | `#FF8A7A` | 7.8:1 |
| secondary | Tunic blue, lit | `#8AB4F8` | 8.5:1 |
| success | Garden green, lit | `#7DCB8A` | 9.2:1 |
| warning | Lantern amber, lit | `#F2C14E` | 10.7:1 |
| accent | Belt brown, lit | `#D4A373` | 7.9:1 |
| border | Stone, night | `#6F7A80` | 4.1:1 |

Filled buttons in dark mode use night background text `#14181A` on the lit colors.

**Risk scale**

Risk always shows as a word and an icon, never color alone. Low uses garden green with a sprout icon, medium uses lantern amber with a lantern icon, high and critical use hat red with a hat icon and the word in bold.

**Typography**

- Headings in a rounded humanist sans with storybook warmth, such as Nunito
- Body in a highly legible sans, such as Atkinson Hyperlegible, built for low-vision readers
- Data and code in a monospace, such as JetBrains Mono
- Body text at least 16px, line height 1.5, and layouts that survive 200% zoom and 400% reflow

**Iconography**

- Logomark is a simple gnome face (red pointed hat over a white beard, two dot eyes, no other features), original artwork in a flat, classic garden-statue style
- Line icons at a 2px stroke on a 24px grid, round caps and joins, one color
- Themed set for core concepts. Hat for alerts, lantern for the risk scale, watering can for scans, shovel for quarantine, garden fence for protected assets, mushroom for unknown devices, sprout for new devices, and a sleeping gnome for the Pi being offline
- Every icon that carries meaning has a text label or accessible name. Decorative icons are hidden from screen readers

**Mascot and voice**

- The gnome appears in empty states, the login screen, and the weekly check-in header, never inside data views
- Copy is plain and calm, with light gnome flavor only in empty states, like "All quiet in the garden. 14 devices, no new alerts"
- Alerts and incident text stay strictly factual

**Accessibility requirements (WCAG 2.2 AA)**

- Text contrast at least 4.5:1, large text and UI components at least 3:1
- Status never conveyed by color alone
- Visible focus ring in tunic blue, at least 2px, on every interactive element
- Full keyboard operation, logical tab order, and a skip-to-content link
- Touch and click targets at least 24 by 24px, 44 by 44px on mobile
- Respect prefers-reduced-motion and prefers-color-scheme
- Charts include a data table view and text summary
- Live alerts announced through an ARIA live region, politely
- Session timeouts warn first and allow extension
- Automated checks with axe in CI, plus a manual screen reader pass with VoiceOver before each release

## Build phases

Phases 1 through 3 make a complete project. The Rust dashboard and playbooks come after that foundation works.

1. **Foundation.** Flash Raspberry Pi OS Lite 64-bit, disable IPv6 on the router, wire the Pi to the router, install Pi-hole, set it as the router's DHCP DNS with a backup DNS, point router syslog at the Pi.
   - Done when DNS queries from every device show up in Pi-hole
2. **Asset inventory.** Scheduled nmap scans plus router DHCP data into a SQLite device table, with new-device alerts.
   - Done when every known device appears with vendor, ports, and services
3. **Vulnerability and risk scoring.** CPE mapping, NVD CVE pulls, CVSS, EPSS, and KEV weighting into a per-asset score.
   - Done when each asset has a score and the top risks are explainable
4. **Behavior monitoring.** DNS analytics (new domains, beaconing, DGA), threat intel matching, then router connection pulls over SSH.
5. **Plain-English incident log.** Alerts become readable entries.
6. **Cloud and ML.** Pi ships data nightly to ADLS Gen2, serverless Databricks jobs build Delta tables, anomaly detection and device classifier, serverless SQL warehouse feeds Power BI.
7. **Response and Blue Team.** Quarantine, on-demand capture, YAML playbooks, push approvals, weekly self-assessment.
8. **Rust and Wasm dashboard with AAA, then the AI check-in agent.**

## Risk register

| ID | Risk | Likelihood | Impact | Treatment | Control |
| --- | --- | --- | --- | --- | --- |
| R-01 | Pi compromise exposes router admin access and full DNS history | Low | High | Mitigate | Hardening, key-only SSH, LUKS, LAN-only dashboard, audit log |
| R-02 | Pi outage breaks DNS for the whole house | Medium | Medium | Mitigate | Backup DNS on the router, reliable power supply, heartbeat alert |
| R-03 | Automated quarantine blocks a legitimate device | Medium | Medium | Mitigate | Disruptive actions require approval |
| R-04 | Prompt injection through hostnames, DNS names, or packet data steers the AI agent | Medium | Medium | Mitigate | Agent is read-only, reads curated summaries, actions go through approval tiers |
| R-05 | Databricks serverless compute runs outside the owner's virtual network | Low | Low | Accept | Data stays in owner's storage under customer-managed keys. Job uses a least-privilege service principal |
| R-06 | Router SSH pulls break after a stock firmware update | Medium | Low | Accept | Phases 1 through 3 do not depend on router SSH |
| R-07 | Devices bypass Pi-hole with hardcoded DNS or DNS over HTTPS | High | Medium | Accept and report | Flag bypassing devices as findings |
| R-08 | Azure costs run away from an idle cluster, Managed HSM, or log ingestion | Low | Medium | Mitigate | Serverless only, no Managed HSM, Log Analytics daily cap, budget alert |
| R-09 | Vulnerable Rust dependency ships in a build | Low | Medium | Mitigate | cargo audit on every build |
| R-10 | ARP spoofing for on-demand capture disrupts the target device | Medium | Low | Accept | Used only on demand, one device at a time |
| R-11 | SD card wears out under constant writes | Medium | Low | Accept for now | Move to USB SSD, keep a backup image |
| R-12 | Scanning the work laptop trips its endpoint security and alerts the employer | Medium | High | Avoid | Do-not-touch list enforced at every collection and response point, tested before go-live |
| R-13 | Loss of the only YubiKey locks the owner out | Low | High | Mitigate | Buy two, store the backup separately |

**Risk acceptance R-05**

Accepted by the owner on Oct 11, 2026. Reasoning is that the project is low sensitivity and Azure Databricks is a managed service with its own isolation. Compensating controls are customer-managed keys on storage and a least-privilege service principal for jobs.

## Cost estimate and guardrails

Expected spend is roughly $0 to $50 a month, mostly driven by Databricks. Estimates are approximate as of Oct 2026.

| Service | Estimate per month | Note |
| --- | --- | --- |
| Azure Container Apps | $0 to a few dollars | Consumption plan free grant covers 180,000 vCPU-seconds, 360,000 GiB-seconds, and 2 million requests ([pricing](https://azure.microsoft.com/en-in/pricing/details/container-apps/)) |
| Key Vault Standard | Under $1 | $0.03 per 10,000 secrets operations |
| Azure OpenAI, weekly check-in | Cents | Weekly check-in only |
| Storage (ADLS Gen2) | Pennies to $2 |  |
| Azure Databricks serverless | Roughly $10 to $40 | Requires Unity Catalog. Serverless SQL warehouse requires Premium ([docs](https://learn.microsoft.com/en-us/azure/databricks/compute/serverless)) |

**Guardrails**

- Budget alert at $25 a month from day one
- No all-purpose clusters. Jobs and SQL warehouse on serverless with the shortest auto-stop
- No Managed HSM, which bills at $3.20 per hour per pool
- Log Analytics daily cap, since Container Apps sends logs there by default

## Operations and logistics

**Platform**

- Raspberry Pi OS Lite 64-bit, matching the Rust aarch64 target
- IPv6 disabled on the router so nothing runs half-monitored
- NTP on the Pi so timestamps line up across systems
- SD card to start (risk accepted, R-11), USB SSD later with a local retention window around 30 days
- Heartbeat from the Pi to the Container App every 5 minutes over the tunnel. Three missed beats trigger an Azure Monitor alert to the Azure mobile app

**Protected assets**

The work laptop stays on the main network. GnomeHome must never probe, capture, spoof, quarantine, or store data about it, because scanning a corporate device can trip its endpoint security and alert the employer. The same rules apply to any future work device.

1. **Find every MAC the laptop uses.** On the laptop, run `ipconfig /all` and note the Physical Address for the Wi-Fi adapter and any dock or Ethernet adapter. Cross-check against the device list in the ASUS app.
2. **Pin the MAC.** In Windows Wi-Fi settings for the home network, confirm random hardware addresses is off. If IT policy controls it, note that the MAC may change and rely on step 8 to catch it.
3. **Reserve its IP.** In the router under LAN, then DHCP Server, add a manual assignment for each MAC. If the reservation screen offers a per-device DNS field, set it to a public resolver like 1.1.1.1 so the laptop never touches Pi-hole.
4. **Create the protected list.** A `protected_assets.yaml` file on the Pi holding each MAC, reserved IP, label, and reason. Only an example file with fake values goes in the repo.
5. **Enforce it at every collection point.**
   - nmap gets an exclude file generated from the list, including for host discovery sweeps
   - The DNS log tailer drops the laptop's queries before anything reaches SQLite
   - Router connection pulls drop its flows before storage
   - Nothing about it ships to Azure
6. **Enforce it at every response point.** The playbook engine refuses any action that targets a protected MAC or IP, including quarantine, blocking, and ARP-spoofed capture, and writes the refusal to the audit log. The check lives in the engine, not in each playbook.
7. **Allow existence only.** The asset table may record that a protected device is present, from passive DHCP data, with a protected flag and no further detail.
8. **Watch for drift.** Alert if a protected MAC shows up at a different IP, or if a new unknown device appears right when the laptop normally connects, which may mean its MAC changed.
9. **Test before go-live.** Run a full scan while capturing on the Pi with tcpdump filtered to the laptop's IP. Zero packets sent to it is a pass.

**Hardware to buy**

- 2.5A power supply and a case with a heatsink
- USB SSD when ready
- Two YubiKeys at the AAA phase, not before

**Accounts and repo**

- Personal Azure subscription and personal GitHub only, kept separate from work
- Free NVD API key
- Private monorepo. Scrub real MACs, IPs, and hostnames and build a sanitized sample dataset before going public
- Docker and synthetic data for local dev, GitHub Actions cross-compiling for aarch64
- Terraform or Bicep for Azure, Databricks Asset Bundles for jobs

**Running on a MacBook**

Everything except always-on DNS for the whole house runs on macOS, so development starts before the Pi is powered and continues alongside it. Step-by-step Docker setup is in Appendix A.

| Component | On the Mac | Notes |
| --- | --- | --- |
| Python jobs (scans, enrichment, scoring, DNS analytics) | Native, Python 3 via Homebrew or uv | Same code as the Pi |
| nmap | Native via Homebrew, run with sudo for ARP discovery | Never inside Docker, since Docker on macOS sits behind a VM and cannot see the LAN directly |
| Rust backend and playbook engine | Native build for the Mac | Cross-compiled for the Pi later with `cross` |
| Pi-hole | Docker (Docker Desktop, OrbStack, or Colima) | Point only the MacBook's own DNS at it while testing. Never the router, since a sleeping laptop would break DNS for the house |
| SQLite | Native | Same schema and file layout |
| Scheduling | Run jobs by hand or with launchd | systemd timers on the Pi |

**Portability rules for the code**

- One config file with a `platform` setting (`mac` or `pi`) and every path, interface name, and schedule in it. No hardcoded Linux paths
- One task runner (`just` or `make`) with the same commands on both, like `just scan`, `just enrich`, `just serve`
- Linux-only pieces (systemd units, LUKS, capabilities) live in a separate `deploy/pi` folder
- Synthetic DNS log and flow generators for anything the Mac cannot see
- The protected-asset list applies on the Mac from the first scan

The development MacBook is an M1, so it shares the Pi's 64-bit ARM architecture. Linux arm64 Docker images run natively on both, and `cross` builds the Pi binary on the Mac without emulation. Rust builds target generic aarch64, never `target-cpu=native`, because the Pi's older Cortex-A53 lacks instructions the M1 has.

**Household**

- Get buy-in from everyone on the network, since DNS logging and capture touch their devices
- Decide how guest devices are treated

## Open questions and decisions

**Open questions**

- [ ] Which USB SSD to buy

**Decision log**

| Date | Decision |
| --- | --- |
| Oct 11, 2026 | Project name is GnomeHome. Heartbeat monitor approved. OS is Raspberry Pi OS Lite 64-bit |
| Oct 11, 2026 | Push notifications through the Azure mobile app |
| Oct 11, 2026 | Disable IPv6 on the router |
| Oct 11, 2026 | Start on SD card, accept wear risk until a USB SSD is bought |
| Oct 11, 2026 | Personal Azure subscription and GitHub only |
| Oct 11, 2026 | Work laptop excluded through a do-not-touch list, with no network segmentation or guest Wi-Fi |
| Oct 11, 2026 | Mixed Python and Rust stack, with SQLite as the contract between them |
| Oct 11, 2026 | Send raw data to the cloud, protected by customer-managed keys |
| Oct 11, 2026 | Container App hosts the AI agent, weekly report, and notification relay. Wasm offloads dashboard work to the browser |
| Oct 11, 2026 | AI agent model runs in Azure OpenAI in the owner's tenant |
| Oct 11, 2026 | Backend framework is Axum instead of Rocket |
| Oct 11, 2026 | Accept Azure Databricks serverless risk (R-05) |
| Oct 11, 2026 | Use Azure Databricks with serverless compute, not Databricks Free Edition |
| Oct 11, 2026 | Standard encryption with mutual TLS, WireGuard, and 24-hour certs instead of layered custom ciphers |
| Oct 11, 2026 | Add an AI weekly check-in agent that talks only to this architecture |
| Oct 10, 2026 | Stack includes Rust, WebAssembly, AAA, a hardened build, and an automated Blue Team |
| Oct 10, 2026 | Use Pi-hole as the DNS data source |
| Oct 10, 2026 | Router confirmed as RT-AX3000 V2, staying on stock firmware |
| Oct 10, 2026 | No managed switch, collect from the router and Pi-hole instead |
| Oct 10, 2026 | Project direction is a home network NDR on the Pi 3B+ |

## Appendix A. Docker setup guide for the MacBook

This guide takes you from nothing to Pi-hole running in Docker on your M1 MacBook. Follow it top to bottom, one step at a time. Every command is meant to be copied and pasted exactly.

### What Docker is

Docker runs a program inside a sealed box called a container, with everything that program needs packed in. You don't install Pi-hole on your Mac. You install Docker once, and Docker runs Pi-hole in its own box that you can start, stop, or throw away without leaving a mess behind.

Think of it like a lunchbox. The recipe (called an image) says what goes inside. Each lunchbox you pack from that recipe is a container. If one gets messed up, you toss it and pack a new one from the same recipe.

**Why GnomeHome uses it on your Mac**

- To run Pi-hole on your Mac this weekend, since Pi-hole is built for Linux and macOS isn't Linux
- To build the Pi's Rust programs on your Mac later, since the `cross` tool uses Docker behind the scenes

**What it is not used for**

- On the Pi itself, Pi-hole installs directly with no Docker, which saves memory on its 1GB of RAM
- nmap and the Python jobs run directly on your Mac, outside Docker, because Docker on a Mac can't see your home network properly

### Before you start

Five minutes of checks so nothing surprises you halfway through.

- [ ] **Confirm the chip.** Click the Apple menu in the top-left corner, then **About This Mac**. Next to **Chip** it should say Apple M1 (or M2, M3, and so on). If it says Intel, stop and tell me, because you'd need a different download.
- [ ] **Confirm macOS is recent.** On that same window, look at the macOS name and version. Docker supports the current macOS and the two before it. If you're more than two versions behind, run Software Update first.
- [ ] **Check free disk space.** Apple menu, then **System Settings**, then **General**, then **Storage**. Aim for at least 20 GB free.
- [ ] **Know how to open Terminal.** Press **Command and Space** together, type `Terminal`, and press **Return**. A window with a blinking cursor opens. That's where you'll paste commands. You can close it any time without breaking anything.
- [ ] **Use your personal Mac and personal accounts.** Not your work laptop.

**How to paste a command into Terminal**

1. Copy the command from this guide.
2. Click inside the Terminal window.
3. Press **Command and V** to paste.
4. Press **Return** to run it.
5. Wait until you see the cursor again on a new line before running the next one.

If Terminal ever asks for a **Password**, it wants your Mac login password. Nothing appears as you type it, not even dots. That's normal. Type it and press **Return**.

### Install Docker Desktop

Docker Desktop is the friendliest way to run Docker on a Mac. It's an app with a normal window, plus the `docker` command in Terminal. It's free for personal use.

1. **Download it.** Go to [Docker's Mac install page](https://docs.docker.com/desktop/setup/install/mac-install/) and click the download button labeled for **Apple silicon**. Not the Intel one. A file called `Docker.dmg` lands in your Downloads folder.
2. **Open the download.** Double-click `Docker.dmg` in Downloads. A window opens showing a whale icon and an Applications folder.
3. **Install it.** Drag the whale icon onto the Applications folder. Wait for the copy to finish before closing anything.
4. **Start it.** Open your Applications folder and double-click **Docker**. If macOS asks whether you're sure you want to open an app downloaded from the internet, click **Open**.
5. **Accept the agreement.** Docker shows its service agreement. Click **Accept**. Docker won't run until you do.
6. **Skip optional extras.** If it offers a survey, a sign-in, or a tour, you can skip them. You don't need a Docker account for this guide.
7. **Wait for it to finish starting.** Look at the menu bar at the top-right of your screen for a small whale icon. When the whale stops animating and the Docker window says the engine is running, you're ready.
8. **Eject the installer.** In Finder's sidebar, click the eject button next to Docker. You can drag `Docker.dmg` to the Trash.

**Optional, but recommended once.** Docker suggests Apple's Rosetta translator for best compatibility. Paste this into Terminal, press Return, and type `A` then Return if it asks you to agree.

```
softwareupdate --install-rosetta
```

**Give Docker sensible limits.** Click the whale in the menu bar, then **Settings**, then **Resources**. Set memory to about 4 GB and leave the rest alone. Click **Apply & restart**.

From now on, Docker has to be running (whale in the menu bar) whenever you use it. If you quit it, Pi-hole stops too.

### Prove it works

Two commands confirm Docker is installed and can run a container.

**1. Check the version.** Open Terminal and run this.

```
docker --version
```

You should see one line starting with `Docker version` followed by numbers. If you see `command not found`, Docker Desktop isn't running or didn't finish installing. Start it from Applications, wait for the whale, and try again.

**2. Run the test container.** Run this.

```
docker run hello-world
```

The first time, Docker downloads the tiny test image, so you'll see a few lines about pulling. Then you should see a message that includes **Hello from Docker!** That means everything works.

**3. Clean up the test.** This removes the test container and image so they don't clutter things.

```
docker rm $(docker ps -aq --filter ancestor=hello-world) && docker rmi hello-world
```

It prints a couple of IDs and the word `Deleted`. That's success.

Stop here if step 2 didn't print **Hello from Docker!** and check the troubleshooting section before going on.

### Run Pi-hole in Docker

You'll make a folder, drop one settings file in it, and tell Docker to start Pi-hole from that file. The settings are adapted from [Pi-hole's official Docker setup](https://github.com/pi-hole/docker-pi-hole), locked down so only your Mac can reach it.

**Step 1. Make a home for the project.** This creates a `gnomehome/pihole` folder inside your home folder and moves Terminal into it.

```
mkdir -p ~/gnomehome/pihole && cd ~/gnomehome/pihole
```

Nothing prints. That's fine. To check, run `pwd` and it should end in `/gnomehome/pihole`.

**Step 2. Create the settings file.** Copy this whole block, every line from `cat` down to `EOF`, paste it into Terminal, and press Return. It writes a file named `docker-compose.yml` for you, so you don't have to touch a text editor.

```
cat > docker-compose.yml << 'EOF'
services:
  pihole:
    container_name: pihole
    image: pihole/pihole:latest
    ports:
      - "127.0.0.1:53:53/tcp"
      - "127.0.0.1:53:53/udp"
      - "127.0.0.1:8080:80/tcp"
    environment:
      TZ: 'America/New_York'
      FTLCONF_dns_listeningMode: 'ALL'
      FTLCONF_dns_upstreams: '1.1.1.1;1.0.0.1'
    volumes:
      - './etc-pihole:/etc/pihole'
    restart: unless-stopped
EOF
```

Check it worked by running `cat docker-compose.yml`. The file prints back exactly as above.

**What each part means**

| Line | Plain English |
| --- | --- |
| `image: pihole/pihole:latest` | Use the official Pi-hole recipe, newest version |
| `127.0.0.1:53:53` | Answer DNS questions on port 53, but only from this Mac (127.0.0.1 means "this computer") |
| `127.0.0.1:8080:80/tcp` | Show the dashboard at `localhost:8080`, again only on this Mac |
| `TZ` | Your time zone, so log times match your clock |
| `FTLCONF_dns_upstreams` | Where Pi-hole asks for answers it doesn't block. 1.1.1.1 is Cloudflare's public DNS |
| `volumes` | Saves Pi-hole's settings and logs in an `etc-pihole` folder next to this file, so they survive restarts |
| `restart: unless-stopped` | Starts Pi-hole again automatically whenever Docker starts, unless you stopped it on purpose |

**Step 3. Start Pi-hole.**

```
docker compose up -d
```

The first run downloads Pi-hole, which takes a minute or two. When it finishes you'll see a line saying the `pihole` container **Started**. The `-d` means it runs in the background so you get Terminal back.

**Step 4. Check it's healthy.** Wait about 30 seconds, then run this.

```
docker compose ps
```

In the STATUS column you want to see `Up` and, after a bit, `(healthy)`. If it says `Restarting` or `Exited`, go to troubleshooting.

**Step 5. Set your dashboard password.**

```
docker exec -it pihole pihole setpassword
```

It asks you to type a new password twice. Like before, nothing shows as you type. Pick something you'll remember and save it in your password manager.

**Step 6. Open the dashboard.** In Safari or Chrome, go to this address and log in with that password.

```
http://localhost:8080/admin
```

You should see the Pi-hole dashboard with graphs at zero. That's correct, since nothing is using it yet.

### Point your Mac at Pi-hole

Test safely first, then switch your Mac over only if you want to see real traffic. Never change the router's DNS to your Mac.

**Safe test, no settings changed.** This asks Pi-hole directly for one website's address.

```
nslookup example.com 127.0.0.1
```

You should see `Server: 127.0.0.1` and an `Address` line with numbers. Refresh the dashboard and the query counter goes up by one. Pi-hole works.

**Optional. Send all of your Mac's lookups through Pi-hole**

1. Apple menu, then **System Settings**, then **Wi-Fi** in the sidebar.
2. Click **Details** next to your connected network.
3. Click **DNS** on the left.
4. Under DNS Servers, take a screenshot of what's there now so you can put it back later.
5. Click the **+** button and type `127.0.0.1`. If other servers are listed, select each and click **−** to remove it, so Pi-hole is the only one.
6. Click **OK**.
7. Browse a few sites, then check the dashboard. You'll see your Mac's lookups appear as they happen.

**Undo it, and always undo it before stopping Pi-hole.** If Pi-hole stops while your Mac still points at it, websites stop loading on your Mac. Nothing is broken. Your Mac is just asking a server that isn't there.

1. Go back to **System Settings**, **Wi-Fi**, **Details**, **DNS**.
2. Select `127.0.0.1` and click **−**.
3. Put back whatever your screenshot showed. If it was empty or grayed out, leaving it empty is fine, since your Mac then uses the router's DNS again.
4. Click **OK**.

**If websites stop loading and you're not sure why,** do the undo steps above first. That fixes it every time.

### Everyday commands

Run these from the project folder. If you opened a new Terminal window, go there first with `cd ~/gnomehome/pihole`.

| I want to | Command |
| --- | --- |
| Go to the project folder | `cd ~/gnomehome/pihole` |
| Start Pi-hole | `docker compose up -d` |
| Stop Pi-hole (undo Mac DNS first) | `docker compose down` |
| See if it's running | `docker compose ps` |
| See its recent log messages | `docker compose logs --tail 50 pihole` |
| Restart it | `docker compose restart` |
| Update to the newest Pi-hole | `docker compose pull && docker compose up -d` |
| Reset the dashboard password | `docker exec -it pihole pihole setpassword` |
| See everything Docker is running | `docker ps` |
| Free up disk space from old images | `docker image prune` |

The Docker Desktop app shows the same things with buttons. Click the whale, then **Go to the Dashboard**, then **Containers**. You can start, stop, and read logs from there.

### Troubleshooting

| What you see | What it means | Fix |
| --- | --- | --- |
| `command not found: docker` | Docker Desktop isn't running or isn't installed | Open Docker from Applications and wait for the whale in the menu bar |
| `Cannot connect to the Docker daemon` | Same as above, Docker's engine is off | Start Docker Desktop and wait until it says the engine is running |
| `port is already allocated` or `address already in use` for 53 | Another program on your Mac is using the DNS port | Run `sudo lsof -i :53` to see what. Quit it, or ask me |
| Same error for 8080 | Something else uses port 8080 | In `docker-compose.yml`, change `8080:80` to `8081:80`, run `docker compose up -d`, and use `localhost:8081/admin` |
| `no configuration file provided` | Terminal isn't in the project folder | Run `cd ~/gnomehome/pihole` and try again |
| STATUS shows `Restarting` or `Exited` | Pi-hole crashed on startup | Run `docker compose logs --tail 50 pihole` and send me what it says |
| Dashboard won't load | Pi-hole is still starting, or the address is off | Wait a minute, check `docker compose ps`, and make sure the address ends in `/admin` |
| `setpassword` isn't recognized | Older or newer Pi-hole version | Run `docker compose logs pihole` and look for a line with a generated password, or ask me |
| Websites stopped loading on the Mac | Mac DNS points at Pi-hole and Pi-hole is off | Do the undo steps in "Point your Mac at Pi-hole" |
| Mac feels slow | Docker is using too much memory | Lower memory in Docker's **Settings**, **Resources**, or quit Docker when you're not using it |

**When in doubt, start fresh.** This wipes Pi-hole's saved settings and logs, but nothing else on your Mac. Undo the Mac DNS change first.

```
cd ~/gnomehome/pihole && docker compose down && rm -rf etc-pihole && docker compose up -d
```

Then set the password again with step 5.

### Glossary

| Word | Meaning |
| --- | --- |
| Image | The recipe for a container. Downloaded once, reused many times |
| Container | A running box made from an image. Disposable |
| Docker Desktop | The Mac app that runs Docker. Must be open for anything to work |
| Docker Compose | Starts containers from a settings file (`docker-compose.yml`) instead of long commands |
| Volume | A folder that lives outside the container, so data survives when the container is replaced |
| Port | A numbered door on your computer. DNS uses door 53, the dashboard uses door 8080 here |
| localhost or 127.0.0.1 | Your own computer talking to itself |
| DNS | The internet's phone book, turning names like example.com into addresses |
| Upstream DNS | Where Pi-hole looks up answers it isn't blocking, here Cloudflare's 1.1.1.1 |
| Terminal | The Mac app where you type commands |
