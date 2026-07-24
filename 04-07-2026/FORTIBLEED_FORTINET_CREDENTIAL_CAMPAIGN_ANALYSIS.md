# FortiBleed — Mass Fortinet Credential-Theft Campaign Now Tied to INC and Lynx Ransomware

---

## Metadata

| Field | Detail |
|---|---|
| **CVE ID** | None assigned — this is a credential-theft and initial-access campaign, not a single software vulnerability. The original mechanism by which configuration data was exfiltrated from FortiGate devices remains publicly unconfirmed; SOCRadar has separately alleged the operators leveraged an undisclosed Nextcloud zero-day for post-compromise access, but no technical detail or CVE has been published for that claim |
| **CVSS Score / Severity** | Not applicable (campaign, not a discrete CVE). Severity assessed as **Critical** on impact grounds: credential exposure at internet-facing perimeter security devices across roughly 430,000 FortiGate firewalls, with confirmed downstream ransomware use |
| **CWE** | Not applicable — primarily CWE-522 (Insufficiently Protected Credentials) / CWE-798-adjacent exposure patterns at the operational level, rather than a single code-level defect |
| **Analysis Date** | 4 July 2026 |
| **Patch Released** | No vendor patch applies — this is a credential-security and detection issue, not a patchable software flaw. Fortinet has stated the exposed data reflects previously compromised credentials rather than a new vulnerability |
| **Active Exploitation** | Confirmed and ongoing. SOCRadar reports the underlying credential-harvesting operation has been active since at least February 2026 and has now been directly linked, via shared infrastructure, to the INC and Lynx ransomware-as-a-service operations |
| **Discovered By** | Security researcher Bob Diachenko (initial exposed-server discovery); further analysis by Hudson Rock, Kevin Beaumont (DoublePulsar), and SOCRadar's Threat Research Unit (STRU) |
| **Affected Versions** | Not version-specific — affects FortiGate firewall deployments broadly, irrespective of FortiOS version, where administrative or SSL VPN credentials have been compromised through brute-force, credential stuffing, or traffic interception |
| **Fixed Version** | Not applicable — remediation is credential rotation, MFA enforcement, and exposure reduction, not a version upgrade |
| **Scale (confirmed)** | SOCRadar assesses the operation targeted more than 430,000 FortiGate firewalls worldwide, with traffic-sniffing tooling deployed on approximately 19,000 devices at peak (reduced to roughly 11,000 after victim notification); the original exposed dataset contained credentials tied to 73,932–75,000 unique firewall URLs across 194 countries and roughly 21,600 unique domains |

---

## 1. Executive Summary

In mid-June 2026, researcher Bob Diachenko discovered an exposed server containing what he described as a "massive Fortinet/FortiGate bruteforce/active exploitation campaign uncovered in action" — a database of tens of thousands of FortiGate VPN and administrative credentials, later dubbed "FortiBleed." Independent verification by Kevin Beaumont and analysis by Hudson Rock confirmed the credentials were authentic and that the dataset represented roughly half of all internet-accessible Fortinet firewalls, most of which remained online and reachable at the time of discovery. Named organisations appearing in the dataset reportedly included Chevron, Samsung, Foxconn, Comcast, AT&T, Mercedes-Benz, Toyota, Siemens, Lenovo, PwC, Accenture, Oracle and numerous government and critical-infrastructure entities, though Fredrick's analysis here relies on the researchers' published characterisations rather than independent verification of each named party.

Follow-up research by SOCRadar's Threat Research Unit substantially expanded the picture. Rather than a static leak, FortiBleed is an active, ongoing initial-access-broker operation that has run since at least February 2026, using credential stuffing and brute-force attacks (SOCRadar cites approximately 1.16 billion credential attempts against FortiGate targets and 2.1 billion against Microsoft SQL Server systems, per Diachenko's analysis) followed by a custom Golang-based tool — "FortiGateSniffer" — that abuses FortiOS's legitimate `diagnose sniffer packet` diagnostic feature on already-compromised devices to intercept authentication traffic (RADIUS, NTLM, Kerberos, LDAP, RDP, WinRM, database and mail-protocol credentials) traversing the firewall. Captured traffic is reconstructed into PCAP files by a component named "SNIFTRAN" and processed by a Python-based toolkit that extracts cleartext credentials and generates Hashcat-ready hash files, which are then cracked using rented enterprise-grade GPU clusters.

The most significant new development, reported 1 July 2026, is that SOCRadar has now linked the FortiBleed infrastructure directly to the INC and Lynx ransomware-as-a-service operations. Investigators identified a Windows server within the FortiBleed infrastructure that had been used to access the ransomware negotiation panels of both groups, showing browser sessions against victim-chat administration dashboards. SOCRadar further reports identifying more than 200 additional operational servers, overlap between FortiBleed-harvested victim organisations and entities later listed on the INC leak site, evidence of an operational team of roughly 20 members with defined roles, and persistent backdoor accounts using the username "adminin" on compromised systems. SOCRadar also alleges — without published technical detail — that the operators exploited a previously undisclosed Nextcloud zero-day to expand access following initial compromise; this claim should be treated as unconfirmed pending further disclosure.

| Verdict | Key Facts |
|---|---|
| **Severity** | Critical by impact — perimeter security-device credentials for ~430,000 FortiGate firewalls implicated; direct link to active ransomware operations |
| **Exploitation status** | Confirmed, ongoing since at least February 2026; SOCRadar reports a second technical white paper with further IOCs is forthcoming |
| **Nature of the issue** | Credential-harvesting and initial-access-broker campaign abusing legitimate FortiOS diagnostic tooling — not a single patchable CVE |
| **Ransomware linkage** | Direct infrastructure overlap with INC and Lynx (believed to be an INC rebrand) ransomware negotiation platforms |
| **Vendor position** | Fortinet has stated the exposed dataset reflects previously compromised credentials rather than a new vulnerability, a characterisation SOCRadar's ongoing-campaign findings appear to sit in tension with |
| **Unconfirmed claim** | Alleged use of an undisclosed Nextcloud zero-day for post-compromise access — no technical detail published as of this analysis |
| **CISA response** | CISA published guidance urging organisations to harden Fortinet device exposure following the initial leak reports |

---

## 2. Product Background

Fortinet's FortiGate firewalls are among the most widely deployed perimeter security appliances in enterprise and government networks, combining firewalling, SSL VPN remote-access termination, and unified threat management in a single platform. Their ubiquity as the trusted boundary between internal networks and the internet is precisely what makes compromised FortiGate credentials so consequential: an administrative or VPN credential for a FortiGate device is not merely access to "a system" but access to the control point that is supposed to keep attackers out of everything behind it.

FortiGate devices have a substantial recent history as ransomware initial-access vectors, most notably through the CVE-2022-42475 and CVE-2023-27997 SSL VPN vulnerabilities exploited widely by ransomware affiliates. FortiBleed is notable precisely because, per SOCRadar's account, the credential harvesting largely did not depend on a new software vulnerability — it relied on brute-forcing and credential-stuffing weak or reused passwords at internet-exposed management and VPN interfaces, followed by abuse of a legitimate built-in diagnostic capability to harvest further credentials from network traffic. This is an important distinction from a conventional CVE-driven campaign: there is no single patch that closes this attack surface, because the attack surface is exposed authentication interfaces and weak credential hygiene rather than a code defect.

INC Ransom has operated as a ransomware-as-a-service platform since mid-2023, targeting healthcare, education, government and other sectors. Lynx, which emerged in mid-2024, is assessed by security researchers (including Palo Alto Networks Unit 42) to be a rebrand of the INC group rather than a genuinely new extortion operation — a lineage consistent with SOCRadar's finding of shared negotiation-panel access between the two "distinct" brands from within the FortiBleed infrastructure.

---

## 3. Vulnerability Details

### Root Cause

FortiBleed is best understood as a multi-stage credential-compromise pipeline rather than a single exploitable flaw:

1. **Initial access** — brute-force and credential-stuffing attacks against internet-exposed FortiGate SSL VPN and administrative interfaces, at a scale Diachenko's analysis puts at roughly 1.16 billion attempts against FortiGate targets. Devices with weak, reused, or default-adjacent credentials, and no meaningful account-lockout or geo-restriction controls, are the ones compromised at this stage.
2. **Abuse of legitimate functionality** — once administrative access is obtained, the "FortiGateSniffer" tool connects over SSH and invokes FortiOS's built-in `diagnose sniffer packet` command, a legitimate troubleshooting feature, to capture live authentication traffic transiting the compromised firewall across roughly two dozen protocols (Kerberos, LDAP, SMB, RADIUS, RDP, WinRM, MSSQL, MySQL, PostgreSQL, SMTP, IMAP, POP3, FTP, Telnet).
3. **Traffic reconstruction and credential extraction** — the "SNIFTRAN" component reconstructs captured packets into PCAP files, which a Python-based "PCAP Deep Analysis Toolkit" mines for cleartext credentials, NTLM/Kerberos hash material, and other authentication artefacts, generating Hashcat-ready files.
4. **Offline cracking at scale** — recovered hashes are cracked using rented enterprise-grade GPU clusters (Kevin Beaumont's reporting cites 36 enterprise-class GPUs hosted at a generative-AI compute provider), an approach that trades the cost of dedicated cracking hardware for on-demand cloud GPU rental.
5. **Monetisation via initial-access brokerage** — cracked credentials, and the network access they unlock, are the product; SOCRadar's new findings indicate the operators or their customers include, or directly overlap with, the INC/Lynx ransomware operation.

Separately, some portion of the originally leaked data reportedly derived from exported FortiGate configuration files (which can contain email addresses and other config-only artefacts) rather than exclusively from live traffic interception — Kevin Beaumont's independent review supports this as at least a partial explanation for the original 73,000–75,000 device dataset, though the precise mechanism by which those configuration exports were obtained has not been publicly established.

### Why It Is Architecturally Significant

FortiBleed illustrates a category of risk that pure vulnerability management does not address: a determined, well-resourced actor achieving durable, wide-scale compromise of security infrastructure primarily through credential weakness and abuse of legitimate diagnostic tooling, rather than through a novel software defect. There is no CVE to patch here, no vendor advisory that closes the door — the exposure exists wherever credential hygiene, MFA enforcement, and management-plane exposure are weak, which is a substantial fraction of the roughly 430,000 targeted FortiGate estate globally, according to SOCRadar.

The pivot from "credential leak" to "ransomware infrastructure" is the more consequential development. It converts what could be dismissed as a hygiene problem into direct evidence that a well-organised group (SOCRadar estimates around 20 members with defined roles) is operating FortiBleed as an initial-access pipeline feeding, or overlapping with, active ransomware operations. The discovery of shared access to both INC's and Lynx's negotiation panels from within FortiBleed infrastructure is also a rare piece of concrete evidence supporting the long-suspected INC-to-Lynx rebrand relationship.

### Affected Endpoints / Code

There is no specific vulnerable code path to enumerate. The exposure surface consists of: internet-facing FortiGate SSL VPN and administrative management interfaces (Beaumont notes a majority of affected devices expose FortiGate management interfaces directly to the internet); any account without MFA enforced; and any FortiGate device on which an attacker has achieved sufficient administrative access to invoke `diagnose sniffer packet`, which by design requires elevated privileges — meaning its abuse here is a post-compromise persistence and collection technique rather than an initial-entry vulnerability.

---

## 4. Full Attack Chain

```
THREAT ACTOR (Russian-speaking multi-operator group per Diachenko's assessment;
now linked to INC/Lynx RaaS infrastructure via SOCRadar)
│
├─[INITIAL ACCESS]
│   ├─ Mass credential stuffing / brute force against internet-exposed
│   │  FortiGate SSL VPN and admin interfaces (~1.16B attempts reported
│   │  against FortiGate targets; ~2.1B against exposed MSSQL systems)
│   └─ Successful logins obtained on weak/reused/default-adjacent
│      credentials at devices lacking MFA and lockout controls
│
├─[ESTABLISH COLLECTION CAPABILITY]
│   ├─ SSH into compromised FortiGate device with harvested admin creds
│   ├─ Deploy "FortiGateSniffer" (Golang) — invokes legitimate FortiOS
│   │  `diagnose sniffer packet` diagnostic command
│   └─ Configure sniffer to monitor ~24 protocols (Kerberos, LDAP, SMB,
│      RADIUS, RDP, WinRM, MSSQL, MySQL, PostgreSQL, SMTP, IMAP, POP3,
│      FTP, Telnet) traversing the firewall
│
├─[COLLECTION & PROCESSING]
│   ├─ "SNIFTRAN" reconstructs captured packets into PCAP files
│   ├─ Python "PCAP Deep Analysis Toolkit" extracts cleartext creds,
│   │  NTLM/Kerberos hashes, database and mail credentials
│   └─ Generates Hashcat-ready hash files; parallel path extracts
│      credential material directly from exported FortiGate configs
│
├─[OFFLINE CRACKING AT SCALE]
│   └─ Hashes cracked via rented enterprise GPU cluster (36 enterprise-
│      class GPUs reported, hosted at a GenAI compute provider)
│
├─[PERSISTENCE]
│   └─ Backdoor accounts observed using username "adminin" on
│      compromised systems (SOCRadar)
│
├─[ALLEGED SECONDARY ACCESS VECTOR — UNCONFIRMED]
│   └─ SOCRadar alleges use of an undisclosed Nextcloud zero-day to
│      expand access post-compromise; no technical detail published
│
├─[MONETISATION / HANDOFF]
│   ├─ Cracked credentials and network access sold or used directly as
│   │  initial access
│   └─ Direct infrastructure overlap identified with INC and Lynx
│      ransomware negotiation-panel access from within FortiBleed
│      operational servers
│
└─[IMPACT]
    └─ Confirmed credential compromise across a substantial fraction of
       internet-accessible FortiGate estate; documented pathway into
       active ransomware operations against victim organisations
```

---

## 5. Campaign Intelligence

### Timeline

| Date | Event |
|---|---|
| February 2026 (assessed) | SOCRadar assesses the underlying credential-harvesting campaign began |
| 18 June 2026 | Bob Diachenko discovers exposed server containing FortiGate credential dataset; CISA publishes guidance urging Fortinet device hardening |
| 18 June 2026 | Hudson Rock and Kevin Beaumont independently verify authenticity of a subset of the exposed credentials, sizing the dataset at ~73,932–75,000 unique firewall URLs across 194 countries |
| 22 June 2026 | SOCRadar publishes research identifying the "FortiGateSniffer" tool and describing the operation as targeting over 430,000 FortiGate firewalls, active since at least February 2026 |
| 1 July 2026 | SOCRadar publishes further research directly linking FortiBleed infrastructure to INC and Lynx ransomware negotiation-panel access; reports ~200 additional operational servers and an estimated 20-member operational team |
| 4 July 2026 | This analysis published; SOCRadar has indicated a further technical white paper with additional IOCs and attribution evidence is forthcoming |

### Threat Actor

Diachenko's initial analysis characterised the operators as a Russian-speaking, multi-operator threat group. SOCRadar's subsequent research does not publicly name a specific tracked APT or RaaS-affiliate designation for the FortiBleed operators themselves, but establishes direct infrastructure and access overlap with the INC and Lynx ransomware-as-a-service groups. Attribution beyond this infrastructure overlap has not been independently confirmed by Fredrick's analysis and should be treated as SOCRadar's assessment pending corroboration.

### Confirmed Victims

No individual victim organisation has been confirmed by name as compromised specifically through the ransomware-linked phase of this campaign as of this analysis. SOCRadar reports overlap between organisations whose credentials appeared in FortiBleed-harvested data and organisations subsequently listed on the INC ransomware leak site, which is suggestive of a causal pathway but is not the same as a confirmed, attributed breach chain for any specific named victim. Organisations named in earlier reporting as appearing within the exposed credential dataset (via Hudson Rock's analysis) include Chevron, Samsung, Foxconn, Comcast, AT&T, Mercedes-Benz, Toyota, Sinopec, State Grid, Siemens, Lenovo, PwC, Accenture and Oracle; their presence in the dataset does not by itself confirm they were breached or ransomed.

### IOC Table

| Indicator | Type | Notes |
|---|---|---|
| Username `adminin` | Backdoor account | Reported by SOCRadar as a persistence indicator on compromised FortiGate-adjacent systems |
| "FortiGateSniffer" (Golang binary) | Tooling | Custom credential-harvesting tool abusing `diagnose sniffer packet` |
| "SNIFTRAN" | Tooling component | Reconstructs sniffed packet captures into PCAP files |
| "PCAP Deep Analysis Toolkit" (Python) | Tooling | Extracts credentials and generates Hashcat-ready hash files from captured traffic |
| Published target IP list | Network indicator | Kevin Beaumont has published a list of IP addresses targeted in the campaign (see References) for organisations to check against their own FortiGate estate |

No file hashes, C2 domains, or additional network indicators beyond the above have been independently confirmed by Fredrick's analysis at the time of writing; organisations should consult SOCRadar's forthcoming technical white paper and Beaumont's published IP list directly rather than relying on secondary summarisation for operational blocking decisions.

---

## 6. MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|---|---|---|
| T1110 | Brute Force | Mass credential stuffing / brute force against FortiGate SSL VPN and admin interfaces |
| T1078 | Valid Accounts | Use of harvested, cracked credentials for continued access |
| T1040 | Network Sniffing | "FortiGateSniffer" abuse of `diagnose sniffer packet` to capture authentication traffic |
| T1552.001 | Unsecured Credentials: Credentials In Files | Extraction of credentials and secrets from exported FortiGate configuration files |
| T1110.002 | Brute Force: Password Cracking | Offline Hashcat-based cracking of harvested NTLM/Kerberos hashes on rented GPU clusters |
| T1136 | Create Account | Persistent backdoor accounts (`adminin`) established on compromised systems |
| T1584.005 | Compromise Infrastructure: Botnet / Compute-for-Hire | Use of rented cloud GPU compute for password-cracking at scale |
| T1657 | Financial Theft (via) / Ransomware Deployment (downstream) | Confirmed infrastructure linkage to INC/Lynx ransomware negotiation and monetisation |

---

## 7. Detection Recommendations

### Configuration and Exposure Check

```bash
# Identify FortiGate management interfaces exposed directly to the
# internet — a primary risk factor identified in this campaign
# (run from an external vantage point / via Shodan-style scanning)
# Look for HTTPS admin portals and SSL VPN portals reachable without
# IP allow-listing or VPN-only access
```

```
# On the FortiGate CLI, review for unexpected use of the diagnostic
# sniffer feature, which is a legitimate but rarely-used-at-scale
# admin capability
diagnose sys top
get system performance status
# Review recent CLI/audit logs for invocation of:
#   diagnose sniffer packet <interface> <filter> <verbose> <count>
```

### Log Query — Suspicious Sniffer Invocation and Admin Access

```
# FortiGate event/audit log hunt for diagnose sniffer packet usage
# outside of known, ticketed troubleshooting activity
event_type=admin_login OR event_type=cmd_exec
| search cmd="*diagnose sniffer packet*"
| stats count by srcip, user, devname, _time
| sort -_time
```

### KQL — Microsoft Sentinel (Downstream Credential Abuse)

```kql
// Hunt for successful authentications using credentials or accounts
// that may originate from FortiGate-harvested credential material,
// focused on anomalous RDP/WinRM/SMB logons shortly after VPN sessions
// from FortiGate-fronted networks
SigninLogs
| where ResultType == "0"
| where AuthenticationRequirement == "singleFactorAuthentication"
| where AppDisplayName has_any ("VPN", "RDP", "WinRM")
| summarize LogonCount = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where LogonCount > 5
| sort by TimeGenerated desc
```

```kql
// Hunt for newly created local/service accounts matching known
// FortiBleed persistence naming pattern
DeviceEvents
| where ActionType == "UserAccountCreated"
| where AccountName has "adminin"
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessAccountName
```

### Suricata Rule

```yaml
alert tcp any any -> $HOME_NET 22 (
  msg:"ET POLICY Possible FortiGate diagnose sniffer packet Invocation via SSH Session";
  flow:established,to_server;
  content:"diagnose"; nocase;
  content:"sniffer"; nocase; distance:0; within:40;
  content:"packet"; nocase; distance:0; within:20;
  classtype:policy-violation;
  reference:url,bleepingcomputer.com/news/security/fortibleed-credential-theft-campaign-linked-to-lynx-ransomware/;
  sid:9026482770;
  rev:1;
)
```

*Note: this rule requires SSH session content inspection (e.g. via a decrypting proxy or bastion host logging) since standard encrypted SSH traffic will not expose command content to a network IDS; it is provided as a template for organisations with SSH command-logging capability rather than a wire-format signature.*

### Sigma Rule

```yaml
title: Backdoor Account Creation Matching FortiBleed "adminin" Pattern
id: 7c2e4f81-9b3d-4a6e-8f12-3d5e6a9c1b04
status: experimental
description: |
  Detects creation of a local or domain account named "adminin", a
  persistence indicator reported by SOCRadar in connection with the
  FortiBleed credential-theft campaign and its confirmed links to
  INC and Lynx ransomware infrastructure.
references:
  - https://www.bleepingcomputer.com/news/security/fortibleed-credential-theft-campaign-linked-to-lynx-ransomware/
  - https://www.bleepingcomputer.com/news/security/fortibleed-campaign-used-custom-fortigate-sniffer-to-steal-credentials/
author: Fredrick
date: 2026-07-04
tags:
  - attack.persistence
  - attack.t1136
  - attack.credential_access
  - attack.t1110
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'net user'
      - 'adminin'
  condition: selection
falsepositives:
  - Legitimate account provisioning that coincidentally uses a similar
    naming convention — verify against change-management records
level: high
```

---

## 8. Remediation

1. **Inventory all FortiGate devices** and determine which expose SSL VPN or administrative management interfaces directly to the internet without IP allow-listing.
2. **Rotate all FortiGate administrative and VPN credentials** organisation-wide, regardless of whether a specific device is believed compromised — the scale of this campaign (430,000+ targeted devices) makes credential reuse a material risk even for unconfirmed devices.
3. **Enforce multi-factor authentication** on all FortiGate SSL VPN and administrative accounts; this is the single control most directly undermined by the brute-force/credential-stuffing phase of this campaign.
4. **Restrict or disable remote invocation of `diagnose sniffer packet`** where not operationally required, and audit historical CLI/audit logs for its use outside known troubleshooting windows.
5. **Check the organisation's FortiGate estate against Kevin Beaumont's published target IP list** (see References) and against any indicators published in SOCRadar's forthcoming technical white paper.
6. **Audit for the `adminin` backdoor account** and any other unexpected local accounts on FortiGate devices and adjacent infrastructure.
7. **Review downstream authentication logs** (RDP, WinRM, SMB, database, email) for anomalous access patterns following VPN sessions through potentially affected FortiGate devices, given the campaign's demonstrated interest in credentials for numerous internal protocols.
8. **Treat the alleged Nextcloud zero-day claim as a watch item**, not an actionable finding, pending technical disclosure; do not delay the above credential and configuration remediation waiting for that detail to be confirmed.
9. **Engage incident response** if overlap is found between the organisation's assets and any published FortiBleed indicators, given the confirmed pathway from this campaign into active ransomware operations.

---

## 9. The Broader Pattern

FortiBleed is a useful corrective to the instinct to equate "vulnerability intelligence" with "CVE tracking." Nothing here required a zero-day in FortiOS to achieve mass compromise of the internet's perimeter security devices — brute force against weak credentials, followed by abuse of a legitimate, built-in diagnostic feature, was sufficient to build a credential-harvesting operation spanning hundreds of thousands of devices over at least five months before it was publicly discovered. Security teams that measure their exposure purely by patch cadence against published CVEs will have had a clean bill of health throughout this campaign's operation.

The confirmed linkage to INC and Lynx ransomware infrastructure is the detail that should reframe how this campaign is prioritised. Credential-harvesting operations are frequently treated as a lower-urgency "hygiene" problem relative to a headline RCE, in part because the causal chain to actual harm feels more diffuse. SOCRadar's discovery of shared access to both ransomware groups' negotiation panels from within FortiBleed's own infrastructure removes that ambiguity: this is not a hypothetical risk of credentials someday being misused, but direct evidence of an operational pipeline from mass credential theft at internet-facing security appliances into ransomware deployment.

The unconfirmed allegation of an undisclosed Nextcloud zero-day being used for lateral access is worth flagging precisely because it should not be — the temptation in vulnerability journalism is to lead with the most dramatic unconfirmed claim. Fredrick's assessment is that organisations should act on the confirmed elements of this campaign (credential exposure, MFA gaps, diagnostic-feature abuse, ransomware infrastructure linkage) immediately, and treat the zero-day claim as a reason to watch for further disclosure rather than a reason to wait for more information before remediating what is already well established.

---

## 10. References

| Source | URL |
|---|---|
| BleepingComputer — FortiBleed credential-theft campaign linked to Lynx ransomware | https://www.bleepingcomputer.com/news/security/fortibleed-credential-theft-campaign-linked-to-lynx-ransomware/ |
| BleepingComputer — FortiBleed campaign used custom FortiGate sniffer to steal credentials | https://www.bleepingcomputer.com/news/security/fortibleed-campaign-used-custom-fortigate-sniffer-to-steal-credentials/ |
| BleepingComputer — FortiBleed leak exposes Fortinet VPN credentials for 73,000 devices | https://www.bleepingcomputer.com/news/security/fortibleed-leak-exposes-fortinet-vpn-credentials-for-73-000-devices/ |
| CISA — Alert urging hardening of Fortinet devices following credential exposure reports (18 June 2026) | https://www.cisa.gov/news-events/alerts/2026/06/18/cisa-urges-hardening-fortinet-devices-after-reports-credential-exposure |

*Note: Kevin Beaumont's DoublePulsar analyses and SOCRadar's original research/whitepaper are quoted and linked at length within the BleepingComputer articles above and inform this analysis accordingly, but were not independently fetched and are omitted from the table above for that reason.*
