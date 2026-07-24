# Zimbra Classic Web Client Stored Cross-Site Scripting — "Read the Email, Lose the Mailbox"

---

## Metadata

| Field | Detail |
|---|---|
| **CVE ID** | Not yet assigned at time of writing. Zimbra's advisory and all press coverage reviewed for this analysis (Zimbra, BleepingComputer, Security Affairs) confirm the flaw has not received a CVE identifier. This should not be confused with the unrelated, previously patched Zimbra XSS flaws CVE-2025-66376 (patched earlier in 2026, exploited by APT28) or CVE-2025-68645 — this is a distinct, newly disclosed issue |
| **CVSS Score / Severity** | No published CVSS vector was located. Zimbra itself rates the internal "Patch Security Severity" as **High**; multiple outlets (Zimbra, BleepingComputer, Security Affairs) independently describe the underlying flaw as "critical" in their reporting. This analysis treats it as critical-tier given the impact and the software's history, while noting the absence of a formal score |
| **CWE** | CWE-79 — Improper Neutralization of Input During Web Page Generation ("Stored Cross-Site Scripting"), consistent with a specially crafted email executing script upon being opened in the Classic Web Client. Not formally assigned by Zimbra in the sources reviewed |
| **Analysis Date** | 11 July 2026 |
| **Patch Released** | Yes. Zimbra Collaboration Suite (ZCS) 10.1.19, released 7 July 2026 |
| **Active Exploitation** | Not confirmed as of this analysis. Zimbra has not tagged the issue as exploited in the wild, and no outlet reviewed reports observed attacks. The flaw's significance rests on who found it and Zimbra's exploitation history, not on confirmed current abuse |
| **Discovered By** | Google's Threat Analysis Group (TAG) — a unit that specialises in identifying zero-day exploits and vulnerabilities used by state-backed hacking groups against high-risk individuals such as journalists, dissidents, and opposition politicians |
| **Affected Versions** | Zimbra Collaboration Suite installations using the Classic Web Client (also known as the Classic UI), prior to 10.1.19. The modern web client is not affected by this specific issue |
| **Fixed Version** | ZCS 10.1.19 and later |

---

## 1. Executive Summary

Zimbra has patched a critical stored cross-site scripting vulnerability in the Classic Web Client, the Ajax-based legacy webmail interface still used across a large share of Zimbra Collaboration Suite deployments because it loads large mail folders faster than the modern client. The flaw allows an attacker to send a specially crafted email that executes malicious JavaScript the moment the recipient opens it in the Classic UI — no attachment execution, no link click, and no separate user action beyond reading the message. A successful exploit can read mailbox contents, harvest session tokens, and modify account settings, effectively converting a single email into full compromise of the recipient's webmail session.

No CVE identifier has been assigned to this issue as of publication, and no source reviewed for this analysis has confirmed active exploitation. What elevates this beyond a routine webmail bug is provenance and pattern: the flaw was reported by Google's Threat Analysis Group, the team that exists specifically to catch exploits already in use by state-sponsored actors against high-value targets, and Zimbra's Classic Web Client has been the entry point for a documented, multi-year run of Russian state-sponsored XSS campaigns — Winter Vivern against NATO-aligned organisations in 2023, APT29/Midnight Blizzard's mass-scale targeting of Zimbra servers in 2024, and APT28's exploitation of a different Classic Web Client XSS flaw (CVE-2025-66376) against Ukrainian government entities as recently as March 2026. Zimbra is used by hundreds of millions of individuals and thousands of government and enterprise customers worldwide, which is precisely the profile that has made it a recurring target for espionage-motivated webmail attacks.

| Verdict | Key Facts |
|---|---|
| **Severity** | Rated "High" patch severity by Zimbra; described as "critical" by Zimbra and independent outlets. No public CVSS score or CVE ID as of this analysis |
| **Exploitation status** | No confirmed in-the-wild exploitation reported at time of writing. Discovered by Google TAG, a unit whose findings frequently precede or coincide with disclosure of state-sponsored exploitation |
| **Nature of the issue** | Stored XSS in the Classic Web Client — a specially crafted email executes attacker-controlled JavaScript when opened, without further user interaction |
| **Reach** | Zimbra Collaboration Suite is used by hundreds of millions of people and thousands of organisations, including many government agencies; the Classic Web Client remains widely deployed as the faster alternative to the modern UI |
| **What's exposed** | Mailbox contents, session data (enabling session hijacking), and account settings |
| **Pattern context** | The fourth Classic Web Client / Zimbra XSS issue in roughly 18 months to draw significant security-press attention, following CVE-2025-66376 (APT28, March 2026), CVE-2025-68645, and CVE-2020-7796 — all added to CISA's KEV catalog |

---

## 2. Product Background

Zimbra Collaboration Suite is a widely deployed email and collaboration platform, used by an estimated hundreds of millions of end users across thousands of businesses and hundreds of government agencies globally. It offers two primary web interfaces: a modern client, and the "Classic Web Client" (also called the Classic UI), an older Ajax-based interface that remains popular specifically because it performs better than the modern client when loading large mail folders — a meaningful advantage for high-volume mailboxes such as those used by government agencies, distribution lists, or long-tenured accounts.

That performance advantage has a security cost. Legacy interfaces tend to receive less ongoing security engineering investment than their actively developed successors, while still processing the same untrusted, attacker-reachable input: arbitrary incoming email content. Because Zimbra sits at the centre of an organisation's email flow — the single most common initial-access and data-exfiltration vector in targeted intrusions — any code-execution-capable flaw in a Zimbra web client is disproportionately valuable to an attacker relative to an equivalent bug in a less centrally trusted application.

---

## 3. Vulnerability Details

### Root Cause

The vulnerability is a stored cross-site scripting flaw in the Classic Web Client's email rendering pipeline. According to Zimbra's own advisory, "a specially crafted email could run malicious code when the email is opened" — indicating that the Classic UI fails to adequately sanitise or neutralise some element of email content (most plausibly HTML/script content embedded in the message body or a related MIME part) before rendering it in the recipient's browser session. Because the payload is "stored" — it resides in the delivered email itself rather than requiring the victim to click a crafted link — the only user action required to trigger execution is opening the message, the single most routine action in any mail client.

Zimbra has not published the specific parameter, header, or content-handling function responsible, and no public technical writeup or proof-of-concept was located as of this analysis. Consistent with responsible disclosure practice for an unexploited, freshly patched flaw, exact exploitation mechanics have not been made public by Zimbra, Google TAG, or the outlets covering the story.

### Why It Is Architecturally Significant

Stored XSS in a webmail client is architecturally dangerous because the attack surface is, by design, open to anyone who can send the target an email — no prior access, no social-engineering click-through, and no separate delivery mechanism are required beyond the normal mail flow every mailbox already accepts. Once triggered, script execution runs in the security context of the logged-in webmail session, giving the attacker access to whatever that session can access: the full mailbox, session/authentication tokens that can be replayed or exfiltrated, and account configuration settings, all without needing the victim's password.

The discovery channel adds further weight. Google's Threat Analysis Group does not routinely audit consumer webmail clients for garden-variety bugs; its work is concentrated on identifying exploits already weaponised, or imminently weaponisable, by government-backed actors against journalists, dissidents, and political figures. TAG's involvement does not itself prove this specific flaw has been exploited, but it places the finding in the same discovery lineage as the Zimbra flaws that have previously turned out to be actively used in espionage campaigns.

### Affected Endpoints / Code

The vulnerable surface is confined to the Classic Web Client's email-rendering component; Zimbra's advisory explicitly states the issue "only impacts the users of Classic Web Client," meaning organisations that have fully migrated users to the modern web client are not exposed to this specific flaw. No further code-level detail (affected JSP/servlet paths, specific MIME handling functions) has been published in the sources reviewed.

---

## 4. Full Attack Chain

```
ATTACKER (requires only the ability to send email to a target
mailbox — no prior access or credentials)
│
├─[STEP 1 — TARGET SELECTION]
│   └─ Identify a target using Zimbra's Classic Web Client —
│      historically prioritised by state-sponsored actors:
│      government agencies, NGOs, journalists, diplomats,
│      military personnel
│
├─[STEP 2 — CRAFT PAYLOAD]
│   └─ Construct a specially crafted email containing a stored
│      XSS payload in a component the Classic UI fails to
│      sanitise on render
│
├─[STEP 3 — DELIVERY]
│   └─ Send the email through normal SMTP delivery to the
│      target's Zimbra mailbox — no bypass of email security
│      controls required beyond normal spam/phishing filtering
│
├─[STEP 4 — TRIGGER]
│   └─ Victim opens the email in the Classic Web Client (a
│      routine action); the unsanitised content executes as
│      JavaScript within the victim's authenticated webmail
│      session — no click-through or attachment execution needed
│
└─[STEP 5 — IMPACT]
    ├─ Theft of session tokens / cookies, enabling session
    │  hijacking without needing the victim's password
    ├─ Exfiltration of mailbox contents (in line with prior
    │  Zimbra XSS campaigns, potentially extending to weeks or
    │  months of historical mail)
    ├─ Modification of account settings (e.g. mail forwarding
    │  rules) to establish persistent covert access
    └─ Potential pivot to further reconnaissance of the victim
       organisation using harvested mailbox intelligence
```

---

## 5. Campaign Intelligence

### Timeline

| Date | Event |
|---|---|
| (undisclosed) | Google's Threat Analysis Group identifies and reports the stored XSS flaw in Zimbra's Classic Web Client to Zimbra |
| 7 July 2026 | Zimbra releases ZCS 10.1.19, patching the flaw; Zimbra's advisory does not assign a CVE ID |
| 10 July 2026 | BleepingComputer and Security Affairs publish independent coverage urging customers to patch |
| 11 July 2026 | This analysis published |

### Threat Actor

No specific threat actor or group has been publicly attributed to this particular flaw, and no source confirms exploitation has occurred. The relevance to threat actor tracking is contextual rather than direct: Zimbra's Classic Web Client and related webmail components have a documented history of exploitation by Russian state-sponsored groups, including Winter Vivern (breach of NATO-aligned Zimbra webmail portals, February 2023, stealing emails from government officials, military personnel, and diplomats), APT29/Midnight Blizzard (mass-scale targeting of vulnerable Zimbra servers, warned by US/UK agencies in October 2024), and APT28/Fancy Bear (exploitation of the unrelated Classic Web Client XSS flaw CVE-2025-66376 against Ukrainian government entities, including the State Hydrology Agency, in a campaign tracked by Seqrite Labs as "Operation GhostMail," March 2026).

### Confirmed Victims

None confirmed for this specific, newly patched flaw. No organisation has been publicly named as a victim of this particular vulnerability as of this analysis.

### IOC Table

No indicators of compromise have been published for this vulnerability, consistent with the absence of confirmed active exploitation. Organisations should not expect a public IOC set for this issue at this stage; monitoring should instead focus on the detection patterns below.

---

## 6. MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|---|---|---|
| T1566.001 / T1566.002 | Phishing: Spearphishing Attachment / Spearphishing Link | The delivery mechanism is a crafted email; in this case the malicious content is embedded directly in the message body rather than an attachment or external link |
| T1189 | Drive-by Compromise | Execution occurs simply by the victim viewing content (opening the email) in a client application, analogous to a drive-by pattern within the webmail context |
| T1059.007 | Command and Scripting Interpreter: JavaScript | The XSS payload executes as JavaScript within the victim's browser-rendered webmail session |
| T1539 | Steal Web Session Cookie | Primary post-exploitation objective — theft of session data to hijack the authenticated mailbox session |
| T1114.002 | Email Collection: Remote Email Collection | Consistent with the pattern established in prior Zimbra XSS campaigns (e.g. CVE-2025-66376), where attackers exfiltrated bulk historical mailbox content post-compromise |

---

## 7. Detection Recommendations

### Version Check

```bash
# Check installed Zimbra Collaboration Suite version
zmcontrol -v

# Vulnerable: any version prior to 10.1.19 where the Classic
# Web Client is enabled and in use
# Safe: 10.1.19 or later
```

### Log Query — Anomalous Classic Web Client Session Behaviour

```
# Zimbra mailbox/access logs
source="zimbra_mailbox_log" OR source="zimbra_access_log"
| where client_interface="Classic" (or user-agent/UI indicator consistent with Classic Web Client)
| where event IN ("filter_rule_created", "forwarding_address_changed", "session_token_reused_new_ip")
| stats count by account, src_ip, event
```

### KQL — Microsoft Sentinel

```kql
// Requires Zimbra mailbox/audit logs ingested into a custom
// table (e.g. ZimbraAudit_CL) via syslog or file-based forwarding.
ZimbraAudit_CL
| where ClientInterface_s == "Classic"
| where EventType_s in ("FilterRuleCreated", "ForwardingAddressChanged", "AccountSettingsModified")
| project TimeGenerated, Account_s, SourceIP_s, EventType_s, Details_s
| order by TimeGenerated desc
// Flags account configuration changes shortly after Classic Web
// Client email access — a plausible post-exploitation signature
// for stored XSS abuse, pending confirmation of the specific
// payload mechanics for this flaw.
```

### Suricata Rule

```
alert http $HOME_NET any -> any any (msg:"Possible Zimbra Classic Web Client Session Token Exfiltration"; flow:to_server,established; content:"ZM_AUTH_TOKEN"; http_client_body; classtype:web-application-attack; reference:url,blog.zimbra.com/2026/07/patch-release-update-zimbra-10-1-19/; sid:9000701; rev:1;)
```

Note: this rule is a generic heuristic for outbound transmission of Zimbra authentication token material and is not a payload-specific signature, since no public technical detail of the exploit exists at time of writing; treat as low-confidence and tune aggressively to your environment.

### Sigma Rule

```yaml
title: Zimbra Classic Web Client Account Configuration Change Following Email Access (Potential Stored XSS Abuse)
id: 6f1c8a92-3d5e-47b1-9a2c-8e4f6b1d9c73
status: experimental
description: |
  Detects account configuration changes (mail forwarding rules,
  filter creation, session token reuse from a new source IP)
  shortly following Classic Web Client email access. Intended as
  a heuristic detection for potential exploitation of the July
  2026 Zimbra Classic Web Client stored XSS vulnerability, which
  at time of writing has not received a CVE ID and for which no
  public technical exploitation detail exists. Requires Zimbra
  mailbox/audit logs.
references:
  - https://blog.zimbra.com/2026/07/patch-release-update-zimbra-10-1-19/
  - https://www.bleepingcomputer.com/news/security/zimbra-urges-customers-to-patch-critical-web-client-xss-flaw/
  - https://securityaffairs.com/195130/hacking/update-now-critical-zimbra-classic-web-client-flaw-could-expose-mailboxes.html
author: Fredrick
date: 2026-07-11
tags:
  - attack.initial-access
  - attack.t1566
  - attack.t1539
logsource:
  category: application
  product: zimbra
detection:
  selection_access:
    ClientInterface: 'Classic'
  selection_change:
    EventType:
      - 'FilterRuleCreated'
      - 'ForwardingAddressChanged'
      - 'AccountSettingsModified'
  timeframe: 15m
  condition: selection_access and selection_change
falsepositives:
  - Legitimate user-initiated mailbox configuration changes made
    shortly after normal Classic Web Client use
level: medium
```

---

## 8. Remediation

1. **Upgrade to Zimbra Collaboration Suite 10.1.19 or later immediately.** This is the sole confirmed fix for the vulnerability.
2. **Prioritise any deployment where the Classic Web Client remains in active use.** Organisations that have fully migrated users to the modern web client are not affected by this specific flaw, but should confirm no users retain Classic UI access before deprioritising.
3. **Treat Zimbra patching as time-sensitive regardless of confirmed exploitation status.** Given the platform's repeated history of rapid, targeted exploitation by state-sponsored actors following disclosure (Winter Vivern, APT29, APT28), do not wait for confirmation of in-the-wild abuse before patching.
4. **Review mailbox configuration changes for high-risk accounts** — government affairs, executive, legal, and any accounts likely to be espionage targets — for unexplained forwarding rules or filter creation in the period since the flaw's disclosure window opened.
5. **Consider migrating remaining Classic Web Client users to the modern client** as a longer-term risk-reduction step, given the pattern of the legacy interface being the recurring point of compromise across multiple, unrelated Zimbra XSS vulnerabilities.
6. **Ensure email gateway and anti-phishing controls are current**, since the delivery mechanism for this class of flaw is a normally-formatted email that may not trip conventional malware/attachment scanning.

---

## 9. The Broader Pattern

This is at least the fourth Zimbra Classic Web Client or webmail cross-site scripting issue in roughly eighteen months to draw significant attention from security researchers and state-sponsored threat actors alike, following CVE-2025-66376 (exploited by APT28 against Ukrainian government targets in March 2026), CVE-2025-68645, and the older CVE-2020-7796 — all of which were added to CISA's Known Exploited Vulnerabilities catalog. That repetition is itself the story: webmail XSS in a platform used by government agencies is not a theoretical risk category for Zimbra, it is a demonstrated, recurring initial-access vector that Russian state-sponsored operators in particular have returned to again and again, because a single stored-XSS bug in a legacy but still-deployed web interface converts an ordinary phishing email into full mailbox compromise with no credential theft required.

The involvement of Google's Threat Analysis Group in this disclosure is worth sitting with, even absent a confirmed exploitation report at time of writing. TAG's mandate is to find the exploits already being used, or about to be used, against high-risk individuals — journalists, dissidents, opposition politicians — which is a materially different discovery motivation than routine bug-bounty or code-audit findings. Whether or not this specific flaw is later confirmed as exploited, the fact that legacy webmail interfaces continue to be a productive hunting ground for this class of researcher is itself a signal that defenders of government, NGO, and high-profile organisational mailboxes should weight this patch more heavily than its unscored CVSS and absent CVE ID might otherwise suggest.

---

## 10. References

| Source | URL |
|---|---|
| Zimbra Blog — Patch Release Update: Zimbra 10.1.19 | https://blog.zimbra.com/2026/07/patch-release-update-zimbra-10-1-19/ |
| BleepingComputer — Zimbra urges customers to patch critical web client XSS flaw | https://www.bleepingcomputer.com/news/security/zimbra-urges-customers-to-patch-critical-web-client-xss-flaw/ |
| Security Affairs — Update Now: Critical Zimbra Classic Web Client Flaw Could Expose Mailboxes | https://securityaffairs.com/195130/hacking/update-now-critical-zimbra-classic-web-client-flaw-could-expose-mailboxes.html |
