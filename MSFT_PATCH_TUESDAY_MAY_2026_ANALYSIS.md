# Microsoft Patch Tuesday May 2026 Full Forensic Analysis

**Advisory:** Microsoft Security Update Guide; May 13, 2026
**Total CVEs Fixed:** 138
**Critical:** 30
**Important:** 104
**Zero-Days Exploited:** None (first zero-day-free Patch Tuesday since June 2024)
**Analysis Date:** 2026-05-14
**Notable CVEs:** CVE-2026-41089 (Netlogon RCE, CVSS 9.8), CVE-2026-41096 (DNS Client RCE, CVSS 9.8), CVE-2026-40402 (Hyper-V priv esc, CVSS 9.3)
**AI Discovery Note:** Microsoft confirmed 16 of this month's fixes were discovered via AI-assisted vulnerability research

---

## 1. Executive Summary

Microsoft's May 2026 Patch Tuesday is a significant release; 138 vulnerabilities, 30 Critical, no zero-days actively exploited. While the absence of exploited zero-days may invite complacency, the breadth and severity of this month's fixes demand the same urgency as any other cycle.

Two vulnerabilities stand out above everything else: a stack-based buffer overflow in Windows Netlogon (CVE-2026-41089, CVSS 9.8) and a heap-based buffer overflow in Windows DNS Client (CVE-2026-41096, CVSS 9.8). Both are unauthenticated network RCE vulnerabilities targeting the most sensitive components of Windows domain infrastructure; domain controllers and DNS resolution. Tenable's senior researcher noted they are at the top of the priority list this month: neither needs internet reachability to matter.

A third critical vulnerability; a use-after-free in Windows Hyper-V (CVE-2026-40402, CVSS 9.3); enables a guest-to-host escape from a virtual machine to the Hyper-V host with SYSTEM privileges. In multi-tenant and private cloud environments, the blast radius of that capability is severe.

Microsoft also disclosed that 16 of this month's fixes were discovered via AI-assisted vulnerability research, confirming that the volume of Patch Tuesday releases is expected to increase as AI-powered vulnerability discovery scales.

Five months into 2026, Microsoft has already patched over 500 CVEs; on pace to surpass 2020's record of 1,245 for a full calendar year.

| Property | Value |
|---|---|
| **Total CVEs** | 138 |
| **Critical** | 30 |
| **Zero-Days Exploited** | 0; first since June 2024 |
| **Top Priority** | CVE-2026-41089 (Netlogon RCE) and CVE-2026-41096 (DNS Client RCE) |
| **AI-Discovered Fixes** | 16 of 138 |
| **2026 CVEs to Date** | 500+ (pace to break 2020 annual record) |

---

## 2. Priority Tier 1; Patch Immediately

### CVE-2026-41089; Windows Netlogon RCE (CVSS 9.8)

A stack-based buffer overflow in Windows Netlogon allows an unauthenticated remote attacker to execute arbitrary code on a domain controller by sending a specially crafted network request.

```
Attack profile:
- No authentication required
- No user interaction required
- Network-accessible; reachable from within the domain network
- Target: Windows Server 2012 through Windows Server 2025 acting as domain controllers
- Impact: Full RCE on domain controller = complete Active Directory compromise
```

Historical context: Netlogon has been attacked before. CVE-2020-1472 (Zerologon) allowed privilege escalation to domain admin via a flaw in the Netlogon authentication protocol. A successful RCE on a domain controller is the highest-impact single compromise in an Active Directory environment.

Tenable's priority assessment: top of the list this month.

### CVE-2026-41096; Windows DNS Client RCE (CVSS 9.8)

A heap-based buffer overflow in the Windows DNS Client allows an attacker to execute code by sending a malicious DNS response that triggers memory corruption in the DNS Client.

```
Attack profile:
- No authentication required
- Triggered by a malicious DNS response
- Affected systems: Windows 11, Windows Server 2022, Windows Server 2025
- No internet reachability required to matter; on-path attackers on internal networks qualify
- DNS poisoning or rogue DNS server on the network is sufficient to deliver the payload
```

The DNS client is present on every Windows system. A malicious DNS response on the local network; from a compromised host acting as a rogue resolver, or via a successful DNS poisoning attack; triggers the overflow without any user action.

### CVE-2026-40402; Windows Hyper-V Privilege Escalation to SYSTEM (CVSS 9.3)

A use-after-free vulnerability in Windows Hyper-V allows an unauthenticated attacker to gain SYSTEM privileges and access the Hyper-V host environment from within a guest virtual machine.

```
Attack profile:
- Exploitable from a guest VM; no host access required
- Achieves SYSTEM on the Hyper-V host
- Affects: Windows Server 2022, Windows 11 23H2
- High-risk environments: multi-tenant hosting, private cloud, VDI deployments
```

In multi-tenant environments, one compromised VM becomes a full host compromise.

---

## 3. Priority Tier 2; Patch Within 48 Hours

### CVE-2026-42898; Microsoft Dynamics 365 On-Premises RCE (CVSS 9.9)

A code injection vulnerability in Microsoft Dynamics 365 on-premises allows an authenticated attacker with low privileges to execute code over the network. No user interaction required. The vulnerability allows manipulation of process session data within Dynamics CRM. With basic access, an attacker can turn a business application server into a remote execution platform.

### CVE-2026-41103; Microsoft SSO Plugin for Jira and Confluence EoP (CVSS 9.1)

The only vulnerability this month rated Exploitation More Likely. An unauthenticated attacker can send a specially crafted SSO response during login and trick the system into accepting a forged identity; bypassing Microsoft Entra ID authentication entirely and accessing Jira or Confluence as any valid user.

### Microsoft Word RCEs; Four Critical Vulnerabilities

| CVE | Type | Exploitation Rating |
|---|---|---|
| CVE-2026-40361 | Use-after-free | More Likely |
| CVE-2026-40364 | Heap-based buffer overflow | More Likely |
| CVE-2026-40366 | Use-after-free | Less Likely |
| CVE-2026-40367 | Untrusted pointer dereference | Unlikely |

All four Word vulnerabilities are exploitable via the Preview Pane; a victim does not need to open the document. CVSS 8.4, rated Critical. CVE-2026-40361 and CVE-2026-40364 are assessed as More Likely to be exploited.

### CVE-2026-40365; Microsoft SharePoint Server RCE (Critical)

An authenticated attacker with at least Site Owner privileges can write arbitrary code and execute it remotely on the SharePoint Server.

---

## 4. Priority Tier 3; Patch This Week

### CVE-2026-42826; Azure DevOps Information Disclosure (CVSS 10.0)

Maximum severity. An unauthenticated actor can disclose sensitive information from Azure DevOps over a network. Note: Microsoft states this requires no customer action; it is a vendor-side fix. Verify your Azure DevOps tenants are receiving this update.

### CVE-2026-33109; Azure Managed Instance for Apache Cassandra RCE (CVSS 9.9)

An authorised attacker can execute code over a network. Vendor-side fix; no customer action required if using managed service.

### CVE-2026-32161; Windows Native Wi-Fi Miniport Driver RCE (Critical)

A race condition (use-after-free) in the Wi-Fi driver allows an unauthenticated attacker to execute code over an adjacent network. Relevant for enterprise environments with untrusted wireless networks.

---

## 5. Secure Boot Certificate Rotation Deadline

The most critical non-CVE update this month involves mandatory rollout of updated Secure Boot certificates. Devices failing to receive these updates before the **June 26, 2026 deadline** face catastrophic boot-level security failures or degraded security states. Ensure your entire fleet successfully rotates to the new trust anchors before the deadline.

---

## 6. AI-Assisted Discovery Context

Microsoft confirmed that 16 of this month's 138 fixes were found via AI-assisted vulnerability research. This confirms what Copy Fail, CVE-2026-3854 (GitHub), and multiple other 2026 vulnerabilities have already demonstrated: AI-powered vulnerability discovery is transitioning from research curiosity to production-grade defense and offense capability.

Microsoft's MDASH (Multi-Model Agentic Scanning Harness); a system that orchestrates more than 100 specialised AI agents across an ensemble of frontier and distilled models; is being used internally to find bugs in the Windows codebase. Satnam Narang at Tenable noted that Microsoft has already patched over 500 CVEs five months into 2026, and AI-assisted discovery is expected to increase the scale of future Patch Tuesday releases further.

---

## 7. MITRE ATT&CK Mapping (Key CVEs)

| CVE | ID | Technique |
|---|---|---|
| CVE-2026-41089 (Netlogon) | T1210 | Exploitation of Remote Services |
| CVE-2026-41096 (DNS Client) | T1557 | Adversary-in-the-Middle (DNS-based delivery) |
| CVE-2026-40402 (Hyper-V) | T1611 | Escape to Host |
| CVE-2026-41103 (SSO Jira) | T1078 | Valid Accounts (forged identity) |
| Word RCEs | T1566.001 | Phishing: Spearphishing Attachment / Preview Pane |
| CVE-2026-42898 (Dynamics) | T1190 | Exploit Public-Facing Application |

---

## 8. Patch Prioritisation Guidance

```powershell
# Priority 1: Domain controllers (Netlogon + DNS Client)
# Patch within 24 hours

# Check domain controllers for pending updates
Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Verbose | 
  Where-Object KB -in ('KB5091157','KB5091158') | 
  Install-WindowsUpdate

# Priority 2: Hyper-V hosts
# Patch within 24 hours; guest-to-host escape risk

# Priority 3: Internet-facing SharePoint, Dynamics 365, Office
# Patch within 48 hours

# Priority 4: All remaining Windows systems (DNS Client on all)
# Patch within standard maintenance window

# Secure Boot deadline verification
# Check Secure Boot certificate status
Confirm-SecureBootUEFI
# If returns True; Secure Boot enabled
# Ensure May 2026 updates applied before June 26, 2026 deadline

# Post-patch verification; domain controllers
dcdiag /test:netlogon
# Check for Netlogon errors post-patch

nslookup microsoft.com
# Verify DNS resolution working correctly post-patch
```

---

## 9. Complete Critical CVE List

| CVE | Component | Type | CVSS | Notes |
|---|---|---|---|---|
| CVE-2026-41089 | Windows Netlogon | RCE | 9.8 | Unauthenticated, stack buffer overflow on DC |
| CVE-2026-41096 | Windows DNS Client | RCE | 9.8 | Unauthenticated, heap buffer overflow |
| CVE-2026-40402 | Windows Hyper-V | EoP to SYSTEM | 9.3 | Guest-to-host VM escape |
| CVE-2026-42898 | Dynamics 365 On-Premises | RCE | 9.9 | Code injection, low-priv auth required |
| CVE-2026-42826 | Azure DevOps | Info Disclosure | 10.0 | Vendor-side fix |
| CVE-2026-33109 | Azure Cassandra Managed | RCE | 9.9 | Vendor-side fix |
| CVE-2026-41103 | SSO Plugin Jira/Confluence | EoP | 9.1 | Exploitation More Likely |
| CVE-2026-40361 | Microsoft Word | RCE | 8.4 | Preview Pane, More Likely |
| CVE-2026-40364 | Microsoft Word | RCE | 8.4 | Preview Pane, More Likely |
| CVE-2026-40365 | SharePoint Server | RCE | Critical | Site Owner or higher |
| CVE-2026-32161 | Wi-Fi Miniport Driver | RCE | Critical | Adjacent network |
| CVE-2026-42823 | Azure Logic Apps | EoP | 9.9 | Vendor-side fix |
| CVE-2026-33117 | Azure SDK | Auth Bypass | 9.1 | Vendor-side fix |

---

*Analysis performed using Microsoft MSRC advisories, Tenable research, SC World, The Hacker News, Talos Intelligence, and Zero Day Initiative.*
