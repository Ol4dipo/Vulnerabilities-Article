# Microsoft Defender 'RoguePlanet' Zero-Day — Unpatched LPE/RCE on Fully-Patched Windows

---

## Metadata

| Field | Detail |
|---|---|
| **CVE ID** | Not yet assigned (publicly disclosed zero-day) |
| **CVSS Score / Severity** | Not yet scored — LPE yields SYSTEM; potential RCE vector under investigation |
| **CWE** | CWE-362 (Race Condition), CWE-59 (Improper Link Resolution / Symlink) |
| **Analysis Date** | 29 June 2026 |
| **Patch Released** | No — Microsoft investigating as of 10 June 2026 |
| **Active Exploitation** | Not confirmed in the wild; PoC publicly released |
| **Discovered By** | Nightmare Eclipse (independent security researcher) |
| **Affected Versions** | Windows 10 and Windows 11 (fully patched with June 2026 updates, KB5094126) |
| **Fixed Version** | None available |

---

## 1. Executive Summary

A security researcher known as Nightmare Eclipse publicly released a proof-of-concept exploit — named "RoguePlanet" — for an unpatched race condition in Microsoft Defender that grants SYSTEM privileges on fully-patched Windows 10 and Windows 11 systems. The exploit was published on 9 June 2026, hours after Microsoft's June 2026 Patch Tuesday addressed two *other* Defender vulnerabilities previously disclosed by the same researcher.

The release is part of an ongoing adversarial disclosure dispute: Nightmare Eclipse has accused Microsoft of removing prior exploit repositories from GitHub and GitLab and of threatening researchers with law-enforcement referrals rather than paying bug bounties. At least five zero-days have now been publicly released under this dispute, several of which have since been exploited in attacks.

ThreatLocker independently confirmed they reproduced the RoguePlanet exploit against a fully-patched Windows 11 system. Microsoft confirmed awareness and active investigation on 10 June 2026 but has not issued a patch.

| Verdict | Key Facts |
|---|---|
| **Impact** | Local privilege escalation to SYSTEM on any fully-patched Windows 10/11 machine |
| **Exploit availability** | Public PoC; independently reproduced by ThreatLocker |
| **Patch status** | None — Microsoft investigating |
| **Attack surface** | Any Windows host running Microsoft Defender (essentially the entire Windows installed base) |
| **Prior escalation** | Previous zero-days in this series have been weaponised in attacks |
| **Potential upside for attackers** | Originally developed as an RCE; full RCE path may still exist |

---

## 2. Product Background

Microsoft Defender (formerly Windows Defender) is the built-in antivirus and anti-malware platform shipped with every version of Windows 10 and Windows 11. It runs as a highly privileged service (`MsMpEng.exe`) with SYSTEM-level access so that it can scan files, memory, and processes that user-mode software cannot reach. This elevated privilege level is inherent to its function — and also makes it an attractive target for privilege-escalation research.

Defender's scanning engine (`mpengine.dll`) processes a vast range of file types and formats, including container images such as VHD/VHDX virtual disk files and files hosted on remote SMB shares. The engine processes these objects proactively and in the background, meaning that simply placing a file in a monitored location (or opening an SMB share) can trigger Defender to act on attacker-controlled content with SYSTEM privileges.

This architecture — a high-privilege service consuming attacker-controlled content — has been the basis for multiple prior Defender vulnerabilities, including those found by Nightmare Eclipse (BlueHammer, RedSun, GreenPlasma, YellowKey) and earlier research by Project Zero and others.

---

## 3. Vulnerability Details

### Root Cause

RoguePlanet exploits a **race condition** in Microsoft Defender's file-handling logic. The specific code path involves Defender's processing of files hosted on remote SMB shares and its interaction with Windows symlink/junction resolution.

The exploit was originally developed as a **remote code execution** vulnerability: by coercing a victim into opening a VHD/VHDX file hosted on an attacker-controlled SMB server, Defender would process the file with SYSTEM privileges, and a race condition in the handling could be won to cause Defender to overwrite its own binary files. Successful exploitation of this original path yielded arbitrary RCE.

Microsoft silently hardened the `mpengine!SysIO*` API family in mid-May 2026, partially blocking the junction/symlink attack path. The researcher rewrote the exploit to work around this mitigation. The current public PoC achieves reliable **local privilege escalation to SYSTEM**; whether a full RCE variant can be re-derived from this revised code base remains unconfirmed.

### Why It Is Architecturally Significant

Defender runs under SYSTEM and is intimately trusted by the Windows kernel. Any vulnerability that allows an attacker to influence Defender's behaviour at the SYSTEM privilege level effectively bypasses one of the most fundamental boundaries in the Windows security model. Unlike a kernel exploit, this does not require deep knowledge of kernel internals; it leverages Defender's own trusted status against the system.

The race condition class is particularly difficult to patch reliably because it requires fixing the timing window *and* all equivalent paths that share the same vulnerable logic — a challenge Microsoft's prior series of partial fixes illustrates clearly.

### Affected Endpoints / Code

- `mpengine.dll` — Defender scanning engine, specifically the `SysIO*` API family
- VHD/VHDX processing code path within `mpengine`
- SMB share file-processing logic
- Symlink/junction evaluation during file scanning

---

## 4. Full Attack Chain

```
ATTACKER (local unprivileged user on target machine, OR remote with user interaction)
│
├─[Variant A — Local Privilege Escalation, confirmed working]
│   ├─ Execute RoguePlanet PoC as any local user
│   ├─ PoC triggers race condition in mpengine.dll file-handling
│   ├─ Race won: Defender performs privileged file operation on attacker-controlled path
│   └─ CMD.EXE spawned with SYSTEM privileges
│       → Full local privilege escalation achieved
│
├─[Variant B — Potential RCE (researcher-noted, not fully confirmed in public PoC)]
│   ├─ Attacker hosts malicious VHD/VHDX on attacker-controlled SMB share
│   ├─ Victim opens SMB share (social engineering or coercion required)
│   ├─ Defender automatically processes VHD/VHDX with SYSTEM privileges
│   ├─ Race condition triggered during remote file processing
│   └─ Outcome: Defender overwrites own binaries → RCE
│       → Status: Partially blocked by May 2026 Defender hardening;
│                 full viability unconfirmed in current PoC
│
└─[POST-EXPLOITATION (both variants)]
    ├─ SYSTEM shell provides unrestricted access to entire OS
    ├─ Disable security tooling, dump credentials (LSASS), install persistence
    └─ Lateral movement using harvested credentials
```

---

## 5. Campaign Intelligence

### Timeline

| Date | Event |
|---|---|
| Prior to May 2026 | Nightmare Eclipse develops RoguePlanet as an RCE via VHD/SMB path |
| ~May 2026 | Microsoft silently hardens `mpengine!SysIO*` API, partially blocking the exploit |
| June 9, 2026 | Nightmare Eclipse publishes RoguePlanet PoC on self-hosted Git platform (projectnightcrawler.dev); timed to drop same day as Microsoft's June Patch Tuesday |
| June 9, 2026 (same day) | ThreatLocker independently reproduces exploit on fully-patched Windows 11 with KB5094126 |
| June 10, 2026 | Microsoft acknowledges the report and confirms active investigation |
| June 29, 2026 | No patch released; researcher continues to maintain self-hosted repository |

### Threat Actor Context

This is a disclosed-PoC situation, not a named threat actor campaign — however, the researcher dispute context is material:

- Nightmare Eclipse has released at least five Windows/Defender zero-days publicly: **BlueHammer**, **RedSun**, **GreenPlasma**, **YellowKey**, and now **RoguePlanet**.
- Per BleepingComputer reporting, "recently leaked Windows zero-days now exploited in attacks" — indicating that prior releases in this series were weaponised.
- The PoC is hosted on a self-managed platform (projectnightcrawler.dev) after GitHub and GitLab repositories were reportedly removed.
- Microsoft's public response has been characterised by the community as threatening rather than constructive, which is driving further disclosures.

### Confirmed Victims

None identified for RoguePlanet specifically. Prior zero-days in this series (BlueHammer, RedSun) have been exploited in attacks per BleepingComputer reporting.

### IOC Table

| Type | Value / Indicator | Notes |
|---|---|---|
| Process | `cmd.exe` or `powershell.exe` spawned as child of `MsMpEng.exe` | Abnormal parent-child relationship; strong indicator of exploitation |
| Process privilege | Process tokens with SYSTEM SID where parent was user-mode process | LPE indicator |
| File system | Modifications to `C:\ProgramData\Microsoft\Windows Defender\` | Defender file tampering |
| Network | Outbound SMB connections from `MsMpEng.exe` to external hosts | Potential Variant B staging |
| File | VHD/VHDX files placed in Defender-monitored paths by unprivileged user | Pre-exploitation staging |

---

## 6. MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|---|---|---|
| T1068 | Exploitation for Privilege Escalation | Core technique — unprivileged → SYSTEM |
| T1203 | Exploitation for Client Execution | Variant B: victim interaction with SMB share triggers exploitation |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Post-SYSTEM: attacker can disable Defender entirely |
| T1003.001 | OS Credential Dumping: LSASS Memory | SYSTEM privileges enable LSASS dump for credential theft |
| T1543.003 | Create or Modify System Process | Persistence via system service installation with SYSTEM privileges |
| T1059.003 | Windows Command Shell | CMD.EXE spawned at SYSTEM via exploit |
| T1574.010 | Hijack Execution Flow: Services File Permissions Weakness | Post-SYSTEM: binary hijacking of Defender or other services |

---

## 7. Detection Recommendations

### Version / Patch Status Check

```powershell
# Check Windows update status — confirm KB5094126 is installed (still vulnerable)
Get-HotFix -Id KB5094126

# Check Defender engine version (no safe version exists yet)
Get-MpComputerStatus | Select-Object AMEngineVersion, AMProductVersion
```

### Anomalous Process Hierarchy Detection

**KQL — Microsoft Sentinel:**
```kql
// Detect CMD or PowerShell spawned under MsMpEng.exe (Defender engine)
SecurityEvent
| where EventID == 4688
| where ParentProcessName has "MsMpEng.exe"
| where NewProcessName has_any ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe")
| project TimeGenerated, Computer, Account, ParentProcessName, NewProcessName, CommandLine
| sort by TimeGenerated desc
```

```kql
// Detect SYSTEM-level process creation from user-initiated parent chain
SecurityEvent
| where EventID == 4688
| where SubjectUserName !endswith "$"
| where TokenElevationType == "%%1937"  // Full token (SYSTEM)
| where ParentProcessName !has_any ("services.exe","lsass.exe","wininit.exe","svchost.exe")
| project TimeGenerated, Computer, Account, NewProcessName, ParentProcessName, TokenElevationType
```

### Defender Telemetry

```powershell
# Check for unexpected Defender engine crashes or restarts (race condition artifact)
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
  Where-Object { $_.Id -in @(1116, 1117, 5007) } |
  Select-Object TimeCreated, Id, Message | Format-List
```

### Suricata Rule (Variant B — SMB staging)

```yaml
alert smb any any -> $HOME_NET any (
  msg:"ET EXPLOIT Defender RoguePlanet Potential VHD/VHDX Remote Staging";
  flow:established,to_server;
  content:".vhdx";
  nocase;
  classtype:policy-violation;
  sid:9026300001;
  rev:1;
)
```

### Sigma Rule

```yaml
title: Microsoft Defender MsMpEng Spawns Shell — Potential RoguePlanet LPE
id: b9c3f182-7e44-4a21-b0da-21c9e4d8f3a1
status: experimental
description: |
  Detects CMD or PowerShell spawned as a direct child of MsMpEng.exe,
  which is consistent with exploitation of the RoguePlanet race condition
  zero-day (no CVE assigned as of 2026-06-29).
references:
  - https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/
  - https://deadeclipse666.blogspot.com/
author: Fredrick
date: 2026-06-29
tags:
  - attack.privilege_escalation
  - attack.t1068
  - attack.execution
  - attack.t1059.003
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\MsMpEng.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
  condition: selection
falsepositives:
  - Highly unlikely under normal operating conditions
level: critical
```

---

## 8. Remediation

Given the absence of a vendor patch, defenders must focus on compensating controls:

1. **Application allowlisting** — ThreatLocker's CEO confirmed that application allowlisting prevents the exploit from executing. Allowlisting blocks the spawned SYSTEM shell from performing any meaningful post-exploitation action even if the race condition is won.

2. **Monitor for abnormal process hierarchy** — Deploy the KQL / Sigma rules above. A SYSTEM-level CMD or PowerShell spawned under `MsMpEng.exe` is a high-confidence indicator; investigate immediately.

3. **Restrict outbound SMB** — Block outbound TCP 445 from endpoints to external IP addresses at the network boundary. This eliminates the Variant B remote trigger path.

4. **Follow Microsoft advisories** — Watch https://msrc.microsoft.com for a patch. When released, apply immediately; prior Defender zero-days in this series were weaponised within days of public disclosure.

5. **Harden Defender's scanning scope** — Where operationally feasible, reduce Defender's automatic scanning of remote network shares in environments where this is not required.

6. **Threat hunt for prior exploitation** — Search for the IOCs above covering the period since 9 June 2026 (the date of public PoC release). Focus on anomalous SYSTEM-level process creation chains.

---

## 9. The Broader Pattern

RoguePlanet is not merely a technical curiosity — it is a symptom of a structural failure in the software-vendor–researcher relationship, and that failure has direct consequences for defenders.

Nightmare Eclipse's series of zero-days (BlueHammer → RedSun → GreenPlasma → YellowKey → RoguePlanet) represents a coordinated escalation strategy in which an aggrieved researcher weaponises public disclosure as leverage against a vendor that they believe is not acting in good faith. Whether or not one agrees with the approach, the outcome is clear: multiple unpatched vulnerabilities in software installed on over a billion Windows endpoints, with public exploits freely available. Some prior releases in this series are already confirmed exploited in attacks.

This raises a question that the security community is actively debating: when a vendor removes a researcher's repository and implicitly threatens law enforcement action, has it forfeited the protections of coordinated disclosure? The debate is not merely academic — its resolution shapes whether critical vulnerability information flows from discoverers to defenders in a timely manner, or is suppressed until adversaries find the same path independently.

For defenders, the lesson is narrower and more urgent: antivirus/EDR platforms are high-privilege, high-trust code that processes attacker-controlled content at scale. They are not a security boundary — they are an attack surface. Any vulnerability in an endpoint security product is, by definition, a vulnerability on every endpoint that product protects. The architectural irony is stark, and it demands that security tooling itself be held to the same rigorous patching standards as the OS beneath it.

---

## 10. References

| Source | URL |
|---|---|
| BleepingComputer — RoguePlanet disclosure | https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/ |
| BleepingComputer — Prior zero-days exploited in attacks | https://www.bleepingcomputer.com/news/security/recently-leaked-windows-zero-days-now-exploited-in-attacks/ |
| BleepingComputer — BlueHammer background | https://www.bleepingcomputer.com/news/security/disgruntled-researcher-leaks-bluehammer-windows-zero-day-exploit/ |
| BleepingComputer — RedSun disclosure | https://www.bleepingcomputer.com/news/microsoft/new-microsoft-defender-redsun-zero-day-poc-grants-system-privileges/ |
| Microsoft MSRC — Coordinated Vulnerability Disclosure | https://www.microsoft.com/en-us/msrc/cvd |
