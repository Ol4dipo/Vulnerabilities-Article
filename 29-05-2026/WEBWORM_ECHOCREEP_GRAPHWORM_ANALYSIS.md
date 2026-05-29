# Webworm: EchoCreep and GraphWorm  Living-Off-Trusted-Services C2

**Threat Actor:** Webworm (overlaps with FishMonger, SixLittleMonkeys, Space Pirates)
**Attribution:** China-aligned APT, active since at least 2022
**Research By:** ESET (Eric Howard)  May 2026
**New Tooling:** EchoCreep (Discord C2), GraphWorm (Microsoft Graph API / OneDrive C2)
**Active Since:** March 21, 2024 (earliest EchoCreep C2 message observed)
**Targets:** Government organisations in Belgium, Italy, Serbia, Poland, Spain, Asia
**Analysis Date:** 2026-05-29
**No CVE:** Living-off-trusted-services technique  no vulnerability exploited

---

## 1. Executive Summary

Webworm, a China-aligned APT group first documented by Symantec in September 2022, has significantly upgraded its 2025 toolset with two new custom backdoors: EchoCreep, which uses Discord for command-and-control communications, and GraphWorm, which uses the Microsoft Graph API and OneDrive for the same purpose.

Both backdoors follow the same strategic logic: route all C2 through legitimate, widely-trusted platforms that organisations allowlist by default. Network monitoring that blocks unknown destinations or flags unusual protocols will not detect HTTPS traffic to discord.com or graph.microsoft.com. These platforms are used daily by millions of enterprises. The C2 traffic is indistinguishable from normal activity.

ESET analysed over 400 Discord messages sent through EchoCreep's C2 channel, finding commands to more than 50 unique targets. The earliest message dates to March 21, 2024  this campaign has been running for over a year.

| Property | Value |
|---|---|
| **Actor** | Webworm (China-aligned APT) |
| **New Tools** | EchoCreep (Discord C2), GraphWorm (MS Graph/OneDrive C2) |
| **Technique Class** | Living-off-trusted-services (LOTS) C2 |
| **Targets** | EU and Asian government entities |
| **C2 Messages Analysed** | 400+ Discord messages, 50+ unique targets |
| **Campaign Active Since** | At least March 21, 2024 |
| **Detection Challenge** | Traffic indistinguishable from legitimate Discord and Microsoft use |

---

## 2. Threat Actor Background

Webworm was first publicly documented by Symantec in September 2022. ESET assesses the group overlaps with clusters tracked as FishMonger, SixLittleMonkeys, and Space Pirates. Historical tooling includes Trochilus RAT, Gh0st RAT, and 9002 RAT.

In the past two years, Webworm began shifting away from traditional backdoors toward proxy tools and living-off-trusted-services techniques  a deliberate evolution toward greater operational stealth. The 2025 toolset is the most significant capability update since the group was first documented.

**European targeting expansion:** ESET observed operations against governmental organisations in Belgium, Italy, Serbia, Poland, and Spain, alongside continued targeting in Asia. The European government focus is consistent with broader Chinese espionage priorities in 2025.

---

## 3. EchoCreep  Discord as C2

### 3.1 Architecture

EchoCreep routes all C2 through the Discord API. Rather than connecting to an attacker-controlled server, the backdoor makes HTTPS calls to discord.com using Discord's standard message API endpoints. From a network monitoring perspective, the traffic is indistinguishable from any other Discord usage.

```
[Victim host running EchoCreep]
        |
        | HTTPS to discord.com (port 443)
        | Discord API: GET/POST /api/v10/channels/{id}/messages
        |
[Operator-controlled Discord server]
        | Four unique channels  one per victim
        | 400+ messages observed, 50+ unique targets
        |
[Webworm operators]
```

### 3.2 Capabilities

- File upload  exfiltrate files via Discord attachment API
- File download  receive operator files via Discord attachments
- Command execution  execute arbitrary commands via cmd.exe
- Runtime reporting  send execution output back to operators as Discord messages

### 3.3 Per-Victim Channel Separation

ESET found four unique channels in the analysed Discord server, each corresponding to a different victim. This separation isolates victim data, allows per-victim cleanup by deleting individual channels, and reflects disciplined long-term campaign management.

---

## 4. GraphWorm  Microsoft Graph API and OneDrive as C2

### 4.1 Architecture

GraphWorm uses Microsoft Graph API OneDrive endpoints exclusively as a job queue. The backdoor polls for new job files written by operators to a per-victim OneDrive directory, executes the job, and uploads results as files to the same directory.

```
[Victim host running GraphWorm]
        |
        | HTTPS to graph.microsoft.com (port 443)
        | /v1.0/me/drive/root/children (OneDrive endpoints only)
        |
[Operator-controlled OneDrive]
        | Separate directory per victim
        | Operator writes job files, backdoor uploads results
        |
[Webworm operators]
```

### 4.2 Capabilities (More Advanced Than EchoCreep)

- Spawn new cmd.exe session
- Execute a newly created process
- File upload to OneDrive  exfiltrate any file
- File download from OneDrive  receive tools or payloads
- Self-termination on operator signal  clean up on command

---

## 5. Supporting Infrastructure

### 5.1 Four Custom Proxy Tools

Alongside the two backdoors, Webworm deployed four custom proxy tools for internal lateral movement:

| Tool | Type |
|---|---|
| WormFrp | Custom fast reverse proxy  encrypted, multi-host chaining |
| ChainWorm | Chain proxy  internal-to-external multi-hop |
| SmuxProxy | Multiplexing proxy  multiple streams over single connection |
| WormSocket | Custom SOCKS proxy  internal network traversal |

All four support encryption and chaining across multiple hosts, making traffic analysis significantly harder than single-hop C2.

### 5.2 SoftEther VPN

Webworm continues using SoftEther VPN  a pattern shared with multiple other Chinese APT groups. SoftEther can disguise VPN traffic as normal HTTPS, has legitimate enterprise use cases that complicate detection, and is freely available.

### 5.3 Fake GitHub Staging Repository

Webworm uses a GitHub repository impersonating a WordPress fork (`github[.]com/anjsdgasdf/WordPress`) as a staging ground for malware and tool downloads. This avoids maintaining dedicated attacker infrastructure while benefiting from GitHub's trusted TLS certificate and CDN.

### 5.4 Network Infrastructure

All Webworm proxy and VPN servers use cloud infrastructure from Vultr (AS20473) and IT7 Networks (AS136907).

---

## 6. Attack Chain

```
[Initial Access  vector unknown]
Spearphishing or public-facing application exploitation suspected
                        |
                        v
[Implant Deployment]
EchoCreep or GraphWorm deployed via fake WordPress GitHub repo
                        |
EchoCreep: connects to Discord channel, awaits commands
GraphWorm: connects to OneDrive, polls for job files
                        |
                        v
[Operator Commands Delivered]
EchoCreep: operator sends Discord message to victim channel
GraphWorm: operator writes job file to victim OneDrive directory
                        |
                        v
[Execution and Exfiltration]
cmd.exe command execution
File exfiltration via Discord attachment or OneDrive upload
Results returned via Discord message or OneDrive file
                        |
                        v
[Lateral Movement]
WormFrp / ChainWorm / SmuxProxy / WormSocket deployed
SoftEther VPN tunnel for operator access
Multi-hop encrypted proxy chains across internal hosts
                        |
                        v
[Long-term Persistent Access]
Campaign maintained since at least March 2024
50+ EU and Asian government targets compromised
```

---

## 7. MITRE ATT&CK Mapping

| ID | Technique | Notes |
|---|---|---|
| T1102.002 | Web Service: Bidirectional Communication | Discord and MS Graph as C2 |
| T1567.002 | Exfiltration to Cloud Storage | OneDrive file upload |
| T1105 | Ingress Tool Transfer | File download via Discord/OneDrive |
| T1059.003 | Windows Command Shell | cmd.exe via both backdoors |
| T1090.003 | Multi-hop Proxy | WormFrp, ChainWorm, SmuxProxy, WormSocket |
| T1572 | Protocol Tunneling | SoftEther VPN as HTTPS |
| T1583.001 | Acquire Infrastructure | Vultr and IT7 Networks servers |
| T1036.005 | Masquerading | Fake WordPress GitHub repository |
| T1071.001 | Application Layer Protocol: Web | HTTPS to discord.com and graph.microsoft.com |

---

## 8. Detection Recommendations

### 8.1 The Core Detection Challenge

Standard destination-based controls will not detect this campaign. discord.com and graph.microsoft.com are globally trusted and allowlisted. Effective detection requires process-level monitoring: which process is making the API call, not just where it is going.

### 8.2 Discord Process Monitoring

```bash
# Legitimate Discord API traffic originates from:
# Discord.exe / Discord (desktop application)
# Web browsers

# Any server process, background service, or script
# connecting to discord.com/api/ is suspicious

# Process-level check on Windows:
Get-NetTCPConnection -RemotePort 443 |
  Where-Object {$_.State -eq "Established"} |
  ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    if ($proc.Name -notmatch "Discord|chrome|msedge|firefox") {
      $dns = [System.Net.Dns]::GetHostEntry($_.RemoteAddress)
      if ($dns.HostName -match "discord") {
        Write-Output "SUSPICIOUS: $($proc.Name) connecting to Discord"
      }
    }
  }
```

### 8.3 Microsoft Graph API Monitoring

```kusto
// GraphWorm  unusual Graph API access from server processes
DeviceNetworkEvents
| where RemoteUrl has "graph.microsoft.com"
| where InitiatingProcessFileName !in~ (
    "OneDrive.exe", "Teams.exe", "OUTLOOK.EXE",
    "chrome.exe", "msedge.exe", "firefox.exe"
  )
| where RemoteUrl contains "/drive/"
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteUrl
| order by TimeGenerated desc
```

### 8.4 KQL (Microsoft Sentinel)

```kusto
// Webworm EchoCreep  non-Discord-client process accessing Discord API
DeviceNetworkEvents
| where RemoteUrl has "discord.com" or RemoteUrl has "discordapp.com"
| where InitiatingProcessFileName !in~ (
    "Discord.exe", "chrome.exe", "msedge.exe",
    "firefox.exe", "iexplore.exe", "brave.exe"
  )
| where RemoteUrl contains "/api/"
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteUrl
| order by TimeGenerated desc

// Webworm GraphWorm  unusual OneDrive file operations from server hosts
CloudAppEvents
| where Application == "Microsoft OneDrive for Business"
| where ActionType in ("FileUploaded", "FileDownloaded")
| where AccountDisplayName !in (known_onedrive_users)
| where IPAddress !in (known_office_ips)
| summarize FileCount = count(), FirstSeen = min(TimeGenerated)
  by AccountDisplayName, IPAddress, bin(TimeGenerated, 1h)
| where FileCount > 10
| order by FileCount desc
```

### 8.5 Sigma Rules

```yaml
title: Webworm EchoCreep Discord C2 (Living-off-Trusted-Services)
id: r5s6t7u8-9v0w-1x2y-3z4a-5b6c7d8e9f0g
status: experimental
description: >
  Detects non-browser processes making API calls to Discord endpoints,
  consistent with Webworm's EchoCreep backdoor C2 technique.
author: Fredrick
date: 2026-05-29
references:
  - https://www.welivesecurity.com/en/eset-research/webworm-new-burrowing-techniques/
  - https://thehackernews.com/2026/05/webworm-deploys-echocreep-and-graphworm.html
logsource:
  category: network_connection
  product: windows
detection:
  selection_discord:
    DestinationHostname|endswith:
      - 'discord.com'
      - 'discordapp.com'
    DestinationPort: 443
  filter_known_clients:
    Image|endswith:
      - '\Discord.exe'
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
      - '\iexplore.exe'
  condition: selection_discord and not filter_known_clients
falsepositives:
  - Applications with legitimate Discord webhook integrations
level: medium
tags:
  - attack.command_and_control
  - attack.t1102.002
  - threat_actor.webworm

---
title: Webworm GraphWorm MS Graph API C2 (Living-off-Trusted-Services)
id: s6t7u8v9-0w1x-2y3z-4a5b-6c7d8e9f0g1h
status: experimental
description: >
  Detects non-M365-application processes accessing Microsoft Graph OneDrive
  endpoints, consistent with Webworm's GraphWorm backdoor C2 technique.
logsource:
  category: network_connection
  product: windows
detection:
  selection_graph:
    DestinationHostname: 'graph.microsoft.com'
    DestinationPort: 443
  filter_known_apps:
    Image|endswith:
      - '\OneDrive.exe'
      - '\Teams.exe'
      - '\OUTLOOK.EXE'
      - '\chrome.exe'
      - '\msedge.exe'
  condition: selection_graph and not filter_known_apps
level: medium
tags:
  - attack.command_and_control
  - attack.t1102.002
  - attack.t1567.002
  - threat_actor.webworm
```

---

## 9. Network IOCs

| Indicator | Type | Notes |
|---|---|---|
| `github[.]com/anjsdgasdf/WordPress` | URL | Fake WordPress malware staging repo |
| AS20473 (Vultr) | ASN | Webworm proxy and VPN infrastructure |
| AS136907 (IT7 Networks) | ASN | Webworm proxy and VPN infrastructure |
| Non-Discord-client process accessing discord.com/api/ | Behaviour | EchoCreep indicator |
| Non-M365-app process accessing graph.microsoft.com/drive/ | Behaviour | GraphWorm indicator |
| Regular timed file creation in OneDrive from server hosts | Behaviour | GraphWorm job polling pattern |

---

## 10. Living-Off-Trusted-Services Context

Webworm joins a growing list of threat actors using legitimate cloud platforms as C2:

| Actor / Context | Platform | Year |
|---|---|---|
| Multiple actors | Google Calendar | 2024 |
| Multiple actors | Solana blockchain | 2024 |
| Multiple actors | Telegram | 2023-2025 |
| Webworm | Discord | 2024-2025 |
| Webworm | Microsoft Graph / OneDrive | 2024-2025 |

The defensive implication is consistent across all cases: destination-based network controls are insufficient. Effective detection requires process-level telemetry correlating which applications are making API calls to trusted platforms, behavioural analysis of call patterns, and endpoint visibility that goes beyond network flow data.

---

## 11. Timeline

| Date | Event |
|---|---|
| **September 2022** | Webworm first documented by Broadcom/Symantec |
| **March 21, 2024** | Earliest EchoCreep Discord C2 message observed by ESET |
| **2025** | GraphWorm and EchoCreep deployed, four custom proxy tools added |
| **May 20, 2026** | ESET publishes full technical analysis |
| **May 29, 2026** | This analysis |

---

## 12. References

| Source | URL |
|---|---|
| ESET WeLiveSecurity (Primary) | https://www.welivesecurity.com/en/eset-research/webworm-new-burrowing-techniques/ |
| The Hacker News | https://thehackernews.com/2026/05/webworm-deploys-echocreep-and-graphworm.html |
| Dark Reading | https://www.darkreading.com/endpoint-security/chinas-webworm-discord-microsoft-graphs |

---

*Analysis performed using ESET WeLiveSecurity primary research, The Hacker News, Dark Reading, and open-source threat intelligence.*
