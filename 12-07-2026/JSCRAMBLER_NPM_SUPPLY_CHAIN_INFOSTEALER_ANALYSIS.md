# Jscrambler npm Package Compromise — Rust Infostealer Shipped via Malicious Preinstall Hook in Version 8.14.0

---

## Metadata

| Field | Detail |
|---|---|
| **CVE ID** | None assigned. This is a software supply-chain compromise of a legitimate npm package rather than a vulnerability in application logic, and no CVE identifier has been published in connection with it |
| **CVSS Score / Severity** | Not applicable / not scored. As a malicious-package incident rather than a scored software flaw, no CVSS vector has been issued; practical severity is high given unauthenticated, install-time code execution with broad credential-harvesting capability |
| **CWE** | CWE-506 (Embedded Malicious Code) most closely describes the mechanism; the underlying enabler is CWE-829 (Inclusion of Functionality from Untrusted Control Sphere), given the payload entered through an unreviewed publish to the npm registry |
| **Analysis Date** | 12 July 2026 |
| **Patch Released** | No patch in the traditional sense. Jscrambler has since published version 8.15.0 from the same maintainer account, containing no install script and no bundled binary. Critically, the malicious 8.14.0 release has **not** been unpublished or deprecated on the npm registry as of this analysis |
| **Active Exploitation** | Confirmed. The malicious payload executed automatically on any install of version 8.14.0 performed with an npm client that still runs preinstall scripts by default; Socket detected the release within six minutes of publication, meaning an unknown but non-zero number of installs occurred in that window and afterward |
| **Discovered By** | Socket (initial detection, six minutes post-publication); further independent analysis by StepSecurity and SafeDep |
| **Affected Versions** | jscrambler npm package version 8.14.0 only. The jscrambler plugins for webpack, gulp, Metro, and grunt were not affected and remained on clean prior releases |
| **Fixed Version** | 8.15.0 (clean release, same maintainer account) or a rollback to 8.13.0 (last known-clean release prior to the incident). Version 8.14.0 remains live on the npm registry, meaning pinned installs will continue to pull the compromised build |

---

## 1. Executive Summary

On 11 July 2026, version 8.14.0 of the jscrambler npm package — a commercial JavaScript obfuscation and application-protection tool typically installed as a build-time development dependency or invoked from continuous integration (CI) pipelines — was published to the npm registry carrying a malicious preinstall hook. The hook required no import statement and no command-line invocation; the act of installing the package was sufficient to trigger it. Socket's automated scanning flagged the release six minutes after publication, an unusually fast catch that nonetheless left a window in which any developer machine or CI runner that pulled the package would already have executed the payload.

The mechanism was a small loader script (`dist/setup.js`) that unpacked a roughly 7.8MB container (`dist/intro.js`, despite its JavaScript-sounding name) holding three gzip-compressed native binaries — one each for Linux, Windows, and macOS. The loader selected the binary matching the host operating system, wrote it under a randomly generated filename in the system temp directory, marked it executable, and launched it detached with output suppressed. Subsequent analysis by Socket identified the payload as a Rust-compiled infostealer built for all three platforms, targeting cloud credentials (AWS, Azure, Google Cloud, including CI metadata endpoints), cryptocurrency wallets (MetaMask, Phantom, Exodus), the Bitwarden password vault, browser-stored passwords and cookies, chat and gaming session tokens (Discord, Slack, Telegram, Steam), and — notably — configuration files and API keys belonging to AI coding assistants including Claude Desktop, Cursor, Windsurf, VS Code, and Zed, several of which store Model Context Protocol (MCP) server credentials.

None of the added files appear in jscrambler's public GitHub repository, whose most recent tag remains 8.13.0, and StepSecurity and SafeDep both independently confirmed no matching commit, tag, or pull request exists for the 8.14.0 release. This indicates the version was pushed directly to the npm registry through a compromised maintainer account or build pipeline, bypassing the project's normal release process entirely — the exact vector has not yet been established.

| Verdict | Key Facts |
|---|---|
| **Severity** | Unscored (supply-chain compromise, not a CVE), but functionally critical: silent, unauthenticated, install-time code execution with full-machine credential harvesting and kernel-level capability on Linux |
| **Exploitation status** | Confirmed and active. The payload executed automatically wherever version 8.14.0 was installed via a client that still runs preinstall scripts by default |
| **Scope** | jscrambler CLI package only (~15,800 weekly downloads); companion build-tool plugins (webpack, gulp, Metro, grunt) were unaffected |
| **What's targeted** | Cloud provider credentials, CI/CD secrets, cryptocurrency wallets, password manager vaults, browser sessions, chat/gaming tokens, and AI coding assistant API keys/MCP credentials |
| **Persistence** | Hidden Windows scheduled task (relaunches every minute); macOS LaunchAgent (reloads on login) |
| **Outstanding risk** | Version 8.14.0 remains published on the npm registry at time of writing; any lockfile or CI configuration pinned to it will continue to install the stealer |

---

## 2. Product Background

Jscrambler is a commercial JavaScript and web application protection platform used to obfuscate, harden, and monitor client-side code against reverse engineering and tampering. Its core CLI package is typically added as a development dependency and invoked from build pipelines or CI/CD systems as part of a release process, alongside companion plugins for common bundlers such as webpack, gulp, Metro, and grunt.

This build-time, CI-integrated positioning is what makes jscrambler — and tools like it — a disproportionately valuable target for a supply-chain attacker relative to its raw download count. Unlike a runtime dependency shipped to end-user browsers, a compromised build-time tool executes with the credentials and network access of the build environment itself: cloud provider API keys, source code repository tokens, container registry credentials, and signing material. A stealer dropped into this environment is not fishing for whatever a random developer's laptop happens to hold; it is placed deliberately at the point where an organisation's most sensitive automation secrets are concentrated.

---

## 3. Vulnerability Details

### Root Cause

The compromise stemmed from an unauthorized publish to the npm registry. Version 8.14.0 was pushed under a legitimate, established maintainer account, but the added files — `dist/setup.js` and `dist/intro.js` — exist nowhere in the project's public GitHub source, with no corresponding commit, tag, or pull request identified by either StepSecurity or SafeDep. The most recent tag in the repository remains 8.13.0. This pattern is consistent with either a compromised maintainer npm token/account or a compromised build/release pipeline that publishes directly to the registry without the corresponding source ever being pushed to version control — investigators have not yet determined which.

### Why It Is Significant

Several factors elevate this beyond a routine malicious-package incident. First, the targeting is unusually current: alongside conventional cloud, wallet, and browser credential theft, the stealer explicitly hunts for configuration and API key material belonging to AI coding assistants (Claude Desktop, Cursor, Windsurf, VS Code, Zed) and their Model Context Protocol server credentials — a category of secret that barely existed as an attack target eighteen months ago and reflects how quickly credential-stealing malware is adapting to new developer tooling.

Second, the payload's reach on Linux extends beyond conventional userspace file theft: it links the kernel's BPF library and is capable of loading an eBPF program into the kernel from memory. Both StepSecurity and SafeDep flagged this capability; what the loaded eBPF program specifically does had not been fully reverse-engineered at the time of the referenced analyses, but the mere presence of an in-kernel loading capability in a credential-stealing payload is a materially different risk profile from a conventional userspace-only stealer, since it opens the door to deeper, harder-to-detect footholds such as syscall interception or covert data exfiltration paths.

Third, the timing is pointed. npm 12 — which disables dependency install scripts by default, precisely the mechanism this attack relied on — shipped on 8 July 2026, three days before the malicious 8.14.0 release. On npm 12, a preinstall hook of this kind does not execute without explicit user approval; on any older client, it still runs automatically. The attack therefore landed in the narrowing window before the ecosystem-wide default changes fully, illustrating both why the mitigation was introduced and how much existing infrastructure remains exposed until upgraded.

Fourth, and most operationally pressing: as of this analysis, version 8.14.0 has not been unpublished, deprecated, or otherwise removed from the npm registry, even though version 8.15.0 (clean) has since superseded it at the top of the package's version listing. Any lockfile, CI cache, or explicit version pin referencing 8.14.0 will continue to install and execute the stealer indefinitely until affected organisations take manual action.

### Affected Endpoints / Code

- `dist/setup.js` — the loader, added in 8.14.0, absent from source control
- `dist/intro.js` — a mislabelled ~7.8MB container of three gzip-compressed native binaries (Linux, Windows, macOS), also absent from source control
- Companion plugin packages (jscrambler-webpack-plugin, gulp-jscrambler, metro-plugin, grunt-jscrambler) were **not** affected and remain on their clean June 2026 releases with no install hooks

---

## 4. Full Attack Chain

```
ATTACKER (compromised npm maintainer account or build/release
pipeline for the jscrambler project — vector not yet confirmed)
│
├─[STEP 1 — MALICIOUS PUBLISH]
│   └─ jscrambler@8.14.0 pushed directly to the npm registry,
│      bypassing normal source control; no matching commit/tag/PR
│      exists in the public GitHub repository
│
├─[STEP 2 — DISTRIBUTION]
│   └─ Package available for install via `npm install jscrambler`
│      or as a resolved dependency in CI pipelines / developer
│      environments running an npm client with default preinstall
│      script execution (i.e. pre-npm-12 clients)
│
├─[STEP 3 — SILENT EXECUTION AT INSTALL TIME]
│   └─ preinstall hook fires automatically, before the package is
│      even fully set up — no import, no CLI invocation required
│
├─[STEP 4 — PAYLOAD STAGING]
│   ├─ setup.js reads intro.js, extracts the OS-matched
│   │  gzip-compressed native binary
│   ├─ Writes binary under a randomly generated filename to the
│   │  system temp directory
│   └─ Marks it executable and launches it detached, output hidden
│
├─[STEP 5 — CREDENTIAL HARVESTING]
│   ├─ Cloud credentials: AWS / Azure / GCP, incl. CI metadata
│   │  endpoints
│   ├─ Crypto wallets: MetaMask, Phantom, Exodus
│   ├─ Password manager: Bitwarden vault
│   ├─ Browser-stored passwords and cookies
│   ├─ Chat/gaming sessions: Discord, Slack, Telegram, Steam
│   └─ AI coding assistant configs/API keys: Claude Desktop,
│      Cursor, Windsurf, VS Code, Zed (incl. MCP server credentials)
│
├─[STEP 6 — PERSISTENCE]
│   ├─ Windows: hidden scheduled task, relaunches every minute
│   └─ macOS: LaunchAgent, reloads on user login
│
├─[STEP 7 — LINUX-SPECIFIC ESCALATION]
│   └─ Links kernel BPF library; capable of loading an eBPF
│      program into the kernel from memory (full behaviour of the
│      loaded program not fully characterised at time of writing)
│
└─[STEP 8 — EXFILTRATION]
    └─ Harvested data shipped over TLS to a drop server;
       runtime monitoring observed connections to two hard-coded
       C2 IP addresses and to Tor infrastructure
```

---

## 5. Campaign Intelligence

### Timeline

| Date | Event |
|---|---|
| 8 July 2026 | npm 12 ships, disabling dependency install scripts by default — the exact mechanism this attack would go on to exploit |
| 11 July 2026 | jscrambler@8.14.0 published to the npm registry with the malicious preinstall hook; Socket flags the release approximately six minutes later |
| 11 July 2026 (following) | StepSecurity and SafeDep independently pull and analyse the release, confirming no matching source-control history and identifying the payload as a cross-platform Rust infostealer; StepSecurity's runtime monitoring captures the first published network indicators |
| Shortly after | jscrambler@8.15.0 published from the same maintainer account, containing no install script and no bundled binary; 8.14.0 remains live on the registry, unpublished/undeprecated |
| 12 July 2026 | This analysis published |

### Threat Actor

Not attributed. Investigators have established that the release bypassed the project's normal source-controlled release process but have not determined whether the root cause is a compromised maintainer npm account or a compromised build/CI pipeline, nor has any individual or group been publicly linked to the activity.

### Confirmed Victims

None named. The package's weekly download count (~15,800) establishes a plausible exposure ceiling, but no organisation has been publicly confirmed as compromised, and the true number of machines that installed 8.14.0 in the window before and after detection is not known.

### IOC Table

| Type | Indicator |
|---|---|
| Malicious package | jscrambler@8.14.0 |
| File hash (SHA-256) | dist/setup.js — a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60 |
| File hash (SHA-256) | dist/intro.js — a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86 |
| File hash (SHA-256) | Linux payload — fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd |
| File hash (SHA-256) | Windows payload — b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903 |
| File hash (SHA-256) | macOS payload — c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd |
| C2 IP | 37.27.122[.]124 |
| C2 IP | 57.128.246[.]79 |
| Anonymity infrastructure | check.torproject[.]org, archive.torproject[.]org |
| On-host artefact | Randomly named hidden file in system temp directory (`.{random}` on Linux/macOS, `.{random}.exe` on Windows) |
| Persistence (Windows) | Hidden scheduled task, relaunch interval ~1 minute |
| Persistence (macOS) | LaunchAgent plist reloading on login |

---

## 6. MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|---|---|---|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Malicious code inserted directly into a published npm package outside the project's normal release process |
| T1059 | Command and Scripting Interpreter | preinstall hook executes automatically as part of the npm install lifecycle |
| T1055 | Process Injection / T1620 (Reflective Code Loading) | eBPF program loaded into the Linux kernel from memory by the dropped binary |
| T1555 | Credentials from Password Stores | Targeting of Bitwarden vault and browser-stored credentials |
| T1552.001 | Unsecured Credentials: Credentials In Files | Harvesting of cloud provider credential files and AI coding assistant / MCP configuration files |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Windows persistence via hidden scheduled task |
| T1547.011/T1543.001-class | Launch Agent (macOS) | Persistence via LaunchAgent reloading on login |
| T1071.001 | Application Layer Protocol: Web Protocols | TLS exfiltration to hard-coded C2 IP addresses |
| T1090.003 | Proxy: Multi-hop Proxy | Observed runtime connections to Tor infrastructure, likely for C2 routing/anonymity |
| T1027 | Obfuscated Files or Information | Payload packaged as a mislabelled, gzip-compressed, multi-binary container (`intro.js`) rather than plain executable files |

---

## 7. Detection Recommendations

### Immediate Package/Version Check

```bash
# Check installed version and lockfiles for the compromised release
grep -R "jscrambler" package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null | grep "8.14.0"
npm ls jscrambler 2>/dev/null

# Check npm cache for the compromised tarball
npm cache ls jscrambler 2>/dev/null | grep "8.14.0"
```

### Install-Time Forensic Review

```bash
# Look for evidence dist/setup.js was executed via npm lifecycle scripts,
# and correlate against timestamps from 11 July 2026 onward.
# No fixed payload filename exists (randomly generated), so pivot on
# install timestamps + unexpected child processes spawned from a
# node_modules/jscrambler directory instead of grepping for a filename.

find / -path "*/node_modules/jscrambler/dist/setup.js" -newer /etc/hostname 2>/dev/null
```

```powershell
# Windows: check for the hidden scheduled task created by the stealer
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } |
  Select-Object TaskName, TaskPath, State

# Review Node.exe child process creation around install timestamps
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match "node" -and $_.TimeCreated -ge (Get-Date "2026-07-11") }
```

```bash
# macOS: check for unfamiliar LaunchAgents
ls -la ~/Library/LaunchAgents/
plutil -p ~/Library/LaunchAgents/*.plist 2>/dev/null | grep -i -A3 "ProgramArguments"
```

### Network / Log Query — C2 Indicators

```
# SIEM / firewall log query for the published C2 endpoints
(dest_ip="37.27.122.124" OR dest_ip="57.128.246.79")
| stats count by src_ip, dest_ip, dest_port, process_name
| sort -count
```

### KQL — Microsoft Sentinel

```kql
// Correlate outbound connections to known C2 IPs with recent npm/node activity
let c2ips = dynamic(["37.27.122.124","57.128.246.79"]);
DeviceNetworkEvents
| where TimeGenerated > datetime(2026-07-11)
| where RemoteIP in (c2ips)
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by TimeGenerated desc

// Companion query: flag any scheduled task creation events shortly
// after a node/npm process execution, on hosts touching build pipelines
DeviceProcessEvents
| where TimeGenerated > datetime(2026-07-11)
| where FileName in~ ("schtasks.exe","node.exe","npm.cmd")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

### Sigma Rule

```yaml
title: Suspicious Native Binary Execution From Node Temp Directory (jscrambler 8.14.0 Supply Chain Compromise)
id: 7e2c4f81-3d5a-4b90-9e6f-1a8c5d3b7e42
status: experimental
description: |
  Detects execution of a randomly named hidden binary from the system
  temp directory shortly after npm/node install activity, consistent
  with the jscrambler@8.14.0 npm supply-chain compromise disclosed
  11 July 2026, in which a malicious preinstall hook dropped a
  cross-platform Rust infostealer during package installation.
references:
  - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
  - https://socket.dev/blog/jscrambler-supply-chain-attack
  - https://www.stepsecurity.io/blog/jscrambler-npm-package-publishes-malicious-preinstall-binary
  - https://safedep.io/jscrambler-npm-supply-chain-compromise/
author: Fredrick
date: 2026-07-12
tags:
  - attack.initial-access
  - attack.t1195.002
  - attack.execution
  - attack.t1059
  - attack.credential-access
  - attack.t1555
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\node.exe'
      - '\npm.cmd'
      - '\npm-cli.js'
  selection_child:
    Image|contains:
      - '\AppData\Local\Temp\'
    CommandLine|re: '\\\.[a-zA-Z0-9]{6,}(\.exe)?$'
  condition: selection_parent and selection_child
falsepositives:
  - Legitimate native-module build steps that stage temporary
    executables during npm install (uncommon, but review any hit
    manually rather than auto-suppressing)
level: high
```

---

## 8. Remediation

1. **Do not install or reference jscrambler@8.14.0.** If your lockfile, CI configuration, or Dockerfile pins this exact version, update the pin to 8.15.0 (clean) or roll back to 8.13.0 (last known-clean pre-incident release), and purge any cached copies of 8.14.0 from local and CI package caches.
2. **Audit for prior installation.** Check package-manager logs, lockfiles, and CI build history for any run referencing `jscrambler@8.14.0` from 11 July 2026 onward. Because the payload's on-disk filename is randomised, pivot on install timestamps correlated against unexpected child-process execution from Node/npm, rather than searching for a fixed artefact name.
3. **Treat any host that installed 8.14.0 as compromised, not merely exposed.** If confirmed or suspected, rotate cloud provider credentials (AWS, Azure, GCP) and CI/CD secrets immediately; rotate npm and GitHub tokens; revoke and re-issue API keys for AI coding assistants and any associated MCP server credentials; revoke active sessions for Discord, Slack, and browser-stored logins; and move funds out of any cryptocurrency wallets that were present on the host.
4. **Remove persistence mechanisms.** On Windows, locate and delete the hidden scheduled task set to relaunch the stealer; on macOS, inspect and remove any unfamiliar LaunchAgent plist under `~/Library/LaunchAgents/`.
5. **Block the published network indicators** (C2 IPs 37.27.122[.]124 and 57.128.246[.]79) at the perimeter and endpoint firewall level, and flag outbound connections to Tor infrastructure from build/CI hosts for review, since legitimate CI systems have no routine need to reach Tor.
6. **Upgrade npm clients to version 12 or later** across developer machines and CI runners, so that dependency install scripts are disabled by default and require explicit approval — the mitigation that would have prevented this specific payload from executing automatically.
7. **Consider dependency pinning with integrity verification** (lockfile hashes, `npm ci` in CI rather than `npm install`, and where feasible a private registry proxy with allow-listing) to reduce exposure to a compromised upstream publish reaching build systems automatically in future incidents of this kind.

---

## 9. The Broader Pattern

This incident sits in a lineage that has become depressingly familiar over the past year: the Shai-Hulud worm's install-hook token theft in September 2025, the phished-maintainer takeover of the widely used chalk and debug packages, and the March 2026 hijack of Axios — a library with more than 83 million weekly downloads — to push a cross-platform trojan. What distinguishes the jscrambler incident is not scale (its ~15,800 weekly downloads are modest against those precedents) but precision: a build-time tool, deliberately positioned inside CI pipelines and developer machines, compromised to harvest exactly the class of secret — cloud keys, deploy tokens, source access — that a build environment concentrates. Reach was never the objective here; access was.

The timing sharpens the point further. npm 12, which disables the exact install-script mechanism this attack relied on, shipped just three days before the malicious release landed — evidence that platform-level defences are arriving, but that the transition window between "mitigation shipped" and "ecosystem fully upgraded" remains wide enough for exactly this kind of attack to succeed. And the stealer's specific interest in AI coding assistant configuration files and MCP server credentials is a signal in its own right: as developers increasingly authorise AI tools with API keys and MCP connections that reach cloud infrastructure, source repositories, and internal systems, those credentials are becoming a first-class target category in their own right, not an afterthought bolted onto a conventional browser-and-wallet stealer. Organisations that have rushed to adopt AI coding tools without treating their credential stores with the same rigour as cloud IAM secrets should read this as an early warning of where this category of attack is heading next.

---

## 10. References

| Source | URL |
|---|---|
| The Hacker News — Compromised jscrambler 8.14.0 npm Release Drops Rust Infostealer During Install | https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html |
| Socket — jscrambler supply chain attack blog | https://socket.dev/blog/jscrambler-supply-chain-attack |
| Socket — jscrambler package version listing | https://socket.dev/npm/package/jscrambler |
| Socket — jscrambler 8.14.0 package diff | https://socket.dev/npm/package/jscrambler/diff/8.14.0 |
| StepSecurity — jscrambler npm package publishes malicious preinstall binary | https://www.stepsecurity.io/blog/jscrambler-npm-package-publishes-malicious-preinstall-binary |
| SafeDep — jscrambler npm supply chain compromise | https://safedep.io/jscrambler-npm-supply-chain-compromise/ |
| GitHub Changelog — npm install-time security and GAT/bypass-2FA deprecation (npm 12) | https://github.blog/changelog/2026-07-08-npm-install-time-security-and-gat-bypass2fa-deprecation/ |
