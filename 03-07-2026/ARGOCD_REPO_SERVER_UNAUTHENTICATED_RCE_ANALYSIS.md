# Argo CD Repo-Server "Octopus Trap" — Unauthenticated RCE Enabling Full Kubernetes Cluster Takeover

---

## Metadata

| Field | Detail |
|---|---|
| **CVE ID** | None assigned as of this analysis — Synacktiv reports the flaw was disclosed to Argo CD maintainers with no CVE issued |
| **CVSS Score / Severity** | Not formally scored by a vendor advisory; assessed as Critical given unauthenticated network RCE with a demonstrated path to full cluster compromise |
| **CWE** | CWE-306 (Missing Authentication for Critical Function) — unauthenticated internal gRPC endpoint; combined with argument-injection-style abuse (CWE-88) of Kustomize's `--helm-command` option |
| **Analysis Date** | 3 July 2026 |
| **Patch Released** | None — unpatched as of this analysis. Mitigation is network-policy isolation only |
| **Active Exploitation** | No confirmed in-the-wild exploitation reported; this is a responsible-disclosure publication by the discovering researchers, not a confirmed campaign |
| **Discovered By** | Synacktiv (published "Caught in the Octopus Trap: Unauthenticated RCE in Argo CD with CodeQL") |
| **Affected Versions** | Demonstrated against Argo CD v2.13.3; Synacktiv has not published a full affected-version range. Risk applies specifically to deployments (commonly via the official Helm chart) where Kubernetes network policies are not enabled |
| **Fixed Version** | None available. Vulnerability reported to Argo CD maintainers in January 2025; remained unpatched some eighteen months later at time of public disclosure (1 July 2026) |
| **Disclosure Timeline** | Reported to maintainers January 2025; publicly disclosed by Synacktiv 1 July 2026 after no fix materialised |

---

## 1. Executive Summary

On 1 July 2026, French security firm Synacktiv publicly disclosed an unauthenticated remote code execution chain in Argo CD's repo-server component, the part of the widely used Kubernetes GitOps tool that reads Git repositories and renders them into deployable manifests. The flaw allows anyone able to reach the repo-server's internal gRPC service — which has no authentication — to send a crafted `GenerateManifest` request that abuses Kustomize's `--helm-command` option, substituting a script from an attacker-controlled Git repository in place of the expected `helm` binary. When Kustomize runs, it executes that script instead, achieving code execution on the repo-server host.

Synacktiv escalated the finding from there: using the resulting code execution, researchers read the `REDIS_PASSWORD` environment variable from the repo-server process, connected to Argo CD's Redis cache, and poisoned the stored deployment manifest data. On the next automatic sync — a default, commonly enabled Argo CD behaviour — Argo CD deployed the attacker-supplied workload into the target Kubernetes cluster, completing a path from an unauthenticated network request to arbitrary workload deployment across everything the Argo CD instance manages.

Critically, there is no patch. Synacktiv reported the issue to Argo CD's maintainers in January 2025 and, after roughly eighteen months without a fix, published full technical detail to allow defenders to assess and mitigate their own exposure. The only available defence is network isolation: Argo CD ships Kubernetes network policies that restrict access to the repo-server and Redis ports, but Synacktiv found that the official Argo CD Helm chart leaves `networkPolicy.create` set to `false` by default — meaning a large proportion of real-world installs likely have the vulnerable ports reachable from anywhere inside the cluster. In that configuration, an attacker who compromises a single unrelated pod anywhere in the cluster gains a direct path to full GitOps-controlled infrastructure takeover.

| Verdict | Key Facts |
|---|---|
| **Severity** | Critical (assessed) — unauthenticated RCE with a demonstrated path to full Kubernetes cluster compromise |
| **Exploitation status** | No confirmed in-the-wild exploitation; public disclosure is by the discovering researchers |
| **Patch status** | None — unpatched after ~18 months from responsible disclosure to publication |
| **Root exposure factor** | Official Argo CD Helm chart ships with network policies disabled by default |
| **Blast radius** | Compromise of repo-server enables Redis cache poisoning, which Argo CD's Auto Sync then deploys automatically to the managed cluster |
| **Historical pattern** | Third Argo CD advisory in roughly a year involving repo-server/Redis credential or secret exposure (following CVE-2025-55190 and CVE-2026-42880) |

---

## 2. Product Background

Argo CD is one of the most widely deployed open-source GitOps continuous-delivery tools for Kubernetes, used by organisations to declaratively manage what runs in their clusters by syncing state from Git repositories. Its repo-server component is the piece that fetches repository content and, using tools such as Helm and Kustomize, renders that content into the Kubernetes manifests that are ultimately applied to the cluster.

By design, Argo CD occupies a uniquely privileged position in the deployment pipeline: it typically holds read access to private source repositories, sync and write access to target clusters, and custody of deployment-related secrets such as the Redis credentials used for its internal cache. As one researcher quoted by CSO Online put it, GitOps engines are "tier-0 control-plane components," sitting at the intersection of source code, configuration management and live infrastructure — meaning a compromise of Argo CD itself is frequently equivalent to a compromise of everything it manages.

Argo CD has been the subject of repeated security findings in this category over the past year: in September 2025, CVE-2025-55190 allowed an API token with only basic read access to retrieve a project's Git repository credentials; in May 2026, CVE-2026-42880 allowed read-only users to read plaintext Kubernetes secrets. This latest finding continues that pattern — internal Argo CD surfaces repeatedly proving willing to hand over credentials and secrets, whether to a low-privilege token or, in this case, to an entirely unauthenticated request.

---

## 3. Vulnerability Details

### Root Cause

The repo-server's `GenerateManifest` gRPC service accepts Kustomize build options without authenticating the caller. Kustomize supports a `--helm-command` option intended to let operators point to a custom `helm` binary path; Synacktiv found that an unauthenticated request to `GenerateManifest` can set this option to point to an attacker-supplied script instead, sourced from a Git repository the attacker controls. When the repo-server subsequently invokes Kustomize to render manifests from that repository, Kustomize executes the attacker's script under the assumption it is calling `helm` — achieving arbitrary code execution in the repo-server's process context.

Synacktiv used CodeQL, a static analysis engine, to map the repo-server codebase and identify this unauthenticated path from network input to command execution — a methodology the firm documented alongside the vulnerability itself.

### Why It Is Architecturally Significant

The vulnerability's severity is compounded by a configuration gap rather than the code flaw alone. Argo CD does ship Kubernetes network policies designed to isolate the repo-server and Redis ports from the rest of the cluster, limiting exploitation to callers who are already inside the Argo CD component network. However, the official Argo CD Helm chart — a very common installation method — ships with `networkPolicy.create: false`, meaning operators must explicitly opt in to the isolation Argo CD itself considers necessary. In deployments where this default goes unchanged, "internal" is not equivalent to "isolated": any single compromised pod elsewhere in the cluster gains a direct path to the repo-server's unauthenticated gRPC surface.

The post-exploitation chain is equally significant architecturally. Code execution on the repo-server alone would be serious, but Synacktiv's demonstration that the resulting access allows extraction of the Redis password, followed by direct manipulation of the Redis-cached manifest data, means the attacker does not need to hold code execution persistently — poisoning the cache once is sufficient, because Argo CD's own Auto Sync feature then does the work of propagating the attacker-controlled manifest into the live cluster on the next scheduled synchronisation. This converts a repo-server compromise into a fully automated, self-propagating cluster takeover, without further attacker interaction.

This also directly revives the underlying weakness behind CVE-2024-31989, a 2024 Cycode finding in which Argo CD's Redis instance had no password at all, allowing any pod in the cluster to poison the deployment cache directly. Argo CD's fix for that issue was to add a Redis password — but because the cache itself is not cryptographically signed or otherwise authenticated, recovering that password through a separate vulnerability (as this new chain does) reopens the identical cache-poisoning attack.

### Affected Endpoints / Code

The vulnerable surface is the repo-server's `GenerateManifest` gRPC service, specifically its handling of Kustomize build options (`--helm-command` / related Kustomize configuration passed through from client requests). Synacktiv demonstrated the full chain against Argo CD v2.13.3; no complete list of affected versions or patched release has been published, and Synacktiv is deliberately withholding its automation tool, "argo-cdown," to give defenders time to apply network-level mitigations before a ready-made exploitation tool becomes available.

---

## 4. Full Attack Chain

The following reflects Synacktiv's published, tested attack chain (not an assessed or hypothetical path) — see Section 10 for the source.

```
ATTACKER (network access to repo-server gRPC port; e.g. via a
compromised pod elsewhere in the cluster, where network policies
are not enforced)
│
├─[PRECONDITION]
│   └─ Argo CD deployed (commonly via Helm chart) with
│      networkPolicy.create left at its default of "false",
│      leaving repo-server and Redis ports reachable cluster-wide
│
├─[EXPLOITATION — Unauthenticated RCE]
│   ├─ Attacker sends unauthenticated request to repo-server's
│   │  GenerateManifest gRPC endpoint
│   ├─ Request sets Kustomize's --helm-command option to reference
│   │  a script hosted in an attacker-controlled Git repository,
│   │  instead of the legitimate helm binary
│   └─ Repo-server invokes Kustomize, which executes the attacker's
│      script in place of helm → code execution on repo-server host
│
├─[CREDENTIAL THEFT]
│   └─ Attacker uses code execution to read the REDIS_PASSWORD
│      environment variable from the repo-server process
│
├─[CACHE POISONING]
│   ├─ Attacker connects to Argo CD's Redis instance using the
│   │  stolen password
│   └─ Attacker overwrites cached deployment manifest data with an
│      attacker-controlled manifest
│
├─[AUTOMATED PROPAGATION]
│   └─ Argo CD's Auto Sync feature (if enabled — a common default)
│      deploys the poisoned manifest to the target Kubernetes
│      cluster on its next scheduled sync, with no further
│      attacker action required
│
└─[IMPACT]
    └─ Attacker-controlled workload runs with the privileges Argo CD
       is configured to deploy with — commonly broad, cluster-wide
       deployment permissions — resulting in full cluster compromise
```

---

## 5. Campaign Intelligence

### Timeline

| Date | Event |
|---|---|
| January 2025 | Synacktiv reports the vulnerability chain to Argo CD maintainers |
| 1 July 2026 | Synacktiv publicly discloses full technical detail ("Caught in the Octopus Trap") after roughly eighteen months without a fix; The Hacker News, CSO Online/InfoWorld and other outlets report on the disclosure |
| 3 July 2026 | This analysis published; no CVE, patch, or confirmed exploitation reported to date |

### Threat Actor

No threat actor has been publicly linked to exploitation of this vulnerability chain. This is a researcher-driven public disclosure, not a reported campaign.

### Confirmed Victims

None reported. No exploitation in the wild has been confirmed by Synacktiv or any other source as of this analysis.

### IOC Table

No indicators of compromise have been published, as no active exploitation has been confirmed. Synacktiv has withheld its exploitation tool ("argo-cdown") specifically to avoid providing attackers a ready-made capability before defenders can mitigate.

---

## 6. MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Unauthenticated exploitation of the repo-server's internal-but-often-reachable gRPC service |
| T1610 | Deploy Container | End state of the attack is deployment of an attacker-controlled workload into the cluster via Argo CD itself |
| T1552.001 | Unsecured Credentials: Credentials In Files/Environment | Theft of the Redis password from the repo-server process environment |
| T1565.001 | Data Manipulation: Stored Data Manipulation | Poisoning of Argo CD's Redis-cached deployment manifest data |
| T1078.004 | Valid Accounts: Cloud Accounts | Abuse of Argo CD's own privileged cluster-deployment permissions to complete the takeover |

---

## 7. Detection Recommendations

### Configuration / Exposure Check

```bash
# Check whether Kubernetes network policies are actively restricting
# access to the Argo CD repo-server and Redis components
kubectl get networkpolicy -A | grep -i argocd

# A healthy install shows one network policy per Argo CD component,
# including argocd-repo-server and argocd-redis-network-policy.
# Absence of these indicates the repo-server and Redis ports are
# reachable from any pod in the cluster's network namespace.
```

```bash
# Confirm whether the repo-server gRPC port is reachable from a
# test pod outside the argocd namespace (run only in a controlled
# test environment, not production)
kubectl run netcheck --rm -it --image=busybox -- \
  nc -zv argocd-repo-server.argocd.svc.cluster.local 8081
```

### Log Query — Anomalous GenerateManifest Calls

```
# Hunt Argo CD repo-server logs for GenerateManifest requests
# containing unusual Kustomize options, particularly helm-command
# overrides referencing unfamiliar Git sources
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-repo-server | \
  grep -i "helm-command\|GenerateManifest" | grep -v "<expected-helm-path>"
```

### KQL — Microsoft Sentinel / Container Insights (Anomalous Repo-Server Child Processes)

```kql
// Repo-server pod spawning unexpected child processes or reaching
// out to network destinations outside expected Git/Helm registries
ContainerLogV2
| where PodNamespace == "argocd"
| where ContainerName has "repo-server"
| where LogMessage has_any ("exec", "helm-command", "kustomize build")
| project TimeGenerated, PodName, ContainerName, LogMessage
| sort by TimeGenerated desc
```

### Suricata Rule

```yaml
alert tcp $HOME_NET any -> $HOME_NET 8081 (
  msg:"ET EXPLOIT Possible Argo CD Repo-Server Unauthenticated GenerateManifest Abuse";
  flow:established,to_server;
  content:"GenerateManifest"; nocase;
  content:"helm-command"; nocase; distance:0;
  classtype:attempted-admin;
  reference:url,synacktiv.com/en/publications/caught-in-the-octopus-trap-unauthenticated-rce-in-argo-cd-with-codeql;
  sid:9026000001;
  rev:1;
)
```

*Note: this rule targets internal cluster traffic (repo-server's default gRPC port 8081) and assumes east-west visibility via a service mesh or CNI-level IDS; standard perimeter Suricata deployments will not see this traffic without in-cluster sensor placement.*

### Sigma Rule

```yaml
title: Argo CD Repo-Server Unauthenticated GenerateManifest Exploitation Attempt
id: 9b3e7a15-2c48-4d90-8f61-1a5d3e7c9b02
status: experimental
description: |
  Detects log evidence consistent with exploitation of the unauthenticated
  Argo CD repo-server GenerateManifest RCE chain disclosed by Synacktiv
  ("Caught in the Octopus Trap"), in which a crafted Kustomize
  --helm-command option is used to achieve code execution.
references:
  - https://www.synacktiv.com/en/publications/caught-in-the-octopus-trap-unauthenticated-rce-in-argo-cd-with-codeql
  - https://thehackernews.com/2026/07/unpatched-argo-cd-repo-server-flaw.html
  - https://www.csoonline.com/article/4192188/argo-cd-flaw-shows-why-gitops-infrastructure-should-be-treated-as-tier-zero.html
author: Fredrick
date: 2026-07-03
tags:
  - attack.initial_access
  - attack.t1190
  - attack.credential_access
  - attack.t1552_001
logsource:
  category: application
  product: kubernetes
  service: argocd-repo-server
detection:
  selection:
    LogMessage|contains:
      - 'helm-command'
      - 'GenerateManifest'
  filter:
    LogMessage|contains: '<known-good-helm-path>'
  condition: selection and not filter
falsepositives:
  - Legitimate custom Helm binary configurations — verify against
    known-good repo-server configuration before escalating
level: high
```

---

## 8. Remediation

1. **Enable Kubernetes network policies immediately.** This is the primary and, currently, only available mitigation. Argo CD ships the required policy manifests; Helm chart users must explicitly set `networkPolicy.create: true` (and `networkPolicy.defaultDenyIngress: true` for maximum isolation), as the chart leaves this disabled by default.
2. **Verify current exposure** using `kubectl get networkpolicy -A` (see Section 7) — confirm a policy exists restricting ingress to `argocd-repo-server` and the Argo CD Redis service to only the components that legitimately need access.
3. **Treat any pod capable of reaching the repo-server or Redis ports as a potential attack path**, not just external attackers — the primary exploitation precondition in Synacktiv's research is lateral reachability from any compromised pod in the cluster, not internet exposure.
4. **Rotate the Redis password** used by Argo CD as a precaution, and consider whether Redis AUTH alone is sufficient given that the underlying cache remains unsigned — additional network-layer controls around the Redis service are advisable regardless of password rotation.
5. **Disable or tightly scope Auto Sync** where feasible, or add manual approval gates for sync operations on production clusters, to reduce the chance that a poisoned cache is automatically propagated without human review.
6. **Monitor for the release of Synacktiv's "argo-cdown" tool** and any subsequent public proof-of-concept, and treat its publication as a signal to re-verify network policy enforcement across all Argo CD deployments.
7. **Track official Argo CD guidance and any forthcoming patch or CVE assignment**; given the eighteen-month gap between initial report and public disclosure, organisations should not assume a fix is imminent and should prioritise the network-isolation mitigation as the durable control.

---

## 9. The Broader Pattern

This is the third significant Argo CD security finding in roughly a year to centre on the same underlying weakness: the repo-server and its adjacent Redis cache hold or expose more trust than the surrounding access controls assume. CVE-2025-55190 let a low-privilege read-only token retrieve repository credentials; CVE-2026-42880 let a read-only user pull plaintext Kubernetes secrets; this latest chain lets an entirely unauthenticated caller reach code execution and, from there, the Redis password and cache-poisoning path that Argo CD's 2024 Redis-password fix was specifically meant to close off. A password requirement without an integrity check on the cache itself only raises the bar for exploitation — it does not remove the underlying architectural assumption that anything able to reach the cache can be trusted to write to it correctly.

The more consequential issue is what this reveals about how GitOps tooling gets deployed in practice. Argo CD's own documentation and shipped manifests reflect an awareness that the repo-server and Redis need network isolation — yet the most common installation path, the official Helm chart, does not enforce that isolation by default. This is a familiar pattern in infrastructure tooling generally: security-relevant defaults that require an operator to opt in rather than opt out tend to go unconfigured in a meaningful share of real-world deployments, particularly for components perceived as "internal." Argo CD's repo-server is a clear illustration of why that perception is dangerous for a tier-0, GitOps control-plane component: internal reachability inside a Kubernetes cluster is a considerably weaker boundary than it sounds, given how routinely a single compromised pod — from an unrelated application vulnerability, a supply-chain compromise, or a misconfigured workload — can occur.

Organisations running Argo CD, or any GitOps engine with comparable privileges, should treat "no authentication required, but only reachable internally" as a materially weaker security property than genuine authentication, and should audit their network policy posture as a first-class control rather than an optional hardening step.

---

## 10. References

| Source | URL |
|---|---|
| Synacktiv — Caught in the Octopus Trap: Unauthenticated RCE in Argo CD with CodeQL | https://www.synacktiv.com/en/publications/caught-in-the-octopus-trap-unauthenticated-rce-in-argo-cd-with-codeql |
| The Hacker News — Unpatched Argo CD Repo-Server Flaw Could Let Attackers Take Over Kubernetes Clusters | https://thehackernews.com/2026/07/unpatched-argo-cd-repo-server-flaw.html |
| CSO Online — Argo CD flaw shows why GitOps infrastructure should be treated as tier zero | https://www.csoonline.com/article/4192188/argo-cd-flaw-shows-why-gitops-infrastructure-should-be-treated-as-tier-zero.html |
| Argo CD — Security Considerations documentation | https://argo-cd.readthedocs.io/en/stable/security_considerations/ |
| Argo CD Helm Chart — network policy default configuration (values.yaml) | https://github.com/argoproj/argo-helm/blob/2685b861d2b2af4f5797522ec3cef8140c3d6049/charts/argo-cd/values.yaml |
| GitHub Security Advisory — CVE-2025-55190 (Argo CD repository credential exposure) | https://github.com/argoproj/argo-cd/security/advisories/GHSA-786q-9hcg-v9ff |
| GitHub Security Advisory — CVE-2026-42880 (Argo CD plaintext secret read) | https://github.com/argoproj/argo-cd/security/advisories/GHSA-3v3m-wc6v-x4x3 |
