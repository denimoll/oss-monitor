# oss-monitor

Platform for monitoring third-party software components (OS packages, runtimes, infrastructure software) for known vulnerabilities and development health.

**oss-monitor** is designed for tracking environment-level software — components that are not part of your product's source code directly, but are still subject to security control: web servers, databases, container runtimes, OS packages, and similar.

## ✨ Features

### Vulnerability Monitoring
- 🔍 Add components by name, version, type (library or product), and ecosystem
- 🔗 Auto-generate identifiers: **PURL** for libraries, **CPE** for products
- 📡 Query public vulnerability databases: [OSV.dev](https://osv.dev) and [NVD](https://nvd.nist.gov)
- 💾 Store components and vulnerabilities in a local SQLite database
- ✅ Mark vulnerabilities as false positives with reasoning
- 🔄 Daily automated refresh at 03:00 UTC

### Organisation
- 🏷️ Tag components (e.g. `prod`, `staging`, `db-server`) and filter by tag
- 👤 Assign an **owner** per component and filter by it
- 📬 **Notification routing** — send each component's alerts to the channel of whoever owns it
- 📝 Notes per component
- 📋 Dashboard with severity breakdown and top vulnerable components

### Remediation
- ⬆️ **Fix versions** — every finding carries the version that clears it, resolved per release branch
- 🎯 One upgrade recommendation per component: *"upgrade to 2.25.4 — clears 7 of 7"*, with smaller intermediate steps

### Prioritization
- 🎯 **CVE-PaaS integration** — enrich every CVE with an exploitation-aware priority: EPSS, CISA/VulnCheck KEV, public PoCs and Nuclei templates
- 🚨 Alerts on KEV listings regardless of CVSS severity — a *medium* CVE under active exploitation outranks an unexploited *critical* one
- ⬆️ Escalation alerts when a CVE you already track gains a PoC or enters KEV

### Security Analysis
- 📊 **OpenSSF Scorecard** — auto-fetch development health score (0–10) when a GitHub repo URL is provided
- 📁 **Evidence & Links** — attach analyst reports, incident links, VirusTotal reports, CVE discussions, and audit reports to any component

### Notifications & Quality Gate
- 🔔 **Webhook notifications** — Slack, Telegram, or any HTTP endpoint
- 🚨 Immediate alerts for new **critical/high CVEs** discovered during refresh
- 📋 Daily digest for Scorecard score failures and stale/abandoned components

## 🚀 Getting Started

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

### Run
```bash
docker-compose up --build
```

| Service | URL |
|---|---|
| Web UI (Streamlit) | http://localhost:8501 |
| REST API + Swagger | http://localhost:8000/docs |

## ⚙️ Configuration

Settings are managed via the **Settings** page in the UI or via the API (`PUT /settings`).

| Setting | Default | Description |
|---|---|---|
| `webhook_url` | `null` | Webhook endpoint (Slack, Telegram, custom HTTP) |
| `notify_on_critical` | `true` | Send immediate alert for new critical CVEs |
| `notify_on_high` | `false` | Send immediate alert for new high CVEs |
| `scorecard_min_score` | `5.0` | Minimum acceptable OpenSSF Scorecard score |
| `stale_days_threshold` | `730` | Days without commits before a component is flagged |
| `notify_on_scorecard_fail` | `true` | Include Scorecard failures in daily digest |
| `notify_on_stale` | `true` | Include stale components in daily digest |
| `cvepaas_enabled` | `false` | Enable CVE-PaaS prioritization |
| `cvepaas_url` | `null` | CVE-PaaS base URL (falls back to `CVEPAAS_URL` env var) |
| `notify_on_kev` | `true` | Immediate alert when a CVE is listed in CISA/VulnCheck KEV |
| `notify_on_priority_critical` | `false` | Immediate alert on CVE-PaaS priority `Critical` |
| `epss_alert_threshold` | `0.0` | Alert when EPSS reaches this value (`0` = off) |
| `notification_routes` | `null` | Per-owner / per-tag webhook routing (see below) |

### Webhook payload format

Immediate CVE alert:
```json
{
  "event": "new_vulnerability",
  "text": "🔴 New CRITICAL vulnerability detected",
  "component": "nginx 1.23.0 [prod,web]",
  "cve_id": "CVE-2024-XXXXX",
  "severity": "critical"
}
```

Daily digest:
```json
{
  "event": "daily_digest",
  "text": "📋 Daily QG digest — 2 issue(s) found",
  "issues": [
    { "component": "nginx 1.23.0", "reason": "Scorecard score 3.5/10 below threshold 5.0", "type": "scorecard_fail" },
    { "component": "redis 6.0.0",  "reason": "No commits for 800 days (threshold: 730)", "type": "stale" }
  ]
}
```

## ⬆️ Fix versions & upgrade advice

"You have 7 CVEs" is a fact. "Upgrade to 2.25.4 and 7 of them go away" is a task. Every finding
carries `fixed_version` when the advisory publishes one, and each component gets a single
recommendation built from them.

Resolving the fix version is not simply "the lowest fix in the advisory". Log4Shell's follow-up
lists log4j-core under **both** `[2.13.0, 2.16.0)` and `[0, 2.12.2)`; a 2.14.1 install must be told
**2.16.0**, because 2.12.2 is a backport of a branch it is not on — recommending it would be a
downgrade that fixes nothing. The resolver picks the fix belonging to the range the installed
version actually falls in.

```
⬆️ Upgrade to 2.25.4 — clears 7 of 7 finding(s)

Smaller upgrade steps
  2.15.0 → clears 1 of 7      2.17.1 → clears 4 of 7
  2.16.0 → clears 2 of 7      2.25.3 → clears 5 of 7
  2.17.0 → clears 3 of 7
```

The steps matter when the full jump is blocked by a breaking change — you can still see what a
smaller bump buys. Findings marked as false positives are excluded, so a suppressed CVE never drags
the recommended version up.

| Source | Fix data |
|---|---|
| **OSV** (libraries) | `affected[].ranges[].events[].fixed`, resolved per branch |
| **NVD** (products) | `versionEndExcluding` only |

NVD often has none: `versionEndIncluding` means the named version is *still* vulnerable and the fix
is some later, unnamed release, and an exact CPE match carries no range at all. Both yield no fix
version rather than a guess, which is why libraries have far better coverage than products.

## 👤 Ownership & notification routing

One webhook for the whole inventory means every team gets every alert, which is how alert channels
become noise nobody reads. Set an **owner** on a component and route its alerts accordingly:

```json
[
  {"match": {"owner": "platform"},          "webhook_url": "https://hooks.slack.com/services/AAA"},
  {"match": {"tag": "prod"},                "webhook_url": "https://hooks.slack.com/services/ONCALL"},
  {"match": {"owner": "data", "tag": "db"}, "webhook_url": "https://hooks.slack.com/services/DATA"}
]
```

- Match on `owner`, on `tag`, or on both — when both are present, both must hold.
- **Every** matching route receives the alert, so a `prod` component owned by `platform` reaches
  the first two channels above.
- A component matching **no** route falls back to the global `webhook_url`, so adding routes never
  silently drops alerts for anyone.
- The daily digest is split per channel: each team gets a digest of its own components.

Configure it on the **Settings** page or via `PUT /settings` with a `notification_routes` array.
Alert payloads carry `owner` and `fixed_version` alongside the existing fields.

## 🌐 Vulnerability sources & rate limits

**NVD** allows 5 requests / 30 s anonymously and 50 / 30 s with a key. A nightly refresh over a few
dozen products exceeds the anonymous budget, and NVD answers with `403`/`429` rather than an error a
caller would notice — the component simply comes back with no vulnerabilities, which looks exactly
like a clean result.

Requests are paced process-wide and retried with exponential backoff and jitter (honouring
`Retry-After`) either way. Set a [free API key](https://nvd.nist.gov/developers/request-an-api-key)
to make it ten times faster:

```bash
NVD_API_KEY=your-key docker compose up
```

| Variable | Default | Description |
|---|---|---|
| `NVD_API_KEY` | _(not set)_ | Raises the NVD budget from 5 to 50 requests / 30 s |
| `NVD_MIN_INTERVAL` | `6.5` (`0.7` with a key) | Seconds between NVD requests; raise it if still throttled |

## 🗄️ Database migrations

Schema changes are [Alembic](https://alembic.sqlalchemy.org) migrations under
`backend/migrations/versions`, applied automatically on startup — no manual step on upgrade.

Databases created before Alembic are adopted automatically: a one-time idempotent bridge brings them
to the baseline shape, stamps them, and from then on they follow the normal path. Existing data is
preserved.

To add a migration after changing `db/models.py`:

```bash
cd backend
alembic revision --autogenerate -m "describe the change"
# review the generated file, then it applies on next startup
```

SQLite cannot `ALTER` most things in place, so migrations run in batch mode (Alembic rebuilds the
table), which is what makes column drops and type changes possible at all.

## 🎯 CVE-PaaS Prioritization

CVSS ranks *theoretical* impact. [CVE-PaaS](https://github.com/denimoll/CVE-PaaS) ranks what is
**actually being exploited** — it combines CVSS with EPSS, the CISA and VulnCheck KEV catalogues,
public PoCs and Nuclei templates into a single `Priority` verdict.

With the integration on, every CVE in the inventory carries that verdict, the dashboard breaks the
inventory down by priority instead of severity alone, and the Quality Gate can alert on
exploitation signals that CVSS severity rules would miss entirely.

> **Requires CVE-PaaS 1.4.0 or newer.** Before that a KEV listing never reached the verdict, so a
> CVE under active exploitation but without a public PoC came back under-prioritised — and
> `notify_on_kev`, the default-on rule here, would never fire for it. Older releases still work;
> they just report less.

### Running CVE-PaaS alongside oss-monitor

CVE-PaaS needs an API key from [ProjectDiscovery](https://cloud.projectdiscovery.io/).
It ships as an opt-in compose profile:

```bash
PDCP_API_KEY=<your_pdcp_key> docker compose --profile cvepaas up --build
```

Then open **Settings → CVE-PaaS Prioritization**, enable the integration, and set the base URL to
`http://cve-paas:8000`. **Test connection** probes `/healthz`, **Backfill priorities** looks up every
stored CVE that has no verdict yet.

Running CVE-PaaS elsewhere works the same — point `cvepaas_url` at it. If that instance is protected
with `CVE_PAAS_API_KEY`, set the matching key on the oss-monitor backend:

```bash
CVEPAAS_API_KEY=<the_same_secret> docker compose up
```

The key is read from the environment only and is **never written to the settings database**. The base
URL likewise comes from stored settings or the environment, never from a request body — the same rule
that keeps the webhook endpoints free of SSRF.

### What gets stored

| Field | Meaning |
|---|---|
| `priority` | `Critical` / `High` / `Medium` / `Low` / `Info` / `Undefined` |
| `epss_score` | Exploit-prediction score, `0.0`–`1.0` |
| `is_kev` | Listed in CISA **or** VulnCheck KEV |
| `is_poc` | A public proof-of-concept exists |
| `is_template` | A Nuclei template exists |
| `cvepaas_links` | Direct links to the PoC, the Nuclei search and the KEV entry |

Only real `CVE-YYYY-NNNNN` identifiers are sent. OSV keys library advisories by `GHSA-`/`PYSEC-`/`GO-`
ID and carries the CVE in `aliases`, so those aliases are stored and used for the lookup — otherwise
no library component could ever be prioritized. An advisory with no CVE alias is simply skipped.

### Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /components/{id}/enrich` | Prioritize one component's CVEs (`?force=true` re-fetches all) |
| `POST /vulnerabilities/enrich` | Backfill priorities across the whole inventory |
| `POST /settings/test-cvepaas` | Probe the configured instance |

The daily 03:00 UTC refresh re-checks every CVE with `force=true`, so a PoC published overnight for a
CVE you have been carrying for months shows up as an **escalation alert**:

```json
{
  "event": "priority_escalation",
  "text": "⬆️ *Exploitation status escalated* — CVE-2024-1337 added to KEV",
  "component": "nginx 1.24.0 [prod,web]",
  "cve_id": "CVE-2024-1337",
  "previous_priority": "Medium",
  "priority": "Critical",
  "epss_score": 0.87,
  "is_kev": true
}
```

> **Cost note:** enrichment is bounded by vulnx, roughly `1.4 s + 0.7 s per CVE` per batch of 50.
> The CVE-PaaS cache absorbs most of it — set a generous `CACHE_TTL_HOURS` (the compose profile
> defaults to 168) and the second run over a stable inventory is close to free.

### OpenSSF Scorecard

Set `repo_url` when adding a component (or via Edit) to enable automatic Scorecard checks:
```
https://github.com/nginx/nginx
```
Score and per-check details are fetched automatically on add and refreshed daily.
Manual refresh: `POST /components/{id}/scorecard`.

### Evidence & Links

Attach supporting material to any component via **Add Evidence** in the UI or `POST /components/{id}/evidence`:

| Type | Use case |
|---|---|
| `analyst_report` | Internal or third-party security analysis |
| `incident_link` | Link to a public incident or GitHub issue |
| `virustotal` | VirusTotal report URL |
| `cve_discussion` | Blog post or HackerNews thread about a CVE |
| `audit_report` | Penetration test or compliance audit result |
| `other` | Anything else |

## 🧪 Tests

```bash
cd backend
pip install -r requirements-test.txt
pytest
```

212 tests covering vulnerability analysis, API endpoints, Scorecard, Quality Gate, Evidence, Settings, bulk import, CVSS scoring, CVE-PaaS prioritization, version comparison and fix resolution, notification routing, NVD rate-limit handling, and schema migrations.

## 📥 Bulk Import

Import multiple components at once from a JSON file via the **Import** page in the UI or `POST /components/import`.

An example file is available at [`examples/import.json`](examples/import.json).

```json
[
  {
    "type": "product",
    "name": "nginx",
    "version": "1.24.0",
    "tags": "prod,web",
    "repo_url": "https://github.com/nginx/nginx"
  },
  {
    "type": "library",
    "name": "lodash",
    "version": "4.17.21",
    "ecosystem": "npm",
    "tags": "frontend"
  }
]
```

**Required fields:** `type`, `name`, `version` (+ `ecosystem` for libraries).  
**Optional:** `tags`, `owner`, `notes`, `repo_url`, `distrib_url`, `identifier_override`.  
**Limit:** 200 components per request. Duplicates are skipped automatically.

## 🔐 API Authentication

Disabled by default. To enable, set the `OSS_MONITOR_API_KEY` environment variable:

```bash
OSS_MONITOR_API_KEY=your-secret-key docker-compose up
```

Then pass the key via the `X-API-Key` header:

```bash
curl -H "X-API-Key: your-secret-key" http://localhost:8000/components
```

## 🗺️ Roadmap

- GitHub release download + SHA-256 checksum verification
- SBOM (CycloneDX/SPDX) import and SCA analysis
- Background job queue for refreshes (long `refresh_all` runs currently hold the HTTP connection)
- Rate limiting on the unauthenticated `/analyze` and `/generate_identifier` endpoints
