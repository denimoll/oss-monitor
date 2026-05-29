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
- 📝 Notes per component
- 📋 Dashboard with severity breakdown and top vulnerable components

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

82 tests covering vulnerability analysis, API endpoints, Scorecard, Quality Gate, Evidence, Settings, bulk import, and CVSS scoring.

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
**Optional:** `tags`, `notes`, `repo_url`, `distrib_url`, `identifier_override`.  
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
