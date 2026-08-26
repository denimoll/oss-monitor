from pydantic import BaseModel, HttpUrl
from enum import Enum
from typing import Any


class ComponentType(str, Enum):
    library = "library"
    product = "product"


class Ecosystem(str, Enum):
    npm = "npm"
    pypi = "pypi"
    maven = "maven"
    nuget = "nuget"
    go = "go"
    crates = "crates.io"


class EvidenceTypeEnum(str, Enum):
    analyst_report = "analyst_report"
    incident_link = "incident_link"
    virustotal = "virustotal"
    cve_discussion = "cve_discussion"
    audit_report = "audit_report"
    other = "other"


class ComponentRequest(BaseModel):
    type: ComponentType
    name: str
    version: str
    ecosystem: Ecosystem | None = None
    identifier_override: str | None = None
    notes: str | None = None
    tags: str | None = None       # comma-separated tags, e.g. "prod,db-server"
    owner: str | None = None      # team/person accountable, matched by notification routes
    repo_url: str | None = None   # GitHub/GitLab repo URL
    distrib_url: str | None = None


class ComponentUpdateRequest(BaseModel):
    notes: str | None = None
    tags: str | None = None
    owner: str | None = None
    repo_url: str | None = None
    distrib_url: str | None = None


class EvidenceRequest(BaseModel):
    type: EvidenceTypeEnum = EvidenceTypeEnum.other
    title: str
    url: str | None = None
    notes: str | None = None


class SettingsUpdate(BaseModel):
    """Flat settings object — all fields optional."""
    webhook_url: str | None = None
    notify_on_critical: bool = True
    notify_on_high: bool = False
    scorecard_min_score: float = 5.0
    stale_days_threshold: int = 730
    notify_on_scorecard_fail: bool = True
    notify_on_stale: bool = True

    # CVE-PaaS integration. The API key is env-only (CVEPAAS_API_KEY) and is
    # deliberately not stored in the settings table.
    cvepaas_enabled: bool = False
    cvepaas_url: str | None = None
    notify_on_kev: bool = True
    notify_on_priority_critical: bool = False
    epss_alert_threshold: float = 0.0

    # Per-owner / per-tag webhook routing; see services/routing.py.
    notification_routes: list[dict] | None = None
