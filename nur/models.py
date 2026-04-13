"""
Core data models for Bakeoff contributions.

Three types of contributions supported:
  - EvalRecord:   a practitioner's evaluation of a security tool
  - AttackMap:    an observed or simulated kill chain (MITRE ATT&CK aligned)
  - IOCBundle:    indicators of compromise linked to specific tools/vendors

All models are designed for anonymization — no PII fields, only buckets.
"""
from __future__ import annotations

from enum import Enum
from pydantic import BaseModel, Field


# ── Shared enums ──────────────────────────────────────────────────────────────

class Industry(str, Enum):
    financial      = "financial"
    healthcare     = "healthcare"
    tech           = "tech"
    government     = "government"
    retail         = "retail"
    energy         = "energy"
    manufacturing  = "manufacturing"
    education      = "education"
    other          = "other"


class OrgSize(str, Enum):
    xs   = "1-100"
    s    = "100-500"
    m    = "500-1000"
    l    = "1000-5000"
    xl   = "5000-10000"
    xxl  = "10000+"


class Role(str, Enum):
    ciso              = "ciso"
    security_director = "security-director"
    security_engineer = "security-engineer"
    security_analyst  = "security-analyst"
    it_manager        = "it-manager"
    compliance        = "compliance"
    other             = "other"


class ContribType(str, Enum):
    eval           = "eval"
    attack_map     = "attack_map"
    ioc_bundle     = "ioc_bundle"
    dashboard_scan = "dashboard_scan"


# ── Context (attached to every contribution) ──────────────────────────────────

class ContribContext(BaseModel):
    industry: Industry | None = None
    org_size: OrgSize | None  = None
    role: Role | None         = None


# ── EvalRecord ────────────────────────────────────────────────────────────────

class EvalRecord(BaseModel):
    """A practitioner's evaluation of a security tool."""
    type: ContribType = ContribType.eval
    context: ContribContext = Field(default_factory=ContribContext)

    # Required
    vendor: str                      # "CrowdStrike", "Splunk", etc.
    category: str                    # "edr", "siem", "cnapp", ...

    # Scored fields (all optional — contribute what you know)
    overall_score: float | None      = Field(None, ge=0, le=10)
    detection_rate: float | None     = Field(None, ge=0, le=100)
    fp_rate: float | None            = Field(None, ge=0, le=100)
    deploy_days: int | None          = None
    cpu_overhead: float | None       = Field(None, ge=0, le=100)
    ttfv_hours: float | None         = None
    would_buy: bool | None           = None
    eval_duration_days: int | None   = None

    # Free-text (will be anonymized before send)
    top_strength: str | None         = None
    top_friction: str | None         = None
    notes: str | None                = None


# ── AttackMap ─────────────────────────────────────────────────────────────────

class RemediationAction(BaseModel):
    """What someone actually did to stop or contain the attack."""
    action: str                      # "Isolated RDP across all subnets"
    category: str = "other"          # containment, detection, eradication, recovery, prevention
    effectiveness: str | None = None # "stopped_attack", "slowed_attack", "no_effect", "made_worse"
    time_to_implement: str | None = None  # "minutes", "hours", "days"
    tool_used: str | None = None     # vendor slug if a tool was involved
    sigma_rule: str | None = None    # Sigma rule YAML if they wrote/used one
    notes: str | None = None         # will be anonymized


class ObservedTechnique(BaseModel):
    """A single observed or simulated MITRE ATT&CK technique."""
    technique_id: str                # "T1566"
    technique_name: str | None       = None
    tactic: str | None               = None
    observed: bool                   = True   # True=seen in wild, False=simulated
    detected_by: list[str]           = Field(default_factory=list)   # vendor slugs
    missed_by: list[str]             = Field(default_factory=list)   # vendor slugs
    blocked_by: str | None           = None   # what stopped this technique
    notes: str | None                = None   # will be anonymized


class AttackMap(BaseModel):
    """An observed or simulated kill chain, MITRE ATT&CK aligned."""
    type: ContribType = ContribType.attack_map
    context: ContribContext = Field(default_factory=ContribContext)

    threat_name: str | None          = None   # "APT28", "ransomware campaign", etc.
    techniques: list[ObservedTechnique] = Field(default_factory=list)
    tools_in_scope: list[str]        = Field(default_factory=list)   # vendor slugs
    source: str                      = "practitioner"   # "red-team", "incident", "simulation"
    notes: str | None                = None

    # What actually worked — the actionable part
    remediation: list[RemediationAction] = Field(default_factory=list)
    time_to_detect: str | None       = None   # "minutes", "hours", "days"
    time_to_contain: str | None      = None   # "minutes", "hours", "days"
    time_to_recover: str | None      = None   # "hours", "days", "weeks"
    severity: str | None             = None   # "critical", "high", "medium", "low"
    data_exfiltrated: bool | None    = None   # was data stolen before containment?
    ransom_paid: bool | None         = None   # did they pay? (no judgment, just data)


# ── IOCBundle ─────────────────────────────────────────────────────────────────

class IOCEntry(BaseModel):
    """A single indicator of compromise."""
    ioc_type: str               # "domain", "ip", "hash-md5", "hash-sha256", "url", "email"
    # value is NEVER stored raw — it is hashed before leaving this machine
    value_hash: str | None = None     # SHA-256 of normalized value (set by anonymizer)
    value_raw: str | None  = None     # only exists locally, stripped before upload

    detected_by: list[str]     = Field(default_factory=list)  # vendor slugs
    missed_by: list[str]       = Field(default_factory=list)
    threat_actor: str | None   = None
    campaign: str | None       = None


class IOCBundle(BaseModel):
    """A set of IOCs linked to vendor detection outcomes."""
    type: ContribType = ContribType.ioc_bundle
    context: ContribContext = Field(default_factory=ContribContext)

    iocs: list[IOCEntry]             = Field(default_factory=list)
    tools_in_scope: list[str]        = Field(default_factory=list)
    source: str                      = "practitioner"   # "incident", "threat-hunt", "red-team"
    notes: str | None                = None


# ── DashboardScan ────────────────────────────────────────────────────────────

class PageFingerprint(BaseModel):
    """Structural fingerprint of a single dashboard page."""
    simhash: str = ""                          # SimHash of DOM skeleton (hex string)
    url_pattern: str = ""                      # URL with IDs stripped (e.g., /dashboard/:id/overview)
    feature_vector: dict[str, int] = Field(default_factory=dict)  # table_count, chart_count, card_count, etc.


class ModuleStatus(BaseModel):
    """A module/feature and its activation status."""
    name: str                                  # Module/feature name
    status: str = "active"                     # "active" or "inactive"


class IntegrationEntry(BaseModel):
    """A connected integration detected in the dashboard."""
    vendor: str                                # Connected vendor name (e.g., "splunk")
    status: str = "unknown"                    # "connected", "disconnected", "unknown"
    context: str = ""                          # "api", "webhook", "data_source", "siem_integration", etc.


class DashboardScan(BaseModel):
    """A browser extension dashboard scrape — structural fingerprints, module utilization, integrations."""
    type: ContribType = ContribType.dashboard_scan
    context: ContribContext = Field(default_factory=ContribContext)

    source_vendor: str                         # Domain of scanned dashboard (e.g., "crowdstrike.com")
    scan_type: str = "single"                  # "single" or "full"
    pages_scanned: int = 1
    page_fingerprints: list[PageFingerprint] = Field(default_factory=list)
    active_modules: list[ModuleStatus] = Field(default_factory=list)
    integrations: list[IntegrationEntry] = Field(default_factory=list)
    aggregate_feature_vector: dict[str, int] = Field(default_factory=dict)


# ── Union type for the upload pipeline ───────────────────────────────────────

Contribution = EvalRecord | AttackMap | IOCBundle | DashboardScan


def contribution_type(c: Contribution) -> str:
    return c.type.value
