"""Asset inventory import — fuzzy-match tool names to the nur vendor registry.

Supports CSV, JSON, and ServiceNow CMDB as import sources.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

from ..server.vendors import VENDOR_REGISTRY


# ── Common aliases for vendor tools ─────────────────────────────────────────

ALIASES: dict[str, str] = {
    # Microsoft Defender
    "mde": "ms-defender",
    "microsoft defender": "ms-defender",
    "defender for endpoint": "ms-defender",
    "defender atp": "ms-defender",
    "windows defender": "ms-defender",
    # CrowdStrike
    "cs": "crowdstrike",
    "falcon": "crowdstrike",
    "crowdstrike falcon": "crowdstrike",
    # SentinelOne
    "s1": "sentinelone",
    "sentinel one": "sentinelone",
    # Palo Alto
    "palo alto": "cortex-xdr",
    "cortex": "cortex-xdr",
    "pan cortex": "cortex-xdr",
    # Microsoft Entra / Azure AD
    "azure ad": "entra-id",
    "aad": "entra-id",
    "entra": "entra-id",
    "azure active directory": "entra-id",
    # Microsoft Sentinel
    "sentinel": "ms-sentinel",
    "azure sentinel": "ms-sentinel",
    # Tenable / Nessus
    "nessus": "tenable",
    # Rapid7
    "insightvm": "rapid7",
    "nexpose": "rapid7",
    # HashiCorp Vault
    "vault": "hashicorp-vault",
    "hashi": "hashicorp-vault",
    "hashicorp": "hashicorp-vault",
    # Cloudflare
    "cf waf": "cloudflare-waf",
    "cf zt": "cloudflare-zt",
    "cloudflare access": "cloudflare-zt",
    # Cisco Duo
    "duo": "cisco-duo",
    # Prisma Cloud
    "prisma": "prisma-cloud",
    "prisma cloud": "prisma-cloud",
    # Recorded Future
    "rf": "recorded-future",
    # QRadar
    "qradar": "qradar",
    "ibm qradar": "qradar",
    # Elastic
    "elastic": "elastic-siem",
    "elk": "elastic-siem",
    # Sophos
    "intercept x": "sophos",
    # CyberArk
    "cyberark": "cyberark-pam",
    # BeyondTrust
    "bt": "beyondtrust",
}


# ── Fuzzy matcher ───────────────────────────────────────────────────────────

def match_tool_to_vendor(tool_name: str) -> str | None:
    """Fuzzy-match a tool name to the nur vendor registry.

    Matching priority:
      1. Exact slug match
      2. Alias lookup
      3. Display name exact match (case-insensitive)
      4. Display name contains (case-insensitive)
      5. Slug contains
    Returns the vendor slug or None.
    """
    if not tool_name or not tool_name.strip():
        return None

    name = tool_name.strip()
    name_lower = name.lower()

    # 1. Exact slug match
    if name_lower in VENDOR_REGISTRY:
        return name_lower

    # 2. Alias lookup
    if name_lower in ALIASES:
        return ALIASES[name_lower]

    # 3. Display name exact match (case-insensitive)
    for vid, vendor in VENDOR_REGISTRY.items():
        if vendor["display_name"].lower() == name_lower:
            return vid

    # 4. Display name contains (case-insensitive) — input is substring of display name
    for vid, vendor in VENDOR_REGISTRY.items():
        if name_lower in vendor["display_name"].lower():
            return vid

    # 5. Partial alias match — input contains an alias key
    for alias, vid in ALIASES.items():
        if alias in name_lower:
            return vid

    # 6. Slug contains — input contains a vendor slug
    for vid in VENDOR_REGISTRY:
        if vid in name_lower:
            return vid

    # 7. Vendor slug is substring of input
    for vid in VENDOR_REGISTRY:
        if vid.replace("-", " ") in name_lower:
            return vid

    return None


# ── CSV import ──────────────────────────────────────────────────────────────

_CSV_COLUMNS = {"tool", "vendor", "product", "software", "name"}


def import_from_csv(path: str) -> list[str]:
    """Import tool names from a CSV. Looks for columns: tool, vendor, product, software, name.

    Returns deduplicated list of vendor slugs matching our registry.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"CSV file not found: {path}")

    matched: set[str] = set()

    with open(p, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return []

        # Find the first column that matches our expected names
        target_col = None
        for col in reader.fieldnames:
            if col.strip().lower() in _CSV_COLUMNS:
                target_col = col
                break

        if target_col is None:
            return []

        for row in reader:
            val = row.get(target_col, "").strip()
            if not val:
                continue
            slug = match_tool_to_vendor(val)
            if slug:
                matched.add(slug)

    return sorted(matched)


# ── JSON import ─────────────────────────────────────────────────────────────

_JSON_KEYS = ("tool", "vendor", "product", "name", "software")


def import_from_json(path: str) -> list[str]:
    """Import from a JSON list of tool names or list of dicts.

    Returns deduplicated list of matched vendor slugs.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"JSON file not found: {path}")

    data = json.loads(p.read_text(encoding="utf-8"))
    matched: set[str] = set()

    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                slug = match_tool_to_vendor(item)
                if slug:
                    matched.add(slug)
            elif isinstance(item, dict):
                # Try known keys
                for key in _JSON_KEYS:
                    val = item.get(key, "")
                    if val:
                        slug = match_tool_to_vendor(str(val))
                        if slug:
                            matched.add(slug)
                        break  # use first matching key
    elif isinstance(data, dict):
        # Maybe a dict of {name: details}
        for key in data:
            slug = match_tool_to_vendor(str(key))
            if slug:
                matched.add(slug)

    return sorted(matched)


# ── ServiceNow CMDB import ──────────────────────────────────────────────────

def import_from_servicenow(instance: str, username: str, password: str) -> list[str]:
    """Pull software inventory from ServiceNow CMDB.

    Queries the cmdb_ci_software table and fuzzy-matches display names.
    Returns deduplicated list of vendor slugs.
    """
    try:
        import httpx
    except ImportError:
        raise ImportError("ServiceNow import requires httpx: pip install httpx")

    url = f"https://{instance}.service-now.com/api/now/table/cmdb_ci_software"
    params = {
        "sysparm_fields": "display_name,name",
        "sysparm_limit": "500",
    }

    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(url, params=params, auth=(username, password))
            resp.raise_for_status()
    except httpx.HTTPError as e:
        raise ConnectionError(f"ServiceNow API error: {e}")

    data = resp.json()
    records = data.get("result", [])

    matched: set[str] = set()
    for record in records:
        name = record.get("display_name") or record.get("name", "")
        if name:
            slug = match_tool_to_vendor(name)
            if slug:
                matched.add(slug)

    return sorted(matched)
