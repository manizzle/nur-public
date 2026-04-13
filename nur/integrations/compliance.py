"""Compliance scanner sync — import status from Drata/Vanta-like exports.

Supports structured JSON (controls array), CSV, and simple JSON dict formats.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path


# ── Passing statuses (case-insensitive) ──────────────────────────────────────

_PASSING_STATUSES = {"passing", "pass", "passed", "compliant", "met", "true", "yes", "1"}


def _is_passing(status: str | bool) -> bool:
    """Determine if a control status counts as passing."""
    if isinstance(status, bool):
        return status
    return str(status).strip().lower() in _PASSING_STATUSES


# ── Framework name normalization ─────────────────────────────────────────────

_FRAMEWORK_ALIASES: dict[str, str] = {
    "hipaa": "HIPAA",
    "hitech": "HITECH",
    "pci-dss": "PCI-DSS",
    "pci_dss": "PCI-DSS",
    "pci dss": "PCI-DSS",
    "pcidss": "PCI-DSS",
    "soc2": "SOC2",
    "soc 2": "SOC2",
    "soc2-type2": "SOC2",
    "nist csf": "NIST CSF",
    "nist-csf": "NIST CSF",
    "nist_csf": "NIST CSF",
    "nist 800-53": "NIST 800-53",
    "nist-800-53": "NIST 800-53",
    "nist_800_53": "NIST 800-53",
    "fedramp": "FedRAMP",
    "fed_ramp": "FedRAMP",
    "cmmc": "CMMC",
    "cis controls": "CIS Controls",
    "cis_controls": "CIS Controls",
    "iso27001": "ISO27001",
    "iso 27001": "ISO27001",
    "iso-27001": "ISO27001",
    "nerc cip": "NERC CIP",
    "nerc-cip": "NERC CIP",
    "nerc_cip": "NERC CIP",
    "dora": "DORA",
    "glba": "GLBA",
    "sox": "SOX",
    "fisma": "FISMA",
    "iec 62443": "IEC 62443",
    "iec-62443": "IEC 62443",
}


def _normalize_framework(name: str) -> str:
    """Normalize a framework name to a canonical form."""
    lower = name.strip().lower()
    return _FRAMEWORK_ALIASES.get(lower, name.strip())


# ── Main import function ─────────────────────────────────────────────────────

def import_compliance_status(path: str) -> dict[str, bool]:
    """Import compliance control status from a JSON or CSV export.

    Accepts three formats:

    1. Structured JSON (Drata/Vanta-like):
       {"controls": [{"id": "AC-1", "status": "passing", "framework": "NIST 800-53"}, ...]}

    2. Simple JSON dict:
       {"HIPAA": true, "PCI_DSS": false, "SOC2": true}

    3. CSV with columns: framework, control_id, status
       (aggregates per framework — passing if any control passes)

    Returns dict of {framework: covered_bool}.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Compliance file not found: {path}")

    suffix = p.suffix.lower()

    if suffix == ".csv":
        return _import_csv(p)
    else:
        # Assume JSON
        return _import_json(p)


def _import_json(p: Path) -> dict[str, bool]:
    """Import from a JSON file — structured controls or simple dict."""
    data = json.loads(p.read_text(encoding="utf-8"))

    if isinstance(data, dict):
        # Check for structured format with "controls" key
        if "controls" in data and isinstance(data["controls"], list):
            return _parse_controls_list(data["controls"])

        # Simple dict format: {"HIPAA": true, "PCI_DSS": false}
        result: dict[str, bool] = {}
        for key, value in data.items():
            framework = _normalize_framework(key)
            if isinstance(value, bool):
                result[framework] = value
            elif isinstance(value, str):
                result[framework] = _is_passing(value)
            elif isinstance(value, dict):
                # Maybe {"status": "passing"}
                status = value.get("status", value.get("covered", False))
                result[framework] = _is_passing(status) if isinstance(status, str) else bool(status)
        return result

    elif isinstance(data, list):
        # List of control objects directly
        return _parse_controls_list(data)

    return {}


def _parse_controls_list(controls: list[dict]) -> dict[str, bool]:
    """Parse a list of control dicts with framework, id, status fields.

    Aggregates per framework: a framework is covered if at least one
    control is passing.
    """
    framework_statuses: dict[str, list[bool]] = {}

    for ctrl in controls:
        framework = ctrl.get("framework", "")
        if not framework:
            continue
        framework = _normalize_framework(framework)
        status = ctrl.get("status", "failing")
        passing = _is_passing(status)

        if framework not in framework_statuses:
            framework_statuses[framework] = []
        framework_statuses[framework].append(passing)

    # A framework is "covered" if at least one control is passing
    return {fw: any(statuses) for fw, statuses in framework_statuses.items()}


def _import_csv(p: Path) -> dict[str, bool]:
    """Import from CSV: framework, control_id, status columns."""
    framework_statuses: dict[str, list[bool]] = {}

    with open(p, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return {}

        # Find framework and status columns (case-insensitive)
        fields_lower = {col.strip().lower(): col for col in reader.fieldnames}
        fw_col = fields_lower.get("framework")
        status_col = fields_lower.get("status")

        if not fw_col or not status_col:
            return {}

        for row in reader:
            framework = _normalize_framework(row.get(fw_col, ""))
            if not framework:
                continue
            status = row.get(status_col, "failing")
            passing = _is_passing(status)

            if framework not in framework_statuses:
                framework_statuses[framework] = []
            framework_statuses[framework].append(passing)

    return {fw: any(statuses) for fw, statuses in framework_statuses.items()}
