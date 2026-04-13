"""
Threat model generator.

Generates MITRE ATT&CK-based threat models from a user's security tool stack,
using vertical configs and the vendor/MITRE mapping data bundled with nur.

Works offline — no server needed.

Usage:
    from nur.threat_model import generate_threat_model
    model = generate_threat_model(["crowdstrike", "splunk", "okta"], "healthcare")
    print(model["threatcl_hcl"])
"""
from __future__ import annotations

from .verticals import get_vertical
from .server.vendors import VENDOR_REGISTRY, load_mitre_map


# ── Constants ────────────────────────────────────────────────────────────────

_TACTIC_IMPACTS: dict[str, list[str]] = {
    "initial-access": ["Confidentiality"],
    "execution": ["Confidentiality"],
    "persistence": ["Integrity"],
    "privilege-escalation": ["Integrity"],
    "defense-evasion": ["Integrity"],
    "credential-access": ["Confidentiality"],
    "discovery": ["Confidentiality"],
    "collection": ["Confidentiality"],
    "lateral-movement": ["Confidentiality"],
    "command-and-control": ["Confidentiality", "Integrity"],
    "exfiltration": ["Confidentiality"],
    "impact": ["Availability", "Confidentiality"],
}

_CATEGORY_RISK_REDUCTION: dict[str, int] = {
    "edr": 85,
    "siem": 75,
    "iam": 80,
    "pam": 80,
    "email": 75,
    "ztna": 80,
    "cnapp": 70,
    "vm": 70,
    "waf": 75,
    "ndr": 75,
    "threat-intel": 65,
}

_VERTICAL_ASSETS: dict[str, dict[str, str]] = {
    "healthcare": {
        "primary": "Electronic Health Records (EHR), PACS imaging, patient PII",
        "infra": "NICU monitors, medical devices, clinical workstations",
    },
    "financial": {
        "primary": "Customer PII, transaction records, trading data, SWIFT messages",
        "infra": "Trading terminals, payment processing systems, ATM networks",
    },
    "energy": {
        "primary": "SCADA configurations, grid topology, operational procedures",
        "infra": "ICS/OT systems, PLCs, safety instrumented systems (SIS)",
    },
    "government": {
        "primary": "Classified documents, PII databases, intelligence reports",
        "infra": "Classified networks, communication systems, critical infrastructure",
    },
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _lookup_technique(technique_id: str, mitre_map: dict) -> dict | None:
    """Look up a technique in mitre_map. Try exact ID first, then base technique."""
    if technique_id in mitre_map:
        return mitre_map[technique_id]
    # Strip sub-technique suffix (e.g. T1566.001 -> T1566)
    base = technique_id.split(".")[0]
    return mitre_map.get(base)


def _hcl_escape(s: str) -> str:
    """Escape a string for HCL double-quoted values."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _truncate(s: str, max_len: int = 80) -> str:
    """Truncate string to max_len chars."""
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


# ── Main generator ───────────────────────────────────────────────────────────

def generate_threat_model(
    stack: list[str],
    vertical: str = "healthcare",
    org_name: str = "Organization",
) -> dict:
    """Generate a threat model for a given stack and vertical.

    Returns a dict with:
    - coverage: which MITRE techniques are covered by which tool
    - gaps: which techniques have no coverage
    - threat_actors: relevant to this vertical
    - compliance: which frameworks and how much coverage
    - recommendations: prioritized actions
    - threatcl_hcl: the threat model in threatcl HCL format (string)
    """
    v = get_vertical(vertical)
    mitre_map = load_mitre_map()

    # Normalize stack to lowercase
    stack_lower = [s.lower().strip() for s in stack]

    # Build stack info with display names
    stack_info = []
    for tool_id in stack_lower:
        vendor = VENDOR_REGISTRY.get(tool_id)
        if vendor:
            stack_info.append({
                "id": tool_id,
                "display_name": vendor["display_name"],
                "category": vendor["category"],
            })
        else:
            stack_info.append({
                "id": tool_id,
                "display_name": tool_id,
                "category": "unknown",
            })

    # ── Analyze technique coverage ────────────────────────────────────
    coverage: dict[str, dict] = {}
    gaps: list[dict] = []

    for idx, tech in enumerate(v.priority_techniques):
        tech_id = tech["id"]
        tech_name = tech["name"]
        tech_why = tech["why"]

        mitre_entry = _lookup_technique(tech_id, mitre_map)
        if not mitre_entry:
            # Technique not in our map — treat as gap
            gaps.append({
                "id": tech_id,
                "name": tech_name,
                "why": tech_why,
                "suggested_categories": [],
                "suggested_vendors": [],
                "priority_rank": idx,
            })
            continue

        primary_vendors = mitre_entry.get("primary_vendors", [])
        covering_tools = []
        for tool_id in stack_lower:
            if tool_id in primary_vendors:
                vendor = VENDOR_REGISTRY.get(tool_id)
                covering_tools.append({
                    "id": tool_id,
                    "display_name": vendor["display_name"] if vendor else tool_id,
                    "category": vendor["category"] if vendor else "unknown",
                })

        if covering_tools:
            coverage[tech_id] = {
                "name": tech_name,
                "why": tech_why,
                "tools": covering_tools,
                "tactic": mitre_entry.get("tactic", ""),
                "detection_approach": mitre_entry.get("detection_approach", ""),
                "prevention_approach": mitre_entry.get("prevention_approach", ""),
            }
        else:
            # Suggest categories and top vendors for the gap
            suggested_cats = mitre_entry.get("categories", [])
            suggested_vendors = [
                vid for vid in primary_vendors[:5] if vid not in stack_lower
            ]
            gaps.append({
                "id": tech_id,
                "name": tech_name,
                "why": tech_why,
                "tactic": mitre_entry.get("tactic", ""),
                "suggested_categories": suggested_cats,
                "suggested_vendors": suggested_vendors,
                "prevention_approach": mitre_entry.get("prevention_approach", ""),
                "priority_rank": idx,
            })

    # ── Compliance coverage ───────────────────────────────────────────
    compliance: dict[str, dict] = {}
    for framework in v.compliance:
        tools_covering = []
        for tool_id in stack_lower:
            vendor = VENDOR_REGISTRY.get(tool_id)
            if vendor and framework in vendor.get("compliance_frameworks", []):
                tools_covering.append(tool_id)
        compliance[framework] = {
            "covered": len(tools_covering) > 0,
            "tools": tools_covering,
        }

    # ── Coverage score ────────────────────────────────────────────────
    total_techniques = len(v.priority_techniques)
    covered_count = len(coverage)
    coverage_score = covered_count / total_techniques if total_techniques > 0 else 0.0

    # ── Recommendations ───────────────────────────────────────────────
    recommendations: list[dict] = []

    for gap in gaps:
        rank = gap.get("priority_rank", 99)
        if rank < 2:
            priority = "critical"
        elif rank < 5:
            priority = "high"
        else:
            priority = "medium"

        cats = gap.get("suggested_categories", [])
        cat_str = ", ".join(cats[:3]) if cats else "specialized"
        vendors = gap.get("suggested_vendors", [])
        vendor_names = []
        for vid in vendors[:3]:
            vinfo = VENDOR_REGISTRY.get(vid)
            vendor_names.append(vinfo["display_name"] if vinfo else vid)
        vendor_str = ", ".join(vendor_names) if vendor_names else "see vendor registry"

        recommendations.append({
            "priority": priority,
            "action": f"Add {cat_str} coverage for {gap['id']} ({gap['name']})",
            "detail": f"{gap['why']}. Consider: {vendor_str}",
        })

    # Also add compliance recommendations
    for framework, info in compliance.items():
        if not info["covered"]:
            recommendations.append({
                "priority": "high",
                "action": f"Address {framework} compliance gap",
                "detail": f"No tools in your stack cover {framework}. Review vendor certifications.",
            })

    # ── Build model dict ──────────────────────────────────────────────
    model = {
        "org_name": org_name,
        "vertical": vertical,
        "vertical_display": v.display_name,
        "stack": stack_info,
        "threat_actors": v.threat_actors,
        "campaigns": v.campaigns,
        "coverage": coverage,
        "gaps": gaps,
        "compliance": compliance,
        "coverage_score": round(coverage_score, 3),
        "recommendations": recommendations,
    }

    # Generate HCL and attach
    model["threatcl_hcl"] = threat_model_to_hcl(model)

    return model


# ── HCL generator ────────────────────────────────────────────────────────────

def threat_model_to_hcl(model: dict) -> str:
    """Convert the threat model dict to threatcl HCL format string."""
    org = model.get("org_name", "Organization")
    vertical = model.get("vertical", "healthcare")
    vertical_display = model.get("vertical_display", vertical)
    stack_info = model.get("stack", [])
    coverage = model.get("coverage", {})
    gaps = model.get("gaps", [])

    tool_names = [t["display_name"] for t in stack_info]
    tool_names_str = ", ".join(tool_names) if tool_names else "no tools"

    assets = _VERTICAL_ASSETS.get(vertical, _VERTICAL_ASSETS["healthcare"])

    lines: list[str] = []

    # Header
    lines.append('spec_version = "0.2.3"')
    lines.append("")
    tm_name = _hcl_escape(f"{org} {vertical_display} Security Stack")
    lines.append(f'threatmodel "{tm_name}" {{')

    desc = _hcl_escape(f"Threat model for {org} using {tool_names_str}")
    lines.append(f'  description = "{desc}"')
    lines.append('  author = "nur"')
    lines.append("")

    # Attributes
    lines.append("  attributes {")
    lines.append('    new_initiative = "false"')
    lines.append('    internet_facing = "true"')
    lines.append('    initiative_size = "Medium"')
    lines.append("  }")
    lines.append("")

    # Information assets
    lines.append('  information_asset "primary_data" {')
    lines.append(f'    description = "{_hcl_escape(assets["primary"])}"')
    lines.append('    information_classification = "Confidential"')
    lines.append("  }")
    lines.append("")

    lines.append('  information_asset "network_infrastructure" {')
    lines.append(f'    description = "{_hcl_escape(assets["infra"])}"')
    lines.append('    information_classification = "Internal"')
    lines.append("  }")

    # Covered techniques — emit threat + control blocks
    for tech_id, info in coverage.items():
        lines.append("")
        threat_label = _hcl_escape(f"{tech_id} {info['name']}")
        lines.append(f'  threat "{threat_label}" {{')
        lines.append(f'    description = "{_hcl_escape(info["why"])}"')

        tactic = info.get("tactic", "impact")
        impacts = _TACTIC_IMPACTS.get(tactic, ["Availability"])
        impacts_str = ", ".join(f'"{i}"' for i in impacts)
        lines.append(f"    impacts = [{impacts_str}]")

        for tool in info["tools"]:
            lines.append("")
            lines.append(f'    control "{_hcl_escape(tool["display_name"])}" {{')
            lines.append("      implemented = true")
            det = _truncate(info.get("detection_approach", ""), 80)
            lines.append(f'      description = "{_hcl_escape(det)}"')
            cat = tool.get("category", "edr")
            rr = _CATEGORY_RISK_REDUCTION.get(cat, 70)
            lines.append(f"      risk_reduction = {rr}")
            lines.append("    }")

        lines.append("  }")

    # Gap techniques — emit threat + expanded_control blocks
    for gap in gaps:
        lines.append("")
        threat_label = _hcl_escape(f"{gap['id']} {gap['name']}")
        lines.append(f'  threat "{threat_label}" {{')
        lines.append(f'    description = "{_hcl_escape(gap["why"])}"')

        tactic = gap.get("tactic", "impact")
        impacts = _TACTIC_IMPACTS.get(tactic, ["Availability"])
        impacts_str = ", ".join(f'"{i}"' for i in impacts)
        lines.append(f"    impacts = [{impacts_str}]")

        cats = gap.get("suggested_categories", [])
        cat_str = ", ".join(cats[:2]) if cats else "specialized"
        lines.append("")
        ctrl_label = _hcl_escape(f"Deploy {cat_str} solution")
        lines.append(f'    expanded_control "{ctrl_label}" {{')
        lines.append("      implemented = false")
        prev = _truncate(gap.get("prevention_approach", ""), 80)
        lines.append(f'      description = "{_hcl_escape(prev)}"')
        lines.append("      risk_reduction = 70")

        rank = gap.get("priority_rank", 99)
        if rank < 2:
            prio = 1
        elif rank < 5:
            prio = 2
        else:
            prio = 3
        lines.append(f"      priority = {prio}")
        lines.append("    }")

        lines.append("  }")

    lines.append("}")
    lines.append("")

    return "\n".join(lines)
