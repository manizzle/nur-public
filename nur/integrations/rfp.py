"""Procurement / RFP comparison helper.

Generate structured vendor comparison reports for tool evaluations, pulling
data from the nur vendor registry.
"""
from __future__ import annotations

from ..server.vendors import VENDOR_REGISTRY, load_mitre_map


# ── Score computation helpers ────────────────────────────────────────────────

def _technique_coverage_count(vendor_id: str, mitre_map: dict) -> int:
    """Count how many MITRE techniques a vendor is listed as primary for."""
    count = 0
    for _tid, entry in mitre_map.items():
        if vendor_id in entry.get("primary_vendors", []):
            count += 1
    return count


def _compliance_score(vendor: dict) -> int:
    """Score 0-100 based on number of compliance frameworks covered."""
    frameworks = vendor.get("compliance_frameworks", [])
    certs = vendor.get("certifications", [])
    # More frameworks + certs = higher score
    return min(100, len(frameworks) * 15 + len(certs) * 8)


def _insurance_score(vendor: dict) -> int:
    """Score 0-100 based on insurance carrier recognition."""
    carriers = vendor.get("insurance_carriers", [])
    if len(carriers) >= 4:
        return 95
    if len(carriers) >= 2:
        return 75
    if len(carriers) >= 1:
        return 50
    return 20


def _risk_score(vendor: dict) -> int:
    """Score 0-100 — lower is better for risk. Based on known issues."""
    issues = vendor.get("known_issues", "")
    if not issues:
        return 95  # no known issues = low risk
    if "breach" in issues.lower() or "cve" in issues.lower():
        return 40
    if "ban" in issues.lower():
        return 25
    return 60


# ── Main comparison generator ────────────────────────────────────────────────

def generate_rfp_comparison(
    candidates: list[str],
    category: str = "edr",
    vertical: str = "healthcare",
) -> dict:
    """Generate a vendor comparison report for procurement/RFP.

    Args:
        candidates: list of vendor slugs (e.g. ["crowdstrike", "sentinelone"])
        category: tool category for filtering
        vertical: industry vertical for compliance relevance

    Returns dict with:
        category, candidates (scored), recommendation, comparison_table
    """
    mitre_map = load_mitre_map()

    candidate_reports: list[dict] = []
    for vid in candidates:
        vendor = VENDOR_REGISTRY.get(vid.lower().strip())
        if not vendor:
            candidate_reports.append({
                "id": vid,
                "display_name": vid,
                "found": False,
                "error": f"Vendor '{vid}' not found in registry",
            })
            continue

        technique_count = _technique_coverage_count(vid, mitre_map)
        comp_score = _compliance_score(vendor)
        ins_score = _insurance_score(vendor)
        risk = _risk_score(vendor)

        # Overall score: weighted average
        overall = int(technique_count * 2 + comp_score * 0.3 + ins_score * 0.2 + risk * 0.2)
        overall = min(100, overall)

        candidate_reports.append({
            "id": vid,
            "display_name": vendor["display_name"],
            "found": True,
            "category": vendor["category"],
            "price_range": vendor.get("price_range", "Unknown"),
            "certifications": vendor.get("certifications", []),
            "compliance_frameworks": vendor.get("compliance_frameworks", []),
            "insurance_carriers": vendor.get("insurance_carriers", []),
            "known_issues": vendor.get("known_issues", ""),
            "typical_deploy_days": vendor.get("typical_deploy_days", 0),
            "scores": {
                "technique_coverage": technique_count,
                "compliance": comp_score,
                "insurance": ins_score,
                "risk": risk,
                "overall": overall,
            },
        })

    # ── Sort by overall score descending ─────────────────────────────
    scored = [c for c in candidate_reports if c.get("found")]
    scored.sort(key=lambda c: c.get("scores", {}).get("overall", 0), reverse=True)

    # ── Generate recommendation ──────────────────────────────────────
    recommendation = ""
    if scored:
        best = scored[0]
        if len(scored) > 1:
            runner = scored[1]
            recommendation = (
                f"{best['display_name']} leads with overall score {best['scores']['overall']} "
                f"vs {runner['display_name']} at {runner['scores']['overall']}. "
            )
            if best["scores"]["risk"] < runner["scores"]["risk"]:
                recommendation += (
                    f"Note: {best['display_name']} has higher risk due to known issues. "
                    f"Consider {runner['display_name']} if risk tolerance is low."
                )
            if best.get("typical_deploy_days", 0) > runner.get("typical_deploy_days", 0) * 2:
                recommendation += (
                    f" {runner['display_name']} deploys significantly faster "
                    f"({runner['typical_deploy_days']}d vs {best['typical_deploy_days']}d)."
                )
        else:
            recommendation = (
                f"{best['display_name']} scores {best['scores']['overall']} overall. "
                f"Consider adding more candidates for a thorough comparison."
            )

    # ── Build comparison table ───────────────────────────────────────
    comparison_table: list[dict] = []
    for c in scored:
        comparison_table.append({
            "vendor": c["display_name"],
            "price": c.get("price_range", "?"),
            "technique_coverage": c["scores"]["technique_coverage"],
            "compliance_score": c["scores"]["compliance"],
            "insurance_score": c["scores"]["insurance"],
            "risk_score": c["scores"]["risk"],
            "overall": c["scores"]["overall"],
            "deploy_days": c.get("typical_deploy_days", "?"),
            "known_issues": c.get("known_issues", "")[:80] if c.get("known_issues") else "None",
        })

    not_found = [c for c in candidate_reports if not c.get("found")]

    return {
        "category": category,
        "vertical": vertical,
        "candidates": candidate_reports,
        "recommendation": recommendation,
        "comparison_table": comparison_table,
        "not_found": [c["id"] for c in not_found],
    }
