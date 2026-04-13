"""MITRE ATT&CK Navigator layer import.

Every security team has ATT&CK Navigator layer JSON files. Import them for
instant gap analysis by mapping Navigator scores to the nur threat model.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..threat_model import generate_threat_model
from ..server.vendors import VENDOR_REGISTRY, load_mitre_map


def import_navigator_layer(layer_path: str, vertical: str = "healthcare") -> dict:
    """Import a MITRE ATT&CK Navigator layer JSON and generate a threat model.

    Navigator format:
        {"techniques": [{"techniqueID": "T1566", "score": 100, "color": "#...", "tactic": "..."}]}

    Scores:  > 50 = covered,  <= 50 = gap.

    Returns a threat model dict (same as generate_threat_model output) plus
    a 'navigator_source' key with import metadata.
    """
    p = Path(layer_path)
    if not p.exists():
        raise FileNotFoundError(f"Navigator layer file not found: {layer_path}")

    data = json.loads(p.read_text(encoding="utf-8"))
    layer_name = data.get("name", p.stem)
    techniques = data.get("techniques", [])

    if not techniques:
        raise ValueError("Navigator layer contains no techniques")

    # ── Parse techniques and determine coverage ──────────────────────
    mitre_map = load_mitre_map()

    covered_technique_ids: set[str] = set()
    gap_technique_ids: set[str] = set()
    technique_details: dict[str, dict] = {}

    for tech in techniques:
        tid = tech.get("techniqueID", "")
        if not tid:
            continue

        score = tech.get("score", 0)
        if score is None:
            score = 0

        technique_details[tid] = {
            "score": score,
            "comment": tech.get("comment", ""),
            "tactic": tech.get("tactic", ""),
            "color": tech.get("color", ""),
        }

        if score > 50:
            covered_technique_ids.add(tid)
        else:
            gap_technique_ids.add(tid)

    # ── Map covered techniques to vendor slugs ───────────────────────
    # Find which vendors in our registry cover these techniques
    inferred_stack: set[str] = set()

    for tid in covered_technique_ids:
        # Look up technique in mitre_map (try exact, then base ID)
        entry = mitre_map.get(tid)
        if not entry:
            base = tid.split(".")[0]
            entry = mitre_map.get(base)

        if entry:
            primary_vendors = entry.get("primary_vendors", [])
            # Add the first vendor from each category to avoid duplicates
            seen_categories: set[str] = set()
            for vid in primary_vendors:
                vendor = VENDOR_REGISTRY.get(vid)
                if vendor and vendor["category"] not in seen_categories:
                    inferred_stack.add(vid)
                    seen_categories.add(vendor["category"])

    # ── Generate the threat model using inferred stack ───────────────
    stack_list = sorted(inferred_stack) if inferred_stack else []
    model = generate_threat_model(
        stack=stack_list,
        vertical=vertical,
        org_name=f"Navigator Import ({layer_name})",
    )

    # ── Attach navigator source metadata ─────────────────────────────
    model["navigator_source"] = {
        "layer_name": layer_name,
        "total_techniques": len(techniques),
        "covered_count": len(covered_technique_ids),
        "gap_count": len(gap_technique_ids),
        "inferred_stack": stack_list,
        "technique_details": technique_details,
    }

    return model
