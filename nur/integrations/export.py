"""Export nur data in standard formats for interop with other security tools.

Supports: STIX 2.1, MISP, CSV, and ATT&CK Navigator layer JSON.
"""
from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone


# ── STIX 2.1 export ─────────────────────────────────────────────────────────

def export_stix_bundle(contributions: list[dict]) -> str:
    """Export contributions as a STIX 2.1 JSON bundle.

    Each contribution becomes an Indicator or ObservedData object.
    Returns the STIX JSON string.
    """
    objects: list[dict] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Bundle identity
    identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'nur')}"
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "nur",
        "identity_class": "tool",
    })

    for contrib in contributions:
        contrib_type = contrib.get("type", "unknown")

        if contrib_type in ("ioc_bundle", "ioc"):
            # IOC contributions become indicators
            iocs = contrib.get("iocs", [])
            if not iocs and "value" in contrib:
                iocs = [contrib]

            for ioc in iocs:
                ioc_type = ioc.get("type", "unknown")
                value = ioc.get("value") or ioc.get("value_hashed", "unknown")

                # Map IOC type to STIX pattern
                pattern = _ioc_to_stix_pattern(ioc_type, value)
                indicator_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, f'{ioc_type}:{value}')}"

                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created": now,
                    "modified": now,
                    "name": f"{ioc_type}: {value[:64]}",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now,
                    "created_by_ref": identity_id,
                    "labels": ["malicious-activity"],
                })

        elif contrib_type in ("eval_record", "eval"):
            # Eval records become notes/reports
            vendor = contrib.get("vendor", "unknown")
            score = contrib.get("overall_score", contrib.get("score", 0))
            note_id = f"note--{uuid.uuid5(uuid.NAMESPACE_DNS, f'eval:{vendor}:{score}')}"

            objects.append({
                "type": "note",
                "spec_version": "2.1",
                "id": note_id,
                "created": now,
                "modified": now,
                "content": f"Vendor evaluation: {vendor} scored {score}",
                "created_by_ref": identity_id,
                "object_refs": [identity_id],
            })

        elif contrib_type in ("attack_map", "attack"):
            # Attack maps become attack-pattern objects
            techniques = contrib.get("techniques", [])
            for tech in techniques:
                tid = tech.get("technique_id", tech.get("id", "unknown"))
                name = tech.get("technique_name", tech.get("name", tid))
                ap_id = f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_DNS, tid)}"

                objects.append({
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": ap_id,
                    "created": now,
                    "modified": now,
                    "name": f"{tid} {name}",
                    "created_by_ref": identity_id,
                    "external_references": [{
                        "source_name": "mitre-attack",
                        "external_id": tid,
                        "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                    }],
                })

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }

    return json.dumps(bundle, indent=2)


def _ioc_to_stix_pattern(ioc_type: str, value: str) -> str:
    """Map an IOC type to a STIX 2.1 pattern string."""
    mapping = {
        "ip": f"[ipv4-addr:value = '{value}']",
        "ipv4": f"[ipv4-addr:value = '{value}']",
        "ipv6": f"[ipv6-addr:value = '{value}']",
        "domain": f"[domain-name:value = '{value}']",
        "url": f"[url:value = '{value}']",
        "hash_md5": f"[file:hashes.MD5 = '{value}']",
        "hash_sha1": f"[file:hashes.'SHA-1' = '{value}']",
        "hash_sha256": f"[file:hashes.'SHA-256' = '{value}']",
        "email": f"[email-addr:value = '{value}']",
    }
    return mapping.get(ioc_type.lower(), f"[artifact:payload_bin = '{value}']")


# ── MISP event export ────────────────────────────────────────────────────────

def export_misp_event(contributions: list[dict]) -> str:
    """Export contributions as a MISP event JSON.

    Returns the MISP event JSON string.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    event_uuid = str(uuid.uuid4())

    attributes: list[dict] = []

    for contrib in contributions:
        contrib_type = contrib.get("type", "unknown")

        if contrib_type in ("ioc_bundle", "ioc"):
            iocs = contrib.get("iocs", [])
            if not iocs and "value" in contrib:
                iocs = [contrib]

            for ioc in iocs:
                ioc_type = ioc.get("type", "unknown")
                value = ioc.get("value") or ioc.get("value_hashed", "unknown")
                misp_type = _ioc_to_misp_type(ioc_type)

                attributes.append({
                    "uuid": str(uuid.uuid4()),
                    "type": misp_type,
                    "category": _ioc_to_misp_category(ioc_type),
                    "value": value,
                    "to_ids": True,
                    "comment": ioc.get("context", ""),
                    "timestamp": now,
                })

        elif contrib_type in ("attack_map", "attack"):
            techniques = contrib.get("techniques", [])
            for tech in techniques:
                tid = tech.get("technique_id", tech.get("id", ""))
                attributes.append({
                    "uuid": str(uuid.uuid4()),
                    "type": "text",
                    "category": "External analysis",
                    "value": f"MITRE ATT&CK: {tid}",
                    "to_ids": False,
                    "comment": tech.get("technique_name", tech.get("name", "")),
                    "timestamp": now,
                })

    event = {
        "Event": {
            "uuid": event_uuid,
            "info": "nur intelligence export",
            "date": now,
            "threat_level_id": "2",
            "analysis": "2",
            "distribution": "0",
            "Attribute": attributes,
            "Tag": [
                {"name": "tlp:amber"},
                {"name": "nur:export"},
            ],
        }
    }

    return json.dumps(event, indent=2)


def _ioc_to_misp_type(ioc_type: str) -> str:
    """Map IOC type to MISP attribute type."""
    mapping = {
        "ip": "ip-dst",
        "ipv4": "ip-dst",
        "ipv6": "ip-dst",
        "domain": "domain",
        "url": "url",
        "hash_md5": "md5",
        "hash_sha1": "sha1",
        "hash_sha256": "sha256",
        "email": "email-src",
    }
    return mapping.get(ioc_type.lower(), "text")


def _ioc_to_misp_category(ioc_type: str) -> str:
    """Map IOC type to MISP category."""
    mapping = {
        "ip": "Network activity",
        "ipv4": "Network activity",
        "ipv6": "Network activity",
        "domain": "Network activity",
        "url": "Network activity",
        "hash_md5": "Payload delivery",
        "hash_sha1": "Payload delivery",
        "hash_sha256": "Payload delivery",
        "email": "Payload delivery",
    }
    return mapping.get(ioc_type.lower(), "Other")


# ── CSV export ───────────────────────────────────────────────────────────────

def export_csv(contributions: list[dict]) -> str:
    """Export contributions as CSV.

    Returns the CSV string.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["type", "value", "category", "source", "timestamp", "extra"])

    for contrib in contributions:
        contrib_type = contrib.get("type", "unknown")

        if contrib_type in ("ioc_bundle", "ioc"):
            iocs = contrib.get("iocs", [])
            if not iocs and "value" in contrib:
                iocs = [contrib]

            for ioc in iocs:
                writer.writerow([
                    ioc.get("type", "unknown"),
                    ioc.get("value") or ioc.get("value_hashed", ""),
                    "ioc",
                    contrib.get("source", ""),
                    ioc.get("first_seen", ""),
                    ioc.get("context", ""),
                ])

        elif contrib_type in ("eval_record", "eval"):
            writer.writerow([
                "eval",
                contrib.get("vendor", ""),
                contrib.get("category", ""),
                contrib.get("source", ""),
                "",
                f"score={contrib.get('overall_score', contrib.get('score', ''))}",
            ])

        elif contrib_type in ("attack_map", "attack"):
            techniques = contrib.get("techniques", [])
            for tech in techniques:
                writer.writerow([
                    "technique",
                    tech.get("technique_id", tech.get("id", "")),
                    "attack-map",
                    "",
                    "",
                    tech.get("technique_name", tech.get("name", "")),
                ])

    return output.getvalue()


# ── ATT&CK Navigator layer export ───────────────────────────────────────────

def export_navigator_layer(threat_model: dict) -> str:
    """Export a threat model as an ATT&CK Navigator layer JSON.

    Takes a threat model dict (from generate_threat_model) and generates a
    Navigator layer that can be opened in the ATT&CK Navigator web tool.

    Covered techniques get score=100 (green), gaps get score=25 (red).
    """
    coverage = threat_model.get("coverage", {})
    gaps = threat_model.get("gaps", [])
    org_name = threat_model.get("org_name", "Organization")
    vertical = threat_model.get("vertical_display", threat_model.get("vertical", ""))

    techniques: list[dict] = []

    # Covered techniques — high score, green
    for tech_id, info in coverage.items():
        tool_names = ", ".join(t["display_name"] for t in info.get("tools", []))
        techniques.append({
            "techniqueID": tech_id,
            "score": 100,
            "color": "#31a354",
            "comment": f"Covered by: {tool_names}",
            "tactic": info.get("tactic", ""),
            "enabled": True,
            "showSubtechniques": False,
        })

    # Gap techniques — low score, red
    for gap in gaps:
        suggested = ", ".join(gap.get("suggested_categories", [])[:3])
        comment = gap.get("why", "")
        if suggested:
            comment += f" | Suggested: {suggested}"
        techniques.append({
            "techniqueID": gap["id"],
            "score": 25,
            "color": "#de2d26",
            "comment": comment,
            "tactic": gap.get("tactic", ""),
            "enabled": True,
            "showSubtechniques": False,
        })

    layer = {
        "name": f"{org_name} — {vertical} Coverage",
        "versions": {
            "layer": "4.5",
            "attack": "14",
            "navigator": "4.9.1",
        },
        "domain": "enterprise-attack",
        "description": (
            f"MITRE ATT&CK coverage map for {org_name}. "
            f"Green = covered, Red = gap. Generated by nur."
        ),
        "filters": {
            "platforms": ["Windows", "Linux", "macOS", "Network", "Cloud"],
        },
        "sorting": 3,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#de2d26", "#fee08b", "#31a354"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Covered (score 100)", "color": "#31a354"},
            {"label": "Gap (score 25)", "color": "#de2d26"},
        ],
        "metadata": [
            {"name": "generator", "value": "nur"},
            {"name": "vertical", "value": vertical},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    return json.dumps(layer, indent=2)
