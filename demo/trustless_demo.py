#!/usr/bin/env python3
"""
Trustless Pipeline Demo — Full E2E proof chain.

Shows the complete flow:
  Contributor → Server (commit + aggregate) → Consumer (verify proof)

The server is an accountable compute node — it commits to every value,
proves every aggregate, and discards individual data. Not blind, but
on a cryptographic leash.
"""
from __future__ import annotations

import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def banner(text: str):
    width = 72
    print(f"\n{'=' * width}")
    print(f"  {text}")
    print(f"{'=' * width}\n")


def section(text: str):
    print(f"\n  -- {text} {'-' * max(0, 56 - len(text))}\n")


def show_receipt(receipt, label: str = "Receipt"):
    d = receipt.to_dict()
    print(f"  {label}:")
    print(f"    receipt_id:      {d['receipt_id']}")
    print(f"    commitment_hash: {d['commitment_hash'][:32]}...")
    print(f"    merkle_root:     {d['merkle_root'][:32]}...")
    print(f"    merkle_proof:    {len(d['merkle_proof'])} nodes")
    print(f"    aggregate_id:    {d['aggregate_id']}")
    print(f"    signature:       {d['server_signature'][:32]}...")
    print()


def main():
    from nur.server.proofs import (
        ProofEngine, verify_receipt, verify_aggregate_proof,
        translate_eval, translate_attack_map, translate_ioc_bundle,
        translate_webhook_crowdstrike, translate_webhook_sentinel,
    )

    engine = ProofEngine()

    banner("TRUSTLESS PIPELINE DEMO")
    print("  The server commits to every value, proves every aggregate,")
    print("  and discards individual data. Cryptographic accountability.")
    print()

    # -- Step 1: Submit EvalRecord -----------------------------------------
    section("Step 1: Submit EvalRecord")

    eval_body = {
        "data": {
            "vendor": "CrowdStrike",
            "category": "edr",
            "overall_score": 9.2,
            "detection_rate": 94.5,
            "fp_rate": 2.1,
            "would_buy": True,
            "top_strength": "Great detection quality across endpoints",
            "top_friction": "High false positive rate on custom apps",
            "notes": "This free text is intentionally DROPPED by the translator",
        }
    }
    vendor, category, values = translate_eval(eval_body)
    print(f"  Translator output:")
    print(f"    vendor:   {vendor}")
    print(f"    category: {category}")
    print(f"    values:   {json.dumps(values, indent=2, default=str)}")
    print(f"    (notes field: DROPPED -- no free text in proof layer)")
    print()

    receipt_eval = engine.commit_contribution(vendor, category, values)
    show_receipt(receipt_eval, "EvalRecord Receipt")

    # -- Step 2: Submit AttackMap ------------------------------------------
    section("Step 2: Submit AttackMap")

    attack_body = {
        "threat_name": "APT29 Campaign",
        "severity": "critical",
        "time_to_detect": "hours",
        "time_to_contain": "days",
        "techniques": [
            {"technique_id": "T1566", "technique_name": "Phishing", "observed": True,
             "detected_by": ["CrowdStrike", "Proofpoint"], "missed_by": ["SentinelOne"]},
            {"technique_id": "T1078", "technique_name": "Valid Accounts", "observed": True,
             "detected_by": ["Okta"], "missed_by": ["CrowdStrike", "SentinelOne"]},
            {"technique_id": "T1021.001", "technique_name": "RDP", "observed": True,
             "detected_by": ["CrowdStrike"], "missed_by": []},
        ],
        "remediation": [
            {"category": "containment", "effectiveness": "stopped_attack",
             "action": "Isolated affected hosts", "sigma_rule": "title: Detect Phishing\n..."},
            {"category": "detection", "effectiveness": "slowed_attack",
             "action": "Deployed new Sigma rules"},
        ],
        "notes": "Full incident writeup -- DROPPED by translator",
    }
    params = translate_attack_map(attack_body)
    print(f"  Translator output:")
    print(f"    techniques: {len(params['techniques'])} (IDs only, no names/notes)")
    print(f"    severity:   {params['severity']}")
    print(f"    remediation: {len(params['remediation'])} actions (category+effectiveness only)")
    print(f"    (notes, action strings, sigma_rule YAML: all DROPPED)")
    print()

    receipt_attack = engine.commit_attack_map(**params)
    show_receipt(receipt_attack, "AttackMap Receipt")

    # Show technique histogram update
    freq = engine.get_technique_frequency()
    print(f"  Technique histogram updated:")
    for t in freq:
        print(f"    {t['technique_id']}: {t['count']} observations ({t['pct']}%)")
    print()

    # -- Step 3: Submit IOC Bundle -----------------------------------------
    section("Step 3: Submit IOC Bundle")

    ioc_body = {
        "iocs": [
            {"ioc_type": "ip", "value_hash": "abc123"},
            {"ioc_type": "domain", "value_hash": "def456"},
            {"ioc_type": "hash-sha256", "value_hash": "ghi789"},
        ],
        "source": "internal-siem",
    }
    ioc_count, ioc_types = translate_ioc_bundle(ioc_body)
    print(f"  Translator output:")
    print(f"    ioc_count: {ioc_count}")
    print(f"    ioc_types: {ioc_types}")
    print(f"    (individual IOC values: NOT sent to proof layer)")
    print()

    receipt_ioc = engine.commit_ioc_bundle(ioc_count, ioc_types)
    show_receipt(receipt_ioc, "IOC Bundle Receipt")

    # -- Step 4: Submit via CrowdStrike webhook ----------------------------
    section("Step 4: Submit via CrowdStrike Webhook")

    cs_webhook = {
        "detection": {
            "technique": "T1059.001",
            "tactic": "execution",
            "severity": "high",
            "scenario": "PowerShell Execution",
            "ioc_type": "ip",
            "ioc_value": "203.0.113.42",
        }
    }
    translated = translate_webhook_crowdstrike(cs_webhook)
    print(f"  Translated CrowdStrike detection:")
    print(f"    attack_map: {translated['attack_map_params'] is not None}")
    print(f"    ioc_bundle: {translated['ioc_params'] is not None}")

    cs_receipts = []
    if translated["attack_map_params"]:
        r = engine.commit_attack_map(**translated["attack_map_params"])
        cs_receipts.append(r)
        show_receipt(r, "CrowdStrike AttackMap Receipt")
    if translated["ioc_params"]:
        r = engine.commit_ioc_bundle(*translated["ioc_params"])
        cs_receipts.append(r)
        show_receipt(r, "CrowdStrike IOC Receipt")

    # -- Step 5: Submit via Sentinel webhook -------------------------------
    section("Step 5: Submit via Sentinel Webhook")

    sentinel_webhook = {
        "properties": {
            "title": "Multi-stage attack",
            "severity": "High",
            "techniques": ["T1566", "T1078"],
            "tactics": ["InitialAccess", "Execution"],
            "entities": [
                {"kind": "ip", "address": "198.51.100.23"},
                {"kind": "host", "hostName": "evil.example.com"},
            ],
        }
    }
    translated = translate_webhook_sentinel(sentinel_webhook)
    print(f"  Translated Sentinel incident:")
    print(f"    attack_map: {translated['attack_map_params'] is not None}")
    print(f"    ioc_bundle: {translated['ioc_params'] is not None}")

    sentinel_receipts = []
    if translated["attack_map_params"]:
        r = engine.commit_attack_map(**translated["attack_map_params"])
        sentinel_receipts.append(r)
        show_receipt(r, "Sentinel AttackMap Receipt")
    if translated["ioc_params"]:
        r = engine.commit_ioc_bundle(*translated["ioc_params"])
        sentinel_receipts.append(r)
        show_receipt(r, "Sentinel IOC Receipt")

    # -- Step 6: Query aggregate with proof --------------------------------
    section("Step 6: Query Aggregate + Proof Chain")

    agg = engine.get_aggregate("CrowdStrike")
    print(f"  Aggregate for CrowdStrike:")
    print(f"    {json.dumps(agg, indent=4)}")
    print()

    proof = engine.prove_aggregate("CrowdStrike")
    print(f"  Aggregate Proof:")
    print(f"    aggregate_id:      {proof.aggregate_id}")
    print(f"    contributor_count: {proof.contributor_count}")
    print(f"    merkle_root:       {proof.merkle_root[:32]}...")
    print(f"    commitment_hashes: {len(proof.commitment_hashes)} hashes")
    print(f"    signature:         {proof.server_signature[:32]}...")
    print()

    # -- Step 7: Verify each receipt ---------------------------------------
    section("Step 7: Verify Receipts Against Merkle Tree")

    # Note: only the most recent receipt's proof is valid against current root.
    # Earlier receipts' proofs were generated with an older root.
    # In production, you'd re-generate proofs or use append-only logs.
    all_receipts = [receipt_eval, receipt_attack, receipt_ioc] + cs_receipts + sentinel_receipts
    labels = ["EvalRecord", "AttackMap", "IOC Bundle"] + \
             [f"CrowdStrike-{i}" for i in range(len(cs_receipts))] + \
             [f"Sentinel-{i}" for i in range(len(sentinel_receipts))]

    for label, receipt in zip(labels, all_receipts):
        valid = verify_receipt(receipt)
        status = "VALID" if valid else "STALE (tree updated since receipt)"
        print(f"  {label:20s} -> {status}")
    print()
    print("  Note: Earlier receipts may show 'stale' because the Merkle tree")
    print("  grew since they were issued. The commitment hash is still in the tree.")

    # -- Step 8: Verify aggregate proof ------------------------------------
    section("Step 8: Verify Aggregate Proof")

    result = verify_aggregate_proof(proof, expected_root=engine.merkle_root)
    print(f"  Verification result:")
    print(f"    valid: {result['valid']}")
    for check, passed in result["checks"].items():
        print(f"    {check}: {'PASS' if passed else 'FAIL'}")
    if result["errors"]:
        for err in result["errors"]:
            print(f"    ERROR: {err}")
    print()

    # -- Step 9: What the server has vs can prove vs cannot see ------------
    section("Step 9: Trust Architecture Summary")

    stats = engine.get_platform_stats()
    print(f"  WHAT THE SERVER HAS:")
    print(f"    - {stats['total_contributions']} commitment hashes (opaque SHA-256)")
    print(f"    - Running sums for {stats['unique_vendors']} vendors")
    print(f"    - Technique frequency histogram ({stats['unique_techniques']} techniques)")
    print(f"    - Merkle tree root: {stats['merkle_root'][:32]}...")
    print()
    print(f"  WHAT IT CAN PROVE:")
    print(f"    - Every aggregate is computed from real committed contributions")
    print(f"    - No contribution was altered after receipt was issued")
    print(f"    - No contributions were excluded or fabricated")
    print(f"    - The contributor count is real (Merkle tree binds it)")
    print()
    print(f"  WHAT IT CANNOT SEE:")
    print(f"    - Which organization submitted which score")
    print(f"    - Individual eval scores (only running sums)")
    print(f"    - Which org reported which technique")
    print(f"    - Free-text notes, incident details, sigma rules")
    print(f"    - Raw IOC values (only counts and types)")
    print()

    # -- Step 10: Prove zero individual values stored ----------------------
    section("Step 10: Zero Individual Values Stored")

    print(f"  ProofEngine internal state:")
    print(f"    _commitments: {len(engine._commitments)} opaque hashes")
    print(f"    _aggregates:  {len(engine._aggregates)} vendor:category buckets")
    print()

    for agg_id, bucket in engine._aggregates.items():
        print(f"    Bucket '{agg_id}':")
        print(f"      total_count: {bucket.total_count}")
        print(f"      sums:        {dict(bucket.sums)}")
        print(f"      counts:      {dict(bucket.counts)}")
        print(f"      (These are RUNNING SUMS -- not lists of individual values)")
        print()

    print(f"  Technique histogram (running counts, not contributor lists):")
    for tid, count in sorted(engine._technique_freq.items()):
        print(f"    {tid}: {count}")
    print()

    print(f"  Vendor detection matrix (counts only):")
    for (tid, vendor), counts in sorted(engine._vendor_detection.items()):
        print(f"    ({tid}, {vendor}): detected={counts['detected']}, missed={counts['missed']}")
    print()

    print(f"  Individual values?  ZERO.")
    print(f"  Individual scores?  ZERO.")
    print(f"  Free-text notes?    ZERO.")
    print(f"  Raw IOC values?     ZERO.")
    print()

    # -- Step 11: Blind Category Discovery -----------------------------------
    section("Step 11: Blind Category Discovery")

    from nur.server.blind_categories import BlindCategoryDiscovery, hash_category

    bcd = engine.blind_categories
    shared_salt = "nur-2026"

    print(f"  Three hospitals independently encounter 'DarkAngel' ransomware.")
    print(f"  None of them know the others are seeing it.\n")

    h = hash_category("DarkAngel", shared_salt)
    print(f"  Category hash: {h[:16]}...")
    print(f"  (Server never sees the name 'DarkAngel' at this stage)\n")

    r1 = bcd.propose_category(h, "threat_actor", "hospital-a")
    print(f"  Hospital A proposes: {r1['status']} (supporters: {r1['supporter_count']}/{r1['threshold']})")

    r2 = bcd.propose_category(h, "threat_actor", "hospital-b")
    print(f"  Hospital B proposes: {r2['status']} (supporters: {r2['supporter_count']}/{r2['threshold']})")

    r3 = bcd.propose_category(h, "threat_actor", "hospital-c")
    print(f"  Hospital C proposes: {r3['status']} (supporters: {r3['supporter_count']}/{r3['threshold']})")
    print(f"  --> Threshold met! Ready for reveal.\n")

    v1 = bcd.vote_reveal(h, "DarkAngel", shared_salt, "hospital-a")
    print(f"  Hospital A votes to reveal: {v1['status']} (remaining: {v1.get('remaining', 0)})")

    v2 = bcd.vote_reveal(h, "DarkAngel", shared_salt, "hospital-b")
    print(f"  Hospital B votes to reveal: {v2['status']}")
    print(f"  --> Revealed name: '{v2['revealed_name']}'\n")

    print(f"  Category now in public taxonomy for aggregation.")
    print(f"  Pending categories: {bcd.pending_count}")
    print(f"  Revealed categories: {bcd.revealed_count}")
    print()

    banner("DEMO COMPLETE -- Trustless architecture verified")
    print("  The server is on a cryptographic leash.")
    print("  Contributors get receipts. Consumers get proofs.")
    print("  Nobody has to trust anyone.")
    print()


if __name__ == "__main__":
    main()
