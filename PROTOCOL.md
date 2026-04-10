# Protocol Specification

## Overview

The nur protocol is a trustless aggregation system for security intelligence. It enables organizations to contribute security data and receive aggregate intelligence without revealing individual inputs, organizational identity, or sensitive operational details.

The protocol solves a fundamental coordination problem: security teams have valuable data about what works, what fails, and what attacks look like -- but sharing that data creates legal, competitive, and operational risk. The nur protocol eliminates that risk by construction. What crosses the network boundary is mathematically guaranteed to be non-attributable.

---

## Data Flow

The protocol distinguishes two categories of data:

**Query Data (inbound)** -- what organizations contribute:
- Threat models (MITRE ATT&CK technique observations)
- IOC hashes (SHA-256 of indicators, never raw values)
- Security stack descriptions (what tools are deployed, in categorical form)

**Response Data (outbound)** -- what organizations receive back:
- Tool intelligence (aggregate detection rates, coverage gaps)
- Remediation intelligence (what stopped the attack, by technique)
- Pricing intelligence (median costs, discount patterns, renewal rates)

The protocol is bidirectional. You contribute query data and receive response data. The exchange is cryptographically verified in both directions.

---

## Contribution Types

### Vendor Evaluations

Structured assessments of security tools across five dimensions:

| Dimension | Fields |
|-----------|--------|
| Detection | detection_rate, time_to_detect, coverage_breadth, missed_techniques |
| Price | cost_per_seat, contract_value, discount_percentage, billing_model |
| Support | sla_response_hours, escalation_quality, resolution_satisfaction |
| Performance | false_positive_rate, resource_overhead, deployment_time |
| Decision | overall_score, would_buy_again, renewal_intent, competitive_displacement |

Each field is either numeric (scores, rates, dollar amounts), boolean (would_buy_again), or categorical (top_strength, billing_model).

### Attack Maps

Observations of attack techniques in the wild:

- MITRE ATT&CK technique IDs observed
- Detection tool effectiveness per technique (detected/missed/partial)
- Remediation category (containment, eradication, recovery)
- Time-to-detect and time-to-contain buckets

### IOC Bundles

Collections of indicators of compromise:

- HMAC-SHA256 hashed indicator values (IPs, domains, file hashes)
- Indicator type classification
- Confidence level
- Associated MITRE technique IDs
- First-seen and last-seen date ranges

---

## Anonymization Pipeline

Every contribution passes through a six-stage pipeline before transmission. All stages run client-side.

```
COLLECT -> SCRUB -> TRANSLATE -> COMMIT -> AGGREGATE -> DISCARD
```

### Stage 1: COLLECT

Load raw security data from incident reports, vendor evaluation notes, or IOC feeds. Data remains in its original form on the contributor's machine.

### Stage 2: SCRUB

Remove personally identifiable information:
- Names matched by regex patterns and removed
- IP addresses hashed with HMAC-SHA256 (keyed, irreversible)
- Hostnames, employee names, network topology stripped entirely
- URLs, email addresses, phone numbers removed
- Organization identity replaced with industry bucket

### Stage 3: TRANSLATE

Convert scrubbed data to protocol-compatible structured form:
- Free text dropped entirely
- Sigma rules and detection rule content dropped
- Remediation narratives replaced with categorical labels
- Numeric values retained (scores, rates, dollar amounts)
- Boolean flags retained
- MITRE ATT&CK technique IDs retained

### Stage 4: COMMIT

The client computes SHA-256 of the canonical JSON payload (the dice chain anchor). The payload is then transmitted to the server. The server creates a Pedersen commitment over the values -- information-theoretically hiding, meaning the commitment reveals nothing about the original values even to an adversary with unlimited computational power.

### Stage 5: AGGREGATE

The server updates running sums, histogram bins, and frequency counters. The aggregate incorporates the new contribution.

### Stage 6: DISCARD

The server deletes the individual contribution values. Only the commitment hash, the aggregate update, and the Merkle leaf remain. Individual scores, per-org details, and raw inputs are permanently gone.

---

## Verification

### Dice Chains

The Attested Data Transformation Chain (ADTC) provides end-to-end verification of data integrity.

1. The client computes `local_hash = SHA-256(canonical_json)` before submission.
2. The server independently computes `contribution_hash = SHA-256(received_canonical_json)` upon receipt.
3. The server returns `contribution_hash` in the receipt.
4. The client compares `local_hash` against `contribution_hash`.
5. If they match, the entire pipeline (scrub, translate, transmit, receive) is verified. No data was altered.

Each receipt extends the chain. Over time, a contributor accumulates a sequence of verified links -- a dice chain -- proving the integrity of every contribution they have made.

### Merkle Proofs

Every commitment is appended to a Merkle tree. The server provides inclusion proofs on request: a path from the leaf (your commitment) to the root, verifiable by any party. The tree is append-only -- the server cannot retroactively modify, insert, or delete entries.

### Receipts

Each contribution produces a receipt containing:
- `commitment_hash` -- the Pedersen commitment identifier
- `contribution_hash` -- the dice chain hash for end-to-end verification
- `merkle_proof` -- path from leaf to root
- `server_signature` -- the server's cryptographic signature over the receipt

The receipt is non-repudiable. The server cannot deny having received the contribution.

---

## Trust Model

### Behavioral Differential Privacy (BDP)

The protocol does not blindly trust all contributions equally. BDP assigns credibility scores based on observable behavioral patterns:

- **Consistency** -- Do the contributor's evaluations show reasonable internal consistency?
- **Variance** -- Are scores within plausible ranges given the aggregate?
- **Timing** -- Do contribution patterns suggest organic evaluation or automated manipulation?
- **Convergence** -- Do scores from this contributor converge with independent contributors over time?

High-credibility contributions receive greater weight in aggregates. Low-credibility contributions are down-weighted. The scoring is behavioral -- it does not require identity verification, organizational attestation, or any out-of-band trust establishment.

A data poisoning attacker would need to maintain consistent, plausible-looking contributions across multiple vendors and dimensions over extended periods -- and even then, their influence on aggregates is bounded by the credibility weighting system.

### Trust Scoring

Trust is earned through usage, not claimed through credentials. A new contributor starts with baseline credibility. Credibility increases with:
- Consistent contribution patterns
- Evaluations that align with independent assessments of the same vendor
- Diverse coverage across vendors and dimensions

Credibility decreases with:
- Outlier scores that diverge significantly from the aggregate
- Irregular contribution timing patterns
- Narrow coverage (single vendor, single dimension)

Individual credibility scores are never exposed. Only their effect on aggregate weighting is observable.

---

## Blind Category Discovery

The protocol's taxonomy is not static. New vendors, tools, techniques, and categories emerge constantly. Blind Category Discovery allows the taxonomy to grow organically from practitioner usage.

### Mechanism

1. A contributor encounters a category not in the taxonomy.
2. The client computes `H = SHA-256(category_name:random_salt)`.
3. The client sends `H` to the server. The server stores the opaque hash.
4. Other contributors independently compute the same `H` for the same category (different salts produce different hashes -- the system uses a deterministic naming convention so that the same category produces the same base name).
5. When `>= 3` distinct organizations have proposed the same hash, the threshold is met.
6. A proposer reveals the plaintext name and salt. The server verifies `SHA-256(name:salt) == H`.
7. The category is added to the public taxonomy.

### Properties

- No single contributor reveals what tools they use until peers independently validate the same category.
- The server cannot determine what was proposed until the reveal phase.
- Categories that only one organization uses never enter the taxonomy -- maintaining k-anonymity.
- The threshold prevents vendor self-promotion (a vendor cannot unilaterally add themselves).

---

## Integration Points

| Interface | Status | Description |
|-----------|--------|-------------|
| CLI | Available | `nur eval`, `nur market`, `nur report` -- full contribution and query |
| Web form | Available | Browser-based contribution for non-technical users |
| REST API | Available | Programmatic access for Pro and Enterprise tiers |
| Voice | In development | Voice-to-eval with automatic structuring |
| Browser extension | In development | Automated vendor evaluation capture from existing tools |
| STIX/TAXII export | Enterprise | Standard threat intelligence format export |

---

## Protocol Versioning

The protocol uses semantic versioning. The current version is **1.0**.

Breaking changes (field removals, commitment scheme changes, Merkle tree restructuring) increment the major version. Additive changes (new contribution types, new evaluation dimensions, new query endpoints) increment the minor version.

All receipts include the protocol version. Verification logic is version-aware -- a v1.0 receipt can always be verified by a v1.x client.
