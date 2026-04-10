# Compliance and Legal Analysis

**For: General Counsel, CISO, Compliance Officers**

---

## Executive Summary

nur is a trustless aggregation protocol where organizations contribute security data (tool evaluations, attack technique observations, IOC hashes) and receive back aggregate intelligence from the collective.

**What leaves your organization:** Numeric scores, categorical labels, boolean flags, MITRE ATT&CK technique IDs, and HMAC-SHA256 hashed IOC values. That is all. Names, IPs, hostnames, free text, and organizational identity are stripped client-side before any data crosses the network boundary.

**What does NOT leave your organization:** Incident reports, breach notifications, material cybersecurity disclosures, personally identifiable information, or forensic report content.

The code is open source. The compliance is verifiable by anyone.

---

## What Data Leaves Your Organization

| Data sent to nur | Example | PII? | Incident report? |
|-----------------|---------|------|------------------|
| Numeric scores | `overall_score: 9.2` | No | No |
| Detection rates | `detection_rate: 94.5` | No | No |
| Boolean flags | `would_buy: true` | No | No |
| Categorical labels | `top_strength: "detection_quality"` | No | No |
| MITRE technique IDs | `T1566, T1490` | No | No |
| Hashed IOC values | `SHA-256(ip_address)` | No (irreversible hash) | No |
| Remediation categories | `containment: stopped_attack` | No | No |

### What Is Stripped Before Transmission

| Data type | Example | Handling |
|-----------|---------|----------|
| Free-text notes | "We found malware on server DC-PROD-03" | Dropped by translator |
| IP addresses | `10.0.5.42` | Hashed to SHA-256 |
| Hostnames | `dc-prod-03.acme.internal` | Not transmitted |
| Employee names | "John Smith, SOC Analyst" | Not transmitted |
| Sigma rules | YAML detection rule content | Dropped by translator |
| Remediation action text | "Isolated hosts in VLAN 42" | Dropped by translator |
| Organization identity | "Acme Energy Corp" | Pseudonymized to industry bucket |
| Network topology | Subnet layouts, firewall rules | Not transmitted |

---

## HIPAA Safe Harbor (45 CFR 164.514(b))

HIPAA's Safe Harbor method requires removal of 18 specific identifier types before data qualifies as de-identified. nur's anonymization pipeline addresses all 18:

- **Names, phone, fax, email** -- stripped by PII removal regex patterns
- **Geographic data below state level** -- not collected
- **Dates except year** -- removed in maximum privacy mode
- **SSN, medical records, health plan IDs, account numbers** -- stripped by dedicated patterns
- **Certificate/license numbers** -- stripped
- **Vehicle identifiers, device identifiers** -- stripped
- **Web URLs, IP addresses** -- stripped or hashed (IOC IPs are HMAC-SHA256)
- **Biometric identifiers, photographs** -- not collected (nur is structured data only)
- **Other unique identifiers** -- API keys, AWS account IDs stripped

The data transmitted to nur consists of numeric scores, categorical labels, boolean flags, MITRE ATT&CK technique IDs, and HMAC-SHA256 hashed IOC values. None of these are identifiers under any of the 18 Safe Harbor categories.

Programmatic verification: the `verify_safe_harbor()` function scans any contribution for residual PII patterns and returns a structured compliance result for each of the 18 identifiers.

---

## GDPR Recital 26 -- Re-identification Risk

GDPR Recital 26 provides that data protection principles do not apply to anonymous information -- data where the subject "is not or no longer identifiable." The standard is whether identification is "reasonably likely" considering all means reasonably likely to be used.

| Re-identification Vector | Mitigation | Assessment |
|------------------------|------------|------------|
| Direct identification | PII stripped; org names replaced with industry buckets | Not possible |
| Indirect identification via linkage | Coarse categorical buckets with k-anonymity guarantees | Mitigated |
| Timing correlation | Timestamps removed in maximum privacy mode | Mitigated |
| Contribution pattern analysis | BDP credibility weighting; Pedersen commitments; individual values discarded | Mathematically infeasible |

The anonymization engine is open source. The certification is not a vendor assertion -- it is verifiable code.

---

## CISA 2015 Safe Harbor

The Cybersecurity Information Sharing Act of 2015 provides explicit liability protection for organizations that share cyber threat indicators and defensive measures.

| Protection | Applicability to nur |
|-----------|---------------------|
| No civil liability | Sharing hashed IOCs, technique observations, and scores is protected |
| No antitrust liability | Multiple orgs contributing evaluations of the same vendor is not collusion |
| FOIA exemption | Data shared through nur is exempt from FOIA requests |
| Regulatory enforcement shield | Shared data cannot be sole basis for regulatory action |
| Privilege non-waiver | Sharing under CISA 2015 does not waive attorney-client privilege |

**Requirements for safe harbor:** (1) PII must be removed before sharing -- nur's client-side translators enforce this technically, (2) sharing must be for a "cybersecurity purpose" -- collective threat intelligence qualifies, (3) reasonable measures to scrub PII -- HMAC-SHA256 hashing and structured-only translation are technically verifiable.

---

## Federal Reporting Obligations

Using nur does **not** satisfy, replace, or conflict with mandatory reporting requirements. Your obligations remain unchanged:

| Framework | Report to | Timeline |
|-----------|----------|----------|
| CIRCIA | CISA | 72 hours (incidents), 24 hours (ransomware payments) |
| NERC CIP-008-6 | E-ISAC + ICS-CERT | Per entity incident response plan |
| SEC Form 8-K | SEC EDGAR | 4 business days after materiality determination |
| State breach notification | State AG office | Varies by state (typically 30-60 days) |

nur is threat intelligence sharing, not incident reporting. These are separate activities.

---

## Server-Side Guarantees

1. **Individual values are discarded** -- only commitment hashes and running aggregate sums are retained
2. **No per-organization attribution** -- the server cannot determine which organization contributed which data point
3. **Merkle tree binding** -- every contribution is cryptographically committed; the server cannot alter, add, or remove contributions
4. **Aggregate-only responses** -- all query responses come from histogram aggregates, never individual contributions
5. **Dice chain verification** -- client and server independently hash the payload; matching hashes verify the entire transformation chain
6. **Billing and data separation** -- no database join path exists between billing identity and contribution data

---

*This document is provided for informational purposes and does not constitute legal advice. Organizations should consult their own legal counsel regarding their specific regulatory obligations.*
