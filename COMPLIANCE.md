# nur — Compliance & Legal Analysis

**For: General Counsel, CISO, Compliance Officers**
**Purpose: Demonstrate that using nur does not create regulatory reporting obligations or liability exposure**

---

## Executive Summary

nur is a social network for security intelligence — a trustless aggregation protocol where organizations contribute security data (tool evaluations, attack technique observations, IOC hashes) and receive back aggregate intelligence from the collective. The protocol IS the product: query data (threat models, IOCs, stacks) flows in, response data (tool intel, remediation, pricing) flows back. Math, not promises.

**The key legal fact:** What leaves your organization when you use nur is *not* an incident report, *not* a breach notification, and *not* a material cybersecurity disclosure. It is structured threat intelligence — numeric scores, categorical labels, and cryptographic hashes — which is explicitly protected under federal information sharing safe harbor laws.

---

## What Data Leaves Your Organization

nur's client-side translators run **on your machine** and convert raw security data into structured, aggregatable form before anything is transmitted. Here is exactly what crosses your network boundary:

| Data sent to nur | Example | Is this PII? | Is this an incident report? |
|-----------------|---------|-------------|---------------------------|
| Numeric scores | `overall_score: 9.2` | No | No |
| Detection rates | `detection_rate: 94.5` | No | No |
| Boolean flags | `would_buy: true` | No | No |
| Categorical labels | `top_strength: "detection_quality"` | No | No |
| MITRE technique IDs | `T1566, T1490` | No | No |
| Hashed IOC values | `SHA-256(ip_address)` | No — irreversible hash | No |
| Remediation categories | `containment: stopped_attack` | No | No |

### What is explicitly stripped before transmission

| Data type | Example | Removed by |
|-----------|---------|-----------|
| Free-text notes | "We found malware on server DC-PROD-03" | `translate_eval()` |
| IP addresses | `10.0.5.42` | Hashed to SHA-256 |
| Hostnames | `dc-prod-03.acme.internal` | Not transmitted |
| Employee names | "John Smith, SOC Analyst" | Not transmitted |
| Sigma rules | YAML detection rule content | `translate_attack_map()` |
| Remediation action text | "Isolated hosts in VLAN 42" | `translate_attack_map()` |
| Organization identity | "Acme Energy Corp" | Pseudonymized |
| Network topology | Subnet layouts, firewall rules | Not transmitted |

### Server-side guarantees

The nur server operates as an "accountable compute node" with the following cryptographic properties:

1. **Individual values are discarded** — only commitment hashes and running aggregate sums are retained
2. **No per-organization attribution** — the server cannot determine which organization contributed which data point
3. **Merkle tree binding** — every contribution is cryptographically committed; the server cannot alter, add, or remove contributions
4. **Aggregate-only responses** — all query responses come from histogram aggregates and template logic, never individual contributions
5. **Dice chain verification** — the client independently hashes the translated payload before submission; the server's receipt contains its own hash of what it received. If they match, the entire transformation chain is verified end-to-end. No data was altered in transit.
6. **BDP anti-poisoning defense** — Behavioral Differential Privacy uses credibility scoring (consistency, variance, timing) to weight contributions. Poisoned data from malicious contributors is automatically down-weighted without revealing individual scores.

---

## Federal Regulatory Framework Analysis

### 1. CIRCIA (Cyber Incident Reporting for Critical Infrastructure Act)

**Requirement:** Report "covered cyber incidents" to CISA within 72 hours. Report ransomware payments within 24 hours. Final rule expected May 2026.

**Analysis:** CIRCIA requires reporting of *cyber incidents* — events that actually or potentially jeopardize information systems or the information they process. What nur receives (numeric scores, categorical labels, hashed IOCs) does not constitute a "covered cyber incident" under CIRCIA's proposed definition. Contributing to nur is threat intelligence sharing, not incident reporting.

**Conclusion:** Using nur does **not** satisfy, replace, or conflict with CIRCIA reporting obligations. Your CIRCIA reporting requirements to CISA remain unchanged.

### 2. NERC CIP-008-6 (Electricity Sector)

**Requirement:** Report Cyber Security Incidents to E-ISAC and ICS-CERT, including functional impact, attack vector, and level of intrusion. Penalties up to $1.29M per violation per day.

**Analysis:** NERC CIP-008-6 requires reporting of incidents that "compromise or attempt to compromise" an Electronic Security Perimeter (ESP) or associated Electronic Access Control and Monitoring Systems (EACMS). The data nur receives does not include: functional impact on BES reliability, specific attack vectors against named systems, or intrusion levels achieved against identified infrastructure.

**Timing consideration:** If your organization is experiencing an active incident, your NERC CIP-008 reporting timeline to E-ISAC takes priority. Contributing aggregate data to nur during an active incident does not fulfill or delay your E-ISAC obligation — they are separate activities.

**Conclusion:** Using nur does **not** satisfy, replace, or conflict with NERC CIP-008-6 obligations.

### 3. SEC Cybersecurity Disclosure (Form 8-K Item 1.05)

**Requirement:** Public companies must disclose material cybersecurity incidents within 4 business days of determining materiality.

**Analysis:** SEC disclosure requires assessment of material impact on the registrant's financial condition and operations. The structured data nur receives (vendor evaluation scores, technique observation frequencies, hashed IOC values) does not constitute disclosure of a material cybersecurity incident. The data is anonymized, aggregated, and contains no information about specific impact to any registrant's business operations.

**Conclusion:** Contributing to nur does **not** constitute an SEC cybersecurity disclosure and does **not** trigger Form 8-K filing requirements.

### 4. State Breach Notification Laws

**Analysis:** State breach notification laws (all 50 states) require notification when personally identifiable information (PII) is compromised. nur does not receive, store, or process PII. Hashed IOC values are irreversible one-way hashes. No individual's personal information is involved at any point in the nur data flow.

**Conclusion:** nur has **no intersection** with state breach notification requirements.

---

## Federal Safe Harbor: CISA 2015

The **Cybersecurity Information Sharing Act of 2015** (extended through September 2026) provides explicit liability protection for organizations that share cyber threat indicators and defensive measures with third parties.

### Protections that apply to nur usage:

| Protection | How it applies to nur |
|-----------|----------------------|
| **No civil liability** for sharing cyber threat indicators | Sharing hashed IOCs, technique observations, and detection scores with nur is protected |
| **No antitrust liability** | Multiple organizations contributing evaluations of the same vendor is not collusion |
| **FOIA exemption** | Data shared through nur is exempt from Freedom of Information Act requests |
| **Regulatory enforcement shield** | Shared data cannot be used as the sole basis for regulatory action against the sharing entity |
| **Evidentiary and discovery bar** | Reports submitted under CISA 2015 protections face limitations on use in civil litigation |

### Requirements for safe harbor applicability:

1. **Personally identifiable information must be removed** before sharing — nur's client-side translators enforce this technically (PII is never transmitted)
2. **Sharing must be for a "cybersecurity purpose"** — nur's purpose (collective threat intelligence, vendor evaluation aggregation, detection gap analysis) qualifies
3. **Reasonable measures to scrub PII** — nur's HMAC-SHA256 hashing, field stripping, and structured-only translation are technically verifiable reasonable measures

---

## De-identification Standards

> "Genuinely unsettled territory... if there's anything that's like regulatory in terms of how to actually make something not personally identifiable, that's very interesting — that basically gives legal standing to some of my code."

nur's anonymization engine was designed for cybersecurity data, but the de-identification controls map directly to healthcare and privacy regulation standards. This section documents that mapping.

### HIPAA Safe Harbor (45 CFR §164.514(b))

HIPAA's Safe Harbor method requires removal of 18 specific identifier types. The following table maps each identifier to nur's technical controls:

| # | Identifier | CFR Reference | nur Handling | Code Reference | Status |
|---|-----------|---------------|-------------|---------------|--------|
| 1 | Names | §164.514(b)(2)(i)(A) | `strip_pii()` removes titled names; `bucket_context_dict()` strips org_name | `anonymize._TITLE_NAME` regex | **Removed** |
| 2 | Geographic data (sub-state) | §164.514(b)(2)(i)(B) | Not collected — nur does not ingest sub-state geographic data | No geographic fields in data model | **N/A** |
| 3 | Dates (except year) | §164.514(b)(2)(i)(C) | `strip_timing` in maximum privacy mode removes timestamps | `privacy.PRIVACY_LEVELS['maximum']` | **Removed** |
| 4 | Phone numbers | §164.514(b)(2)(i)(D) | `strip_pii()` removes via regex | `anonymize._PHONE` regex | **Removed** |
| 5 | Fax numbers | §164.514(b)(2)(i)(E) | `strip_pii()` — same phone regex covers fax patterns | `anonymize._PHONE` regex | **Removed** |
| 6 | Email addresses | §164.514(b)(2)(i)(F) | `strip_pii()` removes via regex | `anonymize._EMAIL` regex | **Removed** |
| 7 | SSN | §164.514(b)(2)(i)(G) | `strip_safe_harbor()` removes SSN patterns | `deidentify._SSN` regex | **Removed** |
| 8 | Medical record numbers | §164.514(b)(2)(i)(H) | `strip_safe_harbor()` removes MRN patterns | `deidentify._MEDICAL_RECORD` regex | **Removed** |
| 9 | Health plan beneficiary numbers | §164.514(b)(2)(i)(I) | `strip_safe_harbor()` removes beneficiary ID patterns | `deidentify._HEALTH_PLAN` regex | **Removed** |
| 10 | Account numbers | §164.514(b)(2)(i)(J) | `strip_safe_harbor()` removes account numbers with context | `deidentify._ACCOUNT_NUM` regex | **Removed** |
| 11 | Certificate/license numbers | §164.514(b)(2)(i)(K) | `strip_security()` removes certificate serials | `anonymize._CERT_SERIAL` regex | **Removed** |
| 12 | Vehicle identifiers | §164.514(b)(2)(i)(L) | `strip_safe_harbor()` removes VIN patterns | `deidentify._VIN` regex | **Removed** |
| 13 | Device identifiers | §164.514(b)(2)(i)(M) | `strip_safe_harbor()` removes device serial/UDI patterns | `deidentify._DEVICE_SERIAL` regex | **Removed** |
| 14 | Web URLs | §164.514(b)(2)(i)(N) | `strip_pii()` removes URLs via regex | `anonymize._URL` regex | **Removed** |
| 15 | IP addresses | §164.514(b)(2)(i)(O) | `strip_security()` removes IPv4/IPv6; IOC IPs are HMAC-hashed | `anonymize._IPV4`, `_IPV6` regexes | **Removed** |
| 16 | Biometric identifiers | §164.514(b)(2)(i)(P) | Not collected — nur is text-only, no biometric data | No biometric fields in data model | **N/A** |
| 17 | Full-face photographs | §164.514(b)(2)(i)(Q) | Not collected — nur is text-only, no image data | No image fields in data model | **N/A** |
| 18 | Other unique identifying numbers | §164.514(b)(2)(i)(R) | `strip_security()` removes AWS account IDs, API keys | `anonymize._API_KEY`, `_AWS_ACCOUNT` regexes | **Removed** |

**Why nur's data flow clears Safe Harbor:** The data transmitted to nur consists of numeric scores, categorical labels, boolean flags, MITRE ATT&CK technique IDs, and HMAC-SHA256 hashed IOC values. None of these are PHI identifiers under any of the 18 Safe Harbor categories. The anonymization pipeline runs client-side before any data crosses the network boundary — the server never receives raw PII.

**Programmatic verification:** The `nur.deidentify` module provides `verify_safe_harbor()` — a function that scans any contribution dict for residual PII patterns and returns a structured compliance result mapping each of the 18 identifiers to its pass/fail status. This enables automated compliance verification as part of the contribution pipeline.

### HIPAA Expert Determination (45 CFR §164.514(a))

The Expert Determination method is an alternative path to de-identification that requires a qualified statistical or scientific expert to certify that the risk of re-identification is "very small." This is a higher bar than Safe Harbor but provides stronger legal protection.

nur's architecture makes a strong case for Expert Determination:

- **Individual values are discarded** — the server retains only Pedersen commitment hashes and running aggregate sums, not per-contributor data
- **Aggregate-only responses** — all query results come from histogram aggregation and template logic, never individual contributions
- **Pedersen commitments** — contributions are cryptographically committed with information-theoretically hiding properties; the server cannot extract individual values from commitments
- **Behavioral Differential Privacy (BDP)** — contributions are weighted by credibility scoring, making it impossible to determine any single contributor's exact input from the aggregate output
- **No join path** — billing identity and contribution data are architecturally separated with no database join between them

**Action item:** Obtaining formal Expert Determination certification from a qualified expert (per 45 CFR §164.514(a)(1)) is a future milestone. The technical architecture supports it; the remaining step is engaging a HIPAA-qualified statistician to formally certify the re-identification risk as "very small."

### GDPR Recital 26 — Re-identification Risk

GDPR Recital 26 provides that data protection principles do not apply to anonymous information — "information which does not relate to an identified or identifiable natural person or to personal data rendered anonymous in such a manner that the data subject is not or no longer identifiable." The standard is whether identification is **"reasonably likely"** considering "all the means reasonably likely to be used" by the controller or another person.

nur's technical controls address each re-identification vector:

| Re-identification Vector | nur Mitigation | Assessment |
|------------------------|----------------|------------|
| **Direct identification** (names, org identifiers) | `strip_pii()` removes names; `bucket_context_dict()` replaces org names with industry buckets | Impossible — no names or org identifiers in transmitted data |
| **Indirect identification via linkage** (combining quasi-identifiers) | Industry, org_size, and role_tier are coarse categorical buckets with k-anonymity guarantees | Mitigated — bucketing ensures each combination maps to many organizations |
| **Timing correlation** (linking contribution timing to known events) | `strip_timing` in maximum mode removes timestamps; submission times not linked to events | Mitigated — no temporal fingerprinting possible |
| **Contribution pattern analysis** (reconstructing individual inputs from outputs) | BDP credibility weighting; Pedersen commitments; individual values discarded; aggregate-only responses | Mitigated — mathematically infeasible to reconstruct individual contributions |

**On vendor self-certification:** A valid criticism of de-identification claims is: "Who's certifying impossible? The vendor." nur addresses this directly — the anonymization engine is **open source**. The certification is not a vendor assertion; it is verifiable code that any party can audit, test, and validate independently. The `verify_safe_harbor()` and `verify_gdpr_recital26()` functions in `nur.deidentify` provide programmatic proof that can be run by compliance teams, auditors, or regulators against any contribution payload.

The `nur.deidentify` module provides `verify_gdpr_recital26()` — a function that returns a structured assessment of re-identification risk across all four vectors, suitable for inclusion in Data Protection Impact Assessments (DPIAs).

---

## Enterprise Data Sharing Playbook

This section addresses the two most common enterprise scenarios where legal friction blocks intelligence sharing — and how nur resolves each.

### Scenario 1: IR Firms Working with Law Firms

**The privilege problem.** When a company experiences a breach, its outside counsel typically retains an incident response firm under a separate engagement letter. This structure exists to preserve attorney-client privilege: the IR firm's forensic report is classified as attorney work product — privileged communication prepared "in anticipation of litigation" ([Morrison Foerster, "Six Considerations to Preserve Privilege"](https://www.mofo.com/resources/insights/231010-six-considerations-to-preserve-privilege)).

The consequence is severe: sharing forensic findings broadly — even sanitized summaries — risks waiving privilege over the entire engagement ([American Bar Association, "Attorney-Client Privilege and Work Product Considerations Following Cyber Incidents"](https://www.americanbar.org/groups/tort_trial_insurance_practice/resources/tortsource/2024-spring/attorney-client-privilege-work-product-considerations-following-cyber-incidents/)). This is why IR firms currently **cannot** share learnings across engagements, even when the same threat actor hits multiple clients. The legal rules governing confidentiality actively undermine collective defense ([Lawfare, "Do the Legal Rules Governing the Confidentiality of Cyber Incident Response Undermine Cybersecurity?"](https://www.lawfaremedia.org/article/do-legal-rules-governing-confidentiality-cyber-incident-response-undermine-cybersecurity)).

**What can vs. cannot be shared under privilege:**

| Can share (privilege-safe) | Cannot share (privilege risk) |
|---|---|
| IOC hashes (IP addresses, file hashes, domains) | Forensic report conclusions |
| MITRE technique IDs observed | Which systems were compromised |
| Vendor tools that detected/missed the attack | Timeline of the breach |
| Generic remediation categories ("isolated hosts") | Specific remediation actions taken |
| Detection rates / time-to-detect buckets | Client identity, scope of damage |

**Why nur preserves privilege:**

1. **No client-identifying information leaves.** The nur protocol transmits numeric scores, categorical labels, and hashed IOC values — none of which identify the client or the engagement.
2. **No forensic report content is shared.** nur's client-side translators strip free-text notes, remediation narratives, and incident timelines before transmission. What crosses the network boundary is structured threat intelligence, not incident details.
3. **What's shared is threat intelligence, not incident details.** IOC hashes, MITRE technique IDs, and detection rate buckets are the same categories of information that CISA, E-ISAC, and sector ISACs already encourage sharing.
4. **CISA 2015 explicitly protects this sharing** with both liability safe harbor and non-waiver of privilege. The statute provides that sharing cyber threat indicators "shall not constitute a waiver of any applicable privilege or protection provided by law."
5. **`verify_safe_harbor()` provides programmatic proof** that nothing privileged was transmitted. The function scans the contribution payload against all 18 HIPAA Safe Harbor identifiers and returns a structured pass/fail result — auditable evidence that the data leaving the organization contains no privileged material.

**The value proposition for IR firms:** An IR firm can contribute intelligence from every engagement — building credibility and reputation on the platform — without ever risking privilege waiver. The law firm retains full control over the forensic report and engagement details. What flows to nur is the collective intelligence that makes the entire security community stronger: which techniques were observed, which tools caught them, and what remediation categories proved effective.

### Scenario 2: In-House Security Teams Sharing Externally

In-house security teams face a different but equally complex set of legal requirements before sharing any security data externally.

**Legal and organizational requirements:**

1. **In-house privilege is weaker.** Several jurisdictions — including France, Austria, Italy, and Sweden — do not recognize communications with in-house attorneys as privileged. Even in the United States, the scope of in-house privilege is narrower than outside counsel privilege and subject to closer scrutiny.
2. **Board/executive/CISO approval is required.** NIST SP 800-150 ("Guide to Cyber Threat Information Sharing") recommends that organizations establish formal policies governing what threat information can be shared, with whom, and under what conditions — including executive-level approval for external sharing ([NIST SP 800-150](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-150.pdf)).
3. **Vendor NDA restrictions.** Many security vendor agreements restrict sharing of evaluation data, test results, or product performance metrics. Sharing detailed benchmark results externally may violate these agreements.
4. **Data classification requirements.** The Traffic Light Protocol (TLP) — RED, AMBER, GREEN, CLEAR — governs how shared threat intelligence can be redistributed. Organizations must classify data before sharing and ensure recipients respect those classifications ([UK Government, "Cyber Threat Intelligence Information Sharing Guide"](https://www.gov.uk/government/publications/cyber-threat-intelligence-information-sharing/cyber-threat-intelligence-information-sharing-guide)).
5. **STIX/TAXII standardization expectations.** Enterprise consumers of threat intelligence increasingly expect data in standard formats (STIX for structure, TAXII for transport) to integrate with their existing security infrastructure.

**How nur addresses each requirement:**

| Requirement | How nur addresses it |
|---|---|
| Legal review of data leaving the org | Client-side translation runs locally — review what's transmitted before it goes |
| PII scrubbing verification | `verify_safe_harbor()` provides programmatic proof of de-identification |
| No client/customer data exposure | nur doesn't collect customer data — only security operational data |
| Vendor NDA compliance | nur transmits scores and categories, not product internals or test methodologies |
| Board/CISO awareness | nur contribution is auditable — cryptographic receipts prove exactly what was shared |
| STIX/TAXII standardization | nur's data model maps to standard threat intel formats |
| CISA 2015 safe harbor | nur usage qualifies — sharing for "cybersecurity purpose" with PII removed |

### Summary

In both scenarios, nur's architecture resolves the fundamental tension: organizations want to share intelligence but can't because sharing risks legal exposure. nur eliminates this tension by construction — the data that crosses the network boundary is, by regulatory definition, not personally identifiable (HIPAA Safe Harbor), not privileged material (no forensic report content), and explicitly protected (CISA 2015 safe harbor). The `verify_safe_harbor()` function provides programmatic proof that compliance teams can present to legal counsel, auditors, or regulators.

---

## Data Flow Certification

The following diagram shows exactly what crosses organizational boundaries:

```
YOUR ORGANIZATION                    nur SERVER
────────────────                     ──────────

Raw incident data
├─ IP addresses        ──STRIPPED──  Never received
├─ hostnames           ──STRIPPED──  Never received
├─ employee names      ──STRIPPED──  Never received
├─ free-text notes     ──STRIPPED──  Never received
├─ sigma rules         ──STRIPPED──  Never received
├─ remediation text    ──STRIPPED──  Never received
│
├─ IOC values          ──HASHED───▶ SHA-256 hash only (irreversible)
├─ vendor scores       ──────────▶  Numeric value (e.g., 9.2)
├─ detection rates     ──────────▶  Numeric value (e.g., 94.5%)
├─ boolean flags       ──────────▶  true/false
├─ technique IDs       ──────────▶  MITRE ATT&CK ID (e.g., T1566)
└─ categories          ──────────▶  Predefined label (e.g., "containment")

                                    Server processes:
                                    ├─ Commits (Pedersen hash)
                                    ├─ Adds to Merkle tree
                                    ├─ Updates running sums
                                    ├─ DISCARDS individual values
                                    └─ Returns cryptographic receipt

RECEIPT returned:
├─ Commitment hash (SHA-256)        Proves your data was included
├─ Merkle inclusion proof           Proves it's in the tree
└─ Server signature                 Server can't deny receiving it
```

---

## Billing & Identity Separation

nur architecturally separates billing from data contribution:

- **Billing system** knows: organization email, payment method, tier
- **nur server** knows: pseudonymous org ID, contribution data, tier access level
- **No join path** exists between billing identity and contribution data in code or database
- A legal request to nur's data systems produces: commitment hashes, aggregate sums, and Merkle trees — none of which are linked to billing identity

---

## Frequently Asked Questions

**Q: Does contributing to nur delay or replace our mandatory incident reporting?**
A: No. nur is threat intelligence sharing, not incident reporting. Your obligations to CISA (CIRCIA), E-ISAC (NERC CIP), SEC (Form 8-K), and state regulators are completely separate and unaffected by nur usage.

**Q: Could nur be subpoenaed for our data?**
A: nur can be subpoenaed, but what the server holds is: commitment hashes (opaque SHA-256 strings), running aggregate sums, and a Merkle tree. There are no individual contribution records, no organization identifiers, and no raw security data. The trustless architecture means there is nothing to produce that identifies any specific organization's contribution.

**Q: Does sharing detection scores with nur violate our NDA with our security vendor?**
A: This depends on your specific vendor agreement. However, sharing an aggregate numeric score (e.g., "9.2 out of 10") and a categorical evaluation (e.g., "detection_quality") is typically not covered by vendor NDAs, which usually restrict sharing of specific technical findings, test methodologies, or product internals. Consult your vendor agreement for specifics.

**Q: What if we're in the middle of an active incident?**
A: Focus on incident response and mandatory reporting first. nur is designed for after-action contribution and peacetime evaluation sharing. There is no time sensitivity requirement — contribute when you're ready.

**Q: Is nur a "security vendor" that requires procurement review?**
A: nur receives only anonymized, structured data — no access to your systems, no credentials, no network access, no agents installed. The community tier is free and requires no procurement. Pro/Enterprise tiers involve a standard SaaS subscription.

**Q: What happens if CISA 2015 safe harbor expires (September 2026)?**
A: Even without CISA 2015 protections, nur's architecture means what you share is technically not "your data" in any identifiable sense — it's anonymized aggregate contributions. However, we actively monitor reauthorization and will notify users of any changes to the legal landscape.

---

## Regulatory Contact Points

For your mandatory reporting obligations (unrelated to nur):

| Framework | Report to | Timeline |
|-----------|----------|----------|
| CIRCIA | CISA (cisa.gov/report) | 72 hours (incidents), 24 hours (ransomware payments) |
| NERC CIP-008-6 | E-ISAC + ICS-CERT | Per your entity's incident response plan |
| SEC Form 8-K | SEC EDGAR | 4 business days after materiality determination |
| State breach notification | State AG office | Varies by state (typically 30-60 days) |

---

*This document is provided for informational purposes and does not constitute legal advice. Organizations should consult their own legal counsel regarding their specific regulatory obligations. Last updated: March 2026.*
