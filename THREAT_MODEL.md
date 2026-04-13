# nur Threat Model

## What We're Protecting

A social network for security intelligence. Product = protocol + users. Organizations contribute threat intelligence (vendor evaluations, attack maps, IOC lists) through a trustless aggregation protocol. The privacy goal: **learn collective insights without exposing any single organization's data**. Give one eval, get forty back. The integration shares. The human gets remediation back. Math, not promises.

Contributions arrive via three channels:
- **CLI** — `nur report`, `nur eval`, `nur upload` (full privacy pipeline)
- **Web form** — `/contribute` page (rate your tool in 60 seconds, no CLI needed)
- **Voice recording** — `/contribute/voice` (speak your eval, stored for processing)

Sensitive data at risk:
- **Network topology** — internal IPs, hostnames, MAC addresses
- **Identity** — analyst names, emails, org name
- **Security posture** — which tools they use, what they miss, detection gaps
- **Operational details** — when incidents happened, how long response took
- **Raw IOCs** — specific indicators from their environment

---

## Threat Actors

| Actor | Goal | Capability |
|-------|------|-----------|
| **Curious Server** | Learn individual org's data from submissions | Sees all anonymized data, can correlate |
| **External Attacker** | Breach server, steal contribution database | Full DB access after compromise |
| **Malicious Contributor** | Poison aggregates with fake data | Submits crafted contributions |
| **Data Poisoner** | Systematically skew aggregates to manipulate vendor scores or remediation guidance | Multiple accounts, crafted submissions designed to bypass range checks |
| **Network Observer** | Intercept data in transit | Passive eavesdropping, traffic analysis |
| **Insider at Org** | Prove what another org contributed | Access to platform + some org knowledge |
| **Colluding Parties** | Combine knowledge to de-anonymize | Multiple orgs share what they know |
| **Spam Account** | Flood platform with low-quality or fake registrations | Automated registration, disposable emails |

---

## Attack → Defense Mapping

### Attack 1: Raw PII in submitted data
**Threat**: Server sees "Contact john.doe@hospital.com about the 192.168.1.1 incident on server db01.corp.internal"

**Defense**: `anonymize.py` — 4-pass regex scrubbing
- Pass 1: emails → `[EMAIL]`, phones → `[PHONE]`, URLs → `[URL]`, names → `[NAME]`
- Pass 2: IPs → `[IP_ADDR]`, MACs → `[MAC_ADDR]`, hostnames → `[INTERNAL_HOST]`, API keys → `[API_KEY]`

**Residual risk**: Novel PII patterns not covered by regex. Custom identifiers (employee IDs, ticket numbers) may slip through.

**Mitigation**: ADTC VAP (Verifiable Absence Proof) runs the same patterns server-side. Both sides confirm zero matches. But this only catches *known* patterns.

---

### Attack 2: Organization identification from context
**Threat**: "A 5000-person financial company using CrowdStrike EDR with a CISO submitting" narrows to ~50 orgs.

**Defense**: `anonymize.py` — k-anonymity bucketing
- "JP Morgan" → `financial` (industry bucket)
- "5247 employees" → `1000-5000` (size bucket)
- "Chief Information Security Officer" → `ciso` (role bucket)
- Org name stripped entirely

**Residual risk**: Combination of industry + size + role + specific vendor scores could still fingerprint an org. If only one `financial` org with `5000-10000` employees evaluates `Wiz`, that's unique.

**Mitigation needed**: Require minimum k contributors per bucket before releasing aggregates. The server query API returns aggregates, but doesn't enforce minimum counts yet.

---

### Attack 3: IOC rainbow tables
**Threat**: SHA-256("evil.com") is deterministic. An attacker pre-computes hashes for all known domains/IPs and matches against submitted IOC hashes.

**Defense**: `keystore.py` — HMAC-SHA256 with org-local secret
- Each org has a unique 256-bit key at `~/.nur/key`
- `HMAC(org_key, "evil.com")` differs between orgs
- Attacker needs the org's key to build a rainbow table

**Residual risk**: If org key is compromised, all their IOC hashes are reversible. Also, IOC hashes from the same org are still correlatable (same key).

**Mitigation**: Key rotation, key derivation per-session, or PSI for IOC comparison instead of hash submission.

---

### Attack 4: Score inference from aggregates
**Threat**: If only 2 orgs contribute CrowdStrike scores, and one knows their own score (9.0), they can compute the other's score from the average.

**Defense**: `dp.py` — Differential Privacy (Laplace mechanism)
- `noised_score = real_score + Laplace(sensitivity/epsilon)`
- Mathematically bounds information leakage
- Privacy budget tracking prevents over-querying

**Residual risk**: Low epsilon = more noise = less utility. High epsilon = less noise = more leakage. The privacy-utility tradeoff is inherent. Also, DP noise on small contributor counts is extreme.

**What epsilon means**:
- epsilon=1.0: Strong privacy, significant noise (scores shift by ±10 points)
- epsilon=5.0: Moderate privacy, noticeable noise (scores shift by ±2 points)
- epsilon=10.0: Weak privacy, minimal noise (scores shift by ±1 point)

---

### Attack 5: IOC list exposure during comparison
**Threat**: Two orgs want to know if they share IOCs, but don't want to reveal their full lists.

**Defense**: `psi.py` — Private Set Intersection (ECDH 2-round protocol)
- Neither party reveals their IOC list
- They learn ONLY the count (or intersection) of shared IOCs
- Based on ECDH commutativity: `H(x)^(a*b) == H(x)^(b*a)`

**Residual risk**: The cardinality itself leaks information (knowing you share 50 out of 100 IOCs tells you something). Malicious party could submit a targeted set to test specific IOCs.

**Mitigation**: Cardinality-only mode (don't reveal which IOCs match). Rate limiting on PSI queries.

---

### Attack 6: Individual scores visible to coordinator
**Threat**: Aggregation coordinator sees each org's raw scores.

**Defense**: `secagg.py` — Additive secret sharing + Shamir's threshold
- Score split into n random shares summing to original
- Each share goes to a different party
- Coordinator only sees random-looking numbers
- Threshold scheme (k-of-n) handles party dropout

**Residual risk**: If coordinator colludes with n-1 parties, they can reconstruct the remaining party's value. Also, with only 2 parties, each learns the other's value from the aggregate.

**Mitigation**: Minimum 3 parties required. Compose with DP: add noise BEFORE splitting into shares.

---

### Attack 7: Skipped anonymization / tampered data
**Threat**: Contributor claims data was anonymized but actually sent raw PII. Or: contributor tampered with the output after anonymization.

**Defense**: `attest/` — ADTC (Attested Data Transformation Chain)
- HMAC-linked CDI chain: `CDI_n = HMAC(CDI_{n-1}, stage_evidence)`
- Break any step → chain verification fails
- Skip a step → CDI derivation breaks
- **VAP**: Deterministic regex scan proves zero PII patterns in output

**Residual risk**: The attestation proves the *process* ran, but can't prove the *input* was real data (could be fabricated). Also, a malicious client could modify the attestation code itself.

**Mitigation**: ZKP (Phase 6) proves data validity. Code signing / reproducible builds for client integrity.

---

### Attack 8: Data poisoning / fake contributions
**Threat**: Attacker submits fake evaluations to skew aggregates (e.g., giving a competitor a score of 0). The Data Poisoner systematically targets specific vendors or remediation categories.

**Defense: Behavioral Differential Privacy (BDP)**:
- `credibility.py` / `bdp.py` — Every contributor builds a behavioral profile over time
- **Query-Contribution Alignment (QCA)**: A real CrowdStrike practitioner contributes evals AND queries about CrowdStrike AND simulates attacks against their stack. A poisoner just submits fake data. The correlation between what you give and what you consume is nearly impossible to fake without being a real practitioner
- **Credibility scoring**: Consistency, variance, timing patterns, contribution diversity all feed into a credibility weight (0.0-1.0)
- **Weighted aggregation**: Poisoned data from low-credibility contributors is automatically down-weighted without revealing individual scores
- **BDP stats**: `/proof/bdp-stats` exposes credibility distribution for transparency

**Additional defenses**:
- `fl/aggregator.py` — Poisoning detection (z-score, cosine anomaly)
- `fl/aggregator.py` — Byzantine-tolerant aggregation (Krum, trimmed mean, geometric median)
- `zkp/` — Zero-knowledge proofs that scores are in valid ranges
- **Invite system** — New registrations require an invite code from an existing user, creating trust chains. Invited users inherit a small credibility boost from their inviter. Mass account creation is blocked.

**Residual risk**: ZKP proves scores are *in range* (0-10) but can't prove they're *honest*. BDP mitigates this by detecting behavioral anomalies, but a sufficiently patient attacker who mimics real usage patterns over time could build credibility before poisoning.

**Mitigation**: BDP credibility scoring + invite trust chains + min-k enforcement make poisoning attacks expensive and detectable. The behavioral signal (QCA) is the key innovation — it turns platform usage patterns into a trust signal.

---

### Attack 9: Traffic analysis
**Threat**: Network observer sees timing, size, and frequency of submissions to infer what happened (e.g., burst of IOC submissions = active incident).

**Defense**: HTTPS (transport layer). No nur-specific defense currently.

**Mitigation needed**: Padding, batching, or scheduled submissions to mask traffic patterns.

---

### Attack 10: Model parameter leakage in FL
**Threat**: Federated learning model updates can leak training data through gradient inversion attacks.

**Defense**: `fl/client.py` — DP-noised gradient updates
- Add calibrated noise to model parameters before sharing
- Composable with per-round privacy budget

**Residual risk**: Deep model gradients are harder to protect than simple aggregates. Gradient inversion attacks are an active research area.

---

### Attack 11: Spam / Sybil accounts
**Threat**: Attacker creates many fake accounts to overwhelm the platform with low-quality data or to amplify poisoning attacks.

**Defense**: Invite system + work email verification
- New users must either have a valid invite code from an existing user OR register with a verified work email
- Free/disposable email domains (gmail, yahoo, hotmail, etc.) are blocked
- Invite chains are tracked — if an inviter is flagged, their downstream invitees are reviewed
- Each user gets a limited number of invite codes (3-5)

**Residual risk**: A determined attacker with access to multiple work email domains could create several accounts. However, each account starts with low BDP credibility and must build it through legitimate usage patterns.

---

### Attack 12: Aggregate response leaks individual data
**Threat**: Query responses could inadvertently reveal individual contributions if aggregates are computed over too few contributors.

**Defense**: Aggregate-only responses + min-k enforcement
- All query responses (`/verify/aggregate/{vendor}`) come from histogram aggregates and template logic, never individual contributions
- `NUR_MIN_K=3` enforced: no vendor data returned with fewer than 3 contributors
- Individual values are discarded after commitment — the server retains only running sums and commitment hashes
- Responses include remediation categories, pricing ranges, and detection rates — all derived from aggregates

**Residual risk**: With exactly k=3 contributors, statistical inference is still possible if one contributor knows their own data.

---

### Attack 13: Tampering with data in transit (dice chain bypass)
**Threat**: Man-in-the-middle or server-side tampering alters contribution data between client submission and server commitment.

**Defense**: Dice chain verification
- Client computes SHA-256 of the canonical JSON payload *before* submission
- Server's `ProofEngine.commit_contribution()` independently computes `contribution_hash` from the same canonical form
- Receipt returns this hash — if client hash matches server hash, the entire transformation chain (extract, anonymize, DP, translate, commit) is verified end-to-end
- This is the "dice chain" link between the Attested Data Transformation Chain (ADTC) and the ProofEngine

**Residual risk**: The dice chain proves data wasn't altered in transit, but doesn't prove the client-side transformation was honest (see Attack 7 for ADTC).

---

### Attack 14: Blind category name squatting
**Threat**: Attacker proposes hashes for common threat actor names to claim category ownership or block legitimate discovery.

**Defense**: Blind category discovery threshold protocol
- Categories are proposed as `H = SHA-256(name:salt)` — server sees only the hash
- Threshold of 3 independent organizations must propose the same hash before reveal is triggered
- On reveal, server verifies `SHA-256(plaintext:salt)` matches the committed hash
- Revealed categories enter the public taxonomy (NIST/D3FEND/RE&CT aligned)
- Server never learns category names until quorum agrees

**Residual risk**: If 3 colluding parties propose the same hash, they can inject a category. Mitigated by the invite system and BDP credibility — all three must be credible contributors.

---

### Attack 15: Voice recording PII exposure
**Threat**: Voice recordings submitted via `/contribute/voice` may contain spoken PII (names, company, IP addresses) that bypass text-based anonymization.

**Defense**: Voice recordings are stored separately (`/tmp/nur-voice-evals/`) for manual processing. They are not automatically transcribed or included in aggregates. Work email verification is required before voice submission. Free/disposable domains are blocked.

**Residual risk**: Audio files inherently contain voice biometrics that could identify the speaker. Manual processing introduces a human-in-the-loop who hears the recording.

**Mitigation needed**: Automated transcription + text anonymization pipeline before any voice data enters aggregates. Voice biometric scrubbing for stored audio.

---

## Which Algorithm Solves Which Problem

| Privacy Problem | Algorithm | File | What it guarantees |
|----------------|-----------|------|-------------------|
| PII in free text | Regex scrubbing | `anonymize.py` | Known patterns removed |
| Org identification | k-anonymity bucketing | `anonymize.py` | Identity hidden in bucket |
| IOC rainbow tables | HMAC-SHA256 keyed hash | `keystore.py` | Per-org unique hashes |
| Score inference | Differential Privacy (Laplace) | `dp.py` | Bounded info leakage (epsilon) |
| IOC list exposure | ECDH Private Set Intersection | `psi.py` | Learn only intersection, not sets |
| Coordinator sees values | Additive/Shamir secret sharing | `secagg.py` | Coordinator sees only random shares |
| Skipped anonymization | ADTC attestation chain | `attest/` | Cryptographic proof of process |
| PII in output | Verifiable Absence Proof | `attest/verify.py` | Zero PII patterns in final output |
| Data poisoning | BDP credibility + Byzantine aggregation + ZKP | `credibility.py`, `bdp.py`, `fl/aggregator.py`, `zkp/` | Behavioral anomaly detection, outlier detection, valid-range proofs |
| Model gradient leakage | DP-noised gradients | `fl/client.py` | Bounded leakage per FL round |
| Campaign correlation | Graph embeddings only | `graph/` | Share model params, not graph structure |
| Spam / Sybil accounts | Invite system + work email verification | `server/app.py` | Trust chains, limited invite codes, disposable domains blocked |
| Transit tampering | Dice chain (ADTC→ProofEngine) | `attest/`, `server/proofs.py` | Client hash matches server commitment end-to-end |
| Aggregate leaking individuals | Min-k enforcement + aggregate-only responses | `server/proofs.py` | No data returned with < k contributors |
| Blind category squatting | Threshold reveal protocol | `server/proofs.py` | 3-org quorum required before category name revealed |

---

## Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│              TRUSTED (your machine)             │
│                                                  │
│  Raw data → Extract → Anonymize → DP → Attest  │
│  Key storage, audit log, receipts, review       │
│                                                  │
│  NOTHING leaves without explicit approval        │
├─────────────────────────────────────────────────┤
│           UNTRUSTED (network + server)           │
│                                                  │
│  Transport (HTTPS assumed)                       │
│  Server receives anonymized data only            │
│  SecAgg coordinator sees random shares only      │
│  PSI peer sees blinded points only               │
│  FL coordinator sees noised gradients only       │
│                                                  │
│  Server stores aggregates, never returns         │
│  individual contributions via query API          │
│  Aggregate-only responses (histograms/templates) │
│  Dice chain: client hash == server hash          │
│  BDP: credibility weights, not individual data   │
│  Invite system: trust chains limit Sybil attacks │
└─────────────────────────────────────────────────┘
```

---

## Known Gaps (ordered by severity)

### Resolved ✅
1. ~~No minimum-k enforcement on aggregates~~ — **Fixed.** `NUR_MIN_K=3` enforced on all query endpoints. No vendor data returned with fewer than 3 contributors.
2. ~~No transport layer enforcement~~ — **Fixed.** Production deployment uses Caddy with auto-HTTPS (Let's Encrypt). Live instance at nur.saramena.us is HTTPS-only.
3. ~~No API key enforcement~~ — **Fixed.** Registration requires work email (free/disposable domains blocked). API key required for all write endpoints.
4. ~~No anti-poisoning defense~~ — **Fixed.** BDP credibility scoring with Query-Contribution Alignment detects and down-weights poisoned contributions.
5. ~~No end-to-end data integrity verification~~ — **Fixed.** Dice chain links client-side ADTC hash to server-side ProofEngine commitment hash.
6. ~~No Sybil/spam defense beyond email~~ — **Fixed.** Invite system with trust chains limits mass account creation.
7. ~~No mechanism for emerging threat categories~~ — **Fixed.** Blind category discovery with 3-org threshold reveal protocol.

### Medium Priority
4. **Client integrity verification** — A modified client could skip anonymization and forge attestation. Mitigated by ADTC chain verification on server side + dice chain end-to-end hash match.
5. **Bucketing quasi-identifiers** — Industry + size + role combinations may be unique enough to fingerprint. Mitigated by min-k enforcement.
6. **IOC hash correlation within same org** — Same HMAC key means same IOC always hashes the same within that org's contributions.
7. **No rate limiting on PSI queries** — Attacker could probe specific IOCs by submitting targeted sets.
8. **Data poisoning via fake contributions** — Mitigated by BDP credibility scoring (Query-Contribution Alignment), invite trust chains, work email requirement, and ZKP range proofs. See Attack 8.
9. **Voice recording PII** — Audio files may contain spoken PII that bypasses text anonymization. Currently stored for manual processing only.

### Low Priority (theoretical)
9. **Gradient inversion on FL** — Active research area, DP noise is the standard defense.
10. **ZKP proves range, not honesty** — Can prove score ∈ [0,10] but not that it's truthful.
11. **Traffic analysis** — Submission patterns could reveal incident timing.

---

## Anti-Spam Measures

| Measure | Status |
|---------|--------|
| Work email required for API keys | ✅ Implemented — gmail, yahoo, hotmail, etc. blocked |
| API key required for write endpoints | ✅ Implemented |
| Invite system (trust chains) | ✅ Implemented — new users need invite code, limited codes per user |
| Min-k enforcement on aggregates | ✅ Implemented (default k=3) |
| HTTPS enforcement (production) | ✅ Implemented via Caddy |
| BDP credibility scoring | ✅ Implemented — behavioral anomaly detection, QCA |
| Dice chain verification | ✅ Implemented — client hash matches server commitment |
| Blind category discovery | ✅ Implemented — 3-org quorum for new categories |
| Aggregate-only responses | ✅ Implemented — no individual data in query responses |
| Rate limiting per API key | Planned |
| Submission batching (traffic analysis defense) | Planned |
| Per-session IOC key derivation | Planned |
| Reproducible client builds | Planned |
| Voice recording auto-transcription + anonymization | Planned |

---

## Legal Safe Harbor

The **Cybersecurity Information Sharing Act of 2015 (CISA 2015)** provides explicit liability protection for organizations sharing cyber threat indicators and defensive measures. nur's data — numeric scores, categorical labels, and cryptographic hashes — qualifies as "cyber threat indicators" under the Act. Key protections: no civil liability, no antitrust liability, FOIA exemption, regulatory enforcement shield. CISA 2015 is extended through September 2026. See [COMPLIANCE.md](COMPLIANCE.md) for the full legal analysis.
