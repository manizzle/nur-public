"""
Credibility engine — detect data poisoning via contributor behavior.

The problem: anyone can submit fake evaluations to game the system.
The solution: real practitioners behave differently than poisoners.

Signals (ordered by how hard they are to fake):

1. SKIN IN THE GAME (hardest to fake)
   Real practitioners don't just submit evals — they ask questions.
   They submit IOCs AND ask for campaign matches. They run threat
   models against their stack. They come back next month.
   A poisoner submits one fake eval and leaves.

2. PROOF OF DEPLOYMENT
   Auto-submitted data from integrations (Splunk, CrowdStrike, Sentinel)
   is machine-generated — can't be faked without running the actual tool.

3. CONTRIBUTION CONSISTENCY
   Same public key contributes over time. IOCs match real campaigns.
   Attack maps align with other orgs' observations. Trust builds.

4. CROSS-SIGNAL CONVERGENCE
   If 5 unrelated orgs (different keys, domains, industries) all report
   the same finding — it's real. One outlier could be gaming.
   Five independent outliers is signal.

Each contributor gets a credibility_score (0.0 to 1.0).
Aggregates use weighted averages based on credibility.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class ContributorProfile:
    """Tracks a contributor's behavior over time."""
    public_key: str
    email_domain: str | None = None

    # Contribution counts by type
    ioc_bundles: int = 0
    attack_maps: int = 0
    tool_evals: int = 0
    threat_models_run: int = 0
    simulations_run: int = 0
    reports_requested: int = 0

    # Quality signals
    iocs_matched_campaigns: int = 0      # how many of their IOCs matched others
    techniques_corroborated: int = 0     # attack map techniques seen by others too
    integration_source: bool = False      # auto-submitted from Splunk/CrowdStrike/etc
    first_contribution: datetime | None = None
    last_contribution: datetime | None = None
    total_contributions: int = 0

    def credibility_score(self) -> float:
        """Calculate credibility score (0.0 to 1.0) based on behavior signals."""
        score = 0.0

        # ── Signal 1: Skin in the game (max 0.35) ──────────────────
        # Real practitioners use multiple features, not just one
        features_used = sum([
            self.ioc_bundles > 0,
            self.attack_maps > 0,
            self.tool_evals > 0,
            self.threat_models_run > 0,
            self.simulations_run > 0,
            self.reports_requested > 0,
        ])
        # Using 1 feature = 0.05, 2 = 0.10, 3+ = 0.15, 4+ = 0.25, 5+ = 0.35
        skin_score = min(0.35, features_used * 0.07)
        score += skin_score

        # ── Signal 2: Proof of deployment (max 0.25) ───────────────
        if self.integration_source:
            score += 0.25  # auto-submitted from real tool = strong signal

        # ── Signal 3: Contribution consistency (max 0.25) ──────────
        # More contributions over time = more trust
        if self.total_contributions >= 10:
            score += 0.15
        elif self.total_contributions >= 5:
            score += 0.10
        elif self.total_contributions >= 2:
            score += 0.05

        # Longevity — contributing for months, not just today
        if self.first_contribution and self.last_contribution:
            days_active = (self.last_contribution - self.first_contribution).days
            if days_active >= 90:
                score += 0.10
            elif days_active >= 30:
                score += 0.05

        # ── Signal 4: Cross-validation (max 0.15) ──────────────────
        # Their IOCs matched real campaigns others reported
        if self.iocs_matched_campaigns >= 5:
            score += 0.10
        elif self.iocs_matched_campaigns >= 1:
            score += 0.05

        # Their attack observations corroborated by others
        if self.techniques_corroborated >= 3:
            score += 0.05

        return min(1.0, max(0.0, round(score, 2)))

    def credibility_tier(self) -> str:
        """Human-readable credibility tier."""
        score = self.credibility_score()
        if score >= 0.7:
            return "trusted"       # integration + history + cross-validation
        elif score >= 0.4:
            return "established"   # multiple features used + some history
        elif score >= 0.15:
            return "new"           # just started, few contributions
        else:
            return "unverified"    # single contribution, no history


def calculate_weighted_aggregate(
    values: list[tuple[float, float]],  # [(value, credibility_weight), ...]
) -> float | None:
    """Calculate credibility-weighted average.

    Regular average: (9.2 + 2.0 + 8.8) / 3 = 6.67
    Weighted average: (9.2*0.8 + 2.0*0.1 + 8.8*0.7) / (0.8+0.1+0.7) = 8.62

    The fake eval (2.0 with 0.1 credibility) barely moves the needle.
    """
    if not values:
        return None
    total_weight = sum(w for _, w in values)
    if total_weight == 0:
        return None
    return sum(v * w for v, w in values) / total_weight


def detect_poisoning_signals(contributions: list[dict]) -> list[dict]:
    """Detect potential data poisoning in a batch of contributions.

    Returns list of suspicious contributions with reasons.
    """
    suspicious = []

    for c in contributions:
        reasons = []

        # Single-feature contributor (only evals, never IOCs or attack maps)
        contributor_types = set()
        # This would need to be checked against the full contributor profile
        # For now, flag evals with extreme scores
        score = c.get("overall_score")
        if score is not None:
            if score <= 1.0 or score >= 9.9:
                reasons.append(f"extreme_score ({score})")

        # Eval with no context (no industry, no org_size)
        ctx = c.get("context", {})
        if c.get("vendor") and not ctx.get("industry"):
            reasons.append("missing_context")

        # Very short eval (no strengths, no friction, no notes)
        if c.get("vendor") and not c.get("top_strength") and not c.get("top_friction"):
            reasons.append("no_qualitative_data")

        if reasons:
            suspicious.append({
                "contribution": c,
                "reasons": reasons,
                "risk": "high" if len(reasons) >= 2 else "medium",
            })

    return suspicious


# ── New contributor defaults ────────────────────────────────────────────────

DEFAULT_CREDIBILITY = 0.15  # new contributors start here
INTEGRATION_CREDIBILITY = 0.65  # auto-submitted from integrations
MINIMUM_CREDIBILITY = 0.05  # absolute floor (still included but barely)
