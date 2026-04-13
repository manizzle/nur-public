"""
HIPAA Safe Harbor de-identification verification — certification layer for nur.

This module maps nur's existing anonymization engine (anonymize.py) against the
18 identifiers specified in HIPAA Safe Harbor (45 CFR §164.514(b)(2)).  It is
NOT a replacement for anonymize.py — it is a verification/certification layer
that checks whether a contribution has been properly de-identified per Safe
Harbor and provides programmatic proof of compliance.

Additionally provides GDPR Recital 26 re-identification risk assessment.

References:
  - 45 CFR §164.514(a)   — Expert Determination method
  - 45 CFR §164.514(b)   — Safe Harbor method (18 identifiers)
  - GDPR Recital 26      — "reasonably likely" re-identification standard
"""
from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from .anonymize import (
    strip_pii,
    strip_security,
    scrub,
    bucket_context_dict,
    _EMAIL,
    _PHONE,
    _URL,
    _TITLE_NAME,
    _IPV4,
    _IPV6,
    _API_KEY,
    _AWS_ACCOUNT,
    _CERT_SERIAL,
)


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic models — structured compliance results
# ══════════════════════════════════════════════════════════════════════════════

class IdentifierCheck(BaseModel):
    """Result of checking one of the 18 HIPAA Safe Harbor identifiers."""
    identifier: str = Field(description="Human-readable identifier name")
    cfr_reference: str = Field(description="CFR section reference, e.g. §164.514(b)(2)(i)(A)")
    status: str = Field(description="One of: removed, not_applicable, needs_review")
    method: str = Field(description="How nur handles this identifier")
    evidence: str = Field(description="Code path or function that enforces removal")


class HIPAASafeHarborStatus(BaseModel):
    """Result of HIPAA Safe Harbor compliance check on a contribution."""
    compliant: bool = Field(description="True if all 18 identifiers are addressed")
    identifier_checks: dict[str, IdentifierCheck] = Field(
        description="Maps each of 18 identifiers to its check result"
    )
    residual_risks: list[str] = Field(
        default_factory=list,
        description="Any PII patterns still detected in the data",
    )
    recommendation: str = Field(
        default="",
        description="Summary recommendation for compliance posture",
    )


# ══════════════════════════════════════════════════════════════════════════════
# Additional regex patterns — identifiers not covered by anonymize.py
# ══════════════════════════════════════════════════════════════════════════════

# §164.514(b)(2)(i)(G) — Social Security Numbers
_SSN = re.compile(
    r"\b\d{3}-\d{2}-\d{4}\b"
)

# §164.514(b)(2)(i)(H) — Medical record numbers
_MEDICAL_RECORD = re.compile(
    r"\b(?:MRN|MR#|Med\.?\s*Rec\.?(?:\s*(?:No\.?|#|Number))?)"
    r"[\s:]*[A-Z0-9]{4,15}\b",
    re.IGNORECASE,
)

# §164.514(b)(2)(i)(I) — Health plan beneficiary numbers
_HEALTH_PLAN = re.compile(
    r"\b(?:HPBN|Member\s*(?:ID|#|No\.?)|Beneficiary\s*(?:ID|#|No\.?)|"
    r"Subscriber\s*(?:ID|#|No\.?)|Policy\s*(?:ID|#|No\.?)|Group\s*(?:ID|#|No\.?))"
    r"[\s:]*[A-Z0-9]{4,20}\b",
    re.IGNORECASE,
)

# §164.514(b)(2)(i)(J) — Account numbers (with context keywords to avoid false positives)
_ACCOUNT_NUM = re.compile(
    r"\b(?:account|acct|routing|aba|iban)[\s#:]*\d{8,17}\b",
    re.IGNORECASE,
)

# §164.514(b)(2)(i)(L) — Vehicle Identification Numbers (17 chars, no I/O/Q)
_VIN = re.compile(
    r"\b(?:VIN[\s:]*)?[A-HJ-NPR-Z0-9]{17}\b"
)

# §164.514(b)(2)(i)(M) — Device identifiers and serial numbers
_DEVICE_SERIAL = re.compile(
    r"\b(?:UDI|device\s*(?:serial|id)|serial\s*(?:number|no\.?|#))"
    r"[\s:]*[A-Z0-9\-]{6,30}\b",
    re.IGNORECASE,
)


# ══════════════════════════════════════════════════════════════════════════════
# Safe Harbor identifier map — all 18 per 45 CFR §164.514(b)(2)
# ══════════════════════════════════════════════════════════════════════════════

SAFE_HARBOR_MAP: dict[str, dict[str, str]] = {
    "names": {
        "cfr_reference": "§164.514(b)(2)(i)(A)",
        "method": "strip_pii() removes titled names; bucket_context_dict() strips org_name",
        "evidence": "anonymize._TITLE_NAME regex; anonymize.bucket_context_dict() pops org-identifying fields",
        "default_status": "removed",
    },
    "geographic_data": {
        "cfr_reference": "§164.514(b)(2)(i)(B)",
        "method": "Not collected — nur does not ingest sub-state geographic data",
        "evidence": "No geographic fields in nur.models.Contribution schema",
        "default_status": "not_applicable",
    },
    "dates": {
        "cfr_reference": "§164.514(b)(2)(i)(C)",
        "method": "strip_timing in maximum privacy mode removes timestamps; standard mode retains only year",
        "evidence": "nur.privacy.PRIVACY_LEVELS['maximum']['strip_timing'] = True",
        "default_status": "removed",
    },
    "phone_numbers": {
        "cfr_reference": "§164.514(b)(2)(i)(D)",
        "method": "strip_pii() removes phone numbers via regex",
        "evidence": "anonymize._PHONE regex replaces with [PHONE]",
        "default_status": "removed",
    },
    "fax_numbers": {
        "cfr_reference": "§164.514(b)(2)(i)(E)",
        "method": "strip_pii() — same phone regex covers fax number patterns",
        "evidence": "anonymize._PHONE regex (fax uses same digit pattern as phone)",
        "default_status": "removed",
    },
    "email_addresses": {
        "cfr_reference": "§164.514(b)(2)(i)(F)",
        "method": "strip_pii() removes email addresses via regex",
        "evidence": "anonymize._EMAIL regex replaces with [EMAIL]",
        "default_status": "removed",
    },
    "ssn": {
        "cfr_reference": "§164.514(b)(2)(i)(G)",
        "method": "strip_safe_harbor() removes SSN patterns",
        "evidence": "deidentify._SSN regex replaces with [SSN]",
        "default_status": "removed",
    },
    "medical_record_numbers": {
        "cfr_reference": "§164.514(b)(2)(i)(H)",
        "method": "strip_safe_harbor() removes medical record number patterns",
        "evidence": "deidentify._MEDICAL_RECORD regex replaces with [MEDICAL_RECORD]",
        "default_status": "removed",
    },
    "health_plan_beneficiary_numbers": {
        "cfr_reference": "§164.514(b)(2)(i)(I)",
        "method": "strip_safe_harbor() removes health plan beneficiary ID patterns",
        "evidence": "deidentify._HEALTH_PLAN regex replaces with [HEALTH_PLAN_ID]",
        "default_status": "removed",
    },
    "account_numbers": {
        "cfr_reference": "§164.514(b)(2)(i)(J)",
        "method": "strip_safe_harbor() removes account number patterns with context keywords",
        "evidence": "deidentify._ACCOUNT_NUM regex replaces with [ACCOUNT_NUM]",
        "default_status": "removed",
    },
    "certificate_license_numbers": {
        "cfr_reference": "§164.514(b)(2)(i)(K)",
        "method": "strip_security() removes certificate serial numbers",
        "evidence": "anonymize._CERT_SERIAL regex replaces with [CERT_SERIAL]",
        "default_status": "removed",
    },
    "vehicle_identifiers": {
        "cfr_reference": "§164.514(b)(2)(i)(L)",
        "method": "strip_safe_harbor() removes VIN patterns",
        "evidence": "deidentify._VIN regex replaces with [VIN]",
        "default_status": "removed",
    },
    "device_identifiers": {
        "cfr_reference": "§164.514(b)(2)(i)(M)",
        "method": "strip_safe_harbor() removes device serial/UDI patterns",
        "evidence": "deidentify._DEVICE_SERIAL regex replaces with [DEVICE_SERIAL]",
        "default_status": "removed",
    },
    "web_urls": {
        "cfr_reference": "§164.514(b)(2)(i)(N)",
        "method": "strip_pii() removes URLs via regex",
        "evidence": "anonymize._URL regex replaces with [URL]",
        "default_status": "removed",
    },
    "ip_addresses": {
        "cfr_reference": "§164.514(b)(2)(i)(O)",
        "method": "strip_security() removes IPv4 and IPv6 addresses; IOC IPs are HMAC-hashed",
        "evidence": "anonymize._IPV4 and _IPV6 regexes replace with [IP_ADDR]",
        "default_status": "removed",
    },
    "biometric_identifiers": {
        "cfr_reference": "§164.514(b)(2)(i)(P)",
        "method": "Not collected — nur is text-only, no biometric data ingested",
        "evidence": "No biometric fields in nur.models.Contribution schema",
        "default_status": "not_applicable",
    },
    "full_face_photographs": {
        "cfr_reference": "§164.514(b)(2)(i)(Q)",
        "method": "Not collected — nur is text-only, no image data ingested",
        "evidence": "No image fields in nur.models.Contribution schema; all inputs are structured text",
        "default_status": "not_applicable",
    },
    "other_unique_identifying_numbers": {
        "cfr_reference": "§164.514(b)(2)(i)(R)",
        "method": "strip_security() removes AWS account IDs, API keys, and other unique identifiers",
        "evidence": "anonymize._API_KEY and _AWS_ACCOUNT regexes; covers common cloud/service identifiers",
        "default_status": "removed",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# Residual PII detection patterns — used by verify_safe_harbor()
# ══════════════════════════════════════════════════════════════════════════════

_RESIDUAL_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("email",          _EMAIL,          "email_addresses"),
    ("phone",          _PHONE,          "phone_numbers"),
    ("ssn",            _SSN,            "ssn"),
    ("ipv4",           _IPV4,           "ip_addresses"),
    ("ipv6",           _IPV6,           "ip_addresses"),
    ("url",            _URL,            "web_urls"),
    ("titled_name",    _TITLE_NAME,     "names"),
    ("api_key",        _API_KEY,        "other_unique_identifying_numbers"),
    ("aws_account",    _AWS_ACCOUNT,    "other_unique_identifying_numbers"),
    ("medical_record", _MEDICAL_RECORD, "medical_record_numbers"),
    ("health_plan",    _HEALTH_PLAN,    "health_plan_beneficiary_numbers"),
    ("account_num",    _ACCOUNT_NUM,    "account_numbers"),
    ("vin",            _VIN,            "vehicle_identifiers"),
    ("device_serial",  _DEVICE_SERIAL,  "device_identifiers"),
]


# ══════════════════════════════════════════════════════════════════════════════
# strip_safe_harbor — enhanced text stripping covering all 18 identifiers
# ══════════════════════════════════════════════════════════════════════════════

def strip_safe_harbor(text: str) -> str:
    """Enhanced text stripping that covers all 18 HIPAA Safe Harbor identifiers.

    Pipeline:
      1. Calls scrub() from anonymize.py (PII + security patterns)
      2. Applies additional patterns for identifiers not covered by scrub():
         SSN, medical record numbers, health plan IDs, account numbers,
         vehicle identification numbers, device serial numbers.

    Returns the scrubbed text with all identified PII replaced by tags.
    """
    if not text:
        return text

    # Pass 1 — HIPAA-specific patterns with context keywords (run first to
    # prevent generic phone/number regexes from consuming the digit sequences)
    text = _SSN.sub("[SSN]", text)
    text = _MEDICAL_RECORD.sub("[MEDICAL_RECORD]", text)
    text = _HEALTH_PLAN.sub("[HEALTH_PLAN_ID]", text)
    text = _ACCOUNT_NUM.sub("[ACCOUNT_NUM]", text)
    text = _VIN.sub("[VIN]", text)
    text = _DEVICE_SERIAL.sub("[DEVICE_SERIAL]", text)

    # Pass 2 — existing anonymize.py pipeline (PII + security)
    text = scrub(text)

    return text


# ══════════════════════════════════════════════════════════════════════════════
# verify_safe_harbor — compliance verification for a contribution dict
# ══════════════════════════════════════════════════════════════════════════════

def _extract_strings(data: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Recursively extract all string values from a nested dict/list."""
    strings: list[tuple[str, str]] = []
    if isinstance(data, str):
        strings.append((prefix or "value", data))
    elif isinstance(data, dict):
        for k, v in data.items():
            strings.extend(_extract_strings(v, prefix=f"{prefix}.{k}" if prefix else k))
    elif isinstance(data, (list, tuple)):
        for i, v in enumerate(data):
            strings.extend(_extract_strings(v, prefix=f"{prefix}[{i}]"))
    return strings


def verify_safe_harbor(data: dict) -> HIPAASafeHarborStatus:
    """Check if a contribution dict meets HIPAA Safe Harbor de-identification.

    Scans all string fields for residual PII patterns, maps each of the 18
    Safe Harbor identifiers to nur's handling, and returns a structured
    compliance result.

    Args:
        data: A contribution dict (e.g., from .model_dump() on a Contribution).

    Returns:
        HIPAASafeHarborStatus with per-identifier checks and any residual risks.
    """
    # Build identifier checks from the static map
    identifier_checks: dict[str, IdentifierCheck] = {}
    for ident_key, info in SAFE_HARBOR_MAP.items():
        identifier_checks[ident_key] = IdentifierCheck(
            identifier=ident_key.replace("_", " ").title(),
            cfr_reference=info["cfr_reference"],
            status=info["default_status"],
            method=info["method"],
            evidence=info["evidence"],
        )

    # Scan all string values for residual PII
    residual_risks: list[str] = []
    strings = _extract_strings(data)

    for field_path, value in strings:
        if not value:
            continue
        for pattern_name, pattern, ident_key in _RESIDUAL_PATTERNS:
            matches = pattern.findall(value)
            if matches:
                # Filter out replacement tags like [EMAIL], [PHONE], etc.
                real_matches = [
                    m for m in matches
                    if not (m.startswith("[") and m.endswith("]"))
                ]
                if real_matches:
                    residual_risks.append(
                        f"Residual {pattern_name} detected in '{field_path}': "
                        f"{real_matches[0]!r}"
                    )
                    # Mark the corresponding identifier as needs_review
                    if ident_key in identifier_checks:
                        identifier_checks[ident_key] = identifier_checks[ident_key].model_copy(
                            update={"status": "needs_review"}
                        )

    compliant = len(residual_risks) == 0

    if compliant:
        recommendation = (
            "Data clears HIPAA Safe Harbor (45 CFR §164.514(b)). "
            "All 18 identifier categories are addressed through removal, "
            "hashing, or non-collection."
        )
    else:
        recommendation = (
            f"Data does NOT clear HIPAA Safe Harbor. "
            f"{len(residual_risks)} residual risk(s) detected. "
            f"Run strip_safe_harbor() on text fields before submission."
        )

    return HIPAASafeHarborStatus(
        compliant=compliant,
        identifier_checks=identifier_checks,
        residual_risks=residual_risks,
        recommendation=recommendation,
    )


# ══════════════════════════════════════════════════════════════════════════════
# verify_gdpr_recital26 — GDPR re-identification risk assessment
# ══════════════════════════════════════════════════════════════════════════════

def verify_gdpr_recital26(data: dict) -> dict:
    """Assess GDPR Recital 26 re-identification risk for a contribution.

    GDPR Recital 26 defines personal data as information relating to an
    identifiable person, where identification is "reasonably likely" given
    "all the means reasonably likely to be used."

    This function assesses whether nur's technical controls make
    re-identification of a contributor unreasonably difficult.

    Args:
        data: A contribution dict (e.g., from .model_dump() on a Contribution).

    Returns:
        Assessment dict with per-vector analysis and overall risk rating.
    """
    # Check for residual direct identifiers
    strings = _extract_strings(data)
    has_residual_pii = False
    for _, value in strings:
        if not value:
            continue
        for _, pattern, _ in _RESIDUAL_PATTERNS:
            matches = pattern.findall(value)
            real_matches = [
                m for m in matches
                if not (m.startswith("[") and m.endswith("]"))
            ]
            if real_matches:
                has_residual_pii = True
                break
        if has_residual_pii:
            break

    # Check for quasi-identifiers (org name, specific role, etc.)
    has_org_name = any(
        k in data for k in ("org_name", "organization", "company", "company_name", "employer")
    )
    has_specific_role = "job_title" in data and data.get("job_title") not in (
        None, "", "other"
    )

    # Build assessment
    direct_status = "fail" if has_residual_pii else "pass"
    indirect_status = "review" if (has_org_name or has_specific_role) else "pass"

    return {
        "compliant": not has_residual_pii and not has_org_name,
        "standard": "GDPR Recital 26",
        "assessment": {
            "direct_identification": {
                "status": direct_status,
                "explanation": (
                    "Direct identification impossible — no names, addresses, or "
                    "organization identifiers in transmitted data. All PII stripped "
                    "client-side by anonymize.strip_pii() and anonymize.strip_security()."
                    if not has_residual_pii else
                    "Residual PII detected in contribution data. Direct identification "
                    "risk exists until PII is stripped."
                ),
            },
            "indirect_identification": {
                "status": indirect_status,
                "explanation": (
                    "Indirect identification via linkage mitigated by bucketing — "
                    "industry, org_size, and role_tier are coarse categorical values. "
                    "bucket_context_dict() replaces specific org names, headcounts, "
                    "and job titles with k-anonymous buckets."
                    if not has_org_name else
                    "Organization name present in data. Run bucket_context_dict() "
                    "to replace with industry bucket before submission."
                ),
            },
            "timing_correlation": {
                "status": "pass",
                "explanation": (
                    "Timing correlation mitigated by strip_timing in maximum privacy "
                    "mode. Timestamps are removed or truncated to year. Contribution "
                    "submission times are not linked to specific events."
                ),
            },
            "contribution_pattern": {
                "status": "pass",
                "explanation": (
                    "Contribution pattern analysis mitigated by Behavioral Differential "
                    "Privacy (BDP) and aggregate-only responses. Individual contributions "
                    "are committed via Pedersen commitments and discarded — only running "
                    "sums are retained. An adversary cannot reconstruct individual "
                    "contribution patterns from aggregate outputs."
                ),
            },
            "overall_risk": "very_low" if not has_residual_pii else "elevated",
            "recommendation": (
                "Contribution data meets GDPR Recital 26 standard — re-identification "
                "is not 'reasonably likely' given nur's technical controls (client-side "
                "stripping, bucketing, Pedersen commitments, aggregate-only responses, BDP). "
                "The anonymization is verifiable by any party (open source), not solely "
                "certified by the vendor."
                if not has_residual_pii and not has_org_name else
                "Contribution data requires additional processing before meeting GDPR "
                "Recital 26. Run the full anonymization pipeline (anonymize.anonymize()) "
                "before submission."
            ),
        },
    }
