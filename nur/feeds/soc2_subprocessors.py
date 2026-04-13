"""
SOC 2 subprocessor list scraper — verified tool usage data.

Companies publish subprocessor lists for SOC 2 compliance.
These show what vendors they ACTUALLY use — not marketing, not surveys.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class SubprocessorEntry:
    company: str  # the company publishing the list
    subprocessor: str  # the vendor/tool being used
    purpose: str  # what it's used for
    data_location: str | None = None  # where data is processed


# Known subprocessor page URLs (public, linked from trust/security pages)
KNOWN_SUBPROCESSOR_PAGES = [
    # Format: (company, url)
    ("Notion", "https://www.notion.so/help/subprocessors"),
    ("Ramp", "https://ramp.com/subprocessors"),
    ("Brex", "https://www.brex.com/legal/subprocessors"),
    ("Linear", "https://linear.app/docs/subprocessors"),
    ("Vercel", "https://vercel.com/legal/sub-processors"),
    ("Supabase", "https://supabase.com/legal/subprocessors"),
    ("Clerk", "https://clerk.com/legal/subprocessors"),
    ("Resend", "https://resend.com/legal/subprocessors"),
    ("Neon", "https://neon.tech/subprocessors"),
    ("PostHog", "https://posthog.com/handbook/company/security#sub-processors"),
    ("Loom", "https://www.loom.com/subprocessors"),
    ("Figma", "https://www.figma.com/summary-of-subprocessors/"),
    ("Datadog", "https://www.datadoghq.com/legal/sub-processors/"),
    ("Twilio", "https://www.twilio.com/legal/sub-processors"),
    ("Stripe", "https://stripe.com/legal/service-providers"),
    ("Plaid", "https://plaid.com/legal/data-protection-addendum/"),
]

# Common security-related subprocessors to look for
SECURITY_VENDORS = {
    "crowdstrike", "sentinelone", "palo alto", "zscaler", "okta",
    "cloudflare", "datadog", "splunk", "elastic", "snyk",
    "wiz", "orca", "lacework", "aqua", "sysdig",
    "1password", "keeper", "hashicorp vault",
    "aws", "azure", "gcp", "google cloud",
    "mongodb", "snowflake", "databricks",
    "auth0", "ping identity", "cyberark",
    "proofpoint", "mimecast", "abnormal",
}


async def scrape_subprocessor_page(company: str, url: str) -> list[SubprocessorEntry]:
    """Scrape a company's subprocessor page and extract vendor names."""
    import httpx

    entries = []
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "nur-research contact@saramena.us"})
            if resp.status_code != 200:
                return entries

            text = resp.text
            # Strip HTML tags for text analysis
            clean = re.sub(r"<[^>]+>", " ", text)
            clean = re.sub(r"\s+", " ", clean)

            # Look for known security vendors in the page
            for vendor in SECURITY_VENDORS:
                if vendor.lower() in clean.lower():
                    entries.append(SubprocessorEntry(
                        company=company,
                        subprocessor=vendor.title(),
                        purpose="detected in subprocessor list",
                    ))
    except Exception as e:
        print(f"Error scraping {company}: {e}")

    return entries


def subprocessor_to_eval_payload(entry: SubprocessorEntry) -> dict:
    """Convert a subprocessor entry to a nur eval contribution.

    This is a 'verified usage' signal — the company uses this vendor
    per their SOC 2 documentation.
    """
    return {
        "data": {
            "vendor": entry.subprocessor,
            "category": "verified_usage",
            "chose_this_vendor": True,
            "source": f"soc2-subprocessor-{entry.company.lower()}",
        }
    }


async def scrape_all_and_ingest(api_url: str, api_key: str | None = None) -> dict:
    """Scrape all known subprocessor pages and ingest into nur."""
    import httpx
    import time

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    results = {"companies_scraped": 0, "entries_found": 0, "ingested": 0, "errors": 0, "vendors_found": []}

    async with httpx.AsyncClient(timeout=30) as client:
        for company, url in KNOWN_SUBPROCESSOR_PAGES:
            entries = await scrape_subprocessor_page(company, url)
            results["companies_scraped"] += 1
            results["entries_found"] += len(entries)

            for entry in entries:
                payload = subprocessor_to_eval_payload(entry)
                try:
                    resp = await client.post(
                        f"{api_url.rstrip('/')}/contribute/submit",
                        json=payload,
                        headers=headers,
                    )
                    if resp.status_code == 200:
                        results["ingested"] += 1
                        if entry.subprocessor not in results["vendors_found"]:
                            results["vendors_found"].append(entry.subprocessor)
                    else:
                        results["errors"] += 1
                except Exception:
                    results["errors"] += 1

            time.sleep(1)  # Rate limit

    return results
