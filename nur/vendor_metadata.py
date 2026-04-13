"""Vendor metadata — category mappings and competitor relationships."""

# Vendor → category auto-fill
VENDOR_CATEGORIES = {
    "crowdstrike": "edr", "crowdstrike falcon": "edr",
    "sentinelone": "edr", "sentinelone singularity": "edr",
    "microsoft defender": "edr", "microsoft defender for endpoint": "edr",
    "cortex xdr": "edr", "carbon black": "edr",
    "sophos": "edr", "sophos intercept x": "edr",
    "bitdefender": "edr", "eset": "edr",
    "trend micro": "edr", "cybereason": "edr",
    "trellix": "edr", "huntress": "edr",
    "splunk": "siem", "splunk enterprise security": "siem",
    "microsoft sentinel": "siem", "ibm qradar": "siem",
    "elastic": "siem", "elastic security": "siem",
    "sumo logic": "siem", "logrhythm": "siem",
    "exabeam": "siem", "securonix": "siem",
    "google chronicle": "siem", "devo": "siem",
    "wiz": "cloud_security", "prisma cloud": "cloud_security",
    "orca security": "cloud_security", "lacework": "cloud_security",
    "aqua security": "cloud_security", "snyk": "cloud_security",
    "sysdig": "cloud_security",
    "okta": "identity", "microsoft entra id": "identity",
    "cyberark": "identity", "beyondtrust": "identity",
    "sailpoint": "identity", "ping identity": "identity",
    "jumpcloud": "identity", "onelogin": "identity",
    "proofpoint": "email_security", "mimecast": "email_security",
    "abnormal security": "email_security", "barracuda": "email_security",
    "palo alto networks": "network_security", "fortinet": "network_security",
    "check point": "network_security", "zscaler": "network_security",
    "cloudflare": "network_security", "netskope": "network_security",
    "darktrace": "ndr", "vectra": "ndr", "vectra ai": "ndr",
    "extrahop": "ndr", "corelight": "ndr",
    "tenable": "vulnerability_management", "qualys": "vulnerability_management",
    "rapid7": "vulnerability_management",
    "drata": "compliance", "vanta": "compliance",
    "secureframe": "compliance", "sprinto": "compliance",
    "knowbe4": "security_awareness", "cofense": "security_awareness",
    "arctic wolf": "mdr", "expel": "mdr", "red canary": "mdr",
}

# Category → top competitors (ordered by market share)
CATEGORY_COMPETITORS = {
    "edr": ["CrowdStrike", "SentinelOne", "Microsoft Defender", "Cortex XDR", "Carbon Black", "Sophos", "Trellix", "Cybereason"],
    "siem": ["Splunk", "Microsoft Sentinel", "Elastic", "IBM QRadar", "Sumo Logic", "Google Chronicle", "Exabeam", "LogRhythm"],
    "cloud_security": ["Wiz", "Prisma Cloud", "Orca Security", "Lacework", "Aqua Security", "Snyk", "Sysdig"],
    "identity": ["Okta", "Microsoft Entra ID", "CyberArk", "BeyondTrust", "SailPoint", "Ping Identity", "JumpCloud"],
    "email_security": ["Proofpoint", "Mimecast", "Abnormal Security", "Barracuda", "Cofense", "IRONSCALES"],
    "network_security": ["Palo Alto Networks", "Fortinet", "Check Point", "Zscaler", "Cloudflare", "Netskope", "Cisco"],
    "ndr": ["Darktrace", "Vectra AI", "ExtraHop", "Corelight", "Stamus Networks"],
    "vulnerability_management": ["Tenable", "Qualys", "Rapid7", "CrowdStrike Falcon Spotlight", "Wiz"],
    "compliance": ["Drata", "Vanta", "Secureframe", "Sprinto", "Thoropass", "Laika"],
    "security_awareness": ["KnowBe4", "Proofpoint Security Awareness", "Cofense", "Hoxhunt"],
    "mdr": ["Arctic Wolf", "Expel", "Red Canary", "Huntress", "eSentire", "Secureworks"],
    "waf": ["Cloudflare WAF", "AWS WAF", "Akamai", "Imperva", "F5", "Fastly"],
    "soar": ["Palo Alto XSOAR", "Splunk SOAR", "Swimlane", "Tines", "Torq"],
    "other": [],
}


def get_category(vendor_name: str) -> str | None:
    return VENDOR_CATEGORIES.get(vendor_name.lower().strip())


def get_competitors(vendor_name: str, category: str | None = None) -> list[str]:
    if not category:
        category = get_category(vendor_name)
    if not category or category not in CATEGORY_COMPETITORS:
        return []
    # Return competitors excluding the selected vendor
    return [c for c in CATEGORY_COMPETITORS.get(category, []) if c.lower() != vendor_name.lower().strip()]
