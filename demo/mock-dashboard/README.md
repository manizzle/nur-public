# Mock Security Dashboard

A self-hosted fake security dashboard ("Falcon Sentinel") for testing the nur browser extension and recording demos.

Designed to reliably trigger every detection path in the extension:

- **Shelfware X-ray** — 28 modules, 19 inactive, $84k/yr unused capacity visible
- **Integration map** — 14 vendor connectors (Splunk, Okta, Datadog, AWS, etc.) with only 3 connected
- **Module status** — clear active/inactive/disabled patterns the extension can read
- **Multi-page nav** — 18 sidebar links so Full Scan can crawl meaningfully

## Run it

```bash
cd demo/mock-dashboard
python3 -m http.server 8000
```

Then visit `http://localhost:8000/index.html` in Chrome with the nur extension loaded.

## What the extension should detect

Run **Full Scan** on the index page. After ~10s of crawling, the report should show:

- ~28 modules scanned, ~19 marked inactive
- Vendors detected: splunk, okta, slack, plus mentions of crowdstrike, datadog, elastic, sumo logic, microsoft, ping, sailpoint, cyberark, aws, azure, gcp, jira, servicenow, qualys, tenable, rapid7
- Multiple pages: index, modules, integrations, detections, billing
- High shelfware percentage (~67%)

If the extension shows different numbers, that's a bug worth filing — the mock is deterministic.

## Pages

| Page | Purpose |
|------|---------|
| `index.html` | Overview with metrics, recent threats |
| `modules.html` | The shelfware money shot — 28 modules, mostly inactive |
| `integrations.html` | 14 vendor connectors, mostly disconnected |
| `detections.html` | Threat detection table with MITRE techniques |
| `billing.html` | Pricing, tier comparison, $84k/yr waste estimate |

Other sidebar links (`hunting.html`, `forensics.html`, etc.) intentionally 404 — they represent locked / upgrade-gated features the extension should detect as inactive.
