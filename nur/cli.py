"""CLI: nur — light on what your industry knows."""
from __future__ import annotations
import json
import os
from pathlib import Path
import click
from .extract import load_file
from .anonymize import anonymize
from .review import render
from .models import ContribContext, Industry, OrgSize, Role


_CONFIG_PATH = Path.home() / ".nur" / "config.json"


def _load_config() -> dict:
    """Load saved config from ~/.nur/config.json."""
    if _CONFIG_PATH.exists():
        try:
            return json.loads(_CONFIG_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _get_api_url(explicit: str | None) -> str | None:
    """Resolve API URL: explicit flag > env var > saved config."""
    if explicit:
        return explicit
    env = os.environ.get("NUR_API_URL")
    if env:
        return env
    return _load_config().get("api_url")


def _get_api_key(explicit: str | None) -> str | None:
    """Resolve API key: explicit flag > env var > saved config."""
    if explicit:
        return explicit
    env = os.environ.get("NUR_API_KEY")
    if env:
        return env
    return _load_config().get("api_key")


@click.group()
def main():
    """nur — light on what your industry knows.

    \b
    Full loop:
      nur init                          # save server URL + API key
      nur report incident_iocs.json     # give data, get intelligence
    """
    pass


# ── Init ────────────────────────────────────────────────────────────────────

@main.command()
def init():
    """Set up nur — save your server URL and API key so you never type them again."""
    config = _load_config()

    click.echo("\n  nur setup")
    click.echo("  " + "=" * 40)

    current_url = config.get("api_url", "")
    url = click.prompt(
        "  Server URL",
        default=current_url or "http://localhost:8000",
        show_default=True,
    )
    config["api_url"] = url.rstrip("/")

    current_key = config.get("api_key", "")
    key = click.prompt(
        "  API key (leave blank for none)",
        default=current_key or "",
        show_default=False,
    )
    if key:
        config["api_key"] = key
    elif "api_key" in config:
        del config["api_key"]

    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_PATH.write_text(json.dumps(config, indent=2))

    # Generate keypair for public-key auth
    from .keystore import get_public_key_hex
    pub_hex = get_public_key_hex()
    config["public_key"] = pub_hex
    _CONFIG_PATH.write_text(json.dumps(config, indent=2))

    click.echo(f"\n  Saved to {_CONFIG_PATH}")
    click.echo(f"  Server: {config['api_url']}")
    click.echo(f"  API key: {'***' + config['api_key'][-4:] if config.get('api_key') else 'none'}")
    click.echo(f"  Public key: {pub_hex[:16]}...")
    click.echo("\n  You're ready. Try: nur report <file>")
    click.echo()


# ── Register ─────────────────────────────────────────────────────────────────

@main.command()
@click.argument("email")
@click.option("--org", default=None, help="Organization name")
@click.option("--invite", default=None, help="Invite code from an existing user")
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
def register(email, org, invite, api_url):
    """Register for an API key with your work email. Generates a keypair and sends a verification link."""
    import httpx
    from .keystore import get_public_key_hex

    api_url = _get_api_url(api_url)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)

    pub_hex = get_public_key_hex()

    click.echo(f"\n  Registering {email}...")
    click.echo(f"  Public key: {pub_hex[:16]}...")

    with httpx.Client(timeout=30) as http:
        resp = http.post(f"{api_url.rstrip('/')}/register", json={
            "email": email,
            "org": org or "",
            "public_key": pub_hex,
            "invite_code": invite or "",
        })

    if resp.status_code != 200:
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        click.echo(f"  Error: {data.get('detail', resp.text[:200])}")
        return

    data = resp.json()

    if data.get("api_key"):
        # Already registered — got key back immediately
        config = _load_config()
        config["api_key"] = data["api_key"]
        config["public_key"] = pub_hex
        _CONFIG_PATH.write_text(json.dumps(config, indent=2))
        click.echo(f"  API key: {data['api_key']}")
        click.echo(f"  Saved to {_CONFIG_PATH}")
    else:
        click.echo(f"  {data.get('message', 'Check your email for the verification link.')}")
        if data.get("verify_url"):
            click.echo(f"  Verify: {data['verify_url']}")

    click.echo()


# ── Upload ───────────────────────────────────────────────────────────────────

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
@click.option("--industry", type=click.Choice([i.value for i in Industry]), default=None)
@click.option("--org-size", type=click.Choice([s.value for s in OrgSize]), default=None)
@click.option("--role", type=click.Choice([r.value for r in Role]), default=None)
@click.option("--epsilon", type=float, default=None, help="Differential privacy budget (e.g. 1.0)")
@click.option("--yes", is_flag=True, help="Skip review prompt (non-interactive)")
@click.option("--json", "json_output", is_flag=True, help="Output result as JSON")
def upload(file, api_url, api_key, industry, org_size, role, epsilon, yes, json_output):
    """Extract, anonymize, review, and submit a contribution file."""
    from .client import Client, UploadResult
    from .review import prompt_approve

    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    ctx = ContribContext(
        industry=Industry(industry) if industry else None,
        org_size=OrgSize(org_size) if org_size else None,
        role=Role(role) if role else None,
    )
    contribs = load_file(file, context=ctx)
    clean = [anonymize(c, epsilon=epsilon) for c in contribs]
    results = []
    client = Client(api_url=api_url, api_key=api_key)
    for c in clean:
        if yes or prompt_approve(c):
            results.append(client.submit(c))
        else:
            results.append(UploadResult(success=False, status_code=0, error="user skipped"))

    ok = sum(1 for r in results if r.success)

    if json_output:
        output = {
            "success": ok == len(results) and ok > 0,
            "count": len(results),
            "submitted": ok,
            "receipts": [r.receipt_hash for r in results if r.receipt_hash],
        }
        click.echo(json.dumps(output, indent=2))
        return

    click.echo(f"\n  {ok}/{len(results)} contributions submitted.")

    # Show receipts
    for r in results:
        if r.receipt_hash:
            click.echo(f"  Receipt: {r.receipt_hash[:16]}...")

    # Show privacy budget warning if DP was used
    if epsilon is not None:
        from .dp import PrivacyBudget
        budget = PrivacyBudget.load()
        budget.spend(epsilon, f"upload {file}")
        budget.save()
        if budget.warning:
            click.echo(f"  {budget.warning}")


# ── Report (actionable intelligence) ─────────────────────────────────────────

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
@click.option("--json", "json_output", is_flag=True, help="Output raw JSON response")
def report(file, api_url, api_key, json_output):
    """Give your incident data, get back intelligence. The main command."""
    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    import httpx

    contribs = load_file(file)

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    # Sign requests with private key
    try:
        from .keystore import get_or_create_keypair, sign_request
        _, priv_key = get_or_create_keypair()
    except Exception:
        priv_key = None

    for c in contribs:
        clean = anonymize(c)
        from .client import _serialize
        payload = _serialize(clean)

        # Dice chain: compute local hash of what we're about to send
        import hashlib as _hashlib
        import json as _json
        local_hash = _hashlib.sha256(
            _json.dumps(payload, sort_keys=True, default=str).encode()
        ).hexdigest()

        if priv_key:
            body_bytes = json.dumps(payload, sort_keys=True).encode()
            headers["X-Signature"] = sign_request(body_bytes, priv_key)

        with httpx.Client(timeout=30) as http:
            resp = http.post(f"{api_url.rstrip('/')}/analyze", json=payload, headers=headers)

        if resp.status_code != 200:
            click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")
            continue

        result = resp.json()

        if json_output:
            click.echo(json.dumps(result, indent=2))
        else:
            click.echo("\n  Analysis Report")
            click.echo(f"  {'=' * 50}")
            click.echo(f"  Status: {result.get('status', 'unknown')}")
            cid = result.get("contribution_id", "?")
            click.echo(f"  Contribution ID: {cid[:16]}...")

            # Show receipt if present
            receipt = result.get("receipt")
            if receipt:
                click.echo(f"  Receipt: {receipt.get('commitment_hash', '?')[:32]}...")
                click.echo(f"  Merkle proof: {len(receipt.get('merkle_proof', []))} nodes")
                # Dice chain verification
                server_hash = receipt.get("contribution_hash", "")
                if server_hash and local_hash == server_hash:
                    click.echo("  Dice chain: VERIFIED")
                elif server_hash:
                    click.echo(f"  Dice chain: MISMATCH (local={local_hash[:16]}... server={server_hash[:16]}...)")

            intel = result.get("intelligence", {})

            # IOC bundle specific
            if "campaign_match" in intel:
                click.echo(f"  Campaign Match: {'Yes' if intel['campaign_match'] else 'No'}")
                click.echo(f"  Shared IOCs: {intel.get('shared_ioc_count', 0)}")
                ioc_dist = intel.get("ioc_type_distribution", {})
                if ioc_dist:
                    click.echo(f"  IOC Types: {', '.join(f'{k}={v}' for k, v in ioc_dist.items())}")

            # Attack map specific
            if "coverage_score" in intel:
                score_pct = int(intel["coverage_score"] * 100)
                click.echo(f"  Coverage Score: {score_pct}%")
                gaps = intel.get("detection_gaps", [])
                if gaps:
                    click.echo(f"  Detection Gaps: {len(gaps)}")
                    for g in gaps[:5]:
                        freq = g.get('frequency', '')
                        click.echo(f"    - {g['technique_id']}: {freq}x observed, {g.get('caught_by_count', '?')} tools detect it")
                hints = intel.get("remediation_hints")
                if hints:
                    cats = hints.get("most_effective_categories", [])
                    if cats:
                        best = cats[0]
                        click.echo(f"  Best Remediation: {best['category']} ({int(best['success_rate'] * 100)}% success rate)")

            # Eval record specific
            if "your_vendor" in intel:
                click.echo(f"  Vendor: {intel['your_vendor']}")
                click.echo(f"  Your Score: {intel.get('your_score', '?')}")
                click.echo(f"  Category Avg: {intel.get('category_avg', '?')}")
                click.echo(f"  Percentile: {intel.get('percentile', '?')}th")
                if intel.get("contributor_count"):
                    click.echo(f"  Based On: {intel['contributor_count']} evaluations")
                gaps_count = intel.get("known_gaps_count", 0)
                if gaps_count > 0:
                    click.echo(f"  Detection Gaps: {gaps_count} techniques")

            # Actions (common to all types)
            actions = intel.get("actions", [])
            if actions:
                click.echo(f"\n  Actions ({len(actions)}):")
                for a in actions:
                    priority = a.get("priority", "?").upper()
                    click.echo(f"    [{priority}] {a.get('action', '')}")
                    if a.get("detail"):
                        click.echo(f"           {a['detail']}")
            click.echo()


# ── Preview ──────────────────────────────────────────────────────────────────

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--epsilon", type=float, default=None, help="Preview with DP noise")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def preview(file, epsilon, json_output):
    """Preview what would be sent without submitting anything."""
    contribs = load_file(file)
    for c in contribs:
        contrib = anonymize(c, epsilon=epsilon)
        if json_output:
            click.echo(json.dumps(contrib.model_dump(mode="json"), indent=2))
        else:
            click.echo(render(contrib))


# ── Eval (interactive vendor evaluation) ──────────────────────────────────────

@main.command()
@click.option("--vendor", default=None, help="Vendor slug (e.g. crowdstrike)")
@click.option("--file", "eval_file", default=None, type=click.Path(exists=True), help="Load eval from JSON file")
@click.option("--api-url", default=None)
@click.option("--api-key", default=None)
@click.option("--json", "json_output", is_flag=True, help="Output as JSON instead of submitting")
def eval(vendor, eval_file, api_url, api_key, json_output):
    """Submit a tool evaluation. Interactive or from file.

    \b
    Examples:
      nur eval                                # interactive walkthrough
      nur eval --vendor crowdstrike           # skip vendor prompt
      nur eval --file my_eval.json            # load from file
    """
    import httpx

    api_url = _get_api_url(api_url)
    api_key = _get_api_key(api_key)

    if eval_file:
        # Load from file
        data = json.loads(open(eval_file).read())
    elif vendor:
        # Semi-interactive with vendor pre-filled
        data = _interactive_eval(vendor)
    else:
        # Fully interactive
        click.echo("\n  Tool Evaluation")
        click.echo("  " + "=" * 40)
        click.echo("  Rate a security tool you've used.\n")

        vendor = click.prompt("  Vendor slug", type=str)
        data = _interactive_eval(vendor)

    if json_output:
        click.echo(json.dumps(data, indent=2))
        return

    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)

    # Submit directly — eval data is already in the right format
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    try:
        from .keystore import get_or_create_keypair, sign_request
        _, priv_key = get_or_create_keypair()
    except Exception:
        priv_key = None

    body = json.dumps(data, sort_keys=True).encode()
    if priv_key:
        headers["X-Signature"] = sign_request(body, priv_key)

    with httpx.Client(timeout=30) as http:
        resp = http.post(f"{api_url.rstrip('/')}/analyze", json=data, headers=headers)

    if resp.status_code == 200:
        result = resp.json()
        intel = result.get("intelligence", {})
        click.echo(f"\n  Submitted! Your {data.get('vendor', '?')} eval is in the pool.")
        if intel.get("your_score") and intel.get("category_avg"):
            click.echo(f"  Your score: {intel['your_score']} vs category avg: {intel['category_avg']}")
        if intel.get("known_gaps"):
            click.echo(f"  Known gaps: {', '.join(intel['known_gaps'][:5])}")
        click.echo()
    else:
        click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")


def _interactive_eval(vendor: str) -> dict:
    """Walk the user through an interactive tool evaluation."""
    categories = ["edr", "siem", "cnapp", "iam", "pam", "email", "ztna", "vm", "waf", "ndr", "soar", "dlp", "threat-intel"]
    industries = ["healthcare", "financial", "tech", "government", "energy", "manufacturing", "retail", "education", "other"]
    sizes = ["1-100", "100-500", "500-1000", "1000-5000", "5000-10000", "10000+"]

    category = click.prompt("  Category", type=click.Choice(categories), default="edr")
    score = click.prompt("  Overall score (0-10)", type=float, default=7.0)
    detection = click.prompt("  Detection rate % (0-100, or skip)", default="", show_default=False)
    fp_rate = click.prompt("  False positive rate % (or skip)", default="", show_default=False)
    deploy = click.prompt("  Deploy days (or skip)", default="", show_default=False)
    would_buy = click.confirm("  Would you buy again?", default=True)
    strength = click.prompt("  Top strength (one line)", default="", show_default=False)
    friction = click.prompt("  Top friction (one line)", default="", show_default=False)
    industry = click.prompt("  Your industry", type=click.Choice(industries), default="tech")
    org_size = click.prompt("  Org size", type=click.Choice(sizes), default="1000-5000")

    # Price (optional)
    click.echo("\n  Pricing (optional — skip with Enter):")
    annual_cost = click.prompt("  Annual cost ($)", default="", show_default=False)
    per_seat_cost = click.prompt("  Per-seat/endpoint cost ($)", default="", show_default=False)
    contract_length = click.prompt("  Contract length (months)", default="", show_default=False)
    discount_pct = click.prompt("  Discount off list price (%)", default="", show_default=False)

    # Support (optional)
    click.echo("\n  Support experience (optional):")
    support_quality = click.prompt("  Support quality (1-10)", default="", show_default=False)
    escalation_ease = click.prompt("  Escalation ease (1-10)", default="", show_default=False)
    support_sla = click.prompt("  SLA response time (hours)", default="", show_default=False)

    # Decision
    click.echo("\n  Decision:")
    chose = click.prompt("  Did you choose this vendor? (y/n)", default="", show_default=False)
    decision_factor = click.prompt("  Main decision factor (price/detection/support/integration/compliance)", default="", show_default=False)

    data = {
        "vendor": vendor,
        "category": category,
        "overall_score": score,
        "would_buy": would_buy,
        "context": {"industry": industry, "org_size": org_size},
    }
    if detection:
        data["detection_rate"] = float(detection)
    if fp_rate:
        data["fp_rate"] = float(fp_rate)
    if deploy:
        data["deploy_days"] = int(deploy)
    if strength:
        data["top_strength"] = strength
    if friction:
        data["top_friction"] = friction
    if annual_cost:
        data["annual_cost"] = float(annual_cost)
    if per_seat_cost:
        data["per_seat_cost"] = float(per_seat_cost)
    if contract_length:
        data["contract_length_months"] = int(contract_length)
    if discount_pct:
        data["discount_pct"] = float(discount_pct)
    if support_quality:
        data["support_quality"] = float(support_quality)
    if escalation_ease:
        data["escalation_ease"] = float(escalation_ease)
    if support_sla:
        data["support_sla_hours"] = float(support_sla)
    if chose:
        data["chose_this_vendor"] = chose.lower().startswith("y")
    if decision_factor:
        data["decision_factor"] = decision_factor

    click.echo("\n  Preview:")
    click.echo(f"    Vendor:    {vendor}")
    click.echo(f"    Category:  {category}")
    click.echo(f"    Score:     {score}/10")
    click.echo(f"    Would buy: {'yes' if would_buy else 'no'}")
    if not click.confirm("\n  Submit this evaluation?", default=True):
        click.echo("  Cancelled.")
        raise SystemExit(0)

    return data


# ── Audit log ────────────────────────────────────────────────────────────────

@main.command()
@click.option("--last", type=int, default=20, help="Show last N entries")
def audit(last):
    """View the local audit log — what was scrubbed and sent."""
    from .audit import read_log
    entries = read_log(last_n=last)
    if not entries:
        click.echo("  No audit entries yet.")
        return
    for entry in entries:
        ts = entry.get("timestamp", "")[:19]
        event = entry.get("event", "?")
        details = {k: v for k, v in entry.items() if k not in ("timestamp", "event")}
        detail_str = ", ".join(f"{k}={v}" for k, v in details.items())
        click.echo(f"  [{ts}] {event}: {detail_str}")


# ── Receipts ─────────────────────────────────────────────────────────────────

@main.command()
def receipts():
    """List contribution receipts — prove you contributed without revealing content."""
    from .client import list_receipts
    rcpts = list_receipts()
    if not rcpts:
        click.echo("  No receipts yet.")
        return
    for r in rcpts:
        ts = r.get("timestamp", "")[:19]
        h = r.get("receipt_hash", "?")[:16]
        click.echo(f"  [{ts}] {h}...")


# ── Search commands ──────────────────────────────────────────────────────────

@main.group()
def search():
    """Search vendor intelligence — scores, rankings, comparisons."""
    pass


@search.command("vendor")
@click.argument("name")
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def search_vendor(name, api_url, api_key, json_output):
    """Look up a vendor with weighted scores and metadata."""
    api_url = _get_api_url(api_url)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    import httpx
    headers = {}
    key = _get_api_key(api_key)
    if key:
        headers["X-API-Key"] = key

    with httpx.Client(timeout=30) as http:
        resp = http.get(f"{api_url.rstrip('/')}/search/vendor/{name}", headers=headers)

    if resp.status_code != 200:
        click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")
        return

    data = resp.json()
    if json_output:
        click.echo(json.dumps(data, indent=2))
        return

    click.echo(f"\n  {data.get('vendor_display', name)}")
    click.echo(f"  {'=' * 50}")
    click.echo(f"  Category:       {data.get('category', '?')}")
    click.echo(f"  Weighted Score: {data.get('weighted_score', '?')}")
    click.echo(f"  Confidence:     {data.get('confidence', '?')}")
    click.echo(f"  Eval Count:     {data.get('eval_count', 0)}")
    if data.get('price_range'):
        click.echo(f"  Price Range:    {data['price_range']}")
    if data.get('certifications'):
        click.echo(f"  Certifications: {', '.join(data['certifications'])}")
    if data.get('insurance_carriers'):
        click.echo(f"  Insurance:      {', '.join(data['insurance_carriers'])}")
    if data.get('known_issues'):
        click.echo(f"  Known Issues:   {data['known_issues'][:80]}")
    metrics = data.get('metrics', {})
    if any(v is not None for v in metrics.values()):
        click.echo("\n  Metrics:")
        if metrics.get('detection_rate') is not None:
            click.echo(f"    Detection Rate: {metrics['detection_rate']}")
        if metrics.get('fp_rate') is not None:
            click.echo(f"    FP Rate:        {metrics['fp_rate']}")
        if metrics.get('deploy_days') is not None:
            click.echo(f"    Deploy Days:    {metrics['deploy_days']}")
    click.echo()


@search.command("category")
@click.argument("name")
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def search_category(name, api_url, api_key, json_output):
    """Rank vendors within a category by weighted score."""
    api_url = _get_api_url(api_url)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    import httpx
    headers = {}
    key = _get_api_key(api_key)
    if key:
        headers["X-API-Key"] = key

    with httpx.Client(timeout=30) as http:
        resp = http.get(f"{api_url.rstrip('/')}/search/category/{name}", headers=headers)

    if resp.status_code != 200:
        click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")
        return

    data = resp.json()
    if json_output:
        click.echo(json.dumps(data, indent=2))
        return

    click.echo(f"\n  Category: {data.get('category', name)}")
    click.echo(f"  {'=' * 50}")
    vendors = data.get("vendors", [])
    if not vendors:
        click.echo("  No vendors found.")
        return
    for i, v in enumerate(vendors, 1):
        score = v.get("weighted_score")
        score_str = f"{score:.1f}" if score is not None else "  ?"
        conf = v.get("confidence", "?")
        click.echo(f"  {i:2d}. {v.get('vendor_display', '?'):25s}  score={score_str}  confidence={conf}")
    click.echo()


@search.command("compare")
@click.argument("vendor_a")
@click.argument("vendor_b")
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def search_compare(vendor_a, vendor_b, api_url, api_key, json_output):
    """Side-by-side comparison of two vendors."""
    api_url = _get_api_url(api_url)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    import httpx
    headers = {}
    key = _get_api_key(api_key)
    if key:
        headers["X-API-Key"] = key

    with httpx.Client(timeout=30) as http:
        resp = http.get(
            f"{api_url.rstrip('/')}/search/compare",
            params={"a": vendor_a, "b": vendor_b},
            headers=headers,
        )

    if resp.status_code != 200:
        click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")
        return

    data = resp.json()
    if json_output:
        click.echo(json.dumps(data, indent=2))
        return

    a = data.get("vendor_a", {})
    b = data.get("vendor_b", {})
    click.echo(f"\n  {'':30s} {'A':>12s}  {'B':>12s}")
    click.echo(f"  {'Vendor':30s} {a.get('vendor_display','?'):>12s}  {b.get('vendor_display','?'):>12s}")
    click.echo(f"  {'=' * 56}")

    def _fmt(val):
        if val is None:
            return "?"
        if isinstance(val, float):
            return f"{val:.1f}"
        return str(val)

    click.echo(f"  {'Weighted Score':30s} {_fmt(a.get('weighted_score')):>12s}  {_fmt(b.get('weighted_score')):>12s}")
    click.echo(f"  {'Confidence':30s} {_fmt(a.get('confidence')):>12s}  {_fmt(b.get('confidence')):>12s}")
    click.echo(f"  {'Eval Count':30s} {_fmt(a.get('eval_count')):>12s}  {_fmt(b.get('eval_count')):>12s}")
    click.echo(f"  {'Category':30s} {_fmt(a.get('category')):>12s}  {_fmt(b.get('category')):>12s}")
    if a.get('price_range') or b.get('price_range'):
        click.echo(f"  {'Price Range':30s} {_fmt(a.get('price_range')):>12s}  {_fmt(b.get('price_range')):>12s}")
    click.echo()


# ── Market command ───────────────────────────────────────────────────────────

@main.command()
@click.argument("category")
@click.option("--api-url", default=None, help="Server URL (default: from nur init)")
@click.option("--api-key", default=None, help="API key (default: from nur init)")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def market(category, api_url, api_key, json_output):
    """Market map for a category — leaders, contenders, emerging, watch."""
    api_url = _get_api_url(api_url)
    if not api_url:
        click.echo("  No server URL configured. Run: nur init")
        raise SystemExit(1)
    import httpx
    headers = {}
    key = _get_api_key(api_key)
    if key:
        headers["X-API-Key"] = key

    with httpx.Client(timeout=30) as http:
        resp = http.get(f"{api_url.rstrip('/')}/intelligence/market/{category}", headers=headers)

    if resp.status_code != 200:
        click.echo(f"  Error: {resp.status_code} {resp.text[:200]}")
        return

    data = resp.json()
    if json_output:
        click.echo(json.dumps(data, indent=2))
        return

    click.echo(f"\n  Market Map: {data.get('category', category)}")
    click.echo(f"  {'=' * 50}")
    click.echo(f"  Total vendors: {data.get('vendor_count', 0)}")

    tiers = data.get("tiers", {})
    for tier_name in ("leaders", "contenders", "emerging", "watch"):
        vendors = tiers.get(tier_name, [])
        if vendors:
            click.echo(f"\n  {tier_name.upper()} ({len(vendors)}):")
            for v in vendors:
                score = v.get("weighted_score")
                score_str = f"{score:.1f}" if score is not None else "  ?"
                click.echo(f"    {v.get('display', '?'):25s}  score={score_str}  conf={v.get('confidence', '?')}")
    click.echo()
