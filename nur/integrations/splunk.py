"""
Splunk integration — generate a Splunk app package that forwards alerts to nur.

Usage:
    from nur.integrations.splunk import generate_splunk_app
    files = generate_splunk_app("https://nur.example.com", "nur_abc123...")
    for path, content in files.items():
        write(path, content)
"""
from __future__ import annotations

import textwrap


def generate_splunk_app(api_url: str, api_key: str) -> dict[str, str]:
    """Generate Splunk app configuration files.

    Returns dict of {filename: content} for the Splunk app package.
    Install by copying the generated directory to $SPLUNK_HOME/etc/apps/nur_integration/
    """
    api_url = api_url.rstrip("/")

    app_conf = textwrap.dedent("""\
        [install]
        is_configured = false
        build = 1

        [ui]
        is_visible = true
        label = nur Integration

        [launcher]
        description = Forward security alerts and IOCs to nur threat intelligence
        author = nur
        version = 1.0.0
    """)

    savedsearches_conf = textwrap.dedent("""\
        [nur_notable_events]
        description = Forward notable events with IOC fields to nur
        search = `notable` | where isnotnull(src_ip) OR isnotnull(dest_ip) OR isnotnull(url) OR isnotnull(file_hash) OR isnotnull(domain) | fields src_ip, dest_ip, src, dst, url, file_hash, hash, domain, dvc, signature, severity, rule_name, source
        dispatch.earliest_time = -15m
        dispatch.latest_time = now
        cron_schedule = */15 * * * *
        is_scheduled = true
        alert.track = false
        action.nur_alert = 1
        action.nur_alert.param.api_url = {api_url}
        action.nur_alert.param.api_key = {api_key}
    """.format(api_url=api_url, api_key=api_key))

    alert_actions_conf = textwrap.dedent(f"""\
        [nur_alert]
        is_custom = 1
        label = Send to nur
        description = Forward IOCs and alerts to nur threat intelligence platform
        icon_path = appIcon.png
        filename = nur_alert.py
        param.api_url = {api_url}
        param.api_key = {api_key}
    """)

    alert_script = textwrap.dedent(f"""\
        #!/usr/bin/env python
        \"\"\"
        Splunk alert action — reads search results from stdin and POSTs IOCs to nur.

        Splunk passes results as a JSON payload on stdin when this script is invoked
        as an alert action.
        \"\"\"
        import json
        import sys
        import os

        try:
            import requests
        except ImportError:
            # Fall back to urllib if requests is not available in Splunk's Python
            import urllib.request
            import urllib.error

            def _post_json(url, data, headers):
                req = urllib.request.Request(
                    url,
                    data=json.dumps(data).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                try:
                    resp = urllib.request.urlopen(req, timeout=30)
                    return resp.status, resp.read().decode()
                except urllib.error.HTTPError as e:
                    return e.code, e.read().decode()

            requests = None


        # IOC field mappings: Splunk field name -> nur IOC type
        IOC_FIELDS = {{
            "src_ip": "ip",
            "dest_ip": "ip",
            "src": "ip",
            "dst": "ip",
            "url": "url",
            "file_hash": "hash-sha256",
            "hash": "hash-sha256",
            "md5": "hash-md5",
            "sha256": "hash-sha256",
            "sha1": "hash-sha1",
            "domain": "domain",
            "dvc": "ip",
        }}


        def extract_iocs(result):
            \"\"\"Extract IOCs from a single Splunk search result row.\"\"\"
            iocs = []
            for field, ioc_type in IOC_FIELDS.items():
                value = result.get(field)
                if value and str(value).strip() and str(value).strip() != "-":
                    iocs.append({{
                        "ioc_type": ioc_type,
                        "value_raw": str(value).strip(),
                    }})
            return iocs


        def main():
            # Splunk passes the payload as the first argument (path to results file)
            # or via stdin in newer versions
            api_url = "{api_url}"
            api_key = "{api_key}"

            # Try to read from Splunk's alert results
            results = []
            if len(sys.argv) > 8:
                # Splunk passes: script results_file ... (8+ args)
                results_file = sys.argv[8] if len(sys.argv) > 8 else None
                if results_file and os.path.exists(results_file):
                    with open(results_file) as f:
                        try:
                            data = json.load(f)
                            results = data.get("results", data) if isinstance(data, dict) else data
                        except json.JSONDecodeError:
                            pass

            if not results:
                # Try stdin
                try:
                    raw = sys.stdin.read()
                    if raw.strip():
                        data = json.loads(raw)
                        results = data.get("results", data) if isinstance(data, dict) else data
                except (json.JSONDecodeError, EOFError):
                    pass

            if not isinstance(results, list):
                results = [results] if isinstance(results, dict) else []

            # Extract IOCs from all results
            all_iocs = []
            for result in results:
                all_iocs.extend(extract_iocs(result))

            if not all_iocs:
                return

            # POST to nur
            payload = {{
                "iocs": all_iocs,
                "source": "splunk",
            }}
            headers = {{
                "Content-Type": "application/json",
                "X-API-Key": api_key,
            }}

            webhook_url = api_url.rstrip("/") + "/ingest/webhook"

            if requests:
                try:
                    resp = requests.post(webhook_url, json=payload, headers=headers, timeout=30)
                    print(f"nur: submitted {{len(all_iocs)}} IOCs, status={{resp.status_code}}")
                except Exception as e:
                    print(f"nur: error submitting IOCs: {{e}}", file=sys.stderr)
            else:
                try:
                    status, body = _post_json(webhook_url, payload, headers)
                    print(f"nur: submitted {{len(all_iocs)}} IOCs, status={{status}}")
                except Exception as e:
                    print(f"nur: error submitting IOCs: {{e}}", file=sys.stderr)


        if __name__ == "__main__":
            main()
    """)

    readme = textwrap.dedent(f"""\
        # nur Splunk Integration

        Automatically forward security alerts and IOCs from Splunk to nur.

        ## Installation

        1. Copy this directory to `$SPLUNK_HOME/etc/apps/nur_integration/`
        2. Restart Splunk: `$SPLUNK_HOME/bin/splunk restart`
        3. The saved search runs every 15 minutes and forwards notable events

        ## Configuration

        Edit `default/savedsearches.conf` to adjust:
        - The search query (customize IOC field names for your environment)
        - The schedule (default: every 15 minutes)
        - API URL and key in the alert action parameters

        ## How It Works

        1. A saved search runs periodically looking for events with IOC fields
        2. When results are found, the `nur_alert.py` script is invoked
        3. The script extracts IOCs (IPs, domains, hashes, URLs) from results
        4. IOCs are POSTed to `{api_url}/ingest/webhook`

        ## IOC Fields Detected

        | Splunk Field | IOC Type     |
        |-------------|-------------|
        | src_ip      | ip          |
        | dest_ip     | ip          |
        | url         | url         |
        | file_hash   | hash-sha256 |
        | hash        | hash-sha256 |
        | md5         | hash-md5    |
        | sha256      | hash-sha256 |
        | domain      | domain      |
    """)

    return {
        "default/app.conf": app_conf,
        "default/savedsearches.conf": savedsearches_conf,
        "default/alert_actions.conf": alert_actions_conf,
        "bin/nur_alert.py": alert_script,
        "README.md": readme,
    }
