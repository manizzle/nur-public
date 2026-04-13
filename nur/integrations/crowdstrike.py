"""
CrowdStrike Falcon integration — pull detections and submit to nur.

TEMPLATE: This connector requires valid CrowdStrike Falcon API credentials.
It will not work without a CrowdStrike subscription and API client credentials
created at https://falcon.crowdstrike.com/support/api-clients-and-keys

Usage:
    from nur.integrations.crowdstrike import pull_crowdstrike_detections
    count = pull_crowdstrike_detections(
        client_id="your-client-id",
        client_secret="your-client-secret",
        api_url="https://nur.example.com",
        nur_api_key="nur_abc123...",
        since_hours=24,
    )
    print(f"Submitted {count} detections")
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx


# Default CrowdStrike API base URL (US-1 cloud)
# Other clouds: US-2 = api.us-2.crowdstrike.com, EU = api.eu-1.crowdstrike.com
FALCON_BASE_URL = "https://api.crowdstrike.com"


def _get_oauth_token(
    client_id: str,
    client_secret: str,
    base_url: str = FALCON_BASE_URL,
) -> str:
    """Authenticate via OAuth2 client_credentials and return access token.

    Raises httpx.HTTPStatusError on failure.
    """
    resp = httpx.post(
        f"{base_url}/oauth2/token",
        data={
            "client_id": client_id,
            "client_secret": client_secret,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def _list_detection_ids(
    token: str,
    since_hours: int = 24,
    base_url: str = FALCON_BASE_URL,
) -> list[str]:
    """Query detection IDs created in the last `since_hours` hours."""
    since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")

    resp = httpx.get(
        f"{base_url}/detections/queries/detections/v1",
        params={
            "filter": f"created_timestamp:>'{since_str}'",
            "limit": 500,
            "sort": "created_timestamp|desc",
        },
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("resources", [])


def _get_detection_details(
    token: str,
    detection_ids: list[str],
    base_url: str = FALCON_BASE_URL,
) -> list[dict[str, Any]]:
    """Fetch full detection details for a batch of detection IDs.

    CrowdStrike uses POST for this endpoint with IDs in the body.
    """
    if not detection_ids:
        return []

    # CrowdStrike API limits batch size to 1000
    all_details: list[dict[str, Any]] = []
    for i in range(0, len(detection_ids), 1000):
        batch = detection_ids[i : i + 1000]
        resp = httpx.post(
            f"{base_url}/detections/entities/summaries/GET/v1",
            json={"ids": batch},
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            timeout=60,
        )
        resp.raise_for_status()
        all_details.extend(resp.json().get("resources", []))

    return all_details


def _extract_detection_data(detection: dict[str, Any]) -> dict[str, Any] | None:
    """Extract technique, IOC, and severity info from a CrowdStrike detection.

    Returns a dict in CrowdStrike webhook format, or None if no useful data.
    """
    behaviors = detection.get("behaviors", [])
    if not behaviors:
        return None

    # Use the first behavior as primary (detections can have multiple)
    behavior = behaviors[0]

    technique = behavior.get("technique_id") or behavior.get("technique", "")
    tactic = behavior.get("tactic") or behavior.get("tactic_id", "")
    severity = detection.get("max_severity_displayname", "Medium")

    # Extract IOC data from the detection
    ioc_type = None
    ioc_value = None

    # Check device for IP
    device = detection.get("device", {})
    if device.get("external_ip"):
        ioc_type = "ip"
        ioc_value = device["external_ip"]

    # Check for SHA256 hash in behaviors
    sha256 = behavior.get("sha256")
    if sha256:
        ioc_type = "hash-sha256"
        ioc_value = sha256

    # Check for MD5
    md5 = behavior.get("md5")
    if md5 and not ioc_value:
        ioc_type = "hash-md5"
        ioc_value = md5

    # Check for filename/filepath as fallback
    filename = behavior.get("filename")
    filepath = behavior.get("filepath")

    if not technique and not ioc_value:
        return None

    result: dict[str, Any] = {
        "detection": {
            "technique": technique,
            "tactic": tactic,
            "severity": severity.lower() if isinstance(severity, str) else "medium",
            "description": behavior.get("description", ""),
            "scenario": behavior.get("scenario", ""),
            "detection_id": detection.get("detection_id", ""),
            "timestamp": behavior.get("timestamp", ""),
        },
    }

    if ioc_type and ioc_value:
        result["detection"]["ioc_type"] = ioc_type
        result["detection"]["ioc_value"] = ioc_value

    if filename:
        result["detection"]["filename"] = filename
    if filepath:
        result["detection"]["filepath"] = filepath

    return result


def pull_crowdstrike_detections(
    client_id: str,
    client_secret: str,
    api_url: str,
    nur_api_key: str,
    since_hours: int = 24,
    falcon_base_url: str = FALCON_BASE_URL,
) -> int:
    """Pull recent detections from CrowdStrike Falcon and submit to nur.

    TEMPLATE: Requires valid CrowdStrike API credentials. Get them from:
    https://falcon.crowdstrike.com/support/api-clients-and-keys

    Required API scopes: Detections (Read)

    Args:
        client_id: CrowdStrike OAuth2 client ID
        client_secret: CrowdStrike OAuth2 client secret
        api_url: nur API base URL (e.g. "https://nur.example.com")
        nur_api_key: nur API key for authentication
        since_hours: How far back to pull detections (default: 24 hours)
        falcon_base_url: CrowdStrike API base URL (default: US-1 cloud)

    Returns:
        Count of detections successfully submitted to nur.
    """
    api_url = api_url.rstrip("/")

    # Step 1: Authenticate
    token = _get_oauth_token(client_id, client_secret, falcon_base_url)

    # Step 2: List recent detection IDs
    detection_ids = _list_detection_ids(token, since_hours, falcon_base_url)
    if not detection_ids:
        return 0

    # Step 3: Get detection details
    detections = _get_detection_details(token, detection_ids, falcon_base_url)

    # Step 4: Convert and submit each detection
    submitted = 0
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": nur_api_key,
    }

    with httpx.Client(timeout=30) as http:
        for detection in detections:
            payload = _extract_detection_data(detection)
            if not payload:
                continue

            try:
                resp = http.post(
                    f"{api_url}/ingest/webhook",
                    json=payload,
                    headers=headers,
                )
                if resp.status_code == 200:
                    submitted += 1
            except httpx.HTTPError:
                # Log but continue — don't fail the entire batch for one error
                continue

    return submitted
