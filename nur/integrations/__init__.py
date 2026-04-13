"""
Integrations — wartime (incident auto-submit) and peacetime (proactive defense).

Wartime:
  - Splunk:       Generate a Splunk app that forwards alerts to nur
  - Sentinel:     Generate an Azure Logic App / Sentinel Playbook ARM template
  - CrowdStrike:  Pull detections from the Falcon API
  - Syslog/CEF:   UDP listener that parses CEF events

Peacetime:
  - Navigator:    Import MITRE ATT&CK Navigator layers for gap analysis
  - Asset:        Import tool inventories from CSV/JSON/ServiceNow
  - Compliance:   Import compliance status from Drata/Vanta exports
  - RFP:          Generate vendor comparison reports for procurement
  - Export:       Export data as STIX 2.1, MISP, CSV, or Navigator layers
"""
from __future__ import annotations

# Wartime integrations
from .splunk import generate_splunk_app
from .sentinel import generate_sentinel_playbook
from .crowdstrike import pull_crowdstrike_detections
from .syslog_listener import start_syslog_listener

# Peacetime integrations
from .navigator import import_navigator_layer
from .asset_inventory import (
    import_from_csv,
    import_from_json,
    import_from_servicenow,
    match_tool_to_vendor,
)
from .compliance import import_compliance_status
from .rfp import generate_rfp_comparison
from .export import (
    export_stix_bundle,
    export_misp_event,
    export_csv,
    export_navigator_layer,
)

__all__ = [
    # Wartime
    "generate_splunk_app",
    "generate_sentinel_playbook",
    "pull_crowdstrike_detections",
    "start_syslog_listener",
    # Peacetime
    "import_navigator_layer",
    "import_from_csv",
    "import_from_json",
    "import_from_servicenow",
    "match_tool_to_vendor",
    "import_compliance_status",
    "generate_rfp_comparison",
    "export_stix_bundle",
    "export_misp_event",
    "export_csv",
    "export_navigator_layer",
]
