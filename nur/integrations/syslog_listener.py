"""
Syslog/CEF listener — receive syslog UDP messages, parse CEF, forward to nur.

CEF format: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension

Usage:
    from nur.integrations.syslog_listener import start_syslog_listener
    start_syslog_listener(port=514, api_url="http://localhost:8000", api_key="nur_abc...")

    # Or use the SyslogListener class for more control:
    listener = SyslogListener(port=514, api_url="http://localhost:8000", api_key="...")
    listener.start()
    # ... later ...
    listener.stop()
"""
from __future__ import annotations

import hashlib
import re
import socket
import threading
import time
from typing import Any

import httpx


# CEF extension field to IOC type mapping
CEF_IOC_FIELDS: dict[str, str] = {
    "src": "ip",
    "dst": "ip",
    "shost": "domain",
    "dhost": "domain",
    "sourceAddress": "ip",
    "destinationAddress": "ip",
    "sourceHostName": "domain",
    "destinationHostName": "domain",
    "requestUrl": "url",
    "request": "url",
    "fileHash": "hash-sha256",
    "fileHashMd5": "hash-md5",
    "fileHashSha256": "hash-sha256",
    "fileHashSha1": "hash-sha1",
    "cs1": "url",          # Often used for URLs in CEF
    "cs2": "domain",       # Often used for domains
    "fname": "filename",
    "filePath": "filepath",
    "sntdom": "domain",
    "dntdom": "domain",
}

# Regex for parsing CEF header
_CEF_HEADER_RE = re.compile(
    r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)",
    re.DOTALL,
)


def parse_cef(message: str) -> dict[str, Any] | None:
    """Parse a CEF-formatted syslog message.

    Returns dict with keys: version, vendor, product, device_version,
    signature_id, name, severity, extensions (dict).
    Returns None if the message is not valid CEF.
    """
    # Strip syslog header if present (e.g., "<134>Jan  1 00:00:00 host CEF:0|...")
    cef_start = message.find("CEF:")
    if cef_start == -1:
        return None
    message = message[cef_start:]

    match = _CEF_HEADER_RE.match(message)
    if not match:
        return None

    extensions_raw = match.group(8)
    extensions: dict[str, str] = {}

    # Parse extension key=value pairs
    # CEF extensions use key=value separated by spaces, with escaped pipes and equals
    if extensions_raw:
        # Simple parser: split on key= patterns
        parts = re.split(r"\s+(?=\w+=)", extensions_raw.strip())
        for part in parts:
            eq_idx = part.find("=")
            if eq_idx > 0:
                key = part[:eq_idx].strip()
                value = part[eq_idx + 1 :].strip()
                if key and value:
                    extensions[key] = value

    return {
        "version": match.group(1),
        "vendor": match.group(2),
        "product": match.group(3),
        "device_version": match.group(4),
        "signature_id": match.group(5),
        "name": match.group(6),
        "severity": match.group(7),
        "extensions": extensions,
    }


def extract_iocs_from_cef(parsed: dict[str, Any]) -> list[dict[str, str]]:
    """Extract IOC entries from parsed CEF extensions."""
    iocs: list[dict[str, str]] = []
    extensions = parsed.get("extensions", {})

    for field, ioc_type in CEF_IOC_FIELDS.items():
        value = extensions.get(field)
        if value and value.strip() and value.strip() not in ("-", "N/A", "none", "null"):
            value = value.strip()
            # Skip non-IOC types like filename/filepath
            if ioc_type in ("filename", "filepath"):
                continue
            iocs.append({
                "ioc_type": ioc_type,
                "value_hash": hashlib.sha256(value.lower().encode()).hexdigest(),
            })

    return iocs


class SyslogListener:
    """UDP syslog listener that parses CEF events and batches them to nur."""

    def __init__(
        self,
        port: int = 514,
        api_url: str = "http://localhost:8000",
        api_key: str = "",
        batch_interval: int = 60,
    ):
        self.port = port
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.batch_interval = batch_interval

        self._stop_event = threading.Event()
        self._batch_lock = threading.Lock()
        self._batch: list[dict[str, Any]] = []
        self._listener_thread: threading.Thread | None = None
        self._flush_thread: threading.Thread | None = None
        self._sock: socket.socket | None = None
        self._total_received = 0
        self._total_submitted = 0

    def start(self) -> None:
        """Start the syslog listener and batch flush threads."""
        self._stop_event.clear()

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)  # So we can check stop_event periodically
        self._sock.bind(("0.0.0.0", self.port))

        self._listener_thread = threading.Thread(
            target=self._listen_loop, daemon=True, name="syslog-listener",
        )
        self._flush_thread = threading.Thread(
            target=self._flush_loop, daemon=True, name="syslog-flusher",
        )

        self._listener_thread.start()
        self._flush_thread.start()
        print(f"  [syslog] Listening on UDP port {self.port}")

    def stop(self) -> None:
        """Stop the listener and flush remaining events."""
        self._stop_event.set()

        if self._listener_thread:
            self._listener_thread.join(timeout=5)
        if self._flush_thread:
            self._flush_thread.join(timeout=5)
        if self._sock:
            self._sock.close()
            self._sock = None

        # Final flush
        self._flush_batch()
        print(
            f"  [syslog] Stopped. Received: {self._total_received}, "
            f"Submitted: {self._total_submitted}"
        )

    def _listen_loop(self) -> None:
        """Main UDP receive loop."""
        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                raise

            try:
                message = data.decode("utf-8", errors="replace")
            except Exception:
                continue

            self._total_received += 1
            source_ip = addr[0] if addr else "unknown"

            # Try to parse as CEF
            parsed = parse_cef(message)
            if parsed:
                iocs = extract_iocs_from_cef(parsed)
                if iocs:
                    event = {
                        "cef": message.strip(),
                        "source_ip": source_ip,
                        "parsed_iocs": iocs,
                        "vendor": parsed["vendor"],
                        "product": parsed["product"],
                        "severity": parsed["severity"],
                    }
                    with self._batch_lock:
                        self._batch.append(event)

    def _flush_loop(self) -> None:
        """Periodically flush the batch to nur."""
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self.batch_interval)
            self._flush_batch()

    def _flush_batch(self) -> None:
        """Send accumulated events to nur webhook."""
        with self._batch_lock:
            if not self._batch:
                return
            batch = self._batch[:]
            self._batch.clear()

        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key,
        }

        submitted = 0
        with httpx.Client(timeout=30) as http:
            for event in batch:
                payload = {
                    "cef": event["cef"],
                    "source_ip": event["source_ip"],
                }
                try:
                    resp = http.post(
                        f"{self.api_url}/ingest/webhook",
                        json=payload,
                        headers=headers,
                    )
                    if resp.status_code == 200:
                        submitted += 1
                except httpx.HTTPError:
                    continue

        self._total_submitted += submitted
        if submitted:
            print(f"  [syslog] Flushed {submitted}/{len(batch)} events to nur")

    @property
    def stats(self) -> dict[str, int]:
        """Return listener statistics."""
        return {
            "total_received": self._total_received,
            "total_submitted": self._total_submitted,
            "batch_pending": len(self._batch),
        }


def start_syslog_listener(
    port: int = 514,
    api_url: str = "http://localhost:8000",
    api_key: str = "",
) -> None:
    """Start a UDP syslog listener that converts CEF events to nur contributions.

    This function blocks until interrupted (Ctrl+C).

    Args:
        port: UDP port to listen on (default: 514, may require root)
        api_url: nur API base URL
        api_key: nur API key for authentication
    """
    listener = SyslogListener(port=port, api_url=api_url, api_key=api_key)
    listener.start()

    try:
        print("  [syslog] Press Ctrl+C to stop")
        while not listener._stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  [syslog] Shutting down...")
    finally:
        listener.stop()
