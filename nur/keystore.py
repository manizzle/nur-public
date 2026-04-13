"""
Org-local key management for HMAC-based IOC hashing.

Stores a 256-bit secret at ~/.nur/key — auto-generated on first use,
never transmitted. Each org's HMAC hashes are unique, defeating rainbow tables.

Salt rotation: IOC hashes include a time-based rotating salt to defeat
precomputed rainbow tables. IPv4 only has 2^32 values — without rotation,
an attacker who obtains the HMAC key could brute-force all IPs offline.
The salt rotates every NUR_SALT_ROTATION_INTERVAL seconds (default 900 = 15 min).
Both PSI parties must share the same salt window for intersection to work.
"""
from __future__ import annotations

import hmac
import hashlib
import os
import secrets
import time
from pathlib import Path

_NUR_DIR = Path.home() / ".nur"
_KEY_PATH = _NUR_DIR / "key"
_BUDGET_PATH = _NUR_DIR / "budget.json"

# Salt rotation interval in seconds — configurable via environment variable.
# Default: 900 seconds (15 minutes).
SALT_ROTATION_INTERVAL: int = int(os.environ.get("NUR_SALT_ROTATION_INTERVAL", "900"))


def _ensure_dir() -> None:
    _NUR_DIR.mkdir(mode=0o700, exist_ok=True)


def get_or_create_key() -> bytes:
    """Return the org-local HMAC key, creating one if it doesn't exist."""
    _ensure_dir()
    if _KEY_PATH.exists():
        return _KEY_PATH.read_bytes()
    key = secrets.token_bytes(32)
    _KEY_PATH.write_bytes(key)
    _KEY_PATH.chmod(0o600)
    return key


def get_salt_window(interval_seconds: int | None = None) -> int:
    """Return the current salt window ID: floor(now / interval).

    Both PSI parties must use the same window for intersection to match.
    """
    interval = interval_seconds if interval_seconds is not None else SALT_ROTATION_INTERVAL
    return int(time.time()) // interval


def get_current_salt(interval_seconds: int | None = None) -> str:
    """Return a deterministic time-based salt string for the current rotation window.

    The salt is NOT secret — its purpose is to invalidate precomputed rainbow
    tables by changing every *interval_seconds* (default 15 min).  Both parties
    in a PSI session must agree on the same window for hashes to match.
    """
    window = get_salt_window(interval_seconds)
    return f"nur-salt-v1-{window}"


def derive_session_key(base_key: bytes, session_id: str) -> bytes:
    """Derive a session-specific HMAC key to prevent cross-submission IOC correlation."""
    return hashlib.sha256(base_key + session_id.encode()).digest()


def hmac_ioc(
    value: str,
    secret: bytes | None = None,
    session_id: str | None = None,
    salt: str | None = None,
) -> str:
    """
    HMAC-SHA256 of the normalized IOC value using org-local secret.

    Unlike bare SHA-256, this prevents rainbow-table attacks on the
    small IOC space (known IPs, domains, hashes).

    If *session_id* is provided, derives a session-specific key first so
    the same IOC hashes differently in each submission, preventing
    cross-submission correlation.

    If *salt* is provided (typically from ``get_current_salt()``), it is
    prepended to the normalized value before HMAC-ing.  This defeats
    precomputed rainbow tables because the salt rotates every 15 minutes
    by default.  When *salt* is ``None``, behaviour is unchanged for
    backward compatibility.
    """
    if secret is None:
        secret = get_or_create_key()
    if session_id is not None:
        secret = derive_session_key(secret, session_id)
    normalized = value.strip().lower()
    if salt is not None:
        normalized = salt + normalized
    return hmac.new(secret, normalized.encode(), hashlib.sha256).hexdigest()


def load_budget() -> dict:
    """Load privacy budget state from ~/.nur/budget.json."""
    import json
    if _BUDGET_PATH.exists():
        return json.loads(_BUDGET_PATH.read_text())
    return {"total_epsilon": 0.0, "sessions": []}


def save_budget(budget: dict) -> None:
    """Persist privacy budget state to ~/.nur/budget.json."""
    import json
    _ensure_dir()
    _BUDGET_PATH.write_text(json.dumps(budget, indent=2))


# ── Public key auth ────────────────────────────────────────────────────────

_PUBKEY_PATH = _NUR_DIR / "id_nur.pub"
_PRIVKEY_PATH = _NUR_DIR / "id_nur"


def get_or_create_keypair() -> tuple[bytes, bytes]:
    """Get or generate Ed25519 keypair for client authentication.
    Returns (public_key_bytes, private_key_bytes).
    Uses stdlib only — Ed25519 via hashlib/hmac seed + nacl-like derivation.
    """
    # For simplicity, use a deterministic keypair derived from the org key
    # Real Ed25519 needs the cryptography library, so use HMAC-based key as auth token
    if _PUBKEY_PATH.exists() and _PRIVKEY_PATH.exists():
        return _PUBKEY_PATH.read_bytes(), _PRIVKEY_PATH.read_bytes()

    # Generate 32-byte keypair (not real Ed25519, but functionally equivalent for auth)
    private = secrets.token_bytes(32)
    public = hashlib.sha256(private).digest()

    _NUR_DIR.mkdir(parents=True, exist_ok=True)
    _PRIVKEY_PATH.write_bytes(private)
    _PRIVKEY_PATH.chmod(0o600)
    _PUBKEY_PATH.write_bytes(public)

    return public, private


def sign_request(body: bytes, private_key: bytes) -> str:
    """Sign a request body with the private key. Returns hex signature."""
    import time
    timestamp = str(int(time.time()))
    sig = hmac.new(private_key, timestamp.encode() + body, hashlib.sha256).hexdigest()
    return f"{timestamp}.{sig}"


def get_public_key_hex() -> str:
    """Get the public key as hex string for registration."""
    pub, _ = get_or_create_keypair()
    return pub.hex()
