"""
Simulated secure storage for device identity secrets.

In production, these values MUST come from a hardware security module (HSM),
a Trusted Platform Module (TPM), or an encrypted vault — NEVER from source code.

Includes automatic pseudonym rotation: after every ``PSEUDONYM_ROTATE_EVERY``
sessions, ``A_I`` is regenerated to produce a fresh, unlinkable pseudonym.
"""

import os
import json
from pathlib import Path

import config as _config

# ── Persistent state file for rotation counter ───────────────────────────
_STATE_FILE = Path("device_state.json")


def _load_state() -> dict:
    """Load persisted device state from disk."""
    if _STATE_FILE.is_file():
        with open(_STATE_FILE, "r") as f:
            return json.load(f)
    return {"session_count": 0, "a_i_hex": "02" * 32}


def _save_state(state: dict) -> None:
    """Persist device state to disk."""
    with open(_STATE_FILE, "w") as f:
        json.dump(state, f)


_state = _load_state()

# ── Device Identity ──────────────────────────────────────────────────────
# ID_REAL : The true device identifier (e.g., a serial number).
# SD      : A secret diversifier used to derive unlinkable pseudonyms.
# A_I     : An epoch / rotation nonce for pseudonym freshness.
# Z_I     : A pre-shared commitment the server uses to verify the client.

ID_REAL = os.environ.get(
    "IOT_DEVICE_ID",
    "demo-user-id-1234567890"
).encode().ljust(32, b'\x00')

SD = bytes.fromhex(os.environ.get(
    "IOT_SECRET_DIVERSIFIER",
    "01" * 32
))

A_I = bytes.fromhex(os.environ.get(
    "IOT_EPOCH_NONCE",
    _state.get("a_i_hex", "02" * 32),
))

Z_I = bytes.fromhex(os.environ.get(
    "IOT_ZI_COMMITMENT",
    "03" * 32
))


def rotate_epoch() -> bytes:
    """
    Increment the session counter and rotate ``A_I`` if the threshold is hit.

    Returns the current (possibly updated) ``A_I`` value.
    """
    global A_I
    _state["session_count"] = _state.get("session_count", 0) + 1

    if _state["session_count"] >= _config.PSEUDONYM_ROTATE_EVERY:
        new_a_i = os.urandom(32)
        _state["a_i_hex"] = new_a_i.hex()
        _state["session_count"] = 0
        A_I = new_a_i
        _save_state(_state)
        return A_I

    _save_state(_state)
    return A_I


def get_session_count() -> int:
    """Return the current session count since last rotation."""
    return _state.get("session_count", 0)
