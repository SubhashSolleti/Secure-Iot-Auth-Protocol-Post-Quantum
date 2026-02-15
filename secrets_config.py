"""
Simulated secure storage for device identity secrets.

In production, these values MUST come from a hardware security module (HSM),
a Trusted Platform Module (TPM), or an encrypted vault — NEVER from source code.
"""

import os

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
    "02" * 32
))

Z_I = bytes.fromhex(os.environ.get(
    "IOT_ZI_COMMITMENT",
    "03" * 32
))
