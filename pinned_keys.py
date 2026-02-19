"""
pinned_keys – Persistent ML-DSA-65 server identity and client-side pinning.

The server generates a long-lived ML-DSA-65 key-pair on first run and
persists it to ``SERVER_IDENTITY_DIR``.  Clients load the pinned public
key from ``PINNED_KEY_FILE`` and reject any m2 signed by a different key.
"""

import os
from typing import Tuple

from pqcrypto.sign.ml_dsa_65 import generate_keypair as sig_generate

from config import SERVER_IDENTITY_DIR, PINNED_KEY_FILE

_SK_FILE = "server_sig.sk"
_PK_FILE = "server_sig.pk"


def generate_and_save_server_identity(
    identity_dir: str = SERVER_IDENTITY_DIR,
) -> Tuple[bytes, bytes]:
    """
    Generate a fresh ML-DSA-65 key-pair and persist it to *identity_dir*.

    Returns ``(pk, sk)``.  If files already exist they are **overwritten**.
    """
    os.makedirs(identity_dir, exist_ok=True)
    pk, sk = sig_generate()
    with open(os.path.join(identity_dir, _PK_FILE), "wb") as f:
        f.write(pk)
    with open(os.path.join(identity_dir, _SK_FILE), "wb") as f:
        f.write(sk)
    return pk, sk


def load_server_identity(
    identity_dir: str = SERVER_IDENTITY_DIR,
) -> Tuple[bytes, bytes]:
    """
    Load the persistent server ML-DSA-65 signing key-pair.

    If the key-pair does not exist yet, it is generated and saved
    automatically (first-run behaviour).
    """
    pk_path = os.path.join(identity_dir, _PK_FILE)
    sk_path = os.path.join(identity_dir, _SK_FILE)

    if not (os.path.isfile(pk_path) and os.path.isfile(sk_path)):
        return generate_and_save_server_identity(identity_dir)

    with open(pk_path, "rb") as f:
        pk = f.read()
    with open(sk_path, "rb") as f:
        sk = f.read()
    return pk, sk


def export_pinned_pk(
    identity_dir: str = SERVER_IDENTITY_DIR,
    pinned_path: str = PINNED_KEY_FILE,
) -> bytes:
    """
    Copy the server public key to *pinned_path* for distribution to clients.

    Returns the public key bytes.
    """
    pk, _ = load_server_identity(identity_dir)
    with open(pinned_path, "wb") as f:
        f.write(pk)
    return pk


def load_pinned_pk(pinned_path: str = PINNED_KEY_FILE) -> bytes:
    """
    Load the client-side pinned server public key.

    Raises ``FileNotFoundError`` if the pinned key has not been
    distributed to the client yet.
    """
    with open(pinned_path, "rb") as f:
        return f.read()
