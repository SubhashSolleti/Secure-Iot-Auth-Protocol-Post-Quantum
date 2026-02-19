"""
pq_commons – Shared cryptographic primitives and utilities.

Provides AEAD encryption (AES-GCM-256), HKDF-SHA256 key derivation,
SHA-256 hashing, hash-chain construction, pseudonym derivation,
and MsgPack serialisation helpers used by both client and server.
"""

import os
import time
import hashlib
from dataclasses import dataclass, field
from typing import Tuple, Dict, Any

import msgpack
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── Serialisation ────────────────────────────────────────────────────────

def pack(obj: Dict[str, Any]) -> bytes:
    """Serialize *obj* to a compact MsgPack binary."""
    return msgpack.packb(obj, use_bin_type=True)


def unpack(b: bytes) -> Dict[str, Any]:
    """Deserialize a MsgPack binary back to a dict."""
    return msgpack.unpackb(b, raw=False)


# ── Random bytes ─────────────────────────────────────────────────────────

def b32(n: int = 32) -> bytes:
    """Return *n* cryptographically random bytes (default 32)."""
    return os.urandom(n)


# ── Hashing ──────────────────────────────────────────────────────────────

def sha256(data: bytes) -> bytes:
    """Compute the SHA-256 digest of *data*."""
    return hashlib.sha256(data).digest()


# ── Key Derivation ───────────────────────────────────────────────────────

def hkdf_sha256(
    ikm: bytes,
    salt: bytes = b"",
    info: bytes = b"",
    length: int = 32,
) -> bytes:
    """Derive a key of *length* bytes from *ikm* using HKDF-SHA-256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt or None,
        info=info or None,
    )
    return hkdf.derive(ikm)


# ── Authenticated Encryption (AES-GCM-256) ──────────────────────────────

def aead_encrypt(key: bytes, ad: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt *plaintext* with AES-GCM.

    Returns (nonce, ciphertext).  A fresh 96-bit random nonce is generated
    for each call.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError(f"AES-GCM key must be 16/24/32 bytes, got {len(key)}")
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, ad)
    return nonce, ct


def aead_decrypt(
    key: bytes,
    ad: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    """
    Decrypt and authenticate *ciphertext* with AES-GCM.

    Raises ``cryptography.exceptions.InvalidTag`` on tampered data.
    """
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, ad)


# ── Hash Chains ──────────────────────────────────────────────────────────

def hash_chain_head(T: bytes, M_client: bytes, n: int) -> bytes:
    """
    Build a hash chain of length *n* from seed ``SHA-256(T) ∥ SHA-256(M_client)``
    and return the **head** (top of the chain).
    """
    seed = sha256(T) + sha256(M_client)
    h = seed
    for _ in range(n):
        h = sha256(h)
    return h


def hash_chain_prev(head: bytes, steps_from_head: int) -> bytes:
    """
    Walk *steps_from_head* additional hashes forward from *head*.

    Note: this produces a value *deeper* in the chain, not closer to the seed.
    """
    h = head
    for _ in range(steps_from_head):
        h = sha256(h)
    return h


# ── Pseudonym Derivation ────────────────────────────────────────────────

def derive_pseudonym(id_real: bytes, sd: bytes, a_i: bytes) -> bytes:
    """
    Derive an unlinkable pseudonym ``PSi`` from the real identity.

    ``PSi = SHA-256(ID_REAL ∥ SHA-256(SD ∥ A_I))``

    Different values of *a_i* (epoch nonce) produce different pseudonyms
    for the same device, preventing cross-session linkability.
    """
    mix = sha256(sd + a_i)
    return sha256(id_real + mix)


# ── Timing Utility ───────────────────────────────────────────────────────

@dataclass
class Timer:
    """Simple high-resolution stopwatch with named checkpoints."""

    t0: float = 0.0
    last: float = 0.0
    marks: Dict[str, float] = field(default_factory=dict)

    def start(self) -> None:
        """Reset and start the timer."""
        self.t0 = time.perf_counter()
        self.last = self.t0

    def mark(self, name: str) -> None:
        """Record elapsed milliseconds since the previous mark."""
        now = time.perf_counter()
        self.marks[name] = (now - self.last) * 1000.0
        self.last = now

    def total_ms(self) -> float:
        """Return total elapsed milliseconds since ``start()``."""
        return (time.perf_counter() - self.t0) * 1000.0
