import os
import time
import struct
import asyncio
import hashlib
from dataclasses import dataclass
from typing import Tuple, Dict, Any

import msgpack
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Maximum allowed message size (64 KB) — prevents memory exhaustion DoS
MAX_MSG_SIZE = 65536

def pack(obj: Dict[str, Any]) -> bytes:
    return msgpack.packb(obj, use_bin_type=True)

def unpack(b: bytes) -> Dict[str, Any]:
    return msgpack.unpackb(b, raw=False)

def b32(n: int = 32) -> bytes:
    return os.urandom(n)

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hkdf_sha256(ikm: bytes, salt: bytes = b"", info: bytes = b"", length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt if salt else None,
        info=info if info else None,
    )
    return hkdf.derive(ikm)

def aead_encrypt(key: bytes, ad: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES-GCM key must be 16/24/32 bytes")
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, ad)
    return nonce, ct

def aead_decrypt(key: bytes, ad: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, ad)

def derive_pseudonym(id_real: bytes, sd: bytes, a_i: bytes) -> bytes:
    """Derive a per-session unlinkable pseudonym (PSi_session).

    Different A_i values produce different pseudonyms, preventing
    cross-session linkability by the server or intermediaries.
    """
    mix = sha256(sd + a_i)
    return sha256(id_real + mix)


def derive_stable_pseudonym(id_real: bytes, sd: bytes) -> bytes:
    """Derive a stable pseudonym (PSi_stable) for sanctions screening.

    Uses a fixed domain separator instead of per-session A_i.
    PSi_stable is consistent across sessions, allowing intermediaries
    to screen against pre-loaded sanctions lists without learning ID_REAL.

    Privacy tradeoff: PSi_stable IS linkable across sessions by design.
    This is strictly better than full identity exposure (intermediary
    cannot learn name, DOB, address) but weaker than per-session
    unlinkability.
    """
    mix = sha256(sd + b"stable-screening-domain-v1")
    return sha256(id_real + mix)

async def send_msg(writer: asyncio.StreamWriter, obj: dict):
    """Length-prefixed MsgPack send with size validation."""
    data = msgpack.packb(obj, use_bin_type=True)
    if len(data) > MAX_MSG_SIZE:
        raise ValueError(f"Message too large: {len(data)} > {MAX_MSG_SIZE}")
    writer.write(struct.pack("!I", len(data)) + data)
    await writer.drain()


async def recv_msg(reader: asyncio.StreamReader) -> dict:
    """Length-prefixed MsgPack receive with size validation."""
    hdr = await reader.readexactly(4)
    (length,) = struct.unpack("!I", hdr)
    if length > MAX_MSG_SIZE:
        raise ValueError(f"Incoming message too large: {length} > {MAX_MSG_SIZE}")
    data = await reader.readexactly(length)
    return msgpack.unpackb(data, raw=False)


@dataclass
class Timer:
    t0: float = 0.0
    last: float = 0.0
    marks: Dict[str, float] = None

    def __post_init__(self):
        self.marks = {}

    def start(self):
        self.t0 = time.perf_counter()
        self.last = self.t0

    def mark(self, name: str):
        now = time.perf_counter()
        self.marks[name] = (now - self.last) * 1000.0
        self.last = now

    def total_ms(self) -> float:
        return (time.perf_counter() - self.t0) * 1000.0
