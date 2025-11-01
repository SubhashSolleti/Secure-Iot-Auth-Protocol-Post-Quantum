import os
import time
import hmac
import hashlib
from dataclasses import dataclass
from typing import Tuple, Dict, Any

import msgpack
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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

def hash_chain_head(T: bytes, M_client: bytes, n: int) -> bytes:
    seed = sha256(T) + sha256(M_client)
    h = seed
    for _ in range(n):
        h = sha256(h)
    return h

def hash_chain_prev(head: bytes, steps_from_head: int) -> bytes:
    h = head
    for _ in range(steps_from_head):
        h = sha256(h)
    return h

def derive_pseudonym(id_real: bytes, sd: bytes, a_i: bytes) -> bytes:
    mix = sha256(sd + a_i)
    return sha256(id_real + mix)

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
