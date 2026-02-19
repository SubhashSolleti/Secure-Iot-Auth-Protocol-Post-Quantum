"""
KEM Adapter – Hybrid ML-KEM-768 + X25519 (with configurable fallback).

The hybrid scheme combines a post-quantum KEM (ML-KEM-768) with a classical
ECDH (X25519) so that an attacker must break *both* to recover the shared
secret.  A configurable policy controls whether a pure-PQ fallback is allowed.
"""

from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from config import KEM_FALLBACK_POLICY

# ── ML-KEM-768 public-key / ciphertext sizes ────────────────────────────
_PQ_PK_LEN = 1184
_PQ_CT_LEN = 1088

# --- Try Hybrid: ML-KEM-768 + X25519 ---
_hybrid_available = False
try:
    from pqcrypto.kem.ml_kem_768 import (
        generate_keypair as _pq_keygen,
        encrypt as _pq_encrypt,
        decrypt as _pq_decrypt,
    )

    def kem_name() -> str:
        """Return human-readable name of the active KEM suite."""
        return "hybrid.ml_kem_768+x25519"

    def kem_generate_keypair() -> Tuple[bytes, bytes]:
        """Generate a hybrid key-pair (PQ ∥ EC public key, (PQ sk, EC sk))."""
        pq_pk, pq_sk = _pq_keygen()
        ec_sk = X25519PrivateKey.generate()
        ec_pk = ec_sk.public_key().public_bytes_raw()
        return pq_pk + ec_pk, (pq_sk, ec_sk.private_bytes_raw())

    def kem_encaps(pk: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate: produce ciphertext and shared secret from a public key."""
        pq_pk, ec_pk = pk[:_PQ_PK_LEN], pk[_PQ_PK_LEN:]
        ct_pq, ss_pq = _pq_encrypt(pq_pk)
        ec_eph = X25519PrivateKey.generate()
        ct_ec = ec_eph.public_key().public_bytes_raw()
        ss_ec = ec_eph.exchange(X25519PublicKey.from_public_bytes(ec_pk))
        ss = HKDF(hashes.SHA256(), 32, None, b"hybrid-kem").derive(ss_pq + ss_ec)
        return ct_pq + ct_ec, ss

    def kem_decaps(sk, ct: bytes) -> bytes:
        """Decapsulate: recover the shared secret from a ciphertext."""
        pq_sk, ec_sk_bytes = sk
        ct_pq, ct_ec = ct[:_PQ_CT_LEN], ct[_PQ_CT_LEN:]
        ss_pq = _pq_decrypt(pq_sk, ct_pq)
        ec_sk = X25519PrivateKey.from_private_bytes(ec_sk_bytes)
        ss_ec = ec_sk.exchange(X25519PublicKey.from_public_bytes(ct_ec))
        return HKDF(hashes.SHA256(), 32, None, b"hybrid-kem").derive(ss_pq + ss_ec)

    _hybrid_available = True
    print("[KEM] Using hybrid ML-KEM-768 + X25519")

except Exception as e:
    print(f"[KEM] Hybrid init failed: {e}")

# --- Fallback: Pure ML-KEM-768 ---
if not _hybrid_available:
    if KEM_FALLBACK_POLICY == "strict":
        raise RuntimeError(
            "[KEM] Hybrid KEM unavailable and KEM_FALLBACK_POLICY='strict'. "
            "Install pqcrypto with X25519 support or set policy to 'relaxed'."
        )
    try:
        from pqcrypto.kem.ml_kem_768 import (
            generate_keypair as _pq_keygen,
            encrypt as _pq_encrypt,
            decrypt as _pq_decrypt,
        )

        def kem_name() -> str:
            return "pqcrypto.ml_kem_768"

        def kem_generate_keypair() -> Tuple[bytes, bytes]:
            return _pq_keygen()

        def kem_encaps(pk: bytes) -> Tuple[bytes, bytes]:
            return _pq_encrypt(pk)

        def kem_decaps(sk, ct: bytes) -> bytes:
            return _pq_decrypt(sk, ct)

        print("[KEM] Fallback to pure ML-KEM-768 (policy=relaxed)")
    except Exception as e2:
        raise RuntimeError(f"[KEM] No KEM backend available: {e2}") from e2