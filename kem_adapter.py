from typing import Tuple
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# --- Try Hybrid: ML-KEM-768 + X25519 ---
try:
    from pqcrypto.kem.ml_kem_768 import generate_keypair, encrypt, decrypt  # ← CORRECT NAME

    def kem_name() -> str:
        return "hybrid.ml_kem_768+x25519"

    def kem_generate_keypair() -> Tuple[bytes, bytes]:
        pq_pk, pq_sk = generate_keypair()  # ← NO underscore
        ec_sk = X25519PrivateKey.generate()
        ec_pk = ec_sk.public_key().public_bytes_raw()
        return pq_pk + ec_pk, (pq_sk, ec_sk.private_bytes_raw())

    def kem_encaps(pk: bytes) -> Tuple[bytes, bytes]:
        pq_pk, ec_pk = pk[:1184], pk[1184:]
        ct_pq, ss_pq = encrypt(pq_pk)
        ec_eph = X25519PrivateKey.generate()
        ct_ec = ec_eph.public_key().public_bytes_raw()
        ss_ec = ec_eph.exchange(X25519PublicKey.from_public_bytes(ec_pk))
        ss = HKDF(hashes.SHA256(), 32, None, b"hybrid").derive(ss_pq + ss_ec)
        return ct_pq + ct_ec, ss

    def kem_decaps(sk: bytes, ct: bytes) -> bytes:
        pq_sk, ec_sk_bytes = sk
        ct_pq, ct_ec = ct[:1088], ct[1088:]
        ss_pq = decrypt(pq_sk, ct_pq)
        ec_sk = X25519PrivateKey.from_private_bytes(ec_sk_bytes)
        ss_ec = ec_sk.exchange(X25519PublicKey.from_public_bytes(ct_ec))
        return HKDF(hashes.SHA256(), 32, None, b"hybrid").derive(ss_pq + ss_ec)

    print("[KEM] Using hybrid ML-KEM-768 + X25519")
except Exception as e:
    print(f"[KEM] Hybrid failed: {e}")
    # --- Fallback: Pure ML-KEM-768 ---
    try:
        from pqcrypto.kem.ml_kem_768 import generate_keypair, encrypt, decrypt
        def kem_name() -> str: return "pqcrypto.ml_kem_768"
        def kem_generate_keypair() -> Tuple[bytes, bytes]: return generate_keypair()
        def kem_encaps(pk: bytes) -> Tuple[bytes, bytes]: return encrypt(pk)
        def kem_decaps(sk: bytes, ct: bytes) -> bytes: return decrypt(sk, ct)
        print("[KEM] Fallback to pure ML-KEM-768")
    except Exception as e2:
        print(f"[KEM] Pure fallback also failed: {e2}")
        raise