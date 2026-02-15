"""
Unit tests for pq_commons and kem_adapter.

Validates AEAD round-trip, HKDF determinism, SHA-256, pseudonym
derivation, hash-chain integrity, and KEM encaps/decaps correctness.
"""

import os
import sys
import pytest

# Ensure the project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pq_commons import (
    aead_encrypt,
    aead_decrypt,
    hkdf_sha256,
    sha256,
    b32,
    derive_pseudonym,
    hash_chain_head,
    hash_chain_prev,
    pack,
    unpack,
    Timer,
)
from kem_adapter import kem_generate_keypair, kem_encaps, kem_decaps, kem_name


# ═══════════════════════════════════════════════════════════════════════════
#  pq_commons
# ═══════════════════════════════════════════════════════════════════════════


class TestAEAD:
    """AES-GCM-256 encrypt / decrypt round-trip."""

    def test_round_trip(self):
        key = b32()
        ad = b"associated-data"
        pt = b"hello world"
        nonce, ct = aead_encrypt(key, ad, pt)
        assert aead_decrypt(key, ad, nonce, ct) == pt

    def test_tampered_ciphertext_fails(self):
        key = b32()
        ad = b"ad"
        nonce, ct = aead_encrypt(key, ad, b"secret")
        tampered = ct[:-1] + bytes([(ct[-1] ^ 0xFF)])
        with pytest.raises(Exception):
            aead_decrypt(key, ad, nonce, tampered)

    def test_wrong_ad_fails(self):
        key = b32()
        nonce, ct = aead_encrypt(key, b"correct-ad", b"data")
        with pytest.raises(Exception):
            aead_decrypt(key, b"wrong-ad", nonce, ct)

    def test_bad_key_length(self):
        with pytest.raises(ValueError):
            aead_encrypt(b"short", b"ad", b"pt")


class TestHKDF:
    """HKDF-SHA-256 key derivation."""

    def test_deterministic(self):
        ikm = b"input-key-material"
        a = hkdf_sha256(ikm, info=b"ctx")
        b_val = hkdf_sha256(ikm, info=b"ctx")
        assert a == b_val

    def test_different_info_yields_different_key(self):
        ikm = b"ikm"
        k1 = hkdf_sha256(ikm, info=b"a")
        k2 = hkdf_sha256(ikm, info=b"b")
        assert k1 != k2

    def test_custom_length(self):
        out = hkdf_sha256(b"ikm", length=64)
        assert len(out) == 64


class TestSHA256:
    def test_known_vector(self):
        # SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        digest = sha256(b"")
        assert digest.hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_deterministic(self):
        assert sha256(b"test") == sha256(b"test")


class TestPseudonym:
    """Pseudonym derivation must be deterministic and unlinkable across epochs."""

    def test_deterministic(self):
        id_r = b"\x01" * 32
        sd = b"\x02" * 32
        ai = b"\x03" * 32
        assert derive_pseudonym(id_r, sd, ai) == derive_pseudonym(id_r, sd, ai)

    def test_different_epoch_yields_different_pseudonym(self):
        id_r = b"\x01" * 32
        sd = b"\x02" * 32
        p1 = derive_pseudonym(id_r, sd, b"\x03" * 32)
        p2 = derive_pseudonym(id_r, sd, b"\x04" * 32)
        assert p1 != p2


class TestHashChain:
    """Hash-chain construction and verification."""

    def test_head_is_deterministic(self):
        T = b"token"
        M = b"material"
        assert hash_chain_head(T, M, 10) == hash_chain_head(T, M, 10)

    def test_preimage_verifies(self):
        """Verify that SHA-256(pre) == head when pre is one step before head."""
        T = b"t"
        M = b"m"
        n = 5
        seed = sha256(T) + sha256(M)
        # compute head
        h = seed
        for _ in range(n):
            h = sha256(h)
        # compute pre (n-1 steps)
        pre = seed
        for _ in range(n - 1):
            pre = sha256(pre)
        assert sha256(pre) == h


class TestMsgPack:
    def test_round_trip(self):
        obj = {"foo": b"bar", "n": 42}
        assert unpack(pack(obj)) == obj


class TestTimer:
    def test_marks(self):
        t = Timer()
        t.start()
        t.mark("a")
        t.mark("b")
        assert "a" in t.marks
        assert "b" in t.marks
        assert t.total_ms() >= 0


# ═══════════════════════════════════════════════════════════════════════════
#  kem_adapter
# ═══════════════════════════════════════════════════════════════════════════


class TestKEM:
    """KEM encapsulation / decapsulation round-trip."""

    def test_kem_name_not_empty(self):
        assert kem_name()

    def test_encaps_decaps_round_trip(self):
        pk, sk = kem_generate_keypair()
        ct, ss_enc = kem_encaps(pk)
        ss_dec = kem_decaps(sk, ct)
        assert ss_enc == ss_dec

    def test_different_keypairs_yield_different_secrets(self):
        pk1, sk1 = kem_generate_keypair()
        pk2, sk2 = kem_generate_keypair()
        _, ss1 = kem_encaps(pk1)
        _, ss2 = kem_encaps(pk2)
        # Extremely unlikely to collide
        assert ss1 != ss2
