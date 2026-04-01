"""
baseline_tls_sim.py — Classical KYC Authentication Baseline Simulator

Simulates a standard TLS 1.3-style KYC handshake WITHOUT post-quantum
protection and WITHOUT pseudonymization. Used as a comparison baseline
for benchmarking PQ-PKAP against traditional KYC authentication.

Baseline design:
  - X25519 ECDH key exchange (no KEM, no lattice crypto)
  - AES-256-GCM for payload encryption
  - ECDSA / HMAC-based identity verification (no PQ signatures)
  - FULL identity transmitted on the wire on each session (no pseudonyms)

This baseline represents the current-state KYC API handshake at a typical
Indian fintech (e.g., bank portal login + Aadhaar eKYC API call pattern).

Usage:
    python baseline_tls_sim.py           # runs 100 baseline sessions
    python baseline_tls_sim.py --n 50    # custom run count
"""

import asyncio
import os
import time
import struct
import hashlib
import statistics
import argparse
import psutil

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ─────────────────────────── Helpers ────────────────────────────

def aead_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce, ct


def aead_decrypt(key: bytes, nonce: bytes, ct: bytes) -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None)


def x25519_handshake() -> bytes:
    """Simulate X25519 ECDH key exchange — returns 32-byte shared secret."""
    server_sk = X25519PrivateKey.generate()
    server_pk = server_sk.public_key()

    client_sk = X25519PrivateKey.generate()
    client_pk = client_sk.public_key()

    # Both sides compute the same shared secret
    ss_client = client_sk.exchange(server_pk)
    ss_server = server_sk.exchange(client_pk)
    assert ss_client == ss_server  # sanity check

    return ss_client


def derive_session_key(ss: bytes, salt: bytes = b"") -> bytes:
    """Derive a session key from shared secret via HKDF."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt or None,
        info=b"classic-session-key"
    ).derive(ss)


# ─────────────────────── Identity Simulation ─────────────────────────
# In traditional KYC, the full identity is transmitted on every auth request.
# We simulate this by constructing a 128-byte "identity payload" that includes
# items equivalent to: Aadhaar number hash + PAN hash + session timestamp.

def build_identity_payload(id_real: bytes) -> bytes:
    """
    Build a classical KYC identity payload sent on each auth session.
    In real systems this might be: masked Aadhaar number, encrypted PAN,
    timestamp, device fingerprint, etc.

    Data exposure: full identity-derived data on EVERY session.
    """
    timestamp = int(time.time()).to_bytes(8, "big")
    nonce = os.urandom(16)                        # per-session nonce
    identity_hash = hashlib.sha256(id_real).digest()  # "masked" ID still ID-derived
    return identity_hash + timestamp + nonce      # 56 bytes of identity data per session


def bytes_exposed_per_session(payload: bytes) -> int:
    """Return number of bytes of identity-linked data exposed per session."""
    # identity_hash (32 bytes) is always exposed to the server
    return 32


# ─────────────────────── Single Session Simulation ─────────────────────

def run_baseline_session(id_real: bytes) -> dict:
    """
    Simulate one complete classical KYC auth session.

    Steps:
      1. X25519 ECDH key exchange
      2. Session key derivation via HKDF
      3. Client constructs full identity payload (no pseudonym)
      4. AEAD encrypt and "transmit" payload
      5. Server "decrypts" and verifies
      6. Session complete

    Returns timing and metadata.
    """
    t_start = time.perf_counter()

    # Step 1: Key exchange
    ss = x25519_handshake()
    t_ecdh = time.perf_counter()

    # Step 2: Session key
    K_sess = derive_session_key(ss)
    t_kdf = time.perf_counter()

    # Step 3: Build full identity payload (data exposure on every session)
    identity_payload = build_identity_payload(id_real)
    data_exposure_bytes = bytes_exposed_per_session(identity_payload)

    # Step 4: Encrypt identity payload
    nonce, ctext = aead_encrypt(K_sess, identity_payload)
    t_enc = time.perf_counter()

    # Step 5: Decrypt (server side simulation)
    recovered = aead_decrypt(K_sess, nonce, ctext)
    assert recovered == identity_payload
    t_dec = time.perf_counter()

    total_ms = (t_dec - t_start) * 1000.0

    # Bandwidth: server pk (32) + client pk (32) + ciphertext (~84)
    # In reality TLS adds certificates; we simulate bare minimum
    bandwidth_bytes = 32 + 32 + len(ctext) + 12  # ec_pks + ctext + nonce

    return {
        "total_ms": total_ms,
        "ecdh_ms": (t_ecdh - t_start) * 1000.0,
        "kdf_ms": (t_kdf - t_ecdh) * 1000.0,
        "enc_ms": (t_enc - t_kdf) * 1000.0,
        "dec_ms": (t_dec - t_enc) * 1000.0,
        "bandwidth_bytes": bandwidth_bytes,
        "data_exposure_bytes": data_exposure_bytes,
    }


# ─────────────────────── Benchmark Runner ─────────────────────────

def run_benchmark(n: int = 100):
    print(f"\n{'='*60}")
    print(f"CLASSICAL KYC BASELINE BENCHMARK  (n={n})")
    print(f"  Key exchange:  X25519 ECDH (no PQ)")
    print(f"  Encryption:    AES-256-GCM")
    print(f"  Identity:      FULL identity transmitted per session (no pseudonyms)")
    print(f"{'='*60}")

    # Simulate a fixed client identity
    id_real = os.urandom(32)

    latencies = []
    bandwidths = []
    exposures = []
    cpu_usages = []
    process = psutil.Process()

    for i in range(n):
        cpu_before = process.cpu_percent(interval=None)
        result = run_baseline_session(id_real)
        cpu_after = process.cpu_percent(interval=None)

        latencies.append(result["total_ms"])
        bandwidths.append(result["bandwidth_bytes"])
        exposures.append(result["data_exposure_bytes"])
        cpu_usages.append(max(cpu_after - cpu_before, 0.0))

        if (i + 1) % 10 == 0:
            print(f"  Run {i+1:>3}/{n}: {result['total_ms']:.3f} ms | "
                  f"{result['bandwidth_bytes']} B | "
                  f"{result['data_exposure_bytes']} B exposed")

    print(f"\n{'─'*60}")
    print(f"RESULTS")
    print(f"{'─'*60}")
    print(f"Latency (ms):")
    print(f"  Mean:  {statistics.mean(latencies):.3f} ± {statistics.stdev(latencies):.3f}")
    print(f"  Min:   {min(latencies):.3f}")
    print(f"  Max:   {max(latencies):.3f}")
    print(f"  p50:   {sorted(latencies)[n // 2]:.3f}")
    print(f"  p99:   {sorted(latencies)[int(n * 0.99)]:.3f}")
    print(f"\nBandwidth (bytes/session):")
    print(f"  Mean:  {statistics.mean(bandwidths):.0f}")
    print(f"\nData Exposure (identity bytes/session):")
    print(f"  Per session: {statistics.mean(exposures):.0f} bytes  ← IDENTITY LEAKS EVERY SESSION")
    print(f"  Over {n} sessions: {sum(exposures)} bytes total identity data exposed")
    print(f"\nCPU usage: {statistics.mean(cpu_usages):.2f}% per session")
    print(f"\nQuantum resistance: ❌  (X25519 broken by Shor's algorithm)")
    print(f"Pseudonymization:   ❌  (ID transmitted every session)")
    print(f"Forward secrecy:    ✅  (ephemeral ECDH)")

    return {
        "scheme": "Classical-X25519+AES256GCM (no PQ, no pseudonyms)",
        "n": n,
        "latency_mean_ms": statistics.mean(latencies),
        "latency_stdev_ms": statistics.stdev(latencies),
        "latency_p50_ms": sorted(latencies)[n // 2],
        "latency_p99_ms": sorted(latencies)[int(n * 0.99)],
        "bandwidth_mean_bytes": statistics.mean(bandwidths),
        "data_exposure_bytes_per_session": statistics.mean(exposures),
        "cpu_mean_pct": statistics.mean(cpu_usages),
        "quantum_resistant": False,
        "pseudonymized": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Classical KYC Baseline Benchmark")
    parser.add_argument("--n", type=int, default=100, help="Number of sessions to simulate")
    args = parser.parse_args()
    run_benchmark(n=args.n)
