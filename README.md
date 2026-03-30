# Secure IoT Auth Protocol: Post-Quantum

A post-quantum, pseudonym-based authentication protocol for privacy-preserving IoT communication.

## 🚀 Overview

This project implements a secure, quantum-resistant client-server authentication system over TCP. It leverages NIST-standardized post-quantum cryptography (**ML-KEM-768**, **ML-DSA-65**) in a hybrid configuration with **X25519** for dual classical + quantum protection.

The protocol uses a custom 5-message handshake with pseudonym-based privacy, mutual authentication via TOFU (Trust On First Use), and directional session keys bound to the full handshake transcript.

### Key Features
- **Hybrid PQC Key Exchange**: ML-KEM-768 + X25519 combiner via HKDF — secure as long as *either* algorithm holds.
- **Long-Term Identity Authentication**: Persistent ML-DSA-65 signing keys with TOFU peer pinning prevent MITM attacks.
- **Pseudonym-Based Privacy**: Derives unlinkable pseudonyms `PSi = SHA256(ID ‖ SHA256(SD ‖ A_i))` to hide real device identities.
- **Directional Session Keys**: Separate client→server (`K_c2s`) and server→client (`K_s2c`) AEAD keys prevent reflection attacks.
- **Transcript Binding**: Session keys are bound to `SHA256(serv_pub ‖ m1 ‖ m2)`, preventing unknown-key-share attacks.
- **Mutual Authentication**: Server proves knowledge of `SHA256(z_i ‖ w_i)` in m2; `w_i` rotated per session for forward secrecy.
- **Replay Protection**: Timestamps (±5s window), random nonces, and challenge-response liveness checks.
- **Rate Limiting & Timeouts**: Per-IP connection throttling and 30-second message timeouts prevent DoS.
- **Secure Key Storage**: Identity private keys restricted to `0o600` (owner-only); secrets never hardcoded.

## 📖 Quick Start

### Prerequisites
- Python ≥ 3.11
- Dependencies: `pqcrypto`, `cryptography`, `msgpack`, `psutil` (see `requirements.txt`)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/SubhashSolleti/Secure-Iot-Auth-Protocol-Post-Quantum.git
   cd Secure-Iot-Auth-Protocol-Post-Quantum
   ```
2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
3. Run the server:
   ```bash
   python server.py
   ```
4. Run the client (in another terminal):
   ```bash
   python client.py
   ```
5. (Optional) Run the benchmark:
   ```bash
   python benchmark.py
   ```

### First Run
On first run, the system automatically generates and persists:
- **Server**: Long-term ML-DSA-65 identity key → `server_data/identity/`
- **Client**: Long-term ML-DSA-65 identity key → `client_data/identity/`, device secrets → `client_data/device_secrets.json`
- **TOFU pinning**: Both sides pin each other's public key on first connection
- **w_i provisioning**: Server provisions client with encrypted `w_i` for future mutual authentication

Subsequent runs reuse persisted keys and verify identities against pinned keys.

## 🛠️ Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Project Structure                          │
├──────────────────────────────────────────────────────────────────────┤
│  client.py        Protocol client — handshake, auth, hash chain     │
│  server.py        Protocol server — handshake, auth, provisioning   │
│  identity.py      Long-term ML-DSA-65 key management (TOFU)        │
│  kem_adapter.py   Hybrid KEM abstraction (ML-KEM-768 + X25519)     │
│  pq_commons.py    Shared crypto primitives (AEAD, HKDF, SHA-256)   │
│  benchmark.py     Latency & CPU benchmarking (n=100 sessions)      │
├──────────────────────────────────────────────────────────────────────┤
│  client_data/     Auto-generated client identity, secrets, w_i     │
│  server_data/     Auto-generated server identity keys              │
│  server_pseudonyms.db  SQLite — pseudonyms + TOFU key bindings     │
└──────────────────────────────────────────────────────────────────────┘
```

| Component | Description | Technology |
|-----------|-------------|------------|
| Client | IoT device identity, handshake initiation, hash-chain generation | Python asyncio, pqcrypto |
| Server | Authentication, pseudonym provisioning, w_i rotation | SQLite, asyncio.Lock |
| Identity | Persistent ML-DSA-65 keypairs, TOFU peer key pinning | pqcrypto, file-based storage (0o600) |
| KEM Adapter | Hybrid ML-KEM-768 + X25519 with automatic fallback | pqcrypto, cryptography |
| Crypto Commons | AES-256-GCM AEAD, HKDF-SHA256, SHA-256, pseudonym derivation | cryptography (pyca) |
| Protocol I/O | Length-prefixed MsgPack with 64 KB message size limit | msgpack, asyncio TCP |

## 🔬 Algorithms

| Algorithm | Family | Standard | Purpose | Security Level |
|-----------|--------|----------|---------|----------------|
| **ML-KEM-768** | PQ KEM (Lattice) | NIST FIPS 203 | Key encapsulation (shared secret) | Level 3 (~AES-192) |
| **X25519** | Classical ECDH | RFC 7748 | Hybrid KEM combiner | ~128-bit classical |
| **ML-DSA-65** | PQ Signature (Lattice) | NIST FIPS 204 | Long-term identity authentication (m₁/m₂) | Level 3 (~AES-192) |
| **AES-256-GCM** | Symmetric AEAD | NIST SP 800-38D | Authenticated encryption (all payloads) | 256-bit / 128-bit PQ |
| **HKDF-SHA256** | KDF | RFC 5869 | Derive directional session keys (`K_c2s`, `K_s2c`) | Domain-separated |
| **SHA-256** | Hash | FIPS 180-4 | Pseudonyms, transcript binding, w_i rotation, hash chains | 128-bit PQ (Grover) |

### Hybrid KEM Construction
```
ss_hybrid = HKDF-SHA256(ss_pq ‖ ss_ec, info="hybrid")
```
- ML-KEM-768 ciphertext: 1,088 bytes, public key: 1,184 bytes
- X25519 ciphertext: 32 bytes (ephemeral public key)
- Combined ciphertext: **1,120 bytes** per handshake

## 🔐 Protocol Flow

```
Client                                            Server
  │                                                 │
  │◄──────── hello { serv_pub } ───────────────────│  KEM keypair generated
  │                                                 │
  │  KEM.Encaps(serv_pub) → (ct, ss)                │
  │  PSi = SHA256(ID ‖ SHA256(SD ‖ A_i))            │
  │  env = PSi ‖ NEV ‖ t1 ‖ z_i                     │
  │  AEAD encrypt env with HKDF(ss)                  │
  │  Sign payload with long-term ML-DSA-65 key       │
  │                                                 │
  │──── m1 { payload, sig, sig_pk } ──────────────►│
  │                                                 │  Verify sig against sig_pk
  │                                                 │  KEM.Decaps → ss
  │                                                 │  Decrypt → PSi, NEV, t1, z_i
  │                                                 │  Check |t1 - now| ≤ 5s
  │                                                 │  TOFU: pin or verify sig_pk for PSi
  │                                                 │  Verify z_i against DB
  │                                                 │
  │                                                 │  env₂ = T ‖ NS ‖ t2 ‖ SHA256(z_i‖w_i)
  │                                                 │  Sign payload with long-term key
  │◄──── m2 { payload, sig, sig_pk } ─────────────│
  │                                                 │
  │  Verify sig, TOFU pin/verify server key          │
  │  Decrypt → T, NS, t2, zi⊕wi                     │
  │  Check |t2 - now| ≤ 5s                          │
  │  Verify zi⊕wi (if w_i known)                    │
  │                                                 │
  │  ── Transcript-bound directional keys ──         │
  │  transcript = SHA256(serv_pub ‖ m1 ‖ m2)         │
  │  K_c2s = HKDF(ss‖NEV‖NS‖transcript, "c2s")      │
  │  K_s2c = HKDF(ss‖NEV‖NS‖transcript, "s2c")      │
  │                                                 │
  │──── m4 { AEAD(K_c2s, PSi‖N_edge‖t4) } ───────►│
  │                                                 │  Decrypt with K_c2s
  │◄──── m5 { AEAD(K_s2c, N_edge+1) } ────────────│  Liveness proof
  │                                                 │
  │  Verify N_edge+1 (liveness ✓)                    │
  │                                                 │
  │◄── provision { AEAD(K_s2c, w_i) } ────────────│  w_i (new or rotated)
  │  Save w_i for next session                       │
  │                                                 │
  │──── hash_commit { head = H^n(seed) } ─────────►│  Client-generated chain
  │◄──── hash_challenge ──────────────────────────│
  │──── hash_reveal { pre = H^(n-1)(seed) } ──────►│
  │◄──── hash_ok { ok: H(pre)==head } ────────────│  Integrity verified
  │                                                 │
```

### Session Key Derivation
```
transcript_hash = SHA256(serv_pub ‖ m1_payload ‖ m2_payload)

K_c2s = HKDF-SHA256(ss ‖ NEV ‖ NS ‖ transcript_hash, info="kdf-sess-c2s")  →  client encrypts
K_s2c = HKDF-SHA256(ss ‖ NEV ‖ NS ‖ transcript_hash, info="kdf-sess-s2c")  →  server encrypts
```

### W_I Rotation
```
Returning clients:  new_w_i = SHA256(old_w_i ‖ T)     # T = per-session random
New clients:        w_i = random(32)                    # Provisioned on first connection
```

## 🛡️ Security Properties

| Property | Mechanism |
|----------|-----------|
| **Quantum resistance** | ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204) |
| **Classical hedge** | Hybrid KEM with X25519 — secure if either algorithm holds |
| **Forward secrecy** | Ephemeral KEM keypair per connection; w_i rotated per session |
| **MITM prevention** | Long-term ML-DSA-65 identity keys with TOFU pinning |
| **Replay protection** | Timestamps (±5s), 256-bit random nonces, liveness challenge |
| **Reflection attack prevention** | Directional session keys (K_c2s ≠ K_s2c) |
| **Unknown-key-share prevention** | Session keys bound to handshake transcript hash |
| **Mutual authentication** | Server proves `SHA256(z_i ‖ w_i)` in m2; verified by client |
| **Identity privacy** | Pseudonyms `PSi` hide real device identifiers |
| **Timing-safe comparisons** | `secrets.compare_digest()` for all secret comparisons |
| **Secure key storage** | Private keys `0o600`; CSPRNG (`os.urandom`) for all randomness |
| **DoS resistance** | 64 KB message limit, 30s timeouts, IP rate limiting (20 conn/min) |

## 📊 Performance

| Metric | Value | Notes |
|--------|-------|-------|
| Full handshake latency | ~4–13 ms | Desktop (Apple Silicon), includes all crypto |
| Handshake bandwidth | ~12.5 KB | ML-DSA-65 signatures dominate (3,293 B each) |
| KEM public key | 1,216 B | ML-KEM-768 (1,184) + X25519 (32) |
| KEM ciphertext | 1,120 B | ML-KEM-768 (1,088) + X25519 (32) |
| Signature size | 3,293 B | ML-DSA-65 |
| Signing public key | 1,952 B | ML-DSA-65 |

Run `python benchmark.py` for detailed latency statistics (mean, stdev, p50, p99).

## 🤝 Contributing

Contributions are welcome!

1. Fork the repo.
2. Create a feature branch: `git checkout -b feature/your-feature`.
3. Commit changes: `git commit -m 'Add your feature'`.
4. Push: `git push origin feature/your-feature`.
5. Open a pull request.

## 🙏 Acknowledgments

- [pqcrypto](https://github.com/pqclean/pqclean) for post-quantum primitives (ML-KEM-768, ML-DSA-65).
- [pyca/cryptography](https://cryptography.io/) for X25519, AES-GCM, and HKDF.

---

⭐ **Star this repo if you find it useful!**  
Questions or issues? Open an [issue](https://github.com/SubhashSolleti/Secure-Iot-Auth-Protocol-Post-Quantum) or reach out on [LinkedIn](https://www.linkedin.com/in/solletikrishnachaitanyasubhash).
