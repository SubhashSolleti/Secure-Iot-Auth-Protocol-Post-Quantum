# PQ-PKAP: Post-Quantum Pseudonymous KYC Authentication Protocol

> A privacy-preserving, audit-compliant authentication protocol for fintech and KYC-regulated financial services — using hybrid post-quantum cryptography and deterministic pseudonymization.

---

## 🔬 Research Summary

This repository contains the research prototype for **PQ-PKAP**, a post-quantum authentication protocol that enables KYC-verified financial service clients to authenticate without transmitting their real identity (`ID_REAL`) in any session.

### Core Privacy Claim

> The service provider authenticates a KYC-verified client via a derived pseudonym **PSi** — without ever receiving or storing the client's real identity. Lawful de-anonymization is preserved via a Provisioning Authority (PA) under regulatory mandate.

```
PSi := SHA-256(ID_REAL ‖ SHA-256(SD ‖ A_i))
```

Where `{ID_REAL, SD, A_i}` are all client-side secrets. The server sees only `PSi` — deriving `ID_REAL` from it requires knowledge of `SD` and `A_i`, both of which remain on the client device.

### Novel Contributions

1. **Pseudonymized Post-Quantum KYC Handshake**: A 5-message hybrid PQC protocol (ML-KEM-768 + X25519 + ML-DSA-65) with per-session deterministic pseudonymization — the first to combine NIST FIPS 203/204 post-quantum standards with audit-compliant identity minimization for financial KYC.

2. **Transcript-Bound Directional Session Keys**: Session keys `K_c2s` and `K_s2c` are bound to the full handshake transcript `H(serv_pub ‖ m1 ‖ m2)`, preventing unknown-key-share and reflection attacks in a quantum-threatening environment.

3. **Forward-Secure Mutual Authentication**: Per-session `w_i` ratchet rotation (`w_i_new = SHA-256(w_i_old ‖ T)`) provides forward secrecy for the authentication chain beyond ephemeral KEM forward secrecy.

### Honest Framing

This protocol is **pseudonymization + selective disclosure** — not a zero-knowledge proof system. The pseudonym achieves per-session unlinkability under SHA-256 second-preimage hardness. Reviewers should note:
- ✅ Per-session unlinkability (different `A_i` → computationally independent `PSi`)
- ✅ Audit-compliant: PA can de-anonymize under regulatory mandate
- ❌ NOT anonymization — PA retains `(ID_REAL → PSi)` mapping
- ❌ NOT zero-knowledge — no proof system is implemented

---

## 🏛️ Regulatory Compatibility

| Regulation | Status | Notes |
|---|---|---|
| **RBI KYC Master Direction 2016** | ✅ Compatible | PA maps to KYC entity; STR de-anonymization preserved |
| **GDPR Art. 5 (Data Minimisation)** | ✅ Satisfied by construction | Server structurally cannot receive ID_REAL |
| **GDPR Art. 25 (Privacy by Design)** | ✅ Architectural enforcement | |
| **FATF Rec. 10 (CDD)** | ✅ Compatible | AML monitoring at PSi level; de-anon on order |
| **PMLA 2002** | ✅ Compatible | PA = certified KYC intermediary |
| **NIST FIPS 203/204** | ✅ Direct compliance | ML-KEM-768 + ML-DSA-65 |
| **DPDPA 2023** | ✅ Compatible | Server = Data Processor; PA = Data Fiduciary |

Full analysis: see [`regulatory_analysis.md`](./regulatory_analysis.md)

---

## 🔐 Protocol Overview

```
Client (KYC user)                                   Server (KYC gateway)
──────────────────────                              ──────────────────────
Holds: ID_REAL, SD, A_i, z_i                        Holds: PSi DB, z_i
       pk_C, sk_C (ML-DSA-65)                              pk_S, sk_S

                          ◄── hello { serv_pub } ──
Derives PSi locally (ID_REAL never leaves device)
KEM.Encaps(serv_pub) → (ct, ss)
Encrypts: PSi ‖ NEV ‖ t1 ‖ z_i with AEAD(HKDF(ss))
Signs m1 with sk_C

── m1 { payload, σ₁, pk_C } ──────────────────────►
                                          Verify σ₁ via pk_C
                                          KEM.Decaps → ss
                                          Decrypt → PSi, z_i
                                          TOFU bind pk_C to PSi
                                          Verify z_i against DB
── m2 { payload, σ₂, pk_S } ◄─────────────────────
Verify σ₂, TOFU pin pk_S                 Signs m2 with sk_S
Verify H(z_i ‖ w_i) [mutual auth]

── Transcript-bound directional session keys ──
  τ = H(serv_pub ‖ m1 ‖ m2)
  K_c2s = HKDF(ss ‖ NEV ‖ NS ‖ τ, "kdf-sess-c2s")
  K_s2c = HKDF(ss ‖ NEV ‖ NS ‖ τ, "kdf-sess-s2c")

── m4 { AEAD(K_c2s, PSi ‖ N_edge ‖ t4) } ────────►
◄── m5 { AEAD(K_s2c, N_edge+1) } ─────────────────  [Liveness proof]
◄── provision { AEAD(K_s2c, w_i_new) } ───────────  [w_i rotation]
── hash_commit / challenge / reveal ───────────────► [Integrity check]
```

Formal protocol specification: see [`formal_protocol.md`](./formal_protocol.md)

---

## 🔒 Security Properties

| Property | Mechanism | Goal |
|---|---|---|
| **Session pseudonymity** | `PSi = H(ID ‖ H(SD ‖ A_i))` — per-session A_i | G1 |
| **Post-quantum forward secrecy** | Ephemeral ML-KEM-768 + X25519 per session | G2 |
| **Mutual authentication** | ML-DSA-65 TOFU + `H(z_i ‖ w_i)` challenge | G3 |
| **Replay resistance** | Timestamps (±5s) + random nonces {NEV, NS} | G4 |
| **Reflection resistance** | Directional keys `K_c2s ≠ K_s2c` | G5 |
| **Unknown-key-share resistance** | Transcript binding `H(serv_pub ‖ m1 ‖ m2)` | G6 |
| **Lawful de-anonymization** | PA holds `(ID_REAL → PSi)` audit ledger | G7 |
| **Quantum resistance** | ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204) | All |

---

## 🔬 Algorithms

| Algorithm | Standard | Role | Security Level |
|---|---|---|---|
| **ML-KEM-768** | NIST FIPS 203 | Hybrid KEM — primary | Level 3 (~AES-192) |
| **X25519** | RFC 7748 | Hybrid KEM — classical hedge | ~128-bit classical |
| **ML-DSA-65** | NIST FIPS 204 | Long-term identity signatures | Level 3 (~AES-192) |
| **AES-256-GCM** | NIST SP 800-38D | AEAD payload encryption | 256-bit / 128-bit PQ |
| **HKDF-SHA256** | RFC 5869 | Session key derivation | Domain-separated |
| **SHA-256** | FIPS 180-4 | Pseudonym, transcript, w_i, hash-chain | 128-bit PQ (Grover) |

---

## 📊 Performance (Prototype, Apple Silicon)

| Metric | Classical KYC Baseline | **PQ-PKAP** | Notes |
|---|---|---|---|
| Latency (mean) | ~0.1–0.5 ms | **~4–13 ms** | PQ crypto overhead |
| Bandwidth/session | ~200 B (bare) | **~13.5 KB** | ML-DSA-65 sigs dominate |
| Identity bytes/session | **32+ B** (every session) | **0 B** | Core privacy claim |
| Quantum resistant | ❌ | ✅ | |
| Pseudonymized | ❌ | ✅ | |
| Mutual auth | ❌ | ✅ | |

Run comparative benchmark:
```bash
python server.py         # terminal 1
python benchmark.py      # terminal 2
```

---

## 🚀 Quick Start

### Prerequisites
- Python ≥ 3.11
- Dependencies: `pqcrypto`, `cryptography`, `msgpack`, `psutil`

### Installation
```bash
git clone https://github.com/SubhashSolleti/Secure-Iot-Auth-Protocol-Post-Quantum.git
cd Secure-Iot-Auth-Protocol-Post-Quantum
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run Protocol
```bash
# Terminal 1 — KYC gateway server
python server.py

# Terminal 2 — Client (KYC user)
python client.py
```

### Benchmark vs Classical KYC Baseline
```bash
# Terminal 1 — keep server running
python server.py

# Terminal 2 — comparative benchmark
python benchmark.py

# Standalone classical baseline (no server needed)
python baseline_tls_sim.py
```

---

## 📁 Project Structure

```
├── client.py              Protocol client — pseudonym derivation, handshake
├── server.py              KYC gateway — auth, pseudonym DB, w_i rotation
├── identity.py            ML-DSA-65 identity keys, TOFU peer pinning
├── kem_adapter.py         Hybrid KEM abstraction (ML-KEM-768 + X25519)
├── pq_commons.py          Shared crypto primitives (AEAD, HKDF, SHA-256)
├── benchmark.py           Comparative benchmark: PQ-PKAP vs Classical KYC
├── baseline_tls_sim.py    Classical X25519+AES KYC baseline simulator
│
├── formal_protocol.md     Formal protocol specification (paper §4)
├── regulatory_analysis.md Regulatory compatibility analysis (paper §6)
├── paper_outline.md       Full paper structure for IEEE TIFS / FC submission
│
├── client_data/           Auto-generated: client identity, secrets, w_i
├── server_data/           Auto-generated: server identity keys
└── server_pseudonyms.db   SQLite: pseudonyms + z_i + w_i + TOFU bindings
```

---

## 📄 Paper Documents

| Document | Contents | Paper Section |
|---|---|---|
| [`formal_protocol.md`](./formal_protocol.md) | Notation, system model, adversary model, security goals, 5-msg handshake, security arguments | §3–5 |
| [`regulatory_analysis.md`](./regulatory_analysis.md) | RBI KYC, GDPR, AML, NIST, DPDPA compatibility tables | §6 |
| [`paper_outline.md`](./paper_outline.md) | Full paper structure, abstract draft, venue selection, reference list | Meta |

---

## Acknowledgments

- [pqcrypto](https://github.com/pqclean/pqclean) — ML-KEM-768 and ML-DSA-65 (NIST FIPS 203/204)
- [pyca/cryptography](https://cryptography.io/) — X25519, AES-GCM, HKDF

---

> ⭐ Star this repo if useful | Questions? Open an [issue](https://github.com/SubhashSolleti/Secure-Iot-Auth-Protocol-Post-Quantum/issues) or reach out on [LinkedIn](https://www.linkedin.com/in/solletikrishnachaitanyasubhash)
