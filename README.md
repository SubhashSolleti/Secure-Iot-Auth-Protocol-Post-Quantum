# 🔐 Secure IoT Authentication Protocol — Post-Quantum

A **production-grade, quantum-resistant authentication protocol** for privacy-preserving IoT, with a real-time web dashboard.

Built for **safety-critical applications** (connected medical devices, SCADA, vehicle telemetry) where long-lived device credentials must resist both current and future quantum attacks.

---

## 🚀 Key Features

| Feature | Description |
|---------|-------------|
| **Post-Quantum Key Exchange** | Hybrid ML-KEM-768 + X25519 — breaks only if *both* PQ and classical are broken |
| **Digital Signatures** | ML-DSA-65 (NIST FIPS 204) for authentication of every handshake message |
| **Pseudonym Privacy** | Device identities are never transmitted — only unlinkable pseudonyms (`PSi`) derived via HKDF |
| **Pseudonym Rotation** | `A_I` epoch nonce auto-rotates every N sessions, eliminating long-term linkability |
| **Session Resumption** | Server-issued encrypted tickets let returning devices skip the full KEM handshake |
| **Certificate Pinning** | Persistent ML-DSA server identity with Trust-On-First-Use (TOFU) client-side pinning |
| **Rate Limiting** | Per-IP token-bucket throttling prevents DoS flooding of the authentication gateway |
| **TLS 1.3 Transport** | Defence-in-depth — the PQ protocol runs *inside* a TLS 1.3 tunnel |
| **Structured Logging** | JSON-formatted logs via `structlog` for SIEM/SOC integration (HIPAA, FDA audit trails) |
| **Encrypted Streaming** | After authentication, sensor data is AES-GCM encrypted with `K_sess` |
| **Web Dashboard** | FastAPI + WebSocket real-time UI to control, visualize, and monitor the protocol |

---

## 📐 System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      Web Dashboard (:8000)                       │
│  ┌────────────┐    ┌────────────────┐    ┌───────────────────┐  │
│  │ Controls   │    │ Protocol Flow  │    │ Live Logs +       │  │
│  │ Start/Stop │    │ Visualizer     │    │ Sensor Telemetry  │  │
│  └─────┬──────┘    └───────┬────────┘    └────────┬──────────┘  │
│        │                   │ WebSocket             │            │
│        └───────────────────┼───────────────────────┘            │
│                            │                                     │
│              ┌─────────────┴─────────────┐                      │
│              │    FastAPI Backend         │                      │
│              │    (web/backend.py)        │                      │
│              └─────┬───────────┬─────────┘                      │
│                    │           │                                  │
│            subprocess      subprocess                            │
└────────────┬───────────────┬─────────────────────────────────────┘
             │               │
    ┌────────▼────────┐    ┌─▼──────────────────┐
    │  server.py      │    │  client.py          │
    │  ─────────      │    │  ──────────         │
    │  • Rate Limiter │◄──►│  • Key Pinning      │
    │  • Session Store│TLS │  • Session Resume   │
    │  • Pinned Keys  │1.3 │  • Pseudonym Rotate │
    │  • Hash Chain   │    │  • Sensor Streaming │
    └────────┬────────┘    └──────────┬──────────┘
             │                        │
    ┌────────▼────────┐    ┌──────────▼──────────┐
    │ SQLite (PSi DB) │    │ device_state.json   │
    │ server_identity/│    │ pinned_server.pk    │
    │ certs/          │    │ secrets_config.py   │
    └─────────────────┘    └─────────────────────┘
```

---

## 🔬 Cryptographic Algorithms

| Algorithm | Standard | Category | Purpose | Security Level |
|-----------|----------|----------|---------|---------------|
| **ML-KEM-768** | NIST FIPS 203 | Post-Quantum KEM | Key encapsulation (shared secret `ss`) | NIST Level 3 (~192-bit) |
| **X25519** | RFC 7748 | Classical ECDH | Hybrid KEM component (combined with ML-KEM) | ~128-bit classical |
| **ML-DSA-65** | NIST FIPS 204 | Post-Quantum Signature | Sign/verify handshake messages m1, m2 | NIST Level 3 (EUF-CMA) |
| **AES-256-GCM** | NIST SP 800-38D | Symmetric AEAD | Encrypt + authenticate all payloads | 256-bit |
| **HKDF-SHA-256** | RFC 5869 | Key Derivation | Derive `K_sess`, AEAD sub-keys, pseudonyms | Domain-separated |
| **SHA-256** | FIPS 180-4 | Hash | Pseudonyms, hash chains, commitments | Collision-resistant |

### Why Hybrid ML-KEM + X25519?

```
Shared Secret = HKDF(ML-KEM-768(ss) ‖ X25519(ss))
```

An attacker must break **both** ML-KEM-768 (quantum-resistant lattice problem) **and** X25519 (classical elliptic curve) to recover the shared secret. This provides defense against:
- **Harvest-now, decrypt-later** quantum attacks
- Potential undiscovered weaknesses in new PQ algorithms

---

## 🔄 Protocol Flow

The protocol uses a **5-message handshake** followed by hash-chain verification and encrypted data streaming:

```
  IoT Client                                    Auth Server
  ──────────                                    ───────────
       │                                              │
       │◄──────────── HELLO (serv_pub, sig_pk) ───────│  Server sends KEM public key
       │                                              │     + ML-DSA signing key
       │                                              │
       │  [Optional: RESUME (ticket)]                 │  Session resumption attempt
       │─────────────────────────────────────────────►│  (skip to streaming if valid)
       │                                              │
       │  m1: {KEM_ct, Enc(PSi‖NEV‖t1‖zi), sig}      │
       │─────────────────────────────────────────────►│  Client encapsulates KEM,
       │                                              │     encrypts pseudonym + nonce
       │                                              │
       │  m2: {Enc(T‖NS‖t2‖H(zi‖wi)), sig}           │
       │◄─────────────────────────────────────────────│  Server signs with persistent
       │                                              │     ML-DSA identity (pinned)
       │                                              │
       │      K_sess = HKDF(ss ‖ NEV ‖ NS)           │  Both derive session key
       │                                              │
       │  m4: Enc_Ksess(PSi ‖ N_edge ‖ t4)           │
       │─────────────────────────────────────────────►│  Liveness challenge
       │                                              │
       │  m5: Enc_Ksess(N_edge + 1)                   │
       │◄─────────────────────────────────────────────│  Liveness response
       │                                              │
       │◄─────────── HASH_HEAD (head, n, pre) ────────│  Hash-chain verification
       │──────────── HASH_USE (pre) ─────────────────►│
       │◄─────────── HASH_OK (bool) ─────────────────│
       │                                              │
       │  ═══════ HANDSHAKE COMPLETE ═══════          │
       │                                              │
       │  stream_data: Enc_Ksess(sensor_json)         │
       │─────────────────────────────────────────────►│  Encrypted telemetry
       │─────────────────────────────────────────────►│  (temperature, humidity,
       │─────────────────────────────────────────────►│   battery, status)
       │                                              │
       │◄─────────── SESSION_TICKET (ticket_id) ──────│  For future resumption
       │                                              │
       │  ═══════ SESSION COMPLETE ═══════            │
```

### Message Breakdown

| Message | Direction | Contents | Protection |
|---------|-----------|----------|------------|
| **HELLO** | S → C | `serv_pub` (KEM), `sig_pk` (ML-DSA) | None (public values) |
| **m1** | C → S | KEM ciphertext + `Enc(PSi, NEV, t1, zi)` + signature | KEM + AEAD + ML-DSA sig |
| **m2** | S → C | `Enc(T, NS, t2, H(zi‖wi))` + signature | AEAD + ML-DSA sig (pinned key) |
| **m4** | C → S | `Enc_Ksess(PSi, N_edge, t4)` | AES-GCM with `K_sess` |
| **m5** | S → C | `Enc_Ksess(N_edge + 1)` | AES-GCM with `K_sess` |
| **stream** | C → S | `Enc_Ksess(sensor_data_json)` | AES-GCM with `K_sess` |

---

## 🛡️ Security Features in Detail

### 1. Session Resumption
After a successful handshake, the server issues an **encrypted session ticket** (32-byte opaque ID). On reconnection, the client presents the ticket to skip the full KEM key exchange — saving energy on battery-constrained devices.

- **One-time use**: Each ticket is consumed on first use
- **TTL-based expiry**: Tickets expire after `SESSION_TICKET_TTL_SEC` (default: 300s)
- **Forward secrecy**: Master key rotates on each server restart

### 2. Certificate Pinning (TOFU)
The server generates a **persistent ML-DSA-65 signing key-pair** on first run, saved to `server_identity/`. The client pins the server's public key on first contact and **rejects any m2 signed by a different key** — stopping MITM attacks cold.

```
First connection:   Client saves server_sig_pk → pinned_server.pk
Subsequent:         if m2.sig_pk ≠ pinned_pk → ABORT ("Possible MITM!")
```

### 3. Rate Limiting
Token-bucket algorithm, keyed per source IP:
- `RATE_LIMIT_BURST = 20` — maximum concurrent tokens
- `RATE_LIMIT_PER_SEC = 10` — refill rate
- Exceeded → immediate `{type: "err", reason: "rate-limited"}` and disconnect

### 4. TLS 1.3 Transport
When `TLS_ENABLED = True` (default), all TCP communication is wrapped in TLS 1.3:
- Auto-generates a self-signed CA + server certificate in `certs/`
- Enforces `TLSVersion.TLSv1_3` minimum on both sides
- In production: replace with certificates from your PKI

### 5. Pseudonym Rotation
The epoch nonce `A_I` auto-rotates every `PSEUDONYM_ROTATE_EVERY` sessions (default: 5). After rotation, the derived pseudonym `PSi = HKDF(ID_REAL ‖ SD ‖ A_I)` changes — making past and future sessions **unlinkable**, even to the server's own network operators.

### 6. Structured Logging
All events use `structlog` with key-value pairs:

```json
{"kem": "hybrid.ml_kem_768+x25519", "tls": true, "event": "connected", "level": "info", "logger": "client", "timestamp": "2026-02-15T22:07:56.681190Z"}
{"latency_ms": 4.13, "event": "handshake_complete", "level": "info", "logger": "client", "timestamp": "2026-02-15T22:07:56.685638Z"}
{"seq": 1, "event": "sensor_packet_sent", "level": "info", "logger": "client", "timestamp": "2026-02-15T22:07:56.685933Z"}
```

Toggle between JSON (`LOG_MODE = "json"`) and human-readable (`LOG_MODE = "text"`) in `config.py`.

---

## 📁 Project Structure

```
Secure-Iot-Auth-Protocol-Post-Quantum/
│
├── server.py               # Auth server: handshake, streaming, ticket issuance
├── client.py               # IoT client: handshake, data streaming, key pinning
├── config.py               # All tuneable constants (network, crypto, timing)
├── secrets_config.py       # Device identity secrets + pseudonym rotation
│
├── kem_adapter.py          # Hybrid ML-KEM-768 + X25519 adapter (with fallback)
├── pq_commons.py           # AEAD, HKDF, SHA-256, pseudonyms, hash chains
│
├── session_store.py        # In-memory session ticket store (issue/resume/expiry)
├── pinned_keys.py          # Persistent ML-DSA identity + TOFU pinning
├── rate_limiter.py         # Per-IP token-bucket rate limiter
├── tls_utils.py            # TLS 1.3 cert generation + SSL context factories
├── log_setup.py            # structlog JSON/text logging configuration
│
├── web/                    # Real-time dashboard
│   ├── backend.py          # FastAPI + WebSocket log streaming
│   └── static/
│       ├── index.html      # Dashboard UI
│       ├── app.js          # WebSocket client + visualizer logic
│       └── style.css       # Dark-themed dashboard styling
│
├── tests/                  # pytest suite (45 tests)
│   ├── test_crypto.py      # AEAD, HKDF, SHA-256, KEM round-trips
│   ├── test_protocol.py    # Full end-to-end handshake + streaming
│   ├── test_session_store.py
│   ├── test_rate_limiter.py
│   ├── test_pinning.py
│   ├── test_tls.py
│   └── test_pseudonym_rotation.py
│
├── benchmark.py            # Performance measurement
├── run_dashboard.sh        # One-command dashboard launcher
├── requirements.txt        # Python dependencies
│
├── certs/                  # Auto-generated TLS certificates (gitignored)
├── server_identity/        # Persistent ML-DSA server key-pair
└── device_state.json       # Pseudonym rotation counter
```

---

## 📖 Quick Start

### Prerequisites
- **Python 3.11+**
- **pip** (or a virtualenv)

### Installation

```bash
# Clone the repository
git clone https://github.com/SubhashSolleti/Secure-Iot-Auth-Protocol-Post-Quantum.git
cd Secure-Iot-Auth-Protocol-Post-Quantum

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Run the Protocol (CLI)

**Terminal 1 — Start Server:**
```bash
python server.py
```

**Terminal 2 — Connect Client:**
```bash
python client.py
```

You'll see structured JSON logs showing the full handshake → streaming → session ticket flow.

### Run the Web Dashboard

```bash
./run_dashboard.sh
```

Open **http://localhost:8000** in your browser.

| Button | Action |
|--------|--------|
| **Start Server** | Launches `server.py` as a subprocess |
| **Connect Client** | Runs `client.py` — watch the protocol steps light up |
| **Reset Device State** | Clears `device_state.json` and `pinned_server.pk` for a fresh demo |

### Run Tests

```bash
python -m pytest tests/ -v
```

```
45 passed in 0.27s
```

---

## ⚙️ Configuration

All protocol parameters live in [`config.py`](config.py):

| Parameter | Default | Description |
|-----------|---------|-------------|
| `HOST` | `127.0.0.1` | Server bind address |
| `PORT` | `8765` | Server listen port |
| `TIME_DELTA_SEC` | `5` | Max acceptable clock skew (replay protection) |
| `HASH_CHAIN_LENGTH` | `20` | Number of hash-chain links |
| `TLS_ENABLED` | `True` | Enable TLS 1.3 transport wrapping |
| `SESSION_TICKET_TTL_SEC` | `300` | Session ticket validity (seconds) |
| `RATE_LIMIT_PER_SEC` | `10` | Token refill rate per IP |
| `RATE_LIMIT_BURST` | `20` | Maximum burst size per IP |
| `PSEUDONYM_ROTATE_EVERY` | `5` | Rotate `A_I` after N sessions |
| `LOG_MODE` | `"json"` | `"json"` or `"text"` log output |
| `STREAM_PACKET_COUNT` | `5` | Sensor packets per session |
| `KEM_FALLBACK_POLICY` | `"strict"` | `"strict"` aborts without hybrid; `"relaxed"` allows pure ML-KEM |

Device secrets are configured in [`secrets_config.py`](secrets_config.py) via environment variables:

| Env Variable | Purpose |
|-------------|---------|
| `IOT_DEVICE_ID` | Real device identifier |
| `IOT_SECRET_DIVERSIFIER` | Secret for pseudonym derivation |
| `IOT_EPOCH_NONCE` | Current pseudonym epoch (auto-managed) |
| `IOT_ZI_COMMITMENT` | Pre-shared z_i commitment |

---

## 🏥 Application Domain: Connected Medical Devices

This protocol is designed for **safety-critical IoT** environments. The recommended application domain is **connected medical device telemetry** (CGMs, pacemakers, insulin pumps, remote patient monitors).

| Protocol Feature | Medical Justification |
|---|---|
| Post-Quantum (ML-KEM-768) | Medical implants have 10–15 year lifecycles |
| Pseudonym Privacy | HIPAA de-identification compliance |
| Pseudonym Rotation | Limits patient linkability windows |
| Certificate Pinning | Prevents MITM on life-critical devices |
| Session Resumption | Saves battery on implanted devices |
| Rate Limiting | Protects hospital gateways from DoS |
| TLS 1.3 | FDA cybersecurity guidance compliance |
| Structured Logging | HIPAA audit trails (21 CFR Part 11) |

### Regulatory Alignment
- **FDA Premarket Cybersecurity Guidance (2023)** — PQ readiness for long-lived devices
- **HIPAA Security Rule** — de-identification, encryption, audit logs
- **NIST SP 800-183** — IoT cybersecurity architecture
- **IEC 62443** — Industrial communication security

---

## 🧪 Testing

The project includes **45 tests** across 7 test files:

| Test File | Coverage | Tests |
|-----------|----------|-------|
| `test_crypto.py` | AEAD, HKDF, SHA-256, pseudonyms, hash chains, KEM | 18 |
| `test_pinning.py` | Key generation, persistence, sign/verify, export | 5 |
| `test_protocol.py` | Full end-to-end handshake + streaming | 1 |
| `test_pseudonym_rotation.py` | Threshold, counter reset, persistence | 4 |
| `test_rate_limiter.py` | Burst, refill, IP isolation, reset | 6 |
| `test_session_store.py` | Issue, resume, one-time-use, expiry, purge | 7 |
| `test_tls.py` | Cert generation, idempotency, SSL contexts | 4 |

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m 'Add your feature'`
4. Push: `git push origin feature/your-feature`
5. Open a pull request

---

## 🙏 Acknowledgments

- [pqcrypto](https://github.com/pqclean/pqclean) — Post-quantum cryptographic primitives
- [cryptography](https://cryptography.io/) — X25519, AES-GCM, HKDF, TLS
- [structlog](https://www.structlog.org/) — Structured logging
- [FastAPI](https://fastapi.tiangolo.com/) — Web dashboard backend

---

⭐ **Star this repo if you find it useful!**
Questions or issues? Open an [issue](https://github.com/SubhashSolleti/Secure-Iot-Auth-Protocol-Post-Quantum) or reach out on [LinkedIn](https://www.linkedin.com/in/solletikrishnachaitanyasubhash).
