# Formal Protocol Specification
## Post-Quantum Pseudonymous KYC Authentication Protocol (PQ-PKAP)

---

## 1. Notation

| Symbol | Type | Description |
|--------|------|-------------|
| `C` | Party | Client (financial service user / device) |
| `S` | Party | Service Provider (bank, KYC gateway) |
| `PA` | Party | Provisioning Authority (trusted KYC issuer) |
| `ID_REAL` | bytes(32) | Client's real identity (e.g., Aadhaar hash, PAN hash) |
| `SD` | bytes(32) | Client-controlled device/session salt — never leaves client |
| `A_i` | bytes(32) | Per-session attester nonce — refreshed per connection |
| `PSi` | bytes(32) | Per-session derived pseudonym: `SHA-256(ID_REAL ‖ SHA-256(SD ‖ A_i))` |
| `PSi_stable` | bytes(32) | Stable screening pseudonym: `SHA-256(ID_REAL ‖ SHA-256(SD ‖ "stable"))` |
| `z_i` | bytes(32) | Client secret token registered during KYC onboarding |
| `w_i` | bytes(32) | Server-provisioned mutual authentication secret (per-session rotated) |
| `T` | bytes(32) | Per-session random token (server-generated, used in w_i rotation) |
| `NEV` | bytes(32) | Client nonce (replay protection) |
| `NS` | bytes(32) | Server nonce (replay protection) |
| `N_edge` | bytes(32) | Client-generated liveness challenge nonce |
| `t1`, `t2`, `t4` | uint64 | Unix timestamps (big-endian, 8 bytes) |
| `ct` | bytes | KEM ciphertext (1,120 bytes for hybrid mode) |
| `ss` | bytes(32) | Hybrid shared secret from ML-KEM-768 + X25519 |
| `K_c2s` | bytes(32) | Directional session key: Client → Server |
| `K_s2c` | bytes(32) | Directional session key: Server → Client |
| `pk_C` | bytes | Client long-term ML-DSA-65 signing public key |
| `sk_C` | bytes | Client long-term ML-DSA-65 signing private key |
| `pk_S` | bytes | Server long-term ML-DSA-65 signing public key |
| `sk_S` | bytes | Server long-term ML-DSA-65 signing private key |
| `KEM.KeyGen()` | → (pk, sk) | Hybrid KEM key generation |
| `KEM.Encaps(pk)` | → (ct, ss) | Encapsulation against server's ephemeral pk |
| `KEM.Decaps(sk, ct)` | → ss | Decapsulation |
| `Sign(sk, m)` | → σ | ML-DSA-65 signing |
| `Verify(pk, m, σ)` | → {0,1} | ML-DSA-65 signature verification |
| `AEAD(k, ad, pt)` | → (nonce, ct) | AES-256-GCM authenticated encryption |
| `AEAD_D(k, ad, n, ct)` | → pt | AES-256-GCM authenticated decryption |
| `H(·)` | → bytes(32) | SHA-256 hash function |
| `HKDF(ikm, info)` | → bytes(32) | HKDF-SHA256 key derivation |
| `‖` | | Byte concatenation |

---

## 2. System Model

### 2.1 Parties and Roles

```
┌──────────────────────────────────────────────────────────────────────┐
│                     PQ-PKAP System Architecture                      │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────┐         ┌─────────────┐         ┌─────────────┐   │
│   │   Client C  │◄───────►│  Server S   │◄───────►│   Auth. PA  │   │
│   │  (Customer) │  TCP    │ (KYC Svc)   │ offline │  (KYC Reg.) │   │
│   └──────┬──────┘         └──────┬──────┘         └──────┬──────┘   │
│          │                       │                        │          │
│   Holds: │                Holds: │                 Holds: │          │
│  ID_REAL │           pseudonym DB│              ID_REAL→  │          │
│  SD, z_i │           PSi, z_i,wi │              PSi map   │          │
│  pk_C,   │           pk_S, sk_S  │              (audit)   │          │
│  sk_C    │                       │                        │          │
└──────────┴───────────────────────┴────────────────────────┴──────────┘
```

- **Client (C)**: A financial service user (human or device). Holds real identity `ID_REAL` and client-side secrets `{SD, A_i, z_i}`. Derives pseudonym `PSi` locally — never sends `ID_REAL` on the wire.
- **Server (S)**: KYC gateway / banking service. Authenticates clients by pseudonym. Never learns `ID_REAL` during normal operation.
- **Provisioning Authority (PA)**: Trusted third party that performs out-of-band KYC enrollment. Issues `z_i` to each client. Maintains `(ID_REAL → PSi)` mapping for lawful de-anonymization (RBI, court order).

### 2.2 Trust Assumptions

| Assumption | Rationale |
|---|---|
| C knows its own `ID_REAL`, `SD`, `z_i` | Provisioned securely at KYC onboarding |
| S trusts `z_i` values issued by PA | Out-of-band provisioning; S verifies `z_i` per-session |
| PA is honest (not colluding with S) | Standard regulatory trust model |
| Network is untrusted (Dolev-Yao) | Adversary can intercept, replay, forge messages |
| A cannot break ML-KEM-768 or ML-DSA-65 in PPT | NIST FIPS 203/204 security assumptions |
| A cannot break AES-256-GCM or HKDF-SHA256 in PPT | Standard symmetric crypto assumptions |
| C and S use synchronized clocks (±5s) | NTP or equivalent time sync |

### 2.3 Threat Model

**Adversary type**: Active, polynomial-time (PPT) adversary operating in the Dolev-Yao model.

**Capabilities of adversary `A`**:
- ✅ Intercept, read, delay, replay, or drop any message on the network
- ✅ Inject crafted messages (active MITM)
- ✅ Compromise the server's database (gains access to stored `(PSi, z_i, w_i)` tuples)
- ✅ Observe multiple sessions and attempt to link `PSi_1` to `PSi_2` across sessions
- ✅ Perform offline dictionary attacks on captured ciphertexts
- ❌ Cannot compromise long-term private keys `sk_C`, `sk_S` while the device is operational
- ❌ Cannot cryptanalytically break ML-KEM-768, ML-DSA-65, or AES-256-GCM in PPT
- ❌ Cannot learn `ID_REAL` from `PSi` without knowing `SD` and `A_i` (pre-image resistance of SHA-256)

---

## 3. Security Goals

**G1 — Session Pseudonymity (Unlinkability)**:  
For any two sessions `(PSi_a, PSi_b)` using different `A_i` values, no PPT adversary can determine whether both sessions belong to the same `ID_REAL`, except with negligible probability.

**G2 — Post-Quantum Forward Secrecy**:  
Compromise of long-term keys `{sk_C, sk_S}` does not reveal session keys `{K_c2s, K_s2c}` from prior sessions. Ephemeral KEM keypair guarantees this even if lattice assumptions break in the future (hybrid hedge via X25519).

**G3 — Mutual Entity Authentication**:  
After a successful handshake, both C and S have cryptographic assurance of each other's identity via:
- S ← verified by TOFU-pinned `pk_S` + ML-DSA-65 signature on m2
- C ← verified via TOFU-pinned `pk_C` + ML-DSA-65 signature on m1 + `z_i` check

**G4 — Replay Resistance**:  
Timestamps `{t1, t2, t4}` within ±5s window and random nonces `{NEV, NS, N_edge}` prevent replay of both authentication messages and session data.

**G5 — Reflection Attack Resistance**:  
Directional keys `K_c2s ≠ K_s2c` prevent an adversary from reflecting server messages back as client messages.

**G6 — Unknown-Key-Share Resistance**:  
Session keys are bound to the full handshake transcript `H(serv_pub ‖ m1 ‖ m2)`, binding them to both parties' contributions.

**G7 — Audit-Compliant De-anonymization**:  
PA can reveal `ID_REAL` for a given `PSi` via its enrollment records. This satisfies RBI KYC and AML lawful interception requirements without requiring S to learn `ID_REAL` during normal operation.

---

## 4. Protocol Specification

### 4.1 KYC Enrollment (Out-of-Band, One-Time)

```
PA performs:
  1. Verify ID_REAL (Aadhaar/PAN/passport — real-world KYC)
  2. z_i ← random(32)
  3. Record (ID_REAL, z_i) in PA's secure audit ledger
  4. Securely provision C with: {ID_REAL, SD=random(32), A_i=random(32), z_i}
  5. C generates: pk_C, sk_C ← ML-DSA-65.KeyGen()
  6. C persists: {ID_REAL, SD, A_i, z_i, pk_C, sk_C} (0o600 permissions)
```

### 4.2 Pseudonym Derivation (Tiered Architecture)

PQ-PKAP uses a **two-tier pseudonym architecture** to simultaneously achieve per-session unlinkability (for authentication) and consistent sanctions screening (for AML compliance):

#### Tier 1: Session Pseudonym (PSi_session) — Unlinkable

Client MUST compute a fresh `PSi` per session, never transmitting `ID_REAL`:

```
A_i  := random(32)                           [Fresh per session — MUST rotate]
PSi  := SHA-256(ID_REAL ‖ SHA-256(SD ‖ A_i))
```

**Security properties**:
- `SHA-256(SD ‖ A_i)` acts as a domain separator; different `A_i` → different inner hash
- `SHA-256(ID_REAL ‖ …)` provides second preimage resistance: given `PSi`, adversary cannot recover `ID_REAL` without knowing `SD` and `A_i`
- Server cannot correlate two sessions with different `A_i` even if it knows `PSi` for each

#### Tier 2: Stable Pseudonym (PSi_stable) — For Screening

Client also computes a **fixed** pseudonym for intermediary sanctions screening:

```
PSi_stable := SHA-256(ID_REAL ‖ SHA-256(SD ‖ "stable-screening-domain-v1"))
```

**Security properties**:
- `PSi_stable` is consistent across sessions (same ID_REAL + SD → same output)
- Intermediary can match against pre-loaded sanctions pseudonyms without learning `ID_REAL`
- The domain separator `"stable-screening-domain-v1"` prevents collision with session pseudonyms

**Privacy tradeoff (explicit)**:
- `PSi_stable` IS linkable across sessions by design — the intermediary can observe that the same entity was screened multiple times
- However, the intermediary **cannot learn** the customer's name, DOB, national ID, or address
- This is **strictly better** than the status quo where full PII is shared with every intermediary
- Per-session unlinkability is preserved at the authentication layer via `PSi_session`

#### Tiered Flow in Protocol

```
Client → Server:   m1 envelope contains {PSi_session, ..., PSi_stable}  [encrypted]
Server → Interm.:  forwards PSi_stable only                             [for screening]
Interm. → Server:  returns CLEAN / FLAGGED                              [no identity]
Server:            uses PSi_stable as DB FK, PSi_session for session binding
```

### 4.3 Five-Message Handshake

```
Client (C)                                              Server (S)
────────────────────────────────────────────────────────────────────

SETUP:
  S computes:
    (serv_pub, serv_priv) ← KEM.KeyGen()              [Ephemeral per-session]

───────────────  hello  ──────────────────────────────────────────►
  C receives serv_pub

MESSAGE m1 (C → S):
  C computes:
    PSi  := H(ID_REAL ‖ H(SD ‖ A_i))                 [Pseudonym — no ID_REAL]
    NEV  ← random(32)                                  [Client nonce]
    t1   := timestamp_now()                            [Replay prevention]
    (ct, ss) := KEM.Encaps(serv_pub)                   [Hybrid KEM encapsulation]
    env  := PSi ‖ NEV ‖ t1 ‖ z_i
    (nonce₁, c₁) := AEAD(HKDF(ss, "kdf-ss"), PSi, env)
    m1_payload := Encode{ct, ad=PSi, nonce₁, c₁}
    σ₁ := Sign(sk_C, m1_payload)

    Send: {type="m1", payload=m1_payload, sig=σ₁, sig_pk=pk_C}

──────────────────────────────────────────────────────────────────►
  S verifies:
    Verify(pk_C, m1_payload, σ₁) = 1                  [Sig check]
    ss := KEM.Decaps(serv_priv, ct)
    env := AEAD_D(HKDF(ss, "kdf-ss"), PSi, nonce₁, c₁)
    (PSi, NEV, t1, z_i) := Parse(env)
    |timestamp_now() - t1| ≤ 5s                        [Replay check]
    TOFU: pin or verify pk_C for PSi                   [Identity binding]
    DB: verify z_i matches stored value for PSi        [Client auth]

MESSAGE m2 (S → C):
  S computes:
    T   ← random(32)                                   [Session token for w_i rotation]
    NS  ← random(32)                                   [Server nonce]
    t2  := timestamp_now()
    env₂ := T ‖ NS ‖ t2 ‖ H(z_i ‖ w_i)               [Server proves knowledge of w_i]
    (nonce₂, c₂) := AEAD(HKDF(ss, "kdf-ss"), PSi, env₂)
    m2_payload := Encode{ad=PSi, nonce₂, c₂}
    σ₂ := Sign(sk_S, m2_payload)

    Send: {type="m2", payload=m2_payload, sig=σ₂, sig_pk=pk_S}

◄─────────────────────────────────────────────────────────────────
  C verifies:
    Verify(pk_S, m2_payload, σ₂) = 1                  [Sig check]
    TOFU: pin or verify pk_S                           [Server identity binding]
    env₂ := AEAD_D(HKDF(ss, "kdf-ss"), PSi, nonce₂, c₂)
    (T, NS, t2, ziw) := Parse(env₂)
    |timestamp_now() - t2| ≤ 5s                        [Replay check]
    If w_i known: H(z_i ‖ w_i) == ziw                 [Mutual auth check]

SESSION KEY DERIVATION (both sides):
    τ  := H(serv_pub ‖ m1_payload ‖ m2_payload)       [Transcript hash]
    K_c2s := HKDF(ss ‖ NEV ‖ NS ‖ τ, "kdf-sess-c2s")  [Client→Server key]
    K_s2c := HKDF(ss ‖ NEV ‖ NS ‖ τ, "kdf-sess-s2c")  [Server→Client key]

MESSAGE m4 (C → S):
  C computes:
    N_edge ← random(32)
    t4 := timestamp_now()
    pt₄ := PSi ‖ N_edge ‖ t4
    (nonce₄, c₄) := AEAD(K_c2s, ad=PSi, pt₄)
    Send: {type="m4", ad=PSi, nonce=nonce₄, ciphertext=c₄}

──────────────────────────────────────────────────────────────────►

MESSAGE m5 (S → C — liveness proof):
  S computes:
    pt₄ := AEAD_D(K_c2s, PSi, nonce₄, c₄)
    N_edge := pt₄[32:64]
    Np1 := (N_edge + 1) mod 2^256
    (nonce₅, c₅) := AEAD(K_s2c, ad=PSi, Np1)
    Send: {type="m5", nonce=nonce₅, ciphertext=c₅}

◄─────────────────────────────────────────────────────────────────
  C verifies:
    back := AEAD_D(K_s2c, PSi, nonce₅, c₅)
    back == (N_edge + 1) mod 2^256                     [Liveness verified ✓]

W_I PROVISIONING / ROTATION (S → C):
  S computes:
    If new client: prov_wi := w_i                      [Fresh w_i from DB]
    Else:          prov_wi := H(w_i ‖ T)               [Ratchet forward]
                   DB: UPDATE w_i = prov_wi WHERE psi = PSi
    (nonce_p, c_p) := AEAD(K_s2c, ad=PSi, prov_wi)
    Send: {type="provision", nonce=nonce_p, ciphertext=c_p}

◄─────────────────────────────────────────────────────────────────
  C stores: w_i_new := prov_wi                         [Saved for next session]

HASH-CHAIN INTEGRITY CHECK (C → S → C):
  C computes:
    seed ← random(32); n := 20
    chain := [H^k(seed) for k in 0..n]
    head := chain[n]; pre := chain[n-1]
    Send: {type="hash_commit", head=head, n=n}
    ← Receive: {type="hash_challenge"}
    Send: {type="hash_reveal", pre=pre}
    ← Receive: {type="hash_ok", ok=H(pre)==head}      [Integrity verified ✓]
```

### 4.4 Session Key Derivation (Detailed)

```
transcript_hash  := SHA-256(serv_pub ‖ m1_payload ‖ m2_payload)

K_c2s := HKDF-SHA256(
    IKM  = ss ‖ NEV ‖ NS ‖ transcript_hash,
    info = b"kdf-sess-c2s",
    len  = 32
)

K_s2c := HKDF-SHA256(
    IKM  = ss ‖ NEV ‖ NS ‖ transcript_hash,
    info = b"kdf-sess-s2c",
    len  = 32
)
```

Both parties derive identical keys because they share `{ss, NEV, NS, transcript_hash}`. The `info` domain separator guarantees `K_c2s ≠ K_s2c`.

### 4.5 w_i Rotation (Forward Secrecy of Auth Chain)

```
Per-session ratchet:
   w_i_new := SHA-256(w_i_old ‖ T)        where T ← uniform random(32), S-generated

First session:
   w_i := uniform random(32)              (PA-provisioned or server-fresh)
```

This forms a one-way ratchet: forward compromise of `w_i_new` does not reveal `w_i_old`. Reversal requires offline preimage attack on SHA-256 (2^128 operations under Grover's algorithm).

---

## 5. Security Arguments

### 5.1 Pseudonymity (Unlinkability)

**Claim**: Given `PSi_a = H(ID ‖ H(SD ‖ A_a))` and `PSi_b = H(ID ‖ H(SD ‖ A_b))` with `A_a ≠ A_b`, no PPT adversary A can link them with probability > 1/2 + ε(λ).

**Argument**: The inner hash `H(SD ‖ A_i)` is indistinguishable from a uniform 32-byte string to any party not knowing `SD`. The outer hash `H(ID_REAL ‖ ·)` then acts as a PRF with key `ID_REAL`. Since each session uses a fresh `A_i`, the outputs are computationally independent under SHA-256 second-preimage resistance.

**Limitation**: Unlinkability applies to `PSi_session` only. `PSi_stable` is deliberately linkable across sessions to enable consistent sanctions screening. The stable pseudonym reveals session frequency to the intermediary but not identity.

### 5.2 Forward Secrecy

**Claim**: Compromise of `{sk_C, sk_S}` after session completion does not reveal `{K_c2s, K_s2c}`.

**Argument**: Session keys are derived from `ss`, which is an ephemeral KEM shared secret. The server discards `serv_priv` after the session. Without `serv_priv`, an adversary cannot recover `ss` from the captured ciphertext `ct`, under the ML-KEM-768 IND-CCA2 assumption (FIPS 203) and the X25519 gap-CDH assumption for the hybrid component.

### 5.3 Mutual Authentication

**Claim**: After a successful run, C is authenticated to S and S is authenticated to C.

**Argument**:  
- C → S: S verifies ML-DSA-65 signature `σ₁` under `pk_C`, checks `z_i` against DB, and verifies TOFU binding. Forgery requires breaking ML-DSA-65 (FIPS 204).  
- S → C: C verifies ML-DSA-65 signature `σ₂` under `pk_S` and verifies `H(z_i ‖ w_i)`. Server knowledge of `w_i` provides authentication beyond the signature (shared secret confirmation).

### 5.4 Replay / Reflection Resistance

**Timestamps** `{t1, t2, t4}` with ±5s window reject stale messages.  
**Nonces** `{NEV, NS}` make each session transcript unique.  
**Directional keys** `K_c2s ≠ K_s2c` (enforced by HKDF `info` domain separation) prevent reflection.

---

## 6. Lawful De-anonymization Procedure

Under regulatory mandate (RBI, court order, AML investigation):

```
1. Regulator presents legal instrument to PA
2. PA reveals: (ID_REAL, SD, A_i_enrollment) for suspect PSi
3. Verifier computes: H(ID_REAL ‖ H(SD ‖ A_i)) and confirms match to PSi
4. Sessions are linked to ID_REAL without exposing other users' identities
```

This is a **surgical de-anonymization** — only the specific PSi under investigation is revealed, not the entire pseudonym database.

---

## 7. Notation Summary Table

| ← | Input | Output | Property |
|---|---|---|---|
| `KEM.KeyGen()` | — | `(pk, sk)` | Ephemeral, discarded post-session |
| `KEM.Encaps(pk)` | server pk | `(ct, ss)` | IND-CCA2 under FIPS 203 |
| `KEM.Decaps(sk, ct)` | server sk, ct | `ss` | Correctness guaranteed |
| `Sign(sk, m)` | signing sk, message | `σ` | EUF-CMA under FIPS 204 |
| `AEAD(k, ad, pt)` | key, assoc data, plaintext | `(nonce, ct)` | AES-256-GCM, 128-bit auth tag |
| `HKDF(ikm, info)` | key material, info | `k` | PRF under SHA-256 assumption |
| `Pseudonym(ID, SD, Ai)` | identity, salt, nonce | `PSi` | Second-preimage resistant |
