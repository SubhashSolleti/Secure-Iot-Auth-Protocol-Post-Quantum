# Regulatory Compatibility Analysis
## PQ-PKAP — Post-Quantum Pseudonymous KYC Authentication Protocol

> **Scope**: This section analyzes the compatibility of PQ-PKAP with Indian financial regulations (RBI KYC/AML), European data protection law (GDPR), and international cybersecurity standards applicable to fintech identity systems.

---

## 1. Overview

PQ-PKAP introduces a *pseudonymization layer* between the client's real identity (`ID_REAL`) and the service provider. The core privacy-preserving claim is:

> **The server authenticates a KYC-verified client without ever receiving or storing their real identity.**

This design must simultaneously satisfy:
- **Regulatory compliance**: Lawful de-anonymization MUST be possible under court order or AML mandate
- **Privacy minimisation**: Normal-operation data minimization consistent with GDPR/PDPB principles
- **Security**: Quantum-resistant protection against future cryptanalytic attacks on stored pseudonym databases

---

## 2. Reserve Bank of India (RBI) — KYC Master Direction 2016

### 2.1 Applicable Requirements

| RBI KYC Requirement | Mechanism in PQ-PKAP | Status |
|---|---|---|
| **Customer identification** (§16) — RE must identify customer | PA performs real-world KYC; issues `z_i` token | ✅ Satisfied (via PA) |
| **Unique Client Code** (§27) — tracking across transactions | `PSi` serves as stable pseudonymous identifier per session set | ✅ Satisfied |
| **AML monitoring** — RE must monitor transaction patterns | S monitors `PSi`-linked sessions (behavioral analytics possible) | ✅ Satisfied |
| **Suspicious transaction reporting (STR)** (§51) | S reports suspicious `PSi`; PA maps to `ID_REAL` for FIU | ✅ Satisfied (via PA de-anon) |
| **Record keeping** (§55) — 5-year retention | Server retains `(PSi, z_i, session_log)` — no ID_REAL needed | ✅ Satisfied |
| **Video/In-person KYC** | Out-of-band PA enrollment step (not replaced by protocol) | ✅ Compatible (complement) |

### 2.2 When Identity Must Be Revealed (De-anonymization Flow)

```
Normal Operation:
   Client ──PSi──► Server         [No ID_REAL transmitted]
   Server logs: (PSi, timestamp, tx_amount)

Regulatory Trigger (AML/STR):
   Step 1: Server flags PSi → reports to FIU-IND / regulator
   Step 2: Regulator → issues legal instrument to PA
   Step 3: PA → reveals (ID_REAL, z_i enrollment record) for that PSi
   Step 4: Full identity + transaction history linked for investigation
```

**Key point for reviewers**: PQ-PKAP does NOT enable anonymous crime. Regulatory access to `ID_REAL` is preserved via the PA's audit ledger, but this access is:
- **Controlled**: Requires legal instrument — no bulk data sharing
- **Auditable**: The PA can log who requested de-anonymization and when
- **Surgical**: Only the target `PSi` is de-anonymized; other users are unaffected

### 2.3 V-CIP Compatibility

RBI's Video-based Customer Identification Process (V-CIP) performs facial scan, document verification, and geo-tagging at enrollment. PQ-PKAP is **complementary** — the PA step maps to the entity performing V-CIP. After enrollment, PQ-PKAP secures all subsequent authentication without re-transmitting identity documents.

---

## 3. GDPR (EU General Data Protection Regulation) — 2016/679

### 3.1 Applicability

GDPR applies to Indian fintech companies serving EU residents, and is a forward-looking compliance target for DPDPA (India's Digital Personal Data Protection Act, 2023).

### 3.2 Principle-by-Principle Analysis

| GDPR Principle | Article | Mechanism in PQ-PKAP | Compliance |
|---|---|---|---|
| **Lawfulness, fairness, transparency** | Art. 5(1)(a) | PA enrollment is consent-based; purpose stated at onboarding | ✅ |
| **Purpose limitation** | Art. 5(1)(b) | Server only receives `PSi` — cannot use `ID_REAL` for secondary purpose | ✅ |
| **Data minimisation** | Art. 5(1)(c) | Server stores `(PSi, z_i, w_i)` — no name, address, biometrics | ✅ |
| **Accuracy** | Art. 5(1)(d) | `z_i` rotated per PA; `PSi` deterministically correct | ✅ |
| **Storage limitation** | Art. 5(1)(e) | 5-year retention of `PSi` logs; `ID_REAL` only at PA (shorter retention configurable) | ✅ |
| **Integrity & confidentiality** | Art. 5(1)(f) | AES-256-GCM + ML-KEM-768 + ML-DSA-65 — quantum-resistant | ✅ |
| **Accountability** | Art. 5(2) | Audit log at PA level; server logs pseudonymous sessions | ✅ |

### 3.3 Data Subject Rights

| Right | GDPR Article | How PQ-PKAP Supports It |
|---|---|---|
| **Right of access** | Art. 15 | Server can provide session logs linked to `PSi` on request via PA intermediation |
| **Right to erasure** | Art. 17 | Server deletes `(PSi, z_i, w_i)` row; `ID_REAL` erasure at PA | ✅ Feasible — pseudonym is the FK |
| **Right to rectification** | Art. 16 | PA updates `z_i`; re-enrollment issues new `PSi` | ✅ Feasible |
| **Right to portability** | Art. 20 | `SD` is client-controlled — client can migrate to new provider | ✅ |
| **Right to object** | Art. 21 | PA can deactivate `z_i`; server rejects future sessions for that `PSi` | ✅ |

### 3.4 GDPR Art. 25 — Data Protection by Design

The pseudonymization approach directly implements GDPR's Art. 25(1) requirement:

> *"the controller shall implement appropriate technical and organisational measures… designed to implement data-protection principles, such as data minimisation, in an effective manner."*

Since `ID_REAL` is never transmitted to or stored by S, PQ-PKAP achieves **architectural data protection by design** — the server is structurally incapable of linking a pseudonym to a real person without PA cooperation.

### 3.5 Pseudonymization vs. Anonymization (Recital 26)

GDPR Recital 26 distinguishes:
- **Anonymous data**: GDPR does not apply
- **Pseudonymous data**: GDPR applies but with reduced obligations (Art. 89)

PQ-PKAP produces **pseudonymous data** at the server. `ID_REAL` can be recovered by PA but not by S alone. This classification means:
- Server is a processor under reduced data subject risk
- PA is the controller with full identity data obligations
- Pseudonymous server logs qualify for research/statistics exemptions (Art. 89)

---

## 4. AML / CFT Requirements (FATF, PMLA India)

### 4.1 FATF Recommendation 10 — Customer Due Diligence (CDD)

| FATF Requirement | PQ-PKAP Mapping |
|---|---|
| Identify & verify identity before/during transaction | PA performs CDD at enrollment; `z_i` is the CDD artifact |
| Monitor transactions | Server monitors `PSi`-linked activity patterns (ML-based AML possible) |
| Keep records for ≥5 years | Server retains pseudonymous logs; PA retains `(ID_REAL, z_i)` mapping |

### 4.2 PMLA 2002 (India) — Compliance Path

```
Traditional KYC:            KYC officer → stores ID documents → AML monitoring
PQ-PKAP KYC:                PA verifies → issues z_i → S authenticates → PA de-anons on order
```

The PMLA allows regulated entities (REs) to rely on certified intermediaries for KYC (§11A). PA maps to this certified intermediary role.

### 4.3 Transaction Monitoring Without Identity Exposure

AML pattern detection can occur at the `PSi` level:
- Velocity limits (number of sessions per `PSi` per hour)
- Anomalous session timing patterns
- Cross-device correlation (same `PSi`, different network origin)

Only when a pattern crosses STR thresholds is the PA queried for `ID_REAL` de-anonymization.

---

## 5. NIST Frameworks and Standards

| Standard | Relevance | PQ-PKAP Compliance |
|---|---|---|
| **NIST SP 800-63-3** (Digital Identity Guidelines) | Authentication Assurance Level (AAL) | AAL3 compatible — hardware-bound keys, MFA via `z_i + signing key` |
| **NIST SP 800-207** (Zero Trust Architecture) | Never trust, always verify | TOFU pinning + per-session KEM + mutual auth = ZTA compatible |
| **NIST FIPS 203** (ML-KEM) | Post-quantum KEM | ML-KEM-768 used directly |
| **NIST FIPS 204** (ML-DSA) | Post-quantum signatures | ML-DSA-65 used directly |
| **NIST SP 800-38D** (AES-GCM) | AEAD encryption | AES-256-GCM used throughout |
| **NIST SP 800-186** (Elliptic Curves) | Classical hedge | X25519 in hybrid KEM |

PQ-PKAP achieves **NIST Post-Quantum Migration** compliance by using exclusively FIPS 203/204 standardized algorithms, making it suitable for use through the projected quantum computing threat horizon (2030+).

---

## 6. India Digital Personal Data Protection Act (DPDPA) 2023

| DPDPA Principle | PQ-PKAP Implementation |
|---|---|
| Consent-based processing (§6) | PA enrollment is explicit consent event |
| Purpose limitation (§6(3)) | Server cannot use pseudonym for undisclosed secondary purposes |
| Data minimisation (§6(4)) | Server structurally receives `PSi` only, not `ID_REAL` |
| Data fiduciary obligations (§10) | PA is Data Fiduciary — full obligations apply; Server is Data Processor |
| Significant Data Fiduciary (§10(2)) | PA designated as SDF if onboarding >1M users; additional audits apply |
| Erasure on request (§12) | Pseudonym row deletion at server; `ID_REAL` erasure at PA |

---

## 7. Regulatory Compatibility Summary

| Regulation | Requirement | PQ-PKAP Status | Notes |
|---|---|---|---|
| RBI KYC 2016 | Customer identification | ✅ Via PA enrollment | PA maps to KYC entity under §3 |
| RBI KYC 2016 | AML monitoring | ✅ Pseudonymous monitoring | De-anonymize only on STR |
| RBI KYC 2016 | Record keeping (5 yr) | ✅ PSi-level retention | PA retains ID_REAL mapping |
| GDPR Art. 5 | Data minimisation | ✅ Server never holds ID_REAL | Core design property |
| GDPR Art. 17 | Right to erasure | ✅ Delete PSi row | Feasible architecture |
| GDPR Art. 25 | Privacy by design | ✅ Structural enforcement | Cannot over-collect by design |
| FATF Rec. 10 | CDD | ✅ Via PA at enrollment | |
| PMLA 2002 | RE + intermediary model | ✅ Compatible | PA = certified KYC intermediary |
| NIST SP 800-63 | AAL3 | ✅ With hardware key storage | |
| NIST FIPS 203/204 | PQ algorithms | ✅ Direct compliance | ML-KEM-768, ML-DSA-65 |
| DPDPA 2023 | Consent + minimization | ✅ Compatible | PA = Data Fiduciary |

---

## 8. Residual Risks and Mitigations

| Risk | Impact | Mitigation in PQ-PKAP |
|---|---|---|
| **PA compromise**: adversary gains `ID_REAL → PSi` mapping | High — full de-anonymization | PA is out-of-scope of protocol; must apply HSM + access controls |
| **`A_i` reuse**: same session params → same `PSi` | Linkability within reuse scope | Protocol MUST enforce rotation of `A_i` per session (design requirement) |
| **`z_i` leakage from server DB** | Client can be impersonated | `z_i` is verified but not sufficient alone; requires `sk_C` signing key too |
| **Quantum advancement**: SHA-256 weakened | Pseudonymity weakened under Grover | SHA-256 hash output collision: 2^128 ops — acceptable under NIST guidance |
| **Regulatory uncertainty (DPDPA implementation)** | Future compliance gaps | Design follows GDPR parity (DPDPA aligns closely with GDPR) |
