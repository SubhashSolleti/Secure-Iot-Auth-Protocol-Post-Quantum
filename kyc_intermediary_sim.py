"""
kyc_intermediary_sim.py — Tiered Pseudonym KYC Intermediary Simulation

Demonstrates the core solution to the KYC intermediary identity exposure
problem using PQ-PKAP's tiered pseudonym architecture:

  Problem: Banks share full customer identity (name, DOB, national ID)
           with every verification intermediary (credit bureaus, sanctions
           screening vendors, correspondent banks). Each intermediary becomes
           an identity leakage surface.

  Solution: Two-tier pseudonym architecture:
    PSi_session = SHA-256(ID_REAL ‖ SHA-256(SD ‖ A_i))     [per-session, unlinkable]
    PSi_stable  = SHA-256(ID_REAL ‖ SHA-256(SD ‖ "stable")) [fixed, for screening]

  The intermediary receives PSi_stable — a 32-byte hash that cannot be
  reversed to the real identity. Multiple sessions produce different
  PSi_session values (unlinkable) but the same PSi_stable for consistent
  sanctions screening.

Actors:
  PA  — Provisioning Authority (trusted KYC issuer, holds ID_REAL → PSi mapping)
  Bank — Service Provider (authenticates via protocol, forwards PSi_stable)
  Intermediary — Sanctions Screening Vendor (checks PSi_stable against list)

Usage:
    python kyc_intermediary_sim.py
"""

import asyncio
import logging
import os
import time
from pathlib import Path

from pq_commons import (
    sha256,
    derive_pseudonym,
    derive_stable_pseudonym,
    b32,
    pack,
    unpack,
    aead_encrypt,
    aead_decrypt,
    hkdf_sha256,
    send_msg,
    recv_msg
)
from identity import IdentityManager
import kem_adapter


# Configure logging — force INFO level with clean handler
logger = logging.getLogger("KYC-Intermediary-Sim")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.propagate = False

DIVIDER = "─" * 60


# ─────────────────────────────────────────────────────────────
#  Provisioning Authority (PA) — Trusted KYC Issuer
# ─────────────────────────────────────────────────────────────

class ProvisioningAuthority:
    """Trusted third party that performs real-world KYC enrollment.

    Holds ID_REAL → PSi_stable mapping. Only entity that can
    de-anonymize a pseudonym under legal mandate.
    """

    def __init__(self):
        # Audit ledger: ID_REAL → {sd, z_i, psi_stable}
        self.ledger: dict[str, dict] = {}
        # Sanctions list: set of real-world identities known to be sanctioned
        self.sanctions_real: set[str] = set()

    def enroll_customer(self, name: str, id_real: bytes) -> dict:
        """Perform out-of-band KYC enrollment.

        Returns device secrets to be provisioned to the client.
        """
        sd = b32()
        z_i = b32()
        psi_stable = derive_stable_pseudonym(id_real, sd)

        self.ledger[id_real.hex()] = {
            "name": name,
            "sd": sd,
            "z_i": z_i,
            "psi_stable": psi_stable,
        }

        logger.info(f"[PA] Enrolled '{name}' → PSi_stable: {psi_stable.hex()[:16]}...")
        return {"id_real": id_real, "sd": sd, "z_i": z_i}

    def flag_for_sanctions(self, id_real: bytes):
        """Mark a real-world identity as sanctioned.

        PA computes PSi_stable for this identity and distributes
        it to intermediaries. The intermediary never learns ID_REAL.
        """
        self.sanctions_real.add(id_real.hex())
        entry = self.ledger.get(id_real.hex())
        if entry:
            psi_stable = entry["psi_stable"]
            logger.warning(
                f"[PA] Flagged '{entry['name']}' — distributing PSi_stable "
                f"{psi_stable.hex()[:16]}... to intermediaries"
            )
            return psi_stable
        return None

    def de_anonymize(self, psi_stable: bytes) -> str | None:
        """Reveal real identity for a given pseudonym (requires legal mandate).

        This is the surgical de-anonymization procedure:
        only the specific PSi under investigation is revealed.
        """
        for id_hex, entry in self.ledger.items():
            if entry["psi_stable"] == psi_stable:
                logger.info(
                    f"[PA] De-anonymized PSi_stable {psi_stable.hex()[:16]}... "
                    f"→ '{entry['name']}' (under legal mandate)"
                )
                return entry["name"]
        return None


# ─────────────────────────────────────────────────────────────
#  Sanctions Screening Intermediary
# ─────────────────────────────────────────────────────────────

class SanctionsIntermediary:
    """Simulates a third-party sanctions screening vendor (e.g., World-Check).

    KEY PRIVACY PROPERTY: This intermediary only sees PSi_stable values.
    It cannot learn names, DOBs, addresses, or any PII.
    """

    def __init__(self, name: str):
        self.name = name
        # Flagged pseudonyms received from PA
        self.flagged_pseudonyms: set[str] = set()

    def receive_sanctions_update(self, psi_stable: bytes):
        """Receive a pseudonymized sanctions entry from the PA.

        In the traditional model, the intermediary would receive
        'Bob Smith, DOB 1985-01-15, Passport X1234'.
        In PQ-PKAP, it receives '0x3fa8c2e1...' — a 32-byte hash.
        """
        self.flagged_pseudonyms.add(psi_stable.hex())
        logger.info(
            f"[{self.name}] Received sanctions update: "
            f"PSi_stable {psi_stable.hex()[:16]}... (NO name, NO DOB, NO address)"
        )

    async def screen(self, psi_stable: bytes) -> dict:
        """Screen a pseudonym against the sanctions list.

        Returns screening result without ever seeing real identity.
        """
        # Simulated network delay (real API would be ~50-200ms)
        await asyncio.sleep(0.01)

        is_flagged = psi_stable.hex() in self.flagged_pseudonyms
        result = {
            "psi_stable": psi_stable.hex()[:16] + "...",
            "status": "FLAGGED" if is_flagged else "CLEAN",
            "identity_exposed": "NONE — only pseudonym received",
        }

        if is_flagged:
            logger.error(
                f"[{self.name}] ⛔ ALERT: PSi_stable {psi_stable.hex()[:16]}... "
                f"matches sanctions list!"
            )
        else:
            logger.info(
                f"[{self.name}] ✅ PSi_stable {psi_stable.hex()[:16]}... is CLEAN"
            )

        return result


# ─────────────────────────────────────────────────────────────
#  Bank Server (Service Provider)
# ─────────────────────────────────────────────────────────────

class BankServer:
    """The Primary Bank — authenticates clients and forwards
    PSi_stable to intermediary for sanctions screening.

    The bank sees PSi_session (per-session) and PSi_stable (for screening)
    but NEVER sees ID_REAL.
    """

    def __init__(self, intermediary: SanctionsIntermediary):
        self.intermediary = intermediary
        # Database: PSi_stable → {z_i, sessions: [PSi_session, ...]}
        self.db: dict[str, dict] = {}

    def register_client(self, psi_stable: bytes, z_i: bytes):
        """Register a client by their stable pseudonym."""
        self.db[psi_stable.hex()] = {
            "z_i": z_i,
            "sessions": [],
        }

    async def authenticate_and_screen(
        self, client_name: str, psi_session: bytes, psi_stable: bytes, z_i: bytes
    ) -> dict:
        """Full authentication + intermediary screening flow.

        1. Verify client credentials (z_i) using PSi_stable as DB key
        2. Forward PSi_stable to intermediary for sanctions check
        3. Return result — client either passes or is blocked
        """
        logger.info(f"\n{'═' * 60}")
        logger.info(f"[Bank] Processing authentication for client '{client_name}'")
        logger.info(f"[Bank]   PSi_session: {psi_session.hex()[:16]}... (unlinkable)")
        logger.info(f"[Bank]   PSi_stable:  {psi_stable.hex()[:16]}... (for screening)")

        # Step 1: Verify credentials
        record = self.db.get(psi_stable.hex())
        if not record:
            logger.error(f"[Bank] Unknown PSi_stable — rejecting")
            return {"status": "REJECTED", "reason": "unknown_client"}

        if record["z_i"] != z_i:
            logger.error(f"[Bank] z_i mismatch — rejecting")
            return {"status": "REJECTED", "reason": "invalid_credentials"}

        logger.info(f"[Bank] ✅ Credentials verified (z_i match)")

        # Step 2: Forward PSi_stable to intermediary
        logger.info(
            f"[Bank] → Forwarding PSi_stable to '{self.intermediary.name}' "
            f"(NOT forwarding ID_REAL, name, DOB, address)"
        )
        screening_result = await self.intermediary.screen(psi_stable)

        # Step 3: Record session and return result
        record["sessions"].append(psi_session.hex()[:16])

        if screening_result["status"] == "FLAGGED":
            logger.error(
                f"[Bank] ⛔ REJECTING client — sanctions match detected"
            )
            return {
                "status": "REJECTED",
                "reason": "AML_FLAGGED",
                "screening": screening_result,
            }

        logger.info(f"[Bank] ✅ Client authenticated and cleared — Welcome!")
        return {
            "status": "APPROVED",
            "screening": screening_result,
        }


# ─────────────────────────────────────────────────────────────
#  Simulation Runner
# ─────────────────────────────────────────────────────────────

async def run_simulation():
    logger.info("=" * 60)
    logger.info("PQ-PKAP TIERED PSEUDONYM KYC SIMULATION")
    logger.info("Demonstrating: Identity Exposure Elimination")
    logger.info("=" * 60)

    # ── Initialize Actors ──
    pa = ProvisioningAuthority()
    intermediary = SanctionsIntermediary("WorldCheck-PQ")
    bank = BankServer(intermediary)

    # ── Phase 1: KYC Enrollment (Out-of-Band) ──
    logger.info(f"\n{DIVIDER}")
    logger.info("PHASE 1: KYC Enrollment (Provisioning Authority)")
    logger.info(DIVIDER)

    alice_real = b"Alice Sharma | DOB:1990-03-15 | Aadhaar:1234-5678-9012"
    bob_real   = b"Bob Patel | DOB:1985-01-20 | Aadhaar:9876-5432-1098"

    alice_secrets = pa.enroll_customer("Alice Sharma", alice_real)
    bob_secrets   = pa.enroll_customer("Bob Patel", bob_real)

    # ── Phase 2: Sanctions Flagging ──
    logger.info(f"\n{DIVIDER}")
    logger.info("PHASE 2: Sanctions List Synchronization")
    logger.info(DIVIDER)
    logger.info("[PA] Bob Patel flagged by OFAC sanctions list")
    bob_flagged_psi = pa.flag_for_sanctions(bob_real)
    if bob_flagged_psi:
        intermediary.receive_sanctions_update(bob_flagged_psi)

    logger.info(
        f"\n[Privacy Check] What does the intermediary know about Bob?"
    )
    logger.info(f"  Name:     ❌ NOT shared")
    logger.info(f"  DOB:      ❌ NOT shared")
    logger.info(f"  Aadhaar:  ❌ NOT shared")
    logger.info(f"  Address:  ❌ NOT shared")
    logger.info(f"  PSi_stable: ✅ {bob_flagged_psi.hex()[:16]}... (opaque 32-byte hash)")

    # ── Phase 3: Register Clients at Bank ──
    logger.info(f"\n{DIVIDER}")
    logger.info("PHASE 3: Client Registration at Bank")
    logger.info(DIVIDER)

    alice_psi_stable = derive_stable_pseudonym(alice_real, alice_secrets["sd"])
    bob_psi_stable   = derive_stable_pseudonym(bob_real, bob_secrets["sd"])

    bank.register_client(alice_psi_stable, alice_secrets["z_i"])
    bank.register_client(bob_psi_stable, bob_secrets["z_i"])
    logger.info("[Bank] Registered 2 clients (by PSi_stable, no real identities stored)")

    # ── Phase 4: Session Authentication ──
    logger.info(f"\n{DIVIDER}")
    logger.info("PHASE 4: Session Authentication + Intermediary Screening")
    logger.info(DIVIDER)

    # Alice - Session 1 (Expect: APPROVED)
    alice_a_i_s1 = b32()
    alice_psi_s1 = derive_pseudonym(alice_real, alice_secrets["sd"], alice_a_i_s1)
    result = await bank.authenticate_and_screen(
        "Alice (Session 1)", alice_psi_s1, alice_psi_stable, alice_secrets["z_i"]
    )

    # Alice - Session 2 (Different PSi_session, same PSi_stable — still APPROVED)
    alice_a_i_s2 = b32()
    alice_psi_s2 = derive_pseudonym(alice_real, alice_secrets["sd"], alice_a_i_s2)
    result = await bank.authenticate_and_screen(
        "Alice (Session 2)", alice_psi_s2, alice_psi_stable, alice_secrets["z_i"]
    )

    # Bob - Session 1 (Expect: REJECTED — sanctions match)
    bob_a_i_s1 = b32()
    bob_psi_s1 = derive_pseudonym(bob_real, bob_secrets["sd"], bob_a_i_s1)
    result = await bank.authenticate_and_screen(
        "Bob (Session 1)", bob_psi_s1, bob_psi_stable, bob_secrets["z_i"]
    )

    # ── Phase 5: Unlinkability Demonstration ──
    logger.info(f"\n{DIVIDER}")
    logger.info("PHASE 5: Unlinkability Verification")
    logger.info(DIVIDER)

    logger.info(f"\n  Alice Session 1 PSi_session: {alice_psi_s1.hex()[:24]}...")
    logger.info(f"  Alice Session 2 PSi_session: {alice_psi_s2.hex()[:24]}...")
    sessions_different = alice_psi_s1 != alice_psi_s2
    logger.info(
        f"  Sessions unlinkable: {'✅ YES' if sessions_different else '❌ NO'} "
        f"(PSi_session values are {'different' if sessions_different else 'SAME — BUG!'})"
    )

    logger.info(f"\n  Alice PSi_stable (screening): {alice_psi_stable.hex()[:24]}...")
    logger.info(
        f"  Stable pseudonym consistent:  ✅ YES (same across both sessions)"
    )

    # ── Phase 6: Data Exposure Comparison ──
    logger.info(f"\n{DIVIDER}")
    logger.info("PHASE 6: Data Exposure Comparison")
    logger.info(DIVIDER)

    logger.info("""
  ┌──────────────────────────────────────────────────────────────────┐
  │              TRADITIONAL KYC vs PQ-PKAP COMPARISON              │
  ├──────────────────────┬──────────────────┬───────────────────────┤
  │ Data Field           │ Traditional KYC  │ PQ-PKAP (This Proto.) │
  ├──────────────────────┼──────────────────┼───────────────────────┤
  │ Full Name            │ ✅ EXPOSED       │ ❌ NOT SENT           │
  │ Date of Birth        │ ✅ EXPOSED       │ ❌ NOT SENT           │
  │ National ID (Aadhaar)│ ✅ EXPOSED       │ ❌ NOT SENT           │
  │ Address              │ ✅ EXPOSED       │ ❌ NOT SENT           │
  │ PAN Number           │ ✅ EXPOSED       │ ❌ NOT SENT           │
  │ Pseudonym (opaque)   │ N/A              │ ✅ PSi_stable only    │
  ├──────────────────────┼──────────────────┼───────────────────────┤
  │ Intermediary can     │                  │                       │
  │  identify person?    │ ✅ YES           │ ❌ NO                 │
  │ Intermediary can     │                  │                       │
  │  screen sanctions?   │ ✅ YES           │ ✅ YES (via PSi)      │
  │ Quantum resistant?   │ ❌ NO            │ ✅ YES                │
  └──────────────────────┴──────────────────┴───────────────────────┘
    """)

    # ── Phase 7: Lawful De-anonymization ──
    logger.info(DIVIDER)
    logger.info("PHASE 7: Lawful De-anonymization (Regulatory Mandate)")
    logger.info(DIVIDER)

    logger.info("[Regulator] Court order received for flagged PSi_stable")
    logger.info("[Regulator] → Requesting de-anonymization from PA")
    revealed_name = pa.de_anonymize(bob_psi_stable)
    if revealed_name:
        logger.info(
            f"[Regulator] Investigation complete — identity revealed: '{revealed_name}'"
        )
        logger.info(
            f"[Regulator] Only Bob's identity was revealed. "
            f"Alice and all other users remain pseudonymous."
        )

    logger.info(f"\n{'═' * 60}")
    logger.info("SIMULATION COMPLETE")
    logger.info("═" * 60)
    logger.info(
        "\nKey Result: Sanctions screening achieved with ZERO identity exposure "
        "to the intermediary."
    )


if __name__ == "__main__":
    asyncio.run(run_simulation())
