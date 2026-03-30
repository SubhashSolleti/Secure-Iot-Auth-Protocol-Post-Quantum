"""
Long-term identity management for PQC authentication.

Uses ML-DSA-65 persistent identity keys with a TOFU (Trust On First Use)
model for peer authentication. On first encounter, a peer's public key is
pinned; subsequent connections are verified against the pinned key.
"""

import os
import secrets
import logging
from pathlib import Path

from pqcrypto.sign.ml_dsa_65 import generate_keypair, sign, verify

logger = logging.getLogger(__name__)


class IdentityManager:
    """Manages long-term ML-DSA-65 identity keys and trusted peer keys."""

    def __init__(self, role: str, data_dir: Path):
        self.role = role
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.trusted_dir = self.data_dir / "trusted_peers"
        self.trusted_dir.mkdir(parents=True, exist_ok=True)
        self.pk, self.sk = self._load_or_generate()

    @staticmethod
    def _secure_permissions(path: Path, private: bool = False):
        """Set restrictive file permissions on key material."""
        os.chmod(path, 0o600 if private else 0o644)

    def _load_or_generate(self):
        """Load existing identity keypair or generate a new one."""
        pk_path = self.data_dir / "identity.pk"
        sk_path = self.data_dir / "identity.sk"
        if pk_path.exists() and sk_path.exists():
            pk = pk_path.read_bytes()
            sk = sk_path.read_bytes()
            # Ensure permissions are correct even for existing files
            self._secure_permissions(sk_path, private=True)
            self._secure_permissions(pk_path, private=False)
            logger.info(f"[{self.role}] Loaded long-term ML-DSA-65 identity key")
            return pk, sk
        pk, sk = generate_keypair()
        pk_path.write_bytes(pk)
        sk_path.write_bytes(sk)
        self._secure_permissions(sk_path, private=True)
        self._secure_permissions(pk_path, private=False)
        logger.info(f"[{self.role}] Generated new long-term ML-DSA-65 identity key")
        return pk, sk

    def sign_message(self, data: bytes) -> bytes:
        """Sign data with long-term private key."""
        return sign(self.sk, data)

    @staticmethod
    def verify_signature(peer_pk: bytes, data: bytes, sig: bytes) -> bool:
        """Verify a signature against a given public key."""
        try:
            return verify(peer_pk, data, sig)
        except Exception:
            return False

    def trust_peer(self, peer_id: str, peer_pk: bytes) -> None:
        """Store a peer's public key on first encounter (TOFU)."""
        path = self.trusted_dir / f"{peer_id}.pk"
        path.write_bytes(peer_pk)
        logger.info(f"[{self.role}] Pinned peer '{peer_id}' (TOFU)")

    def get_trusted_peer_key(self, peer_id: str) -> bytes | None:
        """Retrieve a previously pinned peer's public key."""
        path = self.trusted_dir / f"{peer_id}.pk"
        if path.exists():
            return path.read_bytes()
        return None

    def verify_peer_identity(self, peer_id: str, peer_pk: bytes) -> tuple[bool, bool]:
        """
        Verify a peer's identity using the TOFU model.

        Returns:
            (is_trusted, is_new)
            - is_trusted: True if peer_pk matches stored key (or first time)
            - is_new: True if this is the first encounter with this peer
        """
        stored = self.get_trusted_peer_key(peer_id)
        if stored is None:
            self.trust_peer(peer_id, peer_pk)
            return True, True
        return secrets.compare_digest(stored, peer_pk), False
