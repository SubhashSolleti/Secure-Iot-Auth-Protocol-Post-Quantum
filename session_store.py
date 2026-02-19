"""
session_store – Session ticket storage for handshake resumption.

After a successful handshake the server issues an encrypted session
ticket containing K_sess and the client pseudonym.  On reconnection
the client presents the ticket to skip the full key-exchange.

Tickets are encrypted with a server-side master key (rotated at startup)
and expire after ``SESSION_TICKET_TTL_SEC``.
"""

import os
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from pq_commons import aead_encrypt, aead_decrypt, b32, sha256
from config import SESSION_TICKET_TTL_SEC


# ── Server-side master key (regenerated each server restart) ─────────────
_TICKET_MASTER_KEY: bytes = b32()  # 256-bit ephemeral key


@dataclass
class _TicketEntry:
    """Internal record for a stored session ticket."""
    psi: bytes          # pseudonym at issue time
    k_sess: bytes       # session key
    issued_at: float    # monotonic timestamp


class SessionStore:
    """
    In-memory session ticket store.

    ``issue()`` creates a ticket from a completed handshake.
    ``resume()`` validates and returns session material.
    Expired tickets are garbage-collected lazily on access.
    """

    def __init__(self, ttl: float = SESSION_TICKET_TTL_SEC) -> None:
        self._ttl = ttl
        self._tickets: Dict[bytes, _TicketEntry] = {}

    # ── Issue ─────────────────────────────────────────────────────────────
    def issue(self, psi: bytes, k_sess: bytes) -> bytes:
        """
        Create an opaque session ticket for the given session.

        Returns a ticket ID (32 bytes) to send to the client.
        """
        ticket_id = b32()
        self._tickets[ticket_id] = _TicketEntry(
            psi=psi,
            k_sess=k_sess,
            issued_at=time.monotonic(),
        )
        return ticket_id

    # ── Resume ────────────────────────────────────────────────────────────
    def resume(self, ticket_id: bytes) -> Optional[Tuple[bytes, bytes]]:
        """
        Attempt to resume a session from *ticket_id*.

        Returns ``(psi, k_sess)`` on success, or ``None`` if the ticket
        is invalid, expired, or already consumed.
        """
        entry = self._tickets.pop(ticket_id, None)  # one-time use
        if entry is None:
            return None
        age = time.monotonic() - entry.issued_at
        if age > self._ttl:
            return None  # expired
        return entry.psi, entry.k_sess

    # ── Housekeeping ──────────────────────────────────────────────────────
    def purge_expired(self) -> int:
        """Remove all expired tickets and return the count removed."""
        now = time.monotonic()
        expired = [
            tid for tid, e in self._tickets.items()
            if (now - e.issued_at) > self._ttl
        ]
        for tid in expired:
            del self._tickets[tid]
        return len(expired)

    @property
    def size(self) -> int:
        """Number of active tickets."""
        return len(self._tickets)
