"""
Tests for session_store – ticket issue, resume, and expiry.
"""

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from session_store import SessionStore
from pq_commons import b32


class TestSessionStore:

    def test_issue_returns_ticket_id(self):
        store = SessionStore()
        psi = b32()
        k_sess = b32()
        ticket = store.issue(psi, k_sess)
        assert isinstance(ticket, bytes)
        assert len(ticket) == 32

    def test_resume_valid_ticket(self):
        store = SessionStore()
        psi = b32()
        k_sess = b32()
        ticket = store.issue(psi, k_sess)
        result = store.resume(ticket)
        assert result is not None
        assert result == (psi, k_sess)

    def test_resume_consumes_ticket(self):
        """Tickets are one-time use."""
        store = SessionStore()
        ticket = store.issue(b32(), b32())
        store.resume(ticket)
        assert store.resume(ticket) is None

    def test_resume_invalid_ticket(self):
        store = SessionStore()
        assert store.resume(b32()) is None

    def test_expired_ticket(self):
        store = SessionStore(ttl=0.01)  # 10ms TTL
        ticket = store.issue(b32(), b32())
        time.sleep(0.02)
        assert store.resume(ticket) is None

    def test_purge_expired(self):
        store = SessionStore(ttl=0.01)
        store.issue(b32(), b32())
        store.issue(b32(), b32())
        time.sleep(0.02)
        removed = store.purge_expired()
        assert removed == 2
        assert store.size == 0

    def test_size(self):
        store = SessionStore()
        assert store.size == 0
        store.issue(b32(), b32())
        store.issue(b32(), b32())
        assert store.size == 2
