"""
Tests for pseudonym rotation – verifies A_I rotates after N sessions.
"""

import os
import sys
import json
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestPseudonymRotation:

    def setup_method(self):
        """Reset secrets_config internal state for isolated tests."""
        import secrets_config
        import config

        self.orig_rotate_every = config.PSEUDONYM_ROTATE_EVERY
        config.PSEUDONYM_ROTATE_EVERY = 3  # rotate every 3 sessions for test

        # Reset internal state
        secrets_config._state = {"session_count": 0, "a_i_hex": "02" * 32}
        secrets_config.A_I = bytes.fromhex("02" * 32)

        # Use a temp file for state persistence
        self._tmpfile = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self._tmpfile.close()
        secrets_config._STATE_FILE = type(secrets_config._STATE_FILE)(self._tmpfile.name)

    def teardown_method(self):
        import config
        config.PSEUDONYM_ROTATE_EVERY = self.orig_rotate_every
        if os.path.isfile(self._tmpfile.name):
            os.unlink(self._tmpfile.name)

    def test_no_rotation_before_threshold(self):
        import secrets_config
        original_a_i = secrets_config.A_I
        secrets_config.rotate_epoch()  # session 1
        secrets_config.rotate_epoch()  # session 2
        assert secrets_config.A_I == original_a_i

    def test_rotation_at_threshold(self):
        import secrets_config
        import config
        original_a_i = secrets_config.A_I
        for _ in range(config.PSEUDONYM_ROTATE_EVERY):
            secrets_config.rotate_epoch()
        assert secrets_config.A_I != original_a_i

    def test_counter_resets_after_rotation(self):
        import secrets_config
        import config
        for _ in range(config.PSEUDONYM_ROTATE_EVERY):
            secrets_config.rotate_epoch()
        assert secrets_config.get_session_count() == 0

    def test_state_persisted_to_file(self):
        import secrets_config
        secrets_config.rotate_epoch()
        with open(self._tmpfile.name, "r") as f:
            state = json.load(f)
        assert state["session_count"] == 1
