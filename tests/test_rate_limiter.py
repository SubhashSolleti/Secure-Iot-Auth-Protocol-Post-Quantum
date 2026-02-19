"""
Tests for rate_limiter – token-bucket per-IP throttling.
"""

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rate_limiter import RateLimiter


class TestRateLimiter:

    def test_allows_within_burst(self):
        rl = RateLimiter(rate=10, burst=5)
        for _ in range(5):
            assert rl.allow("1.2.3.4") is True

    def test_denies_after_burst(self):
        rl = RateLimiter(rate=10, burst=3)
        for _ in range(3):
            rl.allow("1.2.3.4")
        assert rl.allow("1.2.3.4") is False

    def test_refills_over_time(self):
        rl = RateLimiter(rate=100, burst=2)
        rl.allow("x")
        rl.allow("x")
        assert rl.allow("x") is False
        time.sleep(0.05)  # 50ms @ 100/sec = ~5 tokens refilled
        assert rl.allow("x") is True

    def test_independent_ips(self):
        rl = RateLimiter(rate=10, burst=1)
        assert rl.allow("a") is True
        assert rl.allow("a") is False
        assert rl.allow("b") is True  # different IP unaffected

    def test_reset_single_ip(self):
        rl = RateLimiter(rate=10, burst=1)
        rl.allow("a")
        rl.reset("a")
        assert rl.allow("a") is True

    def test_reset_all(self):
        rl = RateLimiter(rate=10, burst=1)
        rl.allow("a")
        rl.allow("b")
        rl.reset()
        assert rl.allow("a") is True
        assert rl.allow("b") is True
