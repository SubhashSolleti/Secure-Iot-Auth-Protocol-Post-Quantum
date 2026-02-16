"""
rate_limiter – Per-IP token-bucket rate limiter.

Prevents DoS attacks by throttling connections per source IP.
Each IP gets a bucket with `RATE_LIMIT_BURST` tokens that refills
at `RATE_LIMIT_PER_SEC` tokens per second.
"""

import time
from dataclasses import dataclass, field
from typing import Dict

from config import RATE_LIMIT_PER_SEC, RATE_LIMIT_BURST


@dataclass
class _Bucket:
    """Internal token bucket for a single IP."""
    tokens: float = RATE_LIMIT_BURST
    last_refill: float = field(default_factory=time.monotonic)


class RateLimiter:
    """
    Thread-safe-ish token-bucket rate limiter keyed by IP address.

    Not truly thread-safe (no locks) but safe for single-threaded asyncio
    since all access is from the event loop.
    """

    def __init__(
        self,
        rate: float = RATE_LIMIT_PER_SEC,
        burst: int = RATE_LIMIT_BURST,
    ) -> None:
        self._rate = rate
        self._burst = burst
        self._buckets: Dict[str, _Bucket] = {}

    def _get_bucket(self, ip: str) -> _Bucket:
        if ip not in self._buckets:
            self._buckets[ip] = _Bucket(tokens=self._burst)
        return self._buckets[ip]

    def allow(self, ip: str) -> bool:
        """
        Return **True** if the IP has remaining tokens (connection allowed).

        Consumes one token on success.  Refills tokens based on elapsed time.
        """
        bucket = self._get_bucket(ip)
        now = time.monotonic()
        elapsed = now - bucket.last_refill
        bucket.tokens = min(self._burst, bucket.tokens + elapsed * self._rate)
        bucket.last_refill = now

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return True
        return False

    def reset(self, ip: str | None = None) -> None:
        """Reset a single IP bucket, or all buckets if *ip* is None."""
        if ip is None:
            self._buckets.clear()
        else:
            self._buckets.pop(ip, None)
