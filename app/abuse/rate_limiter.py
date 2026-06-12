from __future__ import annotations

import time
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from app.config import RATE_LIMIT_CAPACITY, RATE_LIMIT_REFILL, FUZZ_THRESHOLD


@dataclass
class AbuseResult:
    is_abusive: bool
    reason: str | None
    score: float


@dataclass
class _Bucket:
    tokens: float = field(default_factory=lambda: float(RATE_LIMIT_CAPACITY))
    last_refill: float = field(default_factory=time.time)
    recent_queries: list[str] = field(default_factory=list)


class RateLimiter:
    """
    Two-layer abuse detection:

    1. Token bucket  — each user gets RATE_LIMIT_CAPACITY requests per window.
       Tokens refill continuously at RATE_LIMIT_REFILL tokens/second so bursting
       is penalised but sustained low-rate usage is fine.

    2. Fuzzing detection — tracks the last N queries per user. If the current
       query is very similar (SequenceMatcher ratio >= FUZZ_THRESHOLD) to a
       recent one, it's flagged as query fuzzing.
    """

    RECENT_WINDOW = 10   # how many recent queries to keep per user

    def __init__(self, capacity: int | None = None, refill_rate: float | None = None):
        self.capacity = capacity if capacity is not None else RATE_LIMIT_CAPACITY
        self.refill_rate = refill_rate if refill_rate is not None else RATE_LIMIT_REFILL
        self._buckets: dict[str, _Bucket] = {}

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get(self, user_id: str) -> _Bucket:
        if user_id not in self._buckets:
            self._buckets[user_id] = _Bucket(tokens=float(self.capacity))
        return self._buckets[user_id]

    def _refill(self, bucket: _Bucket) -> None:
        now = time.time()
        elapsed = now - bucket.last_refill
        bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.refill_rate)
        bucket.last_refill = now

    def _is_fuzzing(self, bucket: _Bucket, query: str) -> bool:
        for prev in bucket.recent_queries[-self.RECENT_WINDOW:]:
            if prev == query:
                # Exact repeat counts as rate-limit abuse, not fuzzing
                continue
            ratio = SequenceMatcher(None, query.lower(), prev.lower()).ratio()
            if ratio >= FUZZ_THRESHOLD:
                return True
        return False

    def _record(self, bucket: _Bucket, query: str) -> None:
        bucket.recent_queries.append(query)
        if len(bucket.recent_queries) > 20:
            bucket.recent_queries = bucket.recent_queries[-20:]

    # ── Public API ────────────────────────────────────────────────────────────

    def check(self, user_id: str, query: str) -> AbuseResult:
        bucket = self._get(user_id)
        self._refill(bucket)

        if self._is_fuzzing(bucket, query):
            self._record(bucket, query)
            return AbuseResult(is_abusive=True, reason="fuzzing_detected", score=0.9)

        if bucket.tokens < 1.0:
            return AbuseResult(is_abusive=True, reason="rate_limit_exceeded", score=1.0)

        bucket.tokens -= 1.0
        self._record(bucket, query)
        return AbuseResult(is_abusive=False, reason=None, score=0.0)

    def reset(self, user_id: str) -> None:
        """Wipe a user's bucket. Handy for testing."""
        self._buckets.pop(user_id, None)

    def stats(self, user_id: str) -> dict:
        """Return current bucket state for a user."""
        bucket = self._get(user_id)
        self._refill(bucket)
        return {
            "user_id": user_id,
            "tokens_remaining": round(bucket.tokens, 2),
            "capacity": self.capacity,
            "recent_query_count": len(bucket.recent_queries),
        }
