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
    tokens: float                                              # set explicitly on creation
    last_refill: float = field(default_factory=time.time)
    recent_queries: list[str] = field(default_factory=list)


class RateLimiter:
    """
    Two-layer abuse detection, evaluated in strict order:

    1. Rate limit  — token bucket, checked FIRST.
       Ensures capacity enforcement can never be skipped.

    2. Fuzzing     — checked SECOND, only on queries long enough
       to produce meaningful similarity scores. Short templated
       strings (e.g. "query 0", "query 1") are excluded by the
       word-count gate so they don't cause false positives.
       Fuzzing does NOT consume a token — the attacker pays nothing.
    """

    RECENT_WINDOW = 10
    MIN_FUZZ_QUERY_WORDS = 6   # ignore short queries for fuzzing check

    def __init__(self, capacity: int | None = None, refill_rate: float | None = None):
        self.capacity = capacity if capacity is not None else RATE_LIMIT_CAPACITY
        self.refill_rate = refill_rate if refill_rate is not None else RATE_LIMIT_REFILL
        self._buckets: dict[str, _Bucket] = {}

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get(self, user_id: str) -> _Bucket:
        if user_id not in self._buckets:
            # Pass capacity explicitly — never relies on module-level constant
            self._buckets[user_id] = _Bucket(tokens=float(self.capacity))
        return self._buckets[user_id]

    def _refill(self, bucket: _Bucket) -> None:
        now = time.time()
        elapsed = now - bucket.last_refill
        bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.refill_rate)
        bucket.last_refill = now

    def _is_fuzzing(self, bucket: _Bucket, query: str) -> bool:
        # Short queries produce false positives — skip them entirely
        if len(query.split()) < self.MIN_FUZZ_QUERY_WORDS:
            return False

        recent = bucket.recent_queries[-self.RECENT_WINDOW:]

        for prev in recent:
            if prev == query:
                continue   # exact repeat is just rate-limit abuse, not fuzzing
            if SequenceMatcher(None, query.lower(), prev.lower()).ratio() >= FUZZ_THRESHOLD:
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

        # ① Rate limit FIRST — cannot be bypassed by fuzzing logic
        if bucket.tokens < 1.0:
            return AbuseResult(is_abusive=True, reason="rate_limit_exceeded", score=1.0)

        # ② Fuzzing SECOND — records the query but does NOT consume a token
        if self._is_fuzzing(bucket, query):
            self._record(bucket, query)
            return AbuseResult(is_abusive=True, reason="fuzzing_detected", score=0.9)

        # ③ Legitimate request — consume token and record
        bucket.tokens -= 1.0
        self._record(bucket, query)
        return AbuseResult(is_abusive=False, reason=None, score=0.0)

    def reset(self, user_id: str) -> None:
        """Wipe a user's bucket. Useful for testing."""
        self._buckets.pop(user_id, None)

    def stats(self, user_id: str) -> dict:
        bucket = self._get(user_id)
        self._refill(bucket)
        return {
            "user_id": user_id,
            "tokens_remaining": round(bucket.tokens, 2),
            "capacity": self.capacity,
            "recent_query_count": len(bucket.recent_queries),
        }
