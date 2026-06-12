import time
import pytest
from app.abuse.rate_limiter import RateLimiter


# ── Normal usage ──────────────────────────────────────────────────────────────

def test_normal_requests_pass():
    limiter = RateLimiter(capacity=10)
    for i in range(5):
        result = limiter.check("user_normal", f"query number {i}")
        assert not result.is_abusive


def test_fresh_user_gets_full_bucket():
    limiter = RateLimiter(capacity=5)
    result = limiter.check("fresh_user", "first query")
    assert not result.is_abusive
    stats = limiter.stats("fresh_user")
    assert stats["tokens_remaining"] == 4.0  # 5 - 1


# ── Rate limiting ─────────────────────────────────────────────────────────────

def test_rate_limit_triggers_after_capacity():
    limiter = RateLimiter(capacity=3, refill_rate=0.0)  # no refill for test
    for i in range(3):
        result = limiter.check("user_spam", f"query {i}")
        assert not result.is_abusive

    # 4th request should be blocked
    result = limiter.check("user_spam", "one more query")
    assert result.is_abusive
    assert result.reason == "rate_limit_exceeded"
    assert result.score == 1.0


def test_different_users_dont_interfere():
    limiter = RateLimiter(capacity=2, refill_rate=0.0)
    for i in range(2):
        limiter.check("user_a", f"query {i}")

    # user_a is exhausted
    assert limiter.check("user_a", "overflow").is_abusive
    # user_b should still be fine
    assert not limiter.check("user_b", "first query").is_abusive


def test_reset_restores_bucket():
    limiter = RateLimiter(capacity=2, refill_rate=0.0)
    limiter.check("user_reset", "q1")
    limiter.check("user_reset", "q2")
    assert limiter.check("user_reset", "q3").is_abusive

    limiter.reset("user_reset")
    assert not limiter.check("user_reset", "q1 again").is_abusive


# ── Fuzzing detection ─────────────────────────────────────────────────────────

def test_fuzzing_detected_on_similar_queries():
    limiter = RateLimiter(capacity=20)
    base = "What is the maximum monthly expense allowed"
    limiter.check("user_fuzz", base)

    near_dup = "What is the maximum monthly expenses allowed"  # very similar
    result = limiter.check("user_fuzz", near_dup)
    assert result.is_abusive
    assert result.reason == "fuzzing_detected"


def test_different_queries_not_flagged_as_fuzzing():
    limiter = RateLimiter(capacity=20)
    queries = [
        "What is the expense policy?",
        "How many sick days do I get?",
        "What are the password requirements?",
        "Can I work from home on Fridays?",
    ]
    for q in queries:
        result = limiter.check("user_varied", q)
        assert not result.is_abusive, f"Legitimate query flagged as fuzzing: {q!r}"


def test_exact_repeat_triggers_rate_limit_not_fuzzing():
    limiter = RateLimiter(capacity=20)
    same = "What is the expense policy?"
    limiter.check("user_repeat", same)
    result = limiter.check("user_repeat", same)
    # Exact repeat is not counted as fuzzing (ratio == 1.0 is excluded)
    # It's just another request consuming a token
    assert not result.is_abusive or result.reason != "fuzzing_detected"


# ── Stats ─────────────────────────────────────────────────────────────────────

def test_stats_returns_correct_structure():
    limiter = RateLimiter(capacity=5)
    limiter.check("user_stats", "a query")
    stats = limiter.stats("user_stats")
    assert "tokens_remaining" in stats
    assert "capacity" in stats
    assert stats["capacity"] == 5
