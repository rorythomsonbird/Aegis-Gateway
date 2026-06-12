from __future__ import annotations

import re
from dataclasses import dataclass

from app.config import INJECTION_THRESHOLD


# ── Compiled regex patterns with associated weights ───────────────────────────
# Weight = how much this pattern contributes to the injection score (0–1)

INJECTION_PATTERNS: list[tuple[re.Pattern, float]] = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions?", re.I), 0.95),
    (re.compile(r"forget\s+(your\s+)?(previous\s+|all\s+)?instructions?", re.I), 0.95),
    (re.compile(r"disregard\s+(all\s+)?(previous|prior)", re.I), 0.85),
    (re.compile(r"(reveal|show|print|output|display)\s+(me\s+)?(your\s+)?(system\s+)?prompt", re.I), 0.95),
    (re.compile(r"what\s+(are|were)\s+(your\s+)?(previous\s+|actual\s+)?instructions", re.I), 0.85),
    (re.compile(r"new\s+(system\s+)?prompt\s*:", re.I), 0.95),
    (re.compile(r"(act|behave)\s+as\s+(if\s+)?(you\s+(are|were)|a|an)\s+", re.I), 0.75),
    (re.compile(r"pretend\s+(you\s+(are|have)|to\s+be)", re.I), 0.75),
    (re.compile(r"you\s+are\s+now\s+\w+", re.I), 0.75),
    (re.compile(r"(override|bypass|disable)\s+(all\s+)?(your\s+)?restrictions?", re.I), 0.90),
    (re.compile(r"developer\s+mode\s*(enabled?|on|activated?)?", re.I), 0.90),
    (re.compile(r"admin\s+(mode|access)\s*(enabled?|on|activated?)?", re.I), 0.90),
    (re.compile(r"\[?\s*(SYSTEM|SYS|INST)\s*\]?\s*:", re.I), 0.80),
    (re.compile(r"your\s+(real|actual|true|hidden)\s+instructions?\s+(are|is|say|state)", re.I), 0.90),
    (re.compile(r"repeat\s+(back\s+)?(everything|all|the\s+context|the\s+documents?)", re.I), 0.75),
    (re.compile(r"translate\s+(the\s+)?(above|previous|following)\s+(to|into)\s+\w+", re.I), 0.55),
]

# Keyword heuristics — lower individual weights, pile up if several appear
INJECTION_KEYWORDS: dict[str, float] = {
    "jailbreak": 0.80,
    "DAN": 0.70,
    "unrestricted mode": 0.75,
    "no restrictions": 0.65,
    "without restrictions": 0.55,
    "god mode": 0.75,
    "sudo": 0.45,
    "root access": 0.70,
    "dev mode": 0.65,
    "base instructions": 0.65,
    "initial prompt": 0.60,
    "original instructions": 0.65,
    "hypothetically speaking": 0.45,
}


@dataclass
class FilterResult:
    is_malicious: bool
    score: float
    reason: str


class InputFilter:
    """
    Scans incoming queries for prompt injection attempts using:
    - Compiled regex patterns (high-confidence markers)
    - Keyword heuristics (lower confidence, but additive)

    Score is the max of all matched signals — not a sum — to keep it bounded [0, 1].
    """

    def analyze(self, query: str) -> FilterResult:
        if not query or not query.strip():
            return FilterResult(is_malicious=False, score=0.0, reason="empty input")

        score = 0.0
        hits: list[str] = []

        # Regex pass
        for pattern, weight in INJECTION_PATTERNS:
            if pattern.search(query):
                if weight > score:
                    score = weight
                hits.append(f"pattern:{pattern.pattern[:40]}")

        # Keyword pass
        query_lower = query.lower()
        for keyword, weight in INJECTION_KEYWORDS.items():
            if keyword.lower() in query_lower:
                if weight > score:
                    score = weight
                hits.append(f"keyword:{keyword}")

        is_malicious = score >= INJECTION_THRESHOLD

        if hits:
            reason = f"Matched: {', '.join(hits[:3])}"
        else:
            reason = "No injection signals detected"

        return FilterResult(is_malicious=is_malicious, score=round(score, 3), reason=reason)

    def sanitize(self, query: str) -> str:
        """
        Strip obvious injection phrases from a borderline query.
        Used when score is suspicious but below the block threshold.
        """
        sanitized = query
        for pattern, _ in INJECTION_PATTERNS:
            sanitized = pattern.sub("", sanitized)
        return " ".join(sanitized.split())  # clean up extra whitespace
