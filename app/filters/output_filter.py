from __future__ import annotations

import re
from dataclasses import dataclass


# ── Patterns that should never appear in responses ────────────────────────────

SENSITIVE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"sk-[a-zA-Z0-9]{20,}", re.I), "OpenAI API key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"-----BEGIN\s+(RSA\s+|EC\s+)?PRIVATE KEY-----"), "Private key"),
    (re.compile(r"(?<!\w)password\s*[:=]\s*\S+", re.I), "Password"),
    (re.compile(r"(?<!\w)secret\s*[:=]\s*\S+", re.I), "Secret"),
    (re.compile(r"(?<!\w)(api[_\s]?key|access[_\s]?token)\s*[:=]\s*\S+", re.I), "API credential"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN"),
    (re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"), "Credit card number"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "Email address"),
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "IP address"),
]

# Phrases that indicate the LLM may be leaking system context
CONTEXT_LEAK_PHRASES: list[str] = [
    "my system prompt is",
    "my instructions say",
    "the context documents contain",
    "i was told to",
    "i have been instructed to",
    "as per my instructions",
    "[document:",
    "[system prompt]",
]

# If we need to redact more than this, block the response entirely
MAX_REDACTIONS = 3


@dataclass
class OutputResult:
    response: str
    blocked: bool
    reason: str | None
    redactions: int


class OutputFilter:
    """
    Scans LLM responses for:
    - Sensitive data patterns (API keys, PII, credentials)
    - Context/system prompt leakage
    - Excessive redactions (which suggests something is very wrong)
    """

    def scan(self, response: str) -> OutputResult:
        if not response:
            return OutputResult(response="", blocked=False, reason=None, redactions=0)

        cleaned = response
        redaction_count = 0

        # Pattern-based redaction
        for pattern, label in SENSITIVE_PATTERNS:
            def redact(m, lbl=label):
                return f"[REDACTED:{lbl}]"
            new = pattern.sub(redact, cleaned)
            if new != cleaned:
                redaction_count += len(pattern.findall(cleaned))
                cleaned = new

        # Context leak detection
        response_lower = cleaned.lower()
        for phrase in CONTEXT_LEAK_PHRASES:
            if phrase in response_lower:
                return OutputResult(
                    response="",
                    blocked=True,
                    reason=f"Response blocked: potential context leakage detected ('{phrase}')",
                    redactions=redaction_count,
                )

        # If too many redactions were needed, block instead of returning a swiss-cheese response
        if redaction_count >= MAX_REDACTIONS:
            return OutputResult(
                response="",
                blocked=True,
                reason=f"Response blocked: {redaction_count} sensitive items detected",
                redactions=redaction_count,
            )

        return OutputResult(
            response=cleaned,
            blocked=False,
            reason=None,
            redactions=redaction_count,
        )
