from __future__ import annotations

import os

from app.config import OPENAI_MODEL


# ── Mock responses ────────────────────────────────────────────────────────────

_MOCK_RESPONSES: dict[str, str] = {
    "expense": (
        "Based on the Employee Expense Policy, employees can submit claims up to "
        "$500 per month. Receipts are required and must be submitted within 30 days. "
        "Manager approval is needed for any single claim over $200."
    ),
    "password": (
        "According to the IT Security Policy, passwords must be at least 12 characters "
        "and include uppercase letters, lowercase letters, numbers, and symbols. "
        "Multi-factor authentication is also required for all internal systems."
    ),
    "remote": (
        "The Remote Work Policy allows up to 3 days of remote work per week with "
        "manager approval. Core hours of 10am–3pm local time must be observed, and "
        "a $500 home office stipend is available as a one-time benefit."
    ),
    "vacation": (
        "Full-time employees accrue 15 days of PTO per year and receive 10 sick days "
        "plus 13 holidays (11 federal + 2 floating). PTO requests for more than 3 "
        "consecutive days need at least 2 weeks' notice."
    ),
    "security": (
        "All security incidents must be reported to security@corp.com within 1 hour "
        "of discovery. Do not attempt to investigate or remediate on your own — "
        "preserve all evidence and contact the incident response team."
    ),
    "office": (
        "The office is open Monday–Friday, 7am to 8pm. A valid badge is required "
        "for entry. Visitors must be pre-registered and escorted at all times. "
        "After-hours access requires manager authorisation."
    ),
    "conduct": (
        "The Code of Conduct requires respectful and professional behaviour at all "
        "times. Harassment and discrimination are grounds for immediate termination. "
        "Conflicts of interest must be disclosed to HR and Legal in writing."
    ),
}

_DEFAULT_RESPONSE = (
    "Based on the available company policy documents, I can help with questions about "
    "expenses, remote work, IT security, time off, office access, and conduct. "
    "Could you provide more detail about what you need?"
)


# ── Public API ────────────────────────────────────────────────────────────────

def active_backend() -> str:
    """Returns a human-readable string identifying the active LLM backend."""
    return f"openai / {OPENAI_MODEL}" if os.getenv("OPENAI_API_KEY") else "mock"


def generate_response(prompt: str) -> str:
    """
    Route to OpenAI if OPENAI_API_KEY is set, otherwise use the mock.
    Key is read from the environment at call time so .env reloads are respected.
    """
    key = os.getenv("OPENAI_API_KEY", "")
    if key:
        return _call_openai(prompt, key)
    return _mock_response(prompt)


# ── Backends ──────────────────────────────────────────────────────────────────

def _call_openai(prompt: str, api_key: str) -> str:
    try:
        from openai import OpenAI
        oai = OpenAI(api_key=api_key)
        base = dict(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
        )
        # Newer models (gpt-4o+, o1, gpt-5 family) require max_completion_tokens.
        # Older models (gpt-3.5-turbo, gpt-4) use max_tokens.
        # Try the new parameter first and fall back if the model rejects it.
        try:
            resp = oai.chat.completions.create(**base, max_completion_tokens=512)
        except Exception as inner:
            if "unsupported_parameter" in str(inner):
                resp = oai.chat.completions.create(**base, max_tokens=512)
            else:
                raise
        return resp.choices[0].message.content or ""
    except Exception as exc:
        return f"LLM error: {exc}"


def _mock_response(prompt: str) -> str:
    prompt_lower = prompt.lower()
    for keyword, response in _MOCK_RESPONSES.items():
        if keyword in prompt_lower:
            return response
    return _DEFAULT_RESPONSE
