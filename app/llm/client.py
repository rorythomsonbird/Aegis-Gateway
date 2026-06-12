from __future__ import annotations

from app.config import OPENAI_API_KEY, OPENAI_MODEL


# ── Mock responses keyed by topic ─────────────────────────────────────────────
# The mock scans the prompt for keywords and returns the best-matching response.
# Real OpenAI is used instead when OPENAI_API_KEY is set in the environment.

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


def generate_response(prompt: str) -> str:
    """
    Main entrypoint. Uses OpenAI if OPENAI_API_KEY is set, otherwise mock.
    """
    if OPENAI_API_KEY:
        return _call_openai(prompt)
    return _mock_response(prompt)


def _call_openai(prompt: str) -> str:
    try:
        from openai import OpenAI  # optional dependency
        client = OpenAI(api_key=OPENAI_API_KEY)
        resp = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=512,
            temperature=0.3,
        )
        return resp.choices[0].message.content or ""
    except Exception as exc:
        return f"LLM unavailable: {exc}"


def _mock_response(prompt: str) -> str:
    prompt_lower = prompt.lower()
    for keyword, response in _MOCK_RESPONSES.items():
        if keyword in prompt_lower:
            return response
    return _DEFAULT_RESPONSE
