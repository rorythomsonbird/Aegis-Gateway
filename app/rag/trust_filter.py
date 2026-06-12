from __future__ import annotations

from app.config import TRUST_THRESHOLD


class TrustFilter:
    """
    Filters retrieved documents by their trust_score before they are
    included in the LLM prompt. Documents below the threshold are dropped.

    trust_score is assigned per-document in documents.json:
      0.9–1.0  Authoritative sources (HR, Legal, IT official docs)
      0.6–0.89 Internal docs with reasonable provenance
      0.0–0.59 Unverified / unknown origin — dropped by default
    """

    def __init__(self, threshold: float = TRUST_THRESHOLD):
        self.threshold = threshold

    def filter(self, documents: list[dict]) -> list[dict]:
        trusted = [doc for doc in documents if doc.get("trust_score", 0) >= self.threshold]

        dropped = len(documents) - len(trusted)
        if dropped:
            print(f"TrustFilter: dropped {dropped} low-trust document(s) (threshold={self.threshold})")

        return trusted
