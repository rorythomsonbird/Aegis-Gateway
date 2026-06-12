from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, field_validator

from app.gateway import process_query, logger


# ── Models ────────────────────────────────────────────────────────────────────

class QueryRequest(BaseModel):
    user_id: str
    query: str

    @field_validator("user_id", "query")
    @classmethod
    def must_not_be_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("field must not be blank")
        return v.strip()


class QueryResponse(BaseModel):
    response: Optional[str] = None
    blocked: bool = False
    reason: Optional[str] = None
    injection_score: float = 0.0


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Secure LLM Gateway",
    description=(
        "Production-style middleware API that secures a RAG pipeline against "
        "prompt injection, data exfiltration, and API abuse."
    ),
    version="1.0.0",
)


@app.get("/", tags=["Health"])
def health():
    return {"status": "ok", "service": "Secure LLM Gateway", "version": "1.0.0"}


@app.post("/query", response_model=QueryResponse, tags=["Gateway"])
async def query(request: QueryRequest):
    return await process_query(request)


@app.get("/logs", tags=["Monitoring"])
def get_logs(limit: int = 20):
    """Return the most recent audit log entries."""
    return logger.recent(limit=limit)


@app.get("/logs/summary", tags=["Monitoring"])
def log_summary():
    """High-level attack detection summary."""
    return logger.attack_summary()
