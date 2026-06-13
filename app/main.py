from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, field_validator

from app.gateway import process_query, logger
from app.llm.client import active_backend
from app.config import (
    INJECTION_THRESHOLD, TRUST_THRESHOLD,
    RATE_LIMIT_CAPACITY, RATE_LIMIT_WINDOW,
    FUZZ_THRESHOLD, TOP_K, EMBED_MODEL, OPENAI_MODEL,
)


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


# ── Startup / shutdown ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    backend = active_backend()
    print("\n" + "─" * 50)
    print("  🔐 Secure LLM Gateway")
    print("─" * 50)
    print(f"  LLM backend     : {backend}")
    print(f"  Embed model     : {EMBED_MODEL}")
    print(f"  Inject threshold: {INJECTION_THRESHOLD}")
    print(f"  Trust threshold : {TRUST_THRESHOLD}")
    print(f"  Rate limit      : {RATE_LIMIT_CAPACITY} req / {RATE_LIMIT_WINDOW}s")
    print(f"  Fuzz threshold  : {FUZZ_THRESHOLD}")
    print(f"  Top-K docs      : {TOP_K}")
    print("─" * 50)
    print("  Docs: http://localhost:8000/docs")
    print("─" * 50 + "\n")
    yield


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Secure LLM Gateway",
    description=(
        "Middleware API that secures a RAG pipeline against prompt injection, "
        "data exfiltration, and API abuse."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def health():
    return {"status": "ok", "service": "Secure LLM Gateway", "version": "1.0.0"}


@app.post("/query", response_model=QueryResponse, tags=["Gateway"])
async def query(request: QueryRequest):
    return await process_query(request)


@app.get("/debug", tags=["Monitoring"])
def debug():
    """Active config — confirms which LLM backend is running and current thresholds."""
    return {
        "llm_backend": active_backend(),
        "embed_model": EMBED_MODEL,
        "injection_threshold": INJECTION_THRESHOLD,
        "trust_threshold": TRUST_THRESHOLD,
        "rate_limit": f"{RATE_LIMIT_CAPACITY} req / {RATE_LIMIT_WINDOW}s",
        "fuzz_threshold": FUZZ_THRESHOLD,
        "top_k": TOP_K,
    }


@app.get("/logs", tags=["Monitoring"])
def get_logs(limit: int = 20):
    """Most recent audit log entries."""
    return logger.recent(limit=limit)


@app.get("/logs/summary", tags=["Monitoring"])
def log_summary():
    """High-level attack detection counts."""
    return logger.attack_summary()
