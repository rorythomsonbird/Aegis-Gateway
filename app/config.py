from pathlib import Path
import os

ROOT = Path(__file__).parent.parent

# Paths
DOCS_PATH = str(ROOT / "data" / "documents.json")
DB_PATH = os.getenv("DB_PATH", str(ROOT / "logs" / "requests.db"))

# Security thresholds
INJECTION_THRESHOLD = float(os.getenv("INJECTION_THRESHOLD", "0.5"))
TRUST_THRESHOLD = float(os.getenv("TRUST_THRESHOLD", "0.5"))

# Rate limiting
RATE_LIMIT_CAPACITY = int(os.getenv("RATE_LIMIT_CAPACITY", "10"))   # max requests
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))        # per N seconds
RATE_LIMIT_REFILL = RATE_LIMIT_CAPACITY / float(RATE_LIMIT_WINDOW)   # tokens/second

# Fuzzing detection
FUZZ_THRESHOLD = float(os.getenv("FUZZ_THRESHOLD", "0.85"))          # similarity ratio

# RAG
TOP_K = int(os.getenv("TOP_K", "3"))                                  # docs to retrieve
EMBED_MODEL = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")

# LLM
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
