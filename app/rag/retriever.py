from __future__ import annotations

import json
import numpy as np
from sentence_transformers import SentenceTransformer

from app.config import DOCS_PATH, EMBED_MODEL, TOP_K


class Retriever:
    """
    Loads documents from a JSON file, embeds them with a sentence transformer,
    and exposes a cosine similarity search. No external vector DB needed.
    """

    def __init__(self, docs_path: str = DOCS_PATH, model_name: str = EMBED_MODEL):
        print(f"Loading embedding model '{model_name}'... (downloads ~90MB on first run)")
        self.model = SentenceTransformer(model_name, device="cpu")
        self.documents: list[dict] = []
        self.embeddings: np.ndarray | None = None
        self._load(docs_path)
        print(f"Retriever ready — {len(self.documents)} documents indexed.")

    def _load(self, docs_path: str) -> None:
        with open(docs_path, encoding="utf-8") as f:
            self.documents = json.load(f)

        texts = [doc["content"] for doc in self.documents]
        raw = self.model.encode(texts, show_progress_bar=False, convert_to_numpy=True)
        self.embeddings = self._normalize(raw)

    @staticmethod
    def _normalize(vecs: np.ndarray) -> np.ndarray:
        norms = np.linalg.norm(vecs, axis=1, keepdims=True)
        return vecs / np.maximum(norms, 1e-10)

    def search(self, query: str, k: int = TOP_K) -> list[dict]:
        query_emb = self.model.encode([query], show_progress_bar=False, convert_to_numpy=True)
        query_norm = self._normalize(query_emb)

        # Cosine similarity via dot product on normalised vectors
        scores = (self.embeddings @ query_norm.T).squeeze()

        # Handle single-document edge case
        if scores.ndim == 0:
            scores = np.array([float(scores)])

        top_indices = np.argsort(scores)[-k:][::-1]

        results = []
        for idx in top_indices:
            doc = dict(self.documents[int(idx)])
            doc["similarity"] = float(scores[int(idx)])
            results.append(doc)

        return results
