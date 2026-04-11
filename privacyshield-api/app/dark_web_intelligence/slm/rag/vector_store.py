"""
vector_store.py — Qdrant vector database client for Aletheos Dark Web Intelligence.

Manages three collections:
  - aletheos_gdpr  : GDPR full statute + recitals (EUR-Lex)
  - aletheos_nist  : NIST Cybersecurity Framework + SP 800-series
  - aletheos_nvd   : NVD CVE feed (refreshed every 24h)

Usage:
    from app.dark_web_intelligence.slm.rag.vector_store import vector_store
    vector_store.search("credential stuffing", collection="aletheos_nvd", top_k=5)
"""

from __future__ import annotations

import os
import uuid
from typing import List, Dict, Optional, Literal

from qdrant_client import QdrantClient
from qdrant_client.http.models import (
    Distance,
    VectorParams,
    PointStruct,
    Filter,
    FieldCondition,
    MatchValue,
)

from app.dark_web_intelligence.slm.config import intel_config

cfg = intel_config.rag

CollectionName = Literal["aletheos_gdpr", "aletheos_nist", "aletheos_nvd"]

COLLECTIONS: List[CollectionName] = [
    cfg.gdpr_collection,
    cfg.nist_collection,
    cfg.nvd_collection,
]


class AletheosVectorStore:
    """
    Thin wrapper around Qdrant that handles collection lifecycle,
    embedding, upsert, and semantic search.
    """

    def __init__(self):
        self._client: Optional[QdrantClient] = None
        self._embedder: Optional[SentenceTransformer] = None

    # ── Lazy initialisation ──────────────────────────────────────────────────

    @property
    def client(self) -> QdrantClient:
        if self._client is None:
            api_key = cfg.qdrant_api_key or os.environ.get("QDRANT_API_KEY")
            if api_key:
                # Qdrant Cloud
                self._client = QdrantClient(
                    url=f"https://{cfg.qdrant_host}",
                    api_key=api_key,
                )
            else:
                # Local instance
                self._client = QdrantClient(
                    host=cfg.qdrant_host,
                    port=cfg.qdrant_port,
                )
            print(f"[vector_store] Connected to Qdrant at {cfg.qdrant_host}:{cfg.qdrant_port}")
        return self._client

    @property
    def embedder(self):
        if self._embedder is None:
            from fastembed import TextEmbedding
            print(f"[vector_store] Loading fastembed model: {cfg.embedding_model_id}")
            self._embedder = TextEmbedding(model_name=cfg.embedding_model_id)
        return self._embedder

    # ── Collection management ────────────────────────────────────────────────

    def ensure_collections(self) -> None:
        """Creates all three collections if they don't already exist."""
        existing = {c.name for c in self.client.get_collections().collections}
        for name in COLLECTIONS:
            if name not in existing:
                self.client.create_collection(
                    collection_name=name,
                    vectors_config=VectorParams(
                        size=cfg.embedding_dim,
                        distance=Distance.COSINE,
                    ),
                )
                print(f"[vector_store] Created collection: {name}")
            else:
                print(f"[vector_store] Collection exists: {name}")

    def collection_count(self, collection: CollectionName) -> int:
        info = self.client.get_collection(collection)
        return info.points_count

    def delete_collection(self, collection: CollectionName) -> None:
        self.client.delete_collection(collection)
        print(f"[vector_store] Deleted collection: {collection}")

    # ── Embedding ────────────────────────────────────────────────────────────

    def embed(self, texts: List[str]) -> List[List[float]]:
        """Batch embed a list of text strings. Returns list of float vectors."""
        # fastembed returns a generator of numpy arrays
        vectors = list(self.embedder.embed(texts))
        return [v.tolist() for v in vectors]

    # ── Upsert ───────────────────────────────────────────────────────────────

    def upsert(
        self,
        collection: CollectionName,
        chunks: List[str],
        payloads: List[Dict],
        batch_size: int = 256,
    ) -> int:
        """
        Embeds and upserts text chunks into the given collection.

        Args:
            collection : one of the three collection names
            chunks     : list of text strings to embed
            payloads   : list of dicts (metadata — source, article, date, etc.)
            batch_size : upsert in batches to avoid request size limits

        Returns:
            total number of points upserted
        """
        assert len(chunks) == len(payloads), "chunks and payloads must have equal length"

        total = 0
        for i in range(0, len(chunks), batch_size):
            batch_chunks   = chunks[i : i + batch_size]
            batch_payloads = payloads[i : i + batch_size]
            batch_vectors  = self.embed(batch_chunks)

            points = [
                PointStruct(
                    id=str(uuid.uuid4()),
                    vector=vec,
                    payload={**meta, "text": chunk},
                )
                for vec, chunk, meta in zip(batch_vectors, batch_chunks, batch_payloads)
            ]

            self.client.upsert(collection_name=collection, points=points)
            total += len(points)
            print(f"[vector_store] Upserted batch {i // batch_size + 1} → {collection} ({total} total)")

        return total

    # ── Search ───────────────────────────────────────────────────────────────

    def search(
        self,
        query: str,
        collection: CollectionName,
        top_k: int = None,
        filter_key: Optional[str] = None,
        filter_value: Optional[str] = None,
    ) -> List[Dict]:
        """
        Semantic search over a collection.

        Args:
            query        : natural language query string
            collection   : collection to search
            top_k        : number of results (defaults to cfg.top_k)
            filter_key   : optional payload key to filter on (e.g. "source")
            filter_value : value to match for the filter

        Returns:
            list of dicts: { "text": str, "score": float, **metadata }
        """
        if top_k is None:
            top_k = cfg.top_k

        query_vector = self.embed([query])[0]

        search_filter = None
        if filter_key and filter_value:
            search_filter = Filter(
                must=[FieldCondition(key=filter_key, match=MatchValue(value=filter_value))]
            )

        hits = self.client.search(
            collection_name=collection,
            query_vector=query_vector,
            limit=top_k,
            query_filter=search_filter,
            with_payload=True,
        )

        return [
            {
                "text":  hit.payload.get("text", ""),
                "score": hit.score,
                **{k: v for k, v in hit.payload.items() if k != "text"},
            }
            for hit in hits
        ]

    def search_all(self, query: str, top_k: int = None) -> Dict[str, List[Dict]]:
        """
        Search all three collections and return results grouped by source.
        Useful for the RAG retriever when we want context from all sources.
        """
        if top_k is None:
            top_k = cfg.top_k

        return {
            "gdpr": self.search(query, cfg.gdpr_collection, top_k=top_k),
            "nist": self.search(query, cfg.nist_collection, top_k=top_k),
            "nvd":  self.search(query, cfg.nvd_collection,  top_k=top_k),
        }


# Singleton — import this everywhere
vector_store = AletheosVectorStore()
