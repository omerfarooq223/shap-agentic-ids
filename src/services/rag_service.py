"""
src/services/rag_service.py

Lightweight retrieval-augmented generation (RAG) for the forensic chat endpoint.

Uses TF-IDF + cosine similarity (scikit-learn) over:
  1. Static markdown knowledge under data/knowledge/
  2. Dynamic alert records from AlertRepository

No vector database or embedding API required — suitable for small corpora (<500 chunks).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from src import config
from src.config import logger

_CHUNK_CHARS = 700
_ALERT_SOURCE_PREFIX = "alert:"


@dataclass(frozen=True)
class RAGChunk:
    """A retrievable passage with provenance."""
    text: str
    source: str
    score: float = 0.0


class RAGService:
    """TF-IDF retrieval over static KB files and live alerts."""

    def __init__(
        self,
        knowledge_dir: Path | None = None,
        top_k: int | None = None,
    ) -> None:
        self._knowledge_dir = knowledge_dir or config.KNOWLEDGE_DIR
        self._top_k = top_k if top_k is not None else config.RAG_TOP_K
        self._vectorizer = TfidfVectorizer(
            stop_words="english",
            max_features=8000,
            ngram_range=(1, 2),
        )
        self._chunks: list[RAGChunk] = []
        self._matrix = None

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    def rebuild_index(self, alerts: list[dict[str, Any]] | None = None) -> int:
        """Rebuild corpus from KB files and optional alert list. Returns chunk count."""
        self._chunks = []
        self._chunks.extend(self._load_static_knowledge())
        if alerts:
            self._chunks.extend(self._alerts_to_chunks(alerts))
        self._matrix = None

        if not self._chunks:
            logger.warning("RAG index empty — no knowledge files or alerts found")
            return 0

        texts = [c.text for c in self._chunks]
        self._matrix = self._vectorizer.fit_transform(texts)
        logger.info(
            f"RAG index built: {len(self._chunks)} chunks "
            f"({len(list(self._knowledge_dir.glob('*.md')))} KB files)"
        )
        return len(self._chunks)

    def _load_static_knowledge(self) -> list[RAGChunk]:
        chunks: list[RAGChunk] = []
        if not self._knowledge_dir.exists():
            return chunks

        for path in sorted(self._knowledge_dir.glob("*.md")):
            try:
                raw = path.read_text(encoding="utf-8")
            except OSError as exc:
                logger.warning(f"Could not read knowledge file {path}: {exc}")
                continue
            for piece in _split_markdown(raw):
                chunks.append(RAGChunk(text=piece, source=path.name))
        return chunks

    def _alerts_to_chunks(self, alerts: list[dict[str, Any]]) -> list[RAGChunk]:
        chunks: list[RAGChunk] = []
        for alert in alerts:
            text = _format_alert_document(alert)
            if not text.strip():
                continue
            alert_id = alert.get("id", alert.get("timestamp", "unknown"))
            chunks.append(
                RAGChunk(text=text, source=f"{_ALERT_SOURCE_PREFIX}{alert_id}")
            )
        return chunks

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def retrieve(self, query: str, alerts: list[dict[str, Any]] | None = None) -> list[RAGChunk]:
        """
        Retrieve top-k chunks for a user query.
        Rebuilds index when alerts are supplied so live detections stay searchable.
        """
        if alerts is not None:
            self.rebuild_index(alerts)
        elif self._matrix is None:
            self.rebuild_index([])

        if not self._chunks or self._matrix is None:
            return []

        query = (query or "").strip()
        if not query:
            return []

        q_vec = self._vectorizer.transform([query])
        scores = cosine_similarity(q_vec, self._matrix).flatten()

        ranked = sorted(
            range(len(self._chunks)),
            key=lambda i: scores[i],
            reverse=True,
        )

        results: list[RAGChunk] = []
        for idx in ranked[: self._top_k]:
            if scores[idx] <= 0:
                continue
            base = self._chunks[idx]
            results.append(
                RAGChunk(text=base.text, source=base.source, score=round(float(scores[idx]), 4))
            )
        return results

    def format_context(self, chunks: list[RAGChunk]) -> str:
        """Format retrieved chunks for LLM system prompt injection."""
        if not chunks:
            return "No relevant passages retrieved from the threat knowledge base."

        lines = ["RETRIEVED KNOWLEDGE (TF-IDF RAG — cite when relevant):"]
        for i, chunk in enumerate(chunks, 1):
            lines.append(
                f"\n[{i}] source={chunk.source} | relevance={chunk.score}\n{chunk.text}"
            )
        return "\n".join(lines)

    @property
    def chunk_count(self) -> int:
        return len(self._chunks)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _split_markdown(text: str) -> list[str]:
    """Split markdown into section-sized chunks on headings and paragraphs."""
    sections = re.split(r"\n(?=#{1,3}\s)", text.strip())
    pieces: list[str] = []
    for section in sections:
        section = section.strip()
        if not section:
            continue
        if len(section) <= _CHUNK_CHARS:
            pieces.append(section)
            continue
        paragraphs = [p.strip() for p in section.split("\n\n") if p.strip()]
        buf = ""
        for para in paragraphs:
            if len(buf) + len(para) + 2 <= _CHUNK_CHARS:
                buf = f"{buf}\n\n{para}".strip() if buf else para
            else:
                if buf:
                    pieces.append(buf)
                buf = para
        if buf:
            pieces.append(buf)
    return pieces


def _format_alert_document(alert: dict[str, Any]) -> str:
    shap_bits = []
    for item in (alert.get("shap_explanation") or [])[:5]:
        if isinstance(item, dict):
            shap_bits.append(
                f"{item.get('feature', '?')}={item.get('value', '?')} "
                f"(impact {item.get('contribution', 0):+.4f})"
            )

    reasoning = alert.get("agent_reasoning") or alert.get("llm_reasoning") or ""
    if isinstance(reasoning, list):
        reasoning = " | ".join(str(r) for r in reasoning[:4])

    intel = alert.get("threat_intel") or {}
    return (
        f"Detected alert: {alert.get('threat_type', 'Unknown')} "
        f"from {alert.get('src_ip', '?')} to {alert.get('dst_ip', '?')}:"
        f"{alert.get('dst_port', '?')} at {alert.get('timestamp', '?')}. "
        f"Risk score {alert.get('risk_score', '?')}/10, status {alert.get('status', '?')}, "
        f"MITRE {alert.get('mitre', '?')}. "
        f"ML confidence {alert.get('ml_confidence', '?')}. "
        f"AbuseIPDB score {intel.get('abuse_score', 'n/a')}. "
        f"Recommendation: {alert.get('recommendation', 'N/A')}. "
        f"SHAP evidence: {'; '.join(shap_bits) or 'none'}. "
        f"Agent reasoning: {reasoning}"
    ).strip()


rag_service = RAGService()
