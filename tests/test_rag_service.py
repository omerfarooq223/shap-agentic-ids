"""Tests for TF-IDF RAG knowledge retrieval."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.services.rag_service import RAGService, _format_alert_document


@pytest.fixture
def kb_dir(tmp_path: Path) -> Path:
    d = tmp_path / "knowledge"
    d.mkdir()
    (d / "mitre.md").write_text(
        "# MITRE\n\n## DDoS\n\nDDoS floods use SYN packets and high packet rates. MITRE T1498.\n\n"
        "## Port scan\n\nPort scanning probes many ports quickly. MITRE T1046.\n",
        encoding="utf-8",
    )
    return d


@pytest.fixture
def rag(kb_dir: Path) -> RAGService:
    return RAGService(knowledge_dir=kb_dir, top_k=3)


class TestRAGService:
    def test_rebuild_indexes_static_files(self, rag: RAGService):
        count = rag.rebuild_index([])
        assert count >= 2

    def test_retrieve_ddos_query(self, rag: RAGService):
        rag.rebuild_index([])
        hits = rag.retrieve("Why was this a DDoS SYN flood?")
        assert hits
        assert any("DDoS" in h.text or "T1498" in h.text for h in hits)
        assert hits[0].score > 0

    def test_retrieve_includes_alerts(self, rag: RAGService):
        alerts = [
            {
                "id": 99,
                "threat_type": "Brute-Force",
                "src_ip": "10.0.0.5",
                "dst_ip": "192.168.1.1",
                "dst_port": 22,
                "timestamp": "12:00 PM",
                "risk_score": 9.1,
                "status": "CRITICAL",
                "mitre": "T1110",
                "ml_confidence": 0.95,
                "recommendation": "Block source IP",
                "shap_explanation": [
                    {"feature": "Destination Port", "value": "22", "contribution": 0.4}
                ],
                "threat_intel": {"abuse_score": 88},
                "agent_reasoning": ["OBSERVE: SSH port"],
            }
        ]
        hits = rag.retrieve("Tell me about brute force on port 22", alerts=alerts)
        assert any(h.source.startswith("alert:") for h in hits)
        assert any("Brute-Force" in h.text or "22" in h.text for h in hits)

    def test_format_context_lists_sources(self, rag: RAGService):
        rag.rebuild_index([])
        hits = rag.retrieve("port scan")
        ctx = rag.format_context(hits)
        assert "RETRIEVED KNOWLEDGE" in ctx
        assert "source=" in ctx

    def test_empty_query_returns_empty(self, rag: RAGService):
        rag.rebuild_index([])
        assert rag.retrieve("   ") == []


class TestAlertFormatting:
    def test_format_alert_document_includes_shap(self):
        doc = _format_alert_document(
            {
                "threat_type": "Port-Scan",
                "src_ip": "1.2.3.4",
                "dst_ip": "10.0.0.1",
                "dst_port": 443,
                "shap_explanation": [
                    {"feature": "Flow Duration", "value": "10", "contribution": 0.2}
                ],
            }
        )
        assert "Port-Scan" in doc
        assert "Flow Duration" in doc
