from __future__ import annotations

import ast
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
QML = PROJECT_ROOT / "qml_preview"
sys.path[:0] = [str(SRC), str(QML)]

import database
from scripts.build_release import build_release
from card_analyzer import AnalysisCancelled, _extract_json_object, analyze_with_card_prompts
from card_validation import validate_card_payloads
from conversation_service import create_conversation, get_messages, list_conversations


class FakeEngine:
    def __init__(self, *, fail_at: int | None = None, malformed_at: int | None = None):
        self.calls = 0
        self.fail_at = fail_at
        self.malformed_at = malformed_at

    def retrieve_chunks(self, query, **kwargs):
        return []

    def complete_chat_messages(self, messages):
        self.calls += 1
        if self.calls == self.fail_at:
            raise RuntimeError("synthetic card failure")
        if self.calls == self.malformed_at:
            return "not json"
        payloads = [
            {"activeTitle": "TEST", "activeRisk": "HIGH", "evidenceRows": [{"kind": "IP", "indicator": "192.0.2.1", "detail": "synthetic", "severity": "HIGH"}]},
            {"techniqueRows": [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution", "risk": "HIGH"}]},
            {"actionRows": [{"p": "P2", "title": "Review", "detail": "Collect evidence"}]},
            {"incidentSummary": "Synthetic test", "incidentAssessment": "Review", "likelyAttackPath": "Unknown", "missingInformation": "Logs", "activeRisk": "HIGH", "activeScore": 75},
            {"sourceRows": [{"name": "Synthetic", "meta": "Fixture", "relevance": 0.8}]},
            {"timelineRows": [{"time": "T0", "title": "Alert", "detail": "Received"}]},
        ]
        return json.dumps(payloads[self.calls - 1])


class ModelFreeTests(unittest.TestCase):
    def test_clean_history_db_first_run_and_existing_data_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            history = root / "history.db"
            with patch.object(database, "HISTORY_DATABASE_PATH", history), patch.object(database, "LEGACY_DATABASE_PATH", root / "absent.db"):
                conversation_id = create_conversation("Synthetic")
                self.assertTrue(history.exists())
                self.assertEqual(get_messages(conversation_id), [])
                connection = sqlite3.connect(history)
                try:
                    before = connection.execute("SELECT COUNT(*) FROM conversations").fetchone()[0]
                    database.initialize_history_database(connection)
                    after = connection.execute("SELECT COUNT(*) FROM conversations").fetchone()[0]
                finally:
                    connection.close()
                self.assertEqual((before, after), (1, 1))

    def test_no_fabricated_mitre_and_malformed_json_fallback(self):
        self.assertEqual(_extract_json_object("broken"), {})
        result = analyze_with_card_prompts(FakeEngine(malformed_at=2), "Synthetic alert")
        serialized = json.dumps(result)
        self.assertNotIn("T0000", serialized)
        self.assertNotIn("T9999", serialized)
        self.assertEqual(result["techniqueRows"][0]["id"], "")

    def test_legacy_history_is_copied_without_modifying_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / "legacy.db"
            destination = root / "history.db"
            connection = sqlite3.connect(legacy)
            database.initialize_history_database(connection)
            connection.execute("INSERT INTO conversations (id, title) VALUES ('synthetic-id', 'Synthetic')")
            connection.commit()
            connection.close()
            before = legacy.read_bytes()
            with patch.object(database, "HISTORY_DATABASE_PATH", destination), patch.object(database, "LEGACY_DATABASE_PATH", legacy):
                rows = list_conversations()
                rows_again = list_conversations()
            self.assertEqual(rows[0]["id"], "synthetic-id")
            self.assertEqual(rows_again, rows)
            self.assertEqual(legacy.read_bytes(), before)
            migrated = sqlite3.connect(destination)
            try:
                self.assertEqual(migrated.execute("SELECT COUNT(*) FROM conversations").fetchone()[0], 1)
                self.assertEqual(migrated.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 0)
            finally:
                migrated.close()

    def test_six_card_partial_failure_keeps_other_cards(self):
        engine = FakeEngine(fail_at=3)
        result = analyze_with_card_prompts(engine, "Synthetic alert")
        self.assertEqual(engine.calls, 6)
        self.assertEqual(len(result["degradedCards"]), 1)
        self.assertTrue(result["evidenceRows"] and result["timelineRows"])

    def test_cancellation_at_card_boundary(self):
        engine = FakeEngine()
        checks = 0
        def cancel():
            nonlocal checks
            checks += 1
            return checks >= 3
        with self.assertRaises(AnalysisCancelled):
            analyze_with_card_prompts(engine, "Synthetic alert", should_cancel=cancel)
        self.assertEqual(engine.calls, 1)

    def test_validator_reports_risk_conflict_and_removes_invalid_mitre(self):
        payloads = {
            "evidence": {"activeRisk": "LOW", "evidenceRows": [{"kind": "IP"}]},
            "mitre": {"techniqueRows": [{"id": "T0000", "name": "Fake"}]},
            "actions": {"actionRows": [{}]},
            "analysis": {"activeRisk": "CRITICAL", "incidentSummary": "x"},
            "sources": {"sourceRows": [{}]},
            "timeline": {"timelineRows": [{}]},
        }
        normalized, warnings, missing = validate_card_payloads(payloads)
        self.assertEqual(normalized["mitre"]["techniqueRows"][0]["id"], "")
        self.assertTrue(any("Risk" in warning for warning in warnings))
        self.assertFalse(missing)

    def test_qml_backend_public_contract_without_window(self):
        source = (QML / "backend_bridge.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        methods = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
        self.assertTrue({"analyze", "regenerate", "cancelAnalysis", "newInvestigation", "selectConversation", "renameActive", "deleteActive"} <= methods)
        self.assertTrue(all(name in source for name in ("resultJson", "historyJson", "analysisRunning", "kbChunks")))

    def test_core_modules_import_without_foundry_sdk(self):
        self.assertNotIn("foundry_local_sdk", sys.modules)
        __import__("vector_retriever")

    def test_clean_release_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = build_release(Path(directory) / "release.zip")
            import zipfile
            with zipfile.ZipFile(archive_path) as archive:
                names = archive.namelist()
            self.assertTrue(any(name.endswith("data/knowledge_index.db") for name in names))
            forbidden = ("/.venv", "/__pycache__", ".pyc", ".log", "cybersoc.db")
            self.assertFalse(any(any(token in name for token in forbidden) for name in names))


if __name__ == "__main__":
    unittest.main()
