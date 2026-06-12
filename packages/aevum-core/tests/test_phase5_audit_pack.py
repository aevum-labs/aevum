# SPDX-License-Identifier: Apache-2.0
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aevum.core.audit.audit_pack import AuditPackError, AuditPackExporter


def _create_test_db(tmp_path: Path) -> Path:
    """Create a minimal test database with a session record."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    conn.executescript("""
        CREATE TABLE sessions (
            session_id TEXT PRIMARY KEY, commit_type TEXT, principal TEXT,
            purpose TEXT, started_at TEXT, closed_at TEXT,
            event_count INTEGER, fact_count INTEGER, checkpoint_count INTEGER,
            merkle_root TEXT, mldsa65_sig TEXT,
            mldsa65_pub TEXT, tsa_token TEXT,
            sigchain_entry_id INTEGER
        );
        CREATE TABLE session_events (
            event_id TEXT PRIMARY KEY, session_id TEXT, sequence INTEGER,
            event_type TEXT, occurred_at TEXT, input_hash TEXT,
            output_hash TEXT, latency_ms INTEGER
        );
    """)
    now = datetime.now(UTC).isoformat()
    h = "a" * 64
    conn.execute(
        "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,1)",
        ("sess-test", "complete", "alice", "support", now, now, 2, 1, 0, h),
    )
    conn.execute(
        "INSERT INTO session_events VALUES (?,?,?,?,?,?,?,?)",
        ("ev-0", "sess-test", 0, "relate", now, h, h, 10),
    )
    conn.execute(
        "INSERT INTO session_events VALUES (?,?,?,?,?,?,?,?)",
        ("ev-1", "sess-test", 1, "navigate", now, h, h, 20),
    )
    conn.commit()
    conn.close()
    return db_path


def _create_empty_session_db(tmp_path: Path) -> Path:
    """Create a database with a session but no events."""
    db_path = tmp_path / "empty.db"
    conn = sqlite3.connect(str(db_path))
    conn.executescript("""
        CREATE TABLE sessions (
            session_id TEXT PRIMARY KEY, commit_type TEXT, principal TEXT,
            purpose TEXT, started_at TEXT, closed_at TEXT,
            event_count INTEGER, fact_count INTEGER, checkpoint_count INTEGER,
            merkle_root TEXT, mldsa65_sig TEXT,
            mldsa65_pub TEXT, tsa_token TEXT,
            sigchain_entry_id INTEGER
        );
        CREATE TABLE session_events (
            event_id TEXT PRIMARY KEY, session_id TEXT, sequence INTEGER,
            event_type TEXT, occurred_at TEXT, input_hash TEXT,
            output_hash TEXT, latency_ms INTEGER
        );
    """)
    now = datetime.now(UTC).isoformat()
    h = "b" * 64
    conn.execute(
        "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL)",
        ("sess-empty", "timeout", "bob", "research", now, now, 0, 0, 0, h),
    )
    conn.commit()
    conn.close()
    return db_path


class TestAuditPackExporter:
    def test_export_returns_dict(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        pack = exporter.export("sess-test")
        assert isinstance(pack, dict)

    def test_export_has_context(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        pack = exporter.export("sess-test")
        assert "@context" in pack

    def test_export_has_graph(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        pack = exporter.export("sess-test")
        assert "@graph" in pack
        assert len(pack["@graph"]) > 0

    def test_export_graph_contains_session_activity(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        pack = exporter.export("sess-test")
        types = [node.get("@type") for node in pack["@graph"]]
        assert "prov:Activity" in types

    def test_export_graph_contains_article12_record(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        pack = exporter.export("sess-test")
        node_types: list[str] = []
        for node in pack["@graph"]:
            t = node.get("@type", "")
            if isinstance(t, list):
                node_types.extend(t)
            else:
                node_types.append(t)
        assert any("Article12" in t for t in node_types)

    def test_export_meta_has_required_fields(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        pack = exporter.export("sess-test")
        meta = pack["_meta"]
        for field in ("export_format", "generated_at", "session_id", "event_count"):
            assert field in meta

    def test_export_meta_event_count_correct(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        pack = exporter.export("sess-test")
        assert pack["_meta"]["event_count"] == 2

    def test_export_json_is_valid_json(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        json_str = exporter.export_json("sess-test")
        parsed = json.loads(json_str)
        assert "@graph" in parsed

    def test_export_unknown_session_raises(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        with pytest.raises(AuditPackError):
            exporter.export("nonexistent-session")

    def test_exporter_missing_db_raises(self, tmp_path: Path) -> None:
        with pytest.raises(AuditPackError):
            AuditPackExporter(tmp_path / "nonexistent.db")

    def test_export_event_nodes_in_graph(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        pack = exporter.export("sess-test")
        entity_nodes = [n for n in pack["@graph"] if n.get("@type") == "prov:Entity"]
        assert len(entity_nodes) == 2

    def test_export_graph_contains_software_agent(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        pack = exporter.export("sess-test")
        node_types: list[str] = []
        for node in pack["@graph"]:
            t = node.get("@type", "")
            if isinstance(t, list):
                node_types.extend(t)
            else:
                node_types.append(t)
        assert "prov:SoftwareAgent" in node_types

    def test_export_graph_contains_person(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        pack = exporter.export("sess-test")
        node_types: list[str] = []
        for node in pack["@graph"]:
            t = node.get("@type", "")
            if isinstance(t, list):
                node_types.extend(t)
            else:
                node_types.append(t)
        assert "prov:Person" in node_types

    def test_export_meta_format_correct(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        pack = exporter.export("sess-test")
        assert pack["_meta"]["export_format"] == "aevum-article12-v2"
        assert pack["_meta"]["eu_ai_act_article"] == "12"

    def test_export_session_id_in_meta(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        pack = exporter.export("sess-test")
        assert pack["_meta"]["session_id"] == "sess-test"

    def test_export_empty_session_has_no_event_entities(self, tmp_path: Path) -> None:
        db = _create_empty_session_db(tmp_path)
        exporter = AuditPackExporter(db)
        pack = exporter.export("sess-empty")
        entity_nodes = [n for n in pack["@graph"] if n.get("@type") == "prov:Entity"]
        assert len(entity_nodes) == 0

    def test_export_empty_session_meta_event_count_zero(self, tmp_path: Path) -> None:
        db = _create_empty_session_db(tmp_path)
        exporter = AuditPackExporter(db)
        pack = exporter.export("sess-empty")
        assert pack["_meta"]["event_count"] == 0

    def test_export_json_indent_default(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        json_str = exporter.export_json("sess-test")
        assert "\n" in json_str  # indented output has newlines

    def test_export_error_message_contains_session_id(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        with pytest.raises(AuditPackError, match="nonexistent"):
            exporter.export("nonexistent")

    def test_close_does_not_raise(self, tmp_path: Path) -> None:
        db = _create_test_db(tmp_path)
        exporter = AuditPackExporter(db)
        exporter.close()  # must not raise
