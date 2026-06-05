# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
CLI tests — Phase 8. Rule 05: always strip ANSI codes before asserting on text output.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from aevum.cli.app import app


def strip_ansi(text: str) -> str:
    """Rule 05: strip ANSI escape codes before any assertion."""
    return re.sub(r"\x1b\[[0-9;]*[mGKH]", "", text)


runner = CliRunner()


class TestConformCommand:
    def test_conform_exits_0_when_all_pass(self) -> None:
        with patch("aevum.cli.app.ConformanceSuite") as mock_cls:
            mock_suite = MagicMock()
            mock_result = MagicMock()
            mock_result.all_passed = True
            mock_result.render.return_value = "STATUS: PASS (9/9)"
            mock_suite.run_all.return_value = mock_result
            mock_cls.return_value = mock_suite

            result = runner.invoke(app, ["conform"])
        assert result.exit_code == 0
        assert "PASS" in strip_ansi(result.output)

    def test_conform_exits_1_when_any_fail(self) -> None:
        with patch("aevum.cli.app.ConformanceSuite") as mock_cls:
            mock_suite = MagicMock()
            mock_result = MagicMock()
            mock_result.all_passed = False
            mock_result.render.return_value = "STATUS: FAIL (8/9)"
            mock_suite.run_all.return_value = mock_result
            mock_cls.return_value = mock_suite

            result = runner.invoke(app, ["conform"])
        assert result.exit_code == 1

    def test_conform_json_output(self) -> None:
        with patch("aevum.cli.app.ConformanceSuite") as mock_cls:
            mock_suite = MagicMock()
            mock_result = MagicMock()
            mock_result.all_passed = True
            mock_result.to_dict.return_value = {"passed": True, "total_count": 9}
            mock_suite.run_all.return_value = mock_result
            mock_cls.return_value = mock_suite

            result = runner.invoke(app, ["conform", "--output", "json"])
        assert result.exit_code == 0
        parsed = json.loads(strip_ansi(result.output))
        assert parsed["passed"] is True

    def test_conform_output_no_ansi_in_text(self) -> None:
        """ANSI stripping must clean the output (Rule 05)."""
        with patch("aevum.cli.app.ConformanceSuite") as mock_cls:
            mock_suite = MagicMock()
            mock_result = MagicMock()
            mock_result.all_passed = True
            mock_result.render.return_value = "PASS (9/9)"
            mock_suite.run_all.return_value = mock_result
            mock_cls.return_value = mock_suite
            result = runner.invoke(app, ["conform"])
        clean = strip_ansi(result.output)
        assert "\x1b" not in clean

    def test_conform_json_fails_raises_exit_1(self) -> None:
        with patch("aevum.cli.app.ConformanceSuite") as mock_cls:
            mock_suite = MagicMock()
            mock_result = MagicMock()
            mock_result.all_passed = False
            mock_result.to_dict.return_value = {"passed": False, "total_count": 9}
            mock_suite.run_all.return_value = mock_result
            mock_cls.return_value = mock_suite

            result = runner.invoke(app, ["conform", "--output", "json"])
        assert result.exit_code == 1

    def test_conform_default_output_is_text(self) -> None:
        with patch("aevum.cli.app.ConformanceSuite") as mock_cls:
            mock_suite = MagicMock()
            mock_result = MagicMock()
            mock_result.all_passed = True
            mock_result.render.return_value = "PASS (9/9)"
            mock_suite.run_all.return_value = mock_result
            mock_cls.return_value = mock_suite

            runner.invoke(app, ["conform"])
        # text mode calls render(), not to_dict()
        assert mock_result.render.called


class TestVerifyCommand:
    def _make_db(self, tmp_path: Path) -> None:
        """Create a minimal sessions DB for testing."""
        db = tmp_path / "aevum.db"
        conn = sqlite3.connect(str(db))
        conn.executescript("""
            CREATE TABLE sessions (
                session_id TEXT PRIMARY KEY, commit_type TEXT,
                principal TEXT, purpose TEXT, started_at TEXT,
                closed_at TEXT, event_count INTEGER, fact_count INTEGER,
                checkpoint_count INTEGER, merkle_root TEXT,
                ed25519_sig TEXT, mldsa65_sig TEXT, ed25519_pub TEXT,
                mldsa65_pub TEXT, tsa_token TEXT, sigchain_entry_id INTEGER
            );
            CREATE TABLE session_events (
                event_id TEXT PRIMARY KEY, session_id TEXT,
                sequence INTEGER, event_type TEXT, occurred_at TEXT,
                input_hash TEXT, output_hash TEXT, latency_ms INTEGER
            );
        """)
        h = hashlib.sha256(b"").hexdigest()
        now = datetime.now(UTC).isoformat()
        conn.execute(
            "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL)",
            ("sess-abc", "complete", "alice", "test", now, now, 0, 0, 0, h),
        )
        conn.commit()
        conn.close()

    def test_verify_missing_db_exits_1(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["verify", "sess-abc", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 1
        assert "not found" in strip_ansi(result.output).lower()

    def test_verify_valid_session_exits_0(self, tmp_path: Path) -> None:
        self._make_db(tmp_path)
        result = runner.invoke(
            app, ["verify", "sess-abc", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "VERIFIED" in strip_ansi(result.output)

    def test_verify_missing_session_exits_1(self, tmp_path: Path) -> None:
        self._make_db(tmp_path)
        result = runner.invoke(
            app, ["verify", "nonexistent", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 1

    def test_verify_shows_merkle_root(self, tmp_path: Path) -> None:
        self._make_db(tmp_path)
        result = runner.invoke(
            app, ["verify", "sess-abc", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "Merkle root:" in strip_ansi(result.output)

    def test_verify_shows_event_count(self, tmp_path: Path) -> None:
        self._make_db(tmp_path)
        result = runner.invoke(
            app, ["verify", "sess-abc", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "Events: 0" in strip_ansi(result.output)

    def test_verify_help(self) -> None:
        result = runner.invoke(app, ["verify", "--help"])
        assert result.exit_code == 0
        clean = strip_ansi(result.output)
        assert "session" in clean.lower() or "verify" in clean.lower()


class TestReplayCommand:
    def _make_db(self, tmp_path: Path) -> None:
        db = tmp_path / "aevum.db"
        conn = sqlite3.connect(str(db))
        conn.executescript("""
            CREATE TABLE sessions (
                session_id TEXT PRIMARY KEY, commit_type TEXT,
                principal TEXT, purpose TEXT, started_at TEXT,
                closed_at TEXT, event_count INTEGER, fact_count INTEGER,
                checkpoint_count INTEGER, merkle_root TEXT,
                ed25519_sig TEXT, mldsa65_sig TEXT, ed25519_pub TEXT,
                mldsa65_pub TEXT, tsa_token TEXT, sigchain_entry_id INTEGER
            );
            CREATE TABLE session_events (
                event_id TEXT PRIMARY KEY, session_id TEXT,
                sequence INTEGER, event_type TEXT, occurred_at TEXT,
                input_hash TEXT, output_hash TEXT, latency_ms INTEGER
            );
        """)
        h = hashlib.sha256(b"").hexdigest()
        now = datetime.now(UTC).isoformat()
        conn.execute(
            "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL)",
            ("sess-xyz", "complete", "bob", "replay-test", now, now, 0, 0, 0, h),
        )
        conn.commit()
        conn.close()

    def test_replay_help_text_parseable(self) -> None:
        result = runner.invoke(app, ["replay", "--help"])
        assert result.exit_code == 0
        clean = strip_ansi(result.output)
        assert "replay" in clean.lower() or "session" in clean.lower()

    def test_replay_missing_db_exits_1(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["replay", "sess-xyz", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 1
        assert "not found" in strip_ansi(result.output).lower()

    def test_replay_valid_session_exits_0(self, tmp_path: Path) -> None:
        self._make_db(tmp_path)
        result = runner.invoke(
            app, ["replay", "sess-xyz", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        assert "PASS" in strip_ansi(result.output)

    def test_replay_missing_session_exits_1(self, tmp_path: Path) -> None:
        self._make_db(tmp_path)
        result = runner.invoke(
            app, ["replay", "no-such-session", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 1

    def test_replay_verbose_flag_accepted(self, tmp_path: Path) -> None:
        self._make_db(tmp_path)
        result = runner.invoke(
            app, ["replay", "sess-xyz", "--verbose", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 0


class TestAuditPackCommand:
    def _make_db(self, tmp_path: Path, session_id: str = "s1") -> None:
        db = tmp_path / "aevum.db"
        conn = sqlite3.connect(str(db))
        conn.executescript("""
            CREATE TABLE sessions (
                session_id TEXT PRIMARY KEY, commit_type TEXT,
                principal TEXT, purpose TEXT, started_at TEXT,
                closed_at TEXT, event_count INTEGER, fact_count INTEGER,
                checkpoint_count INTEGER, merkle_root TEXT,
                ed25519_sig TEXT, mldsa65_sig TEXT, ed25519_pub TEXT,
                mldsa65_pub TEXT, tsa_token TEXT, sigchain_entry_id INTEGER
            );
            CREATE TABLE session_events (
                event_id TEXT PRIMARY KEY, session_id TEXT,
                sequence INTEGER, event_type TEXT, occurred_at TEXT,
                input_hash TEXT, output_hash TEXT, latency_ms INTEGER
            );
        """)
        h = hashlib.sha256(b"").hexdigest()
        now = datetime.now(UTC).isoformat()
        conn.execute(
            "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL)",
            (session_id, "complete", "alice", "test", now, now, 0, 0, 0, h),
        )
        conn.commit()
        conn.close()

    def test_audit_pack_missing_db_exits_1(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["audit-pack", "sess-1", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 1

    def test_audit_pack_to_stdout(self, tmp_path: Path) -> None:
        self._make_db(tmp_path)
        result = runner.invoke(
            app, ["audit-pack", "s1", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        pack = json.loads(strip_ansi(result.output))
        assert "@context" in pack
        assert "@graph" in pack

    def test_audit_pack_to_file(self, tmp_path: Path) -> None:
        """Audit pack writes JSON-LD to a file."""
        self._make_db(tmp_path)
        out_file = tmp_path / "pack.json"
        result = runner.invoke(app, [
            "audit-pack", "s1",
            "--state-dir", str(tmp_path),
            "--output", str(out_file),
        ])
        assert result.exit_code == 0
        assert out_file.exists()
        pack = json.loads(out_file.read_text())
        assert "@context" in pack
        assert "@graph" in pack

    def test_audit_pack_missing_session_exits_1(self, tmp_path: Path) -> None:
        self._make_db(tmp_path)
        result = runner.invoke(
            app, ["audit-pack", "no-such-session", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 1

    def test_audit_pack_help(self) -> None:
        result = runner.invoke(app, ["audit-pack", "--help"])
        assert result.exit_code == 0
        clean = strip_ansi(result.output)
        assert "session" in clean.lower() or "audit" in clean.lower()


class TestCLIHelp:
    def test_help_shows_all_new_commands(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        clean = strip_ansi(result.output)
        for cmd in ("init", "verify", "receipt", "audit-pack", "conform", "replay"):
            assert cmd in clean

    def test_help_still_shows_existing_commands(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        clean = strip_ansi(result.output)
        for cmd in ("version", "server", "store", "complication", "conformance"):
            assert cmd in clean

    def test_each_new_command_has_help(self) -> None:
        for cmd in ("init", "verify", "receipt", "audit-pack", "conform", "replay"):
            result = runner.invoke(app, [cmd, "--help"])
            assert result.exit_code == 0, f"--help failed for command: {cmd}"

    def test_init_help_mentions_state_dir(self) -> None:
        result = runner.invoke(app, ["init", "--help"])
        assert result.exit_code == 0
        assert "state-dir" in strip_ansi(result.output)

    def test_conform_help_mentions_output(self) -> None:
        result = runner.invoke(app, ["conform", "--help"])
        assert result.exit_code == 0
        assert "output" in strip_ansi(result.output).lower()

    def test_replay_help_mentions_verbose(self) -> None:
        result = runner.invoke(app, ["replay", "--help"])
        assert result.exit_code == 0
        assert "verbose" in strip_ansi(result.output).lower()


_EMPTY_MERKLE = hashlib.sha256(b"").hexdigest()

_DB_SCHEMA = """
    CREATE TABLE sessions (
        session_id TEXT PRIMARY KEY, commit_type TEXT,
        principal TEXT, purpose TEXT, started_at TEXT,
        closed_at TEXT, event_count INTEGER, fact_count INTEGER,
        checkpoint_count INTEGER, merkle_root TEXT,
        ed25519_sig TEXT, mldsa65_sig TEXT, ed25519_pub TEXT,
        mldsa65_pub TEXT, tsa_token TEXT, sigchain_entry_id INTEGER
    );
    CREATE TABLE session_events (
        event_id TEXT PRIMARY KEY, session_id TEXT,
        sequence INTEGER, event_type TEXT, occurred_at TEXT,
        input_hash TEXT, output_hash TEXT, latency_ms INTEGER
    );
"""


def _receipt_merkle_root(entries: list[dict]) -> str:  # type: ignore[type-arg]
    """Compute the same Merkle root as _compute_merkle_from_entries for test fixtures."""
    if not entries:
        return hashlib.sha256(b"").hexdigest()
    sorted_entries = sorted(entries, key=lambda e: e["sequence"])
    leaves = [
        hashlib.sha256((e["input_hash"] + e["output_hash"]).encode("ascii")).hexdigest()
        for e in sorted_entries
    ]
    current = leaves
    while len(current) > 1:
        nxt = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else left
            nxt.append(hashlib.sha256((left + right).encode("ascii")).hexdigest())
        current = nxt
    return current[0]


def _make_receipt_doc(
    session_id: str = "test-session-001",
    n_entries: int = 0,
    tamper_count: bool = False,
    tamper_root: bool = False,
) -> dict:  # type: ignore[type-arg]
    entries = []
    for i in range(n_entries):
        entries.append({
            "sequence": i,
            "event_type": "relate",
            "input_hash": hashlib.sha256(f"in-{i}".encode()).hexdigest(),
            "output_hash": hashlib.sha256(f"out-{i}".encode()).hexdigest(),
            "occurred_at": "2026-01-01T00:00:00+00:00",
            "latency_ms": 5,
        })
    return {
        "session_id": session_id,
        "exported_at": "2026-01-01T01:00:00+00:00",
        "entry_count": len(entries) + (1 if tamper_count else 0),
        "merkle_root": ("a" * 64) if tamper_root else _receipt_merkle_root(entries),
        "entries": entries,
    }


class TestReceiptCommand:
    def _make_db(self, tmp_path: Path, session_id: str = "sess-r01") -> None:
        db = tmp_path / "aevum.db"
        conn = sqlite3.connect(str(db))
        conn.executescript(_DB_SCHEMA)
        now = datetime.now(UTC).isoformat()
        conn.execute(
            "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL)",
            (session_id, "complete", "alice", "test", now, now, 0, 0, 0, _EMPTY_MERKLE),
        )
        conn.commit()
        conn.close()

    def test_receipt_help(self) -> None:
        result = runner.invoke(app, ["receipt", "--help"])
        assert result.exit_code == 0
        assert "receipt" in strip_ansi(result.output).lower()

    def test_receipt_missing_db_exits_1(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["receipt", "sess-r01", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 1
        assert "not found" in strip_ansi(result.output).lower()

    def test_receipt_valid_session_outputs_json(self, tmp_path: Path) -> None:
        self._make_db(tmp_path)
        result = runner.invoke(
            app, ["receipt", "sess-r01", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        doc = json.loads(strip_ansi(result.output))
        assert doc["session_id"] == "sess-r01"

    def test_receipt_output_has_required_fields(self, tmp_path: Path) -> None:
        self._make_db(tmp_path)
        result = runner.invoke(
            app, ["receipt", "sess-r01", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        doc = json.loads(strip_ansi(result.output))
        for field in ("session_id", "entry_count", "entries", "exported_at", "merkle_root"):
            assert field in doc, f"Missing field: {field}"

    def test_receipt_empty_session_has_correct_merkle_root(self, tmp_path: Path) -> None:
        self._make_db(tmp_path)
        result = runner.invoke(
            app, ["receipt", "sess-r01", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 0
        doc = json.loads(strip_ansi(result.output))
        assert doc["entry_count"] == 0
        assert doc["merkle_root"] == _EMPTY_MERKLE

    def test_receipt_missing_session_exits_1(self, tmp_path: Path) -> None:
        self._make_db(tmp_path)
        result = runner.invoke(
            app, ["receipt", "no-such-session", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 1


class TestVerifyReceiptFile:
    def _write_receipt(self, tmp_path: Path, doc: dict) -> Path:  # type: ignore[type-arg]
        f = tmp_path / "receipt.json"
        f.write_text(json.dumps(doc), encoding="utf-8")
        return f

    def test_verify_receipt_file_valid_exits_0(self, tmp_path: Path) -> None:
        f = self._write_receipt(tmp_path, _make_receipt_doc())
        result = runner.invoke(app, ["verify", str(f)])
        assert result.exit_code == 0
        assert "VERIFIED" in strip_ansi(result.output)

    def test_verify_receipt_file_with_entries_exits_0(self, tmp_path: Path) -> None:
        f = self._write_receipt(tmp_path, _make_receipt_doc(n_entries=2))
        result = runner.invoke(app, ["verify", str(f)])
        assert result.exit_code == 0
        assert "VERIFIED" in strip_ansi(result.output)

    def test_verify_receipt_file_shows_merkle_root(self, tmp_path: Path) -> None:
        f = self._write_receipt(tmp_path, _make_receipt_doc(n_entries=2))
        result = runner.invoke(app, ["verify", str(f)])
        assert result.exit_code == 0
        assert "Merkle root:" in strip_ansi(result.output)

    def test_verify_receipt_file_tampered_count_exits_1(self, tmp_path: Path) -> None:
        f = self._write_receipt(tmp_path, _make_receipt_doc(n_entries=2, tamper_count=True))
        result = runner.invoke(app, ["verify", str(f)])
        assert result.exit_code == 1
        assert "TAMPERED" in strip_ansi(result.output)

    def test_verify_receipt_file_tampered_root_exits_1(self, tmp_path: Path) -> None:
        f = self._write_receipt(tmp_path, _make_receipt_doc(n_entries=2, tamper_root=True))
        result = runner.invoke(app, ["verify", str(f)])
        assert result.exit_code == 1
        assert "TAMPERED" in strip_ansi(result.output)

    def test_verify_receipt_file_missing_fields_exits_1(self, tmp_path: Path) -> None:
        f = tmp_path / "partial.json"
        f.write_text('{"session_id": "x", "entries": []}', encoding="utf-8")
        result = runner.invoke(app, ["verify", str(f)])
        assert result.exit_code == 1

    def test_verify_receipt_file_bad_json_exits_1(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.json"
        f.write_bytes(b"not valid json {{{")
        result = runner.invoke(app, ["verify", str(f)])
        assert result.exit_code == 1

    def test_verify_dispatches_to_session_mode_for_nonfile(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["verify", "sess-abc-not-a-file", "--state-dir", str(tmp_path)]
        )
        assert result.exit_code == 1
        assert "not found" in strip_ansi(result.output).lower()

    def test_verify_receipt_roundtrip(self, tmp_path: Path) -> None:
        """Receipt produced by aevum receipt verifies cleanly with aevum verify."""
        db = tmp_path / "aevum.db"
        conn = sqlite3.connect(str(db))
        conn.executescript(_DB_SCHEMA)
        now = datetime.now(UTC).isoformat()
        conn.execute(
            "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL)",
            ("roundtrip-01", "complete", "alice", "test", now, now, 0, 0, 0, _EMPTY_MERKLE),
        )
        conn.commit()
        conn.close()

        export_result = runner.invoke(
            app, ["receipt", "roundtrip-01", "--state-dir", str(tmp_path)]
        )
        assert export_result.exit_code == 0

        receipt_file = tmp_path / "roundtrip.json"
        receipt_file.write_text(export_result.output, encoding="utf-8")

        verify_result = runner.invoke(app, ["verify", str(receipt_file)])
        assert verify_result.exit_code == 0
        assert "VERIFIED" in strip_ansi(verify_result.output)
