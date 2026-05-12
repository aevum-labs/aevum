# SPDX-License-Identifier: Apache-2.0
"""Phase 2 — Trifecta enforcement tests."""
import pytest

from aevum.core.cedar_engine import CedarPolicyEngine


class TestTrifectaEnforcement:
    @pytest.fixture
    def engine(self):
        return CedarPolicyEngine.default()

    def _call(self, engine, ctx):
        return engine.is_permitted(
            "AevumAgent", "test-agent", "tool_call",
            "ToolAction", "some-tool", ctx,
        )

    def test_all_three_taint_labels_denied(self, engine):
        permitted = self._call(engine, {
            "taint_reads_untrusted": True,
            "taint_reads_private": True,
            "taint_can_exfiltrate": True,
        })
        assert not permitted

    def test_reads_untrusted_and_exfiltrate_only_permitted(self, engine):
        permitted = self._call(engine, {
            "taint_reads_untrusted": True,
            "taint_reads_private": False,
            "taint_can_exfiltrate": True,
        })
        assert permitted

    def test_reads_untrusted_and_reads_private_only_permitted(self, engine):
        permitted = self._call(engine, {
            "taint_reads_untrusted": True,
            "taint_reads_private": True,
            "taint_can_exfiltrate": False,
        })
        assert permitted

    def test_reads_private_and_exfiltrate_only_permitted(self, engine):
        permitted = self._call(engine, {
            "taint_reads_untrusted": False,
            "taint_reads_private": True,
            "taint_can_exfiltrate": True,
        })
        assert permitted

    def test_only_reads_untrusted_permitted(self, engine):
        permitted = self._call(engine, {
            "taint_reads_untrusted": True,
            "taint_reads_private": False,
            "taint_can_exfiltrate": False,
        })
        assert permitted

    def test_only_reads_private_permitted(self, engine):
        permitted = self._call(engine, {
            "taint_reads_untrusted": False,
            "taint_reads_private": True,
            "taint_can_exfiltrate": False,
        })
        assert permitted

    def test_only_exfiltrate_permitted(self, engine):
        permitted = self._call(engine, {
            "taint_reads_untrusted": False,
            "taint_reads_private": False,
            "taint_can_exfiltrate": True,
        })
        assert permitted

    def test_no_taint_labels_permitted(self, engine):
        permitted = self._call(engine, {
            "taint_reads_untrusted": False,
            "taint_reads_private": False,
            "taint_can_exfiltrate": False,
        })
        assert permitted

    def test_no_taint_context_at_all_permitted(self, engine):
        # Missing taint context → when clause doesn't fire → tool_call permitted
        permitted = self._call(engine, {})
        assert permitted

    def test_trifecta_applies_to_all_tool_names(self, engine):
        for tool_id in ["send-email", "web-search", "file-write", "exfil-tool"]:
            permitted = engine.is_permitted(
                "AevumAgent", "agent", "tool_call",
                "ToolAction", tool_id,
                {
                    "taint_reads_untrusted": True,
                    "taint_reads_private": True,
                    "taint_can_exfiltrate": True,
                },
            )
            assert not permitted, f"Trifecta should block tool {tool_id!r}"

    def test_trifecta_only_applies_to_tool_call_action(self, engine):
        # relate_graph_write is not gated by trifecta
        permitted = engine.is_permitted(
            "AevumAgent", "agent", "relate_graph_write",
            "DataGraph", "knowledge",
            {
                "taint_reads_untrusted": True,
                "taint_reads_private": True,
                "taint_can_exfiltrate": True,
                "has_crisis_content": False,
            },
        )
        assert permitted
