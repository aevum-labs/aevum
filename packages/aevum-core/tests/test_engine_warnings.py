# SPDX-License-Identifier: Apache-2.0
"""Tests for Engine in-memory storage warning (Change 4)."""
from __future__ import annotations

import logging

from aevum.core.engine import Engine


def test_in_memory_warning_fires(caplog):
    with caplog.at_level(logging.WARNING, logger="aevum.core.engine"):
        Engine()
    assert any("in-memory" in r.message.lower() for r in caplog.records)


def test_persistent_store_no_warning(caplog, tmp_path):
    from aevum.store.oxigraph import OxigraphStore

    store = OxigraphStore(path=str(tmp_path / "test.db"))
    with caplog.at_level(logging.WARNING, logger="aevum.core.engine"):
        Engine(graph_store=store)
    assert not any("in-memory" in r.message.lower() for r in caplog.records)
