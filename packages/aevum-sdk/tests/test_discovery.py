"""Tests for entry point discovery."""

from __future__ import annotations

from aevum.sdk.discovery import ENTRY_POINT_GROUP, discover_complications


def test_entry_point_group_name() -> None:
    assert ENTRY_POINT_GROUP == "aevum.complications"


def test_discover_returns_list() -> None:
    """discover_complications always returns a list, never raises."""
    result = discover_complications()
    assert isinstance(result, list)
    # In test environment there may be zero complications — that is fine
