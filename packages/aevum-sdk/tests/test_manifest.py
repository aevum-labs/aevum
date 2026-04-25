"""Tests for manifest generation."""

from __future__ import annotations

from hello_complication import HelloComplication


def test_manifest_has_required_fields() -> None:
    m = HelloComplication().manifest()
    for field in ["name", "version", "capabilities", "schema_version"]:
        assert field in m, f"Missing field: {field}"


def test_manifest_name_matches_class() -> None:
    m = HelloComplication().manifest()
    assert m["name"] == "hello"


def test_manifest_version_matches_class() -> None:
    m = HelloComplication().manifest()
    assert m["version"] == "0.1.0"


def test_manifest_capabilities_is_list() -> None:
    m = HelloComplication().manifest()
    assert isinstance(m["capabilities"], list)
    assert "echo" in m["capabilities"]


def test_manifest_schema_version() -> None:
    m = HelloComplication().manifest()
    assert m["schema_version"] == "1.0"


def test_manifest_capabilities_is_copy() -> None:
    """Modifying returned manifest must not affect class attribute."""
    m = HelloComplication().manifest()
    m["capabilities"].append("injected")
    assert "injected" not in HelloComplication.capabilities
