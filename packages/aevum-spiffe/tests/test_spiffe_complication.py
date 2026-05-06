"""
Tests for SpiffeComplication.
Uses mocked SPIFFE WorkloadApiClient — no real SPIRE deployment required.
"""
from __future__ import annotations

import datetime
import sys
import unittest.mock

import pytest


def _make_mock_svid(spiffe_id_str: str = "spiffe://example.org/billing") -> unittest.mock.MagicMock:
    """Build a minimal mock JWT-SVID."""
    mock_svid = unittest.mock.MagicMock()
    mock_spiffe_id = unittest.mock.MagicMock()
    mock_spiffe_id.__str__ = lambda self: spiffe_id_str
    mock_trust_domain = unittest.mock.MagicMock()
    mock_trust_domain.name = "example.org"
    mock_spiffe_id.trust_domain = mock_trust_domain
    mock_svid.spiffe_id = mock_spiffe_id
    mock_svid.expiry = datetime.datetime(
        2026, 5, 6, 14, 0, 0, tzinfo=datetime.timezone.utc
    ).timestamp()
    return mock_svid


def _make_mock_client(svid: unittest.mock.MagicMock) -> unittest.mock.MagicMock:
    """Build a mock WorkloadApiClient context manager."""
    client = unittest.mock.MagicMock()
    client.__enter__ = unittest.mock.MagicMock(return_value=client)
    client.__exit__ = unittest.mock.MagicMock(return_value=False)
    client.fetch_jwt_svid = unittest.mock.MagicMock(return_value=svid)
    return client


def _make_mock_engine() -> unittest.mock.MagicMock:
    """Minimal engine mock with a ledger."""
    engine = unittest.mock.MagicMock()
    engine._ledger.append = unittest.mock.MagicMock(return_value=None)
    return engine


class TestSpiffeComplicationWithMockSPIRE:

    def test_on_approved_emits_spiffe_attested(self) -> None:
        """Successful attestation must emit a spiffe.attested event."""
        from aevum.spiffe import SpiffeComplication

        mock_svid = _make_mock_svid()
        mock_client = _make_mock_client(mock_svid)
        mock_engine = _make_mock_engine()

        comp = SpiffeComplication(socket_path="unix:///fake/socket")

        with unittest.mock.patch(
            "aevum.spiffe.complication.WorkloadApiClient",
            return_value=mock_client,
        ):
            comp.on_approved(mock_engine)

        assert comp.is_attested is True
        assert comp.get_actor_spiffe_id() == "spiffe://example.org/billing"

        mock_engine._ledger.append.assert_called_once()
        call_kwargs = mock_engine._ledger.append.call_args.kwargs
        assert call_kwargs["event_type"] == "spiffe.attested"
        assert call_kwargs["payload"]["spiffe_id"] == "spiffe://example.org/billing"
        assert call_kwargs["payload"]["trust_domain"] == "example.org"
        assert call_kwargs["actor"] == "aevum-spiffe"

    def test_missing_spiffe_library_degrades_gracefully(self) -> None:
        """Missing py-spiffe must warn and not raise."""
        from aevum.spiffe import SpiffeComplication

        mock_engine = _make_mock_engine()
        comp = SpiffeComplication()

        with unittest.mock.patch.dict(sys.modules, {"spiffe": None}):
            comp.on_approved(mock_engine)

        assert comp.is_attested is False
        assert comp.get_actor_spiffe_id() is None
        mock_engine._ledger.append.assert_not_called()

    def test_socket_unavailable_degrades_gracefully(self) -> None:
        """Unreachable SPIFFE socket must warn and not raise."""
        from aevum.spiffe import SpiffeComplication

        mock_engine = _make_mock_engine()
        comp = SpiffeComplication(socket_path="unix:///nonexistent/socket")

        bad_client = unittest.mock.MagicMock()
        bad_client.__enter__ = unittest.mock.MagicMock(
            side_effect=Exception("Connection refused")
        )
        bad_client.__exit__ = unittest.mock.MagicMock(return_value=False)

        with unittest.mock.patch(
            "aevum.spiffe.complication.WorkloadApiClient",
            return_value=bad_client,
        ):
            comp.on_approved(mock_engine)

        assert comp.is_attested is False
        mock_engine._ledger.append.assert_not_called()

    def test_get_actor_spiffe_id_before_attestation(self) -> None:
        """get_actor_spiffe_id() returns None before attestation."""
        from aevum.spiffe import SpiffeComplication

        comp = SpiffeComplication()
        assert comp.get_actor_spiffe_id() is None

    def test_spiffe_id_format_preserved(self) -> None:
        """SPIFFE ID must be stored verbatim as returned by the SVID."""
        from aevum.spiffe import SpiffeComplication

        spiffe_id = "spiffe://production.example.com/service/billing-agent-v2"
        mock_svid = _make_mock_svid(spiffe_id)
        mock_client = _make_mock_client(mock_svid)
        mock_engine = _make_mock_engine()

        comp = SpiffeComplication()

        with unittest.mock.patch(
            "aevum.spiffe.complication.WorkloadApiClient",
            return_value=mock_client,
        ):
            comp.on_approved(mock_engine)

        assert comp.get_actor_spiffe_id() == spiffe_id

        call_kwargs = mock_engine._ledger.append.call_args.kwargs
        assert call_kwargs["payload"]["spiffe_id"] == spiffe_id
        assert call_kwargs["payload"]["trust_domain"] == "example.org"

    def test_audience_passed_to_workload_api(self) -> None:
        """Custom audience must be forwarded to fetch_jwt_svid."""
        from aevum.spiffe import SpiffeComplication

        mock_svid = _make_mock_svid()
        mock_client = _make_mock_client(mock_svid)
        mock_engine = _make_mock_engine()

        comp = SpiffeComplication(audience=["billing-service", "audit"])

        with unittest.mock.patch(
            "aevum.spiffe.complication.WorkloadApiClient",
            return_value=mock_client,
        ):
            comp.on_approved(mock_engine)

        mock_client.fetch_jwt_svid.assert_called_once_with(
            audiences=["billing-service", "audit"]
        )

    def test_svid_jwt_not_stored(self) -> None:
        """The JWT token itself must NOT appear in the spiffe.attested payload."""
        from aevum.spiffe import SpiffeComplication

        mock_svid = _make_mock_svid()
        mock_svid.token = "eyJhbGciOiJFZERTQSJ9.SENSITIVE.CONTENT"
        mock_client = _make_mock_client(mock_svid)
        mock_engine = _make_mock_engine()

        comp = SpiffeComplication()

        with unittest.mock.patch(
            "aevum.spiffe.complication.WorkloadApiClient",
            return_value=mock_client,
        ):
            comp.on_approved(mock_engine)

        call_kwargs = mock_engine._ledger.append.call_args.kwargs
        payload_str = str(call_kwargs["payload"])
        assert "eyJ" not in payload_str, "JWT token must not appear in payload"
        assert "SENSITIVE" not in payload_str, "JWT token must not appear in payload"

    def test_manifest_passes_validation(self) -> None:
        """manifest() must satisfy ManifestValidator (all required fields present)."""
        from aevum.spiffe import SpiffeComplication

        sys.path.insert(0, "../../packages/aevum-core/src")
        from aevum.core.complications.manifest_validator import ManifestValidator

        comp = SpiffeComplication()
        errors = ManifestValidator().validate(comp.manifest())
        assert errors == [], f"Manifest validation errors: {errors}"


class TestSpiffeComplicationWithEngine:

    def test_spiffe_attested_appears_in_sigchain(self) -> None:
        """spiffe.attested must be a verifiable, signed event in the chain."""
        # Engine lives in aevum-core; pythonpath configured in pyproject.toml
        from aevum.core import Engine
        from aevum.spiffe import SpiffeComplication

        mock_svid = _make_mock_svid()
        mock_client = _make_mock_client(mock_svid)

        comp = SpiffeComplication()
        engine = Engine()

        with unittest.mock.patch(
            "aevum.spiffe.complication.WorkloadApiClient",
            return_value=mock_client,
        ):
            engine.install_complication(comp)
            engine.approve_complication("aevum-spiffe")
            # Engine has no automatic on_approved hook; caller invokes it.
            comp.on_approved(engine)

        entries = engine.get_ledger_entries()
        event_types = [e["event_type"] for e in entries]

        assert "spiffe.attested" in event_types, (
            f"spiffe.attested not in chain. Events: {event_types}"
        )
        assert engine.verify_sigchain() is True, "Chain must be intact after attestation"

        attested = next(e for e in entries if e["event_type"] == "spiffe.attested")
        assert attested["payload"]["spiffe_id"] == "spiffe://example.org/billing"
        assert attested["actor"] == "aevum-spiffe"
