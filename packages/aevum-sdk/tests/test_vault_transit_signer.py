"""
Tests for VaultTransitSigner.
Uses a mock Vault response — no real Vault dependency.
"""
from __future__ import annotations

import sys
import unittest.mock

import pytest
from aevum.core.audit.sigchain import Sigchain


def test_vault_signer_import_error_without_hvac() -> None:
    """VaultTransitSigner raises ImportError when hvac is not installed."""
    with unittest.mock.patch.dict(sys.modules, {"hvac": None}), pytest.raises(ImportError, match="hvac"):
        from aevum.sdk.signing.vault_transit import VaultTransitSigner
        VaultTransitSigner(
            vault_url="http://vault:8200",
            vault_token="s.fake",
            key_name="aevum-key",
        )


def test_vault_signer_provenance() -> None:
    """VaultTransitSigner reports vault-transit provenance."""
    hvac_mock = unittest.mock.MagicMock()
    with unittest.mock.patch.dict(sys.modules, {"hvac": hvac_mock}):
        if "aevum.sdk.signing.vault_transit" in sys.modules:
            del sys.modules["aevum.sdk.signing.vault_transit"]
        from aevum.sdk.signing.vault_transit import VaultTransitSigner
        signer = VaultTransitSigner(
            vault_url="http://vault:8200",
            vault_token="s.fake",
            key_name="aevum-key",
        )
        assert signer.provenance == "vault-transit"
        assert "vault" in signer.key_id.lower() or "aevum-key" in signer.key_id


def test_vault_signer_accepted_by_sigchain() -> None:
    """Sigchain accepts VaultTransitSigner without errors at construction."""
    hvac_mock = unittest.mock.MagicMock()
    with unittest.mock.patch.dict(sys.modules, {"hvac": hvac_mock}):
        if "aevum.sdk.signing.vault_transit" in sys.modules:
            del sys.modules["aevum.sdk.signing.vault_transit"]
        from aevum.sdk.signing.vault_transit import VaultTransitSigner

        signer = VaultTransitSigner(
            vault_url="http://vault:8200",
            vault_token="s.fake",
            key_name="aevum-key",
        )
        sc = Sigchain(signer=signer)
        assert sc.key_provenance == "vault-transit"
