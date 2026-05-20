# SPDX-License-Identifier: Apache-2.0
"""
Layer 5 — VaultTransitSigner wire format conformance tests (Phase B-3 / Phase C).

Verifies the key_scheme, provenance, and key_id format contracts for VaultTransitSigner.
No live Vault instance is required — these tests verify structural properties only.

Contracts:
  - key_scheme: "ed25519+vault-transit"
  - provenance: "vault-transit"
  - key_id: "{vault_addr}/v1/transit/keys/{key_name}" (stable, deterministic)

Reference: aevum.core.audit.signer.VaultTransitSigner
"""
from __future__ import annotations

from aevum.core.audit.signer import VaultTransitSigner


class TestVaultTransitKeySchemeContract:
    """VaultTransitSigner must declare key_scheme = "ed25519+vault-transit"."""

    def test_key_scheme_is_ed25519_vault_transit(self) -> None:
        signer = VaultTransitSigner("aevum-signing", vault_addr="http://vault:8200", token="tok")
        assert signer.key_scheme == "ed25519+vault-transit"

    def test_key_scheme_is_stable_across_calls(self) -> None:
        signer = VaultTransitSigner("aevum-signing", vault_addr="http://vault:8200", token="tok")
        assert signer.key_scheme == signer.key_scheme

    def test_key_scheme_is_different_from_in_process_scheme(self) -> None:
        from aevum.core.audit.signer import InProcessSigner
        in_process = InProcessSigner()
        vault = VaultTransitSigner("key", vault_addr="http://vault:8200", token="tok")
        # In-process signer has no key_scheme property — vault transit must declare its own
        assert vault.key_scheme == "ed25519+vault-transit"
        assert not hasattr(in_process, "key_scheme") or in_process.key_scheme != vault.key_scheme  # type: ignore[attr-defined]


class TestVaultTransitProvenanceContract:
    """VaultTransitSigner must declare provenance = "vault-transit" (external trust boundary)."""

    def test_provenance_is_vault_transit(self) -> None:
        signer = VaultTransitSigner("aevum-signing", vault_addr="http://vault:8200", token="tok")
        assert signer.provenance == "vault-transit"

    def test_provenance_differs_from_in_process(self) -> None:
        from aevum.core.audit.signer import InProcessSigner
        in_process = InProcessSigner()
        vault = VaultTransitSigner("key", vault_addr="http://vault:8200", token="tok")
        assert vault.provenance != in_process.provenance


class TestVaultTransitKeyIdContract:
    """key_id must be stable and encode vault_addr + key_name for auditor lookup."""

    def test_key_id_contains_vault_addr_host(self) -> None:
        signer = VaultTransitSigner("aevum-signing", vault_addr="http://vault:8200", token="tok")
        assert "vault:8200" in signer.key_id

    def test_key_id_contains_key_name(self) -> None:
        signer = VaultTransitSigner("aevum-signing", vault_addr="http://vault:8200", token="tok")
        assert "aevum-signing" in signer.key_id

    def test_key_id_is_stable_property(self) -> None:
        signer = VaultTransitSigner("my-key", vault_addr="http://vault:8200", token="tok")
        assert signer.key_id == signer.key_id

    def test_different_key_names_produce_different_key_ids(self) -> None:
        s1 = VaultTransitSigner("key-a", vault_addr="http://vault:8200", token="tok")
        s2 = VaultTransitSigner("key-b", vault_addr="http://vault:8200", token="tok")
        assert s1.key_id != s2.key_id

    def test_different_vault_addrs_produce_different_key_ids(self) -> None:
        s1 = VaultTransitSigner("key", vault_addr="http://vault-prod:8200", token="tok")
        s2 = VaultTransitSigner("key", vault_addr="http://vault-staging:8200", token="tok")
        assert s1.key_id != s2.key_id
