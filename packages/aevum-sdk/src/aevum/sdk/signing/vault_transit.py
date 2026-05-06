"""
VaultTransitSigner — HashiCorp Vault Transit Engine signing backend.

The private key never leaves Vault. Aevum sends only the SHA3-256 digest
of the canonical event, receives the signature. prehashed=true ensures
event payload content is never transmitted to Vault.

Requires: pip install aevum-sdk[vault]
(hvac is an optional dependency — not imported at module level)

Usage:
    from aevum.sdk.signing.vault_transit import VaultTransitSigner
    from aevum.core.audit.sigchain import Sigchain

    signer = VaultTransitSigner(
        vault_url="https://vault.example.com",
        vault_token="s.xxx",
        key_name="aevum-signing-key",
    )
    sigchain = Sigchain(signer=signer)
    engine = Engine(ledger=InMemoryLedger(sigchain))
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from aevum.core.audit.signer import Signer

if TYPE_CHECKING:
    pass  # hvac imported lazily to avoid hard dependency


class VaultTransitSigner(Signer):
    """
    Signs SHA3-256 digests via Vault Transit Engine.

    Key requirements in Vault:
        vault secrets enable transit
        vault write transit/keys/aevum-signing-key type=ed25519
        vault policy write aevum-sign - <<EOF
            path "transit/sign/aevum-signing-key" { capabilities = ["update"] }
            path "transit/keys/aevum-signing-key" { capabilities = ["read"] }
        EOF

    The key name is used as key_id for chain tracking. If you rotate keys,
    use a different key_name and emit a session.start with the new signer
    so the chain boundary is explicit.
    """

    def __init__(
        self,
        vault_url: str,
        vault_token: str,
        key_name: str,
        mount_point: str = "transit",
        key_version: int | None = None,
    ) -> None:
        try:
            import hvac  # noqa: F401 — verify available at init time
        except ImportError as exc:
            raise ImportError(
                "VaultTransitSigner requires hvac. "
                "Install with: pip install aevum-sdk[vault]"
            ) from exc

        self._vault_url = vault_url.rstrip("/")
        self._vault_token = vault_token
        self._key_name = key_name
        self._mount_point = mount_point
        self._key_version = key_version  # None = latest
        self._key_id_str = (
            f"{vault_url}/transit/keys/{key_name}"
            + (f":{key_version}" if key_version else "")
        )
        self._public_key_cache: bytes | None = None

    def sign(self, digest: bytes) -> bytes:
        """
        Sign the SHA3-256 digest via Vault Transit.
        Uses prehashed=true — Vault signs the digest directly.
        The digest is base64-encoded for the Vault API.
        """
        import hvac

        client = hvac.Client(url=self._vault_url, token=self._vault_token)
        input_b64 = base64.b64encode(digest).decode()

        response = client.secrets.transit.sign_data(
            name=self._key_name,
            hash_input=input_b64,
            prehashed=True,
            mount_point=self._mount_point,
        )

        # Vault returns "vault:v{n}:base64signature"
        raw_sig = response["data"]["signature"]
        sig_b64 = raw_sig.split(":")[-1]
        return base64.b64decode(sig_b64 + "==")  # re-pad for b64decode

    def public_key_bytes(self) -> bytes:
        """Fetch public key from Vault key metadata (cached after first call)."""
        if self._public_key_cache is not None:
            return self._public_key_cache

        import hvac

        client = hvac.Client(url=self._vault_url, token=self._vault_token)
        response = client.secrets.transit.read_key(
            name=self._key_name,
            mount_point=self._mount_point,
        )
        # For ed25519, Vault returns keys[version][public_key] as base64
        keys = response["data"]["keys"]
        version = str(self._key_version or max(int(v) for v in keys))
        pub_b64 = keys[version]["public_key"]
        self._public_key_cache = base64.b64decode(pub_b64 + "==")
        return self._public_key_cache

    @property
    def key_id(self) -> str:
        return self._key_id_str

    @property
    def provenance(self) -> str:
        return "vault-transit"
