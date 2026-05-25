# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
ReceiptEncoder — wraps Ed25519 (DualSigner) + TSAClient in a COSE_Sign1 envelope.

RFC 9052 §4.2 COSE_Sign1 structure:
  [protected_bstr, unprotected_map, payload_bstr, signature_bstr]

  protected header (CBOR map, then bstr-wrapped):
    {1: -8, 3: "application/aevum-receipt+cbor", 4: b"aevum-issuer-v1",
     "iss": "did:web:<AEVUM_ISSUER_HOST>",
     "sub": "urn:aevum:receipt:<sigchain_entry_hash[:16]>",
     "iat": <int unix timestamp>}
    alg -8 = EdDSA (Ed25519). NOT -7 (ECDSA/ES256).

  unprotected header (plain CBOR map):
    {9: <tsa_token_bytes>}  if TSA succeeded and not dev mode
    label 9 per draft-ietf-cose-tsa-tst-header-parameter-08 (TBD; using 9 as placeholder)

  payload: AevumReceipt.to_cbor_payload() bytes

  signature: Ed25519 over SHA3-256(CBOR(Sig_Structure))
    Sig_Structure = ["Signature1", protected_bstr, b"", payload_bstr]
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import TYPE_CHECKING, Any

import cbor2
from aevum.core.receipt import AevumReceipt

if TYPE_CHECKING:
    from aevum.core.audit.signer import Signer
    from aevum.core.tsa import TSAClient

logger = logging.getLogger(__name__)

# COSE algorithm identifier for EdDSA (Ed25519) per RFC 9053.
# -7 is ECDSA (ES256) — WRONG. -8 is EdDSA — CORRECT.
_COSE_ALG_EDDSA = -8

# draft-ietf-cose-tsa-tst-header-parameter-08 label TBD; using integer 9 as placeholder.
# Update when RFC publishes.
_COSE_TST_HEADER_LABEL = 9


def _build_protected_header(
    issuer_uri: str,
    subject_uri: str,
    issued_at: int,
) -> dict[Any, Any]:
    """Build the COSE_Sign1 protected header map with SCITT-profile fields."""
    return {
        1: _COSE_ALG_EDDSA,
        3: "application/aevum-receipt+cbor",
        4: b"aevum-issuer-v1",
        # SCITT-profile protected header fields
        # draft-ietf-scitt-architecture-22 §4.1 — iss/sub labels TBD
        # Using CBOR text key strings until integer labels are standardized.
        # When draft publishes as RFC: update to assigned integer labels.
        "iss": issuer_uri,
        "sub": subject_uri,
        "iat": issued_at,
    }


def _build_protected_bstr(
    issuer_uri: str,
    subject_uri: str,
    issued_at: int,
) -> bytes:
    """Return the bstr-wrapped CBOR encoding of the protected header."""
    return cbor2.dumps(_build_protected_header(issuer_uri, subject_uri, issued_at))


def _build_sig_structure(protected_bstr: bytes, payload_bstr: bytes) -> bytes:
    """
    Sig_Structure per RFC 9052 §4.4:
      ["Signature1", protected_bstr, external_aad, payload_bstr]
    external_aad is empty bytes for our use case.
    """
    return cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])


class ReceiptEncoder:
    """
    Encodes an AevumReceipt as a COSE_Sign1 envelope.

    Uses the kernel's Ed25519 signing key (via Signer protocol) and optionally
    stamps the receipt with an RFC 3161 TSA token in the unprotected header.

    In dev_mode (AEVUM_DEV=1): no TSA calls, no network I/O.
    issuer_host: hostname for the SCITT iss field (did:web:<host>).
      Default: "aevum.local". Production: set AEVUM_ISSUER_HOST env var.
    """

    def __init__(
        self,
        signer: Signer,
        tsa_client: TSAClient | None = None,
        dev_mode: bool = False,
        issuer_host: str = "aevum.local",
    ) -> None:
        self._signer = signer
        self._tsa_client = tsa_client
        self._dev_mode = dev_mode
        self._issuer_host = issuer_host

    def encode(self, receipt: AevumReceipt) -> bytes:
        """
        Encode an AevumReceipt as a COSE_Sign1 envelope.

        In dev_mode: no TSA call, no external network calls.
        Returns raw CBOR bytes of the 4-element COSE_Sign1 array.
        """
        issuer_uri = "did:web:" + self._issuer_host
        subject_uri = "urn:aevum:receipt:" + receipt.sigchain_entry_hash[:16]
        issued_at = int(time.time())

        protected_bstr = _build_protected_bstr(issuer_uri, subject_uri, issued_at)
        payload_bstr = receipt.to_cbor_payload()

        sig_structure = _build_sig_structure(protected_bstr, payload_bstr)
        digest = hashlib.sha3_256(sig_structure).digest()
        signature_bytes = self._signer.sign(digest)

        unprotected: dict[int, Any] = {}
        if not self._dev_mode and self._tsa_client is not None:
            try:
                tsa_token = self._tsa_client.timestamp(payload_bstr)
                if tsa_token is not None:
                    # draft-ietf-cose-tsa-tst-header-parameter-08 label TBD; using 9 as placeholder.
                    unprotected[_COSE_TST_HEADER_LABEL] = tsa_token.token_bytes
            except Exception as exc:  # noqa: BLE001
                logger.warning("ReceiptEncoder: TSA timestamp failed (non-blocking): %s", exc)

        cose_sign1 = [protected_bstr, unprotected, payload_bstr, signature_bytes]
        return cbor2.dumps(cose_sign1)

    @classmethod
    def from_env(cls) -> ReceiptEncoder:
        """
        Construct from environment variables.
        AEVUM_DEV=1 → dev_mode=True, no TSA client.
        AEVUM_ISSUER_HOST → issuer hostname for SCITT iss field (default: aevum.local).
        Otherwise: production InProcessSigner + TSAClient.
        """
        from aevum.core.audit.signer import InProcessSigner
        from aevum.core.tsa import TSAClient

        dev_mode = os.environ.get("AEVUM_DEV", "").strip() == "1"
        issuer_host = os.environ.get("AEVUM_ISSUER_HOST", "aevum.local")
        signer: Signer = InProcessSigner()
        tsa_client: TSAClient | None = None if dev_mode else TSAClient()
        return cls(
            signer=signer,
            tsa_client=tsa_client,
            dev_mode=dev_mode,
            issuer_host=issuer_host,
        )
