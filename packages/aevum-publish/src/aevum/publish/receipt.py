# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Public API surface for the COSE_Sign1 receipt format.

AevumReceipt  — canonical receipt payload (aevum.core.receipt)
ReceiptEncoder — COSE_Sign1 envelope builder (aevum.publish.encoder)

Both are re-exported here as the stable public interface for
packages that want to consume receipts without importing from
internal submodules directly.

COSE_Sign1 structure (RFC 9052 §4.2):
  [protected_bstr, unprotected_map, payload_bstr, signature_bstr]

  protected header:
    {1: -8 (EdDSA/Ed25519), 3: content_type, 4: kid,
     15: {1: "did:web:<host>", 2: "urn:aevum:receipt:..."}, "iat": <int>}
    label 15 is the CWT_Claims map (draft-ietf-scitt-architecture-22).

  unprotected header:
    {270: <RFC 3161 TST bytes>}  if TSA succeeded (CTT mode, RFC 9921 label 270 —
    the TST covers the signature bytes; see encoder.py for the CTT-vs-TTC rationale)

  signature: Ed25519 over SHA3-256(CBOR(Sig_Structure))

CRITICAL: alg = -8 (EdDSA). -7 is ES256/ECDSA — wrong silently.
"""

from aevum.core.receipt import AevumReceipt as AevumReceipt

from aevum.publish.encoder import ReceiptEncoder as ReceiptEncoder

__all__ = ["AevumReceipt", "ReceiptEncoder"]
