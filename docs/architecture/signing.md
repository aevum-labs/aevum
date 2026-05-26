# Signing Architecture

## Overview

Every Aevum sigchain entry is signed with **both** Ed25519 (PyNaCl) and
ML-DSA-65 (liboqs-python) when `DualSigner` is configured. Both signatures must
be present and valid for a chain entry to be accepted during verification — this
is an AND check, not OR. If either signature is invalid, `SignatureError` is raised.

This is defense-in-depth: if one algorithm is compromised, the other must also be
compromised for a forgery to succeed.

---

## DualSigner

`DualSigner` (`aevum.core.signing.DualSigner`) holds:

- An Ed25519 keypair (via PyNaCl `nacl.signing.SigningKey`)
- An ML-DSA-65 keypair (via liboqs-python `oqs.Signature("ML-DSA-65")`)

```python
from aevum.core.signing import DualSigner, _OQS_AVAILABLE

if _OQS_AVAILABLE:
    signer = DualSigner.generate()   # new keypair (liboqs required)
    signer = DualSigner.load(path)   # load from disk

    dual_sig = signer.sign(data)     # returns DualSignature
    DualSigner.verify(data, dual_sig)  # raises SignatureError if invalid
```

`DualSigner.generate()` and `DualSigner.sign()` require liboqs native `.so`.
When liboqs is absent (`_OQS_AVAILABLE = False`), both raise `ImportError`.

`DualSigner.verify()` is a `@staticmethod` — it does not need a `DualSigner`
instance, only the data and the `DualSignature` (which embeds the public keys).

### Key sizes

| Component | Size |
|---|---|
| Ed25519 secret key | 32 bytes |
| Ed25519 public key | 32 bytes |
| ML-DSA-65 secret key | 4,032 bytes |
| ML-DSA-65 public key | 1,952 bytes |
| Ed25519 signature | 64 bytes |
| ML-DSA-65 signature | 3,309 bytes |

### Key file permissions

`DualSigner.save(path)` writes three files:

| File | Permissions |
|---|---|
| `ed25519.key` (secret) | `0o600` |
| `mldsa65.sk` (secret) | `0o600` |
| `mldsa65.pk` (public) | `0o644` |

---

## Wiring into the Sigchain

`DualSigner` is an **optional** constructor argument to `Sigchain`:

```python
from aevum.core.audit.sigchain import Sigchain
from aevum.core.signing import DualSigner

# Default: Ed25519 only (InProcessSigner)
chain = Sigchain()

# With dual-signing: Ed25519 + ML-DSA-65
signer = DualSigner.load(state_dir)
chain = Sigchain(dual_signer=signer)
```

The **default signer** is `InProcessSigner` (`aevum.core.audit.signer.InProcessSigner`),
which generates an Ed25519 key in-process at startup. `DualSigner` is additive —
it adds a second signing layer on top of `InProcessSigner`, it does not replace it.

When `dual_signer` is provided, `Sigchain.new_event()`:

1. Signs the canonical event fields with `InProcessSigner` (Ed25519 — chain-linking
   signature, stored in `AuditEvent.signature`).
2. Signs the same canonical bytes with `DualSigner` (Ed25519 + ML-DSA-65 —
   stored in `AuditEvent.ed25519_sig`, `ed25519_pub`, `mldsa65_sig`, `mldsa65_pub`).
3. Immediately verifies the `DualSignature` belt-and-suspenders before
   attaching it to the event.

When `dual_signer` is absent (default), steps 2–3 are skipped. Chain entries will
have `mldsa65_sig=None` and `mldsa65_pub=None`.

`Sigchain.verify_chain()` verifies the dual-sig on each entry **only** when:
- `dual_signer` is configured on the `Sigchain` instance, **and**
- the entry has non-None `mldsa65_sig`.

---

## Two-Layer Signing Model

Aevum uses two distinct signing layers:

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1 — Sigchain integrity (every entry, always)             │
│  InProcessSigner → Ed25519 signature → AuditEvent.signature     │
│                                                                 │
│  Layer 2 — Post-quantum augmentation (when DualSigner wired)    │
│  DualSigner → Ed25519 + ML-DSA-65 → AuditEvent.{ed25519,mldsa} │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  Layer 3 — Receipt portability (COSE_Sign1, when encoder wired) │
│  ReceiptEncoder → Ed25519 COSE_Sign1 → AuditEvent.receipt_cbor  │
└─────────────────────────────────────────────────────────────────┘
```

### Why COSE_Sign1 receipts use Ed25519 only

The `ReceiptEncoder` (Phase 1A) encodes COSE_Sign1 receipts with algorithm `-8`
(Ed25519). Adding ML-DSA-65 to COSE_Sign1 would require algorithm `-48` (tentative
IANA assignment for ML-DSA-65) and would produce receipts that many existing COSE
consumers cannot verify. The ML-DSA-65 protection is at **Layer 2** (sigchain),
not Layer 3 (COSE receipt). This is intentional — do not conflate the two layers.

---

## InProcessSigner

`InProcessSigner` (`aevum.core.audit.signer.InProcessSigner`) is the default
signing implementation. It is a **production class** (not a test fixture) that
generates an Ed25519 key in-process at startup.

```python
from aevum.core.audit.signer import InProcessSigner

signer = InProcessSigner()  # auto-generates Ed25519 key
```

When liboqs is absent, use `InProcessSigner` for tests that need signing without
`DualSigner.generate()`:

```python
from aevum.core.audit.signer import InProcessSigner
from aevum.core.audit.sigchain import Sigchain

# Works without liboqs — no DualSigner needed
chain = Sigchain(signer=InProcessSigner())
```

---

## Operating without liboqs

When liboqs is not installed (`_OQS_AVAILABLE = False`):

- `DualSigner.generate()` raises `ImportError`
- `DualSigner.sign()` raises `ImportError`
- `DualSigner.verify()` raises `ImportError` (after Ed25519 is verified)
- `Sigchain` falls back to Ed25519-only mode automatically
- Canary 6 (`dual_signature_every_chain_entry`) passes with a skip note
- All sigchain entries have `mldsa65_sig=None`

This is the expected behaviour for development environments. Install liboqs for
production dual-signing. See `docs/deployment/liboqs.md`.

---

## EAR §742.15

ML-DSA-65 (FIPS 204) supplemental notification filed 2026-05-24.
See [SECURITY.md](../../security.md) for the full filing history.
