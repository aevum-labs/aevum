# liboqs Deployment Guide

Aevum's ML-DSA-65 dual-signing uses `liboqs-python`, which is a Python binding for
the [Open Quantum Safe](https://openquantumsafe.org/) liboqs C library. The pip
package does **not** bundle the native `.so` — it must be built and installed
separately before running `pip install aevum-core`.

When liboqs is not installed, Aevum falls back to Ed25519-only mode (see
[Running without liboqs](#running-without-liboqs)).

---

## Development (Linux / macOS — cmake build)

```bash
sudo apt-get install -y cmake ninja-build   # Debian/Ubuntu
# brew install cmake ninja                  # macOS

curl -fsSL https://github.com/open-quantum-safe/liboqs/archive/refs/tags/0.14.0.tar.gz | tar xz

cmake -GNinja \
  -DCMAKE_INSTALL_PREFIX="$HOME/_oqs" \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_USE_OPENSSL=OFF \
  -S liboqs-0.14.0 -B liboqs-build

ninja -C liboqs-build -j$(nproc) install
rm -rf liboqs-0.14.0 liboqs-build

export LD_LIBRARY_PATH="$HOME/_oqs/lib:$LD_LIBRARY_PATH"
# On macOS: export DYLD_LIBRARY_PATH="$HOME/_oqs/lib:$DYLD_LIBRARY_PATH"

pip install "aevum-core"   # liboqs-python will now find the native library
```

Add the `LD_LIBRARY_PATH` export to your shell profile (`.bashrc`, `.zshrc`) so
it persists across sessions.

---

## Production (Docker — two-stage build)

A two-stage build keeps the final image small: compile liboqs in a builder stage,
then copy only the shared library to the runtime stage.

```dockerfile
# ── Stage 1: build liboqs ──────────────────────────────────────────────────
FROM python:3.12-slim AS liboqs-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://github.com/open-quantum-safe/liboqs/archive/refs/tags/0.14.0.tar.gz | tar xz \
    && cmake -GNinja \
       -DCMAKE_INSTALL_PREFIX=/opt/oqs \
       -DBUILD_SHARED_LIBS=ON \
       -DOQS_USE_OPENSSL=OFF \
       -S liboqs-0.14.0 -B liboqs-build \
    && ninja -C liboqs-build -j$(nproc) install \
    && rm -rf liboqs-0.14.0 liboqs-build

# ── Stage 2: runtime ───────────────────────────────────────────────────────
FROM python:3.12-slim

COPY --from=liboqs-builder /opt/oqs/lib /opt/oqs/lib

ENV LD_LIBRARY_PATH="/opt/oqs/lib:$LD_LIBRARY_PATH"

RUN pip install --no-cache-dir "aevum-core"

# Your application entrypoint
CMD ["python", "-m", "your_app"]
```

---

## Conda

```bash
conda install -c conda-forge liboqs
pip install "aevum-core"
```

Conda-forge packages the pre-built liboqs C library for Linux and macOS.
No cmake step required.

---

## Verifying installation

```python
from aevum.core.signing import _OQS_AVAILABLE, DualSigner

if _OQS_AVAILABLE:
    s = DualSigner.generate()
    print(f"ML-DSA-65 ready. Public key: {len(s.mldsa65_public_key)} bytes")
else:
    print("liboqs not available — ML-DSA-65 disabled, Ed25519 only")
```

Expected output when liboqs is correctly installed:

```
ML-DSA-65 ready. Public key: 1952 bytes
```

---

## Running without liboqs

When liboqs is not installed, Aevum operates in **Ed25519-only mode**:

- All sigchain entries are signed with Ed25519 (`InProcessSigner`).
- `DualSigner.generate()` and `DualSigner.sign()` raise `ImportError`.
- The canary test (canary 6: `dual_signature_every_chain_entry`) reports
  `passed=True` with a skip note rather than failing.
- Sigchain entries will have `mldsa65_sig=None` and `mldsa65_pub=None`.

This is acceptable for development and evaluation. Production deployments
that require post-quantum signing must install liboqs.

---

## Key sizes (ML-DSA-65)

When dual-signing is active, each sigchain entry carries a `DualSignature`:

| Field | Size |
|---|---|
| Ed25519 signature | 64 bytes |
| ML-DSA-65 signature | 3,309 bytes |
| Ed25519 public key | 32 bytes |
| ML-DSA-65 public key | 1,952 bytes |
| **Total per `DualSignature`** | **~5.4 KB** |

For high-throughput deployments, consider the storage overhead before
enabling dual-signing on every sigchain entry.

---

## EAR §742.15 compliance

ML-DSA-65 (FIPS 204, Module-Lattice-Based Digital Signature Algorithm) is a
published, standardized NIST algorithm. The original EAR §742.15 notification
for Aevum was filed 2026-05-20. A supplemental notification adding ML-DSA-65
was filed 2026-05-24. See [SECURITY.md](../../security.md) for details.

---

## Related documents

- `docs/architecture/signing.md` — dual-signing architecture and sigchain wiring
- `docs/deployment/key-rotation.md` — rotating Ed25519 + ML-DSA-65 keypairs
- `docs/deployment/rekor-self-hosted.md` — Rekor transparency log anchoring
