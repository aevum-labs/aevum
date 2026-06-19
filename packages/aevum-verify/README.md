# aevum-verify

Standalone sigchain verifier for Aevum. `aevum-verify` shares no code with
`aevum-core` — every cryptographic primitive (the signing-digest
construction, payload hashing, chain hashing, RFC 6962 Merkle inclusion and
consistency proofs, tree-head signatures, and TSA certificate-chain
validation) is reimplemented directly from the public spec,
[`docs/spec/aevum-signing-v1.md`](https://github.com/aevum-labs/aevum/blob/main/docs/spec/aevum-signing-v1.md),
not derived from or imported from the chain producer's runtime.

This means signature verification no longer trusts the operator's runtime:
any third party — an auditor, a regulator, opposing counsel — can confirm
that an exported chain is internally consistent and matches its claimed
signatures using an implementation that imports nothing from the system that
produced the chain. `aevum-verify` is **tamper-evident, not tamper-proof** —
it detects whether an exported chain has been altered after the fact; it
makes no claim about events that were never recorded or about the integrity
of the system that generated the chain in the first place.

## Independence

- Zero runtime dependency on `aevum-core` — `aevum-verify`'s own package
  metadata does not declare it, and `aevum-verify`'s wheel does not pull it
  in.
- Zero imports of any `aevum.core.*` module from `_core.py` or `_format.py`,
  enforced by an AST-level test (`test_merkle_sth.py::TestMerkleIndependence`)
  that fails the build if either file ever imports from the producer again.
- The only inputs trusted are the pinned public key bytes the caller supplies
  out-of-band, and the chain file itself.

Tests are the one place this package still touches `aevum-core`: fixtures
use the real `Sigchain`/`DualSigner` to produce genuinely signed chains so
the independent reimplementation can be checked against real signatures,
not just its own assumptions. None of that is reachable from `aevum-verify`'s
verification logic or its packaged dependencies.

## Install

```bash
pip install aevum-verify
# With post-quantum (ML-DSA-65) support:
pip install "aevum-verify[pqc]"
```

## CLI usage

```bash
aevum-verify CHAIN_FILE --ed25519-pub HEX [--mldsa65-pub HEX]
```

- `CHAIN_FILE` — path to a JSON file containing a list of serialised chain entries.
- `--ed25519-pub` — pinned Ed25519 public key as 64-char hex, or `@/path/to/file` for a raw 32-byte binary key.
- `--mldsa65-pub` — pinned ML-DSA-65 public key as hex or `@filepath`; required for hybrid (`ed25519+ml-dsa-65`) chains.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | VERIFIED — all entries intact |
| 1 | FAILED — chain tampered, signature invalid, or trust-anchor mismatch |
| 2 | Usage error (bad arguments or unreadable file) |

### Example

```bash
aevum-verify chain.json --ed25519-pub "$(cat pubkey.hex)"
```

> **Key file format matters.** If your public key is stored as a `.hex` file
> (ASCII hex text, e.g. `1cb499...`), pass it with
> `--ed25519-pub "$(cat file.hex)"`. The `@/path/to/file` form reads the file
> as **raw 32-byte binary**, not hex text — using `@` against a `.hex` text
> file will not parse as a valid Ed25519 key.

## Python API

```python
from aevum.verify import load_chain, verify_chain

entries = load_chain("chain.json")
result = verify_chain(entries, ed25519_pub=bytes.fromhex(pubkey_hex))
assert result.ok, result.reason
```

## Trust model

The verifier trusts only the public key bytes supplied out-of-band by the
caller — never anything embedded in the chain file itself. For hybrid
entries, both the pinned Ed25519 key and the pinned ML-DSA-65 key must be
supplied; absence of either signature or key for a hybrid entry fails
closed. A chain mixing key schemes (e.g. some entries classical, some
hybrid) is rejected outright as a downgrade/splice fingerprint.

Malformed or hostile input — corrupt JSON, truncated files, missing fields,
wrong-length keys, garbage-hex embedded fields, oversized hex values or
entry counts — fails closed (a reported FAILED result, a non-zero exit
code, or a usage error) rather than raising an unhandled exception or
silently accepting bad data.

## License

Apache-2.0
