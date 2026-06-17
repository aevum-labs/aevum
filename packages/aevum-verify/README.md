# aevum-verify

Standalone sigchain verifier for Aevum. Re-implements verification from the
spec — entry signatures, the Merkle root, inclusion/consistency proofs,
tree-head signatures, and TSA certificate-chain validation — independently
of `aevum-core`, anchored only to pinned, out-of-band public keys.

Any third party — an auditor, a regulator, opposing counsel — can confirm
that an exported chain is authentic and unmodified without trusting the
Aevum vendor or the deploying firm's systems.

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

Merkle inclusion, consistency, and signed-tree-head verification are
re-implemented from the RFC 6962 spec independently of `aevum-core` — this
package never imports `aevum.core.audit.merkle`.

## License

Apache-2.0
