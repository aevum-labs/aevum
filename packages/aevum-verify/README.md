# aevum-verify

Standalone independent verifier for Aevum sigchain entries and chains.

Re-implements verification from the spec without importing aevum-core infrastructure.
The trust anchor is always the pinned published key, never the key embedded in entries.

## Usage

```bash
aevum-verify entries.json --ed25519-pubkey <hex|file> [--mldsa-pubkey <hex|file>]
```

Exit codes: `0` = VERIFIED, `1` = FAILED, `2` = input error.

## Install

```bash
pip install aevum-verify            # classical (Ed25519) chains
pip install 'aevum-verify[pqc]'    # + ML-DSA-65 hybrid chains
```
