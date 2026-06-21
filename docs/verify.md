---
title: "Verify an Aevum Chain Independently"
description: "How to verify an Aevum sigchain or auditor evidence pack using only the standalone aevum-verify package — no Aevum installation, no producer source code, no network access."
---

# Verify It Yourself

Aevum's headline claim is that its records are **independently verifiable** —
not just tamper-evident in theory, but checkable by someone who does not
trust Aevum, the operator, or the model provider. This page is that proof,
made runnable.

## Why this exists

`aevum-verify` is a separate PyPI package with **zero runtime dependency on
`aevum-core`**. It reimplements the signing-digest construction, payload
hashing, chain hashing, and Merkle proof checks directly from the public
spec — it does not import or trust the code that produced the chain. That
means an auditor, regulator, or opposing counsel can confirm a chain is
internally consistent using an implementation that shares no code with the
system being audited. That separation is what makes the records defensible
instead of merely self-attested.

## Install

A clean virtual environment is enough — you do not need `aevum-core`,
the Aevum source, or network access to anything but PyPI.

```bash
pipx run aevum-verify --help          # try it without installing
# or
pip install aevum-verify
```

**Dual-signed (hybrid Ed25519 + ML-DSA-65) chains need the `[pqc]` extra:**

```bash
pip install "aevum-verify[pqc]"
```

A plain `aevum-verify` install can verify classical Ed25519-only chains, but
it cannot check the post-quantum signature on a hybrid chain — it fails
closed with `liboqs unavailable — cannot verify ML-DSA-65 signature` rather
than silently skipping the check. If your chain is hybrid-signed, install
`[pqc]` up front.

## Verify a chain

Aevum's demo publishes a synthetic sample chain and its pinned public key so
you can try this immediately, with no real data involved:

```bash
curl -O https://demo.aevum.build/sample-chain.json
curl -O https://demo.aevum.build/sample-ed25519-pub.hex

pipx run aevum-verify sample-chain.json \
  --ed25519-pub "$(cat sample-ed25519-pub.hex)"
```

Expect:

```text
VERIFIED — 5 entries intact
```

with exit code `0`.

!!! warning "`--ed25519-pub` takes the key value, not a filename"
    `--ed25519-pub` expects the hex string itself (or `@/path/to/file` for
    *raw binary*). A `.hex` file holds hex **text**, so passing the bare
    filename will not parse as a key — read it into the argument with
    `"$(cat sample-ed25519-pub.hex)"` as shown above. This is the most
    common copy-paste mistake when running the command by hand.

If you were handed a self-contained **auditor evidence pack** instead (a
directory with `chain.json`, `ed25519-pub.hex`, `manifest.json`, and
`VERIFY.txt`), the same shape applies — `cd` into the pack and run the
command printed in its `VERIFY.txt`. A hybrid pack additionally carries
`mldsa65-pub.hex` and requires `--mldsa65-pub "$(cat mldsa65-pub.hex)"`.

No `pipx`? `pip install aevum-verify`, then run `aevum-verify ...` the same
way.

## What a failure looks like

Change one byte of the chain and verification fails — this is what tells
you the verifier is actually checking something, not just printing success:

```bash
aevum-verify tampered-chain.json --ed25519-pub "$(cat sample-ed25519-pub.hex)"
```

```text
FAILED — entry 0: payload_hash mismatch
```

with exit code `1`. A `FAILED` line always names the first failing entry and
the specific check that broke — `payload_hash mismatch`, `Ed25519 signature
invalid`, `prior_hash mismatch`, or (for hybrid chains without the `[pqc]`
extra) `liboqs unavailable`. Any `FAILED` result means the chain's contents
must not be trusted.

## What this proves, and what it doesn't

- **An independent *code path*, not an independent third party.**
  `aevum-verify` re-derives every check from the public signing spec and
  RFC 6962 — it shares no code with the producer — but it is still software
  Aevum publishes. It is the instrument an independent third party uses, not
  a substitute for one.
- **Tamper-evident, not tamper-proof.** A `VERIFIED` result means the chain
  is internally consistent with its signatures and hashes since it was
  written — not that it is physically impossible to forge under any threat
  model. See [Tamper-Evident Logging](concepts/tamper-evident-logs.md) for
  what append-only, hash-chained, and signed each guarantee (and don't).
- **Verifies integrity, not completeness.** A clean chain proves nothing in
  it was altered after capture — it does not prove every action the agent
  took was recorded in the first place. See
  [Capture Faithfulness](concepts/capture-faithfulness.md) for that boundary
  and how `capture.gap` events make it visible instead of silent.

For the full CLI reference, exit codes, and the Python API, see the
[`aevum-verify` package README](https://github.com/aevum-labs/aevum/blob/main/packages/aevum-verify/README.md).
