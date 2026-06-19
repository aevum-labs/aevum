# aevum-core

The independent black box for AI agents — tamper-evident, independently
verifiable records of what your agents did.

`aevum-core` is the Aevum context kernel: five governed functions (`ingest`,
`query`, `review`, `commit`, `replay`) over an append-only episodic ledger,
gated by five unconditional barriers (crisis detection, classification
ceiling, consent, audit immutability, provenance) that are hardcoded and
never policy-controlled.

- **SHA3-256 hash-chained sigchain** — every event is RFC 8785 (JCS)
  canonicalized and Ed25519-signed (RFC 8032); an optional hybrid ML-DSA-65
  (FIPS 204) signature runs alongside it for post-quantum defense-in-depth.
- **COSE_Sign1 receipts with RFC 3161 trusted timestamps** — each entry is
  wrapped in a portable, independently verifiable receipt.
- **RFC 6962-style Merkle log** — Signed Tree Heads with inclusion and
  consistency proofs detect any historical rewrite of the ledger.
- **Cedar ABAC + OPA policy engines** — consent and content/infrastructure
  decisions are externalised and optional, sitting behind the unconditional
  barriers rather than replacing them.
- Verification logic also ships as a separate package,
  [`aevum-verify`](https://pypi.org/project/aevum-verify/), so a receipt can
  be checked without running the rest of the kernel.

## Install

    pip install aevum-core
    pip install "aevum-core[cedar]"  # + real Cedar consent enforcement

## Docs

Full documentation, threat model, and regulatory alignment:
https://github.com/aevum-labs/aevum

## License

Apache-2.0.
