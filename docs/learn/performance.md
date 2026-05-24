# Aevum Performance Benchmarks

Measured: 2026-05-24
Environment: Linux 6.18.5, CPython 3.11.15, cloud container (ephemeral)

## Ed25519+SHA3-256+CBOR signing (receipt encoding)

Operation: SHA3-256(payload) → CBOR header → Ed25519 sign (PyNaCl)
Sample size: 5,000 operations after 200-op warmup

| Metric | Value |
|--------|-------|
| p50    | 0.029 ms |
| p99    | 0.062 ms |
| peak   | 0.141 ms |

**Architecture decision: sign-every-entry** (p50 well under 1 ms threshold)

Every sigchain entry receives a COSE_Sign1 receipt with a full Ed25519 signature.
Batch Merkle-root signing is not required.

## SQLite WAL receipt storage

Operation: INSERT row (400-byte blob) with WAL journal mode, NORMAL synchronous
Sample size: 10,000 inserts, single transaction

| Metric | Value |
|--------|-------|
| Rate   | 110,490 inserts/sec |
| Elapsed | 0.09 s |
| Result | Excellent (>50,000 threshold) |

SQLite WAL is suitable for receipt storage at production agent call rates.
No external database is required for single-node deployments.

## Notes

- Benchmarks run in an isolated cloud container; bare-metal numbers will be higher.
- Ed25519 via PyNaCl (libsodium backend). SHA3-256 via CPython hashlib.
- SQLite WAL benchmark uses a single transaction; per-event transaction mode
  will be slower but is not needed for receipt blobs (appended in bulk).
