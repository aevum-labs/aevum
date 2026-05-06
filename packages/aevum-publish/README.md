# aevum-publish

Sigstore Rekor v2 transparency log complication for Aevum.

Submits periodic chain checkpoints to an external transparency log,
enabling adversarial-resistant verification: even if an operator is
compromised, they cannot silently replace the chain without the external
witness detecting the discrepancy.

```bash
pip install aevum-publish[rekor]
```

```python
from aevum.core import Engine
from aevum.publish import PublishComplication

engine = Engine()
comp = PublishComplication(
    rekor_url="https://rekor.sigstore.dev",  # or private Rekor
    every_n_events=100,                      # checkpoint every 100 events
    every_seconds=300,                       # or every 5 minutes
)
engine.install_complication(comp)
engine.approve_complication("aevum-publish")
comp.on_approved(engine)  # must be called explicitly
# Chain now contains signed transparency.checkpoint events with Rekor inclusion proofs
```

## Checkpoint format

Each checkpoint is a SHA-256 digest of:
```json
{"prior_hash": "...", "sequence": 42, "signer_key_id": "...", "system_time": ...}
```

Submitted to Rekor as a `hashedrekord` entry. The Rekor log index and
inclusion proof are stored in the local sigchain as a `transparency.checkpoint`
AuditEvent, so the chain self-documents its verification history.

## Private Rekor

For confidential deployments where checkpoint hashes must not be public:

```python
comp = PublishComplication(rekor_url="https://your-private-rekor.example.com")
```

## Without Rekor

If `httpx` is not installed or the Rekor endpoint is unreachable, the
complication logs a warning and continues. The Engine write path is never
blocked.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `AEVUM_PUBLISH_EVERY_N_EVENTS` | `100` | Submit checkpoint after N events |
| `AEVUM_PUBLISH_EVERY_SECONDS` | `300` | Submit checkpoint after N seconds |

## See also

- [ADR-007: Transparency log](../../docs/adrs/adr-007-transparency-log.md)
- [Sigstore Rekor v2](https://github.com/sigstore/rekor-tiles)
