---
description: "Deploy a private Rekor v2 transparency log for air-gapped or confidential Aevum deployments."
---

# Self-Hosted Rekor v2 Deployment Guide

This guide covers deploying a private Rekor v2 (rekor-tiles) transparency log
for Aevum deployments that cannot or should not submit chain checkpoints to the
public Sigstore log. Common scenarios:

- Air-gapped environments with no internet access
- Regulated industries where checkpoint hashes must stay on-premises
- Multi-tenant deployments with separate per-tenant logs
- Development and staging environments

## Why private Rekor?

Aevum's `aevum-publish` complication submits SHA-256 digests of chain checkpoint
records to an external transparency log. The digests are hash values only — they
do not contain payload data — but their submission to a public log may not be
acceptable in some deployments (e.g., classified environments, or deployments
where chain activity timing is sensitive).

A private Rekor log provides the same cryptographic witnessing guarantee (an
external record that the chain root existed at a given time) without any external
data leaving your infrastructure.

## Architecture overview

```
                    ┌──────────────────────────────────┐
                    │      Your private infrastructure  │
                    │                                   │
  aevum-publish ───>│  Rekor v2 (rekor-tiles)           │
  complication      │  ┌─────────────────────────────┐  │
                    │  │ Trillian log server          │  │
                    │  │ Trillian + Rekor frontend    │  │
                    │  └─────────────────────────────┘  │
                    │          │                        │
                    │  Persistent storage (MySQL/PG)    │
                    └──────────────────────────────────┘
```

## Prerequisites

- Docker and Docker Compose (or Kubernetes)
- 2 GB RAM minimum
- Persistent disk for the transparency log database
- A domain name or internal hostname for the Rekor endpoint

## Quick start (Docker Compose)

The rekor-tiles project provides a reference Docker Compose configuration.
The following is a minimal adaptation for use with Aevum.

### 1. Clone rekor-tiles

```bash
git clone https://github.com/sigstore/rekor-tiles
cd rekor-tiles
```

### 2. Start the Rekor stack

```bash
docker compose up -d
```

By default, Rekor v2 listens on port 3000. Verify:

```bash
curl http://localhost:3000/api/v2/log
```

Expected response (abridged):

```json
{
  "treeSize": 0,
  "rootHash": "...",
  "signedTreeHead": "..."
}
```

### 3. Configure Aevum to use your private Rekor

Set the `AEVUM_REKOR_URL` environment variable before starting your application:

```bash
export AEVUM_REKOR_URL="http://your-rekor-host:3000"
```

Or pass it explicitly to `PublishComplication`:

```python
from aevum.publish import PublishComplication

comp = PublishComplication(
    rekor_url="http://your-rekor-host:3000",
    every_n_events=100,
    every_seconds=300,
)
engine.install_complication(comp)
engine.approve_complication("aevum-publish")
comp.on_approved(engine)
```

The complication will now submit to your private log. No data leaves
your infrastructure.

### 4. Verify submission

After a checkpoint is submitted, inspect the local sigchain for the
`transparency.checkpoint` event:

```python
entries = engine.get_ledger_entries()
cp = next(e for e in entries if e["event_type"] == "transparency.checkpoint")
print(cp["payload"]["rekor_log_index"])       # log index in your private Rekor
print(cp["payload"]["rekor_server"])           # your private Rekor URL
print(cp["payload"].get("inclusion_proof"))   # Merkle inclusion proof
```

## Production hardening

### TLS

Always run Rekor behind a TLS terminator in production:

```yaml
services:
  nginx:
    image: nginx:alpine
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./certs:/etc/nginx/certs
    ports:
      - "443:443"
    depends_on:
      - rekor
```

Set `AEVUM_REKOR_URL` to the HTTPS endpoint:

```bash
export AEVUM_REKOR_URL="https://rekor.internal.example.com"
```

### Persistence

The Trillian log database must be backed up alongside your Aevum store.
For disaster recovery, back up:

1. The Trillian MySQL or PostgreSQL database
2. The Rekor signing key (used to sign the Signed Tree Head)
3. Your Aevum PostgreSQL database (sigchain + knowledge graph)

### Air-gapped deployments

In fully air-gapped environments:

1. Pre-pull all required Docker images in your connected environment
2. Transfer them to the air-gapped environment via approved media
3. Deploy with `AEVUM_REKOR_URL` pointing to the internal endpoint
4. The lint rule (`No hardcoded Rekor URLs`) ensures no source code
   references the public Sigstore log — your build is self-contained

### Separate logs per tenant

For multi-tenant deployments, run one Rekor instance per tenant and configure
each Aevum Engine with the appropriate URL:

```python
tenant_a_comp = PublishComplication(rekor_url="https://rekor-tenant-a.internal")
tenant_b_comp = PublishComplication(rekor_url="https://rekor-tenant-b.internal")
```

## Verifying the log

Use the Rekor CLI (from the rekor-tiles project) to verify entries:

```bash
rekor-cli --rekor_server http://your-rekor-host:3000 \
  get --log-index <log_index>
```

Cross-reference the returned `body.spec.data.hash.value` with the SHA-256 digest
recorded in the `transparency.checkpoint` AuditEvent to confirm the entry
references the correct chain state.

## Troubleshooting

### `AEVUM_REKOR_URL not configured` warning

You will see this warning if `AEVUM_REKOR_URL` is not set and no `rekor_url` is
passed to `PublishComplication`. The complication degrades gracefully — no
checkpoint is submitted and the Engine write path is not blocked. Set the env var
to enable anchoring.

### Submission failures

If submission fails, the complication logs a warning and retries at the next
threshold (N events or T seconds). Check:

1. Is `AEVUM_REKOR_URL` correct and reachable?
2. Does the Rekor endpoint return 200/201 for `POST /api/v2/log/entries`?
3. Is httpx installed? (`pip install aevum-publish[rekor]`)

### Inclusion proof verification

If `inclusion_proof` is absent from the `transparency.checkpoint` payload,
the Rekor server returned a response without a `verification.inclusionProof`
field. Rekor v2 (rekor-tiles) always includes this field; Rekor v1 does not.
Ensure you are running Rekor v2.

## See also

- [ADR-007: Transparency log](../adrs/adr-007-transparency-log.md)
- [rekor-tiles project](https://github.com/sigstore/rekor-tiles)
- [Deployment guide](../learn/deployment.md)
- [THREAT_MODEL.md](https://github.com/aevum-labs/aevum/blob/main/THREAT_MODEL.md) — trust assumptions for external anchoring
