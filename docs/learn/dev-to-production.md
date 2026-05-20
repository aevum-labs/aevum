---
description: "Five steps to move from AEVUM_DEV=1 to a production Aevum deployment."
---

# Dev to Production — Upgrade Checklist

`AEVUM_DEV=1` gives you a working Aevum engine with zero configuration.
Before you deploy, complete these five steps to replace every dev-mode default
with a production-grade equivalent.

!!! warning "Dev mode is never safe for production"
    `AEVUM_DEV=1` grants consent to every subject and every operation for the
    lifetime of the process. It uses an ephemeral in-memory sigchain that is
    discarded on exit. Do not expose a dev-mode engine to real user data.

---

## Step 1 — Remove AEVUM_DEV=1

Unset or delete the environment variable:

=== "Linux / macOS"

    ```bash
    unset AEVUM_DEV
    # or in your .env file: remove the line AEVUM_DEV=1
    ```

=== "Docker / Compose"

    Remove the environment entry from your `docker-compose.yml` or Dockerfile:

    ```yaml
    # Remove or comment out:
    # - AEVUM_DEV=1
    ```

With `AEVUM_DEV` unset, the Engine raises a barrier error for any ingest or
query call that lacks a consent grant. Verify this:

```python
engine = Engine()
result = engine.ingest(
    data={"note": "test"},
    provenance={"source_id": "svc", "chain_of_custody": ["svc"], "classification": 0},
    purpose="my-app",
    subject_id="user-1",
    actor="my-agent",
)
assert result.status == "error"
assert result.data["error_code"] == "consent_required"
```

---

## Step 2 — Grant explicit consent

Replace the auto-consent ledger with real consent grants. Each grant is
per-subject, per-purpose, and time-bounded:

```python
from aevum.core.consent.models import ConsentGrant

engine.add_consent_grant(ConsentGrant(
    grant_id="grant-user1-support-2026",
    subject_id="user-1",
    grantee_id="support-agent",
    operations=["ingest", "query"],
    purpose="support-ticket-resolution",
    classification_max=0,
    granted_at="2026-01-01T00:00:00Z",
    expires_at="2027-01-01T00:00:00Z",
))
```

Guidelines:

- `purpose` must be specific and auditable. "any", "all", and empty string are rejected.
- `expires_at` is mandatory. Short-lived grants are preferable.
- Grant one grant per subject/purpose pair, not a single catch-all grant.
- Store grants in your application database and reload them on restart.

---

## Step 3 — Configure a persistent graph store

Dev mode uses `InMemoryGraphStore` — all data is lost on process exit.
For production, configure a persistent backend:

=== "Oxigraph (file-backed, small deployments)"

    ```python
    from aevum.store.oxigraph import OxigraphStore

    engine = Engine(
        graph_store=OxigraphStore(path="/var/lib/aevum/graph"),
    )
    ```

=== "PostgreSQL (team/production deployments)"

    ```python
    from aevum.store.postgres import PostgresStore

    engine = Engine(
        graph_store=PostgresStore(dsn="postgresql://user:pass@host:5432/aevum"),
    )
    ```

The persistent store maintains the sigchain across process restarts. The
`session.start` event written at Engine init will include a `causation_id`
linking to the last event of the previous session, creating a continuous
auditable chain.

---

## Step 4 — Configure the policy engine

Dev mode uses `NullPolicyEngine` — all ABAC decisions are PERMIT.
For production, install Cedar (the default) or configure OPA:

=== "Cedar (default, in-process)"

    ```bash
    pip install "aevum-core[cedar]"
    ```

    ```python
    from aevum.core.policy.cedar_engine import CedarPolicyEngine

    engine = Engine(
        policy_engine=CedarPolicyEngine.from_policies(Path("policies/")),
    )
    ```

=== "OPA (sidecar)"

    ```python
    engine = Engine(opa_url="http://localhost:8181")
    ```

    Run the OPA sidecar:

    ```bash
    opa run --server --bundle policies/
    ```

Without a real policy engine, any principal can call any function on any
resource. NullPolicyEngine logs a WARNING on first use to remind you.

---

## Step 5 — Use an external signer

Dev mode uses `InProcessSigner` — the signing key lives in Python heap memory
alongside the agent process. This satisfies tamper-detection but not
tamper-prevention.

For regulated deployments (FDA 21 CFR §11.10(e), EU AI Act Art. 12, HIPAA §164.312(b)):

=== "HashiCorp Vault Transit"

    ```bash
    pip install httpx  # already in aevum-core deps
    ```

    ```bash
    vault secrets enable transit
    vault write transit/keys/aevum-signing type=ed25519
    export VAULT_ADDR=https://vault.example.com
    export VAULT_TOKEN=<your-token>
    ```

    ```python
    from aevum.core.audit.signer import VaultTransitSigner
    from aevum.core.audit.sigchain import Sigchain

    signer = VaultTransitSigner("aevum-signing")
    engine = Engine(sigchain=Sigchain(signer=signer))
    ```

=== "AWS KMS (future)"

    AWS KMS signing is not yet implemented. Use `VaultTransitSigner` or
    implement the `Signer` protocol (see `aevum.core.audit.signer.Signer`).

=== "Custom KMS"

    Implement the `Signer` protocol and pass it to `Sigchain`:

    ```python
    from aevum.core.audit.signer import Signer

    class MyKMSSigner(Signer):
        def sign(self, digest: bytes) -> bytes: ...
        def public_key_bytes(self) -> bytes: ...

        @property
        def key_id(self) -> str: ...

        @property
        def provenance(self) -> str:
            return "my-kms"

    engine = Engine(sigchain=Sigchain(signer=MyKMSSigner()))
    ```

---

## Production checklist

Run through this before any deployment:

- [ ] `AEVUM_DEV` is unset (not `""`, not `"0"` — unset)
- [ ] Explicit consent grants loaded for all subjects
- [ ] Persistent graph store configured (Oxigraph or PostgreSQL)
- [ ] Cedar or OPA policy engine configured
- [ ] External signer configured (Vault Transit or equivalent)
- [ ] `engine.verify_sigchain()` returns `True` after startup
- [ ] No `NullPolicyEngine` warnings in logs
- [ ] Consent required check passes (test with a subject that has no grant)
- [ ] Review THREAT_MODEL.md Assumption 4 — confirm storage assumptions hold

---

## What dev mode never changes

These five absolute barriers are always active regardless of `AEVUM_DEV`:

1. **Crisis detection** — ingested content is always screened
2. **Classification ceiling** — results above actor clearance are always redacted
3. **Consent** — in dev mode this is bypassed by `DevModeConsentLedger`; in production it is enforced
4. **Audit immutability** — the ledger never allows deletion or overwrite
5. **Provenance** — every ingest requires a `source_id`

Never call `barriers.py` functions directly. Never monkeypatch them in production tests.
