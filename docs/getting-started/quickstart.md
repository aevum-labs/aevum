---
description: "Install aevum-core, create consent grants, ingest signed data, query with purpose, replay past decisions, and verify the sigchain — in under 10 minutes."
---

# Quickstart

Get Aevum running in 10 minutes on Linux or macOS.
For Windows, see the [Windows Guide](quickstart-windows.md).

## Prerequisites

- Python 3.11 or higher
- `pip` (comes with Python)

Check your version:

```bash
python --version
# Python 3.11.x or higher
```

## Step 1 — Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

You should see `(.venv)` in your prompt.

## Step 2 — Install aevum-core

```bash
pip install aevum-core
```

Verify:

```bash
python -c "import aevum.core; print('aevum-core', aevum.core.__version__)"
```

## Step 3 — Create your first script

Create a file called `demo.py`:

```python
from aevum.core import Engine
from aevum.core.consent.models import ConsentGrant

# Step 4: Create the engine (in-memory storage)
engine = Engine()

# Step 5: Grant an agent consent to operate
engine.add_consent_grant(ConsentGrant(
    grant_id="demo-grant",
    subject_id="user-1",
    grantee_id="demo-agent",
    operations=["ingest", "query"],
    purpose="product-demo",
    classification_max=0,
    granted_at="2026-01-01T00:00:00Z",
    expires_at="2030-01-01T00:00:00Z",
))

# Step 6: Ingest data — every write is signed and chained
result = engine.ingest(
    data={"note": "User requested account review"},
    provenance={
        "source_id": "demo",
        "chain_of_custody": ["demo"],
        "classification": 0,
    },
    purpose="product-demo",
    subject_id="user-1",
    actor="demo-agent",
)
print("audit_id:", result.audit_id)  # urn:aevum:audit:<uuid7>
print("status:  ", result.status)    # ok

# Step 7: Query — returns results only with an active consent grant
q = engine.query(
    purpose="product-demo",
    subject_ids=["user-1"],
    actor="demo-agent",
)
print("results: ", list(q.data["results"].keys()))  # ['user-1']

# Step 8: Replay any past decision deterministically
r = engine.replay(audit_id=result.audit_id, actor="demo-agent")
print("replayed:", r.data["replayed_payload"]["note"])

# Step 9: Verify the sigchain is intact
ok = engine.verify_sigchain()
print("chain intact:", ok)  # True
```

## Step 4 — Run it

```bash
python demo.py
```

Expected output:

```
audit_id: urn:aevum:audit:0196...
status:   ok
results:  ['user-1']
replayed: User requested account review
chain intact: True
```

## What just happened

Every step is governed:

- **Ingest** — data was written through the governed membrane, signed with Ed25519, and chained with SHA3-256
- **Query** — results were returned because `demo-agent` holds an active consent grant for `user-1`
- **Replay** — the original payload was reconstructed from the immutable episodic ledger
- **Verify** — the entire sigchain was verified from genesis

Try removing the `add_consent_grant` call. `ingest` and `query` will both return `status="error"` with `error_code="consent_required"`. This is Barrier 3.

## Next steps

- [Installation](installation.md) — all install options including persistence and HTTP API
- [The Five Functions](../concepts/five-functions.md) — understand the full API
- [The Five Barriers](../concepts/five-barriers.md) — understand what is unconditional
- [Billing Inquiry Walkthrough](../use-cases/billing-inquiry.md) — a real end-to-end example
