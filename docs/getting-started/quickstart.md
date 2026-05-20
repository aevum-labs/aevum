---
description: "Install aevum-core, set AEVUM_DEV=1, ingest signed data, and verify the sigchain — in under 5 minutes."
---

# Quickstart

Get Aevum running in 5 minutes using developer mode.

<div class="grid cards" markdown>

-   :material-clock-fast:{ .lg } **5 minutes to first sigchain entry**

    Set `AEVUM_DEV=1`, ingest data, verify the chain. No database,
    no consent configuration required.

-   :material-shield-check:{ .lg } **Production path**

    When you are ready to deploy, follow the
    [Dev to Production checklist](https://github.com/aevum-labs/aevum/blob/main/docs/learn/dev-to-production.md).

</div>

## Prerequisites

- Python 3.11 or higher
- `pip` (comes with Python)

## Step 1 — Create a virtual environment and install

=== "Linux / macOS"

    ```bash
    python -m venv .venv
    source .venv/bin/activate
    pip install aevum-core
    ```

=== "Windows"

    ```powershell
    python -m venv .venv
    .venv\Scripts\Activate.ps1
    pip install aevum-core
    ```

Verify:

```bash
python -c "import aevum.core; print('aevum-core', aevum.core.__version__)"
```

## Step 2 — Set AEVUM_DEV=1

=== "Linux / macOS"

    ```bash
    export AEVUM_DEV=1
    ```

=== "Windows (PowerShell)"

    ```powershell
    $env:AEVUM_DEV = "1"
    ```

`AEVUM_DEV=1` enables zero-config developer mode:

| Default | Production equivalent |
|---|---|
| Auto-consent (all subjects, all operations) | Explicit `ConsentGrant` per subject |
| Auto-provenance (hostname + git commit) | Application-supplied provenance |
| `NullPolicyEngine` (permit everything) | `CedarPolicyEngine` or OPA |
| `InMemoryLedger` (discarded on exit) | Oxigraph or PostgreSQL store |

!!! warning "Never use AEVUM_DEV=1 in production"
    Dev mode bypasses the consent barrier (Barrier 3). It is strictly for
    local development and learning.

## Step 3 — Write demo.py

Create `demo.py`:

```python
from aevum.core import Engine

# Engine reads AEVUM_DEV=1 and configures itself for zero-friction development.
engine = Engine()

# Ingest — every write is signed with Ed25519 and chained with SHA3-256.
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
print("audit_id:", result.audit_id)   # urn:aevum:audit:0196...
print("status:  ", result.status)     # ok

# Query — returns results; in dev mode consent is auto-granted.
q = engine.query(
    purpose="product-demo",
    subject_ids=["user-1"],
    actor="demo-agent",
)
print("results: ", list(q.data["results"].keys()))  # ['user-1']

# Replay — reconstruct any past decision deterministically.
r = engine.replay(audit_id=result.audit_id, actor="demo-agent")
print("replayed:", r.data["replayed_payload"]["note"])

# Verify — check the entire sigchain from genesis.
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

You will also see a prominent warning banner in your logs:

```
WARNING  aevum.dev:dev_mode.py - AEVUM DEVELOPER MODE ACTIVE (AEVUM_DEV=1)
```

This is intentional. It is impossible to miss, so you cannot accidentally
ship a dev-mode engine to production.

## What just happened

- **`Engine()`** — read `AEVUM_DEV=1`, configured auto-consent, auto-provenance,
  NullPolicyEngine, and InMemoryLedger. Logged the WARN banner.
- **`ingest()`** — wrote data through the governed membrane, signed the event with
  Ed25519, and chained it with SHA3-256.
- **`query()`** — returned results because dev-mode auto-consent is active.
- **`replay()`** — reconstructed the original payload from the immutable ledger.
- **`verify_sigchain()`** — walked every event from genesis, verifying both the
  SHA3-256 chain and the Ed25519 signatures.

## What happens without AEVUM_DEV=1

Unset `AEVUM_DEV` and run again:

```bash
unset AEVUM_DEV
python demo.py
```

`ingest()` and `query()` both return `status="error"` with
`error_code="consent_required"`. This is Barrier 3 — no traversal without consent.
In production you add explicit `ConsentGrant` objects before calling these functions.

## Next steps

- [Dev to Production checklist](https://github.com/aevum-labs/aevum/blob/main/docs/learn/dev-to-production.md) — 5 steps to a production deployment
- [Architecture](/learn/architecture/) — governed membrane, sigchain, barriers, consent model
- [Pure Python guide](/learn/guides/pure-python/) — a real end-to-end example without AEVUM_DEV
- [LangChain guide](/learn/guides/langchain/) — integrating Aevum with LangChain

## Windows-specific notes

### CLI: command not found

If `aevum` is not found after installing `aevum-cli`, use the module form:

```powershell
python -m aevum.cli --help
```

### Long path support

Enable long path support in Windows if virtualenv paths exceed 260 characters (run as Administrator):

```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
    -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
```

### WSL recommendation

For a smoother experience on Windows, use WSL 2 (Ubuntu) and follow the Linux
instructions above.
