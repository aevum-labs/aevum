---
description: "Install aevum-core, create consent grants, ingest signed data, query with purpose, replay past decisions, and verify the sigchain — in under 10 minutes."
---

# Quickstart

Get Aevum running in 10 minutes.

## Prerequisites

- Python 3.11 or higher
- `pip` (comes with Python)

Check your version:

=== "Linux / macOS"

    ```bash
    python --version
    # Python 3.11.x or higher
    ```

=== "Windows"

    ```powershell
    python --version
    # Python 3.11.x or higher
    ```

    Windows users: install Python from [python.org](https://www.python.org/downloads/)
    and tick **"Add Python to PATH"** during installation.

## Step 1 — Create a virtual environment

=== "Linux / macOS"

    ```bash
    python -m venv .venv
    source .venv/bin/activate
    ```

=== "Windows"

    ```powershell
    python -m venv .venv
    .venv\Scripts\Activate.ps1
    ```

    If you see a script execution policy error:

    ```powershell
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    .venv\Scripts\Activate.ps1
    ```

You should see `(.venv)` in your prompt.

## Step 2 — Install aevum-core

=== "Linux / macOS"

    ```bash
    pip install aevum-core
    ```

=== "Windows"

    ```powershell
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

=== "Linux / macOS"

    ```bash
    python demo.py
    ```

=== "Windows"

    ```powershell
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

## Windows-specific notes

### CLI: command not found

If `aevum` is not found after installing `aevum-cli`, use the module form:

```powershell
python -m aevum.cli --help
python -m aevum.cli version
```

To add the Scripts directory to your PATH permanently:

```powershell
$p = python -c "import sys; print(sys.exec_prefix)"
[Environment]::SetEnvironmentVariable(
    "PATH",
    [Environment]::GetEnvironmentVariable("PATH", "User") + ";$p\Scripts",
    "User"
)
```

Restart your terminal after running this.

### Long path support

Some paths inside virtualenvs can exceed 260 characters on Windows.
Enable long path support (run as Administrator):

```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
    -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
```

### WSL recommendation

For a smoother development experience on Windows, use WSL 2 (Ubuntu) and follow
the Linux instructions above inside the WSL terminal.

## Next steps

- [Architecture](/learn/architecture/) — how the governed membrane, sigchain, barriers, and consent model work
- [Security](/learn/security/) — threat model and production security architecture
- [Deployment](/learn/deployment/) — all install options including persistence and HTTP API
- [Billing Inquiry Walkthrough](../use-cases/billing-inquiry.md) — a real end-to-end example
