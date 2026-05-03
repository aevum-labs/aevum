---
description: "Windows quickstart: PowerShell and WSL setup, aevum-core install, consent-gated ingest and query, sigchain verification, and PATH configuration."
---

# Windows Quickstart

Get Aevum running on Windows using PowerShell, Command Prompt, or WSL.

## Prerequisites

- Python 3.11 or higher from [python.org](https://www.python.org/downloads/)
- During installation, tick **"Add Python to PATH"**

Verify in PowerShell:

```powershell
python --version
# Python 3.11.x or higher
```

## Step 1 — Create a virtual environment

=== "PowerShell"

    ```powershell
    python -m venv .venv
    .venv\Scripts\Activate.ps1
    ```

    If you see a script execution policy error:

    ```powershell
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    .venv\Scripts\Activate.ps1
    ```

=== "Command Prompt"

    ```cmd
    python -m venv .venv
    .venv\Scripts\activate.bat
    ```

=== "WSL (Ubuntu)"

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

You should see `(.venv)` in your prompt.

## Step 2 — Install aevum-core

```powershell
pip install aevum-core
```

Verify:

```powershell
python -c "import aevum.core; print('aevum-core', aevum.core.__version__)"
```

## Step 3 — Create your first script

Create a file called `demo.py`:

```python
from aevum.core import Engine
from aevum.core.consent.models import ConsentGrant

engine = Engine()

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
print("audit_id:", result.audit_id)
print("status:  ", result.status)

q = engine.query(
    purpose="product-demo",
    subject_ids=["user-1"],
    actor="demo-agent",
)
print("results: ", list(q.data["results"].keys()))

r = engine.replay(audit_id=result.audit_id, actor="demo-agent")
print("replayed:", r.data["replayed_payload"]["note"])

print("chain intact:", engine.verify_sigchain())
```

## Step 4 — Run it

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

## Step 5 — CLI (optional)

Install the CLI:

```powershell
pip install aevum-cli
```

If `aevum` is not found after install, use the module form:

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

## Windows-specific notes

### Long path support

Some paths inside virtualenvs can exceed 260 characters on Windows.
Enable long path support:

```powershell
# Run as Administrator
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
    -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
```

### Windows Defender / antivirus

Some antivirus tools slow down `pip install` significantly.
If installation takes more than 5 minutes, temporarily disable real-time
protection for the install, then re-enable it.

### WSL recommendation

For a smoother development experience on Windows, use WSL 2 (Ubuntu) and follow
the [Linux quickstart](quickstart.md) inside the WSL terminal.
