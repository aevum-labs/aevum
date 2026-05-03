---
description: "Troubleshooting guide: consent_required errors, provenance_required, crisis barrier triggers, sigchain failures, OPA sidecar issues, and Windows PATH."
---

# Troubleshooting

Common errors and fixes.

## ModuleNotFoundError: No module named 'aevum.core'

The virtual environment is not active, or Aevum is not installed
in the current environment.

```bash
# Verify which Python is running
python -c "import sys; print(sys.executable)"

# Install in the current environment
pip install aevum-core

# Verify
python -c "import aevum.core; print('ok')"
```

On Linux/macOS, activate your virtual environment first:

```bash
source .venv/bin/activate
```

On Windows (PowerShell):

```powershell
.venv\Scripts\Activate.ps1
```

---

## "cedarpy not installed — consent decisions are permissive"

This is a warning, not an error. Cedar is an optional dependency.
The five absolute barriers still fire unconditionally.

To install Cedar:

```bash
pip install "aevum-core[cedar]"
```

---

## status="error", error_code="consent_required"

Your agent does not have an active consent grant for this operation.

Common causes:
- The grant does not include the operation (e.g., `"replay"` is not in the operations list)
- The grant has expired (check `expires_at`)
- The grant was revoked (check `revocation_status`)
- The `subject_id` in the call does not match the `subject_id` in the grant
- The `purpose` in the call does not match the `purpose` in the grant
- The `actor` (used as `grantee_id`) does not match the grant's `grantee_id`

```python
# Inspect the ConsentGrant object you created:
print("grantee_id:", grant.grantee_id)
print("operations:", grant.operations)
print("expires_at:", grant.expires_at)
print("purpose:   ", grant.purpose)
print("subject_id:", grant.subject_id)

# Confirm the grant is in the ledger:
print("ledger count:", engine.ledger_count())
```

---

## KeyError: 'replayed_payload' on engine.replay()

The replay call is returning `status="error"`, not `status="ok"`.
Always check `result.status` before accessing `result.data`:

```python
r = engine.replay(audit_id="urn:aevum:audit:...", actor="my-agent")
if r.status == "ok":
    print(r.data["replayed_payload"])
else:
    print("Replay failed:", r.data)
```

Common cause: the actor does not have a consent grant that includes `"replay"`
in the operations list.

---

## status="error", error_code="provenance_required"

The `provenance` dict is missing or has no `source_id`.

```python
# This fails:
engine.ingest(
    data={...},
    provenance={},  # no source_id
    ...
)

# Fix:
engine.ingest(
    data={...},
    provenance={
        "source_id": "my-system",           # required
        "chain_of_custody": ["my-system"],   # recommended
        "classification": 0,                 # required
    },
    ...
)
```

---

## status="crisis"

The ingested payload contains a crisis keyword (suicidal ideation, immediate
physical danger, medical emergency).

This is Barrier 1 firing correctly. The data was not ingested.

The `result.data["safe_message"]` and `result.data["resources"]` fields contain
text appropriate to present to the user.

If the keyword triggered incorrectly (false positive), open an issue on
[GitHub](https://github.com/aevum-labs/aevum/issues) with the specific
phrase and context.

---

## aevum: command not found (Windows)

The Python Scripts directory is not on your PATH.
Use the module form instead:

```powershell
python -m aevum.cli version
python -m aevum.cli --help
```

To fix permanently (PowerShell):

```powershell
$p = python -c "import sys; print(sys.exec_prefix)"
[Environment]::SetEnvironmentVariable(
    "PATH",
    [Environment]::GetEnvironmentVariable("PATH", "User") + ";$p\Scripts",
    "User"
)
```

Restart your terminal after running this.

---

## engine.verify_sigchain() returns False

The sigchain integrity check failed. This means either:
- A ledger entry was modified after it was written
- The Ed25519 signing key changed between events without proper key rotation

Steps to diagnose:

```python
events = engine.get_ledger_entries()
for e in events:
    print(e["sequence"], e["audit_id"], e["event_type"], e["actor"])
# The last valid event is the one before the chain breaks
```

1. Note which `audit_id` is the last valid event
2. Check whether a key rotation occurred (`signer_key_id` field)
3. If using a persistent store, check for direct database modifications
4. Open a [GitHub Issue](https://github.com/aevum-labs/aevum/issues) with
   the specific `audit_id` if you cannot identify the cause

---

## PostgreSQL: "column does not exist" or schema errors

Run the database migration:

```bash
aevum store migrate --dsn postgresql://user:password@host:5432/aevum
```

---

## OPA sidecar: all operations returning error

OPA is configured (`AEVUM_OPA_URL` is set) but not reachable.
Aevum fails closed — any OPA error results in a denial.

```bash
# Check OPA is running
curl http://your-opa-host:8181/health

# Check the policy
curl http://your-opa-host:8181/v1/data/aevum/authz/allow \
  -d '{"input": {"principal": "test", "action": "query", "resource": {}}}' \
  -H "Content-Type: application/json"
```

Expected: `{"result": true}` for a permissive policy.

If OPA is not reachable, unset `AEVUM_OPA_URL` to use Cedar only:

```bash
unset AEVUM_OPA_URL
```

---

## ValidationError: purpose must be specific

Aevum rejects generic purpose values:

```python
# These raise ValidationError:
ConsentGrant(..., purpose="any")
ConsentGrant(..., purpose="all")
ConsentGrant(..., purpose="")

# Use a specific, auditable purpose:
ConsentGrant(..., purpose="billing-inquiry")
ConsentGrant(..., purpose="care-coordination")
```

---

## Still stuck?

Open an issue on [GitHub Issues](https://github.com/aevum-labs/aevum/issues)
with:
1. The error message and traceback
2. The Python version (`python --version`)
3. The aevum-core version (`python -c "import aevum.core; print(aevum.core.__version__)"`)
4. Minimal code that reproduces the issue
