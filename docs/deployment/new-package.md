# How to Register a New PyPI Package Before Releasing

When a new package is added to `packages/` it must be registered on PyPI
**before** the release workflow runs. Trusted Publishing cannot create new
projects — it can only publish to projects that already exist.

The release workflow's "Verify PyPI registration" step will fail fast with a
clear error if any package is missing, so an unregistered package will never
block a partially-completed publish.

---

## Why This Step Exists

PyPI's confirmed Trusted Publishing publisher (the one configured in
`release.yml`) can publish new **versions** of existing projects, but it
**cannot create new projects**. A pending publisher CAN create a new project
on first push. This guide uses the pending-publisher approach for the initial
registration only; subsequent releases use the confirmed publisher as normal.

---

## Steps

### 1. Create a pending publisher on PyPI

1. Go to [pypi.org](https://pypi.org) and log in as `aevum-labs`.
2. Navigate to **Your projects → Publishing → Add a new pending publisher**.
3. Fill in the form:

   | Field            | Value                          |
   |------------------|--------------------------------|
   | PyPI project name | `{new-package-name}` (e.g. `aevum-spiffe`) |
   | Owner            | `aevum-labs`                   |
   | Repository name  | `aevum`                        |
   | Workflow name    | `release.yml`                  |
   | Environment name | `release`                      |

4. Click **Add**.

### 2. Run the release workflow

Tag the release as normal (`git tag vX.Y.Z && git push origin vX.Y.Z`).

On the **first** publish of the new package, PyPI converts the pending
publisher into a confirmed publisher and creates the project automatically.
Subsequent releases use the confirmed publisher.

### 3. Verify

After the workflow completes, confirm the package appears at
`https://pypi.org/project/{new-package-name}/`.

---

## Manual pre-flight check (optional)

Before tagging, you can verify locally that all packages exist:

```bash
for pkg in packages/aevum-*/pyproject.toml; do
  name=$(grep '^name' "$pkg" | cut -d'"' -f2)
  curl -sf "https://pypi.org/pypi/$name/json" > /dev/null \
    || echo "NOT ON PYPI: $name"
done
```

Any `NOT ON PYPI` result must be resolved before tagging.
See step 1 above to register the missing package.

---

## Private packages

`aevum-maintainer` is excluded from the dist directory before publishing
and is intentionally never registered on PyPI. The pre-flight check skips it.
