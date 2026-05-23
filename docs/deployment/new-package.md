# How to Register a New PyPI Package Before Releasing

When a new package is added to `packages/` it needs a PyPI registration before
the release workflow can publish it. A **pending publisher** is sufficient —
the pre-flight check will warn but not block, and the first upload creates the
project automatically. You do not need a confirmed publisher or an existing
project page before tagging the release.

The release workflow's "Verify PyPI registration" step logs a WARNING for any
404 package and continues. The publish step then attempts the upload; if no
publisher (pending or confirmed) exists, that step will fail with a clear auth
error. With `skip-existing: true` set, a partial publish is recoverable — only
the missing package needs to be re-registered and re-released.

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

Before tagging, you can check which packages already exist on PyPI:

```bash
for pkg in packages/aevum-*/pyproject.toml; do
  name=$(grep '^name' "$pkg" | cut -d'"' -f2)
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://pypi.org/pypi/$name/json")
  if [[ "$status" == "200" ]]; then
    echo "OK: $name"
  else
    echo "WARNING (HTTP $status): $name — ensure a pending publisher is registered"
  fi
done
```

A WARNING result is fine as long as a pending publisher is registered on PyPI
(see step 1 above). The first upload converts it to a confirmed publisher and
creates the project page. Only worry if no publisher of any kind exists.

---

## Private packages

`aevum-maintainer` is excluded from the dist directory before publishing
and is intentionally never registered on PyPI. The pre-flight check skips it.
