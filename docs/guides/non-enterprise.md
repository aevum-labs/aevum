---
description: "Guidance by user type: developer, startup, enterprise, AI/ML engineer, compliance team, and contributor — with recommended reading paths and installs."
---

# Guide by User Type

Different teams use Aevum differently. This guide explains what each
user type needs to know.

## Individual developer / side project

**You want:** A quick, honest answer on whether Aevum is useful for your project.

**Start here:**
1. Read the [fit assessment](fit-assessment.md) — 5 minutes
2. If it's a fit, run the [quickstart](../getting-started/quickstart.md) — 10 minutes
3. Read [The Five Functions](../concepts/five-functions.md) — 15 minutes

**Minimum install:**

```bash
pip install aevum-core
```

No database required. In-memory storage is fine for prototyping.

**Typical use:** Prototyping a consent-aware AI agent. Exploring the sigchain
and replay guarantees. Evaluating whether Aevum fits a future project.

---

## Startup / small team

**You want:** Governance primitives that let you ship quickly without
building custom audit infrastructure.

**Start here:**
1. [Quickstart](../getting-started/quickstart.md) — get something running
2. [Billing Inquiry Walkthrough](../use-cases/billing-inquiry.md) — see a real pattern
3. [Building an Integration Layer](integration-layer.md) — connect your data sources
4. [Installation](../getting-started/installation.md) — add persistence when ready

**Recommended install for early production:**

```bash
pip install aevum-core aevum-store-oxigraph "aevum-core[cedar]"
```

Oxigraph gives you single-node persistence. Cedar gives you real consent
policy enforcement. No database service required.

**Typical path:**
- Start with in-memory for development
- Switch to Oxigraph for staging
- Switch to PostgreSQL for production with multiple instances

---

## Enterprise evaluation team

**You want:** A thorough technical assessment before committing to adoption.

**Start here:**
1. [Fit Assessment](fit-assessment.md)
2. [Enterprise Evaluation Package](../enterprise/overview.md)
3. [Security Architecture](../enterprise/security-architecture.md)
4. [Threat Model](../enterprise/threat-model.md)
5. [Production Deployment](../enterprise/deployment-guide.md)

**Typical questions:**

*"How does it integrate with our existing identity provider?"*
→ via `aevum-oidc`. The OIDC complication validates JWTs and maps claims
to `grantee_id` values. Your IDP issues the tokens; Aevum validates them.

*"Does it work with our PostgreSQL cluster?"*
→ Yes. `aevum-store-postgres` uses standard PostgreSQL 14+. Schema migration
is handled by `aevum store migrate`.

*"What are the data residency implications?"*
→ Aevum is self-hosted. Nothing leaves your infrastructure unless you configure
an external OPA sidecar or OIDC endpoint.

---

## AI/ML engineer

**You want:** The API details and integration patterns.

**Start here:**
1. [The Five Functions](../concepts/five-functions.md) — the complete API
2. [The Five Barriers](../concepts/five-barriers.md) — what you can't override
3. [Consent Model](../concepts/consent-model.md) — grant semantics
4. [Reference: Engine](../reference/engine.md) — full API reference

**Integration pattern:**

Aevum wraps your agent — your agent calls Aevum's five functions instead of
directly accessing data stores:

```python
# Instead of:
data = my_db.query("SELECT * FROM invoices WHERE customer_id = ?", customer_id)

# Your agent calls:
result = engine.query(
    purpose="billing-inquiry",
    subject_ids=[customer_id],
    actor="billing-agent",
)
data = result.data["results"].get(customer_id, {})
```

The agent does not change its logic — it changes where it reads data from.
Aevum intercepts, governs, and logs.

---

## Compliance / legal team

**You want:** To understand what evidence Aevum produces and how to use it.

**What Aevum provides:**
- A tamper-evident, cryptographically signed log of every AI operation
- Every operation includes: who did it, what data they accessed, under what consent
- Any past decision can be replayed to show exactly what the AI saw at decision time
- Consent grants are logged and immutable

**What Aevum does NOT provide:**
- Compliance reports (the ledger is evidence, not a report)
- Legal interpretations of regulations
- Automated regulatory submissions

**For a GDPR audit:**
1. The episodic ledger (`urn:aevum:provenance`) shows every data access
2. The consent ledger (`urn:aevum:consent`) shows every grant and revocation
3. `engine.replay(audit_id=...)` reconstructs any past AI decision exactly

**For a HIPAA audit:**
The `actor`, `purpose`, `subject_id`, and `classification` fields in every
audit event provide the access log required by the HIPAA Security Rule's
audit control standard (§164.312(b)).

---

## Open source contributor

**You want:** To understand the codebase and contribute effectively.

**Start here:**
1. [Contributing](../contributing.md)
2. `packages/aevum-core/tests/` — especially `test_canary.py` for the barriers
3. `packages/aevum-core/src/aevum/core/barriers.py` — the five absolute barriers
4. `packages/aevum-core/src/aevum/core/engine.py` — the kernel wiring

**Key invariants to preserve:**
- Absolute barriers in `barriers.py` are never relaxed or made configurable
- The `__init__.py` namespace rule (see `CLAUDE.md`)
- The five function verb naming (ingest, query, review, commit, replay)
- Apache-2.0 license for all code

See [CLAUDE.md](https://github.com/aevum-labs/aevum/blob/main/CLAUDE.md) for
the full briefing document.
