# Guide by User Type

Different teams use Aevum differently. This guide explains what each
user type needs to know.

## Individual developer / side project

**You want:** A quick, honest answer on whether Aevum is useful for
your project.

**Start here:**
1. Read the [fit assessment](../index.md#who-it-is-for) — 5 minutes
2. If it's a fit, run the [quickstart](../getting-started/quickstart.md)
   — 10 minutes
3. Read [The Five Functions](../learn/architecture.md#five-public-functions) — 15 minutes

**Minimum install:**

```bash
pip install aevum-core
```

No database required. In-memory storage is fine for prototyping.

**Typical use:** Prototyping a consent-aware AI agent. Exploring the
sigchain and verifiable decision records. Evaluating whether Aevum fits
a future project.

---

## Startup / small team

**You want:** Governance primitives that let you ship quickly without
building custom audit infrastructure.

**Start here:**
1. [Quickstart](../getting-started/quickstart.md) — get something running
2. [Billing Inquiry Walkthrough](../use-cases/billing-inquiry.md) — see
   a real pattern
3. [Building an Integration Layer](integration-layer.md) — connect your
   data sources
4. [Installation](../learn/deployment.md) — add persistence
   when ready

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

**You want:** A thorough technical assessment before committing to
adoption.

**Start here:**
1. [Fit Assessment](../index.md#who-it-is-for)
2. [Enterprise Evaluation Package](../learn/deployment.md)
3. [Security Architecture](../learn/security.md)
4. [Threat Model](../learn/security.md)
5. [Production Deployment](../learn/deployment.md)

**Typical questions:**

*"How does it integrate with our existing identity provider?"*
→ Aevum's consent grants use `grantee_id` to identify which actor is
making a request. Your application validates the token from your identity
provider using any standard JWT library, extracts the relevant claim
(typically `sub` or a custom claim), and passes it as `actor` when
calling the kernel. No Aevum-specific auth package is required.

*"Does it work with our PostgreSQL cluster?"*
→ Yes. `aevum-store-postgres` uses standard PostgreSQL 14+. Schema
migration is handled by `aevum store migrate`.

*"What are the data residency implications?"*
→ Aevum is self-hosted. Nothing leaves your infrastructure unless you
configure an external OPA sidecar or external identity provider endpoint.

*"Does Aevum make us compliant with GDPR / HIPAA / EU AI Act?"*
→ No. Aevum provides technical controls designed to support compliance
programs. Whether those controls satisfy your specific regulatory
obligations depends on your deployment, jurisdiction, and surrounding
controls. Consult qualified legal counsel.

---

## AI/ML engineer

**You want:** The API details and integration patterns.

**Start here:**
1. [The Five Functions](../learn/architecture.md#five-public-functions) — the complete API
2. [The Five Barriers](../learn/architecture.md#five-unconditional-barriers) — what you cannot
   override
3. [Consent Model](../learn/architecture.md#consent-model) — grant semantics
4. [The Sigchain](../learn/architecture.md#the-sigchain) — audit trail mechanics
5. [Integration Layer](integration-layer.md) — connecting your data
   sources

**Key integration note.** The Engine's five functions are synchronous.
If you are calling Aevum from an async Python application (FastAPI,
asyncio, etc.), use a thread executor to avoid blocking the event loop.
See [Building an Integration Layer](integration-layer.md) for the
pattern.

---

## Compliance and legal team

**You want:** To understand what evidence Aevum produces and how to use it.

**What Aevum provides:**

- A tamper-evident, signed record of every AI operation including who
  acted, what data was accessed, and under what consent grant
- Any past AI decision can be retrieved as a verified record showing
  exactly what was recorded at the time
- Every consent grant and revocation is permanently logged

**What Aevum does not provide:**

- Compliance reports — the ledger is evidence, not a report
- Legal interpretation of regulations
- Automated regulatory submissions

**For a GDPR or HIPAA audit:**

The episodic ledger (`urn:aevum:provenance`) contains every data access
with actor, purpose, subject_id, and classification. The consent ledger
(`urn:aevum:consent`) shows every grant and revocation. Both are
tamper-evident and can be exported for auditors.

See [CONTROL_MAPPING.md](https://github.com/aevum-labs/aevum/blob/main/CONTROL_MAPPING.md)
for a regulation-by-regulation mapping of what Aevum's controls address.
