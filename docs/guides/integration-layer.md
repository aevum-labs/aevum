# Building an Integration Layer

Aevum governs access to context. It does not move data between your systems.
Your integration layer is the code that bridges your data sources and Aevum's
governed membrane.

## What the integration layer is

```
Your data sources                  Aevum
  ┌──────────────┐                ┌─────────────────────┐
  │ Billing DB   │─── ingest ────>│  governed membrane  │
  │ CRM          │─── ingest ────>│  knowledge graph    │
  │ ERP          │─── ingest ────>│  episodic ledger    │
  └──────────────┘                └─────────────────────┘
                                           │
                                        query
                                           │
                                  ┌────────▼────────┐
                                  │   Your agent    │
                                  └─────────────────┘
```

The integration layer is the code that:
1. Reads from your data sources
2. Calls `engine.ingest()` with proper provenance and classification
3. Handles the `OutputEnvelope` response

You build this. Aevum governs it.

## Option A: Direct Python (simplest)

Write a Python function that reads from your source and ingests to Aevum:

```python
import psycopg2
from aevum.core import Engine
from aevum.core.consent.models import ConsentGrant

engine = Engine()

def sync_invoice(invoice_id: str, customer_id: str) -> None:
    """Read an invoice from billing DB and ingest to Aevum."""
    conn = psycopg2.connect(dsn="postgresql://billing-db/invoices")
    cur = conn.cursor()
    cur.execute("SELECT * FROM invoices WHERE id = %s", (invoice_id,))
    row = cur.fetchone()

    result = engine.ingest(
        data={
            "invoice_id": row["id"],
            "amount": float(row["amount"]),
            "status": row["status"],
            "payment_date": row["payment_date"].isoformat() if row["payment_date"] else None,
        },
        provenance={
            "source_id": "billing-db",
            "chain_of_custody": ["billing-db"],
            "classification": 1,
        },
        purpose="billing-inquiry",
        subject_id=customer_id,
        actor="sync-job",
        idempotency_key=f"invoice-{invoice_id}",
    )

    if result.status != "ok":
        raise RuntimeError(f"Ingest failed: {result.data}")
```

Call this from a cron job, a webhook handler, or wherever your data changes.

## Option B: Aevum Complication (native integration)

For tighter integration, build a complication using `aevum-sdk`:

```python
from aevum.sdk import AgentComplication

class BillingComplication(AgentComplication):
    def manifest(self):
        return {
            "name": "billing-connector",
            "version": "1.0.0",
            "capabilities": ["billing.ingest", "billing.sync"],
        }

    def on_event(self, event_type: str, payload: dict) -> None:
        if event_type == "invoice.updated":
            self._sync_invoice(payload["invoice_id"], payload["customer_id"])

    def _sync_invoice(self, invoice_id: str, customer_id: str) -> None:
        # ... your sync logic ...
        pass
```

Complications go through Aevum's 7-state lifecycle (DISCOVERED → PENDING →
APPROVED → ACTIVE → ...) and are themselves logged in the episodic ledger.

Use Option B when: the integration needs to be governed, versioned, and
auditable as a first-class part of your Aevum deployment.

## Option C: Message Queue (enterprise scale)

For high-volume or multi-system integrations, use a message queue:

```
Billing system ──> Kafka topic "invoices" ──> Aevum ingest consumer
CRM            ──> Kafka topic "customers" ──> Aevum ingest consumer
ERP            ──> Kafka topic "contracts" ──> Aevum ingest consumer
```

```python
from kafka import KafkaConsumer
import json

consumer = KafkaConsumer(
    "invoices",
    bootstrap_servers=["kafka:9092"],
    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
)

for message in consumer:
    invoice = message.value
    engine.ingest(
        data=invoice,
        provenance={
            "source_id": "billing-system",
            "chain_of_custody": ["billing-system", "kafka"],
            "classification": 1,
        },
        purpose="billing-inquiry",
        subject_id=invoice["customer_id"],
        actor="ingest-consumer",
        idempotency_key=f"invoice-{invoice['id']}-{message.offset}",
    )
```

The `chain_of_custody` list records every system the data passed through
before reaching Aevum, satisfying Barrier 5 (Provenance).

## A complete example: billing use case fully wired

```python
from aevum.core import Engine
from aevum.core.consent.models import ConsentGrant

# Setup
engine = Engine()

def setup_customer_consent(customer_id: str, consent_ref: str) -> None:
    engine.add_consent_grant(ConsentGrant(
        grant_id=f"customer-{customer_id}-billing",
        subject_id=customer_id,
        grantee_id="billing-agent",
        operations=["ingest", "query"],
        purpose="billing-inquiry",
        classification_max=1,
        granted_at="2026-01-01T00:00:00Z",
        expires_at="2027-01-01T00:00:00Z",
        authorization_ref=consent_ref,
    ))

def handle_invoice_event(invoice: dict) -> None:
    """Called by your webhook handler or message consumer."""
    customer_id = invoice["customer_id"]

    result = engine.ingest(
        data=invoice,
        provenance={
            "source_id": "billing-system",
            "chain_of_custody": ["billing-system"],
            "classification": 1,
        },
        purpose="billing-inquiry",
        subject_id=customer_id,
        actor="webhook-handler",
        idempotency_key=f"invoice-{invoice['id']}",
    )
    return result.audit_id

def handle_support_inquiry(customer_id: str, agent_id: str) -> dict:
    """Called by your support agent."""
    result = engine.query(
        purpose="billing-inquiry",
        subject_ids=[customer_id],
        actor=agent_id,
        classification_max=1,
    )
    if result.status == "ok":
        return result.data["results"].get(customer_id, {})
    return {}
```

## The webhook: how Aevum talks back

Aevum can notify your systems when reviews are approved or vetoed:

```python
engine.register_webhook(
    webhook_id="billing-webhooks",
    url="https://your-system.internal/aevum-events",
    secret="your-hmac-secret",
    events=["review.approved", "review.vetoed"],
)
```

Your webhook handler receives HMAC-signed POST requests. Verify the
signature before processing.

## What Aevum does vs what you build

| Aevum handles | You build |
|---|---|
| Consent enforcement | Data source connectors (DB queries, API calls) |
| Sigchain and audit | Webhook handler or message consumer |
| Human review gates | Notification to reviewers |
| Classification ceilings | Posting outcomes to external systems |
| Replay and verification | Agent logic and UI |

## Technology stack summary

| Layer | Technology |
|---|---|
| Kernel | aevum-core |
| Persistence | aevum-store-oxigraph (dev) or aevum-store-postgres (prod) |
| HTTP API | aevum-server (FastAPI) |
| MCP tools | aevum-mcp |
| Policy | Cedar in-process + OPA HTTP sidecar (optional) |
| Identity | aevum-oidc (optional) |
| Your integration | Python, your message queue, your DB client |
