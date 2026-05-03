---
description: "Billing inquiry walkthrough: consent-gated ingest, purpose-scoped query, human review gate, manager approval, and commit to the episodic ledger."
---

# Billing Inquiry Walkthrough

This walkthrough shows a complete end-to-end example using Aevum in a
customer support context: an agent answers a billing question and, with
human approval, issues a credit.

## The scenario

A customer contacts support: "Has invoice INV-001 been paid? I think I
was charged incorrectly."

A billing agent needs to:
1. Look up the invoice status
2. Answer the customer's question
3. If a credit is warranted, request manager approval before issuing it
4. Record the outcome

## The players

| Actor | Role |
|---|---|
| `billing-agent` | AI agent with query access to billing data |
| `billing-manager` | Human who approves or vetoes credits |
| `customer-42` | The data subject (the customer) |
| `billing-system` | The source system that sends invoice data to Aevum |

## Setup

```python
from aevum.core import Engine
from aevum.core.consent.models import ConsentGrant

engine = Engine()

# Customer consented to billing inquiries when they signed up
engine.add_consent_grant(ConsentGrant(
    grant_id="customer-42-billing",
    subject_id="customer-42",
    grantee_id="billing-agent",
    operations=["ingest", "query"],
    purpose="billing-inquiry",
    classification_max=1,
    granted_at="2026-01-01T00:00:00Z",
    expires_at="2027-01-01T00:00:00Z",
    authorization_ref="signup-consent-2026-01-01",
))

# Audit agent can replay decisions
engine.add_consent_grant(ConsentGrant(
    grant_id="customer-42-audit",
    subject_id="customer-42",
    grantee_id="audit-agent",
    operations=["replay"],
    purpose="billing-inquiry",
    classification_max=1,
    granted_at="2026-01-01T00:00:00Z",
    expires_at="2027-01-01T00:00:00Z",
))
```

## Part 1: The question

### Step 1 — Ingest

When the support ticket arrives, the billing system sends the invoice data
to Aevum through the governed membrane:

```python
ingest_result = engine.ingest(
    data={
        "invoice_id": "INV-001",
        "amount": 1500.00,
        "status": "paid",
        "payment_date": "2026-04-28",
        "line_items": [
            {"description": "Professional Services", "amount": 1500.00}
        ],
    },
    provenance={
        "source_id": "billing-system",
        "chain_of_custody": ["billing-system"],
        "classification": 1,
    },
    purpose="billing-inquiry",
    subject_id="customer-42",
    actor="billing-agent",
    idempotency_key="INV-001-ingest",
)

invoice_audit_id = ingest_result.audit_id
print(f"Ingested: {invoice_audit_id}")  # urn:aevum:audit:...
print(f"Status: {ingest_result.status}")  # ok
```

### Step 2 — Query

The billing agent queries the knowledge graph to retrieve the invoice status:

```python
query_result = engine.query(
    purpose="billing-inquiry",
    subject_ids=["customer-42"],
    actor="billing-agent",
    classification_max=1,
)

invoice_data = query_result.data["results"]["customer-42"]
print(f"Invoice status: {invoice_data['status']}")  # paid
```

### Step 3 — Agent response

The billing agent can now answer the customer:

> "Invoice INV-001 was paid in full on April 28, 2026. The $1,500 charge
> was for Professional Services. Is there a specific charge you believe
> was incorrect?"

## Part 2: The follow-up action

The customer replies: "The $1,500 charge is wrong — it should have been $1,350.
I have a 10% discount on Professional Services."

### Step 4 — Review gate

The billing agent cannot issue a credit autonomously. It requests manager review:

```python
review_audit_id = engine.create_review(
    proposed_action="issue_credit:INV-001:150.00",
    reason="Customer has 10% discount on Professional Services. Overcharge: $150.00",
    actor="billing-agent",
    autonomy_level=2,  # L2 — can act with human approval
    risk_assessment="Low. Standard discount application. Amount: $150.00.",
)

print(f"Review requested: {review_audit_id}")
# The operation is now pending — nothing has happened yet
```

### Step 5 — Manager approves

The billing manager reviews the context and approves:

```python
approval_result = engine.review(
    audit_id=review_audit_id,
    actor="billing-manager",
    action="approve",
)

print(f"Approval status: {approval_result.status}")  # ok
```

If the manager had vetoed, `approval_result.status` would be `"error"` and
the credit would not be issued.

### Step 6 — Action posted to financial system

After approval, the billing agent posts the credit to the financial system.
This step is **outside Aevum** — Aevum governs access, not your financial system.

```python
# Your code — calls your billing API
financial_system.post_credit(
    invoice_id="INV-001",
    amount=150.00,
    reason="Professional Services discount",
)
```

### Step 7 — Outcome committed

The billing agent records the outcome in Aevum's episodic ledger:

```python
commit_result = engine.commit(
    event_type="credit.issued",
    payload={
        "invoice_id": "INV-001",
        "credit_amount": 150.00,
        "reason": "Professional Services 10% discount",
        "approved_by": "billing-manager",
        "review_audit_id": review_audit_id,
    },
    actor="billing-agent",
    idempotency_key="credit-INV-001",
)

print(f"Committed: {commit_result.audit_id}")  # urn:aevum:audit:...
```

## The complete flow

```
billing-system              aevum-core                  billing-manager
      │                          │                              │
      │  ingest(invoice data)    │                              │
      │─────────────────────────>│                              │
      │       audit_id           │                              │
      │<─────────────────────────│                              │
      │                          │                              │
billing-agent                    │                              │
      │  query(purpose, subject) │                              │
      │─────────────────────────>│                              │
      │       results            │                              │
      │<─────────────────────────│                              │
      │                          │                              │
      │ [answer customer]        │                              │
      │                          │                              │
      │  create_review(credit)   │                              │
      │─────────────────────────>│                              │
      │       review_audit_id    │                              │
      │<─────────────────────────│                              │
      │                          │  [notification to manager]  │
      │                          │────────────────────────────>│
      │                          │  review(approve)            │
      │                          │<────────────────────────────│
      │                          │                              │
      │ [post credit to billing] │                              │
      │                          │                              │
      │  commit(credit.issued)   │                              │
      │─────────────────────────>│                              │
      │       audit_id           │                              │
      │<─────────────────────────│                              │
```

## What Aevum does vs what you build

| Aevum handles | You build |
|---|---|
| Consent enforcement | Notification to billing-manager |
| Cryptographic audit trail | Posting the credit to your financial system |
| Human review gates | The billing agent logic |
| Replay of any past decision | The customer-facing support UI |
| Sigchain verification | Integration with your billing system |

Aevum is the governed membrane. Your application provides the business logic,
the UI, and the integration with external systems.
