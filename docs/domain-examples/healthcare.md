---
description: "Healthcare domain: HIPAA PHI classification, FHIR R4 ingest with consent grants, care-coordination purpose scoping, and access log for HIPAA audits."
---

# Healthcare Domain Example (FHIR R4 / HIPAA)

This example shows how to configure Aevum for a healthcare context.
No additional packages are required -- this uses aevum-core primitives.

## Classification levels for PHI

Aevum's four classification levels map naturally to HIPAA data categories:

| Level | Data type | Example |
|---|---|---|
| 0 | De-identified | Aggregate statistics |
| 1 | Limited dataset | Dates, zip codes (no direct identifiers) |
| 2 | Identified PHI | Name, DOB, diagnosis |
| 3 | Sensitive PHI | Mental health, substance abuse, HIV status |

## Example: ingest a FHIR R4 Patient resource

```python
from aevum.core import Engine
from aevum.core.consent.models import ConsentGrant

engine = Engine()

# Patient has consented to care coordination queries (not research)
engine.add_consent_grant(ConsentGrant(
    grant_id="patient-42-care-coord",
    subject_id="patient/42",
    grantee_id="care-coordination-agent",
    operations=["ingest", "query"],
    purpose="care-coordination",          # Specific and auditable
    classification_max=2,                 # PHI but not sensitive PHI
    granted_at="2026-01-01T00:00:00Z",
    expires_at="2027-01-01T00:00:00Z",
    authorization_ref="HIPAA-TPO-consent-form-2026-01-01",
))

result = engine.ingest(
    data={
        "resourceType": "Patient",
        "id": "42",
        "name": [{"family": "Smith", "given": ["Alice"]}],
        "birthDate": "1980-03-15",
    },
    provenance={
        "source_id": "ehr-system",
        "chain_of_custody": ["ehr-system"],
        "classification": 2,              # Identified PHI
    },
    purpose="care-coordination",
    subject_id="patient/42",
    actor="care-coordination-agent",
)
# result.audit_id is now a permanent, signed record of this ingestion
```

## SHACL-style validation (planned for aevum-domain-healthcare)

Future domain pack will include:
- FHIR R4 SHACL shapes for structural validation
- HIPAA minimum-necessary constraint enforcement
- PHI classification inference from resource type
