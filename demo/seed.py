"""
Seed a fresh Engine session with consent grants.

Grants:
  demo-agent   ingest, query, replay, export on user-demo
               purposes: billing-inquiry, compliance-audit
  intruder-agent  NO grants (demonstrates Barrier 3 in Scenario B)

Note: demo-human performs review approve/veto actions. The review() function
does not check consent (barriers spec), so no grant is needed for demo-human.

Scenario C uses engine.create_review() at request time, not at seed time.
"""

from __future__ import annotations

from aevum.core import Engine
from aevum.core.consent.models import ConsentGrant


_DEMO_OPS = ["ingest", "query", "replay", "export"]
_EXPIRES  = "2030-01-01T00:00:00Z"
_GRANTED  = "2026-01-01T00:00:00Z"


def seed_engine(engine: Engine) -> None:
    for purpose in ("billing-inquiry", "compliance-audit"):
        engine.add_consent_grant(ConsentGrant(
            grant_id=f"seed-agent-{purpose}",
            subject_id="user-demo",
            grantee_id="demo-agent",
            operations=_DEMO_OPS,
            purpose=purpose,
            classification_max=1,
            granted_at=_GRANTED,
            expires_at=_EXPIRES,
        ))
    # intruder-agent: intentionally no grant — demonstrates Barrier 3 (Consent)
    # demo-human: no grant needed — review() does not check consent
