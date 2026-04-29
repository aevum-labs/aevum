# Legal Domain Example (GDPR)

## GDPR Article 17: Right to Erasure

Aevum's consent revocation is immediate and propagates to all derived context.

```python
# User exercises right to erasure
engine.revoke_consent_grant("user-99-analytics-consent")

# All subsequent queries for user-99 are now blocked (Barrier 3)
result = engine.query(
    purpose="analytics",
    subject_ids=["user/99"],
    actor="analytics-agent",
)
assert result.status == "error"
assert result.data["error_code"] == "consent_required"
# The revocation is recorded in the sigchain -- provable in regulatory audit
```

## GDPR Article 30: Records of Processing Activities

Every ingest and query is automatically logged to the episodic ledger
with: actor, subject, purpose, timestamp, classification level, and
a hash-chain linking every event. This log satisfies Article 30
recordkeeping requirements without additional configuration.
