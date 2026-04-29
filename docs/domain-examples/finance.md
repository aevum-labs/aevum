# Finance Domain Example (FIBO / SOX)

## Classification levels for financial data

| Level | Data type |
|---|---|
| 0 | Public market data |
| 1 | Aggregate portfolio data |
| 2 | Individual account data |
| 3 | Insider / pre-public information |

## Example: SOX audit trail for a financial decision

```python
from aevum.core import Engine

engine = Engine()
# (Add consent grants as shown in the main README for your subjects)

result = engine.commit(
    event_type="trading.order.submitted",
    payload={
        "order_id": "ORD-2026-0042",
        "symbol": "AAPL",
        "quantity": 1000,
        "side": "buy",
        "rationale": "Quarterly rebalancing per IPS",
    },
    actor="portfolio-management-agent",
)
# result.audit_id is cryptographically signed and chain-verified
# Satisfies SOX Section 302/404 recordkeeping requirements
```

## Human-review gate for large trades

```python
# Continuing from the example above (engine already configured)
review_id = engine.create_review(
    proposed_action="Submit block order: 50,000 AAPL @ market",
    reason="Order exceeds $10M threshold requiring compliance approval",
    actor="portfolio-management-agent",
    autonomy_level=3,
    risk_assessment="high -- large block, illiquid conditions",
    deadline_iso="2026-04-29T16:00:00Z",  # Market close
)
# Veto-as-default: if no human acts before 16:00, the order is blocked
```
