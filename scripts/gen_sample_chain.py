# SPDX-License-Identifier: Apache-2.0
"""Generate the synthetic 'verify it yourself' sample sigchain for the public demo.

Run ONCE; commit the emitted sample-chain.json + sample-ed25519-pub.hex.
Contains NO real data — every payload is flagged synthetic. The signing key is
ephemeral and discarded; only its PUBLIC key is written. Re-run only if the
sigchain export schema changes (tests/test_sample_chain_verifies.py will fail
and tell you). Re-running rotates BOTH the sample and the key — commit them
together.
"""
from __future__ import annotations

from pathlib import Path

from aevum.core.audit.sigchain import Sigchain
from aevum.verify._core import dump_chain

OUT = Path("demo/public")
SAMPLE = OUT / "sample-chain.json"
PUBKEY = OUT / "sample-ed25519-pub.hex"

# Clearly-synthetic, compliance-flavored events (financial-services demo).
EVENTS = [
    ("consent.granted",  {"subject": "DEMO-0001", "purpose": "account_review", "synthetic": True}),
    ("agent.tool_call",  {"tool": "ledger.read", "subject": "DEMO-0001", "synthetic": True}),
    ("agent.decision",   {"decision": "approve", "amount_usd": 2500, "synthetic": True}),
    ("human.checkpoint", {"reviewer": "demo-officer", "outcome": "approved", "synthetic": True}),
    ("audit.sealed",     {"note": "synthetic demo session — not real data", "synthetic": True}),
]


def main() -> None:
    chain = Sigchain()
    events = [chain.new_event(event_type=t, payload=p, actor="aevum-demo") for t, p in EVENTS]
    OUT.mkdir(parents=True, exist_ok=True)
    dump_chain(events, SAMPLE)
    pub_hex = chain._signer.public_key_bytes().hex()
    PUBKEY.write_text(pub_hex + "\n")
    print(f"wrote {SAMPLE} ({len(events)} events)")
    print(f"wrote {PUBKEY}")
    print(f"PINNED ED25519 PUBKEY: {pub_hex}")


if __name__ == "__main__":
    main()
