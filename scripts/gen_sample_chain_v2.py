# SPDX-License-Identifier: Apache-2.0
"""Generate the synthetic 'verify it yourself' sample sigchain for the public
v2 (principal-binding) demo — a single chain spanning sig_format_version
1 then 2 (DD4 per-entry dispatch, spec aevum-signing-v2.md).

Run ONCE; commit the emitted sample-chain-v2.json + sample-chain-v2-pub.hex.
Contains NO real data — every payload is flagged synthetic, and every
principal_identity/claims value is synthetic too. The Ed25519 signing key
and the commitment key are both ephemeral and discarded; only the Ed25519
PUBLIC key is written (DD6: chain verification never needs the commitment
key — only identity-matching does, and this demo performs none). Re-run
only if the sigchain export schema changes (tests/test_sample_chain_v2_verifies.py
will fail and tell you). Re-running rotates the sample and the signing
key — commit them together.
"""
from __future__ import annotations

from pathlib import Path

from aevum.core.audit.commitment_key_store import CommitmentKeyStore
from aevum.core.audit.sigchain import Sigchain
from aevum.verify._core import dump_chain

OUT = Path("demo/public")
SAMPLE = OUT / "sample-chain-v2.json"
PUBKEY = OUT / "sample-chain-v2-pub.hex"


def main() -> None:
    chain = Sigchain()
    store = CommitmentKeyStore()
    key_id = store.create_key(scope="demo-deployment")
    key = store.get_key(key_id)
    assert key is not None

    events = []

    # --- sig_format_version 1: same shape as the v1 public demo, no principal
    # binding at all. ---
    events.append(chain.new_event(
        event_type="consent.granted",
        payload={"subject": "DEMO-0001", "purpose": "account_review", "synthetic": True},
        actor="aevum-demo",
    ))
    events.append(chain.new_event(
        event_type="agent.tool_call",
        payload={"tool": "ledger.read", "subject": "DEMO-0001", "synthetic": True},
        actor="aevum-demo",
    ))

    # --- sig_format_version 2: the same chain now opts into principal-binding
    # (DD2-DD7). The bound credential identity is a synthetic OIDC sub —
    # never the same as actor, and never written to the chain in the clear
    # (only its HMAC commitment and an allow-listed claim blob are signed). ---
    events.append(chain.new_event(
        event_type="agent.decision",
        payload={"decision": "approve", "amount_usd": 2500, "synthetic": True},
        actor="aevum-demo",
        principal_identity="urn:demo:oidc:sub:DEMO-0001-synthetic",
        principal_claims={
            "iss": "https://idp.demo.aevum.build",
            "aud": "aevum-demo",
            "jti": "demo-jti-0001",
            "iat": 1750000000,
            "exp": 1750003600,
            # Included to demonstrate the allow-list strips it — 'sub' must
            # never appear in the signed principal_binding blob (DD7).
            "sub": "urn:demo:oidc:sub:DEMO-0001-synthetic",
        },
        commitment_key_id=key_id,
        commitment_key=key,
    ))
    events.append(chain.new_event(
        event_type="human.checkpoint",
        payload={"reviewer": "demo-officer", "outcome": "approved", "synthetic": True},
        actor="aevum-demo",
        principal_identity="urn:demo:oidc:sub:demo-officer-synthetic",
        principal_claims={
            "iss": "https://idp.demo.aevum.build",
            "aud": "aevum-demo",
            "jti": "demo-jti-0002",
        },
        commitment_key_id=key_id,
        commitment_key=key,
    ))
    # A v2 entry with no external credential to bind — principal_binding and
    # principal_commitment stay null even on a sig_format_version=2 entry
    # (DD2: the three fields are nullable even within v2). sig_format_version
    # must never DECREASE (DD4), so once the chain has moved to v2 every
    # subsequent entry — including this one — stays at v2.
    events.append(chain.new_event(
        event_type="audit.sealed",
        payload={"note": "synthetic demo session — not real data", "synthetic": True},
        actor="aevum-demo",
        commitment_key_id=key_id,
    ))

    OUT.mkdir(parents=True, exist_ok=True)
    dump_chain(events, SAMPLE)
    pub_hex = chain._signer.public_key_bytes().hex()
    PUBKEY.write_text(pub_hex + "\n")
    print(f"wrote {SAMPLE} ({len(events)} events)")
    print(f"versions: {[e.sig_format_version for e in events]}")
    print(f"wrote {PUBKEY}")
    print(f"PINNED ED25519 PUBKEY: {pub_hex}")
    print("(commitment key discarded — DD6: chain verification never needs it)")


if __name__ == "__main__":
    main()
