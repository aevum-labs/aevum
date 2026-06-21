# SPDX-License-Identifier: Apache-2.0
"""
aevum.spiffe — SPIFFE/SPIRE cryptographic agent identity complication.

Provides cryptographically-attested agent identity via SPIFFE JWT-SVIDs.
Emits a spiffe.attested AuditEvent when on_approved() is called. When
commitment_key_id is configured, the SPIFFE ID is bound via a v2
principal_identity commitment (not recorded raw); SVID metadata (trust
domain, audience, expiry -- not the JWT itself) is always recorded.

Requires: pip install aevum-spiffe[spiffe]  (installs py-spiffe 0.2.3+)

Without py-spiffe installed: importing this module succeeds but
SpiffeComplication.on_approved() will warn and skip gracefully.

Usage (producer):
    from aevum.spiffe import SpiffeComplication
    engine.install_complication(comp)
    engine.approve_complication("aevum-spiffe")
    comp.on_approved(engine)  # commit spiffe.attested event

Usage (verifier -- re-verifying a recorded v2 principal_binding later):
    from aevum.spiffe import SpiffeBindingVerifier

    verifier = SpiffeBindingVerifier()
    result = verifier.verify(
        {"principal_binding": event.principal_binding},
        at_time=datetime.now(UTC),
        expected_issuers=["spiffe://example.org"],
        expected_audience="aevum",
    )
    result.verified            # bool
    result.checks_performed    # e.g. ["structure", "validity_window", ...]
    result.checks_not_performed  # always names cnf/issuer-signature/token-replay
"""

from aevum.spiffe.complication import SpiffeComplication
from aevum.spiffe.verifier import SpiffeBindingVerifier

__version__ = "0.9.0"
__all__ = ["SpiffeBindingVerifier", "SpiffeComplication"]
