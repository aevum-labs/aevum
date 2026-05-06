"""
aevum.spiffe — SPIFFE/SPIRE cryptographic agent identity complication.

Provides cryptographically-attested agent identity via SPIFFE JWT-SVIDs.
Emits a spiffe.attested AuditEvent when on_approved() is called, recording
the SPIFFE ID and SVID metadata (not the JWT itself).

Requires: pip install aevum-spiffe[spiffe]  (installs py-spiffe 0.2.3+)

Without py-spiffe installed: importing this module succeeds but
SpiffeComplication.on_approved() will warn and skip gracefully.

Usage:
    from aevum.spiffe import SpiffeComplication
    engine.install_complication(comp)
    engine.approve_complication("aevum-spiffe")
    comp.on_approved(engine)  # emit spiffe.attested event
"""

from aevum.spiffe.complication import SpiffeComplication

__version__ = "0.1.0"
__all__ = ["SpiffeComplication"]
