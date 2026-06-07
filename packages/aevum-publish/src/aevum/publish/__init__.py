# SPDX-License-Identifier: Apache-2.0
"""
aevum.publish — Rekor v2 transparency log complication + COSE_Sign1 receipt format.

Submits chain checkpoints to an external transparency log, enabling
adversarial-resistant chain verification. Without external witnessing,
a compromised operator could silently replace the entire chain.

Requires: pip install aevum-publish[rekor]  (installs httpx)

Without httpx installed: importing succeeds, but checkpoint submission
warns and skips gracefully.

The Rekor URL is read from the AEVUM_REKOR_URL environment variable or
passed explicitly. No URL is hardcoded. See docs/deployment/rekor-self-hosted.md.

Usage:
    from aevum.publish import PublishComplication
    comp = PublishComplication(
        rekor_url="https://your-rekor-instance.example.com",  # or set AEVUM_REKOR_URL
        every_n_events=100,
        every_seconds=300,
    )
    engine.install_complication(comp)
    engine.approve_complication("aevum-publish")
    comp.on_approved(engine)  # must be called explicitly — Engine does not auto-call

COSE_Sign1 receipt format:
    from aevum.publish import AevumReceipt, ReceiptEncoder
    from aevum.core.audit.signer import InProcessSigner
    signer = InProcessSigner()
    encoder = ReceiptEncoder(signer=signer, dev_mode=True)
    receipt = AevumReceipt.from_sigchain_event(event)
    cose_bytes = encoder.encode(receipt)
"""

from aevum.publish.backends import (
    NullBackend,
    RekorV2Backend,
    ScittTsBackend,
    TransparencyBackend,
)
from aevum.publish.complication import PublishComplication
from aevum.publish.receipt import AevumReceipt, ReceiptEncoder

__version__ = "0.7.3"
__all__ = [
    "PublishComplication",
    "AevumReceipt",
    "ReceiptEncoder",
    "TransparencyBackend",
    "NullBackend",
    "RekorV2Backend",
    "ScittTsBackend",
]
