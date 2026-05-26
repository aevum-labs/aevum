# SPDX-License-Identifier: Apache-2.0
"""
aevum.publish — Rekor v2 transparency log complication.

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
"""

from aevum.publish.complication import PublishComplication

__version__ = "0.4.0"
__all__ = ["PublishComplication"]
