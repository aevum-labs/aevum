# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
SigningConfig — Rekor URL resolution without hardcoded production URLs.

The URL is resolved (in order) from:
1. The ``rekor_url`` constructor argument
2. The ``AEVUM_REKOR_URL`` environment variable
3. ``None`` — Rekor anchoring disabled (RekorAnchor will not submit)

This mirrors the TUF SigningConfig pattern used by sigstore-python:
configuration lives outside source, never baked into the binary.

Production deployments must configure AEVUM_REKOR_URL. The default is
intentionally absent so that deployments without a configured endpoint
do not silently submit to any public log.
"""
from __future__ import annotations

import os


class SigningConfig:
    """Rekor URL provider. Reads AEVUM_REKOR_URL; no hardcoded URL."""

    def __init__(self, rekor_url: str | None = None) -> None:
        self.rekor_url: str | None = rekor_url or os.environ.get("AEVUM_REKOR_URL")

    @classmethod
    def from_env(cls) -> SigningConfig:
        return cls()

    def is_configured(self) -> bool:
        return self.rekor_url is not None
