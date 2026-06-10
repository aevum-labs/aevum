# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Kernel bootstrap — Aevum's entry point.

Kernel.local() is the zero-config path:
  from aevum.core import Kernel
  kernel = Kernel.local()

This verifies principles, loads or generates signing keys,
starts the TSA client, runs behavioral canaries, and returns
a kernel ready to open sessions.
"""
from __future__ import annotations

import logging
from pathlib import Path

from aevum.core.canary import CanarySuite
from aevum.core.principles import Principles, PrinciplesVerifier
from aevum.core.signing import DualSigner
from aevum.core.tsa import DEFAULT_TSA_URLS, TSAClient

logger = logging.getLogger(__name__)

DEFAULT_STATE_DIR = Path.home() / ".aevum"
DEFAULT_PRINCIPLES_PATH = Path("signed_principles.yaml")


class Kernel:
    """
    The Aevum governed context kernel.

    Usage:
      kernel = Kernel.local()           # zero-config, local state
      kernel = Kernel.local(            # custom config
          state_dir=Path("/var/aevum"),
          principles_path=Path("/etc/aevum/signed_principles.yaml"),
          tsa_enabled=True,
      )
    """

    def __init__(
        self,
        principles: Principles,
        signer: DualSigner,
        tsa_client: TSAClient,
    ) -> None:
        self._principles = principles
        self._signer = signer
        self._tsa_client = tsa_client

    @property
    def principles(self) -> Principles:
        return self._principles

    @property
    def signer(self) -> DualSigner:
        return self._signer

    @property
    def tsa_client(self) -> TSAClient:
        return self._tsa_client

    @classmethod
    def local(
        cls,
        state_dir: Path | None = None,
        principles_path: Path | None = None,
        tsa_enabled: bool = True,
        tsa_urls: list[str] | None = None,
    ) -> Kernel:
        """
        Boot the kernel with local state.

        Steps:
          1. Verify signed_principles.yaml (halts on failure)
          2. Load or generate DualSigner keys
          3. Create TSAClient
          4. Run behavioral canary suite (halts on failure)
          5. Return ready Kernel

        Raises:
          PrinciplesError: if principles verification fails
          CanaryError: if a behavioral canary fails
        """
        _state_dir = state_dir or DEFAULT_STATE_DIR
        _principles_path = principles_path or DEFAULT_PRINCIPLES_PATH

        # Step 1: Verify principles
        logger.info("Verifying signed principles at %s", _principles_path)
        verifier = PrinciplesVerifier(_principles_path)
        principles = verifier.verify()

        # Step 2: Load or generate DualSigner (hybrid; fails closed if liboqs absent)
        keys_dir = _state_dir / "keys"
        if (keys_dir / "ed25519.key").exists():
            logger.debug("Loading existing signing keys from %s", keys_dir)
            signer = DualSigner.load(keys_dir)
        else:
            logger.info("Generating new dual signing keypair in %s", keys_dir)
            signer = DualSigner.generate()
            signer.save(keys_dir)
            logger.info(
                "New keys generated. Ed25519 pubkey: %s...",
                signer.ed25519_public_key.hex()[:16],
            )
        logger.info(
            "Signing posture: hybrid Ed25519 + ML-DSA-65 (ed25519_pub=%s...)",
            signer.ed25519_public_key.hex()[:16],
        )

        # Step 3: TSA client
        tsa_client = TSAClient(
            tsa_urls=tsa_urls or DEFAULT_TSA_URLS,
            enabled=tsa_enabled,
        )

        # Step 4: Canary suite
        kernel = cls(principles=principles, signer=signer, tsa_client=tsa_client)
        suite = CanarySuite(kernel)
        suite.run_all()

        logger.info("Kernel boot complete.")
        return kernel
