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
import os
from pathlib import Path

from aevum.core.audit.sigchain import Sigchain
from aevum.core.audit.signer import Signer
from aevum.core.canary import CanarySuite
from aevum.core.principles import Principles, PrinciplesVerifier
from aevum.core.signing import DualSigner, load_or_generate_ed25519_signer
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
        signer: DualSigner | Signer,
        tsa_client: TSAClient,
    ) -> None:
        self._principles = principles
        self._signer = signer
        self._tsa_client = tsa_client
        if isinstance(signer, DualSigner):
            # Hybrid: persisted Ed25519 primary + ML-DSA-65 dual signature.
            self._sigchain = Sigchain(
                signer=signer.as_primary_signer(),
                dual_signer=signer,
                tsa_client=tsa_client,
            )
        else:
            # Classical-only: Ed25519 primary, no post-quantum dual signature.
            self._sigchain = Sigchain(
                signer=signer,
                dual_signer=None,
                tsa_client=tsa_client,
            )

    @property
    def principles(self) -> Principles:
        return self._principles

    @property
    def signer(self) -> DualSigner | Signer:
        return self._signer

    @property
    def tsa_client(self) -> TSAClient:
        return self._tsa_client

    @property
    def signing_posture(self) -> str:
        """Active signing posture: "hybrid" or "classical-only"."""
        return "hybrid" if isinstance(self._signer, DualSigner) else "classical-only"

    @property
    def sigchain(self) -> Sigchain:
        """The kernel's canonical append-only sigchain backed by the persisted Ed25519 key."""
        return self._sigchain

    def engine(self, **kwargs: object) -> object:
        """Create an Engine wired to this kernel's canonical sigchain.

        All keyword arguments are forwarded to Engine(). The sigchain= parameter is
        pre-filled with kernel.sigchain; signing_posture= is pre-filled from the kernel's
        active posture. Passing either explicitly raises TypeError.
        """
        from aevum.core.engine import Engine  # local import avoids circular dependency
        return Engine(sigchain=self._sigchain, signing_posture=self.signing_posture, **kwargs)  # type: ignore[arg-type]

    @classmethod
    def local(
        cls,
        state_dir: Path | None = None,
        principles_path: Path | None = None,
        tsa_enabled: bool = True,
        tsa_urls: list[str] | None = None,
        posture: str | None = None,
    ) -> Kernel:
        """
        Boot the kernel with local state.

        Steps:
          1. Verify signed_principles.yaml (halts on failure)
          2. Load or generate signing keys per posture
          3. Create TSAClient
          4. Run behavioral canary suite (halts on failure)
          5. Return ready Kernel

        Args:
          posture: "hybrid" (default) or "classical-only". Overrides
                   AEVUM_SIGNING_POSTURE env var when set. "classical-only"
                   is a degraded posture — it must be explicitly opted into
                   and is loudly logged. Default is hybrid (fail-closed).

        Raises:
          PrinciplesError: if principles verification fails
          CanaryError: if a behavioral canary fails
          SignerUnavailableError: if hybrid posture and liboqs is absent
        """
        _state_dir = state_dir or DEFAULT_STATE_DIR
        _principles_path = principles_path or DEFAULT_PRINCIPLES_PATH
        _posture = posture or os.environ.get("AEVUM_SIGNING_POSTURE", "hybrid")

        # Step 1: Verify principles
        logger.info("Verifying signed principles at %s", _principles_path)
        verifier = PrinciplesVerifier(_principles_path)
        principles = verifier.verify()

        # Step 2: Load or generate signing keys according to posture
        keys_dir = _state_dir / "keys"
        _signer: DualSigner | Signer
        if _posture == "classical-only":
            logger.warning(
                "Signing posture: CLASSICAL-ONLY (Ed25519, NO post-quantum protection) — "
                "explicitly opted in via AEVUM_SIGNING_POSTURE=classical-only. "
                "Entries will not carry ML-DSA-65 signatures."
            )
            _signer = load_or_generate_ed25519_signer(keys_dir)
            logger.info(
                "Signing posture: classical Ed25519 (ed25519_pub=%s...)",
                _signer.public_key_bytes().hex()[:16],
            )
        else:
            # Default: hybrid (fail-closed if liboqs absent — P1 invariant preserved)
            if (keys_dir / "ed25519.key").exists():
                logger.debug("Loading existing signing keys from %s", keys_dir)
                _signer = DualSigner.load(keys_dir)
            else:
                logger.info("Generating new dual signing keypair in %s", keys_dir)
                _signer = DualSigner.generate()
                _signer.save(keys_dir)
                logger.info(
                    "New keys generated. Ed25519 pubkey: %s...",
                    _signer.ed25519_public_key.hex()[:16],
                )
            logger.info(
                "Signing posture: hybrid Ed25519 + ML-DSA-65 (ed25519_pub=%s...)",
                _signer.ed25519_public_key.hex()[:16],
            )

        # Step 3: TSA client
        tsa_client = TSAClient(
            tsa_urls=tsa_urls or DEFAULT_TSA_URLS,
            enabled=tsa_enabled,
        )

        # Step 4: Canary suite
        kernel = cls(principles=principles, signer=_signer, tsa_client=tsa_client)
        suite = CanarySuite(kernel)
        suite.run_all()

        logger.info("Kernel boot complete.")
        return kernel
