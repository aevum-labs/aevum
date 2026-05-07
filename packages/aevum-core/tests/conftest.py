"""pytest configuration for aevum-core test suite."""
from __future__ import annotations

import logging


def pytest_configure(config: object) -> None:  # noqa: ARG001
    """
    Suppress the cedarpy-not-installed warning during tests.

    cedarpy is an optional runtime dependency — consent falls back to
    permissive when absent. Tests verify barrier behaviour and sigchain
    integrity; Cedar policy evaluation is tested separately via
    packages/aevum-core/policies/. The warning is correct for production
    but is noise in the test suite where Cedar is intentionally absent.
    """
    logging.getLogger("aevum.core.policy.bridge").setLevel(logging.ERROR)
