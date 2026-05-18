# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for aevum-maintainer tests."""
from __future__ import annotations

import pytest
from aevum.core.engine import Engine
from aevum_maintainer.server import create_app
from fastapi.testclient import TestClient


@pytest.fixture
def engine() -> Engine:
    return Engine()


@pytest.fixture
def client(engine: Engine) -> TestClient:
    app = create_app(engine=engine)
    return TestClient(app, raise_server_exceptions=False)
