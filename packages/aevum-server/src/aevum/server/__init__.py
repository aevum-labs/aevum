# SPDX-License-Identifier: Apache-2.0
"""aevum.server — HTTP API server wrapping the Aevum kernel."""

from aevum.server.app import create_app

__version__ = "0.4.0"

__all__ = ["create_app"]
