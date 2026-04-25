"""
python -m aevum.server — development convenience entrypoint.

Starts aevum-server with an in-memory Engine and default settings.
NOT for production. Production operators use:
  uvicorn aevum.server.app:create_app --factory
  gunicorn aevum.server.app:create_app -k uvicorn.workers.UvicornWorker

Configuration via environment variables (see aevum/server/core/config.py).
Full CLI with config management arrives in Phase 5 (aevum-cli).
"""

import uvicorn
from aevum.core.engine import Engine

from aevum.server.app import create_app
from aevum.server.core.config import Settings


def main() -> None:
    settings = Settings()
    engine = Engine(opa_url=settings.opa_url or None)
    app = create_app(engine, settings=settings)
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
