"""`python -m witness_api`: serve the API with uvicorn (configuration from WITNESS_*)."""

from __future__ import annotations

import asyncio
import logging
import os
import sys

import uvicorn

from .app import create_app
from .settings import Settings


def main() -> int:
    level = os.environ.get("WITNESS_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        settings = Settings.from_env()
    except ValueError as e:
        print(f"witness-api: {e}", file=sys.stderr)
        return 2
    app = create_app(settings)
    config = uvicorn.Config(app, host=settings.host, port=settings.port, loop="none",
                            log_level=level.lower(), proxy_headers=False,
                            server_header=False)
    server = uvicorn.Server(config)
    # psycopg's async driver needs a selector loop; Windows defaults to the proactor loop.
    factory = asyncio.SelectorEventLoop if sys.platform == "win32" else None
    with asyncio.Runner(loop_factory=factory) as runner:
        try:
            runner.run(server.serve())
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
