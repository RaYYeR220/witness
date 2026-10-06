"""`python -m witness_relay`: serve the relay with uvicorn (config from the environment)."""

from __future__ import annotations

import asyncio
import logging
import os
import sys

import uvicorn

from .app import create_app
from .config import RelayConfig


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("RELAY_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one INFO line per request
    cfg = RelayConfig.from_env()
    server = uvicorn.Server(
        uvicorn.Config(create_app(cfg), host=cfg.host, port=cfg.port, log_config=None)
    )
    # psycopg's async driver and aiomqtt need a selector loop; Windows defaults to Proactor.
    loop_factory = asyncio.SelectorEventLoop if sys.platform == "win32" else None
    asyncio.run(server.serve(), loop_factory=loop_factory)


if __name__ == "__main__":
    main()
