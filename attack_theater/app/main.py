"""Entry point: wire catalog, director, log watcher, and web server."""
import asyncio
import logging
import os
import sys
from pathlib import Path

import uvicorn

from .catalog import Catalog
from .director import Director
from .log_watcher import LogWatcher
from . import web

log = logging.getLogger("main")

DB_PATH = Path(os.environ.get("DB_PATH", "/data/theater.db"))
MMDB_PATH = Path(os.environ.get("MMDB_PATH", "/data/GeoLite2-City.mmdb"))
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))


async def _main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout,
    )

    if not os.environ.get("THEATER_PASSWORD"):
        log.warning(
            "THEATER_PASSWORD is not set — dashboard has no authentication. "
            "Set it in .env if this host is shared or the port may be forwarded."
        )

    if MMDB_PATH.exists() and MMDB_PATH.is_file():
        from . import geo
        geo.init(MMDB_PATH)
        log.info("GeoLite2 loaded: %s", MMDB_PATH)
    else:
        log.warning("GeoLite2 not found at %s — geo lookups disabled", MMDB_PATH)

    catalog = Catalog(DB_PATH)
    await catalog.init()

    director = Director(catalog, web.broadcast)
    web.setup(director, catalog)

    loop = asyncio.get_event_loop()
    event_queue: asyncio.Queue = asyncio.Queue()
    watcher = LogWatcher(event_queue, loop)
    watcher.start()

    async def _bridge() -> None:
        while True:
            event = await event_queue.get()
            director.push_event(event)

    await director.run()
    asyncio.ensure_future(_bridge())

    config = uvicorn.Config(web.app, host=HOST, port=PORT, log_level="info")
    server = uvicorn.Server(config)
    try:
        await server.serve()
    finally:
        watcher.stop()
        await catalog.close()


def main() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main()
