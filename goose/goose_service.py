#!/usr/bin/env python3
# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Service GOOSE : point d'entrée principal (API HTTP + envoi continu)."""
from __future__ import annotations

import logging
import argparse
import pathlib
import signal
import sys
import threading

ROOT = pathlib.Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from goose61850.service import GooseService  # type: ignore[import-not-found]

log = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Démarre le service GOOSE (API HTTP + envoi continu des flux).",
    )
    parser.add_argument(
        "--host",
        default="localhost",
        help="Adresse d'écoute de l'API HTTP (défaut: localhost).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=7053,
        help="Port d'écoute de l'API HTTP (défaut: 7053).",
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    service = GooseService(host=args.host, port=args.port)
    service.start()

    stop_event = threading.Event()

    def on_signal(sig: int, frame: object) -> None:
        service.stop()
        stop_event.set()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    log.info(f"GOOSE service on http://{args.host}:{args.port} (API /api/streams, web UI /); Ctrl+C to stop")

    stop_event.wait()


if __name__ == "__main__":
    main()
