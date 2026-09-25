# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Logging setup of the po services.

:func:`setup` sends every record to stdout (journalctl adds the time) and
keeps the last :data:`LOG_MAX` lines in memory for the log panel of the web
UI (``GET /api/mms/logs``, server-sent events). Modules only call
``logging.getLogger(__name__)``; the iec61850 library configures nothing.
"""

from __future__ import annotations

import logging
import os
import sys
import threading

LOG_MAX = 500
FORMAT = "%(levelname)s %(name)s: %(message)s"

LOG_LINES: list[tuple[int, str]] = []  # (seq, line), seq increasing
LOG_LOCK = threading.Lock()
LOG_CONDITION = threading.Condition(LOG_LOCK)
_next_seq = 0


class UiLogHandler(logging.Handler):
    """Keeps the last lines for the UI, one entry per line of the message."""

    def emit(self, record: logging.LogRecord) -> None:
        global _next_seq
        try:
            text = self.format(record)
        except Exception:  # noqa: BLE001 - logging must not raise
            self.handleError(record)
            return
        with LOG_LOCK:
            for line in text.split("\n"):
                _next_seq += 1
                LOG_LINES.append((_next_seq, line))
            del LOG_LINES[:-LOG_MAX]
            LOG_CONDITION.notify_all()


def _ui_format(record: logging.LogRecord) -> str:
    message = record.getMessage()
    if record.exc_info:
        message += "\n" + logging.Formatter().formatException(record.exc_info)
    return message if record.levelno == logging.INFO else f"{record.levelname}: {message}"


class _UiFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return _ui_format(record)


def setup(level: str | int | None = None) -> None:
    """Configure the root logger once; ``level`` defaults to $PO_LOG_LEVEL or INFO."""
    root = logging.getLogger()
    if any(isinstance(h, UiLogHandler) for h in root.handlers):
        return
    level = level or os.environ.get("PO_LOG_LEVEL", "INFO")
    root.setLevel(level.upper() if isinstance(level, str) else level)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter(FORMAT))
    ui = UiLogHandler()
    ui.setFormatter(_UiFormatter())
    root.addHandler(console)
    root.addHandler(ui)
    # Flask's development server logs every request at INFO.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
