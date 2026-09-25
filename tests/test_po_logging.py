# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""po_logging: the lines kept for the log panel of the web UI."""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest

import po_logging


@pytest.fixture
def ui_logger() -> Iterator[logging.Logger]:
    logger = logging.getLogger("test.po_logging")
    handler = po_logging.UiLogHandler()
    handler.setFormatter(po_logging._UiFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    saved = list(po_logging.LOG_LINES)
    po_logging.LOG_LINES.clear()
    yield logger
    logger.removeHandler(handler)
    po_logging.LOG_LINES[:] = saved


def _lines() -> list[str]:
    return [line for _, line in po_logging.LOG_LINES]


def test_ui_lines(ui_logger: logging.Logger) -> None:
    ui_logger.info("[Stream s1] 3 RCB enabled")
    ui_logger.warning("[Stream s1] Connection closed")
    ui_logger.info("REPORT A\n  member 1")
    assert _lines() == ["[Stream s1] 3 RCB enabled", "WARNING: [Stream s1] Connection closed", "REPORT A", "  member 1"]
    seqs = [seq for seq, _ in po_logging.LOG_LINES]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


def test_ui_lines_keep_the_last_ones(ui_logger: logging.Logger) -> None:
    for i in range(po_logging.LOG_MAX + 10):
        ui_logger.info(f"line {i}")
    assert len(po_logging.LOG_LINES) == po_logging.LOG_MAX
    assert _lines()[-1] == f"line {po_logging.LOG_MAX + 9}"


def test_exceptions_reach_the_ui(ui_logger: logging.Logger) -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        ui_logger.exception("[processbus] SV handler")
    lines = _lines()
    assert lines[0] == "ERROR: [processbus] SV handler" and lines[-1] == "ValueError: boom"
