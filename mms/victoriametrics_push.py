# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Batched push of Prometheus lines to VictoriaMetrics (POST /api/v1/import/prometheus).

Lines are buffered per URL and sent at most every 200 ms, or as soon as
500 are waiting, so a burst of reports costs a few HTTP requests.
"""

from __future__ import annotations

import logging
import threading
import urllib.error
import urllib.request
from typing import Dict, List, Optional

log = logging.getLogger(__name__)

DEFAULT_BATCH_INTERVAL_SEC = 0.2
DEFAULT_BATCH_SIZE_MAX = 500


def _do_post_impl(base_url: str, lines: List[str], debug: bool = False) -> None:
    """Send lines in one HTTP request."""
    body = "\n".join(lines).encode("utf-8")
    url = base_url.rstrip("/") + "/api/v1/import/prometheus"
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "text/plain; charset=utf-8")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            code = getattr(resp, "status", 200)
            if debug:
                log.info(f"[VictoriaMetrics] pushed {len(lines)} metrics -> {code}")
    except urllib.error.HTTPError as err:
        log.warning(f"[VictoriaMetrics] push failed: HTTP {err.code} {err.reason}")
    except urllib.error.URLError as err:
        log.warning(f"[VictoriaMetrics] push failed: {err}")


class _Batcher:
    """Buffer of lines for one URL, flushed by a background thread."""

    _instances: Dict[str, "_Batcher"] = {}
    _lock = threading.Lock()

    def __init__(
        self,
        base_url: str,
        interval_sec: float = DEFAULT_BATCH_INTERVAL_SEC,
        max_lines: int = DEFAULT_BATCH_SIZE_MAX,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.interval_sec = interval_sec
        self.max_lines = max_lines
        self._buffer: List[str] = []
        self._buffer_lock = threading.Lock()
        self._flush_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._debug = False

    @classmethod
    def get(cls, base_url: str, interval_sec: float, max_lines: int) -> "_Batcher":
        with cls._lock:
            if base_url not in cls._instances:
                cls._instances[base_url] = cls(base_url, interval_sec, max_lines)
            return cls._instances[base_url]

    def add(self, lines: List[str], debug: bool = False) -> None:
        if not lines:
            return
        self._debug = self._debug or debug
        to_send: List[str] = []
        with self._buffer_lock:
            self._buffer.extend(lines)
            if len(self._buffer) >= self.max_lines:
                to_send = self._take_buffer()
        if to_send:
            _do_post_impl(self.base_url, to_send, debug=self._debug)

    def _take_buffer(self) -> List[str]:
        """Empty the buffer and return its lines (caller holds _buffer_lock)."""
        if not self._buffer:
            return []
        to_send = self._buffer[:]
        self._buffer.clear()
        return to_send

    def _run_flush_loop(self) -> None:
        while not self._stop.wait(self.interval_sec):
            self.flush()

    def ensure_started(self) -> None:
        if self._flush_thread is not None and self._flush_thread.is_alive():
            return
        self._flush_thread = threading.Thread(target=self._run_flush_loop, daemon=True)
        self._flush_thread.start()

    def flush(self) -> None:
        """Send the buffered lines now."""
        with self._buffer_lock:
            to_send = self._take_buffer()
        if to_send:
            _do_post_impl(self.base_url, to_send, debug=self._debug)


def push_lines(
    base_url: str,
    lines: List[str],
    *,
    batch_interval_sec: float = DEFAULT_BATCH_INTERVAL_SEC,
    batch_max_lines: int = DEFAULT_BATCH_SIZE_MAX,
    debug: bool = False,
) -> None:
    """Queue Prometheus lines for VictoriaMetrics (batched), or post them now if batching is off."""
    if not lines:
        return
    if batch_interval_sec <= 0:
        _do_post_impl(base_url, lines, debug)
        return
    batcher = _Batcher.get(base_url, batch_interval_sec, batch_max_lines)
    batcher.add(lines, debug=debug)
    batcher.ensure_started()
