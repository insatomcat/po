# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import binascii
import queue
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple, Union

from open61850 import ethernet

from .codec import decode_goose_pdu, encode_goose_pdu
from .types import GooseFrame, GoosePDU

log = logging.getLogger(__name__)


GOOSE_ETHERTYPE = 0x88B8
_QUEUE_MAX = 50_000
_CAPTURE_TIMEOUT_S = 0.05
_CAPTURE_BUFFER_BYTES = 4 * 1024 * 1024


def nic_rx_stats(iface: str) -> Dict[str, int]:
    """Kernel RX counters (/sys/class/net/...): losses before the capture socket."""
    base = Path("/sys/class/net") / iface / "statistics"
    out: Dict[str, int] = {}
    for name in ("rx_missed_errors", "rx_dropped", "rx_errors", "rx_fifo_errors"):
        path = base / name
        if not path.is_file():
            continue
        try:
            out[name] = int(path.read_text().strip())
        except (OSError, ValueError):
            continue
    return out


def parse_ethernet_goose(raw: bytes) -> Optional[Tuple[str, str, int, Optional[int], int, bytes]]:
    """Parse a raw Ethernet frame into (dst, src, app_id, vlan_id, ethertype, apdu)."""
    frame = ethernet.parse_frame(raw, (GOOSE_ETHERTYPE,))
    if frame is None:
        return None
    return frame.dst_mac, frame.src_mac, frame.app_id, frame.vlan_id, frame.ethertype, frame.apdu


def _build_frame(
    dst_mac: str,
    src_mac: str,
    app_id: int,
    pdu: GoosePDU,
    vlan_id: Optional[int] = None,
    vlan_priority: Optional[int] = None,
) -> bytes:
    return ethernet.build_frame(
        dst_mac=dst_mac.lower(),
        src_mac=src_mac.lower(),
        ethertype=GOOSE_ETHERTYPE,
        app_id=app_id,
        apdu=encode_goose_pdu(pdu),
        vlan_id=vlan_id,
        vlan_priority=vlan_priority,
    )


@dataclass
class GoosePublisher:
    """Publishes GOOSE frames on a network interface."""

    iface: str
    src_mac: str
    app_id: int
    vlan_id: Optional[int] = None
    vlan_priority: Optional[int] = None

    def send(
        self,
        dst_mac: str,
        pdu: GoosePDU,
        count: int = 1,
        inter: float = 0.0,
    ) -> None:
        """Send one or more GOOSE frames."""
        raw = _build_frame(
            dst_mac=dst_mac,
            src_mac=self.src_mac,
            app_id=self.app_id,
            pdu=pdu,
            vlan_id=self.vlan_id,
            vlan_priority=self.vlan_priority,
        )
        from scapy.all import sendp  # type: ignore[import-untyped]

        sendp(raw, iface=self.iface, count=count, inter=inter, verbose=False)


@dataclass(frozen=True)
class _RawPacket:
    ts_rx: float
    raw: bytes


class GooseSubscriber:
    """GOOSE subscriber: raw frames from the shared process bus capture, decoded on a worker."""

    def __init__(
        self,
        iface: str,
        app_id: Optional[int] = None,
        callback: Optional[Callable[[GooseFrame], None]] = None,
        debug: bool = False,
    ) -> None:
        self.iface = iface
        self.app_id = app_id
        self.callback = callback
        self.debug = debug
        self._queue: queue.Queue[_RawPacket] = queue.Queue(maxsize=_QUEUE_MAX)
        self._drops = 0
        self._packets = 0
        self._worker: Optional[threading.Thread] = None
        self._worker_lock = threading.Lock()
        self._mux: Optional[object] = None

    def _ensure_worker(self) -> None:
        with self._worker_lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self._worker = threading.Thread(
                target=self._worker_loop,
                daemon=True,
                name="goose-subscriber-worker",
            )
            self._worker.start()

    def _worker_loop(self) -> None:
        while True:
            try:
                item = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            self._handle_raw(item.ts_rx, item.raw)

    def _enqueue_raw(self, ts_rx: float, raw: bytes) -> None:
        self._ensure_worker()
        try:
            self._queue.put_nowait(_RawPacket(ts_rx=ts_rx, raw=raw))
        except queue.Full:
            self._drops += 1

    def _drain_queue(self, timeout_s: float = 2.0) -> None:
        deadline = time.time() + timeout_s
        while time.time() < deadline and not self._queue.empty():
            time.sleep(0.01)

    def _handle_raw(self, ts_rx: float, raw: bytes) -> None:
        parsed = parse_ethernet_goose(raw)
        if parsed is None:
            return
        dst_mac, src_mac, app_id, vlan_id, ethertype, goose_payload = parsed
        if self.app_id is not None and app_id != self.app_id:
            return

        try:
            pdu = decode_goose_pdu(goose_payload)
        except Exception:
            pdu = None

        if self.debug and pdu is not None:
            log.info(
                f"[DEBUG] GOOSE {src_mac}→{dst_mac} app=0x{app_id:04x} "
                f"st={pdu.st_num} sq={pdu.sq_num}",
            )

        frame = GooseFrame(
            dst_mac=dst_mac,
            src_mac=src_mac,
            app_id=app_id,
            vlan_id=vlan_id,
            ethertype=ethertype,
            raw_payload=goose_payload,
            pdu=pdu,
            ts_rx=ts_rx,
        )
        if self.callback:
            self.callback(frame)

    def stats(self) -> Dict[str, int]:
        return {
            "queue_size": int(self._queue.qsize()),
            "drops": int(self._drops),
            "packets": int(self._packets),
        }

    def _use_processbus_mux(self) -> bool:
        """Shared GOOSE and SV capture (one socket per interface)."""
        try:
            root = Path(__file__).resolve().parents[2]
            root_str = str(root)
            if root_str not in sys.path:
                sys.path.insert(0, root_str)
            from processbus_capture import ProcessbusCapture  # noqa: WPS433

            self._mux = ProcessbusCapture.get(self.iface)
            return True
        except Exception:
            return False

    def _on_mux_packet(self, ts_rx: float, raw: bytes) -> None:
        parsed = parse_ethernet_goose(raw)
        if parsed is None:
            return
        _, _, app_id, _, _, _ = parsed
        if self.app_id is not None and app_id != self.app_id:
            return
        self._packets += 1
        self._enqueue_raw(ts_rx, raw)

    def run_until(
        self,
        should_stop: Callable[[], bool],
        poll_s: float = 0.05,
    ) -> int:
        """Capture until should_stop() returns True (shared process bus capture)."""
        self._ensure_worker()

        if self._use_processbus_mux():
            from processbus_capture import ProcessbusCapture  # noqa: WPS433

            mux = ProcessbusCapture.get(self.iface)
            unsubscribe = mux.subscribe_goose(self._on_mux_packet)
            try:
                while not should_stop():
                    time.sleep(poll_s)
            finally:
                unsubscribe()
            self._drain_queue()
            return self._drops

        log.warning(
            f"[goose] WARNING: direct capture on {self.iface} "
            f"(process bus capture unavailable), GOOSE only",
        )
        from open61850.capture import PacketCapture

        with PacketCapture(
            self.iface, (ethernet.ETHERTYPE_GOOSE,), buffer_bytes=_CAPTURE_BUFFER_BYTES, timeout=_CAPTURE_TIMEOUT_S
        ) as cap:
            while not should_stop():
                frame = cap.recv()
                if frame is None:
                    continue
                self._packets += 1
                self._enqueue_raw(frame.timestamp, frame.data)

        self._drain_queue()
        return self._drops

    def start(
        self,
        count: int = 0,
        timeout: Optional[Union[int, float]] = None,
        stop_filter: Optional[Callable[..., bool]] = None,
    ) -> None:
        """Blocking capture (CLI); prefer run_until() for long runs."""
        deadline: Optional[float] = None
        if timeout is not None:
            deadline = time.time() + float(timeout)
        n = 0

        def should_stop() -> bool:
            if stop_filter is not None and stop_filter(None):
                return True
            if deadline is not None and time.time() >= deadline:
                return True
            if count > 0 and n >= count:
                return True
            return False

        self.run_until(should_stop=should_stop)


def decode_hex_goose(hex_str: str) -> GoosePDU:
    """Decode a GOOSE APDU given as a hex string."""
    hex_str = hex_str.replace(" ", "").replace("\n", "")
    data = binascii.unhexlify(hex_str)
    return decode_goose_pdu(data)
