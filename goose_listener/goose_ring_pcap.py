"""Tampon glissant GOOSE + export PCAP (4 s avant chaque problème)."""
from __future__ import annotations

import struct
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, List, Optional, Tuple

RING_DEFAULT_WINDOW_S = 4.0
PCAP_MAGIC = 0xA1B2C3D4
PCAP_NETWORK_ETHERNET = 1

Packet = Tuple[float, bytes]


@dataclass
class RingSnapshotMeta:
    dump_id: str
    path: Path
    created_at: float
    reason: str
    packet_count: int
    window_s: float
    go_id: str = ""


class GooseRingBuffer:
    """Conserve les trames Ethernet GOOSE des N dernières secondes."""

    def __init__(self, window_s: float = RING_DEFAULT_WINDOW_S, *, max_packets: int = 80_000) -> None:
        self._window_s = max(0.5, float(window_s))
        self._max_packets = max_packets
        self._packets: Deque[Packet] = deque()
        self._lock = threading.Lock()

    @property
    def window_s(self) -> float:
        return self._window_s

    def set_window(self, window_s: float) -> None:
        with self._lock:
            self._window_s = max(0.5, float(window_s))
            self._prune_locked(time.time())

    def add(self, ts_rx: float, raw: bytes) -> None:
        if not raw:
            return
        with self._lock:
            self._packets.append((ts_rx, raw))
            while len(self._packets) > self._max_packets:
                self._packets.popleft()
            self._prune_locked(ts_rx)

    def _prune_locked(self, now: float) -> None:
        cutoff = now - self._window_s
        while self._packets and self._packets[0][0] < cutoff:
            self._packets.popleft()

    def snapshot(self, *, now: Optional[float] = None) -> List[Packet]:
        ts = time.time() if now is None else now
        with self._lock:
            self._prune_locked(ts)
            return list(self._packets)

    def stats(self) -> dict:
        with self._lock:
            return {
                "window_s": self._window_s,
                "packet_count": len(self._packets),
                "oldest_ts": self._packets[0][0] if self._packets else None,
                "newest_ts": self._packets[-1][0] if self._packets else None,
            }


def write_pcap(path: Path, packets: List[Packet]) -> int:
    """Écrit un fichier PCAP (linktype Ethernet). Retourne le nombre de paquets."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        f.write(
            struct.pack(
                "<IHHIIII",
                PCAP_MAGIC,
                2,
                4,
                0,
                0,
                65535,
                PCAP_NETWORK_ETHERNET,
            )
        )
        for ts, raw in packets:
            ts_sec = int(ts)
            ts_usec = int(round((ts - ts_sec) * 1_000_000))
            incl = len(raw)
            f.write(struct.pack("<IIII", ts_sec, ts_usec, incl, incl))
            f.write(raw)
    return len(packets)


def _safe_slug(text: str, *, max_len: int = 48) -> str:
    out = []
    for ch in text:
        if ch.isalnum() or ch in "-_":
            out.append(ch)
        elif ch in " /.":
            out.append("_")
    slug = "".join(out).strip("_")
    return (slug or "dump")[:max_len]
