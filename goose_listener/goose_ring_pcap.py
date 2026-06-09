"""Tampon glissant GOOSE + export PCAP (4 s avant chaque problème)."""
from __future__ import annotations

import json
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

RING_DEFAULT_WINDOW_S = 4.0
PCAP_MAGIC = 0xA1B2C3D4
PCAP_NETWORK_ETHERNET = 1
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 1
PCAPNG_EPB = 6
PCAPNG_OPT_END = 0
PCAPNG_SHB_COMMENT = 1
PCAPNG_IDB_IF_TSRESOL = 9
PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D

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


def format_ts_local(ts: Optional[float]) -> Optional[str]:
    """Horodatage lisible (heure locale PO) pour corrélation avec l'UI."""
    if ts is None:
        return None
    dt = datetime.fromtimestamp(float(ts))
    ms = int(round((float(ts) % 1) * 1000))
    return f"{dt.strftime('%Y-%m-%d %H:%M:%S')}.{ms:03d}"


def build_pcap_comment(problem: Dict[str, Any], packets: List[Packet]) -> str:
    """Texte embarqué dans le PCAP-NG (visible dans Wireshark > propriétés fichier)."""
    kind = problem.get("kind") or "problem"
    go_id = problem.get("go_id") or ""
    ts_prob = problem.get("ts_goose")
    if ts_prob is None:
        ts_prob = problem.get("ts_expected")
    lines = [
        "PO GOOSE Listener — ring buffer 4 s",
        f"Problème: {kind}" + (f" ({go_id})" if go_id else ""),
    ]
    prob_s = format_ts_local(ts_prob)
    if prob_s:
        lines.append(f"Heure problème (UI): {prob_s}")
    if packets:
        lines.append(f"Premier paquet: {format_ts_local(packets[0][0])}")
        lines.append(f"Dernier paquet:  {format_ts_local(packets[-1][0])}")
    msg = str(problem.get("message") or "").strip()
    if msg:
        lines.append(f"Détail: {msg}")
    lines.append(
        "Wireshark: afficher Date/heure (pas « depuis début capture ») pour voir l'heure réelle."
    )
    return "\n".join(lines)


def _pad4(data: bytes) -> bytes:
    pad = (4 - (len(data) % 4)) % 4
    return data + (b"\x00" * pad)


def _pcapng_option(code: int, value: bytes) -> bytes:
    return struct.pack("<HH", code, len(value)) + _pad4(value)


def _pcapng_timestamp_us(ts: float) -> Tuple[int, int]:
    """Découpe un epoch float en (high, low) pour EPB PCAP-NG (résolution µs)."""
    total_us = int(round(float(ts) * 1_000_000))
    if total_us < 0:
        total_us = 0
    return (total_us >> 32) & 0xFFFFFFFF, total_us & 0xFFFFFFFF


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    body_padded = _pad4(body)
    total = 4 + 4 + len(body_padded) + 4
    return (
        struct.pack("<II", block_type, total)
        + body_padded
        + struct.pack("<I", total)
    )


def _write_pcapng(
    f,
    packets: List[Packet],
    *,
    comment: str = "",
) -> None:
    shb_body = struct.pack(
        "<IHHq",
        PCAPNG_BYTE_ORDER_MAGIC,
        1,
        0,
        -1,
    )
    if comment:
        shb_body += _pcapng_option(
            PCAPNG_SHB_COMMENT,
            comment.encode("utf-8"),
        )
    shb_body += struct.pack("<HH", PCAPNG_OPT_END, 0)
    f.write(_pcapng_block(PCAPNG_SHB, shb_body))

    idb_body = struct.pack("<HxxI", PCAP_NETWORK_ETHERNET, 65535)
    idb_body += _pcapng_option(PCAPNG_IDB_IF_TSRESOL, bytes([6]))
    idb_body += struct.pack("<HH", PCAPNG_OPT_END, 0)
    f.write(_pcapng_block(PCAPNG_IDB, idb_body))

    for ts, raw in packets:
        ts_high, ts_low = _pcapng_timestamp_us(ts)
        epb_body = struct.pack("<IIII", 0, ts_high, ts_low, len(raw))
        epb_body += struct.pack("<I", len(raw))
        epb_body += _pad4(raw)
        epb_body += struct.pack("<HH", PCAPNG_OPT_END, 0)
        f.write(_pcapng_block(PCAPNG_EPB, epb_body))


def write_dump_meta(
    path: Path,
    *,
    dump_id: str,
    problem: Dict[str, Any],
    packets: List[Packet],
    window_s: float,
) -> None:
    ts_prob = problem.get("ts_goose")
    if ts_prob is None:
        ts_prob = problem.get("ts_expected")
    payload = {
        "dump_id": dump_id,
        "window_s": window_s,
        "problem": {
            "kind": problem.get("kind"),
            "go_id": problem.get("go_id") or "",
            "ts_goose": problem.get("ts_goose"),
            "ts_expected": problem.get("ts_expected"),
            "ts_goose_local": format_ts_local(problem.get("ts_goose")),
            "ts_expected_local": format_ts_local(problem.get("ts_expected")),
            "problem_time_local": format_ts_local(ts_prob),
            "message": problem.get("message"),
        },
        "capture": {
            "packet_count": len(packets),
            "oldest_ts": packets[0][0] if packets else None,
            "newest_ts": packets[-1][0] if packets else None,
            "oldest_local": format_ts_local(packets[0][0]) if packets else None,
            "newest_local": format_ts_local(packets[-1][0]) if packets else None,
        },
        "wireshark_hint": (
            "Colonne Time : View > Time Display Format > "
            "Date and Time of Day (horodatage absolu libpcap)."
        ),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def write_pcap(
    path: Path,
    packets: List[Packet],
    *,
    comment: str = "",
    problem: Optional[Dict[str, Any]] = None,
    dump_id: str = "",
    window_s: float = RING_DEFAULT_WINDOW_S,
) -> int:
    """Écrit un PCAP-NG (timestamps epoch absolus + commentaire problème)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not comment and problem is not None:
        comment = build_pcap_comment(problem, packets)
    with path.open("wb") as f:
        _write_pcapng(f, packets, comment=comment)
    if problem is not None and dump_id:
        write_dump_meta(
            path.with_suffix(".meta.json"),
            dump_id=dump_id,
            problem=problem,
            packets=packets,
            window_s=window_s,
        )
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
