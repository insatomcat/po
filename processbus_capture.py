"""Capture unique processbus : GOOSE (0x88b8) + SV (0x88ba) sur une socket libpcap."""
from __future__ import annotations

import queue
import threading
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple
import sys

GOOSE_ETHERTYPE = 0x88B8
SV_ETHERTYPE = 0x88BA

PCAP_SNAPLEN = 65535
PCAP_READ_TIMEOUT_MS = 50
PCAP_BUFFER_BYTES = 4 * 1024 * 1024
SV_QUEUE_MAX = 20_000

GOOSE_BPF = "(ether proto 0x88b8) or (vlan and ether proto 0x88b8)"
SV_BPF = "(ether proto 0x88ba) or (vlan and ether proto 0x88ba)"
PROCESSBUS_BPF = f"({GOOSE_BPF}) or ({SV_BPF})"

GooseHandler = Callable[[float, bytes], None]
SvHandler = Callable[[object, bytes, float], None]


def frame_ethertype(frame: bytes) -> Optional[int]:
    """Ethertype réel (après VLAN 0x8100 si présent)."""
    if len(frame) < 14:
        return None
    eth_type = (frame[12] << 8) | frame[13]
    if eth_type == 0x8100:
        if len(frame) < 18:
            return None
        return (frame[16] << 8) | frame[17]
    return eth_type


def bpf_for_modes(*, goose: bool, sv: bool) -> Tuple[str, str]:
    """Retourne (filtre BPF, libellé mode)."""
    if goose and sv:
        return PROCESSBUS_BPF, "goose+sv"
    if goose:
        return GOOSE_BPF, "goose"
    if sv:
        return SV_BPF, "sv"
    return GOOSE_BPF, "idle"


@dataclass
class ProcessbusCaptureStats:
    packets: int = 0
    goose_packets: int = 0
    sv_packets: int = 0
    sv_queue_drops: int = 0
    loop_errors: int = 0
    last_error: Optional[str] = None
    bpf_mode: str = "idle"
    pcap_recv: int = 0
    pcap_drop: int = 0
    pcap_ifdrop: int = 0


@dataclass
class _SvSubscription:
    handler: SvHandler


class ProcessbusCapture:
    """Une socket pcapy par interface ; BPF adaptatif selon les abonnés actifs."""

    _instances: Dict[str, ProcessbusCapture] = {}
    _instances_lock = threading.Lock()

    @classmethod
    def get(cls, iface: str) -> ProcessbusCapture:
        with cls._instances_lock:
            if iface not in cls._instances:
                cls._instances[iface] = ProcessbusCapture(iface)
            return cls._instances[iface]

    def __init__(self, iface: str) -> None:
        self.iface = iface
        self._lock = threading.Lock()
        self._goose_handlers: Dict[int, GooseHandler] = {}
        self._goose_next_id = 0
        self._sv_sub: Optional[_SvSubscription] = None
        self._thread: Optional[threading.Thread] = None
        self._sv_worker: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._stats = ProcessbusCaptureStats()
        self._stats_lock = threading.Lock()
        self._cap: Optional[object] = None
        self._bpf_generation = 0
        self._applied_bpf_gen = -1
        self._sv_queue: queue.Queue[Tuple[object, bytes, float]] = queue.Queue(maxsize=SV_QUEUE_MAX)
        self._goose_ring: Optional[object] = None

    def enable_goose_ring(self, window_s: float = 4.0) -> None:
        gl_dir = str(Path(__file__).resolve().parent / "goose_listener")
        if gl_dir not in sys.path:
            sys.path.insert(0, gl_dir)
        from goose_ring_pcap import GooseRingBuffer

        with self._lock:
            if self._goose_ring is None:
                self._goose_ring = GooseRingBuffer(window_s)
            else:
                self._goose_ring.set_window(window_s)

    def disable_goose_ring(self) -> None:
        with self._lock:
            self._goose_ring = None

    def snapshot_goose_ring(self) -> List[Tuple[float, bytes]]:
        with self._lock:
            ring = self._goose_ring
        if ring is None:
            return []
        return ring.snapshot()

    def goose_ring_stats(self) -> Dict[str, object]:
        with self._lock:
            ring = self._goose_ring
        if ring is None:
            return {"enabled": False}
        s = ring.stats()
        s["enabled"] = True
        return s

    def stats(self) -> Dict[str, object]:
        """Compteurs mis à jour par le thread capture (pas d'appel cap.stats() ici)."""
        with self._stats_lock:
            s = self._stats
            with self._lock:
                goose_n = len(self._goose_handlers)
                sv_on = self._sv_sub is not None
                running = self._thread is not None and self._thread.is_alive()
            return {
                "multiplexed": True,
                "iface": self.iface,
                "running": running,
                "goose_subscribers": goose_n,
                "sv_active": sv_on,
                "bpf_mode": s.bpf_mode,
                "packets": s.packets,
                "goose_packets": s.goose_packets,
                "sv_packets": s.sv_packets,
                "sv_queue_size": int(self._sv_queue.qsize()),
                "sv_queue_drops": s.sv_queue_drops,
                "pcap_recv": s.pcap_recv,
                "pcap_drop": s.pcap_drop,
                "pcap_ifdrop": s.pcap_ifdrop,
                "loop_errors": s.loop_errors,
                "last_error": s.last_error,
            }

    def subscribe_goose(self, handler: GooseHandler) -> Callable[[], None]:
        with self._lock:
            sub_id = self._goose_next_id
            self._goose_next_id += 1
            self._goose_handlers[sub_id] = handler
            self._bpf_generation += 1
            self._ensure_thread_locked()
            return lambda: self._unsubscribe_goose(sub_id)

    def subscribe_sv(self, handler: SvHandler) -> Callable[[], None]:
        with self._lock:
            if self._sv_sub is not None:
                raise RuntimeError("Une capture SV est déjà active sur cette interface.")
            self._sv_sub = _SvSubscription(handler=handler)
            self._bpf_generation += 1
            self._ensure_thread_locked()
            self._ensure_sv_worker_locked()
            return self._unsubscribe_sv

    def _unsubscribe_goose(self, sub_id: int) -> None:
        with self._lock:
            self._goose_handlers.pop(sub_id, None)
            if self._has_consumers_locked():
                self._bpf_generation += 1
            self._maybe_stop_locked()

    def _unsubscribe_sv(self) -> None:
        with self._lock:
            self._sv_sub = None
            if self._has_consumers_locked():
                self._bpf_generation += 1
            self._maybe_stop_locked()

    def _has_consumers_locked(self) -> bool:
        return bool(self._goose_handlers) or self._sv_sub is not None

    def _modes_locked(self) -> Tuple[bool, bool]:
        return bool(self._goose_handlers), self._sv_sub is not None

    def _ensure_thread_locked(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name=f"processbus-capture-{self.iface}",
        )
        self._thread.start()

    def _ensure_sv_worker_locked(self) -> None:
        if self._sv_worker is not None and self._sv_worker.is_alive():
            return
        self._sv_worker = threading.Thread(
            target=self._sv_worker_loop,
            daemon=True,
            name=f"processbus-sv-worker-{self.iface}",
        )
        self._sv_worker.start()

    def _maybe_stop_locked(self) -> None:
        if self._has_consumers_locked():
            return
        self._stop.set()

    def _poll_pcap_stats(self, cap: object) -> None:
        try:
            recv, drop, ifdrop = cap.stats()  # type: ignore[attr-defined]
        except Exception:
            return
        with self._stats_lock:
            self._stats.pcap_recv = int(recv)
            self._stats.pcap_drop = int(drop)
            self._stats.pcap_ifdrop = int(ifdrop)

    def _apply_bpf_if_needed(self, cap: object) -> None:
        with self._lock:
            gen = self._bpf_generation
            if gen == self._applied_bpf_gen:
                return
            goose, sv = self._modes_locked()
            bpf, mode = bpf_for_modes(goose=goose, sv=sv)
            self._applied_bpf_gen = gen
        try:
            cap.setfilter(bpf)  # type: ignore[attr-defined]
            with self._stats_lock:
                self._stats.bpf_mode = mode
            print(f"[processbus] BPF {self.iface} → {mode} ({bpf})", flush=True)
        except Exception as exc:
            with self._stats_lock:
                self._stats.loop_errors += 1
                self._stats.last_error = f"setfilter: {exc}"

    def _sv_worker_loop(self) -> None:
        while not self._stop.is_set() or not self._sv_queue.empty():
            try:
                header, raw, ts_rx = self._sv_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            with self._lock:
                sv = self._sv_sub
            if sv is None:
                continue
            try:
                sv.handler(header, raw, ts_rx)
            except Exception:
                traceback.print_exc()

    def _enqueue_sv(self, header: object, raw: bytes, ts_rx: float) -> None:
        try:
            self._sv_queue.put_nowait((header, raw, ts_rx))
        except queue.Full:
            with self._stats_lock:
                self._stats.sv_queue_drops += 1

    def _capture_loop(self) -> None:
        try:
            import pcapy
        except ImportError:
            with self._stats_lock:
                self._stats.last_error = "pcapy non installé"
            return

        cap = None
        while not self._stop.is_set():
            with self._lock:
                if not self._has_consumers_locked():
                    break

            if cap is None:
                try:
                    cap = pcapy.open_live(
                        self.iface,
                        PCAP_SNAPLEN,
                        1,
                        PCAP_READ_TIMEOUT_MS,
                    )
                    with self._lock:
                        self._cap = cap
                        self._applied_bpf_gen = -1
                    try:
                        cap.setbuff(PCAP_BUFFER_BYTES)
                    except Exception:
                        pass
                    self._apply_bpf_if_needed(cap)
                    with self._stats_lock:
                        self._stats.last_error = None
                except Exception as exc:
                    with self._stats_lock:
                        self._stats.loop_errors += 1
                        self._stats.last_error = str(exc)
                    if self._stop.wait(1.0):
                        break
                    continue

            self._apply_bpf_if_needed(cap)

            try:
                header, pkt = cap.next()
            except Exception as exc:
                with self._stats_lock:
                    self._stats.loop_errors += 1
                    self._stats.last_error = str(exc)
                with self._lock:
                    self._cap = None
                cap = None
                if self._stop.wait(0.2):
                    break
                continue

            if not pkt:
                continue
            if self._stop.is_set():
                break

            raw = bytes(pkt)
            ts = header.getts()
            ts_rx = float(ts[0]) + float(ts[1]) / 1e6
            etype = frame_ethertype(raw)

            with self._stats_lock:
                self._stats.packets += 1
                n = self._stats.packets
            if n % 50 == 0:
                self._poll_pcap_stats(cap)

            with self._lock:
                goose_handlers = list(self._goose_handlers.values())
                sv_active = self._sv_sub is not None

            if etype == GOOSE_ETHERTYPE:
                with self._stats_lock:
                    self._stats.goose_packets += 1
                with self._lock:
                    ring = self._goose_ring
                if ring is not None:
                    ring.add(ts_rx, raw)
                for handler in goose_handlers:
                    try:
                        handler(ts_rx, raw)
                    except Exception:
                        traceback.print_exc()
            elif etype == SV_ETHERTYPE and sv_active:
                with self._stats_lock:
                    self._stats.sv_packets += 1
                self._enqueue_sv(header, raw, ts_rx)

        with self._lock:
            self._cap = None
        cap = None
