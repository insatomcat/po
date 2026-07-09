from __future__ import annotations

import binascii
import queue
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple, Union

from scapy.all import (  # type: ignore[import-untyped]
    Dot1Q,
    Ether,
    Raw,
    sendp,
)

from .codec import decode_goose_pdu, encode_goose_pdu
from .types import GooseFrame, GoosePDU


GOOSE_ETHERTYPE = 0x88B8
_QUEUE_MAX = 50_000
_PCAP_SNAPLEN = 65535
_PCAP_READ_TIMEOUT_MS = 50
_PCAP_BUFFER_BYTES = 4 * 1024 * 1024


def goose_bpf_filter(app_id: Optional[int] = None) -> str:
    """Filtre BPF kernel : GOOSE (0x88b8) uniquement, optionnellement par APPID.

    Sans filtre BPF, la capture reçoit aussi les SV (0x88ba) et autres trames
    sur processbus ; le worker ne suit pas les rafales GOOSE (sqNum 0..3).
    """
    if app_id is None:
        return "(ether proto 0x88b8) or (vlan and ether proto 0x88b8)"
    aid = f"0x{app_id:04x}"
    plain = f"ether proto 0x88b8 and ether[14:2]={aid}"
    tagged = f"vlan and ether proto 0x88b8 and ether[18:2]={aid}"
    return f"({plain}) or ({tagged})"


def nic_rx_stats(iface: str) -> Dict[str, int]:
    """Compteurs RX noyau (/sys/class/net/…) — pertes avant libpcap."""
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


def _format_mac(mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac)


def parse_ethernet_goose(raw: bytes) -> Optional[Tuple[str, str, int, Optional[int], int, bytes]]:
    """Décode une trame Ethernet brute → (dst, src, app_id, vlan_id, ethertype, apdu)."""
    if len(raw) < 14:
        return None
    dst_mac = _format_mac(raw[0:6])
    src_mac = _format_mac(raw[6:12])
    offset = 12
    ethertype = int.from_bytes(raw[offset: offset + 2], "big")
    offset += 2
    vlan_id: Optional[int] = None
    if ethertype == 0x8100:
        if len(raw) < offset + 4:
            return None
        vlan_id = int.from_bytes(raw[offset: offset + 2], "big") & 0x0FFF
        ethertype = int.from_bytes(raw[offset + 2: offset + 4], "big")
        offset += 4
    if ethertype != GOOSE_ETHERTYPE:
        return None
    payload = raw[offset:]
    if len(payload) < 8:
        return None
    app_id = int.from_bytes(payload[0:2], "big")
    length = int.from_bytes(payload[2:4], "big")
    if length < 8 or length > len(payload):
        return None
    goose_payload = payload[8:length]
    return dst_mac, src_mac, app_id, vlan_id, ethertype, goose_payload


def _mac_str(mac: str) -> str:
    return mac.lower()


def _build_frame(
    dst_mac: str,
    src_mac: str,
    app_id: int,
    pdu: GoosePDU,
    vlan_id: Optional[int] = None,
    vlan_priority: Optional[int] = None,
) -> bytes:
    payload = encode_goose_pdu(pdu)

    app_id_bytes = app_id.to_bytes(2, "big")
    length_bytes = (8 + len(payload)).to_bytes(2, "big")
    reserved = b"\x00\x00\x00\x00"
    goose_header = app_id_bytes + length_bytes + reserved

    eth = Ether(dst=_mac_str(dst_mac), src=_mac_str(src_mac))
    if vlan_id is not None:
        prio = 0 if vlan_priority is None else int(vlan_priority)
        pkt = eth / Dot1Q(prio=prio, vlan=vlan_id, type=GOOSE_ETHERTYPE) / Raw(goose_header + payload)
    else:
        pkt = eth / Raw(goose_header + payload)
    return bytes(pkt)


@dataclass
class GoosePublisher:
    """Publication de trames GOOSE sur un interface réseau."""

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
        """Envoie une ou plusieurs trames GOOSE."""
        raw = _build_frame(
            dst_mac=dst_mac,
            src_mac=self.src_mac,
            app_id=self.app_id,
            pdu=pdu,
            vlan_id=self.vlan_id,
            vlan_priority=self.vlan_priority,
        )
        sendp(raw, iface=self.iface, count=count, inter=inter, verbose=False)


@dataclass(frozen=True)
class _RawPacket:
    ts_rx: float
    raw: bytes


class GooseSubscriber:
    """Souscripteur GOOSE : capture pcapy (bytes bruts) + worker de décodage."""

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
            print(
                f"[DEBUG] GOOSE {src_mac}→{dst_mac} app=0x{app_id:04x} "
                f"st={pdu.st_num} sq={pdu.sq_num}",
                flush=True,
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
        """Multiplexeur partagé GOOSE+SV (une socket par interface)."""
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
        """Capture continue jusqu'à should_stop() == True (multiplexeur processbus)."""
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

        print(
            f"[goose] ATTENTION: capture directe sur {self.iface} "
            f"(multiplexeur processbus indisponible) — BPF GOOSE seul",
            flush=True,
        )
        try:
            import pcapy
        except ImportError as exc:
            raise RuntimeError(
                "pcapy requis pour la capture GOOSE fiable : pip install pcapy"
            ) from exc

        bpf = goose_bpf_filter(self.app_id)
        cap = pcapy.open_live(self.iface, _PCAP_SNAPLEN, 1, _PCAP_READ_TIMEOUT_MS)
        try:
            cap.setfilter(bpf)
        except Exception as exc:
            raise RuntimeError(f"setfilter({bpf!r}) sur {self.iface}: {exc}") from exc
        try:
            cap.setbuff(_PCAP_BUFFER_BYTES)
        except Exception:
            pass

        while not should_stop():
            try:
                header, pkt = cap.next()
            except Exception:
                if should_stop():
                    break
                time.sleep(poll_s)
                continue
            if not pkt:
                continue
            self._packets += 1
            ts = header.getts()
            ts_rx = float(ts[0]) + float(ts[1]) / 1e6
            self._enqueue_raw(ts_rx, bytes(pkt))

        self._drain_queue()
        return self._drops

    def start(
        self,
        count: int = 0,
        timeout: Optional[Union[int, float]] = None,
        stop_filter: Optional[Callable[..., bool]] = None,
    ) -> None:
        """Capture bloquante (CLI). Préférer run_until() pour l'écoute longue durée."""
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
    """Utilitaire : décode une chaîne hexadécimale représentant un APDU GOOSE."""
    hex_str = hex_str.replace(" ", "").replace("\n", "")
    data = binascii.unhexlify(hex_str)
    return decode_goose_pdu(data)
