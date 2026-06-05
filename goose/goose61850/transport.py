from __future__ import annotations

import binascii
import queue
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional, Union

from scapy.all import (  # type: ignore[import-untyped]
    AsyncSniffer,
    Ether,
    Raw,
    Dot1Q,
    sendp,
    sniff,
)

from .codec import decode_goose_pdu, encode_goose_pdu
from .types import GooseFrame, GoosePDU


GOOSE_ETHERTYPE = 0x88B8
_QUEUE_MAX = 50_000


def goose_bpf_filter(app_id: Optional[int] = None) -> str:
    """Filtre BPF kernel : GOOSE (0x88b8) uniquement, optionnellement par APPID.

    Sans filtre BPF, scapy.sniff() reçoit aussi les SV (0x88ba) et autres trames
    sur processbus ; le callback Python ne suit pas les rafales GOOSE (sqNum 0..3).
    """
    if app_id is None:
        return "(ether proto 0x88b8) or (vlan and ether proto 0x88b8)"
    aid = f"0x{app_id:04x}"
    plain = f"ether proto 0x88b8 and ether[14:2]={aid}"
    tagged = f"vlan and ether proto 0x88b8 and ether[18:2]={aid}"
    return f"({plain}) or ({tagged})"


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

    # En-tête GOOSE spécifique (APPID + longueur + reserved1 + reserved2)
    app_id_bytes = app_id.to_bytes(2, "big")
    length_bytes = (8 + len(payload)).to_bytes(2, "big")  # 8 octets de header GOOSE
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


class GooseSubscriber:
    """Abstraction simple de souscripteur GOOSE basé sur scapy."""

    def __init__(
        self,
        iface: str,
        app_id: Optional[int] = None,
        callback: Optional[Callable[[GooseFrame], None]] = None,
        debug: bool = False,
    ) -> None:
        """
        - `iface` : nom de l'interface (ex: "eth0").
        - `app_id` : si renseigné, filtre les trames GOOSE sur cet APPID uniquement.
        - `callback` : fonction appelée pour chaque trame décodée.
        """
        self.iface = iface
        self.app_id = app_id
        self.callback = callback
        self.debug = debug
        self._queue: queue.Queue = queue.Queue(maxsize=_QUEUE_MAX)
        self._drops = 0
        self._worker: Optional[threading.Thread] = None
        self._worker_lock = threading.Lock()

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
                pkt = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            self._handle_pkt(pkt)

    def _enqueue(self, pkt) -> None:  # type: ignore[no-untyped-def]
        self._ensure_worker()
        try:
            self._queue.put_nowait(pkt)
        except queue.Full:
            self._drops += 1

    def _drain_queue(self, timeout_s: float = 2.0) -> None:
        deadline = time.time() + timeout_s
        while time.time() < deadline and not self._queue.empty():
            time.sleep(0.01)

    def _handle_pkt(self, pkt) -> None:  # type: ignore[no-untyped-def]
        """Décode une trame GOOSE et appelle le callback utilisateur."""
        if self.debug:
            print(f"[DEBUG] pkt: {pkt.summary()}")

        eth = pkt.getlayer(Ether)
        if eth is None:
            if not hasattr(pkt, "type"):
                return
            if pkt.type == GOOSE_ETHERTYPE:
                payload = bytes(pkt.payload)
                src_mac = getattr(pkt, "src", "unknown")
                dst_mac = getattr(pkt, "dst", "unknown")
                ethertype = pkt.type
            else:
                return
        else:
            if eth.type == 0x8100 and pkt.haslayer(Dot1Q):
                dot1q = pkt[Dot1Q]
                if dot1q.type != GOOSE_ETHERTYPE:
                    return
                payload = bytes(dot1q.payload)
                src_mac = str(eth.src)
                dst_mac = str(eth.dst)
                ethertype = dot1q.type
            else:
                if eth.type != GOOSE_ETHERTYPE:
                    return
                payload = bytes(eth.payload)
                src_mac = str(eth.src)
                dst_mac = str(eth.dst)
                ethertype = eth.type

        if len(payload) < 8:
            return

        app_id = int.from_bytes(payload[0:2], "big")
        length = int.from_bytes(payload[2:4], "big")

        if self.app_id is not None and app_id != self.app_id:
            return

        goose_payload = payload[8:length]

        try:
            pdu = decode_goose_pdu(goose_payload)
        except Exception:
            pdu = None

        try:
            ts_rx = float(pkt.time)
        except (AttributeError, TypeError, ValueError):
            ts_rx = time.time()

        frame = GooseFrame(
            dst_mac=dst_mac,
            src_mac=src_mac,
            app_id=app_id,
            vlan_id=None,
            ethertype=ethertype,
            raw_payload=goose_payload,
            pdu=pdu,
            ts_rx=ts_rx,
        )

        if self.callback:
            self.callback(frame)

    def run_until(
        self,
        should_stop: Callable[[], bool],
        poll_s: float = 0.1,
    ) -> int:
        """Capture continue (une seule session libpcap) jusqu'à should_stop() == True.

        Évite de rouvrir la socket périodiquement (source de pertes de cycles entiers).
        Retourne le nombre de paquets droppés (file pleine).
        """
        self._ensure_worker()
        bpf = goose_bpf_filter(self.app_id)
        sniffer = AsyncSniffer(
            iface=self.iface,
            filter=bpf,
            prn=self._enqueue,
            store=False,
            stop_filter=lambda _: should_stop(),
        )
        sniffer.start()
        try:
            while not should_stop():
                time.sleep(poll_s)
        finally:
            sniffer.stop()
            self._drain_queue()
        return self._drops

    def start(
        self,
        count: int = 0,
        timeout: Optional[Union[int, float]] = None,
        stop_filter: Optional[Callable[..., bool]] = None,
    ) -> None:
        """Démarre la capture (bloquante).

        Préférer run_until() pour une écoute longue durée sans trou de capture.
        """
        self._ensure_worker()
        sniff(
            iface=self.iface,
            filter=goose_bpf_filter(self.app_id),
            prn=self._enqueue,
            store=False,
            timeout=timeout,
            count=count if count > 0 else 0,
            stop_filter=stop_filter or (lambda _: False),
        )
        self._drain_queue()


def decode_hex_goose(hex_str: str) -> GoosePDU:
    """Utilitaire : décode une chaîne hexadécimale représentant un APDU GOOSE."""
    hex_str = hex_str.replace(" ", "").replace("\n", "")
    data = binascii.unhexlify(hex_str)
    return decode_goose_pdu(data)
