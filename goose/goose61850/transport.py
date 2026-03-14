from __future__ import annotations

import binascii
from dataclasses import dataclass
from typing import Callable, Optional

from scapy.all import (  # type: ignore[import-untyped]
    Ether,
    Raw,
    Dot1Q,
    sendp,
    sniff,
)

from .codec import decode_goose_pdu, encode_goose_pdu
from .types import GooseFrame, GoosePDU


GOOSE_ETHERTYPE = 0x88B8


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

    def _handle_pkt(self, pkt) -> None:  # type: ignore[no-untyped-def]
        """Callback scapy pour chaque paquet sniffé.

        On essaie d'abord de récupérer une couche Ether, mais certains OS
        (ou certaines interfaces) renvoient des trames au format "Cooked"
        sans cette couche. Dans ce cas, on vérifie directement le champ type.
        """
        if self.debug:
            # résumé très court pour ne pas spammer de données brutes
            print(f"[DEBUG] pkt: {pkt.summary()}")

        eth = pkt.getlayer(Ether)
        if eth is None:
            # mode "Cooked" ou autre encapsulation : on regarde directement le type
            if not hasattr(pkt, "type"):
                return
            # si c'est directement du GOOSE sur cette interface
            if pkt.type == GOOSE_ETHERTYPE:
                payload = bytes(pkt.payload)
                src_mac = getattr(pkt, "src", "unknown")
                dst_mac = getattr(pkt, "dst", "unknown")
                ethertype = pkt.type
            else:
                return
        else:
            # Gestion des trames VLAN-tagguées : Ether(type=0x8100) / Dot1Q(type=0x88B8)
            if eth.type == 0x8100 and pkt.haslayer(Dot1Q):
                dot1q = pkt[Dot1Q]
                if dot1q.type != GOOSE_ETHERTYPE:
                    return
                payload = bytes(dot1q.payload)
                src_mac = str(eth.src)
                dst_mac = str(eth.dst)
                ethertype = dot1q.type
            else:
                # Trame non VLAN : on s'attend à voir directement l'EtherType GOOSE
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
        # reserved1 = payload[4:6]
        # reserved2 = payload[6:8]

        if self.app_id is not None and app_id != self.app_id:
            return

        goose_payload = payload[8:length]

        try:
            pdu = decode_goose_pdu(goose_payload)
        except Exception:
            pdu = None

        frame = GooseFrame(
            dst_mac=dst_mac,
            src_mac=src_mac,
            app_id=app_id,
            vlan_id=None,  # géré par scapy en amont si nécessaire
            ethertype=ethertype,
            raw_payload=goose_payload,
            pdu=pdu,
        )

        if self.callback:
            self.callback(frame)

    def start(self, count: int = 0, timeout: Optional[int] = None) -> None:
        """Démarre la capture (bloquante).

        - `count` : nombre maximum de trames à capturer (0 = illimité).
        - `timeout` : durée max en secondes (None = illimité).
        """

        sniff(
            iface=self.iface,
            prn=self._handle_pkt,
            store=False,
            timeout=timeout,
            count=count if count > 0 else 0,
            # pas de filtre BPF pour laisser passer tout type de trames
        )


def decode_hex_goose(hex_str: str) -> GoosePDU:
    """Utilitaire : décode une chaîne hexadécimale représentant un APDU GOOSE."""
    hex_str = hex_str.replace(" ", "").replace("\n", "")
    data = binascii.unhexlify(hex_str)
    return decode_goose_pdu(data)

