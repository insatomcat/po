"""COTP (ISO Transport Class 0) minimal pour MMS sur TPKT/TCP.

Ce module implémente uniquement ce qui est nécessaire côté client:
  - envoi d'un CR TPDU (Connection Request) et attente du CC (Connection Confirm),
  - envoi de DT TPDU (Data) pour transporter les PDUs supérieurs (ACSE/MMS),
  - réception de DT TPDU côté client.

Il suppose TPKT (RFC 1006) en dessous, géré par le module tpkt.
"""

from __future__ import annotations

import socket
from typing import Optional

from tpkt import send_tpkt, recv_tpkt, TPKTError


class COTPError(RuntimeError):
    """Erreur générique COTP."""


def _build_cr_tpdu(
    src_ref: int = 0x0001,
    dst_ref: int = 0x0000,
    tpdu_size: int = 0x0D,
    called_tsap: int = 0x0001,
    calling_tsap: int = 0x0001,
) -> bytes:
    """Construit un CR TPDU pour MMS (classe 0).

    Les valeurs par défaut correspondent à la trame observée dans Wireshark :
      - TPDU size param : C0 01 0D
      - Called TSAP     : C2 02 00 01
      - Calling TSAP    : C1 02 00 01
    """
    if not (0 <= src_ref <= 0xFFFF and 0 <= dst_ref <= 0xFFFF):
        raise ValueError("src_ref/dst_ref doivent tenir sur 2 octets")

    li = 0x11  # length of remaining bytes (sans ce champ lui-même)
    pdu_type = 0xE0  # CR

    dst_hi, dst_lo = (dst_ref >> 8) & 0xFF, dst_ref & 0xFF
    src_hi, src_lo = (src_ref >> 8) & 0xFF, src_ref & 0xFF

    # Classe 0, sans options spéciales
    class_and_opts = 0x00

    # Paramètre TPDU size: code 0xC0, length 0x01, value tpdu_size
    if not (0 <= tpdu_size <= 0xFF):
        raise ValueError("tpdu_size doit tenir sur 1 octet")

    # Called TSAP (C2 02 00 01) et Calling TSAP (C1 02 00 01)
    if not (0 <= called_tsap <= 0xFFFF and 0 <= calling_tsap <= 0xFFFF):
        raise ValueError("called_tsap/calling_tsap doivent tenir sur 2 octets")

    cts_hi, cts_lo = (called_tsap >> 8) & 0xFF, called_tsap & 0xFF
    cls_hi, cls_lo = (calling_tsap >> 8) & 0xFF, calling_tsap & 0xFF

    return bytes(
        [
            li,
            pdu_type,
            dst_hi,
            dst_lo,
            src_hi,
            src_lo,
            class_and_opts,
            0xC0,
            0x01,
            tpdu_size,
            0xC2,
            0x02,
            cts_hi,
            cts_lo,
            0xC1,
            0x02,
            cls_hi,
            cls_lo,
        ]
    )


def _parse_cc_tpdu(pdu: bytes) -> None:
    """Vérifie qu'un TPDU est bien un CC (Connection Confirm)."""
    if len(pdu) < 7:
        raise COTPError(f"CC TPDU trop court: {len(pdu)} octets")

    # pdu[0] = LI, pdu[1] = type
    li = pdu[0]
    pdu_type = pdu[1]
    if pdu_type != 0xD0:
        raise COTPError(f"PDU COTP inattendu: type=0x{pdu_type:02X}, attendu CC (0xD0)")

    # Contrôle minimal sur la longueur interne
    if li + 1 != len(pdu):
        # Certains stacks peuvent inclure des options supplémentaires; on reste tolérant
        if li + 1 > len(pdu):
            raise COTPError(
                f"Longueur CC TPDU incohérente: LI={li}, len(pdu)={len(pdu)}"
            )


def cotp_connect(
    sock: socket.socket,
    src_ref: int = 0x0001,
    dst_ref: int = 0x0000,
    tpdu_size: int = 0x0A,
    timeout: Optional[float] = 5.0,
) -> None:
    """Établit une connexion COTP sur un socket TCP déjà connecté.

    Envoie un CR TPDU et attend un CC TPDU de la part du serveur.
    """
    cr = _build_cr_tpdu(src_ref=src_ref, dst_ref=dst_ref, tpdu_size=tpdu_size)
    send_tpkt(sock, cr)

    payload = recv_tpkt(sock, timeout=timeout)
    if payload is None:
        raise COTPError("Connexion fermée lors de l'attente du CC TPDU")

    _parse_cc_tpdu(payload)


def cotp_send_data(sock: socket.socket, user_data: bytes) -> None:
    """Envoie un DT TPDU (Data) contenant user_data."""
    if not isinstance(user_data, (bytes, bytearray)):
        raise TypeError("user_data doit être bytes ou bytearray")

    # Pour MMS sur RFC 1006, la longueur TPKT porte déjà la taille du user_data.
    # Le LI COTP ne couvre donc que les octets COTP eux-mêmes (type + contrôle).
    # Trame de référence Wireshark : 02 F0 80 ...
    header = bytes([0x02, 0xF0, 0x80])
    pdu = header + user_data
    send_tpkt(sock, pdu)


def cotp_recv_data(sock: socket.socket, timeout: Optional[float] = None) -> Optional[bytes]:
    """Reçoit un DT TPDU et retourne user_data.

    Ignore les autres types de TPDU (CR, CC, DR...) côté client.
    Retourne None si la connexion est fermée proprement.
    """
    while True:
        payload = recv_tpkt(sock, timeout=timeout)
        if payload is None:
            return None
        if len(payload) < 3:
            raise COTPError(f"TPDU trop court: {len(payload)} octets")

        li = payload[0]
        pdu_type = payload[1]

        if pdu_type == 0xF0:
            # DT TPDU
            if li + 1 > len(payload):
                raise COTPError(
                    f"Longueur DT TPDU incohérente: LI={li}, len(payload)={len(payload)}"
                )
            # payload[2] = octet de contrôle, le reste est user_data
            return payload[3 : 1 + li]

        # Autres types: on ignore ou on pourrait ajouter du handling plus fin si besoin
        # 0xE0: CR, 0xD0: CC, 0x80: DR, 0xC0: DTACK, ...
        # Ici on boucle simplement pour lire le suivant.

