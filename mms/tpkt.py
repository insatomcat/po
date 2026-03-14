"""TPKT (RFC 1006) helper for MMS / ISO-on-TCP.

Cette couche encapsule le payload ISO (COTP, ACSE, MMS, ...) dans un en-tête
TPKT de 4 octets au-dessus d'un socket TCP Python standard.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional


TPKT_VERSION = 0x03


class TPKTError(RuntimeError):
    """Erreur générique TPKT."""


def send_tpkt(sock: socket.socket, payload: bytes) -> None:
    """Envoie un PDU ISO dans un TPKT au-dessus de TCP.

    payload est le contenu ISO brut (COTP, ACSE, MMS...).
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload doit être de type bytes ou bytearray")

    length = 4 + len(payload)
    if length > 0xFFFF:
        raise TPKTError(f"TPKT trop long ({length} octets)")

    header = struct.pack("!BBH", TPKT_VERSION, 0x00, length)
    sock.sendall(header + payload)


def recv_tpkt(sock: socket.socket, timeout: Optional[float] = None) -> Optional[bytes]:
    """Lit un TPKT complet et retourne le payload ISO (sans l'en-tête).

    Retourne None si la connexion est fermée proprement par le pair.
    Lève TPKTError en cas d'incohérence.
    """
    old_timeout = sock.gettimeout()
    if timeout is not None:
        sock.settimeout(timeout)

    try:
        header = _recv_exact(sock, 4)
        if not header:
            return None

        ver, reserved, length = struct.unpack("!BBH", header)
        if ver != TPKT_VERSION:
            raise TPKTError(f"Version TPKT inattendue: {ver!r}")
        if reserved != 0x00:
            raise TPKTError(f"Octet réservé TPKT inattendu: {reserved!r}")
        if length < 4:
            raise TPKTError(f"Longueur TPKT invalide: {length}")

        to_read = length - 4
        if to_read == 0:
            return b""

        payload = _recv_exact(sock, to_read)
        if payload is None:
            return None
        if len(payload) != to_read:
            raise TPKTError(
                f"Payload TPKT tronqué: attendu {to_read} octets, reçu {len(payload)}"
            )
        return payload
    finally:
        if timeout is not None:
            sock.settimeout(old_timeout)


def _recv_exact(sock: socket.socket, size: int) -> Optional[bytes]:
    """Lit exactement size octets ou None si EOF avant."""
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

