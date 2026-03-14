#!/usr/bin/env python3
"""
IEC 61850-9-2 / 61869-9 SV receiver (BER) en mode service web uniquement.

- Écoute soit :
  - sur une interface Ethernet brute (ethertype 0x88ba), ou
  - sur un port UDP,
  selon les variables d'environnement :
    SVRECV_INTERFACE=<iface>    (ex: processbus)
    SVRECV_UDP_PORT=<port>      (ex: 5000)
  Si les deux sont définis, l'interface Ethernet est prioritaire.

- Expose une API FastAPI pour consulter les derniers paquets et statistiques.
"""

from __future__ import annotations

import os
import socket
import struct
import threading
import time
from typing import List, Optional

from fastapi import FastAPI
from pydantic import BaseModel


ETH_HEADER_LEN = 14  # dst(6) + src(6) + ethertype(2)
ETH_P_61850_SV = 0x88BA


def mac_fmt(b: bytes) -> str:
    if len(b) < 6:
        return "??:??:??:??:??:??"
    return ":".join(f"{x:02x}" for x in b[:6])


def read_ber_tag_len(data: bytes, off: int):
    if off >= len(data):
        return None, 0, off
    tag = data[off]
    off += 1
    L = data[off]
    off += 1
    if L & 0x80:
        n = L & 0x7F
        L = 0
        for _ in range(n):
            if off >= len(data):
                return tag, 0, off
            L = (L << 8) | data[off]
            off += 1
    return tag, L, off


def parse_sv_packet(data: bytes):
    """
    Parse SV payload (8-byte header + savPdu), yield (svID, smpCnt) per ASDU.
    """
    if len(data) < 8:
        return
    off = 8

    tag, sav_len, off = read_ber_tag_len(data, off)
    if tag != 0x60:
        return
    sav_end = off + sav_len
    if sav_end > len(data):
        return

    tag, no_len, off = read_ber_tag_len(data, off)
    if tag != 0x80 or no_len != 1 or off >= len(data):
        return
    no_asdu = data[off]
    off += 1

    tag, seq_len, off = read_ber_tag_len(data, off)
    if tag != 0xA2:
        return
    seq_end = off + seq_len
    if seq_end > len(data):
        return

    for _ in range(no_asdu):
        if off >= seq_end:
            break
        tag, asdu_len, off = read_ber_tag_len(data, off)
        if tag != 0x30:
            off += asdu_len
            continue
        asdu_end = off + asdu_len
        svid = None
        smp_cnt = None
        while off < asdu_end:
            t, L, off = read_ber_tag_len(data, off)
            if off + L > len(data):
                break
            val = data[off : off + L]
            off += L
            if t == 0x80:
                svid = val.decode("utf-8", errors="replace")
            elif t == 0x82 and L == 2:
                smp_cnt = struct.unpack("!H", val)[0]
        if svid is not None and smp_cnt is not None:
            yield svid, smp_cnt


class PacketInfo(BaseModel):
    timestamp: float
    offset_ms: float
    svid: str
    smp_cnts: List[int]
    src: str
    dst: Optional[str]


class SvidStats(BaseModel):
    svid: str
    last_timestamp: float
    last_offset_ms: float
    last_smp_cnt: int
    packet_count: int


app = FastAPI(title="SV Receiver Service")

_packets_lock = threading.Lock()
_packets: list[PacketInfo] = []
_max_packets = 5000

_svid_stats: dict[str, SvidStats] = {}


def _record_packet(info: PacketInfo) -> None:
    with _packets_lock:
        _packets.append(info)
        if len(_packets) > _max_packets:
            # on garde un buffer circulaire simple
            del _packets[: len(_packets) - _max_packets]

        st = _svid_stats.get(info.svid)
        last_smp = info.smp_cnts[-1] if info.smp_cnts else -1
        if st is None:
            _svid_stats[info.svid] = SvidStats(
                svid=info.svid,
                last_timestamp=info.timestamp,
                last_offset_ms=info.offset_ms,
                last_smp_cnt=last_smp,
                packet_count=1,
            )
        else:
            st.last_timestamp = info.timestamp
            st.last_offset_ms = info.offset_ms
            st.last_smp_cnt = last_smp
            st.packet_count += 1


def _receiver_loop(interface: Optional[str], udp_port: Optional[int]) -> None:
    if interface:
        sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_61850_SV)
        )
        sock.bind((interface, 0))
        source_desc = f"raw-eth:{interface}"
    elif udp_port:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", udp_port))
        source_desc = f"udp:{udp_port}"
    else:
        # Pas de configuration : on ne démarre pas de boucle.
        return

    while True:
        data, addr = sock.recvfrom(65535)
        recv_time = time.time()

        if interface:
            if len(data) < ETH_HEADER_LEN:
                continue
            dst_mac = mac_fmt(data[0:6])
            src_mac = mac_fmt(data[6:12])
            payload = data[ETH_HEADER_LEN:]
            src_desc = src_mac
            dst_desc = dst_mac
        else:
            payload = data
            src_desc = f"{addr[0]}:{addr[1]}"
            dst_desc = None

        asdus = list(parse_sv_packet(payload))
        if not asdus:
            continue

        round_sec = int(recv_time)
        offset_in_sec = recv_time - round_sec
        offset_ms = offset_in_sec * 1e3

        svid = asdus[0][0]
        smp_cnts = [c for _, c in asdus]

        info = PacketInfo(
            timestamp=recv_time,
            offset_ms=offset_ms,
            svid=svid,
            smp_cnts=smp_cnts,
            src=src_desc,
            dst=dst_desc,
        )
        _record_packet(info)


@app.on_event("startup")
def _on_startup() -> None:
    iface = os.environ.get("SVRECV_INTERFACE") or None
    port_str = os.environ.get("SVRECV_UDP_PORT")
    udp_port: Optional[int] = None
    if port_str:
        try:
            udp_port = int(port_str)
        except ValueError:
            udp_port = None

    t = threading.Thread(
        target=_receiver_loop,
        args=(iface, udp_port),
        name="sv-receiver-loop",
        daemon=True,
    )
    t.start()


@app.get("/packets", response_model=list[PacketInfo])
def get_packets(limit: int = 100) -> list[PacketInfo]:
    if limit <= 0:
        limit = 1
    with _packets_lock:
        if not _packets:
            return []
        return list(_packets[-limit:])


@app.get("/stats", response_model=list[SvidStats])
def get_stats() -> list[SvidStats]:
    with _packets_lock:
        return list(_svid_stats.values())

