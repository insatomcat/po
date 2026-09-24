#!/usr/bin/env python3
# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""List the MMS PDUs of a pcap/pcapng capture (ISO-on-TCP, port 102).

TCP streams are reassembled per direction, TPKT and COTP are unwrapped and
segmented TSDUs are joined on the EOT bit. Each line shows the direction,
the PDU kind, the MMS service and the invokeID. Stdlib only.

Usage:
    python3 tools/pcap_mms.py capture.pcapng [--hex] [--service getNameList]
"""

from __future__ import annotations

import argparse
import struct
import sys
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from iec61850 import ber  # noqa: E402

SESSION_DATA = b"\x01\x00\x01\x00"
PDU_KINDS = {
    0xA0: "confirmed-request", 0xA1: "confirmed-response", 0xA2: "confirmed-error",
    0xA3: "unconfirmed", 0xA4: "reject", 0xA8: "initiate-request", 0xA9: "initiate-response",
    0xAB: "conclude-request", 0xAC: "conclude-response",
}
SERVICES = {
    0: "status", 1: "getNameList", 2: "identify", 4: "read", 5: "write",
    6: "getVariableAccessAttributes", 11: "defineNamedVariableList",
    12: "getNamedVariableListAttributes", 13: "deleteNamedVariableList",
    72: "fileOpen", 73: "fileRead", 74: "fileClose", 77: "fileDirectory",
}


@dataclass
class MmsMessage:
    ts: float
    to_server: bool
    user_data: bytes  # COTP user data: session + presentation + MMS


def _packets(data: bytes) -> Iterator[tuple[float, bytes]]:
    """Ethernet frames of a pcapng or classic pcap file."""
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        off, linktypes = 0, []
        while off + 12 <= len(data):
            btype, blen = struct.unpack_from("<II", data, off)
            body = data[off + 8 : off + blen - 4]
            if btype == 1:
                linktypes.append(struct.unpack_from("<H", body, 0)[0])
            elif btype == 6:
                iface, hi, lo, caplen, _ = struct.unpack_from("<IIIII", body, 0)
                if linktypes[iface] == 1:
                    yield ((hi << 32) | lo) / 1e6, body[20 : 20 + caplen]
            off += blen
        return
    endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = data[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    off = 24
    while off + 16 <= len(data):
        sec, frac, caplen, _ = struct.unpack_from(endian + "IIII", data, off)
        yield sec + frac / (1e9 if nano else 1e6), data[off + 16 : off + 16 + caplen]
        off += 16 + caplen


def mms_messages(path: Path, port: int = 102) -> Iterator[MmsMessage]:
    streams: dict[tuple, dict] = defaultdict(lambda: {"next": None, "buf": b"", "tsdu": b""})
    for ts, pkt in _packets(path.read_bytes()):
        o = 14
        ethertype = int.from_bytes(pkt[12:14], "big")
        if ethertype == 0x8100:
            ethertype, o = int.from_bytes(pkt[16:18], "big"), 18
        if ethertype != 0x0800 or pkt[o + 9] != 6:
            continue
        total = int.from_bytes(pkt[o + 2 : o + 4], "big")
        t = o + (pkt[o] & 0x0F) * 4
        sport, dport, seq = struct.unpack_from("!HHI", pkt, t)
        payload = pkt[t + (pkt[t + 12] >> 4) * 4 : o + total]
        if port not in (sport, dport) or not payload:
            continue
        key = (pkt[o + 12 : o + 16], sport, pkt[o + 16 : o + 20], dport)
        st = streams[key]
        if st["next"] is not None and seq < st["next"]:
            skip = st["next"] - seq
            if skip >= len(payload):
                continue  # retransmission
            payload, seq = payload[skip:], st["next"]
        st["next"] = seq + len(payload)
        st["buf"] += payload
        while len(st["buf"]) >= 4 and st["buf"][0] == 3:
            n = int.from_bytes(st["buf"][2:4], "big")
            if len(st["buf"]) < n:
                break
            tpdu, st["buf"] = st["buf"][4:n], st["buf"][n:]
            if len(tpdu) < 3 or tpdu[1] != 0xF0:
                continue
            st["tsdu"] += tpdu[3:]
            if tpdu[2] & 0x80:
                yield MmsMessage(ts, dport == port, st["tsdu"])
                st["tsdu"] = b""


def describe(user_data: bytes) -> str:
    if not user_data.startswith(SESSION_DATA):
        return f"session SPDU 0x{user_data[0]:02x} ({len(user_data)} bytes)"
    try:
        pres = ber.decode_tlv(user_data, len(SESSION_DATA))
        pdv = list(ber.iter_tlvs(ber.decode_tlv(pres.value).value))
        pdu = ber.decode_tlv(pdv[-1].value)
    except ber.BerError as exc:
        return f"undecodable ({exc})"
    kind = PDU_KINDS.get(pdu.tag, f"0x{pdu.tag:x}")
    if pdu.tag in (0xA0, 0xA1):
        invoke, service = list(ber.iter_tlvs(pdu.value))[:2]
        number = ber.tag_number(service.tag)
        return f"{kind} {SERVICES.get(number, f'service[{number}]')} invokeID={ber.decode_integer(invoke.value)}"
    if pdu.tag == 0xA2:
        invoke = ber.decode_tlv(pdu.value)
        return f"{kind} invokeID={ber.decode_unsigned(invoke.value)}"
    return kind


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("capture", type=Path)
    parser.add_argument("--hex", action="store_true", help="print the COTP user data in hex")
    parser.add_argument("--service", help="only show PDUs whose description contains this text")
    parser.add_argument("--port", type=int, default=102)
    args = parser.parse_args()
    for msg in mms_messages(args.capture, args.port):
        text = describe(msg.user_data)
        if args.service and args.service not in text:
            continue
        print(f"{msg.ts:.6f} {'>' if msg.to_server else '<'} {len(msg.user_data):6d}  {text}")
        if args.hex:
            print(f"    {msg.user_data.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
