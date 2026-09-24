# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""tools/pcap_mms.py: TCP, TPKT and COTP reassembly on a synthetic capture."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from conftest import DATA_DIR, ROOT

from goose_ring_pcap import write_pcap

sys.path.insert(0, str(ROOT / "tools"))
import pcap_mms  # noqa: E402

IED = bytes([10, 0, 0, 2])
CLIENT = bytes([10, 0, 0, 1])


def _tcp_frame(payload: bytes, seq: int) -> bytes:
    tcp = (102).to_bytes(2, "big") + (50000).to_bytes(2, "big") + seq.to_bytes(4, "big")
    tcp += bytes(4) + bytes([0x50, 0x18]) + bytes(6)  # 20-byte header, no options
    ip = bytes([0x45, 0]) + (20 + len(tcp) + len(payload)).to_bytes(2, "big") + bytes(5)
    ip += bytes([6]) + bytes(2) + IED + CLIENT
    return bytes(12) + bytes.fromhex("0800") + ip + tcp + payload


def test_segmented_response_is_one_message(tmp_path: Path) -> None:
    segments = json.loads((DATA_DIR / "iedscout_getnamelist.json").read_text())["gnl_vars_resp_segments"]
    stream = b""
    for seg, eot in segments:
        tpdu = bytes([0x02, 0xF0, 0x80 if eot else 0x00]) + bytes.fromhex(seg)
        stream += bytes([3, 0]) + (4 + len(tpdu)).to_bytes(2, "big") + tpdu
    half = len(stream) // 2
    frames = [
        (1.0, _tcp_frame(stream[:half], 1000)),
        (1.1, _tcp_frame(stream[:half], 1000)),  # retransmission
        (1.2, _tcp_frame(stream[half:], 1000 + half)),
    ]
    path = tmp_path / "capture.pcapng"
    write_pcap(path, frames)

    messages = list(pcap_mms.mms_messages(path))
    assert len(messages) == 1
    assert not messages[0].to_server
    assert messages[0].user_data == b"".join(bytes.fromhex(seg) for seg, _ in segments)
    assert pcap_mms.describe(messages[0].user_data) == "confirmed-response getNameList invokeID=2"
