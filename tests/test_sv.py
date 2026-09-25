# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Characterization tests for Sampled Values parsing and the rt_sender frame layout."""

from __future__ import annotations

import math
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

import sv_listener_view as svl
from parse_ref_pkt import REF
from processbus_capture import ethertypes_for_modes, frame_ethertype

ROOT = Path(__file__).resolve().parent.parent


def _asdu(svid: str, smp_cnt: int, conf_rev: int, smp_synch: int, seq_data: bytes) -> bytes:
    """ASDU exactly as rt_sender.c ber_encode_asdu() lays it out."""
    body = (
        bytes([0x80, len(svid)]) + svid.encode()
        + bytes([0x82, 2]) + smp_cnt.to_bytes(2, "big")
        + bytes([0x83, 4]) + conf_rev.to_bytes(4, "big")
        + bytes([0x85, 1, smp_synch])
        + bytes([0x87, len(seq_data)]) + seq_data
    )
    return _tl(0x30, len(body)) + body


def _tl(tag: int, length: int) -> bytes:
    return bytes([tag, length]) if length < 128 else bytes([tag, 0x81, length])


def _sv_payload(appid: int, asdus: list[bytes]) -> bytes:
    """8-byte SV header + savPdu, as rt_sender.c ber_build_sv_packet()."""
    seq = b"".join(asdus)
    sav = bytes([0x80, 1, len(asdus)]) + _tl(0xA2, len(seq)) + seq
    apdu = _tl(0x60, len(sav)) + sav
    return appid.to_bytes(2, "big") + (8 + len(apdu)).to_bytes(2, "big") + bytes(4) + apdu


def _seq_data_6i3u(values: list[int]) -> bytes:
    return b"".join(struct.pack("!iI", v, 0) for v in values)


def test_reference_packet_4i4u() -> None:
    asdus = svl.parse_sv_asdus_with_seqdata(REF)
    assert asdus == [
        ("LDTM1_SVI_DEP3", 0x11B8, [0] * 9),
        ("LDTM1_SVI_DEP3", 0x11B9, [0] * 9),
    ]


def test_6i3u_payload() -> None:
    vals0 = [1000, -500, -500, 0, 0, 0, 10000, -5000, -5000]
    vals1 = [i + 1 for i in range(9)]
    payload = _sv_payload(
        0x4060,
        [
            _asdu("SV_1", 0, 10000, 2, _seq_data_6i3u(vals0)),
            _asdu("SV_1", 1, 10000, 2, _seq_data_6i3u(vals1)),
        ],
    )
    assert svl.parse_sv_asdus_with_seqdata(payload) == [("SV_1", 0, vals0), ("SV_1", 1, vals1)]


def test_4i4u_is_mapped_to_nine_channels() -> None:
    vals = [1, 2, 3, 4, 5, 6, 7, 8]
    payload = _sv_payload(0x4000, [_asdu("X", 7, 1, 0, b"".join(struct.pack("!iI", v, 0) for v in vals))])
    # Ia Ib Ic In -> Ia Ib Ic Ires, In and Ih are zero, Va Vb Vc; Vn is dropped.
    assert svl.parse_sv_asdus_with_seqdata(payload) == [("X", 7, [1, 2, 3, 4, 0, 0, 5, 6, 7])]


def test_parse_sv_frame_handles_vlan() -> None:
    payload = _sv_payload(0x4000, [_asdu("SV_1", 3, 1, 2, _seq_data_6i3u(list(range(9))))])
    plain = bytes(12) + bytes.fromhex("88ba") + payload
    tagged = bytes(12) + bytes.fromhex("81008064") + bytes.fromhex("88ba") + payload
    assert svl.parse_sv_frame(plain) == svl.parse_sv_frame(tagged) == [("SV_1", 3, list(range(9)))]
    assert svl.parse_sv_frame(bytes(12) + bytes.fromhex("88b8") + payload) == []


def _stats() -> dict:
    from collections import deque

    return {
        "parse_errors": 0, "sv_packets": 0, "asdu_seen": 0, "last_pkt_time": None, "packet_timestamps": deque(),
        "misses_all": 0, "misses_events": deque(), "last_smpcnt": None, "min_delay_all": 1e9, "max_delay_all": 0,
        "min_delay_sync_all": 1e9, "max_delay_sync_all": 0, "smpcnt0_timestamps": deque(),
    }


def _frame(svid: str, dst_last: int, smp_cnt: int = 1) -> bytes:
    payload = _sv_payload(0x4000 + dst_last, [_asdu(svid, smp_cnt, 1, 2, _seq_data_6i3u(list(range(9))))])
    return bytes([1, 0x0C, 0xCD, 4, 0, dst_last]) + bytes(6) + bytes.fromhex("8100a069") + bytes.fromhex("88ba") + payload


def _feed(frames: list[bytes], config: dict, stats: dict, samples: list, seen: set) -> None:
    import threading

    for raw in frames:
        svl.process_sv_frame(raw, 0.0, samples, threading.Lock(), stats, threading.Lock(), config, seen, threading.Lock())


def test_malformed_frame_counts_a_parse_error() -> None:
    svl._KNOWN_STREAMS.clear()
    payload = _sv_payload(0x4000, [_asdu("SV_1", 3, 1, 2, _seq_data_6i3u(list(range(9))))])
    broken = bytes(12) + bytes.fromhex("88ba") + payload[:8] + payload[8:].replace(b"\x80\x01\x01", b"\x80\x01\x02", 1)
    stats = _stats()
    _feed([broken], {"svid": "SV_1"}, stats, [], set())
    assert stats["parse_errors"] == 1 and stats["sv_packets"] == 0
    assert "noASDU=2" in stats["last_error"]


def test_only_the_selected_stream_is_decoded(monkeypatch: pytest.MonkeyPatch) -> None:
    svl._KNOWN_STREAMS.clear()
    decoded: list[int] = []
    real = svl.sv_codec.decode_sv_frame
    monkeypatch.setattr(svl.sv_codec, "decode_sv_frame", lambda raw: decoded.append(raw[5]) or real(raw))
    stats, samples, seen = _stats(), [], set()
    frames = [_frame("OTHER", 0x10, n) for n in range(3)] + [_frame("MINE", 0x20, n) for n in range(3)]
    _feed(frames, {"svid": "MINE"}, stats, samples, seen)
    assert decoded == [0x10, 0x20, 0x20, 0x20]  # OTHER once, to learn its svID
    assert seen == {"OTHER", "MINE"}
    assert (stats["sv_packets"], stats["asdu_seen"]) == (6, 6)
    assert [smp for smp, _ in samples] == [0, 1, 2]

    for key, (svids, count, _) in list(svl._KNOWN_STREAMS.items()):  # past the refresh time
        svl._KNOWN_STREAMS[key] = (svids, count, 0.0)
    _feed([_frame("OTHER", 0x10)], {"svid": "MINE"}, stats, samples, seen)
    assert decoded[-1] == 0x10


def test_phasor_of_a_50hz_sine() -> None:
    samples = [
        (n, [100.0 * math.sin(2 * math.pi * 50 * n / 4800 + 0.5)] + [0.0] * 8)
        for n in range(96)
    ]
    mag, phase = svl.compute_phasor_from_samples(samples, 0)
    assert mag == pytest.approx(100.0, rel=1e-9)
    assert phase == pytest.approx(0.5 - math.pi / 2, abs=1e-9)


def test_frame_ethertype_and_filter_modes() -> None:
    assert frame_ethertype(bytes(12) + bytes.fromhex("88ba")) == 0x88BA
    assert frame_ethertype(bytes(12) + bytes.fromhex("8100806488b8")) == 0x88B8
    assert frame_ethertype(bytes(10)) is None
    assert ethertypes_for_modes(goose=True, sv=False) == ((0x88B8,), "goose")
    assert ethertypes_for_modes(goose=False, sv=True) == ((0x88BA,), "sv")
    assert ethertypes_for_modes(goose=True, sv=True) == ((0x88B8, 0x88BA), "goose+sv")
    assert ethertypes_for_modes(goose=False, sv=False) == ((0x88B8,), "idle")


# --- rt_sender.c (Linux only) ----------------------------------------------


@pytest.fixture(scope="module")
def rt_sender(tmp_path_factory: pytest.TempPathFactory) -> Path:
    cc = shutil.which("cc") or shutil.which("gcc")
    if not sys.platform.startswith("linux") or cc is None:
        pytest.skip("rt_sender builds on Linux only")
    out = tmp_path_factory.mktemp("rt_sender") / "rt_sender"
    subprocess.run([cc, "-O2", "-o", str(out), str(ROOT / "svgenerator" / "rt_sender.c"), "-lm"], check=True)
    return out


def _dump(binary: Path, *args: str) -> bytes:
    proc = subprocess.run(
        [str(binary), "--dump", "--appid", "0x4060", "--conf-rev", "10000", "--smp-synch", "2",
         *args, "lo", "00:00:00:00:00:01", "01:0c:cd:04:00:01", "SV_1"],
        capture_output=True, text=True, check=True,
    )
    hex_lines = [line.split(":", 1)[1] for line in proc.stderr.splitlines() if line.startswith("  0")]
    return bytes.fromhex("".join(hex_lines).replace(" ", ""))


def test_rt_sender_dump_zero(rt_sender: Path) -> None:
    payload = _dump(rt_sender, "--zero")
    expected = _sv_payload(
        0x4060,
        [
            _asdu("SV_1", 0, 10000, 2, _seq_data_6i3u([0] * 9)),
            _asdu("SV_1", 1, 10000, 2, _seq_data_6i3u([0] * 9)),
        ],
    )
    assert payload == expected


def test_rt_sender_dump_sine_scaling(rt_sender: Path) -> None:
    payload = _dump(rt_sender, "--freq", "50", "--i-peak", "10", "--v-peak", "100")
    (_, cnt0, vals0), (_, cnt1, vals1) = svl.parse_sv_asdus_with_seqdata(payload)
    assert (cnt0, cnt1) == (0, 1)
    assert vals0 == [0, -8660, 8660, 0, 0, 0, 0, -8660, 8660]
    angle = 2 * math.pi * 50 / 4800
    assert vals1[0] == round(10 * math.sin(angle) * 1000)
    assert vals1[6] == round(100 * math.sin(angle) * 100)
