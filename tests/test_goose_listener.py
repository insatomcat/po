# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Characterization tests for the GOOSE Listener timing logic and PCAP dumps.

The trip delay is measured from kernel receive timestamps, so these tests
pin the reference-time arithmetic and the timestamp precision of the dumps.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from goose_listener_service import (
    SvFlowInfo,
    TargetTiming,
    auto_svid_for_goose,
    compute_delta_net_ms,
    extract_dep_token,
    fault_phase_s,
    is_trigger_event,
    nearest_fault_t_ref,
)
from goose_ring_pcap import GooseRingBuffer, write_pcap
from iec_data import BoolData, IntData, StructureData
from trigger_classify import classify_trigger

KEY = ("IED/LLN0$GO$gcb", "GO_1")


def test_trigger_needs_st_num_increase_and_sq_num_zero() -> None:
    assert not is_trigger_event(None, 5, 0, key=KEY, last_trigger_st={})
    assert not is_trigger_event(5, 5, 0, key=KEY, last_trigger_st={})
    assert is_trigger_event(5, 6, 0, key=KEY, last_trigger_st={})
    assert not is_trigger_event(5, 6, 2, key=KEY, last_trigger_st={})


def test_lenient_trigger_accepts_first_frame_of_new_st_num_once() -> None:
    assert is_trigger_event(5, 6, 2, key=KEY, last_trigger_st={}, lenient=True)
    assert not is_trigger_event(5, 6, 3, key=KEY, last_trigger_st={KEY: 6}, lenient=True)


@pytest.mark.parametrize(
    ("prev", "curr", "kind"),
    [
        (None, [BoolData(True)], "initial"),
        ([BoolData(False)], [BoolData(True)], "trip"),
        ([BoolData(True)], [BoolData(False)], "reset"),
        ([IntData(0)], [IntData(4)], "trip"),
        ([StructureData([BoolData(True), BoolData(False)])], [StructureData([BoolData(False), BoolData(True)])], "mixed"),
        ([BoolData(True)], [BoolData(True)], "unknown"),
    ],
)
def test_classify_trigger(prev: object, curr: object, kind: str) -> None:
    assert classify_trigger(prev, curr)[0] == kind  # type: ignore[arg-type]


def test_dep_token_matching() -> None:
    assert extract_dep_token("SSC600LD0/LLN0$GO$LDPX_GSI_DEP5_B") == "DEP5"
    flows = [
        SvFlowInfo(name="a", svid="LDTM1_SVI_DEP5", fault=True, fault_cycle_s=4, fault_smpcnt=0, fault_offset_s=0),
        SvFlowInfo(name="b", svid="LDTM1_SVI_DEP50", fault=True, fault_cycle_s=4, fault_smpcnt=0, fault_offset_s=0),
    ]
    assert auto_svid_for_goose("X/LLN0$GO$LDPX_GSI_DEP5_B", "", flows) == "LDTM1_SVI_DEP5"
    assert auto_svid_for_goose("X/LLN0$GO$LDPX_GSI_DEP6", "", flows) is None


def test_nearest_fault_reference() -> None:
    phase = fault_phase_s(smpcnt=480, offset_s=1)  # 1.1 s into a 4 s cycle
    assert phase == pytest.approx(1.1)
    assert nearest_fault_t_ref(1000.0 * 4 + 1.124, 4.0, phase) == pytest.approx(4001.1)
    assert nearest_fault_t_ref(4000.0 + 3.2, 4.0, phase) == pytest.approx(4005.1)


def test_delta_net_linked_and_unlinked() -> None:
    linked = TargetTiming(svid="SV", cycle_s=4.0, smpcnt=0, offset_s=0, phase_s=0.0, linked=True)
    delta, t_ref = compute_delta_net_ms(8.024, 0.0, linked)
    assert t_ref == 8.0 and delta == pytest.approx(24.0)
    unlinked = TargetTiming(svid=None, cycle_s=None, smpcnt=0, offset_s=0, phase_s=0.0, linked=False)
    delta, t_ref = compute_delta_net_ms(8.030, 5.0, unlinked)
    assert t_ref == 8.0 and delta == pytest.approx(25.0)


def test_ring_buffer_keeps_window() -> None:
    ring = GooseRingBuffer(window_s=4.0)
    for ts in (100.0, 102.0, 104.5, 105.0):
        ring.add(ts, b"frame")
    assert [ts for ts, _ in ring.snapshot(now=105.0)] == [102.0, 104.5, 105.0]


def _pcapng_packets(data: bytes) -> list[tuple[int, bytes]]:
    """Return (timestamp in microseconds, frame) for every Enhanced Packet Block."""
    out: list[tuple[int, bytes]] = []
    off = 0
    while off < len(data):
        block_type, block_len = struct.unpack_from("<II", data, off)
        if block_type == 6:
            _, ts_hi, ts_lo, cap_len, _ = struct.unpack_from("<IIIII", data, off + 8)
            out.append(((ts_hi << 32) | ts_lo, data[off + 28 : off + 28 + cap_len]))
        off += block_len
    return out


def test_pcap_dump_keeps_microsecond_timestamps(tmp_path: Path) -> None:
    frames = [(1767225600.023456, b"\x01" * 60), (1767225600.023789, b"\x02" * 61)]
    path = tmp_path / "dump.pcapng"
    assert write_pcap(path, frames, comment="test") == 2
    assert _pcapng_packets(path.read_bytes()) == [
        (1767225600023456, b"\x01" * 60),
        (1767225600023789, b"\x02" * 61),
    ]
