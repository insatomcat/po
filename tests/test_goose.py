# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Characterization tests for GOOSE: codec, Ethernet parsing and the stream service."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from goose61850 import service as goose_service
from goose61850.codec import decode_goose_pdu, encode_goose_pdu
from goose61850.transport import _build_frame, goose_bpf_filter, parse_ethernet_goose
from goose61850.types import GoosePDU
from iec61850.data import encode_utc_time
from iec_data import BitStringData, BoolData, FloatData, IntData, RawData, TimestampData, UIntData

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _pdu(**overrides: object) -> GoosePDU:
    fields: dict[str, object] = dict(
        gocb_ref="IED1LD0/LLN0$GO$gcb1",
        time_allowed_to_live=2000,
        dat_set="IED1LD0/LLN0$DS1",
        go_id="GOOSE_1",
        timestamp=T0,
        st_num=5,
        sq_num=3,
        simulation=False,
        conf_rev=1,
        nds_com=False,
        num_dat_set_entries=2,
        all_data=[BoolData(True), BitStringData(b"\x00\x00", 3)],
    )
    fields.update(overrides)
    return GoosePDU(**fields)  # type: ignore[arg-type]


GOLDEN_APDU = (
    "615b"
    "8014" + b"IED1LD0/LLN0$GO$gcb1".hex()
    + "810207d0"
    + "8210" + b"IED1LD0/LLN0$DS1".hex()
    + "8307" + b"GOOSE_1".hex()
    + "84086955b90000000000"
    + "850105" "860103" "870100" "880101" "890100" "8a0102"
    + "ab08" "8301ff" "8403030000"
)


def test_encode_golden() -> None:
    assert encode_goose_pdu(_pdu()).hex() == GOLDEN_APDU


def test_decode_golden() -> None:
    assert decode_goose_pdu(bytes.fromhex(GOLDEN_APDU)) == _pdu()


def test_round_trip_all_data_types() -> None:
    pdu = _pdu(all_data=[IntData(-129), UIntData(70000), FloatData(1.5)], num_dat_set_entries=3)
    assert decode_goose_pdu(encode_goose_pdu(pdu)) == pdu


def test_encode_without_go_id() -> None:
    decoded = decode_goose_pdu(encode_goose_pdu(_pdu(go_id=None)))
    assert decoded.go_id is None


def test_timestamp_fraction_round_trip() -> None:
    t = datetime(2026, 1, 1, 0, 0, 0, 500000, tzinfo=timezone.utc)
    assert decode_goose_pdu(encode_goose_pdu(_pdu(timestamp=t))).timestamp == t


def _ethernet(apdu: bytes, *, app_id: int = 0x0100, vlan: bool) -> bytes:
    dst = bytes.fromhex("010ccd010001")
    src = bytes.fromhex("0002a3000001")
    header = app_id.to_bytes(2, "big") + (8 + len(apdu)).to_bytes(2, "big") + b"\x00" * 4
    tag = bytes.fromhex("8100" "8064") if vlan else b""  # prio 4, VLAN 100
    return dst + src + tag + bytes.fromhex("88b8") + header + apdu


@pytest.mark.parametrize("vlan", [False, True])
def test_parse_ethernet_goose(vlan: bool) -> None:
    apdu = bytes.fromhex(GOLDEN_APDU)
    parsed = parse_ethernet_goose(_ethernet(apdu, vlan=vlan) + b"\x00\x00")  # Ethernet padding
    assert parsed == (
        "01:0c:cd:01:00:01",
        "00:02:a3:00:00:01",
        0x0100,
        100 if vlan else None,
        0x88B8,
        apdu,
    )


def test_build_frame_with_vlan_matches_former_scapy_output() -> None:
    # Bytes produced by scapy Ether()/Dot1Q(prio=4, vlan=100, type=0x88b8)/Raw(...).
    frame = _build_frame("01:0C:CD:01:00:01", "00:02:a3:00:00:01", 0x100, _pdu(), vlan_id=100, vlan_priority=4)
    assert frame[:18].hex() == "010ccd0100010002a30000018100806488b8"
    assert frame[18:26].hex() == "0100" + f"{8 + len(bytes.fromhex(GOLDEN_APDU)):04x}" + "00000000"
    assert frame[26:].hex() == GOLDEN_APDU


def test_build_frame_without_vlan_uses_goose_ethertype() -> None:
    # scapy used to leave the EtherType at its 0x9000 default here.
    frame = _build_frame("01:0c:cd:01:00:01", "00:02:a3:00:00:01", 0x100, _pdu())
    assert frame[12:14].hex() == "88b8"
    assert parse_ethernet_goose(frame) is not None


def test_parse_ethernet_rejects_other_ethertypes() -> None:
    frame = bytearray(_ethernet(bytes.fromhex(GOLDEN_APDU), vlan=False))
    frame[12:14] = bytes.fromhex("88ba")
    assert parse_ethernet_goose(bytes(frame)) is None


def test_bpf_filter() -> None:
    assert goose_bpf_filter() == "(ether proto 0x88b8) or (vlan and ether proto 0x88b8)"
    assert goose_bpf_filter(0x100) == (
        "(ether proto 0x88b8 and ether[14:2]=0x0100) or "
        "(vlan and ether proto 0x88b8 and ether[18:2]=0x0100)"
    )


# --- stream service ---------------------------------------------------------


@pytest.fixture
def service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> goose_service.GooseService:
    monkeypatch.setattr(goose_service, "STREAMS_PATH", tmp_path / "streams.json")
    monkeypatch.setattr(goose_service, "RECENTS_PATH", tmp_path / "recents.json")
    return goose_service.GooseService()


STREAM_CONFIG = {
    "iface": "eth0",
    "src_mac": "00:02:a3:00:00:01",
    "dst_mac": "01:0c:cd:01:00:01",
    "app_id": 0x100,
    "gocb_ref": "IED1LD0/LLN0$GO$gcb1",
    "dat_set": "IED1LD0/LLN0$DS1",
    "go_id": "GOOSE_1",
    "all_data": [True, {"bit-string": "0000", "unused": 3}, ["raw", 17, "0000000000000000"]],
}


def test_stream_persistence_round_trip(service: goose_service.GooseService, tmp_path: Path) -> None:
    stream = service.add_stream(dict(STREAM_CONFIG))
    assert (tmp_path / "streams.json").exists()
    stream.sq_num = 42
    service._save_state()
    reloaded = goose_service.GooseService().get_stream(stream.id)
    assert reloaded is not None
    assert reloaded.all_data == stream.all_data
    # A restarted publisher sends a new state: stNum + 1, sqNum 0, a new t.
    assert (reloaded.st_num, reloaded.sq_num) == (2, 0)
    assert reloaded.changed_at > stream.changed_at


def test_to_pdu_refreshes_embedded_times(service: goose_service.GooseService) -> None:
    stream = service.add_stream(dict(STREAM_CONFIG))
    pdu = stream.to_pdu()
    utc = pdu.all_data[2]
    assert isinstance(utc, RawData) and utc.tag == 0x91
    secs = int.from_bytes(utc.value[:4], "big")
    assert abs(secs - time.time()) < 5
    assert pdu.num_dat_set_entries == 3
    assert pdu.all_data[0] == BoolData(True)


def test_timestamp_data_in_all_data_is_refreshed(service: goose_service.GooseService) -> None:
    stream = service.add_stream(dict(STREAM_CONFIG))
    stream.all_data = [TimestampData(T0)]
    refreshed = stream.to_pdu().all_data[0]
    assert isinstance(refreshed, TimestampData) and refreshed.value > T0


def test_modify_stream_bumps_st_num(service: goose_service.GooseService) -> None:
    stream = service.add_stream(dict(STREAM_CONFIG))
    service.modify_stream(stream.id, {"all_data": [False]})
    assert stream.st_num == 2
    assert stream.all_data == [BoolData(False)]


def test_modify_stream_resets_sq_num(service: goose_service.GooseService) -> None:
    stream = service.add_stream(dict(STREAM_CONFIG))
    stream.sq_num = 7
    service.modify_stream(stream.id, {"all_data": [False]})
    assert stream.sq_num == 0


def test_t_is_stable_between_retransmissions(service: goose_service.GooseService) -> None:
    # IEC 61850-8-1: t is the time of the last stNum change.
    stream = service.add_stream(dict(STREAM_CONFIG))
    first = stream.to_pdu().timestamp
    time.sleep(0.01)
    assert stream.to_pdu().timestamp == first


def test_retransmissions_differ_only_by_sq_num(service: goose_service.GooseService) -> None:
    stream = service.add_stream(dict(STREAM_CONFIG))
    now = time.monotonic()
    (_, first), = service._due_frames(now)
    assert service._due_frames(now) == []  # next one is 10 ms later
    (_, second), = service._due_frames(now + 0.011)
    assert (first.sq_num, second.sq_num) == (0, 1)
    assert second.st_num == first.st_num and second.timestamp == first.timestamp
    assert second.all_data == first.all_data
    assert stream.current_interval_ms == 40.0  # 10, 20, then 40 ms

    time.sleep(0.01)
    service.modify_stream(stream.id, {"all_data": [False, 3, ["raw", 145, "00" * 8]]})
    (_, changed), = service._due_frames(time.monotonic())
    assert (changed.st_num, changed.sq_num) == (2, 0)
    assert changed.timestamp > first.timestamp
    assert changed.all_data[2].value[:4] == encode_utc_time(changed.timestamp)[:4]  # type: ignore[union-attr]
    assert stream.current_interval_ms == 20.0


def test_restart_from_recent_is_a_new_state(service: goose_service.GooseService) -> None:
    stream = service.add_stream(dict(STREAM_CONFIG))
    stream.st_num, stream.sq_num = 5, 99
    service.delete_stream(stream.id)
    assert service.restart_from_recent(stream.id)
    (restarted,) = service.list_streams()
    assert (restarted.st_num, restarted.sq_num) == (6, 0)
    assert restarted.changed_at > stream.changed_at
