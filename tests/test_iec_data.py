# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Characterization tests for the shared MMS Data model (iec_data.py)."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

import pytest

from iec_data import (
    ArrayData,
    BitStringData,
    BoolData,
    FloatData,
    IntData,
    MmsStringData,
    OctetStringData,
    RawData,
    StructureData,
    TimestampData,
    UIntData,
    VisibleStringData,
    decode_iec_data,
    decode_iec_data_at,
    decode_iec_data_sequence,
    encode_iec_data,
    iec_data_from_json,
    iec_data_to_json,
)


@pytest.mark.parametrize(
    ("value", "encoded"),
    [
        (BoolData(True), "8301ff"),
        (BoolData(False), "830100"),
        (IntData(0), "850100"),
        (IntData(127), "85017f"),
        (IntData(128), "85020080"),
        (IntData(-1), "8501ff"),
        (IntData(-129), "8502ff7f"),
        (UIntData(0), "860100"),
        (UIntData(255), "8601ff"),
        (UIntData(2000), "860207d0"),
        (FloatData(1.5), "8705083fc00000"),
        (BitStringData(b"\xc0", 6), "840206c0"),
        (OctetStringData(b"\x13\xd5\xc0\x07"), "890413d5c007"),
        (VisibleStringData("LD0"), "8a034c4430"),
        (MmsStringData("é"), "8f02c3a9"),
    ],
)
def test_encode_primitive(value: object, encoded: str) -> None:
    assert encode_iec_data(value).hex() == encoded  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "value",
    [
        BoolData(True),
        IntData(-129),
        UIntData(70000),
        FloatData(1.5),
        BitStringData(b"\x06\x80", 0),
        OctetStringData(b"\x00\x01"),
        VisibleStringData("CBCSWI1$CO$Pos$Oper"),
        StructureData([BoolData(False), StructureData([IntData(3)]), UIntData(1)]),
        ArrayData([IntData(1), IntData(2)]),
    ],
)
def test_round_trip(value: object) -> None:
    encoded = encode_iec_data(value)  # type: ignore[arg-type]
    decoded, end = decode_iec_data_at(encoded, 0)
    assert end == len(encoded)
    assert decoded == value


def test_long_form_length_round_trip() -> None:
    value = OctetStringData(bytes(300))
    encoded = encode_iec_data(value)
    assert encoded[:4].hex() == "8982012c"
    assert decode_iec_data_at(encoded, 0)[0] == value


def test_decode_utc_time() -> None:
    # 2026-01-01T00:00:00.5Z, quality byte 0x0a
    raw = (1767225600).to_bytes(4, "big") + (1 << 23).to_bytes(3, "big") + b"\x0a"
    decoded = decode_iec_data(0x91, raw)
    assert decoded == TimestampData(datetime(2026, 1, 1, 0, 0, 0, 500000, tzinfo=timezone.utc))


def test_decode_binary_time() -> None:
    # 1984-01-02 00:00:01.250: 1250 ms of day, day 1 since 1984-01-01.
    raw = (1250).to_bytes(4, "big") + (1).to_bytes(2, "big")
    decoded = decode_iec_data(0x8C, raw)
    assert decoded == TimestampData(datetime(1984, 1, 2, 0, 0, 1, 250000, tzinfo=timezone.utc))


def test_decode_float64() -> None:
    raw = b"\x0b" + struct.pack("!d", 1.25)
    assert decode_iec_data(0x87, raw) == FloatData(1.25)


def test_unknown_tag_is_kept_raw() -> None:
    assert decode_iec_data(0x9F, b"\x01") == RawData(0x9F, b"\x01")


def test_sequence_stops_on_truncated_tlv() -> None:
    data = bytes.fromhex("8301ff" "8505")  # second TLV claims 5 bytes, has 0
    assert decode_iec_data_sequence(data) == [BoolData(True)]


def test_json_mapping() -> None:
    value = StructureData(
        [
            BoolData(True),
            IntData(-3),
            BitStringData(b"\x06\x80", 0),
            OctetStringData(b"\xab"),
            ArrayData([UIntData(1)]),
        ]
    )
    as_json = iec_data_to_json(value)
    assert as_json == {
        "structure": [
            True,
            -3,
            {"bit-string": "0680", "unused": 0},
            {"octet-string": "ab"},
            {"array": [1]},
        ]
    }
    # Non-negative ints come back as UIntData: the JSON form loses signedness.
    back = iec_data_from_json(as_json)
    assert back == StructureData(
        [
            BoolData(True),
            IntData(-3),
            BitStringData(b"\x06\x80", 0),
            OctetStringData(b"\xab"),
            ArrayData([UIntData(1)]),
        ]
    )


def test_json_legacy_raw_forms() -> None:
    # goose_cli "raw:TAG:HEX" historically used a context tag number.
    assert iec_data_from_json(["raw", 3, "01"]) == RawData(0x83, b"\x01")
    assert iec_data_from_json({"raw": 12, "hex": "00"}) == RawData(0x8C, b"\x00")
    # Strings with control characters keep the legacy boolean-tag encoding.
    assert iec_data_from_json("\x00") == RawData(0x83, b"\x00")


@pytest.mark.xfail(strict=True, reason="known bug: negative ints are not minimally encoded (X.690 8.3.2)")
def test_encode_negative_int_minimal() -> None:
    assert encode_iec_data(IntData(-128)).hex() == "850180"
