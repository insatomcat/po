# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Application-side view of the IEC 61850 ``Data`` model.

The model and its BER codec live in :mod:`iec61850.data`. This module keeps
the historical names used across po and the JSON mapping of the HTTP APIs,
including the legacy goose_cli forms.
"""

from __future__ import annotations

from typing import Any

from iec61850 import ber
from iec61850.data import (  # noqa: F401 - re-exported
    DATA_TYPES as _IEC_DATA_TYPES,
    ArrayData,
    BitStringData,
    BoolData,
    FloatData,
    IECData,
    IntData,
    MmsStringData,
    OctetStringData,
    RawData,
    StructureData,
    TimestampData,
    UIntData,
    VisibleStringData,
    decode_data as decode_iec_data,
    decode_data_at as decode_iec_data_at,
    encode_data as encode_iec_data,
)

_tlv = ber.encode_tlv


def decode_iec_data_sequence(data: bytes) -> list[IECData]:
    """Decode consecutive Data TLVs, stopping silently at the first malformed one."""
    items: list[IECData] = []
    offset = 0
    while offset < len(data):
        try:
            item, offset = decode_iec_data_at(data, offset)
        except ValueError:
            break
        items.append(item)
    return items


# --- JSON mapping ------------------------------------------------------------


def iec_data_to_json(d: IECData) -> Any:
    """Convert a Data value to a JSON-serializable value."""
    if isinstance(d, (BoolData, IntData, UIntData, FloatData)):
        return d.value
    if isinstance(d, (VisibleStringData, MmsStringData)):
        return d.value
    if isinstance(d, TimestampData):
        return d.value.isoformat()
    if isinstance(d, BitStringData):
        return {"bit-string": d.value.hex(), "unused": d.unused_bits}
    if isinstance(d, OctetStringData):
        return {"octet-string": d.value.hex()}
    if isinstance(d, StructureData):
        return {"structure": [iec_data_to_json(m) for m in d.members]}
    if isinstance(d, ArrayData):
        return {"array": [iec_data_to_json(e) for e in d.elements]}
    if isinstance(d, RawData):
        return {"raw": d.tag, "hex": d.value.hex()}
    return None


def _legacy_tag_to_ber(tag_num: int) -> int:
    """goose_cli "raw" values carry a context tag number (primitive)."""
    if 0 <= tag_num <= 0x1F:
        return 0x80 | tag_num
    return tag_num & 0xFF


def iec_data_from_json(val: Any) -> IECData:
    """Convert a JSON value to a Data value.

    Also accepts the legacy raw tuple ``["raw", tag_num, hex_str]``.
    """
    if isinstance(val, bool):
        return BoolData(val)
    if isinstance(val, int):
        return UIntData(val) if val >= 0 else IntData(val)
    if isinstance(val, float):
        return FloatData(val)
    if isinstance(val, str):
        # goose_cli compatibility: before the Data model, strings such as
        # "s:\x00" were sent with the boolean context tag 0x83. Strict IEDs
        # rely on it, so strings with control characters keep that encoding.
        if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in val):
            return RawData(0x83, val.encode("latin1", errors="replace"))
        return VisibleStringData(val)
    if isinstance(val, (list, tuple)):
        if len(val) == 3 and val[0] == "raw":
            try:
                return RawData(_legacy_tag_to_ber(int(val[1])), bytes.fromhex(str(val[2])))
            except (ValueError, TypeError):
                pass
        return ArrayData([iec_data_from_json(e) for e in val])
    if isinstance(val, dict):
        if "bit-string" in val:
            try:
                return BitStringData(bytes.fromhex(str(val["bit-string"])), int(val.get("unused", 0)))
            except (ValueError, TypeError):
                pass
        if "octet-string" in val:
            try:
                return OctetStringData(bytes.fromhex(str(val["octet-string"])))
            except (ValueError, TypeError):
                pass
        if "structure" in val:
            return StructureData([iec_data_from_json(m) for m in val.get("structure", [])])
        if "array" in val:
            return ArrayData([iec_data_from_json(e) for e in val.get("array", [])])
        if "raw" in val:
            try:
                return RawData(_legacy_tag_to_ber(int(val["raw"])), bytes.fromhex(str(val.get("hex", ""))))
            except (ValueError, TypeError):
                pass
    return RawData(0, str(val).encode("utf-8", errors="replace"))
