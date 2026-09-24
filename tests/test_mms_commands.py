# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Characterization tests for the Pos Oper command encoder (mms/mms_commands_codec.py).

The value is an IEDscout template. Decoded, the Oper structure is
{ctlVal, origin{orCat, orIdent}, ctlNum, T, Test, Check}. The code calls the
first field "ctlNum" and the last one "ctlVal"; these tests pin what is
really sent.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from iec_data import (
    BitStringData,
    BoolData,
    IntData,
    OctetStringData,
    StructureData,
    TimestampData,
    UIntData,
    decode_iec_data_at,
)
from mms.asn1_codec import reset_invoke_id
from mms.mms_commands_codec import encode_pos_oper_execute_step3, encode_pos_oper_write

ITEM = "CBCSWI1$CO$Pos$Oper"


@pytest.fixture(autouse=True)
def _fresh_invoke_id() -> None:
    reset_invoke_id()


def _oper_value(pdu: bytes) -> StructureData:
    start = pdu.find(bytes.fromhex("a222"))
    assert start > 0
    value, end = decode_iec_data_at(pdu, start)
    assert end == len(pdu)
    assert isinstance(value, StructureData)
    return value


def _fields(value: StructureData) -> dict[str, object]:
    ctl_val, origin, ctl_num, t, test, check = value.members
    return {"ctlVal": ctl_val, "origin": origin, "ctlNum": ctl_num, "T": t, "Test": test, "Check": check}


@pytest.mark.parametrize(("position", "ctl_val"), [("open", False), ("closed", True)])
def test_oper_write_sets_ctl_val(position: str, ctl_val: bool) -> None:
    pdu = encode_pos_oper_write(domain_id="VMC7_2BayLD", item_id=ITEM, position=position)  # type: ignore[arg-type]
    fields = _fields(_oper_value(pdu))
    assert fields["ctlVal"] == BoolData(ctl_val)
    assert fields["origin"] == StructureData([IntData(3), OctetStringData(bytes.fromhex("13d5c007"))])
    assert fields["ctlNum"] == UIntData(0)
    assert fields["Test"] == BoolData(False)
    assert fields["Check"] == BitStringData(b"\xc0", 6)


def test_oper_write_refreshes_timestamp() -> None:
    pdu = encode_pos_oper_write(domain_id="VMC7_2BayLD", item_id=ITEM, position="open")
    t = _fields(_oper_value(pdu))["T"]
    assert isinstance(t, TimestampData)
    assert abs(t.value - datetime.now(timezone.utc)) < timedelta(seconds=5)


def test_oper_write_targets_item() -> None:
    pdu = encode_pos_oper_write(domain_id="VMC7_2BayLD", item_id=ITEM, position="open")
    assert b"\x1a\x0bVMC7_2BayLD\x1a\x13CBCSWI1$CO$Pos$Oper" in pdu
    assert pdu[:4] == bytes.fromhex("01000100")


def test_step2_flips_ctl_val() -> None:
    # "step2" adds 1 to what the code believes is ctlNum: it turns open into close.
    pdu = encode_pos_oper_write(domain_id="VMC7_2BayLD", item_id=ITEM, position="open", step="step2")
    assert _fields(_oper_value(pdu))["ctlVal"] == BoolData(True)


def test_step3_is_limited_to_one_object() -> None:
    with pytest.raises(NotImplementedError):
        encode_pos_oper_execute_step3(domain_id="LD0", item_id=ITEM, position="closed")
    pdu = encode_pos_oper_execute_step3(domain_id="VMC7_2BayLD", item_id=ITEM, position="closed")
    assert _fields(_oper_value(pdu))["ctlVal"] == BoolData(True)
