# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""mms/reporting.py: subscription plan, text and VictoriaMetrics lines.

The expected Prometheus lines are the ones the historical pipeline
(asn1_codec + victoriametrics_push with SCL labels) produced for the same
report bytes, so Grafana series did not change when it was replaced.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from iec61850 import ber
from iec61850.data import (
    BitStringData,
    BoolData,
    FloatData,
    IntData,
    OctetStringData,
    StructureData,
    TimestampData,
    UIntData,
    VisibleStringData,
    encode_binary_time,
    encode_data,
)
from iec61850.mms import ObjectName, TrgOps, decode_report, pdu
from iec61850.mms.report import ReasonCode, bitstring_of
from iec61850.mms.types import PrimitiveType, StructureType
from mms import reporting

DS = "IED01_LD0/LLN0$DS_TEST"
TOE = datetime(2026, 9, 24, 14, 40, 54, 747000, tzinfo=timezone.utc)
T = TimestampData(datetime(2026, 9, 24, 9, 19, 15, 501000, tzinfo=timezone.utc), quality=0x67)
Q_INVALID = BitStringData(b"\x42\x00", 3)
Q_GOOD = BitStringData(b"\x00\x00", 3)

F = StructureType([("f", PrimitiveType("float", 32))])
CMV = StructureType([
    ("cVal", StructureType([("mag", F), ("ang", F)])),
    ("range", PrimitiveType("integer", 8)),
    ("rangeAng", PrimitiveType("integer", 8)),
    ("q", PrimitiveType("bit-string", -13)),
    ("t", PrimitiveType("utc-time")),
])
MV = StructureType([("mag", F), ("range", PrimitiveType("integer", 8)), ("q", PrimitiveType("bit-string", -13)), ("t", PrimitiveType("utc-time"))])
SPS = StructureType([("stVal", PrimitiveType("boolean")), ("q", PrimitiveType("bit-string", -13)), ("t", PrimitiveType("utc-time"))])
DPC = StructureType([
    ("origin", StructureType([("orCat", PrimitiveType("integer", 8)), ("orIdent", PrimitiveType("octet-string", -64))])),
    ("stVal", PrimitiveType("bit-string", 2)),
    ("q", PrimitiveType("bit-string", -13)),
    ("t", PrimitiveType("utc-time")),
])

MEMBERS = [
    (ObjectName("LMODELGAPC1$ST$LogOut10", "IED01_LD0"), SPS, StructureData([BoolData(True), Q_GOOD, T])),
    (ObjectName("BAYMMXU1$MX$A$phsA", "IED01_BayLD"), CMV, StructureData([
        StructureData([StructureData([FloatData(12.5)]), StructureData([FloatData(-120.0)])]),
        IntData(0), IntData(0), Q_INVALID, T,
    ])),
    (ObjectName("BAYMMXU1$MX$Hz", "IED01_BayLD"), MV, StructureData([StructureData([FloatData(49.9996)]), IntData(0), Q_INVALID, T])),
    (ObjectName("CBXCBR1$ST$Pos", "IED01_BayLD"), DPC, StructureData([
        StructureData([IntData(3), OctetStringData(b"\x13\xd5")]), BitStringData(b"\x80", 6), Q_GOOD, T,
    ])),
]


def _report_bytes(inclusion: list[bool]) -> bytes:
    """An informationReport as the VMC7 sends it with po's OptFlds (067b00)."""
    values = [
        encode_data(VisibleStringData("LDTEST_DEP1")),
        encode_data(BitStringData(bytes.fromhex("7b00"), 6)),
        encode_data(UIntData(7)),
        ber.encode_tlv(0x8C, encode_binary_time(TOE)),
        encode_data(VisibleStringData(DS)),
        encode_data(BoolData(False)),
        encode_data(OctetStringData(bytes(8))),
        encode_data(bitstring_of(inclusion)),
    ]
    included = [m for m, inc in zip(MEMBERS, inclusion) if inc]
    values += [encode_data(value) for _, _, value in included]
    values += [encode_data(ReasonCode(integrity=True).to_bitstring()) for _ in included]
    body = ber.encode_tlv(0xA1, ber.encode_tlv(0x80, b"RPT")) + ber.encode_tlv(0xA0, b"".join(values))
    return pdu.wrap(ber.encode_tlv(0xA3, ber.encode_tlv(0xA0, body)))


def _data_set(with_types: bool = True) -> reporting.DataSetInfo:
    return reporting.DataSetInfo(
        DS, [reporting.MemberInfo(name, reporting.member_label(name), mms_type if with_types else None) for name, mms_type, _ in MEMBERS]
    )


def _new_lines(raw: bytes, data_set: reporting.DataSetInfo) -> list[str]:
    message = pdu.decode_pdu(pdu.unwrap(raw))
    return reporting.report_to_lines(decode_report(message), data_set)  # type: ignore[arg-type]


def _historical_lines() -> list[str]:
    ts = int(TOE.timestamp() * 1000)
    base = f'rpt_id="LDTEST_DEP1",data_set="{DS}"'
    return [
        f'mms_report_value{{{base},member="SeqNum"}} 7.0 {ts}',
        f'mms_report_value{{{base},member="BufOvfl"}} 0.0 {ts}',
        f'mms_report_value{{{base},member="LogOut10"}} 1.0 {ts}',
        f'mms_report_value{{{base},member="A.phsA",component="mag"}} 12.5 {ts}',
        f'mms_report_value{{{base},member="A.phsA",component="ang"}} -120.0 {ts}',
        f'mms_report_value{{{base},member="Hz"}} 49.9996 {ts}',
        f'mms_report_value{{{base},member="Pos",component="orCat"}} 3.0 {ts}',
        f'mms_report_value{{{base},member="Pos",component="state"}} 2.0 {ts}',
    ]


def test_lines_match_the_historical_pipeline() -> None:
    raw = _report_bytes([True, True, True, True])
    assert _new_lines(raw, _data_set()) == _historical_lines()


def test_lines_without_types_fall_back_like_before() -> None:
    raw = _report_bytes([True, True, True, True])
    assert _new_lines(raw, _data_set(with_types=False)) == _historical_lines()


def test_partial_inclusion_keeps_member_names() -> None:
    # Members are named by their position in the data set. The historical
    # pipeline published Hz here under the first member's name (LogOut10).
    raw = _report_bytes([False, False, True, False])
    members = [line.split("member=")[1].split("}")[0] for line in _new_lines(raw, _data_set())]
    assert members == ['"SeqNum"', '"BufOvfl"', '"Hz"']


def test_format_report() -> None:
    message = pdu.decode_pdu(pdu.unwrap(_report_bytes([False, True, False, False])))
    text = reporting.format_report(decode_report(message), _data_set())  # type: ignore[arg-type]
    assert text[0].startswith("REPORT LDTEST_DEP1 seq=7")
    assert text[1:] == [
        "  IED01_BayLD/BAYMMXU1$MX$A$phsA (integrity)",
        "      cVal.mag.f=12.5  cVal.ang.f=-120.0  range=0  rangeAng=0  q=invalid,failure  "
        "t=2026-09-24 09:19:15.501 [clock-failure,not-synchronized,accuracy=7bits]",
    ]


def test_member_label() -> None:
    assert reporting.member_label(ObjectName("BAYMMXU1$MX$A$phsA", "LD")) == "A.phsA"
    assert reporting.member_label(ObjectName("XCBR1$ST$Pos$stVal", "LD")) == "Pos.stVal"
    assert reporting.member_label(ObjectName("LLN0", "LD")) == "LLN0"


def test_triggers() -> None:
    assert reporting.parse_triggers(None) == TrgOps(integrity=True, general_interrogation=True)
    assert reporting.parse_triggers("dchg, qchg,gi") == TrgOps(data_change=True, quality_change=True, general_interrogation=True)
    assert reporting.parse_triggers(None).to_bitstring() == BitStringData(b"\x0c", 2)  # po's historical 020c
    assert reporting.LEGACY_OPT_FLDS.to_bitstring() == BitStringData(bytes.fromhex("7b00"), 6)
    with pytest.raises(ValueError, match="unknown trigger"):
        reporting.parse_triggers("integrity,foo")


AVAILABLE = [f"LLN0$BR$CB_A0{i}" for i in (1, 2, 3, 4)] + [f"LLN0$BR$CB_B0{i}" for i in (1, 2)]
GROUPS = reporting.groups_from_names("LD0", AVAILABLE + ["LLN0$BR$CB_A01$RptID", "XCBR1"])


def _names(plan: list[list[ObjectName]]) -> list[list[str]]:
    return [[o.item for o in group] for group in plan]


def test_groups_from_names() -> None:
    assert [(str(g.base), g.name) for g in GROUPS] == [("LD0/LLN0$BR$CB_A", "CB_A"), ("LD0/LLN0$BR$CB_B", "CB_B")]
    assert [o.item for o in GROUPS[0].instances] == AVAILABLE[:4]


def test_plan_every_group_by_default() -> None:
    plan, missing = reporting.plan_subscriptions(GROUPS)
    assert _names(plan) == [AVAILABLE[:4], AVAILABLE[4:]] and missing == []


def test_plan_with_patterns() -> None:
    plan, missing = reporting.plan_subscriptions(GROUPS, patterns=reporting.parse_rcb_filter(" CB_B*, CB_Z* "))
    assert _names(plan) == [AVAILABLE[4:]] and missing == ["CB_Z*"]


def test_plan_prefers_requested_then_previous_instances() -> None:
    plan, missing = reporting.plan_subscriptions(GROUPS, wanted=["LLN0$BR$CB_A03", "LLN0$BR$CB_C01"])
    assert _names(plan) == [["LLN0$BR$CB_A03", "LLN0$BR$CB_A01", "LLN0$BR$CB_A02", "LLN0$BR$CB_A04"]]
    assert missing == ["LLN0$BR$CB_C01"]
    plan, _ = reporting.plan_subscriptions(GROUPS, wanted=["LLN0$BR$CB_A03"], previous=["LD0/LLN0$BR$CB_A02"])
    assert _names(plan)[0][:2] == ["LLN0$BR$CB_A02", "LLN0$BR$CB_A03"]
    plan, _ = reporting.plan_subscriptions(GROUPS, previous=["LLN0$BR$CB_B02"])  # older bare items still match
    assert _names(plan)[1][0] == "LLN0$BR$CB_B02"
    plan, _ = reporting.plan_subscriptions(GROUPS, wanted=["LLN0$BR$CB_B"])  # a group without instance number
    assert _names(plan) == [AVAILABLE[4:]]


def test_groups_from_scl_and_filter() -> None:
    from conftest import DATA_DIR

    from iec61850 import scl

    ied = scl.find_ied(scl.load_ieds(DATA_DIR / "two_ieds.scd.xml"), "192.0.2.10")
    assert ied is not None and ied.domains == ["IED01_ALD0", "IED01_ACTRL"]
    groups = reporting.groups_from_scl(ied)
    plan, _ = reporting.plan_subscriptions(groups, patterns=["CB_LDPX_*", "CB_LDADD_*"])
    assert [[str(o) for o in g] for g in plan] == [
        [f"IED01_ALD0/LLN0$BR$CB_LDPX_DQPO_DEP1{i:02d}" for i in (1, 2, 3)],
        [f"IED01_ALD0/LLN0$BR$CB_LDPX_DQPO_DEP2{i:02d}" for i in (1, 2, 3)],
        [f"IED01_ALD0/LLN0$BR$CB_LDADD_DQPO_DEP1{i:02d}" for i in (1, 2)],
    ]
    assert [str(g.base) for g in reporting.groups_from_scl(ied, ["IED01_ACTRL"])] == ["IED01_ACTRL/CBCSWI1$BR$CB_POS"]
