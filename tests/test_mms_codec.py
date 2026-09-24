# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Characterization tests for the MMS encoders and decoders (mms/asn1_codec.py).

Golden request bytes are the current output of the encoders, which the target
IEDs accept. Tests marked xfail describe the ISO 9506 behaviour the code does
not implement yet; they flip to XPASS (and fail, being strict) once fixed.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from iec61850 import ber
from iec_data import (
    BitStringData,
    BoolData,
    IntData,
    OctetStringData,
    StructureData,
    TimestampData,
    UIntData,
    VisibleStringData,
    _tlv,
    encode_iec_data,
)
from mms.asn1_codec import (
    OBJECT_CLASS_DOMAIN,
    OBJECT_CLASS_NAMED_VARIABLE,
    decode_mms_get_name_list_response,
    decode_mms_pdu,
    encode_mms_get_name_list,
    encode_mms_get_rcb,
    encode_mms_initiate,
    encode_mms_set_rcb,
    is_read_response_success,
    reset_invoke_id,
)

SESSION_PREFIX = bytes.fromhex("01000100")


@pytest.fixture(autouse=True)
def _fresh_invoke_id() -> None:
    reset_invoke_id()


def _presentation(mms_pdu: bytes) -> bytes:
    """Session prefix + fully-encoded-data with presentation context 3."""
    pdv = bytes.fromhex("020103") + _tlv(0xA0, mms_pdu)
    return SESSION_PREFIX + _tlv(0x61, _tlv(0x30, pdv))


def _confirmed_response(service_tag: int, service: bytes, invoke_id: int = 300) -> bytes:
    body = _tlv(0x02, invoke_id.to_bytes(2, "big")) + _tlv(service_tag, service)
    return _presentation(_tlv(0xA1, body))


def _information_report(values: list[bytes]) -> bytes:
    rpt_name = _tlv(0xA1, _tlv(0x80, b"RPT"))
    report = _tlv(0xA0, rpt_name + _tlv(0xA0, b"".join(values)))
    return _presentation(_tlv(0xA3, report))


# --- Requests ---------------------------------------------------------------


def test_get_rcb_values_request() -> None:
    pdu = encode_mms_get_rcb("IED01_LD0", "LLN0$BR$CB_LDPHAS1_CYPO03")
    assert pdu.hex() == (
        "01000100613f303d020103a038a0360202012ca430a12ea02c302aa028a126"
        "1a0949454430315f4c44301a194c4c4e302442522443425f4c4450484153315f4359504f3033"
    )


def test_invoke_id_increments_per_request() -> None:
    first = encode_mms_get_rcb("LD0", "LLN0$BR$CB01")
    second = encode_mms_get_rcb("LD0", "LLN0$BR$CB01")
    assert first[17:19].hex() == "012c"
    assert second[17:19].hex() == "012d"


def test_set_rcb_sequence() -> None:
    pdus = encode_mms_set_rcb("LD0", "LLN0$BR$CB01")
    assert [p.hex() for p in pdus] == [
        "0100010061373035020103a030a02e0202012ca528a021301fa01da11b1a034c44301a144c4c4e3024425224434230312452657376546d73a003850105",
        "0100010061373035020103a030a02e0202012da528a020301ea01ca11a1a034c44301a134c4c4e30244252244342303124496e74675064a004860207d0",
        "0100010061373035020103a030a02e0202012ea528a020301ea01ca11a1a034c44301a134c4c4e302442522443423031245472674f7073a0048402020c",
        "0100010061393037020103a032a0300202012fa52aa021301fa01da11b1a034c44301a144c4c4e302442522443423031244f7074466c6473a0058403067b00",
        "0100010061383036020103a031a02f02020130a529a0223020a01ea11c1a034c44301a154c4c4e302442522443423031245075726765427566a003830101",
        "01000100613e303c020103a037a03502020131a52fa021301fa01da11b1a034c44301a144c4c4e30244252244342303124456e7472794944a00a89080000000000000000",
        "0100010061363034020103a02fa02d02020132a527a020301ea01ca11a1a034c44301a134c4c4e30244252244342303124527074456e61a003830101",
        "0100010061323030020103a02ba02902020133a523a01c301aa018a1161a034c44301a0f4c4c4e302442522443423031244749a003830101",
    ]


def test_get_name_list_requests() -> None:
    # Current encoding. Suspected non-conformant (objectClass and objectScope
    # are CHOICEs, so explicitly tagged in ISO 9506); to check on a capture.
    assert encode_mms_get_name_list(OBJECT_CLASS_DOMAIN).hex() == (
        "0100010061163014020103a00fa00d0202012ca10730058001098100"
    )
    assert encode_mms_get_name_list(
        OBJECT_CLASS_NAMED_VARIABLE, scope_vmd=False, domain_id="LD0"
    ).hex() == "01000100611b3019020103a014a0120202012da10c300a80010081051a034c4430"


def test_initiate_is_a_fixed_replay() -> None:
    pdu = encode_mms_initiate()
    assert len(pdu) == 180
    assert pdu[:2].hex() == "0db2"  # Session CONNECT SPDU
    assert encode_mms_initiate() == pdu


def _walk(data: bytes) -> list[bytes]:
    """Decode every TLV recursively; return the primitive contents in order."""
    out: list[bytes] = []
    for tlv in ber.iter_tlvs(data):
        out.extend(_walk(tlv.value) if ber.is_constructed(tlv.tag) else [tlv.value])
    return out


def test_long_item_name_uses_long_form_length() -> None:
    item = "LLN0$BR$" + "X" * 120
    pdu = encode_mms_get_rcb("IED01_LD0", item)
    assert pdu[4:6].hex() == "6181"  # presentation content > 127 bytes: long form
    assert _walk(pdu[4:])[-2:] == [b"IED01_LD0", item.encode()]


# --- Responses --------------------------------------------------------------


def test_read_response_success_and_failure() -> None:
    success = _confirmed_response(0xA4, _tlv(0xA1, _tlv(0xA2, bytes.fromhex("8a03525054"))))
    failure = _confirmed_response(0xA4, _tlv(0xA1, bytes.fromhex("80010a")))
    assert is_read_response_success(success)
    assert not is_read_response_success(failure)


@pytest.mark.xfail(strict=True, reason="known bug: decoder stops on the confirmed-ResponsePDU [1] tag")
def test_get_name_list_response() -> None:
    names = _tlv(0xA0, _tlv(0x1A, b"LD0") + _tlv(0x1A, b"LD1"))
    more_follows = bytes.fromhex("8101ff")
    pdu = _confirmed_response(0xA1, names + more_follows)
    assert decode_mms_get_name_list_response(pdu) == (["LD0", "LD1"], True)


# --- Reports ----------------------------------------------------------------


def _report_values(opt_flds: bytes) -> list[bytes]:
    member = StructureData(
        [
            BitStringData(b"\x80", 6),  # stVal Dbpos
            BitStringData(b"\x00\x00", 3),  # q
            TimestampData(datetime(2026, 3, 1, tzinfo=timezone.utc)),
        ]
    )
    return [
        encode_iec_data(VisibleStringData("CB_LDCMDDJ_DQPO03")),
        encode_iec_data(BitStringData(opt_flds, 6)),
        encode_iec_data(UIntData(42)),
        bytes.fromhex("8c06") + (3600_000).to_bytes(4, "big") + (15400).to_bytes(2, "big"),
        encode_iec_data(VisibleStringData("IED1LD0/LLN0$DS1")),
        encode_iec_data(BoolData(False)),
        encode_iec_data(OctetStringData(bytes(8))),
        encode_iec_data(BitStringData(b"\x80", 7)),
        encode_iec_data(member),
        encode_iec_data(BitStringData(b"\x40", 2)),  # reason code: data-change
    ]


def test_information_report_header() -> None:
    report = decode_mms_pdu(_information_report(_report_values(bytes.fromhex("7b00"))))
    assert report.rpt_id == "CB_LDCMDDJ_DQPO03"
    assert report.seq_num == 42
    assert report.data_set_name == "IED1LD0/LLN0$DS1"
    assert report.buf_ovfl is False
    assert report.time_of_entry == "2026-03-01T01:00:00+00:00"
    assert len(report.entries) == 10
    # Values are flattened to the "legacy" untyped form.
    assert report.entries[8]["success"] == ["80", "0000", "2026-03-01T00:00:00+00:00"]


@pytest.mark.xfail(strict=True, reason="known bug: header layout is fixed, OptFlds is ignored")
def test_information_report_without_sequence_number() -> None:
    values = _report_values(bytes.fromhex("3b00"))  # sequence-number bit cleared
    del values[2]
    report = decode_mms_pdu(_information_report(values))
    assert report.seq_num is None
    assert report.data_set_name == "IED1LD0/LLN0$DS1"


def test_unknown_pdu_falls_back_to_raw_hex() -> None:
    pdu = _confirmed_response(0xA5, bytes.fromhex("8100"))
    report = decode_mms_pdu(pdu)
    assert report.rpt_id is None
    assert report.entries == [{"raw_hex": pdu.hex()}]


def test_int_entry_decodes_signed() -> None:
    values = _report_values(bytes.fromhex("7b00"))
    values[8] = encode_iec_data(IntData(-5))
    report = decode_mms_pdu(_information_report(values))
    assert report.entries[8]["success"] == -5
