# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Characterization tests for the SCL data set parser (mms/scl_parser.py)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from conftest import DATA_DIR

from mms import mms_report_processing as processing
from mms.scl_parser import parse_scl_data_set_members, parse_scl_data_set_members_with_components

SCL = DATA_DIR / "minimal_ied.scl.xml"
MEMBERS = ["Pos.stVal", "TotW.mag", "A.phsA"]


def test_data_set_members_and_keys() -> None:
    labels = parse_scl_data_set_members(SCL)
    assert labels == {
        "IED1/LLN0$DS1": MEMBERS,
        "IED1_1LD0/LLN0$DS1": MEMBERS,  # naming used by the VMC7 IED
        "IED1/LD0$DS1": MEMBERS,
        "IED1_1LD0/LD0$DS1": MEMBERS,
    }


def test_components_and_enums() -> None:
    _, components, enums = parse_scl_data_set_members_with_components(SCL)
    assert components["IED1/LLN0$DS1"] == {"TotW.mag": ["f"]}
    assert enums["IED1/LLN0$DS1"] == {"Pos.stVal": {0: "intermediate", 1: "off", 2: "on", 3: "bad"}}


@pytest.mark.xfail(strict=True, reason="known gap: the standard MMS reference <ied><ldInst>/LLN0$DS is not a key")
def test_standard_data_set_reference_is_a_key() -> None:
    assert "IED1LD0/LLN0$DS1" in parse_scl_data_set_members(SCL)


@pytest.mark.xfail(strict=True, reason="known gap: SDO (A.phsA) are not resolved")
def test_sub_data_object_components() -> None:
    _, components, _ = parse_scl_data_set_members_with_components(SCL)
    assert components["IED1/LLN0$DS1"]["A.phsA"] == ["cVal", "q", "t"]


@pytest.fixture
def loaded_labels() -> Iterator[None]:
    saved = dict(processing.DATA_SET_MEMBER_LABELS)
    processing.DATA_SET_MEMBER_LABELS.clear()
    processing.DATA_SET_MEMBER_LABELS.update(parse_scl_data_set_members(SCL))
    yield
    processing.DATA_SET_MEMBER_LABELS.clear()
    processing.DATA_SET_MEMBER_LABELS.update(saved)


def test_report_label_resolution_falls_back_on_data_set_name(loaded_labels: None) -> None:
    # 8 header entries + 3 values + 3 reason codes.
    assert processing._resolve_member_labels_for_dataset("IED1LD0/LLN0$DS1", 14) == MEMBERS
    assert processing._resolve_member_labels_for_dataset("IED1LD0/LLN0$DS1", 12) == []
    assert processing._resolve_member_labels_for_dataset("OTHER/LLN0$DS9", 14) == []
