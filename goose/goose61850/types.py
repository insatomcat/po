# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from open61850.goose import GoosePDU  # noqa: F401 - re-exported


@dataclass
class GooseFrame:
    """A received GOOSE frame: link-layer fields, raw APDU and decoded PDU."""

    dst_mac: str
    src_mac: str
    app_id: int
    vlan_id: Optional[int]
    ethertype: int
    raw_payload: bytes
    pdu: Optional[GoosePDU] = None
    ts_rx: Optional[float] = None  # kernel receive timestamp

