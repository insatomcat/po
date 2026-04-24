from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from iec_data import IECData


@dataclass
class GoosePDU:
    """Représentation haut niveau du PDU GOOSE (selon IEC 61850-8-1)."""

    gocb_ref: str
    time_allowed_to_live: int
    dat_set: str
    go_id: Optional[str]
    timestamp: datetime
    st_num: int
    sq_num: int
    simulation: bool
    conf_rev: int
    nds_com: bool
    num_dat_set_entries: int
    all_data: list[IECData] = field(default_factory=list)


@dataclass
class GooseFrame:
    """Trame complète GOOSE au niveau liaison (Ethernet + APDU)."""

    dst_mac: str
    src_mac: str
    app_id: int
    vlan_id: Optional[int]
    ethertype: int
    raw_payload: bytes
    pdu: Optional[GoosePDU] = None

