# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""GOOSE codec entry points used by po; the codec lives in :mod:`iec61850.goose`."""

from __future__ import annotations

from iec61850.data import DATA_TYPES
from iec61850.goose import GooseDecodeError as ASN1DecodeError  # noqa: F401 - historical name
from iec61850.goose import GoosePDU, decode_goose_pdu  # noqa: F401 - re-exported
from iec61850.goose import encode_goose_pdu as _encode_goose_pdu
from iec_data import iec_data_from_json


def encode_goose_pdu(pdu: GoosePDU) -> bytes:
    """Encode a GOOSE PDU, accepting JSON-style values in ``all_data`` as the HTTP API does."""
    if any(not isinstance(d, DATA_TYPES) for d in pdu.all_data):
        pdu = GoosePDU(**{**pdu.__dict__, "all_data": [
            d if isinstance(d, DATA_TYPES) else iec_data_from_json(d) for d in pdu.all_data
        ]})
    return _encode_goose_pdu(pdu)
