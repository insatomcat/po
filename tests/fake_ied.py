# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""A scripted MMS server on a socketpair, for the tests of PO's MMS service.

Copied from the open61850 test suite, which keeps its own.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from typing import Optional

import pytest
from conftest import DATA_DIR

from open61850 import ber
from open61850.data import (
    decode_data_sequence,
    BitStringData,
    BoolData,
    IECData,
    IntData,
    OctetStringData,
    StructureData,
    TimestampData,
    UIntData,
    VisibleStringData,
    encode_data,
)
from open61850.mms import (
    OBJECT_CLASS_DOMAIN,
    DataAccessError,
    InformationReport,
    MmsClient,
    MmsConnectionError,
    MmsReject,
    MmsTimeout,
    ObjectName,
    OptFlds,
    ReasonCode,
    ServiceError,
    TrgOps,
    association,
    decode_report,
    pdu,
    rcb,
    transport,
)
from open61850.mms.report import ReportDecodeError, bits_of, bitstring_of

ASSOCIATION = json.loads((DATA_DIR / "association_responses.json").read_text())
CAPTURE = json.loads((DATA_DIR / "iedscout_reports_control.json").read_text())
LD = "IED01_BayLD"
POS = ObjectName("CBCSWI1$CO$Pos", LD)
OPER = ObjectName("CBCSWI1$CO$Pos$Oper", LD)


Handler = Callable[[int, int, bytes, "FakeServer"], None]


class FakeServer:
    """A scripted MMS server on a socketpair. ``handler(invoke_id, service, content, server)``."""

    def __init__(self, handler: Handler, tpdu_size: int = 1024, accept: str = "vmc7_accept") -> None:
        self.handler = handler
        self.accept = bytes.fromhex(ASSOCIATION[accept])
        self.client_sock, self.sock = socket.socketpair()
        self.conn = transport.IsoConnection(self.sock, tpdu_size=tpdu_size)
        self.errors: list[BaseException] = []
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        try:
            cr = transport.recv_tpkt(self.sock)
            assert cr is not None and cr[1] == 0xE0
            transport.send_tpkt(self.sock, bytes.fromhex("0bd00000000100c0010a"))  # CC, 1024-byte TPDUs
            assert self.conn.recv() == association.association_request()
            self.conn.send(self.accept)
            while True:
                user_data = self.conn.recv()
                if user_data is None:
                    return
                request = ber.decode_tlv(pdu.unwrap(user_data))
                invoke, service = list(ber.iter_tlvs(request.value))[:2]
                self.handler(ber.decode_unsigned(invoke.value), ber.tag_number(service.tag), service.value, self)
        except OSError:
            pass
        except BaseException as exc:  # noqa: BLE001 - reported by the fixture
            self.errors.append(exc)

    def respond(self, invoke_id: int, service: int, content: bytes) -> None:
        body = ber.encode_tlv(0x02, ber.encode_unsigned(invoke_id)) + ber.encode_tlv(ber.make_tag(service, constructed=True), content)
        self.conn.send(pdu.wrap(ber.encode_tlv(0xA1, body)))

    def send_mms(self, mms_pdu: bytes) -> None:
        self.conn.send(pdu.wrap(mms_pdu))

    def close(self) -> None:
        self.conn.close()


def _read_names(content: bytes) -> list[ObjectName]:
    spec = next(t for t in ber.iter_tlvs(content) if t.tag == 0xA1)
    return pdu._decode_variable_list(ber.decode_tlv(spec.value).value)


def _read_ok(values: list[bytes]) -> bytes:
    return ber.encode_tlv(0xA1, b"".join(values))


class FakeModel:
    """Variables of a fake server; unknown ones answer object-non-existent."""

    def __init__(self, values: dict[str, IECData], refuse: frozenset[str] = frozenset()) -> None:
        self.values = values
        self.refuse = refuse
        self.writes: list[tuple[str, IECData]] = []

    def __call__(self, invoke_id: int, service: int, content: bytes, server: FakeServer) -> None:
        if service == pdu.SERVICE_READ:
            out = []
            for n in _read_names(content):
                v = self.values.get(n.item)
                out.append(encode_data(v) if v is not None else bytes.fromhex("80010a"))
            server.respond(invoke_id, service, _read_ok(out))
        elif service == pdu.SERVICE_WRITE:
            spec, data = list(ber.iter_tlvs(content))[:2]
            name = pdu._decode_variable_list(spec.value)[0].item
            from open61850.data import decode_data_sequence

            (value,) = decode_data_sequence(data.value)
            if name.rsplit("$", 1)[1] in self.refuse:
                server.respond(invoke_id, service, bytes.fromhex("800103"))
                return
            self.writes.append((name, value))
            self.values[name] = value
            server.respond(invoke_id, service, bytes.fromhex("8100"))



def _last_appl_error(add_cause: int, obj: str = f"{LD}/CBCSWI1$CO$Pos$Oper", error: int = 1) -> bytes:
    return encode_data(StructureData([
        VisibleStringData(obj), IntData(error),
        StructureData([IntData(2), OctetStringData(b"po")]), UIntData(0), IntData(add_cause),
    ]))


def _report(names: list[ObjectName], values: list[bytes]) -> bytes:
    body = pdu._variable_list(names) + ber.encode_tlv(0xA0, b"".join(values))
    return ber.encode_tlv(0xA3, ber.encode_tlv(0xA0, body))


class ControlIed(FakeModel):
    """A breaker with a configurable control model and scripted reactions to Oper."""

    def __init__(self, ctl_model: int, on_oper: Optional[Callable[[FakeServer, IECData], Optional[bytes]]] = None) -> None:
        super().__init__({"CBCSWI1$CF$Pos$ctlModel": IntData(ctl_model), "CBCSWI1$CO$Pos$SBO": VisibleStringData("")})
        self.on_oper = on_oper

    def __call__(self, invoke_id: int, service: int, content: bytes, server: FakeServer) -> None:
        if service == pdu.SERVICE_WRITE and self.on_oper is not None:
            spec, data = list(ber.iter_tlvs(content))[:2]
            name = pdu._decode_variable_list(spec.value)[0]
            if name.item.endswith("$Oper"):
                (value,) = decode_data_sequence(data.value)
                self.writes.append((name.item, value))
                response = self.on_oper(server, value)
                server.respond(invoke_id, service, response or bytes.fromhex("8100"))
                return
        super().__call__(invoke_id, service, content, server)


def _terminate(server: FakeServer, _value: IECData) -> None:
    # The write response goes first, the captured CommandTermination 50 ms later.
    threading.Timer(0.05, lambda: server.conn.send(bytes.fromhex(CAPTURE["command_termination"]))).start()
