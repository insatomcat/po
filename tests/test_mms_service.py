# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""The MMS subscription service end to end, against a scripted IED."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from test_lib_mms import FakeModel, FakeServer
from test_mms_reporting import DS, MEMBERS, _report_bytes

from iec61850 import ber
from iec61850.data import BoolData, IntData, VisibleStringData
from iec61850.mms import pdu, transport
from mms import mms_service


class FakeIed:
    """RCBs CB_A01 (used by someone else) and CB_A02 (free) on data set DS."""

    def __init__(self) -> None:
        values = {
            "LLN0$BR$CB_A01$RptEna": BoolData(True), "LLN0$BR$CB_A01$ResvTms": IntData(5),
            "LLN0$BR$CB_A02$RptEna": BoolData(False), "LLN0$BR$CB_A02$ResvTms": IntData(0),
            "LLN0$BR$CB_A02$RptID": VisibleStringData("LDTEST_DEP1"),
            "LLN0$BR$CB_A02$DatSet": VisibleStringData(DS),
        }
        self.model = FakeModel(values)
        self.servers: list[FakeServer] = []
        self.lock = threading.Lock()

    def handler(self, invoke_id: int, service: int, content: bytes, server: FakeServer) -> None:
        if service == pdu.SERVICE_GET_NAME_LIST:
            names = ["LLN0", "LLN0$BR$CB_A01", "LLN0$BR$CB_A01$RptID", "LLN0$BR$CB_A02", "XCBR1"]
            body = ber.encode_tlv(0xA0, b"".join(ber.encode_tlv(0x1A, n.encode()) for n in names))
            server.respond(invoke_id, service, body + ber.encode_tlv(0x81, b"\x00"))
        elif service == pdu.SERVICE_GET_NAMED_VARIABLE_LIST_ATTRIBUTES:
            members = [name for name, _, _ in MEMBERS]
            listing = pdu._variable_list(members)
            server.respond(invoke_id, service, b"\x80\x01\x00" + ber.encode_tlv(0xA1, ber.decode_tlv(listing).value))
        elif service == pdu.SERVICE_GET_VARIABLE_ACCESS_ATTRIBUTES:
            server.respond(invoke_id, service, bytes.fromhex("800100a1028000"))  # unknown type: forces the fallback
        else:
            self.model(invoke_id, service, content, server)
            if service == pdu.SERVICE_WRITE and self.model.writes[-1][0].endswith("$GI"):
                server.conn.send(_report_bytes([True, True, True, True]))

    def connect(self, *_args: object, **_kwargs: object) -> object:
        server = FakeServer(self.handler)
        with self.lock:
            self.servers.append(server)
        return server.client_sock


@pytest.fixture
def service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[mms_service.SubscriptionManager, FakeIed, list[str]]]:
    for name in ("SUBSCRIPTIONS_PATH", "RECENTS_PATH", "COMMANDS_PATH"):
        monkeypatch.setattr(mms_service, name, tmp_path / f"{name}.json")
    ied = FakeIed()
    monkeypatch.setattr(transport.socket, "create_connection", ied.connect)
    pushed: list[str] = []
    monkeypatch.setattr(mms_service, "push_lines", lambda _url, lines, **_k: pushed.extend(lines))
    manager = mms_service.SubscriptionManager(vm_url="http://vm", vm_batch_ms=0)
    yield manager, ied, pushed
    manager.purge_all()
    for server in ied.servers:
        server.close()


def _wait(condition, timeout: float = 5.0) -> None:  # type: ignore[no-untyped-def]
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return
        time.sleep(0.02)
    raise AssertionError("condition not met in time")


def test_subscription_end_to_end(service: tuple[mms_service.SubscriptionManager, FakeIed, list[str]]) -> None:
    manager, ied, pushed = service
    cfg = mms_service.SubscriptionConfig(id="s1", ied_host="ied", ied_port=102, domain="LD0", debug=True)
    runtime = manager.create_subscription(cfg)
    _wait(lambda: len(pushed) >= 8)

    assert runtime.rcb_items == ["LLN0$BR$CB_A02"]  # CB_A01 is used by another client
    assert runtime.last_error is None
    writes = [(n.rsplit("$", 1)[1], v) for n, v in ied.model.writes]
    assert [a for a, _ in writes] == ["ResvTms", "IntgPd", "TrgOps", "OptFlds", "PurgeBuf", "EntryID", "RptEna", "GI"]
    assert dict(writes)["TrgOps"].value == b"\x0c"  # po's historical integrity + GI
    assert any('member="A.phsA",component="mag"} 12.5' in line for line in pushed)
    with mms_service.LOG_LOCK:
        logs = [line for _, line in mms_service.LOG_LINES]
    assert any(line.startswith("REPORT LDTEST_DEP1 seq=7") for line in logs)

    manager.delete_subscription("s1")
    assert ied.model.writes[-1] == ("LLN0$BR$CB_A02$RptEna", BoolData(False))


def test_triggers_are_configurable(service: tuple[mms_service.SubscriptionManager, FakeIed, list[str]]) -> None:
    manager, ied, pushed = service
    cfg = mms_service.SubscriptionConfig(
        id="s2", ied_host="ied", ied_port=102, domain="LD0", triggers="dchg,qchg,integrity,gi", integrity_ms=1000
    )
    manager.create_subscription(cfg)
    _wait(lambda: len(pushed) >= 8)
    writes = dict((n.rsplit("$", 1)[1], v) for n, v in ied.model.writes)
    assert writes["TrgOps"].value == b"\x6c"
    assert writes["IntgPd"].value == 1000


def test_http_api_fields(service: tuple[mms_service.SubscriptionManager, FakeIed, list[str]]) -> None:
    import json

    from mms.mms_api import handle_mms

    manager, _, pushed = service
    body = {"id": "s3", "ied_host": "ied", "domain": "LD0", "triggers": "integrity,bogus"}
    status, result = handle_mms(manager, "/subscriptions", "POST", json.dumps(body).encode())
    assert status == 400 and "unknown trigger" in result["error"]

    body["triggers"] = "dchg,gi"
    status, result = handle_mms(manager, "/subscriptions", "POST", json.dumps(body).encode())
    assert status == 201
    assert (result["triggers"], result["integrity_ms"]) == ("dchg,gi", 2000)
    _wait(lambda: len(pushed) >= 8)

    status, result = handle_mms(manager, "/subscriptions/s3", "PUT", json.dumps({"integrity_ms": "500"}).encode())
    assert status == 200 and result["integrity_ms"] == 500
    status, result = handle_mms(manager, "/subscriptions/s3", "PUT", json.dumps({"triggers": "nope"}).encode())
    assert status == 400
