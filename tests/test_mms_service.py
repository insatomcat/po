# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""The MMS subscription service end to end, against a scripted IED."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fake_ied import FakeModel, FakeServer
from test_mms_reporting import DS, MEMBERS, _report_bytes

from open61850 import ber
from open61850.data import BoolData, IntData, VisibleStringData
from open61850.mms import pdu, transport
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
            object_class = list(ber.iter_tlvs(ber.decode_tlv(content).value))[0].value[0]
            if object_class == 9:  # domains
                names = ["LD0"]
            else:
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


def test_subscription_end_to_end(
    service: tuple[mms_service.SubscriptionManager, FakeIed, list[str]], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("INFO", logger="mms.mms_service")
    manager, ied, pushed = service
    cfg = mms_service.SubscriptionConfig(id="s1", ied_host="ied", ied_port=102, domain="LD0", debug=True)
    runtime = manager.create_subscription(cfg)
    _wait(lambda: len(pushed) >= 8)

    assert runtime.rcb_items == ["LD0/LLN0$BR$CB_A02"]  # CB_A01 is used by another client
    assert runtime.last_error is None
    writes = [(n.rsplit("$", 1)[1], v) for n, v in ied.model.writes]
    assert [a for a, _ in writes] == ["ResvTms", "IntgPd", "TrgOps", "OptFlds", "PurgeBuf", "EntryID", "RptEna", "GI"]
    assert dict(writes)["TrgOps"].value == b"\x0c"  # po's historical integrity + GI
    assert any('member="A.phsA",component="mag"} 12.5' in line for line in pushed)
    assert any(r.getMessage().startswith("REPORT LDTEST_DEP1 seq=7") for r in caplog.records)

    manager.delete_subscription("s1")
    assert ied.model.writes[-2:] == [("LLN0$BR$CB_A02$RptEna", BoolData(False)), ("LLN0$BR$CB_A02$ResvTms", IntData(0))]


def test_stop_all_releases_rcbs_and_keeps_the_configuration(
    service: tuple[mms_service.SubscriptionManager, FakeIed, list[str]],
) -> None:
    manager, ied, pushed = service
    manager.create_subscription(mms_service.SubscriptionConfig(id="s9", ied_host="ied", ied_port=102, domain="LD0"))
    _wait(lambda: len(pushed) >= 8)
    manager.stop_all()
    assert ied.model.writes[-2:] == [("LLN0$BR$CB_A02$RptEna", BoolData(False)), ("LLN0$BR$CB_A02$ResvTms", IntData(0))]
    assert "s9" in manager.list_subscriptions()


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
    status, result = handle_mms(manager, "/subscriptions/s3", "PUT", json.dumps({"rcb_filter": "CB_A*"}).encode())
    assert status == 200 and result["rcb_filter"] == "CB_A*" and result["domain"] == "LD0"

    body = {"id": "s4", "ied_host": "ied", "rcb_filter": "CB_Z*"}  # no domain: every logical device
    status, result = handle_mms(manager, "/subscriptions", "POST", json.dumps(body).encode())
    assert status == 201 and result["domain"] == "" and result["rcb_filter"] == "CB_Z*"
    status, result = handle_mms(manager, "/subscriptions", "POST", json.dumps({"id": "s5"}).encode())
    assert status == 400 and "ied_host" in result["error"]


def test_command_operates_the_breaker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    from fake_ied import ControlIed, _last_appl_error, _report, _terminate

    from open61850.mms import control
    from mms.mms_api import handle_mms

    monkeypatch.setattr(mms_service, "COMMANDS_PATH", tmp_path / "commands.json")
    monkeypatch.setattr(mms_service, "SUBSCRIPTIONS_PATH", tmp_path / "subscriptions.json")
    monkeypatch.setattr(mms_service, "RECENTS_PATH", tmp_path / "recents.json")
    refuse = {"on": False}

    def react(server: FakeServer, value: object) -> object:
        if refuse["on"]:
            server.send_mms(_report([control.LAST_APPL_ERROR], [_last_appl_error(5, "IED01_BayLD/CBCSWI1$CO$Pos$Oper")]))
            return bytes.fromhex("800103")
        return _terminate(server, value)  # type: ignore[arg-type]

    ied = ControlIed(control.CTL_MODEL_DIRECT_ENHANCED, react)
    servers: list[FakeServer] = []

    def connect(*_a: object, **_k: object) -> object:
        servers.append(FakeServer(ied))
        return servers[-1].client_sock

    monkeypatch.setattr(transport.socket, "create_connection", connect)
    manager = mms_service.SubscriptionManager(vm_url=None, vm_batch_ms=0)
    body = {"id": "c1", "ied_host": "ied", "domain": "IED01_BayLD", "item": "CBCSWI1$CO$Pos$Oper", "position": "open"}
    assert handle_mms(manager, "/commands", "POST", json.dumps({**body, "position": "intermediate"}).encode())[0] == 400
    assert handle_mms(manager, "/commands", "POST", json.dumps(body).encode())[0] == 201
    try:
        for expected_ctl_num in (0, 1):
            status, result = handle_mms(manager, "/commands/c1/send", "POST", b"")
            assert status == 200 and result["terminated"] and result["ctl_num"] == expected_ctl_num
        oper = ied.writes[-1][1]
        assert oper.members[0] == BoolData(False)  # type: ignore[attr-defined]
        assert oper.members[1].members[0] == IntData(2)  # type: ignore[attr-defined]  # station-control

        refuse["on"] = True
        status, result = handle_mms(manager, "/commands/c1/send", "POST", b"")
        assert status == 409 and result["add_cause"] == "position-reached"
    finally:
        for server in servers:
            server.close()


class _NamesClient:
    """Answers GetNameList only: domains, then the names of each domain."""

    def __init__(self, domains: dict[str, list[str]]) -> None:
        self.domains = domains
        self.calls: list[object] = []

    def get_name_list(self, object_class: int, domain: object = None) -> list[str]:
        self.calls.append(domain)
        return list(self.domains) if object_class == 9 else self.domains[domain]  # type: ignore[index]


def _groups(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, client: _NamesClient, **cfg: object) -> list[str]:
    from conftest import DATA_DIR

    for name in ("SUBSCRIPTIONS_PATH", "RECENTS_PATH", "COMMANDS_PATH"):
        monkeypatch.setattr(mms_service, name, tmp_path / f"{name}.json")
    manager = mms_service.SubscriptionManager(vm_url=None, vm_batch_ms=0)
    config = mms_service.SubscriptionConfig(id="g", ied_host="192.0.2.10", ied_port=102, **cfg)  # type: ignore[arg-type]
    config.scl = str(DATA_DIR / "two_ieds.scd.xml") if config.scl == "fixture" else config.scl
    groups = manager._rcb_groups(config, client, mms_service.load_scl_ied(config))  # type: ignore[arg-type]
    return [str(g.base) for g in groups]


def test_blocks_come_from_the_scl_when_it_matches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _NamesClient({"IED01_ALD0": [], "IED01_ACTRL": []})
    groups = _groups(tmp_path, monkeypatch, client, scl="fixture")
    assert "IED01_ALD0/LLN0$BR$CB_LDPX_DQPO_DEP1" in groups and "IED01_ACTRL/CBCSWI1$BR$CB_POS" in groups
    assert client.calls == [None]  # only the domain list: no name listing of the logical devices


def test_blocks_are_discovered_when_the_scl_describes_another_ied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _NamesClient({"IED02LD0": ["LLN0", "LLN0$BR$CB_X01", "LLN0$BR$CB_X02", "LLN0$BR$CB_X01$RptID"], "IED02CTRL": []})
    assert _groups(tmp_path, monkeypatch, client, scl="fixture") == ["IED02LD0/LLN0$BR$CB_X"]
    assert client.calls == [None, "IED02LD0", "IED02CTRL"]


def test_a_missing_domain_is_named(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from open61850.mms import MmsError

    with pytest.raises(MmsError, match="domain IED01_XLD0 not on the IED at 192.0.2.10, which has IED02LD0"):
        _groups(tmp_path, monkeypatch, _NamesClient({"IED02LD0": []}), domain="IED01_XLD0")
