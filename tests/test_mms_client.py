# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""TPKT/COTP framing and MMSReportsClient behaviour against a scripted fake IED."""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import Callable, Iterator

import pytest
from conftest import DATA_DIR

from iec_data import _tlv
from mms import mms_reports_client
from mms.asn1_codec import MMSReport
from mms.cotp import cotp_recv_data, cotp_send_data
from mms.mms_reports_client import MMSReportsClient
from mms.tpkt import TPKTError, recv_tpkt, send_tpkt

SESSION_PREFIX = bytes.fromhex("01000100")


def _presentation(mms_pdu: bytes) -> bytes:
    pdv = bytes.fromhex("020103") + _tlv(0xA0, mms_pdu)
    return SESSION_PREFIX + _tlv(0x61, _tlv(0x30, pdv))


def _write_response(invoke_id: int) -> bytes:
    body = _tlv(0x02, invoke_id.to_bytes(2, "big")) + _tlv(0xA5, bytes.fromhex("8100"))
    return _presentation(_tlv(0xA1, body))


def _read_response(invoke_id: int) -> bytes:
    service = _tlv(0xA4, _tlv(0xA1, _tlv(0xA2, bytes.fromhex("8a03525054"))))
    return _presentation(_tlv(0xA1, _tlv(0x02, invoke_id.to_bytes(2, "big")) + service))


def _report(rpt_id: str) -> bytes:
    values = _tlv(0x8A, rpt_id.encode()) + bytes.fromhex("8403067b00") + bytes.fromhex("860101")
    report = _tlv(0xA0, _tlv(0xA1, _tlv(0x80, b"RPT")) + _tlv(0xA0, values))
    return _presentation(_tlv(0xA3, report))


def _invoke_id_of(request: bytes) -> int:
    return int.from_bytes(request[17:19], "big")


# --- framing ----------------------------------------------------------------


def test_tpkt_round_trip() -> None:
    a, b = socket.socketpair()
    with a, b:
        send_tpkt(a, b"\x01\x02\x03")
        assert recv_tpkt(b, timeout=1) == b"\x01\x02\x03"
        a.sendall(b"\x04\x00\x00\x05\x00")
        with pytest.raises(TPKTError):
            recv_tpkt(b, timeout=1)


def test_tpkt_eof_returns_none() -> None:
    a, b = socket.socketpair()
    with b:
        a.close()
        assert recv_tpkt(b, timeout=1) is None


def test_cotp_reassembles_segmented_tsdu() -> None:
    # A 2176-byte GetNameList response from a real IED, split over three DT TPDUs.
    segments = json.loads((DATA_DIR / "iedscout_getnamelist.json").read_text())["gnl_vars_resp_segments"]
    a, b = socket.socketpair()
    with a, b:
        for seg, eot in segments:
            send_tpkt(a, bytes([0x02, 0xF0, 0x80 if eot else 0x00]) + bytes.fromhex(seg))
        assert cotp_recv_data(b, timeout=1) == b"".join(bytes.fromhex(seg) for seg, _ in segments)


def test_cotp_data_skips_other_tpdus() -> None:
    a, b = socket.socketpair()
    with a, b:
        send_tpkt(a, bytes.fromhex("06d00000000100"))  # a CC TPDU, ignored
        cotp_send_data(a, b"payload")
        assert cotp_recv_data(b, timeout=1) == b"payload"


# --- client against a fake IED ----------------------------------------------

Script = Callable[[socket.socket], None]


@pytest.fixture
def fake_ied(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[Script], None]]:
    """Route MMSReportsClient's TCP connection to a thread running `script`."""
    threads: list[threading.Thread] = []
    errors: list[BaseException] = []

    def install(script: Script) -> None:
        client_side, ied_side = socket.socketpair()

        def run() -> None:
            try:
                with ied_side:
                    cr = recv_tpkt(ied_side, timeout=2)
                    assert cr is not None and cr[1] == 0xE0
                    send_tpkt(ied_side, bytes.fromhex("06d00000000100"))
                    initiate = cotp_recv_data(ied_side, timeout=2)
                    assert initiate is not None and initiate[:2] == b"\x0d\xb2"
                    cotp_send_data(ied_side, b"\x0e\x00")  # content not decoded by the client
                    script(ied_side)
            except BaseException as exc:  # noqa: BLE001 - surfaced after the test
                errors.append(exc)

        monkeypatch.setattr(
            mms_reports_client.socket, "create_connection", lambda *_a, **_k: client_side
        )
        t = threading.Thread(target=run, daemon=True)
        threads.append(t)
        t.start()

    yield install
    for t in threads:
        t.join(timeout=5)
    if errors:
        raise errors[0]


def test_enable_reporting_forwards_interleaved_reports(fake_ied: Callable[[Script], None]) -> None:
    seen_attrs: list[bytes] = []

    def script(ied: socket.socket) -> None:
        get = cotp_recv_data(ied, timeout=2)
        assert get is not None
        cotp_send_data(ied, _report("early"))  # a report arrives before the response
        cotp_send_data(ied, _read_response(_invoke_id_of(get)))
        for _ in range(8):
            req = cotp_recv_data(ied, timeout=2)
            assert req is not None
            seen_attrs.append(req.rsplit(b"$", 1)[1].split(b"\xa0", 1)[0])
            cotp_send_data(ied, _write_response(_invoke_id_of(req)))
        cotp_send_data(ied, _report("late"))

    fake_ied(script)
    reports: list[MMSReport] = []
    client = MMSReportsClient("ied", timeout=2)
    client.connect()
    try:
        client.enable_reporting("LD0", "LLN0$BR$CB01", report_callback=reports.append)
        client.loop_reports(reports.append, quiet_heartbeat=True)
    finally:
        client.close()

    assert seen_attrs == [
        b"ResvTms", b"IntgPd", b"TrgOps", b"OptFlds", b"PurgeBuf", b"EntryID", b"RptEna", b"GI",
    ]
    assert [r.rpt_id for r in reports] == ["early", "late"]
    assert reports[0].raw_pdu is not None


@pytest.mark.xfail(strict=True, reason="known bug: responses are not matched by invokeID")
def test_probe_rcb_ignores_response_to_other_request(fake_ied: Callable[[Script], None]) -> None:
    def script(ied: socket.socket) -> None:
        get = cotp_recv_data(ied, timeout=2)
        assert get is not None
        # A late success answer to an older request, then the real failure.
        cotp_send_data(ied, _read_response(_invoke_id_of(get) - 1))
        failure = _tlv(0xA4, _tlv(0xA1, bytes.fromhex("80010a")))
        body = _tlv(0x02, _invoke_id_of(get).to_bytes(2, "big")) + failure
        cotp_send_data(ied, _presentation(_tlv(0xA1, body)))

    fake_ied(script)
    client = MMSReportsClient("ied", timeout=2)
    client.connect()
    try:
        assert client.probe_rcb("LD0", "LLN0$BR$MISSING") is False
    finally:
        client.close()
