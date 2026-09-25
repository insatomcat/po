# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""processbus_capture: one AF_PACKET capture shared by GOOSE and SV (Linux, root)."""

from __future__ import annotations

import socket
import struct
import sys
import time

import pytest

DST = bytes.fromhex("010ccd010001")
SRC = bytes.fromhex("020000000001")


def _frame(ethertype: int, vlan: int | None = None, body: bytes = b"\x00\x01\x00\x08\x00\x00\x00\x00") -> bytes:
    tag = struct.pack("!HH", 0x8100, (4 << 13) | vlan) if vlan is not None else b""
    return DST + SRC + tag + ethertype.to_bytes(2, "big") + body


linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="AF_PACKET is Linux only")


def _raw_sender() -> socket.socket:
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)  # type: ignore[attr-defined]
    except PermissionError:
        pytest.skip("needs CAP_NET_RAW")
    sock.bind(("lo", 0))
    return sock


@linux_only
def test_processbus_capture_on_lo() -> None:
    import threading

    from processbus_capture import ProcessbusCapture

    sender = _raw_sender()
    mux = ProcessbusCapture("lo")
    goose: list[bytes] = []
    sv: list[bytes] = []
    done = threading.Event()

    def on_goose(_ts: float, raw: bytes) -> None:
        goose.append(raw)

    def on_sv(_header: object, raw: bytes, _ts: float) -> None:
        sv.append(raw)
        done.set()

    unsubscribe_goose = mux.subscribe_goose(on_goose)
    unsubscribe_sv = mux.subscribe_sv(on_sv)
    try:
        deadline = time.time() + 5
        while mux.stats()["bpf_mode"] != "goose+sv" and time.time() < deadline:
            time.sleep(0.02)
        with sender:
            sender.send(_frame(0x88B8, vlan=305))
            sender.send(_frame(0x0800))
            sender.send(_frame(0x88BA, vlan=105))
            assert done.wait(5)
        time.sleep(0.1)
        assert goose == [_frame(0x88B8, vlan=305)] and sv == [_frame(0x88BA, vlan=105)]
        stats = mux.stats()
        assert stats["goose_packets"] == 1 and stats["sv_packets"] == 1
    finally:
        unsubscribe_sv()
        unsubscribe_goose()


@linux_only
def test_processbus_capture_lets_sv_through_only_for_an_sv_subscriber() -> None:
    from processbus_capture import ProcessbusCapture

    sender = _raw_sender()
    mux = ProcessbusCapture("lo")
    goose: list[bytes] = []
    unsubscribe_goose = mux.subscribe_goose(lambda _ts, raw: goose.append(raw))

    def wait_mode(mode: str) -> None:
        deadline = time.time() + 5
        while mux.stats()["bpf_mode"] != mode and time.time() < deadline:
            time.sleep(0.02)
        assert mux.stats()["bpf_mode"] == mode

    try:
        with sender:
            wait_mode("goose")
            sender.send(_frame(0x88BA, vlan=105))
            sender.send(_frame(0x88B8, vlan=305))
            deadline = time.time() + 5
            while not goose and time.time() < deadline:
                time.sleep(0.02)
            assert mux.stats()["packets"] == 1  # the SV frame stayed in the kernel

            sv: list[bytes] = []
            unsubscribe_sv = mux.subscribe_sv(lambda _h, raw, _ts: sv.append(raw))
            wait_mode("goose+sv")
            sender.send(_frame(0x88BA, vlan=105))
            deadline = time.time() + 5
            while not sv and time.time() < deadline:
                time.sleep(0.02)
            unsubscribe_sv()
            assert sv == [_frame(0x88BA, vlan=105)]
    finally:
        unsubscribe_goose()
