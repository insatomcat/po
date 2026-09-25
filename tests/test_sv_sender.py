# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""The sender command of an SV flow: open61850-sv by default, rt_sender on request."""

from __future__ import annotations

import sys

import pytest

pytest.importorskip("fastapi")
import sv_service  # noqa: E402
from open61850.sv_publisher import _parser, stream_from_args  # noqa: E402


def _flow(**kwargs: object) -> sv_service.FlowConfig:
    base = dict(name="f1", interface="eth1", src_mac="02:00:00:00:0f:01", dst_mac="01:0c:cd:04:0f:01",
                svid="IED01_TEST_SV1", appid=0x4F01, conf_rev=20000, smp_synch=2, vlan_id=105, vlan_priority=5,
                freq_hz=50.0, i_peak=354.0, v_peak=51440.0, phase_deg=20.0, fault=True, fault_i_peak=5000.0,
                fault_v_peak=20000.0, fault_phase_deg=80.0, fault_cycle_s=4, fault_smpcnt=24, fault_offset_s=1)
    base.update(kwargs)
    return sv_service.FlowConfig(**base)  # type: ignore[arg-type]


def test_flows_run_open61850_sv_with_their_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sv_service, "SV_SENDER", "open61850")
    cmd = sv_service.build_rt_sender_cmd(_flow())
    assert cmd[:3] == [sys.executable, "-m", "open61850.sv_publisher"]
    stream = stream_from_args(_parser().parse_args(cmd[3:]))
    assert (stream.sv_id, stream.app_id, stream.conf_rev, stream.smp_synch) == ("IED01_TEST_SV1", 0x4F01, 20000, 2)
    assert (stream.vlan_id, stream.vlan_priority, stream.fault.cycle_s, stream.fault.start_smp) == (105, 5, 4, 24)
    assert stream.waves[0].amplitude == 354.0 and stream.fault.waves[0].amplitude == 5000.0


def test_rt_sender_on_request(monkeypatch: pytest.MonkeyPatch, tmp_path: object) -> None:
    monkeypatch.setattr(sv_service, "SV_SENDER", "rt_sender")
    monkeypatch.setattr(sv_service, "RT_SENDER_PATH", sv_service.BASE_DIR / "rt_sender.c")  # any existing file
    cmd = sv_service.build_rt_sender_cmd(_flow(fault=False, vlan_id=None))
    assert cmd[0].endswith("rt_sender.c") and "--fault" not in cmd and "--vlan-id" not in cmd
    assert cmd[-4:] == ["eth1", "02:00:00:00:0f:01", "01:0c:cd:04:0f:01", "IED01_TEST_SV1"]
