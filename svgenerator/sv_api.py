"""
API SV Generator exposée sans FastAPI pour intégration dans le service unifié.
Routes: /flows, /flows/recents, /flows/{name}
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Ajouter le répertoire parent pour les imports
_here = Path(__file__).resolve().parent
if str(_here) not in sys.path:
    sys.path.insert(0, str(_here))

from sv_service import (
    FlowConfig,
    FlowState,
    FlowRuntime,
    flows,
    flows_lock,
    recents,
    recents_lock,
    start_flow_process,
    stop_flow_process,
    save_config,
    _add_to_recents,
    _load_recents,
    _is_pid_alive,
    rebuild_from_config,
)


def init_sv_api() -> None:
    """Initialise l'API SV (charge config, récents) pour usage sans uvicorn."""
    _load_recents()
    rebuild_from_config()


def handle_sv(path: str, method: str, body: bytes | None) -> tuple[int, dict | list]:
    """
    Traite une requête API SV.
    path: chemin après /api/sv (ex: "/flows", "/flows/recents", "/flows/monflux")
    method: GET, POST, PUT, DELETE
    body: corps brut (JSON pour POST/PUT)
    Retourne (status_code, body_json_serializable).
    """
    path = (path or "/").rstrip("/") or "/"
    data = {}
    if body and method in ("POST", "PUT"):
        try:
            data = json.loads(body.decode("utf-8")) if isinstance(body, bytes) else json.loads(body)
            if not isinstance(data, dict):
                data = {}
        except json.JSONDecodeError:
            return 400, {"detail": "Invalid JSON"}

    # GET /flows
    if path == "/flows" and method == "GET":
        result = []
        with flows_lock:
            for fr in flows.values():
                running = (
                    (fr.proc is not None and fr.proc.poll() is None)
                    or (fr.pid is not None and _is_pid_alive(fr.pid))
                )
                result.append(
                    FlowState(
                        name=fr.config.name,
                        interface=fr.config.interface,
                        src_mac=fr.config.src_mac,
                        dst_mac=fr.config.dst_mac,
                        svid=fr.config.svid,
                        appid=fr.config.appid,
                        conf_rev=fr.config.conf_rev,
                        smp_synch=fr.config.smp_synch,
                        vlan_id=fr.config.vlan_id,
                        vlan_priority=fr.config.vlan_priority,
                        freq_hz=fr.config.freq_hz,
                        i_peak=fr.config.i_peak,
                        v_peak=fr.config.v_peak,
                        phase_deg=fr.config.phase_deg,
                        fault=fr.config.fault,
                        fault_i_peak=fr.config.fault_i_peak,
                        fault_v_peak=fr.config.fault_v_peak,
                        fault_phase_deg=fr.config.fault_phase_deg,
                        fault_cycle_s=fr.config.fault_cycle_s,
                        running=running,
                    ).dict()
                )
        return 200, result

    # GET /flows/recents
    if path == "/flows/recents" and method == "GET":
        with recents_lock:
            return 200, [c.dict() for c in recents]

    # POST /flows
    if path == "/flows" and method == "POST":
        try:
            cfg = FlowConfig(**data)
        except Exception as e:
            return 422, {"detail": str(e)}
        with flows_lock:
            if cfg.name in flows:
                return 409, {"detail": "Flow already exists"}
            try:
                proc = start_flow_process(cfg)
            except Exception as exc:
                return 500, {"detail": str(exc)}
            flows[cfg.name] = FlowRuntime(config=cfg, proc=proc)
        _add_to_recents(cfg)
        save_config()
        return 201, FlowState(
            name=cfg.name,
            interface=cfg.interface,
            src_mac=cfg.src_mac,
            dst_mac=cfg.dst_mac,
            svid=cfg.svid,
            appid=cfg.appid,
            conf_rev=cfg.conf_rev,
            smp_synch=cfg.smp_synch,
            vlan_id=cfg.vlan_id,
            vlan_priority=cfg.vlan_priority,
            freq_hz=cfg.freq_hz,
            i_peak=cfg.i_peak,
            v_peak=cfg.v_peak,
            phase_deg=cfg.phase_deg,
            fault=cfg.fault,
            fault_i_peak=cfg.fault_i_peak,
            fault_v_peak=cfg.fault_v_peak,
            fault_phase_deg=cfg.fault_phase_deg,
            fault_cycle_s=cfg.fault_cycle_s,
            running=True,
        ).dict()

    # PUT /flows/{name}
    if path.startswith("/flows/") and path != "/flows/" and path != "/flows/recents" and method == "PUT":
        name = path[len("/flows/"):].rstrip("/")
        if not name:
            return 404, {"detail": "Not found"}
        try:
            cfg = FlowConfig(**{**data, "name": name})
        except Exception as e:
            return 422, {"detail": str(e)}
        with flows_lock:
            if name in flows:
                stop_flow_process(flows[name])
            try:
                proc = start_flow_process(cfg)
            except Exception as exc:
                return 500, {"detail": str(exc)}
            flows[cfg.name] = FlowRuntime(config=cfg, proc=proc)
        _add_to_recents(cfg)
        save_config()
        return 200, FlowState(
            name=cfg.name,
            interface=cfg.interface,
            src_mac=cfg.src_mac,
            dst_mac=cfg.dst_mac,
            svid=cfg.svid,
            appid=cfg.appid,
            conf_rev=cfg.conf_rev,
            smp_synch=cfg.smp_synch,
            vlan_id=cfg.vlan_id,
            vlan_priority=cfg.vlan_priority,
            freq_hz=cfg.freq_hz,
            i_peak=cfg.i_peak,
            v_peak=cfg.v_peak,
            phase_deg=cfg.phase_deg,
            fault=cfg.fault,
            fault_i_peak=cfg.fault_i_peak,
            fault_v_peak=cfg.fault_v_peak,
            fault_phase_deg=cfg.fault_phase_deg,
            fault_cycle_s=cfg.fault_cycle_s,
            running=True,
        ).dict()

    # DELETE /flows/{name}
    if path.startswith("/flows/") and path != "/flows/" and path != "/flows/recents" and method == "DELETE":
        name = path[len("/flows/"):].rstrip("/")
        if not name:
            return 404, {"detail": "Not found"}
        with flows_lock:
            fr = flows.get(name)
            if fr is None:
                return 404, {"detail": "Flow not found"}
            _add_to_recents(fr.config)
            stop_flow_process(fr)
            del flows[name]
        save_config()
        return 200, {"status": "ok"}

    # DELETE /flows (tous)
    if path == "/flows" and method == "DELETE":
        with flows_lock:
            for fr in flows.values():
                _add_to_recents(fr.config)
                stop_flow_process(fr)
            flows.clear()
        save_config()
        return 200, {"status": "ok"}

    return 404, {"detail": "Not found"}
