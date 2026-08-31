"""API GOOSE Listener pour intégration dans po_service."""
from __future__ import annotations

import json
from http import HTTPStatus
from typing import Any, Optional, Union

GooseListenerResponse = Union[
    tuple[int, Any],
    tuple[int, str, str],
    tuple[int, bytes, str],
]

from goose_listener_service import (
    get_goose_listener,
    init_goose_listener,
    _normalize_event_filter,
    _targets_from_payload,
)


def handle_goose_listener(path: str, method: str, body: bytes | None) -> GooseListenerResponse:
    mgr = get_goose_listener()
    if mgr is None:
        return HTTPStatus.SERVICE_UNAVAILABLE, {
            "error": "GOOSE Listener non configuré (--svview-interface)",
        }

    path = (path or "/").rstrip("/") or "/"
    data: dict = {}
    if body and method in ("POST", "PUT", "PATCH"):
        try:
            raw = json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
            data = raw if isinstance(raw, dict) else {}
        except json.JSONDecodeError:
            return HTTPStatus.BAD_REQUEST, {"error": "JSON invalide"}

    if path == "/status" and method == "GET":
        return HTTPStatus.OK, mgr.status()

    if path == "/scan" and method == "POST":
        duration_s = float(data.get("duration_s", 5))
        err = mgr.start_scan(duration_s=duration_s)
        if err:
            return HTTPStatus.CONFLICT, {"error": err}
        return HTTPStatus.OK, mgr.scan_status()

    if path == "/scan" and method == "GET":
        return HTTPStatus.OK, mgr.scan_status()

    if path == "/analysis/start" and method == "POST":
        targets = _targets_from_payload(data.get("targets") or [])
        event_filter = _normalize_event_filter(
            str(data.get("event_filter") or "declenchements_only").strip()
        )
        err = mgr.start_analysis(targets, event_filter=event_filter)
        if err:
            return HTTPStatus.BAD_REQUEST, {"error": err}
        return HTTPStatus.OK, mgr.analysis_status()

    if path == "/analysis/filter" and method == "POST":
        event_filter = _normalize_event_filter(str(data.get("event_filter") or "").strip())
        err = mgr.set_event_filter(event_filter)
        if err:
            return HTTPStatus.BAD_REQUEST, {"error": err}
        return HTTPStatus.OK, mgr.analysis_status()

    if path == "/analysis/problems" and method == "POST":
        cycle_s = data.get("cycle_s")
        threshold_ms = data.get("threshold_ms")
        err = mgr.set_problem_config(
            cycle_s=float(cycle_s) if cycle_s is not None else None,
            threshold_ms=float(threshold_ms) if threshold_ms is not None else None,
        )
        if err:
            return HTTPStatus.BAD_REQUEST, {"error": err}
        return HTTPStatus.OK, mgr.analysis_status()

    if path == "/analysis/demo-delay" and method == "POST":
        err = mgr.inject_demo_delay(
            gocb_ref=str(data.get("gocb_ref") or "").strip() or None,
            go_id=str(data.get("go_id") or "").strip() or None,
        )
        if err:
            return HTTPStatus.CONFLICT, {"error": err}
        return HTTPStatus.OK, mgr.analysis_status()

    if path == "/analysis/stop" and method == "POST":
        mgr.stop_analysis()
        return HTTPStatus.OK, mgr.analysis_status()

    if path == "/analysis/reset" and method == "POST":
        mgr.reset_session()
        return HTTPStatus.OK, mgr.analysis_status()

    if path == "/analysis" and method == "GET":
        return HTTPStatus.OK, mgr.analysis_status()

    if path == "/analysis/events/export" and method == "GET":
        return HTTPStatus.OK, mgr.export_events_txt(), "text/plain; charset=utf-8"

    if path == "/analysis/problems/export" and method == "GET":
        return HTTPStatus.OK, mgr.export_problems_txt(), "text/plain; charset=utf-8"

    if path == "/analysis/dumps" and method == "GET":
        return HTTPStatus.OK, mgr.list_ring_dumps()

    if method == "GET" and path.startswith("/analysis/dumps/") and path.endswith("/pcap"):
        dump_id = path[len("/analysis/dumps/") : -len("/pcap")]
        data = mgr.read_ring_dump_bytes(dump_id)
        if data is None:
            return HTTPStatus.NOT_FOUND, {"error": "Dump introuvable"}
        return HTTPStatus.OK, data, "application/vnd.tcpdump.pcap"

    return HTTPStatus.NOT_FOUND, {"error": "Route inconnue"}


def configure_goose_listener(iface: Optional[str]) -> None:
    if iface:
        init_goose_listener(iface)


def restore_goose_listener_analysis() -> None:
    """Relance l'analyse persistée une fois le service prêt (après init SV/GOOSE)."""
    mgr = get_goose_listener()
    if mgr is not None:
        mgr.restore_analysis_if_needed()
