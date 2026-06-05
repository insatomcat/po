"""API GOOSE Listener pour intégration dans po_service."""
from __future__ import annotations

import json
from http import HTTPStatus
from typing import Any, Optional, Union

GooseListenerResponse = Union[tuple[int, Any], tuple[int, str, str]]

from goose_listener_service import (
    AnalysisTarget,
    get_goose_listener,
    init_goose_listener,
    _normalize_event_filter,
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
        raw_targets = data.get("targets") or []
        targets: list[AnalysisTarget] = []
        if isinstance(raw_targets, list):
            for item in raw_targets:
                if not isinstance(item, dict):
                    continue
                gocb_ref = str(item.get("gocb_ref") or "").strip()
                if not gocb_ref:
                    continue
                go_id = str(item.get("go_id") or "").strip()
                delay_ms = float(item.get("delay_ms") or 0)
                targets.append(
                    AnalysisTarget(
                        gocb_ref=gocb_ref,
                        go_id=go_id,
                        delay_ms=max(0.0, delay_ms),
                    )
                )
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

    if path == "/analysis/stop" and method == "POST":
        mgr.stop_analysis()
        return HTTPStatus.OK, mgr.analysis_status()

    if path == "/analysis" and method == "GET":
        return HTTPStatus.OK, mgr.analysis_status()

    if path == "/analysis/events/export" and method == "GET":
        return HTTPStatus.OK, mgr.export_events_txt(), "text/plain; charset=utf-8"

    if path == "/analysis/problems/export" and method == "GET":
        return HTTPStatus.OK, mgr.export_problems_txt(), "text/plain; charset=utf-8"

    return HTTPStatus.NOT_FOUND, {"error": "Route inconnue"}


def configure_goose_listener(iface: Optional[str]) -> None:
    if iface:
        init_goose_listener(iface)
