"""API Stress-test pour intégration dans po_service."""
from __future__ import annotations

import json
from http import HTTPStatus
from typing import Any

from .stress_service import get_stress_manager


def handle_stress(path: str, method: str, body: bytes | None) -> tuple[int, Any]:
    mgr = get_stress_manager()
    path = (path or "/").rstrip("/") or "/"
    data: dict[str, Any] = {}
    if body and method in ("POST", "PUT", "PATCH"):
        try:
            raw = json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
            data = raw if isinstance(raw, dict) else {}
        except json.JSONDecodeError:
            return HTTPStatus.BAD_REQUEST, {"error": "JSON invalide"}

    if path == "/status" and method == "GET":
        key = str(data.get("key") or "").strip() or None
        return HTTPStatus.OK, mgr.status(key)

    if path == "/hosts" and method == "GET":
        return HTTPStatus.OK, {"hosts": mgr.hosts()}

    if path == "/hosts" and method in ("PUT", "POST"):
        hosts = data.get("hosts")
        if not isinstance(hosts, list):
            return HTTPStatus.BAD_REQUEST, {"error": "hosts doit être une liste"}
        return HTTPStatus.OK, {"hosts": mgr.save_hosts(hosts)}

    if path == "/connect" and method == "POST":
        result = mgr.connect(
            host=str(data.get("host") or "").strip(),
            port=int(data.get("port") or 22),
            user=str(data.get("user") or "root"),
            identity=str(data.get("identity") or ""),
            password=str(data.get("password") or ""),
            name=str(data.get("name") or ""),
            force_ssh=bool(data.get("force_ssh")),
        )
        if result.get("error") and result.get("current") is None:
            return HTTPStatus.BAD_GATEWAY, result
        if result.get("error"):
            return HTTPStatus.BAD_GATEWAY, result
        return HTTPStatus.OK, result

    if path == "/start" and method == "POST":
        spec = {
            "cpus": data.get("cpus") or [],
            "workloads": data.get("workloads") or ["cpu"],
            "cpu_load": int(data.get("cpu_load") or 100),
            "timeout_s": int(data.get("timeout_s") or 0),
        }
        key = str(data.get("key") or "").strip() or None
        result = mgr.start(spec, key=key)
        if result.get("error"):
            return HTTPStatus.CONFLICT, result
        return HTTPStatus.OK, result

    if path == "/stop" and method == "POST":
        key = str(data.get("key") or "").strip() or None
        result = mgr.stop(key)
        if result.get("error"):
            return HTTPStatus.CONFLICT, result
        return HTTPStatus.OK, result

    if path == "/disconnect" and method == "POST":
        key = str(data.get("key") or "").strip() or None
        stop_stress = bool(data.get("stop_stress"))
        return HTTPStatus.OK, mgr.disconnect(key, stop_stress=stop_stress)

    if path == "/select" and method == "POST":
        key = str(data.get("key") or "").strip()
        if not key:
            return HTTPStatus.BAD_REQUEST, {"error": "key requise"}
        result = mgr.select(key)
        if result.get("error"):
            return HTTPStatus.NOT_FOUND, result
        return HTTPStatus.OK, result

    return HTTPStatus.NOT_FOUND, {"error": "Route inconnue"}
