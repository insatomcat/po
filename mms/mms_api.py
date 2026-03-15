"""
API MMS exposée pour intégration dans le service unifié.
Routes: /subscriptions, /recents, /logs (SSE)
"""
from __future__ import annotations

import json
import uuid
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

if TYPE_CHECKING:
    from .mms_service import SubscriptionManager, SubscriptionRuntime


def handle_mms(
    manager: "SubscriptionManager",
    path: str,
    method: str,
    body: Optional[bytes],
) -> Tuple[int, Any]:
    """
    Traite une requête API MMS (hors SSE /logs).
    path: chemin après /api/mms (ex: "/subscriptions", "/recents")
    method: GET, POST, PUT, DELETE
    body: corps brut (JSON pour POST/PUT)
    Retourne (status_code, body) où body est dict/list (sérialisable JSON) ou None pour 204.
    """
    from .mms_service import SubscriptionConfig

    path = (path or "/").rstrip("/") or "/"

    def _read_json() -> Tuple[Optional[dict], bool]:
        if not body or len(body) == 0:
            return {}, True
        try:
            data = json.loads(body.decode("utf-8"))
            return (data, True) if isinstance(data, dict) else (None, False)
        except Exception:
            return None, False

    def _runtime_to_dict(rt: "SubscriptionRuntime") -> Dict[str, Any]:
        cfg = rt.config
        return {
            "id": cfg.id,
            "ied_host": cfg.ied_host,
            "ied_port": cfg.ied_port,
            "domain": cfg.domain,
            "scl": cfg.scl,
            "rcb_list": cfg.rcb_list,
            "debug": cfg.debug,
            "last_error": rt.last_error,
            "rcb_items": list(rt.rcb_items),
        }

    # GET /recents
    if path == "/recents" and method == "GET":
        recents = manager.get_recents()
        return HTTPStatus.OK, recents

    # GET /subscriptions
    if path == "/subscriptions" and method == "GET":
        subs = [
            _runtime_to_dict(rt)
            for rt in manager.list_subscriptions().values()
        ]
        return HTTPStatus.OK, subs

    # GET /subscriptions/<id>
    if path.startswith("/subscriptions/") and method == "GET":
        sub_id = path.split("/", 2)[2]
        rt = manager.get_subscription(sub_id)
        if not rt:
            return HTTPStatus.NOT_FOUND, {"error": f"subscription {sub_id!r} not found"}
        return HTTPStatus.OK, _runtime_to_dict(rt)

    # POST /subscriptions
    if path == "/subscriptions" and method == "POST":
        data, ok = _read_json()
        if not ok or data is None:
            return HTTPStatus.BAD_REQUEST, {"error": "invalid JSON body"}
        try:
            sub_id = data.get("id") or uuid.uuid4().hex
            ied_host = data["ied_host"]
            ied_port = int(data.get("ied_port", 102))
            domain = data["domain"]
        except KeyError as e:
            return HTTPStatus.BAD_REQUEST, {"error": f"missing field: {e.args[0]}"}
        except (TypeError, ValueError):
            return HTTPStatus.BAD_REQUEST, {"error": "invalid ied_port"}

        cfg = SubscriptionConfig(
            id=sub_id,
            ied_host=str(ied_host),
            ied_port=int(ied_port),
            domain=str(domain),
            scl=data.get("scl"),
            rcb_list=data.get("rcb_list"),
            debug=bool(data.get("debug", False)),
        )
        try:
            rt = manager.create_subscription(cfg)
        except ValueError as e:
            return HTTPStatus.CONFLICT, {"error": str(e)}
        return HTTPStatus.CREATED, _runtime_to_dict(rt)

    # PUT /subscriptions/<id>
    if path.startswith("/subscriptions/") and method == "PUT":
        sub_id = path.split("/", 2)[2].rstrip("/")
        data, ok = _read_json()
        if not ok or data is None:
            return HTTPStatus.BAD_REQUEST, {"error": "invalid JSON body"}
        allowed_fields = {"ied_host", "ied_port", "domain", "scl", "rcb_list", "debug"}
        update_fields: Dict[str, Any] = {}
        for k, v in data.items():
            if k not in allowed_fields:
                continue
            if k == "ied_port" and v is not None:
                try:
                    v = int(v)
                except (TypeError, ValueError):
                    return HTTPStatus.BAD_REQUEST, {"error": "invalid ied_port"}
            update_fields[k] = v
        try:
            rt = manager.update_subscription(sub_id, update_fields)
        except KeyError:
            return HTTPStatus.NOT_FOUND, {"error": f"subscription {sub_id!r} not found"}
        return HTTPStatus.OK, _runtime_to_dict(rt)

    # DELETE /subscriptions
    if path == "/subscriptions" and method == "DELETE":
        manager.purge_all()
        return HTTPStatus.NO_CONTENT, None

    # DELETE /subscriptions/<id>
    if path.startswith("/subscriptions/") and method == "DELETE":
        sub_id = path.split("/", 2)[2]
        if not manager.get_subscription(sub_id):
            return HTTPStatus.NOT_FOUND, {"error": f"subscription {sub_id!r} not found"}
        manager.delete_subscription(sub_id)
        return HTTPStatus.NO_CONTENT, None

    return HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"}


def serve_logs_sse(handler: Any) -> None:
    """
    Flux SSE = équivalent journalctl -f : envoie d'abord le buffer (500 lignes), puis le temps réel.
    """
    from mms.mms_service import LOG_LINES, LOG_LOCK, LOG_CONDITION

    def escape_sse(s: str) -> str:
        return s.replace("\r", "").replace("\n", " ").replace("\x00", "")

    handler.send_response(HTTPStatus.OK)
    handler.send_header("Content-Type", "text/event-stream")
    handler.send_header("Cache-Control", "no-cache")
    handler.send_header("Connection", "keep-alive")
    handler.end_headers()

    last_sent_seq = 0
    while True:
        try:
            # Copier les lignes à envoyer sous le lock, sans faire d’I/O (évite bloquer le worker)
            with LOG_LOCK:
                to_send = [
                    (seq, line)
                    for seq, line in LOG_LINES
                    if seq > last_sent_seq
                ]
                if to_send:
                    last_sent_seq = to_send[-1][0]
                else:
                    LOG_CONDITION.wait(timeout=0.5)
            # Envoi hors lock pour ne pas bloquer _log()
            for _seq, line in to_send:
                handler.wfile.write(f"data: {escape_sse(line)}\n\n".encode("utf-8"))
                handler.wfile.flush()
            if not to_send:
                handler.wfile.write(b": \n\n")
                handler.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            break
