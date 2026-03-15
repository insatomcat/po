#!/usr/bin/env python3
"""
Service PO unifié : MMS, GOOSE, SV Generator, SV Listener sur un seul port 7050.

Routes:
  - /healthz           -> health check
  - /                  -> Web UI unifiée (onglets MMS | GOOSE | SV | SV Listener)
  - /api/mms/*         -> API MMS (subscriptions, recents, logs SSE)
  - /api/goose/*       -> API GOOSE (streams, recent, restart)
  - /api/sv/*          -> API SV (flows, recents)
  - /api/svview/*      -> proxy vers SV Listener (si --svview-interface)
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http import HTTPStatus
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "goose"))
sys.path.insert(0, str(ROOT / "svgenerator"))

# Import après configuration du path
from mms import mms_service as _mms_svc
from mms.mms_service import SubscriptionManager, _TeeStdout
from mms.mms_api import handle_mms, serve_logs_sse
from goose61850.service import GooseService, _handle_api as goose_handle_api
from svgenerator.sv_api import handle_sv, init_sv_api


def _send_json(handler: BaseHTTPRequestHandler, status: int, payload: object) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else b""
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    if body:
        handler.wfile.write(body)


class UnifiedHandler(BaseHTTPRequestHandler):
    manager: SubscriptionManager
    goose_service: GooseService
    svview_port: int | None = None

    def _proxy_to_svview(self, method: str, path: str, body: bytes | None) -> bool:
        """Proxy vers le SV Listener Flask. Retourne True si la requête a été traitée."""
        if not path.startswith("/api/svview"):
            return False
        port = getattr(UnifiedHandler, "svview_port", None)
        if port is None:
            _send_json(self, HTTPStatus.SERVICE_UNAVAILABLE, {"error": "SV Listener non configuré (--svview-interface)"})
            return True
        backend_path = path[len("/api/svview"):] or "/"
        url = f"http://127.0.0.1:{port}{backend_path}"
        if "?" in self.path:
            url = f"http://127.0.0.1:{port}{backend_path}?" + self.path.split("?", 1)[1]
        try:
            req = Request(url, data=body, method=method)
            for h in ("Content-Type", "Accept"):
                v = self.headers.get(h)
                if v:
                    req.add_header(h, v)
            with urlopen(req, timeout=10) as resp:
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    if k.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp.read())
        except HTTPError as e:
            self.send_response(e.code)
            self.end_headers()
            self.wfile.write(e.read() if e.fp else b"")
        except (URLError, OSError) as e:
            self.send_error(HTTPStatus.BAD_GATEWAY, str(e))
        return True

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/svview") and self._proxy_to_svview("GET", path, None):
            return
        if path == "/healthz":
            _send_json(self, HTTPStatus.OK, {"status": "ok"})
            return
        if path == "/" or path == "/index.html" or path == "/ui":
            self._serve_unified_ui()
            return
        if path.startswith("/api/mms/"):
            sub = path[len("/api/mms"):].split("?")[0] or "/"
            if sub == "/logs":
                serve_logs_sse(self)
                return
            status, body = handle_mms(
                self.manager, sub, "GET", None
            )
            _send_json(self, status, body)
            return
        if path.startswith("/api/goose/"):
            sub = path[len("/api/goose"):] or "/"
            status, result = goose_handle_api(
                self.goose_service, sub, "GET", None
            )
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            if status != 204:
                self.wfile.write(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                )
            return
        if path.startswith("/api/sv/"):
            sub = path[len("/api/sv"):] or "/"
            status, result = handle_sv(sub, "GET", None)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                json.dumps(result, ensure_ascii=False).encode("utf-8")
            )
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else None
        if path.startswith("/api/svview") and self._proxy_to_svview("POST", path, body):
            return
        if path.startswith("/api/mms/"):
            sub = path[len("/api/mms"):] or "/"
            status, resp = handle_mms(self.manager, sub, "POST", body)
            _send_json(self, status, resp)
            return
        if path.startswith("/api/goose/"):
            sub = path[len("/api/goose"):] or "/"
            status, result = goose_handle_api(
                self.goose_service, sub, "POST", body
            )
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            if status != 204:
                self.wfile.write(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                )
            return
        if path.startswith("/api/sv/"):
            sub = path[len("/api/sv"):] or "/"
            status, result = handle_sv(sub, "POST", body)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                json.dumps(result, ensure_ascii=False).encode("utf-8")
            )
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_PUT(self) -> None:
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else None

        if path.startswith("/api/mms/"):
            sub = path[len("/api/mms"):] or "/"
            status, resp = handle_mms(self.manager, sub, "PUT", body)
            _send_json(self, status, resp)
            return
        if path.startswith("/api/sv/"):
            sub = path[len("/api/sv"):] or "/"
            status, result = handle_sv(sub, "PUT", body)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                json.dumps(result, ensure_ascii=False).encode("utf-8")
            )
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_PATCH(self) -> None:
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else None

        if path.startswith("/api/goose/"):
            sub = path[len("/api/goose"):] or "/"
            status, result = goose_handle_api(
                self.goose_service, sub, "PATCH", body
            )
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            if status != 204:
                self.wfile.write(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                )
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_DELETE(self) -> None:
        path = self.path.split("?", 1)[0]

        if path.startswith("/api/mms/"):
            sub = path[len("/api/mms"):] or "/"
            status, resp = handle_mms(self.manager, sub, "DELETE", None)
            if status == HTTPStatus.NO_CONTENT:
                self.send_response(HTTPStatus.NO_CONTENT)
                self.end_headers()
            else:
                _send_json(self, status, resp)
            return
        if path.startswith("/api/goose/"):
            sub = path[len("/api/goose"):] or "/"
            status, result = goose_handle_api(
                self.goose_service, sub, "DELETE", None
            )
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            if status != 204:
                self.wfile.write(
                    json.dumps(result, ensure_ascii=False).encode("utf-8")
                )
            return
        if path.startswith("/api/sv/"):
            sub = path[len("/api/sv"):] or "/"
            status, result = handle_sv(sub, "DELETE", None)
            body = json.dumps(result, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def _serve_unified_ui(self) -> None:
        html = getattr(UnifiedHandler, "_ui_html_cache", None)
        if html is None:
            ui_path = ROOT / "unified_ui.html"
            try:
                html = ui_path.read_text(encoding="utf-8")
                UnifiedHandler._ui_html_cache = html
            except OSError:
                html = "<h1>unified_ui.html not found</h1>"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def log_message(self, format: str, *args: object) -> None:
        msg = f"[HTTP] {self.address_string()} - {format % args}"
        print(msg)
        # Alimenter le buffer des logs MMS (affichage onglet MMS) même après restart
        with _mms_svc.LOG_LOCK:
            _mms_svc.LOG_NEXT_SEQ += 1
            _mms_svc.LOG_LINES.append((_mms_svc.LOG_NEXT_SEQ, msg))
            if len(_mms_svc.LOG_LINES) > _mms_svc.LOG_MAX:
                _mms_svc.LOG_LINES.pop(0)
            _mms_svc.LOG_CONDITION.notify_all()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Service PO unifié (MMS, GOOSE, SV) sur le port 7050."
    )
    parser.add_argument(
        "--listen-host",
        default="0.0.0.0",
        help="Adresse d'écoute (défaut: 0.0.0.0).",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=7050,
        help="Port d'écoute (défaut: 7050).",
    )
    parser.add_argument(
        "--victoriametrics-url",
        metavar="URL",
        help="URL VictoriaMetrics pour MMS.",
    )
    parser.add_argument(
        "--vm-batch-ms",
        type=int,
        default=5000,
        help="Intervalle batch VM en ms (défaut: 5000).",
    )
    parser.add_argument(
        "--svview-interface",
        metavar="IFACE",
        help="Interface réseau pour SV Listener (capture 0x88ba, onglet phasors).",
    )
    args = parser.parse_args()

    svview_port: int | None = None
    if args.svview_interface:
        sys.path.insert(0, str(ROOT))
        from svlistener_view.sv_listener_view import create_svview_app

        svview_app = create_svview_app(args.svview_interface)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        svview_port = sock.getsockname()[1]
        sock.close()

        def run_svview() -> None:
            svview_app.run(host="127.0.0.1", port=svview_port, use_reloader=False, threaded=True)

        t = threading.Thread(target=run_svview, daemon=True)
        t.start()
        UnifiedHandler.svview_port = svview_port
        print(f"[+] SV Listener sur http://127.0.0.1:{svview_port} (proxy /api/svview)", file=sys.stderr)

    manager = SubscriptionManager(
        vm_url=args.victoriametrics_url,
        vm_batch_ms=args.vm_batch_ms,
    )
    UnifiedHandler.manager = manager

    goose = GooseService(host="127.0.0.1", port=0)  # pas de serveur HTTP
    goose.start_sender_only()
    UnifiedHandler.goose_service = goose

    sys.stdout = _TeeStdout(sys.__stdout__)

    init_sv_api()

    server_address = (args.listen_host, args.listen_port)
    httpd = ThreadingHTTPServer(server_address, UnifiedHandler)
    print(
        f"Service PO démarré sur http://{args.listen_host}:{args.listen_port} "
        f"(MMS, GOOSE, SV)"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[Interrupt] Arrêt demandé.")
    finally:
        goose.stop()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
