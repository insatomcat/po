# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""GOOSE service: continuous stream publication with an HTTP API."""
from __future__ import annotations

import logging
import html as html_module
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# State files (in goose/)
_GOOSE_DIR = Path(__file__).resolve().parent.parent
STREAMS_PATH = _GOOSE_DIR / "streams.json"
RECENTS_PATH = _GOOSE_DIR / "recents.json"
from urllib.parse import parse_qs, urlparse

from open61850.data import encode_binary_time, encode_utc_time
from iec_data import IECData, RawData, TimestampData, iec_data_from_json, iec_data_to_json
from .transport import _build_frame
from .types import GoosePDU


@dataclass
class GooseStream:
    """Configuration of a continuously published GOOSE stream."""

    id: str
    iface: str
    src_mac: str
    dst_mac: str
    app_id: int
    vlan_id: Optional[int]
    vlan_priority: Optional[int]
    gocb_ref: str
    dat_set: str
    go_id: str
    ttl: int
    conf_rev: int
    simulation: bool
    nds_com: bool
    all_data: List[IECData]

    st_num: int = 1
    sq_num: int = 0
    next_send_time: float = field(default_factory=time.monotonic)
    current_interval_ms: float = 10.0
    # Time of the last stNum change: the GOOSE t, and the time written into
    # the timestamps of allData. Retransmissions differ only by sqNum.
    changed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def new_state(self, min_interval_ms: float) -> None:
        """A state change: stNum + 1, sqNum back to 0, fast retransmission restarts now."""
        self.st_num = (self.st_num + 1) & 0xFFFFFFFF or 1
        self.sq_num = 0
        self.changed_at = datetime.now(timezone.utc)
        self.next_send_time = time.monotonic()
        self.current_interval_ms = min_interval_ms

    @classmethod
    def _refresh_time_value(cls, v: IECData, now: datetime) -> IECData:
        """Set the timestamps of allData (typed and legacy raw) to ``now``."""
        if isinstance(v, TimestampData):
            return TimestampData(now)
        if isinstance(v, RawData):
            if v.tag == 0x91:
                # Respecte la longueur d'origine si > 8 octets.
                base = encode_utc_time(now)
                if len(v.value) > 8:
                    return RawData(v.tag, base + v.value[8:])
                return RawData(v.tag, base[: len(v.value)] if v.value else base)
            if v.tag == 0x8C:
                base = encode_binary_time(now)
                return RawData(v.tag, base[: len(v.value)] if v.value else base)
        return v

    def to_pdu(self) -> GoosePDU:
        # Timestamps loaded from JSON or the CLI would be stale: they take the time
        # of the state change, which some IEDs check against t.
        live_all_data = [
            self._refresh_time_value(v, self.changed_at)
            for v in self.all_data
        ]
        return GoosePDU(
            gocb_ref=self.gocb_ref,
            time_allowed_to_live=self.ttl,
            dat_set=self.dat_set,
            go_id=self.go_id,
            timestamp=self.changed_at,
            st_num=self.st_num,
            sq_num=self.sq_num,
            simulation=self.simulation,
            conf_rev=self.conf_rev,
            nds_com=self.nds_com,
            num_dat_set_entries=len(live_all_data),
            all_data=live_all_data,
        )


def _stream_to_dict(s: GooseStream) -> Dict[str, Any]:
    return {
        "id": s.id,
        "iface": s.iface,
        "src_mac": s.src_mac,
        "dst_mac": s.dst_mac,
        "app_id": s.app_id,
        "vlan_id": s.vlan_id,
        "vlan_priority": s.vlan_priority,
        "gocb_ref": s.gocb_ref,
        "dat_set": s.dat_set,
        "go_id": s.go_id,
        "ttl": s.ttl,
        "conf_rev": s.conf_rev,
        "simulation": s.simulation,
        "nds_com": s.nds_com,
        "all_data": [iec_data_to_json(d) for d in s.all_data],
        "st_num": s.st_num,
        "sq_num": s.sq_num,
    }


def _parse_all_data(raw: List[Any]) -> List[IECData]:
    """Convert JSON values to IECData; also accepts the old ["raw", tag, hex] form."""
    return [iec_data_from_json(item) for item in raw]


class GooseService:
    """Continuous GOOSE stream publication, driven by an HTTP API."""

    IEC_MIN_MS = 10
    IEC_MAX_MS = 2000

    def __init__(
        self,
        host: str = "localhost",
        port: int = 7053,
    ) -> None:
        self.host = host
        self.port = port
        self._streams_path = STREAMS_PATH
        self._recents_path = RECENTS_PATH
        self._streams: Dict[str, GooseStream] = {}
        # Recently configured streams (10 at most).
        self._recent: List[Dict[str, Any]] = []
        self._streams_lock = threading.Lock()
        self._stop = threading.Event()
        self._sender_thread: Optional[threading.Thread] = None
        self._http_server: Optional[HTTPServer] = None
        # Load the saved streams, if any.
        self._load_state()

    def add_stream(self, config: Dict[str, Any]) -> GooseStream:
        with self._streams_lock:
            stream_id = str(uuid.uuid4())
            all_data = _parse_all_data(config.get("all_data", []))
            s = GooseStream(
                id=stream_id,
                iface=config["iface"],
                src_mac=config["src_mac"],
                dst_mac=config["dst_mac"],
                app_id=config["app_id"],
                vlan_id=config.get("vlan_id"),
                vlan_priority=config.get("vlan_priority"),
                gocb_ref=config["gocb_ref"],
                dat_set=config["dat_set"],
                go_id=config["go_id"],
                ttl=config.get("ttl", 5000),
                conf_rev=config.get("conf_rev", 1),
                simulation=config.get("simulation", False),
                nds_com=config.get("nds_com", False),
                all_data=all_data,
                st_num=1,
                sq_num=0,
                next_send_time=time.monotonic(),
                current_interval_ms=float(max(self.IEC_MIN_MS, 1)),
            )
            self._streams[stream_id] = s

        # Add the stream to the recent ones when its configuration is new.
        self._remember_recent(_stream_to_dict(s))
        # Save outside the critical section to avoid blocking.
        self._save_state()
        return s

    def modify_stream(self, stream_id: str, updates: Dict[str, Any]) -> Optional[GooseStream]:
        with self._streams_lock:
            s = self._streams.get(stream_id)
            if s is None:
                return None
            if "all_data" in updates:
                s.all_data = _parse_all_data(updates["all_data"])
            if "ttl" in updates:
                s.ttl = updates["ttl"]
            if "gocb_ref" in updates:
                s.gocb_ref = updates["gocb_ref"]
            if "dat_set" in updates:
                s.dat_set = updates["dat_set"]
            if "go_id" in updates:
                s.go_id = updates["go_id"]
            if "conf_rev" in updates:
                s.conf_rev = updates["conf_rev"]
            if "simulation" in updates:
                s.simulation = updates["simulation"]
            if "nds_com" in updates:
                s.nds_com = updates["nds_com"]
            s.new_state(float(max(self.IEC_MIN_MS, 1)))

        # Sauvegarde hors section critique.
        self._save_state()
        return s

    def delete_stream(self, stream_id: str) -> bool:
        with self._streams_lock:
            s = self._streams.pop(stream_id, None)

        if s is None:
            return False

        # The deleted stream goes to the recent ones.
        entry = _stream_to_dict(s)
        self._remember_recent(entry)
        self._save_state()
        return True

    def get_stream(self, stream_id: str) -> Optional[GooseStream]:
        with self._streams_lock:
            return self._streams.get(stream_id)

    def list_streams(self) -> List[GooseStream]:
        with self._streams_lock:
            return list(self._streams.values())

    def list_recent(self) -> List[Dict[str, Any]]:
        """The recently stopped streams."""
        with self._streams_lock:
            # Shallow copy so callers cannot change the list in place.
            return list(self._recent)

    def _remember_recent(self, entry: Dict[str, Any]) -> None:
        """Add an entry to the recent ones if it is really new.

        New means no entry of _recent has the same configuration (interface,
        addresses, GOOSE parameters), leaving out the id, the stNum/sqNum
        counters and all_data, which change over time for one logical stream.

        When the same configuration exists, its entry is replaced by the fresh
        snapshot (all_data included) and moved first.
        """
        with self._streams_lock:
            # Deduplication: compare the configuration without id/st_num/sq_num
            # and all_data, to keep one entry per logical stream.
            def _config_key(e: Dict[str, Any]) -> Dict[str, Any]:
                return {
                    k: e.get(k)
                    for k in (
                        "iface",
                        "src_mac",
                        "dst_mac",
                        "app_id",
                        "vlan_id",
                        "vlan_priority",
                        "gocb_ref",
                        "dat_set",
                        "go_id",
                        "ttl",
                        "conf_rev",
                        "simulation",
                        "nds_com",
                    )
                }

            new_key = _config_key(entry)
            for idx, e in enumerate(self._recent):
                if _config_key(e) == new_key:
                    # Same logical stream: refresh the snapshot (all_data, id, ...)
                    # and move it first, as the most recently deleted one.
                    self._recent.pop(idx)
                    self._recent.insert(0, entry)
                    self._recent = self._recent[:10]
                    return

            # Insert first and keep 10 entries.
            self._recent.insert(0, entry)
            self._recent = self._recent[:10]

    def restart_from_recent(self, hist_id: str) -> bool:
        """Restart a stream from the recent ones."""
        with self._streams_lock:
            entry = None
            for e in self._recent:
                if str(e.get("id")) == hist_id:
                    entry = e
                    break
            if entry is None:
                return False

            # A stream with the same gocbRef already runs: do not restart.
            gref = str(entry.get("gocb_ref", ""))
            for s_active in self._streams.values():
                if s_active.gocb_ref == gref:
                    return False

            now = time.monotonic()
            all_data = _parse_all_data(entry.get("all_data", []))
            s = GooseStream(
                # New stream, new internal id.
                id=str(uuid.uuid4()),
                iface=str(entry["iface"]),
                src_mac=str(entry["src_mac"]),
                dst_mac=str(entry["dst_mac"]),
                app_id=int(entry["app_id"]),
                vlan_id=entry.get("vlan_id"),
                vlan_priority=entry.get("vlan_priority"),
                gocb_ref=str(entry["gocb_ref"]),
                dat_set=str(entry["dat_set"]),
                go_id=str(entry["go_id"]),
                ttl=int(entry.get("ttl", 5000)),
                conf_rev=int(entry.get("conf_rev", 1)),
                simulation=bool(entry.get("simulation", False)),
                nds_com=bool(entry.get("nds_com", False)),
                all_data=all_data,
                st_num=int(entry.get("st_num", 1)),
                sq_num=int(entry.get("sq_num", 0)),
                next_send_time=now,
                current_interval_ms=float(max(self.IEC_MIN_MS, 1)),
            )
            s.new_state(float(max(self.IEC_MIN_MS, 1)))  # t is now: publish it as a new state
            self._streams[s.id] = s

        self._save_state()
        return True

    # ------------------------------------------------------------------
    # Simple persistence on disk
    # ------------------------------------------------------------------

    def _save_state(self) -> None:
        """Save the streams and the recent ones to streams.json and recents.json.

        Call it outside `_streams_lock`: it takes the lock to copy the state,
        then writes to disk outside the critical section.
        """
        try:
            with self._streams_lock:
                streams = [_stream_to_dict(s) for s in self._streams.values()]
                recent = list(self._recent)
            for path, payload in [
                (self._streams_path, {"streams": streams}),
                (self._recents_path, {"recents": recent}),
            ]:
                tmp_path = path.with_suffix(path.suffix + ".tmp")
                tmp_path.write_text(
                    json.dumps(payload, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                tmp_path.replace(path)
        except (OSError, TypeError, ValueError) as e:
            log.error(f"[GOOSE] Cannot save the state: {e}")

    def _load_state(self) -> None:
        """Reload the streams from streams.json and recents.json."""
        streams_data: List[Any] = []
        recent_data: List[Any] = []
        if self._streams_path.exists():
            try:
                raw = json.loads(self._streams_path.read_text(encoding="utf-8"))
                streams_data = raw.get("streams") or []
            except (OSError, json.JSONDecodeError, AttributeError) as e:
                log.warning(f"[GOOSE] Cannot load {self._streams_path}: {e}")
        if self._recents_path.exists():
            try:
                raw = json.loads(self._recents_path.read_text(encoding="utf-8"))
                recent_data = raw.get("recents") or raw.get("recent") or []
            except (OSError, json.JSONDecodeError, AttributeError) as e:
                log.warning(f"[GOOSE] Cannot load {self._recents_path}: {e}")
        now = time.monotonic()

        with self._streams_lock:
            self._streams.clear()
            self._recent = []
            for item in streams_data:
                try:
                    all_data = _parse_all_data(item.get("all_data", []))
                    s = GooseStream(
                        id=str(item["id"]),
                        iface=str(item["iface"]),
                        src_mac=str(item["src_mac"]),
                        dst_mac=str(item["dst_mac"]),
                        app_id=int(item["app_id"]),
                        vlan_id=item.get("vlan_id"),
                        vlan_priority=item.get("vlan_priority"),
                        gocb_ref=str(item["gocb_ref"]),
                        dat_set=str(item["dat_set"]),
                        go_id=str(item["go_id"]),
                        ttl=int(item.get("ttl", 5000)),
                        conf_rev=int(item.get("conf_rev", 1)),
                        simulation=bool(item.get("simulation", False)),
                        nds_com=bool(item.get("nds_com", False)),
                        all_data=all_data,
                        st_num=int(item.get("st_num", 1)),
                        sq_num=int(item.get("sq_num", 0)),
                        next_send_time=now,
                        current_interval_ms=float(max(self.IEC_MIN_MS, 1)),
                    )
                    # Restarted publisher: new t, so a new state (stNum + 1, sqNum 0).
                    s.new_state(float(max(self.IEC_MIN_MS, 1)))
                    self._streams[s.id] = s
                except (KeyError, TypeError, ValueError) as e:
                    log.warning(f"[GOOSE] Stream entry skipped (invalid data): {e}")
                    continue

            # Reload the recent streams as they are (converted only when one
            # is restarted).
            for e in recent_data:
                if isinstance(e, dict):
                    self._recent.append(e)

            # With no recent streams but some configured ones, start _recent
            # from a snapshot of the current streams, so the Recent list is
            # not empty right after a restart.
            if not self._recent and self._streams:
                for s in list(self._streams.values())[:10]:
                    self._recent.append(_stream_to_dict(s))

    def _sender_loop(self) -> None:
        while not self._stop.wait(0.01):
            for s, pdu in self._due_frames(time.monotonic()):
                try:
                    self._send_one(s, pdu)
                except Exception as e:
                    log.warning(f"[GOOSE] Cannot send stream {s.id}: {e}")

    def _due_frames(self, now: float) -> List[tuple[GooseStream, GoosePDU]]:
        """Build the PDUs due at ``now`` and advance sqNum and the schedule.

        Done under the lock so that a state change (modify_stream) is never
        mixed with the counters of the frame being sent.
        """
        frames: List[tuple[GooseStream, GoosePDU]] = []
        with self._streams_lock:
            for s in self._streams.values():
                if s.next_send_time > now:
                    continue
                frames.append((s, s.to_pdu()))
                s.sq_num = (s.sq_num + 1) & 0xFFFFFFFF or 1  # 0 only right after a state change
                s.next_send_time = now + s.current_interval_ms / 1000.0
                s.current_interval_ms = min(s.current_interval_ms * 2.0, float(self.IEC_MAX_MS))
        return frames

    def _send_one(self, s: GooseStream, pdu: Optional[GoosePDU] = None) -> None:
        if pdu is None:
            pdu = s.to_pdu()
        raw = _build_frame(
            dst_mac=s.dst_mac,
            src_mac=s.src_mac,
            app_id=s.app_id,
            pdu=pdu,
            vlan_id=s.vlan_id,
            vlan_priority=s.vlan_priority,
        )
        from scapy.all import sendp  # type: ignore[import-untyped]

        sendp(raw, iface=s.iface, count=1, inter=0.0, verbose=False)

    def start(self) -> None:
        self.start_sender_only()
        handler = make_unified_handler(self)
        self._http_server = HTTPServer((self.host, self.port), handler)

        def run_server() -> None:
            assert self._http_server is not None
            self._http_server.serve_forever()

        t = threading.Thread(target=run_server, daemon=True)
        t.start()

    def start_sender_only(self) -> None:
        """Start only the GOOSE sender thread (no HTTP server)."""
        self._stop.clear()
        self._sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
        self._sender_thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._http_server:
            self._http_server.shutdown()
            self._http_server = None


def _handle_api(service: GooseService, path: str, method: str, body: Optional[bytes]) -> tuple[int, Dict[str, Any]]:
    try:
        data = json.loads(body or "{}") if body else {}
    except json.JSONDecodeError:
        return 400, {"error": "Invalid JSON"}

    if path == "/streams" and method == "POST":
        required = ["iface", "src_mac", "dst_mac", "app_id", "gocb_ref", "dat_set", "go_id"]
        for k in required:
            if k not in data:
                return 400, {"error": f"Missing field: {k}"}
        s = service.add_stream(data)
        return 201, _stream_to_dict(s)

    if path.startswith("/streams/") and path != "/streams/":
        stream_id = path.split("/", 2)[2].rstrip("/")
        if method == "GET":
            s = service.get_stream(stream_id)
            if s is None:
                return 404, {"error": "Not found"}
            return 200, _stream_to_dict(s)
        if method == "PATCH":
            s = service.modify_stream(stream_id, data)
            if s is None:
                return 404, {"error": "Not found"}
            return 200, _stream_to_dict(s)
        if method == "DELETE":
            ok = service.delete_stream(stream_id)
            if not ok:
                return 404, {"error": "Not found"}
            return 204, {}

    if path == "/streams" and method == "GET":
        streams = service.list_streams()
        return 200, {"streams": [_stream_to_dict(s) for s in streams]}

    if path == "/recent" and method == "GET":
        recent = service.list_recent()
        return 200, {"recent": recent}

    if path.startswith("/recent/") and path.endswith("/restart") and method == "POST":
        parts = path.split("/")
        if len(parts) >= 3 and parts[2]:
            hist_id = parts[2]
            ok = service.restart_from_recent(hist_id)
            if not ok:
                return 404, {"error": "Not found or already running"}
            return 200, {"status": "ok"}
        return 404, {"error": "Not found"}

    return 404, {"error": "Not found"}


def make_unified_handler(service: GooseService) -> type:
    """One handler: API under /api/*, web UI at the root."""

    class UnifiedHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # type: ignore[override]
            parsed = urlparse(self.path)
            path = parsed.path or "/"

            if path.startswith("/api"):
                self._dispatch_api(path)
                return

            if path == "/" or path == "/streams":
                self._render_streams_list()
            elif path.startswith("/streams/") and path.endswith("/edit"):
                # /streams/<id>/edit
                parts = path.split("/")
                if len(parts) >= 3 and parts[2]:
                    stream_id = parts[2]
                    self._render_edit(stream_id)
                else:
                    self._send_not_found()
            else:
                self._send_not_found()

        def do_POST(self) -> None:  # type: ignore[override]
            parsed = urlparse(self.path)
            path = parsed.path or "/"

            if path.startswith("/api"):
                self._dispatch_api(path)
                return

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            data = parse_qs(body.decode("utf-8")) if body else {}

            if path.startswith("/streams/") and path.endswith("/edit"):
                parts = path.split("/")
                if len(parts) >= 3 and parts[2]:
                    stream_id = parts[2]
                    self._handle_edit_post(stream_id, data)
                    return
            elif path.startswith("/streams/") and path.endswith("/delete"):
                parts = path.split("/")
                if len(parts) >= 3 and parts[2]:
                    stream_id = parts[2]
                    service.delete_stream(stream_id)
                    self._redirect("/streams")
                    return
            elif path.startswith("/recent/") and path.endswith("/restart"):
                parts = path.split("/")
                if len(parts) >= 3 and parts[2]:
                    hist_id = parts[2]
                    service.restart_from_recent(hist_id)
                    self._redirect("/streams")
                    return

            self._send_not_found()

        def do_PATCH(self) -> None:  # type: ignore[override]
            parsed = urlparse(self.path)
            path = parsed.path or "/"
            if path.startswith("/api"):
                self._dispatch_api(path)
            else:
                self._send_not_found()

        def do_DELETE(self) -> None:  # type: ignore[override]
            parsed = urlparse(self.path)
            path = parsed.path or "/"
            if path.startswith("/api"):
                self._dispatch_api(path)
            else:
                self._send_not_found()

        def _dispatch_api(self, path: str) -> None:
            api_path = path[4:] or "/"
            body = None
            if self.command in ("POST", "PATCH"):
                length = int(self.headers.get("Content-Length", 0))
                if length:
                    body = self.rfile.read(length)
            status, result = _handle_api(service, api_path, self.command, body)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            if status != 204:
                self.wfile.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))

        # --- Helpers HTML ---

        def _render_streams_list(self) -> None:
            streams = service.list_streams()
            recent = service.list_recent()

            _e = html_module.escape
            rows = []
            for s in streams:
                rows.append(
                    f"<tr>"
                    f"<td>{_e(s.id)}</td>"
                    f"<td>{_e(s.gocb_ref)}</td>"
                    f"<td>{_e(s.go_id)}</td>"
                    f"<td>{_e(s.src_mac)}</td>"
                    f"<td>{_e(s.dst_mac)}</td>"
                    f"<td class=\"actions\">"
                    f"<a href=\"/streams/{_e(s.id)}/edit\" class=\"btn btn--accent\">Edit</a>"
                    f" "
                    f"<form method=\"POST\" action=\"/streams/{_e(s.id)}/delete\" style=\"display:inline\" onsubmit=\"return confirm('Delete this stream?');\">"
                    f"<button type=\"submit\" class=\"btn btn--danger\">Delete</button>"
                    f"</form>"
                    f"</td>"
                    f"</tr>"
                )
            rows_html = "\n".join(rows) if rows else '<tr><td colspan="6" class="empty">No stream</td></tr>'

            recent_rows: List[str] = []
            active_grefs = {s.gocb_ref for s in streams}
            for r in recent:
                rid = r.get("id", "")
                gref = r.get("gocb_ref", "")
                can_restart = gref not in active_grefs and bool(gref)
                if can_restart:
                    action_html = (
                        f"<form method=\"POST\" action=\"/recent/{_e(rid)}/restart\" style=\"display:inline\">"
                        f"<button type=\"submit\" class=\"btn btn--accent\">Restart</button>"
                        f"</form>"
                    )
                else:
                    action_html = '<span class="muted">Already running</span>'

                # Every stream detail, as pretty-printed JSON.
                details_json = json.dumps(r, ensure_ascii=False, indent=2)
                details_html = html_module.escape(details_json)
                action_html += (
                    "<br><details class=\"details-row\"><summary>Details</summary>"
                    f"<pre>{details_html}</pre></details>"
                )

                recent_rows.append(
                    f"<tr>"
                    f"<td>{_e(rid)}</td>"
                    f"<td>{_e(gref)}</td>"
                    f"<td>{_e(r.get('go_id', ''))}</td>"
                    f"<td>{_e(r.get('src_mac', ''))}</td>"
                    f"<td>{_e(r.get('dst_mac', ''))}</td>"
                    f"<td class=\"actions\">{action_html}</td>"
                    f"</tr>"
                )
            recent_rows_html = (
                "\n".join(recent_rows) if recent_rows else '<tr><td colspan="6" class="empty">No recent stream</td></tr>'
            )

            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GOOSE - Configured streams</title>
  <style>
    :root {{
      --bg: #1a1b26;
      --surface: #24283b;
      --text: #c0caf5;
      --muted: #565f89;
      --accent: #7aa2f7;
      --danger: #f7768e;
      --success: #9ece6a;
    }}
    * {{ box-sizing: border-box; }}
    body {{ background: var(--bg); color: var(--text); font-family: system-ui, sans-serif; margin: 0; padding: 1.5rem 2rem; }}
    h1 {{ font-size: 1.5rem; font-weight: 600; margin: 0 0 1rem 0; color: var(--accent); }}
    h2 {{ font-size: 1rem; font-weight: 600; margin: 0.75rem 0 0.5rem 0; color: var(--muted); }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .btn {{ display: inline-block; padding: 0.35rem 0.7rem; border-radius: 4px; font-size: 0.85rem; cursor: pointer; border: none; font-family: inherit; text-decoration: none; }}
    .btn--accent {{ background: var(--accent); color: var(--bg); }}
    .btn--accent:hover {{ opacity: 0.9; text-decoration: none; }}
    .btn--danger {{ background: var(--danger); color: var(--bg); }}
    .btn--danger:hover {{ opacity: 0.9; }}
    .muted {{ color: var(--muted); font-size: 0.9rem; }}
    .toolbar {{ display: flex; gap: 0.5rem; margin-bottom: 1rem; }}
    table {{ width: 100%; max-width: 1200px; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; }}
    th, td {{ padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.06); }}
    th {{ background: rgba(0,0,0,0.2); font-weight: 600; color: var(--text); }}
    td.actions {{ white-space: nowrap; }}
    .recents-section {{ margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid var(--muted); }}
    .details-row summary {{ cursor: pointer; color: var(--accent); font-size: 0.9rem; }}
    .details-row pre {{ background: rgba(0,0,0,0.3); padding: 0.5rem; border-radius: 4px; font-size: 0.8rem; overflow-x: auto; margin: 0.25rem 0 0; }}
    .empty {{ color: var(--muted); font-style: italic; }}
  </style>
</head>
<body>
  <h1>Configured GOOSE streams</h1>
  <div class="toolbar">
    <a href="/streams" class="btn btn--accent">Refresh</a>
  </div>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>gocbRef</th>
        <th>goID</th>
        <th>src_mac</th>
        <th>dst_mac</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>

  <section class="recents-section">
    <h2>Recently configured streams</h2>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>gocbRef</th>
          <th>goID</th>
          <th>src_mac</th>
          <th>dst_mac</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {recent_rows_html}
      </tbody>
    </table>
  </section>
</body>
</html>
"""
            self._send_html(html)

        def _render_edit(self, stream_id: str) -> None:
            s = service.get_stream(stream_id)
            if s is None:
                self._send_not_found()
                return

            all_data_json = json.dumps(_stream_to_dict(s)["all_data"], ensure_ascii=False, indent=2)
            _e = html_module.escape

            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Edit stream {_e(stream_id)}</title>
  <style>
    :root {{
      --bg: #1a1b26;
      --surface: #24283b;
      --text: #c0caf5;
      --muted: #565f89;
      --accent: #7aa2f7;
      --danger: #f7768e;
      --success: #9ece6a;
    }}
    * {{ box-sizing: border-box; }}
    body {{ background: var(--bg); color: var(--text); font-family: system-ui, sans-serif; margin: 0; padding: 1.5rem 2rem; max-width: 900px; }}
    h1 {{ font-size: 1.5rem; font-weight: 600; margin: 0 0 1rem 0; color: var(--accent); }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .btn {{ display: inline-block; padding: 0.35rem 0.7rem; border-radius: 4px; font-size: 0.9rem; cursor: pointer; border: none; font-family: inherit; text-decoration: none; }}
    .btn--accent {{ background: var(--accent); color: var(--bg); }}
    .btn--accent:hover {{ opacity: 0.9; text-decoration: none; }}
    .details-grid {{ display: grid; gap: 0.5rem; margin-bottom: 1rem; color: var(--muted); font-size: 0.9rem; }}
    label {{ display: block; margin-top: 0.75rem; font-weight: 600; color: var(--text); }}
    input[type=text], textarea {{ width: 100%; padding: 0.5rem 0.75rem; background: var(--surface); border: 1px solid var(--muted); border-radius: 4px; color: var(--text); font-family: inherit; }}
    input:focus, textarea:focus {{ outline: none; border-color: var(--accent); }}
    textarea {{ height: 12rem; font-family: monospace; font-size: 0.85rem; }}
    .readonly {{ opacity: 0.8; cursor: not-allowed; }}
    .form-actions {{ display: flex; gap: 0.5rem; margin-top: 1.5rem; }}
  </style>
</head>
<body>
  <h1>Edit the stream</h1>
  <div class="details-grid">
    <p><strong>ID:</strong> {_e(s.id)}</p>
    <p><strong>Interface:</strong> {_e(s.iface)} &nbsp; <strong>src_mac:</strong> {_e(s.src_mac)} &nbsp; <strong>dst_mac:</strong> {_e(s.dst_mac)}</p>
    <p><strong>APPID:</strong> 0x{s.app_id:04X}</p>
  </div>

  <form method="POST" action="/streams/{_e(s.id)}/edit">
    <label>gocbRef</label>
    <input type="text" name="gocb_ref" value="{_e(s.gocb_ref)}" class="readonly" readonly>

    <label>datSet</label>
    <input type="text" name="dat_set" value="{_e(s.dat_set)}" class="readonly" readonly>

    <label>goID</label>
    <input type="text" name="go_id" value="{_e(s.go_id)}" class="readonly" readonly>

    <label>TTL (ms)</label>
    <input type="text" name="ttl" value="{s.ttl}">

    <label>allData (JSON list of values and ['raw', tag, hex])</label>
    <textarea name="all_data_json">{_e(all_data_json)}</textarea>

    <div class="form-actions">
      <button type="submit" class="btn btn--accent">Save</button>
      <a href="/streams" class="btn" style="background:var(--surface);color:var(--text);border:1px solid var(--muted)">Cancel</a>
    </div>
  </form>
</body>
</html>
"""
            self._send_html(html)

        def _handle_edit_post(self, stream_id: str, data: Dict[str, List[str]]) -> None:
            updates: Dict[str, Any] = {}
            ttl_vals = data.get("ttl")
            if ttl_vals and ttl_vals[0].strip():
                try:
                    updates["ttl"] = int(ttl_vals[0].strip())
                except ValueError:
                    pass

            all_data_vals = data.get("all_data_json")
            if all_data_vals and all_data_vals[0].strip():
                try:
                    updates["all_data"] = json.loads(all_data_vals[0])
                except json.JSONDecodeError:
                    # Ignore bad JSON rather than failing the request.
                    pass

            if updates:
                service.modify_stream(stream_id, updates)
            self._redirect("/streams")

        def _send_html(self, html: str, status: int = 200) -> None:
            data = html.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _redirect(self, location: str) -> None:
            self.send_response(303)
            self.send_header("Location", location)
            self.end_headers()

        def _send_not_found(self) -> None:
            self._send_html("<h1>404 Not Found</h1>", status=404)

        def log_message(self, format: str, *args: Any) -> None:  # type: ignore[override]
            pass

    return UnifiedHandler
