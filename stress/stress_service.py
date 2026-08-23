"""Orchestration SSH / locale des stress-tests (stress-ng)."""
from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import remote_ops

ROOT = Path(__file__).resolve().parent
HOSTS_PATH = ROOT / "hosts.json"
OPS_SOURCE = (ROOT / "remote_ops.py").read_bytes()

DEFAULT_HOSTS = [
    {"id": "ccv1", "name": "ccv1", "host": "ccv1", "port": 22, "user": "root", "identity": ""},
    {"id": "ccv2", "name": "ccv2", "host": "ccv2", "port": 22, "user": "root", "identity": ""},
]

HISTORY_MAX = 120


def session_key(user: str, host: str, port: int) -> str:
    return f"{user}@{host}:{int(port)}"


def _format_ssh_error(text: str, sess: StressSession | None = None) -> str:
    raw = (text or "").strip()
    lines = [
        ln.strip()
        for ln in raw.splitlines()
        if ln.strip() and "Warning:" not in ln and not ln.startswith("debug")
    ]
    msg = lines[-1] if lines else raw
    target = f"{sess.user}@{sess.host}" if sess else ""
    if "Permission denied" in msg:
        who = target or msg.split(":", 1)[0]
        return f"Authentification SSH refusée pour {who} (clé publique ou mot de passe)."
    if "Connection refused" in msg:
        port = sess.port if sess else 22
        host = sess.host if sess else ""
        return f"SSH refusé sur {host}:{port}."
    if "timed out" in msg.lower() or "Timeout" in msg:
        return f"Timeout SSH vers {target or msg}."
    if "Could not resolve" in msg or "Name or service not known" in msg:
        host = sess.host if sess else msg
        return f"Hôte inconnu: {host}."
    if "No route to host" in msg:
        host = sess.host if sess else msg
        return f"Pas de route vers {host}."
    if not msg:
        return f"Échec SSH vers {target}." if target else "Échec SSH."
    if target and target not in msg:
        return f"{target}: {msg}"
    return msg


def is_local_host(host: str) -> bool:
    h = (host or "").strip().lower()
    if h in {"", "localhost", "127.0.0.1", "::1"}:
        return True
    try:
        names = {socket.gethostname().lower(), socket.getfqdn().lower()}
        names.add(socket.gethostname().split(".")[0].lower())
        names.add(socket.getfqdn().split(".")[0].lower())
        if h in names or h.split(".")[0] in names:
            return True
    except OSError:
        pass
    try:
        target_ips = {info[4][0] for info in socket.getaddrinfo(host, None)}
        local_ips = {"127.0.0.1", "::1"}
        try:
            local_ips.update(info[4][0] for info in socket.getaddrinfo(socket.gethostname(), None))
        except OSError:
            pass
        if target_ips & local_ips:
            return True
    except OSError:
        pass
    return False


def _load_hosts() -> list[dict[str, Any]]:
    try:
        data = json.loads(HOSTS_PATH.read_text(encoding="utf-8"))
        if isinstance(data, list) and data:
            clean = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                host = str(item.get("host") or "").strip()
                if not host:
                    continue
                clean.append({
                    "id": str(item.get("id") or host),
                    "name": str(item.get("name") or host),
                    "host": host,
                    "port": int(item.get("port") or 22),
                    "user": str(item.get("user") or "root"),
                    "identity": str(item.get("identity") or ""),
                })
            if clean:
                return clean
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return [dict(h) for h in DEFAULT_HOSTS]


def _save_hosts(hosts: list[dict[str, Any]]) -> None:
    HOSTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    HOSTS_PATH.write_text(json.dumps(hosts, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _pct(prev: tuple[int, int] | None, cur: tuple[int, int]) -> float | None:
    if not prev:
        return None
    d_idle = cur[0] - prev[0]
    d_total = cur[1] - prev[1]
    if d_total <= 0:
        return 0.0
    used = 1.0 - (d_idle / d_total)
    return round(max(0.0, min(100.0, used * 100.0)), 1)


@dataclass
class StressSession:
    key: str
    name: str
    host: str
    port: int
    user: str
    identity: str = ""
    password: str = field(default="", repr=False)
    local: bool = False
    control_path: str | None = None
    last_error: str | None = None
    connected: bool = False
    hostname: str = ""
    nproc: int = 0
    cpus: list[dict[str, Any]] = field(default_factory=list)
    vms: list[dict[str, Any]] = field(default_factory=list)
    actors: list[dict[str, Any]] = field(default_factory=list)
    isolated: list[int] = field(default_factory=list)
    housekeeping: list[int] = field(default_factory=list)
    unassigned_isolated: list[int] = field(default_factory=list)
    vm_cpus: list[int] = field(default_factory=list)
    non_vm: list[int] = field(default_factory=list)
    cpu_source: str = ""
    free_logical_label: str = ""
    stress_ng: str | None = None
    isolcpus: str = ""
    nohz_full: str = ""
    running: bool = False
    stress: dict[str, Any] | None = None
    history: list[dict[str, Any]] = field(default_factory=list)
    prev_counters: dict[int, tuple[int, int]] = field(default_factory=dict)
    log_tail: str = ""
    connected_at: float = 0.0
    last_stats_at: float = 0.0


class StressManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, StressSession] = {}
        self._hosts = _load_hosts()
        self._current_key: str | None = None
        self._askpass_dir: str | None = None

    def hosts(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(h) for h in self._hosts]

    def save_hosts(self, hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        clean: list[dict[str, Any]] = []
        for item in hosts:
            if not isinstance(item, dict):
                continue
            host = str(item.get("host") or "").strip()
            if not host:
                continue
            name = str(item.get("name") or host).strip() or host
            hid = str(item.get("id") or name).strip() or name
            clean.append({
                "id": hid,
                "name": name,
                "host": host,
                "port": int(item.get("port") or 22),
                "user": str(item.get("user") or "root").strip() or "root",
                "identity": str(item.get("identity") or "").strip(),
            })
        if not clean:
            clean = [dict(h) for h in DEFAULT_HOSTS]
        with self._lock:
            self._hosts = clean
            _save_hosts(clean)
            return [dict(h) for h in self._hosts]

    def _ssh_base(self, sess: StressSession, *, master: bool = False) -> list[str]:
        cmd = ["ssh"]
        if sess.control_path:
            cmd += ["-S", sess.control_path]
        if master:
            cmd += ["-MNf", "-o", "ControlPersist=180"]
        cmd += [
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=8",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            "-p", str(sess.port),
        ]
        if sess.identity:
            cmd += ["-i", sess.identity, "-o", "IdentitiesOnly=yes"]
        if not sess.password:
            cmd += ["-o", "BatchMode=yes"]
        cmd.append(f"{sess.user}@{sess.host}")
        return cmd

    def _ssh_env(self, sess: StressSession) -> dict[str, str]:
        env = os.environ.copy()
        if not sess.password:
            return env
        if self._askpass_dir is None:
            self._askpass_dir = tempfile.mkdtemp(prefix="po-stress-askpass-")
            script = Path(self._askpass_dir) / "askpass"
            script.write_text("#!/bin/sh\nprintf '%s\\n' \"$PO_SSH_PASS\"\n", encoding="utf-8")
            script.chmod(0o700)
        env["SSH_ASKPASS"] = str(Path(self._askpass_dir) / "askpass")
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["PO_SSH_PASS"] = sess.password
        env.setdefault("DISPLAY", ":0")
        return env

    def _ensure_master(self, sess: StressSession) -> None:
        if sess.local:
            return
        if not sess.control_path:
            safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in sess.key)
            sess.control_path = str(Path(tempfile.gettempdir()) / f"po-stress-{safe}.sock")
        check = subprocess.run(
            ["ssh", "-O", "check", "-S", sess.control_path, f"{sess.user}@{sess.host}"],
            capture_output=True,
            text=True,
        )
        if check.returncode == 0:
            return
        env = self._ssh_env(sess)
        proc = subprocess.run(
            self._ssh_base(sess, master=True),
            capture_output=True,
            text=True,
            env=env,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            timeout=15,
        )
        if proc.returncode != 0:
            raise RuntimeError(_format_ssh_error(proc.stderr or proc.stdout or "", sess))

    def _close_master(self, sess: StressSession) -> None:
        if sess.local or not sess.control_path:
            return
        subprocess.run(
            ["ssh", "-O", "exit", "-S", sess.control_path, f"{sess.user}@{sess.host}"],
            capture_output=True,
            text=True,
        )
        try:
            Path(sess.control_path).unlink(missing_ok=True)
        except OSError:
            pass

    def _run_ops(self, sess: StressSession, op: str, spec: dict[str, Any] | None = None) -> dict[str, Any]:
        if sess.local:
            return remote_ops.dispatch(op, spec or {})
        self._ensure_master(sess)
        args = [op]
        if spec:
            args.append(base64.b64encode(json.dumps(spec).encode("utf-8")).decode("ascii"))
        env = self._ssh_env(sess)
        cmd = self._ssh_base(sess) + ["python3", "-"] + args
        proc = subprocess.run(
            cmd,
            input=OPS_SOURCE,
            capture_output=True,
            timeout=25,
            env=env,
        )
        stdout = (proc.stdout or b"").decode("utf-8", errors="replace")
        stderr = (proc.stderr or b"").decode("utf-8", errors="replace")
        if not stdout.strip():
            raise RuntimeError(_format_ssh_error(stderr, sess) or f"SSH sans sortie (code {proc.returncode})")
        try:
            data = json.loads(stdout.strip().splitlines()[-1])
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"JSON invalide depuis la cible: {stdout[-400:]}") from exc
        if not isinstance(data, dict):
            raise RuntimeError("réponse cible invalide")
        if data.get("error"):
            raise RuntimeError(str(data["error"]))
        return data

    def _apply_probe(self, sess: StressSession, data: dict[str, Any]) -> None:
        sess.hostname = str(data.get("hostname") or sess.host)
        sess.nproc = int(data.get("nproc") or 0)
        sess.cpus = list(data.get("cpus") or [])
        sess.vms = list(data.get("vms") or [])
        sess.actors = list(data.get("actors") or [])
        sess.isolated = [int(x) for x in (data.get("isolated") or [])]
        sess.housekeeping = [int(x) for x in (data.get("housekeeping") or [])]
        sess.unassigned_isolated = [int(x) for x in (data.get("unassigned_isolated") or data.get("free_logical") or [])]
        sess.vm_cpus = [int(x) for x in (data.get("vm_cpus") or [])]
        sess.non_vm = [int(x) for x in (data.get("non_vm") or [])]
        sess.cpu_source = str(data.get("cpu_source") or "")
        sess.free_logical_label = str(data.get("free_logical_label") or "")
        sess.stress_ng = data.get("stress_ng")
        sess.isolcpus = str(data.get("isolcpus") or "")
        sess.nohz_full = str(data.get("nohz_full") or "")
        sess.running = bool(data.get("running"))
        sess.stress = data.get("stress") if isinstance(data.get("stress"), dict) else None
        sess.last_error = str(data["error"]) if data.get("error") else None
        sess.connected = True
        sess.connected_at = sess.connected_at or time.time()
        self._ingest_counters(sess, sess.cpus, data.get("local_time") or time.time())

    def _mean_load(self, sess: StressSession, ids: list[int]) -> float | None:
        if not ids:
            return None
        vals = []
        idset = set(ids)
        for cpu in sess.cpus:
            if int(cpu.get("id", -1)) in idset and cpu.get("load_pct") is not None:
                vals.append(float(cpu["load_pct"]))
        if not vals:
            return None
        return round(sum(vals) / len(vals), 1)

    def _ingest_counters(self, sess: StressSession, rows: list[dict[str, Any]], ts: float) -> None:
        now_counters: dict[int, tuple[int, int]] = {}
        for row in rows:
            try:
                cid = int(row.get("id"))
                idle = int(row.get("idle") or 0)
                total = int(row.get("total") or 0)
            except (TypeError, ValueError):
                continue
            now_counters[cid] = (idle, total)
        by_id = {int(c["id"]): c for c in sess.cpus if "id" in c}
        for cid, cur in now_counters.items():
            load = _pct(sess.prev_counters.get(cid), cur)
            if cid in by_id:
                by_id[cid]["load_pct"] = load
                by_id[cid]["idle"] = cur[0]
                by_id[cid]["total"] = cur[1]
            else:
                sess.cpus.append({"id": cid, "idle": cur[0], "total": cur[1], "load_pct": load})
        sess.prev_counters = now_counters
        stressed = [int(c) for c in ((sess.stress or {}).get("cpus") or [])]
        point = {
            "t": ts,
            "stressed_pct": self._mean_load(sess, stressed),
            "vm_pct": self._mean_load(sess, sess.vm_cpus),
            "hk_pct": self._mean_load(sess, sess.housekeeping),
            "free_isol_pct": self._mean_load(sess, sess.unassigned_isolated),
        }
        if any(point[k] is not None for k in ("stressed_pct", "vm_pct", "hk_pct", "free_isol_pct")):
            sess.history.append(point)
            if len(sess.history) > HISTORY_MAX:
                sess.history = sess.history[-HISTORY_MAX:]
        sess.last_stats_at = ts

    def _public_session(self, sess: StressSession) -> dict[str, Any]:
        elapsed = None
        if sess.running and sess.stress and sess.stress.get("started_at"):
            elapsed = round(time.time() - float(sess.stress["started_at"]), 1)
        return {
            "key": sess.key,
            "name": sess.name,
            "host": sess.host,
            "port": sess.port,
            "user": sess.user,
            "identity": sess.identity,
            "local": sess.local,
            "hostname": sess.hostname,
            "nproc": sess.nproc,
            "cpus": sess.cpus,
            "vms": sess.vms,
            "actors": sess.actors,
            "isolated": sess.isolated,
            "housekeeping": sess.housekeeping,
            "unassigned_isolated": sess.unassigned_isolated,
            "vm_cpus": sess.vm_cpus,
            "non_vm": sess.non_vm,
            "cpu_source": sess.cpu_source,
            "free_logical_label": sess.free_logical_label,
            "stress_ng": sess.stress_ng,
            "isolcpus": sess.isolcpus,
            "nohz_full": sess.nohz_full,
            "running": sess.running,
            "stress": {**sess.stress, "elapsed_s": elapsed} if sess.stress else None,
            "history": sess.history[-90:],
            "log_tail": sess.log_tail,
            "error": sess.last_error,
            "connected": sess.connected,
            "connected_at": sess.connected_at,
            "last_stats_at": sess.last_stats_at,
        }

    def _summaries(self) -> list[dict[str, Any]]:
        out = []
        for sess in self._sessions.values():
            elapsed = None
            if sess.running and sess.stress and sess.stress.get("started_at"):
                elapsed = round(time.time() - float(sess.stress["started_at"]), 1)
            out.append({
                "key": sess.key,
                "name": sess.name,
                "host": sess.host,
                "hostname": sess.hostname,
                "local": sess.local,
                "connected": sess.connected,
                "running": sess.running,
                "cpus": (sess.stress or {}).get("cpus") if sess.stress else [],
                "elapsed_s": elapsed,
                "error": sess.last_error,
            })
        return out

    def status(self, key: str | None = None) -> dict[str, Any]:
        with self._lock:
            k = key or self._current_key
            sess = self._sessions.get(k) if k else None
            if sess and sess.connected:
                try:
                    data = self._run_ops(sess, "stats")
                    sess.log_tail = str(data.get("log_tail") or "")
                    sess.running = bool(data.get("running"))
                    sess.stress = data.get("stress") if isinstance(data.get("stress"), dict) else None
                    sess.last_error = None
                    self._ingest_counters(sess, list(data.get("cpus") or []), data.get("local_time") or time.time())
                except Exception as exc:  # noqa: BLE001
                    sess.last_error = str(exc)
            return {
                "current": self._public_session(sess) if sess else None,
                "sessions": self._summaries(),
                "hosts": [dict(h) for h in self._hosts],
            }

    def connect(
        self,
        *,
        host: str,
        port: int = 22,
        user: str = "root",
        identity: str = "",
        password: str = "",
        name: str = "",
        force_ssh: bool = False,
    ) -> dict[str, Any]:
        host = (host or "").strip()
        if not host:
            return {"error": "Adresse du nœud requise"}
        user = (user or "root").strip() or "root"
        port = int(port or 22)
        key = session_key(user, host, port)
        with self._lock:
            sess = self._sessions.get(key)
            if sess is None:
                sess = StressSession(
                    key=key,
                    name=(name or host).strip() or host,
                    host=host,
                    port=port,
                    user=user,
                    identity=(identity or "").strip(),
                    password=password or "",
                    local=False if force_ssh else is_local_host(host),
                )
                self._sessions[key] = sess
            else:
                sess.identity = (identity or "").strip() or sess.identity
                if password:
                    sess.password = password
                if name:
                    sess.name = name
            self._current_key = key
            try:
                data = self._run_ops(sess, "probe")
            except Exception as exc:  # noqa: BLE001
                sess.connected = False
                sess.last_error = str(exc)
                self._close_master(sess)
                return {"error": str(exc), "current": self._public_session(sess), "sessions": self._summaries(), "hosts": [dict(h) for h in self._hosts]}
            self._apply_probe(sess, data)
            try:
                time.sleep(0.3)
                stats = self._run_ops(sess, "stats")
                sess.log_tail = str(stats.get("log_tail") or "")
                sess.running = bool(stats.get("running"))
                sess.stress = stats.get("stress") if isinstance(stats.get("stress"), dict) else sess.stress
                self._ingest_counters(sess, list(stats.get("cpus") or []), stats.get("local_time") or time.time())
            except Exception:
                pass
            return {
                "current": self._public_session(sess),
                "sessions": self._summaries(),
                "hosts": [dict(h) for h in self._hosts],
            }

    def start(self, spec: dict[str, Any], key: str | None = None) -> dict[str, Any]:
        with self._lock:
            k = key or self._current_key
            sess = self._sessions.get(k) if k else None
            if not sess or not sess.connected:
                return {"error": "Aucun nœud connecté"}
            try:
                data = self._run_ops(sess, "start", spec)
            except Exception as exc:  # noqa: BLE001
                sess.last_error = str(exc)
                return {"error": str(exc), "current": self._public_session(sess), "sessions": self._summaries(), "hosts": [dict(h) for h in self._hosts]}
            if data.get("error"):
                sess.last_error = str(data["error"])
                return {"error": str(data["error"]), "current": self._public_session(sess), "sessions": self._summaries(), "hosts": [dict(h) for h in self._hosts]}
            sess.running = True
            sess.stress = data
            sess.last_error = None
            sess.history = []
            sess.prev_counters = {}
            return {
                "current": self._public_session(sess),
                "sessions": self._summaries(),
                "hosts": [dict(h) for h in self._hosts],
            }

    def stop(self, key: str | None = None) -> dict[str, Any]:
        with self._lock:
            k = key or self._current_key
            sess = self._sessions.get(k) if k else None
            if not sess or not sess.connected:
                return {"error": "Aucun nœud connecté"}
            try:
                self._run_ops(sess, "stop")
            except Exception as exc:  # noqa: BLE001
                sess.last_error = str(exc)
                return {"error": str(exc), "current": self._public_session(sess), "sessions": self._summaries(), "hosts": [dict(h) for h in self._hosts]}
            sess.running = False
            sess.stress = None
            sess.last_error = None
            return {
                "current": self._public_session(sess),
                "sessions": self._summaries(),
                "hosts": [dict(h) for h in self._hosts],
            }

    def disconnect(self, key: str | None = None, *, stop_stress: bool = False) -> dict[str, Any]:
        with self._lock:
            k = key or self._current_key
            sess = self._sessions.pop(k, None) if k else None
            if sess:
                if stop_stress:
                    try:
                        self._run_ops(sess, "stop")
                    except Exception:
                        pass
                self._close_master(sess)
            if self._current_key == k:
                self._current_key = next(iter(self._sessions), None)
            current = self._sessions.get(self._current_key) if self._current_key else None
            return {
                "current": self._public_session(current) if current else None,
                "sessions": self._summaries(),
                "hosts": [dict(h) for h in self._hosts],
            }

    def select(self, key: str) -> dict[str, Any]:
        with self._lock:
            sess = self._sessions.get(key)
            if not sess:
                return {"error": "Session inconnue"}
            self._current_key = key
            return {
                "current": self._public_session(sess),
                "sessions": self._summaries(),
                "hosts": [dict(h) for h in self._hosts],
            }

    def shutdown(self) -> None:
        with self._lock:
            for sess in list(self._sessions.values()):
                try:
                    self._run_ops(sess, "stop")
                except Exception:
                    pass
                self._close_master(sess)
            self._sessions.clear()
            self._current_key = None


_MANAGER: StressManager | None = None
_MANAGER_LOCK = threading.Lock()


def get_stress_manager() -> StressManager:
    global _MANAGER
    with _MANAGER_LOCK:
        if _MANAGER is None:
            _MANAGER = StressManager()
        return _MANAGER
