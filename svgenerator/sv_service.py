from __future__ import annotations

import json
import os
import pathlib
import signal
import threading
import time
from subprocess import Popen
from typing import Dict, Optional

import subprocess
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field


BASE_DIR = pathlib.Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "flows.json"
RECENTS_PATH = BASE_DIR / "recents.json"
RT_SENDER_PATH = BASE_DIR / "rt_sender"
PIDS_DIR = BASE_DIR / "pids"


class FlowConfig(BaseModel):
    """
    Configuration persistée pour un flux SV.
    """

    name: str = Field(..., description="Nom unique du flux")
    interface: str = Field(..., description="Interface réseau (ex: eth0)")
    src_mac: str = Field(..., description="Adresse MAC source aa:bb:cc:dd:ee:ff")
    dst_mac: str = Field(..., description="Adresse MAC destination")
    svid: str = Field(..., description="svID (nom logique du flux)")
    appid: int = Field(..., ge=0, le=0xFFFF, description="APPID SV obligatoire 0-65535")
    conf_rev: int = Field(..., ge=0, le=0xFFFFFFFF, description="confRev obligatoire 0-4294967295")

    # Paramètres temps-réel passés à rt_sender
    smp_synch: int = Field(
        0, description="smpSynch (0=None,1=Local,2=Global) pour --smp-synch"
    )
    vlan_id: Optional[int] = Field(
        None, description="VLAN ID 0-4095 pour --vlan-id (None = pas de VLAN)"
    )
    vlan_priority: int = Field(
        0, description="Priorité VLAN 0-7 pour --vlan-priority"
    )
    freq_hz: float = Field(50.0, description="Fréquence en Hz pour --freq")
    i_peak: float = Field(10.0, description="Courant crête en A pour --i-peak")
    v_peak: float = Field(100.0, description="Tension crête en V pour --v-peak")
    phase_deg: float = Field(0.0, description="Déphasage I/V en degrés pour --phase")

    fault: bool = Field(
        False,
        description="Active le mode défaut (--fault); autres paramètres facultatifs",
    )
    fault_i_peak: Optional[float] = Field(
        None, description="Courant crête en défaut pour --fault-i-peak"
    )
    fault_v_peak: Optional[float] = Field(
        None, description="Tension crête en défaut pour --fault-v-peak"
    )
    fault_phase_deg: Optional[float] = Field(
        None, description="Phase défaut en degrés pour --fault-phase"
    )
    fault_cycle_s: float = Field(
        1.0, description="Durée d'un demi-cycle normal/fault en s pour --fault-cycle"
    )


class FlowState(BaseModel):
    """
    État courant exposé par l'API.
    """

    name: str
    interface: str
    src_mac: str
    dst_mac: str
    svid: str
    appid: int
    conf_rev: int
    smp_synch: int
    vlan_id: Optional[int]
    vlan_priority: int
    freq_hz: float
    i_peak: float
    v_peak: float
    phase_deg: float
    fault: bool
    fault_i_peak: Optional[float]
    fault_v_peak: Optional[float]
    fault_phase_deg: Optional[float]
    fault_cycle_s: float
    running: bool


class FlowRuntime:
    """
    Conteneur interne: configuration + process rt_sender associé.
    proc: handle du processus si lancé par nous; None si adopté (processus déjà vivant).
    pid: PID pour les flux adoptés (proc=None) ou pour arrêter un flux lancé par nous.
    """

    def __init__(
        self,
        config: FlowConfig,
        proc: Optional[Popen] = None,
        pid: Optional[int] = None,
    ) -> None:
        self.config = config
        self.proc: Optional[Popen] = proc
        self.pid: Optional[int] = pid


app = FastAPI(title="SV Generator Service")
api = APIRouter(prefix="/api")

flows_lock = threading.Lock()
flows: Dict[str, FlowRuntime] = {}

RECENTS_MAX = 10
recents: list[FlowConfig] = []
recents_lock = threading.Lock()


def _add_to_recents(cfg: FlowConfig) -> None:
    """Ajoute un flux aux récents (10 uniques max, dédup par nom). Persisté sur disque."""
    with recents_lock:
        recents.insert(0, cfg)
        seen: set[str] = set()
        kept: list[FlowConfig] = []
        for c in recents:
            if c.name not in seen:
                seen.add(c.name)
                kept.append(c)
        recents.clear()
        recents.extend(kept[:RECENTS_MAX])
    _save_recents()


def _load_recents() -> None:
    """Charge les récents depuis le fichier au démarrage."""
    if not RECENTS_PATH.exists():
        return
    with RECENTS_PATH.open("r", encoding="utf-8") as f:
        data = json.load(f)
    with recents_lock:
        recents.clear()
        for item in data.get("recents", [])[:RECENTS_MAX]:
            try:
                recents.append(FlowConfig(**item))
            except Exception:
                pass


def _save_recents() -> None:
    with recents_lock:
        payload = {"recents": [c.dict() for c in recents]}
    tmp_path = RECENTS_PATH.with_suffix(".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
    tmp_path.replace(RECENTS_PATH)


def load_config() -> Dict[str, FlowConfig]:
    if not CONFIG_PATH.exists():
        return {}
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        data = json.load(f)
    result: Dict[str, FlowConfig] = {}
    for item in data.get("flows", []):
        try:
            cfg = FlowConfig(**item)
        except Exception as exc:
            name = item.get("name", "<unknown>")
            print(f"Skipping invalid SV flow config '{name}': {exc}")
            continue
        result[cfg.name] = cfg
    return result


def save_config() -> None:
    with flows_lock:
        payload = {"flows": [fr.config.dict() for fr in flows.values()]}
    tmp_path = CONFIG_PATH.with_suffix(".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
    tmp_path.replace(CONFIG_PATH)


def build_rt_sender_cmd(cfg: FlowConfig) -> list[str]:
    if not RT_SENDER_PATH.exists():
        raise RuntimeError(f"rt_sender binary not found at {RT_SENDER_PATH}")

    cmd: list[str] = [str(RT_SENDER_PATH)]

    # Options de timing / contenu SV
    cmd += ["--appid", str(cfg.appid)]
    cmd += ["--conf-rev", str(cfg.conf_rev)]
    cmd += ["--smp-synch", str(cfg.smp_synch)]

    if cfg.vlan_id is not None:
        cmd += ["--vlan-id", str(cfg.vlan_id)]
        cmd += ["--vlan-priority", str(cfg.vlan_priority)]

    cmd += ["--freq", str(cfg.freq_hz)]
    cmd += ["--i-peak", str(cfg.i_peak)]
    cmd += ["--v-peak", str(cfg.v_peak)]
    cmd += ["--phase", str(cfg.phase_deg)]

    if cfg.fault:
        cmd.append("--fault")
        if cfg.fault_i_peak is not None:
            cmd += ["--fault-i-peak", str(cfg.fault_i_peak)]
        if cfg.fault_v_peak is not None:
            cmd += ["--fault-v-peak", str(cfg.fault_v_peak)]
        if cfg.fault_phase_deg is not None:
            cmd += ["--fault-phase", str(cfg.fault_phase_deg)]
        cmd += ["--fault-cycle", str(cfg.fault_cycle_s)]

    # Arguments positionnels: interface, MACs, svID
    cmd += [
        cfg.interface,
        cfg.src_mac,
        cfg.dst_mac,
        cfg.svid,
    ]

    return cmd


def _pidfile_path(name: str) -> pathlib.Path:
    PIDS_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
    return PIDS_DIR / f"{safe_name}.pid"


def _is_pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _write_pidfile(name: str, pid: int) -> None:
    _pidfile_path(name).write_text(str(pid), encoding="utf-8")


def _remove_pidfile(name: str) -> None:
    pf = _pidfile_path(name)
    if pf.exists():
        try:
            pf.unlink()
        except OSError:
            pass


def _try_adopt_flow(cfg: FlowConfig) -> Optional[FlowRuntime]:
    """Adopte un flux si son processus rt_sender est déjà vivant (survit au restart du service)."""
    pf = _pidfile_path(cfg.name)
    if not pf.exists():
        return None
    try:
        pid = int(pf.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None
    if not _is_pid_alive(pid):
        _remove_pidfile(cfg.name)
        return None
    return FlowRuntime(config=cfg, proc=None, pid=pid)


def start_flow_process(cfg: FlowConfig) -> Popen:
    cmd = build_rt_sender_cmd(cfg)
    # start_new_session=True: le processus survit au redémarrage du service po.
    # Les capacités temps réel (SCHED_FIFO, mlockall) sont dans le binaire C.
    proc = Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    _write_pidfile(cfg.name, proc.pid)
    return proc


def stop_flow_process(fr: FlowRuntime) -> None:
    pid = fr.pid
    if fr.proc is not None:
        if fr.proc.poll() is not None:
            pid = None
        else:
            pid = fr.proc.pid
        fr.proc = None
    fr.pid = None
    if pid is None:
        _remove_pidfile(fr.config.name)
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        _remove_pidfile(fr.config.name)
        return
    except Exception:
        pass
    for _ in range(50):  # 5 s
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            break
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
    _remove_pidfile(fr.config.name)


def rebuild_from_config() -> None:
    """Charge flows.json. Adopte les processus déjà vivants (PID) ou en démarre de nouveaux.
    Les flux SV survivent au redémarrage du service po (start_new_session)."""
    cfgs = load_config()
    with flows_lock:
        flows.clear()
        for name, cfg in cfgs.items():
            adopted = _try_adopt_flow(cfg)
            if adopted is not None:
                flows[name] = adopted
                continue
            try:
                proc = start_flow_process(cfg)
                flows[name] = FlowRuntime(config=cfg, proc=proc, pid=proc.pid)
            except Exception as exc:
                print(f"Failed to start flow {name}: {exc}")
                flows[name] = FlowRuntime(config=cfg, proc=None, pid=None)


@app.on_event("startup")
def on_startup() -> None:
    _load_recents()
    rebuild_from_config()


@app.on_event("shutdown")
def on_shutdown() -> None:
    # Ne pas arrêter les flux SV : ils survivent au service (start_new_session).
    # L'utilisateur les arrête explicitement via l'API si besoin.
    pass


def _webui_html() -> str:
    return """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SV Generator – Flux</title>
  <style>
    :root {
      --bg: #1a1b26;
      --surface: #24283b;
      --text: #c0caf5;
      --muted: #565f89;
      --accent: #7aa2f7;
      --danger: #f7768e;
      --success: #9ece6a;
    }
    * { box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 1.5rem;
      line-height: 1.5;
    }
    h1 { font-size: 1.5rem; font-weight: 600; margin: 0 0 1rem 0; color: var(--accent); }
    .toolbar { display: flex; gap: 0.75rem; align-items: center; margin-bottom: 1.25rem; flex-wrap: wrap; }
    .btn {
      padding: 0.5rem 0.75rem;
      border: none;
      border-radius: 6px;
      font-size: 0.875rem;
      cursor: pointer;
      background: var(--surface);
      color: var(--text);
    }
    .btn:hover { filter: brightness(1.15); }
    .btn--accent { background: var(--accent); color: var(--bg); }
    .btn--danger { background: var(--danger); color: #fff; }
    .btn--small { padding: 0.35rem 0.6rem; font-size: 0.8rem; }
    table {
      width: 100%;
      border-collapse: collapse;
      background: var(--surface);
      border-radius: 8px;
      overflow: hidden;
    }
    th, td { padding: 0.6rem 0.75rem; text-align: left; }
    th {
      background: rgba(0,0,0,0.2);
      font-weight: 600;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      color: var(--muted);
    }
    tr:hover td { background: rgba(255,255,255,0.03); }
    .status { font-weight: 500; }
    .status.running { color: var(--success); }
    .details-row td {
      background: #0f0f14;
      padding: 1rem 0.75rem;
      border-top: none;
      vertical-align: top;
    }
    .details-grid {
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 0.25rem 1rem;
      font-size: 0.85rem;
    }
    .details-grid dt { color: var(--muted); margin: 0; }
    .details-grid dd { margin: 0; }
    .recents-section { margin-top: 2rem; border-top: 1px solid var(--surface); }
    .recents-section h2 {
      font-size: 1rem;
      font-weight: 600;
      margin: 0.75rem 0 0.5rem 0;
      color: var(--muted);
    }
    .empty { text-align: center; padding: 2rem; color: var(--muted); }
    #msg { font-size: 0.85rem; margin-top: 0.5rem; }
    #msg.err { color: var(--danger); }
    #msg.ok { color: var(--success); }
  </style>
</head>
<body>
  <h1>SV Generator</h1>
  <div class="toolbar">
    <button type="button" id="refresh" class="btn">Actualiser</button>
    <button type="button" id="deleteAll" class="btn btn--danger">Tout supprimer</button>
  </div>
  <div id="msg"></div>
  <h2 style="font-size:1rem; font-weight:600; margin:1.5rem 0 0.5rem 0; color:var(--muted);">Flux en cours</h2>
  <table>
    <thead>
      <tr>
        <th></th>
        <th>Nom</th>
        <th>Interface</th>
        <th>src_mac → dst_mac</th>
        <th>svID</th>
        <th>VLAN</th>
        <th></th>
      </tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>
  <div class="recents-section">
  <h2>Récents</h2>
  <table>
    <thead>
      <tr>
        <th></th>
        <th>Nom</th>
        <th>Interface</th>
        <th>src_mac → dst_mac</th>
        <th>svID</th>
        <th>VLAN</th>
        <th></th>
      </tr>
    </thead>
    <tbody id="recents-tbody"></tbody>
  </table>
  </div>
  <script>
    const tbody = document.getElementById('tbody');
    const recentsTbody = document.getElementById('recents-tbody');
    const msg = document.getElementById('msg');
    function setMsg(text, isErr) {
      msg.textContent = text;
      msg.className = isErr ? 'err' : 'ok';
    }
    function formatFlowDetails(f) {
      const kv = [
        ['name', f.name],
        ['interface', f.interface],
        ['src_mac', f.src_mac],
        ['dst_mac', f.dst_mac],
        ['svid', f.svid],
        ['appid', f.appid],
        ['conf_rev', f.conf_rev],
        ['smp_synch', f.smp_synch],
        ['vlan_id', f.vlan_id],
        ['vlan_priority', f.vlan_priority],
        ['freq_hz', f.freq_hz],
        ['i_peak', f.i_peak],
        ['v_peak', f.v_peak],
        ['phase_deg', f.phase_deg],
        ['fault', f.fault],
        ['fault_i_peak', f.fault_i_peak],
        ['fault_v_peak', f.fault_v_peak],
        ['fault_phase_deg', f.fault_phase_deg],
        ['fault_cycle_s', f.fault_cycle_s],
      ];
      return kv.filter(([,v]) => v !== undefined && v !== null)
        .map(([k,v]) => '<dt>' + escapeHtml(k) + '</dt><dd>' + escapeHtml(String(v)) + '</dd>').join('');
    }
    async function load() {
      try {
        const r = await fetch('/api/flows');
        if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
        const flows = await r.json();
        tbody.innerHTML = flows.length === 0
          ? '<tr><td colspan="7" class="empty">Aucun flux.</td></tr>'
          : flows.flatMap(f => {
              const rowId = 'row-' + escapeHtml(f.name);
              const detailsId = 'details-' + escapeHtml(f.name);
              return [
                '<tr id="' + rowId + '">' +
                  '<td><button type="button" class="btn btn--small" data-target="' + detailsId + '" aria-label="Détails">Détails</button></td>' +
                  '<td>' + escapeHtml(f.name) + '</td>' +
                  '<td>' + escapeHtml(f.interface) + '</td>' +
                  '<td>' + escapeHtml(f.src_mac) + ' → ' + escapeHtml(f.dst_mac) + '</td>' +
                  '<td>' + escapeHtml(f.svid) + '</td>' +
                  '<td>' + (f.vlan_id != null ? f.vlan_id + (f.vlan_priority != null ? ' (prio ' + f.vlan_priority + ')' : '') : '–') + '</td>' +
                  '<td><button type="button" class="btn btn--danger btn--small delete-one" data-name="' + escapeHtml(f.name) + '">Supprimer</button></td>' +
                '</tr>',
                '<tr id="' + detailsId + '" class="details-row" style="display:none"><td colspan="7"><div class="details-grid">' + formatFlowDetails(f) + '</div></td></tr>'
              ];
            }).join('');
        tbody.querySelectorAll('[data-target]').forEach(btn => {
          btn.addEventListener('click', () => {
            const el = document.getElementById(btn.dataset.target);
            const visible = el.style.display !== 'none';
            el.style.display = visible ? 'none' : 'table-row';
            btn.textContent = visible ? 'Détails' : 'Réduire';
          });
        });
        tbody.querySelectorAll('.delete-one').forEach(btn => {
          btn.addEventListener('click', () => deleteFlow(btn.dataset.name));
        });
        loadRecents(flows);
      } catch (e) {
        setMsg('Erreur: ' + e.message, true);
      }
    }
    let lastRecents = [];
    async function loadRecents(currentFlows) {
      try {
        const r = await fetch('/api/flows/recents');
        if (!r.ok) return;
        const recents = await r.json();
        lastRecents = recents;
        const runningNames = new Set((currentFlows || []).filter(f => f.running).map(f => f.name));
        recentsTbody.innerHTML = recents.length === 0
          ? '<tr><td colspan="7" class="empty">Aucun flux récent.</td></tr>'
          : recents.flatMap((cfg, i) => {
              const canRestart = !runningNames.has(cfg.name);
              const detailsId = 'recents-details-' + i;
              return [
                '<tr>' +
                  '<td><button type="button" class="btn btn--small" data-target="' + detailsId + '" aria-label="Détails">Détails</button></td>' +
                  '<td>' + escapeHtml(cfg.name) + '</td>' +
                  '<td>' + escapeHtml(cfg.interface) + '</td>' +
                  '<td>' + escapeHtml(cfg.src_mac) + ' → ' + escapeHtml(cfg.dst_mac) + '</td>' +
                  '<td>' + escapeHtml(cfg.svid) + '</td>' +
                  '<td>' + (cfg.vlan_id != null ? cfg.vlan_id + (cfg.vlan_priority != null ? ' (prio ' + cfg.vlan_priority + ')' : '') : '–') + '</td>' +
                  '<td>' + (canRestart
                    ? '<button type="button" class="btn btn--accent btn--small restart-one" data-idx="' + i + '">Relancer</button>'
                    : '<span class="status running">En cours</span>') + '</td>' +
                '</tr>',
                '<tr id="' + detailsId + '" class="details-row" style="display:none"><td colspan="7"><div class="details-grid">' + formatFlowDetails(cfg) + '</div></td></tr>'
              ];
            }).join('');
        recentsTbody.querySelectorAll('[data-target]').forEach(btn => {
          btn.addEventListener('click', () => {
            const el = document.getElementById(btn.dataset.target);
            const visible = el.style.display !== 'none';
            el.style.display = visible ? 'none' : 'table-row';
            btn.textContent = visible ? 'Détails' : 'Réduire';
          });
        });
        recentsTbody.querySelectorAll('.restart-one').forEach(btn => {
          btn.addEventListener('click', () => restartFlow(lastRecents[parseInt(btn.dataset.idx, 10)]));
        });
      } catch (e) {}
    }
    async function restartFlow(cfg) {
      try {
        const r = await fetch('/api/flows', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(cfg),
        });
        if (!r.ok) throw new Error(r.status + ' ' + (await r.text()));
        setMsg('Flux "' + cfg.name + '" relancé.', false);
        load();
      } catch (e) {
        setMsg('Erreur: ' + e.message, true);
      }
    }
    function escapeHtml(s) {
      if (s == null) return '';
      const d = document.createElement('div');
      d.textContent = s;
      return d.innerHTML;
    }
    async function deleteFlow(name) {
      if (!confirm('Supprimer le flux "' + name + '" ?')) return;
      try {
        const r = await fetch('/api/flows/' + encodeURIComponent(name), { method: 'DELETE' });
        if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
        setMsg('Flux "' + name + '" supprimé.', false);
        load();
      } catch (e) {
        setMsg('Erreur: ' + e.message, true);
      }
    }
    async function deleteAll() {
      if (!confirm('Supprimer tous les flux ?')) return;
      try {
        const r = await fetch('/api/flows', { method: 'DELETE' });
        if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
        setMsg('Tous les flux ont été supprimés.', false);
        load();
      } catch (e) {
        setMsg('Erreur: ' + e.message, true);
      }
    }
    document.getElementById('refresh').addEventListener('click', () => { setMsg('', false); load(); });
    document.getElementById('deleteAll').addEventListener('click', deleteAll);
    load();
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def webui_index() -> HTMLResponse:
    """Page web : liste des flux et boutons supprimer."""
    return HTMLResponse(content=_webui_html())


@api.get("/flows", response_model=list[FlowState])
def list_flows() -> list[FlowState]:
    result: list[FlowState] = []
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
                )
            )
    return result


@api.post("/flows", response_model=FlowState)
def create_flow(cfg: FlowConfig) -> FlowState:
    with flows_lock:
        if cfg.name in flows:
            raise HTTPException(status_code=409, detail="Flow already exists")
        try:
            proc = start_flow_process(cfg)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))
        flows[cfg.name] = FlowRuntime(config=cfg, proc=proc)
    _add_to_recents(cfg)
    save_config()
    return FlowState(
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
    )


@api.put("/flows/{name}", response_model=FlowState)
def update_flow(name: str, cfg: FlowConfig) -> FlowState:
    if cfg.name != name:
        cfg = FlowConfig(**{**cfg.dict(), "name": name})

    with flows_lock:
        if name in flows:
            stop_flow_process(flows[name])
        try:
            proc = start_flow_process(cfg)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))
        flows[name] = FlowRuntime(config=cfg, proc=proc)
    _add_to_recents(cfg)
    save_config()
    return FlowState(
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
    )


@api.get("/flows/recents")
def list_recents() -> list[dict]:
    """Liste des 10 derniers flux (uniques) pour relance."""
    with recents_lock:
        return [c.dict() for c in recents]


@api.delete("/flows/{name}")
def delete_flow(name: str) -> dict:
    with flows_lock:
        fr = flows.get(name)
        if fr is None:
            raise HTTPException(status_code=404, detail="Flow not found")
        _add_to_recents(fr.config)
        stop_flow_process(fr)
        del flows[name]
    save_config()
    return {"status": "ok"}


@api.delete("/flows")
def delete_all_flows() -> dict:
    with flows_lock:
        for fr in flows.values():
            _add_to_recents(fr.config)
            stop_flow_process(fr)
        flows.clear()
    save_config()
    return {"status": "ok"}


app.include_router(api)

