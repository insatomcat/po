# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import sys
from pathlib import Path

# Bootstrap pour exécution standalone (python3 mms/mms_service.py)
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

"""
Service HTTP long‑running pour gérer des flux de reports MMS par domaine.

Concepts:
  - Le service est démarré une fois, avec des paramètres globaux:
        --victoriametrics-url URL
        --vm-batch-ms N
    Le push VictoriaMetrics est donc le mode par défaut.

  - Via l'API HTTP, on gère des « flux domaine » (subscriptions MMS) :
        * création / modification / suppression d'un flux
        * mise en mode debug (affichage texte dans la console) ou non
        * modification de la liste RCB (rcb-list) et du fichier SCL
        * listing des flux et de leurs options actuelles

  - Un flux est défini par:
        * ied_host, ied_port : IED cible
        * domain_id          : domaine MMS (LD)
        * scl_path           : chemin fichier SCL/ICD (optionnel)
        * rcb_list_path      : chemin liste des RCB à activer (optionnel → liste intégrée)
        * debug_console      : bool (affiche les reports en texte dans la console du service)

  - Chaque flux tourne dans un thread dédié qui ouvre la connexion MMS,
    active les RCB, boucle sur les reports et les pousse vers VictoriaMetrics.

API HTTP (JSON, état persistant dans mms/subscriptions.json) :

  POST /subscriptions
      Body:
        {
          "id": "flux-1",           # optionnel, sinon généré
          "ied_host": "10.1.2.3",
          "ied_port": 102,
          "domain": "IED01_LD0",
          "scl": "/chemin/vers/fichier.icd",        # optionnel
          "rcb_list": "/chemin/vers/rcb.txt",       # optionnel
          "debug": true                             # optionnel, défaut False
        }
      Réponse:
        201 Created + JSON du flux

  GET /subscriptions
      Réponse:
        200 OK
        [
          {
            "id": "...",
            "ied_host": "...",
            "ied_port": 102,
            "domain": "...",
            "scl": "...",
            "rcb_list": "...",
            "debug": true,
            "last_error": "..." | null,
            "rcb_items": ["...", ...]
          },
          ...
        ]

  GET /subscriptions/<id>
      Réponse :
        200 OK + JSON du flux
        404 si inconnu

  PUT /subscriptions/<id>
      Body: mêmes champs que POST mais tous optionnels (patch sémantique).
      Derrière les coulisses, on arrête l'ancien thread et on en lance un nouveau
      avec la nouvelle configuration.

  DELETE /subscriptions/<id>
      Supprime le flux (arrête le thread) et renvoie 204.

  DELETE /subscriptions
      Supprime tous les flux (arrête tous les threads) et renvoie 204.

  GET /healthz
      Simple check 200 OK.

  GET /logs
      Flux SSE des logs du service (temps réel).
"""

import argparse
import json
import os
import queue
import sys
import threading
from pathlib import Path
import time
import uuid
from dataclasses import dataclass, asdict, field
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Dict, Optional, Any, Tuple

from iec61850 import scl
from iec61850.mms import (
    OBJECT_CLASS_DOMAIN,
    OBJECT_CLASS_NAMED_VARIABLE,
    MmsClient,
    MmsError,
    ObjectName,
    control,
    decode_report,
    is_report,
    rcb,
)
from iec61850.mms import pdu as pdu_types
from mms import reporting
from mms.scl_parser import parse_scl_data_set_members_with_components
from mms.victoriametrics_push import push_lines

# Capture des logs pour diffusion SSE (seq monotonique pour fenêtre glissante)
LOG_LINES: list[tuple[int, str]] = []  # (seq, line)
LOG_NEXT_SEQ = 0
LOG_MAX = 500
LOG_LOCK = threading.Lock()
LOG_CONDITION = threading.Condition(LOG_LOCK)


class _TeeStdout:
    """Redirige stdout vers la sortie réelle + buffer pour GET /logs."""

    def __init__(self, real: Any) -> None:
        self._real = real
        self._buf = ""

    def write(self, s: str) -> None:
        global LOG_NEXT_SEQ
        self._real.write(s)
        self._real.flush()  # journalctl immédiat (stdout en pipe = buffer par bloc)
        with LOG_LOCK:
            self._buf += s
            while "\n" in self._buf:
                line, self._buf = self._buf.split("\n", 1)
                LOG_NEXT_SEQ += 1
                LOG_LINES.append((LOG_NEXT_SEQ, line))
                if len(LOG_LINES) > LOG_MAX:
                    LOG_LINES.pop(0)
                LOG_CONDITION.notify_all()

    def flush(self) -> None:
        self._real.flush()


@dataclass
class SubscriptionConfig:
    id: str
    ied_host: str
    ied_port: int
    domain: str = ""  # one logical device; empty: every one the IED has
    scl: Optional[str] = None  # CID/SCD: block names without asking the IED, and a consistency check
    rcb_list: Optional[str] = None  # older: file of block names
    debug: bool = False
    triggers: Optional[str] = None  # e.g. "integrity,gi" (default) or "dchg,qchg,integrity,gi"
    integrity_ms: int = 2000
    rcb_filter: Optional[str] = None  # e.g. "CB_LDPX_*, CB_LDADD_*"; empty: every block


CONFIG_FIELDS = ("ied_host", "ied_port", "domain", "scl", "rcb_list", "rcb_filter", "debug", "triggers", "integrity_ms")


def config_from_json(data: Dict[str, Any], sub_id: Optional[str] = None) -> SubscriptionConfig:
    """A subscription from an API body; raises KeyError (missing ied_host) or ValueError."""
    cfg = SubscriptionConfig(
        id=str(sub_id or data.get("id") or uuid.uuid4().hex),
        ied_host=str(data["ied_host"]),
        ied_port=int(data.get("ied_port") or 102),
        domain=str(data.get("domain") or ""),
        scl=data.get("scl") or None,
        rcb_list=data.get("rcb_list") or None,
        rcb_filter=data.get("rcb_filter") or None,
        debug=bool(data.get("debug", False)),
        triggers=data.get("triggers") or None,
        integrity_ms=int(data.get("integrity_ms") or 2000),
    )
    reporting.parse_triggers(cfg.triggers)
    return cfg


def config_to_json(cfg: SubscriptionConfig) -> Dict[str, Any]:
    out = {"id": cfg.id, **{name: getattr(cfg, name) for name in CONFIG_FIELDS}}
    out["triggers"] = cfg.triggers or reporting.DEFAULT_TRIGGERS
    return out


@dataclass
class SubscriptionRuntime:
    config: SubscriptionConfig
    last_error: Optional[str] = None
    thread: Optional[threading.Thread] = None
    stop_event: threading.Event = threading.Event()
    client: Optional[MmsClient] = None
    total_reports: int = 0
    reports_since_log: int = 0
    last_log_ts: float = 0.0
    rcb_items: list = field(default_factory=list)  # liste des RCB souscrits (remplie par le worker)
    # Conteneur mutable pour que le thread worker voie le toggle debug sans restart
    debug_console: list = field(default_factory=lambda: [False])


@dataclass
class MMSCommandConfig:
    """Configuration persistée d'une commande MMS (write/operate)."""

    id: str
    name: str
    ied_host: str
    ied_port: int
    domain: str
    item: str
    position: str  # "open" | "closed"


# ctlVal of a double point control (DPC): TRUE closes, FALSE opens.
COMMAND_POSITIONS = {"open": False, "closed": True}
# po is a substation control tool: station-control, like IEDscout.
COMMAND_ORIGIN = control.Origin(control.OR_CAT_STATION_CONTROL, b"po")


RECENTS_MAX = 20
_RECONNECT_DELAY_INITIAL = 5.0
_RECONNECT_DELAY_MAX = 60.0

# Drapeau debug par flux (in-memory, pas de persistance)
_DEBUG_CONSOLE: Dict[str, bool] = {}

# Chemins des fichiers de persistance (dans mms/)
_MMS_DIR = Path(__file__).resolve().parent
SUBSCRIPTIONS_PATH = _MMS_DIR / "subscriptions.json"
RECENTS_PATH = _MMS_DIR / "recents.json"
COMMANDS_PATH = _MMS_DIR / "commands.json"


class SubscriptionManager:
    """Gestion centralisée des flux (in‑memory avec persistance sur disque)."""

    def __init__(self, vm_url: Optional[str], vm_batch_ms: int) -> None:
        self._subs: Dict[str, SubscriptionRuntime] = {}
        self._recents: list[Dict[str, Any]] = []
        self._commands: Dict[str, MMSCommandConfig] = {}
        self._ctl_nums: Dict[str, int] = {}
        self._lock = threading.Lock()
        self._vm_url = vm_url
        self._vm_batch_ms = vm_batch_ms
        self._state_path = SUBSCRIPTIONS_PATH
        self._recents_path = RECENTS_PATH
        self._commands_path = COMMANDS_PATH
        self._load_state()
        self._load_recents()
        self._load_commands()

    def list_subscriptions(self) -> Dict[str, SubscriptionRuntime]:
        with self._lock:
            return dict(self._subs)

    def get_subscription(self, sub_id: str) -> Optional[SubscriptionRuntime]:
        with self._lock:
            return self._subs.get(sub_id)

    def create_subscription(self, cfg: SubscriptionConfig) -> SubscriptionRuntime:
        with self._lock:
            if cfg.id in self._subs:
                raise ValueError(f"subscription {cfg.id!r} already exists")
            runtime = SubscriptionRuntime(config=cfg, debug_console=[cfg.debug])
            self._subs[cfg.id] = runtime
            _DEBUG_CONSOLE[cfg.id] = cfg.debug
            self._save_state_locked()
        self._start_subscription_thread(runtime)
        self._add_to_recents(runtime)
        return runtime

    def update_subscription(self, sub_id: str, new_fields: Dict[str, Any]) -> SubscriptionRuntime:
        with self._lock:
            runtime = self._subs.get(sub_id)
            if not runtime:
                raise KeyError(sub_id)
            # Cas 1 : mise à jour uniquement du flag debug → pas de redémarrage
            only_debug = all(
                (k == "debug") or (v is None)
                for k, v in new_fields.items()
            )
            if only_debug and "debug" in new_fields and new_fields["debug"] is not None:
                new_val = bool(new_fields["debug"])
                runtime.config.debug = new_val
                runtime.debug_console[0] = new_val
                _DEBUG_CONSOLE[sub_id] = new_val
                self._save_state_locked()
                print(f"[MMS] Flux {sub_id}: debug={new_val} (sans restart)", flush=True)
                return runtime

            # Cas 2 : modification host/port/domain/scl/rcb_list → redémarrer le flux
            data = asdict(runtime.config)
            data.update({k: v for k, v in new_fields.items() if v is not None})
            if "debug" in new_fields:
                data["debug"] = bool(new_fields["debug"])
            cfg = SubscriptionConfig(**data)
            runtime.config = cfg
            runtime.debug_console[0] = cfg.debug
            _DEBUG_CONSOLE[cfg.id] = cfg.debug
            self._save_state_locked()
        self._stop_runtime(runtime)
        self._start_subscription_thread(runtime)
        return runtime

    def delete_subscription(self, sub_id: str) -> None:
        with self._lock:
            runtime = self._subs.pop(sub_id, None)
            _DEBUG_CONSOLE.pop(sub_id, None)
            self._save_state_locked()
        if runtime:
            self._add_to_recents(runtime)
            self._stop_runtime(runtime)

    def purge_all(self) -> None:
        """Supprime tous les flux (arrêt de tous les threads + reset du fichier de conf)."""
        with self._lock:
            runtimes = list(self._subs.values())
            self._subs.clear()
            _DEBUG_CONSOLE.clear()
            self._save_state_locked()
        for rt in runtimes:
            self._add_to_recents(rt)
            self._stop_runtime(rt)

    def stop_all(self) -> None:
        """Stop every stream (their RCBs are disabled and released) and keep the configuration."""
        with self._lock:
            runtimes = list(self._subs.values())
        for rt in runtimes:
            rt.stop_event.set()
        for rt in runtimes:
            self._stop_runtime(rt)

    def get_recents(self) -> list[Dict[str, Any]]:
        with self._lock:
            return list(self._recents)

    def _add_to_recents(self, runtime: SubscriptionRuntime) -> None:
        """Ajoute un flux aux récents (20 derniers uniques par id)."""
        cfg = runtime.config
        entry = {**config_to_json(cfg), "triggers": cfg.triggers, "rcb_items": list(runtime.rcb_items)}
        with self._lock:
            self._recents = [e for e in self._recents if e.get("id") != cfg.id]
            self._recents.insert(0, entry)
            self._recents = self._recents[:RECENTS_MAX]
            self._save_recents_locked()

    def _load_recents(self) -> None:
        try:
            with open(self._recents_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except FileNotFoundError:
            return
        except Exception as e:
            print(f"[Recents] Impossible de charger {self._recents_path}: {e}")
            return
        if isinstance(raw, list):
            items = raw
        else:
            items = raw.get("recents", raw.get("recent", []))
        self._recents = (items or [])[:RECENTS_MAX]

    def _save_recents_locked(self) -> None:
        try:
            payload = {"recents": self._recents}
            tmp_path = self._recents_path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, self._recents_path)
        except Exception as e:
            print(f"[Recents] Erreur sauvegarde {self._recents_path}: {e}")

    # --- commandes MMS (persistence + envoi) ---

    def list_commands(self) -> list[Dict[str, Any]]:
        with self._lock:
            return [asdict(c) for c in self._commands.values()]

    def get_command(self, cmd_id: str) -> Optional[MMSCommandConfig]:
        with self._lock:
            return self._commands.get(cmd_id)

    def create_command(self, cfg: MMSCommandConfig) -> MMSCommandConfig:
        with self._lock:
            if cfg.id in self._commands:
                raise ValueError(f"command {cfg.id!r} already exists")
            self._commands[cfg.id] = cfg
            self._save_commands_locked()
        return cfg

    def delete_command(self, cmd_id: str) -> None:
        with self._lock:
            if cmd_id not in self._commands:
                raise KeyError(cmd_id)
            self._commands.pop(cmd_id, None)
            self._save_commands_locked()

    def purge_commands(self) -> None:
        with self._lock:
            self._commands.clear()
            self._save_commands_locked()

    def send_command(self, cmd_id: str) -> Dict[str, Any]:
        """Operate the configured control once; raise ControlError when the IED refuses it."""
        with self._lock:
            cfg = self._commands.get(cmd_id)
            if not cfg:
                raise KeyError(cmd_id)
            ctl_num = self._ctl_nums.get(cmd_id, 0)
            self._ctl_nums[cmd_id] = (ctl_num + 1) & 0xFF
        if cfg.position not in COMMAND_POSITIONS:
            raise ValueError(f"position must be one of: {'|'.join(COMMAND_POSITIONS)}")

        name = ObjectName(cfg.item, cfg.domain)
        _log_line(f"[MMS-CMD] {cfg.position} {name} on {cfg.ied_host}:{cfg.ied_port} ctlNum={ctl_num}")
        try:
            with MmsClient.connect(cfg.ied_host, cfg.ied_port, timeout=5.0) as client:
                result = control.operate(
                    client, name, COMMAND_POSITIONS[cfg.position], origin=COMMAND_ORIGIN, ctl_num=ctl_num
                )
        except MmsError as exc:
            _log_line(f"[MMS-CMD] {cfg.position} {name} failed: {exc}")
            raise
        _log_line(f"[MMS-CMD] {cfg.position} {name} done: {result}")
        return {
            "ctl_model": control.CTL_MODELS.get(result.ctl_model, str(result.ctl_model)),
            "ctl_num": result.ctl_num,
            "terminated": result.terminated,
            "duration_ms": round(result.duration * 1000),
        }

    def _load_commands(self) -> None:
        try:
            with open(self._commands_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except FileNotFoundError:
            return
        except Exception as e:
            print(f"[MMS-CMD] Impossible de charger {self._commands_path}: {e}")
            return

        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            items = raw.get("commands", raw.get("cmds", []))
        else:
            return

        if not isinstance(items, list):
            return

        loaded: Dict[str, MMSCommandConfig] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                cmd = MMSCommandConfig(
                    id=str(item["id"]),
                    name=str(item.get("name") or item["id"]),
                    ied_host=str(item["ied_host"]),
                    ied_port=int(item.get("ied_port", 102)),
                    domain=str(item["domain"]),
                    item=str(item["item"]),
                    position=str(item.get("position") or "closed"),
                )
            except (KeyError, TypeError, ValueError) as e:
                print(f"[MMS-CMD] Commande ignorée (données invalides): {e}")
                continue
            loaded[cmd.id] = cmd

        with self._lock:
            self._commands = loaded
        if loaded:
            print(f"[MMS-CMD] {len(loaded)} commande(s) rechargée(s) depuis {self._commands_path}.")

    def _save_commands_locked(self) -> None:
        try:
            payload = [asdict(c) for c in self._commands.values()]
            tmp_path = self._commands_path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, self._commands_path)
        except Exception as e:
            print(f"[MMS-CMD] Erreur sauvegarde {self._commands_path}: {e}")

    # --- gestion des threads ---

    def _start_subscription_thread(self, runtime: SubscriptionRuntime) -> None:
        runtime.stop_event = threading.Event()
        runtime.last_error = None
        runtime.total_reports = 0
        runtime.reports_since_log = 0
        runtime.last_log_ts = time.time()
        t = threading.Thread(
            target=self._subscription_worker,
            args=(runtime,),
            daemon=True,
        )
        runtime.thread = t
        t.start()

    # --- persistance ---

    def _load_state(self) -> None:
        """Charge la configuration des flux depuis le fichier JSON (si présent)."""
        try:
            with open(self._state_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except FileNotFoundError:
            return
        except Exception as e:
            print(f"[State] Impossible de charger {self._state_path}: {e}")
            return
        if not isinstance(raw, list):
            print(f"[State] Format inattendu dans {self._state_path}, ignoré.")
            return
        for item in raw:
            if not isinstance(item, dict):
                continue
            try:
                cfg = SubscriptionConfig(**item)
            except TypeError as e:
                print(f"[State] Config invalide ignorée: {e}")
                continue
            rt = SubscriptionRuntime(config=cfg, debug_console=[cfg.debug])
            self._subs[cfg.id] = rt
            _DEBUG_CONSOLE[cfg.id] = cfg.debug
        if self._subs:
            print(f"[State] {len(self._subs)} flux rechargés depuis {self._state_path}.")
            # Démarrer les threads après reconstruction des runtimes
            for rt in list(self._subs.values()):
                self._start_subscription_thread(rt)

    def _save_state_locked(self) -> None:
        """Sauvegarde la configuration des flux dans un fichier JSON (lock déjà tenu)."""
        try:
            data = [asdict(rt.config) for rt in self._subs.values()]
            tmp_path = self._state_path.with_suffix(self._state_path.suffix + ".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, self._state_path)
        except Exception as e:
            print(f"[State] Erreur lors de l'enregistrement de {self._state_path}: {e}")

    def _stop_runtime_locked(self, runtime: SubscriptionRuntime) -> None:
        """Ask the worker to stop; it disables its report control blocks before closing."""
        runtime.stop_event.set()

    def _stop_runtime(self, runtime: SubscriptionRuntime) -> None:
        self._stop_runtime_locked(runtime)
        t = runtime.thread
        if t and t.is_alive():
            t.join(timeout=5.0)
            if t.is_alive():
                client = runtime.client
                if client is not None:
                    client.close()
                t.join(timeout=2.0)
                if t.is_alive():
                    print(f"[MMS] Warning: thread {t.name!r} did not stop in time.")

    def _subscription_worker(self, runtime: SubscriptionRuntime) -> None:
        """Connect, subscribe and process reports; reconnect with backoff until stopped."""
        cfg = runtime.config
        scl_labels: Dict[str, list] = {}
        if cfg.scl:
            try:
                scl_labels, _, _ = parse_scl_data_set_members_with_components(cfg.scl)
                print(f"[SCL] {len(scl_labels)} data set key(s) loaded from {cfg.scl} (fallback labels)")
            except Exception as e:
                print(f"[SCL] Cannot load {cfg.scl}: {e}")
        wanted = load_rcb_list(cfg.rcb_list)
        scl_ied = load_scl_ied(cfg)
        try:
            settings = reporting.rcb_settings(cfg.triggers, cfg.integrity_ms)
        except ValueError as e:
            runtime.last_error = str(e)
            print(f"[MMS] Stream {cfg.id}: {e}")
            return

        reconnect_delay_sec = _RECONNECT_DELAY_INITIAL
        while not runtime.stop_event.is_set():
            reports: "queue.Queue[pdu_types.InformationReport]" = queue.Queue()
            client: Optional[MmsClient] = None
            enabled: list[ObjectName] = []
            connection_ok = False
            try:
                print(f"[MMS] Stream {cfg.id}: connecting to {cfg.ied_host}:{cfg.ied_port} ...")
                client = MmsClient.connect(cfg.ied_host, cfg.ied_port, timeout=10.0, on_information_report=reports.put)
                runtime.client = client
                data_sets, enabled = self._subscribe(runtime, client, wanted, scl_ied, settings, scl_labels)
                connection_ok = bool(enabled)
                print(f"[Stream {cfg.id}] {len(enabled)} RCB enabled: {', '.join(str(r) for r in enabled)}")
                while not runtime.stop_event.is_set():
                    try:
                        message = reports.get(timeout=0.5)
                    except queue.Empty:
                        if not client.is_connected:
                            break
                        continue
                    self._handle_report(runtime, message, data_sets)
                if not runtime.stop_event.is_set():
                    reason = client.wait_closed(0)
                    print(f"[Stream {cfg.id}] Connection closed ({reason}). Reconnecting...")
            except MmsError as e:
                if runtime.stop_event.is_set():
                    break
                runtime.last_error = str(e)
                print(f"[MMS] Stream {cfg.id}: {e}")
            except Exception as e:  # noqa: BLE001 - keep the stream alive
                if runtime.stop_event.is_set():
                    break
                runtime.last_error = f"{type(e).__name__}: {e}"
                print(f"[Stream {cfg.id}] Unexpected error: {runtime.last_error}")
            finally:
                if client is not None:
                    if runtime.stop_event.is_set() and client.is_connected:
                        for r in enabled:
                            try:
                                rcb.disable(client, r)
                            except MmsError:
                                pass
                        if enabled:
                            print(f"[Stream {cfg.id}] {len(enabled)} RCB disabled.")
                    client.close()
                runtime.client = None

            if runtime.stop_event.is_set():
                break
            if connection_ok:
                reconnect_delay_sec = _RECONNECT_DELAY_INITIAL
            else:
                reconnect_delay_sec = min(reconnect_delay_sec * 2.0, _RECONNECT_DELAY_MAX)
            print(f"[MMS] Stream {cfg.id}: retrying in {reconnect_delay_sec:.0f} s...")
            runtime.stop_event.wait(reconnect_delay_sec)

        print(f"[Stream {cfg.id}] Subscription thread stopped.")

    def _subscribe(
        self,
        runtime: SubscriptionRuntime,
        client: MmsClient,
        wanted: Optional[list],
        scl_ied: "Optional[scl.SclIed]",
        settings: "rcb.RcbSettings",
        scl_labels: Dict[str, list],
    ) -> "tuple[Dict[str, reporting.DataSetInfo], list[ObjectName]]":
        """Pick a free instance of each selected block, read its data set and enable it."""
        cfg = runtime.config
        groups = self._rcb_groups(cfg, client, scl_ied)
        plan, missing = reporting.plan_subscriptions(
            groups, patterns=reporting.parse_rcb_filter(cfg.rcb_filter), wanted=wanted, previous=runtime.rcb_items
        )
        for name in missing:
            print(f"[Stream {cfg.id}] no report control block matches {name}")
        print(f"[Stream {cfg.id}] {len(plan)} of {len(groups)} report control block(s) selected")
        data_sets: Dict[str, reporting.DataSetInfo] = {}
        enabled: list[ObjectName] = []
        errors: list[str] = []
        for i, candidates in enumerate(plan, 1):
            if runtime.stop_event.is_set():
                break
            options = rcb.usable(client, candidates)
            status = None
            refused: list[str] = []
            for option in options:
                ds_ref = option.dat_set or ""
                if ds_ref and ds_ref not in data_sets:  # before enabling: the GI report follows at once
                    data_sets[ds_ref] = reporting.load_data_set(client, ds_ref, scl_labels.get(ds_ref))
                try:
                    rcb.enable(client, option.rcb, settings)
                except MmsError as e:
                    refused.append(str(e))
                    continue
                status = option
                break
            if status is None:
                base = rcb.instance_base(str(candidates[0]))
                errors.append(f"{base}: every instance is in use" + (f" ({refused[-1]})" if refused else ""))
                print(f"[Stream {cfg.id}] [{i}/{len(plan)}] {errors[-1]}")
                continue
            ds_ref = status.dat_set or ""
            enabled.append(status.rcb)
            members = len(data_sets[ds_ref].members) if ds_ref in data_sets else 0
            print(f"[Stream {cfg.id}] [{i}/{len(plan)}] {status.rcb.item} enabled "
                  f"(RptID {status.rpt_id}, {members} members)")
        runtime.rcb_items = [str(r) for r in enabled]
        runtime.last_error = "; ".join(errors) or None
        return data_sets, enabled

    def _rcb_groups(
        self, cfg: SubscriptionConfig, client: MmsClient, scl_ied: "Optional[scl.SclIed]"
    ) -> "list[reporting.RcbGroup]":
        """The IED's report control blocks: from the SCL when it matches the IED, else asked to the IED."""
        ied_domains = client.get_name_list(OBJECT_CLASS_DOMAIN)
        if cfg.domain and cfg.domain not in ied_domains:
            raise MmsError(f"domain {cfg.domain} not on the IED at {cfg.ied_host}, which has {_list(ied_domains)}")
        wanted_domains = [cfg.domain] if cfg.domain else ied_domains
        if scl_ied is not None:
            known = [d for d in scl_ied.domains if d in wanted_domains]
            if known:
                groups = reporting.groups_from_scl(scl_ied, known)
                print(f"[Stream {cfg.id}] {len(groups)} report control block(s) of {scl_ied.name} from {cfg.scl}")
                return groups
            print(
                f"[Stream {cfg.id}] {cfg.scl} describes {scl_ied.name} ({_list(scl_ied.domains)}) but the IED at "
                f"{cfg.ied_host} has {_list(ied_domains)}: asking the IED instead"
            )
        groups: "list[reporting.RcbGroup]" = []
        for domain in wanted_domains:
            names = client.get_name_list(OBJECT_CLASS_NAMED_VARIABLE, domain)
            found = reporting.groups_from_names(domain, names)
            if found:
                print(f"[Stream {cfg.id}] {domain}: {len(found)} report control block(s) among {len(names)} names")
            groups += found
        return groups

    def _handle_report(
        self,
        runtime: SubscriptionRuntime,
        message: "pdu_types.InformationReport",
        data_sets: "Dict[str, reporting.DataSetInfo]",
    ) -> None:
        cfg = runtime.config
        if not is_report(message):
            _log_line(f"[Stream {cfg.id}] informationReport {message.variables}: {message.results}")
            return
        try:
            report = decode_report(message)
        except MmsError as e:
            _log_line(f"[Stream {cfg.id}] undecodable report: {e}")
            return
        now = time.time()
        runtime.total_reports += 1
        runtime.reports_since_log += 1
        if now - runtime.last_log_ts >= 60.0:
            _log_line(
                f"[Stream {cfg.id}] Status: {len(runtime.rcb_items)} RCB, {runtime.reports_since_log} "
                f"report(s) in the last {int(now - runtime.last_log_ts)} s."
            )
            runtime.reports_since_log = 0
            runtime.last_log_ts = now
        data_set = data_sets.get(report.data_set or "")
        if self._vm_url:
            push_lines(
                self._vm_url,
                reporting.report_to_lines(report, data_set),
                batch_interval_sec=self._vm_batch_ms / 1000.0 if self._vm_batch_ms > 0 else 0.0,
            )
        if _DEBUG_CONSOLE.get(cfg.id, False):
            for line in reporting.format_report(report, data_set):
                _log_line(line)


def _list(names: list[str], shown: int = 4) -> str:
    return ", ".join(names[:shown]) + (f" (+{len(names) - shown})" if len(names) > shown else "") if names else "none"


def load_scl_ied(cfg: SubscriptionConfig) -> "Optional[scl.SclIed]":
    """The IED of ``cfg.scl`` at ``cfg.ied_host`` (the only one of a CID), or None."""
    if not cfg.scl:
        return None
    try:
        ieds = scl.load_ieds(cfg.scl)
    except scl.SclError as e:
        print(f"[SCL] {e}")
        return None
    ied = scl.find_ied(ieds, cfg.ied_host)
    if ied is None:
        print(f"[SCL] {cfg.scl}: no IED at {cfg.ied_host} among {_list([i.name for i in ieds])}")
    elif ied.addresses and cfg.ied_host not in ied.addresses:
        print(f"[SCL] {cfg.scl}: {ied.name} is at {', '.join(ied.addresses)}, connecting to {cfg.ied_host}")
    return ied


def runtime_to_json(rt: SubscriptionRuntime) -> Dict[str, Any]:
    return {**config_to_json(rt.config), "last_error": rt.last_error, "rcb_items": list(rt.rcb_items)}


def load_rcb_list(path: Optional[str]) -> Optional[list]:
    """Block names or groups from a text file (one per line, # comments); None = every group."""
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            items = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    except OSError as e:
        print(f"[RCB] Cannot read {path}: {e}. Subscribing to every group.", flush=True)
        return None
    return items or None


def _log_line(msg: str) -> None:
    """Write to the real stdout (journalctl) and to the SSE log buffer."""
    global LOG_NEXT_SEQ
    sys.__stdout__.write(msg + "\n")
    sys.__stdout__.flush()
    with LOG_LOCK:
        LOG_NEXT_SEQ += 1
        LOG_LINES.append((LOG_NEXT_SEQ, msg))
        if len(LOG_LINES) > LOG_MAX:
            LOG_LINES.pop(0)
        LOG_CONDITION.notify_all()


def _json_error(handler: BaseHTTPRequestHandler, status: int, message: str) -> None:
    payload = {"error": message}
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class MMSServiceHandler(BaseHTTPRequestHandler):
    manager: SubscriptionManager  # injecté par le main()

    def _read_json(self) -> Tuple[Optional[dict], bool]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}, True
        try:
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                return None, False
            return data, True
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            return None, False

    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_logs_sse(self) -> None:
        """Flux SSE des logs en temps réel (seq pour fenêtre glissante)."""
        def escape_sse(s: str) -> str:
            return s.replace("\r", "").replace("\n", " ").replace("\x00", "")

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        last_sent_seq = 0
        while True:
            try:
                with LOG_LOCK:
                    for seq, line in LOG_LINES:
                        if seq > last_sent_seq:
                            self.wfile.write(f"data: {escape_sse(line)}\n\n".encode("utf-8"))
                            self.wfile.flush()
                            last_sent_seq = seq
                    LOG_CONDITION.wait(timeout=2.0)
                self.wfile.write(b": \n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                break

    def _serve_webui(self) -> None:
        """Sert la page webui.html (même répertoire que ce script)."""
        state_dir = os.path.dirname(os.path.abspath(__file__))
        ui_path = os.path.join(state_dir, "webui.html")
        try:
            with open(ui_path, "rb") as f:
                body = f.read()
        except OSError as e:
            self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
            self.end_headers()
            self.wfile.write(f"webui non trouvée: {e}".encode("utf-8"))
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if path == "/" or path == "/ui" or path == "/index.html":
            self._serve_webui()
            return
        if path == "/logs":
            self._serve_logs_sse()
            return
        if path == "/recents":
            recents = self.manager.get_recents()
            self._send_json(HTTPStatus.OK, recents)
            return
        if path == "/subscriptions":
            subs = [
                self._runtime_to_dict(rt)
                for rt in self.manager.list_subscriptions().values()
            ]
            self._send_json(HTTPStatus.OK, subs)
            return
        if path.startswith("/subscriptions/"):
            sub_id = path.split("/", 2)[2]
            rt = self.manager.get_subscription(sub_id)
            if not rt:
                _json_error(self, HTTPStatus.NOT_FOUND, f"subscription {sub_id!r} not found")
                return
            self._send_json(HTTPStatus.OK, self._runtime_to_dict(rt))
            return
        _json_error(self, HTTPStatus.NOT_FOUND, "unknown endpoint")

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/subscriptions":
            _json_error(self, HTTPStatus.NOT_FOUND, "unknown endpoint")
            return
        data, ok = self._read_json()
        if not ok or data is None:
            _json_error(self, HTTPStatus.BAD_REQUEST, "invalid JSON body")
            return
        try:
            cfg = config_from_json(data)
        except KeyError as e:
            _json_error(self, HTTPStatus.BAD_REQUEST, f"missing field: {e.args[0]}")
            return
        except (TypeError, ValueError) as e:
            _json_error(self, HTTPStatus.BAD_REQUEST, str(e))
            return
        try:
            rt = self.manager.create_subscription(cfg)
        except ValueError as e:
            _json_error(self, HTTPStatus.CONFLICT, str(e))
            return
        self._send_json(HTTPStatus.CREATED, self._runtime_to_dict(rt))

    def do_PUT(self) -> None:  # noqa: N802
        if not self.path.startswith("/subscriptions/"):
            _json_error(self, HTTPStatus.NOT_FOUND, "unknown endpoint")
            return
        sub_id = self.path.split("/", 2)[2]
        data, ok = self._read_json()
        if not ok or data is None:
            _json_error(self, HTTPStatus.BAD_REQUEST, "invalid JSON body")
            return
        # On accepte seulement les champs connus
        allowed_fields = set(CONFIG_FIELDS)
        update_fields: Dict[str, Any] = {}
        for k, v in data.items():
            if k not in allowed_fields:
                continue
            if k == "triggers" and v is not None:
                try:
                    reporting.parse_triggers(v)
                except ValueError as e:
                    _json_error(self, HTTPStatus.BAD_REQUEST, str(e))
                    return
            if k in ("ied_port", "integrity_ms") and v is not None:
                try:
                    v = int(v)
                except (TypeError, ValueError):
                    _json_error(self, HTTPStatus.BAD_REQUEST, f"invalid {k}")
                    return
            update_fields[k] = v
        try:
            rt = self.manager.update_subscription(sub_id, update_fields)
        except KeyError:
            _json_error(self, HTTPStatus.NOT_FOUND, f"subscription {sub_id!r} not found")
            return
        self._send_json(HTTPStatus.OK, self._runtime_to_dict(rt))

    def do_DELETE(self) -> None:  # noqa: N802
        if self.path == "/subscriptions":
            # Purge globale de tous les flux
            self.manager.purge_all()
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
            return
        if self.path.startswith("/subscriptions/"):
            sub_id = self.path.split("/", 2)[2]
            if not self.manager.get_subscription(sub_id):
                _json_error(self, HTTPStatus.NOT_FOUND, f"subscription {sub_id!r} not found")
                return
            self.manager.delete_subscription(sub_id)
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
            return
        _json_error(self, HTTPStatus.NOT_FOUND, "unknown endpoint")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        # Réduire le bruit des logs HTTP standard
        print(f"[HTTP] {self.address_string()} - {format % args}")

    @staticmethod
    def _runtime_to_dict(rt: SubscriptionRuntime) -> Dict[str, Any]:
        return runtime_to_json(rt)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Service HTTP pour gérer des subscriptions MMS (flux par domaine) et pousser vers VictoriaMetrics.",
    )
    parser.add_argument(
        "--listen-host",
        default="localhost",
        help="Adresse d'écoute HTTP (défaut: localhost).",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=7050,
        help="Port d'écoute HTTP (défaut: 7050).",
    )
    parser.add_argument(
        "--victoriametrics-url",
        metavar="URL",
        help="URL VictoriaMetrics (ex. http://localhost:8428). Si omis, seul le mode console debug sera disponible.",
    )
    parser.add_argument(
        "--vm-batch-ms",
        type=int,
        default=5000,
        help="Intervalle de batch VM en ms (défaut: 5000).",
    )
    args = parser.parse_args()

    manager = SubscriptionManager(vm_url=args.victoriametrics_url, vm_batch_ms=args.vm_batch_ms)
    MMSServiceHandler.manager = manager

    sys.stdout = _TeeStdout(sys.__stdout__)

    server_address = (args.listen_host, args.listen_port)
    httpd = ThreadingHTTPServer(server_address, MMSServiceHandler)
    print(
        f"Service MMS démarré sur http://{args.listen_host}:{args.listen_port} "
        f"(VictoriaMetrics: {args.victoriametrics_url or 'désactivé'}, batch={args.vm_batch_ms}ms)"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[Interrupt] Arrêt du service MMS demandé par l'utilisateur.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

