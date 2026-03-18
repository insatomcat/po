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
          "domain": "VMC7_1LD0",
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
import errno
import json
import os
import sys
import threading
from pathlib import Path
import time
import uuid
from dataclasses import dataclass, asdict, field
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Dict, Optional, Any, Tuple

from mms.mms_reports_client import MMSReportsClient, MMSConnectionError
from mms.scl_parser import parse_scl_data_set_members_with_components
from mms.mms_report_processing import (
    DATA_SET_MEMBER_LABELS,
    DATA_SET_MEMBER_COMPONENTS,
    load_item_ids_from_file,
    process_mms_report,
)

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
    domain: str
    scl: Optional[str] = None
    rcb_list: Optional[str] = None
    debug: bool = False


@dataclass
class SubscriptionRuntime:
    config: SubscriptionConfig
    last_error: Optional[str] = None
    thread: Optional[threading.Thread] = None
    stop_event: threading.Event = threading.Event()
    client: Optional[MMSReportsClient] = None
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
    position: str  # "open" | "closed" | "intermediate"


RECENTS_MAX = 20

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
            self._stop_runtime_locked(runtime)
            self._save_state_locked()
        t = runtime.thread
        if t and t.is_alive():
            t.join(timeout=5.0)
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

    def get_recents(self) -> list[Dict[str, Any]]:
        with self._lock:
            return list(self._recents)

    def _add_to_recents(self, runtime: SubscriptionRuntime) -> None:
        """Ajoute un flux aux récents (20 derniers uniques par id)."""
        cfg = runtime.config
        entry = {
            "id": cfg.id,
            "ied_host": cfg.ied_host,
            "ied_port": cfg.ied_port,
            "domain": cfg.domain,
            "scl": cfg.scl,
            "rcb_list": cfg.rcb_list,
            "debug": cfg.debug,
            "rcb_items": list(runtime.rcb_items),
        }
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

    def send_command(self, cmd_id: str) -> str:
        """
        Envoie la commande MMS configurée et retourne la réponse brute en hex.
        """
        with self._lock:
            cfg = self._commands.get(cmd_id)
        if not cfg:
            raise KeyError(cmd_id)

        from mms.mms_commands_codec import encode_pos_oper_write
        from mms.mms_reports_client import MMSReportsClient

        client = MMSReportsClient(cfg.ied_host, cfg.ied_port, timeout=5.0, debug=False)
        try:
            client.connect()

            expected_item = cfg.item.encode("ascii", errors="ignore")
            expected_obj = f"{cfg.domain}/{cfg.item}".encode("ascii", errors="ignore")

            def _extract_error_addcause(resp_bytes: bytes) -> tuple[int | None, int | None]:
                if b"LastApplError" not in resp_bytes:
                    return None, None
                start = resp_bytes.find(b"LastApplError")
                window = resp_bytes[start:]
                vals: list[int] = []
                for i in range(len(window) - 2):
                    if window[i] == 0x85 and window[i + 1] == 0x01:
                        vals.append(window[i + 2])
                # error (ControlLastApplError) est dans {0,1,2,3}
                err_candidates = [v for v in vals if v in (0, 1, 2, 3)]
                error = err_candidates[-1] if err_candidates else None
                # addCause est souvent le seul autre entier "significatif"
                non_err = [v for v in vals if v not in (0, 1, 2, 3)]
                addCause = non_err[0] if non_err else (vals[-1] if vals else None)
                return error, addCause

            # addCause IEC 61850 → libellé court pour les logs
            _ADDCAUSE_LABELS: dict[int, str] = {
                0: "unknown", 1: "not-supported", 2: "blocked-by-switching-hierarchy",
                3: "select-failed", 4: "invalid-position", 5: "position-reached",
                6: "param-chg-in-execution", 7: "step-limit", 8: "blocked-by-interlocking",
                9: "blocked-by-synchrocheck", 10: "command-already-in-execution",
                11: "blocked-by-health", 12: "1-of-n-control",
            }

            def _log_step_response(step: str, resp: bytes) -> None:
                """Loggue la réponse d'une étape avec addCause décodé."""
                e2, ac = _extract_error_addcause(resp)
                ac_label = _ADDCAUSE_LABELS.get(ac, str(ac)) if ac is not None else "n/a"
                # a0 4e / a0 03 = failure dans write-response ; a1 = success
                if b"\xa0\x4e" in resp or b"\xa0\x03" in resp:
                    status = "FAILURE"
                elif b"\xa1" in resp:
                    status = "success"
                else:
                    status = "?"
                print(
                    f"[MMS-CMD] {step} response status={status} error={e2} "
                    f"addCause={ac} ({ac_label}) hex={resp.hex()}",
                    flush=True,
                )

            def _send_three_step_sequence() -> bytes:
                # Protocole validé terrain :
                # L'IED s'attend à UN SEUL PDU Oper par commande (direct-with-enhanced-security).
                # ctlNum=0 → ouvre ; ctlNum=1 → ferme.
                # Envoyer step2 après open (ctlNum=1) déclenche une FERMETURE immédiate.
                # → open  : 1 seul PDU (step1 ctlNum=0), pas de step2 ni step3.
                # → close : 1 PDU Oper (step1 ctlNum=1) + step3 execute pour compléter la séquence.

                pdu1 = encode_pos_oper_write(  # type: ignore[arg-type]
                    domain_id=cfg.domain,
                    item_id=cfg.item,
                    position=cfg.position,
                    step="step1",
                )
                print(
                    f"[MMS-CMD] send oper position={cfg.position} domain={cfg.domain} item={cfg.item} "
                    f"pdu_len={len(pdu1)} pdu_hex={pdu1.hex()}",
                    flush=True,
                )
                resp1 = client.send_confirmed_pdu_and_wait(pdu1)
                _log_step_response("oper", resp1)

                if cfg.position == "open":
                    # Un seul PDU suffit pour l'ouverture.
                    print("[MMS-CMD] open: séquence complète (1 seul PDU Oper)", flush=True)
                    return resp1

                # closed : step3 execute requis pour déclencher la CommandTermination finale
                time.sleep(0.01)
                resp3 = resp1
                try:
                    from mms.mms_commands_codec import encode_pos_oper_execute_step3

                    pdu3 = encode_pos_oper_execute_step3(
                        domain_id=cfg.domain,
                        item_id=cfg.item,
                        position=cfg.position,
                    )
                    print(
                        f"[MMS-CMD] send step3(execute) position={cfg.position} "
                        f"domain={cfg.domain} item={cfg.item} pdu_len={len(pdu3)} pdu_hex={pdu3.hex()}",
                        flush=True,
                    )
                    client.send_confirmed_pdu(pdu3)
                    try:
                        resp3 = client.recv_until_contains(
                            substrings=(b"LastApplError", expected_item, expected_obj),
                            timeout_total=4.5,
                            per_read_timeout=0.5,
                            stop_on_first=False,
                        )
                    except TypeError:
                        resp3 = client.recv_until_contains(
                            substrings=(b"LastApplError", expected_item, expected_obj),
                            timeout_total=4.5,
                            per_read_timeout=0.5,
                        )
                except Exception as e:
                    print(f"[MMS-CMD] step3 skipped due to: {e}", flush=True)

                return resp3

            resp2 = _send_three_step_sequence()
            err, addCause = _extract_error_addcause(resp2)

            if addCause == 12:
                # Commande déjà en exécution :
                # - on évite de rejouer immédiatement sur la même association,
                # - on laisse une fenêtre plus longue à l'IED pour libérer l'état.
                print(
                    "[MMS-CMD] addCause=12 (COMMAND_ALREADY_IN_EXECUTION). "
                    "Retry after reconnect and longer delay…",
                    flush=True,
                )
                try:
                    client.close()
                except Exception:
                    pass
                time.sleep(8.0)
                client.connect()
                resp2 = _send_three_step_sequence()

            resp_hex = resp2.hex()
            ac_label = _ADDCAUSE_LABELS.get(addCause, str(addCause)) if addCause is not None else "n/a"
            print(
                f"[MMS-CMD] final response error={err} addCause={addCause} ({ac_label}) "
                f"response_hex={resp_hex}",
                flush=True,
            )
            return resp_hex
        finally:
            try:
                client.close()
            except Exception:
                pass

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
            except Exception:
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
        runtime.stop_event.set()
        client = runtime.client
        if client is not None:
            try:
                client.close()
            except Exception:
                pass

    def _stop_runtime(self, runtime: SubscriptionRuntime) -> None:
        self._stop_runtime_locked(runtime)
        t = runtime.thread
        if t and t.is_alive():
            t.join(timeout=5.0)

    def _subscription_worker(self, runtime: SubscriptionRuntime) -> None:
        """Boucle de (re)connexion pour un flux, très proche de test_client_reports.main()."""
        cfg = runtime.config

        # Charger le SCL (optionnel) pour renseigner les labels des DataSet
        if cfg.scl:
            try:
                parsed, comp, enums = parse_scl_data_set_members_with_components(cfg.scl)
                # On met à jour les mappings globaux (partagés) – adapté aux cas usuels
                DATA_SET_MEMBER_LABELS.update(parsed)
                for k, v in comp.items():
                    DATA_SET_MEMBER_COMPONENTS.setdefault(k, {}).update(v)
                # enums n'est pas utilisé ici, mais conservé pour compat future
                _ = enums
                print(f"[SCL] {len(parsed)} data set(s) chargé(s) depuis {cfg.scl}")
            except Exception as e:
                print(f"[SCL] Erreur lors du chargement de {cfg.scl}: {e}")

        item_ids = load_item_ids_from_file(cfg.rcb_list)
        runtime.rcb_items = list(item_ids)
        print(
            f"[RCB] Flux {cfg.id}: {len(item_ids)} RCB à activer "
            f"(source: {'fichier' if cfg.rcb_list else 'liste intégrée'})"
        )

        reconnect_delay_sec = 5.0
        vm_url = self._vm_url
        batch_interval_sec = self._vm_batch_ms / 1000.0 if self._vm_batch_ms > 0 else 0.0

        while not runtime.stop_event.is_set():
            client = MMSReportsClient(cfg.ied_host, cfg.ied_port, debug=False)
            runtime.client = client
            try:
                print(f"[MMS] Flux {cfg.id}: connexion à {cfg.ied_host}:{cfg.ied_port} ...")
                client.connect()
                print("[MMS] Connexion établie. Activation des RCB...")

                def _log(msg: str) -> None:
                    """Écrit vers journalctl (stdout) + LOG_LINES (fenêtre logs web UI)."""
                    sys.__stdout__.write(msg + "\n")
                    sys.__stdout__.flush()
                    with LOG_LOCK:
                        global LOG_NEXT_SEQ
                        LOG_NEXT_SEQ += 1
                        LOG_LINES.append((LOG_NEXT_SEQ, msg))
                        if len(LOG_LINES) > LOG_MAX:
                            LOG_LINES.pop(0)
                        LOG_CONDITION.notify_all()

                class _LogStream:
                    """Stream qui écrit vers stdout + LOG_LINES (pour reports debug dans web UI)."""

                    def __init__(self) -> None:
                        self._buf = ""

                    def write(self, s: str) -> None:
                        self._buf += s
                        while "\n" in self._buf:
                            line, self._buf = self._buf.split("\n", 1)
                            _log(line)

                    def flush(self) -> None:
                        if self._buf:
                            _log(self._buf)
                            self._buf = ""
                        sys.__stdout__.flush()

                _log_stream = _LogStream()

                def callback(report: Any) -> None:
                    now = time.time()
                    runtime.total_reports += 1
                    runtime.reports_since_log += 1
                    if now - runtime.last_log_ts >= 60.0:
                        _log(
                            f"[Flux {cfg.id}] Statut: {len(item_ids)} RCB abonnés, "
                            f"{runtime.reports_since_log} report(s) reçu(s) sur les "
                            f"{int(now - runtime.last_log_ts)} dernières secondes."
                        )
                        runtime.reports_since_log = 0
                        runtime.last_log_ts = now
                    show_console = _DEBUG_CONSOLE.get(cfg.id, False)
                    process_mms_report(
                        report,
                        vm_url=vm_url,
                        show_in_console=show_console,
                        verbose=False,
                        batch_interval_sec=batch_interval_sec,
                        batch_max_lines=500,
                        member_components=DATA_SET_MEMBER_COMPONENTS or None,
                        console_out=_log_stream,
                    )

                for i, item_id in enumerate(item_ids, 1):
                    if runtime.stop_event.is_set():
                        break
                    print(f"[Flux {cfg.id}] Abonnement [{i}/{len(item_ids)}] {cfg.domain}/{item_id} ...")
                    client.enable_reporting(cfg.domain, item_id, report_callback=callback)

                if runtime.stop_event.is_set():
                    break

                print(
                    f"[Flux {cfg.id}] {len(item_ids)} RCB abonnés. En attente de reports..."
                )

                # Boucle bloquante jusqu'à perte de connexion ou arrêt
                client.loop_reports(callback, quiet_heartbeat=True)

                if runtime.stop_event.is_set():
                    break
                print(f"[Flux {cfg.id}] Connexion fermée par l'IED. Tentative de reconnexion...")

            except MMSConnectionError as e:
                if runtime.stop_event.is_set():
                    # Arrêt demandé pendant une opération MMS : on sort proprement.
                    break
                runtime.last_error = str(e)
                print(f"[MMS] Flux {cfg.id}: erreur de connexion ou de protocole : {e}")
                print(f"[MMS] Flux {cfg.id}: nouvelle tentative dans {reconnect_delay_sec} s...")
            except Exception as e:
                # Cas fréquent : socket fermé pendant un arrêt → EBADF, qu'on ne logue pas comme erreur.
                if isinstance(e, OSError) and getattr(e, "errno", None) == errno.EBADF:
                    break
                if runtime.stop_event.is_set():
                    # Erreur liée probablement à la fermeture du socket lors d'un arrêt demandé
                    break
                runtime.last_error = str(e)
                print(f"[Flux {cfg.id}] Erreur inattendue: {e}")
            finally:
                try:
                    client.close()
                except Exception:
                    pass
                runtime.client = None

            if runtime.stop_event.is_set():
                break

            # Attente avant reconnexion
            for _ in range(int(reconnect_delay_sec * 10)):
                if runtime.stop_event.is_set():
                    break
                time.sleep(0.1)

        print(f"[Flux {cfg.id}] Arrêt du thread de subscription.")


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
        except Exception:
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
            sub_id = data.get("id") or uuid.uuid4().hex
            ied_host = data["ied_host"]
            ied_port = int(data.get("ied_port", 102))
            domain = data["domain"]
        except KeyError as e:
            _json_error(self, HTTPStatus.BAD_REQUEST, f"missing field: {e.args[0]}")
            return
        except (TypeError, ValueError):
            _json_error(self, HTTPStatus.BAD_REQUEST, "invalid ied_port")
            return

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
        allowed_fields = {"ied_host", "ied_port", "domain", "scl", "rcb_list", "debug"}
        update_fields: Dict[str, Any] = {}
        for k, v in data.items():
            if k not in allowed_fields:
                continue
            if k == "ied_port" and v is not None:
                try:
                    v = int(v)
                except (TypeError, ValueError):
                    _json_error(self, HTTPStatus.BAD_REQUEST, "invalid ied_port")
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

