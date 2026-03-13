from __future__ import annotations

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

API HTTP (JSON, état persistant dans mms_subscriptions.json):

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
            "status": "running" | "stopped" | "error",
            "last_error": "..." | null
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
"""

import argparse
import errno
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, asdict
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Dict, Optional, Any, Tuple

from mms_reports_client import MMSReportsClient, MMSConnectionError
from scl_parser import parse_scl_data_set_members_with_components
from mms_report_processing import (
    DATA_SET_MEMBER_LABELS,
    DATA_SET_MEMBER_COMPONENTS,
    load_item_ids_from_file,
    process_mms_report,
)


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
    status: str = "stopped"  # "running" | "stopped" | "error"
    last_error: Optional[str] = None
    thread: Optional[threading.Thread] = None
    stop_event: threading.Event = threading.Event()
    client: Optional[MMSReportsClient] = None
    total_reports: int = 0
    reports_since_log: int = 0
    last_log_ts: float = 0.0


class SubscriptionManager:
    """Gestion centralisée des flux (in‑memory avec persistance sur disque)."""

    _STATE_FILE = "mms_subscriptions.json"

    def __init__(self, vm_url: Optional[str], vm_batch_ms: int) -> None:
        self._subs: Dict[str, SubscriptionRuntime] = {}
        self._lock = threading.Lock()
        self._vm_url = vm_url
        self._vm_batch_ms = vm_batch_ms
        self._state_path = os.path.join(os.getcwd(), self._STATE_FILE)
        self._load_state()

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
            runtime = SubscriptionRuntime(config=cfg)
            self._subs[cfg.id] = runtime
            self._save_state_locked()
        self._start_subscription_thread(runtime)
        return runtime

    def update_subscription(self, sub_id: str, new_fields: Dict[str, Any]) -> SubscriptionRuntime:
        with self._lock:
            runtime = self._subs.get(sub_id)
            if not runtime:
                raise KeyError(sub_id)
            # Cas 1 : mise à jour uniquement du flag debug → pas besoin de redémarrer le flux
            only_debug = all(
                (k == "debug") or (v is None)
                for k, v in new_fields.items()
            )
            if only_debug and "debug" in new_fields and new_fields["debug"] is not None:
                runtime.config.debug = bool(new_fields["debug"])
                self._save_state_locked()
                return runtime

            # Cas 2 : modification de la connectivité (host, port, domain, scl, rcb_list, etc.)
            # → reconstruire la config et redémarrer le thread.
            data = asdict(runtime.config)
            data.update({k: v for k, v in new_fields.items() if v is not None})
            cfg = SubscriptionConfig(**data)
            runtime.config = cfg
            # Arrêter le thread courant
            self._stop_runtime_locked(runtime)
            self._save_state_locked()
        # (re)lancer en dehors du lock
        self._start_subscription_thread(runtime)
        return runtime

    def delete_subscription(self, sub_id: str) -> None:
        with self._lock:
            runtime = self._subs.pop(sub_id, None)
            self._save_state_locked()
        if runtime:
            self._stop_runtime(runtime)

    def purge_all(self) -> None:
        """Supprime tous les flux (arrêt de tous les threads + reset du fichier de conf)."""
        with self._lock:
            runtimes = list(self._subs.values())
            self._subs.clear()
            self._save_state_locked()
        for rt in runtimes:
            self._stop_runtime(rt)

    # --- gestion des threads ---

    def _start_subscription_thread(self, runtime: SubscriptionRuntime) -> None:
        runtime.stop_event = threading.Event()
        runtime.status = "running"
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
            rt = SubscriptionRuntime(config=cfg)
            self._subs[cfg.id] = rt
        if self._subs:
            print(f"[State] {len(self._subs)} flux rechargés depuis {self._state_path}.")
            # Démarrer les threads après reconstruction des runtimes
            for rt in list(self._subs.values()):
                self._start_subscription_thread(rt)

    def _save_state_locked(self) -> None:
        """Sauvegarde la configuration des flux dans un fichier JSON (lock déjà tenu)."""
        try:
            data = [asdict(rt.config) for rt in self._subs.values()]
            tmp_path = self._state_path + ".tmp"
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
        runtime.status = "stopped"

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

                def callback(report: Any) -> None:
                    now = time.time()
                    runtime.total_reports += 1
                    runtime.reports_since_log += 1
                    # Log périodique (~1 min) du statut du flux
                    if now - runtime.last_log_ts >= 60.0:
                        print(
                            f"[Flux {cfg.id}] Statut: {len(item_ids)} RCB abonnés, "
                            f"{runtime.reports_since_log} report(s) reçu(s) sur les "
                            f"{int(now - runtime.last_log_ts)} dernières secondes.",
                            flush=True,
                        )
                        runtime.reports_since_log = 0
                        runtime.last_log_ts = now
                    process_mms_report(
                        report,
                        vm_url=vm_url,
                        show_in_console=cfg.debug,
                        verbose=False,
                        batch_interval_sec=batch_interval_sec,
                        batch_max_lines=500,
                        member_components=DATA_SET_MEMBER_COMPONENTS or None,
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
                runtime.status = "error"
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
                runtime.status = "error"
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

        runtime.status = "stopped"
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

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if self.path == "/subscriptions":
            subs = [
                self._runtime_to_dict(rt)
                for rt in self.manager.list_subscriptions().values()
            ]
            self._send_json(HTTPStatus.OK, subs)
            return
        if self.path.startswith("/subscriptions/"):
            sub_id = self.path.split("/", 2)[2]
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
            "status": rt.status,
            "last_error": rt.last_error,
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

