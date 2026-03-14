from __future__ import annotations

"""
CLI pour piloter le service MMS HTTP.

Ce programme convertit des commandes utilisateur en appels HTTP vers l'API
exposée par `mms_service.py` :

  - Créer un flux :
        python3 mmsctl.py create \
            --api-url http://127.0.0.1:8080 \
            --id flux-1 \
            --ied-host 10.132.159.191 \
            --ied-port 102 \
            --domain VMC7_1LD0 \
            --scl /chemin/ied.icd \
            --rcb-list /chemin/rcb.txt \
            --debug

  - Lister les flux :
        python3 mmsctl.py list --api-url http://127.0.0.1:8080

  - Afficher un flux :
        python3 mmsctl.py get flux-1 --api-url http://127.0.0.1:8080

  - Mettre à jour un flux (ex. changer la rcb-list et le debug) :
        python3 mmsctl.py update flux-1 \
            --api-url http://127.0.0.1:8080 \
            --rcb-list /nouveau/rcb.txt \
            --debug/--no-debug

  - Supprimer un flux :
        python3 mmsctl.py delete flux-1 --api-url http://127.0.0.1:8080
"""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict


def _default_api_url() -> str:
    return "http://localhost:7050"


def _http_request(
    method: str,
    url: str,
    *,
    json_body: Dict[str, Any] | None = None,
) -> tuple[int, str]:
    """Envoie une requête HTTP simple et renvoie (status, body_text)."""
    data = None
    headers = {}
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = getattr(resp, "status", 200)
            body = resp.read().decode("utf-8", errors="replace")
            return status, body
    except urllib.error.HTTPError as e:  # pragma: no cover - simple log
        body = e.read().decode("utf-8", errors="replace")
        return e.code, body
    except urllib.error.URLError as e:
        print(f"Erreur réseau vers {url}: {e}", file=sys.stderr)
        return 0, ""


def _api_base(base: str, suffix: str, unified: bool) -> str:
    """Préfixe /api/mms si service unifié."""
    u = base.rstrip("/")
    if unified:
        return f"{u}/api/mms{suffix}"
    return f"{u}{suffix}"


def cmd_list(args: argparse.Namespace) -> int:
    base = args.api_url.rstrip("/")
    url = _api_base(base, "/subscriptions", getattr(args, "unified", True))
    status, body = _http_request("GET", url)
    if status == 0:
        return 1
    if status != 200:
        print(f"Erreur {status}: {body}", file=sys.stderr)
        return 1
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        print(body)
        return 0
    if not data:
        print("Aucun flux.")
        return 0
    for sub in data:
        sid = sub.get("id")
        domain = sub.get("domain")
        host = sub.get("ied_host")
        port = sub.get("ied_port")
        status_txt = sub.get("status")
        debug = sub.get("debug")
        print(f"- {sid}: {domain} @ {host}:{port}  status={status_txt}  debug={debug}")
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    base = args.api_url.rstrip("/")
    url = _api_base(base, f"/subscriptions/{urllib.parse.quote(args.id)}", getattr(args, "unified", True))
    status, body = _http_request("GET", url)
    if status == 0:
        return 1
    if status == 404:
        print(f"Flux {args.id!r} introuvable.", file=sys.stderr)
        return 1
    if status != 200:
        print(f"Erreur {status}: {body}", file=sys.stderr)
        return 1
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        print(body)
        return 0
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return 0


def cmd_create(args: argparse.Namespace) -> int:
    base = args.api_url.rstrip("/")
    url = _api_base(base, "/subscriptions", getattr(args, "unified", True))
    payload: Dict[str, Any] = {
        "ied_host": args.ied_host,
        "ied_port": args.ied_port,
        "domain": args.domain,
    }
    if args.id:
        payload["id"] = args.id
    if args.scl:
        payload["scl"] = args.scl
    if args.rcb_list:
        payload["rcb_list"] = args.rcb_list
    if args.debug is not None:
        payload["debug"] = args.debug
    status, body = _http_request("POST", url, json_body=payload)
    if status == 0:
        return 1
    if status not in (200, 201):
        print(f"Erreur {status}: {body}", file=sys.stderr)
        return 1
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        print(body)
        return 0
    print("Flux créé:")
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    base = args.api_url.rstrip("/")
    url = _api_base(base, f"/subscriptions/{urllib.parse.quote(args.id)}", getattr(args, "unified", True))
    payload: Dict[str, Any] = {}
    if args.ied_host:
        payload["ied_host"] = args.ied_host
    if args.ied_port is not None:
        payload["ied_port"] = args.ied_port
    if args.domain:
        payload["domain"] = args.domain
    if args.scl is not None:
        payload["scl"] = args.scl
    if args.rcb_list is not None:
        payload["rcb_list"] = args.rcb_list
    if args.debug is not None:
        payload["debug"] = args.debug
    if not payload:
        print("Aucune option à mettre à jour (utiliser --ied-host/--ied-port/--domain/--scl/--rcb-list/--debug/--no-debug).")
        return 1
    status, body = _http_request("PUT", url, json_body=payload)
    if status == 0:
        return 1
    if status == 404:
        print(f"Flux {args.id!r} introuvable.", file=sys.stderr)
        return 1
    if status != 200:
        print(f"Erreur {status}: {body}", file=sys.stderr)
        return 1
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        print(body)
        return 0
    print("Flux mis à jour:")
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    base = args.api_url.rstrip("/")
    url = _api_base(base, f"/subscriptions/{urllib.parse.quote(args.id)}", getattr(args, "unified", True))
    status, body = _http_request("DELETE", url)
    if status == 0:
        return 1
    if status == 404:
        print(f"Flux {args.id!r} introuvable.", file=sys.stderr)
        return 1
    if status not in (200, 204):
        print(f"Erreur {status}: {body}", file=sys.stderr)
        return 1
    print(f"Flux {args.id!r} supprimé.")
    return 0


def cmd_purge(args: argparse.Namespace) -> int:
    """Supprime tous les flux côté service (DELETE /subscriptions)."""
    base = args.api_url.rstrip("/")
    url = _api_base(base, "/subscriptions", getattr(args, "unified", True))
    status, body = _http_request("DELETE", url)
    if status == 0:
        return 1
    if status not in (200, 204):
        print(f"Erreur {status}: {body}", file=sys.stderr)
        return 1
    print("Tous les flux ont été supprimés.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CLI pour gérer les flux MMS d'un service mms_service.py.",
    )
    parser.add_argument(
        "--api-url",
        default=_default_api_url(),
        help=f"URL de base de l'API (défaut: {_default_api_url()}).",
    )
    parser.add_argument(
        "--unified",
        action="store_true",
        default=True,
        help="Utiliser le préfixe /api/mms (service unifié, défaut).",
    )
    parser.add_argument(
        "--standalone",
        dest="unified",
        action="store_false",
        help="Service MMS standalone (sans préfixe /api/mms).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # list
    p_list = sub.add_parser("list", help="Lister tous les flux.")
    p_list.set_defaults(func=cmd_list)

    # get
    p_get = sub.add_parser("get", help="Afficher le détail d'un flux.")
    p_get.add_argument("id", help="Identifiant du flux.")
    p_get.set_defaults(func=cmd_get)

    # create
    p_create = sub.add_parser("create", help="Créer un nouveau flux.")
    p_create.add_argument("--id", help="Identifiant du flux (sinon généré côté service).")
    p_create.add_argument("--ied-host", required=True, help="IP/hostname de l'IED.")
    p_create.add_argument("--ied-port", type=int, default=102, help="Port MMS (défaut: 102).")
    p_create.add_argument("--domain", required=True, help="Domain ID MMS (LD).")
    p_create.add_argument("--scl", help="Chemin du fichier SCL/ICD.")
    p_create.add_argument("--rcb-list", help="Chemin du fichier listant les RCB.")
    dbg = p_create.add_mutually_exclusive_group()
    dbg.add_argument("--debug", dest="debug", action="store_true", help="Activer le mode debug (affichage console).")
    dbg.add_argument("--no-debug", dest="debug", action="store_false", help="Désactiver le mode debug.")
    p_create.set_defaults(func=cmd_create, debug=None)

    # update
    p_update = sub.add_parser("update", help="Mettre à jour un flux existant.")
    p_update.add_argument("id", help="Identifiant du flux à modifier.")
    p_update.add_argument("--ied-host", help="Nouvelle IP/hostname de l'IED.")
    p_update.add_argument("--ied-port", type=int, help="Nouveau port MMS.")
    p_update.add_argument("--domain", help="Nouveau Domain ID MMS (LD).")
    p_update.add_argument("--scl", help="Nouveau chemin du fichier SCL/ICD (utiliser chaîne vide pour le désactiver).")
    p_update.add_argument("--rcb-list", help="Nouveau chemin du fichier RCB (utiliser chaîne vide pour revenir par défaut).")
    dbg2 = p_update.add_mutually_exclusive_group()
    dbg2.add_argument("--debug", dest="debug", action="store_true", help="Activer le mode debug (affichage console).")
    dbg2.add_argument("--no-debug", dest="debug", action="store_false", help="Désactiver le mode debug.")
    p_update.set_defaults(func=cmd_update, debug=None)

    # delete
    p_delete = sub.add_parser("delete", help="Supprimer un flux.")
    p_delete.add_argument("id", help="Identifiant du flux à supprimer.")
    p_delete.set_defaults(func=cmd_delete)

    # purge
    p_purge = sub.add_parser("purge", help="Supprimer tous les flux.")
    p_purge.set_defaults(func=cmd_purge)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 1
    return int(func(args))  # type: ignore[call-arg]


if __name__ == "__main__":
    raise SystemExit(main())

