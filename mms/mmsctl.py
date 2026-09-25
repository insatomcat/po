# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Command line for the MMS subscription service (HTTP API of mms_service.py).

    python3 mms/mmsctl.py create --id s1 --ied-host 192.0.2.10 --rcb-filter "CB_LDPX_*" --debug
    python3 mms/mmsctl.py list
    python3 mms/mmsctl.py get s1
    python3 mms/mmsctl.py update s1 --triggers dchg,qchg,gi --no-debug
    python3 mms/mmsctl.py delete s1

--api-url defaults to the unified service (http://localhost:7050, /api/mms
prefix); add --standalone for a standalone mms_service.py.
"""

from __future__ import annotations

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
    """Send one HTTP request and return (status, body_text)."""
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
        print(f"Network error for {url}: {e}", file=sys.stderr)
        return 0, ""


def _api_base(base: str, suffix: str, unified: bool) -> str:
    """Add the /api/mms prefix for the unified service."""
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
        print(f"Error {status}: {body}", file=sys.stderr)
        return 1
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        print(body)
        return 0
    if not data:
        print("No subscription.")
        return 0
    for sub in data:
        sid = sub.get("id")
        domain = sub.get("domain")
        host = sub.get("ied_host")
        port = sub.get("ied_port")
        debug = sub.get("debug")
        print(f"- {sid}: {domain or 'all domains'} @ {host}:{port}  debug={debug}")
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    base = args.api_url.rstrip("/")
    url = _api_base(base, f"/subscriptions/{urllib.parse.quote(args.id)}", getattr(args, "unified", True))
    status, body = _http_request("GET", url)
    if status == 0:
        return 1
    if status == 404:
        print(f"Subscription {args.id!r} not found.", file=sys.stderr)
        return 1
    if status != 200:
        print(f"Error {status}: {body}", file=sys.stderr)
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
    }
    if args.domain:
        payload["domain"] = args.domain
    if args.rcb_filter:
        payload["rcb_filter"] = args.rcb_filter
    if args.id:
        payload["id"] = args.id
    if args.scl:
        payload["scl"] = args.scl
    if args.rcb_list:
        payload["rcb_list"] = args.rcb_list
    if args.triggers:
        payload["triggers"] = args.triggers
    if args.integrity_ms:
        payload["integrity_ms"] = args.integrity_ms
    if args.debug is not None:
        payload["debug"] = args.debug
    status, body = _http_request("POST", url, json_body=payload)
    if status == 0:
        return 1
    if status not in (200, 201):
        print(f"Error {status}: {body}", file=sys.stderr)
        return 1
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        print(body)
        return 0
    print("Subscription created:")
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
    if args.rcb_filter is not None:
        payload["rcb_filter"] = args.rcb_filter
    if args.triggers is not None:
        payload["triggers"] = args.triggers
    if args.integrity_ms is not None:
        payload["integrity_ms"] = args.integrity_ms
    if args.debug is not None:
        payload["debug"] = args.debug
    if not payload:
        print("Nothing to update (use --ied-host/--ied-port/--domain/--scl/--rcb-filter/--rcb-list/--triggers/--integrity-ms/--debug/--no-debug).")
        return 1
    status, body = _http_request("PUT", url, json_body=payload)
    if status == 0:
        return 1
    if status == 404:
        print(f"Subscription {args.id!r} not found.", file=sys.stderr)
        return 1
    if status != 200:
        print(f"Error {status}: {body}", file=sys.stderr)
        return 1
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        print(body)
        return 0
    print("Subscription updated:")
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    base = args.api_url.rstrip("/")
    url = _api_base(base, f"/subscriptions/{urllib.parse.quote(args.id)}", getattr(args, "unified", True))
    status, body = _http_request("DELETE", url)
    if status == 0:
        return 1
    if status == 404:
        print(f"Subscription {args.id!r} not found.", file=sys.stderr)
        return 1
    if status not in (200, 204):
        print(f"Error {status}: {body}", file=sys.stderr)
        return 1
    print(f"Subscription {args.id!r} deleted.")
    return 0


def cmd_purge(args: argparse.Namespace) -> int:
    """Delete every subscription of the service (DELETE /subscriptions)."""
    base = args.api_url.rstrip("/")
    url = _api_base(base, "/subscriptions", getattr(args, "unified", True))
    status, body = _http_request("DELETE", url)
    if status == 0:
        return 1
    if status not in (200, 204):
        print(f"Error {status}: {body}", file=sys.stderr)
        return 1
    print("Every subscription was deleted.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage the subscriptions of the MMS service.",
    )
    parser.add_argument(
        "--api-url",
        default=_default_api_url(),
        help=f"API base URL (default {_default_api_url()}).",
    )
    parser.add_argument(
        "--unified",
        action="store_true",
        default=True,
        help="Use the /api/mms prefix (unified service, default).",
    )
    parser.add_argument(
        "--standalone",
        dest="unified",
        action="store_false",
        help="Standalone MMS service (no /api/mms prefix).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # list
    p_list = sub.add_parser("list", help="List every subscription.")
    p_list.set_defaults(func=cmd_list)

    # get
    p_get = sub.add_parser("get", help="Show one subscription.")
    p_get.add_argument("id", help="Subscription id.")
    p_get.set_defaults(func=cmd_get)

    # create
    p_create = sub.add_parser("create", help="Create a subscription.")
    p_create.add_argument("--id", help="Subscription id (generated by the service when omitted).")
    p_create.add_argument("--ied-host", required=True, help="IED address or host name.")
    p_create.add_argument("--ied-port", type=int, default=102, help="MMS port (default 102).")
    p_create.add_argument("--domain", help="One logical device (MMS domain); default: every one of the IED.")
    p_create.add_argument("--scl", help="CID/SCD of the IED: block names without asking the IED.")
    p_create.add_argument("--rcb-filter", help='Blocks to subscribe to, e.g. "CB_LDPX_*, CB_LDADD_*" (default: all).')
    p_create.add_argument("--rcb-list", help="File listing the RCBs (older than --rcb-filter).")
    p_create.add_argument("--triggers", help="Trigger options: dchg,qchg,dupd,integrity,gi (default integrity,gi).")
    p_create.add_argument("--integrity-ms", type=int, help="Integrity period in ms (default 2000).")
    dbg = p_create.add_mutually_exclusive_group()
    dbg.add_argument("--debug", dest="debug", action="store_true", help="Enable debug output (reports in the log).")
    dbg.add_argument("--no-debug", dest="debug", action="store_false", help="Disable debug output.")
    p_create.set_defaults(func=cmd_create, debug=None)

    # update
    p_update = sub.add_parser("update", help="Change a subscription.")
    p_update.add_argument("id", help="Id of the subscription to change.")
    p_update.add_argument("--ied-host", help="New IED address or host name.")
    p_update.add_argument("--ied-port", type=int, help="New MMS port.")
    p_update.add_argument("--domain", help="New MMS domain (logical device).")
    p_update.add_argument("--scl", help="New SCL/ICD file (empty string to drop it).")
    p_update.add_argument("--rcb-filter", help='New block filter ("" for every block).')
    p_update.add_argument("--rcb-list", help="New RCB list file (empty string to drop it).")
    p_update.add_argument("--triggers", help="Trigger options: dchg,qchg,dupd,integrity,gi.")
    p_update.add_argument("--integrity-ms", type=int, help="Integrity period in ms.")
    dbg2 = p_update.add_mutually_exclusive_group()
    dbg2.add_argument("--debug", dest="debug", action="store_true", help="Enable debug output (reports in the log).")
    dbg2.add_argument("--no-debug", dest="debug", action="store_false", help="Disable debug output.")
    p_update.set_defaults(func=cmd_update, debug=None)

    # delete
    p_delete = sub.add_parser("delete", help="Delete a subscription.")
    p_delete.add_argument("id", help="Id of the subscription to delete.")
    p_delete.set_defaults(func=cmd_delete)

    # purge
    p_purge = sub.add_parser("purge", help="Delete every subscription.")
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

