#!/usr/bin/env python3
# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Command line for the GOOSE service: turns arguments into API requests."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.request
from urllib.parse import urlparse
from typing import Any, List

ROOT = pathlib.Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _unescape_string_literal(v: str) -> str:
    r"""
    Lets the command line carry escapes like '\\x00', turned into the real
    bytes (NUL here).
    """
    if len(v) == 4 and v[0] == "\\" and v[1] == "x":
        try:
            return bytes([int(v[2:], 16)]).decode("latin1")
        except ValueError:
            pass
    if len(v) == 5 and v[0] == "\\" and v[1] == "\\" and v[2] == "x":
        try:
            return bytes([int(v[3:], 16)]).decode("latin1")
        except ValueError:
            pass
    try:
        return v.encode("utf-8").decode("unicode_escape")
    except Exception:
        return v


def _parse_values(values: List[str]) -> List[Any]:
    """Parse --value TYPE:VAL into an all_data list (Python, JSON serialisable)."""
    all_data: List[Any] = []
    for raw in values:
        if ":" not in raw:
            raise ValueError(f"invalid --value: {raw!r}")
        type_prefix, val = raw.split(":", 1)
        t = type_prefix.strip().lower()
        if t in ("b", "bool"):
            all_data.append(val.lower() in ("1", "true", "t", "yes", "y"))
        elif t in ("i", "int"):
            all_data.append(int(val, 0))
        elif t in ("s", "str"):
            all_data.append(_unescape_string_literal(val))
        elif t in ("r", "raw"):
            if ":" not in val:
                raise ValueError(f"invalid raw value (expected TAG:HEX): {val!r}")
            tag_str, hex_str = val.split(":", 1)
            all_data.append(["raw", int(tag_str, 0), hex_str.strip()])
        else:
            raise ValueError(f"unknown type: {t!r}")
    return all_data


def _serialize_all_data(all_data: List[Any]) -> List[Any]:
    """Make it JSON-ready: tuples become lists."""
    out: List[Any] = []
    for x in all_data:
        if isinstance(x, tuple) and len(x) == 3 and x[0] == "raw":
            out.append(list(x))
        else:
            out.append(x)
    return out


def build_stream_config(args: argparse.Namespace) -> dict:
    """Build the stream configuration dict for the API."""
    values = getattr(args, "value", None) or []
    all_data = _parse_values(values) if values else []
    if getattr(args, "bool", None):
        for v in args.bool:
            all_data.append(v.lower() in ("1", "true", "t", "yes", "y"))
    if getattr(args, "int", None):
        for v in args.int:
            all_data.append(int(v, 0))
    if getattr(args, "str", None):
        for v in args.str:
            all_data.append(_unescape_string_literal(v))

    return {
        "iface": args.iface,
        "src_mac": args.src_mac,
        "dst_mac": args.dst_mac,
        "app_id": args.appid,
        "vlan_id": getattr(args, "vlan_id", None),
        "vlan_priority": getattr(args, "vlan_priority", None),
        "gocb_ref": args.gocb_ref,
        "dat_set": args.dat_set,
        "go_id": args.go_id,
        "ttl": getattr(args, "ttl", 5000),
        "conf_rev": getattr(args, "conf_rev", 1),
        "simulation": getattr(args, "sim", False),
        "nds_com": getattr(args, "nds_com", False),
        "all_data": _serialize_all_data(all_data),
    }


def _api_path(base_url: str, path: str) -> str:
    """API path: /api/goose/... for the unified service (7050), /api/... standalone (7053)."""
    u = base_url.rstrip("/")
    parsed = urlparse(u)
    port = parsed.port
    if port == 7050:
        return f"/api/goose{path}"
    return f"/api{path}"


def _api_request(base_url: str, method: str, path: str, body: dict | None = None) -> dict:
    full_path = _api_path(base_url, path)
    url = f"{base_url.rstrip('/')}{full_path}"
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    with urllib.request.urlopen(req) as resp:
        if resp.status in (200, 201):
            return json.loads(resp.read().decode("utf-8"))
        if resp.status == 204:
            return {}
        raise RuntimeError(f"API error {resp.status}: {resp.read().decode()}")


def cmd_add(args: argparse.Namespace, base_url: str) -> None:
    config = build_stream_config(args)
    result = _api_request(base_url, "POST", "/streams", body=config)
    print(f"Stream created: {result['id']}")
    print(json.dumps(result, indent=2, ensure_ascii=False))


def cmd_modify(args: argparse.Namespace, base_url: str) -> None:
    stream_id = args.stream_id
    body: dict = {}
    if getattr(args, "value", None):
        body["all_data"] = _serialize_all_data(_parse_values(args.value))
    if getattr(args, "ttl", None) is not None:
        body["ttl"] = args.ttl
    if getattr(args, "gocb_ref", None):
        body["gocb_ref"] = args.gocb_ref
    if getattr(args, "dat_set", None):
        body["dat_set"] = args.dat_set
    if getattr(args, "go_id", None):
        body["go_id"] = args.go_id
    if not body:
        print("Nothing to change.", file=sys.stderr)
        sys.exit(1)
    result = _api_request(base_url, "PATCH", f"/streams/{stream_id}", body=body)
    print(f"Stream changed: {stream_id}")
    print(json.dumps(result, indent=2, ensure_ascii=False))


def cmd_delete(args: argparse.Namespace, base_url: str) -> None:
    _api_request(base_url, "DELETE", f"/streams/{args.stream_id}")
    print(f"Stream deleted: {args.stream_id}")


def cmd_list(args: argparse.Namespace, base_url: str) -> None:
    result = _api_request(base_url, "GET", "/streams")
    streams = result.get("streams", [])
    if not streams:
        print("No stream configured.")
        return
    for s in streams:
        print(f"{s['id']}  gocbRef={s['gocb_ref']}  goID={s['go_id']}  stNum={s['st_num']}  sqNum={s['sq_num']}")


def _value_to_spec(v: Any) -> str:
    """Turn one all_data item into a --value TYPE:VALUE argument."""
    # Forme brute: ["raw", tag, hex]
    if isinstance(v, list) and len(v) == 3 and v[0] == "raw":
        tag = int(v[1])
        hex_str = str(v[2])
        return f"raw:{tag}:{hex_str}"
    # bool
    if isinstance(v, bool):
        return f"b:{'1' if v else '0'}"
    # int
    if isinstance(v, int):
        return f"i:{v}"
    # str
    if isinstance(v, str):
        if v == "\x00":
            # Common case: a NUL byte
            return "s:'\\\\x00'"
        # Quoting of unusual values is left to the user.
        return f"s:{v}"
    # fallback: repr
    return f"s:{repr(v)}"


def cmd_update_cmd(args: argparse.Namespace, base_url: str) -> None:
    """Print a prefilled 'modify' command for one stream."""
    stream_id = args.stream_id
    s = _api_request(base_url, "GET", f"/streams/{stream_id}")
    all_data = s.get("all_data", [])

    cmd_lines: list[str] = []
    prog = sys.argv[0] if sys.argv and sys.argv[0] else "goose_cli.py"
    cmd_lines.append(f"python3 {prog} modify {stream_id} \\")

    # Offer the current all_data values as --value arguments
    for v in all_data:
        spec = _value_to_spec(v)
        cmd_lines.append(f"  --value {spec} \\")

    # List the other editable fields as comments.
    cmd_lines.append("  # --ttl {ttl} --gocb-ref '{gocb_ref}' --dat-set '{dat_set}' --go-id '{go_id}'".format(
        ttl=s.get("ttl", 5000),
        gocb_ref=s.get("gocb_ref", ""),
        dat_set=s.get("dat_set", ""),
        go_id=s.get("go_id", ""),
    ))

    # Drop the trailing backslash.
    if cmd_lines[-2].endswith(" \\"):
        cmd_lines[-2] = cmd_lines[-2].rstrip(" \\")

    print("\n".join(cmd_lines))


def _add_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("add", help="Add a GOOSE stream")
    p.add_argument("iface", help="Network interface")
    p.add_argument("src_mac", help="Source MAC")
    p.add_argument("dst_mac", help="Destination MAC")
    p.add_argument("--appid", type=lambda x: int(x, 0), required=True)
    p.add_argument("--vlan-id", type=int, default=None)
    p.add_argument("--vlan-priority", type=int, default=None)
    p.add_argument("--gocb-ref", required=True)
    p.add_argument("--dat-set", required=True)
    p.add_argument("--go-id", required=True)
    p.add_argument("--ttl", type=int, default=5000)
    p.add_argument("--conf-rev", type=int, default=1)
    p.add_argument("--sim", action="store_true")
    p.add_argument("--nds-com", action="store_true")
    p.add_argument("--entries", type=int, default=None, help="(ignored, kept for compatibility)")
    p.add_argument("--value", action="append", default=[])
    p.add_argument("--bool", action="append")
    p.add_argument("--int", action="append")
    p.add_argument("--str", action="append")


def _modify_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("modify", help="Change a stream")
    p.add_argument("stream_id", help="Stream id (from add)")
    p.add_argument("--value", action="append", default=[])
    p.add_argument("--ttl", type=int)
    p.add_argument("--gocb-ref")
    p.add_argument("--dat-set")
    p.add_argument("--go-id")


def _update_cmd_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "update-cmd",
        help="Print a prefilled 'modify' command for a stream",
    )
    p.add_argument("stream_id", help="Stream id (from add or list)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Command line for the GOOSE service.",
    )
    parser.add_argument(
        "--service",
        default="http://localhost:7050",
        help="Service URL (unified: 7050, standalone: 7053)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    _add_parser(sub)
    _modify_parser(sub)
    _update_cmd_parser(sub)
    sub.add_parser("list", help="List the streams")
    d = sub.add_parser("delete", help="Delete a stream")
    d.add_argument("stream_id")
    args = parser.parse_args()
    base_url = args.service.rstrip("/")

    try:
        if args.command == "add":
            cmd_add(args, base_url)
        elif args.command == "modify":
            cmd_modify(args, base_url)
        elif args.command == "update-cmd":
            cmd_update_cmd(args, base_url)
        elif args.command == "delete":
            cmd_delete(args, base_url)
        elif args.command == "list":
            cmd_list(args, base_url)
    except urllib.error.URLError as e:
        print(f"Cannot reach the service: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"API error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
