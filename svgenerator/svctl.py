from __future__ import annotations

import argparse
import sys

import requests


DEFAULT_BASE_URL = "http://127.0.0.1:7051"


def cmd_list(args: argparse.Namespace) -> None:
    resp = requests.get(f"{args.base_url}/api/flows", timeout=5.0)
    if resp.status_code >= 400:
        print(f"Error: {resp.status_code} {resp.text}", file=sys.stderr)
        sys.exit(1)
    flows = resp.json()
    if not flows:
        print("No flows.")
        return
    for f in flows:
        name = f.get("name")
        interface = f.get("interface")
        src_mac = f.get("src_mac")
        dst_mac = f.get("dst_mac")
        svid = f.get("svid")
        running = f.get("running")

        if not getattr(args, "verbose", False):
            freq = f.get("freq_hz")
            fault = f.get("fault")
            extra = ""
            if freq is not None:
                extra += f" freq={freq}Hz"
            if fault is not None:
                extra += f" fault={fault}"

            print(
                f"{name}: iface={interface} {src_mac} -> {dst_mac} "
                f"svid={svid}{extra} running={running}"
            )
            continue

        # Mode verbeux: afficher tous les champs connus, y compris VLAN et défaut.
        print(f"Flow {name}:")
        print(f"  iface         : {interface}")
        print(f"  src_mac       : {src_mac}")
        print(f"  dst_mac       : {dst_mac}")
        print(f"  svid          : {svid}")
        print(f"  running       : {running}")
        print(f"  smp_synch     : {f.get('smp_synch')}")
        print(f"  vlan_id       : {f.get('vlan_id')}")
        print(f"  vlan_priority : {f.get('vlan_priority')}")
        print(f"  freq_hz       : {f.get('freq_hz')}")
        print(f"  i_peak        : {f.get('i_peak')}")
        print(f"  v_peak        : {f.get('v_peak')}")
        print(f"  phase_deg     : {f.get('phase_deg')}")
        print(f"  fault         : {f.get('fault')}")
        print(f"  fault_i_peak  : {f.get('fault_i_peak')}")
        print(f"  fault_v_peak  : {f.get('fault_v_peak')}")
        print(f"  fault_phase_d : {f.get('fault_phase_deg')}")
        print(f"  fault_cycle_s : {f.get('fault_cycle_s')}")
        print()


def cmd_create(args: argparse.Namespace) -> None:
    payload = {
        "name": args.name,
        "interface": args.interface,
        "src_mac": args.src_mac,
        "dst_mac": args.dst_mac,
        "svid": args.svid,
        "fault": args.fault,
    }
    if args.smp_synch is not None:
        payload["smp_synch"] = args.smp_synch
    if args.vlan_id is not None:
        payload["vlan_id"] = args.vlan_id
    if args.vlan_priority is not None:
        payload["vlan_priority"] = args.vlan_priority
    if args.freq is not None:
        payload["freq_hz"] = args.freq
    if args.i_peak is not None:
        payload["i_peak"] = args.i_peak
    if args.v_peak is not None:
        payload["v_peak"] = args.v_peak
    if args.phase is not None:
        payload["phase_deg"] = args.phase
    if args.fault_i_peak is not None:
        payload["fault_i_peak"] = args.fault_i_peak
    if args.fault_v_peak is not None:
        payload["fault_v_peak"] = args.fault_v_peak
    if args.fault_phase is not None:
        payload["fault_phase_deg"] = args.fault_phase
    if args.fault_cycle is not None:
        payload["fault_cycle_s"] = args.fault_cycle
    resp = requests.post(f"{args.base_url}/api/flows", json=payload, timeout=5.0)
    if resp.status_code >= 400:
        print(f"Error: {resp.status_code} {resp.text}", file=sys.stderr)
        sys.exit(1)
    f = resp.json()
    print(
        f"Created flow {f['name']} on {f['interface']} "
        f"{f['src_mac']} -> {f['dst_mac']} svid={f['svid']}"
    )


def cmd_update(args: argparse.Namespace) -> None:
    payload = {
        "name": args.name,
        "interface": args.interface,
        "src_mac": args.src_mac,
        "dst_mac": args.dst_mac,
        "svid": args.svid,
        "fault": args.fault,
    }
    if args.smp_synch is not None:
        payload["smp_synch"] = args.smp_synch
    if args.vlan_id is not None:
        payload["vlan_id"] = args.vlan_id
    if args.vlan_priority is not None:
        payload["vlan_priority"] = args.vlan_priority
    if args.freq is not None:
        payload["freq_hz"] = args.freq
    if args.i_peak is not None:
        payload["i_peak"] = args.i_peak
    if args.v_peak is not None:
        payload["v_peak"] = args.v_peak
    if args.phase is not None:
        payload["phase_deg"] = args.phase
    if args.fault_i_peak is not None:
        payload["fault_i_peak"] = args.fault_i_peak
    if args.fault_v_peak is not None:
        payload["fault_v_peak"] = args.fault_v_peak
    if args.fault_phase is not None:
        payload["fault_phase_deg"] = args.fault_phase
    if args.fault_cycle is not None:
        payload["fault_cycle_s"] = args.fault_cycle
    resp = requests.put(f"{args.base_url}/api/flows/{args.name}", json=payload, timeout=5.0)
    if resp.status_code >= 400:
        print(f"Error: {resp.status_code} {resp.text}", file=sys.stderr)
        sys.exit(1)
    f = resp.json()
    print(
        f"Updated flow {f['name']} on {f['interface']} "
        f"{f['src_mac']} -> {f['dst_mac']} svid={f['svid']}"
    )


def cmd_delete(args: argparse.Namespace) -> None:
    resp = requests.delete(f"{args.base_url}/api/flows/{args.name}", timeout=5.0)
    if resp.status_code >= 400:
        print(f"Error: {resp.status_code} {resp.text}", file=sys.stderr)
        sys.exit(1)
    print(f"Deleted flow {args.name}")


def cmd_clear(args: argparse.Namespace) -> None:
    resp = requests.delete(f"{args.base_url}/api/flows", timeout=5.0)
    if resp.status_code >= 400:
        print(f"Error: {resp.status_code} {resp.text}", file=sys.stderr)
        sys.exit(1)
    print("Deleted all flows")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="svctl",
        description="SV generator control CLI (talks to sv_service REST API)",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Base URL of service (default {DEFAULT_BASE_URL})",
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="List flows")
    p_list.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show all details for each flow (including VLAN, fault params, etc.)",
    )
    p_list.set_defaults(func=cmd_list)

    p_create = sub.add_parser("create", help="Create a new flow")
    p_create.add_argument("name", help="Flow name (unique)")
    p_create.add_argument("interface", help="Network interface (e.g. eth0)")
    p_create.add_argument("src_mac", help="Source MAC aa:bb:cc:dd:ee:ff")
    p_create.add_argument("dst_mac", help="Destination MAC")
    p_create.add_argument("svid", help="svID")
    p_create.add_argument("--smp-synch", type=int, choices=[0, 1, 2])
    p_create.add_argument("--vlan-id", type=int)
    p_create.add_argument("--vlan-priority", type=int)
    p_create.add_argument("--freq", type=float)
    p_create.add_argument("--i-peak", type=float)
    p_create.add_argument("--v-peak", type=float)
    p_create.add_argument("--phase", type=float)
    p_create.add_argument("--fault", action="store_true")
    p_create.add_argument("--fault-i-peak", type=float)
    p_create.add_argument("--fault-v-peak", type=float)
    p_create.add_argument("--fault-phase", type=float)
    p_create.add_argument("--fault-cycle", type=float)
    p_create.set_defaults(func=cmd_create)

    p_update = sub.add_parser("update", help="Update an existing flow")
    p_update.add_argument("name", help="Flow name")
    p_update.add_argument("interface", help="Network interface (e.g. eth0)")
    p_update.add_argument("src_mac", help="Source MAC aa:bb:cc:dd:ee:ff")
    p_update.add_argument("dst_mac", help="Destination MAC")
    p_update.add_argument("svid", help="svID")
    p_update.add_argument("--smp-synch", type=int, choices=[0, 1, 2])
    p_update.add_argument("--vlan-id", type=int)
    p_update.add_argument("--vlan-priority", type=int)
    p_update.add_argument("--freq", type=float)
    p_update.add_argument("--i-peak", type=float)
    p_update.add_argument("--v-peak", type=float)
    p_update.add_argument("--phase", type=float)
    p_update.add_argument("--fault", action="store_true")
    p_update.add_argument("--fault-i-peak", type=float)
    p_update.add_argument("--fault-v-peak", type=float)
    p_update.add_argument("--fault-phase", type=float)
    p_update.add_argument("--fault-cycle", type=float)
    p_update.set_defaults(func=cmd_update)

    p_delete = sub.add_parser("delete", help="Delete a flow")
    p_delete.add_argument("name", help="Flow name")
    p_delete.set_defaults(func=cmd_delete)

    p_clear = sub.add_parser("clear", help="Delete all flows")
    p_clear.set_defaults(func=cmd_clear)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

