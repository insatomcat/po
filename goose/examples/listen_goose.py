#!/usr/bin/env python3
from __future__ import annotations

import argparse
import pathlib
import sys
from datetime import datetime
from typing import Optional

# Ajoute la racine du dépôt au sys.path pour pouvoir importer goose61850 et iec_data
ROOT = pathlib.Path(__file__).resolve().parents[1]
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from goose61850 import GooseSubscriber
from goose61850.types import GooseFrame


def summarize_frame(frame: GooseFrame, show_all_elements: bool = False) -> str:
    pdu = frame.pdu
    if pdu is None:
        return (
            f"{frame.src_mac} -> {frame.dst_mac} "
            f"APPID=0x{frame.app_id:04X} (PDU non décodé)"
        )

    ts: Optional[datetime] = pdu.timestamp
    ts_str = ts.isoformat() if ts else "-"

    # aperçu des données décodées (allData)
    preview = ""
    if pdu.all_data:
        if show_all_elements:
            preview = f" allData={repr(pdu.all_data)}"
        else:
            # on limite pour ne pas flooder la sortie
            shown = ", ".join(repr(v) for v in pdu.all_data[:5])
            if len(pdu.all_data) > 5:
                shown += ", ..."
            preview = f" allData=[{shown}]"

    return (
        f"[{ts_str}] {frame.src_mac} -> {frame.dst_mac} "
        f"APPID=0x{frame.app_id:04X} "
        f"gocbRef={pdu.gocb_ref} "
        f"goID={pdu.go_id} "
        f"stNum={pdu.st_num} sqNum={pdu.sq_num} "
        f"confRev={pdu.conf_rev} "
        f"entries={pdu.num_dat_set_entries}"
        f"{preview}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Écoute les trames GOOSE et affiche un résumé pour chacune.",
    )
    parser.add_argument(
        "iface",
        help="Interface réseau à écouter (ex: en0, eth0, ...)",
    )
    parser.add_argument(
        "--app-id",
        type=lambda x: int(x, 0),
        default=None,
        help="Filtre APPID (ex: 0x1000). Si omis, accepte tous les APPID.",
    )
    parser.add_argument(
        "--go-id",
        type=str,
        default=None,
        help="Filtre sur goID (chaîne exacte). Si omis, accepte tous les goID.",
    )
    parser.add_argument(
        "--gocb-ref",
        type=str,
        default=None,
        help="Filtre sur gocbRef (chaîne exacte).",
    )
    parser.add_argument(
        "--src-mac",
        type=str,
        default=None,
        help="Filtre sur adresse MAC source.",
    )
    parser.add_argument(
        "--dst-mac",
        type=str,
        default=None,
        help="Filtre sur adresse MAC destination.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Affiche des informations de debug sur chaque paquet capturé.",
    )
    parser.add_argument(
        "--show-all-elements",
        action="store_true",
        help="Affiche l'intégralité de la liste allData (aucune troncature).",
    )

    args = parser.parse_args()

    def on_frame(frame: GooseFrame) -> None:
        if frame.pdu is None:
            # pas de filtre possible sur goID si PDU non décodé
            print(summarize_frame(frame, show_all_elements=args.show_all_elements))
            return

        # filtres au niveau PDU
        if args.go_id is not None and frame.pdu.go_id != args.go_id:
            return
        if args.gocb_ref is not None and frame.pdu.gocb_ref != args.gocb_ref:
            return

        # filtres au niveau trame Ethernet
        if args.src_mac is not None and frame.src_mac.lower() != args.src_mac.lower():
            return
        if args.dst_mac is not None and frame.dst_mac.lower() != args.dst_mac.lower():
            return

        print(summarize_frame(frame, show_all_elements=args.show_all_elements))

    sub = GooseSubscriber(
        iface=args.iface,
        app_id=args.app_id,
        callback=on_frame,
        debug=args.debug,
    )

    print(
        f"Écoute GOOSE sur {args.iface} "
        f"(APPID={'*' if args.app_id is None else hex(args.app_id)}, "
        f"goID={'*' if args.go_id is None else args.go_id}, "
        f"gocbRef={'*' if args.gocb_ref is None else args.gocb_ref})..."
    )
    print("Interrompre avec Ctrl+C.")

    sub.start()


if __name__ == "__main__":
    main()

