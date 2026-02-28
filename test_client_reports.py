"""Test d'abonnement aux reports MMS sur un IED.

Usage:
    python3 test_client_reports.py [--debug] [host [port]]

Sans --debug : pas d'affichage des PDUs envoyés/reçus.
Avec --debug : affiche les trames (>>> envoi, <<< réception).
"""

import argparse
import sys

from mms_reports_client import MMSReportsClient
from asn1_codec import MMSReport  # juste pour le type

IED_IP_DEFAULT = "10.132.159.191"
IED_PORT_DEFAULT = 102
DOMAIN_ID = "VMC7_1LD0"

# RCB auxquels s'abonner (GetRCBValues + séquence SetRCBValues pour chacun)
ITEM_IDS = [
    "LLN0$BR$CB_LDPX_DQPO02",
    "LLN0$BR$CB_LDADD_DQPO02",
    "LLN0$BR$CB_LDCAP1_DQPO02",
    "LLN0$BR$CB_LDEPF_DQPO02",
    "LLN0$BR$CB_LDCMDSA1_DQPO02",
    "LLN0$BR$CB_LDLOCDEF_DQPO02",
    "LLN0$BR$CB_LDCMDDJ_DQPO02",
    "LLN0$BR$CB_LDSUDJ_DQPO02",
    "LLN0$BR$CB_LDCMDST_DQPO02",
    "LLN0$BR$CB_LDRS_DQPO02",
    "LLN0$BR$CB_LDREC_DQPO02",
    "LLN0$BR$CB_LDSUIED_DQPO02",
    "LLN0$BR$CB_LDCAP1_CYPO02",
    "LLN0$BR$CB_LDCMDDJ_CYPO02",
    "LLN0$BR$CB_LDPHAS1_CYPO02",
]


def on_report(report: MMSReport) -> None:
    print("REPORT reçu :")
    print(f"  RCB    : {report.rcb_reference}")
    print(f"  RptId  : {report.rpt_id}")
    print(f"  DataSet: {report.data_set_name}")
    print(f"  SeqNum : {report.seq_num}")
    if report.entries:
        for i, e in enumerate(report.entries):
            print(f"    [{i}] {e}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="S'abonner aux reports MMS sur un IED (Get + SetRCBValues par RCB)."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Afficher les PDUs envoyés et reçus (>>> / <<<).",
    )
    parser.add_argument(
        "host",
        nargs="?",
        default=IED_IP_DEFAULT,
        help=f"IP de l'IED (défaut: {IED_IP_DEFAULT}).",
    )
    parser.add_argument(
        "port",
        nargs="?",
        type=int,
        default=IED_PORT_DEFAULT,
        help=f"Port MMS (défaut: {IED_PORT_DEFAULT}).",
    )
    args = parser.parse_args()

    client = MMSReportsClient(args.host, args.port, debug=args.debug)
    client.connect()

    for i, item_id in enumerate(ITEM_IDS, 1):
        print(f"Abonnement [{i}/{len(ITEM_IDS)}] {DOMAIN_ID}/{item_id} ...")
        client.enable_reporting(DOMAIN_ID, item_id)

    print(f"\n{len(ITEM_IDS)} RCB abonnés. En attente de reports...\n")
    client.loop_reports(on_report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
