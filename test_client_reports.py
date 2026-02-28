"""Test d'abonnement aux reports MMS sur un IED.

Usage:
    python3 test_client_reports.py [--debug] [--verbose] [host [port]]

Sans --debug : pas d'affichage des PDUs envoyés/reçus.
Avec --debug : affiche les trames (>>> envoi, <<< réception).
Avec --verbose : PDU brut (hex) et valeur brute de chaque entrée pour analyser la réponse.

Sémantique des entrées du report (IEC 61850 / MMS) :
  [0]–[7]  : En-tête du report (RptId, options, numéro de séquence, heure, nom du data set, etc.).
  [8] et + : Membres du Data Set, dans l'ordre défini sur l'IED. Chaque entrée = (valeur, qualité,
             horodatage). La signification de [8], [9], … = 1er, 2e, … FCDA du data set.
  Le report n'envoie pas les noms. Pour avoir "[8] = Beh" etc. : définir le data set dans le SCL/ICD
  ou interroger GetDataSetDirectory, puis remplir DATA_SET_MEMBER_LABELS ci-dessous (même ordre).
"""

import argparse
import sys

from mms_reports_client import MMSReportsClient
from asn1_codec import MMSReport  # juste pour le type

VERBOSE = False  # mis à True par --verbose

IED_IP_DEFAULT = "10.132.159.191"
IED_PORT_DEFAULT = 102
DOMAIN_ID = "VMC7_1LD0"

# Libellés des entrées 0-7 (en-tête MMS)
ENTRY_LABELS = (
    "RptId", "OptFlds", "SeqNum", "TimeOfEntry",
    "DatSet", "BufOvfl", "EntryID", "Inclusion",
)

# Noms des membres du Data Set (ordre = ordre dans le report). Remplir depuis SCL/ICD.
# Clé = report.data_set_name (ex. "VMC7_1LD0/LLN0$DS_LDPHAS1_CYPO").
DATA_SET_MEMBER_LABELS: dict[str, list[str]] = {}

# Codes qualité/reason courants (hex → libellé court)
QUALITY_LABELS = {
    "0208": "good",
    "0300": "questionable",
    "0000": "invalid",
}


def _format_entry_value(val):  # noqa: C901
    """Formate une entrée pour affichage (structure data+qualité+time ou qualité seule)."""
    if isinstance(val, list) and len(val) >= 3:
        # Structure type [value, quality_hex?, timestamp] ou [value, reserved, quality_hex, timestamp]
        v = val[0]
        if len(val) == 3:
            qual, ts = val[1], val[2]
        else:
            qual, ts = val[2], val[3]
        q = str(qual) if isinstance(qual, str) else (qual.hex() if hasattr(qual, "hex") else str(qual))
        q_label = QUALITY_LABELS.get(q.lower(), "")
        q_str = f"{q}" + (f" ({q_label})" if q_label else "")
        return f"value={v!r}  quality={q_str}  time={ts}"
    if isinstance(val, str) and len(val) == 4:
        label = QUALITY_LABELS.get(val.lower(), "")
        return f"{val} ({label})" if label else val
    return val


ITEM_IDS = [
    "LLN0$BR$CB_LDPX_DQPO03",
    "LLN0$BR$CB_LDADD_DQPO03",
    "LLN0$BR$CB_LDCAP1_DQPO03",
    "LLN0$BR$CB_LDEPF_DQPO03",
    "LLN0$BR$CB_LDCMDSA1_DQPO03",
    "LLN0$BR$CB_LDLOCDEF_DQPO03",
    "LLN0$BR$CB_LDCMDDJ_DQPO03",
    "LLN0$BR$CB_LDSUDJ_DQPO03",
    "LLN0$BR$CB_LDCMDST_DQPO03",
    "LLN0$BR$CB_LDRS_DQPO03",
    "LLN0$BR$CB_LDREC_DQPO03",
    "LLN0$BR$CB_LDSUIED_DQPO03",
    "LLN0$BR$CB_LDCAP1_CYPO03",
    "LLN0$BR$CB_LDCMDDJ_CYPO03",
    "LLN0$BR$CB_LDPHAS1_CYPO03",
]


def _hex_block(data: bytes, line_len: int = 64) -> str:
    """Hex du PDU par lignes de line_len octets (pour lecture / copier dans Wireshark)."""
    h = data.hex()
    return "\n      ".join(h[i : i + line_len * 2] for i in range(0, len(h), line_len * 2))


def on_report(report: MMSReport) -> None:
    print("REPORT reçu :")
    if VERBOSE and getattr(report, "raw_pdu", None):
        pdu = report.raw_pdu
        print(f"  [verbose] PDU brut ({len(pdu)} octets) :")
        print(f"      {_hex_block(pdu)}")
        print()
    print(f"  RptId       : {report.rpt_id}")
    print(f"  DataSet     : {report.data_set_name}")
    print(f"  SeqNum      : {report.seq_num}")
    print(f"  TimeOfEntry : {report.time_of_entry}")
    print(f"  BufOvfl     : {report.buf_ovfl}")
    if report.entries:
        member_labels = DATA_SET_MEMBER_LABELS.get(report.data_set_name or "", [])
        print(f"  Entries ({len(report.entries)}) :")
        if len(report.entries) > len(ENTRY_LABELS):
            print("  (à partir de [8] : 1er, 2e, … membre du data set)")
            print("  (chaque membre = valeur mesurée + qualité IEC 61850 + horodatage)")
        for i, e in enumerate(report.entries):
            val = e.get("success", e) if isinstance(e, dict) else e
            if i < len(ENTRY_LABELS):
                label = ENTRY_LABELS[i]
            else:
                j = i - len(ENTRY_LABELS)
                label = member_labels[j] if j < len(member_labels) else ""
            disp = _format_entry_value(val)
            if label:
                print(f"    [{i}] {label}: {disp}")
            else:
                print(f"    [{i}] {disp}")
            if VERBOSE:
                print(f"         raw= {val!r}")


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
        "--verbose",
        action="store_true",
        help="Afficher PDU brut (hex) et valeur brute de chaque entrée pour analyser la réponse.",
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
    global VERBOSE
    VERBOSE = args.verbose

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
