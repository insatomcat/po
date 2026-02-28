"""Test d'abonnement aux reports MMS sur un IED.

Usage:
    python3 test_client_reports.py [--debug] [--verbose] [--scl FICHIER] [host [port]]

Sans --debug : pas d'affichage des PDUs envoyés/reçus.
Avec --debug : affiche les trames (>>> envoi, <<< réception).
Avec --verbose : PDU brut (hex) et valeur brute de chaque entrée pour analyser la réponse.
Avec --scl FICHIER : charge un SCL/ICD pour afficher les noms des membres du data set ([8]=Beh, etc.).

Sémantique des entrées du report (IEC 61850 / MMS) :
  [0]–[7]  : En-tête du report (RptId, options, numéro de séquence, heure, nom du data set, etc.).
  [8] et + : Membres du Data Set, dans l'ordre défini sur l'IED. Chaque entrée = (valeur, qualité,
             horodatage). Avec --scl, les noms sont déduits du fichier SCL/ICD.
"""

import argparse
import sys

from mms_reports_client import MMSReportsClient
from asn1_codec import MMSReport  # juste pour le type
from scl_parser import parse_scl_data_set_members

VERBOSE = False  # mis à True par --verbose

IED_IP_DEFAULT = "10.132.159.191"
IED_PORT_DEFAULT = 102
DOMAIN_ID = "VMC7_1LD0"

# Libellés des entrées 0-7 (en-tête MMS)
ENTRY_LABELS = (
    "RptId", "OptFlds", "SeqNum", "TimeOfEntry",
    "DatSet", "BufOvfl", "EntryID", "Inclusion",
)

# Noms des membres du Data Set (ordre = ordre dans le report).
# Rempli automatiquement par --scl FICHIER, ou manuellement ci-dessous.
DATA_SET_MEMBER_LABELS: dict[str, list[str]] = {}

# Codes qualité/reason courants (hex → libellé court)
QUALITY_LABELS = {
    "0208": "good",
    "0300": "questionable",
    "0000": "invalid",
}


def _looks_like_quality_hex(s) -> bool:
    """True si la valeur ressemble à un code qualité (4 ou 6 caractères hex)."""
    if not isinstance(s, str) or len(s) not in (4, 6):
        return False
    return all(c in "0123456789abcdefABCDEF" for c in s)


def _format_entry_value(val):  # noqa: C901
    """Formate une entrée pour affichage (structure data+qualité+time ou qualité seule)."""
    if isinstance(val, list) and len(val) >= 3:
        # Structure [value, quality_hex?, timestamp] ou [value, reserved, quality_hex, timestamp]
        v = val[0]
        if len(val) == 3:
            a1, a2 = val[1], val[2]
            # Souvent [value, 0, quality_hex] sans timestamp
            if _looks_like_quality_hex(a2):
                qual, ts = a2, None
            else:
                qual, ts = a1, a2
        else:
            qual, ts = val[2], val[3]
        q = str(qual) if isinstance(qual, str) else (qual.hex() if hasattr(qual, "hex") else str(qual))
        q_label = QUALITY_LABELS.get(q.lower(), "")
        q_str = f"{q}" + (f" ({q_label})" if q_label else "")
        if ts is None or _looks_like_quality_hex(ts) or (isinstance(ts, (int, float)) and not isinstance(ts, bool)):
            return f"value={v!r}  quality={q_str}"
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


def _is_undecoded_raw(report: MMSReport) -> bool:
    """True si le PDU n'a pas été reconnu (fallback raw_hex)."""
    if not report.entries or len(report.entries) != 1:
        return False
    e = report.entries[0]
    return isinstance(e, dict) and "raw_hex" in e


def on_report(report: MMSReport) -> None:
    if _is_undecoded_raw(report):
        n = len(report.entries[0].get("raw_hex", "")) // 2 if report.entries else 0
        print(f"  [PDU non décodé, {n} octets] (autre type de message MMS)")
        if VERBOSE and report.entries:
            print(f"      {report.entries[0].get('raw_hex', '')[:120]}...")
        return

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
        ds_name = report.data_set_name or ""
        member_labels = DATA_SET_MEMBER_LABELS.get(ds_name, [])
        if not member_labels and ds_name and "$" in ds_name:
            # Repli : matcher par la fin du nom (ex. $DS_LDPHAS1_CYPO) si le préfixe IED diffère
            suffix = "$" + ds_name.split("$", 1)[-1]
            for k, labels in DATA_SET_MEMBER_LABELS.items():
                if k.endswith(suffix):
                    member_labels = labels
                    break
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
                if j < len(member_labels):
                    label = member_labels[j]
                elif j < 2 * len(member_labels):
                    # Qualité/reason associée au (j - N)e membre
                    label = f"qualité({member_labels[j - len(member_labels)]})"
                else:
                    label = ""
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
        "--scl",
        metavar="FICHIER",
        help="Fichier SCL ou ICD pour afficher les noms des membres du data set ([8]=Beh, etc.).",
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

    if args.scl:
        try:
            parsed = parse_scl_data_set_members(args.scl)
            DATA_SET_MEMBER_LABELS.update(parsed)
            print(f"[SCL] {len(parsed)} data set(s) chargé(s) depuis {args.scl}")
        except FileNotFoundError:
            print(f"[SCL] Fichier non trouvé : {args.scl}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"[SCL] Erreur : {e}", file=sys.stderr)
            return 1

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
