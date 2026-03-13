"""Test d'abonnement aux reports MMS sur un IED.

Usage:
    python3 test_client_reports.py [--debug] [--verbose] [--scl FICHIER]
                                   [--domain ID] [--victoriametrics-url URL]
                                   [host [port]]

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
import atexit
import sys
import time

from mms_reports_client import MMSReportsClient, MMSConnectionError
from scl_parser import parse_scl_data_set_members_with_components
from victoriametrics_push import push_mms_report_flush
from mms_report_processing import (
    MMSReport,
    DATA_SET_MEMBER_LABELS,
    DATA_SET_MEMBER_COMPONENTS,
    DATA_SET_MEMBER_ENUMS,
    load_item_ids_from_file,
    process_mms_report,
)

VERBOSE = False  # mis à True par --verbose

IED_IP_DEFAULT = "10.132.159.191"
IED_PORT_DEFAULT = 102
DOMAIN_ID = "VMC7_1LD0" # ABB : SSC600SW_ALD0

ITEM_IDS = []  # rétro‑compat : sera alimenté via load_item_ids_from_file si besoin


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
        "--domain",
        default=DOMAIN_ID,
        help=f"Domain ID MMS (défaut: {DOMAIN_ID}).",
    )
    parser.add_argument(
        "--victoriametrics-url",
        metavar="URL",
        help="Envoyer les valeurs des reports vers VictoriaMetrics (ex. http://localhost:8428).",
    )
    parser.add_argument(
        "--vm-batch-ms",
        type=int,
        default=200,
        help="Intervalle de batch VM en ms (défaut: 200). Une requête HTTP par intervalle ou dès 500 lignes.",
    )
    parser.add_argument(
        "--vm-no-batch",
        action="store_true",
        help="Désactiver le batching : une requête HTTP par report (comportement legacy).",
    )
    parser.add_argument(
        "--vm-console",
        action="store_true",
        help="Afficher les reports dans la console en plus de les envoyer vers VictoriaMetrics.",
    )
    parser.add_argument(
        "--rcb-list",
        metavar="FICHIER",
        help=(
            "Fichier texte listant les RCB à activer (une par ligne, ex. "
            "LLN0$BR$CB_LDPX_DQPO03). Si omis, utilise la liste intégrée."
        ),
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
    vm_url = args.victoriametrics_url or None
    show_in_console = not bool(vm_url) or args.vm_console
    batch_interval_sec = 0 if args.vm_no_batch else args.vm_batch_ms / 1000.0
    if vm_url:
        if args.vm_no_batch:
            print(f"[VictoriaMetrics] Push activé vers {vm_url} (pas de batch)")
        else:
            print(f"[VictoriaMetrics] Push activé vers {vm_url} (batch: {args.vm_batch_ms}ms)")
        if args.vm_console:
            print("[Console] Affichage des reports activé (--vm-console)")
        atexit.register(lambda u=vm_url: push_mms_report_flush(u))
    else:
        print("[Console] Reports affichés dans la console (pas de --victoriametrics-url)")

    if args.scl:
        try:
            parsed, comp, enums = parse_scl_data_set_members_with_components(args.scl)
            DATA_SET_MEMBER_LABELS.update(parsed)
            for k, v in comp.items():
                DATA_SET_MEMBER_COMPONENTS.setdefault(k, {}).update(v)
            for k, v in enums.items():
                DATA_SET_MEMBER_ENUMS.setdefault(k, {}).update(v)
            print(f"[SCL] {len(parsed)} data set(s) chargé(s) depuis {args.scl}")
        except FileNotFoundError:
            print(f"[SCL] Fichier non trouvé : {args.scl}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"[SCL] Erreur : {e}", file=sys.stderr)
            return 1

    def callback(report: MMSReport) -> None:
        process_mms_report(
            report,
            vm_url=vm_url,
            show_in_console=show_in_console,
            verbose=VERBOSE,
            batch_interval_sec=batch_interval_sec,
            batch_max_lines=500,
            member_components=DATA_SET_MEMBER_COMPONENTS or None,
        )

    domain_id = args.domain
    item_ids = load_item_ids_from_file(args.rcb_list)
    print(f"[RCB] {len(item_ids)} RCB à activer (source: {'fichier' if args.rcb_list else 'liste intégrée'})")

    # Boucle de (re)connexion automatique : tant que le processus tourne, on tente
    # de se reconnecter et de réactiver les RCB si la connexion est perdue (reboot IED, coupure réseau, etc.).
    reconnect_delay_sec = 5.0
    while True:
        client = MMSReportsClient(args.host, args.port, debug=args.debug)
        try:
            print(f"[MMS] Connexion à {args.host}:{args.port} ...")
            client.connect()
            print("[MMS] Connexion établie. Activation des RCB...")

            for i, item_id in enumerate(item_ids, 1):
                print(f"Abonnement [{i}/{len(item_ids)}] {domain_id}/{item_id} ...")
                client.enable_reporting(domain_id, item_id, report_callback=callback)

            print(f"\n{len(item_ids)} RCB abonnés. En attente de reports...")
            print("  (Si rien n'apparaît : l'IED n'envoie peut-être qu'en cas d'événement. Essayez --debug pour voir les PDUs reçus.)\n")

            # Boucle bloquante jusqu'à perte de connexion ou Ctrl+C
            client.loop_reports(callback)

            # Si on sort de loop_reports sans exception, la connexion est fermée proprement côté IED.
            print("[MMS] Connexion fermée par l'IED. Tentative de reconnexion...")

        except KeyboardInterrupt:
            print("\n[Interrupt] Arrêt demandé par l'utilisateur, fermeture de la connexion.")
            client.close()
            break
        except MMSConnectionError as e:
            print(f"[MMS] Erreur de connexion ou de protocole : {e}")
            print(f"[MMS] Nouvelle tentative dans {reconnect_delay_sec} s...")
        finally:
            client.close()
        try:
            time.sleep(reconnect_delay_sec)
        except KeyboardInterrupt:
            print("\n[Interrupt] Arrêt demandé par l'utilisateur, fermeture de la connexion.")
            break

    return 0


if __name__ == "__main__":
    sys.exit(main())
