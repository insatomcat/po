"""Découverte des reports MMS disponibles sur un IED IEC 61850.

Se connecte en MMS à l'adresse IP donnée. Essaie d'abord GetNameList pour
lister les domaines et RCB. Si l'IED ne supporte pas GetNameList (réponse
incorrecte), utilise un sondage par GetRCBValues sur des domaines/RCB connus.

Usage:
    python3 -m mms.discover_reports [--debug] [--domain ID] [host [port]]
    python3 mms/discover_reports.py [--debug] [--domain ID] [host [port]]

Exemple:
    python3 -m mms.discover_reports 10.132.159.191 102
    python3 -m mms.discover_reports --domain VMC7_1LD0 10.132.159.94 102
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Permettre l'exécution directe (python3 mms/discover_reports.py)
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mms.mms_reports_client import MMSReportsClient, MMSConnectionError
from mms.asn1_codec import OBJECT_CLASS_DOMAIN, OBJECT_CLASS_NAMED_VARIABLE


# Patterns typiques pour les Report Control Blocks IEC 61850
RCB_PATTERNS = ("$BR$CB", "$RP$", "BR$CB", "RP$", "$RCB", "RCB$")

# Domaines et RCB connus (fallback quand GetNameList échoue)
DEFAULT_DOMAINS = ("VMC7_1LD0", "LD0", "IED1_LD0")
DEFAULT_RCB_ITEMS = (
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
)


def _is_rcb(name: str) -> bool:
    """True si le nom ressemble à un Report Control Block (LLN0$BR$CB_xxx, etc.)."""
    u = name.upper()
    for pat in RCB_PATTERNS:
        if pat.upper() in u:
            return True
    return False


def discover_by_probe(
    client: MMSReportsClient,
    domains: tuple[str, ...],
    items: tuple[str, ...],
    debug: bool = False,
) -> list[tuple[str, str]]:
    """Sonde GetRCBValues sur domain×items pour trouver les RCB existants."""
    reports: list[tuple[str, str]] = []
    for domain_id in domains:
        for item_id in items:
            try:
                if client.probe_rcb(domain_id, item_id):
                    reports.append((domain_id, item_id))
                    if debug:
                        print(f"[DEBUG]     → RCB trouvé : {domain_id}/{item_id}", flush=True)
            except Exception:
                pass
    return reports


def discover_reports(
    client: MMSReportsClient,
    *,
    fallback_domains: tuple[str, ...] = DEFAULT_DOMAINS,
    fallback_items: tuple[str, ...] = DEFAULT_RCB_ITEMS,
    debug: bool = False,
) -> list[tuple[str, str]]:
    """
    Parcourt GetNameList pour trouver les RCB. Si GetNameList échoue (IED non
    conforme), sonde GetRCBValues sur fallback_domains × fallback_items.
    """
    reports: list[tuple[str, str]] = []

    # 1. Essayer GetNameList vmd-specific (domaines)
    result = client.get_name_list(OBJECT_CLASS_DOMAIN, scope_vmd=True)
    if result:
        domains, _ = result
        if domains:
            print(f"  Domaines trouvés (GetNameList) : {', '.join(domains)}", flush=True)
            for domain_id in domains:
                result2 = client.get_name_list(
                    OBJECT_CLASS_NAMED_VARIABLE,
                    scope_vmd=False,
                    domain_id=domain_id,
                )
                if result2:
                    names, _ = result2
                    for n in names:
                        if _is_rcb(n):
                            reports.append((domain_id, n))
            return reports

    # 2. GetNameList échoué ou liste vide → sondage par GetRCBValues
    print("  GetNameList non supporté ou vide. Sondage par GetRCBValues...", flush=True)
    reports = discover_by_probe(client, fallback_domains, fallback_items, debug=debug)
    return reports


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Découvrir les reports MMS disponibles sur un IED IEC 61850."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Afficher les PDUs MMS envoyés et reçus.",
    )
    parser.add_argument(
        "--domain",
        action="append",
        metavar="ID",
        help="Domaine(s) à sonder si GetNameList échoue (ex: VMC7_1LD0). Répétable.",
    )
    parser.add_argument(
        "host",
        nargs="?",
        default="10.132.159.191",
        help="IP de l'IED (défaut: 10.132.159.191).",
    )
    parser.add_argument(
        "port",
        nargs="?",
        type=int,
        default=102,
        help="Port MMS (défaut: 102).",
    )
    args = parser.parse_args()

    print(f"Connexion MMS à {args.host}:{args.port}...", flush=True)

    try:
        client = MMSReportsClient(args.host, args.port, debug=args.debug)
        client.connect()
        print("Connexion établie. Découverte des reports...", flush=True)
    except MMSConnectionError as e:
        print(f"Erreur : {e}", file=sys.stderr, flush=True)
        return 1

    domains = tuple(args.domain) if args.domain else DEFAULT_DOMAINS

    try:
        reports = discover_reports(
            client,
            fallback_domains=domains,
            fallback_items=DEFAULT_RCB_ITEMS,
            debug=args.debug,
        )
    finally:
        client.close()

    print(f"\nReports (RCB) trouvés : {len(reports)}", flush=True)
    if reports:
        for domain_id, item_id in sorted(reports):
            print(f"  {domain_id} / {item_id}", flush=True)
    else:
        print("  Aucun RCB identifié.")
        print("  Note : certains IED ne supportent pas GetNameList ou utilisent des noms non standards.", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
