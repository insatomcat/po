#!/usr/bin/env python3
"""
Découverte des Report Control Blocks (RCB) sur un IED IEC 61850 et abonnement
pour recevoir les reports (mode publisher/subscriber).

Usage :
    python mms_reports.py <ip_serveur> [port] [réf_RCB...]
    python mms_reports.py 10.132.159.191 102
    python mms_reports.py 10.132.159.191 102 "VMC7_2LD0/LLN0$BR$CB_LDPX_DQPO01"

Sans réf_RCB : connexion, découverte de tous les RCB, affichage, abonnement à tous.
Avec réf_RCB : connexion puis abonnement uniquement aux références données (pas de découverte).
"""

import signal
import sys
import time

# Même contournement que mms_client pour le retour (None, 0) de IedConnection_connect
import pyiec61850.pyiec61850 as _iec61850

_orig_connect = _iec61850.IedConnection_connect

def _unwrap_connect(conn, host, port):
    out = _orig_connect(conn, host, port)
    if isinstance(out, tuple) and len(out) > 1:
        return out[1]
    return out


_iec61850.IedConnection_connect = _unwrap_connect

from pyiec61850.mms import (
    MMSClient,
    ConnectionFailedError,
    MMSError,
    ReadError,
    LinkedListGuard,
    unpack_result,
)
from pyiec61850.mms.reporting import (
    ReportClient,
    Report,
    ReportEntry,
    RCBConfig,
    ReportConfigError,
    ReportError,
)


def decouvre_rcbs(client: MMSClient) -> list[tuple[str, str]]:
    """
    Parcourt le modèle et retourne la liste des RCB (référence complète, type "BR" ou "RP").
    """
    conn = getattr(client, "_connection", None)
    if not conn:
        return []

    refs: list[tuple[str, str]] = []
    devices = client.get_logical_devices()
    if not devices:
        return refs

    for device in devices:
        result = _iec61850.IedConnection_getLogicalDeviceDirectory(conn, device)
        value, error, ok = unpack_result(result)
        if not ok or not value:
            continue
        with LinkedListGuard(value) as guard:
            nodes = list(guard)

        for node in nodes:
            ln_ref = f"{device}/{node}"

            # BRCB (Buffered Report Control Block)
            res_br = _iec61850.IedConnection_getLogicalNodeDirectory(
                conn, ln_ref, _iec61850.ACSI_CLASS_BRCB
            )
            v_br, err_br, ok_br = unpack_result(res_br)
            if ok_br and v_br:
                with LinkedListGuard(v_br) as g:
                    for name in g:
                        if name:
                            # Référence objet standard : LD/LN.DO (point, pas $BR$)
                            refs.append((f"{ln_ref}.{name}", "BR"))

            # URCB (Unbuffered Report Control Block)
            res_ur = _iec61850.IedConnection_getLogicalNodeDirectory(
                conn, ln_ref, _iec61850.ACSI_CLASS_URCB
            )
            v_ur, err_ur, ok_ur = unpack_result(res_ur)
            if ok_ur and v_ur:
                with LinkedListGuard(v_ur) as g:
                    for name in g:
                        if name:
                            refs.append((f"{ln_ref}.{name}", "RP"))

    return refs


def _ref_variantes(rcb_ref: str, rcb_type: str) -> list[str]:
    """Retourne plusieurs formats de référence à essayer (espace MMS, slash, point, etc.)."""
    sep_br = "$BR$" if rcb_type == "BR" else "$RP$"
    variantes: list[str] = []

    # Réf déjà avec $BR$/$RP$ (ex. CLI) : essayer telle quelle puis avec espace au lieu de /
    if "$BR$" in rcb_ref or "$RP$" in rcb_ref:
        variantes.append(rcb_ref)
        if "/" in rcb_ref:
            variantes.append(rcb_ref.replace("/", " ", 1))  # format MMS vu sur le fil : "LD LN$BR$..."
        return variantes

    if "." not in rcb_ref:
        return [rcb_ref]

    ld_ln, nom = rcb_ref.rsplit(".", 1)

    # Format MMS tel que vu dans Wireshark : "VMC7_1LD0 LLN0$BR$CB_..." (espace entre LD et LN)
    ld_ln_espace = ld_ln.replace("/", " ", 1)
    variantes.append(f"{ld_ln_espace}{sep_br}{nom}")
    variantes.append(rcb_ref)
    variantes.append(f"{ld_ln}{sep_br}{nom}")

    # Sans préfixe "CB_" dans le chemin MMS
    if nom.startswith("CB_"):
        nom_sans_cb = nom[3:]
        variantes.append(f"{ld_ln_espace}{sep_br}{nom_sans_cb}")
        variantes.append(f"{ld_ln}.{nom_sans_cb}")
        variantes.append(f"{ld_ln}{sep_br}{nom_sans_cb}")

    # Préfixes BRCB/URCB
    variantes.append(f"{ld_ln_espace}{sep_br}BRCB_{nom}")
    variantes.append(f"{ld_ln_espace}{sep_br}URCB_{nom}")

    return variantes


def _get_rcb_ref_qui_marche(
    report_client: ReportClient, rcb_ref: str, rcb_type: str
) -> str | None:
    """Essaie plusieurs formats de référence ; retourne celle qui réussit ou None."""
    for ref in _ref_variantes(rcb_ref, rcb_type):
        try:
            report_client.get_rcb_values(ref)
            return ref
        except (ReadError, ReportConfigError, ReportError, Exception):
            continue
    return None


def affiche_rcbs(report_client: ReportClient, refs: list[tuple[str, str]]) -> None:
    """Affiche pour chaque RCB la config (dataset, rptEna, rptId, etc.)."""
    print("\n" + "=" * 60)
    print("REPORT CONTROL BLOCKS (RCB)")
    print("=" * 60)

    for rcb_ref, rcb_type in refs:
        ref_ok = _get_rcb_ref_qui_marche(report_client, rcb_ref, rcb_type)
        print(f"\n  {ref_ok or rcb_ref}  [{rcb_type}]")
        if not ref_ok:
            print(f"    (aucun format de référence accepté par l'IED)")
            continue
        try:
            cfg = report_client.get_rcb_values(ref_ok)
            if cfg.data_set:
                print(f"    DataSet : {cfg.data_set}")
            if cfg.rpt_id is not None:
                print(f"    RptId   : {cfg.rpt_id}")
            if cfg.rpt_ena is not None:
                print(f"    RptEna  : {cfg.rpt_ena}")
            if cfg.integrity_period is not None and cfg.integrity_period:
                print(f"    IntgPd  : {cfg.integrity_period} ms")
        except Exception as e:
            print(f"    (config non lue : {e})")


def callback_report(report: Report) -> None:
    """Appelé à chaque réception d'un report."""
    print("\n--- REPORT ---")
    print(f"  RCB    : {report.rcb_reference}")
    print(f"  RptId  : {report.rpt_id}")
    print(f"  DataSet: {report.data_set_name}")
    print(f"  SeqNum : {report.seq_num}  (entries: {len(report.entries)})")
    for i, entry in enumerate(report.entries):
        val = entry.value
        reason = getattr(entry, "reason_code", None)
        r = f"  reason={reason}" if reason is not None else ""
        print(f"    [{i}] {val}{r}")
    print("---")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        script = argv[0] if argv else "mms_reports.py"
        print(f"Usage : {script} <ip_serveur> [port] [réf_RCB...]")
        print(f"Exemple : {script} 10.132.159.191 102")
        print(f"Exemple : {script} 10.132.159.191 102 \"VMC7_2LD0/LLN0$BR$CB_LDPX_DQPO01\"")
        return 1

    host = argv[1]
    port = 102
    refs_cli: list[str] = []
    idx = 2
    if len(argv) > 2 and argv[2].isdigit():
        port = int(argv[2])
        idx = 3
        refs_cli = argv[idx:] if idx <= len(argv) else []
        if refs_cli and not ("$BR$" in " ".join(refs_cli) or "$RP$" in " ".join(refs_cli)):
            print("  (Astuce : si la réf RCB contient $, utiliser des guillemets simples : 'LD/LN$BR$nom')")

    with MMSClient() as client:
        try:
            print(f"Connexion à {host}:{port} ...")
            client.connect(host, port)
            print("Connexion réussie.")
        except ConnectionFailedError as e:
            print(f"ERREUR : {e}")
            return 1

        report_client = ReportClient(client)
        conn = client._connection

        if refs_cli:
            # Références fournies en argument : pas de découverte, on s'abonne uniquement à celles-ci
            rcb_list = [
                (ref, "BR" if "$BR$" in ref else "RP")
                for ref in refs_cli
            ]
            print(f"\n{len(rcb_list)} RCB demandé(s) en ligne de commande.")
        else:
            # Découverte de tous les RCB
            rcb_list = decouvre_rcbs(client)
            if not rcb_list:
                print("Aucun RCB trouvé sur l'IED.")
                return 0
            print(f"\n{len(rcb_list)} RCB trouvé(s).")
            affiche_rcbs(report_client, rcb_list)
            if rcb_list:
                print("\n  (Si aucun RCB n'a affiché de config ci‑dessus, consulter le SCL ou la doc")
                print("   du constructeur pour le format MMS exact des Report Control Blocks.)")

        # Abonnement
        print("\n" + "=" * 60)
        print("ABONNEMENT AUX REPORTS (Ctrl+C pour quitter)")
        print("=" * 60)

        abonne_refs: list[str] = []
        for rcb_ref, rcb_type in rcb_list:
            ref_ok = _get_rcb_ref_qui_marche(report_client, rcb_ref, rcb_type) or rcb_ref
            try:
                cfg = report_client.get_rcb_values(ref_ok)
                rpt_id = cfg.rpt_id or "rpt1"
                report_client.install_report_handler(ref_ok, rpt_id, callback_report)
                report_client.enable_reporting(ref_ok)
                print(f"  Abonné : {ref_ok}")
                abonne_refs.append(ref_ok)
            except (ReadError, ReportConfigError, ReportError) as e:
                print(f"  Ignoré : {ref_ok} — {e}")

        print(f"\n  → {len(abonne_refs)} abonnement(s) réussi(s), {len(rcb_list) - len(abonne_refs)} ignoré(s).")

        # Boucle de réception (traitement des messages MMS entrants)
        stop = [False]

        def sigint(_sig, _frame):
            stop[0] = True

        signal.signal(signal.SIGINT, sigint)
        signal.signal(signal.SIGTERM, sigint)

        print("\nEn attente de reports...\n")
        try:
            while not stop[0]:
                _iec61850.IedConnection_tick(conn)
                time.sleep(0.02)
        except KeyboardInterrupt:
            pass

        # Désactivation des reports à la sortie (uniquement ceux qu'on a activés)
        for rcb_ref in abonne_refs:
            try:
                report_client.disable_reporting(rcb_ref)
            except Exception:
                pass
        report_client.uninstall_all_handlers()
        print("\nDéconnexion.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
