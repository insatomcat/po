#!/usr/bin/env python3
"""
Récupération des données en continu par POLLING (lecture périodique).

Avec pyiec61850-ng on ne peut pas recevoir les reports (push), mais on peut
lire les valeurs à intervalle régulier : tu obtiens les mêmes infos en "pull".

Usage par références :
    python mms_poll.py <ip> <intervalle_sec> [port] <réf1> [réf2 ...]

Usage utile : poller le DataSet d'un RCB (ex. CB_LDPX_DQPO01) :
    python mms_poll.py <ip> <intervalle_sec> [port] --rcb 'VMC7_1LD0 LLN0$BR$CB_LDPX_DQPO01'

Ctrl+C pour arrêter.
"""

import os
import signal
import sys
import time
from datetime import datetime, timezone

# Même contournement connexion que mms_client
import pyiec61850.pyiec61850 as _iec61850

_orig_connect = _iec61850.IedConnection_connect

def _unwrap_connect(conn, host, port):
    out = _orig_connect(conn, host, port)
    if isinstance(out, tuple) and len(out) > 1:
        return out[1]
    return out


_iec61850.IedConnection_connect = _unwrap_connect

from pyiec61850.mms import MMSClient, ConnectionFailedError, ReadError, MMSError
from pyiec61850.mms.reporting import ReportClient


def _mms_to_python(val) -> str:
    """Convertit un MmsValue simple en str affichable."""
    if val is None:
        return "?"
    try:
        t = _iec61850.MmsValue_getType(val)
        if t == getattr(_iec61850, "MMS_BOOLEAN", 2):
            return str(bool(_iec61850.MmsValue_getBoolean(val)))
        if t == getattr(_iec61850, "MMS_INTEGER", 4):
            return str(_iec61850.MmsValue_toInt32(val))
        if t == getattr(_iec61850, "MMS_UNSIGNED", 5):
            return str(_iec61850.MmsValue_toUint32(val))
        if t == getattr(_iec61850, "MMS_FLOAT", 6):
            return str(_iec61850.MmsValue_toFloat(val))
        if t in (getattr(_iec61850, "MMS_VISIBLE_STRING", 8), getattr(_iec61850, "MMS_STRING", 13)):
            return _iec61850.MmsValue_toString(val) or "?"
        if t == getattr(_iec61850, "MMS_BIT_STRING", 3):
            return str(_iec61850.MmsValue_getBitStringAsInteger(val))
    except Exception:
        pass
    return "?"


def _lire_dataset(conn, dataset_ref: str) -> list[str] | None:
    """Lit un data set par référence ; retourne la liste des valeurs (str) ou None."""
    try:
        client_ds = _iec61850.IedConnection_readDataSetValues(conn, dataset_ref, None)
        if not client_ds:
            return None
        n = _iec61850.ClientDataSet_getDataSetSize(client_ds)
        values = _iec61850.ClientDataSet_getValues(client_ds)
        if not values or n <= 0:
            _iec61850.ClientDataSet_destroy(client_ds)
            return None
        out = []
        for i in range(n):
            elt = _iec61850.MmsValue_getElement(values, i)
            out.append(_mms_to_python(elt))
        _iec61850.ClientDataSet_destroy(client_ds)
        return out
    except Exception:
        return None


def main(argv: list[str]) -> int:
    # Repérer --rcb et reconstruire la réf RCB (le shell peut tronquer après $ ou espace)
    rcb_ref: str | None = None
    consumed: set[int] = set()
    for i, a in enumerate(argv):
        if a in ("--rcb", "-rcb"):
            if i + 1 < len(argv):
                parts = []
                for j in range(i + 1, len(argv)):
                    parts.append(argv[j])
                    consumed.add(j)
                    joined = " ".join(parts)
                    if "$BR$" in joined or "$RP$" in joined:
                        rcb_ref = joined
                        consumed.add(i)
                        break
            if rcb_ref is None:
                # Réf depuis la variable d'env (évite que le shell interprète les $)
                rcb_ref = (os.environ.get("MMS_POLL_RCB_REF") or "").strip()
                if rcb_ref and ("$BR$" in rcb_ref or "$RP$" in rcb_ref):
                    consumed.add(i)
            break

    args = [a for k, a in enumerate(argv[1:]) if (k + 1) not in consumed]

    if rcb_ref and "$BR$" not in rcb_ref and "$RP$" not in rcb_ref:
        rcb_ref = None
        print("Réf RCB tronquée (les $ ont été interprétés par le shell).")
        print("Utiliser : MMS_POLL_RCB_REF='VMC7_1LD0 LLN0$BR$CB_LDPX_DQPO01' podman run -e MMS_POLL_RCB_REF ... mms_poll.py 10.132.159.191 1 102 --rcb")
        return 1

    if len(args) < 2:
        script = argv[0] if argv else "mms_poll.py"
        print(f"Usage : {script} <ip> <intervalle_sec> [port] <réf1> [réf2 ...]")
        print(f"   ou : {script} <ip> <intervalle_sec> [port] --rcb 'VMC7_1LD0 LLN0$BR$CB_LDPX_DQPO01'")
        print("  → --rcb : poll le DataSet du RCB. Si les $ disparaissent, utiliser MMS_POLL_RCB_REF (voir ci-dessus).")
        return 1

    host = args[0]
    try:
        interval_sec = float(args[1])
    except (ValueError, IndexError):
        print("L'intervalle doit être un nombre (secondes).")
        return 1

    port = 102
    refs: list[str] = []
    idx = 2
    if len(args) > 2 and args[2].isdigit():
        port = int(args[2])
        idx = 3
    if not rcb_ref:
        refs = [a for a in (args[idx:] if idx < len(args) else []) if a not in ("--rcb", "-rcb")]
        if not refs:
            print("Indique au moins une référence à lire, ou --rcb 'LD LN$BR$NomRCB'.")
            return 1

    with MMSClient() as client:
        try:
            print(f"Connexion à {host}:{port} ...")
            client.connect(host, port)
            print("Connexion réussie.")
        except ConnectionFailedError as e:
            print(f"ERREUR : {e}")
            return 1

        conn = client._connection
        dataset_ref: str | None = None

        if rcb_ref:
            report_client = ReportClient(client)
            last_err: str | None = None
            for ref_try in (rcb_ref, rcb_ref.replace("/", " ", 1)):
                try:
                    cfg = report_client.get_rcb_values(ref_try)
                    dataset_ref = (cfg.data_set or "").strip()
                    if dataset_ref:
                        break
                except Exception as e:
                    last_err = str(e)
                    dataset_ref = None
            if not dataset_ref:
                # Contournement : deviner la réf du DataSet à partir du nom RCB (ex. CB_LDPX_DQPO01 → DS_LDPX_DQPO01)
                rcb_name = ""
                if "$BR$" in rcb_ref:
                    rcb_name = rcb_ref.split("$BR$")[-1].strip()
                elif "$RP$" in rcb_ref:
                    rcb_name = rcb_ref.split("$RP$")[-1].strip()
                ld_ln = rcb_ref.split("$")[0].strip()  # "VMC7_1LD0 LLN0" ou "VMC7_1LD0/LLN0"
                for guessed in (
                    f"{ld_ln}.DS_{rcb_name[3:]}" if rcb_name.startswith("CB_") else f"{ld_ln}.DS_{rcb_name}",
                    f"{ld_ln}.{rcb_name}",
                    ld_ln.replace(" ", "/", 1) + f".DS_{rcb_name[3:]}" if rcb_name.startswith("CB_") else "",
                    ld_ln.replace(" ", "/", 1) + f".{rcb_name}",
                ):
                    if not guessed:
                        continue
                    vals_test = _lire_dataset(conn, guessed)
                    if vals_test is None and " " in guessed:
                        vals_test = _lire_dataset(conn, guessed.replace(" ", "/", 1))
                    if vals_test is not None:
                        dataset_ref = guessed
                        print(f"RCB non lisible ; DataSet deviné : {dataset_ref}")
                        break
                if not dataset_ref:
                    print(f"Impossible de lire le RCB : {rcb_ref}")
                    if last_err:
                        print(f"  Détail : {last_err}")
                    print("  → GetRCBValues non supporté ou réf MMS différente. Contournement : poll par réf explicites.")
                    return 1
            # Le DataSet peut être avec espace (format MMS) ou slash
            print(f"RCB : {rcb_ref}")
            print(f"DataSet : {dataset_ref}")
            # Tester une première lecture pour vérifier le format
            vals = _lire_dataset(conn, dataset_ref)
            if vals is None and " " in dataset_ref:
                vals = _lire_dataset(conn, dataset_ref.replace(" ", "/", 1))
            if vals is None:
                vals = _lire_dataset(conn, dataset_ref.replace("/", " ", 1))
            if vals is None:
                print("Impossible de lire le DataSet (vérifier la réf ou le format LD/LN).")
                return 1
            refs = []  # mode dataset : pas de refs manuelles
        else:
            vals = None

        if refs:
            print(f"Lecture de {len(refs)} point(s) toutes les {interval_sec}s (Ctrl+C pour arrêter).")
            header_parts = ["heure"]
            for ref in refs:
                short = ref.split(".")[-1] if "." in ref else ref.split("/")[-1]
                header_parts.append(short[:14])
            print(" | ".join(header_parts))
            print("-" * (8 * len(refs) + 20))
        else:
            print(f"Poll du DataSet ({len(vals)} membre(s)) toutes les {interval_sec}s (Ctrl+C pour arrêter).")
            header_parts = ["heure"] + [f"v{i}" for i in range(len(vals))]
            print(" | ".join(header_parts))
            print("-" * (6 * (len(vals) + 1) + 12))

        stop = [False]

        def sigint(_sig, _frame):
            stop[0] = True

        signal.signal(signal.SIGINT, sigint)
        signal.signal(signal.SIGTERM, sigint)

        while not stop[0]:
            t = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
            line: list[str] = [t]
            if refs:
                for ref in refs:
                    try:
                        val = client.read_value(ref)
                        line.append(str(val))
                    except (ReadError, MMSError):
                        line.append("ERR")
            else:
                vals = _lire_dataset(conn, dataset_ref)
                if vals is None:
                    vals = _lire_dataset(conn, dataset_ref.replace(" ", "/", 1))
                if vals is None:
                    vals = _lire_dataset(conn, dataset_ref.replace("/", " ", 1))
                if vals is not None:
                    line.extend(vals)
                else:
                    line.append("ERR")
            print(" | ".join(line))
            try:
                time.sleep(interval_sec)
            except KeyboardInterrupt:
                break

    print("\nArrêt.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
