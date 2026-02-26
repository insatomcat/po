#!/usr/bin/env python3
"""
Script de debug de connexion IEC 61850 / libiec61850.

Utilise les bindings bas niveau pour afficher le code d'erreur exact
retourné par IedConnection_connect().

Usage :
    python mms_debug_connect.py <ip_serveur> [port]

Exemples :
    python mms_debug_connect.py 10.132.159.191
    python mms_debug_connect.py 10.132.159.191 102
"""

import sys

import pyiec61850.pyiec61850 as iec61850


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        script = argv[0] if argv else "mms_debug_connect.py"
        print(f"Usage : {script} <ip_serveur> [port]")
        return 1

    host = argv[1]
    port = 102

    if len(argv) > 2:
        try:
            port = int(argv[2])
        except ValueError:
            print(f"Port invalide : {argv[2]!r}")
            return 1

    print(f"Tentative de connexion libiec61850 vers {host}:{port}")

    conn = iec61850.IedConnection_create()
    raw = iec61850.IedConnection_connect(conn, host, port)

    # Le binding SWIG peut retourner un tuple (ret, error) au lieu d'un entier
    if isinstance(raw, tuple):
        print(f"Retour binding (tuple)  : {raw}")
        error = raw[1] if len(raw) > 1 else raw[0]
        if len(raw) > 1 and raw[1] == 0 and raw[0] is None:
            print("Interprétation          : erreur=0 (IED_ERROR_OK) mais 1er élément None.")
            print("                         Souvent lié à association MMS rejetée ou TLS requis.")
    else:
        error = raw
        print(f"Code d'erreur numérique : {error}")

    error_name = None
    for name in dir(iec61850):
        if not name.startswith("IED_ERROR_"):
            continue
        try:
            if getattr(iec61850, name) == error:
                error_name = name
                break
        except Exception:
            continue

    if error_name:
        print(f"Constante d'erreur      : {error_name}")
    else:
        print(f"Constante d'erreur      : inconnue (valeur={error!r})")

    # Nettoyage connexion
    try:
        iec61850.IedConnection_close(conn)
    except Exception:
        pass

    iec61850.IedConnection_destroy(conn)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

