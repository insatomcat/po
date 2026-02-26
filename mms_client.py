#!/usr/bin/env python3
"""
Client MMS IEC 61850 en ligne de commande.

Ce script se connecte à un serveur IEC 61850 via MMS, lit des valeurs
et affiche les réponses.

Usage :
    python mms_client.py <ip_serveur> [port] [objet_iec61850...]

Exemples :
    python mms_client.py 192.168.1.100
    python mms_client.py 192.168.1.100 102 "LD0/MMXU1.TotW"
    python mms_client.py localhost 10102

Si aucun objet n'est passé en argument, le script parcourt le modèle
de données (quelques devices/nœuds/objets) et lit quelques valeurs
pour montrer le principe.
"""

import sys
from typing import List, Optional

# Contournement : certains bindings SWIG retournent (None, error_code) au lieu
# d'un entier pour IedConnection_connect ; on normalise pour que 0 = succès.
import pyiec61850.pyiec61850 as _iec61850

_orig_connect = _iec61850.IedConnection_connect

def _unwrap_connect(conn, host, port):
    out = _orig_connect(conn, host, port)
    if isinstance(out, tuple) and len(out) > 1:
        return out[1]  # code d'erreur (0 = IED_ERROR_OK)
    return out


_iec61850.IedConnection_connect = _unwrap_connect

from pyiec61850.mms import (
    MMSClient,
    ConnectionFailedError,
    ReadError,
    MMSError,
    LinkedListGuard,
    unpack_result,
)


def _est_valeur_simple(valeur: object) -> bool:
    """True si la valeur est un type simple (int, float, bool, str lisible), pas une structure MMS."""
    if isinstance(valeur, (bool, int, float)):
        return True
    if isinstance(valeur, str) and not valeur.startswith("<MmsValue"):
        return True
    return False


def lire_et_afficher(client: MMSClient, ref_objet: str) -> Optional[object]:
    """
    Lit un objet de données IEC 61850 et affiche sa valeur.

    :param client: instance MMSClient déjà connectée
    :param ref_objet: référence complète (ex: "LD0/MMXU1.TotW.mag.f")
    :return: valeur lue, ou None en cas d'erreur
    """
    print(f"\nLecture de : {ref_objet}")

    try:
        valeur = client.read_value(ref_objet)
        print(f"  Valeur : {valeur}")
        return valeur
    except ReadError as exc:
        print(f"  Échec de la lecture : {exc}")
        return None


# Chemins d'attributs courants (CDC IEC 61850) à essayer quand le serveur
# ne renvoie pas la liste des attributs (GetDirectory vide).
_CHEMINS_ATTR_FALLBACK = (
    "stVal", "mag.f", "d", "q", "t",
    "phsA.cVal.mag.f", "phsB.cVal.mag.f", "phsC.cVal.mag.f",
    "cVal.mag.f", "mag.i", "mag.f",
)


def _lit_attributs_fallback(
    client: MMSClient,
    device: str,
    node: str,
    do_path: str,
    max_feuilles_par_do: int,
    nb_feuilles: List[int],
) -> None:
    """
    Quand get_data_attributes ne renvoie rien, tente de lire des attributs
    courants (stVal, mag.f, d, etc.) pour afficher au moins quelques valeurs.
    """
    base_ref = f"{device}/{node}.{do_path}"
    for suffix in _CHEMINS_ATTR_FALLBACK:
        if nb_feuilles[0] >= max_feuilles_par_do:
            return
        ref = f"{base_ref}.{suffix}"
        try:
            valeur = client.read_value(ref)
        except ReadError:
            continue
        if _est_valeur_simple(valeur):
            print(f"  {ref}")
            print(f"    → {valeur}")
            nb_feuilles[0] += 1


def _decouvre_attributs_et_lit(
    client: MMSClient,
    device: str,
    node: str,
    do_path: str,
    depth: int,
    max_depth: int,
    max_feuilles_par_do: int,
    nb_feuilles: List[int],
) -> None:
    """
    Récursivement découvre les data attributes sous un DO (ou sous-attribut)
    et lit les feuilles pour afficher des valeurs simples.
    Si le serveur ne liste pas les attributs, utilise un jeu de chemins courants.
    """
    if depth >= max_depth or nb_feuilles[0] >= max_feuilles_par_do:
        return

    try:
        attrs = client.get_data_attributes(device, node, do_path)
    except Exception:
        attrs = []

    if not attrs:
        # Pas d'attributs listés par l'IED : essai de chemins courants (stVal, mag.f, etc.)
        if depth == 0:
            _lit_attributs_fallback(
                client, device, node, do_path, max_feuilles_par_do, nb_feuilles
            )
        return

    for attr in attrs:
        if nb_feuilles[0] >= max_feuilles_par_do:
            return
        ref = f"{device}/{node}.{do_path}.{attr}" if do_path else f"{device}/{node}.{attr}"
        try:
            valeur = client.read_value(ref)
        except ReadError:
            continue

        if _est_valeur_simple(valeur):
            print(f"  {ref}")
            print(f"    → {valeur}")
            nb_feuilles[0] += 1
        else:
            # Structure ou type non mappé : descendre si on peut
            sous_chemin = f"{do_path}.{attr}" if do_path else attr
            _decouvre_attributs_et_lit(
                client, device, node, sous_chemin, depth + 1, max_depth, max_feuilles_par_do, nb_feuilles
            )


def parcourir_et_lire(client: MMSClient) -> None:
    """
    Découvre une partie du modèle (LD/LN/DataObject) et lit quelques valeurs.
    """
    print("\n" + "=" * 60)
    print("PARCOURS DU MODÈLE & LECTURE DE VALEURS")
    print("=" * 60)

    devices = client.get_logical_devices()
    if not devices:
        print("Aucun logical device trouvé sur le serveur.")
        return

    print(f"\nLogical devices trouvés : {len(devices)}")

    # Certaines versions de libiec61850 ne fournissent pas le helper
    # IedConnection_getLogicalNodeList utilisé par MMSClient.get_logical_nodes().
    # On contourne en utilisant directement IedConnection_getLogicalDeviceDirectory
    # via la connexion interne du client.

    conn = getattr(client, "_connection", None)
    if conn is None:
        print("Connexion MMS interne indisponible, impossible de parcourir le modèle.")
        return

    # On parcourt tous les logical devices trouvés
    for device in devices:
        print(f"\n--- Device : {device} ---")

        # Récupération des logical nodes du device via l'API bas niveau
        try:
            result = _iec61850.IedConnection_getLogicalDeviceDirectory(conn, device)
            value, error, ok = unpack_result(result)

            if not ok or not value:
                print(
                    "  Impossible de lister les logical nodes pour ce device "
                    "(appel IedConnection_getLogicalDeviceDirectory en échec)."
                )
                print(
                    "  Utilise plutôt des références complètes en argument, "
                    'par ex. "LD0/MMXU1.TotW" ou "VMC7_1LD0/MMXU1.TotW".'
                )
                continue

            with LinkedListGuard(value) as guard:
                nodes = list(guard)

        except Exception as exc:
            print(
                "  Erreur lors de la découverte des logical nodes pour ce device : "
                f"{exc}"
            )
            print(
                "  Utilise plutôt des références complètes en argument, "
                'par ex. "LD0/MMXU1.TotW" ou "VMC7_1LD0/MMXU1.TotW".'
            )
            continue

        if not nodes:
            print("  Aucun logical node trouvé pour ce device.")
            continue

        for node in nodes[:3]:
            data_objects = client.get_data_objects(device, node)
            if not data_objects:
                continue

            for obj in data_objects[:3]:
                # Découverte récursive des attributs pour atteindre les feuilles (stVal, mag.f, etc.)
                print(f"\n  DO : {device}/{node}.{obj}")
                nb_feuilles = [0]
                _decouvre_attributs_et_lit(
                    client, device, node, obj, depth=0, max_depth=6, max_feuilles_par_do=25, nb_feuilles=nb_feuilles
                )


def lire_objets_specifiques(client: MMSClient, refs: List[str]) -> None:
    """
    Lit un ensemble de références passées en argument.
    """
    print("\n" + "=" * 60)
    print("LECTURE D'OBJETS SPÉCIFIQUES")
    print("=" * 60)

    ok = 0
    ko = 0

    for ref in refs:
        valeur = lire_et_afficher(client, ref)
        if valeur is not None:
            ok += 1
        else:
            ko += 1

    print(f"\nRésumé : {ok} lecture(s) réussie(s), {ko} en échec.")


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        script = argv[0] if argv else "mms_client.py"
        print(f"Usage : {script} <ip_serveur> [port] [objet_iec61850...]")
        print(f"Exemple 1 : {script} 192.168.1.100")
        print(f"Exemple 2 : {script} localhost 10102")
        print(f'Exemple 3 : {script} 192.168.1.100 102 "LD0/MMXU1.TotW"')
        return 1

    hostname = argv[1]
    port = 102
    refs: List[str] = []

    if len(argv) > 2:
        try:
            port = int(argv[2])
            refs = argv[3:]
        except ValueError:
            # Si l'argument 2 n'est pas un entier, on le traite comme une référence
            refs = argv[2:]

    with MMSClient() as client:
        try:
            print(f"Connexion au serveur IEC 61850 {hostname}:{port} ...")
            client.connect(hostname, port)
            print("Connexion réussie.")

            identite = client.get_server_identity()
            print(
                "\nIdentité du serveur : "
                f"{getattr(identite, 'vendor', '?')} "
                f"{getattr(identite, 'model', '?')}"
            )

            if refs:
                lire_objets_specifiques(client, refs)
            else:
                parcourir_et_lire(client)

        except ConnectionFailedError as exc:
            print(f"ERREUR : connexion impossible - {exc}")
            return 1
        except MMSError as exc:
            print(f"ERREUR : échec d'une opération MMS - {exc}")
            return 1

    print("\nConnexion fermée. Terminé.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

