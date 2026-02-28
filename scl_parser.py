"""Parse SCL/ICD (IEC 61850-6) pour extraire les DataSet et leurs membres (FCDA).

Utilisation :
    from scl_parser import parse_scl_data_set_members
    labels = parse_scl_data_set_members("fichier.icd")
    # labels["VMC7_1LD0/LLN0$DS_LDPHAS1_CYPO"] = ["Beh.stVal", "Mod.stVal", ...]
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List


def _ns(tag: str) -> str:
    """Retire le préfixe de namespace pour matcher {http://...}localName."""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _tag(elem: ET.Element, local: str) -> bool:
    return _ns(elem.tag) == local


def _fcda_label(fcda: ET.Element) -> str:
    """Libellé lisible pour un FCDA : doName ou doName.daName."""
    do = fcda.get("doName") or fcda.get("do") or ""
    da = fcda.get("daName") or fcda.get("da") or ""
    if da:
        return f"{do}.{da}".strip(".")
    return do or "?"


def _data_set_keys(ied_name: str, ld_inst: str, ln_class: str, ln_inst: str, ds_name: str) -> List[str]:
    """Construit les clés possibles pour matcher report.data_set_name (formats courants)."""
    # Format type rapport MMS : "VMC7_1LD0/LLN0$DS_LDPHAS1_CYPO"
    keys = []
    ln_part = f"{ln_class}{ln_inst}" if ln_inst and ln_inst != "0" else ln_class
    # Avec et sans instance (les reports utilisent souvent "LLN0" sans le "1")
    ln_variants = [ln_part]
    if ln_part != ln_class:
        ln_variants.append(ln_class)
    for ln in ln_variants:
        keys.append(f"{ied_name}/{ln}${ds_name}")
        keys.append(f"{ied_name}_1{ld_inst}/{ln}${ds_name}")
    keys.append(f"{ied_name}/{ld_inst}${ds_name}")
    keys.append(f"{ied_name}_1{ld_inst}/{ld_inst}${ds_name}")
    seen = set()
    return [k for k in keys if k not in seen and not seen.add(k)]


def parse_scl_data_set_members(
    path: str | Path,
) -> Dict[str, List[str]]:
    """
    Parse un fichier SCL ou ICD et retourne un dictionnaire :
      clé = identifiant du data set (pour matcher report.data_set_name),
      valeur = liste des libellés des membres (FCDA) dans l'ordre.

    Plusieurs clés peuvent pointer vers la même liste (formats de nom différents).
    """
    tree = ET.parse(path)
    root = tree.getroot()

    result: Dict[str, List[str]] = {}

    # Parcours IED -> AccessPoint -> Server -> LDevice -> LN0/LN -> DataSet -> FCDA
    for ied in root.iter():
        if not _tag(ied, "IED"):
            continue
        ied_name = ied.get("name") or ""
        if not ied_name:
            continue

        for ap in ied:
            if not _tag(ap, "AccessPoint"):
                continue
            for server in ap:
                if not _tag(server, "Server"):
                    continue
                for ld in server:
                    if not _tag(ld, "LDevice"):
                        continue
                    ld_inst = ld.get("inst") or ""

                    for ln in ld:
                        ln_tag = _ns(ln.tag)
                        if ln_tag not in ("LN0", "LN"):
                            continue
                        ln_class = ln.get("lnClass") or ""
                        ln_inst = ln.get("inst") or ""

                        for ds in ln:
                            if not _tag(ds, "DataSet"):
                                continue
                            ds_name = ds.get("name") or ""
                            if not ds_name:
                                continue

                            members: List[str] = []
                            for fcda in ds:
                                if _tag(fcda, "FCDA"):
                                    members.append(_fcda_label(fcda))
                                elif _tag(fcda, "FCCB"):
                                    members.append(fcda.get("cbName") or "FCCB")
                                # FCB optionnel, on peut l'ignorer ou ajouter un libellé

                            if not members:
                                continue

                            for key in _data_set_keys(ied_name, ld_inst, ln_class, ln_inst, ds_name):
                                result[key] = members

    return result
