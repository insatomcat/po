"""Parse SCL/ICD (IEC 61850-6) pour extraire les DataSet et leurs membres (FCDA).

Utilisation :
    from scl_parser import parse_scl_data_set_members, parse_scl_data_set_members_with_components
    labels = parse_scl_data_set_members("fichier.icd")
    labels, components = parse_scl_data_set_members_with_components("fichier.icd")
    # components[ds_key]["A.phsA"] = ["mag", "ang"]  (noms des composants depuis DataTypeTemplates)
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple


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


def _fcda_do_da(fcda: ET.Element) -> Tuple[str, str]:
    """Retourne (doName, daName) pour la résolution DataTypeTemplates. Si doName='A.phsA' sans daName, décompose en ('A', 'phsA')."""
    do = fcda.get("doName") or fcda.get("do") or ""
    da = fcda.get("daName") or fcda.get("da") or ""
    if da:
        return do.strip("."), da
    if "." in do:
        parts = do.split(".", 1)
        return parts[0], parts[1]
    return do, ""


def _find_ln_type_for_fcda(ied_elem: ET.Element, fcda: ET.Element) -> str:
    """Retourne le lnType du LN référencé par le FCDA (ldInst, lnClass, lnInst) dans cet IED."""
    fcda_ld = fcda.get("ldInst") or ""
    fcda_lnclass = fcda.get("lnClass") or ""
    fcda_lninst = fcda.get("lnInst") or ""
    for ap in ied_elem:
        if not _tag(ap, "AccessPoint"):
            continue
        for server in ap:
            if not _tag(server, "Server"):
                continue
            for ld in server:
                if not _tag(ld, "LDevice"):
                    continue
                if (ld.get("inst") or "") != fcda_ld:
                    continue
                for ln in ld:
                    if _ns(ln.tag) not in ("LN0", "LN"):
                        continue
                    if (ln.get("lnClass") or "") != fcda_lnclass or (ln.get("inst") or "") != fcda_lninst:
                        continue
                    return ln.get("lnType") or ""
    return ""


def _parse_data_type_templates(
    root: ET.Element,
) -> Tuple[Dict[str, Dict[str, str]], Dict[str, Dict[str, str]], Dict[str, List[str]]]:
    """
    Parse DataTypeTemplates : LNodeType id -> { DO name -> type }, DOType id -> { DA name -> type }, DAType id -> [BDA names].
    """
    lnodetypes: Dict[str, Dict[str, str]] = {}
    dotypes: Dict[str, Dict[str, str]] = {}
    datypes: Dict[str, List[str]] = {}

    templates = None
    for elem in root.iter():
        if _tag(elem, "DataTypeTemplates"):
            templates = elem
            break
    if templates is None:
        return lnodetypes, dotypes, datypes

    for elem in templates:
        if _tag(elem, "LNodeType"):
            lid = elem.get("id") or ""
            if not lid:
                continue
            do_map: Dict[str, str] = {}
            for do in elem:
                if _tag(do, "DO"):
                    name = do.get("name") or ""
                    typ = do.get("type") or ""
                    if name:
                        do_map[name] = typ
            lnodetypes[lid] = do_map
        elif _tag(elem, "DOType"):
            did = elem.get("id") or ""
            if not did:
                continue
            da_map = {}
            for da in elem:
                if _tag(da, "DA"):
                    name = da.get("name") or ""
                    typ = da.get("type") or da.get("bType") or ""
                    if name:
                        da_map[name] = typ
            dotypes[did] = da_map
        elif _tag(elem, "DAType"):
            aid = elem.get("id") or ""
            if not aid:
                continue
            bdas = [bda.get("name") or "" for bda in elem if _tag(bda, "BDA")]
            bdas = [n for n in bdas if n]
            datypes[aid] = bdas

    return lnodetypes, dotypes, datypes


def _resolve_fcda_components(
    do_name: str,
    da_name: str,
    ln_type: str,
    lnodetypes: Dict[str, Dict[str, str]],
    dotypes: Dict[str, Dict[str, str]],
    datypes: Dict[str, List[str]],
) -> Optional[List[str]]:
    """Pour un FCDA (doName, daName) et un lnType, retourne la liste des noms de composants (ex. [mag, ang]) ou None."""
    do_map = lnodetypes.get(ln_type)
    if not do_map:
        return None
    do_type = do_map.get(do_name)
    if not do_type:
        return None
    da_map = dotypes.get(do_type)
    if not da_map:
        return None
    da_type = da_map.get(da_name)
    if not da_type:
        return None
    return datypes.get(da_type)


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


def parse_scl_data_set_members_with_components(
    path: str | Path,
) -> Tuple[Dict[str, List[str]], Dict[str, Dict[str, List[str]]]]:
    """
    Comme parse_scl_data_set_members, et en plus retourne pour chaque data set
    les noms des composants par membre (ex. A.phsA -> [mag, ang]) depuis DataTypeTemplates.
    """
    tree = ET.parse(path)
    root = tree.getroot()
    lnodetypes, dotypes, datypes = _parse_data_type_templates(root)

    result: Dict[str, List[str]] = {}
    components: Dict[str, Dict[str, List[str]]] = {}  # key -> { member_label -> [comp0, comp1, ...] }

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
                        ln_type = ln.get("lnType") or ""

                        for ds in ln:
                            if not _tag(ds, "DataSet"):
                                continue
                            ds_name = ds.get("name") or ""
                            if not ds_name:
                                continue

                            members_list: List[str] = []
                            comp_map: Dict[str, List[str]] = {}
                            for fcda in ds:
                                if _tag(fcda, "FCDA"):
                                    do_name, da_name = _fcda_do_da(fcda)
                                    label = _fcda_label(fcda)
                                    members_list.append(label)
                                    fcda_ln_type = _find_ln_type_for_fcda(ied, fcda) or ln_type
                                    if fcda_ln_type and do_name and da_name:
                                        comp_names = _resolve_fcda_components(
                                            do_name, da_name, fcda_ln_type,
                                            lnodetypes, dotypes, datypes,
                                        )
                                        if comp_names:
                                            comp_map[label] = comp_names
                                elif _tag(fcda, "FCCB"):
                                    members_list.append(fcda.get("cbName") or "FCCB")

                            if not members_list:
                                continue

                            for key in _data_set_keys(ied_name, ld_inst, ln_class, ln_inst, ds_name):
                                result[key] = members_list
                                if comp_map:
                                    components[key] = comp_map

    return result, components
