"""Classification déclenchement GOOSE : déclenchement vs retombée via allData."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from iec_data import (
    ArrayData,
    BitStringData,
    BoolData,
    IECData,
    IntData,
    StructureData,
    UIntData,
)

FlatValue = Tuple[str, Any]  # (type, value)


def _flatten_iec_data(items: List[IECData], prefix: str = "") -> Dict[str, FlatValue]:
    out: Dict[str, FlatValue] = {}
    for i, item in enumerate(items):
        path = f"{prefix}{i}" if not prefix else f"{prefix}{i}"
        if isinstance(item, BoolData):
            out[path] = ("bool", item.value)
        elif isinstance(item, (IntData, UIntData)):
            out[path] = ("int", int(item.value))
        elif isinstance(item, BitStringData):
            out[path] = ("bits", (item.value.hex(), item.unused_bits))
        elif isinstance(item, StructureData):
            out.update(_flatten_iec_data(item.members, f"{path}."))
        elif isinstance(item, ArrayData):
            out.update(_flatten_iec_data(item.elements, f"{path}."))
    return out


def _bool_transition(
    prev: Optional[FlatValue],
    curr: FlatValue,
) -> Optional[str]:
    if curr[0] != "bool":
        return None
    new_v = curr[1]
    if prev is None or prev[0] != "bool":
        return "rise" if new_v else "fall"
    old_v = prev[1]
    if old_v is False and new_v is True:
        return "rise"
    if old_v is True and new_v is False:
        return "fall"
    return None


def _int_transition(
    prev: Optional[FlatValue],
    curr: FlatValue,
) -> Optional[str]:
    if curr[0] != "int":
        return None
    new_v = int(curr[1])
    if prev is None or prev[0] != "int":
        if new_v != 0:
            return "rise"
        return None
    old_v = int(prev[1])
    if old_v == 0 and new_v != 0:
        return "rise"
    if old_v != 0 and new_v == 0:
        return "fall"
    return None


def classify_trigger(
    prev_all_data: Optional[List[IECData]],
    curr_all_data: List[IECData],
) -> Tuple[str, str, str]:
    """
    Retourne (kind, label_fr, detail).
    kind: declenchement | retombee | initial | mixte | inconnu
    """
    if prev_all_data is None:
        return "initial", "Premier", "pas de snapshot précédent"

    prev_flat = _flatten_iec_data(prev_all_data)
    curr_flat = _flatten_iec_data(curr_all_data)
    paths = sorted(set(prev_flat) | set(curr_flat))

    rises: List[str] = []
    falls: List[str] = []
    details: List[str] = []

    for path in paths:
        pv = prev_flat.get(path)
        cv = curr_flat.get(path)
        if pv == cv:
            continue
        tr = _bool_transition(pv, cv)
        if tr == "rise":
            rises.append(path)
            old_s = pv[1] if pv and pv[0] == "bool" else "?"
            details.append(f"bool[{path}]: {old_s}→True")
            continue
        if tr == "fall":
            falls.append(path)
            old_s = pv[1] if pv and pv[0] == "bool" else "?"
            details.append(f"bool[{path}]: {old_s}→False")
            continue
        tr_i = _int_transition(pv, cv)
        if tr_i == "rise":
            rises.append(path)
            pval = pv[1] if pv else "?"
            details.append(f"int[{path}]: {pval}→{cv[1]}")
        elif tr_i == "fall":
            falls.append(path)
            details.append(f"int[{path}]: {pv[1]}→{cv[1]}")

    detail = "; ".join(details[:4])
    if len(details) > 4:
        detail += f" (+{len(details) - 4})"

    if rises and not falls:
        return "declenchement", "Déclenchement", detail or f"bool↑ {', '.join(rises[:3])}"
    if falls and not rises:
        return "retombee", "Retombée", detail or f"bool↓ {', '.join(falls[:3])}"
    if len(rises) > len(falls):
        return "declenchement", "Déclenchement", detail or "transitions dominantes ↑"
    if len(falls) > len(rises):
        return "retombee", "Retombée", detail or "transitions dominantes ↓"
    if rises or falls:
        return "mixte", "Mixte", detail
    return "inconnu", "Inconnu", detail or "aucun bool/int discriminant changé"
