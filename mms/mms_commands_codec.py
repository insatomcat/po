"""
Encodage (BER) minimal pour des commandes MMS type IEC 61850.

Hypothèses basées sur un exemple fourni (commande écriture sur *. $CO$Pos$Oper) :
  - la commande est encodée comme un MMS write via `encode_mms_set_rcb_attribute`
  - seul le BIT STRING de `ctlVal` (dernières 2 octets du template) dépend de la position
"""

from __future__ import annotations

import time
from typing import Literal

from .asn1_codec import encode_mms_set_rcb_attribute


# Templates BER (valeur) issus de deux requêtes IEDscout consécutives
# (PDUs 101 bytes) sur `...$CO$Pos$Oper`.
#
# Dans les deux cas, seule la BIT STRING finale `84 02 <word16>` dépend
# de la "position" (open/closed/intermediate). Le reste de la valeur est
# différent entre step1/step2 (SBO / test / execution).

_VALUE_TEMPLATE_STEP1_HEX = (
    "a222830100a209850103890413d5c007860100910869babddddc36a53f"
    "830100840206c0"
)
_VALUE_TEMPLATE_STEP2_HEX = (
    "a222830101a209850103890413d5c007860100910869babde5ce24963f"
    "830100840206c0"
)

_VALUE_TEMPLATE_STEP1_BASE = bytes.fromhex(_VALUE_TEMPLATE_STEP1_HEX)
_VALUE_TEMPLATE_STEP2_BASE = bytes.fromhex(_VALUE_TEMPLATE_STEP2_HEX)


Position = Literal["open", "closed", "intermediate", "testbascule"]

# Analyse des PDUs IEDscout capturés sur le terrain :
#   - les deux commandes (open et close) utilisent ctlVal=0x06C0
#   - la seule différence fonctionnelle est le ctlNum : 0 pour une direction, 1 pour l'autre
#   - l'IED détermine la direction via ctlNum, PAS via ctlVal
_CTLNUM_FOR_POSITION: dict[str, int] = {
    "open":   0,   # ctlNum=0 → ouvre le DJ (PDU IEDscout "open")
    "closed": 1,   # ctlNum=1 → ferme le DJ (PDU IEDscout "close")
}
_CTLVAL_BASCULE = 0x06C0  # valeur commune aux deux directions


def _bitstring_for_position(pos: Position) -> int:
    # Toutes les commandes utilisent 0x06C0 ; la direction est dans ctlNum.
    # Les valeurs spécifiques sont conservées pour des tests éventuels.
    if pos == "testbascule":
        return 0x06C0
    if pos == "intermediate":
        return 0x0600
    # open et closed : ctlVal=0x06C0 (direction via ctlNum)
    return _CTLVAL_BASCULE


def _ctlnum_for_position(pos: Position, fallback: int) -> int:
    """Retourne le ctlNum imposé par la direction, ou `fallback` si non défini."""
    return _CTLNUM_FOR_POSITION.get(pos, fallback)


def _render_value_for_position_from_template(pos: Position, base: bytes) -> bytes:
    t = bytearray(base)
    # Met à jour le timestamp IEC 61850 (tag 91 08) pour éviter de rejouer
    # exactement la même commande avec un temps figé.
    _refresh_iec61850_timestamp_inplace(t)
    # Attendu : ... 84 02 <hi> <lo>
    if len(t) < 4 or t[-4] != 0x84 or t[-3] != 0x02:
        raise ValueError("Template value: structure inattendue (bitstring final introuvable)")
    word16 = _bitstring_for_position(pos)
    t[-2] = (word16 >> 8) & 0xFF
    t[-1] = word16 & 0xFF
    return bytes(t)


def _set_first_ctl_num_inplace(buf: bytearray, ctl_num: int) -> None:
    """Met à jour le premier champ 83 01 xx (ctlNum) du template valeur."""
    ctl_num &= 0xFF
    marker = b"\x83\x01"
    idx = bytes(buf).find(marker)
    if idx < 0:
        return
    val_idx = idx + 2
    if val_idx < len(buf):
        buf[val_idx] = ctl_num


def _encode_iec61850_timestamp_now() -> bytes:
    """
    TimeStamp IEC 61850 sur 8 octets:
      - 4 octets secondes epoch
      - 3 octets fraction de seconde (24 bits)
      - 1 octet quality
    """
    now = time.time()
    sec = int(now)
    frac = int((now - sec) * (1 << 24)) & 0xFFFFFF
    quality = 0x3F  # conservé comme dans les templates observés
    return (
        sec.to_bytes(4, "big")
        + bytes([(frac >> 16) & 0xFF, (frac >> 8) & 0xFF, frac & 0xFF, quality])
    )


def _refresh_iec61850_timestamp_inplace(buf: bytearray) -> None:
    marker = b"\x91\x08"
    idx = bytes(buf).find(marker)
    if idx < 0:
        return
    start = idx + 2
    end = start + 8
    if end > len(buf):
        return
    buf[start:end] = _encode_iec61850_timestamp_now()


def encode_pos_oper_write(
    *,
    domain_id: str,
    item_id: str,
    position: Position,
    step: Literal["step1", "step2"] = "step1",
    ctl_num: int | None = None,
) -> bytes:
    """
    Encode un MMS write vers un objet "CO$Pos$Oper".

    - `domain_id` correspond au LD MMS (ex: VMC7_2BayLD)
    - `item_id` est la référence complète sous le domaine (ex:
        CBCSWI1$CO$Pos$Oper)
    - La direction (open/closed) est encodée via ctlNum (0=open, 1=closed),
      pas via ctlVal. ctlVal est toujours 0x06C0 (observation IEDscout).
    """
    base = _VALUE_TEMPLATE_STEP1_BASE if step == "step1" else _VALUE_TEMPLATE_STEP2_BASE
    value_b = bytearray(_render_value_for_position_from_template(position, base))
    # ctlNum fixe par direction (0=open, 1=closed), incrémenté d'1 pour step2
    step_offset = 0 if step == "step1" else 1
    fixed_base = _ctlnum_for_position(position, ctl_num if ctl_num is not None else 0)
    effective_ctl_num = (fixed_base + step_offset) & 0xFF
    _set_first_ctl_num_inplace(value_b, effective_ctl_num)
    value = bytes(value_b)
    # attribute="" car item_id contient déjà `$...$Oper`.
    return encode_mms_set_rcb_attribute(
        domain_id=domain_id,
        item_id=item_id,
        attribute="",
        value=value,
    )


# --- Execution "step3" (longueur 97 octets) ---
#
# D'après le pcap IEDscout qui marche, l'exécution semble inclure une 3e requête
# (confirmed-RequestPDU) plus courte, dont le format BER global est différent
# de step1/step2. Pour débloquer rapidement le contrôle, on reproduit ce PDU
# en dur pour le cas ciblé (DJ) observé.

_EXEC_STEP3_TEMPLATE_FERMETURE_HEX = (
    "615b3059020103a054a352a050a0283026a024a1221a0b564d43375f324261794c44"
    "1a134342435357493124434f24506f73244f706572a024a222830100a209850103"
    "890413d5c007860100910869babddddc36a53f830100840206c0"
)

# Ajout du prefix MMS attendu par encode_mms_* (01000100)
_EXEC_STEP3_PREFIX_HEX = "01000100"


def encode_pos_oper_execute_step3(
    *,
    domain_id: str,
    item_id: str,
    position: Position,
    ctl_num: int | None = None,
) -> bytes:
    """
    Encode la 3e requête d'exécution (step3) pour CO$Pos$Oper.

    Limitation (MVP) : uniquement la config DJ/contrôle observée dans les traces
    (domain_id=VMC7_2BayLD, item_id=CBCSWI1$CO$Pos$Oper).
    """
    if domain_id != "VMC7_2BayLD" or item_id != "CBCSWI1$CO$Pos$Oper":
        raise NotImplementedError("step3 execute support limité à VMC7_2BayLD / CBCSWI1$CO$Pos$Oper")

    base_hex = _EXEC_STEP3_PREFIX_HEX + _EXEC_STEP3_TEMPLATE_FERMETURE_HEX
    b = bytearray(bytes.fromhex(base_hex))
    _refresh_iec61850_timestamp_inplace(b)

    # ctlNum fixe par direction (idem step1) pour que l'IED reconnaisse la séquence
    fixed_ctl = _ctlnum_for_position(position, ctl_num if ctl_num is not None else 0)
    _set_first_ctl_num_inplace(b, fixed_ctl)

    # ctlVal = 0x06C0 dans tous les cas (l'IED utilise ctlNum pour la direction)
    if len(b) < 4 or b[-4] != 0x84 or b[-3] != 0x02:
        raise ValueError("Template step3: BIT STRING final inattendu")
    word16 = _bitstring_for_position(position)
    b[-2] = (word16 >> 8) & 0xFF
    b[-1] = word16 & 0xFF
    return bytes(b)

