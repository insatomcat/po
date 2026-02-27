"""Codec ASN.1/BER pour MMS (GetRCBValues, SetRCBValues par attribut).

Basé sur l'analyse des trames Wireshark pour l'IED cible.
- GetRCBValues : confirmed-RequestPDU [read] avec object name domainId/itemId.
- SetRCBValues : confirmed-RequestPDU [write] avec object name domainId/itemId$Attribut + valeur.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class MMSReport:
    """Représentation Python simplifiée d'un Report MMS."""

    rcb_reference: Optional[str] = None
    rpt_id: Optional[str] = None
    data_set_name: Optional[str] = None
    seq_num: Optional[int] = None
    entries: list[Dict[str, Any]] | None = None


_PREFIX = b"\x01\x00\x01\x00"  # Session/Presentation
_invoke_id = 0x012C  # Compteur pour invokeID (aligné sur les traces Wireshark)


def reset_invoke_id(base: int = 0x012C) -> None:
    """Réinitialise le compteur invokeID (appelé à chaque nouvelle session)."""
    global _invoke_id
    _invoke_id = base


def _next_invoke_id() -> int:
    global _invoke_id
    prev = _invoke_id
    _invoke_id = (_invoke_id + 1) & 0xFFFF
    return prev


def _encode_ia5(s: str) -> bytes:
    """Encode une IA5String : 1a len octets."""
    b = s.encode("ascii")
    return b"\x1a" + bytes([len(b)]) + b


def _encode_domain_specific_name(domain_id: str, item_id: str) -> bytes:
    """Construit le bloc variableSpecification: name: domain-specific (deux IA5String)."""
    return _encode_ia5(domain_id) + _encode_ia5(item_id)


def encode_mms_initiate() -> bytes:
    """Construit un MMS InitiateRequest (replay de trame capturée)."""
    return bytes.fromhex(
        (
            "0db20506130100160102140200023302000134020001"
            "c19c318199a003800101a28191810400000001820400000001"
            "a423300f0201010604520100013004060251013010020103"
            "060528ca220201300406025101615e305c020101a0576055"
            "a107060528ca220203a20706052901876701a30302010c"
            "a606060429018767a70302010cbe2f282d020103a028a826"
            "800300fde881010582010583010aa416800101810305f100"
            "820c03ee1c00000408000079ef18"
        )
    )


def encode_mms_get_rcb(domain_id: str, item_id: str) -> bytes:
    """Construit un MMS GetRCBValues (confirmed-RequestPDU [read]).

    Object name = domainId / itemId (ex: VMC7_1LD0 / LLN0$BR$CB_LDPHAS1_CYPO02).
    """
    name_part = _encode_domain_specific_name(domain_id, item_id)

    # a1 [len] name_part
    a1_inner = b"\xa1" + bytes([len(name_part)]) + name_part
    # a0 [len] a1
    a0_1 = b"\xa0" + bytes([len(a1_inner)]) + a1_inner
    # 30 [len] a0
    seq_1 = b"\x30" + bytes([len(a0_1)]) + a0_1
    # a0 [len] seq_1
    a0_2 = b"\xa0" + bytes([len(seq_1)]) + seq_1
    # a1 [len] a0_2
    a1_2 = b"\xa1" + bytes([len(a0_2)]) + a0_2
    # a4 [len] a1_2
    a4 = b"\xa4" + bytes([len(a1_2)]) + a1_2

    inv = _next_invoke_id()
    invoke_part = b"\x02\x02" + bytes([inv >> 8, inv & 0xFF])

    # a0 [len] invoke + a4
    inner = invoke_part + a4
    a0_3 = b"\xa0" + bytes([len(inner)]) + inner
    # a0 [len] a0_3
    a0_4 = b"\xa0" + bytes([len(a0_3)]) + a0_3
    # 30 [len] 02 01 03 + a0_4
    fixed = b"\x02\x01\x03"
    seq_top = fixed + a0_4
    seq_2 = b"\x30" + bytes([len(seq_top)]) + seq_top
    # 61 [len] seq_2
    app1 = b"\x61" + bytes([len(seq_2)]) + seq_2

    return _PREFIX + app1


def _encode_mms_value_boolean(val: bool) -> bytes:
    return b"\x83\x01\x01" if val else b"\x83\x01\x00"


def _encode_mms_value_unsigned(val: int) -> bytes:
    """Encode un unsigned (tag 85 ou 86 selon taille)."""
    if val < 0x100:
        return b"\x85\x01" + bytes([val])
    if val < 0x10000:
        return b"\x86\x02" + bytes([val >> 8, val & 0xFF])
    b = val.to_bytes((val.bit_length() + 7) // 8 or 1, "big")
    return b"\x86" + bytes([len(b)]) + b


def _encode_mms_value_bitstring(bits: bytes) -> bytes:
    """Encode un bit string (tag 84). bits inclut les octets de padding si nécessaire."""
    return b"\x84" + bytes([len(bits)]) + bits


def _encode_mms_value_octetstring(val: bytes) -> bytes:
    return b"\x89" + bytes([len(val)]) + val


def encode_mms_set_rcb_attribute(
    domain_id: str,
    item_id: str,
    attribute: str,
    value: bytes,
) -> bytes:
    """Construit un MMS SetRCBValues (Write) pour un attribut donné.

    item_id peut inclure $Attribut (ex: LLN0$BR$CB_LDPHAS1_CYPO02$RptEna)
    ou on le passe séparément : item_id="LLN0$BR$CB_LDPHAS1_CYPO02", attribute="RptEna".

    value : encodage BER brut de la valeur (ex: 83 01 01 pour boolean true).

    Structure observée dans Wireshark :
      a5 [len]
        a0 [len]  -- name block
          30 [len]  -- SEQUENCE
            a0 [len] a1 [len] name_part
        a0 [len] value  -- value block (sibling)
    """
    full_item = f"{item_id}${attribute}" if attribute else item_id
    name_part = _encode_domain_specific_name(domain_id, full_item)

    # a1 [len] name_part
    a1_inner = b"\xa1" + bytes([len(name_part)]) + name_part
    # a0 [len] a1
    a0_name_inner = b"\xa0" + bytes([len(a1_inner)]) + a1_inner
    # 30 [len] a0 (SEQUENCE containing name)
    seq_name = b"\x30" + bytes([len(a0_name_inner)]) + a0_name_inner
    # a0 [len] 30 (name block)
    a0_name_block = b"\xa0" + bytes([len(seq_name)]) + seq_name
    # a0 [len] value (value block)
    a0_val = b"\xa0" + bytes([len(value)]) + value
    # a5 [len] a0_name_block + a0_val (two siblings)
    a5_content = a0_name_block + a0_val
    a5 = b"\xa5" + bytes([len(a5_content)]) + a5_content

    inv = _next_invoke_id()
    invoke_part = b"\x02\x02" + bytes([inv >> 8, inv & 0xFF])

    # a0 [len] invoke + a5
    inner = invoke_part + a5
    a0_3 = b"\xa0" + bytes([len(inner)]) + inner
    a0_4 = b"\xa0" + bytes([len(a0_3)]) + a0_3
    fixed = b"\x02\x01\x03"
    seq_top = fixed + a0_4
    seq_2 = b"\x30" + bytes([len(seq_top)]) + seq_top
    app1 = b"\x61" + bytes([len(seq_2)]) + seq_2

    return _PREFIX + app1


# Valeurs par défaut observées dans les trames qui fonctionnent
DEFAULT_RESV_TMS = 5
DEFAULT_INTG_PD_MS = 2000
DEFAULT_TRG_OPS = bytes.fromhex("020c")  # data-change, quality-change, ...
DEFAULT_OPT_FLDS = bytes.fromhex("067b00")
DEFAULT_PURGE_BUF = True
DEFAULT_ENTRY_ID = bytes(8)
DEFAULT_RPT_ENA = True
DEFAULT_GI = True


def encode_mms_set_rcb(
    domain_id: str,
    item_id: str,
    *,
    rpt_ena: bool = True,
    intg_pd_ms: int = 2000,
    resv_tms: int = 5,
    trg_ops: bytes = DEFAULT_TRG_OPS,
    opt_flds: bytes = DEFAULT_OPT_FLDS,
    purge_buf: bool = True,
    entry_id: bytes = DEFAULT_ENTRY_ID,
    gi: bool = True,
) -> list[bytes]:
    """Génère la séquence complète de SetRCBValues pour activer les reports.

    Retourne une liste de PDUs à envoyer dans l'ordre (ResvTms, IntgPd, TrgOps,
    OptFlds, PurgeBuf, EntryID, RptEna, GI).
    """
    pdus: list[bytes] = []
    pdus.append(
        encode_mms_set_rcb_attribute(
            domain_id, item_id, "ResvTms", _encode_mms_value_unsigned(resv_tms)
        )
    )
    pdus.append(
        encode_mms_set_rcb_attribute(
            domain_id, item_id, "IntgPd", _encode_mms_value_unsigned(intg_pd_ms)
        )
    )
    pdus.append(
        encode_mms_set_rcb_attribute(
            domain_id, item_id, "TrgOps", _encode_mms_value_bitstring(trg_ops)
        )
    )
    pdus.append(
        encode_mms_set_rcb_attribute(
            domain_id, item_id, "OptFlds", _encode_mms_value_bitstring(opt_flds)
        )
    )
    pdus.append(
        encode_mms_set_rcb_attribute(
            domain_id, item_id, "PurgeBuf", _encode_mms_value_boolean(purge_buf)
        )
    )
    pdus.append(
        encode_mms_set_rcb_attribute(
            domain_id, item_id, "EntryID", _encode_mms_value_octetstring(entry_id)
        )
    )
    pdus.append(
        encode_mms_set_rcb_attribute(
            domain_id, item_id, "RptEna", _encode_mms_value_boolean(rpt_ena)
        )
    )
    pdus.append(
        encode_mms_set_rcb_attribute(
            domain_id, item_id, "GI", _encode_mms_value_boolean(gi)
        )
    )
    return pdus


def decode_mms_pdu(pdu: bytes) -> Any:
    """Décode un PDU MMS et retourne un MMSReport ou autre structure."""
    return MMSReport(
        rcb_reference=None,
        rpt_id=None,
        data_set_name=None,
        seq_num=None,
        entries=[{"raw_hex": pdu.hex()}],
    )
