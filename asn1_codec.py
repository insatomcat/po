"""Codec ASN.1/BER pour MMS (GetRCBValues, SetRCBValues par attribut).

Basé sur l'analyse des trames Wireshark pour l'IED cible.
- GetRCBValues : confirmed-RequestPDU [read] avec object name domainId/itemId.
- SetRCBValues : confirmed-RequestPDU [write] avec object name domainId/itemId$Attribut + valeur.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union


@dataclass
class MMSReport:
    """Représentation Python simplifiée d'un Report MMS (informationReport)."""

    rcb_reference: Optional[str] = None
    rpt_id: Optional[str] = None
    data_set_name: Optional[str] = None
    seq_num: Optional[int] = None
    time_of_entry: Optional[Any] = None
    buf_ovfl: Optional[bool] = None
    entries: list[Dict[str, Any]] | None = None
    raw_pdu: Optional[bytes] = None  # PDU brut (rempli par le client pour debug/verbose)


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


# --- Décodage BER (longueur, skip, types MMS Report) -------------------------


def _ber_read_length(data: bytes, offset: int) -> tuple[int, int]:
    """Lit la longueur BER à offset. Retourne (length, nb_octets_lus)."""
    if offset >= len(data):
        return 0, 0
    b = data[offset]
    if b < 0x80:
        return b, 1
    n = b & 0x7F
    if offset + 1 + n > len(data):
        return 0, 0
    length = 0
    for i in range(n):
        length = (length << 8) | data[offset + 1 + i]
    return length, 1 + n


def _ber_skip(data: bytes, offset: int) -> int:
    """Avance offset après le TLV (tag + length + value). Retourne nouvel offset."""
    if offset >= len(data):
        return offset
    tag = data[offset]
    offset += 1
    length, n = _ber_read_length(data, offset)
    offset += n + length
    return offset


def _ber_decode_visible_string(data: bytes, offset: int) -> tuple[str, int]:
    """Décode visible-string (tag 8a ou 1a) à offset. Retourne (str, nouvel_offset)."""
    if offset >= len(data):
        return "", offset
    tag = data[offset]
    offset += 1
    length, n = _ber_read_length(data, offset)
    offset += n
    if offset + length > len(data):
        return "", offset
    val = data[offset : offset + length].decode("ascii", errors="replace")
    return val, offset + length


def _ber_decode_unsigned(data: bytes, offset: int) -> tuple[int, int]:
    """Décode unsigned (tag 85/86) à offset."""
    if offset >= len(data):
        return 0, offset
    offset += 1
    length, n = _ber_read_length(data, offset)
    offset += n
    if length == 0 or offset + length > len(data):
        return 0, offset
    val = int.from_bytes(data[offset : offset + length], "big")
    return val, offset + length


def _ber_decode_boolean(data: bytes, offset: int) -> tuple[bool, int]:
    """Décode boolean (tag 83) à offset."""
    if offset + 3 > len(data) or data[offset] != 0x83:
        return False, offset
    offset += 1
    if data[offset] != 1:
        return False, offset + 2
    return data[offset + 1] != 0, offset + 2


def _ber_decode_octet_string(data: bytes, offset: int) -> tuple[bytes, int]:
    """Décode octet-string (tag 89) à offset."""
    if offset >= len(data) or data[offset] != 0x89:
        return b"", offset
    offset += 1
    length, n = _ber_read_length(data, offset)
    offset += n
    if offset + length > len(data):
        return b"", offset
    return data[offset : offset + length], offset + length


def _ber_decode_bit_string(data: bytes, offset: int) -> tuple[bytes, int]:
    """Décode bit-string (tag 84) à offset. Retourne (octets bruts, nouvel_offset)."""
    if offset >= len(data) or data[offset] != 0x84:
        return b"", offset
    offset += 1
    length, n = _ber_read_length(data, offset)
    offset += n
    if offset + length > len(data):
        return b"", offset
    return data[offset : offset + length], offset + length


# Epochs : 1984 (IEC 61850) pour petites valeurs, 1970 (Unix) pour timestamps type 202x
_EPOCH_1984 = datetime(1984, 1, 1, tzinfo=timezone.utc)
# Seuil : au-delà on considère que c'est un timestamp Unix (évite 2040 au lieu de 2024)
_SECS_UNIX_MIN = 1_000_000_000  # ~2001


def _timestamp_to_iso(sec: int, frac: float = 0.0) -> str:
    """Convertit secondes (depuis 1970 ou 1984) + fraction en ISO UTC."""
    if sec >= _SECS_UNIX_MIN:
        base = 0.0  # Unix epoch
    else:
        base = _EPOCH_1984.timestamp()
    dt = datetime.fromtimestamp(base + sec + frac, tz=timezone.utc)
    return dt.isoformat()


def _ber_decode_binary_time(data: bytes, offset: int) -> tuple[Any, int]:
    """Décode binary-time (tag 8c). 4–6 octets : secondes (depuis 1970 ou 1984) + optionnel fraction."""
    if offset >= len(data) or data[offset] != 0x8C:
        return "<binary-time?>", offset
    offset += 1
    length, n = _ber_read_length(data, offset)
    offset += n
    if offset + length > len(data) or length < 4:
        return "<binary-time?>", offset + max(0, length)
    raw = data[offset : offset + length]
    offset += length
    try:
        sec = int.from_bytes(raw[:4], "big")
        frac = int.from_bytes(raw[4:6], "big") / 65536.0 if length >= 6 else 0.0
        if 0 < sec < 0x7FFFFFFF:
            return _timestamp_to_iso(sec, frac), offset
        return raw.hex(), offset
    except (ValueError, OSError):
        return raw.hex(), offset


def _ber_decode_utc_time(data: bytes, offset: int) -> tuple[Any, int]:
    """Décode utc-time (tag 91). 4 octets secondes (1970 ou 1984) + optionnel fraction."""
    if offset >= len(data) or data[offset] != 0x91:
        return "<utc-time?>", offset
    offset += 1
    length, n = _ber_read_length(data, offset)
    offset += n
    if offset + length > len(data):
        return "<utc-time?>", offset + max(0, length)
    raw = data[offset : offset + length]
    offset += length
    if length >= 4:
        try:
            sec = int.from_bytes(raw[:4], "big")
            if 0 < sec < 0x7FFFFFFF:
                return _timestamp_to_iso(sec), offset
        except (ValueError, OSError):
            pass
    return raw.hex(), offset


def _ber_decode_float(data: bytes, offset: int) -> tuple[Any, int]:
    """Décode MMS floating-point (tag 87). 1 octet format puis 4 ou 8 octets (IEEE 754)."""
    import struct
    if offset >= len(data) or data[offset] != 0x87:
        return None, offset
    offset += 1
    length, n = _ber_read_length(data, offset)
    offset += n
    if offset + length > len(data) or length < 5:
        return None, offset + max(0, length)
    # Premier octet = format, puis 4 ou 8 octets IEEE 754 big-endian
    payload = data[offset + 1 : offset + length]
    end = offset + length
    try:
        if len(payload) == 4:
            return round(struct.unpack("!f", payload)[0], 6), end
        if len(payload) == 8:
            return round(struct.unpack("!d", payload)[0], 6), end
    except struct.error:
        pass
    return payload.hex(), end


def _ber_decode_structure(data: bytes, offset: int) -> tuple[Union[List[Any], Dict[str, Any]], int]:
    """Décode une structure (tag a2 ou constructed 0x20+). Retourne liste des champs décodés."""
    if offset >= len(data):
        return [], offset
    tag = data[offset]
    if tag != 0xA2 and (tag & 0x1F) != 0x20:
        return [], offset
    offset += 1
    length, n = _ber_read_length(data, offset)
    offset += n
    end = offset + length
    if end > len(data):
        return [], offset
    content = data[offset:end]
    offset = end
    fields: List[Any] = []
    pos = 0
    while pos < len(content):
        try:
            val, pos = _ber_decode_data_value(content, pos)
            fields.append(val)
        except (IndexError, ValueError):
            break
    return fields, offset


def _ber_decode_data_value(data: bytes, offset: int) -> tuple[Any, int]:
    """
    Décode une valeur Data MMS à offset (tag 8a, 80, 1a, 84, 86, 8c, 83, 89, 87, 91, a2...).
    Retourne (valeur Python, nouvel_offset). Les structures sont décodées récursivement.
    """
    if offset >= len(data):
        return None, offset
    tag = data[offset]
    if tag in (0x8A, 0x1A, 0x80):
        return _ber_decode_visible_string(data, offset)
    if tag == 0x84:
        bits, off = _ber_decode_bit_string(data, offset)
        return bits.hex(), off
    if tag == 0x85 or tag == 0x86:
        return _ber_decode_unsigned(data, offset)
    if tag == 0x83:
        return _ber_decode_boolean(data, offset)
    if tag == 0x89:
        octs, off = _ber_decode_octet_string(data, offset)
        return octs.hex(), off
    if tag == 0x8C:
        return _ber_decode_binary_time(data, offset)
    if tag == 0x91:
        return _ber_decode_utc_time(data, offset)
    if tag == 0x87:
        return _ber_decode_float(data, offset)
    if tag == 0xA2 or (tag & 0x1F) == 0x20:
        fields, off = _ber_decode_structure(data, offset)
        return fields if fields else "<structure>", off
    # défaut: skip
    return "<unknown>", _ber_skip(data, offset)


def _decode_mms_report_list(data: bytes, offset: int) -> tuple[list[Dict[str, Any]], int]:
    """
    Décode listOfAccessResult : suite de valeurs Data (8a, 84, 86, 8c, 83, 89, a2...).
    Retourne (liste de {"success": value}, nouvel_offset).
    """
    results: list[Dict[str, Any]] = []
    while offset < len(data):
        try:
            val, offset = _ber_decode_data_value(data, offset)
            results.append({"success": val})
        except (IndexError, ValueError):
            break
    return results, offset


def decode_mms_pdu(pdu: bytes) -> Any:
    """
    Décode un PDU MMS. Si c'est un Report (unconfirmed-PDU [RPT] / informationReport),
    retourne un MMSReport avec rpt_id, data_set_name, seq_num, time_of_entry, buf_ovfl, entries.
    Sinon retourne un MMSReport avec entries=[raw_hex] pour compatibilité.
    """
    data = pdu
    if data.startswith(_PREFIX):
        data = data[len(_PREFIX) :]

    if len(data) < 4 or data[0] != 0x61:
        return MMSReport(
            rcb_reference=None,
            rpt_id=None,
            data_set_name=None,
            seq_num=None,
            entries=[{"raw_hex": pdu.hex()}],
        )

    offset = 1
    length, n = _ber_read_length(data, offset)
    offset += n
    end_outer = offset + length
    if end_outer > len(data):
        data = data[offset:]
    else:
        data = data[offset:end_outer]

    # unconfirmed-PDU : SEQUENCE { version, [0] { [3] informationReport } }
    offset = 0
    if len(data) < 2 or data[0] != 0x30:
        return MMSReport(entries=[{"raw_hex": pdu.hex()}])
    offset += 1
    seq_len, nn = _ber_read_length(data, offset)
    offset += nn
    # 02 01 03 (version)
    if offset + 3 <= len(data) and data[offset] == 0x02:
        offset = _ber_skip(data, offset)
    # [0] contient [3] informationReport
    if offset >= len(data) or data[offset] != 0xA0:
        return MMSReport(entries=[{"raw_hex": pdu.hex()}])
    offset += 1
    outer_len, nn = _ber_read_length(data, offset)
    offset += nn
    a0_content = data[offset : offset + outer_len]
    offset += outer_len
    if len(a0_content) < 2 or a0_content[0] != 0xA3:
        return MMSReport(entries=[{"raw_hex": pdu.hex()}])
    ir_len, nn = _ber_read_length(a0_content, 1)
    # contenu de [3] = après tag (1) + length (nn)
    ir_start = 1 + nn
    ir = a0_content[ir_start : ir_start + ir_len]
    pos = 0
    # Premier [0] dans informationReport : contient variableAccessSpec (a1 "RPT") puis [0] listOfAccessResult
    if len(ir) < 5 or ir[pos] != 0xA0:
        return MMSReport(entries=[{"raw_hex": pdu.hex()}])
    pos += 1
    outer_len, nn = _ber_read_length(ir, pos)
    pos += nn
    # inner = contenu du premier [0]
    inner = ir[pos : pos + outer_len] if pos + outer_len <= len(ir) else ir[pos:]
    pos = 0
    # Skip a1 (variableListName "RPT")
    if len(inner) < 2 or inner[pos] != 0xA1:
        return MMSReport(entries=[{"raw_hex": pdu.hex()}])
    pos = _ber_skip(inner, pos)
    # a0 [0] listOfAccessResult
    if pos >= len(inner) or inner[pos] != 0xA0:
        return MMSReport(entries=[{"raw_hex": pdu.hex()}])
    pos += 1
    list_len, nn = _ber_read_length(inner, pos)
    pos += nn
    list_data = inner[pos : pos + list_len] if pos + list_len <= len(inner) else inner[pos:]

    entries_list, _ = _decode_mms_report_list(list_data, 0)
    if not entries_list:
        return MMSReport(entries=[{"raw_hex": pdu.hex()}])

    # Mapping Wireshark: 0=RptID, 1=OptFlds, 2=SeqNum, 3=TimeOfEntry, 4=DatSet, 5=BufOvfl, 6=EntryID, 7=Inclusion, 8+=data
    rpt_id = None
    seq_num = None
    data_set_name = None
    time_of_entry = None
    buf_ovfl = None
    if len(entries_list) > 0:
        rpt_id = entries_list[0].get("success")
    if len(entries_list) > 1:
        pass  # OptFlds
    if len(entries_list) > 2:
        seq_num = entries_list[2].get("success")
    if len(entries_list) > 3:
        time_of_entry = entries_list[3].get("success")
    if len(entries_list) > 4:
        data_set_name = entries_list[4].get("success")
    if len(entries_list) > 5:
        buf_ovfl = entries_list[5].get("success")

    return MMSReport(
        rcb_reference=None,
        rpt_id=rpt_id,
        data_set_name=data_set_name,
        seq_num=seq_num,
        time_of_entry=time_of_entry,
        buf_ovfl=buf_ovfl,
        entries=entries_list,
    )
