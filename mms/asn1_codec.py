"""Codec ASN.1/BER pour MMS (GetRCBValues, SetRCBValues par attribut).

Basé sur l'analyse des trames Wireshark pour l'IED cible.
- GetRCBValues : confirmed-RequestPDU [read] avec object name domainId/itemId.
- SetRCBValues : confirmed-RequestPDU [write] avec object name domainId/itemId$Attribut + valeur.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from iec_data import (
    BoolData, IntData, UIntData, FloatData,
    BitStringData, OctetStringData, VisibleStringData, MmsStringData,
    TimestampData, StructureData, ArrayData, RawData, IECData,
    decode_iec_data_at,
)


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


_PREFIX = b"\x01\x00\x01\x00"  # Session/Presentation header (ISO 8327 / RFC 1006)

# InvokeID initial aligné sur les traces Wireshark capturées terrain.
# L'IED n'impose pas de valeur de départ, mais la cohérence avec les captures
# facilite la comparaison lors des analyses Wireshark ultérieures.
_INVOKE_ID_INITIAL = 0x012C
_invoke_id = _INVOKE_ID_INITIAL

# ObjectClass ISO 9506 GetNameList : domain=9, namedVariable=0, namedVariableList=2
OBJECT_CLASS_DOMAIN = 9
OBJECT_CLASS_NAMED_VARIABLE = 0
OBJECT_CLASS_NAMED_VARIABLE_LIST = 2

# Tags BER/ASN.1 utilisés dans les encodeurs et décodeurs MMS (ISO 9506 / X.690)
_TAG_IA5_STRING = 0x1A   # IA5String (ASCII 7-bit)
_TAG_BOOLEAN    = 0x83   # BOOLEAN
_TAG_BIT_STRING = 0x84   # BIT STRING
_TAG_UINT_SHORT = 0x85   # Unsigned integer ≤ 1 octet (MMS extension)
_TAG_UINT_LONG  = 0x86   # Unsigned integer ≥ 2 octets (MMS extension)
_TAG_FLOAT      = 0x87   # Floating-point (IEEE 754)
_TAG_OCTET_STR  = 0x89   # OCTET STRING
_TAG_VIS_STRING = 0x8A   # VisibleString
_TAG_BIN_TIME   = 0x8C   # binary-time (IEC 61850-8-1 TimeOfDay)
_TAG_UTC_TIME   = 0x91   # utc-time
_TAG_STRUCTURE  = 0xA2   # Structure [2] CONSTRUCTED (MMS Data)
_TAG_APP_PDU    = 0x61   # Application [1] — enveloppe PDU ISO 8650
_TAG_SEQUENCE   = 0x30   # SEQUENCE (universal constructed)
_TAG_CTX0_C     = 0xA0   # [0] IMPLICIT CONSTRUCTED
_TAG_CTX1_C     = 0xA1   # [1] IMPLICIT CONSTRUCTED
_TAG_CTX3_C     = 0xA3   # [3] IMPLICIT CONSTRUCTED — informationReport
_TAG_CTX4_C     = 0xA4   # [4] IMPLICIT CONSTRUCTED — read (GetRCBValues)
_TAG_CTX5_C     = 0xA5   # [5] IMPLICIT CONSTRUCTED — write (SetRCBValues)


def reset_invoke_id(base: int = _INVOKE_ID_INITIAL) -> None:
    """Réinitialise le compteur invokeID (appelé à chaque nouvelle session)."""
    global _invoke_id
    _invoke_id = base


def _next_invoke_id() -> int:
    global _invoke_id
    prev = _invoke_id
    _invoke_id = (_invoke_id + 1) & 0xFFFF
    return prev


def _encode_ia5(s: str) -> bytes:
    """Encode une IA5String : tag 1a + len + octets."""
    b = s.encode("ascii")
    return bytes([_TAG_IA5_STRING, len(b)]) + b


def _encode_domain_specific_name(domain_id: str, item_id: str) -> bytes:
    """Construit le bloc variableSpecification: name: domain-specific (deux IA5String)."""
    return _encode_ia5(domain_id) + _encode_ia5(item_id)


def encode_mms_initiate() -> bytes:
    """Construit un MMS InitiateRequest (replay de trame capturée terrain).

    Ce PDU est un replay fidèle d'une capture Wireshark effectuée sur l'IED
    cible. Il encode les couches Session (ISO 8327) + Présentation (ISO 8823)
    + ACSE (ISO 8650) + MMS InitiateRequest (ISO 9506) avec les paramètres
    négociés lors des captures : max-services-outstanding, PDU size, etc.

    NE PAS modifier ces octets sans re-capturer sur l'IED : les paramètres
    ACSE (Application Context OID, Presentation Context List) sont spécifiques
    au profil IEC 61850-8-1 de l'équipement et doivent correspondre exactement.

    Décomposition (vérifiable dans Wireshark) :
      0d b2 05 06 …        Session SPDU type CN (Connect)
      c1 9c 31 81 99 …     Presentation CP-PPDU
        a0 03 80 01 01      ACSE : Application Context (IEC 61850-8-1)
        a2 81 91 …          ACSE : Called AP Title + Presentation Context List
      be 2f 28 2d …        ACSE User Information → MMS InitiateRequestPDU
        02 01 03            MMS version = 3
        a0 28 …             proposedParameterCBB
        a8 26 …             initRequestDetail (maxServOutstanding, PDU sizes…)
    """
    return bytes.fromhex(
        "0db20506130100160102140200023302000134020001"   # Session SPDU CN
        "c19c318199"                                      # Presentation CP-PPDU header
        "a003800101"                                      # ACSE Application Context OID
        "a28191"                                          # ACSE Called AP / Pres context list
        "810400000001820400000001"
        "a423300f0201010604520100013004060251013010020103"
        "060528ca220201300406025101615e305c020101a0576055"
        "a107060528ca220203a20706052901876701a30302010c"   # ACSE Presentation Context List
        "a606060429018767a70302010c"
        "be2f282d"                                        # ACSE User Info → MMS PDU
        "020103"                                          # MMS version 3
        "a028a826"
        "800300fde881010582010583010a"                    # proposedParameterCBB + PDU sizes
        "a416800101810305f100"
        "820c03ee1c00000408000079ef18"                    # initRequestDetail
    )


def encode_mms_get_rcb(domain_id: str, item_id: str) -> bytes:
    """Construit un MMS GetRCBValues (confirmed-RequestPDU [read]).

    Object name = domainId / itemId (ex: VMC7_1LD0 / LLN0$BR$CB_LDPHAS1_CYPO02).
    """
    name_part = _encode_domain_specific_name(domain_id, item_id)

    def _tlv(tag: int, value: bytes) -> bytes:
        return bytes([tag, len(value)]) + value

    a1_inner = _tlv(_TAG_CTX1_C, name_part)
    a0_1     = _tlv(_TAG_CTX0_C, a1_inner)
    seq_1    = _tlv(_TAG_SEQUENCE, a0_1)
    a0_2     = _tlv(_TAG_CTX0_C, seq_1)
    a1_2     = _tlv(_TAG_CTX1_C, a0_2)
    a4       = _tlv(_TAG_CTX4_C, a1_2)

    inv = _next_invoke_id()
    invoke_part = b"\x02\x02" + bytes([inv >> 8, inv & 0xFF])

    inner   = invoke_part + a4
    a0_3    = _tlv(_TAG_CTX0_C, inner)
    a0_4    = _tlv(_TAG_CTX0_C, a0_3)
    seq_2   = _tlv(_TAG_SEQUENCE, b"\x02\x01\x03" + a0_4)
    app1    = _tlv(_TAG_APP_PDU, seq_2)

    return _PREFIX + app1


def encode_mms_get_name_list(
    object_class: int,
    scope_vmd: bool = True,
    domain_id: Optional[str] = None,
) -> bytes:
    """Construit un MMS GetNameList (confirmed-RequestPDU [getNameList]).

    object_class : OBJECT_CLASS_DOMAIN (9), OBJECT_CLASS_NAMED_VARIABLE (0), etc.
    scope_vmd : True = vmd-specific (NULL), False = domain-specific avec domain_id.
    domain_id : requis si scope_vmd=False (ex: VMC7_1LD0).
    """
    # GetNameList-Request ::= SEQUENCE {
    #   objectClass [0] IMPLICIT ObjectClass,
    #   objectScope [1] IMPLICIT ObjectScope
    # }
    # objectClass ENUMERATED : 80 01 09 pour domain
    obj_class = b"\x80\x01" + bytes([object_class & 0xFF])
    if scope_vmd:
        # vmd-specific [0] IMPLICIT NULL
        obj_scope = b"\x81\x00"
    else:
        if not domain_id:
            raise ValueError("domain_id requis pour scope domain-specific")
        # domain-specific [1] IMPLICIT Identifier (VisibleString)
        id_bytes = _encode_ia5(domain_id)
        obj_scope = b"\x81" + bytes([len(id_bytes)]) + id_bytes

    def _tlv(tag: int, value: bytes) -> bytes:
        return bytes([tag, len(value)]) + value

    gnl_req     = _tlv(_TAG_SEQUENCE, obj_class + obj_scope)
    gnl_wrapper = _tlv(_TAG_CTX1_C, gnl_req)

    inv = _next_invoke_id()
    invoke_part = b"\x02\x02" + bytes([inv >> 8, inv & 0xFF])

    inner  = invoke_part + gnl_wrapper
    a0_3   = _tlv(_TAG_CTX0_C, inner)
    a0_4   = _tlv(_TAG_CTX0_C, a0_3)
    seq_2  = _tlv(_TAG_SEQUENCE, b"\x02\x01\x03" + a0_4)
    app1   = _tlv(_TAG_APP_PDU, seq_2)

    return _PREFIX + app1


def _encode_mms_value_boolean(val: bool) -> bytes:
    return bytes([_TAG_BOOLEAN, 1, 1 if val else 0])


def _encode_mms_value_unsigned(val: int) -> bytes:
    """Encode un unsigned (tag UINT_SHORT ≤1 octet, UINT_LONG sinon)."""
    if val < 0x100:
        return bytes([_TAG_UINT_SHORT, 1, val])
    if val < 0x10000:
        return bytes([_TAG_UINT_LONG, 2, val >> 8, val & 0xFF])
    b = val.to_bytes((val.bit_length() + 7) // 8 or 1, "big")
    return bytes([_TAG_UINT_LONG, len(b)]) + b


def _encode_mms_value_bitstring(bits: bytes) -> bytes:
    """Encode un bit string. bits inclut les octets de padding si nécessaire."""
    return bytes([_TAG_BIT_STRING, len(bits)]) + bits


def _encode_mms_value_octetstring(val: bytes) -> bytes:
    return bytes([_TAG_OCTET_STR, len(val)]) + val


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

    def _tlv(tag: int, value: bytes) -> bytes:
        return bytes([tag, len(value)]) + value

    a1_inner      = _tlv(_TAG_CTX1_C, name_part)
    a0_name_inner = _tlv(_TAG_CTX0_C, a1_inner)
    seq_name      = _tlv(_TAG_SEQUENCE, a0_name_inner)
    a0_name_block = _tlv(_TAG_CTX0_C, seq_name)
    a0_val        = _tlv(_TAG_CTX0_C, value)
    a5            = _tlv(_TAG_CTX5_C, a0_name_block + a0_val)

    inv = _next_invoke_id()
    invoke_part = b"\x02\x02" + bytes([inv >> 8, inv & 0xFF])

    inner  = invoke_part + a5
    a0_3   = _tlv(_TAG_CTX0_C, inner)
    a0_4   = _tlv(_TAG_CTX0_C, a0_3)
    seq_2  = _tlv(_TAG_SEQUENCE, b"\x02\x01\x03" + a0_4)
    app1   = _tlv(_TAG_APP_PDU, seq_2)

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



def _iec_data_to_legacy(d: IECData) -> Any:
    """Convertit IECData en type Python simple (format historique pour les entries MMS)."""
    if isinstance(d, BoolData):
        return d.value
    if isinstance(d, (IntData, UIntData)):
        return d.value
    if isinstance(d, FloatData):
        return d.value
    if isinstance(d, (VisibleStringData, MmsStringData)):
        return d.value
    if isinstance(d, TimestampData):
        return d.value.isoformat()
    if isinstance(d, (BitStringData, OctetStringData)):
        return d.value.hex()
    if isinstance(d, StructureData):
        return [_iec_data_to_legacy(m) for m in d.members]
    if isinstance(d, ArrayData):
        return [_iec_data_to_legacy(e) for e in d.elements]
    return "<unknown>"


def _ber_decode_data_value(data: bytes, offset: int) -> tuple[Any, int]:
    """Décode une valeur Data MMS à offset. Délègue à decode_iec_data_at (iec_data.py)."""
    try:
        item, next_offset = decode_iec_data_at(data, offset)
        return _iec_data_to_legacy(item), next_offset
    except ValueError:
        return None, _ber_skip(data, offset)


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



def is_read_response_success(pdu: bytes) -> bool:
    """
    True si le PDU est une confirmed-ResponsePDU avec Read-Response (a4) *réussie*.

    Read-Response success : contenu de a4 inclut des données (8a, 86, 83...).
    Read-Response failure : contenu de a4 = failure [1] avec erreur (ex. a1 03 80 01 0a
    pour object-non-existent).
    """
    data = pdu
    if data.startswith(_PREFIX):
        data = data[len(_PREFIX):]
    if len(data) < 6 or data[0] != 0x61:
        return False
    # Chercher a4 (read [4]) dans le PDU (il peut être imbriqué dans 61)
    pos = data.find(b"\xa4")
    if pos < 0:
        return False
    pos += 1
    if pos >= len(data):
        return False
    ln, n = _ber_read_length(data, pos)
    pos += n
    if pos + ln > len(data):
        return False
    content = data[pos : pos + ln]
    # Failure : pattern a1 03 80 01 0a (failure [1] avec error code 0x0a)
    if ln <= 12 and b"\xa1\x03\x80" in content[:8]:
        return False
    # Success : contient des données (visible string 8a/1a, unsigned 86/85, boolean 83, etc.)
    return any(b in content for b in (b"\x8a", b"\x1a", b"\x86", b"\x85", b"\x83", b"\x84"))


def decode_mms_get_name_list_response(pdu: bytes) -> Optional[tuple[List[str], bool]]:
    """
    Décode une réponse GetNameList (confirmed-ResponsePDU [getNameList]).
    Retourne (list_of_identifier, more_follows) ou None si ce n'est pas une réponse GetNameList.
    """
    data = pdu
    if data.startswith(_PREFIX):
        data = data[len(_PREFIX):]
    if len(data) < 8 or data[0] != 0x61:
        return None
    offset = 1
    length, n = _ber_read_length(data, offset)
    offset += n
    end_outer = min(offset + length, len(data))
    payload = data[offset:end_outer]

    # Chercher getNameList [1] = 0xA1 (ISO 9506 ConfirmedServiceResponse)
    pos = 0
    # Skip version et invokeID dans confirmed-ResponsePDU
    if len(payload) < 4 or payload[pos] != 0x30:
        return None
    pos += 1
    seq_len, nn = _ber_read_length(payload, pos)
    pos += nn
    seq_end = pos + seq_len
    if seq_end > len(payload):
        seq_end = len(payload)
    def _find_a1_in(inner: bytes, start: int, end: int) -> Optional[int]:
        """Recherche récursive du TLV a1 (getNameList) dans inner[start:end]."""
        p = start
        while p < end - 1:
            tag = inner[p]
            p += 1
            ln, nn = _ber_read_length(inner, p)
            p += nn
            if p + ln > end:
                break
            if tag == 0xA1:
                return p - 1  # position du tag a1
            if tag == 0xA0:
                found = _find_a1_in(inner, p, p + ln)
                if found is not None:
                    return found
            p += ln
        return None

    a1_pos = _find_a1_in(payload, pos, seq_end)
    if a1_pos is None:
        return None

    pos = a1_pos
    gnl_len, nn = _ber_read_length(payload, pos)
    pos += nn
    gnl_end = pos + gnl_len
    if gnl_end > len(payload):
        gnl_end = len(payload)
    gnl_content = payload[pos:gnl_end]

    # GetNameList-Response : listOfIdentifier [0], moreFollows [1]
    names: List[str] = []
    more_follows = False
    p = 0
    while p < len(gnl_content):
        if p >= len(gnl_content):
            break
        tag = gnl_content[p]
        p += 1
        ln, nn = _ber_read_length(gnl_content, p)
        p += nn
        if p + ln > len(gnl_content):
            break
        chunk = gnl_content[p:p + ln]
        p += ln
        if tag == 0xA0:
            # listOfIdentifier SEQUENCE OF VisibleString
            q = 0
            while q < len(chunk):
                if chunk[q] in (0x1A, 0x8A, 0x80):
                    s, q = _ber_decode_visible_string(chunk, q)
                    if s:
                        names.append(s)
                else:
                    q = _ber_skip(chunk, q)
        elif tag == 0xA1 and len(chunk) >= 2 and chunk[0] == 0x83:
            # moreFollows BOOLEAN
            more_follows = len(chunk) > 1 and chunk[1] != 0

    return names, more_follows


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
