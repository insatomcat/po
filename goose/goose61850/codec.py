from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from iec_data import (
    IECData, _IEC_DATA_TYPES,
    decode_iec_data_sequence,
    encode_iec_data,
    iec_data_from_json,
)
from .types import GoosePDU


class ASN1DecodeError(Exception):
    pass


def _read_tlv(data: bytes, offset: int) -> Tuple[int, int, bytes, int]:
    """Lit un TLV ASN.1 BER simple (tag <= 30, longueur courte ou longue)."""
    if offset >= len(data):
        raise ASN1DecodeError("Offset hors limites")

    tag = data[offset]
    offset += 1

    if offset >= len(data):
        raise ASN1DecodeError("Longueur manquante")

    length_byte = data[offset]
    offset += 1

    if length_byte & 0x80:
        num_len_bytes = length_byte & 0x7F
        if num_len_bytes == 0 or offset + num_len_bytes > len(data):
            raise ASN1DecodeError("Longueur longue invalide")
        length = 0
        for _ in range(num_len_bytes):
            length = (length << 8) | data[offset]
            offset += 1
    else:
        length = length_byte

    if offset + length > len(data):
        raise ASN1DecodeError("Contenu TLV tronqué")

    value = data[offset : offset + length]
    offset += length
    return tag, length, value, offset


def _decode_visible_string(raw: bytes) -> str:
    try:
        return raw.decode("ascii", errors="replace")
    except Exception:
        return raw.hex()


def _decode_boolean(raw: bytes) -> bool:
    return len(raw) > 0 and raw[0] != 0


def _decode_integer(raw: bytes) -> int:
    value = 0
    for b in raw:
        value = (value << 8) | b
    # interprétation signée minimale si MSB à 1
    if raw and (raw[0] & 0x80):
        value -= 1 << (8 * len(raw))
    return value


def _decode_timestamp(raw: bytes) -> datetime:
    # Timestamp GOOSE = 8 octets (MMS TimeOfDay / Epoch)
    if len(raw) < 8:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    secs = int.from_bytes(raw[0:4], "big")
    # les 3 octets suivants sont des fractions, qu'on ignore ici
    return datetime.fromtimestamp(secs, tz=timezone.utc)


def _parse_goose_fields(tlvs: List[Tuple[int, bytes]]) -> Dict[str, Any]:
    """Associe les tags MMS/GOOSE aux champs de haut niveau.

    Les numéros de tag suivent IEC 61850-8-1 (simplifié) :
      0: gocbRef (VisibleString)
      1: timeAllowedToLive (Integer)
      2: datSet (VisibleString)
      3: goID (VisibleString)
      4: t (TimeOfDay)
      5: stNum (Integer)
      6: sqNum (Integer)
      7: test / simulation (Boolean)
      8: confRev (Integer)
      9: ndsCom (Boolean)
      10: numDatSetEntries (Integer)
      11: allData (séquence de valeurs)

    Pour les éléments de allData :
      - Booléen (inner_tag_num == 1)  -> bool Python
      - Entier  (inner_tag_num == 2)  -> int Python
      - Texte   (inner_tag_num == 3)  -> str Python (VisibleString)
      - Autre   (inner_tag_num != 1/2/3) -> tuple bijectif :
            ("raw", inner_tag_num, <hex bytes>)
    """
    fields: Dict[str, Any] = {}
    all_data: List[Any] = []

    for tag, value in tlvs:
        # tag de type contexte : ignorer les bits de classe/constructé (0b1110_0000)
        tag_num = tag & 0x1F

        if tag_num == 0:
            fields["gocb_ref"] = _decode_visible_string(value)
        elif tag_num == 1:
            fields["time_allowed_to_live"] = _decode_integer(value)
        elif tag_num == 2:
            fields["dat_set"] = _decode_visible_string(value)
        elif tag_num == 3:
            fields["go_id"] = _decode_visible_string(value)
        elif tag_num == 4:
            fields["timestamp"] = _decode_timestamp(value)
        elif tag_num == 5:
            fields["st_num"] = _decode_integer(value)
        elif tag_num == 6:
            fields["sq_num"] = _decode_integer(value)
        elif tag_num == 7:
            fields["simulation"] = _decode_boolean(value)
        elif tag_num == 8:
            fields["conf_rev"] = _decode_integer(value)
        elif tag_num == 9:
            fields["nds_com"] = _decode_boolean(value)
        elif tag_num == 10:
            fields["num_dat_set_entries"] = _decode_integer(value)
        elif tag_num == 11:
            # allData : séquence TLV de Data IEC 61850 (types standard)
            all_data = decode_iec_data_sequence(value)
        else:
            # Champ inconnu : on le stocke dans un dict annexe si besoin plus tard
            unk = fields.setdefault("_unknown", [])
            unk.append((tag_num, value))

    if all_data:
        fields["all_data"] = all_data

    return fields


def decode_goose_pdu(payload: bytes) -> GoosePDU:
    """Décode un APDU GOOSE (partie applicative) en `GoosePDU`.

    On suppose que `payload` commence au début du PDU GOOSE (après les en-têtes
    Ethernet / VLAN / APPID / length / reserved).
    """
    tlvs: List[Tuple[int, bytes]] = []

    # Le PDU GOOSE est encapsulé dans un tag d'application (0x61) qui contient
    # lui‑même la séquence de champs contextuels [0]..[11]. On commence donc
    # par lire ce premier TLV, puis on parse récursivement son contenu.
    if not payload:
        raise ASN1DecodeError("PDU vide")

    outer_tag, _outer_len, outer_value, _ = _read_tlv(payload, 0)

    # outer_value contient la vraie séquence de champs GOOSE
    offset = 0
    while offset < len(outer_value):
        tag, length, value, offset = _read_tlv(outer_value, offset)
        tlvs.append((tag, value))

    fields = _parse_goose_fields(tlvs)

    return GoosePDU(
        gocb_ref=fields.get("gocb_ref", ""),
        time_allowed_to_live=int(fields.get("time_allowed_to_live", 0)),
        dat_set=fields.get("dat_set", ""),
        go_id=fields.get("go_id"),
        timestamp=fields.get("timestamp", datetime.fromtimestamp(0, tz=timezone.utc)),
        st_num=int(fields.get("st_num", 0)),
        sq_num=int(fields.get("sq_num", 0)),
        simulation=bool(fields.get("simulation", False)),
        conf_rev=int(fields.get("conf_rev", 0)),
        nds_com=bool(fields.get("nds_com", False)),
        num_dat_set_entries=int(fields.get("num_dat_set_entries", 0)),
        all_data=fields.get("all_data", []),
    )


def encode_goose_pdu(pdu: GoosePDU) -> bytes:
    """Encode un `GoosePDU` vers un payload binaire GOOSE.

    Attention : cet encodeur est volontairement simplifié et ne couvre pas tous
    les types de données possibles dans `all_data`. Il est suffisant pour créer
    des trames de test dans la plupart des cas de base.
    """

    def enc_tag(tag_num: int, content: bytes) -> bytes:
        """
        Encode un tag de contexte pour un champ GOOSE.

        Observations sur des trames SCU réelles :
          - Les champs simples (0..10) utilisent des tags contexte **primitifs**
            (0x80..0x8A).
          - Le champ allData (11) est encodé avec un tag contexte **construit**
            (0xAB).
        On reproduit ce comportement ici.
        """
        if tag_num == 11:
            # allData : [CONTEXT | CONSTRUCTED] numéro 11 -> 0xAB
            tag = 0xA0 | (tag_num & 0x1F)
        else:
            # Champs simples : [CONTEXT | PRIMITIVE] -> 0x8n
            tag = 0x80 | (tag_num & 0x1F)
        length = len(content)
        if length < 0x80:
            len_bytes = bytes([length])
        else:
            tmp = length.to_bytes(4, "big")
            tmp = tmp.lstrip(b"\x00")
            len_bytes = bytes([0x80 | len(tmp)]) + tmp
        return bytes([tag]) + len_bytes + content

    def enc_visible_string(s: str) -> bytes:
        return s.encode("ascii", errors="ignore")

    def enc_boolean(v: bool) -> bytes:
        return b"\xFF" if v else b"\x00"

    def enc_integer(v: int) -> bytes:
        if v == 0:
            return b"\x00"
        is_negative = v < 0
        abs_v = -v if is_negative else v
        raw = abs_v.to_bytes((abs_v.bit_length() + 7) // 8, "big")
        if is_negative:
            # conversion en complément à deux minimal
            n_bits = len(raw) * 8
            max_val = 1 << n_bits
            twos = (max_val - abs_v) & (max_val - 1)
            raw = twos.to_bytes(len(raw), "big")
            if not (raw[0] & 0x80):
                raw = b"\xFF" + raw
        else:
            if raw[0] & 0x80:
                raw = b"\x00" + raw
        return raw

    def enc_timestamp(dt: datetime) -> bytes:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        secs = int(dt.timestamp())
        # 4 octets pour les secondes + 3 octets de fractions (0) + 1 octet qualité (0)
        return secs.to_bytes(4, "big") + b"\x00\x00\x00\x00"

    parts: List[bytes] = []

    parts.append(enc_tag(0, enc_visible_string(pdu.gocb_ref)))
    parts.append(enc_tag(1, enc_integer(pdu.time_allowed_to_live)))
    parts.append(enc_tag(2, enc_visible_string(pdu.dat_set)))
    if pdu.go_id is not None:
        parts.append(enc_tag(3, enc_visible_string(pdu.go_id)))
    parts.append(enc_tag(4, enc_timestamp(pdu.timestamp)))
    parts.append(enc_tag(5, enc_integer(pdu.st_num)))
    parts.append(enc_tag(6, enc_integer(pdu.sq_num)))
    parts.append(enc_tag(7, enc_boolean(pdu.simulation)))
    parts.append(enc_tag(8, enc_integer(pdu.conf_rev)))
    parts.append(enc_tag(9, enc_boolean(pdu.nds_com)))
    parts.append(enc_tag(10, enc_integer(pdu.num_dat_set_entries)))

    # Encodage extrêmement simple de all_data : chaque entrée est encodée comme un
    # entier ou une chaîne VisibleString selon son type Python.
    all_data_content = b""
    for d in pdu.all_data:
        item = d if isinstance(d, _IEC_DATA_TYPES) else iec_data_from_json(d)
        all_data_content += encode_iec_data(item)

    if all_data_content:
        parts.append(enc_tag(11, all_data_content))

    # Assemblage des champs GOOSE dans le conteneur d'application 0x61
    inner = b"".join(parts)
    outer_tag = 0x61  # [APPLICATION 1], construit
    inner_len = len(inner)
    if inner_len < 0x80:
        len_bytes = bytes([inner_len])
    else:
        tmp = inner_len.to_bytes(4, "big")
        tmp = tmp.lstrip(b"\x00")
        len_bytes = bytes([0x80 | len(tmp)]) + tmp

    return bytes([outer_tag]) + len_bytes + inner

