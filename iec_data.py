"""Types de données IEC 61850 partagés (GOOSE allData / MMS Data CHOICE).

IEC 61850-8-1 Data ::= CHOICE — tags context-implicites BER :
  [1]  0xA1  array          CONSTRUCTED SEQUENCE OF Data
  [2]  0xA2  structure      CONSTRUCTED SEQUENCE OF Data
  [3]  0x83  boolean
  [4]  0x84  bit-string
  [5]  0x85  integer (signé)
  [6]  0x86  unsigned
  [7]  0x87  floating-point (format_byte + IEEE 754)
  [9]  0x89  octet-string
  [10] 0x8A  visible-string
  [12] 0x8C  binary-time (TimeOfDay 6 octets)
  [15] 0x8F  mms-string (UTF-8)
  [17] 0x91  utc-time (8 octets)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, List, Union

_DAYS_1970_TO_1984 = 5113  # jours entre 1970-01-01 et 1984-01-01


@dataclass
class BoolData:
    value: bool

    def __repr__(self) -> str:
        return f"bool({self.value})"


@dataclass
class IntData:
    value: int

    def __repr__(self) -> str:
        return f"int({self.value})"


@dataclass
class UIntData:
    value: int

    def __repr__(self) -> str:
        return f"uint({self.value})"


@dataclass
class FloatData:
    value: float

    def __repr__(self) -> str:
        return f"float({self.value})"


@dataclass
class BitStringData:
    value: bytes
    unused_bits: int = 0

    def __repr__(self) -> str:
        return f"bit-string({self.value.hex()}, unused={self.unused_bits})"


@dataclass
class OctetStringData:
    value: bytes

    def __repr__(self) -> str:
        return f"octet-string({self.value.hex()})"


@dataclass
class VisibleStringData:
    value: str

    def __repr__(self) -> str:
        return f"visible-string({self.value!r})"


@dataclass
class MmsStringData:
    value: str

    def __repr__(self) -> str:
        return f"mms-string({self.value!r})"


@dataclass
class TimestampData:
    value: datetime

    def __repr__(self) -> str:
        return f"timestamp({self.value.isoformat()})"


@dataclass
class StructureData:
    members: List["IECData"] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"structure({self.members!r})"


@dataclass
class ArrayData:
    elements: List["IECData"] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"array({self.elements!r})"


@dataclass
class RawData:
    """Valeur de type inconnu : tag BER brut + octets."""

    tag: int
    value: bytes

    def __repr__(self) -> str:
        return f"raw(tag=0x{self.tag:02X}, {self.value.hex()})"


IECData = Union[
    BoolData, IntData, UIntData, FloatData,
    BitStringData, OctetStringData, VisibleStringData, MmsStringData,
    TimestampData, StructureData, ArrayData, RawData,
]

# Tuple pour isinstance() sans Union
_IEC_DATA_TYPES = (
    BoolData, IntData, UIntData, FloatData,
    BitStringData, OctetStringData, VisibleStringData, MmsStringData,
    TimestampData, StructureData, ArrayData, RawData,
)


# ── Décodage BER ──────────────────────────────────────────────────────────────

def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Lit un TLV BER. Retourne (tag, value_bytes, next_offset)."""
    if offset >= len(data):
        raise ValueError("offset hors limites")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("longueur manquante")
    lb = data[offset]
    offset += 1
    if lb & 0x80:
        n = lb & 0x7F
        if n == 0 or offset + n > len(data):
            raise ValueError("longueur longue invalide")
        length = 0
        for _ in range(n):
            length = (length << 8) | data[offset]
            offset += 1
    else:
        length = lb
    if offset + length > len(data):
        raise ValueError("TLV tronqué")
    return tag, data[offset: offset + length], offset + length


def _decode_utc_time(raw: bytes) -> datetime:
    """Décode utc-time 8 octets : secs(4) + fraction(3) + quality(1)."""
    secs = int.from_bytes(raw[:4], "big")
    frac_bytes = int.from_bytes(raw[4:7], "big")
    frac = frac_bytes / (1 << 24)
    return datetime.fromtimestamp(secs + frac, tz=timezone.utc)


def _decode_binary_time(raw: bytes) -> datetime:
    """Décode binary-time 6 octets : ms_du_jour(4) + jours_depuis_1984(2)."""
    ms = int.from_bytes(raw[:4], "big")
    days = int.from_bytes(raw[4:6], "big")
    secs_total = (_DAYS_1970_TO_1984 + days) * 86400 + ms // 1000
    frac = (ms % 1000) / 1000.0
    return datetime.fromtimestamp(secs_total + frac, tz=timezone.utc)


def decode_iec_data(tag: int, value: bytes) -> IECData:
    """Décode un item Data IEC 61850 depuis son tag BER et ses octets de valeur."""
    if tag == 0x83:  # [3] boolean
        return BoolData(bool(value and value[0]))
    if tag == 0x84:  # [4] bit-string : premier octet = unused_bits
        unused = value[0] if value else 0
        return BitStringData(value[1:] if len(value) > 1 else b"", unused)
    if tag == 0x85:  # [5] integer (signé)
        return IntData(int.from_bytes(value, "big", signed=True) if value else 0)
    if tag == 0x86:  # [6] unsigned
        return UIntData(int.from_bytes(value, "big") if value else 0)
    if tag == 0x87:  # [7] floating-point : format_byte + IEEE 754
        if len(value) == 5:
            return FloatData(round(struct.unpack("!f", value[1:])[0], 7))
        if len(value) == 9:
            return FloatData(round(struct.unpack("!d", value[1:])[0], 15))
    if tag == 0x89:  # [9] octet-string
        return OctetStringData(value)
    if tag in (0x8A, 0x1A, 0x80):  # [10] visible-string (et variantes IA5)
        return VisibleStringData(value.decode("ascii", errors="replace"))
    if tag == 0x8C:  # [12] binary-time
        if len(value) == 6:
            try:
                return TimestampData(_decode_binary_time(value))
            except (ValueError, OSError):
                pass
    if tag == 0x8F:  # [15] mms-string
        return MmsStringData(value.decode("utf-8", errors="replace"))
    if tag == 0x91:  # [17] utc-time
        if len(value) >= 8:
            try:
                return TimestampData(_decode_utc_time(value[:8]))
            except (ValueError, OSError):
                pass
    if tag == 0xA1:  # [1] array (constructed)
        return ArrayData(decode_iec_data_sequence(value))
    if tag == 0xA2:  # [2] structure (constructed)
        return StructureData(decode_iec_data_sequence(value))
    return RawData(tag, value)


def decode_iec_data_sequence(data: bytes) -> list[IECData]:
    """Décode une séquence TLV d'items IECData."""
    items: list[IECData] = []
    offset = 0
    while offset < len(data):
        try:
            tag, value, offset = _read_tlv(data, offset)
        except ValueError:
            break
        items.append(decode_iec_data(tag, value))
    return items


def decode_iec_data_at(data: bytes, offset: int) -> tuple[IECData, int]:
    """Décode un item IECData à offset dans data. Retourne (IECData, next_offset)."""
    tag, value, next_offset = _read_tlv(data, offset)
    return decode_iec_data(tag, value), next_offset


# ── Encodage BER ──────────────────────────────────────────────────────────────

def _tlv(tag: int, content: bytes) -> bytes:
    """Construit un TLV BER avec longueur courte ou longue."""
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    tmp = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(tmp)]) + tmp + content


def encode_iec_data(d: IECData) -> bytes:
    """Encode un item IECData en TLV BER (IEC 61850 Data CHOICE)."""
    if isinstance(d, BoolData):
        return _tlv(0x83, b"\xff" if d.value else b"\x00")
    if isinstance(d, IntData):
        v = d.value
        if v == 0:
            return _tlv(0x85, b"\x00")
        n_bytes = (v.bit_length() + 8) // 8
        return _tlv(0x85, v.to_bytes(n_bytes, "big", signed=True))
    if isinstance(d, UIntData):
        v = d.value
        if v == 0:
            return _tlv(0x86, b"\x00")
        return _tlv(0x86, v.to_bytes((v.bit_length() + 7) // 8 or 1, "big"))
    if isinstance(d, FloatData):
        return _tlv(0x87, b"\x08" + struct.pack("!f", d.value))
    if isinstance(d, BitStringData):
        return _tlv(0x84, bytes([d.unused_bits]) + d.value)
    if isinstance(d, OctetStringData):
        return _tlv(0x89, d.value)
    if isinstance(d, VisibleStringData):
        return _tlv(0x8A, d.value.encode("ascii", errors="replace"))
    if isinstance(d, MmsStringData):
        return _tlv(0x8F, d.value.encode("utf-8", errors="replace"))
    if isinstance(d, TimestampData):
        ts = d.value.timestamp()
        secs = int(ts)
        frac = int((ts - secs) * (1 << 24))
        return _tlv(0x91, secs.to_bytes(4, "big") + frac.to_bytes(3, "big") + b"\x00")
    if isinstance(d, StructureData):
        return _tlv(0xA2, b"".join(encode_iec_data(m) for m in d.members))
    if isinstance(d, ArrayData):
        return _tlv(0xA1, b"".join(encode_iec_data(e) for e in d.elements))
    if isinstance(d, RawData):
        return _tlv(d.tag, d.value)
    return b""


# ── Conversion JSON ───────────────────────────────────────────────────────────

def iec_data_to_json(d: IECData) -> Any:
    """Convertit IECData en type JSON-sérialisable (format riche)."""
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
    if isinstance(d, BitStringData):
        return {"bit-string": d.value.hex(), "unused": d.unused_bits}
    if isinstance(d, OctetStringData):
        return {"octet-string": d.value.hex()}
    if isinstance(d, StructureData):
        return {"structure": [iec_data_to_json(m) for m in d.members]}
    if isinstance(d, ArrayData):
        return {"array": [iec_data_to_json(e) for e in d.elements]}
    if isinstance(d, RawData):
        return {"raw": d.tag, "hex": d.value.hex()}
    return None


def iec_data_from_json(val: Any) -> IECData:
    """Convertit une valeur JSON en IECData.

    Accepte également l'ancien format raw tuple : ["raw", tag_num, hex_str].
    """
    if isinstance(val, bool):
        return BoolData(val)
    if isinstance(val, int):
        return UIntData(val) if val >= 0 else IntData(val)
    if isinstance(val, float):
        return FloatData(val)
    if isinstance(val, str):
        # Compat historique GOOSE:
        # avant le refactor IECData, les valeurs "s:\\x00" envoyées via goose_cli
        # étaient encodées en tag contexte 3 (0x83), pas en VisibleString 0x8A.
        # Pour éviter une régression sur des IED stricts, on garde ce comportement
        # pour les chaînes contenant des caractères de contrôle/non imprimables.
        if any((ord(c) < 0x20 or ord(c) == 0x7F) for c in val):
            return RawData(0x83, val.encode("latin1", errors="replace"))
        return VisibleStringData(val)
    def _legacy_tag_to_ber(tag_num: int) -> int:
        """Compat historique goose_cli raw: le tag est un numéro contextuel (primitif)."""
        if 0 <= tag_num <= 0x1F:
            return 0x80 | tag_num
        return tag_num & 0xFF

    if isinstance(val, (list, tuple)):
        # Ancien format : ["raw", tag_num, hex_str]
        if len(val) == 3 and val[0] == "raw":
            try:
                ber_tag = _legacy_tag_to_ber(int(val[1]))
                return RawData(ber_tag, bytes.fromhex(str(val[2])))
            except (ValueError, TypeError):
                pass
        return ArrayData([iec_data_from_json(e) for e in val])
    if isinstance(val, dict):
        if "bit-string" in val:
            try:
                return BitStringData(
                    bytes.fromhex(str(val["bit-string"])),
                    int(val.get("unused", 0)),
                )
            except (ValueError, TypeError):
                pass
        if "octet-string" in val:
            try:
                return OctetStringData(bytes.fromhex(str(val["octet-string"])))
            except (ValueError, TypeError):
                pass
        if "structure" in val:
            return StructureData([iec_data_from_json(m) for m in val.get("structure", [])])
        if "array" in val:
            return ArrayData([iec_data_from_json(e) for e in val.get("array", [])])
        if "raw" in val:
            try:
                return RawData(
                    _legacy_tag_to_ber(int(val["raw"])),
                    bytes.fromhex(str(val.get("hex", ""))),
                )
            except (ValueError, TypeError):
                pass
    return RawData(0, str(val).encode("utf-8", errors="replace"))
