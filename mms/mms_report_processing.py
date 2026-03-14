from __future__ import annotations

import sys

"""
Logique commune de traitement des reports MMS :
  - formatage texte pour la console
  - push vers VictoriaMetrics
  - aide pour charger les listes de RCB

Ce module est utilisé à la fois par :
  - le service HTTP (`mms_service.py`)
  - l'outil CLI (`test_client_reports.py`)
"""

from typing import Any, Dict, List, Optional

from .asn1_codec import MMSReport  # juste pour le type
from .victoriametrics_push import push_mms_report


ENTRY_LABELS = (
    "RptId",
    "OptFlds",
    "SeqNum",
    "TimeOfEntry",
    "DatSet",
    "BufOvfl",
    "EntryID",
    "Inclusion",
)

# Noms des membres du Data Set (ordre = ordre dans le report).
# Rempli automatiquement par parse_scl_data_set_members_with_components.
DATA_SET_MEMBER_LABELS: dict[str, list[str]] = {}
# Noms des composants par membre (ex. A.phsA -> [mag, ang]) depuis DataTypeTemplates.
DATA_SET_MEMBER_COMPONENTS: dict[str, dict[str, list[str]]] = {}
# Mappings enum par membre (ex. Pos.stVal -> {0: "off", 1: "on", ...}).
DATA_SET_MEMBER_ENUMS: dict[str, dict[str, dict[int, str]]] = {}

# Codes qualité/reason courants (hex → libellé court)
QUALITY_LABELS = {
    "0208": "good",
    "0300": "questionable",
    "0000": "invalid",
}

ORCAT_LABELS = {
    0: "not-supported",
    1: "bay-control",
    2: "station-control",
    3: "remote-control",
    4: "automatic-bay",
    5: "automatic-station",
    6: "automatic-remote",
    7: "maintenance",
    8: "process",
}


ITEM_IDS_DEFAULT = [
    "LLN0$BR$CB_LDPX_DQPO03",
    "LLN0$BR$CB_LDADD_DQPO03",
    "LLN0$BR$CB_LDCAP1_DQPO03",
    "LLN0$BR$CB_LDEPF_DQPO03",
    "LLN0$BR$CB_LDCMDSA1_DQPO03",
    "LLN0$BR$CB_LDLOCDEF_DQPO03",
    "LLN0$BR$CB_LDCMDDJ_DQPO03",
    "LLN0$BR$CB_LDSUDJ_DQPO03",
    "LLN0$BR$CB_LDCMDST_DQPO03",
    "LLN0$BR$CB_LDRS_DQPO03",
    "LLN0$BR$CB_LDREC_DQPO03",
    "LLN0$BR$CB_LDSUIED_DQPO03",
    "LLN0$BR$CB_LDCAP1_CYPO03",
    "LLN0$BR$CB_LDCMDDJ_CYPO03",
    "LLN0$BR$CB_LDPHAS1_CYPO03",
]


def load_item_ids_from_file(path: str | None) -> list[str]:
    """Charge la liste des RCB (ITEM_IDS_DEFAULT) depuis un fichier texte, une par ligne.

    - Lignes vides ou commençant par '#' sont ignorées.
    - Si le fichier est absent ou invalide, on revient à ITEM_IDS_DEFAULT.
    """
    if not path:
        return ITEM_IDS_DEFAULT
    try:
        ids: list[str] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ids.append(line)
        return ids or ITEM_IDS_DEFAULT
    except OSError as e:
        print(f"[RCB] Impossible de lire {path}: {e}. Utilisation de la liste intégrée.", flush=True)
        return ITEM_IDS_DEFAULT


def _looks_like_quality_hex(s: Any) -> bool:
    """True si la valeur ressemble à un code qualité (4 ou 6 caractères hex)."""
    if not isinstance(s, str) or len(s) not in (4, 6):
        return False
    return all(c in "0123456789abcdefABCDEF" for c in s)


def _format_entry_value(val: Any) -> Any:  # noqa: C901
    """Formate une entrée pour affichage (structure data+qualité+time ou qualité seule)."""
    # Cas particulier : Pos (position de disjoncteur) encodé comme structure imbriquée.
    # Exemple de val brut observé :
    # [[3, '...orIdent...'], '0680', '034000', '2026-03-11T10:30:29+00:00', False]
    if (
        isinstance(val, list)
        and len(val) >= 4
        and isinstance(val[0], list)
        and len(val[0]) >= 1
    ):
        # val[0][0] = orCat (ordinal), val[0][1] = origin.orIdent, val[1] = mot hexa avec bits de position
        or_cat_ordinal = val[0][0]
        or_ident = val[0][1] if len(val[0]) > 1 else None
        pos_word = val[1]
        qual = val[2]
        ts = val[3]
        q = str(qual) if isinstance(qual, str) else (qual.hex() if hasattr(qual, "hex") else str(qual))
        q_label = QUALITY_LABELS.get(q.lower(), "")
        q_str = f"{q}" + (f" ({q_label})" if q_label else "")
        parts: List[str] = []
        # orCat (catégorie d'origine)
        try:
            or_cat_int = int(or_cat_ordinal)
        except (TypeError, ValueError):
            or_cat_int = None
        if or_cat_int is not None and or_cat_int in ORCAT_LABELS:
            parts.append(f"origin.orCat={or_cat_int} ({ORCAT_LABELS[or_cat_int]})")
        else:
            parts.append(f"origin.orCat={or_cat_ordinal!r}")

        # Position (double bit dans le mot hexa, ex. 0x0640=open, 0x0680=closed)
        pos_state: str | None = "unknown"
        if isinstance(pos_word, str):
            try:
                pw = int(pos_word, 16)
                if pw & 0x80:
                    pos_state = "closed"
                elif pw & 0x40:
                    pos_state = "open"
                elif pw == 0x0000 or pw == 0x0012:
                    pos_state = "intermediate"
                else:
                    pos_state = f"0x{pw:04x}"
            except ValueError:
                pos_state = pos_word
        parts.append(f"stVal={pos_state}")

        if or_ident is not None:
            parts.append(f"origin.orIdent={or_ident!r}")
        return "  ".join(parts) + f"  quality={q_str}  time={ts}"

    if isinstance(val, list) and len(val) >= 3:
        # Structure [value, quality_hex?, timestamp] ou [value, reserved, quality_hex, timestamp]
        v = val[0]
        if len(val) == 3:
            a1, a2 = val[1], val[2]
            # Souvent [value, 0, quality_hex] sans timestamp
            if _looks_like_quality_hex(a2):
                qual, ts = a2, None
            else:
                qual, ts = a1, a2
        else:
            qual, ts = val[2], val[3]
        q = str(qual) if isinstance(qual, str) else (qual.hex() if hasattr(qual, "hex") else str(qual))
        q_label = QUALITY_LABELS.get(q.lower(), "")
        q_str = f"{q}" + (f" ({q_label})" if q_label else "")
        if ts is None or _looks_like_quality_hex(ts) or (isinstance(ts, (int, float)) and not isinstance(ts, bool)):
            return f"value={v!r}  quality={q_str}"
        return f"value={v!r}  quality={q_str}  time={ts}"
    if isinstance(val, str) and len(val) == 4:
        label = QUALITY_LABELS.get(val.lower(), "")
        return f"{val} ({label})" if label else val
    return val


def _hex_block(data: bytes, line_len: int = 64) -> str:
    """Hex du PDU par lignes de line_len octets (pour lecture / copier dans Wireshark)."""
    h = data.hex()
    return "\n      ".join(h[i : i + line_len * 2] for i in range(0, len(h), line_len * 2))


def _is_undecoded_raw(report: MMSReport) -> bool:
    """True si le PDU n'a pas été reconnu (fallback raw_hex)."""
    if not report.entries or len(report.entries) != 1:
        return False
    e = report.entries[0]
    return isinstance(e, dict) and "raw_hex" in e


def _print_report(report: MMSReport, verbose: bool = False, out: Any = None) -> None:
    """Affiche le détail d'un report dans la console.
    out: stream de sortie (sys.__stdout__ pour contourner TeeStdout), ou None pour print().
    """
    def w(s: str = "") -> None:
        if out is not None:
            out.write(s + "\n")
            out.flush()
        else:
            print(s, flush=True)
    w("REPORT reçu :")
    if verbose and getattr(report, "raw_pdu", None):
        pdu = report.raw_pdu
        w(f"  [verbose] PDU brut ({len(pdu)} octets) :")
        w(f"      {_hex_block(pdu)}")
        w()
    w(f"  RptId       : {report.rpt_id}")
    w(f"  DataSet     : {report.data_set_name}")
    w(f"  SeqNum      : {report.seq_num}")
    toe = report.time_of_entry
    toe_note = ""
    if isinstance(toe, str) and len(toe) >= 4 and toe[:4].isdigit() and int(toe[:4]) < 2000:
        toe_note = "  (epoch IEC 61850 1984, souvent = horloge IED non synchronisée)"
    w(f"  TimeOfEntry : {toe}{toe_note}")
    w(f"  BufOvfl     : {report.buf_ovfl}")
    if report.entries:
        ds_name = report.data_set_name or ""
        member_labels = DATA_SET_MEMBER_LABELS.get(ds_name, [])
        if not member_labels and ds_name and "$" in ds_name:
            # Repli : matcher par la fin du nom (ex. $DS_LDPHAS1_CYPO) si le préfixe IED diffère
            suffix = "$" + ds_name.split("$", 1)[-1]
            for k, labels in DATA_SET_MEMBER_LABELS.items():
                if k.endswith(suffix):
                    member_labels = labels
                    break
        w(f"  Entries ({len(report.entries)}) :")
        if len(report.entries) > len(ENTRY_LABELS):
            w("  (à partir de [8] : 1er, 2e, … membre du data set)")
            w("  (chaque membre = valeur mesurée + qualité IEC 61850 + horodatage)")
        for i, e in enumerate(report.entries):
            val = e.get("success", e) if isinstance(e, dict) else e
            if i < len(ENTRY_LABELS):
                label = ENTRY_LABELS[i]
            else:
                j = i - len(ENTRY_LABELS)
                if j < len(member_labels):
                    label = member_labels[j]
                elif j < 2 * len(member_labels):
                    # Qualité/reason associée au (j - N)e membre
                    label = f"qualité({member_labels[j - len(member_labels)]})"
                else:
                    label = ""
            disp = _format_entry_value(val)
            if label:
                w(f"    [{i}] {label}: {disp}")
            else:
                w(f"    [{i}] {disp}")
            if verbose:
                w(f"         raw= {val!r}")


def process_mms_report(  # noqa: PLR0913
    report: MMSReport,
    *,
    vm_url: str | None = None,
    show_in_console: bool = True,
    verbose: bool = False,
    batch_interval_sec: float = 0.2,
    batch_max_lines: int = 500,
    member_components: dict[str, dict[str, list[str]]] | None = None,
    console_out: Any = None,
) -> None:
    """Traitement standard d'un report MMS : push VM + affichage console."""
    def _out(s: str) -> None:
        if console_out is not None:
            console_out.write(s + "\n")
            console_out.flush()
        else:
            print(s, flush=True)

    if _is_undecoded_raw(report):
        n = len(report.entries[0].get("raw_hex", "")) // 2 if report.entries else 0
        _out(f"  [PDU non décodé, {n} octets] (autre type de message MMS)")
        if verbose and report.entries:
            _out(f"      {report.entries[0].get('raw_hex', '')[:120]}...")
        return

    if vm_url:
        try:
            push_mms_report(
                vm_url,
                report,
                DATA_SET_MEMBER_LABELS,
                member_components=member_components or DATA_SET_MEMBER_COMPONENTS or None,
                debug=verbose,
                batch_interval_sec=batch_interval_sec,
                batch_max_lines=batch_max_lines,
            )
        except Exception as e:  # pragma: no cover - log simple
            _out(f"[VictoriaMetrics] {e}")
        if not show_in_console:
            return

    _print_report(report, verbose=verbose, out=console_out)

