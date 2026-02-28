"""Envoi des reports MMS vers VictoriaMetrics (format Prometheus avec timestamp).

Usage:
    from victoriametrics_push import push_mms_report
    push_mms_report("http://localhost:8428", report, member_labels={...})
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Type pour MMSReport (éviter import circulaire)
MMSReport = Any


def _label_escape(s: str) -> str:
    """Échappe les caractères spéciaux dans une valeur de label Prometheus."""
    s = str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return s


def _value_to_float(val: Any) -> Optional[float]:
    """Convertit une valeur décodée MMS en float (ou None). Gère bool, nombre, listes imbriquées."""
    if val is None:
        return None
    if isinstance(val, bool):
        return 1.0 if val else 0.0
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        return float(val)
    if isinstance(val, list) and len(val) >= 1:
        first = val[0]
        if isinstance(first, (int, float)) and not isinstance(first, bool):
            return float(first)
        if isinstance(first, bool):
            return 1.0 if first else 0.0
        if isinstance(first, list):
            # [[0.0], [0.0]] ou [[0.0]] : prendre le premier nombre trouvé
            for item in first:
                if isinstance(item, (int, float)) and not isinstance(item, bool):
                    return float(item)
                if isinstance(item, list) and len(item) >= 1 and isinstance(item[0], (int, float)):
                    return float(item[0])
    return None


def _entry_value_and_timestamp(val: Any, report: MMSReport) -> tuple[Optional[float], int]:
    """Retourne (valeur numérique, timestamp_ms). Si l'entrée est [value, quality, time], extrait value."""
    value_part = val
    if isinstance(val, list) and len(val) >= 3:
        value_part = val[0]
    num = _value_to_float(value_part)
    ts_ms = _entry_timestamp(val, report)
    return num, ts_ms


def _parse_iso_to_ts_ms(s: Any) -> Optional[int]:
    """Convertit une chaîne ISO (ex. 2024-02-20T10:33:12+00:00) en timestamp ms, ou None."""
    if s is None or not isinstance(s, str):
        return None
    s = s.strip()
    if not s or len(s) < 10:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except (ValueError, TypeError):
        return None


# Timestamp avant 2000-01-01 → considéré comme erroné (ex. time_of_entry en 1984), on utilise "now"
_TS_MS_MIN_2000 = 946684800000


def _entry_timestamp(entry_val: Any, report: MMSReport) -> int:
    """Retourne le timestamp (ms) pour une entrée : celui de l'entrée si dispo, sinon time_of_entry, sinon now."""
    if isinstance(entry_val, list) and len(entry_val) >= 3:
        # [value, quality, time] ou [value, reserved, quality, time]
        ts_val = entry_val[2] if len(entry_val) == 3 else entry_val[3]
        ms = _parse_iso_to_ts_ms(ts_val)
        if ms is not None:
            return ms if ms >= _TS_MS_MIN_2000 else int(time.time() * 1000)
    if getattr(report, "time_of_entry", None):
        ms = _parse_iso_to_ts_ms(report.time_of_entry)
        if ms is not None:
            return ms if ms >= _TS_MS_MIN_2000 else int(time.time() * 1000)
    return int(time.time() * 1000)


_ENTRY_LABELS = (
    "RptId", "OptFlds", "SeqNum", "TimeOfEntry",
    "DatSet", "BufOvfl", "EntryID", "Inclusion",
)


def _member_name(index: int, member_labels: List[str]) -> str:
    """Nom du membre pour le label Prometheus."""
    if index < len(_ENTRY_LABELS):
        return _ENTRY_LABELS[index]
    j = index - len(_ENTRY_LABELS)
    if j < len(member_labels):
        return member_labels[j]
    if j < 2 * len(member_labels):
        return f"qualite_{member_labels[j - len(member_labels)]}"
    return f"entry_{index}"


def push_mms_report(
    base_url: str,
    report: MMSReport,
    member_labels: Optional[Dict[str, List[str]]] = None,
    debug: bool = False,
) -> None:
    """
    Envoie les valeurs numériques d'un report MMS vers VictoriaMetrics (POST /api/v1/import/prometheus).
    Chaque entrée convertible en float devient une métrique mms_report_value avec labels rpt_id, data_set, member.
    Le timestamp utilisé est celui de l'entrée (si structure avec time), sinon time_of_entry, sinon maintenant.
    Si debug=True, affiche l'URL, un échantillon des lignes envoyées et le code HTTP.
    """
    if not report.entries or getattr(report, "rpt_id", None) is None:
        if debug:
            print("[VictoriaMetrics] skip: no entries or rpt_id", flush=True)
        return
    rpt_id = (report.rpt_id or "unknown").replace('"', "_")
    data_set = (report.data_set_name or "unknown").replace('"', "_")
    ds_name = report.data_set_name or ""
    labels_list = (member_labels or {}).get(ds_name, [])
    if not labels_list and ds_name and "$" in ds_name:
        suffix = "$" + ds_name.split("$", 1)[-1]
        for k, L in (member_labels or {}).items():
            if k.endswith(suffix):
                labels_list = L
                break
    lines: List[str] = []
    for i, e in enumerate(report.entries):
        val = e.get("success", e) if isinstance(e, dict) else e
        num, ts_ms = _entry_value_and_timestamp(val, report)
        if num is None:
            continue
        member = _member_name(i, labels_list)
        member_esc = _label_escape(member)
        # Prometheus format with optional timestamp (ms)
        line = f'mms_report_value{{rpt_id="{_label_escape(rpt_id)}",data_set="{_label_escape(data_set)}",member="{member_esc}"}} {num} {ts_ms}'
        lines.append(line)
    if not lines:
        if debug:
            print("[VictoriaMetrics] skip: no numeric values in report", flush=True)
        return
    body = "\n".join(lines).encode("utf-8")
    url = base_url.rstrip("/") + "/api/v1/import/prometheus"
    if debug:
        print(f"[VictoriaMetrics] POST {url} ({len(lines)} metrics, rpt_id={rpt_id!r}, data_set={data_set!r})", flush=True)
        for idx, ln in enumerate(lines[:3]):
            sample = ln if len(ln) <= 100 else ln[:97] + "..."
            print(f"[VictoriaMetrics]   sample {idx + 1}: {sample}", flush=True)
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "text/plain; charset=utf-8")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            code = getattr(resp, "status", 200)
            if debug:
                print(f"[VictoriaMetrics] pushed {len(lines)} metrics (rpt_id={rpt_id!r}) -> {code}", flush=True)
            if debug and code not in (200, 204):
                print(f"[VictoriaMetrics] unexpected status: {code}", flush=True)
    except urllib.error.URLError as err:
        print(f"[VictoriaMetrics] push failed: {err}", flush=True)
    except urllib.error.HTTPError as err:
        print(f"[VictoriaMetrics] push failed: HTTP {err.code} {err.reason}", flush=True)
        if debug and err.fp:
            try:
                body_read = err.fp.read(500).decode("utf-8", errors="replace")
                print(f"[VictoriaMetrics] response: {body_read}", flush=True)
            except Exception:
                pass
