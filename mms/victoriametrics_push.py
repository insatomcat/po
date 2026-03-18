"""Envoi des reports MMS vers VictoriaMetrics (format Prometheus avec timestamp).

Usage:
    from victoriametrics_push import push_mms_report
    push_mms_report("http://localhost:8428", report, member_labels={...})

Les reports sont mis en buffer et envoyés par batch (une requête HTTP par intervalle)
pour réduire le nombre de connexions.
"""

from __future__ import annotations

import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Batching : une requête toutes les 200 ms ou dès 500 lignes
DEFAULT_BATCH_INTERVAL_SEC = 0.2
DEFAULT_BATCH_SIZE_MAX = 500

# Type pour MMSReport (éviter import circulaire)
MMSReport = Any


def _label_escape(s: str) -> str:
    """Échappe les caractères spéciaux dans une valeur de label Prometheus."""
    s = str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return s


def _value_to_float(val: Any) -> Optional[float]:
    """Convertit une valeur décodée MMS en float (ou None). Garde la première valeur pour rétrocompat."""
    floats = _value_to_floats(val)
    return floats[0] if floats else None


def _value_to_floats(val: Any) -> List[float]:
    """Extrait toutes les valeurs numériques d'une structure MMS (ex. [[250.31], [-140.0]] → [250.31, -140.0])."""
    out: List[float] = []

    def collect(x: Any) -> None:
        if x is None:
            return
        if isinstance(x, bool):
            out.append(1.0 if x else 0.0)
            return
        if isinstance(x, (int, float)) and not isinstance(x, bool):
            out.append(float(x))
            return
        if isinstance(x, list):
            for item in x:
                collect(item)

    collect(val)
    return out


def _entry_values_and_timestamp(val: Any, report: MMSReport) -> tuple[List[float], int]:
    """Retourne (liste des valeurs numériques, timestamp_ms). Si l'entrée est [value, quality, time], extrait value."""
    value_part = val
    if isinstance(val, list) and len(val) >= 3:
        value_part = val[0]
    nums = _value_to_floats(value_part)
    ts_ms = _entry_timestamp(val, report)
    return nums, ts_ms


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
    """Retourne le timestamp (ms) pour une entrée.

    Simplification volontaire : on utilise systématiquement time_of_entry du report
    (s'il est valide), afin d'avoir exactement un point par Report et par série,
    et éviter les timestamps divergents entre membres du même DataSet.
    """
    if getattr(report, "time_of_entry", None):
        ms = _parse_iso_to_ts_ms(report.time_of_entry)
        if ms is not None and ms >= _TS_MS_MIN_2000:
            return ms
    # Fallback : now si le report n'a pas de time_of_entry exploitable
    return int(time.time() * 1000)


_ENTRY_LABELS = (
    "RptId", "OptFlds", "SeqNum", "TimeOfEntry",
    "DatSet", "BufOvfl", "EntryID", "Inclusion",
)


_PHASOR_MEMBER_PATTERNS = ("phsA", "phsB", "phsC")


def _default_component_names(member: str, n: int) -> Optional[List[str]]:
    """Si le membre ressemble à un phasor (A.phsA, PhV.phsB, ...) et n==2, retourne ['mag', 'ang'].

    Utilisé en repli quand le modèle MMS (DataTypeTemplates) ne fournit pas les composants.
    """
    if n != 2:
        return None
    for pat in _PHASOR_MEMBER_PATTERNS:
        if pat in member:
            return ["mag", "ang"]
    return None


def _extract_pos_components(val: Any) -> Optional[Dict[str, float]]:
    """Extrait des composantes numériques pour Pos (state, orCat) à partir de la valeur brute.

    Exemple attendu:
        [[3, '...orIdent...'], '0680', '034000', '2026-03-11T10:30:29+00:00', False]

    - val[0][0] = orCat (ordinal)
    - val[1]    = mot hexa combinant orCat/position (bits 0x40=open, 0x80=closed, 0x0/0x12=intermediate)
    """
    if not (isinstance(val, list) and len(val) >= 2):
        return None
    main = val[0]
    if not (isinstance(main, list) and len(main) >= 1):
        return None
    comps: Dict[str, float] = {}

    # Catégorie d'origine (orCat) en ordinal
    or_cat = main[0]
    try:
        comps["orCat"] = float(int(or_cat))
    except (TypeError, ValueError):
        pass

    # DBPOS IEC 61850 : bits de position dans l'octet bas du mot 16 bits.
    #   0x0680 → closed (2), 0x0640 → open (1), 0x0600/0x0000/... → intermediate (0)
    state_val: float | None = None
    if isinstance(val[1], str):
        try:
            pw = int(val[1], 16)
            lo = pw & 0x00FF
            if lo & 0x80:
                state_val = 2.0  # closed
            elif lo & 0x40:
                state_val = 1.0  # open
            else:
                state_val = 0.0  # intermediate (octet bas sans bits positionnels)
        except ValueError:
            state_val = None
    if state_val is not None:
        comps["state"] = state_val

    return comps or None


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


def _do_post_impl(base_url: str, lines: List[str], debug: bool = False) -> None:
    """Envoi direct (une requête HTTP)."""
    body = "\n".join(lines).encode("utf-8")
    url = base_url.rstrip("/") + "/api/v1/import/prometheus"
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "text/plain; charset=utf-8")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            code = getattr(resp, "status", 200)
            if debug:
                print(f"[VictoriaMetrics] pushed {len(lines)} metrics -> {code}", flush=True)
    except urllib.error.URLError as err:
        print(f"[VictoriaMetrics] push failed: {err}", flush=True)
    except urllib.error.HTTPError as err:
        print(f"[VictoriaMetrics] push failed: HTTP {err.code} {err.reason}", flush=True)


def _report_to_lines(
    report: MMSReport,
    member_labels: Optional[Dict[str, List[str]]] = None,
    member_components: Optional[Dict[str, Dict[str, List[str]]]] = None,
    *,
    debug: bool = False,
) -> List[str]:
    """Convertit un report MMS en lignes Prometheus (sans envoyer).
    member_components[ds_key][member_label] = noms des composants (ex. [mag, ang]) depuis l'ICD.
    """
    if not report.entries or getattr(report, "rpt_id", None) is None:
        return []
    rpt_id = (report.rpt_id or "unknown").replace('"', "_")
    data_set = (report.data_set_name or "unknown").replace('"', "_")
    ds_name = report.data_set_name or ""
    labels_list = (member_labels or {}).get(ds_name, [])
    comp_map: Dict[str, List[str]] = {}
    if member_components:
        comp_map = (member_components.get(ds_name) or {})
        if not comp_map and ds_name and "$" in ds_name:
            suffix = "$" + ds_name.split("$", 1)[-1]
            for k, c in (member_components or {}).items():
                if k.endswith(suffix):
                    comp_map = c
                    break
        # Repli : si on n'a pas de composants pour un DataSet CYPO/DQPO,
        # essayer de récupérer ceux du DataSet GME équivalent (suffixe GOOSE dans l'ICD).
        if not comp_map and ds_name:
            alt = None
            if "_CYPO_" in ds_name:
                alt = ds_name.replace("_CYPO_", "_GME_")
            elif "_DQPO_" in ds_name:
                alt = ds_name.replace("_DQPO_", "_GME_")
            if alt:
                comp_map = (member_components.get(alt) or {})
                if not comp_map and "$" in alt:
                    suffix_alt = "$" + alt.split("$", 1)[-1]
                    for k, c in (member_components or {}).items():
                        if k.endswith(suffix_alt):
                            comp_map = c
                            break
    if not labels_list and ds_name and "$" in ds_name:
        suffix = "$" + ds_name.split("$", 1)[-1]
        for k, L in (member_labels or {}).items():
            if k.endswith(suffix):
                labels_list = L
                break
    lines: List[str] = []
    for i, e in enumerate(report.entries):
        val = e.get("success", e) if isinstance(e, dict) else e
        member = _member_name(i, labels_list)
        member_esc = _label_escape(member)

        # Cas particulier : Pos (position de disjoncteur) encodé comme structure imbriquée.
        if member.startswith("Pos"):
            comps = _extract_pos_components(val)
            if comps:
                ts_ms = _entry_timestamp(val, report)
                for cname, num in comps.items():
                    labels = (
                        f'rpt_id="{_label_escape(rpt_id)}",'
                        f'data_set="{_label_escape(data_set)}",'
                        f'member="{member_esc}",'
                        f'component="{_label_escape(cname)}"'
                    )
                    line = f"mms_report_value{{{labels}}} {num} {ts_ms}"
                    lines.append(line)
                if debug:
                    print(
                        f"[DEBUG MMS->VM] member={member} raw_val={val!r} POS_comps={comps}",
                        flush=True,
                    )
                continue

        nums, ts_ms = _entry_values_and_timestamp(val, report)
        if not nums:
            continue
        comp_names = comp_map.get(member) if comp_map else None
        # Si on a plusieurs valeurs numériques et pas de noms de composants fournis
        # par l'ICD, repli heuristique mag/ang pour les phasors.
        if comp_names is None and len(nums) > 1:
            comp_names = _default_component_names(member, len(nums))
        if debug and ("PhV.phs" in member or "PhV" in member):
            # Log détaillé pour debug des phasors (val brut + nums extraits)
            print(
                f"[DEBUG MMS->VM] member={member} raw_val={val!r} nums={nums}",
                flush=True,
            )

        for idx, num in enumerate(nums):
            if len(nums) > 1:
                comp = (
                    comp_names[idx]
                    if comp_names and idx < len(comp_names)
                    else str(idx)
                )
                labels = f'rpt_id="{_label_escape(rpt_id)}",data_set="{_label_escape(data_set)}",member="{member_esc}",component="{_label_escape(comp)}"'
            else:
                labels = f'rpt_id="{_label_escape(rpt_id)}",data_set="{_label_escape(data_set)}",member="{member_esc}"'
            line = f"mms_report_value{{{labels}}} {num} {ts_ms}"
            lines.append(line)
    return lines


class _Batcher:
    """Buffer et flush périodique vers VictoriaMetrics."""

    _instances: Dict[str, "_Batcher"] = {}
    _lock = threading.Lock()

    def __init__(
        self,
        base_url: str,
        interval_sec: float = DEFAULT_BATCH_INTERVAL_SEC,
        max_lines: int = DEFAULT_BATCH_SIZE_MAX,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.interval_sec = interval_sec
        self.max_lines = max_lines
        self._buffer: List[str] = []
        self._buffer_lock = threading.Lock()
        self._flush_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._debug = False

    @classmethod
    def get(cls, base_url: str, interval_sec: float, max_lines: int) -> "_Batcher":
        with cls._lock:
            if base_url not in cls._instances:
                cls._instances[base_url] = cls(base_url, interval_sec, max_lines)
            return cls._instances[base_url]

    def add(self, lines: List[str], debug: bool = False) -> None:
        if not lines:
            return
        self._debug = self._debug or debug
        to_send: List[str] = []
        with self._buffer_lock:
            self._buffer.extend(lines)
            if len(self._buffer) >= self.max_lines:
                to_send = self._take_buffer()
        if to_send:
            _do_post_impl(self.base_url, to_send, debug=self._debug)

    def _take_buffer(self) -> List[str]:
        """Extrait le buffer (appelé avec _buffer_lock tenu). Retourne [] si vide."""
        if not self._buffer:
            return []
        to_send = self._buffer[:]
        self._buffer.clear()
        return to_send

    def _run_flush_loop(self) -> None:
        while not self._stop.wait(self.interval_sec):
            with self._buffer_lock:
                to_send = self._take_buffer()
            if to_send:
                _do_post_impl(self.base_url, to_send, debug=self._debug)

    def ensure_started(self) -> None:
        if self._flush_thread is not None and self._flush_thread.is_alive():
            return
        self._flush_thread = threading.Thread(target=self._run_flush_loop, daemon=True)
        self._flush_thread.start()

    def flush(self) -> None:
        """Force l'envoi immédiat du buffer."""
        with self._buffer_lock:
            to_send = self._take_buffer()
        if to_send:
            _do_post_impl(self.base_url, to_send, debug=self._debug)


def push_mms_report(
    base_url: str,
    report: MMSReport,
    member_labels: Optional[Dict[str, List[str]]] = None,
    member_components: Optional[Dict[str, Dict[str, List[str]]]] = None,
    debug: bool = False,
    *,
    batch_interval_sec: float = DEFAULT_BATCH_INTERVAL_SEC,
    batch_max_lines: int = DEFAULT_BATCH_SIZE_MAX,
) -> None:
    """
    Envoie les valeurs numériques d'un report MMS vers VictoriaMetrics (POST /api/v1/import/prometheus).
    member_components : optionnel, depuis parse_scl_data_set_members_with_components, pour des libellés
    de composants (ex. mag, ang) au lieu de 0, 1.
    """
    lines = _report_to_lines(
        report,
        member_labels,
        member_components,
        debug=debug,
    )
    if not lines:
        if debug:
            print("[VictoriaMetrics] skip: no entries or rpt_id or no numeric values", flush=True)
        return
    if debug:
        for line in lines:
            print(f"[DEBUG VM LINE] {line}", flush=True)
    if batch_interval_sec <= 0:
        # Envoi immédiat (comportement legacy, pas de batching)
        _do_post_impl(base_url, lines, debug)
        return
    batcher = _Batcher.get(base_url, batch_interval_sec, batch_max_lines)
    batcher.add(lines, debug=debug)
    batcher.ensure_started()


def push_mms_report_flush(base_url: str) -> None:
    """Force l'envoi immédiat du buffer pour l'URL donnée."""
    batcher = _Batcher.get(base_url, DEFAULT_BATCH_INTERVAL_SEC, DEFAULT_BATCH_SIZE_MAX)
    batcher.flush()
