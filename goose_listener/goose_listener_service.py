"""GOOSE Listener : scan de flux et mesure delta déclenchement → seconde pile."""
from __future__ import annotations

import math
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parent.parent
GOOSE_ROOT = ROOT / "goose"
for p in (str(ROOT), str(GOOSE_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from goose61850.transport import GooseSubscriber, nic_rx_stats  # noqa: E402
from goose61850.types import GooseFrame  # noqa: E402
from trigger_classify import classify_trigger  # noqa: E402

Key = Tuple[str, str]  # (gocb_ref, go_id)

EVENT_FILTER_DECLENCHEMENTS_ONLY = "declenchements_only"
PANEL_EVENTS_MAX = 50
PANEL_PROBLEMS_MAX = 50
EVENT_FILTER_ALL = "all"
VALID_EVENT_FILTERS = {EVENT_FILTER_DECLENCHEMENTS_ONLY, EVENT_FILTER_ALL}


def _normalize_event_filter(event_filter: str) -> str:
    """Alias historique defauts_only → declenchements_only."""
    if event_filter == "defauts_only":
        return EVENT_FILTER_DECLENCHEMENTS_ONLY
    return event_filter

DEFAULT_PROBLEM_CYCLE_S = 4.0
DEFAULT_PROBLEM_THRESHOLD_MS = 40.0
PROBLEMS_TIME_BUCKET_S = 10.0
PROBLEMS_CONTEXT_MAX = 30
HIST_BIN_MS = 1.0
NIC_DELTA_SANITY_MAX = 10_000_000
RING_WINDOW_S = 4.0
MAX_RING_DUMPS = 80
DUMPS_DIR = Path(__file__).resolve().parent / "dumps"


def _stream_key(gocb_ref: str, go_id: Optional[str]) -> Key:
    return (gocb_ref, go_id or "")


def _missing_grace_s(cycle_s: float) -> float:
    return min(5.0, cycle_s * 0.25)


def _nic_counter_delta(baseline: Dict[str, int], current: Dict[str, int]) -> Dict[str, int]:
    """Delta entre deux lectures sysfs (gère reset compteur, ignore écarts absurdes)."""
    out: Dict[str, int] = {}
    if not baseline:
        return out
    for name in set(baseline) | set(current):
        prev = int(baseline.get(name, 0))
        now = int(current.get(name, 0))
        if now < prev:
            continue
        delta = now - prev
        if delta > NIC_DELTA_SANITY_MAX:
            continue
        if delta > 0:
            out[name] = delta
    return out


def is_trigger_event(
    prev_st_num: Optional[int],
    st_num: int,
    sq_num: int,
    *,
    key: Key,
    last_trigger_st: Dict[Key, int],
    lenient: bool = False,
) -> bool:
    """Déclenchement GOOSE : stNum↑ et sqNum=0 (strict ou tolérant si sqNum=0 manqué)."""
    if prev_st_num is None:
        return False
    if st_num <= prev_st_num:
        return False
    if sq_num == 0:
        return True
    if lenient:
        return last_trigger_st.get(key) != st_num
    return False


def _missing_slots_between(
    t_prev: float,
    t_next: float,
    cycle_s: float,
    *,
    confirm_before: Optional[float] = None,
) -> List[float]:
    """Timestamps attendus manquants strictement entre t_prev et t_next."""
    grace = _missing_grace_s(cycle_s)
    gap = t_next - t_prev
    if gap <= cycle_s + grace:
        return []
    n_periods = max(1, int(round(gap / cycle_s)))
    n_missing = max(0, n_periods - 1)
    slots = [t_prev + k * cycle_s for k in range(1, n_missing + 1)]
    if confirm_before is not None:
        slots = [s for s in slots if s + grace <= confirm_before]
    return slots


def _index_events_by_key(events: List[TriggerEvent]) -> Dict[Key, List[TriggerEvent]]:
    idx: Dict[Key, List[TriggerEvent]] = {}
    for e in events:
        idx.setdefault(_stream_key(e.gocb_ref, e.go_id), []).append(e)
    for rows in idx.values():
        rows.sort(key=lambda ev: ev.ts_goose)
    return idx


def _declenchements_for_key(events: List[TriggerEvent], key: Key) -> List[TriggerEvent]:
    return [
        e for e in events
        if _stream_key(e.gocb_ref, e.go_id) == key and e.event_kind == "declenchement"
    ]


def _declenchements_from_index(index: Dict[Key, List[TriggerEvent]], key: Key) -> List[TriggerEvent]:
    return [e for e in index.get(key, ()) if e.event_kind == "declenchement"]


def _events_between_declenchements(
    events: List[TriggerEvent],
    key: Key,
    t_lo: float,
    t_hi: float,
    *,
    limit: int = PROBLEMS_CONTEXT_MAX,
) -> List[Dict[str, Any]]:
    """Déclenchements entre deux défauts (exclus) pour diagnostic."""
    return _events_between_indexed(
        [e for e in events if _stream_key(e.gocb_ref, e.go_id) == key],
        t_lo,
        t_hi,
        limit=limit,
    )


def _event_context_row(e: TriggerEvent) -> Dict[str, Any]:
    return {
        "ts_goose": e.ts_goose,
        "event_kind": e.event_kind,
        "event_label": e.event_label,
        "st_num": e.st_num,
        "sq_num": e.sq_num,
        "delta_net_ms": round(e.delta_net_ms, 3),
        "change_detail": e.change_detail,
    }


def _events_between_indexed(
    key_events: List[TriggerEvent],
    t_lo: float,
    t_hi: float,
    *,
    limit: int = PROBLEMS_CONTEXT_MAX,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for e in key_events:
        if e.ts_goose <= t_lo:
            continue
        if e.ts_goose >= t_hi:
            break
        rows.append(_event_context_row(e))
        if len(rows) >= limit:
            break
    return rows


def _compute_problems(
    targets: Dict[Key, AnalysisTarget],
    events: List[TriggerEvent],
    *,
    cycle_s: float,
    threshold_ms: float,
    running: bool,
    now: float,
) -> List[Dict[str, Any]]:
    problems: List[Dict[str, Any]] = []
    cycle_s = max(1.0, float(cycle_s))
    threshold_ms = max(0.0, float(threshold_ms))
    index = _index_events_by_key(events)

    for key, target in targets.items():
        key_events = index.get(key, ())
        declenchements = _declenchements_from_index(index, key)

        for evt in declenchements:
            sq = evt.sq_num
            if sq != 0:
                problems.append({
                    "kind": "capture_incomplete",
                    "gocb_ref": evt.gocb_ref,
                    "go_id": evt.go_id,
                    "ts_goose": evt.ts_goose,
                    "ts_expected": None,
                    "delta_net_ms": round(evt.delta_net_ms, 3),
                    "st_num": evt.st_num,
                    "sq_num": sq,
                    "message": (
                        f"sqNum={sq} (sqNum=0 manqué en capture) — "
                        f"Δ={evt.delta_net_ms:.2f} ms non fiable"
                    ),
                })
                continue
            if evt.delta_net_ms > threshold_ms:
                problems.append({
                    "kind": "delay_exceeded",
                    "gocb_ref": evt.gocb_ref,
                    "go_id": evt.go_id,
                    "ts_goose": evt.ts_goose,
                    "ts_expected": None,
                    "delta_net_ms": round(evt.delta_net_ms, 3),
                    "st_num": evt.st_num,
                    "sq_num": sq,
                    "message": (
                        f"Δ net {evt.delta_net_ms:.2f} ms > seuil {threshold_ms:.0f} ms"
                    ),
                })

        for i in range(len(declenchements) - 1):
            t_prev = declenchements[i].ts_goose
            t_next = declenchements[i + 1].ts_goose
            context = _events_between_indexed(key_events, t_prev, t_next)
            gap = t_next - t_prev
            for ts_exp in _missing_slots_between(t_prev, t_next, cycle_s):
                problems.append({
                    "kind": "missing",
                    "gocb_ref": target.gocb_ref,
                    "go_id": target.go_id,
                    "ts_goose": None,
                    "ts_expected": ts_exp,
                    "delta_net_ms": None,
                    "st_num": None,
                    "message": (
                        f"Déclenchement manquant (cycle {cycle_s:.0f} s, "
                        f"écart {gap:.1f} s)"
                    ),
                    "context": context,
                    "gap_s": round(gap, 3),
                    "declenchement_prev_ts": t_prev,
                    "declenchement_next_ts": t_next,
                })

        if declenchements and running:
            t_last = declenchements[-1].ts_goose
            grace = _missing_grace_s(cycle_s)
            gap = now - t_last
            if gap > cycle_s + grace:
                n_overdue = int((gap - grace) // cycle_s)
                if n_overdue >= 1:
                    ts_exp = t_last + n_overdue * cycle_s
                    context = _events_between_indexed(key_events, t_last, now)
                    problems.append({
                        "kind": "missing",
                        "gocb_ref": target.gocb_ref,
                        "go_id": target.go_id,
                        "ts_goose": None,
                        "ts_expected": ts_exp,
                        "delta_net_ms": None,
                        "st_num": None,
                        "message": (
                            f"Déclenchement manquant (cycle {cycle_s:.0f} s, "
                            f"écart {gap:.1f} s) — en retard"
                        ),
                        "context": context,
                        "gap_s": round(gap, 3),
                        "declenchement_prev_ts": t_last,
                        "declenchement_next_ts": None,
                    })

    return _dedupe_problems(problems)


def _problem_sort_key(p: Dict[str, Any]) -> float:
    ts = p.get("ts_goose") or p.get("ts_expected") or 0.0
    return float(ts)


def _fmt_ts_export(ts: float) -> str:
    from datetime import datetime

    d = datetime.fromtimestamp(ts)
    return d.strftime("%d/%m/%Y %H:%M:%S") + f".{int((ts % 1) * 1000):03d}"


def _event_export_line(e: TriggerEvent) -> str:
    detail = f"  {e.change_detail}" if e.change_detail else ""
    return (
        f"{_fmt_ts_export(e.ts_goose)}  {e.event_label}  "
        f"gocbRef={e.gocb_ref}  goID={e.go_id}  APPID=0x{e.app_id:04X}  "
        f"stNum={e.st_num}  sqNum={e.sq_num}  "
        f"Δ={e.delta_net_ms:.3f} ms  lag={e.processing_lag_ms:.2f} ms{detail}"
    )


def _problem_export_line(p: Dict[str, Any]) -> str:
    kind = p.get("kind", "")
    ts = p.get("ts_goose") or p.get("ts_expected")
    ts_s = _fmt_ts_export(float(ts)) if ts is not None else "—"
    parts = [
        ts_s,
        str(kind),
        f"goID={p.get('go_id') or '—'}",
    ]
    if p.get("delta_net_ms") is not None:
        parts.append(f"Δ={p['delta_net_ms']:.3f} ms")
    if p.get("sq_num") is not None:
        parts.append(f"sqNum={p['sq_num']}")
    if p.get("st_num") is not None:
        parts.append(f"stNum={p['st_num']}")
    msg = p.get("message")
    if msg:
        parts.append(str(msg))
    return "  ".join(parts)


HistBuckets = Dict[Key, Dict[int, int]]


def _delta_bin(delta_ms: float, *, bin_width_ms: float = HIST_BIN_MS) -> int:
    return int(math.floor(float(delta_ms) / bin_width_ms + 1e-9))


def _hist_buckets_add(buckets: HistBuckets, key: Key, delta_ms: float) -> None:
    b = _delta_bin(delta_ms)
    per_key = buckets.setdefault(key, {})
    per_key[b] = per_key.get(b, 0) + 1


def _hist_buckets_total(buckets: HistBuckets) -> int:
    return sum(sum(per_key.values()) for per_key in buckets.values())


def _build_histogram_from_buckets(
    per_key_buckets: HistBuckets,
    targets_snap: Dict[Key, AnalysisTarget],
    *,
    bin_width_ms: float = HIST_BIN_MS,
) -> Optional[Dict[str, Any]]:
    """Construit l'histogramme depuis des compteurs cumulés (indépendant de la RAM)."""
    all_bins: Set[int] = set()
    for buckets in per_key_buckets.values():
        all_bins.update(buckets.keys())
    if not all_bins:
        return None

    lo_bin = min(all_bins)
    hi_bin = max(all_bins)
    lo = lo_bin * bin_width_ms
    hi = (hi_bin + 1) * bin_width_ms
    num_bins = hi_bin - lo_bin + 1
    edges = [lo + i * bin_width_ms for i in range(num_bins + 1)]

    series: List[Dict[str, Any]] = []
    palette_idx = 0
    for key, t in targets_snap.items():
        key_buckets = per_key_buckets.get(key, {})
        counts = [0] * num_bins
        total = 0
        for b, c in key_buckets.items():
            idx = b - lo_bin
            if 0 <= idx < num_bins:
                counts[idx] = c
            total += c
        label = t.gocb_ref if not t.go_id else f"{t.gocb_ref} / {t.go_id}"
        series.append({
            "label": label,
            "gocb_ref": t.gocb_ref,
            "go_id": t.go_id,
            "color_index": palette_idx,
            "counts": counts,
            "total": total,
        })
        palette_idx += 1

    return {
        "bin_edges": [round(e, 3) for e in edges],
        "bin_width_ms": bin_width_ms,
        "series": series,
        "total": _hist_buckets_total(per_key_buckets),
    }


def _dedupe_problems(problems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Évite les doublons pour un même manquant, sans fusionner les Δ>seuil."""
    deduped: List[Dict[str, Any]] = []
    seen: Set[Tuple[Any, ...]] = set()
    for p in sorted(problems, key=_problem_sort_key, reverse=True):
        kind = p.get("kind")
        go_id = str(p.get("go_id") or "")
        if kind == "missing":
            key_d: Tuple[Any, ...] = ("missing", go_id, p.get("ts_expected"))
        elif kind == "delay_exceeded":
            key_d = ("delay", go_id, p.get("ts_goose"), p.get("st_num"))
        elif kind == "capture_incomplete":
            key_d = ("capture", go_id, p.get("ts_goose"), p.get("st_num"))
        else:
            key_d = (kind, go_id, p.get("ts_goose"), p.get("ts_expected"), p.get("st_num"))
        if key_d in seen:
            continue
        seen.add(key_d)
        deduped.append(p)
    return deduped


@dataclass
class ScanEntry:
    gocb_ref: str
    go_id: str
    app_id: int
    frames: int = 0


@dataclass
class AnalysisTarget:
    gocb_ref: str
    go_id: str
    delay_ms: float = 0.0


@dataclass
class _PollSnapshot:
    mode: str
    last_error: Optional[str]
    capture_running: bool
    scan_running: bool
    scan_duration_s: float
    scan_deadline: float
    scan_entries: List[ScanEntry]
    analysis_running: bool
    event_filter: str
    targets: Dict[Key, AnalysisTarget]
    events: List[TriggerEvent]
    events_total: int
    events_rev: int
    cycle_s: float
    threshold_ms: float
    hist_buckets: HistBuckets


@dataclass
class _AnalysisPollCache:
    key: Optional[Tuple[Any, ...]] = None
    problems_all: List[Dict[str, Any]] = field(default_factory=list)
    filtered_count: int = 0
    events_recent: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class TriggerEvent:
    ts_goose: float
    gocb_ref: str
    go_id: str
    app_id: int
    st_num: int
    sq_num: int
    ts_seconde_pile: float
    delta_net_ms: float
    processing_lag_ms: float = 0.0
    event_kind: str = "inconnu"
    event_label: str = "Inconnu"
    change_detail: str = ""


@dataclass
class GooseListenerManager:
    iface: str
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _capture_thread: Optional[threading.Thread] = field(default=None, repr=False)
    _subscriber: Optional[object] = field(default=None, repr=False)
    _capture_active: bool = field(default=False, repr=False)
    _mode: str = "idle"  # idle | scan | analyze
    _last_error: Optional[str] = field(default=None, repr=False)

    # Scan
    _scan_deadline: float = 0.0
    _scan_duration_s: float = 5.0
    _scan_entries: Dict[Key, ScanEntry] = field(default_factory=dict, repr=False)

    # Analyse
    _targets: Dict[Key, AnalysisTarget] = field(default_factory=dict, repr=False)
    _last_st_num: Dict[Key, int] = field(default_factory=dict, repr=False)
    _last_trigger_st: Dict[Key, int] = field(default_factory=dict, repr=False)
    _last_all_data: Dict[Key, list] = field(default_factory=dict, repr=False)
    _event_filter: str = EVENT_FILTER_DECLENCHEMENTS_ONLY
    _problem_cycle_s: float = DEFAULT_PROBLEM_CYCLE_S
    _problem_threshold_ms: float = DEFAULT_PROBLEM_THRESHOLD_MS
    _events: Deque[TriggerEvent] = field(default_factory=lambda: deque(maxlen=10000), repr=False)
    _events_by_key: Dict[Key, List[float]] = field(default_factory=dict, repr=False)
    _hist_all_buckets: HistBuckets = field(default_factory=dict, repr=False)
    _hist_declenchement_buckets: HistBuckets = field(default_factory=dict, repr=False)
    _events_rev: int = field(default=0, repr=False)
    _targets_frozen: frozenset[Key] = field(default_factory=frozenset, repr=False)
    _analysis_poll_cache: _AnalysisPollCache = field(
        default_factory=_AnalysisPollCache,
        repr=False,
    )
    _status_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _analysis_capture_baseline: Dict[str, Any] = field(default_factory=dict, repr=False)
    _analysis_baseline_active: bool = field(default=False, repr=False)
    _problem_snapshot_keys: Set[Tuple[Any, ...]] = field(default_factory=set, repr=False)
    _ring_dump_records: List[Dict[str, Any]] = field(default_factory=list, repr=False)
    _ring_dump_seq: int = field(default=0, repr=False)

    MAX_EVENTS = 10000
    CAPTURE_QUEUE_WARN = 100

    def _ensure_capture_if_needed(self) -> None:
        with self._lock:
            if self._mode not in ("scan", "analyze"):
                return
        self._ensure_capture()

    def _analysis_cache_key(
        self,
        snap: _PollSnapshot,
        now: float,
    ) -> Tuple[Any, ...]:
        cap = self._capture_reliability(analysis_running=snap.analysis_running)
        mux = cap.get("mux") or {}
        return (
            snap.events_rev,
            snap.event_filter,
            snap.cycle_s,
            snap.threshold_ms,
            snap.analysis_running,
            int(now // PROBLEMS_TIME_BUCKET_S),
            tuple(sorted(snap.targets.keys())),
            cap.get("drops_since_analysis_start", 0),
            cap.get("queue_size", 0),
            cap.get("reliable", True),
            mux.get("pcap_drop", 0),
            mux.get("pcap_ifdrop", 0),
            mux.get("bpf_mode"),
        )

    def _poll_snapshot(self, *, load_events: bool = True) -> _PollSnapshot:
        with self._lock:
            self._expire_scan_if_due()
            capture_running = bool(
                self._capture_thread
                and self._capture_thread.is_alive()
                and self._capture_active
            )
            scan_running = self._mode == "scan"
            analysis_running = self._mode == "analyze"
            return _PollSnapshot(
                mode=self._mode,
                last_error=self._last_error,
                capture_running=capture_running,
                scan_running=scan_running,
                scan_duration_s=self._scan_duration_s,
                scan_deadline=self._scan_deadline,
                scan_entries=list(self._scan_entries.values()),
                analysis_running=analysis_running,
                event_filter=self._event_filter,
                targets=dict(self._targets),
                events=list(self._events) if load_events else [],
                events_total=len(self._events),
                events_rev=self._events_rev,
                cycle_s=self._problem_cycle_s,
                threshold_ms=self._problem_threshold_ms,
                hist_buckets=self._active_hist_buckets_locked(),
            )

    def _active_hist_buckets_locked(self) -> HistBuckets:
        """Copie des compteurs histogramme actifs (_lock tenu)."""
        src = (
            self._hist_all_buckets
            if self._event_filter == EVENT_FILTER_ALL
            else self._hist_declenchement_buckets
        )
        return {k: dict(v) for k, v in src.items()}

    def _ensure_capture(self) -> None:
        if self._capture_thread and self._capture_thread.is_alive():
            return
        self._capture_active = True
        self._capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._capture_thread.start()

    def _stop_capture_if_idle(self) -> None:
        if self._mode == "idle":
            self._capture_active = False

    def _expire_scan_if_due(self) -> None:
        """Termine un scan dont la durée est écoulée (_lock tenu)."""
        if self._mode == "scan" and time.time() >= self._scan_deadline:
            self._mode = "idle"
            self._stop_capture_if_idle()

    def _capture_should_stop(self) -> bool:
        with self._lock:
            if not self._capture_active:
                return True
            self._expire_scan_if_due()
            return not self._capture_active

    def _capture_loop(self) -> None:
        sub = GooseSubscriber(iface=self.iface, callback=self._on_frame)
        self._subscriber = sub
        while self._capture_active:
            try:
                sub.run_until(should_stop=self._capture_should_stop)
            except Exception as exc:
                with self._lock:
                    self._last_error = str(exc)
                time.sleep(0.5)

    def _on_frame(self, frame: GooseFrame) -> None:
        ts_goose = frame.ts_rx if frame.ts_rx is not None else time.time()
        ts_now = time.time()
        pdu = frame.pdu
        if pdu is None:
            return

        key = _stream_key(pdu.gocb_ref, pdu.go_id)
        mode = self._mode
        if mode == "idle":
            return
        if mode == "analyze" and key not in self._targets_frozen:
            return

        if mode == "scan":
            with self._lock:
                if self._mode != "scan":
                    return
                ent = self._scan_entries.get(key)
                if ent is None:
                    ent = ScanEntry(
                        gocb_ref=pdu.gocb_ref,
                        go_id=pdu.go_id or "",
                        app_id=frame.app_id,
                    )
                    self._scan_entries[key] = ent
                ent.frames += 1
            return

        prev_data_copy: Optional[list] = None
        pdu_data_copy: Optional[list] = None
        delay_ms = 0.0
        is_trigger = False

        with self._lock:
            if self._mode != "analyze":
                return
            target = self._targets.get(key)
            if target is None:
                return

            prev_st = self._last_st_num.get(key)
            prev_raw = self._last_all_data.get(key)
            prev_data_copy = list(prev_raw) if prev_raw is not None else None
            self._last_st_num[key] = pdu.st_num

            if not is_trigger_event(
                prev_st,
                pdu.st_num,
                pdu.sq_num,
                key=key,
                last_trigger_st=self._last_trigger_st,
                lenient=True,
            ):
                if pdu.all_data is not None:
                    self._last_all_data[key] = list(pdu.all_data)
                return

            delay_ms = target.delay_ms
            pdu_data_copy = list(pdu.all_data) if pdu.all_data else None
            is_trigger = True

        if not is_trigger:
            return

        ts_pile = math.floor(ts_goose)
        delta_ms = (ts_goose - ts_pile) * 1000.0 - delay_ms
        kind, label, detail = classify_trigger(prev_data_copy, pdu_data_copy)
        evt = TriggerEvent(
            ts_goose=ts_goose,
            gocb_ref=pdu.gocb_ref,
            go_id=pdu.go_id or "",
            app_id=frame.app_id,
            st_num=pdu.st_num,
            sq_num=pdu.sq_num,
            ts_seconde_pile=ts_pile,
            delta_net_ms=delta_ms,
            processing_lag_ms=max(0.0, (ts_now - ts_goose) * 1000.0),
            event_kind=kind,
            event_label=label,
            change_detail=detail,
        )
        with self._lock:
            if self._mode != "analyze":
                return
            if pdu_data_copy is not None:
                self._last_all_data[key] = pdu_data_copy
            self._last_trigger_st[key] = pdu.st_num
            _hist_buckets_add(self._hist_all_buckets, key, delta_ms)
            if kind == "declenchement":
                _hist_buckets_add(self._hist_declenchement_buckets, key, delta_ms)
            if self._event_passes_filter_unlocked(evt):
                self._events.append(evt)
                self._events_rev += 1
                self._events_by_key.setdefault(key, []).append(delta_ms)

    def start_scan(self, duration_s: float = 5.0) -> Optional[str]:
        duration_s = max(0.5, min(float(duration_s), 120.0))
        with self._lock:
            if self._mode == "analyze":
                return "Analyse en cours : arrêtez l'analyse avant de scanner."
            self._mode = "scan"
            self._scan_duration_s = duration_s
            self._scan_deadline = time.time() + duration_s
            self._scan_entries.clear()
            self._last_error = None
        self._ensure_capture()
        return None

    def scan_status(self) -> Dict[str, Any]:
        snap = self._poll_snapshot()
        return self._scan_from_snapshot(snap, time.time())

    def _event_passes_filter_unlocked(self, event: TriggerEvent) -> bool:
        if self._event_filter == EVENT_FILTER_ALL:
            return True
        return event.event_kind == "declenchement"

    def _purge_events_unlocked(self) -> None:
        if self._event_filter == EVENT_FILTER_ALL:
            return
        kept = [e for e in self._events if self._event_passes_filter_unlocked(e)]
        self._events.clear()
        self._events.extend(kept)

    def set_event_filter(self, event_filter: str) -> Optional[str]:
        event_filter = _normalize_event_filter(event_filter.strip())
        if event_filter not in VALID_EVENT_FILTERS:
            return (
                f"Filtre invalide (attendu: {EVENT_FILTER_DECLENCHEMENTS_ONLY} "
                f"ou {EVENT_FILTER_ALL})."
            )
        with self._lock:
            self._event_filter = event_filter
            self._purge_events_unlocked()
            self._analysis_poll_cache.key = None
        return None

    def set_problem_config(
        self,
        cycle_s: Optional[float] = None,
        threshold_ms: Optional[float] = None,
    ) -> Optional[str]:
        with self._lock:
            if cycle_s is not None:
                if cycle_s < 1.0:
                    return "Le cycle doit être ≥ 1 s."
                self._problem_cycle_s = float(cycle_s)
            if threshold_ms is not None:
                if threshold_ms < 0:
                    return "Le seuil doit être ≥ 0 ms."
                self._problem_threshold_ms = float(threshold_ms)
            self._analysis_poll_cache.key = None
        return None

    def start_analysis(
        self,
        targets: List[AnalysisTarget],
        event_filter: str = EVENT_FILTER_DECLENCHEMENTS_ONLY,
    ) -> Optional[str]:
        if not targets:
            return "Sélectionnez au moins un gocbRef/goID."
        event_filter = _normalize_event_filter(event_filter.strip())
        if event_filter not in VALID_EVENT_FILTERS:
            return (
                f"Filtre invalide (attendu: {EVENT_FILTER_DECLENCHEMENTS_ONLY} "
                f"ou {EVENT_FILTER_ALL})."
            )
        with self._lock:
            self._expire_scan_if_due()
            if self._mode == "scan":
                return "Scan en cours : attendez la fin du scan."
            self._mode = "analyze"
            self._event_filter = event_filter
            self._targets.clear()
            self._last_st_num.clear()
            self._last_trigger_st.clear()
            self._last_all_data.clear()
            for t in targets:
                key = _stream_key(t.gocb_ref, t.go_id)
                self._targets[key] = t
            self._events.clear()
            self._events_by_key.clear()
            self._hist_all_buckets.clear()
            self._hist_declenchement_buckets.clear()
            self._events_rev = 0
            self._targets_frozen = frozenset(self._targets.keys())
            self._analysis_poll_cache.key = None
            self._last_error = None
            self._problem_snapshot_keys.clear()
        self._ensure_capture()
        self._enable_ring_capture()
        self._analysis_capture_baseline = self._snapshot_capture_baseline()
        self._analysis_baseline_active = True
        return None

    def stop_analysis(self) -> None:
        with self._lock:
            if self._mode == "analyze":
                self._mode = "idle"
            self._targets_frozen = frozenset()
            self._analysis_baseline_active = False
            self._analysis_capture_baseline = {}
            self._problem_snapshot_keys.clear()
            self._stop_capture_if_idle()
        self._disable_ring_capture()

    def _scan_from_snapshot(self, snap: _PollSnapshot, now: float) -> Dict[str, Any]:
        remaining = (
            max(0.0, snap.scan_deadline - now) if snap.scan_running else 0.0
        )
        entries = sorted(
            [
                {
                    "gocb_ref": e.gocb_ref,
                    "go_id": e.go_id,
                    "app_id": e.app_id,
                    "frames": e.frames,
                }
                for e in snap.scan_entries
            ],
            key=lambda x: (x["gocb_ref"], x["go_id"]),
        )
        return {
            "running": snap.scan_running,
            "duration_s": snap.scan_duration_s,
            "remaining_s": round(remaining, 2),
            "entries": entries,
        }

    def _analysis_from_snapshot(self, snap: _PollSnapshot, now: float) -> Dict[str, Any]:
        targets = [
            {
                "gocb_ref": t.gocb_ref,
                "go_id": t.go_id,
                "delay_ms": t.delay_ms,
            }
            for t in snap.targets.values()
        ]
        targets_snap = snap.targets
        all_events = snap.events
        event_filter = snap.event_filter
        running = snap.analysis_running
        cycle_s = snap.cycle_s
        threshold_ms = snap.threshold_ms

        cache_key = self._analysis_cache_key(snap, now)
        cache = self._analysis_poll_cache
        histogram = _build_histogram_from_buckets(snap.hist_buckets, targets_snap)
        if cache.key == cache_key:
            problems_all = cache.problems_all
            filtered_count = cache.filtered_count
            events_recent = cache.events_recent
        else:

            filtered_events = list(all_events)
            filtered_count = len(filtered_events)
            events_recent = [
                {
                    "ts_goose": e.ts_goose,
                    "gocb_ref": e.gocb_ref,
                    "go_id": e.go_id,
                    "app_id": e.app_id,
                    "st_num": e.st_num,
                    "sq_num": e.sq_num,
                    "delta_net_ms": round(e.delta_net_ms, 3),
                    "processing_lag_ms": round(e.processing_lag_ms, 2),
                    "event_kind": e.event_kind,
                    "event_label": e.event_label,
                    "change_detail": e.change_detail,
                }
                for e in filtered_events[-PANEL_EVENTS_MAX:]
            ]
            problems_all = _compute_problems(
                targets_snap,
                all_events,
                cycle_s=cycle_s,
                threshold_ms=threshold_ms,
                running=running,
                now=now,
            )
            cache.key = cache_key
            cache.problems_all = problems_all
            cache.filtered_count = filtered_count
            cache.events_recent = events_recent

        capture_rel = self._capture_reliability(analysis_running=running)
        capture_rel = {**capture_rel, "ring_buffer": self._goose_ring_stats()}
        if running and not capture_rel["reliable"]:
            problems_all = [
                {
                    "kind": "capture_unreliable",
                    "gocb_ref": "",
                    "go_id": "",
                    "ts_goose": None,
                    "ts_expected": now,
                    "delta_net_ms": None,
                    "st_num": None,
                    "sq_num": None,
                    "message": (
                        "Capture non fiable — mesures invalides : "
                        f"{capture_rel['invalid_reason']}"
                    ),
                },
                *problems_all,
            ]

        problems_all = self._attach_ring_dumps_for_new_problems(problems_all)

        problems_recent = sorted(
            problems_all,
            key=_problem_sort_key,
            reverse=True,
        )[:PANEL_PROBLEMS_MAX]
        return {
            "running": running,
            "targets": targets,
            "event_filter": event_filter,
            "capture": capture_rel,
            "event_count": filtered_count,
            "event_count_total": snap.events_total,
            "events_rev": snap.events_rev,
            "events_recent": events_recent,
            "events_panel_max": PANEL_EVENTS_MAX,
            "histogram": histogram,
            "problems_config": {
                "cycle_s": cycle_s,
                "threshold_ms": threshold_ms,
            },
            "problems": problems_recent,
            "problem_count": len(problems_all),
            "problems_panel_max": PANEL_PROBLEMS_MAX,
            "last_error": snap.last_error,
        }

    def analysis_status(self) -> Dict[str, Any]:
        now = time.time()
        snap = self._poll_snapshot(load_events=False)
        if self._analysis_poll_cache.key != self._analysis_cache_key(snap, now):
            snap = self._poll_snapshot(load_events=True)
        return self._analysis_from_snapshot(snap, now)

    def export_events_txt(self) -> str:
        with self._lock:
            events = sorted(self._events, key=lambda e: e.ts_goose)
            filt = self._event_filter
        if not events:
            return "# Aucun événement en mémoire\n"
        filt_label = (
            "déclenchements seuls"
            if filt == EVENT_FILTER_DECLENCHEMENTS_ONLY
            else "tous les événements"
        )
        header = f"# GOOSE Listener — {len(events)} événement(s) ({filt_label})\n"
        return header + "\n".join(_event_export_line(e) for e in events) + "\n"

    def export_problems_txt(self) -> str:
        now = time.time()
        with self._lock:
            running = self._mode == "analyze"
            all_events = list(self._events)
            targets_snap = dict(self._targets)
            cycle_s = self._problem_cycle_s
            threshold_ms = self._problem_threshold_ms
        problems = _compute_problems(
            targets_snap,
            all_events,
            cycle_s=cycle_s,
            threshold_ms=threshold_ms,
            running=running,
            now=now,
        )
        if not problems:
            return "# Aucun problème détecté\n"
        ordered = sorted(problems, key=_problem_sort_key)
        header = f"# GOOSE Listener — {len(ordered)} problème(s)\n"
        return header + "\n".join(_problem_export_line(p) for p in ordered) + "\n"

    def _enable_ring_capture(self) -> None:
        try:
            from processbus_capture import ProcessbusCapture  # noqa: WPS433

            ProcessbusCapture.get(self.iface).enable_goose_ring(RING_WINDOW_S)
        except Exception:
            pass

    def _disable_ring_capture(self) -> None:
        try:
            from processbus_capture import ProcessbusCapture  # noqa: WPS433

            ProcessbusCapture.get(self.iface).disable_goose_ring()
        except Exception:
            pass

    def _ring_snapshot_packets(self) -> List[Tuple[float, bytes]]:
        try:
            from processbus_capture import ProcessbusCapture  # noqa: WPS433

            return ProcessbusCapture.get(self.iface).snapshot_goose_ring()
        except Exception:
            return []

    def _goose_ring_stats(self) -> Dict[str, Any]:
        try:
            from processbus_capture import ProcessbusCapture  # noqa: WPS433

            return ProcessbusCapture.get(self.iface).goose_ring_stats()
        except Exception:
            return {"enabled": False}

    def _problem_snapshot_key(self, problem: Dict[str, Any]) -> Tuple[Any, ...]:
        kind = problem.get("kind")
        if kind == "capture_unreliable":
            return ("capture_unreliable",)
        return (
            kind,
            problem.get("go_id") or "",
            problem.get("ts_goose"),
            problem.get("ts_expected"),
            problem.get("st_num"),
        )

    def _attach_ring_dumps_for_new_problems(
        self,
        problems: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for raw in problems:
            p = dict(raw)
            key = self._problem_snapshot_key(p)
            if key not in self._problem_snapshot_keys:
                meta = self._save_ring_snapshot(p)
                if meta is not None:
                    p["dump_id"] = meta["dump_id"]
                    p["dump_packets"] = meta["packet_count"]
                self._problem_snapshot_keys.add(key)
            elif p.get("dump_id"):
                pass
            else:
                for rec in reversed(self._ring_dump_records):
                    if rec.get("problem_key") == key:
                        p["dump_id"] = rec["dump_id"]
                        p["dump_packets"] = rec.get("packet_count")
                        break
            out.append(p)
        return out

    def _save_ring_snapshot(self, problem: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        packets = self._ring_snapshot_packets()
        if not packets:
            return None
        gl_dir = str(Path(__file__).resolve().parent)
        if gl_dir not in sys.path:
            sys.path.insert(0, gl_dir)
        from goose_ring_pcap import write_pcap, _safe_slug  # noqa: WPS433

        kind = str(problem.get("kind") or "problem")
        go_id = str(problem.get("go_id") or "")
        self._ring_dump_seq += 1
        slug = _safe_slug(go_id or kind)
        dump_id = (
            f"{self._ring_dump_seq:04d}_"
            f"{time.strftime('%Y%m%d_%H%M%S')}_{kind}_{slug}"
        )
        path = DUMPS_DIR / f"{dump_id}.pcap"
        count = write_pcap(path, packets)
        meta = {
            "dump_id": dump_id,
            "path": path,
            "created_at": time.time(),
            "reason": kind,
            "packet_count": count,
            "window_s": RING_WINDOW_S,
            "go_id": go_id,
            "problem_key": self._problem_snapshot_key(problem),
        }
        self._ring_dump_records.append(meta)
        self._prune_ring_dumps()
        return meta

    def _prune_ring_dumps(self) -> None:
        while len(self._ring_dump_records) > MAX_RING_DUMPS:
            old = self._ring_dump_records.pop(0)
            p = old.get("path")
            if isinstance(p, Path):
                try:
                    p.unlink(missing_ok=True)
                except OSError:
                    pass

    def list_ring_dumps(self) -> Dict[str, Any]:
        dumps = [
            {
                "dump_id": rec["dump_id"],
                "created_at": rec["created_at"],
                "reason": rec.get("reason"),
                "go_id": rec.get("go_id") or "",
                "packet_count": rec.get("packet_count"),
                "window_s": rec.get("window_s", RING_WINDOW_S),
            }
            for rec in reversed(self._ring_dump_records)
        ]
        return {
            "window_s": RING_WINDOW_S,
            "count": len(dumps),
            "max_dumps": MAX_RING_DUMPS,
            "ring_buffer": self._goose_ring_stats(),
            "dumps": dumps,
        }

    def read_ring_dump_bytes(self, dump_id: str) -> Optional[bytes]:
        safe = (dump_id or "").strip()
        if not safe or "/" in safe or "\\" in safe or ".." in safe:
            return None
        for rec in self._ring_dump_records:
            if rec.get("dump_id") == safe:
                path = rec.get("path")
                if isinstance(path, Path) and path.is_file():
                    return path.read_bytes()
                return None
        path = DUMPS_DIR / f"{safe}.pcap"
        if path.is_file():
            return path.read_bytes()
        return None

    def _mux_stats(self) -> Dict[str, Any]:
        try:
            root = str(ROOT)
            if root not in sys.path:
                sys.path.insert(0, root)
            from processbus_capture import ProcessbusCapture  # noqa: WPS433

            return ProcessbusCapture.get(self.iface).stats()
        except Exception:
            return {}

    def _subscriber_stats(self) -> Dict[str, Any]:
        sub = self._subscriber
        if sub is None:
            base = {
                "backend": "pcapy",
                "queue_size": 0,
                "drops": 0,
                "packets": 0,
                "nic": nic_rx_stats(self.iface),
            }
        else:
            base = sub.stats()
            base["backend"] = "pcapy"
            base["nic"] = nic_rx_stats(self.iface)
        mux = self._mux_stats()
        base["multiplexed"] = bool(mux.get("multiplexed"))
        base["mux"] = mux
        return base

    def _snapshot_capture_baseline(self) -> Dict[str, Any]:
        stats = self._subscriber_stats()
        mux = stats.get("mux") or {}
        return {
            "drops": int(stats.get("drops", 0)),
            "nic": dict(stats.get("nic", {})),
            "pcap_drop": int(mux.get("pcap_drop", 0)),
            "pcap_ifdrop": int(mux.get("pcap_ifdrop", 0)),
            "sv_queue_drops": int(mux.get("sv_queue_drops", 0)),
        }

    def _capture_reliability(self, *, analysis_running: bool) -> Dict[str, Any]:
        stats = self._subscriber_stats()
        mux = stats.get("mux") or {}
        nic_now = stats.get("nic") or {}
        queue_size = int(stats.get("queue_size", 0))
        track_deltas = analysis_running and self._analysis_baseline_active
        baseline = self._analysis_capture_baseline if track_deltas else {}

        drops_delta = 0
        pcap_drop_delta = 0
        pcap_ifdrop_delta = 0
        sv_q_drop_delta = 0
        nic_delta: Dict[str, int] = {}
        nic_notes: List[str] = []
        reasons: List[str] = []

        if track_deltas:
            drops_delta = max(0, int(stats.get("drops", 0)) - int(baseline.get("drops", 0)))
            nic_delta = _nic_counter_delta(
                {k: int(v) for k, v in (baseline.get("nic") or {}).items()},
                {k: int(v) for k, v in nic_now.items()},
            )
            pcap_drop_delta = max(
                0,
                int(mux.get("pcap_drop", 0)) - int(baseline.get("pcap_drop", 0)),
            )
            pcap_ifdrop_delta = max(
                0,
                int(mux.get("pcap_ifdrop", 0)) - int(baseline.get("pcap_ifdrop", 0)),
            )
            sv_q_drop_delta = max(
                0,
                int(mux.get("sv_queue_drops", 0)) - int(baseline.get("sv_queue_drops", 0)),
            )
            if drops_delta:
                reasons.append(f"{drops_delta} paquet(s) perdus (file Python GOOSE)")
            if queue_size > self.CAPTURE_QUEUE_WARN:
                reasons.append(f"file GOOSE {queue_size} (retard traitement)")
            if pcap_drop_delta:
                reasons.append(f"libpcap ps_drop +{pcap_drop_delta}")
            if pcap_ifdrop_delta:
                reasons.append(f"libpcap ps_ifdrop +{pcap_ifdrop_delta}")
            if sv_q_drop_delta:
                reasons.append(f"file SV +{sv_q_drop_delta}")
            bpf_mode = mux.get("bpf_mode")
            pcap_ok = pcap_drop_delta == 0 and pcap_ifdrop_delta == 0
            missed = nic_delta.get("rx_missed_errors", 0)
            if missed and not (bpf_mode == "goose" and pcap_ok):
                nic_notes.append(f"rx_missed_errors +{missed}")
            rx_drop = nic_delta.get("rx_dropped", 0)
            if rx_drop and bpf_mode != "goose":
                nic_notes.append(
                    f"rx_dropped +{rx_drop} (compteur interface, pas libpcap)"
                )
            elif rx_drop and bpf_mode == "goose" and not pcap_ok:
                nic_notes.append(
                    f"rx_dropped +{rx_drop} (bus chargé + pertes libpcap)"
                )

        reliable = not reasons if track_deltas else True

        return {
            "reliable": reliable,
            "backend": stats.get("backend", "pcapy"),
            "drops_total": int(stats.get("drops", 0)),
            "drops_since_analysis_start": drops_delta,
            "packets": int(stats.get("packets", 0)),
            "queue_size": queue_size,
            "queue_warn": self.CAPTURE_QUEUE_WARN,
            "pcap_drop_delta": pcap_drop_delta,
            "pcap_ifdrop_delta": pcap_ifdrop_delta,
            "mux": mux,
            "nic": nic_now,
            "nic_delta_since_analysis_start": nic_delta,
            "nic_advisory": "; ".join(nic_notes) if nic_notes else None,
            "invalid_reason": "; ".join(reasons) if reasons else None,
        }

    def _capture_debug_stats(self) -> Dict[str, Any]:
        rel = self._capture_reliability(analysis_running=self._mode == "analyze")
        mux = self._mux_stats()
        return {
            "backend": rel["backend"],
            "queue_size": rel["queue_size"],
            "drops": rel["drops_total"],
            "drops_since_analysis_start": rel["drops_since_analysis_start"],
            "packets": rel["packets"],
            "reliable": rel["reliable"],
            "invalid_reason": rel["invalid_reason"],
            "nic": rel["nic"],
            "nic_delta_since_analysis_start": rel["nic_delta_since_analysis_start"],
            "nic_advisory": rel["nic_advisory"],
            "pcap_drop_delta": rel["pcap_drop_delta"],
            "pcap_ifdrop_delta": rel["pcap_ifdrop_delta"],
            "multiplexed": bool(mux.get("multiplexed")),
            "mux": mux,
        }

    def status(self) -> Dict[str, Any]:
        self._ensure_capture_if_needed()
        with self._status_lock:
            now = time.time()
            snap = self._poll_snapshot(load_events=False)
            if self._analysis_poll_cache.key != self._analysis_cache_key(snap, now):
                snap = self._poll_snapshot(load_events=True)
            return self._status_from_snapshot(snap, now)

    def _status_from_snapshot(self, snap: _PollSnapshot, now: float) -> Dict[str, Any]:
        return {
            "iface": self.iface,
            "capture_running": snap.capture_running,
            "capture": self._capture_debug_stats(),
            "mode": snap.mode,
            "scan": self._scan_from_snapshot(snap, now),
            "analysis": self._analysis_from_snapshot(snap, now),
            "last_error": snap.last_error,
        }


_manager: Optional[GooseListenerManager] = None
_manager_lock = threading.Lock()


def init_goose_listener(iface: str) -> GooseListenerManager:
    global _manager
    with _manager_lock:
        if _manager is not None and _manager.iface == iface:
            return _manager
        if _manager is not None:
            _manager._capture_active = False
        _manager = GooseListenerManager(iface=iface)
        return _manager


def get_goose_listener() -> Optional[GooseListenerManager]:
    return _manager
