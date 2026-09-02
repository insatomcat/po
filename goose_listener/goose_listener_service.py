"""GOOSE Listener : scan de flux et mesure delta déclenchement → référence SV (smpCnt / cycle)."""
from __future__ import annotations

import json
import math
import random
import re
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple

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

DEFAULT_PROBLEM_THRESHOLD_MS = 40.0
DEMO_DELAY_MARGIN_MS = 45.0
PROBLEMS_TIME_BUCKET_S = 10.0
PROBLEMS_CONTEXT_MAX = 30
HIST_BIN_MS = 1.0
NIC_DELTA_SANITY_MAX = 10_000_000
RING_WINDOW_S = 4.0
MAX_RING_DUMPS = 80
CAPTURE_WARMUP_S = 2.0
CAPTURE_WARMUP_MAX_S = 8.0
_GL_DIR = Path(__file__).resolve().parent
DUMPS_DIR = _GL_DIR / "dumps"
ANALYSIS_STATE_PATH = _GL_DIR / "analysis_state.json"
SMP_PER_SEC = 4800
_DEP_RE = re.compile(r"DEP(\d+)", re.IGNORECASE)

_sv_flows_getter: Optional[Callable[[], List[Dict[str, Any]]]] = None


def set_sv_flows_getter(fn: Optional[Callable[[], List[Dict[str, Any]]]]) -> None:
    """Enregistre un getter des flux SV (po_service) pour lier gocbRef → svID."""
    global _sv_flows_getter
    _sv_flows_getter = fn


def _stream_key(gocb_ref: str, go_id: Optional[str]) -> Key:
    return (gocb_ref, go_id or "")


def _targets_from_payload(raw_targets: Any) -> List[AnalysisTarget]:
    """Construit la liste de cibles depuis un JSON (API ou fichier d'état)."""
    targets: List[AnalysisTarget] = []
    if not isinstance(raw_targets, list):
        return targets
    for item in raw_targets:
        if not isinstance(item, dict):
            continue
        gocb_ref = str(item.get("gocb_ref") or "").strip()
        if not gocb_ref:
            continue
        go_id = str(item.get("go_id") or "").strip()
        try:
            delay_ms = max(0.0, float(item.get("delay_ms") or 0))
        except (TypeError, ValueError):
            delay_ms = 0.0
        svid = str(item.get("svid") or "").strip() or None
        if "svid_manual" in item:
            svid_manual = bool(item.get("svid_manual"))
        else:
            svid_manual = bool(svid)
        targets.append(
            AnalysisTarget(
                gocb_ref=gocb_ref,
                go_id=go_id,
                delay_ms=delay_ms,
                svid=svid,
                svid_manual=svid_manual,
            )
        )
    return targets


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


def _problem_delay_exceeded(evt: TriggerEvent, threshold_ms: float) -> Dict[str, Any]:
    return {
        "kind": "delay_exceeded",
        "gocb_ref": evt.gocb_ref,
        "go_id": evt.go_id,
        "ts_goose": evt.ts_goose,
        "ts_expected": None,
        "delta_net_ms": round(evt.delta_net_ms, 3),
        "st_num": evt.st_num,
        "sq_num": evt.sq_num,
        "message": (
            f"Δ net {evt.delta_net_ms:.2f} ms > seuil {threshold_ms:.0f} ms"
        ),
    }


def _problem_excludes_histogram_delta(p: Dict[str, Any]) -> bool:
    return p.get("kind") in ("delay_exceeded", "capture_incomplete")


def _problem_capture_incomplete(evt: TriggerEvent) -> Dict[str, Any]:
    sq = evt.sq_num
    return {
        "kind": "capture_incomplete",
        "gocb_ref": evt.gocb_ref,
        "go_id": evt.go_id,
        "ts_goose": evt.ts_goose,
        "ts_expected": None,
        "delta_net_ms": round(evt.delta_net_ms, 3),
        "st_num": evt.st_num,
        "sq_num": sq,
        "message": (
            f"sqNum={sq} (sqNum=0 manqué en capture) - "
            f"Δ={evt.delta_net_ms:.2f} ms non fiable"
        ),
    }


def _problem_missing_between(
    target: AnalysisTarget,
    *,
    t_prev: float,
    t_next: float,
    ts_exp: float,
    context: List[Dict[str, Any]],
    cycle_s: float,
) -> Dict[str, Any]:
    gap = t_next - t_prev
    return {
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
        "cycle_s": cycle_s,
        "declenchement_prev_ts": t_prev,
        "declenchement_next_ts": t_next,
    }


def _compute_overdue_missing_problems(
    targets: Dict[Key, AnalysisTarget],
    events: List[TriggerEvent],
    *,
    running: bool,
    now: float,
) -> List[Dict[str, Any]]:
    """Manquants « en retard » depuis le dernier déclenchement (poll périodique)."""
    if not running:
        return []
    problems: List[Dict[str, Any]] = []
    index = _index_events_by_key(events)
    flows = list_sv_flow_infos()
    for key, target in targets.items():
        timing = resolve_target_timing(target, flows)
        if timing.cycle_s is None:
            continue
        cycle_s = max(1.0, float(timing.cycle_s))
        declenchements = _declenchements_from_index(index, key)
        if not declenchements:
            continue
        key_events = index.get(key, ())
        t_last = declenchements[-1].ts_goose
        grace = _missing_grace_s(cycle_s)
        gap = now - t_last
        if gap <= cycle_s + grace:
            continue
        n_overdue = int((gap - grace) // cycle_s)
        if n_overdue < 1:
            continue
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
                f"écart {gap:.1f} s) - en retard"
            ),
            "context": context,
            "gap_s": round(gap, 3),
            "cycle_s": cycle_s,
            "declenchement_prev_ts": t_last,
            "declenchement_next_ts": None,
        })
    return _dedupe_problems(problems)


def _problem_identity_key(p: Dict[str, Any]) -> Tuple[Any, ...]:
    """Clé stable pour déduplication et persistance session."""
    kind = p.get("kind")
    go_id = str(p.get("go_id") or "")
    if kind == "capture_unreliable":
        return ("capture_unreliable",)
    if kind == "missing":
        return ("missing", go_id, p.get("ts_expected"))
    if kind == "delay_exceeded":
        return ("delay_exceeded", go_id, p.get("ts_goose"), p.get("st_num"))
    if kind == "capture_incomplete":
        return ("capture_incomplete", go_id, p.get("ts_goose"), p.get("st_num"))
    return (kind, go_id, p.get("ts_goose"), p.get("ts_expected"), p.get("st_num"))


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
    ts_s = _fmt_ts_export(float(ts)) if ts is not None else "-"
    parts = [
        ts_s,
        str(kind),
        f"goID={p.get('go_id') or '-'}",
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
        key_d = _problem_identity_key(p)
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
    svid: Optional[str] = None
    svid_manual: bool = False


@dataclass
class SvFlowInfo:
    name: str
    svid: str
    fault: bool
    fault_cycle_s: int
    fault_smpcnt: int
    fault_offset_s: int


@dataclass
class TargetTiming:
    svid: Optional[str]
    cycle_s: Optional[float]
    smpcnt: int
    offset_s: int
    phase_s: float
    linked: bool


def extract_dep_token(text: str) -> Optional[str]:
    m = _DEP_RE.search(text or "")
    if not m:
        return None
    return f"DEP{m.group(1)}"


def list_sv_flow_infos() -> List[SvFlowInfo]:
    raw: List[Any] = []
    getter = _sv_flows_getter
    if getter is not None:
        try:
            raw = list(getter() or [])
        except Exception as exc:
            print(f"[GOOSE Listener] Lecture des flux SV impossible: {exc}")
            raw = []
    else:
        try:
            from sv_service import list_flows_for_listener  # type: ignore

            raw = list(list_flows_for_listener() or [])
        except Exception:
            try:
                from sv_service import flows, flows_lock  # type: ignore

                with flows_lock:
                    raw = [
                        {
                            "name": fr.config.name,
                            "svid": fr.config.svid,
                            "fault": fr.config.fault,
                            "fault_cycle_s": int(fr.config.fault_cycle_s),
                            "fault_smpcnt": int(getattr(fr.config, "fault_smpcnt", 0)),
                            "fault_offset_s": int(getattr(fr.config, "fault_offset_s", 0)),
                        }
                        for fr in flows.values()
                    ]
            except Exception as exc:
                print(f"[GOOSE Listener] Lecture des flux SV impossible: {exc}")
                raw = []
    out: List[SvFlowInfo] = []
    seen: Set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        svid = str(item.get("svid") or "").strip()
        if not svid or svid in seen:
            continue
        seen.add(svid)
        try:
            cycle = max(1, int(item.get("fault_cycle_s") or 2))
        except (TypeError, ValueError):
            cycle = 2
        try:
            smpcnt = max(0, min(SMP_PER_SEC - 1, int(item.get("fault_smpcnt") or 0)))
        except (TypeError, ValueError):
            smpcnt = 0
        try:
            offset = max(0, int(item.get("fault_offset_s") or 0))
        except (TypeError, ValueError):
            offset = 0
        out.append(
            SvFlowInfo(
                name=str(item.get("name") or ""),
                svid=svid,
                fault=bool(item.get("fault")),
                fault_cycle_s=cycle,
                fault_smpcnt=smpcnt,
                fault_offset_s=offset,
            )
        )
    return out


def sv_flows_public() -> List[Dict[str, Any]]:
    return [
        {
            "name": f.name,
            "svid": f.svid,
            "fault": f.fault,
            "fault_cycle_s": f.fault_cycle_s,
            "fault_smpcnt": f.fault_smpcnt,
            "fault_offset_s": f.fault_offset_s,
        }
        for f in list_sv_flow_infos()
    ]


def auto_svid_for_goose(
    gocb_ref: str, go_id: str, flows: List[SvFlowInfo]
) -> Optional[str]:
    token = extract_dep_token(gocb_ref) or extract_dep_token(go_id)
    if not token:
        return None
    matches: List[str] = []
    seen: Set[str] = set()
    for f in flows:
        if extract_dep_token(f.svid) == token and f.svid not in seen:
            seen.add(f.svid)
            matches.append(f.svid)
    if len(matches) == 1:
        return matches[0]
    return None


def lookup_sv_flow(svid: str, flows: List[SvFlowInfo]) -> Optional[SvFlowInfo]:
    want = (svid or "").strip()
    if not want:
        return None
    for f in flows:
        if f.svid == want:
            return f
    return None


def fault_phase_s(smpcnt: int, offset_s: int) -> float:
    return float(offset_s) + (float(smpcnt) / float(SMP_PER_SEC))


def nearest_fault_t_ref(ts_goose: float, cycle_s: float, phase_s: float) -> float:
    n = math.floor((ts_goose - phase_s) / cycle_s)
    t0 = n * cycle_s + phase_s
    t1 = t0 + cycle_s
    if abs(ts_goose - t1) < abs(ts_goose - t0):
        return t1
    return t0


def apply_auto_svid(
    target: AnalysisTarget, flows: Optional[List[SvFlowInfo]] = None
) -> AnalysisTarget:
    if target.svid_manual and (target.svid or "").strip():
        return target
    flows = flows if flows is not None else list_sv_flow_infos()
    auto = auto_svid_for_goose(target.gocb_ref, target.go_id, flows)
    if auto:
        target.svid = auto
        target.svid_manual = False
    elif not target.svid_manual:
        target.svid = None
    return target


def resolve_target_timing(
    target: AnalysisTarget, flows: Optional[List[SvFlowInfo]] = None
) -> TargetTiming:
    flows = flows if flows is not None else list_sv_flow_infos()
    svid = (target.svid or "").strip() or None
    if not svid and not target.svid_manual:
        svid = auto_svid_for_goose(target.gocb_ref, target.go_id, flows)
    info = lookup_sv_flow(svid or "", flows) if svid else None
    if info is None:
        return TargetTiming(
            svid=svid,
            cycle_s=None,
            smpcnt=0,
            offset_s=0,
            phase_s=0.0,
            linked=False,
        )
    return TargetTiming(
        svid=info.svid,
        cycle_s=float(info.fault_cycle_s),
        smpcnt=info.fault_smpcnt,
        offset_s=info.fault_offset_s,
        phase_s=fault_phase_s(info.fault_smpcnt, info.fault_offset_s),
        linked=True,
    )


def compute_delta_net_ms(
    ts_goose: float, delay_ms: float, timing: TargetTiming
) -> Tuple[float, float]:
    if timing.linked and timing.cycle_s is not None:
        t_ref = nearest_fault_t_ref(ts_goose, timing.cycle_s, timing.phase_s)
    else:
        t_ref = float(math.floor(ts_goose))
    return (ts_goose - t_ref) * 1000.0 - delay_ms, t_ref


def _target_public_dict(
    t: AnalysisTarget, flows: Optional[List[SvFlowInfo]] = None
) -> Dict[str, Any]:
    timing = resolve_target_timing(t, flows)
    return {
        "gocb_ref": t.gocb_ref,
        "go_id": t.go_id,
        "delay_ms": t.delay_ms,
        "svid": timing.svid or t.svid,
        "svid_manual": t.svid_manual,
        "cycle_s": timing.cycle_s,
        "fault_smpcnt": timing.smpcnt if timing.linked else None,
        "fault_offset_s": timing.offset_s if timing.linked else None,
        "sv_linked": timing.linked,
    }


def _targets_fingerprint(targets: Dict[Key, AnalysisTarget]) -> Tuple[Any, ...]:
    flows = list_sv_flow_infos()
    rows = []
    for key in sorted(targets.keys()):
        t = targets[key]
        timing = resolve_target_timing(t, flows)
        rows.append(
            (
                key,
                t.svid,
                t.svid_manual,
                timing.cycle_s,
                timing.smpcnt,
                timing.offset_s,
            )
        )
    return tuple(rows)


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
    analysis_started_at: float
    event_filter: str
    targets: Dict[Key, AnalysisTarget]
    events: List[TriggerEvent]
    events_total: int
    events_rev: int
    threshold_ms: float
    hist_buckets: HistBuckets


@dataclass
class _AnalysisPollCache:
    key: Optional[Tuple[Any, ...]] = None
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
    _analysis_warmup_deadline: float = field(default=0.0, repr=False)
    _analysis_warmup_started: float = field(default=0.0, repr=False)
    _problems_ram: List[Dict[str, Any]] = field(default_factory=list, repr=False)
    _problem_identity_keys: Set[Tuple[Any, ...]] = field(default_factory=set, repr=False)
    _last_declenchement_ts: Dict[Key, float] = field(default_factory=dict, repr=False)
    _ring_dump_records: List[Dict[str, Any]] = field(default_factory=list, repr=False)
    _ring_dump_seq: int = field(default=0, repr=False)
    _analysis_started_at: float = field(default=0.0, repr=False)

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
        mux = cap.get("processbus") or cap.get("mux") or {}
        return (
            snap.events_rev,
            snap.event_filter,
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
            _targets_fingerprint(snap.targets),
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
                analysis_started_at=self._analysis_started_at if analysis_running else 0.0,
                event_filter=self._event_filter,
                targets=dict(self._targets),
                events=list(self._events) if load_events else [],
                events_total=len(self._events),
                events_rev=self._events_rev,
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

        timing = resolve_target_timing(target)
        delta_ms, t_ref = compute_delta_net_ms(ts_goose, delay_ms, timing)
        kind, label, detail = classify_trigger(prev_data_copy, pdu_data_copy)
        evt = TriggerEvent(
            ts_goose=ts_goose,
            gocb_ref=pdu.gocb_ref,
            go_id=pdu.go_id or "",
            app_id=frame.app_id,
            st_num=pdu.st_num,
            sq_num=pdu.sq_num,
            ts_seconde_pile=t_ref,
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
            pending_problems: List[Dict[str, Any]] = []
            if kind == "declenchement":
                pending_problems = self._problems_for_declenchement_unlocked(
                    key, evt, target
                )
            exclude_from_hist = any(
                _problem_excludes_histogram_delta(p) for p in pending_problems
            )
            if not exclude_from_hist:
                _hist_buckets_add(self._hist_all_buckets, key, delta_ms)
                if kind == "declenchement":
                    _hist_buckets_add(self._hist_declenchement_buckets, key, delta_ms)
            if self._event_passes_filter_unlocked(evt):
                self._events.append(evt)
                self._events_rev += 1
                self._events_by_key.setdefault(key, []).append(delta_ms)
        if pending_problems:
            self._accumulate_problems(pending_problems)

    def _analysis_state_dict_unlocked(self) -> Dict[str, Any]:
        return {
            "running": self._mode == "analyze",
            "event_filter": self._event_filter,
            "threshold_ms": self._problem_threshold_ms,
            "targets": [
                {
                    "gocb_ref": t.gocb_ref,
                    "go_id": t.go_id,
                    "delay_ms": t.delay_ms,
                    "svid": t.svid,
                    "svid_manual": t.svid_manual,
                }
                for t in self._targets.values()
            ],
        }

    def _persist_analysis_state(self) -> None:
        """Écrit la config d'analyse (cibles + options) pour survivre à un restart."""
        try:
            with self._lock:
                payload = self._analysis_state_dict_unlocked()
            tmp_path = ANALYSIS_STATE_PATH.with_suffix(
                ANALYSIS_STATE_PATH.suffix + ".tmp"
            )
            tmp_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            tmp_path.replace(ANALYSIS_STATE_PATH)
        except (OSError, TypeError, ValueError) as exc:
            print(f"[GOOSE Listener] Erreur sauvegarde état: {exc}")

    def restore_analysis_if_needed(self) -> None:
        """Relance l'analyse si elle tournait au stop du service (sans l'historique)."""
        if not ANALYSIS_STATE_PATH.exists():
            return
        try:
            raw = json.loads(ANALYSIS_STATE_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(
                f"[GOOSE Listener] Impossible de charger {ANALYSIS_STATE_PATH}: {exc}"
            )
            return
        if not isinstance(raw, dict) or not raw.get("running"):
            return
        targets = _targets_from_payload(raw.get("targets"))
        if not targets:
            return
        try:
            threshold_ms = (
                float(raw["threshold_ms"])
                if raw.get("threshold_ms") is not None
                else None
            )
        except (TypeError, ValueError):
            threshold_ms = None
        with self._lock:
            if threshold_ms is not None and threshold_ms >= 0:
                self._problem_threshold_ms = threshold_ms
        event_filter = _normalize_event_filter(
            str(raw.get("event_filter") or EVENT_FILTER_DECLENCHEMENTS_ONLY).strip()
        )
        err = self.start_analysis(targets, event_filter=event_filter)
        if err:
            print(f"[GOOSE Listener] Relance analyse ignorée: {err}")
            return
        print(
            f"[GOOSE Listener] Analyse relancée ({len(targets)} flux) "
            f"après restart du service"
        )

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
        persist = False
        with self._lock:
            self._event_filter = event_filter
            self._purge_events_unlocked()
            self._analysis_poll_cache.key = None
            persist = self._mode == "analyze"
        if persist:
            self._persist_analysis_state()
        return None

    def set_problem_config(
        self,
        cycle_s: Optional[float] = None,
        threshold_ms: Optional[float] = None,
    ) -> Optional[str]:
        persist = False
        with self._lock:
            if threshold_ms is not None:
                if threshold_ms < 0:
                    return "Le seuil doit être ≥ 0 ms."
                self._problem_threshold_ms = float(threshold_ms)
            self._analysis_poll_cache.key = None
            persist = self._mode == "analyze"
        if persist:
            self._persist_analysis_state()
        return None


    def inject_demo_delay(
        self,
        gocb_ref: Optional[str] = None,
        go_id: Optional[str] = None,
    ) -> Optional[str]:
        """Injecte un déclenchement fictif avec delta > seuil (démo UI, pas d'émission réseau)."""
        problem: Optional[Dict[str, Any]] = None
        with self._lock:
            if self._mode != "analyze":
                return "Lancez une analyse avant de simuler un retard."
            if not self._targets:
                return "Aucun flux en analyse."
            want_gocb = (gocb_ref or "").strip()
            want_go = (go_id or "").strip()
            if want_gocb:
                target = self._targets.get(_stream_key(want_gocb, want_go))
                if target is None:
                    return "Flux introuvable dans l'analyse en cours."
            else:
                target = random.choice(list(self._targets.values()))
            key = _stream_key(target.gocb_ref, target.go_id)
            threshold_ms = max(0.0, float(self._problem_threshold_ms))
            delay_ms = float(target.delay_ms)
            offset_ms = min(max(delay_ms + threshold_ms + DEMO_DELAY_MARGIN_MS, 1.0), 900.0)
            now = time.time()
            timing = resolve_target_timing(target)
            if timing.linked and timing.cycle_s is not None:
                t_ref = nearest_fault_t_ref(now, timing.cycle_s, timing.phase_s)
            else:
                t_ref = float(math.floor(now))
            ts_goose = t_ref + offset_ms / 1000.0
            if ts_goose > now:
                if timing.linked and timing.cycle_s is not None:
                    t_ref = t_ref - float(timing.cycle_s)
                else:
                    t_ref -= 1.0
                ts_goose = t_ref + offset_ms / 1000.0
            delta_ms = (ts_goose - t_ref) * 1000.0 - delay_ms
            scan_ent = self._scan_entries.get(key)
            app_id = scan_ent.app_id if scan_ent is not None else 0
            st_num = int(self._last_st_num.get(key) or 0) + 1
            evt = TriggerEvent(
                ts_goose=ts_goose,
                gocb_ref=target.gocb_ref,
                go_id=target.go_id,
                app_id=app_id,
                st_num=st_num,
                sq_num=0,
                ts_seconde_pile=t_ref,
                delta_net_ms=delta_ms,
                processing_lag_ms=0.0,
                event_kind="declenchement",
                event_label="Déclenchement",
                change_detail="démo (injection UI)",
            )
            if self._event_passes_filter_unlocked(evt):
                self._events.append(evt)
                self._events_rev += 1
                self._events_by_key.setdefault(key, []).append(delta_ms)
            self._analysis_poll_cache.key = None
            problem = _problem_delay_exceeded(evt, threshold_ms)
            problem["demo"] = True
        if problem:
            self._accumulate_problems([problem])
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
            sv_flows = list_sv_flow_infos()
            for t in targets:
                apply_auto_svid(t, sv_flows)
                key = _stream_key(t.gocb_ref, t.go_id)
                self._targets[key] = t
            self._events.clear()
            self._events_by_key.clear()
            self._hist_all_buckets.clear()
            self._hist_declenchement_buckets.clear()
            self._problems_ram.clear()
            self._problem_identity_keys.clear()
            self._last_declenchement_ts.clear()
            self._events_rev = 0
            self._targets_frozen = frozenset(self._targets.keys())
            self._analysis_poll_cache.key = None
            self._last_error = None
            self._analysis_started_at = time.time()
        self._ensure_capture()
        self._enable_ring_capture()
        self._schedule_capture_baseline()
        self._persist_analysis_state()
        return None

    def stop_analysis(self) -> None:
        with self._lock:
            if self._mode == "analyze":
                self._mode = "idle"
            self._analysis_started_at = 0.0
            self._targets_frozen = frozenset()
            self._analysis_baseline_active = False
            self._analysis_capture_baseline = {}
            self._analysis_warmup_deadline = 0.0
            self._analysis_warmup_started = 0.0
            self._stop_capture_if_idle()
        self._disable_ring_capture()
        self._persist_analysis_state()

    def reset_session(self) -> None:
        """Efface événements, histogramme et problèmes. L'analyse continue."""
        dumps_to_delete: List[Dict[str, Any]] = []
        analyzing = False
        with self._lock:
            self._events.clear()
            self._events_by_key.clear()
            self._hist_all_buckets.clear()
            self._hist_declenchement_buckets.clear()
            self._problems_ram.clear()
            self._problem_identity_keys.clear()
            self._last_declenchement_ts.clear()
            self._events_rev += 1
            self._analysis_poll_cache.key = None
            dumps_to_delete = list(self._ring_dump_records)
            self._ring_dump_records.clear()
            analyzing = self._mode == "analyze"
        for rec in dumps_to_delete:
            for key in ("path", "meta_path"):
                p = rec.get(key)
                if isinstance(p, Path):
                    try:
                        p.unlink(missing_ok=True)
                    except OSError:
                        pass
        if analyzing:
            self._schedule_capture_baseline()

    def clear_problems(self) -> None:
        """Efface uniquement la liste des problèmes (et dumps PCAP associés). L'analyse continue."""
        dumps_to_delete: List[Dict[str, Any]] = []
        with self._lock:
            self._problems_ram.clear()
            self._problem_identity_keys.clear()
            self._analysis_poll_cache.key = None
            dumps_to_delete = list(self._ring_dump_records)
            self._ring_dump_records.clear()
        for rec in dumps_to_delete:
            for key in ("path", "meta_path"):
                p = rec.get(key)
                if isinstance(p, Path):
                    try:
                        p.unlink(missing_ok=True)
                    except OSError:
                        pass

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
        sv_flows = list_sv_flow_infos()
        targets = [
            _target_public_dict(t, sv_flows) for t in snap.targets.values()
        ]
        targets_snap = snap.targets
        all_events = snap.events
        event_filter = snap.event_filter
        running = snap.analysis_running
        started_at = snap.analysis_started_at if running and snap.analysis_started_at else None
        elapsed_s = (
            round(max(0.0, now - started_at), 1) if started_at is not None else 0.0
        )
        threshold_ms = snap.threshold_ms

        cache_key = self._analysis_cache_key(snap, now)
        cache = self._analysis_poll_cache
        histogram = _build_histogram_from_buckets(snap.hist_buckets, targets_snap)
        if cache.key == cache_key:
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
            live_problems = _compute_overdue_missing_problems(
                targets_snap,
                all_events,
                running=running,
                now=now,
            )
            self._accumulate_problems(live_problems)
            cache.key = cache_key
            cache.filtered_count = filtered_count
            cache.events_recent = events_recent

        capture_rel = self._capture_reliability(analysis_running=running)
        capture_rel = {**capture_rel, "ring_buffer": self._goose_ring_stats()}
        if running and not capture_rel["reliable"]:
            self._accumulate_problems([
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
                        "Capture non fiable - mesures invalides : "
                        f"{capture_rel['invalid_reason']}"
                    ),
                },
            ])

        with self._lock:
            problems_all = list(self._problems_ram)

        problems_recent = sorted(
            problems_all,
            key=_problem_sort_key,
            reverse=True,
        )[:PANEL_PROBLEMS_MAX]
        return {
            "running": running,
            "started_at": started_at,
            "elapsed_s": elapsed_s,
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
                "threshold_ms": threshold_ms,
            },
            "problems": problems_recent,
            "problem_count": len(problems_all),
            "problems_panel_max": PANEL_PROBLEMS_MAX,
            "sv_flows": sv_flows_public(),
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
        header = f"# GOOSE Listener - {len(events)} événement(s) ({filt_label})\n"
        return header + "\n".join(_event_export_line(e) for e in events) + "\n"

    def export_problems_txt(self) -> str:
        with self._lock:
            problems = list(self._problems_ram)
        if not problems:
            return "# Aucun problème détecté\n"
        ordered = sorted(problems, key=_problem_sort_key)
        header = f"# GOOSE Listener - {len(ordered)} problème(s) (session)\n"
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

    def _problems_for_declenchement_unlocked(
        self,
        key: Key,
        evt: TriggerEvent,
        target: AnalysisTarget,
    ) -> List[Dict[str, Any]]:
        """Détecte Δ/sqNum/manquants à la réception (comme l'histogramme)."""
        out: List[Dict[str, Any]] = []
        timing = resolve_target_timing(target)
        cycle_s = timing.cycle_s
        threshold_ms = max(0.0, float(self._problem_threshold_ms))
        t_next = evt.ts_goose
        t_prev = self._last_declenchement_ts.get(key)
        if t_prev is not None and cycle_s is not None:
            cycle_s = max(1.0, float(cycle_s))
            key_events = [
                e for e in self._events
                if _stream_key(e.gocb_ref, e.go_id) == key
            ]
            context = _events_between_indexed(key_events, t_prev, t_next)
            for ts_exp in _missing_slots_between(t_prev, t_next, cycle_s):
                out.append(
                    _problem_missing_between(
                        target,
                        t_prev=t_prev,
                        t_next=t_next,
                        ts_exp=ts_exp,
                        context=context,
                        cycle_s=cycle_s,
                    )
                )
        self._last_declenchement_ts[key] = t_next

        if evt.sq_num != 0:
            out.append(_problem_capture_incomplete(evt))
        elif evt.delta_net_ms > threshold_ms:
            out.append(_problem_delay_exceeded(evt, threshold_ms))
        return out

    def _accumulate_problems(self, live: List[Dict[str, Any]]) -> None:
        """Ajoute les nouveaux problèmes à la liste session (indépendante des 10k événements)."""
        new_entries: List[Dict[str, Any]] = []
        with self._lock:
            for p in live:
                key = _problem_identity_key(p)
                if key in self._problem_identity_keys:
                    continue
                entry = dict(p)
                self._problems_ram.append(entry)
                self._problem_identity_keys.add(key)
                new_entries.append(entry)
        for entry in new_entries:
            meta = self._save_ring_snapshot(entry)
            if meta is None:
                continue
            entry["dump_id"] = meta["dump_id"]
            entry["dump_packets"] = meta["packet_count"]
            entry["dump_problem_ts"] = meta.get("problem_ts")
            entry["dump_oldest_ts"] = meta.get("packet_oldest_ts")
            entry["dump_newest_ts"] = meta.get("packet_newest_ts")

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
        count = write_pcap(
            path,
            packets,
            problem=problem,
            dump_id=dump_id,
            window_s=RING_WINDOW_S,
        )
        ts_prob = problem.get("ts_goose")
        if ts_prob is None:
            ts_prob = problem.get("ts_expected")
        meta = {
            "dump_id": dump_id,
            "path": path,
            "meta_path": path.with_suffix(".meta.json"),
            "created_at": time.time(),
            "reason": kind,
            "packet_count": count,
            "window_s": RING_WINDOW_S,
            "go_id": go_id,
            "problem_ts": ts_prob,
            "packet_oldest_ts": packets[0][0] if packets else None,
            "packet_newest_ts": packets[-1][0] if packets else None,
            "problem_key": _problem_identity_key(problem),
        }
        self._ring_dump_records.append(meta)
        self._prune_ring_dumps()
        return meta

    def _prune_ring_dumps(self) -> None:
        while len(self._ring_dump_records) > MAX_RING_DUMPS:
            old = self._ring_dump_records.pop(0)
            for key in ("path", "meta_path"):
                p = old.get(key)
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
                "problem_ts": rec.get("problem_ts"),
                "packet_oldest_ts": rec.get("packet_oldest_ts"),
                "packet_newest_ts": rec.get("packet_newest_ts"),
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
        base["processbus"] = mux
        base["processbus_active"] = bool(mux.get("running"))
        return base

    def _mux_capture_ready(self, mux: Optional[Dict[str, Any]] = None) -> bool:
        mux = mux if mux is not None else self._mux_stats()
        if not mux.get("running"):
            return False
        return int(mux.get("packets") or 0) > 0

    def _schedule_capture_baseline(self) -> None:
        """Ignore le burst d'ouverture libpcap (restart / capture froide)."""
        if self._mux_capture_ready():
            self._analysis_capture_baseline = self._snapshot_capture_baseline()
            self._analysis_baseline_active = True
            self._analysis_warmup_deadline = 0.0
            self._analysis_warmup_started = 0.0
            return
        now = time.time()
        self._analysis_capture_baseline = {}
        self._analysis_baseline_active = False
        self._analysis_warmup_started = now
        self._analysis_warmup_deadline = now + CAPTURE_WARMUP_S

    def _maybe_arm_capture_baseline(self) -> None:
        if self._analysis_baseline_active or self._analysis_warmup_deadline <= 0:
            return
        now = time.time()
        ready = self._mux_capture_ready()
        overdue = (
            self._analysis_warmup_started > 0
            and (now - self._analysis_warmup_started) >= CAPTURE_WARMUP_MAX_S
        )
        if not overdue and (now < self._analysis_warmup_deadline or not ready):
            if not ready and now >= self._analysis_warmup_deadline:
                self._analysis_warmup_deadline = now + 0.5
            return
        self._analysis_capture_baseline = self._snapshot_capture_baseline()
        self._analysis_baseline_active = True
        self._analysis_warmup_deadline = 0.0
        self._analysis_warmup_started = 0.0

    def _snapshot_capture_baseline(self) -> Dict[str, Any]:
        stats = self._subscriber_stats()
        mux = stats.get("processbus") or stats.get("mux") or {}
        return {
            "drops": int(stats.get("drops", 0)),
            "nic": dict(stats.get("nic", {})),
            "pcap_drop": int(mux.get("pcap_drop", 0)),
            "pcap_ifdrop": int(mux.get("pcap_ifdrop", 0)),
            "sv_queue_drops": int(mux.get("sv_queue_drops", 0)),
        }

    def _capture_reliability(self, *, analysis_running: bool) -> Dict[str, Any]:
        self._maybe_arm_capture_baseline()
        stats = self._subscriber_stats()
        mux = stats.get("processbus") or stats.get("mux") or {}
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
            "processbus": mux,
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
            "processbus": mux,
            "processbus_active": bool(mux.get("running")),
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
            "sv_flows": sv_flows_public(),
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
