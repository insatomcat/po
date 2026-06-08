#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import pathlib
import signal
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Ajoute la racine du dépôt au sys.path pour pouvoir importer goose61850 et iec_data
ROOT = pathlib.Path(__file__).resolve().parents[1]
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
GOOSE_LISTENER_ROOT = PROJECT_ROOT / "goose_listener"
if str(GOOSE_LISTENER_ROOT) not in sys.path:
    sys.path.insert(0, str(GOOSE_LISTENER_ROOT))

from goose61850 import GooseSubscriber
from goose61850.transport import goose_bpf_filter
from iec_data import BoolData
from trigger_classify import classify_trigger
from goose_listener_service import (
    _missing_grace_s,
    _missing_slots_between,
    is_trigger_event,
)
from goose61850.types import GooseFrame

Key = Tuple[str, str]


def fmt_ts_ms(ts: float) -> str:
    return datetime.fromtimestamp(ts).isoformat(timespec="milliseconds")


def pdu_first_bool_is_true(all_data: Optional[list]) -> bool:
    if not all_data:
        return False
    first = all_data[0]
    if isinstance(first, BoolData):
        return bool(first.value)
    return False


def passes_display_filters(pdu, args: argparse.Namespace) -> bool:
    if getattr(args, "sqnum_zero", False) and pdu.sq_num != 0:
        return False
    if getattr(args, "bool_true", False) and not pdu_first_bool_is_true(pdu.all_data):
        return False
    return True


def summarize_frame(
    frame: GooseFrame,
    *,
    ts_rx: Optional[float] = None,
    show_all_elements: bool = False,
) -> str:
    pdu = frame.pdu
    if pdu is None:
        return (
            f"{frame.src_mac} -> {frame.dst_mac} "
            f"APPID=0x{frame.app_id:04X} (PDU non décodé)"
        )

    if ts_rx is not None:
        ts_str = fmt_ts_ms(ts_rx)
    else:
        ts_str = fmt_pdu_ts(pdu.timestamp)

    preview = ""
    if pdu.all_data:
        if show_all_elements:
            preview = f" allData={repr(pdu.all_data)}"
        else:
            shown = ", ".join(repr(v) for v in pdu.all_data[:5])
            if len(pdu.all_data) > 5:
                shown += ", ..."
            preview = f" allData=[{shown}]"

    return (
        f"[{ts_str}] {frame.src_mac} -> {frame.dst_mac} "
        f"APPID=0x{frame.app_id:04X} "
        f"gocbRef={pdu.gocb_ref} "
        f"goID={pdu.go_id} "
        f"stNum={pdu.st_num} sqNum={pdu.sq_num} "
        f"confRev={pdu.conf_rev} "
        f"entries={pdu.num_dat_set_entries}"
        f"{preview}"
    )


def compute_delta_ms(ts_rx: float, delay_ms: float) -> Tuple[float, float]:
    ts_pile = math.floor(ts_rx)
    delta_ms = (ts_rx - ts_pile) * 1000.0 - delay_ms
    return ts_pile, delta_ms


def is_trigger(prev_st_num: Optional[int], st_num: int, sq_num: int) -> bool:
    if prev_st_num is None:
        return False
    return st_num > prev_st_num and sq_num == 0


def fmt_rx_ts(ts_rx: float) -> str:
    d = datetime.fromtimestamp(ts_rx)
    return d.strftime("%d/%m/%Y %H:%M:%S") + f".{int((ts_rx % 1) * 1000):03d}"


@dataclass
class AuditFrame:
    sq_num: int
    ts_rx: float
    pdu_ts: Optional[datetime] = None


@dataclass
class StNumEpoch:
    st_num: int
    prev_st_num: Optional[int]
    frames: List[AuditFrame] = field(default_factory=list)


def fmt_pdu_ts(pdu_ts: Optional[datetime]) -> str:
    if pdu_ts is None:
        return "-"
    return pdu_ts.isoformat(timespec="milliseconds")


def frac_ms(ts_rx: float) -> float:
    return (ts_rx - math.floor(ts_rx)) * 1000.0


@dataclass
class TriggerRecord:
    ts_rx: float
    kind: str
    label: str
    st_num: int
    sq_num: int
    delta_ms: float
    frac_ms_val: float
    ts_pile: int
    detail: str


def _fmt_trigger_line(rec: TriggerRecord) -> str:
    line = (
        f"    {fmt_rx_ts(rec.ts_rx)}  {rec.label:<11}  st={rec.st_num:>6}  "
        f"sq={rec.sq_num:>5}  frac={rec.frac_ms_val:>7.2f} ms  Δ={rec.delta_ms:>7.2f} ms"
    )
    if rec.detail:
        line += f"  ({rec.detail})"
    return line


def _problem_dedup_key(p: dict) -> Tuple[object, ...]:
    return (
        p.get("kind"),
        p.get("go_id"),
        p.get("ts_goose"),
        p.get("ts_expected"),
        p.get("st_num"),
        p.get("message"),
    )


def run_api_problem_diag(base_url: str, *, poll_s: float = 1.0) -> None:
    """Lit les problèmes depuis po_service (même source que la GUI)."""
    base_url = base_url.rstrip("/")
    url = f"{base_url}/api/gooselistener/analysis"
    seen: set[Tuple[object, ...]] = set()
    print(f"Diagnostic via API : {url}", file=sys.stderr)
    print(
        "Utilisez ce mode quand l'analyse GUI tourne déjà (évite le conflit de capture).",
        file=sys.stderr,
    )
    print("Interrompre avec Ctrl+C.", file=sys.stderr)

    api_stop = {"flag": False, "count": 0}

    def _on_api_stop(signum: int, frame: object) -> None:
        api_stop["count"] += 1
        api_stop["flag"] = True
        if api_stop["count"] >= 2:
            raise KeyboardInterrupt

    signal.signal(signal.SIGINT, _on_api_stop)
    signal.signal(signal.SIGTERM, _on_api_stop)

    try:
        while not api_stop["flag"]:
            try:
                with urlopen(url, timeout=5) as resp:
                    data = json.loads(resp.read().decode())
            except URLError as exc:
                print(f"Erreur API : {exc}", file=sys.stderr, flush=True)
            else:
                if not data.get("running"):
                    print(
                        "Analyse GUI inactive — lancez l'analyse dans l'UI.",
                        file=sys.stderr,
                        flush=True,
                    )

                for prob in data.get("problems") or []:
                    pk = _problem_dedup_key(prob)
                    if pk in seen:
                        continue
                    seen.add(pk)
                    kind = prob.get("kind", "")
                    go_id = prob.get("go_id", "")
                    ts = prob.get("ts_goose") or prob.get("ts_expected")
                    ts_s = fmt_rx_ts(float(ts)) if ts is not None else "—"
                    delta = prob.get("delta_net_ms")
                    msg = prob.get("message") or kind
                    if kind == "delay_exceeded" and delta is not None:
                        sq = prob.get("sq_num")
                        sq_note = f"  sqNum={sq}" if sq is not None else ""
                        if sq not in (None, 0):
                            sq_note += " (sqNum=0 manqué)"
                        print(
                            f"⚠ Δ > seuil  {ts_s}  {go_id}  Δ={delta:.2f} ms{sq_note}",
                            file=sys.stderr,
                            flush=True,
                        )
                    elif kind == "missing":
                        print(
                            f"⚠ Manquant  {ts_s}  {go_id}  {msg}",
                            file=sys.stderr,
                            flush=True,
                        )
                    else:
                        print(
                            f"⚠ {kind}  {ts_s}  {go_id}  {msg}",
                            file=sys.stderr,
                            flush=True,
                        )

            deadline = time.time() + poll_s
            while time.time() < deadline and not api_stop["flag"]:
                time.sleep(0.05)
    except KeyboardInterrupt:
        api_stop["flag"] = True
    finally:
        print(
            f"\n=== Bilan API ({len(seen)} problème(s) distinct(s)) ===",
            file=sys.stderr,
        )


def print_delay_alert(record: TriggerRecord, *, threshold_ms: float) -> None:
    sq_note = f"  sqNum={record.sq_num}"
    if record.sq_num != 0:
        sq_note += " (sqNum=0 manqué)"
    print(
        f"⚠ Δ > seuil  {fmt_rx_ts(record.ts_rx)}  {record.label}  "
        f"st={record.st_num}{sq_note}  Δ={record.delta_ms:.2f} ms (seuil {threshold_ms:.0f} ms)",
        file=sys.stderr,
        flush=True,
    )


def print_problem_diagnostic(
    *,
    gocb_ref: str,
    go_id: str,
    prev_defaut: Optional[TriggerRecord],
    current: TriggerRecord,
    gap: Optional[float],
    cycle_s: float,
    grace: float,
    missing_slots: List[float],
    delay_high: bool,
    threshold_ms: float,
    between: List[TriggerRecord],
) -> None:
    print("\n" + "=" * 72, file=sys.stderr)
    print("DIAGNOSTIC ANOMALIE", file=sys.stderr)
    print(f"  flux : gocbRef={gocb_ref}  goID={go_id or '-'}", file=sys.stderr)

    reasons: List[str] = []
    if delay_high:
        reasons.append(f"Δ {current.delta_ms:.2f} ms > seuil {threshold_ms:.0f} ms")
    if missing_slots:
        reasons.append(f"{len(missing_slots)} défaut(s) manquant(s)")
    elif gap is not None and abs(gap - cycle_s) > grace:
        reasons.append(
            f"écart défauts {gap:.2f} s hors marge (attendu ~{cycle_s:.0f} s ± {grace:.1f} s)"
        )
    print(f"  cause : {' ; '.join(reasons)}", file=sys.stderr)

    if prev_defaut is not None:
        print("  défaut précédent :", file=sys.stderr)
        print(_fmt_trigger_line(prev_defaut), file=sys.stderr)
    else:
        print("  défaut précédent : (aucun — premier défaut de référence)", file=sys.stderr)

    print("  défaut courant :", file=sys.stderr)
    print(_fmt_trigger_line(current), file=sys.stderr)

    if gap is not None:
        msg = f"  écart défauts : {gap:.2f} s (cycle configuré {cycle_s:.0f} s)"
        if missing_slots:
            slots = ", ".join(fmt_rx_ts(s) for s in missing_slots)
            msg += f" → manquant(s) attendu(s) : {slots}"
        print(msg, file=sys.stderr)

    if between:
        print(f"  GOOSE entre les deux défauts ({len(between)}) :", file=sys.stderr)
        for rec in between:
            print(_fmt_trigger_line(rec), file=sys.stderr)
    else:
        print("  GOOSE entre les deux défauts : (aucun — aucun déclenchement intermédiaire)", file=sys.stderr)

    print("=" * 72, file=sys.stderr, flush=True)


def print_epoch_audit(epoch: StNumEpoch, delay_ms: float) -> None:
    frames = epoch.frames
    if not frames:
        return

    sq_nums = [f.sq_num for f in frames]
    sq0_frames = [f for f in frames if f.sq_num == 0]
    warnings: List[str] = []

    if epoch.prev_st_num is not None and epoch.st_num != epoch.prev_st_num + 1:
        warnings.append(
            f"stNum saute de {epoch.prev_st_num} à {epoch.st_num} (écart {epoch.st_num - epoch.prev_st_num})"
        )
    if not sq0_frames:
        warnings.append("aucune trame sqNum=0 vue pour ce stNum")
    elif len(sq0_frames) > 1:
        warnings.append(f"{len(sq0_frames)} trames sqNum=0 (attendu: 1)")
    if frames[0].sq_num != 0:
        warnings.append(
            f"première trame reçue sqNum={frames[0].sq_num} (sqNum=0 manquée ou perdue ?)"
        )

    expected_sq = 0
    for f in frames:
        if f.sq_num != expected_sq:
            if f.sq_num > expected_sq:
                warnings.append(f"trou sqNum: attendu {expected_sq}, reçu {f.sq_num}")
            break
        expected_sq += 1

    first = frames[0]
    first_delta = compute_delta_ms(first.ts_rx, delay_ms)[1]
    sq0_delta = compute_delta_ms(sq0_frames[0].ts_rx, delay_ms)[1] if sq0_frames else None

    print(f"\n=== Audit stNum {epoch.st_num} (précédent {epoch.prev_st_num}) ===", file=sys.stderr)
    print(
        f"  trames capturées : {len(frames)} | sqNum=0 : {len(sq0_frames)} | "
        f"premier sqNum vu : {frames[0].sq_num}",
        file=sys.stderr,
    )
    if sq0_delta is not None:
        print(
            f"  Δ net si sqNum=0 : {sq0_delta:.2f} ms | "
            f"Δ net si 1ère trame : {first_delta:.2f} ms",
            file=sys.stderr,
        )
    show = frames[:12]
    for i, f in enumerate(show):
        pdu_frac = "-"
        if f.pdu_ts is not None:
            pt = f.pdu_ts.timestamp()
            pdu_frac = f"{frac_ms(pt):.2f}ms"
        print(
            f"  [{i:02d}] sqNum={f.sq_num:>3}  rx={fmt_rx_ts(f.ts_rx)}  "
            f"frac_rx={frac_ms(f.ts_rx):>7.2f}ms  pdu_ts={fmt_pdu_ts(f.pdu_ts)}  pdu_frac={pdu_frac}",
            file=sys.stderr,
        )
    if len(frames) > len(show):
        print(f"  ... +{len(frames) - len(show)} trames", file=sys.stderr)
    if warnings:
        print("  ⚠ anomalies :", file=sys.stderr)
        for w in warnings:
            print(f"    - {w}", file=sys.stderr)
    else:
        print("  ✓ séquence conforme (stNum↑, sqNum=0 en premier, retransmissions 0,1,2…)", file=sys.stderr)
    print("", file=sys.stderr)


def print_delay_stats(deltas: list[float]) -> None:
    if not deltas:
        return
    buckets: Dict[str, int] = defaultdict(int)
    for d in deltas:
        buckets[f"{round(d):.0f}ms"] += 1
    print("\n--- Statistiques Δ net ---", file=sys.stderr)
    print(f"  événements : {len(deltas)}", file=sys.stderr)
    print(f"  min/max    : {min(deltas):.2f} / {max(deltas):.2f} ms", file=sys.stderr)
    for k in sorted(buckets, key=lambda x: float(x.replace("ms", ""))):
        n = buckets[k]
        bar = "█" * min(40, n)
        print(f"  {k:>8} : {n:4d} {bar}", file=sys.stderr)
    print("", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Écoute les trames GOOSE et affiche un résumé pour chacune.",
    )
    parser.add_argument(
        "iface",
        help="Interface réseau à écouter (ex: en0, eth0, ...)",
    )
    parser.add_argument(
        "--app-id",
        type=lambda x: int(x, 0),
        default=None,
        help="Filtre APPID (ex: 0x1000). Si omis, accepte tous les APPID.",
    )
    parser.add_argument(
        "--go-id",
        type=str,
        default=None,
        help="Filtre sur goID (chaîne exacte). Si omis, accepte tous les goID.",
    )
    parser.add_argument(
        "--gocb-ref",
        type=str,
        default=None,
        help="Filtre sur gocbRef (chaîne exacte).",
    )
    parser.add_argument(
        "--src-mac",
        type=str,
        default=None,
        help="Filtre sur adresse MAC source.",
    )
    parser.add_argument(
        "--dst-mac",
        type=str,
        default=None,
        help="Filtre sur adresse MAC destination.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Affiche des informations de debug sur chaque paquet capturé.",
    )
    parser.add_argument(
        "--show-all-elements",
        action="store_true",
        help="Affiche l'intégralité de la liste allData (aucune troncature).",
    )
    parser.add_argument(
        "--sqnum-zero",
        action="store_true",
        help="N'affiche que les trames avec sqNum=0 (filtre affichage uniquement).",
    )
    parser.add_argument(
        "--bool-true",
        action="store_true",
        help="N'affiche que les trames dont le 1er allData est bool(True).",
    )
    parser.add_argument(
        "--measure-delay",
        action="store_true",
        help="Mesure Δ net sur déclenchements (stNum↑, sqNum=0, ts réception pcap).",
    )
    parser.add_argument(
        "--triggers-only",
        action="store_true",
        help="Avec --measure-delay : n'affiche que les déclenchements (pas les retransmissions).",
    )
    parser.add_argument(
        "--delay-ms",
        type=float,
        default=0.0,
        help="Temporisation protection à soustraire du Δ (défaut: 0).",
    )
    parser.add_argument(
        "--stats-every",
        type=int,
        default=0,
        metavar="N",
        help="Avec --measure-delay : résumé des Δ toutes les N déclenchements.",
    )
    parser.add_argument(
        "--audit-triggers",
        action="store_true",
        help="Avec --measure-delay : dump la séquence sqNum de chaque stNum (vérifie la détection).",
    )
    parser.add_argument(
        "--problem-watch",
        action="store_true",
        help="Suivi continu manquants/délais (active --measure-delay --triggers-only).",
    )
    parser.add_argument(
        "--problem-diag",
        action="store_true",
        help="Mode diagnostic : silencieux si OK, rapport détaillé uniquement sur anomalie "
        "(manquant, écart hors marge, Δ>seuil). Active --measure-delay.",
    )
    parser.add_argument(
        "--problem-cycle",
        type=float,
        default=4.0,
        help="Cycle attendu entre défauts en secondes (défaut: 4).",
    )
    parser.add_argument(
        "--problem-threshold",
        type=float,
        default=40.0,
        help="Seuil Δ net en ms (défaut: 40).",
    )
    parser.add_argument(
        "--from-api",
        metavar="URL",
        default=None,
        help="Diagnostic via po_service (ex: http://127.0.0.1:7050). "
        "À utiliser si l'analyse GUI tourne — même résultats que l'UI.",
    )
    args = parser.parse_args()

    if args.from_api:
        if not args.problem_diag:
            args.problem_diag = True
        run_api_problem_diag(args.from_api)
        return

    if args.problem_diag:
        args.measure_delay = True
        if args.problem_watch:
            print(
                "Note : --problem-diag remplace --problem-watch (suivi continu ignoré).",
                file=sys.stderr,
            )
    elif args.problem_watch:
        args.measure_delay = True
        args.triggers_only = True

    if args.triggers_only and not args.measure_delay:
        parser.error("--triggers-only requiert --measure-delay")
    if args.audit_triggers and not args.measure_delay:
        parser.error("--audit-triggers requiert --measure-delay")

    last_st: Dict[Key, int] = {}
    last_all_data: Dict[Key, list] = {}
    last_defaut_ts: Dict[Key, float] = {}
    defaut_gaps: list[float] = []
    deltas: list[float] = []
    trigger_count = 0
    defaut_count = 0
    problem_missing = 0
    problem_delay = 0
    problem_diag_count = 0
    between_triggers: Dict[Key, List[TriggerRecord]] = defaultdict(list)
    last_defaut_record: Dict[Key, TriggerRecord] = {}
    last_trigger_st: Dict[Key, int] = {}
    defaut_delay_hits: List[TriggerRecord] = []
    current_epoch: Optional[StNumEpoch] = None

    def close_epoch() -> None:
        nonlocal current_epoch
        if current_epoch is not None and args.audit_triggers:
            print_epoch_audit(current_epoch, args.delay_ms)
        current_epoch = None

    def on_frame(frame: GooseFrame) -> None:
        nonlocal trigger_count, current_epoch, defaut_count, problem_missing, problem_delay
        nonlocal problem_diag_count
        ts_rx = frame.ts_rx if frame.ts_rx is not None else time.time()

        if frame.pdu is None:
            if not args.triggers_only and not args.problem_diag:
                print(summarize_frame(frame, ts_rx=ts_rx, show_all_elements=args.show_all_elements))
            return

        pdu = frame.pdu
        show_frame = passes_display_filters(pdu, args)
        if args.go_id is not None and pdu.go_id != args.go_id:
            return
        if args.gocb_ref is not None and pdu.gocb_ref != args.gocb_ref:
            return
        if args.src_mac is not None and frame.src_mac.lower() != args.src_mac.lower():
            return
        if args.dst_mac is not None and frame.dst_mac.lower() != args.dst_mac.lower():
            return

        key: Key = (pdu.gocb_ref, pdu.go_id or "")
        prev = last_st.get(key)
        if args.problem_diag:
            triggered = is_trigger_event(
                prev, pdu.st_num, pdu.sq_num,
                key=key, last_trigger_st=last_trigger_st, lenient=True,
            )
        else:
            triggered = is_trigger(prev, pdu.st_num, pdu.sq_num)

        st_changed = prev is not None and pdu.st_num > prev
        if args.audit_triggers:
            rec = AuditFrame(sq_num=pdu.sq_num, ts_rx=ts_rx, pdu_ts=pdu.timestamp)
            if st_changed:
                close_epoch()
                current_epoch = StNumEpoch(st_num=pdu.st_num, prev_st_num=prev, frames=[rec])
            elif current_epoch is not None and pdu.st_num == current_epoch.st_num:
                current_epoch.frames.append(rec)

        last_st[key] = pdu.st_num
        pdu_data = list(pdu.all_data) if pdu.all_data else None

        if not triggered:
            if pdu_data is not None:
                last_all_data[key] = pdu_data
            if args.problem_diag or args.triggers_only:
                return

        if args.measure_delay and triggered:
            ts_pile, delta_ms = compute_delta_ms(ts_rx, args.delay_ms)
            prev_data = last_all_data.get(key)
            kind, label, detail = classify_trigger(prev_data, pdu.all_data)
            if pdu_data is not None:
                last_all_data[key] = pdu_data
            trigger_count += 1
            deltas.append(delta_ms)
            frac_ms = (ts_rx - ts_pile) * 1000.0

            record = TriggerRecord(
                ts_rx=ts_rx,
                kind=kind,
                label=label,
                st_num=pdu.st_num,
                sq_num=pdu.sq_num,
                delta_ms=delta_ms,
                frac_ms_val=frac_ms,
                ts_pile=int(ts_pile),
                detail=detail,
            )

            if args.problem_diag:
                grace = _missing_grace_s(args.problem_cycle)
                delay_high = (
                    kind == "declenchement"
                    and pdu.sq_num == 0
                    and delta_ms > args.problem_threshold
                )
                gap_bad = False
                gap: Optional[float] = None
                missing: List[float] = []
                prev_rec = last_defaut_record.get(key)
                prev_ts = last_defaut_ts.get(key)

                if delay_high:
                    problem_delay += 1
                    defaut_delay_hits.append(record)
                    print_delay_alert(record, threshold_ms=args.problem_threshold)

                if kind == "declenchement":
                    defaut_count += 1

                    if prev_ts is not None and prev_rec is not None:
                        gap = ts_rx - prev_ts
                        defaut_gaps.append(gap)
                        missing = _missing_slots_between(
                            prev_ts, ts_rx, args.problem_cycle
                        )
                        gap_bad = bool(missing) or abs(gap - args.problem_cycle) > grace

                    if gap_bad:
                        if missing:
                            problem_missing += len(missing)
                        problem_diag_count += 1
                        print_problem_diagnostic(
                            gocb_ref=pdu.gocb_ref,
                            go_id=pdu.go_id or "",
                            prev_defaut=prev_rec,
                            current=record,
                            gap=gap,
                            cycle_s=args.problem_cycle,
                            grace=grace,
                            missing_slots=missing,
                            delay_high=delay_high,
                            threshold_ms=args.problem_threshold,
                            between=list(between_triggers[key]),
                        )

                    between_triggers[key] = []
                    last_defaut_record[key] = record
                    last_defaut_ts[key] = ts_rx
                else:
                    between_triggers[key].append(record)
                last_trigger_st[key] = pdu.st_num
            elif args.triggers_only and show_frame:
                print(
                    f"{fmt_rx_ts(ts_rx)}  {label:<11}  {pdu.st_num:>6}  {pdu.sq_num:>5}  "
                    f"{frac_ms:>8.2f}  {delta_ms:>8.2f}  {int(ts_pile)}"
                    + (f"  # {detail}" if detail else "")
                )
            if args.problem_watch and not args.problem_diag:
                grace = _missing_grace_s(args.problem_cycle)
                if kind == "declenchement":
                    defaut_count += 1
                    if pdu.sq_num == 0 and delta_ms > args.problem_threshold:
                        problem_delay += 1
                        print(
                            f"  └─ ⚠ Δ {delta_ms:.2f} ms > seuil {args.problem_threshold:.0f} ms",
                            file=sys.stderr,
                        )
                    prev_def = last_defaut_ts.get(key)
                    if prev_def is not None:
                        gap = ts_rx - prev_def
                        defaut_gaps.append(gap)
                        missing = _missing_slots_between(
                            prev_def, ts_rx, args.problem_cycle
                        )
                        msg = f"  └─ écart défauts: {gap:.2f} s (attendu ~{args.problem_cycle:.0f} s, marge {grace:.1f} s)"
                        if missing:
                            problem_missing += len(missing)
                            slots = ", ".join(fmt_rx_ts(s) for s in missing)
                            msg += f" → {len(missing)} manquant(s): {slots}"
                        elif abs(gap - args.problem_cycle) > grace:
                            msg += " → écart hors marge"
                        else:
                            msg += " → OK"
                        print(msg, file=sys.stderr)
                    else:
                        print("  └─ premier défaut de référence", file=sys.stderr)
                    last_defaut_ts[key] = ts_rx
                elif kind == "retombee":
                    print(
                        f"  └─ (fin défaut — ignoré pour cycle défaut {args.problem_cycle:.0f} s)",
                        file=sys.stderr,
                    )
                else:
                    print(
                        f"  └─ (type {label} — non compté comme défaut)",
                        file=sys.stderr,
                    )
            elif not args.problem_diag and show_frame:
                line = summarize_frame(frame, ts_rx=ts_rx, show_all_elements=args.show_all_elements)
                print(
                    f"{line}  | rx={fmt_rx_ts(ts_rx)} type={label} frac={frac_ms:.2f}ms "
                    f"Δnet={delta_ms:.2f}ms pile={int(ts_pile)} *** TRIGGER ***"
                    + (f" ({detail})" if detail else "")
                )

            if args.stats_every and trigger_count % args.stats_every == 0:
                print_delay_stats(deltas)
            if args.triggers_only or args.problem_diag:
                return

        if args.triggers_only or args.problem_diag:
            return

        if show_frame:
            print(summarize_frame(frame, ts_rx=ts_rx, show_all_elements=args.show_all_elements))

    sub = GooseSubscriber(
        iface=args.iface,
        app_id=args.app_id,
        callback=on_frame,
        debug=args.debug,
    )

    print(
        f"Écoute GOOSE sur {args.iface} "
        f"(APPID={'*' if args.app_id is None else hex(args.app_id)}, "
        f"goID={'*' if args.go_id is None else args.go_id}, "
        f"gocbRef={'*' if args.gocb_ref is None else args.gocb_ref})...",
        file=sys.stderr,
    )
    print(f"Filtre BPF : {goose_bpf_filter(args.app_id)}", file=sys.stderr)
    display_filters: List[str] = []
    if args.sqnum_zero:
        display_filters.append("sqNum=0")
    if args.bool_true:
        display_filters.append("bool(True)")
    if display_filters:
        print(
            f"Filtres affichage : {', '.join(display_filters)}",
            file=sys.stderr,
        )
    if args.problem_diag:
        print(
            f"Mode diagnostic (anomalies seules) : cycle défaut={args.problem_cycle} s "
            f"| seuil Δ={args.problem_threshold} ms",
            file=sys.stderr,
        )
        print(
            "Silencieux si OK. Δ>seuil : alerte compacte immédiate. "
            "Manquant / écart cycle : rapport détaillé.",
            file=sys.stderr,
        )
        print(
            "Détection : sqNum=0, ou premier cadre d'un nouveau stNum si sqNum=0 absent en capture.",
            file=sys.stderr,
        )
        print(
            "Le cycle doit correspondre à l'intervalle entre événements « Défaut » "
            "(pas entre tous les GOOSE).",
            file=sys.stderr,
        )
        print(
            "Si l'analyse GUI tourne en parallèle, la capture CLI peut être vide. "
            "Utilisez alors : --from-api http://127.0.0.1:7050",
            file=sys.stderr,
        )
    elif args.problem_watch:
        print(
            f"Mode suivi continu : cycle défaut={args.problem_cycle} s "
            f"| seuil Δ={args.problem_threshold} ms",
            file=sys.stderr,
        )
        print(
            "Vérifiez que le cycle correspond à l'intervalle entre événements « Défaut » "
            "(pas entre tous les GOOSE : défaut + fin défaut = souvent 2× plus court).",
            file=sys.stderr,
        )
    if args.measure_delay:
        if args.problem_diag:
            mode = "diagnostic silencieux (déclenchements seuls, rapport si anomalie)"
        elif args.triggers_only:
            mode = "déclenchements seuls"
        else:
            mode = "toutes trames + marque TRIGGER"
        print(
            f"Mesure Δ net : temporisation={args.delay_ms} ms | mode={mode}",
            file=sys.stderr,
        )
        if args.triggers_only:
            print(
                "Colonnes: réception | type | stNum | sqNum | frac_seconde(ms) | Δ net(ms) | seconde_pile",
                file=sys.stderr,
            )
            print("-" * 88, file=sys.stderr)
        if args.audit_triggers:
            print(
                "Mode audit : après chaque stNum, la séquence sqNum complète est affichée sur stderr.",
                file=sys.stderr,
            )
    print("Interrompre avec Ctrl+C.", file=sys.stderr)

    capture_stop = {"flag": False, "count": 0}

    def _on_stop_signal(signum: int, frame: object) -> None:
        capture_stop["count"] += 1
        capture_stop["flag"] = True
        if capture_stop["count"] >= 2:
            raise KeyboardInterrupt

    signal.signal(signal.SIGINT, _on_stop_signal)
    signal.signal(signal.SIGTERM, _on_stop_signal)

    if args.go_id and args.app_id is None:
        print(
            "Astuce : ajoutez --app-id 0x150A pour réduire le trafic GOOSE capturé.",
            file=sys.stderr,
        )

    try:
        sub.run_until(should_stop=lambda: capture_stop["flag"])
    except KeyboardInterrupt:
        capture_stop["flag"] = True
    finally:
        drop_n = sub.stats().get("drops", sub._drops)
        if drop_n:
            print(
                f"⚠ {drop_n} paquet(s) GOOSE perdus (file de capture pleine).",
                file=sys.stderr,
            )
        close_epoch()
        if args.measure_delay:
            print_delay_stats(deltas)
            print(f"\n{trigger_count} déclenchement(s) détecté(s).", file=sys.stderr)
        if args.problem_diag or args.problem_watch:
            title = "Bilan diagnostic" if args.problem_diag else "Bilan suivi"
            print(f"\n=== {title} ===", file=sys.stderr)
            print(f"  défauts vus        : {defaut_count}", file=sys.stderr)
            print(f"  Δ > seuil          : {problem_delay}", file=sys.stderr)
            print(f"  manquants déduits  : {problem_missing}", file=sys.stderr)
            if args.problem_diag:
                print(f"  rapports cycle     : {problem_diag_count}", file=sys.stderr)
                if defaut_delay_hits:
                    print(f"\n=== Δ > seuil ({len(defaut_delay_hits)} défaut(s)) ===", file=sys.stderr)
                    for rec in defaut_delay_hits:
                        print(f"  {_fmt_trigger_line(rec)}", file=sys.stderr)
                elif problem_diag_count == 0 and problem_delay == 0:
                    print("  → aucune anomalie détectée", file=sys.stderr)
                if trigger_count == 0:
                    print(
                        "  ⚠ Aucun déclenchement capturé — po_service utilise peut-être "
                        "déjà l'interface.",
                        file=sys.stderr,
                    )
                    print(
                        "    Essayez : --from-api http://127.0.0.1:7050",
                        file=sys.stderr,
                    )
            if defaut_gaps:
                avg = sum(defaut_gaps) / len(defaut_gaps)
                print(
                    f"  écart moyen défauts: {avg:.2f} s "
                    f"(min {min(defaut_gaps):.2f} / max {max(defaut_gaps):.2f})",
                    file=sys.stderr,
                )
                print(
                    f"  → cycle configuré  : {args.problem_cycle} s "
                    f"(essayez --problem-cycle {round(avg)})",
                    file=sys.stderr,
                )


if __name__ == "__main__":
    main()
