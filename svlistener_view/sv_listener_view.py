#!/usr/bin/env python3
"""
Listener SV (IEC 61869-9 6I3U) – affichage ASCII des phasors U et I.

Capture les paquets SV sur une interface configurable, parse les valeurs
Ia,Ib,Ic et Va,Vb,Vc, et dessine 2 cercles (un pour U, un pour I) avec
des flèches aux angles 0°, -120°, -240° (cercle trigonométrique).

Usage:
  sudo python3 sv_listener_view.py -i <interface> [--interval 1] [--window 10] [--svid SVID] [--web 8080]

  -i, --interface   Interface réseau (obligatoire)
  --interval SEC    Intervalle de rafraîchissement en secondes (défaut: 1)
  --window SEC      Fenêtre pour stats délai inter-paquets (défaut: 10)
  --svid SVID       Filtrer sur le svID ; si absent, affiche la liste des svIDs vus
  --web PORT        Serveur web pour visualisation graphique (ex: 8080)
"""

from __future__ import annotations

import math
import os
import struct
import sys
import threading
import time
import traceback
from collections import deque

try:
    # Facultatif: permet de faire tourner Flask sous uvicorn via ASGI.
    from uvicorn.middleware.wsgi import WSGIMiddleware

    HAS_UVICORN_MIDDLEWARE = True
except ImportError:
    HAS_UVICORN_MIDDLEWARE = False

try:
    import pcapy
except ImportError:
    print("pcapy requis: pip install pcapy", file=sys.stderr)
    sys.exit(1)

try:
    from flask import Flask, jsonify, request, render_template
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

ETH_HEADER_LEN = 14
ETH_VLAN_LEN = 4
ETH_P_61850_SV = 0x88BA
I_SCALE = 1000
V_SCALE = 100
SEQDATA_6I3U = 72   # 6 I + 3 U
SEQDATA_4I4U = 64   # 4 I + 4 U
SMP_PER_CYCLE = 96  # 4800/50 Hz
SMP_MOD = 4800  # smpCnt wrap (4800 samples/sec)
CIRCLE_RADIUS = 8


def _read_ber_tag_len(data: bytes, off: int) -> tuple[int | None, int, int]:
    if off >= len(data):
        return None, 0, off
    tag = data[off]
    off += 1
    L = data[off]
    off += 1
    if L & 0x80:
        n = L & 0x7F
        L = 0
        for _ in range(n):
            if off >= len(data):
                return tag, 0, off
            L = (L << 8) | data[off]
            off += 1
    return tag, L, off


def parse_sv_asdus_with_seqdata(data: bytes) -> list[tuple[str, int, list[int]]]:
    """
    Parse SV payload, retourne [(svID, smpCnt, [Ia,Ib,Ic,Ires,In,Ih,Va,Vb,Vc]), ...].
    Gère 6I3U (72 octets) et 4I4U (64 octets). Format canonique: 9 valeurs (6I+3U).
    """
    out: list[tuple[str, int, list[int]]] = []
    if len(data) < 8:
        return out
    off = 8
    tag, sav_len, off = _read_ber_tag_len(data, off)
    if tag != 0x60:
        return out
    sav_end = off + sav_len
    if sav_end > len(data):
        return out
    tag, no_len, off = _read_ber_tag_len(data, off)
    if tag != 0x80 or no_len != 1 or off >= len(data):
        return out
    no_asdu = data[off]
    off += 1
    tag, seq_len, off = _read_ber_tag_len(data, off)
    if tag != 0xA2:
        return out
    seq_end = off + seq_len
    if seq_end > len(data):
        return out

    for _ in range(no_asdu):
        if off >= seq_end:
            break
        tag, asdu_len, off = _read_ber_tag_len(data, off)
        if tag != 0x30:
            off += asdu_len
            continue
        asdu_end = off + asdu_len
        svid: str | None = None
        smp_cnt: int | None = None
        seq_data: bytes | None = None
        while off < asdu_end:
            t, L, off = _read_ber_tag_len(data, off)
            if off + L > len(data):
                break
            val = data[off : off + L]
            off += L
            if t == 0x80:
                svid = val.decode("utf-8", errors="replace")
            elif t == 0x82 and L == 2:
                smp_cnt = struct.unpack("!H", val)[0]
            elif t == 0x87 and L >= SEQDATA_4I4U:
                seq_data = val[:L]
        if svid is not None and smp_cnt is not None and seq_data is not None:
            vals = _parse_seqdata(seq_data)
            if vals:
                out.append((svid, smp_cnt, vals))
    return out


def _parse_seqdata(seq_data: bytes) -> list[int]:
    """Parse seqData 6I3U (72 octets) ou 4I4U (64 octets) → [Ia,Ib,Ic,Ires,In,Ih,Va,Vb,Vc]."""
    n = len(seq_data)
    if n >= SEQDATA_6I3U:
        vals = []
        for i in range(9):
            idx = i * 8
            v = struct.unpack("!i", seq_data[idx : idx + 4])[0]
            vals.append(v)
        return vals
    if n >= SEQDATA_4I4U:
        vals = []
        for i in range(8):
            idx = i * 8
            v = struct.unpack("!i", seq_data[idx : idx + 4])[0]
            vals.append(v)
        return [vals[0], vals[1], vals[2], vals[3], 0, 0, vals[4], vals[5], vals[6]]
    return []


def payload_from_frame(frame: bytes) -> bytes | None:
    """Extrait le payload SV (ethertype 0x88ba, avec ou sans VLAN)."""
    if len(frame) < ETH_HEADER_LEN:
        return None
    eth_type = (frame[12] << 8) | frame[13]
    payload_offset = ETH_HEADER_LEN
    if eth_type == 0x8100:
        if len(frame) < ETH_HEADER_LEN + ETH_VLAN_LEN + 2:
            return None
        eth_type = (frame[16] << 8) | frame[17]
        payload_offset = ETH_HEADER_LEN + ETH_VLAN_LEN
    if eth_type != ETH_P_61850_SV:
        return None
    return bytes(frame[payload_offset:])


def compute_phasor_from_samples(
    samples: list[tuple[int, list[float]]], idx: int
) -> tuple[float, float]:
    """
    Calcule le phasor (magnitude, phase_rad) pour le canal idx à partir
    des échantillons sur un cycle (96 samples à 50 Hz). DFT au fondamental.
    """
    if len(samples) < SMP_PER_CYCLE:
        return 0.0, 0.0
    re = 0.0
    im = 0.0
    for n, (_, vals) in enumerate(samples[-SMP_PER_CYCLE:]):
        x = vals[idx]
        angle = -2.0 * math.pi * n / SMP_PER_CYCLE
        re += x * math.cos(angle)
        im += x * math.sin(angle)
    re /= SMP_PER_CYCLE
    im /= SMP_PER_CYCLE
    mag = 2.0 * math.sqrt(re * re + im * im)
    phase = math.atan2(im, re)
    return mag, phase


def draw_arrow(grid: list[list[str]], cx: int, cy: int, angle_rad: float, length: float, ch: str) -> None:
    """Dessine une flèche du centre (cx,cy) dans la direction angle, longueur length (en unités grille)."""
    if length < 0.3:
        return
    # angle: 0 = droite, pi/2 = haut (y décroissant en ascii)
    dx = length * math.cos(angle_rad)
    dy = -length * math.sin(angle_rad)
    ex = cx + dx
    ey = cy + dy
    steps = max(1, int(length * 2))
    for i in range(1, steps + 1):
        t = i / steps
        x = int(round(cx + dx * t))
        y = int(round(cy + dy * t))
        if 0 <= y < len(grid) and 0 <= x < len(grid[0]):
            if t >= 0.9:
                grid[y][x] = ch
            elif grid[y][x] == " ":
                grid[y][x] = "·"


def draw_ellipse(grid: list[list[str]], cx: int, cy: int, rx: int, ry: int) -> None:
    """Dessine une ellipse ASCII de centre (cx,cy), rayon horizontal rx, vertical ry."""
    chars = ".-'`"
    for i in range(-ry, ry + 1):
        for j in range(-rx, rx + 1):
            # (j/rx)^2 + (i/ry)^2 = 1 sur le bord
            d = math.sqrt((j / rx) ** 2 + (i / ry) ** 2) if rx > 0 and ry > 0 else 0
            if 0.92 <= d <= 1.08:
                y, x = cy + i, cx + j
                if 0 <= y < len(grid) and 0 <= x < len(grid[0]):
                    idx = min(int((d - 0.92) / 0.16 * len(chars)), len(chars) - 1)
                    if idx < 0:
                        idx = 0
                    c = chars[idx] if grid[y][x] == " " else grid[y][x]
                    grid[y][x] = c


def render_phasor_circle(
    width: int, height: int,
    phasors: list[tuple[float, float]], scale: float, label: str,
    scale_pct: float = 100.0, aspect: float = 24/10
) -> list[list[str]]:
    """
    Grille ASCII: ellipse avec 3 flèches (magnitude, phase_rad).
    phase: 0 = droite, cercle trigonométrique.
    scale_pct: 100 = base, 200 = rayon doublé.
    aspect: ratio h/l des caractères (1.78 pour cercle visuel VGA).
    """
    sf = max(0.25, scale_pct / 100.0)
    grid = [[" " for _ in range(width)] for _ in range(height)]
    cx, cy = width // 2, height // 2
    ry = int((min(cy, CIRCLE_RADIUS) - 1) * sf)
    rx = int(min(cx - 1, ry * aspect))
    ry = min(ry, cy - 1)
    rx = min(rx, cx - 1)
    draw_ellipse(grid, cx, cy, rx, ry)

    r_arrow = max(1, min(rx, ry) - 1)
    max_mag = max((p[0] for p in phasors), default=1.0)
    scale_len = r_arrow / max(max_mag * scale, 1e-6)

    chars = ["A", "B", "C"]
    for i, (mag, phase_rad) in enumerate(phasors):
        length = mag * scale_len
        ch = chars[i]
        draw_arrow(grid, cx, cy, phase_rad, length, ch)

    for i, c in enumerate(list(label)):
        x = cx - len(label) // 2 + i
        if 0 <= x < width:
            grid[0][x] = c
    return grid


def render_phasor_display(
    u_arrows: list[tuple[float, float]], i_arrows: list[tuple[float, float]],
    u_mags: list[float], i_mags: list[float],
    scale_pct: float = 100.0, aspect: float = 24/10
) -> str:
    """Affichage des 2 cercles avec phasors (mag, phase)."""
    sf = max(0.25, scale_pct / 100.0)
    w = int(55 * sf)
    h = int(21 * sf)
    u_scale = 0.015 if max(u_mags) > 0 else 0.01
    i_scale = 0.02 if max(i_mags) > 0 else 0.01
    grid_u = render_phasor_circle(w, h, u_arrows, u_scale, "U (V)", scale_pct, aspect)
    grid_i = render_phasor_circle(w, h, i_arrows, i_scale, "I (A)", scale_pct, aspect)
    lines = []
    for row_u, row_i in zip(grid_u, grid_i):
        lines.append("".join(row_u) + "    " + "".join(row_i))
    return "\n".join(lines)


def render_display(
    u_vals: list[float], i_vals: list[float],
    u_scale: float = 0.01, i_scale: float = 0.002,
    scale_pct: float = 100.0, aspect: float = 24/10
) -> str:
    """Affichage instantané: 3 flèches à 0°, -120°, -240° avec longueur = valeur."""
    w, h = 55, 21
    u_arrows = [(abs(v), 0.0 if v >= 0 else math.pi) if i == 0 else
                (abs(v), math.radians(-120) if v >= 0 else math.radians(60)) if i == 1 else
                (abs(v), math.radians(-240) if v >= 0 else math.radians(120))
                for i, v in enumerate(u_vals)]
    i_arrows = [(abs(v), 0.0 if v >= 0 else math.pi) if i == 0 else
                (abs(v), math.radians(-120) if v >= 0 else math.radians(60)) if i == 1 else
                (abs(v), math.radians(-240) if v >= 0 else math.radians(120))
                for i, v in enumerate(i_vals)]
    return render_phasor_display(
        u_arrows, i_arrows,
        [abs(v) for v in u_vals], [abs(v) for v in i_vals],
        scale_pct, aspect
    )


def compute_display_data(
    buf: list, stats: dict, stats_lock: threading.Lock,
    config: dict, svid: str | None
) -> dict:
    """Calcule les données d'affichage (phasors, stats) pour console ou API."""
    out: dict = {"svid": svid, "samples_count": len(buf)}
    if svid and buf:
        with stats_lock:
            min_all_val = stats["min_delay_all"]
            max_all_val = stats["max_delay_all"]
            ts_list = list(stats["packet_timestamps"])
            min_sync_all_val = stats["min_delay_sync_all"]
            max_sync_all_val = stats["max_delay_sync_all"]
            smpcnt0_list = list(stats["smpcnt0_timestamps"])
            misses_all = stats["misses_all"]
            misses_events = list(stats["misses_events"])
        window = config.get("window", 10)
        now = time.time()
        delays_win = [ts_list[i + 1] - ts_list[i] for i in range(len(ts_list) - 1)]
        min_win = min(delays_win) * 1e6 if delays_win else None
        max_win = max(delays_win) * 1e6 if delays_win else None
        min_all = min_all_val * 1e6 if min_all_val != float("inf") else None
        max_all = max_all_val * 1e6 if max_all_val > 0 else None
        delays_sync_win = [t - math.floor(t) for t in smpcnt0_list]
        min_sync_win = min(delays_sync_win) * 1e6 if delays_sync_win else None
        max_sync_win = max(delays_sync_win) * 1e6 if delays_sync_win else None
        min_sync_all = min_sync_all_val * 1e6 if min_sync_all_val != float("inf") else None
        max_sync_all = max_sync_all_val * 1e6 if max_sync_all_val > 0 else None
        misses_win = sum(g for t, g in misses_events if t >= now - window)

        out["window"] = window
        out["delay_all"] = f"min={min_all:.2f} max={max_all:.2f}" if min_all is not None else "-"
        out["delay_win"] = f"min={min_win:.2f} max={max_win:.2f}" if min_win is not None else "-"
        out["sync_all"] = f"min={min_sync_all:.2f} max={max_sync_all:.2f}" if min_sync_all is not None else "-"
        out["sync_win"] = f"min={min_sync_win:.2f} max={max_sync_win:.2f}" if min_sync_win is not None else "-"
        out["misses_all"] = misses_all
        out["misses_win"] = misses_win

        scale_pct = config.get("scale", 100)
        if len(buf) >= SMP_PER_CYCLE:
            u_mags, u_phases = [], []
            for idx in [6, 7, 8]:
                mag, ph = compute_phasor_from_samples(buf, idx)
                u_mags.append(mag)
                u_phases.append(ph)
            i_mags, i_phases = [], []
            for idx in [0, 1, 2]:
                mag, ph = compute_phasor_from_samples(buf, idx)
                i_mags.append(mag)
                i_phases.append(ph)
            phase_ref = u_phases[0]
            u_arrows = [(u_mags[i], u_phases[i] - phase_ref) for i in range(3)]
            i_arrows = [
                (i_mags[i], (u_phases[i] - phase_ref) + (i_phases[i] - u_phases[i]))
                for i in range(3)
            ]
            phase_shifts_deg = [math.degrees(i_phases[i] - u_phases[i]) for i in range(3)]
            out["u_arrows"] = [[p[0], p[1]] for p in u_arrows]
            out["i_arrows"] = [[p[0], p[1]] for p in i_arrows]
            out["u_mags"] = u_mags
            out["i_mags"] = i_mags
            out["phase_shifts"] = phase_shifts_deg
        else:
            s = buf[-1][1]
            u_vals = [s[6], s[7], s[8]]
            i_vals = [s[0], s[1], s[2]]
            u_arrows = [(abs(v), 0.0 if v >= 0 else math.pi) if i == 0 else
                        (abs(v), math.radians(-120) if v >= 0 else math.radians(60)) if i == 1 else
                        (abs(v), math.radians(-240) if v >= 0 else math.radians(120))
                        for i, v in enumerate(u_vals)]
            i_arrows = [(abs(v), 0.0 if v >= 0 else math.pi) if i == 0 else
                        (abs(v), math.radians(-120) if v >= 0 else math.radians(60)) if i == 1 else
                        (abs(v), math.radians(-240) if v >= 0 else math.radians(120))
                        for i, v in enumerate(i_vals)]
            out["u_arrows"] = [[p[0], p[1]] for p in u_arrows]
            out["i_arrows"] = [[p[0], p[1]] for p in i_arrows]
            out["u_mags"] = [abs(v) for v in u_vals]
            out["i_mags"] = [abs(v) for v in i_vals]
            out["phase_shifts"] = None
    return out


def _reset_stats_for_new_svid(stats: dict, stats_lock: threading.Lock) -> None:
    """Réinitialise les stats lors d'un changement de svID."""
    with stats_lock:
        stats["min_delay_all"] = float("inf")
        stats["max_delay_all"] = 0.0
        stats["last_pkt_time"] = None
        stats["packet_timestamps"].clear()
        stats["min_delay_sync_all"] = float("inf")
        stats["max_delay_sync_all"] = 0.0
        stats["smpcnt0_timestamps"].clear()
        stats["misses_all"] = 0
        stats["misses_events"].clear()
        stats["last_smpcnt"] = None


def create_flask_app(
    samples: list, samples_lock: threading.Lock,
    stats: dict, stats_lock: threading.Lock,
    seen_svids: set, seen_svids_lock: threading.Lock,
    config: dict,
) -> Flask:
    app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "templates"))

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/data")
    def api_data():
        with samples_lock:
            buf = list(samples)
        with seen_svids_lock:
            svids = sorted(seen_svids)
        with stats_lock:
            debug = {
                "capture_running": bool(stats.get("capture_running")),
                "capture_heartbeat": stats.get("capture_heartbeat"),
                "capture_packets": int(stats.get("capture_packets", 0)),
                "sv_packets": int(stats.get("sv_packets", 0)),
                "asdu_seen": int(stats.get("asdu_seen", 0)),
                "parse_errors": int(stats.get("parse_errors", 0)),
                "capture_loop_errors": int(stats.get("capture_loop_errors", 0)),
                "last_error": stats.get("last_error"),
                "last_error_at": stats.get("last_error_at"),
            }
        svid = config.get("svid")
        if not svid:
            return jsonify({"svid": None, "svids": svids, "debug": debug})
        data = compute_display_data(buf, stats, stats_lock, config, svid)
        data["svids"] = svids
        data["debug"] = debug
        return jsonify(data)

    @app.route("/api/config", methods=["GET"])
    def api_config_get():
        return jsonify(dict(config))

    @app.route("/api/config", methods=["POST"])
    def api_config_post():
        j = request.get_json() or {}
        for k in ("interval", "window", "scale", "aspect"):
            if k in j:
                v = float(j[k])
                if k in ("interval", "window") and v > 0:
                    config[k] = max(0.1 if k == "interval" else 1, v)
                elif k == "scale" and 10 <= v <= 500:
                    config[k] = v
                elif k == "aspect" and 1 <= v <= 4:
                    config[k] = v
        return jsonify(dict(config))

    @app.route("/api/svid", methods=["POST"])
    def api_svid_post():
        j = request.get_json() or {}
        new_svid = j.get("svid")
        if new_svid is not None and not isinstance(new_svid, str):
            new_svid = str(new_svid) if new_svid else None
        if new_svid is not None and new_svid.strip() == "":
            new_svid = None
        config["svid"] = new_svid
        with samples_lock:
            samples.clear()
        _reset_stats_for_new_svid(stats, stats_lock)
        return jsonify({"svid": config["svid"]})

    return app


def capture_loop(iface: str, samples: list, samples_lock: threading.Lock,
                 stats: dict, stats_lock: threading.Lock, config: dict,
                 seen_svids: set, seen_svids_lock: threading.Lock) -> None:
    with stats_lock:
        stats["capture_running"] = True
    cap = pcapy.open_live(iface, 512, 1, 100)
    try:
        cap.setfilter("ether proto 0x88ba or (vlan and ether proto 0x88ba)")
    except Exception as e:
        print(f"[capture] setfilter: {e}", file=sys.stderr)
    print(f"[+] Capture sur {iface} (0x88ba)" + (f", svID={config.get('svid')}" if config.get("svid") else ""), file=sys.stderr)
    try:
        while True:
            try:
                header, raw = cap.next()
                if not header:
                    continue
                with stats_lock:
                    stats["capture_packets"] += 1
                    stats["capture_heartbeat"] = time.time()

                payload = payload_from_frame(raw)
                if not payload:
                    continue

                ts = header.getts()
                ts_sec = ts[0] + ts[1] / 1e6
                asdus = parse_sv_asdus_with_seqdata(payload)
                with stats_lock:
                    stats["sv_packets"] += 1
                    stats["asdu_seen"] += len(asdus)
                with seen_svids_lock:
                    for svid, _, _ in asdus:
                        seen_svids.add(svid)

                svid_filter = config.get("svid")
                if svid_filter:
                    asdus = [a for a in asdus if a[0] == svid_filter]
                    if not asdus:
                        continue
                else:
                    continue

                with stats_lock:
                    if stats["last_pkt_time"] is not None:
                        delay = ts_sec - stats["last_pkt_time"]
                        stats["min_delay_all"] = min(stats["min_delay_all"], delay)
                        stats["max_delay_all"] = max(stats["max_delay_all"], delay)
                    stats["last_pkt_time"] = ts_sec
                    stats["packet_timestamps"].append(ts_sec)
                    window_sec = config.get("window", 10)
                    while stats["packet_timestamps"] and stats["packet_timestamps"][0] < ts_sec - window_sec:
                        stats["packet_timestamps"].popleft()

                for svid, smp_cnt, vals in asdus:
                    with stats_lock:
                        last = stats["last_smpcnt"]
                        if last is not None:
                            if smp_cnt == last:
                                gap = 0  # doublon
                            elif smp_cnt > last:
                                gap = smp_cnt - last - 1
                            else:
                                gap = (SMP_MOD - last - 1) + smp_cnt  # wrap
                            if gap > 0:
                                stats["misses_all"] += gap
                                stats["misses_events"].append((ts_sec, gap))
                                while stats["misses_events"] and stats["misses_events"][0][0] < ts_sec - config.get("window", 10):
                                    stats["misses_events"].popleft()
                        stats["last_smpcnt"] = smp_cnt
                    if smp_cnt == 0:
                        delay_sync = ts_sec - math.floor(ts_sec)
                        with stats_lock:
                            stats["min_delay_sync_all"] = min(stats["min_delay_sync_all"], delay_sync)
                            stats["max_delay_sync_all"] = max(stats["max_delay_sync_all"], delay_sync)
                            stats["smpcnt0_timestamps"].append(ts_sec)
                            while stats["smpcnt0_timestamps"] and stats["smpcnt0_timestamps"][0] < ts_sec - config.get("window", 10):
                                stats["smpcnt0_timestamps"].popleft()
                    ia = vals[0] / I_SCALE
                    ib = vals[1] / I_SCALE
                    ic = vals[2] / I_SCALE
                    va = vals[6] / V_SCALE
                    vb = vals[7] / V_SCALE
                    vc = vals[8] / V_SCALE
                    with samples_lock:
                        samples.append((smp_cnt, [ia, ib, ic, vals[3]/I_SCALE, vals[4]/I_SCALE, vals[5]/I_SCALE, va, vb, vc]))
                        if len(samples) > 5000:
                            samples[:] = samples[-SMP_PER_CYCLE * 2:]
            except Exception as e:
                err = f"{type(e).__name__}: {e}"
                with stats_lock:
                    stats["parse_errors"] += 1
                    stats["capture_loop_errors"] += 1
                    stats["last_error"] = err
                    stats["last_error_at"] = time.time()
                print(f"[capture] erreur loop ({iface}): {err}", file=sys.stderr)
                print(traceback.format_exc(), file=sys.stderr)
                continue
    except KeyboardInterrupt:
        pass
    finally:
        with stats_lock:
            stats["capture_running"] = False


def create_svview_app(
    interface: str,
    *,
    window: float | None = None,
    scale: float | None = None,
    aspect: float | None = None,
    svid: str | None = None,
) -> "Flask":
    """
    Construire l'app Flask + démarrer la capture.
    Peut être appelé depuis po_service (avec interface explicite) ou depuis
    l'exécution directe/uvicorn (paramètres optionnels lus dans l'env).
    """
    window = float(window or os.environ.get("SVVIEW_WINDOW", "10"))
    scale = float(scale if scale is not None else os.environ.get("SVVIEW_SCALE", "100"))
    aspect = float(aspect if aspect is not None else os.environ.get("SVVIEW_ASPECT", str(24 / 10)))
    svid = svid if svid is not None else os.environ.get("SVVIEW_SVID") or None

    config = {
        "interval": 1.0,
        "window": window,
        "scale": scale,
        "aspect": aspect,
        "svid": svid,
    }

    samples: list[tuple[int, list[float]]] = []
    samples_lock = threading.Lock()
    seen_svids: set[str] = set()
    seen_svids_lock = threading.Lock()
    stats = {
        "min_delay_all": float("inf"),
        "max_delay_all": 0.0,
        "last_pkt_time": None,
        "packet_timestamps": deque(maxlen=50000),
        "min_delay_sync_all": float("inf"),
        "max_delay_sync_all": 0.0,
        "smpcnt0_timestamps": deque(maxlen=50000),
        "misses_all": 0,
        "misses_events": deque(maxlen=50000),  # (ts_sec, gap)
        "last_smpcnt": None,
        "capture_running": False,
        "capture_heartbeat": None,
        "capture_packets": 0,
        "sv_packets": 0,
        "asdu_seen": 0,
        "parse_errors": 0,
        "capture_loop_errors": 0,
        "last_error": None,
        "last_error_at": None,
    }
    stats_lock = threading.Lock()

    t_cap = threading.Thread(
        target=capture_loop,
        args=(interface, samples, samples_lock, stats, stats_lock, config, seen_svids, seen_svids_lock),
        daemon=True,
    )
    t_cap.start()

    if not HAS_FLASK:
        print("Flask requis pour l'interface web: pip install flask", file=sys.stderr)
        sys.exit(1)

    app_flask = create_flask_app(
        samples, samples_lock, stats, stats_lock, seen_svids, seen_svids_lock, config
    )
    return app_flask


# Application pour uvicorn / exécution directe (si SVVIEW_INTERFACE défini)
_flask_app: "Flask | None" = None
if os.environ.get("SVVIEW_INTERFACE"):
    _flask_app = create_svview_app(os.environ["SVVIEW_INTERFACE"])
if HAS_UVICORN_MIDDLEWARE and _flask_app:
    app = WSGIMiddleware(_flask_app)
else:
    app = _flask_app


def main() -> None:
    """
    Lancement direct (sans uvicorn), utile pour debug local.
    SVVIEW_INTERFACE doit être défini.
    """
    iface = os.environ.get("SVVIEW_INTERFACE")
    if not iface:
        print("SVVIEW_INTERFACE non défini (interface réseau requise)", file=sys.stderr)
        sys.exit(1)
    flask_app = _flask_app or create_svview_app(iface)
    port = int(os.environ.get("SVVIEW_PORT", "7052"))
    print(f"[+] Interface web: http://0.0.0.0:{port}", file=sys.stderr)
    flask_app.run(host="0.0.0.0", port=port, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
