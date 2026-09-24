#!/usr/bin/env python3
# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Capture GOOSE and SV with pcapy and with iec61850.capture at the same time, and compare.

    sudo python3 tools/capture_compare.py IFACE [--seconds 10]

Both captures are passive. Reports, per backend: frames by ethertype, frames
with an 802.1Q tag, kernel drops and CPU time of the capture thread; then
whether both saw the same frames byte for byte and how far apart their
timestamps are.
"""

from __future__ import annotations

import argparse
import bisect
import multiprocessing
import statistics
import sys
import threading
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from iec61850.capture import PacketCapture  # noqa: E402

from processbus_capture import PROCESSBUS_BPF as BPF  # noqa: E402


def _ethertype(frame: bytes) -> int:
    ethertype = int.from_bytes(frame[12:14], "big")
    return int.from_bytes(frame[16:18], "big") if ethertype == 0x8100 else ethertype


class Result:
    def __init__(self, name: str) -> None:
        self.name = name
        self.frames: list[tuple[float, bytes]] = []
        self.cpu = 0.0
        self.dropped = 0
        self.error: str | None = None


def run_pcapy(iface: str, stop: threading.Event, start: threading.Barrier, out: Result) -> None:
    import pcapy

    cap = pcapy.open_live(iface, 65535, 1, 50)
    cap.setfilter(BPF)
    start.wait()
    cpu0 = time.thread_time()
    while not stop.is_set():
        header, pkt = cap.next()
        if header is None or not pkt:
            continue
        sec, usec = header.getts()
        out.frames.append((sec + usec / 1e6, bytes(pkt)))
    out.cpu = time.thread_time() - cpu0
    out.dropped = cap.stats()[1]


def run_afpacket(iface: str, stop: threading.Event, start: threading.Barrier, out: Result) -> None:
    with PacketCapture(iface, timeout=0.05) as cap:
        start.wait()
        cpu0 = time.thread_time()
        while not stop.is_set():
            frame = cap.recv()
            if frame is not None:
                out.frames.append((frame.timestamp, frame.data))
        out.cpu = time.thread_time() - cpu0
        out.dropped = cap.stats().dropped


def _record(backend: str, iface: str, seconds: float, conn: object) -> None:
    """Child process: capture for ``seconds`` and send the result back."""
    stop = threading.Event()
    start = threading.Barrier(2)
    res = Result(backend)
    worker = threading.Thread(
        target=run_pcapy if backend == "pcapy" else run_afpacket, args=(iface, stop, start, res), daemon=True
    )
    worker.start()
    start.wait()
    time.sleep(seconds)
    stop.set()
    worker.join(timeout=5)
    conn.send((res.frames, res.cpu, res.dropped))  # type: ignore[attr-defined]


def _nearest(times: list[float], ts: float) -> float:
    i = bisect.bisect_left(times, ts)
    candidates = [times[j] for j in (i - 1, i) if 0 <= j < len(times)]
    return min(candidates, key=lambda t: abs(t - ts))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("iface")
    parser.add_argument("--seconds", type=float, default=10.0)
    parser.add_argument("--only", choices=("pcapy", "afpacket"), help="run one backend alone (CPU cost without the other)")
    args = parser.parse_args()

    backends = [args.only] if args.only else ["pcapy", "afpacket"]
    procs, pipes = [], []
    for backend in backends:  # one process each: separate GILs, as in production
        parent, child = multiprocessing.Pipe(duplex=False)
        proc = multiprocessing.Process(target=_record, args=(backend, args.iface, args.seconds, child))
        proc.start()
        procs.append(proc)
        pipes.append(parent)
    results = []
    for backend, pipe, proc in zip(backends, pipes, procs):
        res = Result(backend)
        res.frames, res.cpu, res.dropped = pipe.recv()
        proc.join()
        results.append(res)

    for res in results:
        kinds = Counter(_ethertype(f) for _, f in res.frames)
        tagged = sum(1 for _, f in res.frames if f[12:14] == b"\x81\x00")
        n = len(res.frames)
        print(
            f"{res.name:9s} {n:7d} frames (GOOSE {kinds[0x88B8]}, SV {kinds[0x88BA]}), {tagged} tagged, "
            f"{res.dropped} dropped, CPU {res.cpu:.2f} s = {res.cpu / args.seconds * 100:.1f} % of a core, "
            f"{res.cpu / max(n, 1) * 1e6:.1f} us/frame"
        )
    if len(results) < 2:
        return 0

    pcap, afp = results
    lo = max(pcap.frames[0][0], afp.frames[0][0]) + 0.5
    hi = min(pcap.frames[-1][0], afp.frames[-1][0]) - 0.5
    a = Counter(f for ts, f in pcap.frames if lo <= ts <= hi)
    b = Counter(f for ts, f in afp.frames if lo <= ts <= hi)
    print(f"over {hi - lo:.1f} s: {sum(a.values())} vs {sum(b.values())} frames, "
          f"only pcapy {sum((a - b).values())}, only afpacket {sum((b - a).values())}")
    # Identical frames recur (smpCnt wraps every second): match each one to the nearest copy.
    times: dict[bytes, list[float]] = {}
    for ts, f in pcap.frames:
        times.setdefault(f, []).append(ts)
    deltas = sorted(
        (ts - _nearest(times[f], ts)) * 1e6 for ts, f in afp.frames if f in times and lo <= ts <= hi
    )
    if deltas:
        print(f"timestamp afpacket - pcapy (us): median {statistics.median(deltas):.1f}, "
              f"p1 {deltas[len(deltas) // 100]:.1f}, p99 {deltas[len(deltas) * 99 // 100]:.1f}, "
              f"min {deltas[0]:.1f}, max {deltas[-1]:.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
