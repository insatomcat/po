#!/usr/bin/env python3
"""
Receiver SV (BER, 2 ASDU/pkt) via pcap – vérification format rt_sender, mesure usec/delay.

Inspiré de sv_counter3.py: capture pcap (timestamps par paquet), file + 2 threads.
Parse BER comme receiver, calcule delay = (usec - expected) % 1e6, expected = smpCnt * (1e6/4800).

Usage:
  sudo python3 sv_receiver_delay.py -i <interface> [--check-format] [--only-wrap]

  --check-format   Capturer un paquet, vérifier format rt_sender, afficher structure, quitter.
  --only-wrap      N'afficher que les paquets smpCnt 0,1.
  --cpu N[,N...]   Épingler le processus sur les CPUs (ex. 0 ou 0,1), comme sv_counter3.
"""

from __future__ import annotations

import argparse
import os
import queue
import struct
import sys
import threading

try:
    import pcapy
except ImportError:
    print("pcapy required: pip install pcapy", file=sys.stderr)
    sys.exit(1)

ETH_HEADER_LEN = 14
ETH_VLAN_LEN = 4
ETH_P_61850_SV = 0x88BA
SMP_PER_SEC = 4800
USEC_PER_SEC = 1_000_000
PER_SAMPLE_US = USEC_PER_SEC / SMP_PER_SEC
QUEUE_MAX = 10000
SNAPLEN = 512
READ_TIMEOUT_MS = 100


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


def parse_sv_packet(data: bytes) -> list[tuple[str, int]]:
    """Parse SV payload (8-byte header + savPdu), retourne [(svID, smpCnt), ...]."""
    out: list[tuple[str, int]] = []
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
        if svid is not None and smp_cnt is not None:
            out.append((svid, smp_cnt))
    return out


def payload_from_frame(frame: bytes) -> tuple[bytes | None, int]:
    """
    Extrait le payload SV (sans Eth, sans VLAN) et l'offset de l'ethertype.
    Retourne (payload, ethertype) ou (None, 0) si pas 0x88ba.
    """
    if len(frame) < ETH_HEADER_LEN:
        return None, 0
    eth_type = (frame[12] << 8) | frame[13]
    payload_offset = ETH_HEADER_LEN
    if eth_type == 0x8100:
        if len(frame) < ETH_HEADER_LEN + ETH_VLAN_LEN + 2:
            return None, 0
        eth_type = (frame[16] << 8) | frame[17]
        payload_offset = ETH_HEADER_LEN + ETH_VLAN_LEN
    if eth_type != ETH_P_61850_SV:
        return None, 0
    return bytes(frame[payload_offset:]), eth_type


def check_format(payload: bytes) -> None:
    """Vérifie le format rt_sender (8-byte header + savPdu, 2 ASDUs) et affiche la structure."""
    if len(payload) < 8:
        print("[check-format] payload < 8 bytes")
        return
    appid = struct.unpack("!H", payload[0:2])[0]
    length = struct.unpack("!H", payload[2:4])[0]
    print(f"[check-format] APPID=0x{appid:04x}  Length={length}  Reserved={payload[4:8].hex()}")
    asdus = parse_sv_packet(payload)
    print(f"[check-format] ASDUs: {len(asdus)}")
    for i, (svid, smpcnt) in enumerate(asdus):
        print(f"  ASDU {i}: svID=\"{svid}\"  smpCnt={smpcnt}")
    if len(asdus) != 2:
        print("[check-format] ATTENTION: rt_sender envoie 2 ASDUs/pkt, trouvé", len(asdus))
    else:
        print("[check-format] Format rt_sender OK (2 ASDUs)")


def capture_loop(
    iface: str,
    packet_queue: queue.Queue[tuple[object, bytes]],
    drop_non_wrap: bool,
) -> None:
    cap = pcapy.open_live(iface, SNAPLEN, 1, READ_TIMEOUT_MS)
    try:
        cap.setfilter("ether proto 0x88ba")
    except Exception as e:
        print(f"[capture] setfilter failed: {e}", file=sys.stderr)
    msg = f"[+] Capture sur {iface} (0x88ba). Ctrl+C pour arrêter."
    if drop_non_wrap:
        msg += " [--drop-non-wrap: enqueue 0,1 uniquement]"
    print(msg + "\n")
    try:
        while True:
            header, raw = cap.next()
            if not header:
                continue
            if drop_non_wrap:
                payload, _ = payload_from_frame(raw)
                if payload:
                    asdus = parse_sv_packet(payload)
                    if asdus and asdus[0][1] > 1:
                        continue
            try:
                packet_queue.put_nowait((header, raw))
            except queue.Full:
                pass
    except KeyboardInterrupt:
        pass


def process_loop(
    packet_queue: queue.Queue[tuple[object, bytes]],
    only_wrap: bool,
    backlog_warn: list[bool],
) -> None:
    last_smp: int | None = None
    try:
        while True:
            header, raw = packet_queue.get()
            sec, usec = header.getts()
            usec_in_sec = usec  # 0..999999
            payload, _ = payload_from_frame(raw)
            if not payload:
                packet_queue.task_done()
                continue
            asdus = parse_sv_packet(payload)
            if not asdus:
                packet_queue.task_done()
                continue
            smp0 = asdus[0][1]
            is_wrap = last_smp is not None and smp0 < last_smp and smp0 <= 1
            last_smp = smp0
            if only_wrap and smp0 > 1:
                packet_queue.task_done()
                continue
            if is_wrap:
                print("\n=== New second (smpCnt wrap) ===")
            if smp0 <= 1 and usec_in_sec > 500_000 and backlog_warn:
                backlog_warn.clear()
                print(
                    "[!] usec ~999 ms pour 0,1: backlog (capture ne suit pas 2400 pkt/s). "
                    "--cpu N ou --drop-non-wrap peuvent aider.",
                    file=sys.stderr,
                )
            delays = []
            for _svid, smpcnt in asdus:
                expected_us = (smpcnt * PER_SAMPLE_US) % USEC_PER_SEC
                delay_us = (usec_in_sec - expected_us) % USEC_PER_SEC
                if delay_us > USEC_PER_SEC / 2:
                    delay_us -= USEC_PER_SEC
                delays.append(round(delay_us))
            # Pour 0,1: un seul délai (paquet envoyé à T+0), éviter delay1 trompeur.
            if smp0 <= 1 and delays:
                delay_str = str(delays[0])
            else:
                delay_str = ", ".join(str(d) for d in delays)
            # usec = µs dans la seconde (pcap), delay = µs vs expected (smpCnt * 1e6/4800)
            print(f"usec, {usec_in_sec}, delay, {delay_str}")
            packet_queue.task_done()
    except KeyboardInterrupt:
        pass


def main() -> None:
    ap = argparse.ArgumentParser(
        description="SV receiver via pcap (format rt_sender, usec/delay).",
    )
    ap.add_argument("-i", "--interface", required=True, metavar="IFACE", help="Interface (ex. eth0, lo)")
    ap.add_argument(
        "--check-format",
        action="store_true",
        help="Capturer un paquet, vérifier format rt_sender, afficher structure et quitter.",
    )
    ap.add_argument(
        "--only-wrap",
        action="store_true",
        help="N'afficher que les paquets smpCnt 0,1.",
    )
    ap.add_argument(
        "--cpu",
        metavar="N[,N...]",
        help="Épingler le processus sur les CPUs (ex. 0 ou 0,1).",
    )
    ap.add_argument(
        "--drop-non-wrap",
        action="store_true",
        help="Avec --only-wrap: ne mettre en file que les paquets 0,1 (drop les autres en capture).",
    )
    args = ap.parse_args()

    if args.cpu:
        try:
            cpus = [int(x.strip()) for x in args.cpu.split(",")]
            os.sched_setaffinity(0, set(cpus))
            print(f"[+] CPU affinity: {sorted(cpus)}", file=sys.stderr)
        except (ValueError, OSError) as e:
            print(f"[!] --cpu invalid: {e}", file=sys.stderr)
            sys.exit(1)

    iface = args.interface
    packet_queue: queue.Queue[tuple[object, bytes]] = queue.Queue(maxsize=QUEUE_MAX)

    if args.check_format:
        cap = pcapy.open_live(iface, SNAPLEN, 1, 2000)
        try:
            cap.setfilter("ether proto 0x88ba")
        except Exception:
            pass
        print(f"[check-format] Capture 1 paquet sur {iface}...")
        for _ in range(5000):
            h, raw = cap.next()
            if not h:
                continue
            payload, _ = payload_from_frame(raw)
            if payload:
                check_format(payload)
                break
        else:
            print("[check-format] Aucun paquet 0x88ba reçu (timeout).")
        return

    if args.drop_non_wrap and not args.only_wrap:
        print("[!] --drop-non-wrap exige --only-wrap.", file=sys.stderr)
        sys.exit(1)
    backlog_warn: list[bool] = [True]
    capture_thread = threading.Thread(
        target=capture_loop,
        args=(iface, packet_queue, bool(args.drop_non_wrap)),
        daemon=True,
    )
    capture_thread.start()
    try:
        process_loop(packet_queue, args.only_wrap, backlog_warn)
    except KeyboardInterrupt:
        print("\n[!] Arrêt.")


if __name__ == "__main__":
    main()
