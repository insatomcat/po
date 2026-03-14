#!/usr/bin/env python3
import pcapy,sys,struct,sys,os
import threading,queue
from datetime import datetime

IFACE = sys.argv[1]
CPU = sys.argv[2]
WRAP_VALUE = int(sys.argv[3])
PER_SAMPLE = 1000000.0 / WRAP_VALUE

WAIT_WINDOW = 20
PROM_FILE = "/tmp/sv_counter.prom"
LOGFILE = "sv_report_log.txt"

# Queue to decouple capture and processing
packet_queue = queue.Queue(maxsize=10000)  # adjust maxsize if needed
stats = {}

def log_line(line: str):
    """Write a line to log file and console"""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    full = f"{ts} {line}"
    print(full)
    with open(LOGFILE, "a") as f:
        f.write(full + "\n")
    f.close()

def process_pkt(pkt):
    eth_type = (pkt[12] << 8) | pkt[13]
    payload_offset = 14
    if eth_type == 0x8100:
        eth_type = (pkt[16] << 8) | pkt[17]
        payload_offset = 18
    if eth_type == 0x88ba:
        results = []
        i = 0
        payload = memoryview(pkt)[payload_offset:].tobytes()
        while i < len(payload):
            pos = payload.find(b'0\x5F\x80', i)
            if pos == -1:
                break
            i = pos
            sv_len = payload[i+3]
            svID = payload[i+4:i+4+sv_len].decode(errors="ignore")
            if payload[i+4+sv_len] != 0x82:
                i += 1
                continue
            cnt_len = payload[i+5+sv_len]
            smpCnt = int.from_bytes(payload[i+6+sv_len:i+6+sv_len+cnt_len], 'big')
            results.append((svID, smpCnt))
            i += 6 + sv_len + cnt_len
        return results

def wrap_range(first, last, wrap):
    """
    Generate a wrapped range.

    Args:
        first (int): start value (inclusive).
        last (int): stop value (exclusive).
        wrap (int): max value before wrapping to 0.

    Returns:
        list of ints
    """
    if first <= last:
        return list(range(first, last))
    else:
        return list(range(first, wrap + 1)) + list(range(0, last))
def update_stats(smpcnts,usec):
    """
    smpcnts: list of (svID, smpCnt)
    Maintains:
      - received_count: total packets seen
      - missed_count: packets considered lost after WAIT_WINDOW
      - awaited: set of out-of-order packets
      - prev: highest in-order packet
    """
    for svID, smpCnt in smpcnts:
        entry = stats.setdefault(svID, {
            "prev": None,
            "awaited": set(),
            "missed_count": 0,
            "outoforder": 0,
            "max_delay": float("-inf"),
            "min_delay": float("inf"),
            "avg_delay": 0,
            "max_reldelay": float("-inf"),
            "min_reldelay": float("inf"),
            "avg_reldelay": 0,
            "received_count": 1,
            "last_usec": usec ,
            "high_delay_count": 0
        })
        awaited = entry["awaited"]

        expected_mod = ((smpCnt - 1) * PER_SAMPLE) % 1000000.0
        delay = (usec - expected_mod) % 1000000.0
        relative_delay = usec - entry["last_usec"]
        entry["last_usec"] = usec
        if relative_delay > 0:
            entry["received_count"] += 1
            if relative_delay > 1000:
                log_line(f"relative delay > 1000us: {relative_delay}")
            if relative_delay < entry["min_reldelay"]:
                entry["min_reldelay"] = relative_delay
            elif relative_delay > entry["max_reldelay"]:
                entry["max_reldelay"] = relative_delay
            entry["avg_reldelay"] += (relative_delay - entry["avg_reldelay"]) / entry["received_count"]
            if delay < entry["min_delay"]:
                entry["min_delay"] = delay
            elif delay > entry["max_delay"]:
                entry["max_delay"] = delay
            entry["avg_delay"] += (delay - entry["avg_delay"]) / entry["received_count"]
            if delay > 1300:
                entry["high_delay_count"] += 1
                log_line(f"delay > 1300us: {delay}")   # move to another thread or interval

        if entry["prev"] is None:
            entry["prev"] = smpCnt
            continue

        expected = (entry["prev"] + 1) % WRAP_VALUE
        #print(f"svID = {svID}  smpCnt = {smpCnt}  expected = {expected} ts = {usec}")

        # future packet → out-of-order
        if (smpCnt - expected) % WRAP_VALUE > 0:
            # packets not received go to awaited
            for i in wrap_range(expected,smpCnt,WRAP_VALUE):
                log_line(str(i) + " late")
                entry["outoforder"] += 1
                awaited.add(i)

        # late or duplicate packet
        elif smpCnt != expected:
            awaited.discard(smpCnt)

        entry["prev"] = smpCnt

        packet_to_assume_lost = smpCnt - WAIT_WINDOW
        if packet_to_assume_lost in awaited:
            awaited.remove(packet_to_assume_lost)
            entry["missed_count"] += 1
            print(f"[{svID}] missed packet {packet_to_assume_lost}, total missed={entry['missed_count']}")

def capture_loop(iface="eth0", snaplen=250, promisc=True, read_timeout_ms=100):
    """Capture packets and put raw payloads into the queue."""
    print(f"[+] Opening interface {iface} for capture...")
    cap = pcapy.open_live(iface, snaplen, int(promisc), read_timeout_ms)
    print("[+] Capture started. Press Ctrl+C to stop.\n")

    try:
        while True:
            header, payload = cap.next()
            if not header:
                continue
            try:
                packet_queue.put_nowait((header,payload))
            except queue.Full:
                print("queue full")
                pass  # drop packet if processing is slower than capture
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user.")

def process_loop():
    """Process packets from the queue, count VLAN and target EtherType packets."""
    vlan_count = 0
    target_count = 0
    total_count = 0

    try:
        while True:
            (header, payload) = packet_queue.get()  # blocking
            sec, usec = header.getts()
            smpCnts = process_pkt(payload)

            if smpCnts:
                update_stats(smpCnts, usec)
            ## Print periodic stats
            #if total_count % 1000 == 0:
            #    now = datetime.now().strftime("%H:%M:%S")
            #    print(f"[{now}] total={total_count:,} vlan={vlan_count:,} target={target_count:,}")

            packet_queue.task_done()
    except KeyboardInterrupt:
        print("\n[!] Processing stopped by user.")
        print(f"Total packets: {total_count}")
        print(f"VLAN packets (0x8100): {vlan_count}")
        print(f"VLAN + EtherType 0x88ba: {target_count}")

if __name__ == "__main__":
    os.sched_setaffinity(0, set(map(int, CPU.split(','))))

    # Start capture thread
    capture_thread = threading.Thread(target=capture_loop, args=(IFACE,), daemon=True)
    capture_thread.start()

    # Start processing thread
    process_thread = threading.Thread(target=process_loop, daemon=True)
    process_thread.start()

    # Keep main thread alive to handle KeyboardInterrupt
    try:
        import time
        while True:
            time.sleep(10)
            lines = []
            log_line("=== Report ===")
            for svID, data in stats.items():
                packets=data['received_count']
                misses=data['missed_count']
                data['received_count'] = 1
                last=data['prev']
                outoforder=data['outoforder']
                delayed=data['high_delay_count']
                minreldelay=round(data['min_reldelay'])
                data['min_reldelay'] = float("inf")
                maxreldelay=round(data['max_reldelay'])
                data['max_reldelay'] = float("-inf")
                avgreldelay=round(data['avg_reldelay'])
                data['avg_reldelay'] = 0
                mindelay=round(data['min_delay'])
                data['min_delay'] = float("inf")
                maxdelay=round(data['max_delay'])
                data['max_delay'] = float("-inf")
                avgdelay=round(data['avg_delay'])
                data['avg_delay'] = 0
                log_line(f"svID={svID} | packets={packets} | misses={misses} | outoforder={outoforder} | delayed={delayed} | mindelay={mindelay} | maxdelay={maxdelay} | avgdelay={avgdelay} | minreldelay={minreldelay} | maxreldelay={maxreldelay} | avgreldelay={avgreldelay}")
                # Prometheus metrics
                lines.append(f'sv_packets_total{{svID="{svID}"}} {packets}')
                lines.append(f'sv_misses_total{{svID="{svID}"}} {misses}')
                lines.append(f'sv_outoforder_total{{svID="{svID}"}} {outoforder}')
                lines.append(f'sv_delayed_total{{svID="{svID}"}} {delayed}')
                lines.append(f'sv_mindelay{{svID="{svID}"}} {mindelay}')
                lines.append(f'sv_maxdelay{{svID="{svID}"}} {maxdelay}')
                lines.append(f'sv_avgdelay{{svID="{svID}"}} {avgdelay}')
                lines.append(f'sv_minreldelay{{svID="{svID}"}} {minreldelay}')
                lines.append(f'sv_maxreldelay{{svID="{svID}"}} {maxreldelay}')
                lines.append(f'sv_avgreldelay{{svID="{svID}"}} {avgreldelay}')
            tmp_file = PROM_FILE + ".tmp"
            with open(tmp_file, "w") as f:
                f.write("\n".join(lines) + "\n")
                os.chown(tmp_file, 65534, 65534)
                os.replace(tmp_file, PROM_FILE)

    except KeyboardInterrupt:
        print("\n[!] Exiting...")

