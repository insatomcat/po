# GOOSE Listener: trip delay measurement

Listens to the GOOSE messages of the process bus, detects **trips** (relay state changes), measures the **net delay Δ** between the reception of the GOOSE and the SV sample that starts the fault, and reports **anomalies** (delay above threshold, missing trips).

It runs inside `po_service` (GOOSE Listener tab of `unified_ui.html`) and on the command line through `goose/examples/listen_goose.py`.

## What it is for

On a protection relay such as an SSC600, each **fault** of the simulated SV stream makes it send a trip GOOSE some 24 ms after the SV sample where the fault starts. The listener checks that this delay stays within a margin (e.g. < 40 ms) and that the trips come at the **expected cycle** of the linked SV stream (e.g. every 4 s). It gathers capture, measurement and alerts for operational diagnosis; it does not replace a full network analysis.

## Measurement

### Reference time

Δ is computed from the **kernel receive timestamp** of the frame (AF_PACKET), taken before any queue, so a busy Python worker does not shift it.

### Formula

Each analysed stream is **linked to an SV stream** (`svID`):

- **automatically** when exactly one svID carries the same `DEPn` token (exact digits: `DEP5`, `DEP6` and `DEP10` differ) as the `gocbRef` (or else the `goID`);
- **by hand** otherwise (svID list), including when 0 or several SV streams share that `DEPn`.

The listener reads `fault_cycle_s`, `fault_smpcnt` and `fault_offset_s` of that SV flow **when the analysis starts** and keeps them for the session; a change on the SV generator side applies at the next start.

```
phase     = offset_s + smpCnt / 4800
t_ref     = the multiple of the cycle closest to ts_rx, shifted by phase
raw Δ     = (ts_rx - t_ref) × 1000   (ms)
net Δ     = raw Δ - delay_ms
```

`smpCnt 0` is on the second boundary on the generator side. Without an SV link, Δ falls back to the second (`floor(ts_rx)`) and missing trips are not detected. `delay_ms` is set per analysed stream (protection time delay to subtract).

Typical values:

| Event | Fraction of the second | Net Δ (~) |
|-------|------------------------|-----------|
| Trip (sqNum=0) | `.023` | ~24 ms |
| Reset | `.136` | ~136 ms (expected, not a trip anomaly) |
| Retransmission sqNum=4 alone | `.131` | ~131 ms: sqNum ≠ 0, frames were lost by the capture |

## Trip detection

A GOOSE **trip** is detected when `stNum` increases and `sqNum == 0` (the first frame of the IEC 61850 burst).

**Tolerant mode**: the capture sometimes loses sqNum=0 (the 0 to 3 burst lasts a few ms). The service and `--problem-diag` then take the **first frame seen** of a new stNum. The Problems panel shows the sqNum used: when it is not 0, the Δ cannot be trusted.

**Classification** (`trigger_classify.py`) compares `allData` with the previous snapshot of the same stream:

| `allData` transition | Kind |
|----------------------|------|
| bool false → true (or integer 0 → non-zero) | `trip` |
| bool true → false (or integer non-zero → 0) | `reset` |
| First event | `initial` |
| Both directions | `mixed` |
| Nothing telling | `unknown` |

Δ > threshold alerts and missing-trip detection only concern `trip` events.

## Layout

```
goose_listener/
├── goose_listener_service.py   # scan, analysis, histogram, problems
├── goose_listener_api.py       # REST routes for po_service
├── goose_ring_pcap.py          # sliding GOOSE buffer and PCAP export
├── trigger_classify.py         # trip / reset classification
├── dumps/                      # automatic PCAPs (4 s before each problem, ignored by git)
└── analysis_state.json         # (generated) mappings, analysis restarted after a service restart
```

GOOSE frames come from the shared capture (`processbus_capture.py`) through `goose61850.transport.GooseSubscriber`, as raw bytes in a queue decoded by a worker thread. During an analysis, the last 4 seconds of GOOSE traffic stay in memory; each new problem writes a PCAP-NG file to `goose_listener/dumps/`.

| Manager mode | Behaviour |
|--------------|-----------|
| `idle` | No processing (the capture may stop) |
| `scan` | Counts frames per `(gocbRef, goID)` for N seconds |
| `analyze` | Measures Δ and detects problems on the selected streams |

## Running it

The listener is on when `po_service` gets a capture interface:

```bash
sudo python3 po_service.py --svview-interface eth1
```

(or `SVVIEW_INTERFACE` in the systemd unit). Without it the tab says "not configured" and the API answers 503.

## Web UI (GOOSE Listener tab)

- **Scan**: listens to every GOOSE for a while (5 s by default) and lists the streams; filter by gocbRef, goID or APPID; add the selection to the analysis.
- **Analysis**: targets `(gocbRef, goID, svID, delay_ms)`, svID found through `DEPn` or chosen by hand; display filter **trips only** or **all events**; start / stop.
- **Problems**: threshold Δ (ms, default 40; alert when the net Δ exceeds it). Kinds: `delay_exceeded` (sqNum column: 0 is fine, anything else means an incomplete capture) and `missing` (a gap in the trip cycle, with the GOOSE received between the two trips). The last 50 are shown; the session list is kept independently of the 10,000-event buffer. **Download (.txt)** exports all of them, **Clear** empties the list and its PCAPs (histogram and events stay), **Simulate a delay** injects a fake trip above the threshold on a random analysed stream, without sending anything on the bus.
- **Histogram and last events**: the API returns the raw Δ per stream (`histogram_series`); the browser bins them by 1 ms. The last 50 events are shown; **Download (.txt)** exports the up to 10,000 in memory.

### Capture health (`GET /status`)

```json
"capture": {
  "queue_size": 0,
  "drops": 0,
  "drops_since_analysis_start": 0,
  "packets": 1234,
  "reliable": true,
  "invalid_reason": null,
  "kernel_drop_delta": 0,
  "nic": { "rx_missed_errors": 0 },
  "nic_delta_since_analysis_start": {}
}
```

- `queue_size` > 100: processing lags behind (measurement not reliable).
- `drops_since_analysis_start` > 0: GOOSE frames lost (Python queue full).
- `kernel_drop_delta` > 0: frames the capture socket could not take.
- `nic_delta_since_analysis_start.rx_missed_errors` > 0: losses in the NIC or kernel, before the socket.
- `reliable: false`: a `capture_unreliable` problem; the Δ values cannot be trusted.
- After a (re)start, loss tracking waits ~2 s for the socket to warm up.

Each event also carries `processing_lag_ms` (processing time minus kernel receive time).

## Memory and persistence

| Structure | Size | Kept |
|-----------|------|------|
| `_events` | 10,000 events (`deque`) | RAM; oldest dropped |
| `_problems_ram` | session list, unbounded | RAM, filled on detection |
| `_hist_*_buckets` | counters per Δ bin | whole session |
| `analysis_state.json` | targets (with svID), filter, threshold | disk |

- A **new analysis** clears events, histogram and problems.
- **Stop** keeps the mappings, and the analysis does not restart with the service.
- A **service restart** loses the history but restores the mappings, and restarts the analysis if it was running.

## REST API (`/api/gooselistener`)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/status` | Scan, analysis and capture state |
| POST / GET | `/scan` | Start a scan `{"duration_s": 5}` / its state |
| POST | `/analysis/start` | Start the analysis (body below) |
| POST | `/analysis/targets` | Save the mappings without starting |
| POST | `/analysis/stop` | Stop |
| POST | `/analysis/reset` | Clear events, histogram and problems (the analysis goes on) |
| POST | `/analysis/problems/clear` | Clear only the problems and their PCAPs |
| GET | `/analysis` | Events, histogram, problems |
| POST | `/analysis/filter` | `{"event_filter": "trips_only" \| "all"}` |
| POST | `/analysis/problems` | `{"threshold_ms": 40}` |
| POST | `/analysis/demo-delay` | Inject a demo `delay_exceeded` (nothing sent on the bus) |
| GET | `/analysis/events/export`, `/analysis/problems/export` | Text exports |
| GET | `/analysis/dumps`, `/analysis/dumps/{id}/pcap` | Automatic PCAPs |

The older filter names `declenchements_only` and `defauts_only` are still accepted.

```bash
curl -s -X POST http://127.0.0.1:7050/api/gooselistener/analysis/start \
  -H 'Content-Type: application/json' \
  -d '{
    "event_filter": "trips_only",
    "targets": [
      {"gocb_ref": "IED01LD0/LLN0$GO$CB_LDPX_GSI_1", "go_id": "LDPX_GSI_1",
       "svid": "IED01_SV1", "svid_manual": true, "delay_ms": 0}
    ]
  }'
```

## Command line (`goose/examples/listen_goose.py`)

```bash
# Display filters only (--sqnum-zero, --bool-true)
sudo python3 goose/examples/listen_goose.py eth1 --app-id 0x150A --go-id LDPX_GSI_1 --sqnum-zero --bool-true
# Delays
sudo python3 goose/examples/listen_goose.py eth1 --app-id 0x150A --go-id LDPX_GSI_1 --measure-delay --triggers-only
# Silent diagnosis: short alert on Δ > threshold, detailed report on missing trips
sudo python3 goose/examples/listen_goose.py eth1 --app-id 0x150A --go-id LDPX_GSI_1 \
  --problem-diag --problem-cycle 4 --problem-threshold 40
# sqNum burst audit: is sqNum=0 received first for each stNum?
sudo python3 goose/examples/listen_goose.py eth1 --app-id 0x150A --go-id LDPX_GSI_1 --measure-delay --audit-triggers
# While the UI analysis runs: read its problems instead of capturing again
python3 goose/examples/listen_goose.py eth1 --from-api http://127.0.0.1:7050 --problem-diag
```

`--problem-cycle` is for the command line only; the service takes the cycle of the linked SV flow.

## Capture: practice and troubleshooting

`processbus_capture.py` opens **one AF_PACKET socket per interface** with a kernel filter that follows the subscribers:

| Active subscribers | Kernel filter |
|--------------------|---------------|
| GOOSE only | `0x88b8` (the thousands of SV frames per second stay in the kernel) |
| SV only | `0x88ba` |
| GOOSE and SV | both |

The session is marked unreliable on socket drops (`kernel_drop`) or Python queue drops, not on the interface `rx_dropped` counter (global to the bus, it can grow while the GOOSE capture is fine). Avoid a second capture next to the service (heavy `tcpdump`, a direct `listen_goose`); use `--from-api`.

The PCAP-NG dumps have absolute epoch timestamps. Wireshark shows the time relative to the first frame by default: use View, Time Display Format, Date and Time of Day to match the problem time of the UI. Each file carries a comment (capture file properties) and a `{id}.meta.json` sidecar with `problem_time_local` and the capture window.

**Frames lost in the burst (sqNum 0 to 3)**: only sqNum=4 shows (~131 ms), or whole cycles are missing. Compare with the kernel:

```bash
tcpdump -i eth1 -nn -t 'ether proto 0x88b8 and ether[14:2]=0x150a'
```

If `tcpdump` sees sqNum 0 to 4 and PO does not, look at PO (APPID filter, no double capture); if `tcpdump` also sees only sqNum=4, the interface or kernel buffers are overloaded.

**Trip cycle and GOOSE interval**: a stream may send a GOOSE (trip then reset) every ~2 s while trips come every ~4 s; the cycle is that of the trips (`fault_cycle_s` of the SV flow).

**A Δ of ~130 ms** usually means the measurement used sqNum=4: check the sqNum column of the Problems panel.

## Requirements

- Linux, root or `CAP_NET_RAW` for the capture (`iec61850.capture`)
- `goose61850` (in `goose/`) and `iec_data.py` (repository root)
- The same interface as the SV Listener (`--svview-interface`)

## License

Copyright 2026 Florent Carli

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for the full text.
