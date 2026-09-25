# PO: maintainer notes

Test and diagnostic platform for IEC 61850 on a SEAPATH process bus (relays
such as an ABB SSC600 VM and a VMC7 IED). It speaks MMS
(client: reports, controls), GOOSE (publish/subscribe) and Sampled Values
(generate/listen), and wraps all of it in one HTTP service with a web UI.

The protocol code is the **open61850** library (Apache 2.0, standard library
only), on PyPI (https://pypi.org/project/open61850/) and in its own
repository: https://github.com/insatomcat/open61850
(locally `~/dev/open61850`). It was extracted from this repository, with its
history, at 0.1.0. PO depends on a version published on PyPI (`requirements.txt`); its
maintainer notes, including what the IED captures taught about MMS on the
wire, are in that repository's AGENTS.md. Protocol changes go there first,
then PO moves to the new tag.

## Using open61850

PO consumes `open61850.data`, `.ethernet`, `.goose`, `.sv`, `.scl`,
`.capture` and `.mms` (client, reports, RCBs, controls, association).
`open61850-mms HOST domains|rcbs|read|subscribe|operate|association` is the
command line to try things against a live IED.

Adapters kept for the applications: `iec_data.py` re-exports `open61850.data`
under the historical names and holds the JSON mapping (with its goose_cli
quirks); `goose61850.codec` / `.types` re-export the GOOSE codec, and
`goose61850.transport` builds and parses frames with `open61850.ethernet`
(scapy is imported only inside `GoosePublisher.send` / `GooseService._send_one`).
po's MMS subscription service and its commands (`send_command`: one
connection per send, `control.operate`, ctlNum incremented per command,
HTTP 409 with the AddCause on refusal) run on `open61850.mms` (see below).
The SV listener (`svlistener_view`) decodes with `open61850.sv`; decoding
runs on the SV worker of `processbus_capture` (frames are timestamped by the
capture thread before the queue). A process bus with 7 SV streams carries
~16,800 frames/s, and only the selected svID needs samples: a stream
(addresses + APPID, read from the raw header) is decoded in full when new,
when it carries the selected svID, and once per second to refresh the svID
list; its other frames are only counted. On a Xeon Gold server (Python
3.13), one second of that traffic costs 11 % of a core, against 23 % for
the old parser that decoded every frame. Library decode alone: 22 us per
2-ASDU frame there, 9 us on a recent Mac (open61850's
`tools/bench_sv_decode.py`). Malformed frames count as `parse_errors`. Streams with fewer than 8
channels per ASDU are listed but not displayed (as before).
Still on their own code: the diagnostic SV scripts in `svgenerator/`.

## Layout

| Path | What it is |
|------|------------|
| `po_service.py` | Unified `http.server` on port 7050. Routes `/api/{mms,goose,sv,svview,gooselistener,stress}/*`, serves `unified_ui.html`. Starts the SV Listener Flask app on a side port and proxies `/api/svview` to it. |
| `unified_ui.html` | Single-file UI (~5.7k lines, vanilla JS), one tab per module. |
| `iec_data.py` | Adapter over `open61850.data` (historical names) plus the JSON mapping of the HTTP APIs. |
| `processbus_capture.py` | One capture per interface, shared by GOOSE and SV consumers (`ProcessbusCapture.get(iface)`), adaptive kernel filter (GOOSE, SV or both, following the subscribers), per-protocol queues and workers, on `open61850.capture`. |
| `mms/` | MMS client stack and service (see below). Stdlib only. |
| `goose/goose61850/` | GOOSE transport (scapy send, receive through `processbus_capture`, `PacketCapture` as fallback) and streaming service over `open61850.goose`. Has its own `pyproject.toml`. |
| `goose_listener/` | Trip-delay measurement: GOOSE trigger (stNum++, sqNum 0) vs the SV fault start of a linked flow, problem detection, PCAP ring dumps. Documented in its README. |
| `svgenerator/` | SV generation. `sv_service.py` launches one sender process per flow, under `seapath-run` when available: `open61850-sv` (`python -m open61850.sv_publisher`, the Rust engine of `open61850[rt]`) by default, or the C `rt_sender.c` (Linux, AF_PACKET, CLOCK_REALTIME, 4800 smp/s, 2 ASDU per frame, fixed 6I3U dataset) with `PO_SV_SENDER=rt_sender`; both take the same options and send the same samples (FastAPI models + process management, pidfiles in `svgenerator/pids/`, flows survive service restarts). `sv_api.py` adapts it to the unified server. `receiver.py`, `sv_counter3.py`, `sv_receiver_delay.py`, `parse_ref_pkt.py` are standalone diagnostic scripts, each with its own BER parser. |
| `svlistener_view/` | SV capture + phasor display (Flask). Uses svID/smpCnt/seqData (quality ignored), 6I3U or 4I4U, 96-sample DFT at 50 Hz. |
| `stress/` | SSH + `stress-ng` load on host cores, CPU topology from `seapath-alloc`. Not 61850. |

Logging: services call `logging.getLogger(__name__)`; `po_logging.setup()`
(called by `po_service.py` and the standalone service entry points) sends
records to stdout for journalctl and keeps the last 500 lines for the MMS
log panel (`GET /api/mms/logs`, SSE). Level from `--log-level` or
`$PO_LOG_LEVEL` (INFO by default; DEBUG adds one line per HTTP request).
The open61850 library logs nothing. Command-line tools keep `print`.

Imports rely on `sys.path.insert` hacks: `iec_data` and `processbus_capture`
are top-level modules, `goose/` and `goose_listener/` are added to the path by
`po_service.py`. Run things from the repo root.

## MMS service (`mms/mms_service.py`)

One thread per subscription (one IED; `domain` optional, empty means every
logical device). The report control blocks come from the SCL file (`scl`,
read with `open61850.scl`) when its IED matches the domains the IED lists,
else from GetNameList of each domain (grouped by two-digit instance
suffix); a mismatch is logged with both names. `rcb_filter` selects blocks
by shell pattern on their name without instance (`CB_LDPX_*, CB_LDADD_*`);
the older `rcb_list` file still works. `reporting.plan_subscriptions` puts
instances used before first, then `rcb.usable`, data set members and types read from the IED
(`reporting.load_data_set`, SCL labels only as fallback), `rcb.enable` with
po's historical OptFlds and the configured `triggers` / `integrity_ms`.
Reports are decoded on the worker thread; `reporting.report_to_lines` keeps
the historical VictoriaMetrics series (a test compares it with the old
pipeline byte for byte), `reporting.format_report` feeds the SSE logs when
debug is on. Stopping a stream disables its RCBs. Reconnect backoff 5 s to
60 s as before.

## MMS on the wire

See open61850's AGENTS.md (envelope, association, GetNameList paging,
IEDscout captures, VMC7 reservations, control sequence). What matters here:
a VMC7 accepts 5 requests in flight and the ABB SSC600 only 1 (the client
honours it); the VMC7 keeps a BRCB reserved while any association from the
same address lives, so the service releases its blocks on stop (SIGTERM is
handled like Ctrl-C and calls `SubscriptionManager.stop_all`).

## GOOSE as implemented

The codec is `open61850.goose`. `service.py` keeps streams in memory, one sender thread polling
every 10 ms, retransmission interval 10 ms doubling to 2000 ms, `sendp` per
frame. PDUs are built and sqNum advanced under the stream lock, then sent
outside it. Any PATCH of a stream is a state change (`GooseStream.new_state`), and so is reloading a stream at startup or restarting it from the recents:
stNum + 1, sqNum 0, `changed_at` = now, fast retransmission again. `t` and
the timestamps inside `allData` are `changed_at`, so retransmissions differ
only by sqNum.

## Known weak points (verified 2026-09-24)

- The service's default `triggers` are `integrity,gi` (po's historical
  TrgOps `020c`); set `dchg,qchg,...` to get reports on change.
- `iec_data_from_json` turns strings with control chars into `RawData(0x83)`
  (legacy goose_cli compatibility).
- Capture is Linux only (AF_PACKET) and needs root or CAP_NET_RAW. It
  replaced pcapy (unmaintained upstream) after a side-by-side check on a
  real process bus, each in its own process, 10 s: the same 152,633 frames
  byte for byte (tags included), timestamps within 1.2 us, no drops; CPU
  2.1 us/frame against 1.4 us for pcapy. A first version with one
  `recvmsg` per frame cost 30 us/frame: keep the ring. With libpcap, the
  `vlan` keyword shifted the offsets of every later test (across `or` too)
  and let only the host's own SV streams through on a NIC that strips tags;
  the ethertype filter of `open61850.capture` checks both positions instead.
- SV: `rt_sender` has its rate, ASDU count and dataset as compile-time
  constants and quality always 0; `open61850-sv` takes them as options. On
  the process bus, on an isolated core with SCHED_FIFO 80, both send every
  sample 4.3 us (median) after its nominal time, p99 about 5 us. Listeners
  assume 4800 smp/s and 50 Hz.
- `scl_parser` keys data sets as `<ied>/LLN0$DS`, `<ied>_1<ld>/...` (VMC7
  naming) but never as the standard `<ied><ld>/LLN0$DS`. SDOs (`A.phsA`)
  are not resolved to components. The service reads labels from the IED
  and uses these only as a fallback.
- The `svgenerator/` diagnostic scripts still carry their own BER readers.
- Three HTTP stacks coexist: `http.server` (unified, MMS, GOOSE), FastAPI
  (SV standalone, models reused by the unified API), Flask (SV listener).

## Tests

`python3 -m pytest` from the repo root (config in `pyproject.toml`, CI in
`.github/workflows/tests.yml` on Python 3.10 and 3.13). The suite is
characterization: golden bytes of what the IEDs accept today, round trips,
a fake IED on a socketpair for the MMS client, and a byte-for-byte check of
`rt_sender --dump` against a Python mirror of its layout (Linux only; on the
Mac run it with `docker run --rm -v "$PWD":/src:ro -w /src python:3.10-slim`
plus `apt-get install gcc libc6-dev` and `pip install pytest`).
`tests/conftest.py` sets up the `sys.path` of `po_service.py` and stubs scapy
when absent.

The library has its own tests. `tests/fake_ied.py` is a copy of its fake
MMS server (socketpair) for the tests of PO's MMS service;
`tests/test_processbus_capture.py` runs the shared capture on `lo` (Linux,
root). open61850 must be installed (`pip install -r requirements.txt`).

Every known bug above has a `xfail(strict=True)` test stating the correct
behaviour. Fixing one makes it XPASS and fail: remove the marker in the same
change. Golden bytes changing means the wire format changed: check it
against a capture before updating them.

## Captures

`open61850-mms HOST[:PORT] association|domains|rcbs [--status]|read|dataset|subscribe|operate`
(from open61850) exercises an IED (works through an SSH tunnel on any local
port). `subscribe` picks a free instance, enables it, prints decoded reports
and disables it on Ctrl-C.

`tools/pcap_mms.py capture.pcapng [--hex] [--service getNameList]` lists the
MMS PDUs of a pcap/pcapng (TCP, TPKT and COTP reassembled). Captures stay out
of git (`*.pcap`, `*.pcapng` ignored); only the few bytes a test needs go to
`tests/data/` (e.g. `iedscout_getnamelist.json`).

## Working here

- Python 3.10+ (dev machine has 3.14), with open61850 installed
  (`pip install -r requirements.txt`, from PyPI). macOS dev box has no scapy,
  Docker is available for Linux-only checks (`rt_sender`, raw sockets on `lo`;
  on `lo` an AF_PACKET socket sees each frame twice, skip `PACKET_OUTGOING`).
- Quick checks: `python3 -m py_compile <file>`; codec round trips with
  `python3 -c` from the repo root.
- All code, comments, messages and docs in English. The only French left is
  the `fr` table of the web UI (`I18N` in `unified_ui.html`), which is a
  translation; the default texts of the page are the English ones. Commit messages in English with the DCO `Signed-off-by` trailer.
