# PO: maintainer notes

Test and diagnostic platform for IEC 61850 on a SEAPATH process bus (relays
such as an ABB SSC600 VM and a VMC7 IED). It speaks MMS
(client: reports, controls), GOOSE (publish/subscribe) and Sampled Values
(generate/listen), and wraps all of it in one HTTP service with a web UI.

Long-term goal: extract an Apache-2.0 IEC 61850 library from this code (the
only open-source alternative, libiec61850, is GPL). The code works on the
target IEDs but was grown from Wireshark captures, so a lot of it is replay
and byte heuristics. Read "Known weak points" before touching protocol code.

## The library: `iec61850/`

Pure stdlib, no I/O, all English. New protocol code goes here; the po
applications consume it. Scope decided with Florent: client side only at
first, kept simple; the package lives in this repo for now.

| Module | Content |
|--------|---------|
| `ber.py` | X.690 primitives: tags as the int of their identifier octets (`0x83`, `0xBF48`), definite lengths, minimal INTEGER, lenient unsigned decode, `iter_tlvs`, `expect_tlv`, `BerError`. |
| `data.py` | MMS `Data` CHOICE (`BoolData` ... `RawData`), `encode_data` / `decode_data*`, UtcTime and binary-time helpers. `TimestampData.quality` keeps the TimeQuality octet, `FloatData.double` the width; float32 decodes to its shortest decimal. Unsigned values get a leading `00` when the high bit is set. |
| `ethernet.py` | Ethernet II / 802.1Q + APPID header: `parse_frame`, `build_frame`, `EthernetFrame`. |
| `goose.py` | `GoosePDU` (with `time_quality`), PDU and frame encode/decode, `GooseDecodeError` on missing mandatory fields. |
| `sv.py` | `SvPDU` / `SvAsdu` with every 9-2 / 61869-9 field (datSet, refrTm, smpRate, smpMod, gmIdentity), PDU and frame codec, INT32+quality sample helpers. |
| `mms/transport.py` | TPKT + COTP class 0: `IsoConnection` (CR/CC with the same CR bytes po always sent, segmentation on send, EOT reassembly on receive, DR = closed). |
| `mms/pdu.py` | Session/presentation envelope (`wrap`/`unwrap`), `ObjectName`, Read / Write / GetNameList / GetNamedVariableListAttributes requests and responses, confirmed-Error, Reject, informationReport. Requests match IEDscout captures. The association is still the replayed `INITIATE_REQUEST`. |
| `mms/client.py` | `MmsClient`: one receive thread, responses matched by invokeID (several requests in flight, from any thread), informationReports to a callback on the receive thread, typed errors (`DataAccessError`, `ServiceError`, `MmsReject`, `MmsTimeout`, `MmsConnectionError`). |
| `mms/report.py` | IEC 61850 report decoding driven by the report's own OptFlds and inclusion bitstring (data references, ConfRev, segmentation, reason codes); `OptFlds` / `TrgOps` / `ReasonCode` flag classes. |
| `mms/types.py` | GetVariableAccessAttributes type descriptions (`StructureType`, `ArrayType`, `PrimitiveType`) and `label()`, which names every leaf of a value after its type (`cVal.mag.f`). |
| `quality.py` | `Quality` (7-3, 13-bit bit string) and `TimeQuality` (UtcTime octet) in readable form. |
| `capture.py` | Linux capture without libpcap: `PacketCapture` reads an AF_PACKET TPACKET_V3 ring (mmap, one poll per block), classic BPF on ethertypes that works with or without a stripped tag, 802.1Q tag put back from the ring header, kernel timestamps, promiscuous membership, `PACKET_STATISTICS` drops. |
| `mms/control.py` | `operate()`: ctlModel read from `CF`, then Oper (direct), SBO read + Oper, or SBOw + Oper; enhanced security waits for the CommandTermination. Refusals raise `ControlError` with the `LastApplError` (AddCause names per 7-2 Ed2). `Origin` defaults to station-control (orCat 2), what po wants: it does substation control, not telecontrol. Report listeners (`MmsClient.add_report_listener`) carry the LastApplError / termination to the waiting call. |
| `mms/rcb.py` | RCB status (RptEna, Resv/ResvTms, Owner, RptID, DatSet), `find_free` among instances (`group_instances` strips the trailing number), `enable` reserves a BRCB with ResvTms first (the VMC7 refuses configuration writes otherwise), then typed, checked writes in po's order; `disable`. |

Adapters kept for the applications: `iec_data.py` re-exports `iec61850.data`
under the historical names and holds the JSON mapping (with its goose_cli
quirks); `goose61850.codec` / `.types` re-export the GOOSE codec, and
`goose61850.transport` builds and parses frames with `iec61850.ethernet`
(scapy is imported only inside `GoosePublisher.send` / `GooseService._send_one`).
po's MMS subscription service and its commands (`send_command`: one
connection per send, `control.operate`, ctlNum incremented per command,
HTTP 409 with the AddCause on refusal) run on `iec61850.mms` (see below).
The SV listener (`svlistener_view`) decodes with `iec61850.sv`; decoding
runs on the SV worker of `processbus_capture` (frames are timestamped by the
capture thread before the queue). A process bus with 7 SV streams carries
~16,800 frames/s, and only the selected svID needs samples: a stream
(addresses + APPID, read from the raw header) is decoded in full when new,
when it carries the selected svID, and once per second to refresh the svID
list; its other frames are only counted. On a Xeon Gold server (Python
3.13), one second of that traffic costs 11 % of a core, against 23 % for
the old parser that decoded every frame. Library decode alone: 22 us per
2-ASDU frame there, 9 us on a recent Mac (`tools/bench_sv_decode.py`);
`ber.decode_tlv` and `sv._asdu_fields` have fast paths for short tags and
lengths. Malformed frames count as `parse_errors`. Streams with fewer than 8
channels per ASDU are listed but not displayed (as before).
Still on their own code: the legacy CLIs `mms/test_client_reports.py` and
`mms/discover_reports.py`, and the diagnostic SV scripts in `svgenerator/`.

## Layout

| Path | What it is |
|------|------------|
| `po_service.py` | Unified `http.server` on port 7050. Routes `/api/{mms,goose,sv,svview,gooselistener,stress}/*`, serves `unified_ui.html`. Starts the SV Listener Flask app on a side port and proxies `/api/svview` to it. |
| `unified_ui.html` | Single-file UI (~5.7k lines, vanilla JS), one tab per module. |
| `iec_data.py` | Adapter over `iec61850.data` (historical names) plus the JSON mapping of the HTTP APIs. |
| `processbus_capture.py` | One capture per interface, shared by GOOSE and SV consumers (`ProcessbusCapture.get(iface)`), adaptive filter, per-protocol queues and workers. Backend `pcapy` (default) or `afpacket` (`PO_CAPTURE_BACKEND=afpacket`). |
| `mms/` | MMS client stack and service (see below). Stdlib only. |
| `goose/goose61850/` | GOOSE transport (scapy send, pcapy receive) and streaming service over `iec61850.goose`. Has its own `pyproject.toml`. |
| `goose_listener/` | Trip-delay measurement: GOOSE trigger (stNum++, sqNum 0) vs the SV fault start of a linked flow, problem detection, PCAP ring dumps. Documented in its README. |
| `svgenerator/` | SV generation. `rt_sender.c` (Linux, AF_PACKET, CLOCK_REALTIME, 4800 smp/s, 2 ASDU per frame, fixed 6I3U dataset) launched as a subprocess by `sv_service.py` (FastAPI models + process management, pidfiles in `svgenerator/pids/`, flows survive service restarts). `sv_api.py` adapts it to the unified server. `receiver.py`, `sv_counter3.py`, `sv_receiver_delay.py`, `parse_ref_pkt.py` are standalone diagnostic scripts, each with its own BER parser. |
| `svlistener_view/` | SV capture + phasor display (Flask). Uses svID/smpCnt/seqData (quality ignored), 6I3U or 4I4U, 96-sample DFT at 50 Hz. |
| `stress/` | SSH + `stress-ng` load on host cores, CPU topology from `seapath-alloc`. Not 61850. |

Imports rely on `sys.path.insert` hacks: `iec_data` and `processbus_capture`
are top-level modules, `goose/` and `goose_listener/` are added to the path by
`po_service.py`. Run things from the repo root.

## MMS service (`mms/mms_service.py`)

One thread per subscription: `MmsClient.connect`, GetNameList of the domain,
`reporting.plan_subscriptions` (every RCB group, or the `rcb_list` entries; a
trailing instance number is the preferred instance, instances used before
come first), `rcb.find_free`, data set members and types read from the IED
(`reporting.load_data_set`, SCL labels only as fallback), `rcb.enable` with
po's historical OptFlds and the configured `triggers` / `integrity_ms`.
Reports are decoded on the worker thread; `reporting.report_to_lines` keeps
the historical VictoriaMetrics series (a test compares it with the old
pipeline byte for byte), `reporting.format_report` feeds the SSE logs when
debug is on. Stopping a stream disables its RCBs. Reconnect backoff 5 s to
60 s as before.

## Legacy MMS stack (`mms/`, still used by controls and old CLIs)

Layers: `tpkt.py` (RFC 1006) -> `cotp.py` (class 0, CR/CC, DT with fixed
`02 F0 80`) -> `asn1_codec.py` (everything above COTP) -> `mms_reports_client.py`
(blocking socket client) -> `mms_service.py` (one thread per subscription,
reconnect with backoff 5 s to 60 s, JSON persistence).

Every confirmed request is built as:

```
01 00 01 00                 Session: Give-Tokens + Data-Transfer SPDUs (fixed)
61 L  30 L                  Presentation: fully-encoded-data, PDV-list
      02 01 03              presentation-context-identifier = 3 (MMS context)
      a0 L                  single-ASN1-type
         a0 L               MMS confirmed-RequestPDU
            02 02 xx xx     invokeID
            a4|a5|a1 ...    read | write | getNameList
```

The code comments call `02 01 03` "MMS version"; it is the presentation
context id. There is no real Session/Presentation/ACSE layer: the association
(`encode_mms_initiate`) is a hex replay of one capture and the Initiate
response is not decoded.

Reports: `decode_mms_pdu` walks `unconfirmed-PDU / informationReport`, decodes
`listOfAccessResult` with `iec_data`, then assumes a fixed header layout
(0 RptID, 1 OptFlds, 2 SeqNum, 3 TimeOfEntry, 4 DatSet, 5 BufOvfl, 6 EntryID,
7 Inclusion, 8+ values then reason codes). `mms_report_processing.py` formats
and labels entries using SCL data (`scl_parser.py`) through module-level
global dicts, and pushes to VictoriaMetrics (`victoriametrics_push.py`).

GetNameList follows ISO 9506 and matches IEDscout byte for byte (checked on
a capture): `a1 { a0 { 80 01 <class> } a1 { 80 00 | 81 <domain> } [82 <continueAfter>] }`.
`MMSReportsClient.get_all_names` pages with continueAfter (the VMC7 answers
100 names per page), and `discover_reports` keeps only `<LN>$BR|RP$<name>`
(68 RCBs on the VMC7, 1088 names if attributes are counted).
`cotp_recv_data` joins DT TPDUs until the EOT bit: responses above ~1 KB
arrive in several segments.

What the VMC7 capture taught (IEDscout, 2026-09-24):
- IEDscout pipelines requests (several outstanding), so a real client must
  match responses by invokeID.
- A confirmed-ErrorPDU carries its invokeID as `80 ..` ([0] IMPLICIT), where
  requests and responses use `02 ..`.
- IEDscout's own Initiate is 204 bytes (po replays a 180-byte one); both
  are accepted.

What the second capture taught (IEDscout on the VMC7, 2026-09-24, fixtures
in `tests/data/iedscout_reports_control.json`):
- IEDscout enables a BRCB with RptEna=FALSE, a read of the whole block,
  ResvTms=42, RptEna=TRUE: it keeps the IED's TrgOps/OptFlds (OptFlds 7a00,
  no EntryID) and does not purge, so ~500 buffered reports arrive at once.
- Data-change reports include 1 to 3 of 19 members: partial inclusion is the
  normal case once dchg/qchg are enabled.
- Control is direct-with-enhanced-security: one Oper write per command
  (ctlVal TRUE = close, FALSE = open, orCat 2, ctlNum 0, Check c0), write
  response in ~2 ms, then a CommandTermination (informationReport on
  `...$CO$Pos$Oper` echoing the Oper) 60 to 90 ms later. po's second
  "step3" Oper for closing is not needed.

RCB activation (`enable_reporting`): one GetRCBValues, then eight separate
writes (ResvTms, IntgPd, TrgOps=`020c`, OptFlds=`067b00`, PurgeBuf,
EntryID=0, RptEna, GI). Write responses are not checked.

Controls used to replay an IEDscout Oper template (`mms_commands_codec.py`,
removed): the code took ctlVal for ctlNum and Check for ctlVal, sent orCat 3,
and added a hardcoded second "step3" Oper for closing. `iec61850.mms.control`
replaces it; BOOLEAN TRUE now goes out as `ff` (DER) where IEDscout sends
`01`, and the VMC7 accepts both (RCB writes already use `ff`).

## GOOSE as implemented

The codec is `iec61850.goose`. `service.py` keeps streams in memory, one sender thread polling
every 10 ms, retransmission interval 10 ms doubling to 2000 ms, `sendp` per
frame. PDUs are built and sqNum advanced under the stream lock, then sent
outside it. Any PATCH of a stream is a state change (`GooseStream.new_state`), and so is reloading a stream at startup or restarting it from the recents:
stNum + 1, sqNum 0, `changed_at` = now, fast retransmission again. `t` and
the timestamps inside `allData` are `changed_at`, so retransmissions differ
only by sqNum.

## Known weak points (verified 2026-09-24)

- InvokeID is a module global shared by every client thread; responses are
  never matched by invokeID, `_recv_until_response` takes the next non-report
  PDU. `is_read_response_success` searches for byte `a4` anywhere.
- Report header decoding ignores OptFlds and the inclusion bitstring; it only
  works with the OptFlds the code itself writes and without segmentation.
- Legacy RCB settings: `DEFAULT_TRG_OPS = 020c` is integrity + GI only (the
  comment claims data-change and quality-change). The service keeps it as
  the default `triggers` (`integrity,gi`); set `dchg,qchg,...` to get
  reports on change. The legacy VictoriaMetrics pipeline also mislabels
  members when the inclusion bitstring skips some; the new one does not.
- RCB writes: `_encode_mms_value_unsigned` uses tag `0x85` (integer) below 256
  and `0x86` (unsigned) above, so `IntgPd` < 256 ms would go out as an integer.
- `iec_data_from_json` turns strings with control chars into `RawData(0x83)`
  (legacy goose_cli compatibility).
- pcapy is unmaintained upstream. `iec61850.capture` replaces it in
  `processbus_capture` (opt-in for now). Checked side by side on a real
  process bus, each backend in its own process, 10 s: the same 152,633 frames
  byte for byte (tags included), timestamps within 1.2 us, no drops; CPU
  2.1 us/frame against 1.4 us for pcapy (`tools/capture_compare.py`). A first
  version with one `recvmsg` per frame cost 30 us/frame: keep the ring.
  Still on pcapy: `goose61850.transport.GooseSubscriber`, the SV listener's
  dedicated mode, the `svgenerator/` scripts.
- libpcap's `vlan` keyword shifts the offsets of every later test, across
  `or` too. `PROCESSBUS_BPF` used to be `(A) or (vlan and A) or (B) or (vlan
  and B)` and, with a NIC that strips tags, let through only the SV streams
  sent by the host itself (their tag stays inline); `vlan` now appears once, last. A test guards it.
- SV: rate, ASDU count and dataset are compile-time constants in
  `rt_sender.c`; quality is always 0; no smpMod/refrTm/gmIdentity. Listeners
  assume 4800 smp/s and 50 Hz.
- `scl_parser` keys data sets as `<ied>/LLN0$DS`, `<ied>_1<ld>/...` (VMC7
  naming) but never as the standard `<ied><ld>/LLN0$DS`; reports still get
  labels through the suffix fallback in `mms_report_processing`. SDOs
  (`A.phsA`) are not resolved to components.
- The legacy MMS stack and the `svgenerator/` diagnostic scripts still carry their own BER readers.
- IED-specific defaults are hardcoded in the legacy CLIs, READMEs and UI
  placeholders (an IED IP and domain, RCB lists, `_DQPO`/`_CYPO` suffix
  normalisation).
- No `logging` (prints, plus a stdout tee for SSE).
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
and pcapy when absent.

`tests/test_lib_*.py` are unit tests of `iec61850/`, including a check that
the library imports without scapy, pcapy, FastAPI or Flask.

Every known bug above has a `xfail(strict=True)` test stating the correct
behaviour. Fixing one makes it XPASS and fail: remove the marker in the same
change. Golden bytes changing means the wire format changed: check it
against a capture before updating them.

## Captures

`tools/mms_client.py HOST[:PORT] domains|rcbs [--status]|read|dataset|subscribe|operate`
exercises `iec61850.mms` against a live IED (works through an SSH tunnel on
any local port). `subscribe` picks a free instance, enables it, prints decoded
reports and disables it on Ctrl-C.

`tools/pcap_mms.py capture.pcapng [--hex] [--service getNameList]` lists the
MMS PDUs of a pcap/pcapng (TCP, TPKT and COTP reassembled). Captures stay out
of git (`*.pcap`, `*.pcapng` ignored); only the few bytes a test needs go to
`tests/data/` (e.g. `iedscout_getnamelist.json`).

## Working here

- Python 3.10+ (dev machine has 3.14). macOS dev box has no scapy/pcapy,
  Docker is available for Linux-only checks (`rt_sender`, raw sockets on `lo`;
  on `lo` an AF_PACKET socket sees each frame twice, skip `PACKET_OUTGOING`).
- Quick checks: `python3 -m py_compile <file>`; codec round trips with
  `python3 -c` from the repo root.
- All code in English. Older modules are still French and get translated
  when they are refactored. Commit messages in English with the DCO `Signed-off-by` trailer.
