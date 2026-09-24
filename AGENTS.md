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

Adapters kept for the applications: `iec_data.py` re-exports `iec61850.data`
under the historical names and holds the JSON mapping (with its goose_cli
quirks); `goose61850.codec` / `.types` re-export the GOOSE codec, and
`goose61850.transport` builds and parses frames with `iec61850.ethernet`
(scapy is imported only inside `GoosePublisher.send` / `GooseService._send_one`).
Still on their own parsers: the MMS stack (`mms/asn1_codec.py`) and the SV
listeners. The SV listener runs per packet at 2400+ frames/s, so switch it to
`iec61850.sv` only after measuring the cost.

## Layout

| Path | What it is |
|------|------------|
| `po_service.py` | Unified `http.server` on port 7050. Routes `/api/{mms,goose,sv,svview,gooselistener,stress}/*`, serves `unified_ui.html`. Starts the SV Listener Flask app on a side port and proxies `/api/svview` to it. |
| `unified_ui.html` | Single-file UI (~5.7k lines, vanilla JS), one tab per module. |
| `iec_data.py` | Adapter over `iec61850.data` (historical names) plus the JSON mapping of the HTTP APIs. |
| `processbus_capture.py` | One pcapy socket per interface, shared by GOOSE and SV consumers (`ProcessbusCapture.get(iface)`), adaptive BPF, per-protocol queues and workers. |
| `mms/` | MMS client stack and service (see below). Stdlib only. |
| `goose/goose61850/` | GOOSE transport (scapy send, pcapy receive) and streaming service over `iec61850.goose`. Has its own `pyproject.toml`. |
| `goose_listener/` | Trip-delay measurement: GOOSE trigger (stNum++, sqNum 0) vs the SV fault start of a linked flow, problem detection, PCAP ring dumps. Documented in its README. |
| `svgenerator/` | SV generation. `rt_sender.c` (Linux, AF_PACKET, CLOCK_REALTIME, 4800 smp/s, 2 ASDU per frame, fixed 6I3U dataset) launched as a subprocess by `sv_service.py` (FastAPI models + process management, pidfiles in `svgenerator/pids/`, flows survive service restarts). `sv_api.py` adapts it to the unified server. `receiver.py`, `sv_counter3.py`, `sv_receiver_delay.py`, `parse_ref_pkt.py` are standalone diagnostic scripts, each with its own BER parser. |
| `svlistener_view/` | SV capture + phasor display (Flask). Parses svID/smpCnt/seqData only, 6I3U or 4I4U, 96-sample DFT at 50 Hz. |
| `stress/` | SSH + `stress-ng` load on host cores, CPU topology from `seapath-alloc`. Not 61850. |

Imports rely on `sys.path.insert` hacks: `iec_data` and `processbus_capture`
are top-level modules, `goose/` and `goose_listener/` are added to the path by
`po_service.py`. Run things from the repo root.

## MMS stack as implemented

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

RCB activation (`enable_reporting`): one GetRCBValues, then eight separate
writes (ResvTms, IntgPd, TrgOps=`020c`, OptFlds=`067b00`, PurgeBuf,
EntryID=0, RptEna, GI). Write responses are not checked.

Controls (`mms_commands_codec.py`, `SubscriptionManager.send_command`): an
`Oper` write built from a captured IEDscout value template. Decoded, the
template is `{ctlVal BOOLEAN, origin{orCat=3, orIdent=13d5c007}, ctlNum=0, T,
Test=false, Check=bitstring c0/6}`. The code names are wrong:
`_set_first_ctl_num_inplace` patches the first `83 01` which is **ctlVal**
(false = open, true = close), and what the code calls "ctlVal 0x06C0" is the
**Check** field. The real ctlNum is never incremented. "Close" sends a second
Oper from a full hardcoded PDU (`encode_pos_oper_execute_step3`) that only
works for the one breaker it was captured on. No SBO. Command results are
found by searching bytes (`b"LastApplError"`, `85 01 xx`).

## GOOSE as implemented

The codec is `iec61850.goose`. `service.py` keeps streams in memory, one sender thread polling
every 10 ms, retransmission interval 10 ms doubling to 2000 ms, `sendp` per
frame. Any PATCH of a stream bumps stNum. Timestamps inside `allData` are
refreshed to "now" on every send.

## Known weak points (verified 2026-09-24)

- InvokeID is a module global shared by every client thread; responses are
  never matched by invokeID, `_recv_until_response` takes the next non-report
  PDU. `is_read_response_success` searches for byte `a4` anywhere.
- Report header decoding ignores OptFlds and the inclusion bitstring; it only
  works with the OptFlds the code itself writes and without segmentation.
- GOOSE service: `t` is set to "now" on every retransmission (it must be the
  time of the last stNum change), and `modify_stream` bumps stNum without
  resetting sqNum to 0.
- RCB writes: `_encode_mms_value_unsigned` uses tag `0x85` (integer) below 256
  and `0x86` (unsigned) above, so `IntgPd` < 256 ms would go out as an integer.
- `iec_data_from_json` turns strings with control chars into `RawData(0x83)`
  (legacy goose_cli compatibility).
- pcapy is unmaintained upstream. A plain `AF_PACKET` socket would do, but the
  kernel strips 802.1Q tags before the socket sees them (verified: a frame sent
  with VLAN 100 is read back untagged); they must be recovered from
  `PACKET_AUXDATA`, which libpcap does silently today.
- SV: rate, ASDU count and dataset are compile-time constants in
  `rt_sender.c`; quality is always 0; no smpMod/refrTm/gmIdentity. Listeners
  assume 4800 smp/s and 50 Hz.
- `scl_parser` keys data sets as `<ied>/LLN0$DS`, `<ied>_1<ld>/...` (VMC7
  naming) but never as the standard `<ied><ld>/LLN0$DS`; reports still get
  labels through the suffix fallback in `mms_report_processing`. SDOs
  (`A.phsA`) are not resolved to components.
- The MMS stack and the SV listeners/scripts still carry their own BER readers.
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
