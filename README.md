# PO - IEC 61850 Platform

Test and diagnostic platform for IEC 61850 on a digital substation process bus. PO speaks **MMS** (reports, controls), **GOOSE** (publish, subscribe, trip delay measurement) and **Sampled Values** (generation, phasor view), behind one HTTP service with a web UI.

The protocol code lives in [`iec61850/`](iec61850/), a pure-stdlib Python library under the Apache 2.0 licence, meant to become a reusable alternative to the GPL libiec61850.

## The `iec61850` library

No dependency outside the standard library, and no I/O except in the capture and MMS transport modules.

| Module | Content |
|--------|---------|
| `ber` | ASN.1 BER primitives (tags, lengths, INTEGER, OBJECT IDENTIFIER, ...) |
| `data` | MMS `Data` values, encoding and decoding, UtcTime |
| `quality` | Quality and TimeQuality in readable form |
| `display` | Readable text for MMS values |
| `ethernet` | Ethernet II / 802.1Q frames with an APPID header |
| `goose` | GOOSE PDUs and frames |
| `sv` | Sampled Values PDUs and frames (IEC 61850-9-2 / 61869-9) |
| `capture` | Linux frame capture on an AF_PACKET ring (no libpcap), kernel timestamps |
| `scl` | SCL (CID/SCD) reader: IEDs, logical devices, data sets, report control blocks |
| `mms.transport` | TPKT and COTP over TCP |
| `mms.association` | Association request (Session, Presentation, ACSE, MMS Initiate) and the negotiated limits of the response |
| `mms.client` | `MmsClient`: requests matched by invokeID, reports delivered to callbacks, typed errors |
| `mms.report` | IEC 61850 report decoding driven by OptFlds and the inclusion bit string |
| `mms.rcb` | Report control blocks: status, reservation, enabling, release |
| `mms.control` | Controls: direct and select-before-operate, normal and enhanced security |
| `mms.types` | Type descriptions (GetVariableAccessAttributes) and value labels |

```python
from iec61850.mms import MmsClient, ObjectName, OBJECT_CLASS_DOMAIN

with MmsClient.connect("192.0.2.10") as client:
    print(client.association.max_outstanding_calling)
    for domain in client.get_name_list(OBJECT_CLASS_DOMAIN):
        print(domain)
    print(client.read(ObjectName("LLN0$ST$Mod$stVal", "IED01_LD0")))
```

`tools/mms_client.py` puts the MMS client on the command line:

```bash
python3 tools/mms_client.py 192.0.2.10 association   # what the IED accepted
python3 tools/mms_client.py 192.0.2.10 domains
python3 tools/mms_client.py 192.0.2.10 rcbs --status
python3 tools/mms_client.py 192.0.2.10 read 'IED01_LD0/LLN0$DC$NamPlt'
python3 tools/mms_client.py 192.0.2.10 subscribe 'IED01_LD0/LLN0$BR$CB_LDPHAS1'
python3 tools/mms_client.py 192.0.2.10 operate 'IED01_BayLD/CBCSWI1$CO$Pos' open
```

## Applications

| Component | Role | Directory |
|-----------|------|-----------|
| **Unified service** | HTTP on one port (7050): web UI and every API below | `po_service.py`, `unified_ui.html` |
| **MMS** | Report subscriptions (blocks found on the IED or in its SCL file), VictoriaMetrics push, controls | [mms/](mms/README.md) |
| **GOOSE** | GOOSE publication (streams, state changes, retransmission) and reception | [goose/](goose/README.md) |
| **GOOSE Listener** | Trip delay measurement against the linked SV stream, problem detection, PCAP dumps | [goose_listener/](goose_listener/README.md) |
| **SV Generator** | SV streams from a real-time C sender (4800 samples/s) | [svgenerator/](svgenerator/README.md) |
| **SV Listener View** | SV reception and U/I phasor display | [svlistener_view/](svlistener_view/README.md) |
| **Stress** | `stress-ng` load on host cores over SSH, CPU topology | [stress/](stress/README.md) |

GOOSE and SV reception share one capture per interface (`processbus_capture.py`): its kernel filter lets SV frames through only while an SV consumer is active.

## Requirements

- **Python 3.10+**
- Library and MMS: standard library only
- Capture (GOOSE Listener, SV Listener View): **Linux**, root or `CAP_NET_RAW`
- GOOSE publication: **scapy**
- SV Generator: FastAPI and friends, see [svgenerator/requirements.txt](svgenerator/requirements.txt), and a C compiler for `rt_sender`
- SV Listener View: Flask

## Quick start

```bash
python3 po_service.py --listen-port 7050
```

Then open **http://localhost:7050** (tabs MMS, GOOSE, SV, SV Listener, GOOSE Listener, Stress).

Options:

- `--listen-host`, `--listen-port`: where the service listens (default port 7050)
- `--victoriametrics-url http://victoriametrics:8428`: push MMS report values to VictoriaMetrics (Grafana)
- `--vm-batch-ms`: VictoriaMetrics batching interval
- `--log-level`: DEBUG, INFO (default), WARNING or ERROR; also `$PO_LOG_LEVEL`. Logs go to stdout (journalctl) and to the log panel of the MMS tab
- `--svview-interface eth1`: the process bus interface; enables the SV Listener and GOOSE Listener tabs (API **503** without it)

`po-service.service` is a systemd unit for the service; site settings (`SVVIEW_INTERFACE`, `PO_VICTORIAMETRICS_URL`) go in a drop-in (`systemctl edit po-service`).

### Main endpoints

| Path | Description |
|------|-------------|
| `/` | Unified web UI |
| `/healthz` | Health check |
| `/api/mms/*` | MMS subscriptions, recent reports, SSE logs, commands |
| `/api/goose/*` | GOOSE streams |
| `/api/sv/*` | SV streams |
| `/api/svview/*` | SV Listener (with `--svview-interface`) |
| `/api/gooselistener/*` | GOOSE Listener: scan, analysis, events, problems (with `--svview-interface`) |
| `/api/stress/*` | Node stress test |

## Repository layout

```
po/
├── iec61850/              # The IEC 61850 library (Apache 2.0, stdlib only)
├── po_service.py          # Unified HTTP service
├── unified_ui.html        # Web UI
├── processbus_capture.py  # Shared GOOSE/SV capture per interface
├── po_logging.py          # Logging setup of the services
├── iec_data.py            # JSON mapping of MMS values for the HTTP APIs
├── mms/                   # MMS subscription service, API, CLI
├── goose/                 # GOOSE service and goose61850 package
├── goose_listener/        # GOOSE trip delay measurement
├── svgenerator/           # SV generator (rt_sender.c) and diagnostics
├── svlistener_view/       # SV phasor view
├── stress/                # Node stress test
├── tools/                 # mms_client.py, pcap_mms.py, bench_sv_decode.py
└── tests/                 # pytest suite
```

Maintainer notes (architecture, what the IED captures taught, known weak points) are in [AGENTS.md](AGENTS.md).

## Tests

```bash
python3 -m pip install pytest
python3 -m pytest
```

The suite needs no network access and no scapy. The capture and `rt_sender` checks run on Linux only.

## License

Copyright 2026 Florent Carli

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.
