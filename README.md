# PO - IEC 61850 Platform

Test and diagnostic platform for IEC 61850 on a digital substation process bus. PO speaks **MMS** (reports, controls), **GOOSE** (publish, subscribe, trip delay measurement) and **Sampled Values** (generation, phasor view), behind one HTTP service with a web UI.

The protocol code is the [open61850](https://github.com/insatomcat/open61850) library: IEC 61850 in pure Python, standard library only, Apache 2.0 (an MMS client with reports, report control blocks and controls; an MMS server; GOOSE and Sampled Values codecs, publishers and stream supervision; SCL and COMTRADE readers; pcap files and a Linux capture for the process bus). It started in this repository and now lives in its own; PO pins a version from PyPI in `requirements.txt`.

```bash
pip install -r requirements.txt
open61850-mms 192.0.2.10 domains      # the library's command line, handy against a live IED
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
- `open61850` (`pip install -r requirements.txt`), standard library only
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
├── requirements.txt       # open61850, pinned to a tag
├── tools/                 # pcap_mms.py (MMS PDUs of a capture)
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
