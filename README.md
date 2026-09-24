# PO - IEC 61850 Platform

Software platform for **MMS** (reports), **GOOSE** and **Sampled Values (SV)** following the IEC 61850 standards. Python implementations, with no GPL dependency for the MMS core (TPKT/COTP/MMS in BER).

## Overview

| Component | Role | Directory |
|-----------|------|-----------|
| **Unified service** | HTTP on a single port (7050): Web UI, MMS/GOOSE/SV API, SV Listener proxy, GOOSE Listener | Root (`po_service.py`, `unified_ui.html`) |
| **MMS** | IEC 61850 report client, HTTP service, API, CLI | [mms/](mms/README.md) |
| **GOOSE** | GOOSE send/receive, HTTP service, API, CLI, library | [goose/](goose/README.md) |
| **GOOSE Listener** | Bus capture, trip Δ measurement to the second stage, alerts (delays, missing frames) | [goose_listener/](goose_listener/README.md) |
| **Stress** | SSH/`stress-ng` stress test of the nodes (housekeeping, cores outside the VM) | [stress/](stress/README.md) |
| **SV Generator** | SV stream generator (IEC 61869-9), FastAPI service, API, CLI | [svgenerator/](svgenerator/README.md) |
| **SV Listener View** | SV capture and visualisation (U/I phasors), web interface | [svlistener_view/](svlistener_view/README.md) |

## Requirements

- **Python 3.10+**
- For MMS: stdlib only (no `pip install`)
- For GOOSE: **pcapy** (capture) + **scapy** (publication) through `goose61850.transport`
- For SV Generator: see [svgenerator/requirements.txt](svgenerator/requirements.txt) (FastAPI, Pydantic, etc.)
- For SV Listener View: `pcapy`, Flask (see [svlistener_view/](svlistener_view/README.md))

## Quick start - unified service

Start everything on port **7050** (Web UI + APIs):

```bash
python3 po_service.py --port 7050
```

Then open **http://localhost:7050**: an interface with the MMS | GOOSE | SV | SV Listener | GOOSE Listener | Stress tabs.

Useful options:

- `--victoriametrics-url http://localhost:8428`: push MMS reports to VictoriaMetrics (Grafana)
- `--svview-interface eth0`: enables the proxy to the SV Listener (SV capture on `eth0`), the **SV Listener** tab, and the **GOOSE Listener** (GOOSE capture on the same interface)

Example on a process bus:

```bash
python3 po_service.py --svview-interface processbus --port 7050
```

Without `--svview-interface`, the SV Listener and GOOSE Listener tabs show "not configured" (API **503**).

### Main endpoints

| Path | Description |
|------|-------------|
| `/` | Unified Web UI |
| `/healthz` | Health check |
| `/api/mms/*` | MMS API (subscriptions, recents, SSE logs) |
| `/api/goose/*` | GOOSE API (streams, recent, restart) |
| `/api/sv/*` | SV API (streams, recents) |
| `/api/svview/*` | Proxy to the SV Listener (if `--svview-interface` is configured) |
| `/api/gooselistener/*` | GOOSE Listener: scan, analysis, events, problems (if `--svview-interface` is configured) |
| `/api/stress/*` | Node stress test: SSH, CPU map, `stress-ng` |

The GOOSE Listener Web UI poll calls `GET /api/gooselistener/status` every **2 s** during a scan or an analysis. Network capture (GOOSE BPF, dedicated queue) stays independent from the UI refresh. See [goose_listener/README.md](goose_listener/README.md) for the Δ measurement, the alerts and the `capture.drops` diagnostic.

## Repository layout

```
po/
├── README.md              # This file
├── po_service.py          # Unified HTTP service (port 7050)
├── unified_ui.html        # Web interface (MMS/GOOSE/SV/SV Listener/GOOSE Listener/Stress tabs)
├── iec_data.py            # Shared IEC 61850 types (IECData, BoolData, IntData, TimestampData, …)
├── mms/                   # MMS client, service, API, CLI -> mms/README.md
├── goose/                 # GOOSE service, lib, CLI -> goose/README.md
├── goose_listener/        # GOOSE listener (Δ measurement, problems) -> goose_listener/README.md
├── stress/                # Node stress test (SSH + stress-ng) -> stress/README.md
├── svgenerator/           # SV generator, API, CLI -> svgenerator/README.md
└── svlistener_view/       # SV listener + view -> svlistener_view/README.md
```

Each subdirectory has its own **README** (applications, services, CLI clients, API).

## Tests

```bash
python3 -m pip install pytest
python3 -m pytest
```

The suite runs without network access, scapy or pcapy. The `rt_sender` checks need Linux and a C compiler.

## Licence and constraints

- MMS core: in-house TPKT/COTP/MMS implementation in BER, **without any GPL library**.
- Other components: see the source files and the READMEs of the subdirectories.

## License

Copyright 2026 Florent Carli

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.
