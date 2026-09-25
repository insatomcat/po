# SV Generator

Generates **Sampled Values** streams (IEC 61850-9-2 / IEC 61869-9, 6I3U layout) on an Ethernet interface, optionally VLAN tagged, with real-time settings (frequency, peak currents and voltages, a periodic fault). A service keeps the flows (FastAPI models, also served by the unified service) and starts one sender process per flow: `open61850-sv` from the open61850 library (its Rust real-time engine) by default, or the C `rt_sender` of this directory with `PO_SV_SENDER=rt_sender`; `svctl` drives its API.

## Components

| File | Role |
|------|------|
| `sv_service.py` | FastAPI app, `FlowConfig` / `FlowState` models, sender process management, state files (port 7051 standalone) |
| `sv_api.py` | The same API for the unified service (`/api/sv`) |
| `svctl.py` | Command line for the API (`list`, `create`, `update`, `delete`, `clear`) |
| `rt_sender.c` | The former real-time sender (C, AF_PACKET, `CLOCK_REALTIME`, 4800 samples/s, 2 ASDUs per frame), kept as a fallback (`PO_SV_SENDER=rt_sender`) |
| `receiver.py`, `sv_receiver_delay.py`, `sv_counter3.py`, `parse_ref_pkt.py` | Diagnostic scripts (reception, delays, missing samples, reference frame dump) |
| `svgenerator.service.example`, `svlistener_view.service.example` | Example systemd units |

Rate, ASDU count and data set are compile-time constants of `rt_sender.c`; quality is always 0. `open61850-sv` takes them as options; on the process bus, both send each sample about 4 µs after its nominal time on an isolated core with SCHED_FIFO 80.

## Installation

```bash
pip install -r svgenerator/requirements.txt
gcc -O2 -o svgenerator/rt_sender svgenerator/rt_sender.c -lrt -lm
```

`rt_sender` goes in `svgenerator/` or on the PATH. Flows are started with `seapath-alloc` real-time CPU allocation when it is available, `taskset` / `chrt` otherwise. They survive a restart of the service (their PIDs are kept in `svgenerator/pids/`).

## Running it

Through the unified service, the API is under `/api/sv/` and the web UI has an SV tab. Standalone:

```bash
cd svgenerator && uvicorn sv_service:app --host 0.0.0.0 --port 7051
```

| Method | Path | Purpose |
|--------|------|---------|
| GET/POST | `/flows` | List (with state), create |
| GET/PUT/DELETE | `/flows/{name}` | Read, change (restarts the process), delete |
| DELETE | `/flows` | Delete every flow |
| GET | `/flows/recents` | Recently deleted flows |

Flows are saved in `svgenerator/flows.json`, the recent ones in `svgenerator/recents.json`.

## svctl

```bash
python3 svgenerator/svctl.py list -v
python3 svgenerator/svctl.py create flow1 eth1 02:00:00:00:00:01 01:0c:cd:04:00:01 IED01_SV1 \
  --appid 0x4000 --conf-rev 1 --freq 50 --i-peak 10 --v-peak 100 --vlan-id 100
python3 svgenerator/svctl.py update flow1 eth1 02:00:00:00:00:01 01:0c:cd:04:00:01 IED01_SV1 \
  --appid 0x4000 --conf-rev 2 --fault --fault-cycle 4
python3 svgenerator/svctl.py delete flow1
python3 svgenerator/svctl.py clear
```

`--base-url` defaults to the unified service (`http://127.0.0.1:7050`); use port 7051 for the standalone one. `--appid` and `--conf-rev` are required. Other options: `--smp-synch`, `--vlan-id`, `--vlan-priority`, `--freq`, `--i-peak`, `--v-peak`, `--phase`, `--fault`, `--fault-i-peak`, `--fault-v-peak`, `--fault-phase`, `--fault-cycle`, `--fault-smpcnt`, `--fault-offset`, and the real-time ones (`--rt-priority`, `--rt-cpu`, `--rt-isolation`, `--rt-scheduler`).

The fault cycle is aligned on the UNIX epoch: two flows with the same `fault_cycle_s` and `fault_offset_s=0` start their fault in the same second. `fault_smpcnt` moves the first fault sample within that second, `fault_offset_s` moves it by whole seconds within the cycle. The fault lasts half the period. Saved configurations from before this format (where `fault_cycle_s` was a half period) are converted when read.

## rt_sender on its own

```bash
sudo ./rt_sender --appid 0x4000 --conf-rev 1 --smp-synch 2 --vlan-id 100 --vlan-priority 4 \
  eth1 02:00:00:00:00:01 01:0c:cd:04:00:01 IED01_SV1
./rt_sender --dump --appid 0x4000 --conf-rev 1 lo 02:00:00:00:00:01 01:0c:cd:04:00:01 IED01_SV1
```

`--dump` builds one frame, prints it in hex and exits; the test suite compares it with a Python mirror of the layout.

## License

Copyright 2026 Florent Carli

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for the full text.
