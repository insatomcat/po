# MMS: report subscriptions and controls

The MMS part of PO subscribes to IEC 61850 reports of one or more IEDs, pushes their values to VictoriaMetrics for Grafana, and sends controls. The protocol lives in the `iec61850.mms` library of this repository (standard library only).

## Components

| File | Role |
|------|------|
| `mms_service.py` | Subscriptions (one thread each), saved commands, state files, standalone HTTP server |
| `mms_api.py` | The same API for the unified service (`/api/mms`) |
| `reporting.py` | Subscription plan, VictoriaMetrics lines and text of the reports |
| `scl_parser.py` | Data set labels from an SCL/ICD file (fallback when the IED cannot tell) |
| `victoriametrics_push.py` | Batched POST of Prometheus lines to `/api/v1/import/prometheus` |
| `mmsctl.py` | Command line for the service API |
| `webui.html` | Page of the standalone service |

`tools/mms_client.py` talks to an IED directly (domains, RCBs, reads, a subscription, a control), without the service.

## Running it

Through the unified service (recommended): start `po_service.py` from the repository root; the MMS routes are under `/api/mms/`.

Standalone:

```bash
python3 mms/mms_service.py --listen-port 8080 --victoriametrics-url http://localhost:8428
```

## HTTP API

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/subscriptions` | Create: `ied_host`, `ied_port`, `domain`, `scl`, `rcb_filter`, `rcb_list`, `debug`, `triggers`, `integrity_ms` |
| GET | `/subscriptions` | List, with `last_error` and the enabled RCBs |
| GET | `/subscriptions/<id>` | One subscription |
| PUT | `/subscriptions/<id>` | Change (a debug-only change applies at once, anything else restarts the thread) |
| DELETE | `/subscriptions`, `/subscriptions/<id>` | Delete all, or one |
| GET | `/recents` | Recently deleted subscriptions |
| GET/POST/DELETE | `/commands`, `/commands/<id>` | Saved controls |
| POST | `/commands/<id>/send` | Send a saved control (409 with the AddCause when the IED refuses) |
| GET | `/logs` | The service log, as server-sent events |

Subscriptions are saved in `mms/subscriptions.json`, commands in `mms/commands.json`. A lost connection is retried with a backoff from 5 s, doubling up to 60 s.

## How a subscription works

- **Blocks**: read from the SCL file (`scl`) when its IED matches the domains the IED lists, else discovered with GetNameList. `domain` limits it to one logical device (empty: all). `rcb_filter` picks blocks by shell pattern on their name without the instance number (`CB_LDPX_*, CB_LDADD_*`); the older `rcb_list` file still works.
- **Instances**: the service takes a free instance (neither enabled nor reserved by another client), or one its own address reserved earlier; it reserves it (`ResvTms`, when the block has it), configures and enables it, and disables and releases it when the subscription stops.
- **Labels**: data set members and their types are read from the IED (GetNamedVariableListAttributes, GetVariableAccessAttributes); the SCL file is only a fallback.
- **Triggers**: `triggers` (`dchg`, `qchg`, `dupd`, `integrity`, `gi`; default `integrity,gi`) and `integrity_ms` (default 2000).
- **VictoriaMetrics**: series `mms_report_value{rpt_id, data_set, member[, component]}`. In Grafana, set Query options, Min step to `1s` or `2s` to see every point.

## mmsctl

```bash
python3 -m mms.mmsctl create --id s1 --ied-host 192.0.2.10 --rcb-filter "CB_LDPX_*" --debug
python3 -m mms.mmsctl list
python3 -m mms.mmsctl get s1
python3 -m mms.mmsctl update s1 --rcb-filter "CB_LDPX_*, CB_LDADD_*" --no-debug
python3 -m mms.mmsctl delete s1
```

`--api-url` defaults to `http://localhost:7050` (unified service); add `--standalone` for `mms_service.py` on its own.

## License

Copyright 2026 Florent Carli

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for the full text.
