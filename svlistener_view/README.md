# SV Listener View

Receives **Sampled Values** (IEC 61850-9-2 / IEC 61869-9) and shows the U and I phasors of one stream in a web page (Flask).

## What it does

- Takes the SV frames of the shared process bus capture (`processbus_capture`, one AF_PACKET socket per interface, shared with GOOSE).
- Lists every svID seen. A stream is decoded in full when it is new, when it carries the selected svID, and once per second; its other frames are only counted.
- For the selected svID (6I3U, or 4I4U mapped onto it): phasors by a 96-sample DFT at 50 Hz, waveforms, inter-frame delays, delay from the second boundary to smpCnt 0, missing samples.
- Counts received frames and frames the SV decoder rejects (shown under the capture badge).

Streams with fewer than 8 channels per ASDU are listed but not displayed. Quality is ignored.

## Requirements

- Python 3.10+
- Linux, root or `CAP_NET_RAW` (AF_PACKET capture)
- Flask (`pip install flask`)

## Running it

Usually through the unified service, which starts the Flask app on a local port and proxies `/api/svview/` to it:

```bash
sudo python3 po_service.py --svview-interface eth1
```

On its own, from the repository root:

```bash
sudo SVVIEW_INTERFACE=eth1 SVVIEW_PORT=7052 python3 svlistener_view/sv_listener_view.py
```

Optional settings: `SVVIEW_WINDOW` (statistics window, s, default 10), `SVVIEW_SCALE`, `SVVIEW_ASPECT`. `svgenerator/svlistener_view.service.example` is a systemd unit for this standalone mode (uvicorn on port 7052).

The capture starts with `POST /api/capture/start` (the UI does it) and stops with `POST /api/capture/stop`; `POST /api/svid` selects a stream; `GET /api/data` returns the display data and the counters.

## Files

| File | Content |
|------|---------|
| `sv_listener_view.py` | Flask app, SV subscription to the shared capture, decoding (`iec61850.sv`), phasors, statistics |
| `templates/index.html` | Standalone web page (the unified UI has its own SV Listener tab) |

## License

Copyright 2026 Florent Carli

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for the full text.
