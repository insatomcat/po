# Node stress test (SSH + stress-ng)

The **Stress** tab of `unified_ui.html` connects PO to a host node (name or address), discovers its CPU topology with `seapath-alloc` (housekeeping, isolated, free logical cores, VM/IRQ/RT actors), runs `stress-ng` on the chosen cores and shows the load live.

The point is to check that the isolation of the IED virtual machines holds under host load, by watching the delays in the **GOOSE Listener** tab.

## How it works

1. PO connects over **SSH**, or locally when the node is the machine running `po_service`.
2. A Python script on the node runs `seapath-alloc` (or falls back on `isolcpus` and libvirt) and reads `/proc/stat`.
3. The UI offers presets: **housekeeping**, **free isolated** (`Free logical`), **except occupied** (housekeeping plus free isolated: leaves out VMs, IRQs, containers and `seapath-alloc` claims).
4. `stress-ng` pins the housekeeping cores with one mask and each isolated core on its own (`isolcpus` ignores a mixed mask). `seapath-run` is used when the SSH cpuset does not allow the CPU.
5. The CPU map and the load chart (stressed, housekeeping, VM) refresh every second.
6. Switch to **GOOSE Listener** to see whether delays appear.

The stress keeps running when you change tabs. **Stop** (or stopping `po_service`) kills `stress-ng`.

## Requirements on the node

- `python3`
- `seapath-alloc` (recommended, for isolated and free cores and the actors)
- `seapath-run` (when the SSH cpuset does not include the isolated cores)
- `stress-ng` (`apt install stress-ng` / `dnf install stress-ng`)
- SSH access with a key (recommended) or a password
- `virsh` when libvirt manages the VMs (SEAPATH)

When the node is the machine running PO, the connection is **local** (no SSH); tick "Force SSH" to use SSH anyway.

## API (`/api/stress`)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/status` | Current session, load, history |
| POST | `/connect` | `{host, port, user, identity, password, name, force_ssh}` |
| POST | `/start` | `{cpus, workloads, cpu_load, timeout_s, key}` |
| POST | `/stop` | `{key}` |
| POST | `/disconnect` | `{key, stop_stress}` (by default the stress goes on) |
| GET/PUT | `/hosts` | Saved nodes (`stress/hosts.json`) |

Workloads (the **what**): `cpu` (default, compute loops, load slider), `cache` (L1/L2/L3), `vm` (64 MB per worker, memory bandwidth), `switch` (context switches). All are pinned to the selected cores (the **where**). The **CPU usage** chart reads `/proc/stat`. A second chart shows rates: cache misses (PMU through `perf`), page faults (`/proc/vmstat`), context switches (`ctxt` in `/proc/stat`). `linux-perf` is optional, for the cache rate.

## License

Copyright 2026 Florent Carli

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for the full text.
