# GOOSE: publication service and goose61850 package

Publishes and receives **GOOSE** messages (IEC 61850-8-1). It has an HTTP service that keeps streams on the bus, a command line for its API, and the `goose61850` package (codec re-exported from `open61850.goose`, transport, analysis).

## Components

| File | Role |
|------|------|
| `goose_service.py` | Standalone service: HTTP API and web page, continuous publication (port 7053) |
| `goose_cli.py` | Command line for the API (`add`, `modify`, `update-cmd`, `list`, `delete`) |
| `goose61850/` | `types`, `codec`, `transport` (`GoosePublisher`, `GooseSubscriber`), `analyzer`, `service` |
| `examples/listen_goose.py` | Listener and trip delay diagnostics on the command line |
| `goose.service` | Example systemd unit |

Publication needs **scapy**; reception goes through the shared process bus capture (`processbus_capture`, Linux AF_PACKET, root).

## Service

Through the unified service, the API is under `/api/goose/` and the web UI has a GOOSE tab. Standalone:

```bash
python3 goose/goose_service.py --host localhost --port 7053
```

| Method | Path | Purpose |
|--------|------|---------|
| GET/POST | `/api/streams` | List, create |
| GET/PATCH/DELETE | `/api/streams/<id>` | Read, change, delete |
| GET | `/api/recent` | Recently deleted streams |
| POST | `/api/recent/<id>/restart` | Start one of them again |

One sender thread polls every 10 ms; the retransmission interval starts at 10 ms and doubles up to 2000 ms. Any change of a stream (PATCH, reload at startup, restart from the recent list) is a new state: stNum + 1, sqNum 0, fast retransmission again. `t` and the utc-time / binary-time values inside `allData` take the time of that change, so retransmissions differ only by sqNum.

Streams are saved in `goose/streams.json`, the recent ones in `goose/recents.json`.

## Command line

```bash
python3 goose/goose_cli.py list
python3 goose/goose_cli.py add eth1 02:00:00:00:00:01 01:0c:cd:01:00:01 \
  --appid 0x1000 --gocb-ref 'IED01_LD0/LLN0$GO$gcb1' --dat-set 'IED01_LD0/LLN0$DS1' \
  --go-id GOOSE_1 --value bool:true --value int:42
python3 goose/goose_cli.py modify <id> --value bool:false
python3 goose/goose_cli.py update-cmd <id>      # prints a prefilled modify command
python3 goose/goose_cli.py delete <id>
```

`--service` defaults to the unified service (`http://localhost:7050`); use `http://localhost:7053` for the standalone one. `--value` takes `bool:`, `int:`, `str:` or `raw:TAG:HEX` (e.g. `raw:0x91:...` for a UtcTime).

## Listening

```bash
sudo python3 goose/examples/listen_goose.py eth1 --app-id 0x1000
sudo python3 goose/examples/listen_goose.py eth1 --measure-delay --triggers-only
python3 goose/examples/listen_goose.py eth1 --from-api http://127.0.0.1:7050 --problem-diag
```

Filters: `--app-id`, `--go-id`, `--gocb-ref`, `--src-mac`, `--dst-mac`, `--sqnum-zero`, `--bool-true`. Trip delay: `--measure-delay`, `--delay-ms`, `--audit-triggers`, `--problem-watch`, `--problem-diag`, `--problem-cycle`, `--problem-threshold`. See [goose_listener/](../goose_listener/README.md) for the measurement itself. While the GOOSE Listener of the service is analysing, prefer `--from-api` to a second capture.

## License

Copyright 2026 Florent Carli

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for the full text.
