# GOOSE – Service et bibliothèque IEC 61850

Envoi et réception de messages **GOOSE** (IEC 61850). Comprend un **service HTTP** (flux multiples, API), un **CLI** pour piloter l’API et une **bibliothèque** `goose61850` (encode/decode, transport, analyse).

## Composants

| Élément | Rôle |
|--------|------|
| **Service** | `goose_service.py` – API HTTP + envoi continu des flux GOOSE (port 7053 en standalone) |
| **API** | Intégrée au service ; routes `/api/streams`, `/api/streams/<id>`, `/api/recent`, `/api/restart` (unifié : préfixe `/api/goose`) |
| **CLI** | `goose_cli.py` – commandes list, create, get, update, delete, restart vers l’API |
| **Bibliothèque** | `goose61850/` – types, codec, transport (publisher/subscriber), analyseur |

## Prérequis

- **Python 3.10+**
- Stdlib uniquement pour la bibliothèque et le service

## Service GOOSE

### Standalone (port 7053)

```bash
cd goose
python3 goose_service.py --host localhost --port 7053
```

- **API** : `GET/POST /api/streams`, `GET/PATCH/DELETE /api/streams/<id>`, `GET /api/recent`, `POST /api/restart`
- **Web UI** : `/` (interface fournie par le service)

### Via service unifié (port 7050)

En lançant `po_service.py` à la racine du dépôt, l’API GOOSE est exposée sous **/api/goose/** (streams, recent, restart). La Web UI unifiée propose l’onglet GOOSE.

## CLI goose_cli

Le CLI envoie des requêtes à l’API (par défaut `http://localhost:7050` en mode unifié, sinon `http://localhost:7053` pour le service standalone).

```bash
# Lister les flux
python3 goose_cli.py list --base-url http://127.0.0.1:7050

# Créer un flux
python3 goose_cli.py create --base-url http://127.0.0.1:7050 \
  --iface eth0 --src-mac 01:0c:cd:01:00:01 --dst-mac 01:0c:cd:01:00:02 \
  --appid 0x100 --gocb-ref "IED1/LLN0$GO$gcb" --dat-set "IED1/LLN0$DS$go" \
  --go-id "GOOSE_1" --value bool:true --value int:42

# Détail d’un flux
python3 goose_cli.py get <id> --base-url http://127.0.0.1:7050

# Mettre à jour (PATCH)
python3 goose_cli.py update <id> --base-url http://127.0.0.1:7050 --ttl 5000

# Supprimer
python3 goose_cli.py delete <id> --base-url http://127.0.0.1:7050

# Redémarrer l’envoi (st_num incrémenté)
python3 goose_cli.py restart <id> --base-url http://127.0.0.1:7050
```

Valeurs `--value` : `bool:true`, `int:42`, `str:texte`, `raw:TAG:HEX` (ex. `raw:1:80`).

> **Timestamps auto-rafraîchis** : si `allData` contient des valeurs de type `utc-time` (tag `0x91`) ou `binary-time` (tag `0x8C`) — passées via `raw:` — elles sont automatiquement mises à jour à l'heure courante à chaque émission. Cela évite qu'un IED récepteur rejette le message comme obsolète.

## Bibliothèque goose61850

Package Python dans `goose61850/` :

| Module | Rôle |
|--------|------|
| `types` | `GoosePDU`, `GooseFrame` |
| `codec` | `decode_goose_pdu`, `encode_goose_pdu` (BER) |
| `transport` | `GooseSubscriber`, `GoosePublisher` (réseau) |
| `analyzer` | `GooseAnalyzer` (inspection / analyse) |
| `service` | Logique métier du service HTTP (flux, persistance, envoi) |

### Exemple : écouter des GOOSE

```bash
cd goose
python3 examples/listen_goose.py -i eth0
```

Options : `-i` interface, `--appid`, `--show-all` pour afficher tout `allData`. Le script utilise `GooseSubscriber` et affiche un résumé de chaque frame (timestamp, gocbRef, goID, stNum, sqNum, allData).

## Fichiers de configuration

- **streams.json** : flux GOOSE définis (créés via API ou CLI), persistance par le service.
- **recents.json** : derniers messages reçus (si réception utilisée).
- **goose.service** : exemple de fichier systemd pour lancer le service en production.

## Structure des fichiers

```
goose/
├── README.md           # Ce fichier
├── goose_service.py    # Point d’entrée service (--host, --port)
├── goose_cli.py        # CLI (list, create, get, update, delete, restart)
├── goose61850/         # Bibliothèque
│   ├── __init__.py
│   ├── types.py        # GoosePDU, GooseFrame
│   ├── codec.py        # Encode / decode BER
│   ├── transport.py    # GooseSubscriber, GoosePublisher
│   ├── service.py      # GooseService, API HTTP
│   └── analyzer.py     # GooseAnalyzer
├── examples/
│   └── listen_goose.py # Exemple écoute GOOSE
├── streams.json        # (généré) flux persistés
├── recents.json        # (généré) derniers messages
├── goose.service       # Exemple systemd
└── pyproject.toml      # Config projet (optionnel)
```
