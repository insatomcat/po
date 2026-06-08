# PO – Plateforme IEC 61850

Plateforme logicielle pour **MMS** (reports), **GOOSE** et **Sampled Values (SV)** selon les normes IEC 61850. Implémentations en Python, sans dépendance GPL pour le cœur MMS (TPKT/COTP/MMS en BER).

## Vue d’ensemble

| Composant | Rôle | Dossier |
|-----------|------|---------|
| **Service unifié** | HTTP sur un seul port (7050) : Web UI, API MMS/GOOSE/SV, proxy SV Listener, GOOSE Listener | Racine (`po_service.py`, `unified_ui.html`) |
| **MMS** | Client reports IEC 61850, service HTTP, API, CLI | [mms/](mms/README.md) |
| **GOOSE** | Envoi/réception GOOSE, service HTTP, API, CLI, bibliothèque | [goose/](goose/README.md) |
| **GOOSE Listener** | Capture bus, mesure Δ déclenchement → seconde pile, alertes (délais, manquants) | [goose_listener/](goose_listener/README.md) |
| **SV Generator** | Générateur de flux SV (IEC 61869-9), service FastAPI, API, CLI | [svgenerator/](svgenerator/README.md) |
| **SV Listener View** | Capture et visualisation SV (phasors U/I), interface web | [svlistener_view/](svlistener_view/README.md) |

## Prérequis

- **Python 3.10+**
- Pour MMS : stdlib uniquement (pas de `pip install`)
- Pour GOOSE : **pcapy** (capture) + **scapy** (publication) via `goose61850.transport`
- Pour SV Generator : voir [svgenerator/requirements.txt](svgenerator/requirements.txt) (FastAPI, Pydantic, etc.)
- Pour SV Listener View : `pcapy`, Flask (voir [svlistener_view/](svlistener_view/README.md))

## Démarrage rapide – Service unifié

Tout démarrer sur le port **7050** (Web UI + APIs) :

```bash
python3 po_service.py --port 7050
```

Puis ouvrir **http://localhost:7050** : interface avec onglets MMS | GOOSE | SV | SV Listener | GOOSE Listener.

Options utiles :

- `--victoriametrics-url http://localhost:8428` : push des reports MMS vers VictoriaMetrics (Grafana)
- `--svview-interface eth0` : active le proxy vers le SV Listener (capture SV sur `eth0`), l’onglet **SV Listener**, et le **GOOSE Listener** (capture GOOSE sur la même interface)

Exemple sur bus process :

```bash
python3 po_service.py --svview-interface processbus --port 7050
```

Sans `--svview-interface` : les onglets SV Listener et GOOSE Listener affichent « non configuré » (API **503**).

### Endpoints principaux

| Chemin | Description |
|--------|-------------|
| `/` | Web UI unifiée |
| `/healthz` | Health check |
| `/api/mms/*` | API MMS (abonnements, recents, logs SSE) |
| `/api/goose/*` | API GOOSE (streams, recent, restart) |
| `/api/sv/*` | API SV (flux, recents) |
| `/api/svview/*` | Proxy vers SV Listener (si `--svview-interface` configuré) |
| `/api/gooselistener/*` | GOOSE Listener : scan, analyse, événements, problèmes (si `--svview-interface` configuré) |

Le poll WebUI du GOOSE Listener appelle `GET /api/gooselistener/status` toutes les **2 s** pendant un scan ou une analyse. La capture réseau (BPF GOOSE, file dédiée) reste indépendante du rafraîchissement UI — voir [goose_listener/README.md](goose_listener/README.md) pour la mesure Δ, les alertes et le diagnostic `capture.drops`.

## Structure du dépôt

```
po/
├── README.md              # Ce fichier
├── po_service.py          # Service HTTP unifié (port 7050)
├── unified_ui.html        # Interface web (onglets MMS/GOOSE/SV/SV Listener/GOOSE Listener)
├── iec_data.py            # Types IEC 61850 partagés (IECData, BoolData, IntData, TimestampData, …)
├── mms/                   # Client MMS, service, API, CLI → mms/README.md
├── goose/                 # GOOSE service, lib, CLI → goose/README.md
├── goose_listener/        # Listener GOOSE (mesure Δ, problèmes) → goose_listener/README.md
├── svgenerator/           # Générateur SV, API, CLI → svgenerator/README.md
└── svlistener_view/       # Listener + vue SV → svlistener_view/README.md
```

Chaque sous-dossier contient son propre **README** (applications, services, clients CLI, API).

## Licence et contraintes

- Cœur MMS : implémentation maison TPKT/COTP/MMS en BER, **sans bibliothèque GPL**.
- Autres composants : voir les fichiers sources et README des sous-dossiers.
