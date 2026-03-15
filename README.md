# PO – Plateforme IEC 61850

Plateforme logicielle pour **MMS** (reports), **GOOSE** et **Sampled Values (SV)** selon les normes IEC 61850. Implémentations en Python, sans dépendance GPL pour le cœur MMS (TPKT/COTP/MMS en BER).

## Vue d’ensemble

| Composant | Rôle | Dossier |
|-----------|------|---------|
| **Service unifié** | HTTP sur un seul port (7050) : Web UI, API MMS/GOOSE/SV, proxy SV Listener | Racine (`po_service.py`, `unified_ui.html`) |
| **MMS** | Client reports IEC 61850, service HTTP, API, CLI | [mms/](mms/README.md) |
| **GOOSE** | Envoi/réception GOOSE, service HTTP, API, CLI, bibliothèque | [goose/](goose/README.md) |
| **SV Generator** | Générateur de flux SV (IEC 61869-9), service FastAPI, API, CLI | [svgenerator/](svgenerator/README.md) |
| **SV Listener View** | Capture et visualisation SV (phasors U/I), interface web | [svlistener_view/](svlistener_view/README.md) |

## Prérequis

- **Python 3.10+**
- Pour MMS : stdlib uniquement (pas de `pip install`)
- Pour GOOSE : stdlib
- Pour SV Generator : voir [svgenerator/requirements.txt](svgenerator/requirements.txt) (FastAPI, Pydantic, etc.)
- Pour SV Listener View : `pcapy`, Flask (voir [svlistener_view/](svlistener_view/README.md))

## Démarrage rapide – Service unifié

Tout démarrer sur le port **7050** (Web UI + APIs) :

```bash
python3 po_service.py --port 7050
```

Puis ouvrir **http://localhost:7050** : interface avec onglets MMS | GOOSE | SV | SV Listener.

Options utiles :

- `--victoriametrics-url http://localhost:8428` : push des reports MMS vers VictoriaMetrics (Grafana)
- `--svview-interface eth0` : active le proxy vers le SV Listener (capture SV sur `eth0`) et l’onglet SV Listener

### Endpoints principaux

| Chemin | Description |
|--------|-------------|
| `/` | Web UI unifiée |
| `/healthz` | Health check |
| `/api/mms/*` | API MMS (abonnements, recents, logs SSE) |
| `/api/goose/*` | API GOOSE (streams, recent, restart) |
| `/api/sv/*` | API SV (flux, recents) |
| `/api/svview/*` | Proxy vers SV Listener (si `--svview-interface` configuré) |

## Structure du dépôt

```
po/
├── README.md              # Ce fichier
├── po_service.py          # Service HTTP unifié (port 7050)
├── unified_ui.html        # Interface web (onglets MMS/GOOSE/SV/SV Listener)
├── mms/                   # Client MMS, service, API, CLI → mms/README.md
├── goose/                 # GOOSE service, lib, CLI → goose/README.md
├── svgenerator/           # Générateur SV, API, CLI → svgenerator/README.md
└── svlistener_view/       # Listener + vue SV → svlistener_view/README.md
```

Chaque sous-dossier contient son propre **README** (applications, services, clients CLI, API).

## Licence et contraintes

- Cœur MMS : implémentation maison TPKT/COTP/MMS en BER, **sans bibliothèque GPL**.
- Autres composants : voir les fichiers sources et README des sous-dossiers.
