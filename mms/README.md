# MMS – Client reports IEC 61850

Client MMS en Python pour **s’abonner aux reports** IEC 61850 et recevoir les données en push. Implémentation **sans bibliothèque GPL** : le protocole est dans la librairie `iec61850.mms` du projet.

## Composants

| Élément | Rôle |
|--------|------|
| **Service HTTP** | `mms_service.py` – gestion de plusieurs flux (abonnements) par API, push VictoriaMetrics |
| **API** | `mms_api.py` – routes `/subscriptions`, `/recents`, `/logs` (SSE), utilisée par le service unifié |
| **CLI du service** | `mmsctl.py` – pilotage du service via HTTP (create, list, get, update, delete) |
| **Client autonome** | `tools/mms_client.py` – interroge un IED directement (domaines, RCB, lectures, abonnement, commande) |

Le protocole est dans la librairie `iec61850.mms` (stdlib uniquement, Python 3.10+).

## Utilisation

### 1. Client en ligne de commande

```bash
python3 tools/mms_client.py 192.0.2.10 domains
python3 tools/mms_client.py 192.0.2.10:102 rcbs --status
python3 tools/mms_client.py 192.0.2.10 read 'IED01_LD0/LLN0$DC$NamPlt'
python3 tools/mms_client.py 192.0.2.10 subscribe 'IED01_LD0/LLN0$BR$CB_LDPHAS1'
```

`subscribe` prend une instance libre du bloc, l'active, affiche les reports décodés et la désactive au Ctrl-C.

**Grafana** : pour afficher un point toutes les 2–4 s, dans le panneau → Query options → **Min step** = `2s` ou `1s`.

### 2. Service HTTP (flux multiples)

Le service MMS peut tourner **standalone** ou être intégré au **service unifié** (port 7050). En mode unifié, l’API est préfixée par `/api/mms`.

**Standalone** (port 8080 par défaut) :

```bash
python3 mms/mms_service.py --port 8080 --victoriametrics-url http://localhost:8428
```

**Via service unifié** (recommandé) : lancer `po_service.py` à la racine ; les routes MMS sont sous `/api/mms/`.

#### API HTTP (résumé)

- **POST /subscriptions** – Créer un flux (ied_host, ied_port, domain, scl, rcb_filter, rcb_list, debug, triggers, integrity_ms)
- **GET /subscriptions** – Lister les flux
- **GET /subscriptions/<id>** – Détail d’un flux
- **PUT /subscriptions/<id>** – Modifier un flux (ré démarre le thread avec la nouvelle config)
- **DELETE /subscriptions/<id>** – Supprimer un flux
- **GET /recents** – Derniers reports reçus
- **GET /logs** – Flux SSE des logs

La configuration des abonnements est persistée dans `mms/subscriptions.json`.

**Reconnexion automatique** : en cas de perte de connexion avec un IED, le service relance automatiquement le thread avec un délai exponentiel (5 s initial, doublement à chaque échec, max 60 s).

### 3. CLI mmsctl

Le CLI appelle l’API du service (par défaut `http://localhost:7050` pour le service unifié).

```bash
# Créer un flux
python3 -m mms.mmsctl create --api-url http://127.0.0.1:7050 \
  --id flux-1 --ied-host 192.0.2.10 --ied-port 102 \
  --rcb-filter "CB_LDPX_*" --debug

# Lister les flux
python3 -m mms.mmsctl list --api-url http://127.0.0.1:7050

# Afficher un flux
python3 -m mms.mmsctl get flux-1 --api-url http://127.0.0.1:7050

# Mettre à jour (ex. filtre, debug)
python3 -m mms.mmsctl update flux-1 --api-url http://127.0.0.1:7050 --rcb-filter "CB_LDPX_*, CB_LDADD_*" --debug

# Supprimer
python3 -m mms.mmsctl delete flux-1 --api-url http://127.0.0.1:7050
```

Avec un service MMS standalone sur 8080 : `--api-url http://127.0.0.1:8080 --no-unified`.

## Service: RCB, libellés et déclencheurs

Le service s'appuie sur le client `iec61850.mms` de la librairie :

- **RCB** : le service lit les blocs dans le fichier SCL (`scl`) quand son IED correspond aux domaines de l'IED, sinon il les découvre par GetNameList. `domain` restreint à un logical device (vide : tous). `rcb_filter` choisit des blocs par motif sur leur nom sans numéro d'instance (`CB_LDPX_*, CB_LDADD_*`) ; l'ancien fichier `rcb_list` fonctionne encore. Le service prend une instance libre (ni activée, ni réservée par un autre client), la réserve (`ResvTms`), la configure et l'active, puis la désactive et la libère à l'arrêt du flux.
- **Libellés** : les membres des data sets et leurs types sont lus sur l'IED (GetNamedVariableListAttributes, GetVariableAccessAttributes). Le fichier SCL n'est plus nécessaire ; s'il est fourni, il sert de repli.
- **Déclencheurs** : `triggers` (`dchg`, `qchg`, `dupd`, `integrity`, `gi`, défaut `integrity,gi`) et `integrity_ms` (défaut 2000).
- **VictoriaMetrics** : mêmes séries qu'avant, `mms_report_value{rpt_id, data_set, member[, component]}`.

## Structure des fichiers

| Fichier | Rôle |
|---------|------|
| `scl_parser.py` | Parse SCL/ICD → mapping Data set → libellés FCDA (repli du service) |
| `reporting.py` | Plan d'abonnement, lignes VictoriaMetrics et texte des reports |
| `mms_service.py` | Service HTTP, gestion des flux (threads), persistance |
| `mms_api.py` | Handlers API pour intégration service unifié |
| `victoriametrics_push.py` | Envoi par lots des lignes Prometheus, POST /api/v1/import/prometheus |
| `mmsctl.py` | CLI HTTP (create, list, get, update, delete) |

## License

Copyright 2026 Florent Carli

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for the full text.
