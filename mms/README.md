# MMS – Client reports IEC 61850

Client MMS en Python pour **s’abonner aux reports** IEC 61850 et recevoir les données en push. Implémentation **sans bibliothèque GPL** : TPKT/COTP et encodage/décodage MMS en BER (ASN.1) dans le projet.

## Fonctionnalités

- Connexion TCP → TPKT (RFC 1006) → COTP classe 0 → MMS
- Initiate MMS, puis **GetRCBValues** + **SetRCBValues** (RptEna, options) pour chaque RCB
- Réception des **reports** (unconfirmed PDU [RPT] / informationReport)
- Décodage des entrées : en-tête (RptId, DataSet, SeqNum, TimeOfEntry, BufOvfl, …) et **membres du Data Set** (valeur, qualité, horodatage)
- Option **SCL/ICD** : chargement d’un fichier CID/SCL pour afficher les noms des membres (ex. `[8] LogOut10`, `[9] A.phsA`, `[12] Hz`)
- Push optionnel vers **VictoriaMetrics** pour Grafana

## Composants

| Élément | Rôle |
|--------|------|
| **Script client** | `test_client_reports.py` – connexion directe à un IED, affichage des reports (et option VM) |
| **Service HTTP** | `mms_service.py` – gestion de plusieurs flux (abonnements) par API, push VictoriaMetrics |
| **API** | `mms_api.py` – routes `/subscriptions`, `/recents`, `/logs` (SSE), utilisée par le service unifié |
| **CLI** | `mmsctl.py` – pilotage du service via HTTP (create, list, get, update, delete) |

## Prérequis

- **Python 3.10+**
- Aucune dépendance externe pour le cœur MMS (stdlib uniquement)

## Utilisation

### 1. Client en ligne de commande (test / démo)

Script principal : **`mms/test_client_reports.py`**

```bash
# Connexion à l’IED par défaut (host/port dans le script)
python3 -m mms.test_client_reports

# Host et port explicites
python3 -m mms.test_client_reports 10.132.159.191 102

# Avec domain ID (défaut : VMC7_1LD0)
python3 -m mms.test_client_reports --domain MON_IED_1LD0 10.132.159.191 102

# Avec fichier SCL/ICD pour les libellés des membres du data set
python3 -m mms.test_client_reports --scl ./IECS.cid 10.132.159.191 102

# Envoyer les valeurs des reports vers VictoriaMetrics (pour Grafana)
python3 -m mms.test_client_reports --victoriametrics-url http://localhost:8428 --scl ./IECS.cid

# Debug (PDU envoyés/reçus) et verbose (PDU brut + valeur brute des entrées)
python3 -m mms.test_client_reports --debug --verbose --scl ./IECS.cid
```

**Grafana** : pour afficher un point toutes les 2–4 s, dans le panneau → Query options → **Min step** = `2s` ou `1s`.

#### Options du client

| Option | Description |
|--------|-------------|
| `--debug` | Affiche les PDUs MMS envoyés et reçus (hex) |
| `--verbose` | PDU brut et valeur brute de chaque entrée de report |
| `--scl FICHIER` | Fichier SCL ou ICD pour les noms des membres (Beh, A.phsA, Hz, …) |
| `--domain ID` | Domain ID MMS (défaut : VMC7_1LD0) |
| `--victoriametrics-url URL` | Push des valeurs vers VictoriaMetrics (ex. http://localhost:8428) |
| `--vm-batch-ms MS` | Intervalle de batch VM en ms (défaut : 200) |
| `--vm-no-batch` | Une requête HTTP par report (legacy) |
| `host` | Adresse IP de l’IED (défaut : 10.132.159.191) |
| `port` | Port MMS (défaut : 102) |

### 2. Service HTTP (flux multiples)

Le service MMS peut tourner **standalone** ou être intégré au **service unifié** (port 7050). En mode unifié, l’API est préfixée par `/api/mms`.

**Standalone** (port 8080 par défaut) :

```bash
python3 mms/mms_service.py --port 8080 --victoriametrics-url http://localhost:8428
```

**Via service unifié** (recommandé) : lancer `po_service.py` à la racine ; les routes MMS sont sous `/api/mms/`.

#### API HTTP (résumé)

- **POST /subscriptions** – Créer un flux (ied_host, ied_port, domain, scl, rcb_list, debug)
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
  --id flux-1 --ied-host 10.132.159.191 --ied-port 102 \
  --domain VMC7_1LD0 --scl /chemin/ied.icd --debug

# Lister les flux
python3 -m mms.mmsctl list --api-url http://127.0.0.1:7050

# Afficher un flux
python3 -m mms.mmsctl get flux-1 --api-url http://127.0.0.1:7050

# Mettre à jour (ex. rcb-list, debug)
python3 -m mms.mmsctl update flux-1 --api-url http://127.0.0.1:7050 --rcb-list /nouveau/rcb.txt --debug

# Supprimer
python3 -m mms.mmsctl delete flux-1 --api-url http://127.0.0.1:7050
```

Avec un service MMS standalone sur 8080 : `--api-url http://127.0.0.1:8080 --no-unified`.

## Fichier SCL/ICD

Pour les libellés lisibles (`[8] LogOut10`, `[9] A.phsA`, etc.), fournir le **fichier CID** (Configured IED Description) de l’IED. Le script et le service utilisent `scl_parser.py` pour faire correspondre l’index d’entrée au nom du membre (Data set + FCDA).

## Structure des fichiers

| Fichier | Rôle |
|---------|------|
| `tpkt.py` | TPKT RFC 1006 (send/recv) |
| `cotp.py` | COTP classe 0 (connexion, send_data, recv_data) |
| `asn1_codec.py` | Encodage BER MMS (Initiate, GetRCBValues, SetRCBValues), décodage des reports |
| `mms_reports_client.py` | Client : TCP/COTP/MMS, Initiate, enable_reporting, loop_reports |
| `mms_report_processing.py` | Traitement des reports et push VictoriaMetrics |
| `scl_parser.py` | Parse SCL/ICD → mapping Data set → libellés FCDA |
| `mms_service.py` | Service HTTP, gestion des flux (threads), persistance |
| `mms_api.py` | Handlers API pour intégration service unifié |
| `victoriametrics_push.py` | Conversion report → Prometheus, POST /api/v1/import/prometheus |
| `test_client_reports.py` | Script client : abonnement RCB, affichage (et option VM) |
| `discover_reports.py` | Découverte des reports MMS disponibles sur un IED |
| `mmsctl.py` | CLI HTTP (create, list, get, update, delete) |

Les RCB abonnés en mode script sont définis dans `test_client_reports.py` (liste `ITEM_IDS`). En mode service, ils viennent de la config de chaque flux (fichier rcb_list ou liste intégrée).
