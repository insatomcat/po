# SV Generator – Générateur de flux Sampled Values

Générateur de flux **Sampled Values (SV)** conforme à l’IEC 61869-9 (ex. 6I3U). Envoi de paquets SV sur une interface Ethernet (VLAN optionnel), avec paramètres temps-réel (fréquence, courants/tensions crête, mode défaut). Un **service API** (FastAPI) gère les flux de manière persistante ; un **CLI** (`svctl`) pilote l’API.

## Composants

| Élément | Rôle |
|--------|------|
| **Service** | `sv_service.py` – application FastAPI (flux, démarrage/arrêt des émetteurs), port 7051 en standalone |
| **API** | `sv_api.py` – handlers `/flows`, `/flows/recents`, `/flows/{name}` pour intégration au service unifié (préfixe `/api/sv`) |
| **CLI** | `svctl.py` – list, create, update, delete, clear vers l’API (base-url 7050 unifié ou 7051 standalone) |
| **Émetteur** | `rt_sender.c` compilé en binaire `rt_sender` – envoi temps-réel des paquets SV (appelé en sous-processus par le service) |

## Prérequis

- **Python 3.10+**
- Dépendances : voir `requirements.txt` (FastAPI, uvicorn, pydantic, requests ; pcapy et Flask pour d’autres outils du dossier)
- **rt_sender** : binaire compilé depuis `rt_sender.c` (C temps-réel), à placer dans le répertoire du service ou dans le PATH

## Installation

```bash
pip install -r requirements.txt
```

Pour le service seul (sans pcapy/Flask) : `fastapi`, `uvicorn`, `pydantic`, `requests` suffisent.

Compilation de l’émetteur temps-réel (exemple Linux) :

```bash
gcc -o rt_sender rt_sender.c -lrt
# Placer rt_sender dans svgenerator/ ou dans le PATH
```

## Utilisation

### 1. Service standalone (port 7051)

```bash
cd svgenerator
uvicorn sv_service:app --host 0.0.0.0 --port 7051
```

- **API** : `GET/POST /flows`, `GET/PUT/DELETE /flows/{name}`, `GET /flows/recents`
- Config persistée dans `flows.json` (dans le répertoire du service)

### 2. Via service unifié (port 7050)

En lançant `po_service.py` à la racine du dépôt, l’API SV est exposée sous **/api/sv/** (flows, recents). La Web UI unifiée propose l’onglet SV. Il n’est pas nécessaire de lancer uvicorn pour le SV dans ce cas.

### 3. CLI svctl

Par défaut le CLI cible `http://127.0.0.1:7050` (service unifié). Pour un service SV standalone sur 7051 : `--base-url http://127.0.0.1:7051`.

```bash
# Lister les flux
python3 svctl.py list
python3 svctl.py list -v   # détail (VLAN, APPID, confRev, fault, etc.)

# Créer un flux (appid et conf_rev obligatoires)
python3 svctl.py create monflux eth0 01:0c:cd:04:00:01 01:0c:cd:04:00:02 "SV_1" \
  --appid 0x4060 --conf-rev 10000 \
  --freq 50 --i-peak 10 --v-peak 100 --vlan-id 100

# Mettre à jour (appid et conf_rev obligatoires)
python3 svctl.py update monflux eth0 01:0c:cd:04:00:01 01:0c:cd:04:00:02 "SV_1" \
  --appid 0x4060 --conf-rev 10001 --fault

# Supprimer un flux
python3 svctl.py delete monflux

# Supprimer tous les flux
python3 svctl.py clear
```

Paramètres obligatoires pour `create`/`update` : `--appid`, `--conf-rev`.

Paramètres optionnels courants : `--smp-synch`, `--vlan-id`, `--vlan-priority`, `--freq`, `--i-peak`, `--v-peak`, `--phase`, `--fault`, `--fault-i-peak`, `--fault-v-peak`, `--fault-phase`, `--fault-cycle`.

### 4. Exécution directe du binaire `rt_sender`

`rt_sender` exige aussi `--appid` et `--conf-rev` (pas de valeur par défaut) :

```bash
./rt_sender --appid 0x4060 --conf-rev 10000 \
  --smp-synch 2 --vlan-id 100 --vlan-priority 4 \
  eth0 01:0c:cd:04:00:01 01:0c:cd:04:00:02 SV_1
```

## API (résumé)

- **GET /flows** – Liste des flux avec état (running, config)
- **POST /flows** – Création (name, interface, src_mac, dst_mac, svid, appid, conf_rev, + options)
- **GET /flows/recents** – Derniers événements (démarrage/arrêt, etc.)
- **PUT /flows/{name}** – Mise à jour (ré démarre le processus avec la nouvelle config)
- **DELETE /flows/{name}** – Suppression et arrêt du flux
- **DELETE /flows** – Suppression de tous les flux (svctl clear)

## Fichiers du dossier

| Fichier | Rôle |
|---------|------|
| `sv_service.py` | FastAPI app, modèles FlowConfig/FlowState, gestion processus rt_sender, persistance |
| `sv_api.py` | Handlers API (handle_sv, init_sv_api) pour service unifié |
| `svctl.py` | CLI (list, create, update, delete, clear) |
| `rt_sender.c` | Source C de l’émetteur SV temps-réel (compilé en `rt_sender`) |
| `receiver.py` | Réception / test de paquets SV (outil associé) |
| `sv_receiver_delay.py` | Mesure de délai / réception (outil associé) |
| `sv_counter3.py` | Compteur / génération (outil associé) |
| `parse_ref_pkt.py` | Parsing de paquets de référence (débogage) |
| `flows.json` | (généré) configuration persistée des flux |
| `recents.json` | (généré) derniers événements |
| `svgenerator.service.example` | Exemple unit systemd pour le service |
| `svlistener_view.service.example` | Exemple unit systemd pour SV Listener View |
