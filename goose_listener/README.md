# GOOSE Listener – Mesure des délais de déclenchement

Module PO pour **écouter les GOOSE** sur le bus process, **détecter les déclenchements** (changement d’état relais), mesurer le **délai net Δ** entre la réception du GOOSE et la « seconde pile » (frontière de seconde UNIX), et signaler les **anomalies** (délai hors seuil, défauts manquants).

Intégré dans **`po_service`** (onglet **GOOSE Listener** de `unified_ui.html`) et utilisable en **CLI** via `goose/examples/listen_goose.py`.

---

## Objectif métier

Sur un relais type SSC600, chaque **défaut** envoie un GOOSE de déclenchement vers ~**24 ms** dans la seconde (offset par rapport à la pile SV). L’objectif est de vérifier que ce délai reste dans une marge (ex. **< 40 ms**) et que les défauts arrivent au **cycle attendu** (ex. toutes les **4 s** sur LDPX_GSI_DEP5).

Le listener ne remplace pas une analyse réseau complète : il agrège capture, mesure et alertes pour le diagnostic opérationnel.

---

## Principe de mesure

### Timestamp de référence

Le Δ est calculé à partir du **timestamp libpcap** (`pkt.time`) à la réception de la trame, **pas** à l’heure de traitement Python (évite une dérive artificielle si la file de capture sature).

### Formule

```
ts_rx     = instant de réception (seconde fractionnaire)
ts_pile   = floor(ts_rx)          # début de la seconde UNIX (« seconde pile »)
Δ brut    = (ts_rx - ts_pile) × 1000   (en ms)
Δ net     = Δ brut - temporisation_ms
```

La **temporisation** (ms) est configurable par flux analysé (protection / paramètre relais à soustraire).

### Exemple typique (LDPX_GSI_DEP5_B)

| Événement | Fraction dans la seconde | Δ net (~) |
|-----------|--------------------------|-----------|
| Défaut (sqNum=0) | `.023` | ~24 ms |
| Fin défaut | `.136` | ~136 ms (normal, pas une anomalie de déclenchement) |
| Retransmission sqNum=4 seule | `.131` | ~131 ms → **sqNum≠0**, indique des paquets ratés en capture |

---

## Détection d’un déclenchement

Un **déclenchement GOOSE** est détecté quand :

1. **`stNum` augmente** (nouvel état sur le GCB)
2. Et **`sqNum == 0`** (première trame de la rafale IEC 61850)

### Mode tolérant (`lenient`)

En capture, le **`sqNum=0`** est parfois perdu (rafale 0→3 en quelques ms). Le mode tolérant accepte alors le **premier cadre vu** d’un nouveau `stNum` comme déclenchement.

- Utilisé par le **service** (`goose_listener_service`) et le CLI en `--problem-diag`
- Le panneau **Problèmes** affiche le **`sqNum`** utilisé : si **≠ 0**, la mesure Δ n’est pas fiable (paquets manqués)

### Classification Défaut / Fin défaut

Via `trigger_classify.py`, comparaison du **`allData`** avec le snapshot précédent sur le même flux :

| Transition `allData` | Type |
|----------------------|------|
| `bool` false → true (ou entier 0 → ≠0) | **Défaut** |
| `bool` true → false (ou entier ≠0 → 0) | **Fin défaut** |
| Premier événement | **Premier** |
| Les deux sens | **Mixte** |
| Rien de discriminant | **Inconnu** |

Les alertes **Δ > seuil** et la détection de **manquants** ne portent que sur les événements **Défaut**.

---

## Architecture

```
goose_listener/
├── goose_listener_service.py   # Capture, scan, analyse, histogramme, problèmes
├── goose_listener_api.py       # Routes REST pour po_service
├── trigger_classify.py         # Classification défaut / fin défaut
└── README.md                   # Ce fichier

goose/goose61850/transport.py   # GooseSubscriber (BPF, file, AsyncSniffer)
goose/examples/listen_goose.py  # CLI diagnostic et écoute
unified_ui.html                 # Onglet GOOSE Listener
```

### Capture réseau

- Interface : celle passée à `po_service` via **`--svview-interface`** (souvent `processbus`)
- **Filtre BPF kernel** : trames GOOSE uniquement (`0x88b8`), optionnellement par **APPID**
- **AsyncSniffer** + **file d’attente** : une seule session libpcap continue (évite les trous entre redémarrages `sniff`)
- Le timestamp de mesure vient de **`pkt.time`**

### Modes du gestionnaire

| Mode | Comportement |
|------|----------------|
| `idle` | Pas de traitement (capture peut s’arrêter) |
| `scan` | Compte les trames par `(gocbRef, goID)` pendant N secondes |
| `analyze` | Mesure Δ et détecte problèmes sur les cibles sélectionnées |

---

## Activation

Le GOOSE Listener est activé automatiquement quand `po_service` est lancé avec une interface réseau :

```bash
python3 po_service.py --svview-interface processbus --port 7050
```

Ou via le service systemd (`po-service.service`) avec `SVVIEW_INTERFACE=processbus`.

Sans `--svview-interface` : l’onglet affiche « non configuré » et l’API répond **503**.

---

## Interface web (onglet GOOSE Listener)

### Découverte

- **Scan** : écoute tous les GOOSE pendant une durée (défaut 5 s), liste les flux vus
- Filtre de recherche (gocbRef, goID, APPID)
- Bouton **Masquer / Afficher** pour replier le panneau
- Sélection → **Ajouter la sélection** vers la liste d’analyse

### Analyse

- Cibles : `(gocbRef, goID, temporisation_ms)`
- Filtre d’affichage : **défauts seuls** ou **tous les événements**
- **Lancer / Arrêter** l’analyse

### Problèmes

Paramètres :

| Paramètre | Défaut | Rôle |
|-----------|--------|------|
| Cycle défaut (s) | 4 | Intervalle attendu entre deux **Défaut** consécutifs |
| Seuil Δ (ms) | 40 | Alerte si Δ net > seuil (sur **sqNum=0** uniquement) |

Types d’anomalies :

- **`delay_exceeded`** : Δ net > seuil sur un défaut (colonne **sqNum** : 0 = OK, ≠0 = capture incomplète)
- **`missing`** : trou dans le cycle défaut ; détail des GOOSE reçus entre les deux défauts

Affichage : **50 derniers** problèmes, **~10 lignes visibles** avec défilement.  
Bouton **Télécharger (.txt)** : export de **tous** les problèmes calculés.

### Histogramme & derniers événements

- L’API expose `histogram_series` : liste des **Δ bruts** par flux (`values[]`). L’**agrégation en barres** (pas 1 ms) est faite dans le navigateur (`glBuildHistogram` dans `unified_ui.html`), pas dans `po_service`.
- **50 derniers** événements en mémoire affichés, **~10 lignes visibles** avec scroll
- Bouton **Télécharger (.txt)** : export de **tous** les événements en RAM (jusqu’à 10 000)

### Métriques de debug (API `/status`)

```json
"capture": {
  "queue_size": 0,
  "drops": 0
}
```

- `queue_size` élevé → traitement en retard
- `drops` > 0 → paquets GOOSE perdus (file pleine)

Chaque événement expose aussi `processing_lag_ms` (écart traitement − réception pcap).

---

## Stockage en mémoire

| Structure | Capacité | Persistance |
|-----------|----------|-------------|
| `_events` | **10 000** événements max (`deque`) | RAM uniquement |
| Panneau UI | 50 derniers affichés | — |
| Export `.txt` | Tout le contenu de `_events` | Téléchargement navigateur |

- **Nouvelle analyse** → historique effacé
- **Redémarrage `po_service`** → tout perdu
- Pas de fichier ni base de données

---

## API REST

Base : **`/api/gooselistener`**

| Méthode | Chemin | Description |
|---------|--------|-------------|
| GET | `/status` | État global (scan + analyse + `capture.queue_size` / `drops`) |
| POST | `/scan` | Démarre un scan `{ "duration_s": 5 }` |
| GET | `/scan` | État du scan |
| POST | `/analysis/start` | Démarre l’analyse (voir corps ci-dessous) |
| POST | `/analysis/stop` | Arrête l’analyse |
| GET | `/analysis` | État analyse (événements, histogramme, problèmes) |
| POST | `/analysis/filter` | `{ "event_filter": "defauts_only" \| "all" }` |
| POST | `/analysis/problems` | `{ "cycle_s": 4, "threshold_ms": 40 }` |
| GET | `/analysis/events/export` | Téléchargement texte de tous les événements en RAM |
| GET | `/analysis/problems/export` | Téléchargement texte de tous les problèmes |

### Exemple : démarrer une analyse

```bash
curl -s -X POST http://127.0.0.1:7050/api/gooselistener/analysis/start \
  -H 'Content-Type: application/json' \
  -d '{
    "event_filter": "defauts_only",
    "targets": [
      {
        "gocb_ref": "SSC600SW_BLD0/LLN0$GO$CB_LDPX_GSI_DEP5",
        "go_id": "LDPX_GSI_DEP5_B",
        "delay_ms": 0
      }
    ]
  }'
```

Configurer les problèmes au démarrage ou en cours :

```bash
curl -s -X POST http://127.0.0.1:7050/api/gooselistener/analysis/problems \
  -H 'Content-Type: application/json' \
  -d '{"cycle_s": 4, "threshold_ms": 40}'
```

---

## CLI `listen_goose.py`

Chemin : `goose/examples/listen_goose.py`

### Écoute simple (filtres affichage)

```bash
python3 goose/examples/listen_goose.py processbus \
  --app-id 0x150A \
  --go-id 'LDPX_GSI_DEP5_B' \
  --sqnum-zero --bool-true
```

`--sqnum-zero` et `--bool-true` filtrent l’**affichage** uniquement ; la capture traite toujours toutes les trames correspondant au BPF.

### Mesure des délais

```bash
python3 goose/examples/listen_goose.py processbus \
  --app-id 0x150A \
  --gocb-ref 'SSC600SW_BLD0/LLN0$GO$CB_LDPX_GSI_DEP5' \
  --go-id 'LDPX_GSI_DEP5_B' \
  --measure-delay --triggers-only
```

### Diagnostic anomalies (capture directe)

```bash
python3 goose/examples/listen_goose.py processbus \
  --app-id 0x150A \
  --gocb-ref 'SSC600SW_BLD0/LLN0$GO$CB_LDPX_GSI_DEP5' \
  --go-id 'LDPX_GSI_DEP5_B' \
  --problem-diag --problem-cycle 4 --problem-threshold 40
```

Silencieux si OK ; alertes compactes sur Δ > seuil ; rapport détaillé sur manquants.

### Audit des rafales sqNum

```bash
python3 goose/examples/listen_goose.py processbus \
  --app-id 0x150A --go-id 'LDPX_GSI_DEP5_B' \
  --measure-delay --audit-triggers
```

Vérifie pour chaque `stNum` si `sqNum=0` est bien reçu en premier.

### Mode API (GUI déjà active)

Quand `po_service` capture déjà `processbus`, **ne pas** lancer une deuxième capture CLI (conflit libpcap → trames perdues). Utiliser :

```bash
python3 goose/examples/listen_goose.py processbus \
  --from-api http://127.0.0.1:7050 --problem-diag
```

Même source de problèmes que l’onglet GUI.

### Options CLI utiles

| Option | Description |
|--------|-------------|
| `--app-id 0x150A` | Filtre BPF + logiciel (fortement recommandé sur `processbus`) |
| `--measure-delay` | Calcule Δ net sur déclenchements |
| `--triggers-only` | N’affiche que les déclenchements (pas les retransmissions) |
| `--problem-diag` | Mode diagnostic silencieux |
| `--problem-cycle` | Cycle défaut attendu (s) |
| `--problem-threshold` | Seuil Δ (ms) |
| `--from-api URL` | Lit les problèmes via `po_service` |
| `--sqnum-zero` / `--bool-true` | Filtres affichage |

---

## Capture : bonnes pratiques et dépannage

### Un seul consommateur sur `processbus`

Deux captures GOOSE simultanées (GUI + CLI direct) se partagent mal la socket : une peut recevoir **zéro** trame. Préférer **`--from-api`** si l’analyse GUI tourne.

### Perte de paquets dans la rafale (sqNum 0–3)

Symptômes :

- Seul **sqNum=4** visible (~131 ms)
- Trous dans la séquence `stNum` (cycles entiers manquants)

Vérification :

```bash
# Référence kernel (indépendante de Python)
tcpdump -i processbus -nn -t \
  'ether proto 0x88b8 and ether[14:2]=0x150a'
```

Si `tcpdump` voit sqNum 0–4 mais pas le CLI → optimiser la stack PO (BPF, `--app-id`, pas de double capture).  
Si `tcpdump` aussi ne voit que sqNum=4 → surcharge interface / buffers kernel.

### Cycle défaut vs intervalle GOOSE

Sur LDPX, un **GOOSE** (défaut + fin défaut) peut arriver toutes les **~2 s**, mais un **défaut** seulement toutes les **~4 s**.  
Le paramètre **cycle défaut** doit refléter l’intervalle entre **Défaut**, pas entre tous les GOOSE.

### Faux Δ ~130 ms

Souvent :

- Mesure sur **sqNum=4** (paquets 0–3 perdus) → vérifier colonne **sqNum** dans Problèmes
- Ancienne dérive `time.time()` au traitement → corrigé avec `pkt.time` (redéployer `po_service`)

---

## Dépendances

- **scapy** (capture GOOSE via `GooseSubscriber`)
- **goose61850** (décodage PDU, dans `goose/`)
- **iec_data.py** (types `allData`, racine du dépôt)
- Même interface réseau que le SV Listener (`--svview-interface`)

---

## Fichiers liés

| Fichier | Rôle |
|---------|------|
| [po_service.py](../po_service.py) | Monte l’API `/api/gooselistener/*` |
| [unified_ui.html](../unified_ui.html) | Onglet GOOSE Listener |
| [goose/examples/listen_goose.py](../goose/examples/listen_goose.py) | CLI |
| [goose/goose61850/transport.py](../goose/goose61850/transport.py) | Capture (BPF, file, `run_until`) |
