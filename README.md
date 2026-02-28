# Client MMS IEC 61850 – Reports

Client MMS en Python pour **s’abonner aux reports** IEC 61850 et recevoir les données en push. Implémentation **sans bibliothèque GPL** : TPKT/COTP et encodage/décodage MMS en BER (ASN.1) dans le projet.

## Fonctionnalités

- Connexion TCP → TPKT (RFC 1006) → COTP classe 0 → MMS
- Initiate MMS, puis **GetRCBValues** + **SetRCBValues** (RptEna, options) pour chaque RCB
- Réception des **reports** (unconfirmed PDU [RPT] / informationReport)
- Décodage des entrées : en-tête (RptId, DataSet, SeqNum, TimeOfEntry, BufOvfl, …) et **membres du Data Set** (valeur, qualité, horodatage)
- Option **SCL/ICD** : chargement d’un fichier CID/SCL pour afficher les noms des membres (ex. `[8] LogOut10`, `[9] A.phsA`, `[12] Hz`)

## Prérequis

- **Python 3.10+**
- Aucune dépendance externe : tout tourne avec la stdlib, sans conteneur ni `pip install`

## Utilisation

Script principal : **`test_client_reports.py`**

```bash
# Connexion à l’IED par défaut (host/port dans le script)
python3 test_client_reports.py

# Host et port explicites
python3 test_client_reports.py 10.132.159.191 102

# Avec domain ID (défaut : VMC7_1LD0)
python3 test_client_reports.py --domain MON_IED_1LD0 10.132.159.191 102

# Avec fichier SCL/ICD pour les libellés des membres du data set
python3 test_client_reports.py --scl ./IECS.cid 10.132.159.191 102

# Envoyer les valeurs des reports vers VictoriaMetrics (pour Grafana)
python3 test_client_reports.py --victoriametrics-url http://localhost:8428 --scl ./IECS.cid

# Debug (PDU envoyés/reçus) et verbose (PDU brut + valeur brute des entrées)
python3 test_client_reports.py --debug --verbose --scl ./IECS.cid
```

**Grafana : afficher un point toutes les 2–4 s**  
Par défaut Grafana utilise un « step » d’environ 15 s, donc un seul point par tranche. Pour voir tous les points poussés (toutes les 2–4 s) : dans le panneau, onglet **Query** → options de la requête (icône engrenage ou « Query options ») → **Min step** = `2s` ou `1s`. Vous pouvez aussi réduire l’intervalle dans « Resolution » si disponible.

### Options

| Option | Description |
|--------|-------------|
| `--debug` | Affiche les PDUs MMS envoyés et reçus (hex) |
| `--verbose` | Affiche le PDU brut et la valeur brute de chaque entrée de report |
| `--scl FICHIER` | Fichier SCL ou ICD (ex. IECS.cid) pour afficher les noms des membres (Beh, A.phsA, Hz, …) |
| `--domain ID` | Domain ID MMS (défaut : VMC7_1LD0) |
| `--victoriametrics-url URL` | Envoyer les valeurs des reports vers VictoriaMetrics (ex. http://localhost:8428) |
| `--vm-batch-ms MS` | Intervalle de batch VM en ms (défaut : 200). Une requête HTTP par intervalle ou dès 500 lignes. |
| `--vm-no-batch` | Désactiver le batching : une requête HTTP par report (comportement legacy). |
| `host` | Adresse IP de l’IED (défaut : 10.132.159.191) |
| `port` | Port MMS (défaut : 102) |

### Exemple de sortie (avec --scl)

```
REPORT reçu :
  RptId       : LDPHAS1_CYPO_DEP1
  DataSet     : VMC7_1LD0/LLN0$DS_LDPHAS1_CYPO
  SeqNum      : 1
  TimeOfEntry : 1984-12-04T04:08:33.234970+00:00
  BufOvfl     : False
  Entries (24) :
    [0] RptId: LDPHAS1_CYPO_DEP1
    ...
    [8] LogOut10: value=False  quality=030000
    [9] A.phsA: value=[[0.0], [0.0]]  quality=030000
    [12] Hz: value=[50.0]  quality=034000  time=2040-02-27T22:07:25+00:00
    [16] qualité(LogOut10): 0208 (good)
    [17] qualité(A.phsA): 0208 (good)
```

Les RCB abonnés sont définis dans `test_client_reports.py` (liste `ITEM_IDS`). Les PDU qui ne sont pas des reports (ex. autres types MMS) sont affichés en une ligne : `[PDU non décodé, N octets]`.

## Fichier SCL/ICD

Pour avoir des libellés lisibles (`[8] LogOut10`, `[9] A.phsA`, etc.), fournir le **fichier CID** (Configured IED Description) de l’IED, en général dans la config de l’appareil (ex. `/etc/cap/ied-1/config/IECS.cid`). Le script parse les DataSet et leurs FCDA pour faire correspondre l’index d’entrée au nom du membre.

## Structure du projet

| Fichier | Rôle |
|---------|------|
| `tpkt.py` | TPKT RFC 1006 (send/recv) |
| `cotp.py` | COTP classe 0 (connexion, send_data, recv_data) |
| `asn1_codec.py` | Encodage BER MMS (Initiate, GetRCBValues, SetRCBValues), décodage des reports (listOfAccessResult → MMSReport) |
| `mms_reports_client.py` | Client : connexion TCP/COTP/MMS, Initiate, enable_reporting (Get + 8× SetRCBValues), loop_reports |
| `scl_parser.py` | Parse SCL/ICD pour extraire DataSet et FCDA → mapping nom du data set → liste de libellés |
| `test_client_reports.py` | Script de test : abonnement à une liste de RCB, affichage des reports (avec ou sans --scl), option --victoriametrics-url |
| `victoriametrics_push.py` | Conversion report → format Prometheus (avec timestamp) et POST vers /api/v1/import/prometheus |
