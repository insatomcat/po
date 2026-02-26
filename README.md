## Client MMS IEC 61850 en Python

Ce projet fournit un petit client MMS IEC 61850 en Python, empaqueté pour être
exécuté dans un conteneur (Docker/Podman).

### 1. Prérequis

- Python 3.11+ (si tu veux l'exécuter hors conteneur)
- Ou bien un moteur de conteneur compatible Docker (par exemple **Podman**)

### 2. Installation locale (sans conteneur)

```bash
pip install -r requirements.txt
python mms_client.py 192.168.1.100 102 "LD0/MMXU1.TotW"
```

### 3. Construction de l'image (Podman)

Depuis la racine du projet :

```bash
podman build -t mms-client .
```

### 4. Exécution du client avec Podman

**Réseau :** si le serveur IEC 61850 est sur le même réseau que la machine hôte
(par ex. 10.132.159.x), il faut utiliser le réseau de l’hôte, sinon le conteneur
ne peut pas joindre l’IP :

```bash
podman run --rm --network host mms-client 10.132.159.191
```

Sans `--network host`, le conteneur est isolé et la connexion échoue souvent
avec « Failed to connect … Error code: (None, 0) ».

#### 4.1 Lecture automatique de quelques valeurs

Le script se connecte à un serveur IEC 61850, parcourt une partie du modèle
et lit quelques valeurs :

```bash
podman run --rm --network host mms-client 192.168.1.100
```

Tu peux aussi préciser le port (par défaut 102) :

```bash
podman run --rm --network host mms-client 192.168.1.100 102
```

#### 4.2 Lecture d'objets spécifiques

Tu peux fournir une ou plusieurs références complètes d'objets IEC 61850
(par exemple `LD0/MMXU1.TotW`) :

```bash
podman run --rm --network host mms-client 192.168.1.100 102 "LD0/MMXU1.TotW"
podman run --rm --network host mms-client 192.168.1.100 "LD0/MMXU1.TotW.mag.f" "LD0/MMXU1.PhV.phsA.mag.f"
```

Si aucune référence n'est fournie, le script :

- découvre les logical devices,
- parcourt quelques logical nodes,
- parcourt quelques data objects,
- lit et affiche la valeur de chaque objet sélectionné.

#### 4.3 Récupérer les données en continu (polling)

Avec pyiec61850-ng on ne peut pas recevoir les reports (push) en Python, mais on peut **lire périodiquement** les mêmes points (polling) pour récupérer les données :

```bash
# Poll par références explicites
podman run --rm --network host --entrypoint python mms-client mms_poll.py 10.132.159.191 1 102 "VMC7_1BayLD/VECAMMXU1.A.phsA.cVal.mag.f" "VMC7_1BayLD/VECAMMXU1.A.phsB.cVal.mag.f"
```

**Données utiles d’un RCB (ex. CB_LDPX_DQPO01)** : poll du **DataSet** du RCB (même contenu qu’un report) :

```bash
# Si les $ sont tronqués (erreur "2 point(s)" avec --rcb dans l’en-tête), passer la réf par variable d’env :
MMS_POLL_RCB_REF='VMC7_1LD0 LLN0$BR$CB_LDPX_DQPO01' podman run --rm --network host -e MMS_POLL_RCB_REF --entrypoint python mms-client mms_poll.py 10.132.159.191 1 102 --rcb
```

Ou avec guillemets simples (selon le shell) :

```bash
podman run --rm --network host --entrypoint python mms-client mms_poll.py 10.132.159.191 1 102 --rcb 'VMC7_1LD0 LLN0$BR$CB_LDPX_DQPO01'
```

→ Lit le RCB pour récupérer la référence du DataSet, puis lit ce DataSet **toutes les 1 s** et affiche tous les membres (Ctrl+C pour arrêter).

#### 4.4 Reports (découverte et activation RptEna)

Le script `mms_reports.py` permet de découvrir les RCB et d’activer RptEna. Avec pyiec61850-ng, **on ne peut pas recevoir les reports en Python** (pas de callback). Pour les données en continu, utiliser le **polling** (4.3).

```bash
podman run --rm --network host --entrypoint python mms-client mms_reports.py 10.132.159.191 102
```

- Connexion, découverte des RCB (BRCB/URCB), affichage de la config ;
- activation de RptEna sur les RCB (format MMS avec espace si besoin) ;
- pas de réception des reports dans ce fork → utiliser `mms_poll.py` pour les données.

### 5. Remarques

- Le projet utilise la bibliothèque `pyiec61850-ng`, qui fournit des bindings
  Python pour `libiec61850` (MMS IEC 61850).
- Le conteneur est basé sur `python:3.11-slim` pour rester léger tout en étant
  compatible avec les roues binaires de `pyiec61850-ng`.

