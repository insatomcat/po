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

### 5. Remarques

- Le projet utilise la bibliothèque `pyiec61850-ng`, qui fournit des bindings
  Python pour `libiec61850` (MMS IEC 61850).
- Le conteneur est basé sur `python:3.11-slim` pour rester léger tout en étant
  compatible avec les roues binaires de `pyiec61850-ng`.

