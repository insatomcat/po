# SV Listener View – Capture et visualisation SV

Application de **capture** et **visualisation** des paquets **Sampled Values (SV)** (IEC 61869-9, format 6I3U). Parse les phasors courants (Ia, Ib, Ic) et tensions (Va, Vb, Vc), affiche des cercles vectoriels (U et I) et fournit une **interface web** (Flask) pour les graphiques.

## Rôle

- Capturer les paquets SV sur une interface réseau (pcapy).
- Parser les ASDUs (smpCnt, courants et tensions).
- Afficher en terminal : résumé ASCII des phasors (optionnel).
- Servir une **Web UI** (Flask) : cercles U/I, stats, délais inter-paquets.
- Peut être utilisé **seul** (serveur Flask sur un port dédié) ou derrière le **service unifié** (proxy `/api/svview` quand `po_service.py` est lancé avec `--svview-interface`).

## Prérequis

- **Python 3.10+**
- **pcapy** : `pip install pcapy` (capture réseau ; sous Linux, droits root ou capabilities pour écouter sur une interface)
- **Flask** : `pip install flask` (interface web)

## Utilisation

Depuis la racine du dépôt (pour que les chemins et imports fonctionnent) :

```bash
# Capture sur eth0, interface web sur le port 8080
sudo python3 svlistener_view/sv_listener_view.py -i eth0 --web 8080
```

Options principales :

| Option | Description |
|--------|-------------|
| `-i`, `--interface` | Interface réseau (obligatoire pour la capture) |
| `--interval SEC` | Intervalle de rafraîchissement en secondes (défaut : 1) |
| `--window SEC` | Fenêtre pour les stats de délai inter-paquets (défaut : 10) |
| `--svid SVID` | Filtrer sur le svID ; si absent, affiche la liste des svIDs vus |
| `--web PORT` | Démarrer le serveur web Flask sur le port indiqué (ex. 8080) |

Sans `--web`, l’outil ne fait qu’afficher en console (liste des svIDs ou flux des phasors si `--svid` est donné).

## Intégration au service unifié

Pour afficher l’onglet « SV Listener » dans l’UI unifiée, lancer le service unifié avec l’**interface de capture** (pas un port) :

```bash
python3 po_service.py --port 7050 --svview-interface eth0
```

Le service unifié démarre alors **SV Listener View** en interne (Flask sur un port local), et proxifie **/api/svview/** vers ce serveur. Aucun lancement séparé de `sv_listener_view.py` n’est nécessaire.

En mode **standalone**, on lance le listener à la main (ex. pour un port web dédié) :

```bash
sudo python3 svlistener_view/sv_listener_view.py -i eth0 --web 8080
```

## Structure

| Fichier | Rôle |
|---------|------|
| `sv_listener_view.py` | Point d’entrée : capture pcapy, parsing SV (6I3U / 4I4U), calcul phasors, serveur Flask, templates |
| `templates/` | Templates HTML/Jinja2 pour la partie web |

Le script gère notamment :

- Décodage BER des ASDUs SV (smpCnt, données 6I+3U ou 4I+4U).
- Calcul des grandeurs pour les cercles (module, angle).
- Stats sur les délais entre paquets (fenêtre configurable).
- Routes Flask pour la page principale et les données (JSON) utilisées par les graphiques.

## Exemple systemd

Un exemple de unit systemd pour le listener est fourni dans `svgenerator/svlistener_view.service.example` (lancement avec uvicorn sur le port 7052). Adapter les chemins et l’interface selon l’environnement.
