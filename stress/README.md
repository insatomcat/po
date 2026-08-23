# Stress-test des nœuds (SSH + stress-ng)

Onglet **Stress** de `unified_ui.html` : connecte PO au nœud hôte (`ccv1`, `ccv2`, ou une adresse libre), découvre la topologie CPU via `seapath-alloc` (housekeeping, isolated, free logical, acteurs VM/IRQ/RT), lance `stress-ng` sur les cœurs choisis, et affiche la charge en direct.

Le but est de vérifier que l'isolation des VM (SSC600W sur ccv1, VMC7 sur ccv2) tient sous charge host, en regardant les latences dans l'onglet **GOOSE Listener**.

## Principe

1. PO se connecte en **SSH** (ou en local si le nœud est la machine qui exécute `po_service`).
2. Un script Python distant exécute `seapath-alloc` (sinon `isolcpus` / libvirt) et lit `/proc/stat`.
3. L'UI propose des presets : **housekeeping**, **isolés libres** (`Free logical`), **tous hors VM** (hors vCPU/vhost et leurs siblings HT).
4. `stress-ng` pinne le housekeeping en un masque, et chaque cœur isolé tout seul (`isolcpus` ignore un masque mixte). `seapath-run` si le cpuset SSH n'autorise pas le CPU.
5. La carte CPU et la courbe (stressés vs housekeeping vs VM) se mettent à jour chaque seconde.
6. L'utilisateur bascule sur **GOOSE Listener** pour voir si des Δ apparaissent.

Le stress continue si on change d'onglet. **Arrêter** (ou l'arrêt de `po_service`) tue `stress-ng`.

## Prérequis sur la cible

- `python3`
- `seapath-alloc` (recommandé, pour isolated / free / acteurs)
- `seapath-run` (si le cpuset SSH n'inclut pas les cœurs isolés)
- `stress-ng` (`apt install stress-ng` / `dnf install stress-ng`)
- Accès SSH clé (recommandé) ou mot de passe
- `virsh` si les VM sont gérées par libvirt (SEAPATH)

Depuis la machine qui héberge déjà PO (souvent `ccv1`), la connexion à `ccv1` est **locale** (pas de SSH). Cocher « Forcer SSH » si besoin.

## API (`/api/stress`)

| Méthode | Chemin | Rôle |
|---------|--------|------|
| GET | `/status` | Session courante, charge, historique |
| POST | `/connect` | `{host, port, user, identity, password, name, force_ssh}` |
| POST | `/start` | `{cpus, workloads, cpu_load, timeout_s, key}` |
| POST | `/stop` | `{key}` |
| POST | `/disconnect` | `{key, stop_stress}` (défaut : le stress continue) |
| GET/PUT | `/hosts` | Nœuds mémorisés (`stress/hosts.json`) |

Workloads : `cpu` (défaut), `cache`, `vm` (64 Mo / worker), `switch`.
