# veille-cyber

Outil personnel et auto-hébergé de veille en cybersécurité :

1. **Agrégation RSS** avec [FreshRSS](https://freshrss.org/) (CERT-FR, CISA,
   presse spécialisée…).
2. **À terme** : un digest hebdomadaire des vulnérabilités prioritaires,
   construit en croisant CISA KEV, EPSS, NVD et CERT-FR.

Le tout tourne sur une stack Docker/Podman, avec un déploiement Ansible prévu.

## État du projet

- [x] FreshRSS conteneurisé (compose compatible Docker et Podman)
- [x] Liste de flux d'exemple (OPML)
- [x] CI : scan de secrets (gitleaks), validation compose, tests Python
- [x] Pipeline de collecte : CISA KEV → flux Atom lisible par FreshRSS
- [x] Collecte automatique en production (services `collector` et `feed`)
- [ ] Pipeline de collecte : EPSS (FIRST), NVD, CERT-FR
- [ ] Priorisation des CVE et digest hebdomadaire en Markdown
- [x] Tests sur jeux de données figés
- [x] Environnement de développement Docker (`compose.dev.yml`)
- [ ] Déploiement Ansible (et ansible-lint en CI)
- [ ] Accès mobile via l'API Google Reader (reverse proxy HTTPS)

## Structure du dépôt

```
.
├── compose.yml                 # Production : FreshRSS, collecte automatique, flux
├── compose.dev.yml             # Environnement de dev (FreshRSS + flux + Python)
├── docker/
│   ├── collector/Dockerfile    # Image de prod du pipeline de collecte
│   ├── python/Dockerfile       # Dev : Python + pytest
│   └── freshrss/               # Dev : FreshRSS préinstallé, abonné au flux de dev
├── .env.example                # Variables à copier dans .env
├── pyproject.toml              # Paquet Python veille-cyber
├── config/
│   └── feed.example.opml       # Flux d'exemple à importer
├── src/veille_cyber/
│   ├── __main__.py             # CLI : python -m veille_cyber run | loop
│   ├── sources/kev.py          # Collecte du catalogue CISA KEV
│   ├── items.py                # Modèle, fusion et purge des CVE retenues
│   ├── state.py                # État persistant (state.json)
│   └── feed.py                 # Génération du flux Atom
├── tests/                      # Tests pytest + jeux de données figés
└── .github/workflows/ci.yml    # Tests, gitleaks, validation compose
```

## Prérequis

- Docker avec le plugin Compose v2, **ou** Podman avec `podman compose`.
- Pour le pipeline hors Docker : Python ≥ 3.11 (aucune dépendance à
  l'exécution, `pytest` pour les tests).

## Démarrage rapide

```sh
cp .env.example .env
docker compose up -d   # ou : podman compose up -d
```

Le premier `up` construit l'image du pipeline de collecte, puis démarre trois
services :

| Service     | Rôle                                                                |
| ----------- | ------------------------------------------------------------------- |
| `freshrss`  | Le lecteur RSS, sur http://127.0.0.1:8080                            |
| `collector` | Lance le pipeline au démarrage, puis toutes les `COLLECT_INTERVAL_HOURS` heures |
| `feed`      | Sert le flux généré à FreshRSS (`http://feed:8000/feed.xml`), sans port exposé sur l'hôte |

Ensuite :

1. Ouvrir http://127.0.0.1:8080 (ou le port défini dans `.env`).
2. Suivre l'assistant d'installation de FreshRSS (langue, base SQLite,
   création du compte administrateur).
3. Importer les flux : *Abonnements → Importer / exporter* →
   `config/feed.example.opml`. Ce fichier contient aussi le flux
   « veille-cyber — CVE prioritaires », alimenté automatiquement par le
   service `collector`.

> Le port n'est exposé que sur `127.0.0.1`. Pour un accès distant, passer par
> un reverse proxy HTTPS ou un tunnel SSH plutôt que d'ouvrir le port.

## Configuration

Variables lues depuis `.env` (jamais versionné) :

| Variable        | Exemple        | Rôle                                                    |
| --------------- | -------------- | ------------------------------------------------------- |
| `FRESHRSS_TAG`  | `latest`       | Tag de l'image `freshrss/freshrss` (épingler une version de préférence) |
| `FRESHRSS_PORT` | `8080`         | Port local d'écoute (lié à `127.0.0.1`)                 |
| `TZ`            | `Europe/Paris` | Fuseau horaire du conteneur                             |
| `CRON_MIN`      | `1,31`         | Minutes de chaque heure où les flux sont rafraîchis     |
| `COLLECT_INTERVAL_HOURS` | `6`   | Intervalle entre deux collectes du pipeline (défaut : 6) |

## Pipeline de collecte

`python -m veille_cyber run` exécute une collecte :

1. télécharge le catalogue [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) ;
2. retient les CVE ajoutées depuis la dernière exécution réussie (7 jours lors
   de la première), ainsi que les CVE déjà suivies, pour détecter un
   changement comme le passage au statut « utilisée par des rançongiciels » ;
3. fusionne avec l'état existant, purge les CVE inchangées depuis trop
   longtemps ;
4. écrit le flux Atom `feed/feed.xml` puis l'état `state.json`, de façon
   atomique. L'état n'avance que si tout a réussi : un run en échec sera
   rattrapé par le suivant.

Les données sont écrites dans `$XDG_DATA_HOME/veille-cyber`
(par défaut `~/.local/share/veille-cyber`).

| Option             | Défaut | Rôle                                                         |
| ------------------ | ------ | ------------------------------------------------------------ |
| `--data-dir`       | voir ci-dessus | Dossier de l'état et du flux                         |
| `--initial-days`   | `7`    | Fenêtre de la toute première exécution (jours)               |
| `--max-entries`    | `200`  | Nombre maximal d'entrées dans le flux                        |
| `--retention-days` | `90`   | Purge de l'état les CVE non modifiées depuis N jours (`0` = jamais) |
| `--kev-file`       | —      | Catalogue KEV local, pour travailler hors ligne              |

Les entrées KEV mal formées sont ignorées avec un avertissement. Un catalogue
dont le format est inattendu fait échouer le run, sans toucher à l'état.

`python -m veille_cyber loop` accepte les mêmes options et exécute `run` en
boucle : une première fois immédiatement, puis toutes les `--interval-hours`
(défaut : 6). Un run en échec est journalisé et retenté après
`--retry-minutes` (défaut : 30), sans arrêter la boucle. C'est la commande du
service `collector`.

**En production**, le service `collector` écrit dans le volume `pipeline`
(`state.json` et `feed/feed.xml`). Le service `feed` le monte en lecture seule et
ne sert que le dossier `feed/`. FreshRSS lit le flux via le réseau interne de
compose : `INTERNAL_HOST_ALLOWLIST` l'autorise à joindre `feed:8000` et aucun
autre hôte privé. Les deux services tournent sans privilège (utilisateur non
root, système de fichiers en lecture seule, aucune capability).

```sh
docker compose logs -f collector   # suivre les collectes
```

## Développement avec Docker

`compose.dev.yml` fournit un environnement de dev complet, indépendant de
la production (projet compose `veille-cyber-dev`, aucun volume partagé) :

| Service    | Rôle                                                                 |
| ---------- | -------------------------------------------------------------------- |
| `freshrss` | FreshRSS jetable sur http://127.0.0.1:8088 (image `docker/freshrss/`) : installé au démarrage, **sans mot de passe**, déjà abonné au flux de dev |
| `collector`| Collecte automatique, comme en prod (même image `docker/collector/`) : un run au démarrage puis toutes les heures, dans `.dev-data/`. Le code de `src/` est monté : `dc restart collector` après une modification |
| `feed`     | Sert `.dev-data/feed/` : `http://feed:8000/feed.xml` pour FreshRSS, http://127.0.0.1:8000/feed.xml depuis l'hôte |
| `python`   | Outil ponctuel (profil `tools`, image `docker/python/`) : Python + pytest, code monté dans `/app`, lancé avec ton UID |

Toutes les données de dev vont dans `.dev-data/` (ignoré par Git).

L'intervalle de collecte du dev se règle avec `DEV_COLLECT_INTERVAL_HOURS`
(défaut : `1`) et `DEV_COLLECT_RETRY_MINUTES` (défaut : `5`), à exporter avant
`dc up`.

**Mise en place** (une seule fois)

```sh
mkdir -p .dev-data/feed   # avant le premier `up`, sinon Docker le crée en root
docker compose -f compose.dev.yml --profile tools build
```

Reconstruire avec la même commande après toute modification dans `docker/`
(par exemple pour monter la version de pytest).

**Au quotidien**

```sh
# Alias pratique (bash/zsh ; en fish : alias dc 'docker compose -f compose.dev.yml')
alias dc='docker compose -f compose.dev.yml'

dc up -d                                                      # stack complète, collecte auto
dc logs -f collector                                          # suivre les collectes
dc run --rm python python -m pytest                          # tests
dc run --rm python python -m veille_cyber run \
    --data-dir /app/.dev-data                                 # collecte réelle
dc run --rm python python -m veille_cyber run \
    --data-dir /app/.dev-data \
    --kev-file tests/fixtures/kev_sample.json --initial-days 100000   # hors ligne
```

Les runs manuels (`dc run --rm python …`) écrivent dans le même `.dev-data/`
que le service `collector`. Pour tester avec le jeu figé sans qu'une collecte
automatique l'écrase, arrêter d'abord le collector : `dc stop collector`.

**Voir le flux dans FreshRSS**

```sh
dc up -d
```

Ouvrir http://127.0.0.1:8088 : rien à configurer, le flux « veille-cyber —
CVE prioritaires » est déjà là. FreshRSS de dev relit chaque flux au plus
5 minutes après sa dernière lecture (1 h par défaut en prod). Pour voir
les nouvelles entrées tout de suite après une collecte, cliquer sur *Actualiser*.

Ce qui est automatisé par `docker/freshrss/` :

- installation (SQLite, utilisateur `admin`, authentification désactivée,
  flux relus toutes les 5 minutes) ;
- import de `docker/freshrss/dev-feeds.opml`, une seule fois par conteneur ;
- autorisation de l'hôte `feed:8000`. FreshRSS bloque par défaut les adresses
  privées (protection anti-SSRF, erreur *URL is not allowed to be resolved*) ;
  la variable `INTERNAL_HOST_ALLOWLIST` lève ce blocage pour ce seul hôte.

> Ces réglages sont réservés au dev : ne pas les reprendre dans `compose.yml`.

**Repartir de zéro**

```sh
dc down                                     # FreshRSS de dev n'a pas de volume : réinstallé au prochain `up`
rm -rf .dev-data/state.json .dev-data/feed/*
```

> Le conteneur `python` tourne avec l'UID/GID `1000` par défaut. Si ton
> utilisateur a un autre UID, exporter `UID` et `GID` avant les commandes :
> `export UID GID=$(id -g)` en bash, `set -x UID (id -u); set -x GID (id -g)`
> en fish.
> Les montages portent l'option `:z` pour SELinux (Fedora, RHEL…).

## Exploitation

**Mise à jour**

```sh
docker compose pull && docker compose up -d --build
```

`--build` reconstruit l'image du collector après un `git pull`.

**Sauvegarde des données** (volume `data` : base, configuration, utilisateurs ;
le volume `pipeline` peut se sauvegarder de la même façon, mais il se reconstruit
en partie seul : un état perdu repart sur les 7 derniers jours)

```sh
docker compose stop
docker run --rm -v veille-cyber_data:/data:ro -v "$PWD":/backup alpine \
  tar czf /backup/freshrss-data-$(date +%F).tgz -C /data .
docker compose start
```

Le nom exact du volume dépend du nom du projet compose : vérifier avec
`docker volume ls`.

**Logs**

```sh
docker compose logs -f freshrss
```

## CI

À chaque push et pull request, GitHub Actions :

- lance les tests Python (`pytest`, Python 3.11) ;
- scanne l'historique Git complet à la recherche de secrets (gitleaks) ;
- valide la syntaxe de `compose.yml` et `compose.dev.yml` avec `.env.example` ;
- construit l'image du service `collector`.

## Sources de données et attributions

- **CISA KEV** : CC0.
- **EPSS** : FIRST demande une attribution. Voir https://www.first.org/epss
- **NVD** : mention requise — *« This product uses data from the NVD API but
  is not endorsed or certified by the NVD. »*
- **CERT-FR** : conditions de réutilisation à confirmer (Licence Ouverte
  Etalab 2.0 a priori).

## Licence

GNU GPL v3. Voir [`LICENSE`](LICENSE).
