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
- [x] CI : scan de secrets (gitleaks) et validation compose
- [ ] Pipeline de collecte : CISA KEV, EPSS (FIRST), NVD, CERT-FR
- [ ] Priorisation des CVE et digest hebdomadaire en Markdown
- [ ] Tests sur jeux de données figés
- [ ] Déploiement Ansible (et ansible-lint en CI)
- [ ] Accès mobile via l'API Google Reader (reverse proxy HTTPS)

## Structure du dépôt

```
.
├── compose.yml                 # Service FreshRSS
├── .env.example                # Variables à copier dans .env
├── config/
│   └── feed.example.opml       # Flux d'exemple à importer
└── .github/workflows/ci.yml    # gitleaks + validation compose
```

## Prérequis

- Docker avec le plugin Compose v2, **ou** Podman avec `podman compose`.

## Démarrage rapide

```sh
cp .env.example .env
docker compose up -d   # ou : podman compose up -d
```

Ensuite :

1. Ouvrir http://127.0.0.1:8080 (ou le port défini dans `.env`).
2. Suivre l'assistant d'installation de FreshRSS (langue, base SQLite,
   création du compte administrateur).
3. Importer les flux : *Abonnements → Importer / exporter* →
   `config/feed.example.opml`.

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

## Exploitation

**Mise à jour**

```sh
docker compose pull && docker compose up -d
```

**Sauvegarde des données** (volume `data` : base, configuration, utilisateurs)

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

- scanne l'historique Git complet à la recherche de secrets (gitleaks) ;
- valide la syntaxe de `compose.yml` avec `.env.example`.

## Sources de données et attributions

- **CISA KEV** : CC0.
- **EPSS** : FIRST demande une attribution. Voir https://www.first.org/epss
- **NVD** : mention requise — *« This product uses data from the NVD API but
  is not endorsed or certified by the NVD. »*
- **CERT-FR** : conditions de réutilisation à confirmer (Licence Ouverte
  Etalab 2.0 a priori).

## Licence

GNU GPL v3. Voir [`LICENSE`](LICENSE).
