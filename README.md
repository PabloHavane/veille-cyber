# veille-cyber

Outil personnel et auto-hébergé de veille en cybersécurité : agrégation RSS
(FreshRSS) et, à terme, digest hebdomadaire des vulnérabilités prioritaires.

## État du projet

- [x] FreshRSS conteneurisé (compose compatible Docker et Podman)
- [x] Liste de flux d'exemple (OPML)
- [X] CI : scan de secrets (gitleaks) et validation compose
- [ ] Pipeline de collecte : CISA KEV, EPSS (FIRST), NVD, CERT-FR
- [ ] Priorisation des CVE et digest hebdomadaire en Markdown
- [ ] Tests sur jeux de données figés
- [ ] Déploiement Ansible (et ansible-lint en CI)
- [ ] Accès mobile via l'API Google Reader (reverse proxy HTTPS)

## Démarrage rapide

```sh
cp .env.example .env
docker compose up -d   # ou : podman compose up -d
```

Puis ouvrir http://127.0.0.1:8080 et importer `config/feeds.example.opml`.

## Sources de données et attributions

- CISA KEV : CC0.
- EPSS : FIRST demande une attribution. Voir https://www.first.org/epss
- NVD et CERT-FR : conditions de réutilisation à compléter.

## Licence

GNU GPL v3. Voir `LICENSE`.