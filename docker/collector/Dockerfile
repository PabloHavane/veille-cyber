# Image de production du pipeline de collecte (service `collector` de compose.yml).
# Contexte de build : la racine du dépôt (voir .dockerignore).
FROM python:3.15-slim

# Utilisateur dédié, sans shell ni home. /data/feed est créé ici pour que Docker/Podman
# initialisent le volume nommé avec ce dossier et ce propriétaire au premier montage.
RUN useradd --system --uid 10001 --user-group --home-dir /nonexistent \
        --shell /usr/sbin/nologin veille \
 && mkdir -p /data/feed \
 && chown -R veille:veille /data

# Aucune dépendance à l'exécution : le paquet est copié tel quel.
COPY src/veille_cyber /opt/veille-cyber/veille_cyber

ENV PYTHONPATH=/opt/veille-cyber \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER veille
ENTRYPOINT ["python", "-m", "veille_cyber"]
CMD ["loop", "--data-dir", "/data"]
