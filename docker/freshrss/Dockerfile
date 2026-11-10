# FreshRSS de dev : installé automatiquement au démarrage, sans authentification,
# déjà abonné au flux de veille-cyber servi par le service `feed`.
# NE PAS utiliser en production (auth désactivée, protection SSRF assouplie).
ARG FRESHRSS_TAG=latest
FROM freshrss/freshrss:${FRESHRSS_TAG}

# - FRESHRSS_INSTALL / FRESHRSS_USER : lus par l'entrypoint officiel, qui installe
#   FreshRSS (SQLite, sans mot de passe) et crée l'utilisateur. Sans effet si déjà fait.
# - INTERNAL_HOST_ALLOWLIST : FreshRSS refuse par défaut les hôtes privés (anti-SSRF),
#   on autorise uniquement le service `feed` du compose de dev.
# - CRON_MIN : rafraîchissement des flux toutes les 5 minutes.
ENV FRESHRSS_INSTALL="--default-user admin --auth-type none --language fr --db-type sqlite --base-url http://127.0.0.1:8088" \
    FRESHRSS_USER="--user admin --language fr --no-default-feeds" \
    INTERNAL_HOST_ALLOWLIST="feed:8000" \
    CRON_MIN="*/5"

COPY dev-feeds.opml /opt/veille-dev/dev-feeds.opml
COPY --chmod=755 dev-init.sh /usr/local/bin/dev-init.sh

# L'entrypoint officiel installe puis exécute la CMD : on y insère l'import des flux.
CMD ["/usr/local/bin/dev-init.sh"]
