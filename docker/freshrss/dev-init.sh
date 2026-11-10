#!/bin/sh
# Exécuté par l'entrypoint officiel de FreshRSS, après l'installation et la
# création de l'utilisateur : importe les flux de dev une seule fois, puis
# démarre cron et Apache comme la CMD d'origine.
set -eu

cd /var/www/FreshRSS
marker=./data/users/admin/.dev-feeds-imported

if [ ! -e "$marker" ]; then
	php -f ./cli/import-for-user.php -- --user admin --filename /opt/veille-dev/dev-feeds.opml
	# Le flux peut être encore vide ou absent : on ne bloque pas le démarrage.
	php -f ./cli/actualize-user.php -- --user admin || true
	touch "$marker"
	./cli/access-permissions.sh --only-userdirs
fi

if [ -n "${CRON_MIN:-}" ]; then
	cron
fi
set +u  # envvars d'Apache lit des variables non définies
. /etc/apache2/envvars
exec apache2 -D FOREGROUND
