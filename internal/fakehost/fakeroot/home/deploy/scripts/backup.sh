#!/bin/bash
# Nightly backup of the web root and database to {{.BackupHost}} ({{.BackupIP}}).
# Installed in deploy's crontab: 30 2 * * *
set -euo pipefail

SRC=/var/www/html
DEST="deploy@{{.BackupIP}}:/srv/backups/"
STAMP="$(date +%F)"

mysqldump -u {{.WPDBUser}} -p{{.WPDBPass}} -h {{.DBIP}} {{.WPDBName}} \
    > /var/backups/{{.WPDBName}}-${STAMP}.sql

rsync -avz --delete "${SRC}" "${DEST}"
rsync -avz /var/backups/ "deploy@{{.BackupIP}}:/srv/backups/db/"

echo "backup ${STAMP} complete -> {{.BackupHost}}"
