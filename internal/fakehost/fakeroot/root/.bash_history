ls -la /var/www/html
cat /var/www/html/wp-config.php
mysql -u {{.WPDBUser}} -p{{.WPDBPass}} -h {{.DBIP}} {{.WPDBName}}
systemctl status nginx
tail -n 100 /var/log/nginx/error.log
df -h
free -m
cd /home/deploy/scripts
./backup.sh
ssh deploy@{{.BackupIP}}
rsync -avz /var/backups/ deploy@{{.BackupIP}}:/srv/backups/
history
exit
