#!/bin/sh
set -x
set -e
cd $(dirname $0)

myuser=root
mydb=isu4_qualifier
myhost=127.0.0.1
myport=3306
sudo /sbin/service redis stop
sudo cp /home/isucon/webapp/dump.rdb /var/lib/redis/dump.rdb
sudo /sbin/service redis start
sleep 3
sudo /sbin/service supervisord restart
mysql -h ${myhost} -P ${myport} -u ${myuser} -e "DROP DATABASE IF EXISTS ${mydb}; CREATE DATABASE ${mydb}"
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/schema.sql
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/dummy_users.sql
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/dummy_log.sql


