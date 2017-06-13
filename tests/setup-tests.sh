#!/bin/bash

set -e

REDIS='redis-cli -s /var/run/redis/redis-webconf.sock'
$REDIS SET USER/testuser "testuser:x:12345:54321:Web User:/home/testuser:/bin/false"
$REDIS SET USER/12345 "testuser:x:12345:54321:Web User:/home/testuser:/bin/false"
$REDIS SET GROUP/testgroup "testgroup:x:54321:www-data"
$REDIS SET GROUP/54321 "testgroup:x:54321:www-data"


mkdir /var/www/default
echo "DEFAULT" > /var/www/default/index.html

mkdir -p /home/testuser/public_html/www/
echo '<?php phpinfo() ?>' > /home/testuser/public_html/www/phpinfo.php
echo '<?php system("id"); ?>' > /home/testuser/public_html/www/system.php

chown -R testuser:www-data /home/testuser/

$REDIS SET WEBHOST/v1/website.com "{\"status\": \"enabled\", \"vhost\": \"www.website.com\", \"host\": \"www.website.com\", \"no_public_html\": 0, \"frontend\": {\"deny\": [], \"allow\": [\"ALL\"], \"redirect_https\": 0, \"proxy_only\": 0, \"HSTS\": \"\", \"env\": \"default\"}, \"user\": \"testuser\", \"directory\": \"www\", \"backend\": {\"mysql_socket\": \"/var/run/mysqld/mysqld.sock\", \"php_mode\": \"default\", \"php_config\": {\"default_charset\": \"iso-8859-1\", \"always_populate_raw_post_data\": \"-1\", \"display_errors\": \"On\"}}}"
$REDIS SET WEBHOST/v1/www.website.com "{\"status\": \"enabled\", \"vhost\": \"www.website.com\", \"host\": \"www.website.com\", \"no_public_html\": 0, \"frontend\": {\"deny\": [], \"allow\": [\"ALL\"], \"redirect_https\": 0, \"proxy_only\": 0, \"HSTS\": \"\", \"env\": \"default\"}, \"user\": \"testuser\", \"directory\": \"www\", \"backend\": {\"mysql_socket\": \"/var/run/mysqld/mysqld.sock\", \"php_mode\": \"default\", \"php_config\": {\"default_charset\": \"iso-8859-1\", \"always_populate_raw_post_data\": \"-1\", \"display_errors\": \"On\"}}}"

$REDIS SET WEBHOST/v1/*.website.com "{\"status\": \"enabled\", \"vhost\": \"www.website.com\", \"host\": \"*.website.com\", \"no_public_html\": 0, \"frontend\": {\"deny\": [], \"allow\": [\"ALL\"], \"redirect_https\": 0, \"proxy_only\": 0, \"HSTS\": \"\", \"env\": \"default\"}, \"user\": \"testuser\", \"directory\": \"www\", \"backend\": {\"mysql_socket\": \"/var/run/mysqld/mysqld.sock\", \"php_mode\": \"default\", \"php_config\": {\"default_charset\": \"iso-8859-1\", \"always_populate_raw_post_data\": \"-1\", \"display_errors\": \"On\"}}}"



exit 0
