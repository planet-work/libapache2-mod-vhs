#/bin/bash


redis-cli -p 6380 SET WEBHOST/v1/website.com "{\"status\": \"enabled\", \"vhost\": \"www.website.com\", \"host\": \"www.website.com\", \"no_public_html\": 0, \"frontend\": {\"deny\": [], \"allow\": [\"ALL\"], \"redirect_https\": 0, \"proxy_only\": 0, \"HSTS\": \"\", \"env\": \"default\"}, \"user\": \"testuser\", \"directory\": \"www\", \"backend\": {\"mysql_socket\": \"/var/run/mysqld/mysqld.sock\", \"php_mode\": \"default\", \"php_config\": {\"default_charset\": \"iso-8859-1\", \"always_populate_raw_post_data\": \"-1\", \"display_errors\": \"On\"}}}"

