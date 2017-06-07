#!/bin/bash

set -e


capsh  --print

echo "======= Runing functionnal tests ======"

id testuser 

#dpkg -l libapache2-mpm-itk | grep 2.4.7-02 && capsh --supports=CAP_DAC_READ_SEARCH || (echo "ERROR: No CAP_DAC_READ_SEARCH Capability";  exit 0)

curl -H 'Host: www.website.com'  http://127.0.0.1/system.php
curl -H 'Host: nowebsite.com'  http://127.0.0.1/

echo "=== All tests passed ===="

echo "******************* LOGS **********************"
cat /var/log/apache2/access.log
echo "************************************************"
#cat /var/log/apache2/error.log
#echo "************************************************"

cd /home/testuser/public_html/www 
wget -q -O /usr/local/bin/wp  https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x /usr/local/bin/wp
mysqladmin create wordpress
/usr/local/bin/wp --allow-root core download --path=/home/testuser/public_html/www
/usr/local/bin/wp --allow-root config create --dbname="wordpress" --dbuser="root" 
/usr/local/bin/wp --allow-root core install --url=http://www.website.com/ --title="Test" --admin_user="admin" --admin_password="admincipwd" --admin_email="xxx@xx.com" --skip-email

cat >/home/testuser/public_html/www/.htaccess << EOF
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
EOF

curl -H 'Host: www.website.com'  http://127.0.0.1/
POSTURL=$(/usr/local/bin/wp post list --field=url)
echo $POSTURL
echo ${POSTURL/www.website.com/127.0.0.1}
echo "************************************************"
curl -H 'Host: www.website.com'  $POSTURL | grep bonjour
echo "************************************************"
curl -H 'Host: www.website.com'  ${POSTURL/www.website.com/127.0.0.1} | grep bonjour

exit 0
