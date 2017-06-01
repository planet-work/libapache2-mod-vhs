mod_vhs 2 - Virtual Hosting module
===============================


mod_vhs is an Apache 2.2 and 2.4 Web Server module allowing mass virtual hosting without the need for file based configuration. The virtual host paths are translated from a Redis Database

**Version 2** comes from evolution of the original `mod_vhs` module (https://bitbucket.org/cosmomill/mod_vhs). It has been designed for shared PHP hosting with the following modifications :

  * Only works with PHP (5.x and 7.0)
  * PHP dynamic configuration for `session_path` and `sendmail_path`
  * Only 1 database support : Redis
  * Caching
  * MPM [ITK](http://mpm-itk.sesse.net/) support
  * Debian packages : tested on Debian Wheezy, Jessie and Stretch
  * Continuous integration and testing (see `.drone.yml`)

A custom `mod_vhs` version with ITK, PHP 7 and flatfile (passwd style) database support is in production since 2006 at [Planet-Work](https://www.planet-work.com/)  for the shared hosting platform (20k+ websites).

This module is designed for running PHP in read-only and stateless containers in conjunction with [libnss-redis](https://github.com/planet-work/libnss-redis)


Redis database
============

All the virtualhosts are in a [Redis](https://redis.io) database in JSON format. The key is WEBHOST/v1/_host_

```json
{
  "status": "enabled",
  "vhost": "test.planet-work.wf",
  "host": "test.planet-work.wf",
  "no_public_html": 0,
  "frontend": {
    "deny": [],
    "allow": [
      "ALL"
    ],
    "redirect_https": false,
    "proxy_only": 0,
    "HSTS": false,
    "env": "php5.6"
  },
  "user": "planet-work",
  "directory": "test",
  "backend": {
    "mysql_socket": "/var/run/mysqld/thales",
    "php_mode": "default",
    "php_config": {
      "short_open_tag": "1",
      "display_errors": "1"
    }
  }
}
```

`frontend` is for Nginx (TODO), `backend` is the configuration for `mod_vhs`.



Installation
=========

See `.drone.yml` file for building and installation example.

On Debian Stretch system : 

```
apt-get install -y libhiredis-dev php7.0-dev apache2-dev libjson-c-dev
dpkg-buildpackage -b
``` 


Configuration
========

`/etc/apache2/mods-availabled/vhs.conf` :
```
<IfModule mod_vhs.c>
  EnableVHS On
  vhs_Default_Host "localhost"
  vhs_Alias /admin-global/ /var/www/admin-global/
  vhs_ScriptAlias /common-cgi-bin/ /usr/lib/cgi-bin/
  vhs_CacheTTL 10
  vhs_CacheCleanInter 10
  vhs_RedisHost  "/run/redis/redis-webconf.sock"
  vhs_PhpSessionAddr "tcp://10.3.100.1:6379?prefix=phpredis_"
  vhs_PhpSendmailPath "/usr/sbin/sendmail_hook" 
</IfModule>
```

mod_vhs only works with mpm_itk (prefork).

Docker and Capabilities
=====

ITK module 2.4 (Debian Jessie and Stretch) need `CAP_DAC_READ_SEARCH` capability which is dropped by Docker un unprivilefed containers.



Author
=====

Frédéric VANNIÈRE <f.vanniere@planet-work.com>

Original author : Xavier Beaudouin <kiwi@oav.net>


See also
====

https://github.com/sshutdownow/mod-myvhost


