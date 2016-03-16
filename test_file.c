#include "vhosts_db_file.h"
#include <stdio.h>

struct db_handler *dbh;

int main() {
    struct vhost_config *conf;

    dbh = get_dbh("/etc/apache2/conf/vhosts.map");
    conf = vhost_getconfig(dbh,"php70.planet-work.on-web.fr");
    printf("Got configuration: %i\n",conf);
    printf("Configuration de %s: \n",conf->vhost);
    
    return 0;
}
