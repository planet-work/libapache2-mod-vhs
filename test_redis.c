#include <stdio.h>
#include <apr_pools.h>
#include "vhosts_db_redis.h"

int main(void) {
	apr_pool_t *p;

	apr_initialize();
	apr_pool_create_ex(&p, NULL,NULL, NULL);
    struct vhost_config *conf = new_vhost_config(p);
	int res;

    res = vhost_getconfig("kaa","www.kaa.on-web.fr",conf,p);
	if (res != 0) {
		printf("ERROR, no conf found\n");
		return 1;
    }
    //printf("Got configuration: %i\n",conf);
    printf("Configuration de %s: \n",conf->vhost);
	printf("  - vhost: %s\n", conf->vhost);
	printf("  - user: %s\n", conf->user);
	printf("  - directory: %s\n", conf->directory);
	//printf("  - php_mode: %s\n", conf->php_mode);
	printf("  - mysql_socket: %s\n", conf->mysql_socket);
	printf("  - php_config: %s\n", conf->php_config);
	free_vhost_config(conf,p);
    
    return 0;
}
