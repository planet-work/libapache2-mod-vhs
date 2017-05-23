#include <stdio.h>
#include <apr_pools.h>
#include <stdlib.h>
#include "vhosts_db_redis.h"


int main(int argc, char *argv[]) {
	apr_pool_t *p;

	apr_initialize();
	apr_pool_create(&p, NULL);
    struct vhost_config *conf = new_vhost_config(p);
	int res;

    char *host = "default";

	if (argc == 2) {
		host = argv[1];
	}

    res = vhost_getconfig(getenv("TENANT"), host, conf, p);
	if (res != 0) {
		printf("ERROR, no conf found\n");
		apr_pool_clear(p);
		apr_pool_destroy(p);
		free_vhost_config(conf,p);
		apr_terminate();
		return 1;
    }

    //printf("Got configuration: %i\n",conf);
    printf("Configuration de %s: \n",conf->vhost);
	printf("  - vhost: %s\n", conf->vhost);
	printf("  - user: %s\n", conf->user);
	printf("  - directory: %s\n", conf->directory);
	printf("  - mysql_socket: %s\n", conf->mysql_socket);
	printf("  - php_config: \n");
	apr_hash_index_t *hidx = NULL;
	for (hidx = apr_hash_first(p, conf->php_config); hidx; hidx = apr_hash_next(hidx)) {
	    printf("       o %s=%s\n", (char *) apr_hash_this_key(hidx), (char *) apr_hash_this_val(hidx));
	}
	printf("\n");
	printf("  - cache: %s\n", conf->cache);


	apr_pool_clear(p);
	apr_pool_destroy(p);
	free_vhost_config(conf,p);
	apr_terminate();
    
    return 0;
}
