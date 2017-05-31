#include <stdio.h>
#include <apr_pools.h>
#include <stdlib.h>
#include "vhosts_db_redis.h"


int main(int argc, char *argv[]) {
	apr_pool_t *p;
	apr_hash_index_t *hidx = NULL;
	int res;
	const void *key;
	void *val;

	apr_initialize();
	apr_pool_create(&p, NULL);
    struct vhost_config *conf = new_vhost_config(p);
    struct vhost_config *conf_cache = new_vhost_config(p);

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
	for (hidx = apr_hash_first(p, conf->php_config); hidx; hidx = apr_hash_next(hidx)) {
		apr_hash_this(hidx, &key, NULL, &val);
	    printf("       o %s=%s\n", (char*)key, (char*)val);
	}
	printf("\n");
	printf("  - cache: %s\n", conf->cache);


	printf("====== Parse cache =======\n");
	res = vhost_parseconfline(conf->cache, conf_cache, p);
	if (res != 0) {
		printf("ERROR, no cache conf found\n");
		apr_pool_clear(p);
		apr_pool_destroy(p);
		free_vhost_config(conf,p);
		apr_terminate();
		return 1;
	}

    printf("Configuration de %s: \n",conf_cache->vhost);
	printf("  - vhost: %s\n", conf_cache->vhost);
	printf("  - user: %s\n", conf_cache->user);
	printf("  - directory: %s\n", conf_cache->directory);
	printf("  - mysql_socket: %s\n", conf_cache->mysql_socket);
	printf("  - php_config: \n");
	for (hidx = apr_hash_first(p, conf_cache->php_config); hidx; hidx = apr_hash_next(hidx)) {
		apr_hash_this(hidx, &key, NULL, &val);
	    printf("       o %s=%s\n", (char *) key, (char *) val);
	}
	printf("\n");
	printf("  - cache: %s\n", conf_cache->cache);


	apr_pool_clear(p);
	apr_pool_destroy(p);
	free_vhost_config(conf,p);
	apr_terminate();
    
    return 0;
}
