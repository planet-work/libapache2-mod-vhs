#include <time.h>
#include <stdio.h>
#include <apr_hash.h>

struct vhost_config {
  char *uri;
  char *vhost;
  char *user;
  char *directory;
  char *mysql_socket;
  char *php_mode;
  apr_hash_t *php_config;
  char *php_modules;
  char *cache;
  time_t added;
};

int vhost_getconfig(const char* tenant, const char *host, struct vhost_config*,apr_pool_t *);
int vhost_parseconfig(const char *json_data,struct vhost_config *conf,apr_pool_t * p);
int vhost_parseconfline(const char *line,struct vhost_config *conf,apr_pool_t * p);
struct db_handler* get_dbh(char *db_path);
int clean_dbh(struct db_handler* dbh);
struct vhost_config *new_vhost_config (apr_pool_t * p);
void free_vhost_config(struct vhost_config *conf,apr_pool_t * p);

