#include <time.h>

struct vhost_config {
  char *uri;
  char *vhost;
  char *user;
  char *directory;
  char *mysql_socket;
  char *php_mode;
  char *php_config;
  char *php_modules;
  time_t added;
};

struct db_handler {
  char *dbh;
  FILE *fd;
  FILE *fd_updated;
  int counter;
  int fd_modified;
  int fd_updated_modified;
};


struct vhost_config *vhost_getconfig(struct db_handler *dbh, char *host);
struct db_handler* get_dbh(char *db_path);
int clean_dbh(struct db_handler* dbh);
void free_vhost_config(struct vhost_config *conf);
