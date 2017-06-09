/*
 * Version of mod_vhs
 */
#define VH_VERSION    "mod_vhs/2.0.0"

#define SENDMAIL_PATH   "/etc/apache2/conf/sendmail-secure"
#define OPEN_BASEDIR    "/usr/share/php:/etc/php5/:/tmp:/var/lib/php/"
#define REDIS_PATH      "tcp://10.3.100.1:6379?prefix=phpredis"
#define REDIS_SOCKET    "/var/run/redis/redis-webconf.sock"

/*
 * Set this if you'd like to have looooots of debug
 */
/*
 *  #define VH_DEBUG 1
 */

#define VH_DEBUG 1

/*
 * Define this if you have Linux/Debian since it seems to have non standards
 * includes
 */
/*
 * #define DEBIAN 1
 */

/* Original Author: Michael Link <mlink@apache.org> */
/* mod_vhs author : Xavier Beaudouin <kiwi@oav.net> */
/* Some parts of this code has been stolen from mod_alias */
/* added support for apache2-mpm-itk by Rene Kanzler <rk (at) cosmomill (dot) de> */

/* We need this to be able to access the docroot. */
#define CORE_PRIVATE

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "pwd.h"
#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_uri.h"
#include "apr_thread_mutex.h"
#include "apr_global_mutex.h"
#include "apr_shm.h"

#if APR_MAJOR_VERSION > 0
#include "apr_regexp.h"
#endif

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "util_ldap.h"
#include "apr_ldap.h"
#include "apr_strings.h"
#include "apr_reslist.h"
#include "apr_dbd.h"
#include "mod_dbd.h"
#include "mpm_common.h"

#include "ap_config_auto.h"

#include "vhosts_db_redis.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <fcntl.h>

/*
 * To enable Apache 2.2 compatibility
 */
#if MODULE_MAGIC_NUMBER_MAJOR >= 20050217
# ifndef DEBIAN
#  define DEBIAN
# endif
#endif


/*
 *  Apache 2.4 per module log
 */
#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(vhs);
#define MOD_ITK "mpm_itk.c"
#else
#define MOD_ITK "itk.c"
#endif 

/*
 * Include php support
 */
#include <zend.h>
#include <zend_API.h>
#include <zend_ini.h>
#include <zend_alloc.h>
#include <zend_operators.h>

extern ZEND_API zend_executor_globals executor_globals;

// PLANET-WORK
#include <libgen.h>
typedef struct {
    apr_hash_t *extension_mappings;
    apr_array_header_t *remove_mappings;
    char *default_language;
    int multimatch;
    int use_path_info;
} mime_dir_config;

typedef struct {
    HashTable config;
} php_conf_rec;

typedef struct {
    char *value;
    size_t value_len;
    char status;
    char htaccess;
} php_dir_entry;


typedef struct extension_info {
    char *forced_type;                /* Additional AddTyped stuff */
    char *encoding_type;              /* Added with AddEncoding... */
    char *language_type;              /* Added with AddLanguage... */
    char *handler;                    /* Added with AddHandler... */
    char *charset_type;               /* Added with AddCharset... */
    char *input_filters;              /* Added with AddInputFilter... */
    char *output_filters;             /* Added with AddOutputFilter... */
} extension_info;



/*
 * For mod_alias like operations
 */
#define AP_MAX_REG_MATCH 10

typedef struct mod_vhs_request_t {
    char *name;                /* ServerName or host accessed uppon request */
    char *associateddomain;        /* The real server name */
    char *admin;            /* ServerAdmin or email for admin */
    char *docroot;            /* DocumentRoot */
    char *uid;                /* Suexec Uid */
    char *gid;                /* Suexec Gid */
    int vhost_found;            /* set to 1 if the struct is field with vhost information, 0 if not, -1 if the vhost does not exist  */
    char *mysql_socket;                 /* Path for MySQL socket */
    char *php_mode;                     /* Mode for PHP */
    char *php_modules;            /* Modules for PHP */
    apr_hash_t *php_config;     /* PHP Options for ini_set (Hashtable) */
    char *gecos;                     /* GECOS : username */

    /* cache management */
    int  usage;
    unsigned  long added;
    char *json;
} mod_vhs_request_t;

/* The structure that is stored in shared memory */
typedef struct {
    unsigned long lastcleaned;
    unsigned int counter;
    char keys [100][200];
    char entries [100][4096];
    unsigned long added[100];
    char wildcards[4096];
} vhs_cache_t;


/*
 * Configuration structure
 */
typedef struct {
    unsigned short int    enable;            /* Enable the module */
    unsigned short int    db_mode;        /* Mode when module have dbd and ldap support */
    char                   *path_prefix;        /* Prefix to add to path returned by database/ldap */
    char                   *default_host;        /* Default host to redirect to */

    unsigned short int     lamer_mode;        /* Lamer friendly mode */
    unsigned short int     log_notfound;        /* Log request for vhost/path is not found */

    char                   *openbdir_path;        /* PHP open_basedir default path */
    unsigned short int     open_basedir;        /* PHP open_basedir */
    unsigned short int     append_basedir;        /* PHP append current directory to open_basedir */
    unsigned short int     display_errors;        /* PHP display_error */
    unsigned short int     phpopt_fromdb;        /* Get PHP options from database/ldap */
    unsigned short int    itk_enable;            /* MPM-ITK support */
    uid_t            itk_defuid;
    gid_t            itk_defgid;
    char            *itk_defusername;

    const char                 *tenant;
    const char                 *db_host;


    unsigned       cache_ttl; 
    unsigned       cache_maxusage; 
    unsigned       cache_cleaninter; 
    apr_global_mutex_t *cache_mutex;
    apr_shm_t      *cache_shm; 
    vhs_cache_t    *cache;   
    char           *cache_mutex_lockfile;
    char           *cache_shm_file;

    const char      *php_sessions;
    const char      *php_sendmail;

    int              conf_id;

    /*
     * From mod_alias.c
     */
    apr_array_header_t        *aliases;
    apr_array_header_t        *redirects;
    /*
     * End of borrowing
     */
} vhs_config_rec;




/*
 * From mod_alias.c
 */
typedef struct {
    const char     *real;
    const char     *fake;
    char           *handler;

#if APR_MAJOR_VERSION > 0
    ap_regex_t     *regexp;
#else
#ifdef DEBIAN
    ap_regex_t     *regexp;
#else
    regex_t        *regexp;
#endif /* DEBIAN */
#endif /* APR_MAJOR_VERSION */
    int        redir_status;    /* 301, 302, 303, 410, etc... */
}    alias_entry;

typedef struct {
    apr_array_header_t *redirects;
}    alias_dir_conf;

void * create_alias_dir_config(apr_pool_t * p, char *d);
void * merge_alias_dir_config(apr_pool_t * p, void *basev, void *overridesv);
int alias_matches(const char *uri, const char *alias_fakename);
const char * add_alias_internal(cmd_parms * cmd, void *dummy, const char *f, const char *r, int use_regex);
const char * add_alias(cmd_parms * cmd, void *dummy, const char *f, const char *r);
const char * add_alias_regex(cmd_parms * cmd, void *dummy, const char *f, const char *r);
const char * add_redirect_internal(cmd_parms * cmd, alias_dir_conf * dirconf,
                                          const char *arg1, const char *arg2,
                      const char *arg3, int use_regex);
const char * add_redirect(cmd_parms * cmd, void *dirconf,
                                 const char *arg1, const char *arg2,
                 const char *arg3);
const char * add_redirect2(cmd_parms * cmd, void *dirconf,
                  const char *arg1, const char *arg2);
const char * add_redirect_regex(cmd_parms * cmd, void *dirconf,
                                       const char *arg1, const char *arg2,
                       const char *arg3);
int alias_matches(const char *uri, const char *alias_fakename);
char * try_alias_list(request_rec * r, apr_array_header_t * aliases,
                 int doesc, int *status);
int fixup_redir(request_rec * r);


#ifdef VH_DEBUG
#  define VH_AP_LOG_ERROR ap_log_error
#else
#  define VH_AP_LOG_ERROR my_ap_log_error
static void my_ap_log_error(void *none, ...)
{
  return;
}
#endif

#ifdef VH_DEBUG
#  define VH_AP_LOG_RERROR ap_log_rerror
#else
#  define VH_AP_LOG_RERROR my_ap_log_rerror
static void my_ap_log_rerror(void *none, ...)
{
  return;
}
#endif

#define VH_VHOST_INFOS_FOUND 1
#define VH_VHOST_INFOS_NOT_FOUND -1
#define VH_VHOST_INFOS_NOT_YET_REQUESTED 0
