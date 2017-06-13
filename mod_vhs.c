/*
 * ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright(c) 2000 The Apache Software Foundation.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. The end-user documentation included with the redistribution, if any, must
 * include the following acknowledgment: "This product includes software
 * developed by the Apache Software Foundation(http://www.apache.org/)."
 * Alternately, this acknowledgment may appear in the software itself, if and
 * wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must not be used to
 * endorse or promote products derived from this software without prior
 * written permission. For written permission, please contact
 * apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache", nor may
 * "Apache" appear in their name, without prior written permission of the
 * Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE APACHE SOFTWARE FOUNDATION OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many individuals on
 * behalf of the Apache Software Foundation.  For more information on the
 * Apache Software Foundation, please see <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software originally
 * written at the National Center for Supercomputing Applications, University
 * of Illinois, Urbana-Champaign.
 */
/*
 * $Id: mod_vhs.c,v 1.108 2009-05-22 20:27:29 kiwi Exp $
 */

#include "mod_vhs.h"

#define VH_KEY "mod_vhs"
#define MUTEX_LOCKFILE "/var/run/apache2/vhs_mutex.lock"
#define MUTEX_FILE NULL

int vhs_redis_lookup(request_rec * r, vhs_config_rec * vhr, const char *hostname, mod_vhs_request_t * reqc);
/*
 * Let's start coding
 */
module AP_MODULE_DECLARE_DATA vhs_module;

int prout = 0;



/*
 * Apache per server config structure
 */
static void *vhs_create_server_config(apr_pool_t * p, server_rec * s)
{
    vhs_config_rec *vhr = (vhs_config_rec *) apr_pcalloc(p, sizeof(vhs_config_rec));

    /*
     * Pre default the module is enabled
     */
    vhr->enable = 0;

    /*
     * We don't know what mode we need so default is 0(disabled);
     */
    vhr->db_mode = 3;

    /*
     * From mod_alias.c
     */
    vhr->aliases = apr_array_make(p, 20, sizeof(alias_entry));
    vhr->redirects = apr_array_make(p, 20, sizeof(alias_entry));

    vhr->itk_enable = 1;
    vhr->phpopt_fromdb = 1;

    vhr->tenant = NULL;
    vhr->db_host = REDIS_SOCKET;
    vhr->cache_ttl = 10;
    vhr->cache_maxusage = 100;
    vhr->cache_cleaninter = 10;

    vhr->cache_mutex = NULL;
    vhr->cache_shm = NULL;
    vhr->cache = NULL;

    vhr->conf_id = 0;


    vhr->php_sessions = REDIS_PATH;
    vhr->php_sendmail = SENDMAIL_PATH;

    vhr->cache_mutex_lockfile = MUTEX_LOCKFILE; //apr_pstrdup(p, MUTEX_LOCKFILE);
    vhr->cache_shm_file = MUTEX_FILE; //ap_server_root_relative(p, MUTEX_FILE);
    return (void *)vhr;
}



static void *vhs_cache_clean(request_rec * r, vhs_config_rec * vhr) {
    unsigned long now = (unsigned long)time(NULL);
    if (now - vhr->cache->lastcleaned < vhr->cache_cleaninter) {
        return NULL;
    }

    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_cache_clean: STARTING CACHE CLEANUP");
/*
    int i;
    for (i = 0; i< sizeof(vhr->cache->added); i++) {
        if (now - vhr->cache->added[i] > vhr->cache_ttl) { 
            VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_cache_clean: idx: %i / entry %s / added=%lu",i, vhr->cache->keys[i], vhr->cache->added[i]);
            vhr->cache->added[i] = 0;
            memset(&vhr->cache->keys[i],'\0',sizeof(vhr->cache->keys[i]));
            memset(&vhr->cache->entries[i],'\0',sizeof(vhr->cache->entries[i]));
        }
    }
*/
    memset(&vhr->cache->wildcards,'\0',sizeof(vhr->cache->wildcards));
    
/*
    for (hi = apr_hash_first(NULL, vhs_cache); hi; hi = apr_hash_next(hi)) {
        apr_hash_this(hi, NULL, NULL, &val);
        reqc = (mod_vhs_request_t*) val;
    }
*/
    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_cache_clean: FINISHED CACHE CLEANUP");
    vhr->cache->lastcleaned = now;
    return NULL;
}

/*
 * Apache merge per server config structures
 */
static void *vhs_merge_server_config(apr_pool_t * p, void *parentv, void *childv)
{

    return parentv;
/* Vhost configuration not supported */
/*
    vhs_config_rec *parent = (vhs_config_rec *) parentv;
    vhs_config_rec *child = (vhs_config_rec *) childv;
    vhs_config_rec *conf = (vhs_config_rec *) apr_pcalloc(p, sizeof(vhs_config_rec));

    conf->enable = (child->enable ? child->enable : parent->enable);
    conf->path_prefix = (child->path_prefix ? child->path_prefix : parent->path_prefix);
    conf->default_host = (child->default_host ? child->default_host : parent->default_host);
    conf->log_notfound = (child->log_notfound ? child->log_notfound : parent->log_notfound);

    conf->open_basedir = (child->open_basedir ? child->open_basedir : parent->open_basedir);
    conf->display_errors = (child->display_errors ? child->display_errors : parent->display_errors);
    conf->append_basedir = (child->append_basedir ? child->append_basedir : parent->append_basedir);
    conf->openbdir_path = (child->openbdir_path ? child->openbdir_path : parent->openbdir_path);
    conf->phpopt_fromdb = (child->phpopt_fromdb ? child->phpopt_fromdb : parent->phpopt_fromdb);

    conf->itk_enable = (child->itk_enable ? child->itk_enable : parent->itk_enable);

    conf->tenant = (child->tenant ? child->tenant : parent->tenant);
    conf->php_sessions = (child->php_sessions ? child->php_sessions : parent->php_sessions);
    conf->php_sendmail = (child->php_sendmail ? child->php_sendmail : parent->php_sendmail);
    conf->db_host = (child->db_host ? child->db_host : parent->db_host);

    conf->cache_ttl      = (child->cache_ttl ? child->cache_ttl : parent->cache_ttl);
    conf->cache_maxusage = (child->cache_maxusage ? child->cache_maxusage : parent->cache_maxusage);
    conf->cache_cleaninter = (child->cache_cleaninter ? child->cache_cleaninter : parent->cache_cleaninter);

    conf->aliases = apr_array_append(p, child->aliases, parent->aliases);
    conf->redirects = apr_array_append(p, child->redirects, parent->redirects);

    conf->conf_id = (child->conf_id ? child->conf_id : parent->conf_id);
    conf->conf_id = parent->conf_id;
    conf->cache_mutex_lockfile = parent->cache_mutex_lockfile;

    //conf->cache_mutex = parent->cache_mutex;
    //conf->cache_shm_file = parent->cache_shm_file;

    return conf;
*/
}

/*
 * Set the fields inside the conf struct
 */
static const char *set_field(cmd_parms * parms, void *mconfig, const char *arg)
{
    int pos = (uintptr_t) parms->info;
    vhs_config_rec *vhr = (vhs_config_rec *) ap_get_module_config(parms->server->module_config, &vhs_module);

    switch (pos) {
    case 1:
        // PLANET-WORK 
        vhr->path_prefix = "";
        break;
    case 2:
        vhr->default_host = apr_pstrdup(parms->pool, arg);
        break;
    case 3:
        vhr->openbdir_path = apr_pstrdup(parms->pool, arg);
        break;
    case 8:
        vhr->php_sessions = apr_pstrdup(parms->pool, arg);
        break;
    case 9:
        vhr->php_sendmail = apr_pstrdup(parms->pool, arg);
        break;
    case 10:
        vhr->db_host = apr_pstrdup(parms->pool, arg);
        break;
    case 11:
        vhr->cache_ttl = strtoumax(arg,NULL,10);
        break;
    case 12:
        vhr->cache_maxusage = strtoumax(arg,NULL,10);
        break;
    case 13:
        vhr->cache_cleaninter = strtoumax(arg,NULL,10);
        break;
    }

    return NULL;
}

/*
 * To setting flags
 */
static const char *set_flag(cmd_parms * parms, void *mconfig, int flag)
{
    int pos = (uintptr_t) parms->info;
    vhs_config_rec *vhr = (vhs_config_rec *) ap_get_module_config(parms->server->module_config,
                                      &vhs_module);

    /*      VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, parms->server,
       "set_flag:Flag='%d' for server: '%s' for pos='%d' line: %d",
       flag, parms->server->defn_name, pos, parms->server->defn_line_number ); */
    switch (pos) {
    case 2:
        if (flag) {
            vhr->open_basedir = 1;
        } else {
            vhr->open_basedir = 0;
        }
        break;
    case 4:
        if (flag) {
            vhr->display_errors = 1;
        } else {
            vhr->display_errors = 0;
        }
        break;
    case 5:
        if (flag) {
            vhr->enable = 1;
        } else {
            vhr->enable = 0;
        }
        break;
    case 6:
        if (flag) {
            vhr->append_basedir = 1;
        } else {
            vhr->append_basedir = 0;
        }
        break;
    case 7:
        if (flag) {
            vhr->log_notfound = 1;
        } else {
            vhr->log_notfound = 0;
        }
        break;
    }
    return NULL;
}

typedef struct {
    uid_t uid;
    gid_t gid;
    char *username;
    int nice_value;
} itk_conf;

static void vhs_child_init(apr_pool_t *p, server_rec *s)
{

    /* Now that we are in a child process, we have to reconnect
     * to the global mutex and the shared segment. We also
     * have to find out the base address of the segment, in case
     * it moved to a new address. */

    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, s, "vhs_child_init: uig/euid = %i/%i",getuid(),geteuid());

    apr_status_t rv;
    vhs_config_rec *vhr = ap_get_module_config(s->module_config, &vhs_module);

    if (!vhr->enable) {
        VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, s, "vhs_child_init: Module disabled");
        return;
    }

    if (!vhr->cache_mutex_lockfile) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "vhs_child_init: mod_vhs global mutex file is NULL");
        return;
    }
    rv = apr_global_mutex_child_init(&(vhr->cache_mutex),
                                     vhr->cache_mutex_lockfile, p); 

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "Failed to attach to "
                     "mod_vhs global mutex file '%s'",
                     vhr->cache_mutex_lockfile);
        return;
    } else {
       VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, s, "vhs_child_init: got global mutex");
   }

    /* We only need to attach to the segment if we didn't inherit
     * it from the parent process (ie. Windows) */
    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, s, "vhs_child_init Checking cache segment");
    if (!vhr->cache_shm) {
        VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, s, "vhs_child_init No cache segment");
        rv = apr_shm_attach(&vhr->cache_shm, vhr->cache_shm_file, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "Failed to attach to "
                         "mod_vhs shared memory file '%s'",
                         vhr->cache_shm_file ?
                             /* Just in case the file was NULL. */
                             vhr->cache_shm_file : "NULL");
            return;
        }
    }
    vhr->cache = apr_shm_baseaddr_get(vhr->cache_shm);
}


/*
 * 
 *  Apache hook after configuration 
 *
 */
static int vhs_global_init(apr_pool_t * pconf, apr_pool_t * plog, apr_pool_t * ptemp, server_rec * s)
{
    module *mpm_itk_module = NULL;


    /* Only for final configuration  Apache 2.4 */
    //if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
    //    return OK;

    // for Apache 2.2
    const char userdata_key[] = "mod_vhs_init";
    void *data;
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        /* This is the first time this function is run. */
        apr_pool_userdata_set((const void *)1, userdata_key,
                apr_pool_cleanup_null, s->process->pool);
        return OK;
    }
    

    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, s, "vhs_global_init: loading version %s.", VH_VERSION);
    ap_add_version_component(pconf, VH_VERSION);

    /* set default configuration for vhost */
    mpm_itk_module = ap_find_linked_module(MOD_ITK);
    if (mpm_itk_module == NULL) {
               ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "vhs_global_init: mpm_itk.c is not loaded");
    } else {
        server_rec *sp;
        for (sp = s; sp; sp = sp->next) {
            vhs_config_rec *vhr = (vhs_config_rec *) ap_get_module_config(sp->module_config,
                                              &vhs_module);
            itk_conf *cfg = (itk_conf *) ap_get_module_config(sp->module_config,
                                      mpm_itk_module);
            vhr->itk_defuid = cfg->uid;
            vhr->itk_defgid = cfg->gid;
            vhr->itk_defusername = cfg->username;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sp, "vhs_global_init: itk uid='%d' itk gid='%d'", cfg->uid, cfg->gid);
        }
    }


    /*
            Creates a global mutex and shared memory segment for cache
            The mutex and shm addresses are stored in the module configuration vhr 
    */
    apr_status_t rv;
    vhs_config_rec *vhr;

    vhr = ap_get_module_config(s->module_config, &vhs_module); 
    rv = apr_global_mutex_create(&(vhr->cache_mutex), vhr->cache_mutex_lockfile, APR_LOCK_DEFAULT, pconf);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "vhs_global_init: Failed to create "
                                        "mod_vhs global mutex file '%s'",vhr->cache_mutex_lockfile);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "vhs_global_init: created mutex uid/euid=%i/%i",getuid(),geteuid());


    rv = apr_shm_create(&vhr->cache_shm, 10240*1024, vhr->cache_shm_file, pconf);
    //rv = apr_shm_create(&vhr->cache_shm, sizeof(*vhr->cache),NULL,global_pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "vhs_global_init: Failed to create "
                     "mod_shm_counter shared segment file '%s'", vhr->cache_shm_file);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    vhr->cache = apr_shm_baseaddr_get(vhr->cache_shm);
    memset(vhr->cache, 0, sizeof(*vhr->cache));

    /* 
       Initialize cache structure
    */
    int i = 0;
    for (i = 0; i < NUMCACHE; i++) {
        vhr->cache->added[i] = 0;
        memset(&vhr->cache->keys[i],'\0',sizeof(vhr->cache->keys[i]));
        memset(&vhr->cache->entries[i],'\0',sizeof(vhr->cache->entries[i]));
    }
    
    memset(&vhr->cache->wildcards,'\0',sizeof(vhr->cache->wildcards));
    vhr->cache->lastcleaned = (unsigned long)time(NULL);

     
    return OK;
}

/*
 * Used for redirect subsystem when a hostname is not found
 */
static int vhs_redirect_stuff(request_rec * r, vhs_config_rec * vhr)
{
    if (vhr->default_host) {
        apr_table_setn(r->headers_out, "Location", vhr->default_host);
        VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                "redirect_stuff: using a redirect to %s for %s", vhr->default_host, r->hostname);
        return HTTP_MOVED_TEMPORARILY;
    }
    /* Failsafe */
    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_ALERT, 0, r->server, "redirect_stuff: no host found(non HTTP/1.1 request, no default set) %s", r->hostname);
    return DECLINED;
}

/*
 *  Get the stuff from Mod Flat File
 */
int vhs_redis_lookup(request_rec * r, vhs_config_rec * vhrX, const char *hostname, mod_vhs_request_t * reqc)
{
    const char *host = 0;
    int res;
    struct vhost_config *p;
    uid_t uid = 65534;

    // TODO CACHE
    // VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup :  CACHE counter = %u",vhr->cache->counter);

    vhs_config_rec *vhr = (vhs_config_rec *) ap_get_module_config(r->server->module_config,
                                      &vhs_module);
    if (!vhr->enable) {
        return DECLINED;
    }
    if (reqc->vhost_found != VH_VHOST_INFOS_NOT_YET_REQUESTED) {
         return OK;
    }
    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup -------------------%s --------------------",r->hostname);
    reqc->usage += 1;

    if (r->hostname == NULL)
        host = vhr->default_host;
    else
        host = r->hostname;
    /* host = ap_get_server_name(r); */
    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: search for vhost: '%s'", host);
    p = new_vhost_config(r->pool);



    int cache_found = 0;
    char *cache_conf = NULL;
    int i = 0;
    unsigned now = (unsigned)time(NULL);
    char *wildcards = NULL;

    if (vhr->cache_mutex != NULL) {
        VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: looking for cache host='%s'",host);
        for (i = 0; i < NUMCACHE; i++) {
           if (now - vhr->cache->added[i] < vhr->cache_ttl && memcmp(host,&vhr->cache->keys[i],strlen(host)) == 0) {
               cache_conf = apr_pcalloc(r->pool, sizeof(vhr->cache->entries[i]));
               memcpy(cache_conf,&vhr->cache->entries[i],sizeof(vhr->cache->entries[i]));
               VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: found cache for '%s' ==> %s", host,cache_conf);
               break;
           }
        }
        if (strlen(vhr->cache->wildcards) > 2) {
            wildcards = apr_pcalloc(r->pool, strlen(vhr->cache->wildcards)+1);
            memcpy(wildcards,vhr->cache->wildcards,strlen(vhr->cache->wildcards));
        }
    } else {
        VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: no cache mutex '%s'",host);
    } 

    if (cache_conf != NULL && strlen(cache_conf) > 10) {
        res = vhost_parseconfline(cache_conf, p, r->pool);
        VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup:  conf from cache line %s",p->directory);
        cache_found = 1;
    } else {
        VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: fetch config for %s  uid/euid/gid/egid=%i/%i/%i/%i",host,getuid(),geteuid(),getgid(),getegid());
        res = vhost_getconfig(vhr->tenant, host, p, r->pool);
        /* Not found, tries with wildcards */
        if (res > 0) {
           VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: no config for %s, checking wildcards ...", host);
           if (wildcards == NULL) {
               VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_host: need to fetch wildcards");
               vhost_getwildcards(vhr->tenant, &wildcards, r->pool);
           }
           res = vhost_getconfig_glob(vhr->tenant, host, p, r->pool, wildcards);
        }
    }

    if (res > 0) {
        VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: no config found for '%s' [res=%i]", host, res);
        VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: search for vhost: '%s'", vhr->default_host);
        res = vhost_getconfig(vhr->tenant, vhr->default_host,p, r->pool);
        if (res > 0) {
            p->vhost = "localhost";
            p->user = "www-data";
            p->directory = "/var/www/default/";
            p->mysql_socket = "/var/run/mysqld/mysqld.sock";
            p->php_config = NULL;
            p->cache = "localhost|localhost|www-data|/var/www/default/|/var/run/mysqld/mysqld.sock|";
        }
    }
    /* servername */
    reqc->name = apr_pstrdup(r->pool, p->vhost);
    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: server_name: %s", reqc->name);

    /* document root */
    reqc->docroot = apr_pstrdup(r->pool, p->directory);
    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: docroot: %s", reqc->docroot);

    /* suexec UID */
    struct passwd pwd;
    struct passwd *result;
    size_t bufsize = 16384;
    char *buf;
    //uid_t uid = 65534;
    int s;
    buf = apr_pcalloc(r->pool,bufsize);
    s = getpwnam_r(p->user, &pwd, buf, bufsize, &result);
    if (s > 0 || result != NULL) {
        uid = pwd.pw_uid;
    } else {
        pwd.pw_uid = uid;
    }
    sprintf(buf, "%d", pwd.pw_uid);
    reqc->uid = apr_pstrdup(r->pool, buf);
    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: uid: %s", reqc->uid);

    sprintf(buf, "%d", pwd.pw_gid);
    reqc->gid = apr_pstrdup(r->pool, buf);
    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: gid: %s", reqc->gid);

    /* GECOS : username */
    reqc->gecos = apr_pstrdup(r->pool, p->user);
    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: gecos: %s", reqc->gecos);

    /* suexec GID */
    //reqc->gid = apr_pstrdup(r->pool, "1002");
    //VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: gid: %s", reqc->gid);

    /* associate domain */
    reqc->associateddomain = apr_pstrdup(r->pool, p->vhost);
    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: associateddomain: %s", reqc->associateddomain);

    /* MySQL socket */
    reqc->mysql_socket = apr_pstrdup(r->pool, p->mysql_socket);
    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: mysql_socket: %s", reqc->mysql_socket);

    /* PHP mode */
    //reqc->php_mode = apr_pstrdup(r->pool, p->php_mode);
    //VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: php_mode: %s", reqc->php_mode);

    /* phpopt_fromdb / options PHP */
    reqc->php_config = p->php_config;
    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: php_config: %s","ARRAY");

    /* PHP modules */
    //reqc->php_modules = apr_pstrdup(r->pool, p->php_modules);
    //VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: php_modules: %s", reqc->php_modules);

    /* the vhost has been found, set vhost_found to VH_VHOST_INFOS_FOUND */
    reqc->vhost_found = VH_VHOST_INFOS_FOUND;

    apr_pool_userdata_set(reqc, VH_KEY, apr_pool_cleanup_null, r->pool);

    if (vhr->cache_mutex != NULL) {
        int rv;
        if (strlen(p->cache) < sizeof(vhr->cache->entries[0]) && cache_found == 0) {
            rv = apr_global_mutex_lock(vhr->cache_mutex);
             if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_CRIT, rv, r, "vhs_redis_lookup: apr_global_mutex_lock failed for cache uid/euid=%i/%i",getuid(),geteuid());
                //return HTTP_INTERNAL_SERVER_ERROR;
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, "vhs_redis_lookup: apr_global_mutex_lock SUCCESS for cache uid/euid=%i/%i",getuid(),geteuid());

                // Add json to cache
                for (i = 0; i < NUMCACHE; i++) {
                    if (vhr->cache->added[i] == 0 || (now - vhr->cache->added[i] > vhr->cache_ttl)) {
                        vhr->cache->added[i] = now;
                        memcpy(&vhr->cache->keys[i],host,strlen(host));
                        vhr->cache->keys[i][strlen(host)] = '\0';
                        memset(&vhr->cache->entries[i],'\0',sizeof(vhr->cache->entries[i]));
                        memcpy(&vhr->cache->entries[i],p->cache,strlen(p->cache)+1);
                        VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: cache entry set for %s [%s] %s size=%i",r->hostname,host,(char*) &vhr->cache->entries[i], (int) sizeof(vhr->cache->entries[i]));
                        break;
                    }
                }
                // Saves wildcards into cache
                if (wildcards != NULL)
                    memcpy(vhr->cache->wildcards,wildcards,4096);
            }

            vhs_cache_clean(r, vhr);
            apr_global_mutex_unlock(vhr->cache_mutex);
        }
    }

    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_redis_lookup: DONE");

    return OK;
}

/*
 * This function will configure MPM-ITK
 */
static int vhs_itk_post_read(request_rec * r)
{
    uid_t libhome_uid;
    gid_t libhome_gid;
    int vhost_found_by_request = DECLINED;

    vhs_config_rec *vhr = (vhs_config_rec *) ap_get_module_config(r->server->module_config,
                                      &vhs_module);
    mod_vhs_request_t *reqc;

    reqc = ap_get_module_config(r->request_config, &vhs_module);
    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: BEGIN2 uid=%d",getuid());

    if (reqc) {
         VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: subrequest reqc->added=%lu", reqc->added);
         return OK;
    }

    if (getuid() >= 1000 && r->prev) { 
        reqc = ap_get_module_config(r->prev->request_config, &vhs_module);
        if (reqc) {
            VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: subrequest for req_conf logid=%s, %lu", r->hostname, reqc->added);
            ap_set_module_config(r->request_config, &vhs_module, reqc);
        }            
        return OK;
    }

    reqc = (mod_vhs_request_t *) apr_pcalloc(r->pool, sizeof(mod_vhs_request_t));
    reqc->vhost_found = VH_VHOST_INFOS_NOT_YET_REQUESTED;
    reqc->added = (unsigned long) time(NULL);
    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: reqc->added=%lu",reqc->added );
    ap_set_module_config(r->request_config, &vhs_module, reqc);

    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: Getting host config for %s", r->hostname);
    vhost_found_by_request = vhs_redis_lookup(r, vhr, r->hostname, reqc);
    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: vhost_found_by_request");
    if (vhost_found_by_request == OK) {
        VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: vhost_found_by_request = OK");
        libhome_uid = atoi(reqc->uid);
        libhome_gid = atoi(reqc->gid);
        VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: uid/gid = %i/%i",libhome_uid,libhome_gid);
    } else {
        VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: vhost_found_by_request = NOT OK");
        libhome_uid = vhr->itk_defuid;
        libhome_gid = vhr->itk_defgid;
    }

    module *mpm_itk_module = ap_find_linked_module(MOD_ITK);
    if (mpm_itk_module == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "vhs_itk_post_read: mpm_itk.c is not loaded");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    itk_conf *cfg = (itk_conf *) ap_get_module_config(r->per_dir_config, mpm_itk_module);

    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: GOT ITK CONFIG");

    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r,
             "vhs_itk_post_read: itk uid='%d' itk gid='%d' itk username='%s' before change", cfg->uid, cfg->gid, cfg->username);
    if ((libhome_uid == -1 || libhome_gid == -1)) {
        VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: -1 || -1");
        cfg->uid = vhr->itk_defuid;
        cfg->gid = vhr->itk_defgid;
        cfg->username = vhr->itk_defusername;
    } else {
        VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: setting uid/gid/setting uid/gid/username = %d/%d/%s", libhome_uid,libhome_gid,reqc->gecos);
        char *itk_username = NULL;
        cfg->uid = libhome_uid;
        cfg->gid = libhome_gid;

        /* set the username - otherwise MPM-ITK will not work */
        /* itk_username = apr_psprintf(r->pool, "%s", pw->pw_name); */
        /* Why root ? */
        itk_username = apr_psprintf(r->pool, "%s", reqc->gecos);
        cfg->username = itk_username;
    }
    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r,
             "vhs_itk_post_read: itk uid='%d' itk gid='%d' itk username='%s' after change", cfg->uid, cfg->gid, cfg->username);
    VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: END ***");

    // PLANET-WORK - Setup some variables for CGI scripts //
    apr_table_setn(r->subprocess_env, "PHP_DOCUMENT_ROOT", reqc->docroot);
    apr_table_setn(r->subprocess_env, "MYSQL_UNIX_PORT", reqc->mysql_socket);
    apr_table_setn(r->subprocess_env, "MYSQL_HOST", basename(reqc->mysql_socket));
    /*
    char *phprc = apr_pcalloc(r->pool,512);
    sprintf(phprc, "/home/php_ini/%s/", reqc->associateddomain);
    apr_table_setn(r->subprocess_env, "PHPRC", phprc);
    apr_table_setn(r->subprocess_env, "VH_GECOS", reqc->gecos);
    apr_table_setn(r->subprocess_env, "VH_PATH", reqc->docroot);
    apr_table_setn(r->subprocess_env, "VH_HOST", reqc->name);
    */

    return OK;
}

/*
 * This function will configure on the fly the php like php.ini will do
 */

static void vhs_php_ini(char *name, char *value, request_rec * r)
{
#ifdef VH_PHP7
    php_conf_rec *d = NULL;
    php_dir_entry e;
    zend_string *key = zend_string_init(name, strlen(name), 0);
    if (zend_alter_ini_entry_chars(key, value, strlen(value), ZEND_INI_SYSTEM, ZEND_INI_STAGE_ACTIVATE) != SUCCESS) {
        //fprintf(stderr,"Unable to set %s=%s\n", key->val,value);
    }
    zend_string_release(key);
#else
    int res;
    res = zend_alter_ini_entry(name, strlen(name)+1, value, strlen(value), ZEND_INI_SYSTEM, ZEND_INI_STAGE_ACTIVATE);
    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "php_ini_entry %s > %s ==> %i", name,value,res);
#endif

}

static void vhs_php_config(request_rec * r, vhs_config_rec * vhr, mod_vhs_request_t * reqc)
{
    php_conf_rec *php_conf;
#ifdef VH_PHP7
    module *php_module = ap_find_linked_module("mod_php7.c");
#else
    module *php_module = ap_find_linked_module("mod_php5.c");
#endif

    if (php_module == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "vhs_php_config: mod_php[57].c is not loaded");
        return;
    }

    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: path ? %s", reqc->docroot);
    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: mysql_socket ? %s", reqc->mysql_socket);
    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: php_config ? %s", "ARRAY");

    /*
     * Some Basic PHP stuff, thank to Igor Popov module
     */
    apr_table_set(r->subprocess_env, "PHP_DOCUMENT_ROOT", reqc->docroot);

    php_conf = ap_get_module_config(r->per_dir_config, php_module);
    
    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: PHP INI  %s / %i  [%s] --- %u",php_module->name,php_module->module_index,r->server->server_hostname,zend_hash_num_elements(&php_conf->config));
    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: PHP INI session.save_path=%s",zend_ini_string("session.save_path",strlen("session.save_path"),0));

    vhs_php_ini("doc_root", reqc->docroot, r);

    /*
     * vhs_PHPopen_baserdir    \ vhs_append_open_basedir |  support
     * vhs_open_basedir_path   /
     */
    /*  PLANET-WORK   fix for PHP bug http://bugs.php.net/bug.php?id=52312
       if(vhr->open_basedir) {
       if(vhr->append_basedir && vhr->openbdir_path) {
       //
       // There is a default open_basedir path and
       // configuration allow appending them
       //
       char *obasedir_path;

       if(vhr->path_prefix) {
       obasedir_path = apr_pstrcat(r->pool, vhr->openbdir_path, ":", vhr->path_prefix, path, NULL);
       } else {
       obasedir_path = apr_pstrcat(r->pool, vhr->openbdir_path, ":", path, NULL);
       }
       zend_alter_ini_entry("open_basedir", 13, obasedir_path, strlen(obasedir_path), ZEND_INI_SYSTEM, ZEND_INI_STAGE_ACTIVATE);
       VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: PHP open_basedir set to %s(appending mode)", obasedir_path);
       } else {
       zend_alter_ini_entry("open_basedir", 13, path, strlen(path), ZEND_INI_SYSTEM, ZEND_INI_STAGE_ACTIVATE);
       VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: PHP open_basedir set to %s", path);
       }
       } else {
       VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: PHP open_basedir inactive defaulting to php.ini values");
       }
     */
    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: server_name : %s", r->hostname);

    /*
     * vhs_PHPopt_fromdb
     */
    if (vhr->phpopt_fromdb) {
        VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: PHP from DB engaged");
        /* Custom PHP settings */
        if (reqc->php_config != NULL) {
            apr_hash_index_t *hidx = NULL;
            for (hidx = apr_hash_first(r->pool, reqc->php_config); hidx; hidx = apr_hash_next(hidx)) { 
                const void *key;
                void *val;
                apr_hash_this(hidx, &key, NULL, &val);
                if (val != NULL) {
                    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG,
                            0, r->server, "vhs_php_config: Zend PHP Stuff => %s => %s", (char *) key, (char *) val);
                    vhs_php_ini((char *) key, val, r);
                }
            }
        } else {
            VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: no PHP stuff found.");
        }

        /* Settings depending on mysql socket value */
        VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: Setting Mysql socket");
        vhs_php_ini("mysql.default_socket", reqc->mysql_socket, r);
        vhs_php_ini("mysqli.default_socket", reqc->mysql_socket, r);
        vhs_php_ini("pdo_mysql.default_socket", reqc->mysql_socket, r);

        /* sendmail_secure */
        VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: Setting sendmail-secure :%s",reqc->associateddomain);
        char *sendmail_path = (char *) apr_pcalloc(r->pool, strlen(vhr->php_sendmail)
                             + strlen(reqc->associateddomain) + 1);
        sprintf(sendmail_path,"%s %s",vhr->php_sendmail,reqc->associateddomain);
        vhs_php_ini("sendmail_path", sendmail_path, r);

        /* Redis sessions */
        VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: Setting session handler");
        char *save_path = (char *)
            apr_pcalloc(r->pool,strlen(vhr->php_sessions) + strlen(reqc->gecos) + 2);
        sprintf(save_path,"%s_%s",vhr->php_sessions,reqc->gecos);
        vhs_php_ini("session.save_path", save_path, r);
        vhs_php_ini("session.save_handler", "redis", r);
        VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: session.save_path: %s", save_path);

    }
}

/*
 * Send the right path to the end user uppon a request.
 */
static int vhs_translate_name(request_rec * r)
{
    vhs_config_rec *vhr = (vhs_config_rec *) ap_get_module_config(r->server->module_config,
                                      &vhs_module);
    core_server_config *conf = (core_server_config *) ap_get_module_config(r->server->module_config,
                                           &core_module);

    const char *host = 0;
    /* mod_alias like functions */
    char *ret = 0;
    int status = 0;

    /* Stuff */
    char *ptr = 0;

    mod_vhs_request_t *reqc;
    int vhost_found_by_request = DECLINED;

    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: BEGIN ************************************************");
    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: the_request:%s", r->the_request);
    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: unparsed_uri:%s", r->unparsed_uri);
    //VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: useragent_ip:%s", r->useragent_ip);
    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: method:%s", r->method);
    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: uri:%s", r->uri);
    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: path_info:%s", r->path_info);
    //VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: log_id:%s", r->log_id);
    //VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: connection>id:%d", r->connection);
    //VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: main:%d", r->main);

    /* If VHS is not enabled, then don't process request */
    if (!vhr->enable) {
        VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: VHS Disabled ");
        return DECLINED;
    }

    // Sub-request
    if (r->main != NULL) {
         VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: Subrequest ! ");
         reqc = ap_get_module_config(r->main->request_config, &vhs_module); 
    } else {
        reqc = ap_get_module_config(r->request_config, &vhs_module);
    }

    if (!reqc) {
        //VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: variable reqc does not already exists.... creating ! pid=%d request_rec=%d @request_config='%d'", getpid(), r, &(r->request_config));
        reqc = (mod_vhs_request_t *) apr_pcalloc(r->pool, sizeof(mod_vhs_request_t));
        reqc->vhost_found = VH_VHOST_INFOS_NOT_YET_REQUESTED;
        ap_set_module_config(r->request_config, &vhs_module, reqc);
    } else {
       //VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: variable reqc already exists ! pid=%d request_rec=%d @request_config='%d'", getpid(), r, &(r->request_config));
    } 
    /* Handle alias stuff */
    if ((ret = try_alias_list(r, vhr->redirects, 1, &status)) != NULL) {
        if (ap_is_HTTP_REDIRECT(status)) {
            /* include QUERY_STRING if any */
            if (r->args) {
                ret = apr_pstrcat(r->pool, ret, "?", r->args, NULL);
            }
            apr_table_setn(r->headers_out, "Location", ret);
        }
        return status;
    }
    if ((ret = try_alias_list(r, vhr->aliases, 0, &status)) != NULL) {
        r->filename = ret;
        return OK;
    }
    /* Avoid handling request that don't start with '/' */
    if (r->uri[0] != '/' && r->uri[0] != '\0') {
        ap_log_error(APLOG_MARK, APLOG_ALERT, 0, r->server, "vhs_translate_name: declined %s no leading `/'", r->uri);
        return DECLINED;
    }
    if (!(host = apr_table_get(r->headers_in, "Host"))) {
        return vhs_redirect_stuff(r, vhr);
    }
    if ((ptr = ap_strchr(host, ':'))) {
        *ptr = '\0';
    }

    if (reqc->vhost_found == VH_VHOST_INFOS_NOT_YET_REQUESTED) {
        VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: looking for %s", host);
        /*
         * Trying to get vhost information
         */
        vhost_found_by_request = vhs_redis_lookup(r, vhr, (char *)host, reqc);
        if (vhost_found_by_request != OK) {
            if (vhr->log_notfound) {
                ap_log_error(APLOG_MARK, APLOG_NOTICE,
                         0, r->server,
                         "vhs_translate_name: no host found in database for %s(lamer mode not eanbled)", host);
            }
            return vhs_redirect_stuff(r, vhr);
        }
    } else {
        VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                "vhs_translate_name: Request to backend has already be done(vhs_itk_post_read()) !");
        if (reqc->vhost_found == VH_VHOST_INFOS_NOT_FOUND)
            vhost_found_by_request = DECLINED;    /* the request has already be done and vhost was not found */
        else
            vhost_found_by_request = OK;    /* the request has already be done and vhost was found */
    }

    if (vhost_found_by_request == OK)
        VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                "vhs_translate_name: path found in database for %s is %s", host, reqc->docroot);
    else {
        if (vhr->log_notfound) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server,
                     "vhs_translate_name: no path found found in database for %s(normal)", host);
        }
        return vhs_redirect_stuff(r, vhr);
    }

    apr_table_set(r->subprocess_env, "VH_HOST", host);
    apr_table_set(r->subprocess_env, "MYSQL_UNIX_PORT", reqc->mysql_socket ? reqc->mysql_socket : "");
    if (strcmp(reqc->mysql_socket,"/var/run/mysqld/mysqld.sock")) {
         apr_table_setn(r->subprocess_env, "MYSQL_HOST", reqc->mysql_socket ? basename(reqc->mysql_socket) : "");
    } else {
         apr_table_setn(r->subprocess_env, "MYSQL_HOST", "localhost");
    }
    apr_table_set(r->subprocess_env, "VH_GECOS", reqc->associateddomain ? reqc->associateddomain : "");
    /* Do we have handle vhr_Path_Prefix here ? */
    if (vhr->path_prefix) {
        apr_table_set(r->subprocess_env, "VH_PATH", apr_pstrcat(r->pool, vhr->path_prefix, reqc->docroot, NULL));
        apr_table_set(r->subprocess_env, "SERVER_ROOT", apr_pstrcat(r->pool, vhr->path_prefix, reqc->docroot, NULL));
    } else {
        apr_table_set(r->subprocess_env, "VH_PATH", reqc->docroot);
        apr_table_set(r->subprocess_env, "SERVER_ROOT", reqc->docroot);
    }

    if (reqc->admin) {
        r->server->server_admin = apr_pstrcat(r->pool, reqc->admin, NULL);
    } else {
        r->server->server_admin = apr_pstrcat(r->pool, "webmaster@", r->hostname, NULL);
    }
    r->server->server_hostname = apr_pstrcat(r->connection->pool, host, NULL);
    r->parsed_uri.path = apr_pstrcat(r->pool, vhr->path_prefix ? vhr->path_prefix : "", reqc->docroot, r->parsed_uri.path, NULL);
    r->parsed_uri.hostname = r->server->server_hostname;
    r->parsed_uri.hostinfo = r->server->server_hostname;

    /* document_root */
    if (vhr->path_prefix) {
        conf->ap_document_root = apr_pstrcat(r->pool, vhr->path_prefix, reqc->docroot, NULL);
    } else {
        conf->ap_document_root = apr_pstrcat(r->pool, reqc->docroot, NULL);
    }

    // PLANET-WORK
    conf->ap_document_root = apr_pstrcat(r->pool, reqc->docroot, NULL);
    /* if directory exist */
    if (!ap_is_directory(r->pool, reqc->docroot)) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, 0, r->server, "vhs_translate_name: homedir '%s' is not dir at all", reqc->docroot);
        return DECLINED;
    }
    r->filename = apr_psprintf(r->pool, "%s%s%s", vhr->path_prefix ? vhr->path_prefix : "", reqc->docroot, r->uri);

    /* Avoid getting two // in filename */
    ap_no2slash(r->filename);

    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: translated http://%s%s to file %s", host, r->uri, r->filename);

    vhs_php_config(r, vhr, reqc);

    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: END ***");
    return OK;
}

/*
 * Stuff for register the module
 */
static const command_rec vhs_commands[] = {
    AP_INIT_FLAG("EnableVHS", set_flag, (void *)5, RSRC_CONF,
             "Enable VHS module"),

    AP_INIT_TAKE1("vhs_Path_Prefix", set_field, (void *)1, RSRC_CONF,
              "Set path prefix."),
    AP_INIT_TAKE1("vhs_Default_Host", set_field, (void *)2, RSRC_CONF,
              "Set default host if HTTP/1.1 is not used."),
    AP_INIT_FLAG("vhs_LogNotFound", set_flag, (void *)7, RSRC_CONF,
             "Log on error log when host or path is not found."),
    AP_INIT_FLAG("vhs_PHPopen_basedir", set_flag, (void *)2, RSRC_CONF,
             "Set PHP open_basedir to path"),
    AP_INIT_FLAG("vhs_PHPdisplay_errors", set_flag, (void *)4, RSRC_CONF,
             "Enable PHP display_errors"),
    AP_INIT_FLAG("vhs_append_open_basedir", set_flag, (void *)6, RSRC_CONF,
             "Append homedir path to PHP open_basedir to vhs_open_basedir_path."),
    AP_INIT_TAKE1("vhs_open_basedir_path", set_field, (void *)3, RSRC_CONF,
              "The default PHP open_basedir path."),
    AP_INIT_TAKE2("vhs_Alias", add_alias, NULL, RSRC_CONF,
              "a fakename and a realname"),
    AP_INIT_TAKE2("vhs_ScriptAlias", add_alias, "cgi-script", RSRC_CONF,
              "a fakename and a realname"),
    AP_INIT_TAKE23("vhs_Redirect", add_redirect,
               (void *)HTTP_MOVED_TEMPORARILY, OR_FILEINFO,
               "an optional status, then document to be redirected and " "destination URL"),
    AP_INIT_TAKE2("vhs_AliasMatch", add_alias_regex, NULL, RSRC_CONF,
              "a regular expression and a filename"),
    AP_INIT_TAKE2("vhs_ScriptAliasMatch", add_alias_regex, "cgi-script",
              RSRC_CONF, "a regular expression and a filename"),
    AP_INIT_TAKE23("vhs_RedirectMatch", add_redirect_regex,
               (void *)HTTP_MOVED_TEMPORARILY, OR_FILEINFO,
               "an optional status, then a regular expression and " "destination URL"),
    AP_INIT_TAKE2("vhs_RedirectTemp", add_redirect2,
              (void *)HTTP_MOVED_TEMPORARILY, OR_FILEINFO,
              "a document to be redirected, then the destination URL"),
    AP_INIT_TAKE2("vhs_RedirectPermanent", add_redirect2,
              (void *)HTTP_MOVED_PERMANENTLY, OR_FILEINFO,
              "a document to be redirected, then the destination URL"),

    AP_INIT_TAKE1("vhs_PhpSessionAddr", set_field, (void *)8, RSRC_CONF, "PHP Session address (Redis)"),
    AP_INIT_TAKE1("vhs_PhpSendmailPath", set_field, (void *)9, RSRC_CONF, "PHP sendmail_path"),
    AP_INIT_TAKE1("vhs_RedisHost", set_field, (void *)10, RSRC_CONF, "Host for redis vhosts DB "),

    AP_INIT_TAKE1("vhs_CacheTTL", set_field, (void *)11, RSRC_CONF, "Cache TTL"),
    AP_INIT_TAKE1("vhs_CacheMaxUsage", set_field, (void *)12, RSRC_CONF, "Cache max usage"),
    AP_INIT_TAKE1("vhs_CacheCleanInter", set_field, (void *)13, RSRC_CONF, "Cache clean interval "),
    {NULL}
};

static void register_hooks(apr_pool_t * p)
{
    /* Modules that have to be loaded before mod_vhs */
    static const char *const aszPre[] = { "mod_userdir.c", "mod_vhost_alias.c", MOD_ITK, 
        
        
        NULL };
    /* Modules that have to be loaded after mod_vhs */
    static const char *const aszSucc[] = { "mod_php.c",  
#ifdef VH_PHP7
         "mod_php7.c",
#else
         "mod_php5.c",
#endif
            NULL };


    static const char *const aszSuc_itk[] = { MOD_ITK, NULL };
    ap_hook_post_read_request(vhs_itk_post_read, NULL, aszSuc_itk, APR_HOOK_REALLY_FIRST);
    //ap_hook_header_parser(vhs_itk_post_read, NULL, aszSuc_itk, -15);

    ap_hook_child_init(vhs_child_init, NULL, NULL, APR_HOOK_REALLY_FIRST); /// 
    ap_hook_post_config(vhs_global_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_translate_name(vhs_translate_name, aszPre, aszSucc, APR_HOOK_FIRST);
    //ap_hook_handler(vhs_php_config, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_fixups(fixup_redir, NULL, NULL, APR_HOOK_MIDDLE);

}

AP_DECLARE_DATA module vhs_module = {
    STANDARD20_MODULE_STUFF,
    create_alias_dir_config,    /* create per-directory config structure */
    merge_alias_dir_config,    /* merge per-directory config structures */
    vhs_create_server_config,    /* create per-server config structure */
    vhs_merge_server_config,    /* merge per-server config structures */
    vhs_commands,        /* command apr_table_t */
    register_hooks        /* register hooks */
};
