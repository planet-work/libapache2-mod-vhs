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
/*
 * Brief instructions to use mod_vhs with apache2-mpm-itk support.
 * - To compile mod_vhs with apache2-mpm-itk support add "-DHAVE_MPM_ITK_SUPPORT" to your "CFLAGS".
 * - To enable apache2-mpm-itk support set "vhs_itk_enable On" in your <VirtualHost> section.
 * - Pass the uidNumber and gidNumber to the uid and gid directive in your home.conf like the example in the README file.
 */

#include "mod_vhs.h"

#define VH_KEY "mod_vhs"

int vhs_consul_lookup(request_rec * r, vhs_config_rec * vhr, const char *hostname, mod_vhs_request_t * reqc);
/*
 * Let's start coding
 */
module AP_MODULE_DECLARE_DATA vhs_module;

/*
 * Apache per server config structure
 */
static void *vhs_create_server_config(apr_pool_t * p, server_rec * s)
{
	vhs_config_rec *vhr = (vhs_config_rec *) apr_pcalloc(p, sizeof(vhs_config_rec));
    apr_pool_t *cache_pool;

	/*
	 * Pre default the module is not enabled
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
	vhr->db_host = NULL;
	vhr->cache_counter = 0;
	vhr->cache_lastclean = (unsigned)time(NULL);

	apr_pool_create(&cache_pool,p);
	vhr->cache = apr_hash_make (cache_pool);

	return (void *)vhr;
}

static void *vhs_cache_clean(request_rec * r, vhs_config_rec * vhr) {
	apr_hash_index_t *hi;
	void *val;
	mod_vhs_request_t *reqc;
	unsigned now = (unsigned)time(NULL);
	if (now - vhr->cache_lastclean < 10) {
		return NULL;
	}
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_cache_clean: hash %u, %i",vhr->cache, apr_hash_count(vhr->cache));
    //VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_cache_clean: STARTING CACHE CLEANUP");
	for (hi = apr_hash_first(NULL, vhr->cache); hi; hi = apr_hash_next(hi)) {
		apr_hash_this(hi, NULL, NULL, &val);
		reqc = (mod_vhs_request_t*) val;
        VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_cache_clean: entry %s / usage=%i, added=%u, docroot=%s, @=%u",reqc->name,reqc->usage,reqc->added,reqc->docroot,hi);

	}
    //VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_cache_clean: FINISHED CACHE CLEANUP");
	vhr->cache_lastclean = now;
	return NULL;
}

/*
 * Apache merge per server config structures
 */
static void *vhs_merge_server_config(apr_pool_t * p, void *parentv, void *childv)
{
	vhs_config_rec *parent = (vhs_config_rec *) parentv;
	vhs_config_rec *child = (vhs_config_rec *) childv;
	vhs_config_rec *conf = (vhs_config_rec *) apr_pcalloc(p, sizeof(vhs_config_rec));

	conf->enable = (child->enable ? child->enable : parent->enable);
	conf->db_mode = (child->db_mode ? child->db_mode : parent->db_mode);
	conf->path_prefix = (child->path_prefix ? child->path_prefix : parent->path_prefix);
	conf->default_host = (child->default_host ? child->default_host : parent->default_host);
	conf->lamer_mode = (child->lamer_mode ? child->lamer_mode : parent->lamer_mode);
	conf->log_notfound = (child->log_notfound ? child->log_notfound : parent->log_notfound);

	conf->open_basedir = (child->open_basedir ? child->open_basedir : parent->open_basedir);
	conf->display_errors = (child->display_errors ? child->display_errors : parent->display_errors);
	conf->append_basedir = (child->append_basedir ? child->append_basedir : parent->append_basedir);
	conf->openbdir_path = (child->openbdir_path ? child->openbdir_path : parent->openbdir_path);
	conf->phpopt_fromdb = (child->phpopt_fromdb ? child->phpopt_fromdb : parent->phpopt_fromdb);

	conf->itk_enable = (child->itk_enable ? child->itk_enable : parent->itk_enable);

	conf->tenant = (child->tenant ? child->tenant : parent->tenant);
	conf->db_host = (child->db_host ? child->db_host : parent->db_host);

	conf->aliases = apr_array_append(p, child->aliases, parent->aliases);
	conf->redirects = apr_array_append(p, child->redirects, parent->redirects);

	return conf;
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

		/* Flag to set the correct mode(LDAP or DBD) when module has both support */
	case 11:
		if (strcmp(arg, "ldap") == 0) {
			vhr->db_mode = 1;
		} else if (strcmp(arg, "dbd") == 0) {
			vhr->db_mode = 2;
		} else if (strcmp(arg, "flat") == 0) {
			vhr->db_mode = 3;
		} else {
			vhr->db_mode = 0;
			return "Unrecognized value for vhs_dbmode directive. Use ldap or dbd ! Module is disabled.";
		}
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
	case 0:
		if (flag) {
			vhr->lamer_mode = 1;
		} else {
			vhr->lamer_mode = 0;
		}
		break;
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

static int vhs_init_handler(apr_pool_t * pconf, apr_pool_t * plog, apr_pool_t * ptemp, server_rec * s)
{
	VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, s, "loading version %s.", VH_VERSION);

	ap_add_version_component(pconf, VH_VERSION);

	unsigned short int itk_enable = 1;
	server_rec *sp;

	module *mpm_itk_module = ap_find_linked_module("mpm_itk.c");
	if (mpm_itk_module == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "vhs_init_handler: mpm_itk.c is not loaded");
		itk_enable = 0;
	}

	for (sp = s; sp; sp = sp->next) {
		vhs_config_rec *vhr = (vhs_config_rec *) ap_get_module_config(sp->module_config,
									      &vhs_module);

		if (vhr->itk_enable) {
			if (!itk_enable) {
				vhr->itk_enable = 0;
			} else {
				itk_conf *cfg = (itk_conf *) ap_get_module_config(sp->module_config,
										  mpm_itk_module);
				vhr->itk_defuid = cfg->uid;
				vhr->itk_defgid = cfg->gid;
				vhr->itk_defusername = cfg->username;

				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, sp, "vhs_init_handler: itk uid='%d' itk gid='%d' "
					     /*itk username='%s' */ , cfg->uid,
					     cfg->gid /*, cfg->username */ );
			}
		}
	}

	ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "vhs_init_handler: mpm_itk.c is not loaded");

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
int vhs_consul_lookup(request_rec * r, vhs_config_rec * vhr, const char *hostname, mod_vhs_request_t * reqc)
{
	const char *host = 0;
	int res;
	struct vhost_config *p;
	uid_t uid = 65534;
	mod_vhs_request_t *reqc_cache;




	vhr->tenant = getenv("TENANT");
	/*if (vhr->tenant == NULL || vhr->db_host == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "vhs_consul_lookup: No Tenant or DB Host specified");
		return DECLINED;
	}*/

	if (!vhr->enable) {
		return DECLINED;
	}

	if (reqc->vhost_found != VH_VHOST_INFOS_NOT_YET_REQUESTED) {
         return OK;
	}

	vhs_cache_clean(r,vhr);

	reqc->added = (unsigned)time(NULL);
	reqc_cache = apr_hash_get(vhr->cache,r->hostname,APR_HASH_KEY_STRING);
	if (reqc_cache != NULL) {
		//reqc = reqc_cache;
		reqc_cache->usage += 1; 
		VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup : reusing cache %s [%i] added:%u  @=%u",r->hostname,reqc_cache->usage,reqc_cache->added,reqc_cache);
        
		//reqc = (mod_vhs_request_t *) apr_pcalloc(r->pool, sizeof(mod_vhs_request_t));
		reqc->name = apr_pstrdup(r->pool, reqc_cache->name);
		reqc->associateddomain = apr_pstrdup(r->pool, reqc_cache->associateddomain);
		reqc->uid = apr_pstrdup(r->pool, reqc_cache->uid);
		reqc->gid = apr_pstrdup(r->pool, reqc_cache->gid);
		reqc->docroot = apr_pstrdup(r->pool, reqc_cache->docroot);
		reqc->gecos = apr_pstrdup(r->pool, reqc_cache->gecos);
		reqc->phpoptions = apr_pstrdup(r->pool, reqc_cache->phpoptions);
		reqc->mysql_socket = apr_pstrdup(r->pool, reqc_cache->mysql_socket);
        apr_pool_userdata_set(reqc, VH_KEY, apr_pool_cleanup_null, r->pool);
		VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup : reusing cached docroot %s", reqc->docroot);
        return OK;
	}

	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup : no cache for %s @=%u / @=%u",r->hostname,vhr->cache,reqc_cache);

	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup -------------------%s---------------[%i]-----",r->hostname,vhr->cache_counter);

	if (r->hostname == NULL)
		host = vhr->default_host;
	else
		host = r->hostname;
	/* host = ap_get_server_name(r); */
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: search for vhost: '%s'", host);
	p = new_vhost_config(r->pool);
	res = vhost_getconfig(vhr->tenant, host, p, r->pool);

	if (res > 0) {
		VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: not config found for '%s'", host);
		VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: search for vhost: '%s'", vhr->default_host);
		res = vhost_getconfig(vhr->tenant, vhr->default_host,p, r->pool);
		//VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: got nothing for '%s'(%i)", host,p);
        if (res > 0) {
			p->vhost = "localhost";
			p->user = "www-data";
			p->directory = "/var/www/";
			p->mysql_socket = "/var/run/mysqld/mysqld.sock";
			p->php_config = "";
		}
	}
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: dbd is ok ::::VHOST  %s", p->vhost);

	/* servername */
	reqc->name = apr_pstrdup(r->pool, p->vhost);
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: server_name: %s", reqc->name);

	/* document root */
	reqc->docroot = apr_pstrdup(r->pool, p->directory);
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: docroot: %s", reqc->docroot);

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
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: uid: %s", reqc->uid);

	sprintf(buf, "%d", pwd.pw_gid);
	reqc->gid = apr_pstrdup(r->pool, buf);
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: gid: %s", reqc->gid);

	/* GECOS : username */
	reqc->gecos = apr_pstrdup(r->pool, p->user);
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: gecos: %s", reqc->gecos);

	/* suexec GID */
	//reqc->gid = apr_pstrdup(r->pool, "1002");
	//VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: gid: %s", reqc->gid);

	/* associate domain */
	reqc->associateddomain = apr_pstrdup(r->pool, p->vhost);
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: associateddomain: %s", reqc->associateddomain);

	/* MySQL socket */
	reqc->mysql_socket = apr_pstrdup(r->pool, p->mysql_socket);
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: mysql_socket: %s", reqc->mysql_socket);

	/* PHP mode */
	//reqc->php_mode = apr_pstrdup(r->pool, p->php_mode);
	//VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: php_mode: %s", reqc->php_mode);

	/* phpopt_fromdb / options PHP */
	reqc->phpoptions = apr_pstrdup(r->pool, p->php_config);
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: php_config: %s", reqc->phpoptions);

	/* PHP modules */
	//reqc->php_modules = apr_pstrdup(r->pool, p->php_modules);
	//VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: php_modules: %s", reqc->php_modules);

	/* the vhost has been found, set vhost_found to VH_VHOST_INFOS_FOUND */
	reqc->vhost_found = VH_VHOST_INFOS_FOUND;

	apr_pool_userdata_set(reqc, VH_KEY, apr_pool_cleanup_null, r->pool);


    vhr->cache_counter += 1;

	apr_pool_t *c_pool = apr_hash_pool_get(vhr->cache);
	reqc_cache = (mod_vhs_request_t *) apr_pcalloc(c_pool, sizeof(mod_vhs_request_t));
    reqc_cache->name = apr_pstrdup(c_pool, reqc->name);
    reqc_cache->associateddomain = apr_pstrdup(c_pool, reqc->associateddomain);
    reqc_cache->uid = apr_pstrdup(c_pool, reqc->uid);
    reqc_cache->gid = apr_pstrdup(c_pool, reqc->gid);
    reqc_cache->docroot = apr_pstrdup(c_pool, reqc->docroot);
    reqc_cache->gecos = apr_pstrdup(c_pool, reqc->gecos);
	reqc_cache->phpoptions = apr_pstrdup(c_pool, reqc->phpoptions);
    reqc_cache->mysql_socket = apr_pstrdup(c_pool, reqc->mysql_socket);
	reqc_cache->usage = 1;
	reqc_cache->added = (unsigned)time(NULL);

	apr_hash_set(vhr->cache,r->hostname,APR_HASH_KEY_STRING,reqc_cache);
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: cache entry set for %s @=%u",r->hostname,vhr->cache);

	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_consul_lookup: DONE");

	return OK;
}

/*
 * This function will configure MPM-ITK
 */
static int vhs_itk_post_read(request_rec * r)
{
	//    struct passwd  *p;

	uid_t libhome_uid;
	gid_t libhome_gid;
	int vhost_found_by_request = DECLINED;

	vhs_config_rec *vhr = (vhs_config_rec *) ap_get_module_config(r->server->module_config,
								      &vhs_module);
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: BEGIN ***");

	mod_vhs_request_t *reqc;

	reqc = ap_get_module_config(r->request_config, &vhs_module);
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: BEGIN2 ");
	if (reqc)
		return OK;
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: BEGIN3 ");

	reqc = (mod_vhs_request_t *) apr_pcalloc(r->pool, sizeof(mod_vhs_request_t));
	reqc->vhost_found = VH_VHOST_INFOS_NOT_YET_REQUESTED;
	ap_set_module_config(r->request_config, &vhs_module, reqc);

	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: Getting host config for %s", r->hostname);
	vhost_found_by_request = vhs_consul_lookup(r, vhr, r->hostname, reqc);
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: vhost_found_by_request");
	if (vhost_found_by_request == OK) {

		VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: vhost_found_by_request = OK");
		libhome_uid = atoi(reqc->uid);
		libhome_gid = atoi(reqc->gid);
		 VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: uid/gid = %i/%i",libhome_uid,libhome_gid);
	} else {

		VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: vhost_found_by_request = NOT OK");
		if (vhr->lamer_mode) {
			VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_itk_post_read: Lamer friendly mode engaged");
			if ((strncasecmp(r->hostname, "www.", 4) == 0)
			    && (strlen(r->hostname) > 4)) {
				char *lhost;
				lhost = apr_pstrdup(r->pool, r->hostname + 5 - 1);
				VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0,
						r->server, "vhs_itk_post_read: Found a lamer for %s -> %s", r->hostname, lhost);
				vhost_found_by_request = vhs_consul_lookup(r, vhr, lhost, reqc);
				if (vhost_found_by_request == OK) {
					libhome_uid = atoi(reqc->uid);
					libhome_gid = atoi(reqc->gid);
					VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG,
							0, r->server,
							"vhs_itk_post_read: lamer for %s -> %s has itk uid='%d' itk gid='%d'",
							r->hostname, lhost, libhome_uid, libhome_gid);
				} else {
					libhome_uid = vhr->itk_defuid;
					libhome_gid = vhr->itk_defgid;
					VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG,
							0, r->server,
							"vhs_itk_post_read: no lamer found for %s set default itk uid='%d' itk gid='%d'",
							r->hostname, libhome_uid, libhome_gid);
				}
			} else {	/* if((strncasecmp(r->hostname, "www.", 4) == 0) &&(strlen(r->hostname) > 4)) */
				libhome_uid = vhr->itk_defuid;
				libhome_gid = vhr->itk_defgid;
				VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0,
						r->server,
						"vhs_itk_post_read: no lamer found for %s set default itk uid='%d' itk gid='%d'",
						r->hostname, libhome_uid, libhome_gid);
			}
		} else {	/* if(vhr->lamer_mode) */
			libhome_uid = vhr->itk_defuid;
			libhome_gid = vhr->itk_defgid;
		}
	}

	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: has ITK");
	module *mpm_itk_module = ap_find_linked_module("mpm_itk.c");
	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: GOT ITK MODULE");

	if (mpm_itk_module == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "vhs_itk_post_read: mpm_itk.c is not loaded");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	itk_conf *cfg = (itk_conf *) ap_get_module_config(r->per_dir_config, mpm_itk_module);

	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: GOT ITK CONFIG");

	VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r,
			 "vhs_itk_post_read: itk uid='%d' itk gid='%d' itk username='%s' before change", cfg->uid, cfg->gid, cfg->username);
	if ((libhome_uid == -1 || libhome_gid == -1)) {
		VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: ICI  : -1 || -1");
		cfg->uid = vhr->itk_defuid;
		cfg->gid = vhr->itk_defgid;
		cfg->username = vhr->itk_defusername;
	} else {
		VH_AP_LOG_RERROR(APLOG_MARK, APLOG_DEBUG, 0, r, "vhs_itk_post_read: ICI  : setting uid/gid/setting uid/gid/usernamee");
		char *itk_username = NULL;
		/* struct passwd *pw = getpwuid(libhome_uid); */

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

static void vhs_php_ini(char *name, char *value)
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
	zend_alter_ini_entry(name, strlen(name), value, strlen(value), ZEND_INI_SYSTEM, ZEND_INI_STAGE_ACTIVATE);
#endif

}

static void vhs_php_config(request_rec * r, vhs_config_rec * vhr, mod_vhs_request_t * reqc)
{
	//extension_info *ext;
	module *mime_module = ap_find_linked_module("mod_mime.c");

	if (mime_module == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "vhs_php_config: mod_mime.c is not loaded");
		return;
	}
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
	//VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: php_mode ? %s", reqc->php_mode);
	VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: php_config ? %s", reqc->phpoptions);
	//VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: php_modules ? %s", reqc->php_modules);

	/*
	 * Some Basic PHP stuff, thank to Igor Popov module
	 */
	apr_table_set(r->subprocess_env, "PHP_DOCUMENT_ROOT", reqc->docroot);
	vhs_php_ini("doc_root", reqc->docroot);
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
		char *retval;
		char *state;
		char *my_phpconfig;

		my_phpconfig = apr_pstrdup(r->pool, reqc->phpoptions);

		VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: DB => %s", my_phpconfig);

		/* Custom PHP settings */
		if (my_phpconfig == NULL) {
			my_phpconfig = "";
		}

		if ((ap_strchr(my_phpconfig, ';') != NULL)
		    && (ap_strchr(my_phpconfig, '=') != NULL)) {

			retval = apr_strtok(my_phpconfig, ";", &state);
			while (retval != NULL) {
				char *key = NULL;
				char *val = NULL;
				char *strtokstate = NULL;

				key = apr_strtok(retval, "=", &strtokstate);
				val = apr_strtok(NULL, "=", &strtokstate);
				if (val != NULL) {
					VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG,
							0, r->server, "vhs_php_config: Zend PHP Stuff => %s => %s", key, val);
					vhs_php_ini(key, val);
				}
				/*
				   } else {
				   VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: Zend PHP Module => %s", key);
				   char *modname = apr_pcalloc(r->pool,strlen(key)+4);
				   sprintf(modname,"%s.so", key); 
				   zend_alter_ini_entry("extension", strlen("extension")+1, modname, strlen(modname)+4, ZEND_INI_SYSTEM, ZEND_INI_STAGE_ACTIVATE);
				   } */
				retval = apr_strtok(NULL, ";", &state);
			}
		} else {
			VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: no PHP stuff found.");
		}

		/* Settings depending on mysql socket value */
	    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: Setting Mysql socket");
		vhs_php_ini("mysql.default_socket", reqc->mysql_socket);
		vhs_php_ini("mysqli.default_socket", reqc->mysql_socket);
		vhs_php_ini("pdo_mysql.default_socket", reqc->mysql_socket);

		/* sendmail_secure */
	    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: Setting sendmail-secure");
		char *sendmail_path = (char *) apr_pcalloc(r->pool, strlen(SENDMAIL_PATH)
						     + strlen(reqc->associateddomain) + 1);
		sprintf(sendmail_path,"%s%s",SENDMAIL_PATH,reqc->associateddomain);
		vhs_php_ini("sendmail_path", sendmail_path);

		/* Redis sessions */
	    VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_php_config: Setting session handler");
		char *save_path = (char *)
		    apr_pcalloc(r->pool,strlen(REDIS_PATH) + strlen(vhr->tenant) + strlen(reqc->gecos) + 2);
		sprintf(save_path,"%s_%s_%s",REDIS_PATH,vhr->tenant,reqc->gecos);
		vhs_php_ini("session.save_path", save_path);
		vhs_php_ini("session.save_handler", "redis");
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
	VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: useragent_ip:%s", r->useragent_ip);
	VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: method:%s", r->method);
	VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: uri:%s", r->uri);
	VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: path_info:%s", r->path_info);
	VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: log_id:%s", r->log_id);
	//VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: connection>id:%d", r->connection);
    //VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: main:%d", r->main);

	/* If VHS is not enabled, then don't process request */
	if (!vhr->enable) {
		VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: VHS Disabled ");
		return DECLINED;
	}

	/* if not dbmode is set then decline */
	if (vhr->db_mode == 0) {
		VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: VHS Disabled because vhs_dbmode is not specified.");
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
		VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: variable reqc does not already exists.... creating ! pid=%d request_rec=%d @request_config='%d'", getpid(), r, &(r->request_config));
		reqc = (mod_vhs_request_t *) apr_pcalloc(r->pool, sizeof(mod_vhs_request_t));
		reqc->vhost_found = VH_VHOST_INFOS_NOT_YET_REQUESTED;
		ap_set_module_config(r->request_config, &vhs_module, reqc);
	} else {
	   VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: variable reqc already exists ! pid=%d request_rec=%d @request_config='%d'", getpid(), r, &(r->request_config));
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
		if (vhr->db_mode == 3) {
			vhost_found_by_request = vhs_consul_lookup(r, vhr, (char *)host, reqc);
		}
		if (vhost_found_by_request != OK) {
			/*
			 * The vhost has not been found
			 * Trying to get lamer mode or not
			 */
			if (vhr->lamer_mode) {
				VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "vhs_translate_name: Lamer friendly mode engaged");
				if ((strncasecmp(host, "www.", 4) == 0)
				    && (strlen(host) > 4)) {
					char *lhost;
					lhost = apr_pstrdup(r->pool, host + 5 - 1);
					VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG,
							0, r->server, "vhs_translate_name: Found a lamer for %s -> %s", host, lhost);
					if (vhr->db_mode == 3) {
						vhost_found_by_request = vhs_consul_lookup(r, vhr, lhost, reqc);
					}
					if (vhost_found_by_request != OK) {
						if (vhr->log_notfound) {
							ap_log_error(APLOG_MARK,
								     APLOG_NOTICE,
								     0,
								     r->server,
								     "vhs_translate_name: no host found in database for %s(lamer %s)", host, lhost);
						}
						return vhs_redirect_stuff(r, vhr);
					}
				}
			} else {
				if (vhr->log_notfound) {
					ap_log_error(APLOG_MARK, APLOG_NOTICE,
						     0, r->server,
						     "vhs_translate_name: no host found in database for %s(lamer mode not eanbled)", host);
				}
				return vhs_redirect_stuff(r, vhr);
			}
		}
	} else {
		VH_AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server,
				"vhs_translate_name: Request to backend has already be done(vhs_itk_post_read()) !");
		if (reqc->vhost_found == VH_VHOST_INFOS_NOT_FOUND)
			vhost_found_by_request = DECLINED;	/* the request has already be done and vhost was not found */
		else
			vhost_found_by_request = OK;	/* the request has already be done and vhost was found */
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
	AP_INIT_FLAG("vhs_Lamer", set_flag, (void *)0, RSRC_CONF,
		     "Enable Lamer Friendly mode"),
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
	AP_INIT_TAKE1("vhs_tenant", set_field, (void *)0, RSRC_CONF, "Tenant"),
	AP_INIT_TAKE1("vhs_db_host", set_field, (void *)0, RSRC_CONF,
		      "Host for consul vhosts DB "),
	{NULL}
};

static void register_hooks(apr_pool_t * p)
{
	/* Modules that have to be loaded before mod_vhs */
	static const char *const aszPre[] = { "mod_userdir.c", "mod_vhost_alias.c", NULL };
	/* Modules that have to be loaded after mod_vhs */
	static const char *const aszSucc[] = { "mod_php.c", "mod_suphp.c", NULL };

	static const char *const aszSuc_itk[] = { "mpm_itk.c", NULL };
	ap_hook_post_read_request(vhs_itk_post_read, NULL, aszSuc_itk, APR_HOOK_REALLY_FIRST);
	//ap_hook_header_parser(vhs_itk_post_read, NULL, aszSuc_itk, -15);

	ap_hook_post_config(vhs_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_translate_name(vhs_translate_name, aszPre, aszSucc, APR_HOOK_FIRST);
	ap_hook_fixups(fixup_redir, NULL, NULL, APR_HOOK_MIDDLE);

}

AP_DECLARE_DATA module vhs_module = {
	STANDARD20_MODULE_STUFF,
	create_alias_dir_config,	/* create per-directory config structure */
	merge_alias_dir_config,	/* merge per-directory config structures */
	vhs_create_server_config,	/* create per-server config structure */
	vhs_merge_server_config,	/* merge per-server config structures */
	vhs_commands,		/* command apr_table_t */
	register_hooks		/* register hooks */
};
