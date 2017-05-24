#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "apr.h"
#include "apr_signal.h"
#include "apr_strings.h"
#include "apr_network_io.h"
#include "apr_file_io.h"
#include "apr_time.h"
#include "apr_getopt.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "apr_portable.h"
#include "apr_poll.h"
#include <hiredis/hiredis.h>
#include <json-c/json.h>

#include "vhosts_db_redis.h"

#define BUFSIZE (8192)
#define DEF_SOCK_TIMEOUT    (APR_USEC_PER_SEC * 30)
#define BUFFER_SIZE (256*1024) // 256kB
#define REDIS_SOCKET    "/var/run/redis/redis-webconf.sock"

char *redis_lookup_last = NULL;
char *redis_lookup_res = NULL;
redisContext *redis_context = NULL;

struct vhost_config *new_vhost_config (apr_pool_t * p) {
    struct vhost_config *conf = apr_pcalloc (p,sizeof (struct vhost_config));
    return conf;
}

void free_vhost_config(struct vhost_config *conf,apr_pool_t * p) {

    /*
    free(conf->uri);
    free(conf->vhost);
    free(conf->user);
    free(conf->directory);
    free(conf->mysql_socket);
    free(conf->php_mode);
    free(conf->php_config);
    free(conf->php_modules);
    */
}


int vhost_parseconfline(const char *line,struct vhost_config *conf,apr_pool_t * p) {
    char * tok;
    char *retval;
	char *key = NULL;
	char *val = NULL;
	char *strtokstate = NULL;
	char *php_conf;
    int i = 0;
    char * p2;


    tok = apr_pcalloc(p,sizeof(char) * strlen(line)+1);

    strcpy(tok, line);

    conf->added = time(NULL);
    conf->cache = apr_pstrdup(p,line);



    while(1) {
        p2 = strchr(tok, '|');
        if(p2 != NULL)
            *p2 = '\0';

        switch (i) {

            case 0: // URI 
                conf->uri = (char *) apr_pcalloc(p,strlen(tok)+1);
                strncpy(conf->uri,tok,strlen(tok));
                break;

            case 1: // VHOST 
                conf->vhost = (char *) apr_pcalloc(p,strlen(tok)+1);
                strncpy(conf->vhost,tok,strlen(tok));
                break;

            case 2: // USER 
                conf->user = (char *) apr_pcalloc(p,strlen(tok)+1);
                strncpy(conf->user,tok,strlen(tok));
                break;

            case 3: // DIRECTORY 
                conf->directory = (char *) apr_pcalloc(p,strlen(tok)+1);
                strncpy(conf->directory,tok,strlen(tok));
                break;

            case 4: // MYSQL_SOCKET 
                conf->mysql_socket = (char *) apr_pcalloc(p,strlen(tok)+1);
                strncpy(conf->mysql_socket,tok,strlen(tok));
                break;

            case 5: // PHP_CONFIG 
				php_conf = (char *) apr_pcalloc(p, strlen(tok)+1);
				strncpy(php_conf,tok,strlen(tok)+1);

                conf->php_config = apr_hash_make(p);
                if ((strchr(php_conf, ';') != NULL) && (strchr(php_conf, '=') != NULL)) { 
                    retval = apr_strtok(php_conf, ";", &php_conf);
                    while (retval != NULL) {
                        key = apr_strtok(retval, "=", &strtokstate);
                        val = apr_strtok(NULL, "=", &strtokstate);
                        if (val != NULL) { 
							apr_hash_set(conf->php_config, key, APR_HASH_KEY_STRING, val);
                        }
                        retval = apr_strtok(NULL, ";", &php_conf);
                    }
                }
                //conf->php_config = (char *) apr_pcalloc(p,2048);
                //strncpy(conf->php_config, tok, strlen(tok));
                break;
        }

        tok = p2 + 1;
        if(p2 == NULL)
            break;
        i++;
    }
    //fprintf(stderr," ======================================================= \n");
    //fflush(stderr);
    return 0;
}


int vhost_parseconfig(const char *json_data,struct vhost_config *conf,apr_pool_t * p) {
    json_object *jpwd;
    json_object *jobj;
    int no_public_html;

    jobj = apr_pcalloc(p,BUFFER_SIZE);
    jpwd = json_tokener_parse(json_data);

    json_object_object_get_ex(jpwd, "host",&jobj);
    conf->uri = (char*) apr_pcalloc(p,strlen(json_object_get_string(jobj))+1);
    strcpy(conf->uri,json_object_get_string(jobj));

    json_object_object_get_ex(jpwd, "vhost",&jobj);
    conf->vhost = (char*) apr_pcalloc(p,strlen(json_object_get_string(jobj))+1);
    strcpy(conf->vhost,json_object_get_string(jobj));

    json_object_object_get_ex(jpwd, "user",&jobj);
    conf->user = (char*) apr_pcalloc(p,strlen(json_object_get_string(jobj))+1);
    strcpy(conf->user,json_object_get_string(jobj));

    no_public_html = 0;
    json_object_object_get_ex(jpwd, "no_public_html",&jobj);
    no_public_html = json_object_get_int(jobj);

    json_object_object_get_ex(jpwd, "directory",&jobj);
    if (strcmp(conf->user,"www-data") == 0) {
        conf->directory = (char*) apr_pcalloc(p,strlen(json_object_get_string(jobj))+1);
        sprintf(conf->directory,"%s",json_object_get_string(jobj));
    } else if (no_public_html == 1) {
        conf->directory = (char*) apr_pcalloc(p,strlen("/home/") + strlen(conf->user) + strlen(json_object_get_string(jobj))+2);
        sprintf(conf->directory,"/home/%s/%s",conf->user,json_object_get_string(jobj));
    } else {
        conf->directory = (char*) apr_pcalloc(p,strlen("/home/") + strlen(conf->user) + strlen("/public_html/") + strlen(json_object_get_string(jobj))+2);
        sprintf(conf->directory,"/home/%s/public_html/%s",conf->user,json_object_get_string(jobj));
    }

    json_object *jback;
    json_object_object_get_ex(jpwd, "backend",&jback);
    //jback = json_object_get_object(jobj);

    json_object_object_get_ex(jback, "mysql_socket",&jobj);
    conf->mysql_socket = (char*) apr_pcalloc(p,strlen(json_object_get_string(jobj))+1);
    strcpy(conf->mysql_socket,json_object_get_string(jobj)); 

    json_object_object_get_ex(jback, "php_config",&jobj);
    char * php_config_str = apr_pcalloc(p,2000);
    conf->php_config = apr_hash_make(p);
    json_object_object_foreach(jobj, key, val) {
        char * hkey = apr_pcalloc(p, strlen(key)+1);
        char * hval = apr_pcalloc(p, strlen(json_object_get_string(val))+1);
        strcpy(hkey, key);
        strcpy(hval, json_object_get_string(val));
        apr_hash_set(conf->php_config, hkey, APR_HASH_KEY_STRING, hval);
        strcat(php_config_str, hkey);
        strcat(php_config_str, "=");
        strcat(php_config_str, hval);
        strcat(php_config_str, ";");
    }
    json_object_put(jpwd);
    conf->cache = (char*) apr_psprintf(p,"%s|%s|%s|%s|%s|%s",
                                             conf->uri,
                                             conf->vhost,
                                             conf->user,
                                             conf->directory,
                                             conf->mysql_socket,
                                             php_config_str);
    conf->added = 0;
    return 0;
}


int vhost_getconfig(const char *tenant, const char *host, struct vhost_config *conf,apr_pool_t * p) {
    char *json_data;

    redisReply *reply;
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds

    redis_context = redisConnectUnixWithTimeout(REDIS_SOCKET, timeout);
    if (redis_context == NULL || redis_context->err) {
        redisFree(redis_context);
        return 1;
    }

    reply = redisCommand(redis_context,"GET %s/%s", "WEBHOST/v1", host);

    if (reply->type == REDIS_REPLY_STRING) {
        json_data = apr_pcalloc(p, reply->len+1);
        strncpy(json_data,reply->str,reply->len+1);
    } else {
        freeReplyObject(reply);
        redisFree(redis_context);
        return 2;
    }

    freeReplyObject(reply);
    redisFree(redis_context);

    return vhost_parseconfig(json_data,conf,p);
}
