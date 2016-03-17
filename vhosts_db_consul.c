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
#include <curl/curl.h>
#include <json-c/json.h>

#include "base64.h"


#include "vhosts_db_consul.h"

#define BUFSIZE (8192)
#define DEF_SOCK_TIMEOUT	(APR_USEC_PER_SEC * 30)
#define CONSUL_URL_BASE "http://localhost:8500/v1/kv/"
#define BUFFER_SIZE (256*1024) // 256kB

const char* delim = "|";


struct curl_write_result {
    char *data;
    int pos;
};

static size_t curl_write(char *ptr, size_t size, size_t nmemb, void *userdata) {
        struct curl_write_result *result = (struct curl_write_result *)userdata;

            if (result->pos + size * nmemb >= BUFFER_SIZE - 1) {
                        fprintf(stderr, "buffer fail\n");
                                return 1;
                                    }

                memcpy(result->data + result->pos, ptr, size * nmemb);
                    result->pos += size * nmemb;

                        return size * nmemb;
}


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


int vhost_getconfig(const char *tenant, const char *host, struct vhost_config *conf,apr_pool_t * p) {
	char *consul_url;
	CURL *curl_handle = curl_easy_init();
	char *curl_data;
    char *json_data;

    fprintf(stderr," ------------------- GETTING HOST CONFIG %s ---------------\n",host);
    // http://localhost:8500/v1/kv/mutupw/host/krow.org    
	
    /*char lastc = *(host + strlen(host) - 1);
    if (lastc == '.' || lastc == ',' || lastc == '\n') {
        host[strlen(host)-1] = '\0';
    }*/

	curl_data = apr_pcalloc(p,BUFFER_SIZE);
    consul_url = apr_pcalloc(p,200);
	sprintf(consul_url, "%s%s/host/%s",CONSUL_URL_BASE,tenant,host);
    struct curl_write_result wr = {
        .data = curl_data,
        .pos = 0
    };

    ////curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_write);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &wr);
    curl_easy_setopt(curl_handle, CURLOPT_URL, consul_url);
    if (tenant == NULL || curl_easy_perform(curl_handle)) {
         return 1;
    }
    curl_data[wr.pos] = '\0';
    if (strlen(curl_data) == 0) {
         return 1;
    }
    //printf(">> %s\n", curl_data);

    json_object *jpwd = json_tokener_parse(curl_data);
    json_object *jservice;
    json_object *jobj;
	json_object *jback;
    const char *valueb64;
    valueb64 = apr_pcalloc(p,10000);
	json_data = apr_pcalloc(p,1);
    jobj = apr_pcalloc(p,BUFFER_SIZE); // this is dumb
    int i;
	for (i=0; i < json_object_array_length(jpwd) ; i++) {
		jservice = json_object_array_get_idx(jpwd, i);

		// We care about the address
		if (json_object_object_get_ex(jservice, "Value", &jobj)) {
			valueb64 = json_object_get_string(jobj);
            //printf("B64: %s\n",valueb64);
		} else {
			return 1;
		}
        int alloc_len = Base64decode_len(valueb64);
        json_data = apr_pcalloc(p,alloc_len);
        Base64decode(json_data, valueb64);
    } 
    printf(">> %s\n", json_data);
    curl_easy_cleanup(curl_handle);

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

    json_object_object_get_ex(jpwd, "directory",&jobj);

	conf->directory = (char*) apr_pcalloc(p,strlen("/home/") + strlen(conf->user) + strlen(json_object_get_string(jobj))+2);
	sprintf(conf->directory,"/home/%s/%s",conf->user,json_object_get_string(jobj));
    //strcpy(conf->directory,json_object_get_string(jobj));

	json_object_object_get_ex(jpwd, "backend_config",&jback);
	//jback = json_object_get_object(jobj);

	json_object_object_get_ex(jback, "mysql_socket",&jobj);
	conf->mysql_socket = (char*) apr_pcalloc(p,strlen(json_object_get_string(jobj))+1);
    strcpy(conf->mysql_socket,json_object_get_string(jobj)); 

	json_object_object_get_ex(jback, "php",&jobj);
	conf->php_config = (char*) apr_pcalloc(p,strlen(json_object_get_string(jobj))+1);
    strcpy(conf->php_config,json_object_get_string(jobj)); 

	conf->added = 0;

    return 0;
}
