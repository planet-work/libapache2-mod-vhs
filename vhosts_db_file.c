#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "vhosts_db_file.h"


#define SENDMAIL_PATH   "/etc/apache2/conf/sendmail-secure"
#define OPEN_BASEDIR    "/usr/share/php:/etc/php5/:/tmp:/var/lib/php/"


const char* delim = "|";


struct db_handler *get_dbh(char * db_path) {
    static struct db_handler db = {NULL,NULL};
    db.dbh = db_path;
    db.fd = NULL;
    db.fd_updated = NULL;
    db.counter = 0;
    db.fd_modified = 0;
    db.fd_updated_modified = 0;
    return &db; 
}


int clean_dbh(struct db_handler* db) {
    fclose(db->fd);
    fclose(db->fd_updated);
    return 0;
}


void free_vhost_config(struct vhost_config *conf) {
    free(conf->uri);
    free(conf->vhost);
    free(conf->user);
    free(conf->directory);
    free(conf->mysql_socket);
    free(conf->php_mode);
    free(conf->php_config);
    free(conf->php_modules);
}


struct vhost_config *parse_line(char* line) {
    static struct vhost_config conf = {NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0};
    char * tok;
    int i = 0;
    char * p2;
    char * sendmail_path;
    char * obasedir;
    char * mysql_socket;
    int has_phpconfig = 0;
    int has_phpmodules = 0;
    
    if (*(line+strlen(line)-1) == '\n') {
         *(line+strlen(line)-1) = '\0';
    }

    tok = malloc(sizeof(char) * strlen(line)+1);
   
    strcpy(tok, line);
   
    conf.added = time(NULL);

    while(1) {
        p2 = strchr(tok, '|');
        if(p2 != NULL)
            *p2 = '\0';

        switch (i) {

            case 0: // URI 
                conf.uri = (char *) malloc(strlen(tok)+1);
                memset(conf.uri,0,strlen(tok)+1);
                strncpy(conf.uri,tok,strlen(tok));
                break;

            case 1: // VHOST 
                conf.vhost = (char *) malloc(strlen(tok)+1);
                memset(conf.vhost,0,strlen(tok)+1);
                strncpy(conf.vhost,tok,strlen(tok));
                break;

            case 2: // USER 
                conf.user = (char *) malloc(strlen(tok)+1);
                memset(conf.user,0,strlen(tok)+1);
                strncpy(conf.user,tok,strlen(tok));
                break;

            case 3: // DIRECTORY 
                conf.directory = (char *) malloc(strlen(tok)+1);
                memset(conf.directory,0,strlen(tok)+1);
                strncpy(conf.directory,tok,strlen(tok));
                break;

            case 4: // MYSQL_SOCKET 
                conf.mysql_socket = (char *) malloc(strlen(tok)+1);
                memset(conf.mysql_socket,0,strlen(tok)+1);
                strncpy(conf.mysql_socket,tok,strlen(tok));
                break;

            case 5: // PHP_MODE 
                conf.php_mode = (char *) malloc(strlen(tok)+1);
                memset(conf.php_mode,0,strlen(tok)+1);
                strncpy(conf.php_mode,tok,strlen(tok));
                break;

            case 6: // PHP_CONFIG 
                has_phpconfig = 1;
                //conf.php_config = (char *) malloc(strlen(tok)+1);
                conf.php_config = (char *) malloc(2048);
                memset(conf.php_config, 0, strlen(tok)+1);
                strncpy(conf.php_config, tok, strlen(tok));
                break;

            case 7: // PHP_MODULES
                has_phpmodules = 1;
                conf.php_modules = (char *) malloc(strlen(tok)+1);
                memset(conf.php_modules, 0, strlen(tok)+1);
                strncpy(conf.php_modules, tok, strlen(tok));
                break;
        }

        tok = p2 + 1;
        if(p2 == NULL)
            break;
        i++;
    }

    return &conf;
    
}


int uri_match (char *line, char*host) {
    if (line != NULL && strlen(line) < 10)
        return 0;
    
    if(line[0] != '*') {
        char *tmp = (char*) malloc(1024);
        strncpy(tmp,line,1024);
        if (strncmp(strtok(tmp,delim),host,1024) == 0) {
            free(tmp);
            return 1;
        }
        free(tmp);
    } else {
        char *tmp = (char*) malloc(1024);
        strncpy(tmp,line,1024);
        char * subdomain = strtok(tmp,delim) + 1;  
        if (strlen(host) > strlen(subdomain)) {
            int j = 1;
            int found = 1;
            for (j; j <= strlen(subdomain) ; j++) {
                 if (host[strlen(host)-j] != subdomain[strlen(subdomain)-j]) {
                    found = 0;
                    break;
                 }
                 if (j == strlen(subdomain) && found) {
                    free(tmp);
                    return 1;
                 }
             }
        }
        free(tmp);
    }
    return 0;
}


struct vhost_config *vhost_getconfig(struct db_handler *dbh, char *host) {
    char * line = (char *)malloc(1024*sizeof(char));
    static FILE * fd_updated = NULL;
    static FILE * fd = NULL;
    struct vhost_config *conf = NULL;
    struct stat sts;
    
     //fprintf(stderr," ------------------- GETTING HOST CONFIG %s ---------------\n",host);
    
    char lastc = *(host + strlen(host) - 1);
    if (lastc == '.' || lastc == ',' || lastc == '\n') {
        host[strlen(host)-1] = '\0';
    }
    
    memset(line,0,1024);
    
    //if (dbh->counter > 100) {
    //    fclose(dbh->fd);
    //    fclose(dbh->fd_updated);
    //}
    
    /*
     * 
     *  UPDATES FILE (small)
     * 
     */

    char* dbh_updated = (char*) malloc(400);
    memset(dbh_updated,0,400);
    strcpy(dbh_updated,dbh->dbh);
    strcat(dbh_updated,".updated");
     
    if (stat (dbh_updated, &sts) == 0) {
         if (dbh->fd_updated_modified > 0 && dbh->fd_updated_modified != sts.st_mtime) {
             fclose(dbh->fd_updated);
             dbh->fd_updated = NULL;
             dbh->fd_updated_modified = sts.st_mtime;
	     //fprintf(stderr,"%i ----- Reopenning FILES\n",getpid());
	     //fflush(stderr);
         }
    }
     
     
    if (dbh->fd_updated == NULL) {
        //fprintf(stderr,"%i -------------------[INFO] Opening NEW fd_updated---------------\n",getpid());
	//fflush(stderr);
        if((fd_updated = fopen(dbh_updated, "r")) == NULL) {
            fprintf(stderr,"ERROR: cannot read updated vhosts file \"%s\"\n",dbh_updated); 
        }
        dbh->fd_updated_modified = sts.st_mtime;
        dbh->fd_updated = fd_updated;
    } else {
       //fprintf(stderr,"%i [INFO] Reusing OLD fd_updated\n",getpid());
       //fflush(stderr);
       fd_updated = dbh->fd_updated;
       fseek ( fd_updated , 0 , SEEK_SET );
    }
    free(dbh_updated); 
    
    while(fd_updated) {
        if(feof(fd_updated))
            break;
   
        if(fgets(line, 1023, fd_updated) == 0)
            break;
            
        if (uri_match(line,host) == 1) { 
            if (conf) {
                free_vhost_config(conf);
            }
            conf = parse_line(line);
        } 
    }
    
    if (conf) {
        free(line);
        return conf;
    }    
   
    
    /*
     * 
     * MAIN DB FILE (big) 
     * 
     */

    if (stat (dbh->dbh, &sts) == 0) {
         if (dbh->fd_modified > 0 && dbh->fd_modified != sts.st_mtime) {
             fclose(dbh->fd);
             dbh->fd = NULL;
             dbh->fd_modified = sts.st_mtime;
         }
    }
    
    
    if (dbh->fd == NULL) {
        //fprintf(stderr,"********************** [INFO] Opening NEW fd ****************************\n");
        if((fd = fopen(dbh->dbh, "r")) == NULL) {
            fprintf(stderr,"ERROR: cannot read vhosts file \"%s\"\n",dbh->dbh);
            return NULL;
        } 
        dbh->fd_modified = sts.st_mtime;
        dbh->fd = fd;
    } else {
       //fprintf(stderr,">>>>>> [INFO] Reusing OLD fd\n");
       fd = dbh->fd;
       fseek ( fd , 0 , SEEK_SET );
    }
    dbh->counter += 1;
    
    while(1)
    {
    	if(feof(fd)) {
            free(line);
    		line = NULL;
    		break;
    	}
        
        fgets(line, 1023, fd);
        
        if (uri_match(line,host) == 1) {
            conf = parse_line(line);
        } 
        
        if (conf) {
            break;
        }
    }
    
    
    free(line);
    return conf;
}
