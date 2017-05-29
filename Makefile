#
# Copyright (c) 2005 Xavier Beaudouin <kiwi@oav.net>
#
# $Id: Makefile,v 1.13 2009-06-25 14:32:52 kiwi Exp $
#

##
## Have a look in this file the compilation / configuration options.
##
## If you are using Debian/GNU Linux, please double check the
## specific updates for your OS.
##

# In general you can use apxs, but on debian you should use apxs2
APXS = apxs2

NAME = mod_vhs
SRCS = mod_vhs.c mod_vhs_alias.c vhosts_db_redis.c 
OBJS = mod_vhs.o mod_vhs_alias.o vhosts_db_redis.o
APACHE_MODULE = $(NAME).so

RM = rm -f
LN = ln -sf
CP = cp -f
INDENT = /usr/bin/indent

# For debian users, you'll have to uncomment these of you will have
# big errors under complilation. Don't ask me why, but debian apache2-itk
# is redefining strangely some headers.... :/

#CFLAGS= -DDEBIAN -I/usr/include/apr-0
CFLAGS= 
GCCGLAGS= -Wall -fdiagnostics-color=auto  -Wstrict-prototypes -Wpointer-arith -Wmissing-prototypes
APXSFLAGS= -Wc,-fdiagnostics-color=auto -Wc,-Wall  -Wc,-Wstrict-prototypes -Wc,-Wpointer-arith -Wc,-Wmissing-prototypes  -Wc,-fstack-protector-strong -Wc,-Wformat -Wc,-Werror=format-security
PHPVER=$(shell php -v 2>&1 | head -1 | cut -c 1-5)
ifeq ($(PHPVER),PHP 5)
  PHP_INC=/usr/include/php5/
else
  PHP_INC=/usr/include/php/20151012/
  CFLAGS+= -DVH_PHP7
endif

CFLAGS+= -I/usr/local/include -I$(PHP_INC) -I$(PHP_INC)/main/ -I$(PHP_INC)/TSRM -I$(PHP_INC)/Zend

APXSCFLAGS=$(CFLAGS)


#CFLAGS+= -DVH_DEBUG 
CFLAGS+= -DHAVE_MOD_PHP_SUPPORT 
CFLAGS+= -DHAVE_MPM_ITK_SUPPORT
CFLAGS+= -DHAVE_MOD_REDIS_SUPPORT
#CFLAGS+= -DHAVE_MOD_FLATFILE_SUPPORT
#CFLAGS+= -DHAVE_MOD_DBD_SUPPORT
#CFLAGS+= -DHAVE_LDAP_SUPPORT
# If you have an old PHP (eg < 5.3.x), then you can enable safe_mode tricks
# on your OWN risk
#CFLAGS+= -DOLD_PHP


# Flags for compilation (Full Debug)
# CFLAGS+= -DVH_DEBUG  -g

# Flags for compilation with PHP
#CFLAGS+= -I/usr/local/include/php -I/usr/local/include/php/main -I/usr/local/include/php/TSRM -I/usr/local/include/php/Zend -DHAVE_MOD_PHP_SUPPORT -Wc,-Wall

LDFLAGS = -lhiredis -ljson-c

################################################################
### End of user configuration directives
################################################################

default: all

all: install

test_redis: test_redis.c vhosts_db_redis.c
	gcc -c $(CFLAGS) $(GCCGLAGS) -ggdb -I/usr/include/apr-1.0/ -I/usr/include/apache2 test_redis.c
	gcc -c $(CFLAGS) $(GCCGLAGS) -ggdb -I/usr/include/apr-1.0/ -I/usr/include/apache2 vhosts_db_redis.c
	gcc -o test_redis $(GCCGLAGS) -ggdb -lapr-1 -lhiredis -ljson-c test_redis.o vhosts_db_redis.o

test_file: test_file.c vhosts_db_file.c
	gcc -c $(CFLAGS) -ggdb test_file.c
	gcc -c $(CFLAGS) -ggdb vhosts_db_file.c
	gcc -o test_file -ggdb test_file.o vhosts_db_file.o
	

install: $(SRCS)
	echo $(PHPVER)
#	$(APXS) -i -a -c $(APXSFLAGS) $(LDFLAGS) $(CFLAGS) $(SRCS)
	$(APXS)  -c  $(APXSFLAGS) $(APXSCFLAGS) $(SRCS)

clean:
	$(RM) $(OBJS) $(APACHE_MODULE) mod_vhs.slo mod_vhs.lo mod_vhs.la mod_vhs_alias.la mod_vhs_alias.lo mod_vhs_alias.slo vhosts_db_*.lo vhosts_db_*.slo test_file.o test_redis.o test_file test_redis
	$(RM) -r .libs

indent:
	$(INDENT) $(SRCS)
	$(RM) $(SRCS).BAK
