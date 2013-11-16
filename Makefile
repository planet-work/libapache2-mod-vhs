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
APXS = apxs

NAME = mod_vhs
SRCS = mod_vhs.c mod_vhs_alias.c vhosts_db_file.c
OBJS = mod_vhs.o mod_vhs_alias.o vhosts_db_file.o
APACHE_MODULE = $(NAME).so

RM = rm -f
LN = ln -sf
CP = cp -f
INDENT = /usr/bin/indent

# For debian users, you'll have to uncomment these of you will have
# big errors under complilation. Don't ask me why, but debian apache2-itk
# is redefining strangely some headers.... :/

#CFLAGS= -DDEBIAN -I/usr/include/apr-0
#CFLAGS+= -I/usr/local/include -I/usr/include/php5 -I/usr/include/php5/main/ -I/usr/include/php5/TSRM -I/usr/include/php5/Zend
CFLAGS+= -I/usr/local/include -I/usr/include/php -I/usr/include/php/main/ -I/usr/include/php/TSRM -I/usr/include/php/Zend

#CFLAGS+= -DVH_DEBUG 
CFLAGS+= -DHAVE_MOD_PHP_SUPPORT 
CFLAGS+= -DHAVE_MPM_ITK_SUPPORT
CFLAGS+= -DHAVE_MOD_FLATFILE_SUPPORT
#CFLAGS+= -DHAVE_MOD_DBD_SUPPORT
#CFLAGS+= -DHAVE_LDAP_SUPPORT
# If you have an old PHP (eg < 5.3.x), then you can enable safe_mode tricks
# on your OWN risk
CFLAGS+= -DOLD_PHP


# Flags for compilation (Full Debug)
#CFLAGS+= -DVH_DEBUG -Wc,-Wall

# Flags for compilation with PHP
#CFLAGS+= -I/usr/local/include/php -I/usr/local/include/php/main -I/usr/local/include/php/TSRM -I/usr/local/include/php/Zend -DHAVE_MOD_PHP_SUPPORT -Wc,-Wall

#LDFLAGS = 

################################################################
### End of user configuration directives
################################################################

default: all

all: install

install: $(SRCS)
#	$(APXS) -i -a -c $(LDFLAGS) $(CFLAGS) $(SRCS)
	$(APXS) -c $(LDFLAGS) $(CFLAGS) $(SRCS)

clean:
	$(RM) $(OBJS) $(APACHE_MODULE) mod_vhs.slo mod_vhs.lo mod_vhs.la mod_vhs_alias.la mod_vhs_alias.lo mod_vhs_alias.slo vhosts_db_file.lo vhosts_db_file.slo
	$(RM) -r .libs

indent:
	$(INDENT) $(SRCS)
	$(RM) $(SRCS).BAK
