#
# Regular cron jobs for the libapache2-mod-vhs package
#
0 4	* * *	root	[ -x /usr/bin/libapache2-mod-vhs_maintenance ] && /usr/bin/libapache2-mod-vhs_maintenance
