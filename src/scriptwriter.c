/*---[ scriptwriter.c ]-----------------------------------------------
 * Copyright (C) 2000-2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Creates the firewall script, based on wizard selections.
 *--------------------------------------------------------------------*/

#include <config.h>
#include <gnome.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>

#include "fortified.h"
#include "globals.h"
#include "wizard.h"
#include "util.h"
#include "scriptwriter.h"
#include "netfilter-script.h"
#include "preferences.h"
#include "gui.h"
#include "dhcp-server.h"
#include "policyview.h"

#define PPP_HOOK_FILE "/etc/ppp/ip-up.local"
const gchar* FORTIFIED_HOOK = "sh "FORTIFIED_CONTROL_SCRIPT" start\n";

static const gchar *
test_bool (const gchar *conf_key)
{
	static gchar *on = "\"on\"";
	static gchar *off = "\"off\"";

	if (preferences_get_bool (conf_key))
		return on;
	else
		return off;
}

void
scriptwriter_output_fortified_script ()
{
	gchar *path = FORTIFIED_CONTROL_SCRIPT;
	FILE *f = fopen (path, "w");

        if (f == NULL) {
                perror(path);
                g_printerr("Script not written!");
		return;
	}
	chmod (path, 00700);

	fprintf (f, "#!/bin/bash\n");
	fprintf (f, "#-----------( Fortified Control Script )-----------#\n\n");

	fprintf (f, "# Load Configuration\n"
		    "source "FORTIFIED_CONFIGURATION_SCRIPT" 2>&1\n\n");

	/* If the system binaries can't be found, try to locate them */
	fprintf (f, "# --(Set program paths)--\n\n");
	if (access("/sbin/iptables", R_OK) == 0)
		fprintf (f, "IPT=/sbin/iptables\n");
	else
		fprintf (f, "IPT=`which iptables`\n");
	if (access("/sbin/ifconfig", R_OK) == 0)
		fprintf (f, "IFC=/sbin/ifconfig\n");
	else
		fprintf (f, "IFC=`which ifconfig`\n");
	if (access("/sbin/modprobe", R_OK) == 0)
		fprintf (f, "MPB=/sbin/modprobe\n");
	else
		fprintf (f, "MPB=`which modprobe`\n");
	if (access("/sbin/lsmod", R_OK) == 0)
		fprintf (f, "LSM=/sbin/lsmod\n");
	else
		fprintf (f, "LSM=`which lsmod`\n");
	if (access("/sbin/rmmod", R_OK) == 0)
		fprintf (f, "RMM=/sbin/rmmod\n\n");
	else
		fprintf (f, "RMM=`which rmmod`\n\n");

	fprintf (f, "\n# --(Extract Network Information)--\n\n");

	fprintf (f, "# External network interface data\n"
		    "IP=`/sbin/ifconfig $IF | grep inet | cut -d : -f 2 | cut -d \\  -f 1`\n"
		    "MASK=`/sbin/ifconfig $IF | grep Mas | cut -d : -f 4`\n"
		    "BCAST=`/sbin/ifconfig $IF |grep Bcast: | cut -d : -f 3 | cut -d \\  -f 1`\n"
		    "NET=$IP/$MASK\n\n");

	fprintf (f, "if [ \"$NAT\" = \"on\" ]; then\n"
		    "	# Internal network interface data\n"
		    "	INIP=`/sbin/ifconfig $INIF | grep inet | cut -d : -f 2 | cut -d \\  -f 1`\n"
		    "	INMASK=`/sbin/ifconfig $INIF | grep Mas | cut -d : -f 4`\n"
		    "	INBCAST=`/sbin/ifconfig $INIF |grep Bcast: | cut -d : -f 3 | cut -d \\  -f 1`\n"
		    "	INNET=$INIP/$INMASK\n"
		    "fi\n\n");


	fprintf (f, "if [ \"$MASK\" = \"\" -a \"$1\" != \"stop\" ]; then\n"
		    "	echo \"External network device $IF is not ready. Aborting..\"\n"
		    "	exit %d\n"
		    "fi\n\n", RETURN_EXT_FAILED);

	fprintf (f, "if [ \"$NAT\" = \"on\" ]; then\n"
		    "	if [ \"$INMASK\" = \"\" -a \"$1\" != \"stop\" ]; then\n"
		    "		echo \"Internal network device $INIF is not ready. Aborting..\"\n"
		    "		exit %d\n"
		    "	fi\n"
		    "fi\n\n", RETURN_INT_FAILED);

	fprintf (f, "\n# --(Helper Functions)--\n\n");

	fprintf (f, "# Scrub data parameters before use\n"
		    "scrub_parameters () {\n"
		    "	target=`echo $target | sed 's/ //'g`\n"
		    "	port=`echo $port | sed 's/ //'g |  sed \"s/-/:/\"`\n"
		    "	ext_port=`echo $ext_port | sed 's/ //'g |  sed \"s/-/:/\"`\n"
		    "	int_port_dashed=`echo $int_port | sed 's/ //'g |  sed \"s/:/-/\"`\n"
		    "	int_port=`echo $int_port | sed 's/ //'g |  sed \"s/-/:/\"`\n"
		    "	if [ \"$target\" == \"everyone\" ]; then target=0/0\n"
		    "	else if [ \"$target\" == \"firewall\" ]; then target=$IP\n"
		    "	else if [ \"$target\" == \"lan\" ]; then target=$INNET\n"
		    "	fi fi fi\n"
		    "}\n\n");

	fprintf (f, "\n# --(Control Functions)--\n\n");

	fprintf (f, "# Create Fortified lock file\n"
		    "lock_fortified () {\n"
		    "	if [ -e /var/lock/subsys ]; then\n"
		    "		touch /var/lock/subsys/fortified\n"
		    "	else\n"
		    "		touch /var/lock/fortified\n"
		    "	fi\n"
		    "}\n\n");

	fprintf (f, "# Remove Fortified lock file\n"
		    "unlock_fortified () {\n"
		    "	if [ -e /var/lock/subsys ]; then\n\n"
		    "		rm -f /var/lock/subsys/fortified\n"
		    "	else\n"
		    "		rm -f /var/lock/fortified\n"
		    "	fi\n"
		    "}\n\n");

	fprintf (f, "# Start system DHCP server\n"
		    "start_dhcp_server () {\n"
		    "	if [ \"$DHCP_DYNAMIC_DNS\" = \"on\" ]; then\n"
		    "		NAMESERVER=\n"
		    "		# Load the DNS information into the dhcp configuration\n"
		    "		while read keyword value garbage\n"
		    "			do\n"
		    "			if [ \"$keyword\" = \"nameserver\" ]; then\n"
		    "				if [ \"$NAMESERVER\" = \"\" ]; then\n"
		    "					NAMESERVER=\"$value\"\n"
		    "				else\n"
		    "					NAMESERVER=\"$NAMESERVER, $value\"\n"
		    "				fi\n"
		    "			fi\n"
		    "			done < /etc/resolv.conf\n\n"

		    "		if [ \"$NAMESERVER\" != \"\" ]; then\n"
		    "			if [ -f /etc/dhcpd.conf ]; then\n"
		    "				sed \"s/domain-name-servers.*$/domain-name-servers $NAMESERVER;/\" /etc/dhcpd.conf > /etc/dhcpd.conf.tmp\n"
		    "				mv /etc/dhcpd.conf.tmp /etc/dhcpd.conf\n"
		    "			fi\n"
		    "			if [ -f /etc/dhcp3/dhcpd.conf ]; then\n"
		    "				sed \"s/domain-name-servers.*$/domain-name-servers $NAMESERVER;/\" /etc/dhcp3/dhcpd.conf > /etc/dhcp3/dhcpd.conf.tmp\n"
		    "				mv /etc/dhcp3/dhcpd.conf.tmp /etc/dhcp3/dhcpd.conf\n"
		    "			fi\n"
		    "		else\n"
		    "			echo -e \"Warning: Could not determine new DNS settings for DHCP\\nKeeping old configuration\"\n"
		    "		fi\n"
		    "	fi\n\n"

		    "	if [ -e /etc/init.d/dhcpd ]; then\n"
		    "		/etc/init.d/dhcpd restart > /dev/null\n"
		    "	else\n"
		    "		/usr/sbin/dhcpd 2> /dev/null\n"
		    "	fi\n\n"

		    "	if [ $? -ne 0 ]; then\n"
		    "		echo Failed to start DHCP server\n"
		    "		exit 200\n"
		    "	fi\n"
		    "}\n\n");

	fprintf (f, "# Start the firewall, enforcing traffic policy\n"
		    "start_firewall () {\n"
		    "	lock_fortified\n"
		    "	source "FORTIFIED_FIREWALL_SCRIPT" 2>&1\n"
		    "	retval=$?\n"
		    "	if [ $retval -eq 0 ]; then\n"
		    "		echo \"Firewall started\"\n"
		    "	else\n"
		    "		echo \"Firewall not started\"\n"
		    "		unlock_fortified\n"
		    "	exit $retval\n"
		    "fi\n"
		    "}\n\n");

	fprintf (f, "# Stop the firewall, traffic flows freely\n"
		    "stop_firewall () {\n"
		    "	$IPT -F\n"
		    "	$IPT -X\n"
		    "	$IPT -Z\n"
		    "	$IPT -P INPUT ACCEPT\n"
		    "	$IPT -P FORWARD ACCEPT\n"
		    "	$IPT -P OUTPUT ACCEPT\n"
		    "	$IPT -t mangle -F 2>/dev/null\n"
		    "	$IPT -t mangle -X 2>/dev/null\n"
		    "	$IPT -t mangle -Z 2>/dev/null\n"
		    "	$IPT -t nat -F 2>/dev/null\n"
		    "	$IPT -t nat -X 2>/dev/null\n"
		    "	$IPT -t nat -Z 2>/dev/null\n"
		    "	retval=$?\n"
		    "	if [ $retval -eq 0 ]; then\n"
		    "		unlock_fortified\n"
		    "		echo \"Firewall stopped\"\n"
		    "	fi\n"
		    "	exit $retval\n"
		    "}\n\n");

	fprintf (f, "# Lock the firewall, blocking all traffic\n"
		    "lock_firewall () {\n"
		    "	$IPT -P INPUT DROP\n"
		    "	$IPT -P FORWARD DROP\n"
		    "	$IPT -P OUTPUT DROP\n"
		    "	$IPT -F;\n"
		    "	$IPT -X\n"
		    "	$IPT -Z\n"
		    "	retval=$?\n"
		    "	if [ $? -eq 0 ]; then\n"
		    "		echo \"Firewall locked\"\n"
		    "	fi\n"
		    "	exit $retval\n"
		    "}\n\n");

	fprintf (f, "# Report the status of the firewall\n"
		    "status () {\n"
		    "	if [ -e /var/lock/subsys/fortified -o -e /var/lock/fortified ]; then\n"
		    "		echo \"Fortified is running...\"\n"
		    "	else\n"
		    "		echo \"Fortified is stopped\"\n"
		    "	fi\n"
		    "}\n\n");

	fprintf (f, "case \"$1\" in\n"
		    "start)\n"
		    "	start_firewall\n"
		    " 	if [ \"$NAT\" = \"on\" -a \"$DHCP_SERVER\" = \"on\" ]; then\n"
		    "		start_dhcp_server\n"
		    "	fi\n"
		    ";;\n"
		    "stop)\n"
		    "	stop_firewall\n"
		    ";;\n"
		    "lock)\n"
		    "	lock_firewall\n"
		    ";;\n"
		    "status)\n"
		    "	status\n"
		    ";;\n"
		    "reload-inbound-policy)\n"
		    "	source "FORTIFIED_INBOUND_SETUP" 2>&1\n"
		    ";;\n"
		    "reload-outbound-policy)\n"
		    "	source "FORTIFIED_OUTBOUND_SETUP" 2>&1\n"
		    ";;\n"
		    "*)\n"
		    "	echo \"usage: $0 {start|stop|lock|status}\"\n"
		    "	exit 1\n"
		    "esac\n"
		    "exit 0\n");

	fclose (f);
}

void
scriptwriter_output_configuration ()
{
	gchar *path = FORTIFIED_CONFIGURATION_SCRIPT;
	FILE *f = fopen (path, "w");

        if (f == NULL) {
                perror(path);
                g_printerr("Script not written!");
		return;
	}
	chmod (path, 00440);

	fprintf (f, "#-----------( Fortified Configuration File )-----------#\n\n");

	fprintf (f, "# --(External Interface)--\n"
		    "# Name of external network interface\n"
		    "IF=\"%s\"\n", preferences_get_string (PREFS_FW_EXT_IF));
	fprintf (f, "# Network interface is a PPP link\n"
		    "EXT_PPP=%s\n", test_bool (PREFS_START_ON_DIAL_OUT));

	fprintf (f, "\n");

	fprintf (f, "# --(Internal Interface--)\n"
		    "# Name of internal network interface\n"
		    "INIF=\"%s\"\n", preferences_get_string (PREFS_FW_INT_IF));

	fprintf (f, "\n");

	fprintf (f, "# --(Network Address Translation)--\n"
		    "# Enable NAT\n"
		    "NAT=%s\n", test_bool (PREFS_FW_NAT));
	fprintf (f, "# Enable DHCP server for NAT clients\n"
		    "DHCP_SERVER=%s\n", test_bool (PREFS_FW_DHCP_ENABLE));
	fprintf (f, "# Forward server's DNS settings to clients in DHCP lease\n");
	if (g_ascii_strcasecmp (preferences_get_string (PREFS_FW_DHCP_NAMESERVER), "<dynamic>") == 0)
		fprintf (f, "DHCP_DYNAMIC_DNS=\"on\"\n");
	else
		fprintf (f, "DHCP_DYNAMIC_DNS=\"off\"\n");

	fprintf (f, "\n");

	fprintf (f, "# --(Inbound Traffic)--\n"
		    "# Packet rejection method\n"
		    "#   DROP:   Ignore the packet\n"
		    "#   REJECT: Send back an error packet in response\n");
	if (preferences_get_bool (PREFS_FW_DENY_PACKETS))
		fprintf (f, "STOP_TARGET=\"DROP\"\n");
	else
		fprintf (f, "STOP_TARGET=\"REJECT\"\n");

	fprintf (f, "\n");

	fprintf (f, "# --(Outbound Traffic)--\n"
	            "# Default Outbound Traffic Policy\n"
		    "#   permissive: everything not denied is allowed\n"
		    "#   restrictive everything not allowed is denied\n");
	if (preferences_get_bool (PREFS_FW_RESTRICTIVE_OUTBOUND_MODE))
		fprintf (f, "OUTBOUND_POLICY=\"restrictive\"\n");
	else
		fprintf (f, "OUTBOUND_POLICY=\"permissive\"\n");

	fprintf (f, "\n");

	fprintf (f, "# --(Type of Service)--\n"
		    "# Enable ToS filtering\n"
		    "FILTER_TOS=%s\n", test_bool (PREFS_FW_FILTER_TOS));
	fprintf (f, "# Apply ToS to typical client tasks such as SSH and HTTP\n"
		    "TOS_CLIENT=%s\n", test_bool (PREFS_FW_TOS_CLIENT));
	fprintf (f, "# Apply ToS to typical server tasks such as SSH, HTTP, HTTPS and POP3\n"
		    "TOS_SERVER=%s\n", test_bool (PREFS_FW_TOS_SERVER));
	fprintf (f, "# Apply ToS to Remote X server connections\n"
		    "TOS_X=%s\n", test_bool (PREFS_FW_TOS_X));

	fprintf (f, "# ToS parameters\n"
		    "#   4:  Maximize Reliability\n"
		    "#   8:  Maximize-Throughput\n"
		    "#   16: Minimize-Delay\n");

	if (preferences_get_bool (PREFS_FW_TOS_OPT_TROUGHPUT))
		fprintf (f, "TOSOPT=8\n");
	else if (preferences_get_bool (PREFS_FW_TOS_OPT_RELIABILITY))
		fprintf (f, "TOSOPT=4\n");
	else if (preferences_get_bool (PREFS_FW_TOS_OPT_DELAY))
		fprintf (f, "TOSOPT=16\n");
	else
		fprintf (f, "TOSOPT=\n");

	fprintf (f, "\n");

	fprintf (f, "# --(ICMP Filtering)--\n"
		    "# Enable ICMP filtering\n"
		    "FILTER_ICMP=%s\n", test_bool (PREFS_FW_FILTER_ICMP));
	fprintf (f, "# Allow Echo requests\n"
		    "ICMP_ECHO_REQUEST=%s\n", test_bool (PREFS_FW_ICMP_ECHO_REQUEST));
	fprintf (f, "# Allow Echo replies\n"
		    "ICMP_ECHO_REPLY=%s\n", test_bool (PREFS_FW_ICMP_ECHO_REPLY));
	fprintf (f, "# Allow Traceroute requests\n"
		    "ICMP_TRACEROUTE=%s\n", test_bool (PREFS_FW_ICMP_TRACEROUTE));
	fprintf (f, "# Allow MS Traceroute Requests\n"
		    "ICMP_MSTRACEROUTE=%s\n", test_bool (PREFS_FW_ICMP_MSTRACEROUTE));
	fprintf (f, "# Allow Unreachable Requests\n"
		    "ICMP_UNREACHABLE=%s\n", test_bool (PREFS_FW_ICMP_UNREACHABLE));
	fprintf (f, "# Allow Timestamping Requests\n"
		    "ICMP_TIMESTAMPING=%s\n", test_bool (PREFS_FW_ICMP_TIMESTAMPING));
	fprintf (f, "# Allow Address Masking Requests\n"
		    "ICMP_MASKING=%s\n", test_bool (PREFS_FW_ICMP_MASKING));
	fprintf (f, "# Allow Redirection Requests\n"
		    "ICMP_REDIRECTION=%s\n", test_bool (PREFS_FW_ICMP_REDIRECTION));
	fprintf (f, "# Allow Source Quench Requests\n"
		    "ICMP_SOURCE_QUENCHES=%s\n", test_bool (PREFS_FW_ICMP_SOURCE_QUENCHES));

	fprintf (f, "\n");

	fprintf (f, "# --(Broadcast Traffic)--\n"
		    "# Block external broadcast traffic\n"
		    "BLOCK_EXTERNAL_BROADCAST=%s\n", test_bool (PREFS_FW_BLOCK_EXTERNAL_BROADCAST));
	fprintf (f, "# Block internal broadcast traffic\n"
		    "BLOCK_INTERNAL_BROADCAST=%s\n", test_bool (PREFS_FW_BLOCK_INTERNAL_BROADCAST));

	fprintf (f, "\n");

	fprintf (f, "# --(Traffic Validation)--\n"
		    "# Block non-routable traffic on the public interfaces\n"
		    "BLOCK_NON_ROUTABLES=%s\n", test_bool (PREFS_FW_BLOCK_NON_ROUTABLES));

	fprintf (f, "\n");

	fprintf (f, "# --(Logging)--\n"
		    "# System log level\n"
		    "LOG_LEVEL=info\n");

	fprintf (f, "\n");

	fclose (f);
}

/* [ script_exists ]
 * Return true if script has been generated
 */
gboolean
script_exists (void)
{
	struct stat statd;
	gint retval;

	retval = stat (FORTIFIED_FIREWALL_SCRIPT, &statd);
	// When installing from RPM the script might already exist but the size will be 0
	return (retval != -1 && statd.st_size != 0);
}

static gboolean
file_exists (const gchar *path)
{
	return g_file_test (path, G_FILE_TEST_EXISTS);
}

static gboolean
dhclient_is_running (void)
{
	gboolean exists;
	
	gchar *path = g_strconcat ("/var/run/dhclient-",
				preferences_get_string (PREFS_FW_EXT_IF),
				".pid", NULL);

	exists = file_exists (path);
	g_free (path);

	return exists;
}

static gboolean
dhcpcd_is_running (void)
{
	gboolean exists;
	gchar *path;
	
	if (file_exists ("/etc/slackware-version")) {
		path = g_strconcat ("/etc/dhcpc/dhcpcd-",
			 preferences_get_string (PREFS_FW_EXT_IF),
			 ".pid", NULL);
	} else {
		path = g_strconcat ("/var/run/dhcpcd-",
			 preferences_get_string (PREFS_FW_EXT_IF),
			 ".pid", NULL);
	}

	exists = file_exists (path);
	g_free (path);

	return exists;
}

static void
append_hook_to_script (FILE *f)
{
	gchar buf[512];
	GList *list = NULL;
	GList *link;

	while (fgets (buf, 512, f) != NULL) {
		if (strstr (buf, FORTIFIED_HOOK))
			return;
		else
			list = g_list_append (list, g_strdup (buf));
	}

	rewind (f);
	fprintf (f, FORTIFIED_HOOK);

	link = list;
	while (link != NULL) {
		fprintf (f, link->data);
		g_free (link->data);
		link = link->next;
	}

	g_list_free (list);
}

static void
remove_hook (gchar *path)
{
	FILE *f;
	gchar buf[512];
	GList *list = NULL;
	GList *link = NULL;
	gint pos = 0;

	f = fopen (path, "r");

	if (f == NULL) {
		perror (g_strconcat ("Could not remove fortified hook in ", path, NULL));
		return;
	}

	while (fgets (buf, 512, f) != NULL) {
		list = g_list_append (list, g_strdup (buf));
		if (strstr (buf, FORTIFIED_HOOK))
			link = g_list_nth (list, pos);
			
		pos++;
	}

	fclose (f);

	if (link != NULL) {
		GList *newlist;
		
		newlist = g_list_remove_link (list, link);
		g_free (link->data);

		f = fopen (path, "w");

		if (f == NULL) {
			perror (g_strconcat ("Could not remove fortified hook in ", path, NULL));
			return;
		}

		link = newlist;
		while (link != NULL) {
			fprintf (f, link->data);
			g_free (link->data);
			link = link->next;
		}

		g_list_free (newlist);
		fclose (f);
	}
}

static void
add_hook (gchar *path)
{
	FILE *f;

	printf ("Adding Fortified startup hook to %s\n", path);

	if (file_exists (path)) {
		f = fopen (path, "r+");

		if (f == NULL) {
			perror ("Could not append fortified hook");
			return;
		}

		append_hook_to_script (f);
		fclose (f);

	} else {
		f = fopen (path, "w");

		if (f == NULL) {
			perror ("Could not write fortified hook");
			return;
		}

		fprintf (f, FORTIFIED_HOOK);
		fclose (f);
	}
}

void
scriptwriter_write_ppp_hook (void)
{
	if (!file_exists ("/etc/ppp")) {
		printf ("No ppp detected on system. Not adding starting hook\n");
		return;
	}

	add_hook (PPP_HOOK_FILE);
	chmod (PPP_HOOK_FILE, 0755);
}

void
scriptwriter_remove_ppp_hook (void)
{
	if (!file_exists ("/etc/ppp/ip-up.local")) {
		return;
	}

	remove_hook (PPP_HOOK_FILE);
}

void
scriptwriter_write_dhcp_hook (void)
{
	/* Red Hat 8+, some Mandrake 9 configurations use dhclient */
	if (dhclient_is_running ()) {
		gchar *path = g_strdup ("/etc/dhclient-exit-hooks");

		add_hook (path);
		g_free (path);

	/* Slackware uses DHCPCD, but it's path is different */
	} else if (dhcpcd_is_running () && file_exists ("/etc/slackware-version")) {
		gchar *path = g_strconcat ("/etc/dhcpc/dhcpcd-",
					   preferences_get_string (PREFS_FW_EXT_IF),
					   ".exe", NULL);

		add_hook (path);
		g_free (path);

	/* Most other distributions use DHCPCD */
	} else if (dhcpcd_is_running ()) {
		gchar *path = g_strconcat ("/etc/dhcpcd/dhcpcd-",
					   preferences_get_string (PREFS_FW_EXT_IF),
					   ".exe", NULL);

		add_hook (path);
		g_free (path);
	}
}

void
scriptwriter_remove_dhcp_hook (void)
{
	gchar *path;

	/* Red Hat, Fedora, SuSE, Mandrake dhclient */
	if (file_exists ("/etc/dhclient-exit-hooks")) {
		path = g_strdup ("/etc/dhclient-exit-hooks");

		remove_hook (path);
		g_free (path);
	}

	/* Slackware DHCPD */
	path = g_strconcat ("/etc/dhcpc/dhcpcd-",
			   preferences_get_string (PREFS_FW_EXT_IF),
			   ".exe", NULL);
	if (file_exists (path)) {
		remove_hook (path);
	}
	g_free (path);

	/* Old DHCPCD */
	path = g_strconcat ("/etc/dhcpcd/dhcpcd-",
			   preferences_get_string (PREFS_FW_EXT_IF),
			   ".exe", NULL);
	if (file_exists (path)) {
		remove_hook (path);
	}
	g_free (path);
}

/* [ check_file ]
 * Check that file exists, if not, create
 */
static void
check_file (const gchar *path)
{
	FILE *file = NULL;

	if ((fopen (path, "r") == NULL) && (errno == ENOENT)) {
	        if ((file = fopen (path, "w")) != NULL) {
			chmod (path, 00440);
			fclose (file);
        	}
	}
}

/* [ create_rules_files ]
 * Create the empty modrules and user scripts, unless already exists.
 */
static void
create_rules_files (void)
{
	check_file (FORTIFIED_CONTROL_SCRIPT);
	check_file (FORTIFIED_FIREWALL_SCRIPT);
	check_file (FORTIFIED_CONFIGURATION_SCRIPT);
	check_file (FORTIFIED_SYSCTL_SCRIPT);
	check_file (FORTIFIED_USER_PRE_SCRIPT);
	check_file (FORTIFIED_USER_POST_SCRIPT);
	check_file (FORTIFIED_NON_ROUTABLES_SCRIPT);
	check_file (FORTIFIED_FILTER_HOSTS_SCRIPT);
	check_file (FORTIFIED_FILTER_PORTS_SCRIPT);
	check_file (FORTIFIED_INBOUND_SETUP);
	check_file (FORTIFIED_OUTBOUND_SETUP);

	check_file (POLICY_IN_ALLOW_FROM);
	check_file (POLICY_IN_ALLOW_SERVICE);
	check_file (POLICY_IN_FORWARD);
	check_file (POLICY_OUT_DENY_TO);
	check_file (POLICY_OUT_DENY_FROM);
	check_file (POLICY_OUT_DENY_SERVICE);
	check_file (POLICY_OUT_ALLOW_TO);
	check_file (POLICY_OUT_ALLOW_FROM);
	check_file (POLICY_OUT_ALLOW_SERVICE);
}

/* [ scriptwriter_output_scripts ]
 * Creates all of the fortified scripts
 */
void
scriptwriter_output_scripts (void)
{
	/* Creating the directories for scripts if they are missing */
	mkdir (FORTIFIED_RULES_DIR "/fortified", 00700);
	mkdir (POLICY_IN_DIR, 00700);
	mkdir (POLICY_OUT_DIR, 00700);

	/* Write the firewall configuration */
	scriptwriter_output_configuration ();

	/* Write the firewall control script */
	scriptwriter_output_fortified_script ();

	/* Write main firewall script */
	write_netfilter_script ();

	/* Create all of the rule file stubs */
	create_rules_files ();

	/* Start firewall on ppp interface up */
	if (preferences_get_bool (PREFS_START_ON_DIAL_OUT))
		scriptwriter_write_ppp_hook ();
	else
		scriptwriter_remove_ppp_hook ();

	/* Start firewall on DCHP lease renewal */
	if (preferences_get_bool (PREFS_START_ON_DHCP))
		scriptwriter_write_dhcp_hook ();
	else
		scriptwriter_remove_dhcp_hook ();
}

/* Check that the scripts on the system and the scripts that could be
   generated by this version of the program match */
gboolean
scriptwriter_versions_match (void)
{
	FILE *f;
	gchar buf[512];
	gchar *version;
	gboolean current;

	if (!file_exists (FORTIFIED_FIREWALL_SCRIPT))
		return FALSE;

	f = fopen (FORTIFIED_FIREWALL_SCRIPT, "r");
	fgets (buf, 512, f);
	version = get_text_between (buf, "Fortified ", ",");

	current = g_str_equal (version, VERSION);
	g_free (version);
	fclose (f);

	return current;
}
