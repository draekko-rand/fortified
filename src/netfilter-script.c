/*---[ netfilter-script.c ]-------------------------------------------
 * Copyright (C) 2000-2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Functions to write the netfilter shell scripts
 *--------------------------------------------------------------------*/

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>   
#include <errno.h>
#include <time.h>

#include "wizard.h"
#include "netfilter-script.h"
#include "util.h"
#include "preferences.h"
#include "policyview.h"
#include "scriptwriter.h"

static void
write_outbound_script ()
{
	gchar *scriptpath = POLICY_OUT_DIR "/setup";
	FILE *script = fopen (scriptpath, "w");

        if (script == NULL) {
                perror(scriptpath);
                g_printerr("Script not written!");
		return;
	}
	chmod (scriptpath, 00440);

	fprintf (script, "# Initialize\n");
	fprintf (script, "$IPT -N OUTBOUND 2> /dev/null\n"
	                 "$IPT -F OUTBOUND\n\n");

	fprintf (script, "# Allow ICMP packets out\n");
	fprintf (script, "$IPT -A OUTBOUND -p icmp -j ACCEPT\n\n");

	fprintf (script, "# Temoporarily set the field separator for CSV format\n"
			 "OLDIFS=$IFS\n"
			 "IFS=','\n\n");

	fprintf (script, "# Allow response traffic\n"
			 "$IPT -A OUTBOUND -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
			 "$IPT -A OUTBOUND -p udp -m state --state ESTABLISHED,RELATED -j ACCEPT\n\n");

	fprintf (script, "if [ \"$OUTBOUND_POLICY\" == \"permissive\" ]; then\n");
	fprintf (script, "	# Hosts to which traffic is denied\n"
	                 "	while read host garbage\n"
	                 "		do\n"
	                 "			$IPT -A OUTBOUND -d $host -j LSO\n"
	                 "		done < "POLICY_OUT_DENY_TO"\n\n");

	fprintf (script, "	# Hosts from which traffic is denied\n"
	                 "	while read host garbage\n"
	                 "		do\n"
	                 "			$IPT -A OUTBOUND -s $host -j LSO\n"
	                 "		done < "POLICY_OUT_DENY_FROM"\n\n");

	fprintf (script, "	# Services denied\n"
	                 "	while read service ports target garbage\n"
	                 "		do\n"
			 "			IFS=' '\n"
			 "			for port in `echo $ports`; do\n"
			 "				scrub_parameters\n"
	                 "				$IPT -A OUTBOUND -p tcp -s $target --dport $port -j LSO\n"
	                 "				$IPT -A OUTBOUND -p udp -s $target --dport $port -j LSO\n"
			 "			done\n"
			 "			IFS=','\n"
	                 "		done < "POLICY_OUT_DENY_SERVICE"\n\n");

	fprintf (script, "	$IPT -A OUTBOUND -j ACCEPT # Default permissive policy \n");
	fprintf (script, "else\n");
	fprintf (script, "	# Hosts to which traffic is allowed\n"
	                 "	while read host garbage\n"
	                 "		do\n"
	                 "			$IPT -A OUTBOUND -d $host -j ACCEPT\n"
	                 "		done < "POLICY_OUT_ALLOW_TO"\n\n");

	fprintf (script, "	# Hosts from which traffic is allowed\n"
	                 "	while read host garbage\n"
	                 "		do\n"
	                 "			$IPT -A OUTBOUND -s $host -j ACCEPT\n"
	                 "		done < "POLICY_OUT_ALLOW_FROM"\n\n");

	fprintf (script, "	# Services allowed\n"
	                 "	while read service ports target garbage\n"
	                 "		do\n"
			 "			IFS=' '\n"
			 "			for port in `echo $ports`; do\n"
			 "				scrub_parameters\n"
	                 "				$IPT -A OUTBOUND -p tcp -s $target --dport $port -j ACCEPT\n"
	                 "				$IPT -A OUTBOUND -p udp -s $target --dport $port -j ACCEPT\n"
			 "			done\n"
			 "			IFS=','\n"
	                 "		done < "POLICY_OUT_ALLOW_SERVICE"\n\n");

	fprintf (script, "	$IPT -A OUTBOUND -j LSO # Default restrictive policy\n");
	fprintf (script, "fi\n\n");

	fprintf (script, "# Restore system field separator\n"
			 "IFS=$OLDIFS\n\n");

	fclose (script);
}

static void
write_inbound_script ()
{
	gchar *scriptpath = POLICY_IN_DIR "/setup";
	FILE *script = fopen (scriptpath, "w");

        if (script == NULL) {
                perror(scriptpath);
                g_printerr("Script not written!");
		return;
	}
	chmod (scriptpath, 00440);

	fprintf (script, "# Initialize\n");
	fprintf (script, "$IPT -N INBOUND 2> /dev/null\n"
	                 "$IPT -F INBOUND\n\n");

	fprintf (script, "# Temoporarily set the field separator for CSV format\n"
			 "OLDIFS=$IFS\n"
			 "IFS=','\n\n");

	fprintf (script, "# Allow response traffic\n"
			 "$IPT -A INBOUND -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
			 "$IPT -A INBOUND -p udp -m state --state ESTABLISHED,RELATED -j ACCEPT\n\n");

	fprintf (script, "# Hosts from which connections are always allowed\n"
	                 "while read host garbage\n"
	                 "	do\n"
	                 "		$IPT -A INBOUND -s $host -j ACCEPT\n"
	                 "	done < "POLICY_IN_ALLOW_FROM"\n\n");

	fprintf (script, "# Services allowed\n"
	                 "while read service ports target garbage\n"
	                 "	do\n"
			 "		IFS=' '\n"
			 "		for port in `echo $ports`; do\n"
			 "			scrub_parameters\n"
			 "			case \"$port\" in\n"
			 "			  # Override broadcast blocking for Samba share discovery\n"
			 "			  \"1900\" ) $IPT -I INPUT -p tcp -s $target --dport 1900 -j ACCEPT\n"
			 "			           $IPT -I INPUT -p udp -s $target --dport 1900 -j ACCEPT;;\n"
			 "			  # Default service handler\n"
			 "			  * ) $IPT -A INBOUND -p tcp -s $target --dport $port -j ACCEPT\n"
			 "			      $IPT -A INBOUND -p udp -s $target --dport $port -j ACCEPT;;\n"
			 "			esac\n"
			 "		done\n"
			 "		IFS=','\n"
	                 "	done < "POLICY_IN_ALLOW_SERVICE"\n\n");

	fprintf (script, "$IPT -A INBOUND -j LSI\n");

	fprintf (script, "# Restore system field separator\n"
			 "IFS=$OLDIFS\n\n");
	fclose (script);
}

static void
write_sysctl_tuning_script ()
{
	gchar *scriptpath = FORTIFIED_SYSCTL_SCRIPT;
	FILE *script = fopen (scriptpath, "w");

        if (script == NULL) {
                perror(scriptpath);
                g_printerr("Script not written!");
		return;
	}
	chmod (scriptpath, 00440);

   fprintf (script, "# --------( Sysctl Tuning - Recommended Parameters )--------\n\n");
   
	fprintf (script, "# Turn off IP forwarding by default\n");
	fprintf (script, "# (this will be enabled if you require masquerading)\n\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/ip_forward ]; then\n"
	"  echo 0 > /proc/sys/net/ipv4/ip_forward\nfi\n\n");
	
	fprintf (script, "# Do not log 'odd' IP addresses (excludes 0.0.0.0 & 255.255.255.255)\n\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/conf/all/log_martians ]; then\n"
	"  echo 0 > /proc/sys/net/ipv4/conf/all/log_martians\nfi\n\n");	

   fprintf (script, "\n# --------( Sysctl Tuning - TCP Parameters )--------\n\n");
   
	fprintf (script, "# Turn off TCP Timestamping in kernel\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/tcp_timestamps ]; then\n"
	"  echo 0 > /proc/sys/net/ipv4/tcp_timestamps\nfi\n\n");    

	fprintf (script, "# Set TCP Re-Ordering value in kernel to '5'\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/tcp_reordering ]; then\n"
	"  echo 5 > /proc/sys/net/ipv4/tcp_reordering\nfi\n\n");
 
	fprintf (script, "# Turn off TCP ACK in kernel\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/tcp_sack ]; then\n"
	"  echo 0 > /proc/sys/net/ipv4/tcp_sack\nfi\n\n");

	fprintf (script, "#Turn off TCP Window Scaling in kernel\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/tcp_window_scaling ]; then\n"
	"  echo 0 > /proc/sys/net/ipv4/tcp_window_scaling\nfi\n\n");

	fprintf (script, "#Set Keepalive timeout to 1800 seconds\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/tcp_keepalive_time ]; then\n"
	"  echo 1800 > /proc/sys/net/ipv4/tcp_keepalive_time\nfi\n\n");

	fprintf (script, "#Set FIN timeout to 30 seconds\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/tcp_fin_timeout ]; then\n"
	"  echo 30 > /proc/sys/net/ipv4/tcp_fin_timeout\nfi\n\n");

	fprintf (script, "# Set TCP retry count to 3\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/tcp_retries1 ]; then\n"
	"  echo 3 > /proc/sys/net/ipv4/tcp_retries1\nfi\n\n");
    
/* note: ECN is now actually an RFC - this is just a stopgap measure until certain
 OS'es get their act together */
 
	fprintf (script, "#Turn off ECN notification in kernel\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/tcp_ecn ]; then\n"
	"  echo 0 > /proc/sys/net/ipv4/tcp_ecn\nfi\n\n");
	
   fprintf (script, "\n# --------( Sysctl Tuning - SYN Parameters )--------\n\n");
   
	fprintf (script, "# Turn on SYN cookies protection in kernel\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/tcp_syncookies ]; then\n"
	"  echo 1 > /proc/sys/net/ipv4/tcp_syncookies\nfi\n\n");
	
	fprintf (script, "# Set SYN ACK retry attempts to '3'\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/tcp_synack_retries ]; then\n"
	"  echo 3 > /proc/sys/net/ipv4/tcp_synack_retries\nfi\n\n");

	fprintf (script, "# Set SYN backlog buffer to '64'\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/tcp_max_syn_backlog ]; then\n"
	"  echo 64 > /proc/sys/net/ipv4/tcp_max_syn_backlog\nfi\n\n");
	
	fprintf (script, "# Set SYN retry attempts to '6'\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/tcp_syn_retries ]; then\n"
	"  echo 6 > /proc/sys/net/ipv4/tcp_syn_retries\nfi\n\n");
	
   fprintf (script, "\n# --------( Sysctl Tuning - Routing / Redirection Parameters )--------\n\n");

/* under 2.4 - source route verification only has 0 (off) and 1 (RFC compliant) */

	fprintf (script, "# Turn on source address verification in kernel\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/conf/all/rp_filter ]; then\n"
	"  for f in /proc/sys/net/ipv4/conf/*/rp_filter\n  do\n   echo 1 > $f\n  done\nfi\n\n");
	
	fprintf (script, "# Turn off source routes in kernel\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/conf/all/accept_source_route ]; then\n"
	"  for f in /proc/sys/net/ipv4/conf/*/accept_source_route\n  do\n   echo 0 > $f\n  done\nfi\n\n");

	fprintf (script, "# Do not respond to 'redirected' packets\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/secure_redirects ]; then\n"
	"  echo 0 > /proc/sys/net/ipv4/secure_redirects\nfi\n\n");
	
	fprintf (script, "# Do not reply to 'redirected' packets if requested\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/send_redirects ]; then\n"
	"  echo 0 > /proc/sys/net/ipv4/send_redirects\nfi\n\n");
    
	fprintf (script, "# Do not reply to 'proxyarp' packets\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/proxy_arp ]; then\n"
	"  echo 0 > /proc/sys/net/ipv4/proxy_arp\nfi\n\n");
	
	fprintf (script, "# Set FIB model to be RFC1812 Compliant\n");
	fprintf (script, "# (certain policy based routers may break with this - if you find\n");
	fprintf (script, "#  that you can't access certain hosts on your network - please set\n");
	fprintf (script, "#  this option to '0' - which is the default)\n\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/ip_fib_model ]; then\n"
	"  echo 2 > /proc/sys/net/ipv4/ip_fib_model\nfi\n\n");

   fprintf (script, "\n# --------( Sysctl Tuning - ICMP/IGMP Parameters )--------\n\n");
   
	fprintf (script, "# ICMP Dead Error Messages protection\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses ]; then\n"
	"  echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses\nfi\n\n");

	fprintf (script, "# ICMP Broadcasting protection\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts ]; then\n"
	"  echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts\nfi\n\n");
	
	fprintf (script, "# IGMP Membership 'overflow' protection\n");
	fprintf (script, "# (if you are planning on running your box as a router - you should either\n");
	fprintf (script, "#  set this option to a number greater than 5, or disable this protection\n");
	fprintf (script, "#  altogether by commenting out this option)\n\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/igmp_max_memberships ]; then\n"
	"  echo 1 > /proc/sys/net/ipv4/igmp_max_memberships\nfi\n\n");

   fprintf (script, "\n# --------( Sysctl Tuning - Miscellanous Parameters )--------\n\n");
   
   	fprintf (script, "# Set TTL to '64' hops\n");
   	fprintf (script, "# (If you are running a masqueraded network, or use policy-based\n");
   	fprintf (script, "#  routing - you may want to increase this value depending on the load\n");
   	fprintf (script, "#  on your link.)\n\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/conf/all/ip_default_ttl ]; then\n"
	"  for f in /proc/sys/net/ipv4/conf/*/ip_default_ttl\n  do\n   echo 64 > $f\n  done\nfi\n\n");

  	fprintf (script, "# Always defragment incoming packets\n");
   	fprintf (script, "# (Some cable modems [ Optus @home ] will suffer intermittent connection\n");
   	fprintf (script, "#  droputs with this setting. If you experience problems, set this to '0')\n\n");	
	fprintf (script, "if [ -e /proc/sys/net/ipv4/ip_always_defrag ]; then\n"
	"  echo 1 > /proc/sys/net/ipv4/ip_always_defrag\nfi\n\n");
	
  	fprintf (script, "# Keep packet fragments in memory for 8 seconds\n");
   	fprintf (script, "# (Note - this option has no affect if you turn packet defragmentation\n");
   	fprintf (script, "#  (above) off!)\n\n");	
	fprintf (script, "if [ -e /proc/sys/net/ipv4/ipfrag_time ]; then\n"
	"  echo 8 > /proc/sys/net/ipv4/ipfrag_time\nfi\n\n");

  	fprintf (script, "# Do not reply to Address Mask Notification Warnings\n");
   	fprintf (script, "# (If you are using your machine as a DMZ router or a PPP dialin server\n");
   	fprintf (script, "#  that relies on proxy_arp requests to provide addresses to it's clients\n");
   	fprintf (script, "#  you may wish to disable this option by setting the value to '1'\n\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/ip_addrmask_agent ]; then\n"
	"  echo 0 > /proc/sys/net/ipv4/ip_addrmask_agent\nfi\n\n");

	fprintf (script, "if [ \"$EXT_PPP\" = \"on\" ]; then\n"
	        	 "	# Turn on dynamic TCP/IP address hacking\n"
			 "	# (Some broken PPPoE clients require this option to be enabled)\n"
			 "	if [ -e /proc/sys/net/ipv4/ip_dynaddr ]; then\n"
			 "		echo 1 > /proc/sys/net/ipv4/ip_dynaddr\n"
			 "	fi\n"
			 "else\n"
			 "	if [ -e /proc/sys/net/ipv4/ip_dynaddr ]; then\n"
			 "		echo 0 > /proc/sys/net/ipv4/ip_dynaddr\n"
			 "	fi\n"
			 "fi");
    
   fprintf (script, "\n# --------( Sysctl Tuning - IPTables Specific Parameters )--------\n\n");
   
	fprintf (script, "# Doubling current limit for ip_conntrack\n");
	fprintf (script, "if [ -e /proc/sys/net/ipv4/ip_conntrack_max ]; then\n"
	"  echo 16384 > /proc/sys/net/ipv4/ip_conntrack_max\nfi\n\n");

	fclose (script);
}

/* [ write_netfilter_script ]
 * Creates the netfilter shell script
 */
void
write_netfilter_script (void)
{
	gchar *scriptpath = FORTIFIED_FIREWALL_SCRIPT;
	FILE *script = fopen (scriptpath, "w");
	time_t now;
	struct tm *tm;
	char timestamp[17];

        if (script == NULL) {
                /* Use perror to get sane error messages */
                perror(scriptpath);
                g_printerr("Script not written!");

		return;
	}

	chmod (scriptpath, 00440);
	write_sysctl_tuning_script ();
	write_inbound_script ();
	write_outbound_script ();
	
	now = time(NULL);
	tm = localtime(&now);
	strftime(timestamp, 17, "%F %R", tm);

	fprintf (script, "#-----------( Fortified " VERSION ", Netfilter kernel subsystem in use )----------#\n");
	fprintf (script, "#                                                                             #\n");
	fprintf (script, "# This firewall was generated by Fortified on %s              #\n", timestamp);
	fprintf (script, "#                                                                             #\n");
	fprintf (script, "#-----------------------------------------------------------------------------#\n\n");
  			
	/* Autoloading of netfilter modules must be done before chains are flushed.*/
    fprintf (script, "\n# --------( Initial Setup - Firewall Modules Autoloader )--------\n\n");

	fprintf (script, "# Remove ipchains module if found\n");
	fprintf (script, "$LSM | grep ipchains -q -s && $RMM ipchains\n\n");

	fprintf (script, "# Try to load every module we need\n");
	fprintf (script, "$MPB ip_tables 2> /dev/null\n");
	fprintf (script, "$MPB iptable_filter 2> /dev/null\n");
	fprintf (script, "$MPB ipt_state 2> /dev/null\n");		
	fprintf (script, "$MPB ip_conntrack 2> /dev/null\n");
	fprintf (script, "$MPB ip_conntrack_ftp 2> /dev/null\n");
	fprintf (script, "$MPB ip_conntrack_irc 2> /dev/null\n");
	fprintf (script, "$MPB ipt_REJECT 2> /dev/null\n");
	/* fprintf (script, "$MPB ipt_REDIRECT 2> /dev/null\n"); */
	fprintf (script, "$MPB ipt_TOS 2> /dev/null\n");
	fprintf (script, "$MPB ipt_MASQUERADE 2> /dev/null\n");
	fprintf (script, "$MPB ipt_LOG 2> /dev/null\n");
	fprintf (script, "$MPB iptable_mangle 2> /dev/null\n");
	fprintf (script, "$MPB ipt_ipv4optsstrip 2> /dev/null\n");
	fprintf (script, "if [ \"$NAT\" = \"on\" ]; then\n"
			 "	$MPB iptable_nat 2> /dev/null\n"
			 "	$MPB ip_nat_ftp 2> /dev/null\n"
			 "	$MPB ip_nat_irc 2> /dev/null\n"
			 "fi\n");

	fprintf (script, "if [ \"EXT_PPP\" = \"on\" ]; then\n"
			 "	$MPB bsd_comp 2> /dev/null\n"
			 "	$MPB ppp_deflate 2> /dev/null\n"
			 "fi\n\n");

   fprintf (script, "\n# --------( Initial Setup - Firewall Capabilities Check )--------\n\n");

	fprintf (script, "# Make sure the test chains does not exist\n");
	fprintf (script, "$IPT -F test 2> /dev/null\n"
			 "$IPT -X test 2> /dev/null\n"
			 "if [ \"$NAT\" = \"on\" ]; then\n"
			 "	$IPT -t nat -F test 2> /dev/null\n"
			 "	$IPT -t nat -X test 2> /dev/null\n"
			 "fi\n\n");

	fprintf (script, "# Iptables support check, mandatory feature\n"
	                 "if [ \"`$IPT -N test 2>&1`\" ]; then\n"
			 "	echo Fatal error: Your kernel does not support iptables.\n"
			 "	return %d\n"
			 "fi\n\n", RETURN_NO_IPTABLES);

	fprintf (script, "# Logging support check\n"
			 "log_supported=1\n"
			 "if [ \"`$IPT -A test -j LOG 2>&1`\" ]; then\n"
			 "	echo Warning: Logging not supported by kernel, you will recieve no firewall event updates.\n"
			 "	log_supported=\"\"\n"
			 "fi\n\n");

	fprintf (script, "if [ \"$NAT\" = \"on\" ]; then\n"
			 "	# NAT support check\n"
			 "	nat_supported=1\n"
			 "	if [ \"`$IPT -t nat -N test 2>&1`\" ]; then\n"
			 "		echo Warning: Network address translation not supported by kernel, feature disabled.\n"
			 "		nat_supported=\"\"\n"
			 "	fi\n"
			 "fi\n\n");

	fprintf (script, "# Mangle support check\n"
			 "mangle_supported=1\n"
			 "if [ \"`$IPT -t mangle -F 2>&1`\" ]; then\n"
			 "	echo Warning: Packet mangling not supported by kernel, feature disabled.\n"
			 "	mangle_supported=\"\"\n"
			 "fi\n\n");

	fprintf (script, "# IP options stripping support check\n");
	fprintf (script, "stripoptions_supported=1\n");
	fprintf (script, "if [ \"`$IPT -t mangle -A test -j IPV4OPTSSTRIP 2>&1`\" ]; then\n"
		/*"  echo Warning: IP options stripping not supported by kernel, feature disabled.\n"*/
		"  stripoptions_supported=\"\"\n"
		"fi\n\n");

   fprintf (script, "\n# --------( Chain Configuration - Flush Existing Chains )--------\n\n");

	fprintf (script, "# Purge standard chains (INPUT, OUTPUT, FORWARD).\n\n");
	fprintf (script, "$IPT -F\n$IPT -X\n$IPT -Z\n\n");

	fprintf (script, "# Purge extended chains (MANGLE & NAT) if they exist.\n\n");
	fprintf (script, "if [ \"$mangle_supported\" ]; then\n");
	fprintf (script, "  $IPT -t mangle -F\n  $IPT -t mangle -X\n  $IPT -t mangle -Z\nfi\n");
	fprintf (script, "if [ \"$nat_supported\" ]; then\n");
	fprintf (script, "  $IPT -t nat -F\n  $IPT -t nat -X\n  $IPT -t nat -Z\nfi\n\n");

   fprintf (script, "\n# --------( Chain Configuration - Configure Default Policy )--------\n\n");
	fprintf (script, "# Configure standard chains (INPUT, OUTPUT, FORWARD).\n\n");
	fprintf (script, "$IPT -P INPUT DROP\n");
	fprintf (script, "$IPT -P OUTPUT DROP\n");
	fprintf (script, "$IPT -P FORWARD DROP\n\n");

	fprintf (script, "# Configure extended chains (MANGLE & NAT) if required.\n\n");
	fprintf (script, "if [ \"$mangle_supported\" ]; then\n");
	fprintf (script, "  $IPT -t mangle -P INPUT ACCEPT\n");
	fprintf (script, "  $IPT -t mangle -P OUTPUT ACCEPT\n");
	fprintf (script, "  $IPT -t mangle -P PREROUTING ACCEPT\n");
	fprintf (script, "  $IPT -t mangle -P POSTROUTING ACCEPT\nfi\n");
	fprintf (script, "if [ \"$nat_supported\" ]; then\n");
	fprintf (script, "  $IPT -t nat -P OUTPUT ACCEPT\n");
	fprintf (script, "  $IPT -t nat -P PREROUTING ACCEPT\n");
	fprintf (script, "  $IPT -t nat -P POSTROUTING ACCEPT\nfi\n\n");

   fprintf (script, "\n# --------( Chain Configuration - Create Default Result Chains )--------\n\n");

	fprintf (script, "# Create a new chain for filtering the input before logging is performed\n"
	                 "$IPT -N LOG_FILTER 2> /dev/null\n"
	                 "$IPT -F LOG_FILTER\n\n");

	fprintf (script, "# Hosts for which logging is disabled\n");
	fprintf (script, "while read host garbage\n\tdo\n");
	fprintf (script, "\t\t$IPT -A LOG_FILTER -s $host -j $STOP_TARGET\n");
	fprintf (script, "\tdone < "FORTIFIED_FILTER_HOSTS_SCRIPT"\n\n");

	fprintf (script, "# Ports for which logging is disabled\n");
	fprintf (script, "while read port garbage\n\tdo\n");
	fprintf (script, "\t\t$IPT -A LOG_FILTER -p tcp --dport $port -j $STOP_TARGET\n");
	fprintf (script, "\t\t$IPT -A LOG_FILTER -p udp --dport $port -j $STOP_TARGET\n");
	fprintf (script, "\tdone < "FORTIFIED_FILTER_PORTS_SCRIPT"\n\n");

	fprintf (script, "# Create a new log and stop input (LSI) chain.\n");
	fprintf (script, "$IPT -N LSI 2> /dev/null\n"
	                 "$IPT -F LSI\n"
	                 "$IPT -A LSI -j LOG_FILTER\n"
	                 "if [ \"$log_supported\" ]; then\n"
	                 "	# Syn-flood protection\n"
	                 "	$IPT -A LSI -p tcp --syn -m limit --limit 1/s -j LOG --log-level=$LOG_LEVEL --log-prefix \"Inbound \"\n"
	                 "	$IPT -A LSI -p tcp --syn -j $STOP_TARGET\n"
	                 "	# Rapid portscan protection\n"
	                 "	$IPT -A LSI -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j LOG --log-level=$LOG_LEVEL --log-prefix \"Inbound \"\n"
	                 "	$IPT -A LSI -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j $STOP_TARGET\n"
	                 "	# Ping of death protection\n"
	                 "	$IPT -A LSI -p icmp --icmp-type echo-request -m limit --limit 1/s -j LOG --log-level=$LOG_LEVEL --log-prefix \"Inbound \"\n"
	                 "	$IPT -A LSI -p icmp --icmp-type echo-request -j $STOP_TARGET\n"
	                 "	# Log everything\n"
	                 "	$IPT -A LSI -m limit --limit 5/s -j LOG --log-level=$LOG_LEVEL --log-prefix \"Inbound \"\n"
	                 "fi\n"
	                 "$IPT -A LSI -j $STOP_TARGET # Terminate evaluation\n\n");

	fprintf (script, "# Create a new log and stop output (LSO) chain.\n");
	fprintf (script, "$IPT -N LSO 2> /dev/null\n"
	                 "$IPT -F LSO\n"
	                 "$IPT -A LSO -j LOG_FILTER\n"
	                 "if [ \"$log_supported\" ]; then\n"
	                 "	# Log everything\n"
	                 "	$IPT -A LSO -m limit --limit 5/s -j LOG --log-level=$LOG_LEVEL --log-prefix \"Outbound \"\n"
	                 "fi\n"
	                 "$IPT -A LSO -j REJECT # Terminate evaluation\n\n");

	fprintf (script, "\n# --------( Initial Setup - Nameservers )--------\n\n");

	fprintf (script, "# Allow regular DNS traffic\n"
			 "while read keyword server garbage\n"
			 "	do\n"
			 "		if [ \"$keyword\" = \"nameserver\" ]; then\n"
			 "			$IPT -A INPUT -p tcp ! --syn -s $server -d 0/0 -j ACCEPT\n"
			 "			$IPT -A INPUT -p udp -s $server -d 0/0 -j ACCEPT\n"
			 "			$IPT -A OUTPUT -p tcp -s $IP -d $server --dport 53 -j ACCEPT\n"
			 "			$IPT -A OUTPUT -p udp -s $IP -d $server --dport 53 -j ACCEPT\n"
			 "		fi\n"
			 "	done < /etc/resolv.conf\n\n");

	fprintf (script, "\n# --------( Initial Setup - Configure Kernel Parameters )--------\n\n");	
	fprintf (script, "source "FORTIFIED_SYSCTL_SCRIPT"\n\n");


	fprintf (script, "\n# --------( Intial Setup - User Defined Pre Script )--------\n\n");
	fprintf (script, "source "FORTIFIED_USER_PRE_SCRIPT"\n\n");

   fprintf (script, "\n# --------( Rules Configuration - Specific Rule - Loopback Interfaces )--------\n\n");

	fprintf (script, "# Allow all traffic on the loopback interface\n");
	fprintf (script, "$IPT -A INPUT -i lo -s 0/0 -d 0/0 -j ACCEPT\n");
	fprintf (script, "$IPT -A OUTPUT -o lo -s 0/0 -d 0/0 -j ACCEPT\n\n");


   fprintf (script, "\n# --------( Rules Configuration - Type of Service (ToS) - Ruleset Filtered by GUI )--------\n\n");

	fprintf (script, "if [ \"$FILTER_TOS\" = \"on\" ]; then\n");
	fprintf (script, "	if [ \"$TOS_CLIENT\" = \"on\" -a $mangle_supported ]; then\n"
			 "		# ToS: Client Applications\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 20:21 --set-tos $TOSOPT\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 22 --set-tos $TOSOPT\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 68 --set-tos $TOSOPT\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 80 --set-tos $TOSOPT\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 443 --set-tos $TOSOPT\n"
			 "	fi\n");

	fprintf (script, "	if [ \"$TOS_SERVER\" = \"on\" -a $mangle_supported ]; then\n"
			 "		# ToS: Server Applications\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 20:21 --set-tos $TOSOPT\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 22 --set-tos $TOSOPT\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 25 --set-tos $TOSOPT\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 53 --set-tos $TOSOPT\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 67 --set-tos $TOSOPT\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 80 --set-tos $TOSOPT\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 110 --set-tos $TOSOPT\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 143 --set-tos $TOSOPT\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 443 --set-tos $TOSOPT\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 1812 --set-tos $TOSOPT\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 1813 --set-tos $TOSOPT\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 2401 --set-tos $TOSOPT\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 8080 --set-tos $TOSOPT\n"
			 "	fi\n");

	fprintf (script, "	if [ \"$TOS_SERVER\" = \"on\" -a $mangle_supported ]; then\n"
			 "		# ToS: The X Window System\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 22 --set-tos 0x10\n"
			 "		$IPT -t mangle -A OUTPUT -p tcp -j TOS --dport 6000:6015 --set-tos 0x08\n"
			 "	fi\n");
	fprintf (script, "fi\n\n");

        fprintf (script, "\n# --------( Rules Configuration - ICMP )--------\n\n");

        fprintf (script, "if [ \"$FILTER_ICMP\" = \"on\" ]; then\n");

	fprintf (script, "	if [ \"$ICMP_ECHO_REQUEST\" = \"on\" ]; then\n"
	                 "		# ICMP: Ping Requests\n"
	                 "		$IPT -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT\n"
	                 "		$IPT -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT\n"
			 "	fi\n");

	fprintf (script, "	if [ \"$ICMP_ECHO_REPLY\" = \"on\" ]; then\n"
	                 "		# ICMP: Ping Replies\n"
	                 "		$IPT -A INPUT -p icmp --icmp-type echo-reply -m limit --limit 1/s -j ACCEPT\n"
	                 "		$IPT -A FORWARD -p icmp --icmp-type echo-reply -m limit --limit 1/s -j ACCEPT\n"
			 "	fi\n");


	fprintf (script, "	if [ \"$ICMP_TRACEROUTE\" = \"on\" ]; then\n"
	                 "		# ICMP: Traceroute Requests\n"
	                 "		$IPT -A INPUT -p udp --dport 33434 -j ACCEPT\n"
	                 "		$IPT -A FORWARD -p udp --dport 33434 -j ACCEPT\n"
	                 "	else\n"
			 "		$IPT -A INPUT -p udp --dport 33434 -j LSI\n"
			 "		$IPT -A FORWARD -p udp --dport 33434 -j LSI\n"
			 "	fi\n");

	fprintf (script, "	if [ \"$ICMP_MSTRACEROUTE\" = \"on\" ]; then\n"
	                 "		# ICMP: MS Traceroute Requests\n"
	                 "		$IPT -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT\n"
	                 "		$IPT -A FORWARD -p icmp --icmp-type destination-unreachable -j ACCEPT\n"
			 "	fi\n");

	fprintf (script, "	if [ \"$ICMP_UNREACHABLE\" = \"on\" ]; then\n"
	                 "		# ICMP: Unreachable Requests\n"
	                 "		$IPT -A INPUT -p icmp --icmp-type host-unreachable -j ACCEPT\n"
	                 "		$IPT -A FORWARD -p icmp --icmp-type host-unreachable -j ACCEPT\n"
			 "	fi\n");

	fprintf (script, "	if [ \"$ICMP_TIMESTAMPING\" = \"on\" ]; then\n"
	                 "		# ICMP: Timestamping Requests\n"
	                 "		$IPT -A INPUT -p icmp --icmp-type timestamp-request -j ACCEPT\n"
	                 "		$IPT -A INPUT -p icmp --icmp-type timestamp-reply -j ACCEPT\n"
			 "	fi\n");

	fprintf (script, "	if [ \"$ICMP_MASKING\" = \"on\" ]; then\n"
	                 "		# ICMP: Address Masking\n"
	                 "		$IPT -A INPUT -p icmp --icmp-type address-mask-request -j ACCEPT\n"
	                 "		$IPT -A INPUT -p icmp --icmp-type address-mask-reply -j ACCEPT\n"
	                 "		$IPT -A FORWARD -p icmp --icmp-type address-mask-request -j ACCEPT\n"
	                 "		$IPT -A FORWARD -p icmp --icmp-type address-mask-reply -j ACCEPT\n"
			 "	fi\n");

	fprintf (script, "	if [ \"$ICMP_REDIRECTION\" = \"on\" ]; then\n"
	                 "		# ICMP: Redirection Requests\n"
	                 "		$IPT -A INPUT -p icmp --icmp-type redirect -m limit --limit 2/s -j ACCEPT\n"
	                 "		$IPT -A FORWARD -p icmp --icmp-type redirect -m limit --limit 2/s -j ACCEPT\n"
			 "	fi\n");

	fprintf (script, "	if [ \"$ICMP_SOURCE_QUENCHES\" = \"on\" ]; then\n"
	                 "		# ICMP: Source Quench Requests\n"
	                 "		$IPT -A INPUT -p icmp --icmp-type source-quench -m limit --limit 2/s -j ACCEPT\n"
	                 "		$IPT -A FORWARD -p icmp --icmp-type source-quench -m limit --limit 2/s -j ACCEPT\n"
			 "	fi\n\n");

	fprintf (script, "	# Catch ICMP traffic not allowed above\n"
			 "	$IPT -A INPUT -p icmp -j LSI\n"
			 "	$IPT -A FORWARD -p icmp -j LSI\n");

	fprintf (script, "else\n"
	                 "	# Allow all ICMP traffic when filtering disabled\n"
	                 "	$IPT -A INPUT -p icmp -m limit --limit 10/s -j ACCEPT\n"
	                 "	$IPT -A FORWARD -p icmp -m limit --limit 10/s -j ACCEPT\n"
			 "fi\n\n");

	fprintf (script, "if [ \"$NAT\" = \"on\" ]; then\n"
			 "	# --------( Rules Configuration - Masquerading - Sysctl Modifications )--------\n\n");
   
	fprintf (script, "	#Turn on IP forwarding\n");
	fprintf (script, "	if [ -e /proc/sys/net/ipv4/ip_forward ]; then\n"
	                 "		echo 1 > /proc/sys/net/ipv4/ip_forward\n"
			 "	fi\n\n");

	fprintf (script, "	# --------( Rules Configuration - Masquerading - Default Ruleset )--------\n\n");
      		
	fprintf (script, "	#TCPMSS Fix - Needed for *many* broken PPPO{A/E} clients\n"
	                 "	$IPT -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n\n");

	fprintf (script, "	if [ \"$stripoptions_supported\" -a \"$mangle_supported\" ]; then\n"
	                 "		#IPv4OPTIONS Fix - Strip IP options from a forwarded packet\n"
	                 "		$IPT -t mangle -A PREROUTING -j IPV4OPTSSTRIP\n"
	                 "	fi\n\n");

	fprintf (script, "	# --------( Rules Configuration - Forwarded Traffic )--------\n\n");

	fprintf (script, "	if [ \"$nat_supported\" ]; then\n"
	                 "		#Masquerade outgoing traffic\n"
	                 "		$IPT -t nat -A POSTROUTING -o $IF -j MASQUERADE\n"
	                 "	fi\n\n");

	fprintf (script, "	# Temoporarily set the field separator for CSV format\n"
	                 "	OLDIFS=$IFS\n"
	                 "	IFS=','\n\n");

	fprintf (script, "	# Services forward from the firewall to the internal network\n"
	                 "	while read service ext_port host int_port garbage\n"
	                 "		do\n"
			 "			scrub_parameters\n"
	                 "			$IPT -A FORWARD -i $IF -p tcp -d $host --dport $int_port -j ACCEPT\n"
	                 "			$IPT -A FORWARD -i $IF -p udp -d $host --dport $int_port -j ACCEPT\n"
	                 "			$IPT -A PREROUTING -t nat -i $IF -p tcp --dport $ext_port -j DNAT --to-destination $host:$int_port_dashed\n"
	                 "			$IPT -A PREROUTING -t nat -i $IF -p udp --dport $ext_port -j DNAT --to-destination $host:$int_port_dashed\n"
	                 "		done < "POLICY_IN_FORWARD"\n\n");

	fprintf (script, "	IFS=$OLDIFS\n\n");

	fprintf (script, "fi\n\n");

   fprintf (script, "\n# --------( Rules Configuration - Inbound Traffic )--------\n\n");

	fprintf (script, "if [ \"$BLOCK_NON_ROUTABLES\" = \"on\" ]; then\n"
	                 "	# Block traffic from non-routable address space on the public interfaces\n"
	                 "	$IPT -N NR 2> /dev/null\n"
			 "	$IPT -F NR\n"
	                 "	while read block garbage\n"
			 "		do\n"
	                 "			$IPT -A NR -s $block -d $NET -i $IF -j LSI\n"
	                 "		done < "FORTIFIED_NON_ROUTABLES_SCRIPT"\n"
	                 "	$IPT -A INPUT -s ! $NET -i $IF -j NR\n"
			 "fi\n\n");

	fprintf (script, "# Block Broadcast Traffic\n"
	                 "if [ \"$BLOCK_EXTERNAL_BROADCAST\" = \"on\" ]; then\n"
	                 "	$IPT -A INPUT -i $IF -d 255.255.255.255 -j DROP\n"
			 "	if [ \"$BCAST\" != \"\" ]; then\n"
	                 "		$IPT -A INPUT -d $BCAST -j DROP\n"
			 "	fi\n"
			 "fi\n\n");

	fprintf (script, "if [ \"$NAT\" = \"on\" -a \"$BLOCK_INTERNAL_BROADCAST\" = \"on\" ]; then\n"
	                 "	$IPT -A INPUT -i $INIF -d 255.255.255.255 -j DROP\n"
			 "	if [ \"$INBCAST\" != \"\" ]; then\n"
	                 "		$IPT -A INPUT -i $INIF -d $INBCAST -j DROP\n"
			 "	fi\n"
			 "fi\n\n");

	fprintf (script, "# Block Multicast Traffic\n"
	                 "#  Some cable/DSL providers require their clients to accept multicast transmissions\n"
	                 "#  you should remove the following four rules if you are affected by multicasting\n"
	                 "$IPT -A INPUT -s 224.0.0.0/8 -d 0/0 -j DROP\n"
	                 "$IPT -A INPUT -s 0/0 -d 224.0.0.0/8 -j DROP\n"
	                 "$IPT -A OUTPUT -s 224.0.0.0/8 -d 0/0 -j DROP\n"
	                 "$IPT -A OUTPUT -s 0/0 -d 224.0.0.0/8 -j DROP\n\n");

	fprintf (script, "# Block Traffic with Stuffed Routing\n"
                         "#  Early versions of PUMP - (the DHCP client application included in RH / Mandrake) require\n"
                         "#  inbound packets to be accepted from a source address of 255.255.255.255.  If you have issues\n"
                         "#  with DHCP clients on your local LAN - either update PUMP, or remove the first rule below)\n"
	                 "$IPT -A INPUT -s 255.255.255.255 -j DROP\n"
	                 "$IPT -A INPUT -d 0.0.0.0 -j DROP\n"
	                 "$IPT -A OUTPUT -s 255.255.255.255 -j DROP\n"
	                 "$IPT -A OUTPUT -d 0.0.0.0 -j DROP\n\n");

	fprintf (script, "$IPT -A INPUT -m state --state INVALID -j DROP # Block Traffic with Invalid Flags\n");
	fprintf (script, "$IPT -A INPUT -f -m limit --limit 10/minute -j LSI # Block Traffic w/ Excessive Fragmented Packets\n");

   fprintf (script, "\n# --------( Rules Configuration - Outbound Traffic )--------\n\n");
	fprintf (script, "$IPT -A OUTPUT -m state --state INVALID -j DROP # Block Traffic w/ Invalid Flags\n\n");

   fprintf (script, "\n# --------( Traffic Policy )--------\n\n");
	fprintf (script, "# Load the inbound traffic policy\n");
	fprintf (script, "source "FORTIFIED_INBOUND_SETUP"\n"
	                 "$IPT -A INPUT -i $IF -j INBOUND # Check Internet to firewall traffic\n"
	                 "if [ \"$NAT\" = \"on\" ]; then\n"
	                 "	$IPT -A INPUT -i $INIF -d $INIP -j INBOUND # Check LAN to firewall (private ip) traffic\n"
	                 "	$IPT -A INPUT -i $INIF -d $IP -j INBOUND   # Check LAN to firewall (public ip) traffic\n"
			 "	if [ \"$INBCAST\" != \"\" ]; then\n"
			 "		$IPT -A INPUT -i $INIF -d $INBCAST -j INBOUND # Check LAN to firewall broadcast traffic\n"
			 "	fi\n"
	                 "fi\n\n");

	fprintf (script, "# Load the outbound traffic policy\n");
	fprintf (script, "source "FORTIFIED_OUTBOUND_SETUP"\n"
	                 "$IPT -A OUTPUT -o $IF -j OUTBOUND # Check firewall to Internet traffic\n"
	                 "if [ \"$NAT\" = \"on\" ]; then\n"
	                 "	$IPT -A OUTPUT -o $INIF -j OUTBOUND  # Check firewall to LAN traffic\n"
	                 "	$IPT -A FORWARD -i $INIF -j OUTBOUND # Check LAN to Internet traffic\n\n"

	                 "	# Allow Internet to LAN response traffic\n"
	                 "	$IPT -A FORWARD -p tcp -d $INNET -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
	                 "	$IPT -A FORWARD -p udp -d $INNET -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
			 "fi\n");

	fprintf (script, "\n# --------( User Defined Post Script )--------\n\n");
	fprintf (script, "source "FORTIFIED_USER_POST_SCRIPT"\n\n");

	fprintf (script, "\n# --------( Unsupported Traffic Catch-All )--------\n\n"
			 "$IPT -A INPUT -j LOG_FILTER\n"
			 "$IPT -A INPUT -j LOG --log-level=$LOG_LEVEL --log-prefix \"Unknown Input\"\n"
			 "$IPT -A OUTPUT -j LOG_FILTER\n"
			 "$IPT -A OUTPUT -j LOG --log-level=$LOG_LEVEL --log-prefix \"Unknown Output\"\n"
			 "$IPT -A FORWARD -j LOG_FILTER\n"
			 "$IPT -A FORWARD -j LOG --log-level=$LOG_LEVEL --log-prefix \"Unknown Forward\"\n\n");

	fprintf (script, "return 0\n");

	fclose (script);

	g_print (_("Firewall script saved as %s\n"), scriptpath);
}
