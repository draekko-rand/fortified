/*---[ service.c ]----------------------------------------------------
 * Copyright (C) 2000 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Return the service used, based on the port and protocol given
 *--------------------------------------------------------------------*/

#include <netdb.h>
#include <netinet/in.h>
#include <ctype.h>

#include "service.h"

typedef struct
{
	gchar *name;
	gchar *ports;
} Service;

Service user_services[] = {
	{"BitTorrent", "6881-6889"},
	{"DHCP", "67-68"},
	{"DNS", "53"},
	{"FTP", "20-21"},
	{"HTTP", "80"},
	{"HTTPS", "443"},
	{"IMAP", "143"},
	{"NFS", "111 2049"},
	{"NNTP", "119"},
	{"NTP", "123"},
	{"POP3", "110"},	
	{"Samba (SMB)", "137-139 445"},
	{"SMTP", "25"},
	{"SSH", "22"},
	{"Telnet", "23"},
	{"Xwindows", "6000-6015"},
};

Service misc_services[] = {
	{"DCOM-scm", "135"},
	{"PhAse zero", "555"},
	{"PC server backdoor", "600"},
	{"Mountd bug", "635"},
	{"Kazaa", "1214"},
	{"Nessus", "1241"},
	{"Subseven", "1234,1243,2772,2773"},
	{"Trin00", "1524,27444,31335"},
	{"SSDP", "1900"},
	{"Backdoor-g/Subseven", "1999"},
	{"CPQ-Wbem", "2301"},
	{"Master's paradise", "3129"},
	{"HotU chat", "3449"},
	{"MS IPSec NAT-T", "4500"},
	{"eDonkey", "4662"},
	{"uPNP", "5000"},
	{"SIP", "5060"},
	{"SIP over TLS", "5061"},
	{"AOL IM", "5190-5193"},
	{"pcAnywhere", "5623"},
	{"VNC reflector", "5999"},
	{"VNC", "5900,5500,5800"},
	{"Gnutella", "6346"},
	{"Deep throat", "6670"},
	{"Sub-7", "6711-6713,6776,16959"},
	{"Gatecrasher", "6969"},
	{"RealAudio", "6970"},
	{"Sub-7 matrix chat", "7215"},
	{"Unreal", "7777-7778"},
	{"SHOUTcast", "8000"},
	{"Teamspeak server", "8767"},
	{"Webadmin", "10000"},
	{"Cheeseworm", "10008"},
	{"Netbus", "12345,12346"},
	{"PowWow", "13223"},
	{"Teamspeak server", "14534"},
	{"Stacheldraht", "16660,60001,65000"},
	{"Conducent", "17027"},
	{"Kuang2", "17300"},
	{"Useradmin", "20000"},
	{"Netbus 2 pro", "20034"},
	{"Acidkor", "20002"},
	{"Girlfriend", "21544"},
	{"Evilftp", "23456"},
	{"Half-life", "27015"},
	{"Backdoor-G or Sub-7", "27374"},
	{"Quake", "27910-27961"},
	{"Netsphere", "30100"},
	{"Back orifice", "31337-31338"},
	{"Hack'a'tack", "31789"},
	{"Sun-RPC portmap", "32770-32900"},
	{"Trinity v3", "33270"},
	{"Traceroute", "33434-33600"},
	{"Inoculan", "41508"},
	{"Teamspeak network", "45647"},
	{"Sockets de troi", "50505"},
	{"Teamspeak query port", "51234"},
	{"Sub-7 spy port", "54283"},
	{"Back orifice 2K", "54320-54321"},
};

GtkListStore*
services_get_model (void)
{
	static GtkListStore *model = NULL;

	gint num_services = sizeof (user_services) / sizeof (Service);
	gint i;

	if (model != NULL)
		return model;

	model = gtk_list_store_new (2,
		G_TYPE_STRING, G_TYPE_STRING);

	for (i = 0; i < num_services; i++) {
		GtkTreeIter iter;

		gtk_list_store_append (model, &iter);
		gtk_list_store_set (model, &iter,
			0, user_services[i].name,
			1, user_services[i].ports,
			-1);
	}

	return model;
}

static void
table_append_services (GHashTable *table, const Service *services, gint num_services)
{
	gint i;

	for (i = 0; i < num_services; i++) {
		gchar **tokens;
		gint j;

		tokens = g_strsplit_set (services[i].ports, ",", -1);

		for (j = 0; tokens[j] != NULL; j++) {
			
			if (g_strrstr (tokens[j], "-")) { /* Token is a port range */
				gint start, end, port;
				gchar **range;

				range = g_strsplit_set (tokens[j], "-", 2);
				start = atoi(range[0]);
				end = atoi(range[1]);
				for (port = start; port <= end; port++) {
					g_hash_table_replace (table, GINT_TO_POINTER (port), services[i].name);
				}

				 g_strfreev (range);
			} else { /* Token is a port number */
				gint port = atoi (tokens[j]);
				g_hash_table_insert (table, GINT_TO_POINTER (port), services[i].name);
			}
		}
		g_strfreev (tokens);
	}
}

/* [ service_get_name ]
 * Return the service/exploit used, based on the port and protocol given
 */
gchar *
service_get_name (gint port, gchar *proto)
{
	static GHashTable *services_table = NULL;
	gchar *name = NULL;

	if (port == 0 || proto == NULL)
		return (g_strdup (_("Unknown")));

	/* Initialize services table */
	if (services_table == NULL) {
		gint elements;

		services_table = g_hash_table_new (g_direct_hash, NULL);
		elements = sizeof (user_services) / sizeof(Service);
		table_append_services (services_table, user_services, elements);
		elements = sizeof (misc_services) / sizeof(Service);
		table_append_services (services_table, misc_services, elements);
	}

	name = (gchar *)g_hash_table_lookup (services_table, GINT_TO_POINTER (port));
	if (!name) { /* The service was not in our table, revert to system's service list */
		struct servent *ent;
		gchar *lowercase_proto;
		
		lowercase_proto =  g_ascii_strdown (proto, -1);
		ent = getservbyport (htons (port), lowercase_proto);
		g_free (lowercase_proto);

		if (ent && ent->s_name != "") {
			name = ent->s_name;
			name[0] = toupper(name[0]);
			/* Register the retrieved service with the table for future reference */
			g_hash_table_insert (services_table, GINT_TO_POINTER (port), g_strdup(name));
		}
	}

	if (name)
		return g_strdup(name);
	else
		return (g_strdup (_("Unknown")));
}

gchar *
service_get_icmp_name (gint type) {
	
	if (type==0) return (g_strdup ("Echo reply"));
	if (type==1 || type == 2) return (g_strdup ("Unassigned"));
	if (type==3) return (g_strdup ("Dest. unreachable"));
	if (type==4) return (g_strdup ("Source quench"));
	if (type==5) return (g_strdup ("Redirect"));
	if (type==6) return (g_strdup ("Alternate host address"));
	if (type==7) return (g_strdup ("Unassigned"));
	if (type==8) return (g_strdup ("Echo"));
	if (type==9) return (g_strdup ("Router advertisement"));
	if (type==10) return (g_strdup ("Router selection"));
	if (type==11) return (g_strdup ("Time exceeded"));
	if (type==12) return (g_strdup ("Parameter problem"));
	if (type==13) return (g_strdup ("Timestamp"));
	if (type==14) return (g_strdup ("Timestamp reply"));
	if (type==15) return (g_strdup ("Information request"));
	if (type==16) return (g_strdup ("Information reply"));
	if (type==17) return (g_strdup ("Address mask request"));
	if (type==18) return (g_strdup ("Address mask reply"));
	if (type==19) return (g_strdup ("Reserved"));
	if (type >= 20 && type <= 29) return (g_strdup ("Reserved"));
	if (type==30) return (g_strdup ("Traceroute"));
	if (type==31) return (g_strdup ("Datagram conversion error"));
	if (type==32) return (g_strdup ("Mobile host redirect"));
	if (type==33) return (g_strdup ("IPv6 where-are-you"));
	if (type==34) return (g_strdup ("IPv6 I-am-here"));
	if (type==35) return (g_strdup ("Mobile registration request"));
	if (type==36) return (g_strdup ("mobile registration reply"));
	if (type >= 37 && type <= 255) return (g_strdup ("Reserved"));
	
	return (g_strdup (_("Unknown")));
}
