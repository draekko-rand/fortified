/*---[ statusview.c ]-----------------------------------------------------
 * Copyright (C) 2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * The Status page and related functions
 *--------------------------------------------------------------------*/

#include <config.h>
#include <gnome.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include <sys/types.h>
#include <fcntl.h>

#include "fortified.h"
#include "globals.h"
#include "statusview.h"
#include "menus.h"
#include "preferences.h"
#include "util.h"
#include "service.h"
#include "tray.h"
#include "gui.h"
#include "xpm/fortified-pixbufs.h"
 
#define DEV_FILE "/proc/net/dev"
#define TCP_FILE "/proc/net/tcp"
#define CONNTRACK_FILE "/proc/net/ip_conntrack"
#define CONNTRACK_TTL 10 /* Number of refresh cycles a non-established connection is kept in the GUI */
#define REFRESH_RATE 1 /* Time in seconds between updates */
#define HISTORY_LENGTH 5 /* Number of samples to use when averaging the traffic rate */
#define COLOR_RETIRED_CONNECTION "#6d6d6d"

static gboolean active_connections_visible = FALSE;

static FirewallStatus current_status;

static GtkWidget *connectionview;

static GtkWidget *device_table;
static GtkWidget *fw_state_icon;
static GtkWidget *fw_state_label;

static gint counter_events_in, counter_events_out, counter_serious_events_in, counter_serious_events_out;
static GtkWidget *events_in, *events_out, *events_serious_in, *events_serious_out;

static GHashTable *conntrack_programs = NULL;


typedef struct _Interface_info Interface_info;
struct _Interface_info
{
	gchar *type;
	gulong received;
	gulong sent;
	gulong previous_total;
	float  average;
	float *traffic_history;
	gint   history_index;
};

typedef struct _Interface_widgets Interface_widgets;
struct _Interface_widgets
{
	GtkWidget *device;
	GtkWidget *type;
	GtkWidget *received;
	GtkWidget *sent;
	GtkWidget *activity;
};

typedef struct _Connection_entry Connection_entry;
struct _Connection_entry
{
	GtkTreeIter *ref;
	gint ttl;
};

enum
{
 	CONNECTIONCOL_SOURCE,
	CONNECTIONCOL_DESTINATION,
	CONNECTIONCOL_PORT,
	CONNECTIONCOL_SERVICE,
	CONNECTIONCOL_PROGRAM,
	CONNECTIONCOL_COLOR,
	NUM_CONNECTIONCOLUMNS
};

static GtkListStore*
get_connectionstore (void)
{
	return GTK_LIST_STORE (gtk_tree_view_get_model (GTK_TREE_VIEW (connectionview)));
}


static unsigned long
get_inode (gchar *m_source, gchar *m_destination,
           gchar *m_remote_port)
{
	gint line_num = 0;
	gchar *line;
	static GIOChannel *in = NULL;
	unsigned long inode;
	GError *error = NULL;

	if (in == NULL) {
		in = g_io_channel_new_file (TCP_FILE, "r", &error);

		if (in == NULL) {
			printf ("Error reading %s: %s\n", TCP_FILE, error->message);
			return 0;
		}
	}

	while (TRUE) {
		int local_port, rem_port;
		gchar local_addr[128], rem_addr[128], more[512];
		struct sockaddr_in localaddr, remaddr;
		gchar *ip;

		inode = -1;

		g_io_channel_read_line (in, &line, NULL, NULL, &error);

		if (line == NULL) // EOF reached
			break;

		line_num++;

		if (line_num == 1) { // Skip tcp file header
			g_free (line);
			continue;
		}

		sscanf(line,
		       "%*X: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %*X %*X:%*X %*X:%*X %*X %*d %*d %ld %512s\n",
		       local_addr, &local_port, rem_addr, &rem_port, &inode, more);

		sscanf(local_addr, "%X",
			&((struct sockaddr_in *) &localaddr)->sin_addr.s_addr);
		sscanf(rem_addr, "%X",
			&((struct sockaddr_in *) &remaddr)->sin_addr.s_addr);
		((struct sockaddr *) &localaddr)->sa_family = AF_INET;
		((struct sockaddr *) &remaddr)->sa_family = AF_INET;

		if (rem_port != atoi (m_remote_port)) {
			g_free (line);
			continue;
		}

		ip = inet_ntoa (localaddr.sin_addr);
		if (!g_str_equal (ip, m_source)) {
			g_free (line);
			continue;
		}

		ip = inet_ntoa (remaddr.sin_addr);
		if (!g_str_equal (ip, m_destination)) {
			g_free (line);
			continue;
		}

		/* printf ("MATCH %s %s\n", ip, m_destination); */
		g_free (line);
		break;
	}

	g_io_channel_seek_position (in, 0, G_SEEK_SET, &error); // Rewind
	return inode;
}

static void
extract_socket_inode (gchar *lname, long *inode_p)
{
	if (!g_str_has_suffix (lname, "]")) {
		*inode_p = -1;
	} else {
		gchar *inode_str, *serr;

		inode_str = get_text_between (lname, "[", "]");

		*inode_p = strtol (inode_str, &serr, 0);
		if (!serr || *serr || *inode_p < 0 || *inode_p >= INT_MAX)
			*inode_p = -1;

		g_free (inode_str);
	}
}

static void
load_program_cache (void)
{
	char line[40];
	int procfdlen, fd, cmdllen;
	char cmdlbuf[512];
	long inode;
	const char *cs, *cmdlp;
	DIR *dirproc = NULL, *dirfd = NULL;
	struct dirent *direproc, *direfd;
	gchar *lname;

	if (conntrack_programs == NULL)
		conntrack_programs = g_hash_table_new_full (g_direct_hash, NULL, NULL, g_free);

	if (!(dirproc=opendir("/proc"))) {
		printf ("error opening proc filesystem\n");
		return;
	}

	while (errno=0, direproc = readdir (dirproc)) {

		if (direproc->d_type!=DT_DIR)
			continue;

		for (cs = direproc->d_name; *cs; cs++)
			if (!g_ascii_isdigit(*cs) || *cs)
				break;

		procfdlen = snprintf (line, sizeof (line), "/proc/%s/fd", direproc->d_name);
		if (procfdlen <= 0 || procfdlen >= sizeof (line)-5) 
			continue;
		errno = 0;
		dirfd = opendir (line);

		if (!dirfd)
			continue;
		line[procfdlen] = '/';
		
		cmdlp = NULL;
		while ((direfd = readdir (dirfd))) {
			if (direfd->d_type!=DT_LNK) 
				continue;

			if (procfdlen+1+strlen(direfd->d_name)+1>sizeof(line)) 
				continue;
			memcpy(line + procfdlen - 2, "fd/", 2+1);
			strcpy(line + procfdlen + 1, direfd->d_name);
			lname = g_file_read_link (line, NULL);

			extract_socket_inode (lname, &inode);

			if (inode < 0) {
				g_free (lname);
				continue;
			}

			if (!cmdlp) {
				if (procfdlen - 2 + 7 >= sizeof(line) - 5) {
					g_free (lname);
					continue;
				}
				strcpy (line + procfdlen-2, "cmdline");
				fd = open(line, O_RDONLY);
				if (fd < 0) {
					g_free (lname);
					continue;
				}
				cmdllen = read (fd, cmdlbuf, sizeof(cmdlbuf) - 1);
				if (close(fd)) {
					g_free (lname);
					continue;
				}
				if (cmdllen == -1) {
					g_free (lname);
					continue;
				}
				if (cmdllen < sizeof (cmdlbuf) - 1) 
					cmdlbuf[cmdllen] = '\0';
				if ((cmdlp = strrchr(cmdlbuf, '/')))
					cmdlp++;
				else 
					cmdlp = cmdlbuf;
			}

			g_hash_table_replace (conntrack_programs, GINT_TO_POINTER (inode), g_strdup (cmdlp));

			g_free (lname);
		}

		closedir(dirfd); 
		dirfd = NULL;

	}

	if (dirproc) 
		closedir(dirproc);
	if (dirfd) 
		closedir(dirfd);
}

static gchar *
get_program_name (gint inode)
{
	gchar *name = NULL;

	name = g_hash_table_lookup (conntrack_programs, GINT_TO_POINTER (inode));
	/* printf ("Looking up: %d, got: %s\n", inode, name); */
	return name;
}

/* [ connectionview_append_connection ]
 * Append a connection to the connectionlist
 */
static GtkTreeIter*
connectionview_append_connection (gchar *source, gchar *destination, gchar *port, gchar *service)
{
	GtkListStore *store = get_connectionstore ();
	GtkTreeIter *iter = g_new (GtkTreeIter, 1);
	unsigned long inode = -1;
	gchar *program;
	static gchar *firewall_ip = NULL;

	if (firewall_ip == NULL);
		firewall_ip = get_ip_of_interface (preferences_get_string (PREFS_FW_EXT_IF));

	 /* Only look up program names for local connections */
	if (g_str_equal (firewall_ip, source)) {
		load_program_cache ();
		inode = get_inode (source, destination, port);
	}

	if (inode != -1)
		program = get_program_name (inode);
	else
		program = g_strdup ("");

	gtk_list_store_append (store, iter);
	gtk_list_store_set (store, iter,
	                    CONNECTIONCOL_SOURCE, source,
	                    CONNECTIONCOL_DESTINATION, destination,
	                    CONNECTIONCOL_PORT, port,
	                    CONNECTIONCOL_SERVICE, service,
			    CONNECTIONCOL_PROGRAM, program, 
			    CONNECTIONCOL_COLOR, NULL,
	                    -1);

	gtk_tree_view_columns_autosize (GTK_TREE_VIEW (connectionview));

	return iter;
}

static void
connectionview_refresh (GHashTable *entries)
{
	static GPatternSpec *pattern = NULL;
	static GIOChannel *in = NULL;

	GError *error = NULL;
	gchar *line;

	if (pattern == NULL)
		pattern = g_pattern_spec_new ("* ESTABLISHED src=* dst=* dport=*");

	if (in == NULL) {
		in = g_io_channel_new_file (CONNTRACK_FILE, "r", &error);

		if (in == NULL) {
			printf ("Error reading %s: %s\n", CONNTRACK_FILE, error->message);
			return;
		}
	}

	while (TRUE) {
		g_io_channel_read_line (in, &line, NULL, NULL, &error);
		if (line == NULL) // EOF reached
			break;

		if (g_pattern_match_string (pattern, line)) { /* Entry is an established connection */
			gchar *source, *destination, *port;
			gchar *key;
			Connection_entry *entry = NULL;
			
			source = get_text_between (line, "src=", " ");
			destination = get_text_between (line, "dst=", " ");
			port = get_text_between (line, "dport=", " ");

			key = g_strdup_printf ("%s%s%s",  source, destination, port);
			entry = g_hash_table_lookup (entries, key);
			if (entry == NULL) { /* Only append new connections to the table */
				GtkTreeIter *ref;
				gchar *service;

				service = service_get_name (atoi (port), "tcp");
				ref = connectionview_append_connection (source, destination, port, service);

				entry = g_new0 (Connection_entry, 1);
				entry->ref = ref;
				g_hash_table_insert (entries, key, entry);
				g_free (service);
			} else {
				GtkListStore *store = get_connectionstore ();

				g_free (key);
				/* Reset color for connections seen this update */
				gtk_list_store_set (store, entry->ref,
				                    CONNECTIONCOL_COLOR, NULL,
				                    -1);
			}

			entry->ttl = CONNTRACK_TTL; /* Refresh TTL for all seen connections */
			g_free (source);
			g_free (destination);
			g_free (port);
		}

		g_free (line);
	}

	g_io_channel_seek_position (in, 0, G_SEEK_SET, &error); /* Rewind */
}

void
status_events_reset (void)
{
	counter_events_in = 0;
	counter_serious_events_in = 0;
	counter_events_out = 0;
	counter_serious_events_out = 0;
	gtk_label_set_text (GTK_LABEL (events_in), "0");
	gtk_label_set_text (GTK_LABEL (events_serious_in), "0");
	gtk_label_set_text (GTK_LABEL (events_out), "0");
	gtk_label_set_text (GTK_LABEL (events_serious_out), "0");
}

void
status_event_in_inc (void)
{
	counter_events_in++;
	gchar *label = g_strdup_printf ("%d", counter_events_in);

	gtk_label_set_text (GTK_LABEL (events_in), label);
	g_free (label);
}

void
status_serious_event_in_inc (void)
{
	counter_serious_events_in++;
	gchar *label = g_strdup_printf ("%d", counter_serious_events_in);

	gtk_label_set_text (GTK_LABEL (events_serious_in), label);
	g_free (label);
}

void
status_event_out_inc (void)
{
	counter_events_out++;
	gchar *label = g_strdup_printf ("%d", counter_events_out);

	gtk_label_set_text (GTK_LABEL (events_out), label);
	g_free (label);
}

void
status_serious_event_out_inc (void)
{
	counter_serious_events_out++;
	gchar *label = g_strdup_printf ("%d", counter_serious_events_out);

	gtk_label_set_text (GTK_LABEL (events_serious_out), label);
	g_free (label);
}

/* [ status_set_fw_state ]
 * Update the state of the firewall
 */
static void
update_state_widgets (FirewallStatus state)
{
	GdkPixbuf *pixbuf;
	const guint8 *icon;
	gchar *label;

	switch (state) {
	  case STATUS_RUNNING: icon = icon_start_large;
	                       label = g_strdup (_("Active")); break;
	  case STATUS_STOPPED: icon = icon_stop_large;
	                       label = g_strdup (_("Disabled")); break;
	  case STATUS_LOCKED:  icon = icon_locked_large;
	                       label = g_strdup (_("Locked")); break;
	  case STATUS_HIT: return; // Don't change icon on hit
	  default: icon = icon_start_large;
	                  label = g_strdup (""); break;
	}

 	pixbuf = gdk_pixbuf_new_from_inline (-1, icon, FALSE, NULL);
	gtk_image_set_from_pixbuf (GTK_IMAGE (fw_state_icon), pixbuf);
	g_object_unref (G_OBJECT(pixbuf));

	gtk_label_set_markup (GTK_LABEL (fw_state_label), g_strconcat (
		"<small>", label, "</small>", NULL));


}

FirewallStatus
status_get_state (void)
{
	return current_status;
}

void
status_set_state (FirewallStatus status)
{
	if (gui_get_active_view () == STATUS_VIEW)
		menus_update_firewall_controls_state (status);

	tray_update (status);
	update_state_widgets (status);

	current_status = status;
}

/* [ status_sync_timeout ]
 * Correct the GUI state in case outside factors change the firewall state
 */
gint
status_sync_timeout (gpointer data)
{
	FirewallStatus state = status_get_state ();

	if (state == STATUS_HIT)
		return TRUE;

	if (fortified_is_locked ()) {
		if (state != STATUS_LOCKED)
			status_set_state (STATUS_RUNNING);
	} else if (state == STATUS_LOCKED)
		status_set_state (STATUS_LOCKED);
	else
		status_set_state (STATUS_STOPPED);

	return TRUE;
}

/* [ refresh_network_data ]
 * Refresh all available data for all the network interfaces in the machine
 */
static void
refresh_network_data (GHashTable *interfaces)
{
	gint line_num = 0;
	gchar *line;
	static GIOChannel *in = NULL;
	GError *error = NULL;
	gchar *str;
	gchar *interface;
	Interface_info *info = NULL;

	if (in == NULL) {
		in = g_io_channel_new_file (DEV_FILE, "r", &error);

		if (in == NULL) {
			printf ("Error reading %s: %s\n", DEV_FILE, error->message);
			return;
		}
	}

	while (TRUE) {
		unsigned long int values[16];
		
		g_io_channel_read_line (in, &line, NULL, NULL, &error);

		if (line == NULL) // EOF reached
			break;
		line_num++;
		if (line_num <= 2) { // Skip dev headers
			g_free (line);
			continue;
		}

		interface = g_strstrip(g_strndup (line, 6)); /* Extract interface */

		/* Interface blacklist */
		if (g_str_equal (interface, "lo")) {
			g_free (line);
			continue;
		}

		info = g_hash_table_lookup (interfaces, interface); /* Retrieve info for updating */
		if (info == NULL) { /* Initialize new interface info structure */
			gint i;
			info = g_new0 (Interface_info, 1);

			/* Initialize interface traffic history, for counting average activity */
			info->traffic_history = (float*)malloc (HISTORY_LENGTH * sizeof (float));
			info->history_index = 0;
			for (i = 0; i < HISTORY_LENGTH; i++)
				info->traffic_history[i] = 0.0;
			info->previous_total = 0;

			g_hash_table_insert (interfaces, g_strdup (interface), info);
		}
		g_free (interface);
			
		str = line+7; // Continue parsing after interface

		/* values array:
		recieve:  0 bytes 1 packets 2 errs 3 drop 4 fifo 5 frame 6 compressed 7 multicast
		transmit: 8 bytes 9 packets 10 errs 11 drop 12 fifo 13 colls 14 carrier 15 compressed */
		sscanf(str,
			"%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
			&values[0], &values[1], &values[2], &values[3], &values[4],
			&values[5], &values[6], &values[7], &values[8], &values[9],
			&values[10], &values[11], &values[12], &values[13], &values[14],
			&values[15]);

		info->received = values[0];
		info->sent = values[8];

		g_free (line);
	}

	g_io_channel_seek_position (in, 0, G_SEEK_SET, &error); // Rewind
}

/* [ refresh_traffic_average ]
 * Recalculate the average traffic for a network interface
 */
static void
refresh_traffic_average (gint seconds, Interface_info *info)
{
	float current = info->received + info->sent;
	float last = info->previous_total;
	float difference = current - last;
	float average = 0.0;
	gint i;

	if (last == 0) {
		info->previous_total = current;
		return;
	}

	difference /= seconds;

	/* Update the history */
	info->traffic_history[info->history_index++] = difference;
	if (info->history_index == HISTORY_LENGTH)
		info->history_index = 0;

	/* Calculate the average */
	for (i = 0; i < HISTORY_LENGTH; i++) {
		average += info->traffic_history[i];
	}
	average /= HISTORY_LENGTH;

	/* Store current total for next refresh */
	info->previous_total = current;

	info->average = average;
}

/* [ refresh_interface_widgets ]
 * Update the onscreen widgets for a particular network interface
 */
static void
refresh_interface_widgets (gchar *interface, Interface_info *info, GHashTable *all_widgets)
{
	Interface_widgets *widgets;
	gchar *received, *sent, *activity;

	widgets = g_hash_table_lookup (all_widgets, interface);
	if (widgets == NULL) {
		gint row = g_hash_table_size (all_widgets)+1;
		gchar *type;
		gchar *ext_if, *int_if;
		
		ext_if = preferences_get_string (PREFS_FW_EXT_IF);
		int_if = preferences_get_string (PREFS_FW_INT_IF);

		if (ext_if != NULL && g_str_equal (interface, ext_if))
			type = g_strdup (_("Internet"));
		else if (preferences_get_bool (PREFS_FW_NAT) && int_if != NULL &&
		         g_str_equal (interface, int_if))
			type = g_strdup (_("Local"));
		else
			type = get_pretty_device_name (interface, FALSE);

		if (ext_if != NULL)
			g_free (ext_if);
		if (int_if != NULL)
			g_free (int_if);

		widgets = g_new (Interface_widgets, 1);

		widgets->device = gtk_label_new (NULL);
		gtk_label_set_markup (GTK_LABEL (widgets->device),
			g_strconcat ("<span size=\"smaller\">", interface ,"</span>", NULL));
		gtk_misc_set_alignment (GTK_MISC (widgets->device), 1.0, 0.0);

		widgets->type = gtk_label_new (NULL);
		gtk_label_set_markup (GTK_LABEL (widgets->type),
			g_strconcat ("<span size=\"smaller\">", type ,"</span>", NULL));
		gtk_misc_set_alignment (GTK_MISC (widgets->type), 1.0, 0.0);

		widgets->received = gtk_label_new ("-");
		gtk_misc_set_alignment (GTK_MISC (widgets->received), 1.0, 0.0);

		widgets->sent = gtk_label_new ("-");
		gtk_misc_set_alignment (GTK_MISC (widgets->sent), 1.0, 0.0);

		widgets->activity = gtk_label_new ("-");
		gtk_misc_set_alignment (GTK_MISC (widgets->activity), 1.0, 0.0);

		g_hash_table_insert (all_widgets, g_strdup (interface), widgets);

		gtk_table_attach (GTK_TABLE (device_table), widgets->device, 0, 1, row, row+1,
			GTK_FILL, GTK_FILL, GNOME_PAD, 2);	
		gtk_table_attach (GTK_TABLE (device_table), widgets->type, 1, 2, row, row+1,
			GTK_FILL, GTK_FILL, GNOME_PAD, 2);	
		gtk_table_attach (GTK_TABLE (device_table), widgets->received, 2, 3, row, row+1,
			GTK_FILL, GTK_FILL, GNOME_PAD, 2);	
		gtk_table_attach (GTK_TABLE (device_table), widgets->sent, 3, 4, row, row+1,
			GTK_FILL, GTK_FILL, GNOME_PAD, 2);	
		gtk_table_attach (GTK_TABLE (device_table), widgets->activity, 4, 5, row, row+1,
			GTK_FILL, GTK_FILL, GNOME_PAD, 2);
			
		gtk_widget_show_all (device_table);
	}

	received = g_strdup_printf ("<span size=\"smaller\">%.1f MB</span>", (float)(info->received)/1048576);
	sent = g_strdup_printf ("<span size=\"smaller\">%.1f MB</span>", (float)(info->sent)/1048576);
	activity = g_strdup_printf ("<span size=\"smaller\">%.1f KB/s</span>", info->average/1024);
	gtk_label_set_markup (GTK_LABEL (widgets->received), received);
	gtk_label_set_markup (GTK_LABEL (widgets->sent), sent);
	gtk_label_set_markup (GTK_LABEL (widgets->activity), activity);
	g_free (received);
	g_free (sent);
	g_free (activity);
}

static void
refresh_interface (gchar *interface, Interface_info *info, GHashTable *all_widgets)
{
	refresh_traffic_average (REFRESH_RATE, info);
	refresh_interface_widgets (interface, info, all_widgets);
}

/* [ update_conntrack_ttl ]
 * Decrement connection track entries time to live and check it they are ready for removal
 */
static gboolean
update_conntrack_ttl (gchar *key, Connection_entry *entry, GHashTable *entries)
{
	GtkListStore *store = get_connectionstore ();

	entry->ttl--;
	if (entry->ttl == 0) { /* Remove dead connections */
		gtk_list_store_remove (store, entry->ref);
		return TRUE;
	} else {
		if (entry->ttl < CONNTRACK_TTL-1) {
			/* Mark connections not seen for a while */
			gtk_list_store_set (store, entry->ref,
		        	            CONNECTIONCOL_COLOR, COLOR_RETIRED_CONNECTION,
					    -1);
		}
	}
	return FALSE;
}

static void
free_connection_entry (gpointer data)
{
	Connection_entry *entry = (Connection_entry *)data;
	
	g_free (entry->ref);
	g_free (data);
}

/* [ update_status_screen ]
 * Timeout callback for refreshing the status view page periodically
 */
static gboolean
update_status_screen (gpointer data)
{
	static GHashTable *interfaces_info = NULL;
	static GHashTable *interfaces_widgets = NULL;
	static GHashTable *conntrack_entries = NULL;

	if (interfaces_info == NULL)
		interfaces_info = g_hash_table_new (g_str_hash, g_str_equal);
	if (interfaces_widgets == NULL)
		interfaces_widgets = g_hash_table_new (g_str_hash, g_str_equal);
	if (conntrack_entries == NULL)
		conntrack_entries = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, free_connection_entry);

	refresh_network_data (interfaces_info);
	g_hash_table_foreach (interfaces_info, (GHFunc)refresh_interface, interfaces_widgets);
	g_hash_table_foreach_remove (conntrack_entries, (GHRFunc)update_conntrack_ttl, conntrack_entries);

	if (active_connections_visible)
		connectionview_refresh (conntrack_entries);

	return TRUE;
}

static void
view_set_color_col (GtkTreeView *view, gint col_num)
{
	GList* renderers;
	GList *columns;
	GtkCellRenderer *renderer;
	GList *e;

	columns = gtk_tree_view_get_columns (view);
	for (e = columns; e != NULL; e = g_list_next(e)) {
		GtkTreeViewColumn* column = e->data;

		renderers = gtk_tree_view_column_get_cell_renderers (column);
		renderer = g_list_nth_data (renderers, 0);
		gtk_tree_view_column_add_attribute (column, renderer, "foreground", CONNECTIONCOL_COLOR);
		g_list_free (renderers);
	}
	g_list_free (columns);
}

void
status_lookup_selected_connection (void)
{
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	GtkListStore *store = get_connectionstore ();
	gchar *source, *destination, *hostname;

	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (connectionview));

	if (!gtk_tree_selection_get_selected (selection, NULL, &iter))
		return;

	gtk_tree_model_get (GTK_TREE_MODEL (store), &iter,
	                    CONNECTIONCOL_SOURCE, &source,
			    CONNECTIONCOL_DESTINATION, &destination,
			    -1);

	hostname = lookup_ip (source);
	if (hostname != NULL)
		gtk_list_store_set (store, &iter,
	        	            CONNECTIONCOL_SOURCE, hostname,
	         	           -1);
	hostname = lookup_ip (destination);
	if (hostname != NULL)
		gtk_list_store_set (store, &iter,
	        	            CONNECTIONCOL_DESTINATION, hostname,
	         	           -1);

	gtk_tree_view_columns_autosize (GTK_TREE_VIEW (connectionview));
	g_free (source);
	g_free (destination);
}

static gboolean
connectionview_has_selection (GtkTreeView *view)
{
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	gboolean has_selection;

	selection = gtk_tree_view_get_selection (view);
	has_selection = gtk_tree_selection_get_selected (selection, NULL, &iter);

	return has_selection;
}

static gboolean
connectionview_button_press_cb (GtkWidget* view, GdkEventButton* event)
{
	gboolean retval = FALSE;
	GtkWidget *menu;

	if (!connectionview_has_selection (GTK_TREE_VIEW (view)))
		return FALSE;

	menu = menus_get_connections_context_menu ();

	switch (event->button) {
		case 1: break;
		case 3: gtk_menu_popup (GTK_MENU (menu), NULL, NULL, NULL, NULL,
		                        event->button, event->time);
			retval = TRUE;
			break;
	}

	return retval;
}

static void
expander_cb (GObject *object, GParamSpec *param_spec, gpointer user_data)
{
	GtkExpander *expander;
	GtkWidget *contents;

	expander = GTK_EXPANDER (object);
	contents = GTK_WIDGET (user_data);

	if (gtk_expander_get_expanded (expander)) {
		gtk_widget_show (contents);
		active_connections_visible = TRUE;
	} else { /* Reclaim vertical space on expander collapse */
		gint width;

		gtk_window_get_size (GTK_WINDOW (Fortified.window), &width, NULL);
		gtk_widget_hide (contents);
		gtk_window_resize (GTK_WINDOW (Fortified.window), width, 1);
		active_connections_visible = FALSE;
	}
}

/* [ create_hitview_page ]
 * Create the hitview
 */
GtkWidget *
create_statusview_page (void)
{
	GtkWidget *statuspagebox;
	GtkWidget *scrolledwin;
	GtkWidget *frame;
	GtkWidget *label;
	GtkWidget *table;
	GtkWidget *table2;
	GdkPixbuf *pixbuf;
	GtkWidget *separator;
	GtkWidget *expander;

	View_def connectionview_def = {6, {
			{_("Source"), G_TYPE_STRING, TRUE},
			{_("Destination"), G_TYPE_STRING, TRUE},
			{_("Port"), G_TYPE_STRING, TRUE},
			{_("Service"), G_TYPE_STRING, TRUE},
			{_("Program"), G_TYPE_STRING, TRUE},
			{_("Color"), G_TYPE_STRING, FALSE},
		}
	};

	statuspagebox = gtk_vbox_new (FALSE, 0);

/* Firewall */
	frame = gtk_frame_new (NULL);
	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<b>", _("Firewall"), "</b>", NULL));
	gtk_frame_set_label_widget (GTK_FRAME (frame), label);
	gtk_frame_set_shadow_type (GTK_FRAME (frame), GTK_SHADOW_NONE);
	gtk_box_pack_start (GTK_BOX (statuspagebox), frame, FALSE, FALSE, GNOME_PAD_SMALL);

	table = gtk_table_new (3, 3, FALSE);
	gtk_table_set_row_spacings (GTK_TABLE(table), GNOME_PAD_SMALL);
	gtk_table_set_col_spacings (GTK_TABLE(table), GNOME_PAD_SMALL);
	gtk_container_add (GTK_CONTAINER (frame), table);

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<span size=\"smaller\" weight=\"bold\">", _("Status"), "</span>", NULL));
	gtk_table_attach (GTK_TABLE (table), label, 0, 1, 0, 1,
		GTK_FILL, GTK_FILL, GNOME_PAD, 5);

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<span size=\"smaller\" weight=\"bold\">", _("Events"), "</span>", NULL));
	gtk_table_attach (GTK_TABLE (table), label, 1, 2, 0, 1,
		GTK_FILL, GTK_FILL, GNOME_PAD, 5);

	table2 = gtk_table_new (3, 3, FALSE);
	gtk_table_set_row_spacings (GTK_TABLE(table), GNOME_PAD_SMALL);
	gtk_table_set_col_spacings (GTK_TABLE(table), GNOME_PAD_SMALL);
	gtk_table_attach (GTK_TABLE (table), table2, 1, 2, 1, 3,
		GTK_FILL, GTK_FILL, GNOME_PAD, 5);

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<span size=\"smaller\" underline=\"single\">", _("Total"), "</span>", NULL));
	gtk_table_attach (GTK_TABLE (table2), label, 1, 2, 0, 1,
		GTK_FILL, GTK_FILL, GNOME_PAD, 5);

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<span size=\"smaller\" underline=\"single\">", _("Serious"), "</span>", NULL));
	gtk_table_attach (GTK_TABLE (table2), label, 2, 3, 0, 1,
		GTK_FILL, GTK_FILL, GNOME_PAD, 5);

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<span size=\"smaller\">", _("Inbound"), "</span>", NULL));
	gtk_misc_set_alignment (GTK_MISC (label), 1.0, 0.0);
	gtk_table_attach (GTK_TABLE (table2), label, 0, 1, 1, 2,
		GTK_FILL, GTK_FILL, GNOME_PAD, 5);

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<span size=\"smaller\">", _("Outbound"), "</span>", NULL));
	gtk_table_attach (GTK_TABLE (table2), label, 0, 1, 2, 3,
		GTK_FILL, GTK_FILL, GNOME_PAD, 5);


	events_in = gtk_label_new ("0");
	gtk_table_attach (GTK_TABLE (table2), events_in, 1, 2, 1, 2,
		GTK_FILL, GTK_FILL, GNOME_PAD, 5);

	events_out = gtk_label_new ("0");
	gtk_table_attach (GTK_TABLE (table2), events_out, 1, 2, 2, 3,
		GTK_FILL, GTK_FILL, GNOME_PAD, 5);


	events_serious_in = gtk_label_new ("0");
	gtk_table_attach (GTK_TABLE (table2), events_serious_in, 2, 3, 1, 2,
		GTK_FILL, GTK_FILL, GNOME_PAD, 5);

	events_serious_out = gtk_label_new ("0");
	gtk_table_attach (GTK_TABLE (table2), events_serious_out, 2, 3, 2, 3,
		GTK_FILL, GTK_FILL, GNOME_PAD, 5);



 	pixbuf = gdk_pixbuf_new_from_inline (-1, icon_start_large, FALSE, NULL);
	fw_state_icon = gtk_image_new_from_pixbuf (pixbuf);
	g_object_unref (G_OBJECT(pixbuf));
	gtk_table_attach (GTK_TABLE (table), fw_state_icon, 0, 1, 1, 2,
		GTK_FILL, GTK_FILL, GNOME_PAD, 0);


	fw_state_label = gtk_label_new (NULL);
	/* Force a size so that the different label lengths don't shift the other content */
	gtk_widget_set_size_request (fw_state_label, 70, -1);
	gtk_label_set_markup (GTK_LABEL (fw_state_label), g_strconcat (
		"<small>", _("Active"), "</small>", NULL));
	gtk_table_attach (GTK_TABLE (table), fw_state_label, 0, 1, 2, 3,
		GTK_FILL, GTK_FILL, GNOME_PAD, 0);	

	separator = gtk_hseparator_new ();
	gtk_box_pack_start (GTK_BOX (statuspagebox), separator, FALSE, FALSE, 10);


/* Network */
	frame = gtk_frame_new (NULL);
	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<b>", _("Network"), "</b>", NULL));
	gtk_frame_set_label_widget (GTK_FRAME (frame), label);
	gtk_frame_set_shadow_type (GTK_FRAME (frame), GTK_SHADOW_NONE);
	gtk_box_pack_start (GTK_BOX (statuspagebox), frame, FALSE, FALSE, 0);

	device_table = gtk_table_new (5, 10, FALSE);
	gtk_table_set_row_spacings (GTK_TABLE(device_table), GNOME_PAD_SMALL);
	gtk_table_set_col_spacings (GTK_TABLE(device_table), GNOME_PAD_SMALL);
	gtk_container_add (GTK_CONTAINER (frame), device_table);

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<span size=\"smaller\" underline=\"single\">", _("Device"), "</span>", NULL));
	gtk_table_attach (GTK_TABLE (device_table), label, 0, 1, 0, 1,
		GTK_FILL, GTK_FILL, GNOME_PAD, 5);	

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<span size=\"smaller\" underline=\"single\">", _("Type"), "</span>", NULL));
	gtk_table_attach (GTK_TABLE (device_table), label, 1, 2, 0, 1,
		GTK_FILL, GTK_FILL, GNOME_PAD, 5);

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<span size=\"smaller\" underline=\"single\">", _("Received"), "</span>", NULL));
	gtk_table_attach (GTK_TABLE (device_table), label, 2, 3, 0, 1,
		GTK_FILL, GTK_FILL, GNOME_PAD, 5);	

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<span size=\"smaller\" underline=\"single\">", _("Sent"), "</span>", NULL));
	gtk_table_attach (GTK_TABLE (device_table), label, 3, 4, 0, 1,
		GTK_FILL, GTK_FILL, GNOME_PAD, 5);	

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<span size=\"smaller\" underline=\"single\">", _("Activity"), "</span>", NULL));
	gtk_table_attach (GTK_TABLE (device_table), label, 4, 5, 0, 1,
		GTK_FILL, GTK_FILL, GNOME_PAD, 5);	

	expander = gtk_expander_new (NULL);
	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<b>", _("Active connections"), "</b>", NULL));
	gtk_expander_set_label_widget (GTK_EXPANDER (expander), label);
	gtk_expander_set_spacing (GTK_EXPANDER (expander), 5);
	gtk_box_pack_start (GTK_BOX (statuspagebox), expander, FALSE, FALSE, 10);

/* Active Connections */	
	connectionview = gui_create_list_view (&connectionview_def, -1, 150);
	g_signal_connect (G_OBJECT (connectionview), "button_press_event",
	                  G_CALLBACK (connectionview_button_press_cb), NULL);
	view_set_color_col (GTK_TREE_VIEW (connectionview), CONNECTIONCOL_COLOR);

	gtk_tree_view_set_rules_hint (GTK_TREE_VIEW (connectionview), TRUE);

	scrolledwin = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolledwin),
	                                GTK_POLICY_NEVER,
	                                GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scrolledwin), GTK_SHADOW_IN);

	g_signal_connect (G_OBJECT (expander), "notify::expanded",
	                  G_CALLBACK (expander_cb), scrolledwin);
	gtk_expander_set_expanded (GTK_EXPANDER (expander), FALSE);
						
	gtk_box_pack_start (GTK_BOX (statuspagebox), scrolledwin, TRUE, TRUE, 1);
	gtk_widget_show (connectionview);
	gtk_widget_set_no_show_all (scrolledwin, TRUE);

	/* Pack the treeview into the scrolled window  */
	gtk_container_add (GTK_CONTAINER (scrolledwin), connectionview);

	gtk_timeout_add (REFRESH_RATE*1000, update_status_screen, NULL);

	gtk_widget_show_all (statuspagebox);

	return statuspagebox;
}
