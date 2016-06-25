/*---[ util.c ]-------------------------------------------------------
 * Copyright (C) 2000-2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Functions that don't logically belong to any other module but still
 * need to be widely accessible
 *--------------------------------------------------------------------*/

#include <sys/stat.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <libgnomevfs/gnome-vfs-mime-handlers.h>

#include "globals.h"
#include "fortified.h"
#include "util.h"
#include "hitview.h"
#include "preferences.h"

extern int h_errno;

static void
error_dialog_response (GtkDialog *dialog,
                       gint response_id,
                       gpointer data)
{
	gtk_widget_destroy (GTK_WIDGET (dialog));
}

/* [ error_dialog ]
 * Run a dialog with an specified error message
 */
void
error_dialog (const gchar *title, const gchar *header, const gchar *message, GtkWidget *parent)
{
	GtkWidget *dialog;
	GtkWidget *hbox;
	GtkWidget *label;
	GdkPixbuf *pixbuf;
	GtkWidget *icon;
	GtkWindow *window = NULL;
	const gchar *text;	

	if (Fortified.window != NULL)
		window = GTK_WINDOW (Fortified.window);

	dialog = gtk_dialog_new_with_buttons (
		title,
		GTK_WINDOW (parent),
		GTK_DIALOG_DESTROY_WITH_PARENT | GTK_DIALOG_NO_SEPARATOR,
		GTK_STOCK_OK,
		GTK_RESPONSE_ACCEPT,
		NULL
	);
	gtk_container_set_border_width (GTK_CONTAINER (dialog), 6);

	/* If the main window is displayed we don't block and need a destroyer cb */
	if (window != NULL)
		g_signal_connect (G_OBJECT (dialog), "response",
		                  G_CALLBACK (error_dialog_response), NULL);

	hbox = gtk_hbox_new (FALSE, 12);
	gtk_container_set_border_width (GTK_CONTAINER (hbox), 6);
	gtk_box_pack_start (GTK_BOX (GTK_DIALOG (dialog)->vbox), hbox, FALSE, FALSE, 0);

	pixbuf = gtk_widget_render_icon (dialog, GTK_STOCK_DIALOG_ERROR, GTK_ICON_SIZE_DIALOG, NULL);
	icon = gtk_image_new_from_pixbuf (pixbuf);
	g_object_unref (G_OBJECT(pixbuf));	
	gtk_misc_set_alignment (GTK_MISC (icon), 0.0, 0.0);
	gtk_box_pack_start (GTK_BOX (hbox), icon, FALSE, FALSE, 0);

	if (header != NULL)
		text = g_strconcat ("<span weight=\"bold\" size=\"larger\">",
		                    header,
		                    "</span>\n\n",
		                    message, "\n", NULL);
	else
		text = message;

	label = gtk_label_new (text);
	gtk_label_set_use_markup (GTK_LABEL (label), TRUE);
	gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
	gtk_box_pack_start (GTK_BOX (hbox), label, FALSE, FALSE, 0);

	gtk_widget_show_all (dialog);

	/* If the main window is not displayed we need an new event loop */
	if (window == NULL)
		gtk_dialog_run (GTK_DIALOG (dialog));
}

/* [ show_error ]
 * Report that a error has occured to the user, either in GUI or on stderr
 */
void
show_error (gchar *message)
{
	if (CONSOLE)
		fprintf (stderr, "%s\n", message);
	else
		error_dialog (_("Fortified error"), NULL, message, Fortified.window);
}

/* [ get_system_log_path ]
 * Get the correct path to the system log, which may vary with distributions
 */
const gchar *
get_system_log_path (void)
{
	static gchar *path = NULL;

	if (path == NULL) {
		/* User has specified the log file location */
		path = preferences_get_string (PREFS_SYSLOG_FILE);

		if (path && g_file_test (path, G_FILE_TEST_EXISTS)) {
			return path;
		} else { /* Try to guess some default syslog location */
			if (g_file_test ("/var/log/messages", G_FILE_TEST_EXISTS))
				path = g_strdup ("/var/log/messages");
			else if (g_file_test ("/var/log/kernel", G_FILE_TEST_EXISTS))
				path = g_strdup ("/var/log/kernel");
			else
				path = NULL;
		}
		
		if (path == NULL) {
			show_error (g_strconcat (
				"<span weight=\"bold\" size=\"larger\">",
				_("Failed to open the system log\n\n"),
				"</span>",
				_("No event information will be available."),
				NULL));
		}
	}
	return path;
}

void
print_hit (Hit *h)
{
	printf ("HIT: %s from %s to %s:%s, protocol %s, service %s\n",
		h->time,
		h->source,
		h->destination,
		h->port,
		h->protocol,
		h->service);
}

Hit *
copy_hit (Hit *h)
{
	Hit *new = g_new (Hit, 1);
	
	new->time = g_strdup (h->time);
	new->direction = g_strdup (h->direction);
	new->in =  g_strdup (h->in);
	new->out = g_strdup (h->out);
	new->port = g_strdup (h->port);
	new->source = g_strdup (h->source);
	new->destination = g_strdup (h->destination);
	new->length = g_strdup (h->length);
	new->tos = g_strdup (h->tos);
	new->protocol = g_strdup (h->protocol);
	new->service = g_strdup (h->service);

	return new;
}

/* [ get_ip_of_interface ]
 * Get the IP address in use by an interface
 */
gchar*
get_ip_of_interface (gchar *itf) {
	int fd;	
	struct ifreq ifreq;
	struct sockaddr_in *sin;
	gchar *ip;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(ifreq.ifr_name, itf);
	ioctl(fd, SIOCGIFADDR, &ifreq);
	sin = (struct sockaddr_in *)&ifreq.ifr_broadaddr;

	ip = g_strdup(inet_ntoa(sin->sin_addr));

	close (fd);
	return ip;
}

/* [ get_subnet_of_interface ]
 * Get the subnet-mask used by an interface
 */
gchar*
get_subnet_of_interface (gchar *itf) {
	int fd;	
	struct ifreq ifreq;
	struct sockaddr_in *sin;
	gchar *subnet;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(ifreq.ifr_name, itf);
	ioctl(fd, SIOCGIFNETMASK, &ifreq);
	sin = (struct sockaddr_in *)&ifreq.ifr_broadaddr;

	subnet = g_strdup(inet_ntoa(sin->sin_addr));
	
	return subnet;
}

GtkTreeModel*
get_devices_model (void)
{
	static GtkTreeModel *model = NULL;
	GIOChannel *in;
	GError *error = NULL;

	if (model != NULL)
		return model;

	model = (GtkTreeModel *)gtk_list_store_new (2,
		G_TYPE_STRING, G_TYPE_STRING);

	in = g_io_channel_new_file ("/proc/net/dev", "r", &error);
	if (in == NULL) {
		gchar *error_message = g_strconcat (
			_("Failed to open /proc/net/dev for reading: "),
			error->message, NULL);
		show_error (error_message);
		g_free (error_message);
		return NULL;
	} else {
		gchar *line, *interface;
	
		while (g_io_channel_read_line (in, &line, NULL, NULL, &error) == G_IO_STATUS_NORMAL) {
			if (index (line, ':')) {
				GtkTreeIter iter;

				interface = g_strndup (line, index (line, ':')-line);
				interface = g_strstrip (interface);
				if (g_str_equal (interface, "lo")) { /* Skip local loopback interface */
					g_free (interface);
					continue;
				}
				gtk_list_store_append (GTK_LIST_STORE (model), &iter);
				gtk_list_store_set (GTK_LIST_STORE (model), &iter,
				                    0, get_pretty_device_name (interface, TRUE),
			                            1, interface,
				                    -1);
				g_free (interface);
			}
	
			g_free (line);
		}
		g_io_channel_shutdown (in, TRUE, NULL);
	}

	return model;
}

gchar *
get_pretty_device_name (gchar *interface, gboolean long_form)
{
	gchar *name;

	if (g_str_has_prefix (interface, "eth"))
		if (long_form)
			name = g_strdup (_("Ethernet device"));
		else
			name = g_strdup (_("Ethernet"));
	else if (g_str_has_prefix (interface, "ppp"))
		if (long_form)
			name = g_strdup (_("Dialup device"));
		else
			name = g_strdup (_("Dialup"));
	else if (g_str_has_prefix (interface, "wlan"))
		if (long_form)
			name = g_strdup (_("Wireless device"));
		else
			name = g_strdup (_("Wireless"));
	else if (g_str_has_prefix (interface, "sit"))
		name = g_strdup (_("IPv6 Tunnel"));
	else if (g_str_has_prefix (interface, "tap"))
		name = g_strdup (_("VPN Tunnel"));
	else if (g_str_has_prefix (interface, "tun"))
		name = g_strdup (_("Routed IP Tunnel"));
	else
		if (long_form)
			name = g_strdup (_("Unknown device"));
		else
			name = g_strdup (_("Unknown"));
	
	if (long_form) {
		gchar *long_name;
		
		long_name = g_strconcat (name, " (", interface, ")", NULL);
		g_free (name);
		return long_name;
	} else
		return name;
	
}

/* [ is_capable_of_nat ]
 * Return true if we can do nat, port forwarding etc.
 */
gboolean
is_capable_of_nat (void)
{
	GtkTreeModel *model;
	model = get_devices_model ();

	return gtk_tree_model_iter_n_children (model, NULL) > 1;
}

/* [ get_text_between ]
 * Give a string and two subtext markers in the string and the function 
 * returns the text between the markers. Note: Return empty string if fail.
 */
gchar *
get_text_between (const gchar *string, gchar *marker1, gchar *marker2)
{
	gint i = strlen (marker1);
	gchar *text = NULL;

	marker1 = strstr (string, marker1);
	if (marker1 != NULL) {
		marker1 += i;
		marker2 = strstr (marker1, marker2);
		if (marker2 != NULL)
			text = g_strndup (marker1, marker2-marker1);

	}

	if (text == NULL)
		text = g_strdup ("");

	return text;
}

/* [ lookup_ip ]
 * Resolve an IP address given in dotted-decimal notation into
 * an hostname or vice versa.
 */
gchar *
lookup_ip (gchar *ip)
{
	struct hostent *hostentry = NULL;
	struct in_addr address;

	if (inet_aton (ip, &address)) {
		hostentry = gethostbyaddr ((char *)&address,
					   sizeof (address), AF_INET);
		if (hostentry != NULL)
			return hostentry->h_name;
		else
			return ip;
	} else {
		hostentry = gethostbyname (ip);
		if (hostentry != NULL) {
			memcpy (&address.s_addr, hostentry ->h_addr, hostentry->h_length);

			return inet_ntoa(address);
		}
		else
			return ip;
	}
}

/* [ is_a_valid_port ]
 * Test that port is a valid number or range
 */
gboolean
is_a_valid_port (const gchar *port)
{
	static GPatternSpec *pattern = NULL;
	gint length, i;

	length = strlen (port);

	/* Only numbers, a dash (range) or a space (delimiter) is allowed */
	for (i = 0; i < length; i++) {
		if (!g_ascii_isdigit (port[i]) &&
		    port[i] != '-' &&
		    port[i] != ' ') {
			return FALSE;
		}
	}

	if (pattern == NULL)
		pattern = g_pattern_spec_new ("*-*");

	if (g_pattern_match_string (pattern, port)) {
		gchar *separator, *start, *end;
		int range_start, range_end;
		
		separator = strstr (port, "-");
		start = g_strndup (port, separator-port);
		end = g_strdup (separator+1);

		range_start = atoi (start);
		range_end = atoi (end);

		g_free (start);
		g_free (end);

		return (range_start >= 1 && range_start <= 65535 &&
			range_end >= 1 && range_end <= 65535);
	} else {
		int port_num;

		port_num = atoi (port);
		return (port_num >= 1 && port_num <= 65535);
	}
}

/* [ is_a_valid_host ]
 * _Very_ loose host string checking
 */
gboolean
is_a_valid_host (const gchar *host)
{
	gint length, i;

	length = strlen (host);
	
	/* Check that the host only contains alphanumerics, dots or slashes */
	for (i = 0; i < length; i++) {
		if (!g_ascii_isalnum (host[i]) &&
		    host[i] != '.' &&
		    host[i] != '/' &&
		    host[i] != '-') {
			return FALSE;
		}
	}

	/* Host name must contain a dot and be over 3 but less than 255 chars long */
	if (length < 3 || length > 255) {
		return FALSE;
	}

	return TRUE;
}

void
free_hit (Hit *h)
{
	if (h == NULL)
		return;

	g_free (h->time);
	g_free (h->direction);
	g_free (h->in);
	g_free (h->out);
	g_free (h->port);
	g_free (h->source);
	g_free (h->destination);
	g_free (h->length);
	g_free (h->tos);
	g_free (h->protocol);
	g_free (h->service);

	g_free (h);
}

/* [ append_to_file ]
 * Append a string to a file
 */
gboolean
append_to_file (gchar *path, gchar *data, gboolean newline)
{
	GIOChannel* out;
	GError *error = NULL;

	out = g_io_channel_new_file (path, "a", &error);

	if (out == NULL) {
		g_printerr ("Error reading file %s: %s\n", path, error->message);
		return FALSE;
	}

	if (g_io_channel_write_chars (out, data, -1, NULL, &error) == G_IO_STATUS_NORMAL) {
		g_io_channel_write_chars (out, "\n", -1, NULL, NULL);
		g_io_channel_shutdown (out, TRUE, &error);
		return TRUE;
	} else {
		g_io_channel_shutdown (out, FALSE, &error);
		return FALSE;
	}
}

/* [ remove_line_from_file ]
 * Remove a single rule from a file
 */
void
remove_line_from_file (gchar *path, gint position)
{
	GIOChannel* io;
	GError *error = NULL;
	gint i;
	gchar *contents = "";
	gchar *tail;

	io = g_io_channel_new_file (path, "r", &error);

	if (io == NULL) {
		g_printerr ("Error reading file %s: %s\n", path, error->message);
		return;
	}

	/* Read contents up until the line to be excised */
	for (i = 0; i < position; i++) {
		gchar *line;
		
		g_io_channel_read_line (io, &line, NULL, NULL, &error);
		contents = g_strconcat (contents, line, NULL);
		g_free (line);
	}
	g_io_channel_read_line (io, &tail, NULL, NULL, &error); /* Skip one line */
	g_free (tail);
	g_io_channel_read_to_end (io, &tail, NULL, &error); /* Read in the rest */
	contents = g_strconcat (contents, tail, NULL);

	g_io_channel_shutdown (io, FALSE, &error);
	io = g_io_channel_new_file (path, "w", &error); /* Write it back out */
	g_io_channel_write_chars (io, contents, -1, NULL, &error);
	g_io_channel_shutdown (io, TRUE, &error);
	g_free (contents);
	g_free (tail);
}

/* [ open_browser ]
 * Open default browser without superuser privileges
 */

void
open_browser (const gchar *str)
{
        const gchar *sudo_user;
        GnomeVFSMimeApplication *app;
        app=gnome_vfs_mime_get_default_application("text/html");
        sudo_user=g_getenv("SUDO_USER");
        if (sudo_user!=NULL)
	{
                g_spawn_command_line_async (g_strjoin(" ","sudo -u",sudo_user,app->command,str, NULL),NULL);
		g_fprintf(stderr,"Doing :%s:\n",g_strjoin(" ","sudo -u",sudo_user,app->command,str, NULL));
	}
        else
                g_spawn_command_line_async (g_strjoin(" ",app->command,str, NULL),NULL);
}
