/*---[ logread.c ]----------------------------------------------------
 * Copyright (C) 2000-2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Functions for reading from the syslog file
 *--------------------------------------------------------------------*/

#include <config.h>
#include <gnome.h>
#include <netdb.h>

#include "globals.h"
#include "logread.h"
#include "util.h"
#include "hitview.h"
#include "statusview.h"
#include "service.h"

static gboolean BUSY = FALSE;

/* [ gvfs_seek_callback ]
 * Zero the buffer and read again
 */
static void
gvfs_seek_callback (GnomeVFSAsyncHandle *handle, GnomeVFSResult result, gpointer data)
{
	Parse *info = data;
	if (result != GNOME_VFS_OK) {
		g_warning ("Seek error");
	}

	memset (info->buffer, 0, FILE_BUF);
	gnome_vfs_async_read (handle, info->buffer, FILE_BUF, logread_async_read_callback, info);
}

static void
gvfs_seek_end_callback (GnomeVFSAsyncHandle *handle, GnomeVFSResult result, gpointer data)
{
	if (result != GNOME_VFS_OK)
		g_warning ("Seek end error");
}

/* [ logread_async_read_callback ]
 * Read file parsing for iptables pattern, add to hitview on match
 */
void
logread_async_read_callback (GnomeVFSAsyncHandle *handle, GnomeVFSResult result, gpointer buffer,
                             GnomeVFSFileSize bytes_requested, GnomeVFSFileSize bytes_read, gpointer data)
{
	gchar **lines = NULL;
	Parse *info = data;
	Hit *h;
	int i = 0;
	
	if (g_str_has_suffix (info->buffer,"\n"))
		info->half_line=0;
	else 
		info->half_line=1;

	if (result == GNOME_VFS_OK && bytes_read > 0) {
	/* split line into (gchar **) and check for pattern */
		lines = g_strsplit_set (info->buffer, "\n",-1);
		while (*(lines+(i+info->half_line)) && (*lines+i != NULL)) {
			if (g_pattern_match_string (info->pattern,*(lines+i) )) {
				h = parse_log_line (*(lines+i));

				if (hitview_append_hit (h) && !hitview_reload_in_progress ())
					status_set_state (STATUS_HIT);
				free_hit (h);
			}
			i++;
		}
		/* end of file or error */
		if (bytes_requested != bytes_read) {
			if (info->continuous) {
				memset (info->buffer, 0, FILE_BUF); /* fill buffer with zeros, next line might be half line */
				BUSY = FALSE;
			} else
				gnome_vfs_async_close (handle, hitview_abort_reload_callback, info);
		} else if ((info->half_line) == 1 && (i > 1)) { /* if last line was half line seek back */
			int len=strlen (*(lines+i));
			gnome_vfs_async_seek (handle,GNOME_VFS_SEEK_CURRENT, -len,
			                      gvfs_seek_callback, info);

		} else {
			memset (info->buffer, 0, FILE_BUF); /* fill buffer with zeros, next line might be half line */
			info->bytes_read += bytes_read;
			gnome_vfs_async_read (handle, info->buffer, FILE_BUF, logread_async_read_callback, info);
		}
	} else {
		if (info->continuous) {
			memset (info->buffer, 0, FILE_BUF); /* fill buffer with zeros, next line might be half line */
			BUSY = FALSE;
		} else {
			gnome_vfs_async_close (handle, hitview_abort_reload_callback, info);
		}


	}

	if (lines)
		g_strfreev (lines);
}

/* [ poll_log_timeout ]
 * Polls the logfile every 500ms for change, if change, parse lines
 */
static int
poll_log_timeout (gpointer data)
{
	Parse *info = data;

	if (BUSY == FALSE) { /* start reading only when previous read has finished */
		BUSY = TRUE;
		gnome_vfs_async_read (info->handle, info->buffer, FILE_BUF, logread_async_read_callback, info);
	}	
	return TRUE; /* TRUE means we want to keep calling the function */
}

static void
gvfs_open_callback (GnomeVFSAsyncHandle *handle, GnomeVFSResult result, gpointer data)
{
	Parse *info;
	
	if (result != GNOME_VFS_OK) {
		g_warning ("Log file not found or access denied.\n"
		           "Firewall log monitoring disabled.");
	} else {
		info = g_new (Parse, 1);
		info->buffer = g_new (gchar, FILE_BUF+1);
		info->pattern = g_pattern_spec_new ("* IN=* OUT=* SRC=* ");
		info->handle = handle;
		info->continuous = TRUE;
		/* seek to the end of file and add a timeout */
		gnome_vfs_async_seek (handle, GNOME_VFS_SEEK_END, 0, gvfs_seek_end_callback, info);
		g_timeout_add (500, poll_log_timeout, info);
	}
}

Hit *
parse_log_line (gchar *line)
{
	struct protoent *protocol;
	Hit *h;
	gchar *type = NULL; // ICMP service type, not part of hit model

	h = g_new0 (Hit, 1);

	/* Take 15 first characters as timestamp */
	h->time = g_strndup (line, 15);

	h->direction = g_strstrip (get_text_between (line, "kernel:", "IN"));
	h->in = get_text_between (line, "IN=", " ");
	h->out = get_text_between (line, "OUT=", " ");
	h->source = get_text_between (line, "SRC=", " ");
	h->destination = get_text_between (line, "DST=", " ");
	h->length = get_text_between (line, "LEN=", " ");
	h->tos = get_text_between (line, "TOS=", " ");
	h->protocol = get_text_between (line, "PROTO=", " ");
	type = get_text_between (line, "TYPE=", " ");
	h->port = get_text_between (line, "DPT=", " ");

	/* If the protocol is a number we do a protocol name lookup */
	if (h->protocol != NULL)
		if (g_ascii_isdigit(h->protocol[0])) {
			protocol = getprotobynumber (atoi (h->protocol));
			if (protocol != NULL) {
				g_free (h->protocol);
				h->protocol = g_utf8_strup (protocol->p_name, -1);
			}
		}

	/* Determine service used based on the port and protocol */
	if (type != "" && strcmp (h->protocol, "icmp") == 0) {
		h->service = service_get_icmp_name (atoi (type));
	} else if (h->port != NULL && h->protocol != NULL)
		h->service = service_get_name (atoi (h->port), g_strdup (h->protocol));

	g_free (type);
	return h;
}

/* [ open_logfile ]
 * Open the system log and attach a reader function with a timeout
 */
void
open_logfile (char *logpath) {
	GnomeVFSAsyncHandle *handle;

	gnome_vfs_async_open(&handle, logpath, GNOME_VFS_OPEN_READ, GNOME_VFS_PRIORITY_DEFAULT,
	                     gvfs_open_callback, NULL);
}
