/*---[ logread.h ]----------------------------------------------------
 * Copyright (C) 2000 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Functions for reading from the syslog file
 *--------------------------------------------------------------------*/

#ifndef _FORTIFIED_LOGREAD
#define _FORTIFIED_LOGREAD

#include <config.h>
#include <gnome.h>
#include <libgnomevfs/gnome-vfs.h>
#include "fortified.h"

#define FILE_BUF 4096

void open_logfile (char *logpath);

void logread_async_read_callback (GnomeVFSAsyncHandle *handle, GnomeVFSResult result, gpointer buffer,
                                  GnomeVFSFileSize bytes_requested, GnomeVFSFileSize bytes_read, gpointer data);

Hit *parse_log_line (gchar *line);

typedef struct _Parse Parse;
struct _Parse
{
	gchar *buffer;
	GPatternSpec *pattern;
	int half_line;
	GnomeVFSFileSize size;
	GnomeVFSFileSize bytes_read;
	GnomeVFSAsyncHandle *handle;
	gboolean continuous;
};

#endif
