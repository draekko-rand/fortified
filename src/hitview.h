/*---[ hitview.h ]-----------------------------------------------------
 * Copyright (C) 2002 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * The Hits page and related functions
 *--------------------------------------------------------------------*/

#ifndef _FORTIFIED_HITVIEW
#define _FORTIFIED_HITVIEW

#include <config.h>
#include <gnome.h>
#include <libgnomevfs/gnome-vfs.h>

#include "fortified.h"

void hitview_clear (void);
void hitview_reload (void);
void hitview_reload_cancel (void);
gboolean hitview_reload_in_progress (void);
void hitview_abort_reload_callback (GnomeVFSAsyncHandle *handle, GnomeVFSResult result, gpointer data);
gboolean hitview_append_hit (Hit *h);
void hitview_toggle_column_visibility (GtkWidget *widget, gint colnum);

Hit *hitview_get_selected_hit (void);
GList *hitview_get_all_hits (void);

void hitview_lookup_selected_hit (void);
void copy_selected_hit (void);
const Hit *get_last_hit (void);

void hitview_disable_events_selected_source (void);
void hitview_disable_events_selected_port (void);

void hitview_allow_host (void);
void hitview_allow_service (void);
void hitview_allow_service_from (void);

GtkWidget *create_hitview_page (void);

enum
{
	HITCOL_TIME,
	HITCOL_DIRECTION,
	HITCOL_IN,
	HITCOL_OUT,
	HITCOL_PORT,
 	HITCOL_SOURCE,
	HITCOL_DESTINATION,
	HITCOL_LENGTH,
	HITCOL_TOS,
	HITCOL_PROTOCOL,
	HITCOL_SERVICE,
	HITCOL_COLOR,
	NUM_HITCOLUMNS
};

#endif
