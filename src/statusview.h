/*---[ statusview.h ]-----------------------------------------------------
 * Copyright (C) 2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * The Status page and related functions
 *--------------------------------------------------------------------*/

#ifndef _FORTIFIED_STATUSVIEW
#define _FORTIFIED_STATUSVIEW

#include <config.h>
#include <gnome.h>

#include "fortified.h"

typedef enum
{
	STATUS_NONE,
	STATUS_STOPPED,
	STATUS_RUNNING,
	STATUS_LOCKED,
	STATUS_HIT
} FirewallStatus;

void status_set_state (FirewallStatus status);
FirewallStatus status_get_state (void);

GtkWidget *create_statusview_page (void);

void status_events_reset (void);
void status_event_in_inc (void);
void status_serious_event_in_inc (void);
void status_event_out_inc (void);
void status_serious_event_out_inc (void);

gint status_sync_timeout (gpointer data);

void status_lookup_selected_connection (void);

#endif
