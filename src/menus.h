/*---[ menus.h ]------------------------------------------------------
 * Copyright (C) 2000 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Functions for installing menus, toolbars and popups
 *--------------------------------------------------------------------*/

#ifndef _FORTIFIED_MENUS
#define _FORTIFIED_MENUS

#include <config.h>
#include <gnome.h>
#include "gui.h"
#include "statusview.h"

GtkWidget *appbar;

void menus_initialize (GtkWidget *app);
void menus_set_toolbar (FortifiedView new_view);

GtkWidget *menus_get_events_inbound_context_menu (void);
GtkWidget *menus_get_events_outbound_context_menu (void);
GtkWidget *menus_get_policy_context_menu (void);
GtkWidget *menus_get_connections_context_menu (void);

void menus_events_save_enabled (gboolean sensitive);
void menus_events_clear_enabled (gboolean sensitive);

void menus_policy_edit_enabled (gboolean sensitive);
void menus_policy_remove_enabled (gboolean sensitive);
void menus_policy_add_enabled (gboolean sensitive);
void menus_policy_apply_enabled (gboolean sensitive);

void menus_update_firewall_controls_state (FirewallStatus state);
void menus_update_events_reloading (gboolean in_progress, gboolean visible);

#endif
