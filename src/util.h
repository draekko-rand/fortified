/*---[ util.h ]-------------------------------------------------------
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

#ifndef _FORTIFIED_UTIL
#define _FORTIFIED_UTIL

#include <config.h>
#include <gnome.h>

#include "fortified.h"

void show_error (gchar *message);
void error_dialog (const gchar *title,
                   const gchar *header,
		   const gchar *message,
		   GtkWidget *parent);

const gchar *get_system_log_path (void);

void print_hit (Hit *h);
Hit *copy_hit (Hit *h);
void free_hit (Hit *h);

GtkTreeModel* get_devices_model (void);
gchar *get_pretty_device_name (gchar *interface, gboolean long_form);
gboolean is_capable_of_nat (void);

gchar *get_text_between (const gchar *string, gchar *marker1, gchar *marker2);

gboolean is_a_valid_port (const gchar *port);
gboolean is_a_valid_host (const gchar *host);

gchar *lookup_ip (gchar *ip);
gchar *get_ip_of_interface (gchar *itf);
gchar *get_subnet_of_interface (gchar *itf);

gboolean append_to_file (gchar *path, gchar *data, gboolean newline);
void remove_line_from_file (gchar *path, gint position);
void open_browser(const gchar *str);

#endif
