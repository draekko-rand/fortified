/*---[ service.h ]----------------------------------------------------
 * Copyright (C) 2000-2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Return service used based on given port.
 *--------------------------------------------------------------------*/

#ifndef _FORTIFIED_SERVICE
#define _FORTIFIED_SERVICE

#include <config.h>
#include <gnome.h>

GtkListStore* services_get_model (void);
gchar *service_get_name (gint port, gchar *proto);
gchar *service_get_icmp_name (gint type);

#endif
