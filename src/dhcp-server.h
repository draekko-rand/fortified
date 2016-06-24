/*---[ dhcp-server.h ]------------------------------------------------
 * Copyright (C) 2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Functions related to running and configuring the system DHCP server
 *--------------------------------------------------------------------*/

#ifndef _FORTIFIED_DHCP_SERVER
#define _FORTIFIED_DHCP_SERVER

#include <config.h>
#include <gnome.h>
#include "wizard.h"

gboolean dhcp_server_exists (void);
gboolean dhcp_server_is_running (void);
gboolean dhcp_server_configuration_exists (void);

void dhcp_server_create_configuration (void);

#endif
