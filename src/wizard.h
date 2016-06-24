/*---[ wizard.h ]------------------------------------------------------
 * Copyright (C) 2000 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * The wizard header file
 *--------------------------------------------------------------------*/

#ifndef _FORTIFIED_WIZARD
#define _FORTIFIED_WIZARD

#include <config.h>
#include <gnome.h>

typedef struct _Wizard Wizard;

struct _Wizard
{
	GPtrArray *pages;
	GtkWidget *notebook;

	gchar *extdevice;
	gchar *intdevice;

	GtkWidget *masq;
	GtkWidget *dhcp_server, *dhcp_new_config, *dhcp_lowest_ip, *dhcp_highest_ip, *dhcp_nameserver;

	GtkWidget *pppcheck;
	GtkWidget *dhcpcheck;

	GtkWidget *start_firewall;
};

void run_wizard (void);
GtkWidget* create_device_page   (Wizard *data);
GtkWidget* create_masq_page     (Wizard *data);

#endif
