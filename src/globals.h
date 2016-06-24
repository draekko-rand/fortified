/*---[ globals.h ]----------------------------------------------------
 * Copyright (C) 2002 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Global structs and variables
 *--------------------------------------------------------------------*/
#ifndef _FORTIFIED_GLOBLAS
#define _FORTIFIED_GLOBALS

#include <config.h>
#include <gnome.h>


typedef struct
{
	GtkWidget     *window;   /* Main window for Fortified */
	GtkWidget     *ruleview; /* TreeView for rules */
	GtkTooltips   *ttips;    /* Tool tips widget */
} FortifiedApp;

extern FortifiedApp Fortified;

gboolean NETFILTER;
gboolean CONSOLE;

#endif
