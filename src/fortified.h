/*---[ fortified.h ]------------------------------------------------
 * Copyright (C) 2000 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * The main fortified header file
 *--------------------------------------------------------------------*/

#ifndef _FORTIFIED_MAIN
#define _FORTIFIED_MAIN

#include <config.h>
#include <gnome.h>

typedef struct _Hit  Hit;

struct _Hit
{
	gchar *time;
	gchar *direction;
	gchar *in;
	gchar *out;
	gchar *port;
	gchar *source;
	gchar *destination;
	gchar *length;
	gchar *tos;
	gchar *protocol;
	gchar *service;
};

gboolean fortified_is_locked (void);

void stop_firewall (void);
void start_firewall (void);
void restart_firewall_if_active (void);
void lock_firewall (void);
void unlock_firewall (void);
void exit_fortified (void);

#endif
