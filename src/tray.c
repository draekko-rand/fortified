/*---[ tray.c ]-------------------------------------------------
 * Copyright (C) 2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * The notification icon in the system tray
 *--------------------------------------------------------------------*/
 
#include "tray.h"
#include "eggtrayicon.h"
#include "globals.h"
#include "xpm/fortified-pixbufs.h"
#include "fortified.h"
#include "gui.h"
#include "util.h"
#include "hitview.h"
#include "statusview.h"
#include "preferences.h"

static EggTrayIcon *tray_icon;
static GtkWidget *tray_icon_image;
static GtkTooltips *tray_icon_tooltip;

static gboolean tray_clicked (GtkWidget *event_box, GdkEventButton *event, gpointer data);
static gboolean tray_menu (GtkWidget *event_box, GdkEventButton *event, gpointer data);

static gboolean animating;

/* [ tray_destroyed ]
 * Catch the destroy signal and restart (work around for the panel crashing)
 */
static gboolean
tray_destroyed (GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	if (preferences_get_bool (PREFS_ENABLE_TRAY_ICON))
		tray_init ();

	return TRUE;
}

/* [ tray_init ]
 * Create the tray application
 */
void tray_init (void)
{
	GtkWidget *eventbox;
	GdkPixbuf *pixbuf;

	tray_icon = egg_tray_icon_new ("Fortified");
 	pixbuf = gdk_pixbuf_new_from_inline (-1, icon_stop_normal, FALSE, NULL);
	tray_icon_image = gtk_image_new_from_pixbuf (pixbuf);

	eventbox = gtk_event_box_new ();
	gtk_widget_show (eventbox);
	gtk_container_add (GTK_CONTAINER (eventbox), tray_icon_image);
	gtk_container_add (GTK_CONTAINER (tray_icon), eventbox);

	g_signal_connect (G_OBJECT (eventbox), "button-release-event",
	                  G_CALLBACK (tray_clicked), NULL );

	gtk_widget_show_all (GTK_WIDGET (tray_icon));

	tray_icon_tooltip = gtk_tooltips_new ();

	g_signal_connect (G_OBJECT (tray_icon), "destroy",
	                  G_CALLBACK (tray_destroyed), NULL);
}

gboolean
tray_is_running (void)
{
	return (tray_icon != NULL);
}

void
tray_remove (void)
{
	gtk_widget_destroy (GTK_WIDGET (tray_icon));
	tray_icon = NULL;
}

/* [ animation_timeout ]
 * Timeout function used to change the tray icon as part of an animation
 */
static int
animation_timeout (gpointer image)
{
	GdkPixbuf *pixbuf;

	if (animating) {
		pixbuf = gdk_pixbuf_new_from_inline (-1, image, FALSE, NULL);
		gtk_image_set_from_pixbuf (GTK_IMAGE (tray_icon_image), pixbuf);
	}

	return FALSE;
}

static int
animation_finish (gpointer image)
{
	animating = FALSE;
	return FALSE;
}

/* [ tray_update ]
 * Set the tray icon status to state
 */
void tray_update (FirewallStatus state)
{
	GdkPixbuf *pixbuf = NULL;
	gchar *tooltip = NULL;

	if (!tray_is_running ())
		return;

	if (state == STATUS_HIT) {
		const Hit *h = get_last_hit ();
		gchar *ip = g_strdup (h->source);

		if (!animating) {

			animating = TRUE;

			g_timeout_add (0, animation_timeout, (gpointer)tray_hit1);
			g_timeout_add (200, animation_timeout, (gpointer)tray_hit2);
			g_timeout_add (400, animation_timeout, (gpointer)tray_hit3);
			g_timeout_add (600, animation_timeout, (gpointer)tray_hit4);
			g_timeout_add (800, animation_timeout, (gpointer)tray_hit5);
			g_timeout_add (1600, animation_timeout, (gpointer)tray_hit4);
			g_timeout_add (1800, animation_timeout, (gpointer)tray_hit3);
			g_timeout_add (2000, animation_timeout, (gpointer)tray_hit2);
			g_timeout_add (2200, animation_timeout, (gpointer)tray_hit1);
			g_timeout_add (2200, animation_finish, NULL);

			tooltip = g_strdup_printf ("Hit from %s detected", ip);
			g_free (ip);
		}

	} else if (state == STATUS_STOPPED) {
 		pixbuf = gdk_pixbuf_new_from_inline (-1, icon_stop_normal, FALSE, NULL);
		tooltip = g_strdup (_("Firewall stopped"));
	} else if (state == STATUS_RUNNING) {
	 	pixbuf = gdk_pixbuf_new_from_inline (-1, icon_start_normal, FALSE, NULL);
		tooltip = g_strdup (_("Firewall running"));
	} else if (state == STATUS_LOCKED) {
	 	pixbuf = gdk_pixbuf_new_from_inline (-1, icon_locked, FALSE, NULL);
		tooltip = g_strdup (_("Firewall locked"));
	}

	if (state != STATUS_HIT) {
		animating = FALSE;
		gtk_image_set_from_pixbuf (GTK_IMAGE (tray_icon_image), pixbuf);
		gtk_widget_show (tray_icon_image);
	}

	gtk_tooltips_set_tip (tray_icon_tooltip, GTK_WIDGET (tray_icon), tooltip, NULL);
	g_free (tooltip);
}

/* [ tray_clicked ]
 * Callback for when the system tray icon is clicked
 */
static gboolean
tray_clicked (GtkWidget *event_box, GdkEventButton *event, gpointer data)
{
	/* Clear state */
	if (event->button == 1 && status_get_state () == STATUS_HIT) {
		status_set_state (STATUS_RUNNING);
	}

	/* Clear state and toggle visibility */
	if (event->button == 1 || event->button == 2) {
		gui_toggle_visibility ();
		return TRUE;

	/* Pop up tray context menu */
	} else if (event->button == 3) {
		return tray_menu (event_box, event, data);
	}

	return FALSE;
}

static void
show_main_window_cb (void)
{
	gui_set_visibility (TRUE);
}

/* [ tray_menu ]
 * Callback for popping up the menu
 */
static gboolean
tray_menu (GtkWidget *widget, GdkEventButton *event, gpointer data)
{
	GtkWidget *status_menu;
	GtkWidget *item;

	status_menu = gtk_menu_new();

	item = gtk_menu_item_new_with_mnemonic (_("_Show Fortified"));
	gtk_container_add (GTK_CONTAINER (status_menu), item);
	g_signal_connect (G_OBJECT (item), "activate",
	                  G_CALLBACK (show_main_window_cb),
	                  NULL);

	item = gtk_menu_item_new ();
	gtk_widget_set_sensitive (item, FALSE);
	gtk_container_add (GTK_CONTAINER (status_menu), item);

	item = gtk_menu_item_new_with_mnemonic (_("_Exit"));
	gtk_container_add (GTK_CONTAINER (status_menu), item);
	g_signal_connect (G_OBJECT (item), "activate",
	                  G_CALLBACK (exit_fortified),
	                  NULL);


	gtk_widget_show_all (status_menu);

	gtk_menu_popup (GTK_MENU(status_menu), NULL, NULL,
	                NULL, NULL,
	                event->button, event->time);

	return TRUE;
}
