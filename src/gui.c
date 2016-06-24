/*---[ gui.c ]--------------------------------------------------------
 * Copyright (C) 2002 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * The GUI builder
 *--------------------------------------------------------------------*/

#include <config.h>
#include <gnome.h>

#include "globals.h"
#include "fortified.h"
#include "gui.h"
#include "statusview.h"
#include "hitview.h"
#include "util.h"
#include "menus.h"
#include "xpm/fortified-pixbufs.h"
#include "tray.h"
#include "preferences.h"
#include "policyview.h"

static GtkWidget *notebook;

static void
widget_sensitivity_sync_toggle (GtkWidget *source, GtkWidget *target)
{
	gboolean sensitive;

	sensitive = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (source));
	gtk_widget_set_sensitive (target, sensitive);
}

/* [ gui_widget_sensitivity_sync ]
 * Binds the value of a widget like a toggle to the sensitive of another widget
 */
void
gui_widget_sensitivity_sync (GtkToggleButton *source, GtkWidget *target)
{
	g_signal_connect (G_OBJECT (source), "toggled",
		G_CALLBACK (widget_sensitivity_sync_toggle), target);
}


/* [ new_treeview_text_column ]
 * Convenience function for creating a text column for a treeview
 */
static GtkTreeViewColumn *
new_treeview_text_column (gint col_num, gchar *title)
{
	GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes (title,
		renderer, "text", col_num, NULL);

	return column;
}

/* [ gui_create_list_view ]
 * Convenience function for constructing a GtkTreeView from a definition
 */
GtkWidget *
gui_create_list_view (View_def *def, gint width, gint height)
{
	GtkListStore *store;
	GtkWidget *view;
	GType *types = g_malloc0 (def->num_columns * sizeof (GType));
	gint i;

	/* Determine the column types */
	for (i = 0; i < def->num_columns; i++) {
		types[i] = def->columns[i].type;
	}

	store = gtk_list_store_newv (def->num_columns, types);
	g_free (types);
	view = gtk_tree_view_new_with_model (GTK_TREE_MODEL (store));

	/* Create the columns from the definition */
	for (i = 0; i < def->num_columns; i++) {
		GtkTreeViewColumn *column;

		if (def->columns[i].visible) {
			column = new_treeview_text_column (i, def->columns[i].label);
			gtk_tree_view_append_column (GTK_TREE_VIEW (view), column);
		}
	}

	if (width != -1 || height != -1)
		gtk_widget_set_size_request (view, width, height);

	g_object_unref (G_OBJECT (store));
	
	return view;
}

/* [ gui_toggle_visibility ]
 * Toggle the visibility for the main Fortified window
 */
gboolean
gui_toggle_visibility (void)
{
	static int window_x = -1;
	static int window_y = -1;

	if (GTK_WIDGET_VISIBLE (Fortified.window)) {
		gtk_window_get_position (GTK_WINDOW (Fortified.window),
		                         &window_x, &window_y);

		gui_set_visibility (FALSE);

		return FALSE;
	} else {
		if (window_x >= 0 && window_y >= 0) {
			gtk_window_move (GTK_WINDOW (Fortified.window),
			                 window_x,
			                 window_y);
		}
		gui_set_visibility (TRUE);

		return FALSE;
	}
}

/* [ show_about ]
 * Creates the about dialog
 */
void 
show_about (GtkWidget *widget, gpointer data)
{
	GdkPixbuf *pixbuf;
	static GtkWidget *dialog = NULL;

	/* Don't create more than one about box */
	if (dialog != NULL) {
		g_assert (GTK_WIDGET_REALIZED (dialog));
		gdk_window_show (dialog->window);
		gdk_window_raise (dialog->window);
	}
	else {
		const gchar *authors[] = {
			"Tomas Junnonen <majix@sci.fi> - Main Developer, Maintainer",
			"Paul Drain <pd@cipherfunk.org> - Developer",
			NULL};

		pixbuf = gdk_pixbuf_new_from_inline (-1, pengo, FALSE, NULL);

		dialog = gnome_about_new (
			"Fortified", VERSION,
			"(C) 2000-2005 Tomas Junnonen",
			_("An all-in-one Linux firewall utility for GNOME.\n"),
			authors,
			NULL,
			NULL, pixbuf);

		g_signal_connect (G_OBJECT (dialog), "destroy",
			G_CALLBACK (gtk_widget_destroyed), &dialog);

		g_object_unref (G_OBJECT(pixbuf));
		gtk_widget_show (dialog);
	}
}

/* [ gui_get_active_view ]
 * Return the view mode that is currently selected
 */
FortifiedView
gui_get_active_view (void)
{
	FortifiedView v;
	
	v = gtk_notebook_get_current_page (GTK_NOTEBOOK (notebook));
	g_assert (v < NUM_VIEWS);
	
	return v;
}

/* [ close_main_window ]
 * Quit or hide, determined by the config files
 */
static gboolean
close_main_window (void)
{
	if (preferences_get_bool (PREFS_MINIMIZE_TO_TRAY) &&
	    preferences_get_bool (PREFS_ENABLE_TRAY_ICON)) {
		gui_toggle_visibility ();
		return TRUE;
	} else {
		exit_fortified ();
		return FALSE;
	}
}


/* [ gui_set_visibility ]
 * Set the visibility of the main Fortified window
 */
void
gui_set_visibility (gboolean visible)
{
	if (visible) {
		gtk_widget_show (Fortified.window);
	} else
		gtk_widget_hide (Fortified.window);
}

static void
view_switched_cb (GtkNotebook *notebook, GtkNotebookPage *page,
                  guint page_num, gpointer data)
{
	/* Show Firewall controls only on Status page */
	if (page_num == STATUS_VIEW)
		menus_update_firewall_controls_state (status_get_state ());
	else
		menus_update_firewall_controls_state (STATUS_NONE);

	if (page_num == EVENTS_VIEW) {
		menus_update_events_reloading (hitview_reload_in_progress (), TRUE);
		if (status_get_state () == STATUS_HIT) { /* Clear hit state on events tab focus */
			status_set_state (STATUS_RUNNING);
		}
	} else
		menus_update_events_reloading (hitview_reload_in_progress (), FALSE);

	menus_set_toolbar (page_num);
}

/* [ gui_construct ]
 * Create the GUI
 */
void
gui_construct (void)
{
	GtkWidget *tablabel;
        GtkWidget *statusview_page;
	GtkWidget *hitview_page;
	GtkWidget *policyview_page;

	gchar hostname[40];

	if (!gethostname (hostname, 39))
		Fortified.window = gnome_app_new (PACKAGE, g_strconcat ("Fortified ", hostname, NULL));
	else
		Fortified.window = gnome_app_new (PACKAGE, "Fortified");

	Fortified.ttips = gtk_tooltips_new ();

/* Set up the main window */
	g_signal_connect (G_OBJECT (Fortified.window), "delete_event",
			  G_CALLBACK (close_main_window), NULL);

	gnome_window_icon_set_default_from_file (
		"/usr/share/pixmaps/fortified.png");

	menus_initialize (Fortified.window);

/* The main application is spread out over a set of notebook pages */
	notebook = gtk_notebook_new ();
	gnome_app_set_contents (GNOME_APP (Fortified.window), notebook);

/* Set up the statusview page */
	statusview_page = create_statusview_page ();
	tablabel = gtk_label_new (_("Status"));
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), statusview_page, tablabel);

/* Set up the hitview page */
	hitview_page = create_hitview_page ();
	tablabel = gtk_label_new (_("Events"));
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), hitview_page, tablabel);

/* Set up the the policyview pages */
	policyview_page = create_policyview_page ();
	tablabel = gtk_label_new (_("Policy"));
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook), policyview_page, tablabel);

	g_signal_connect_after (G_OBJECT (notebook), "switch-page",
			        G_CALLBACK (view_switched_cb), NULL);

	/* FIXME: By making the window non-resizable the expanders collapse properly,
	    but it would be nicer if it worked with a resizable window */
	//gtk_window_set_resizable (GTK_WINDOW (Fortified.window), FALSE);

	/* Show the tray icon */
	if (preferences_get_bool (PREFS_ENABLE_TRAY_ICON))
		tray_init ();
}
