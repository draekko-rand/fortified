/*---[ hitview.c ]-----------------------------------------------------
 * Copyright (C) 2002-2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * The Events page and related functions
 *--------------------------------------------------------------------*/

#include <config.h>
#include <gnome.h>
#include <libgnomevfs/gnome-vfs.h>

#include "fortified.h"
#include "globals.h"
#include "hitview.h"
#include "util.h"
#include "menus.h"
#include "preferences.h"
#include "statusview.h"
#include "logread.h"
#include "scriptwriter.h"

#define COLOR_SERIOUS_HIT "#bd1f00"
#define COLOR_BROADCAST_HIT "#6d6d6d"

static GtkListStore *hitstore;
static GtkWidget *hitview;
static Hit *last_hit = NULL;
static GnomeVFSAsyncHandle *hitview_ghandle = (GnomeVFSAsyncHandle*)NULL;

const Hit *
get_last_hit (void)
{
	return last_hit;
}

gboolean
hitview_reload_in_progress (void)
{
	return (hitview_ghandle != NULL);
}

void
hitview_abort_reload_callback (GnomeVFSAsyncHandle *handle, GnomeVFSResult result, gpointer data)
{
	Parse *info = data;
	if (result != GNOME_VFS_OK) {
		g_warning ("Close error");
	}
	g_free (info->buffer);
	g_pattern_spec_free (info->pattern);
	g_free (info);
	hitview_ghandle = (GnomeVFSAsyncHandle*)NULL;

	menus_update_events_reloading (FALSE, gui_get_active_view () == EVENTS_VIEW);
	printf ("Finished reading events list\n");
}

/* [ create_text_column ]
 * Convinience funtion for creating a text column for a treeview
 */
static GtkTreeViewColumn *
create_text_column (gint number, gchar * title)
{
	GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes (title, renderer,
	                                                   "text", number,
	                                                   "foreground", HITCOL_COLOR,
	                                                   NULL);
	return column;
}

/* [ hitview_clear ]
 * Clears the log CList
 */
void
hitview_clear (void)
{
	if (status_get_state () == STATUS_HIT)
		status_set_state (STATUS_RUNNING);

	menus_events_clear_enabled (FALSE);
	menus_events_save_enabled (FALSE);
	gtk_list_store_clear (hitstore);
	if (last_hit != NULL) {
		free_hit (last_hit);
		last_hit = NULL;
	}
	gtk_tree_view_columns_autosize (GTK_TREE_VIEW (hitview));
	status_events_reset ();
}

/* [ unselect_all ]
 * Unselect all entries in the hitview
 */
static void
unselect_all (void)
{
	GtkTreeSelection *s;

	s = gtk_tree_view_get_selection (GTK_TREE_VIEW (hitview));
	gtk_tree_selection_unselect_all (s);
}

/* [ has_selected ]
 * Return true if there are entries selected in the hitview
 */
static gboolean
has_selected (void)
{
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	gboolean has_selected;

	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (hitview));
	has_selected = gtk_tree_selection_get_selected (selection, NULL, &iter);

	return has_selected;
}

/* [ scroll_to_hit ]
 * Scroll the hitview to the hit iter points to. Only works in ascending sort mode
 */
static void
scroll_to_hit (GtkTreeIter *iter)
{
	static GtkTreeModel *model = NULL;
	gint colid;
	GtkSortType order;
	GtkTreePath *last;

	if (model == NULL)
		model = gtk_tree_view_get_model (GTK_TREE_VIEW (hitview));

	last = gtk_tree_model_get_path (model, iter);
	gtk_tree_sortable_get_sort_column_id (GTK_TREE_SORTABLE (model), &colid, &order);

	if (order == GTK_SORT_ASCENDING)
		gtk_tree_view_scroll_to_cell (GTK_TREE_VIEW (hitview), last, NULL, TRUE, 1.0, 1.0);

	 gtk_tree_path_free (last);
}

/* [ compare_to_last_hit ]
 * Loosely compare a hit to the previous one. Return true if they are similiar
 */
static gboolean
compare_to_last_hit (Hit *new)
{
	const Hit *old = get_last_hit ();
	gboolean same = TRUE;

	if (old == NULL || new == NULL)
		return FALSE;
	
	/* Going from most likely to differ to least */
	if (strcmp (new->port, old->port) != 0) {
		same = FALSE;
	}
	else if (strcmp (new->protocol, old->protocol) != 0) {
		same = FALSE;
	}
	else if (strcmp (new->source, old->source) != 0) {
		same = FALSE;
	}
	else if (strcmp (new->destination, old->destination) != 0) {
		same = FALSE;
	}
/*	else if (strcmp (new->in, old->in) == 0)
		same = FALSE;
	else if (strcmp (new->out, old->out) == 0)
		same = FALSE;
*/
	return same;
}

/* [ hit_is_for_me ]
 * Test if the destination of a hit matches the external interface IP
 */
static gboolean
hit_is_for_me (Hit *h)
{
	static gchar *myip = NULL;
	
	if (myip == NULL) {
		myip = get_ip_of_interface (preferences_get_string (PREFS_FW_EXT_IF));
	}

	return (strcmp (myip, h->destination) == 0);
}

/* [ hit_is_serious ]
 * Test if a hit is classified as serious
 */
static gboolean
hit_is_serious (Hit *h)
{
	return (hit_is_for_me (h) && atoi (h->port) < 1024);
}

/* [ hit_is_broadcast ]
 * Test if the hit is a broadcasted message
 */
static gboolean
hit_is_broadcast (Hit *h)
{
	return (g_str_has_suffix (h->destination, ".255"));
}

static gboolean
hit_is_outbound (Hit *h)
{
	return g_str_equal (h->direction, "Outbound");
}

static gboolean
hit_is_inbound (Hit *h)
{
	return g_str_equal (h->direction, "Inbound");
}

/* [ hitview_append_hit ]
 * Append a hit to the hitlist, return true if successful
 */
gboolean
hitview_append_hit (Hit *h)
{
	GtkTreeIter iter;
	static gchar *color_serious = COLOR_SERIOUS_HIT;
	static gchar *color_broadcast = COLOR_BROADCAST_HIT;
	gchar *color = NULL;

	if (preferences_get_bool (PREFS_SKIP_REDUNDANT))
		if (compare_to_last_hit (h)) {
			/* printf ("Hit filtered: Redundant\n"); */
			return FALSE;
		}

	if (preferences_get_bool (PREFS_SKIP_NOT_FOR_FIREWALL))
		if (!hit_is_for_me (h) && !hit_is_outbound (h)) {
			/* printf ("Hit filtered: Someone else's problem \n"); */
			return FALSE;
		}

	if (hit_is_broadcast (h)) {
		color = color_broadcast;
	} else if (hit_is_serious (h)) {
		color = color_serious;
		if (hit_is_outbound (h))
			status_serious_event_out_inc ();
		else
			status_serious_event_in_inc ();
	}

	if (hit_is_outbound (h)) {
		status_event_out_inc ();
		g_free (h->direction);
		h->direction = g_strdup (_("Outbound")); /* Localize the direction */
	} else if (hit_is_inbound (h)) {
		status_event_in_inc ();
		g_free (h->direction);
		h->direction = g_strdup (_("Inbound"));
	} else {
		g_free (h->direction);
		h->direction = g_strdup (_("Unknown"));
	}

	gtk_list_store_append (hitstore, &iter);
	gtk_list_store_set (hitstore, &iter,
	                    HITCOL_TIME,        h->time,
			    HITCOL_DIRECTION,	h->direction,
	                    HITCOL_IN,          h->in,
	                    HITCOL_OUT,         h->out,
	                    HITCOL_PORT,        h->port,
	                    HITCOL_SOURCE,      h->source,
	                    HITCOL_DESTINATION, h->destination,
	                    HITCOL_LENGTH,      h->length,
	                    HITCOL_TOS,         h->tos,
	                    HITCOL_PROTOCOL,    h->protocol,
	                    HITCOL_SERVICE,     h->service,
			    HITCOL_COLOR,       color,
	                    -1);

	if (!has_selected ())
		scroll_to_hit (&iter);

	if (last_hit != NULL) {
		free_hit (last_hit);
	}
	last_hit = copy_hit (h);

	menus_events_clear_enabled (TRUE);
	menus_events_save_enabled (TRUE);

	/* Fixes a glitch in the view's rendering that causes
	   text to jump around when mouse moves over an entry */
	if (!hitview_reload_in_progress ())
		gtk_tree_view_columns_autosize (GTK_TREE_VIEW (hitview));

	return TRUE;
}

/* [ gvfs_open_callback ]
 * Open and read the file asynchronously
 */
static void
gvfs_open_callback (GnomeVFSAsyncHandle *handle, GnomeVFSResult result, gpointer data)
{
	Parse *info = g_new (Parse, 1);
	GnomeVFSFileInfo *file_info;

	if (result != GNOME_VFS_OK) {
		g_warning ("Failed to open file for async reading");
		g_free (info);
		return;
	}
	file_info = gnome_vfs_file_info_new ();

	if (gnome_vfs_get_file_info((gchar *)data, file_info, GNOME_VFS_FILE_INFO_DEFAULT) != GNOME_VFS_OK) {
		g_warning ("File info error");
		g_free (info);
		return;
	}

	info->size = file_info->size;
	info->bytes_read = 0;
	info->buffer = g_new (gchar, FILE_BUF+1);
	info->pattern = g_pattern_spec_new ("* IN=* OUT=* SRC=* ");
	info->continuous = FALSE;
	gnome_vfs_file_info_unref (file_info);
	gnome_vfs_async_read (handle, info->buffer, FILE_BUF, logread_async_read_callback, info);
}

void
hitview_reload_cancel (void)
{
	printf ("Canceled reload of events list\n");
	gnome_vfs_async_cancel (hitview_ghandle);
	menus_update_events_reloading (FALSE, gui_get_active_view () == EVENTS_VIEW);
	hitview_ghandle = (GnomeVFSAsyncHandle*)NULL;
}

/* [ hitview_reload ]
 * Loads the entire kernel log file into the hitlist
 */
void
hitview_reload (void)
{	
	const gchar *path;

	 /* If a new reload request comes while the previous operation is still pending, cancel it */
	if (hitview_reload_in_progress ()) { 	
		gnome_vfs_async_cancel (hitview_ghandle);
	}

	path = get_system_log_path ();

	if (!g_file_test (path, G_FILE_TEST_EXISTS)) {
		gchar *error = g_strdup_printf ("Error reading system log %s, file does not exist", path);
		show_error (error);
		g_free (error);
		return;
	}

	hitview_clear ();
	gnome_vfs_async_open (&hitview_ghandle, path, GNOME_VFS_OPEN_READ, GNOME_VFS_PRIORITY_DEFAULT, 
                              gvfs_open_callback, (gpointer)path);

	menus_update_events_reloading (TRUE, gui_get_active_view () == EVENTS_VIEW);
}

/* [ create_hitlist_model ]
 * Creates the list for storage of hits
 */
static GtkTreeModel *
create_hitlist_model (void)
{
	hitstore = gtk_list_store_new (NUM_HITCOLUMNS,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING);

	return GTK_TREE_MODEL (hitstore);
}

/* [ hitview_toggle_column_visibility ]
 * Negate the visibility of a column
 */
void
hitview_toggle_column_visibility (GtkWidget *widget, gint colnum)
{
	GtkTreeViewColumn *column;
	gboolean visible;

	g_assert (colnum < NUM_HITCOLUMNS);

	if (hitview == NULL)
		return;

	column = gtk_tree_view_get_column (GTK_TREE_VIEW (hitview), colnum);
	visible = !gtk_tree_view_column_get_visible (column);
	gtk_tree_view_column_set_visible(column, visible);

	switch (colnum) {
	  case 0: preferences_set_bool (PREFS_HITVIEW_TIME_COL, visible); break;
	  case 1: preferences_set_bool (PREFS_HITVIEW_DIRECTION_COL, visible); break;
	  case 2: preferences_set_bool (PREFS_HITVIEW_IN_COL, visible); break;
	  case 3: preferences_set_bool (PREFS_HITVIEW_OUT_COL, visible); break;
	  case 4: preferences_set_bool (PREFS_HITVIEW_PORT_COL, visible); break;
	  case 5: preferences_set_bool (PREFS_HITVIEW_SOURCE_COL, visible); break;
	  case 6: preferences_set_bool (PREFS_HITVIEW_DESTINATION_COL, visible); break;
	  case 7: preferences_set_bool (PREFS_HITVIEW_LENGTH_COL, visible); break;
	  case 8: preferences_set_bool (PREFS_HITVIEW_TOS_COL, visible); break;
	  case 9: preferences_set_bool (PREFS_HITVIEW_PROTOCOL_COL, visible); break;
	  case 10: preferences_set_bool (PREFS_HITVIEW_SERVICE_COL, visible); break;
	}
}

/* [ hitview_add_columns ]
 * Add the columns to the hit TreeView
 */
static void
hitview_add_columns (GtkTreeView *treeview)
{
	GtkTreeViewColumn *column;
	gboolean visible;

	/* column for time */
	column = create_text_column (HITCOL_TIME, _("Time"));
	gtk_tree_view_column_set_sort_column_id (column, HITCOL_TIME);
	gtk_tree_view_append_column (treeview, column);
	visible = preferences_get_bool (PREFS_HITVIEW_TIME_COL);
	gtk_tree_view_column_set_visible (column, visible);

	/* column for direction */
	column = create_text_column (HITCOL_DIRECTION, _("Direction"));
	gtk_tree_view_column_set_sort_column_id (column, HITCOL_DIRECTION);
	gtk_tree_view_append_column (treeview, column);
	visible = preferences_get_bool (PREFS_HITVIEW_DIRECTION_COL);
	gtk_tree_view_column_set_visible (column, visible);

	/* column for in device */
	column = create_text_column (HITCOL_IN, _("In"));
	gtk_tree_view_column_set_sort_column_id (column, HITCOL_IN);
	gtk_tree_view_append_column (treeview, column);
	visible = preferences_get_bool (PREFS_HITVIEW_IN_COL);
	gtk_tree_view_column_set_visible (column, visible);

	/* column for out device */
	column = create_text_column (HITCOL_OUT, _("Out"));
	gtk_tree_view_column_set_sort_column_id (column, HITCOL_OUT);
	gtk_tree_view_append_column (treeview, column);
	visible = preferences_get_bool (PREFS_HITVIEW_OUT_COL);
	gtk_tree_view_column_set_visible (column, visible);

	/* column for port */
	column = create_text_column (HITCOL_PORT, _("Port"));
	gtk_tree_view_column_set_sort_column_id (column, HITCOL_PORT);
	gtk_tree_view_append_column (treeview, column);
	visible = preferences_get_bool (PREFS_HITVIEW_PORT_COL);
	gtk_tree_view_column_set_visible (column, visible);

	/* column for source */
	column = create_text_column (HITCOL_SOURCE, _("Source"));
	gtk_tree_view_column_set_sort_column_id (column, HITCOL_SOURCE);
	gtk_tree_view_append_column (treeview, column);
	visible = preferences_get_bool (PREFS_HITVIEW_SOURCE_COL);
	gtk_tree_view_column_set_visible (column, visible);

	/* column for destination */
	column = create_text_column (HITCOL_DESTINATION, _("Destination"));
	gtk_tree_view_column_set_sort_column_id (column, HITCOL_DESTINATION);
	gtk_tree_view_append_column (treeview, column);
	visible = preferences_get_bool (PREFS_HITVIEW_DESTINATION_COL);
	gtk_tree_view_column_set_visible (column, visible);
	
	/* column for packet length */
	column = create_text_column (HITCOL_LENGTH, _("Length"));
	gtk_tree_view_column_set_sort_column_id (column, HITCOL_LENGTH);
	gtk_tree_view_append_column (treeview, column);
	visible = preferences_get_bool (PREFS_HITVIEW_LENGTH_COL);
	gtk_tree_view_column_set_visible (column, visible);

	/* column for ToS */
	column = create_text_column (HITCOL_TOS, _("TOS"));
	gtk_tree_view_column_set_sort_column_id (column, HITCOL_TOS);
	gtk_tree_view_append_column (treeview, column);
	visible = preferences_get_bool (PREFS_HITVIEW_TOS_COL);
	gtk_tree_view_column_set_visible (column, visible);

	/* column for protocol */
	column = create_text_column (HITCOL_PROTOCOL, _("Protocol"));
	gtk_tree_view_column_set_sort_column_id (column, HITCOL_PROTOCOL);
	gtk_tree_view_append_column (treeview, column);	
	visible = preferences_get_bool (PREFS_HITVIEW_PROTOCOL_COL);
	gtk_tree_view_column_set_visible (column, visible);

	/* column for service */
	column = create_text_column (HITCOL_SERVICE, _("Service"));
	gtk_tree_view_column_set_sort_column_id (column, HITCOL_SERVICE);
	gtk_tree_view_append_column (treeview, column);	
	visible = preferences_get_bool (PREFS_HITVIEW_SERVICE_COL);
	gtk_tree_view_column_set_visible (column, visible);
}

/* [ get_hit ]
 * Retrieve the specific hit iter points to
 */
static Hit *
get_hit (GtkTreeModel *model,
         GtkTreeIter iter)
{
	Hit *h = g_new (Hit, 1);

	gtk_tree_model_get (model, &iter,
	                    HITCOL_TIME,        &h->time,
			    HITCOL_DIRECTION,   &h->direction,
	                    HITCOL_IN,          &h->in,
	                    HITCOL_OUT,         &h->out,
	                    HITCOL_PORT,        &h->port,
	                    HITCOL_SOURCE,      &h->source,
	                    HITCOL_DESTINATION, &h->destination,
	                    HITCOL_LENGTH,      &h->length,
	                    HITCOL_TOS,         &h->tos,
	                    HITCOL_PROTOCOL,    &h->protocol,
	                    HITCOL_SERVICE,     &h->service,
	                    -1);

	return h; 
}

/* [ hit_activated_cb ]
 * Callback for selecting a row in the hit view
 * TODO: Default action for hits? Hit->Rule helper maybe.
 */
static void 
hit_activated_cb (GtkTreeView *treeview,
                 GtkTreePath *path,
                 GtkTreeViewColumn *arg2,
                 gpointer data)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	Hit *h;

	model = gtk_tree_view_get_model (treeview);
	gtk_tree_model_get_iter (model, &iter, path);
	h = get_hit (model, iter);

	print_hit (h);
	free_hit (h);

	unselect_all ();
}

/* [ hitview_get_selected_hit ]
 * Get the hit that is currently selected in the hitview
 */
Hit *
hitview_get_selected_hit (void)
{
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	Hit *h = NULL;
	gboolean has_selected;

	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (hitview));

	has_selected = gtk_tree_selection_get_selected (selection,
	                                                NULL,
	                                                &iter);
	if (has_selected) {
		model = gtk_tree_view_get_model (GTK_TREE_VIEW (hitview));
		h = get_hit (model, iter);
	}

	return h;
}

GList *
hitview_get_all_hits (void)
{
	GList *hits = NULL;
	Hit *h;
	GtkTreeModel *model;
	GtkTreeIter iter;

	model = gtk_tree_view_get_model (GTK_TREE_VIEW (hitview));
	if (gtk_tree_model_get_iter_first (model, &iter)) {
		do {
			h = get_hit (model, iter);
			hits = g_list_append (hits, h);
		} while (gtk_tree_model_iter_next (model, &iter));
	} else
		printf ("Error compiling list of hits\n");

	return hits;
}

/* [ hitview_button_press_cb ]
 * Pop up an menu when right clicking the hitview
 */
static gboolean
hitview_button_press_cb (GtkWidget* widget, GdkEventButton* event)
{
	gboolean retval = FALSE;
	Hit *h;
	GtkWidget *menu;

	/* Clear hit state */
	if (status_get_state () == STATUS_HIT)
		status_set_state (STATUS_RUNNING);

	h = hitview_get_selected_hit ();
	if (h == NULL)
		return retval;
	else if (hit_is_outbound (h))
		menu = menus_get_events_outbound_context_menu ();
	else
		menu = menus_get_events_inbound_context_menu ();

	switch (event->button) {
		case 1: break;
		
		case 3: gtk_menu_popup (GTK_MENU (menu), NULL, NULL, NULL, NULL, 
		                        event->button, event->time);
			retval = TRUE;
			break;
	}

	g_free (h);
	return retval;
}

/* [ append_filter_file ]
 * Append data to a events filter file
 */
static gboolean
append_filter_file (gchar *path, gchar *data)
{
	GIOChannel* out;
	GError *error = NULL;

	out = g_io_channel_new_file (path, "a", &error);

	if (out == NULL) {
		g_printerr ("Error reading file %s: %s\n", path, error->message);
		return FALSE;
	}

	if (g_io_channel_write_chars (out, data, -1, NULL, &error) == G_IO_STATUS_NORMAL) {
		g_io_channel_shutdown (out, TRUE, &error);
		return TRUE;
	} else {
		g_io_channel_shutdown (out, FALSE, &error);
		return FALSE;
	}
}
/* [ disable_events_selected_source ]
 * Disable events from the selected source
 */
void
hitview_disable_events_selected_source (void)
{
	Hit *h;
	gchar *data;

	h = hitview_get_selected_hit ();
	if (h == NULL)
		return;

	data = g_strconcat (h->source, "\n", NULL);
	append_filter_file (FORTIFIED_FILTER_HOSTS_SCRIPT, data);
	g_free (h);
	g_free (data);

	restart_firewall_if_active ();
}

void
hitview_disable_events_selected_port (void)
{
	Hit *h;
	gchar *data;

	h = hitview_get_selected_hit ();
	if (h == NULL)
		return;

	data = g_strconcat (h->port, "\n", NULL);
	append_filter_file (FORTIFIED_FILTER_PORTS_SCRIPT, data);
	g_free (h);
	g_free (data);

	restart_firewall_if_active ();
}

void
hitview_allow_host (void)
{
	Hit *h;

	h = hitview_get_selected_hit ();
	if (h == NULL)
		return;

	if (hit_is_outbound (h))
		policyview_create_rule (RULETYPE_OUTBOUND_ALLOW_TO, h);
	else
		policyview_create_rule (RULETYPE_INBOUND_ALLOW_FROM, h);

	g_free (h);
}

void
hitview_allow_service (void)
{
	Hit *h;

	h = hitview_get_selected_hit ();
	if (h == NULL)
		return;

	if (hit_is_outbound (h))
		policyview_create_rule (RULETYPE_OUTBOUND_ALLOW_SERVICE, h);
	else
		policyview_create_rule (RULETYPE_INBOUND_ALLOW_SERVICE, h);

	g_free (h);
}

void
hitview_allow_service_from (void)
{
	Hit *h;

	h = hitview_get_selected_hit ();
	if (h == NULL)
		return;

	if (hit_is_outbound (h))
		policyview_create_rule (RULETYPE_OUTBOUND_ALLOW_SERVICE_FROM, h);
	else
		policyview_create_rule (RULETYPE_INBOUND_ALLOW_SERVICE_FROM, h);

	g_free (h);
}

/* [ lookup_selected_hit ]
 * Resolve the IP address/hostname from the selected line in hitview
 */
void
hitview_lookup_selected_hit (void)
{
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	static GtkTreeModel *model = NULL;
	gchar *source, *destination;
	gchar *hostname = NULL;

	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (hitview));
	if (!gtk_tree_selection_get_selected (selection, NULL, &iter))
		return;

	if (!model)
		model = gtk_tree_view_get_model (GTK_TREE_VIEW (hitview));

	gtk_tree_model_get (model, &iter,
	                    HITCOL_SOURCE, &source,
			    HITCOL_DESTINATION, &destination,
	                    -1);
	hostname = lookup_ip (source);
	if (hostname != NULL)
		gtk_list_store_set (hitstore, &iter,
	        	            HITCOL_SOURCE, hostname,
	         	           -1);
	hostname = lookup_ip (destination);
	if (hostname != NULL)
		gtk_list_store_set (hitstore, &iter,
	        	            HITCOL_DESTINATION, hostname,
	         	           -1);

	gtk_tree_view_columns_autosize (GTK_TREE_VIEW (hitview));
	g_free (source);
	g_free (destination);
}

/* [ month_number ]
 * Convert a three letter month identifier to a number
 */
static int
month_number (gchar *month)
{
	int num = 0;

	if (strcmp (month, "Jan") == 0)
		num = 1;
	else if (strcmp (month, "Feb") == 0)
		num = 2;
	else if (strcmp (month, "Mar") == 0)
		num = 3;
	else if (strcmp (month, "Apr") == 0)
		num = 4;
	else if (strcmp (month, "May") == 0)
		num = 5;
	else if (strcmp (month, "Jun") == 0)
		num = 6;
	else if (strcmp (month, "Jul") == 0)
		num = 7;
	else if (strcmp (month, "Aug") == 0)
		num = 8;
	else if (strcmp (month, "Sep") == 0)
		num = 9;
	else if (strcmp (month, "Oct") == 0)
		num = 10;
	else if (strcmp (month, "Nov") == 0)
		num = 11;
	else if (strcmp (month, "Dec") == 0)
		num = 12;

	return num;
}

/* [ time_sort_func ]
 * Function for sorting the time column
 */
static int
time_sort_func (GtkTreeModel *model, 
	        GtkTreeIter  *a, 
	        GtkTreeIter  *b, 
	        gpointer      user_data)
{
	enum { MONTH, DATE, CLOCK };

	gchar *data1, *data2;
	gchar **time1, **time2;
	gint month1, month2;
	gint day1, day2;
	gint sort = 0;

	gtk_tree_model_get (model, a, HITCOL_TIME, &data1, -1);
	gtk_tree_model_get (model, b, HITCOL_TIME, &data2, -1);

	time1 = g_strsplit (data1, " ", 3);
	time2 = g_strsplit (data2, " ", 3);

	month1 = month_number (time1[MONTH]);
	month2 = month_number (time2[MONTH]); 

	/* Compare first month, then the day, and last the clock */
	if (month1 != month2)
		sort = ((month1 < month2) ? -1:1);
	else {
		day1 = atoi (time1[DATE]);
		day2 = atoi (time2[DATE]);

		if (day1 != day2)
			sort = ((day1 < day2) ? -1:1);
		else
			sort = strcasecmp (time1[CLOCK], time2[CLOCK]);
	}

	g_free (data1);
	g_free (data2);
	g_strfreev (time1);
	g_strfreev (time2);

	return sort;
}

/* [ num_sort_func ]
 * Function for sorting a (text) column with only numbers in it
 */
static int
num_sort_func (GtkTreeModel *model, 
	       GtkTreeIter  *a, 
	       GtkTreeIter  *b, 
	       gpointer      column)
{
	gchar *data1, *data2;
	gint n1, n2;

	gtk_tree_model_get (model, a, (gint)column, &data1, -1);
	gtk_tree_model_get (model, b, (gint)column, &data2, -1);

	n1 = atoi (data1);
	n2 = atoi (data2);

	g_free (data1);
	g_free (data2);

	if (n1 == n2)
		return 0;
	else
		return ((n1 < n2) ? -1:1);
}

/* [ copy_selected_hit ]
 * Copy the selected hit to the clipboard
 */
void
copy_selected_hit (void)
{
	Hit *h;
	gchar *text;
	GtkClipboard *cb;

	h = hitview_get_selected_hit ();

	if (h == NULL)
		return;

	cb = gtk_clipboard_get (GDK_SELECTION_CLIPBOARD);

	text = g_strconcat (
		"Time: ", h->time,
		" Source: ", h->source,
		" Destination: ", h->destination,
		" In IF: ", h->in,
		" Out IF: ", h->out,
		" Port: ", h->port,
		" Length: ", h->length,
		" ToS: ", h->tos,
		" Protocol: ", h->protocol,
		" Service: ", h->service,
		NULL);

	gtk_clipboard_set_text (cb, text, strlen (text));
	g_free (text);
	free_hit (h);
}

/* [ create_hitview_page ]
 * Create the hitview
 */
GtkWidget *
create_hitview_page (void)
{
	GtkWidget *hitpagebox;
	GtkTreeModel *hitmodel;
	GtkWidget *scrolledwin;
	GtkWidget *frame;
	GtkWidget *label;

	hitpagebox = gtk_vbox_new (FALSE, 0);
	hitmodel = create_hitlist_model ();
	hitview = gtk_tree_view_new_with_model (hitmodel);

	frame = gtk_frame_new (NULL);
	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<b>", _("Blocked Connections"), "</b>", NULL));
	gtk_frame_set_label_widget (GTK_FRAME (frame), label);
	gtk_frame_set_shadow_type (GTK_FRAME (frame), GTK_SHADOW_NONE);
	gtk_box_pack_start (GTK_BOX (hitpagebox), frame, FALSE, FALSE, GNOME_PAD_SMALL);

	scrolledwin = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolledwin),
	                                GTK_POLICY_NEVER,
	                                GTK_POLICY_ALWAYS);

	gtk_box_pack_start (GTK_BOX (hitpagebox), scrolledwin, TRUE, TRUE, 0);

	/* Pack the treeview into the scrolled window  */
	gtk_container_add (GTK_CONTAINER (scrolledwin), hitview);
	hitview_add_columns (GTK_TREE_VIEW (hitview));
	gtk_tree_view_set_rules_hint (GTK_TREE_VIEW (hitview), TRUE);
	gtk_tree_view_set_search_column (GTK_TREE_VIEW (hitview),
		HITCOL_TIME);

	g_signal_connect (G_OBJECT (hitview), "button_press_event",
	                  G_CALLBACK (hitview_button_press_cb), NULL);
	g_signal_connect (G_OBJECT (hitview), "row-activated",
	                  G_CALLBACK (hit_activated_cb), NULL);

	/* The list is by default sorted by time */
	gtk_tree_sortable_set_sort_column_id (GTK_TREE_SORTABLE (hitmodel), HITCOL_TIME, GTK_SORT_ASCENDING);

	/* Some of the columns need special functions for sorting */
	gtk_tree_sortable_set_sort_func (GTK_TREE_SORTABLE (hitmodel), HITCOL_TIME,
	                                 time_sort_func, NULL, NULL);

	gtk_tree_sortable_set_sort_func (GTK_TREE_SORTABLE (hitmodel), HITCOL_PORT,
	                                 num_sort_func, (gpointer)HITCOL_PORT, NULL);

	gtk_tree_sortable_set_sort_func (GTK_TREE_SORTABLE (hitmodel), HITCOL_LENGTH,
	                                 num_sort_func, (gpointer)HITCOL_LENGTH, NULL);

	g_object_unref (G_OBJECT (hitmodel));

	/* Default icon states */
	menus_events_clear_enabled (FALSE);
	menus_events_save_enabled (FALSE);

	gtk_widget_show_all (hitpagebox);
	return hitpagebox;
}
