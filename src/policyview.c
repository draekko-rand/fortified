/*---[ policyview.c ]-------------------------------------------------
 * Copyright (C) 2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * The traffic policy editor page
 *--------------------------------------------------------------------*/

#include <config.h>
#include <gnome.h>
#include <stdarg.h>
#include <sys/wait.h>

#include "policyview.h"
#include "gui.h"
#include "globals.h"
#include "preferences.h"
#include "menus.h"
#include "fortified.h"
#include "util.h"
#include "scriptwriter.h"
#include "service.h"

#define RULEVIEW_HEIGHT 110

static GtkTreeView *modifying_view, *selected_view;
static GtkWidget *in_allow_from, *in_allow_service, *in_forward,
	*out_deny_from, *out_deny_to, *out_deny_service,
	*out_allow_from, *out_allow_to, *out_allow_service;

static gboolean modified_inbound, modified_outbound, modifications_require_restart;

static GtkWidget *inbound_group;
static GtkWidget *outbound_group;

/* Feature mask for a target selector widget */
typedef enum
{
	TARGET_ANYONE   = 1 << 1,
	TARGET_FIREWALL = 1 << 2,
	TARGET_LAN      = 1 << 3,
	TARGET_HOST     = 1 << 4,
	TARGET_ALL      = 0x3FFFFE
} TargetMask;

/* The different types of policy widgets implemented */
enum
{
	RULE_HOST_SELECTOR,
	RULE_SERVICE_SELECTOR,
	RULE_TARGET_SELECTOR,
	RULE_FORWARD_SELECTOR,
	RULE_COMMENT
} ;

enum
{
	POLICY_GROUP_INBOUND,
	POLICY_GROUP_OUTBOUND,
};

static GtkWidget *
embed_in_scrolled_window (GtkWidget *widget)
{
	GtkWidget *window;

	window = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (window), GTK_SHADOW_IN);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (window),
	                                GTK_POLICY_NEVER,
	                                GTK_POLICY_AUTOMATIC);

	gtk_container_add (GTK_CONTAINER (window), widget);

	return window;	
}

static void
widget_visibility_sync_toggle (GtkWidget *source, GtkWidget *target) {
	gboolean visible;

	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (source));
	if (visible)
		gtk_widget_show (target);
	else
		gtk_widget_hide (target);
}

/* [ append_to_view ]
 * Append rule data to a rule view
 * Either pass the view to be appended to, OR the already initialized store and iter
 */
static gboolean
append_to_view (GtkTreeView *view, GtkListStore *user_store, GtkTreeIter *user_iter, gchar *data)
{
	GtkTreeIter *iter;
	GtkListStore *store;

	gchar **tokens;
	gchar *token;
	gint elements_read;
	gint i, columns;


	if (view == NULL) {
		iter = user_iter;
		store = user_store;
	} else {
		iter = g_new (GtkTreeIter, 1);
		store = (GtkListStore *)gtk_tree_view_get_model(GTK_TREE_VIEW (view));
	}

	columns = gtk_tree_model_get_n_columns (GTK_TREE_MODEL (store));

	tokens = g_strsplit (data, ",", -1);
	for (i = 0, token = tokens[0]; token != NULL; i++) {
		token = tokens[i];
	}
	elements_read = i-1;

	if (elements_read != columns) { /* Check that the rule entry has the correct number of parameters */
		g_printerr ("Malformed user rule encountered: %s. Cause: insufficient elements!\n", data);
		g_free (data);
		g_strfreev (tokens);
		return FALSE;
	}

	gtk_list_store_append (store, iter);

	for (i = 0; i < columns; i++) {
		token = g_strstrip (tokens[i]);

		if (gtk_tree_model_get_column_type (GTK_TREE_MODEL (store), i) == G_TYPE_INT)
			gtk_list_store_set (store, iter, i, atoi(token), -1);
		else
			gtk_list_store_set (store, iter, i, token, -1);
	}

	if (preferences_get_bool (PREFS_APPLY_POLICY_INSTANTLY))
		policyview_apply ();
	else
		menus_policy_apply_enabled (TRUE);

	g_strfreev (tokens);
	if (view != NULL)
		g_free (iter);
	return TRUE;
}

/* [ reload_view ]
 * Reload the data in a view from a rule file
 */
static void
reload_view (GtkTreeView *view, gchar *path)
{
	GtkTreeIter iter;
	GtkListStore *store;
	GIOChannel* in;
	GError *error = NULL;
	gchar *line;

	store = (GtkListStore *)gtk_tree_view_get_model(GTK_TREE_VIEW (view));
	in = g_io_channel_new_file (path, "r", &error);
	
	if (in == NULL) {
		g_printerr ("Error reading file %s: %s\n", path, error->message);
		return;
	}

	while (g_io_channel_read_line (in, &line, NULL, NULL, &error) == G_IO_STATUS_NORMAL) {
		if (g_str_has_prefix(g_strstrip (line), "#")) /* Skip comments */
			continue;

		append_to_view (NULL, store, &iter, line);
	}

	g_io_channel_shutdown (in, FALSE, NULL);
}

static void
rule_dialog_reset (GtkDialog *dialog)
{
	GtkWidget *element = NULL;

	element = g_object_get_data (G_OBJECT (dialog), "host_selector");
	if (element) {
		gtk_entry_set_text (GTK_ENTRY (element), "");
		gtk_widget_grab_focus (element); /* Reset focus */
	}

	element = g_object_get_data (G_OBJECT (dialog), "service_selector_service");
	if (element) {
		element = gtk_bin_get_child (GTK_BIN (element));
		gtk_entry_set_text (GTK_ENTRY (element), "");
		element = g_object_get_data (G_OBJECT (dialog), "service_selector_port");
		gtk_entry_set_text (GTK_ENTRY (element), "");
	}
	
	element = g_object_get_data (G_OBJECT (dialog), "target_selector_anyone");
	if (element) {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (element), TRUE); /* Reset the dialog */
		element = g_object_get_data (G_OBJECT (dialog), "target_selector_host");
		gtk_entry_set_text (GTK_ENTRY (element), "");
	}

	element = g_object_get_data (G_OBJECT (dialog), "forward_selector_host");
	if (element) {
		gtk_entry_set_text (GTK_ENTRY (element), "");
		element = g_object_get_data (G_OBJECT (dialog), "forward_selector_port");
		gtk_entry_set_text (GTK_ENTRY (element), "");
	}

	element = g_object_get_data (G_OBJECT (dialog), "comment");
	if (element) {
		gtk_entry_set_text (GTK_ENTRY (element), "");
	}

	GtkTreeIter *iter = g_object_steal_data (G_OBJECT (dialog), "editing");
	if (iter)
		g_free(iter);
}

static gboolean
rule_dialog_validate_data (GtkDialog *dialog)
{
	GtkWidget *element = NULL;
	GtkWidget *toggle;

	element = g_object_get_data (G_OBJECT (dialog), "host_selector");
	if (element) {
		if (!is_a_valid_host (gtk_entry_get_text (GTK_ENTRY (element)))) {
			error_dialog (_("Invalid host"),
			              _("Invalid host"),
				      _("The host you have specified is not a valid host,\n"
			                "please review your choice."),
			              Fortified.window);
			return FALSE;
		}
	}

	element = g_object_get_data (G_OBJECT (dialog), "service_selector_port");
	if (element) {
		if (!is_a_valid_port (gtk_entry_get_text (GTK_ENTRY (element)))) {
			error_dialog (_("Invalid port"),
			              _("Invalid port"),
				      _("The port you have specified is not a valid port,\n"
			                "please review your choice."),
			              Fortified.window);
			return FALSE;
		}
	}
	
	element = g_object_get_data (G_OBJECT (dialog), "target_selector_host");
	toggle = g_object_get_data (G_OBJECT (dialog), "target_selector_ip");
	if (element &&
	    gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (toggle))) {
		if (!is_a_valid_host (gtk_entry_get_text (GTK_ENTRY (element)))) {
			error_dialog (_("Invalid host"),
			              _("Invalid host"),
				      _("The host you have specified is not a valid host,\n"
			                "please review your choice."),
			              Fortified.window);
			return FALSE;
		}
	}

	element = g_object_get_data (G_OBJECT (dialog), "forward_selector_host");
	if (element) {
		if (!is_a_valid_host (gtk_entry_get_text (GTK_ENTRY (element)))) {
			error_dialog (_("Invalid internal host"),
			              _("Invalid internal host"),
				      _("The host you have specified is not a valid host,\n"
			                "please review your choice."),
			              Fortified.window);
			return FALSE;
		}
		element = g_object_get_data (G_OBJECT (dialog), "forward_selector_port");
		if (!is_a_valid_port (gtk_entry_get_text (GTK_ENTRY (element)))) {
			error_dialog (_("Invalid internal port"),
			              _("Invalid internal port"),
				      _("The port you have specified is not a valid port,\n"
			                "please review your choice."),
			              Fortified.window);
			return FALSE;
		}
	}

	return TRUE;
}

static void unescape_string (gchar *src, gchar *dst)
{
	char c;

	while ((c = *src++) != '\0') {
		switch (c) {
		  case '\\':
		    switch (c = *src++) {
			case 'c':
			  *dst++ = ',';
			  break;
			case '\0':
			  *src--;
			default:
			  *dst++ = '\\'; 
			  break;
		    }
		    break;
		  default:
		    *dst++ = c;
		    break;
		}
	}

	*dst = 0;
}

static void escape_string (gchar *src, gchar *dst)
{
	char c;

	while ((c = *src++) != '\0') {
		switch (c) {
		  case ',':
		     *dst++ = '\\';
		     *dst++ = 'c';
		     break;
		  default:
		    *dst++ = c;
		    break;
		}
	}

	*dst = 0;
}

static gchar*
rule_dialog_extract_data (GtkDialog *dialog)
{
	GtkWidget *element = NULL;
	gchar *data = "";

	element = g_object_get_data (G_OBJECT (dialog), "host_selector");
	if (element) {
		data = g_strconcat (data, ", ", gtk_entry_get_text (GTK_ENTRY (element)), NULL);
	}

	element = g_object_get_data (G_OBJECT (dialog), "service_selector_service");
	if (element) {
		element = gtk_bin_get_child (GTK_BIN (element));
		data = g_strconcat (data, ", ", gtk_entry_get_text (GTK_ENTRY (element)), NULL);
			
		element = g_object_get_data (G_OBJECT (dialog), "service_selector_port");
		data = g_strconcat (data, ", ", gtk_entry_get_text (GTK_ENTRY (element)), NULL);
	}

	element = g_object_get_data (G_OBJECT (dialog), "target_selector_anyone");
	if (element) {
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (element)))
			data = g_strconcat (data, ", everyone", NULL);

		element = g_object_get_data (G_OBJECT (dialog), "target_selector_firewall");
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (element)))
			data = g_strconcat (data, ", firewall", NULL);
			
		element = g_object_get_data (G_OBJECT (dialog), "target_selector_lan");
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (element)))
			data = g_strconcat (data, ", lan", NULL);

		element = g_object_get_data (G_OBJECT (dialog), "target_selector_ip");
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (element))) {
			element = g_object_get_data (G_OBJECT (dialog), "target_selector_host");
			data = g_strconcat (data, ", ", gtk_entry_get_text (GTK_ENTRY (element)), NULL);
		}
	}

	element = g_object_get_data (G_OBJECT (dialog), "forward_selector_host");
	if (element) {
		data = g_strconcat (data, ", ", gtk_entry_get_text (GTK_ENTRY (element)), NULL);

		element = g_object_get_data (G_OBJECT (dialog), "forward_selector_port");
		data = g_strconcat (data, ", ", gtk_entry_get_text (GTK_ENTRY (element)), NULL);
	}

	element = g_object_get_data (G_OBJECT (dialog), "comment");
	if (element) {
		gchar *text, *buf;

		text = g_strdup (gtk_entry_get_text (GTK_ENTRY (element)));
		buf = malloc (strlen (text) * 2);
		
		escape_string (text, buf);
		data = g_strconcat (data, ", ", buf, NULL);
		g_free (buf);
	}

	g_strstrip (data);
	if (g_str_has_prefix (data, ", ")) {
		return data+2;
	} else
		return data;
}

static void
rule_dialog_response_cb (GtkDialog *dialog,
                         gint response_id,
                         gpointer user_data)
{
	if (response_id == GTK_RESPONSE_ACCEPT) {
		gchar *data;

		if (!rule_dialog_validate_data (dialog))
			return;

		data = rule_dialog_extract_data (dialog);

		if (data != NULL) {
			gchar *rule_file = g_object_get_data (G_OBJECT (modifying_view), "rule_file");
			GtkTreeIter *iter = g_object_steal_data (G_OBJECT (dialog), "editing");

			if (iter) { /* Modifying an existing entry */
				GtkTreeModel *model;
				gint *position;
				
				model = gtk_tree_view_get_model (GTK_TREE_VIEW (modifying_view));
				position = g_object_steal_data (G_OBJECT (dialog), "position");
				gtk_list_store_remove (GTK_LIST_STORE (model), iter); /* Remove from the view */
				remove_line_from_file (rule_file, (int)position);

				g_free (iter);
			}

			append_to_file (rule_file, data, TRUE);
			if (g_strrstr (rule_file, "inbound")) {
				if (modifying_view == GTK_TREE_VIEW (in_forward))
					modifications_require_restart = TRUE;
				else
					modified_inbound = TRUE;
			} else
				modified_outbound = TRUE;
			append_to_view (GTK_TREE_VIEW (modifying_view), NULL, NULL, data);

		}
	}

	gtk_widget_hide (GTK_WIDGET (dialog));
	rule_dialog_reset (dialog);
	modifying_view = NULL;
	menus_policy_edit_enabled (FALSE);
	menus_policy_remove_enabled (FALSE);
}

static void
activate_dialog_cb (GtkWidget *dialog)
{
	gtk_dialog_response (GTK_DIALOG (dialog), GTK_RESPONSE_ACCEPT);
}

static GtkWidget *
create_dialog_header (gchar *title, GtkWidget *dialog)
{
	GtkWidget *vbox, *catbox, *label;

	vbox = gtk_vbox_new (FALSE, 14);
	gtk_box_pack_start  (GTK_BOX (GTK_DIALOG (dialog)->vbox), vbox, FALSE, FALSE, 8);
	catbox = gtk_vbox_new (FALSE, 6);
	gtk_box_pack_start (GTK_BOX (vbox), catbox, FALSE, FALSE, 0);

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<span weight=\"bold\">", title, "</span>", NULL));
	gtk_misc_set_alignment (GTK_MISC (label), 0, 0.0);
	gtk_box_pack_start (GTK_BOX (catbox), label, FALSE, FALSE, 0);

	return catbox;
}

static GtkWidget *
create_indented_box (GtkWidget *parent)
{
	GtkWidget *hbox, *vbox, *label, *rowbox;

	hbox = gtk_hbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (parent), hbox, FALSE, FALSE, 0);

	label = gtk_label_new ("    ");
	gtk_box_pack_start (GTK_BOX (hbox), label, FALSE, FALSE, 0);

	vbox = gtk_vbox_new (FALSE, 6);
	gtk_box_pack_start (GTK_BOX (hbox), vbox, FALSE, FALSE, 0);

	rowbox = gtk_hbox_new (FALSE, 6);
	gtk_box_pack_start (GTK_BOX (vbox), rowbox, FALSE, FALSE, 0);

	return rowbox;
}

static void
add_host_selector (gchar *title, GtkWidget *dialog)
{
	GtkWidget *label;
	GtkWidget *catbox;
	GtkWidget *rowbox;
	GtkWidget *entry;

	catbox = create_dialog_header (title, dialog);
	rowbox = create_indented_box (catbox);

	label = gtk_label_new (_("IP, host or network"));
	gtk_misc_set_alignment (GTK_MISC (label), 0, 0.5);

	gtk_box_pack_start (GTK_BOX (rowbox), label, FALSE, FALSE, 0);

	entry = gtk_entry_new ();
	g_object_set_data (G_OBJECT (dialog), "host_selector", entry);
	gtk_widget_set_size_request (entry, 150, -1);
	g_signal_connect_swapped (G_OBJECT (entry), "activate",
	                          G_CALLBACK (activate_dialog_cb), G_OBJECT (dialog));
	gtk_box_pack_start (GTK_BOX (rowbox), entry, FALSE, FALSE, 0);
}

/* Update the port suggestions when the user selects a named service */
static void
update_ports_from_service (GtkComboBox *combo, GtkWidget *dialog)
{
	GtkTreeIter iter;

	if (gtk_combo_box_get_active_iter (combo, &iter)) {
		GtkTreeModel *model;
		gchar *ports;
		GtkWidget *entry;

		model = gtk_combo_box_get_model (combo);
		gtk_tree_model_get (model, &iter, 1, &ports, -1);

		/* Update the firewall hosts port range with the ports of the service */
		entry = g_object_get_data (G_OBJECT (dialog), "service_selector_port");
		gtk_entry_set_text (GTK_ENTRY (entry), ports);
		/* Update the internal port range with the ports of the service */
		entry = g_object_get_data (G_OBJECT (dialog), "forward_selector_port");
		if (entry != NULL)
			gtk_entry_set_text (GTK_ENTRY (entry), ports);
	}
}

/* Suggest a service name when the user manually enters a port number */
static gboolean
resolve_port_to_service (GtkEntry *entry, GdkEventKey *event, GtkWidget *combo)
{
	const gchar *port;

	port = gtk_entry_get_text (entry);

	if (strlen (port) > 1) {
		gchar *service;
		GtkWidget *service_entry;

		service = service_get_name (atoi(port), "tcp");
		service_entry = gtk_bin_get_child (GTK_BIN (combo));
		gtk_entry_set_text (GTK_ENTRY (service_entry), service);

		g_free (service);
	}

	return FALSE;
}

static void
add_service_selector (gchar *title, GtkWidget *dialog)
{
	GtkSizeGroup *sizegroup;
	GtkWidget *combo;
	GtkWidget *entry;
	GtkWidget *label;
	GtkWidget *catbox, *rowbox;

	catbox = create_dialog_header (title, dialog);
	rowbox = create_indented_box (catbox);

	sizegroup = gtk_size_group_new (GTK_SIZE_GROUP_BOTH);
		
	label = gtk_label_new (_("Name"));
	gtk_size_group_add_widget (sizegroup, label);
	gtk_misc_set_alignment (GTK_MISC (label), 0, 0.5);
	gtk_box_pack_start (GTK_BOX (rowbox), label, FALSE, FALSE, 0);

	combo = gtk_combo_box_entry_new_with_model (GTK_TREE_MODEL (services_get_model ()), 0);
	gtk_widget_set_size_request (combo, 100, -1);
	g_object_set_data (G_OBJECT (dialog), "service_selector_service", combo);
	entry = gtk_bin_get_child (GTK_BIN (combo));
	g_signal_connect_swapped (G_OBJECT (entry), "activate",
	                          G_CALLBACK (activate_dialog_cb), G_OBJECT (dialog));
	gtk_box_pack_start (GTK_BOX (rowbox), combo, FALSE, FALSE, 0);

	rowbox = create_indented_box (catbox);
		
	label = gtk_label_new (_("Port"));
	gtk_size_group_add_widget (sizegroup, label);
	gtk_misc_set_alignment (GTK_MISC (label), 0, 0.5);
	gtk_box_pack_start (GTK_BOX (rowbox), label, FALSE, FALSE, 0);

	entry = gtk_entry_new ();
	gtk_widget_set_size_request (entry, 100, -1);
	g_object_set_data (G_OBJECT (dialog), "service_selector_port", entry);
	g_signal_connect_swapped (G_OBJECT (entry), "activate",
	                          G_CALLBACK (activate_dialog_cb), G_OBJECT (dialog));
	g_signal_connect (G_OBJECT (entry), "key-release-event",
	                  G_CALLBACK (resolve_port_to_service), combo);
	gtk_box_pack_start (GTK_BOX (rowbox), entry, FALSE, FALSE, 0);

	g_signal_connect (G_OBJECT (combo), "changed",
	                  G_CALLBACK (update_ports_from_service), dialog);

}

static void
add_target_selector (gchar *title, TargetMask mask, GtkWidget *dialog)
{
	GtkWidget *catbox, *rowbox;
	GtkWidget *anyone, *firewall, *lan, *ip;

	catbox = create_dialog_header (title, dialog);
	rowbox = create_indented_box (catbox);

	anyone = gtk_radio_button_new_with_label (NULL, _("Anyone"));
	g_object_set_data (G_OBJECT (dialog), "target_selector_anyone", anyone);
	firewall = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON (anyone), _("Firewall host"));
	g_object_set_data (G_OBJECT (dialog), "target_selector_firewall", firewall);
	lan = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON (firewall), _("LAN clients"));
	g_object_set_data (G_OBJECT (dialog), "target_selector_lan", lan);
	ip = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON (lan), _("IP, host or network"));
	g_object_set_data (G_OBJECT (dialog), "target_selector_ip", ip);

	if (mask & TARGET_ANYONE) {
		gtk_box_pack_start (GTK_BOX (rowbox), anyone, FALSE, FALSE, 0);
	}
	if (mask & TARGET_FIREWALL) {
		gtk_box_pack_start (GTK_BOX (rowbox), firewall, FALSE, FALSE, 0);
	}
	if (mask & TARGET_LAN) {
		gtk_box_pack_start (GTK_BOX (rowbox), lan, FALSE, FALSE, 0);
	}
	if (mask & TARGET_HOST) {
		GtkWidget *entry;

		rowbox = create_indented_box (catbox);
		gtk_box_pack_start (GTK_BOX (rowbox), ip, FALSE, FALSE, 0);

		entry = gtk_entry_new ();
		g_object_set_data (G_OBJECT (dialog), "target_selector_host", entry);
		gtk_widget_set_size_request (entry, 120, -1);
		g_signal_connect_swapped (G_OBJECT (entry), "activate",
		                          G_CALLBACK (activate_dialog_cb), G_OBJECT (dialog));

		gtk_box_pack_start (GTK_BOX (rowbox), entry, FALSE, FALSE, 0);
		gtk_widget_set_sensitive (entry, FALSE);
		gui_widget_sensitivity_sync (GTK_TOGGLE_BUTTON (ip), entry);
	}
}

static void
add_forward_selector (gchar *title, GtkWidget *dialog)
{
	GtkSizeGroup *sizegroup;
	GtkWidget *entry;
	GtkWidget *label;
	GtkWidget *catbox, *rowbox;

	catbox = create_dialog_header (title, dialog);
	rowbox = create_indented_box (catbox);

	sizegroup = gtk_size_group_new (GTK_SIZE_GROUP_BOTH);
		
	label = gtk_label_new (_("IP or host"));
	gtk_size_group_add_widget (sizegroup, label);
	gtk_misc_set_alignment (GTK_MISC (label), 0, 0.5);
	gtk_box_pack_start (GTK_BOX (rowbox), label, FALSE, FALSE, 0);

	entry = gtk_entry_new ();
	gtk_widget_set_size_request (entry, 150, -1);
	g_object_set_data (G_OBJECT (dialog), "forward_selector_host", entry);
	g_signal_connect_swapped (G_OBJECT (entry), "activate",
	                          G_CALLBACK (activate_dialog_cb), G_OBJECT (dialog));
	gtk_box_pack_start (GTK_BOX (rowbox), entry, FALSE, FALSE, 0);

	rowbox = create_indented_box (catbox);
		
	label = gtk_label_new (_("Port"));
	gtk_size_group_add_widget (sizegroup, label);
	gtk_misc_set_alignment (GTK_MISC (label), 0, 0.5);
	gtk_box_pack_start (GTK_BOX (rowbox), label, FALSE, FALSE, 0);

	entry = gtk_entry_new ();
	gtk_widget_set_size_request (entry, 100, -1);
	g_object_set_data (G_OBJECT (dialog), "forward_selector_port", entry);
	g_signal_connect_swapped (G_OBJECT (entry), "activate",
	                          G_CALLBACK (activate_dialog_cb), G_OBJECT (dialog));
	gtk_box_pack_start (GTK_BOX (rowbox), entry, FALSE, FALSE, 0);
}

static void
add_comment_space (gchar *title, GtkWidget *dialog)
{
	GtkWidget *catbox;
	GtkWidget *rowbox;
	GtkWidget *entry;
	GtkWidget *hbox, *vbox;
	GtkWidget *label;

	catbox = create_dialog_header (title, dialog);
	hbox = gtk_hbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (catbox), hbox, FALSE, FALSE, 0);
	label = gtk_label_new ("    ");
	gtk_box_pack_start (GTK_BOX (hbox), label, FALSE, FALSE, 0);
	vbox = gtk_vbox_new (FALSE, 6);
	gtk_box_pack_start (GTK_BOX (hbox), vbox, TRUE, TRUE, 0);
	rowbox = gtk_hbox_new (FALSE, 6);
	gtk_box_pack_start (GTK_BOX (vbox), rowbox, FALSE, FALSE, 0);

	entry = gtk_entry_new ();
	g_object_set_data (G_OBJECT (dialog), "comment", entry);
	g_signal_connect_swapped (G_OBJECT (entry), "activate",
	                          G_CALLBACK (activate_dialog_cb), G_OBJECT (dialog));
	gtk_box_pack_start (GTK_BOX (rowbox), entry, TRUE, TRUE, 0);
}

static gboolean
rule_dialog_delete_request_cb (GtkWidget *widget, GdkEvent *event)
{
	return TRUE;
}

static GtkWidget *
create_dialog (gchar *title, ...)
{
	GtkWidget *dialog;
	va_list ap;

	dialog = gtk_dialog_new_with_buttons (title,
	                                      GTK_WINDOW (Fortified.window),
	                                      GTK_DIALOG_DESTROY_WITH_PARENT | GTK_DIALOG_NO_SEPARATOR,
	                                      /* GTK_STOCK_HELP, GTK_RESPONSE_HELP, */
	                                      GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
	                                      GTK_STOCK_ADD, GTK_RESPONSE_ACCEPT,
	                                      NULL);	

	gtk_container_set_border_width (GTK_CONTAINER (dialog), 8);

	g_signal_connect (G_OBJECT (dialog), "response",
	                  G_CALLBACK (rule_dialog_response_cb), NULL);
	/* Keep the dialog from being destroyed */
	g_signal_connect (G_OBJECT (dialog), "delete-event",
	                  G_CALLBACK (rule_dialog_delete_request_cb), NULL);

	va_start (ap, title);
	gint arg = va_arg (ap, gint);
	while (arg != -1) {
		char *widget_title;
		widget_title = va_arg (ap, char *);
	
		if (arg == RULE_HOST_SELECTOR) {
			add_host_selector (widget_title, dialog);
		} else if (arg == RULE_SERVICE_SELECTOR) {
			add_service_selector (widget_title, dialog);
		} else if (arg == RULE_TARGET_SELECTOR) {
			TargetMask mask;
			
			mask = va_arg (ap, TargetMask);
			add_target_selector (widget_title, mask, dialog);
		}  else if (arg == RULE_FORWARD_SELECTOR) {
			add_forward_selector (widget_title, dialog);
		} else if (arg == RULE_COMMENT) {
			add_comment_space (widget_title, dialog);
		}
		
		
		arg = va_arg (ap, gint);
	}

	va_end (ap);

	gtk_window_set_resizable (GTK_WINDOW (dialog), FALSE);

	return dialog;
}

static void
dialog_update_nat_widgets (GtkWidget *dialog)
{
	GtkWidget *element;

	element = g_object_get_data (G_OBJECT (dialog), "target_selector_lan");
	if (element)
		gtk_widget_set_sensitive (element, preferences_get_bool (PREFS_FW_NAT));
}

void
policyview_edit_rule (void)
{
	GtkWidget *dialog;
	GtkTreeSelection *selected;
	GtkTreeModel *model;
	GtkTreeIter *iter;

	if (modifying_view != NULL)
		return;

	iter = g_new (GtkTreeIter, 1);
	selected = gtk_tree_view_get_selection (selected_view);
	modifying_view = selected_view;
	dialog = g_object_get_data (G_OBJECT (modifying_view), "dialog");

	if (gtk_tree_selection_get_selected (selected, &model, iter)) {
		GtkTreePath* path;
		gint pos;
		gchar *data;
		gchar *comment;
		gchar *buf;
		GtkWidget *element;

		path = gtk_tree_model_get_path (model, iter);
		pos = gtk_tree_path_get_indices(path)[0];

		if (GTK_WIDGET (modifying_view) == in_allow_from ||
		    GTK_WIDGET (modifying_view) == out_deny_from ||
		    GTK_WIDGET (modifying_view) == out_deny_to ||
		    GTK_WIDGET (modifying_view) == out_allow_from ||
		    GTK_WIDGET (modifying_view) == out_allow_to) {

			gtk_tree_model_get (model, iter, 0, &data, -1);
			element = g_object_get_data (G_OBJECT (dialog), "host_selector");
			gtk_entry_set_text (GTK_ENTRY (element), data);
			
			gtk_tree_model_get (model, iter, 1, &comment, -1);
		} else if (GTK_WIDGET (modifying_view) == in_allow_service ||
		           GTK_WIDGET (modifying_view) == out_deny_service ||
			   GTK_WIDGET (modifying_view) == out_allow_service) {

			gchar *service, *port, *target;

			gtk_tree_model_get (model, iter, 0, &service, 1, &port, 2, &target, -1);
			element = g_object_get_data (G_OBJECT (dialog), "service_selector_service");
			element = gtk_bin_get_child (GTK_BIN (element));
			gtk_entry_set_text (GTK_ENTRY (element), service);
			element = g_object_get_data (G_OBJECT (dialog), "service_selector_port");
			gtk_entry_set_text (GTK_ENTRY (element), port);

			if (g_str_equal (target, "everyone")) {
				element = g_object_get_data (G_OBJECT (dialog), "target_selector_anyone");
			} else if (g_str_equal (target, "firewall")) {
				element = g_object_get_data (G_OBJECT (dialog), "target_selector_firewall");
			} else if (g_str_equal (target, "lan")) {
				element = g_object_get_data (G_OBJECT (dialog), "target_selector_lan");
			} else {
				GtkWidget *entry;
				entry = g_object_get_data (G_OBJECT (dialog), "target_selector_host");
				gtk_entry_set_text (GTK_ENTRY (entry), target);
				element = g_object_get_data (G_OBJECT (dialog), "target_selector_ip");
			}
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (element), TRUE);
			
			gtk_tree_model_get (model, iter, 3, &comment, -1);
		} else if (GTK_WIDGET (modifying_view) == in_forward) {
			gchar *service, *port, *target_host, *target_port;
			
			gtk_tree_model_get (model, iter, 0, &service, 1, &port, 2, &target_host, 3, &target_port, -1);
			element = g_object_get_data (G_OBJECT (dialog), "service_selector_service");
			element = gtk_bin_get_child (GTK_BIN (element));
			gtk_entry_set_text (GTK_ENTRY (element), service);
			element = g_object_get_data (G_OBJECT (dialog), "service_selector_port");
			gtk_entry_set_text (GTK_ENTRY (element), port);
			
			element = g_object_get_data (G_OBJECT (dialog), "forward_selector_host");
			gtk_entry_set_text (GTK_ENTRY (element), target_host);
			element = g_object_get_data (G_OBJECT (dialog), "forward_selector_port");
			gtk_entry_set_text (GTK_ENTRY (element), target_port);

			gtk_tree_model_get (model, iter, 4, &comment, -1);
		}

		element = g_object_get_data (G_OBJECT (dialog), "comment");
		buf = malloc (strlen (comment));
		unescape_string (comment, buf);
		gtk_entry_set_text (GTK_ENTRY (element), buf);
		
		g_free (comment);

		g_object_set_data (G_OBJECT (dialog), "editing", iter);
		g_object_set_data (G_OBJECT (dialog), "position", (gint *)pos);
		dialog_update_nat_widgets (dialog);
		gtk_widget_show_all (dialog);

		gtk_tree_path_free (path);
	}

}

void
policyview_add_rule (void)
{
	GtkWidget *dialog;

	if (modifying_view != NULL)
		return;

	modifying_view = selected_view;
	dialog = g_object_get_data (G_OBJECT (modifying_view), "dialog");

	dialog_update_nat_widgets (dialog);
	gtk_widget_show_all (dialog);
}

void
policyview_remove_rule (void)
{
	GtkTreeSelection *selected;
	GtkTreeModel *model;
	GtkTreeIter iter;

	selected = gtk_tree_view_get_selection (selected_view);
	if (gtk_tree_selection_get_selected (selected, &model, &iter)) {
		GtkTreePath* path;
		gint pos;
		gchar *rule_file;

		path = gtk_tree_model_get_path (model, &iter);
		pos = gtk_tree_path_get_indices(path)[0];

		gtk_list_store_remove (GTK_LIST_STORE (model), &iter); /* Remove from the view */
		rule_file = g_object_get_data (G_OBJECT (selected_view), "rule_file");
		remove_line_from_file (rule_file, pos); /* Remove from the rule file*/

		if (g_strrstr (rule_file, "inbound")) {
			if (selected_view == GTK_TREE_VIEW (in_forward))
				modifications_require_restart = TRUE;
			else
				modified_inbound = TRUE;
		} else
			modified_outbound = TRUE;

		gtk_tree_path_free (path);
		menus_policy_edit_enabled (FALSE);
		menus_policy_remove_enabled (FALSE);

		if (preferences_get_bool (PREFS_APPLY_POLICY_INSTANTLY))
			policyview_apply ();
		else
			menus_policy_apply_enabled (TRUE);
	}
}

/* [ ruleview_button_cb ]
 * Pop up an menu when right clicking the ruleview
 */
static gboolean
ruleview_button_cb (GtkTreeView *view, GdkEventButton *event, GtkWidget *menu)
{
	gboolean retval = FALSE;

	if (selected_view != view) {
		menus_policy_edit_enabled (FALSE);
		menus_policy_remove_enabled (FALSE);
	} else if (gtk_tree_selection_count_selected_rows(gtk_tree_view_get_selection (view))) {
		menus_policy_edit_enabled (TRUE);
		menus_policy_remove_enabled (TRUE);
	}

	selected_view = view;
	menus_policy_add_enabled (TRUE);

	switch (event->button) {
		case 1: break;
		case 3:	gtk_menu_popup (GTK_MENU (menu), NULL, NULL, NULL, NULL, 
                  	                event->button, event->time);
			retval = TRUE;
			break;
	}

	return retval;
}

static gboolean
ruleview_selection_cb (GtkTreeView *view, gboolean arg1, gpointer data)
{
	menus_policy_edit_enabled (TRUE);
	menus_policy_remove_enabled (TRUE);
	return TRUE;
}

static void
set_outbound_mode (GtkToggleButton *toggle)
{
	preferences_set_bool (PREFS_FW_RESTRICTIVE_OUTBOUND_MODE,
		gtk_toggle_button_get_active (toggle));
	modifications_require_restart = TRUE;

	if (preferences_get_bool (PREFS_APPLY_POLICY_INSTANTLY))
		policyview_apply ();
	else
		menus_policy_apply_enabled (TRUE);
}

void
policyview_reload_inbound_policy (void)
{
	gint retval;
	gchar *arg[3] = {"fortified.sh", "reload-inbound-policy", NULL};
	gchar *output;
	GError *error = NULL;

	if (g_spawn_sync (FORTIFIED_RULES_DIR "/fortified",
	                  arg, NULL,
	                  G_SPAWN_STDERR_TO_DEV_NULL,
	                  NULL, NULL,
	                  &output, /* Standard output */
	                  NULL, /* Standard error */
	                  &retval, &error) != TRUE) {
		printf ("Error spawning shell process: %s\n", error->message);
	}

	printf ("%s", output);

	if (retval != 0) {
		retval = WEXITSTATUS (retval);
	
		error_dialog (_("Failed to apply policy"),
		              _("Failed to apply inbound policy"),
		              g_strconcat (_("There was an error when applying the inbound policy:"),
		                          "\n", output, NULL),
		              Fortified.window);
	}
	g_free (output);
}

void
policyview_reload_outbound_policy (void)
{
	gint retval;
	gchar *arg[3] = {"fortified.sh", "reload-outbound-policy", NULL};
	gchar *output;
	GError *error = NULL;

	if (g_spawn_sync (FORTIFIED_RULES_DIR "/fortified",
	                  arg, NULL,
	                  G_SPAWN_STDERR_TO_DEV_NULL,
	                  NULL, NULL,
	                  &output, /* Standard output */
	                  NULL, /* Standard error */
	                  &retval, &error) != TRUE) {
		printf ("Error spawning shell process: %s\n", error->message);
	}

	printf ("%s", output);

	if (retval != 0) {
		retval = WEXITSTATUS (retval);
	
		error_dialog (_("Failed to apply policy"),
		              _("Failed to apply outbound policy"),
		              g_strconcat (_("There was an error when applying the outbound policy:"),
		                          "\n", output, NULL),
		              Fortified.window);
	}
	g_free (output);
}

void
policyview_apply (void)
{
	if (modifications_require_restart) {
	/* Reload the whole firewall */
		scriptwriter_output_configuration ();
		start_firewall ();
	} else {
	/* Only reload the policy group(s) modified */
		if (modified_inbound)
			policyview_reload_inbound_policy ();
		if (modified_outbound)
			policyview_reload_outbound_policy ();
	}

	modified_inbound = modified_outbound = modifications_require_restart = FALSE;
	menus_policy_apply_enabled (FALSE);
}

static void
clear_ruleview (GtkWidget *view)
{
	GtkTreeModel *model;

	model = gtk_tree_view_get_model (GTK_TREE_VIEW (view));
	gtk_list_store_clear (GTK_LIST_STORE (model));
}

void
policyview_create_rule (RuleType type, Hit *h)
{
	gchar *data = NULL;
	gchar *path = NULL;
	GtkWidget *view = NULL;

	if (type == RULETYPE_INBOUND_ALLOW_FROM) {
		data = g_strconcat (h->source, ", ", NULL);
		view = in_allow_from;
		path = POLICY_IN_ALLOW_FROM;
	} else if (type == RULETYPE_INBOUND_ALLOW_SERVICE) {
		data = g_strconcat (h->service, ", ", h->port, ", everyone", ", ", NULL);
		view = in_allow_service;
		path = POLICY_IN_ALLOW_SERVICE;
	} else if (type == RULETYPE_INBOUND_ALLOW_SERVICE_FROM) {
		data = g_strconcat (h->service, ", ", h->port, ", ", h->source, ", ", NULL);
		view = in_allow_service;
		path = POLICY_IN_ALLOW_SERVICE;
	} else if (type == RULETYPE_OUTBOUND_ALLOW_TO) {
		data = g_strconcat (h->destination, ", ", NULL);
		view = out_allow_to;
		path = POLICY_OUT_ALLOW_TO;
	} else if (type == RULETYPE_OUTBOUND_ALLOW_SERVICE) {
		data = g_strconcat (h->service, ", ", h->port, ", everyone", ", ", NULL);
		view = out_allow_service;
		path = POLICY_OUT_ALLOW_SERVICE;
	} else if (type == RULETYPE_OUTBOUND_ALLOW_SERVICE_FROM) {
		data = g_strconcat (h->service, ", ", h->port, ", ", h->source, ", ", NULL);
		view = out_allow_service;
		path = POLICY_OUT_ALLOW_SERVICE;
	}

	if (data) {
		append_to_file (path, data, TRUE);
		clear_ruleview (view);
		reload_view (GTK_TREE_VIEW (view), path);
		restart_firewall_if_active ();
		menus_policy_apply_enabled (FALSE);
	}
}

/* [ policyview_install_default_ruleset ]
 * Set some sane outbound defaults so the user doesn't lock himself out
 */
void
policyview_install_default_ruleset (void)
{
	Hit *h;

	h = g_new0 (Hit, 1);
	h->service = g_strdup ("DNS");
	h->port = g_strdup ("53");
	policyview_create_rule (RULETYPE_OUTBOUND_ALLOW_SERVICE, h);
	free_hit (h);
	h = g_new0 (Hit, 1);
	h->service = g_strdup ("HTTP");
	h->port = g_strdup ("80");
	policyview_create_rule (RULETYPE_OUTBOUND_ALLOW_SERVICE, h);
	free_hit (h);
	h = g_new0 (Hit, 1);
	h->service = g_strdup ("DHCP");
	h->port = g_strdup ("67-68");
	policyview_create_rule (RULETYPE_OUTBOUND_ALLOW_SERVICE, h);
	free_hit (h);
}

static GtkWidget *
setup_rule_view (View_def *def, gchar *path, GtkWidget *dialog, GtkWidget *menu)
{
	GtkWidget *view;

	view = gui_create_list_view (def, -1, RULEVIEW_HEIGHT);
	reload_view (GTK_TREE_VIEW (view), path);
	g_object_set_data (G_OBJECT (view), "dialog", dialog);
	g_object_set_data (G_OBJECT (view), "rule_file", path);
	g_signal_connect (G_OBJECT (view), "button_press_event",
	                  G_CALLBACK (ruleview_button_cb), menu);
	g_signal_connect (G_OBJECT (view), "cursor-changed",
	                  G_CALLBACK (ruleview_selection_cb), menu);
	g_signal_connect (G_OBJECT (view), "row-activated",
	                  G_CALLBACK (policyview_edit_rule), NULL);
	
	return view;
}

void
poicyview_update_nat_widgets (void)
{
	gboolean nat_enabled;
	
	nat_enabled = preferences_get_bool (PREFS_FW_NAT);

	gtk_widget_set_sensitive (in_forward, nat_enabled);
	gtk_widget_set_sensitive (out_allow_from, nat_enabled);
	gtk_widget_set_sensitive (out_deny_from, nat_enabled);
}

static GtkWidget *
create_inboundpolicy_page (void)
{
	GtkWidget *inbound_box;
	GtkWidget *scrolledwin;
	GtkWidget *menu;
	GtkWidget *dialog;

	/* Definitions of the views */
	View_def in_allow_from_def = {2, {
			{_("Allow connections from host"), G_TYPE_STRING, TRUE},
			{_("Comment"), G_TYPE_STRING, FALSE},
		}
	};
	View_def in_allow_service_def = {4, {
			{_("Allow service"), G_TYPE_STRING, TRUE},
			{_("Port"), G_TYPE_STRING, TRUE},
			{_("For"), G_TYPE_STRING, TRUE},
			{_("Comment"), G_TYPE_STRING, FALSE},
		}
	};
	View_def in_forward_def = {5, {
			{_("Forward service"), G_TYPE_STRING, TRUE},
			{_("Firewall Port"), G_TYPE_STRING, TRUE},
			{_("To"), G_TYPE_STRING, TRUE},
			{_("Port"), G_TYPE_STRING, TRUE},
			{_("Comment"), G_TYPE_STRING, FALSE},
		}
	};

	menu = menus_get_policy_context_menu ();
	inbound_box = gtk_vbox_new (FALSE, 0);

	dialog = create_dialog (_("Add new inbound rule"),
		RULE_HOST_SELECTOR, _("Allow connections from"),
		RULE_COMMENT, _("Comment"),
		-1);
	in_allow_from = setup_rule_view (&in_allow_from_def, POLICY_IN_ALLOW_FROM, dialog, menu);
	scrolledwin = embed_in_scrolled_window (in_allow_from);
	gtk_box_pack_start (GTK_BOX (inbound_box), scrolledwin, TRUE, TRUE, 0);

	dialog = create_dialog (_("Add new inbound rule"),
		RULE_SERVICE_SELECTOR, _("Allow service"),
		RULE_TARGET_SELECTOR, _("When the source is"), TARGET_ANYONE | TARGET_LAN | TARGET_HOST,
		RULE_COMMENT, _("Comment"),
		-1);
	in_allow_service = setup_rule_view (&in_allow_service_def, POLICY_IN_ALLOW_SERVICE, dialog, menu);
	scrolledwin = embed_in_scrolled_window (in_allow_service);
	gtk_box_pack_start (GTK_BOX (inbound_box), scrolledwin, TRUE, TRUE, 0);

	dialog = create_dialog (_("Add new inbound rule"),
		RULE_SERVICE_SELECTOR, _("Forward service from firewall"),
		RULE_FORWARD_SELECTOR, _("To internal host"),
		RULE_COMMENT, _("Comment"),
		-1);
	in_forward = setup_rule_view (&in_forward_def, POLICY_IN_FORWARD, dialog, menu);
	scrolledwin = embed_in_scrolled_window (in_forward);
	gtk_box_pack_start (GTK_BOX (inbound_box), scrolledwin, TRUE, TRUE, 0);

	gtk_widget_show_all (inbound_box);
	return inbound_box;
}

static GtkWidget *
create_outboundpolicy_page (void)
{
	GtkWidget *outbound_box, *permissive_box, *restrictive_box;
	GtkWidget *scrolledwin;
	GtkWidget *label;
	GtkWidget *button;
	GtkWidget *menu;
	GtkWidget *dialog;

	View_def out_deny_to_def = {2, {
			{_("Deny connections to host"), G_TYPE_STRING, TRUE},
			{_("Comment"), G_TYPE_STRING, FALSE},
		}
	};
	View_def out_deny_from_def = {2, {
			{_("Deny connections from LAN host"), G_TYPE_STRING, TRUE},
			{_("Comment"), G_TYPE_STRING, FALSE},
		}
	};
	View_def out_deny_service_def = {4, {
			{_("Deny service"), G_TYPE_STRING, TRUE},
			{_("Port"), G_TYPE_STRING, TRUE},
			{_("For"), G_TYPE_STRING, TRUE},
			{_("Comment"), G_TYPE_STRING, FALSE},
		}
	};

	View_def out_allow_to_def = {2, {
			{_("Allow connections to host"), G_TYPE_STRING, TRUE},
			{_("Comment"), G_TYPE_STRING, FALSE},
		}
	};
	View_def out_allow_from_def = {2, {
			{_("Allow connections from LAN host"), G_TYPE_STRING, TRUE},
			{_("Comment"), G_TYPE_STRING, FALSE},
		}
	};
	View_def out_allow_service_def = {4, {
			{_("Allow service"), G_TYPE_STRING, TRUE},
			{_("Port"), G_TYPE_STRING, TRUE},
			{_("For"), G_TYPE_STRING, TRUE},
			{_("Comment"), G_TYPE_STRING, FALSE},
		}
	};

	menu = menus_get_policy_context_menu ();

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<b>", _("_Outbound traffic"), "</b>", NULL));

	outbound_box = gtk_vbox_new (FALSE, 0);
	permissive_box = gtk_vbox_new (FALSE, 0);
	restrictive_box = gtk_vbox_new (FALSE, 0);

	button = gtk_radio_button_new_with_label (NULL,
		_("Permissive by default, blacklist traffic"));
	gtk_box_pack_start (GTK_BOX (outbound_box), button, FALSE, FALSE, 2);
	g_signal_connect (G_OBJECT (button), "toggled",
	                  G_CALLBACK (widget_visibility_sync_toggle), permissive_box);

	button = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON (button),
		_("Restrictive by default, whitelist traffic"));
	/* Load default outbound mode policy */
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (button),
		preferences_get_bool (PREFS_FW_RESTRICTIVE_OUTBOUND_MODE));
	gtk_box_pack_start (GTK_BOX (outbound_box), button, FALSE, FALSE, 2);
	g_signal_connect (G_OBJECT (button), "toggled",
	                  G_CALLBACK (widget_visibility_sync_toggle), restrictive_box);
	g_signal_connect (G_OBJECT (button), "toggled",
	                  G_CALLBACK (set_outbound_mode), NULL);

/* Out: Permissive */
	gtk_box_pack_start (GTK_BOX (outbound_box), permissive_box, TRUE, TRUE, 0);

	dialog = create_dialog (_("Add new outbound rule"),
		RULE_HOST_SELECTOR, _("Deny connections to"),
		RULE_COMMENT, _("Comment"),
		-1);
	out_deny_to = setup_rule_view (&out_deny_to_def, POLICY_OUT_DENY_TO, dialog, menu);
	scrolledwin = embed_in_scrolled_window (out_deny_to);
	gtk_box_pack_start (GTK_BOX (permissive_box), scrolledwin, TRUE, TRUE, 0);

	dialog = create_dialog (_("Add new outbound rule"),
		RULE_HOST_SELECTOR, _("Deny connections from"),
		RULE_COMMENT, _("Comment"),
		-1);
	out_deny_from = setup_rule_view (&out_deny_from_def, POLICY_OUT_DENY_FROM, dialog, menu);
	scrolledwin = embed_in_scrolled_window (out_deny_from);
	gtk_box_pack_start (GTK_BOX (permissive_box), scrolledwin, TRUE, TRUE, 0);

	dialog = create_dialog (_("Add new outbound rule"),
		RULE_SERVICE_SELECTOR, _("Deny service"),
		RULE_TARGET_SELECTOR, _("When the source is"), TARGET_ALL,
		RULE_COMMENT, _("Comment"),
		-1);
	out_deny_service = setup_rule_view (&out_deny_service_def, POLICY_OUT_DENY_SERVICE, dialog, menu);
	scrolledwin = embed_in_scrolled_window (out_deny_service);
	gtk_box_pack_start (GTK_BOX (permissive_box), scrolledwin, TRUE, TRUE, 0);

/* Out: Restrictive */
	gtk_box_pack_start (GTK_BOX (outbound_box), restrictive_box, TRUE, TRUE, 0);

	dialog = create_dialog (_("Add new outbound rule"),
		RULE_HOST_SELECTOR, _("Allow connections to"),
		RULE_COMMENT, _("Comment"),
		-1);
	out_allow_to = setup_rule_view (&out_allow_to_def, POLICY_OUT_ALLOW_TO, dialog, menu);
	scrolledwin = embed_in_scrolled_window (out_allow_to);
	gtk_box_pack_start (GTK_BOX (restrictive_box), scrolledwin, TRUE, TRUE, 0);

	dialog = create_dialog (_("Add new outbound rule"),
		RULE_HOST_SELECTOR, _("Allow connections from"),
		RULE_COMMENT, _("Comment"),
		-1);
	out_allow_from = setup_rule_view (&out_allow_from_def, POLICY_OUT_ALLOW_FROM, dialog, menu);
	scrolledwin = embed_in_scrolled_window (out_allow_from);
	gtk_box_pack_start (GTK_BOX (restrictive_box), scrolledwin, TRUE, TRUE, 0);

	dialog = create_dialog (_("Add new outbound rule"),
		RULE_SERVICE_SELECTOR, _("Allow service"),
		RULE_TARGET_SELECTOR, _("When the source is"), TARGET_ALL,
		RULE_COMMENT, _("Comment"),
		-1);
	out_allow_service = setup_rule_view (&out_allow_service_def, POLICY_OUT_ALLOW_SERVICE, dialog, menu);
	scrolledwin = embed_in_scrolled_window (out_allow_service);
	gtk_box_pack_start (GTK_BOX (restrictive_box), scrolledwin, TRUE, TRUE, 0);

	if (preferences_get_bool (PREFS_FW_RESTRICTIVE_OUTBOUND_MODE)) {
		gtk_widget_show_all (permissive_box);
		gtk_widget_set_no_show_all (permissive_box, TRUE);
		gtk_widget_hide (permissive_box);
	} else {
		gtk_widget_show_all (restrictive_box);
		gtk_widget_set_no_show_all (restrictive_box, TRUE);
		gtk_widget_hide (restrictive_box);
	}

	return outbound_box;
}

static void
switch_policy_group (GtkComboBox *combo)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	gint policy_group;

	gtk_combo_box_get_active_iter (combo, &iter);
	model = gtk_combo_box_get_model (combo);
	gtk_tree_model_get (model, &iter, 0, &policy_group, -1);
	
	if (policy_group == POLICY_GROUP_INBOUND) {
		gtk_widget_hide (outbound_group);
		gtk_widget_show (inbound_group);
	} else if (policy_group == POLICY_GROUP_OUTBOUND) {
		gtk_widget_hide (inbound_group);
		gtk_widget_show (outbound_group);
	}

	menus_policy_edit_enabled (FALSE);
	menus_policy_remove_enabled (FALSE);
	menus_policy_add_enabled (FALSE);
}

GtkWidget *
create_policyview_page (void)
{
	GtkWidget *policypage;
	GtkWidget *hbox;
	GtkWidget *combo;
	GtkWidget *label;
	GtkCellRenderer *renderer;
	GtkTreeModel *model;
	GtkTreeIter iter;

	policypage = gtk_vbox_new (FALSE, 0);

	model = (GtkTreeModel *)gtk_list_store_new (2, G_TYPE_INT, G_TYPE_STRING);

	gtk_list_store_append (GTK_LIST_STORE (model), &iter);
	gtk_list_store_set (GTK_LIST_STORE (model), &iter,
	                    0, POLICY_GROUP_INBOUND,
	                    1, _("Inbound traffic policy"),
	                    -1);
	gtk_list_store_append (GTK_LIST_STORE (model), &iter);
	gtk_list_store_set (GTK_LIST_STORE (model), &iter,
	                    0, POLICY_GROUP_OUTBOUND,
	                    1, _("Outbound traffic policy"),
	                    -1);

	hbox = gtk_hbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (policypage), hbox, FALSE, FALSE, 7);

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<span weight=\"bold\">", _("Editing"), "</span>", NULL));
	gtk_box_pack_start (GTK_BOX (hbox), label, FALSE, FALSE, GNOME_PAD_SMALL);

	combo = gtk_combo_box_new_with_model (model);
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 0);
	renderer = gtk_cell_renderer_text_new ();
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (combo), renderer, FALSE);
	gtk_cell_layout_set_attributes (GTK_CELL_LAYOUT (combo), renderer, "text", 1, NULL);
	g_signal_connect (combo, "changed",
	                  G_CALLBACK (switch_policy_group), NULL);

	gtk_box_pack_start (GTK_BOX (hbox), combo, FALSE, FALSE, 0);

	inbound_group = create_inboundpolicy_page ();
	gtk_box_pack_start (GTK_BOX (policypage), inbound_group, TRUE, TRUE, 0);

	outbound_group = create_outboundpolicy_page ();
	gtk_widget_show_all (outbound_group);
	gtk_widget_set_no_show_all (outbound_group, TRUE);
	gtk_widget_hide (outbound_group);
	gtk_box_pack_start (GTK_BOX (policypage), outbound_group, TRUE, TRUE, 0);

	/* Disable the buttons by default */
	menus_policy_edit_enabled (FALSE);
	menus_policy_remove_enabled (FALSE);
	menus_policy_add_enabled (FALSE);
	menus_policy_apply_enabled (FALSE);

	poicyview_update_nat_widgets ();

	gtk_widget_show_all (policypage);

	return policypage;
}
