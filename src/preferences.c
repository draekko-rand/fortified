/*---[ preferences.c ]------------------------------------------------
 * Copyright (C) 2000-2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Functions for modifying/reading the program preferences and the
 * preferences GUI
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <errno.h>
#include <gconf/gconf-client.h>
#include <glade/glade-xml.h>

#include "globals.h"
#include "fortified.h"
#include "preferences.h"
#include "wizard.h"
#include "wizard-choices.h"
#include "scriptwriter.h"
#include "statusview.h"
#include "util.h"
#include "gui.h"
#include "service.h"
#include "tray.h"
#include "dhcp-server.h"

typedef enum
{
	SECTION_INTERFACE,
	SECTION_INTERFACE_EVENTS,
	SECTION_INTERFACE_POLICY,
	SECTION_FIREWALL,
	SECTION_FIREWALL_NETWORK,
	SECTION_FIREWALL_ICMP,
	SECTION_FIREWALL_TOS,
	SECTION_FIREWALL_ADVANCED,
} Section;

typedef struct _PreferencesDialog PreferencesDialog;
struct _PreferencesDialog 
{
	GtkWidget *dialog_main;
	GtkTooltips *tooltips;
	GtkWidget *notebook;

/* Interface */
	GtkWidget *check_enable_tray_icon;
	GtkWidget *check_minimize_to_tray;
	
/* Events */
	GtkWidget *check_skip_redundant;
	GtkWidget *check_skip_not_for_firewall;

	GtkWidget *window_host_filter;
	GtkWidget *window_port_filter;
	GtkWidget *view_host_filter;
	GtkWidget *view_port_filter;
	GtkWidget *button_add_host;
	GtkWidget *button_add_port;
	GtkWidget *button_remove_host;
	GtkWidget *button_remove_port;
	GtkWidget *dialog_host_filter;
	GtkWidget *dialog_port_filter;
	GtkWidget *entry_host;
	GtkWidget *entry_port;

/* Policy */
	GtkWidget *check_apply_policy_instantly;

/* Firewall */
/*	GtkWidget *check_start_on_boot; */
	GtkWidget *check_start_on_gui;
	GtkWidget *check_start_on_dial_out;
	GtkWidget *check_start_on_dhcp;

/* Network settings */
	GtkWidget *combo_ext_device;
	GtkWidget *box_local_network_settings;
	GtkWidget *combo_int_device;
	GtkWidget *check_enable_connection_sharing;
	GtkWidget *check_enable_dhcp;
	GtkWidget *expander_dhcp;
	GtkWidget *radio_dhcp_create_conf;
	GtkWidget *table_dhcp_settings;
	GtkWidget *entry_dhcp_lowest_ip;
	GtkWidget *entry_dhcp_highest_ip;
	GtkWidget *entry_dhcp_name_server;

/* ICMP */
	GtkWidget *check_enable_icmp;
	GtkWidget *frame_icmp_types;
	GtkWidget *check_icmp_echo_request;
	GtkWidget *check_icmp_echo_reply;
	GtkWidget *check_icmp_traceroute;
	GtkWidget *check_icmp_mstraceroute;
	GtkWidget *check_icmp_unreachable;
	GtkWidget *check_icmp_timestamping;
	GtkWidget *check_icmp_address_masking;
	GtkWidget *check_icmp_redirection;
	GtkWidget *check_icmp_source_quenching;

/* ToS */
	GtkWidget *check_enable_tos;
	GtkWidget *frame_tos_services;
	GtkWidget *check_prioritize_workstations;
	GtkWidget *check_prioritize_servers;
	GtkWidget *check_prioritize_x;
	GtkWidget *frame_tos_maximize;
	GtkWidget *radio_max_throughput;
	GtkWidget *radio_max_reliability;
	GtkWidget *radio_max_interactivity;

/* Advanced */	
	GtkWidget *radio_deny_packets;
	GtkWidget *check_block_external_broadcast;
	GtkWidget *check_block_internal_broadcast;
	GtkWidget *check_block_non_routables;
};

static GConfClient *client = NULL;
static gboolean prefs_init = FALSE;

/* [ preferences_init ]
 * Initialize the GConfClient
 */
static void
preferences_init (void)
{
	if (prefs_init)
		return;

	client = gconf_client_get_default ();
	gconf_client_add_dir (client, "/apps/fortified", GCONF_CLIENT_PRELOAD_NONE, NULL);

	prefs_init = TRUE;
}

/* [ preferences_check_schema ]
 * Check that a Fortified gconf schema has been installed
 * The schema is not optional
 */
void
preferences_check_schema (void)
{
	gchar *string;

	if (!prefs_init)
		preferences_init ();    

	string = preferences_get_string (PREFS_SYSLOG_FILE);
        if (string == NULL) {
		gchar msg[] = N_("A proper configuration for Fortified was not found. "
        	                 "If you are running Fortified from the directory you "
	                         "built it in, run 'make install-data-local' to install a "
	                         "configuration, or simply 'make install' to install the "
	                         "whole program.\n\n"
	                         "Fortified will now close.");
		GtkWidget *dialog;

		dialog = gtk_message_dialog_new (NULL, GTK_DIALOG_DESTROY_WITH_PARENT,
        	                                 GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, msg);
		gtk_dialog_run (GTK_DIALOG (dialog));
		gtk_widget_destroy (dialog);
		exit(1);
	}
}

gboolean
preferences_get_bool (const gchar *gconf_key)
{
	if (!prefs_init)
		preferences_init ();

	return gconf_client_get_bool (client, gconf_key, NULL);
}

gchar *
preferences_get_string (const gchar *gconf_key)
{
	gchar *str;

	if (!prefs_init)
		preferences_init ();

	str = gconf_client_get_string (client, gconf_key, NULL);

	return str;
}

void
preferences_set_bool (const gchar *gconf_key, gboolean data)
{
	g_return_if_fail (gconf_key);

	if (!prefs_init)
		preferences_init ();

	gconf_client_set_bool (client, gconf_key, data, NULL);
}

void
preferences_set_string (const gchar *gconf_key, const gchar *data)
{
	g_return_if_fail (gconf_key || data);

	if (!prefs_init)
		preferences_init ();

	gconf_client_set_string (client, gconf_key, data, NULL);
}

static void
preferences_show_help (void)
{
	open_browser ("http://www.fs-security.com/docs/preferences.php");
}

static GtkTreeModel*
create_sections_model (void)
{
	GtkTreeStore *store;
	GtkTreeIter *iter;
	GtkTreeIter *top_section;

	store = gtk_tree_store_new (2, G_TYPE_INT, G_TYPE_STRING);

	iter = g_new (GtkTreeIter, 1);
	gtk_tree_store_append (store, iter, NULL);
	top_section = gtk_tree_iter_copy (iter);
	gtk_tree_store_set (store, iter,
	                    0, SECTION_INTERFACE,
			    1, _("Interface"),
			    -1);
	gtk_tree_store_append (store, iter, top_section);
	gtk_tree_store_set (store, iter,
	                    0, SECTION_INTERFACE_EVENTS,
			    1, _("Events"),
			    -1);
	gtk_tree_store_append (store, iter, top_section);
	gtk_tree_store_set (store, iter,
	                    0, SECTION_INTERFACE_POLICY,
			    1, _("Policy"),
			    -1);
	gtk_tree_iter_free (top_section);

	gtk_tree_store_append (store, iter, NULL);
	top_section = gtk_tree_iter_copy (iter);
	gtk_tree_store_set (store, iter,
	                    0, SECTION_FIREWALL,
			    1, _("Firewall"),
			    -1);
	gtk_tree_store_append (store, iter, top_section);
	gtk_tree_store_set (store, iter,
	                    0, SECTION_FIREWALL_NETWORK,
			    1, _("Network Settings"),
			    -1);
	gtk_tree_store_append (store, iter, top_section);
	gtk_tree_store_set (store, iter,
	                    0, SECTION_FIREWALL_ICMP,
			    1, _("ICMP Filtering"),
			    -1);
	gtk_tree_store_append (store, iter, top_section);
	gtk_tree_store_set (store, iter,
	                    0, SECTION_FIREWALL_TOS,
			    1, _("ToS Filtering"),
			    -1);
	gtk_tree_store_append (store, iter, top_section);
	gtk_tree_store_set (store, iter,
	                    0, SECTION_FIREWALL_ADVANCED,
			    1, _("Advanced Options"),
			    -1);
	gtk_tree_iter_free (top_section);
	g_free (iter);

	return GTK_TREE_MODEL (store);
}

static void
dialog_destroyed (GtkObject  *obj,  
		  void      **dialog_pointer)
{
	if (dialog_pointer != NULL) {
		g_free (*dialog_pointer);
		*dialog_pointer = NULL;
	}
}

static Section
get_current_section (GtkTreeView *sections)
{
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	Section selected;

	model = gtk_tree_view_get_model (sections);
	selection = gtk_tree_view_get_selection (sections);
	gtk_tree_selection_get_selected (selection, NULL, &iter);
	gtk_tree_model_get (model, &iter, 0, &selected, -1);
	
	return selected;
}

static void
change_section_cb (GtkTreeView *view, PreferencesDialog *dialog)
{
	Section section;

	section = get_current_section (view);
	gtk_notebook_set_page (GTK_NOTEBOOK (dialog->notebook), section);
}

static void
select_first_section (GtkTreeView *view)
{
	GtkTreePath *path;
	
	path = gtk_tree_path_new_from_string ("0");
	gtk_tree_view_set_cursor (view, path, NULL, FALSE);
	gtk_tree_path_free (path);
}

static void
filter_host_view_append (GtkListStore *store, gchar *host)
{
	GtkTreeIter iter;

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, host, -1);
}

static void
filter_port_view_append (GtkListStore *store, gchar *port)
{
	GtkTreeIter iter;
	gchar *data, *service;

	service = service_get_name (atoi (port), "tcp");
	data = g_strconcat (g_strstrip (port), " (", service, ")", NULL);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, data, -1);

	g_free (service);
	g_free (data);
}

static void
filter_host_view_reload (GtkListStore *store)
{
	GIOChannel* in;
	GError *error = NULL;
	gchar *line;

	in = g_io_channel_new_file (FORTIFIED_FILTER_HOSTS_SCRIPT, "r", &error);
	if (in == NULL) {
		g_printerr ("Error reading file %s: %s\n", FORTIFIED_FILTER_HOSTS_SCRIPT, error->message);
		g_error_free (error);
		return;
	}	

	while (g_io_channel_read_line (in, &line, NULL, NULL, &error) == G_IO_STATUS_NORMAL) {
		filter_host_view_append (store, g_strstrip (line));
		g_free (line);
	}

	if (error != NULL)
		g_error_free (error);
}

static void
filter_port_view_reload (GtkListStore *store)
{
	GIOChannel* in;
	GError *error = NULL;
	gchar *line;

	in = g_io_channel_new_file (FORTIFIED_FILTER_PORTS_SCRIPT, "r", &error);
	if (in == NULL) {
		g_printerr ("Error reading file %s: %s\n", FORTIFIED_FILTER_PORTS_SCRIPT, error->message);
		g_error_free (error);
		return;
	}	

	while (g_io_channel_read_line (in, &line, NULL, NULL, &error) == G_IO_STATUS_NORMAL) {
		filter_port_view_append (store, line);
		g_free (line);
	}

	if (error != NULL)
		g_error_free (error);
}

static void
filter_host_dialog_cb (GtkDialog *host_dialog, gint response, PreferencesDialog *dialog)
{
	if (response == GTK_RESPONSE_OK) {
		gchar *host;
		GtkListStore *store;

		host = g_strdup (gtk_entry_get_text (GTK_ENTRY (dialog->entry_host)));
		printf ("read host: %s\n", host);
		store = GTK_LIST_STORE (gtk_tree_view_get_model (GTK_TREE_VIEW (dialog->view_host_filter)));
		filter_host_view_append (store, host);
		append_to_file (FORTIFIED_FILTER_HOSTS_SCRIPT, host, TRUE);
		g_free (host);
	}

	/* Reset dialog */
	gtk_entry_set_text (GTK_ENTRY (dialog->entry_host), "");
	gtk_widget_grab_focus (dialog->entry_host);

	gtk_widget_hide (GTK_WIDGET (host_dialog));
}

static void
filter_port_dialog_cb (GtkDialog *port_dialog, gint response, PreferencesDialog *dialog)
{
	if (response == GTK_RESPONSE_OK) {
		gchar *port;
		GtkListStore *store;

		port = g_strdup (gtk_entry_get_text (GTK_ENTRY (dialog->entry_port)));
		store = GTK_LIST_STORE (gtk_tree_view_get_model (GTK_TREE_VIEW (dialog->view_port_filter)));
		filter_port_view_append (store, port);
		append_to_file (FORTIFIED_FILTER_PORTS_SCRIPT, port, TRUE);
		g_free (port);
	}

	/* Reset dialog */
	gtk_entry_set_text (GTK_ENTRY (dialog->entry_port), "");
	gtk_widget_grab_focus (dialog->entry_port);

	gtk_widget_hide (GTK_WIDGET (port_dialog));
}

static void
filter_host_remove (GtkTreeView *view)
{
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;

	model = gtk_tree_view_get_model (view);
	selection = gtk_tree_view_get_selection (view);
	if (gtk_tree_selection_get_selected (selection, NULL, &iter)) {
		GtkTreePath* path;
		gint pos;
		
		path = gtk_tree_model_get_path (model, &iter);
		pos = gtk_tree_path_get_indices(path)[0];
		
		gtk_list_store_remove (GTK_LIST_STORE (model), &iter);
		remove_line_from_file (FORTIFIED_FILTER_HOSTS_SCRIPT, pos);

		gtk_tree_path_free (path);
	}
}

static void
filter_port_remove (GtkTreeView *view)
{
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;

	model = gtk_tree_view_get_model (view);
	selection = gtk_tree_view_get_selection (view);
	if (gtk_tree_selection_get_selected (selection, NULL, &iter)) {
		GtkTreePath* path;
		gint pos;
		
		path = gtk_tree_model_get_path (model, &iter);
		pos = gtk_tree_path_get_indices(path)[0];
		
		gtk_list_store_remove (GTK_LIST_STORE (model), &iter);
		remove_line_from_file (FORTIFIED_FILTER_PORTS_SCRIPT, pos);

		gtk_tree_path_free (path);
	}
}

static void
activate_dialog_cb (GtkWidget *dialog)
{
	gtk_dialog_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);
}

static void
setup_interface_section (PreferencesDialog *dialog)
{
	gui_widget_sensitivity_sync (GTK_TOGGLE_BUTTON (dialog->check_enable_tray_icon), dialog->check_minimize_to_tray);
}

static void
setup_events_section (PreferencesDialog *dialog)
{
	GtkWidget *window;
	GtkWidget *view;
	GtkListStore *store;
	View_def host_filter_def = {1, {
			{_("Hosts"), G_TYPE_STRING, TRUE},
		}
	};
	View_def port_filter_def = {1, {
			{_("Ports"), G_TYPE_STRING, TRUE},
		}
	};
	
	/* Set up list of filtered hosts */
	window = dialog->window_host_filter;
	view = gui_create_list_view (&host_filter_def, 120, 150);
	dialog->view_host_filter = view;
	gtk_container_add (GTK_CONTAINER (window), view);
	store = GTK_LIST_STORE (gtk_tree_view_get_model (GTK_TREE_VIEW (view)));
	filter_host_view_reload (store);
	gtk_widget_show_all (view);
	g_signal_connect_swapped (dialog->button_add_host, "clicked",
	                          G_CALLBACK (gtk_widget_show_all), dialog->dialog_host_filter);
	g_signal_connect_swapped (dialog->button_remove_host, "clicked",
	                          G_CALLBACK (filter_host_remove), dialog->view_host_filter);
	g_signal_connect (dialog->dialog_host_filter, "response",
	                  G_CALLBACK (filter_host_dialog_cb), dialog);
	g_signal_connect_swapped (dialog->entry_host, "activate",
	                          G_CALLBACK (activate_dialog_cb), dialog->dialog_host_filter);

	/* Set up list of filtered ports */
	window = dialog->window_port_filter;
	view = gui_create_list_view (&port_filter_def, 120, 150);
	dialog->view_port_filter = view;
	gtk_container_add (GTK_CONTAINER (window), view);
	store = GTK_LIST_STORE (gtk_tree_view_get_model (GTK_TREE_VIEW (view)));
	filter_port_view_reload (store);
	gtk_widget_show_all (view);
	g_signal_connect_swapped (dialog->button_add_port, "clicked",
	                          G_CALLBACK (gtk_widget_show_all), dialog->dialog_port_filter);
	g_signal_connect_swapped (dialog->button_remove_port, "clicked",
	                          G_CALLBACK (filter_port_remove), dialog->view_port_filter);
	g_signal_connect (dialog->dialog_port_filter, "response",
	                  G_CALLBACK (filter_port_dialog_cb), dialog);
	g_signal_connect_swapped (dialog->entry_port, "activate",
	                          G_CALLBACK (activate_dialog_cb), dialog->dialog_port_filter);
}

static void
setup_network_settings_section (PreferencesDialog *dialog)
{
	GtkTreeModel *model;

	model = get_devices_model ();

	gtk_combo_box_set_model (GTK_COMBO_BOX (dialog->combo_ext_device), model);
	gtk_combo_box_set_model (GTK_COMBO_BOX (dialog->combo_int_device), model);

	gui_widget_sensitivity_sync (GTK_TOGGLE_BUTTON (dialog->check_enable_dhcp), dialog->expander_dhcp);
	gui_widget_sensitivity_sync (GTK_TOGGLE_BUTTON (dialog->radio_dhcp_create_conf), dialog->table_dhcp_settings);
	gtk_expander_set_expanded (GTK_EXPANDER (dialog->expander_dhcp), FALSE);

	gtk_widget_set_sensitive (dialog->box_local_network_settings, is_capable_of_nat ());
}

static void
setup_icmp_section (PreferencesDialog *dialog)
{
	gui_widget_sensitivity_sync (GTK_TOGGLE_BUTTON (dialog->check_enable_icmp), dialog->frame_icmp_types);
}

static void
setup_tos_section (PreferencesDialog *dialog)
{
	gui_widget_sensitivity_sync (GTK_TOGGLE_BUTTON (dialog->check_enable_tos), dialog->frame_tos_services);
	gui_widget_sensitivity_sync (GTK_TOGGLE_BUTTON (dialog->check_enable_tos), dialog->frame_tos_maximize);
}

void
preferences_update_widget_from_conf (GtkWidget *widget, const gchar *gconf_key)
{
	if (GTK_IS_ENTRY (widget)) {
		gchar *data;

		data = preferences_get_string (gconf_key);
		gtk_entry_set_text (GTK_ENTRY (widget), data);

		g_free (data);
	} else if (GTK_IS_TOGGLE_BUTTON (widget)) {
		gboolean active;

		active = preferences_get_bool (gconf_key);
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), active);
	} else {
		printf ("Failed to update widget from conf: %s\n", gconf_key);
		g_assert_not_reached ();
	}
}

void
preferences_update_conf_from_widget (GtkWidget *widget, const gchar *gconf_key)
{
	if (GTK_IS_ENTRY (widget)) {
		const gchar *data;

		data = gtk_entry_get_text (GTK_ENTRY (widget));
		preferences_set_string (gconf_key, data);
	} else if (GTK_IS_TOGGLE_BUTTON (widget)) {
		gboolean active;

		active = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget));
		preferences_set_bool (gconf_key, active);
	} else {
		printf ("Failed to update conf from widget: %s\n", gconf_key);
		g_assert_not_reached ();
	}
}

static gboolean
combo_set_active_device (GtkComboBox *combo, gchar *new_if)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	gchar *interface;

	model = gtk_combo_box_get_model (combo);

	gtk_tree_model_get_iter_first (model, &iter);
	do {
		gtk_tree_model_get (model, &iter, 1, &interface, -1);
		if (g_str_equal (interface, new_if)) {
			gtk_combo_box_set_active_iter (combo, &iter);
			return TRUE;
		}
	} while (gtk_tree_model_iter_next (model, &iter));

	return FALSE;
}

static gchar *
combo_get_active_device (GtkComboBox *combo)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	gchar *interface;

	model = gtk_combo_box_get_model (combo);
	gtk_combo_box_get_active_iter (combo, &iter);
	gtk_tree_model_get (model, &iter, 1, &interface, -1);

	return interface;
}

static gboolean
validate_dhcp_settings (PreferencesDialog *dialog)
{
	const gchar *name_server, *highest_ip, *lowest_ip;
	gboolean validates = TRUE;

	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (dialog->check_enable_dhcp)) ||
	    !gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (dialog->radio_dhcp_create_conf)))
		return TRUE;

	name_server = gtk_entry_get_text (GTK_ENTRY (dialog->entry_dhcp_name_server));
	highest_ip = gtk_entry_get_text (GTK_ENTRY (dialog->entry_dhcp_highest_ip));
	lowest_ip = gtk_entry_get_text (GTK_ENTRY (dialog->entry_dhcp_lowest_ip));

	validates = (is_a_valid_host (highest_ip) &&
		     is_a_valid_host (lowest_ip) &&
		     (is_a_valid_host (name_server) || g_ascii_strcasecmp (name_server, "<dynamic>") == 0));

	if (!validates) {
		error_dialog (_("Please review your choices"),
		              _("Invalid DHCP configuration"),
		              _("Please review your DHCP settings, the configuration\n"
		                "you specified is not valid."),
		             dialog->dialog_main);
	}

	return validates;
}

static void
load_preferences (PreferencesDialog *dialog)
{
	/* Interface */
	preferences_update_widget_from_conf (dialog->check_enable_tray_icon, PREFS_ENABLE_TRAY_ICON);
	preferences_update_widget_from_conf (dialog->check_minimize_to_tray, PREFS_MINIMIZE_TO_TRAY);

	gtk_widget_set_sensitive (dialog->check_minimize_to_tray, preferences_get_bool (PREFS_ENABLE_TRAY_ICON));

	/* Events */
	preferences_update_widget_from_conf (dialog->check_skip_redundant, PREFS_SKIP_REDUNDANT);
	preferences_update_widget_from_conf (dialog->check_skip_not_for_firewall, PREFS_SKIP_NOT_FOR_FIREWALL);
	
	/* Policy */
	preferences_update_widget_from_conf (dialog->check_apply_policy_instantly, PREFS_APPLY_POLICY_INSTANTLY);

	/* Firewall */
/*	preferences_update_widget_from_conf (dialog->check_start_on_boot, PREFS_START_ON_BOOT); */
	preferences_update_widget_from_conf (dialog->check_start_on_gui, PREFS_START_ON_GUI);
	preferences_update_widget_from_conf (dialog->check_start_on_dial_out, PREFS_START_ON_DIAL_OUT);
	preferences_update_widget_from_conf (dialog->check_start_on_dhcp, PREFS_START_ON_DHCP);

	/* Network settings */
	if (!combo_set_active_device (GTK_COMBO_BOX (dialog->combo_ext_device),
	                              preferences_get_string (PREFS_FW_EXT_IF))) {
		printf ("Warning: External interface previously configured not found\n");
		gtk_combo_box_set_active (GTK_COMBO_BOX (dialog->combo_ext_device), 0); /* Default to the first item */
	}
	if (!combo_set_active_device (GTK_COMBO_BOX (dialog->combo_int_device),
	                              preferences_get_string (PREFS_FW_INT_IF))) {
		printf ("Warning: External interface previously configured not found\n");
		gtk_combo_box_set_active (GTK_COMBO_BOX (dialog->combo_int_device), 0); /* Default to the first item */
	}

	preferences_update_widget_from_conf (dialog->check_enable_connection_sharing, PREFS_FW_NAT);
	preferences_update_widget_from_conf (dialog->check_enable_dhcp, PREFS_FW_DHCP_ENABLE);
	preferences_update_widget_from_conf (dialog->entry_dhcp_lowest_ip, PREFS_FW_DHCP_LOWEST_IP);
	preferences_update_widget_from_conf (dialog->entry_dhcp_highest_ip, PREFS_FW_DHCP_HIGHEST_IP);
	preferences_update_widget_from_conf (dialog->entry_dhcp_name_server, PREFS_FW_DHCP_NAMESERVER);

	gtk_widget_set_sensitive (dialog->expander_dhcp, preferences_get_bool (PREFS_FW_DHCP_ENABLE));
	gtk_widget_set_sensitive (dialog->table_dhcp_settings, FALSE);

	/* ICMP */
	preferences_update_widget_from_conf (dialog->check_enable_icmp, PREFS_FW_FILTER_ICMP);

	preferences_update_widget_from_conf (dialog->check_icmp_echo_request, PREFS_FW_ICMP_ECHO_REQUEST);
	preferences_update_widget_from_conf (dialog->check_icmp_echo_reply, PREFS_FW_ICMP_ECHO_REPLY);
	preferences_update_widget_from_conf (dialog->check_icmp_traceroute, PREFS_FW_ICMP_TRACEROUTE);
	preferences_update_widget_from_conf (dialog->check_icmp_mstraceroute, PREFS_FW_ICMP_MSTRACEROUTE);
	preferences_update_widget_from_conf (dialog->check_icmp_unreachable, PREFS_FW_ICMP_UNREACHABLE);
	preferences_update_widget_from_conf (dialog->check_icmp_timestamping, PREFS_FW_ICMP_TIMESTAMPING);
	preferences_update_widget_from_conf (dialog->check_icmp_address_masking, PREFS_FW_ICMP_MASKING);
	preferences_update_widget_from_conf (dialog->check_icmp_redirection, PREFS_FW_ICMP_REDIRECTION);
	preferences_update_widget_from_conf (dialog->check_icmp_source_quenching, PREFS_FW_ICMP_SOURCE_QUENCHES);

	gtk_widget_set_sensitive (dialog->frame_icmp_types, preferences_get_bool (PREFS_FW_FILTER_ICMP));

	/* ToS */
	preferences_update_widget_from_conf (dialog->check_enable_tos, PREFS_FW_FILTER_TOS);

	preferences_update_widget_from_conf (dialog->check_prioritize_workstations, PREFS_FW_TOS_CLIENT);
	preferences_update_widget_from_conf (dialog->check_prioritize_servers, PREFS_FW_TOS_SERVER);
	preferences_update_widget_from_conf (dialog->check_prioritize_x, PREFS_FW_TOS_X);

	preferences_update_widget_from_conf (dialog->radio_max_throughput, PREFS_FW_TOS_OPT_TROUGHPUT);
	preferences_update_widget_from_conf (dialog->radio_max_reliability, PREFS_FW_TOS_OPT_RELIABILITY);
	preferences_update_widget_from_conf (dialog->radio_max_interactivity, PREFS_FW_TOS_OPT_DELAY);

	gtk_widget_set_sensitive (dialog->frame_tos_services, preferences_get_bool (PREFS_FW_FILTER_TOS));
	gtk_widget_set_sensitive (dialog->frame_tos_maximize, preferences_get_bool (PREFS_FW_FILTER_TOS));

	/* Advanced */
	preferences_update_widget_from_conf (dialog->radio_deny_packets, PREFS_FW_DENY_PACKETS);
	preferences_update_widget_from_conf (dialog->check_block_external_broadcast, PREFS_FW_BLOCK_EXTERNAL_BROADCAST);
	preferences_update_widget_from_conf (dialog->check_block_internal_broadcast, PREFS_FW_BLOCK_INTERNAL_BROADCAST);
	preferences_update_widget_from_conf (dialog->check_block_non_routables, PREFS_FW_BLOCK_NON_ROUTABLES);
}

static void
save_preferences (PreferencesDialog *dialog)
{
	/* Interface */
	preferences_update_conf_from_widget (dialog->check_enable_tray_icon, PREFS_ENABLE_TRAY_ICON);
	preferences_update_conf_from_widget (dialog->check_minimize_to_tray, PREFS_MINIMIZE_TO_TRAY);

	/* Events */
	preferences_update_conf_from_widget (dialog->check_skip_redundant, PREFS_SKIP_REDUNDANT);
	preferences_update_conf_from_widget (dialog->check_skip_not_for_firewall, PREFS_SKIP_NOT_FOR_FIREWALL);
	
	/* Policy */
	preferences_update_conf_from_widget (dialog->check_apply_policy_instantly, PREFS_APPLY_POLICY_INSTANTLY);

	/* Firewall */
/*	preferences_update_conf_from_widget (dialog->check_start_on_boot, PREFS_START_ON_BOOT); */
	preferences_update_conf_from_widget (dialog->check_start_on_gui, PREFS_START_ON_GUI);
	preferences_update_conf_from_widget (dialog->check_start_on_dial_out, PREFS_START_ON_DIAL_OUT);
	preferences_update_conf_from_widget (dialog->check_start_on_dhcp, PREFS_START_ON_DHCP);

	/* Network settings */
	preferences_set_string (PREFS_FW_EXT_IF, combo_get_active_device (GTK_COMBO_BOX (dialog->combo_ext_device)));
	preferences_set_string (PREFS_FW_INT_IF, combo_get_active_device (GTK_COMBO_BOX (dialog->combo_int_device)));

	preferences_update_conf_from_widget (dialog->check_enable_connection_sharing, PREFS_FW_NAT);
	preferences_update_conf_from_widget (dialog->check_enable_dhcp, PREFS_FW_DHCP_ENABLE);
	preferences_update_conf_from_widget (dialog->entry_dhcp_lowest_ip, PREFS_FW_DHCP_LOWEST_IP);
	preferences_update_conf_from_widget (dialog->entry_dhcp_highest_ip, PREFS_FW_DHCP_HIGHEST_IP);
	preferences_update_conf_from_widget (dialog->entry_dhcp_name_server, PREFS_FW_DHCP_NAMESERVER);

	/* ICMP */
	preferences_update_conf_from_widget (dialog->check_enable_icmp, PREFS_FW_FILTER_ICMP);

	preferences_update_conf_from_widget (dialog->check_icmp_echo_request, PREFS_FW_ICMP_ECHO_REQUEST);
	preferences_update_conf_from_widget (dialog->check_icmp_echo_reply, PREFS_FW_ICMP_ECHO_REPLY);
	preferences_update_conf_from_widget (dialog->check_icmp_traceroute, PREFS_FW_ICMP_TRACEROUTE);
	preferences_update_conf_from_widget (dialog->check_icmp_mstraceroute, PREFS_FW_ICMP_MSTRACEROUTE);
	preferences_update_conf_from_widget (dialog->check_icmp_unreachable, PREFS_FW_ICMP_UNREACHABLE);
	preferences_update_conf_from_widget (dialog->check_icmp_timestamping, PREFS_FW_ICMP_TIMESTAMPING);
	preferences_update_conf_from_widget (dialog->check_icmp_address_masking, PREFS_FW_ICMP_MASKING);
	preferences_update_conf_from_widget (dialog->check_icmp_redirection, PREFS_FW_ICMP_REDIRECTION);
	preferences_update_conf_from_widget (dialog->check_icmp_source_quenching, PREFS_FW_ICMP_SOURCE_QUENCHES);

	/* ToS */
	preferences_update_conf_from_widget (dialog->check_enable_tos, PREFS_FW_FILTER_TOS);

	preferences_update_conf_from_widget (dialog->check_prioritize_workstations, PREFS_FW_TOS_CLIENT);
	preferences_update_conf_from_widget (dialog->check_prioritize_servers, PREFS_FW_TOS_SERVER);
	preferences_update_conf_from_widget (dialog->check_prioritize_x, PREFS_FW_TOS_X);

	preferences_update_conf_from_widget (dialog->radio_max_throughput, PREFS_FW_TOS_OPT_TROUGHPUT);
	preferences_update_conf_from_widget (dialog->radio_max_reliability, PREFS_FW_TOS_OPT_RELIABILITY);
	preferences_update_conf_from_widget (dialog->radio_max_interactivity, PREFS_FW_TOS_OPT_DELAY);

	gtk_widget_set_sensitive (dialog->frame_tos_services, preferences_get_bool (PREFS_FW_FILTER_TOS));
	gtk_widget_set_sensitive (dialog->frame_tos_maximize, preferences_get_bool (PREFS_FW_FILTER_TOS));

	/* Advanced */
	preferences_update_conf_from_widget (dialog->radio_deny_packets, PREFS_FW_DENY_PACKETS);
	preferences_update_conf_from_widget (dialog->check_block_external_broadcast, PREFS_FW_BLOCK_EXTERNAL_BROADCAST);
	preferences_update_conf_from_widget (dialog->check_block_internal_broadcast, PREFS_FW_BLOCK_INTERNAL_BROADCAST);
	preferences_update_conf_from_widget (dialog->check_block_non_routables, PREFS_FW_BLOCK_NON_ROUTABLES);

	scriptwriter_output_configuration ();

	/* Write DHCP configuration */
	if (preferences_get_bool (PREFS_FW_NAT) &&
	    preferences_get_bool (PREFS_FW_DHCP_ENABLE) &&
	    gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (dialog->radio_dhcp_create_conf)))
		dhcp_server_create_configuration ();

	/* Start firewall on ppp interface up */
	if (preferences_get_bool (PREFS_START_ON_DIAL_OUT))
		scriptwriter_write_ppp_hook ();
	else
		scriptwriter_remove_ppp_hook ();
		
	/* Start firewall on DCHP lease renewal */
	if (preferences_get_bool (PREFS_START_ON_DHCP))
		scriptwriter_write_dhcp_hook ();
	else
		scriptwriter_remove_dhcp_hook ();

	restart_firewall_if_active ();

	poicyview_update_nat_widgets ();

	if (preferences_get_bool (PREFS_ENABLE_TRAY_ICON)) {
		if (!tray_is_running ())
			tray_init ();
	} else {
		if (tray_is_running ())
			tray_remove ();
	}
}

static void
preferences_response_cb (GtkDialog *main_dialog, gint response, PreferencesDialog *dialog)
{
	if (response == GTK_RESPONSE_ACCEPT) {
		if (validate_dhcp_settings (dialog)) {
			save_preferences (dialog);
			gtk_widget_destroy (GTK_WIDGET (main_dialog));
		}
	} else if (response == GTK_RESPONSE_HELP) {
		preferences_show_help ();
	} else
		gtk_widget_destroy (GTK_WIDGET (main_dialog));
}

static void
log_handler_cb (const gchar *log_domain, GLogLevelFlags
                log_level, const gchar *message, gpointer user_data)
{
	return;
}

static PreferencesDialog *
get_preferences_dialog (GtkWindow *parent)
{
	static PreferencesDialog *dialog = NULL;
	GladeXML *gui;
	GtkTreeModel *model;
	GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;
	GtkWidget *sections;

	if (dialog != NULL) {
		gtk_window_set_transient_for (GTK_WINDOW (dialog->dialog_main),
					      parent);
		gtk_window_present (GTK_WINDOW (dialog->dialog_main));

		return dialog;
	}

	/* Suppress libglade warnings */
	g_log_set_handler ("libglade", 
                           G_LOG_LEVEL_WARNING,
		    	   log_handler_cb, 
			   NULL);

	/* Try to load the interface from the current directory first */
	gui = glade_xml_new ("preferences.glade", NULL, NULL);
	if (gui == NULL) { /* If that fails, load the shared interface file */
		gui = glade_xml_new (GLADEDIR"/preferences.glade", NULL, NULL);
	}

	if (gui == NULL) {
		error_dialog (_("Missing file"),
		              _("Fortified interface file not found"),
			      _("The interface markup file preferences.glade could not be found."),
			      Fortified.window);
		return NULL;
	}	

	dialog = g_new0 (PreferencesDialog, 1);

	dialog->dialog_main = glade_xml_get_widget (gui, "preferences_dialog");
	g_signal_connect (G_OBJECT (dialog->dialog_main), "destroy",
			  G_CALLBACK (dialog_destroyed), &dialog);
	g_signal_connect (G_OBJECT (dialog->dialog_main), "response",
			  G_CALLBACK (preferences_response_cb), dialog);

	/* Set up the contents index */
	sections = glade_xml_get_widget (gui, "sections");
	model = create_sections_model ();
	gtk_tree_view_set_model (GTK_TREE_VIEW (sections), model);
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("", renderer, "text", 1, NULL);
	gtk_tree_view_append_column (GTK_TREE_VIEW (sections), column);
	gtk_tree_view_expand_all (GTK_TREE_VIEW (sections));
	g_signal_connect (G_OBJECT (sections), "cursor-changed",
			  G_CALLBACK (change_section_cb), dialog);

	/* Set up the notebook */
	dialog->notebook = glade_xml_get_widget (gui, "notebook");
	gtk_notebook_set_show_tabs (GTK_NOTEBOOK (dialog->notebook), FALSE);

	/* Set up the interface section */
	dialog->check_enable_tray_icon = glade_xml_get_widget (gui, "check_enable_tray_icon");
	dialog->check_minimize_to_tray = glade_xml_get_widget (gui, "check_minimize_to_tray");

	setup_interface_section (dialog);

	/* Set up the events section */
	dialog->check_skip_redundant = glade_xml_get_widget (gui, "check_skip_redundant");
	dialog->check_skip_not_for_firewall = glade_xml_get_widget (gui, "check_skip_not_for_firewall");

	dialog->window_host_filter = glade_xml_get_widget (gui, "window_host_filter");
	dialog->window_port_filter = glade_xml_get_widget (gui, "window_port_filter");
	dialog->button_add_host = glade_xml_get_widget (gui, "button_add_host");
	dialog->button_add_port = glade_xml_get_widget (gui, "button_add_port");
	dialog->button_remove_host = glade_xml_get_widget (gui, "button_remove_host");
	dialog->button_remove_port = glade_xml_get_widget (gui, "button_remove_port");
	dialog->dialog_host_filter = glade_xml_get_widget (gui, "dialog_host_filter");
	dialog->dialog_port_filter = glade_xml_get_widget (gui, "dialog_port_filter");
	dialog->entry_host = glade_xml_get_widget (gui, "entry_host");
	dialog->entry_port = glade_xml_get_widget (gui, "entry_port");

	setup_events_section (dialog);

	/* Set up the policy section */
	dialog->check_apply_policy_instantly = glade_xml_get_widget (gui, "check_apply_policy_instantly");

	/* Set up the firewall section */
/*	dialog->check_start_on_boot = glade_xml_get_widget (gui, "check_start_on_boot"); */
	dialog->check_start_on_gui = glade_xml_get_widget (gui, "check_start_on_gui");
	dialog->check_start_on_dial_out = glade_xml_get_widget (gui, "check_start_on_dial_out");
	dialog->check_start_on_dhcp = glade_xml_get_widget (gui, "check_start_on_dhcp");

	/* Set up the network settings section */
	dialog->combo_ext_device = glade_xml_get_widget (gui, "combo_ext_device");
	dialog->box_local_network_settings = glade_xml_get_widget (gui, "box_local_network_settings");
	dialog->combo_int_device = glade_xml_get_widget (gui, "combo_int_device");
	dialog->check_enable_connection_sharing = glade_xml_get_widget (gui, "check_enable_connection_sharing");
	dialog->check_enable_dhcp = glade_xml_get_widget (gui, "check_enable_dhcp");
	dialog->expander_dhcp = glade_xml_get_widget (gui, "expander_dhcp");
	dialog->radio_dhcp_create_conf = glade_xml_get_widget (gui, "radio_dhcp_create_conf");
	dialog->table_dhcp_settings = glade_xml_get_widget (gui, "table_dhcp_settings");
	dialog->entry_dhcp_lowest_ip = glade_xml_get_widget (gui, "entry_dhcp_lowest_ip");
	dialog->entry_dhcp_highest_ip = glade_xml_get_widget (gui, "entry_dhcp_highest_ip");
	dialog->entry_dhcp_name_server = glade_xml_get_widget (gui, "entry_dhcp_name_server");

	setup_network_settings_section (dialog);

	/* Set up ICMP section */
	dialog->check_enable_icmp = glade_xml_get_widget (gui, "check_enable_icmp");
	dialog->frame_icmp_types = glade_xml_get_widget (gui, "frame_icmp_types");
	dialog->check_icmp_echo_request = glade_xml_get_widget (gui, "check_icmp_echo_request");
	dialog->check_icmp_echo_reply = glade_xml_get_widget (gui, "check_icmp_echo_reply");
	dialog->check_icmp_traceroute = glade_xml_get_widget (gui, "check_icmp_traceroute");
	dialog->check_icmp_mstraceroute = glade_xml_get_widget (gui, "check_icmp_mstraceroute");
	dialog->check_icmp_unreachable = glade_xml_get_widget (gui, "check_icmp_unreachable");
	dialog->check_icmp_timestamping = glade_xml_get_widget (gui, "check_icmp_timestamping");
	dialog->check_icmp_address_masking = glade_xml_get_widget (gui, "check_icmp_address_masking");
	dialog->check_icmp_redirection = glade_xml_get_widget (gui, "check_icmp_redirection");
	dialog->check_icmp_source_quenching = glade_xml_get_widget (gui, "check_icmp_source_quenching");

	setup_icmp_section (dialog);

	/* Set up the ToS section */
	dialog->check_enable_tos = glade_xml_get_widget (gui, "check_enable_tos");
	dialog->frame_tos_services = glade_xml_get_widget (gui, "frame_tos_services");
	dialog->check_prioritize_workstations = glade_xml_get_widget (gui, "check_prioritize_workstations");
	dialog->check_prioritize_servers = glade_xml_get_widget (gui, "check_prioritize_servers");
	dialog->check_prioritize_x = glade_xml_get_widget (gui, "check_prioritize_x");
	dialog->frame_tos_maximize = glade_xml_get_widget (gui, "frame_tos_maximize");
	dialog->radio_max_throughput = glade_xml_get_widget (gui, "radio_max_throughput");
	dialog->radio_max_reliability = glade_xml_get_widget (gui, "radio_max_reliability");
	dialog->radio_max_interactivity = glade_xml_get_widget (gui, "radio_max_interactivity");

	setup_tos_section (dialog);

	/* Set up the advanced section */
	dialog->radio_deny_packets = glade_xml_get_widget (gui, "radio_drop_packets");
	dialog->check_block_external_broadcast = glade_xml_get_widget (gui, "check_block_external_broadcast");
	dialog->check_block_internal_broadcast = glade_xml_get_widget (gui, "check_block_internal_broadcast");
	dialog->check_block_non_routables = glade_xml_get_widget (gui, "check_block_non_routables");

	select_first_section (GTK_TREE_VIEW (sections));
	/* Set the default page */
	gtk_notebook_set_page (GTK_NOTEBOOK (dialog->notebook), 0);

	g_object_unref (gui);
	
	return dialog;
}

/* [ preferences_run ]
 * Display the preferences GUI
 */
void
preferences_show (void)
{
	PreferencesDialog *dialog;

	dialog = get_preferences_dialog (GTK_WINDOW (Fortified.window));

	if (!dialog)
		return;

	load_preferences (dialog);

	if (!GTK_WIDGET_VISIBLE (dialog->dialog_main))
		gtk_widget_show (dialog->dialog_main);
}
