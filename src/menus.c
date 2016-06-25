/*---[ menus.c ]------------------------------------------------------
 * Copyright (C) 2000-2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Menu and toolbar related functions and definitions
 *--------------------------------------------------------------------*/

#include "menus.h"
#include "fortified.h"
#include "wizard.h"
#include "savelog.h"
#include "preferences.h"
#include "gui.h"
#include "hitview.h"
#include "util.h"
#include "globals.h"
#include "policyview.h"
#include "statusview.h"

#include "xpm/fortified-pixbufs.h"

#define FORTIFIED_STOCK_WIZARD "fortified-wizard-icon"
#define FORTIFIED_STOCK_START_FIREWALL "fortified-start-firewall-icon"
#define FORTIFIED_STOCK_STOP_FIREWALL "fortified-stop-firewall-icon"
#define FORTIFIED_STOCK_LOCK_FIREWALL "fortified-lock-firewall-icon"
#define FORTIFIED_STOCK_UNLOCK_FIREWALL "fortified-unlock-firewall-icon"
#define FORTIFIED_STOCK_EDIT "fortified-edit"

static GtkAccelGroup *main_accel_group;

static GtkUIManager *ui_manager;

static void open_homepage (void);
static void open_manual (void);
static void copy_selected (void);

/* Normal items */
static GtkActionEntry entries[] = {
	{ "FirewallMenu", NULL, N_("_Firewall") },
	{ "EditMenu", NULL, N_("_Edit") },
	{ "EventsMenu", NULL, N_("E_vents") },
	{ "EventsShowSubmenu", NULL, N_("_Show Column") },
	{ "PolicyMenu", NULL, N_("_Policy") },
	{ "HelpMenu", NULL, N_("_Help") },

/*Q*/	{ "Quit", GTK_STOCK_QUIT, N_("_Quit"), "<control>Q", N_("Quit the program"), exit_fortified },
	{ "RunWizard", FORTIFIED_STOCK_WIZARD, N_("Run _Wizard"), NULL, N_("Run the firewall wizard"), run_wizard },
/*S*/	{ "StartFirewall", FORTIFIED_STOCK_START_FIREWALL, N_("_Start Firewall"), "<control>S", N_("Start the firewall"), start_firewall },
/*P*/	{ "StopFirewall", FORTIFIED_STOCK_STOP_FIREWALL, N_("Sto_p Firewall"), "<control>P", N_("Stop the firewall"), stop_firewall },
	{ "LockFirewall", FORTIFIED_STOCK_LOCK_FIREWALL, N_("_Lock Firewall"), NULL, N_("Lock the firewall"), lock_firewall },
	{ "UnlockFirewall", FORTIFIED_STOCK_UNLOCK_FIREWALL, N_("_Unlock Firewall"), NULL, N_("Unlock the firewall"), unlock_firewall },

/*C*/	{ "CopyEvent", GTK_STOCK_COPY, N_("_Copy description"), "<control>C", N_("Copy event description"), copy_selected },
	{ "Preferences", GTK_STOCK_PREFERENCES, N_("_Preferences"), NULL, N_("Program preferences"), preferences_show },

/*F12*/	{ "SaveEventList", GTK_STOCK_SAVE, N_("_Save List"), "F12", N_("Save the events to a file"), savelog_show_dialog },
/*L*/	{ "ClearEventList", GTK_STOCK_CLEAR, N_("_Clear"), "<control>L", N_("Clear the events"), hitview_clear },
	{ "ReloadEventList", GTK_STOCK_REFRESH, N_("_Reload"), NULL, N_("Reload the events"), hitview_reload },
	{ "CancelReloadEventList", GTK_STOCK_STOP, N_("_Cancel"), NULL, N_("Cancel reloading the events"), hitview_reload_cancel },

	{ "RemoveRule", GTK_STOCK_REMOVE, N_("_Remove Rule"), NULL, N_("Remove the selected rule"), policyview_remove_rule },
	{ "AddRule", GTK_STOCK_ADD, N_("_Add Rule"), NULL, N_("Add a rule to the selected policy group"), policyview_add_rule },
	{ "EditRule", FORTIFIED_STOCK_EDIT, N_("_Edit Rule"), NULL, N_("Edit the selected rule"), policyview_edit_rule },
	{ "ApplyPolicy", GTK_STOCK_APPLY, N_("A_pply Policy"), NULL, N_("Apply the changes made the policy"), policyview_apply },

	{ "OpenManual", GTK_STOCK_HELP, N_("Online Users' _Manual"), NULL, N_("Open the online users' manual in a browser"), open_manual },
	{ "OpenHomepage", GTK_STOCK_HOME, N_("Fortified _Homepage"), NULL, N_("Open the Fortified homepage in a browser"), open_homepage },
	{ "ShowAbout", GNOME_STOCK_ABOUT, N_("_About"), NULL, N_("About Fortified"), G_CALLBACK (show_about) },

	{ "AllowInboundFrom", NULL, N_("Allow Connections From Source"), NULL, N_("Allow all connections from this source"), hitview_allow_host },
	{ "AllowInboundService", NULL, N_("Allow Inbound Service for Everyone"), NULL, N_("Allow inbound service for everyone"), hitview_allow_service },
	{ "AllowInboundServiceFrom", NULL, N_("Allow Inbound Service for Source"), NULL, N_("Allow inbound service for source"), hitview_allow_service_from },
	{ "AllowOutboundTo", NULL, N_("Allow Connections to Destination"), NULL, N_("Allow connections to destination"), hitview_allow_host },
	{ "AllowOutboundService", NULL, N_("Allow Outbound Service for Everyone"), NULL, N_("Allow outbound service for everyone"), hitview_allow_service },
	{ "AllowOutboundServiceFrom", NULL, N_("Allow Outbound Service for Source"), NULL, N_("Allow outbound service for source"), hitview_allow_service_from },
	{ "DisableEventsSource", NULL, N_("Disable Events from Source"), NULL, N_("Do not show future events from this source"), hitview_disable_events_selected_source },
	{ "DisableEventsPort", NULL, N_("Disable Events on Port"), NULL, N_("Do not show future events from on this port"), hitview_disable_events_selected_port },
/*R*/	{ "LookupSelectedHit", GTK_STOCK_INDEX, N_("_Lookup Hostnames"), "<control>R", N_("Look up the hostnames of the selected hit"), hitview_lookup_selected_hit },

	{ "TerminateConnection", GTK_STOCK_CANCEL, N_("_Terminate Connection"), NULL, N_("Terminate the selected connection"), status_lookup_selected_connection },
	{ "LookupSelectedConnection", GTK_STOCK_INDEX, N_("_Lookup Hostnames"), NULL, N_("Look up the hostnames of the selected connection"), status_lookup_selected_connection },
};

/* Toggle items */
#define NUM_SHOW_TOGGLES 11
static GtkToggleActionEntry toggle_entries[] = {
	{ "ShowCol0", NULL, N_("Time"), "<control>1", N_("Show time column"), NULL, FALSE },
	{ "ShowCol1", NULL, N_("Direction"), "<control>2", N_("Show direction column"), NULL, FALSE },
	{ "ShowCol2", NULL, N_("In"), "<control>3", N_("Show in column"), NULL, FALSE },
	{ "ShowCol3", NULL, N_("Out"), "<control>4", N_("Show out column"), NULL, FALSE },
	{ "ShowCol4", NULL, N_("Port"), "<control>5", N_("Show port column"), NULL, FALSE },
	{ "ShowCol5", NULL, N_("Source"), "<control>6", N_("Show port column"), NULL, FALSE },
	{ "ShowCol6", NULL, N_("Destination"), "<control>7", N_("Show port column"), NULL, FALSE },
	{ "ShowCol7", NULL, N_("Length"), "<control>8", N_("Show port column"), NULL, FALSE },
	{ "ShowCol8", NULL, N_("ToS"), "<control>9", N_("Show port column"), NULL, FALSE },
	{ "ShowCol9", NULL, N_("Protocol"), "<control>0", N_("Show port column"), NULL, FALSE },
	{ "ShowCol10", NULL, N_("Service"), "<control>plus", N_("Show port column"), NULL, FALSE },
};

static const char *ui_description =
	"<ui>"
	"  <menubar name='MainMenu'>"
	"    <menu action='FirewallMenu'>"
	"      <menuitem action='RunWizard'/>"
	"      <separator name='sep1'/>"
	"      <menuitem action='StartFirewall'/>"
	"      <menuitem action='StopFirewall'/>"
	"      <menuitem action='LockFirewall'/>"
	"      <separator name='sep2'/>"
	"      <menuitem action='Quit'/>"
	"    </menu>"
	"    <menu action='EditMenu'>"
	"      <menuitem action='CopyEvent'/>"
	"      <separator/>"
	"      <menuitem action='Preferences'/>"
	"    </menu>"
	"    <menu action='EventsMenu'>"
	"      <menuitem action='ClearEventList'/>"
	"      <menuitem action='ReloadEventList'/>"
	"      <separator name='1'/>"
	"      <menuitem action='SaveEventList'/>"
	"      <separator name='2' />"
	"      <menu action='EventsShowSubmenu'>"
	"        <menuitem action='ShowCol0'/>"
	"        <menuitem action='ShowCol1'/>"
	"        <menuitem action='ShowCol2'/>"
	"        <menuitem action='ShowCol3'/>"
	"        <menuitem action='ShowCol4'/>"
	"        <menuitem action='ShowCol5'/>"
	"        <menuitem action='ShowCol6'/>"
	"        <menuitem action='ShowCol7'/>"
	"        <menuitem action='ShowCol8'/>"
	"        <menuitem action='ShowCol9'/>"
	"        <menuitem action='ShowCol10'/>"
	"      </menu>"
	"    </menu>"
	"    <menu action='PolicyMenu'>"
	"      <menuitem action='AddRule'/>"
	"      <menuitem action='RemoveRule'/>"
	"      <menuitem action='EditRule'/>"
	"      <separator/>"
	"      <menuitem action='ApplyPolicy'/>"
	"    </menu>"
	"    <menu action='HelpMenu'>"
	"      <menuitem action='OpenManual'/>"
	"      <menuitem action='OpenHomepage'/>"
	"      <separator/>"
	"      <menuitem action='ShowAbout'/>"
	"    </menu>"
	"  </menubar>"
	"  <toolbar name='Toolbar'>"
	"    <placeholder name='StatusbarWidgets'/>"
	"    <placeholder name='EventsbarWidgets'/>"
	"    <placeholder name='PolicybarWidgets'/>"
	"  </toolbar>"

	"  <popup name='EventsInboundContext'>"
	"    <menuitem action='AllowInboundFrom'/>"
	"    <menuitem action='AllowInboundService'/>"
	"    <menuitem action='AllowInboundServiceFrom'/>"
	"    <separator name='1'/>"
	"    <menuitem action='DisableEventsSource'/>"
	"    <menuitem action='DisableEventsPort'/>"
	"    <separator name='2'/>"
	"    <menuitem action='LookupSelectedHit'/>"
	"  </popup>"
	"  <popup name='EventsOutboundContext'>"
	"    <menuitem action='AllowOutboundTo'/>"
	"    <menuitem action='AllowOutboundService'/>"
	"    <menuitem action='AllowOutboundServiceFrom'/>"
	"    <separator name='1'/>"
	"    <menuitem action='DisableEventsSource'/>"
	"    <menuitem action='DisableEventsPort'/>"
	"    <separator name='2'/>"
	"    <menuitem action='LookupSelectedHit'/>"
	"  </popup>"

	"  <popup name='PolicyContext'>"
	"    <menuitem action='AddRule'/>"
	"    <menuitem action='RemoveRule'/>"
	"    <menuitem action='EditRule'/>"
	"  </popup>"

	"  <popup name='ConnectionsContext'>"
/*	"    <menuitem action='TerminateConnection'/>"
	"    <separator name=''/>" */
	"    <menuitem action='LookupSelectedConnection'/>"
	"  </popup>"

	"</ui>";

static const char *statusbar_description =
	"<toolbar name='Toolbar'>"
	"  <placeholder name='StatusbarWidgets'>"
/*	"    <toolitem action='RunWizard'/>" */
	"    <toolitem action='Preferences'/>"
	"    <separator/>"
	"    <placeholder name='FirewallStateActive'/>"
	"    <placeholder name='FirewallStateDisabled'/>"
	"    <placeholder name='FirewallStateLocked'/>"
	"    <placeholder name='FirewallStateUnlocked'/>"
	"  </placeholder>"
	"</toolbar>";

static const char *firewall_state_active_description =
	"<toolbar name='Toolbar'>"
	"  <placeholder name='FirewallStateActive'>"
	"    <toolitem name='StopFirewall' action='StopFirewall'/>"
	"  </placeholder>"
	"</toolbar>";

static const char *firewall_state_disabled_description =
	"<toolbar name='Toolbar'>"
	"  <placeholder name='FirewallStateDisabled'>"
	"    <toolitem name='StartFirewall' action='StartFirewall'/>"
	"  </placeholder>"
	"</toolbar>";

static const char *firewall_state_locked_description =
	"<toolbar name='Toolbar'>"
	"  <placeholder name='FirewallStateLocked'>"
	"    <toolitem action='UnlockFirewall'/>"
	"  </placeholder>"
	"</toolbar>";

static const char *firewall_state_unlocked_description =
	"<toolbar name='Toolbar'>"
	"  <placeholder name='FirewallStateUnlocked'>"
	"    <toolitem action='LockFirewall'/>"
	"  </placeholder>"
	"</toolbar>";

static const char *eventsbar_description =
	"<toolbar name='Toolbar'>"
	"  <placeholder name='EventsbarWidgets'>"
	"    <toolitem action='SaveEventList'/>"
	"    <separator/>"
	"    <toolitem action='ClearEventList'/>"
	"    <placeholder name='EventsReloading'/>"
	"    <placeholder name='EventsNotReloading'/>"
	"  </placeholder>"
	"</toolbar>";

static const char *events_reloading_description =
	"<toolbar name='Toolbar'>"
	"  <placeholder name='EventsReloading'>"
	"    <toolitem action='CancelReloadEventList'/>"
	"  </placeholder>"
	"</toolbar>";

static const char *events_not_reloading_description =
	"<toolbar name='Toolbar'>"
	"  <placeholder name='EventsNotReloading'>"
	"    <toolitem action='ReloadEventList'/>"
	"  </placeholder>"
	"</toolbar>";

static const char *policybar_description =
	"<toolbar name='Toolbar'>"
	"  <placeholder name='PolicybarWidgets'>"
	"    <toolitem action='AddRule'/>"
	"    <toolitem action='RemoveRule'/>"
	"    <toolitem action='EditRule'/>"
	"    <separator/>"
	"    <toolitem action='ApplyPolicy'/>"
	"  </placeholder>"
	"</toolbar>";

static void
register_icon_set (GtkIconFactory *icon_factory, const gchar *stock_id, const guint8 rgba_data [])
{
	GtkIconSet *icon_set;
	GtkIconSource *icon_source;
	GdkPixbuf *pixbuf;

	pixbuf = gdk_pixbuf_new_from_inline (-1, rgba_data, FALSE, NULL);
	icon_set = gtk_icon_set_new ();
	icon_source = gtk_icon_source_new ();

	gtk_icon_source_set_pixbuf (icon_source, pixbuf);
	gtk_icon_set_add_source (icon_set, icon_source);
	gtk_icon_factory_add (icon_factory, stock_id, icon_set);
}

static guint
merge_ui (const gchar *description)
{
	guint merge_id;
	GError *error;
	
	merge_id = gtk_ui_manager_add_ui_from_string (ui_manager, description, -1, &error); 
	if (!merge_id) {
		g_message ("Building menus failed: %s", error->message);
		g_error_free (error);
		exit (EXIT_FAILURE);
	}
	gtk_ui_manager_ensure_update (ui_manager);

	return merge_id;
}

/* [ menus_set_toolbar ]
 * Switch the application toolbar to a view specific one
 */
void
menus_set_toolbar (FortifiedView new_view)
{
	static guint merge_id = -1;
	const char *description;

	if (new_view == STATUS_VIEW)
		description = statusbar_description;
	else if (new_view == EVENTS_VIEW)
		description = eventsbar_description;
	else
		description = policybar_description;

	if (merge_id != -1) { /* Remove the previous toolbar contents */
		gtk_ui_manager_remove_ui (ui_manager, merge_id);
	}

	merge_id = merge_ui (description);
}

void
menus_update_firewall_controls_state (FirewallStatus state)
{
	static guint start_stop_merge_id = -1;
	static guint lock_merge_id = -1;
	const gchar *description = NULL;

	switch (state) {
	  case STATUS_HIT:
	  case STATUS_RUNNING: description = firewall_state_active_description; break;
	  case STATUS_STOPPED: description = firewall_state_disabled_description; break;
	  case STATUS_LOCKED:  description = firewall_state_locked_description; break;
	  case STATUS_NONE: break;
	  default: g_assert_not_reached ();
	}

	if (start_stop_merge_id != -1)
		gtk_ui_manager_remove_ui (ui_manager, start_stop_merge_id);
	if (lock_merge_id != -1)
		gtk_ui_manager_remove_ui (ui_manager, lock_merge_id);

	if (state == STATUS_NONE) { /* Do not add a toolbar item */
		start_stop_merge_id = -1;
		lock_merge_id = -1;
	} else {
		if (state == STATUS_HIT || state == STATUS_RUNNING || state == STATUS_STOPPED) {
			lock_merge_id = merge_ui (firewall_state_unlocked_description);
			start_stop_merge_id = merge_ui (description);
		} else if (state == STATUS_LOCKED)
			lock_merge_id = merge_ui (description);
	}
}

void
menus_update_events_reloading (gboolean in_progress, gboolean visible)
{
	static guint merge_id = -1;
	const gchar *description = NULL;

	if (in_progress)
		description = events_reloading_description;
	else
		description = events_not_reloading_description;

	if (merge_id != -1)
		gtk_ui_manager_remove_ui (ui_manager, merge_id);

	if (visible)
		merge_id = merge_ui (description);
	else
		merge_id = -1;
}

/* [ menus_initialize ]
 * Install the menus and the toolbar in *window
 */
void
menus_initialize (GtkWidget *window)
{
	GtkIconFactory *icon_factory;
	GtkWidget *menubar;
	GtkActionGroup *action_group;
	GError *error;
	guint merge_id;
	GtkWidget *toolbar;
	int i;

	icon_factory = gtk_icon_factory_new ();
	gtk_icon_factory_add_default (icon_factory);

	register_icon_set (icon_factory, FORTIFIED_STOCK_WIZARD, icon_wizard);
	register_icon_set (icon_factory, FORTIFIED_STOCK_START_FIREWALL, icon_start_toolbar);
	register_icon_set (icon_factory, FORTIFIED_STOCK_STOP_FIREWALL, icon_stop_toolbar);
	register_icon_set (icon_factory, FORTIFIED_STOCK_EDIT, icon_edit);
	register_icon_set (icon_factory, FORTIFIED_STOCK_LOCK_FIREWALL, icon_locked);
	register_icon_set (icon_factory, FORTIFIED_STOCK_UNLOCK_FIREWALL, icon_unlocked);

	action_group = gtk_action_group_new ("MenuActions");
	gtk_action_group_set_translation_domain (action_group, GETTEXT_PACKAGE);
	gtk_action_group_add_actions (action_group, entries, G_N_ELEMENTS (entries), window);

	toggle_entries[0].is_active = preferences_get_bool (PREFS_HITVIEW_TIME_COL);
	toggle_entries[1].is_active = preferences_get_bool (PREFS_HITVIEW_DIRECTION_COL);
	toggle_entries[2].is_active = preferences_get_bool (PREFS_HITVIEW_IN_COL);
	toggle_entries[3].is_active = preferences_get_bool (PREFS_HITVIEW_OUT_COL);
	toggle_entries[4].is_active = preferences_get_bool (PREFS_HITVIEW_PORT_COL);
	toggle_entries[5].is_active = preferences_get_bool (PREFS_HITVIEW_SOURCE_COL);
	toggle_entries[6].is_active = preferences_get_bool (PREFS_HITVIEW_DESTINATION_COL);
	toggle_entries[7].is_active = preferences_get_bool (PREFS_HITVIEW_LENGTH_COL);
	toggle_entries[8].is_active = preferences_get_bool (PREFS_HITVIEW_TOS_COL);
	toggle_entries[9].is_active = preferences_get_bool (PREFS_HITVIEW_PROTOCOL_COL);
	toggle_entries[10].is_active = preferences_get_bool (PREFS_HITVIEW_SERVICE_COL);

	gtk_action_group_add_toggle_actions (action_group, toggle_entries, G_N_ELEMENTS (toggle_entries), NULL);

	ui_manager = gtk_ui_manager_new ();
	gtk_ui_manager_insert_action_group (ui_manager, action_group, 0);

	main_accel_group = gtk_ui_manager_get_accel_group (ui_manager);
	gtk_window_add_accel_group (GTK_WINDOW (window), main_accel_group);
	g_object_unref (main_accel_group);

	error = NULL;
	merge_id = gtk_ui_manager_add_ui_from_string (ui_manager, ui_description, -1, &error);
	if (!merge_id) {
		g_message ("Building menus failed: %s", error->message);
		g_error_free (error);
		exit (EXIT_FAILURE);
	}
	
	for (i = 0; i < NUM_SHOW_TOGGLES; i++) { /* Register new callbacks for all toggle items */
		GtkWidget *toggle;
		gchar *path;

		path = g_strdup_printf ("/MainMenu/EventsMenu/EventsShowSubmenu/ShowCol%d", i);
		toggle = gtk_ui_manager_get_widget (ui_manager, path);
		g_signal_connect (G_OBJECT (toggle), "toggled",
		                  G_CALLBACK (hitview_toggle_column_visibility), (gint*)i);
		
		g_free (path); 
	}

	menubar = gtk_ui_manager_get_widget (ui_manager, "/MainMenu");
	gnome_app_set_menus (GNOME_APP (window), GTK_MENU_BAR (menubar));

	toolbar = gtk_ui_manager_get_widget (ui_manager, "/Toolbar");
	gnome_app_set_toolbar (GNOME_APP (Fortified.window), GTK_TOOLBAR (toolbar));
	/* gtk_toolbar_set_style (GTK_TOOLBAR (toolbar), GTK_TOOLBAR_ICONS); */

	menus_set_toolbar (STATUS_VIEW);
	menus_update_firewall_controls_state (STATUS_RUNNING);
	menus_update_events_reloading (FALSE, FALSE);
}

GtkWidget *
menus_get_events_inbound_context_menu (void)
{
	return gtk_ui_manager_get_widget (ui_manager, "/EventsInboundContext");
}

GtkWidget *
menus_get_events_outbound_context_menu (void)
{
	return gtk_ui_manager_get_widget (ui_manager, "/EventsOutboundContext");
}

GtkWidget *
menus_get_policy_context_menu (void)
{
	return gtk_ui_manager_get_widget (ui_manager, "/PolicyContext");
}

GtkWidget *
menus_get_connections_context_menu (void)
{
	return gtk_ui_manager_get_widget (ui_manager, "/ConnectionsContext");
}

void
menus_events_save_enabled (gboolean enabled)
{
	GtkAction *action;

	action = gtk_ui_manager_get_action (ui_manager, "/MainMenu/EventsMenu/SaveEventList");
	g_object_set (G_OBJECT (action), "sensitive", enabled, NULL);
}

void
menus_events_clear_enabled (gboolean enabled)
{
	GtkAction *action;

	action = gtk_ui_manager_get_action (ui_manager, "/MainMenu/EventsMenu/ClearEventList");
	g_object_set (G_OBJECT (action), "sensitive", enabled, NULL);
}

void
menus_policy_edit_enabled (gboolean enabled)
{
	GtkAction *action;

	action = gtk_ui_manager_get_action (ui_manager, "/PolicyContext/EditRule");
	g_object_set (G_OBJECT (action), "sensitive", enabled, NULL);
}

void
menus_policy_remove_enabled (gboolean enabled)
{
	GtkAction *action;

	action = gtk_ui_manager_get_action (ui_manager, "/PolicyContext/RemoveRule");
	g_object_set (G_OBJECT (action), "sensitive", enabled, NULL);
}

void
menus_policy_add_enabled (gboolean enabled)
{
	GtkAction *action;

	action = gtk_ui_manager_get_action (ui_manager, "/PolicyContext/AddRule");
	g_object_set (G_OBJECT (action), "sensitive", enabled, NULL);
}

void
menus_policy_apply_enabled (gboolean enabled)
{
	GtkAction *action;

	action = gtk_ui_manager_get_action (ui_manager, "/MainMenu/PolicyMenu/ApplyPolicy");
	g_object_set (G_OBJECT (action), "sensitive", enabled, NULL);
}

static void
open_homepage (void)
{
	open_browser ("https://github.com/draekko-rand/fortified");
}

static void
open_manual (void)
{
	open_browser ("https://github.com/draekko-rand/fortified/wiki");
}

/* [ copy_selected ]
 * Copy the selection in the active view to the clipboard
 */
static void
copy_selected (void)
{
	FortifiedView v;

	v = gui_get_active_view ();

	if (v == EVENTS_VIEW)
		copy_selected_hit ();
}
