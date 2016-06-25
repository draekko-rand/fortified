/*---[ wizard.c ]------------------------------------------------------
 * Copyright (C) 2000-2002 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.de
 *
 * The wizard functions
 *--------------------------------------------------------------------*/
#include "globals.h"
#include "fortified.h"
#include "wizard.h"
#include "wizard-choices.h"
#include "scriptwriter.h"
#include "util.h"
#include "xpm/fortified-pixbufs.h"
#include "preferences.h"
#include "dhcp-server.h"
#include "gui.h"
#include "statusview.h"

enum
{
	RESPONSE_GO_BACK,
	RESPONSE_GO_FORWARD,
	RESPONSE_QUIT,
	RESPONSE_FINISHED
};

enum
{
	WIZARD_WELCOME_PAGE,
	WIZARD_NET_DEVICE_PAGE,
	WIZARD_NAT_PAGE,
	WIZARD_FINISHED_PAGE
};

static void
ext_device_selection_changed (GtkComboBox *combo, Wizard *data)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	gchar *interface;

	gtk_combo_box_get_active_iter (combo, &iter);
	model = gtk_combo_box_get_model (combo);
	gtk_tree_model_get (model, &iter, 1, &interface, -1);

	data->extdevice = interface;
}

static void
int_device_selection_changed (GtkComboBox *combo, Wizard *data)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	gchar *interface;

	gtk_combo_box_get_active_iter (combo, &iter);
	model = gtk_combo_box_get_model (combo);
	gtk_tree_model_get (model, &iter, 1, &interface, -1);

	data->intdevice = interface;
}

static gboolean
combo_set_active_device (GtkComboBox *combo, gchar *new_if)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	gchar *interface = NULL;

	model = gtk_combo_box_get_model (combo);

	gtk_tree_model_get_iter_first (model, &iter);
	do {
		gtk_tree_model_get (model, &iter, 1, &interface, -1);
		if (interface != NULL && new_if != NULL &&
		    g_str_equal (interface, new_if)) {
			gtk_combo_box_set_active_iter (combo, &iter);
			return TRUE;
		}
	} while (gtk_tree_model_iter_next (model, &iter));

	return FALSE;
}

/* [ create_device_page ]
 * Create the contents of the simple device selection page
 */
GtkWidget*
create_device_page (Wizard *data)
{
	GtkWidget *table;
	GtkWidget *label;
	GtkWidget *hbox;
	GtkWidget *combo;
	GtkCellRenderer *renderer;

	table = gtk_table_new (5, 2, FALSE);
	gtk_table_set_row_spacings (GTK_TABLE(table), GNOME_PAD_SMALL);
	gtk_table_set_col_spacings (GTK_TABLE(table), GNOME_PAD_SMALL);

	label = gtk_label_new (_(
		"Please select your Internet connected network device from the drop-down\n"
		"list of available devices."));
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.0);
	gtk_label_set_justify (GTK_LABEL (label), GTK_JUSTIFY_LEFT);
	gtk_table_attach (GTK_TABLE (table), label, 0, 1, 0, 1,
		GTK_FILL, GTK_FILL, GNOME_PAD, GNOME_PAD);

	hbox = gtk_hbox_new (FALSE, GNOME_PAD_SMALL);
	gtk_table_attach (GTK_TABLE (table), hbox, 0, 1, 1, 2,
		GTK_FILL, GTK_FILL, GNOME_PAD, 2);

 	label = gtk_label_new (_("Detected device(s):"));
	gtk_box_pack_start (GTK_BOX (hbox), label, FALSE, FALSE, 5);

	combo = gtk_combo_box_new_with_model (get_devices_model ());
	renderer = gtk_cell_renderer_text_new ();
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (combo), renderer, FALSE);
	gtk_cell_layout_set_attributes (GTK_CELL_LAYOUT (combo), renderer, "text", 0, NULL);
	g_signal_connect (combo, "changed",
	                  G_CALLBACK (ext_device_selection_changed), data);
	if (!combo_set_active_device (GTK_COMBO_BOX (combo),
	                              preferences_get_string (PREFS_FW_EXT_IF))) {
		printf ("Warning: External interface previously configured not found\n");
		gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 0); /* Default to the first item */
	}

	gtk_box_pack_start (GTK_BOX (hbox), combo, FALSE, FALSE, 5);

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<small>", _(
		"Tip: If you use a modem the device name is likely ppp0. If you have a cable modem or a\n"
		"DSL connection, choose eth0. Choose ppp0 if you know your cable or DSL operator uses\n"
		"the PPPoE protocol."
		), "</small>", NULL));
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.0);
	gtk_label_set_justify (GTK_LABEL (label), GTK_JUSTIFY_LEFT);
	gtk_table_attach (GTK_TABLE (table), label, 0, 1, 2, 3,
		GTK_FILL, GTK_FILL, GNOME_PAD, GNOME_PAD);

	data->pppcheck = gtk_check_button_new_with_label (_(
		"Start the firewall on dial-out"));
	gtk_tooltips_set_tip (Fortified.ttips, data->pppcheck, _(
		"Check this option and the firewall will start when "
		"you dial your Internet Service Provider."), "");
	gtk_table_attach (GTK_TABLE (table), data->pppcheck, 0, 2, 3, 4,
		GTK_FILL, GTK_FILL, GNOME_PAD, 0);

	data->dhcpcheck = gtk_check_button_new_with_label (_(
		"IP address is assigned via DHCP"));
	gtk_tooltips_set_tip (Fortified.ttips, data->dhcpcheck, _(
		"Check this option if you need to connect to a DHCP server. "
		"Cable modem and DSL users should check this."), "");

	gtk_table_attach (GTK_TABLE (table), data->dhcpcheck, 0, 2, 4, 5,
		GTK_FILL, GTK_FILL, GNOME_PAD, 0);

	return table;
}

static void
manual_reference_enter (GtkWidget *widget)
{
	const gchar *text = gtk_label_get_text (GTK_LABEL (widget));
	gtk_label_set_markup (GTK_LABEL (widget), g_strconcat (
			      "<span foreground=\"red\" underline=\"single\">",
			      text, "</span>", NULL));
}

static void
manual_reference_leave (GtkWidget *widget)
{
	const gchar *text = gtk_label_get_text (GTK_LABEL (widget));
	gtk_label_set_markup (GTK_LABEL (widget), g_strconcat (
			      "<span foreground=\"blue\" underline=\"none\">",
			      text, "</span>", NULL));
}

static GtkWidget*
manual_reference_new (gchar *description, gchar *url)
{
	GtkWidget *event_box = gtk_event_box_new ();
	GtkWidget *label = gtk_label_new (NULL);

	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
			      "<span foreground=\"blue\">",
			      description, "</span>", NULL));

	gtk_container_add (GTK_CONTAINER (event_box), label);

	gtk_widget_set_events (event_box, GDK_BUTTON_PRESS_MASK | GDK_ENTER_NOTIFY_MASK | GDK_LEAVE_NOTIFY_MASK);
	g_signal_connect_swapped (G_OBJECT (event_box), "button_press_event",
		G_CALLBACK (open_browser), "https://github.com/draekko-rand/fortified/wiki");

	g_signal_connect_swapped (G_OBJECT (event_box), "enter_notify_event",
		G_CALLBACK (manual_reference_enter), label);
	g_signal_connect_swapped (G_OBJECT (event_box), "leave_notify_event",
		G_CALLBACK (manual_reference_leave), label);

	gtk_event_box_set_above_child (GTK_EVENT_BOX (event_box), TRUE);

	return event_box;
}

/* [ create_masq_page ]
 * Create the contents of the ipmasq setup page
 */
GtkWidget*
create_masq_page (Wizard *data)
{
	GtkWidget *table;
	GtkWidget *table2;
	GtkWidget *table3;
	GtkWidget *label;
	GtkWidget *nat_enabled;
	GtkWidget *combo;
	GtkCellRenderer *renderer;
	GtkWidget *vbox;
	GtkWidget *dhcp_server;
	GtkWidget *dhcp_expander;
	GtkWidget *dhcp_keep_config;
	GtkWidget *dhcp_new_config;
	GtkWidget *dhcp_lowest_ip;
	GtkWidget *dhcp_highest_ip;
	GtkWidget *dhcp_nameserver;

	table = gtk_table_new (2, 2, FALSE);
	gtk_table_set_row_spacings (GTK_TABLE (table), GNOME_PAD_SMALL);
	gtk_table_set_col_spacings (GTK_TABLE (table), GNOME_PAD_SMALL);

	label = gtk_label_new (_(
		"Fortified can share your Internet connection with the computers on your local network\n"
		"using a single public IP address and a method called Network Address Translation."));

	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.0);
	gtk_label_set_justify (GTK_LABEL (label), GTK_JUSTIFY_LEFT);
	gtk_table_attach (GTK_TABLE (table), label, 0, 2, 0, 1,
		GTK_FILL, GTK_FILL, GNOME_PAD, GNOME_PAD_SMALL);

	nat_enabled = gtk_check_button_new_with_label (_("Enable Internet connection sharing"));
	gtk_table_attach (GTK_TABLE (table), nat_enabled, 0, 2, 2, 3,
		GTK_FILL, GTK_FILL, GNOME_PAD, GNOME_PAD_SMALL);

	data->masq = nat_enabled;

	vbox = gtk_vbox_new (FALSE, GNOME_PAD);
	gtk_widget_set_sensitive (vbox, gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (data->masq)));
	gtk_table_attach (GTK_TABLE (table), vbox, 0, 2, 3, 4,
		GTK_FILL, GTK_FILL, GNOME_PAD, 0);

	gui_widget_sensitivity_sync (GTK_TOGGLE_BUTTON (nat_enabled), vbox);

	table2 = gtk_table_new (2, 5, FALSE);
	gtk_table_set_row_spacings (GTK_TABLE(table2), GNOME_PAD_SMALL);
	gtk_table_set_col_spacings (GTK_TABLE(table2), GNOME_PAD_SMALL);
	gtk_box_pack_start (GTK_BOX (vbox), table2, FALSE, FALSE, 0);

 	label = gtk_label_new (_("Local area network device:"));
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
	gtk_label_set_justify (GTK_LABEL (label), GTK_JUSTIFY_LEFT);
	gtk_table_attach (GTK_TABLE (table2), label, 0, 1, 0, 1,
		GTK_FILL, GTK_FILL, GNOME_PAD, 3);

	combo = gtk_combo_box_new_with_model (get_devices_model ());
	renderer = gtk_cell_renderer_text_new ();
	gtk_cell_layout_pack_start (GTK_CELL_LAYOUT (combo), renderer, FALSE);
	gtk_cell_layout_set_attributes (GTK_CELL_LAYOUT (combo), renderer, "text", 0, NULL);
	g_signal_connect (combo, "changed",
	                  G_CALLBACK (int_device_selection_changed), data);
	if (!combo_set_active_device (GTK_COMBO_BOX (combo),
	                              preferences_get_string (PREFS_FW_INT_IF))) {
		printf ("Warning: Internal interface previously configured not found\n");
		gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 0); /* Default to the first item */
	}
	gtk_table_attach (GTK_TABLE (table2), combo, 1, 2, 0, 1,
		GTK_FILL, GTK_FILL, GNOME_PAD, 3);

	dhcp_server = gtk_check_button_new_with_label (_("Enable DHCP for local network"));
	gtk_table_attach (GTK_TABLE (table2), dhcp_server, 0, 1, 1, 2,
		GTK_FILL, GTK_FILL, GNOME_PAD, 3);

	label = manual_reference_new (_("Explain the DHCP function..."),
				     "https://github.com/draekko-rand/fortified/wiki");

	gtk_table_attach (GTK_TABLE (table2), label, 1, 2, 1, 2,
		GTK_FILL, GTK_FILL, GNOME_PAD, 3);

	dhcp_expander = gtk_expander_new (_("DHCP server details"));
	gtk_expander_set_spacing (GTK_EXPANDER (dhcp_expander), 3);
	gtk_table_attach (GTK_TABLE (table2), dhcp_expander, 0, 2, 2, 3,
		GTK_FILL, GTK_FILL, GNOME_PAD, 0);
	gtk_expander_set_expanded (GTK_EXPANDER (dhcp_expander), TRUE);
	gtk_expander_set_expanded (GTK_EXPANDER (dhcp_expander), FALSE);

	gtk_widget_set_sensitive (dhcp_expander, FALSE);

	/* If a dhcpd binary exists, allow the user to configure it */
	if (dhcp_server_exists ()) {
		gui_widget_sensitivity_sync (GTK_TOGGLE_BUTTON (dhcp_server), dhcp_expander);
	} else {
		gtk_widget_set_sensitive (dhcp_server, FALSE);
	}

	vbox = gtk_vbox_new (FALSE, GNOME_PAD);
	gtk_container_add (GTK_CONTAINER (dhcp_expander), vbox);

	dhcp_keep_config = gtk_radio_button_new_with_label (NULL,
		_("Keep existing DHCP configuration"));
	gtk_box_pack_start (GTK_BOX (vbox), dhcp_keep_config, FALSE, FALSE, 0);

	dhcp_new_config = gtk_radio_button_new_with_label_from_widget (GTK_RADIO_BUTTON (dhcp_keep_config),
		_("Create new DHCP configuration:"));
	gtk_box_pack_start (GTK_BOX (vbox), dhcp_new_config, FALSE, FALSE, 0);

	table3 = gtk_table_new (2, 5, FALSE);
	gtk_table_set_row_spacings (GTK_TABLE(table3), GNOME_PAD_SMALL);
	gtk_table_set_col_spacings (GTK_TABLE(table3), GNOME_PAD_SMALL);
	gtk_box_pack_start (GTK_BOX (vbox), table3, FALSE, FALSE, 0);

	if (dhcp_server_configuration_exists ()) {
		gtk_widget_set_sensitive (table3, FALSE);
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (dhcp_new_config), TRUE);
		gtk_widget_set_sensitive (dhcp_keep_config, FALSE);
	}

	gui_widget_sensitivity_sync (GTK_TOGGLE_BUTTON (dhcp_new_config), table3);

	label = gtk_label_new (_("Lowest IP address to assign:"));
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
	gtk_table_attach (GTK_TABLE (table3), label, 0, 1, 2, 3,
		GTK_FILL, GTK_FILL, GNOME_PAD, 0);

	dhcp_lowest_ip = gtk_entry_new ();
	gtk_entry_set_text (GTK_ENTRY (dhcp_lowest_ip), preferences_get_string (PREFS_FW_DHCP_LOWEST_IP)); 
	gtk_table_attach (GTK_TABLE (table3), dhcp_lowest_ip, 1, 2, 2, 3,
		GTK_FILL, GTK_FILL, GNOME_PAD, 0);

	label = gtk_label_new (_("Highest IP address to assign:"));
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
	gtk_table_attach (GTK_TABLE (table3), label, 0, 1, 3, 4,
		GTK_FILL, GTK_FILL, GNOME_PAD, 0);

	dhcp_highest_ip = gtk_entry_new ();
	gtk_entry_set_text (GTK_ENTRY (dhcp_highest_ip), preferences_get_string (PREFS_FW_DHCP_HIGHEST_IP));
	gtk_table_attach (GTK_TABLE (table3), dhcp_highest_ip, 1, 2, 3, 4,
		GTK_FILL, GTK_FILL, GNOME_PAD, 0);

	label = gtk_label_new (_("Name server:"));
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.5);
	gtk_table_attach (GTK_TABLE (table3), label, 0, 1, 4, 5,
		GTK_FILL, GTK_FILL, GNOME_PAD, 0);

	dhcp_nameserver = gtk_entry_new ();
	gtk_entry_set_text (GTK_ENTRY (dhcp_nameserver), preferences_get_string (PREFS_FW_DHCP_NAMESERVER));
	gtk_table_attach (GTK_TABLE (table3), dhcp_nameserver, 1, 2, 4, 5,
		GTK_FILL, GTK_FILL, GNOME_PAD, 0);

	/* Bind controls we need later to wizard struct */
	data->dhcp_server = dhcp_server;
	data->dhcp_new_config = dhcp_new_config;
	data->dhcp_lowest_ip = dhcp_lowest_ip;
	data->dhcp_highest_ip = dhcp_highest_ip;
	data->dhcp_nameserver = dhcp_nameserver;

	return table;
}

/* [ create_welcome_page ]
 * Create the contents of the welcoming screen
 */
static GtkWidget*
create_welcome_page (Wizard *data)
{
	GtkWidget *label;
	GtkWidget *image;
	GtkWidget *hbox;
	GtkWidget *vbox;
	GdkPixbuf *pixbuf;

	hbox = gtk_hbox_new (FALSE, GNOME_PAD_BIG);

 	pixbuf = gdk_pixbuf_new_from_inline (-1, pengo, FALSE, NULL);
	image = gtk_image_new_from_pixbuf (pixbuf);
	g_object_unref (G_OBJECT(pixbuf));
	gtk_box_pack_start (GTK_BOX(hbox), image, FALSE, FALSE, 0);

	vbox = gtk_vbox_new (FALSE, GNOME_PAD_SMALL);
	gtk_box_pack_start (GTK_BOX(hbox), vbox, FALSE, FALSE, 0);


	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (_(
		"This wizard will help you to set up a firewall for your\n"
		"Linux machine. You will be asked some questions\n"
		"about your network setup in order to customize the\n"
		"firewall for your system.\n\n"),
		"<small>", _(
		"Tip: If you are uncertain of how to answer a question it is\n"
		"best to use the default value supplied.\n\n"
		), "</small>",
		_("Please press the forward button to continue.\n"), NULL)
	);
	gtk_box_pack_start (GTK_BOX(vbox), label, FALSE, FALSE, 0);


	return hbox;
}

/* [ create_finish_page ]
 * Create the contents of the final wizard screen
 */
static GtkWidget*
create_finish_page (Wizard *data)
{
	FirewallStatus state;
	GtkWidget *label;
	GtkWidget *vbox;
	GtkWidget *check_start_now;

	vbox = gtk_vbox_new (FALSE, GNOME_PAD_SMALL);

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<b>", _("The wizard is now ready to start your firewall."), "</b>",
		"\n\n", _("Press the save button to continue, or the back button to review your choices."),
		NULL)
	);
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.0);
	gtk_box_pack_start (GTK_BOX(vbox), label, FALSE, FALSE, GNOME_PAD_SMALL);

	check_start_now = gtk_check_button_new_with_label (_("Start firewall now"));
	gtk_box_pack_start (GTK_BOX(vbox), check_start_now, FALSE, FALSE, GNOME_PAD_SMALL);

	label = gtk_label_new (NULL);
	gtk_label_set_markup (GTK_LABEL (label), g_strconcat (
		"<small>", _(
		"Tip: If you are connecting to the firewall host remotely you might want to\n"
		"defer starting the firewall until you have created additional policy."),
		"</small>", NULL)
	);
	gtk_misc_set_alignment (GTK_MISC (label), 0.0, 0.0);
	gtk_box_pack_start (GTK_BOX(vbox), label, FALSE, FALSE, GNOME_PAD_SMALL);

	state = status_get_state ();

	/* Default to starting firewall on the first run, or if the firewall
	   was already started */
	if (preferences_get_bool (PREFS_FIRST_RUN) ||
	    !script_exists () ||
	    state == STATUS_RUNNING ||
	    state == STATUS_HIT) {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (check_start_now), TRUE);
	}

	data->start_firewall = check_start_now;

	return vbox;
}

/* [ create_page ]
 * Create the default wizard page layout container
 */
static GtkWidget *
create_page (const char *title)
{
	GtkWidget *label;
	GtkWidget *vbox;
	GtkWidget *hbox;
	GtkWidget *alignment;
	GtkWidget *image;
	GdkPixbuf *pixbuf;
	gchar *title_string;

	/* create vbox */
	vbox = gtk_vbox_new (FALSE, GNOME_PAD);

	/* create the titlebar */
	hbox = gtk_hbox_new (FALSE, GNOME_PAD_BIG);
	pixbuf = gdk_pixbuf_new_from_inline (-1, logo, FALSE, NULL);
	image = gtk_image_new_from_pixbuf (pixbuf);
	g_object_unref (G_OBJECT(pixbuf));
	gtk_box_pack_start (GTK_BOX(hbox), image, FALSE, FALSE, 0);

	alignment = gtk_alignment_new (1.0, 1.0, 1.0, 1.0);
	gtk_box_pack_start (GTK_BOX(hbox), alignment, TRUE, TRUE, 0);

	title_string = g_strconcat ("<span size=\"xx-large\" weight=\"ultrabold\">", title ? title : "", "</span>", NULL);
	label = gtk_label_new (title_string);
	gtk_label_set_use_markup (GTK_LABEL(label), TRUE);
	g_free (title_string);
	gtk_container_add (GTK_CONTAINER(alignment), label);
	//gtk_box_pack_start (GTK_BOX(hbox), label, FALSE, FALSE, 0);

	/* pack the titlebar */
	gtk_box_pack_start (GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

	/* pack the separator */
	gtk_box_pack_start (GTK_BOX(vbox), gtk_hseparator_new(), FALSE, FALSE, 0);

	return vbox;
}

/* [ dialog_response_cb ]
 * Controls what happens when one of the wizard buttons are pressed
 * Possible page flow control code would go here
 */
static void
dialog_response_cb (GtkDialog *dialog, int response, gpointer data)
{
	Wizard *wizard = (Wizard *)data;
	int current_page = gtk_notebook_get_current_page (GTK_NOTEBOOK(wizard->notebook));

	if (response == RESPONSE_QUIT) {
		if (preferences_get_bool (PREFS_FIRST_RUN) || !script_exists ())
			exit_fortified ();

		g_free (wizard);
		gtk_widget_destroy (GTK_WIDGET(dialog));

	}  else if (response == RESPONSE_GO_FORWARD && current_page == WIZARD_NAT_PAGE) {
	/* Validate the choices made on the NAT page */
		gboolean validates = TRUE;

		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (wizard->masq)) &&
		    g_str_equal (wizard->extdevice, wizard->intdevice)) {
			gchar *message;
			message = g_strconcat ("<span weight=\"bold\" size=\"larger\">",
			                       _("Please review your choices"), "\n\n</span>",
			                       _("The local area and the Internet connected devices can not be the same."),
			                       NULL);
			show_error (message);
			g_free (message);
			validates = FALSE;
		} else if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (wizard->dhcp_server)) &&
		          gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (wizard->dhcp_new_config))) {
			const gchar *nameserver = gtk_entry_get_text (GTK_ENTRY (wizard->dhcp_nameserver));

			validates = (is_a_valid_host (gtk_entry_get_text (GTK_ENTRY (wizard->dhcp_highest_ip))) &&
				     is_a_valid_host (gtk_entry_get_text (GTK_ENTRY (wizard->dhcp_lowest_ip))) &&
				     (is_a_valid_host (nameserver) || g_ascii_strcasecmp (nameserver, "<dynamic>") == 0));

			if (!validates) {
				gchar *message;
				message = g_strconcat ("<span weight=\"bold\" size=\"larger\">",
				                       _("Please review your choices"), "\n\n</span>",
				                       _("The supplied DHCP configuration is not valid."),
				                       NULL);
				show_error (message);
				g_free (message);
			}
		}

		if (validates) {
			gtk_notebook_set_current_page (GTK_NOTEBOOK(wizard->notebook), ++current_page);
			gtk_dialog_set_response_sensitive (dialog, RESPONSE_GO_FORWARD, current_page < WIZARD_FINISHED_PAGE);
			gtk_dialog_set_response_sensitive (dialog, RESPONSE_FINISHED, current_page == WIZARD_FINISHED_PAGE);
		}

	} else if (response == RESPONSE_FINISHED) {

		save_choices (wizard);
		scriptwriter_output_scripts ();

		/* Write DHCP configuration */
		if (preferences_get_bool (PREFS_FW_NAT) &&
		    preferences_get_bool (PREFS_FW_DHCP_ENABLE) &&
		    gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (wizard->dhcp_new_config)))
			dhcp_server_create_configuration ();

		if (preferences_get_bool (PREFS_FIRST_RUN)) {
			/* Mark that the wizard has been run at least once */
			preferences_set_bool (PREFS_FIRST_RUN, FALSE);
		}

		/* Finally, start the firewall */
		if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (wizard->start_firewall)))
			start_firewall ();

		g_free (wizard);
		gtk_widget_destroy (GTK_WIDGET(dialog));

		/* Show the main interface */
		gui_set_visibility (TRUE);
	} else {
		if (response == RESPONSE_GO_BACK) {
			gtk_notebook_set_current_page (GTK_NOTEBOOK(wizard->notebook), --current_page);
		} else if (response == RESPONSE_GO_FORWARD) {
			gtk_notebook_set_current_page (GTK_NOTEBOOK(wizard->notebook), ++current_page);
		}

		gtk_dialog_set_response_sensitive (dialog, RESPONSE_GO_BACK, current_page > 0);
		gtk_dialog_set_response_sensitive (dialog, RESPONSE_GO_FORWARD, current_page < WIZARD_FINISHED_PAGE);
		gtk_dialog_set_response_sensitive (dialog, RESPONSE_FINISHED, current_page == WIZARD_FINISHED_PAGE);
	}
}

/* [ run_wizard ]
 * Run the firewall wizard
 */
void
run_wizard (void)
{
	Wizard *wizard;
	GtkWidget *dialog;
	GtkWidget *notebook;
	GtkWidget *page;
	GtkWidget *alignment;
	gint i;

	wizard = g_new (Wizard, 1);
	
	dialog = gtk_dialog_new_with_buttons (_("Firewall Wizard"),
	                                      NULL, 0,
	                                      GTK_STOCK_GO_BACK, RESPONSE_GO_BACK,
	                                      GTK_STOCK_GO_FORWARD, RESPONSE_GO_FORWARD,
	                                      GTK_STOCK_SAVE, RESPONSE_FINISHED,
	                                      GTK_STOCK_QUIT, RESPONSE_QUIT,
	                                      NULL);

	g_signal_connect (dialog, "response",
	                  G_CALLBACK(dialog_response_cb), wizard);

	gtk_dialog_set_default_response   (GTK_DIALOG(dialog), RESPONSE_GO_FORWARD);
	gtk_dialog_set_response_sensitive (GTK_DIALOG(dialog), RESPONSE_GO_BACK, FALSE);
	gtk_dialog_set_response_sensitive (GTK_DIALOG(dialog), RESPONSE_GO_FORWARD, TRUE);
	gtk_dialog_set_response_sensitive (GTK_DIALOG(dialog), RESPONSE_FINISHED, FALSE);

	/* The wizard is a notebook widget without tabs */
	notebook = wizard->notebook = gtk_notebook_new ();
	gtk_notebook_set_show_tabs (GTK_NOTEBOOK(notebook), FALSE);
	gtk_notebook_set_show_border (GTK_NOTEBOOK(notebook), FALSE);
	gtk_box_pack_start (GTK_BOX(GTK_DIALOG(dialog)->vbox), notebook, TRUE, TRUE, 0);

	/* Create the basic wizard pages */
	wizard->pages = g_ptr_array_new ();

	page = create_page (_("Welcome to Fortified"));
	alignment = gtk_alignment_new (0.5, 0.5, 0.5, 0.5);
	gtk_box_pack_start (GTK_BOX(page), alignment, TRUE, TRUE, 0);
	gtk_container_add (GTK_CONTAINER(alignment), create_welcome_page (wizard));
	g_ptr_array_add (wizard->pages, page);

	page = create_page (_("Network device setup"));
	alignment = gtk_alignment_new (0.5, 0.5, 0.5, 0.5);
	gtk_box_pack_start (GTK_BOX(page), alignment, TRUE, TRUE, 0);
	gtk_container_add (GTK_CONTAINER(alignment), create_device_page (wizard));
	g_ptr_array_add (wizard->pages, page);

	page = create_page (_("Internet connection sharing setup"));
	alignment = gtk_alignment_new (0.5, 0.5, 0.5, 0.5);
	gtk_box_pack_start (GTK_BOX(page), alignment, TRUE, TRUE, 0);
	gtk_container_add (GTK_CONTAINER(alignment), create_masq_page (wizard));
	g_ptr_array_add (wizard->pages, page);

	/* Final page */
	page = create_page (_("Ready to start your firewall"));
	alignment = gtk_alignment_new (0.5, 0.5, 0.5, 0.5);
	gtk_box_pack_start (GTK_BOX(page), alignment, TRUE, TRUE, 0);
	gtk_container_add (GTK_CONTAINER(alignment), create_finish_page (wizard));
	g_ptr_array_add (wizard->pages, page);

	/* Load pages into notebook */
	for (i = 0; i < wizard->pages->len; i++) {
		gtk_notebook_append_page (GTK_NOTEBOOK(notebook),
		                          GTK_WIDGET(g_ptr_array_index (wizard->pages,i)),
		                          NULL);
	}

	/* Set some simple defaults when run for the first time, otherwise load previous choices */
	if (!preferences_get_bool (PREFS_FIRST_RUN)) {
		load_choices (wizard);
	}

	gtk_window_set_default_size (GTK_WINDOW (dialog), -1, 350);
	gtk_widget_show_all (dialog);
}
