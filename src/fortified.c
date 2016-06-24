/*---[ fortified.c ]------------------------------------------------
 * Copyright (C) 2000-2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * The main application file
 *--------------------------------------------------------------------*/

#include <config.h>
#include <gnome.h>
#include <sys/stat.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <errno.h>
#include <popt.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "globals.h"
#include "fortified.h"
#include "gui.h"
#include "menus.h"
#include "util.h"
#include "logread.h"
#include "wizard.h"
#include "preferences.h"
#include "scriptwriter.h"
#include "dhcp-server.h"
#include "statusview.h"

FortifiedApp Fortified;

static gint save_session (GnomeClient       *client,
                          gint               phase,
                          GnomeSaveStyle     save_style,
                          gint               is_shutdown,
                          GnomeInteractStyle interact_style,
                          gint               is_fast,
                          gpointer           client_data);

static void session_die (GnomeClient        *client,
                         gpointer            client_data);

gboolean fortified_is_locked (void);

static FirewallStatus firewall_state_prelock;

/* [ stop_firewall ]
 * Flushes, zeroes and sets all policies to accept
 */
void
stop_firewall (void)
{
	gint retval;
	gchar *arg[3] = {"fortified.sh", "stop", NULL};
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

	if (retval == 0) {
		if (!CONSOLE)
			status_set_state (STATUS_STOPPED);
	} else {
		retval = WEXITSTATUS (retval);
	
		if (CONSOLE)
			show_error (_("Failed to stop the firewall"));
		else
			error_dialog (_("Failed to stop the firewall"),
			              _("Failed to stop the firewall"),
				      _("There was an undetermined error when trying to stop the firewall."),
				      Fortified.window);
	}
	
	g_free (output);
}

/* [ start_firewall ]
 * Executes the firewall script
 */
void
start_firewall (void)
{
	gint retval;
	gchar *arg[3] = {"fortified.sh", "start", NULL};
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

	if (retval == 0) {
		if (!CONSOLE)
			status_set_state (STATUS_RUNNING);
	} else {
		gchar *message;
		retval = WEXITSTATUS (retval);

		if (retval == RETURN_EXT_FAILED) {
			message = g_strdup_printf (_(
				"The device %s is not ready."), 
				preferences_get_string (PREFS_FW_EXT_IF));
		} else if (retval == RETURN_INT_FAILED) {
			message = g_strdup_printf (_(
				"The device %s is not ready."), 
				preferences_get_string (PREFS_FW_INT_IF));
		} else if (retval == RETURN_NO_IPTABLES) {
			message = g_strdup (_("Your kernel does not support iptables."));
		} else {
			message = g_strdup (_("An unknown error occurred."));
		}

		message = g_strconcat (message, "\n\n", _(
			"Please check your network device settings and make sure your\n"
			"Internet connection is active."), NULL);
		
		if (CONSOLE) {
			message = g_strconcat (_("Failed to start the firewall\n"),
			                       message, NULL);
			show_error (message);
		} else {
			error_dialog (_("Failed to start the firewall"),
			              _("Failed to start the firewall"),
				      message,
				      Fortified.window);
			status_set_state (STATUS_STOPPED);
		}

		g_free (message);
	}

	g_free (output);
}

void
restart_firewall_if_active (void)
{
	if (status_get_state () == STATUS_RUNNING ||
	    status_get_state () == STATUS_HIT)
			start_firewall ();
}

/* [ lock_firewall ]
 * Flushes and sets all policies to deny
 */
void
lock_firewall (void)
{
	gint retval;
	gchar *arg[3] = {"fortified.sh", "lock", NULL};
	gchar *output;
	GError *error = NULL;

	firewall_state_prelock = status_get_state ();

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

	if (retval == 0) {
		if (!CONSOLE)
			status_set_state (STATUS_LOCKED);
	} else {
		retval = WEXITSTATUS (retval);
	
		if (CONSOLE)
			show_error (_("Failed to lock the firewall"));
		else {
			error_dialog (_("Failed to lock the firewall"),
			              _("Failed to lock the firewall"),
				      _("There was an undetermined error when trying to lock the firewall."),
				      Fortified.window);
		}
	}

	g_free (output);
}

/* [ unlock_firewall ]
 * Return the firewall to the state prior to locking
 */
void
unlock_firewall (void)
{
	if (firewall_state_prelock == STATUS_RUNNING ||
	    firewall_state_prelock == STATUS_HIT)
		start_firewall ();
	else
		stop_firewall ();
}

/* [ exit_fortified ]
 * Quit firestater
 */
void
exit_fortified (void)
{
	gtk_main_quit ();
}

/* [ save_session ]
 * Saves the current session for later revival
 */
static gint
save_session (GnomeClient       *client,
              gint               phase,
              GnomeSaveStyle     ave_style,
              gint               is_shutdown,
              GnomeInteractStyle interact_style,
              gint               is_fast,
              gpointer           client_data)
{
	gchar **argv = g_new0 (gchar*, 4);
	guint argc = 1;

	argv[0] = client_data;
	gnome_client_set_clone_command (client, argc, argv);
	gnome_client_set_restart_command (client, argc, argv);

	return TRUE;
}

/* [ session_die ]
 * Gracefully end the session
 */
static void
session_die (GnomeClient *client, gpointer client_data)
{
	exit_fortified ();
}

static const gchar *
get_lock_file_path (void)
{
	static gchar *path = NULL;

	if (path == NULL) {
		DIR *d;

		if ((d = opendir ("/var/lock/subsys")) != NULL) {
			closedir (d);
			path = g_strdup ("/var/lock/subsys/fortified");
		} else if ((d = opendir ("/var/lock")) != NULL) {
			closedir (d);
			path = g_strdup ("/var/lock/fortified");
		} else {
			perror ("Not able to determine a lock file");
		}
	}

	return path;
}

gboolean
fortified_is_locked (void)
{
	return g_file_test (get_lock_file_path (), G_FILE_TEST_EXISTS);
}

static void
show_help (void)
{
	gchar *help = g_strconcat (
		_("Fortified"), " ", VERSION "\n\n",
		_(" -s, --start            Start the firewall\n"
		" -p, --stop             Stop the firewall\n"
		"     --lock             Lock the firewall, blocking all traffic\n"
		"     --generate-scripts Generate firewall scripts from current configuration\n"
		"     --start-hidden     Start Fortified with the GUI not visible\n"
		" -v, --version          Prints Fortified's version number\n"
		" -h, --help             You're looking at it\n"
	), NULL);

	fprintf (stderr, "%s", help);
	g_free (help);
}

static gboolean
is_root (void)
{
	if (getuid () != 0) {
		if (CONSOLE)
		 	show_error (_("Insufficient privileges"));
		else
			error_dialog (_("Insufficient privileges"),
			              _("Insufficient privileges"),
			              _("You must have root user privileges to use Fortified."),
			              Fortified.window);

		return FALSE;
	}

	return TRUE;
}

/* [ main ]
 * The main function, this is where it all begins and ends
 */
int
main (int argc, char* argv[])
{
	GnomeClient *client;
	gint i;
	gboolean must_run_wizard;
	gboolean show_gui = TRUE;

	/* Text domain and codeset */	
	bindtextdomain (GETTEXT_PACKAGE, GNOMELOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	/* Parse arguments */
	for (i = 0; i < argc; i++) {
		const char * arg = argv[i];

		if (!strcmp (arg, "-s") || !strcmp(arg, "--start")) {
			CONSOLE = TRUE;
			gnome_program_init ("fortified", VERSION, LIBGNOME_MODULE, 1, argv, NULL);
			if (is_root ())
				start_firewall ();
			return 0;
		} else if (!strcmp (arg, "-p") || !strcmp(arg, "--stop")) {
			CONSOLE = TRUE;
			gnome_program_init ("fortified", VERSION, LIBGNOME_MODULE, 1, argv, NULL);
			if (is_root ())
				stop_firewall ();
			return 0;
		} else if (!strcmp(arg, "--lock")) {
			CONSOLE = TRUE;
			gnome_program_init ("fortified", VERSION, LIBGNOME_MODULE, 1, argv, NULL);
			if (is_root ())
				lock_firewall ();
			return 0;
		} else if (!strcmp(arg, "--generate-scripts")) {
			CONSOLE = TRUE;
			gnome_program_init ("fortified", VERSION, LIBGNOME_MODULE, 1, argv, NULL);
			if (is_root ())
				scriptwriter_output_scripts ();
			return 0;
		} else if (!strcmp(arg, "--start-hidden")) {
			show_gui = FALSE;
		} else if (!strcmp (arg, "-v") || !strcmp(arg, "--version")) {
			printf ("Fortified %s\n", VERSION);
			return 0;
		} else if (!strcmp (arg, "-h") || !strcmp (arg, "--help") || !strcmp(arg, "-help")) {
			CONSOLE = TRUE;
			gnome_program_init ("fortified", VERSION, LIBGNOME_MODULE, 1, argv, NULL);
			show_help ();
			return 0;	
		}
	}

	gnome_program_init ("fortified", VERSION, LIBGNOMEUI_MODULE, argc, argv, NULL);

	/* Set up the session managment */
	client = gnome_master_client ();
	g_signal_connect (G_OBJECT (client), "save_yourself",
			  G_CALLBACK (save_session), argv[0]);
	g_signal_connect (G_OBJECT (client), "die",
			  G_CALLBACK (session_die), NULL);

	/* Check that the user is root */
	if (!is_root ())
		return 1;

	/* Check that a valid gconf schema is installed */
	preferences_check_schema();

	/* If we're starting Fortified for the first time or the script is missing, create modal wizard */
	must_run_wizard = (preferences_get_bool (PREFS_FIRST_RUN) || !script_exists ());

	/* Creating the GUI */
	gui_construct ();
	/* Attach a timeout that keeps the GUI fw status in sync with userland changes */
	status_sync_timeout (NULL); /* Do one immediate refresh */
	g_timeout_add (5000, status_sync_timeout, NULL);

	/* Initialize the system log file polling function */
	open_logfile ((gchar *)get_system_log_path ());

	if (preferences_get_bool (PREFS_FIRST_RUN))
		policyview_install_default_ruleset ();

	/* Run wizard, without the main gui visible */
	if (must_run_wizard)
		run_wizard ();
	else {
		/* Test that our scripts are up to date */
		if (!scriptwriter_versions_match ()) {
			printf (_("Updating firewall to new version...\n"));
			scriptwriter_output_scripts ();
			printf (_("Firewall update complete\n"));
		}
			
		if (preferences_get_bool (PREFS_START_ON_GUI))
			start_firewall ();

		gui_set_visibility (show_gui);
	}

	gtk_main ();

	return 0;
}
