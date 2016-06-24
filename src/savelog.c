/*---[ savelog.c ]----------------------------------------------------
 * Copyright (C) 2000-2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Functions for saving the events list to a file
 *--------------------------------------------------------------------*/

#include "savelog.h"
#include "fortified.h"
#include "globals.h"
#include "hitview.h"
#include "util.h"

static void
write_event (gpointer data, gpointer user_data)
{
	Hit *h = (Hit *)data;
	GIOChannel *out = (GIOChannel *)user_data;

	if (h != NULL) {
		gchar *data;

		data = g_strdup_printf ("Time:%s Direction: %s In:%s Out:%s "
		                        "Port:%s Source:%s Destination:%s Length:%s "
					"TOS:%s Protocol:%s Service:%s\n",
		                        h->time,
		                        h->direction,
		                        h->in,
		                        h->out,
		                        h->port,
		                        h->source,
		                        h->destination,
		                        h->length,
		                        h->tos,
		                        h->protocol,
		                        h->service);

		
		g_io_channel_write_chars (out, data, -1, NULL, NULL);
		g_free (data);
	}

	free_hit (h);
}

static void
save_dialog_response_cb (GtkDialog *dialog,
                         gint response_id,
                         gpointer user_data)
{
	if (response_id == GTK_RESPONSE_ACCEPT) {
		gchar *filename;
		GIOChannel *out;
		GList *events;
		GError *error = NULL;

		filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
		out = g_io_channel_new_file (filename, "w", &error);

		if (out == NULL) {
			gchar *message;

			message = g_strdup_printf (_("Error writing to file %s\n\n%s"), filename, error->message);
			show_error (message);
			g_free (message);
			return;
		}

		events = hitview_get_all_hits ();
		g_list_foreach (events, write_event, out);

		g_io_channel_shutdown (out, TRUE, &error);
		g_free (filename);
		g_list_free (events);
	}

	gtk_widget_destroy (GTK_WIDGET (dialog));
}

/* [ create_savelog_filesel ]
 * Creates a file selection dialog, passed to savelog
 */
void
savelog_show_dialog (void)
{
	GtkWidget *dialog;

	dialog = gtk_file_chooser_dialog_new (_("Save Events To File"),
                                              GTK_WINDOW (Fortified.window),
                                              GTK_FILE_CHOOSER_ACTION_SAVE,
                                              GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
                                              GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT,
                                              NULL);

	gtk_file_chooser_set_current_name (GTK_FILE_CHOOSER (dialog), "fortified-events.txt");

	g_signal_connect (G_OBJECT (dialog), "response",
	                  G_CALLBACK (save_dialog_response_cb), NULL);

	gtk_widget_show (dialog);
}
