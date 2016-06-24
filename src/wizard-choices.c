/*---[ wizard-choices.c ]---------------------------------------------
 * Copyright (C) 2000-2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Functions dealing with saving/restoring the users wizard choices
 *--------------------------------------------------------------------*/

#include "wizard-choices.h"
#include "wizard.h"
#include "util.h"
#include "preferences.h"

void
load_choices (Wizard *data)
{
	/* External device */
	data->extdevice = preferences_get_string (PREFS_FW_EXT_IF);

	preferences_update_widget_from_conf (data->pppcheck, PREFS_START_ON_DIAL_OUT);
	preferences_update_widget_from_conf (data->dhcpcheck, PREFS_START_ON_DHCP);

	/* NAT */
	preferences_update_widget_from_conf (data->masq, PREFS_FW_NAT);
	data->intdevice = preferences_get_string (PREFS_FW_INT_IF);
	preferences_update_widget_from_conf (data->dhcp_server, PREFS_FW_DHCP_ENABLE);
	preferences_update_widget_from_conf (data->dhcp_lowest_ip, PREFS_FW_DHCP_LOWEST_IP);
	preferences_update_widget_from_conf (data->dhcp_highest_ip, PREFS_FW_DHCP_HIGHEST_IP);
	preferences_update_widget_from_conf (data->dhcp_nameserver, PREFS_FW_DHCP_NAMESERVER);
}

void
save_choices (Wizard *data)
{
	/* External device */
	preferences_set_string (PREFS_FW_EXT_IF, data->extdevice);

	preferences_update_conf_from_widget (data->pppcheck, PREFS_START_ON_DIAL_OUT);
	preferences_update_conf_from_widget (data->dhcpcheck, PREFS_START_ON_DHCP);

	/* NAT */
	preferences_update_conf_from_widget (data->masq, PREFS_FW_NAT);
	preferences_set_string (PREFS_FW_INT_IF, data->intdevice);
	preferences_update_conf_from_widget (data->dhcp_server, PREFS_FW_DHCP_ENABLE);
	preferences_update_conf_from_widget (data->dhcp_lowest_ip, PREFS_FW_DHCP_LOWEST_IP);
	preferences_update_conf_from_widget (data->dhcp_highest_ip, PREFS_FW_DHCP_HIGHEST_IP);
	preferences_update_conf_from_widget (data->dhcp_nameserver, PREFS_FW_DHCP_NAMESERVER);
}
