/*---[ preferences.h ]------------------------------------------------
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

#ifndef _FORTIFIED_PREFERENCES
#define _FORTIFIED_PREFERENCES

#define PREFS_FIRST_RUN "/apps/fortified/client/first_run"
#define PREFS_SYSLOG_FILE "/apps/fortified/client/system_log"

#define PREFS_ENABLE_TRAY_ICON "/apps/fortified/client/enable_tray_icon"
#define PREFS_MINIMIZE_TO_TRAY "/apps/fortified/client/minimize_to_tray"

#define PREFS_SKIP_REDUNDANT "/apps/fortified/client/filter/redundant"
#define PREFS_SKIP_NOT_FOR_FIREWALL "/apps/fortified/client/filter/not_for_firewall"

#define PREFS_APPLY_POLICY_INSTANTLY "/apps/fortified/client/policy_auto_apply"

#define PREFS_START_ON_BOOT "/apps/fortified/client/start_firewall_on_boot"
#define PREFS_START_ON_GUI "/apps/fortified/client/start_firewall_on_gui"
#define PREFS_START_ON_DIAL_OUT "/apps/fortified/client/start_firewall_on_dial_out"
#define PREFS_START_ON_DHCP "/apps/fortified/client/start_firewall_on_dhcp"

#define PREFS_FW_EXT_IF "/apps/fortified/firewall/ext_if"
#define PREFS_FW_INT_IF "/apps/fortified/firewall/int_if"
#define PREFS_FW_NAT "/apps/fortified/firewall/nat"

#define PREFS_FW_DHCP_ENABLE "/apps/fortified/firewall/dhcp/enable_server"
#define PREFS_FW_DHCP_LOWEST_IP "/apps/fortified/firewall/dhcp/lowest_ip"
#define PREFS_FW_DHCP_HIGHEST_IP "/apps/fortified/firewall/dhcp/highest_ip"
#define PREFS_FW_DHCP_NAMESERVER "/apps/fortified/firewall/dhcp/nameserver"

#define PREFS_FW_FILTER_ICMP "/apps/fortified/firewall/icmp/enable"
#define PREFS_FW_ICMP_ECHO_REQUEST "/apps/fortified/firewall/icmp/echo_request"
#define PREFS_FW_ICMP_ECHO_REPLY "/apps/fortified/firewall/icmp/echo_reply"
#define PREFS_FW_ICMP_TRACEROUTE "/apps/fortified/firewall/icmp/traceroute"
#define PREFS_FW_ICMP_MSTRACEROUTE "/apps/fortified/firewall/icmp/mstraceroute"
#define PREFS_FW_ICMP_UNREACHABLE "/apps/fortified/firewall/icmp/unreachable"
#define PREFS_FW_ICMP_TIMESTAMPING "/apps/fortified/firewall/icmp/timestamping"
#define PREFS_FW_ICMP_MASKING "/apps/fortified/firewall/icmp/masking"
#define PREFS_FW_ICMP_REDIRECTION "/apps/fortified/firewall/icmp/redirection"
#define PREFS_FW_ICMP_SOURCE_QUENCHES "/apps/fortified/firewall/icmp/source_quenches"

#define PREFS_FW_FILTER_TOS "/apps/fortified/firewall/tos/enable"
#define PREFS_FW_TOS_CLIENT "/apps/fortified/firewall/tos/client"
#define PREFS_FW_TOS_SERVER "/apps/fortified/firewall/tos/server"
#define PREFS_FW_TOS_X "/apps/fortified/firewall/tos/x"
#define PREFS_FW_TOS_OPT_TROUGHPUT "/apps/fortified/firewall/tos/optimize_troughput"
#define PREFS_FW_TOS_OPT_RELIABILITY "/apps/fortified/firewall/tos/optimize_reliability"
#define PREFS_FW_TOS_OPT_DELAY "/apps/fortified/firewall/tos/optimize_delay"

#define PREFS_FW_DENY_PACKETS "/apps/fortified/firewall/deny_packets"
#define PREFS_FW_BLOCK_EXTERNAL_BROADCAST "/apps/fortified/firewall/block_external_broadcast"
#define PREFS_FW_BLOCK_INTERNAL_BROADCAST "/apps/fortified/firewall/block_internal_broadcast"
#define PREFS_FW_BLOCK_NON_ROUTABLES "/apps/fortified/firewall/block_non_routables"

#define PREFS_FW_RESTRICTIVE_OUTBOUND_MODE "/apps/fortified/firewall/restrictive_outbound"

#define PREFS_HITVIEW_TIME_COL "/apps/fortified/client/ui/hitview_time_col"
#define PREFS_HITVIEW_DIRECTION_COL "/apps/fortified/client/ui/hitview_direction_col"
#define PREFS_HITVIEW_IN_COL "/apps/fortified/client/ui/hitview_in_col"
#define PREFS_HITVIEW_OUT_COL "/apps/fortified/client/ui/hitview_out_col"
#define PREFS_HITVIEW_PORT_COL "/apps/fortified/client/ui/hitview_port_col"
#define PREFS_HITVIEW_SOURCE_COL "/apps/fortified/client/ui/hitview_source_col"
#define PREFS_HITVIEW_DESTINATION_COL "/apps/fortified/client/ui/hitview_destination_col"
#define PREFS_HITVIEW_LENGTH_COL "/apps/fortified/client/ui/hitview_length_col"
#define PREFS_HITVIEW_TOS_COL "/apps/fortified/client/ui/hitview_tos_col"
#define PREFS_HITVIEW_PROTOCOL_COL "/apps/fortified/client/ui/hitview_protocol_col"
#define PREFS_HITVIEW_SERVICE_COL "/apps/fortified/client/ui/hitview_service_col"

#include <config.h>
#include <gnome.h>

void preferences_check_schema (void);

gboolean preferences_get_bool   (const gchar *gconf_key);
void     preferences_set_bool   (const gchar *gconf_key, gboolean data);
gchar   *preferences_get_string (const gchar *gconf_key);
void     preferences_set_string (const gchar *gconf_key, const gchar *data);

void preferences_update_conf_from_widget (GtkWidget *widget, const gchar *gconf_key);
void preferences_update_widget_from_conf (GtkWidget *widget, const gchar *gconf_key);

void preferences_show (void);

#endif
