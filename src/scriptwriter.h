/*---[ scriptwriter.h ]-----------------------------------------------
 * Copyright (C) 2000 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Functions to write firewall shell scripts
 *--------------------------------------------------------------------*/

#ifndef _FORTIFIED_SCRIPTWRITER
#define _FORTIFIED_SCRIPTWRITER

#include <config.h>
#include <gnome.h>
#include "wizard.h"
#include "policyview.h"

#define RETURN_EXT_FAILED 2
#define RETURN_INT_FAILED 3
#define RETURN_NO_IPTABLES 100

#define FORTIFIED_CONTROL_SCRIPT       FORTIFIED_RULES_DIR "/fortified/fortified.sh"
#define FORTIFIED_FIREWALL_SCRIPT      FORTIFIED_RULES_DIR "/fortified/firewall"
#define FORTIFIED_CONFIGURATION_SCRIPT FORTIFIED_RULES_DIR "/fortified/configuration"
#define FORTIFIED_SYSCTL_SCRIPT        FORTIFIED_RULES_DIR "/fortified/sysctl-tuning"
#define FORTIFIED_USER_PRE_SCRIPT      FORTIFIED_RULES_DIR "/fortified/user-pre"
#define FORTIFIED_USER_POST_SCRIPT     FORTIFIED_RULES_DIR "/fortified/user-post"
#define FORTIFIED_NON_ROUTABLES_SCRIPT FORTIFIED_RULES_DIR "/fortified/non-routables"
#define FORTIFIED_FILTER_HOSTS_SCRIPT  FORTIFIED_RULES_DIR "/fortified/events-filter-hosts"
#define FORTIFIED_FILTER_PORTS_SCRIPT  FORTIFIED_RULES_DIR "/fortified/events-filter-ports"
#define FORTIFIED_INBOUND_SETUP        POLICY_IN_DIR"/setup"
#define FORTIFIED_OUTBOUND_SETUP       POLICY_OUT_DIR"/setup"

gboolean script_exists (void);
void scriptwriter_output_scripts (void);

void scriptwriter_output_fortified_script (void);
void scriptwriter_output_configuration (void);

void scriptwriter_write_ppp_hook (void);
void scriptwriter_remove_ppp_hook (void);

void scriptwriter_write_dhcp_hook (void);
void scriptwriter_remove_dhcp_hook (void);

gboolean scriptwriter_versions_match (void);

#endif
