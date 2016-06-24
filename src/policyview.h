/*---[ policyview.h ]-------------------------------------------------
 * Copyright (C) 2004 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * The traffic policy editor functions
 *--------------------------------------------------------------------*/

#ifndef _FORTIFIED_POLICYVIEW
#define _FORTIFIED_POLICYVIEW

#include "fortified.h"

#define POLICY_IN_DIR  FORTIFIED_RULES_DIR"/fortified/inbound"
#define POLICY_OUT_DIR FORTIFIED_RULES_DIR"/fortified/outbound"

#define POLICY_IN_ALLOW_FROM    POLICY_IN_DIR"/allow-from"
#define POLICY_IN_ALLOW_SERVICE POLICY_IN_DIR"/allow-service"
#define POLICY_IN_FORWARD       POLICY_IN_DIR"/forward"

#define POLICY_OUT_DENY_TO      POLICY_OUT_DIR"/deny-to"
#define POLICY_OUT_DENY_FROM    POLICY_OUT_DIR"/deny-from"
#define POLICY_OUT_DENY_SERVICE POLICY_OUT_DIR"/deny-service"

#define POLICY_OUT_ALLOW_TO           POLICY_OUT_DIR"/allow-to"
#define POLICY_OUT_ALLOW_FROM         POLICY_OUT_DIR"/allow-from"
#define POLICY_OUT_ALLOW_SERVICE      POLICY_OUT_DIR"/allow-service"

typedef enum
{
	RULETYPE_INBOUND_ALLOW_FROM,
	RULETYPE_INBOUND_ALLOW_SERVICE,
	RULETYPE_INBOUND_ALLOW_SERVICE_FROM,
	RULETYPE_OUTBOUND_ALLOW_TO,
	RULETYPE_OUTBOUND_ALLOW_SERVICE,
	RULETYPE_OUTBOUND_ALLOW_SERVICE_FROM,

} RuleType;

GtkWidget *create_policyview_page (void);

void policyview_edit_rule (void);
void policyview_add_rule (void);
void policyview_remove_rule (void);
void policyview_apply (void);
 
void policyview_reload_inbound_policy (void);
void policyview_reload_outbound_policy (void);

void policyview_create_rule (RuleType type, Hit *h);
void policyview_install_default_ruleset (void);

void poicyview_update_nat_widgets (void);

#endif
