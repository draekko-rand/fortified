/*---[ wizard-choices.h ]---------------------------------------------
 * Copyright (C) 2000-2002 Tomas Junnonen (majix@sci.fi)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Functions dealing with saving/restoring the users wizard choices
 *--------------------------------------------------------------------*/

#ifndef _FORTIFIED_WIZARD_CHOICES
#define _FORTIFIED_WIZARD_CHOICES

#include <config.h>
#include <gnome.h>
#include "wizard.h"

void load_choices (Wizard *data);
void save_choices (Wizard *data);

#endif
