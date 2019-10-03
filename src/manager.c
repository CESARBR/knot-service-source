/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2018, CESAR. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <hal/linux_log.h>
#include <ell/ell.h>

#include "settings.h"
#include "msg.h"
#include "dbus.h"
#include "manager.h"

static void setup_complete(void *user_data)
{
	struct settings *settings = user_data;
	int err;

	err = msg_start(settings);
	if (err < 0)
		hal_log_error("msg_start(): %s", strerror(-err));
}

int manager_start(struct settings *settings)
{
	int err;

	err = dbus_start(setup_complete, settings);
	if (err)
		hal_log_error("dbus_start(): %s", strerror(-err));

	return err;
}

void manager_stop(void)
{

	l_dbus_unregister_interface(dbus_get_bus(),
				    SETTINGS_INTERFACE);
	dbus_stop();
	msg_stop();
}
