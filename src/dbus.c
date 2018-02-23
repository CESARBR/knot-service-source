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

#include <ell/ell.h>

#include "hal/linux_log.h"

#include "dbus.h"

static struct l_dbus *g_dbus = NULL;

static void dbus_disconnect_callback(void *user_data)
{
	hal_log_info("D-Bus disconnected");
}

static void dbus_request_name_callback(struct l_dbus *dbus, bool success,
					bool queued, void *user_data)
{
	if (!success) {
		hal_log_error("Name request failed");
		return;
	}
}

static void dbus_ready_callback(void *user_data)
{
	l_dbus_name_acquire(g_dbus, KNOT_SERVICE, false, false, true,
			    dbus_request_name_callback, NULL);

	if (!l_dbus_object_manager_enable(g_dbus))
		hal_log_error("Unable to register the ObjectManager");

}

struct l_dbus *dbus_get_bus(void)
{
	return g_dbus;
}

int dbus_start(void)
{
	g_dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);

	l_dbus_set_ready_handler(g_dbus, dbus_ready_callback, g_dbus, NULL);

	l_dbus_set_disconnect_handler(g_dbus,
				      dbus_disconnect_callback,
				      NULL, NULL);

	return 0;
}


void dbus_stop(void)
{

}
