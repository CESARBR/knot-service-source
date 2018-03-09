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

#define KNOT_SERVICE			"br.org.cesar.knot"
#define SETTINGS_INTERFACE		"br.org.cesar.knot.Settings1"
#define DEVICE_INTERFACE		"br.org.cesar.knot.Device1"

int dbus_start(void);
void dbus_stop(void);

struct l_dbus *dbus_get_bus(void);

struct l_dbus_message *dbus_error_already_exists(struct l_dbus_message *msg,
						 const char *emsg);
struct l_dbus_message *dbus_error_busy(struct l_dbus_message *msg);
