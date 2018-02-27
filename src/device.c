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

#include <errno.h>
#include <ell/ell.h>

#include "hal/linux_log.h"

#include "dbus.h"
#include "device.h"

struct knot_device {
	uint64_t id;
	char *name;
	char *path;
	bool online;
	bool paired;
	bool registered;
};

static void device_free(struct knot_device *device)
{
	l_free(device->name);
	l_free(device->path);
	l_free(device);
}

static bool property_get_name(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	struct knot_device *device = user_data;

	l_dbus_message_builder_append_basic(builder, 's', device->name);
	hal_log_info("%s GetProperty(Name = %s)", device->path, device->name);

	return true;
}

static bool property_get_id(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	struct knot_device *device = user_data;

	l_dbus_message_builder_append_basic(builder, 't', &device->id);
	hal_log_info("%s GetProperty(Id = %"PRIu64")",
		     device->path, device->id);

	return true;
}

static bool property_get_online(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	struct knot_device *device = user_data;

	l_dbus_message_builder_append_basic(builder, 'b', &device->online);
	hal_log_info("%s GetProperty(Online = %d)",
		     device->path, device->online);

	return true;
}

static bool property_get_registered(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	struct knot_device *device = user_data;

	l_dbus_message_builder_append_basic(builder, 'b', &device->registered);
	hal_log_info("%s GetProperty(Registered = %d)",
		     device->path, device->registered);

	return true;
}

static bool property_get_paired(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	struct knot_device *device = user_data;

	l_dbus_message_builder_append_basic(builder, 'b', &device->paired);
	hal_log_info("%s GetProperty(Paired = %d)",
		     device->path, device->paired);

	return true;
}

static void device_setup_interface(struct l_dbus_interface *interface)
{
	if (!l_dbus_interface_property(interface, "Name", 0, "s",
				       property_get_name,
				       NULL))
		hal_log_error("Can't add 'Name' property");

	if (!l_dbus_interface_property(interface, "Id", 0, "t",
				       property_get_id,
				       NULL))
		hal_log_error("Can't add 'Id' property");

	if (!l_dbus_interface_property(interface, "Online", 0, "b",
				       property_get_online,
				       NULL))
		hal_log_error("Can't add 'Online' property");

	if (!l_dbus_interface_property(interface, "Paired", 0, "b",
				       property_get_paired,
				       NULL))
		hal_log_error("Can't add 'Paired' property");

	if (!l_dbus_interface_property(interface, "Registered", 0, "b",
				       property_get_registered,
				       NULL))
		hal_log_error("Can't add 'Registered' property");
}

int device_start(void)
{
	/* nRF24 Device (device) object */
	if (!l_dbus_register_interface(dbus_get_bus(),
				       DEVICE_INTERFACE,
				       device_setup_interface,
				       NULL, false)) {
		hal_log_error("dbus: unable to register %s", DEVICE_INTERFACE);
		return -EINVAL;
	}

	return 0;
}

void device_stop(void)
{
	l_dbus_unregister_interface(dbus_get_bus(),
				    DEVICE_INTERFACE);
}

struct knot_device *device_create(uint64_t id, const char *name)
{
	struct knot_device *device;

	device = l_new(struct knot_device, 1);
	device->id = id;
	device->name = l_strdup(name);
	device->online = false;
	device->registered = false;

	device->path = l_strdup_printf("/dev_%"PRIu64, id);
	if (!l_dbus_object_add_interface(dbus_get_bus(),
					 device->path,
					 DEVICE_INTERFACE,
					 device)) {
		hal_log_error("dbus: unable to add %s to %s",
			      DEVICE_INTERFACE, device->path);

		device_free(device);
		return NULL;
	}

	if (!l_dbus_object_add_interface(dbus_get_bus(),
					 device->path,
					 L_DBUS_INTERFACE_PROPERTIES,
					 device)) {
		hal_log_error("dbus: unable to add %s to %s",
			      L_DBUS_INTERFACE_PROPERTIES, device->path);
		goto prop_reg_fail;
	}

	return device;

prop_reg_fail:

	l_dbus_object_remove_interface(dbus_get_bus(),
				       device->path,
				       DEVICE_INTERFACE);
	device_free(device);
	return NULL;
}

void device_destroy(struct knot_device *device)
{
	l_dbus_object_remove_interface(dbus_get_bus(),
				       device->path,
				       DEVICE_INTERFACE);
	l_dbus_object_remove_interface(dbus_get_bus(),
				       device->path,
				       L_DBUS_INTERFACE_PROPERTIES);

	device_free(device);
}

bool device_set_name(struct knot_device *device, const char *name)
{
	struct l_dbus_message_builder *builder;
	struct l_dbus_message *signal;

	if (!name)
		return false;

	signal = l_dbus_message_new_signal(dbus_get_bus(),
					   device->path,
					   DEVICE_INTERFACE,
					   "Name");
	builder = l_dbus_message_builder_new(signal);
	l_dbus_message_builder_append_basic(builder, 's', name);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	if (l_dbus_send(dbus_get_bus(), signal) == 0)
		return false;

	l_free(device->name);
	device->name = l_strdup(name);

	return true;
}

bool device_set_paired(struct knot_device *device, bool paired)
{
	struct l_dbus_message_builder *builder;
	struct l_dbus_message *signal;

	if (device->paired == paired)
		return false;

	signal = l_dbus_message_new_signal(dbus_get_bus(),
					   device->path,
					   DEVICE_INTERFACE,
					   "Paired");
	builder = l_dbus_message_builder_new(signal);
	l_dbus_message_builder_append_basic(builder, 'b', &paired);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	if (l_dbus_send(dbus_get_bus(), signal) == 0)
		return false;

	device->paired = paired;

	return true;
}
