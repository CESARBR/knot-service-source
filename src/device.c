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
	int refs;
	uint64_t id;
	char *name;			/* Friendly name */
	char *path;			/* D-Bus object path */
	char *uuid;			/* Device UUID from cloud */
	bool connected;			/* Low level radio connection status */
	bool online;			/* Fog 'Online' property */
	bool paired;			/* Low level pairing state */
	bool registered;		/* Registered to cloud */
	struct l_dbus_message *msg;	/* Pending operation */
	struct l_dbus_proxy *proxy;
};

static struct l_hashmap *device_list;

static void device_free(struct knot_device *device)
{
	l_free(device->name);
	l_free(device->path);
	l_free(device->uuid);
	l_free(device);
}

static struct knot_device *device_ref(struct knot_device *device)
{
	if (unlikely(!device))
		return NULL;

	__sync_fetch_and_add(&device->refs, 1);

	return device;
}

static void device_unref(struct knot_device *device)
{
	if (unlikely(!device))
		return;

	if (!__sync_sub_and_fetch(&device->refs, 1))
		return;

	device_free(device);
}

static void method_reply(struct l_dbus_proxy *proxy,
		       struct l_dbus_message *result,
		       void *user_data)
{
	struct knot_device *device = user_data;
	struct l_dbus_message *reply;

	if (l_dbus_message_is_error(result)) {
		const char *name;

		l_dbus_message_get_error(result, &name, NULL);

		l_error("Failed to Pair device %s (%s)",
					l_dbus_proxy_get_path(device->proxy),
					name);
		return;
	}

	if (device->msg == NULL)
		return;

	reply = l_dbus_message_new_method_return(device->msg);
	l_dbus_send(dbus_get_bus(), reply);
	l_dbus_message_unref(device->msg);
	device->msg = NULL;
}

static struct l_dbus_message *method_pair(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct knot_device *device = user_data;

	if (device->paired)
		return dbus_error_already_exists(msg, "Already paired");

	if (device->msg)
		return dbus_error_busy(msg);

	device->msg = l_dbus_message_ref(msg);

	l_dbus_proxy_method_call(device->proxy, "Pair",
				 NULL, method_reply, device, NULL);

	return NULL;
}

static struct l_dbus_message *method_forget(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct knot_device *device = user_data;

	if (!device->paired)
		return dbus_error_not_available(msg);

	if (device->msg)
		return dbus_error_busy(msg);

	device->msg = l_dbus_message_ref(msg);

	l_dbus_proxy_method_call(device->proxy, "Forget",
				 NULL, method_reply, device, NULL);

	return NULL;
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

static bool property_get_uuid(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	struct knot_device *device = user_data;
	const char *uuid = (device->uuid ? : ""); /* FIXME */

	l_dbus_message_builder_append_basic(builder, 's', uuid);
	hal_log_info("%s GetProperty(UUID = %s)", device->path, uuid);

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
	bool online;

	/*
	 * Online behaviour
	 * Before registration: 'Online' refers to low level connection status.
	 * After registration: 'Online' means that the low level connection
	 * is established and there is an active connection between Fog & knotd.
	 */
	if (!device->registered)
		online = device->connected;
	else
		online = device->online;

	l_dbus_message_builder_append_basic(builder, 'b', &online);
	hal_log_info("%s GetProperty(Online = %d)",
		     device->path, online);

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
	l_dbus_interface_method(interface, "Pair", 0,
				method_pair, "", "", "");
	l_dbus_interface_method(interface, "Forget", 0,
				method_forget, "", "", "");

	if (!l_dbus_interface_property(interface, "Name", 0, "s",
				       property_get_name,
				       NULL))
		hal_log_error("Can't add 'Name' property");

	if (!l_dbus_interface_property(interface, "UUID", 0, "s",
				       property_get_uuid,
				       NULL))
		hal_log_error("Can't add 'UUID' property");

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
	device_list = l_hashmap_new();
	return 0;
}

void device_stop(void)
{
	l_dbus_unregister_interface(dbus_get_bus(),
				    DEVICE_INTERFACE);
	l_hashmap_destroy(device_list, (l_hashmap_destroy_func_t) device_destroy);
}

struct knot_device *device_create(struct l_dbus_proxy *proxy,
				  uint64_t id, const char *name, bool paired)
{
	struct knot_device *device;

	device = l_new(struct knot_device, 1);
	device->id = id;
	device->name = l_strdup(name);
	device->uuid = NULL; /* FIXME */
	device->paired = paired;
	device->online = false;
	device->registered = false;
	device->proxy = proxy;

	device->path = l_strdup_printf("/dev_%"PRIu64, id);

	if (!l_dbus_register_object(dbus_get_bus(),
			       device->path,
			       device_ref(device),
			       (l_dbus_destroy_func_t) device_unref,
			       DEVICE_INTERFACE, device,
			       L_DBUS_INTERFACE_PROPERTIES, device,
			       NULL)) {
		device_free(device);
		return NULL;
	}
	device = device_ref(device);
	l_hashmap_insert(device_list, L_INT_TO_PTR(id), device);

	hal_log_info("device_create(): %" PRIx64 " created", id);

	return device;
}

void device_destroy(struct knot_device *device)
{
	if(!l_hashmap_remove(device_list, L_INT_TO_PTR(device->id)))
		return;
	l_dbus_unregister_object(dbus_get_bus(), device->path);
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

bool device_set_uuid(struct knot_device *device, const char *uuid)
{
	struct l_dbus_message_builder *builder;
	struct l_dbus_message *signal;

	if (!uuid)
		return false;

	signal = l_dbus_message_new_signal(dbus_get_bus(),
					   device->path,
					   DEVICE_INTERFACE,
					   "Uuid");
	builder = l_dbus_message_builder_new(signal);
	l_dbus_message_builder_append_basic(builder, 's', uuid);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	if (l_dbus_send(dbus_get_bus(), signal) == 0)
		return false;

	l_free(device->uuid);
	device->uuid = l_strdup(uuid);

	return true;
}

bool device_set_registered(struct knot_device *device, bool registered)
{
	struct l_dbus_message_builder *builder;
	struct l_dbus_message *signal;

	if (device->registered == registered)
		return false;

	signal = l_dbus_message_new_signal(dbus_get_bus(),
					   device->path,
					   DEVICE_INTERFACE,
					   "Registered");
	builder = l_dbus_message_builder_new(signal);
	l_dbus_message_builder_append_basic(builder, 'b', &registered);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	if (l_dbus_send(dbus_get_bus(), signal) == 0)
		return false;

	device->registered = registered;

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

bool device_set_connected(struct knot_device *device, bool connected)
{
	struct l_dbus_message_builder *builder;
	struct l_dbus_message *signal;

	/* Defines if radio connection is estabished or not */

	if (device->connected == connected)
		return false;

	device->connected = connected;

	signal = l_dbus_message_new_signal(dbus_get_bus(),
					   device->path,
					   DEVICE_INTERFACE,
					   "Online");
	builder = l_dbus_message_builder_new(signal);
	l_dbus_message_builder_append_basic(builder, 'b', &connected);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	if (l_dbus_send(dbus_get_bus(), signal) == 0)
		return false;

	return true;
}

struct knot_device *device_get(uint64_t id)
{
	struct knot_device *device;

	device = l_hashmap_lookup(device_list, L_INT_TO_PTR(id));
	if (!device)
		return NULL;
	else
		return device;
}

uint64_t device_get_id(struct knot_device *device)
{
	if (unlikely(!device))
		return 0;

	return device->id;
}

bool device_forget(struct knot_device *device)
{
	if (!device->paired)
		return false;

	if (device->msg) {
		hal_log_error("error: Pair/Forget in progress!");
		return false;
	}

	/* TODO: Fix potential race condition with D-Bus method call */
	l_dbus_proxy_method_call(device->proxy, "Forget",
				 NULL, method_reply, device, NULL);

	return true;
}
