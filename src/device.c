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
#include <knot_types.h>
#include <knot_protocol.h>

#include "dbus.h"
#include "settings.h"
#include "proto.h"
#include "device.h"
#include "proxy.h"

struct knot_device {
	int refs;
	char *id;
	char *name;			/* Friendly name */
	char *path;			/* D-Bus object path */
	char *uuid;			/* Device UUID from cloud */
	bool online;			/* Fog 'Online' property */
	bool paired;			/* Low level pairing state */
	bool registered;		/* Registered to cloud */
	struct l_dbus_message *msg;	/* Pending operation */
	uint32_t msg_id;		/* Pending method reply */
};

static struct l_hashmap *device_list;

static void device_free(struct knot_device *device)
{
	hal_log_info("device_free(%p)", device);
	if (unlikely(!device))
		return;

	if (device->msg)
		l_dbus_message_unref(device->msg);

	if (device->msg_id)
		l_dbus_cancel(dbus_get_bus(), device->msg_id);

	l_free(device->name);
	l_free(device->path);
	l_free(device->uuid);
	l_free(device->id);
	l_free(device);
}

static struct knot_device *device_ref(struct knot_device *device)
{
	if (unlikely(!device))
		return NULL;

	__sync_fetch_and_add(&device->refs, 1);

	hal_log_info("device_ref(%p): %d", device, device->refs);

	return device;
}

static void device_unref(struct knot_device *device)
{
	if (unlikely(!device))
		return;

	hal_log_info("device_unref(%p): %d", device, device->refs - 1);
	if (__sync_sub_and_fetch(&device->refs, 1))
		return;

	device_free(device);
}

static void unregister(void *user_data)
{
	struct knot_device *device = user_data;

	/* Automatically calls device_unref() */
	l_dbus_unregister_object(dbus_get_bus(), device->path);

	/* Release last reference */
	l_hashmap_remove(device_list, device->id);
	device_unref(device);
}

static void foreach_unregister_object(const void *key,
				      void *value, void *user_data)
{
	struct knot_device *device = value;


	/* Automatically calls device_unref() */
	l_dbus_unregister_object(dbus_get_bus(), device->path);
}

static void method_pair_reply(struct l_dbus_proxy *proxy,
		       struct l_dbus_message *result,
		       void *user_data)
{
	struct knot_device *device = user_data;
	struct l_dbus_message *reply;

	if (l_dbus_message_is_error(result)) {
		l_error("Failed to Pair() device %s" , device->id);
		return;
	}

	reply = l_dbus_message_new_method_return(device->msg);
	l_dbus_send(dbus_get_bus(), reply);
	l_dbus_message_unref(device->msg);
	device->msg = NULL;

	device->msg_id = 0;
}

static void method_forget_reply(struct l_dbus_proxy *proxy,
		       struct l_dbus_message *result,
		       void *user_data)
{
	struct knot_device *device = user_data;
	struct l_dbus_message *reply;


	if (l_dbus_message_is_error(result)) {
		l_error("Failed to Forget() device %s" , device->id);
		return;
	}

	if (device->msg == NULL)
		return;

	reply = l_dbus_message_new_method_return(device->msg);
	l_dbus_send(dbus_get_bus(), reply);
	l_dbus_message_unref(device->msg);
	device->msg = NULL;

	device->msg_id = 0;
}

static struct l_dbus_message *method_pair(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct knot_device *device = user_data;
	struct l_dbus_proxy *ellproxy;

	if (device->paired)
		return dbus_error_already_exists(msg, "Already paired");

	if (device->msg)
		return dbus_error_busy(msg);

	ellproxy = proxy_get(device->id);
	if (!ellproxy)
		return dbus_error_not_available(msg);

	device->msg = l_dbus_message_ref(msg);
	device->msg_id = l_dbus_proxy_method_call(ellproxy, "Pair", NULL,
					  method_pair_reply, device, NULL);

	return NULL;
}

static struct l_dbus_message *method_forget(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct knot_device *device = user_data;
	struct l_dbus_proxy *ellproxy;


	if (!device->paired)
		return dbus_error_not_available(msg);

	if (device->msg)
		return dbus_error_busy(msg);

	ellproxy = proxy_get(device->id);
	if (!ellproxy)
		return dbus_error_not_available(msg);

	/* FIXME: potential race condition. Registration might be in progress */

	/* Registered to cloud ? */

	if (device->uuid) {
		/*
		 *  At msg.c@proxy_removed() will manage additional
		 *  KNoT operations sending unregister request if the
		 *  peer (thing) is connected.
		 */
		proto_rmnode_by_uuid(device->uuid);
		return l_dbus_message_new_method_return(msg);
	}

	/* Remove from lower layers only */
	device->msg = l_dbus_message_ref(msg);
	device->msg_id = l_dbus_proxy_method_call(ellproxy, "Forget",
						  NULL, method_forget_reply,
						  device, unregister);
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

	l_dbus_message_builder_append_basic(builder, 's', device->id);
	hal_log_info("%s GetProperty(Id = %s)",
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
	l_dbus_interface_method(interface, "Pair", 0,
				method_pair, "", "", "");
	l_dbus_interface_method(interface, "Forget", 0,
				method_forget, "", "", "");

	if (!l_dbus_interface_property(interface, "Name", 0, "s",
				       property_get_name,
				       NULL))
		hal_log_error("Can't add 'Name' property");

	if (!l_dbus_interface_property(interface, "Uuid", 0, "s",
				       property_get_uuid,
				       NULL))
		hal_log_error("Can't add 'Uuid' property");

	if (!l_dbus_interface_property(interface, "Id", 0, "s",
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
	device_list = l_hashmap_string_new();
	return 0;
}

void device_stop(void)
{
	l_hashmap_foreach(device_list, foreach_unregister_object, NULL);
	l_hashmap_destroy(device_list, (l_hashmap_destroy_func_t) device_unref);
	l_dbus_unregister_interface(dbus_get_bus(), DEVICE_INTERFACE);
}

struct knot_device *device_create(const char *id, const char *name,
				  bool paired, bool registered)
{
	struct knot_device *device;

	device = l_new(struct knot_device, 1);
	device->refs = 0;
	device->id = l_strdup(id);
	device->name = l_strdup(name);
	device->uuid = NULL; /* FIXME */
	device->paired = paired;
	device->online = false;
	device->registered = registered;
	device->msg = NULL;
	device->msg_id = 0;

	device->path = l_strdup_printf("/dev_%s", id);

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
	l_hashmap_insert(device_list, id, device);

	return device;
}

void device_destroy(const char *id)
{
	struct knot_device *device;


	device = l_hashmap_lookup(device_list, id);
	if (!device)
		return;

	unregister(device);
}

bool device_set_name(struct knot_device *device, const char *name)
{
	if (unlikely(!device))
		return false;

	if (!name)
		return false;

	l_free(device->name);
	device->name = l_strdup(name);

	l_dbus_property_changed(dbus_get_bus(), device->path,
				DEVICE_INTERFACE, "Name");

	return true;
}

bool device_set_uuid(struct knot_device *device, const char *uuid)
{
	if (unlikely(!device))
		return false;

	if (unlikely(!uuid))
		return false;

	l_free(device->uuid);
	device->uuid = l_strdup(uuid);

	l_dbus_property_changed(dbus_get_bus(), device->path,
				DEVICE_INTERFACE, "Uuid");

	return true;
}

bool device_set_registered(struct knot_device *device, bool registered)
{
	if (unlikely(!device))
		return false;

	if (device->registered == registered)
		return false;

	device->registered = registered;
	l_dbus_property_changed(dbus_get_bus(), device->path,
				DEVICE_INTERFACE, "Registered");

	return true;
}

bool device_set_paired(struct knot_device *device, bool paired)
{
	if (unlikely(!device))
		return false;

	if (device->paired == paired)
		return false;

	device->paired = paired;

	l_dbus_property_changed(dbus_get_bus(), device->path,
				DEVICE_INTERFACE, "Paired");

	return true;
}

bool device_set_online(struct knot_device *device, bool online)
{
	if (unlikely(!device))
		return false;

	/* Defines if cloud connection is estabished or not */
	if (device->online == online)
		return false;

	device->online = online;

	l_dbus_property_changed(dbus_get_bus(), device->path,
				DEVICE_INTERFACE, "Online");

	return true;
}

struct knot_device *device_get(const char *id)
{
	struct knot_device *device;

	device = l_hashmap_lookup(device_list, id);
	if (!device)
		return NULL;
	else
		return device;
}

const char *device_get_id(struct knot_device *device)
{
	if (unlikely(!device))
		return 0;

	return device->id;
}

bool device_forget(struct knot_device *device)
{
	struct l_dbus_proxy *ellproxy;

	if (!device->paired)
		return false;

	if (device->msg) {
		hal_log_error("error: Pair/Forget in progress!");
		return false;
	}

	/* TODO: Fix potential race condition with D-Bus method call */

	ellproxy = proxy_get(device->id);
	if (!ellproxy)
		return false;

	device->msg_id = l_dbus_proxy_method_call(ellproxy, "Forget", NULL,
						  method_forget_reply,
						  device, unregister);

	return true;
}
