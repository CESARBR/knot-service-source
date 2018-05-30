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

#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <ell/ell.h>

#include "hal/linux_log.h"

#include "dbus.h"
#include "device.h"
#include "proxy.h"

/* Low level proxy: nrfd, lora, ... */
struct service_proxy {
	char *name;
	char *path;
	char *interface;
	unsigned int watch_id;
	struct l_dbus_client *client;
	struct l_hashmap *ellproxy_list;
	proxy_ready_func_t ready_cb;
	void *user_data;
};

struct foreach {
	proxy_foreach_func_t func;
	void *user_data;
};

static struct service_proxy *proxy;

static void proxy_free(struct service_proxy *proxy)
{
	l_hashmap_destroy(proxy->ellproxy_list, NULL);
	l_free(proxy->name);
	l_free(proxy->path);
	l_free(proxy->interface);
	l_free(proxy);
}

static void foreach_device(const void *key, void *value, void *user_data)
{
	struct foreach *foreach = user_data;
	struct knot_device *device;
	const char *id;

	if (!l_dbus_proxy_get_property(value, "Id", "s", &id))
		return;

	device = device_get(id);
	if (!device)
		return;

	foreach->func(device, foreach->user_data);
}

static void service_appeared(struct l_dbus *dbus, void *user_data)
{
	struct service_proxy *proxy = user_data;
	hal_log_info("Service appeared: %s", proxy->name);
	proxy->ellproxy_list = l_hashmap_string_new();
}

static void service_disappeared(struct l_dbus *dbus, void *user_data)
{
	struct service_proxy *proxy = user_data;
	hal_log_info("Service disappeared: %s", proxy->name);

	/* FIXME: Investigate if proxy should be released */
	l_hashmap_destroy(proxy->ellproxy_list, NULL);
	proxy->ellproxy_list = NULL;
}

static void added(struct l_dbus_proxy *ellproxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(ellproxy);
	const char *path = l_dbus_proxy_get_path(ellproxy);
	struct service_proxy *proxy = user_data;
	struct knot_device *device;
	const char *id;
	const char *name;
	bool paired = false;

	if (strcmp(interface, proxy->interface) != 0)
		return;

	if (!l_dbus_proxy_get_property(ellproxy, "Id", "s", &id))
		return;

	if (!l_dbus_proxy_get_property(ellproxy, "Paired", "b", &paired))
		return;

	if (!l_dbus_proxy_get_property(ellproxy, "Name", "s", &name))
		return;

	device = device_get(id);
	if (!device) {
		/* Ownership belongs to device.c */
		device = device_create(id, name, paired, false);
		if (!device) {
			hal_log_error("Can't create device: %s", id);
			return;
		}
	}

	hal_log_info("Id: %s proxy added: %s %s",
			     id, path, interface);
	l_hashmap_insert(proxy->ellproxy_list, id, ellproxy);
}

static void removed(struct l_dbus_proxy *ellproxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(ellproxy);
	const char *path = l_dbus_proxy_get_path(ellproxy);
	const char *id;
	struct service_proxy *proxy = user_data;

	if (strcmp(interface, proxy->interface) != 0)
		return;

	/* Debug purpose only */
	hal_log_info("proxy removed: %s %s", path, interface);
	if (!l_dbus_proxy_get_property(ellproxy, "Id", "s", &id))
		return;

	l_hashmap_remove(proxy->ellproxy_list, id);
	device_destroy(id);
}

static void property_changed(struct l_dbus_proxy *ellproxy,
			     const char *propname, struct l_dbus_message *msg,
			     void *user_data)
{
	struct service_proxy *proxy = user_data;
	const char *path = l_dbus_proxy_get_path(ellproxy);
	const char *interface = l_dbus_proxy_get_interface(ellproxy);
	struct knot_device *device;
	const char *name;
	const char *id;
	bool bvalue;

	if (strcmp(proxy->interface, interface) != 0)
		return;

	if (!l_dbus_proxy_get_property(ellproxy, "Id", "s", &id))
		return;

	device = device_get(id);
	if (!device)
		return;

	if (strcmp("Name", propname) == 0) {
		if (l_dbus_message_get_arguments(msg, "s", &name))
			device_set_name(device, name);

	} else if (strcmp("Paired", propname) == 0) {
		if (l_dbus_message_get_arguments(msg, "b", &bvalue))
			device_set_paired(device, bvalue);
	} else if (strcmp("Connected", propname) == 0) {
		/* Ignoring for now ... It is being mapped to Online */
	} else {
		/* Ignore other properties */
		return;
	}

	hal_log_info("property changed: %s (%s %s)", propname, path, interface);
}

static struct service_proxy *watch_create(const char *service,
			const char *path, const char *interface)
{
	struct service_proxy *proxy;

	proxy = l_new(struct service_proxy, 1);
	proxy->name = l_strdup(service);
	proxy->path = l_strdup(path);
	proxy->interface = l_strdup(interface);
	proxy->ellproxy_list = NULL;
	proxy->watch_id = l_dbus_add_service_watch(dbus_get_bus(), service,
						   service_appeared,
						   service_disappeared,
						   proxy, NULL);

	proxy->client = l_dbus_client_new(dbus_get_bus(), service, "/");
	l_dbus_client_set_proxy_handlers(proxy->client, added,
					 removed, property_changed,
					 proxy, NULL);

	return proxy;
}

static void watch_remove(struct service_proxy *proxy)
{
	l_dbus_client_destroy(proxy->client);
	l_dbus_remove_watch(dbus_get_bus(), proxy->watch_id);

	proxy_free(proxy);
}

static void ready_callback(struct l_dbus_client *client, void *user_data)
{
	struct service_proxy *proxy = user_data;

	if (proxy->ready_cb)
		proxy->ready_cb(proxy->name, proxy->user_data);
}

int proxy_start(const char *service, const char *path, const char *interface,
		proxy_ready_func_t ready_cb, void *user_data)
{

	hal_log_info("D-Bus Proxy");

	/*
	 * TODO: Add API to allow registering proxies dynamically.
	 * nrfd, iwpand or any other radio should implement a well
	 * defined interface to report new devices found or created.
	 */
	proxy = watch_create(service, path, interface);
	proxy->ready_cb = ready_cb;
	proxy->user_data = user_data;

	/* Ready gets called after notifying all proxies */
	l_dbus_client_set_ready_handler(proxy->client,
					ready_callback,
					proxy, NULL);
	return 0;
}

void proxy_stop(void)
{
	watch_remove(proxy);
}

void proxy_foreach(const char *service,
		   proxy_foreach_func_t foreach_cb, void *user_data)
{
	struct foreach foreach = { .func = foreach_cb, .user_data = user_data };
	/* TODO: Create a list of service */

	l_hashmap_foreach(proxy->ellproxy_list, foreach_device, &foreach);
}

struct l_dbus_proxy *proxy_get(const char *id)
{
	return l_hashmap_lookup(proxy->ellproxy_list, id);
}
