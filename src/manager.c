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

#include <knot_protocol.h>

#include <hal/linux_log.h>
#include <ell/ell.h>

#include "node.h"
#include "settings.h"
#include "proto.h"
#include "session.h"
#include "msg.h"
#include "dbus.h"
#include "proxy.h"
#include "manager.h"

static struct proto_ops *selected_protocol;

static bool on_accepted_cb(struct node_ops *node_ops, int client_socket)
{
	int err;

	err = session_create(node_ops, selected_protocol, client_socket, msg_process);
	if (err < 0) {
		/* FIXME: Stop knotd if cloud if not available */
		close(client_socket);
	}

	return true;
}

static bool property_get_port(struct l_dbus *dbus,
				     struct l_dbus_message *msg,
				     struct l_dbus_message_builder *builder,
				     void *user_data)
{
	uint16_t port = UINT16_MAX; /* FIXME */

	l_dbus_message_builder_append_basic(builder, 'q', &port);
	hal_log_info("GetProperty(Port = %"PRIu32")", port);

	return true;
}

static bool property_get_url(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	const char *url = "url-unknown";

	l_dbus_message_builder_append_basic(builder, 's', url);
	hal_log_info("GetProperty(URL = %s)", url);

	return true;
}

static bool property_get_uuid(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	const char *uuid = "uuid-unknown";

	l_dbus_message_builder_append_basic(builder, 's', uuid);
	hal_log_info("GetProperty(UUID = %s)", uuid);

	return true;
}

static struct l_dbus_message *property_set_uuid(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	const char *uuid;

	if (!l_dbus_message_iter_get_variant(new_value, "s", &uuid))
		return dbus_error_invalid_args(message);

	hal_log_info("SetProperty(UUID = %s)", uuid);

	return l_dbus_message_new_method_return(message);
}

static bool property_get_token(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	const char *token = "token-unknown";

	l_dbus_message_builder_append_basic(builder, 's', token);
	hal_log_info("GetProperty(Token = %s)", token);

	return true;
}

static void setup_interface(struct l_dbus_interface *interface)
{
	if (!l_dbus_interface_property(interface, "Port", 0, "q",
				       property_get_port,
				       NULL))
		hal_log_error("Can't add 'Port' property");

	if (!l_dbus_interface_property(interface, "URL", 0, "s",
				       property_get_url,
				       NULL))
		hal_log_error("Can't add 'URL' property");

	if (!l_dbus_interface_property(interface, "UUID", 0, "s",
				       property_get_uuid,
				       property_set_uuid))
		hal_log_error("Can't add 'URL' property");

	if (!l_dbus_interface_property(interface, "Token", 0, "s",
				       property_get_token,
				       NULL))
		hal_log_error("Can't add 'URL' property");
}


int manager_start(const struct settings *settings)
{
	const char *path = "/";
	int err;

	err = proto_start(settings, &selected_protocol);
	if (err < 0) {
		hal_log_error("proto_start(): %s", strerror(-err));
		return err;
	}

	err = node_start(on_accepted_cb);
	if (err < 0) {
		hal_log_error("node_start(): %s", strerror(-err));
		goto fail_node;
	}

	err = msg_start(settings->uuid, selected_protocol);
	if (err < 0) {
		hal_log_error("msg_start(): %s", strerror(-err));
		goto fail_msg;
	}

	err = dbus_start();
	if (err) {
		hal_log_error("dbus_start(): %s", strerror(-err));
		goto fail_dbus;
	}

	/* Manager object */
	if (!l_dbus_register_interface(dbus_get_bus(),
				       SETTINGS_INTERFACE,
				       setup_interface,
				       NULL, false))
		hal_log_error("dbus: unable to register %s",
			      SETTINGS_INTERFACE);

	if (!l_dbus_object_add_interface(dbus_get_bus(),
					 path,
					 SETTINGS_INTERFACE,
					 NULL))
	    hal_log_error("dbus: unable to add %s to %s",
					SETTINGS_INTERFACE, path);

	if (!l_dbus_object_add_interface(dbus_get_bus(),
					 path,
					 L_DBUS_INTERFACE_PROPERTIES,
					 NULL))
	    hal_log_error("dbus: unable to add %s to %s",
					L_DBUS_INTERFACE_PROPERTIES, path);

	return proxy_start();

fail_dbus:
	msg_stop();
fail_msg:
	node_stop();
fail_node:
	proto_stop();

	return err;
}

void manager_stop(void)
{
	proxy_stop();

	l_dbus_unregister_interface(dbus_get_bus(),
				    SETTINGS_INTERFACE);
	dbus_stop();
	session_destroy_all();
	msg_stop();
	node_stop();
	proto_stop();
}
