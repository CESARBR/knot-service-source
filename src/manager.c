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
#include "storage.h"
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

static void emit_signal_string(const char *path,
			       const char *prop, const char *newval)
{
	struct l_dbus_message *signal;
	struct l_dbus_message_builder *builder;

	signal = l_dbus_message_new_signal(dbus_get_bus(),
					   path,
					   SETTINGS_INTERFACE,
					   prop);
	builder = l_dbus_message_builder_new(signal);
	l_dbus_message_builder_append_basic(builder, 's', newval);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	l_dbus_send(dbus_get_bus(), signal);
}

static void emit_signal_uint16(const char *path,
			       const char *prop, uint16_t newval)
{
	struct l_dbus_message *signal;
	struct l_dbus_message_builder *builder;

	signal = l_dbus_message_new_signal(dbus_get_bus(),
					   path,
					   SETTINGS_INTERFACE,
					   prop);
	builder = l_dbus_message_builder_new(signal);
	l_dbus_message_builder_append_basic(builder, 'q', &newval);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	l_dbus_send(dbus_get_bus(), signal);
}

static bool property_get_port(struct l_dbus *dbus,
				     struct l_dbus_message *msg,
				     struct l_dbus_message_builder *builder,
				     void *user_data)
{
	const struct settings *settings = user_data;

	l_dbus_message_builder_append_basic(builder, 'q', &settings->port);
	hal_log_info("Get('Port' = %"PRIu16")", settings->port);

	return true;
}

static struct l_dbus_message *property_set_port(struct l_dbus *dbus,
					struct l_dbus_message *msg,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct settings *settings = user_data;
	uint16_t port;

	if (!l_dbus_message_iter_get_variant(new_value, "q", &port))
		return dbus_error_invalid_args(msg);

	settings->port = port;
	hal_log_info("Set('Port' = %" PRIu16")", port);

	storage_write_key_int(settings->config_path, "Cloud", "Port", port);
	emit_signal_uint16(l_dbus_message_get_path(msg), "Port", port);

	return l_dbus_message_new_method_return(msg);
}

static bool property_get_host(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	const struct settings *settings = user_data;

	l_dbus_message_builder_append_basic(builder, 's', settings->host);
	hal_log_info("Get('Host' = %s)", settings->host);

	return true;
}

static struct l_dbus_message *property_set_host(struct l_dbus *dbus,
					struct l_dbus_message *msg,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct settings *settings = user_data;
	const char *host;

	if (!l_dbus_message_iter_get_variant(new_value, "s", &host))
		return dbus_error_invalid_args(msg);

	l_free(settings->host);
	settings->host = l_strdup(host);
	hal_log_info("Set('Host' = %s)", settings->host);

	storage_write_key_string(settings->config_path, "Cloud", "Host", host);
	emit_signal_string(l_dbus_message_get_path(msg), "Host", host);

	return l_dbus_message_new_method_return(msg);
}

static bool property_get_uuid(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	const struct settings *settings = user_data;

	l_dbus_message_builder_append_basic(builder, 's', settings->uuid);
	hal_log_info("Get('Uuid' = %s)", settings->uuid);

	return true;
}

static struct l_dbus_message *property_set_uuid(struct l_dbus *dbus,
					struct l_dbus_message *msg,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct settings *settings = user_data;
	const char *uuid;

	if (!l_dbus_message_iter_get_variant(new_value, "s", &uuid))
		return dbus_error_invalid_args(msg);

	l_free(settings->uuid);
	settings->uuid = l_strdup(uuid);
	hal_log_info("Set('Uuid' = %s)", settings->uuid);

	storage_write_key_string(settings->config_path, "Cloud", "Uuid", uuid);
	emit_signal_string(l_dbus_message_get_path(msg), "Uuid", uuid);

	return l_dbus_message_new_method_return(msg);
}

static bool property_get_token(struct l_dbus *dbus,
				  struct l_dbus_message *msg,
				  struct l_dbus_message_builder *builder,
				  void *user_data)
{
	const struct settings *settings = user_data;

	l_dbus_message_builder_append_basic(builder, 's', settings->token);
	hal_log_info("Get('Token' = %s)", settings->token);

	return true;
}

static struct l_dbus_message *property_set_token(struct l_dbus *dbus,
					struct l_dbus_message *msg,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct settings *settings = user_data;
	const char *token;

	if (!l_dbus_message_iter_get_variant(new_value, "s", &token))
		return dbus_error_invalid_args(msg);

	l_free(settings->token);
	settings->token = l_strdup(token);
	hal_log_info("Set('Token' = %s)", settings->token);

	storage_write_key_string(settings->config_path,
				 "Cloud", "Token", token);
	emit_signal_string(l_dbus_message_get_path(msg), "Token", token);

	return l_dbus_message_new_method_return(msg);
}

static void setup_interface(struct l_dbus_interface *interface)
{
	if (!l_dbus_interface_property(interface, "Port", 0, "q",
				       property_get_port,
				       property_set_port))
		hal_log_error("Can't add 'Port' property");

	if (!l_dbus_interface_property(interface, "Host", 0, "s",
				       property_get_host,
				       property_set_host))
		hal_log_error("Can't add 'Host' property");

	if (!l_dbus_interface_property(interface, "Uuid", 0, "s",
				       property_get_uuid,
				       property_set_uuid))
		hal_log_error("Can't add 'Uuid' property");

	if (!l_dbus_interface_property(interface, "Token", 0, "s",
				       property_get_token,
				       property_set_token))
		hal_log_error("Can't add 'Token' property");
}

int manager_start(struct settings *settings)
{
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

	if (!l_dbus_register_object(dbus_get_bus(),
				    "/",
				    settings, NULL,
				    SETTINGS_INTERFACE, settings,
				    L_DBUS_INTERFACE_PROPERTIES, settings,
				    NULL))

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
