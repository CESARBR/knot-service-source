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

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <unistd.h>

#include <ell/ell.h>

#include <json-c/json.h>
#include <knot/knot_types.h>
#include <knot/knot_protocol.h>
#include <hal/linux_log.h>

#include "settings.h"
#include "parser.h"
#include "proto.h"

extern struct proto_ops proto_ws;
extern struct proto_ops proto_socketio;

static struct proto_ops *proto_ops[] = {
	&proto_ws,
	&proto_socketio,
	NULL
};

struct proto_proxy {
	int sock;			/* Cloud connection */
	proto_proxy_ready_func_t ready_cb; /* Call only once */
	bool ready_once;
	void *user_data;
	struct l_queue *device_list; /* mydevice */
};

static struct proto_ops *proto = NULL; /* Selected protocol */
static struct l_timeout *timeout;

static inline bool is_uuid_valid(const char *uuid)
{
	return strlen(uuid) == KNOT_PROTOCOL_UUID_LEN;
}

static inline bool is_token_valid(const char *token)
{
	return strlen(token) == KNOT_PROTOCOL_TOKEN_LEN;
}

static struct proto_ops *get_proto_ops(const char *protocol_name)
{
	int i;
	struct proto_ops *selected_protocol = NULL;

	for (i = 0; proto_ops[i]; i++) {
		if (strcmp(protocol_name, proto_ops[i]->name) != 0)
			continue;

		selected_protocol = proto_ops[i];
	}

	return selected_protocol;
}

int proto_start(const struct settings *settings)
{
	/*
	 * Selecting meshblu IoT protocols & services: Websockets or
	 * SocketIO 'proto_ops' drivers implements an abstraction
	 * similar to WEB client operations.
	 * TODO: later support dynamic protocol selection.
	 */

	proto = get_proto_ops(settings->proto);
	if (proto == NULL)
		return -EINVAL;

	hal_log_info("proto_ops: %s", proto->name);

	return proto->probe(settings->host, settings->port);
}

void proto_stop()
{
	if (proto != NULL) {
		proto->remove();
		proto = NULL;
	}

	l_timeout_remove(timeout);
}

int proto_connect(void)
{
	if (unlikely(!proto))
		return -EIO;

	return proto->connect();
}

void proto_close(int prot_sock)
{
	if (unlikely(!proto))
		return;

	proto->close(prot_sock);
}
