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

#include <hal/linux_log.h>

#include "proto.h"

extern struct proto_ops proto_http;
#ifdef HAVE_WEBSOCKETS
extern struct proto_ops proto_ws;
#endif

static struct proto_ops *proto_ops[] = {
	&proto_http,
#ifdef HAVE_WEBSOCKETS
	&proto_ws,
#endif
	NULL
};

static struct proto_ops *proto = NULL; /* Selected protocol */

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

int proto_start(const struct settings *settings, struct proto_ops **proto_ops)
{
	/*
	 * Selecting meshblu IoT protocols & services: HTTP/REST,
	 * Websockets, Socket IO, MQTT, COAP. 'proto_ops' drivers
	 * implements an abstraction similar to WEB client operations.
	 * TODO: later support dynamic protocol selection.
	 */

	proto = get_proto_ops(settings->proto);
	if (proto == NULL)
		return -EINVAL;

	if (proto->probe(settings->host, settings->port) < 0)
		return -EIO;

	hal_log_info("proto_ops: %s", proto->name);

	*proto_ops = proto;

	return 0;
}

void proto_stop()
{
	if (proto != NULL) {
		proto->remove();
		proto = NULL;
	}
}
