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
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <glib.h>

#include <knot_protocol.h>

#include <hal/linux_log.h>

#include "node.h"
#include "serial.h"
#include "proto.h"
#include "session.h"
#include "msg.h"
#include "settings.h"
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

int manager_start(const struct settings *settings)
{
	int err;

	err = proto_start(settings, &selected_protocol);
	if (err < 0)
		goto fail_proto;

	err = node_start(settings->tty, on_accepted_cb);
	if (err < 0)
		goto fail_node;

	err = msg_start(settings->uuid, selected_protocol);
	if (err < 0)
		goto fail_msg;

	err = 0;
	goto done;

fail_msg:
	node_stop();
fail_node:
	proto_stop();
fail_proto:
done:
	return err;
}

void manager_stop(void)
{
	session_destroy_all();
	msg_stop();
	node_stop();
	proto_stop();
}
