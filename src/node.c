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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <ell/ell.h>

#include <hal/linux_log.h>

#include "node.h"

struct on_accept_data {
	struct node_ops *node_ops;
	on_accepted on_accepted_cb;
};

/* TODO: After adding buildroot, investigate if it is possible
 * to add macros for conditional builds, or a dynamic builtin
 * plugin mechanism.
 */
extern struct node_ops unix_ops;
extern struct node_ops tcp_ops;
extern struct node_ops tcp6_ops;

static struct node_ops *node_ops[] = {
	&unix_ops,
	&tcp_ops,
	&tcp6_ops,
	NULL
};

static struct l_queue *channel_list = NULL;

static int node_listen(const struct node_ops *node_ops)
{
	int server_socket;
	int err;

	err = node_ops->probe();
	if (err < 0)
		return err;

	server_socket = node_ops->listen();
	if (server_socket < 0) {
		hal_log_error("%p listen(): %s(%d)", node_ops,
			strerror(-server_socket), -server_socket);

		node_ops->remove();
	}

	return server_socket;
}

static bool try_accept(struct node_ops *node_ops,
		       int server_socket, on_accepted on_accepted_cb)
{
	int client_socket;

	client_socket = node_ops->accept(server_socket);
	if (client_socket < 0) {
		hal_log_error("%p accept(): %s(%d)",
			node_ops, strerror(-client_socket), -client_socket);
		return false;
	}

	if (on_accepted_cb(node_ops, client_socket) == false) {
		close(client_socket);
		return false;
	}

	return true;
}

static bool on_accept(struct l_io *channel, void *user_data)
{
	struct on_accept_data *on_accept_data = user_data;
	struct node_ops *node_ops = on_accept_data->node_ops;
	on_accepted on_accepted_cb = on_accept_data->on_accepted_cb;
	int server_socket;

	server_socket = l_io_get_fd(channel);

	return try_accept(node_ops, server_socket, on_accepted_cb);
}

/*
 * TODO: consider moving this to node-*.c
 */
static int set_nonblocking(int fd)
{
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
		return -errno;

	return 0;
}

static void create_channel(int server_socket,
			   struct node_ops *node_ops,
			   on_accepted on_accepted_cb)
{
	struct on_accept_data *on_accept_data;
	struct l_io *channel;
	int err;

	channel = l_io_new(server_socket);
	err = set_nonblocking(server_socket);
	if (err < 0)
		hal_log_error("Failed to change socket (%d) to non-blocking: %s(%d)",
			      server_socket, strerror(-err), -err);

	l_io_set_close_on_destroy(channel, true);

	on_accept_data = l_new(struct on_accept_data, 1);
	on_accept_data->node_ops = node_ops;
	on_accept_data->on_accepted_cb = on_accepted_cb;

	l_io_set_read_handler(channel, on_accept, on_accept_data, l_free);

	l_queue_push_tail(channel_list, channel);

	hal_log_info("node_ops(%p): (%s) created accept channel",
		     node_ops, node_ops->name);
}

int node_start(on_accepted on_accepted_cb)
{
	int server_socket;
	int i;

	channel_list = l_queue_new();

	/*
	 * Probing all access technologies: nRF24L01, BTLE, TCP, Unix
	 * sockets, Serial, etc. 'node_ops' drivers implements an
	 * abstraction similar to server sockets, it enables incoming
	 * connections and provides functions to receive and send data
	 * streams from/to KNOT nodes.
	 */
	for (i = 0; node_ops[i]; i++) {
		server_socket = node_listen(node_ops[i]);
		if (server_socket < 0)
			continue;

		create_channel(server_socket, node_ops[i], on_accepted_cb);
	}

	return 0;
}

void node_stop(void)
{
	int i;

	l_queue_destroy(channel_list,
			(l_queue_destroy_func_t) l_io_destroy);

	/* Remove only previously loaded modules */
	for (i = 0; node_ops[i]; i++)
		node_ops[i]->remove();
}
