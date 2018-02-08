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

#include <glib.h>

#include <hal/linux_log.h>

#include "node.h"
#include "serial.h"

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
extern struct node_ops serial_ops;

static struct node_ops *node_ops[] = {
	&unix_ops,
	&tcp_ops,
	&tcp6_ops,
#if 0
	// Remove temporarly: causing excessive interruptions
	&serial_ops,
#endif
	NULL
};

static GSList *accept_channel_watch_list = NULL;

static bool is_serial(const struct node_ops *node_ops)
{
	return strcmp("Serial", node_ops->name) == 0;
}

static int start_node_server(const char *tty, const struct node_ops *node_ops)
{
	int err = -EIO;
	int server_socket;

	if (is_serial(node_ops)) {
		if (tty == NULL)
			/* Ignore Serial driver if port is not informed */
			return err;
		serial_load_config(tty);
	}

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

static void stop_node_server(const struct node_ops *node_ops)
{
	node_ops->remove();
}

static void stop_all_node_servers()
{
	int i;
	/* Remove only previously loaded modules */
	for (i = 0; node_ops[i]; i++)
		stop_node_server(node_ops[i]);
}

static GIOChannel *create_accept_channel(int server_socket)
{
	GIOChannel *channel;

	channel = g_io_channel_unix_new(server_socket);
	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_flags(channel, G_IO_FLAG_NONBLOCK, NULL);

	return channel;
}

static void try_accept(struct node_ops* node_ops, int server_socket,
	on_accepted on_accepted_cb)
{
	int client_socket;

	client_socket = node_ops->accept(server_socket);
	if (client_socket < 0) {
		hal_log_error("%p accept(): %s(%d)",
			node_ops, strerror(-client_socket), -client_socket);
		return;
	}

	on_accepted_cb(node_ops, client_socket);
}

static gboolean on_accept(GIOChannel *channel, GIOCondition condition,
	gpointer user_data)
{
	struct node_ops *node_ops;
	on_accepted on_accepted_cb;
	int server_socket;

	node_ops = ((struct on_accept_data *)user_data)->node_ops;
	on_accepted_cb = ((struct on_accept_data *)user_data)->on_accepted_cb;

	if (condition & (G_IO_NVAL | G_IO_HUP | G_IO_ERR))
		return FALSE;

	server_socket = g_io_channel_unix_get_fd(channel);

	try_accept(node_ops, server_socket, on_accepted_cb);

	return TRUE;
}

static void on_accept_channel_destroyed(gpointer user_data)
{
	g_free(user_data);
}

static void add_accept_channel_watch(GIOChannel *channel,
	struct node_ops *node_ops, on_accepted on_accepted_cb)
{
	guint watch_id;
	GIOCondition cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	struct on_accept_data *on_accept_data;

	on_accept_data = g_new0(struct on_accept_data, 1);
	on_accept_data->node_ops = node_ops;
	on_accept_data->on_accepted_cb = on_accepted_cb;

	watch_id = g_io_add_watch_full(channel, G_PRIORITY_DEFAULT, cond,
		on_accept, on_accept_data, on_accept_channel_destroyed);
	g_io_channel_unref(channel);

	accept_channel_watch_list = g_slist_prepend(accept_channel_watch_list,
		GUINT_TO_POINTER(watch_id));

	hal_log_info("node_ops(%p): (%s) watch: %d", node_ops,
					node_ops->name, watch_id);
}

static void remove_accept_channel_watch(guint watch_id)
{
	g_source_remove(watch_id);
}

static void remove_all_accept_channel_watches()
{
	GSList *list;
	guint watch_id;

	list = accept_channel_watch_list;
	while (list) {
		watch_id = GPOINTER_TO_UINT(list->data);
		remove_accept_channel_watch(watch_id);

		hal_log_info("Removed watch: %d", watch_id);

		list = g_slist_next(list);
	}

	g_slist_free(accept_channel_watch_list);
}

int node_start(const char *tty, on_accepted on_accepted_cb)
{
	int i;
	int server_socket;
	GIOChannel *accept_channel;

	/*
	 * Probing all access technologies: nRF24L01, BTLE, TCP, Unix
	 * sockets, Serial, etc. 'node_ops' drivers implements an
	 * abstraction similar to server sockets, it enables incoming
	 * connections and provides functions to receive and send data
	 * streams from/to KNOT nodes.
	 */
	for (i = 0; node_ops[i]; i++) {
		server_socket = start_node_server(tty, node_ops[i]);
		if (server_socket < 0)
			continue;

		accept_channel = create_accept_channel(server_socket);
		add_accept_channel_watch(accept_channel, node_ops[i], on_accepted_cb);
	}

	return 0;
}

void node_stop(void)
{
	stop_all_node_servers();
	remove_all_accept_channel_watches();
}
