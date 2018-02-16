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
#include <stdbool.h>

#include <glib.h>

#include <hal/linux_log.h>

#include "session.h"

/*
 * Device session storing the connected
 * device context: 'drivers' and file descriptors
 */
struct session {
	struct node_ops *node_ops;
	struct proto_ops *proto_ops;

	unsigned int node_id;	/* Radio event source */
	unsigned int proto_id;	/* TCP/backend event source */
	GIOChannel *proto_io;	/* Protocol GIOChannel reference */

	on_data on_data;
};

static GSList *session_list = NULL;

static int connect_proto(struct session *session);
static void disconnect_proto(struct session *session);

static GIOChannel *create_proto_channel(int proto_socket)
{
  GIOChannel *channel;

  channel = g_io_channel_unix_new(proto_socket);

  return channel;
}

static void destroy_proto_channel(GIOChannel *channel)
{
  g_io_channel_shutdown(channel, FALSE, NULL);
  g_io_channel_unref(channel);
}

static gboolean on_proto_channel_disconnected(GIOChannel *channel,
  GIOCondition cond, gpointer user_data)
{
	struct session *session = user_data;

	/*
	 * Mark protocol watch as removed. Return FALSE to remove
	 * GIOChannel watch. This callback gets called when the
	 * REMOTE initiates a disconnection or if an error happens.
	 * In this case, radio (or Unix) transport should be left
	 * connected.
	 */
	session->proto_id = 0;

	if (session->proto_io) {
    destroy_proto_channel(session->proto_io);
		session->proto_io = NULL;
	}

	return FALSE;
}

static void on_proto_channel_destroyed(gpointer user_data)
{
	struct session *session = user_data;

	/*
	 * Considering that Radio (Unix) transport should stay
	 * connected for Cloud initiated disconnection, just
	 * 'reset' protocol references to signal that Cloud
	 * connection needs to be re-established on-demand.
	 */
	session->proto_io = NULL;
	session->proto_id = 0;
}

static guint add_proto_channel_watch(GIOChannel *channel,
  struct session *session)
{
  guint watch_id;
  GIOCondition watch_cond;

  /* Watch for TCP socket disconnection */
	watch_cond = G_IO_HUP | G_IO_NVAL | G_IO_ERR;
	watch_id = g_io_add_watch_full(
    channel,
		G_PRIORITY_DEFAULT,
    watch_cond,
		on_proto_channel_disconnected,
    session,
		on_proto_channel_destroyed);
  
  return watch_id;
}

static void remove_proto_channel_watch(guint watch_id)
{
  g_source_remove(watch_id);
}

static GIOChannel *create_node_channel(int node_socket)
{
  GIOChannel *channel;

  channel = g_io_channel_unix_new(node_socket);
	g_io_channel_set_close_on_unref(channel, TRUE);

  return channel;
}

static bool is_node_error_event(GIOCondition cond)
{
	return cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL);
}

static bool is_node_disconnected_event(GIOCondition cond)
{
	return cond & G_IO_HUP;
}

static gboolean on_node_channel_error_event(GIOChannel *channel,
	GIOCondition cond, gpointer user_data)
{
	struct session *session = user_data;

	/*
	 * Mark as removed. node_io has only one
	 * reference. Returning FALSE removes the
	 * last reference and the destroy callback
	 * is called.
	 */
	if (is_node_disconnected_event(cond))
		disconnect_proto(session);

	session->node_id = 0;

	return FALSE;
}

static gboolean on_node_channel_data_event(GIOChannel *channel,
	GIOCondition cond, gpointer user_data)
{
	int err;
	int node_socket, proto_socket;
	struct session *session = user_data;
	struct node_ops *node_ops = session->node_ops;
	uint8_t ipdu[512], opdu[512]; /* FIXME: */
	ssize_t recvbytes, sentbytes, olen;

	node_socket = g_io_channel_unix_get_fd(channel);

	recvbytes = node_ops->recv(node_socket, ipdu, sizeof(ipdu));
	if (recvbytes <= 0) {
		err = errno;
		hal_log_error("readv(): %s(%d)", strerror(err), err);
		return FALSE;
	}

	if (!session->proto_io) {
		err = connect_proto(session);
		if (err) {
			/* TODO:  missing reply an error */
			hal_log_error("Can't connect to cloud service!");
			session->node_id = 0;
			return FALSE;
		}

		hal_log_info("Reconnected to cloud service");
	}

	proto_socket = g_io_channel_unix_get_fd(session->proto_io);

	olen = session->on_data(node_socket, proto_socket,
		ipdu, recvbytes,
		opdu, sizeof(opdu));
	/* olen: output length or -errno */
	if (olen < 0) {
		/* Server didn't reply any error */
		hal_log_error("KNOT IoT proto error: %s(%zd)",
						strerror(-olen), -olen);
		return FALSE;
	}

	/* If there are no octets to be sent */
	if (!olen)
		return TRUE;

	/* Response from the gateway: error or response for the given command */
	sentbytes = node_ops->send(node_socket, opdu, olen);
	if (sentbytes < 0)
		hal_log_error("node_ops: %s(%zd)",
					strerror(-sentbytes), -sentbytes);

	return TRUE;
}

static gboolean on_node_channel_event(GIOChannel *channel,
	GIOCondition cond, gpointer user_data)
{
	if (is_node_error_event(cond)) {
		return on_node_channel_error_event(channel, cond, user_data);
	}

	return on_node_channel_data_event(channel, cond, user_data);
}

static void on_node_channel_destroyed(gpointer user_data)
{
	struct session *session = user_data;
	GIOChannel *proto_channel;

	proto_channel = session->proto_io;

	/*
	 * Destroy callback may be called after a remote (Radio or Unix peer)
	 * initiated disconnection. If Cloud is still connected: disconnect
	 * release allocated resources.
	 */

	if (session->proto_id) {
    remove_proto_channel_watch(session->proto_id);
		destroy_proto_channel(proto_channel);
	}

	session_list = g_slist_remove(session_list, session);
	g_free(session);
}

static guint add_node_channel_watch(GIOChannel *channel,
  struct session *session)
{
  guint watch_id;
  GIOCondition watch_cond;

  /* Watch for unix socket disconnection */
	watch_cond = G_IO_HUP | G_IO_NVAL | G_IO_ERR | G_IO_IN;
	watch_id = g_io_add_watch_full(
    channel,
    G_PRIORITY_DEFAULT,
    watch_cond,
    on_node_channel_event,
    session,
    on_node_channel_destroyed);
	g_io_channel_unref(channel);

  return watch_id;
}

static void remove_node_channel_watch(guint watch_id)
{
	g_source_remove(watch_id);
}

static int connect_proto(struct session *session)
{
	int proto_socket;

	proto_socket = session->proto_ops->connect();
	if (proto_socket < 0) {
		hal_log_info("Cloud connect(): %s(%d)",
			     strerror(-proto_socket), -proto_socket);
		return proto_socket;
	}

	/* Keep one reference to call sign-off */
	session->proto_io = create_proto_channel(proto_socket);
	session->proto_id = add_proto_channel_watch(session->proto_io, session);

	return 0;
}

static void disconnect_proto(struct session *session)
{
	int proto_socket;

	if (!session->proto_io)
		return;

	proto_socket = g_io_channel_unix_get_fd(session->proto_io);
	session->proto_ops->close(proto_socket);

	/* Channel and watch cleanup will be held at disconnect callback */
}

int session_create(struct node_ops *node_ops, struct proto_ops *proto_ops,
	int client_socket, on_data on_data)
{
  GIOChannel *node_channel;
	struct session *session;
	int err;

	session = g_new0(struct session, 1);

	/* TODO: Create refcount */
	session->node_ops = node_ops;
	session->proto_ops = proto_ops;
	session->on_data = on_data;

	err = connect_proto(session);
	if (err < 0) {
		g_free(session);
		return err;
	}

  node_channel = create_node_channel(client_socket);
	session->node_id = add_node_channel_watch(node_channel, session);

	hal_log_info("node:%p proto:%p", node_channel, session->proto_io);

	session_list = g_slist_prepend(session_list, session);

	return 0;
}

static void session_destroy(struct session *session)
{
	/* 
	 * Sessions are destroyed and removed from list when the node
	 * channel is destroyed.
	 */
	remove_node_channel_watch(session->node_id);
}

void session_destroy_all(void)
{
	GSList *list;
	struct session *session;

	for (list = session_list; list; list = g_slist_next(list)) {
		session = list->data;

		session_destroy(session);
	}

	g_slist_free(session_list);
}
