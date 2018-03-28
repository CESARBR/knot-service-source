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

#include <ell/ell.h>

#include <hal/linux_log.h>

#include "settings.h"
#include "node.h"
#include <knot_types.h>
#include <knot_protocol.h>
#include "proto.h"
#include "session.h"

/*
 * Device session storing the connected
 * device context: 'drivers' and file descriptors
 */
struct session {
	struct node_ops *node_ops;
	struct proto_ops *proto_ops;

	struct l_io *node_channel;	/* Radio event source */
	struct l_io *proto_channel;	/* Cloud event source */

	on_data on_data;

	int refs;
};

static struct l_queue *session_list = NULL;

static struct session *session_ref(struct session *session)
{
	if (unlikely(!session))
		return NULL;

	__sync_fetch_and_add(&session->refs, 1);

	return session;
}

static struct session *session_new(void)
{
	struct session *session;

	session = l_new(struct session, 1);
	session->refs = 0;

	return session_ref(session);
}

static void session_unref(struct session *session)
{
	if (unlikely(!session))
                return;

        if (__sync_sub_and_fetch(&session->refs, 1))
		return;

	l_io_destroy(session->node_channel);
	l_io_destroy(session->proto_channel);
	l_free(session);
}

static void disconnect_proto(struct session *session)
{
	struct l_io *channel;
	int proto_socket;

	if (!session->proto_channel)
		return;

	proto_socket = l_io_get_fd(session->proto_channel);
	session->proto_ops->close(proto_socket);

	channel = session->proto_channel;
	session->proto_channel = NULL;
	l_io_destroy(channel);

	/* Channel cleanup will be held at disconnect callback */
}

static void on_proto_channel_disconnected(struct l_io *channel,
					  void *user_data)
{
	struct session *session = user_data;

	/*
	 * This callback gets called when the REMOTE initiates a
	 * disconnection or if an error happens.
	 * In this case, radio transport should be left
	 * connected.
	 */
	if (session->proto_channel) {
		session->proto_channel = NULL;
		l_io_destroy(channel);
	}
}

static void on_proto_channel_destroyed(void *user_data)
{
	struct session *session = user_data;

	session_unref(session);
}

static struct l_io *create_proto_channel(int proto_socket,
					 struct session *session)
{
	struct l_io *channel;

	channel = l_io_new(proto_socket);
	if (channel == NULL) {
		hal_log_error("Can't create proto channel");
		return NULL;
	}

	l_io_set_disconnect_handler(channel,
				    on_proto_channel_disconnected,
				    session_ref(session),
				    on_proto_channel_destroyed);
	return channel;
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
	session->proto_channel = create_proto_channel(proto_socket, session);

	return 0;
}

static void on_node_channel_disconnected(struct l_io *channel, void *user_data)
{
	struct session *session = user_data;

	disconnect_proto(session);

	/*
	 * Remove initiated disconnection:
	 * Destroy ELL channel and remove tracked session
	 */
	if (session->node_channel) {
		session->node_channel = NULL;

		l_io_destroy(channel);
		l_queue_remove(session_list, session);
		session_unref(session);
	}
}

static void on_node_channel_destroyed(void *user_data)
{
	struct session *session = user_data;

	session_unref(session);
}

static void on_node_channel_destroy_timeout(struct l_timeout *timeout,
					    void *user_data)
{
	struct l_io *channel = user_data;

	l_io_destroy(channel);
}

static void on_node_channel_data_error(struct l_io *channel)
{
	static bool destroying = false;

	if (destroying)
		return;

	destroying = true;

	l_timeout_create(1,
			 on_node_channel_destroy_timeout,
			 channel,
			 NULL);
}

static bool on_node_channel_data(struct l_io *channel, void * user_data)
{
	struct session *session = user_data;
	struct node_ops *node_ops = session->node_ops;
	uint8_t ipdu[512], opdu[512]; /* FIXME: */
	ssize_t recvbytes, sentbytes, olen;
	int node_socket, proto_socket;
	int err;

	node_socket = l_io_get_fd(channel);

	recvbytes = node_ops->recv(node_socket, ipdu, sizeof(ipdu));
	if (recvbytes <= 0) {
		err = errno;
		hal_log_error("readv(): %s(%d)", strerror(err), err);
		on_node_channel_data_error(channel);
		return false;
	}

	if (!session->proto_channel) {
		err = connect_proto(session);
		if (err) {
			/* TODO:  missing reply an error */
			hal_log_error("Can't connect to cloud service!");
			on_node_channel_data_error(channel);
			return false;
		}

		hal_log_info("Reconnected to cloud service");
	}

	proto_socket = l_io_get_fd(session->proto_channel);

	olen = session->on_data(node_socket, proto_socket,
				ipdu, recvbytes,
				opdu, sizeof(opdu));
	/* olen: output length or -errno */
	if (olen < 0) {
		/* Server didn't reply any error */
		hal_log_error("KNOT IoT proto error: %s(%zd)",
			      strerror(-olen), -olen);
		on_node_channel_data_error(channel);
		return false;
	}

	/* If there are no octets to be sent */
	if (!olen)
		return true;

	/* Response from the gateway: error or response for the given command */
	sentbytes = node_ops->send(node_socket, opdu, olen);
	if (sentbytes < 0)
		hal_log_error("node_ops: %s(%zd)",
			      strerror(-sentbytes), -sentbytes);

	return true;
}

static struct l_io *create_node_channel(int node_socket,
					struct session *session)
{
	struct l_io *channel;

	channel = l_io_new(node_socket);
	if (channel == NULL) {
		hal_log_error("Can't create node channel");
		return NULL;
	}

	l_io_set_close_on_destroy(channel, true);

	l_io_set_read_handler(channel, on_node_channel_data,
			      session, NULL);
	l_io_set_disconnect_handler(channel,
				    on_node_channel_disconnected,
				    session_ref(session),
				    on_node_channel_destroyed);

	return channel;
}

int session_create(struct node_ops *node_ops, struct proto_ops *proto_ops,
		   int client_socket, on_data on_data)
{
	struct session *session;
	int err;

	session = session_new();
	session->node_ops = node_ops;
	session->proto_ops = proto_ops;
	session->on_data = on_data;

	err = connect_proto(session);
	if (err < 0) {
		session_unref(session);
		return err;
	}

	session->node_channel = create_node_channel(client_socket, session);

	hal_log_info("node:%p proto:%p",
		     session->node_channel, session->proto_channel);

	if (!session_list)
		session_list = l_queue_new();

	l_queue_push_tail(session_list, session);

	return 0;
}

static void session_destroy(struct session *session, void *user_data)
{
	struct l_io *channel;
	/*
	 * Sessions are destroyed and removed from list when the node
	 * channel is destroyed.
	 */
	if (session->proto_channel) {
		channel = session->proto_channel;
		session->proto_channel = NULL; /* Lock: destroying */

		/* Destroy calls disconnect & destroyed callbacks */
		l_io_destroy(channel);
	}

	if (session->node_channel) {
		channel = session->node_channel;
		session->node_channel = NULL; /* Lock: destroying */

		/* Destroy calls disconnect & destroyed callbacks */
		l_io_destroy(channel);
	}
}

void session_destroy_all(void)
{
	/*
	 * session_destroy() will remove the entries from session_list.
	 * Wait it clear the list beforing freeing it.
	 */
	l_queue_foreach(session_list,
			(l_queue_foreach_func_t) session_destroy,
			NULL);
	l_queue_destroy(session_list, (l_queue_destroy_func_t) session_unref);
	session_list = NULL;
}
