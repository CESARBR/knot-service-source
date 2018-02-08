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
#include "proto.h"
#include "serial.h"
#include "msg.h"
#include "settings.h"
#include "manager.h"

/*
 * Device session storing the connected
 * device context: 'drivers' and file descriptors
 */
struct session {
	unsigned int node_id;	/* Radio event source */
	unsigned int proto_id;	/* TCP/backend event source */
	GIOChannel *proto_io;	/* Protocol GIOChannel reference */
	struct node_ops *ops;
};

static GSList *session_list = NULL;

extern struct proto_ops proto_http;
#ifdef HAVE_WEBSOCKETS
extern struct proto_ops proto_ws;
#endif

static struct proto_ops *proto; /* Selected IoT protocol */
static struct proto_ops *proto_ops[] = {
	&proto_http,
#ifdef HAVE_WEBSOCKETS
	&proto_ws,
#endif
	NULL
};

static void node_io_destroy(gpointer user_data)
{
	struct session *session = user_data;
	GIOChannel *proto_io;

	proto_io = session->proto_io;

	/*
	 * Destroy callback may be called after a remote (Radio or Unix peer)
	 * initiated disconnection. If Cloud is still connected: disconnect
	 * release allocated resources.
	 */

	if (session->proto_id) {
		g_source_remove(session->proto_id);

		g_io_channel_shutdown(proto_io, FALSE, NULL);
		g_io_channel_unref(proto_io);
	}

	session_list = g_slist_remove(session_list, session);
	g_free(session);
}

static gboolean proto_io_watch(GIOChannel *io, GIOCondition cond,
								 gpointer user_data)
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
		g_io_channel_unref(session->proto_io);
		session->proto_io = NULL;
	}

	return FALSE;
}

static void proto_io_destroy(gpointer user_data)
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

static gboolean node_io_watch(GIOChannel *io, GIOCondition cond,
						gpointer user_data)
{
	struct session *session = user_data;
	struct node_ops *ops = session->ops;
	uint8_t ipdu[512], opdu[512]; /* FIXME: */
	ssize_t recvbytes, sentbytes, olen;
	int sock, proto_sock, err;
	GIOCondition watch_cond;


	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		/*
		 * Mark as removed. node_io has only one
		 * reference. Returning FALSE removes the
		 * last reference and the destroy callback
		 * is called.
		 */
		if (cond & G_IO_HUP && session->proto_io) {
			proto_sock =
				g_io_channel_unix_get_fd(session->proto_io);
			proto->close(proto_sock);
		}
		session->node_id = 0;
		return FALSE;
	}

	sock = g_io_channel_unix_get_fd(io);

	recvbytes = ops->recv(sock, ipdu, sizeof(ipdu));
	if (recvbytes <= 0) {
		err = errno;
		hal_log_error("readv(): %s(%d)", strerror(err), err);
		return FALSE;
	}

	if (!session->proto_io) {
		proto_sock = proto->connect();
		if (proto_sock < 0) {
			/* TODO:  missing reply an error */
			hal_log_info("Can't connect to cloud service!");
			session->node_id = 0;
			return FALSE;
		}

		hal_log_info("Connected to cloud service!");

		session->proto_io = g_io_channel_unix_new(proto_sock);

		watch_cond = G_IO_HUP | G_IO_NVAL | G_IO_ERR;
		session->proto_id = g_io_add_watch_full(session->proto_io,
							G_PRIORITY_DEFAULT,
							watch_cond,
							proto_io_watch, session,
							proto_io_destroy);
	} else
		proto_sock = g_io_channel_unix_get_fd(session->proto_io);

	olen = msg_process(sock, proto_sock, ipdu,
					recvbytes, opdu, sizeof(opdu));
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

	sentbytes = ops->send(sock, opdu, olen);
	if (sentbytes < 0)
		hal_log_error("node_ops: %s(%zd)",
					strerror(-sentbytes), -sentbytes);

	return TRUE;
}

static bool on_accepted_cb(struct node_ops *node_ops, int client_socket)
{
	GIOChannel *node_io, *proto_io;
	int proto_sock;
	GIOCondition watch_cond;
	struct session *session;

	/* FIXME: Stop knotd if cloud if not available */
	proto_sock = proto->connect();

	/* Disconnect peer if fog/cloud is down */
	if (proto_sock < 0) {
		hal_log_info("Cloud connect(): %s(%d)",
					 strerror(-proto_sock), -proto_sock);
		close(client_socket);
		return true;
	}

	node_io = g_io_channel_unix_new(client_socket);
	g_io_channel_set_close_on_unref(node_io, TRUE);

	proto_io = g_io_channel_unix_new(proto_sock);

	session = g_new0(struct session, 1);
	/* Watch for unix socket disconnection */
	watch_cond = G_IO_HUP | G_IO_NVAL | G_IO_ERR | G_IO_IN;
	session->node_id = g_io_add_watch_full(node_io,
				G_PRIORITY_DEFAULT, watch_cond,
				node_io_watch, session,
				node_io_destroy);
	g_io_channel_unref(node_io);

	/* Watch for TCP socket disconnection */
	watch_cond = G_IO_HUP | G_IO_NVAL | G_IO_ERR;
	session->proto_id = g_io_add_watch_full(proto_io,
				G_PRIORITY_DEFAULT, watch_cond,
				proto_io_watch, session,
				proto_io_destroy);

	/* Keep one reference to call sign-off */
	session->proto_io = proto_io;

	/* TODO: Create refcount */
	session->ops = node_ops;

	hal_log_info("node:%p proto:%p", node_io, proto_io);

	session_list = g_slist_prepend(session_list, session);

	return true;
}

int manager_start(const struct settings *settings)
{
	int err, i;

	/*
	 * Selecting meshblu IoT protocols & services: HTTP/REST,
	 * Websockets, Socket IO, MQTT, COAP. 'proto_ops' drivers
	 * implements an abstraction similar to WEB client operations.
	 * TODO: later support dynamic protocol selection.
	 */

	for (i = 0; proto_ops[i]; i++) {
		if (strcmp(settings->proto, proto_ops[i]->name) != 0)
			continue;

		proto = proto_ops[i];
	}

	if (proto == NULL)
		return -EINVAL;

	/* Starting msg layer */
	err = msg_start(settings->uuid, proto);
	if (err < 0)
		return err;

	if (proto->probe(settings->host, settings->port) < 0) {
		msg_stop();
		return -EIO;
	}

	hal_log_info("proto_ops: %s", proto->name);

	err = node_start(settings->tty, on_accepted_cb);
	if (err < 0) {
		msg_stop();
		proto->remove();
	}

	return err;
}

void manager_stop(void)
{
	GSList *list;
	struct session *session;

	msg_stop();
	node_stop();

	proto->remove();

	for (list = session_list; list; list = g_slist_next(list)) {
		session = list->data;

		/* Freed by node_io_destroy */
		g_source_remove(session->node_id);
	}

	g_slist_free(session_list);
}
