/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2015, CESAR. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the CESAR nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL CESAR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

#include "log.h"
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

static GSList *server_watch = NULL;
static GSList *session_list = NULL;

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

/*
 * Select default IoT protocol index. TODO: Later it can
 * be member of 'session' struct, allowing nodes to select
 * dynamically the wanted IoT protocol at run time.
 */
static int proto_index = 0;

/* TODO: After adding buildroot, investigate if it is possible
 * to add macros for conditional builds, or a dynamic builtin
 * plugin mechanism.
 */
extern struct node_ops unix_ops;
extern struct node_ops serial_ops;

static struct node_ops *node_ops[] = {
	&unix_ops,
	&serial_ops,
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
			proto_ops[proto_index]->close(proto_sock);
		}
		session->node_id = 0;
		return FALSE;
	}

	sock = g_io_channel_unix_get_fd(io);

	recvbytes = ops->recv(sock, ipdu, sizeof(ipdu));
	if (recvbytes < 0) {
		err = errno;
		log_error("readv(): %s(%d)", strerror(err), err);
		return TRUE;
	}

	if (!session->proto_io) {
		proto_sock = proto_ops[proto_index]->connect();
		if (proto_sock < 0) {
			/* TODO:  missing reply an error */
			log_info("Can't connect to cloud service!");
			session->node_id = 0;
			return FALSE;
		}

		log_info("Connected to cloud service!");

		session->proto_io = g_io_channel_unix_new(proto_sock);

		watch_cond = G_IO_HUP | G_IO_NVAL | G_IO_ERR;
		session->proto_id = g_io_add_watch_full(session->proto_io,
							G_PRIORITY_DEFAULT,
							watch_cond,
							proto_io_watch, session,
							proto_io_destroy);
	} else
		proto_sock = g_io_channel_unix_get_fd(session->proto_io);

	olen = msg_process(sock, proto_sock, proto_ops[proto_index], ipdu,
					recvbytes, opdu, sizeof(opdu));
	/* olen: output length or -errno */
	if (olen < 0) {
		/* Server didn't reply any error */
		log_error("KNOT IoT proto error: %s(%ld)",
						strerror(-olen), -olen);
		return TRUE;
	}
	/* If there are no octets to be sent */
	if (!olen)
		return TRUE;

	/* Response from the gateway: error or response for the given command */
	sentbytes = ops->send(sock, opdu, olen);
	if (sentbytes < 0)
		log_error("node_ops: %s(%ld)",
					strerror(-sentbytes), -sentbytes);

	return TRUE;
}

static gboolean accept_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct node_ops *ops = user_data;
	GIOChannel *node_io, *proto_io;
	int sockfd, srv_sock, proto_sock;
	GIOCondition watch_cond;
	struct session *session;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR))
		return FALSE;

	srv_sock = g_io_channel_unix_get_fd(io);

	sockfd = ops->accept(srv_sock);
	if (sockfd < 0) {
		log_error("%p accept(): %s(%d)", ops,
					strerror(-sockfd), -sockfd);
		return FALSE;
	}

	/* FIXME: Stop knotd if cloud if not available */
	proto_sock = proto_ops[proto_index]->connect();
	if (proto_sock < 0) {
		log_info("Can't connect to cloud service!");
		return FALSE;
	}

	node_io = g_io_channel_unix_new(sockfd);
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
	session->ops = ops;

	log_info("node:%p proto:%p", node_io, proto_io);

	session_list = g_slist_prepend(session_list, session);

	return TRUE;
}

int manager_start(const struct settings *settings)
{
	GIOCondition cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	GIOChannel *server_io;
	int err, sock, i;
	guint server_watch_id;

	/* Tell Serial which port to use */
	if (settings->tty)
		serial_load_config(settings->tty);

	/* Starting msg layer */
	err = msg_start(settings->uuid);
	if (err < 0)
		return err;

	/*
	 * Selecting meshblu IoT protocols & services: HTTP/REST,
	 * Websockets, Socket IO, MQTT, COAP. 'proto_ops' drivers
	 * implements an abstraction similar to WEB client operations.
	 * TODO: later support dynamic protocol selection.
	 */

	for (i = 0; proto_ops[i]; i++) {
		if (strcmp(settings->proto, proto_ops[i]->name) != 0)
			continue;

		if (proto_ops[i]->probe(settings->host, settings->port) < 0)
			return -EIO;

		log_info("proto_ops(%p): %s", proto_ops[i],
							proto_ops[i]->name);
		proto_index = i;
	}

	/*
	 * Probing all access technologies: nRF24L01, BTLE, TCP, Unix
	 * sockets, Serial, etc. 'node_ops' drivers implements an
	 * abstraction similar to server sockets, it enables incoming
	 * connections and provides functions to receive and send data
	 * streams from/to KNOT nodes.
	 */
	for (i = 0; node_ops[i]; i++) {

		/* Ignore Serial driver if port is not informed */
		if ((strcmp("Serial", node_ops[i]->name) == 0) &&
							settings->tty == NULL)
			continue;

		if (node_ops[i]->probe() < 0)
			continue;

		sock = node_ops[i]->listen();
		if (sock < 0) {
			err = sock;
			log_error("%p listen(): %s(%d)", node_ops[i],
						strerror(-err), -err);
			node_ops[i]->remove();
			continue;
		}

		server_io = g_io_channel_unix_new(sock);
		g_io_channel_set_close_on_unref(server_io, TRUE);
		g_io_channel_set_flags(server_io, G_IO_FLAG_NONBLOCK, NULL);

		/* Use node_ops as parameter to allow multi drivers */
		server_watch_id = g_io_add_watch(server_io, cond, accept_cb,
								node_ops[i]);
		g_io_channel_unref(server_io);

		log_info("node_ops(%p): (%s) watch: %d", node_ops[i],
					node_ops[i]->name, server_watch_id);

		server_watch = g_slist_prepend(server_watch,
				      GUINT_TO_POINTER(server_watch_id));
	}

	return 0;
}

void manager_stop(void)
{
	GSList *list;
	struct session *session;
	guint server_watch_id;
	int i;

	msg_stop();

	/* Remove only previously loaded modules */
	for (i = 0; node_ops[i]; i++)
		node_ops[i]->remove();

	proto_ops[proto_index]->remove();

	for (list = server_watch; list; list = g_slist_next(list)) {
		server_watch_id = GPOINTER_TO_UINT(list->data);
		g_source_remove(server_watch_id);

		log_info("Removed watch: %d", server_watch_id);
	}

	g_slist_free(server_watch);

	for (list = session_list; list; list = g_slist_next(list)) {
		session = list->data;

		/* Freed by node_io_destroy */
		g_source_remove(session->node_id);
	}

	g_slist_free(session_list);
}
