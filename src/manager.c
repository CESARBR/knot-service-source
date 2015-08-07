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
#include <json-c/json.h>

#include <glib.h>
#include <knot/proto.h>

#include "node.h"
#include "proto.h"
#include "manager.h"

/*
 * Device session storing the connected
 * device context: 'drivers' and file descriptors
 */
struct session {
	unsigned int radio_id;	/* Radio event source */
	unsigned int proto_id;	/* TCP/backend event source */
	GIOChannel *proto_io;	/* Protocol GIOChannel reference */
	struct node_ops *ops;
	char *uuid;
	char *token;
};

static unsigned int server_watch_id;
static struct proto_ops *proto_ops;

/* TODO: After adding buildroot, investigate if it is possible
 * to add macros for conditional builds, or a dynamic builtin
 * plugin mechanism.
 */
extern struct node_ops unix_ops;
#ifdef HAVE_RADIOHEAD
extern struct node_ops nrf24_ops;
extern struct node_ops tcp_ops;
#endif

static struct node_ops *node_ops[] = {
	&unix_ops,
#ifdef HAVE_RADIOHEAD
	&nrf24_ops,
	&tcp_ops,
#endif
	NULL
};

static void parse_device_info(const char *json_str, struct session *session)
{
	json_object *jobj,*json_uuid, *json_token;
	const char *uuid, *token;

	jobj = json_tokener_parse(json_str);
	if (jobj == NULL)
		return;

	if (!json_object_object_get_ex(jobj, "uuid", &json_uuid))
		return;

	if (!json_object_object_get_ex(jobj, "token", &json_token))
		return;

	uuid = json_object_get_string(json_uuid);
	token = json_object_get_string(json_token);

	session->uuid = g_strdup(uuid);
	session->token = g_strdup(token);
}

static gboolean node_io_watch(GIOChannel *io, GIOCondition cond,
			      gpointer user_data)
{
	struct session *session = user_data;
	struct node_ops *ops = session->ops;
	uint8_t dgram[128];
	const knot_header *hdr = (const knot_header *) dgram;
	struct json_buffer jbuf = { .data = NULL, .size = 0 };
	ssize_t nbytes;
	int sock, proto_sock, err = 0;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		return FALSE;

	sock = g_io_channel_unix_get_fd(io);

	nbytes = ops->recv(sock, dgram, sizeof(dgram));
	if (nbytes < 0) {
		err = errno;
		printf("readv(): %s(%d)\n", strerror(err), err);
		return FALSE;
	}

	printf("KNOT OP: 0x%02X LEN: %02x\n", hdr->opcode, hdr->len);

	proto_sock = g_io_channel_unix_get_fd(session->proto_io);
	switch (hdr->opcode) {
	case KNOT_OP_REGISTER:
		err = proto_ops->signup(proto_sock, &jbuf);
		printf("%s: %s\n", __PRETTY_FUNCTION__, jbuf.data);
		parse_device_info(jbuf.data, session);
		free(jbuf.data);
		break;
	default:
		/* TODO: reply unknown command */
		break;
	}

	if (err)
		printf("KNOT IoT proto error: %s(%d)\n", strerror(err), err);

	return TRUE;
}

static void node_io_destroy(gpointer user_data)
{

	struct session *session = user_data;
	int sock;

	/* Mark as removed */
	session->radio_id = 0;

	/*
	 * When the protocol connection (backend) is dropped
	 * call signoff & unref the GIOChannel.
	 */
	sock = g_io_channel_unix_get_fd(session->proto_io);
	proto_ops->close(sock);
	g_io_channel_unref(session->proto_io);

	if (session->proto_id)
		g_source_remove(session->proto_id);

	if (session->token)
		g_free(session->token);

	if (session->uuid)
		g_free(session->uuid);

	g_free(session);
}

static gboolean proto_io_watch(GIOChannel *io, GIOCondition cond,
					       gpointer user_data)
{
	/* Return FALSE to remove protocol GIOChannel reference */

	return FALSE;
}

static void proto_io_destroy(gpointer user_data)
{
	struct session *session = user_data;

	/*
	 * Remove Unix socket GIOChannel watch when protocol
	 * socket disconnects. Removing the watch triggers
	 * channe unref and consequently disconnection of
	 * the Unix socket
	 */

	/* Mark protocol watch as removed */
	session->proto_id = 0;

	if (session->radio_id)
	    g_source_remove(session->radio_id);
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

	printf("%p accept()\n", ops);
	sockfd = ops->accept(srv_sock);
	if (sockfd < 0) {
		printf("%p accept(): %s(%d)\n", ops,
					strerror(-sockfd), -sockfd);
		return FALSE;
	}

	node_io = g_io_channel_unix_new(sockfd);
	g_io_channel_set_close_on_unref(node_io, TRUE);

	proto_sock = proto_ops->connect();
	proto_io = g_io_channel_unix_new(proto_sock);
	g_io_channel_set_close_on_unref(proto_io, TRUE);

	session = g_new0(struct session, 1);
	/* Watch for unix socket disconnection */
	watch_cond = G_IO_HUP | G_IO_NVAL | G_IO_ERR | G_IO_IN;
	session->radio_id = g_io_add_watch_full(node_io,
				G_PRIORITY_DEFAULT, watch_cond,
				node_io_watch, session,
				node_io_destroy);

	/* Keep only one ref: GIOChannel watch */
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

	return TRUE;
}

int manager_start(void)
{
	GIOCondition cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	GIOChannel *server_io;
	int err, sock, i;

	for (i = 0; node_ops[i]; i++) {

		printf("Probing %p: %s\n", node_ops[i], node_ops[i]->name);

		if (node_ops[i]->probe() < 0)
			continue;

		sock = node_ops[i]->listen();
		if (sock < 0) {
			err = sock;
			printf("%p listen(): %s(%d)\n", node_ops[i],
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
	}


	return 0;
}

void manager_stop(void)
{
	int i;

	/* Remove only previously loaded modules */
	for (i = 0; node_ops[i]; i++)
		node_ops[i]->remove();

	if (server_watch_id)
		g_source_remove(server_watch_id);
}

int proto_ops_register(struct proto_ops *ops)
{
	/*
	 * At the moment only onde instance is supported. The
	 * ideia is try to support dynamic selection of back-end
	 * service.
	 */
	proto_ops = ops;

	return 0;
}

void proto_ops_unregister(struct proto_ops *ops)
{

}
