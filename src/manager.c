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

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <glib.h>
#include <knot/proto.h>

#include "node.h"
#include "proto.h"

/* Abstract unit socket namespace */
#define KNOT_UNIX_SOCKET	"knot"

struct watch_pair {
	unsigned int radio_id;	/* Radio event source */
	unsigned int proto_id;	/* TCP/backend event source */
	GIOChannel *proto_io;	/* Protocol GIOChannel reference */
};

static unsigned int server_watch_id;
static struct proto_ops *proto_ops;
static struct node_ops *node_ops;

static gboolean unix_io_watch(GIOChannel *io, GIOCondition cond,
			      gpointer user_data)
{
	struct watch_pair *watch = user_data;
	struct iovec iov[2];
	knot_header hdr;
	uint8_t payload[128];
	ssize_t nbytes;
	int sock, proto_sock, err = 0;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		return FALSE;

	sock = g_io_channel_unix_get_fd(io);

	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = payload;
	iov[1].iov_len = sizeof(payload);

	nbytes = readv(sock, iov, 2);
	if (nbytes < 0) {
		err = errno;
		printf("readv(): %s(%d)\n", strerror(err), err);
		return FALSE;
	}

	printf("KNOT OP: 0x%02X LEN: %02x\n", hdr.opcode, hdr.len);

	proto_sock = g_io_channel_unix_get_fd(watch->proto_io);
	switch (hdr.opcode) {
	case KNOT_OP_REGISTER:
		err = proto_ops->signup(proto_sock);
		break;
	default:
		/* TODO: reply unknown command */
		break;
	}

	if (err)
		printf("KNOT IoT proto error: %s(%d)\n", strerror(err), err);

	return TRUE;
}

static void unix_io_destroy(gpointer user_data)
{

	struct watch_pair *watch = user_data;
	int sock;

	/* Mark as removed */
	watch->radio_id = 0;

	/*
	 * When the protocol connection (backend) is dropped
	 * call signoff & unref the GIOChannel.
	 */
	sock = g_io_channel_unix_get_fd(watch->proto_io);
	proto_ops->close(sock);
	g_io_channel_unref(watch->proto_io);

	if (watch->proto_id)
		g_source_remove(watch->proto_id);

	g_free(watch);
}

static gboolean proto_io_watch(GIOChannel *io, GIOCondition cond,
					       gpointer user_data)
{
	/* Return FALSE to remove protocol GIOChannel reference */

	return FALSE;
}

static void proto_io_destroy(gpointer user_data)
{
	struct watch_pair *watch = user_data;

	/*
	 * Remove Unix socket GIOChannel watch when protocol
	 * socket disconnects. Removing the watch triggers
	 * channe unref and consequently disconnection of
	 * the Unix socket
	 */

	/* Mark protocol watch as removed */
	watch->proto_id = 0;

	if (watch->radio_id)
	    g_source_remove(watch->radio_id);
}

static gboolean accept_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	GIOChannel *unix_io, *proto_io;
	int unix_sock, srv_sock, proto_sock;
	GIOCondition watch_cond;
	struct watch_pair *watch;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR))
		return FALSE;

	/* TODO: accept */
	printf("TODO: accepting ...\n");

	srv_sock = g_io_channel_unix_get_fd(io);

	unix_sock = accept(srv_sock, NULL, NULL);
	if (unix_sock < 0)
		return FALSE;

	unix_io = g_io_channel_unix_new(unix_sock);
	g_io_channel_set_close_on_unref(unix_io, TRUE);

	proto_sock = proto_ops->connect();
	proto_io = g_io_channel_unix_new(proto_sock);
	g_io_channel_set_close_on_unref(proto_io, TRUE);

	watch = g_new0(struct watch_pair, 1);
	/* Watch for unix socket disconnection */
	watch_cond = G_IO_HUP | G_IO_NVAL | G_IO_ERR | G_IO_IN;
	watch->radio_id = g_io_add_watch_full(unix_io,
				G_PRIORITY_DEFAULT, watch_cond,
				unix_io_watch, watch,
				unix_io_destroy);

	/* Keep only one ref: GIOChannel watch */
	g_io_channel_unref(unix_io);

	/* Watch for TCP socket disconnection */
	watch_cond = G_IO_HUP | G_IO_NVAL | G_IO_ERR;
	watch->proto_id = g_io_add_watch_full(proto_io,
				G_PRIORITY_DEFAULT, watch_cond,
				proto_io_watch, watch,
				proto_io_destroy);

	/* Keep one reference to call sign-off */
	watch->proto_io = proto_io;

	return TRUE;
}

int manager_start(void)
{
	int err, sock;
	GIOCondition cond;
	GIOChannel *server_io;
	struct sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {
		err = -errno;
		goto done;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	/* Abstract namespace: first character must be null */
	strncpy(addr.sun_path + 1, KNOT_UNIX_SOCKET, strlen(KNOT_UNIX_SOCKET));
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		close(sock);
		err = -errno;
		goto done;
	}

	server_io = g_io_channel_unix_new(sock);
	g_io_channel_set_close_on_unref(server_io, TRUE);
	g_io_channel_set_flags(server_io, G_IO_FLAG_NONBLOCK, NULL);

	if (listen(sock, 1) == -1) {
		g_io_channel_unref(server_io);
		err = -errno;
		goto done;
	}

	cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	server_watch_id = g_io_add_watch(server_io, cond, accept_cb, NULL);
	g_io_channel_unref(server_io);

	err = 0;

done:
	return err;
}

void manager_stop(void)
{
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

int node_ops_register(struct node_ops *ops)
{
	/*
	 * At the moment only onde instance is supported. The
	 * ideia is try to support multiple radio technologies and
	 * even proxy for any socket based communication. eg: Proxy
	 * for external incoming connections, connecting it to Meshblu
	 * or other backends.
	 */
	node_ops = ops;

	return 0;
}

void node_ops_unregister(struct node_ops *ops)
{
	node_ops = NULL;
}
