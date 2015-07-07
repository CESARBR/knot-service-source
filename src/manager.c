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

#include "proto.h"

/* Abstract unit socket namespace */
#define KNOT_UNIX_SOCKET	"knot"

GIOChannel *server_io;

static struct proto_ops *proto_ops;

static gboolean accept_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	GIOChannel *cli_io;
	int cli_sock, srv_sock, node_sock;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR))
		return FALSE;

	/* TODO: accept */
	printf("TODO: accepting ...\n");

	srv_sock = g_io_channel_unix_get_fd(io);

	cli_sock = accept(srv_sock, NULL, NULL);
	if (cli_sock < 0)
		return FALSE;

	cli_io = g_io_channel_unix_new(cli_sock);
	g_io_channel_set_close_on_unref(cli_io, TRUE);
	g_io_channel_set_flags(cli_io, G_IO_FLAG_NONBLOCK, NULL);

	/* TODO: handle requests */

	node_sock = proto_ops->signup();

	printf("Node sock: %d\n", node_sock);

	g_io_channel_unref(cli_io);

	return TRUE;
}

int manager_start(void)
{
	int err, sock;
	GIOCondition cond;
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
	g_io_add_watch(server_io, cond, accept_cb, NULL);

	err = 0;

done:
	return err;
}

void manager_stop(void)
{
	g_io_channel_unref(server_io);
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
