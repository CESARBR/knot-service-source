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
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <ell/ell.h>
#include <hal/linux_log.h>

#include "unix.h"
#include "tcp4.h"

static struct l_io *io4;

static bool read_cb(struct l_io *io, void *user_data)
{
	struct l_io *io_dst = user_data;
	char buffer[1280];
	ssize_t len;
	int sock_src;
	int sock_dst;
	int err;

	sock_src = l_io_get_fd(io);

	len = read(sock_src, buffer, sizeof(buffer));
	if (len < 0)
		return true;

	sock_dst = l_io_get_fd(io_dst);
	len = write(sock_dst, buffer, len);
	if (len < 0) {
		err = errno;
		hal_log_info("write(): %s(%d)", strerror(err), err);
	}

	return true;
}

static void disconnect_cb(struct l_io *io, void *user_data)
{
	struct l_io *io_peer = user_data;
	l_io_destroy(io_peer);

	hal_log_info("disconnect_cb(%p): %p", io, io_peer);
}

static bool accept_tcp4_cb(struct l_io *io, void *user_data)
{
	struct l_io *io_unix;
	struct l_io *io_cli;
	int sock_unix;
	int sock_cli;
	int sock;

	sock = l_io_get_fd(io);

	sock_cli = accept(sock, NULL, NULL);
	if (sock_cli == -1)
		return true;

	sock_unix = unix_connect();
	if (sock_unix < 0) {
		close(sock_cli);
		return true;
	}

	io_cli = l_io_new(sock_cli);
	l_io_set_close_on_destroy(io_cli, true);

	io_unix = l_io_new(sock_unix);
	l_io_set_close_on_destroy(io_unix, true);

	l_io_set_read_handler(io_cli, read_cb, io_unix, NULL);
	l_io_set_disconnect_handler(io_cli, disconnect_cb, io_unix, NULL);

	l_io_set_read_handler(io_unix, read_cb, io_cli, NULL);
	l_io_set_disconnect_handler(io_unix, disconnect_cb, io_cli, NULL);

	hal_log_info("accept_cb io_cli:%p io_unix:%p", io_cli, io_unix);

	return true;
}

int tcp4_start(int port4)
{
	struct sockaddr_in addr4;
	int sock;
	int on = 1;
	int err;

	hal_log_info("Starting TCP IPv4 at port %d...", port4);

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		err = errno;
		hal_log_error("socket IPv4(): %s(%d)", strerror(err), err);
		return -err;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
					(char *) &on, sizeof(on)) < 0) {
		err = errno;
		hal_log_error("setsockopt IPv4(): %s(%d)", strerror(err), err);
		goto fail;
	}

	memset(&addr4, 0, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_port = htons(port4);
	addr4.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sock, (struct sockaddr *) &addr4, sizeof(addr4)) < 0) {
		err = errno;
		hal_log_error("bind IPv4(): %s(%d)", strerror(err), err);
		goto fail;
	}

	if (listen(sock, 1) == -1) {
		err = errno;
		goto fail;
	}

	io4 = l_io_new(sock);
	l_io_set_close_on_destroy(io4, true);

	l_io_set_read_handler(io4, accept_tcp4_cb, NULL, NULL);

	return 0;

fail:
	close (sock);

	return -err;
}

void tcp4_stop(void)
{
	if (io4)
		l_io_destroy(io4);
}
