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
#include "tcp6.h"

static struct l_io *io6;

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
		hal_log_info("TCPv6 write(): %s(%d)", strerror(err), err);
	}

	return true;
}

static void disconnect_cb(struct l_io *io, void *user_data)
{
	struct l_io *io_peer = user_data;
	l_io_destroy(io_peer);

	hal_log_info("TCPv6 disconnect_cb(%p): %p", io, io_peer);
}

static bool accept_tcp6_cb(struct l_io *io, void *user_data)
{
	struct sockaddr_in6 addr6;
	struct l_io *io_unix;
	struct l_io *io_cli;
	char ipv6_str[INET6_ADDRSTRLEN];
	socklen_t addrlen;
	int sock_unix;
	int sock_cli;
	int sock;

	sock = l_io_get_fd(io);

	addrlen = sizeof(addr6);
	memset(&addr6, 0, sizeof(addr6));

	sock_cli = accept(sock, (struct sockaddr *) &addr6, &addrlen);
	if (sock_cli == -1)
		return true;

	inet_ntop(AF_INET6, &(addr6.sin6_addr), ipv6_str, INET6_ADDRSTRLEN);
	hal_log_info("TCP6 accept(): %s", ipv6_str);

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

	return true;
}

int tcp6_start(int port6)
{
	struct sockaddr_in6 addr6;
	int sock;
	int on = 1;
	int err;

	hal_log_info("Starting TCP IPv6 at port %d...", port6);

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		err = errno;
		hal_log_error("socket IPv6(): %s(%d)", strerror(err), err);
		return -err;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
					(char *) &on, sizeof(on)) < 0) {
		err = errno;
		hal_log_error("setsockopt IPv6(): %s(%d)", strerror(err), err);
		goto fail;
	}

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET;
	addr6.sin6_port = htons(port6);
	addr6.sin6_addr = in6addr_any;

	if (bind(sock, (struct sockaddr *) &addr6, sizeof(addr6)) < 0) {
		err = errno;
		hal_log_error("bind IPv6(): %s(%d)", strerror(err), err);
		goto fail;
	}

	if (listen(sock, 1) == -1) {
		err = errno;
		goto fail;
	}

	io6 = l_io_new(sock);
	l_io_set_close_on_destroy(io6, true);

	l_io_set_read_handler(io6, accept_tcp6_cb, NULL, NULL);

	return 0;

fail:
	close (sock);

	return -err;
}

void tcp6_stop(void)
{
	if (io6)
		l_io_destroy(io6);
}
