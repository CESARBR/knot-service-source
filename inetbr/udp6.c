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
#include "udp6.h"

static struct l_io *io6;
static struct l_hashmap *udp_hash6;

struct watch6 {
	struct l_io *io;		/* ELL watch */
	int sock;			/* Unix socket */
	int cli_sock;			/* DGRAM socket */
	struct sockaddr_in6 addr;
};

static void downlink6_destroy(void *user_data)
{
	char *ipv6 = user_data;
	struct watch6 *watch;

	/* Unix socket gets disconnected: remote or local initiated */
	watch = l_hashmap_remove(udp_hash6, ipv6);

	l_free(ipv6);

	if (!watch)
		return;

	hal_log_info("destroyed watch(%p) io(%p)", watch, watch->io);
	l_free(watch);

}


static bool downlink6_cb(struct l_io *io, void *user_data)
{
	const char *ipv6 = user_data;
	struct sockaddr_in6 addr;
	struct watch6 *watch;
	char buffer[1280];
	ssize_t len;
	int sock, err;

	sock = l_io_get_fd(io);
	len = read(sock, buffer, sizeof(buffer));
	if (len < 0) {
		err = errno;
		hal_log_error("read(): %s(%d)", strerror(err), err);
		return false;
	}

	watch = l_hashmap_lookup(udp_hash6, ipv6);
	if (!watch)
		return false;

	memcpy(&addr, &watch->addr, sizeof(addr));
	if (sendto(watch->cli_sock, buffer, len, 0,
			(struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		hal_log_error("sendto(%s):  %s(%d)", ipv6, strerror(err), err);
	}

	return true;
}

static bool read_udp6_cb(struct l_io *io, void *user_data)
{
	struct sockaddr_in6 addr6;
	struct watch6 *watch;
	char buffer[1280];
	char ipv6_str[INET6_ADDRSTRLEN];
	socklen_t addrlen;
	ssize_t len;
	int err;
	int cli_sock;
	int sock;

	cli_sock = l_io_get_fd(io);

	addrlen = sizeof(addr6);
	memset(&addr6, 0, sizeof(addr6));
	len = recvfrom(cli_sock, buffer, sizeof(buffer), 0,
		       (struct sockaddr *) &addr6, &addrlen);

	inet_ntop(AF_INET6, &(addr6.sin6_addr), ipv6_str, INET6_ADDRSTRLEN);

	watch = l_hashmap_lookup(udp_hash6, ipv6_str);
	if (watch) {
		sock = watch->sock;
	} else {
		/* New peer */
		sock = unix_connect();
		if (sock < 0)
			return true;

		watch = l_new(struct watch6, 1);
		watch->io = l_io_new(sock);
		l_io_set_close_on_destroy(watch->io, true);
		watch->sock = sock;
		watch->cli_sock = cli_sock;

		l_io_set_read_handler(watch->io, downlink6_cb, l_strdup(ipv6_str),
				      downlink6_destroy);
		l_hashmap_insert(udp_hash6, ipv6_str, watch);
	}

	memcpy(&watch->addr, &addr6, sizeof(watch->addr));

	hal_log_info("%s, watch:%p, io: %p sock:%d > %d, port:%d, len:%zu",
		     ipv6_str, watch, watch->io, cli_sock, sock, addr6.sin6_port, len);

	len = write(sock, buffer, len);
	if (len < 0) {
		err = errno;
		hal_log_info("write(): %s(%d)", strerror(err), err);
	}

	return true;
}

int udp6_start(int port6)
{
	struct sockaddr_in6 addr6;
	int on = 1;
	int err;
	int sock;

	hal_log_info("Starting UDP IPv6 at port %d...", port6);

	sock = socket(AF_INET6, SOCK_DGRAM, 0);
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
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(port6);
	addr6.sin6_addr = in6addr_any;

	if (bind(sock, (struct sockaddr *) &addr6, sizeof(addr6)) < 0) {
		err = errno;
		hal_log_error("bind IPv6(): %s(%d)", strerror(err), err);
		goto fail;
	}

	io6 = l_io_new(sock);
	l_io_set_close_on_destroy(io6, true);
	l_io_set_read_handler(io6, read_udp6_cb, NULL, NULL);

	udp_hash6 = l_hashmap_string_new();

	return 0;

fail:
	close (sock);

	return -err;
}

void udp6_stop(void)
{
	l_hashmap_destroy(udp_hash6, NULL);
	if (io6)
		l_io_destroy(io6);
}
