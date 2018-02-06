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

#include <glib.h>

#include <hal/linux_log.h>

#include "unix.h"
#include "inet6.h"

static gint io6_watch = -1;
static GHashTable *inet_hash6 = NULL;

struct watch6 {
	int id;				/* glib watch */
	int sock;			/* Unix socket */
	int cli_sock;			/* DGRAM socket */
	struct sockaddr_in6 addr;
};

static void downlink6_destroy(gpointer user_data)
{
	g_hash_table_remove(inet_hash6, user_data);

	g_free(user_data);
}

static gboolean downlink6_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	const char *ipv6 = user_data;
	struct sockaddr_in6 addr;
	struct watch6 *watch;
	char buffer[1280];
	ssize_t len;
	int sock, err;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		return FALSE;

	sock = g_io_channel_unix_get_fd(io);
	len = read(sock, buffer, sizeof(buffer));
	if (len < 0) {
		err = errno;
		hal_log_error("read(): %s(%d)", strerror(err), err);
		return TRUE;
	}

	watch = g_hash_table_lookup(inet_hash6, ipv6);
	if (!watch)
		return TRUE;

	memcpy(&addr, &watch->addr, sizeof(addr));
	if (sendto(watch->cli_sock, buffer, len, 0,
			   (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		hal_log_error("sendto(%s):  %s(%d)", ipv6, strerror(err), err);
	}

	return TRUE;
}

static gboolean read_inet6_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	GIOCondition down_cond = G_IO_ERR | G_IO_HUP | G_IO_NVAL | G_IO_IN;
	struct sockaddr_in6 addr6;
	struct watch6 *watch;
	char buffer[1280];
	char ipv6_str[INET6_ADDRSTRLEN];
	socklen_t addrlen;
	ssize_t len;
	int err;
	int cli_sock;
	int sock;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		return FALSE;

	cli_sock = g_io_channel_unix_get_fd(io);

	addrlen = sizeof(addr6);
	memset(&addr6, 0, sizeof(addr6));
	len = recvfrom(cli_sock, buffer, sizeof(buffer), 0,
		       (struct sockaddr *) &addr6, &addrlen);

	inet_ntop(AF_INET6, &(addr6.sin6_addr), ipv6_str, INET6_ADDRSTRLEN);

	watch = g_hash_table_lookup(inet_hash6, ipv6_str);
	if (watch)
		sock = watch->sock;
	else {
		/* New peer */
		sock = unix_connect();
		if (sock < 0)
			return TRUE;

		watch = g_new0(struct watch6, 1);
		io = g_io_channel_unix_new(sock);
		g_io_channel_set_close_on_unref(io, TRUE);
		watch->sock = sock;
		watch->cli_sock = cli_sock;
		watch->id = g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
						 down_cond,
						 downlink6_cb,
						 g_strdup(ipv6_str),
						 downlink6_destroy);
		g_io_channel_unref(io);

		g_hash_table_insert(inet_hash6,
				    g_strdup(ipv6_str),
				    watch);
	}

	memcpy(&watch->addr, &addr6, sizeof(watch->addr));

	hal_log_info("%s, watch: %d sock:%d > %d, port:%d, len:%zu",
		     ipv6_str, watch->id, cli_sock, sock, addr6.sin6_port, len);

	len = write(sock, buffer, len);
	if (len < 0) {
		err = errno;
		hal_log_info("write(): %s(%d)", strerror(err), err);
	}

	return TRUE;
}

int inet6_start(int port6)
{
	GIOCondition cond = G_IO_ERR | G_IO_HUP | G_IO_NVAL | G_IO_IN;
	struct sockaddr_in6 addr6;
	GIOChannel *io6;
	int on = 1;
	int err;
	int sock;

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

	io6 = g_io_channel_unix_new(sock);
	g_io_channel_set_close_on_unref(io6, TRUE);
	io6_watch = g_io_add_watch_full(io6, G_PRIORITY_DEFAULT,
				  cond, read_inet6_cb, NULL, NULL);
	g_io_channel_unref(io6);

	inet_hash6 = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, g_free);
	return 0;

fail:
	close(sock);

	return -err;
}

static void remove_downlink6_source(gpointer key, gpointer value,
						gpointer user_data)
{
	struct watch6 *watch = value;

	g_source_remove(watch->id);
}

void inet6_stop(void)
{
	g_hash_table_foreach(inet_hash6, remove_downlink6_source, NULL);
	g_hash_table_destroy(inet_hash6);

	if (io6_watch > 0)
		g_source_remove(io6_watch);
}
