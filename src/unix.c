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

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "node.h"

/* Abstract unit socket namespace */
#define KNOT_UNIX_SOCKET	"knot"

static int unix_probe(void)
{

	return 0;
}

static void unix_remove(void)
{

}

static int unix_listen(void)
{
	int err, sock;
	struct sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sock < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	/* Abstract namespace: first character must be null */
	strncpy(addr.sun_path + 1, KNOT_UNIX_SOCKET, strlen(KNOT_UNIX_SOCKET));
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		err = -errno;
		close(sock);
		return err;
	}

	if (listen(sock, 1) == -1) {
		err = -errno;
		close(sock);
		return err;
	}

	return sock;
}

static int unix_accept(int srv_sockfd)
{
	int sockfd;

	sockfd = accept(srv_sockfd, NULL, NULL);
	if (sockfd == -1)
		return -errno;

	return sockfd;
}

static ssize_t unix_recv(int sockfd, void *buffer, size_t len)
{
	return recv(sockfd, buffer, len, 0);
}

static ssize_t unix_send(int sockfd, const void *buffer, size_t len)
{
	return send(sockfd, buffer, len, 0);
}

struct node_ops unix_ops = {
	.name = "Unix",
	.probe = unix_probe,
	.remove = unix_remove,

	.listen = unix_listen,
	.accept = unix_accept,
	.recv = unix_recv,
	.send = unix_send
};
