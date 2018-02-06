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

/* Abstract unit socket namespace */
#define KNOT_UNIX_SOCKET	"knot"

static inline int unix_connect(void)
{
	struct sockaddr_un addr;
	int err, sock;

	sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sock < 0) {
		err = errno;
		hal_log_error("unix socket(): %s (%d)", strerror(err), err);
		return -err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	/* Abstract namespace: first character must be null */
	strcpy(addr.sun_path + 1, KNOT_UNIX_SOCKET);

	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		hal_log_error("unix connect(): %s (%d)", strerror(err), err);
		close(sock);
		return -err;
	}

	return sock;
}
