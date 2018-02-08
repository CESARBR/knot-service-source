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

#ifndef __NODE_H__
#define __NODE_H__

#include <stdbool.h>
#include <unistd.h>

#include "settings.h"

/*
 * This 'driver' intends to be an abstraction for Radio technologies or
 * proxy for other services using TCP or any socket based communication.
 */
struct node_ops {
	const char *name;
	int (*probe) (void);
	void (*remove) (void);

	int (*listen) (void); /* Enable incoming connections */
	int (*accept) (int srv_sockfd); /* Returns a 'pollable' FD */
	ssize_t (*recv) (int sockfd, void *buffer, size_t len);
	ssize_t (*send) (int sockfd, const void *buffer, size_t len);
};

typedef bool (*on_accepted)(struct node_ops *node_ops, int client_socket);

/*
 * For NRF24L01, there is only one file descriptor associated with
 * the SPI. In this case, sockfd can be just an integer used to map
 * internally the clients. Another approach are eventfd or socketpair,
 * they can be alternatives to integrate to glib main loop or other
 * event loop system.
 */

int node_start(const char *tty, on_accepted on_accepted_cb);
void node_stop(void);

#endif /* __NODE_H__ */
