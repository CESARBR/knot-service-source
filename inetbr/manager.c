/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2017, CESAR. All rights reserved.
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
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <hal/linux_log.h>

#include "manager.h"

#define SERVER_PORT_IPV4		8084
#define SERVER_PORT_IPV6		8086

static int sock4 = -1;
static int sock6 = -1;

static int inet4_start(void)
{
	struct sockaddr_in addr4;
	int on = 1;
	int err;

	sock4 = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock4 < 0) {
		err = errno;
		hal_log_error("socket IPv4(): %s(%d)", strerror(err), err);
		return -err;
	}

	if (setsockopt(sock4, SOL_SOCKET, SO_REUSEADDR,
					(char *) &on, sizeof(on)) < 0) {
		err = errno;
		hal_log_error("setsockopt IPv4(): %s(%d)", strerror(err), err);
		goto fail;
	}

	memset(&addr4, 0, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_port = htons(SERVER_PORT_IPV4);
	addr4.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sock4, (struct sockaddr *) &addr4, sizeof(addr4)) < 0) {
		err = errno;
		hal_log_error("bind IPv4(): %s(%d)", strerror(err), err);
		goto fail;
	}

	return 0;

fail:
	close (sock4);

	return -err;
}

static void inet4_stop(void)
{
	if (sock4 >= 0)
		close(sock4);
}

static int inet6_start(void)
{
	struct sockaddr_in6 addr6;
	int on = 1;
	int err;

	sock6 = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock6 < 0) {
		err = errno;
		hal_log_error("socket IPv6(): %s(%d)", strerror(err), err);
		return -err;
	}

	if (setsockopt(sock6, SOL_SOCKET, SO_REUSEADDR,
					(char *) &on, sizeof(on)) < 0) {
		err = errno;
		hal_log_error("setsockopt IPv6(): %s(%d)", strerror(err), err);
		goto fail;
	}

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(SERVER_PORT_IPV6);
	addr6.sin6_addr = in6addr_any;

	if (bind(sock6, (struct sockaddr *) &addr6, sizeof(addr6)) < 0) {
		err = errno;
		hal_log_error("bind IPv6(): %s(%d)", strerror(err), err);
		goto fail;
	}

	return 0;

fail:
	close(sock6);

	return -err;
}

static void inet6_stop(void)
{
	if (sock6 >= 0)
		close(sock6);
}


int manager_start(void)
{
	int ret;

	ret = inet4_start();
	if (ret < 0)
		return ret;

	ret = inet6_start();
	if (ret < 0)
		inet4_stop();

	return ret;
}

void manager_stop(void)
{
	inet4_stop();
	inet6_stop();
}
