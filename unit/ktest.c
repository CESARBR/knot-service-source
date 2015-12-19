/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2015, CESAR. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	* Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *	* Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 *	* Neither the name of the CESAR nor the
 *	  names of its contributors may be used to endorse or promote products
 *	  derived from this software without specific prior written permission.
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
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <glib.h>

#include "src/log.h"

/* Abstract unit socket namespace */
#define KNOT_UNIX_SOCKET			"knot"

static int sockfd;

static int unix_connect(void)
{
	struct sockaddr_un addr;
	int err, sock;

	sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {
		err = errno;
		LOG_ERROR(" >socket failure: %s (%d)\n", strerror(err), err);
		return -err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	/* Abstract namespace: first character must be null */
	strcpy(addr.sun_path + 1, KNOT_UNIX_SOCKET);

	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		LOG_ERROR("connect(): %s (%d)", strerror(err), err);
		close(sock);
		return -err;
	}

	return sock;
}

static void connection_test(void)
{
	sockfd = unix_connect();
	g_assert(sockfd > 0);
}

static void close_test(void)
{
	g_assert(close(sockfd) == 0);
	sockfd = -1;
}

/* Register and run all tests */
int main(int argc, char *argv[])
{
	g_test_init (&argc, &argv, NULL);

	/* TEST 1: Unix socket connection  */
	g_test_add_func("/1/connect", connection_test);
	g_test_add_func("/1/close", close_test);

	return g_test_run();
}
