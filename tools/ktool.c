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
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <glib.h>

/* Abstract unit socket namespace */
#define KNOT_UNIX_SOCKET	"knot"

static int sock;
static const char *opt_token;

static int unix_connect(void)
{
	int err, sock;
	struct sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	/* Abstract namespace: first character must be null */
	strncpy(addr.sun_path + 1, KNOT_UNIX_SOCKET, strlen(KNOT_UNIX_SOCKET));

	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		err = -errno;
		close(sock);
		return err;
	}

	return sock;
}

static int cmd_register(void)
{
	int err;
	ssize_t nbytes;
	uint8_t datagram[128];

	memset(datagram, 0, sizeof(datagram));

	/* TODO: set knot protocol headers and palyload */
	nbytes = write(sock, datagram, sizeof(datagram));
	if (nbytes < 0) {
		err = errno;
		printf("write(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	return 0;
}

static int cmd_auth(const char *token)
{
	int err;
	ssize_t nbytes;
	uint8_t datagram[128];

	memset(datagram, 0, sizeof(datagram));

	/* TODO: set knot protocol headers and palyload */
	nbytes = write(sock, datagram, sizeof(datagram));
	if (nbytes < 0) {
		err = errno;
		printf("write(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	return 0;
}

static GOptionEntry options[] = {
	{ "token", 'a', 0, G_OPTION_ARG_STRING, &opt_token,
					"token", "Hex format" },
	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *gerr = NULL;
	int err;

	printf("KNOT Tool\n");

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &gerr)) {
		printf("Invalid arguments: %s\n", gerr->message);
		g_error_free(gerr);
		exit(EXIT_FAILURE);
	}

	sock = unix_connect();
	if (sock == -1) {
		err = -errno;
		printf("connect(): %s (%d)\n", strerror(-err), -err);
		return err;
	}

	if (opt_token) {
		printf("Authenticating node ...\n");
		err = cmd_auth(opt_token);
	} else {
		/* token not informed: force registration */
		printf("Registering node ...\n");
		err = cmd_register();
	}

	printf("Exiting\n");

	close(sock);

	return err;
}
