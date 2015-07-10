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
#include <stdint.h>

#include <libwebsockets.h>

#include <glib.h>

#include "proto.h"
#include "ws.h"

struct libwebsocket_context *context;

static int ws_signup(void)
{
	struct libwebsocket *ws;
	gboolean use_ssl = FALSE;
	const char *address = "meshblu.octoblu.com";
	int port = 80;

	ws = libwebsocket_client_connect(context, address, port,
					 use_ssl, "/ws/v2", address,
					 "origin", NULL, -1);

	return libwebsocket_get_socket_fd(ws);
}

static int ws_signin(const char *token)
{
	return 0;
}

static void ws_signoff(int sock)
{

}

static struct proto_ops ops = {
	.signup = ws_signup,
	.signin = ws_signin,
	.signoff= ws_signoff,
};

static int callback_lws_default(struct libwebsocket_context * this,
			       struct libwebsocket *wsi,
			       enum libwebsocket_callback_reasons
			       reason, void *user, void *in, size_t len)
{

	printf("LwS: callback\n");

	return 0;
}

static struct libwebsocket_protocols protocols[] = {

	{
		"default",
		callback_lws_default,
		0, 0, 0, NULL, NULL, 0
	},
	{
		NULL, NULL, 0, 0, 0, NULL, NULL, 0 /* end of list */
	}
};

int ws_register(void)
{
	struct lws_context_creation_info info;

	memset(&info, 0, sizeof info);

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.gid = -1;
	info.uid = -1;
	info.protocols = protocols;

	context = libwebsocket_create_context(&info);

	return proto_ops_register(&ops);
}

void ws_unregister(void)
{
	libwebsocket_context_destroy(context);

	proto_ops_unregister(&ops);
}
