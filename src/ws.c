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
static GHashTable *wstable;

static const char *lws_reason2str(enum libwebsocket_callback_reasons reason)
{
	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		return "ESTABLISHED";
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		return "CLIENT_CONNECTION_ERROR";
	case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
		return "CLIENT_FILTER_PRE_ESTABLISH";
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		return "CLIENT_ESTABLISHED";
	case LWS_CALLBACK_CLOSED:
		return "CLOSED";
	case LWS_CALLBACK_CLOSED_HTTP:
		return "CLOSED_HTTP";
	case LWS_CALLBACK_RECEIVE:
		return "RECEIVE";
	case LWS_CALLBACK_CLIENT_RECEIVE:
		return "CLIENT_RECEIVE";
	case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
		return "CLIENT_RECEIVE_PONG";
	case LWS_CALLBACK_CLIENT_WRITEABLE:
		return "CLIENT_WRITEABLE";
	case LWS_CALLBACK_SERVER_WRITEABLE:
		return "SERVER_WRITEABLE";
	case LWS_CALLBACK_HTTP:
		return "HTTP";
	case LWS_CALLBACK_HTTP_BODY:
		return "HTTP_BODY";
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		return "BODY_COMPLETION";
	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
		return "HTTP_FILE_COMPLETION";
	case LWS_CALLBACK_HTTP_WRITEABLE:
		return "HTTP_WRITEABLE";
	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
		return "FILTER_NETWORK_CONNECTION";
	case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
		return "FILTER_HTTP_CONNECTION";
	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
		return "SERVER_NEW_CLIENT_INSTANTIATED";
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		return "FILTER_PROTOCOL_CONNECTION";
	case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS:
		return "OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS";
	case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS:
		return "OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS";
	case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
		return "OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION";
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		return "CLIENT_APPEND_HANDSHAKE_HEADER";
	case LWS_CALLBACK_CONFIRM_EXTENSION_OKAY:
		return "CONFIRM_EXTENSION_OKAY";
	case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
		return "CLIENT_CONFIRM_EXTENSION_SUPPORTED";
	case LWS_CALLBACK_PROTOCOL_INIT:
		return "PROTOCOL_INIT";
	case LWS_CALLBACK_PROTOCOL_DESTROY:
		return "PROTOCOL_DESTROY";
	case LWS_CALLBACK_WSI_CREATE: /* always protocol[0] */
		return "WSI_CREATE";
	case LWS_CALLBACK_WSI_DESTROY: /* always protocol[0] */
		return "WSI_DESTROY";
	case LWS_CALLBACK_GET_THREAD_ID:
		return "GET_THREAD_ID";

	/* external poll() management support */
	case LWS_CALLBACK_ADD_POLL_FD:
		return "ADD_POLL_FD";
	case LWS_CALLBACK_DEL_POLL_FD:
		return "DEL_POLL_FD";
	case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
		return "CHANGE_MODE_POLL_FD";
	case LWS_CALLBACK_LOCK_POLL:
		return "LOCK_POLL";
	case LWS_CALLBACK_UNLOCK_POLL:
		return "UNLOCK_POLL";

	case LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY:
		return "OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY";
	case LWS_CALLBACK_USER: /* user code can use any including / above */
		return "USER";
	default:
		return "UNKNOWN";
	}
}

static int ws_signup(void)
{
	struct libwebsocket *ws;
	gboolean use_ssl = FALSE;
	const char *address = "meshblu.octoblu.com";
	int sock, port = 80;

	ws = libwebsocket_client_connect(context, address, port,
					 use_ssl, "/ws/v2", address,
					 "origin", NULL, -1);

	/*
	 * FIXME: Improve socket tracking. If sock is being returned
	 * to sign-up caller, GIOChannel ref/unref mechanism must be
	 * used to automatically close the socket when the last
	 * reference is dropped.
	 */
	sock = libwebsocket_get_socket_fd(ws);

	g_hash_table_insert(wstable, GINT_TO_POINTER(sock), ws);

	return sock;
}

static int ws_signin(const char *token)
{
	return 0;
}

static void ws_signoff(int sock)
{
	if (!g_hash_table_remove(wstable, GINT_TO_POINTER(sock)))
		printf("Removing key: sock %d not found!\n", sock);
}

static struct proto_ops ops = {
	.signup = ws_signup,
	.signin = ws_signin,
	.signoff= ws_signoff,
};

static int callback_lws_default(struct libwebsocket_context * this,
			       struct libwebsocket *wsi,
			       enum libwebsocket_callback_reasons reason,
			       void *user, void *in, size_t len)
{

	printf("%s reason(%02X): %s\n", __PRETTY_FUNCTION__, reason,
						lws_reason2str(reason));

	switch (reason) {
	case LWS_CALLBACK_CLOSED:
		break;
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		break;
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		break;
	case LWS_CALLBACK_CLIENT_RECEIVE:
		break;
	case LWS_CALLBACK_CLIENT_WRITEABLE:
		break;
	/* TODO: Investigate other reasons that needs to be handled */
	default:
		break;
	}

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

	wstable = g_hash_table_new(g_direct_hash, g_direct_equal);

	return proto_ops_register(&ops);
}

void ws_unregister(void)
{
	g_hash_table_destroy(wstable);

	libwebsocket_context_destroy(context);

	proto_ops_unregister(&ops);
}
