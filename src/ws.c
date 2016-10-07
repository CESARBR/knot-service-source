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
#include <errno.h>

#include <libwebsockets.h>

#include <glib.h>

#include <json-c/json.h>

#include "log.h"
#include "proto.h"

#define MAX_PAYLOAD		4096
#define SERVICE_TIMEOUT		100

struct lws_context *context;
static GHashTable *wstable;
gboolean got_response = FALSE;
gboolean connection_error = FALSE;
gboolean connected = FALSE;
static struct lws *ws;

struct per_session_data_ws {
	struct lws *ws;
	/*
	 * This buffer MUST have LWS_PRE bytes valid BEFORE the pointer. this
	 * is defined in the lws documentation,
	 */
	unsigned char buffer[LWS_PRE + MAX_PAYLOAD];
	unsigned int len;
	char *json;
};

struct per_session_data_ws *psd;

static gboolean timeout_ws(gpointer user_data)
{
	lws_service(context, 0);

	return TRUE;
}
/*
 * Return '0' if device has been created or a negative value
 * mapped to generic Linux -errno codes.
 */
static int ret2errno(const char *json_str, const char *expected_result)
{
	json_object *jobj, *jobjentry;
	int err = -EIO;

	jobj = json_tokener_parse(json_str);
	if (jobj == NULL)
		goto done;

	if (json_object_get_type(jobj) == json_type_array) {
		jobjentry = json_object_array_get_idx(jobj, 0);
		if (jobjentry == NULL)
			goto done;
	}
	if (!strcmp(json_object_get_string(jobjentry), expected_result))
		err = 0;

done:
	json_object_put(jobj);

	return err;
}
static int handle_response(json_raw_t *json)
{
	size_t realsize;
	json_object *jobj, *jres;
	const char *jobjstringres;

	jres = json_tokener_parse(psd->json);
	if (jres == NULL)
		return -EINVAL;

	jobj = json_object_array_get_idx(jres, 1);
	jobjstringres = json_object_to_json_string(jobj);

	realsize = strlen(jobjstringres) + 1;

	json->data = (char *) realloc(json->data, json->size + realsize);
	if (json->data == NULL) {
		LOG_ERROR("Not enough memory\n");
		return -ENOMEM;
	}

	memcpy(json->data + json->size, jobjstringres, realsize);
	json->size += realsize;
	json->data[json->size - 1] = 0;
	json_object_put(jres);

	return 0;
}

static const char *lws_reason2str(enum lws_callback_reasons reason)
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
	case LWS_CALLBACK_WSI_CREATE:
		return "WSI_CREATE";
	case LWS_CALLBACK_WSI_DESTROY:
		return "WSI_DESTROY";
	case LWS_CALLBACK_GET_THREAD_ID:
		return "GET_THREAD_ID";

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
	case LWS_CALLBACK_USER:
		return "USER";

	case LWS_CALLBACK_RECEIVE_PONG:
		return "RECEIVE PONG";
	case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
		return "PEER INITIATED CLOSE";
	case LWS_CALLBACK_WS_EXT_DEFAULTS:
		return "EXT DEFAULTS";
	case LWS_CALLBACK_CGI:
		return "CGI";
	case LWS_CALLBACK_CGI_TERMINATED:
		return "CGI TERMINATED";
	case LWS_CALLBACK_CGI_STDIN_DATA:
		return "CGI STDIN DATA";
	case LWS_CALLBACK_CGI_STDIN_COMPLETED:
		return "CGI STDIN COMPLETED";
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		return "ESTABLISHED CLIENT HTTP";
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		return "CLOSED CLIENT HTTP";
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		return "RECEIVE CLIENT HTTP";
	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		return "COMPLETED CLIENT HTTP";
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		return "RECEIVE CLIENT HTTP READ";

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		return "LWS_CALLBACK_HTTP_DROP_PROTOCOL";
	case LWS_CALLBACK_CHECK_ACCESS_RIGHTS:
		return "LWS_CALLBACK_CHECK_ACCESS_RIGHTS";
	case LWS_CALLBACK_PROCESS_HTML:
		return "LWS_CALLBACK_PROCESS_HTML";
	case LWS_CALLBACK_ADD_HEADERS:
		return "LWS_CALLBACK_ADD_HEADERS";
	case LWS_CALLBACK_SESSION_INFO:
		return "LWS_CALLBACK_SESSION_INFO";
	case LWS_CALLBACK_GS_EVENT:
		return "LWS_CALLBACK_GS_EVENT";
	case LWS_CALLBACK_HTTP_PMO:
		return "LWS_CALLBACK_HTTP_PMO";
	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		return "LWS_CALLBACK_CLIENT_HTTP_WRITEABLE";
	case LWS_CALLBACK_HTTP_BIND_PROTOCOL:
		return "LWS_CALLBACK_HTTP_BIND_PROTOCOL";

	default:
		return "UNKNOWN";
	}
}

static void ws_close(int sock)
{
	if (!g_hash_table_remove(wstable, GINT_TO_POINTER(sock)))
		LOG_ERROR("Removing key: sock %d not found!\n", sock);
}

static int ws_mknode(int sock, const char *owner_uuid,
					json_raw_t *json)
{
	int err;
	json_object *jobj, *jarray;
	const char *jobjstring;
	const char *expected_result = "registered";

	jobj = json_tokener_parse(owner_uuid);
	if (jobj == NULL)
		return -EINVAL;

	jarray = json_object_new_array();
	json_object_array_add(jarray, json_object_new_string("register"));
	json_object_array_add(jarray, jobj);
	jobjstring = json_object_to_json_string(jarray);

	psd = g_new0(struct per_session_data_ws, 1);
	psd->ws = g_hash_table_lookup(wstable, GINT_TO_POINTER(sock));

	if (psd->ws == NULL) {
		err = -EBADF;
		LOG_ERROR("Not found\n");
		goto done;
	}
	psd->len = sprintf((char *)&psd->buffer[LWS_PRE], "%s", jobjstring);
	lws_callback_on_writable(psd->ws);

	/* Keep serving context until server responds or an error occurs */
	while (!got_response || connection_error)
		lws_service(context, SERVICE_TIMEOUT);

	err = ret2errno(psd->json, expected_result);

	/*
	 * The expected JSON format is:
	 * ["registered", {"uuid":"VALUE",...,"token":"VALUE"}]
	 */
	if (err < 0)
		goto done;

	err = handle_response(json);

done:
	connection_error = FALSE;
	got_response = FALSE;

	json_object_put(jarray);
	g_free(psd);

	return err;
}

static int ws_signin(int sock, const char *uuid, const char *token,
							json_raw_t *json)
{
	int err;
	const char *jobjstring;
	json_object *jobj, *jarray;
	const char *expected_result = "ready";
	const char *expected_result_schema = "device";

	jobj = json_object_new_object();
	jarray = json_object_new_array();

	if (!jobj || !jarray) {
		LOG_ERROR("JSON: no memory\n");
		return -ENOMEM;
	}

	json_object_object_add(jobj, "uuid", json_object_new_string(uuid));
	json_object_object_add(jobj, "token", json_object_new_string(token));

	json_object_array_add(jarray,
	json_object_new_string("identity"));
	json_object_array_add(jarray, jobj);

	jobjstring = json_object_to_json_string(jarray);

	LOG_INFO("TX JSON %s\n", jobjstring);

	psd = g_new0(struct per_session_data_ws, 1);
	psd->ws = g_hash_table_lookup(wstable, GINT_TO_POINTER(sock));

	if (psd->ws == NULL) {
		LOG_ERROR("Not found\n");
		err = -EBADF;
		goto done;
	}

	psd->len = sprintf((char *)&psd->buffer[LWS_PRE], "%s", jobjstring);
	lws_callback_on_writable(psd->ws);

	/* Keep serving context until server responds or an error occurs */
	while (!got_response || connection_error)
		lws_service(context, SERVICE_TIMEOUT);

	if (ret2errno((char *)psd->json, expected_result) < 0) {
		err = -EIO;
		goto done;
	}

	got_response = FALSE;
	connection_error = FALSE;

	/*
	 * Unlike HTTP signin WS does not return the schema, so we need to
	 * make another request to get it.
	 */

	/* Here we just replace the operation index 0 and the token */
	json_object_array_put_idx(jarray, 0, json_object_new_string("device"));
	json_object_object_del(json_object_array_get_idx(jarray, 1), "token");

	jobjstring = json_object_to_json_string(jarray);

	g_free(psd);

	psd = g_new0(struct per_session_data_ws, 1);
	psd->ws = g_hash_table_lookup(wstable, GINT_TO_POINTER(sock));

	if (psd->ws == NULL) {
		LOG_ERROR("Not found\n");
		err = -EBADF;
		goto done;
	}


	psd->len = sprintf((char *)&psd->buffer[LWS_PRE], "%s", jobjstring);
	lws_callback_on_writable(psd->ws);

	while (!got_response || connection_error)
		lws_service(context, SERVICE_TIMEOUT);

	err = ret2errno(psd->json, expected_result_schema);
	/*
	 * The expected result:
	 * ["devices",{"uuid": ...
	 *		"schema" : [
	 *			{"sensor_id": x, "value_type": w,
	 *				"unit": z "type_id": y, "name": "foo"}]
	 *		}]
	 */
	if (err < 0)
		goto done;

	err = handle_response(json);
done:
	got_response = FALSE;
	connection_error = FALSE;

	g_free(psd);
	json_object_put(jarray);

	return err;
}

static int callback_lws_http(struct lws *wsi,
					enum lws_callback_reasons reason,
					void *user, void *in, size_t len)

{
	LOG_INFO("reason(%02X): %s\n", reason, lws_reason2str(reason));

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		LOG_INFO("LWS_CALLBACK_ESTABLISHED\n");
		break;
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		LOG_INFO("LWS_CALLBACK_CLIENT_CONNECTION_ERROR\n");
		connection_error = TRUE;
		break;
	case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
		break;
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		LOG_INFO("LWS_CALLBACK_CLIENT_ESTABLISHED\n");
		connected = TRUE;
		break;
	case LWS_CALLBACK_CLOSED:
		LOG_INFO("LWS_CALLBACK_CLOSED\n");
		connection_error = TRUE;
		break;
	case LWS_CALLBACK_CLOSED_HTTP:
		break;
	case LWS_CALLBACK_RECEIVE:
		break;
	case LWS_CALLBACK_CLIENT_RECEIVE:
		{
		((char *)in)[len] = '\0';
		psd->json = (char *) in;
		got_response = TRUE;
		LOG_INFO("JSON RX %d '%s'\n", (int)len, (char *)psd->json);
		/* Flow control will be enabled again when client writes data */
		lws_rx_flow_control(wsi, 0);
		}
		break;
	case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
		break;
	case LWS_CALLBACK_CLIENT_WRITEABLE:
		{
		int l;

		if (psd->ws == wsi)
			LOG_INFO("Client wsi %p writable\n", wsi);

		l = lws_write(psd->ws, &psd->buffer[LWS_PRE], psd->len,
								LWS_WRITE_TEXT);
		LOG_INFO("Wrote (%d) bytes\n", l);

		/* Enable RX when after message is successfully sent */
		if (l < 0) {
			connection_error = TRUE;
			return -1;
		}
			lws_rx_flow_control(wsi, 1);
		}
		break;
	case LWS_CALLBACK_SERVER_WRITEABLE:
	case LWS_CALLBACK_HTTP:
	case LWS_CALLBACK_HTTP_BODY:
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
	case LWS_CALLBACK_HTTP_WRITEABLE:
	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
	case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
	case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS:
	case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS:
	case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
	case LWS_CALLBACK_CONFIRM_EXTENSION_OKAY:
	case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
	case LWS_CALLBACK_PROTOCOL_INIT:
	case LWS_CALLBACK_PROTOCOL_DESTROY:
	case LWS_CALLBACK_WSI_CREATE: // always protocol[0]
	case LWS_CALLBACK_WSI_DESTROY: // always protocol[0]
	case LWS_CALLBACK_GET_THREAD_ID:
	case LWS_CALLBACK_ADD_POLL_FD:
	case LWS_CALLBACK_DEL_POLL_FD:
	case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
	case LWS_CALLBACK_LOCK_POLL:
	case LWS_CALLBACK_UNLOCK_POLL:
	case LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY:
	case LWS_CALLBACK_USER:
	case LWS_CALLBACK_RECEIVE_PONG:
	case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
	case LWS_CALLBACK_WS_EXT_DEFAULTS:
	case LWS_CALLBACK_CGI:
	case LWS_CALLBACK_CGI_TERMINATED:
	case LWS_CALLBACK_CGI_STDIN_DATA:
	case LWS_CALLBACK_CGI_STDIN_COMPLETED:
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
	case LWS_CALLBACK_CHECK_ACCESS_RIGHTS:
	case LWS_CALLBACK_PROCESS_HTML:
	case LWS_CALLBACK_ADD_HEADERS:
	case LWS_CALLBACK_SESSION_INFO:
	case LWS_CALLBACK_GS_EVENT:
	case LWS_CALLBACK_HTTP_PMO:
	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
	case LWS_CALLBACK_HTTP_BIND_PROTOCOL:
		break;
	default:
		break;
	}

	return 0;
}

static struct lws_protocols protocols[] = {
	{
		"http-only",
		callback_lws_http,
		0, 65536, 0, NULL
	},
	{
		NULL, NULL, 0, 0, 0, NULL /* end of list */
	}
};

static int ws_connect(void)
{
	struct lws_client_connect_info info;
	static char ads_port[300];

	gboolean use_ssl = FALSE; /* wss */
	// const char *address = "meshblu.octoblu.com";
	const char *address = "localhost";
	// int sock, port = 80;
	int sock, port = 8000;

	memset(&info, 0, sizeof(info));

	snprintf(ads_port, sizeof(ads_port), "%s:%u", address, port);

	LOG_INFO("Connecting to %s...\n", ads_port);

	info.context = context;
	info.address = address;
	info.port = port;
	info.ssl_connection = use_ssl;
	info.path = "/ws/v2";
	info.host = info.address;
	info.origin = info.address;
	info.ietf_version_or_minus_one = -1;
	info.protocol = protocols[0].name;

	ws = lws_client_connect_via_info(&info);

	if (ws == NULL) {
		int err = errno;
		LOG_ERROR("libwebsocket_client_connect(): %s(%d)\n",
							strerror(err), err);
		return -err;
	}

	while (!connected || connection_error)
		lws_service(context, SERVICE_TIMEOUT);

	sock = lws_get_socket_fd(ws);
	g_hash_table_insert(wstable, GINT_TO_POINTER(sock), ws);

	connected = FALSE;

	/* FIXME: Investigate alternatives for libwebsocket_service() */
	g_timeout_add_seconds(1, timeout_ws, NULL);

	return sock;
}

static int ws_probe(const char *host, unsigned int port)
{
	struct lws_context_creation_info info;

	memset(&info, 0, sizeof info);

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.gid = -1;
	info.uid = -1;
	info.protocols = protocols;

	context = lws_create_context(&info);

	wstable = g_hash_table_new(g_direct_hash, g_direct_equal);

	return 0;
}

static void ws_remove(void)
{
	g_hash_table_destroy(wstable);
	lws_context_destroy(context);
}

struct proto_ops proto_ws = {
	.name = "ws",	/* websockets */
	.probe = ws_probe,
	.remove = ws_remove,
	.connect = ws_connect,
	.close = ws_close,
	.mknode = ws_mknode,
	.signin = ws_signin,
};
