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
#include <stdbool.h>
#include <string.h>
#include <libwebsockets.h>

#include <ell/ell.h>
#include <json-c/json.h>

#include <hal/linux_log.h>
#include "settings.h"
#include "proto.h"

#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define WS_RX_BUFFER_SIZE	4096

static const char *host_address;
static int host_port;
static struct lws_context *context;
struct l_hashmap *lws_list;

struct ws_session {
	bool got_response;	/* FIXME: find better approach */
	uint16_t size;		/* Amount TX or RX */
	unsigned char data[0];	/* WS_RX_BUFFER_SIZE */
};

static const char *lws_reason2string(enum lws_callback_reasons reason)
{
	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		return "LWS_CALLBACK_ESTABLISHED";
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		return "LWS_CALLBACK_CLIENT_CONNECTION_ERROR";
	case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
		return "LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH";
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		return "LWS_CALLBACK_CLIENT_ESTABLISHED";
	case LWS_CALLBACK_CLOSED:
		return "LWS_CALLBACK_CLOSED";
	case LWS_CALLBACK_CLOSED_HTTP:
		return "LWS_CALLBACK_CLOSED_HTTP";
	case LWS_CALLBACK_RECEIVE:
		return "LWS_CALLBACK_RECEIVE";
	case LWS_CALLBACK_RECEIVE_PONG:
		return "LWS_CALLBACK_RECEIVE_PONG";
	case LWS_CALLBACK_CLIENT_RECEIVE:
		return "LWS_CALLBACK_CLIENT_RECEIVE";
	case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
		return "LWS_CALLBACK_CLIENT_RECEIVE_PONG";
	case LWS_CALLBACK_CLIENT_WRITEABLE:
		return "LWS_CALLBACK_CLIENT_WRITEABLE";
	case LWS_CALLBACK_SERVER_WRITEABLE:
		return "LWS_CALLBACK_SERVER_WRITEABLE";
	case LWS_CALLBACK_HTTP:
		return "LWS_CALLBACK_HTTP";
	case LWS_CALLBACK_HTTP_BODY:
		return "LWS_CALLBACK_HTTP_BODY";
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		return "LWS_CALLBACK_HTTP_BODY_COMPLETION";
	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
		return "LWS_CALLBACK_HTTP_FILE_COMPLETION";
	case LWS_CALLBACK_HTTP_WRITEABLE:
		return "LWS_CALLBACK_HTTP_WRITEABLE";
	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
		return "LWS_CALLBACK_FILTER_NETWORK_CONNECTION";
	case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
		return "LWS_CALLBACK_FILTER_HTTP_CONNECTION";
	case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
		return "LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED";
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		return "LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION";
	case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS:
		return "LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS";
	case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS:
		return "LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS";
	case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
		return "LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION";
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		return "LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER";
	case LWS_CALLBACK_CONFIRM_EXTENSION_OKAY:
		return "LWS_CALLBACK_CONFIRM_EXTENSION_OKAY";
	case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
		return "LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED";
	case LWS_CALLBACK_PROTOCOL_INIT:
		return "LWS_CALLBACK_PROTOCOL_INIT";
	case LWS_CALLBACK_PROTOCOL_DESTROY:
		return "LWS_CALLBACK_PROTOCOL_DESTROY";
	case LWS_CALLBACK_WSI_CREATE:
		return "LWS_CALLBACK_WSI_CREATE";
	case LWS_CALLBACK_WSI_DESTROY:
		return "LWS_CALLBACK_WSI_DESTROY";
	case LWS_CALLBACK_GET_THREAD_ID:
		return "LWS_CALLBACK_GET_THREAD_ID";
	case LWS_CALLBACK_ADD_POLL_FD:
		return "LWS_CALLBACK_ADD_POLL_FD";
	case LWS_CALLBACK_DEL_POLL_FD:
		return "LWS_CALLBACK_DEL_POLL_FD";
	case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
		return "LWS_CALLBACK_CHANGE_MODE_POLL_FD";
	case LWS_CALLBACK_LOCK_POLL:
		return "LWS_CALLBACK_LOCK_POLL";
	case LWS_CALLBACK_UNLOCK_POLL:
		return "LWS_CALLBACK_UNLOCK_POLL";
	case LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY:
		return "LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY";
	case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
		return "LWS_CALLBACK_WS_PEER_INITIATED_CLOSE";
	case LWS_CALLBACK_WS_EXT_DEFAULTS:
		return "LWS_CALLBACK_WS_EXT_DEFAULTS:";
	case LWS_CALLBACK_CGI:
		return "LWS_CALLBACK_CGI";
	case LWS_CALLBACK_CGI_TERMINATED:
		return "LWS_CALLBACK_CGI_TERMINATED";
	case LWS_CALLBACK_CGI_STDIN_DATA:
		return "LWS_CALLBACK_CGI_STDIN_DATA";
	case LWS_CALLBACK_CGI_STDIN_COMPLETED:
		return "LWS_CALLBACK_CGI_STDIN_COMPLETED";
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		return "LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP";
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		return "LWS_CALLBACK_CLOSED_CLIENT_HTTP";
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		return "LWS_CALLBACK_RECEIVE_CLIENT_HTTP";
	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		return "LWS_CALLBACK_COMPLETED_CLIENT_HTTP";
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		return "LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ";
	case LWS_CALLBACK_HTTP_BIND_PROTOCOL:
		return "LWS_CALLBACK_HTTP_BIND_PROTOCOL";
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
	case LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION:
		return "LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION";
	case LWS_CALLBACK_RAW_RX:
		return "LWS_CALLBACK_RAW_RX";
	case LWS_CALLBACK_RAW_CLOSE:
		return "LWS_CALLBACK_RAW_CLOSE";
	case LWS_CALLBACK_RAW_WRITEABLE:
		return "LWS_CALLBACK_RAW_WRITEABLE:";
	case LWS_CALLBACK_RAW_ADOPT:
		return "LWS_CALLBACK_RAW_ADOPT";
	case LWS_CALLBACK_RAW_ADOPT_FILE:
		return "LWS_CALLBACK_RAW_ADOPT_FILE";
	case LWS_CALLBACK_RAW_RX_FILE:
		return "LWS_CALLBACK_RAW_RX_FILE";
	case LWS_CALLBACK_RAW_WRITEABLE_FILE:
		return "LWS_CALLBACK_RAW_WRITEABLE_FILE";
	case LWS_CALLBACK_RAW_CLOSE_FILE:
		return "LWS_CALLBACK_RAW_CLOSE_FILE";
	case LWS_CALLBACK_SSL_INFO:
		return "LWS_CALLBACK_SSL_INFO";
	case LWS_CALLBACK_CHILD_WRITE_VIA_PARENT:
		return "LWS_CALLBACK_CHILD_WRITE_VIA_PARENT";
	case LWS_CALLBACK_CHILD_CLOSING:
		return "LWS_CALLBACK_CHILD_CLOSING";
	case LWS_CALLBACK_CGI_PROCESS_ATTACH:
		return "LWS_CALLBACK_CGI_PROCESS_ATTACH";
	case LWS_CALLBACK_USER:
		return "LWS_CALLBACK_USER";
	}

	return NULL;
}

static int wait_for_response(struct lws *ws)
{
	struct ws_session *session;

	lws_callback_on_writable(ws);

	session = lws_wsi_user(ws);
	if (session)
		session->got_response = false;

	while (session == NULL) {
		/* User data (session) is NULL while not connected */
		lws_service(context, 0);
		session = lws_wsi_user(ws);

		/* FIXME: add timeout */
	}

	while (!session->got_response)
		lws_service(context, 0);

	return 0;
}

static void ws_close(int sock)
{
}

static int ws_mknode(int sock, const char *device_json, json_raw_t *json)
{
	json_object *jobj, *jarray;
	const char *jobjstring;
	struct lws *ws;
	struct ws_session *session;
	int ret;

	ws = l_hashmap_lookup(lws_list, L_INT_TO_PTR(sock));
	if (!ws)
		return -EINVAL;

	session = lws_wsi_user(ws);
	if (!session)
		return -EINVAL;

	jobj = json_tokener_parse(device_json);
	if (jobj == NULL)
		return -EINVAL;

	jarray = json_object_new_array();
	json_object_array_add(jarray, json_object_new_string("register"));
	json_object_array_add(jarray, jobj);
	jobjstring = json_object_to_json_string(jarray);

	session->size = snprintf((char *) &(session->data[LWS_PRE]),
				WS_RX_BUFFER_SIZE, "%s", jobjstring);

	ret = wait_for_response(ws);

	json_object_put(jarray);

	/* TODO: Avoid another allocation */
	json->data = l_strndup((const char *) session->data, session->size);
	json->size = session->size;

	return ret;
}

static int ws_device(int sock, const char *uuid,
		     const char *token, json_raw_t *json)
{
	return 0;
}

static int ws_signin(int sock, const char *uuid,
		     const char *token, json_raw_t *json)
{
	json_object *jobj, *jarray;
	const char *jobjstring;
	struct ws_session *session;
	struct lws *ws;
	int ret;

	ws = l_hashmap_lookup(lws_list, L_INT_TO_PTR(sock));
	if (!ws)
		return -EINVAL;

	session = lws_wsi_user(ws);
	if (!session)
		return -EINVAL;

	/* Identifying a device is by a UUID and a Token */
	jobj = json_object_new_object();
	jarray = json_object_new_array();
	if (!jobj || !jarray) {
		hal_log_error("JSON: no memory");
		return -ENOMEM;
	}

	json_object_object_add(jobj, "uuid", json_object_new_string(uuid));
	json_object_object_add(jobj, "token", json_object_new_string(token));

	json_object_array_add(jarray, json_object_new_string("identity"));
	json_object_array_add(jarray, jobj);

	jobjstring = json_object_to_json_string(jarray);
	hal_log_info("WS TX JSON %s", jobjstring);

	session->size = snprintf((char *) &(session->data[LWS_PRE]),
				WS_RX_BUFFER_SIZE, "%s", jobjstring);
	ret = wait_for_response(ws);
	json_object_put(jarray);
	if (ret != 0)
		goto done;

	/* TODO: For identity response verify if status is 200 */

	/* Retrieve a device from the Meshblu device registry by it's uuid */
	jobj = json_object_new_object();
	jarray = json_object_new_array();
	if (!jobj || !jarray) {
		hal_log_error("JSON: no memory");
		return -ENOMEM;
	}

	json_object_object_add(jobj, "uuid", json_object_new_string(uuid));
	json_object_array_add(jarray, json_object_new_string("device"));
	json_object_array_add(jarray, jobj);

	jobjstring = json_object_to_json_string(jarray);
	hal_log_info("WS TX JSON %s", jobjstring);

	session->size = snprintf((char *) &(session->data[LWS_PRE]),
				WS_RX_BUFFER_SIZE, "%s", jobjstring);

	ret = wait_for_response(ws);
	json_object_put(jarray);
	if (ret != 0)
		goto done;

	/* TODO: Avoid another allocation */
	json->data = l_strndup((const char *) session->data, session->size);
	json->size = session->size;

done:
	return ret;
}

static int ws_rmnode(int sock, const char *uuid,
		     const char *token, json_raw_t *json)
{
	return 0;
}

static int ws_update(int sock, const char *uuid, const char *token,
		     const char *jreq, json_raw_t *json)
{
	return 0;
}

static int ws_data(int sock, const char *uuid, const char *token,
		   const char *jreq, json_raw_t *json)
{
	return 0;
}

static void parse(struct ws_session *session, const char *in, size_t len)
{
	char op[256];
	int index = 0;

	/* TODO: Avoid buffer overflow for 'op' */
	if (sscanf(in, "%*[^\"]\"%[^\"]\",%n]", op, &index) != 1)
		return;

	session->size = MIN(WS_RX_BUFFER_SIZE, len - index - 1); /* skip ']'*/
	memset(session->data, 0, WS_RX_BUFFER_SIZE);
	strncpy((char *) session->data, &in[index], session->size);
}

static int callback_lws_ws(struct lws *wsi,
			     enum lws_callback_reasons reason,
			     void *user_data, void *in, size_t len)

{
	struct ws_session *session = user_data;
	int ret;

	hal_log_info("<<< %s >>>", lws_reason2string(reason));
	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		session->got_response = true;
		break;
	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (session->size == 0)
			break;

		ret = lws_write(wsi, &(session->data[LWS_PRE]),
				session->size, LWS_WRITE_TEXT);
		lws_rx_flow_control(wsi, 1);
		hal_log_info("lws_write(): %d", ret);
		session->size = 0;
		break;
	case LWS_CALLBACK_CLIENT_RECEIVE:
		session->got_response = true;
		parse(session, in, len);
		break;
	default:
		break;
	}

	return 0;
}

static struct lws_protocols protocols[] = {
	{
		"ws",
		callback_lws_ws,
		/* user per_session_data_size */
		WS_RX_BUFFER_SIZE + sizeof(struct ws_session),
		/* rx_buffer_size */
		WS_RX_BUFFER_SIZE,
		/* id */
		0,
		/* user */
		NULL,
		/* 0 indicates restrict send() size to .rx_buffer_size */
		0,
	},
	{
		NULL, NULL, 0, 0, 0, NULL, 0			/* end of list */
	}
};

static int ws_connect(void)
{
	struct lws_client_connect_info info;
	struct lws *ws;
	int sock;

	memset(&info, 0, sizeof(info));

	info.context = context;
	info.ssl_connection = 0;
	info.address = host_address;
	info.port = host_port;
	info.path = "/ws/v2";
	info.host = host_address;
	info.ietf_version_or_minus_one = -1;
	info.protocol = protocols[0].name;
	info.userdata = NULL;

	ws = lws_client_connect_via_info(&info);

	sock = lws_get_socket_fd((struct lws *) ws);
	l_hashmap_insert(lws_list, L_INT_TO_PTR(sock), ws);

	/* TODO: Create thread for each connected client */
	wait_for_response(ws);

	return sock;
}

static int ws_probe(const char *host, unsigned int port)
{
	struct lws_context_creation_info i;

	host_address = host;
	host_port = port;

	memset(&i, 0, sizeof(i));
	i.port = CONTEXT_PORT_NO_LISTEN;
	i.gid = -1;
	i.uid = -1;
	i.protocols = protocols;

	context = lws_create_context(&i);
	lws_list = l_hashmap_new();

	return 0;
}

static void ws_remove(void)
{
	/* FIXME: */
	l_hashmap_destroy(lws_list, NULL);
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
	.rmnode = ws_rmnode,
	.schema = ws_update,
	.data = ws_data,
	.fetch = ws_device,
	.async = NULL,
	.async_stop = NULL,
	.setdata = ws_update
};
