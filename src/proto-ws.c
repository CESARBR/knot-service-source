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

#include <knot/knot_types.h>
#include <knot/knot_protocol.h>
#include <hal/linux_log.h>
#include "settings.h"
#include "proto.h"

#define MIN(a,b) ((a) < (b) ? (a) : (b))

/* WS RX Buffer: Critical to mydevices */
#define WS_RX_BUFFER_SIZE	32768

static const char *host_address;
static int host_port;
static struct lws_context *context;
struct l_hashmap *lws_list;
struct l_timeout *poll_timeout;

struct ws_session {
	bool got_response;	/* FIXME: find better approach */
	bool force_close;
	uint16_t size;		/* Amount TX or RX */
	proto_property_changed_func_t prop_cb; /* Subscribe callback */
	void *user_data;
	unsigned char rsp[32];  /* Command response */
	unsigned char data[0];	/* WS_RX_BUFFER_SIZE */
};

/* Used to remove an entry from lws_list */
static bool lws_list_cmp(const void *key, void *value, void *user_data)
{
	return (value == user_data ? true : false);
}

static int ws_send_msg(struct lws *ws, bool wait_reply)
{
	struct ws_session *session;
	struct lws *lws;
	int sock;

	sock = lws_get_socket_fd(ws);

	lws_callback_on_writable(ws);

	session = lws_wsi_user(ws);
	if (session)
		session->got_response = false;

	/*
	 * User data (session) is NULL while not connected.
	 * User data(session) is NOT valid while WSI is destroyed.
	 */
	lws = l_hashmap_lookup(lws_list, L_INT_TO_PTR(sock));
	while (lws) {

		/* lws engine: process events */
		lws_service(context, 0);

		/* Might be destroyed: connection error */
		lws = l_hashmap_lookup(lws_list, L_INT_TO_PTR(sock));
		if (lws == NULL)
			break;

		session = lws_wsi_user(lws);
		/* Still connecting? */
		if (session == NULL)
			continue;

		if (!wait_reply)
			break;

		if (session->got_response)
			break;
	}

	return (lws ? 0 : -EIO);
}

static void poll_service(struct l_timeout *timeout, void *user_data)
{
	/* When subscribed it is necessary to poll service for data */
	lws_service(context, 0);
	l_timeout_modify(timeout, 1);
}

static void parse_config(struct ws_session *session,
			 const char *in, size_t len)
{
	json_object *jobj;
	json_object *jobjkey;

	jobj = json_tokener_parse(in);
	if (!jobj) {
		hal_log_error("JSON: config parsing error");
		return;
	}

	if (json_object_object_get_ex(jobj, "schema", &jobjkey)) {
		session->prop_cb("schema",
				 json_object_to_json_string(jobjkey),
				 session->user_data);
	}

	if (json_object_object_get_ex(jobj, "config", &jobjkey)) {
		session->prop_cb("config",
				 json_object_to_json_string(jobjkey),
				 session->user_data);
	}

	if (json_object_object_get_ex(jobj, "get_data", &jobjkey)) {
		session->prop_cb("get_data",
				 json_object_to_json_string(jobjkey),
				 session->user_data);
	}

	if (json_object_object_get_ex(jobj, "set_data", &jobjkey)) {
		session->prop_cb("set_data",
				 json_object_to_json_string(jobjkey),
				 session->user_data);
	}

	if (json_object_object_get_ex(jobj, "online", &jobjkey)) {
		session->prop_cb("online",
				 json_object_to_json_string(jobjkey),
				 session->user_data);
	}

	json_object_put(jobj);
}

static void parse(struct ws_session *session, const char *in, size_t len)
{
	int index = 0;

	if (sscanf(in, "%*[^\"]\"%32[^\"]\",%n]", session->rsp, &index) != 1)
		return;

	session->size = MIN(WS_RX_BUFFER_SIZE, len - index - 1); /* skip ']'*/

		memset(session->data, 0, WS_RX_BUFFER_SIZE);
		strncpy((char *) session->data, &in[index], session->size);
	if (strcmp("config", (const char *) session->rsp) != 0)
		return;
	else // If receive config, wait for the following response
		session->got_response = false;

	hal_log_info("session:%p CMD:<%s> RX:<%s>", session, session->rsp, session->data);

	/* Skip if subscribe is not active */
	if (!session->prop_cb)
		return;

	parse_config(session, in + index, session->size);
}

static void ws_close(int sock)
{
	struct ws_session *session;
	struct lws *ws = l_hashmap_remove(lws_list, L_INT_TO_PTR(sock));

	if (!ws)
		return;
	session = lws_wsi_user(ws);
	session->force_close = true;
	lws_callback_on_writable(ws);
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

	ret = ws_send_msg(ws, true);

	json_object_put(jarray);

	if (strcmp("registered", (const char *) session->rsp) != 0)
		return -EACCES;

	/* TODO: Avoid another allocation */
	json->data = l_strndup((const char *) session->data, session->size);
	json->size = session->size;

	return ret;
}

/* TODO: remove uuid & token */
static int ws_fetch(int sock, const char *uuid,
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

	/* Retrieve a device from the Meshblu device registry by it's uuid */
	jobj = json_object_new_object();
	jarray = json_object_new_array();
	if (!jobj || !jarray) {
		hal_log_error("JSON: no memory");
		return -ENOMEM;
	}

	json_object_array_add(jarray, json_object_new_string("mydevices"));
	json_object_array_add(jarray, jobj);

	jobjstring = json_object_to_json_string(jarray);

	session->size = snprintf((char *) &(session->data[LWS_PRE]),
				WS_RX_BUFFER_SIZE, "%s", jobjstring);

	ret = ws_send_msg(ws, true);
	json_object_put(jarray);
	if (ret != 0)
		goto done;

	if (strcmp("mydevices", (const char *) session->rsp) != 0)
		return -EACCES;

	/* TODO: Avoid another allocation */
	json->data = l_strndup((const char *) session->data, session->size);
	json->size = session->size;

done:
	return ret;
}

static int ws_signin(int sock, const char *uuid, const char *token,
		     json_raw_t *json, proto_property_changed_func_t prop_cb,
		     void *user_data)
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

	session->size = snprintf((char *) &(session->data[LWS_PRE]),
				WS_RX_BUFFER_SIZE, "%s", jobjstring);
	ret = ws_send_msg(ws, true);
	json_object_put(jarray);
	if (ret != 0)
		goto done;

	if (strcmp("ready", (const char *) session->rsp) != 0)
		return -EACCES;

	/* Subscribe to monitor for changes */
	if (!prop_cb)
		return ret;

	session->prop_cb = prop_cb;
	session->user_data = user_data;

	/* Fetch initial settings */
	jobj = json_object_new_object();
	jarray = json_object_new_array();
	if (!jobj || !jarray) {
		hal_log_error("JSON: no memory");
		return -ENOMEM;
	}

	/* Retrieve a device from the Meshblu device registry by it's uuid */
	json_object_object_add(jobj, "uuid", json_object_new_string(uuid));
	json_object_array_add(jarray, json_object_new_string("device"));
	json_object_array_add(jarray, jobj);

	jobjstring = json_object_to_json_string(jarray);

	session->size = snprintf((char *) &(session->data[LWS_PRE]),
				WS_RX_BUFFER_SIZE, "%s", jobjstring);

	/* Wait for 'device' */
	ret = ws_send_msg(ws, true);
	json_object_put(jarray);
	if (ret != 0)
		goto done;

	if (strcmp("device", (const char *) session->rsp) != 0)
		return -EACCES;

	/* TODO: Avoid another allocation */
	json->data = l_strndup((const char *) session->data, session->size);
	json->size = session->size;

	/* Parsing 'device': same format as 'config' */
	parse_config(session, (const char *) session->data, session->size);

	/* Subscribe to receive next changes */
	jobj = json_object_new_object();
	jarray = json_object_new_array();
	if (!jobj || !jarray) {
		hal_log_error("JSON: no memory");
		return -ENOMEM;
	}

	json_object_object_add(jobj, "uuid", json_object_new_string(uuid));
	json_object_array_add(jarray, json_object_new_string("subscribe"));
	json_object_array_add(jarray, jobj);

	jobjstring = json_object_to_json_string(jarray);

	session->size = snprintf((char *) &(session->data[LWS_PRE]),
				WS_RX_BUFFER_SIZE, "%s", jobjstring);

	/* No response */
	ret = ws_send_msg(ws, false);
	json_object_put(jarray);
	if (!poll_timeout)
		poll_timeout = l_timeout_create(1, poll_service, NULL, NULL);
done:
	return ret;
}

static int ws_rmnode(int sock, const char *uuid,
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

	jobj = json_object_new_object();
	jarray = json_object_new_array();
	if (!jobj || !jarray) {
		hal_log_error("JSON: no memory");
		return -ENOMEM;
	}

	json_object_object_add(jobj, "uuid", json_object_new_string(uuid));
	json_object_array_add(jarray, json_object_new_string("unregister"));
	json_object_array_add(jarray, jobj);

	jobjstring = json_object_to_json_string(jarray);
	session->size = snprintf((char *) &(session->data[LWS_PRE]),
				WS_RX_BUFFER_SIZE, "%s", jobjstring);

	ret = ws_send_msg(ws, true);
	json_object_put(jarray);
	if (ret != 0)
		goto done;

	if (strcmp("unregistered", (const char *) session->rsp) != 0)
		return -EACCES;

	/* TODO: Avoid another allocation */
	json->data = l_strndup((const char *) session->data, session->size);
	json->size = session->size;

done:
	return ret;
}

static int ws_update(int sock, const char *uuid,
		     const char *token, const char *jreq)
{
	json_object *jobj_uuid;
	json_object *jobj_schema;
	json_object *jobj_set;
	json_object *jarray_out;
	json_object *jarray_in;
	const char *jobjstring;
	struct ws_session *session;
	struct lws *ws;
	int ret = -ENOMEM;

	ws = l_hashmap_lookup(lws_list, L_INT_TO_PTR(sock));
	if (!ws)
		return -EINVAL;

	session = lws_wsi_user(ws);
	if (!session)
		return -EINVAL;

	/*
	 * Based on Meshblu WebSockets API.
	 * https://meshblu-websocket.readme.io/docs/update
	 */
	jarray_out = json_object_new_array();
	if (jarray_out == NULL)
		goto fail;

	json_object_array_add(jarray_out, json_object_new_string("update"));

	jarray_in = json_object_new_array();
	if (jarray_in == NULL)
		goto fail;

	json_object_array_add(jarray_out, jarray_in);

	jobj_uuid = json_object_new_object();
	if (jobj_uuid == NULL)
		goto fail;

	/* Add UUID to internal array */
	json_object_array_add(jarray_in, jobj_uuid);

	jobj_set = json_object_new_object();
	if (jobj_set == NULL)
		goto fail;

	/* Add "$set" to internal array */
	json_object_array_add(jarray_in, jobj_set);

	jobj_schema = json_tokener_parse(jreq);
	if (jobj_schema == NULL) {
		ret = -EINVAL;
		goto fail;
	}

	json_object_object_add(jobj_uuid, "uuid", json_object_new_string(uuid));
	json_object_object_add(jobj_set, "$set", jobj_schema);

	jobjstring = json_object_to_json_string(jarray_out);

	session->size = snprintf((char *) &(session->data[LWS_PRE]),
				WS_RX_BUFFER_SIZE, "%s", jobjstring);

	ret = ws_send_msg(ws, true);
	if (ret != 0)
		goto fail;

	if (strcmp("error", (const char *) session->rsp) == 0)
                return -EACCES;

fail:
	hal_log_error("WS(update): %s(%d)", strerror(-ret), -ret);
	json_object_put(jarray_out);

	return ret;
}

static int ws_data(int sock, const char *uuid,
		   const char *token, const char *jreq)
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

	jobj = json_tokener_parse(jreq);
	jarray = json_object_new_array();
	if (!jobj || !jarray) {
		hal_log_error("JSON: no memory");
		return -ENOMEM;
	}

	json_object_object_add(jobj, "uuid", json_object_new_string(uuid));
	json_object_object_add(jobj, "token", json_object_new_string(token));
	json_object_array_add(jarray, json_object_new_string("data"));
	json_object_array_add(jarray, jobj);

	jobjstring = json_object_to_json_string(jarray);

	session->size = snprintf((char *) &(session->data[LWS_PRE]),
				WS_RX_BUFFER_SIZE, "%s", jobjstring);

	ret = ws_send_msg(ws, false);
	json_object_put(jarray);
	if (strcmp("data", (const char *) session->rsp) == 0)
                return -EACCES;

	return ret;
}

static int callback_lws_ws(struct lws *wsi,
			     enum lws_callback_reasons reason,
			     void *user_data, void *in, size_t len)

{
	struct ws_session *session = user_data;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		session->got_response = true;
		break;
	case LWS_CALLBACK_CLIENT_WRITEABLE:
		if (session->force_close)
			return -1;
		if (session->size == 0)
			break;

		lws_write(wsi, &(session->data[LWS_PRE]),
				session->size, LWS_WRITE_TEXT);
		lws_rx_flow_control(wsi, 1);
		session->size = 0;
		break;
	case LWS_CALLBACK_CLIENT_RECEIVE:
		session->got_response = true;
		parse(session, in, len);
		break;
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		hal_log_info("WSI: %p Host may be invalid or unreachable", wsi);
		break;
	case LWS_CALLBACK_WSI_CREATE: // always protocol[0]
		hal_log_info("WSI: %p created", wsi);
		break;
	case LWS_CALLBACK_WSI_DESTROY: // always protocol[0]
		/*
		 * l_hashmap_remove() can't be used at this point. socket is
		 * invalid already. lws_get_socket_fd() will return -1.
		 */
		l_hashmap_foreach_remove(lws_list, lws_list_cmp, wsi);
		hal_log_info("WSI: %p destroyed", wsi);
		break;
	case LWS_CALLBACK_ESTABLISHED:
		break;
	case LWS_CALLBACK_RAW_RX:
	case LWS_CALLBACK_RAW_CLOSE:
	case LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION:
	case LWS_CALLBACK_RAW_WRITEABLE:
	case LWS_CALLBACK_RAW_ADOPT:
	case LWS_CALLBACK_RAW_ADOPT_FILE:
	case LWS_CALLBACK_RAW_RX_FILE:
	case LWS_CALLBACK_RAW_WRITEABLE_FILE:
	case LWS_CALLBACK_RAW_CLOSE_FILE:
	case LWS_CALLBACK_SSL_INFO:
	case LWS_CALLBACK_CHILD_WRITE_VIA_PARENT:
	case LWS_CALLBACK_CHILD_CLOSING:
	case LWS_CALLBACK_CGI_PROCESS_ATTACH:
	case LWS_CALLBACK_CLOSED:
	case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
	case LWS_CALLBACK_CLOSED_HTTP:
	case LWS_CALLBACK_RECEIVE:
	case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
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
	case LWS_CALLBACK_GET_THREAD_ID:
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
	},
	{
		NULL, NULL, 0, 0, 0, NULL	/* end of list */
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

	if (!ws)
		return -1;

	sock = lws_get_socket_fd(ws);
	l_hashmap_insert(lws_list, L_INT_TO_PTR(sock), ws);

	hal_log_info("WSI: %p key:(%d) %p", ws, sock, L_INT_TO_PTR(sock));
	/* TODO: Create thread for each connected client */
	ws_send_msg(ws, true);

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
	if (poll_timeout)
		l_timeout_remove(poll_timeout);

	lws_context_destroy(context);
	l_hashmap_destroy(lws_list, NULL);
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
	.fetch = ws_fetch,
	.async = NULL,
	.async_stop = NULL,
	.setdata = ws_update
};
