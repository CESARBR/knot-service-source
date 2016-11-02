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
#define IDENTIFY_REQUEST	"[\"identify\"]"
#define READY_RESPONSE		"[\"ready\""
#define NOT_READY_RESPONSE	"[\"notReady\""
#define READY_RESPONSE_LEN	(sizeof(READY_RESPONSE) - 1)
#define NOT_READY_RESPONSE_LEN	(sizeof(NOT_READY_RESPONSE) - 1)
#define CLOUD_PATH		"/socket.io/?EIO=4&transport=websocket"
#define DEFAULT_CLOUD_HOST	"localhost"

struct lws_context *context;
static GHashTable *wstable;
static gboolean got_response = FALSE;
static gboolean connection_error = FALSE;
static gboolean connected = FALSE;
static gboolean ready = FALSE;
struct lws_client_connect_info info;
static char *host_address = "localhost";
static int host_port = 3000;


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

static struct per_session_data_ws *psd;

/*
 * A message has the following structure: <packet_type>[json_message]
 * Packet types defined by Engine.IO:
 */
enum packet_type {
	EIO_OPEN,
	EIO_CLOSE,
	EIO_PING,
	EIO_PONG,
	EIO_MSG,
	EIO_UPGRADE,
	EIO_NOOP
};

struct handshake_data {
	const char *sid;
	int pingInterval;
	int pingTimeout;
};

static struct handshake_data *h_data;

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
		log_error("Not enough memory");
		return -ENOMEM;
	}

	memcpy(json->data + json->size, jobjstringres, realsize);
	json->size += realsize;
	json->data[json->size - 1] = 0;
	json_object_put(jres);

	return 0;
}

static void parse_handshake_data(const char *json_str)
{
	json_object *jobj, *jsid, *jtimeout, *jinterval;

	jobj = json_tokener_parse(json_str);
	/*
	 * During connection establishment a JSON is received with a socket id
	 * (sid), pingInterval - frequency the client should ping the server and
	 * pingTimeout - time to disconnect after not receiving a pong
	 */
	if (!json_object_object_get_ex(jobj, "sid", &jsid))
		goto done;
	if (!json_object_object_get_ex(jobj, "pingInterval", &jinterval))
		goto done;
	if (!json_object_object_get_ex(jobj, "pingTimeout", &jtimeout))
		goto done;

	h_data = g_new0(struct handshake_data, 1);

	h_data->sid = json_object_get_string(jsid);
	h_data->pingInterval = json_object_get_int(jinterval);
	h_data->pingTimeout = json_object_get_int(jtimeout);

	/* TODO: Send ping every h_data.pingInterval; */
done:
	json_object_put(jobj);
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
		log_error("Removing key: sock %d not found!", sock);
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
		log_error("Not found");
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
		log_error("JSON: no memory");
		return -ENOMEM;
	}

	json_object_object_add(jobj, "uuid", json_object_new_string(uuid));
	json_object_object_add(jobj, "token", json_object_new_string(token));

	json_object_array_add(jarray,
	json_object_new_string("identity"));
	json_object_array_add(jarray, jobj);

	jobjstring = json_object_to_json_string(jarray);

	log_info("TX JSON %s", jobjstring);

	psd = g_new0(struct per_session_data_ws, 1);
	psd->ws = g_hash_table_lookup(wstable, GINT_TO_POINTER(sock));

	if (psd->ws == NULL) {
		log_error("Not found");
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
		log_error("Not found");
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

static int ws_rmnode(int sock, const char *uuid, const char *token,
							json_raw_t *json)
{
	int err;
	const char *jobjstring;
	json_object *jobj;
	json_object *jarray;
	const char *expected_result = "unregistered";

	jobj = json_object_new_object();
	jarray = json_object_new_array();

	if (!jobj || !jarray) {
		log_error("JSON: no memory");
		return -ENOMEM;
	}

	json_object_object_add(jobj, "uuid", json_object_new_string(uuid));
	json_object_object_add(jobj, "token", json_object_new_string(token));

	jobjstring = json_object_to_json_string(jobj);

	json_object_array_add(jarray, json_object_new_string("unregister"));
	json_object_array_add(jarray, jobj);

	jobjstring = json_object_to_json_string(jarray);

	log_info("TX JSON %s", jobjstring);

	psd = g_new0(struct per_session_data_ws, 1);
	psd->ws = g_hash_table_lookup(wstable, GINT_TO_POINTER(sock));

	if (psd->ws == NULL) {
		log_error("Not found");
		err = -EBADF;
		goto done;
	}

	psd->len = sprintf((char *)&psd->buffer[LWS_PRE], "%s", jobjstring);
	lws_callback_on_writable(psd->ws);

	/* Keep serving context until server responds or an error occurs */
	while (!got_response || connection_error)
		lws_service(context, SERVICE_TIMEOUT);

	err = ret2errno(psd->json, expected_result);

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

static int ws_schema(int sock, const char *uuid, const char *token,
					const char *jreq, json_raw_t *json)
{
	int err;
	struct json_object *jobj, *ajobj, *jobjdev, *jarray, *jset;
	const char *jobjstr;
	const char *expected_result = "updated";

	jobj = json_tokener_parse(jreq);
	if (jobj == NULL)
		return -EINVAL;

	ajobj = json_object_new_array();
	jarray = json_object_new_array();
	jobjdev = json_object_new_object();

	json_object_array_add(jarray, json_object_new_string("update"));
	json_object_object_add(jobjdev, "uuid", json_object_new_string(uuid));
	json_object_object_add(jobjdev, "token", json_object_new_string(token));
	json_object_array_add(ajobj, jobjdev);

	jset = json_object_new_object();
	json_object_object_add(jset, "$set", jobj);

	json_object_array_add(ajobj, jset);
	json_object_array_add(jarray, ajobj);
	jobjstr = json_object_to_json_string(jarray);

	psd = g_new0(struct per_session_data_ws, 1);
	psd->ws = g_hash_table_lookup(wstable, GINT_TO_POINTER(sock));

	if (psd->ws == NULL) {
		log_error("Not found");
		err = -EBADF;
		goto done;
	}

	psd->len = sprintf((char *)&psd->buffer[LWS_PRE], "%s", jobjstr);
	lws_callback_on_writable(psd->ws);

	/* Keep serving context until server responds or an error occurs */
	while (!got_response || connection_error)
		lws_service(context, SERVICE_TIMEOUT);

	err = ret2errno(psd->json, expected_result);

	if (err < 0)
		goto done;

	err = handle_response(json);

done:
	got_response = FALSE;
	connection_error = FALSE;

	json_object_put(jarray);
	g_free(psd);

	return err;
}

static int ws_data(int sock, const char *uuid, const char *token,
					const char *jreq, json_raw_t *json)
{
	int err;
	struct json_object *jobj, *jmsg;
	const char *jobjstr;

	jobj = json_tokener_parse(jreq);
	if (jobj == NULL)
		return -EINVAL;

	jmsg = json_object_new_array();
	json_object_array_add(jmsg, json_object_new_string("data"));
	json_object_object_add(jobj, "uuid", json_object_new_string(uuid));
	json_object_object_add(jobj, "token", json_object_new_string(token));
	json_object_array_add(jmsg, jobj);
	jobjstr = json_object_to_json_string(jmsg);

	psd = g_new0(struct per_session_data_ws, 1);
	psd->ws = g_hash_table_lookup(wstable, GINT_TO_POINTER(sock));

	if (psd->ws == NULL) {
		log_error("Not found");
		err = -EBADF;
		goto done;
	}
	psd->len = sprintf((char *)&psd->buffer[LWS_PRE], "%s", jobjstr);
	lws_callback_on_writable(psd->ws);
	err = 0;

	/* WS data does not expect any response */

done:
	got_response = FALSE;
	connection_error = FALSE;

	json_object_put(jmsg);
	g_free(psd);

	return err;
}

static int send_identity(void)
{
	int err = -ECONNREFUSED;
	/*
	 * Part of the connection establishment process is to identify yourself
	 * an identity msg with an empty json will generate a new uuid/token
	 * a possible FIXME is to authenticate the owner (GW)
	 */
	psd->len = snprintf((char *) psd->buffer + LWS_PRE, MAX_PAYLOAD,
							"42[\"identity\",{}]");
	lws_callback_on_writable(psd->ws);

	/*
	 * After receiving an identify request and sending an identity response
	 * the cloud will send a ready or notReady back which will be mapped
	 * to ready or connection_error respectively.
	 */
	while (!ready && !connection_error)
		lws_service(context, SERVICE_TIMEOUT);

	if (connection_error)
		goto done;

	err = 0;
done:
	ready = FALSE;
	connected = TRUE;
	got_response = FALSE;
	g_free(psd);

	return err;
}

static void handle_cloud_response(const char *resp)
{
	int packet_type, offset = 0, len = strlen(resp);

	/* Find message type */
	if (sscanf(resp, "%1d", &packet_type) < 0)
		return;
	/*
	 * Skip packet type, if packet type is EIO_OPEN, resp is like 0{...}
	 * otherwise resp is packet_type[...]
	 */
	if (packet_type == EIO_OPEN)
		resp += 1;
	else {
		while (offset < len && resp[offset] != '[')
			offset++;
		resp += offset;
	}
	log_info("JSON_RX %d = %s", packet_type, resp);

	switch (packet_type) {
	case EIO_OPEN:
		parse_handshake_data(resp);
		break;
	case EIO_PONG:
		/* TODO */
		break;
	case EIO_MSG:
		if (!strcmp(resp, IDENTIFY_REQUEST))
			connected = TRUE;
		else if (!strncmp(resp, READY_RESPONSE, READY_RESPONSE_LEN))
			ready = TRUE;
		else if (!strncmp(resp, NOT_READY_RESPONSE,
							NOT_READY_RESPONSE_LEN))
			connection_error = TRUE;
		else
			break;
	default:
		break;
	}
}

static int callback_lws_http(struct lws *wsi,
					enum lws_callback_reasons reason,
					void *user, void *in, size_t len)

{
	log_info("reason(%02X): %s", reason, lws_reason2str(reason));

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		log_info("LWS_CALLBACK_ESTABLISHED");
		break;
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		log_info("LWS_CALLBACK_CLIENT_CONNECTION_ERROR");
		connection_error = TRUE;
		break;
	case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
		break;
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		log_info("LWS_CALLBACK_CLIENT_ESTABLISHED");
		connected = TRUE;
		break;
	case LWS_CALLBACK_CLOSED:
		log_info("LWS_CALLBACK_CLOSED");
		connection_error = TRUE;
		break;
	case LWS_CALLBACK_CLOSED_HTTP:
		break;
	case LWS_CALLBACK_RECEIVE:
		break;
	case LWS_CALLBACK_CLIENT_RECEIVE:
		handle_cloud_response((char *) in);
		break;
	case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
		break;
	case LWS_CALLBACK_CLIENT_WRITEABLE:
		{
		int l;

		if (psd->ws == wsi)
			log_info("Client wsi %p writable", wsi);

		l = lws_write(psd->ws, &psd->buffer[LWS_PRE], psd->len,
								LWS_WRITE_TEXT);
		log_info("Wrote (%d) bytes", l);

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
	int err, sock;
	static char ads_port[300];
	gboolean use_ssl = FALSE; /* wss */

	memset(&info, 0, sizeof(info));
	snprintf(ads_port, sizeof(ads_port) - 1, "%s:%u", host_address,
								host_port);

	log_info("Connecting to %s...", ads_port);

	psd = g_new0(struct per_session_data_ws, 1);
	info.context = context;
	info.ssl_connection = use_ssl;
	info.address = host_address;
	info.port = host_port;
	info.path = CLOUD_PATH;
	info.host = info.address;
	info.origin = info.address;
	info.ietf_version_or_minus_one = -1;
	info.protocol = protocols[0].name;

	connected = FALSE;
	connection_error = FALSE;
	got_response = FALSE;

	psd->ws = lws_client_connect_via_info(&info);

	if (psd->ws == NULL) {
		err = errno;
		log_error("libwebsocket_client_connect(): %s(%d)",
							strerror(err), err);
		return -err;
	}

	/*
	 * Connect via info is a non blocking method, it returns a websocket
	 * instance but it may not be writable yet, so here we keep serving the
	 * context until the connection is actually established. When the
	 * LWS_CALLBACK_CLIENT_ESTABLISHED is triggered.
	 */
	while (!connected && !connection_error)
		lws_service(context, SERVICE_TIMEOUT);

	if (connection_error) {
		g_free(psd);
		return -ECONNREFUSED;
	}
	/* Map ws to a unique int */
	sock = lws_get_socket_fd(psd->ws);
	g_hash_table_insert(wstable, GINT_TO_POINTER(sock), psd->ws);

	connected = FALSE;
	connection_error = FALSE;
	got_response = FALSE;

	err = send_identity();
	if (err < 0)
		return err;

	connected = FALSE;
	connection_error = FALSE;
	got_response = FALSE;

	/* FIXME: Investigate alternatives for libwebsocket_service() */
	g_timeout_add_seconds(1, timeout_ws, NULL);

	return sock;
}

static int ws_probe(const char *host, unsigned int port)
{
	struct lws_context_creation_info i;

	memset(&i, 0, sizeof(i));

	i.port = CONTEXT_PORT_NO_LISTEN;
	i.gid = -1;
	i.uid = -1;
	i.protocols = protocols;

	context = lws_create_context(&i);

	wstable = g_hash_table_new(g_direct_hash, g_direct_equal);

	return 0;
}

static void ws_remove(void)
{
	g_hash_table_destroy(wstable);
	lws_context_destroy(context);
	g_free(h_data);
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
	.schema = ws_schema,
	.data = ws_data,
};
