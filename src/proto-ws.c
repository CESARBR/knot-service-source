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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

#include <libwebsockets.h>

#include <ell/ell.h>

#include <json-c/json.h>

#include <hal/linux_log.h>

#include "proto.h"

#define MAX_PAYLOAD		4096
#define SERVICE_TIMEOUT		100
#define IDENTIFY_REQUEST	"[\"identify\"]"
#define READY_RESPONSE		"[\"ready\""
#define NOT_READY_RESPONSE	"[\"notReady\""
#define CONFIG_MSG		"[\"config\",{"
#define READY_RESPONSE_LEN	(sizeof(READY_RESPONSE) - 1)
#define NOT_READY_RESPONSE_LEN	(sizeof(NOT_READY_RESPONSE) - 1)
#define CONFIG_MSG_LEN		(sizeof(CONFIG_MSG) - 1)
#define CLOUD_PATH		"/socket.io/?EIO=4&transport=websocket"
#define DEFAULT_CLOUD_HOST	"localhost"
#define DEVICE_INDEX		0
#define OPERATION_PREFIX	420
#define MESSAGE_PREFIX		42

static struct lws_context *context;
static struct l_timeout *timeout = NULL;
static struct l_hashmap *wstable = NULL;
static bool got_response = false;
static bool connection_error = false;
static bool connected = false;
static bool client_connection_error = false;
static bool ready = false;
static char *host_address = "localhost";
static int host_port = 3000;
static struct l_queue *wsis = NULL;
static int conn_index = 0;

/* Struct used to fetch data from cloud and send to THING */
struct to_fetch {
	int sock;
	void *user_data;
	void (*watch_cb)(json_raw_t, void *);
	void (*watch_destroy_cb) (void *);
};

struct per_session_data_ws {
	int index;
	/*
	 * This buffer MUST have LWS_PRE bytes valid BEFORE the pointer. this
	 * is defined in the lws documentation,
	 */
	unsigned char buffer[LWS_PRE + MAX_PAYLOAD];
	unsigned int len;
	char *json;
	struct to_fetch data;
	struct timeval interval;
};

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

static struct handshake_data *h_data = NULL;
static struct per_session_data_ws *psd;

static void *queue_at(struct l_queue *queue, unsigned int index)
{
	unsigned int i = 0;
	const struct l_queue_entry *current = l_queue_get_entries(queue);
	while (current && i < index) {
		current = current->next;
		i++;
	}

	return current ? current->data : NULL;
}

static void send_ping(const void *key, void *value, void *user_data)
{
	struct timeval *timenow = user_data;
	struct per_session_data_ws *p;
	struct lws *ws;

	p = (struct per_session_data_ws *) value;
	if (timenow->tv_sec - p->interval.tv_sec > 10) {
		gettimeofday(&p->interval, NULL);

		/* Send EIO_PING and expects EIO_PONG */
		p->len = snprintf((char *) p->buffer + LWS_PRE,
						MAX_PAYLOAD, "%d", EIO_PING);

		ws = queue_at(wsis, p->index);

		lws_callback_on_writable(ws);
		lws_service(context, SERVICE_TIMEOUT);
	}
}

static void timeout_ws(struct l_timeout *timeout, void *user_data)
{
	struct timeval timenow;

	gettimeofday(&timenow, NULL);
	lws_service(context, SERVICE_TIMEOUT);
	/* check if some socket needs to send ping */
	l_hashmap_foreach(wstable, send_ping, &timenow);
}

static int handle_response(json_raw_t *json)
{
	size_t realsize;
	json_object *jobj, *jres, *jprop, *jschema, *jschema_val;
	int has_schema;
	const char *jobjstringres;

	jres = json_tokener_parse(psd->json);
	if (jres == NULL)
		return -EINVAL;

	jobj = json_object_array_get_idx(jres, DEVICE_INDEX);
	/* Try to find device information inside the returned json */
	json_object_object_get_ex(jobj, "device", &jprop);
	/* Meshblu returns schema as value of key '1' */
	has_schema = json_object_object_get_ex(jprop, "1", &jschema);
	/* If response has schema, combine it as a key/value pair */
	if (has_schema) {
		json_object_object_get_ex(jschema, "schema", &jschema_val);
		json_object_object_add(jprop, "schema",
						json_object_get(jschema_val));
	}
	/* If device property was found return it */
	jobjstringres = json_object_to_json_string(jobj);
	if (jprop)
		jobjstringres = json_object_to_json_string(jprop);

	realsize = strlen(jobjstringres) + 1;

	json->data = (char *) realloc(json->data, json->size + realsize);
	if (json->data == NULL) {
		hal_log_error("Not enough memory");
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

	h_data = l_new(struct handshake_data, 1);

	h_data->sid = json_object_get_string(jsid);
	h_data->pingInterval = json_object_get_int(jinterval);
	h_data->pingTimeout = json_object_get_int(jtimeout);

	/* TODO: Send ping every h_data.pingInterval; */
done:
	if (h_data) {
		l_free(h_data);
		h_data = NULL;
	}
	json_object_put(jobj);
}

static void ws_close(int sock)
{
	struct lws *ws;

	/*
	 * When a thing disconnects the close callback is called. Then we
	 * find its alloted resources at the 'wstable' and 'wsis' list
	 * and free them.
	 */
	psd = l_hashmap_lookup(wstable, L_INT_TO_PTR(sock));
	if (!psd)
		return;

	ws = queue_at(wsis, psd->index);
	lws_callback_on_writable(ws);
	lws_service(context, SERVICE_TIMEOUT);

	if (!l_queue_remove(wsis, ws))
		hal_log_error("Removing wsi: no wsi found for sock %d", sock);

	if (!l_hashmap_remove(wstable, L_INT_TO_PTR(sock))) {
		hal_log_error("Removing key: sock %d not found!", sock);
		return;
	}
	l_free(psd->json);
	l_free(psd);
}

static int ws_mknode(int sock, const char *device_json, json_raw_t *json)
{
	int err;
	json_object *jobj, *jarray;
	const char *jobjstring;
	struct lws *ws;

	psd = l_hashmap_lookup(wstable, L_INT_TO_PTR(sock));
	if (!psd)
		return -EINVAL;

	jobj = json_tokener_parse(device_json);
	if (jobj == NULL)
		return -EINVAL;

	jarray = json_object_new_array();
	json_object_array_add(jarray, json_object_new_string("register"));
	json_object_array_add(jarray, jobj);
	jobjstring = json_object_to_json_string(jarray);

	ws = queue_at(wsis, psd->index);
	if (ws == NULL) {
		err = -EBADF;
		hal_log_error("Not found");
		goto done;
	}
	/*
	 * Since the size of psd->buffer is LWS_PRE + MAX_PAYLOAD bytes and the
	 * buffer is offset by LWS_PRE, this means there are only MAX_PAYLOAD
	 * bytes left to write.
	 */
	psd->len = snprintf((char *) psd->buffer + LWS_PRE, MAX_PAYLOAD,
					"%d%s", OPERATION_PREFIX, jobjstring);
	/*
	 * lws_callback_on_writable tells libwebsockets there is data to be sent
	 * As soon as possible LWS_CALLBACK_CLIENT_WRITEABLE will be triggered
	 * and psd->buffer will be written. Meanwhile, lws_service keeps the
	 * context 'alive' until server responds or an error occurs. Since knotd
	 * wasn't designed to be completely asynchronous, the operations on
	 * msg.c expects a blocking behavior, so this while forces it. Every
	 * message received will trigger a LWS_CALLBACK_CLIENT_RECEIVE. Once
	 * the server responds, the got_response flag will be set to true and
	 * we leave the loop. Since all messages are serialized by the unix
	 * socket between radio daemon (eg: nrfd, lorad) and knotd, there is no
	 * problem in using a global 'per session data (psd)' and flags, they
	 * won't be overwritten.
	 */
	lws_callback_on_writable(ws);
	hal_log_info("WS JSON TX: %s", jobjstring);
	while (!got_response && !connection_error)
		lws_service(context, SERVICE_TIMEOUT);

	if (connection_error)
		err = -ECONNRESET;

	err = handle_response(json);
	if (err < 0)
		goto done;
done:
	connection_error = false;
	got_response = false;

	json_object_put(jarray);

	return err;
}

static int ws_device(int sock, const char *uuid,
					const char *token, json_raw_t *json)
{
	int err;
	const char *jobjstring;
	json_object *jobj, *jarray;
	struct lws *ws;

	psd = l_hashmap_lookup(wstable, L_INT_TO_PTR(sock));
	if (!psd)
		return -EINVAL;

	jobj = json_object_new_object();
	jarray = json_object_new_array();

	if (!jobj || !jarray) {
		hal_log_error("JSON: no memory");
		err = -ENOMEM;
		return err;
	}

	json_object_object_add(jobj, "uuid", json_object_new_string(uuid));

	json_object_array_add(jarray,
	json_object_new_string("device"));
	json_object_array_add(jarray, jobj);

	jobjstring = json_object_to_json_string(jarray);

	hal_log_info("WS JSON TX %s", jobjstring);

	ws = queue_at(wsis, psd->index);
	if (ws == NULL) {
		hal_log_error("Not found");
		err = -EBADF;
		goto done;
	}

	psd->len = snprintf((char *)&psd->buffer + LWS_PRE, MAX_PAYLOAD, "%d%s",
						OPERATION_PREFIX, jobjstring);
	lws_callback_on_writable(ws);

	while (!got_response && !connection_error)
		lws_service(context, SERVICE_TIMEOUT);

	if (connection_error) {
		err = -ECONNREFUSED;
		goto done;
	}

	err = handle_response(json);

done:
	got_response = false;
	connection_error = false;

	json_object_put(jarray);

	return err;
}

static int ws_signin(int sock, const char *uuid, const char *token,
							json_raw_t *json)
{
	int err;
	const char *jobjstring;
	json_object *jobj, *jarray;
	struct lws *ws;

	psd = l_hashmap_lookup(wstable, L_INT_TO_PTR(sock));
	if (!psd)
		return -EINVAL;

	jobj = json_object_new_object();
	jarray = json_object_new_array();

	if (!jobj || !jarray) {
		hal_log_error("JSON: no memory");
		err = -ENOMEM;
		return err;
	}

	json_object_object_add(jobj, "uuid", json_object_new_string(uuid));
	json_object_object_add(jobj, "token", json_object_new_string(token));

	json_object_array_add(jarray,
	json_object_new_string("identity"));
	json_object_array_add(jarray, jobj);

	jobjstring = json_object_to_json_string(jarray);

	hal_log_info("WS TX JSON %s", jobjstring);

	ws = queue_at(wsis, psd->index);

	if (ws == NULL) {
		hal_log_error("Not found");
		err = -EBADF;
		goto done;
	}

	psd->len = snprintf((char *)&psd->buffer + LWS_PRE, MAX_PAYLOAD, "%d%s",
					OPERATION_PREFIX, jobjstring);
	lws_callback_on_writable(ws);

	/* Keep serving context until server responds or an error occurs */
	while (!ready && !connection_error)
		lws_service(context, SERVICE_TIMEOUT);


	if (connection_error) {
		err = -ECONNREFUSED;
		goto done;
	}

	err = ws_device(sock, uuid, token, json);

done:
	ready = false;
	connection_error = false;

	json_object_put(jarray);

	return err;
}

static int ws_rmnode(int sock, const char *uuid, const char *token,
							json_raw_t *json)
{
	int err;
	const char *jobjstring;
	json_object *jobj, *jarray;
	struct lws *ws;

	psd = l_hashmap_lookup(wstable, L_INT_TO_PTR(sock));
	if (!psd)
		return -EINVAL;

	jobj = json_object_new_object();
	jarray = json_object_new_array();

	if (!jobj || !jarray) {
		hal_log_error("JSON: no memory");
		return -ENOMEM;
	}

	json_object_object_add(jobj, "uuid", json_object_new_string(uuid));
	json_object_object_add(jobj, "token", json_object_new_string(token));

	jobjstring = json_object_to_json_string(jobj);

	json_object_array_add(jarray, json_object_new_string("unregister"));
	json_object_array_add(jarray, jobj);

	jobjstring = json_object_to_json_string(jarray);

	hal_log_info("WS JSON TX %s", jobjstring);

	ws = queue_at(wsis, psd->index);
	if (ws == NULL) {
		hal_log_error("Not found");
		err = -EBADF;
		goto done;
	}

	psd->len = snprintf((char *) psd->buffer + LWS_PRE, MAX_PAYLOAD,
					"%d%s", OPERATION_PREFIX, jobjstring);
	lws_callback_on_writable(ws);

	/*
	 * Execution is blocked until server responds or and error occurs
	 * lws_service makes sure libwebsockets keeps doing its job.
	 */
	while (!got_response && !connection_error)
		lws_service(context, SERVICE_TIMEOUT);

	if (connection_error)
		err = -ECONNRESET;

	err = handle_response(json);

	if (err < 0)
		goto done;
done:
	got_response = false;
	connection_error = false;

	json_object_put(jarray);

	return err;
}

static int ws_update(int sock, const char *uuid, const char *token,
					const char *jreq, json_raw_t *json)
{
	int err;
	struct json_object *jobj, *jarray;
	const char *jobjstr;
	struct lws *ws;

	psd = l_hashmap_lookup(wstable, L_INT_TO_PTR(sock));
	if (!psd)
		return -EINVAL;

	jobj = json_tokener_parse(jreq);
	if (jobj == NULL)
		return -EINVAL;

	jarray = json_object_new_array();

	json_object_array_add(jarray, json_object_new_string("update"));
	json_object_object_add(jobj, "uuid", json_object_new_string(uuid));

	json_object_array_add(jarray, jobj);
	jobjstr = json_object_to_json_string(jarray);

	ws = queue_at(wsis, psd->index);
	if (ws == NULL) {
		hal_log_error("Not found");
		err = -EBADF;
		goto done;
	}
	psd->len = snprintf((char *)&psd->buffer + LWS_PRE, MAX_PAYLOAD, "%d%s",
						MESSAGE_PREFIX, jobjstr);
	lws_callback_on_writable(ws);

	hal_log_info("WS JSON TX: %s", jobjstr);

	lws_service(context, SERVICE_TIMEOUT);

	if (connection_error) {
		err = -ECONNREFUSED;
		goto done;
	}

	err = 0;

done:
	got_response = false;
	connection_error = false;
	json_object_put(jarray);

	return err;
}

static int ws_data(int sock, const char *uuid, const char *token,
					const char *jreq, json_raw_t *json)
{
	int err;
	struct json_object *jobj, *jmsg;
	const char *jobjstr;
	struct lws *ws;

	psd = l_hashmap_lookup(wstable, L_INT_TO_PTR(sock));
	if (!psd)
		return -EINVAL;

	jobj = json_tokener_parse(jreq);
	if (jobj == NULL)
		return -EINVAL;

	jmsg = json_object_new_array();
	json_object_array_add(jmsg, json_object_new_string("data"));
	json_object_object_add(jobj, "uuid", json_object_new_string(uuid));
	json_object_object_add(jobj, "token", json_object_new_string(token));
	json_object_array_add(jmsg, jobj);
	jobjstr = json_object_to_json_string(jmsg);

	ws = queue_at(wsis, psd->index);
	if (ws == NULL) {
		hal_log_error("Not found");
		err = -EBADF;
		goto done;
	}
	psd->len = snprintf((char *)&psd->buffer + LWS_PRE, MAX_PAYLOAD, "%d%s",
						OPERATION_PREFIX, jobjstr);
	lws_callback_on_writable(ws);
	err = 0;

	while (!got_response && !connection_error)
		lws_service(context, SERVICE_TIMEOUT);

done:
	got_response = false;
	connection_error = false;

	json_object_put(jmsg);

	return err;
}

static void handle_cloud_response(const char *resp, struct lws *wsi)
{
	int packet_type, offset = 0, len = strlen(resp);
	json_raw_t json;
	size_t realsize;
	json_object *jobj, *jres;
	const char *jobjstringres;
	struct per_session_data_ws *session_data;

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

	switch (packet_type) {
	case EIO_OPEN:
		parse_handshake_data(resp);
		break;
	case EIO_PONG:
		/* TODO */
		break;
	case EIO_MSG:
		hal_log_info("WS JSON_RX %d = %s", packet_type, resp);
		if (!strcmp(resp, IDENTIFY_REQUEST))
			connected = true;
		else if (!strncmp(resp, READY_RESPONSE, READY_RESPONSE_LEN))
			ready = true;
		else if (!strncmp(resp, NOT_READY_RESPONSE,
						NOT_READY_RESPONSE_LEN)) {
			connection_error = true;
			client_connection_error = true;
		/*
		 * Every time a device is updated a CONFIG_MSG is sent to all
		 * devices that subscribed for the updated device's uuid
		 * including the device itself, so here we parse the message,
		 * which may contain an get_data, set_data or config and
		 * call the watch_cb that will be responsible of forwarding
		 * the message to the thing.
		 */
		} else if (!strncmp(resp, CONFIG_MSG, CONFIG_MSG_LEN)) {
			session_data = l_hashmap_lookup(wstable,
				L_INT_TO_PTR(lws_get_socket_fd(wsi)));

			if (!session_data)
				break;

			memset(&json, 0, sizeof(json_raw_t));

			jres = json_tokener_parse(resp);
			if (jres == NULL)
				break;

			jobj = json_object_array_get_idx(jres, 1);

			jobjstringres = json_object_to_json_string(jobj);

			realsize = strlen(jobjstringres) + 1;

			json.data = (char *) realloc(json.data,
							json.size + realsize);
			if (json.data == NULL) {
				hal_log_error("Not enough memory");
				break;
			}

			memcpy(json.data + json.size, jobjstringres, realsize);
			json.size += realsize;
			json.data[json.size - 1] = 0;

			if (session_data->data.watch_cb)
				session_data->data.watch_cb(json,
						session_data->data.user_data);

			json_object_put(jres);
			free(json.data);
		} else {
			if (psd->json)
				l_free(psd->json);
			psd->json = l_strdup(resp);
			got_response = true;
		}
		break;
	default:
		break;
	}
}

static int callback_lws_http(struct lws *wsi,
					enum lws_callback_reasons reason,
					void *user_data, void *in, size_t len)

{
	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		hal_log_info("LWS_CALLBACK_ESTABLISHED");
		break;
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		hal_log_info("LWS_CALLBACK_CLIENT_CONNECTION_ERROR");
		client_connection_error = true;
		break;
	case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
		break;
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		hal_log_info("LWS_CALLBACK_CLIENT_ESTABLISHED");
		break;
	case LWS_CALLBACK_CLOSED:
		hal_log_info("LWS_CALLBACK_CLOSED FOR WSI %p", wsi);
		wsi = NULL;
		/* FIXME: Needed? connection_error = true; */
		break;
	case LWS_CALLBACK_CLOSED_HTTP:
		break;
	case LWS_CALLBACK_RECEIVE:
		break;
	case LWS_CALLBACK_CLIENT_RECEIVE:
		handle_cloud_response((char *) in, wsi);
		break;
	case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
		break;
	case LWS_CALLBACK_CLIENT_WRITEABLE:
		{
		int l;

		gettimeofday(&psd->interval, NULL);

		psd = l_hashmap_lookup(wstable,
				L_INT_TO_PTR(lws_get_socket_fd(wsi)));

		l = lws_write(wsi, &psd->buffer[LWS_PRE], psd->len,
								LWS_WRITE_TEXT);
		/*
		 * Since pings are sent continuously, ignore them to have
		 * a cleaner log.
		 */
		if (l > 1)
			hal_log_info("WS TX%d bytes", l);

		/* Enable RX when after message is successfully sent */
		if (l < 0) {
			connection_error = true;
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
	struct lws *ws;
	int sock;
	static char ads_port[300];
	bool use_ssl = false; /* wss */

	memset(&info, 0, sizeof(info));
	snprintf(ads_port, sizeof(ads_port) - 1, "%s:%u", host_address,
								host_port);

	hal_log_info("Connecting to %s...", ads_port);

	psd = l_new(struct per_session_data_ws, 1);

	info.context = context;
	info.ssl_connection = use_ssl;
	info.address = host_address;
	info.port = host_port;
	info.path = CLOUD_PATH;
	info.host = info.address;
	info.origin = info.address;
	info.ietf_version_or_minus_one = -1;
	info.protocol = protocols[0].name;

	connected = false;
	client_connection_error = false;
	connection_error = false;
	got_response = false;

	/*
	 * Every new connection is stored in the 'wsis' list. The client only
	 * sees a fd which is the key for its respective per session data (psd).
	 * In this struct we store an index that is related to the position of
	 * the websocket instance (wsi) in the 'wsis' list. The relationships
	 * are: fd <-> psd->index <-> wsi (wsis at psd->index)
	 */
	ws = lws_client_connect_via_info(&info);

	psd->index = conn_index++;

	/*
	 * Connect via info is a non blocking method, it returns a websocket
	 * instance but it may not be writable yet, so here we keep serving the
	 * context until the connection is actually established. When the
	 * LWS_CALLBACK_CLIENT_ESTABLISHED is triggered.
	 */
	while (!connected && !client_connection_error)
		lws_service(context, SERVICE_TIMEOUT);

	if (client_connection_error) {
		l_free(psd);
		/* TODO: ws leaking */
		return -ECONNREFUSED;
	}

	l_queue_push_tail(wsis, ws);

	/* Map ws to a unique int */
	sock = lws_get_socket_fd((struct lws *) ws);
	gettimeofday(&psd->interval, NULL);
	l_hashmap_insert(wstable, L_INT_TO_PTR(sock), psd);

	connected = false;
	client_connection_error = false;
	connection_error = false;
	got_response = false;

	return sock;
}

static int ws_probe(const char *host, unsigned int port)
{
	struct lws_context_creation_info i;

	memset(&i, 0, sizeof(i));

	host_address = l_strdup(host);
	host_port = port;

	i.port = CONTEXT_PORT_NO_LISTEN;
	i.gid = -1;
	i.uid = -1;
	i.protocols = protocols;
	context = lws_create_context(&i);

	wsis = l_queue_new();
	wstable = l_hashmap_new();

	/* FIXME: Investigate alternatives for libwebsocket_service() */
	timeout = l_timeout_create(1, timeout_ws, NULL, NULL);

	return 0;
}

static void session_data_free(struct per_session_data_ws *psd)
{
	l_free(psd->json);
	l_free(psd);
}

static void ws_remove(void)
{
	if (timeout) {
		l_timeout_remove(timeout);
		timeout = NULL;
	}
	l_queue_destroy(wsis, NULL);
	l_hashmap_destroy(wstable, (l_hashmap_destroy_func_t) session_data_free);
	lws_context_destroy(context);
	l_free(host_address);
}

static void on_proto_destroyed(void *user_data)
{
	struct to_fetch *data = user_data;

	if (data->watch_destroy_cb)
		data->watch_destroy_cb(data->user_data);

	data->watch_cb = NULL;
	data->user_data = NULL;
	data->watch_destroy_cb = NULL;
}

/*
 * Watch or poll the cloud to changes in the device.  uuid/token are used
 * by the http protocol in order to constantly fetch specific device data
 * since websockets uses a 'subscription' mechanism there is no need to
 * store these values.
 */
static unsigned int ws_async(int sock, const char *uuid,
	const char *token, void (*proto_watch_cb)	(json_raw_t, void *),
	void *user_data, void (*proto_watch_destroy_cb) (void *))
{
	struct to_fetch *data;
	struct per_session_data_ws *value;
	struct l_io *proto_io;

	value = l_hashmap_lookup(wstable, L_INT_TO_PTR(sock));
	if (!value)
		return -EINVAL;

	data = &value->data;
	data->watch_cb = proto_watch_cb;
	data->user_data = user_data;
	data->watch_destroy_cb = proto_watch_destroy_cb;

	proto_io = l_io_new(sock);
	l_io_set_disconnect_handler(proto_io, NULL, data, on_proto_destroyed);

	l_hashmap_insert(wstable, L_INT_TO_PTR(sock), value);

	return L_PTR_TO_UINT(proto_io);
}

static void ws_async_stop(int sock, unsigned int watch_id)
{
	struct l_io *proto_io = L_UINT_TO_PTR(watch_id);
	l_io_destroy(proto_io);
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
	.async = ws_async,
	.async_stop = ws_async_stop,
	.setdata = ws_update
};
