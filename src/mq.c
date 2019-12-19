/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2019, CESAR. All rights reserved.
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

/**
 *  Message Queue source file
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef  _GNU_SOURCE
#define  _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdbool.h>
#include <sys/time.h>
#include <errno.h>
#include <ell/ell.h>
#include <hal/linux_log.h>
#include <amqp.h>
#include <amqp_framing.h>
#include <amqp_tcp_socket.h>

#include "settings.h"
#include "mq.h"

#define MQ_CONNECTION_TIMEOUT_US 10000
#define MQ_CONNECTION_RETRY_TIMEOUT_MS 1000

struct mq_context {
	amqp_connection_state_t conn;
	struct l_io *amqp_io;
	struct l_timeout *conn_retry_timeout;
	mq_connected_cb_t connected_cb;
	void *connected_data;
	mq_read_cb_t read_cb;
};

static struct mq_context mq_ctx;

static const char *mq_server_exception_string(amqp_rpc_reply_t reply)
{
	amqp_connection_close_t *m = reply.reply.decoded;
	static char r[512];

	switch (reply.reply.id) {
	case AMQP_CONNECTION_CLOSE_METHOD:
		snprintf(r, sizeof(r),
			 "server connection error %uh, message: %.*s\n",
			 m->reply_code, (int)m->reply_text.len,
			 (char *)m->reply_text.bytes);
		break;
	case AMQP_CHANNEL_CLOSE_METHOD:
		snprintf(r, sizeof(r),
			 "server channel error %uh, message: %.*s\n",
			 m->reply_code, (int)m->reply_text.len,
			 (char *)m->reply_text.bytes);
		break;
	default:
		snprintf(r, sizeof(r),
			 "unknown server error, method id 0x%08X\n",
			 reply.reply.id);
		break;
	}

	return l_strdup(r);
}

static const char *mq_rpc_reply_string(amqp_rpc_reply_t reply)
{
	switch (reply.reply_type) {
	case AMQP_RESPONSE_NONE:
		return "missing RPC reply type!";
	case AMQP_RESPONSE_LIBRARY_EXCEPTION:
		return amqp_error_string2(reply.library_error);
	case AMQP_RESPONSE_SERVER_EXCEPTION:
		return mq_server_exception_string(reply);
	case AMQP_RESPONSE_NORMAL:
	default:
		return "";
	}
}

static char *mq_bytes_to_new_string(amqp_bytes_t data)
{
	char *str = l_new(char, data.len + 1);

	memcpy(str, data.bytes, data.len);
	str[data.len] = '\0';
	return str;
}

/**
 * Callback function to consume message envelope from AMQP queue.
 *
 * Returns true on success or false if the read callback is not set.
 */
static bool on_receive(struct l_io *io, void *user_data)
{
	amqp_rpc_reply_t res;
	amqp_envelope_t envelope;
	char *exchange, *routing_key, *body;
	struct timeval time_out = { .tv_usec = MQ_CONNECTION_TIMEOUT_US };
	bool success;

	if (amqp_release_buffers_ok(mq_ctx.conn))
		amqp_release_buffers(mq_ctx.conn);

	res = amqp_consume_message(mq_ctx.conn, &envelope, &time_out, 0);

	if (AMQP_RESPONSE_NORMAL != res.reply_type)
		return true;

	hal_log_dbg("Receive %u, exchange %.*s routingkey %.*s\n",
			(unsigned)envelope.delivery_tag,
			(int)envelope.exchange.len,
			(char *)envelope.exchange.bytes,
			(int)envelope.routing_key.len,
			(char *)envelope.routing_key.bytes);

	hal_log_dbg("Body: %.*s\n",
			(int)envelope.message.body.len,
			(char *)envelope.message.body.bytes);

	if (!mq_ctx.read_cb) {
		hal_log_dbg("AMQP read callback is not set");
		amqp_destroy_envelope(&envelope);
		return false;
	}

	exchange = mq_bytes_to_new_string(envelope.exchange);
	routing_key = mq_bytes_to_new_string(envelope.routing_key);
	body = mq_bytes_to_new_string(envelope.message.body);

	success = mq_ctx.read_cb(exchange, routing_key, body, user_data);
	if (!success)
		/* TODO: Add the msg on the queue again */
		hal_log_dbg("Message envelope not consumed");

	hal_log_dbg("Destroy received envelope");
	amqp_destroy_envelope(&envelope);
	l_free(exchange);
	l_free(routing_key);
	l_free(body);

	return true;
}

static void on_disconnect(struct l_io *io, void *user_data)
{
	amqp_rpc_reply_t r;
	int err;

	hal_log_info("AMQP broker disconnected");
	r = amqp_channel_close(mq_ctx.conn, 1, AMQP_REPLY_SUCCESS);
	if (r.reply_type != AMQP_RESPONSE_NORMAL)
		hal_log_error("amqp_channel_close: %s",
				mq_rpc_reply_string(r));

	r = amqp_connection_close(mq_ctx.conn, AMQP_REPLY_SUCCESS);
	if (r.reply_type != AMQP_RESPONSE_NORMAL)
		hal_log_error("amqp_connection_close: %s",
				mq_rpc_reply_string(r));

	err = amqp_destroy_connection(mq_ctx.conn);
	if (err < 0)
		hal_log_error("amqp_destroy_connection: %s",
				amqp_error_string2(err));

	l_io_destroy(mq_ctx.amqp_io);
	mq_ctx.conn = NULL;
	mq_ctx.amqp_io = NULL;

	l_timeout_modify_ms(mq_ctx.conn_retry_timeout,
			    MQ_CONNECTION_RETRY_TIMEOUT_MS);
}

static void start_connection(struct l_timeout *ltimeout, void *user_data)
{
	const struct settings *settings = user_data;
	amqp_socket_t *socket;
	struct amqp_connection_info cinfo;
	char *tmp_url = l_strdup(settings->rabbitmq_url);
	amqp_rpc_reply_t r;
	struct timeval timeout = { .tv_usec = MQ_CONNECTION_TIMEOUT_US };
	int status;

	hal_log_dbg("Trying to connect to rabbitmq");
	// This function will change the url after processed
	status = amqp_parse_url(tmp_url, &cinfo);
	if (status) {
		hal_log_error("amqp_parse_url: %s", amqp_error_string2(status));
		goto done;
	}

	mq_ctx.conn = amqp_new_connection();
	if (!mq_ctx.conn) {
		hal_log_error("amqp_new_connection: Error on creation");
		goto done;
	}

	socket = amqp_tcp_socket_new(mq_ctx.conn);
	if (!socket) {
		hal_log_error("error creating tcp socket");
		goto destroy_conn;
	}

	status = amqp_socket_open_noblock(socket, cinfo.host, cinfo.port,
					  &timeout);
	if (status < 0) {
		hal_log_error("error opening socket: %s",
					amqp_error_string2(status));
		goto close_conn;
	}

	r = amqp_login(mq_ctx.conn, cinfo.vhost,
		       AMQP_DEFAULT_MAX_CHANNELS, AMQP_DEFAULT_FRAME_SIZE,
		       AMQP_DEFAULT_HEARTBEAT, AMQP_SASL_METHOD_PLAIN,
		       cinfo.user, cinfo.password);
	if (r.reply_type != AMQP_RESPONSE_NORMAL) {
		hal_log_error("amqp_login(): %s", mq_rpc_reply_string(r));
		goto close_conn;
	}

	hal_log_info("Connected to amqp://%s:%s@%s:%d/%s", cinfo.user,
		     cinfo.password, cinfo.host, cinfo.port, cinfo.vhost);

	amqp_channel_open(mq_ctx.conn, 1);
	r = amqp_get_rpc_reply(mq_ctx.conn);
	if (r.reply_type != AMQP_RESPONSE_NORMAL) {
		hal_log_error("amqp_channel_open(): %s",
				mq_rpc_reply_string(r));
		goto close_conn;
	}

	mq_ctx.amqp_io = l_io_new(amqp_get_sockfd(mq_ctx.conn));

	status = l_io_set_disconnect_handler(mq_ctx.amqp_io, on_disconnect,
					     NULL, NULL);
	if (!status) {
		hal_log_error("Error on set up disconnect handler");
		goto io_destroy;
	}

	mq_ctx.connected_cb(mq_ctx.connected_data);
	goto done;

io_destroy:
	l_io_destroy(mq_ctx.amqp_io);
	mq_ctx.amqp_io = NULL;
close_conn:
	r = amqp_connection_close(mq_ctx.conn, AMQP_REPLY_SUCCESS);
	if (r.reply_type != AMQP_RESPONSE_NORMAL)
		hal_log_error("amqp_connection_close: %s",
				mq_rpc_reply_string(r));
destroy_conn:
	status = amqp_destroy_connection(mq_ctx.conn);
	if (status < 0)
		hal_log_error("status destroy: %s", amqp_error_string2(status));

	mq_ctx.conn = NULL;
	l_timeout_modify_ms(ltimeout, MQ_CONNECTION_RETRY_TIMEOUT_MS);
done:
	l_free(tmp_url);
}

/**
 * mq_publish_persistent_message:
 * @queue: queue declared previously
 * @exchange: exchange name
 * @routing_keys: routing key name
 * @headers: array of table entry with headers
 * @num_headers: headers length
 * @expiration_ms: expiration property in miliseconds or 0 if no expiration time
 * @body: the message to be sent
 *
 * Publishs a persistent message in the exchange and routing key to aqueue bond,
 * so even if there is no consumer listening the message aren't lost.
 *
 * Returns: 0 if successfull and negative integer otherwise.
 */
int8_t mq_publish_persistent_message(amqp_bytes_t queue,
				       const char *exchange,
				       const char *routing_keys,
				       amqp_table_entry_t *headers,
				       size_t num_headers,
				       uint64_t expiration_ms,
				       const char *body)
{
	amqp_basic_properties_t props;
	amqp_rpc_reply_t resp;
	char *expiration_str;
	int8_t rc; // Return Code

	/* Declare the exchange as durable */
	amqp_exchange_declare(mq_ctx.conn, 1,
			amqp_cstring_bytes(exchange),
			amqp_cstring_bytes("topic"),
			0 /* passive*/,
			1 /* durable */,
			0 /* auto_delete*/,
			0 /* internal */,
			amqp_empty_table);
	resp = amqp_get_rpc_reply(mq_ctx.conn);
	if (resp.reply_type != AMQP_RESPONSE_NORMAL) {
		hal_log_error("amqp_exchange_declare(): %s",
			      mq_rpc_reply_string(resp));
		return -1;
	}

	/* Bind exchange to keep messages */
	amqp_queue_bind(mq_ctx.conn, 1, queue,
			amqp_cstring_bytes(exchange),
			amqp_cstring_bytes(routing_keys),
			amqp_empty_table);

	if (amqp_get_rpc_reply(mq_ctx.conn).reply_type !=
			       AMQP_RESPONSE_NORMAL) {
		hal_log_error("Error while binding queue");
		return -1;
	}

	props._flags =	AMQP_BASIC_CONTENT_TYPE_FLAG	|
			AMQP_BASIC_DELIVERY_MODE_FLAG;
	if (expiration_ms) {
		props._flags |= AMQP_BASIC_EXPIRATION_FLAG;
		expiration_str = l_strdup_printf("%"PRIu64, expiration_ms);
		props.expiration = amqp_cstring_bytes(expiration_str);
	}

	if (num_headers > 0) {
		props._flags |= AMQP_BASIC_HEADERS_FLAG;
		props.headers.num_entries = num_headers;
		props.headers.entries = headers;
	}

	props.content_type = amqp_cstring_bytes("text/plain");
	props.delivery_mode = AMQP_DELIVERY_PERSISTENT;

	rc = amqp_basic_publish(mq_ctx.conn, 1,
			amqp_cstring_bytes(exchange),
			amqp_cstring_bytes(routing_keys),
			0 /* mandatory */,
			0 /* immediate */,
			&props, amqp_cstring_bytes(body));
	if (rc < 0)
		hal_log_error("amqp_basic_publish(): %s",
				amqp_error_string2(rc));

	if (expiration_ms)
		l_free(expiration_str);

	return rc;
}

/**
 * mq_declare_new_queue:
 * @name: queue name
 *
 * Declares a durable queue in amqp connection.
 *
 * Returns: the queue declared or NULL otherwise.
 */
amqp_bytes_t mq_declare_new_queue(const char *name)
{
	amqp_bytes_t queue;
	amqp_queue_declare_ok_t *r;

	if (!mq_ctx.conn) {
		queue.bytes = NULL;
		return queue;
	}

	r = amqp_queue_declare(mq_ctx.conn, 1,
			amqp_cstring_bytes(name),
			0, /* passive */
			1, /* durable */
			0, /* exclusive */
			0, /* auto-delete */
			amqp_empty_table);

	if (amqp_get_rpc_reply(mq_ctx.conn).reply_type !=
			       AMQP_RESPONSE_NORMAL) {
		hal_log_error("Error declaring queue name");
		queue.bytes = NULL;
	}

	queue = amqp_bytes_malloc_dup(r->queue);
	if (queue.bytes == NULL)
		hal_log_error("Out of memory while copying queue buffer");

	return queue;
}

/**
 * mq_bind_queue:
 * @queue: queue declared
 * @exchange: exchange to be declared
 * @routing_key: routing key to bind
 *
 * Declares a exchange and bind a routing key to a queue to be a consumer.
 *
 * Returns: 0 if successfull and -1 otherwise.
 */
int mq_bind_queue(amqp_bytes_t queue,
			      const char *exchange,
			      const char *routing_key)
{
	if (exchange == NULL || routing_key == NULL)
		return -1;

	/* Declare the exchange as durable */
	amqp_exchange_declare(mq_ctx.conn, 1,
			amqp_cstring_bytes(exchange),
			amqp_cstring_bytes("topic"),
			0 /* passive*/,
			1 /* durable */,
			0 /* auto_delete*/,
			0 /* internal */,
			amqp_empty_table);

	/* Set up to bind a queue to an exchange */
	amqp_queue_bind(mq_ctx.conn, 1, queue,
			amqp_cstring_bytes(exchange),
			amqp_cstring_bytes(routing_key),
			amqp_empty_table);

	if (amqp_get_rpc_reply(mq_ctx.conn).reply_type !=
			       AMQP_RESPONSE_NORMAL) {
		hal_log_error("Error while binding queue");
		return -1;
	}

	return 0;
}

/**
 * mq_set_read_cb:
 * @queue: queue that is going to be consume
 * @on_read: callback to be called when receive some amqp message
 * @user_data: user data provided to callback
 *
 * Set the callback handler when receive any message from amqp connection.
 *
 * Returns: 0 if successfull and -1 otherwise.
 */
int mq_set_read_cb(amqp_bytes_t queue, mq_read_cb_t on_read, void *user_data)
{
	int err;

	mq_ctx.read_cb = on_read;

	if (!mq_ctx.amqp_io) {
		hal_log_error("Error amqp service not started");
		return -1;
	}

	err = l_io_set_read_handler(mq_ctx.amqp_io, on_receive,
				    user_data, NULL);
	if (!err) {
		l_io_destroy(mq_ctx.amqp_io);
		hal_log_error("Error on set up read handler on AMQP io\n");
		return -1;
	}

	/* Start a queue consumer */
	amqp_basic_consume(mq_ctx.conn, 1,
			queue,
			amqp_empty_bytes,
			0, /* no_local */
			1, /* no_ack */
			0, /* exclusive */
			amqp_empty_table);

	if (amqp_get_rpc_reply(mq_ctx.conn).reply_type !=
							AMQP_RESPONSE_NORMAL) {
		hal_log_error("Error while starting consumer");
		return -1;
	}

	return 0;
}

int mq_start(struct settings *settings, mq_connected_cb_t on_connected,
	     void *user_data)
{
	mq_ctx.connected_cb = on_connected;
	mq_ctx.connected_data = user_data;

	mq_ctx.conn_retry_timeout = l_timeout_create_ms(1, // start in oneshot
				start_connection,
				settings, NULL);

	return 0;
}

void mq_stop(void)
{
	amqp_rpc_reply_t r;
	int err;

	l_timeout_remove(mq_ctx.conn_retry_timeout);

	if (!mq_ctx.conn)
		return;

	r = amqp_channel_close(mq_ctx.conn, 1, AMQP_REPLY_SUCCESS);
	if (r.reply_type != AMQP_RESPONSE_NORMAL)
		hal_log_error("amqp_channel_close: %s",
			      mq_rpc_reply_string(r));

	r = amqp_connection_close(mq_ctx.conn, AMQP_REPLY_SUCCESS);
	if (r.reply_type != AMQP_RESPONSE_NORMAL)
		hal_log_error("amqp_connection_close: %s",
			      mq_rpc_reply_string(r));

	err = amqp_destroy_connection(mq_ctx.conn);
	if (err < 0)
		hal_log_error("amqp_destroy_connection: %s",
				amqp_error_string2(err));
}
