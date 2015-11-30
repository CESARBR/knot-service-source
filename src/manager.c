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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <json-c/json.h>

#include <glib.h>

#include <proto-net/knot_proto_net.h>
#include <proto-app/knot_proto_app.h>

#include "node.h"
#include "proto.h"
#include "serial.h"
#include "manager.h"

/*
 * Device session storing the connected
 * device context: 'drivers' and file descriptors
 */
struct session {
	unsigned int radio_id;	/* Radio event source */
	unsigned int proto_id;	/* TCP/backend event source */
	GIOChannel *proto_io;	/* Protocol GIOChannel reference */
	struct node_ops *ops;
	char *uuid;
	char *token;
};

static unsigned int server_watch_id;

extern struct proto_ops proto_http;
#ifdef HAVE_WEBSOCKETS
extern struct proto_ops proto_ws;
#endif

static struct proto_ops *proto_ops[] = {
	&proto_http,
#ifdef HAVE_WEBSOCKETS
	&proto_ws,
#endif
	NULL
};

/*
 * Select default IoT protocol index. TODO: Later it can
 * be member of 'session' struct, allowing nodes to select
 * dynamically the wanted IoT protocol at run time.
 */
static int proto_index = 0;

/* TODO: After adding buildroot, investigate if it is possible
 * to add macros for conditional builds, or a dynamic builtin
 * plugin mechanism.
 */
extern struct node_ops unix_ops;
extern struct node_ops serial_ops;
#ifdef HAVE_RADIOHEAD
extern struct node_ops nrf24_ops;
extern struct node_ops tcp_ops;
#endif

static struct node_ops *node_ops[] = {
	&unix_ops,
	&serial_ops,
#ifdef HAVE_RADIOHEAD
	&nrf24_ops,
	&tcp_ops,
#endif
	NULL
};

struct owner {
	char *uuid;
	char *token;
};

static struct owner *owner;

static GKeyFile *load_config(const char *file)
{
	GError *gerr = NULL;
	GKeyFile *keyfile;

	keyfile = g_key_file_new();

	g_key_file_set_list_separator(keyfile, ',');

	if (!g_key_file_load_from_file(keyfile, file, 0, &gerr)) {
		printf("Parsing %s: %s\n", file, gerr->message);
		g_error_free(gerr);
		g_key_file_free(keyfile);
		return NULL;
	}

	return keyfile;
}

static int parse_config(GKeyFile *config)
{
	GError *gerr = NULL;
	char *uuid, *token;

	uuid = g_key_file_get_string(config, "Credential", "UUID", &gerr);
	if (gerr) {
		printf("%s", gerr->message);
		g_clear_error(&gerr);
		return -EINVAL;
	} else
		printf("UUID=%s\n", uuid);

	token = g_key_file_get_string(config, "Credential", "TOKEN", &gerr);
	if (gerr) {
		printf("%s", gerr->message);
		g_clear_error(&gerr);
		g_free(uuid);
		return -EINVAL;
	} else
		printf("TOKEN=%s\n", token);

	/* TODO: UUID & TOKEN consistency */

	owner = g_new0(struct owner, 1);
	owner->uuid = uuid;
	owner->token= token;

	return 0;
}

static int parse_device_info(const char *json_str, struct session *session)
{
	json_object *jobj,*json_uuid, *json_token;
	const char *uuid, *token;

	jobj = json_tokener_parse(json_str);
	if (jobj == NULL)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj, "uuid", &json_uuid))
		return -EINVAL;

	if (!json_object_object_get_ex(jobj, "token", &json_token))
		return -EINVAL;

	uuid = json_object_get_string(json_uuid);
	token = json_object_get_string(json_token);

	session->uuid = g_strdup(uuid);
	session->token = g_strdup(token);

	return 0;
}

static gboolean node_io_watch(GIOChannel *io, GIOCondition cond,
			      gpointer user_data)
{
	struct session *session = user_data;
	struct node_ops *ops = session->ops;
	uint8_t dgram[128];
	const knot_msg_header *hdr = (const knot_msg_header *) dgram;
	struct json_buffer jbuf;
	ssize_t nbytes;
	int sock, proto_sock, err = 0;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		return FALSE;

	sock = g_io_channel_unix_get_fd(io);

	nbytes = ops->recv(sock, dgram, sizeof(dgram));
	if (nbytes < 0) {
		err = errno;
		printf("readv(): %s(%d)\n", strerror(err), err);
		return FALSE;
	}

	printf("KNOT OP: 0x%02X LEN: %02x\n", hdr->type, hdr->payload_len);

	proto_sock = g_io_channel_unix_get_fd(session->proto_io);
	switch (hdr->type) {
	case KNOT_MSG_REGISTER_REQ:
		memset(&jbuf, 0, sizeof(jbuf));
		err = proto_ops[proto_index]->signup(proto_sock,
						owner->uuid, &jbuf);
		if (err < 0) {
			printf("manager signup: %s(%d)\n",
						strerror(-err), -err);
			return FALSE;
		}

		parse_device_info(jbuf.data, session);
		free(jbuf.data);
		break;
	default:
		/* TODO: reply unknown command */
		break;
	}

	if (err)
		printf("KNOT IoT proto error: %s(%d)\n", strerror(err), err);

	return TRUE;
}

static void node_io_destroy(gpointer user_data)
{

	struct session *session = user_data;
	int sock;

	/* Mark as removed */
	session->radio_id = 0;

	/*
	 * When the protocol connection (backend) is dropped
	 * call signoff & unref the GIOChannel.
	 */
	sock = g_io_channel_unix_get_fd(session->proto_io);
	proto_ops[proto_index]->close(sock);
	g_io_channel_unref(session->proto_io);

	if (session->proto_id)
		g_source_remove(session->proto_id);

	if (session->token)
		g_free(session->token);

	if (session->uuid)
		g_free(session->uuid);

	g_free(session);
}

static gboolean proto_io_watch(GIOChannel *io, GIOCondition cond,
					       gpointer user_data)
{
	/* Return FALSE to remove protocol GIOChannel reference */

	return FALSE;
}

static void proto_io_destroy(gpointer user_data)
{
	struct session *session = user_data;

	/*
	 * Remove Unix socket GIOChannel watch when protocol
	 * socket disconnects. Removing the watch triggers
	 * channe unref and consequently disconnection of
	 * the Unix socket
	 */

	/* Mark protocol watch as removed */
	session->proto_id = 0;

	if (session->radio_id)
	    g_source_remove(session->radio_id);
}

static gboolean accept_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct node_ops *ops = user_data;
	GIOChannel *node_io, *proto_io;
	int sockfd, srv_sock, proto_sock;
	GIOCondition watch_cond;
	struct session *session;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR))
		return FALSE;

	srv_sock = g_io_channel_unix_get_fd(io);

	printf("%p accept()\n", ops);
	sockfd = ops->accept(srv_sock);
	if (sockfd < 0) {
		printf("%p accept(): %s(%d)\n", ops,
					strerror(-sockfd), -sockfd);
		return FALSE;
	}

	node_io = g_io_channel_unix_new(sockfd);
	g_io_channel_set_close_on_unref(node_io, TRUE);

	proto_sock = proto_ops[proto_index]->connect();
	proto_io = g_io_channel_unix_new(proto_sock);
	g_io_channel_set_close_on_unref(proto_io, TRUE);

	session = g_new0(struct session, 1);
	/* Watch for unix socket disconnection */
	watch_cond = G_IO_HUP | G_IO_NVAL | G_IO_ERR | G_IO_IN;
	session->radio_id = g_io_add_watch_full(node_io,
				G_PRIORITY_DEFAULT, watch_cond,
				node_io_watch, session,
				node_io_destroy);

	/* Keep only one ref: GIOChannel watch */
	g_io_channel_unref(node_io);

	/* Watch for TCP socket disconnection */
	watch_cond = G_IO_HUP | G_IO_NVAL | G_IO_ERR;
	session->proto_id = g_io_add_watch_full(proto_io,
				G_PRIORITY_DEFAULT, watch_cond,
				proto_io_watch, session,
				proto_io_destroy);

	/* Keep one reference to call sign-off */
	session->proto_io = proto_io;

	/* TODO: Create refcount */
	session->ops = ops;

	return TRUE;
}

int manager_start(const char *file, const char *proto, const char *tty)
{
	GIOCondition cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	GIOChannel *server_io;
	GKeyFile *keyfile;
	int err, sock, i;

	keyfile = load_config(file);
	if (keyfile == NULL)
		return -ENOENT;

	err = parse_config(keyfile);

	g_key_file_free(keyfile);

	if (err	< 0)
		return err;

	/* Tell Serial which port to use */
	if (tty)
		serial_load_config(tty);

	/*
	 * Selecting meshblu IoT protocols & services: HTTP/REST,
	 * Websockets, Socket IO, MQTT, COAP. 'proto_ops' drivers
	 * implements an abstraction similar to WEB client operations.
	 * TODO: later support dynamic protocol selection.
	 */

	for (i = 0; proto_ops[i]; i++) {
		if (strcmp(proto, proto_ops[i]->name) != 0)
			continue;

		if (proto_ops[i]->probe() < 0)
			return -EIO;

		printf("proto_ops(%p): %s\n", proto_ops[i], proto_ops[i]->name);
		proto_index = i;
	}

	/*
	 * Probing all access technologies: nRF24L01, BTLE, TCP, Unix
	 * sockets, Serial, etc. 'node_ops' drivers implements an
	 * abstraction similar to server sockets, it enables incoming
	 * connections and provides functions to receive and send data
	 * streams from/to KNOT nodes.
	 */
	for (i = 0; node_ops[i]; i++) {

		/* Ignore Serial driver if port is not informed */
		if ((strcmp("Serial", node_ops[i]->name) == 0) && tty == NULL)
			continue;

		if (node_ops[i]->probe() < 0)
			continue;

		printf("node_ops(%p): %s\n", node_ops[i], node_ops[i]->name);
		sock = node_ops[i]->listen();
		if (sock < 0) {
			err = sock;
			printf("%p listen(): %s(%d)\n", node_ops[i],
						strerror(-err), -err);
			node_ops[i]->remove();
			continue;
		}

		server_io = g_io_channel_unix_new(sock);
		g_io_channel_set_close_on_unref(server_io, TRUE);
		g_io_channel_set_flags(server_io, G_IO_FLAG_NONBLOCK, NULL);

		/* Use node_ops as parameter to allow multi drivers */
		server_watch_id = g_io_add_watch(server_io, cond, accept_cb,
								node_ops[i]);
		g_io_channel_unref(server_io);
	}

	return 0;
}

void manager_stop(void)
{
	int i;

	/* Remove only previously loaded modules */
	for (i = 0; node_ops[i]; i++)
		node_ops[i]->remove();

	proto_ops[proto_index]->remove();

	if (server_watch_id)
		g_source_remove(server_watch_id);

	if (owner) {
		g_free(owner->uuid);
		g_free(owner->token);
		g_free(owner);
	}
}
