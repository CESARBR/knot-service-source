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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <glib.h>

#include <proto-net/knot_proto_net.h>
#include <proto-app/knot_proto_app.h>

/* Abstract unit socket namespace */
#define KNOT_UNIX_SOCKET	"knot"

static int sock;
static gboolean opt_add = FALSE;
static gboolean opt_schema = FALSE;
static gboolean opt_data = FALSE;
static char *opt_uuid = NULL;
static char *opt_json = NULL;
static gboolean opt_id = FALSE;
static gboolean opt_subs = FALSE;
static gboolean opt_unsubs = FALSE;

static GMainLoop *main_loop;

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
	knot_msg_register msg;
	knot_msg_credential crdntl;
	const char *devname = "dummy0";
	int len = strlen(devname);
	ssize_t nbytes;
	int err;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.type = KNOT_MSG_REGISTER_REQ;
	msg.hdr.payload_len = len;
	strncpy(msg.devName, devname, len);

	nbytes = write(sock, &msg, sizeof(msg.hdr) + len);
	if (nbytes < 0) {
		err = errno;
		printf("writev(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	memset(&crdntl, 0, sizeof(crdntl));
	nbytes = read(sock, &crdntl, sizeof(crdntl));
	if (nbytes < 0) {
		err = errno;
		printf("KNOT Register read(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	if (crdntl.result != KNOT_SUCCESS) {
		printf("KNOT Register: error(0x%02x)\n", crdntl.result);
		return -EPROTO;
	}

	printf("UUID: %*s\n", (int) sizeof(crdntl.uuid), crdntl.uuid);

	return 0;
}

static int cmd_unregister(void)
{
	knot_msg_unregister msg;
	knot_msg_result rslt;
	ssize_t nbytes;
	int err;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.type = KNOT_MSG_UNREGISTER_REQ;
	msg.hdr.payload_len = sizeof(msg.uuid);
	strncpy(msg.uuid, opt_uuid, sizeof(msg.uuid));

	nbytes = write(sock, &msg, sizeof(msg));
	if (nbytes < 0) {
		err = errno;
		printf("KNOT Unregister: %s(%d)\n", strerror(err), err);
		return -err;
	}

	memset(&rslt, 0, sizeof(rslt));
	nbytes = read(sock, &rslt, sizeof(rslt));
	if (nbytes < 0) {
		err = errno;
		printf("KNOT Unregister read(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	if (rslt.result != KNOT_SUCCESS) {
		printf("KNOT Unregister: error(0x%02x)\n", rslt.result);
		return -EPROTO;
	}

	printf("KNOT Unregister: OK\n");

	return 0;
}

static int cmd_schema(void)
{
	struct stat sb;
	int err;

	if (!opt_uuid) {
		printf("Device's UUID missing!\n");
		return -EINVAL;
	}

	/*
	 * In order to allow a more flexible way to manage schemas, ktool
	 * receives a JSON file and convert it to KNOT protocol format.
	 * Variable length argument could be another alternative, however
	 * it will not be intuitive to the users to inform the data id, type,
	 * and values.
	 */

	if (!opt_json) {
		printf("Device's SCHEMA missing!\n");
		return -EINVAL;
	}

	if (stat(opt_json, &sb) == -1) {
		err = errno;
		printf("json file: %s(%d)\n", strerror(err), err);
		return -err;
	}

	if ((sb.st_mode & S_IFMT) != S_IFREG) {
		printf("json file: invalid argument!\n");
		return -EINVAL;
	}

	return 0;
}

static int cmd_data(void)
{
	struct stat sb;
	int err;

	if (!opt_uuid) {
		printf("Device's UUID missing!\n");
		return -EINVAL;
	}

	/*
	 * In order to allow a more flexible way to manage data, ktool
	 * receives a JSON file and convert it to KNOT protocol format.
	 * Variable length argument could be another alternative, however
	 * it will not be intuitive to the users to inform the data id, type,
	 * and values.
	 */

	if (!opt_json) {
		printf("Device's data missing!\n");
		return -EINVAL;
	}

	if (stat(opt_json, &sb) == -1) {
		err = errno;
		printf("json file: %s(%d)\n", strerror(err), err);
		return -err;
	}

	if ((sb.st_mode & S_IFMT) != S_IFREG) {
		printf("json file: invalid argument!\n");
		return -EINVAL;
	}

	return 0;
}

static int cmd_id(void)
{
	int err;
	ssize_t nbytes;
	uint8_t datagram[128];

	memset(datagram, 0, sizeof(datagram));

	/*
	 * TODO: set knot protocol headers and payload
	 * Send UUID and token to identify a previously
	 * registered device.
	 */
	nbytes = write(sock, datagram, sizeof(datagram));
	if (nbytes < 0) {
		err = errno;
		printf("write(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	return 0;
}

static int cmd_subscribe(void)
{
	return -ENOSYS;
}

static int cmd_unsubscribe(void)
{
	return -ENOSYS;
}

/*
 * 'token' and 'uuid' are returned by registration process. Later a
 * command line prompt may be displayed to the user allowing an
 * interactive mode to be able to receive messages and change properties
 * on demand. Options should be provided to inform invalid 'token'/'uuid'
 * to allow testing error conditions, or inform previously registered
 * devices. Commands are based on KNOT protocol, and they should be mapped
 * to any specific backend.
 */

static GOptionEntry schema_options[] = {
	{ "uuid", 0, 0, G_OPTION_ARG_STRING, &opt_uuid,
						"Device's UUID", NULL },
	{ "json", 0, 0, G_OPTION_ARG_FILENAME, &opt_json,
						"Path to JSON file", NULL },
	{ NULL },
};

static GOptionEntry options[] = {

	{ "add", 'a', 0, G_OPTION_ARG_NONE, &opt_add,
				"Register a device to Meshblu",
				NULL },
	{ "remove", 'r', 0, G_OPTION_ARG_STRING, &opt_uuid,
				"Unregister a device from Meshblu",
				NULL },
	{ "schema", 'h', 0, G_OPTION_ARG_NONE, &opt_schema,
				"Get/Put JSON representing device's schema",
				NULL },
	{ "data", 'd', 0, G_OPTION_ARG_NONE, &opt_data,
				"Sends data of a given device", NULL },
	{ "id", 'i', 0, G_OPTION_ARG_NONE, &opt_id,
				"Identify a Meshblu device",
				NULL },
	{ "subscribe", 's', 0, G_OPTION_ARG_NONE, &opt_subs,
				"Subscribe for messages of a given device",
				NULL },
	{ "unsubscribe", 'u', 0, G_OPTION_ARG_NONE, &opt_unsubs,
				"Unsubscribe for messages", NULL },
	{ NULL },
};

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GOptionGroup *schema_group;
	GError *gerr = NULL;
	int err = 0;

	printf("KNOT Tool\n");

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	/* Define options for setting or reading JSON schema of a given
	   device(UUID):
	    read:
		ktool --schema --uuid=value
	    write:
		ktool --schema --uuid=value --json=filename
	 */
	schema_group = g_option_group_new("schema", "Schema options",
					"Show all schema options", NULL, NULL);
	g_option_context_add_group(context, schema_group);
	g_option_group_add_entries(schema_group, schema_options);

	/* TODO: Use GOptionGroup to inform parameters */
	if (!g_option_context_parse(context, &argc, &argv, &gerr)) {
		printf("Invalid arguments: %s\n", gerr->message);
		g_error_free(gerr);
		g_option_context_free(context);
		exit(EXIT_FAILURE);
	}

	g_option_context_free(context);

	signal(SIGTERM, sig_term);
	signal(SIGINT, sig_term);
	main_loop = g_main_loop_new(NULL, FALSE);

	sock = unix_connect();
	if (sock == -1) {
		err = -errno;
		printf("connect(): %s (%d)\n", strerror(-err), -err);
		return err;
	}

	if (opt_add) {
		printf("Registering node ...\n");
		err = cmd_register();
	} else if (opt_schema) {
		printf("Registering JSON schema for a device ...\n");
		err = cmd_schema();
	} else if (opt_data) {
		printf("Setting data for a device ...\n");
		err = cmd_data();
	} else if (opt_uuid) {
		printf("Unregistering node: %s\n", opt_uuid);
		err = cmd_unregister();
	} else if (opt_id) {
		printf("Identifying node ...\n");
		err = cmd_id();
	} else if (opt_subs) {
		printf("Subscribing node ...\n");
		err = cmd_subscribe();
	} else if (opt_unsubs) {
		printf("Unsubscribing node ...\n");
		err = cmd_unsubscribe();
	}

	if (err < 0) {
		close(sock);
		return err;
	}

	g_main_loop_run(main_loop);
	g_main_loop_unref(main_loop);

	printf("Exiting\n");

	close(sock);

	return 0;
}
