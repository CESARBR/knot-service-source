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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <math.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <glib.h>
#include <fcntl.h>
#include <termios.h>
#include <json-c/json.h>

#include <knot_protocol.h>
#include <knot_types.h>

struct schema {
	GSList *list;
	int err;
};

typedef void (*json_object_func_t) (struct json_object *jobj,
					const char *key, void *user_data);

static int sock;
static char *opt_unix = "knot";
static gboolean opt_add = FALSE;
static gboolean opt_rm = FALSE;
static gboolean opt_schema = FALSE;
static gboolean opt_data = FALSE;
static char *opt_uuid = NULL;
static char *opt_token = NULL;
static char *opt_json = NULL;
static char *opt_tty = NULL;
static uint64_t opt_device_id = 0;
static gboolean opt_cfg = FALSE;
static gboolean opt_id = FALSE;
static gboolean opt_subs = FALSE;
static gboolean opt_unsubs = FALSE;
static gboolean opt_con = FALSE;

static GMainLoop *main_loop;

static ssize_t receive(int sockfd, void *buffer, size_t len)
{
	ssize_t nbytes;
	int err, msg_size, offset, remaining;
	knot_msg_header *hdr = buffer;

	nbytes = read(sockfd, buffer, len);
	if (nbytes < 0) {
		err = -errno;
		printf("read() error\n");
		return err;
	}
	msg_size = hdr->payload_len + 2;

	offset = nbytes;

	while (offset < msg_size) {
		remaining = len - offset;
		if (remaining > 0)
			nbytes = read(sock, buffer + offset, remaining);
		else
			goto done;

		err = errno;
		if (nbytes < 0 && err != EAGAIN)
			goto done;
		else if (nbytes > 0)
			offset += nbytes;
	}
done:
	return offset;
}

static int unix_connect(const char *opt_unix)
{
	int err, sock;
	struct sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sock < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	/* Abstract namespace: first character must be null */
	memcpy(addr.sun_path + 1, opt_unix, strlen(opt_unix));

	/*
	 * FIXME:
	 * Is it necessary to close the socket when error happens
	 * knot-hal/src/nrfd/manager.c does not close, which one
	 * is better?
	 */
	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		err = -errno;
		close(sock);
		return err;
	}

	return sock;
}

static int serial_connect(char *opt_tty)
{
	struct termios term;
	int ttyfd;

	memset(&term, 0, sizeof(term));
	/*
	 * 8-bit characters, no parity bit,no Bit mask for data bits
	 * only need 1 stop bit
	 */
	term.c_cflag &= ~PARENB;
	term.c_cflag &= ~CSTOPB;
	term.c_cflag &= ~CSIZE;
	term.c_cflag |= CS8;
	/* No flow control*/
	term.c_cflag &= ~CRTSCTS;
	/* Read block until 2 bytes arrives */
	term.c_cc[VMIN] = 2;
	/* 0.1 seconds read timeout */
	term.c_cc[VTIME] = 1;
	/* Turn on READ & ignore ctrl lines */
	term.c_cflag |= CREAD | CLOCAL;

	cfsetospeed(&term, B9600);
	cfsetispeed(&term, B9600);

	ttyfd = open(opt_tty, O_RDWR | O_NOCTTY);
	if (ttyfd < 0)
		return -errno;
	/*
	 * Flushes the input and/or output queue and
	 * Set the new options for the port
	 */
	tcflush(ttyfd, TCIFLUSH);
	tcsetattr(ttyfd, TCSANOW, &term);

	return ttyfd;
}

static void print_json_value(struct json_object *jobj,
					const char *key, void *user_data)
{
	enum json_type type;
	const char *name;

	type = json_object_get_type(jobj);
	name = json_type_to_name(type);

	switch (type) {
	case json_type_null:
		break;
	case json_type_boolean:
		printf("%s(%s)\n", json_object_get_boolean(jobj) ?
					"true" : "false", name);
		break;
	case json_type_double:
		printf("%lf(%s)\n", json_object_get_double(jobj), name);
		break;
	case json_type_int:
		printf("%d(%s)\n", json_object_get_int(jobj), name);
		break;
	case json_type_string:
		printf("%s(%s)\n", json_object_get_string(jobj), name);
		break;
	case json_type_object:
		break;
	case json_type_array:
		break;
	}
}

static void load_schema(struct json_object *jobj,
					const char *key, void *user_data)
{
	struct schema *schema = user_data;
	knot_msg_schema *entry;
	GSList *ltmp;
	enum json_type type;
	const char *data_name = NULL;
	int intval, err = EINVAL;

	/*
	 * This callback is called for all entries: skip
	 * parsing if one error has been detected previously.
	 */
	if (schema->err)
		return;

	type = json_object_get_type(jobj);

	switch (type) {
	case json_type_null:
	case json_type_boolean:
	case json_type_double:
	case json_type_object:
	case json_type_array:
		/* Not available */
		break;
	case json_type_int:
		intval = json_object_get_int(jobj);

		if (strcmp("sensor_id", key) == 0) {
			entry = g_new0(knot_msg_schema, 1);
			entry->sensor_id = intval;
			schema->list = g_slist_append(schema->list, entry);
			err = 0;
		} else if (strcmp("value_type", key) == 0) {
			ltmp = g_slist_last(schema->list);
			if (!ltmp)
				goto done;

			/*
			*FIXME: if value_type appers before sensor_id? or other
			*wrong order
			*/
			entry = ltmp->data;
			entry->values.value_type = intval;
			err = 0;
		} else if (strcmp("unit", key) == 0) {
			ltmp = g_slist_last(schema->list);
			if (!ltmp)
				goto done;

			/*
			*FIXME: if unit appers before sensor_id? or other
			*wrong order
			*/
			entry = ltmp->data;
			entry->values.unit = intval;
			err = 0;
		} else if (strcmp("type_id", key) == 0) {
			ltmp = g_slist_last(schema->list);
			if (!ltmp)
				goto done;

			/*
			*FIXME: if type_id appers before sensor_id? or other
			*wrong order
			*/
			entry = ltmp->data;
			entry->values.type_id = intval;
			err = 0;
		}

		break;
	case json_type_string:
		data_name = json_object_get_string(jobj);

		if (strcmp("name", key) != 0 || data_name == NULL)
			goto done;

		ltmp = g_slist_last(schema->list);
		if (!ltmp)
			goto done;
		/*
		*FIXME: if name comes before sensor_id,value_type,unit, type_id
		*or other wrong order
		*/
		entry = ltmp->data;
		strcpy(entry->values.name, data_name);
		err = 0;
		break;
	}

done:
	schema->err = err;
}

static void read_json_entry(struct json_object *jobj,
					const char *key, void *user_data)
{
	knot_msg_data *msg = user_data;
	knot_data *kdata = &(msg->payload);
	knot_value_type_bool *kbool;
	knot_value_type_float *kfloat;
	knot_value_type_int *kint;
	int32_t ipart, fpart;
	enum json_type type;
	const char *str;

	type = json_object_get_type(jobj);

	if ((strcmp("sensor_id", key) == 0) && (type == json_type_int))
		msg->sensor_id = json_object_get_int(jobj);
	else if (strcmp("value", key) == 0) {
		switch (type) {
		case json_type_boolean:
			kbool = (knot_value_type_bool *) &(kdata->values.val_b);
			*kbool = json_object_get_boolean(jobj);
			msg->hdr.payload_len = sizeof(knot_value_type_bool);
			break;
		case json_type_double:
			/* Trick to get integral and fractional parts */
			str = json_object_get_string(jobj);
			/* FIXME: how to handle overflow? */
			if (sscanf(str, "%d.%d", &ipart, &fpart) != 2)
				break;

			kfloat = (knot_value_type_float *) &(kdata->
								values.val_f);
			kfloat->value_int = ipart;
			kfloat->value_dec = fpart;
			kfloat->multiplier = 1; /* TODO: */
			msg->hdr.payload_len = sizeof(knot_value_type_float);
			break;
		case json_type_int:
			kint = (knot_value_type_int *) &(kdata->values.val_i);
			kint->value = json_object_get_int(jobj);
			kint->multiplier = 1;
			msg->hdr.payload_len = sizeof(knot_value_type_int);
			break;
		case json_type_string:
		case json_type_null:
			/* FIXME: */
			break;

		/* FIXME: */
		case json_type_object:
			break;
		case json_type_array:
			break;
		}
	} else {
		printf("Unexpected JSON entry!\n");
	}
}

static void json_object_foreach(struct json_object *jobj,
				json_object_func_t func, void *user_data)
{
	struct json_object *next;
	enum json_type type;
	int len, i;

	if (!jobj)
		return;

	json_object_object_foreach(jobj, key, val) {
		type = json_object_get_type(val);
		switch (type) {
		case json_type_null:
		case json_type_boolean:
		case json_type_double:
		case json_type_int:
		case json_type_string:
			func(val, key, user_data);
			break;
		case json_type_object:
			next = json_object_get(val);
			json_object_foreach(next, func, user_data);
			json_object_put(next);
			break;
		case json_type_array:
			len = json_object_array_length(val);
			for (i = 0; i < len; i++) {
				next = json_object_array_get_idx(val, i);
				json_object_foreach(next, func, user_data);
			}
			break;
		}
	}
}

static int authenticate(const char *uuid, const char *token)
{
	knot_msg_authentication msg;
	knot_msg_result resp;
	ssize_t nbytes;
	int err;

	memset(&msg, 0, sizeof(msg));
	memset(&resp, 0, sizeof(resp));

	msg.hdr.type = KNOT_MSG_AUTH_REQ;
	msg.hdr.payload_len = sizeof(msg.uuid) + sizeof(msg.token);
	memcpy(msg.uuid, uuid, sizeof(msg.uuid));
	memcpy(msg.token, token, sizeof(msg.token));

	nbytes = write(sock, &msg, sizeof(msg.hdr) + msg.hdr.payload_len);
	if (nbytes < 0) {
		err = errno;
		printf("write(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	nbytes = receive(sock, &resp, sizeof(resp));
	if (nbytes < 0) {
		err = errno;
		printf("read(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	if (resp.result != KNOT_SUCCESS) {
		printf("error(0x%02x)\n", resp.result);
		return -EPROTO;
	}

	return 0;
}

static int write_knot_data(struct json_object *jobj)
{
	knot_msg_data msg;
	knot_msg_result resp;
	ssize_t nbytes;
	int err;

	memset(&msg, 0, sizeof(msg));
	memset(&resp, 0, sizeof(resp));

	/*
	 * The current implementation is limited to only data entry.
	 * JSON files should not contain array elements.
	 */

	json_object_foreach(jobj, read_json_entry, &msg);

	if (msg.hdr.payload_len == 0) {
		printf("JSON parsing error: data not found!\n");
		return -EINVAL;
	}

	msg.hdr.type = KNOT_MSG_DATA;
	/* Payload len is set by read_json_entry() */

	msg.hdr.payload_len += sizeof(msg.sensor_id);
	nbytes = write(sock, &msg, sizeof(msg.hdr) + msg.hdr.payload_len);
	if (nbytes < 0) {
		err = errno;
		printf("write(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	nbytes = receive(sock, &resp, sizeof(resp));
	if (nbytes < 0) {
		err = errno;
		printf("read(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	if (resp.result != KNOT_SUCCESS) {
		printf("error(0x%02x)\n", resp.result);
		return -EPROTO;
	}

	return 0;
}

static int send_schema(GSList *list)
{
	knot_msg_schema msg;
	knot_msg_schema *entry;
	GSList *l;
	ssize_t nbytes;
	int err;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.type = KNOT_MSG_SCHEMA;

	for (l = list; l;) {
		entry = l->data;

		msg.hdr.payload_len = sizeof(entry->values) +
						sizeof(entry->sensor_id);

		memcpy(&msg.values, &entry->values, sizeof(entry->values));
		msg.sensor_id = entry->sensor_id;


		l = g_slist_next(l);
		if (!l)
			msg.hdr.type = KNOT_MSG_SCHEMA_END;

		nbytes = write(sock, &msg, sizeof(msg.hdr) +
						msg.hdr.payload_len);
		if (nbytes < 0) {
			err = errno;
			printf("write(): %s(%d)\n", strerror(err), err);
			return -err;
		}
	}

	return 0;
}

static int cmd_register(void)
{
	knot_msg_register msg;
	knot_msg_credential crdntl;
	const char *devname = "dummy0\0";
	int len = strlen(devname);
	ssize_t nbytes;
	int err;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.type = KNOT_MSG_REGISTER_REQ;
	msg.hdr.payload_len = len + sizeof(msg.id);
	msg.id = opt_device_id ? opt_device_id : 0x123456789abcdef;
	memcpy(msg.devName, devname, len);

	nbytes = write(sock, &msg, sizeof(msg.hdr) + msg.hdr.payload_len);
	if (nbytes < 0) {
		err = errno;
		printf("writev(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	memset(&crdntl, 0, sizeof(crdntl));
	nbytes = receive(sock, &crdntl, sizeof(crdntl));
	if (nbytes < 0) {
		err = errno;
		printf("KNOT Register read(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	if (crdntl.result != KNOT_SUCCESS) {
		printf("KNOT Register: error(0x%02x)\n", crdntl.result);
		return -EPROTO;
	}

	printf("UUID: %.*s\n", (int) sizeof(crdntl.uuid), crdntl.uuid);
	printf("TOKEN: %.*s\n", (int) sizeof(crdntl.token), crdntl.token);

	return 0;
}

static int cmd_unregister(void)
{
	knot_msg_unregister msg;
	knot_msg_result rslt;
	ssize_t nbytes;
	int err;

	/*
	 * When token is informed try authenticate first. Leave this
	 * block sequential to allow testing unregistering without
	 * previous authentication.
	 */

	if (opt_token) {
		printf("Authenticating ...\n");
		err = authenticate(opt_uuid, opt_token);
	}

	memset(&msg, 0, sizeof(msg));
	msg.hdr.type = KNOT_MSG_UNREGISTER_REQ;
	msg.hdr.payload_len = 0;

	nbytes = write(sock, &msg, sizeof(msg));
	if (nbytes < 0) {
		err = errno;
		printf("KNOT Unregister: %s(%d)\n", strerror(err), err);
		return -err;
	}

	memset(&rslt, 0, sizeof(rslt));
	nbytes = receive(sock, &rslt, sizeof(rslt));
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

static int cmd_schema(gboolean auth)
{
	struct json_object *jobj;
	struct schema schema;
	struct stat sb;
	int err = 0;

	/*
	 * Checks if the device needs to be authenticated or already is
	 * (e.g when calling from cmd_connect)
	 */
	if(!auth)
		goto done;

	if (!opt_uuid) {
		printf("Device's UUID missing!\n");
		return -EINVAL;
	}

	/*
	 * When token is informed try authenticate first. Leave this
	 * block sequential to allow testing sending schema without
	 * previous authentication.
	 */


	if (opt_token) {
		printf("Authenticating ...\n");
		err = authenticate(opt_uuid, opt_token);
	}

done:
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

	jobj = json_object_from_file(opt_json);
	if (!jobj) {
		printf("json file(%s): failed to read from file!\n", opt_json);
		return -EINVAL;
	}

	memset(&schema, 0, sizeof(schema));
	json_object_foreach(jobj, load_schema, &schema);
	if (!schema.err)
		err = send_schema(schema.list);

	g_slist_free_full(schema.list, g_free);
	json_object_put(jobj);

	return err;
}

static int cmd_data(void)
{
	struct json_object *jobj;
	struct stat sb;
	int err;

	if (!opt_uuid) {
		printf("Device's UUID missing!\n");
		return -EINVAL;
	}

	/*
	 * When token is informed try authenticate first. Leave this
	 * block sequential to allow testing sending data without
	 * previous authentication.
	 */
	if (opt_token) {
		printf("Authenticating ...\n");
		err = authenticate(opt_uuid, opt_token);
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

	jobj = json_object_from_file(opt_json);
	if (!jobj) {
		printf("json file(%s): failed to read from file!\n", opt_json);
		return -EINVAL;
	}

	json_object_foreach(jobj, print_json_value, NULL);
	write_knot_data(jobj);
	json_object_put(jobj);

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

static gboolean send_config(gpointer user_data)
{
	struct json_object *jobj;

	printf ("Sending config \n");

	jobj = json_object_from_file("json/data-temperature.json");
	if (!jobj) {
		printf("json file(%s): failed to read from file!\n", opt_json);
		return FALSE;
	}
	json_object_foreach(jobj, print_json_value, NULL);
	write_knot_data(jobj);
	json_object_put(jobj);

	return TRUE;
}

static gboolean proto_receive(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	knot_msg recv;
	knot_msg resp;
	ssize_t nbytes;
	int err, sock;
	struct json_object *jobj;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		g_main_loop_quit(main_loop);
		return FALSE;
	}

	sock = g_io_channel_unix_get_fd(io);

	nbytes = read(sock, &recv, sizeof(recv));
	if (nbytes < 0) {
		err = errno;
		printf("read(): %s(%d)\n", strerror(err), err);
		return TRUE;
	}

	printf("message: %i", recv.hdr.type);
	switch (recv.hdr.type) {
	case KNOT_MSG_SET_CONFIG:
		printf("sensor_id: %d\n", recv.config.sensor_id);
		printf("event_flags: %d\n", recv.config.values.event_flags);
		printf("time_sec: %d\n", recv.config.values.time_sec);
		printf("lower_limit: %d.%d\n",
				recv.config.values.lower_limit.val_f.value_int,
				recv.config.values.lower_limit.val_f.value_dec);
		printf("upper_limit: %d.%d\n",
				recv.config.values.upper_limit.val_f.value_int,
				recv.config.values.upper_limit.val_f.value_dec);
		resp.hdr.type = KNOT_MSG_CONFIG_RESP;
		resp.hdr.payload_len = sizeof(resp.item.sensor_id);
		resp.item.sensor_id = recv.config.sensor_id;
		nbytes = write(sock, &resp, sizeof(knot_msg_item));
		if (nbytes < 0) {
			err = errno;
			printf("node_ops: %s(%d)\n", strerror(err), err);
			return TRUE;
		}
		/*
		 * For testing purposes, assuming the config is to send data
		 * each 10 seconds.
		 */
		g_timeout_add_seconds(10, send_config,NULL);
		break;
	case KNOT_MSG_SET_DATA:
		printf("sensor_id: %d\n", recv.data.sensor_id);
		printf("value: %d.%d\n",
				recv.data.payload.values.val_f.value_int,
				recv.data.payload.values.val_f.value_dec);
		resp.hdr.type = KNOT_MSG_DATA_RESP;
		resp.hdr.payload_len = sizeof(knot_data) +
						sizeof(resp.data.sensor_id);
		resp.data.sensor_id = recv.data.sensor_id;
		memcpy(&(resp.data.payload), &(recv.data.payload),
							sizeof(knot_data));
		nbytes = write(sock, &resp, sizeof(knot_msg_data));
		if (nbytes < 0) {
			err = errno;
			printf("node_ops: %s(%d)\n", strerror(err), err);
			return TRUE;
		}
		break;
	case KNOT_MSG_GET_DATA:
		/*
		 * Based on the sensor_id, sends the correct data json. The
		 * test folders only contains schema and data for the sensor_ids
		 * 251,252 and 253.
		 */
		switch (recv.item.sensor_id) {
		case 251:
			jobj = json_object_from_file("json/data-volume.json");
			break;
		case 252:
			jobj = json_object_from_file("json/data-temperature.json");
			break;
		case 253:
			jobj = json_object_from_file("json/data-switch.json");
			break;
		default:
			jobj = NULL;
		}

		if (!jobj) {
			printf("json file(%s): failed to read from file!\n",
								opt_json);
			return -EINVAL;
		}

		json_object_foreach(jobj, print_json_value, NULL);
		write_knot_data(jobj);
		json_object_put(jobj);

		break;
	case KNOT_MSG_UNREGISTER_REQ:
		resp.hdr.type = KNOT_MSG_UNREGISTER_RESP;
		nbytes = write(sock, &resp, sizeof(knot_msg_header) + resp.hdr.payload_len);
		if (nbytes < 0) {
			err = errno;
			printf("node_ops: %s(%d)\n", strerror(err), err);
			return TRUE;
		}

		break;
	}

	return TRUE;
}

static int cmd_config(void)
{
	int err;

	if (!opt_uuid) {
		printf("Device's UUID missing!\n");
		return -EINVAL;
	}

	if (!opt_token) {
		printf("Device's TOKEN missing!\n");
		return -EINVAL;
	}

	/*
	 * When token is informed try authenticate first. Leave this
	 * block sequential to allow testing sending data without
	 * previous authentication.
	 */
	printf("Authenticating ...\n");
	err = authenticate(opt_uuid, opt_token);

	if (err) {
		printf("Authentication failed!\n");
		return -EINVAL;
	}

	return 0;
}

static int cmd_connect(void)
{
	int err;

	/* If uuid and token are given, register. Otherwise, authenticates */
	if (opt_uuid && opt_token) {
		err = authenticate(opt_uuid, opt_token);
		if (err) {
			printf("Error authenticating\n");
			return -EINVAL;
		}
	} else {
		err = cmd_register();
		if (err) {
			printf("Error registering\n");
			return -EINVAL;
		}
	}

	cmd_schema(FALSE);

	/*
	 * The listener is started when the ktool starts.
	 * No need to do anything.
	 */

	return 0;
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
static GOptionEntry options[] = {
	{ "device-id", 'I', 0, G_OPTION_ARG_INT64, &opt_device_id,
						"Device's ID", "ID" },
	{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &opt_uuid,
						"Device's UUID", "UUID" },
	{ "token", 't', 0, G_OPTION_ARG_STRING, &opt_token,
						"Device's token", "TOKEN" },
	{ "json", 'j', 0, G_OPTION_ARG_FILENAME, &opt_json,
						"Path to JSON file",
						"json/data-temperature" },
	{ "unix", 'U', 0, G_OPTION_ARG_STRING, &opt_unix,
			"Specify unix socket to connect. Default: knot",
			"[ knot | :thing:nrfd]" },
	{ "tty", 'T', 0, G_OPTION_ARG_STRING, &opt_tty,
			"Specify TTY to connect.", "/dev/ttyUSB0" },
	{ NULL },
};

static GOptionEntry commands[] = {

	{ "add", 0, 0, G_OPTION_ARG_NONE, &opt_add,
	"Register a device to Meshblu. Eg: ./ktool --add [-U=value | T=value| I=value]",
				NULL },
	{ "remove", 0, 0, G_OPTION_ARG_NONE, &opt_rm,
		"Unregister a device from Meshblu. " \
		"Eg: ./ktool --remove -u=value -t=value [-U=value | T=value]",
				NULL },
	{ "schema", 0, 0, G_OPTION_ARG_NONE, &opt_schema,
	"Get/Put JSON representing device's schema. " \
	"Eg: ./ktool --schema -u=value -t=value -j=value [-U=value | T=value]",
				NULL },
	{ "data", 0, 0, G_OPTION_ARG_NONE, &opt_data,
	"Sends data of a given device. " \
	"Eg: ./ktool --data -u=value -t=value -j=value [-U=value | -T=value]",
				NULL},
	{ "id", 0, 0, G_OPTION_ARG_NONE, &opt_id,
		"Identify (Authenticate) a Meshblu device",
				NULL },
	{ "subscribe", 0, 0, G_OPTION_ARG_NONE, &opt_subs,
		"Subscribe for messages of a given device",
				NULL },
	{ "unsubscribe", 0, 0, G_OPTION_ARG_NONE, &opt_unsubs,
		"Unsubscribe for messages",
				NULL },
	{ "config", 0, 0, G_OPTION_ARG_NONE, &opt_cfg,
	"Listen for config file. " \
	"Eg: ./ktool --config -u=value -t=value [-U=value | -T=value]",
				NULL },
	{ "connect", 0, 0, G_OPTION_ARG_NONE, &opt_con,
	"Comprehensive of add, schema and config. "\
	"If uuid and token are given, authenticates it. " \
	"Otherwise, register a new device. " \
	"Eg: ./ktool --connect -j=value [-u=value | -t=value |-U=value | " \
	"-T=value]",
				NULL },
	{ NULL },
};

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GOptionGroup *opt_group;
	GError *gerr = NULL;
	int err = 0;

	guint receive_watch_id;
	GIOChannel *knotd_io;
	GIOCondition watch_cond;

	opt_uuid = NULL;
	opt_token = NULL;
	opt_json = NULL;
	opt_device_id = 0;

	printf("KNOT Tool\n");

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, commands, NULL);

	/* Define options for setting or reading JSON schema of a given
	 * device(UUID):
	 *  read:
	 *	ktool --schema --uuid=value
	 *  write:
	 *	ktool --schema --uuid=value --token=value --json=filename
	 */
	opt_group = g_option_group_new("options", "Options usage",
					"Show all schema options", NULL, NULL);
	g_option_context_add_group(context, opt_group);
	g_option_group_add_entries(opt_group, options);

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

	if (opt_tty)
		sock = serial_connect(opt_tty);
	else
		sock = unix_connect(opt_unix);

	if (sock == -1) {
		err = -errno;
		printf("connect(): %s (%d)\n", strerror(-err), -err);
		return err;
	}

	/*
	 * Starts watch to receive data from cloud
	 */
	knotd_io = g_io_channel_unix_new(sock);
	watch_cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	receive_watch_id = g_io_add_watch(knotd_io, watch_cond, proto_receive,
									NULL);
	g_io_channel_unref(knotd_io);
	printf("watch: %d\n", receive_watch_id);

	if (opt_add) {
		printf("Registering node ...\n");
		err = cmd_register();
	}

	if (opt_schema) {
		printf("Registering JSON schema for a device ...\n");
		err = cmd_schema(TRUE);
	} else if (opt_data) {
		printf("Setting data for a device ...\n");
		err = cmd_data();
	} else if (opt_rm) {
		printf("Unregistering node: %s\n", opt_uuid);
		err = cmd_unregister();
	} else if (opt_id) {
		printf("Identifying node ...\n");
		err = authenticate(opt_uuid, opt_token);
	} else if (opt_subs) {
		printf("Subscribing node ...\n");
		err = cmd_subscribe();
	} else if (opt_unsubs) {
		printf("Unsubscribing node ...\n");
		err = cmd_unsubscribe();
	} else if (opt_cfg) {
		printf("Configuration files...\n");
		err = cmd_config();
	} else if (opt_con) {
		printf("Connecting to Gateway\n");
		err = cmd_connect();
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
