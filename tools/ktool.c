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
#include <getopt.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <ell/ell.h>
#include <fcntl.h>
#include <termios.h>
#include <json-c/json.h>

#include <knot/knot_protocol.h>
#include <knot/knot_types.h>

#define TIMEOUT_MAINLOOP_QUIT 1

struct schema {
	struct l_queue *list;
	int err;
};

typedef void (*json_object_func_t) (struct json_object *jobj,
					const char *key, void *user_data);

static int sock;
static char *opt_unix = "knot";
static bool opt_add = false;
static bool opt_rm = false;
static bool opt_schema = false;
static bool opt_data = false;
static char *opt_uuid = NULL;
static char *opt_token = NULL;
static char *opt_json = NULL;
static char *opt_tty = NULL;
static uint64_t opt_device_id = 0;
static bool opt_cfg = false;
static bool opt_id = false;
static bool opt_subs = false;
static bool opt_unsubs = false;
static bool opt_con = false;

struct l_io *knotd_io;

static void main_loop_quit(struct l_timeout *timeout, void *user_data)
{
	l_main_quit();
	l_timeout_remove(timeout);
}

static void l_terminate(void)
{
	static bool terminating = false;

	if (terminating)
		return;

	terminating = true;

	if (knotd_io)
		l_io_destroy(knotd_io);

	l_timeout_create(TIMEOUT_MAINLOOP_QUIT, main_loop_quit, NULL, NULL);
}

static void l_signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_terminate();
		break;
	}
}

static ssize_t receive(int sockfd, void *buffer, size_t len)
{
	ssize_t nbytes;
	int err, msg_size, offset, remaining;
	knot_msg_header *hdr = buffer;

	nbytes = read(sockfd, buffer, len);
	if (nbytes < 0) {
		err = -errno;
		fprintf(stderr, "read() error\n");
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
			entry = l_new(knot_msg_schema, 1);
			entry->sensor_id = intval;
			l_queue_push_head(schema->list, entry);
			err = 0;
		} else if (strcmp("value_type", key) == 0) {
			entry = l_queue_peek_head(schema->list);
			if (!entry)
				goto done;

			/*
			*FIXME: if value_type appers before sensor_id? or other
			*wrong order
			*/
			entry->values.value_type = intval;
			err = 0;
		} else if (strcmp("unit", key) == 0) {
			entry = l_queue_peek_head(schema->list);
			if (!entry)
				goto done;

			/*
			*FIXME: if unit appers before sensor_id? or other
			*wrong order
			*/
			entry->values.unit = intval;
			err = 0;
		} else if (strcmp("type_id", key) == 0) {
			entry = l_queue_peek_head(schema->list);
			if (!entry)
				goto done;

			/*
			*FIXME: if type_id appers before sensor_id? or other
			*wrong order
			*/
			entry->values.type_id = intval;
			err = 0;
		}

		break;
	case json_type_string:
		data_name = json_object_get_string(jobj);

		if (strcmp("name", key) != 0 || data_name == NULL)
			goto done;

		entry = l_queue_peek_head(schema->list);
		if (!entry)
			goto done;
		/*
		*FIXME: if name comes before sensor_id,value_type,unit, type_id
		*or other wrong order
		*/
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
	knot_value_type *kvalue = &(msg->payload);
	knot_value_type_bool *kbool;
	knot_value_type_float *kfloat;
	knot_value_type_int *kint;
	enum json_type type;
	const char *str;

	type = json_object_get_type(jobj);

	if ((strcmp("sensor_id", key) == 0) && (type == json_type_int))
		msg->sensor_id = json_object_get_int(jobj);
	else if (strcmp("value", key) == 0) {
		switch (type) {
		case json_type_boolean:
			kbool = (knot_value_type_bool *) &(kvalue->val_b);
			*kbool = json_object_get_boolean(jobj);
			msg->hdr.payload_len = sizeof(knot_value_type_bool);
			break;
		case json_type_double:
			/* FIXME: how to handle overflow? */
			kfloat = (knot_value_type_float *) &(kvalue->val_f);
			*kfloat = (float) json_object_get_double(jobj);
			msg->hdr.payload_len = sizeof(knot_value_type_float);
			break;
		case json_type_int:
			kint = (knot_value_type_int *) &(kvalue->val_i);
			*kint = json_object_get_int(jobj);
			msg->hdr.payload_len = sizeof(knot_value_type_int);
			break;
		case json_type_string:
			str = json_object_get_string(jobj);

			memset(kvalue->raw, 0, sizeof(kvalue->raw));
			strncpy((char *) kvalue->raw, str, sizeof(kvalue->raw));
			msg->hdr.payload_len = sizeof(kvalue->raw);
			break;
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
		fprintf(stderr, "Unexpected JSON entry!\n");
	}
}

static void wrapper_json_object_object_foreach(struct json_object *jobj,
                json_object_func_t func, void *user_data)
{
    struct json_object *next;
    enum json_type type;
    int len, i;

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
	    if (!next)
        	return;
            wrapper_json_object_object_foreach(next, func, user_data);
            json_object_put(next);
            break;
        case json_type_array:
            len = json_object_array_length(val);
            for (i = 0; i < len; i++) {
                next = json_object_array_get_idx(val, i);
		if (!next)
        		return;
                wrapper_json_object_object_foreach(next, func, user_data);
            }
            break;
        }
    }
}

static void json_object_foreach(struct json_object *jobj,
                json_object_func_t func, void *user_data)
{
    if (!jobj)
        return;

    wrapper_json_object_object_foreach(jobj, func, user_data);
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
		fprintf(stderr, "write(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	nbytes = receive(sock, &resp, sizeof(resp));
	if (nbytes < 0) {
		err = errno;
		fprintf(stderr, "read(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	if (resp.result != 0) {
		fprintf(stderr, "error(0x%02x)\n", resp.result);
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
		fprintf(stderr, "JSON parsing error: data not found!\n");
		return -EINVAL;
	}

	msg.hdr.type = KNOT_MSG_PUSH_DATA_REQ;
	/* Payload len is set by read_json_entry() */

	msg.hdr.payload_len += sizeof(msg.sensor_id);
	nbytes = write(sock, &msg, sizeof(msg.hdr) + msg.hdr.payload_len);
	if (nbytes < 0) {
		err = errno;
		fprintf(stderr, "write(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	nbytes = receive(sock, &resp, sizeof(resp));
	if (nbytes < 0) {
		err = errno;
		fprintf(stderr, "read(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	if (resp.result != 0) {
		fprintf(stderr, "error(0x%02x)\n", resp.result);
		return -EPROTO;
	}

	return 0;
}

static int send_schema(struct l_queue *list)
{
	knot_msg_schema msg;
	knot_msg_schema *entry;
	ssize_t nbytes;
	int err;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.type = KNOT_MSG_SCHM_FRAG_REQ;

	while (!l_queue_isempty(list)) {
		entry = l_queue_pop_head(list);

		msg.hdr.payload_len = sizeof(entry->values) +
							sizeof(entry->sensor_id);

		memcpy(&msg.values, &entry->values, sizeof(entry->values));
		msg.sensor_id = entry->sensor_id;

		if (l_queue_length(list) == 0)
			msg.hdr.type = KNOT_MSG_SCHM_END_REQ;

		nbytes = write(sock, &msg, sizeof(msg.hdr) +
					msg.hdr.payload_len);

		if (nbytes < 0) {
			err = errno;
			fprintf(stderr, "write(): %s(%d)\n", strerror(err), err);
			return -err;
		}
		l_free(entry);
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
	msg.hdr.type = KNOT_MSG_REG_REQ;
	msg.hdr.payload_len = len + sizeof(msg.id);
	msg.id = opt_device_id ? opt_device_id : 0x123456789abcdef;
	memcpy(msg.devName, devname, len);

	nbytes = write(sock, &msg, sizeof(msg.hdr) + msg.hdr.payload_len);
	if (nbytes < 0) {
		err = errno;
		fprintf(stderr, "writev(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	memset(&crdntl, 0, sizeof(crdntl));
	nbytes = receive(sock, &crdntl, sizeof(crdntl));
	if (nbytes < 0) {
		err = errno;
		fprintf(stderr, "KNOT Register read(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	if (crdntl.result != 0) {
		fprintf(stderr, "KNOT Register: error(0x%02x)\n", crdntl.result);
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
	msg.hdr.type = KNOT_MSG_UNREG_REQ;
	msg.hdr.payload_len = 0;

	nbytes = write(sock, &msg, sizeof(msg));
	if (nbytes < 0) {
		err = errno;
		fprintf(stderr, "KNOT Unregister: %s(%d)\n", strerror(err), err);
		return -err;
	}

	memset(&rslt, 0, sizeof(rslt));
	nbytes = receive(sock, &rslt, sizeof(rslt));
	if (nbytes < 0) {
		err = errno;
		fprintf(stderr, "KNOT Unregister read(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	if (rslt.result != 0) {
		fprintf(stderr, "KNOT Unregister: error(0x%02x)\n", rslt.result);
		return -EPROTO;
	}

	printf("KNOT Unregister: OK\n");

	return 0;
}

static int cmd_schema(bool auth)
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
		fprintf(stderr, "Device's UUID missing!\n");
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
		fprintf(stderr, "Device's SCHEMA missing!\n");
		return -EINVAL;
	}

	if (stat(opt_json, &sb) == -1) {
		err = errno;
		fprintf(stderr, "json file: %s(%d)\n", strerror(err), err);
		return -err;
	}

	if ((sb.st_mode & S_IFMT) != S_IFREG) {
		fprintf(stderr, "json file: invalid argument!\n");
		return -EINVAL;
	}

	jobj = json_object_from_file(opt_json);
	if (!jobj) {
		fprintf(stderr, "json file(%s): failed to read from file!\n", opt_json);
		return -EINVAL;
	}

	memset(&schema, 0, sizeof(schema));
	schema.list = l_queue_new();
	json_object_foreach(jobj, load_schema, &schema);
	if (!schema.err)
		err = send_schema(schema.list);
	else
		err = -schema.err;

	l_queue_destroy(schema.list, l_free);
	json_object_put(jobj);

	return err;
}

static int cmd_data(void)
{
	struct json_object *jobj;
	struct stat sb;
	int err;

	if (!opt_uuid) {
		fprintf(stderr, "Device's UUID missing!\n");
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
		fprintf(stderr, "Device's data missing!\n");
		return -EINVAL;
	}

	if (stat(opt_json, &sb) == -1) {
		err = errno;
		fprintf(stderr, "json file: %s(%d)\n", strerror(err), err);
		return -err;
	}

	if ((sb.st_mode & S_IFMT) != S_IFREG) {
		fprintf(stderr, "json file: invalid argument!\n");
		return -EINVAL;
	}

	jobj = json_object_from_file(opt_json);
	if (!jobj) {
		fprintf(stderr, "json file(%s): failed to read from file!\n", opt_json);
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

static void send_config(struct l_timeout *timeout, void *user_data)
{
	struct json_object *jobj;

	l_info ("Sending config \n");

	jobj = json_object_from_file("json/data-temperature.json");
	if (!jobj) {
		fprintf(stderr, "json file(%s): failed to read from file!\n", opt_json);
		return;
	}
	json_object_foreach(jobj, print_json_value, NULL);
	write_knot_data(jobj);
	json_object_put(jobj);
}

static void on_disconnect(struct l_io *io, void *user_data)
{
	printf("disconnected from knotd\n");
}

static void destroy_io(void *user_data) {
	l_terminate();
}

static bool proto_receive(struct l_io *io, void *user_data)
{
	knot_msg recv;
	knot_msg resp;
	ssize_t nbytes;
	int err, sock;
	struct json_object *jobj;

	sock = l_io_get_fd(io);

	nbytes = read(sock, &recv, sizeof(recv));
	if (nbytes < 0) {
		err = errno;
		fprintf(stderr, "read(): %s(%d)\n", strerror(err), err);
		return true;
	}

	switch (recv.hdr.type) {
	case KNOT_MSG_PUSH_CONFIG_REQ:
		printf("sensor_id: %d\n", recv.config.sensor_id);
		printf("event_flags: %d\n", recv.config.values.event_flags);
		printf("time_sec: %d\n", recv.config.values.time_sec);
		printf("lower_limit: %f\n",
				recv.config.values.lower_limit.val_f);
		printf("upper_limit: %f\n",
				recv.config.values.upper_limit.val_f);
		resp.hdr.type = KNOT_MSG_PUSH_CONFIG_RSP;
		resp.hdr.payload_len = sizeof(resp.item.sensor_id);
		resp.item.sensor_id = recv.config.sensor_id;
		nbytes = write(sock, &resp, sizeof(knot_msg_item));
		if (nbytes < 0) {
			err = errno;
			fprintf(stderr, "node_ops: %s(%d)\n", strerror(err), err);
			return true;
		}
		/*
		 * For testing purposes, assuming the config is to send data
		 * each 10 seconds.
		 */
		l_timeout_create(10, send_config, NULL, NULL);
		break;
	case KNOT_MSG_PUSH_DATA_REQ:
		printf("sensor_id: %d\n", recv.data.sensor_id);
		printf("value: %f\n",
				recv.data.payload.val_f);
		resp.hdr.type = KNOT_MSG_PUSH_DATA_RSP;
		resp.hdr.payload_len = sizeof(knot_value_type) +
						sizeof(resp.data.sensor_id);
		resp.data.sensor_id = recv.data.sensor_id;
		memcpy(&(resp.data.payload), &(recv.data.payload),
		       sizeof(knot_value_type));
		nbytes = write(sock, &resp, sizeof(knot_msg_data));
		if (nbytes < 0) {
			err = errno;
			fprintf(stderr, "node_ops: %s(%d)\n", strerror(err), err);
			return true;
		}
		break;
	case KNOT_MSG_POLL_DATA_REQ:
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
			fprintf(stderr, "json file(%s): failed to read from file!\n",
								opt_json);
			return -EINVAL;
		}

		json_object_foreach(jobj, print_json_value, NULL);
		write_knot_data(jobj);
		json_object_put(jobj);

		break;
	case KNOT_MSG_UNREG_REQ:
		resp.hdr.type = KNOT_MSG_UNREG_RSP;
		nbytes = write(sock, &resp, sizeof(knot_msg_header) + resp.hdr.payload_len);
		if (nbytes < 0) {
			err = errno;
			fprintf(stderr, "node_ops: %s(%d)\n", strerror(err), err);
			return true;
		}

		break;
	}

	return true;
}

static int cmd_config(void)
{
	int err;

	if (!opt_uuid) {
		fprintf(stderr, "Device's UUID missing!\n");
		return -EINVAL;
	}

	if (!opt_token) {
		fprintf(stderr, "Device's TOKEN missing!\n");
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
		fprintf(stderr, "Authentication failed!\n");
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
			fprintf(stderr, "Error authenticating\n");
			return -EINVAL;
		}
	} else {
		err = cmd_register();
		if (err) {
			fprintf(stderr, "Error registering\n");
			return -EINVAL;
		}
	}

	err = cmd_schema(false);
	if (err < 0) {
		fprintf(stderr, "Error sending schema: %s (%d)\n", strerror(err), -err);
		return err;
	}

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

static void usage(void)
{
	printf("ktool - KNoT tools\n"
		"Usage:\n");
	printf("\tktool [options]\n");
	printf("Application Options:\n"
		"\t-a, --add				Register a device to Meshblu. "
		"Eg: ./ktool --add [-U=value | T=value| I=value]\n"

		"\t-s, --schema				Get/Put JSON representing device's schema."
		" Eg: ./ktool --schema -u=value -t=value -j=value [-U=value | T=value]\n"

		"\t-C, --config				Listen for config file."
		" Eg: ./ktool --config -u=value -t=value [-U=value | -T=value]\n"

		"\t-c, --connect				Comprehensive of add, schema and config."
		" If uuid and token are given, authenticates it."
		" Otherwise, register a new device."
		" Eg: ./ktool --connect -j=value [-u=value | -t=value |-U=value | -T=value]\n"

		"\t-r, --remove				Unregister a device from Meshblu. "
		"Eg: ./ktool --remove -u=value -t=value [-U=value | T=value]\n"

		"\t-d, --data				Sends data of a given device. "
		"Eg: ./ktool --data -u=value -t=value -j=value [-U=value | -T=value]\n"

		"\t-i, --id				Identify (Authenticate) a Meshblu device.\n"
		"\t-S, --subscribe				Subscribe for messages of a given device.\n"
		"\t-n, --unsubscribe			Unsubscribe for messages.\n"
		"\nOptions usage:\n"
		"\t-I, --device-id				Device's ID.\n"
		"\t-u, --uuid				Device's UUID.\n"
		"\t-t, --token				Device's token.\n"
		"\t-j, --json				Path to JSON file.\n"
		"\t-U, --unix				Specify unix socket to connect. Default: knot.\n"
		"\t-T, --tty				Specify TTY to connect.\n"
		"\t-h  --help				Show help options\n");
}

static const struct option main_options[] = {

	{ "add", no_argument, NULL, 'a' },
	{ "schema", no_argument, NULL, 's' },
	{ "config", no_argument, NULL, 'C' },
	{ "connect", no_argument, NULL, 'c' },
	{ "remove", no_argument, NULL, 'r' },
	{ "data", no_argument, NULL, 'd'},
	{ "id", no_argument, NULL, 'i' },
	{ "subscribe", no_argument, NULL, 'S' },
	{ "unsubscribe", no_argument, NULL, 'n' },
	{ "help", no_argument, NULL, 'h' },
	{ "device-id", required_argument, NULL, 'I' },
	{ "uuid", required_argument, NULL, 'u' },
	{ "token", required_argument, NULL, 't' },
	{ "json", required_argument, NULL, 'j' },
	{ "unix", required_argument, NULL, 'U' },
	{ "tty", required_argument, NULL, 'T' },
	{ },
};


static int parse_args(int argc, char *argv[])
{
	int opt;

	for (;;) {
		opt = getopt_long(argc, argv, "asCcrdiSnhI:u:t:j:U:T:",
				  main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'a':
			opt_add = true;
			break;
		case 's':
			opt_schema = true;
			break;
		case 'C':
			opt_cfg = true;
			break;
		case 'c':
			opt_con = true;
			break;
		case 'r':
			opt_rm = true;
			break;
		case 'd':
			opt_data = true;
			break;
		case 'i':
			opt_id = true;
			break;
		case 'S':
			opt_subs = true;
			break;
		case 'n':
			opt_unsubs = true;
			break;
		case 'I':
			opt_device_id = atoi(optarg);
			break;
		case 'u':
			opt_uuid = l_strdup(optarg);
			break;
		case 't':
			opt_token = l_strdup(optarg);
			break;
		case 'j':
			opt_json = l_strdup(optarg);
			break;
		case 'U':
			opt_unix = l_strdup(optarg);
			break;
		case 'T':
			opt_uuid = l_strdup(optarg);
			break;
		case 'h':
			usage();
			l_main_exit();
			return 0;
		default:
			return -EINVAL;
		}
	}


	if (argc - optind > 0) {
		fprintf(stderr, "Invalid command line parameters\n");
		return -EINVAL;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int err = 0;

	opt_uuid = NULL;
	opt_token = NULL;
	opt_json = NULL;
	opt_device_id = 0;

	printf("KNOT Tool\n");


	/* Define options for setting or reading JSON schema of a given
	 * device(UUID):
	 *  read:
	 *	ktool --schema --uuid=value
	 *  write:
	 *	ktool --schema --uuid=value --token=value --json=filename
	 */
	err = parse_args(argc, argv);
	if (err < 0) {
		fprintf(stderr, "parse_args(): %s (%d)\n", strerror(-err), -err);
		goto main_exit;
	}

	if (!l_main_init())
		goto main_exit;

	if (opt_tty)
		sock = serial_connect(opt_tty);
	else
		sock = unix_connect(opt_unix);

	if (sock == -1) {
		err = -errno;
		fprintf(stderr, "connect(): %s (%d)\n", strerror(-err), -err);
		return err;
	}

	/*
	 * Starts watch to receive data from cloud
	 */
	knotd_io = l_io_new(sock);
	l_io_set_close_on_destroy(knotd_io, true);
	l_io_set_read_handler(knotd_io, proto_receive, NULL, NULL);
	l_io_set_disconnect_handler(knotd_io, on_disconnect, NULL, destroy_io);
	printf("watch: %p\n", knotd_io);

	if (opt_add) {
		printf("Registering node ...\n");
		err = cmd_register();
	}

	if (opt_schema) {
		printf("Registering JSON schema for a device ...\n");
		err = cmd_schema(true);
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

	if (err >= 0)
		l_main_run_with_signal(l_signal_handler, NULL);

main_exit:
	l_main_exit();

	printf("Exiting\n");

	close(sock);

	return 0;
}
