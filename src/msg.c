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

#ifndef  _GNU_SOURCE
#define  _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <ell/ell.h>

#include <json-c/json.h>

#include <knot_types.h>
#include <knot_protocol.h>
#include <hal/linux_log.h>

#include "settings.h"
#include "proto.h"
#include "msg.h"

#define MIN(a,b) ((a) < (b) ? (a) : (b))

struct config {
	knot_msg_config kmcfg;		/* knot_message_config from cloud */
	char *hash;			/* Checksum of kmcfg */
	bool confirmed;
};

struct proto_watch;

struct trust {
	int refs;
	pid_t	pid;			/* Peer PID */
	uint64_t id;			/* Session identification */
	bool rollback;		/* Remove from cloud if true */
	char *uuid;			/* Device UUID */
	char *token;			/* Device token */
	struct l_queue *schema;			/* knot_schema accepted by cloud */
	struct l_queue *schema_tmp;		/*
					* knot_schema to be submitted to cloud
					*/
	struct l_queue *config;			/* knot_config accepted from cloud */
	const struct proto_ops *proto_ops; /* Cloud driver */
	struct l_io *proto_io;		/* Cloud IO channel */
	struct proto_watch *proto_watch;
};

struct proto_watch {
	unsigned int id;
	struct l_io *node_io;
	struct trust *trust;
};

/* Maps sockets to sessions: online devices only.  */
static struct l_hashmap *trust_map;

/* IoT protocol: http or ws */
static struct proto_ops *proto;

static char owner_uuid[KNOT_PROTOCOL_UUID_LEN + 1];

/* Message processing */
static int8_t msg_register(int sock, int proto_sock,
	const knot_msg_register *kreq, size_t ilen,
	knot_msg_credential *krsp);
static int8_t msg_unregister(int sock, int proto_sock);
static int8_t msg_data(int sock, int proto_sock,
	const knot_msg_data *kmdata);
static int8_t msg_auth(int sock, int proto_sock,
	const knot_msg_authentication *kmauth);
static int8_t msg_schema(int sock, int proto_sock,
	const knot_msg_schema *kmsch, bool eof);
static struct l_queue *msg_config(int sock, json_raw_t json, ssize_t *result);
static int8_t msg_config_resp(int sock, const knot_msg_item *rsp);
static struct l_queue *msg_setdata(int sock, json_raw_t json, ssize_t *result);
static int8_t msg_setdata_resp(int sock, int proto_sock,
	const knot_msg_data *kmdata);
static struct l_queue *msg_getdata(int sock, json_raw_t json, ssize_t *result);
static int fw_push(int sock, knot_msg *kmsg);
static struct trust *trust_ref(struct trust *trust);
static void trust_unref(struct trust *trust);

static void queue_concat(struct l_queue *queue, struct l_queue *with)
{
	struct l_queue_entry *current;

	if (!queue || !with)
		return;

	current = (struct l_queue_entry *)l_queue_get_entries(with);
	while (current) {
		l_queue_push_tail(queue, current->data);
		current = current->next;
	}
}

static struct l_queue *queue_clone(struct l_queue *queue)
{
	struct l_queue *clone = NULL;

	if (!queue)
		goto done;

	clone = l_queue_new();
	queue_concat(clone, queue);

done:
	return clone;
}

static char *compute_checksum_for_string(enum l_checksum_type type,
	const char *string, size_t length)
{
	char *result = NULL;
	struct l_checksum *checksum;

	checksum = l_checksum_new(type);
	if (!checksum)
		goto fail_create;

	if (!l_checksum_update(checksum, string, length)) {
		goto fail_update;
	}

	result = l_checksum_get_string(checksum);

fail_update:
	l_checksum_free(checksum);
fail_create:
	return result;
}

static void send_message(void *data, void *user_data)
{
	int result;
	knot_msg *msg = data;
	int node_socket = L_PTR_TO_INT(user_data);

	result = fw_push(node_socket, msg);
	if (result)
		hal_log_error("KNOT SEND ERROR");
}

/*
 * Callback that parses the JSON for config (and in the future, send data)
 * messages. It is called from the protocol that is used to communicate with
 * the cloud (e.g. http, websocket).
 */
static void on_device_changed(json_raw_t device_message, void *user_data)
{
	const struct proto_watch *watch = user_data;
	int node_socket;
	ssize_t result;
	struct l_queue *config_messages, *setdata_messages, *getdata_messages;
	struct l_queue *messages = NULL;

	node_socket = l_io_get_fd(watch->node_io);
	config_messages = msg_config(node_socket, device_message, &result);
	setdata_messages = msg_setdata(node_socket, device_message, &result);
	getdata_messages = msg_getdata(node_socket, device_message, &result);

	messages = l_queue_new();
	queue_concat(messages, config_messages);
	queue_concat(messages, setdata_messages);
	queue_concat(messages, getdata_messages);

	l_queue_foreach(messages, send_message, L_INT_TO_PTR(node_socket));

	/*
	 * Message data will be free'd only when destroying messages
	 * as it contains references to all messages. The first three
	 * are freeing l_queue-specific resources.
	 */
	l_queue_destroy(config_messages, NULL);
	l_queue_destroy(setdata_messages, NULL);
	l_queue_destroy(getdata_messages, NULL);
	l_queue_destroy(messages, l_free);
}

static void on_device_watch_destroyed(void *user_data)
{
	struct proto_watch *proto_watch = user_data;
	proto_watch->trust->proto_watch = NULL;
	trust_unref(proto_watch->trust);
	l_free(proto_watch);
}

static struct proto_watch *create_device_watch(struct trust *trust,
	struct l_io *node_channel)
{
	struct proto_watch *proto_watch;
	int proto_socket;

	proto_socket = l_io_get_fd(trust->proto_io);

	proto_watch = l_new(struct proto_watch, 1);
	proto_watch->id = proto->async(proto_socket,
		trust->uuid,
		trust->token,
		on_device_changed,
		proto_watch,
		on_device_watch_destroyed);
	proto_watch->node_io = node_channel;
	/*
	 * Retained to remove the device watch from the trust when the
	 * watch is destroyed by the protocol driver
	 */
	proto_watch->trust = trust_ref(trust);

	return proto_watch;
}

static void remove_device_watch(struct proto_watch *proto_watch)
{
	int proto_socket;

	proto_socket = l_io_get_fd(proto_watch->trust->proto_io);
	proto->async_stop(proto_socket, proto_watch->id);
}

static void config_free(void *data)
{
	struct config *cfg = data;

	l_free(cfg->hash);
	l_free(cfg);
}

static void trust_map_create()
{
	trust_map = l_hashmap_new();
}

static void trust_map_destroy()
{
	l_hashmap_destroy(trust_map, (l_hashmap_destroy_func_t) trust_unref);
}

static struct trust *trust_map_get(int id)
{
	return l_hashmap_lookup(trust_map, L_INT_TO_PTR(id));
}

static void trust_map_add(int id, struct trust *trust)
{
	l_hashmap_insert(trust_map, L_INT_TO_PTR(id), trust);
}

static void trust_map_remove(int id)
{
	struct trust *trust = l_hashmap_remove(trust_map, L_INT_TO_PTR(id));
	if (trust)
		trust_unref(trust);
}

static void trust_map_replace(int id, struct trust *trust)
{
	trust_map_remove(id);
	trust_map_add(id, trust);
}

static struct trust *trust_new()
{
	struct trust *trust = l_new(struct trust, 1);
	trust->refs = 1;
	return trust;
}

static struct trust *trust_ref(struct trust *trust)
{
	atomic_fetch_add(&trust->refs, 1);

	return trust;
}

static void trust_unref(struct trust *trust)
{
	if (atomic_fetch_sub(&trust->refs, 1) > 1)
		return;

	l_io_destroy(trust->proto_io);
	l_free(trust->uuid);
	l_free(trust->token);
	l_queue_destroy(trust->schema, l_free);
	l_queue_destroy(trust->schema_tmp, l_free);
	l_queue_destroy(trust->config, config_free);
	l_free(trust);
}

static void on_node_channel_disconnected(struct l_io *channel, void *used_data)
{
	struct trust *trust;
	int node_socket, proto_socket;

	node_socket = l_io_get_fd(channel);

	trust = trust_map_get(node_socket);
	if (!trust)
		return;

	/* Zombie device: registration not complete */
	if (trust->rollback) {
		proto_socket = l_io_get_fd(trust->proto_io);
		if (msg_unregister(node_socket, proto_socket) != KNOT_SUCCESS) {
			hal_log_info("Rollback failed UUID: %s", trust->uuid);
		}
	}

	if (trust->proto_watch) {
		remove_device_watch(trust->proto_watch);
	}

	trust_map_remove(node_socket);
}

static void on_node_channel_destroyed(void *user_data)
{
	struct trust *trust = (struct trust *)user_data;
	trust_unref(trust);
}

static struct l_io *create_node_channel(int node_socket, struct trust *trust)
{
	struct l_io *channel;

	channel = l_io_new(node_socket);
	l_io_set_disconnect_handler(channel,
		on_node_channel_disconnected,
		trust_ref(trust),
		on_node_channel_destroyed);
	return channel;
}

static void trust_create(int node_socket, int proto_socket, char *uuid,
	char *token, uint64_t device_id, pid_t pid, bool rollback,
	struct l_queue *schema, struct l_queue *config)
{
	struct trust *trust;
	struct l_io *node_channel;

	trust = trust_new();
	trust->uuid = uuid;
	trust->token = token;
	trust->id = device_id;
	trust->pid = pid;
	trust->rollback = rollback;
	trust->schema = schema;
	trust->config = config;
	/*
	 * TODO: find a better way to store a reference to the cloud as if it
	 * disconnects we won't recover.
	 */
	trust->proto_io = l_io_new(proto_socket);

	trust_map_replace(node_socket, trust);

	/* Add a watch to remove the credential when the client disconnects */
	node_channel = create_node_channel(node_socket, trust);

	/* Add watch to device changes in the cloud */
	trust->proto_watch = create_device_watch(trust, node_channel);
}

static bool schema_sensor_id_cmp(const void *entry_data, const void *user_data)
{
	const knot_msg_schema *schema = entry_data;
	unsigned int sensor_id = L_PTR_TO_UINT(user_data);

	return sensor_id == schema->sensor_id;
}

static knot_msg_schema *trust_get_sensor_schema(const struct trust *trust,
	unsigned int sensor_id)
{
	return l_queue_find(trust->schema,
		schema_sensor_id_cmp,
		L_UINT_TO_PTR(sensor_id));
}

static void trust_sensor_schema_free(struct trust *trust)
{
	l_queue_destroy(trust->schema, l_free);
	trust->schema = NULL;
}

static knot_msg_schema *trust_get_sensor_schema_tmp(const struct trust *trust,
	unsigned int sensor_id)
{
	return l_queue_find(trust->schema_tmp,
		schema_sensor_id_cmp,
		L_UINT_TO_PTR(sensor_id));
}

static void trust_sensor_schema_tmp_add(struct trust *trust,
	const knot_msg_schema *schema)
{
	knot_msg_schema *schema_copy;

	schema_copy = l_memdup(schema, sizeof(*schema));
	l_queue_push_tail(trust->schema_tmp, schema_copy);
}

static void trust_sensor_schema_tmp_free(struct trust *trust)
{
	l_queue_destroy(trust->schema_tmp, l_free);
	trust->schema_tmp = NULL;
}

static void trust_sensor_schema_complete(struct trust *trust)
{
	trust_sensor_schema_free(trust);
	trust->schema = trust->schema_tmp;
	trust->schema_tmp = NULL;
}

static void trust_config_update(struct trust *trust, struct l_queue *config)
{
	l_queue_destroy(trust->config, config_free);
	trust->config = config;
}

static bool config_sensor_id_cmp(const void *entry_data, const void *user_data)
{
	const struct config *config = entry_data;
	unsigned int sensor_id = L_PTR_TO_UINT(user_data);

	return config->kmcfg.sensor_id == sensor_id;
}

static void trust_config_confirm(struct trust *trust, uint8_t sensor_id)
{
	struct config *config_item = l_queue_find(trust->config,
		config_sensor_id_cmp,
		L_UINT_TO_PTR(sensor_id));

	if (config_item)
		config_item->confirmed = true;
}

/*
 * TODO: consider making this part of proto-ws.c signin()
 */
static int proto_rmnode(int proto_socket, const char *uuid, const char *token)
{
	int result, err;
	json_raw_t response = { NULL, 0 };

	err = proto->rmnode(proto_socket, uuid, token, &response);
	if (err < 0) {
		result = KNOT_CLOUD_FAILURE;
		hal_log_error("rmnode() failed %s (%d)", strerror(-err), -err);
		goto done;
	}

	result = KNOT_SUCCESS;

done:
	if (response.data)
		free(response.data);
	return result;
}

static int8_t msg_unregister(int node_socket, int proto_socket)
{
	int8_t result;	
	const struct trust *trust;

	trust = trust_map_get(node_socket);
	if (!trust) {
		hal_log_info("Permission denied!");
		result = KNOT_CREDENTIAL_UNAUTHORIZED;
		goto done;
	}

	hal_log_info("rmnode: %.36s", trust->uuid);
	result = proto_rmnode(proto_socket, trust->uuid, trust->token);
	if (result != KNOT_SUCCESS)
		goto done;

	trust_map_remove(node_socket);
	result = KNOT_SUCCESS;

done:
	return result;
}

static char *checksum_config(json_object *jobjkey)
{
	const char *c;

	c = json_object_to_json_string(jobjkey);

	return compute_checksum_for_string(L_CHECKSUM_SHA1, c, strlen(c));
}

/*
 * Checks if the config message received from the cloud is valid.
 * Validates if the values are valid and if the event_flags are consistent
 * with desired events.
 * No need to check if sensor_id,event_flags and time_sec are positive for
 * they are unsigned from protocol.
 */
static int config_is_valid(struct l_queue *config_list)
{
	knot_msg_config *config;
	struct config *cfg;
	struct l_queue_entry *entry;
	int diff_int, diff_dec;

	entry = (struct l_queue_entry *) l_queue_get_entries(config_list);
	while (entry) {
		cfg = entry->data;
		config = &cfg->kmcfg;

		/* Check if event_flags are valid */
		if ((config->values.event_flags | KNOT_EVT_FLAG_NONE) &&
			!(config->values.event_flags & (KNOT_EVT_FLAG_TIME |
						KNOT_EVT_FLAG_LOWER_THRESHOLD |
						KNOT_EVT_FLAG_UPPER_THRESHOLD |
						KNOT_EVT_FLAG_CHANGE |
						KNOT_EVT_FLAG_UNREGISTERED)))
			/*
			 * TODO: DEFINE KNOT_CONFIG ERRORS IN PROTOCOL
			 * KNOT_INVALID_CONFIG in new protocol
			 */
			return KNOT_ERROR_UNKNOWN;

		/* Check consistency of time_sec */
		if (config->values.event_flags & KNOT_EVT_FLAG_TIME) {
			if (config->values.time_sec == 0)
				/*
				 * TODO: DEFINE KNOT_CONFIG ERRORS IN PROTOCOL
				 * KNOT_INVALID_CONFIG in new protocol
				 */
				return KNOT_ERROR_UNKNOWN;
		} else {
			if (config->values.time_sec > 0)
				/*
				 * TODO: DEFINE KNOT_CONFIG ERRORS IN PROTOCOL
				 * KNOT_INVALID_CONFIG in new protocol
				 */
				return KNOT_ERROR_UNKNOWN;
		}

		/* Check consistency of limits */
		if (config->values.event_flags &
					(KNOT_EVT_FLAG_LOWER_THRESHOLD |
					KNOT_EVT_FLAG_UPPER_THRESHOLD)) {

			diff_int = config->values.upper_limit.val_f.value_int -
				config->values.lower_limit.val_f.value_int;

			diff_dec = config->values.upper_limit.val_f.value_dec -
				config->values.lower_limit.val_f.value_dec;

			if (diff_int < 0)
				/*
				 * TODO: DEFINE KNOT_CONFIG ERRORS IN PROTOCOL
				 * KNOT_INVALID_CONFIG in new protocol
				 */
				return KNOT_ERROR_UNKNOWN;
			else if (diff_int == 0 && diff_dec <= 0)
				/*
				 * TODO: DEFINE KNOT_CONFIG ERRORS IN PROTOCOL
				 * KNOT_INVALID_CONFIG in new protocol
				 */
				return KNOT_ERROR_UNKNOWN;
		}
		entry = entry->next;
	}
	return KNOT_SUCCESS;
}

/*
 * Parsing knot_value_types attribute
 */
static void parse_json_value_types(json_object *jobj, knot_value_types *limit)
{
	json_object *jobjkey;
	int32_t ipart, fpart;
	const char *str;

	jobjkey = jobj;
	switch (json_object_get_type(jobjkey)) {
	case json_type_boolean:
		limit->val_b = json_object_get_boolean(jobjkey);
		break;
	case json_type_double:
		/* Trick to get integral and fractional parts */
		str = json_object_get_string(jobjkey);
		/* FIXME: how to handle overflow? */
		if (sscanf(str, "%d.%d", &ipart, &fpart) != 2)
			break;
		limit->val_f.value_int = ipart;
		limit->val_f.value_dec = fpart;
		limit->val_f.multiplier = 1; /* TODO: */
		break;
	case json_type_int:

		limit->val_i.value = json_object_get_int(jobjkey);
		limit->val_i.multiplier = 1;
		break;
	case json_type_string:
	case json_type_null:
	case json_type_object:
	case json_type_array:
	default:
		break;
	}
}

static int parse_device_info(const char *json_str,
					char **puuid, char **ptoken)
{
	json_object *jobj, *json_uuid, *json_token;
	const char *uuid, *token;
	int err = -EINVAL;

	jobj = json_tokener_parse(json_str);
	if (jobj == NULL)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj, "uuid", &json_uuid))
		goto done;

	if (!json_object_object_get_ex(jobj, "token", &json_token))
		goto done;

	uuid = json_object_get_string(json_uuid);
	token = json_object_get_string(json_token);

	*puuid = l_strdup(uuid);
	*ptoken = l_strdup(token);

	err = 0; /* Success */
done:
	json_object_put(jobj);

	return err;
}

static struct l_queue *parse_device_schema(const char *json_str)
{
	json_object *jobj, *jobjarray, *jobjentry, *jobjkey;
	struct l_queue *list = NULL;
	knot_msg_schema *entry;
	int sensor_id, value_type, unit, type_id, i;
	const char *name;

	jobj = json_tokener_parse(json_str);
	if (!jobj)
		return NULL;

	list = l_queue_new();
	/* Expected JSON object is in the following format:
	 *
	 * {"uuid": ...
	 *		"schema" : [
	 *			{"sensor_id": x, "value_type": w,
	 *				"unit": z "type_id": y, "name": "foo"}]
	 * }
	 */

	/* 'schema' is an array */
	if (!json_object_object_get_ex(jobj, "schema", &jobjarray))
		goto done;

	if (json_object_get_type(jobjarray) != json_type_array)
		goto done;

	for (i = 0; i < json_object_array_length(jobjarray); i++) {

		jobjentry = json_object_array_get_idx(jobjarray, i);

		/* Getting 'sensor_id' */
		if (!json_object_object_get_ex(jobjentry, "sensor_id",
								&jobjkey))
			goto done;

		if (json_object_get_type(jobjkey) != json_type_int)
			goto done;

		sensor_id = json_object_get_int(jobjkey);

		/* Getting 'value_type' */
		if (!json_object_object_get_ex(jobjentry, "value_type",
								&jobjkey))
			goto done;

		if (json_object_get_type(jobjkey) != json_type_int)
			goto done;

		value_type = json_object_get_int(jobjkey);

		/* Getting 'unit' */
		if (!json_object_object_get_ex(jobjentry, "unit", &jobjkey))
			goto done;

		if (json_object_get_type(jobjkey) != json_type_int)
			goto done;

		unit = json_object_get_int(jobjkey);

		/* Getting 'type_id' */
		if (!json_object_object_get_ex(jobjentry, "type_id", &jobjkey))
			goto done;

		if (json_object_get_type(jobjkey) != json_type_int)
			goto done;

		type_id = json_object_get_int(jobjkey);

		/* Getting 'name' */
		if (!json_object_object_get_ex(jobjentry, "name", &jobjkey))
			goto done;

		if (json_object_get_type(jobjkey) != json_type_string)
			goto done;

		name = json_object_get_string(jobjkey);
		/*
		 * Validation not required: validation has been performed
		 * previously when schema has been submitted to the cloud.
		 */
		entry = l_new(knot_msg_schema, 1);
		entry->sensor_id = sensor_id;
		entry->values.value_type = value_type;
		entry->values.unit = unit;
		entry->values.type_id = type_id;
		strncpy(entry->values.name, name,
						sizeof(entry->values.name) - 1);

		l_queue_push_tail(list, entry);
	}

done:
	/*
	 * TODO: should done label be used only for the error case
	 * as in parse_device_config() and parse_device_setdata()?
	 */
	json_object_put(jobj);

	if (l_queue_isempty(list)) {
		l_queue_destroy(list, NULL);
		list = NULL;
	}

	return list;
}

/*
 * Parses the json from the cloud with the config. The message is discarded if:
 * There are no "devices" or "config" fields in the JSON or they are not arrays.
 * The mandatory fields "sensor_id" and "event_flags" are missing.
 * Any field that is sent has the wrong type.
 */
static struct l_queue *parse_device_config(const char *json_str)
{
	json_object *jobj, *jobjarray, *jobjentry, *jobjkey;
	struct l_queue *list = NULL;
	struct config *entry;
	int sensor_id, event_flags, time_sec, i;
	knot_value_types lower_limit, upper_limit;
	json_type jtype;

	jobj = json_tokener_parse(json_str);
	if (!jobj)
		return NULL;

	list = l_queue_new();

	/* Getting 'config' from the device properties:
	 *
	 * {"uuid": ...
	 *		"config" : [
	 *			{"sensor_id": v, "event_flags": w,
	 *				"time_sec": x "lower_limit": y,
	 *						"upper_limit": z}]
	 * }
	 */

	/* 'config' is an array */
	if (!json_object_object_get_ex(jobj, "config", &jobjarray))
		goto done;

	if (json_object_get_type(jobjarray) != json_type_array)
		goto done;

	for (i = 0; i < json_object_array_length(jobjarray); i++) {

		jobjentry = json_object_array_get_idx(jobjarray, i);
		if (!jobjentry)
			goto done;

		/* Getting 'sensor_id' */
		if (!json_object_object_get_ex(jobjentry, "sensor_id",
								&jobjkey))
			goto done;

		if (json_object_get_type(jobjkey) != json_type_int)
			goto done;

		sensor_id = json_object_get_int(jobjkey);

		/* Getting 'event_flags' */
		if (!json_object_object_get_ex(jobjentry, "event_flags",
								&jobjkey))
			goto done;

		if (json_object_get_type(jobjkey) != json_type_int)
			goto done;

		event_flags = json_object_get_int(jobjkey);

		/* If 'time_sec' is defined, gets it */

		time_sec = 0;
		if (json_object_object_get_ex(jobjentry, "time_sec",
								 &jobjkey)) {
			if (json_object_get_type(jobjkey) != json_type_int)
				goto done;

			time_sec = json_object_get_int(jobjkey);
		}

		/* If 'lower_limit' is defined, gets it. */

		memset(&lower_limit, 0, sizeof(knot_value_types));
		if (json_object_object_get_ex(jobjentry, "lower_limit",
								&jobjkey)) {
			jtype = json_object_get_type(jobjkey);
			if (jtype != json_type_int &&
				jtype != json_type_double &&
				jtype != json_type_boolean)
				goto done;

			parse_json_value_types(jobjkey,
						&lower_limit);
		}

		/* If 'upper_limit' is defined, gets it. */

		memset(&upper_limit, 0, sizeof(knot_value_types));
		if (json_object_object_get_ex(jobjentry, "upper_limit",
								&jobjkey)){
			jtype = json_object_get_type(jobjkey);
			if (jtype != json_type_int &&
					jtype != json_type_double &&
					jtype != json_type_boolean)
				goto done;
			parse_json_value_types(jobjkey,
						&upper_limit);
		}

		entry = l_new(struct config, 1);
		entry->kmcfg.sensor_id = sensor_id;
		entry->kmcfg.values.event_flags = event_flags;
		entry->kmcfg.values.time_sec = time_sec;
		memcpy(&(entry->kmcfg.values.lower_limit), &lower_limit,
						sizeof(knot_value_types));
		memcpy(&(entry->kmcfg.values.upper_limit), &upper_limit,
						sizeof(knot_value_types));
		entry->hash = checksum_config(jobjentry);
		entry->confirmed = false;

		l_queue_push_tail(list, entry);
	}

	json_object_put(jobj);

	return list;

done:
	l_queue_destroy(list, config_free);
	json_object_put(jobj);

	return NULL;
}

/*
 * Parses the json from the cloud with the set_data.
 * Whenever the GW sends a data to the thing, it will also insert another field
 * in the data in the cloud informing that this data have already been sent.
 * When/if the user updates the data, the field is erased and the data is sent
 * again, regardless if the value is the same or not.
 */
static struct l_queue *parse_device_setdata(const char *json_str)
{
	json_object *jobj, *jobjarray, *jobjentry, *jobjkey;
	struct l_queue *list = NULL;
	knot_msg_data *entry;
	int sensor_id, i;
	knot_data data;
	json_type jtype;

	jobj = json_tokener_parse(json_str);
	if (!jobj)
		return NULL;

	list = l_queue_new();

	/*
	 * Getting 'set_data' from the device properties:
	 * {"uuid":
	 *		"set_data" : [
	 *			{"sensor_id": v,
	 *			"value": w}]
	 * }
	 */

	/* 'set_data' is an array */
	if (!json_object_object_get_ex(jobj, "set_data", &jobjarray))
		goto done;

	if (json_object_get_type(jobjarray) != json_type_array)
		goto done;

	for (i = 0; i < json_object_array_length(jobjarray); i++) {

		jobjentry = json_object_array_get_idx(jobjarray, i);
		if (!jobjentry)
			goto done;

		/* Getting 'sensor_id' */
		if (!json_object_object_get_ex(jobjentry, "sensor_id",
								&jobjkey))
			goto done;

		if (json_object_get_type(jobjkey) != json_type_int)
			goto done;

		sensor_id = json_object_get_int(jobjkey);

		/* Getting 'value' */
		memset(&data, 0, sizeof(knot_data));
		if (json_object_object_get_ex(jobjentry, "value",
								&jobjkey)) {
			jtype = json_object_get_type(jobjkey);
			if (jtype != json_type_int &&
				jtype != json_type_double &&
				jtype != json_type_boolean)
				goto done;

			parse_json_value_types(jobjkey,
						&data.values);
		}

		entry = l_new(knot_msg_data, 1);
		entry->sensor_id = sensor_id;
		memcpy(&(entry->payload), &data, sizeof(knot_data));
		l_queue_push_tail(list, entry);
	}
	json_object_put(jobj);

	return list;

done:
	l_queue_destroy(list, l_free);
	json_object_put(jobj);

	return NULL;
}

/*
 * Parses the json from the cloud with the get_data.
 */
static struct l_queue *parse_device_getdata(const char *json_str)
{
	json_object *jobj, *jobjarray, *jobjentry, *jobjkey;
	struct l_queue *list = NULL;
	knot_msg_item *entry;
	int sensor_id, i;

	jobj = json_tokener_parse(json_str);
	if (!jobj)
		return NULL;

	list = l_queue_new();

	/*
	 * Getting 'get_data' from the device properties
	 * {"devices":[{"uuid":
	 *		"get_data" : [
	 *			{"sensor_id": v
	 *			}]
	 * }
	 */

	/* 'set_data' is an array */
	if (!json_object_object_get_ex(jobj, "get_data", &jobjarray))
		goto done;

	if (json_object_get_type(jobjarray) != json_type_array)
		goto done;

	for (i = 0; i < json_object_array_length(jobjarray); i++) {

		jobjentry = json_object_array_get_idx(jobjarray, i);
		if (!jobjentry)
			goto done;

		/* Getting 'sensor_id' */
		if (!json_object_object_get_ex(jobjentry, "sensor_id",
								&jobjkey))
			goto done;

		if (json_object_get_type(jobjkey) != json_type_int)
			goto done;

		sensor_id = json_object_get_int(jobjkey);

		entry = l_new(knot_msg_item, 1);
		entry->sensor_id = sensor_id;

		l_queue_push_tail(list, entry);
	}
	json_object_put(jobj);

	return list;

done:
	l_queue_destroy(list, l_free);
	json_object_put(jobj);

	return NULL;
}

static void update_msg_item_header(void *entry_data, void *user_data)
{
	knot_msg_item *kmitem = entry_data;
	kmitem->hdr.type = KNOT_MSG_GET_DATA;
	kmitem->hdr.payload_len = sizeof(kmitem->sensor_id);
}

/*
 * Includes the proper header in the getdata messages and returns a list with
 * all the sensor from which the data is requested.
 */
static struct l_queue *msg_getdata(int node_socket, json_raw_t device_message,
	ssize_t *result)
{
	struct trust *trust;
	struct l_queue *messages;

	trust = trust_map_get(node_socket);
	if (!trust) {
		hal_log_info("Permission denied!");
		*result = KNOT_CREDENTIAL_UNAUTHORIZED;
		return NULL;
	}
	*result = KNOT_SUCCESS;

	messages = parse_device_getdata(device_message.data);
	l_queue_foreach(messages, update_msg_item_header, NULL);

	return messages;
}

static void update_msg_data_header(void *entry_data, void *user_data)
{
	knot_msg_data *kmdata = entry_data;
	kmdata->hdr.type = KNOT_MSG_SET_DATA;
	kmdata->hdr.payload_len = sizeof(kmdata->sensor_id) +
		sizeof(kmdata->payload);
}

/*
 * Includes the proper header in the setdata messages and returns a list with
 * all the sensor data that will be sent to the thing.
 */
static struct l_queue *msg_setdata(int node_socket, json_raw_t device_message,
	ssize_t *result)
{
	struct trust *trust;
	struct l_queue *messages;

	trust = trust_map_get(node_socket);
	if (!trust) {
		hal_log_info("Permission denied!");
		*result = KNOT_CREDENTIAL_UNAUTHORIZED;
		return NULL;
	}
	*result = KNOT_SUCCESS;

	messages = parse_device_setdata(device_message.data);
	l_queue_foreach(messages, update_msg_data_header, NULL);

	return messages;
}

static knot_msg_config *duplicate_msg_config(const knot_msg_config *config)
{
	knot_msg_config *new_config = l_new(knot_msg_config, 1);
	memcpy(new_config, config, sizeof(knot_msg_config));
	new_config->hdr.type = KNOT_MSG_SET_CONFIG;
	new_config->hdr.payload_len = sizeof(new_config->sensor_id) +
		sizeof(new_config->values);
	return new_config;
}

static void duplicate_and_append(struct config *config,
	struct l_queue *msg_config_list)
{
	knot_msg_config *msg_config = duplicate_msg_config(&config->kmcfg);
	l_queue_push_tail(msg_config_list, msg_config);
}

static struct l_queue *config_to_msg_config_list(struct l_queue *config_list)
{
	struct l_queue *msg_config_list;

	if (l_queue_isempty(config_list))
		return NULL;

	msg_config_list = l_queue_new();

	l_queue_foreach(config_list,
		(l_queue_foreach_func_t) duplicate_and_append,
		msg_config_list);

	return msg_config_list;
}

static bool config_cmp(struct config *config1, struct config *config2)
{
	/* If hashes don't match, either changed or is a new config */
	return !strcmp(config1->hash, config2->hash);
}

static bool exists_and_confirmed(struct config *received,
	struct l_queue *current_list)
{
	struct config *current = l_queue_find(current_list,
		(l_queue_match_func_t) config_cmp,
		received);
	return current && current->confirmed;
}

static struct l_queue *get_changed_config(struct l_queue *current,
	struct l_queue *received)
{
	struct l_queue *received_copy;
	struct l_queue *changed_configs;

	/*
	 * TODO:
	 * If a sensor_id is not in the list anymore, notify the thing.
	 */
	/*
	 * TODO:
	 * Define which approach is better, the current or when at least one
	 * config changes, the whole config message should be sent.
	 */
	received_copy = queue_clone(received);
	l_queue_foreach_remove(received_copy,
		(l_queue_remove_func_t) exists_and_confirmed,
		current);
	changed_configs = config_to_msg_config_list(received_copy);

	if (received_copy)
		l_queue_destroy(received_copy, NULL);
	
	return changed_configs;
}

/*
 * Parses the JSON from cloud to get all the configs. If the config is valid,
 * checks if any changed, and put them in the list that will be sent to the
 * thing. Returns the list with the messages to be sent or NULL if any error.
 */
static struct l_queue *msg_config(int node_socket, json_raw_t device_message,
	ssize_t *result)
{
	struct trust *trust;
	struct l_queue *config;
	struct l_queue *changed_config;

	trust = trust_map_get(node_socket);
	if (!trust) {
		hal_log_info("Permission denied!");
		*result = KNOT_CREDENTIAL_UNAUTHORIZED;
		return NULL;
	}

	config = parse_device_config(device_message.data);

	/* config_is_valid() returns 0 if SUCCESS */
	if (config_is_valid(config)) {
		hal_log_error("Invalid config message");
		l_queue_destroy(config, l_free);
		/*
		 * TODO: DEFINE KNOT_CONFIG ERRORS IN PROTOCOL
		 * KNOT_INVALID_CONFIG in new protocol
		 */
		*result = KNOT_NO_DATA;
		return NULL;
	}

	changed_config = get_changed_config(trust->config, config);
	trust_config_update(trust, config);

	*result = KNOT_SUCCESS;

	return changed_config;
}

/*
 * Sends the messages to the THING. Expects a response from the gateway
 * acknowledging that the message was successfully received.
 */
static int fw_push(int sock, knot_msg *kmsg)
{
	ssize_t nbytes;
	int err;

	nbytes = write(sock, kmsg->buffer, kmsg->hdr.payload_len +
							sizeof(kmsg->hdr));
	if (nbytes < 0) {
		err = errno;
		hal_log_error("node_ops: %s(%d)", strerror(err), err);
		return -err;
	}

	return 0;
}

static int get_socket_credentials(int sock, struct ucred *cred)
{
	socklen_t sklen;

	memset(cred, 0, sizeof(struct ucred));
	sklen = sizeof(struct ucred);
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, cred, &sklen) == -1) {
		hal_log_error("getsockopt(%d): %s(%d)", sock,
			strerror(errno), errno);
		return KNOT_ERROR_UNKNOWN;
	}

	return KNOT_SUCCESS;
}

static bool msg_register_has_valid_length(const knot_msg_register *kreq,
	size_t length)
{
	/* Min PDU len containing at least one char representing name */
	return length > (sizeof(kreq->hdr) + sizeof(kreq->id));
}

static bool msg_register_has_valid_device_name(const knot_msg_register *kreq)
{
	return kreq->devName[0] != '\0';
}

/* device_name must have length of KNOT_PROTOCOL_DEVICE_NAME_LEN */
static void msg_register_get_device_name(const knot_msg_register *kreq,
	char *device_name)
{
	size_t length;
	/*
	 * Make sure the device name is at maximum 63 bytes leaving 1 byte left
	 * for the terminating null character
	 */
	memset(device_name, 0, KNOT_PROTOCOL_DEVICE_NAME_LEN);

	length = MIN(kreq->hdr.payload_len - sizeof(kreq->id),
			KNOT_PROTOCOL_DEVICE_NAME_LEN - 1);

	strncpy(device_name, kreq->devName, length);
}

static json_object *create_device_object(const char *device_name,
	uint64_t device_id, const char *owner_uuid)
{
	json_object *device;
	device = json_object_new_object();
	if (!device) {
		return NULL;
	}

	json_object_object_add(device, "type",
				json_object_new_string("KNOTDevice"));
	json_object_object_add(device, "name",
				json_object_new_string(device_name));
	json_object_object_add(device, "id",
				json_object_new_int64(device_id));
	json_object_object_add(device, "owner",
				json_object_new_string(owner_uuid));

	return device;
}

static bool is_uuid_valid(const char *uuid)
{
	return strlen(uuid) == KNOT_PROTOCOL_UUID_LEN;
}

static bool is_token_valid(const char *token)
{
	return strlen(token) == KNOT_PROTOCOL_TOKEN_LEN;
}

/*
 * TODO: consider making this part of proto-ws.c mknode()
 */
static int proto_mknode(int proto_socket, const char *device_name,
	uint64_t device_id, const char *owner_uuid, char **uuid, char **token)
{
	int err, result;
	json_object *device;
	const char *device_as_string;
	json_raw_t response;

	device = create_device_object(device_name, device_id,
		owner_uuid);
	if (!device) {
		hal_log_error("JSON: no memory");
		result = KNOT_ERROR_UNKNOWN;
		goto fail_device;
	}

	device_as_string = json_object_to_json_string(device);
	memset(&response, 0, sizeof(response));
	err = proto->mknode(proto_socket, device_as_string, &response);
	json_object_put(device);

	if (err < 0) {
		hal_log_error("manager mknode: %s(%d)", strerror(-err), -err);
		result = KNOT_CLOUD_FAILURE;
		goto fail_mknode;
	}

	if (parse_device_info(response.data, uuid, token) < 0) {
		hal_log_error("Unexpected response!");
		result = KNOT_CLOUD_FAILURE;
		goto fail_parse;
	}

	/* Parse function never returns NULL for 'uuid' or 'token' fields */
	if (!is_uuid_valid(*uuid) || !is_token_valid(*token)) {
		hal_log_error("Invalid UUID or token!");
		result = KNOT_CLOUD_FAILURE;
		goto fail_valid;
	}

	result = KNOT_SUCCESS;
	goto done;

fail_valid:
	l_free(*uuid);
	l_free(*token);
done:
fail_parse:
	free(response.data);
fail_mknode:
fail_device:
	return result;
}

/*
 * TODO: consider making this part of proto-ws.c signin()
 */
static int proto_signin(int proto_socket, const char *uuid, const char *token,
	struct l_queue **schema, struct l_queue **config)
{
	int err, result;
	json_raw_t response;

	err = proto->signin(proto_socket, uuid, token, &response);

	if (!response.data) {
		result = KNOT_CLOUD_FAILURE;
		goto fail_signin_no_data;
	}

	if (err < 0) {
		hal_log_error("manager signin(): %s(%d)", strerror(-err), -err);
		result = KNOT_CREDENTIAL_UNAUTHORIZED;
		goto fail_signin;
	}

	if (schema != NULL) {
		*schema = parse_device_schema(response.data);
	}

	if (config != NULL) {
		*config = parse_device_config(response.data);
	}

	result = KNOT_SUCCESS;

fail_signin:
	free(response.data);
fail_signin_no_data:
	return result;
}

static void msg_credential_create(knot_msg_credential *message,
	const char *uuid, const char *token)
{
	strcpy(message->uuid, uuid);
	strcpy(message->token, token);

	/* Payload length includes the result, UUID and TOKEN */
	message->hdr.payload_len = sizeof(*message) - sizeof(knot_msg_header);
}

static int8_t msg_register(int node_socket, int proto_socket,
				 const knot_msg_register *kreq, size_t ilen,
				 knot_msg_credential *krsp)
{
	struct trust *trust;
	char *uuid, *token;
	int8_t result;
	char device_name[KNOT_PROTOCOL_DEVICE_NAME_LEN];
	struct ucred cred;

	if (!msg_register_has_valid_length(kreq, ilen)
		|| !msg_register_has_valid_device_name(kreq)) {
		hal_log_error("Missing device name!");
		result = KNOT_REGISTER_INVALID_DEVICENAME;
		goto fail_length;
	}

	/*
	 * Credential (Process ID) verification will work for unix socket
	 * only. For other socket types additional authentication mechanism
	 * will be required.
	 */
	result = get_socket_credentials(node_socket, &cred);
	if (result != KNOT_SUCCESS)
		hal_log_info("sock:%d, pid:%ld", node_socket, (long int) cred.pid);

	/*
	 * Due to radio packet loss, peer may re-transmits register request
	 * if response does not arrives in 20 seconds. If this device was
	 * previously added we just send the uuid/token again.
	 */
	hal_log_info("Registering (id 0x%" PRIx64 ") fd:%d", kreq->id, node_socket);
	trust = trust_map_get(node_socket);
	if (trust && kreq->id == trust->id && trust->pid == cred.pid) {
		hal_log_info("Register: trusted device");
		msg_credential_create(krsp, trust->uuid, trust->token);
		result = KNOT_SUCCESS;
		goto done;
	}

	msg_register_get_device_name(kreq, device_name);
	result = proto_mknode(proto_socket, device_name, kreq->id,
		owner_uuid,	&uuid, &token);
	if (result != KNOT_SUCCESS)
		goto fail_create;

	hal_log_info("UUID: %s, TOKEN: %s", uuid, token);

	result = proto_signin(proto_socket, uuid, token, NULL, NULL);
	if (result != KNOT_SUCCESS)
		goto fail_signin;

	msg_credential_create(krsp, uuid, token);

	trust_create(node_socket, proto_socket, uuid, token, kreq->id,
		(cred.pid ? : INT32_MAX), true, NULL, NULL);

	result = KNOT_SUCCESS;
	goto done;

fail_signin:
	l_free(uuid);
	l_free(token);
done:
fail_create:
fail_length:
	return result;
}

static int8_t msg_auth(int node_socket, int proto_socket,
				const knot_msg_authentication *kmauth)
{
	int8_t result;
	struct l_queue *schema, *config;
	char *uuid, *token;

	if (trust_map_get(node_socket)) {
		hal_log_info("Authenticated already");
		result = KNOT_SUCCESS;
		goto done;
	}

	result = proto_signin(proto_socket, kmauth->uuid, kmauth->token,
		&schema, &config);
	if (result != KNOT_SUCCESS)
		goto done;

	if (schema == NULL) {
		result = KNOT_SCHEMA_EMPTY;
		goto fail_schema;
	}

	if (config_is_valid(config)) {
		hal_log_error("Invalid config message");
		l_queue_destroy(config, config_free);
		config = NULL;
	}

	/*
	 * l_strndup returns a newly-allocated buffer n + 1 bytes
	 * long which will always be nul-terminated.
	 */
	uuid = l_strndup(kmauth->uuid, sizeof(kmauth->uuid));
	token = l_strndup(kmauth->token, sizeof(kmauth->token));
	/* TODO: should we receive the ID? Should we get the socket PID? */
	trust_create(node_socket, proto_socket, uuid, token, 0, 0, false,
		schema, config);

	result = KNOT_SUCCESS;
	goto done;

fail_schema:
	l_queue_destroy(config, config_free);
done:
	return result;
}

static json_object *create_schema_object(uint8_t sensor_id, uint8_t value_type,
	uint8_t unit, uint16_t type_id, const char *name)
{
	json_object *schema;

	schema = json_object_new_object();
	json_object_object_add(schema, "sensor_id",
		json_object_new_int(sensor_id));
	json_object_object_add(schema, "value_type",
		json_object_new_int(value_type));
	json_object_object_add(schema, "unit",
		json_object_new_int(unit));
	json_object_object_add(schema, "type_id",
		json_object_new_int(type_id));
	json_object_object_add(schema, "name",
		json_object_new_string(name));

	return schema;
}

static void create_and_append(knot_msg_schema *schema,
	json_object *schema_list)
{
	json_object *item = create_schema_object(schema->sensor_id, schema->values.value_type,
		schema->values.unit, schema->values.type_id, schema->values.name);
	json_object_array_add(schema_list, item);
}

static json_object *create_schema_list_object(struct l_queue *schema_list)
{
	json_object *jschema, *jschema_list;

	jschema = json_object_new_object();
	jschema_list = json_object_new_array();
	l_queue_foreach(schema_list,
		(l_queue_foreach_func_t) create_and_append,
		jschema_list);
	json_object_object_add(jschema, "schema", jschema_list);

	return jschema;
}

/*
 * TODO: consider making this part of proto-ws.c signin()
 */
static int proto_schema(int proto_socket, const char *uuid, const char *token,
	struct l_queue *schema_list)
{
	int result, err;
	json_object *jschema_list;
	const char *jschema_list_as_string;
	json_raw_t response;

	jschema_list = create_schema_list_object(schema_list);
	jschema_list_as_string = json_object_to_json_string(jschema_list);

	memset(&response, 0, sizeof(response));
	err = proto->schema(proto_socket, uuid, token, jschema_list_as_string,
		&response);

	if (response.data)
		free(response.data);

	json_object_put(jschema_list);

	if (err < 0) {
		hal_log_error("manager schema(): %s(%d)", strerror(-err), -err);
		result = KNOT_CLOUD_FAILURE;
		goto done;
	}

	result = KNOT_SUCCESS;

done:
	return result;
}

static int8_t msg_schema(int node_socket, int proto_socket,
				const knot_msg_schema *schema, bool eof)
{
	int8_t result;
	struct trust *trust;

	trust = trust_map_get(node_socket);
	if (!trust) {
		hal_log_info("Permission denied!");
		result = KNOT_CREDENTIAL_UNAUTHORIZED;
		goto done;
	}

	/*
	 * For security reason, remove from rollback avoiding clonning attack.
	 * If schema is being sent means that credentals (UUID/token) has been
	 * properly received (registration complete).
	 */
	trust->rollback = false;

	/*
	 * {
	 *	"schema" : [
	 *		{"sensor_id": x, "value_type": w,
	 *			"unit": z "type_id": y, "name": "foo"}
	 * 	]
	 * }
	 */

	/*
	 * Checks whether the schema was received before and if not, adds
	 * to a temporary list until receiving complete schema.
	 */
	if (!trust_get_sensor_schema_tmp(trust, schema->sensor_id))
		trust_sensor_schema_tmp_add(trust, schema);

	 /* TODO: missing timer to wait for end of schema transfer */

	if (!eof) {
		result = KNOT_SUCCESS;
		goto done;
	}

	result = proto_schema(proto_socket, trust->uuid, trust->token,
		trust->schema_tmp);
	if (result != KNOT_SUCCESS) {
		trust_sensor_schema_tmp_free(trust);
		goto done;
	}

	/* If succeed: free old schema and use the new one */
	trust_sensor_schema_complete(trust);

done:
	return result;
}

/*
 * Updates the 'devices' db, removing the sensor_id that just sent the data
 */
static void update_device_getdata(int proto_sock, char *uuid, char *token,
					uint8_t sensor_id)
{
	json_object *jobj, *jobjarray, *jobjentry, *jobjkey;
	json_object *ajobj, *setdatajobj;
	json_raw_t json;
	const char *jobjstr;
	int i, err;

	memset(&json, 0, sizeof(json));
	err = proto->fetch(proto_sock, uuid, token, &json);
	if (err < 0) {
		hal_log_error("signin(): %s(%d)", strerror(-err), -err);
		goto done;
	}

	jobj = json_tokener_parse(json.data);
	if (!jobj)
		goto done;

	ajobj = json_object_new_array();
	setdatajobj = json_object_new_object();

	/*
	 * Getting 'get_data' from the device properties
	 * {"devices":[{"uuid":
	 *		"get_data" : [
	 *			{"sensor_id": v
	 *			}]
	 *		}]
	 * }
	 */

	/* 'get_data' is an array */
	if (!json_object_object_get_ex(jobj, "get_data", &jobjarray))
		goto done;

	if (json_object_get_type(jobjarray) != json_type_array)
		goto done;

	for (i = 0; i < json_object_array_length(jobjarray); i++) {

		jobjentry = json_object_array_get_idx(jobjarray, i);
		if (!jobjentry)
			break;

		/* Getting 'sensor_id' */
		if (!json_object_object_get_ex(jobjentry, "sensor_id",
								&jobjkey))
			continue;

		/*
		 * Creates a list with all the sensor_id in the get_data list
		 * except for the one that was just received
		 */
		if (json_object_get_int(jobjkey) != sensor_id) {
			json_object_array_add(ajobj,
						json_object_get(jobjentry));
			continue;
		}
		/*
		 * TODO: if the value changed before it was updated, the entry
		 * should not be erased
		 */
	}

	json_object_object_add(setdatajobj, "get_data", json_object_get(ajobj));
	jobjstr = json_object_to_json_string(setdatajobj);

	err = proto->setdata(proto_sock, uuid, token, jobjstr, &json);

done:
	if (jobj)
		json_object_put(jobj);
	if (setdatajobj)
		json_object_put(setdatajobj);
	if (ajobj)
		json_object_put(ajobj);
	free(json.data);
}

/*
 * TODO: consider moving this to knot-protocol
 */
static int knot_data_as_int(const knot_data *data)
{
	return data->values.val_i.value;
}

/*
 * TODO: consider moving this to knot-protocol
 */
static int knot_data_get_double_length(const knot_data *data)
{
	char buffer[12]; /* INT_MAX 2147483647 */
	/* FIXME: precision */
	return sprintf(buffer, "%d", data->values.val_f.value_dec);
}

/*
 * TODO: consider moving this to knot-protocol
 */
static double knot_data_as_double(const knot_data *data)
{
	int length = knot_data_get_double_length(data);
	return data->values.val_f.multiplier *
		(data->values.val_f.value_int +
		(data->values.val_f.value_dec / pow(10, length)));
}

/*
 * TODO: consider moving this to knot-protocol
 */
static bool knot_data_as_boolean(const knot_data *data)
{
	return data->values.val_b;
}

static json_object *create_data_object(uint8_t sensor_id,
	uint8_t value_type, const knot_data *value)
{
	json_object *data;

	data = json_object_new_object();
	json_object_object_add(data, "sensor_id",
						json_object_new_int(sensor_id));

	switch (value_type) {
	case KNOT_VALUE_TYPE_INT:
		json_object_object_add(data, "value",
				json_object_new_int(knot_data_as_int(value)));
		break;
	case KNOT_VALUE_TYPE_FLOAT:
		json_object_object_add(data, "value",
					json_object_new_double(knot_data_as_double(value)));
		break;
	case KNOT_VALUE_TYPE_BOOL:
		json_object_object_add(data, "value",
				json_object_new_boolean(knot_data_as_boolean(value)));
		break;
	case KNOT_VALUE_TYPE_RAW:
		break;
	default:
		json_object_put(data);
		return NULL;
	}

	return data;
}

/*
 * TODO: consider making this part of proto-ws.c signin()
 */
static int proto_data(int proto_socket, const char *uuid, const char *token,
	uint8_t sensor_id, uint8_t value_type, const knot_data *value)
{
	int result, err;
	struct json_object *data;
	const char *data_as_string;
	json_raw_t response;

	data = create_data_object(sensor_id, value_type, value);
	if (!data) {
		result = KNOT_INVALID_DATA;
		goto done;
	}

	data_as_string = json_object_to_json_string(data);

	memset(&response, 0, sizeof(response));
	err = proto->data(proto_socket, uuid, token, data_as_string, &response);

	if (response.data)
		free(response.data);

	json_object_put(data);

	if (err < 0) {
		hal_log_error("manager data(): %s(%d)", strerror(-err), -err);
		result = KNOT_CLOUD_FAILURE;
		goto done;
	}

	result = KNOT_SUCCESS;

done:
	return result;
}

static int8_t msg_data(int node_socket, int proto_socket,
					const knot_msg_data *kmdata)
{
	int8_t result;
	int err;
	uint8_t sensor_id;
	const struct trust *trust;
	const knot_msg_schema *schema;
	/*
	 * Pointer to KNOT data containing header, sensor id
	 * and a primitive KNOT type
	 */
	const knot_data *kdata = &(kmdata->payload);

	trust = trust_map_get(node_socket);
	if (!trust) {
		hal_log_info("Permission denied!");
		result = KNOT_CREDENTIAL_UNAUTHORIZED;
		goto done;
	}

	sensor_id = kmdata->sensor_id;
	schema = trust_get_sensor_schema(trust, sensor_id);
	if (!schema) {
		hal_log_info("sensor_id(0x%02x): data type mismatch!",
								sensor_id);
		result = KNOT_INVALID_DATA;
		goto done;
	}

	err = knot_schema_is_valid(schema->values.type_id,
				schema->values.value_type, schema->values.unit);
	if (err) {
		hal_log_info("sensor_id(0x%d), type_id(0x%04x): unit mismatch!",
					sensor_id, schema->values.type_id);
		result = KNOT_INVALID_DATA;
		goto done;
	}

	hal_log_info("sensor:%d, unit:%d, value_type:%d", sensor_id,
				schema->values.unit, schema->values.value_type);

	result = proto_data(proto_socket, trust->uuid, trust->token, sensor_id,
		schema->values.value_type, kdata);

	update_device_getdata(proto_socket, trust->uuid, trust->token, sensor_id);

done:
	return result;
}

static int8_t msg_config_resp(int node_socket, const knot_msg_item *response)
{
	struct trust *trust;
	uint8_t sensor_id;

	trust = trust_map_get(node_socket);
	if (!trust) {
		hal_log_info("Permission denied!");
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	sensor_id = response->sensor_id;
	trust_config_confirm(trust, sensor_id);

	hal_log_info("THING %s received config for sensor %d", trust->uuid,
								sensor_id);

	return KNOT_SUCCESS;
}

/*
 * Updates de 'devices' db, removing the sensor_id that was acknowledged by the
 * THING.
 */
static void update_device_setdata(int proto_sock, char *uuid, char *token,
					uint8_t sensor_id)
{
	json_object *jobj, *jobjarray, *jobjentry, *jobjkey;
	json_object *ajobj, *setdatajobj;
	json_raw_t json;
	const char *jobjstr;
	int i, err;

	memset(&json, 0, sizeof(json));
	err = proto->fetch(proto_sock, uuid, token, &json);

	if (err < 0) {
		hal_log_error("signin(): %s(%d)", strerror(-err), -err);
		goto done;
	}

	jobj = json_tokener_parse(json.data);
	if (!jobj)
		goto done;

	ajobj = json_object_new_array();
	setdatajobj = json_object_new_object();
	/*
	 * Getting 'set_data' from the device properties:
	 * {"devices":[{"uuid":
	 *		"set_data" : [
	 *			{"sensor_id": v,
	 *			"value": w}]
	 * }
	 */

	/* 'set_data' is an array */
	if (!json_object_object_get_ex(jobj, "set_data", &jobjarray))
		goto done;

	if (json_object_get_type(jobjarray) != json_type_array)
		goto done;


	for (i = 0; i < json_object_array_length(jobjarray); i++) {

		jobjentry = json_object_array_get_idx(jobjarray, i);
		if (!jobjentry)
			break;

		/* Getting 'sensor_id' */
		if (!json_object_object_get_ex(jobjentry, "sensor_id",
								&jobjkey))
			continue;

		if (json_object_get_int(jobjkey) != sensor_id) {
			json_object_array_add(ajobj,
						json_object_get(jobjentry));
			continue;
		}
		/*
		 * TODO: if the value changed before it was updated, the entry
		 * should not be erased
		 */
	}

	json_object_object_add(setdatajobj, "set_data", json_object_get(ajobj));
	jobjstr = json_object_to_json_string(setdatajobj);

	err = proto->setdata(proto_sock, uuid, token, jobjstr, &json);

done:
	if (jobj)
		json_object_put(jobj);
	if (setdatajobj)
		json_object_put(setdatajobj);
	if (ajobj)
		json_object_put(ajobj);
	free(json.data);
}

/*
 * Works like msg_data() (copy & paste), but removes the received info from
 * the 'devices' database.
 */
static int8_t msg_setdata_resp(int node_socket, int proto_socket,
					const knot_msg_data *kmdata)
{
	int8_t result;
	int err;
	uint8_t sensor_id;
	const struct trust *trust;
	const knot_msg_schema *schema;
	/*
	 * Pointer to KNOT data containing header, sensor id
	 * and a primitive KNOT type
	 */
	const knot_data *kdata = &(kmdata->payload);

	trust = trust_map_get(node_socket);
	if (!trust) {
		hal_log_info("Permission denied!");
		result = KNOT_CREDENTIAL_UNAUTHORIZED;
		goto done;
	}

	sensor_id = kmdata->sensor_id;
	schema = trust_get_sensor_schema(trust, sensor_id);
	if (!schema) {
		hal_log_info("sensor_id(0x%02x): data type mismatch!",
								sensor_id);
		result = KNOT_INVALID_DATA;
		goto done;
	}

	err = knot_schema_is_valid(schema->values.type_id,
				schema->values.value_type, schema->values.unit);
	if (err) {
		hal_log_info("sensor_id(0x%d), type_id(0x%04x): unit mismatch!",
					sensor_id, schema->values.type_id);
		result = KNOT_INVALID_DATA;
		goto done;
	}

	hal_log_info("sensor:%d, unit:%d, value_type:%d", sensor_id,
				schema->values.unit, schema->values.value_type);

	/* Fetches the 'devices' db */
	update_device_setdata(proto_socket, trust->uuid, trust->token,
								sensor_id);

	result = proto_data(proto_socket, trust->uuid, trust->token, sensor_id,
		schema->values.value_type, kdata);
	if (result != KNOT_SUCCESS)
		goto done;

	hal_log_info("THING %s updated data for sensor %d", trust->uuid,
								sensor_id);
	result = KNOT_SUCCESS;

done:
	return result;
}


ssize_t msg_process(int sock, int proto_sock,
				const void *ipdu, size_t ilen,
				void *opdu, size_t omtu)
{
	const knot_msg *kreq = ipdu;
	knot_msg *krsp = opdu;
	uint8_t rtype;
	int8_t result = KNOT_INVALID_DATA;
	bool eof;

	/* Verify if output PDU has a min length */
	if (omtu < sizeof(knot_msg)) {
		hal_log_error("Output PDU: invalid PDU length");
		return -EINVAL;
	}

	/* Set a default payload length for error */
	krsp->hdr.payload_len = sizeof(krsp->action.result);

	/* At least header should be received */
	if (ilen < sizeof(knot_msg_header)) {
		hal_log_error("KNOT PDU: invalid minimum length");
		return -EINVAL;
	}

	/* Checking PDU length consistency */
	if (ilen != (sizeof(kreq->hdr) + kreq->hdr.payload_len)) {
		hal_log_error("KNOT PDU: length mismatch");
		return -EINVAL;
	}

	hal_log_info("KNOT OP: 0x%02X LEN: %02x",
				kreq->hdr.type, kreq->hdr.payload_len);

	switch (kreq->hdr.type) {
	case KNOT_MSG_REGISTER_REQ:
		/* Payload length is set by the caller */
		result = msg_register(sock, proto_sock,
							&kreq->reg, ilen, &krsp->cred);
		rtype = KNOT_MSG_REGISTER_RESP;
		break;
	case KNOT_MSG_UNREGISTER_REQ:
		result = msg_unregister(sock, proto_sock);
		rtype = KNOT_MSG_UNREGISTER_RESP;
		break;
	case KNOT_MSG_DATA:
		result = msg_data(sock, proto_sock, &kreq->data);
		rtype = KNOT_MSG_DATA_RESP;
		break;
	case KNOT_MSG_AUTH_REQ:
		result = msg_auth(sock, proto_sock, &kreq->auth);
		rtype = KNOT_MSG_AUTH_RESP;
		break;
	case KNOT_MSG_SCHEMA:
	case KNOT_MSG_SCHEMA_END:
		eof = kreq->hdr.type == KNOT_MSG_SCHEMA_END ? true : false;
		result = msg_schema(sock, proto_sock, &kreq->schema, eof);
		rtype = KNOT_MSG_SCHEMA_RESP;
		if (eof)
			rtype = KNOT_MSG_SCHEMA_END_RESP;
		break;
	case KNOT_MSG_CONFIG_RESP:
		result = msg_config_resp(sock, &kreq->item);
		/* No octets to be transmitted */
		return 0;
	case KNOT_MSG_DATA_RESP:
		result = msg_setdata_resp(sock, proto_sock, &kreq->data);
		return 0;
	default:
		/* TODO: reply unknown command */
		break;
	}

	krsp->hdr.type = rtype;

	krsp->action.result = result;

	/* Return the actual amount of octets to be transmitted */
	return (sizeof(knot_msg_header) + krsp->hdr.payload_len);
}

int msg_start(const char *uuid, struct proto_ops *proto_ops)
{
	memset(owner_uuid, 0, sizeof(owner_uuid));
	strncpy(owner_uuid, uuid, sizeof(owner_uuid));
	proto = proto_ops;

	trust_map_create();

	return 0;
}

void msg_stop(void)
{
	trust_map_destroy();
}
