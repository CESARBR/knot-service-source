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
#include <errno.h>

#include <sys/socket.h>

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include <json-c/json.h>

#include <knot_types.h>
#include <knot_protocol.h>

#include <unistd.h>

#include <hal/linux_log.h>

#include "proto.h"
#include "msg.h"

struct config {
	knot_msg_config kmcfg;		/* knot_message_config from cloud */
	char *hash;			/* Checksum of kmcfg */
	gboolean confirmed;

};

struct trust {
	gint refs;
	pid_t	pid;			/* Peer PID */
	uint64_t id;			/* Session identification */
	gboolean rollback;		/* Remove from cloud if TRUE */
	char *uuid;			/* Device UUID */
	char *token;			/* Device token */
	GSList *schema;			/* knot_schema accepted by cloud */
	GSList *schema_tmp;		/*
					* knot_schema to be submitted to cloud
					*/
	GSList *config;			/* knot_config accepted from cloud */
	GSList *config_tmp;		/* knot_config to be validate by GW */
	const struct proto_ops *proto_ops; /* Cloud driver */
	GIOChannel *proto_io;		/* Cloud IO channel */
};

struct proto_watch {
	unsigned int id;
	GIOChannel *node_io;
};

/* Maps sockets to sessions: online devices only.  */
static GHashTable *trust_list;

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
	const knot_msg_schema *kmsch, gboolean eof);
static GSList *msg_config(int sock, json_raw_t json, ssize_t *result);
static int8_t msg_config_resp(int sock, const knot_msg_item *rsp);
static GSList *msg_setdata(int sock, json_raw_t json, ssize_t *result);
static int8_t msg_setdata_resp(int sock, int proto_sock,
	const knot_msg_data *kmdata);
static GSList *msg_getdata(int sock, json_raw_t json, ssize_t *result);
static int fw_push(int sock, knot_msg *kmsg);

/*
 * Callback that parses the JSON for config (and in the future, send data)
 * messages. It is called from the protocol that is used to communicate with
 * the cloud (e.g. http, websocket).
 */
static void on_device_changed(json_raw_t json, void *user_data)
{
	const struct proto_watch *watch = user_data;
	int sock;
	ssize_t result;
	GSList *list;
	GSList *tmp;

	sock = g_io_channel_unix_get_fd(watch->node_io);

	list = msg_config(sock, json, &result);
	list = g_slist_concat(list, msg_setdata(sock, json, &result));
	list = g_slist_concat(list, msg_getdata(sock, json, &result));

	tmp = list;
	while (tmp) {
		result = fw_push(sock, tmp->data);
		if (result)
			hal_log_error("KNOT SEND ERROR");
		tmp = g_slist_next(tmp);
	}
	g_slist_free_full(list, g_free);
}

static struct proto_watch *add_device_watch(int proto_socket, char *uuid,
	char *token, GIOChannel *node_channel)
{
	struct proto_watch *proto_watch;

	proto_watch = g_new0(struct proto_watch, 1);
	proto_watch->id = proto->async(proto_socket, uuid, token, on_device_changed,
		proto_watch);
	proto_watch->node_io = g_io_channel_ref(node_channel);

	return proto_watch;
}

static void remove_device_watch(struct proto_watch *proto_watch)
{
	if (proto_watch->id > 0)
		g_source_remove(proto_watch->id);

	g_io_channel_unref(proto_watch->node_io);
	g_free(proto_watch);
}

static void config_free(gpointer mem)
{
	struct config *cfg = mem;

	g_free(cfg->hash);
	g_free(cfg);
}

static struct trust *trust_ref(struct trust *trust)
{
	g_atomic_int_inc(&trust->refs);

	return trust;
}

static void trust_unref(struct trust *trust)
{
	if (!g_atomic_int_dec_and_test(&trust->refs))
		return;

	g_io_channel_unref(trust->proto_io);
	g_free(trust->uuid);
	g_free(trust->token);
	g_slist_free_full(trust->schema, g_free);
	g_slist_free_full(trust->schema_tmp, g_free);
	g_slist_free_full(trust->config, config_free);
	g_free(trust);
}

static struct trust *trust_get(int id)
{
	return g_hash_table_lookup(trust_list, GINT_TO_POINTER(id));
}

static void trust_remove(int id)
{
	g_hash_table_remove(trust_list, GINT_TO_POINTER(id));
}

static GIOChannel *create_node_channel(int node_socket)
{
	return g_io_channel_unix_new(node_socket);
}

static gboolean on_node_channel_disconnected(GIOChannel *channel,
	GIOCondition cond, gpointer used_data)
{
	struct trust *trust;
	int node_socket, proto_socket;

	node_socket = g_io_channel_unix_get_fd(channel);

	trust = trust_get(node_socket);
	if (!trust)
		return FALSE;

	/* Zombie device: registration not complete */
	if (trust->rollback) {
		proto_socket = g_io_channel_unix_get_fd(trust->proto_io);
		if (msg_unregister(node_socket, proto_socket) != KNOT_SUCCESS) {
			hal_log_info("Rollback failed UUID: %s", trust->uuid);
		}
	}

	g_hash_table_remove(trust_list, GINT_TO_POINTER(node_socket));

	return FALSE;
}

static void on_node_channel_destroyed(gpointer user_data)
{
	struct trust *trust = (struct trust *)user_data;
	trust_unref(trust);
}

static void add_node_channel_watch(GIOChannel *channel, struct trust *trust)
{
	g_io_add_watch_full(channel,
		G_PRIORITY_HIGH,
		G_IO_HUP | G_IO_NVAL | G_IO_ERR,
		on_node_channel_disconnected,
		trust_ref(trust),
		on_node_channel_destroyed);
	g_io_channel_unref(channel);
}

static GIOChannel *create_proto_channel(int proto_socket)
{
	return g_io_channel_unix_new(proto_socket);
}

static gboolean on_proto_channel_disconnected(GIOChannel *channel,
	GIOCondition cond, gpointer user_data)
{
	struct proto_watch *proto_watch = (struct proto_watch *)user_data;

	remove_device_watch(proto_watch);

	return FALSE;
}

static void add_proto_channel_watch(GIOChannel *channel,
	struct proto_watch *proto_watch)
{
	g_io_add_watch(channel,
		G_IO_HUP | G_IO_NVAL | G_IO_ERR,
		on_proto_channel_disconnected,
		proto_watch);
}

static void trust_create(int node_socket, int proto_socket, char *uuid,
	char *token, uint64_t device_id, pid_t pid, bool rollback,
	GSList *schema, GSList *config)
{
	struct trust *trust;
	struct proto_watch *proto_watch;
	GIOChannel *node_channel;

	trust = g_new0(struct trust, 1);
	trust->uuid = uuid;
	trust->token = token;
	trust->id = device_id;
	trust->pid = pid;
	trust->rollback = rollback;
	trust->schema = schema;
	trust->config = config;

	g_hash_table_replace(trust_list, GINT_TO_POINTER(node_socket),
							trust_ref(trust));

	/* Add a watch to remove the credential when the client disconnects */
	node_channel = create_node_channel(node_socket);
	add_node_channel_watch(node_channel, trust);

	/* Add a watch to remove source when cloud disconnects */
	proto_watch = add_device_watch(proto_socket, uuid, token, node_channel);
	trust->proto_io = create_proto_channel(proto_socket);
	add_proto_channel_watch(trust->proto_io, proto_watch);
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

	trust = trust_get(node_socket);
	if (!trust) {
		hal_log_info("Permission denied!");
		result = KNOT_CREDENTIAL_UNAUTHORIZED;
		goto done;
	}

	hal_log_info("rmnode: %.36s", trust->uuid);
	result = proto_rmnode(proto_socket, trust->uuid, trust->token);
	if (result != KNOT_SUCCESS)
		goto done;

	trust_remove(node_socket);
	result = KNOT_SUCCESS;

done:
	return result;
}

static int sensor_id_cmp(gconstpointer a, gconstpointer b)
{
	const knot_msg_schema *schema = a;
	unsigned int sensor_id = GPOINTER_TO_UINT(b);

	return sensor_id - schema->sensor_id;
}

static char *checksum_config(json_object *jobjkey)
{
	const char *c;

	c = json_object_to_json_string(jobjkey);

	return g_compute_checksum_for_string(G_CHECKSUM_SHA1, c, strlen(c));
}

/*
 * Checks if the config message received from the cloud is valid.
 * Validates if the values are valid and if the event_flags are consistent
 * with desired events.
 * No need to check if sensor_id,event_flags and time_sec are positive for
 * they are unsigned from protocol.
 */
static int config_is_valid(GSList *config_list)
{
	knot_msg_config *config;
	struct config *cfg;
	GSList *list;
	int diff_int, diff_dec;

	for (list = config_list; list; list = g_slist_next(list)) {
		cfg = list->data;
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

	*puuid = g_strdup(uuid);
	*ptoken = g_strdup(token);

	err = 0; /* Success */
done:
	json_object_put(jobj);

	return err;
}

static GSList *parse_device_schema(const char *json_str)
{
	json_object *jobj, *jobjarray, *jobjentry, *jobjkey;
	GSList *list = NULL;
	knot_msg_schema *entry;
	int sensor_id, value_type, unit, type_id, i;
	const char *name;

	jobj = json_tokener_parse(json_str);
	if (!jobj)
		return NULL;

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
		entry = g_new0(knot_msg_schema, 1);
		entry->sensor_id = sensor_id;
		entry->values.value_type = value_type;
		entry->values.unit = unit;
		entry->values.type_id = type_id;
		strncpy(entry->values.name, name,
						sizeof(entry->values.name) - 1);

		list = g_slist_append(list, entry);
	}
done:
	json_object_put(jobj);

	return list;
}

/*
 * Parses the json from the cloud with the config. The message is discarded if:
 * There are no "devices" or "config" fields in the JSON or they are not arrays.
 * The mandatory fields "sensor_id" and "event_flags" are missing.
 * Any field that is sent has the wrong type.
 */
static GSList *parse_device_config(const char *json_str)
{
	json_object *jobj, *jobjarray, *jobjentry, *jobjkey;
	GSList *list = NULL;
	struct config *entry;
	int sensor_id, event_flags, time_sec, i;
	knot_value_types lower_limit, upper_limit;
	json_type jtype;

	jobj = json_tokener_parse(json_str);
	if (!jobj)
		return NULL;

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

		entry = g_new0(struct config, 1);
		entry->kmcfg.sensor_id = sensor_id;
		entry->kmcfg.values.event_flags = event_flags;
		entry->kmcfg.values.time_sec = time_sec;
		memcpy(&(entry->kmcfg.values.lower_limit), &lower_limit,
						sizeof(knot_value_types));
		memcpy(&(entry->kmcfg.values.upper_limit), &upper_limit,
						sizeof(knot_value_types));
		entry->hash = checksum_config(jobjentry);
		entry->confirmed = FALSE;
		list = g_slist_append(list, entry);
	}

	json_object_put(jobj);

	return list;

done:
	g_slist_free_full(list, config_free);
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
static GSList *parse_device_setdata(const char *json_str)
{
	json_object *jobj, *jobjarray, *jobjentry, *jobjkey;
	GSList *list = NULL;
	knot_msg_data *entry;
	int sensor_id, i;
	knot_data data;
	json_type jtype;

	jobj = json_tokener_parse(json_str);
	if (!jobj)
		return NULL;

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

		entry = g_new0(knot_msg_data, 1);
		entry->sensor_id = sensor_id;
		memcpy(&(entry->payload), &data, sizeof(knot_data));
		list = g_slist_append(list, entry);
	}
	json_object_put(jobj);

	return list;

done:
	g_slist_free_full(list, g_free);
	json_object_put(jobj);

	return NULL;
}

/*
 * Parses the json from the cloud with the get_data.
 */
static GSList *parse_device_getdata(const char *json_str)
{
	json_object *jobj, *jobjarray, *jobjentry, *jobjkey;
	GSList *list = NULL;
	knot_msg_item *entry;
	int sensor_id, i;

	jobj = json_tokener_parse(json_str);
	if (!jobj)
		return NULL;

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

		entry = g_new0(knot_msg_item, 1);
		entry->sensor_id = sensor_id;
		list = g_slist_append(list, entry);
	}
	json_object_put(jobj);

	return list;

done:
	g_slist_free_full(list, g_free);
	json_object_put(jobj);

	return NULL;
}

/*
 * Includes the proper header in the getdata messages and returns a list with
 * all the sensor from which the data is requested.
 */
static GSList *msg_getdata(int sock, json_raw_t json, ssize_t *result)
{
	struct trust *trust;
	GSList *list;
	GSList *tmp;
	knot_msg_item *kmitem;

	trust = g_hash_table_lookup(trust_list, GINT_TO_POINTER(sock));
	if (!trust) {
		hal_log_info("Permission denied!");
		*result = KNOT_CREDENTIAL_UNAUTHORIZED;
		return NULL;
	}
	*result = KNOT_SUCCESS;

	list = parse_device_getdata(json.data);

	for (tmp = list; tmp; tmp = g_slist_next(tmp)) {
		kmitem = tmp->data;
		kmitem->hdr.type = KNOT_MSG_GET_DATA;
		kmitem->hdr.payload_len = sizeof(kmitem->sensor_id);
	}

	return list;
}

/*
 * Includes the proper header in the setdata messages and returns a list with
 * all the sensor data that will be sent to the thing.
 */
static GSList *msg_setdata(int sock, json_raw_t json, ssize_t *result)
{
	struct trust *trust;
	GSList *list;
	GSList *tmp;
	knot_msg_data *kmdata;

	trust = g_hash_table_lookup(trust_list, GINT_TO_POINTER(sock));
	if (!trust) {
		hal_log_info("Permission denied!");
		*result = KNOT_CREDENTIAL_UNAUTHORIZED;
		return NULL;
	}
	*result = KNOT_SUCCESS;

	list = parse_device_setdata(json.data);

	for (tmp = list; tmp; tmp = g_slist_next(tmp)) {
		kmdata = tmp->data;
		kmdata->hdr.type = KNOT_MSG_SET_DATA;
		kmdata->hdr.payload_len = sizeof(kmdata->sensor_id) +
							sizeof(kmdata->payload);
	}

	return list;
}


/*
 * Returns a list of all the configs that changed compared to the stored in
 * trust->config. If the trust->config is empty, returns a list with all the
 * configs that were received by the cloud. If nothing was received from the
 * cloud, returns NULL.
 */
static GSList *get_changed_config(GSList *current, GSList *received)
{
	GSList *cur;
	GSList *rec = received;
	struct config *rcfg;
	struct config *ccfg;
	knot_msg_config *kmsg;
	GSList *list = NULL;
	gboolean match;

	/*If nothing was received from the cloud, returns NULL.*/
	if (!received)
		return NULL;

	/*
	 * If there is nothing in the current config list, returns all that was
	 *received from the cloud
	 */
	if (!current) {
		while (rec) {
			rcfg = rec->data;
			kmsg = g_new0(knot_msg_config, 1);
			memcpy(kmsg, &rcfg->kmcfg, sizeof(knot_msg_config));
			kmsg->hdr.type = KNOT_MSG_SET_CONFIG;
			kmsg->hdr.payload_len = sizeof(kmsg->sensor_id) +
							sizeof(kmsg->values);
			list = g_slist_append(list, kmsg);
			rec = g_slist_next(rec);
		}
		return list;
	}
	/*
	 * Compares the received configs with the ones already stored.
	 * If the hash matches one in the current list, the config did not
	 * change.
	 * If no match was found, then either the config for that sensor changed
	 * or it is a new sensor.
	 */
	/*
	 * TODO:
	 * If a sensor_id is not in the list anymore, notify the thing.
	 */
	/*
	 * TODO:
	 * Define which approach is better, the current or when at least one
	 * config changes, the whole config message should be sent.
	 */
	while (rec) {
		rcfg = rec->data;
		match = FALSE;
		for (cur = current; cur; cur = g_slist_next(cur)) {
			ccfg = cur->data;
			if (!strcmp(ccfg->hash, rcfg->hash)) {
				match = TRUE;
				rcfg->confirmed = ccfg->confirmed;
				if (!rcfg->confirmed) {
					kmsg = g_new0(knot_msg_config, 1);
					memcpy(kmsg, &rcfg->kmcfg,
						sizeof(knot_msg_config));
					kmsg->hdr.type = KNOT_MSG_SET_CONFIG;
					kmsg->hdr.payload_len =
						sizeof(kmsg->sensor_id) +
						sizeof(kmsg->values);
					list = g_slist_append(list, kmsg);
				}
				break;
			}
		}
		if (!match) {
			kmsg = g_new0(knot_msg_config, 1);
			memcpy(kmsg, &rcfg->kmcfg, sizeof(knot_msg_config));
			kmsg->hdr.type = KNOT_MSG_SET_CONFIG;
			kmsg->hdr.payload_len = sizeof(kmsg->sensor_id) +
							sizeof(kmsg->values);
			list = g_slist_append(list, kmsg);
		}
		rec = g_slist_next(rec);
	}

	return list;
}

/*
 * Parses the JSON from cloud to get all the configs. If the config is valid,
 * checks if any changed, and put them in the list that  will be sent to the
 * thing. Returns the list with the messages to be sent or  NULL if any error.
 */
static GSList *msg_config(int sock, json_raw_t json, ssize_t *result)
{
	struct trust *trust;
	GSList *list;

	trust = g_hash_table_lookup(trust_list, GINT_TO_POINTER(sock));
	if (!trust) {
		hal_log_info("Permission denied!");
		*result = KNOT_CREDENTIAL_UNAUTHORIZED;
		return NULL;
	}

	trust->config_tmp = parse_device_config(json.data);

	/* config_is_valid() returns 0 if SUCCESS */
	if (config_is_valid(trust->config_tmp)) {
		hal_log_error("Invalid config message");
		g_slist_free_full(trust->config_tmp, config_free);
		trust->config_tmp = NULL;
		/*
		 * TODO: DEFINE KNOT_CONFIG ERRORS IN PROTOCOL
		 * KNOT_INVALID_CONFIG in new protocol
		 */
		*result = KNOT_NO_DATA;
		return NULL;
	}

	list = get_changed_config(trust->config, trust->config_tmp);
	g_slist_free_full(trust->config, config_free);
	trust->config = trust->config_tmp;
	trust->config_tmp = NULL;

	*result = KNOT_SUCCESS;

	return list;
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
	g_free(*uuid);
	g_free(*token);
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
	GSList **schema, GSList **config)
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
	trust = trust_get(node_socket);
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
	g_free(uuid);
	g_free(token);
done:
fail_create:
fail_length:
	return result;
}

static int8_t msg_auth(int node_socket, int proto_socket,
				const knot_msg_authentication *kmauth)
{
	int8_t result;
	GSList *schema, *config;
	char *uuid, *token;

	if (trust_get(node_socket)) {
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
		goto done;
	}

	if (config_is_valid(config)) {
		hal_log_error("Invalid config message");
		g_slist_free_full(config, config_free);
		config = NULL;
	}

	/*
	 * g_strndup returns a newly-allocated buffer n + 1 bytes
	 * long which will always be nul-terminated.
	 */
	uuid = g_strndup(kmauth->uuid, sizeof(kmauth->uuid));
	token = g_strndup(kmauth->token, sizeof(kmauth->token));
	/* TODO: should we receive the ID? Should we get the socket PID? */
	trust_create(node_socket, proto_socket, uuid, token, 0, 0, FALSE,
		schema, config);

	result = KNOT_SUCCESS;

done:
	return result;
}

static int8_t msg_schema(int sock, int proto_sock,
				const knot_msg_schema *kmsch, gboolean eof)
{
	const knot_msg_schema *schema = kmsch;
	knot_msg_schema *kschema;
	struct json_object *jobj, *ajobj, *schemajobj;
	struct trust *trust;
	GSList *list;
	json_raw_t json;
	const char *jobjstr;
	int err;
	gboolean found = FALSE;

	trust = g_hash_table_lookup(trust_list, GINT_TO_POINTER(sock));
	if (!trust) {
		hal_log_info("Permission denied!");
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	/*
	 * For security reason, remove from rollback avoiding clonning attack.
	 * If schema is being sent means that credentals (UUID/token) has been
	 * properly received (registration complete).
	 */
	trust->rollback = FALSE;

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
	kschema = g_memdup(schema, sizeof(*schema));
	for (list = trust->schema_tmp; list ; list = g_slist_next(list)) {
		schema = list->data;
		if (kschema->sensor_id == schema->sensor_id)
			found = TRUE;
	}
	if (!found)
		trust->schema_tmp = g_slist_append(trust->schema_tmp, kschema);

	 /* TODO: missing timer to wait for end of schema transfer */

	if (!eof)
		return KNOT_SUCCESS;

	/* SCHEMA is an array of entries */
	ajobj = json_object_new_array();
	schemajobj = json_object_new_object();

	/* Creating an array if the sensor supports multiple data types */
	for (list = trust->schema_tmp; list; list = g_slist_next(list)) {
		schema = list->data;
		jobj = json_object_new_object();
		json_object_object_add(jobj, "sensor_id",
				json_object_new_int(schema->sensor_id));
		json_object_object_add(jobj, "value_type",
				json_object_new_int(schema->values.value_type));
		json_object_object_add(jobj, "unit",
				json_object_new_int(schema->values.unit));
		json_object_object_add(jobj, "type_id",
				json_object_new_int(schema->values.type_id));
		json_object_object_add(jobj, "name",
				json_object_new_string(schema->values.name));

		json_object_array_add(ajobj, jobj);
	}

	json_object_object_add(schemajobj, "schema", ajobj);
	jobjstr = json_object_to_json_string(schemajobj);

	memset(&json, 0, sizeof(json));
	err = proto->schema(proto_sock, trust->uuid, trust->token,
							jobjstr, &json);
	if (json.data)
		free(json.data);

	json_object_put(schemajobj);

	if (err < 0) {
		g_slist_free_full(trust->schema_tmp, g_free);
		trust->schema_tmp = NULL;
		hal_log_error("manager schema(): %s(%d)", strerror(-err), -err);
		return KNOT_CLOUD_FAILURE;
	}

	/* If POST succeed: free old schema and use the new one */
	g_slist_free_full(trust->schema, g_free);
	trust->schema = trust->schema_tmp;
	trust->schema_tmp = NULL;

	return KNOT_SUCCESS;
}

/*
 * Updates de 'devices' db, removing the sensor_id that just sent the data
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
	 *		"set_data" : [
	 *			{"sensor_id": v,
	 *			"value": w}]
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

static int8_t msg_data(int sock, int proto_sock,
					const knot_msg_data *kmdata)
{
	/*
	 * Pointer to KNOT data containing header, sensor id
	 * and a primitive KNOT type
	 */
	const knot_data *kdata = &(kmdata->payload);
	struct json_object *jobj;
	const struct trust *trust;
	const knot_msg_schema *schema;
	GSList *list;
	json_raw_t json;
	const char *jobjstr;
	/* INT_MAX 2147483647 */
	char str[12];
	double doubleval;
	uint8_t sensor_id;
	int len, err;

	trust = g_hash_table_lookup(trust_list, GINT_TO_POINTER(sock));
	if (!trust) {
		hal_log_info("Permission denied!");
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	sensor_id = kmdata->sensor_id;

	list = g_slist_find_custom(trust->schema, GUINT_TO_POINTER(sensor_id),
								sensor_id_cmp);
	if (!list) {
		hal_log_info("sensor_id(0x%02x): data type mismatch!",
								sensor_id);
		return KNOT_INVALID_DATA;
	}

	schema = list->data;

	err = knot_schema_is_valid(schema->values.type_id,
				schema->values.value_type, schema->values.unit);
	if (err) {
		hal_log_info("sensor_id(0x%d), type_id(0x%04x): unit mismatch!",
					sensor_id, schema->values.type_id);
		return KNOT_INVALID_DATA;
	}

	hal_log_info("sensor:%d, unit:%d, value_type:%d", sensor_id,
				schema->values.unit, schema->values.value_type);

	jobj = json_object_new_object();
	json_object_object_add(jobj, "sensor_id",
						json_object_new_int(sensor_id));

	switch (schema->values.value_type) {
	case KNOT_VALUE_TYPE_INT:
		json_object_object_add(jobj, "value",
				json_object_new_int(kdata->values.val_i.value));
		break;
	case KNOT_VALUE_TYPE_FLOAT:

		/* FIXME: precision */
		len = sprintf(str, "%d", kdata->values.val_f.value_dec);

		doubleval = kdata->values.val_f.multiplier *
			(kdata->values.val_f.value_int +
			(kdata->values.val_f.value_dec / pow(10, len)));

		json_object_object_add(jobj, "value",
					json_object_new_double(doubleval));
		break;
	case KNOT_VALUE_TYPE_BOOL:
		json_object_object_add(jobj, "value",
				json_object_new_boolean(kdata->values.val_b));
		break;
	case KNOT_VALUE_TYPE_RAW:
		break;
	default:
		json_object_put(jobj);
		return KNOT_INVALID_DATA;
	}

	jobjstr = json_object_to_json_string(jobj);

	hal_log_info("JSON: %s", jobjstr);

	memset(&json, 0, sizeof(json));
	err = proto->data(proto_sock, trust->uuid, trust->token,
							jobjstr, &json);
	if (json.data)
		free(json.data);

	json_object_put(jobj);

	if (err < 0) {
		hal_log_error("manager data(): %s(%d)", strerror(-err), -err);
		return KNOT_CLOUD_FAILURE;
	}

	update_device_getdata(proto_sock, trust->uuid, trust->token, sensor_id);

	return KNOT_SUCCESS;
}

static int8_t msg_config_resp(int sock, const knot_msg_item *rsp)
{
	struct trust *trust;
	uint8_t sensor_id;
	GSList *list;
	struct config *entry;

	trust = g_hash_table_lookup(trust_list, GINT_TO_POINTER(sock));
	if (!trust) {
		hal_log_info("Permission denied!");
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}
	sensor_id = rsp->sensor_id;
	for (list = trust->config; list; list = g_slist_next(list)) {
		entry = list->data;
		if (entry->kmcfg.sensor_id == sensor_id) {
			entry->confirmed = TRUE;
			break;
		}
	}
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
static int8_t msg_setdata_resp(int sock, int proto_sock,
					const knot_msg_data *kmdata)
{
	/*
	 * Pointer to KNOT data containing header, sensor id
	 * and a primitive KNOT type
	 */
	const knot_data *kdata = &(kmdata->payload);
	struct json_object *jobj;
	const struct trust *trust;
	const knot_msg_schema *schema;
	GSList *list;
	json_raw_t json;
	const char *jobjstr;
	/* INT_MAX 2147483647 */
	char str[12];
	double doubleval;
	uint8_t sensor_id;
	int len, err;

	trust = g_hash_table_lookup(trust_list, GINT_TO_POINTER(sock));
	if (!trust) {
		hal_log_info("Permission denied!");
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	sensor_id = kmdata->sensor_id;

	list = g_slist_find_custom(trust->schema, GUINT_TO_POINTER(sensor_id),
								sensor_id_cmp);
	if (!list) {
		hal_log_info("sensor_id(0x%02x): data type mismatch!",
								sensor_id);
		return KNOT_INVALID_DATA;
	}

	schema = list->data;

	err = knot_schema_is_valid(schema->values.type_id,
				schema->values.value_type, schema->values.unit);
	if (err) {
		hal_log_info("sensor_id(0x%d), type_id(0x%04x): unit mismatch!",
					sensor_id, schema->values.type_id);
		return KNOT_INVALID_DATA;
	}

	hal_log_info("sensor:%d, unit:%d, value_type:%d", sensor_id,
				schema->values.unit, schema->values.value_type);

	/* Fetches the 'devices' db */
	update_device_setdata(proto_sock, trust->uuid, trust->token,
								sensor_id);

	jobj = json_object_new_object();
	json_object_object_add(jobj, "sensor_id",
						json_object_new_int(sensor_id));

	switch (schema->values.value_type) {
	case KNOT_VALUE_TYPE_INT:
		json_object_object_add(jobj, "value",
				json_object_new_int(kdata->values.val_i.value));
		break;
	case KNOT_VALUE_TYPE_FLOAT:

		/* FIXME: precision */
		len = sprintf(str, "%d", kdata->values.val_f.value_dec);

		doubleval = kdata->values.val_f.multiplier *
			(kdata->values.val_f.value_int +
			(kdata->values.val_f.value_dec / pow(10, len)));

		json_object_object_add(jobj, "value",
					json_object_new_double(doubleval));
		break;
	case KNOT_VALUE_TYPE_BOOL:
		json_object_object_add(jobj, "value",
				json_object_new_boolean(kdata->values.val_b));
		break;
	case KNOT_VALUE_TYPE_RAW:
		break;
	default:
		json_object_put(jobj);
		return KNOT_INVALID_DATA;
	}

	jobjstr = json_object_to_json_string(jobj);

	memset(&json, 0, sizeof(json));
	err = proto->data(proto_sock, trust->uuid, trust->token,
							jobjstr, &json);
	if (json.data)
		free(json.data);

	json_object_put(jobj);

	if (err < 0) {
		hal_log_error("manager data(): %s(%d)", strerror(-err), -err);
		return KNOT_CLOUD_FAILURE;
	}

	hal_log_info("THING %s updated data for sensor %d", trust->uuid,
								sensor_id);

	return KNOT_SUCCESS;
}


ssize_t msg_process(int sock, int proto_sock,
				const void *ipdu, size_t ilen,
				void *opdu, size_t omtu)
{
	const knot_msg *kreq = ipdu;
	knot_msg *krsp = opdu;
	uint8_t rtype;
	int8_t result = KNOT_INVALID_DATA;
	gboolean eof;

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
		eof = kreq->hdr.type == KNOT_MSG_SCHEMA_END ? TRUE : FALSE;
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

	trust_list = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, (GDestroyNotify) trust_unref);
	return 0;
}

void msg_stop(void)
{
	g_hash_table_destroy(trust_list);
}
