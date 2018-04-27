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
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <unistd.h>

#include <ell/ell.h>

#include <json-c/json.h>
#include <knot_types.h>
#include <knot_protocol.h>
#include <hal/linux_log.h>

#include "settings.h"
#include "proto.h"

extern struct proto_ops proto_http;
#ifdef HAVE_WEBSOCKETS
extern struct proto_ops proto_ws;
extern struct proto_ops proto_socketio;
#endif

static struct proto_ops *proto_ops[] = {
	&proto_http,
#ifdef HAVE_WEBSOCKETS
	&proto_ws,
	&proto_socketio,
#endif
	NULL
};

struct proto_proxy {
	int sock;			/* Cloud connection */
	proto_proxy_func_t added_cb;
	proto_proxy_func_t removed_cb;
	proto_proxy_ready_func_t ready_cb; /* Call only once */
	bool ready_once;
	void *user_data;
	struct l_queue *device_list;
};

static struct proto_ops *proto = NULL; /* Selected protocol */
static char owner_uuid[KNOT_PROTOCOL_UUID_LEN + 1];
static struct l_timeout *timeout;
static struct proto_proxy *proxy;

static void proxy_destroy(void *user_data)
{
	struct proto_proxy *proxy = user_data;
	l_queue_destroy(proxy->device_list, l_free);
	l_free(proxy);
}

static inline bool is_uuid_valid(const char *uuid)
{
	return strlen(uuid) == KNOT_PROTOCOL_UUID_LEN;
}

static inline bool is_token_valid(const char *token)
{
	return strlen(token) == KNOT_PROTOCOL_TOKEN_LEN;
}

static struct l_queue *parse_mydevices(const char *json_str)
{
	json_object *jobj, *jobjentry, *jobjkey;
	struct l_queue *list;
	int64_t id;
	int len;
	int i;

	jobj = json_tokener_parse(json_str);
	if (!jobj) {
		hal_log_error("JSON: unexpected format");
		return NULL;
	}

	len = json_object_array_length(jobj);
	if (len == 0) {
		json_object_put(jobj);
		return NULL;
	}

	list = l_queue_new();
	for (i = 0; i < len; i++) {
		jobjentry = json_object_array_get_idx(jobj, i);
		/* Getting 'Id' */
		if (!json_object_object_get_ex(jobjentry, "id", &jobjkey))
			continue;

		/*
		 * Following API recommendation ...
		 * Set errno to 0 directly before a call to this function to
		 * determine whether or not conversion was successful.
		 */
		errno = 0;
		id = json_object_get_int64(jobjkey);
		if (errno)
			continue;

		l_queue_push_tail(list, l_memdup(&id, sizeof(id)));
	}

	json_object_put(jobj);
	return list;
}

static bool device_id_cmp(const void *a, const void *b)
{
	const uint64_t *val1 = a;
	const uint64_t *val2 = b;

	return (*val1 == *val2 ? true : false);
}

static void timeout_callback(struct l_timeout *timeout, void *user_data)
{
	struct proto_proxy *proxy = user_data;
	struct l_queue *list;
	struct l_queue *added_list;
	struct l_queue *removed_list;
	struct l_queue *registered_list;
	json_raw_t json;
	uint64_t *valx;
	uint64_t *valy;
	int err;

	/* Fetch all devices from cloud */
	memset(&json, 0, sizeof(json));
	err = proto->fetch(proxy->sock, NULL, NULL, &json);
	if (err < 0)
		hal_log_error("fetch(): %s(%d)", strerror(-err), -err);

	if (json.size == 0)
		goto done;

	/* List containing all devices returned from cloud */
	list = parse_mydevices(json.data);

	added_list = l_queue_new();
	registered_list = l_queue_new();

	/* Detecting added & removed devices */
	for (valx = l_queue_pop_head(list);
	     valx; valx = l_queue_pop_head(list)) {
		valy = l_queue_remove_if(proxy->device_list,
					 device_id_cmp, valx);

		if (valy == NULL) {
			/* New device */
			l_queue_push_tail(registered_list, valx);
			l_queue_push_tail(added_list,
					  l_memdup(valx, sizeof(*valx)));
		} else { /* Still registered */
			l_queue_push_tail(registered_list, valy);
			l_free(valx);
		}
	}

	/* list is empty: destroy */
	l_queue_destroy(list, NULL);

	/* Left in list: removed */
	removed_list = proxy->device_list;

	/* Informing added devices */
	for (valx = l_queue_pop_head(added_list);
	     valx; valx = l_queue_pop_head(added_list)) {
		proxy->added_cb(*valx, proxy->user_data);
	}

	l_queue_destroy(added_list, l_free);
	/* Overwrite: Keep a copy for the next iteration */
	proxy->device_list = registered_list;

	/* Informing removed devices */
	for (valx = l_queue_pop_head(removed_list);
	     valx; valx = l_queue_pop_head(removed_list)) {
		proxy->removed_cb(*valx, proxy->user_data);
		l_free(valx);
	}
	l_queue_destroy(removed_list, l_free);

	if (proxy->ready_cb && !proxy->ready_once) {
		proxy->ready_cb(proxy->user_data);
		proxy->ready_once = true;
	}

done:
	l_timeout_modify(timeout, 5);
	l_free(json.data);
}

static json_object *device_json_create(const char *device_name,
					 uint64_t device_id)
{
	json_object *device;

	device = json_object_new_object();
	if (!device)
		return NULL;

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

static int device_parse_info(const char *json_str, char *uuid, char *token)
{
	json_object *jobj, *json_uuid, *json_token;
	const char *str;
	int err = -EINVAL;

	jobj = json_tokener_parse(json_str);
	if (jobj == NULL)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj, "uuid", &json_uuid))
		goto done;

	if (!json_object_object_get_ex(jobj, "token", &json_token))
		goto done;

	str = json_object_get_string(json_uuid);
	strncpy(uuid, str, KNOT_PROTOCOL_UUID_LEN);
	str = json_object_get_string(json_token);
	strncpy(token, str, KNOT_PROTOCOL_TOKEN_LEN);

	err = 0; /* Success */
done:
	json_object_put(jobj);

	return err;
}

/*
 * Parsing knot_value_types attribute
 */
static void parse_json_value_types(json_object *jobj, knot_value_types *limit)
{
	json_object *jobjkey;
	const char *str;
	int32_t ipart, fpart;

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

static struct l_queue *device_parse_schema(const char *json_str)
{
	json_object *jobj, *jobjarray, *jobjentry, *jobjkey;
	struct l_queue *list;
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
	 * as in device_parse_config() and parse_device_setdata()?
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
static struct l_queue *device_parse_config(const char *json_str)
{
	json_object *jobj, *jobjarray, *jobjentry, *jobjkey;
	struct l_queue *list;
	knot_msg_config *config;
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
		if (json_object_object_get_ex(jobjentry,
					      "upper_limit", &jobjkey)) {
			jtype = json_object_get_type(jobjkey);
			if (jtype != json_type_int &&
					jtype != json_type_double &&
					jtype != json_type_boolean)
				goto done;

			parse_json_value_types(jobjkey, &upper_limit);
		}

		config = l_new(knot_msg_config, 1);
		config->sensor_id = sensor_id;
		config->values.event_flags = event_flags;
		config->values.time_sec = time_sec;
		memcpy(&(config->values.lower_limit), &lower_limit,
						sizeof(knot_value_types));
		memcpy(&(config->values.upper_limit), &upper_limit,
						sizeof(knot_value_types));
		l_queue_push_tail(list, config);
	}

	json_object_put(jobj);

	return list;

done:
	l_queue_destroy(list, l_free);
	json_object_put(jobj);

	return NULL;
}

static json_object *schema_create_object(uint8_t sensor_id, uint8_t value_type,
					 uint8_t unit, uint16_t type_id,
					 const char *name)
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

static void schema_create_and_append(knot_msg_schema *schema,
			      json_object *schema_list)
{
	json_object *item = schema_create_object(schema->sensor_id,
						 schema->values.value_type,
						 schema->values.unit,
						 schema->values.type_id,
						 schema->values.name);
	json_object_array_add(schema_list, item);
}

static json_object *schema_create_list(struct l_queue *schema_list)
{
	json_object *jschema, *jschema_list;

	jschema = json_object_new_object();
	jschema_list = json_object_new_array();
	l_queue_foreach(schema_list,
			(l_queue_foreach_func_t) schema_create_and_append,
			jschema_list);
	json_object_object_add(jschema, "schema", jschema_list);

	return jschema;
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

static json_object *data_create_object(uint8_t sensor_id,
				       uint8_t value_type,
				       const knot_data *value)
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
 * Updates the 'devices' db, removing the sensor_id that just sent the data
 */
void proto_getdata(int proto_sock, char *uuid, char *token, uint8_t sensor_id)
{
	json_object *jobj = NULL, *jobjarray = NULL;
	json_object *jobjentry = NULL, *jobjkey = NULL;
	json_object *ajobj = NULL, *setdatajobj = NULL;
	json_raw_t json;
	const char *jobjstr;
	int i, err;

	memset(&json, 0, sizeof(json));
	err = proto->fetch(proto_sock, uuid, token, &json);
	if (err < 0) {
		hal_log_error("fetch(): %s(%d)", strerror(-err), -err);
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
	l_free(json.data);
}

/*
 * Updates de 'devices' db, removing the sensor_id that was acknowledged by the
 * THING.
 */
void proto_setdata(int proto_sock, char *uuid, char *token, uint8_t sensor_id)
{
	json_object *jobj = NULL, *jobjarray = NULL;
        json_object *jobjentry = NULL, *jobjkey = NULL;
        json_object *ajobj = NULL, *setdatajobj = NULL;
	const char *jobjstr;
	json_raw_t json;
	int i, err;

	memset(&json, 0, sizeof(json));
	err = proto->fetch(proto_sock, uuid, token, &json);

	if (err < 0) {
		hal_log_error("fetch(): %s(%d)", strerror(-err), -err);
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
	l_free(json.data);
}

static struct proto_ops *get_proto_ops(const char *protocol_name)
{
	int i;
	struct proto_ops *selected_protocol = NULL;

	for (i = 0; proto_ops[i]; i++) {
		if (strcmp(protocol_name, proto_ops[i]->name) != 0)
			continue;

		selected_protocol = proto_ops[i];
	}

	return selected_protocol;
}

int proto_start(const struct settings *settings)
{
	/*
	 * Selecting meshblu IoT protocols & services: HTTP/REST,
	 * Websockets, Socket IO, MQTT, COAP. 'proto_ops' drivers
	 * implements an abstraction similar to WEB client operations.
	 * TODO: later support dynamic protocol selection.
	 */

	proto = get_proto_ops(settings->proto);
	if (proto == NULL)
		return -EINVAL;

	hal_log_info("proto_ops: %s", proto->name);

	memset(owner_uuid, 0, sizeof(owner_uuid));
	strncpy(owner_uuid, settings->uuid, sizeof(owner_uuid));

	return proto->probe(settings->host, settings->port);
}

void proto_stop()
{
	if (proto != NULL) {
		proto->remove();
		proto = NULL;
	}

	l_timeout_remove(timeout);
}

int proto_connect(void)
{
	if (unlikely(!proto))
		return -EIO;

	return proto->connect();
}

void proto_close(int prot_sock)
{
	if (unlikely(!proto))
		return;

	proto->close(prot_sock);
}

int proto_mknode(int proto_socket, const char *device_name,
			uint64_t device_id, char *uuid, char *token)
{
	json_object *device;
	const char *device_as_string;
	json_raw_t response;
	int err, result;

	memset(&response, 0, sizeof(response));
	device = device_json_create(device_name, device_id);
	if (!device) {
		hal_log_error("JSON: no memory");
		result = KNOT_ERROR_UNKNOWN;
		goto fail;
	}

	device_as_string = json_object_to_json_string(device);
	err = proto->mknode(proto_socket, device_as_string, &response);
	json_object_put(device);

	if (err < 0) {
		hal_log_error("manager mknode: %s(%d)", strerror(-err), -err);
		result = KNOT_CLOUD_FAILURE;
		goto fail;
	}

	if (response.size == 0 ||
	    (device_parse_info(response.data, uuid, token) < 0)) {
		hal_log_error("Unexpected response!");
		result = KNOT_CLOUD_FAILURE;
		goto fail;
	}

	/* Parse function never returns NULL for 'uuid' or 'token' fields */
	if (!is_uuid_valid(uuid) || !is_token_valid(token)) {
		hal_log_error("Invalid UUID or token!");
		result = KNOT_CLOUD_FAILURE;
		goto fail;
	}

	result = KNOT_SUCCESS;
fail:
	l_free(response.data);
	return result;
}

int proto_signin(int proto_socket, const char *uuid, const char *token,
			struct l_queue **schema, struct l_queue **config)
{
	json_raw_t response;
	int err, result;

	memset(&response, 0, sizeof(response));
	err = proto->signin(proto_socket, uuid, token, &response);

	if (!response.data) {
		result = KNOT_CLOUD_FAILURE;
		goto fail;
	}

	if (err < 0) {
		hal_log_error("manager signin(): %s(%d)", strerror(-err), -err);
		result = KNOT_CREDENTIAL_UNAUTHORIZED;
		goto fail;
	}

	if (schema != NULL)
		*schema = device_parse_schema(response.data);

	if (config != NULL)
		*config = device_parse_config(response.data);

	result = KNOT_SUCCESS;

fail:
	l_free(response.data);
	return result;
}

int proto_schema(int proto_socket, const char *uuid,
		 const char *token, struct l_queue *schema_list)
{
	json_object *jschema_list;
	const char *jschema_list_as_string;
	json_raw_t response;
	int result, err;

	jschema_list = schema_create_list(schema_list);
	jschema_list_as_string = json_object_to_json_string(jschema_list);

	memset(&response, 0, sizeof(response));
	err = proto->schema(proto_socket, uuid, token,
			    jschema_list_as_string, &response);

	if (response.data)
		l_free(response.data);

	json_object_put(jschema_list);

	if (err < 0) {
		hal_log_error("manager schema(): %s(%d)", strerror(-err), -err);
		result = KNOT_CLOUD_FAILURE;
	} else
		result = KNOT_SUCCESS;

	return result;
}

int proto_data(int proto_socket, const char *uuid,
		      const char *token, uint8_t sensor_id,
		      uint8_t value_type, const knot_data *value)
{
	struct json_object *data;
	const char *data_as_string;
	json_raw_t response;
	int result, err;

	data = data_create_object(sensor_id, value_type, value);
	if (!data) {
		result = KNOT_INVALID_DATA;
		goto done;
	}

	data_as_string = json_object_to_json_string(data);

	memset(&response, 0, sizeof(response));
	err = proto->data(proto_socket, uuid, token, data_as_string, &response);

	if (response.data)
		l_free(response.data);

	json_object_put(data);

	if (err < 0) {
		hal_log_error("manager data(): %s(%d)", strerror(-err), -err);
		result = KNOT_CLOUD_FAILURE;
	} else
		result = KNOT_SUCCESS;

done:
	return result;
}

int proto_rmnode(int proto_socket, const char *uuid, const char *token)
{
	json_raw_t response = { NULL, 0 };
	int result, err;

	err = proto->rmnode(proto_socket, uuid, token, &response);
	if (err < 0) {
		result = KNOT_CLOUD_FAILURE;
		hal_log_error("rmnode() failed %s (%d)", strerror(-err), -err);
		goto done;
	}

	result = KNOT_SUCCESS;

done:
	if (response.data)
		l_free(response.data);
	return result;
}

int proto_set_proxy_handlers(int sock,
			     proto_proxy_func_t added,
			     proto_proxy_func_t removed,
			     proto_proxy_ready_func_t ready,
			     void *user_data)
{
	proxy = l_new(struct proto_proxy, 1);
	proxy->sock = sock;
	proxy->added_cb = added;
	proxy->removed_cb = removed;
	proxy->ready_cb = ready;
	proxy->ready_once = false;
	proxy->user_data = user_data;
	proxy->device_list = l_queue_new();

	/* TODO: Currently restricted to one 'watcher' */
	timeout = l_timeout_create_ms(1, timeout_callback,
				      proxy, proxy_destroy);

	return 0;
}

int proto_rmnode_by_uuid(const char *uuid)
{
	return proto_rmnode(proxy->sock, uuid, NULL);
}
