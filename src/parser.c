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

#include <errno.h>
#include <stdio.h>

#include <ell/ell.h>
#include <hal/linux_log.h>

#include <knot/knot_types.h>
#include <knot/knot_protocol.h>

#include <json-c/json.h>

#include "parser.h"

#define MIN(x,y) ((x)<(y)?(x):(y))

/*
 * Parsing knot_value_type attribute
 */
static int parse_json2data(json_object *jobj, knot_value_type *kvalue)
{
	json_object *jobjkey;
	const char *str;
	uint8_t *u8val;
	size_t olen = 0;

	jobjkey = jobj;
	switch (json_object_get_type(jobjkey)) {
	case json_type_boolean:
		kvalue->val_b = json_object_get_boolean(jobjkey);
		olen = sizeof(kvalue->val_b);
		break;
	case json_type_double:
		/* FIXME: how to handle overflow? */
		kvalue->val_f = (float) json_object_get_double(jobjkey);
		olen = sizeof(kvalue->val_f);
		break;
	case json_type_int:

		kvalue->val_i = json_object_get_int(jobjkey);
		olen = sizeof(kvalue->val_i);
		break;
	case json_type_string:
		str = json_object_get_string(jobjkey);
		u8val = l_base64_decode(str, strlen(str), &olen);
		if (!u8val)
			break;

		if (olen > KNOT_DATA_RAW_SIZE)
			olen = KNOT_DATA_RAW_SIZE; /* truncate */

		memcpy(kvalue->raw, u8val, olen);
		l_free(u8val);
		break;
	/* FIXME: not implemented */
	case json_type_null:
	case json_type_object:
	case json_type_array:
	default:
		break;
	}

	return olen;
}

struct l_queue *parser_schema_to_list(const char *json_str)
{
	json_object *jobjarray, *jobjentry, *jobjkey;
	struct l_queue *list;
	knot_msg_schema *entry;
	int sensor_id, value_type, unit, type_id;
	uint64_t i;
	const char *name;

	jobjarray = json_tokener_parse(json_str);
	if (!jobjarray)
		return NULL;

	if (json_object_get_type(jobjarray) != json_type_array) {
		json_object_put(jobjarray);
		return NULL;
	}

	list = l_queue_new();
	/* Expected JSON object is in the following format:
	 *
	 * [ {"sensor_id": x, "value_type": w,
	 *		"unit": z "type_id": y, "name": "foo"}]
	 * }
	 */

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
	json_object_put(jobjarray);

	if (l_queue_isempty(list)) {
		l_queue_destroy(list, NULL);
		list = NULL;
	}

	return list;
}

struct l_queue *parser_queue_from_json_array(json_object *jobj,
					parser_json_array_item_cb foreach_cb)
{
	json_object *jobjentry, *jarray;
	struct l_queue *list;
	void *item;
	int len;
	int i;

	jarray = json_object_object_get(jobj, "devices");
	if (!jarray)
		return NULL;

	if (json_object_get_type(jarray) != json_type_array)
		return NULL;

	len = json_object_array_length(jarray);
	list = l_queue_new();

	for (i = 0; i < len; i++) {
		jobjentry = json_object_array_get_idx(jarray, i);

		item = foreach_cb(jobjentry);
		if (item)
			l_queue_push_tail(list, item);
	}

	return list;
}

struct l_queue *parser_request_to_list(json_object *jso)
{
	struct l_queue *list;
	json_object *json_array;
	json_object *jobjentry;
	int sensor_id;
	uint64_t i;

	list = l_queue_new();

	if (!json_object_object_get_ex(jso, "data", &json_array))
		goto fail;

	for (i = 0; i < json_object_array_length(json_array); i++) {

		jobjentry = json_object_array_get_idx(json_array, i);
		if (!jobjentry)
			goto fail;

		if (json_object_get_type(jobjentry) != json_type_int)
			goto fail;

		sensor_id = json_object_get_int(jobjentry);

		if (!l_queue_push_tail(list,
				l_memdup(&sensor_id, sizeof(sensor_id))))
			goto fail;
	}

	return list;

fail:
	l_queue_destroy(list, l_free);
	return NULL;
}

json_object *parser_sensorid_to_json(const char *key, struct l_queue *list)
{
	int *id;
	json_object *ajobj;
	json_object *entry;
	json_object *setdatajobj;

	ajobj = json_object_new_array();

	for (id = l_queue_pop_head(list); id;
	     id = l_queue_pop_head(list)) {
			entry = json_object_new_object();
			json_object_object_add(entry, "sensor_id",
					       json_object_new_int(*id));
			json_object_array_add(ajobj, json_object_get(entry));
	}

	setdatajobj = json_object_new_object();
	json_object_object_add(setdatajobj, key, ajobj);

	return setdatajobj;
}

struct l_queue *parser_update_to_list(json_object *jso)
{
	json_object *json_array;
	json_object *json_data;
	json_object *jobjkey;
	knot_msg_data *msg;
	struct l_queue *list;
	uint64_t i;
	int jtype;
	int olen;
	uint8_t sensor_id;

	list = l_queue_new();

	if (!json_object_object_get_ex(jso, "data", &json_array))
		goto fail;

	for (i = 0; i < json_object_array_length(json_array); i++) {

		json_data = json_object_array_get_idx(json_array, i);
		if (!json_data)
			goto fail;

		/* Getting 'sensor_id' */
		if (!json_object_object_get_ex(json_data,
							"sensor_id", &jobjkey))
			goto fail;

		if (json_object_get_type(jobjkey) != json_type_int)
			goto fail;

		sensor_id = json_object_get_int(jobjkey);

		/* Getting 'value' */
		if (!json_object_object_get_ex(json_data, "value", &jobjkey))
			goto fail;

		jtype = json_object_get_type(jobjkey);
		if (jtype != json_type_int &&
		jtype != json_type_double && jtype != json_type_boolean &&
			jtype != json_type_string)
			goto fail;

		msg = l_new(knot_msg_data, 1);

		olen = parse_json2data(jobjkey, &msg->payload);
		if (olen <= 0) {
			l_free(msg);
			goto fail;
		}

		msg->sensor_id = sensor_id;
		msg->hdr.type = KNOT_MSG_PUSH_DATA_REQ;
		msg->hdr.payload_len = olen + sizeof(msg->sensor_id);

		if (!l_queue_push_tail(list, msg)) {
			l_free(msg);
			goto fail;
		}
	}

	return list;

fail:
	l_queue_destroy(list, l_free);
	return NULL;
}

/*
 * TODO: consider moving this to knot-protocol
 */
static int knot_value_as_int(const knot_value_type *data)
{
	return data->val_i;
}

/*
 * TODO: consider moving this to knot-protocol
 */
static double knot_value_as_double(const knot_value_type *data)
{
	return (double) data->val_f;
}

/*
 * TODO: consider moving this to knot-protocol
 */
static bool knot_value_as_boolean(const knot_value_type *data)
{
	return data->val_b;
}

static char *knot_value_as_raw(const knot_value_type *data,
			       uint8_t kval_len, size_t *encoded_len)
{
	char *encoded;
	size_t olen;

	encoded = l_base64_encode(data->raw, kval_len, 0, &olen);
	if (!encoded)
		return NULL;

	*encoded_len = olen;

	return encoded;
}

json_object *parser_data_create_object(const char *device_id, uint8_t sensor_id,
				       uint8_t value_type,
				       const knot_value_type *value,
				       uint8_t kval_len)
{
	json_object *json_msg;
	json_object *data;
	json_object *json_array;
	char *encoded;
	size_t encoded_len;

	json_msg = json_object_new_object();
	json_array = json_object_new_array();

	json_object_object_add(json_msg, "id",
			       json_object_new_string(device_id));
	data = json_object_new_object();
	json_object_object_add(data, "sensor_id",
			       json_object_new_int(sensor_id));

	switch (value_type) {
	case KNOT_VALUE_TYPE_INT:
		json_object_object_add(data, "value",
				json_object_new_int(knot_value_as_int(value)));
		break;
	case KNOT_VALUE_TYPE_FLOAT:
		json_object_object_add(data, "value",
			json_object_new_double(knot_value_as_double(value)));
		break;
	case KNOT_VALUE_TYPE_BOOL:
		json_object_object_add(data, "value",
			json_object_new_boolean(knot_value_as_boolean(value)));
		break;
	case KNOT_VALUE_TYPE_RAW:
		/* Encode as base64 */
		encoded = knot_value_as_raw(value, kval_len, &encoded_len);
		if (!encoded)
			goto fail;

		json_object_object_add(data, "value",
			json_object_new_string_len(encoded, encoded_len));
		break;
	default:
		goto fail;
	}

	json_object_array_add(json_array, data);
	json_object_object_add(json_msg, "data", json_array);

	/*
	 * Returned JSON object is in the following format:
	 *
	 * { "id": "fbe64efa6c7f717e",
	 *   "data": [{
	 *     "sensor_id": 1,
	 *     "value": false,
	 *   }]
	 * }
	 */

	return json_msg;
fail:
	json_object_put(data);
	json_object_put(json_array);
	json_object_put(json_msg);
	return NULL;
}

json_object *parser_device_json_create(const char *device_id,
				       const char *device_name)
{
	json_object *device;

	device = json_object_new_object();
	if (!device)
		return NULL;

	json_object_object_add(device, "name",
			       json_object_new_string(device_name));
	json_object_object_add(device, "id",
			       json_object_new_string(device_id));

	/*
	 * Returned JSON object is in the following format:
	 *
	 * { "id": "fbe64efa6c7f717e",
	 *   "name": "KNoT Thing"
	 * }
	 */
	return device;
}

json_object *parser_auth_json_create(const char *device_id,
				     const char *device_token)
{
	json_object *auth;

	auth = json_object_new_object();
	if (!auth)
		return NULL;

	json_object_object_add(auth, "id",
			       json_object_new_string(device_id));
	json_object_object_add(auth, "token",
			       json_object_new_string(device_token));

	/*
	 * Returned JSON object is in the following format:
	 *
	 * { "id": "fbe64efa6c7f717e",
	 *   "token": "0c20c12e2ac058d0513d81dc58e33b2f9ff8c83d"
	 * }
	 */
	return auth;
}

json_object *parser_unregister_json_create(const char *device_id)
{
	json_object *unreg;

	unreg = json_object_new_object();
	if (!unreg)
		return NULL;

	json_object_object_add(unreg, "id",
			       json_object_new_string(device_id));

	/*
	 * Returned JSON object is in the following format:
	 *
	 * { "id": "fbe64efa6c7f717e" }
	 */
	return unreg;
}

static json_object *schema_item_create_obj(knot_msg_schema *schema)
{
	json_object *json_schema;

	json_schema = json_object_new_object();

	json_object_object_add(json_schema, "sensor_id",
				       json_object_new_int(schema->sensor_id));
	json_object_object_add(json_schema, "value_type",
				json_object_new_int(
					schema->values.value_type));
	json_object_object_add(json_schema, "unit",
				json_object_new_int(
					schema->values.unit));
	json_object_object_add(json_schema, "type_id",
				json_object_new_int(
					schema->values.type_id));
	json_object_object_add(json_schema, "name",
				json_object_new_string(
					schema->values.name));

	/*
	 * Returned JSON object is in the following format:
	 *
	 * {
	 *   "sensor_id": 1,
	 *   "value_type": 0xFFF1,
	 *   "unit": 0,
	 *   "type_id": 3,
	 *   "name": "Door lock"
	 * }
	 */

	return json_schema;
}

static void schema_item_create_and_append(void *data, void *user_data)
{
	knot_msg_schema *schema = data;
	json_object *schema_list = user_data;
	json_object *item;

	item = schema_item_create_obj(schema);
	json_object_array_add(schema_list, item);
}

json_object *parser_schema_create_object(const char *device_id,
					 struct l_queue *schema_list)
{
	json_object *json_msg;
	json_object *json_schema_array;

	json_msg = json_object_new_object();
	json_schema_array = json_object_new_array();

	json_object_object_add(json_msg, "id",
			       json_object_new_string(device_id));

	l_queue_foreach(schema_list, schema_item_create_and_append,
			json_schema_array);

	json_object_object_add(json_msg, "schema", json_schema_array);

	/*
	 * Returned JSON object is in the following format:
	 *
	 * { "id": "fbe64efa6c7f717e",
	 *   "schema" : [{
	 *         "sensor_id": 1,
	 *         "value_type": 0xFFF1,
	 *         "unit": 0,
	 *         "type_id": 3,
	 *         "name": "Door lock"
	 *   }]
	 * }
	 */

	return json_msg;
}

const char *parser_get_key_str_from_json_obj(json_object *jso, const char *key)
{
	json_object *jobjkey;

	if (!json_object_object_get_ex(jso, key, &jobjkey))
		return NULL;

	if (json_object_get_type(jobjkey) != json_type_string)
		return NULL;

	return json_object_get_string(jobjkey);
}

bool parser_is_key_str_or_null(const json_object *jso, const char *key)
{
	json_object *jobjkey;
	enum json_type type;

	if (!json_object_object_get_ex(jso, key, &jobjkey))
		return false;

	type = json_object_get_type(jobjkey);

	return type == json_type_string || type == json_type_null;
}
