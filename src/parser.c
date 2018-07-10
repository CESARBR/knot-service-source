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

#include <knot_types.h>
#include <knot_protocol.h>

#include <json-c/json.h>

#include "parser.h"

int parser_device(const char *json_str, char *uuid, char *token)
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
	/* FIXME: not implemented */
	case json_type_string:
	case json_type_null:
	case json_type_object:
	case json_type_array:
	default:
		break;
	}
}

struct l_queue *parser_schema_to_list(const char *json_str)
{
	json_object *jobjarray, *jobjentry, *jobjkey;
	struct l_queue *list;
	knot_msg_schema *entry;
	int sensor_id, value_type, unit, type_id, i;
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

/*
 * Parses the json from the cloud with the config. The message is discarded if:
 * There are no "devices" or "config" fields in the JSON or they are not arrays.
 * The mandatory fields "sensor_id" and "event_flags" are missing.
 * Any field that is sent has the wrong type.
 */
struct l_queue *parser_config_to_list(const char *json_str)
{
	json_object *jobjarray, *jobjentry, *jobjkey;
	struct l_queue *list;
	knot_msg_config *config;
	int sensor_id, event_flags, time_sec, i;
	knot_value_types lower_limit, upper_limit;
	json_type jtype;

	jobjarray = json_tokener_parse(json_str);
	if (!jobjarray)
		return NULL;

	if (json_object_get_type(jobjarray) != json_type_array) {
		json_object_put(jobjarray);
		return NULL;
	}

	list = l_queue_new();

	/* Getting 'config' from the device properties:
	 *
	 * [ {"sensor_id": v, "event_flags": w,
	 *				"time_sec": x "lower_limit": y,
	 * } ]
	 */

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
		config->hdr.type = KNOT_MSG_SET_CONFIG;
		config->hdr.payload_len = sizeof(config->values) + 1;
		config->sensor_id = sensor_id;
		config->values.event_flags = event_flags;
		config->values.time_sec = time_sec;
		memcpy(&(config->values.lower_limit), &lower_limit,
						sizeof(knot_value_types));
		memcpy(&(config->values.upper_limit), &upper_limit,
						sizeof(knot_value_types));
		l_queue_push_tail(list, config);
	}

	json_object_put(jobjarray);

	return list;

done:
	l_queue_destroy(list, l_free);
	json_object_put(jobjarray);

	return NULL;
}

/*
 * Checks if the config message received from the cloud is valid.
 * Validates if the values are valid and if the event_flags are consistent
 * with desired events.
 * No need to check if sensor_id,event_flags and time_sec are positive for
 * they are unsigned from protocol.
 */
int8_t parser_config_is_valid(struct l_queue *config_list)
{
	struct l_queue_entry *entry;
	knot_msg_config *config;
	int diff_int, diff_dec;

	entry = (struct l_queue_entry *) l_queue_get_entries(config_list);
	while (entry) {
		config = entry->data;

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

struct l_queue *parser_mydevices_to_list(const char *json_str)
{
	json_object *jobj, *jobjentry, *jobjkey;
	struct l_queue *list;
	struct mydevice *mydevice;
	const char *uuid;
	const char *name;
	const char *id;
	int len;
	int i;

	jobj = json_tokener_parse(json_str);
	if (!jobj)
		return NULL;

	if (json_object_get_type(jobj) != json_type_array) {
		json_object_put(jobj);
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
		/* Getting 'Id': Mandatory field for registered device */
		if (!json_object_object_get_ex(jobjentry, "id", &jobjkey))
			continue;

		id = json_object_get_string(jobjkey);

		/* Getting 'schema': Mandatory field for registered device */
		if (!json_object_object_get_ex(jobjentry, "schema", &jobjkey))
			continue;

		/* Getting 'Name' */
		if (!json_object_object_get_ex(jobjentry, "name", &jobjkey))
			continue;

		name = json_object_get_string(jobjkey);

		/* Getting 'Uuid' */
		if (!json_object_object_get_ex(jobjentry, "uuid", &jobjkey))
			continue;

		uuid = json_object_get_string(jobjkey);

		mydevice = l_new(struct mydevice, 1);
		mydevice->id   = l_strdup(id);
		mydevice->name = l_strdup(name);
		mydevice->uuid = l_strdup(uuid);
		l_queue_push_tail(list, mydevice);
	}

	json_object_put(jobj);
	return list;
}

struct l_queue *parser_sensorid_to_list(const char *json_str)
{
	struct l_queue *list;
	json_object *jobjarray;
	json_object *jobjentry;
	json_object *jobjkey;
	int sensor_id;
	int i;

	jobjarray = json_tokener_parse(json_str);
	if (!jobjarray)
		return NULL;

	if (json_object_get_type(jobjarray) != json_type_array) {
		json_object_put(jobjarray);
		return NULL;
	}

	list = l_queue_new();
	for (i = 0; i < json_object_array_length(jobjarray); i++) {

		jobjentry = json_object_array_get_idx(jobjarray, i);
		if (!jobjentry)
			break;

		/* Getting 'sensor_id' */
		if (!json_object_object_get_ex(jobjentry,
					       "sensor_id", &jobjkey))
			continue;

		errno = 0;
		sensor_id = json_object_get_int(jobjkey);
		if (errno == EINVAL)
			continue;

		/* Order matters: Add to tail to generate the same json */
		l_queue_push_tail(list,
				  l_memdup(&sensor_id, sizeof(sensor_id)));

	}

	json_object_put(jobjarray);

	if (l_queue_isempty(list)) {
		l_queue_destroy(list, NULL);
		return NULL;
	}

	return list;
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

int parser_jso_setdata_to_msg(json_object *jso, knot_msg_data *msg)
{
	json_object *jobjkey;
	knot_data data;
	int sensor_id;
	int jtype;

	/* Getting 'sensor_id' */
	if (!json_object_object_get_ex(jso, "sensor_id", &jobjkey))
		return -EINVAL;

	if (json_object_get_type(jobjkey) != json_type_int)
		return -EINVAL;

	sensor_id = json_object_get_int(jobjkey);

	/* Getting 'value' */
	memset(&data, 0, sizeof(knot_data));
	if (!json_object_object_get_ex(jso, "value", &jobjkey))
		return -EINVAL;

	/* TODO: RAW is not supported */
	jtype = json_object_get_type(jobjkey);
	if (jtype != json_type_int &&
	    jtype != json_type_double && jtype != json_type_boolean)
		return -EINVAL;

	msg->hdr.type = KNOT_MSG_SET_DATA;
	msg->hdr.payload_len = sizeof(knot_msg_data) - sizeof(knot_msg_header);
	msg->sensor_id = sensor_id;
	parse_json_value_types(jobjkey, &msg->payload.values);

	return 0;
}
