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
		config->hdr.type = KNOT_MSG_CONFIG;
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

struct l_queue *parser_mydevices_to_list(const char *json_str)
{
	json_object *jobj, *jobjentry, *jobjkey;
	struct l_queue *list;
	int64_t id;
	struct mydevice *mydevice;
	const char *uuid;
	const char *name;
	int len;
	int i;

	jobj = json_tokener_parse(json_str);
	if (!jobj)
		return NULL;
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

		/* Getting 'Name' */
		if (!json_object_object_get_ex(jobjentry, "name", &jobjkey))
			continue;

		name = json_object_get_string(jobjkey);

		/* Getting 'Uuid' */
		if (!json_object_object_get_ex(jobjentry, "uuid", &jobjkey))
			continue;

		errno = 0;
		uuid = json_object_get_string(jobjkey);
		if (errno)
			continue;

		mydevice = l_new(struct mydevice, 1);
		mydevice->id = id;
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
