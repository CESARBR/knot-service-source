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

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include <json-c/json.h>

#include <knot_types.h>
#include <knot_protocol.h>

#include <unistd.h>

#include "proto.h"
#include "log.h"
#include "msg.h"

struct config {
	knot_msg_config kmcfg;		/* knot_message_config from cloud */
	char *hash;			/* Checksum of kmcfg */
	gboolean confirmed;

};

struct trust {
	char *uuid;			/* Device UUID */
	char *token;			/* Device token */
	GSList *schema;			/* knot_schema accepted by cloud */
	GSList *schema_tmp;		/*
					* knot_schema to be submitted to cloud
					*/
	GSList *config;			/* knot_config accepted from cloud */
	GSList *config_tmp;		/* knot_config to be validate by GW */
};

struct proto_watch {
	unsigned int id;
	GIOChannel *node_io;
};

/* Maps sockets to sessions  */
static GHashTable *trust_list;

static char owner_uuid[KNOT_PROTOCOL_UUID_LEN + 1];

static void config_free(gpointer mem)
{
	struct config *cfg = mem;

	g_free(cfg->hash);
	g_free(cfg);
}

static void trust_free(struct trust *trust)
{
	g_free(trust->uuid);
	g_free(trust->token);
	g_slist_free_full(trust->schema, g_free);
	g_slist_free_full(trust->schema_tmp, g_free);
	g_slist_free_full(trust->config, config_free);
	g_free(trust);
}

static gboolean node_hup_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	int sock = g_io_channel_unix_get_fd(io);

	g_hash_table_remove(trust_list, GINT_TO_POINTER(sock));

	return FALSE;
}

static gboolean proto_hup_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct proto_watch *proto_watch = user_data;

	if (proto_watch->id > 0)
		g_source_remove(proto_watch->id);
	g_io_channel_unref(proto_watch->node_io);
	g_free(proto_watch);

	return FALSE;
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

static int8_t msg_unregister(int sock, int proto_sock,
					const struct proto_ops *proto_ops,
					const knot_msg_unregister *kreq)
{
	const struct trust *trust;
	json_raw_t jbuf = { NULL, 0 };
	int8_t result;
	int err;

	trust = g_hash_table_lookup(trust_list, GINT_TO_POINTER(sock));
	if (!trust) {
		log_info("Permission denied!");
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	/* 36 octets */
	if (kreq->hdr.payload_len != 0) {
		log_error("Wrong payload length!");
		result = KNOT_INVALID_DATA;
		goto done;
	}

	log_info("rmnode: %.36s", trust->uuid);

	err = proto_ops->rmnode(proto_sock, trust->uuid, trust->token, &jbuf);
	if (err < 0) {
		result = KNOT_CLOUD_FAILURE;
		log_error("rmnode() failed %s (%d)", strerror(-err), -err);
		goto done;
	}

	result = KNOT_SUCCESS;

done:
	if (jbuf.data)
		free(jbuf.data);

	return result;
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
		log_info("Permission denied!");
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
		log_info("Permission denied!");
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
		log_info("Permission denied!");
		*result = KNOT_CREDENTIAL_UNAUTHORIZED;
		return NULL;
	}

	trust->config_tmp = parse_device_config(json.data);

	/* config_is_valid() returns 0 if SUCCESS */
	if (config_is_valid(trust->config_tmp)) {
		log_error("Invalid config message");
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
		log_error("node_ops: %s(%d)", strerror(err), err);
		return -err;
	}

	return 0;
}

/*
 * Callback that parses the JSON for config (and in the future, send data)
 * messages. It is called from the protocol that is used to communicate with
 * the cloud (e.g. http, websocket).
 */
static void proto_watch_cb(json_raw_t json, void *user_data)
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
			log_error("KNOT SEND ERROR");
		tmp = g_slist_next(tmp);
	}
	g_slist_free_full(list, g_free);
}

static int8_t msg_register(int sock, int proto_sock,
					const struct proto_ops *proto_ops,
					const knot_msg_register *kreq,
					knot_msg_credential *krsp)
{
	GIOChannel *io, *proto_io;
	struct trust *trust;
	json_object *jobj;
	const char *jobjstring;
	char *uuid, *token;
	json_raw_t json;
	int err, len;
	int8_t result;
	char thing_name[KNOT_PROTOCOL_DEVICE_NAME_LEN];
	struct proto_watch *proto_watch;

	if (kreq->devName[0] == '\0') {
		log_error("Empty device name!");
		return KNOT_REGISTER_INVALID_DEVICENAME;
	}

	/*
	 * Make sure the thing name is at maximum 63 bytes leaving 1 byte left
	 * for the terminating null character
	 */
	memset(thing_name, 0, sizeof(thing_name));

	len = MIN(kreq->hdr.payload_len, KNOT_PROTOCOL_DEVICE_NAME_LEN - 1);

	strncpy(thing_name, kreq->devName, len);

	jobj = json_object_new_object();
	if (!jobj) {
		log_error("JSON: no memory");
		return KNOT_ERROR_UNKNOWN;
	}

	json_object_object_add(jobj, "type",
				json_object_new_string("KNOTDevice"));
	json_object_object_add(jobj, "name",
				json_object_new_string(thing_name));
	json_object_object_add(jobj, "owner",
				json_object_new_string(owner_uuid));

	jobjstring = json_object_to_json_string(jobj);

	memset(&json, 0, sizeof(json));
	err = proto_ops->mknode(proto_sock, jobjstring, &json);

	json_object_put(jobj);

	if (err < 0) {
		log_error("manager mknode: %s(%d)", strerror(-err), -err);
		free(json.data);
		return KNOT_CLOUD_FAILURE;
	}

	if (parse_device_info(json.data, &uuid, &token) < 0) {
		log_error("Unexpected response!");
		free(json.data);
		return KNOT_CLOUD_FAILURE;
	}

	free(json.data);

	log_info("UUID: %s, TOKEN: %s", uuid, token);

	/* Parse function never returns NULL for 'uuid' or 'token' fields */
	if (strlen(uuid) != KNOT_PROTOCOL_UUID_LEN ||
				strlen(token) != KNOT_PROTOCOL_TOKEN_LEN) {
		log_error("Invalid UUID or token!");
		result = KNOT_CLOUD_FAILURE;
		goto done;
	}

	strcpy(krsp->uuid, uuid);
	strcpy(krsp->token, token);

	/* Payload length includes the result, UUID and TOKEN */
	krsp->hdr.payload_len = sizeof(*krsp) - sizeof(knot_msg_header);

	trust = g_new0(struct trust, 1);
	trust->uuid = uuid;
	trust->token = token;

	g_hash_table_replace(trust_list, GINT_TO_POINTER(sock), trust);
	/* Add a watch to remove the credential when the client disconnects */
	io = g_io_channel_unix_new(sock);
	g_io_add_watch(io, G_IO_HUP | G_IO_NVAL | G_IO_ERR, node_hup_cb, NULL);
	g_io_channel_unref(io);

	proto_watch = g_new0(struct proto_watch, 1);
	proto_watch->id = proto_ops->async(proto_sock, trust->uuid,
				trust->token, proto_watch_cb, proto_watch);
	proto_watch->node_io = g_io_channel_ref(io);

	/* Add a watch to remove source when cloud disconnects */
	proto_io = g_io_channel_unix_new(proto_sock);
	g_io_add_watch(proto_io, G_IO_HUP | G_IO_NVAL | G_IO_ERR, proto_hup_cb,
			proto_watch);
	g_io_channel_unref(proto_io);

	return KNOT_SUCCESS;

done:
	g_free(uuid);
	g_free(token);

	return result;
}

static int8_t msg_auth(int sock, int proto_sock,
				const struct proto_ops *proto_ops,
				const knot_msg_authentication *kmauth)
{
	GIOChannel *io;
	GIOChannel *proto_io;
	json_raw_t json;
	struct trust *trust;
	struct proto_watch *proto_watch;
	int err;

	if (g_hash_table_lookup(trust_list, GINT_TO_POINTER(sock))) {
		log_info("Authenticated already");
		return KNOT_SUCCESS;
	}

	memset(&json, 0, sizeof(json));
	trust = g_new0(struct trust, 1);
	/*
	 * g_strndup returns a newly-allocated buffer n + 1 bytes
	 * long which will always be nul-terminated.
	 */
	trust->uuid = g_strndup(kmauth->uuid, sizeof(kmauth->uuid));
	trust->token = g_strndup(kmauth->token, sizeof(kmauth->token));
	err = proto_ops->signin(proto_sock, trust->uuid, trust->token, &json);

	if (!json.data) {
		trust_free(trust);
		return KNOT_SCHEMA_EMPTY;
	}

	trust->schema = parse_device_schema(json.data);
	trust->config_tmp = parse_device_config(json.data);

	free(json.data);

	if (err < 0) {
		log_error("signin(): %s(%d)", strerror(-err), -err);
		trust_free(trust);
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	if (config_is_valid(trust->config_tmp)) {
		log_error("Invalid config message");
		g_slist_free_full(trust->config_tmp, config_free);
		trust->config_tmp = NULL;
	} else {
		trust->config = trust->config_tmp;
		trust->config_tmp = NULL;
	}

	g_hash_table_insert(trust_list, GINT_TO_POINTER(sock), trust);

	/* Add a watch to remove the credential when the client disconnects */
	io = g_io_channel_unix_new(sock);
	g_io_add_watch(io, G_IO_HUP | G_IO_NVAL | G_IO_ERR, node_hup_cb, NULL);
	g_io_channel_unref(io);


	proto_watch = g_new0(struct proto_watch, 1);
	proto_watch->id = proto_ops->async(proto_sock,
			trust->uuid, trust->token, proto_watch_cb, proto_watch);
	proto_watch->node_io = g_io_channel_ref(io);

	/* Add a watch to remove source when cloud disconnects */
	proto_io = g_io_channel_unix_new(proto_sock);
	g_io_add_watch(proto_io, G_IO_HUP | G_IO_NVAL | G_IO_ERR, proto_hup_cb,
			proto_watch);
	g_io_channel_unref(proto_io);

	return KNOT_SUCCESS;
}

static int8_t msg_schema(int sock, int proto_sock,
				const struct proto_ops *proto_ops,
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
		log_info("Permission denied!");
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

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
	err = proto_ops->schema(proto_sock, trust->uuid, trust->token,
							jobjstr, &json);
	if (json.data)
		free(json.data);

	json_object_put(schemajobj);

	if (err < 0) {
		g_slist_free_full(trust->schema_tmp, g_free);
		trust->schema_tmp = NULL;
		log_error("manager schema(): %s(%d)", strerror(-err), -err);
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
static void update_device_getdata(const struct proto_ops *proto_ops,
					int proto_sock, char *uuid, char *token,
					uint8_t sensor_id)
{
	json_object *jobj, *jobjarray, *jobjentry, *jobjkey;
	json_object *ajobj, *setdatajobj;
	json_raw_t json;
	const char *jobjstr;
	int i, err;

	memset(&json, 0, sizeof(json));
	err = proto_ops->fetch(proto_sock, uuid, token, &json);

	if (err < 0) {
		log_error("signin(): %s(%d)", strerror(-err), -err);
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

	err = proto_ops->setdata(proto_sock, uuid, token, jobjstr, &json);

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
					const struct proto_ops *proto_ops,
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
		log_info("Permission denied!");
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	sensor_id = kmdata->sensor_id;

	list = g_slist_find_custom(trust->schema, GUINT_TO_POINTER(sensor_id),
								sensor_id_cmp);
	if (!list) {
		log_info("sensor_id(0x%02x): data type mismatch!", sensor_id);
		return KNOT_INVALID_DATA;
	}

	schema = list->data;

	err = knot_schema_is_valid(schema->values.type_id,
				schema->values.value_type, schema->values.unit);
	if (err) {
		log_info("sensor_id(0x%d), type_id(0x%04x): unit mismatch!",
					sensor_id, schema->values.type_id);
		return KNOT_INVALID_DATA;
	}

	log_info("sensor:%d, unit:%d, value_type:%d", sensor_id,
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

	log_info("JSON: %s", jobjstr);

	memset(&json, 0, sizeof(json));
	err = proto_ops->data(proto_sock, trust->uuid, trust->token,
							jobjstr, &json);
	if (json.data)
		free(json.data);

	json_object_put(jobj);

	if (err < 0) {
		log_error("manager data(): %s(%d)", strerror(-err), -err);
		return KNOT_CLOUD_FAILURE;
	}

	update_device_getdata(proto_ops, proto_sock, trust->uuid, trust->token,
								sensor_id);

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
		log_info("Permission denied!");
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
	log_info("THING %s received config for sensor %d", trust->uuid,
								sensor_id);
	return KNOT_SUCCESS;
}

/*
 * Updates de 'devices' db, removing the sensor_id that was acknowledged by the
 * THING.
 */
static void update_device_setdata(const struct proto_ops *proto_ops,
					int proto_sock, char *uuid, char *token,
					uint8_t sensor_id)
{
	json_object *jobj, *jobjarray, *jobjentry, *jobjkey;
	json_object *ajobj, *setdatajobj;
	json_raw_t json;
	const char *jobjstr;
	int i, err;

	memset(&json, 0, sizeof(json));
	err = proto_ops->fetch(proto_sock, uuid, token, &json);

	if (err < 0) {
		log_error("signin(): %s(%d)", strerror(-err), -err);
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

	err = proto_ops->setdata(proto_sock, uuid, token, jobjstr, &json);

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
					const struct proto_ops *proto_ops,
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
		log_info("Permission denied!");
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	sensor_id = kmdata->sensor_id;

	list = g_slist_find_custom(trust->schema, GUINT_TO_POINTER(sensor_id),
								sensor_id_cmp);
	if (!list) {
		log_info("sensor_id(0x%02x): data type mismatch!", sensor_id);
		return KNOT_INVALID_DATA;
	}

	schema = list->data;

	err = knot_schema_is_valid(schema->values.type_id,
				schema->values.value_type, schema->values.unit);
	if (err) {
		log_info("sensor_id(0x%d), type_id(0x%04x): unit mismatch!",
					sensor_id, schema->values.type_id);
		return KNOT_INVALID_DATA;
	}

	log_info("sensor:%d, unit:%d, value_type:%d", sensor_id,
				schema->values.unit, schema->values.value_type);

	/* Fetches the 'devices' db */
	update_device_setdata(proto_ops, proto_sock, trust->uuid, trust->token,
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
	err = proto_ops->data(proto_sock, trust->uuid, trust->token,
							jobjstr, &json);
	if (json.data)
		free(json.data);

	json_object_put(jobj);

	if (err < 0) {
		log_error("manager data(): %s(%d)", strerror(-err), -err);
		return KNOT_CLOUD_FAILURE;
	}

	log_info("THING %s updated data for sensor %d", trust->uuid,
								sensor_id);

	return KNOT_SUCCESS;
}


ssize_t msg_process(int sock, int proto_sock,
				const struct proto_ops *proto_ops,
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
		log_error("Output PDU: invalid PDU length");
		return -EINVAL;
	}

	/* Set a default payload length for error */
	krsp->hdr.payload_len = sizeof(krsp->action.result);

	/* At least header should be received */
	if (ilen < sizeof(knot_msg_header)) {
		log_error("KNOT PDU: invalid minimum length");
		goto done;
	}

	/* Checking PDU length consistency */
	if (ilen != (sizeof(kreq->hdr) + kreq->hdr.payload_len)) {
		log_error("KNOT PDU: length mismatch");
		goto done;
	}

	log_info("KNOT OP: 0x%02X LEN: %02x",
				kreq->hdr.type, kreq->hdr.payload_len);

	switch (kreq->hdr.type) {
	case KNOT_MSG_REGISTER_REQ:
		/* Payload length is set by the caller */
		result = msg_register(sock, proto_sock, proto_ops,
						&kreq->reg, &krsp->cred);
		rtype = KNOT_MSG_REGISTER_RESP;
		break;
	case KNOT_MSG_UNREGISTER_REQ:
		result = msg_unregister(sock, proto_sock, proto_ops,
								&kreq->unreg);
		rtype = KNOT_MSG_UNREGISTER_RESP;
		break;
	case KNOT_MSG_DATA:
		result = msg_data(sock, proto_sock, proto_ops, &kreq->data);
		rtype = KNOT_MSG_DATA_RESP;
		break;
	case KNOT_MSG_AUTH_REQ:
		result = msg_auth(sock, proto_sock, proto_ops, &kreq->auth);
		rtype = KNOT_MSG_AUTH_RESP;
		break;
	case KNOT_MSG_SCHEMA:
	case KNOT_MSG_SCHEMA_END:
		eof = kreq->hdr.type == KNOT_MSG_SCHEMA_END ? TRUE : FALSE;
		result = msg_schema(sock, proto_sock, proto_ops, &kreq->schema,
									eof);
		rtype = KNOT_MSG_SCHEMA_RESP;
		if (eof)
			rtype = KNOT_MSG_SCHEMA_END_RESP;
		break;
	case KNOT_MSG_CONFIG_RESP:
		result = msg_config_resp(sock, &kreq->item);
		/* No octets to be transmitted */
		return 0;
	case KNOT_MSG_DATA_RESP:
		result = msg_setdata_resp(sock, proto_sock, proto_ops,
								&kreq->data);
		return 0;
	default:
		/* TODO: reply unknown command */
		break;
	}

done:
	krsp->hdr.type = rtype;

	krsp->action.result = result;

	/* Return the actual amount of octets to be transmitted */
	return (sizeof(knot_msg_header) + krsp->hdr.payload_len);
}

int msg_start(const char *uuid)
{
	memset(owner_uuid, 0, sizeof(owner_uuid));
	strncpy(owner_uuid, uuid, sizeof(owner_uuid));

	trust_list = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					NULL, (GDestroyNotify) trust_free);

	return 0;
}

void msg_stop(void)
{
	g_hash_table_destroy(trust_list);
}
