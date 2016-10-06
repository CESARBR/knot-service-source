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

#include "proto.h"
#include "log.h"
#include "msg.h"

struct trust {
	char *uuid;			/* Device UUID */
	char *token;			/* Device token */
	GSList *schema;			/* knot_schema accepted by cloud */
	GSList *schema_tmp;		/*
					* knot_schema to be submitted to cloud
					*/
	GSList *config;			/* knot_config accepted by cloud */
};

/* Maps sockets to sessions  */
static GHashTable *trust_list;

static void trust_free(struct trust *trust)
{
	g_free(trust->uuid);
	g_free(trust->token);
	g_slist_free_full(trust->schema, g_free);
	g_slist_free_full(trust->schema_tmp, g_free);
	g_slist_free_full(trust->config, g_free);
	g_free(trust);
}

static gboolean node_hup_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	int sock = g_io_channel_unix_get_fd(io);

	g_hash_table_remove(trust_list, GINT_TO_POINTER(sock));

	return FALSE;
}

static int sensor_id_cmp(gconstpointer a, gconstpointer b)
{
	const knot_msg_schema *schema = a;
	unsigned int sensor_id = GPOINTER_TO_UINT(b);

	return sensor_id - schema->sensor_id;
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

	if (!json_object_object_get_ex(jobj, "devices", &jobjarray))
		goto done;

	if (json_object_get_type(jobjarray) != json_type_array ||
				json_object_array_length(jobjarray) != 1)
		goto done;

	/* Getting first entry of 'devices' array :
	 *
	 * {"devices":[{"uuid": ...
	 *		"schema" : [
	 *			{"sensor_id": x, "value_type": w,
	 *				"unit": z "type_id": y, "name": "foo"}]
	 *		}]
	 * }
	 */
	jobjentry = json_object_array_get_idx(jobjarray, 0);
	if (!jobjentry)
		goto done;

	/* 'schema' is an array */
	if (!json_object_object_get_ex(jobjentry, "schema", &jobjarray))
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
	knot_msg_config *entry;
	int sensor_id, event_flags, time_sec, i;
	knot_value_types lower_limit, upper_limit;
	json_type jtype;

	jobj = json_tokener_parse(json_str);
	if (!jobj)
		return NULL;

	if (!json_object_object_get_ex(jobj, "devices", &jobjarray))
		goto done;

	if (json_object_get_type(jobjarray) != json_type_array ||
				json_object_array_length(jobjarray) != 1)
		goto done;

	/* Getting first entry of 'devices' array :
	 *
	 * {"devices":[{"uuid":
	 *		"config" : [
	 *			{"sensor_id": v, "event_flags": w,
	 *				"time_sec": x "lower_limit": y,
	 *						"upper_limit": z}]
	 *		}]
	 * }
	 */

	jobjentry = json_object_array_get_idx(jobjarray, 0);
	if (!jobjentry)
		goto done;

	/* 'config' is an array */
	if (!json_object_object_get_ex(jobjentry, "config", &jobjarray))
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

		entry = g_new0(knot_msg_config, 1);
		entry->sensor_id = sensor_id;
		entry->values.event_flags = event_flags;
		entry->values.time_sec = time_sec;
		memcpy(&(entry->values.lower_limit), &lower_limit,
						sizeof(knot_value_types));
		memcpy(&(entry->values.upper_limit), &upper_limit,
						sizeof(knot_value_types));
		list = g_slist_append(list, entry);
	}

	json_object_put(jobj);

	return list;

done:
	g_slist_free_full(list, g_free);
	json_object_put(jobj);

	return NULL;
}

static int8_t msg_register(const credential_t *owner,
					int sock, int proto_sock,
					const struct proto_ops *proto_ops,
					const knot_msg_register *kreq,
					knot_msg_credential *krsp)
{
	GIOChannel *io;
	struct trust *trust;
	json_object *jobj;
	const char *jobjstring;
	char *uuid, *token;
	json_raw_t json;
	int err;
	int8_t result;

	if (kreq->devName[0] == '\0') {
		LOG_ERROR("Empty device name!\n");
		return KNOT_REGISTER_INVALID_DEVICENAME;
	}

	jobj = json_object_new_object();
	if (!jobj) {
		LOG_ERROR("JSON: no memory\n");
		return KNOT_ERROR_UNKNOWN;
	}

	json_object_object_add(jobj, "KNOTDevice",
				json_object_new_string("type"));
	json_object_object_add(jobj, "name",
			       json_object_new_string(kreq->devName));
	json_object_object_add(jobj, "owner",
				json_object_new_string(owner->uuid));

	jobjstring = json_object_to_json_string(jobj);

	memset(&json, 0, sizeof(json));
	err = proto_ops->mknode(proto_sock, jobjstring, &json);

	json_object_put(jobj);

	if (err < 0) {
		LOG_ERROR("manager mknode: %s(%d)\n", strerror(-err), -err);
		free(json.data);
		return KNOT_CLOUD_FAILURE;
	}

	if (parse_device_info(json.data, &uuid, &token) < 0) {
		LOG_ERROR("Unexpected response!\n");
		free(json.data);
		return KNOT_CLOUD_FAILURE;
	}

	free(json.data);

	LOG_INFO("UUID: %s, TOKEN: %s\n", uuid, token);

	/* Parse function never returns NULL for 'uuid' or 'token' fields */
	if (strlen(uuid) != 36 || strlen(token) != 40) {
		LOG_ERROR("Invalid UUID or token!\n");
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

	return KNOT_SUCCESS;

done:
	g_free(uuid);
	g_free(token);

	return result;
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
		LOG_INFO("Permission denied!\n");
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	/* 36 octets */
	if (kreq->hdr.payload_len != 0) {
		LOG_ERROR("Wrong payload length!\n");
		result = KNOT_INVALID_DATA;
		goto done;
	}

	LOG_INFO("rmnode: %.36s\n", trust->uuid);

	err = proto_ops->rmnode(proto_sock, trust->uuid, trust->token, &jbuf);
	if (err < 0) {
		result = KNOT_CLOUD_FAILURE;
		LOG_ERROR("rmnode() failed %s (%d)\n", strerror(-err), -err);
		goto done;
	}

	result = KNOT_SUCCESS;

done:
	if (jbuf.data)
		free(jbuf.data);

	return result;
}

static int8_t msg_auth(int sock, int proto_sock,
				const struct proto_ops *proto_ops,
				const knot_msg_authentication *kmauth)
{
	GIOChannel *io;
	json_raw_t json;
	struct trust *trust;
	int err;

	if (g_hash_table_lookup(trust_list, GINT_TO_POINTER(sock))) {
		LOG_INFO("Authenticated already\n");
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
	trust->config = parse_device_config(json.data);

	free(json.data);

	if (err < 0) {
		LOG_ERROR("signin(): %s(%d)\n", strerror(-err), -err);
		trust_free(trust);
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	g_hash_table_insert(trust_list, GINT_TO_POINTER(sock), trust);

	/* Add a watch to remove the credential when the client disconnects */
	io = g_io_channel_unix_new(sock);
	g_io_add_watch(io, G_IO_HUP | G_IO_NVAL | G_IO_ERR, node_hup_cb, NULL);
	g_io_channel_unref(io);

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

	trust = g_hash_table_lookup(trust_list, GINT_TO_POINTER(sock));
	if (!trust) {
		LOG_INFO("Permission denied!\n");
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

	/* Add to a temporary list until receiving complete schema */
	kschema = g_memdup(schema, sizeof(*schema));
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
		LOG_ERROR("manager schema(): %s(%d)\n", strerror(-err), -err);
		return KNOT_CLOUD_FAILURE;
	}

	/* If POST succeed: free old schema and use the new one */
	g_slist_free_full(trust->schema, g_free);
	trust->schema = trust->schema_tmp;
	trust->schema_tmp = NULL;

	return KNOT_SUCCESS;
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
		LOG_INFO("Permission denied!\n");
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	sensor_id = kmdata->sensor_id;


	list = g_slist_find_custom(trust->schema, GUINT_TO_POINTER(sensor_id),
								sensor_id_cmp);
	if (!list) {
		LOG_INFO("sensor_id(0x%02x): data type mismatch!\n", sensor_id);
		return KNOT_INVALID_DATA;
	}

	schema = list->data;

	err = knot_schema_is_valid(schema->values.type_id,
				schema->values.value_type, schema->values.unit);
	if (err) {
		LOG_INFO("sensor_id(0x%d), type_id(0x%04x): unit mismatch!\n",
					sensor_id, schema->values.type_id);
		return KNOT_INVALID_DATA;
	}

	LOG_INFO("sensor:%d, unit:%d, value_type:%d\n", sensor_id,
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
	printf("JSON: %s\n", jobjstr);

	memset(&json, 0, sizeof(json));
	err = proto_ops->data(proto_sock, trust->uuid, trust->token,
							jobjstr, &json);
	if (json.data)
		free(json.data);

	json_object_put(jobj);

	if (err < 0) {
		LOG_ERROR("manager data(): %s(%d)\n", strerror(-err), -err);
		return KNOT_CLOUD_FAILURE;
	}

	return KNOT_SUCCESS;
}

ssize_t msg_process(const credential_t *owner, int sock, int proto_sock,
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
		LOG_ERROR("Output PDU: invalid PDU length\n");
		return -EINVAL;
	}

	/* Response is always the next opcode */
	rtype = kreq->hdr.type + 1;

	/* Set a default payload length for error */
	krsp->hdr.payload_len = sizeof(krsp->action.result);

	/* At least header should be received */
	if (ilen < sizeof(knot_msg_header)) {
		LOG_ERROR("KNOT PDU: invalid minimum length\n");
		goto done;
	}

	/* Checking PDU length consistency */
	if (ilen != (sizeof(kreq->hdr) + kreq->hdr.payload_len)) {
		LOG_ERROR("KNOT PDU: length mismatch\n");
		goto done;
	}

	LOG_INFO("KNOT OP: 0x%02X LEN: %02x\n",
				kreq->hdr.type, kreq->hdr.payload_len);

	switch (kreq->hdr.type) {
	case KNOT_MSG_REGISTER_REQ:

		/* Payload length is set by the caller */
		result = msg_register(owner, sock, proto_sock, proto_ops,
						&kreq->reg, &krsp->cred);
		break;
	case KNOT_MSG_UNREGISTER_REQ:
		result = msg_unregister(sock, proto_sock, proto_ops,
								&kreq->unreg);
		break;
	case KNOT_MSG_DATA:
		result = msg_data(sock, proto_sock, proto_ops, &kreq->data);
		break;
	case KNOT_MSG_AUTH_REQ:
		result = msg_auth(sock, proto_sock, proto_ops, &kreq->auth);
		break;
	case KNOT_MSG_SCHEMA:
	case KNOT_MSG_SCHEMA | KNOT_MSG_SCHEMA_FLAG_END:
		eof = kreq->hdr.type & KNOT_MSG_SCHEMA_FLAG_END ? TRUE : FALSE;
		result = msg_schema(sock, proto_sock, proto_ops, &kreq->schema,
									eof);
		break;
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

int msg_start(void)
{
	trust_list = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					NULL, (GDestroyNotify) trust_free);

	return 0;
}

void msg_stop(void)
{
	g_hash_table_destroy(trust_list);
}
