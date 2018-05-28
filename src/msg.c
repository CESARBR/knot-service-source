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
#include "node.h"
#include "device.h"
#include "proxy.h"
#include "proto.h"
#include "parser.h"
#include "msg.h"

#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define KNOT_ID_LEN 16
#define ROLLBACK_TICKS		5 /* Equals to 5*1096ms */

struct session {
	int refs;
	bool trusted;			/* Authenticated */
	struct node_ops *node_ops;
	struct l_io *node_channel;	/* Radio event source */
	struct l_io *proto_channel;	/* Cloud event source */
	int node_fd;			/* Unix socket */
	uint64_t id;			/* Device identification */
	int rollback;			/* Counter: remove if schema is not received */
	char *uuid;			/* Device UUID */
	char *token;			/* Device token */
	struct l_queue *schema_list;	/* Schema accepted by cloud */
	char *schema;			/* Current schema */
	struct l_queue *schema_list_tmp;/* Schema to be submitted to cloud */
	struct l_queue *config_list;	/* knot_config accepted from cloud */
	char *config;			/* Current config */
	struct l_queue *getdata_list;	/* List of sensors requested */
	char *getdata;			/* Current get_data */
	struct l_timeout *downstream_to; /* Active when there is data to send */
	char *setdata;			/* Current get_data */
	json_object *setdata_jso;	/* JSON object representing set_data */
};

static struct l_queue *session_list;
static struct l_queue *device_id_list;
static struct l_timeout *start_to;
static const char *owner_uuid;
static bool proxy_enabled = false;

static struct session *session_ref(struct session *session)
{
	if (unlikely(!session))
		return NULL;

	__sync_fetch_and_add(&session->refs, 1);

	return session;
}

static struct session *session_new(struct node_ops *node_ops)
{
	struct session *session;

	session = l_new(struct session, 1);
	session->refs = 0;
	session->uuid = NULL;
	session->token = NULL;
	session->id = INT32_MAX;
	session->node_ops = node_ops;
	session->schema_list = NULL;
	session->schema_list_tmp = NULL;
	session->config_list = NULL;
	session->getdata_list = NULL;
	session->setdata_jso = NULL;

	return session_ref(session);
}

static void session_destroy(struct session *session)
{
	if (unlikely(!session))
		return;

	l_io_destroy(session->node_channel);
	l_io_destroy(session->proto_channel);

	l_free(session->uuid);
	l_free(session->token);
	l_queue_destroy(session->schema_list, l_free);
	l_queue_destroy(session->schema_list_tmp, l_free);
	l_queue_destroy(session->config_list, l_free);
	l_queue_destroy(session->getdata_list, l_free);
	l_timeout_remove(session->downstream_to);
	l_free(session->schema);
	l_free(session->config);
	l_free(session->getdata);
	l_free(session->setdata);

	l_free(session);
}

static void session_unref(struct session *session)
{
	if (unlikely(!session))
		return;

	if (__sync_sub_and_fetch(&session->refs, 1))
		return;

	session_destroy(session);
}

static void mydevice_free(void *data)
{
	struct mydevice *mydevice = data;
	if (unlikely(!mydevice))
		return;

	l_free(mydevice->id);
	l_free(mydevice->uuid);
	l_free(mydevice->name);
	l_free(mydevice);
}

static bool device_id_cmp(const void *a, const void *b)
{
	const struct mydevice *val1 = a;
	const char *id = b;

	return strcmp(val1->id, id) == 0 ? true : false;
}

static bool device_uuid_cmp(const void *a, const void *b)
{
	const struct mydevice *mydevice = a;
	const char *uuid = b;
	return strcmp(mydevice->uuid, uuid) == 0 ? true: false;
}

static bool sensor_id_cmp(const void *a, const void *b)
{
	const uint8_t *val1 = a;
	const uint8_t val2 = L_PTR_TO_INT(b);

	return (*val1 == val2 ? true : false);
}

static bool schema_sensor_id_cmp(const void *entry_data, const void *user_data)
{
	const knot_msg_schema *schema = entry_data;
	unsigned int sensor_id = L_PTR_TO_UINT(user_data);

	return sensor_id == schema->sensor_id;
}

static knot_msg_schema *schema_find(struct l_queue *schema,
						unsigned int sensor_id)
{
	return l_queue_find(schema,
			    schema_sensor_id_cmp,
			    L_UINT_TO_PTR(sensor_id));
}

static bool config_sensor_id_cmp(const void *entry_data, const void *user_data)
{
	const knot_msg_config *config = entry_data;
	unsigned int sensor_id = L_PTR_TO_UINT(user_data);

	return config->sensor_id == sensor_id;
}

static int8_t msg_unregister(struct session *session)
{
	int proto_sock;
	int8_t result;

	if (!session->trusted) {
		hal_log_info("unregister: Permission denied!");
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	hal_log_info("rmnode: %.36s", session->uuid);
	proto_sock = l_io_get_fd(session->proto_channel);
	result = proto_rmnode(proto_sock, session->uuid, session->token);
	if (result != KNOT_SUCCESS)
		return result;

	session_unref(session);

	return KNOT_SUCCESS;
}

static bool session_node_fd_cmp(const void *entry_data, const void *user_data)
{
	const struct session *session = entry_data;
	int node_fd = L_PTR_TO_INT(user_data);

	return session->node_fd == node_fd;
}

static bool session_uuid_cmp(const void *entry_data, const void *user_data)
{
	const struct session *session = entry_data;
	const char *uuid = user_data;

	return strcmp(session->uuid, uuid) == 0 ? true : false;
}

static void downstream_callback(struct l_timeout *timeout, void *user_data)
{
	struct session *session = user_data;
	struct node_ops *node_ops = session->node_ops;
	json_object *jso;
	knot_msg_config *config;
	knot_msg_data data;
	knot_msg_item item;
	ssize_t olen, osent;
	void *opdu;
	uint8_t *sensor_id;
	int err;

	/* Waiting schema? */
	if (session->rollback) {
		if (session->rollback > ROLLBACK_TICKS) {
			session->rollback = 0;
			msg_unregister(session);
			hal_log_info("Removing %s (rollback)", session->uuid);
			return;
		}

		l_timeout_modify_ms(timeout, 1096);
		hal_log_info("Waiting schema...");
		session->rollback++;
		return;
	}

	/* Wait schema before sending downstream data */

	/* Priority 1: Config message has higher priority */
	config = l_queue_peek_head(session->config_list);
	if (config) {
		opdu = config;
		olen = sizeof(*config);
		goto do_send;
	}

	/* Priority 2: Set Data */
	if (session->setdata_jso) {
		jso = json_object_array_get_idx(session->setdata_jso, 0);
		if (jso) {
			if (parser_jso_setdata_to_msg(jso, &data) == 0) {
				opdu = &data;
				olen = sizeof(data);
				goto do_send;
			}
		}
	}

	/* Priority 3: Get Data */
	sensor_id = l_queue_peek_head(session->getdata_list);
	if (!sensor_id)
		goto disable_timer;

	item.hdr.type = KNOT_MSG_GET_DATA;
	item.hdr.payload_len = sizeof(*sensor_id);
	item.sensor_id = *sensor_id;
	olen = sizeof(item);
	opdu = &item;

do_send:
	osent = node_ops->send(session->node_fd, opdu, olen);
	hal_log_info("Sending downstream data fd(%d)...", session->node_fd);
	if (osent < 0) {
		err = -osent;
		hal_log_error("Can't send downstream data: %s(%d)",
			      strerror(err), err);
		goto disable_timer;
	}

	l_timeout_modify_ms(timeout, 1096);

	return;

disable_timer:
	hal_log_info("Disabling downstream ...");
}

static bool property_changed(const char *name,
			     const char *value, void *user_data)
{
	json_object *jso;
	struct l_queue *list;
	struct session *session;
	struct knot_device *device;
	char id[KNOT_ID_LEN + 1];

	/* FIXME: manage link overload or not connected */
	session = l_queue_find(session_list, session_node_fd_cmp, user_data);
	if (!session)
		return false;

	/* FIXME: Memory leak & detect if schema has changed */
	if (strcmp("schema", name) == 0) {
		if (session->schema && strcmp(session->schema, value) == 0)
			goto done;

		/* Track to detect if update is required */
		list = parser_schema_to_list(value);
		if (list == NULL) {
			hal_log_error("schema: parse error!");
			goto done;
		}

		l_queue_destroy(session->schema_list, l_free);
		session->schema_list = list;
		l_free(session->schema);
		session->schema = l_strdup(value);

		snprintf(id, KNOT_ID_LEN + 1,"%016"PRIx64, session->id);
		device = device_get(id);
		if (device)
			device_set_registered(device, true);

	} else if (strcmp("config", name) == 0) {
		if (session->config && strcmp(session->config, value) == 0)
			goto done;

		list = parser_config_to_list(value);
		if (list == NULL) {
			hal_log_error("config: parse error!");
			goto done;
		}

		if (parser_config_is_valid(list) != KNOT_SUCCESS) {
			hal_log_error("config: invalid format!");
			l_queue_destroy(list, l_free);
			goto done;
		}

		/* Always push to devices when connection is established */
		l_queue_destroy(session->config_list, l_free);
		session->config_list = list;
		l_free(session->config);
		session->config = l_strdup(value);
	} else if (strcmp("get_data", name) == 0) {
		if (session->getdata && strcmp(session->getdata, value) == 0)
			goto done;

		/* Always push to devices when connection is established */
		list = parser_sensorid_to_list(value);
		if (list == NULL) {
			hal_log_error("get_data: parse error!");
			goto done;
		}

		l_queue_destroy(session->getdata_list, l_free);
		session->getdata_list = list;
		l_free(session->getdata);
		session->getdata = l_strdup(value);

	} else if (strcmp("set_data", name) == 0) {
		if (session->setdata && strcmp(session->setdata, value) == 0)
			goto done;

		jso = json_tokener_parse(value);
		if (!jso)
			goto done;

		if (json_object_get_type(jso) != json_type_array) {
			json_object_put(jso);
			return NULL;
		}

		l_free(session->setdata);
		session->setdata = l_strdup(value);
		session->setdata_jso = jso;

	} else if (strcmp("online", name) == 0) {
		snprintf(id, KNOT_ID_LEN + 1,"%016"PRIx64, session->id);
		device = device_get(id);
		if (device)
			device_set_online(device, (strcmp("true", value) == 0));
	}

	/* Timeout created already? */
	if (session->downstream_to) {
		l_timeout_modify_ms(session->downstream_to, 512);
		return true;
	}

done:
	return true;
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

	memcpy(device_name, kreq->devName, length);
}

static void msg_credential_create(knot_msg_credential *message,
				  const char *uuid, const char *token)
{
	memcpy(message->uuid, uuid, sizeof(message->uuid));
	memcpy(message->token, token, sizeof(message->token));

	/* Payload length includes the result, UUID and TOKEN */
	message->hdr.payload_len = sizeof(*message) - sizeof(knot_msg_header);
}

static int8_t msg_register(struct session *session,
			   const knot_msg_register *kreq, size_t ilen,
			   knot_msg_credential *krsp)
{
	char device_name[KNOT_PROTOCOL_DEVICE_NAME_LEN];
	char uuid[KNOT_PROTOCOL_UUID_LEN + 1];
	char token[KNOT_PROTOCOL_TOKEN_LEN + 1];
	char id[KNOT_ID_LEN + 1];
	int proto_sock;
	int8_t result;

	if (!msg_register_has_valid_length(kreq, ilen)
		|| !msg_register_has_valid_device_name(kreq)) {
		hal_log_error("Missing device name!");
		return KNOT_REGISTER_INVALID_DEVICENAME;
	}

	/*
	 * Due to radio packet loss, peer may re-transmits register request
	 * if response does not arrives in 20 seconds. If this device was
	 * previously added we just send the uuid/token again.
	 */
	hal_log_info("Registering (id 0x%016" PRIx64 ")", kreq->id);

	if (session->trusted && kreq->id == session->id) {
		hal_log_info("Register: trusted device");
		msg_credential_create(krsp, session->uuid, session->token);
		return KNOT_SUCCESS;
	}

	msg_register_get_device_name(kreq, device_name);
	memset(uuid, 0, sizeof(uuid));
	memset(token, 0, sizeof(token));
	snprintf(id, KNOT_ID_LEN + 1, "%016"PRIx64, kreq->id);
	proto_sock = l_io_get_fd(session->proto_channel);
	result = proto_mknode(proto_sock, owner_uuid,
			      device_name, id, uuid, token);
	if (result != KNOT_SUCCESS)
		return result;

	hal_log_info("UUID: %s, TOKEN: %s", uuid, token);

	result = proto_signin(proto_sock, uuid, token, property_changed,
			      L_INT_TO_PTR(session->node_fd));

	if (result != KNOT_SUCCESS)
		return result;

	msg_credential_create(krsp, uuid, token);

	session->trusted = true;
	session->id = kreq->id;			/* Device Id */
	session->uuid = l_strdup(uuid);
	session->token = l_strdup(token);
	session->rollback = 1; /* Initial counter value */

	return KNOT_SUCCESS;
}

static bool msg_unregister_req(void *user_data)
{
	knot_msg_unregister kmunreg;
	struct session *session;
	struct node_ops *node_ops;
	struct mydevice *mydevice = user_data;
	ssize_t olen, osent;
	void *opdu;
	int err = 0;

	session = l_queue_find(session_list, session_uuid_cmp, mydevice->uuid);
	if (!session)
		return false;

	node_ops = session->node_ops;

	kmunreg.hdr.type = KNOT_MSG_UNREGISTER_REQ;
	kmunreg.hdr.payload_len = 0;
	olen = sizeof(knot_msg_unregister) + kmunreg.hdr.payload_len;
	opdu = &kmunreg;

	osent = node_ops->send(session->node_fd, opdu, olen);
	if (osent < 0) {
		err = -osent;
		hal_log_error("Can't send unregister message: %s(%d)",
				strerror(err), err);
		return false;
	}

	return true;
}

/* Mandatory before any operation */
static int8_t msg_auth(struct session *session,
		       const knot_msg_authentication *kmauth)
{
	char uuid[KNOT_PROTOCOL_UUID_LEN + 1];
	char token[KNOT_PROTOCOL_TOKEN_LEN + 1];
	struct mydevice *mydevice;
	int proto_sock;
	int8_t result;

	if (session->trusted) {
		hal_log_info("Authenticated already");
		return KNOT_SUCCESS;
	}

	/*
	 * PDU is not null-terminated. Copy UUID and token to
	 * a null-terminated stringmanage link overload or not connected .
	 */
	memset(uuid, 0, sizeof(uuid));
	memset(token, 0, sizeof(token));

	memcpy(uuid, kmauth->uuid, sizeof(kmauth->uuid));
	memcpy(token, kmauth->token, sizeof(kmauth->token));
	/* Set UUID & token: Used at property_changed */
	session->uuid = l_strdup(uuid);
	session->token = l_strdup(token);
	proto_sock = l_io_get_fd(session->proto_channel);
	/* Set Id */
	mydevice = l_queue_find(device_id_list, device_uuid_cmp, session->uuid);
	if (mydevice)
		session->id = strtoull(mydevice->id, NULL, 16);

	result = proto_signin(proto_sock, uuid, token, property_changed,
			      L_INT_TO_PTR(session->node_fd));

	session->rollback = 0; /* Rollback disabled */

	if (result != KNOT_SUCCESS) {
		l_free(session->uuid);
		l_free(session->token);
		session->uuid = NULL;
		session->token = NULL;
		return result;
	}

	session->trusted = true;

	return KNOT_SUCCESS;
}

static int8_t msg_schema(struct session *session,
			 const knot_msg_schema *schema, bool eof)
{
	int proto_sock;
	int8_t result;

	if (!session->trusted) {
		hal_log_info("schema: not authorized!");
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
	if (session->schema_list_tmp == NULL)
		session->schema_list_tmp = l_queue_new();

	if (!schema_find(session->schema_list_tmp, schema->sensor_id))
		l_queue_push_tail(session->schema_list_tmp,
				  l_memdup(schema, sizeof(*schema)));

	if (!eof) {
		result = KNOT_SUCCESS;
		goto done;
	}

	proto_sock = l_io_get_fd(session->proto_channel);
	result = proto_schema(proto_sock, session->uuid,
			      session->token, session->schema_list_tmp);
	if (result != KNOT_SUCCESS) {
		l_queue_destroy(session->schema_list_tmp, l_free);
		session->schema_list_tmp = NULL;
		goto done;
	}

	/* If succeeded: free old schema and use the new one */
	l_queue_destroy(session->schema_list, l_free);
	session->schema_list = session->schema_list_tmp;
	session->schema_list_tmp = NULL;

	/*
	 * For security reason, remove from rollback avoiding clonning attack.
	 * If schema is being sent means that credentals (UUID/token) has been
	 * properly received (registration complete).
	 */
	session->rollback = 0; /* Rollback disabled */

done:
	return result;
}

static int8_t msg_data(struct session *session, const knot_msg_data *kmdata)
{
	const knot_msg_schema *schema;
	const char *json_str;
	json_object *jobj;
	int proto_sock;
	int err;
	int8_t result;
	uint8_t sensor_id;
	uint8_t *sensor_id_ptr;
	/*
	 * Pointer to KNOT data containing header, sensor id
	 * and a primitive KNOT type
	 */
	const knot_data *kdata = &(kmdata->payload);

	if (!session->trusted) {
		hal_log_info("data: Permission denied!");
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	sensor_id = kmdata->sensor_id;
	schema = schema_find(session->schema_list, sensor_id);
	if (!schema) {
		hal_log_info("sensor_id(0x%02x): data type mismatch!",
			     sensor_id);
		return KNOT_INVALID_DATA;
	}

	err = knot_schema_is_valid(schema->values.type_id,
				   schema->values.value_type,
				   schema->values.unit);
	if (err) {
		hal_log_info("sensor_id(0x%d), type_id(0x%04x): unit mismatch!",
			     sensor_id, schema->values.type_id);
		return KNOT_INVALID_DATA;
	}

	hal_log_info("sensor:%d, unit:%d, value_type:%d", sensor_id,
		     schema->values.unit, schema->values.value_type);

	proto_sock = l_io_get_fd(session->proto_channel);
	result = proto_data(proto_sock, session->uuid, session->token,
			    sensor_id, schema->values.value_type, kdata);

	/* Remove pending get data request & update cloud */
	sensor_id_ptr = l_queue_remove_if(session->getdata_list,
			       sensor_id_cmp, L_INT_TO_PTR(sensor_id));
	if (sensor_id_ptr == NULL)
		goto done;

	l_free(sensor_id_ptr);
	/* Updating 'get_data' array at Cloud */
	jobj = parser_sensorid_to_json("get_data", session->getdata_list);
	json_str = json_object_to_json_string(jobj);
	proto_getdata(proto_sock, session->uuid, session->token, json_str);

	json_object_put(jobj);

done:
	return result;
}

static int8_t msg_config_resp(struct session *session,
			      const knot_msg_item *response)
{
	knot_msg_config *config;
	uint8_t sensor_id;

	if (!session->trusted) {
		hal_log_info("config resp: Permission denied!");
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	sensor_id = response->sensor_id;

	/* TODO: Always forward instead of avoid sending repeated configs */
	config = l_queue_remove_if(session->config_list,
				   config_sensor_id_cmp,
				   L_UINT_TO_PTR(sensor_id));
	if (!config)
		return KNOT_INVALID_DATA;

	l_free(config);

	hal_log_info("THING %s received config for sensor %d", session->uuid,
								sensor_id);

	return KNOT_SUCCESS;
}

/*
 * Works like msg_data() (copy & paste), but removes the received info from
 * the 'devices' database.
 */
static int8_t msg_setdata_resp(struct session *session,
			       const knot_msg_data *kmdata)
{
	const knot_msg_schema *schema;
	const char *json_str;
	json_object *jsoarray;
	json_object *jsokey;
	json_object *jso;
	int proto_sock;
	int err;
	uint8_t sensor_id;
	int8_t result;
	/*
	 * Pointer to KNOT data containing header, sensor id
	 * and a primitive KNOT type
	 *
	 * Format to push to cloud:
	 * "set_data" : [
	 *		{"sensor_id": v, "value": w}]
	 */

	const knot_data *kdata = &(kmdata->payload);

	if (!session->trusted) {
		hal_log_info("setdata: Permission denied!");
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	sensor_id = kmdata->sensor_id;
	schema = schema_find(session->schema_list, sensor_id);
	if (!schema) {
		hal_log_info("sensor_id(0x%02x): data type mismatch!",
								sensor_id);
		return KNOT_INVALID_DATA;
	}

	err = knot_schema_is_valid(schema->values.type_id,
				   schema->values.value_type,
				   schema->values.unit);
	if (err) {
		hal_log_info("sensor_id(0x%d), type_id(0x%04x): unit mismatch!",
					sensor_id, schema->values.type_id);
		return KNOT_INVALID_DATA;
	}

	hal_log_info("sensor:%d, unit:%d, value_type:%d", sensor_id,
				schema->values.unit, schema->values.value_type);

	proto_sock = l_io_get_fd(session->proto_channel);
	result = proto_data(proto_sock, session->uuid, session->token,
			    sensor_id, schema->values.value_type, kdata);
	if (result != KNOT_SUCCESS)
		return result;

	hal_log_info("THING %s updated data for sensor %d", session->uuid,
								sensor_id);

	/* Access first entry */
	jso = json_object_array_get_idx(session->setdata_jso, 0);
	if (!jso)
		goto done;

	if(!json_object_object_get_ex(jso, "sensor_id", &jsokey))
		goto done;

	if (json_object_get_type(jsokey) != json_type_int)
		goto done;

	/* Protocol inconsistency */
	if (sensor_id != json_object_get_int(jsokey))
		goto done;

	/* Releasing array entry: Removing first entry  */
	if (json_object_array_del_idx(session->setdata_jso, 0, 1) != 0)
		goto done;

	l_free(session->setdata);
	session->setdata =
		l_strdup(json_object_to_json_string(session->setdata_jso));

	/* Updating 'set_data' array at Cloud */
	jso = json_object_new_object();
	jsoarray = json_tokener_parse(session->setdata);
	json_object_object_add(jso, "set_data", jsoarray);
	json_str = json_object_to_json_string(jso);
	proto_setdata(proto_sock, session->uuid, session->token, json_str);
	json_object_put(jso);

	return KNOT_SUCCESS;

done:
	return result;
}

static int8_t msg_unregister_resp(struct session *session)
{
	struct mydevice *mydevice = l_queue_find(device_id_list,
						 device_uuid_cmp,
						 session->uuid);
	struct knot_device *device = device_get(mydevice->id);

	if (device_forget(device))
		hal_log_info("Proxy for %s removed", mydevice->id);
	else
		hal_log_info("Can't remove proxy for %s" , mydevice->id);

	mydevice = l_queue_remove_if(device_id_list, device_id_cmp,
			mydevice->id);

	device_destroy(mydevice->id);
	mydevice_free(mydevice);

	return KNOT_SUCCESS;
}

static ssize_t msg_process(struct session *session,
				const void *ipdu, size_t ilen,
				void *opdu, size_t omtu)
{
	const knot_msg *kreq = ipdu;
	knot_msg *krsp = opdu;
	uint8_t rtype = 0;
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
		result = msg_register(session, &kreq->reg, ilen, &krsp->cred);
		rtype = KNOT_MSG_REGISTER_RESP;
		if (result != KNOT_SUCCESS)
			break;

		/* Enable downstream after registration & authentication */
		session->downstream_to =
			l_timeout_create_ms(512,
					    downstream_callback,
					    session, NULL);
		break;
	case KNOT_MSG_UNREGISTER_REQ:
		result = msg_unregister(session);
		rtype = KNOT_MSG_UNREGISTER_RESP;
		break;
	case KNOT_MSG_DATA:
		result = msg_data(session, &kreq->data);
		rtype = KNOT_MSG_DATA_RESP;
		break;
	case KNOT_MSG_AUTH_REQ:
		result = msg_auth(session, &kreq->auth);
		rtype = KNOT_MSG_AUTH_RESP;
		if (result != KNOT_SUCCESS)
			break;

		/* Enable downstream after authentication */
		session->downstream_to =
			l_timeout_create_ms(512,
					    downstream_callback,
					    session, NULL);
		break;
	case KNOT_MSG_SCHEMA:
	case KNOT_MSG_SCHEMA_END:
		eof = kreq->hdr.type == KNOT_MSG_SCHEMA_END ? true : false;
		result = msg_schema(session, &kreq->schema, eof);
		rtype = KNOT_MSG_SCHEMA_RESP;
		if (eof)
			rtype = KNOT_MSG_SCHEMA_END_RESP;
		break;
	case KNOT_MSG_CONFIG_RESP:
		result = msg_config_resp(session, &kreq->item);
		/* No octets to be transmitted */
		return 0;
	case KNOT_MSG_DATA_RESP:
		result = msg_setdata_resp(session, &kreq->data);
		return 0;
	case KNOT_MSG_UNREGISTER_RESP:
		result = msg_unregister_resp(session);
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

static void session_proto_disconnected_cb(struct l_io *channel,
					  void *user_data)
{
	struct session *session = user_data;
	struct knot_device *device;
	char id[KNOT_ID_LEN + 1];
	snprintf(id, KNOT_ID_LEN + 1,"%016"PRIx64, session->id);
	device = device_get(id);

	/* Connection to cloud broken */
	if (device)
		device_set_online(device, false);

	/*
	 * This callback gets called when the REMOTE initiates a
	 * disconnection or if an error happens.
	 * In this case, radio transport should be left
	 * connected.
	 */
	if (session->proto_channel) {
		session->proto_channel = NULL;
		l_io_destroy(channel);
	}
}

static struct l_io *create_proto_channel(int proto_sock,
					 struct session *session)
{
	struct l_io *channel;
	struct knot_device *device;
	char id[KNOT_ID_LEN + 1];
	snprintf(id, KNOT_ID_LEN + 1,"%016"PRIx64, session->id);
	device = device_get(id);

	channel = l_io_new(proto_sock);
	if (channel == NULL) {
		hal_log_error("Can't create proto channel");
		return NULL;
	}

	/* Connection to cloud established */
	if (device)
		device_set_online(device, true);

	l_io_set_disconnect_handler(channel,
				    session_proto_disconnected_cb,
				    session_ref(session),
				    NULL);
	return channel;
}

static int session_proto_connect(struct session *session)
{
	int proto_sock;

	proto_sock = proto_connect();
	if (proto_sock < 0) {
		hal_log_info("Cloud connect(): %s(%d)",
			     strerror(-proto_sock), -proto_sock);
		return proto_sock;
	}

	/* Keep one reference to call sign-off */
	session->proto_channel = create_proto_channel(proto_sock, session);

	return 0;
}

static void session_node_disconnected_cb(struct l_io *channel, void *user_data)
{
	struct session *session = user_data;
	struct l_io *proto_channel;
	int proto_sock;

	/* ELL returns -1 when calling l_io_get_fd() at disconnected callback */
	session = l_queue_remove_if(session_list,
				    session_node_fd_cmp,
				    L_INT_TO_PTR(session->node_fd));

	hal_log_info("session(%p) disconnected (node)", session);

	if (session->rollback) {
		msg_unregister(session);
		l_timeout_remove(session->downstream_to);
		session->downstream_to = NULL;

		hal_log_info("Removing %s (rollback)", session->uuid);
	}

	/* Disconnect from fog/cloud */
	if (!session->proto_channel)
		return;

	proto_sock = l_io_get_fd(session->proto_channel);
	proto_close(proto_sock);

	proto_channel = session->proto_channel;
	session->proto_channel = NULL;
	l_io_destroy(proto_channel);

	/* Channel cleanup will be held at disconnect callback */

	session_unref(session);
}

static void session_node_destroy_to(struct l_timeout *timeout,
					    void *user_data)
{
	struct l_io *channel = user_data;

	l_io_destroy(channel);
}

static void on_node_channel_data_error(struct l_io *channel)
{
	static bool destroying = false;

	if (destroying)
		return;

	destroying = true;

	l_timeout_create(1,
			 session_node_destroy_to,
			 channel,
			 NULL);
}

static bool session_node_data_cb(struct l_io *channel, void *user_data)
{
	struct session *session = user_data;
	struct node_ops *node_ops = session->node_ops;
	uint8_t ipdu[512], opdu[512]; /* FIXME: */
	ssize_t recvbytes, sentbytes, olen;
	int node_socket;
	int err;

	node_socket = l_io_get_fd(channel);

	recvbytes = node_ops->recv(node_socket, ipdu, sizeof(ipdu));
	if (recvbytes <= 0) {
		err = errno;
		hal_log_error("readv(): %s(%d)", strerror(err), err);
		on_node_channel_data_error(channel);
		return false;
	}

	if (!session->proto_channel) {
		err = session_proto_connect(session);
		if (err) {
			/* TODO:  missing reply an error */
			hal_log_error("Can't connect to cloud service!");
			on_node_channel_data_error(channel);
			return false;
		}

		hal_log_info("Reconnected to cloud service");
	}

	/* Blocking: Wait until response from cloud is received */
	olen = msg_process(session, ipdu, recvbytes, opdu, sizeof(opdu));
	/* olen: output length or -errno */
	if (olen < 0) {
		/* Server didn't reply any error */
		hal_log_error("KNOT IoT proto error: %s(%zd)",
			      strerror(-olen), -olen);
		on_node_channel_data_error(channel);
		return false;
	}

	/* If there are no octets to be sent */
	if (!olen)
		return true;

	/* Response from the gateway: error or response for the given command */
	sentbytes = node_ops->send(node_socket, opdu, olen);
	if (sentbytes < 0)
		hal_log_error("node_ops: %s(%zd)",
			      strerror(-sentbytes), -sentbytes);

	return true;
}

static struct l_io *create_node_channel(int node_socket,
					struct session *session)
{
	struct l_io *channel;

	channel = l_io_new(node_socket);
	if (channel == NULL) {
		hal_log_error("Can't create node channel");
		return NULL;
	}

	l_io_set_close_on_destroy(channel, true);

	l_io_set_read_handler(channel, session_node_data_cb,
			      session, NULL);
	l_io_set_disconnect_handler(channel,
				    session_node_disconnected_cb,
				    session_ref(session),
				    NULL);

	return channel;
}

static struct session *session_create(struct node_ops *node_ops,
				      int client_socket)
{
	struct session *session;
	int err;

	session = session_new(node_ops);
	err = session_proto_connect(session);
	if (err < 0) {
		session_unref(session);
		return NULL;
	}

	session->node_channel = create_node_channel(client_socket, session);
	session->node_fd = client_socket; /* Required to manage disconnections */

	hal_log_info("node:%p proto:%p",
		     session->node_channel, session->proto_channel);

	return session;
}

static bool session_accept_cb(struct node_ops *node_ops, int client_socket)
{
	struct session *session;

	session = session_create(node_ops, client_socket);
	if (!session) {
		/* FIXME: Stop knotd if cloud if not available */
		return false;
	}

	l_queue_push_head(session_list, session);

	return true;
}

static void forget_if_unknown(struct knot_device *device, void *user_data)
{
	const char *id = device_get_id(device);

	/* device_id_list contains cloud devices */

	if (l_queue_find(device_id_list, device_id_cmp, id))
		return; /* match: belongs to service & cloud */

	hal_log_info("Device %s not found at Cloud", id);

	if (device_forget(device))
		hal_log_info("Proxy for %s removed", id);
	else
		hal_log_info("Can't remove proxy for %s" , id);
}

static void proxy_added(const char *device_id, const char *uuid,
						const char *name, void *user_data)
{
	struct knot_device *device = device_get(device_id);
	struct mydevice *mydevice = l_new(struct mydevice, 1);

	/* Tracks 'proxy' devices that belongs to Cloud. */
	hal_log_info("Device added: %s UUID: %s", device_id, uuid);

	if (!device) {
		/* Ownership belongs to device.c */
		device = device_create(device_id, name, true, true);
		if (!device)
			return;
	}

	device_set_uuid(device, uuid);

	mydevice->uuid = l_strdup(uuid);
	mydevice->id = l_strdup(device_id);
	mydevice->name = l_strdup(name);

	l_queue_push_head(device_id_list, mydevice);
}

static void proxy_removed(const char *device_id, void *user_data)
{
	struct knot_device *device = device_get(device_id);
	struct mydevice *mydevice = l_queue_find(device_id_list,
						 device_id_cmp,
						 device_id);

	/* Tracks 'proxy' devices removed from Cloud. */
	if (device == NULL) {
		/* Other service or created by external apps(eg: ktool) */
		hal_log_error("Device %s not found!", device_id);
		return;
	}

	/* Send unregister request to device */
	if(msg_unregister_req(mydevice)) {
		hal_log_info("Sending unregister message ...");
		return;
	}

	hal_log_info("Unregister message can't be sent!!");

	if (device_forget(device))
		hal_log_info("Proxy for %s removed", mydevice->id);
	else
		hal_log_info("Can't remove proxy for %s" , mydevice->id);

	mydevice = l_queue_remove_if(device_id_list, device_id_cmp,
			mydevice->id);

	device_destroy(mydevice->id);
	mydevice_free(mydevice);
}

static void service_ready(const char *service, void *user_data)
{
	/*
	 * Service proxy objects retrieved from low level service.
	 * Gets called after notifying all ELL client proxies.
	 */
	hal_log_info("Service proxy %s is ready", service);

	/* Step3: Remove if needed. For each service proxy: find at cloud? */
	proxy_foreach(service, forget_if_unknown, NULL);
}

static void proxy_ready(void *user_data)
{
	/*
	 * Sequential: protocol proxy registered, now register service
	 * proxy. At this point, cloud device list is properly retrieved.
	 */

	hal_log_info("Protocol proxy is ready");

	/* Step2: Getting service (device) proxies. eg: nrfd objects  */
	if (proxy_start("br.org.cesar.knot.nrf", NULL,
			"br.org.cesar.knot.nrf.Device1",
			service_ready, user_data) == 0)
		proxy_enabled = true;
}

static void start_timeout(struct l_timeout *timeout, void *user_data)
{
	struct settings *settings = user_data;
	int sock;

	/* FIXME: how to manage disconnection from cloud? */
	sock = proto_connect();
	if (sock < 0)
		goto connect_fail;

	/* 'settings' may be changed by D-Bus interface */
	if (proto_signin(sock, settings->uuid, settings->token,
			 NULL, NULL) != KNOT_SUCCESS)
		goto signin_fail;

	/* Keep a reference to a valid credential */
	owner_uuid = settings->uuid;
	/* Step1: Getting Cloud (device) proxies using owner credential */
	proto_set_proxy_handlers(sock,
				 proxy_added,
				 proxy_removed,
				 proxy_ready,
				 settings);

	/* Last operation: Enable if cloud is connected & authenticated */
	node_start(session_accept_cb);

	return;

signin_fail:
	proto_close(sock);

connect_fail:
	/* Schedule this callback to 5 seconds */
	l_timeout_modify(timeout, 5);
}

int msg_start(struct settings *settings)
{
	int err;

	session_list = l_queue_new();

	err = device_start();
	if (err < 0) {
		hal_log_error("device_start(): %s", strerror(-err));
		return err;
	}

	err = proto_start(settings);
	if (err < 0) {
		hal_log_error("proto_start(): %s", strerror(-err));
		goto proto_fail;
	}

	device_id_list = l_queue_new();
	start_to =  l_timeout_create_ms(1, start_timeout, settings, NULL);

	return (start_to ? 0 : -ENOMEM);

proto_fail:
	device_stop();

	return err;
}

void msg_stop(void)
{
	if (start_to)
		l_timeout_remove(start_to);

	node_stop();
	if (proxy_enabled)
		proxy_stop();
	proto_stop();
	device_stop();

	l_queue_destroy(device_id_list, mydevice_free);

	l_queue_destroy(session_list,
			(l_queue_destroy_func_t) session_unref);
}
