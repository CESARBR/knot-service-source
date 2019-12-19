/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2019, CESAR. All rights reserved.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <stdint.h>
#include <ell/ell.h>
#include <json-c/json.h>
#include <hal/linux_log.h>
#include <amqp.h>

#include <knot/knot_protocol.h>

#include "settings.h"
#include "mq.h"
#include "parser.h"
#include "cloud.h"

#define MQ_QUEUE_FOG "connOut-messages"
#define MQ_QUEUE_CLOUD "connIn-messages"

/* Exchanges */
#define MQ_EXCHANGE_FOG "connOut"
#define MQ_EXCHANGE_CLOUD "connIn"

/* Headers */
#define MQ_AUTHORIZATION_HEADER "Authorization"

#define MQ_MSG_EXPIRATION_TIME_MS 2000

 /* Southbound traffic (commands) */
#define MQ_EVENT_DATA_UPDATE "data.update"
#define MQ_EVENT_DATA_REQUEST "data.request"
#define MQ_EVENT_DEVICE_REGISTERED "device.registered"
#define MQ_EVENT_DEVICE_UNREGISTERED "device.unregistered"
#define MQ_EVENT_DEVICE_AUTH "device.auth"
#define MQ_EVENT_SCHEMA_UPDATED "schema.updated"
#define MQ_EVENT_DEVICE_LIST "device.list"

 /* Northbound traffic (control, measurements) */
#define MQ_CMD_DATA_PUBLISH "data.publish"
#define MQ_CMD_DEVICE_REGISTER "device.register"
#define MQ_CMD_DEVICE_UNREGISTER "device.unregister"
#define MQ_CMD_DEVICE_AUTH "device.cmd.auth"
#define MQ_CMD_SCHEMA_UPDATE "schema.update"
#define MQ_CMD_DEVICE_LIST "device.cmd.list"

cloud_cb_t cloud_cb;
struct settings *conf;
amqp_table_entry_t headers[1];

static void cloud_device_free(void *data)
{
	struct cloud_device *mydevice = data;

	if (unlikely(!mydevice))
		return;

	l_queue_destroy(mydevice->schema, l_free);
	l_free(mydevice->id);
	l_free(mydevice->uuid);
	l_free(mydevice->name);
	l_free(mydevice);
}

static void cloud_msg_destroy(struct cloud_msg *msg)
{
	if (msg->type == LIST_MSG)
		l_queue_destroy(msg->list, cloud_device_free);
	else if (msg->type == UPDATE_MSG || msg->type == REQUEST_MSG)
		l_queue_destroy(msg->list, l_free);

	l_free(msg);
}

static int map_routing_key_to_msg_type(const char *routing_key)
{
	if (!strcmp(routing_key, MQ_EVENT_DATA_UPDATE))
		return UPDATE_MSG;
	else if (!strcmp(routing_key, MQ_EVENT_DATA_REQUEST))
		return REQUEST_MSG;
	else if (!strcmp(routing_key, MQ_EVENT_DEVICE_REGISTERED))
		return REGISTER_MSG;
	else if (!strcmp(routing_key, MQ_EVENT_DEVICE_UNREGISTERED))
		return UNREGISTER_MSG;
	else if (!strcmp(routing_key, MQ_EVENT_DEVICE_AUTH))
		return AUTH_MSG;
	else if (!strcmp(routing_key, MQ_EVENT_SCHEMA_UPDATED))
		return SCHEMA_MSG;
	else if (!strcmp(routing_key, MQ_EVENT_DEVICE_LIST))
		return LIST_MSG;
	return -1;
}

static void *cloud_device_array_foreach(json_object *array_item)
{
	json_object *jobjkey;
	struct cloud_device *mydevice;
	struct l_queue *schema;
	const char *id, *name;

	/* Getting 'Id': Mandatory field for registered device */
	id = parser_get_key_str_from_json_obj(array_item, "id");
	if (!id)
		return NULL;

	/* Getting 'schema': Mandatory field for registered device */
	if (!json_object_object_get_ex(array_item, "schema", &jobjkey))
		return NULL;

	schema = parser_schema_to_list(json_object_to_json_string(jobjkey));
	if (!schema)
		return NULL;

	/* Getting 'Name' */
	name = parser_get_key_str_from_json_obj(array_item, "name");
	if (!name)
		return NULL;

	mydevice = l_new(struct cloud_device, 1);
	mydevice->id = l_strdup(id);
	mydevice->name = l_strdup(name);
	mydevice->uuid = l_strdup(id);
	mydevice->schema = schema;

	return mydevice;
}

static struct cloud_msg *create_msg(const char *routing_key, json_object *jso)
{
	struct cloud_msg *msg = l_new(struct cloud_msg, 1);

	msg->type = map_routing_key_to_msg_type(routing_key);

	switch (msg->type) {
	case UPDATE_MSG:
		msg->error = NULL;
		msg->device_id = parser_get_key_str_from_json_obj(jso, "id");
		if (!msg->device_id) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

		msg->list = parser_update_to_list(jso);
		if (!msg->list) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

		break;
	case REQUEST_MSG:
		msg->error = NULL;
		msg->device_id = parser_get_key_str_from_json_obj(jso, "id");
		if (!msg->device_id) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

		msg->list = parser_request_to_list(jso);
		if (!msg->list) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

		break;
	case REGISTER_MSG:
		msg->device_id = parser_get_key_str_from_json_obj(jso, "id");
		if (!msg->device_id ||
				!parser_is_key_str_or_null(jso, "error")) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

		msg->token = parser_get_key_str_from_json_obj(jso, "token");
		if (!msg->token) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

		msg->error = parser_get_key_str_from_json_obj(jso, "error");
		break;
	case UNREGISTER_MSG:
		msg->device_id = parser_get_key_str_from_json_obj(jso, "id");
		if (!msg->device_id ||
				!parser_is_key_str_or_null(jso, "error")) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

		msg->error = parser_get_key_str_from_json_obj(jso, "error");
		break;
	case AUTH_MSG:
		msg->device_id = parser_get_key_str_from_json_obj(jso, "id");
		if (!msg->device_id ||
				!parser_is_key_str_or_null(jso, "error")) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

		msg->error = parser_get_key_str_from_json_obj(jso, "error");
		break;
	case SCHEMA_MSG:
		msg->device_id = parser_get_key_str_from_json_obj(jso, "id");
		if (!msg->device_id ||
				!parser_is_key_str_or_null(jso, "error")) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

		msg->error = parser_get_key_str_from_json_obj(jso, "error");
		break;
	case LIST_MSG:
		msg->device_id = NULL;
		msg->list = parser_queue_from_json_array(jso,
						cloud_device_array_foreach);
		if (!msg->list || !parser_is_key_str_or_null(jso, "error")) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

		msg->error = parser_get_key_str_from_json_obj(jso, "error");
		break;
	default:
		hal_log_error("Unknown event %s", routing_key);
		goto err;
	}

	return msg;
err:
	cloud_msg_destroy(msg);
	return NULL;
}

/**
 * Callback function to consume and parse the received message from AMQP queue
 * and call the respective handling callback function. In case of a error on
 * parse, the message is consumed, but not used.
 *
 * Returns true if the message envelope was consumed or returns false otherwise.
 */
static bool on_cloud_receive_message(const char *exchange,
				     const char *routing_key,
				     const char *body, void *user_data)
{
	struct cloud_msg *msg;
	bool consumed = true;
	json_object *jso;

	jso = json_tokener_parse(body);
	if (!jso) {
		hal_log_error("Error on parse JSON object");
		return false;
	}

	msg = create_msg(routing_key, jso);
	if (msg) {
		consumed = cloud_cb(msg, user_data);
		cloud_msg_destroy(msg);
	}

	json_object_put(jso);

	return consumed;
}

/**
 * cloud_register_device:
 * @id: device id
 * @name: device name
 *
 * Requests cloud to add a device.
 * The confirmation that the cloud received the message comes from a callback
 * set in function cloud_set_read_handler with message type REGISTER_MSG.
 *
 * Returns: 0 if successful and a KNoT error otherwise.
 */
int cloud_register_device(const char *id, const char *name)
{
	amqp_bytes_t queue_cloud;
	json_object *jobj_device;
	const char *json_str;
	int result;

	queue_cloud = mq_declare_new_queue(MQ_QUEUE_CLOUD);
	if (!queue_cloud.bytes) {
		hal_log_error("Error on declare a new queue.\n");
		return -1;
	}

	jobj_device = parser_device_json_create(id, name);
	if (!jobj_device) {
		amqp_bytes_free(queue_cloud);
		return KNOT_ERR_CLOUD_FAILURE;
	}
	json_str = json_object_to_json_string(jobj_device);

	headers[0].value.value.bytes = amqp_cstring_bytes(conf->token);

	result = mq_publish_persistent_message(queue_cloud,
					       MQ_EXCHANGE_CLOUD,
					       MQ_CMD_DEVICE_REGISTER,
					       headers, 1,
					       MQ_MSG_EXPIRATION_TIME_MS,
					       json_str);
	if (result < 0)
		result = KNOT_ERR_CLOUD_FAILURE;

	json_object_put(jobj_device);
	amqp_bytes_free(queue_cloud);

	return result;
}

/**
 * cloud_unregister_device:
 * @id: device id
 *
 * Requests cloud to remove a device.
 * The confirmation that the cloud received the message comes from a callback
 * set in function cloud_set_read_handler  with message type UNREGISTER_MSG.
 *
 * Returns: 0 if successful and a KNoT error otherwise.
 */
int cloud_unregister_device(const char *id)
{
	amqp_bytes_t queue_cloud;
	json_object *jobj_unreg;
	const char *json_str;
	int result;

	queue_cloud = mq_declare_new_queue(MQ_QUEUE_CLOUD);
	if (!queue_cloud.bytes) {
		hal_log_error("Error on declare a new queue.\n");
		return -1;
	}

	jobj_unreg = parser_unregister_json_create(id);
	if (!jobj_unreg) {
		amqp_bytes_free(queue_cloud);
		return KNOT_ERR_CLOUD_FAILURE;
	}
	json_str = json_object_to_json_string(jobj_unreg);

	headers[0].value.value.bytes = amqp_cstring_bytes(conf->token);

	result = mq_publish_persistent_message(queue_cloud,
					       MQ_EXCHANGE_CLOUD,
					       MQ_CMD_DEVICE_UNREGISTER,
					       headers, 1,
					       MQ_MSG_EXPIRATION_TIME_MS,
					       json_str);
	if (result < 0)
		return KNOT_ERR_CLOUD_FAILURE;

	json_object_put(jobj_unreg);
	amqp_bytes_free(queue_cloud);

	return 0;
}

/**
 * cloud_auth_device:
 * @id: device id
 * @token: device token
 *
 * Requests cloud to auth a device.
 * The confirmation that the cloud received the message comes from a callback
 * set in function cloud_set_read_handler.
 *
 * Returns: 0 if successful and a KNoT error otherwise.
 */
int cloud_auth_device(const char *id, const char *token)
{
	amqp_bytes_t queue_cloud;
	json_object *jobj_auth;
	const char *json_str;
	int result;

	queue_cloud = mq_declare_new_queue(MQ_QUEUE_CLOUD);
	if (queue_cloud.bytes == NULL) {
		hal_log_error("Error on declare a new queue.\n");
		return -1;
	}

	jobj_auth = parser_auth_json_create(id, token);
	if (!jobj_auth) {
		amqp_bytes_free(queue_cloud);
		return KNOT_ERR_CLOUD_FAILURE;
	}
	json_str = json_object_to_json_string(jobj_auth);

	headers[0].value.value.bytes = amqp_cstring_bytes(conf->token);

	result = mq_publish_persistent_message(queue_cloud,
					       MQ_EXCHANGE_CLOUD,
					       MQ_CMD_DEVICE_AUTH,
					       headers, 1,
					       0, // Set no expiration time
					       json_str);
	if (result < 0)
		result = KNOT_ERR_CLOUD_FAILURE;

	json_object_put(jobj_auth);
	amqp_bytes_free(queue_cloud);

	return result;
}

/**
 * cloud_update_schema:
 *
 * Requests cloud to update the device schema.
 * The confirmation that the cloud received the message comes from a callback
 * set in function cloud_set_read_handler with message type SCHEMA_MSG.
 *
 * Returns: 0 if successful and a KNoT error otherwise.
 */
int cloud_update_schema(const char *id, struct l_queue *schema_list)
{
	amqp_bytes_t queue_cloud;
	json_object *jobj_schema;
	const char *json_str;
	int result;

	queue_cloud = mq_declare_new_queue(MQ_QUEUE_CLOUD);
	if (!queue_cloud.bytes) {
		hal_log_error("Error on declare a new queue.\n");
		return -1;
	}

	jobj_schema = parser_schema_create_object(id, schema_list);
	if (!jobj_schema) {
		amqp_bytes_free(queue_cloud);
		return KNOT_ERR_CLOUD_FAILURE;
	}
	json_str = json_object_to_json_string(jobj_schema);

	headers[0].value.value.bytes = amqp_cstring_bytes(conf->token);

	result = mq_publish_persistent_message(queue_cloud,
					       MQ_EXCHANGE_CLOUD,
					       MQ_CMD_SCHEMA_UPDATE,
					       headers, 1,
					       MQ_MSG_EXPIRATION_TIME_MS,
					       json_str);
	if (result < 0)
		result = KNOT_ERR_CLOUD_FAILURE;

	json_object_put(jobj_schema);
	amqp_bytes_free(queue_cloud);

	return result;
}

/**
 * cloud_list_devices:
 *
 * Requests cloud to list the devices from the gateway.
 * The confirmation that the cloud received the message comes from a callback
 * set in function cloud_set_read_handler with message type LIST_MSG.
 *
 * Returns: 0 if successful and a KNoT error otherwise.
 */
int cloud_list_devices(void)
{
	amqp_bytes_t queue_cloud;
	json_object *jobj_empty;
	const char *json_str;
	int result;

	queue_cloud = mq_declare_new_queue(MQ_QUEUE_CLOUD);
	if (!queue_cloud.bytes) {
		hal_log_error("Error on declare a new queue.\n");
		return -1;
	}

	jobj_empty = json_object_new_object();
	json_str = json_object_to_json_string(jobj_empty);

	headers[0].value.value.bytes = amqp_cstring_bytes(conf->token);

	result = mq_publish_persistent_message(queue_cloud,
					       MQ_EXCHANGE_CLOUD,
					       MQ_CMD_DEVICE_LIST,
					       headers, 1,
					       0, // Set no expiration time
					       json_str);
	if (result < 0)
		result = KNOT_ERR_CLOUD_FAILURE;

	json_object_put(jobj_empty);
	amqp_bytes_free(queue_cloud);

	return result;
}

/**
 * cloud_publish_data:
 * @id: device id
 * @sensor_id: schema sensor id
 * @value_type: schema value type defined in KNoT protocol
 * @value: value to be sent
 * @kval_len: length of @value
 *
 * Sends device's data to cloud.
 *
 * Returns: 0 if successful and a KNoT error otherwise.
 */
int cloud_publish_data(const char *id, uint8_t sensor_id, uint8_t value_type,
		       const knot_value_type *value,
		       uint8_t kval_len)
{
	amqp_bytes_t queue_cloud;
	json_object *jobj_data;
	const char *json_str;
	int result;

	queue_cloud = mq_declare_new_queue(MQ_QUEUE_CLOUD);
	if (!queue_cloud.bytes) {
		hal_log_error("Error on declare a new queue.\n");
		return -1;
	}

	jobj_data = parser_data_create_object(id, sensor_id, value_type, value,
					      kval_len);
	if (!jobj_data) {
		amqp_bytes_free(queue_cloud);
		return KNOT_ERR_CLOUD_FAILURE;
	}
	json_str = json_object_to_json_string(jobj_data);

	headers[0].value.value.bytes = amqp_cstring_bytes(conf->token);

	result = mq_publish_persistent_message(queue_cloud,
					       MQ_EXCHANGE_CLOUD,
					       MQ_CMD_DATA_PUBLISH,
					       headers, 1,
					       MQ_MSG_EXPIRATION_TIME_MS,
					       json_str);
	if (result < 0)
		result = KNOT_ERR_CLOUD_FAILURE;

	json_object_put(jobj_data);
	amqp_bytes_free(queue_cloud);
	return result;
}

/**
 * cloud_set_read_handler:
 * @cb: callback to handle message received from cloud
 * @user_data: user data provided to callbacks
 *
 * Set callback handler when receive cloud messages.
 *
 * Returns: 0 if successful and -1 otherwise.
 */
int cloud_set_read_handler(cloud_cb_t read_handler, void *user_data)
{
	const char *fog_events[] = {
		MQ_EVENT_DATA_UPDATE,
		MQ_EVENT_DATA_REQUEST,
		MQ_EVENT_DEVICE_REGISTERED,
		MQ_EVENT_DEVICE_UNREGISTERED,
		MQ_EVENT_DEVICE_AUTH,
		MQ_EVENT_SCHEMA_UPDATED,
		MQ_EVENT_DEVICE_LIST,
		NULL
	};
	amqp_bytes_t queue_fog;
	int err, i;

	cloud_cb = read_handler;

	queue_fog = mq_declare_new_queue(MQ_QUEUE_FOG);
	if (queue_fog.bytes == NULL) {
		hal_log_error("Error on declare a new queue.\n");
		return -1;
	}

	for (i = 0; fog_events[i] != NULL; i++) {
		err = mq_bind_queue(queue_fog, MQ_EXCHANGE_FOG, fog_events[i]);
		if (err) {
			hal_log_error("Error on set up queue to consume.\n");
			amqp_bytes_free(queue_fog);
			return -1;
		}
	}

	err = mq_set_read_cb(queue_fog, on_cloud_receive_message, user_data);
	if (err) {
		hal_log_error("Error on set up read callback\n");
		return -1;
	}
	amqp_bytes_free(queue_fog);

	return 0;
}

int cloud_start(struct settings *settings, cloud_connected_cb_t connected_cb,
		void *user_data)
{
	conf = settings;
	headers[0].key = amqp_cstring_bytes(MQ_AUTHORIZATION_HEADER);
	headers[0].value.kind = AMQP_FIELD_KIND_UTF8;
	headers[0].value.value.bytes = amqp_cstring_bytes(settings->token);

	return mq_start(settings, connected_cb, user_data);
}

void cloud_stop(void)
{
	mq_stop();
}
