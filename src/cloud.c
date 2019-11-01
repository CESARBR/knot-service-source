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
#include "amqp.h"
#include "parser.h"
#include "cloud.h"

#define AMQP_QUEUE_FOG "fog-messages"
#define AMQP_QUEUE_CLOUD "cloud-messages"

/* Exchanges */
#define AMQP_EXCHANGE_FOG "fog"
#define AMQP_EXCHANGE_CLOUD "cloud"

 /* Southbound traffic (commands) */
#define AMQP_EVENT_DATA_UPDATE "data.update"
#define AMQP_EVENT_DATA_REQUEST "data.request"
#define AMQP_EVENT_DEVICE_REGISTERED "device.registered"
#define AMQP_EVENT_DEVICE_UNREGISTERED "device.unregistered"
#define AMQP_EVENT_DEVICE_AUTH "device.auth"
#define AMQP_EVENT_SCHEMA_UPDATED "schema.updated"
#define AMQP_EVENT_DEVICE_LIST "device.list"

 /* Northbound traffic (control, measurements) */
#define AMQP_CMD_DATA_PUBLISH "data.publish"
#define AMQP_CMD_DEVICE_REGISTER "device.register"
#define AMQP_CMD_DEVICE_UNREGISTER "device.unregister"
#define AMQP_CMD_DEVICE_AUTH "device.cmd.auth"
#define AMQP_CMD_SCHEMA_UPDATE "schema.update"
#define AMQP_CMD_DEVICE_LIST "device.cmd.list"

cloud_cb_t cloud_cb;

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
	if (!strcmp(routing_key, AMQP_EVENT_DATA_UPDATE))
		return UPDATE_MSG;
	else if (!strcmp(routing_key, AMQP_EVENT_DATA_REQUEST))
		return REQUEST_MSG;
	else if (!strcmp(routing_key, AMQP_EVENT_DEVICE_REGISTERED))
		return REGISTER_MSG;
	else if (!strcmp(routing_key, AMQP_EVENT_DEVICE_UNREGISTERED))
		return UNREGISTER_MSG;
	else if (!strcmp(routing_key, AMQP_EVENT_DEVICE_AUTH))
		return AUTH_MSG;
	else if (!strcmp(routing_key, AMQP_EVENT_SCHEMA_UPDATED))
		return SCHEMA_MSG;
	else if (!strcmp(routing_key, AMQP_EVENT_DEVICE_LIST))
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
		msg->device_id = parser_get_key_str_from_json_obj(jso, "id");
		msg->list = parser_update_to_list(jso);
		if (!msg->device_id || !msg->list) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

		break;
	case REQUEST_MSG:
		msg->device_id = parser_get_key_str_from_json_obj(jso, "id");
		msg->list = parser_request_to_list(jso);
		if (!msg->device_id || !msg->list) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

		break;
	case REGISTER_MSG:
		msg->device_id = parser_get_key_str_from_json_obj(jso, "id");
		msg->token = parser_get_key_str_from_json_obj(jso, "token");
		if (!msg->device_id || !msg->token) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

		break;
	case UNREGISTER_MSG:
		msg->device_id = parser_get_key_str_from_json_obj(jso, "id");
		if (!msg->device_id) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

		break;
	case AUTH_MSG:
		msg->device_id = parser_get_key_str_from_json_obj(jso, "id");
		msg->auth = parser_get_key_bool_from_json_obj(jso,
							      "authenticated");
		if (!msg->device_id || msg->auth < 0) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

		break;
	case SCHEMA_MSG:
		msg->device_id = parser_get_key_str_from_json_obj(jso, "id");
		if (!msg->device_id) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

		msg->error = parser_get_key_str_from_json_obj(jso, "error");
		break;
	case LIST_MSG:
		msg->device_id = NULL;
		msg->list = parser_queue_from_json_array(jso,
						cloud_device_array_foreach);
		if (!msg->list) {
			hal_log_error("Malformed JSON message");
			goto err;
		}

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

	queue_cloud = amqp_declare_new_queue(AMQP_QUEUE_CLOUD);
	if (!queue_cloud.bytes) {
		hal_log_error("Error on declare a new queue.\n");
		return -1;
	}

	jobj_device = parser_device_json_create(id, name);
	json_str = json_object_to_json_string(jobj_device);

	result = amqp_publish_persistent_message(queue_cloud,
						 AMQP_EXCHANGE_CLOUD,
						 AMQP_CMD_DEVICE_REGISTER,
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
	json_object *jobj;
	const char *json_str;
	int result;

	queue_cloud = amqp_declare_new_queue(AMQP_QUEUE_CLOUD);
	if (!queue_cloud.bytes) {
		hal_log_error("Error on declare a new queue.\n");
		return -1;
	}

	jobj = json_object_new_object();
	json_object_object_add(jobj, "id", json_object_new_string(id));
	json_str = json_object_to_json_string(jobj);

	result = amqp_publish_persistent_message(queue_cloud,
		AMQP_EXCHANGE_CLOUD, AMQP_CMD_DEVICE_UNREGISTER, json_str);
	if (result < 0)
		return KNOT_ERR_CLOUD_FAILURE;

	json_object_put(jobj);
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
	json_object *jobj_device;
	const char *json_str;
	int result;

	queue_cloud = amqp_declare_new_queue(AMQP_QUEUE_CLOUD);
	if (queue_cloud.bytes == NULL) {
		hal_log_error("Error on declare a new queue.\n");
		return -1;
	}

	jobj_device = parser_auth_json_create(id, token);
	json_str = json_object_to_json_string(jobj_device);

	result = amqp_publish_persistent_message(queue_cloud,
						 AMQP_EXCHANGE_CLOUD,
						 AMQP_CMD_DEVICE_AUTH,
						 json_str);
	if (result < 0)
		result = KNOT_ERR_CLOUD_FAILURE;

	json_object_put(jobj_device);
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

	queue_cloud = amqp_declare_new_queue(AMQP_QUEUE_CLOUD);
	if (!queue_cloud.bytes) {
		hal_log_error("Error on declare a new queue.\n");
		return -1;
	}

	jobj_schema = parser_schema_create_object(id, schema_list);
	json_str = json_object_to_json_string(jobj_schema);

	result = amqp_publish_persistent_message(queue_cloud,
						 AMQP_EXCHANGE_CLOUD,
						 AMQP_CMD_SCHEMA_UPDATE,
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

	queue_cloud = amqp_declare_new_queue(AMQP_QUEUE_CLOUD);
	if (!queue_cloud.bytes) {
		hal_log_error("Error on declare a new queue.\n");
		return -1;
	}

	jobj_empty = json_object_new_object();
	json_str = json_object_to_json_string(jobj_empty);

	result = amqp_publish_persistent_message(queue_cloud,
						 AMQP_EXCHANGE_CLOUD,
						 AMQP_CMD_DEVICE_LIST,
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

	jobj_data = parser_data_create_object(id, sensor_id, value_type, value,
				       kval_len);
	json_str = json_object_to_json_string(jobj_data);

	queue_cloud = amqp_declare_new_queue(AMQP_QUEUE_CLOUD);
	if (!queue_cloud.bytes) {
		hal_log_error("Error on declare a new queue.\n");
		return -1;
	}

	result = amqp_publish_persistent_message(queue_cloud,
						 AMQP_EXCHANGE_CLOUD,
						 AMQP_CMD_DATA_PUBLISH,
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
		AMQP_EVENT_DATA_UPDATE,
		AMQP_EVENT_DATA_REQUEST,
		AMQP_EVENT_DEVICE_REGISTERED,
		AMQP_EVENT_DEVICE_UNREGISTERED,
		AMQP_EVENT_DEVICE_AUTH,
		AMQP_EVENT_SCHEMA_UPDATED,
		AMQP_EVENT_DEVICE_LIST,
		NULL
	};
	amqp_bytes_t queue_fog;
	int err, i;

	cloud_cb = read_handler;

	queue_fog = amqp_declare_new_queue(AMQP_QUEUE_FOG);
	if (queue_fog.bytes == NULL) {
		hal_log_error("Error on declare a new queue.\n");
		return -1;
	}

	for (i = 0; fog_events[i] != NULL; i++) {
		err = amqp_set_queue_to_consume(queue_fog, AMQP_EXCHANGE_FOG,
						fog_events[i]);
		if (err) {
			hal_log_error("Error on set up queue to consume.\n");
			amqp_bytes_free(queue_fog);
			return -1;
		}
	}

	amqp_bytes_free(queue_fog);

	err = amqp_set_read_cb(on_cloud_receive_message, user_data);
	if (err) {
		hal_log_error("Error on set up read callback\n");
		return -1;
	}

	return 0;
}

int cloud_start(struct settings *settings, cloud_connected_cb_t connected_cb,
		void *user_data)
{
	return amqp_start(settings, connected_cb, user_data);
}

void cloud_stop(void)
{
	amqp_stop();
}
