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

/* Exchanges */
#define AMQP_EXCHANGE_FOG "fog"
#define AMQP_EXCHANGE_CLOUD "cloud"

 /* Southbound traffic (commands) */
#define AMQP_EVENT_DATA_UPDATE "data.update"
#define AMQP_EVENT_DATA_REQUEST "data.request"
#define AMQP_EVENT_DEVICE_REGISTERED "device.registered"
#define AMQP_EVENT_DEVICE_UNREGISTERED "device.unregistered"

 /* Northbound traffic (control, measurements) */
#define AMQP_CMD_DATA_PUBLISH "data.publish"
#define AMQP_CMD_DEVICE_REGISTER "device.register"
#define AMQP_CMD_DEVICE_UNREGISTER "device.unregister"

/* Hashmap to user callback from southbound traffic */
static struct l_hashmap *map_event_to_cb;

/* Union with all cloud callbacks */
union cloud_cb_t {
	cloud_downstream_cb_t update_cb;
	cloud_downstream_cb_t request_cb;
	cloud_device_added_cb_t added_cb;
	cloud_device_removed_cb_t removed_cb;
};

/* Struct that has a callback #cb that handle event in #event_id */
struct event_handler {
	void *cb;
	enum {
		UPDATE_EVT,
		REQUEST_EVT,
		ADDED_EVT,
		REMOVED_EVT,
	} event_id;
};

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
	json_object *jso;
	struct l_queue *list;
	const char *id, *token;
	bool consumed = true;
	const struct event_handler *evt_handler;
	union cloud_cb_t cb_handler;

	evt_handler = l_hashmap_lookup(map_event_to_cb, routing_key);
	if (!evt_handler) {
		hal_log_error("Error cb handler not set");
		return false;
	}

	jso = json_tokener_parse(body);
	if (!jso) {
		hal_log_error("Error on parse JSON object");
		return consumed;
	}

	switch (evt_handler->event_id) {
	case UPDATE_EVT:
		cb_handler.update_cb = evt_handler->cb;
		id = parser_get_key_str_from_json_obj(jso, "id");
		list = parser_update_to_list(jso);
		if (!id || !list) {
			hal_log_error("Malformed JSON message");
			l_queue_destroy(list, l_free);
			break;
		}

		consumed = cb_handler.update_cb(id, list, user_data);
		l_queue_destroy(list, l_free);
		break;
	case REQUEST_EVT:
		cb_handler.request_cb = evt_handler->cb;
		id = parser_get_key_str_from_json_obj(jso, "id");
		list = parser_request_to_list(jso);
		if (!id || !list) {
			hal_log_error("Malformed JSON message");
			break;
		}

		consumed = cb_handler.request_cb(id, list, user_data);
		l_queue_destroy(list, l_free);
		break;
	case ADDED_EVT:
		cb_handler.added_cb = evt_handler->cb;
		id = parser_get_key_str_from_json_obj(jso, "id");
		token = parser_get_key_str_from_json_obj(jso, "token");
		if (!id || !token)
			return false;

		cb_handler.added_cb(id, token, user_data);
		break;
	case REMOVED_EVT:
		cb_handler.removed_cb = evt_handler->cb;
		id = parser_get_key_str_from_json_obj(jso, "id");
		if (!id) {
			hal_log_error("Malformed JSON message");
			break;
		}

		cb_handler.removed_cb(id, user_data);
		break;
	default:
		hal_log_error("Unknown event %s", routing_key);
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
 * set in function cloud_set_read_handlers.
 *
 * Returns: 0 if successful and a KNoT error otherwise.
 */
int cloud_register_device(const char *id, const char *name)
{
	json_object *jobj_device;
	const char *json_str;
	int result;

	jobj_device = parser_device_json_create(id, name);
	json_str = json_object_to_json_string(jobj_device);
	result = amqp_publish_persistent_message(AMQP_EXCHANGE_CLOUD,
						 AMQP_CMD_DEVICE_REGISTER,
						 json_str);
	if (result < 0)
		result = KNOT_ERR_CLOUD_FAILURE;

	json_object_put(jobj_device);

	return result;
}

/**
 * cloud_unregister_device:
 * @id: device id
 *
 * Requests cloud to remove a device.
 * The confirmation that the cloud received the message comes from a callback
 * set in function cloud_set_read_handlers.
 *
 * Returns: 0 if successful and a KNoT error otherwise.
 */
int cloud_unregister_device(const char *id)
{
	json_object *jobj;
	const char *json_str;
	int result;

	jobj = json_object_new_object();
	json_object_object_add(jobj, "id", json_object_new_string(id));
	json_str = json_object_to_json_string(jobj);

	result = amqp_publish_persistent_message(
		AMQP_EXCHANGE_CLOUD, AMQP_CMD_DEVICE_UNREGISTER, json_str);
	if (result < 0)
		return KNOT_ERR_CLOUD_FAILURE;

	json_object_put(jobj);

	return 0;
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
	json_object *jobj_data;
	const char *json_str;
	int result;

	jobj_data = parser_data_create_object(id, sensor_id, value_type, value,
				       kval_len);
	json_str = json_object_to_json_string(jobj_data);
	result = amqp_publish_persistent_message(AMQP_EXCHANGE_CLOUD,
						 AMQP_CMD_DATA_PUBLISH,
						 json_str);
	if (result < 0)
		result = KNOT_ERR_CLOUD_FAILURE;

	json_object_put(jobj_data);
	return result;
}

/**
 * cloud_set_read_handlers:
 * @on_update: callback to be called when receive an update message
 * @on_request: callback to be called when receive an request message
 * @on_removed: callback to be called when device is removed
 * @user_data: user data provided to callbacks
 *
 * Set callback handlers when receive cloud messages.
 *
 * Returns: 0 if successful and -1 otherwise.
 */
int cloud_set_read_handlers(cloud_downstream_cb_t on_update,
		  cloud_downstream_cb_t on_request,
		  cloud_device_added_cb_t on_added,
		  cloud_device_removed_cb_t on_removed,
		  void *user_data)
{
	const char *fog_events[] = {
		AMQP_EVENT_DATA_UPDATE,
		AMQP_EVENT_DATA_REQUEST,
		AMQP_EVENT_DEVICE_REGISTERED,
		AMQP_EVENT_DEVICE_UNREGISTERED,
		NULL
	};
	const struct event_handler handlers[] = {
		{ .cb = on_update, .event_id = UPDATE_EVT },
		{ .cb = on_request, .event_id = REQUEST_EVT },
		{ .cb = on_added, .event_id = ADDED_EVT },
		{ .cb = on_removed, .event_id = REMOVED_EVT },
	};
	amqp_bytes_t queue_fog;
	int err, i;

	map_event_to_cb = l_hashmap_string_new();

	queue_fog = amqp_declare_new_queue(AMQP_QUEUE_FOG);
	if (queue_fog.bytes == NULL) {
		hal_log_error("Error on declare a new queue.\n");
		return -1;
	}

	for (i = 0; fog_events[i] != NULL; i++) {
		if (handlers[i].cb)
			l_hashmap_insert(map_event_to_cb, fog_events[i],
					 l_memdup(handlers + i,
						  sizeof(handlers[i])));
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

int cloud_start(struct settings *settings)
{
	return amqp_start(settings);
}

void cloud_stop(void)
{
	l_hashmap_destroy(map_event_to_cb, l_free);
	amqp_stop();
}
