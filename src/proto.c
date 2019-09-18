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
#include <knot/knot_types.h>
#include <knot/knot_protocol.h>
#include <hal/linux_log.h>

#include "settings.h"
#include "parser.h"
#include "proto.h"

extern struct proto_ops proto_ws;
extern struct proto_ops proto_socketio;

static struct proto_ops *proto_ops[] = {
	&proto_ws,
	&proto_socketio,
	NULL
};

struct proto_proxy {
	int sock;			/* Cloud connection */
	proto_proxy_added_func_t added_cb;
	proto_proxy_ready_func_t ready_cb; /* Call only once */
	bool ready_once;
	void *user_data;
	struct l_queue *device_list; /* mydevice */
};

static struct proto_ops *proto = NULL; /* Selected protocol */
static struct l_timeout *timeout;
static struct proto_proxy *proxy;

static void mydevice_free(struct mydevice *mydevice)
{
	if (unlikely(!mydevice))
		return;

	l_free(mydevice->id);
	l_free(mydevice->uuid);
	l_free(mydevice->name);
	l_free(mydevice);
}

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

static bool device_id_cmp(const void *a, const void *b)
{
	const struct mydevice *mydevice1 = a;
	const struct mydevice *mydevice2 = b;

	return strcmp(mydevice1->id, mydevice2->id) == 0 ? true:false;
}

static void timeout_callback(struct l_timeout *timeout, void *user_data)
{
	struct proto_proxy *proxy = user_data;
	struct l_queue *list;
	struct l_queue *added_list;
	struct l_queue *registered_list;
	struct mydevice *mydevice1;
	struct mydevice *mydevice2;
	json_raw_t json;
	int err;

	/* Fetch all devices from cloud */
	memset(&json, 0, sizeof(json));
	err = proto->fetch(proxy->sock, NULL, NULL, &json);
	if (err < 0)
		hal_log_error("fetch(): %s(%d)", strerror(-err), -err);

	if (json.size == 0)
		goto done;

	/* List containing all devices returned from cloud */
	list = parser_mydevices_to_list(json.data);

	added_list = l_queue_new();
	registered_list = l_queue_new();

	/*
	 * Detecting added devices. At the END of the loop:
	 * device_list: contains removed from cloud
	 * registered_list: all devices read from cloud
	 * added_list: new devices at cloud
	 */
	for (mydevice1 = l_queue_pop_head(list);
	     mydevice1; mydevice1 = l_queue_pop_head(list)) {
		mydevice2 = l_queue_remove_if(proxy->device_list,
					 device_id_cmp, mydevice1);

		if (mydevice2 == NULL) {
			/* New device */
			l_queue_push_tail(registered_list, mydevice1);
			l_queue_push_tail(added_list,
					  l_memdup(mydevice1, sizeof(*mydevice1)));
		} else { /* Still registered */
			l_queue_push_tail(registered_list, mydevice2);
			mydevice_free(mydevice1);
		}
	}

	/* list is empty: destroy */
	l_queue_destroy(list, NULL);
	l_queue_destroy(proxy->device_list, NULL);

	/* Informing added devices */
	for (mydevice1 = l_queue_pop_head(added_list);
	     mydevice1; mydevice1 = l_queue_pop_head(added_list)) {
		proxy->added_cb(mydevice1->id, mydevice1->uuid, mydevice1->name,
				mydevice1->online, proxy->user_data);
	}

	l_queue_destroy(added_list, (l_queue_destroy_func_t) mydevice_free);
	/* Overwrite: Keep a copy for the next iteration */
	proxy->device_list = registered_list;

	if (proxy->ready_cb && !proxy->ready_once) {
		proxy->ready_cb(proxy->user_data);
		proxy->ready_once = true;
	}

done:
	l_timeout_modify(timeout, 5);
	l_free(json.data);
}

static json_object *device_json_create(const char *owner_uuid,
				       const char *device_name,
				       const char *device_id)
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
			       json_object_new_string(device_id));
	json_object_object_add(device, "owner",
			       json_object_new_string(owner_uuid));

	return device;
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
 * Updates the 'devices' db, removing the sensor_id that just sent the data
 */
int proto_getdata(int proto_sock, char *uuid, char *token, const char *json_str)
{
	return proto->setdata(proto_sock, uuid, token, json_str);
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
	 * Selecting meshblu IoT protocols & services: Websockets or
	 * SocketIO 'proto_ops' drivers implements an abstraction
	 * similar to WEB client operations.
	 * TODO: later support dynamic protocol selection.
	 */

	proto = get_proto_ops(settings->proto);
	if (proto == NULL)
		return -EINVAL;

	hal_log_info("proto_ops: %s", proto->name);

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

int proto_mknode(int proto_socket, const char *owner_uuid,
		 const char *device_name, const char *device_id,
		 char *uuid, char *token)
{
	json_object *device;
	const char *device_as_string;
	json_raw_t response;
	int err, result;

	memset(&response, 0, sizeof(response));
	device = device_json_create(owner_uuid, device_name, device_id);
	if (!device) {
		hal_log_error("JSON: no memory");
		result = KNOT_ERR_INVALID;
		goto fail;
	}

	device_as_string = json_object_to_json_string(device);
	err = proto->mknode(proto_socket, device_as_string, &response);
	json_object_put(device);

	if (err < 0) {
		hal_log_error("manager mknode: %s(%d)", strerror(-err), -err);
		result = KNOT_ERR_CLOUD_FAILURE;
		goto fail;
	}

	if (response.size == 0 ||
	    (parser_device(response.data, uuid, token) < 0)) {
		hal_log_error("Unexpected response!");
		result = KNOT_ERR_CLOUD_FAILURE;
		goto fail;
	}

	/* Parse function never returns NULL for 'uuid' or 'token' fields */
	if (!is_uuid_valid(uuid) || !is_token_valid(token)) {
		hal_log_error("Invalid UUID or token!");
		result = KNOT_ERR_CLOUD_FAILURE;
		goto fail;
	}

	result = 0;
fail:
	l_free(response.data);
	return result;
}

int proto_signin(int proto_socket, const char *uuid, const char *token,
		 proto_property_changed_func_t prop_cb, void *user_data)
{
	json_raw_t response;
	int err, result;

	/* FIXME: Remove json/response */
	memset(&response, 0, sizeof(response));
	err = proto->signin(proto_socket, uuid, token,
			    &response, prop_cb, user_data);
	if (err < 0) {
		hal_log_error("manager signin(): %s(%d)", strerror(-err), -err);
		result = KNOT_ERR_PERM;
		goto fail;
	}

	result = 0;

fail:
	l_free(response.data);

	return result;
}

int proto_schema(int proto_socket, const char *uuid,
		 const char *token, struct l_queue *schema_list)
{
	json_object *jschema_list;
	const char *jschema_list_as_string;
	int result, err;

	jschema_list = schema_create_list(schema_list);
	jschema_list_as_string = json_object_to_json_string(jschema_list);

	err = proto->schema(proto_socket, uuid, token,
			    jschema_list_as_string);

	json_object_put(jschema_list);

	if (err < 0) {
		hal_log_error("manager schema(): %s(%d)", strerror(-err), -err);
		result = KNOT_ERR_CLOUD_FAILURE;
	} else
		result = 0;

	return result;
}

int proto_set_proxy_handlers(int sock,
			     proto_proxy_added_func_t added,
			     proto_proxy_ready_func_t ready,
			     void *user_data)
{
	proxy = l_new(struct proto_proxy, 1);
	proxy->sock = sock;
	proxy->added_cb = added;
	proxy->ready_cb = ready;
	proxy->ready_once = false;
	proxy->user_data = user_data;
	proxy->device_list = l_queue_new();

	/* TODO: Currently restricted to one 'watcher' */
	timeout = l_timeout_create_ms(1, timeout_callback,
				      proxy, proxy_destroy);

	return 0;
}
