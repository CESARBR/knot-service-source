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

#include <knot/knot_types.h>
#include <knot/knot_protocol.h>
#include <hal/linux_log.h>

#include "settings.h"
#include "node.h"
#include "device.h"
#include "proxy.h"
#include "cloud.h"
#include "msg.h"

#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define KNOT_ID_LEN		17 /* 16 char + '\0' */
#define ROLLBACK_TICKS		5 /* Equals to 5*1096ms */

struct session {
	int refs;
	bool trusted;			/* Authenticated */
	bool device_req_auth;		/* Auth requested by device */
	struct node_ops *node_ops;
	struct l_io *node_channel;	/* Radio event source */
	int node_fd;			/* Unix socket */
	uint64_t id;			/* Device identification */
	int rollback;			/* Counter: remove if schema is not received */
	char *uuid;			/* Device UUID */
	char *token;			/* Device token */
	struct l_queue *config_list;	/* knot_config accepted from cloud */
	struct l_queue *schema_list;	/* Schema accepted by cloud */
	struct l_timeout *downstream_to; /* Active when there is data to send */
	struct l_queue *update_list;	/* List of update messages */
	struct l_queue *request_list;	/* List of request messages */
};

static struct l_queue *session_list;
static struct l_queue *device_id_list;
static struct l_timeout *start_to;
static bool proxy_enabled = false;

static struct session *session_ref(struct session *session)
{
	if (unlikely(!session))
		return NULL;

	__sync_fetch_and_add(&session->refs, 1);
	hal_log_info("session_ref(%p): %d", session, session->refs);

	return session;
}

static struct session *session_new(struct node_ops *node_ops)
{
	struct session *session;

	session = l_new(struct session, 1);
	session->trusted = false;
	session->device_req_auth = false;
	session->refs = 0;
	session->uuid = NULL;
	session->token = NULL;
	session->id = INT32_MAX;
	session->node_ops = node_ops;
	session->config_list = NULL;
	session->schema_list = l_queue_new();
	session->update_list = l_queue_new();
	session->request_list = l_queue_new();

	return session_ref(session);
}

static void session_destroy(struct session *session)
{
	if (unlikely(!session))
		return;

	l_io_destroy(session->node_channel);

	l_free(session->uuid);
	l_free(session->token);
	l_queue_destroy(session->config_list, l_free);
	l_queue_destroy(session->schema_list, l_free);
	l_queue_destroy(session->update_list, l_free);
	l_queue_destroy(session->request_list, l_free);
	l_timeout_remove(session->downstream_to);

	l_free(session);
}

static void session_unref(struct session *session)
{
	if (unlikely(!session))
		return;

	hal_log_info("session_unref(%p): %d", session, session->refs - 1);
	if (__sync_sub_and_fetch(&session->refs, 1))
		return;

	session_destroy(session);
}

static void cloud_device_free(void *data)
{
	struct cloud_device *mydevice = data;
	if (unlikely(!mydevice))
		return;

	l_queue_destroy(mydevice->schema, l_free);
	l_free(mydevice->id);
	l_free(mydevice->uuid);
	l_free(mydevice->name);
	l_timeout_remove(mydevice->unreg_timeout);
	l_free(mydevice);
}

static void schema_dup_foreach(void *data, void *user_data)
{
	struct l_queue *schema = user_data;
	knot_msg_schema *msg = data;

	l_queue_push_tail(schema, l_memdup(msg, sizeof(*msg)));
}

static struct cloud_device *mydevice_dup(const struct cloud_device *mydevice)
{
	struct cloud_device *mydevice_dup;

	mydevice_dup = l_memdup(mydevice, sizeof(*mydevice));
	mydevice_dup->id = l_strdup(mydevice->id);
	mydevice_dup->uuid = l_strdup(mydevice->uuid);
	mydevice_dup->name = l_strdup(mydevice->name);
	mydevice_dup->schema = l_queue_new();

	l_queue_foreach(mydevice->schema, schema_dup_foreach,
			mydevice_dup->schema);

	return mydevice_dup;
}

static bool device_id_cmp(const void *a, const void *b)
{
	const struct cloud_device *val1 = a;
	const char *id = b;

	return strcmp(val1->id, id) == 0 ? true : false;
}

static bool device_uuid_cmp(const void *a, const void *b)
{
	const struct cloud_device *mydevice = a;
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
	int8_t result;
	char id[KNOT_ID_LEN];

	if (!session->trusted) {
		hal_log_info("[session %p] unregister: Permission denied!",
			     session);
		return KNOT_ERR_PERM;
	}

	snprintf(id, sizeof(id), "%016"PRIX64, session->id);
	hal_log_info("[session %p] rmnode: %s", session, id);

	result = cloud_unregister_device(id);
	if (result != 0)
		return result;

	l_timeout_remove(session->downstream_to);
	session->downstream_to = NULL;

	l_free(session->uuid);
	session->uuid = NULL;
	l_free(session->token);
	session->token = NULL;
	session->trusted = false;
	session->id = INT32_MAX;

	return 0;
}

static bool session_node_fd_cmp(const void *entry_data, const void *user_data)
{
	const struct session *session = entry_data;
	int node_fd = L_PTR_TO_INT(user_data);

	return session->node_fd == node_fd;
}

static bool session_id_cmp(const void *entry_data, const void *user_data)
{
	const struct session *session = entry_data;
	char id[KNOT_ID_LEN];
	const char *device_id = user_data;

	snprintf(id, sizeof(id), "%016"PRIx64, session->id);

	return !strcmp(id, device_id);
}

static bool session_uuid_cmp(const void *entry_data, const void *user_data)
{
	const struct session *session = entry_data;
	const char *uuid = user_data;

	if (!session->uuid)
		return false;

	return strcmp(session->uuid, uuid) == 0 ? true : false;
}

static void downstream_callback(struct l_timeout *timeout, void *user_data)
{
	struct session *session = user_data;
	struct node_ops *node_ops = session->node_ops;
	knot_msg_data *msg = NULL;
	knot_msg_config *config;
	knot_msg_item item;
	char id[KNOT_ID_LEN];
	ssize_t olen, osent;
	void *opdu;
	uint8_t *sensor_id;
	int err;

	/* Waiting schema? */
	if (session->rollback) {
		if (session->rollback > ROLLBACK_TICKS) {
			session->rollback = 0;
			snprintf(id, sizeof(id), "%016"PRIx64, session->id);
			device_destroy(id);
			hal_log_info("[session %p] Removing %s (rollback)",
				     session, session->uuid);
			return;
		}

		l_timeout_modify_ms(timeout, 1096);
		hal_log_info("[session %p] Waiting schema...", session);
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
	if (!l_queue_isempty(session->update_list)) {
		msg = l_queue_pop_head(session->update_list);
		opdu = msg;
		olen = sizeof(msg->hdr) + msg->hdr.payload_len;
		goto do_send;
	}

	/* Priority 3: Get Data */
	sensor_id = l_queue_peek_head(session->request_list);
	if (!sensor_id)
		goto disable_timer;

	item.hdr.type = KNOT_MSG_POLL_DATA_REQ;
	item.hdr.payload_len = sizeof(*sensor_id);
	item.sensor_id = *sensor_id;
	olen = sizeof(item);
	opdu = &item;

do_send:
	osent = node_ops->send(session->node_fd, opdu, olen);
	hal_log_info("[session %p] Sending downstream data fd(%d)...",
		     session, session->node_fd);
	if (msg)
		l_free(msg);

	if (osent < 0) {
		err = -osent;
		hal_log_error("[session %p] Can't send downstream data: " \
			      "%s(%d)", session, strerror(err), err);
		goto disable_timer;
	}

	l_timeout_modify_ms(timeout, 1096);

	return;

disable_timer:
	hal_log_info("[session %p] Disabling downstream ...", session);
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
	memcpy(message->uuid, uuid, KNOT_ID_LEN);
	memcpy(message->token, token, sizeof(message->token));

	/* Payload length includes the result, UUID and TOKEN */
	message->hdr.payload_len = sizeof(*message) - sizeof(knot_msg_header);
}

static int8_t msg_register(struct session *session,
			   const knot_msg_register *kreq, size_t ilen,
			   knot_msg_credential *krsp)
{
	struct cloud_device *device_pending = l_new(struct cloud_device, 1);
	char device_name[KNOT_PROTOCOL_DEVICE_NAME_LEN];
	char uuid[KNOT_PROTOCOL_UUID_LEN + 1];
	char token[KNOT_PROTOCOL_TOKEN_LEN + 1];
	char id[KNOT_ID_LEN];
	int8_t result;

	if (!msg_register_has_valid_length(kreq, ilen)
		|| !msg_register_has_valid_device_name(kreq)) {
		hal_log_error("[session %p] Missing device name!", session);
		return KNOT_ERR_INVALID;
	}

	/*
	 * Due to radio packet loss, peer may re-transmits register request
	 * if response does not arrives in 20 seconds. If this device was
	 * previously added we just send the uuid/token again.
	 */
	hal_log_info("[session %p] Registering (id 0x%016" PRIx64 ")",
		     session, kreq->id);

	if (session->trusted && kreq->id == session->id) {
		hal_log_info("[session %p] Register: trusted device", session);
		msg_credential_create(krsp, session->uuid, session->token);
		return 0;
	}

	msg_register_get_device_name(kreq, device_name);
	memset(uuid, 0, sizeof(uuid));
	memset(token, 0, sizeof(token));
	snprintf(id, sizeof(id), "%016"PRIx64, kreq->id);

	result = cloud_register_device(id, device_name);
	if (result != 0)
		return result;

	device_pending->id = l_strdup(id);
	/**
	 * Hacking: The id is sent inside the uuid field to avoid changes in
	 * on structs in knot_protocol library.
	 */
	device_pending->uuid = l_strdup(id);
	device_pending->name = l_strdup(device_name);
	device_pending->online = false;
	device_pending->schema = l_queue_new();

	l_queue_push_head(device_id_list, device_pending);

	session->id = kreq->id;
	session->rollback = 1; /* Initial counter value */

	return 0;
}

static bool msg_unregister_req(void *user_data)
{
	knot_msg_unregister kmunreg;
	struct session *session;
	struct node_ops *node_ops;
	struct cloud_device *mydevice = user_data;
	ssize_t olen, osent;
	void *opdu;
	int err = 0;

	session = l_queue_find(session_list, session_uuid_cmp, mydevice->uuid);
	if (!session)
		return false;

	node_ops = session->node_ops;

	kmunreg.hdr.type = KNOT_MSG_UNREG_REQ;
	kmunreg.hdr.payload_len = 0;
	olen = sizeof(knot_msg_unregister) + kmunreg.hdr.payload_len;
	opdu = &kmunreg;

	osent = node_ops->send(session->node_fd, opdu, olen);
	if (osent < 0) {
		err = -osent;
		hal_log_error("[session %p] Can't send unregister message: %s(%d)",
				session, strerror(err), err);
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
	struct cloud_device *mydevice;
	int8_t result;

	if (session->trusted) {
		hal_log_info("[session %p] Authenticated already", session);
		return 0;
	}

	mydevice = l_queue_find(device_id_list, device_uuid_cmp, kmauth->uuid);
	if (!mydevice)
		return KNOT_ERR_PERM;

	/* Set Id */
	session->id = strtoull(mydevice->id, NULL, 16);

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

	hal_log_info("[session %p] Authenticating UUID: %s, TOKEN: %s",
		     session, uuid, token);

	session->device_req_auth = true;
	result = cloud_auth_device(mydevice->id, token);

	session->rollback = 0; /* Rollback disabled */

	if (result != 0) {
		l_free(session->token);
		session->token = NULL;
		return result;
	}

	l_queue_foreach(mydevice->schema, schema_dup_foreach,
			session->schema_list);

	session->trusted = true;

	return 0;
}

static int8_t msg_schema(struct session *session,
			 const knot_msg_schema *schema, bool eof)
{
	int8_t result = 0;
	int err;
	char id[KNOT_ID_LEN];

	err = knot_schema_is_valid(schema->values.type_id,
				   schema->values.value_type,
				   schema->values.unit);
	if (err) {
		hal_log_error("Invalid schema!");
		return err;
	}

	if (!session->trusted) {
		hal_log_info("[session %p] schema: not authorized!", session);
		return KNOT_ERR_PERM;
	}

	/*
	 * {
	 *	"schema" : [
	 *		{"sensor_id": x, "value_type": w,
	 *			"unit": z, "type_id": y, "name": "foo"}
	 * 	]
	 * }
	 */

	if (!schema_find(session->schema_list, schema->sensor_id))
		l_queue_push_tail(session->schema_list,
				  l_memdup(schema, sizeof(*schema)));

	if (eof) {
		snprintf(id, sizeof(id), "%016"PRIx64, session->id);
		result = cloud_update_schema(id, session->schema_list);
	}

	if (result < 0) {
		l_queue_destroy(session->schema_list, l_free);
		session->schema_list = NULL;
	}

	return result;
}

static int8_t msg_data(struct session *session, const knot_msg_data *kmdata)
{
	const knot_msg_schema *schema;
	char id[KNOT_ID_LEN];
	int8_t result;
	uint8_t sensor_id;
	uint8_t *sensor_id_ptr;
	uint8_t kval_len;
	/*
	 * Pointer to KNOT data containing header, sensor id
	 * and a primitive KNOT type
	 */
	const knot_value_type *kvalue = &(kmdata->payload);

	if (!session->trusted) {
		hal_log_info("[session %p] data: Permission denied!", session);
		return KNOT_ERR_PERM;
	}

	snprintf(id, sizeof(id), "%016"PRIx64, session->id);
	sensor_id = kmdata->sensor_id;
	schema = schema_find(session->schema_list, sensor_id);
	if (!schema) {
		hal_log_info("[session %p] sensor_id(0x%02x): data type mismatch!",
			     session, sensor_id);
		return KNOT_ERR_INVALID;
	}

	hal_log_info("[session %p] sensor:%d, unit:%d, value_type:%d", session,
		     sensor_id, schema->values.unit, schema->values.value_type);

	kval_len = kmdata->hdr.payload_len - sizeof(kmdata->sensor_id);
	result = cloud_publish_data(id, sensor_id, schema->values.value_type,
				    kvalue, kval_len);
	if (result < 0)
		goto done;

	/* Remove pending get data request */
	sensor_id_ptr = l_queue_remove_if(session->request_list,
					  sensor_id_cmp,
					  L_INT_TO_PTR(sensor_id));
	if (sensor_id_ptr == NULL)
		goto done;

	l_free(sensor_id_ptr);

done:
	return result;
}

static int8_t msg_config_resp(struct session *session,
			      const knot_msg_item *response)
{
	knot_msg_config *config;
	uint8_t sensor_id;

	if (!session->trusted) {
		hal_log_info("[session %p] config resp: Permission denied!",
			     session);
		return KNOT_ERR_PERM;
	}

	sensor_id = response->sensor_id;

	/* TODO: Always forward instead of avoid sending repeated configs */
	config = l_queue_remove_if(session->config_list,
				   config_sensor_id_cmp,
				   L_UINT_TO_PTR(sensor_id));
	if (!config)
		return KNOT_ERR_INVALID;

	l_free(config);

	hal_log_info("[session %p] THING %s received config for sensor %d",
		     session, session->uuid, sensor_id);

	return 0;
}

/*
 * Works like msg_data() (copy & paste), but removes the received info from
 * the 'devices' database.
 */
static int8_t msg_setdata_resp(struct session *session,
			       const knot_msg_data *kmdata)
{
	const knot_msg_schema *schema;
	char id[KNOT_ID_LEN];
	uint8_t sensor_id;
	int8_t result;
	uint8_t kval_len;
	/*
	 * Pointer to KNOT data containing header, sensor id
	 * and a primitive KNOT type
	 *
	 * Format to push to cloud:
	 * "set_data" : [
	 *		{"sensor_id": v, "value": w}]
	 */

	const knot_value_type *kvalue = &(kmdata->payload);

	if (!session->trusted) {
		hal_log_info("[session %p] setdata: Permission denied!",
			     session);
		return KNOT_ERR_PERM;
	}

	snprintf(id, sizeof(id), "%016"PRIx64, session->id);
	sensor_id = kmdata->sensor_id;
	schema = schema_find(session->schema_list, sensor_id);
	if (!schema) {
		hal_log_info("[session %p] sensor_id(0x%02x): data type mismatch!",
			     session, sensor_id);
		return KNOT_ERR_INVALID;
	}

	hal_log_info("[session %p] sensor:%d, unit:%d, value_type:%d",
		     session, sensor_id, schema->values.unit,
		     schema->values.value_type);

	kval_len = kmdata->hdr.payload_len - sizeof(kmdata->sensor_id);
	result = cloud_publish_data(id, sensor_id, schema->values.value_type,
				    kvalue, kval_len);
	if (result != 0)
		return result;

	hal_log_info("[session %p] THING %s updated data for sensor %d",
		     session, session->uuid, sensor_id);

	return 0;
}

static void device_forget_destroy(struct cloud_device *mydevice)
{
	struct knot_device *device;

	if (!mydevice)
		return;

	device = device_get(mydevice->id);

	if (device_forget(device))
		hal_log_info("Removing proxy for %s", mydevice->id);

	mydevice = l_queue_remove_if(device_id_list, device_id_cmp,
			mydevice->id);

	cloud_device_free(mydevice);
}

static int8_t msg_unregister_resp(struct session *session)
{
	struct cloud_device *mydevice = l_queue_find(device_id_list,
						 device_uuid_cmp,
						 session->uuid);

	device_forget_destroy(mydevice);

	return 0;
}

static ssize_t msg_process(struct session *session,
				const void *ipdu, size_t ilen,
				void *opdu, size_t omtu)
{
	const knot_msg *kreq = ipdu;
	knot_msg *krsp = opdu;
	uint8_t rtype = 0;
	size_t plen;
	int8_t result = KNOT_ERR_INVALID;

	/* Verify if output PDU has a min length */
	if (omtu < sizeof(knot_msg)) {
		hal_log_error("[session %p] Output PDU: invalid PDU length",
			      session);
		return -EINVAL;
	}

	/* Set a default payload length for error */
	krsp->hdr.payload_len = sizeof(krsp->action.result);

	/* At least header should be received */
	if (ilen < sizeof(knot_msg_header)) {
		hal_log_error("[session %p] KNOT PDU: invalid minimum length",
			      session);
		return -EINVAL;
	}

	/* Checking PDU length consistency */
	plen = sizeof(kreq->hdr) + kreq->hdr.payload_len;
	if (ilen != plen) {
		hal_log_error("[session %p] KNOT PDU: len mismatch %ld/%ld",
			      session, ilen, plen);
		return -EINVAL;
	}

	hal_log_info("[session %p] KNOT OP: 0x%02X LEN: %02x",
		     session, kreq->hdr.type, kreq->hdr.payload_len);

	switch (kreq->hdr.type) {
	case KNOT_MSG_REG_REQ:
		/* Payload length is set by the caller */
		result = msg_register(session, &kreq->reg, ilen, &krsp->cred);
		if (result != 0)
			break;
		session->downstream_to =
			l_timeout_create_ms(512,
					    downstream_callback,
					    session, NULL);
		return 0;
	case KNOT_MSG_UNREG_REQ:
		result = msg_unregister(session);
		rtype = KNOT_MSG_UNREG_RSP;
		break;
	case KNOT_MSG_PUSH_DATA_REQ:
		result = msg_data(session, &kreq->data);
		rtype = KNOT_MSG_PUSH_DATA_RSP;
		break;
	case KNOT_MSG_AUTH_REQ:
		result = msg_auth(session, &kreq->auth);
		rtype = KNOT_MSG_AUTH_RSP;
		if (result != 0)
			break;

		/* Enable downstream after authentication */
		session->downstream_to =
			l_timeout_create_ms(512,
					    downstream_callback,
					    session, NULL);
		/*
		 * KNOT_MSG_AUTH_RSP is sent on function
		 * handle_device_auth
		 */
		return 0;
	case KNOT_MSG_SCHM_FRAG_REQ:
		rtype = KNOT_MSG_SCHM_FRAG_RSP;
		result = msg_schema(session, &kreq->schema, false);
		break;
	case KNOT_MSG_SCHM_END_REQ:
		rtype = KNOT_MSG_SCHM_END_RSP;
		result = msg_schema(session, &kreq->schema, true);
		if (result != 0)
			break;

		/*
		 * KNOT_MSG_SCHM_END_RSP is sent on function
		 * handle_schema_updated
		 */
		return 0;
	case KNOT_MSG_PUSH_CONFIG_RSP:
		result = msg_config_resp(session, &kreq->item);
		/* No octets to be transmitted */
		return 0;
	case KNOT_MSG_PUSH_DATA_RSP:
		result = msg_setdata_resp(session, &kreq->data);
		return 0;
	case KNOT_MSG_UNREG_RSP:
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

static void session_node_disconnected_cb(struct l_io *channel, void *user_data)
{
	struct session *session = user_data;
	struct knot_device *device;
	char id[KNOT_ID_LEN];

	/* ELL returns -1 when calling l_io_get_fd() at disconnected callback */
	session = l_queue_remove_if(session_list,
				    session_node_fd_cmp,
				    L_INT_TO_PTR(session->node_fd));

	hal_log_info("[session %p] disconnected (node)", session);

	snprintf(id, sizeof(id), "%016"PRIx64, session->id);
	if (session->rollback) {
		device_destroy(id);
		hal_log_info("[session %p] Removing %s (rollback)",
			     session, session->uuid);
	}

	device = device_get(id);
	if (device)
		device_set_online(device, false);

	session_unref(session);
}

static void session_node_destroy_cb(void *user_data)
{
	struct session *session = user_data;
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
		hal_log_error("[session %p] readv(): %s(%d)",
			      session, strerror(err), err);
		on_node_channel_data_error(channel);
		return false;
	}

	/* Blocking: Wait until response from cloud is received */
	olen = msg_process(session, ipdu, recvbytes, opdu, sizeof(opdu));
	/* olen: output length or -errno */
	if (olen < 0) {
		/* Server didn't reply any error */
		hal_log_error("[session %p] KNOT IoT cloud error: %s(%zd)",
			      session, strerror(-olen), -olen);
		return true;
	}

	/* If there are no octets to be sent */
	if (!olen)
		return true;

	/* Response from the gateway: error or response for the given command */
	sentbytes = node_ops->send(node_socket, opdu, olen);
	if (sentbytes < 0)
		hal_log_error("[session %p] node_ops: %s(%zd)",
			      session, strerror(-sentbytes), -sentbytes);

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
				    session_node_destroy_cb);

	return channel;
}

static struct session *session_create(struct node_ops *node_ops,
				      int client_socket)
{
	struct session *session;

	session = session_new(node_ops);

	session->node_channel = create_node_channel(client_socket, session);
	if (session->node_channel == NULL) {
		session_unref(session);
		return NULL;
	}
	session->node_fd = client_socket; /* Required to manage disconnections */

	hal_log_info("[session %p] Session created", session);

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
		hal_log_info("Removing proxy for %s", id);
}

static bool handle_device_added(struct session *session, const char *device_id,
				const char *token)
{
	struct knot_device *device_dbus = device_get(device_id);
	struct cloud_device *device_pending = l_queue_find(device_id_list,
						 device_id_cmp,
						 device_id);
	const struct node_ops *node_ops;
	knot_msg_credential msg;
	ssize_t olen, osent;
	int err, result;

	node_ops = session->node_ops;

	/* Tracks 'proxy' devices that belongs to Cloud. */
	hal_log_info("Device added: %s", device_id);

	if (!device_dbus) {
		if (!device_pending)
			return true;
		/* Ownership belongs to device.c */
		device_dbus = device_create(device_pending->id,
					    device_pending->name,
					    true /* paired */,
					    false /* registered */,
					    false /* online */);
		if (!device_dbus)
			return true;
	}

	device_set_uuid(device_dbus, device_pending->uuid);
	device_pending->unreg_timeout = NULL;
	session->trusted = false;
	session->uuid = l_strdup(device_pending->uuid);
	session->token = l_strdup(token);

	memset(&msg, 0, sizeof(msg));
	msg_credential_create(&msg, device_pending->uuid, token);

	msg.hdr.type = KNOT_MSG_REG_RSP;
	olen = sizeof(msg.hdr) + msg.hdr.payload_len;

	osent = node_ops->send(session->node_fd, &msg, olen);
	if (osent < 0) {
		err = -osent;
		hal_log_error("[session %p] Can't send register response %s(%d)"
			      , session, strerror(err), err);
	}

	session->device_req_auth = false;
	result = cloud_auth_device(device_id, session->token);
	if (result != 0) {
		l_free(session->uuid);
		l_free(session->token);
		session->uuid = NULL;
		session->token = NULL;
		return true;
	}

	return true;
}

/*
 * Forget device and destroy its proxy if the unregister response isn't
 * received within 1096 seconds.
 */
static void unregister_callback(struct l_timeout *timeout, void *user_data)
{
	struct cloud_device *mydevice = user_data;

	hal_log_info("Unregister response not received");

	device_forget_destroy(mydevice);
}

static bool handle_device_removed(const char *device_id)
{
	struct knot_device *device = device_get(device_id);
	struct cloud_device *mydevice = l_queue_find(device_id_list,
						 device_id_cmp,
						 device_id);

	hal_log_info("Device removed: %s", device_id);

	/* Tracks 'proxy' devices removed from Cloud. */
	if (device == NULL) {
		/* Other service or created by external apps(eg: ktool) */
		hal_log_error("Device %s not found!", device_id);
		return true;
	}

	/* Send unregister request to device */
	if(msg_unregister_req(mydevice)) {
		hal_log_info("Sending unregister message ...");
		/* Start unregister timeout */
		mydevice->unreg_timeout = l_timeout_create_ms(1096,
							unregister_callback,
							mydevice, NULL);
		return true;
	}

	hal_log_info("Unregister message can't be sent!!");

	device_forget_destroy(mydevice);
	return false;
}

static bool handle_device_auth(struct session *session, const char *device_id,
			       int auth)
{
	struct knot_device *device;
	ssize_t osent;
	int osent_err;
	knot_msg msg;

	if (!session->device_req_auth)
		goto done;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.type = KNOT_MSG_AUTH_RSP;
	msg.hdr.payload_len = sizeof(msg.action.result);

	if (!auth) {
		hal_log_error("[session %p] Not Authorized", session);
		msg.action.result = KNOT_ERR_PERM;
	}

	osent = session->node_ops->send(session->node_fd, &msg,
					sizeof(msg.hdr) + msg.hdr.payload_len);
	if (osent < 0) {
		osent_err = -osent;
		hal_log_error("[session %p] Can't send msg response  %s(%d)",
			      session, strerror(osent_err), osent_err);
		return false;
	}

done:
	device = device_get(device_id);
	if (device)
		device_set_online(device, auth);

	session->trusted = auth;

	return true;
}

static bool handle_schema_updated(struct session *session,
				  const char *device_id, const char *err)
{
	struct knot_device *device;
	struct cloud_device *mydevice = l_queue_find(device_id_list,
						 device_id_cmp,
						 device_id);
	ssize_t osent;
	int osent_err;
	bool result = false;
	knot_msg msg;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.type = KNOT_MSG_SCHM_END_RSP;
	msg.hdr.payload_len = sizeof(msg.action.result);

	if (err) {
		hal_log_error("%s", err);

		msg.action.result = KNOT_ERR_CLOUD_FAILURE;
		result = true;

		/* TODO: Send a error signal via D-Bus */
	}

	osent = session->node_ops->send(session->node_fd, &msg,
					sizeof(msg.hdr) + msg.hdr.payload_len);
	if (osent < 0) {
		osent_err = -osent;
		hal_log_error("[session %p] Can't send msg response %s(%d)",
			      session, strerror(osent_err), osent_err);
		return result;
	}

	device = device_get(device_id);
	if (device)
		device_set_registered(device, true);

	l_queue_foreach(session->schema_list, schema_dup_foreach,
			mydevice->schema);

	/*
	 * For security reason, remove from rollback avoiding clonning attack.
	 * If schema is being sent means that credentals (UUID/token) has been
	 * properly received (registration complete).
	 */
	session->rollback = 0; /* Rollback disabled */

	return true;
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

static void create_devices_dbus(void *data, void *user_data)
{
	const struct cloud_device *mydevice = data;
	struct knot_device *device_dbus;
	bool registered = mydevice->schema != NULL;

	device_dbus = device_create(mydevice->id, mydevice->name, true,
				    registered, false);
	if (device_dbus)
		device_set_uuid(device_dbus, mydevice->uuid);

	l_queue_push_head(device_id_list, mydevice_dup(mydevice));
}

static bool handle_cloud_msg_list(struct l_queue *devices)
{
	l_queue_foreach(devices, create_devices_dbus, NULL);
	proxy_ready(NULL);

	/* Start to accept thing connections when receive cloud devices */
	node_start(session_accept_cb);

	return true;
}

static void append_on_update_list(void *data, void *user_data)
{
	const struct session *session = user_data;
	knot_msg_schema *schema_found;
	knot_msg_data *msg = data;

	schema_found = schema_find(session->schema_list, msg->sensor_id);
	if (schema_found)
		l_queue_push_tail(session->update_list,
				  l_memdup(msg, sizeof(*msg)));
}

static void append_on_request_list(void *data, void *user_data)
{
	const struct session *session = user_data;
	knot_msg_schema *schema_found;
	unsigned int *msg = data;

	schema_found = schema_find(session->schema_list, *msg);
	if (schema_found)
		l_queue_push_tail(session->request_list,
				  l_memdup(msg, sizeof(*msg)));
}

/**
 * Handle commands from cloud (UPDATE_MSG/REQUEST_MSG) to be sent downstream
 * to thing.
 */
static bool handle_cloud_msg_downstream(struct session *session,
					struct l_queue *list,
					l_queue_foreach_func_t append_list_cb)
{
	l_queue_foreach(list, append_list_cb, session);

	if (session->downstream_to)
		l_timeout_modify_ms(session->downstream_to, 512);

	return true;
}

static bool on_cloud_receive(const struct cloud_msg *msg, void *user_data)
{
	struct session *session = l_queue_find(session_list, session_id_cmp,
					       msg->device_id);

	/**
	 * Verify if thing session exists otherwise requeue the message.
	 * Unregister/List message don't require to have a session to be
	 * processed.
	 */
	if (!session && msg->type != UNREGISTER_MSG && msg->type != LIST_MSG) {
		hal_log_error("Unable to find the session with id: %s",
				msg->device_id);
		return false;
	}

	switch (msg->type) {
	case UPDATE_MSG:
		return handle_cloud_msg_downstream(session, msg->list,
						   append_on_update_list);
	case REQUEST_MSG:
		return handle_cloud_msg_downstream(session, msg->list,
						   append_on_request_list);
	case REGISTER_MSG:
		return handle_device_added(session, msg->device_id, msg->token);
	case UNREGISTER_MSG:
		return handle_device_removed(msg->device_id);
	case AUTH_MSG:
		return handle_device_auth(session, msg->device_id, msg->auth);
	case SCHEMA_MSG:
		return handle_schema_updated(session, msg->device_id,
					     msg->error);
	case LIST_MSG:
		return handle_cloud_msg_list(msg->list);
	default:
		return true;
	}
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

	err = cloud_start(settings);
	if (err < 0) {
		hal_log_error("cloud_start(): %s", strerror(-err));
		goto cloud_fail;
	}

	err = cloud_set_read_handler(on_cloud_receive, NULL);
	if (err < 0) {
		hal_log_error("cloud_set_read_handler(): %s", strerror(-err));
		goto cloud_operation_fail;
	}

	device_id_list = l_queue_new();

	err = cloud_list_devices();
	if (err < 0) {
		hal_log_error("cloud_list_devices(): %s", strerror(-err));
		goto cloud_operation_fail;
	}

	return 0;

cloud_operation_fail:
	cloud_stop();
cloud_fail:
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
	cloud_stop();
	device_stop();

	l_queue_destroy(device_id_list, cloud_device_free);

	l_queue_destroy(session_list,
			(l_queue_destroy_func_t) session_unref);
}
