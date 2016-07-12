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

#include <proto-app/knot_types.h>
#include <proto-net/knot_proto_net.h>
#include <proto-app/knot_proto_app.h>

#include "proto.h"
#include "log.h"
#include "msg.h"

struct trust {
	credential_t *credential;
	GSList *schema;			/* List of knot_schema */
};

/* Maps sockets to sessions  */
static GHashTable *trust_list;

static void credential_free(credential_t *credential)
{
	g_free(credential->uuid);
	g_free(credential->token);
	g_free(credential);
}

static void trust_free(struct trust *trust)
{
	credential_free(trust->credential);
	g_slist_free_full(trust->schema, g_free);
	g_free(trust);
}

static gboolean node_hup_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	int sock = g_io_channel_unix_get_fd(io);

	g_hash_table_remove(trust_list, GINT_TO_POINTER(sock));

	return FALSE;
}

static credential_t *parse_device_info(const char *json_str)
{
	json_object *jobj,*json_uuid, *json_token;
	const char *uuid, *token;
	credential_t *credential = NULL;

	jobj = json_tokener_parse(json_str);
	if (jobj == NULL)
		return NULL;

	if (!json_object_object_get_ex(jobj, "uuid", &json_uuid))
		goto done;

	if (!json_object_object_get_ex(jobj, "token", &json_token))
		goto done;

	uuid = json_object_get_string(json_uuid);
	token = json_object_get_string(json_token);

	credential = g_new0(credential_t, 1);
	credential->uuid = g_strdup(uuid);
	credential->token = g_strdup(token);

done:
	json_object_put(jobj);

	return credential;
}

static int8_t msg_register(const credential_t *owner,
					int sock, int proto_sock,
					const struct proto_ops *proto_ops,
					const knot_msg_register *kreq,
					knot_msg_credential *krsp)
{
	GIOChannel *io;
	struct trust *trust;
	credential_t *credential;
	json_object *jobj;
	const char *jobjstring;
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
		return KNOT_CLOUD_FAILURE;
	}

	credential = parse_device_info(json.data);

	free(json.data);

	if (!credential) {
		LOG_ERROR("Unexpected response!\n");
		return KNOT_CLOUD_FAILURE;
	}

	LOG_INFO("UUID: %s, TOKEN: %s\n", credential->uuid, credential->token);

	/* Parse function never returns NULL for 'uuid' or 'token' fields */
	if (strlen(credential->uuid) != 36 || strlen(credential->token) != 40) {
		LOG_ERROR("Invalid UUID or token!\n");
		result = KNOT_CLOUD_FAILURE;
		goto done;
	}

	strcpy(krsp->uuid, credential->uuid);

	/* Payload length includes the result, and UUID */
	krsp->hdr.payload_len = sizeof(*krsp) - sizeof(knot_msg_header);

	trust = g_new0(struct trust, 1);
	trust->credential = credential;

	g_hash_table_replace(trust_list, GINT_TO_POINTER(sock), trust);
	/* Add a watch to remove the credential when the client disconnects */
	io = g_io_channel_unix_new(sock);
	g_io_add_watch(io, G_IO_HUP | G_IO_NVAL | G_IO_ERR , node_hup_cb, NULL);
	g_io_channel_unref(io);

	return KNOT_SUCCESS;

done:
	credential_free(credential);

	return result;
}

static int8_t msg_unregister(int sock, int proto_sock,
					const struct proto_ops *proto_ops,
					const knot_msg_unregister *kreq)
{
	const struct trust *trust;
	const credential_t *credential;
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

	credential = trust->credential;

	LOG_INFO("rmnode: %.36s\n", credential->uuid);

	err = proto_ops->rmnode(proto_sock, credential, credential->uuid,
								&jbuf);
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
	credential_t *credential;
	int err;

	if (g_hash_table_lookup(trust_list, GINT_TO_POINTER(sock))) {
		LOG_INFO("Authenticated already\n");
		return KNOT_SUCCESS;
	}

	credential = g_new0(credential_t, 1);
	credential->uuid = g_strdup(kmauth->uuid);
	credential->token = g_strdup(kmauth->token);

	memset(&json, 0, sizeof(json));
	err = proto_ops->signin(proto_sock, credential, kmauth->uuid, &json);

	LOG_INFO("%s\n", json.data);

	if (json.data)
		free(json.data);

	if (err < 0) {
		LOG_ERROR("signin(): %s(%d)\n", strerror(-err), -err);
		credential_free(credential);
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	trust = g_new0(struct trust, 1);
	trust->credential = credential;
	g_hash_table_insert(trust_list, GINT_TO_POINTER(sock), trust);

	/* Add a watch to remove the credential when the client disconnects */
	io = g_io_channel_unix_new(sock);
	g_io_add_watch(io, G_IO_HUP | G_IO_NVAL | G_IO_ERR , node_hup_cb, NULL);
	g_io_channel_unref(io);

	return KNOT_SUCCESS;
}

static int8_t msg_schema(int sock, int proto_sock,
				const struct proto_ops *proto_ops,
				const knot_msg_config *kmcfg, gboolean eof)
{
	const knot_schema *schema = &(kmcfg->schema);
	knot_schema *kschema;
	struct json_object *jobj, *ajobj, *schemajobj;
	struct trust *trust;
	const credential_t *credential;
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
	 * "schema":[
	 *		{"data_id":<integer>, "data_type":<integer>, "name":"<name>"},
	 *		...
	 *	]
	 */

	kschema = g_memdup(schema, sizeof(*schema));
	trust->schema = g_slist_append(trust->schema, kschema);
	if (!eof)
		return KNOT_SUCCESS;

	/* SCHEMA is an array of entries */
	ajobj = json_object_new_array();
	schemajobj = json_object_new_object();

	/* For each entry */
	for (list = trust->schema; list; list = g_slist_next(list)) {
		jobj = json_object_new_object();
		json_object_object_add(jobj, "data_id",
				       json_object_new_int(schema->data_id));
		json_object_object_add(jobj, "data_type",
				       json_object_new_int(schema->data_type));
		json_object_object_add(jobj, "name",
				       json_object_new_string(schema->name));

		json_object_array_add(ajobj, jobj);
	}

	json_object_object_add(schemajobj, "schema", ajobj);
	jobjstr = json_object_to_json_string(schemajobj);

	credential = trust->credential;
	memset(&json, 0, sizeof(json));
	err = proto_ops->schema(proto_sock, credential, credential->uuid,
							jobjstr, &json);
	if (json.data)
		free(json.data);

	json_object_put(schemajobj);

	if (err < 0) {
		LOG_ERROR("manager schema(): %s(%d)\n", strerror(-err), -err);
		return KNOT_CLOUD_FAILURE;
	}

	return KNOT_SUCCESS;
}

static int8_t msg_data(int sock, int proto_sock,
					const struct proto_ops *proto_ops,
					const knot_msg_data *kmdata)
{
	/* Pointer to KNOT data containing header and a primitive KNOT type */
	const knot_data *kdata = &(kmdata->payload);
	struct json_object *jobj;
	const struct trust *trust;
	const credential_t *credential;
	json_raw_t json;
	const char *jobjstr;
	/* INT_MAX 2147483647 */
	char str[12];
	double doubleval;
	int len, err;

	LOG_INFO("id:%d, unit:%d, value_type:%d\n", kdata->hdr.id,
				kdata->hdr.unit, kdata->hdr.value_type);

	trust = g_hash_table_lookup(trust_list, GINT_TO_POINTER(sock));
	if (!trust) {
		LOG_INFO("Permission denied!\n");
		return KNOT_CREDENTIAL_UNAUTHORIZED;
	}

	/* TODO: Missing SCHEMA checking */
	jobj = json_object_new_object();
	json_object_object_add(jobj, "id", json_object_new_int(kdata->hdr.id));
	json_object_object_add(jobj, "unit",
					json_object_new_int(kdata->hdr.unit));

	switch (kdata->hdr.value_type) {
	case KNOT_VALUE_TYPE_INT:
		json_object_object_add(jobj, "value",
			       json_object_new_int(kdata->int_k.value));
		break;
	case KNOT_VALUE_TYPE_FLOAT:

		/* FIXME: precision */
		len = sprintf(str, "%d", kdata->float_k.value_dec);

		doubleval = kdata->float_k.multiplier *
				(kdata->float_k.value_int +
				 (kdata->float_k.value_dec / pow(10, len)));

		json_object_object_add(jobj, "value",
				       json_object_new_double(doubleval));
		break;
	case KNOT_VALUE_TYPE_BOOL:
		json_object_object_add(jobj, "value",
			       json_object_new_boolean(kdata->bool_k.value));
		break;
	case KNOT_VALUE_TYPE_RAW:
		break;
	default:
		json_object_put(jobj);
		return KNOT_INVALID_DATA;
	}

	jobjstr = json_object_to_json_string(jobj);
	printf("JSON: %s\n", jobjstr);

	credential = trust->credential;
	memset(&json, 0, sizeof(json));
	err = proto_ops->data(proto_sock, credential, credential->uuid,
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
		LOG_ERROR("Input PDU: invalid PDU length\n");
		goto done;
	}

	/* Checking PDU length consistency */
	if (ilen != (sizeof(kreq->hdr) + kreq->hdr.payload_len)) {
		LOG_ERROR("Input PDU: invalid PDU length\n");
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
		result = msg_schema(sock, proto_sock, proto_ops, &kreq->config,
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
