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

#include <string.h>
#include <glib.h>

#include <json-c/json.h>

#include <proto-net/knot_proto_net.h>
#include <proto-app/knot_proto_app.h>

#include "proto.h"
#include "log.h"
#include "msg.h"

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

static int8_t json_result(const char *jraw)
{
	json_object *jobj, *jfield;
	int8_t result = KNOT_ERROR_UNKNOWN;
	int code;

	if(jraw == NULL)
		return KNOT_NO_DATA;

	jobj = json_tokener_parse(jraw);
	if (jobj == NULL)
		return KNOT_GW_FAILURE;

	if (json_object_object_get_ex(jobj, "error", &jfield)) {
		const char *msg = json_object_get_string(jfield);
		if(strcmp("Device not found", msg) == 0)
			result = KNOT_INVALID_DEVICE;

		/* Allow overwritting if 'code' is available */
	}

	/*
	 * In addition to 'error', 'code' may be included in the
	 * returned JSON error message. In general, 'error' is
	 * generic message (string format). 'code' is a HTTP
	 * error. The logic implemented here, returns the KNOT
	 * error equivalent to the HTTP error returned or a generic
	 * error when 'code' is not found.
	 */
	if (json_object_object_get_ex(jobj, "code", &jfield) != TRUE)
		goto done;

	code = json_object_get_int(jfield);
	if(json_object_object_get_ex(jobj, "message", &jfield) != TRUE)
		goto done;

	switch(code) {
	case 200:
		result = KNOT_SUCCESS;
		break;
		/* Unauthorized */
	case 401:
		result = KNOT_CREDENTIAL_UNAUTHORIZED;
		break;
		/* Device not found */
	case 404:
		result = KNOT_DEVICE_NOT_FOUND;
		break;
	default:
		LOG_ERROR("'%s' code=%d\n",
			  json_object_get_string(jfield), code);
		break;
	}

done:
	json_object_put(jobj);

	return result;
}

static int8_t msg_register(const credential_t *owner, int proto_sock,
				    const struct proto_ops *proto_ops,
				    const knot_msg_register *kreq,
				    knot_msg_credential *krsp)
{
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
	err = proto_ops->signup(proto_sock, jobjstring, &json);

	json_object_put(jobj);

	if (err < 0) {
		LOG_ERROR("manager signup: %s(%d)\n", strerror(-err), -err);
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

	result = KNOT_SUCCESS;

done:
	g_free(credential->uuid);
	g_free(credential->token);
	g_free(credential);

	return result;
}

static int8_t msg_unregister(const credential_t *owner, int proto_sock,
				    const struct proto_ops *proto_ops,
				    const knot_msg_unregister *kreq)
{
	json_raw_t jbuf = { NULL, 0 };
	int8_t result;
	int err;

	/* 36 octets */
	if (kreq->hdr.payload_len != sizeof(kreq->uuid)) {
		LOG_ERROR("Wrong payload length!\n");
		result = KNOT_INVALID_DATA;
		goto done;
	}

	/*
	 * Owner UUID and Token are always valid. These parameters
	 * are verified when they are loaded from storage. Permission
	 * related to owner & devices needs to be checked by the backend
	 * service. eg: Device doesn't belongs to the current owner.
	 */

	LOG_INFO("signout: %36s\n", kreq->uuid);

	err = proto_ops->signout(proto_sock, owner, kreq->uuid, &jbuf);
	if (err < 0) {
		result = KNOT_CLOUD_FAILURE;
		LOG_ERROR("signout %s failed %s (%d)\n",
					kreq->uuid, strerror(-err), -err);
		goto done;
	}

	result = json_result(jbuf.data);

	/* Propagate KNOT result to the caller */

done:
	if (jbuf.data)
		free(jbuf.data);

	return result;
}

ssize_t msg_process(const credential_t *owner, int proto_sock,
				const struct proto_ops *proto_ops,
				const void *ipdu, size_t ilen,
				void *opdu, size_t omtu)
{
	const knot_msg *kreq = ipdu;
	knot_msg *krsp = opdu;
	uint8_t rtype;
	int8_t result = KNOT_INVALID_DATA;

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

	/* Missing payload? */
	if (kreq->hdr.payload_len == 0) {
		LOG_ERROR("Input PDU: invalid PDU length\n");
		goto done;
	}

	LOG_INFO("KNOT OP: 0x%02X LEN: %02x\n",
				kreq->hdr.type, kreq->hdr.payload_len);

	switch (kreq->hdr.type) {
	case KNOT_MSG_REGISTER_REQ:

		/* Payload length is set by the caller */
		result = msg_register(owner, proto_sock, proto_ops,
						&kreq->reg, &krsp->cred);
		break;
	case KNOT_MSG_UNREGISTER_REQ:
		result = msg_unregister(owner, proto_sock, proto_ops,
								&kreq->unreg);
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
