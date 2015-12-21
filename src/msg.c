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
	credential_t *credential;

	jobj = json_tokener_parse(json_str);
	if (jobj == NULL)
		return NULL;

	if (!json_object_object_get_ex(jobj, "uuid", &json_uuid))
		return NULL;

	if (!json_object_object_get_ex(jobj, "token", &json_token))
		return NULL;

	uuid = json_object_get_string(json_uuid);
	token = json_object_get_string(json_token);

	credential = g_new0(credential_t, 1);
	credential->uuid = g_strdup(uuid);
	credential->token = g_strdup(token);

	return credential;
}

ssize_t msg_process(const credential_t *owner, int proto_sock,
				const struct proto_ops *proto_ops,
				const void *ipdu, ssize_t ilen)
{
	const knot_msg_header *ihdr = ipdu;
	credential_t *credential;
	json_raw_t json;
	int err;

	LOG_INFO("KNOT OP: 0x%02X LEN: %02x\n", ihdr->type, ihdr->payload_len);

	switch (ihdr->type) {
	case KNOT_MSG_REGISTER_REQ:
		memset(&json, 0, sizeof(json));
		err = proto_ops->signup(proto_sock, owner->uuid, &json);
		if (err < 0) {
			LOG_ERROR("manager signup: %s(%d)\n",
						strerror(-err), -err);
			return FALSE;
		}

		/* TODO: leaking */
		credential = parse_device_info(json.data);
		LOG_INFO("UUID: %s, TOKEN: %s\n", credential->uuid,
							credential->token);
		free(json.data);
		break;
	default:
		/* TODO: reply unknown command */
		break;
	}

	return 0;
}
