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

struct cloud_msg {
	const char *device_id;
	const char *error;
	enum {
		UPDATE_MSG,
		REQUEST_MSG,
		REGISTER_MSG,
		UNREGISTER_MSG,
		AUTH_MSG,
		SCHEMA_MSG,
		LIST_MSG
	} type;
	union {
		const char *token; // used when type is REGISTER
		struct l_queue *list; // used when type is UPDATE/REQUEST/LIST
	};
};

struct cloud_device {
	char *id;
	char *uuid;
	char *name;
	bool online;
	struct l_queue *schema;
	struct l_timeout *unreg_timeout;
};

typedef bool (*cloud_cb_t) (const struct cloud_msg *msg, void *user_data);
typedef void (*cloud_connected_cb_t) (void *user_data);

int cloud_set_read_handler(cloud_cb_t read_handler, void *user_data);
int cloud_start(struct settings *settings, cloud_connected_cb_t connected_cb,
		void *user_data);
void cloud_stop(void);
int cloud_publish_data(const char *id, uint8_t sensor_id,
		       uint8_t value_type,
		       const knot_value_type *value,
		       uint8_t kval_len);
int cloud_register_device(const char *id, const char *name);
int cloud_unregister_device(const char *id);
int cloud_auth_device(const char *id, const char *token);
int cloud_update_schema(const char *id, struct l_queue *schema_list);
int cloud_list_devices(void);
