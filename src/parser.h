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

typedef void *(*parser_json_array_item_cb) (json_object *array_item);

struct l_queue *parser_schema_to_list(const char *json_str);
struct l_queue *parser_queue_from_json_array(json_object *jobj,
				parser_json_array_item_cb foreach_cb);

struct l_queue *parser_request_to_list(json_object *jso);
json_object *parser_sensorid_to_json(const char *key, struct l_queue *list);
struct l_queue *parser_update_to_list(json_object *jso);

json_object *parser_data_create_object(const char *device_id, uint8_t sensor_id,
				uint8_t value_type,
				const knot_value_type *value,
				uint8_t kval_len);
json_object *parser_device_json_create(const char *device_id,
				       const char *device_name);
json_object *parser_auth_json_create(const char *device_id,
				     const char *device_token);
json_object *parser_unregister_json_create(const char *device_id);
json_object *parser_schema_create_object(const char *device_id,
					 struct l_queue *schema_list);
const char *parser_get_key_str_from_json_obj(json_object *jso, const char *key);
bool parser_is_key_str_or_null(const json_object *jso, const char *key);
