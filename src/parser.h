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
struct mydevice {
       char *id;
       char *uuid;
       char *name;
       bool online;
       struct l_timeout *unreg_timeout;
};

int parser_device(const char *json_str, char *uuid, char *token);
struct l_queue *parser_schema_to_list(const char *json_str);
struct l_queue *parser_config_to_list(const char *json_str);
struct l_queue *parser_mydevices_to_list(const char *json_str);

struct l_queue *parser_sensorid_to_list(const char *json_str);
json_object *parser_sensorid_to_json(const char *key, struct l_queue *list);
struct l_queue *parser_update_to_list(json_object *jso);

int8_t parser_config_is_valid(struct l_queue *config_list);
json_object *parser_data_create_object(const char *device_id, uint8_t sensor_id,
				uint8_t value_type,
				const knot_value_type *value,
				uint8_t kval_len);
