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

typedef bool (*cloud_downstream_cb_t) (const char *id, struct l_queue *data,
				       void *user_data);

typedef void (*cloud_device_removed_cb_t) (const char *id,
				      void *user_data);

int cloud_set_read_handlers(cloud_downstream_cb_t on_update,
		  cloud_downstream_cb_t on_request,
		  cloud_device_removed_cb_t on_removed,
		  void *user_data);
int cloud_start(struct settings *settings);
void cloud_stop(void);
int cloud_publish_data(const char *id, uint8_t sensor_id,
		       uint8_t value_type,
		       const knot_value_type *value,
		       uint8_t kval_len);
int cloud_unregister_device(const char *id);
