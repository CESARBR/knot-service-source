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

struct knot_device;

int device_start(void);
void device_stop(void);


struct knot_device *device_create(const char *id, const char *name,
				  bool paired, bool registered, bool online);
void device_destroy(const char *id);
struct knot_device *device_get(const char *id);
const char *device_get_id(struct knot_device *device);

bool device_set_name(struct knot_device *device, const char *name);
bool device_set_uuid(struct knot_device *device, const char *uuid);
bool device_set_paired(struct knot_device *device, bool paired);
bool device_get_paired(struct knot_device *device);
bool device_set_registered(struct knot_device *device, bool registered);
bool device_set_online(struct knot_device *device, bool online);

bool device_forget(struct knot_device *device);
bool device_send_signal_notify(struct knot_device *device, const char *msg);
bool device_reply_forget_failed(struct knot_device *device, const char *err);
