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

typedef void (*storage_foreach_func_t) (const char *mac, const char *id,
					const char *name, void *user_data);

void storage_foreach_nrf24_keys(int fd,
				storage_foreach_func_t func, void *user_data);

int storage_write_key_string(int fd, const char *group,
			     const char *key, const char *value);

char *storage_read_key_string(int fd, const char *group,
			      const char *key);

int storage_write_key_int(int fd, const char *group,
			  const char *key, int value);

int storage_read_key_int(int fd, const char *group,
			 const char *key, int *value);

int storage_write_key_uint64(int fd, const char *group,
			     const char *key, uint64_t value);

int storage_read_key_uint64(int fd, const char *group,
			    const char *key, uint64_t *value);

int storage_remove_group(int fd, const char *group);

int storage_open(const char *pathname);
int storage_close(int fd);
