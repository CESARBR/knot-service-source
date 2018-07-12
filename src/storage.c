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

#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ell/ell.h>

#include "storage.h"
#include "settings.h"

static struct l_hashmap *storage_list = NULL;

int storage_open(const char *pathname)
{
	struct l_settings *settings;
	int fd;

	fd = open(pathname, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0)
		return -errno;

	settings = l_settings_new();
	/* Ignore error if file doesn't exists */
	l_settings_load_from_file(settings, pathname);

	if (!storage_list)
		storage_list = l_hashmap_new();

	l_hashmap_insert(storage_list, L_INT_TO_PTR(fd), settings);

	return fd;
}

int storage_close(int fd)
{
	struct l_settings *settings;

	settings = l_hashmap_remove(storage_list, L_INT_TO_PTR(fd));
	if(!settings)
		return -ENOENT;

	l_settings_free(settings);

	return close(fd);
}

static int save_settings(int fd, struct l_settings *settings)
{
	char *res;
	size_t res_len;
	int err = 0;

	res = l_settings_to_data(settings, &res_len);
	ftruncate(fd, 0);
	if (pwrite(fd, res, res_len, 0) < 0)
		err = -errno;

	l_free(res);

	return err;
}

void storage_foreach_nrf24_keys(int fd,
				storage_foreach_func_t func, void *user_data)
{
	struct l_settings *settings;
	char **groups;
	char *name;
	char *id;
	int i;

	settings = l_hashmap_lookup(storage_list, L_INT_TO_PTR(fd));
	if (!settings)
		return;

	groups = l_settings_get_groups(settings);

	for (i = 0; groups[i] != NULL; i++) {
		id = l_settings_get_string(settings, groups[i], "Id");
		if (!id)
			continue;

		name = l_settings_get_string(settings, groups[i], "Name");
		if (name)
			func(groups[i], id, name, user_data);

		l_free(id);
		l_free(name);
		l_free(groups[i]);
	}

	l_free(groups);
}

int storage_write_key_string(int fd, const char *group,
			     const char *key, const char *value)
{
	struct l_settings *settings;

	settings = l_hashmap_lookup(storage_list, L_INT_TO_PTR(fd));
	if (!settings)
		return -EIO;

	if (l_settings_set_string(settings, group, key, value) == false)
		return -EINVAL;

	return save_settings(fd, settings);
}

char *storage_read_key_string(int fd, const char *group, const char *key)
{
	struct l_settings *settings;

	settings = l_hashmap_lookup(storage_list, L_INT_TO_PTR(fd));
	if (!settings)
		return NULL;

	if (l_settings_has_group(settings, group) == false)
		return NULL;

	return l_settings_get_string(settings, group, key);
}

int storage_write_key_int(int fd, const char *group, const char *key, int value)
{
	struct l_settings *settings;

	settings = l_hashmap_lookup(storage_list, L_INT_TO_PTR(fd));
	if (!settings)
		return -EINVAL;

	if (l_settings_set_int(settings, group, key, value) == false)
		return -EINVAL;

	return save_settings(fd, settings);
}

int storage_read_key_int(int fd, const char *group, const char *key, int *value)
{
	struct l_settings *settings;

	settings = l_hashmap_lookup(storage_list, L_INT_TO_PTR(fd));
	if (!settings)
		return -EINVAL;

	if (l_settings_has_group(settings, group) == false)
		return -EINVAL;

	if (l_settings_get_int(settings, group, key, value) == false)
		return -EINVAL;

	return 0;
}

int storage_write_key_uint64(int fd, const char *group,
			     const char *key, uint64_t value)
{
	struct l_settings *settings;

	settings = l_hashmap_lookup(storage_list, L_INT_TO_PTR(fd));
	if (!settings)
		return -EINVAL;

	if (l_settings_set_uint64(settings, group, key, value) == false)
		return -EINVAL;

	return save_settings(fd, settings);
}

int storage_read_key_uint64(int fd, const char *group,
			    const char *key, uint64_t *value)
{
	struct l_settings *settings;

	settings = l_hashmap_lookup(storage_list, L_INT_TO_PTR(fd));
	if (!settings)
		return -EINVAL;

	if (l_settings_has_group(settings, group) == false)
		return -EINVAL;

	if (l_settings_get_uint64(settings, group, key, value) == false)
		return -EINVAL;

	return 0;
}

int storage_remove_group(int fd, const char *group)
{
	struct l_settings *settings;

	settings = l_hashmap_lookup(storage_list, L_INT_TO_PTR(fd));
	if (!settings)
		return -EINVAL;

	if (l_settings_remove_group(settings, group) == false)
		return -EINVAL;

	return save_settings(fd, settings);
}
