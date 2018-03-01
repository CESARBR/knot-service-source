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

static int settings_to_file(const char *pathname, struct l_settings *settings)
{
	char *res;
	size_t res_len;
	int fd;
	int err = 0;

	res = l_settings_to_data(settings, &res_len);

	fd = open(pathname, O_WRONLY | O_TRUNC);
	if (fd < 0){
		err = -errno;
		goto failure;
	}

	if (write(fd, res, res_len) == -1)
		err = -errno;

	close(fd);

failure:
	l_free(res);
	return err;
}

int storage_write_key_string(const char *pathname, const char *group,
			     const char *key, const char *value)
{
	struct l_settings *settings = l_settings_new();
	int ret = -EINVAL;
	bool err;

	err = l_settings_load_from_file(settings, pathname);
	if (!err){
		ret = -ENOENT;
		goto failure;
	}

	err = l_settings_set_string(settings, group, key, value);
	if (!err)
		goto failure;

	ret = settings_to_file(pathname, settings);

failure:
	l_settings_free(settings);
	return ret;
}

char *storage_read_key_string(const char *pathname, const char *group,
			      const char *key)
{
	struct l_settings *settings = l_settings_new();
	char *str = NULL;
	bool err;

	err = l_settings_load_from_file(settings, pathname);
	if (!err)
		goto failure;

	err = l_settings_has_group(settings, group);
	if (!err)
		goto failure;

	str = l_settings_get_string(settings, group, key);

failure:
	l_settings_free(settings);
	return str;
}

int storage_write_key_int(const char *pathname, const char *group,
			  const char *key, int value)
{
	struct l_settings *settings = l_settings_new();
	int ret = -EINVAL;
	bool err;

	err = l_settings_load_from_file(settings, pathname);
	if (!err){
		ret = -ENOENT;
		goto failure;
	}

	err  = l_settings_set_int(settings, group, key, value);
	if (!err)
		goto failure;

	ret = settings_to_file(pathname, settings);

failure:
	l_settings_free(settings);
	return ret;
}

int storage_read_key_int(const char *pathname, const char *group,
			 const char *key, int *value)
{
	struct l_settings *settings = l_settings_new();
	int ret = 0;
	bool err;

	err = l_settings_load_from_file(settings, pathname);
	if (!err){
		ret = -ENOENT;
		goto failure;
	}

	err = l_settings_has_group(settings, group);
	if (!err){
		ret = -EINVAL;
		goto failure;
	}

	err = l_settings_get_int(settings, group, key, value);
	if (!err){
		ret = -EINVAL;
		goto failure;
	}

failure:
	l_settings_free(settings);
	return ret;
}

int storage_write_key_uint64(const char *pathname, const char *group,
			     const char *key, uint64_t value)
{
	struct l_settings *settings = l_settings_new();
	int ret = -EINVAL;
	bool err;

	err = l_settings_load_from_file(settings, pathname);
	if (!err){
		ret = -ENOENT;
		goto failure;
	}

	err = l_settings_set_uint64(settings, group, key, value);
	if (!err)
		goto failure;

	ret = settings_to_file(pathname, settings);

failure:
	l_settings_free(settings);
	return ret;
}

int storage_read_key_uint64(const char *pathname, const char *group,
			    const char *key, uint64_t *value)
{
	struct l_settings *settings = l_settings_new();
	int ret = 0;
	bool err;

	err = l_settings_load_from_file(settings, pathname);
	if (!err){
		ret = -ENOENT;
		goto failure;
	}

	err = l_settings_has_group(settings, group);
	if (!err){
		ret = -EINVAL;
		goto failure;
	}

	err = l_settings_get_uint64(settings, group, key, value);
	if (!err){
		ret = -EINVAL;
		goto failure;
	}

failure:
	l_settings_free(settings);
	return ret;
}

int storage_remove_group(const char *pathname, const char *group)
{
	struct l_settings *settings = l_settings_new();
	int ret = -EINVAL;
	bool err;

	err = l_settings_load_from_file(settings, pathname);
	if (!err){
		ret = -ENOENT;
		goto failure;
	}

	err = l_settings_remove_group(settings, group);
	if (!err)
		goto failure;

	ret = settings_to_file(pathname, settings);

failure:
	l_settings_free(settings);
	return ret;
}
