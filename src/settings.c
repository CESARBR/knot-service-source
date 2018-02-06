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

#include "settings.h"

#include <errno.h>
#include <stdbool.h>

#include <glib.h>
#include <json-c/json.h>

static gboolean use_ell = FALSE;
static const char *config_path = "/etc/knot/gatewayConfig.json";
static char *host = NULL;
static unsigned int port = 0;
static const char *proto = "ws";
static const char *tty = NULL;
static gboolean detach = TRUE;
static gboolean run_as_nobody = TRUE;

static GOptionEntry options_spec[] = {
	{ "ell", 'e', 0, G_OPTION_ARG_NONE, &use_ell,
					"Use ELL instead of glib" },
	{ "config", 'c', 0, G_OPTION_ARG_STRING, &config_path,
					"Configuration file path", "path" },
	{ "host", 'h', 0, G_OPTION_ARG_STRING, &host,
					"Cloud server host name", "host" },
	{ "port", 'p', 0, G_OPTION_ARG_INT, &port,
					"Cloud server port", "port" },
	{ "proto", 'P', 0, G_OPTION_ARG_STRING, &proto,
					"Protocol used to communicate with cloud server, e.g. http or ws",
					"proto" },
	{ "tty", 't', 0, G_OPTION_ARG_STRING, &tty,
					"TTY device path, e.g. /dev/ttyUSB0", "tty" },
	{ "nodetach", 'n', G_OPTION_FLAG_REVERSE,
					G_OPTION_ARG_NONE, &detach,
					"Disable running in background" },
	{ "disable-nobody", 'b', G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE,
					&run_as_nobody, "Disable running as nobody" },
	{ NULL },
};

static int parse_args(int argc, char *argv[], struct settings *settings)
{
	int err = -EINVAL;
	GOptionContext *context;
	GError *gerr = NULL;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options_spec, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &gerr)) {
		g_printerr("Invalid arguments: %s\n", gerr->message);
		g_error_free(gerr);
		goto done;
	}

	settings->use_ell = use_ell;
	settings->config_path = config_path;
	settings->host = host;
	settings->port = port;
	settings->proto = proto;
	settings->tty = tty;
	settings->detach = detach;
	settings->run_as_nobody = run_as_nobody;

	err = 0;

done:
	g_option_context_free(context);
	return err;
}

static bool is_valid_config_file(const char *config_path)
{
	return config_path != NULL;
}

static bool get_as_string(json_object *root, char *name, const char **value)
{
	json_object *obj;

	if (!json_object_object_get_ex(root, name, &obj))
		return false;

	*value = json_object_get_string(obj);

	return true;
}

static bool get_as_int(json_object *root, char *name, int *value)
{
	json_object *obj;

	if (!json_object_object_get_ex(root, name, &obj))
		return false;

	*value = json_object_get_int(obj);

	return true;
}

static int parse_config_file(const char *config_path, struct settings *settings)
{
	int err = -EINVAL;
	const char *obj_value;
	json_object *root, *cloud;

	/* Load data from config file */
	root = json_object_from_file(config_path);
	if (!root)
		goto fail_get_root;

	if (!json_object_object_get_ex(root, "cloud", &cloud))
		goto fail_get_cloud;

	/*
	 * Command line options (host and port) have higher priority
	 * than values read from config file. UUID should
	 * not be read from command line due security reason.
	 */

	/* UUID is mandatory */
	if (!get_as_string(cloud, "uuid", &obj_value) || obj_value == NULL)
		goto fail_get_uuid;
	settings->uuid = g_strdup(obj_value);

	if (settings->host == NULL) {
		if (!get_as_string(cloud, "serverName", &obj_value))
			goto fail_get_host;
	} else {
		/* Allocate, so that we can free it later */
		obj_value = settings->host;
	}
	settings->host = g_strdup(obj_value);

	if (settings->port == 0) {
		if (!get_as_int(cloud, "port", (int *)&settings->port))
			goto fail_get_port;
	}

	err = 0;
	goto done;

fail_get_port:
	g_free(settings->host);
fail_get_host:
	g_free(settings->uuid);
fail_get_uuid:
fail_get_cloud:
done:
	/* Free mem allocated for root object */
	json_object_put(root);
fail_get_root:
	return err;
}

int settings_parse(int argc, char *argv[], struct settings **settings)
{
	int err = -EINVAL;

	*settings = g_new0(struct settings, 1);

	err = parse_args(argc, argv, *settings);
	if (err)
		goto failure;

	if (!is_valid_config_file((*settings)->config_path)) {
		err = -EINVAL;
		g_printerr("Missing configuration file\n");
		goto failure;
	}

	err = parse_config_file((*settings)->config_path, *settings);
	if (err) {
		g_printerr("Configuration file is invalid\n");
		goto failure;
	}

	err = 0;
	goto done;

failure:
	g_free(*settings);
done:
	return err;
}

void settings_free(struct settings *settings)
{
	g_free(settings->host);
	g_free(settings->uuid);
	g_free(settings);
}
