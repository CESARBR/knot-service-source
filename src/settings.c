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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <getopt.h>

#include <ell/ell.h>
#include <json-c/json.h>

#include "settings.h"

static bool use_ell = false;
static const char *config_path = "/etc/knot/gatewayConfig.json";
static char *host = NULL;
static unsigned int port = 0;
static const char *proto = "ws";
static const char *tty = NULL;
static bool detach = true;
static bool run_as_nobody = true;
static bool help = false;

static void usage(void)
{
	printf("knotd - KNoT deamon\n"
		"Usage:\n");
	printf("\tknotd [options]\n");
	printf("Options:\n"
		"\t-e, --ell               Use ELL instead of glib\n"
		"\t-c, --config            Configuration file path\n"
		"\t-h, --host              Cloud server host name\n"
		"\t-p, --port              Remote port\n"
		"\t-P, --proto             Protocol used to communicate with cloud server, e.g. http or ws\n"
		"\t-t, --tty               TTY device path, e.g. /dev/ttyUSB0\n"
		"\t-n, --nodetach          Disable running in background\n"
		"\t-b, --disable-nobody    Disable running as nobody\n"
		"\t-H, --help              Show help options\n");
}

static const struct option main_options[] = {
	{ "ell",		no_argument,		NULL, 'e' },
	{ "config",		required_argument,	NULL, 'c' },
	{ "host",		required_argument,	NULL, 'h' },
	{ "port",		required_argument,	NULL, 'p' },
	{ "proto",		required_argument,	NULL, 'P' },
	{ "tty",		required_argument,	NULL, 't' },
	{ "nodetach",		no_argument,		NULL, 'n' },
	{ "disable-nobody",	no_argument,		NULL, 'b' },
	{ "help",		no_argument,		NULL, 'H' },
	{ }
};

static int parse_args(int argc, char *argv[], struct settings *settings)
{
	int opt;

	for (;;) {
		opt = getopt_long(argc, argv, "ec:h:p:P:t:nbH",
				  main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'e':
			settings->use_ell = true;
			break;
		case 'c':
			settings->config_path = optarg;
			break;
		case 'h':
			settings->host = optarg;
			break;
		case 'p':
			settings->port = atoi(optarg);
			break;
		case 'P':
			settings->proto = optarg;
			break;
		case 't':
			settings->tty = optarg;
			break;
		case 'n':
			settings->detach = false;
			break;
		case 'b':
			settings->run_as_nobody = false;
			break;
		case 'H':
			usage();
			settings->help = true;
			return EXIT_SUCCESS;
		default:
			return EXIT_FAILURE;
		}
	}

	if (argc - optind > 0) {
		fprintf(stderr, "Invalid command line parameters\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
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
	int err = EXIT_FAILURE;
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
	settings->uuid = l_strdup(obj_value);

	if (settings->host == NULL) {
		if (!get_as_string(cloud, "serverName", &obj_value))
			goto fail_get_host;
	} else {
		/* Allocate, so that we can free it later */
		obj_value = settings->host;
	}
	settings->host = l_strdup(obj_value);

	if (settings->port == 0) {
		if (!get_as_int(cloud, "port", (int *)&settings->port))
			goto fail_get_port;
	}

	err = EXIT_SUCCESS;
	goto done;

fail_get_port:
	l_free(settings->host);
fail_get_host:
	l_free(settings->uuid);
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
	int err = EXIT_FAILURE;

	*settings = l_new(struct settings, 1);

	(*settings)->use_ell = use_ell;
	(*settings)->config_path = config_path;
	(*settings)->host = host;
	(*settings)->port = port;
	(*settings)->proto = proto;
	(*settings)->tty = tty;
	(*settings)->detach = detach;
	(*settings)->run_as_nobody = run_as_nobody;
	(*settings)->help = help;

	err = parse_args(argc, argv, *settings);
	if (err)
		goto failure;

	if (!is_valid_config_file((*settings)->config_path)) {
		err = EXIT_FAILURE;
		fprintf(stderr, "Missing KNoT configuration file!\n");
		goto failure;
	}

	err = parse_config_file((*settings)->config_path, *settings);
	if (err) {
		fprintf(stderr, "%s is not a regular file!\n", config_path);
		goto failure;
	}

	err = EXIT_SUCCESS;
	goto done;

failure:
	l_free(*settings);
done:
	return err;
}

void settings_free(struct settings *settings)
{
	l_free(settings->host);
	l_free(settings->uuid);
	l_free(settings);
}
