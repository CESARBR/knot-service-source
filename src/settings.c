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

#include "settings.h"
#include "storage.h"

#define DEFAULT_CONFIG_PATH "/etc/knot/knotd.conf"
#define DEFAULT_HOST "localhost"
#define DEFAULT_PORT 3000
#define DEFAULT_PROTO "ws"

static const char *tty = NULL;
static bool detach = true;
static bool help = false;

static void usage(void)
{
	printf("knotd - KNoT deamon\n"
		"Usage:\n");
	printf("\tknotd [options]\n");
	printf("Options:\n"
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
		opt = getopt_long(argc, argv, "c:h:p:P:t:nbH",
				  main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'c':
			settings->config_path = optarg;
			break;
		case 'h':
			settings->host = l_strdup(optarg);
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
			return 0;
		default:
			return -EINVAL;
		}
	}

	if (argc - optind > 0) {
		fprintf(stderr, "Invalid command line parameters\n");
		return -EINVAL;
	}

	return 0;
}

struct settings *settings_load(int argc, char *argv[])
{
	struct settings *settings;
	struct stat buf;
	unsigned int port = 0;
	char *host = NULL;
	char *uuid = NULL;

	settings = l_new(struct settings, 1);

	settings->config_path = DEFAULT_CONFIG_PATH;
	settings->host = NULL;
	settings->port = UINT32_MAX;
	settings->proto = DEFAULT_PROTO;
	settings->tty = tty;
	settings->detach = detach;
	settings->run_as_nobody = true;
	settings->help = help;
	settings->uuid = NULL;

	if (parse_args(argc, argv, settings) < 0)
		goto failure;

	memset(&buf, 0, sizeof(buf));
	if (stat(settings->config_path, &buf) < 0) {
		fprintf(stderr, "Missing KNoT configuration file!\n");
		goto failure;
	}

	/*
	 * Command line options (host and port) have higher priority
	 * than values read from config file. UUID should
	 * not be read from command line due security reason.
	 */

	/* UUID is mandatory */
	uuid = storage_read_key_string(settings->config_path, "Cloud","Uuid");
	if (uuid == NULL) {
		fprintf(stderr, "%s UUID missing!\n", settings->config_path);
		goto failure;
	}

	if (settings->host == NULL) {
		host = storage_read_key_string(settings->config_path,
					       "Cloud","ServerName");
		if(!host)
			settings->host = l_strdup(DEFAULT_HOST);
		else
			settings->host = host;
	}

	if (settings->port == UINT32_MAX) {
		if (storage_read_key_int(settings->config_path, "Cloud", "Port",
					(int *) &port) < 0)
			settings->port = DEFAULT_PORT;
		else
			settings->port = port;
	}

	settings->uuid = uuid;

	goto done;

failure:
	settings_free(settings);
	return NULL;
done:
	return settings;
}

void settings_free(struct settings *settings)
{
	l_free(settings->host);
	l_free(settings->uuid);
	l_free(settings);
}
