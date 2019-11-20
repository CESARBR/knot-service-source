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

#define DEFAULT_CONFIG_PATH		"/etc/knot/knotd.conf"
#define DEFAULT_AMQP_URL		"amqp://guest:guest@localhost:5672"

static bool detach = true;
static bool help = false;

static void usage(void)
{
	printf("knotd - KNoT deamon\n"
		"Usage:\n");
	printf("\tknotd [options]\n");
	printf("Options:\n"
		"\t-c, --config            Configuration file path\n"
		"\t-n, --nodetach          Disable running in background\n"
		"\t-r, --user-root         Run as root(default is knot)\n"
		"\t-R, --rabbitmq-url      Connect with a different url "
		"amqp://[$USERNAME[:$PASSWORD]\\@]$HOST[:$PORT]/[$VHOST]\n"
		"\t-H, --help              Show help options\n");
}

static const struct option main_options[] = {
	{ "config",		required_argument,	NULL, 'c' },
	{ "rabbitmq-url",	required_argument,	NULL, 'R' },
	{ "nodetach",		no_argument,		NULL, 'n' },
	{ "user-root",		no_argument,		NULL, 'r' },
	{ "help",		no_argument,		NULL, 'H' },
	{ }
};

static int parse_args(int argc, char *argv[], struct settings *settings)
{
	int opt;

	for (;;) {
		opt = getopt_long(argc, argv, "c:R:nrH",
				  main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'c':
			settings->config_path = optarg;
			break;
		case 'R':
			settings->rabbitmq_url = optarg;
			break;
		case 'n':
			settings->detach = false;
			break;
		case 'r':
			settings->run_as_root = true;
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
	char *token = NULL;

	settings = l_new(struct settings, 1);

	settings->config_path = DEFAULT_CONFIG_PATH;
	settings->configfd = -1;
	settings->detach = detach;
	settings->run_as_root = false;
	settings->help = help;
	settings->token = NULL;
	settings->rabbitmq_url = l_strdup(DEFAULT_AMQP_URL);

	if (parse_args(argc, argv, settings) < 0)
		goto failure;

	memset(&buf, 0, sizeof(buf));
	if (stat(settings->config_path, &buf) < 0) {
		fprintf(stderr, "Missing KNoT configuration file!\n");
		goto failure;
	}

	settings->configfd = storage_open(settings->config_path);
	if (settings->configfd  < 0)
		goto failure;

	/*
	 * Command line options (host and port) have higher priority
	 * than values read from config file. Token should
	 * not be read from command line due security reason.
	 */

	/* Token is mandatory */
	token = storage_read_key_string(settings->configfd, "Cloud", "Token");
	if (token == NULL) {
		fprintf(stderr, "%s Token missing!\n", settings->config_path);
		goto failure;
	}

	settings->token = token;

	goto done;

failure:
	settings_free(settings);
	return NULL;
done:
	return settings;
}

void settings_free(struct settings *settings)
{
	if (settings->configfd >= 0)
		storage_close(settings->configfd);

	l_free(settings->token);
	l_free(settings->rabbitmq_url);
	l_free(settings);
}
