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
#include <getopt.h>

#include <ell/ell.h>

#include "settings.h"

#define DEFAULT_AMQP_URL		"amqp://guest:guest@localhost:5672"

static bool detach = true;
static bool help = false;

static void usage(void)
{
	printf("knotd - KNoT deamon\n"
		"Usage:\n");
	printf("\tknotd [options]\n");
	printf("Options:\n"
		"\t-n, --nodetach          Disable running in background\n"
		"\t-r, --user-root         Run as root(default is knot)\n"
		"\t-R, --rabbitmq-url      Connect with a different url "
		"amqp://[$USERNAME[:$PASSWORD]\\@]$HOST[:$PORT]/[$VHOST]\n"
		"\t-H, --help              Show help options\n");
}

static const struct option main_options[] = {
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
		opt = getopt_long(argc, argv, "R:nrH",
				  main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
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

	settings = l_new(struct settings, 1);

	settings->detach = detach;
	settings->run_as_root = false;
	settings->help = help;
	settings->rabbitmq_url = l_strdup(DEFAULT_AMQP_URL);

	if (parse_args(argc, argv, settings) < 0)
		goto failure;

	goto done;

failure:
	settings_free(settings);
	return NULL;
done:
	return settings;
}

void settings_free(struct settings *settings)
{
	l_free(settings->rabbitmq_url);
	l_free(settings);
}
