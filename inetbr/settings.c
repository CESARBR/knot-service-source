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

static const bool detach = true;
static const bool help = false;

static void usage(void)
{
	printf("inetbr - KNoT deamon\n"
		"Usage:\n");
	printf("\tinetbrd [options]\n");
	printf("Options:\n"
		"\t-p, --port4            localhost IPv4 port. Default 8884"
		"\t-P, --port6            localhost IPv6 port. Default 8886"
		"\t-n, --nodetach         Disable running in background\n"
		"\t-h  --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "port4",		required_argument,	NULL, 'p' },
	{ "port6",		required_argument,	NULL, 'P' },
	{ "nodetach",		no_argument,		NULL, 'n' },
	{ "help",		no_argument,		NULL, 'h' },
	{ }
};

static int parse_args(int argc, char *argv[], struct settings *settings)
{
	int opt;

	for (;;) {
		opt = getopt_long(argc, argv, "c:h:p:P:nbH",
				  main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'p':
			settings->port4 = atoi(optarg);
			break;
		case 'P':
			settings->port6 = atoi(optarg);
			break;
		case 'n':
			settings->detach = false;
			break;
		case 'h':
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

	settings->port4 = 8884;
	settings->port6 = 8886;
	settings->detach = detach;
	settings->help = help;

	if (parse_args(argc, argv, settings) < 0) {
		settings_free(settings);
		return NULL;
	}

	return settings;
}

void settings_free(struct settings *settings)
{
	l_free(settings);
}
