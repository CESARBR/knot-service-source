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
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <hal/linux_log.h>

#include "manager.h"

static gboolean opt_detach = TRUE;
static int opt_port4 = 9994;
static int opt_port6 = 9996;

static GMainLoop *main_loop;

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static GOptionEntry options[] = {
	{ "nodetach", 'n', G_OPTION_FLAG_REVERSE,
					G_OPTION_ARG_NONE, &opt_detach,
					"Logging in foreground" },
	{ "port4", 'p', 0, G_OPTION_ARG_INT, &opt_port4,
			"IPv4 port", "localhost IPv4 port. Default 9994" },
	{ "port6", 'P', 0, G_OPTION_ARG_INT, &opt_port6,
			"IPv6 port", "localhost IPv6 port. Default 9996" },
	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *gerr = NULL;
	int err;

	signal(SIGTERM, sig_term);
	signal(SIGINT, sig_term);
	signal(SIGPIPE, SIG_IGN);

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &gerr)) {
		g_printerr("Invalid arguments: %s\n", gerr->message);
		g_error_free(gerr);
		g_option_context_free(context);
		return EXIT_FAILURE;
	}

	g_option_context_free(context);

	err = manager_start(opt_port4, opt_port6);
	if (err < 0) {
		g_error("%s(%d)", strerror(-err), -err);
		return EXIT_FAILURE;
	}

	hal_log_init("inetbrd", opt_detach);
	hal_log_info("KNOT IPv4/IPv6 Border Router");

	if (opt_detach) {
		if (daemon(0, 0)) {
			hal_log_error("Can't start daemon!");
			manager_stop();
			return EXIT_FAILURE;
		}
	}

	main_loop = g_main_loop_new(NULL, FALSE);

	g_main_loop_run(main_loop);

	manager_stop();
	hal_log_close();

	g_main_loop_unref(main_loop);

	return EXIT_SUCCESS;
}
