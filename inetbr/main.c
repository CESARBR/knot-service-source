/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2017, CESAR. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the CESAR nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL CESAR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include <glib.h>

#include <hal/linux_log.h>

static gboolean opt_detach = TRUE;

static GMainLoop *main_loop;

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static GOptionEntry options[] = {
	{ "nodetach", 'n', G_OPTION_FLAG_REVERSE,
					G_OPTION_ARG_NONE, &opt_detach,
					"Logging in foreground" },
	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *gerr = NULL;

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

	hal_log_init("inetbrd", opt_detach);
	hal_log_info("KNOT IPv4/IPv6 Border Router");

	if (opt_detach) {
		if (daemon(0, 0)) {
			hal_log_error("Can't start daemon!");
			return EXIT_FAILURE;
		}
	}

	main_loop = g_main_loop_new(NULL, FALSE);

	g_main_loop_run(main_loop);

	hal_log_close();

	g_main_loop_unref(main_loop);

	return EXIT_SUCCESS;
}
