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

#include <ell/ell.h>

#include <hal/linux_log.h>
#include "settings.h"
#include "manager.h"
#include "filewatch.h"

static GMainLoop *main_loop;

static struct settings *settings;

static void on_config_modified()
{
	hal_log_info("Configuration file modified. Exiting  ...");
	/*
	 * TODO: implement a robust & clean way to reload settings
	 * instead of force quitting when configuration file changes.
	 */
	if (settings->use_ell)
		l_main_exit();
	else
		g_main_loop_quit(main_loop);
}

static void sig_term(int sig)
{
	if (settings->use_ell)
		l_main_exit();
	else
		g_main_loop_quit(main_loop);
}

static void main_loop_quit(struct l_timeout *timeout, void *user_data)
{
	l_main_quit();
}

static void terminate(void)
{
	static bool terminating = false;

	if (terminating)
		return;

	terminating = true;

	l_timeout_create(1, main_loop_quit, NULL, NULL);
}

static void signal_handler(struct l_signal *signal, uint32_t signo,
							void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		terminate();
		break;
	}
}

int main(int argc, char *argv[])
{
	int err;
	struct l_signal *sig;
	sigset_t mask;
	void *config_watch;

	err = settings_parse(argc, argv, &settings);
	if (err)
		goto fail_settings;

	hal_log_init("knotd", settings->detach);
	hal_log_info("KNOT Gateway");

	err = manager_start(settings);
	if (err < 0) {
		hal_log_error("start(): %s (%d)", strerror(-err), -err);
		goto failure;
	}

	/* Set user id to nobody */
	if (settings->run_as_nobody) {
		err = setuid(65534);
		if (err != 0) {
			manager_stop();
			hal_log_error("Set uid to nobody failed.  " \
				"%s(%d). Exiting ...", strerror(errno), errno);
			goto failure;
		}
	}

	config_watch = file_watch_add(settings->config_path, on_config_modified);
	if (config_watch == NULL) {
		manager_stop();
		hal_log_error("Failed to add configuration file watcher. Exiting ...");
		goto failure;
	}

	if (settings->use_ell) {
		if (!l_main_init())
			goto failure;
	} else
		main_loop = g_main_loop_new(NULL, FALSE);

	if (settings->detach) {
		if (daemon(0, 0)) {
			hal_log_error("Can't start daemon!");
			goto failure;
		}
	}

	if (settings->use_ell) {
		sigemptyset(&mask);
		sigaddset(&mask, SIGINT);
		sigaddset(&mask, SIGTERM);

		sig = l_signal_create(&mask, signal_handler, NULL, NULL);

		l_main_run();

		l_signal_remove(sig);
		l_main_exit();
	} else {
		signal(SIGTERM, sig_term);
		signal(SIGINT, sig_term);
		signal(SIGPIPE, SIG_IGN);

		g_main_loop_run(main_loop);
		g_main_loop_unref(main_loop);
	}

	file_watch_remove(config_watch);

	manager_stop();
	settings_free(settings);

	hal_log_info("Exiting");
	hal_log_close();

	return EXIT_SUCCESS;

failure:
	hal_log_close();
	if (settings->use_ell)
		l_main_exit();

	settings_free(settings);
fail_settings:
	return EXIT_FAILURE;
}
