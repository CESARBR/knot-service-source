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

static int run_as_nobody()
{
	if (setuid(65534))
		return -errno;
	return 0;
}

static void l_on_config_modified()
{
	hal_log_info("Configuration file modified. Exiting  ...");
	/*
	 * TODO: implement a robust & clean way to reload settings
	 * instead of force quitting when configuration file changes.
	 */
	terminate();
}

static void g_on_config_modified()
{
	hal_log_info("Configuration file modified. Exiting  ...");
	/*
	 * TODO: implement a robust & clean way to reload settings
	 * instead of force quitting when configuration file changes.
	 */
	g_main_loop_quit(main_loop);
}

static int detach()
{
	if (daemon(0, 0))
		return -errno;
	return 0;
}

static void sig_term(int sig)
{
	if (settings->use_ell)
		l_main_exit();
	else
		g_main_loop_quit(main_loop);
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
	int err = EXIT_FAILURE;
	struct l_signal *sig;
	sigset_t mask;
	void *config_watch;

	err = settings_parse(argc, argv, &settings);
	if (err)
		goto fail_settings;

	hal_log_init("knotd", settings->detach);
	hal_log_info("KNOT Gateway");

	err = manager_start(settings);
	if (err) {
		hal_log_error("Failed to start the manager: %s (%d)", strerror(-err), -err);
		goto fail_manager;
	}

	/* Set user id to nobody */
	if (settings->run_as_nobody) {
		err = run_as_nobody();
		if (err) {
			hal_log_error("Failed to run as nobody. " \
				"%s (%d). Exiting ...", strerror(-err), -err);
			goto fail_nobody;
		}
	}

	if (settings->use_ell) {
		if (!l_main_init())
			goto fail_main_loop;
	} else
		main_loop = g_main_loop_new(NULL, FALSE);

	if (settings->use_ell)
		config_watch = l_file_watch_add(settings->config_path, l_on_config_modified);
	else
		config_watch = g_file_watch_add(settings->config_path, g_on_config_modified);
	if (config_watch == NULL) {
		hal_log_error("Failed to add configuration file watcher. Exiting ...");
		goto fail_config_watch;
	}

	if (settings->detach) {
		err = detach();
		if (err) {
			hal_log_error("Failed to detach. " \
				"%s (%d). Exiting ...", strerror(-err), -err);
			goto fail_detach;
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

	hal_log_info("Exiting");

	err = EXIT_SUCCESS;
	goto done;

fail_detach:
	if (settings->use_ell)
		l_main_exit();
done:
fail_config_watch:
	if (settings->use_ell)
		l_file_watch_remove(config_watch);
	else
		g_file_watch_remove(config_watch);
fail_main_loop:
fail_nobody:
	manager_stop();
fail_manager:
	hal_log_close();
	settings_free(settings);
fail_settings:
	return err;
}
