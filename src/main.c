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

#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <ell/ell.h>

#include <hal/linux_log.h>
#include "settings.h"
#include "manager.h"

static void main_loop_quit(struct l_timeout *timeout, void *user_data)
{
	l_timeout_remove(timeout);
	l_main_quit();
}

static void l_terminate(void)
{
	static bool terminating = false;

	if (terminating)
		return;

	terminating = true;

	l_timeout_create(1, main_loop_quit, NULL, NULL);
}

static bool l_main_loop_init()
{
	return l_main_init();
}

static void signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_terminate();
		break;
	}
}

static void l_main_loop_run()
{
	l_main_run_with_signal(signal_handler, NULL);

	l_main_exit();
}

static int run_as_user_knot(void)
{
	if (setuid(1003))
		return -errno;
	return 0;
}

static int detach()
{
	if (daemon(0, 0))
		return -errno;
	return 0;
}

int main(int argc, char *argv[])
{
	struct settings *settings;

	int err = EXIT_FAILURE;

	settings = settings_load(argc, argv);
	if (settings == NULL)
		return err;

	if (settings->help) {
		settings_free(settings);
		return EXIT_SUCCESS;
	}

	if (!l_main_loop_init())
		goto fail_main_loop;

	hal_log_init("knotd", settings->detach);
	hal_log_info("KNOT Gateway");

	err = manager_start(settings);
	if (err) {
		hal_log_error("Failed to start the manager: %s (%d)",
			      strerror(-err), -err);
		goto fail_manager;
	}

	/* Set user id to user 'knot' */
	if (settings->run_as_root == false) {
		err = run_as_user_knot();
		if (err) {
			hal_log_error("Failed to run as user 'knot' " \
				"%s (%d). Exiting ...", strerror(-err), -err);
			goto fail_user_knot;
		}
	}

	if (settings->detach) {
		err = detach();
		if (err) {
			hal_log_error("Failed to detach. " \
				"%s (%d). Exiting ...", strerror(-err), -err);
			goto fail_detach;
		}
	}

	l_main_loop_run();

	hal_log_info("Exiting");

	err = EXIT_SUCCESS;

fail_detach:
fail_user_knot:
	manager_stop();
fail_manager:
	l_main_exit();
	hal_log_close();
fail_main_loop:
	settings_free(settings);

	return err;
}
