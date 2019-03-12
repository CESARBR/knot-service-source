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
#include <signal.h>

#include <ell/ell.h>
#include <hal/linux_log.h>

#include "settings.h"
#include "manager.h"

static void main_loop_quit(struct l_timeout *timeout, void *user_data)
{
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

static void l_signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_terminate();
		break;
	}
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

	hal_log_init("inetbrd", settings->detach);
	hal_log_info("KNOT IPv4/IPv6 Border Router");

	if (settings->detach) {
		if (daemon(0, 0)) {
			hal_log_error("Can't start daemon!");
			return EXIT_FAILURE;
		}
	}

	if (!l_main_init())
		goto main_fail;

	err = manager_start(settings->port4, settings->port6);
	if (err < 0) {
		fprintf(stderr, "%s(%d)\n", strerror(-err), -err);
		goto manager_fail;
	}

	l_main_run_with_signal(l_signal_handler, NULL);

	manager_stop();

	err = EXIT_SUCCESS;

manager_fail:
	l_main_exit();

main_fail:
	hal_log_close();
	settings_free(settings);

	return err;

}
