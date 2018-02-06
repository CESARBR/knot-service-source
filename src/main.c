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
#include <sys/inotify.h>

#include <ell/ell.h>

#include <hal/linux_log.h>
#include "settings.h"
#include "manager.h"

#define BUF_LEN (sizeof(struct inotify_event))

static GMainLoop *main_loop;

static struct settings *settings;

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

static gboolean inotify_cb(GIOChannel *gio, GIOCondition condition,
								gpointer data)
{
	int inotifyFD = g_io_channel_unix_get_fd(gio);
	char buf[BUF_LEN];
	ssize_t numRead;
	const struct inotify_event *event;

	numRead = read(inotifyFD, buf, BUF_LEN);
	if (numRead == -1) {
		hal_log_error("Error read from inotify fd");
		return FALSE;
	}

	hal_log_info("Read %ld bytes from inotify fd", (long) numRead);

	/* Process the events in buffer returned by read() */

	event = (struct inotify_event *) buf;
	if (event->mask & IN_MODIFY)
		g_main_loop_quit(main_loop);

	return TRUE;
}

int main(int argc, char *argv[])
{
	struct l_signal *sig;
	int err;
	GIOChannel *inotify_io;
	int inotifyFD, wd;
	guint watch_id;
	sigset_t mask;

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

	/*
	 * TODO: implement a robust & clean way to reload settings
	 * instead of force quitting when configuration file changes.
	 */

	/* Starting inotify */
	inotifyFD = inotify_init();

	wd = inotify_add_watch(inotifyFD, settings->config_path, IN_MODIFY);
	if (wd == -1) {
		manager_stop();
		close(inotifyFD);
		hal_log_error("inotify_add_watch(): %s", settings->config_path);
		goto failure;
	}
	/* Setting gio channel to watch inotify fd */
	inotify_io = g_io_channel_unix_new(inotifyFD);
	watch_id = g_io_add_watch(inotify_io, G_IO_IN, inotify_cb, NULL);
	g_io_channel_set_close_on_unref(inotify_io, TRUE);
	g_io_channel_unref(inotify_io);

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

	/* inotify cleanup */
	g_source_remove(watch_id);
	inotify_rm_watch(inotifyFD, wd);

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
