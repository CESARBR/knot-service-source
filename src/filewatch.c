#include "filewatch.h"

#include <errno.h>
#include <unistd.h>
#include <stdbool.h>

#include <glib.h>
#include <ell/ell.h>
#include <sys/inotify.h>

#define BUF_LEN (sizeof(struct inotify_event))

struct file_watch {
	int inotify_fd;
	int inotify_wd;
	guint g_watch_id;
	struct l_io *channel;
};

static bool read_inotify_event(int fd, on_file_modified on_file_modified_cb)
{
	char buf[BUF_LEN];
	ssize_t read_count;
	const struct inotify_event *event;

	read_count = read(fd, buf, BUF_LEN);
	if (read_count == -1)
		return false;

	event = (struct inotify_event *) buf;
	if (event->mask & IN_MODIFY)
		on_file_modified_cb();

	return true;
}

static gboolean g_on_inotify_event(GIOChannel *gio, GIOCondition condition,
								gpointer data)
{
	int inotify_fd;
	on_file_modified on_file_modified_cb;

	inotify_fd = g_io_channel_unix_get_fd(gio);
	on_file_modified_cb = (on_file_modified) data;

	return read_inotify_event(inotify_fd, on_file_modified_cb);
}

static bool l_on_inotify_event(struct l_io *io, void *data)
{
	int inotify_fd;
	on_file_modified on_file_modified_cb;

	inotify_fd = l_io_get_fd(io);
	on_file_modified_cb = (on_file_modified) data;

	return read_inotify_event(inotify_fd, on_file_modified_cb);
}

static int create_inotify_watch(struct file_watch *watch, const char *path)
{
	watch->inotify_fd = inotify_init();
	watch->inotify_wd = inotify_add_watch(watch->inotify_fd, path, IN_MODIFY);
	if (watch->inotify_wd == -1) {
		close(watch->inotify_fd);
		return -errno;
	}

	return 0;
}

static void destroy_inotify_watch(struct file_watch *watch)
{
	inotify_rm_watch(watch->inotify_fd, watch->inotify_wd);
}

static void g_create_mainloop_io_channel(struct file_watch *watch,
	on_file_modified on_file_modified_cb)
{
	GIOChannel *inotify_io;

	inotify_io = g_io_channel_unix_new(watch->inotify_fd);
	watch->g_watch_id = g_io_add_watch(inotify_io, G_IO_IN,
		g_on_inotify_event, on_file_modified_cb);
	g_io_channel_set_close_on_unref(inotify_io, TRUE);
	g_io_channel_unref(inotify_io);
}

static void g_destroy_mainloop_io_channel(struct file_watch *watch)
{
	g_source_remove(watch->g_watch_id);
}

static bool l_create_mainloop_io_channel(struct file_watch *watch,
	on_file_modified on_file_modified_cb)
{
	watch->channel = l_io_new(watch->inotify_fd);
	return l_io_set_read_handler(watch->channel, l_on_inotify_event,
		on_file_modified_cb, NULL);
}

static void l_destroy_mainloop_io_channel(struct file_watch *watch)
{
	l_io_destroy(watch->channel);
}

void *g_file_watch_add(const char *path, on_file_modified on_file_modified_cb)
{
	int err = 0;
	struct file_watch *watch;

	watch = g_new0(struct file_watch, 1);

	err = create_inotify_watch(watch, path);
	if (err)
		goto failure;

	g_create_mainloop_io_channel(watch, on_file_modified_cb);

	goto done;

failure:
	g_free(watch);
	watch = NULL;
done:
	return watch;
}

void g_file_watch_remove(void *watch)
{
	struct file_watch *file_watch;

	file_watch = (struct file_watch *) watch;

	g_destroy_mainloop_io_channel(file_watch);
	destroy_inotify_watch(file_watch);
	g_free(file_watch);
}

void *l_file_watch_add(const char *path, on_file_modified on_file_modified_cb)
{
	int err = 0;
	struct file_watch *watch;

	watch = l_new(struct file_watch, 1);

	err = create_inotify_watch(watch, path);
	if (err)
		goto fail_inotify;

	if (!l_create_mainloop_io_channel(watch, on_file_modified_cb))
		goto fail_channel;

	goto done;

fail_channel:
	destroy_inotify_watch(watch);
fail_inotify:
	l_free(watch);
	watch = NULL;
done:
	return watch;
}

void l_file_watch_remove(void *watch)
{
	struct file_watch *file_watch;

	file_watch = (struct file_watch *) watch;

	l_destroy_mainloop_io_channel(file_watch);
	destroy_inotify_watch(file_watch);
	l_free(file_watch);
}