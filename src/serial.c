/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2015, CESAR. All rights reserved.
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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
 #include <inttypes.h>

#include <glib.h>

#include "log.h"
#include "node.h"
#include "serial.h"

#define __STDC_FORMAT_MACROS

static gint tty_watch;

struct serial_opts {
	char tty[24];
	int vmin;
};

static struct serial_opts serial_opts;

struct pipe_pair {
	int	sock;		/* End-point descriptor */
	uint64_t pipeid;	/* Pipe identification */
};

static GSList *pipes = NULL;

static gint pipe_id_cmp(gconstpointer a, gconstpointer b)
{
	const struct pipe_pair *pipepair1 = b;
	const struct pipe_pair *pipepair2 = b;

	return pipepair1->pipeid - pipepair2->pipeid;
}

static gboolean tty_data_watch(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	GSList *list;
	struct pipe_pair pipepair;
	int srvfd = GPOINTER_TO_INT(user_data);
	int rbytes, err, ttyfd;
	uint64_t pipeid;
	uint8_t buffer[256];

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		return FALSE;

	ttyfd = g_io_channel_unix_get_fd(io);

	/* Read pipe address only */
	rbytes = read(ttyfd, buffer, sizeof(buffer));
	if (rbytes < 0)
		return TRUE;

	/*
	 * Serial 'driver' is only a development driver to help debuging
	 * and development of KNOT protocol in the x86 machines. It is
	 * basically a wrapper/proxy of the SPI communication to TTY.
	 * MSB: byte 0
	 * byte 0-4: pipe identification (big endian)
	 * byte   5: datagram length
	 * byte 6-x: payload
	 */

	pipeid = buffer[4];
	pipeid |= buffer[3] << 8;
	pipeid |= buffer[2] << 16;
	pipeid |= buffer[1] << 24;
	pipeid |= (uint64_t) buffer[0] << 32;

	memset(&pipepair, 0, sizeof(pipepair));
	pipepair.pipeid = pipeid;

	list = g_slist_find_custom(pipes, &pipepair, pipe_id_cmp);
	if (!list) {
		/* New pipe: trigger accept */
		if (write(srvfd, &pipeid, sizeof(pipeid)) < 0) {
			err = errno;
			log_error("serial: write(): %s(%d)", strerror(err), err);
		}
	} else {
		/* Existent pipe: forward data */
		struct pipe_pair *pipepair;
		size_t size = rbytes - 6; /* Remove pipeid and length */

		pipepair = list->data;
		if (write(pipepair->sock, &buffer[6], size) < 0) {
			err = errno;
			log_error("serial: write(): %s(%d)", strerror(err), err);
		}
	}

	return TRUE;
}

static int serial_probe(void)
{
	struct stat st;
	int err = 0;

	if (stat(serial_opts.tty, &st) < 0) {
		err = errno;
		log_error("serial stat(): %s(%d)", strerror(err), err);
	}

	return -err;
}

static void pipepair_free(gpointer user_data)
{
	struct pipe_pair *pipepair = user_data;

	close(pipepair->sock);
	g_free(pipepair);
}

static void serial_remove(void)
{

	if (tty_watch)
		g_source_remove(tty_watch);

	g_slist_free_full(pipes, pipepair_free);
}

static int serial_listen(void)
{
	GIOCondition watch_cond;
	GIOChannel *io;
	struct termios term;
	int srvfd, ttyfd;

	memset(&term, 0, sizeof(term));

	term.c_iflag = ~(IXON | IXOFF | IXANY);
	term.c_oflag = ~OPOST;
	term.c_cflag = CRTSCTS | CS8 | CLOCAL | CREAD;
	term.c_lflag = ~(ICANON | ECHO | ECHOE | ISIG);
	term.c_cc[VMIN] = serial_opts.vmin;
	term.c_cc[VTIME] = 0;

	cfsetospeed(&term, B9600);
	cfsetispeed(&term, B9600);

	ttyfd = open(serial_opts.tty, O_RDWR | O_NOCTTY);
	if (ttyfd < 0)
		return -errno;

	tcsetattr(ttyfd, TCSANOW, &term);

	io = g_io_channel_unix_new(ttyfd);
	g_io_channel_set_close_on_unref(io, TRUE);

	watch_cond = G_IO_HUP | G_IO_NVAL | G_IO_ERR | G_IO_IN;

	srvfd = eventfd(0, 0);
	tty_watch = g_io_add_watch_full(io,
				G_PRIORITY_HIGH, watch_cond,
				tty_data_watch, GINT_TO_POINTER(srvfd), NULL);
	g_io_channel_unref(io);

	return srvfd;
}

static int serial_accept(int srv_sockfd)
{
	struct pipe_pair *pipepair;
	int sv[2];
	uint64_t pipeid;
	int err;

	/*
	 * New 'thing' identified: new pipe added. Create a socketpair
	 * to identify each connected 'thing' to its pipe.
	 */

	if (read(srv_sockfd, &pipeid, sizeof(pipeid)) < 0) {
		err = errno;
		log_error("serial: accept(): %s(%d)", strerror(err), err);
		return -err;
	}

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0) {
		err = errno;
		log_error("serial: socketpair(): %s(%d)", strerror(err), err);
		return -err;
	}

	log_info("New thing accept(%d) pipeid: %" PRIu64, sv[0], pipeid);

	pipepair = g_new0(struct pipe_pair, 1);
	pipepair->sock = sv[1];
	pipepair->pipeid = pipeid;
	pipes = g_slist_append(pipes, pipepair);

	return sv[0];
}

static ssize_t serial_recv(int sockfd, void *buffer, size_t len)
{
	return read(sockfd, buffer, len);
}

static ssize_t serial_send(int sockfd, const void *buffer, size_t len)
{
	return write(sockfd, buffer, len);
}

struct node_ops serial_ops = {
	.name = "Serial",
	.probe = serial_probe,
	.remove = serial_remove,

	.listen = serial_listen,
	.accept = serial_accept,
	.recv = serial_recv,
	.send = serial_send
};

int serial_load_config(const char *tty)
{
	memset(&serial_opts, 0, sizeof(serial_opts));
	strncpy(serial_opts.tty, tty, sizeof(serial_opts.tty));
	serial_opts.vmin = 8; /* 8 octets */

	return 0;
}
