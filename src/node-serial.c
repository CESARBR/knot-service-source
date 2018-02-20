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

#include <ell/ell.h>

#include <hal/linux_log.h>

#include "node.h"
#include "serial.h"

#define __STDC_FORMAT_MACROS

struct serial_opts {
	char tty[24];
	int vmin;
};

static struct serial_opts serial_opts;

struct pipe_pair {
	int	sock;		/* End-point descriptor */
	uint64_t pipeid;	/* Pipe identification */
};

static struct l_io *tty_io;
static struct l_queue *pipes = NULL;

static bool pipe_id_cmp(const struct pipe_pair *pipepair, uint64_t *pipeid)
{
	return pipepair->pipeid == *pipeid;
}

static bool tty_data_watch(struct l_io *io, void *user_data)
{
	struct pipe_pair *existent_pipepair;
	int srvfd = L_PTR_TO_INT(user_data);
	int rbytes, err, ttyfd;
	uint64_t pipeid;
	uint8_t buffer[256];

	ttyfd = l_io_get_fd(io);

	/* Read pipe address only */
	rbytes = read(ttyfd, buffer, sizeof(buffer));
	if (rbytes < 0)
		return true;

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

	existent_pipepair = l_queue_find(pipes,
		(l_queue_match_func_t) pipe_id_cmp, (void *) &pipeid);
	if (!existent_pipepair) {
		/* New pipe: trigger accept */
		if (write(srvfd, &pipeid, sizeof(pipeid)) < 0) {
			err = errno;
			hal_log_error("serial: write(): %s(%d)", strerror(err),
									err);
		}
	} else {
		/* Existent pipe: forward data */
		size_t size = rbytes - 6; /* Remove pipeid and length */

		if (write(existent_pipepair->sock, &buffer[6], size) < 0) {
			err = errno;
			hal_log_error("serial: write(): %s(%d)", strerror(err),
									err);
		}
	}

	return true;
}

static int serial_probe(void)
{
	int err;
	struct stat st;

	if (stat(serial_opts.tty, &st) < 0) {
		err = errno;
		hal_log_error("serial stat(): %s(%d)", strerror(err), err);
		return -err;
	}

	pipes = l_queue_new();

	return 0;
}

static void pipepair_free(void *user_data)
{
	struct pipe_pair *pipepair = user_data;

	close(pipepair->sock);
	l_free(pipepair);
}

static void serial_remove(void)
{
	if (tty_io)
		l_io_destroy(tty_io);

	l_queue_destroy(pipes, pipepair_free);
}

static int serial_listen(void)
{
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

	tty_io = l_io_new(ttyfd);
	l_io_set_close_on_destroy(tty_io, true);

	srvfd = eventfd(0, 0);
	l_io_set_read_handler(tty_io, tty_data_watch, L_INT_TO_PTR(srvfd), NULL);

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
		hal_log_error("serial: accept(): %s(%d)", strerror(err), err);
		return -err;
	}

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0) {
		err = errno;
		hal_log_error("serial: socketpair(): %s(%d)", strerror(err), err);
		return -err;
	}

	hal_log_info("New thing accept(%d) pipeid: %" PRIu64, sv[0], pipeid);

	pipepair = l_new(struct pipe_pair, 1);
	pipepair->sock = sv[1];
	pipepair->pipeid = pipeid;
	l_queue_push_tail(pipes, pipepair);

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
