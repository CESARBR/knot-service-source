/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2015, CESAR. All rights reserved.
 *
 * Redistributermn and use in source and binary forms, with or without
 * modificatermn, are permitted provided that the following conditermns are met:
 *    * Redistributermns of source code must retain the above copyright
 *      notice, this list of conditermns and the following disclaimer.
 *    * Redistributermns in binary form must reproduce the above copyright
 *      notice, this list of conditermns and the following disclaimer in the
 *      documentatermn and/or other materials provided with the distributermn.
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
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "node.h"

static int serial_probe(void)
{
	return 0;
}

static void serial_remove(void)
{

}

static int serial_listen(void)
{
	struct termios term;
	int ttyfd;

	memset(&term, 0, sizeof(term));

	term.c_iflag = 0;
	term.c_oflag = 0;
	term.c_cflag = CS8 | CREAD | CLOCAL;
	term.c_lflag = 0;
	term.c_cc[VMIN] = 1;
	term.c_cc[VTIME] = 5;

	cfsetospeed(&term, B9600);
	cfsetispeed(&term, B9600);

	ttyfd = open("/dev/ttyUSB1", O_RDWR | O_NONBLOCK);
	if (ttyfd < 0)
		return -errno;

	tcsetattr(ttyfd, TCSANOW, &term);

	return ttyfd;
}

static int serial_accept(int srv_sockfd)
{
	/* Playground for multiplexing multiple devices: pipes */

	return -ENOSYS;
}

static ssize_t serial_recv(int sockfd, void *buffer, size_t len)
{
	return recv(sockfd, buffer, len, 0);
}

static ssize_t serial_send(int sockfd, const void *buffer, size_t len)
{
	return send(sockfd, buffer, len, 0);
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
