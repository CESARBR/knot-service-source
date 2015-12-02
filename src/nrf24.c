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
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/spi/spidev.h>

#include "log.h"
#include "node.h"

/* TODO: Use GKeyFile to read the device path, or bus & chip select */
static const char *spidevpath = "/dev/spidev0.0";
static int spifd;

static int nrf24_probe(void)
{
	int err;

	/*
	 * TODO: stat() of the available path. Path of Beagle Bone Black &
	 * Raspiberry are different
	 */
	spifd = open(spidevpath, O_RDWR | O_CLOEXEC);
	if (spifd == -1) {
		err = errno;
		LOG_ERROR("%s open(): %s(%d)\n", spidevpath,
					strerror(err), err);
		return -err;
	}

	err = ioctl(spifd, SPI_IOC_WR_MODE, SPI_MODE_0);
	if (err < 0) {
		err = errno;
		LOG_ERROR("%s ioctl(SPI_IOC_WR_MODE): %s(%d)\n", spidevpath,
							strerror(err), err);
		goto done;
	}

	err = ioctl(spifd, SPI_IOC_RD_MODE, SPI_MODE_0);
	if (err < 0) {
		err = errno;
		LOG_ERROR("%s ioctl(SPI_IOC_RD_MODE): %s(%d)\n", spidevpath,
							strerror(err), err);
		goto done;
	}

	/* FIXME: Use macro of config file - 8bits */
	err = ioctl(spifd, SPI_IOC_WR_BITS_PER_WORD, 0x08);
	if (err < 0) {
		err = errno;
		LOG_ERROR("%s ioctl(SPI_IOC_WR_BITS_PER_WORD): %s(%d)\n",
						spidevpath, strerror(err), err);
		goto done;
	}

	/* FIXME: Use macro of config file - 8bits */
	err = ioctl(spifd, SPI_IOC_RD_BITS_PER_WORD, 0x08);
	if (err < 0) {
		err = errno;
		LOG_ERROR("%s ioctl(SPI_IOC_RD_BITS_PER_WORD): %s(%d)\n",
						spidevpath, strerror(err), err);
		goto done;
	}

	/* FIXME: Use macro of config file - 8Mhz */
	err = ioctl(spifd, SPI_IOC_WR_MAX_SPEED_HZ, 8000000);
	if (err < 0) {
		err = errno;
		LOG_ERROR("%s ioctl(SPI_IOC_WR_MAX_SPEED_HZ): %s(%d)\n",
				spidevpath, strerror(err), err);
		goto done;
	}

	/* FIXME: Use macro of config file - 8Mhz */
	err = ioctl(spifd, SPI_IOC_RD_MAX_SPEED_HZ, 8000000);
	if (err < 0) {
		err = errno;
		LOG_ERROR("%s ioctl(SPI_IOC_WD_MAX_SPEED_HZ): %s(%d)\n",
				spidevpath, strerror(err), err);
		goto done;
	}

	return 0;

done:
	close(spifd);

	return -err;
}

static void nrf24_remove(void)
{

	if (spifd)
		close(spifd);
}

static int nrf24_listen(void)
{
	return -ENOSYS;
}

static int nrf24_accept(int srv_sockfd)
{
	return -ENOSYS;
}

static ssize_t nrf24_recv(int sockfd, void *buffer, size_t len)
{
	return -ENOSYS;
}

static ssize_t nrf24_send(int sockfd, const void *buffer, size_t len)
{
	return -ENOSYS;
}

static struct node_ops nrf24_ops = {
	.name = "NRF24L01",
	.probe = nrf24_probe,
	.remove = nrf24_remove,

	.listen = nrf24_listen,
	.accept = nrf24_accept,
	.recv = nrf24_recv,
	.send = nrf24_send
};

/*
 * The following functions MAY be implemented as plugins
 * initialization functions, avoiding function calls such
 * as manager@manager_start()->node@node_init()->
 * manager@node_ops_register()->node@node_probe()
 */
