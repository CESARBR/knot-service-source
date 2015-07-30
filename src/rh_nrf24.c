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

#include "node.h"

static int nrf24_probe(void)
{
	return -ENOSYS;
}

static void nrf24_remove(void)
{
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
	.name = "Radio Head: nRF24",
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
int node_init(void)
{
	return node_ops_register(&nrf24_ops);
}

void node_exit(void)
{
}
