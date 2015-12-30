/*
 * This file is part of the KNOT Project
 *
 * Copyright (c) 2015, CESAR. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	* Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *	* Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 *	* Neither the name of the CESAR nor the
 *	  names of its contributors may be used to endorse or promote products
 *	  derived from this software without specific prior written permission.
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

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <glib.h>

#include <proto-net/knot_proto_net.h>
#include <proto-app/knot_proto_app.h>

#include "src/log.h"

/* Abstract unit socket namespace */
#define KNOT_UNIX_SOCKET			"knot"

/* device name for the register */
#define	KTEST_DEVICE_NAME			"ktest_unit_test"

static int sockfd;

static int unix_connect(void)
{
	struct sockaddr_un addr;
	int err, sock;

	sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {
		err = errno;
		LOG_ERROR(" >socket failure: %s (%d)\n", strerror(err), err);
		return -err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	/* Abstract namespace: first character must be null */
	strcpy(addr.sun_path + 1, KNOT_UNIX_SOCKET);

	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		LOG_ERROR("connect(): %s (%d)", strerror(err), err);
		close(sock);
		return -err;
	}

	return sock;
}

static void connection_test(void)
{
	sockfd = unix_connect();
	g_assert(sockfd > 0);
}

static void close_test(void)
{
	g_assert(close(sockfd) == 0);
	sockfd = -1;
}

static ssize_t do_request(const knot_msg *kmsg, size_t len, knot_msg *kresp)
{
	ssize_t nbytes;
	int err;

	nbytes = write(sockfd, kmsg, len);
	if (nbytes < 0) {
		err = errno;
		LOG_ERROR("write(): %s(%d)\n", strerror(err), err);
		return -err;
	}

	nbytes = read(sockfd, kresp, sizeof(knot_msg));
	if (nbytes < 0) {
		err = errno;
		LOG_ERROR("read(): %s (%d)\n", strerror(err), err);
		return -err;
	}

	return nbytes;
}

static void register_test_missing_devname(void)
{
	knot_msg kmsg, kresp;
	ssize_t size;

	memset(&kmsg, 0, sizeof(knot_msg));
	kmsg.hdr.type = KNOT_MSG_REGISTER_REQ;

	/* Sending register message with missing parameters. */

	kmsg.hdr.payload_len = 0;
	size = do_request(&kmsg, sizeof(kmsg.reg), &kresp);

	/* Response consistency */
	g_assert(size == sizeof(kresp.action));
	g_assert(kresp.hdr.payload_len == sizeof(kresp.action.result));

	/* Response opcode & result */
	g_assert(kresp.hdr.type == KNOT_MSG_REGISTER_RESP);
	g_assert(kresp.action.result == KNOT_INVALID_DATA);
}

static void register_test_empty_devname(void)
{
	knot_msg kmsg, kresp;
	ssize_t size;

	memset(&kmsg, 0, sizeof(knot_msg));
	kmsg.hdr.type = KNOT_MSG_REGISTER_REQ;

	kmsg.hdr.payload_len = 1;
	size = do_request(&kmsg, sizeof(kmsg.reg), &kresp);

	/* Response consistency */
	g_assert(size == sizeof(kresp.action));
	g_assert(kresp.hdr.payload_len == sizeof(kresp.action.result));

	/* Response opcode & result */
	g_assert(kresp.hdr.type == KNOT_MSG_REGISTER_RESP);
	g_assert(kresp.action.result == KNOT_REGISTER_INVALID_DEVICENAME);
}

static void register_test_invalid_payload_len(void)
{
	knot_msg kmsg, kresp;
	ssize_t size;

	memset(&kmsg, 0, sizeof(knot_msg));
	kmsg.hdr.type = KNOT_MSG_REGISTER_REQ;

	/* One additional octet: larger than expected msg length  */
	kmsg.hdr.payload_len = sizeof(kmsg.reg) - sizeof(kmsg.hdr) + 1;
	size = do_request(&kmsg, sizeof(kmsg.reg), &kresp);

	/* Response consistency */
	g_assert(size == sizeof(kresp.action));
	g_assert(kresp.hdr.payload_len == sizeof(kresp.action.result));

	/* Response opcode & result */
	g_assert(kresp.hdr.type == KNOT_MSG_REGISTER_RESP);
	g_assert(kresp.action.result == KNOT_INVALID_DATA);
}

static void register_test_valid_devname(void)
{
	knot_msg kmsg, kresp;
	ssize_t size;

	memset(&kmsg, 0, sizeof(knot_msg));
	kmsg.hdr.type = KNOT_MSG_REGISTER_REQ;

	/* Copying name to registration message */
	kmsg.hdr.payload_len = strlen(KTEST_DEVICE_NAME);
	strcpy(kmsg.reg.devName, KTEST_DEVICE_NAME);

	size = do_request(&kmsg, sizeof(kmsg.reg), &kresp);

	/* Response consistency */
	g_assert(size == sizeof(kresp.cred));

	/* Response opcode & result */
	g_assert(kresp.hdr.type == KNOT_MSG_REGISTER_RESP);
	g_assert(kresp.action.result == KNOT_SUCCESS);

	LOG_INFO("UUID: %s\n", kresp.cred.uuid);
}

/* Register and run all tests */
int main(int argc, char *argv[])
{
	g_test_init (&argc, &argv, NULL);

	g_test_add_func("/1/connect", connection_test);

	g_test_add_func("/1/register_missing_devname",
				register_test_missing_devname);
	g_test_add_func("/1/register_empty_devname",
				register_test_empty_devname);
	g_test_add_func("/1/register_invalid_payload_len",
				register_test_invalid_payload_len);
	g_test_add_func("/1/register_valid_devname",
				register_test_valid_devname);

	g_test_add_func("/1/close", close_test);

	return g_test_run();
}
