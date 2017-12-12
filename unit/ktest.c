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


#include <knot_protocol.h>
#include <knot_types.h>

#include <hal/linux_log.h>

/* Abstract unit socket namespace */
#define KNOT_UNIX_SOCKET			"knot"

/* device name for the register */
#define	KTEST_DEVICE_NAME			"ktest_unit_test"

static int sockfd;
static char uuid128[KNOT_PROTOCOL_UUID_LEN];

static int unix_connect(void)
{
	struct sockaddr_un addr;
	int err, sock;

	sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sock < 0) {
		err = errno;
		hal_log_error(" >socket failure: %s (%d)", strerror(err), err);
		return -err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	/* Abstract namespace: first character must be null */
	strcpy(addr.sun_path + 1, KNOT_UNIX_SOCKET);

	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		hal_log_error("connect(): %s (%d)", strerror(err), err);
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
		hal_log_error("write(): %s(%d)", strerror(err), err);
		return -err;
	}

	nbytes = read(sockfd, kresp, sizeof(knot_msg));
	if (nbytes < 0) {
		err = errno;
		hal_log_error("read(): %s (%d)", strerror(err), err);
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
	size = do_request(&kmsg, sizeof(kmsg.reg.hdr), &kresp);

	/* Response consistency */
	g_assert(size == sizeof(kresp.action));
	g_assert(kresp.hdr.payload_len == sizeof(kresp.action.result));

	/* Response opcode & result */
	g_assert(kresp.hdr.type == KNOT_MSG_REGISTER_RESP);
	g_assert(kresp.action.result == KNOT_REGISTER_INVALID_DEVICENAME);
}

static void register_test_empty_devname(void)
{
	knot_msg kmsg, kresp;
	ssize_t size, plen;

	memset(&kmsg, 0, sizeof(knot_msg));
	kmsg.hdr.type = KNOT_MSG_REGISTER_REQ;

	kmsg.hdr.payload_len = 1;

	plen = sizeof(kmsg.reg.hdr) + kmsg.hdr.payload_len;
	size = do_request(&kmsg, plen, &kresp);

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
	g_assert(kresp.action.result == KNOT_REGISTER_INVALID_DEVICENAME);
}

static void register_test_valid_devname(void)
{
	knot_msg kmsg, kresp;
	ssize_t size, plen;

	memset(&kresp, 0, sizeof(kresp));
	memset(&kmsg, 0, sizeof(knot_msg));
	kmsg.hdr.type = KNOT_MSG_REGISTER_REQ;

	/* Copying name to registration message */
	kmsg.hdr.payload_len = strlen(KTEST_DEVICE_NAME);
	strcpy(kmsg.reg.devName, KTEST_DEVICE_NAME);

	plen = sizeof(kmsg.reg.hdr) + kmsg.hdr.payload_len;
	size = do_request(&kmsg, plen, &kresp);

	/* Response consistency */
	g_assert(size == sizeof(kresp.cred));

	/* Response opcode & result */
	g_assert(kresp.hdr.type == KNOT_MSG_REGISTER_RESP);
	g_assert(kresp.action.result == KNOT_SUCCESS);

	hal_log_info("UUID: %s", kresp.cred.uuid);
	memcpy(uuid128, kresp.cred.uuid, sizeof(kresp.cred.uuid));
}

static void unregister_test_invalid_payload_len0(void)
{
	knot_msg kmsg, kresp;

	memset(&kresp, 0, sizeof(kresp));
	memset(&kmsg, 0, sizeof(kmsg));
	kmsg.hdr.type = KNOT_MSG_UNREGISTER_REQ;

	/*
	 * Sending: payload_len == 0
	 * Expected: 'KNOT_INVALID_DATA'
	 */
	kmsg.hdr.payload_len = 0;
	g_assert(do_request(&kmsg, sizeof(kmsg.unreg), &kresp) ==
							sizeof(kresp.action));
	g_assert(kresp.hdr.payload_len == sizeof(kresp.action.result));
	g_assert(kresp.hdr.type == KNOT_MSG_UNREGISTER_RESP);
	g_assert(kresp.action.result == KNOT_INVALID_DATA);
}

static void unregister_test_invalid_large_payload(void)
{
	knot_msg kmsg, kresp;

	memset(&kmsg, 0, sizeof(kmsg));
	memset(&kresp, 0, sizeof(kresp));
	kmsg.hdr.type = KNOT_MSG_UNREGISTER_REQ;

	/*
	 * Sending: payload_len == sizeof(kmsg.unreg) - sizeof(kmsg.hdr) + 1
	 * Expected: 'KNOT_INVALID_DATA'
	 */

	kmsg.hdr.payload_len = sizeof(kmsg.unreg) - sizeof(kmsg.hdr) + 1;
	g_assert(do_request(&kmsg, sizeof(kmsg.unreg), &kresp) ==
							sizeof(kresp.action));
	g_assert(kresp.hdr.payload_len == sizeof(kresp.action.result));
	g_assert(kresp.hdr.type == KNOT_MSG_UNREGISTER_RESP);
	g_assert(kresp.action.result == KNOT_INVALID_DATA);
}

static void unregister_test_valid_device(void)
{
	knot_msg kmsg, kresp;

	memset(&kmsg, 0, sizeof(kmsg));
	memset(&kresp, 0, sizeof(kresp));
	kmsg.hdr.type = KNOT_MSG_UNREGISTER_REQ;

	kmsg.hdr.payload_len = 0;
	g_assert(do_request(&kmsg, sizeof(kmsg.unreg), &kresp) ==
							sizeof(kresp.action));
	g_assert(kresp.hdr.payload_len == sizeof(kresp.action.result));
	g_assert(kresp.hdr.type == KNOT_MSG_UNREGISTER_RESP);
	g_assert(kresp.action.result == KNOT_SUCCESS);
}

/* Register and run all tests */
int main(int argc, char *argv[])
{

	signal(SIGPIPE, SIG_IGN);

	g_test_init (&argc, &argv, NULL);

	g_test_add_func("/1/connect", connection_test);
	g_test_add_func("/1/register_missing_devname",
				register_test_missing_devname);
	g_test_add_func("/1/close", close_test);

	g_test_add_func("/2/connect", connection_test);
	g_test_add_func("/2/register_empty_devname",
				register_test_empty_devname);
	g_test_add_func("/2/close", close_test);

	g_test_add_func("/3/connect", connection_test);
	g_test_add_func("/3/register_invalid_payload_len",
				register_test_invalid_payload_len);
	g_test_add_func("/3/close", close_test);

	g_test_add_func("/4/connect", connection_test);
	g_test_add_func("/4/register_valid_devname",
				register_test_valid_devname);
	g_test_add_func("/4/close", close_test);

	g_test_add_func("/5/connect", connection_test);
	g_test_add_func("/5/unregister_invalid_payload_len0",
				unregister_test_invalid_payload_len0);
	g_test_add_func("/5/close", close_test);

	g_test_add_func("/6/connect", connection_test);
	g_test_add_func("/6/unregister_test_invalid_large_payload",
				unregister_test_invalid_large_payload);
	g_test_add_func("/6/close", close_test);

	g_test_add_func("/7/connect", connection_test);
	g_test_add_func("/7/unregister_test_valid_device",
				unregister_test_valid_device);
	g_test_add_func("/7/close", close_test);

	return g_test_run();
}
